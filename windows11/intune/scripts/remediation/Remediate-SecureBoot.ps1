<#
.SYNOPSIS
    Intune Proactive Remediation — Remediation script for Secure Boot compliance.
.DESCRIPTION
    Secure Boot cannot be enabled from within the OS. This script:
      1. Logs the non-compliant state to the Windows Application event log
      2. Writes a structured registry key for helpdesk/reporting queries
      3. Optionally triggers a toast notification to the logged-on user
.NOTES
    Run as: SYSTEM (64-bit)
    Platform: Windows 11
#>

#region — Event log setup
$logName    = 'Application'
$sourceName = 'IntuneSecureBoot'

if (-not [System.Diagnostics.EventLog]::SourceExists($sourceName)) {
    [System.Diagnostics.EventLog]::CreateEventSource($sourceName, $logName)
}
#endregion

#region — Collect state
$state = [ordered]@{
    Timestamp    = (Get-Date -Format 'o')
    ComputerName = $env:COMPUTERNAME
    SecureBoot   = $null
    TPMPresent   = $null
    TPMReady     = $null
    VBSStatus    = $null
    Issues       = [System.Collections.Generic.List[string]]::new()
}

try { $state.SecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop }
catch { $state.SecureBoot = $false; $state.Issues.Add("SecureBootUEFI: $($_.Exception.Message)") }

$tpm = Get-Tpm -ErrorAction SilentlyContinue
$state.TPMPresent = [bool]$tpm.TpmPresent
$state.TPMReady   = [bool]$tpm.TpmReady
if (-not $tpm.TpmPresent) { $state.Issues.Add('TPM not present') }
if ($tpm.TpmPresent -and -not $tpm.TpmReady) { $state.Issues.Add('TPM not ready') }

$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
$state.VBSStatus = $dg.VirtualizationBasedSecurityStatus
if ($dg.VirtualizationBasedSecurityStatus -eq 0) { $state.Issues.Add('VBS not running') }
#endregion

#region — Write to registry (queryable via Graph / MEM reports)
$regPath = 'HKLM:\SOFTWARE\IntuneRemediations\SecureBoot'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

Set-ItemProperty -Path $regPath -Name 'LastCheck'    -Value $state.Timestamp  -Type String
Set-ItemProperty -Path $regPath -Name 'SecureBoot'   -Value ([int]$state.SecureBoot) -Type DWord
Set-ItemProperty -Path $regPath -Name 'TPMPresent'   -Value ([int]$state.TPMPresent) -Type DWord
Set-ItemProperty -Path $regPath -Name 'TPMReady'     -Value ([int]$state.TPMReady)   -Type DWord
Set-ItemProperty -Path $regPath -Name 'VBSStatus'    -Value $state.VBSStatus         -Type DWord
Set-ItemProperty -Path $regPath -Name 'Issues'       -Value ($state.Issues -join '; ') -Type String
#endregion

#region — Event log entry
$message = @"
Secure Boot remediation check on $($state.ComputerName)
Timestamp  : $($state.Timestamp)
SecureBoot : $($state.SecureBoot)
TPMPresent : $($state.TPMPresent)
TPMReady   : $($state.TPMReady)
VBSStatus  : $($state.VBSStatus)
Issues     : $($state.Issues -join ' | ')

ACTION REQUIRED: Secure Boot and/or TPM issues cannot be resolved automatically.
A technician must enable Secure Boot in the device firmware (UEFI settings).
"@

Write-EventLog -LogName $logName -Source $sourceName -EventId 1001 -EntryType Warning -Message $message
#endregion

#region — Toast notification to logged-on user
$loggedOnUser = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
if ($loggedOnUser) {
    $toastScript = @'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

$xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Security Configuration Required</text>
      <text>Your device is missing a required security setting (Secure Boot). Please contact the IT helpdesk to schedule a firmware update.</text>
    </binding>
  </visual>
</toast>
"@

$toastXml = [Windows.Data.Xml.Dom.XmlDocument]::new()
$toastXml.LoadXml($xml)
$toast = [Windows.UI.Notifications.ToastNotification]::new($toastXml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Microsoft.CompanyPortal_8wekyb3d8bbwe!App').Show($toast)
'@

    $encodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($toastScript))
    $userSid = (New-Object System.Security.Principal.NTAccount($loggedOnUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value

    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList "-NonInteractive -WindowStyle Hidden -EncodedCommand $encodedScript" `
        -ErrorAction SilentlyContinue
}
#endregion

Write-Output "Remediation completed. Issues logged: $($state.Issues -join ' | ')"
exit 0
