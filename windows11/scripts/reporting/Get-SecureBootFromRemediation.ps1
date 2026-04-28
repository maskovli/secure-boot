<#
.SYNOPSIS
    Henter Secure Boot-inventar fra Proactive Remediation via Graph API.
.DESCRIPTION
    Leser preRemediationDetectionScriptOutput fra alle deviceRunStates på
    Collect-SecureBootInventory-scriptet og parser JSON-outputen til en CSV-rapport.

    Requires: Microsoft.Graph PowerShell SDK
    Permissions: DeviceManagementScripts.Read.All
                 DeviceManagementManagedDevices.Read.All
.PARAMETER ScriptId
    ID på Proactive Remediation (deviceHealthScript) i Intune.
    Finn den i Intune-portalen eller kjør Get-MgDeviceManagementDeviceHealthScript.
.PARAMETER OutputPath
    Sti for CSV-output. Standard: .\SecureBootInventory_<dato>.csv
.PARAMETER TenantId
    Entra ID tenant-ID (valgfri).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ScriptId,

    [string] $OutputPath = ".\SecureBootInventory_$(Get-Date -Format 'yyyyMMdd').csv",

    [string] $TenantId
)

#region — Auth
$connectParams = @{ Scopes = @('DeviceManagementScripts.Read.All', 'DeviceManagementManagedDevices.Read.All') }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }
Connect-MgGraph @connectParams -NoWelcome
#endregion

#region — Hent deviceRunStates (paginert)
Write-Host "Henter run states for script $ScriptId ..." -ForegroundColor Cyan

$baseUri  = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$ScriptId/deviceRunStates"
$expand   = '?$expand=managedDevice($select=deviceName,userPrincipalName,osVersion,azureADDeviceId)'
$allRuns  = [System.Collections.Generic.List[object]]::new()
$nextUri  = $baseUri + $expand

do {
    $page    = Invoke-MgGraphRequest -Method GET -Uri $nextUri -ErrorAction Stop
    if ($page.value) { $allRuns.AddRange([object[]]$page.value) }
    $nextUri = $page.'@odata.nextLink'
} while ($nextUri)

Write-Host "Hentet $($allRuns.Count) enheter" -ForegroundColor Green
#endregion

#region — Parse og bygg rapport
$report = foreach ($run in $allRuns) {
    $parsed = $null

    if ($run.preRemediationDetectionScriptOutput) {
        try {
            $parsed = $run.preRemediationDetectionScriptOutput | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            # Output er ikke gyldig JSON — script kjørte ikke korrekt
        }
    }

    [PSCustomObject]@{
        DeviceName          = $run.managedDevice.deviceName
        UPN                 = $run.managedDevice.userPrincipalName
        OSVersion           = $run.managedDevice.osVersion
        LastRun             = $run.lastStateUpdateDateTime
        DetectionState      = $run.detectionState
        SecureBoot          = $parsed.SecureBoot
        FirmwareType        = $parsed.FirmwareType
        # Sertifikatstatus — nøkkelfelt for 2026-deadline
        CertStatus          = $parsed.CertStatus          # UpToDate | NeedsUpdate | Unknown | NotApplicable
        DB_Has2023Cert      = $parsed.DB_Has2023Cert
        DB_Has2011Cert      = $parsed.DB_Has2011Cert
        KEK_Has2023Cert     = $parsed.KEK_Has2023Cert
        KEK_Has2011Cert     = $parsed.KEK_Has2011Cert
        # TPM
        TPMPresent          = $parsed.TPMPresent
        TPMReady            = $parsed.TPMReady
        TPMSpecVersion      = $parsed.TPMSpecVersion
        # VBS / HVCI / Credential Guard
        VBSStatus           = $parsed.VBSStatus
        HVCIStatus          = $parsed.HVCIStatus
        CredentialGuard     = $parsed.CredentialGuardStatus
        # Hardware
        Manufacturer        = $parsed.Manufacturer
        Model               = $parsed.Model
        SerialNumber        = $parsed.SerialNumber
        CollectedAt         = $parsed.CollectedAt
        AzureADDeviceId     = $run.managedDevice.azureADDeviceId
        RawOutput           = if (-not $parsed) { $run.preRemediationDetectionScriptOutput } else { $null }
    }
}
#endregion

#region — Output
$report | Sort-Object SecureBoot, DeviceName |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Rapport lagret: $OutputPath" -ForegroundColor Green

Write-Host "`nOppsummering — Sertifikatstatus (2026-deadline):" -ForegroundColor Yellow
$report | Group-Object CertStatus |
    Select-Object @{N='CertStatus'; E={$_.Name}}, @{N='Antall'; E={$_.Count}} |
    Sort-Object Antall -Descending | Format-Table -AutoSize

Write-Host "Oppsummering — Secure Boot:" -ForegroundColor Cyan
$report | Group-Object SecureBoot |
    Select-Object @{N='SecureBoot'; E={$_.Name}}, @{N='Antall'; E={$_.Count}} |
    Sort-Object Antall -Descending | Format-Table -AutoSize

Write-Host "Oppsummering — Firmware:" -ForegroundColor Cyan
$report | Group-Object FirmwareType |
    Select-Object @{N='FirmwareType'; E={$_.Name}}, @{N='Antall'; E={$_.Count}} |
    Sort-Object Antall -Descending | Format-Table -AutoSize

Write-Host "Oppsummering — VBS:" -ForegroundColor Cyan
$report | Group-Object VBSStatus |
    Select-Object @{N='VBSStatus'; E={$_.Name}}, @{N='Antall'; E={$_.Count}} |
    Sort-Object Antall -Descending | Format-Table -AutoSize

Disconnect-MgGraph | Out-Null
#endregion
