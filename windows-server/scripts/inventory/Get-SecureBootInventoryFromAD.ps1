<#
.SYNOPSIS
    Collect Secure Boot inventory from Windows Servers via AD / WinRM.
.DESCRIPTION
    For environments with Active Directory but no Intune or ConfigMgr.
    Targets either an AD OU (via Get-ADComputer) or an explicit list of
    computer names, runs the same Secure Boot inventory logic remotely
    via Invoke-Command, and writes a CSV report.

    Collected per device:
      - Secure Boot on/off, firmware type
      - UEFI db / KEK certificate thumbprints (2011 vs 2023)
      - CertStatus: UpToDate | NeedsUpdate | Unknown | NotApplicable
      - TPM presence/version, VBS / HVCI / Credential Guard state
      - Manufacturer, Model, Serial, OS version

    Requires:
      - PowerShell 5.1+ on the runner
      - ActiveDirectory module (when using -SearchBase)
      - WinRM enabled on targets (Enable-PSRemoting)
      - Credentials with local admin on targets (or current user trusted)

.PARAMETER SearchBase
    AD distinguished name of the OU to enumerate, e.g.
    "OU=Servers,OU=Production,DC=contoso,DC=com".
    All enabled computer accounts under this OU are inventoried.

.PARAMETER ComputerName
    Explicit list of computer names. Mutually exclusive with -SearchBase.

.PARAMETER Credential
    PSCredential with local admin on targets. Optional — defaults to
    current user if Kerberos delegation works.

.PARAMETER ThrottleLimit
    Parallel Invoke-Command fan-out. Default: 32.

.PARAMETER OutputPath
    CSV destination. Default: .\SecureBootInventory_AD_<date>.csv

.EXAMPLE
    .\Get-SecureBootInventoryFromAD.ps1 `
        -SearchBase "OU=Servers,DC=contoso,DC=com" `
        -OutputPath .\servers.csv

.EXAMPLE
    .\Get-SecureBootInventoryFromAD.ps1 `
        -ComputerName SRV01,SRV02,SRV03 `
        -Credential (Get-Credential)

.NOTES
    Author  : Marius Skovli
    Date    : 24.02.2026
    Version : 1.0

    Reference thumbprints (SHA-1):
      Windows UEFI CA 2011 : 580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D (db)
      Windows UEFI CA 2023 : 45A0FA32604773C82433C3B7D59E7466B3AC0C67 (db)
      KEK 2011             : 31590BFD89C9D74ED087CA28B7C54AC03D55CF72 (KEK)
      KEK 2023             : 459AB6FB5E284D272D5E3E6ABC8ED663829D632B (KEK)
#>
[CmdletBinding(DefaultParameterSetName = 'OU')]
param(
    [Parameter(Mandatory, ParameterSetName = 'OU')]
    [string] $SearchBase,

    [Parameter(Mandatory, ParameterSetName = 'Computers')]
    [string[]] $ComputerName,

    [System.Management.Automation.PSCredential] $Credential,

    [ValidateSet('Default','Kerberos','Negotiate','CredSSP','Basic')]
    [string] $Authentication = 'Default',

    [switch] $UseSSL,

    [switch] $UseFQDN,

    [int] $ThrottleLimit = 32,

    [string] $OutputPath = ".\SecureBootInventory_AD_$(Get-Date -Format 'yyyyMMdd').csv"
)

#region — Resolve target list
if ($PSCmdlet.ParameterSetName -eq 'OU') {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not installed. Install RSAT-AD-PowerShell or run from a DC."
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Host "Enumerating computers under: $SearchBase" -ForegroundColor Cyan
    $adComputers = Get-ADComputer -SearchBase $SearchBase -Filter { Enabled -eq $true } `
        -Properties OperatingSystem, DNSHostName
    $targets = if ($UseFQDN) {
        $adComputers.DNSHostName | Where-Object { $_ }
    } else {
        $adComputers.Name | Where-Object { $_ }
    }
    Write-Host "Found $($targets.Count) enabled computer accounts" -ForegroundColor Green
}
else {
    $targets = $ComputerName
    Write-Host "Targeting $($targets.Count) explicit computer(s)" -ForegroundColor Cyan
}

if (-not $targets) { throw "No targets to inventory." }
#endregion

#region — Inventory scriptblock (runs on each remote)
$inventoryScript = {
    function Test-ByteArrayEqual {
        param([byte[]]$A, [byte[]]$B)
        if ($A.Length -ne $B.Length) { return $false }
        for ($i = 0; $i -lt $A.Length; $i++) {
            if ($A[$i] -ne $B[$i]) { return $false }
        }
        return $true
    }

    function Get-UEFIDBCertificates {
        param([string]$Variable)
        try {
            $uefiVar = Get-SecureBootUEFI -Name $Variable -ErrorAction Stop
            $bytes   = $uefiVar.Bytes
        }
        catch { return @() }

        $x509Guid = [byte[]](0xa1,0x59,0xc0,0xa5,0xe4,0x94,0xa7,0x4a,0x87,0xb5,0xab,0x15,0x5c,0x2b,0xf0,0x72)
        $certs    = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
        $offset   = 0

        while ($offset + 28 -le $bytes.Length) {
            $sigTypeGuid = [byte[]]($bytes[$offset..($offset + 15)])
            $sigListSize = [BitConverter]::ToUInt32($bytes, $offset + 16)
            $sigHdrSize  = [BitConverter]::ToUInt32($bytes, $offset + 20)
            $sigSize     = [BitConverter]::ToUInt32($bytes, $offset + 24)
            if ($sigListSize -eq 0) { break }

            if (Test-ByteArrayEqual -A $sigTypeGuid -B $x509Guid) {
                $sigOffset = $offset + 28 + $sigHdrSize
                $listEnd   = $offset + $sigListSize
                while ($sigOffset + $sigSize -le $listEnd) {
                    $certBytes = $bytes[($sigOffset + 16)..($sigOffset + $sigSize - 1)]
                    try {
                        $certs.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$certBytes))
                    } catch {}
                    $sigOffset += $sigSize
                }
            }
            $offset += $sigListSize
        }
        return $certs
    }

    $data = [ordered]@{ ComputerName = $env:COMPUTERNAME }

    # Secure Boot
    try { $data.SecureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
    catch {
        $data.SecureBoot      = $false
        $data.SecureBootError = $_.Exception.Message
    }

    # Firmware type
    $uefiKey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue
    $data.FirmwareType = if ($uefiKey) { 'UEFI' } else { 'Legacy' }

    # Cert thumbprints (uppercase)
    $thumb2011DB  = '580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D'
    $thumb2023DB  = '45A0FA32604773C82433C3B7D59E7466B3AC0C67'
    $thumb2011KEK = '31590BFD89C9D74ED087CA28B7C54AC03D55CF72'
    $thumb2023KEK = '459AB6FB5E284D272D5E3E6ABC8ED663829D632B'

    if ($data.FirmwareType -eq 'UEFI') {
        $dbCerts  = Get-UEFIDBCertificates -Variable 'db'
        $kekCerts = Get-UEFIDBCertificates -Variable 'KEK'

        $dbThumbs  = $dbCerts  | ForEach-Object { $_.Thumbprint.ToUpper() }
        $kekThumbs = $kekCerts | ForEach-Object { $_.Thumbprint.ToUpper() }

        $data.DB_Has2011Cert  = $dbThumbs  -contains $thumb2011DB
        $data.DB_Has2023Cert  = $dbThumbs  -contains $thumb2023DB
        $data.KEK_Has2011Cert = $kekThumbs -contains $thumb2011KEK
        $data.KEK_Has2023Cert = $kekThumbs -contains $thumb2023KEK

        $data.CertStatus = if ($data.DB_Has2023Cert -and $data.KEK_Has2023Cert) {
            'UpToDate'
        } elseif ($data.DB_Has2011Cert -or $data.KEK_Has2011Cert) {
            'NeedsUpdate'
        } else {
            'Unknown'
        }

        $data.DBCertSubjects  = ($dbCerts  | ForEach-Object { $_.Subject }) -join '; '
        $data.KEKCertSubjects = ($kekCerts | ForEach-Object { $_.Subject }) -join '; '
    } else {
        $data.DB_Has2011Cert  = $null
        $data.DB_Has2023Cert  = $null
        $data.KEK_Has2011Cert = $null
        $data.KEK_Has2023Cert = $null
        $data.CertStatus      = 'NotApplicable'
    }

    # TPM
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    $data.TPMPresent   = [bool]$tpm.TpmPresent
    $data.TPMReady     = [bool]$tpm.TpmReady
    $data.TPMEnabled   = [bool]$tpm.TpmEnabled
    $data.TPMActivated = [bool]$tpm.TpmActivated
    $tpmWmi = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    $data.TPMSpecVersion = $tpmWmi.SpecVersion

    # VBS / HVCI / Credential Guard
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($dg) {
        $data.VBSStatus = switch ($dg.VirtualizationBasedSecurityStatus) {
            0 { 'Off' } 1 { 'EnabledNotRunning' } 2 { 'Running' }
            default { "Unknown($($dg.VirtualizationBasedSecurityStatus))" }
        }
        $data.HVCIStatus = switch ($dg.CodeIntegrityPolicyEnforcementStatus) {
            0 { 'Off' } 1 { 'AuditMode' } 2 { 'EnforcementMode' }
            default { "Unknown($($dg.CodeIntegrityPolicyEnforcementStatus))" }
        }
        $data.CredentialGuardStatus = if ($dg.SecurityServicesRunning -contains 1) { 'Running' } else { 'NotRunning' }
    }

    # Hardware / OS
    $cs   = Get-CimInstance Win32_ComputerSystem    -ErrorAction SilentlyContinue
    $bios = Get-CimInstance Win32_BIOS              -ErrorAction SilentlyContinue
    $os   = Get-CimInstance Win32_OperatingSystem   -ErrorAction SilentlyContinue
    $data.Manufacturer = $cs.Manufacturer
    $data.Model        = $cs.Model
    $data.SerialNumber = $bios.SerialNumber
    $data.OSCaption    = $os.Caption
    $data.OSVersion    = $os.Version
    $data.CollectedAt  = (Get-Date -Format 'o')

    [PSCustomObject]$data
}
#endregion

#region — Run remotely
Write-Host "Connecting to $($targets.Count) target(s) (ThrottleLimit=$ThrottleLimit) ..." -ForegroundColor Cyan

$invokeParams = @{
    ComputerName   = $targets
    ScriptBlock    = $inventoryScript
    ThrottleLimit  = $ThrottleLimit
    Authentication = $Authentication
    ErrorAction    = 'SilentlyContinue'
    ErrorVariable  = 'remoteErrors'
}
if ($Credential) { $invokeParams['Credential'] = $Credential }
if ($UseSSL)     { $invokeParams['UseSSL']     = $true }

$results = Invoke-Command @invokeParams

# Build placeholder rows for unreachable targets
$reached = $results | Select-Object -ExpandProperty PSComputerName -Unique
$failed  = $targets | Where-Object {
    $name = $_
    -not ($reached | Where-Object { $_ -eq $name -or $_ -like "$name*" })
}
foreach ($fail in $failed) {
    $err = $remoteErrors | Where-Object { $_.TargetObject -eq $fail } | Select-Object -First 1
    $results += [PSCustomObject]@{
        ComputerName     = $fail
        SecureBoot       = $null
        FirmwareType     = $null
        CertStatus       = 'Unreachable'
        SecureBootError  = if ($err) { $err.Exception.Message } else { 'No response' }
    }
}
#endregion

#region — Output
$results |
    Select-Object ComputerName, SecureBoot, FirmwareType, CertStatus,
                  DB_Has2023Cert, DB_Has2011Cert, KEK_Has2023Cert, KEK_Has2011Cert,
                  TPMPresent, TPMReady, TPMSpecVersion,
                  VBSStatus, HVCIStatus, CredentialGuardStatus,
                  Manufacturer, Model, SerialNumber,
                  OSCaption, OSVersion, CollectedAt,
                  DBCertSubjects, KEKCertSubjects, SecureBootError |
    Sort-Object CertStatus, ComputerName |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nReport saved: $OutputPath" -ForegroundColor Green

Write-Host "`nSummary - CertStatus (June 2026 deadline):" -ForegroundColor Yellow
$results | Group-Object CertStatus |
    Select-Object @{N='CertStatus'; E={$_.Name}}, @{N='Count'; E={$_.Count}} |
    Sort-Object Count -Descending | Format-Table -AutoSize

Write-Host "Summary - Secure Boot:" -ForegroundColor Cyan
$results | Group-Object SecureBoot |
    Select-Object @{N='SecureBoot'; E={$_.Name}}, @{N='Count'; E={$_.Count}} |
    Sort-Object Count -Descending | Format-Table -AutoSize

Write-Host "Summary - Firmware:" -ForegroundColor Cyan
$results | Group-Object FirmwareType |
    Select-Object @{N='FirmwareType'; E={$_.Name}}, @{N='Count'; E={$_.Count}} |
    Sort-Object Count -Descending | Format-Table -AutoSize
#endregion
