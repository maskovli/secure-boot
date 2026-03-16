<#
.SYNOPSIS
    Intune Proactive Remediation - Secure Boot inventory shipped to Log Analytics / Sentinel.
.DESCRIPTION
    Runs the same Secure Boot certificate inventory as Collect-SecureBootInventory.ps1
    but sends the result to a Log Analytics workspace via the Logs Ingestion API
    (DCR/DCE-based, replacement for the deprecated HTTP Data Collector API).

    The data lands in a custom table 'SecureBootInventory_CL' which is queryable
    from Microsoft Sentinel. See the KQL pack and README in this folder for
    workbook queries, analytic rules, and hunting queries.

    Always exits 0 - this is a data-harvesting script paired with NoOp.ps1.

    Authentication: OAuth2 client_credentials using a dedicated Entra app
    registration that holds 'Monitoring Metrics Publisher' role on the DCR.
    The client secret is embedded in the script and must be replaced before
    upload to Intune. Rotate the secret on the same cadence as your other
    Intune-deployed credentials (recommended: 6-12 months).

    Future migration: certificate-based auth via Intune-deployed cert removes
    the embedded secret. Out of scope for this version.

.NOTES
    Author  : Marius Skovli
    Date    : 12.03.2026
    Version : 1.0
    Run as  : SYSTEM (64-bit)
    Paired with: NoOp.ps1 (remediation)
    Platform: Windows 11

    Required Azure resources (created once, before deploying the script):
      1. Log Analytics workspace
      2. Custom table 'SecureBootInventory_CL' (DCR-based)
      3. Data Collection Endpoint (DCE) in the same region
      4. Data Collection Rule (DCR) targeting the custom table
      5. Entra app registration with 'Monitoring Metrics Publisher' on the DCR

    Replace the five placeholder constants below before uploading to Intune.
#>

#region - Replace these five constants before uploading to Intune
$TenantId       = '00000000-0000-0000-0000-000000000000'
$AppId          = '00000000-0000-0000-0000-000000000000'
$AppSecret      = 'REPLACE_WITH_CLIENT_SECRET'
$DceEndpoint    = 'https://your-dce-name.region.ingest.monitor.azure.com'
$DcrImmutableId = 'dcr-00000000000000000000000000000000'
$StreamName     = 'Custom-SecureBootInventory_CL'
#endregion

#region - Activate SeSystemEnvironmentPrivilege
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class UEFIPrivilege {
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
        ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct TokPriv1Luid { public int Count; public long Luid; public int Attr; }
    const int SE_PRIVILEGE_ENABLED  = 0x00000002;
    const int TOKEN_QUERY            = 0x00000008;
    const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static bool Enable(string privilege) {
        TokPriv1Luid tp;
        IntPtr htok = IntPtr.Zero;
        OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1; tp.Luid = 0; tp.Attr = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(null, privilege, ref tp.Luid);
        return AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
'@ -ErrorAction SilentlyContinue
[UEFIPrivilege]::Enable('SeSystemEnvironmentPrivilege') | Out-Null
#endregion

#region - Inventory helpers
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
        $bytes = (Get-SecureBootUEFI -Name $Variable -ErrorAction Stop).Bytes
    } catch { return @() }
    $x509Guid = [byte[]](0xa1,0x59,0xc0,0xa5,0xe4,0x94,0xa7,0x4a,0x87,0xb5,0xab,0x15,0x5c,0x2b,0xf0,0x72)
    $certs = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    $offset = 0
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
                try { $certs.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$certBytes)) } catch {}
                $sigOffset += $sigSize
            }
        }
        $offset += $sigListSize
    }
    return $certs
}
#endregion

#region - Collect inventory
$thumb2011DB  = '580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D'
$thumb2023DB  = '45A0FA32604773C82433C3B7D59E7466B3AC0C67'
$thumb2011KEK = '31590BFD89C9D74ED087CA28B7C54AC03D55CF72'
$thumb2023KEK = '459AB6FB5E284D272D5E3E6ABC8ED663829D632B'

$record = [ordered]@{
    TimeGenerated   = (Get-Date).ToUniversalTime().ToString('o')
    DeviceName      = $env:COMPUTERNAME
    SecureBoot      = $false
    FirmwareType    = 'Unknown'
    DB_Has2011Cert  = $false
    DB_Has2023Cert  = $false
    KEK_Has2011Cert = $false
    KEK_Has2023Cert = $false
    CertStatus      = 'Unknown'
    TPMPresent      = $false
    TPMReady        = $false
    TPMSpecVersion  = $null
    VBSStatus       = $null
    HVCIStatus      = $null
    CredentialGuard = $null
    Manufacturer    = $null
    Model           = $null
    SerialNumber    = $null
    OSVersion       = $null
    AzureADDeviceId = $null
}

try { $record.SecureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch {}
$record.FirmwareType = if (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue) { 'UEFI' } else { 'Legacy' }

if ($record.FirmwareType -eq 'UEFI') {
    $dbThumbs  = Get-UEFIDBCertificates -Variable 'db'  | ForEach-Object { $_.Thumbprint.ToUpper() }
    $kekThumbs = Get-UEFIDBCertificates -Variable 'KEK' | ForEach-Object { $_.Thumbprint.ToUpper() }
    $record.DB_Has2011Cert  = $dbThumbs  -contains $thumb2011DB
    $record.DB_Has2023Cert  = $dbThumbs  -contains $thumb2023DB
    $record.KEK_Has2011Cert = $kekThumbs -contains $thumb2011KEK
    $record.KEK_Has2023Cert = $kekThumbs -contains $thumb2023KEK
    $record.CertStatus = if ($record.DB_Has2023Cert -and $record.KEK_Has2023Cert) {
        'UpToDate'
    } elseif ($record.DB_Has2011Cert -or $record.KEK_Has2011Cert) {
        'NeedsUpdate'
    } else { 'Unknown' }
} else {
    $record.CertStatus = 'NotApplicable'
}

$tpm = Get-Tpm -ErrorAction SilentlyContinue
$record.TPMPresent = [bool]$tpm.TpmPresent
$record.TPMReady   = [bool]$tpm.TpmReady
$tpmWmi = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
$record.TPMSpecVersion = $tpmWmi.SpecVersion

$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($dg) {
    $record.VBSStatus = switch ($dg.VirtualizationBasedSecurityStatus) {
        0 { 'Off' } 1 { 'EnabledNotRunning' } 2 { 'Running' } default { "Unknown($($dg.VirtualizationBasedSecurityStatus))" }
    }
    $record.HVCIStatus = switch ($dg.CodeIntegrityPolicyEnforcementStatus) {
        0 { 'Off' } 1 { 'AuditMode' } 2 { 'EnforcementMode' } default { "Unknown($($dg.CodeIntegrityPolicyEnforcementStatus))" }
    }
    $record.CredentialGuard = if ($dg.SecurityServicesRunning -contains 1) { 'Running' } else { 'NotRunning' }
}

$cs   = Get-CimInstance Win32_ComputerSystem  -ErrorAction SilentlyContinue
$bios = Get-CimInstance Win32_BIOS            -ErrorAction SilentlyContinue
$os   = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$record.Manufacturer = $cs.Manufacturer
$record.Model        = $cs.Model
$record.SerialNumber = $bios.SerialNumber
$record.OSVersion    = $os.Version

# AzureAD device ID (best-effort - useful for cross-correlating with Sentinel Intune data)
try {
    $aadJoinInfo = & dsregcmd /status 2>$null
    $aadId = ($aadJoinInfo | Select-String -Pattern 'DeviceId\s*:\s*([0-9a-f-]+)' -ErrorAction SilentlyContinue).Matches.Groups[1].Value
    if ($aadId) { $record.AzureADDeviceId = $aadId }
} catch {}
#endregion

#region - Send to Log Analytics via Logs Ingestion API
function Get-EntraAccessToken {
    param($Tenant, $Client, $Secret)
    $tokenUri = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token"
    $body = @{
        client_id     = $Client
        client_secret = $Secret
        scope         = 'https://monitor.azure.com//.default'
        grant_type    = 'client_credentials'
    }
    $resp = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    return $resp.access_token
}

function Send-LogAnalyticsRecord {
    param($Token, $Endpoint, $DcrId, $Stream, $Payload)
    $uri     = "$Endpoint/dataCollectionRules/$DcrId/streams/$Stream`?api-version=2023-01-01"
    $headers = @{ 'Authorization' = "Bearer $Token"; 'Content-Type' = 'application/json' }
    $body    = @($Payload) | ConvertTo-Json -Depth 5 -Compress
    Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ErrorAction Stop
}

try {
    $token = Get-EntraAccessToken -Tenant $TenantId -Client $AppId -Secret $AppSecret
    Send-LogAnalyticsRecord -Token $token -Endpoint $DceEndpoint -DcrId $DcrImmutableId -Stream $StreamName -Payload $record
    # Compact summary for Intune detection output (visible in console + still queryable via Graph)
    "OK CertStatus=$($record.CertStatus) SecureBoot=$($record.SecureBoot) Firmware=$($record.FirmwareType)"
}
catch {
    # Single retry on transient failures
    Start-Sleep -Seconds 5
    try {
        $token = Get-EntraAccessToken -Tenant $TenantId -Client $AppId -Secret $AppSecret
        Send-LogAnalyticsRecord -Token $token -Endpoint $DceEndpoint -DcrId $DcrImmutableId -Stream $StreamName -Payload $record
        "OK_RETRY CertStatus=$($record.CertStatus)"
    }
    catch {
        "FAIL $($_.Exception.Message)"
    }
}
#endregion

exit 0
