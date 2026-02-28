<#
.SYNOPSIS
    Proactive Remediation — detection script for Secure Boot inventory harvesting.
.DESCRIPTION
    Collects Secure Boot state, UEFI DB/KEK certificate versions (2011 vs 2023),
    TPM, firmware, VBS, HVCI, and Credential Guard state.
    Always exits 0 — this script harvests data only, it does not detect issues.
    Output is captured by Intune as preRemediationDetectionScriptOutput and
    queryable via Graph API on deviceHealthScripts/{id}/deviceRunStates.
.NOTES
    Author  : Marius Skovli
    Date    : 03.02.2026
    Version : 1.0
    Run as  : SYSTEM (64-bit)
    Paired with: NoOp.ps1 (remediation)

    Certificate thumbprints (SHA-1):
      Windows UEFI CA 2011 : 580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D (db)
      Windows UEFI CA 2023 : 45A0FA32604773C82433C3B7D59E7466B3AC0C67 (db)
      KEK 2011             : 31590BFD89C9D74ED087CA28B7C54AC03D55CF72 (KEK)
      KEK 2023             : 459AB6FB5E284D272D5E3E6ABC8ED663829D632B (KEK)
#>

#region — Aktiver SeSystemEnvironmentPrivilege (påkrevd for Get-SecureBootUEFI som SYSTEM via IME)
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

$script:PrivilegeEnableResult = $null
try {
    $script:PrivilegeEnableResult = [UEFIPrivilege]::Enable('SeSystemEnvironmentPrivilege')
}
catch {
    $script:PrivilegeEnableResult = "Exception: $($_.Exception.Message)"
}
#endregion

#region — Helper: parse UEFI EFI_SIGNATURE_LIST and extract X509 certs
$script:UEFIQueryErrors = @{}
$script:UEFIQueryBytes  = @{}

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
        $script:UEFIQueryBytes[$Variable] = $bytes.Length
    }
    catch {
        $script:UEFIQueryErrors[$Variable] = $_.Exception.Message
        return @()
    }

    # EFI_CERT_X509_GUID = {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}
    $x509Guid = [byte[]](0xa1,0x59,0xc0,0xa5,0xe4,0x94,0xa7,0x4a,0x87,0xb5,0xab,0x15,0x5c,0x2b,0xf0,0x72)

    $certs  = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
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
                # Each signature: 16-byte owner GUID + cert DER bytes
                $certBytes = $bytes[($sigOffset + 16)..($sigOffset + $sigSize - 1)]
                try {
                    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$certBytes)
                    $certs.Add($cert)
                }
                catch {}
                $sigOffset += $sigSize
            }
        }
        $offset += $sigListSize
    }
    return $certs
}
#endregion

$data = [ordered]@{}

#region — Secure Boot on/off
try {
    $data.SecureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
}
catch {
    $data.SecureBoot      = $false
    $data.SecureBootError = $_.Exception.Message
}
#endregion

#region — Firmware type
$uefiKey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue
$data.FirmwareType = if ($uefiKey) { 'UEFI' } else { 'Legacy' }
#endregion

#region — Secure Boot DB/KEK certificate versions
# Thumbprints to check (SHA-1, uppercase no dashes)
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

    # Overall cert readiness:
    #   UpToDate       = 2023 certs present
    #   NeedsUpdate    = 2023 missing (2011 expiry June 2026)
    #   LegacyOnly     = only 2011 certs found
    $data.CertStatus = if ($data.DB_Has2023Cert -and $data.KEK_Has2023Cert) {
        'UpToDate'
    } elseif ($data.DB_Has2011Cert -or $data.KEK_Has2011Cert) {
        'NeedsUpdate'
    } else {
        'Unknown'
    }
}
else {
    $data.DB_Has2011Cert  = $null
    $data.DB_Has2023Cert  = $null
    $data.KEK_Has2011Cert = $null
    $data.KEK_Has2023Cert = $null
    $data.CertStatus      = 'NotApplicable'
}
#endregion

#region — TPM
$tpm = Get-Tpm -ErrorAction SilentlyContinue
$data.TPMPresent     = [bool]$tpm.TpmPresent
$data.TPMReady       = [bool]$tpm.TpmReady
$data.TPMEnabled     = [bool]$tpm.TpmEnabled
$data.TPMActivated   = [bool]$tpm.TpmActivated

$tpmWmi = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
$data.TPMSpecVersion = $tpmWmi.SpecVersion
#endregion

#region — VBS / HVCI / Credential Guard
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
    $data.CredentialGuardStatus   = if ($dg.SecurityServicesRunning -contains 1) { 'Running' } else { 'NotRunning' }
    $data.VBSHardwareRequirementMet = ($dg.VirtualizationBasedSecurityStatus -ge 1)
}
#endregion

#region — Hardware
$cs   = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$bios = Get-CimInstance Win32_BIOS          -ErrorAction SilentlyContinue
$data.Manufacturer = $cs.Manufacturer
$data.Model        = $cs.Model
$data.SerialNumber = $bios.SerialNumber
$data.CollectedAt  = (Get-Date -Format 'o')
#endregion

#region — Diagnostikk (for å feilsøke hvorfor cert-data mangler)
$data.Diag_PrivilegeEnableResult = "$script:PrivilegeEnableResult"
$data.Diag_DBQueryError          = $script:UEFIQueryErrors['db']
$data.Diag_KEKQueryError         = $script:UEFIQueryErrors['KEK']
$data.Diag_DBBytes               = $script:UEFIQueryBytes['db']
$data.Diag_KEKBytes              = $script:UEFIQueryBytes['KEK']
$data.Diag_PSVersion             = $PSVersionTable.PSVersion.ToString()
$data.Diag_WhoAmI                = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { 'unknown' }
$data.Diag_Is64Bit               = [Environment]::Is64BitProcess
#endregion

$data | ConvertTo-Json -Compress
exit 0
