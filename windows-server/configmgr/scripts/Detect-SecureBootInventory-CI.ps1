<#
.SYNOPSIS
    Configuration Manager CI discovery script - Secure Boot certificate inventory.
.DESCRIPTION
    Designed to run as the Discovery Script in a ConfigMgr Configuration Item,
    deployed via a Configuration Baseline to a server collection.

    On each evaluation cycle the script:
      1. Activates SeSystemEnvironmentPrivilege so Get-SecureBootUEFI works as SYSTEM
      2. Reads UEFI db and KEK variables and parses EFI_SIGNATURE_LIST entries
      3. Compares X509 thumbprints against the known 2011 and 2023 CAs
      4. Writes structured data to HKLM:\SOFTWARE\SecureBootInventory
      5. Returns a single status string for the Compliance Rule to evaluate:
            UpToDate | NeedsUpdate | Unknown | NotApplicable

    Pair this with a CI Compliance Rule:
        Setting Type    : Script
        Data Type       : String
        Operator        : Equals
        Value           : UpToDate
        Severity        : Critical (or Warning during pilot)

    Add the CI to a Configuration Baseline and deploy to the server collection
    on a daily evaluation schedule.

    The registry path can be added to Hardware Inventory (see README) so the
    same data flows into the SCCM database for SQL/CMPivot reporting.

.NOTES
    Author  : Marius Skovli
    Date    : 25.02.2026
    Version : 1.0
    Run as  : SYSTEM (configured automatically by the CI engine)
    Platform: Windows Server 2016+ / Windows 10+

    Certificate thumbprints (SHA-1):
      Windows UEFI CA 2011 : 580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D (db)
      Windows UEFI CA 2023 : 45A0FA32604773C82433C3B7D59E7466B3AC0C67 (db)
      KEK 2011             : 31590BFD89C9D74ED087CA28B7C54AC03D55CF72 (KEK)
      KEK 2023             : 459AB6FB5E284D272D5E3E6ABC8ED663829D632B (KEK)
#>

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

#region - Helpers
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
    } catch { return @() }

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
#endregion

#region - Inventory
$thumb2011DB  = '580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D'
$thumb2023DB  = '45A0FA32604773C82433C3B7D59E7466B3AC0C67'
$thumb2011KEK = '31590BFD89C9D74ED087CA28B7C54AC03D55CF72'
$thumb2023KEK = '459AB6FB5E284D272D5E3E6ABC8ED663829D632B'

$state = [ordered]@{
    SecureBoot      = $false
    FirmwareType    = 'Unknown'
    DB_Has2011Cert  = $false
    DB_Has2023Cert  = $false
    KEK_Has2011Cert = $false
    KEK_Has2023Cert = $false
    CertStatus      = 'Unknown'
    LastEvaluation  = (Get-Date -Format 'o')
}

try { $state.SecureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { }

if (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue) {
    $state.FirmwareType = 'UEFI'
} else {
    $state.FirmwareType = 'Legacy'
}

if ($state.FirmwareType -eq 'UEFI') {
    $dbCerts  = Get-UEFIDBCertificates -Variable 'db'
    $kekCerts = Get-UEFIDBCertificates -Variable 'KEK'
    $dbThumbs  = $dbCerts  | ForEach-Object { $_.Thumbprint.ToUpper() }
    $kekThumbs = $kekCerts | ForEach-Object { $_.Thumbprint.ToUpper() }

    $state.DB_Has2011Cert  = $dbThumbs  -contains $thumb2011DB
    $state.DB_Has2023Cert  = $dbThumbs  -contains $thumb2023DB
    $state.KEK_Has2011Cert = $kekThumbs -contains $thumb2011KEK
    $state.KEK_Has2023Cert = $kekThumbs -contains $thumb2023KEK

    $state.CertStatus = if ($state.DB_Has2023Cert -and $state.KEK_Has2023Cert) {
        'UpToDate'
    } elseif ($state.DB_Has2011Cert -or $state.KEK_Has2011Cert) {
        'NeedsUpdate'
    } else {
        'Unknown'
    }
} else {
    $state.CertStatus = 'NotApplicable'
}
#endregion

#region - Persist to registry (queryable via Hardware Inventory + CMPivot)
$regPath = 'HKLM:\SOFTWARE\SecureBootInventory'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

Set-ItemProperty -Path $regPath -Name 'CertStatus'      -Value $state.CertStatus                    -Type String
Set-ItemProperty -Path $regPath -Name 'SecureBoot'      -Value ([int]$state.SecureBoot)             -Type DWord
Set-ItemProperty -Path $regPath -Name 'FirmwareType'    -Value $state.FirmwareType                  -Type String
Set-ItemProperty -Path $regPath -Name 'DB_Has2011Cert'  -Value ([int]$state.DB_Has2011Cert)         -Type DWord
Set-ItemProperty -Path $regPath -Name 'DB_Has2023Cert'  -Value ([int]$state.DB_Has2023Cert)         -Type DWord
Set-ItemProperty -Path $regPath -Name 'KEK_Has2011Cert' -Value ([int]$state.KEK_Has2011Cert)        -Type DWord
Set-ItemProperty -Path $regPath -Name 'KEK_Has2023Cert' -Value ([int]$state.KEK_Has2023Cert)        -Type DWord
Set-ItemProperty -Path $regPath -Name 'LastEvaluation'  -Value $state.LastEvaluation                -Type String
#endregion

# Return the single discovery value for the CI Compliance Rule to evaluate.
# Compliance Rule should be: Equals "UpToDate"
$state.CertStatus
