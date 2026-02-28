<#
.SYNOPSIS
    ConfigMgr Run Scripts feature - ad-hoc Secure Boot inventory.
.DESCRIPTION
    Designed for the ConfigMgr console "Run Script" feature (right-click a
    collection or a single device, select Run Script). Returns a single-line
    JSON document captured by ConfigMgr as ScriptOutput. The administrator
    can pipe each device's output through ConvertFrom-Json to build a quick
    table without waiting for a Configuration Baseline evaluation cycle.

    Use this when:
      - You need fresh data right now (e.g. after deploying the
        EnableSecurebootCertificateUpdates policy, to verify rollout)
      - The CI/CB has not yet evaluated, or the Hardware Inventory cycle
        has not yet collected the registry extension
      - You want to spot-check a single host without configuring a CB

    Run-time constraints (Run Scripts feature):
      - Single .ps1 file, no external dependencies
      - Output captured as a string, max ~4 KB - we emit compact JSON
      - Must be approved by a script approver before execution
      - Runs as SYSTEM by default

    Pipeline pattern (run in console, then export results):
        Get-CMScriptExecutionStatus -CollectionId XXX -ScriptName 'SecureBoot Inventory' |
            ForEach-Object { $_.ScriptOutput | ConvertFrom-Json } |
            Export-Csv .\runscript-secureboot.csv -NoTypeInformation

.NOTES
    Author  : Marius Skovli
    Date    : 26.02.2026
    Version : 1.0
    Run as  : SYSTEM (default for Run Scripts feature)
    Platform: Windows Server 2016+ / Windows 10+
#>

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

$thumb2011DB  = '580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D'
$thumb2023DB  = '45A0FA32604773C82433C3B7D59E7466B3AC0C67'
$thumb2011KEK = '31590BFD89C9D74ED087CA28B7C54AC03D55CF72'
$thumb2023KEK = '459AB6FB5E284D272D5E3E6ABC8ED663829D632B'

$data = [ordered]@{
    ComputerName    = $env:COMPUTERNAME
    SecureBoot      = $false
    FirmwareType    = 'Unknown'
    DB_Has2011Cert  = $false
    DB_Has2023Cert  = $false
    KEK_Has2011Cert = $false
    KEK_Has2023Cert = $false
    CertStatus      = 'Unknown'
    CollectedAt     = (Get-Date -Format 'o')
}

try { $data.SecureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch {}
$data.FirmwareType = if (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue) { 'UEFI' } else { 'Legacy' }

if ($data.FirmwareType -eq 'UEFI') {
    $dbThumbs  = Get-UEFIDBCertificates -Variable 'db'  | ForEach-Object { $_.Thumbprint.ToUpper() }
    $kekThumbs = Get-UEFIDBCertificates -Variable 'KEK' | ForEach-Object { $_.Thumbprint.ToUpper() }
    $data.DB_Has2011Cert  = $dbThumbs  -contains $thumb2011DB
    $data.DB_Has2023Cert  = $dbThumbs  -contains $thumb2023DB
    $data.KEK_Has2011Cert = $kekThumbs -contains $thumb2011KEK
    $data.KEK_Has2023Cert = $kekThumbs -contains $thumb2023KEK
    $data.CertStatus = if ($data.DB_Has2023Cert -and $data.KEK_Has2023Cert) {
        'UpToDate'
    } elseif ($data.DB_Has2011Cert -or $data.KEK_Has2011Cert) {
        'NeedsUpdate'
    } else { 'Unknown' }
} else {
    $data.CertStatus = 'NotApplicable'
}

# Return compact JSON - captured as ScriptOutput by Run Scripts feature
$data | ConvertTo-Json -Compress
