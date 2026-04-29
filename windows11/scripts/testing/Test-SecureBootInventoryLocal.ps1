<#
.SYNOPSIS
    Lokal valideringsscript for Secure Boot-inventarharvesting.
.DESCRIPTION
    Kjører samme logikk som Collect-SecureBootInventory.ps1, men med
    fargekodet output og ekstra diagnostikk. Bruk dette til å verifisere
    at maskinen din faktisk har 2023-sertifikatene før du stoler på
    Intune-rapporten.

    Kjør som administrator i et lokalt PowerShell-vindu (eller som
    SYSTEM via psexec -s -i for å reprodusere IME-konteksten).

.EXAMPLE
    # Kjør som lokal admin
    .\Test-SecureBootInventoryLocal.ps1

.EXAMPLE
    # Reproduser SYSTEM-konteksten (krever Sysinternals psexec)
    psexec -s -i powershell.exe -ExecutionPolicy Bypass -File .\Test-SecureBootInventoryLocal.ps1

.NOTES
    Forventet thumbprints:
      Windows UEFI CA 2011 : 580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D (db)
      Windows UEFI CA 2023 : 45A0FA32604773C82433C3B7D59E7466B3AC0C67 (db)
      KEK 2011             : 31590BFD89C9D74ED087CA28B7C54AC03D55CF72 (KEK)
      KEK 2023             : 459AB6FB5E284D272D5E3E6ABC8ED663829D632B (KEK)
#>
[CmdletBinding()]
param()

function Write-Section($title) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkCyan
    Write-Host " $title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor DarkCyan
}

function Write-Pass($msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "  [INFO] $msg" -ForegroundColor Yellow }

#region — Kontekst
Write-Section "1. Kjørekontekst"

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
Write-Info "WhoAmI    : $($identity.Name)"
Write-Info "IsSystem  : $($identity.IsSystem)"
Write-Info "Is64Bit   : $([Environment]::Is64BitProcess)"
Write-Info "PSVersion : $($PSVersionTable.PSVersion)"

$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin -or $identity.IsSystem) {
    Write-Pass "Kjører elevated (Admin eller SYSTEM)"
} else {
    Write-Fail "IKKE elevated — Get-SecureBootUEFI vil sannsynligvis feile"
}
#endregion

#region — Privilegium
Write-Section "2. SeSystemEnvironmentPrivilege"

$whoamiPriv = whoami /priv 2>&1 | Out-String
if ($whoamiPriv -match 'SeSystemEnvironmentPrivilege\s+\S.*?\s+(Enabled|Disabled)') {
    $privState = $Matches[1]
    Write-Info "Token-state før Enable: $privState"
} else {
    Write-Fail "SeSystemEnvironmentPrivilege finnes IKKE i token"
}

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
        bool result = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        if (err != 0) {
            throw new System.ComponentModel.Win32Exception(err,
                "AdjustTokenPrivileges siste-feil: " + err + " (1300=ERROR_NOT_ALL_ASSIGNED)");
        }
        return result;
    }
}
'@ -ErrorAction Stop

try {
    $enableResult = [UEFIPrivilege]::Enable('SeSystemEnvironmentPrivilege')
    if ($enableResult) {
        Write-Pass "AdjustTokenPrivileges returnerte True (privilegium aktivert)"
    } else {
        Write-Fail "AdjustTokenPrivileges returnerte False"
    }
}
catch {
    Write-Fail "Privilegium-aktivering kastet exception: $($_.Exception.Message)"
}

# Sjekk state etter
$whoamiPrivAfter = whoami /priv 2>&1 | Out-String
if ($whoamiPrivAfter -match 'SeSystemEnvironmentPrivilege\s+\S.*?\s+(Enabled|Disabled)') {
    $privStateAfter = $Matches[1]
    if ($privStateAfter -eq 'Enabled') {
        Write-Pass "Token-state etter Enable: Enabled"
    } else {
        Write-Fail "Token-state etter Enable: $privStateAfter — privilegium ikke aktivert!"
    }
}
#endregion

#region — Confirm-SecureBootUEFI
Write-Section "3. Secure Boot på/av"

try {
    $sbState = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($sbState) { Write-Pass "Secure Boot er ENABLED" }
    else          { Write-Fail "Secure Boot er DISABLED" }
}
catch {
    Write-Fail "Confirm-SecureBootUEFI feilet: $($_.Exception.Message)"
}
#endregion

#region — Get-SecureBootUEFI db/KEK
Write-Section "4. Get-SecureBootUEFI db / KEK"

function Test-UEFIVar($name) {
    try {
        $v = Get-SecureBootUEFI -Name $name -ErrorAction Stop
        Write-Pass "Get-SecureBootUEFI -Name '$name' lyktes — $($v.Bytes.Length) bytes"
        return $v
    }
    catch {
        Write-Fail "Get-SecureBootUEFI -Name '$name' feilet: $($_.Exception.Message)"
        return $null
    }
}

$db  = Test-UEFIVar 'db'
$kek = Test-UEFIVar 'KEK'
#endregion

#region — Sertifikat-parsing
Write-Section "5. Sertifikat-parsing og thumbprint-validering"

$thumb2011DB  = '580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D'
$thumb2023DB  = '45A0FA32604773C82433C3B7D59E7466B3AC0C67'
$thumb2011KEK = '31590BFD89C9D74ED087CA28B7C54AC03D55CF72'
$thumb2023KEK = '459AB6FB5E284D272D5E3E6ABC8ED663829D632B'

function Test-ByteArrayEqual {
    param([byte[]]$A, [byte[]]$B)
    if ($A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; $i++) {
        if ($A[$i] -ne $B[$i]) { return $false }
    }
    return $true
}

function Get-CertsFromUEFIBytes {
    param([byte[]]$Bytes)
    $x509Guid = [byte[]](0xa1,0x59,0xc0,0xa5,0xe4,0x94,0xa7,0x4a,0x87,0xb5,0xab,0x15,0x5c,0x2b,0xf0,0x72)
    $certs = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    $offset = 0
    while ($offset + 28 -le $Bytes.Length) {
        $sigTypeGuid = [byte[]]($Bytes[$offset..($offset + 15)])
        $sigListSize = [BitConverter]::ToUInt32($Bytes, $offset + 16)
        $sigHdrSize  = [BitConverter]::ToUInt32($Bytes, $offset + 20)
        $sigSize     = [BitConverter]::ToUInt32($Bytes, $offset + 24)
        if ($sigListSize -eq 0) { break }
        if (Test-ByteArrayEqual -A $sigTypeGuid -B $x509Guid) {
            $sigOffset = $offset + 28 + $sigHdrSize
            $listEnd   = $offset + $sigListSize
            while ($sigOffset + $sigSize -le $listEnd) {
                $certBytes = $Bytes[($sigOffset + 16)..($sigOffset + $sigSize - 1)]
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

function Show-CertReport {
    param($Bytes, $Label, $ExpectedNew, $ExpectedOld)
    if (-not $Bytes) { Write-Fail "${Label}: ingen bytes å parse"; return }
    $certs = Get-CertsFromUEFIBytes -Bytes $Bytes
    Write-Info "$Label inneholder $($certs.Count) X509-sertifikat(er):"
    foreach ($c in $certs) {
        Write-Host ("    Subject    : {0}" -f $c.Subject)
        Write-Host ("    Thumbprint : {0}" -f $c.Thumbprint)
        Write-Host ("    NotAfter   : {0}" -f $c.NotAfter)
        Write-Host ""
    }
    $thumbs = $certs | ForEach-Object { $_.Thumbprint.ToUpper() }
    if ($thumbs -contains $ExpectedNew) { Write-Pass "$Label har 2023-sertifikatet ($ExpectedNew)" }
    else                                { Write-Fail "$Label MANGLER 2023-sertifikatet ($ExpectedNew)" }
    if ($thumbs -contains $ExpectedOld) { Write-Info "$Label har 2011-sertifikatet ($ExpectedOld)" }
    else                                { Write-Info "$Label har IKKE 2011-sertifikatet" }
}

if ($db)  { Show-CertReport -Bytes $db.Bytes  -Label 'db'  -ExpectedNew $thumb2023DB  -ExpectedOld $thumb2011DB }
if ($kek) { Show-CertReport -Bytes $kek.Bytes -Label 'KEK' -ExpectedNew $thumb2023KEK -ExpectedOld $thumb2011KEK }
#endregion

#region — Konklusjon
Write-Section "6. Konklusjon"

if ($db -and $kek) {
    $dbThumbs  = (Get-CertsFromUEFIBytes -Bytes $db.Bytes)  | ForEach-Object { $_.Thumbprint.ToUpper() }
    $kekThumbs = (Get-CertsFromUEFIBytes -Bytes $kek.Bytes) | ForEach-Object { $_.Thumbprint.ToUpper() }

    if (($dbThumbs -contains $thumb2023DB) -and ($kekThumbs -contains $thumb2023KEK)) {
        Write-Pass "CertStatus = UpToDate — 2023-sertifikatene er installert i både db og KEK"
    }
    elseif (($dbThumbs -contains $thumb2011DB) -or ($kekThumbs -contains $thumb2011KEK)) {
        Write-Fail "CertStatus = NeedsUpdate — 2023-sertifikatene mangler (2011 utgår juni 2026)"
    }
    else {
        Write-Fail "CertStatus = Unknown — fant verken 2011 eller 2023-sertifikater"
    }
} else {
    Write-Fail "Kunne ikke lese db/KEK — ingen konklusjon mulig"
}
#endregion
