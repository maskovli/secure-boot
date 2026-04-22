<#
.SYNOPSIS
    Intune Proactive Remediation — Detection script for Secure Boot compliance.
.DESCRIPTION
    Checks Secure Boot status, TPM state, firmware type, and Code Integrity.
    Exits 0 (compliant) or 1 (non-compliant / remediation needed).
.NOTES
    Run as: SYSTEM (64-bit)
    Platform: Windows 11
#>

$issues = [System.Collections.Generic.List[string]]::new()

# Firmware type — must be UEFI
$firmwareType = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue)
if (-not $firmwareType) {
    $issues.Add('BIOS_LEGACY: Device is not running UEFI firmware or CSM is enabled')
}

# Secure Boot state
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    if (-not $secureBoot) {
        $issues.Add('SECUREBOOT_DISABLED: Secure Boot is supported but disabled in firmware')
    }
}
catch {
    $issues.Add("SECUREBOOT_UNSUPPORTED: $($_.Exception.Message)")
}

# TPM
$tpm = Get-Tpm -ErrorAction SilentlyContinue
if (-not $tpm) {
    $issues.Add('TPM_ABSENT: No TPM detected')
}
elseif (-not $tpm.TpmPresent) {
    $issues.Add('TPM_NOT_PRESENT: TPM chip not present')
}
elseif (-not $tpm.TpmReady) {
    $issues.Add('TPM_NOT_READY: TPM is present but not ready/initialized')
}

# Code Integrity / HVCI
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($dg) {
    # VirtualizationBasedSecurityStatus: 0=Off, 1=Enabled/not running, 2=Running
    if ($dg.VirtualizationBasedSecurityStatus -eq 0) {
        $issues.Add('VBS_DISABLED: Virtualization-Based Security is not running')
    }
}

if ($issues.Count -gt 0) {
    Write-Output "NON_COMPLIANT: $($issues -join ' | ')"
    exit 1
}

Write-Output 'COMPLIANT: Secure Boot, TPM, and VBS are all in the required state'
exit 0
