<#
.SYNOPSIS
    Proactive Remediation — detection script for Secure Boot inventory harvesting.
.DESCRIPTION
    Collects Secure Boot, TPM, firmware, VBS, HVCI, and Credential Guard state.
    Always exits 0 — this script harvests data only, it does not detect issues.
    Output is captured by Intune as preRemediationDetectionScriptOutput and
    queryable via Graph API on deviceHealthScripts/{id}/deviceRunStates.
.NOTES
    Run as: SYSTEM (64-bit)
    Paired with: NoOp.ps1 (remediation)
#>

$data = [ordered]@{}

# Secure Boot
try {
    $data.SecureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
}
catch {
    $data.SecureBoot = $false
    $data.SecureBootError = $_.Exception.Message
}

# Firmware type
$uefiKey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue
$data.FirmwareType = if ($uefiKey) { 'UEFI' } else { 'Legacy' }

# TPM
$tpm = Get-Tpm -ErrorAction SilentlyContinue
$data.TPMPresent        = [bool]$tpm.TpmPresent
$data.TPMReady          = [bool]$tpm.TpmReady
$data.TPMEnabled        = [bool]$tpm.TpmEnabled
$data.TPMActivated      = [bool]$tpm.TpmActivated

# TPM spec version
$tpmWmi = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
$data.TPMSpecVersion    = $tpmWmi.SpecVersion

# Device Guard / VBS / HVCI / Credential Guard
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($dg) {
    # VirtualizationBasedSecurityStatus: 0=Off, 1=Enabled not running, 2=Running
    $data.VBSStatus = switch ($dg.VirtualizationBasedSecurityStatus) {
        0 { 'Off' }
        1 { 'EnabledNotRunning' }
        2 { 'Running' }
        default { "Unknown($($dg.VirtualizationBasedSecurityStatus))" }
    }
    # CodeIntegrityPolicyEnforcementStatus: 0=Off, 1=AuditMode, 2=EnforcementMode
    $data.HVCIStatus = switch ($dg.CodeIntegrityPolicyEnforcementStatus) {
        0 { 'Off' }
        1 { 'AuditMode' }
        2 { 'EnforcementMode' }
        default { "Unknown($($dg.CodeIntegrityPolicyEnforcementStatus))" }
    }
    # CredentialGuard: 0=Off, 1=Enabled, 2=EnabledWithUEFILock, 3=EnabledWithoutUEFILock
    $data.CredentialGuardStatus = switch (($dg.SecurityServicesRunning -contains 1)) {
        $true  { 'Running' }
        $false { 'NotRunning' }
    }
    $data.VBSHardwareRequirementMet = ($dg.VirtualizationBasedSecurityStatus -ge 1)
}

# Hardware info
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
$data.Manufacturer  = $cs.Manufacturer
$data.Model         = $cs.Model
$data.SerialNumber  = $bios.SerialNumber
$data.CollectedAt   = (Get-Date -Format 'o')

# Output as JSON — captured by Intune as preRemediationDetectionScriptOutput
$data | ConvertTo-Json -Compress

exit 0
