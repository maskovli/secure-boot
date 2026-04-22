# Windows 11 — Secure Boot Troubleshooting

## Quick Diagnostics

Run this on the affected device (as admin) to get a full picture:

```powershell
# SecureBoot
try { $sb = Confirm-SecureBootUEFI } catch { $sb = "Not supported (legacy BIOS or CSM)" }

# TPM
$tpm = Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManagedAuthLevel

# Firmware type
$fw = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State -EA SilentlyContinue).UEFISecureBootEnabled

# Device Guard
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -EA SilentlyContinue

[PSCustomObject]@{
    SecureBoot        = $sb
    FirmwareUEFI      = $fw
    TPMPresent        = $tpm.TpmPresent
    TPMReady          = $tpm.TpmReady
    VBSStatus         = $dg.VirtualizationBasedSecurityStatus
    HVCIStatus        = $dg.CodeIntegrityPolicyEnforcementStatus
}
```

---

## Common Issues

### Confirm-SecureBootUEFI throws "Cmdlet not supported on this platform"

The device is running in legacy BIOS mode (or CSM is enabled).

**Resolution:**
1. Enter firmware settings (usually F2/Del/F12 at POST)
2. Disable CSM / Legacy Boot
3. Enable UEFI mode
4. Re-install Windows if previously installed in legacy mode (disk must be GPT)

---

### Secure Boot is supported but shows as disabled

Secure Boot is present in firmware but turned off.

**Resolution:** Enable manually in firmware settings. This cannot be done remotely via software.

For fleet-wide remediation, raise a helpdesk ticket process or use SCCM/WinPE-based tooling for on-site enablement at next hardware touch.

---

### HVCI / Memory Integrity causes Blue Screen or driver errors

A kernel driver is incompatible with HVCI.

**Resolution:**
1. Check **Event Viewer** → `Microsoft-Windows-CodeIntegrity/Operational`
   - Event ID **3099**: driver blocked by HVCI
   - Event ID **3064**: driver not compatible
2. Identify the driver and get an updated version from the vendor
3. If no update is available, add a policy exception or switch HVCI to Audit mode temporarily

---

### Intune compliance shows "Not evaluated" for Secure Boot

Device has not yet checked in since the policy was assigned.

**Trigger manual sync:**
```powershell
# Option 1 — via IME
Get-Service -Name IntuneManagementExtension | Restart-Service -Force

# Option 2 — via Settings
# Settings → Accounts → Access work or school → Info → Sync
```

---

### TPM shows as present but not ready

TPM may need to be initialized or ownership taken.

**Resolution:**
```powershell
Initialize-Tpm -AllowClear -AllowPhysicalPresence
```
Or clear TPM ownership in firmware settings and let Windows reclaim it on next boot.

---

## Event IDs to Know

| Source | Event ID | Meaning |
|---|---|---|
| Microsoft-Windows-Kernel-Boot | 16 | Secure Boot violation detected at boot |
| Microsoft-Windows-CodeIntegrity/Operational | 3064 | Driver loaded but not HVCI compatible |
| Microsoft-Windows-CodeIntegrity/Operational | 3099 | Driver blocked by HVCI enforcement |
| Microsoft-Windows-Security-Auditing | 4826 | Boot Configuration Data loaded |
| TPM-WMI | 1796 | TPM ownership/auth change |
