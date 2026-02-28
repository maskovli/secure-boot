# Windows 11 — Secure Boot Deployment Guide (Intune)

> **Author:** Marius Skovli
> **Created:** 20.01.2026
> **Last updated:** 06.02.2026

This guide walks through deploying Secure Boot compliance, the 2023 certificate update (June 2026 deadline), Device Guard / VBS, and the inventory Proactive Remediation against an Intune-managed Windows 11 fleet.

## Prerequisites

- Intune tenant with enrolled Windows 11 devices
- Devices must support UEFI firmware (not legacy BIOS)
- TPM 2.0 required for full compliance
- Admin role: Intune Administrator or equivalent

---

## 1. Compliance Policy

**File:** [`windows11/intune/compliance/secureboot-compliance.json`](../../windows11/intune/compliance/secureboot-compliance.json)

**What it checks:**
| Setting | Required value |
|---|---|
| Secure Boot | Enabled |
| TPM | Present (2.0 preferred) |
| Firmware type | UEFI |
| Code Integrity | Enabled |
| OS Drive encryption | BitLocker (optional, recommended) |

**Import steps:**
1. Intune portal → **Devices** → **Compliance** → **Create policy**
2. Platform: **Windows 10 and later**
3. Use **Import** if available, or manually recreate settings from JSON
4. Assign to target group (start with a pilot group)
5. Set non-compliance action: **Mark device noncompliant** after 0 days (or grace period as needed)

> [!WARNING]
> Do not set Conditional Access blocks immediately. Monitor compliance state for 1–2 weeks before enforcing access restrictions.

---

## 2. Proactive Remediation

**Files:**
- Detection: [`windows11/intune/scripts/detection/Detect-SecureBoot.ps1`](../../windows11/intune/scripts/detection/Detect-SecureBoot.ps1)
- Remediation: [`windows11/intune/scripts/remediation/Remediate-SecureBoot.ps1`](../../windows11/intune/scripts/remediation/Remediate-SecureBoot.ps1)

> [!NOTE]
> Secure Boot cannot be enabled programmatically from within Windows. The remediation script notifies the user and logs the issue for helpdesk follow-up.

**Deploy steps:**
1. Intune portal → **Devices** → **Remediations** → **Create**
2. Upload detection and remediation scripts
3. Run as: **System** (64-bit)
4. Schedule: Daily
5. Assign to the same group as the compliance policy

---

## 3. Device Guard / VBS Policy (Settings Catalog)

**File:** [`windows11/intune/policies/deviceguard-vbs.json`](../../windows11/intune/policies/deviceguard-vbs.json)

Configures:
- Virtualization-Based Security (VBS) — enabled
- Platform Security Level — Secure Boot + DMA protection
- Hypervisor-Protected Code Integrity (HVCI) — enabled (audit or enforce)

> [!CAUTION]
> HVCI/Memory Integrity can cause issues with older drivers. Start in **Audit** mode and review Event ID 3099/3064 in the **Microsoft-Windows-CodeIntegrity/Operational** log before switching to **Enforce**.

**Import steps:**
1. Intune portal → **Devices** → **Configuration** → **Create** → **Settings Catalog**
2. Search for and add: **Device Guard** settings
3. Or import the JSON template directly if using Graph API / Intune export format

---

## 4. Verification

After policy assignment and device check-in:

```powershell
# On device — verify Secure Boot
Confirm-SecureBootUEFI

# On device — verify VBS / HVCI
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, CodeIntegrityPolicyEnforcementStatus
```

In Intune: **Devices** → select device → **Device compliance** to see per-setting status.

---

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `Confirm-SecureBootUEFI` throws exception | Legacy BIOS / CSM enabled | Enable UEFI mode in firmware, disable CSM |
| Secure Boot present but disabled | Disabled in UEFI settings | Enable in firmware — cannot be done from OS |
| HVCI causes BSOD / driver issues | Incompatible driver | Identify driver via Event 3099, get updated driver or exclude |
| Device shows compliant but Secure Boot is off | Compliance policy not yet synced | Trigger manual sync: `Start-Process -FilePath "C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe"` |
