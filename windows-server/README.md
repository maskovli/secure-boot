# Windows Server — Secure Boot

> **Author:** Marius Skovli
> **Created:** 17.01.2026
> **Last updated:** 24.02.2026

Tooling and documentation for inventorying, enforcing, and remediating Secure Boot across Windows Server estates that are managed via Active Directory, Group Policy, Azure Arc, or ConfigMgr — i.e. environments without Intune.

---

## Why Secure Boot Matters on Servers

Servers running with **Secure Boot enabled** rely on the firmware-stored UEFI signature databases (`db` and `KEK`) to validate every signed boot component. Microsoft's **Windows UEFI CA 2011** and **Microsoft Corporation KEK CA 2011** certificates **expire in June 2026**. Servers that have not received the **2023 replacements** (`Windows UEFI CA 2023` and `Microsoft Corporation KEK 2K CA 2023`) before that date will eventually be unable to verify newly-signed bootloaders or firmware updates.

For server estates not enrolled in Intune, this becomes a manual planning exercise — but only if you can see the current state across every server. That is the gap this section fills.

---

## What's Available Now

### `scripts/inventory/Get-SecureBootInventoryFromAD.ps1`

Production-ready PowerShell script that:

- Targets either an **AD OU** (via `Get-ADComputer`) or an **explicit list of computer names**.
- Fans out in parallel via `Invoke-Command` (`-ThrottleLimit`, default 32).
- Collects per-server: Secure Boot state, firmware type, UEFI `db`/`KEK` certificate thumbprints (2011 vs 2023), `CertStatus` classification (`UpToDate` / `NeedsUpdate` / `Unknown` / `NotApplicable`), TPM presence/version, VBS / HVCI / Credential Guard state, manufacturer, model, serial, OS.
- Supports `-Authentication` (`Default|Kerberos|Negotiate|CredSSP|Basic`), `-UseSSL`, and `-UseFQDN` for hardened hosts (DMZ, NDES servers, cross-forest).
- Surfaces unreachable hosts with `CertStatus = Unreachable` and the WinRM error in the CSV — no machine is silently dropped.

#### Example

```powershell
# Inventory an entire Servers OU using FQDN (recommended for Kerberos)
.\Get-SecureBootInventoryFromAD.ps1 `
    -SearchBase "OU=Servers,DC=contoso,DC=com" `
    -UseFQDN `
    -OutputPath C:\Reports\servers-secureboot.csv

# Single hardened host with explicit credentials and Negotiate (NTLM fallback)
.\Get-SecureBootInventoryFromAD.ps1 `
    -ComputerName SRV-NDES01.contoso.com `
    -Authentication Negotiate `
    -Credential (Get-Credential)
```

#### Prerequisites

- PowerShell 5.1+ on the runner.
- `ActiveDirectory` module (RSAT-AD-PowerShell) when using `-SearchBase`.
- WinRM enabled on targets (`Enable-PSRemoting -Force`).
- Local administrator on targets (Confirm-SecureBootUEFI / Get-SecureBootUEFI require elevation).

---

## Planned Coverage

### GPO (`gpo/`)
- ADMX-based deployment of `EnableSecurebootCertificateUpdates = 22852` (the 2023 cert deployment policy).
- Registry templates for environments without an Intune-equivalent CSP path.
- Startup security policy export format.

### Azure Arc (`arc/`)
- Intune policies applied to Arc-enrolled servers.
- Azure Policy definitions for Secure Boot / TPM / 2023-certificate compliance.
- Arc-specific detection scripts that surface state in Azure Resource Graph.

### ConfigMgr (`configmgr/`)
- Configuration Items with PowerShell detection methods (re-using the Intune detection logic).
- Compliance Baseline exports.
- Hardware Inventory extensions for Secure Boot state.
- Client-side reporting scripts.

---

## Prerequisites by Approach

| Feature | Minimum version |
|---|---|
| AD/WinRM inventory (this repo) | Windows Server 2016+ with WinRM enabled |
| Azure Arc + Intune management | Windows Server 2019 + Arc agent |
| ConfigMgr Compliance Baselines | Current Branch 2203+ |
| GPO UEFI Secure Boot settings | Windows Server 2016+ |

---

## Reference — UEFI Certificate Thumbprints

| Variable | Certificate | Thumbprint (SHA-1) |
|---|---|---|
| `db`  | Windows UEFI CA 2011  | `580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D` |
| `db`  | Windows UEFI CA 2023  | `45A0FA32604773C82433C3B7D59E7466B3AC0C67` |
| `KEK` | KEK CA 2011           | `31590BFD89C9D74ED087CA28B7C54AC03D55CF72` |
| `KEK` | KEK 2K CA 2023        | `459AB6FB5E284D272D5E3E6ABC8ED663829D632B` |
