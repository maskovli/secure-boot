# Secure Boot

Scripts, policies, and documentation for enforcing, monitoring, and inventorying Secure Boot across Windows 11 and Windows Server estates — covering Intune, Active Directory, GPO, Azure Arc, and ConfigMgr.

> **Author:** Marius Skovli
> **Created:** 15.01.2026
> **Last updated:** 24.02.2026

> [!NOTE]
> Active development is currently focused on **Windows 11 + Intune** and **Windows Server inventory via AD/WinRM**. ConfigMgr and Azure Arc coverage is being added incrementally.

---

## Why This Repository Exists

Microsoft's **Windows UEFI CA 2011** and **Microsoft Corporation KEK CA 2011** certificates expire in **June 2026**. Every Windows device with Secure Boot enabled must have the **2023 replacement certificates** (`Windows UEFI CA 2023` and `Microsoft Corporation KEK 2K CA 2023`) installed in firmware before that deadline, or it will eventually fail to boot signed bootloaders and updates.

This repository provides a complete tooling chain to:

1. **Inventory** — discover the Secure Boot certificate state across an entire estate (clients via Intune, servers via AD/WinRM).
2. **Deploy** — push the 2023 certificate update via Intune Settings Catalog / OMA-URI (`SecureBoot/EnableSecurebootCertificateUpdates = 22852`) or GPO.
3. **Verify** — confirm 2023 certificates are present in the UEFI `db` and `KEK` variables, with full chain detail per device.
4. **Report** — generate CSV reports for compliance evidence and migration planning.

---

## Scope

| Platform | Management | Status |
|---|---|---|
| Windows 11 | Intune (Compliance + Proactive Remediation) | Active — production-ready |
| Windows 11 | Local validation (PowerShell) | Active — production-ready |
| Windows Server 2016+ | Active Directory + WinRM | Active — production-ready |
| Windows Server 2022/2025 | GPO | Planned |
| Windows Server 2022/2025 | Azure Arc + Intune | Planned |
| Windows Server 2019+ | ConfigMgr (Current Branch) | Planned |

---

## Repository Structure

```
secure-boot/
├── windows11/
│   ├── intune/
│   │   ├── policies/                # OMA-URI / Settings Catalog JSON exports
│   │   ├── compliance/              # Compliance policy JSON exports
│   │   └── scripts/
│   │       ├── detection/           # Proactive Remediation detection scripts
│   │       └── remediation/         # Proactive Remediation remediation scripts
│   └── scripts/
│       ├── reporting/               # Graph API reporting (CSV)
│       └── testing/                 # Local validation tooling
├── windows-server/
│   ├── scripts/
│   │   └── inventory/               # AD/WinRM inventory harvester
│   ├── gpo/                         # ADMX templates and GPO exports (planned)
│   ├── arc/                         # Azure Arc + Intune (planned)
│   └── configmgr/                   # CIs and Compliance Baselines (planned)
├── shared/
│   └── schemas/                     # Shared JSON schemas for policy exports
└── docs/
    └── windows11/                   # Deployment + troubleshooting guides
```

---

## Windows 11 — Intune

### What's Covered

| Component | File | Purpose |
|---|---|---|
| Compliance policy | `windows11/intune/compliance/secureboot-compliance.json` | Enforces Secure Boot, TPM 2.0, UEFI, Code Integrity |
| Settings Catalog (DG/VBS) | `windows11/intune/policies/deviceguard-vbs.json` | VBS, HVCI, Credential Guard, Secure Launch |
| Settings Catalog (2023 cert) | `windows11/intune/policies/secureboot-cert-update-2023.json` | Deploys Windows UEFI CA 2023 + KEK 2023 |
| Proactive Remediation (basic) | `Detect-SecureBoot.ps1` + `Remediate-SecureBoot.ps1` | Compliance check with helpdesk notification |
| Proactive Remediation (full inventory) | `Collect-SecureBootInventory.ps1` + `NoOp.ps1` | Harvests cert thumbprints, TPM, VBS state |
| Reporting (compliance) | `Get-SecureBootFromComplianceData.ps1` | Tenant-wide Secure Boot compliance via Graph |
| Reporting (cert inventory) | `Get-SecureBootFromRemediation.ps1` | Per-device 2011/2023 cert state via Graph |
| Local validation | `Test-SecureBootInventoryLocal.ps1` | Manual PC validation with color-coded output |

### Quick Start

1. **Import the compliance policy** from `windows11/intune/compliance/`.
2. **Deploy the cert-update Settings Catalog policy** from `windows11/intune/policies/secureboot-cert-update-2023.json`.
3. **Deploy the inventory Proactive Remediation** from `windows11/intune/scripts/`.
4. **After at least one device run state**, generate a CSV report with `Get-SecureBootFromRemediation.ps1`.

See [`docs/windows11/deployment.md`](docs/windows11/deployment.md) for the full walkthrough and [`docs/windows11/troubleshooting.md`](docs/windows11/troubleshooting.md) for common issues.

---

## Windows Server — Active Directory / WinRM

For server estates without Intune or ConfigMgr.

`windows-server/scripts/inventory/Get-SecureBootInventoryFromAD.ps1` enumerates either:
- An AD OU (`-SearchBase "OU=Servers,DC=contoso,DC=com"`), or
- An explicit list of computer names (`-ComputerName SRV01,SRV02`)

…and fans out via `Invoke-Command` (parallel, throttled) to collect the same Secure Boot inventory data — Secure Boot state, db/KEK 2011 vs 2023 thumbprints, `CertStatus`, TPM, VBS/HVCI, Credential Guard, hardware/OS — into a CSV.

Optional `-Authentication`, `-UseSSL`, and `-UseFQDN` parameters cover Kerberos SPN issues and DMZ/hardened hosts.

---

## Key Reference — UEFI Certificate Thumbprints

| Variable | Certificate | Thumbprint (SHA-1) |
|---|---|---|
| `db`  | Windows UEFI CA 2011  | `580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D` |
| `db`  | Windows UEFI CA 2023  | `45A0FA32604773C82433C3B7D59E7466B3AC0C67` |
| `KEK` | KEK CA 2011           | `31590BFD89C9D74ED087CA28B7C54AC03D55CF72` |
| `KEK` | KEK 2K CA 2023        | `459AB6FB5E284D272D5E3E6ABC8ED663829D632B` |

---

## Contributing

Pull requests and issues welcome. Scripts should be idempotent, ASCII-safe (PowerShell 5.1 reads `.ps1` files without BOM as ANSI), and follow existing naming conventions.

---

## License

MIT
