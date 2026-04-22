# Secure Boot

Scripts, policies, and documentation for enforcing and monitoring Secure Boot across Windows 11 and Windows Server environments — covering Intune, Azure Arc, ConfigMgr, and GPO.

> [!NOTE]
> Active development is currently focused on **Windows 11 + Intune**. Windows Server coverage (Arc, ConfigMgr, GPO) is being added incrementally.

---

## Scope

| Platform | Management | Status |
|---|---|---|
| Windows 11 | Intune | Active |
| Windows Server 2022/2025 | GPO | Planned |
| Windows Server 2022/2025 | Azure Arc + Intune | Planned |
| Windows Server 2019+ | ConfigMgr (Current Branch) | Planned |

---

## Repository Structure

```
secure-boot/
├── windows11/
│   ├── intune/
│   │   ├── policies/          # OMA-URI / Settings Catalog JSON exports
│   │   ├── compliance/        # Compliance policy JSON exports
│   │   └── scripts/
│   │       ├── detection/     # Proactive Remediation — detection scripts
│   │       └── remediation/   # Proactive Remediation — remediation scripts
│   └── scripts/
│       ├── detection/         # Standalone detection/audit scripts
│       ├── remediation/       # Standalone remediation scripts
│       └── reporting/         # Reporting and inventory scripts
├── windows-server/
│   ├── gpo/                   # ADMX templates and GPO exports
│   ├── arc/                   # Azure Arc + Intune management
│   └── configmgr/
│       ├── detection-methods/ # CI detection methods (PowerShell)
│       ├── compliance-baselines/ # CB exports
│       └── scripts/
├── shared/
│   └── schemas/               # Shared JSON schemas for policy exports
└── docs/
    ├── windows11/
    └── windows-server/
```

---

## Windows 11 — Intune

### What's Covered

- **Compliance policy**: Enforces Secure Boot, TPM 2.0, UEFI firmware, and Code Integrity
- **Proactive Remediation**: Detects non-compliant Secure Boot state and logs/reports
- **Settings Catalog / OMA-URI**: Configures Device Guard and Virtualization-Based Security (VBS)
- **Reporting script**: Inventory of Secure Boot status across all managed devices via Graph API

### Quick Start

1. Import the compliance policy from [`windows11/intune/compliance/`](windows11/intune/compliance/)
2. Deploy the Proactive Remediation from [`windows11/intune/scripts/`](windows11/intune/scripts/)
3. Optionally deploy the Settings Catalog policy from [`windows11/intune/policies/`](windows11/intune/policies/) to enforce Device Guard / VBS

See [`docs/windows11/deployment.md`](docs/windows11/deployment.md) for full walkthrough.

---

## Windows Server

> Coming soon. Will cover:
> - GPO: ADMX-based Secure Boot and UEFI enforcement
> - Azure Arc: Intune policies applied to Arc-enrolled servers
> - ConfigMgr: Compliance Baselines with custom CI for Secure Boot detection

---

## Contributing

Pull requests and issues welcome. Scripts should be idempotent, signed where possible, and follow existing naming conventions.

---

## License

MIT
