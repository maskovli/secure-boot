# Windows Server — Secure Boot

> **Status: Planned** — Active development is focused on Windows 11 + Intune. This section will be added incrementally.

## Planned Coverage

### GPO (`gpo/`)
- ADMX-based Secure Boot enforcement
- UEFI firmware policy templates
- Startup security policy export format

### Azure Arc (`arc/`)
- Intune policies applied to Arc-enrolled servers
- Azure Policy definitions for Secure Boot / TPM compliance
- Arc-specific detection scripts

### ConfigMgr (`configmgr/`)
- Configuration Items with PowerShell detection methods
- Compliance Baseline exports
- Hardware Inventory extensions for Secure Boot state
- Client-side detection and reporting scripts

## Prerequisites

| Feature | Minimum version |
|---|---|
| Azure Arc + Intune management | Windows Server 2019 + Arc agent |
| ConfigMgr Compliance Baselines | Current Branch 2203+ |
| GPO UEFI Secure Boot settings | Windows Server 2016+ |
