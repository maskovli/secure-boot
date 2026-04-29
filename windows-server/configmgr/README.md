# Windows Server - Secure Boot via ConfigMgr

> **Author:** Marius Skovli
> **Created:** 28.02.2026
> **Last updated:** 28.02.2026
> **Status:** ⚠️ **Untested in production** — see warning below

> [!WARNING]
> **The ConfigMgr CI/CB, Run Scripts, CMPivot, and reporting components have not yet been validated end-to-end** against a live ConfigMgr Current Branch site. The PowerShell discovery and inventory logic reuses the byte-parser that has been verified in the Intune and AD/WinRM channels, but the CI compliance rule, Hardware Inventory class extension, and SMS Provider WMI queries have not been exercised yet.
>
> Treat everything in this folder as **beta / reference design** until you have:
> 1. Imported the CI, wrapped it in a CB, and deployed to a pilot collection
> 2. Confirmed the CB returns Compliant for a known-good host
> 3. (Optional) Extended Hardware Inventory and verified `SMS_G_System_SECUREBOOTINVENTORY` populates
> 4. Validated the reporting script returns expected data
>
> Report issues or schema mismatches via a GitHub issue.

Tooling for inventorying Secure Boot certificate state across a ConfigMgr-managed server estate, focused on the **June 2026 expiry of the Microsoft UEFI 2011 certificates**.

This is the third delivery channel in the repository alongside Intune (`windows11/`) and AD/WinRM (`windows-server/scripts/inventory/`). Use this when servers are managed by ConfigMgr Current Branch and you want:

- Compliance evaluation visible in the ConfigMgr console
- Historical reporting via SQL/SMS Provider (offline hosts included)
- Live spot-checks via CMPivot
- Ad-hoc fleet runs via the Run Scripts feature

---

## Why Build This Ourselves

ConfigMgr collects **`SMS_Firmware`** out of the box (two booleans: `UEFI` and `SecureBoot`) and ships a built-in report **"Hardware - Security -> Details of firmware states on devices"**. Neither inspects the contents of the UEFI `db` and `KEK` variables, so neither can tell you whether the 2023 certificates have been deployed. The CI in this folder fills that gap.

---

## Components

| File | Purpose |
|---|---|
| `scripts/Detect-SecureBootInventory-CI.ps1` | Configuration Item discovery script. Runs on each client, parses UEFI db/KEK, writes structured registry data, returns a single status string for the CI Compliance Rule. |
| `scripts/Invoke-SecureBootInventoryRunScript.ps1` | Run Scripts payload. Returns compact JSON as ScriptOutput - for ad-hoc spot-checks without waiting for a CB cycle. |
| `scripts/Get-SecureBootFromConfigMgr.ps1` | Reporting script for the site server. Queries SMS Provider WMI and exports a CSV. |
| `cmpivot/SecureBoot-Inventory.kql` | Five canned CMPivot queries (per-device state, group counts, action list, missing-data check, full thumbprint matrix). |

---

## Deployment Walkthrough

### 1. Create the Configuration Item

1. ConfigMgr console -> **Assets and Compliance** -> **Compliance Settings** -> **Configuration Items** -> **Create**
2. Type: **Windows Desktops and Servers**, name: `Secure Boot - Cert Inventory`
3. Settings tab -> **New** -> Setting Type: **Script**, Data Type: **String**
4. Discovery script: paste `Detect-SecureBootInventory-CI.ps1`, language **PowerShell**
5. Compliance Rules tab -> **New**
   - Selected setting: the script setting from step 4
   - Rule type: **Value**
   - The setting must comply with the following rule: **Equals** `UpToDate`
   - Severity: **Warning** during pilot, **Critical** in production

### 2. Wrap in a Configuration Baseline

1. **Configuration Baselines** -> **Create**, name: `Secure Boot - Cert Inventory`
2. Add the CI you just created
3. Deploy to a server collection (start with a pilot collection of 5-10 hosts)
4. Schedule: **Every 1 day**
5. Tick **Remediate noncompliant rules when supported** = **off** (this CI is detection-only; deploy the 2023-cert policy separately via GPO/Intune)

### 3. (Optional but recommended) Extend Hardware Inventory

This step makes the registry data visible in SQL views and CMPivot, and enables `Get-SecureBootFromConfigMgr.ps1` to report on offline hosts.

1. **Administration** -> **Client Settings** -> Default Client Settings -> **Hardware Inventory** -> **Set Classes** -> **Add** -> **Connect**
2. Connect to a sample host that has already run the CI (so the registry path exists)
3. Browse to `HKLM\SOFTWARE\SecureBootInventory` and select the values to inventory:
   - `CertStatus` (String)
   - `SecureBoot` (DWord)
   - `FirmwareType` (String)
   - `DB_Has2011Cert`, `DB_Has2023Cert`, `KEK_Has2011Cert`, `KEK_Has2023Cert` (DWord)
   - `LastEvaluation` (String)
4. Save the class with a recognizable name, e.g. `SecureBootInventory`
5. The next Hardware Inventory cycle will collect the data into `SMS_G_System_SECUREBOOTINVENTORY` (WMI) and `v_GS_SECUREBOOTINVENTORY` (SQL view)

### 4. Approve and import the Run Script

1. **Software Library** -> **Scripts** -> **Create Script**
2. Name: `Secure Boot Inventory (ad-hoc)`, language: **PowerShell**
3. Paste `Invoke-SecureBootInventoryRunScript.ps1`
4. Approve the script (a different admin must approve - separation of duties)
5. To run: right-click a collection or device -> **Run Script** -> select the script -> **Next** -> **Next**
6. Watch results in **Monitoring** -> **Script Status** - each device's `ScriptOutput` is the JSON document.

### 5. Run a CMPivot live query

1. Right-click the server collection -> **Start CMPivot**
2. Open `cmpivot/SecureBoot-Inventory.kql`, paste the **Query 1** block
3. Run - one row per online device with CertStatus, SecureBoot, FirmwareType, LastEvaluation
4. Export from the CMPivot toolbar if you want a quick CSV

### 6. Generate the full CSV report

On the site server (or a host with the ConfigMgr admin console + PowerShell module):

```powershell
.\Get-SecureBootFromConfigMgr.ps1 `
    -SiteCode PRI `
    -SiteServer cm01.contoso.com `
    -CollectionId PRI00042 `
    -OutputPath C:\Reports\sb-servers.csv
```

The script first tries the custom Hardware Inventory class (richest data, includes offline hosts). If that class doesn't exist, it falls back to Configuration Baseline compliance state.

---

## Output Comparison Across Channels

| Channel | Reach | Latency | Granularity |
|---|---|---|---|
| Intune Proactive Remediation (`windows11/`) | Intune-managed Win11 | ~24h until next run | Full thumbprint detail, JSON |
| AD/WinRM (`windows-server/scripts/inventory/`) | Any AD-joined host with WinRM | Real-time | Full thumbprint detail, CSV |
| ConfigMgr CI/CB (this folder) | ConfigMgr-managed | ~24h CB cycle | CertStatus + bool fields |
| ConfigMgr CMPivot | ConfigMgr-managed, online only | Real-time | Live registry read |
| ConfigMgr Run Scripts | ConfigMgr-managed | Real-time, on-demand | Full JSON per device |

All four channels share the same logic core (`Test-ByteArrayEqual` byte compare + EFI_SIGNATURE_LIST parser) so output is directly comparable.

---

## Reference - UEFI Certificate Thumbprints

| Variable | Certificate | Thumbprint (SHA-1) |
|---|---|---|
| `db`  | Windows UEFI CA 2011  | `580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D` |
| `db`  | Windows UEFI CA 2023  | `45A0FA32604773C82433C3B7D59E7466B3AC0C67` |
| `KEK` | KEK CA 2011           | `31590BFD89C9D74ED087CA28B7C54AC03D55CF72` |
| `KEK` | KEK 2K CA 2023        | `459AB6FB5E284D272D5E3E6ABC8ED663829D632B` |
