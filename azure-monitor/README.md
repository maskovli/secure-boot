# Azure Monitor / Sentinel - Secure Boot Inventory

> **Author:** Marius Skovli
> **Created:** 16.03.2026
> **Last updated:** 16.03.2026
> **Status:** ⚠️ **Untested in production** — see warning below

> [!WARNING]
> **This integration has not yet been validated end-to-end against a live Log Analytics workspace.** The PowerShell payload reuses the same byte-parser and certificate-detection logic that has been verified in the Intune Proactive Remediation channel, but the DCE/DCR/app-registration pipeline and the KQL queries have not been exercised on real ingested data yet.
>
> Treat everything in this folder as **beta / reference design** until you have:
> 1. Created the workspace, custom table, DCE, DCR, and app registration in a non-production tenant
> 2. Confirmed at least one record arrives in `SecureBootInventory_CL` with the expected schema
> 3. Validated each KQL query block against that data
>
> Report issues or schema mismatches via a GitHub issue.

Fourth delivery channel for Secure Boot certificate inventory: ship the same per-device data from **Intune-managed Windows 11 devices** to a **Log Analytics workspace** so it can be queried, alerted on, and visualized in **Microsoft Sentinel**.

This complements (does not replace) the Intune Proactive Remediation channel. Both can run in parallel: Intune captures `preRemediationDetectionScriptOutput` for Graph API queries, Log Analytics gets the same record for Sentinel-side analytics, retention, and cross-source correlation.

---

## Why Send to Log Analytics / Sentinel

| Capability | Intune-only (Graph API) | Log Analytics / Sentinel |
|---|---|---|
| Per-device latest state | Yes | Yes |
| Historical trend / change detection | No (snapshot only) | Yes (configurable retention) |
| Cross-source correlation (Intune + Sign-in + EDR) | No | Yes |
| Scheduled analytic rules / incidents | No | Yes |
| Workbooks / dashboards | Limited | Full Sentinel workbooks |
| Hunting queries (KQL) | No | Yes |
| Long-term archive | 30 days | Up to 12 years (Auxiliary tier) |

For the **June 2026 cert deadline** specifically, Sentinel gives you:
- A trend chart showing 2023-cert rollout progress over time
- An alert when a device regresses from `UpToDate` to `NeedsUpdate`
- A countdown analytic rule that escalates as deadline approaches
- Joins with `IntuneDevices` table for UPN-level enrichment

---

## Architecture

```
Windows 11 device (Intune-enrolled)
    |
    | Send-SecureBootInventoryToLogAnalytics.ps1
    | (Intune Proactive Remediation, runs as SYSTEM)
    | - SeSystemEnvironmentPrivilege activation
    | - UEFI db/KEK parse, cert thumbprint check
    | - OAuth2 client_credentials -> Entra app
    | - HTTPS POST JSON record
    v
Data Collection Endpoint (DCE)
    |
    v
Data Collection Rule (DCR) -- schema validation, optional KQL transform
    |
    v
Log Analytics workspace
    |- Custom table: SecureBootInventory_CL
    |
    v
Microsoft Sentinel
    |- Workbooks (rollout progress, OEM breakdown)
    |- Analytic rules (regression, deadline countdown)
    |- Hunting queries (KQL)
    |- Cross-table joins (IntuneDevices, SigninLogs, etc.)
```

This stack uses the **Logs Ingestion API** (DCR/DCE-based), which is the supported successor to the deprecated HTTP Data Collector API.

---

## Components

| File | Purpose |
|---|---|
| `scripts/Send-SecureBootInventoryToLogAnalytics.ps1` | Intune Proactive Remediation detection script. Inventories Secure Boot state, gets bearer token, posts JSON record to DCE. |
| `kql/SecureBootInventory-Sentinel.kql` | 9 KQL queries: latest state, distribution, trend, action list, stale devices, IntuneDevices join, OEM breakdown, regression rule, deadline countdown rule. |

Pair the detection script with the existing `windows11/intune/scripts/remediation/NoOp.ps1` (always exits 0 - inventory is detection-only).

---

## Setup Walkthrough

### 1. Create the Log Analytics workspace (skip if existing)

Use any region close to your tenant. Sentinel is enabled separately on top of the workspace.

### 2. Create the custom table

1. Azure Portal -> Log Analytics workspace -> **Tables** -> **Create** -> **New custom log (DCR-based)**
2. **Table name**: `SecureBootInventory` (the `_CL` suffix is added automatically)
3. **Data Collection Rule**: select **Create a new data collection rule**, name it `dcr-secureboot-inventory`
4. **Data Collection Endpoint**: select an existing DCE in the same region, or create one named `dce-secureboot-<region>`
5. **Schema and transformation**: upload a sample JSON record (one document with all the fields the script sends - see `Sample record` below) so the portal generates the schema. Set `TimeGenerated` as the timestamp column.
6. Review and create.

#### Sample record (paste into the portal schema step)

```json
{
  "TimeGenerated": "2026-03-12T14:23:01.123Z",
  "DeviceName": "WIN-PILOT-01",
  "SecureBoot": true,
  "FirmwareType": "UEFI",
  "DB_Has2011Cert": true,
  "DB_Has2023Cert": true,
  "KEK_Has2011Cert": false,
  "KEK_Has2023Cert": true,
  "CertStatus": "UpToDate",
  "TPMPresent": true,
  "TPMReady": true,
  "TPMSpecVersion": "2.0, 0, 1.38",
  "VBSStatus": "Running",
  "HVCIStatus": "EnforcementMode",
  "CredentialGuard": "Running",
  "Manufacturer": "HP",
  "Model": "EliteBook 840 G9",
  "SerialNumber": "5CG0123456",
  "OSVersion": "10.0.26100.4061",
  "AzureADDeviceId": "00000000-0000-0000-0000-000000000000"
}
```

### 3. Note the DCR / DCE / stream details

After table creation, capture:
- **DCE endpoint URI** (`https://<dce>.<region>.ingest.monitor.azure.com`)
- **DCR immutable ID** (starts with `dcr-` - find it under DCR -> Overview -> JSON view -> `immutableId`)
- **Stream name** (default `Custom-SecureBootInventory_CL`)

### 4. Create the Entra app registration

1. Azure Portal -> **Entra ID** -> **App registrations** -> **New registration**
2. Name: `secureboot-inventory-ingest`
3. **Certificates & secrets** -> **New client secret** -> set expiry to 6-12 months, copy the value (it's only shown once)
4. Capture the **Application (client) ID** and **Directory (tenant) ID**

### 5. Grant the app role on the DCR (least privilege)

1. Open the DCR -> **Access control (IAM)** -> **Add role assignment**
2. Role: **Monitoring Metrics Publisher**
3. Assign to: the app registration you just created
4. Save

> [!IMPORTANT]
> Assign the role on the **DCR resource only**, not on the workspace or subscription. This is least-privilege - the app can only write to this one DCR.

### 6. Embed the credentials and upload to Intune

Open `scripts/Send-SecureBootInventoryToLogAnalytics.ps1` and replace the six placeholder constants at the top:

```powershell
$TenantId       = '<your-tenant-id>'
$AppId          = '<app-registration-client-id>'
$AppSecret      = '<client-secret-value>'
$DceEndpoint    = 'https://your-dce.region.ingest.monitor.azure.com'
$DcrImmutableId = 'dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
$StreamName     = 'Custom-SecureBootInventory_CL'
```

Then in Intune:
1. **Devices** -> **Scripts and remediations** -> **Create**
2. Detection script: this script
3. Remediation script: `windows11/intune/scripts/remediation/NoOp.ps1`
4. Run as: **SYSTEM**, 64-bit
5. Schedule: **Daily**
6. Assign to a pilot group of 5-10 devices first

### 7. Verify ingestion

Within ~10 minutes after the first device runs the script, run this in Sentinel:

```kusto
SecureBootInventory_CL
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, CertStatus, SecureBoot, FirmwareType
| order by TimeGenerated desc
```

If you get rows back, the pipeline works. Roll out to the full collection.

### 8. Import the KQL pack

Open `kql/SecureBootInventory-Sentinel.kql`, copy individual blocks into:
- **Sentinel -> Logs**: as ad-hoc queries
- **Sentinel -> Workbooks**: as tile queries (charts via `| render`)
- **Sentinel -> Analytics**: as scheduled analytic rules (queries 8 and 9)
- **Sentinel -> Hunting**: as saved hunting queries

---

## Operational Notes

### Secret rotation

The client secret is embedded in the script and uploaded to Intune. Rotate it every 6-12 months:
1. Add a new secret in the app registration
2. Replace `$AppSecret` in the script
3. Re-upload to Intune (existing devices pick up the new script on next sync)
4. After 24-48h, delete the old secret

### Future: certificate-based auth

Replacing the embedded secret with a device certificate deployed via Intune (SCEPman, NDES, or Intune-issued cert) eliminates the secret-rotation burden and is more secure. Out of scope for this version - the embedded-secret pattern matches what most Intune-deployed scripts use today.

### Cost estimate

Per device per day: one record, ~1 KB. For 10,000 devices: ~10 MB/day, ~300 MB/month. At commercial pricing this is a few dollars per month - negligible.

---

## Reference

| Variable | Certificate | Thumbprint (SHA-1) |
|---|---|---|
| `db`  | Windows UEFI CA 2011  | `580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D` |
| `db`  | Windows UEFI CA 2023  | `45A0FA32604773C82433C3B7D59E7466B3AC0C67` |
| `KEK` | KEK CA 2011           | `31590BFD89C9D74ED087CA28B7C54AC03D55CF72` |
| `KEK` | KEK 2K CA 2023        | `459AB6FB5E284D272D5E3E6ABC8ED663829D632B` |

### Microsoft Learn references

- [Logs Ingestion API in Azure Monitor](https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview)
- [Tutorial: Send data via Logs Ingestion API](https://learn.microsoft.com/azure/azure-monitor/logs/tutorial-logs-ingestion-portal)
- [Migrate from HTTP Data Collector API](https://learn.microsoft.com/azure/azure-monitor/logs/custom-logs-migrate)
