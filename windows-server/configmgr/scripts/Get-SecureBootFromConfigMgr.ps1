<#
.SYNOPSIS
    Reporting script - Secure Boot inventory from ConfigMgr SMS Provider.
.DESCRIPTION
    Queries the ConfigMgr SMS Provider via WMI for Secure Boot certificate
    state collected by the Configuration Item discovery script
    (Detect-SecureBootInventory-CI.ps1).

    Two data sources are supported - the script tries them in this order
    and uses whichever returns data:

      1. Custom Hardware Inventory class
         (when the registry path HKLM:\SOFTWARE\SecureBootInventory has been
         added as a custom class to Default Client Settings -> Hardware
         Inventory). This gives the richest data and works for offline hosts
         since data is in the SCCM database.

      2. Configuration Baseline compliance state
         (always available as soon as the CB has evaluated). This gives
         CertStatus per device but not the full thumbprint breakdown.

    Outputs a CSV report - same column shape as the AD/Intune reports so
    they can be unioned in a downstream analysis pipeline.

    Requires: ConfigurationManager PowerShell module (loaded automatically
              from the SCCM admin console host)

.PARAMETER SiteCode
    Three-letter ConfigMgr site code, e.g. 'PRI'. Detected automatically
    if running on the site server with the console installed.

.PARAMETER SiteServer
    FQDN of the SMS Provider. Defaults to the local machine.

.PARAMETER CollectionId
    Optional collection ID to scope the report. If omitted, all systems
    that have the inventory data are returned.

.PARAMETER BaselineName
    Display name of the Configuration Baseline that wraps the CI.
    Used when falling back to CB compliance data.

.PARAMETER OutputPath
    CSV destination. Default: .\SecureBootInventory_ConfigMgr_<date>.csv

.EXAMPLE
    .\Get-SecureBootFromConfigMgr.ps1 -SiteCode PRI -SiteServer cm01.contoso.com

.EXAMPLE
    .\Get-SecureBootFromConfigMgr.ps1 `
        -SiteCode PRI `
        -CollectionId PRI00042 `
        -BaselineName 'Secure Boot - Cert Inventory' `
        -OutputPath C:\Reports\sb-servers.csv

.NOTES
    Author  : Marius Skovli
    Date    : 27.02.2026
    Version : 1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $SiteCode,

    [string] $SiteServer = $env:COMPUTERNAME,

    [string] $CollectionId,

    [string] $BaselineName = 'Secure Boot - Cert Inventory',

    [string] $OutputPath = ".\SecureBootInventory_ConfigMgr_$(Get-Date -Format 'yyyyMMdd').csv"
)

$namespace = "root\sms\site_$SiteCode"
$cimParams = @{ ComputerName = $SiteServer; Namespace = $namespace; ErrorAction = 'Stop' }

#region - Source 1: custom Hardware Inventory class
Write-Host "Source 1 - Trying custom Hardware Inventory class..." -ForegroundColor Cyan

# When you add HKLM:\SOFTWARE\SecureBootInventory as a custom class, ConfigMgr
# typically names the SMS_Provider WMI class along the lines of
# SMS_G_System_SecureBootInventory or SMS_G_System_<class-name-from-mof>.
# Adjust the class name below if your MOF used a different ClassName attribute.
$inventoryClass = 'SMS_G_System_SECUREBOOTINVENTORY'

$inventoryRows = $null
try {
    $query = "SELECT * FROM $inventoryClass"
    if ($CollectionId) {
        $query = @"
SELECT inv.*, sys.Name0 AS DeviceName
FROM $inventoryClass AS inv
JOIN SMS_R_System AS sys ON inv.ResourceID = sys.ResourceID
JOIN SMS_FullCollectionMembership AS m ON sys.ResourceID = m.ResourceID
WHERE m.CollectionID = '$CollectionId'
"@
    }
    $inventoryRows = Get-CimInstance @cimParams -Query $query
    Write-Host "  Found $($inventoryRows.Count) rows" -ForegroundColor Green
}
catch {
    Write-Host "  Custom class not available: $($_.Exception.Message)" -ForegroundColor Yellow
}
#endregion

#region - Source 2: CB compliance state (fallback)
$cbRows = $null
if (-not $inventoryRows) {
    Write-Host "Source 2 - Falling back to Configuration Baseline compliance..." -ForegroundColor Cyan
    try {
        $cbQuery = @"
SELECT cs.ResourceID, cs.ComplianceState, cs.LastComplianceMessageStatusTime,
       sys.Name0 AS DeviceName
FROM SMS_G_System_CI_ComplianceState AS cs
JOIN SMS_ConfigurationBaselineInfo AS cb ON cs.LocalAppliedCIs = cb.CI_UniqueID
JOIN SMS_R_System AS sys ON cs.ResourceID = sys.ResourceID
WHERE cb.LocalizedDisplayName = '$BaselineName'
"@
        $cbRows = Get-CimInstance @cimParams -Query $cbQuery
        Write-Host "  Found $($cbRows.Count) compliance state rows" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not query Configuration Baseline state: $($_.Exception.Message)"
    }
}
#endregion

#region - Build report
$report = if ($inventoryRows) {
    $inventoryRows | ForEach-Object {
        [PSCustomObject]@{
            ComputerName     = if ($_.DeviceName) { $_.DeviceName } else { $_.PSComputerName }
            SecureBoot       = [bool]$_.SecureBoot
            FirmwareType     = $_.FirmwareType
            CertStatus       = $_.CertStatus
            DB_Has2023Cert   = [bool]$_.DB_Has2023Cert
            DB_Has2011Cert   = [bool]$_.DB_Has2011Cert
            KEK_Has2023Cert  = [bool]$_.KEK_Has2023Cert
            KEK_Has2011Cert  = [bool]$_.KEK_Has2011Cert
            LastEvaluation   = $_.LastEvaluation
            DataSource       = 'HardwareInventory'
        }
    }
} elseif ($cbRows) {
    $cbRows | ForEach-Object {
        $stateText = switch ($_.ComplianceState) {
            0 { 'Unknown' }
            1 { 'Compliant (UpToDate)' }
            2 { 'NonCompliant (NeedsUpdate or Unknown)' }
            3 { 'NotApplicable' }
            4 { 'Error' }
            default { "State($($_.ComplianceState))" }
        }
        [PSCustomObject]@{
            ComputerName    = $_.DeviceName
            CertStatus      = $stateText
            LastEvaluation  = $_.LastComplianceMessageStatusTime
            DataSource      = 'ComplianceBaseline'
        }
    }
} else {
    Write-Warning "No data found. Verify the CI/CB has evaluated and either Hardware Inventory or compliance reporting is configured."
    return
}
#endregion

#region - Output
$report | Sort-Object CertStatus, ComputerName |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nReport saved: $OutputPath" -ForegroundColor Green

Write-Host "`nSummary - CertStatus (June 2026 deadline):" -ForegroundColor Yellow
$report | Group-Object CertStatus |
    Select-Object @{N='CertStatus'; E={$_.Name}}, @{N='Count'; E={$_.Count}} |
    Sort-Object Count -Descending | Format-Table -AutoSize
#endregion
