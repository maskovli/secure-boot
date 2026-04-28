<#
.SYNOPSIS
    Graph API reporting script — Secure Boot inventory across all Intune-managed Windows 11 devices.
.DESCRIPTION
    Uses the deviceCompliancePolicySettingStateSummaries endpoint to retrieve per-device Secure Boot
    compliance state in two Graph calls (vs. N calls per device). Outputs a CSV report.

    Requires: Microsoft.Graph PowerShell SDK
    Permissions: DeviceManagementManagedDevices.Read.All
.PARAMETER OutputPath
    Path for the CSV output. Defaults to .\SecureBootInventory_<date>.csv
.PARAMETER TenantId
    Entra ID tenant ID.
.PARAMETER ClientId
    App registration client ID (if using app-only auth).
.NOTES
    For delegated auth (interactive), run as a user with Intune read access.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = ".\SecureBootInventory_$(Get-Date -Format 'yyyyMMdd').csv",
    [string] $TenantId,
    [string] $ClientId
)

#region — Auth
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement)) {
    throw 'Microsoft.Graph.DeviceManagement module is required. Install-Module Microsoft.Graph -Scope CurrentUser'
}

$connectParams = @{ Scopes = 'DeviceManagementManagedDevices.Read.All' }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }
if ($ClientId) { $connectParams['ClientId'] = $ClientId }

Connect-MgGraph @connectParams -NoWelcome
#endregion

#region — Get SecureBoot setting state summary
# Graph: GET /deviceManagement/deviceCompliancePolicySettingStateSummaries?$filter=setting eq 'secureBootEnabled'
# This returns a summary object with an ID we can use to get per-device states.
Write-Host 'Looking up Secure Boot compliance setting summary...' -ForegroundColor Cyan

$baseUri = 'https://graph.microsoft.com/v1.0/deviceManagement'

$summaryResponse = Invoke-MgGraphRequest -Method GET `
    -Uri "$baseUri/deviceCompliancePolicySettingStateSummaries?`$filter=setting eq 'secureBootEnabled'"

$summary = $summaryResponse.value | Select-Object -First 1

if (-not $summary) {
    Write-Warning "No Secure Boot compliance setting summary found. Ensure the compliance policy with 'secureBootEnabled' is assigned and has evaluated at least one device."
    Disconnect-MgGraph | Out-Null
    return
}

Write-Host "Summary found — ID: $($summary.id)" -ForegroundColor Green
Write-Host "  Compliant: $($summary.compliantDeviceCount)  NonCompliant: $($summary.nonCompliantDeviceCount)  Unknown: $($summary.unknownDeviceCount)  NotApplicable: $($summary.notApplicableDeviceCount)"
#endregion

#region — Get per-device setting states (paginated)
# Graph: GET /deviceManagement/deviceCompliancePolicySettingStateSummaries/{id}/deviceComplianceSettingStates
Write-Host 'Fetching per-device Secure Boot states...' -ForegroundColor Cyan

$allStates = [System.Collections.Generic.List[object]]::new()
$nextUri   = "$baseUri/deviceCompliancePolicySettingStateSummaries/$($summary.id)/deviceComplianceSettingStates"

do {
    $page    = Invoke-MgGraphRequest -Method GET -Uri $nextUri
    $allStates.AddRange([object[]]$page.value)
    $nextUri = $page.'@odata.nextLink'
} while ($nextUri)

Write-Host "Retrieved $($allStates.Count) device setting state records" -ForegroundColor Green
#endregion

#region — Build report
# Each state object has: deviceId, deviceName, state, userId, userEmail, userName,
#   userPrincipalName, deviceModel, setting, settingName, osDescription, osVersion
$report = $allStates | ForEach-Object {
    [PSCustomObject]@{
        DeviceName      = $_.deviceName
        UPN             = $_.userPrincipalName
        UserName        = $_.userName
        OSVersion       = $_.osVersion
        DeviceModel     = $_.deviceModel
        SecureBootState = $_.state   # compliant | nonCompliant | notApplicable | unknown | error
        DeviceId        = $_.deviceId
    }
}
#endregion

#region — Output
$report | Sort-Object SecureBootState, DeviceName |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Report saved to $OutputPath" -ForegroundColor Green

Write-Host "`nSummary by state:" -ForegroundColor Cyan
$report | Group-Object SecureBootState |
    Select-Object @{N='State'; E={$_.Name}}, @{N='Count'; E={$_.Count}} |
    Sort-Object Count -Descending |
    Format-Table -AutoSize

Disconnect-MgGraph | Out-Null
#endregion
