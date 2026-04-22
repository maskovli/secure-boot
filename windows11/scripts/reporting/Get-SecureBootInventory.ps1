<#
.SYNOPSIS
    Graph API reporting script — Secure Boot inventory across all Intune-managed Windows 11 devices.
.DESCRIPTION
    Queries Microsoft Graph for managed Windows devices and reads the registry key written by
    the Proactive Remediation script (HKLM:\SOFTWARE\IntuneRemediations\SecureBoot).
    Outputs a CSV report suitable for export to Excel or Power BI.

    Requires: Microsoft.Graph PowerShell SDK (or Graph API access token)
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

#region — Fetch devices
Write-Host 'Fetching managed Windows devices from Graph...' -ForegroundColor Cyan

$devices = Get-MgDeviceManagementManagedDevice -Filter "operatingSystem eq 'Windows'" -All `
    -Property 'id,deviceName,userPrincipalName,osVersion,complianceState,lastSyncDateTime,azureADDeviceId'

Write-Host "Found $($devices.Count) Windows devices" -ForegroundColor Green
#endregion

#region — Query per-device Secure Boot setting state from compliance policies
# SettingStates is a navigation property on deviceCompliancePolicyState — it is NOT
# returned inline. Must be fetched via the dedicated settingStates endpoint per policy.
# Graph: GET /deviceManagement/managedDevices/{id}/deviceCompliancePolicyStates/{policyStateId}/settingStates

$total   = $devices.Count
$counter = 0

$report = foreach ($device in $devices) {
    $counter++
    Write-Progress -Activity 'Querying compliance setting states' `
        -Status "$counter / $total — $($device.DeviceName)" `
        -PercentComplete (($counter / $total) * 100)

    $secureBootState = 'Unknown'

    $policyStates = Get-MgDeviceManagementManagedDeviceCompliancePolicyState `
        -ManagedDeviceId $device.Id -ErrorAction SilentlyContinue

    foreach ($ps in $policyStates) {
        $settingStates = Get-MgDeviceManagementManagedDeviceCompliancePolicyStateSettingState `
            -ManagedDeviceId $device.Id `
            -DeviceCompliancePolicyStateId $ps.Id `
            -ErrorAction SilentlyContinue

        $sb = $settingStates | Where-Object { $_.Setting -match 'SecureBoot' }
        if ($sb) {
            $secureBootState = $sb.State   # compliant | nonCompliant | notApplicable | unknown
            break
        }
    }

    [PSCustomObject]@{
        DeviceName       = $device.DeviceName
        UPN              = $device.UserPrincipalName
        OSVersion        = $device.OsVersion
        ComplianceState  = $device.ComplianceState
        LastSync         = $device.LastSyncDateTime
        SecureBootState  = $secureBootState
        AzureADDeviceId  = $device.AzureAdDeviceId
    }
}

Write-Progress -Activity 'Querying compliance setting states' -Completed
#endregion

#region — Output
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Report saved to $OutputPath" -ForegroundColor Green

$summary = $report | Group-Object SecureBootState | Select-Object Name, Count
Write-Host "`nSummary:" -ForegroundColor Cyan
$summary | Format-Table -AutoSize

Disconnect-MgGraph | Out-Null
#endregion
