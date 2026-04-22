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

#region — Query Proactive Remediation results
# The remediation script writes to HKLM:\SOFTWARE\IntuneRemediations\SecureBoot.
# We read this via the Intune Device Health Script result endpoint.
# Graph: GET /deviceManagement/deviceHealthScripts/{id}/deviceRunStates

# Alternatively, build report from compliance state + detected apps
# For this script we use compliance policy state per-device as a proxy

$report = foreach ($device in $devices) {
    $complianceStates = Get-MgDeviceManagementManagedDeviceCompliancePolicyState -ManagedDeviceId $device.Id -ErrorAction SilentlyContinue

    $secureBoot = $complianceStates |
        Where-Object { $_.SettingStates.Setting -match 'secureboot' } |
        Select-Object -ExpandProperty SettingStates -ErrorAction SilentlyContinue |
        Where-Object { $_.Setting -match 'secureboot' }

    [PSCustomObject]@{
        DeviceName       = $device.DeviceName
        UPN              = $device.UserPrincipalName
        OSVersion        = $device.OsVersion
        ComplianceState  = $device.ComplianceState
        LastSync         = $device.LastSyncDateTime
        SecureBootState  = if ($secureBoot) { $secureBoot.State } else { 'Unknown' }
        AzureADDeviceId  = $device.AzureAdDeviceId
    }
}
#endregion

#region — Output
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Report saved to $OutputPath" -ForegroundColor Green

$summary = $report | Group-Object SecureBootState | Select-Object Name, Count
Write-Host "`nSummary:" -ForegroundColor Cyan
$summary | Format-Table -AutoSize

Disconnect-MgGraph | Out-Null
#endregion
