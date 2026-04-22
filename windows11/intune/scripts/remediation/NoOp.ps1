<#
.SYNOPSIS
    Proactive Remediation — no-op remediation script.
.DESCRIPTION
    Paired with Collect-SecureBootInventory.ps1. Since the detection script
    always exits 0, this script is never triggered. Required by Intune.
.NOTES
    Run as: SYSTEM (64-bit)
#>
exit 0
