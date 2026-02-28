<#
.SYNOPSIS
    Proactive Remediation — no-op remediation script.
.DESCRIPTION
    Paired with Collect-SecureBootInventory.ps1. Since the detection script
    always exits 0, this script is never triggered. Required by Intune.
.NOTES
    Author  : Marius Skovli
    Date    : 03.02.2026
    Version : 1.0
    Run as  : SYSTEM (64-bit)
#>
exit 0
