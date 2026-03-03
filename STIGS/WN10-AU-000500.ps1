<#
.SYNOPSIS
    Ensures the Application event log maximum size is configured to 32768 KB (32 MB) or greater.
    Inadequate log size can cause the log to fill quickly, preventing audit events from being recorded properly.

    NOTE:
      - Run as Administrator.
      - If the system is configured to send audit records directly to an audit server, this is Not Applicable (NA) and must be documented with the ISSO.
      - This script enforces the policy-backed registry value used by Group Policy:
        HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize

.NOTES
    Author          : Vlad Zelenskiy
    LinkedIn        : linkedin.com/in/vladzelenskiy/
    GitHub          : https://github.com/vlzelen
    Date Created    : 2026-03-02
    Last Modified   : 2026-03-02
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 26-03-02
    Tested By       : Vlad Zelenskiy
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN10-AU-000500.ps1
#>

# WN10-AU-000500 - Application event log MaxSize >= 32768 KB
# Run as Administrator

$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$Name = "MaxSize"
$Min  = 32768

# Admin check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Run as Administrator."
    exit 1
}

# Ensure key exists
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }

# Read current value (if present)
$Current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name

# Enforce "or greater" without lowering higher values
if ($null -eq $Current -or [int]$Current -lt $Min) {
    Set-ItemProperty -Path $Path -Name $Name -Type DWord -Value $Min
}

# Verify
$Verify = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
if ([int]$Verify -ge $Min) {
    Write-Host "COMPLIANT: $Name = $Verify KB"
    exit 0
} else {
    Write-Host "FAILED: $Name = $Verify KB"
    exit 1
}
