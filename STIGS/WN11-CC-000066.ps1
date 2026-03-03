<#
.SYNOPSIS
    Ensures command line data is included in process creation events.
    This improves investigation and detection by recording the command line used when a process is created.

    Enforces:
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1

    NOTE:
      - Run as Administrator.
      - This setting affects Event ID 4688 (Process Creation) details when auditing is enabled.

.NOTES
    Author          : Vlad Zelenskiy
    LinkedIn        : linkedin.com/in/vladzelenskiy/
    GitHub          : https://github.com/vlzelen
    Date Created    : 2026-03-02
    Last Modified   : 2026-03-02
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000066

.TESTED ON
    Date(s) Tested  : 2026-03-02
    Tested By       : Vlad Zelenskiy
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-CC-000066.ps1
#>

# WN11-CC-000066 - Include command line data in process creation events
# Run as Administrator

$Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$Name  = "ProcessCreationIncludeCmdLine_Enabled"
$Value = 1

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

# Check compliance
if ($null -ne $Current -and [int]$Current -eq $Value) {
    Write-Host "COMPLIANT: $Name = $Current"
    exit 0
}

Write-Host "NOT compliant: $Name is '$Current'. Attempting remediation..."

# Remediate
Set-ItemProperty -Path $Path -Name $Name -Type DWord -Value $Value

# Verify
$Verify = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
if ([int]$Verify -eq $Value) {
    Write-Host "COMPLIANT: $Name is now set to $Verify"
    exit 0
} else {
    Write-Host "FAILED: $Name = $Verify"
    exit 1
}
