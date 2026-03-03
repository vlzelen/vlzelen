<#
.SYNOPSIS
    Enables PowerShell Script Block Logging on Windows 11.
    Script Block Logging records detailed information from PowerShell command and script processing to support detection and investigation.

    Enforces:
      HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1

    NOTE:
      - Run as Administrator.

.NOTES
    Author          : Vlad Zelenskiy
    LinkedIn        : linkedin.com/in/vladzelenskiy/
    GitHub          : https://github.com/vlzelen
    Date Created    : 2026-03-02
    Last Modified   : 2026-03-02
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000326

.TESTED ON
    Date(s) Tested  : 2026-03-02
    Tested By       : Vlad Zelenskiy
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-CC-000326.ps1
#>

# WN11-CC-000326 - Enable PowerShell Script Block Logging
# Run as Administrator

$Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$Name  = "EnableScriptBlockLogging"
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
