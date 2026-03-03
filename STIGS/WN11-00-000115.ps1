<#
.SYNOPSIS
    Ensures the Telnet Client Windows feature is not installed.
    Telnet does not support required security features such as encrypting credentials or traffic.

    NOTE:
      - Run as Administrator.
      - This STIG is satisfied when the optional feature "TelnetClient" is Disabled.
      - The manual check mentions C:\Windows\System32\telnet.exe; however, the correct remediation is to disable/remove the Windows feature.

.NOTES
    Author          : Vlad Zelenskiy
    LinkedIn        : linkedin.com/in/vladzelenskiy/
    GitHub          : https://github.com/vlzelen
    Date Created    : 2026-03-02
    Last Modified   : 2026-03-02
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000115

.TESTED ON
    Date(s) Tested  : 26-03-02
    Tested By       : Vlad Zelenskiy
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-00-000115.ps1
#>

# WN11-00-000115 - Telnet Client must not be installed
# Run as Administrator

$FeatureName = "TelnetClient"
$TelnetPath  = "$env:WINDIR\System32\telnet.exe"

# Admin check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Run as Administrator."
    exit 1
}

# Read current feature state
try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop
    $state   = $feature.State
} catch {
    Write-Host "ERROR: Unable to query optional feature '$FeatureName'. Details: $($_.Exception.Message)"
    exit 1
}

# Check compliance
if ($state -eq "Disabled") {
    if (Test-Path $TelnetPath) {
        Write-Host "WARNING: Feature is Disabled but '$TelnetPath' exists. Investigate image/component state."
    }
    Write-Host "COMPLIANT: $FeatureName is Disabled."
    exit 0
}

Write-Host "NOT compliant: $FeatureName state is '$state'. Attempting remediation..."

# Remediate (disable feature)
try {
    Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -ErrorAction Stop | Out-Null
} catch {
    Write-Host "ERROR: Remediation failed while disabling '$FeatureName'. Details: $($_.Exception.Message)"
    exit 1
}

# Verify
try {
    $verify = (Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop).State
} catch {
    Write-Host "ERROR: Unable to verify optional feature '$FeatureName' after remediation. Details: $($_.Exception.Message)"
    exit 1
}

if ($verify -eq "Disabled") {
    Write-Host "COMPLIANT: $FeatureName is now Disabled."
    exit 0
} else {
    Write-Host "FAILED: $FeatureName state is '$verify' after remediation."
    exit 1
}
