<#
.SYNOPSIS
    Disables “Windows Update from other PCs on the Internet” by preventing Delivery Optimization from using Internet peering.
    Per STIG WN11-CC-000206, DODownloadMode must not be set to 3 (Internet). This script enforces a safe default of 0 (HTTP only).

    Applies to domain/GPO-managed systems via:
      HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode

    Also evaluates standalone (Settings-driven) systems via:
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\DODownloadMode

    Compliant values (Policy path):
      0   = HTTP only (No peering)
      1   = LAN
      2   = Group
      99  = Simple
      100 = Bypass
    Non-compliant:
      3   = Internet

    NOTE:
      - Run as Administrator.
      - If the policy path exists, it takes precedence over the standalone Config path.
      - This script will set the policy value to 0 (HTTP only) when non-compliant or missing.

.NOTES
    Author          : Vlad Zelenskiy
    LinkedIn        : linkedin.com/in/vladzelenskiy/
    GitHub          : https://github.com/vlzelen
    Date Created    : 2026-03-02
    Last Modified   : 2026-03-02
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000206

.TESTED ON
    Date(s) Tested  : 2026-03-02
    Tested By       : Vlad Zelenskiy
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-CC-000206.ps1
#>

# WN11-CC-000206 - Disable Internet peering for Delivery Optimization (Windows Update from other PCs on the Internet)
# Run as Administrator

$PolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
$ConfigPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
$Name       = "DODownloadMode"

$SafePolicyValue = 0  # HTTP only (No peering)
$SafeConfigValue = 0  # Off (Standalone setting)

# Admin check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Run as Administrator."
    exit 1
}

# Read current values (if present)
$PolicyCurrent = (Get-ItemProperty -Path $PolicyPath -Name $Name -ErrorAction SilentlyContinue).$Name
$ConfigCurrent = (Get-ItemProperty -Path $ConfigPath -Name $Name -ErrorAction SilentlyContinue).$Name

# Determine effective control: policy wins when present (even if value missing, the key implies intent to manage)
$PolicyKeyExists = Test-Path $PolicyPath

# Compliance logic:
# - Policy-managed: compliant if value exists and != 3 (Internet)
# - Standalone: compliant if value exists and is 0 (Off) or 1 (LAN)
if ($PolicyKeyExists) {
    if ($null -ne $PolicyCurrent -and [int]$PolicyCurrent -ne 3) {
        Write-Host "COMPLIANT (Policy): $Name = $PolicyCurrent (Internet mode not enabled)."
        exit 0
    }

    if ($null -eq $PolicyCurrent) {
        Write-Host "NOT compliant (Policy): $Name not configured. Attempting remediation..."
    } else {
        Write-Host "NOT compliant (Policy): $Name = $PolicyCurrent. Attempting remediation..."
    }

    # Ensure policy path exists and set safe default
    if (-not $PolicyKeyExists) { New-Item -Path $PolicyPath -Force | Out-Null }
    Set-ItemProperty -Path $PolicyPath -Name $Name -Type DWord -Value $SafePolicyValue

    # Verify
    $Verify = (Get-ItemProperty -Path $PolicyPath -Name $Name -ErrorAction Stop).$Name
    if ([int]$Verify -ne 3) {
        Write-Host "COMPLIANT (Policy): $Name is now set to $Verify."
        exit 0
    } else {
        Write-Host "FAILED (Policy): $Name remains set to 3 (Internet)."
        exit 1
    }
}
else {
    # Standalone evaluation (Settings-driven)
    if ($null -ne $ConfigCurrent -and ([int]$ConfigCurrent -eq 0 -or [int]$ConfigCurrent -eq 1)) {
        Write-Host "COMPLIANT (Standalone): $Name = $ConfigCurrent (Off or LAN)."
        exit 0
    }

    if ($null -eq $ConfigCurrent) {
        Write-Host "NOT compliant (Standalone): $Name not configured. Attempting remediation..."
    } else {
        Write-Host "NOT compliant (Standalone): $Name = $ConfigCurrent. Attempting remediation..."
    }

    # Ensure config path exists and set safe default (Off)
    if (-not (Test-Path $ConfigPath)) { New-Item -Path $ConfigPath -Force | Out-Null }
    Set-ItemProperty -Path $ConfigPath -Name $Name -Type DWord -Value $SafeConfigValue

    # Verify
    $Verify = (Get-ItemProperty -Path $ConfigPath -Name $Name -ErrorAction Stop).$Name
    if ([int]$Verify -eq 0 -or [int]$Verify -eq 1) {
        Write-Host "COMPLIANT (Standalone): $Name is now set to $Verify."
        exit 0
    } else {
        Write-Host "FAILED (Standalone): $Name is $Verify after remediation."
        exit 1
    }
}
