<#
.SYNOPSIS
    Disables Windows Copilot on Windows 11 by enabling the policy “Turn off Windows Copilot”.
    This helps prevent potential data communication outside the enterprise and uncontrolled feature updates.

    Enforces (User Configuration policy):
      HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot\TurnOffWindowsCopilot = 1

    Also sets a machine policy value (defense in depth):
      HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot\TurnOffWindowsCopilot = 1

    NOTE:
      - Run as Administrator.
      - STIG is written as a User Configuration setting; this script sets HKCU for the current user and HKLM as an additional hardening measure.

.NOTES
    Author          : Vlad Zelenskiy
    LinkedIn        : linkedin.com/in/vladzelenskiy/
    GitHub          : https://github.com/vlzelen
    Date Created    : 2026-03-02
    Last Modified   : 2026-03-02
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000125

.TESTED ON
    Date(s) Tested  : 2026-03-02
    Tested By       : Vlad Zelenskiy
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-00-000125.ps1
#>

# WN11-00-000125 - Disable Windows Copilot (Turn off Windows Copilot = Enabled)
# Run as Administrator

$HKCUPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
$HKLMPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
$Name     = "TurnOffWindowsCopilot"
$Value    = 1

# Admin check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Run as Administrator."
    exit 1
}

# Ensure keys exist
if (-not (Test-Path $HKCUPath)) { New-Item -Path $HKCUPath -Force | Out-Null }
if (-not (Test-Path $HKLMPath)) { New-Item -Path $HKLMPath -Force | Out-Null }

# Read current values
$CUCurrent = (Get-ItemProperty -Path $HKCUPath -Name $Name -ErrorAction SilentlyContinue).$Name
$LMCurrent = (Get-ItemProperty -Path $HKLMPath -Name $Name -ErrorAction SilentlyContinue).$Name

# Check compliance (require HKCU for current user; set HKLM as well)
if ($null -ne $CUCurrent -and [int]$CUCurrent -eq $Value -and $null -ne $LMCurrent -and [int]$LMCurrent -eq $Value) {
    Write-Host "COMPLIANT: $Name is enabled in HKCU and HKLM."
    exit 0
}

Write-Host "NOT compliant: Attempting remediation..."

# Remediate
Set-ItemProperty -Path $HKCUPath -Name $Name -Type DWord -Value $Value
Set-ItemProperty -Path $HKLMPath -Name $Name -Type DWord -Value $Value

# Verify
$CUVerify = (Get-ItemProperty -Path $HKCUPath -Name $Name -ErrorAction Stop).$Name
$LMVerify = (Get-ItemProperty -Path $HKLMPath -Name $Name -ErrorAction Stop).$Name

if ([int]$CUVerify -eq $Value -and [int]$LMVerify -eq $Value) {
    Write-Host "COMPLIANT: Copilot is disabled (HKCU=$CUVerify, HKLM=$LMVerify)."
    exit 0
} else {
    Write-Host "FAILED: Verification did not match expected values (HKCU=$CUVerify, HKLM=$LMVerify)."
    exit 1
}
