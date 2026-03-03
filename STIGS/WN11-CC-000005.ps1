<#
.SYNOPSIS
    Disables camera access from the lock screen by enabling the policy "Prevent enabling lock screen camera".
    This prevents unauthorized use of the camera without authentication.

    Enforces:
      HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera = 1

    NOTE:
      - Run as Administrator.
      - If the device does not have a camera, this is Not Applicable (NA).
      - This script includes a basic camera presence check; validate against your environment if needed.

.NOTES
    Author          : Vlad Zelenskiy
    LinkedIn        : linkedin.com/in/vladzelenskiy/
    GitHub          : https://github.com/vlzelen
    Date Created    : 2026-03-02
    Last Modified   : 2026-03-02
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000005

.TESTED ON
    Date(s) Tested  : 2026-03-02
    Tested By       : Vlad Zelenskiy
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\WN11-CC-000005.ps1
#>

# WN11-CC-000005 - Camera access from the lock screen must be disabled
# Run as Administrator

$Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$Name  = "NoLockScreenCamera"
$Value = 1

# Admin check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Run as Administrator."
    exit 1
}

# NA check: device has no camera (basic detection)
try {
    $cameraPresent = $false

    # Try CIM first (common and fast)
    $cimCameras = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
        Where-Object { $_.PNPClass -eq "Camera" -or $_.Name -match "camera|webcam|integrated camera" }

    if ($cimCameras) { $cameraPresent = $true }

    # Fallback check (some devices enumerate as "Image")
    if (-not $cameraPresent) {
        $cimImages = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
            Where-Object { $_.PNPClass -eq "Image" -and $_.Name -match "camera|webcam" }
        if ($cimImages) { $cameraPresent = $true }
    }

    if (-not $cameraPresent) {
        Write-Host "NA: No camera detected on this device."
        exit 0
    }
} catch {
    # If detection fails, continue with enforcement (do not incorrectly mark NA)
    Write-Host "WARNING: Camera detection failed. Continuing with enforcement."
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
