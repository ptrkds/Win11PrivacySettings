# Windows 11 Privacy Settings based on
# https://github.com/StellarSand/privacy-settings/blob/main/Privacy Settings/Windows-11.md

# Manual Steps Required (Not Automatable via PowerShell)
Write-Host "--------------------------------------------"
Write-Host "This script follows Windows 11 privacy suggestions:"
Write-Host "https://github.com/StellarSand/privacy-settings/blob/main/Privacy"
Write-Host ""
Write-Host "It covers the following:"
Write-Host "- Changing Lock Screen & Screen Saver Settings"
Write-Host "- Enabling Real-time Protection, Cloud Protection, but disable Automatic Sample Submission"
Write-Host "- Enabling all Firewalls (Domain, Private, Public)"
Write-Host "- Enabling Core Isolation - Memory Integrity (Requires Reboot)"
Write-Host "- Disabling Windows welcome experience, tips, and suggestions"
Write-Host "- Disabling Personalization for tips, shortcuts, new apps and device usage"
Write-Host "- Disabling Snapshots and delete Snapshots"
Write-Host "- Disabling Nearby Sharing"
Write-Host "- Disabling Remote Desktop"
Write-Host "- Enabling Storage Sense"
Write-Host "- Delivery Optimization"
Write-Host "- Disabling Phone Link"
Write-Host "- Disabling App Permissions (Location, Camera, Mic, Notifications)"
Write-Host "- Disabling AutoPlay"
Write-Host "- Disabling Find My Device"
Write-Host "- Disabling online speech recognition"
Write-Host "- Blocking Microsoft telemetry"
Write-Host "- Disabling ads in File Explorer"
Write-Host "- Disabling Copilot"
Write-Host "- Restarting Windows Explorer to apply settings"
Write-Host ""
Write-Host "However not everything can be set by this PowerShell script"
Write-Host "Additional manual steps mentioned after the script run for better privacy"
Write-Host ""
Write-Host "--------------------------------------------"
Write-Host ""
Write-Host "Press any y to continue"
Write-Host ""

$key = $Host.UI.RawUI.ReadKey()
if ($key.Character -eq 'y') {
    Write-Host "Pressed Yes"
}else{
    exit
}

# Progress tracking
function Show-Progress {
    param (
        [int]$CurrentStep,
        [int]$TotalSteps,
        [string]$Message
    )
    Write-Host "[$CurrentStep/$TotalSteps] $Message"
}

# Check and update registry settings
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value
    )
    if (!(Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name -eq $Value) {
        Write-Host "Already set: $Path -> $Name"
    } else {
        try {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
            Write-Host "Successful: $Path -> $Name"
        } catch {
            Write-Host "Failed: $Path -> $Name"
        }
    }
}

# Define total number of steps
$TotalSteps = 20
$Step = 0

# Change Lock Screen & Screen Saver Settings
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Changing Lock Screen & Screen Saver Settings..."
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 0
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SlideshowEnabled" -Value 0
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1
Write-Host ""

# Enable Real-time Protection, Cloud Protection, but disable Automatic Sample Submission
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Enabling Real-time Protection, Cloud Protection, but disable Automatic Sample Submission..."
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableBlockAtFirstSeen $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -SubmitSamplesConsent 2
Write-Host ""

# Enable all Firewalls (Domain, Private, Public)
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Enabling all Firewalls (Domain, Private, Public)..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host ""

# Enable Core Isolation - Memory Integrity (Requires Reboot)
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Enabling Core Isolation - Memory Integrity (Requires Reboot)..."
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\MemoryIntegrity" -Name "Enabled" -Value 1
Write-Host ""

# Disable Windows Welcome Experience, Tips, and Suggestions
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling Windows welcome experience, tips, and suggestions..."
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Value 0
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0
Write-Host ""

# Disable Personalization for tips, shortcuts, new apps and device usage
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling Personalization for tips, shortcuts, new apps and device usage..."
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Value 0
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Value 0
try{
    #Disable Device usage categories
    $deviceUsageRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Intent"
    $deviceUsageCategories = @("Gaming", "School", "Creativity", "Family", "Entertainment", "Business", "Developer")

    # Disable all device usage options
    foreach ($category in $deviceUsageCategories) {
        $fullPath = "$deviceUsageRegPath\$category"
        if (!(Test-Path $fullPath)) {
            New-Item -Path $fullPath -Force | Out-Null
        }
        Set-ItemProperty -Path $fullPath -Name "Value" -Value 0
        Write-Host "Device usage setting '$category' has been turned off."
    }
} catch {
    Write-Host "Failed: Disable Device Usage categories"
}
Write-Host ""

# Recall & Disable Snapshots
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling Snapshots and delete Snapshots..."
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Recall" -Name "SnapshotsEnabled" -Value 0
try{
    $snapshotPath = "$env:LOCALAPPDATA\Microsoft\Recall"

    if (Test-Path $snapshotPath) {
        Remove-Item -Path "$snapshotPath\*" -Recurse -Force
        Write-Output "All Recall Snapshots have been deleted."
    } else {
        Write-Output "No Recall Snapshots found."
    }
} catch {
    Write-Host "Failed: Delete Snapshots"
}
Write-Host ""

# Disable Nearby Sharing
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling Nearby Sharing..."
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "CdpSessionUserAuthzPolicy" -Value 0
Write-Host ""

# Disable Remote Desktop
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling Remote Desktop..."
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Write-Host ""

# Enable Storage Sense
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Enabling Storage Sense..."
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Value 1
Write-Host ""

# Disable Delivery Optimization
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling Delivery Optimization..."
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0
Write-Host ""

# Disable Phone Link
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling Phone Link..."
if (Get-AppxPackage *Microsoft.YourPhone*) {
    Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage -AllUsers | Out-Null
    Write-Host "Successful: Phone Link removed"
} else {
    Write-Host "Already removed: Phone Link"
}
Write-Host ""

# Disable App Permissions
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling App Permissions (Location, Camera, Mic, Notifications)..."
try{
    $permissions = @(
        @{ Name = "Location"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" },
        @{ Name = "Camera"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" },
        @{ Name = "Microphone"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" },
        @{ Name = "Notifications"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" }
    )

    foreach ($perm in $permissions) {
        if (Test-Path $perm.Path) {
            # Set the registry value to "Deny"
            if ($perm.Name -ne "Notifications") {
                Set-ItemProperty -Path "$($perm.Path)\NonPackaged" -Name "Value" -Value "Deny" -ErrorAction SilentlyContinue
            }
            else {
                # For notifications
                Set-ItemProperty -Path $perm.Path -Name "ToastEnabled" -Value 0 -ErrorAction SilentlyContinue
            }
            Write-Host "$($perm.Name) access has been disabled."
        } else {
            Write-Host "Registry path for $($perm.Name) not found. It may already be disabled."
        }
    }
} catch {
    Write-Host "Failed: Disable some or all permissions"
}
Write-Host ""

# Disable AutoPlay
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling AutoPlay..."
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1
Write-Host ""

# Configure Network Settings
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Configuring network settings..."
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowRandomization" -Name "value" -Value 1
Write-Host ""

# Disable Find My Device
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling Find My Device..."
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Settings\FindMyDevice" -Name "LocationSyncEnabled" -Value 0
Write-Host ""

# Disable Speech Recognition
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling online speech recognition..."
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Value 0
Write-Host ""

# Disable Windows Telemetry
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Blocking Microsoft telemetry..."
try{
    Get-Content "C:\Windows\System32\drivers\etc\hosts" | Out-File "C:\Windows\System32\drivers\etc\hosts.bak" -ErrorAction Stop

    # Download list from https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.winoffice.txt
    Invoke-WebRequest -URI "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.winoffice.txt" -OutFile native.winoffice.txt
    Get-Content "native.winoffice.txt" | Where { $_ -notmatch "^#" } | Add-Content "C:\Windows\System32\drivers\etc\hosts" -ErrorAction Stop
    Remove-Item "native.winoffice.txt"
} catch {
    Write-Host "Failed: Telemetry setting"
}
Write-Host ""

# Disable Ads in File Explorer (Requires Reboot)
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling ads in File Explorer (Requires Reboot)..."
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0
Write-Host ""

# Disable Copilot
Show-Progress -CurrentStep (++$Step) -TotalSteps $TotalSteps -Message "Disabling Copilot..."
New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows" -Name "WindowsCopilot" -Force | Out-Null
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1

Write-Host ""
Write-Host ""
Write-Host "Windows 11 privacy settings successfully applied!"
Write-Host "Reboot required for some changes!"
Write-Host ""
Write-Host "--------------------------------------------"
Write-Host "Optional Manual Steps After Script Execution:"
Write-Host "Configure Ethernet & Wi-Fi DNS Settings:"
Write-Host "   - Open Settings (Win + I) > Network & internet > Ethernet or Wi-Fi."
Write-Host "   - Click 'Hardware properties' > 'DNS server assignment' > 'Edit'."
Write-Host "   - Set 'Edit DNS settings' to 'Manual'."
Write-Host "   - Enable 'IPv4' and enter preferred DNS (e.g., Quad9: 9.9.9.9)."
Write-Host "   - Enable 'DNS over HTTPS' (Automatic template)."
Write-Host "   - Disable 'Fallback to plaintext'."
Write-Host "   - Enter an alternate IPv4 DNS (e.g., Quad9: 149.112.112.112)."
Write-Host "   - Enable 'DNS over HTTPS' (Automatic template)."
Write-Host "   - Disable 'Fallback to plaintext'."
Write-Host "   - Enable 'IPv6' and enter preferred DNS (e.g., Quad9: 2620:fe::fe)."
Write-Host "   - Enable 'DNS over HTTPS' (Automatic template)."
Write-Host "   - Disable 'Fallback to plaintext'."
Write-Host "   - Enter an alternate IPv6 DNS (e.g., Quad9: 2620:fe::9)."
Write-Host "   - Enable 'DNS over HTTPS' (Automatic template)."
Write-Host "   - Disable 'Fallback to plaintext'."
Write-Host "   - Click 'Save'."
Write-Host ""

Write-Host "Press any key to exit"
Write-Host ""

$Host.UI.RawUI.ReadKey()