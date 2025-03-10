# Windows 11 Privacy Settings

## Windows 11 Privacy Settings PowerShell script

This script follows Windows 11 privacy suggestions:
https://github.com/StellarSand/privacy-settings/blob/main/Privacy Settings/Windows-11.md

It covers the following:
- Changing Lock Screen & Screen Saver Settings
- Enabling Real-time Protection, Cloud Protection, but disable Automatic Sample Submission
- Enabling all Firewalls (Domain, Private, Public)
- Enabling Core Isolation - Memory Integrity (Requires Reboot)
- Disabling Windows welcome experience, tips, and suggestions
- Disabling Personalization for tips, shortcuts, new apps and device usage
- Disabling Snapshots and delete Snapshots
- Disabling Nearby Sharing
- Disabling Remote Desktop
- Enabling Storage Sense
- Delivery Optimization
- Disabling Phone Link
- Disabling App Permissions (Location, Camera, Mic, Notifications)
- Disabling AutoPlay
- Disabling Find My Device
- Disabling online speech recognition
- Blocking Microsoft telemetry
- Disabling ads in File Explorer
- Disabling Copilot
- Restarting Windows Explorer to apply settings

However not everything can be set by this PowerShell script

## Optional manual steps after script execution for better privacy:

Configure Ethernet & Wi-Fi DNS Settings:
   - Open Settings (Win + I) > Network & internet > Ethernet or Wi-Fi.
   - Click 'Hardware properties' > 'DNS server assignment' > 'Edit'.
   - Set 'Edit DNS settings' to 'Manual'.
   - Enable 'IPv4' and enter preferred DNS (e.g., Quad9: 9.9.9.9).
   - Enable 'DNS over HTTPS' (Automatic template).
   - Disable 'Fallback to plaintext'.
   - Enter an alternate IPv4 DNS (e.g., Quad9: 149.112.112.112).
   - Enable 'DNS over HTTPS' (Automatic template).
   - Disable 'Fallback to plaintext'.
   - Enable 'IPv6' and enter preferred DNS (e.g., Quad9: 2620:fe::fe).
   - Enable 'DNS over HTTPS' (Automatic template).
   - Disable 'Fallback to plaintext'.
   - Enter an alternate IPv6 DNS (e.g., Quad9: 2620:fe::9).
   - Enable 'DNS over HTTPS' (Automatic template).
   - Disable 'Fallback to plaintext'.
   - Click 'Save'.
