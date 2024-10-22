# Define the path to the blacklist, whitelist, and log files
$blacklistDir = "C:\RDP"
$blacklistPath = "$blacklistDir\blacklist.txt"
$whitelistPath = "$blacklistDir\whitelist.txt"
$logPath = "$blacklistDir\log.txt"

# Create the directory if it doesn't exist
if (-not (Test-Path $blacklistDir)) {
    New-Item -Path $blacklistDir -ItemType Directory
}

# Create the blacklist and whitelist files if they don't exist
if (-not (Test-Path $blacklistPath)) {
    New-Item -Path $blacklistPath -ItemType File
}
if (-not (Test-Path $whitelistPath)) {
    New-Item -Path $whitelistPath -ItemType File
}

# Create the log file if it doesn't exist
if (-not (Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType File
}

# Function to log messages
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "$timestamp - $message"
}

# Function to check failed RDP attempts and update the blacklist
function Update-Blacklist {
    try {
        Log-Message "Starting Update-Blacklist function."

        # Get failed RDP connection attempts from the event log
        $failedRDPAttempts = Get-WinEvent -LogName "Security" -FilterXPath "*[System[(EventID=4625)]]"

        if ($failedRDPAttempts.Count -eq 0) {
            Log-Message "No failed RDP attempts found."
            return
        }

        # Log details of each failed attempt for debugging
        foreach ($event in $failedRDPAttempts) {
            $properties = $event.Properties | ForEach-Object { $_.Value }
            Log-Message "Event ID: $($event.Id), Properties: $($properties -join ', ')"
        }

        # Group by source IP and count occurrences
        $ipGroups = $failedRDPAttempts | Group-Object -Property { $_.Properties[19].Value } | Where-Object { $_.Count -gt 3 }

        if ($ipGroups.Count -eq 0) {
            Log-Message "No IPs with more than 3 failed attempts."
            return
        }

        # Add IPs with more than 3 failed attempts to the blacklist, excluding whitelisted IPs
        $whitelist = Get-Content -Path $whitelistPath
        foreach ($group in $ipGroups) {
            $sourceIP = $group.Name
            Log-Message "Processing IP: $sourceIP"
            if ($sourceIP -and $sourceIP -ne "-" -and $sourceIP -match "^\d{1,3}(\.\d{1,3}){3}$" -and -not (Get-Content $blacklistPath | Select-String -Pattern $sourceIP) -and -not ($whitelist -contains $sourceIP)) {
                Add-Content -Path $blacklistPath -Value $sourceIP
                Log-Message "Added $sourceIP to blacklist."
            } else {
                Log-Message "$sourceIP is already in the blacklist, is invalid, or is whitelisted."
            }
        }

        Log-Message "Update-Blacklist function completed successfully."
    } catch {
        Log-Message "Error in Update-Blacklist function: $_"
    }
}

# Function to enable the firewall for all profiles
function Enable-Firewall {
    try {
        Log-Message "Starting Enable-Firewall function."

        # Enable the firewall for all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

        Log-Message "Firewall enabled for all profiles."
    } catch {
        Log-Message "Error in Enable-Firewall function: $_"
    }
}

# Function to update the firewall rule
function Update-FirewallRule {
    try {
        Log-Message "Starting Update-FirewallRule function."

        # Read the blacklist and whitelist files
        $blacklist = Get-Content -Path $blacklistPath
        $whitelist = Get-Content -Path $whitelistPath

        # Remove whitelisted IPs from the blacklist
        $effectiveBlacklist = $blacklist | Where-Object { $whitelist -notcontains $_ }

        if ($effectiveBlacklist.Count -eq 0) {
            Log-Message "Effective blacklist is empty. No firewall rule update needed."
            return
        }

        # Create or update the firewall rule
        $existingRule = Get-NetFirewallRule -DisplayName "Block RDP from Blacklist" -ErrorAction SilentlyContinue
        if ($existingRule) {
            Set-NetFirewallRule -DisplayName "Block RDP from Blacklist" -RemoteAddress $effectiveBlacklist -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389 -Profile Any
            Log-Message "Updated existing firewall rule with new effective blacklist."
        } else {
            New-NetFirewallRule -DisplayName "Block RDP from Blacklist" -RemoteAddress $effectiveBlacklist -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389 -Profile Any
            Log-Message "Created new firewall rule with effective blacklist."
        }

        Log-Message "Update-FirewallRule function completed successfully."
    } catch {
        Log-Message "Error in Update-FirewallRule function: $_"
    }
}

# Run the functions
Enable-Firewall
Update-Blacklist
Update-FirewallRule

# Define the scheduled task action to run this script
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$PSScriptRoot\RDPSecure.ps1`""

# Define the trigger to run the task every 15 minutes
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 1)

# Define the scheduled task settings
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# Register the scheduled task
Register-ScheduledTask -TaskName "UpdateRDPBlacklist" -Action $action -Trigger $trigger -Settings $settings

Log-Message "Scheduled task registered successfully."
