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

# Function to validate IP address (both IPv4 and IPv6)
function Test-ValidIP {
    param (
        [string]$ip
    )
    
    try {
        $parsedIP = [System.Net.IPAddress]::Parse($ip)
        # Exclude empty or invalid IPs
        return $ip -ne "-" -and $ip -ne "" -and $ip -ne $null
    } catch {
        return $false
    }
}

# Function to log messages with log rotation
function Log-Message {
    param (
        [string]$message
    )
    
    # Check if log file size exceeds 10MB
    if ((Test-Path $logPath) -and ((Get-Item $logPath).Length -gt 10MB)) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupPath = "$blacklistDir\log_$timestamp.txt"
        Rename-Item -Path $logPath -NewName $backupPath -Force
        New-Item -Path $logPath -ItemType File
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "$timestamp - $message"
}

# Function to check failed RDP attempts and update the blacklist
function Update-Blacklist {
    try {
        Log-Message "Starting Update-Blacklist function."

        # Enable audit policies
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable
        auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
        
        # Get failed RDP connection attempts from the event log
        $failedRDPAttempts = Get-WinEvent -LogName "Security" -FilterXPath "*[System[(EventID=4625)]]"

        if ($failedRDPAttempts.Count -eq 0) {
            Log-Message "No failed RDP attempts found."
            return
        }

        # Get existing blacklist and whitelist
        $existingBlacklist = @(Get-Content -Path $blacklistPath)
        $whitelist = @(Get-Content -Path $whitelistPath)

        # Group by source IP and count occurrences
        $ipGroups = $failedRDPAttempts | Group-Object -Property { $_.Properties[19].Value } | Where-Object { $_.Count -gt 3 }

        if ($ipGroups.Count -eq 0) {
            Log-Message "No IPs with more than 3 failed attempts."
            return
        }

        $blacklistUpdated = $false
        
        # Add IPs with more than 3 failed attempts to the blacklist, excluding whitelisted IPs
        foreach ($group in $ipGroups) {
            $sourceIP = $group.Name
            Log-Message "Processing IP: $sourceIP"
            
            if (Test-ValidIP -ip $sourceIP) {
                if ($whitelist -contains $sourceIP) {
                    Log-Message "$sourceIP is in whitelist - skipping."
                    continue
                }
                
                if ($existingBlacklist -contains $sourceIP) {
                    Log-Message "$sourceIP is already in blacklist - skipping."
                    continue
                }
                
                Add-Content -Path $blacklistPath -Value $sourceIP
                Log-Message "Added $sourceIP to blacklist."
                $blacklistUpdated = $true
            } else {
                Log-Message "$sourceIP is not a valid IP address - skipping."
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
        $blacklist = @(Get-Content -Path $blacklistPath)
        $whitelist = @(Get-Content -Path $whitelistPath)

        # Remove whitelisted IPs from the blacklist
        $effectiveBlacklist = $blacklist | Where-Object { $whitelist -notcontains $_ }

        if ($effectiveBlacklist.Count -eq 0) {
            Log-Message "Effective blacklist is empty. No firewall rule update needed."
            return
        }

        # Separate IPv4 and IPv6 addresses
        $ipv4List = @()
        $ipv6List = @()
        
        foreach ($ip in $effectiveBlacklist) {
            try {
                $parsedIP = [System.Net.IPAddress]::Parse($ip)
                if ($parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $ipv4List += $ip
                } elseif ($parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                    $ipv6List += $ip
                }
            } catch {
                Log-Message "Invalid IP address found in blacklist: $ip"
            }
        }

        # Update or create IPv4 rule
        $ruleName = "Block RDP from Blacklist - IPv4"
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($ipv4List.Count -gt 0) {
            if ($existingRule) {
                Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $ipv4List -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389 -Profile Any
                Log-Message "Updated existing IPv4 firewall rule."
            } else {
                New-NetFirewallRule -DisplayName $ruleName -RemoteAddress $ipv4List -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389 -Profile Any
                Log-Message "Created new IPv4 firewall rule."
            }
        }

        # Update or create IPv6 rule
        $ruleName = "Block RDP from Blacklist - IPv6"
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($ipv6List.Count -gt 0) {
            if ($existingRule) {
                Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $ipv6List -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389 -Profile Any
                Log-Message "Updated existing IPv6 firewall rule."
            } else {
                New-NetFirewallRule -DisplayName $ruleName -RemoteAddress $ipv6List -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389 -Profile Any
                Log-Message "Created new IPv6 firewall rule."
            }
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

# Define the trigger to run the task every 5 minutes indefinitely
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)

# Define the scheduled task settings
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# Register the scheduled task
Register-ScheduledTask -TaskName "UpdateRDPBlacklist" -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM"

Log-Message "Scheduled task registered successfully."
