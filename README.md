# RDP Secure Script

## Overview

This PowerShell script is designed to enhance the security of Windows servers by monitoring failed Remote Desktop Protocol (RDP) login attempts and automatically blocking IP addresses that exceed a specified threshold of failed attempts. Additionally, it supports a whitelist to ensure that certain IP addresses are always allowed to connect.

## Features

- **Automatic IP Blocking**: Monitors failed RDP login attempts and blocks IP addresses with more than 3 failed attempts.
- **Whitelist Support**: Ensures that whitelisted IP addresses are never blocked.
- **Firewall Rule Management**: Updates the Windows Firewall to block IP addresses listed in the blacklist.
- **Scheduled Task**: Runs the script every 15 minutes to keep the blacklist and firewall rules updated.
- **Firewall Enablement**: Ensures the firewall is enabled for all profiles (Domain, Private, and Public).

## Prerequisites

- Windows Server with PowerShell installed.
- Administrative privileges to create scheduled tasks and modify firewall rules.

## Installation

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/Jurgens92/RDPSecure.git
   cd RDPSecure
   .\RDPSecure.ps1


## Create Required Directories and Files: Ensure the following directory and files exist:
C:\RDP\
C:\RDP\blacklist.txt
C:\RDP\whitelist.txt
C:\RDP\log.txt

## You can create them manually or the script will create them if they do not exist.
Edit the Whitelist: Add any IP addresses you want to whitelist to C:\RDP\whitelist.txt, one per line.
