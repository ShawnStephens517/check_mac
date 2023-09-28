#!/bin/bash

# Script to Perform Basic Audits on MacOS BigSur for DoD Compliance

# Function to create a logs directory and move CSV there
create_logs_folder_and_export() {
  logs_folder="./logs"
  if [ ! -d "$logs_folder" ]; then
    mkdir "$logs_folder"
  fi
  mv "$csv_file" "$logs_folder/"
}

current_date_time=$(date '+%Y-%m-%d_%H-%M-%S')
csv_file="./audit_results_${current_date_time}.csv"

# Initialize CSV file with headers
echo "Check,Statuqs,Command Ran" > $csv_file

# Function to log results to CSV file
log_to_csv() {
  echo "$1,$2,$3" >> $csv_file
}

echo "Starting DoD Compliance Audit for MacOS BigSur"

# Ensure Firewall is Enabled
echo "Checking if Firewall is Enabled..."
firewall_status=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)
if [[ $firewall_status == *"enabled"* ]]; then
  echo "Firewall is enabled."
  log_to_csv "Firewall" "Enabled" "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
else
  echo "Firewall is not enabled. Not compliant."
  log_to_csv "Firewall" "Not Compliant" "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
fi

# Check for Automatic Updates
echo "Checking for Automatic Updates..."
softwareupdate_status=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload)
if [[ $softwareupdate_status -eq 1 ]]; then
  echo "Automatic updates are enabled."
  log_to_csv "Automatic Updates" "Enabled" "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload"
else
  echo "Automatic updates are not enabled. Not compliant."
  log_to_csv "Automatic Updates" "Not Compliant" "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload"
fi

# Verify FileVault is active
echo "Checking if FileVault is active..."
filevault_status=$(fdesetup status)
if [[ $filevault_status == *"FileVault is On"* ]]; then
  echo "FileVault is active."
  log_to_csv "Filevault" "Active" "fdesetup status"
else
  echo "FileVault is not active. Not compliant."
  log_to_csv "FileVault" "Not Compliant" "fdesetup status"
fi

# Check for Remote Login (SSH)
echo "Checking for Remote Login (SSH)..."
remote_status=$(systemsetup -getremotelogin)
if [[ $remote_status == *"On"* ]]; then
  echo "Remote login is enabled. Not compliant."
  log_to_csv "Remote Login" "Not Compliant" "systemsetup -getremotelogin"
else
  echo "Remote login is disabled."
  log_to_csv "Remote Login" "Disabled" "systemsetup -getremotelogin"
fi

# Check if Gatekeeper is enabled
echo "Checking if Gatekeeper is enabled..."
gatekeeper_status=$(spctl --status)
if [[ $gatekeeper_status == *"assessments enabled"* ]]; then
  echo "Gatekeeper is enabled."
  log_to_csv "Gatekeeper" "Enabled" "spctl --status"
else
  echo "Gatekeeper is disabled. Not compliant."
  log_to_csv "Gatekeeper" "Not Compliant" "spctl --status"
fi

# Check SIP (System Integrity Protection) status
echo "Checking SIP status..."
sip_status=$(csrutil status)
if [[ $sip_status == *"enabled"* ]]; then
  echo "SIP is enabled."
  log_to_csv "SIP" "Enabled" "csrutil status"
else
  echo "SIP is disabled. Not compliant."
  log_to_csv "SIP" "Not Compliant" "csrutil status"
fi

# Check if root account is disabled
echo "Checking if root account is disabled..."
root_status=$(dscl . -read /Users/root AuthenticationAuthority)
if [[ $root_status == *"AuthenticationAuthority"* ]]; then
  echo "Root account is enabled. Not compliant."
  log_to_csv "Root Account" "Not Compliant" "dscl . -read /Users/root AuthenticationAuthority"
else
  echo "Root account is disabled."
  log_to_csv "Root Account" "Disabled" "dscl . -read /Users/root AuthenticationAuthority"
fi


# Check for password policies
echo "Checking for password policies..."
# Note: Replace 'someuser' with the username you want to check
password_policies=$(pwpolicy getaccountpolicies)
if [[ $password_policies == *"isPolicyActive: 1"* ]]; then
  echo "Password policies are active."
  log_to_csv "Password Policies" "Active" "pwpolicy getaccountpolicies"
else
  echo "Password policies are not active. Not compliant."
  log_to_csv "Password Policies" "Not Compliant" "pwpolicy getaccountpolicies"
fi

# List all installed applications
echo "Listing all installed applications..."
installed_apps=$(mdfind "kMDItemKind == 'Application'")
installed_apps=$(echo "$installed_apps" | tr '\n' ';')
echo "$installed_apps"
log_to_csv "Installed Applications" "$installed_apps" "mdfind "kMDItemKind == 'Application'""

# Check if Screen Saver is required to be password protected
echo "Checking if Screen Saver is password protected..."
screen_saver_pw=$(defaults -currentHost read /Library/Preferences/com.apple.screensaver askForPassword)
if [[ $screen_saver_pw -eq 1 ]]; then
  echo "Screen Saver is password protected."
  log_to_csv "Screen Saver" "Password Protected" "defaults -currentHost read /Library/Preferences/com.apple.screensaver askForPassword"
else
  echo "Screen Saver is not password protected. Not compliant."
  log_to_csv "Screen Saver" "Not Compliant" "defaults -currentHost read /Library/Preferences/com.apple.screensaver askForPassword"
fi

# Check for open network shares
echo "Checking for open network shares..."
open_shares=$(smbutil statshares -a)
if [[ $open_shares == *"NT_STATUS_OK"* ]]; then
  echo "Open network shares found. Not compliant." 
  log_to_csv "Network Shares (SMB)" "Not Compliant" "smbutil statshares -a"
else
  echo "No open network shares found."
  log_to_csv "Network Shares (SMB)" "None Found" "smbutil statshares -a"
fi

#TODO Fix this Check
# Check if Bluetooth is turned off
echo "Checking Bluetooth status..."
bluetooth_status=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState)
if [[ $bluetooth_status -eq 0 ]]; then
  echo "Bluetooth is disabled."
  log_to_csv "Bluetooth" "Broken Check" "defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState"
else
  echo "Bluetooth is enabled. Not compliant."
  log_to_csv "Bluetooth" "Broken Check" "defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState"
fi

#TODO Needs verification. If the /Users/Guest dir is not present it presents an error if ran from CMD
# Check if 'Guest' user is disabled
echo "Checking if 'Guest' user is disabled..."
guest_status=$(dscl . -read /Users/Guest | grep -i "UserShell: /usr/bin/false")
if [[ $guest_status ]]; then
  echo "'Guest' user is disabled. \n"
  log_to_csv "Guest User" "Disabled" "dscl . -read /Users/Guest | grep -i 'UserShell: /usr/bin/false'"
else
  echo "'Guest' user is enabled. Not compliant."
  log_to_csv "Guest User" "Non Compliant" "dscl . -read /Users/Guest | grep -i 'UserShell: /usr/bin/false'"
fi


# Check USB ports 
echo "Checking USB Connections..."
usb_status=$(system_profiler SPUSBDataType)
usb_status=$(echo "$usb_status" | awk -F': ' '/Manufacturer/{print $2}' | tr '\n' ';')
echo "$usb_status"
log_to_csv "USB Connections" "\"$usb_status\"" "system_profiler SPUSBDataType"


# Check if logging is enabled
echo "Checking if logging is enabled..."
audit_status=$(audit -s | grep "enabled")
if [[ $audit_status ]]; then
  echo "Logging is enabled."
  log_to_csv "Logging" "Enabled" "audit -s | grep "enabled""
else
  echo "Logging is disabled. Not compliant."
  log_to_csv "Logging" "Not Compliant" "audit -s | grep "enabled""
fi

# Additional checks can be added here


# Export all logs to logs folder
create_logs_folder_and_export


echo "DoD Compliance Audit Completed. Please consult official guidelines for comprehensive audit."

