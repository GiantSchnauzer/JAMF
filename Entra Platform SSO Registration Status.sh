#!/bin/zsh

####################################################################################################
#
# Extension Attribute: Entra / Platform SSO Registration Status (Lightweight)
#
# Description:
# This Extension Attribute reports the Microsoft Entra (Azure AD) Platform SSO registration status for the active console user on a macOS device managed by Jamf Pro.
#
# The script queries the Jamf Conditional Access framework (getPSSOStatus) to determine whether the device and user are registered with Microsoft Entra and capable of satisfying Conditional Access requirements.
#
# The output includes:
#	•	Registration state (Registered / Not Registered)
#	•	Platform SSO status code and interpretation
#	•	Azure tenant ID
#	•	Entra device ID
#	•	User principal name (UPN)
#	•	Cloud authentication host
#	•	Whether the SSO extension is running in full mode
#	•	JamfAAD Azure ID acquisition state
#	•	User home directory
#
# The script is optimized for Jamf inventory performance by inspecting only the current console user and avoiding multi-user scans or keychain enumeration.
#
# This Extension Attribute can be used to identify devices that are not properly registered with Microsoft Entra or where Platform SSO registration has failed.
#
####################################################################################################

jamfCA="/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/Jamf Conditional Access.app/Contents/MacOS/JAMF Conditional Access"

runAsUser() {
    local uid="$1"
    shift
    /bin/launchctl asuser "$uid" "$@"
}

get_value() {
    local source="$1"
    local key="$2"
    printf '%s\n' "$source" | /usr/bin/awk -F ": " -v k="$key" '$1 == k {print $2; exit}'
}

loggedInUser=$(/usr/bin/stat -f%Su /dev/console 2>/dev/null)
if [[ -z "$loggedInUser" || "$loggedInUser" == "root" || "$loggedInUser" == "loginwindow" ]]; then
    echo "<result>No active console user</result>"
    exit 0
fi

userUID=$(/usr/bin/id -u "$loggedInUser" 2>/dev/null)
if [[ -z "$userUID" ]]; then
    echo "<result>Unable to determine UID for $loggedInUser</result>"
    exit 0
fi

userHome=$(/usr/bin/dscl . -read "/Users/$loggedInUser" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{print $2}')
if [[ -z "$userHome" ]]; then
    echo "<result>Unable to determine home directory for $loggedInUser</result>"
    exit 0
fi

aadPlist="$userHome/Library/Preferences/com.jamf.management.jamfAAD.plist"
aadID="NotFound"

if [[ -f "$aadPlist" ]]; then
    aadID=$(/usr/bin/defaults read "$aadPlist" have_an_Azure_id 2>/dev/null)
    [[ -z "$aadID" ]] && aadID="0"
fi

if [[ ! -x "$jamfCA" ]]; then
    echo "<result>User: $loggedInUser
Home: $userHome
Status: Jamf Conditional Access binary not found
JamfAAD have_an_Azure_id: $aadID</result>"
    exit 0
fi

ssoStatus=$(runAsUser "$userUID" "$jamfCA" getPSSOStatus 2>/dev/null | /usr/bin/tr -d '()[]"' | /usr/bin/sed -E 's/, /\n/g')

if [[ -z "$ssoStatus" ]]; then
    echo "<result>User: $loggedInUser
Home: $userHome
Status: No getPSSOStatus data returned
JamfAAD have_an_Azure_id: $aadID</result>"
    exit 0
fi

rawStatus=$(printf '%s\n' "$ssoStatus" | /usr/bin/head -n1 | /usr/bin/tr -d '[:space:]')

case "$rawStatus" in
    0) pssoStatusText="pSSO Not Enabled" ;;
    1) pssoStatusText="pSSO Enabled not registered" ;;
    2) pssoStatusText="pSSO Enabled and registered" ;;
    *) pssoStatusText="Unknown pSSO State" ;;
esac

cleanStatus=$(printf '%s\n' "$ssoStatus" | /usr/bin/sed -E 's/(extraDeviceInformation |AnyHashable|primary_registration_metadata_)//g')

tenant_id=$(get_value "$cleanStatus" "tenant_id")
device_id=$(get_value "$cleanStatus" "device_id")
upn=$(get_value "$cleanStatus" "upn")
cloud_host=$(get_value "$cleanStatus" "cloud_host")
full_mode=$(get_value "$cleanStatus" "isSSOExtensionInFullMode")

[[ -z "$tenant_id" ]] && tenant_id="NotFound"
[[ -z "$device_id" ]] && device_id="NotFound"
[[ -z "$upn" ]] && upn="NotFound"
[[ -z "$cloud_host" ]] && cloud_host="NotFound"
[[ -z "$full_mode" ]] && full_mode="NotFound"

if [[ "$rawStatus" == "2" ]]; then
    registrationState="Registered"
elif [[ "$rawStatus" == "1" ]]; then
    registrationState="Not Fully Registered"
else
    registrationState="Not Registered"
fi

echo "<result>User: $loggedInUser
Home: $userHome
Registration: $registrationState
PSSO Status: $rawStatus ($pssoStatusText)
JamfAAD have_an_Azure_id: $aadID
tenant_id: $tenant_id
device_id: $device_id
isSSOExtensionInFullMode: $full_mode
cloud_host: $cloud_host
upn: $upn</result>"
