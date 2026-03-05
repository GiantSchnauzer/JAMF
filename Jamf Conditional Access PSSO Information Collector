#!/bin/bash

####################################################################################################
#
# Script Name: Jamf Conditional Access PSSO Information Collector
#
# Description:
# This script collects Jamf Conditional Access and Microsoft Platform SSO information for the
# currently logged in macOS user. It executes Jamf Conditional Access commands in a specific order
# to retrieve version details, Azure AD user association, and Platform SSO registration metadata.
#
# The script gathers the following information:
# • Jamf Conditional Access version
# • Azure AD user association for the logged in macOS account
# • Platform SSO status code
# • Azure AD device metadata including Tenant ID and Device ID
# • Microsoft Enterprise SSO Extension full mode status
# • Azure authentication cloud host
#
# Execution Order:
# 1. Jamf Conditional Access version
# 2. Jamf Conditional Access gatherAADInfo
# 3. Jamf Conditional Access getPSSOStatus
#
# Jamf Pro Usage:
# This script can be used in two scenarios:
#
# 1. Extension Attribute
#    Configure this script as a Jamf Pro Extension Attribute to report Jamf Conditional Access
#    and Platform SSO related values during inventory submission.
#
# 2. Inventory Collection
#    The script collects data when a Jamf inventory update is performed. Inventory updates occur
#    when the command `jamf recon` is executed.
#
# Important Notes:
# • Jamf inventory must be updated using `jamf recon` for Jamf Pro to store the latest EA value.
# • If used as an Extension Attribute, it will run during inventory collection initiated by recon.
# • The script relies on Jamf Conditional Access components being installed on the device.
# • The script retrieves information for the currently logged in console user only.
#
# Author: Anyone
# Created: 2026-03-05
# Version: 1.0
#
# Change Log:
# 2026-03-05  v1.0  Initial version
#
####################################################################################################

set -euo pipefail

JCA="/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/Jamf Conditional Access.app/Contents/MacOS/Jamf Conditional Access"

if [[ ! -x "$JCA" ]]; then
  echo "ERROR: Jamf Conditional Access binary not found or not executable:"
  echo "$JCA"
  exit 1
fi

current_user="$(/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk -F': ' '/Name/{print $2}' | /usr/bin/awk 'NR==1{print $1}')"
if [[ -z "${current_user:-}" || "$current_user" == "loginwindow" ]]; then
  echo "ERROR: No active console user detected"
  exit 2
fi

echo "Current login user: $current_user"
echo ""

echo "1) Jamf Conditional Access version"
version_out="$("$JCA" version 2>&1 || true)"
echo "$version_out"
version_val="$(echo "$version_out" | /usr/bin/awk -F'=' '/version=/{print $2; exit}')"
echo ""

echo "2) Jamf Conditional Access gatherAADInfo"
gather_out="$("$JCA" gatherAADInfo 2>&1 || true)"
echo "$gather_out"
echo ""

echo "3) Jamf Conditional Access getPSSOStatus"
psso_out="$("$JCA" getPSSOStatus 2>&1 || true)"
echo "$psso_out"
echo ""

status_code="$(echo "$psso_out" | /usr/bin/awk 'NR==1{print $1}')"

upn="$(echo "$psso_out" | /usr/bin/sed -n 's/.*primary_registration_metadata_upn"):\s*\([^,]*\).*/\1/p' | /usr/bin/head -n 1)"
cloud_host="$(echo "$psso_out" | /usr/bin/sed -n 's/.*primary_registration_metadata_cloud_host"):\s*\([^,]*\).*/\1/p' | /usr/bin/head -n 1)"
device_id="$(echo "$psso_out" | /usr/bin/sed -n 's/.*primary_registration_metadata_device_id"):\s*\([^,]*\).*/\1/p' | /usr/bin/head -n 1)"
tenant_id="$(echo "$psso_out" | /usr/bin/sed -n 's/.*primary_registration_metadata_tenant_id"):\s*\([^]]*\).*/\1/p' | /usr/bin/head -n 1)"
full_mode="$(echo "$psso_out" | /usr/bin/sed -n 's/.*isSSOExtensionInFullMode"):\s*\([^,]*\).*/\1/p' | /usr/bin/head -n 1)"

echo "Parsed summary"
echo "version: ${version_val:-unknown}"
echo "psso_status_code: ${status_code:-unknown}"
echo "upn: ${upn:-unknown}"
echo "cloud_host: ${cloud_host:-unknown}"
echo "tenant_id: ${tenant_id:-unknown}"
echo "device_id: ${device_id:-unknown}"
echo "sso_full_mode: ${full_mode:-unknown}"
