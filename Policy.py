import winreg
from openpyxl import Workbook
from datetime import datetime

# Initialize Excel workbook
timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
excel_file_path = f"WinSer2019_Audit_Report_{timestamp}.xlsx"
workbook = Workbook()
worksheet = workbook.active
worksheet.title = "Compliance Report"

# Write headers to the worksheet
headers = ["Sl no.", "Category", "Control Objective", "Compliance Status"]
worksheet.append(headers)

# Function to log messages to Excel
def log_to_excel(serial_number, category, control_objective, compliance_status):
    worksheet.append([serial_number, category, control_objective, compliance_status])

# Function to check compliance and log results
def check_compliance(serial_number, category, control_objective, check_function):
    compliance_status = check_function()
    if compliance_status == "Registry Not Found":
        compliance_status = "Registry Not Found"
    elif compliance_status == "Access Denied":
        compliance_status = "Access Denied"
    elif compliance_status:
        compliance_status = "Compliant"
    else:
        compliance_status = "Non-Compliant"
    log_to_excel(serial_number, category, control_objective, compliance_status)
    print(f"Serial Number: {serial_number}, Category: {category}, Control Objective: {control_objective}, Compliance Status: {compliance_status}")

# Define policy compliance check functions

def policy1_check():
    # Check 'Account lockout duration' is set to '15 or more minute(s).'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            lockout_duration, _ = winreg.QueryValueEx(key, "LockoutDuration")
        return lockout_duration >= 15
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy2_check():
    # Ensure 'Allow Administrator account lockout' is set to 'Enabled'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            enable_admin_lockout, _ = winreg.QueryValueEx(key, "EnableAdminAccountLockout")
        return enable_admin_lockout == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy3_check():
    # Ensure 'Reset account lockout counter after' is set to '15 or more minute(s).'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            reset_lockout_count, _ = winreg.QueryValueEx(key, "ResetLockoutCount")
        return reset_lockout_count >= 15
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy4_check():
    # Ensure 'Minimum password age' is set to '1 or more day(s).'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            min_password_age, _ = winreg.QueryValueEx(key, "MinimumPasswordAge")
        return min_password_age >= 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy5_check():
    # Ensure 'Maximum password age' is set to '60 or fewer days'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            max_password_age, _ = winreg.QueryValueEx(key, "MaximumPasswordAge")
        return max_password_age <= 60
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy6_check():
    # Ensure 'Minimum password length' is set to '14 or more characters'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            min_password_length, _ = winreg.QueryValueEx(key, "MinimumPasswordLength")
        return min_password_length >= 14
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy7_check():
    # Ensure 'Password must meet complexity requirements' is set to 'Enabled'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            password_complexity, _ = winreg.QueryValueEx(key, "PasswordComplexity")
        return password_complexity == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy8_check():
    # Ensure 'Store passwords using reversible encryption' is set to 'Disabled'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            reversible_encryption, _ = winreg.QueryValueEx(key, "ClearTextPassword")
        return reversible_encryption == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy9_check():
    # Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Cryptography") as key:
            credential_manager_access, _ = winreg.QueryValueEx(key, "DisableCredentialManager")
        return credential_manager_access == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy10_check():
    # Ensure 'Act as part of the operating system' is set to 'No One'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon") as key:
            operating_system_access, _ = winreg.QueryValueEx(key, "SeTcbPrivilege")
        return operating_system_access is None
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy11_check():
    # Ensure 'Add workstations to domain' is set to 'No One'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SAM\SAM\Domains\Account\Users\000001F5") as key:
            add_workstations, _ = winreg.QueryValueEx(key, "SeMachineAccountPrivilege")
        return add_workstations is None
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy12_check():
    # Ensure 'Guest account is disabled'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SAM\SAM\Domains\Account\Users\000001F5") as key:
            guest_account, _ = winreg.QueryValueEx(key, "Disabled")
        return guest_account == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy13_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy14_check():
    # Ensure 'Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            restrict_anonymous, _ = winreg.QueryValueEx(key, "RestrictAnonymous")
        return restrict_anonymous == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy15_check():
    # Ensure 'Do not store LAN Manager hash value on next password change' is set to 'Enabled'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            no_lanman_hash, _ = winreg.QueryValueEx(key, "NoLMHash")
        return no_lanman_hash == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy16_check():
    # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            restrict_anonymous_sam, _ = winreg.QueryValueEx(key, "RestrictAnonymousSAM")
        return restrict_anonymous_sam == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy17_check():
    # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            restrict_anonymous, _ = winreg.QueryValueEx(key, "RestrictAnonymous")
        return restrict_anonymous == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy18_check():
    # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            ntlm_ssp_client, _ = winreg.QueryValueEx(key, "NtlmMinClientSec")
        return ntlm_ssp_client == 536870912
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy19_check():
    # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            ntlm_ssp_server, _ = winreg.QueryValueEx(key, "NtlmMinServerSec")
        return ntlm_ssp_server == 536870912
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy20_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy21_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy22_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy23_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy24_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy25_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy26_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy27_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy28_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy29_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy30_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy31_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy32_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy33_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy34_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy35_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy36_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy37_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy38_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy39_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy40_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy41_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy42_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy43_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy44_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy45_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy46_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy47_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy48_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy49_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy50_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
    
def policy51_check():
    # Ensure 'Guest account status is set to Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SAM\SAM\Domains\Account\Users\000001F5") as key:
            guest_account_status, _ = winreg.QueryValueEx(key, "UserAccountControl")
        # Check if the Guest account is disabled (value has the 'ACCOUNTDISABLE' flag set, which is 0x0002)
        return (guest_account_status & 0x0002) != 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"


def policy52_check():
    # Ensure 'Audit account logon events' is set to 'Success and Failure'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\EventLog\Security") as key:
            audit_account_logon_events, _ = winreg.QueryValueEx(key, "AuditAccountLogon")
        return audit_account_logon_events == 3  # 3 means Success and Failure
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy53_check():
    # Ensure 'Audit logon events' is set to 'Success and Failure'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\EventLog\Security") as key:
            audit_logon_events, _ = winreg.QueryValueEx(key, "AuditLogon")
        return audit_logon_events == 3  # 3 means Success and Failure
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy54_check():
    # Ensure 'Audit object access' is set to 'Success and Failure'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\EventLog\Security") as key:
            audit_object_access, _ = winreg.QueryValueEx(key, "AuditObjectAccess")
        return audit_object_access == 3  # 3 means Success and Failure
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy55_check():
    # Ensure 'Audit process tracking' is set to 'Success and Failure'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\EventLog\Security") as key:
            audit_process_tracking, _ = winreg.QueryValueEx(key, "AuditProcessTracking")
        return audit_process_tracking == 3  # 3 means Success and Failure
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy56_check():
    # Ensure 'Audit policy change' is set to 'Success and Failure'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\EventLog\Security") as key:
            audit_policy_change, _ = winreg.QueryValueEx(key, "AuditPolicyChange")
        return audit_policy_change == 3  # 3 means Success and Failure
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy57_check():
    # Ensure 'Audit privilege use' is set to 'Success and Failure'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\EventLog\Security") as key:
            audit_privilege_use, _ = winreg.QueryValueEx(key, "AuditPrivilegeUse")
        return audit_privilege_use == 3  # 3 means Success and Failure
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy58_check():
    # Ensure 'Audit system events' is set to 'Success and Failure'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\EventLog\Security") as key:
            audit_system_events, _ = winreg.QueryValueEx(key, "AuditSystemEvents")
        return audit_system_events == 3  # 3 means Success and Failure
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy59_check():
    # Ensure 'Allow log on locally' is set to 'Administrators, Users'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Windows\Permissions") as key:
            allow_logon_locally, _ = winreg.QueryValueEx(key, "SeInteractiveLogonRight")
        return "Administrators" in allow_logon_locally and "Users" in allow_logon_locally
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy60_check():
    # Ensure 'Deny log on locally' is set to 'Guests'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Windows\Permissions") as key:
            deny_logon_locally, _ = winreg.QueryValueEx(key, "SeDenyInteractiveLogonRight")
        return "Guests" in deny_logon_locally
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy61_check():
    # Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services") as key:
            allow_logon_rds, _ = winreg.QueryValueEx(key, "SeRemoteInteractiveLogonRight")
        return "Administrators" in allow_logon_rds
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy62_check():
    # Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services") as key:
            deny_logon_rds, _ = winreg.QueryValueEx(key, "SeDenyRemoteInteractiveLogonRight")
        return "Guests" in deny_logon_rds
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy63_check():
    # Ensure 'Force logoff when logon hours expire' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            force_logoff_expired, _ = winreg.QueryValueEx(key, "ForceLogoffWhenLogonHoursExpire")
        return force_logoff_expired == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy64_check():
    # Ensure 'Smart card removal behavior' is set to 'Lock Workstation'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\SmartCardRemoval") as key:
            smart_card_removal, _ = winreg.QueryValueEx(key, "SmartCardRemovalPolicy")
        return smart_card_removal == 1  # 1 means Lock Workstation
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy65_check():
    # Ensure 'Require strong (Windows 2000 or later) session key' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            require_strong_session_key, _ = winreg.QueryValueEx(key, "RequireStrongKey")
        return require_strong_session_key == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy66_check():
    # Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            restrict_anonymous_access, _ = winreg.QueryValueEx(key, "RestrictAnonymous")
        return restrict_anonymous_access == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy67_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_auth_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_auth_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy68_check():
    # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            ntlm_client_security, _ = winreg.QueryValueEx(key, "NtlmMinClientSec")
        return ntlm_client_security == 536870912
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy69_check():
    # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            ntlm_server_security, _ = winreg.QueryValueEx(key, "NtlmMinServerSec")
        return ntlm_server_security == 536870912
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy70_check():
    # Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            allow_shutdown_without_logon, _ = winreg.QueryValueEx(key, "ShutdownWithoutLogon")
        return allow_shutdown_without_logon == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy71_check():
    # Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_admin_approval_mode, _ = winreg.QueryValueEx(key, "FilterAdministratorToken")
        return uac_admin_approval_mode == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy72_check():
    # Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent for non-Windows binaries'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_behavior_admin, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
        return uac_behavior_admin == 2
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy73_check():
    # Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_behavior_standard_user, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorUser")
        return uac_behavior_standard_user == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy74_check():
    # Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_detect_install, _ = winreg.QueryValueEx(key, "EnableInstallerDetection")
        return uac_detect_install == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy75_check():
    # Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_elevate_uiaccess, _ = winreg.QueryValueEx(key, "EnableSecureUIAPaths")
        return uac_elevate_uiaccess == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy76_check():
    # Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_admin_mode, _ = winreg.QueryValueEx(key, "EnableLUA")
        return uac_admin_mode == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy77_check():
    # Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_virtualize_failures, _ = winreg.QueryValueEx(key, "EnableVirtualization")
        return uac_virtualize_failures == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy78_check():
    # Ensure 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy") as key:
            fips_policy, _ = winreg.QueryValueEx(key, "Enabled")
        return fips_policy == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy79_check():
    # Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel") as key:
            require_case_insensitivity, _ = winreg.QueryValueEx(key, "ObCaseInsensitive")
        return require_case_insensitivity == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy80_check():
    # Ensure 'System settings: Optional subsystems' is set to 'No subsystems listed'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems") as key:
            optional_subsystems, _ = winreg.QueryValueEx(key, "Optional")
        return optional_subsystems == ""
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy81_check():
    # Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            block_microsoft_accounts, _ = winreg.QueryValueEx(key, "NoConnectedUser")
        return block_microsoft_accounts == 3
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy82_check():
    # Ensure 'Accounts: Guest account status' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SAM\SAM\Domains\Account\Users\000001F5") as key:
            guest_account_status, _ = winreg.QueryValueEx(key, "AccountDisabled")
        return guest_account_status == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy83_check():
    # Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            limit_blank_password_use, _ = winreg.QueryValueEx(key, "LimitBlankPasswordUse")
        return limit_blank_password_use == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy84_check():
    # Ensure 'Audit: Audit the access of global system objects' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager") as key:
            audit_global_system_objects, _ = winreg.QueryValueEx(key, "AuditBaseObjects")
        return audit_global_system_objects == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy85_check():
    # Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            shutdown_on_audit_fail, _ = winreg.QueryValueEx(key, "CrashOnAuditFail")
        return shutdown_on_audit_fail == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy86_check():
    # Ensure 'DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DCOM") as key:
            dcom_machine_access_restrictions, _ = winreg.QueryValueEx(key, "MachineAccessRestriction")
        return dcom_machine_access_restrictions is None
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy87_check():
    # Ensure 'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DCOM") as key:
            dcom_machine_launch_restrictions, _ = winreg.QueryValueEx(key, "MachineLaunchRestriction")
        return dcom_machine_launch_restrictions is None
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy88_check():
    # Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR") as key:
            allowed_to_eject_removable_media, _ = winreg.QueryValueEx(key, "Start")
        return allowed_to_eject_removable_media == 3
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy89_check():
    # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Print") as key:
            prevent_install_printer_drivers, _ = winreg.QueryValueEx(key, "NoAddPrinterDrivers")
        return prevent_install_printer_drivers == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy90_check():
    # Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Schedule") as key:
            allow_server_operators_schedule_tasks, _ = winreg.QueryValueEx(key, "AllowDomainUsersToCreateTask")
        return allow_server_operators_schedule_tasks == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy91_check():
    # Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters") as key:
            ldap_server_signing_requirements, _ = winreg.QueryValueEx(key, "LDAPServerIntegrity")
        return ldap_server_signing_requirements == 2
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy92_check():
    # Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            refuse_machine_account_password_changes, _ = winreg.QueryValueEx(key, "RefusePasswordChange")
        return refuse_machine_account_password_changes == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy93_check():
    # Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            secure_channel_encrypt_sign, _ = winreg.QueryValueEx(key, "SealSecureChannel")
        return secure_channel_encrypt_sign == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy94_check():
    # Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            secure_channel_encrypt, _ = winreg.QueryValueEx(key, "RequireSignOrSeal")
        return secure_channel_encrypt == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy95_check():
    # Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            require_strong_key, _ = winreg.QueryValueEx(key, "RequireStrongKey")
        return require_strong_key == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy96_check():
    # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            dont_display_last_username, _ = winreg.QueryValueEx(key, "DontDisplayLastUserName")
        return dont_display_last_username == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy97_check():
    # Ensure 'Interactive logon: Machine account lockout threshold' is set to '10 or more invalid logon attempts'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            lockout_threshold, _ = winreg.QueryValueEx(key, "MaxMachineAccountPasswordAge")
        return lockout_threshold >= 10
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy98_check():
    # Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s)'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            inactivity_limit, _ = winreg.QueryValueEx(key, "MaxIdlenessLimit")
        return inactivity_limit <= 900
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
        
def policy99_check():
    # Ensure 'Interactive logon: Prompt user to change password before expiration' is set to '14 or more day(s)'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            password_change_prompt, _ = winreg.QueryValueEx(key, "PasswordExpiryWarning")
        return password_change_prompt >= 14
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy100_check():
    # Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            require_dc_authentication, _ = winreg.QueryValueEx(key, "ForceUnlockLogon")
        return require_dc_authentication == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy101_check():
    # Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\SmartCardRemoval") as key:
            smart_card_removal_behavior, _ = winreg.QueryValueEx(key, "ForcePolicy")
        return smart_card_removal_behavior == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy102_check():
    # Ensure 'Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") as key:
            logons_to_cache, _ = winreg.QueryValueEx(key, "CachedLogonsCount")
        # Convert the retrieved value to an integer before comparison
        return int(logons_to_cache) <= 4
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
    except ValueError:
        return "Invalid Registry Value"

def policy103_check():
    # Ensure 'Interactive logon: Message title for users attempting to log on' is configured
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            message_title, _ = winreg.QueryValueEx(key, "LegalNoticeCaption")
        return bool(message_title.strip())
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy104_check():
    # Ensure 'Interactive logon: Message text for users attempting to log on' is configured
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            message_text, _ = winreg.QueryValueEx(key, "LegalNoticeText")
        return bool(message_text.strip())
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy105_check():
    # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") as key:
            digitally_sign_communications, _ = winreg.QueryValueEx(key, "RequireSecuritySignature")
        return digitally_sign_communications == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy106_check():
    # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") as key:
            send_unencrypted_password, _ = winreg.QueryValueEx(key, "EnablePlainTextPassword")
        return send_unencrypted_password == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy107_check():
    # Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            idle_time_before_suspending, _ = winreg.QueryValueEx(key, "IdleTimeout")
        return idle_time_before_suspending <= 15
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy108_check():
    # Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            digitally_sign_server_communications, _ = winreg.QueryValueEx(key, "RequireSecuritySignature")
        return digitally_sign_server_communications == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy109_check():
    # Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            disconnect_when_logon_hours_expire, _ = winreg.QueryValueEx(key, "EnableForcedLogOff")
        return disconnect_when_logon_hours_expire == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy110_check():
    # Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            allow_anonymous_sid_name_translation, _ = winreg.QueryValueEx(key, "AnonymousSidNameTranslation")
        return allow_anonymous_sid_name_translation == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy111_check():
    # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            restrict_anonymous_sam_shares, _ = winreg.QueryValueEx(key, "RestrictAnonymousSAM")
        return restrict_anonymous_sam_shares == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy112_check():
    # Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            no_password_storage, _ = winreg.QueryValueEx(key, "DisableDomainCreds")
        return no_password_storage == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy113_check():
    # Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            everyone_permissions_anonymous, _ = winreg.QueryValueEx(key, "EveryoneIncludesAnonymous")
        return everyone_permissions_anonymous == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy114_check():
    # Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            named_pipes_anonymous, _ = winreg.QueryValueEx(key, "NullSessionPipes")
        return named_pipes_anonymous == ""
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy115_check():
    # Ensure 'Network access: Remotely accessible registry paths' is set to a secure value
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            remotely_accessible_registry_paths, _ = winreg.QueryValueEx(key, "NullSessionShares")
        # Define a secure list of registry paths
        secure_paths = []
        return set(remotely_accessible_registry_paths.split(",")) <= set(secure_paths)
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy116_check():
    # Ensure 'Network access: Remotely accessible registry paths and sub-paths' is set to a secure value
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            remotely_accessible_registry_subpaths, _ = winreg.QueryValueEx(key, "NullSessionShares")
        # Define a secure list of registry paths and sub-paths
        secure_subpaths = []
        return set(remotely_accessible_registry_subpaths.split(",")) <= set(secure_subpaths)
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy117_check():
    # Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators Only'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            restrict_remote_calls_to_sam, _ = winreg.QueryValueEx(key, "RestrictRemoteSAM")
        return restrict_remote_calls_to_sam == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy118_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy119_check():
    # Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            ldap_client_signing_requirements, _ = winreg.QueryValueEx(key, "LDAPClientIntegrity")
        return ldap_client_signing_requirements == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy120_check():
    # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require 128-bit encryption'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            ntlm_client_security_min, _ = winreg.QueryValueEx(key, "NtlmMinClientSec")
        return ntlm_client_security_min == 536870912
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy121_check():
    # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require 128-bit encryption'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            ntlm_server_security_min, _ = winreg.QueryValueEx(key, "NtlmMinServerSec")
        return ntlm_server_security_min == 536870912
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy122_check():
    # Ensure 'Recovery console: Allow automatic administrative logon' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            recovery_console_admin_logon, _ = winreg.QueryValueEx(key, "RecoveryConsoleAdminPassword")
        return recovery_console_admin_logon == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy123_check():
    # Ensure 'Recovery console: Allow floppy copy and access to all drives and all folders' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            recovery_console_floppy_copy, _ = winreg.QueryValueEx(key, "RecoveryConsoleSecurityLevel")
        return recovery_console_floppy_copy == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy124_check():
    # Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            shutdown_without_logon, _ = winreg.QueryValueEx(key, "ShutdownWithoutLogon")
        return shutdown_without_logon == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy125_check():
    # Ensure 'Shutdown: Clear virtual memory pagefile' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management") as key:
            clear_virtual_memory_pagefile, _ = winreg.QueryValueEx(key, "ClearPageFileAtShutdown")
        return clear_virtual_memory_pagefile == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy126_check():
    # Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when key is first used or User must enter a password each time the key is used'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Cryptography") as key:
            force_strong_key_protection, _ = winreg.QueryValueEx(key, "ForceKeyProtection")
        return force_strong_key_protection in [1, 2]
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy127_check():
    # Ensure 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy") as key:
            use_fips_algorithms, _ = winreg.QueryValueEx(key, "Enabled")
        return use_fips_algorithms == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy128_check():
    # Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_admin_approval, _ = winreg.QueryValueEx(key, "FilterAdministratorToken")
        return uac_admin_approval == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy129_check():
    # Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_elevation_prompt, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
        return uac_elevation_prompt == 2
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy130_check():
    # Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_standard_users, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorUser")
        return uac_standard_users == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy131_check():
    # Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_detect_installations, _ = winreg.QueryValueEx(key, "EnableInstallerDetection")
        return uac_detect_installations == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy132_check():
    # Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_uiaccess, _ = winreg.QueryValueEx(key, "EnableSecureUIAPaths")
        return uac_uiaccess == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy133_check():
    # Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_run_admins, _ = winreg.QueryValueEx(key, "EnableLUA")
        return uac_run_admins == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy134_check():
    # Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_secure_desktop, _ = winreg.QueryValueEx(key, "PromptOnSecureDesktop")
        return uac_secure_desktop == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy135_check():
    # Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            uac_virtualization, _ = winreg.QueryValueEx(key, "EnableVirtualization")
        return uac_virtualization == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy136_check():
    # Ensure 'Accounts: Administrator account status' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SAM\SAM\Domains\Account\Users\000001F4") as key:
            admin_account_status, _ = winreg.QueryValueEx(key, "AccountDisabled")
        return admin_account_status == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy137_check():
    # Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            limit_blank_passwords, _ = winreg.QueryValueEx(key, "LimitBlankPasswordUse")
        return limit_blank_passwords == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy138_check():
    # Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            shutdown_on_audit_failure, _ = winreg.QueryValueEx(key, "CrashOnAuditFail")
        return shutdown_on_audit_failure == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy139_check():
    # Ensure 'DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DCOM") as key:
            dcom_machine_access, _ = winreg.QueryValueEx(key, "MachineAccessRestriction")
        return dcom_machine_access is None
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy140_check():
    # Ensure 'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DCOM") as key:
            dcom_machine_launch, _ = winreg.QueryValueEx(key, "MachineLaunchRestriction")
        return dcom_machine_launch is None
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy141_check():
    # Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR") as key:
            format_eject_media, _ = winreg.QueryValueEx(key, "Start")
        return format_eject_media == 3
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy142_check():
    # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Print") as key:
            prevent_printer_drivers, _ = winreg.QueryValueEx(key, "NoAddPrinterDrivers")
        return prevent_printer_drivers == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy143_check():
    # Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Schedule") as key:
            allow_scheduling_tasks, _ = winreg.QueryValueEx(key, "AllowDomainUsersToCreateTask")
        return allow_scheduling_tasks == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy144_check():
    # Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters") as key:
            ldap_signing_requirements, _ = winreg.QueryValueEx(key, "LDAPServerIntegrity")
        return ldap_signing_requirements == 2
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy145_check():
    # Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            refuse_password_changes, _ = winreg.QueryValueEx(key, "RefusePasswordChange")
        return refuse_password_changes == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy146_check():
    # Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            encrypt_sign_channel, _ = winreg.QueryValueEx(key, "SealSecureChannel")
        return encrypt_sign_channel == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy147_check():
    # Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            encrypt_channel, _ = winreg.QueryValueEx(key, "RequireSignOrSeal")
        return encrypt_channel == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy148_check():
    # Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            require_strong_key, _ = winreg.QueryValueEx(key, "RequireStrongKey")
        return require_strong_key == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy149_check():
    # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            dont_display_last_username, _ = winreg.QueryValueEx(key, "DontDisplayLastUserName")
        return dont_display_last_username == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy150_check():
    # Ensure 'Interactive logon: Machine account lockout threshold' is set to '10 or more invalid logon attempts'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            lockout_threshold, _ = winreg.QueryValueEx(key, "MaxMachineAccountPasswordAge")
        return lockout_threshold >= 10
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
def policy151_check():
    # Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            no_lanman_hash, _ = winreg.QueryValueEx(key, "NoLMHash")
        return no_lanman_hash == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy152_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_auth_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_auth_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy153_check():
    # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            ntlm_ssp_client, _ = winreg.QueryValueEx(key, "NtlmMinClientSec")
        return ntlm_ssp_client == 536870912
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy154_check():
    # Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            ntlm_ssp_server, _ = winreg.QueryValueEx(key, "NtlmMinServerSec")
        return ntlm_ssp_server == 536870912
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy155_check():
    # Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            limit_blank_passwords, _ = winreg.QueryValueEx(key, "LimitBlankPasswordUse")
        return limit_blank_passwords == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy156_check():
    # Ensure 'Audit: Audit the access of global system objects' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            audit_access_objects, _ = winreg.QueryValueEx(key, "AuditBaseObjects")
        return audit_access_objects == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy157_check():
    # Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            crash_on_audit_fail, _ = winreg.QueryValueEx(key, "CrashOnAuditFail")
        return crash_on_audit_fail == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy158_check():
    # Ensure 'DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DCOM") as key:
            machine_access_restrictions, _ = winreg.QueryValueEx(key, "MachineAccessRestriction")
        return machine_access_restrictions is None
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy159_check():
    # Ensure 'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DCOM") as key:
            machine_launch_restrictions, _ = winreg.QueryValueEx(key, "MachineLaunchRestriction")
        return machine_launch_restrictions is None
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy160_check():
    # Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices") as key:
            format_eject_media, _ = winreg.QueryValueEx(key, "RemovableDisks: Deny read access")
        return format_eject_media == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy161_check():
    # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers") as key:
            add_printer_drivers, _ = winreg.QueryValueEx(key, "AddPrinterDrivers")
        return add_printer_drivers == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy162_check():
    # Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            seal_secure_channel, _ = winreg.QueryValueEx(key, "SealSecureChannel")
        return seal_secure_channel == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy163_check():
    # Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            encrypt_secure_channel, _ = winreg.QueryValueEx(key, "EncryptSecureChannel")
        return encrypt_secure_channel == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy164_check():
    # Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            sign_secure_channel, _ = winreg.QueryValueEx(key, "SignSecureChannel")
        return sign_secure_channel == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy165_check():
    # Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            disable_password_changes, _ = winreg.QueryValueEx(key, "DisablePasswordChange")
        return disable_password_changes == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy166_check():
    # Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            max_password_age, _ = winreg.QueryValueEx(key, "MaximumPasswordAge")
        return int(max_password_age) <= 30
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
    except ValueError:
        return "Invalid Registry Value"

def policy167_check():
    # Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            require_strong_key, _ = winreg.QueryValueEx(key, "RequireStrongKey")
        return require_strong_key == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy168_check():
    # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            dont_display_last_user, _ = winreg.QueryValueEx(key, "DontDisplayLastUserName")
        return dont_display_last_user == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy169_check():
    # Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            dont_require_ctrl_alt_del, _ = winreg.QueryValueEx(key, "DisableCAD")
        return dont_require_ctrl_alt_del == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy170_check():
    # Ensure 'Interactive logon: Message text for users attempting to log on' is set to 'Not Blank'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            message_text, _ = winreg.QueryValueEx(key, "LegalNoticeText")
        return bool(message_text)
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy171_check():
    # Ensure 'Interactive logon: Message title for users attempting to log on' is set to 'Not Blank'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            message_title, _ = winreg.QueryValueEx(key, "LegalNoticeCaption")
        return bool(message_title)
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy172_check():
    # Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") as key:
            cached_logons_count, _ = winreg.QueryValueEx(key, "CachedLogonsCount")
        return int(cached_logons_count) <= 4
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
    except ValueError:
        return "Invalid Registry Value"

def policy173_check():
    # Ensure 'Interactive logon: Prompt user to change password before expiration' is set to '14 or more day(s)'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") as key:
            password_expiration_warning, _ = winreg.QueryValueEx(key, "PasswordExpiryWarning")
        return int(password_expiration_warning) >= 14
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
    except ValueError:
        return "Invalid Registry Value"

def policy174_check():
    # Ensure 'Interactive logon: Require smart card' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            require_smart_card, _ = winreg.QueryValueEx(key, "ScForceOption")
        return require_smart_card == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy175_check():
    # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") as key:
            require_security_signature, _ = winreg.QueryValueEx(key, "RequireSecuritySignature")
        return require_security_signature == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy176_check():
    # Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") as key:
            enable_security_signature, _ = winreg.QueryValueEx(key, "EnableSecuritySignature")
        return enable_security_signature == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy177_check():
    # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") as key:
            enable_plain_text_password, _ = winreg.QueryValueEx(key, "EnablePlainTextPassword")
        return enable_plain_text_password == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy178_check():
    # Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            auto_disconnect, _ = winreg.QueryValueEx(key, "AutoDisconnect")
        return int(auto_disconnect) <= 15
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
    except ValueError:
        return "Invalid Registry Value"

def policy179_check():
    # Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            require_security_signature, _ = winreg.QueryValueEx(key, "RequireSecuritySignature")
        return require_security_signature == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy180_check():
    # Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            enable_security_signature, _ = winreg.QueryValueEx(key, "EnableSecuritySignature")
        return enable_security_signature == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy181_check():
    # Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            enable_logon_hours, _ = winreg.QueryValueEx(key, "EnableForcedLogoff")
        return enable_logon_hours == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy182_check():
    # Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            anonymous_sid_name_translation, _ = winreg.QueryValueEx(key, "TurnOffAnonymousBlock")
        return anonymous_sid_name_translation == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy183_check():
    # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            restrict_anonymous_sam, _ = winreg.QueryValueEx(key, "RestrictAnonymousSAM")
        return restrict_anonymous_sam == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy184_check():
    # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            restrict_anonymous, _ = winreg.QueryValueEx(key, "RestrictAnonymous")
        return restrict_anonymous == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy185_check():
    # Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            everyone_anonymous_users, _ = winreg.QueryValueEx(key, "EveryoneIncludesAnonymous")
        return everyone_anonymous_users == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy186_check():
    # Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to ''
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            null_sessions_pipes, _ = winreg.QueryValueEx(key, "NullSessionPipes")
        return null_sessions_pipes == ''
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy187_check():
    # Ensure 'Network access: Remotely accessible registry paths and sub-paths' is set to ''
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            null_sessions_shares, _ = winreg.QueryValueEx(key, "NullSessionShares")
        return null_sessions_shares == ''
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy188_check():
    # Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            restrict_null_session_access, _ = winreg.QueryValueEx(key, "RestrictNullSessAccess")
        return restrict_null_session_access == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy189_check():
    # Ensure 'Network access: Shares that can be accessed anonymously' is set to ''
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            null_sessions_shares, _ = winreg.QueryValueEx(key, "NullSessionShares")
        return null_sessions_shares == ''
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy190_check():
    # Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            no_lm_hash, _ = winreg.QueryValueEx(key, "NoLMHash")
        return no_lm_hash == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy191_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy192_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy193_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy194_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy195_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy196_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy197_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy198_check():
    # Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            lm_authentication_level, _ = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        return lm_authentication_level == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy199_check():
    # Ensure 'Recovery console: Allow automatic administrative logon' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole") as key:
            auto_admin_logon, _ = winreg.QueryValueEx(key, "SecurityLevel")
        return auto_admin_logon == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy200_check():
    # Ensure 'Recovery console: Allow floppy copy and access to all drives and all folders' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole") as key:
            allow_floppy_copy, _ = winreg.QueryValueEx(key, "SetCommand")
        return allow_floppy_copy == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy201_check():
    # Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            shutdown_without_logon, _ = winreg.QueryValueEx(key, "ShutdownWithoutLogon")
        return shutdown_without_logon == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy202_check():
    # Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User must enter a password each time they use a key'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Cryptography") as key:
            force_strong_key_protection, _ = winreg.QueryValueEx(key, "ForceKeyProtection")
        return force_strong_key_protection == 2
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy203_check():
    # Ensure 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            fips_algorithm_policy, _ = winreg.QueryValueEx(key, "FIPSAlgorithmPolicy")
        return fips_algorithm_policy == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy204_check():
    # Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel") as key:
            ob_case_insensitive, _ = winreg.QueryValueEx(key, "ObCaseInsensitive")
        return ob_case_insensitive == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy205_check():
    # Ensure 'System settings: Optional subsystems' is set to 'Blank'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems") as key:
            optional, _ = winreg.QueryValueEx(key, "Optional")
        return optional == ''
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy206_check():
    # Ensure 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers") as key:
            authenticode_enabled, _ = winreg.QueryValueEx(key, "AuthenticodeEnabled")
        return authenticode_enabled == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy207_check():
    # Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            enable_lua, _ = winreg.QueryValueEx(key, "EnableLUA")
        return enable_lua == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy208_check():
    # Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            consent_prompt_behavior_admin, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
        return consent_prompt_behavior_admin == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy209_check():
    # Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent for non-Windows binaries'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            consent_prompt_behavior_admin, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
        return consent_prompt_behavior_admin == 5
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy210_check():
    # Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            consent_prompt_behavior_user, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorUser")
        return consent_prompt_behavior_user == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy211_check():
    # Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            enable_installer_detection, _ = winreg.QueryValueEx(key, "EnableInstallerDetection")
        return enable_installer_detection == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy212_check():
    # Ensure 'User Account Control: Only elevate executables that are signed and validated' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            validate_admin_code_signatures, _ = winreg.QueryValueEx(key, "ValidateAdminCodeSignatures")
        return validate_admin_code_signatures == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy213_check():
    # Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            elevate_uia_access, _ = winreg.QueryValueEx(key, "EnableUIADesktopToggle")
        return elevate_uia_access == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy214_check():
    # Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            enable_lua, _ = winreg.QueryValueEx(key, "EnableLUA")
        return enable_lua == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy215_check():
    # Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            prompt_on_secure_desktop, _ = winreg.QueryValueEx(key, "PromptOnSecureDesktop")
        return prompt_on_secure_desktop == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy216_check():
    # Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            enable_virtualization, _ = winreg.QueryValueEx(key, "EnableVirtualization")
        return enable_virtualization == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy217_check():
    # Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            limit_blank_password_use, _ = winreg.QueryValueEx(key, "LimitBlankPasswordUse")
        return limit_blank_password_use == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy218_check():
    # Ensure 'Audit: Audit the access of global system objects' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            audit_base_objects, _ = winreg.QueryValueEx(key, "AuditBaseObjects")
        return audit_base_objects == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy219_check():
    # Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            crash_on_audit_fail, _ = winreg.QueryValueEx(key, "CrashOnAuditFail")
        return crash_on_audit_fail == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy220_check():
    # Ensure 'DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DCOM") as key:
            machine_access_restriction, _ = winreg.QueryValueEx(key, "MachineAccessRestriction")
        return machine_access_restriction is None
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy221_check():
    # Ensure 'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DCOM") as key:
            machine_launch_restriction, _ = winreg.QueryValueEx(key, "MachineLaunchRestriction")
        return machine_launch_restriction is None
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy222_check():
    # Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices") as key:
            deny_read_access, _ = winreg.QueryValueEx(key, "DenyReadAccess")
        return deny_read_access == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy223_check():
    # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers") as key:
            add_printer_drivers, _ = winreg.QueryValueEx(key, "AddPrinterDrivers")
        return add_printer_drivers == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy224_check():
    # Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            seal_secure_channel, _ = winreg.QueryValueEx(key, "SealSecureChannel")
        return seal_secure_channel == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy225_check():
    # Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            encrypt_secure_channel, _ = winreg.QueryValueEx(key, "EncryptSecureChannel")
        return encrypt_secure_channel == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy226_check():
    # Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            sign_secure_channel, _ = winreg.QueryValueEx(key, "SignSecureChannel")
        return sign_secure_channel == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy227_check():
    # Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            disable_password_change, _ = winreg.QueryValueEx(key, "DisablePasswordChange")
        return disable_password_change == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy228_check():
    # Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            max_password_age, _ = winreg.QueryValueEx(key, "MaximumPasswordAge")
        return int(max_password_age) <= 30
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
    except ValueError:
        return "Invalid Registry Value"

def policy229_check():
    # Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") as key:
            require_strong_key, _ = winreg.QueryValueEx(key, "RequireStrongKey")
        return require_strong_key == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy230_check():
    # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            dont_display_last_user, _ = winreg.QueryValueEx(key, "DontDisplayLastUserName")
        return dont_display_last_user == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy231_check():
    # Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            disable_ctrl_alt_del, _ = winreg.QueryValueEx(key, "DisableCAD")
        return disable_ctrl_alt_del == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy232_check():
    # Ensure 'Interactive logon: Message text for users attempting to log on' is set to 'Not Blank'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            legal_notice_text, _ = winreg.QueryValueEx(key, "LegalNoticeText")
        return bool(legal_notice_text)
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy233_check():
    # Ensure 'Interactive logon: Message title for users attempting to log on' is set to 'Not Blank'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            legal_notice_caption, _ = winreg.QueryValueEx(key, "LegalNoticeCaption")
        return bool(legal_notice_caption)
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy234_check():
    # Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") as key:
            cached_logons_count, _ = winreg.QueryValueEx(key, "CachedLogonsCount")
        return int(cached_logons_count) <= 4
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
    except ValueError:
        return "Invalid Registry Value"

def policy235_check():
    # Ensure 'Interactive logon: Prompt user to change password before expiration' is set to '14 or more day(s)'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") as key:
            password_expiry_warning, _ = winreg.QueryValueEx(key, "PasswordExpiryWarning")
        return int(password_expiry_warning) >= 14
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
    except ValueError:
        return "Invalid Registry Value"

def policy236_check():
    # Ensure 'Interactive logon: Require smart card' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            sc_force_option, _ = winreg.QueryValueEx(key, "ScForceOption")
        return sc_force_option == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy237_check():
    # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") as key:
            require_security_signature, _ = winreg.QueryValueEx(key, "RequireSecuritySignature")
        return require_security_signature == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy238_check():
    # Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") as key:
            enable_security_signature, _ = winreg.QueryValueEx(key, "EnableSecuritySignature")
        return enable_security_signature == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy239_check():
    # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") as key:
            enable_plain_text_password, _ = winreg.QueryValueEx(key, "EnablePlainTextPassword")
        return enable_plain_text_password == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy240_check():
    # Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            auto_disconnect, _ = winreg.QueryValueEx(key, "AutoDisconnect")
        return int(auto_disconnect) <= 15
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"
    except ValueError:
        return "Invalid Registry Value"

def policy241_check():
    # Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            require_security_signature, _ = winreg.QueryValueEx(key, "RequireSecuritySignature")
        return require_security_signature == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy242_check():
    # Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            enable_security_signature, _ = winreg.QueryValueEx(key, "EnableSecuritySignature")
        return enable_security_signature == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy243_check():
    # Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            enable_forced_logoff, _ = winreg.QueryValueEx(key, "EnableForcedLogoff")
        return enable_forced_logoff == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy244_check():
    # Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            turn_off_anonymous_block, _ = winreg.QueryValueEx(key, "TurnOffAnonymousBlock")
        return turn_off_anonymous_block == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy245_check():
    # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            restrict_anonymous_sam, _ = winreg.QueryValueEx(key, "RestrictAnonymousSAM")
        return restrict_anonymous_sam == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy246_check():
    # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            restrict_anonymous, _ = winreg.QueryValueEx(key, "RestrictAnonymous")
        return restrict_anonymous == 1
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy247_check():
    # Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            everyone_includes_anonymous, _ = winreg.QueryValueEx(key, "EveryoneIncludesAnonymous")
        return everyone_includes_anonymous == 0
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def policy248_check():
    # Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to ''
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            null_session_pipes, _ = winreg.QueryValueEx(key, "NullSessionPipes")
        return null_session_pipes == ''
    except FileNotFoundError:
        return "Registry Not Found"
    except PermissionError:
        return "Access Denied"

def perform_compliance_checks():
    # Perform compliance checks for all policies
    check_compliance(1, "Account Lockout Policy", "Ensure 'Account lockout duration' is set to '15 or more minute(s).'", policy1_check)
    check_compliance(2, "Account Lockout Policy", "Ensure 'Allow Administrator account lockout' is set to 'Enabled'.", policy2_check)
    check_compliance(3, "Account Lockout Policy", "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s).'", policy3_check)
    check_compliance(4, "Password Policy", "Ensure 'Minimum password age' is set to '1 or more day(s).'", policy4_check)
    check_compliance(5, "Password Policy", "Ensure 'Maximum password age' is set to '60 or fewer days'.", policy5_check)
    check_compliance(6, "Password Policy", "Ensure 'Minimum password length' is set to '14 or more characters'.", policy6_check)
    check_compliance(7, "Password Policy", "Ensure 'Password must meet complexity requirements' is set to 'Enabled'.", policy7_check)
    check_compliance(8, "Password Policy", "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'.", policy8_check)
    check_compliance(9, "User Rights Assignment", "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'.", policy9_check)
    check_compliance(10, "User Rights Assignment", "Ensure 'Act as part of the operating system' is set to 'No One'.", policy10_check)
    check_compliance(11, "User Rights Assignment", "Ensure 'Add workstations to domain' is set to 'No One'.", policy11_check)
    check_compliance(12, "Account Policy", "Ensure 'Guest account is disabled'.", policy12_check)
    check_compliance(13, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy13_check)
    check_compliance(14, "Network Security", "Ensure 'Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'.", policy14_check)
    check_compliance(15, "Network Security", "Ensure 'Do not store LAN Manager hash value on next password change' is set to 'Enabled'.", policy15_check)
    check_compliance(16, "Network Security", "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'.", policy16_check)
    check_compliance(17, "Network Security", "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'.", policy17_check)
    check_compliance(18, "Network Security", "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'.", policy18_check)
    check_compliance(19, "Network Security", "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'.", policy19_check)
    check_compliance(20, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy20_check)
    check_compliance(21, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy21_check)
    check_compliance(22, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy22_check)
    check_compliance(23, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy23_check)
    check_compliance(24, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy24_check)
    check_compliance(25, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy25_check)
    check_compliance(26, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy26_check)
    check_compliance(27, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy27_check)
    check_compliance(28, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy28_check)
    check_compliance(29, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy29_check)
    check_compliance(30, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy30_check)
    check_compliance(31, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy31_check)
    check_compliance(32, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy32_check)
    check_compliance(33, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy33_check)
    check_compliance(34, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy34_check)
    check_compliance(35, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy35_check)
    check_compliance(36, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy36_check)
    check_compliance(37, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy37_check)
    check_compliance(38, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy38_check)
    check_compliance(39, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy39_check)
    check_compliance(40, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy40_check)
    check_compliance(41, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy41_check)
    check_compliance(42, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy42_check)
    check_compliance(43, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy43_check)
    check_compliance(44, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy44_check)
    check_compliance(45, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy45_check)
    check_compliance(46, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy46_check)
    check_compliance(47, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy47_check)
    check_compliance(48, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy48_check)
    check_compliance(49, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy49_check)
    check_compliance(50, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy50_check)
    check_compliance(51, "Guest Account", "Ensure 'Guest account status is set to Disabled'", policy51_check)
    check_compliance(52, "Audit Policy", "Ensure 'Audit account logon events' is set to 'Success and Failure'", policy52_check)
    check_compliance(53, "Audit Policy", "Ensure 'Audit logon events' is set to 'Success and Failure'", policy53_check)
    check_compliance(54, "Audit Policy", "Ensure 'Audit object access' is set to 'Success and Failure'", policy54_check)
    check_compliance(55, "Audit Policy", "Ensure 'Audit process tracking' is set to 'Success and Failure'", policy55_check)
    check_compliance(56, "Audit Policy", "Ensure 'Audit policy change' is set to 'Success and Failure'", policy56_check)
    check_compliance(57, "Audit Policy", "Ensure 'Audit privilege use' is set to 'Success and Failure'", policy57_check)
    check_compliance(58, "Audit Policy", "Ensure 'Audit system events' is set to 'Success and Failure'", policy58_check)
    check_compliance(59, "Logon Rights", "Ensure 'Allow log on locally' is set to 'Administrators, Users'", policy59_check)
    check_compliance(60, "Logon Rights", "Ensure 'Deny log on locally' is set to 'Guests'", policy60_check)
    check_compliance(61, "Remote Desktop Services", "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators'", policy61_check)
    check_compliance(62, "Remote Desktop Services", "Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests'", policy62_check)
    check_compliance(63, "Logon Hours", "Ensure 'Force logoff when logon hours expire' is set to 'Enabled'", policy63_check)
    check_compliance(64, "Smart Card", "Ensure 'Smart card removal behavior' is set to 'Lock Workstation'", policy64_check)
    check_compliance(65, "Session Key", "Ensure 'Require strong (Windows 2000 or later) session key' is set to 'Enabled'", policy65_check)
    check_compliance(66, "Network Access", "Ensure 'Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'", policy66_check)
    check_compliance(67, "LAN Manager", "Ensure 'LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'", policy67_check)
    check_compliance(68, "NTLM SSP", "Ensure 'Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security'", policy68_check)
    check_compliance(69, "NTLM SSP", "Ensure 'Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security'", policy69_check)
    check_compliance(70, "Shutdown", "Ensure 'Allow system to be shut down without having to log on' is set to 'Disabled'", policy70_check)
    check_compliance(71, "User Account Control", "Ensure 'Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'", policy71_check)
    check_compliance(72, "User Account Control", "Ensure 'Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent for non-Windows binaries'", policy72_check)
    check_compliance(73, "User Account Control", "Ensure 'Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'", policy73_check)
    check_compliance(74, "User Account Control", "Ensure 'Detect application installations and prompt for elevation' is set to 'Enabled'", policy74_check)
    check_compliance(75, "User Account Control", "Ensure 'Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'", policy75_check)
    check_compliance(76, "User Account Control", "Ensure 'Run all administrators in Admin Approval Mode' is set to 'Enabled'", policy76_check)
    check_compliance(77, "User Account Control", "Ensure 'Virtualize file and registry write failures to per-user locations' is set to 'Enabled'", policy77_check)
    check_compliance(78, "Cryptography", "Ensure 'Use FIPS compliant algorithms for encryption, hashing, and signing' is set to 'Enabled'", policy78_check)
    check_compliance(79, "System Objects", "Ensure 'Require case insensitivity for non-Windows subsystems' is set to 'Enabled'", policy79_check)
    check_compliance(80, "System Settings", "Ensure 'Optional subsystems' is set to 'No subsystems listed'", policy80_check)
    check_compliance(81, "Microsoft Accounts", "Ensure 'Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'", policy81_check)
    check_compliance(82, "Accounts", "Ensure 'Guest account status' is set to 'Disabled'", policy82_check)
    check_compliance(83, "Accounts", "Ensure 'Limit local account use of blank passwords to console logon only' is set to 'Enabled'", policy83_check)
    check_compliance(84, "Audit", "Ensure 'Audit the access of global system objects' is set to 'Disabled'", policy84_check)
    check_compliance(85, "Audit", "Ensure 'Shut down system immediately if unable to log security audits' is set to 'Enabled'", policy85_check)
    check_compliance(86, "DCOM", "Ensure 'Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'", policy86_check)
    check_compliance(87, "DCOM", "Ensure 'Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'", policy87_check)
    check_compliance(88, "Devices", "Ensure 'Allowed to format and eject removable media' is set to 'Administrators'", policy88_check)
    check_compliance(89, "Devices", "Ensure 'Prevent users from installing printer drivers' is set to 'Enabled'", policy89_check)
    check_compliance(90, "Domain Controller", "Ensure 'Allow server operators to schedule tasks' is set to 'Disabled'", policy90_check)
    check_compliance(91, "Domain Controller", "Ensure 'LDAP server signing requirements' is set to 'Require signing'", policy91_check)
    check_compliance(92, "Domain Controller", "Ensure 'Refuse machine account password changes' is set to 'Disabled'", policy92_check)
    check_compliance(93, "Domain Member", "Ensure 'Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'", policy93_check)
    check_compliance(94, "Domain Member", "Ensure 'Digitally encrypt secure channel data (when possible)' is set to 'Enabled'", policy94_check)
    check_compliance(95, "Domain Member", "Ensure 'Require strong (Windows 2000 or later) session key' is set to 'Enabled'", policy95_check)
    check_compliance(96, "Interactive Logon", "Ensure 'Do not display last user name' is set to 'Enabled'", policy96_check)
    check_compliance(97, "Interactive Logon", "Ensure 'Machine account lockout threshold' is set to '10 or more invalid logon attempts'", policy97_check)
    check_compliance(98, "Interactive Logon", "Ensure 'Machine inactivity limit' is set to '900 or fewer second(s)'", policy98_check)
    check_compliance(99, "Interactive Logon", "Ensure 'Prompt user to change password before expiration' is set to '14 or more day(s)'", policy99_check)
    check_compliance(100, "Interactive Logon", "Ensure 'Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'", policy100_check)
    check_compliance(101, "Smart Card", "Ensure 'Smart card removal behavior' is set to 'Lock Workstation'", policy101_check)
    check_compliance(102, "Logon Cache", "Ensure 'Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'", policy102_check)
    check_compliance(103, "Logon Message", "Ensure 'Message title for users attempting to log on' is configured", policy103_check)
    check_compliance(104, "Logon Message", "Ensure 'Message text for users attempting to log on' is configured", policy104_check)
    check_compliance(105, "Network Client", "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'", policy105_check)
    check_compliance(106, "Network Client", "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'", policy106_check)
    check_compliance(107, "Network Server", "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'", policy107_check)
    check_compliance(108, "Network Server", "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'", policy108_check)
    check_compliance(109, "Network Server", "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'", policy109_check)
    check_compliance(110, "Network Access", "Ensure 'Allow anonymous SID/Name translation' is set to 'Disabled'", policy110_check)
    check_compliance(111, "Network Access", "Ensure 'Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'", policy111_check)
    check_compliance(112, "Network Access", "Ensure 'Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'", policy112_check)
    check_compliance(113, "Network Access", "Ensure 'Let Everyone permissions apply to anonymous users' is set to 'Disabled'", policy113_check)
    check_compliance(114, "Network Access", "Ensure 'Named Pipes that can be accessed anonymously' is set to 'None'", policy114_check)
    check_compliance(115, "Network Access", "Ensure 'Remotely accessible registry paths' is set to a secure value", policy115_check)
    check_compliance(116, "Network Access", "Ensure 'Remotely accessible registry paths and sub-paths' is set to a secure value", policy116_check)
    check_compliance(117, "Network Access", "Ensure 'Restrict clients allowed to make remote calls to SAM' is set to 'Administrators Only'", policy117_check)
    check_compliance(118, "LAN Manager", "Ensure 'LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'", policy118_check)
    check_compliance(119, "LDAP Client", "Ensure 'LDAP client signing requirements' is set to 'Negotiate signing'", policy119_check)
    check_compliance(120, "NTLM SSP", "Ensure 'Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require 128-bit encryption'", policy120_check)
    check_compliance(121, "NTLM SSP", "Ensure 'Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require 128-bit encryption'", policy121_check)
    check_compliance(122, "Recovery Console", "Ensure 'Allow automatic administrative logon' is set to 'Disabled'", policy122_check)
    check_compliance(123, "Recovery Console", "Ensure 'Allow floppy copy and access to all drives and all folders' is set to 'Disabled'", policy123_check)
    check_compliance(124, "Shutdown", "Ensure 'Allow system to be shut down without having to log on' is set to 'Disabled'", policy124_check)
    check_compliance(125, "Shutdown", "Ensure 'Clear virtual memory pagefile' is set to 'Enabled'", policy125_check)
    check_compliance(126, "Cryptography", "Ensure 'Force strong key protection for user keys stored on the computer' is set to 'User is prompted when key is first used or User must enter a password each time the key is used'", policy126_check)
    check_compliance(127, "Cryptography", "Ensure 'Use FIPS compliant algorithms for encryption, hashing, and signing' is set to 'Enabled'", policy127_check)
    check_compliance(128, "User Account Control", "Ensure 'Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'", policy128_check)
    check_compliance(129, "User Account Control", "Ensure 'Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent'", policy129_check)
    check_compliance(130, "User Account Control", "Ensure 'Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'", policy130_check)
    check_compliance(131, "User Account Control", "Ensure 'Detect application installations and prompt for elevation' is set to 'Enabled'", policy131_check)
    check_compliance(132, "User Account Control", "Ensure 'Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'", policy132_check)
    check_compliance(133, "User Account Control", "Ensure 'Run all administrators in Admin Approval Mode' is set to 'Enabled'", policy133_check)
    check_compliance(134, "User Account Control", "Ensure 'Switch to the secure desktop when prompting for elevation' is set to 'Enabled'", policy134_check)
    check_compliance(135, "User Account Control", "Ensure 'Virtualize file and registry write failures to per-user locations' is set to 'Enabled'", policy135_check)
    check_compliance(136, "Accounts", "Ensure 'Administrator account status' is set to 'Disabled'", policy136_check)
    check_compliance(137, "Accounts", "Ensure 'Limit local account use of blank passwords to console logon only' is set to 'Enabled'", policy137_check)
    check_compliance(138, "Audit", "Ensure 'Shut down system immediately if unable to log security audits' is set to 'Enabled'", policy138_check)
    check_compliance(139, "DCOM", "Ensure 'Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'", policy139_check)
    check_compliance(140, "DCOM", "Ensure 'Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'", policy140_check)
    check_compliance(141, "Devices", "Ensure 'Allowed to format and eject removable media' is set to 'Administrators'", policy141_check)
    check_compliance(142, "Devices", "Ensure 'Prevent users from installing printer drivers' is set to 'Enabled'", policy142_check)
    check_compliance(143, "Domain Controller", "Ensure 'Allow server operators to schedule tasks' is set to 'Disabled'", policy143_check)
    check_compliance(144, "Domain Controller", "Ensure 'LDAP server signing requirements' is set to 'Require signing'", policy144_check)
    check_compliance(145, "Domain Controller", "Ensure 'Refuse machine account password changes' is set to 'Disabled'", policy145_check)
    check_compliance(146, "Domain Member", "Ensure 'Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'", policy146_check)
    check_compliance(147, "Domain Member", "Ensure 'Digitally encrypt secure channel data (when possible)' is set to 'Enabled'", policy147_check)
    check_compliance(148, "Domain Member", "Ensure 'Require strong (Windows 2000 or later) session key' is set to 'Enabled'", policy148_check)
    check_compliance(149, "Interactive Logon", "Ensure 'Do not display last user name' is set to 'Enabled'", policy149_check)
    check_compliance(150, "Interactive Logon", "Ensure 'Machine account lockout threshold' is set to '10 or more invalid logon attempts'", policy150_check)
    check_compliance(151, "Network Security", "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'.", policy103_check)
    check_compliance(152, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy104_check)
    check_compliance(153, "Network Security", "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'.", policy105_check)
    check_compliance(154, "Network Security", "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'.", policy106_check)
    check_compliance(155, "Accounts", "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'.", policy107_check)
    check_compliance(156, "Audit", "Ensure 'Audit: Audit the access of global system objects' is set to 'Disabled'.", policy108_check)
    check_compliance(157, "Audit", "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'.", policy109_check)
    check_compliance(158, "DCOM", "Ensure 'DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'.", policy110_check)
    check_compliance(159, "DCOM", "Ensure 'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'.", policy111_check)
    check_compliance(160, "Devices", "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'.", policy112_check)
    check_compliance(161, "Devices", "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'.", policy113_check)
    check_compliance(162, "Domain Member", "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'.", policy114_check)
    check_compliance(163, "Domain Member", "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'.", policy115_check)
    check_compliance(164, "Domain Member", "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'.", policy116_check)
    check_compliance(165, "Domain Member", "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'.", policy117_check)
    check_compliance(166, "Domain Member", "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days'.", policy118_check)
    check_compliance(167, "Domain Member", "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'.", policy119_check)
    check_compliance(167, "Interactive Logon", "Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'.", policy120_check)
    check_compliance(169, "Interactive Logon", "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'.", policy121_check)
    check_compliance(170, "Interactive Logon", "Ensure 'Interactive logon: Message text for users attempting to log on' is set to 'Not Blank'.", policy122_check)
    check_compliance(171, "Interactive Logon", "Ensure 'Interactive logon: Message title for users attempting to log on' is set to 'Not Blank'.", policy123_check)
    check_compliance(172, "Interactive Logon", "Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'.", policy124_check)
    check_compliance(173, "Interactive Logon", "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to '14 or more day(s)'.", policy125_check)
    check_compliance(174, "Interactive Logon", "Ensure 'Interactive logon: Require smart card' is set to 'Disabled'.", policy126_check)
    check_compliance(175, "Microsoft Network Client", "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'.", policy127_check)
    check_compliance(176, "Microsoft Network Client", "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'.", policy128_check)
    check_compliance(177, "Microsoft Network Client", "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'.", policy129_check)
    check_compliance(178, "Microsoft Network Server", "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'.", policy130_check)
    check_compliance(179, "Microsoft Network Server", "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'.", policy131_check)
    check_compliance(180, "Microsoft Network Server", "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'.", policy132_check)
    check_compliance(181, "Microsoft Network Server", "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'.", policy133_check)
    check_compliance(182, "Network Access", "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'.", policy134_check)
    check_compliance(183, "Network Access", "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'.", policy135_check)
    check_compliance(184, "Network Access", "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'.", policy136_check)
    check_compliance(185, "Network Access", "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'.", policy137_check)
    check_compliance(186, "Network Access", "Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to ''.", policy138_check)
    check_compliance(187, "Network Access", "Ensure 'Network access: Remotely accessible registry paths and sub-paths' is set to ''.", policy139_check)
    check_compliance(188, "Network Access", "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'.", policy140_check)
    check_compliance(189, "Network Access", "Ensure 'Network access: Shares that can be accessed anonymously' is set to ''.", policy141_check)
    check_compliance(190, "Network Security", "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'.", policy142_check)
    check_compliance(191, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy143_check)
    check_compliance(192, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy144_check)
    check_compliance(193, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy145_check)
    check_compliance(194, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy146_check)
    check_compliance(195, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy147_check)
    check_compliance(196, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy148_check)
    check_compliance(197, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy149_check)
    check_compliance(198, "Network Security", "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'.", policy150_check)
    check_compliance(199, "Recovery Console", "Ensure 'Recovery console: Allow automatic administrative logon' is set to 'Disabled'.", policy151_check)
    check_compliance(200, "Recovery Console", "Ensure 'Recovery console: Allow floppy copy and access to all drives and all folders' is set to 'Disabled'.", policy152_check)
    check_compliance(201, "Shutdown", "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'.", policy153_check)
    check_compliance(202, "System Cryptography", "Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User must enter a password each time they use a key'.", policy154_check)
    check_compliance(203, "System Cryptography", "Ensure 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' is set to 'Enabled'.", policy155_check)
    check_compliance(204, "System Objects", "Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'.", policy156_check)
    check_compliance(205, "System Settings", "Ensure 'System settings: Optional subsystems' is set to 'Blank'.", policy157_check)
    check_compliance(206, "System Settings", "Ensure 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' is set to 'Enabled'.", policy158_check)
    check_compliance(207, "User Account Control", "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'.", policy159_check)
    check_compliance(208, "User Account Control", "Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'.", policy160_check)
    check_compliance(209, "User Account Control", "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent for non-Windows binaries'.", policy161_check)
    check_compliance(210, "User Account Control", "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'.", policy162_check)
    check_compliance(211, "User Account Control", "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'.", policy163_check)
    check_compliance(212, "User Account Control", "Ensure 'User Account Control: Only elevate executables that are signed and validated' is set to 'Disabled'.", policy164_check)
    check_compliance(213, "User Account Control", "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'.", policy165_check)
    check_compliance(214, "User Account Control", "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'.", policy166_check)
    check_compliance(215, "User Account Control", "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'.", policy167_check)
    check_compliance(216, "User Account Control", "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'.", policy168_check)
    check_compliance(217, "Accounts", "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'.", policy169_check)
    check_compliance(218, "Audit", "Ensure 'Audit: Audit the access of global system objects' is set to 'Disabled'.", policy170_check)
    check_compliance(219, "Audit", "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'.", policy171_check)
    check_compliance(220, "DCOM", "Ensure 'DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'.", policy172_check)
    check_compliance(221, "DCOM", "Ensure 'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not Defined'.", policy173_check)
    check_compliance(222, "Devices", "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'.", policy174_check)
    check_compliance(223, "Devices", "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'.", policy175_check)
    check_compliance(224, "Domain Member", "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'.", policy176_check)
    check_compliance(225, "Domain Member", "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'.", policy177_check)
    check_compliance(226, "Domain Member", "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'.", policy178_check)
    check_compliance(227, "Domain Member", "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'.", policy179_check)
    check_compliance(228, "Domain Member", "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days'.", policy180_check)
    check_compliance(229, "Domain Member", "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'.", policy181_check)
    check_compliance(230, "Interactive Logon", "Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'.", policy182_check)
    check_compliance(231, "Interactive Logon", "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'.", policy183_check)
    check_compliance(232, "Interactive Logon", "Ensure 'Interactive logon: Message text for users attempting to log on' is set to 'Not Blank'.", policy184_check)
    check_compliance(233, "Interactive Logon", "Ensure 'Interactive logon: Message title for users attempting to log on' is set to 'Not Blank'.", policy185_check)
    check_compliance(234, "Interactive Logon", "Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'.", policy186_check)
    check_compliance(235, "Interactive Logon", "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to '14 or more day(s)'.", policy187_check)
    check_compliance(236, "Interactive Logon", "Ensure 'Interactive logon: Require smart card' is set to 'Disabled'.", policy188_check)
    check_compliance(237, "Microsoft Network Client", "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'.", policy189_check)
    check_compliance(238, "Microsoft Network Client", "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'.", policy190_check)
    check_compliance(239, "Microsoft Network Client", "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'.", policy191_check)
    check_compliance(240, "Microsoft Network Server", "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'.", policy192_check)
    check_compliance(241, "Microsoft Network Server", "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'.", policy193_check)
    check_compliance(242, "Microsoft Network Server", "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'.", policy194_check)
    check_compliance(243, "Microsoft Network Server", "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'.", policy195_check)
    check_compliance(244, "Network Access", "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'.", policy196_check)
    check_compliance(245, "Network Access", "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'.", policy197_check)
    check_compliance(246, "Network Access", "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'.", policy198_check)
    check_compliance(247, "Network Access", "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'.", policy199_check)
    check_compliance(248, "Network Access", "Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to ''.", policy200_check)

# Execute compliance checks
perform_compliance_checks()

# Save the workbook
workbook.save(excel_file_path)
