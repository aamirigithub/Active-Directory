# DSAI

# Active Directory Audit PowerShell Script

This script automates a comprehensive AD audit and outputs the results in a structured table format with severity classification.

```powershell
<#
.SYNOPSIS
    Active Directory Comprehensive Audit Script
.DESCRIPTION
    Performs security and health checks on Active Directory and outputs results in a tabular format
    with severity classification (Critical, Error, Warning, Information).
.NOTES
    Version: 1.2
    Requires: ActiveDirectory module, Domain Admin privileges
#>

# Import required module
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
if (-not (Get-Module ActiveDirectory)) {
    Write-Host "ActiveDirectory module not found. Install RSAT-AD-PowerShell first." -ForegroundColor Red
    exit
}

# Initialize results array
$auditResults = @()

# Function to add findings to results
function Add-AuditFinding {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,
        [string]$Severity,
        [string]$Details
    )
    $auditResults += [PSCustomObject]@{
        Category = $Category
        Check = $Check
        Status = $Status
        Severity = $Severity
        Details = $Details
    }
}

# 1. Privileged Group Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Privileged Groups"
$privilegedGroups = "Domain Admins","Enterprise Admins","Schema Admins","Administrators"
foreach ($group in $privilegedGroups) {
    $members = Get-ADGroupMember $group -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    if ($members.Count -gt 5) {
        Add-AuditFinding -Category "Privileged Access" -Check "$group Membership" -Status "Warning" -Severity "High" -Details "Group has $($members.Count) members: $($members -join ', ')"
    } elseif ($members) {
        Add-AuditFinding -Category "Privileged Access" -Check "$group Membership" -Status "OK" -Severity "Information" -Details "Members: $($members -join ', ')"
    }
}

# 2. Inactive Account Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Inactive Accounts"
$inactiveThreshold = (Get-Date).AddDays(-90)
$inactiveUsers = Search-ADAccount -AccountInactive -UsersOnly -DateTime $inactiveThreshold | Where-Object { $_.Enabled }
if ($inactiveUsers) {
    Add-AuditFinding -Category "Account Hygiene" -Check "Inactive Users" -Status "Warning" -Severity "Medium" -Details "$($inactiveUsers.Count) users inactive for 90+ days"
}

# 3. Password Policy Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Password Policies"
$domainPolicy = Get-ADDefaultDomainPasswordPolicy
if ($domainPolicy.MaxPasswordAge.Days -ge 90) {
    Add-AuditFinding -Category "Password Policy" -Check "Password Age" -Status "Warning" -Severity "Medium" -Details "Password expires every $($domainPolicy.MaxPasswordAge.Days) days (should be ≤ 90)"
}
if ($domainPolicy.ComplexityEnabled -eq $false) {
    Add-AuditFinding -Category "Password Policy" -Check "Complexity" -Status "Critical" -Severity "High" -Details "Password complexity not enforced"
}

# 4. Replication Health Check
Write-Progress -Activity "Auditing AD" -Status "Checking Replication"
try {
    $replErrors = repadmin /replsummary 2>&1 | Where-Object { $_ -match "FAILED" }
    if ($replErrors) {
        Add-AuditFinding -Category "Replication" -Check "Replication Errors" -Status "Critical" -Severity "High" -Details ($replErrors -join '; ')
    }
} catch {
    Add-AuditFinding -Category "Replication" -Check "Replication Check" -Status "Error" -Severity "High" -Details "Failed to check replication"
}

# 5. GPO Audit
Write-Progress -Activity "Auditing AD" -Status "Checking GPOs"
try {
    $gpoWithPasswords = Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\" -Recurse -Force -ErrorAction SilentlyContinue | Select-String "cpassword"
    if ($gpoWithPasswords) {
        Add-AuditFinding -Category "Group Policy" -Check "Stored Passwords" -Status "Critical" -Severity "High" -Details "Passwords found in GPOs"
    }
} catch {
    Add-AuditFinding -Category "Group Policy" -Check "GPO Audit" -Status "Error" -Severity "Medium" -Details "Failed to check GPOs"
}

# 6. Kerberos Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Kerberos"
$kerberosPolicy = Get-ADAccountAuthorizationPolicy
if ($kerberosPolicy.MaxTicketAge -gt 10) {
    Add-AuditFinding -Category "Authentication" -Check "Kerberos Ticket Age" -Status "Warning" -Severity "Medium" -Details "Max ticket age is $($kerberosPolicy.MaxTicketAge) hours (should be ≤ 10)"
}

# 7. DNS Health Check
Write-Progress -Activity "Auditing AD" -Status "Checking DNS"
try {
    $dnsTest = dcdiag /test:dns /v
    if ($dnsTest -match "failed") {
        Add-AuditFinding -Category "DNS" -Check "DNS Health" -Status "Error" -Severity "High" -Details "DNS test failed"
    }
} catch {
    Add-AuditFinding -Category "DNS" -Check "DNS Check" -Status "Error" -Severity "High" -Details "Failed to check DNS"
}

# 8. FSMO Roles Check
Write-Progress -Activity "Auditing AD" -Status "Checking FSMO Roles"
try {
    $fsmoRoles = netdom query fsmo 2>&1
    if ($fsmoRoles -match "error") {
        Add-AuditFinding -Category "FSMO Roles" -Check "Role Availability" -Status "Critical" -Severity "High" -Details "FSMO role check failed"
    } else {
        Add-AuditFinding -Category "FSMO Roles" -Check "Role Status" -Status "OK" -Severity "Information" -Details "All roles available"
    }
} catch {
    Add-AuditFinding -Category "FSMO Roles" -Check "FSMO Check" -Status "Error" -Severity "High" -Details "Failed to check FSMO roles"
}

# Output results in formatted table
Write-Progress -Activity "Auditing AD" -Completed
Write-Host "`nACTIVE DIRECTORY AUDIT RESULTS`n" -ForegroundColor Cyan
$auditResults | Sort-Object Severity,Category | Format-Table -AutoSize -Wrap -Property @(
    @{Label="Severity"; Expression={
        switch ($_.Severity) {
            "Critical" { "CRITICAL" }
            "High" { "HIGH" }
            "Medium" { "MEDIUM" }
            default { "INFO" }
        }
    }}
    @{Label="Category"; Expression={$_.Category}}
    @{Label="Check"; Expression={$_.Check}}
    @{Label="Status"; Expression={
        switch ($_.Status) {
            "OK" { "✓" }
            {$_ -match "Warning"} { "⚠" }
            {$_ -match "Error|Critical"} { "✗" }
            default { $_ }
        }
    }}
    @{Label="Details"; Expression={$_.Details}}
)

# Export to CSV with timestamp
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$auditResults | Export-Csv -Path "AD_Audit_$timestamp.csv" -NoTypeInformation
Write-Host "`nResults exported to AD_Audit_$timestamp.csv" -ForegroundColor Green
```

## Sample Output Structure

```
ACTIVE DIRECTORY AUDIT RESULTS

Severity Category            Check                     Status Details
------- --------            -----                     ------ -------
CRITICAL Password Policy     Complexity                ✗      Password complexity not enforced
HIGH     Privileged Access  Domain Admins Membership  ⚠      Group has 8 members: Admin1, Admin2...
HIGH     Replication        Replication Errors        ✗      FAILED: DC1 to DC2
MEDIUM   Account Hygiene    Inactive Users           ⚠      15 users inactive for 90+ days
INFO     FSMO Roles         Role Status               ✓      All roles available
```

## Key Features

1. **Comprehensive Checks**:
   - Privileged group membership
   - Inactive/expired accounts
   - Password policies
   - Replication health
   - GPO vulnerabilities
   - Kerberos settings
   - DNS health
   - FSMO roles

2. **Severity Classification**:
   - Critical (immediate action needed)
   - High (security risks)
   - Medium (best practice violations)
   - Information (status updates)

3. **Automated Reporting**:
   - On-screen formatted table
   - CSV export with timestamp

4. **Visual Indicators**:
   - ✓ (OK)
   - ⚠ (Warning)
   - ✗ (Error/Critical)

To run: Execute in PowerShell with Domain Admin privileges. Ensure RSAT-AD-PowerShell is installed first.