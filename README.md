# Active-Directory

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

Category  : Privileged Access
Check     : Domain Admins Membership
Check     : Enterprise Admins Membership
Check     : Schema Admins Membership
Check     : Administrators Membership

Category  : Account Hygiene
Check     : Inactive Users detection (>90 days)

Category  : Password Policy
Check     : Password Age
Check     : Non-expiry password identification
Check     : Recently created accounts review
Check     : service accounts analysis with SPN details
Check     : disabled accounts in privileged groups

Category: System Analysis
Check: domain and forest information
Check: password policy compliance
Check: organizational units structure
Check: computer accounts statistics
Check: group policy objects analysis

Category  : Replication
Check     : Replication Status

Category  : Group Policy
Check     : GPO Passwords

Category  : Authentication
Check     : Kerberos Policy

Category  : DNS
Check     : DNS Health

Category  : FSMO Roles
Check     : Role Status

   - ⚠ (Warning)
   - ✗ (Error/Critical)

To run: Execute in PowerShell with Domain Admin privileges. Ensure RSAT-AD-PowerShell is installed first.
