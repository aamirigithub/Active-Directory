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
   - ⚠ (Warning)
   - ✗ (Error/Critical)

To run: Execute in PowerShell with Domain Admin privileges. Ensure RSAT-AD-PowerShell is installed first.
