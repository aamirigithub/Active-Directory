# Enhanced Active Directory Audit Script with Console Output and File Export

<#
.SYNOPSIS
    Active Directory Comprehensive Audit Script with Console and File Output
.DESCRIPTION
    Performs security and health checks on Active Directory and outputs results to both console and file
.NOTES
    Version: 1.3
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
    $finding = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        Check = $Check
        Status = $Status
        Severity = $Severity
        Details = $Details
    }
    $auditResults += $finding
    return $finding
}

# 1. Privileged Group Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Privileged Groups"
$privilegedGroups = "Domain Admins","Enterprise Admins","Schema Admins","Administrators"
foreach ($group in $privilegedGroups) {
    try {
        $members = Get-ADGroupMember $group -ErrorAction Stop | Select-Object -ExpandProperty Name
        if ($members.Count -gt 5) {
            Add-AuditFinding -Category "Privileged Access" -Check "$group Membership" -Status "Warning" -Severity "High" -Details "Group has $($members.Count) members: $($members -join ', ')"
        } elseif ($members) {
            Add-AuditFinding -Category "Privileged Access" -Check "$group Membership" -Status "OK" -Severity "Information" -Details "Members: $($members -join ', ')"
        }
    } catch {
        Add-AuditFinding -Category "Privileged Access" -Check "$group Membership" -Status "Error" -Severity "High" -Details "Failed to query group members: $_"
    }
}

# 2. Inactive Account Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Inactive Accounts"
try {
    $inactiveThreshold = (Get-Date).AddDays(-90)
    $inactiveUsers = Search-ADAccount -AccountInactive -UsersOnly -DateTime $inactiveThreshold -ErrorAction Stop | Where-Object { $_.Enabled }
    if ($inactiveUsers) {
        Add-AuditFinding -Category "Account Hygiene" -Check "Inactive Users" -Status "Warning" -Severity "Medium" -Details "$($inactiveUsers.Count) users inactive for 90+ days"
    } else {
        Add-AuditFinding -Category "Account Hygiene" -Check "Inactive Users" -Status "OK" -Severity "Information" -Details "No inactive users found"
    }
} catch {
    Add-AuditFinding -Category "Account Hygiene" -Check "Inactive Users" -Status "Error" -Severity "High" -Details "Failed to check inactive accounts: $_"
}

# 3. Password Policy Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Password Policies"
try {
    $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    if ($domainPolicy.MaxPasswordAge.Days -ge 90) {
        Add-AuditFinding -Category "Password Policy" -Check "Password Age" -Status "Warning" -Severity "Medium" -Details "Password expires every $($domainPolicy.MaxPasswordAge.Days) days (should be ≤ 90)"
    }
    if ($domainPolicy.ComplexityEnabled -eq $false) {
        Add-AuditFinding -Category "Password Policy" -Check "Complexity" -Status "Critical" -Severity "High" -Details "Password complexity not enforced"
    }
    if ($domainPolicy.MinPasswordLength -lt 8) {
        Add-AuditFinding -Category "Password Policy" -Check "Minimum Length" -Status "Warning" -Severity "Medium" -Details "Minimum password length is $($domainPolicy.MinPasswordLength) (should be ≥ 8)"
    }
} catch {
    Add-AuditFinding -Category "Password Policy" -Check "Password Policy" -Status "Error" -Severity "High" -Details "Failed to check password policy: $_"
}

# 4. Replication Health Check
Write-Progress -Activity "Auditing AD" -Status "Checking Replication"
try {
    $replSummary = repadmin /replsummary 2>&1
    $replErrors = $replSummary | Where-Object { $_ -match "FAILED" }
    if ($replErrors) {
        Add-AuditFinding -Category "Replication" -Check "Replication Errors" -Status "Critical" -Severity "High" -Details ($replErrors -join '; ')
    } else {
        Add-AuditFinding -Category "Replication" -Check "Replication Status" -Status "OK" -Severity "Information" -Details "No replication errors found"
    }
} catch {
    Add-AuditFinding -Category "Replication" -Check "Replication Check" -Status "Error" -Severity "High" -Details "Failed to check replication: $_"
}

# 5. GPO Audit
Write-Progress -Activity "Auditing AD" -Status "Checking GPOs"
try {
    $gpoWithPasswords = Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\" -Recurse -Force -ErrorAction Stop | Select-String "cpassword"
    if ($gpoWithPasswords) {
        Add-AuditFinding -Category "Group Policy" -Check "Stored Passwords" -Status "Critical" -Severity "High" -Details "Passwords found in GPOs"
    } else {
        Add-AuditFinding -Category "Group Policy" -Check "GPO Passwords" -Status "OK" -Severity "Information" -Details "No passwords found in GPOs"
    }
} catch {
    Add-AuditFinding -Category "Group Policy" -Check "GPO Audit" -Status "Error" -Severity "Medium" -Details "Failed to check GPOs: $_"
}

# 6. Kerberos Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Kerberos"
try {
    $kerberosPolicy = Get-ADAccountAuthorizationPolicy -ErrorAction Stop
    if ($kerberosPolicy.MaxTicketAge -gt 10) {
        Add-AuditFinding -Category "Authentication" -Check "Kerberos Ticket Age" -Status "Warning" -Severity "Medium" -Details "Max ticket age is $($kerberosPolicy.MaxTicketAge) hours (should be ≤ 10)"
    }
    if ($kerberosPolicy.MaxClockSkew -gt 5) {
        Add-AuditFinding -Category "Authentication" -Check "Clock Skew" -Status "Warning" -Severity "Medium" -Details "Max clock skew is $($kerberosPolicy.MaxClockSkew) minutes (should be ≤ 5)"
    }
} catch {
    Add-AuditFinding -Category "Authentication" -Check "Kerberos Policy" -Status "Error" -Severity "High" -Details "Failed to check Kerberos policy: $_"
}

# 7. DNS Health Check
Write-Progress -Activity "Auditing AD" -Status "Checking DNS"
try {
    $dnsTest = dcdiag /test:dns /v 2>&1
    if ($dnsTest -match "failed") {
        Add-AuditFinding -Category "DNS" -Check "DNS Health" -Status "Error" -Severity "High" -Details "DNS test failed"
    } else {
        Add-AuditFinding -Category "DNS" -Check "DNS Health" -Status "OK" -Severity "Information" -Details "DNS test passed"
    }
} catch {
    Add-AuditFinding -Category "DNS" -Check "DNS Check" -Status "Error" -Severity "High" -Details "Failed to check DNS: $_"
}

# 8. FSMO Roles Check
Write-Progress -Activity "Auditing AD" -Status "Checking FSMO Roles"
try {
    $fsmoRoles = netdom query fsmo 2>&1
    if ($fsmoRoles -match "error") {
        Add-AuditFinding -Category "FSMO Roles" -Check "Role Availability" -Status "Critical" -Severity "High" -Details "FSMO role check failed"
    } else {
        Add-AuditFinding -Category "FSMO Roles" -Check "Role Status" -Status "OK" -Severity "Information" -Details "All roles available: $($fsmoRoles -join ', ')"
    }
} catch {
    Add-AuditFinding -Category "FSMO Roles" -Check "FSMO Check" -Status "Error" -Severity "High" -Details "Failed to check FSMO roles: $_"
}

# Output results to console with color coding
Write-Progress -Activity "Auditing AD" -Completed
Write-Host "`nACTIVE DIRECTORY AUDIT RESULTS`n" -ForegroundColor Cyan

# Define color mapping for severity levels
$severityColors = @{
    "Critical" = "Red"
    "High" = "Magenta"
    "Medium" = "Yellow"
    "Information" = "Green"
}

# Display results in console with color coding
foreach ($result in ($auditResults | Sort-Object { 
    switch ($_.Severity) {
        "Critical" { 1 }
        "High" { 2 }
        "Medium" { 3 }
        default { 4 }
    }
})) {
    $color = $severityColors[$result.Severity]
    $statusSymbol = switch ($result.Status) {
        "OK" { "✓" }
        {$_ -match "Warning"} { "⚠" }
        {$_ -match "Error|Critical"} { "✗" }
        default { $_ }
    }
    
    Write-Host ("[{0}] {1}: {2} - {3}" -f 
        $result.Severity.ToUpper(),
        $result.Category,
        $result.Check,
        $result.Details) -ForegroundColor $color
}

# Export to CSV and HTML with timestamp
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$csvPath = "AD_Audit_$timestamp.csv"
$htmlPath = "AD_Audit_$timestamp.html"

# Export to CSV
$auditResults | Export-Csv -Path $csvPath -NoTypeInformation -Force

# Create HTML report
$htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory Audit Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        table { border-collapse: collapse; width: 100%; }
        th { background-color: #0066cc; color: white; text-align: left; padding: 8px; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        .Critical { background-color: #ffcccc; }
        .High { background-color: #ffdddd; }
        .Medium { background-color: #fff3cd; }
        .Information { background-color: #d4edda; }
    </style>
</head>
<body>
    <h1>Active Directory Audit Report</h1>
    <p>Generated on: $(Get-Date)</p>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Category</th>
            <th>Check</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Details</th>
        </tr>
"@

$htmlRows = $auditResults | ForEach-Object {
    $class = $_.Severity
    @"
        <tr class="$class">
            <td>$($_.Timestamp)</td>
            <td>$($_.Category)</td>
            <td>$($_.Check)</td>
            <td>$($_.Status)</td>
            <td>$($_.Severity)</td>
            <td>$($_.Details)</td>
        </tr>
"@
}

$htmlFooter = @"
    </table>
</body>
</html>
"@

$htmlContent = $htmlHeader + $htmlRows + $htmlFooter
$htmlContent | Out-File -FilePath $htmlPath -Force

Write-Host "`nResults exported to:" -ForegroundColor Green
Write-Host " - CSV file: $csvPath" -ForegroundColor Green
Write-Host " - HTML report: $htmlPath" -ForegroundColor Green
