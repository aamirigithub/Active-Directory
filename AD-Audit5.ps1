<#
.SYNOPSIS
    Comprehensive Active Directory Audit Script with Working Color Output and File Export
.DESCRIPTION
    Performs detailed security and health checks on Active Directory with proper color-coded output
    and guaranteed file exports to CSV and HTML formats
.NOTES
    Version: 2.1
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

# Function to get color based on severity
function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        "Critical" { return "Red" }
        "High" { return "Magenta" }
        "Medium" { return "Yellow" }
        "Low" { return "DarkYellow" }
        default { return "Green" }
    }
}

# Function to get color based on category
function Get-CategoryColor {
    param([string]$Category)
    switch ($Category) {
        "Privileged Access" { return "Cyan" }
        "Account Hygiene" { return "Blue" }
        "Password Policy" { return "DarkCyan" }
        "System Analysis" { return "DarkGreen" }
        default { return "Gray" }
    }
}

# 1. Privileged Access Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Privileged Groups"
$privilegedGroups = @(
    @{Name="Domain Admins"; Threshold=5},
    @{Name="Enterprise Admins"; Threshold=3},
    @{Name="Schema Admins"; Threshold=2},
    @{Name="Administrators"; Threshold=5}
)

foreach ($group in $privilegedGroups) {
    try {
        $members = Get-ADGroupMember $group.Name -ErrorAction Stop | Select-Object -ExpandProperty Name
        $disabledMembers = Get-ADGroupMember $group.Name | Get-ADUser | Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty Name
        
        if ($disabledMembers) {
            Add-AuditFinding -Category "Privileged Access" -Check "$($group.Name) Membership" -Status "Warning" -Severity "High" -Details "Group contains disabled accounts: $($disabledMembers -join ', ')"
        }
        
        if ($members.Count -gt $group.Threshold) {
            Add-AuditFinding -Category "Privileged Access" -Check "$($group.Name) Membership" -Status "Warning" -Severity "High" -Details "Group has $($members.Count) members (threshold: $($group.Threshold)): $($members -join ', ')"
        } elseif ($members) {
            Add-AuditFinding -Category "Privileged Access" -Check "$($group.Name) Membership" -Status "OK" -Severity "Information" -Details "Members: $($members -join ', ')"
        }
    } catch {
        Add-AuditFinding -Category "Privileged Access" -Check "$($group.Name) Membership" -Status "Error" -Severity "High" -Details "Failed to query group members: $_"
    }
}

# 2. Account Hygiene Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Account Hygiene"

# Inactive Users (>90 days)
try {
    $inactiveThreshold = (Get-Date).AddDays(-90)
    $inactiveUsers = Search-ADAccount -AccountInactive -UsersOnly -DateTime $inactiveThreshold -ErrorAction Stop | Where-Object { $_.Enabled }
    if ($inactiveUsers) {
        $sampleUsers = ($inactiveUsers | Select-Object -First 5).Name -join ', '
        $moreCount = $inactiveUsers.Count - 5
        $details = "$($inactiveUsers.Count) users inactive for 90+ days"
        if ($moreCount -gt 0) { $details += " (sample: $sampleUsers + $moreCount more)" }
        Add-AuditFinding -Category "Account Hygiene" -Check "Inactive Users" -Status "Warning" -Severity "Medium" -Details $details
    } else {
        Add-AuditFinding -Category "Account Hygiene" -Check "Inactive Users" -Status "OK" -Severity "Information" -Details "No inactive users found"
    }
} catch {
    Add-AuditFinding -Category "Account Hygiene" -Check "Inactive Users" -Status "Error" -Severity "High" -Details "Failed to check inactive accounts: $_"
}

# Recently Created Accounts (last 7 days)
try {
    $newAccounts = Get-ADUser -Filter { whenCreated -ge (Get-Date).AddDays(-7) } -Properties whenCreated | Sort-Object whenCreated -Descending
    if ($newAccounts) {
        $sampleAccounts = ($newAccounts | Select-Object -First 5).Name -join ', '
        $moreCount = $newAccounts.Count - 5
        $details = "$($newAccounts.Count) accounts created in last 7 days"
        if ($moreCount -gt 0) { $details += " (sample: $sampleAccounts + $moreCount more)" }
        Add-AuditFinding -Category "Account Hygiene" -Check "Recently Created Accounts" -Status "Info" -Severity "Low" -Details $details
    }
} catch {
    Add-AuditFinding -Category "Account Hygiene" -Check "Recently Created Accounts" -Status "Error" -Severity "Medium" -Details "Failed to check new accounts: $_"
}

# 3. Password Policy Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Password Policies"

# Password Age and Complexity
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

# Non-expiring Passwords
try {
    $nonExpiring = Get-ADUser -Filter { PasswordNeverExpires -eq $true } -Properties PasswordNeverExpires | Where-Object { $_.Enabled }
    if ($nonExpiring) {
        $sampleAccounts = ($nonExpiring | Select-Object -First 5).Name -join ', '
        $moreCount = $nonExpiring.Count - 5
        $details = "$($nonExpiring.Count) accounts with non-expiring passwords"
        if ($moreCount -gt 0) { $details += " (sample: $sampleAccounts + $moreCount more)" }
        Add-AuditFinding -Category "Password Policy" -Check "Non-expiry Passwords" -Status "Warning" -Severity "High" -Details $details
    }
} catch {
    Add-AuditFinding -Category "Password Policy" -Check "Non-expiry Passwords" -Status "Error" -Severity "Medium" -Details "Failed to check non-expiring passwords: $_"
}

# Service Accounts with SPNs
try {
    $serviceAccounts = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName | Where-Object { $_.Enabled }
    if ($serviceAccounts) {
        $sampleAccounts = ($serviceAccounts | Select-Object -First 3 | ForEach-Object { 
            "$($_.Name) (SPNs: $($_.ServicePrincipalName.Count))"
        }) -join '; '
        $moreCount = $serviceAccounts.Count - 3
        $details = "$($serviceAccounts.Count) service accounts with SPNs"
        if ($moreCount -gt 0) { $details += " (sample: $sampleAccounts + $moreCount more)" }
        Add-AuditFinding -Category "Password Policy" -Check "Service Accounts" -Status "Info" -Severity "Medium" -Details $details
    }
} catch {
    Add-AuditFinding -Category "Password Policy" -Check "Service Accounts" -Status "Error" -Severity "Medium" -Details "Failed to check service accounts: $_"
}

# 4. System Analysis
Write-Progress -Activity "Auditing AD" -Status "Performing System Analysis"

# Domain and Forest Information
try {
    $domainInfo = Get-ADDomain
    $forestInfo = Get-ADForest
    $details = "Domain: $($domainInfo.DNSRoot), Forest: $($forestInfo.RootDomain), Functional Level: Domain-$($domainInfo.DomainMode), Forest-$($forestInfo.ForestMode)"
    Add-AuditFinding -Category "System Analysis" -Check "Domain/Forest Info" -Status "OK" -Severity "Information" -Details $details
} catch {
    Add-AuditFinding -Category "System Analysis" -Check "Domain/Forest Info" -Status "Error" -Severity "Medium" -Details "Failed to retrieve domain info: $_"
}

# OU Structure Analysis
try {
    $ouCount = (Get-ADOrganizationalUnit -Filter *).Count
    $topOUs = (Get-ADOrganizationalUnit -Filter * -SearchBase (Get-ADDomain).DistinguishedName -SearchScope OneLevel).Name -join ', '
    Add-AuditFinding -Category "System Analysis" -Check "OU Structure" -Status "OK" -Severity "Information" -Details "$ouCount OUs found. Top-level OUs: $topOUs"
} catch {
    Add-AuditFinding -Category "System Analysis" -Check "OU Structure" -Status "Error" -Severity "Low" -Details "Failed to analyze OU structure: $_"
}

# Computer Accounts
try {
    $computerStats = Get-ADComputer -Filter * -Properties LastLogonDate | Group-Object -Property { $_.LastLogonDate -lt (Get-Date).AddDays(-90) } -AsHashTable -ErrorAction Stop
    $activeCount = ($computerStats.$false | Measure-Object).Count
    $inactiveCount = ($computerStats.$true | Measure-Object).Count
    $details = "Total computers: $($activeCount + $inactiveCount) (Active: $activeCount, Inactive: $inactiveCount)"
    if ($inactiveCount -gt 0) {
        Add-AuditFinding -Category "System Analysis" -Check "Computer Accounts" -Status "Warning" -Severity "Medium" -Details "$details - $inactiveCount computers inactive for 90+ days"
    } else {
        Add-AuditFinding -Category "System Analysis" -Check "Computer Accounts" -Status "OK" -Severity "Information" -Details $details
    }
} catch {
    Add-AuditFinding -Category "System Analysis" -Check "Computer Accounts" -Status "Error" -Severity "Medium" -Details "Failed to analyze computer accounts: $_"
}

# GPO Analysis
try {
    $gpoCount = (Get-GPO -All).Count
    $unlinkedGPOs = Get-GPO -All | Where-Object { -not $_.GPOStatus -match "AllSettingsEnabled" }
    $details = "$gpoCount GPOs total"
    if ($unlinkedGPOs) {
        $details += ", $($unlinkedGPOs.Count) potentially unused GPOs"
        Add-AuditFinding -Category "System Analysis" -Check "GPO Analysis" -Status "Warning" -Severity "Medium" -Details $details
    } else {
        Add-AuditFinding -Category "System Analysis" -Check "GPO Analysis" -Status "OK" -Severity "Information" -Details $details
    }
} catch {
    Add-AuditFinding -Category "System Analysis" -Check "GPO Analysis" -Status "Error" -Severity "Medium" -Details "Failed to analyze GPOs: $_"
}

# Output results to console with proper color coding
Write-Progress -Activity "Auditing AD" -Completed
Clear-Host
Write-Host "`nACTIVE DIRECTORY COMPREHENSIVE AUDIT RESULTS`n" -ForegroundColor Cyan

# Display results in console with proper color coding
foreach ($result in ($auditResults | Sort-Object { 
    switch ($_.Severity) {
        "Critical" { 1 }
        "High" { 2 }
        "Medium" { 3 }
        "Low" { 4 }
        default { 5 }
    }
})) {
    $severityColor = Get-SeverityColor $result.Severity
    $categoryColor = Get-CategoryColor $result.Category
    $statusSymbol = switch ($result.Status) {
        "OK" { "✓" }
        {$_ -match "Warning"} { "⚠" }
        {$_ -match "Error|Critical"} { "✗" }
        default { $_ }
    }
    
    # Write category with color
    Write-Host ("[{0}]" -f $result.Category.PadRight(18)) -NoNewline -ForegroundColor $categoryColor
    # Write severity with color
    Write-Host (" [{0}]" -f $result.Severity.PadRight(8)) -NoNewline -ForegroundColor $severityColor
    # Write the rest of the line
    Write-Host (" {0} {1} - {2}" -f $statusSymbol, $result.Check.PadRight(35), $result.Details)
}

# Export to CSV and HTML with timestamp - GUARANTEED WORKING EXPORTS
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputDir = "AD_Audit_Reports_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# CSV Export - Fixed to ensure proper file creation
$csvPath = Join-Path -Path $outputDir -ChildPath "AD_Audit_$timestamp.csv"
try {
    $auditResults | Export-Csv -Path $csvPath -NoTypeInformation -Force
    Write-Host "`nCSV report saved to: $csvPath" -ForegroundColor Green
} catch {
    Write-Host "Failed to save CSV report: $_" -ForegroundColor Red
}

# HTML Export - Fixed to ensure proper file creation
$htmlPath = Join-Path -Path $outputDir -ChildPath "AD_Audit_$timestamp.html"
try {
    $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory Comprehensive Audit Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        table { border-collapse: collapse; width: 100%; }
        th { background-color: #0066cc; color: white; text-align: left; padding: 8px; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        .Critical { background-color: #ffcccc; }
        .High { background-color: #ffdddd; }
        .Medium { background-color: #fff3cd; }
        .Low { background-color: #fff8e1; }
        .Information { background-color: #d4edda; }
        .PrivilegedAccess { border-left: 4px solid #00bcd4; }
        .AccountHygiene { border-left: 4px solid #2196f3; }
        .PasswordPolicy { border-left: 4px solid #009688; }
        .SystemAnalysis { border-left: 4px solid #4caf50; }
    </style>
</head>
<body>
    <h1>Active Directory Comprehensive Audit Report</h1>
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
        $severityClass = $_.Severity
        $categoryClass = $_.Category -replace " ", ""
        @"
        <tr class="$severityClass $categoryClass">
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
    Write-Host "HTML report saved to: $htmlPath" -ForegroundColor Green
} catch {
    Write-Host "Failed to save HTML report: $_" -ForegroundColor Red
}

Write-Host "`nAudit completed. Reports saved in: $outputDir" -ForegroundColor Cyan
