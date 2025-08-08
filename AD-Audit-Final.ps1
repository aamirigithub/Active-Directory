<#
.SYNOPSIS
    Enterprise Active Directory Comprehensive Audit Script
.DESCRIPTION
    Performs complete security, compliance, and configuration assessment of Active Directory
    with detailed reporting and remediation recommendations
.NOTES
    Version: 6.0
    Requires: Active Directory module, Domain Admin privileges
.AUTHOR
    Aamir Mukhtar
.DATE
    08-07-2025
#>

# Import required modules
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
if (-not (Get-Module ActiveDirectory)) {
    Write-Host "ActiveDirectory module not found. Install RSAT-AD-PowerShell first." -ForegroundColor Red
    exit
}

# Initialize results array and compliance framework
$auditResults = @()
$complianceFrameworks = @("SOX", "HIPAA", "PCI-DSS", "NIST", "ISO27001")

# Function to add findings to results
function Add-AuditFinding {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,
        [string]$Severity,
        [string]$Details,
        [string]$Compliance = "",
        [string]$Recommendation = "",
        [string]$CVSS = "",
        [string]$RiskRating = ""
    )
    $finding = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        Check = $Check
        Status = $Status
        Severity = $Severity
        Details = $Details
        Compliance = $Compliance
        Recommendation = $Recommendation
        CVSS = $CVSS
        RiskRating = $RiskRating
    }
    $auditResults += $finding
    return $finding
}

# Function to calculate risk rating
function Get-RiskRating {
    param($Likelihood, $Impact)
    $riskMatrix = @{
        "Low-Low" = "Low"
        "Low-Medium" = "Low"
        "Low-High" = "Medium"
        "Medium-Low" = "Low"
        "Medium-Medium" = "Medium"
        "Medium-High" = "High"
        "High-Low" = "Medium"
        "High-Medium" = "High"
        "High-High" = "Critical"
    }
    return $riskMatrix["$Likelihood-$Impact"]
}

# 1. AD Infrastructure Analysis
Write-Progress -Activity "Auditing AD" -Status "Analyzing Infrastructure"
try {
    $domainInfo = Get-ADDomain
    $forestInfo = Get-ADForest
    $ouCount = (Get-ADOrganizationalUnit -Filter *).Count
    
    $details = "Forest: $($forestInfo.Name) | Domains: $($forestInfo.Domains -join ', ') | Functional Level: Forest-$($forestInfo.ForestMode), Domain-$($domainInfo.DomainMode) | OUs: $ouCount"
    Add-AuditFinding -Category "Infrastructure" -Check "AD Topology" -Status "OK" -Severity "Information" -Details $details
    
    # Analyze OU structure and protection
    $unprotectedOUs = Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion | 
                      Where-Object { $_.ProtectedFromAccidentalDeletion -eq $false }
    if ($unprotectedOUs) {
        Add-AuditFinding -Category "Infrastructure" -Check "OU Protection" -Status "Warning" -Severity "Medium" -Details "$($unprotectedOUs.Count) OUs not protected from accidental deletion" -Compliance "SOX,PCI-DSS" -Recommendation "Enable 'Protect from accidental deletion' on all OUs" -CVSS "5.3" -RiskRating (Get-RiskRating "Medium" "Medium")
    }
} catch {
    Add-AuditFinding -Category "Infrastructure" -Check "AD Topology" -Status "Error" -Severity "High" -Details "Failed to analyze AD infrastructure: $_"
}

# Domain Information
Write-Host "`n[1/12] Collecting Domain Information..." -ForegroundColor Cyan
try {
    $Domain = Get-ADDomain
    $Forest = Get-ADForest
    $DomainControllers = Get-ADDomainController -Filter *
    
    $DomainInfo = [PSCustomObject]@{
        DomainName = $Domain.DNSRoot
        NetBIOSName = $Domain.NetBIOSName
        DomainMode = $Domain.DomainMode
        ForestMode = $Forest.ForestMode
        DomainControllers = $DomainControllers.Name -join ', '
        CreationDate = $Domain.Created
    }
    
    $AuditResults['DomainInfo'] = $DomainInfo
    Write-Host "Domain information collected" -ForegroundColor Green
} catch {
    Write-Host "Failed to collect domain information: $($_.Exception.Message)" -ForegroundColor Red
}

# FSMO Roles Check
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

# DNS Health Check
Write-Progress -Activity "Auditing AD" -Status "Checking DNS"
try {
    $dnsTest = dcdiag /test:dns /v
    if ($dnsTest -match "failed") {
        Add-AuditFinding -Category "DNS" -Check "DNS Health" -Status "Error" -Severity "High" -Details "DNS test failed"
    }
} catch {
    Add-AuditFinding -Category "DNS" -Check "DNS Check" -Status "Error" -Severity "High" -Details "Failed to check DNS"
}


# 2. User Account Analysis
Write-Progress -Activity "Auditing AD" -Status "Analyzing User Accounts"
try {
    # Account status breakdown
    $users = Get-ADUser -Filter * -Properties Enabled, LockedOut, PasswordNeverExpires, PasswordLastSet
    $enabledUsers = $users | Where-Object { $_.Enabled -eq $true }
    $disabledUsers = $users | Where-Object { $_.Enabled -eq $false }
    $lockedUsers = $users | Where-Object { $_.LockedOut -eq $true }
    
    Add-AuditFinding -Category "User Accounts" -Check "Account Status" -Status "OK" -Severity "Information" -Details "Total: $($users.Count) | Enabled: $($enabledUsers.Count) | Disabled: $($disabledUsers.Count) | Locked: $($lockedUsers.Count)"
    
    # Password never expires
    $neverExpire = $enabledUsers | Where-Object { $_.PasswordNeverExpires -eq $true }
    if ($neverExpire) {
        $details = "$($neverExpire.Count) active accounts with non-expiring passwords"
        Add-AuditFinding -Category "User Accounts" -Check "Password Expiration" -Status "Warning" -Severity "High" -Details $details -Compliance "SOX,HIPAA,PCI-DSS" -Recommendation "Review and set password expiration for these accounts" -CVSS "7.5" -RiskRating (Get-RiskRating "High" "High")
    }
    
    # Old passwords
    $oldPasswords = $enabledUsers | Where-Object { $_.PasswordLastSet -lt (Get-Date).AddDays(-365) }
    if ($oldPasswords) {
        $details = "$($oldPasswords.Count) accounts with passwords older than 1 year"
        Add-AuditFinding -Category "User Accounts" -Check "Password Age" -Status "Warning" -Severity "Medium" -Details $details -Compliance "PCI-DSS" -Recommendation "Enforce password rotation policy" -CVSS "5.5" -RiskRating (Get-RiskRating "Medium" "Medium")
    }

    # Kerberos Audit
    Write-Progress -Activity "Auditing AD" -Status "Checking Kerberos"
    $kerberosPolicy = Get-ADAccountAuthorizationPolicy
    if ($kerberosPolicy.MaxTicketAge -gt 10) {
        Add-AuditFinding -Category "Authentication" -Check "Kerberos Ticket Age" -Status "Warning" -Severity "Medium" -Details "Max ticket age is $($kerberosPolicy.MaxTicketAge) hours (should be ≤ 10)"
    }

} catch {
    Add-AuditFinding -Category "User Accounts" -Check "Account Analysis" -Status "Error" -Severity "High" -Details "Failed to analyze user accounts: $_"
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

# Inactive Account Audit
Write-Progress -Activity "Auditing AD" -Status "Checking Inactive Accounts"
$inactiveThreshold = (Get-Date).AddDays(-90)
$inactiveUsers = Search-ADAccount -AccountInactive -UsersOnly -DateTime $inactiveThreshold | Where-Object { $_.Enabled }
if ($inactiveUsers) {
    Add-AuditFinding -Category "Account Hygiene" -Check "Inactive Users" -Status "Warning" -Severity "Medium" -Details "$($inactiveUsers.Count) users inactive for 90+ days"
}

# Privileged Access Audit
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

# 3. Privileged Access Review
Write-Progress -Activity "Auditing AD" -Status "Reviewing Privileged Access"
$privilegedGroups = @(
    @{Name="Domain Admins"; Threshold=5; Compliance="SOX,HIPAA,PCI-DSS"},
    @{Name="Enterprise Admins"; Threshold=3; Compliance="SOX,HIPAA,PCI-DSS"},
    @{Name="Schema Admins"; Threshold=2; Compliance="SOX,HIPAA,PCI-DSS"},
    @{Name="Administrators"; Threshold=5; Compliance="SOX,HIPAA,PCI-DSS"},
    @{Name="Account Operators"; Threshold=0; Compliance="SOX"},
    @{Name="Server Operators"; Threshold=0; Compliance="SOX"}
)

foreach ($group in $privilegedGroups) {
    try {
        $members = Get-ADGroupMember $group.Name -ErrorAction Stop | Select-Object -ExpandProperty Name
        $memberCount = $members.Count
        
        if ($memberCount -gt $group.Threshold) {
            $details = "$memberCount members in $($group.Name) (Threshold: $($group.Threshold))"
            Add-AuditFinding -Category "Privileged Access" -Check "$($group.Name) Membership" -Status "Warning" -Severity "High" -Details $details -Compliance $group.Compliance -Recommendation "Reduce membership to threshold level" -CVSS "9.0" -RiskRating (Get-RiskRating "High" "High")
        }
        
        # Check for service accounts in privileged groups
        $serviceAccounts = Get-ADGroupMember $group.Name | Get-ADUser -Properties ServicePrincipalName | Where-Object { $_.ServicePrincipalName }
        if ($serviceAccounts) {
            $details = "$($serviceAccounts.Count) service accounts in $($group.Name)"
            Add-AuditFinding -Category "Privileged Access" -Check "Service Accounts in $($group.Name)" -Status "Critical" -Severity "High" -Details $details -Compliance $group.Compliance -Recommendation "Remove service accounts from privileged groups" -CVSS "9.5" -RiskRating (Get-RiskRating "High" "High")
        }
    } catch {
        Add-AuditFinding -Category "Privileged Access" -Check "$($group.Name) Membership" -Status "Error" -Severity "High" -Details "Failed to query group members: $_"
    }
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

# Group Policy Objects
Write-Host "`n[11/12] Analyzing Group Policy Objects..." -ForegroundColor Cyan
try {
    Import-Module GroupPolicy -ErrorAction Stop
    $GPOs = Get-GPO -All
    
    $GPOReport = $GPOs | Select-Object DisplayName, Id, CreationTime, ModificationTime,
        @{Name="DaysSinceModified"; Expression={(Get-Date) - $_.ModificationTime | Select-Object -ExpandProperty Days}}
    
    $GPOStats = [PSCustomObject]@{
        TotalGPOs = $GPOs.Count
        RecentlyModified = ($GPOs | Where-Object {$_.ModificationTime -gt (Get-Date).AddDays(-30)}).Count
        UnlinkedGPOs = 0  # This would require additional analysis
    }
    
    $AuditResults['GPOStats'] = $GPOStats
    $AuditResults['GPODetails'] = $GPOReport
    Write-Host "Analyzed $($GPOs.Count) Group Policy Objects" -ForegroundColor Green
} catch {
    Write-Host "! Group Policy module not available - skipping GPO analysis" -ForegroundColor Yellow
}


# 4. Group and Permission Analysis
Write-Progress -Activity "Auditing AD" -Status "Analyzing Groups and Permissions"
try {
    # Nested group analysis
    $nestedGroups = Get-ADGroup -Filter * -Properties Members | Where-Object { 
        $_.Members | Where-Object { $_.ObjectClass -eq "group" }
    }
    if ($nestedGroups) {
        $details = "$($nestedGroups.Count) groups with nested group memberships"
        Add-AuditFinding -Category "Group Analysis" -Check "Nested Groups" -Status "Warning" -Severity "Medium" -Details $details -Compliance "SOX" -Recommendation "Review nested group memberships for excessive privileges" -CVSS "6.5" -RiskRating (Get-RiskRating "Medium" "Medium")
    }
    
    # Orphaned groups (no members)
    $orphanedGroups = Get-ADGroup -Filter * -Properties Members | Where-Object { $_.Members.Count -eq 0 }
    if ($orphanedGroups) {
        $details = "$($orphanedGroups.Count) groups with no members"
        Add-AuditFinding -Category "Group Analysis" -Check "Orphaned Groups" -Status "Warning" -Severity "Low" -Details $details -Recommendation "Consider removing unused groups" -CVSS "3.5" -RiskRating (Get-RiskRating "Low" "Low")
    }
    
    # Permission inheritance analysis
    $brokenInheritance = Get-ADObject -Filter { nTSecurityDescriptor.AreAccessRulesProtected -eq $true } -SearchBase (Get-ADDomain).DistinguishedName
    if ($brokenInheritance) {
        $details = "$($brokenInheritance.Count) objects with broken inheritance"
        Add-AuditFinding -Category "Permission Analysis" -Check "Inheritance Issues" -Status "Warning" -Severity "Medium" -Details $details -Compliance "SOX" -Recommendation "Review manually assigned permissions" -CVSS "5.5" -RiskRating (Get-RiskRating "Medium" "Medium")
    }
} catch {
    Add-AuditFinding -Category "Group Analysis" -Check "Group Analysis" -Status "Error" -Severity "High" -Details "Failed to analyze groups: $_"
}

# 5. Security Configuration Assessment
Write-Progress -Activity "Auditing AD" -Status "Assessing Security Configuration"
try {
    # GPO security analysis
    $gpos = Get-GPO -All
    $unlinkedGPOs = $gpos | Where-Object { -not $_.GPOStatus -match "AllSettingsEnabled" }
    if ($unlinkedGPOs) {
        $details = "$($unlinkedGPOs.Count) unlinked GPOs found"
        Add-AuditFinding -Category "Security Configuration" -Check "Unlinked GPOs" -Status "Warning" -Severity "Medium" -Details $details -Recommendation "Review and remove unused GPOs" -CVSS "4.0" -RiskRating (Get-RiskRating "Medium" "Low")
    }
    
    # Domain controller security
    $dcs = Get-ADDomainController -Filter *
    foreach ($dc in $dcs) {
        $smb1Enabled = Test-NetConnection -ComputerName $dc.HostName -CommonTCPPort SMB
        if ($smb1Enabled.TcpTestSucceeded) {
            Add-AuditFinding -Category "Security Configuration" -Check "SMBv1 Enabled" -Status "Critical" -Severity "High" -Details "SMBv1 enabled on $($dc.HostName)" -Compliance "PCI-DSS" -Recommendation "Disable SMBv1 immediately" -CVSS "10.0" -RiskRating (Get-RiskRating "High" "High")
        }
    }
    
    # Trust relationships
    $trusts = Get-ADTrust -Filter *
    foreach ($trust in $trusts) {
        if ($trust.TrustType -eq "External") {
            Add-AuditFinding -Category "Security Configuration" -Check "External Trust" -Status "Warning" -Severity "High" -Details "External trust to $($trust.Target)" -Compliance "SOX" -Recommendation "Review trust necessity and security" -CVSS "8.0" -RiskRating (Get-RiskRating "High" "High")
        }
    }
    
    # Authentication protocols
    $authPolicy = Get-ADOptionalFeature -Identity "Recycle Bin Feature"
    if (-not $authPolicy.Enabled) {
        Add-AuditFinding -Category "Security Configuration" -Check "AD Recycle Bin" -Status "Warning" -Severity "Medium" -Details "AD Recycle Bin not enabled" -Recommendation "Enable AD Recycle Bin feature" -CVSS "5.5" -RiskRating (Get-RiskRating "Medium" "Medium")
    }
} catch {
    Add-AuditFinding -Category "Security Configuration" -Check "Security Configuration" -Status "Error" -Severity "High" -Details "Failed to assess security configuration: $_"
}

# Security Event Analysis (if available)
Write-Host "`n[12/12] Basic Security Summary..." -ForegroundColor Cyan
$SecuritySummary = [PSCustomObject]@{
    AuditDate = Get-Date
    DomainName = $Domain.DNSRoot
    TotalUsers = (Get-ADUser -Filter *).Count
    EnabledUsers = (Get-ADUser -Filter {Enabled -eq $true}).Count
    TotalGroups = (Get-ADGroup -Filter *).Count
    PrivilegedUsers = $PrivilegedGroupsAudit.Count
    InactiveUsers = $InactiveUsers.Count
    NonExpiringPasswords = $NonExpiringPasswords.Count
    ServiceAccounts = $ServiceAccounts.Count
    RecentlyCreatedUsers = $RecentlyCreated.Count
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

# 6. Compliance and Risk Assessment
Write-Progress -Activity "Auditing AD" -Status "Performing Compliance Assessment"
try {
    # Password policy compliance
    $domainPolicy = Get-ADDefaultDomainPasswordPolicy
    $passwordChecks = @(
        @{Name="Minimum Length"; Value=$domainPolicy.MinPasswordLength; Required=8; Compliance="PCI-DSS"},
        @{Name="Complexity"; Value=$domainPolicy.ComplexityEnabled; Required=$true; Compliance="PCI-DSS"},
        @{Name="Password History"; Value=$domainPolicy.PasswordHistoryCount; Required=24; Compliance="SOX"}
    )
    
    foreach ($check in $passwordChecks) {
        if ($check.Value -lt $check.Required) {
            $details = "$($check.Name) is $($check.Value) (should be $($check.Required))"
            Add-AuditFinding -Category "Compliance" -Check "Password Policy" -Status "Warning" -Severity "High" -Details $details -Compliance $check.Compliance -Recommendation "Adjust password policy to meet requirements" -CVSS "7.5" -RiskRating (Get-RiskRating "High" "High")
        }
    }
    
    # Account lockout policy
    $lockoutPolicy = Get-ADDefaultDomainPasswordPolicy
    if ($lockoutPolicy.LockoutThreshold -eq 0) {
        Add-AuditFinding -Category "Compliance" -Check "Account Lockout" -Status "Critical" -Severity "High" -Details "No account lockout policy configured" -Compliance "PCI-DSS" -Recommendation "Configure account lockout threshold" -CVSS "9.0" -RiskRating (Get-RiskRating "High" "High")
    }
} catch {
    Add-AuditFinding -Category "Compliance" -Check "Compliance Assessment" -Status "Error" -Severity "High" -Details "Failed to perform compliance assessment: $_"
}


# Generate comprehensive reports
Write-Progress -Activity "Auditing AD" -Status "Generating Reports"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputDir = "AD_Comprehensive_Audit_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# 1. Export to CSV
$csvPath = Join-Path -Path $outputDir -ChildPath "AD_Audit_Detailed_$timestamp.csv"
$auditResults | Export-Csv -Path $csvPath -NoTypeInformation -Force

# 2. Generate HTML Report
$htmlPath = Join-Path -Path $outputDir -ChildPath "AD_Audit_Report_$timestamp.html"
$htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory Comprehensive Audit Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        h2 { color: #009688; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th { background-color: #0066cc; color: white; text-align: left; padding: 8px; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        .Critical { background-color: #ffcccc; }
        .High { background-color: #ffdddd; }
        .Medium { background-color: #fff3cd; }
        .Low { background-color: #fff8e1; }
        .Information { background-color: #d4edda; }
        .risk-matrix { margin: 20px 0; }
        .risk-matrix th { background-color: #333; }
        .recommendations { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>Active Directory Comprehensive Audit Report</h1>
    <p>Generated on: $(Get-Date)</p>
    <p>Audit Scope: AD domains, forests, OUs, user accounts, groups, permissions, security configuration</p>
    
    <h2>Executive Summary</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
            <th>Info</th>
        </tr>
"@

# Generate summary table
$summary = $auditResults | Group-Object Category | ForEach-Object {
    $cat = $_.Name
    $counts = $_.Group | Group-Object Severity -AsHashTable
    @"
        <tr>
            <td>$cat</td>
            <td>$($counts['Critical'].Count)</td>
            <td>$($counts['High'].Count)</td>
            <td>$($counts['Medium'].Count)</td>
            <td>$($counts['Low'].Count)</td>
            <td>$($counts['Information'].Count)</td>
        </tr>
"@
}

$htmlRiskMatrix = @"
    </table>
    
    <h2>Risk Assessment Matrix</h2>
    <table class="risk-matrix">
        <tr>
            <th>Risk Level</th>
            <th>Count</th>
            <th>Description</th>
        </tr>
        <tr class="Critical">
            <td>Critical</td>
            <td>$($auditResults | Where-Object { $_.RiskRating -eq 'Critical' } | Measure-Object).Count</td>
            <td>Immediate action required. Severe impact to security and compliance.</td>
        </tr>
        <tr class="High">
            <td>High</td>
            <td>$($auditResults | Where-Object { $_.RiskRating -eq 'High' } | Measure-Object).Count</td>
            <td>Urgent attention needed. Significant security or compliance impact.</td>
        </tr>
        <tr class="Medium">
            <td>Medium</td>
            <td>$($auditResults | Where-Object { $_.RiskRating -eq 'Medium' } | Measure-Object).Count</td>
            <td>Should be addressed. Moderate security or compliance impact.</td>
        </tr>
        <tr class="Low">
            <td>Low</td>
            <td>$($auditResults | Where-Object { $_.RiskRating -eq 'Low' } | Measure-Object).Count</td>
            <td>Consider addressing. Minor security or compliance impact.</td>
        </tr>
    </table>
    
    <h2>Detailed Findings</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Check</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Compliance</th>
            <th>Risk</th>
            <th>Details</th>
        </tr>
"@

$htmlRows = $auditResults | Sort-Object { 
    switch ($_.Severity) {
        "Critical" { 1 }
        "High" { 2 }
        "Medium" { 3 }
        "Low" { 4 }
        default { 5 }
    }
} | ForEach-Object {
    $severityClass = $_.Severity
    @"
        <tr class="$severityClass">
            <td>$($_.Category)</td>
            <td>$($_.Check)</td>
            <td>$($_.Status)</td>
            <td>$($_.Severity)</td>
            <td>$($_.Compliance)</td>
            <td>$($_.RiskRating)</td>
            <td>$($_.Details)</td>
        </tr>
"@
}

$htmlRecommendations = @"
    </table>
    
    <div class="recommendations">
        <h2>Prioritized Remediation Plan</h2>
        <h3>Critical Items (0-7 days)</h3>
        <ul>
            <li>Remove service accounts from privileged groups</li>
            <li>Disable SMBv1 on all domain controllers</li>
            <li>Configure account lockout policy</li>
        </ul>
        
        <h3>High Priority (7-14 days)</h3>
        <ul>
            <li>Reduce membership in privileged groups to threshold levels</li>
            <li>Review external trust relationships</li>
            <li>Set password expiration for accounts with non-expiring passwords</li>
        </ul>
        
        <h3>Medium Priority (14-30 days)</h3>
        <ul>
            <li>Review nested group memberships</li>
            <li>Enable 'Protect from accidental deletion' on OUs</li>
            <li>Enable AD Recycle Bin feature</li>
        </ul>
        
        <h3>Long-term Improvements</h3>
        <ul>
            <li>Implement regular AD audit schedule (quarterly)</li>
            <li>Establish privileged access management program</li>
            <li>Deploy AD monitoring solution</li>
        </ul>
    </div>
</body>
</html>
"@

$htmlContent = $htmlHeader + $summary + $htmlRiskMatrix + $htmlRows + $htmlRecommendations
$htmlContent | Out-File -FilePath $htmlPath -Force

# 3. Generate Remediation Plan
$remediationPath = Join-Path -Path $outputDir -ChildPath "AD_Remediation_Plan_$timestamp.txt"
$criticalItems = $auditResults | Where-Object { $_.Severity -eq "Critical" }
$highItems = $auditResults | Where-Object { $_.Severity -eq "High" }
$mediumItems = $auditResults | Where-Object { $_.Severity -eq "Medium" }

$remediationContent = @"
ACTIVE DIRECTORY REMEDIATION PLAN
Generated: $(Get-Date)

=== CRITICAL ITEMS (Address within 7 days) ===
$(($criticalItems | ForEach-Object { 
    "• [$($_.Category)] $($_.Check): $($_.Details)`n  Recommendation: $($_.Recommendation)`n"
}) -join "`n")

=== HIGH PRIORITY (Address within 14 days) ===
$(($highItems | ForEach-Object { 
    "• [$($_.Category)] $($_.Check): $($_.Details)`n  Recommendation: $($_.Recommendation)`n"
}) -join "`n")

=== MEDIUM PRIORITY (Address within 30 days) ===
$(($mediumItems | ForEach-Object { 
    "• [$($_.Category)] $($_.Check): $($_.Details)`n  Recommendation: $($_.Recommendation)`n"
}) -join "`n")

=== RESOURCE REQUIREMENTS ===
• Security Team: 2-3 members for critical items
• System Admins: Ongoing support for implementation
• Monitoring Tools: SIEM integration recommended

=== MAINTENANCE RECOMMENDATIONS ===
1. Implement quarterly AD audits
2. Establish change control process for privileged access
3. Deploy continuous monitoring for AD changes
4. Conduct annual AD security training
"@

$remediationContent | Out-File -FilePath $remediationPath -Force

# Display completion message
Write-Host "`nCOMPREHENSIVE AD AUDIT COMPLETED" -ForegroundColor Green
Write-Host "Reports saved to: $outputDir" -ForegroundColor Cyan
Write-Host "• Detailed CSV: AD_Audit_Detailed_$timestamp.csv" -ForegroundColor Yellow
Write-Host "• HTML Report: AD_Audit_Report_$timestamp.html" -ForegroundColor Yellow
Write-Host "• Remediation Plan: AD_Remediation_Plan_$timestamp.txt" -ForegroundColor Yellow
