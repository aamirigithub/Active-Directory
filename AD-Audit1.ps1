#CAI
# Active Directory Security Audit Script
# Requires: Active Directory PowerShell Module and appropriate permissions

#Requires -Modules ActiveDirectory

param(
    [string]$OutputPath = "C:\ADAudit",
    [switch]$ExportToCSV,
    [switch]$Detailed
)

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$AuditResults = @{}
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host "Starting Active Directory Security Audit..." -ForegroundColor Green
Write-Host "Output Directory: $OutputPath" -ForegroundColor Yellow

# 1. Domain Information
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
    Write-Host "✓ Domain information collected" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to collect domain information: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Privileged Groups Audit
Write-Host "`n[2/12] Auditing Privileged Groups..." -ForegroundColor Cyan
$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins", 
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators"
)

$PrivilegedGroupsAudit = @()
foreach ($GroupName in $PrivilegedGroups) {
    try {
        $Group = Get-ADGroup -Identity $GroupName -Properties Members, ManagedBy, Description -ErrorAction SilentlyContinue
        if ($Group) {
            $Members = Get-ADGroupMember -Identity $GroupName -Recursive | Get-ADUser -Properties LastLogonDate, PasswordLastSet, Enabled
            
            foreach ($Member in $Members) {
                $PrivilegedGroupsAudit += [PSCustomObject]@{
                    GroupName = $GroupName
                    MemberName = $Member.Name
                    MemberSAM = $Member.SamAccountName
                    MemberType = $Member.ObjectClass
                    Enabled = $Member.Enabled
                    LastLogon = $Member.LastLogonDate
                    PasswordLastSet = $Member.PasswordLastSet
                    DaysSinceLastLogon = if($Member.LastLogonDate) { (Get-Date) - $Member.LastLogonDate | Select-Object -ExpandProperty Days } else { "Never" }
                }
            }
        }
    } catch {
        Write-Warning "Could not audit group: $GroupName"
    }
}

$AuditResults['PrivilegedGroups'] = $PrivilegedGroupsAudit
Write-Host "✓ Privileged groups audited ($($PrivilegedGroupsAudit.Count) members found)" -ForegroundColor Green

# 3. Inactive User Accounts
Write-Host "`n[3/12] Finding Inactive User Accounts..." -ForegroundColor Cyan
$InactiveThreshold = (Get-Date).AddDays(-90)
$InactiveUsers = Get-ADUser -Filter {LastLogonDate -lt $InactiveThreshold -and Enabled -eq $true} -Properties LastLogonDate, PasswordLastSet, Description, Department

$InactiveUsersReport = $InactiveUsers | Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet, Description, Department,
    @{Name="DaysSinceLastLogon"; Expression={(Get-Date) - $_.LastLogonDate | Select-Object -ExpandProperty Days}}

$AuditResults['InactiveUsers'] = $InactiveUsersReport
Write-Host "✓ Found $($InactiveUsers.Count) inactive user accounts (>90 days)" -ForegroundColor Green

# 4. Password Policy Compliance
Write-Host "`n[4/12] Checking Password Policies..." -ForegroundColor Cyan
$DefaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy
$FineGrainedPolicies = Get-ADFineGrainedPasswordPolicy -Filter *

$PasswordPolicyAudit = [PSCustomObject]@{
    DefaultPolicy = $DefaultPasswordPolicy
    FineGrainedPolicies = $FineGrainedPolicies.Count
    MinPasswordLength = $DefaultPasswordPolicy.MinPasswordLength
    PasswordHistoryCount = $DefaultPasswordPolicy.PasswordHistoryCount
    MaxPasswordAge = $DefaultPasswordPolicy.MaxPasswordAge.Days
    LockoutThreshold = $DefaultPasswordPolicy.LockoutThreshold
    ComplexityEnabled = $DefaultPasswordPolicy.ComplexityEnabled
}

$AuditResults['PasswordPolicy'] = $PasswordPolicyAudit
Write-Host "✓ Password policies analyzed" -ForegroundColor Green

# 5. Users with Non-Expiring Passwords
Write-Host "`n[5/12] Finding Users with Non-Expiring Passwords..." -ForegroundColor Cyan
$NonExpiringPasswords = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordLastSet, LastLogonDate, Description

$NonExpiringReport = $NonExpiringPasswords | Select-Object Name, SamAccountName, PasswordLastSet, LastLogonDate, Description,
    @{Name="PasswordAge"; Expression={if($_.PasswordLastSet){(Get-Date) - $_.PasswordLastSet | Select-Object -ExpandProperty Days}else{"Unknown"}}}

$AuditResults['NonExpiringPasswords'] = $NonExpiringReport
Write-Host "✓ Found $($NonExpiringPasswords.Count) users with non-expiring passwords" -ForegroundColor Green

# 6. Recently Created Accounts
Write-Host "`n[6/12] Finding Recently Created Accounts..." -ForegroundColor Cyan
$RecentThreshold = (Get-Date).AddDays(-30)
$RecentlyCreated = Get-ADUser -Filter {Created -gt $RecentThreshold} -Properties Created, LastLogonDate, CreatedBy, Description

$RecentlyCreatedReport = $RecentlyCreated | Select-Object Name, SamAccountName, Created, LastLogonDate, Description,
    @{Name="DaysOld"; Expression={(Get-Date) - $_.Created | Select-Object -ExpandProperty Days}}

$AuditResults['RecentlyCreated'] = $RecentlyCreatedReport
Write-Host "✓ Found $($RecentlyCreated.Count) recently created accounts (<30 days)" -ForegroundColor Green

# 7. Disabled Accounts in Privileged Groups
Write-Host "`n[7/12] Finding Disabled Accounts in Privileged Groups..." -ForegroundColor Cyan
$DisabledPrivileged = $PrivilegedGroupsAudit | Where-Object {$_.Enabled -eq $false}
$AuditResults['DisabledPrivileged'] = $DisabledPrivileged
Write-Host "✓ Found $($DisabledPrivileged.Count) disabled accounts in privileged groups" -ForegroundColor Green

# 8. Service Accounts Analysis
Write-Host "`n[8/12] Analyzing Service Accounts..." -ForegroundColor Cyan
$ServiceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, LastLogonDate, TrustedForDelegation

$ServiceAccountsReport = $ServiceAccounts | Select-Object Name, SamAccountName, 
    @{Name="SPNs"; Expression={$_.ServicePrincipalName -join "; "}},
    PasswordLastSet, LastLogonDate, TrustedForDelegation,
    @{Name="PasswordAge"; Expression={if($_.PasswordLastSet){(Get-Date) - $_.PasswordLastSet | Select-Object -ExpandProperty Days}else{"Unknown"}}}

$AuditResults['ServiceAccounts'] = $ServiceAccountsReport
Write-Host "✓ Found $($ServiceAccounts.Count) service accounts" -ForegroundColor Green

# 9. Organizational Units Structure
Write-Host "`n[9/12] Analyzing OU Structure..." -ForegroundColor Cyan
$OUs = Get-ADOrganizationalUnit -Filter * -Properties Description, ManagedBy, gPLink

$OUReport = $OUs | Select-Object Name, DistinguishedName, Description,
    @{Name="LinkedGPOs"; Expression={if($_.gPLink){($_.gPLink -split '\[')[1..999] | Where-Object{$_} | Measure-Object | Select-Object -ExpandProperty Count}else{0}}}

$AuditResults['OrganizationalUnits'] = $OUReport
Write-Host "✓ Analyzed $($OUs.Count) Organizational Units" -ForegroundColor Green

# 10. Computer Accounts Analysis
Write-Host "`n[10/12] Analyzing Computer Accounts..." -ForegroundColor Cyan
$InactiveComputerThreshold = (Get-Date).AddDays(-60)
$Computers = Get-ADComputer -Filter * -Properties LastLogonDate, OperatingSystem, OperatingSystemVersion, Enabled, Created

$ComputerStats = [PSCustomObject]@{
    TotalComputers = $Computers.Count
    EnabledComputers = ($Computers | Where-Object {$_.Enabled -eq $true}).Count
    DisabledComputers = ($Computers | Where-Object {$_.Enabled -eq $false}).Count
    InactiveComputers = ($Computers | Where-Object {$_.LastLogonDate -lt $InactiveComputerThreshold -and $_.Enabled -eq $true}).Count
    WindowsServers = ($Computers | Where-Object {$_.OperatingSystem -like "*Server*"}).Count
    WindowsWorkstations = ($Computers | Where-Object {$_.OperatingSystem -like "*Windows*" -and $_.OperatingSystem -notlike "*Server*"}).Count
}

$AuditResults['ComputerStats'] = $ComputerStats
Write-Host "✓ Analyzed $($Computers.Count) computer accounts" -ForegroundColor Green

# 11. Group Policy Objects
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
    Write-Host "✓ Analyzed $($GPOs.Count) Group Policy Objects" -ForegroundColor Green
} catch {
    Write-Host "! Group Policy module not available - skipping GPO analysis" -ForegroundColor Yellow
}

# 12. Security Event Analysis (if available)
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

$AuditResults['SecuritySummary'] = $SecuritySummary
Write-Host "✓ Security summary completed" -ForegroundColor Green

# Generate Reports
Write-Host "`nGenerating Reports..." -ForegroundColor Green

# Create main report
$MainReport = @"
ACTIVE DIRECTORY SECURITY AUDIT REPORT
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Domain: $($Domain.DNSRoot)

EXECUTIVE SUMMARY
=================
Total Users: $($SecuritySummary.TotalUsers)
Enabled Users: $($SecuritySummary.EnabledUsers)
Privileged Users: $($SecuritySummary.PrivilegedUsers)
Inactive Users (>90 days): $($SecuritySummary.InactiveUsers)
Non-Expiring Passwords: $($SecuritySummary.NonExpiringPasswords)
Service Accounts: $($SecuritySummary.ServiceAccounts)
Recently Created Users: $($SecuritySummary.RecentlyCreatedUsers)

SECURITY CONCERNS
================
"@

if ($InactiveUsers.Count -gt 0) {
    $MainReport += "`n• $($InactiveUsers.Count) inactive user accounts should be reviewed"
}
if ($NonExpiringPasswords.Count -gt 0) {
    $MainReport += "`n• $($NonExpiringPasswords.Count) accounts have non-expiring passwords"
}
if ($DisabledPrivileged.Count -gt 0) {
    $MainReport += "`n• $($DisabledPrivileged.Count) disabled accounts remain in privileged groups"
}

$MainReport | Out-File "$OutputPath\AD_Audit_Summary_$Timestamp.txt" -Encoding UTF8

# Export to CSV if requested
if ($ExportToCSV) {
    Write-Host "Exporting detailed data to CSV files..." -ForegroundColor Yellow
    
    $PrivilegedGroupsAudit | Export-Csv "$OutputPath\PrivilegedGroups_$Timestamp.csv" -NoTypeInformation
    $InactiveUsersReport | Export-Csv "$OutputPath\InactiveUsers_$Timestamp.csv" -NoTypeInformation
    $NonExpiringReport | Export-Csv "$OutputPath\NonExpiringPasswords_$Timestamp.csv" -NoTypeInformation
    $RecentlyCreatedReport | Export-Csv "$OutputPath\RecentlyCreated_$Timestamp.csv" -NoTypeInformation
    $ServiceAccountsReport | Export-Csv "$OutputPath\ServiceAccounts_$Timestamp.csv" -NoTypeInformation
    $OUReport | Export-Csv "$OutputPath\OrganizationalUnits_$Timestamp.csv" -NoTypeInformation
    
    if ($AuditResults.ContainsKey('GPODetails')) {
        $GPOReport | Export-Csv "$OutputPath\GroupPolicies_$Timestamp.csv" -NoTypeInformation
    }
}

Write-Host "`n" -NoNewline
Write-Host "AUDIT COMPLETE!" -ForegroundColor Green -BackgroundColor Black
Write-Host "Reports saved to: $OutputPath" -ForegroundColor Yellow
Write-Host "`nKey Files Generated:" -ForegroundColor Cyan
Write-Host "• AD_Audit_Summary_$Timestamp.txt (Main Report)" -ForegroundColor White

if ($ExportToCSV) {
    Write-Host "• CSV files for detailed analysis" -ForegroundColor White
}

# Display critical findings
Write-Host "`nCRITICAL FINDINGS:" -ForegroundColor Red -BackgroundColor Yellow
if ($InactiveUsers.Count -gt 10) {
    Write-Host "⚠ HIGH: $($InactiveUsers.Count) inactive user accounts detected" -ForegroundColor Red
}
if ($NonExpiringPasswords.Count -gt 5) {
    Write-Host "⚠ MEDIUM: $($NonExpiringPasswords.Count) accounts with non-expiring passwords" -ForegroundColor Yellow
}
if ($DisabledPrivileged.Count -gt 0) {
    Write-Host "⚠ LOW: $($DisabledPrivileged.Count) disabled accounts in privileged groups" -ForegroundColor Yellow
}

Write-Host "`nRecommendations:" -ForegroundColor Green
Write-Host "• Review and disable/delete inactive user accounts"
Write-Host "• Implement regular password expiration for service accounts where possible"
Write-Host "• Remove disabled accounts from privileged groups"
Write-Host "• Monitor recently created accounts for unauthorized access"
Write-Host "• Review service account permissions and SPNs"
