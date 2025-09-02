# How to Check Service Account Usage in Active Directory

# Find all accounts with Service Principal Names (SPNs)
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, LastLogonDate, Enabled |
Select-Object Name, SamAccountName, Enabled, LastLogonDate, 
    @{Name='SPNCount'; Expression={$_.ServicePrincipalName.Count}},
    @{Name='SPNs'; Expression={$_.ServicePrincipalName -join '; '}} |
Sort-Object SPNCount -Descending

# Check recent logons (requires auditing enabled)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 1000 | 
Where-Object { $_.Message -like "*ServiceAccount*" } |
Select-Object TimeCreated, @{Name='Account'; Expression={$_.Properties[5].Value}},
    @{Name='Source'; Expression={$_.Properties[11].Value}}

# Local service enumeration
Get-WmiObject -Class Win32_Service | 
Where-Object { $_.StartName -like "*ServiceAccount*" } |
Select-Object Name, StartName, State, PathName

# Domain-wide search (requires admin access to all servers):
$servers = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} | Select-Object -ExpandProperty Name

foreach ($server in $servers) {
    try {
        $services = Invoke-Command -ComputerName $server -ScriptBlock {
            Get-WmiObject -Class Win32_Service | 
            Where-Object { $_.StartName -like "*svc_*" -or $_.StartName -like "*service*" }
        } -ErrorAction SilentlyContinue
        
        if ($services) {
            Write-Host "Services on $server :" -ForegroundColor Yellow
            $services | Select-Object Name, StartName, State | Format-Table
        }
    }
    catch {
        Write-Warning "Cannot access $server"
    }
}

# Use PowerShell to Count Logons
$ServiceAccount = "svc_account_name"
$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security';
    ID = 4624
} -MaxEvents 10000

$UsageCount = ($Events | Where-Object {
    $_.Properties[5].Value -eq $ServiceAccount
}).Count

Write-Output "Service account '$ServiceAccount' was used $UsageCount times."

# Let’s say you have a service account called svc_sqlagent. You want to know how many times it was used in the past week.
$ServiceAccount = "svc_sqlagent"
$StartDate = (Get-Date).AddDays(-7)

$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security';
    ID = 4624;
    StartTime = $StartDate
} -MaxEvents 10000

$UsageCount = ($Events | Where-Object {
    $_.Properties[5].Value -eq $ServiceAccount -and
    $_.Properties[8].Value -eq 5
}).Count

Write-Output "Service account '$ServiceAccount' was used $UsageCount times in the past week."



# Check Scheduled Tasks Using Service Accounts
# On individual servers
Get-ScheduledTask | 
Where-Object { $_.Principal.UserId -like "*ServiceAccount*" } |
Select-Object TaskName, Principal


# Check Group Policy Preferences for Stored Credentials
# Search for stored credentials in SYSVOL
Find-String -Path "\\domain.com\SYSVOL\domain.com\Policies\*.xml" -Pattern "cpassword" -SimpleMatch

# Check IIS Application Pool Accounts
# On servers with IIS
Import-Module WebAdministration
Get-ChildItem IIS:\AppPools | 
Select-Object Name, @{Name='Username'; Expression={$_.processModel.userName}} |
Where-Object { $_.Username -like "*svc_*" }

# Comprehensive Service Account Discovery Script
# Comprehensive service account audit script
$serviceAccounts = @()

# 1. Find AD accounts with SPNs
$spnAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, LastLogonDate, PasswordLastSet, PasswordNeverExpires |
Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires,
    @{Name='SPNCount'; Expression={$_.ServicePrincipalName.Count}},
    @{Name='SPNs'; Expression={$_.ServicePrincipalName -join '; '}}

# 2. Find likely service accounts by naming convention
$namingPatternAccounts = Get-ADUser -Filter {SamAccountName -like "svc_*" -or SamAccountName -like "*service*" -or SamAccountName -like "*app*"} -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires

# 3. Combine results
$serviceAccounts = $spnAccounts + $namingPatternAccounts | Sort-Object -Unique -Property SamAccountName

# Display results
$serviceAccounts | Format-Table Name, SamAccountName, Enabled, LastLogonDate, SPNCount -AutoSize

# Export to CSV
$serviceAccounts | Export-Csv -Path "Service_Accounts_Audit_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

# Check Service Account Group Memberships
# Find groups containing service accounts
$serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} | Select-Object -ExpandProperty SamAccountName

foreach ($account in $serviceAccounts) {
    $groups = Get-ADPrincipalGroupMembership -Identity $account | Select-Object -ExpandProperty Name
    Write-Host "$account is member of: $($groups -join ', ')" -ForegroundColor Cyan
}

# Check Service Account Permissions
# Check delegated permissions for service accounts
Get-ADObject -Filter * -Properties nTSecurityDescriptor | 
Where-Object { $_.nTSecurityDescriptor.Access } |
ForEach-Object {
    $acl = $_.nTSecurityDescriptor
    foreach ($ace in $acl.Access) {
        if ($ace.IdentityReference -like "*svc_*") {
            [PSCustomObject]@{
                Object = $_.Name
                ObjectType = $_.ObjectClass
                ServiceAccount = $ace.IdentityReference
                Permission = $ace.ActiveDirectoryRights
            }
        }
    }
}


# Monitor Service Account Usage in Real-Time
# Real-time monitoring (run in separate window)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 100 -Oldest |
Where-Object { $_.Message -like "*svc_*" } |
ForEach-Object {
    $time = $_.TimeCreated
    $account = $_.Properties[5].Value
    $source = $_.Properties[11].Value
    Write-Host "[$time] $account logged on from $source" -ForegroundColor Green
}

# Check Service Account Password Policies
# Check accounts with non-expiring passwords
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties PasswordNeverExpires, PasswordLastSet |
Where-Object { $_.PasswordNeverExpires -eq $true } |
Select-Object Name, SamAccountName, PasswordLastSet, PasswordNeverExpires |
Sort-Object PasswordLastSet


# Generate Comprehensive Report
# Generate complete service account report
$report = @()

$serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties *

foreach ($account in $serviceAccounts) {
    $report += [PSCustomObject]@{
        Name = $account.Name
        SamAccountName = $account.SamAccountName
        Enabled = $account.Enabled
        LastLogon = $account.LastLogonDate
        PasswordLastSet = $account.PasswordLastSet
        PasswordNeverExpires = $account.PasswordNeverExpires
        SPNCount = $account.ServicePrincipalName.Count
        SPNs = $account.ServicePrincipalName -join '; '
        MemberOf = (Get-ADPrincipalGroupMembership -Identity $account.SamAccountName | Select-Object -ExpandProperty Name) -join ', '
    }
}

$report | Export-Csv -Path "Comprehensive_Service_Account_Report_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
$report | Format-Table -AutoSize
