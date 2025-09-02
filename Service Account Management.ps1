How to Check Service Account Usage in Active Directory


# Find all accounts with Service Principal Names (SPNs)
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, LastLogonDate, Enabled |
Select-Object Name, SamAccountName, Enabled, LastLogonDate, 
    @{Name='SPNCount'; Expression={$_.ServicePrincipalName.Count}},
    @{Name='SPNs'; Expression={$_.ServicePrincipalName -join '; '}} |
Sort-Object SPNCount -Descending
```

2. Check Service Account Logons

```powershell
# Check recent logons (requires auditing enabled)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 1000 | 
Where-Object { $_.Message -like "*ServiceAccount*" } |
Select-Object TimeCreated, @{Name='Account'; Expression={$_.Properties[5].Value}},
    @{Name='Source'; Expression={$_.Properties[11].Value}}
```

3. Find Services Running Under Service Accounts

On individual servers:

```powershell
# Local service enumeration
Get-WmiObject -Class Win32_Service | 
Where-Object { $_.StartName -like "*ServiceAccount*" } |
Select-Object Name, StartName, State, PathName
```

Domain-wide search (requires admin access to all servers):

```powershell
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
```

4. Check Scheduled Tasks Using Service Accounts

```powershell
# On individual servers
Get-ScheduledTask | 
Where-Object { $_.Principal.UserId -like "*ServiceAccount*" } |
Select-Object TaskName, Principal
```

5. Check Group Policy Preferences for Stored Credentials

```powershell
# Search for stored credentials in SYSVOL
Find-String -Path "\\domain.com\SYSVOL\domain.com\Policies\*.xml" -Pattern "cpassword" -SimpleMatch
```

6. Check IIS Application Pool Accounts

```powershell
# On servers with IIS
Import-Module WebAdministration
Get-ChildItem IIS:\AppPools | 
Select-Object Name, @{Name='Username'; Expression={$_.processModel.userName}} |
Where-Object { $_.Username -like "*svc_*" }
```

7. Comprehensive Service Account Discovery Script

```powershell
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

8. Check Service Account Group Memberships

```powershell
# Find groups containing service accounts
$serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} | Select-Object -ExpandProperty SamAccountName

foreach ($account in $serviceAccounts) {
    $groups = Get-ADPrincipalGroupMembership -Identity $account | Select-Object -ExpandProperty Name
    Write-Host "$account is member of: $($groups -join ', ')" -ForegroundColor Cyan
}
```

9. Check Service Account Permissions

```powershell
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
```

10. Monitor Service Account Usage in Real-Time

```powershell
# Real-time monitoring (run in separate window)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 100 -Oldest |
Where-Object { $_.Message -like "*svc_*" } |
ForEach-Object {
    $time = $_.TimeCreated
    $account = $_.Properties[5].Value
    $source = $_.Properties[11].Value
    Write-Host "[$time] $account logged on from $source" -ForegroundColor Green
}
```

11. Check Service Account Password Policies

```powershell
# Check accounts with non-expiring passwords
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties PasswordNeverExpires, PasswordLastSet |
Where-Object { $_.PasswordNeverExpires -eq $true } |
Select-Object Name, SamAccountName, PasswordLastSet, PasswordNeverExpires |
Sort-Object PasswordLastSet
```

12. Generate Comprehensive Report

```powershell
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
```

Key Things to Check:

1. SPN Count: More SPNs = more services using the account
2. Last Logon: Recent activity indicates active use
3. Group Memberships: Privileged groups indicate elevated access
4. Password Settings: Non-expiring passwords are common for service accounts
5. Enabled Status: Disabled accounts might still be referenced

Best Practices:

· Regularly audit service account usage
· Document each service account's purpose
· Implement least privilege principles
· Monitor for unusual activity
· Use managed service accounts where possible

This comprehensive approach will help you identify where service accounts are being used and assess their security posture.