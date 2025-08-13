

A list of Windows command-line tools commonly used for managing and administering Active Directory on both desktop and server environments. These commands help with tasks like managing users, groups, computers, domains, and policies.

1. DSADD (Add Objects)
	• Purpose: Adds Active Directory objects such as users, groups, computers, and organizational units (OUs).
Example (Add User):

dsadd user "CN=JohnDoe,OU=Users,DC=example,DC=com" -samid jdoe -pwd P@ssw0rd -memberof "CN=Domain Admins,CN=Users,DC=example,DC=com"
	• Adds a user JohnDoe with the samid of jdoe and assigns a password.

2. DSQUERY (Query Active Directory)
	• Purpose: Queries the directory for objects like users, computers, and groups.
Example (Find Disabled Accounts):

dsquery user -disabled
	• Lists all disabled user accounts.

3. DSMOD (Modify Objects)
	• Purpose: Modifies existing Active Directory objects.
Example (Modify Group Membership):

dsmod group "CN=Domain Admins,CN=Users,DC=example,DC=com" -addmbr "CN=JohnDoe,OU=Users,DC=example,DC=com"
	• Adds JohnDoe to the Domain Admins group.

4. DSRM (Remove Objects)
	• Purpose: Removes objects from Active Directory.
Example (Remove a User):

dsrm "CN=JohnDoe,OU=Users,DC=example,DC=com"
	• Removes the user JohnDoe.

5. DSRM /RESTORE (Backup & Restore Active Directory)
	• Purpose: Starts Directory Services Restore Mode (DSRM) for repairing or restoring the Active Directory database.
Example (Enter DSRM Mode):

bcdedit /set safeboot dsrepair
	• Reboots the server into Directory Services Restore Mode.

6. DSRMUTIL (Reset DSRM Password)
	• Purpose: Resets the Directory Services Restore Mode administrator password.
Example (Reset DSRM Password):

ntdsutil "set dsrm password" "reset password on server null" quit
	• Resets the DSRM administrator password on the local server.

7. NTDSUTIL (Database Utilities)
	• Purpose: Used to manage and maintain the Active Directory database (backup, restore, metadata cleanup, etc.).
Example (Metadata Cleanup):

ntdsutil
metadata cleanup
connections
connect to server ServerName
quit
select operation target
list domains
quit
	• Performs a metadata cleanup of a decommissioned domain controller.

8. NETDOM (Domain Management)
	• Purpose: Manages domain trust relationships, joins machines to a domain, and resets domain machine accounts.
Example (Join a Computer to a Domain):

netdom join ComputerName /domain:example.com /userd:adminuser /passwordd:P@ssw0rd
	• Joins ComputerName to the domain example.com.

9. REPADMIN (Replication Management)
	• Purpose: Monitors and manages Active Directory replication.
Example (Check Replication Status):

repadmin /showrepl
	• Displays the replication status of domain controllers.
Example (Force Replication):

repadmin /syncall /A /e
	• Forces synchronization between all domain controllers.

10. GPUPDATE (Group Policy Update)
	• Purpose: Manually refreshes Group Policy settings.
Example (Force a Group Policy Update):

gpupdate /force
	• Forces a Group Policy update immediately.

11. GPRESULT (Group Policy Result)
	• Purpose: Displays Group Policy settings and Resultant Set of Policy (RSoP) for a computer or user.
Example (Group Policy Results for User):

gpresult /r /user JohnDoe
	• Displays Group Policy information applied to user JohnDoe.

12. CSVDE (Import/Export Data to/from Active Directory)
	• Purpose: Imports and exports Active Directory objects to and from a CSV file.
Example (Export AD Data to CSV):

csvde -f output.csv
	• Exports all Active Directory data to output.csv.
Example (Import from CSV File):

csvde -i -f import.csv
	• Imports data from import.csv into Active Directory.

13. LDIFDE (LDAP Directory Import/Export)
	• Purpose: Similar to CSVDE, but uses LDAP Data Interchange Format (LDIF) for importing/exporting.
Example (Export AD Data):

ldifde -f export.ldf
	• Exports AD objects to export.ldf.
Example (Import AD Data):

ldifde -i -f import.ldf
	• Imports AD objects from import.ldf.

14. NLTEST (Domain Testing Utility)
	• Purpose: Used for network logon testing and domain controller diagnostics.
Example (Check Secure Channel):

nltest /sc_query:example.com
	• Verifies the secure channel between the local machine and the domain example.com.

15. ADUC (Active Directory Users and Computers)
	• Purpose: The dsa.msc command opens the GUI tool for managing users, groups, and other AD objects.
Example (Open Active Directory Users and Computers):

dsa.msc
	• Opens the ADUC management console.

16. POWERSHELL AD MODULE
	• Purpose: Manage Active Directory using PowerShell cmdlets.
Example (Get AD User):

powershell
Get-ADUser -Identity JohnDoe
	• Retrieves information about the user JohnDoe.
Example (Add User to Group):

powershell
Add-ADGroupMember -Identity "Domain Admins" -Members "JohnDoe"
	• Adds JohnDoe to the Domain Admins group.

17. NET USER (Manage User Accounts)
	• Purpose: Manages user accounts from the command line.
Example (Create a New User):

net user JohnDoe P@ssw0rd /add /domain
	• Creates a new user JohnDoe with the password P@ssw0rd in the domain.

18. NET GROUP (Manage Groups)
	• Purpose: Manages domain groups and their members.
Example (Add a User to a Group):

net group "Domain Admins" JohnDoe /add /domain
	• Adds JohnDoe to the Domain Admins group.

19. SCHTASKS (Task Scheduler Management)
	• Purpose: Manages and schedules tasks on a remote or local computer.
Example (Create a Task to Run a Script):

schtasks /create /tn "AD Backup" /tr C:\scripts\backup.ps1 /sc daily /ru System
	• Creates a scheduled task that runs a PowerShell backup script daily.

20. WBADMIN (Backup and Recovery)
	• Purpose: Command-line tool to manage system backups, including Active Directory backup.
Example (Backup Active Directory):

wbadmin start systemstatebackup -backuptarget:D:
	• Starts a system state backup, including Active Directory, to drive D:.

missing commands from the previous list, with their purpose and examples for managing Active Directory:

21. NET LOCALGROUP (Manage Local Groups)
	• Purpose: Adds, displays, or modifies local groups on computers.
Example (Add User to Local Group):

net localgroup "Administrators" JohnDoe /add
	• Adds user JohnDoe to the local Administrators group.
Example (List Local Group Members):

net localgroup "Administrators"
	• Displays all members of the Administrators group.

22. NET TIME (Synchronize Time)
	• Purpose: Displays or synchronizes the local computer's time with a domain controller or another time source.
Example (Display Time on Domain Controller):

net time \\DC01
	• Displays the current time from the domain controller DC01.
Example (Synchronize Local Time with Domain Controller):

net time \\DC01 /set /y
	• Synchronizes the local computer's time with the time from DC01.

23. GPRESULT (Group Policy Resultant Set of Policy)
	• Purpose: Displays the applied Group Policy settings for a user or computer.
Example (Check Group Policy for Current User):

gpresult /r
	• Displays the Resultant Set of Policy (RSoP) for the current user.
Example (Check Group Policy for a Specific User):

gpresult /user JohnDoe /r
	• Displays RSoP for the user JohnDoe.

24. GPUPDATE (Group Policy Update)
	• Purpose: Manually refreshes Group Policy settings on the local machine.
Example (Force Group Policy Update):

gpupdate /force
	• Forces a refresh of the computer and user Group Policies.

25. WBADMIN (Backup Active Directory)
	• Purpose: Command-line tool to manage system backups, including backing up the Active Directory database.
Example (Backup Active Directory):

wbadmin start systemstatebackup -backuptarget:E:
	• Starts a system state backup (including Active Directory) to the drive E:.

26. DSGET (Get Active Directory Object Details)
	• Purpose: Displays detailed properties of specific Active Directory objects.
Example (Get User Details):

dsget user "CN=JohnDoe,OU=Users,DC=example,DC=com"
	• Displays detailed properties of the user JohnDoe.
Example (Get Group Members):

dsget group "CN=Domain Admins,CN=Users,DC=example,DC=com" -members
	• Displays members of the Domain Admins group.

27. DSQUERY (Query Active Directory)
	• Purpose: Queries the directory for various objects like users, computers, groups, and OUs.
Example (Query Disabled Users):

dsquery user -disabled
	• Lists all disabled users in the directory.

28. NETDOM (Join and Manage Domains)
	• Purpose: Manages domain trust relationships, joins computers to domains, and resets domain computer account passwords.
Example (Join Computer to Domain):

netdom join ComputerName /domain:example.com /userd:adminuser /passwordd:P@ssw0rd
	• Joins ComputerName to the domain example.com.
Example (Reset Machine Account Password):

netdom resetpwd /server:DC01 /userd:adminuser /passwordd:P@ssw0rd
	• Resets the machine account password for the domain controller DC01.

29. REPADMIN (Active Directory Replication Management)
	• Purpose: Monitors and manages replication between domain controllers.
Example (Check Replication Status):

repadmin /showrepl
	• Displays the replication status for all domain controllers.
Example (Force Replication):

repadmin /syncall /A /e
	• Forces synchronization of all directory partitions across all domain controllers.

30. CSVDE (Import/Export Active Directory Data)
	• Purpose: Imports and exports Active Directory objects in CSV format.
Example (Export AD Data to CSV):

csvde -f output.csv
	• Exports all AD objects to a CSV file named output.csv.
Example (Import AD Data from CSV):

csvde -i -f import.csv
	• Imports data from import.csv into Active Directory.

31. LDIFDE (LDAP Import/Export)
	• Purpose: Imports and exports Active Directory objects in LDAP Data Interchange Format (LDIF).
Example (Export AD Data to LDIF):

ldifde -f output.ldf
	• Exports all AD objects to an LDIF file named output.ldf.
Example (Import AD Data from LDIF):

ldifde -i -f import.ldf
	• Imports data from an LDIF file import.ldf into Active Directory.

32. WHOAMI (Display User Information)
	• Purpose: Displays details about the current logged-in user and security groups.
Example (Display Current User and Groups):

whoami /groups
	• Displays the current user and associated groups.

33. NLTEST (Domain and Trust Testing)
	• Purpose: Tests trust relationships and domain controller configuration.
Example (Check Trust Relationships):

nltest /domain_trusts
	• Lists the trust relationships between domains.
Example (Verify Secure Channel):

nltest /sc_query:example.com
	• Verifies the secure channel between the computer and the domain example.com.

missing Active Directory commands that weren't covered previously, with their purpose and examples:

	34. DSADD (Add Objects to Active Directory)
	• Purpose: Adds a new user, group, computer, contact, or organizational unit to Active Directory.
Example (Add a New User):

dsadd user "CN=JohnDoe,OU=Users,DC=example,DC=com" -samid johndoe -pwd P@ssw0rd
	• Adds a new user JohnDoe with the username johndoe and password P@ssw0rd.

	35. DSMOD (Modify Active Directory Objects)
	• Purpose: Modifies attributes of an existing user, group, computer, or organizational unit.
Example (Modify User):

dsmod user "CN=JohnDoe,OU=Users,DC=example,DC=com" -pwdnew NewP@ssw0rd
	• Changes the password of JohnDoe to NewP@ssw0rd.

	36.  DSRM (Remove Active Directory Objects)
	• Purpose: Deletes objects from Active Directory.
Example (Remove a User):

dsrm "CN=JohnDoe,OU=Users,DC=example,DC=com"
	• Deletes the user JohnDoe from Active Directory.

	36. DSMOVE (Move Active Directory Objects)
	• Purpose: Moves an object to a new location within Active Directory.
Example (Move User to a Different OU):

dsmove "CN=JohnDoe,OU=Users,DC=example,DC=com" -newparent "OU=IT,DC=example,DC=com"
	• Moves the user JohnDoe from the Users OU to the IT OU.

	37.  CSVDE (Import/Export Active Directory Data)
	• Purpose: Imports and exports Active Directory objects in CSV format.
Example (Export Users to CSV):

csvde -f users.csv -r "(objectClass=user)"
	• Exports all user objects to users.csv.

	38.  LDIFDE (Import/Export Active Directory Data in LDIF Format)
	• Purpose: Imports and exports directory objects in LDAP Data Interchange Format (LDIF).
Example (Export All Users):

ldifde -f export.ldf -r "(objectClass=user)"
	• Exports all user objects to an LDIF file.

	39.  NETDOM (Domain Management)
	• Purpose: Joins computers to a domain, manages trust relationships, and resets computer accounts.
Example (Rename a Computer and Join Domain):

netdom renamecomputer %COMPUTERNAME% /newname:NewName /userd:adminuser /passwordd:P@ssw0rd
	• Renames the current computer to NewName and joins the domain.

	40.  NLTEST (Domain Test Utility)
	• Purpose: Verifies trust relationships and checks domain controller replication status.
Example (Check Domain Controller Status):

nltest /dclist:example.com
	• Lists all domain controllers in the domain example.com.

	41.  WHOAMI (User Information)
	• Purpose: Displays information about the user currently logged into the system.
Example (Check Current User):

whoami
	• Displays the username of the currently logged-in user.

	42.  NTDSUTIL (AD Database and Domain Services Management)
	• Purpose: Manages the Active Directory database, domain controllers, and operations masters.
Example (Manage FSMO Roles):

ntdsutil roles
	• Enters FSMO role management mode to transfer or seize roles.

	43.  REPLMON (Replication Monitor)
	• Purpose: Monitors replication between domain controllers in a forest (GUI-based tool).
Example (Open Replication Monitor):

replmon
	• Launches the Replication Monitor GUI tool.

	44.  ADREPLSTATUS (Active Directory Replication Status Tool)
	• Purpose: Provides graphical monitoring of replication status across domain controllers.
Example:
	• Download and install the AD Replication Status Tool to view real-time replication health in a GUI interface.

	45. SCHMMGMT.MSC (Schema Management)
	• Purpose: Opens the Active Directory Schema Management snap-in for managing schema objects.
Example (Open Schema Management Console):

schmmgmt.msc
	• Opens the Active Directory Schema Management console.

	46. DSACLs (Modify Object Permissions)
	• Purpose: Displays or modifies access control lists (ACLs) of objects in Active Directory.
Example (View Permissions of a User):

dsacls "CN=JohnDoe,OU=Users,DC=example,DC=com"
	• Displays the ACLs for the user JohnDoe.


