# Invoke-CleverSpray
**Password Spraying Script detecting current and previous passwords of Active Directory User**

**Options:**
> -Password: Password to spray.  
> -PasswordFile: Path to file containing a list of passwords to spray.  
> -Username: samAccountName of the user to target.  
> -UsernamesFile: Path to file containing a list of samAccountNames to target.  
> -Domain: The domain to query for users, defaults to the current domain.  
> -Limit: Integer to substract to "badPwdCount" to avoid blocking accounts (must be at least 2 ; default is 2).  
> -Delay: Delay between authentication attemps (in ms).  
> -HideOld: Hide old password discovered (default is false).

**Usage:**
Import Invoke-CleverSpray:
```
Import-Module .\Invoke-CleverSpray.ps1
```
Spray a unique password:
```
Invoke-CleverSpray -Password "Passw0rd"
```
Spray multiple passwords: 
```
Invoke-CleverSpray -PasswordFile ".\pwd_list.txt"
```

**Behavior:**
- Retrieves default or specified domain (to specify a domain, use the -Domain paramater) using Get-NetDomain from PowerView (@harmj0y) and identifies the PDCe to send authentication requests (because the domain PDCe centralizes "badPwdCount" attributes for the domain users)
- Retrieves all the domain user accounts using Get-NetUser from PowerView (@harmj0y) or within specified file (-UsernamesFile)
- For each users, it verifies if the "badPwdCount" attribute is inferior to the threshold set passed as argument (-Limit), if it is:
    - It tries to authenticates using provided password (-Password) or a password within a specified password list file (-PasswordFile) with each users' accounts
        - If authentication is successful, the user's current password has been discovered
        - If authentication is unsuccessful: 
            - **checks if user's "badPwdCount" attribute was incremented**: if not, provided password is a previous password of the user account (be creative, detect the user's password creation pattern to guess it's actual password ;)
            - if user's "badPwdCount" attribute was incremented, no previous or current password was found for that specific user
    - If a delay is set (-Delay), wait for Delay +/- Jitter (-Jitter) or directly spray on to the next user of the domain.

 **WARNING: Default -Limit is set to 1 (i.e. only user accounts having a "badPwdCount" lower or equal to 1 will be targeted). You can increase this value at your own risk to target more users. I cannot garantee no users will be locked.**

**Greetings: **
Thanks @harmj0y for PowerView !
