# Invoke-CleverSpray
**PowerShell script to conduct "advanced" password spraying on Active Directory users' accounts**

**Options :**
> -Password : Password to spray.  
> -PasswordFile : Path to file containing a list of passwords to spray.  
> -Domain : The domain to query for users, defaults to the current domain.  
> -Limit : Integer to substract to "badPwdCount" to avoid blocking accounts (must be at least 2 ; default is 2).  
> -Delay : Delay between authentication attemps (in ms).  
> -HideOld : Hide old password discovered (default is false).

**Usage :**
Import Invoke-CleverSpray :
```
Import-Module .\Invoke-CleverSpray.ps1
```
Spray a unique password :
```
Invoke-CleverSpray -Password "Passw0rd"
```
Spray multiple passwords : 
```
Invoke-CleverSpray -PasswordFile ".\pwd_list.txt"
```

**Behavior :**
- Retrieves default or specified domain (to specify a domain, use the -Domain paramater) using Get-NetDomain from PowerView (@harmj0y) and identifies the PDCe to send authentication requests (because the domain PDCe centralizes "badPwdCount" attributes for the domain users)
- Retrieves all the domain user accounts using Get-NetUser from PowerView (@harmj0y)
- Retrieves the domain lockout threshold 
- Calculates the "badPwdCount threshold" not to exceed :
    - Default is the domain lockout threshold minus 2
    - The threshold can be customized using the -Limit parameter and is then calculated as domain lockout threshold minus Limit
- For each users, it verifies if the "badPwdCount" attribute is inferior to the calculated threshold in order not to lock any account, if it is :
    - It tries to authenticates using provided password (-Password) or a password within a specified password list file (-PasswordFile) with each users' accounts
        - If authentication is successful, the user's current password has been discovered
        - If authentication is unsuccessful: 
            - **checks if user's "badPwdCount" attribute was incremented** : if not, provided password is a previous password of the user account (be creative, detect the user's password creation pattern to guess it's actual password...)
            - if user's "badPwdCount" attribute was incremented, no previous or current password was found for that specific user
    - If a delay is set (-Delay), wait for Delay or directly spray on to the next user of the domain.

**Greetings : **
Thanks @harmj0y for PowerView !
