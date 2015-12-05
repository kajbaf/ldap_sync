[CmdletBinding()]
Param([Parameter(Mandatory=$True)][string]$Usr, [Parameter(Mandatory=$True)][string]$OU, [string]$DC="t1w063")

###### VERSION INFO

### Create new Homefolder and Set Permissions
### V5 edited:
### Making $DC parameter optional
### Using Production Credentials.
### a litttle cleanup

################
function Write-Log {
[CmdletBinding()] param([Parameter(Mandatory=$True,ValueFromPipeline=$True)][object[]]$objects)
  BEGIN {
	 echo "$(Get-Date –f o) Start logging" >> MoveUser.log
  }
  PROCESS 
  {
	Foreach ($obj in $objects) {
		echo $obj >> MoveUser.log
	}
  }
  END
  {
  }
}
trap{ 
	Write-Log "error: ", $_
    Write "error: $_"
    write "exit: "
    write "$err"
	Write-Log $err
    exit $err
}
####### Credentials and other static data
# Production credentials
$uname = 'ddddddd.ir\svc-sssss'
$ppword = 'pppppppp'

$pword = ConvertTo-SecureString  –AsPlainText -Force –String $ppword
$cred =  New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $uname, $pword

$server = "t1w063"
$error.clear()
$err=0
#################

$err = 1
Import-Module ActiveDirectory
If($? -eq $False){
	$err = 11
	throw "unable to load ActiveDirectory Module"
}

if ($args -eq "-V") {
	#write "change to verbose"
	$VerbosePreference = "Continue" 
}

Write-Verbose $Host.name
Write-Verbose "$env:USERNAME @ $env:COMPUTERNAME . $env:USERDNSDOMAIN using server $DC"
Write-Log "$env:USERNAME @ $env:COMPUTERNAME . $env:USERDNSDOMAIN using server $DC"
Write-Verbose "args:$args, user:$Usr, OU:$OU, server:$DC, VerbosePreference:$VerbosePreference"
Write-Log "args:$args, user:$Usr, OU:$OU, server:$DC, VerbosePreference:$VerbosePreference"

$err = 2
$user = Get-ADUser $Usr -Server $DC -Credential $cred
If($? -eq $False){
	$err = 12
	throw "nonexistent user $Usr"
}

$user | select sid, SamAccountName, DistinguishedName, Name, ObjectGUID | Write-Verbose

$err = 3
$target = Get-ADOrganizationalUnit -Identity $OU -Server $DC -Credential $cred
If($? -eq $False){
	$err = 13
	throw "nonexistent target $OU"
}
$target | select DistinguishedName, ObjectGUID | Write-Verbose

write ("moving " + $user.SamAccountName + " to " + $target.DistinguishedName)
$err = 4
Move-ADObject $user.ObjectGUID -TargetPath $target -Server $DC -Credential $cred
If($? -eq $False){
	$err = 14
	throw "error moving user $user to target $target"
}

$user2 = Get-ADUser $user.ObjectGUID  -Server $DC -Credential $cred
$user2 | select SamAccountName, DistinguishedName, Name, ObjectGUID | Write-Verbose

$err= 0
throw "0"
Exit 0