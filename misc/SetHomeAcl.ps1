[CmdletBinding()]
Param([Parameter(Mandatory=$True)][string]$HPath, [Parameter(Mandatory=$True)][string]$Usr, [string]$DC="t1w063",
    [string]$Share="\\dc1w009\users$", [string]$Tsddl='#')
    # [string]$Tsddl='#', [string]$Share="\\dc1w009.ddddddd.ir\users$")

###### VERSION INFO

### Create new Homefolder and Set Permissions
### V2 added:
### check if ActiveDirectory Module loaded: revised
### New Verbose function created; able to write objects.
### Making $DC parameter optional
### Check if the HomeFolder exists.
### Set ACL from a newly created ACE. Error: Principal mapping required.

### V3 edited:
### my Verbose function obsoluted; renamed to My-Verbose
### Set ACL from a SDDL. No ownership setting.

### V4 CleanUp:
### my Verbose function removed
### other cleanups

### V5 Addedd:
### Write-Log addedd

### V6 Changed:
### "net use" access to home server, no PsExec.exe required
### Adding extra Error Codes and Write-Log

### My Trap
function Write-Log {
[CmdletBinding()] param([Parameter(Mandatory=$True,ValueFromPipeline=$True)][object[]]$objects)
  BEGIN {
	 echo "$(Get-Date –f o) " >> D:\scripts\SetHomeAcl.log
  }
  PROCESS {
	Foreach ($obj in $objects) {
		 $obj | Out-String >> D:\scripts\SetHomeAcl.log
	}
  }
  END{
  }
}
trap{ 
	net use * /d /y
	Write-Log "error: ", $_
    Write "error: $_"
    write "exit: "
    write "$err"
	Write-Log $err
    Exit $err
}
	
### Credential and other static data
$error.clear()
$err = 0
Write-Log "`n   #######++++--- Initiate The Script ---++++#######"
# Production credentials
$uname = 'ddddddd\svc-sssss'
$ppword = 'ppppppp'
$pword = ConvertTo-SecureString  –AsPlainText -Force –String $ppword
$cred =  New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $uname, $pword
$server = "t1w063"
# domain sddl, no owner setting
If ($Tsddl -eq '#'){
	$Tsddl = 'G:DUD:(A;OICI;FA;;;#)(A;OICIID;FA;;;SY)(A;OICIID;0x1301bf;;;S-1-5-21-1480964169-1710879411-3095655000-2182)(A;OICIID;FA;;;DA)(A;OICIID;0x1301bf;;;S-1-5-21-1480964169-1710879411-3095655000-36568)'
}

# $HPath = Join-Path $HPath.Trim() ''
# $Share = Join-Path $Share.Trim() ''
Write-Log "prechange variables HPath: $HPath, Share: $Share, Folder, $Folder"
Write-Verbose "prechange variables HPath: $HPath, Share: $Share, Folder, $Folder"
If ($HPath.StartsWith($Share)) {
	Write-Log "$HPath is a complete home path."
	$Folder = $HPath.Replace($Share, '')
	While ($Folder.StartsWith('\')) { $Folder = $Folder.Substring(1) }
} 
Else {
	Write-Log "$HPath is a folder name."
	$Folder = $HPath
	$HPath = Join-Path $Share $Folder
}
Write-Log "postchange variables HPath: $HPath, Share: $Share, Folder, $Folder"
Write-Verbose "postchange variables HPath: $HPath, Share: $Share, Folder, $Folder"
#################

$err = 1
Import-Module ActiveDirectory
If($? -eq $False){
	throw "unable to load ActiveDirectory Module"
}

If ($args -eq "-V") {
    #write "change to verbose"
    $VerbosePreference = "Continue" 
}

Write-Verbose $Host.name
Write-Log "Host $($Host.name)"
Write-Verbose "$env:USERNAME @ $env:COMPUTERNAME . $env:USERDNSDOMAIN"
Write-Log "$env:USERNAME @ $env:COMPUTERNAME . $env:USERDNSDOMAIN"
Write-Verbose "args:$args, user:$Usr, HPath: $HPath, server:$DC, VerbosePreference:$VerbosePreference"
Write-Log "args:$args, user:$Usr, HPath: $HPath, server:$DC, VerbosePreference:$VerbosePreference"

$err = 2
$user = Get-ADUser $Usr -Server $DC -Credential $cred
If($? -eq $False){
	throw "nonexistent user $Usr"
}
$user | select SamAccountName, SID, DistinguishedName, Name, ObjectGUID | Write-Log

$err = 9
$(net use) | Write-Log
net use * /d /y
$(net use) | Write-Log

$err = 8
$net = New-Object -com Wscript.Network  # Manage mapped shares
$drive = $net.EnumNetworkDrives()		# Get current shaers
[string]::Concat("first enumeration `n", $drive) | Write-Log
for ($i = 0; $i -lt $drive.Count(); $i += 2){
	$d = $drive.Item($i)
	$r = $drive.Item($i + 1)
	If( $($r).StartsWith($Share) ) {	# if the $Share is previously mapped
		If ($d -ne ""){
			Write-Log "drive letter in use $d"
			Write-Verbose "drive letter in use $d"
			net use $d /d
			# $net.RemoveNetworkDrive($d, $True)	# remove the share
		}
		Else{
			Write-Log "no drive letter in use $r"
			Write-Verbose "no drive letter in use $r"
			net use $r /d
			# $net.RemoveNetworkDrive($r, $True)
		}
	}
}
[string]::Concat("last enumeration `n", $net.EnumNetworkDrives()) | Write-Log
$err = 7
$net.MapNetworkDrive('S:', $Share, $False, $uname, $ppword)
If($? -eq $False){
	throw "Cannot map the root $Share"
}
If ($(Test-Path 'S:\') -eq $False){
	throw "Cannot map the root $Share"
}
[string]::Concat("after mapping `n", $net.EnumNetworkDrives()) | Write-Log

$err = 3
Write-Log (Join-Path 'S:' $Folder)
If ($(Test-Path(Join-Path 'S:' $Folder)) -eq $True){
	throw "The folder exists S:\$Folder"
}
If ($(Test-Path $HPath) -eq $True){
	throw "The folder exists $HPath"
}
Write-Log "Creating folder $HPath"
$err = 6
mkdir $HPath
If($? -eq $False){
	throw "Error creating target $HPath"
}

$err = 4
$acl = Get-Acl $HPath
If($? -eq $False){
	throw "error getting target ACL $HPath"
}
$acl | select PSPath, Sddl, Owner, AccessToString | Write-Log

Write-Log $("--OLD ACL-- `n" + $acl.AccessToString)
$sddl = $Tsddl.replace('#',$user.SID)
Write-Log $sddl
$acl.SetSecurityDescriptorSddlForm($sddl)
Write-Log $("--NewACL-- `n" + $acl.AccessToString)

write ("setting permission for " + $user.SamAccountName + " to " + $HPath)
$err = 5
Set-Acl -Path $HPath -AclObject $acl
If($? -eq $False){
	throw "error setting permission for $Usr to $HPath"
}

$acl2 = Get-Acl $HPath
Write-Log $("Finall permissions `n" + $acl2.AccessToString)

$err = 0
throw "0"
Exit 0
