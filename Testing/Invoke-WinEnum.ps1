function Get-BinaryWritableServices {
    <#
    Modified https://github.com/A-mIn3/WINspect
    .SYNOPSIS
    Gets services binaries with permission   
    Services to be ignored are those in system32 subtree and 
    ACL's for System,Administrator or TrustedInstaller
    .DESCRIPTION
    This function checks services that have writable binaries and returns an array 
    containing service objects.
    #>
    $abusable=@(
        'Modify',
        'TakeOwnership',
        'ChangePermissions',
        'Write',
        'Delete',
        'FullControl'
    )
    $writableServices = New-Object System.Collections.ArrayList
    $services = Get-WmiObject -Class Win32_Service| where {$_.pathname -ne $null -and $_.pathname -notmatch ".*system32.*"}
    try{
        $services | foreach {
            $service = $_
            $pathname = $($service.pathname.subString(0, $service.pathname.toLower().IndexOf(".exe")+4)).trim('"')
            $binaryAcl = Get-Acl $pathname  -ErrorAction SilentlyContinue  
            $acls = $binaryAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | where {$_.AccessControlType -match 'allow'}
            foreach($acl in $acls){
                try{
                    $trustee = $acl.IdentityReference.Translate([System.Security.Principal.NTAccount])
                }catch{
                    #do nothing
                }
                if(($trustee -notmatch 'System') -and ($trustee -notmatch 'Administrator') -and ($trustee -notmatch 'TrustedInstaller')){
                    $permissions = $acl.FileSystemRights.ToString().split(',').trim()
                    foreach($permission in $permissions){
                        if(($abusable -contains $permission)){
                            $data = New-Object  PSObject -Property @{
                                "Service"     = $service.name
                                "Path"        = $pathname
                                "Trustee"     = $trustee
                                "Permissions" = $permissions
                            }
                            $writableServices.add($data) | Out-Null
                            return
                        }
                    }
                }
            } 
        }
        if($writableServices.Count -gt 0){
            $writableServices  |Format-List
        }else{
            Write-Output "[+] No Weird ACL on Service Binary Found"
        }
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
    }
}
function Get-LocalShares {
    <#
    Modified https://github.com/A-mIn3/WINspect/blob/master/WINspect.ps1
    #>
    $permissionFlags = @{
        0x1 =   "Read-List";
        0x2 =   "Write-Create";
        0x4 =   "Append-Create Subdirectory";                  	
        0x20    =   "Execute file-Traverse directory";
        0x40    =   "Delete child"
        0x10000 =   "Delete";                     
        0x40000 =   "Write access to DACL";
        0x80000 =   "Write Onwer"
    }
    $shares = New-Object System.Collections.ArrayList
    try{
        Get-WmiObject -class Win32_share -Filter "type=0"| foreach {
            $shareSecurityObj = Get-WmiObject -class Win32_LogicalShareSecuritySetting -Filter "Name='$($_.Name)'"
            $securityDescriptor = $shareSecurityObj.GetSecurityDescriptor().Descriptor
            ForEach($ace in $securityDescriptor.dacl){
                # 0 = Allow ; 1 = Deny
                if([int]$ace.acetype -eq 0){
                    $accessMask  = $ace.accessmask
                    $permissions = ""
                    foreach($flag in $permissionFlags.Keys){
                        if($flag -band $accessMask){
                            $permissions+=$permissionFlags[$flag]
                            $permissions+=";"
                        }
                    }
                    $share = New-Object  PSObject -Property @{
                        "ShareName"    =  $_.Name     
                        "Trustee"      =  $ace.trustee.Name 
                        "Permissions"  =  $permissions
                    }
                    $shares.add($share) | Out-Null
                }
            }    
        }
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
    }
    if($shares.Count -gt 0){
        Write-Output ($shares | Format-List ShareName,Trustee, Permissions)
    }else{
        Write-Output "[*] No local Shares Were Found"
    }
}
function Get-UACLevel {
    <#
    https://github.com/A-mIn3/WINspect/blob/master/WINspect.ps1
    .SYNOPSIS
    Checks current configuration of User Account Control
    .DESCRIPTION
    This functions inspects registry informations related to UAC configuration 
    and checks whether UAC is enabled and which level of operation is used.
    #>
    try {
        $UACRegValues = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
        if ([int]$UACRegValues.EnableLUA -eq 1) {
            Write-Output "[+] UAC is enabled"
        }
        else {
            Write-Output "[-] UAC is disabled"
        }
        $consentPrompt = $UACregValues.ConsentPromptBehaviorAdmin
        $secureDesktop = $UACregValues.PromptOnSecureDesktop
        if ( $consentPrompt -eq 0 -and $secureDesktop -eq 0) {
            Write-Output "[*] UAC Level : Never Notify"
        }
        elseif ($consentPrompt -eq 5 -and $secureDesktop -eq 0) {
            Write-Output "[*] UAC Level : Notify only when apps try to make changes (No secure desktop)"
        }
        elseif ($consentPrompt -eq 5 -and $secureDesktop -eq 1) {
            Write-Output "[*] UAC Level : Notify only when apps try to make changes (secure desktop on)"
        }
        elseif ($consentPrompt -eq 5 -and $secureDesktop -eq 2) {
            Write-Output "[*] UAC Level : Always Notify with secure desktop"
        }
    }
    catch {
        Write-Output "[-] $($_.Exception.Message)"
    }
}
function Get-RegistryAutoLogon {
    <#
    .SYNOPSIS
    Finds any autologon credentials left in the registry.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    Checks if any autologon accounts/credentials are set in a number of registry locations.
    If they are, the credentials are extracted and returned as a custom PSObject.
    .EXAMPLE
    Get-RegistryAutoLogon
    Finds any autologon credentials left in the registry.
    .OUTPUTS
    PowerUp.RegistryAutoLogon
    Custom PSObject containing autologin credentials found in the registry.
    .LINK
    https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/windows_autologin.rb
    #>
    
    [OutputType('PowerUp.RegistryAutoLogon')]
    [CmdletBinding()]
    Param()

    $AutoAdminLogon = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)
    Write-Verbose "AutoAdminLogon key: $($AutoAdminLogon.AutoAdminLogon)"

    if ($AutoAdminLogon -and ($AutoAdminLogon.AutoAdminLogon -ne 0)) {

        $DefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
        $DefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
        $DefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword
        $AltDefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
        $AltDefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
        $AltDefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword

        if ($DefaultUserName -or $AltDefaultUserName) {
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'DefaultDomainName' $DefaultDomainName
            $Out | Add-Member Noteproperty 'DefaultUserName' $DefaultUserName
            $Out | Add-Member Noteproperty 'DefaultPassword' $DefaultPassword
            $Out | Add-Member Noteproperty 'AltDefaultDomainName' $AltDefaultDomainName
            $Out | Add-Member Noteproperty 'AltDefaultUserName' $AltDefaultUserName
            $Out | Add-Member Noteproperty 'AltDefaultPassword' $AltDefaultPassword
            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.RegistryAutoLogon')
            $Out
        }
    }
}
function Get-CachedGPPPassword {
    <#
    .SYNOPSIS
    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences and
    left in cached files on the host.
    Author: Chris Campbell (@obscuresec)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    Get-CachedGPPPassword searches the local machine for cached for groups.xml, scheduledtasks.xml, services.xml and
    datasources.xml files and returns plaintext passwords.
    .EXAMPLE
    Get-CachedGPPPassword
    NewName   : [BLANK]
    Changed   : {2013-04-25 18:36:07}
    Passwords : {Super!!!Password}
    UserNames : {SuperSecretBackdoor}
    File      : C:\ProgramData\Microsoft\Group Policy\History\{32C4C89F-7
                C3A-4227-A61D-8EF72B5B9E42}\Machine\Preferences\Groups\Gr
                oups.xml
    .LINK
    http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
    https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
    https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
    http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
    http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
    #>
    [CmdletBinding()]
    Param()
    # Some XML issues between versions
    Set-StrictMode -Version 2
    # make sure the appropriate assemblies are loaded
    Add-Type -Assembly System.Security
    Add-Type -Assembly System.Core
    # helper that decodes and decrypts password
    function local:Get-DecryptedCpassword {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
        [CmdletBinding()]
        Param(
            [string] $Cpassword
        )
        try {
            # Append appropriate padding based on string length
            $Mod = ($Cpassword.length % 4)
            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }
            $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            # Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            # Set IV to all nulls to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }
        catch {
            Write-Error $Error[0]
        }
    }
    # helper that parses fields from the found xml preference files
    function local:Get-GPPInnerField {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
        [CmdletBinding()]
        Param(
            $File
        )
        try {
            $Filename = Split-Path $File -Leaf
            [XML] $Xml = Get-Content ($File)
            $Cpassword = @()
            $UserName = @()
            $NewName = @()
            $Changed = @()
            $Password = @()
            # check for password field
            if ($Xml.innerxml -like "*cpassword*"){
                Write-Verbose "Potential password in $File"
                switch ($Filename) {
                    'Groups.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Services.xml' {
                        $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Scheduledtasks.xml' {
                        $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'DataSources.xml' {
                        $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Printers.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Drives.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                }
           }
           ForEach ($Pass in $Cpassword) {
               Write-Verbose "Decrypting $Pass"
               $DecryptedPassword = Get-DecryptedCpassword $Pass
               Write-Verbose "Decrypted a password of $DecryptedPassword"
               #append any new passwords to array
               $Password += , $DecryptedPassword
           }
            # put [BLANK] in variables
            if (-not $Password) {$Password = '[BLANK]'}
            if (-not $UserName) {$UserName = '[BLANK]'}
            if (-not $Changed)  {$Changed = '[BLANK]'}
            if (-not $NewName)  {$NewName = '[BLANK]'}
            # Create custom object to output results
            $ObjectProperties = @{'Passwords' = $Password;
                                  'UserNames' = $UserName;
                                  'Changed' = $Changed;
                                  'NewName' = $NewName;
                                  'File' = $File}
            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Verbose "The password is between {} and may be more than one value."
            if ($ResultsObject) { Return $ResultsObject }
        }
        catch {Write-Error $Error[0]}
    }
    try {
        $AllUsers = $Env:ALLUSERSPROFILE
        if ($AllUsers -notmatch 'ProgramData') {
            $AllUsers = "$AllUsers\Application Data"
        }
        # discover any locally cached GPP .xml files
        $XMlFiles = Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue
        if ( -not $XMlFiles ) {
            Write-Verbose 'No preference files found.'
        }
        else {
            Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
            ForEach ($File in $XMLFiles) {
                Get-GppInnerField $File.Fullname
            }
        }
    }
    catch {
        Write-Error $Error[0]
    }
}
function Get-UnattendedInstallFile {
    <#
    .SYNOPSIS
    Checks several locations for remaining unattended installation files,
    which may have deployment credentials.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .EXAMPLE
    Get-UnattendedInstallFile
    Finds any remaining unattended installation files.
    .LINK
    http://www.fuzzysecurity.com/tutorials/16.html
    .OUTPUTS
    PowerUp.UnattendedInstallFile
    Custom PSObject containing results.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.UnattendedInstallFile')]
    [CmdletBinding()]
    Param()
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                            "c:\sysprep\sysprep.inf",
                            "c:\sysprep.inf",
                            (Join-Path $Env:WinDir "\Panther\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
                        )
    # test the existence of each path and return anything found
    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'UnattendPath' $_
        $Out | Add-Member Aliasproperty Name UnattendPath
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.UnattendedInstallFile')
        $Out
    }
    $ErrorActionPreference = $OrigError
}
function Get-UnquotedService {
    <#
    .SYNOPSIS
    Returns the name and binary path for services with unquoted paths
    that also have a space in the name.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: Get-ModifiablePath, Test-ServiceDaclPermission  
    .DESCRIPTION
    Uses Get-WmiObject to query all win32_service objects and extract out
    the binary pathname for each. Then checks if any binary paths have a space
    and aren't quoted.
    .EXAMPLE
    Get-UnquotedService
    Get a set of potentially exploitable services.
    .OUTPUTS
    PowerUp.UnquotedService
    .LINK
    https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/trusted_service_path.rb
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.UnquotedService')]
    [CmdletBinding()]
    Param()
    # find all paths to service .exe's that have a space in the path and aren't quoted
    $VulnServices = Get-WmiObject -Class win32_service | Where-Object {
        $_ -and ($Null -ne $_.pathname) -and ($_.pathname.Trim() -ne '') -and (-not $_.pathname.StartsWith("`"")) -and (-not $_.pathname.StartsWith("'")) -and ($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf('.exe') + 4)) -match '.* .*'
    }
    if ($VulnServices) {
        ForEach ($Service in $VulnServices) {
            $SplitPathArray = $Service.pathname.Split(' ')
            $ConcatPathArray = @()
            for ($i=0;$i -lt $SplitPathArray.Count; $i++) {
                        $ConcatPathArray += $SplitPathArray[0..$i] -join ' '
            }
            $ModifiableFiles = $ConcatPathArray | Get-ModifiablePath
            $ModifiableFiles | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
                $CanRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $Service.name
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ServiceName' $Service.name
                $Out | Add-Member Noteproperty 'Path' $Service.pathname
                $Out | Add-Member Noteproperty 'ModifiablePath' $_
                $Out | Add-Member Noteproperty 'StartName' $Service.startname
                $Out | Add-Member Noteproperty 'AbuseFunction' "Write-ServiceBinary -Name '$($Service.name)' -Path <HijackPath>"
                $Out | Add-Member Noteproperty 'CanRestart' ([Bool]$CanRestart)
                $Out | Add-Member Aliasproperty Name ServiceName
                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.UnquotedService')
                $Out
            }
        }
    }
}
function Get-RegistryAlwaysInstallElevated {
    <#
    .SYNOPSIS
    Checks if any of the AlwaysInstallElevated registry keys are set.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    Returns $True if the HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
    or the HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated keys
    are set, $False otherwise. If one of these keys are set, then all .MSI files run with
    elevated permissions, regardless of current user permissions.
    .EXAMPLE
    Get-RegistryAlwaysInstallElevated
    Returns $True if any of the AlwaysInstallElevated registry keys are set.
    .OUTPUTS
    System.Boolean
    $True if RegistryAlwaysInstallElevated is set, $False otherwise.
    #>
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    if (Test-Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer') {
        $HKLMval = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
        Write-Verbose "HKLMval: $($HKLMval.AlwaysInstallElevated)"
        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){
            $HKCUval = (Get-ItemProperty -Path 'HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            Write-Verbose "HKCUval: $($HKCUval.AlwaysInstallElevated)"
            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                Write-Verbose 'AlwaysInstallElevated enabled on this machine!'
                $True
            }
            else{
                Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
                $False
            }
        }
        else{
            Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
            $False
        }
    }
    else{
        Write-Verbose 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer does not exist'
        $False
    }
    $ErrorActionPreference = $OrigError
}
function Get-LocalSecurityProducts {
    <#
    Modified https://github.com/HarmJ0y/WINspect/blob/master/WINspect.ps1
    .SYNOPSIS		
	Gets Windows Firewall Profile status and checks for installed third party security products.		
    .DESCRIPTION
    This function operates by examining registry keys specific to the Windows Firewall and by using the 
    Windows Security Center to get information regarding installed security products.            
    .NOTE
    The documentation in the msdn is not very clear regarding the productState property provided by
    the SecurityCenter2 namespace. For this reason, this function only uses available informations that were obtained by testing 
    different security products againt the Windows API.                    
    .LINK
    http://neophob.com/2010/03/wmi-query-windows-securitycenter2
    #>
    $firewallPolicySubkey="HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
    try{
	    if(Test-Path -Path $($firewallPolicySubkey+"\StandardProfile")){
            $enabled = $(Get-ItemProperty -Path $($firewallPolicySubkey+"\StandardProfile") -Name EnableFirewall).EnableFirewall  
            if($enabled -eq 1){
                $standardProfile="Enabled"
            }
            else{
                $standardProfile="Disabled"
            }
            Write-Output "[*] Standard Profile Firewall : $standardProfile"
        }else{
            Write-Warning  "[-] Could not find Standard Profile Registry Subkey"
	    }    
        if(Test-Path -Path $($firewallPolicySubkey+"\PublicProfile")){
            $enabled = $(Get-ItemProperty -Path $($firewallPolicySubkey+"\PublicProfile") -Name EnableFirewall).EnableFirewall  
            if($enabled -eq 1){
                $publicProfile="Enabled"
            }
            else{
                $publicProfile="Disabled"
            }
            Write-Output "[*] Public Profile Firewall   : $publicProfile"
        }else{
	        Write-Warning "[-] Could not find Public Profile Registry Subkey"
        }
        if(Test-Path -Path $($firewallPolicySubkey+"\DomainProfile")){
            $enabled = (Get-ItemProperty -Path $($firewallPolicySubkey+"\DomainProfile") -Name EnableFirewall).EnableFirewall  
            if($enabled -eq 1){
                $domainProfile="Enabled"
            }else{
                $domainProfile="Disabled"
            }
            Write-Output "[*] Domain Profile Firewall   : $domainProfile"
        }else{       
            Write-Warning "[-] Could not find Private Profile Registry Subkey"
	    }              
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
    	Write-Warning -Message "[-] Error : Could not check Windows Firewall registry informations"	
    }       
    $SecurityProvider=@{         
        "00" = "None";
        "01" = "Firewall";
        "02" = "AutoUpdate_Settings";
        "04" = "AntiVirus";           
        "08" = "AntiSpyware";
        "10" = "Internet_Settings";
        "20" = "User_Account_Control";
        "40" = "Service"
    }
    $RealTimeBehavior = @{                              
        "00" = "Off";
        "01" = "Expired";
        "10" = "ON";
        "11" = "Snoozed"
    }
    $DefinitionStatus = @{
        "00" = "Up-to-date";
        "10" = "Out-of-date"
    }
    $role = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
    if($role -ne 0 -and $role -ne 1){
        return
    }
    if(Get-WmiObject -Namespace root -class __NAMESPACE -filter "name='SecurityCenter2'"){
        $securityCenterNS="root\SecurityCenter2"
    }else{
        $securityCenterNS="root\SecurityCenter"
    }       
    # checks for third party firewall products 
    Write-Output "`n[*] Checking for third party Firewall products" 
    try {  
        $firewalls= @(Get-WmiObject -Namespace $securityCenterNS -class FirewallProduct)
        if($firewalls.Count -eq 0){
	        Write-Output "[-] No other firewall installed"
        }else{
            Write-Output "[+] Found $($firewalls.Count) third party firewall products"
            $firewalls| foreach {
                # The structure of the API is different depending on the version of the SecurityCenter Namespace
                if($securityCenterNS.endswith("2")){
                    [int]$productState=$_.ProductState
            	    $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                    $provider=$hexString.substring(0,2)
                    $realTimeProtec=$hexString.substring(2,2)
                    $definition=$hexString.substring(4,2)
                    "[+] Product Name: $($_.displayName)"
                    "[+] Service Type: $($SecurityProvider[[String]$provider])"
                    "[+] State       : $($RealTimeBehavior[[String]$realTimeProtec])"
                }else{
                    "[+] Company Name: $($_.CompanyName)"
                    "[+] Product Name: $($_.displayName)"
                    "[+] State       : $($_.enabled)"
                }
            }
        }
        # checks for antivirus products
        Write-Output "`n[*] Checking for installed antivirus products" 
        $antivirus=@(Get-WmiObject -Namespace $securityCenterNS -class AntiVirusProduct)
        if($antivirus.Count -eq 0){
            Write-Output "[-] No antivirus product installed"      
        }else{
            Write-Output "[+] Found $($antivirus.Count) AntiVirus solutions"
        	$antivirus| foreach {
                if($securityCenterNS.endswith("2")){
                 	[int]$productState=$_.ProductState
                    $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                    $provider=$hexString.substring(0,2)
                    $realTimeProtec=$hexString.substring(2,2)
                    $definition=$hexString.substring(4,2)
                    "[+] Product Name          :  $($_.displayName)"
                    "[+] Service Type          :  $($SecurityProvider[[String]$provider])"
                    "[+] Real Time Protection  :  $($RealTimeBehavior[[String]$realTimeProtec])"
                    "[+] Signature Definitions :  $($DefinitionStatus[[String]$definition])"
                }else{
                    "[+] Company Name           : $($_.CompanyName)"
                    "[+] Product Name           : $($_.displayName)"
                    "[+] Real Time Protection   : $($_.onAccessScanningEnabled)"
                    "[+] Product up-to-date     : $($_.productUpToDate)"
                }
            }
        }
        # Checks for antispyware products
	    Write-Output "`n[?] Checking for installed antispyware products" 
        $antispyware=@(Get-WmiObject -Namespace $securityCenterNS -class AntiSpywareProduct)
        if($antispyware.Count -eq 0){
            Write-Output "[-] No antiSpyware product installed"     
        }else{
            Write-Output "[+] Found $($antiSpyware.Count) antiSpyware solutions"
            $antispyware| foreach {
		        if($securityCenterNS.endswith("2")){
                    [int]$productState=$_.ProductState
                    $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                    $provider=$hexString.substring(0,2)
                    $realTimeProtec=$hexString.substring(2,2)
                    $definition=$hexString.substring(4,2)
                    Write-Output "[+] Product Name         : $($_.displayName)" 
                    Write-Output "[+] Service Type         : $($SecurityProvider[[String]$provider])" 
                    Write-Output "[+] Real Time Protection : $($RealTimeBehavior[[String]$realTimeProtec])" 
                    Write-Output "[+] Signature Definitions: $($DefinitionStatus[[String]$definition])" 
                }else{
                    Write-Output "[+] Company Name         : $($_.CompanyName)" 
                    Write-Output "[+] Product Name         : $($_.displayName)" 
                    Write-Output "[+] Real Time Protection : $($_.onAccessScanningEnabled)" 
                    Write-Output "[+] Product up-to-date   : $($_.productUpToDate)" 
                }
            }
        }
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
    }
}
function Get-ScheduledTasks {
    <#
    .SYNOPSIS
    Checks for scheduled tasks whose binaries are not in *.system32.*
    .DESCRIPTION
    This function looks for scheduled tasks invoking non-system executables.
    .NOTE
    This functions uses the schtasks.exe utility to get informations about
    scheduled task and then tries to parse the results. Here I choose to parse XML output from the command.
    Another approach would be using the ScheduledTask Powershell module that was introduced starting from version 3.0 .
    #>
    $tasks = New-Object System.Collections.ArrayList
    [xml]$tasksXMLobj = $(schtasks.exe /query /xml ONE)
    $tasksXMLobj.Tasks.Task | foreach {
        $taskCommandPath = [System.Environment]::ExpandEnvironmentVariables($_.actions.exec.command).trim()
        if(($taskCommandPath) -and ($taskCommandPath -notmatch ".*system32.*")){
            if($_.Principals.Principal.UserID){
                $sid = New-Object System.Security.Principal.SecurityIdentifier($_.Principals.Principal.UserID)
                $taskSecurityContext = $sid.Translate([System.Security.Principal.NTAccount])
            }elseif($_.Principals.Principal.GroupId){
                $sid = New-Object System.Security.Principal.SecurityIdentifier($_.Principals.Principal.GroupId)
                $taskSecurityContext = $sid.Translate([System.Security.Principal.NTAccount])
            }else{
                $taskSecurityContext = 'Error translating sid'
            }
            $task = New-Object psobject -Property @{
                TaskCommand = $taskCommandPath
                SecurityContext  = $taskSecurityContext
            }
            $tasks.add($task) | Out-Null
        }
    }
    if($null -eq $task){
        Write-Output "[+] No suspicious scheduled tasks were found"
    }else{
        Write-Output $tasks | Format-List taskCommand,SecurityContext
    }
}
function Get-HostedServices {
    <#
    .SYNOPSIS
    Checks hosted services running DLLs not located in the system32 subtree.
    .DESCRIPTION
    This functions tries to identify whether there are any configured hosted 
    services based on DLLs not in system32.  
    .RETURNS
    When invoked without the $display switch, returns 
    PSobject array containing the service name, service groupname 
    and the service DLL path. 
    #>
    $srvcs = New-Object System.Collections.ArrayList
    try{   
        $services = Get-WmiObject -Class Win32_service | where { $_.pathname -match "svchost\.exe" -and $(Test-Path $("HKLM:\SYSTEM\CurrentControlSet\Services\"+$_.Name+"\Parameters")) -eq $true}
        if($services){
            foreach($service in $services){
                $serviceName  = $service.Name 
                $serviceGroup = $service.pathname.split(" ")[2]
                $serviceDLLPath=$(Get-ItemProperty $("HKLM:\SYSTEM\CurrentControlSet\Services\"+$service.Name+"\Parameters") -Name ServiceDLL).ServiceDLL
                if(($serviceDLLPath) -and ($serviceDLLPath -notmatch ".*system32.*")){ 
                    $srvc = New-Object psobject -Property @{
                        serviceName    = $serviceName
                        serviceGroup   = $serviceGroup
                        serviceDLLPath = $serviceDLLPath
                    }
                    $srvcs.add($srvc)  | Out-Null
                }
            }
        }
    }catch{
       Write-Output "[-] $($_.Exception.Message)"        
    }
    if($srvcs.count -eq 0){
        Write-Output "[+] Found no user hosted services"
    }else{
        Write-Output $srvcs | Format-List serviceName,serviceGroup,serviceDLLPath
    }
}
function Invoke-WinEnum{
    Write-Output "[*] ComputerName $env:COMPUTERNAME"
    Write-Output "[*] User $env:USERNAME"
    Write-Output "[*] UserDomain $env:USERDOMAIN"

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-RegistryAutoLogon/
    Write-Output "`n[*] Checking AutoLogon"
    try{
        $autologon = Get-RegistryAutoLogon
        if($autologon){
            Write-Output "[-] AutoLogon Credentials Found"
            $autologon
        }else{
            Write-Output "[+] No AutoLogon Credentials Found"
        }
    }catch{
        Write-Output "[-] AutoLogon Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-CachedGPPPassword/
    Write-Output "`n[*] Checking CachedGPPPassword"
    try{
        $CachedGPPPassword = Get-CachedGPPPassword
        if($CachedGPPPassword){
            Write-Output "[-] CachedGPPPassword Found"
            $CachedGPPPassword
        }else{
            Write-Output "[+] No CachedGPPPassword Found"
        }
    }catch{
        Write-Output "[-] CachedGPPPassword Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-UnattendedInstallFile/
    Write-Output "`n[*] Checking UnattendedInstallFiles"
    try{
        $UnattendedInstallFile = Get-UnattendedInstallFile
        if($UnattendedInstallFile){
            Write-Output "[-] UnattendedInstallFiles Found"
            $UnattendedInstallFile
        }else{
            Write-Output "[+] No UnattendedInstallFiles Found"
        }
    }catch{
        Write-Output "[-] UnattendedInstallFiles Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-UnquotedService/
    Write-Output "`n[*] Checking Unquoted Services"
    try{
        $UnquotedService = Get-UnquotedService
        if($UnquotedService){
            Write-Output "[-] Unquoted Services Found"
            $UnquotedService
        }else{
            Write-Output "[+] No Unquoted Services Found"
        }
    }catch{
        Write-Output "[-] Unquoted Services Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-RegistryAlwaysInstallElevated/
    Write-Output "`n[*] Checking AlwaysInstallElevated"
    try{
        $UnquotedService = Get-RegistryAlwaysInstallElevated
        if($UnquotedService){
            Write-Output "[-] AlwaysInstallElevated Found"
            $UnquotedService
        }else{
            Write-Output "[+] No AlwaysInstallElevated Found"
        }
    }catch{
        Write-Output "[-] AlwaysInstallElevated Failed"
    }

    #
    Write-Output "`n[*] Checking Local Security Products"
    try{
        Get-LocalSecurityProducts
    }catch{
        Write-Output "[-] Local Security Products Failed"
    }

    #
    Write-Output "`n[*] Checking for UAC Configuration"
    try{
        Get-UACLevel
    }catch{
        Write-Output "[-] Checking for UAC Configuration Failed"
    }

    #
    Write-Output "`n[*] Checking for Local Shares"
    try{
        Get-LocalShares
    }catch{
        Write-Output "[-] Checking for Local Shares Failed"
    }

    #
    Write-Output "`n[*] Checking for ScheduledTasks Not Located in System32"
    try{
        Get-ScheduledTasks
    }catch{
        Write-Output "[-] Checking for ScheduledTasks Failed"
    }

    #
    Write-Output "`n[*] Checking Services for DLLs Not Located in System32"
    try{
        Get-HostedServices
    }catch{
        Write-Output "[-] Checking for Services for DLLs Not Located in System32 Failed"
    }

    #
    Write-Output "`n[*] Checking ACL's on Services Not Located in System32"
    try{
        Get-BinaryWritableServices
    }catch{
        "[-] Checking ACL's on Services Not Located in System32 Failed"
    }
}
#Invoke-WinEnum