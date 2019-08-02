function Get-FirewallStatus {
    #https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1
    $regkey = "HKLM:\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
    $output = New-Object -TypeName PSobject -Property @{
        Standard    = If ((Get-ItemProperty $regkey\StandardProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
        Domain      = If ((Get-ItemProperty $regkey\DomainProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
        Public      = If ((Get-ItemProperty $regkey\PublicProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
    }
    Write-Output $output
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
function Invoke-WinEnum{
    Write-Output "[*] ComputerName $env:COMPUTERNAME"
    Write-Output "[*] User $env:USERNAME"
    Write-Output "[*] UserDomain $env:USERDOMAIN"

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-RegistryAutoLogon/
    Write-Output "`n[*] Checking AutoLogon"
    try{
        $autologon=Get-RegistryAutoLogon
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
        $CachedGPPPassword=Get-CachedGPPPassword
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
        $UnattendedInstallFile=Get-UnattendedInstallFile
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
        $UnquotedService=Get-UnquotedService
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
        $UnquotedService=Get-RegistryAlwaysInstallElevated
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
    Write-Output "`n[*] Checking Firewall Status"
    try{
        Get-FirewallStatus
    }catch{
        Write-Output "[-] Firewall status Failed"
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
}
Invoke-WinEnum