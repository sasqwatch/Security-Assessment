<#
Test-Domain.ps1 - PowerShell script for checking basic settings for Active Directory Security
Domain version of https://github.com/cutaway/chaps/
#>
########## Output Header Write-Host Functions ##############
# Postive Outcomes - configurations / settings that are, at a minimum, expected.
Function Write-Pos{
    Write-Host "[+] " -ForegroundColor Green -NoNewline;
}
# Negative Outcomes - configurations / settings that are not expected, dangerous, or unnecessarily increase risk.
Function Write-Neg{
    Write-Host "[-] " -ForegroundColor Red -NoNewline;
}
# Information Statements - general statements about the system or a test.
Function Write-Info{
    Write-Host "[*] " -ForegroundColor Blue -NoNewline;
}
# Reporting Marks - markers that can be used to automate reporting.
Function Write-Rep{
    Write-Host "[$] " -ForegroundColor Magenta -NoNewline;
}
# Error Outcomes - tests that resulted in errors. Could be, but are not necessarily,  a finding. Each should be manually reviewed.
Function Write-Err{
    Write-Host "[x] " -ForegroundColor Yellow -NoNewline;
}

function Invoke-Domain{
    param (
        [string]$DomainController,
        [string]$Domain,
        [string]$DistinguishedName
    )

    ############## Set variables ##############
    if(!$DomainController -or !$Domain){
        try{
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }catch{
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "DC=$($Domain.replace(".", ",DC="))"
        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }else{
        $distinguished_name = $DistinguishedName
    }

    try{
        $adsi = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$distinguished_name"
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }
    try{
        . $PSScriptRoot\ASBBypass.ps1
        . $PSScriptRoot\PowerView.ps1
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }

    #Check Domain Trust https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
    Write-Info; Write-Host "Looking for Domain Trust"
    $trust=Get-DomainTrust
    foreach($DomainTrust in $trust){
        if($DomainTrust.TrustAttributes -contains 'WITHIN_FOREST'){
            Write-Neg; Write-Host "Possible Parent-Child Trust Found"
            Write-Output $DomainTrust
        }else{
            Write-Info; Write-Host "Trust Found"
            Write-Output $DomainTrust
         }
    }
    Write-Info; Write-Host "Looking for Forest Trust"
    Get-ForestTrust

    #Creds in SYSVOL
    Write-Info; Write-Host "Looking for Cpassword in Sysvol"
    $xmls=Get-ChildItem -r \\$domain\sysvol\$domain\policies\ -Include *.xml
    foreach($path in $xmls){
        [xml]$Xml = Get-Content ($Path.fullname)
        if($Xml.Groups.User.Properties.cpassword){
            Write-Neg; Write-Host "Credentials found:" $Path.fullname
            $creds = $true
        }
    }
    if(-not $creds){
        Write-Pos; Write-Host "No passwords found in Sysvol"  
    }

    #Active Directory Integrated DNS Wilcard Record https://blog.netspi.com/exploiting-adidns/
    Write-Info; Write-Host "Testing Active Directory Integrated DNS Wilcard Record"
    try{
        $zones=(Get-DomainDNSZone).ZoneName | where {$_ -notlike 'RootDNSServers'}
    }catch{
        Write-Err; Write-Host "Testing for Active Directory Integrated DNS Wilcard Record failed."
    }
    foreach($zone in $zones){
        $records=(Get-DomainDNSRecord -ZoneName $zone).name
        $wildcard = $false
        foreach($record in $records){
            if($record -contains '*'){
                Write-Pos; Write-Host "Wildcard record exists for zone $zone"
                $wildcard = $true
                break
            }
        }
        if(-not $wildcard){
        Write-Neg; Write-Host "Wildcard record does not exists for zone $zone"
        }
    }
    
    #Machine Account Quota https://blog.netspi.com/machineaccountquota-is-useful-sometimes/
    Write-Info; Write-Host "Testing ms-DS-MachineAccountQuota"
    Try{
        $maq = $adsi.Properties.'ms-DS-MachineAccountQuota'
    }
    Catch{
        Write-Err; Write-Host "Testing for ms-DS-MachineAccountQuota failed."
    }
    if($maq -eq '0') { 
        Write-Pos; Write-Host "Users are not allowed to add computer objects to the domain"
    }else{ 
        Write-Neg; Write-Host "ms-DS-MachineAccountQuota is:" $maq 
    }

    #Default Domain Policy
    Write-Info; Write-Host "Testing Default Domain Policy"
    $password_policy = (Get-DomainPolicy).SystemAccess
    if([int]($password_policy).ClearTextPassword -eq 0){
        Write-Pos; Write-Host "Reversible Encryption Disabled"
    }else{
        Write-Neg; Write-Host "Reversible Encryption Enabled"
    }
    if([int]($password_policy).PasswordComplexity -eq 1){
        Write-Pos; Write-Host "Password Complexity Enabled"
    }else{
        Write-Neg; Write-Host "Password Complexity Enabled Disabled"
    }
    if([int]($password_policy).MinimumPasswordLength -ge 12){
        Write-Pos; Write-Host "Minimum Password Length:" ($password_policy).MinimumPasswordLength 
    }else{
        Write-Neg; Write-Host "Minimum Password Length: " ($password_policy).MinimumPasswordLength
    }
    if([int]($password_policy).LockoutBadCount -eq 0){
        Write-Neg; Write-Host "Login tries before lockout is unlimimted"
    }else{
        Write-Pos; Write-Host "Login tries before lockout set to: " ($password_policy).LockoutBadCount
    }
    $regv=(Get-DomainPolicy).RegistryValues
    $NoLMHash=$regv.'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'
    if($NoLMHash -notcontains '0'){
        Write-Pos; Write-Host "NoLMHash is enabled"
    }else{
        Write-Neg; Write-Host "NoLMHash is disabled"
   }
}
#Invoke-Domain -DomainController 192.168.3.10 -Domain hackme.local