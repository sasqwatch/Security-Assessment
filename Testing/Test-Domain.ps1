function Invoke-Domain{
    param (
        [string]$DomainController,
        [string]$Domain,
        [string]$DistinguishedName
    )

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
        . $PSScriptRoot\GroupPolicyAutologon.ps1
        . $PSScriptRoot\GPPPassword.ps1
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }

    #Check Trust https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
    Write-Host "`n[*] Looking for Domain Trust"
    $trust=Get-DomainTrust -Domain $Domain -DomainController $DomainController
    foreach($DomainTrust in $trust){
        if($DomainTrust.TrustAttributes -contains 'WITHIN_FOREST'){
            Write-Host "[-] Possible Parent-Child Trust Found" -ForegroundColor Red
            Write-Output $DomainTrust
        }else{
            Write-Host "`n[*] Trust Found"
            Write-Output $DomainTrust
         }
    }
    Write-Host "`n[*] Looking for Forest Trust"
    try{
        Get-ForestTrust
    }catch{
        Write-Host "[-] Forest Trust Enumeration Failed" -ForegroundColor Red
    }

    #Creds in SYSVOL
    Write-Host "`n[*] Looking for Passwords in Sysvol"
    try{
        $GPOpass=Get-GroupPolicyAutologon
        if($GPOpass){
            Write-Host "[-] GPOPassword Found in Sysvol" -ForegroundColor Red
            Write-Output $GPOpass
        }
    }catch{
        Write-Host "[-] Testing GPOPassword in Sysvol Failed" -ForegroundColor Red
    }
    if(Test-Path \\$domain\sysvol\$domain\policies\){
        $xmls=Get-ChildItem -r \\$domain\sysvol\$domain\policies\ -Include *.xml
        foreach($path in $xmls){
            [xml]$Xml = Get-Content ($Path.fullname)
            if($Xml.Groups.User.Properties.cpassword){
                Write-Host "[-] Credentials found: $($Path.fullname)" -ForegroundColor Red
            }
        }
    }else{
        Write-Host "[-] Testing CPassword in Sysvol Failed" -ForegroundColor Red
    }
    
    #Active Directory Integrated DNS Wilcard Record https://blog.netspi.com/exploiting-adidns/
    Write-Host "`n[*] Testing Active Directory Integrated DNS Wilcard Record"
    try{
        $zones=(Get-DomainDNSZone -Domain $Domain -DomainController $DomainController).ZoneName | where {$_ -notlike 'RootDNSServers'}
    }catch{
        Write-Host "[-] Testing for Active Directory Integrated DNS Wilcard Record Failed" -ForegroundColor Red
    }
    foreach($zone in $zones){
        $records=(Get-DomainDNSRecord -ZoneName $zone -Domain $Domain -DomainController $DomainController).name
        $wildcard = $false
        foreach($record in $records){
            if($record -contains '*'){
                Write-Host "[+] Wildcard record exists for zone $zone" -ForegroundColor Green
                $wildcard = $true
                break
            }
        }
        if(-not $wildcard){
        Write-Host "[-] Wildcard record does not exists for zone $zone" -ForegroundColor Red
        }
    }
    
    #Machine Account Quota https://blog.netspi.com/machineaccountquota-is-useful-sometimes/
    Write-Host "`n[*] Testing ms-DS-MachineAccountQuota"
    Try{
        $maq = $adsi.Properties.'ms-DS-MachineAccountQuota'
        if($maq -eq '0') { 
            Write-Host "[+] Users are not allowed to add computer objects to the domain" -ForegroundColor Green
        }else{ 
            Write-Host "[-] ms-DS-MachineAccountQuota is: $maq" -ForegroundColor Red
        }
    }
    Catch{
        Write-Host "[-] Testing for ms-DS-MachineAccountQuota failed." -ForegroundColor Red
    }

    #Domain Password Policy
    Write-Host "`n[*] Testing Domain Password Policy"
    try{
        $password_policy = (Get-DomainPolicy -Domain $Domain -DomainController $DomainController).SystemAccess
        $regv=(Get-DomainPolicy -Domain $Domain -DomainController $DomainController).RegistryValues
    }catch{
        Write-Host "[-] Testing for Domain Password Policy Failed." -ForegroundColor Red
    }
    if($password_policy -and $regv){
        if([int]($password_policy).ClearTextPassword -eq 0){
            Write-Host "[+] Reversible Encryption Disabled" -ForegroundColor Green
        }else{
            Write-Host "[-] Reversible Encryption Enabled" -ForegroundColor Red
        }
        if([int]($password_policy).PasswordComplexity -eq 1){
            Write-Host "[+] Password Complexity Enabled" -ForegroundColor Green
        }else{
            Write-Host "[-] Password Complexity Enabled Disabled" -ForegroundColor Red
        }
        if([int]($password_policy).MinimumPasswordLength -ge 12){
            Write-Host "[+] Minimum Password Length: $($password_policy.MinimumPasswordLength)" -ForegroundColor Green
        }else{
            Write-Host "[-] Minimum Password Length: $($password_policy.MinimumPasswordLength)" -ForegroundColor Red
        }
        if([int]($password_policy).LockoutBadCount -eq 0){
            Write-Host "[-] Login tries before lockout is unlimimted" -ForegroundColor Red
        }else{
            Write-Host "[+] Login tries before lockout set to: $($password_policy.LockoutBadCount)" -ForegroundColor Green
        }
        $NoLMHash=$regv.'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'
        if($NoLMHash -notcontains '0'){
             Write-Host "[+] NoLMHash is enabled" -ForegroundColor Green
        }else{
            Write-Host "[-] NoLMHash is disabled" -ForegroundColor Red
        }
    }
   Stop-Transcript
}
#Invoke-Domain -DomainController 192.168.3.10 -Domain hackme.local