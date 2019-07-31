<#
Test-Domain.ps1 - PowerShell script for checking basic settings for Active Directory Security
Domain version of https://github.com/cutaway/chaps/
#>

param (
    [string]$DomainController,
    [string]$domain,
    [string]$DistinguishedName
)

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
############## functions ##############
function Get-IniContent
{  
    param(  
        [parameter(Mandatory = $true)] [string] $filePath  
    )  

    $anonymous = "NoSection"

    $ini = @{}  
    switch -regex -file $filePath  
    {  
        "^\[(.+)\]$" # Section  
        {  
            $section = $matches[1]  
            $ini[$section] = @{}  
            $CommentCount = 0  
        }  

        "^(;.*)$" # Comment  
        {  
            if (!($section))  
            {  
                $section = $anonymous  
                $ini[$section] = @{}  
            }  
            $value = $matches[1]  
            $CommentCount = $CommentCount + 1  
            $name = "Comment" + $CommentCount  
            $ini[$section][$name] = $value  
        }   

        "(.+?)\s*=\s*(.*)" # Key  
        {  
            if (!($section))  
            {  
                $section = $anonymous  
                $ini[$section] = @{}  
            }  
            $name,$value = $matches[1..2]  
            $ini[$section][$name] = $value  
        }  
    }  

    return $ini  
}  

############## Set variables ##############
if(!$DomainController -or !$Domain)
{

    try
    {
        $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
        throw
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
    $dns = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/DC=$domain,CN=MicrosoftDNS,DC=DomainDnsZones,$distinguished_name"
    $trust = New-Object System.DirectoryServices.DirectorySearcher('DC=hackme,DC=local')
}catch{
    Write-Output "[-] $($_.Exception.Message)"
    throw
}

#Check Parent-Child Trust https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
Write-Info; Write-Host "Looking for trust"
$TrustAttributes = @{
    [uint32]'0x00000001' = 'NON_TRANSITIVE'
    [uint32]'0x00000002' = 'UPLEVEL_ONLY'
    [uint32]'0x00000004' = 'FILTER_SIDS'
    [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
    [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
    [uint32]'0x00000020' = 'WITHIN_FOREST'
    [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
    [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
    [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
    [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
    [uint32]'0x00000400' = 'PIM_TRUST'
}
$trust.Filter = '(objectClass=trustedDomain)'
$results = $trust.FindAll()
$results | Where-Object {$_} | ForEach-Object {
    $SourceDomain = $Env:USERDNSDOMAIN
    $Props = $_.Properties
    $TrustAttrib = @()
    $TrustAttrib += $TrustAttributes.Keys | Where-Object { $Props.trustattributes[0] -band $_ } | ForEach-Object { $TrustAttributes[$_] }

    $Direction = Switch ($Props.trustdirection) {
    0 { 'Disabled' }
    1 { 'Inbound' }
    2 { 'Outbound' }
    3 { 'Bidirectional' }
    }

    $TrustType = Switch ($Props.trusttype) {
    1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
    2 { 'WINDOWS_ACTIVE_DIRECTORY' }
    3 { 'MIT' }
    }

    $DomainTrust = New-Object PSObject
    $DomainTrust | Add-Member Noteproperty 'SourceName' $SourceDomain
    $DomainTrust | Add-Member Noteproperty 'TargetName' $Props.name[0]
    $DomainTrust | Add-Member Noteproperty 'TrustType' $TrustType
    $DomainTrust | Add-Member Noteproperty 'TrustAttributes' $($TrustAttrib -join ',')
    $DomainTrust | Add-Member Noteproperty 'TrustDirection' "$Direction"
    $DomainTrust | Add-Member Noteproperty 'WhenCreated' $Props.whencreated[0]
    $DomainTrust | Add-Member Noteproperty 'WhenChanged' $Props.whenchanged[0]
    if($DomainTrust.TrustAttributes -contains 'WITHIN_FOREST'){
        Write-Neg; Write-Host "Possible Parent-Child Trust Found" -NoNewline
        Write-Output $DomainTrust
    }else{
        Write-Info; Write-Host "Trust Found" -NoNewline
        Write-Output $DomainTrust
    }
}

#Creds in SYSVOL
Write-Info; Write-Host "Looking for Cpassword in Sysvol"
try{
    $xmls=Get-ChildItem -r \\$domain\sysvol\$domain\policies\ -Include *.xml
}catch{
    Write-Err; Write-Host "Testing for Cpassword in Sysvol failed."
}
$creds = $false
foreach($path in $xmls){
    [xml]$Xml = Get-Content ($Path.fullname)
    if($Xml.Groups.User.Properties.cpassword){
        Write-Neg; Write-Host "Credentials found:" $Path.fullname
        $creds = $true
    }
}
if($creds -eq $false){
    Write-Pos; Write-Host "No passwords found in Sysvol"  
}

#Active Directory Integrated DNS Wilcard Record https://blog.netspi.com/exploiting-adidns/
Write-Info; Write-Host "Testing Active Directory Integrated DNS Wilcard Record"
try{
    $records = ($dns.Children).distinguishedName
}catch{
    Write-Err; Write-Host "Testing for Active Directory Integrated DNS Wilcard Record failed."
}
$wildcard = $false
foreach($record in $records){
    if("DC=*,$($dns.distinguishedName)" -contains $record){
        $wildcard = $true
        break
    }
}
if($wildcard){
    Write-Pos; Write-Host "Wildcard record exists"
}else{
    Write-Neg; Write-Host "Wildcard record does not exists"
}

#Machine Account Quota https://blog.netspi.com/machineaccountquota-is-useful-sometimes/
Write-Info; Write-Host "Testing ms-DS-MachineAccountQuota"
Try{
    $maq = $adsi.Properties.'ms-DS-MachineAccountQuota'
    if($maq -eq '0') { 
        Write-Pos; Write-Host "Users are not allowed to add computer objects to the domain"
    }else{ 
        Write-Neg; Write-Host "ms-DS-MachineAccountQuota is:" $maq 
    }
}
Catch{
    Write-Err; Write-Host "Testing for ms-DS-MachineAccountQuota failed."
}

#Default Domain Policy
Write-Info; Write-Host "Testing Default Domain Policy"
$GPO = "\\$domain\sysvol\$domain\policies\{31B2F340-016D-11D2-945F-00C04FB984F9}"
$GptTmplPath = $GPO + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
$password_policy = (Get-IniContent $GptTmplPath).'System Access'
#Write-Info; Write-Host "Domain Password Policy"
#Write-Output $password_policy
#Write-Info; Write-Host "Domain Kerberos Policy"
#Write-Output (Get-IniContent $GptTmplPath).'Kerberos Policy'
#Write-Info; Write-Host "Domain Registry Values" -NoNewline
#Write-Output (Get-IniContent $GptTmplPath).'Registry Values' | Format-Table key,value
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
    Write-Pos; Write-Host "Minimum Password Length is: " ($password_policy).MinimumPasswordLength 
}else{
    Write-Neg; Write-Host "Minimum Password Length is: " ($password_policy).MinimumPasswordLength
}
if([int]($password_policy).LockoutBadCount -eq 0){
    Write-Neg; Write-Host "Login tries before lockout is unlimimted "
}else{
    Write-Pos; Write-Host "Login tries before lockout set to: " ($password_policy).LockoutBadCount
}
$regv=(Get-IniContent $GptTmplPath).'Registry Values'
$NoLMHash=$regv.Item('MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash')
if($NoLMHash -contains '0'){
    Write-Neg; Write-Host "NoLMHash is disabled"
}else{
    Write-Pos; Write-Host "NoLMHash is enabled"
}