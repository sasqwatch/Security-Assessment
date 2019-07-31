function Enable-Laps{
<#   
.SYNOPSIS   
-----------
Enable Laps
    
.DESCRIPTION 
-----------
Enable Laps
    
.PARAMETER Name
Name of the new GPO

.PARAMETER OU
Name of the OU that will be linked to the new GPO

.NOTES   
Name:        Enable-Laps
Author:      Cube0x0
Blog:        https://github.com/cube0x0
.EXAMPLE
PowerShell.exe -Command '& {. .\enable-laps.ps1; enable-laps -Name "Enable-laps" -OU "dc=contoso,dc=com"}'
Description
-----------
Enable Laps
#>
param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$false)]
        [string]
        $OU = (Get-ADDomain).distinguishedname

)
    #Copy laps module
    copy-item -path ($PSScriptRoot + "\admpwd.ps") -destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"

    #copy Gpo template to policy definitions
    copy-item -path ($scriptpath + "\AdmPwd.admx") -destination "C:\Windows\PolicyDefinitions"
    copy-item -path ($scriptpath + "\AdmPwd.adml") -destination "C:\Windows\PolicyDefinitions\en-US"
    
    #load modules and configure LAPS
    regsvr32 schmmgmt.dll
    Import-Module ADMPwd.ps
    Update-AdmPwdADSchema
    Set-AdmPwdComputerSelfPermission -OrgUnit $ou

    #Create LAPS GPO
    try{
        new-gpo -name $Name | new-gplink -target $OU
    }catch{
        write-warning "Could not create new gpo and link it to $($OU)"
        return
    }
    Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd' `
    -Type DWord -ValueName 'PasswordLength' -Value 32 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd' `
    -Type DWord -ValueName 'PwdExpirationProtectionEnabled' -Value 1 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd' `
    -Type DWord -ValueName 'PasswordComplexity' -Value 4 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd' `
    -Type DWord -ValueName 'PasswordAgeDays' -Value 30 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd' `
    -Type DWord -ValueName 'AdmPwdEnabled' -Value 1 | out-null

    #
    Write-Output "Please deploy $($PSScriptRoot)\LAPS.x64 to clients"
    Write-Output "Set read password permission with 
Set-AdmPwdReadPasswordPermission -OrgUnit '$($ou)' -AllowedPrincipals '<user/group/computer>'"
}