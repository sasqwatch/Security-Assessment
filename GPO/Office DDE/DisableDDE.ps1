function Disable-DDE{
    <#   
.SYNOPSIS   
Function to disable DDEAUTO for Outlook, Word, OneNote, and Excel versions 2010, 2013, 2016 
    
.DESCRIPTION 
Disable DDEAUTO for Outlook, Word, OneNote, and Excel versions 2010, 2013, 2016 
    
.PARAMETER Name
Name of the new GPO

.PARAMETER OU
Name of the OU that will be linked to the new GPO

.NOTES   
Name:        DisableDDE
Author:      Cube0x0
Blog:        https://github.com/cube0x0

.EXAMPLE
PowerShell.exe -Command '& {. .\DisableDDE.ps1; DisableDDE -Name "DisableDDE" -OU "ou=users,dc=contoso,dc=com"}'

Description
-----------
Disable DDEAUTO for Outlook, Word, OneNote, and Excel versions 2010, 2013, 2016 
#>
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,
    
        [Parameter(Mandatory=$true)]
        [string]
        $OU
    )
    if(get-module grouppolicy -ListAvailable){
        import-module grouppolicy
    }else{
        write-warning "Could not import grouppolicy module"
        return
    }
    
    #create new GPO and assign in to a OU
    try{
        new-gpo -name $Name | new-gplink -target $OU
    }catch{
        write-warning "Could not create new gpo and link it to $($OU)"
        return
    }
    
    #set the registry keys in the Preferences section of the new GPO
    #Word
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Options' `
    -Type DWord  -ValueName 'DontUpdateLinks' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Word\Options' `
    -Type DWord  -ValueName 'DontUpdateLinks' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Word\Options' `
    -Type DWord  -ValueName 'DontUpdateLinks' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Options\WordMail' `
    -Type DWord  -ValueName 'DontUpdateLinks' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Word\Options\WordMail' `
    -Type DWord  -ValueName 'DontUpdateLinks' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Word\Options\WordMail' `
    -Type DWord  -ValueName 'DontUpdateLinks' -Value 00000001 | out-null
    
    #OneNote
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\OneNote\Options' `
    -Type DWord  -ValueName 'DisableEmbeddedFiles' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\OneNote\Options' `
    -Type DWord  -ValueName 'DisableEmbeddedFiles' -Value 00000001 | out-null
    
    #Excel
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Options' `
    -Type DWord  -ValueName 'DontUpdateLinks' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Options' `
    -Type DWord  -ValueName 'DDEAllowed' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Options' `
    -Type DWord  -ValueName 'DDECleaned' -Value 00000001 | out-null
    
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Excel\Options' `
    -Type DWord  -ValueName 'DontUpdateLinks' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Excel\Options' `
    -Type DWord  -ValueName 'DDEAllowed' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Excel\Options' `
    -Type DWord  -ValueName 'DDECleaned' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Excel\Options' `
    -Type DWord  -ValueName 'Options' -Value 00000117 | out-null
    
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Excel\Options' `
    -Type DWord  -ValueName 'DontUpdateLinks' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Excel\Options' `
    -Type DWord  -ValueName 'DDEAllowed' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Excel\Options' `
    -Type DWord  -ValueName 'DDECleaned' -Value 00000001 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Excel\Options' `
    -Type DWord  -ValueName 'Options' -Value 00000117 | out-null
}
