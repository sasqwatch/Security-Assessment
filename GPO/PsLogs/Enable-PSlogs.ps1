function Enable-PSlogs{
<#   
.SYNOPSIS   
-----------
Enable PowerShell Logging
    
.DESCRIPTION 
-----------
Enable PowerShell Logging
    
.PARAMETER Name
Name of the new GPO

.PARAMETER OU
Name of the OU that will be linked to the new GPO

.PARAMETER Transcripting
Switch param if you want to enable transcripting logging and write logs to disk

.NOTES   
Name:        Enable-PSlogs
Author:      Cube0x0
Blog:        https://github.com/cube0x0

.EXAMPLE
PowerShell.exe -Command '& {. .\Enable-PSlogs.ps1; Enable-PSlogs -Name "Enable-PSlogs" -OU "ou=machines,dc=contoso,dc=com"}'

Description
-----------
Enable PowerShell Logging
#>
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,
    
        [Parameter(Mandatory=$true)]
        [string]
        $OU,

        [switch]
        $Transcripting
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
    
    #Script block logging 
    Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -Type DWord  -ValueName 'EnableScriptBlockLogging' -Value 1 | out-null
    #disabled to save disk space
	#Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    #-Type DWord  -ValueName 'EnableScriptBlockInvocationLogging' -Value 1 | out-null

    #Module logging
    Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
    -Type DWord  -ValueName 'EnableModuleLogging' -Value 1 | out-null
    Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
    -Type String  -ValueName '*' -Value '*' | out-null

    #Transcripting
    if ($Transcripting){
        $path = Read-Host "Directory for Transcripting"
        if (!(Test-Path $path)){
            Write-Warning "Could not connect to transcript folder"
            return
        }
        Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription' `
        -Type DWord  -ValueName 'EnableTranscripting' -Value 1 | out-null
        #disabled to save disk space
		#Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription' `
        #-Type DWord  -ValueName 'EnableInvocationHeader' -Value 1 | out-null
        Set-GPRegistryValue -Name $name -Key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription' `
        -Type String  -ValueName 'OutputDirectory' -Value $path | out-null
    }

}
