#Multi Threading :D
#linux.csv
    #ComputerName Username Password
    #------------ -------- --------
    #192.168.1.40 cube     cube
#Generates LinEnum reports for multiple hosts
#Install-Module -Name Posh-SSH -Force
#Install-Module -Name PoshRSJob -Force
function Invoke-Linux{
    param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        $Computers = '.\linux.csv',
        [ValidateScript({Test-Path -Path $_ })]
        [string]$ScriptPath
    )
    #Import ComputerName, Username, Passwords from CSV
    if(Test-Path $Computers){
        $Computers = import-csv $Computers -ErrorAction Stop
    }
    #Import dependencies
    try{
        Import-Module PoshRSJob -ErrorAction Stop
        Import-Module Posh-SSH -ErrorAction Stop
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }
    #Create output folder
    $OutputFolder = "$((Get-Location).path)\linux"
    if(-not(Test-Path $OutputFolder)){
        New-Item -ItemType Directory -Name 'linux' -Path "." | Out-Null
    }
    #Get latest LinEnum.sh
    #Use a local copy for extended testing
    if($ScriptPath){
        $Script = Get-Content $ScriptPath -ErrorAction Stop
    }else{
        try{
            $Script = (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh')
        }catch{
            Write-Output "[-] Can't Download LinEnum"
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
    }
    #Params
    $ScriptParams = @{
        'Script' = $Script
        'Location' = $OutputFolder
    }
    #One thread for every computer :D
    Get-RSJob | where {$_.state -like 'Completed'} | Remove-RSJob 
    $Computers | start-rsjob -Name {$_.computername} -ArgumentList $ScriptParams -ModulesToImport 'Posh-SSH' -ScriptBlock {
            param($Inputargs)
            $Script = $Inputargs.Script
            $Location = $Inputargs.Location
            $secpasswd = ConvertTo-SecureString $_.password -AsPlainText -Force
            $creds = New-Object System.Management.Automation.PSCredential ($_.username, $secpasswd)
            try{
                $session = New-SSHSession -ComputerName $_.ComputerName -Credential $creds -Force -WarningAction SilentlyContinue
            }catch{
                Add-Content -Path "$Location\$($_.ComputerName)" -Value '[-] Error connecting to host'
            }
            if($session){
                $output = (Invoke-SSHCommand -SSHSession $session -Command "$script | /bin/bash")
                Add-Content -Path "$Location\$($_.ComputerName)" -Value $output.output
                Remove-SSHSession -SSHSession $session | Out-Null
            }
        } | Wait-RSJob -ShowProgress
        $errors=Get-RSJob | where {$_.HasErrors -eq $true}
        if($errors){
            Write-Output "[-] Failed connecting to following hosts"
            Write-Output $errors
        }
}
#Invoke-Linux
