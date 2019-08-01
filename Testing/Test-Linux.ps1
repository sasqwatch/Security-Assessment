#Multi Threading Coming Soon
#linux.csv
    #ComputerName Username Password
    #------------ -------- --------
    #192.168.1.40 cube     cube
function Invoke-Linux {
    param (
        [string]$Csv = '.\linux.csv',
        [string]$LinEnumPath
    )
    #Generates LinEnum reports for multiple hosts
    #Install-Module -Name Posh-SSH -Force

    #Create folder
    if(-not(Test-Path "$((Get-Location).path)\linux")){
        New-Item -ItemType Directory -Name 'linux' -Path (Get-Location).path | Out-Null
    }
    #Get latest LinEnum.sh
    #Use a local copy for extended testing
    if($LinEnumPath){
        try{
            $LinEnum = Get-Content $LinEnumPath -ErrorAction Stop
        }catch{
            Write-Host '[-]Bad LinEnumPath'
            return
        }
    }else{
        try{
            $LinEnum = (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh')
        }catch{
            Write-Host "[-]Can't Download LinEnum"
            return
        }
    }
    #Import ComputerName, Username, Passwords from CSV
    $computers = import-csv $Csv
    foreach ($computer in $computers){
        $session = $null
        $secpasswd = ConvertTo-SecureString $computer.Password -AsPlainText -Force
        $creds = New-Object System.Management.Automation.PSCredential ($computer.Username, $secpasswd)
        try{
            $session = New-SSHSession -ComputerName $computer.ComputerName -Credential $creds -Force
        }catch{
            Write-Host "[-] Error connecting to $($computer.ComputerName)" -ForegroundColor Red
        }
        if($session){
            $output = (Invoke-SSHCommand -SSHSession $session -Command "$LinEnum | /bin/bash")
            Add-Content -Path "$((Get-Location).path)\linux\$($computer.ComputerName)" -Value $output.output
            Remove-SSHSession -SSHSession $session
        }else{
            Add-Content -Path "$((Get-Location).path)\linux\$($computer.ComputerName)" -Value '[-] Error connecting to host'
        }
    }
}
#Invoke-Linux
