#Multi Threading Coming Soon
function Invoke-LinEnum {
    param (
        [string]$Csv = '.\linux.csv',
        [string]$LinEnumPath
    )
    #Generates LinEnum reports for multiple hosts
    #install Posh-SSH module and PoshRSJob
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
    #PS C:\Users\cube\Desktop> import-csv .\linux.csv
    #ComputerName Username Password
    #------------ -------- --------
    #192.168.1.40 cube     cube
    $computers = import-csv $Csv
    foreach ($computer in $computers){
        $secpasswd = ConvertTo-SecureString $computer.Password -AsPlainText -Force
        $creds = New-Object System.Management.Automation.PSCredential ($computer.Username, $secpasswd)
        $session = New-SSHSession -ComputerName $computer.ComputerName -Credential $creds -Force
        $output = (Invoke-SSHCommand -SSHSession $session -Command "$LinEnum | /bin/bash")
        Add-Content -Path "$((Get-Location).path)\linux\$($computer.ComputerName)" -Value $output.output
        Remove-SSHSession -SSHSession $session
    }
}
#Invoke-LinEnum