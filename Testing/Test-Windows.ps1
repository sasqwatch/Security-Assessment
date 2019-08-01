function Invoke-Windows{
    Start-Transcript -Path "$(Get-Location)\$env:COMPUTERNAME.txt" -NoClobber
    try{
        . $PSScriptRoot\ASBBypass.ps1 | Out-Null
        . $PSScriptRoot\PowerUp.ps1
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }
    Write-Host "[*] ComputerName $env:COMPUTERNAME"
    Write-Host "[*] User $env:USERNAME"
    Write-Host "[*] UserDomain $env:USERDOMAIN"

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-RegistryAutoLogon/
    Write-Host "`n[*] Checking AutoLogon"
    try{
        $autologon=Get-RegistryAutoLogon
        if($autologon){
            Write-Host "[-] AutoLogon Credentials Found" -ForegroundColor Red
            $autologon
        }else{
            Write-Host "[+] No AutoLogon Credentials Found" -ForegroundColor Green
        }
    }catch{
        Write-Host "[-] AutoLogon Failed" -ForegroundColor Red
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-CachedGPPPassword/
    Write-Host "`n[*] Checking CachedGPPPassword"
    try{
        $CachedGPPPassword=Get-CachedGPPPassword
        if($CachedGPPPassword){
            Write-Host "[-] CachedGPPPassword Found" -ForegroundColor Red
            $CachedGPPPassword
        }else{
            Write-Host "[+] No CachedGPPPassword Found" -ForegroundColor Green
        }
    }catch{
        Write-Host "[-] CachedGPPPassword Failed" -ForegroundColor Red
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-UnattendedInstallFile/
    Write-Host "`n[*] Checking UnattendedInstallFiles"
    try{
        $UnattendedInstallFile=Get-UnattendedInstallFile
        if($UnattendedInstallFile){
            Write-Host "[-] UnattendedInstallFiles Found" -ForegroundColor Red
            $UnattendedInstallFile
        }else{
            Write-Host "[+] No UnattendedInstallFiles Found" -ForegroundColor Green
        }
    }catch{
        Write-Host "[-] UnattendedInstallFiles Failed" -ForegroundColor Red
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-UnquotedService/
    Write-Host "`n[*] Checking Unquoted Services"
    try{
        $UnquotedService=Get-UnquotedService
        if($UnquotedService){
            Write-Host "[-] Unquoted Services Found" -ForegroundColor Red
            $UnquotedService
        }else{
            Write-Host "[+] No Unquoted Services Found" -ForegroundColor Green
        }
    }catch{
        Write-Host "[-] Unquoted Services Failed" -ForegroundColor Red
    }
    Stop-Transcript
}
#Invoke-Windows