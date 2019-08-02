function Invoke-WinEnum{
    Write-Output "[*] ComputerName $env:COMPUTERNAME"
    Write-Output "[*] User $env:USERNAME"
    Write-Output "[*] UserDomain $env:USERDOMAIN"

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-RegistryAutoLogon/
    Write-Output "`n[*] Checking AutoLogon"
    try{
        $autologon=Get-RegistryAutoLogon
        if($autologon){
            Write-Output "[-] AutoLogon Credentials Found"
            $autologon
        }else{
            Write-Output "[+] No AutoLogon Credentials Found"
        }
    }catch{
        Write-Output "[-] AutoLogon Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-CachedGPPPassword/
    Write-Output "`n[*] Checking CachedGPPPassword"
    try{
        $CachedGPPPassword=Get-CachedGPPPassword
        if($CachedGPPPassword){
            Write-Output "[-] CachedGPPPassword Found"
            $CachedGPPPassword
        }else{
            Write-Output "[+] No CachedGPPPassword Found"
        }
    }catch{
        Write-Output "[-] CachedGPPPassword Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-UnattendedInstallFile/
    Write-Output "`n[*] Checking UnattendedInstallFiles"
    try{
        $UnattendedInstallFile=Get-UnattendedInstallFile
        if($UnattendedInstallFile){
            Write-Output "[-] UnattendedInstallFiles Found"
            $UnattendedInstallFile
        }else{
            Write-Output "[+] No UnattendedInstallFiles Found"
        }
    }catch{
        Write-Output "[-] UnattendedInstallFiles Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-UnquotedService/
    Write-Output "`n[*] Checking Unquoted Services"
    try{
        $UnquotedService=Get-UnquotedService
        if($UnquotedService){
            Write-Output "[-] Unquoted Services Found"
            $UnquotedService
        }else{
            Write-Output "[+] No Unquoted Services Found"
        }
    }catch{
        Write-Output "[-] Unquoted Services Failed"
    }
}