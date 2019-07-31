function Invoke-Windows{
    try{
        . $PSScriptRoot\ASBBypass.ps1
        . $PSScriptRoot\PowerUp.ps1
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }
}
#Invoke-Windows