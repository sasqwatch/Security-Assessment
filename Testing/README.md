Scripts written to aid automated scanning during whitebox security/vuln assessments

# Poc's
### Test-Windows.ps1
	Invoke-WindowsWMI	-  Run PowerShell script on multiple hosts simultaneously with WMI
	Invoke-WindowsPS	-  Run PowerShell script on multiple hosts simultaneously with PSRemote

### Invoke-Stager.ps1
	Invoke-Stager		-  Example how to use -ScriptPath or -URL with Test-Windows.ps1 functions
	
### Invoke-WinEnum.ps1
	Invoke-WinEnum		-  Check Windows host security (to be continued. thx to Harmj0y and A-mIn3)
	Autologon, Cached GPP Password, Unattended Install Files, Unquoted Services Paths,
	AlwaysInstallElevated, Firewall Product and Status, AntiVirus Product and Status, 
	AntiSpyware Product and Status, UAC Configuration, Local SMB Shares and Permissions, 
	Non Standard Scheduled Tasks, Potential Service DDL Hijacking
	
### Test-Linux.ps1
	Invoke-Linux		-  Run Bash script on multiple hosts simultaneously with Posh-SSH and PoshRSJob

### Test-Domain.ps1
	Invoke-Domain		-  Runs simple checks on the domain

### bloodhoundanalytics.py
	Gather Active Directory statistics from BloodHound data

# Software

https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10

https://github.com/CISOfy/lynis

https://github.com/BloodHoundAD/BloodHound/

https://www.tenable.com/products/nessus

# Nessus Audit Files
https://github.com/nsacyber/Windows-Secure-Host-Baseline/tree/master/Windows/Compliance
https://github.com/nsacyber/Windows-Secure-Host-Baseline/tree/master/Windows%20Firewall/Compliance
