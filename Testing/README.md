Scripts written to aid automated scanning during whitebox security/vuln assessments

# Poc's
### Invoke-WinEnum.ps1
	Invoke-WinEnum		-  Check Windows host security (to be continued. thx to Harmj0y and A-mIn3)
* General System Information
* Local users in Administrators, RDP, DCOM, PSRemote group
* Firewall, AntiVirus, and Spyware Product for Workstations
* Autologon Credentials
* Cached GPP Password
* Unattended Install Files
* Unquoted Services Paths
* AlwaysInstallElevated
* UAC Configuration 
* ACL on Local SMB Shares
* ACL on Service Binaries and Directories
* ACL on Possible High Privileged Scheduled Tasks Binaries and Directories
* ACL on AutoRuns Binaries and Directories for System and Local Administrators
* ACL on Directories located in System and Local Administrators PATH Variable
* Active Listenings Ports
* Installed Software
* Print Spool and Wpad Status
* PowerShell Logging
* LAPS
* Lsass Protection
* SMBv1
* PowerShell v2
* .Net Versions
* Windows Defender Configuration for Servers
* IIS (encrypted web.config strings, encrypted application pools and virtual directory passwords)
* MSSQL (Links, Users, Default and Weak Passwords, Databases, ACL on .mdf, Vulnerable configurations...)

(ACL's for System, Local Administrators, and TrustedInstaller is being ignored)
### Invoke-Chaps.ps1
	Invoke-Chaps		-  Secure baseline checks (Modified version of chaps.ps1 originally written by cutaway)
### Test-Linux.ps1
	Invoke-Linux		-  Run Bash script on multiple hosts simultaneously with Posh-SSH
### Test-Windows.ps1
	Invoke-WindowsWMI	-  Run PowerShell script on multiple hosts simultaneously with WMI
	Invoke-WindowsPS	-  Run PowerShell script on multiple hosts simultaneously with PSRemote
### Invoke-Stager.ps1
	Invoke-Stager		-  Example how to use -ScriptPath or -URL with Test-Windows.ps1 functions
### Test-Domain.ps1
	Invoke-Domain		-  Runs simple checks on the domain
* Domain and Forest Trust
* GPO Autologon and CPassword in Sysvol
* Active Directory Integrated DNS Wildcard Record
* Password Policy
* MachineAccountQuota
### bloodhoundanalytics.py
	Gather Active Directory statistics from BloodHound data

# Software

https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10

https://github.com/CISOfy/lynis

https://github.com/BloodHoundAD/BloodHound/

https://www.tenable.com/products/nessus

https://github.com/GhostManager/Ghostwriter

# Nessus Audit Files
https://github.com/nsacyber/Windows-Secure-Host-Baseline/tree/master/Windows/Compliance

https://github.com/nsacyber/Windows-Secure-Host-Baseline/tree/master/Windows%20Firewall/Compliance
