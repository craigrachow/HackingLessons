# Windows CLI inc PowerShell (Complete)
HTB Introduction to Windows Command Line (Complete)  
HTB Windows Fundermentals (Complete)  

## General Commands

| Command | Description | Example |
|----------|--------------|----------|
| `cls` | Clear the terminal screen | `cls` |
| `echo` | Display a message or variable value | `echo Hello HTB!` |
| `help` | Show available commands | `help` |
| `get-command` | Show available commands | `get-command` |
| `get-alias` | Show available shorter or alias commands | `get-alias` |
| `exit` | Close Command Prompt or PowerShell | `exit` |
| `dokey /history` | Lists previous command history | `dokey /history` |
| `more` | Reads a file and scrunches the spacing | `more /s` |
| `type` | Displays the contents of a file | `type <filename>` |
| `find /i` | Command to use to find string in text | `find /i "string" < password.txt ` |
| `xfreerdp` | Initiate a RDP connection | `xfreerdp /v:<targetIP> /u:<user> /p:<password>` |
| `ssh` | Connect to target host via SSH | `ssh <user>@<targetIP>` |

---

## File & Directory Commands

| Command | Description | Example |
|----------|--------------|----------|
| `dir` | List directory contents | `dir /a /s` |
| `cd` | Change directory | `cd C:\Users\Public` |
| `copy` | Copy files | `copy C:\file.txt D:\backup\` |
| `move` | Move files | `move file.txt C:\Temp` |
| `del` | Delete a file | `del secrets.txt` |
| `mkdir` | Create a new directory | `mkdir C:\Temp\Logs` |
| `rmdir` | Remove directory | `rmdir /S /Q old_folder` |
| `Get-ChildItem` | PowerShell version of `dir` | `Get-ChildItem -Recurse` |
| `Get-Content` | Display file contents | `Get-Content .\flag.txt` |

---

## System Information Commands

| Command | Description | Example |
|----------|--------------|----------|
| `systeminfo` | Display detailed system info | `systeminfo` |
| `set` | Show environment variables | `set` |
| `$env:` | PowerShell environment variables | `$env:USERNAME` |
| `wmic os get caption` | Get OS version | `wmic os get caption` |
| `Get-ComputerInfo` | PowerShell detailed info | `Get-ComputerInfo | Select CsName, WindowsVersion` |
| `hostname` | Display system hostname | `hostname` |
| `whoami` | Show current user | `whoami /all` (shows token details) |

---

## Input/Output Operators

| Operator | Description | Example |
|-----------|--------------|----------|
| `>` | Redirect output to file (overwrite) | `whoami > user.txt` |
| `>>` | Append output to file | `ipconfig >> netinfo.txt` |
| `<` | Take input from file | `sort < list.txt` |
| `|` | Pipe output to another command | `ipconfig | findstr IPv4` |

---

## Find & Filter Content

| Command | Description | Example |
|----------|--------------|----------|
| `find` | Search for text in files | `find "password" *.txt` |
| `findstr` | Advanced string search | `findstr /S /I "admin" *.log` |
| `Select-String` | PowerShell search (grep alternative) | `Select-String -Path *.txt -Pattern password` |
| `grep` | (If available via WSL) Search for text | `grep -i password *.config` |

---

## User and Group Commands

| Command | Description | Example |
|----------|--------------|----------|
| `whoami` | Show current user | `whoami /all` |
| `net user` | List local users | `net user` |
| `net user <username>` | Show details for user | `net user administrator` |
| `query user` | Show logged-on users | `query user` |
| `Get-LocalUser` | PowerShell list local users | `Get-LocalUser` |
| `net localgroup` | List local groups | `net localgroup administrators` |
| `net localgroup <group> <user> /add` | Add user to group | `net localgroup administrators bob /add` |
| `Get-LocalGroupMember` | PowerShell equivalent | `Get-LocalGroupMember administrators` |
| `New-LocalUser` | Create user | `New-LocalUser -Name bob -Password (ConvertTo-SecureString 'P@ss123!' -AsPlainText -Force)` |

---

## Networking Commands

| Command | Description | Example |
|----------|--------------|----------|
| `ipconfig` | Show network configuration | `ipconfig /all` |
| `ping` | Test connectivity | `ping 10.10.10.1` |
| `tracert` | Trace route to host | `tracert hackthebox.com` |
| `netstat` | Show network connections | `netstat -ano` |
| `nslookup` | DNS lookup | `nslookup hackthebox.com` |
| `net share` | Shows shares on the local computer | `net share` |
| `arp` | Displays contents and entries within the Address Resolution Protocol (ARP) cache | `arp -a` |
| `Get-NetTCPConnection` | PowerShell netstat equivalent | `Get-NetTCPConnection | ? {$_.State -eq 'Established'}` |
| `Test-NetConnection` | Check port and latency | `Test-NetConnection 10.10.10.10 -Port 80` |

---

## Managing Services

| Command | Description | Example |
|----------|--------------|----------|
| `net start` | List running services | `net start` |
| `sc query` | Query service status | `sc query Spooler` |
| `Get-Service` | PowerShell list of services | `Get-Service | Where-Object {$_.Status -eq 'Running'}` |
| `tasklist` | List of processes running| `tasklist /svc` |
| `wmic service` | List of processes running| `wmic service list brief ` |
| `sc start` | Start a service | `sc start wuauserv` |
| `net start start` | Start a service | `net start wuauserv` |
| `Start-Service` | Start a service | `Start-Service -Name Spooler` |
| `Stop-Service` | Stop a service | `Stop-Service -Name Spooler` |

---

## Scheduled Tasks

| Command | Description | Example |
|----------|--------------|----------|
| `schtasks /query /fo LIST /v` | List all scheduled tasks | `schtasks /query /fo LIST /v` |
| `schtasks /create` | Create a scheduled task | `schtasks /create /sc daily /tn backup /tr C:\backup.bat` |
| `Get-ScheduledTask` | PowerShell equivalent | `Get-ScheduledTask | Select TaskName, State` |

---

## Interacting With The Web

| Command | Description | Example |
|----------|--------------|----------|
| `curl` | Download content from URL | `curl http://10.10.10.5/file.exe -o file.exe` |
| `Invoke-WebRequest` | PowerShell web downloader | `Invoke-WebRequest -Uri http://10.10.10.5/shell.ps1 -OutFile shell.ps1` |
| `Invoke-RestMethod` | API requests in PowerShell | `Invoke-RestMethod -Uri https://api.ipify.org` |

---

## Event Log

| Command | Description | Example |
|----------|--------------|----------|
| `wevtutil qe Security /c:10 /f:text` | Query last 10 security events | `wevtutil qe Application /c:5 /f:text` |
| `Get-EventLog` | PowerShell event log reader | `Get-EventLog -LogName System -Newest 10` |
| `Get-WinEvent` | Newer event log cmdlet | `Get-WinEvent -LogName Security -MaxEvents 20` |

---

## Windows Registry

| Command | Description | Example |
|----------|--------------|----------|
| `reg query` | Query registry | `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run` |
| `reg add` | Add new registry key/value | `reg add HKCU\Software\HackTheBox /v Level /t REG_SZ /d Beginner` |
| `Get-ItemProperty` | PowerShell registry view | `Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'` |

---

## PowerShell Cmdlets and Modules

| Cmdlet | Description | Example |
|---------|--------------|----------|
| `Get-Command` | List available cmdlets | `Get-Command *process*` |
| `Get-Help` | View command help | `Get-Help Get-Process -Detailed` |
| `Import-Module` | Load module | `Import-Module ActiveDirectory` |
| `Get-Module` | List modules | `Get-Module -ListAvailable` |

---

## PowerShell Scripting

| Topic | Example |
|--------|----------|
| Variables | `$ip = "10.10.10.5"` |
| Loops | `for ($i=1; $i -le 5; $i++) { Write-Host $i }` |
| Functions | `function Get-HTBFlag { Get-Content C:\flag.txt }` |
| Run script | `powershell -ExecutionPolicy Bypass -File script.ps1` |

---

## Good Enumeration Examples

```powershell
# Quick recon of Windows HTB target
whoami /all
ipconfig /all
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
netstat -ano | findstr LISTENING
net user

# PowerShell enumeration
Get-LocalUser
Get-Service | ? {$_.Status -eq 'Running'}
Get-ScheduledTask | Select TaskName, State
Test-NetConnection -ComputerName 10.10.10.5 -Port 5985
```

## Good Resources 
- https://ss64.com/nt/  




