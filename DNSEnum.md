#check out nameserver

dig NS inlanefreight.com
dig SOA inlanefreight.com
nslookup -type=SPF inlanefreight.com
nslookup -type=txt _dmarc.inlanefreight.com

google the following string "site:blah.com -www -docs -devblogs"
Also, we can use public services such as VirusTotal, DNSdumpster, Netcraft, and others to read known entries for the corresponding domain.

python3 ctfr.py -d inlanefreight.com
https://github.com/UnaPibaGeek/ctfr
Installing
$ git clone https://github.com/UnaPibaGeek/ctfr.git
$ cd ctfr
$ pip3 install -r requirements.txt
Using

#Performing DNS Zone Transfer
dig axfr inlanefreight.com @10.129.184.188

#DNS Python
pip install dnspython

#DNSEnum
https://github.com/theMiddleBlue/DNSenum/blob/master/dnsenum.sh
 ./dnsenum.sh -d inlanefreight.htb -n 10.129.184.188


read more
https://securitytrails.com/blog/google-hacking-techniques
https://securitytrails.com/blog/dns-enumeration
