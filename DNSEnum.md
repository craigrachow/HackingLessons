#check out nameserver

dig NS inlanefreight.com
dig SOA inlanefreight.com
nslookup -type=SPF inlanefreight.com
nslookup -type=txt _dmarc.inlanefreight.com

google the following string "site:blah.com -www -docs -devblogs"
Also, we can use public services such as VirusTotal, DNSdumpster, Netcraft, and others to read known entries for the corresponding domain.

python3 ctfr.py -d inlanefreight.com
https://github.com/UnaPibaGeek/ctfr


read more
https://securitytrails.com/blog/google-hacking-techniques
