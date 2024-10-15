# Network Enumeration (Complete)
**Network Enumeration with nmap**   
**Introduction to Networking**



### nmap Cheat Sheet
The cheat sheet is as a useful command reference for this module.

Command	Description
> - **nmap -p- -T5 <ip> -v** -	Going to show all ports open/running and 5threads.
> - **nmap -p 22,25,80 -A <ip> -v**	- get info for the open ports
> - **nmap -sS <ip>** -	scanning all ports on IP  
> - **nmap  -sV <ip>** - does a service scan on a target ip
> - **nmap -O <ip>** - scanning hosts looking for OS details
> - **nmap -F 192.168.1.1/24** - scan only common ports on a subnet
> - **nmap -A <ip>** - does a deep scan for everything above.
#


Further Useful nmap Commands
> - **nmap -PR 192.168.1.1/24** - scan subnet for hosts
> - **nmap -sn 192.168.1.1/24** - scan subnet for hosts
> - **nmap -sC <ip>** - does a scripts scan on a target ip (this and service scan can be combined with -sVC)
> - **nmap --script <ip>** - does a quick vulnerability scan on a host
> - **nmap -p 8080 --script="http-enum" <ip>** - does a scripts scan on a target ip and port.
> - **nmap -iL list.txt** -	Scans ip/hosts in the textfile    
> - other options -f (fragment, make it harder for detection), --source 53 (make it appear as if coming from dns port)    
#

Other programs
> - **masscan 192.168.0.1/24 -p0-65535 --rate=10000** - scans network for all hosts, but fast


