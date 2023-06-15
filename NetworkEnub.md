Recon

#going to show all ports open/running and 5threads.
nmap -p- -T5 <ip> -v

#get info for the open ports
nmap -p 22,25,80 -A <ip> -v

#scanning all ports on IP
nmap -sS <ip>

#scanning verion of service on each port
nmap  -sV <ip>

#scanning for OS
nmap -O <ip>

#scan only common ports on a subnet
nmap -F 192.168.1.1/24



