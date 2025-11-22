# Networking Enumeration
A summary of core networking concepts used in cybersecurity, pentesting, and enumeration cheatsheet. 

### OSI Model (7 Layers)
The **Open Systems Interconnection (OSI)** model is a conceptual framework used to understand how data travels across networks. It divides networking into **7 layers**, each with a specific role.

| Layer | Name | Function (Brief) |
|------|------|------------------|
| 7 | Application | User interface layer – protocols like HTTP, FTP, SMTP. |
| 6 | Presentation | Formats and encrypts data (SSL/TLS, JPEG, ASCII). |
| 5 | Session | Creates and manages communication sessions (NetBIOS, RPC). |
| 4 | Transport | Responsible for reliable data delivery (TCP/UDP). |
| 3 | Network | Handles IP addressing and routing (IP, ICMP). |
| 2 | Data Link | Manages frames & MAC addresses (Ethernet, ARP). |
| 1 | Physical | Physical transmission – cables, signals, NICs. |

### TCP/IP Model (4 Layers)
A simplified model used in real-world networking (used by the Internet).

| Layer | OSI Equivalent | Purpose |
|------|-----------------|---------|
| Application | OSI Layers 5–7 | HTTP, DNS, SSH, SMTP — user interaction protocols |
| Transport | OSI Layer 4 | TCP (reliable) / UDP (fast, unreliable) |
| Internet | OSI Layer 3 | IP addressing, routing |
| Network Access | OSI Layers 1–2 | MAC addressing, Ethernet, Wi-Fi |

**Network Models Visual Reference:**  
**https://cdn.services-k8s.prod.aws.htb.systems/content/modules/34/redesigned/net_models4_updated.png**

### Types of Firewalls
| Type | Description |
|------|-------------|
| Packet-Filtering | Checks packets based on IP, port, protocol. |
| Stateful Inspection | Tracks active connections and traffic states. |
| Proxy Firewall | Acts as middleman between client & internet. |
| Next-Gen Firewall | Includes deep packet inspection & IDS/IPS features. |
| Host-Based Firewall | Installed on individual machines (e.g., Windows Defender). |

### IDS vs IPS
| System | Purpose | Example Tools |
|--------|--------|----------------|
| IDS – Intrusion Detection System | Monitors and alerts on suspicious activity | Snort, Zeek (Bro) |
| IPS – Intrusion Prevention System | Blocks malicious traffic automatically | Suricata, Cisco NGFW |
---

## Common Ports

| Port | Protocol | Purpose / Usage |
|------|---------|---------------------------|
| 20/21 | FTP | File transfer |
| 22 | SSH | Remote login (secure) |
| 23 | Telnet | Remote login (insecure) |
| 25 | SMTP | Email transfer |
| 53 | DNS | Domain name resolution |
| 67/68 | DHCP | Dynamically assign IPs |
| 80 | HTTP | Standard web traffic |
| 110 | POP3 | Retrieve emails |
| 139 | NetBIOS | Windows file sharing |
| 143 | IMAP | Email access |
| 443 | HTTPS | Encrypted web |
| 445 | SMB | Windows file sharing |
| 3306 | MySQL | Database |
| 3389 | RDP | Remote desktop |
| 5900 | VNC | Remote desktop |
| 8000–9000 | Common dev/web ports |
| 27017 | MongoDB | Developer DB used a lot in labs |

---

## Common Networking Tools (with Examples)

| Tool | Purpose | Example Usage |
|------|---------|----------------|
| **netstat** | Show active connections | `netstat -ano` |
| **lsof** | List open files/sockets | `lsof -i :80` |
| **nc** (netcat) | Send/receive connections | `nc -lvp 4444` |
| **ipconfig** | Show IP config (Windows) | `ipconfig /all` |
| **ifconfig** | Linux network config | `ifconfig eth0` |
| **Get-NetAdapter** | PowerShell NIC info | `Get-NetAdapter` |
| **masscan** | Fast port scanner | `masscan 10.10.10.0/24 -p80,22` |

---

## Enumeration with Nmap
Nmap is one of the most powerful **network discovery and enumeration tools** in pentesting.

### Common Nmap Commands

| Purpose | Command |
|--------|---------|
| Basic Scan | `nmap 10.10.10.5` |
| Port Scan | `nmap -p 80,443,22 10.10.10.5` |
| All Ports | `nmap -p- 10.10.10.5` |
| Service Detection | `nmap -sV 10.10.10.5` |
| OS Detection | `nmap -O 10.10.10.5` |
| Aggressive Scan | `nmap -A 10.10.10.5` |
| Save Output | `nmap -oN scan.txt 10.10.10.5` |
| Script Scan | `nmap --script vuln 10.10.10.5` |
| Stealth Scan | `nmap -sS 10.10.10.5` |
| UDP Scan | `nmap -sU 10.10.10.5` |
| Scan full subnet | `nmap 10.10.10.0/24` |
|Other Options | `-f (fragment, make it harder for detection)` <br> `--source 53 (make it appear as if coming from dns port)` |  

### Useful Nmap Scans:  
Use **multiple scans** and **save output**:  
`nmap -sC -sV -oN initial.txt 10.10.10.5`
To quickly find services worth attacking type `grep -i "open" initial.txt`

A comprenhensive scan:
`nmap -A <ip>` - does a deep scan for everything in the common commands.

Other programs
> - **masscan 192.168.0.1/24 -p0-65535 --rate=10000** - scans network for all hosts, but fast
> - **masscan 192.168.0.1/24 -p23 --rate=1000** - does a quick scan for all telnet open
> - other options --randomize-hosts (dont scan in order)

