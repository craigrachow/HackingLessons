# Linux Bash Scripting
A practical summary of essential Bash skills for server and security related tasks.


## Basic Bash Commands & Fundamentals
Bash is a **command interpreter** allowing you to **automate tasks, search, process data, and script exploits**. Common commands used in Linux enumeration, file searching, system inspection, and automation.

| Command | Description | Example (CTF / Hacking Use) |
|--------|-------------|-----------------------------|
| `ls -la` | List all files, including hidden | Find hidden `.ssh/` or `.git/` folders |
| `pwd` | Show current directory | Useful during directory traversal exploitation |
| `cat` | Read contents of a file | `cat /etc/passwd` |
| `history` | View command history | Look for leaked credentials |
| `chmod` | Change permissions | `chmod +x exploit.sh` |
| `grep` | Search content in files | `grep -r "password" /var/www/` |
| `find` | Locate files on system | `find / -name "*.conf" 2>/dev/null` |

**Example 1 – Count errors in system log:** `grep -c "ERROR" system.log`  
**Example 2 – Find logs modified in last 24 hours:** `find . -name "*.log" -mtime -1`  
**Example 3 – List potential password files:** `find / -type f -iname "*pass*" 2>/dev/null`  
**Example 4 – Search for writable files (priv esc):** `find / -writable -type f 2>/dev/null`  

---

## Writing Your First Bash Script

Example: **Hello World** script.

```bash
#!/bin/bash
# This is a basic bash script
# Saved as hello.sh

echo "Hello HTB — let's hack something!"
```

Run it:

```bash
chmod +x hello.sh
./hello.sh
```

---

## Input & Output

I/O redirection is used a lot in exploitation & log analysis.

| Syntax        | Purpose                     |
| ------------- | --------------------------- |
| `>`           | redirect output (overwrite) |
| `>>`          | append output               |
| `<`           | provide input from a file   |
| `2>/dev/null` | discard errors              |

**Example 1 – Extract usernames into a file:** `cut -d: -f1 /etc/passwd > users.txt`
**Example 2 – Hide error messages (useful in exploitation):** `find / -name "*.conf" 2>/dev/null`

---

## Arguments (`$1`, `$2`, `$@`)

Pass values into scripts from the command line.
```bash
#!/bin/bash
echo "Target IP is: $1"
```
Run:
```bash
./scan.sh 10.10.10.5
```

**Example 1 – Scan with parameter:** `nmap -sV $1`
**Example 2 – Loop through multiple IPs:** `for ip in "$@"; do nmap -sV $ip; done`

---

## 🔑 Variables

| Type         | Example                       |
| ------------ | ----------------------------- |
| User defined | `NAME="craig"`                |
| Built-in     | `$USER`, `$HOME`, `$HOSTNAME` |

**Example 1 – System investigation:**

```bash
echo "User logged in: $USER"
```

**Example 2 – Save command output:**

```bash
IP=$(hostname -I)
echo "My IP is: $IP"
```

---

## 📦 Arrays

```bash
PORTS=(21 22 80 443 3306)
for p in "${PORTS[@]}"; do
    nc -zv 10.10.10.5 $p
done
```

**Example 1 – Scan ports automatically**
**Example 2 – Store usernames for brute force attempts**

---

## 🔀 Conditional Execution (`if`, `&&`, `||`)

```bash
if [ -f "/etc/passwd" ]; then
    echo "File exists!"
fi
```

**CTF Example – Check for privilege escalation:**

```bash
[ $(id -u) -eq 0 ] && echo "ROOT access achieved!"
```

---

## ➕ Arithmetic

```bash
TOTAL=$(($SUCCESS + $FAIL))
```

**Example 1 – Count login attempts:**

```bash
FAILED=$(grep -c "Failed password" auth.log)
```

**Example 2 – Calculate hash collisions:**

```bash
COUNT=$(wc -l hashes.txt)
```

---

## 🔁 Loops

```bash
for USER in $(cut -d: -f1 /etc/passwd); do
    echo $USER
done
```

**Example – Bruteforce SSH usernames:**

```bash
for U in $(cat users.txt); do echo "Testing $U"; done
```

---

## ⚖️ Comparison Operators

| Operator | Meaning           |
| -------- | ----------------- |
| `-eq`    | Equals            |
| `-ne`    | Not equal         |
| `-gt`    | Greater than      |
| `-lt`    | Less than         |
| `=`      | String equals     |
| `!=`     | String not equals |

**Example – Check if service crashed:**

```bash
ERROR_COUNT=5
if [ "$ERROR_COUNT" -gt 0 ]; then echo "Alerts found!"; fi
```

---

## 🧩 Functions

```bash
function scan_port() {
    nc -zv $1 $2
}
scan_port 10.10.10.5 22
```

**Example – Automate basic nmap scan**

```bash
scan_nmap(){
    nmap -sV $1
}
scan_nmap 10.10.10.5
```

---

## 📁 Good Example Scripts

> *These are already written correctly and do not need edits.*

You provided solid real-world scripts for **log analysis & error detection**. Great for:

* cron jobs
* monitoring servers
* threat detection
* forensic analysis

---

### 🧠 Next Suggestions

* Convert `analyse-logs.sh` into **CTF evidence parser**
* Add **colour-coded (RED/YELLOW/GREEN)** log alerts
* Export to **CSV** and analyse in `pandas`
* Store results in `/opt/ctf-reports/`

---

Let me know if you'd like:

* 🚀 A **privilege escalation script** in bash
* 🧠 Bash **flashcards** for revision
* 📊 A script that **auto-detects vulnerable binaries** (SUID / Capabilities)

Happy hacking 🐧💻⚔️

```

---

Let me know if you want a **PDF version**, **Git repo structure**, or **flashcard drill mode** for memorising bash commands.
```

