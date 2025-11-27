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

## Variables

| Type         | Example                       |
| ------------ | ----------------------------- |
| User defined | `NAME="craig"`                |
| Built-in     | `$USER`, `$HOME`, `$HOSTNAME` |

**Example 1 – System investigation:** `echo "User logged in: $USER"`
**Example 2 – Save command output:** 
```bash
IP=$(hostname -I)
echo "My IP is: $IP"
```

---

## Arrays
```bash
PORTS=(21 22 80 443 3306)
for p in "${PORTS[@]}"; do
    nc -zv 10.10.10.5 $p
done
```

**Example 1 – Scan ports automatically**
**Example 2 – Store usernames for brute force attempts**

---

## Conditional Execution (`if`, `&&`, `||`)

```bash
if [ -f "/etc/passwd" ]; then
    echo "File exists!"
fi
```

**CTF Example – Check for privilege escalation:** `[ $(id -u) -eq 0 ] && echo "ROOT access achieved!"`

---

## Arithmetic

`TOTAL=$(($SUCCESS + $FAIL))`

**Example 1 – Count login attempts:** `FAILED=$(grep -c "Failed password" auth.log)`
**Example 2 – Calculate hash collisions:** `COUNT=$(wc -l hashes.txt)`

---

## Loops

```bash
for USER in $(cut -d: -f1 /etc/passwd); do
    echo $USER
done
```

**Example – Bruteforce SSH usernames:** `for U in $(cat users.txt); do echo "Testing $U"; done`

---

## Comparison Operators

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

## Functions

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

## Good Example Scripts

Example – Search log files changed in the last day for any errors or fatal alerts. Count and print them.
```bash
#!/bin/bash analyse-logs.sh
LOG_DIR=”/Users/name/logs”
APP_LOG_FILE=”application.log”
SYS_LOG_FILE=”system.log”
echo -e “\analysing log files”
echo “==============”
echo -e “\List of log files updated in last 24 hours”
Find $LOG_DIR -name “*.log” -mtime -1
echo -e “\searching ERROR logs in application.log file”
grep “ERROR”  “$LOG_DIR/$APP_LOG_FILE”
grep -c “ERROR” “$LOG_DIR/$APP_LOG_FILE”
grep -c “FATAL” “$LOG_DIR/$APP_LOG_FILE”
echo -e “\analysing system.log”
grep -c “FATAL” system.log
grep -c “CRITICAL” system.log
grep -c “CRITICAL” system.log`
```
More efficient of the above script 
```bash
#!/bin/bash analyse-logs.sh
LOG_DIR=”/Users/name/logs”
APP_LOG_FILE=”application.log”
SYS_LOG_FILE=”system.log”
ERROR_PATTERNS=(“ERROR” “FATAL” “CRITICAL”)
echo -e “\analysing log files”
echo “==============”
echo -e “\List of log files updated in last 24 hours”
LOG_FILES=$(find $LOG_DIR -name “*.log” -mtime -1)
echo “$LOG_FILES”
echo -e “\searching ERROR logs in application.log file”
grep  “${ERROR_PATTERNS[0]}”  “$LOG_DIR/$APP_LOG_FILE”
grep -c “${ERROR_PATTERNS[0]}” “$LOG_DIR/$APP_LOG_FILE”
grep -c “${ERROR_PATTERNS[1]}” “$LOG_DIR/$APP_LOG_FILE”
echo -e “\analysing system.log”
grep -c “${ERROR_PATTERNS[1]}” system.log
grep -c “${ERROR_PATTERNS[2]}” system.log
grep -c “${ERROR_PATTERNS[2]}” system.log`
```
Best efficiency of the above script with formatting
```bash
#!/bin/bash analyse-logs.sh
LOG_DIR=”/Users/name/logs”
ERROR_PATTERNS=(“ERROR” “FATAL” “CRITICAL”)
REPORT_FILE=”/Users/name/logs/log_analysis_report.txt”
echo -e “\analysing log files” > “$REPORT_FILE”
echo “==============” >> “$REPORT_FILE”
echo -e “\List of log files updated in last 24 hours” >> “$REPORT_FILE”
LOG_FILES=$(find $LOG_DIR -name “*.log” -mtime -1)
echo “$LOG_FILES” >> “$REPORT_FILE” 
for LOG_FILE in $LOG_FILES; do
     echo -e “\n”
     echo “=======================================” >> “$REPORT_FILE”
     echo “=================$LOG_FILE======================” >> “$REPORT_FILE”
     echo “=======================================” >> “$REPORT_FILE”
          for PATTERN in ${$ERROR_PATTERNS[@]}; do
          echo -e “\searching $PATTERN logs in $LOG_FILE file” >> “$REPORT_FILE”
          grep  “$PATTERN”  “$LOG_FILE” >> “$REPORT_FILE”
          echo -e “\number of $PATTERN logs found in $LOG_FILE” >> “$REPORT_FILE”
           ERROR_COUNT=$(grep -c “$PATTERN” “$LOG_FILE”
          echo $ERROR_COUNT >> “$REPORT_FILE”
          if [ “$ERROR_COUNT” -gt 10];then
              echo “WARNING ACTION REQUIRED: too many $PATTERN errors in log file $LOG_FILE”
           fi 
     done
done
echo – e “\Log analysis completed and report saved in : $RPORT_FILE

