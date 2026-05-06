
# 🐍 Introduction to Python 3 — Cheat Sheet (CTF & Pentesting Focus)

A quick reference guide covering core Python concepts with practical examples for scripting, automation, and hacking tasks.


## Executing Python Code

Python scripts can be run in multiple ways.

### Methods
```bash
python3 script.py
```

```bash
chmod +x script.py
./script.py
```

### Shebang Example
```python
#!/usr/bin/env python3
print("Hello from Python")
```

---

## Introduction to Variables

Variables store data such as strings, numbers, or lists.

```python
ip = "10.10.10.5"
port = 22
```

### Example (CTF use)
```python
target = "10.10.10.5"
print(f"Scanning {target}")
```

```python
wordlist = ["admin", "root", "user"]
```

---

## 🔀 Conditional Statements & Loops

Used to control logic and automate repetitive tasks.

### If Statement
```python
if port == 22:
    print("SSH detected")
```

### Loop Example
```python
for user in ["admin", "root"]:
    print(f"Trying {user}")
```

### Practical Example
```python
ports = [21,22,80]
for p in ports:
    print(f"Checking port {p}")
```

---

## 🧩 Defining Functions

Functions group reusable code.

```python
def scan_port(port):
    print(f"Scanning port {port}")
```

### Example
```python
def login(user, password):
    print(f"Trying {user}:{password}")

login("admin", "admin123")
```

---

## 🧪 Interactive Mode

Run Python directly in terminal:

```bash
python3
```

### Example
```python
>>> 2 + 2
4
```

---

## 🧼 Making Code Classy (Clean Code)

Good practices:
- Use meaningful variable names
- Add comments
- Keep code readable

```python
# Bad
x = "10.10.10.5"

# Good
target_ip = "10.10.10.5"
```

---

## 📚 Introduction to Libraries

Libraries extend Python functionality.

### Common Libraries
- os → interact with system
- sys → handle arguments
- requests → HTTP requests

```python
import os
os.system("whoami")
```

---

## 📦 Managing Libraries

Install packages using pip:

```bash
pip install requests
```

### Example
```python
import requests
r = requests.get("http://target")
print(r.status_code)
```

---

## 🧠 Importance of Libraries

Libraries allow you to:
- Avoid writing everything from scratch
- Automate tasks quickly
- Interact with APIs and services

Example:
```python
import requests
print(requests.get("http://example.com").text)
```

---

# 🌐 Practical Project — Webpage Word Extractor

---

## 🧪 The First Iteration

```python
import requests

url = "http://example.com"
response = requests.get(url)

print(response.text)
```

---

## 🔄 Continuously Improving the Code

```python
words = response.text.split()

for word in words[:20]:
    print(word)
```

---

## 🚀 Further Improvements

```python
import re

clean_words = re.findall(r"\b[a-zA-Z]{4,}\b", response.text)

for word in set(clean_words):
    print(word)
```

### Save Output
```python
with open("words.txt", "w") as f:
    for word in clean_words:
        f.write(word + "\n")
```

---

## 🧠 Key Takeaways

- Python is powerful for automation & scripting
- Functions and loops help scale tasks
- Libraries like requests are essential
- Start simple → improve iteratively

---

## 🔥 Next Steps

- Build a port scanner
- Create a brute-force script
- Learn socket and subprocess
- Explore pwntools

---

Happy hacking 🐍💻⚔️
