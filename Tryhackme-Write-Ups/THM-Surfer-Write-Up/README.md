Hello and welcome back to my new write up. This one is on Tryhackme room called Surfer. It is rated as medium
but really is easy if you know even little about SSRF. Let's jump right in.

We will start with nmap scan.

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-20 14:16 EDT
Nmap scan report for 10.10.91.227 (10.10.91.227)
Host is up (0.084s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 45:56:59:60:5e:c5:8d:6c:a3:f1:ee:c4:d7:a8:1e:96 (RSA)
|   256 41:0d:09:84:fb:b5:9e:67:87:d1:74:22:f7:87:82:aa (ECDSA)
|_  256 08:86:c6:f2:75:2c:c3:2f:14:db:aa:81:08:bc:87:cc (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/backup/chat.txt
| http-title: 24X7 System+
|_Requested resource was /login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

It shows us two ports open. 80 which is http and 22 which is ssh. It also has `robots.txt` file with `/backup/chat.txt`. Before we visit that 
we will start tool called feroxbuster to look for another directories/files becuase we should always have something running in the background while we perform manual testing to save time. We will start it with `-x php` becuase we see PHPSESSID
which means that it runs php and `-o` to save it into file for later. The command will look like this

```
# feroxbuster -u http://10.10.203.218 -x php -o ferox
```

Now let's visit the web page. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Surfer-Write-Up/images/surfer_web_login.png?raw=true)

It's a login page but we don't have any credentials. But what we do have is suspicious disallowed entry in robots.txt. Let's look into that.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Surfer-Write-Up/images/surfer_web_robots.png?raw=true)

There is a conversation between two people talking about credentials. Now we know the flag is hidden on internal server but we don't know exactly where and also user is supposedely using username as password. We could've guessed the credentials because it's just `admin:admin`. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Surfer-Write-Up/images/surfer_web_admin.png?raw=true)

It is some dashboard about some business. Only one feature is available - export2pdf.
If we click it it generates pdf for something on localhost. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Surfer-Write-Up/images/surfer_export_pdf.png?raw=true)

Can we somehow change the url which it uses for the report generation ? 
Time to start burpsuite and catch the export request. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Surfer-Write-Up/images/surfer_burp_original.png?raw=true)

It uses the url as parameter which we can easily change.
Let's see what did feroxbuster give us, hopefully place with a flag. 

```
302      GET        0l        0w        0c http://10.10.203.218/ => /login.php
200      GET      113l      291w     4774c http://10.10.203.218/login.php
301      GET        9l       28w      315c http://10.10.203.218/backup => http://10.10.203.218/backup/
302      GET        0l        0w        0c http://10.10.203.218/logout.php => /login.php
301      GET        9l       28w      317c http://10.10.203.218/internal => http://10.10.203.218/internal/
302      GET        0l        0w        0c http://10.10.203.218/index.php => /login.php
301      GET        9l       28w      315c http://10.10.203.218/assets => http://10.10.203.218/assets/
301      GET        9l       28w      318c http://10.10.203.218/assets/js => http://10.10.203.218/assets/js/
301      GET        9l       28w      319c http://10.10.203.218/assets/img => http://10.10.203.218/assets/img/
200      GET        1l        7w       39c http://10.10.203.218/internal/admin.php
---redacted---
```

Interesting directory here is `internal` with php page `admin.php`. If we try to access in web browser it return only message:
`This page can only be accessed locally.`
Let's try to put it into the URL parameter to see if we can
access it that way. We only need to change the directory and page we are exporting to pdf.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Surfer-Write-Up/images/surf_burp_changed.png?raw=true)

After that forward the request and we get a flag. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Surfer-Write-Up/images/surfer_burp_flag.png?raw=true)

And that's a wrap.