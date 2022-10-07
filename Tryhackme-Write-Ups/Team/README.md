Hello this is my first write up I hope you will like it. For any questions or whatever message u can find me on Twitter https://twitter.com/Vojtech1337 . 
We will start with adding host to the /etc/hosts file and after that we will do all ports nmap scan.
```
echo "\n10.10.162.244 team.thm" >> /etc/hosts

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-05 06:13 EDT
Nmap scan report for 10.10.96.107 (10.10.96.107)
Host is up (0.069s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 79:5f:11:6a:85:c2:08:24:30:6c:d4:88:74:1b:79:4d (RSA)
|   256 af:7e:3f:7e:b4:86:58:83:f1:f6:a2:54:a6:9b:ba:ad (ECDSA)
|_  256 26:25:b0:7b:dc:3f:b2:94:37:12:5d:cd:06:98:c7:9f (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works! If you see this add 'te...
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
We see that we have ftp open so lets try to login with anonymous and leave password blank. But we have noo success. Next comes the web page on port 80.
![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/Team/images/team_web.png?raw=true)

It looks like a static page - nothing interesting there. Gobuster didn't find any directories but found one subdomain -dev.team.thm .
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     team.thm
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
2022/10/07 07:11:48 Starting gobuster in DNS enumeration mode
===============================================================
Found: dev.team.thm
===============================================================
2022/10/07 07:20:56 Finished
===============================================================

```
We need to add it to the /etc/hosts as well to acess it.
```
echo "\n10.10.162.244 dev.team.thm" >> /etc/hosts
```
Now let's see what is on this page.
![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/Team/images/dev_team_web.png?raw=true)

Only thing here is link when we click it it redirects us to dev.team.thm/script.php?page=teamshare.php

