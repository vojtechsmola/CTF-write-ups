Yo,
welcome to write up for machine Health from Hackthebox.
Starting of as always with nmap scan of all ports

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-14 17:41 EST
Nmap scan report for 10.10.11.176 (10.10.11.176)
Host is up (0.062s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 32:b7:f4:d4:2f:45:d3:30:ee:12:3b:03:67:bb:e6:31 (RSA)
|   256 86:e1:5d:8c:29:39:ac:d7:e8:15:e6:49:e2:35:ed:0c (ECDSA)
|_  256 ef:6b:ad:64:d5:e4:5b:3e:66:79:49:f4:ec:4c:23:9f (ED25519)
80/tcp   open     http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HTTP Monitoring Tool
3000/tcp filtered ppp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

There are three ports open. Standartly port 22 being ssh and port 80 being apache web server. Unusual is port 3000 which is filtered. I'll keep that in mind
if I ever find a way to get there for example with SSRF. 

Let's visit the website first because there's nothing much to do with ssh. 

IMG1

The page shows us hostname health.htb. I'll add it to my `/etc/hosts` file with simple command:

```

echo "10.10.11.166 health.htb" >> /etc/hosts

```

Visiting the page with the hostname gives the same page.