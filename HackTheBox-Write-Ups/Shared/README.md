Hello and welcome back to yet another write up. This one will be for box Shared from Hackthebox. 

We will start with nmap:

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-15 15:47 EST
Warning: 10.10.11.172 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.172 (10.10.11.172)
Host is up (0.13s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 91:e8:35:f4:69:5f:c2:e2:0e:27:46:e2:a6:b6:d8:65 (RSA)
|   256 cf:fc:c4:5d:84:fb:58:0b:be:2d:ad:35:40:9d:c3:51 (ECDSA)
|_  256 a3:38:6d:75:09:64:ed:70:cf:17:49:9a:dc:12:6d:11 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-title: Did not follow redirect to http://shared.htb
|_http-server-header: nginx/1.18.0
443/tcp open  ssl/http nginx 1.18.0
|_http-title: Did not follow redirect to https://shared.htb
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US
| Not valid before: 2022-03-20T13:37:14
|_Not valid after:  2042-03-15T13:37:14
|_http-server-header: nginx/1.18.0
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|   h2
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 372.49 seconds
```

First things first let's add shared.htb to our host file `echo '10.10.11.172 shared.htb' >> /etc/hosts`
When we visit this page it redirects us to https version of the site. 

IMG1

Here we can view certificate for potential leaks of other hostnames. 

IMG2

It uses wildcard which so I'll start fuzzing for other subdomains. For this I'll use wfuzz:
```
└─# wfuzz -u https://10.10.11.172 -H "Host: FUZZ.shared.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt 
* Wfuzz 3.1.0 - The Web Fuzzer                         

Target: https://10.10.11.172/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                     
=====================================================================

000000024:   301        7 L      11 W       169 Ch      "admin"                                                                                                                                                                     
000000015:   301        7 L      11 W       169 Ch      "ns"                                                                                                                                                                        
000000007:   301        7 L      11 W       169 Ch      "webdisk"                                                                                                                                                                   
000000003:   301        7 L      11 W       169 Ch      "ftp"                                                                                                                                                                       
000000023:   301        7 L      11 W       169 Ch      "forum"                                                                                                                                                                     
000000022:   301        7 L      11 W       169 Ch      "pop3"                                                                                                                                                                      
000000021:   301        7 L      11 W       169 Ch      "ns3"          
```
And then add flag `--hw 11` to hide all those redirects.

```
└─# wfuzz -u https://10.10.11.172 -H "Host: FUZZ.shared.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw 11
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.11.172/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                     
=====================================================================

000000001:   302        0 L      0 W        0 Ch        "www"                                                                                                                                                                       
000002549:   200        64 L     151 W      3229 Ch     "checkout"  
```

I'll keep the list of the ones that I find in mind if I don't find
anything on `https://shared.htb/`. When we visit the site we see that it loads index.php so it is a php web application for some 
shop.

IMG3

Let's see how it works when I try to buy something. For this I spin up burpsuite. If we click proceed to checkout
this is what the request looks like.

IMG4

We see that the cookie decodes to JSON. I'll send it to repeater and try to do sql injection. It doesn't have to be url encoded.
With `' -- -` it still works the same. This signalizes sql injection. Time to move to union select and find columns that we can use. After a few tries and changing the product code I see that we can use column to exfiltrate data.

IMG5

After trying different payloads specific for different databases I found out that it uses Mysql - Mariadb.

IMG6

From this point I used payloads from this site with slight modifications.

IMG7

IMG8

IMG9

IMGx

IMG10

We can now take the password hash and try to crack for example in crackstation. It works 

IMG11

Now let's login with ssh. And we are in. Looking around filesytem there is a script_review folder in /opt but it is
empty. I'll run pspy if there isn't some cronjob doing something with or in this folder. 

```
james_mason@shared:/tmp$ ./pspy64 
2022/11/15 17:35:06 CMD: UID=0    PID=180783 | /bin/bash /root/c.sh 
2022/11/15 17:36:01 CMD: UID=1001 PID=180795 | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython 
2022/11/15 17:36:01 CMD: UID=1001 PID=181003 | /usr/bin/python3 /usr/local/bin/ipython 
``` 

I don't knwo what /root/c.sh is. But user with uid 1001 (which dan_smith we can get that info from /etc/passwd) kills ipython 
and starts it again. Now I'll try to get version of ipython running to then search for vulnerabilities. 



