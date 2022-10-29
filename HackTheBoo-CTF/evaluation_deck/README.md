Hello and welcome back to another write up this one is on Hackthebox's Hacktheboo CTF 2022 web challenge evaluation deck. Let's spin up docker container and look at the page. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBoo-CTF/evaluation_deck/images/evaluation_web.png?raw=true)

It's a page with some game where u can flip cards. Let's view source code which we can download from the challenge info. It's written in Flask
so we're gonna start by looking at the routes.py file that is stored in blueprints directory. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBoo-CTF/evaluation_deck/images/evaluation_web_source.png?raw=true)

We see that it uses dangerous python function exec with our input which we can abuse.
Lets catch the POST request it sends when we flip arbitrary card and send it to repeater. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBoo-CTF/evaluation_deck/images/evaluation_web_burp.png?raw=true)

Now we need to change some value. I chose operator because I couldn't get out of the `int()` function which broke the request when I tried
to do something with it. Let's try to put python code in there and test if it works with `sleep 3` command. If we see that the response took
over 3 seconds to process we have code execution. Note that we need to escape it with ; at the begining and end. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBoo-CTF/evaluation_deck/images/evaluation_web_burp3.png?raw=true)

It was succesful. Now i couldn't get the flag with cat tac or anything like that. But i used some shell magic with regular expression to extract it
one character at the time. We know from test flag that it start with HTB{ 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBoo-CTF/evaluation_deck/images/evaluation_web_reg.png?raw=true)

With this i used intruder to bruteforce and was adding one character from response that took over 3 seconds. I might later add 
python script to automate this whole process. 

Thank you so much for reading this write up. If you have any suggestions, questions or just want to play CTFs with someone reach me out 
on Twitter or wherever else you can find me.
https://twitter.com/Vojtech1337