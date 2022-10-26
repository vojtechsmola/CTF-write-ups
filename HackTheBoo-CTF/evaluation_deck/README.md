Hello and welcome back to another write up this one is on Hackthebox's Hacktheboo CTF 2022 web challenge evaluation deck. Let's spin up docker container and look at the page. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBoo-CTF/evaluation_deck/images/evaluation_web.png?raw=true)

It's a page with some game where u can flip cards. Let's view source code which we can download from the challenge info. It's written in Flask
so we're gonna start by looking at the routes.py file that is stored in blueprints directory. 