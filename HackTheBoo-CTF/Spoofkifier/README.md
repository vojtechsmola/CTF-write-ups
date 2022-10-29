Hello and welcome back to another write up. This one will be for web challenge Spookifier from Hacktheboo ctf. 
We start by visiting web page.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBoo-CTF/Spoofkifier/images/spookiefier_web.png?raw=true)

We see input field. First thing I will try is SSTI with the following payload: 
`${7*7}` and it works.

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBoo-CTF/Spoofkifier/images/spookiefier_web_payload.png?raw=true)

Now we can either try finding out which template is in use going by the following diagram:

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBoo-CTF/Spoofkifier/images/ssti.png?raw=true)

Or we can just simply look at the source code to find out it is mako. 
Next I'll search for payloads on PayloadAllTheThings(https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection). I'll just use the first one and change it up a little. 

![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBoo-CTF/Spoofkifier/images/spookiefier_web_payload1.png?raw=true)

When we send the first one with no changes it returns 0. This is return code of the system function when executed sucesfully.
Instead of system we use `popen()`. This returns nothing. We need to add `read()` so it returns string that we want. 
The final payload looks like this.
```
${self.module.cache.util.os.popen("cat ../flag.txt").read()}
```
This will gives us flag and we succesfully finished the challenge. 
![alt text](https://github.com/vojtechsmola/CTF-write-ups/blob/main/HackTheBoo-CTF/Spoofkifier/images/spookiefier_web_flag.png?raw=true)

Thank you for reading this short write up. If you have any suggestions, questions or just want to play CTFs with someone reach me out on Twitter or wherever else you can find me. https://twitter.com/Vojtech1337
