Hello and welcome back to yet another write up. This will be write up for Tryhackme room Corridor.
As the description suggests it is about IDOR vulnerability. Normally, I would do nmap scan but since this challenge
is about IDOR I'll go visit the web page right away. 

When we visit the page we see bunch of doors. 

-- picture -- 

If we move our mouse over we can see it that we can click it or we can see
different directory on the left down. Lets' click arbitrary doors. It takes us on a page with nothing on it.
The directory name looks awfully lot like a md5hash. Trying to crack it in crackstation we get number.

-- crackstation --

Time to crack all the other hashes as well. You can either click it one by one or you can get all of them
if you press c+u on the default landing page. Then copy all the hashes. U can scrape the hashes with ```sed``` and ```awk```
```
# curl http://10.10.171.70/ | grep alt | awk '{print $3}' |  sed -e 's/^"//' -e 's/"$//' | sed 's/\<alt\>//g' | sed 's/\<=\>//g' | sed 's/=//g' | sed 's/"//g'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3213  100  3213    0     0  12070      0 --:--:-- --:--:-- --:--:-- 12078
c4ca4238a0b923820dcc509a6f75849b
c81e728d9d4c2f636f067f89cc14862c
eccbc87e4b5ce2fe28308fd9f2a7baf3
a87ff679a2f3e71d9181a67b7542122c
e4da3b7fbbce2345d7772b0674a318d5
1679091c5a880faf6fb5e6087eb1b2dc
8f14e45fceea167a5a36dedd4bea2543
c9f0f895fb98ab9159f51fd0297e236d
45c48cce2e2d7fbdea1afc51c7c6ad26
d3d9446802a44259755d38e6d163e820
6512bd43d9caa6e02c990b0a82652dca
c20ad4d76fe97759aa27a0c99bff6710
c51ce410c124a10e0db5e4b97fc2af39
```
