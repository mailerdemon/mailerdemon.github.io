---
layout:     post
title:      Wall
date:       2020-01-01 00:00:00
summary:    Write-up of HackTheBox's Wall.
categories: writeup
thumbnail: hammer
tags:
 - hackthebox
 - writeup
 - walkthrough

---

![](/images/wall/infocard.png)

# Initial Scan

{% highlight plaintext %}
root@kali:~/HTB/Wall# nmap 10.10.10.157 -sC -sV -oA wall.nmap
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-26 18:42 EDT
Nmap scan report for 10.10.10.157
Host is up (0.055s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 2e:93:41:04:23:ed:30:50:8d:0d:58:23:de:7f:2c:15 (RSA)
|   256 4f:d5:d3:29:40:52:9e:62:58:36:11:06:72:85:1b:df (ECDSA)
|_  256 21:64:d0:c0:ff:1a:b4:29:0b:49:e1:11:81:b6:73:66 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.05 seconds
{% endhighlight %}

# Web discovery
http://10.10.10.157 shows a standard "It works!" page, so we have to fuzz for directories and files to find anymore of a web presence. Using `gobuster` with the php file extension reveals three new pages:

SHOW GOBUSTER OUTPUT

Here's `aa.php`:

Here's `panel.php`:

And here's `/monitoring`:

![](/images/wall/image1.png)

# Trying other methods
I intercepted the three pages with Burp to see if there are any opportunities for user input, but I didn't find anything interesting. From here, I decided to change all my GET request to POST requests and see what came up. When doing this on `/monitoring`, we find an interesting redirect URL:

{% highlight html %}
HTTP/1.1 200 OK
Date: Thu, 26 Sep 2019 23:30:14 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Wed, 03 Jul 2019 22:47:23 GMT
ETag: "9a-58ccea50ba4c6-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 154
Connection: close
Content-Type: text/html
 
<h1>This page is not ready yet !</h1>
<h2>We should redirect you to the required page !</h2>

<meta http-equiv="refresh" content="0; URL='/centreon'" />
{% endhighlight %}

# Centreon login

http://10.10.10.157 shows a Centreon login page along with the version number:

![](/images/wall/image2.png)

I got stuck here for a while. I rechecked my enumeration to make sure I didn't miss any credentials, read up on Centron vulnerabilities, attempted a 2019 CVE on SQL injection, and fired up Hydra to brute-force the log in.

Strangely, what worked was some manual guesswork (using the first bunch from rockyou.txt). The right combination was admin:password1.

# RCE exploit -- the easy (?) way

Aside from the SQLi I'd mentioned, there's another 2019 CVE available for Centreon: an RCE from the maker of the box. 

INSERT THE SCRIPT

This isn't as straightforward as I'd hoped it would be though. I inserted some `print` statements throughout the script to ensure that the `requests` and `BeautifulSoup` modules weren't grabbing/parsing nonsense, and even when it seemed to be spot-on, I couldn't verify that I had command execution. So I decided to follow the script along myself and manually trigger the exploit.

# RCE exploit -- the other easy way

