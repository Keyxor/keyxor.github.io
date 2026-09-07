---
title: "BroScience — Remediation: Findings, Severity, and Fixes"
summary: "Six findings, none exotic, none optional. Code-level fixes, a sequencing order that is deliberately not severity order, and CVSS scoring with the alternates spelled out."
date: 2026-09-06
draft: true
tier: full
categories:
  - Defensive
tags:
  - BroScience
  - Hack The Box
  - Linux
  - PHP
  - CVSS
  - Vulnerability Management
  - Secure Coding
ShowToc: true
TocOpen: false
---

**Target:** BroScience, a bodybuilding community site (Hack The Box, Linux/Debian 11)

**Scope of this page:** findings, severity, and remediation. Exploitation detail for each finding is on the [attack page](../../offensive/broscience/). Detection content for the same chain is on the [detection page](../broscience-detection/).

**Result:** six findings, all six load bearing for the path from an anonymous HTTP request to root.

## Summary

A PHP application behind Apache, with PostgreSQL on loopback and a root cron job renewing a TLS certificate that lives in a user's home directory.

None of the six findings is exotic. A `path=` parameter, a `rand()` where `random_bytes()` belonged, an `unserialize()` on a cookie, and an unquoted variable in a shell script. All four patterns turn up in production code, and three of them would survive a casual review.

The chain is unusual in that no single finding is sufficient and no single finding is optional. The file read yields no code execution on its own; it yields source. The predictable activation code yields an account, not privilege. The deserialization sink is unreachable without a session. What makes the application critical is the sequence, which is why the composite score is materially higher than any individual finding.

The cheapest control that would have stopped everything sits outside the application code: `www-data` should not have write access to the document root. The gadget chain still fires, `fwrite()` fails, and there is no webshell.

## Findings

| # | Vulnerability | CWE | OWASP 2021 | Location | CVSS v3.1 |
|---|---|---|---|---|---|
| V1 | Directory traversal via double URL encoding, leading to arbitrary file read and source disclosure | CWE-22, CWE-174 | A01 | `includes/img.php` (`path`) | 7.5 High |
| V2 | Predictable activation code from a time-seeded PRNG | CWE-338, CWE-330 | A02 | `utils.php`, `generate_activation_code()` | 6.5 Medium |
| V3 | Deserialization of untrusted data with a reachable gadget chain | CWE-502 | A08 | `utils.php`, `get_theme()` | 8.8 High |
| V4 | Hardcoded database credentials and password salt in a web-readable file | CWE-798, CWE-312 | A07 | `includes/db_connect.php` | 7.5 High |
| V5 | Fast hash with a single global salt | CWE-916, CWE-759 | A02 | `register.php` | 7.5 High |
| V6 | OS command injection in a root-executed cron script | CWE-78 | A03 | `/opt/renew_cert.sh` | 7.8 High |

Two configuration weaknesses are not scored as separate findings but are load bearing, and both appear in the priority table below: the document root is writable by `www-data`, and a root cron job reads a file from a user's home directory.

## Remediation

### V1, directory traversal and source disclosure

The `path` parameter is checked for traversal sequences and then decoded again downstream, so the filter and the filesystem call are looking at two different strings. `..%252f` reads as the literal text `..%2f` when it is checked and becomes `../` after a later decode.

```php
<?php
// Decode repeatedly BEFORE validating, until the string stops changing.
$raw = $_GET['path'] ?? '';
do { $prev = $raw; $raw = urldecode($raw); } while ($raw !== $prev);

// Allowlist of identifiers, not a sanitized filesystem path.
$allowed = ['default' => 'default.png', 'a1' => 'avatar_1.png', 'a2' => 'avatar_2.png'];
if (!isset($allowed[$raw])) { http_response_code(404); exit; }

// Canonicalize and confirm containment as defense in depth.
$base = realpath('/var/www/html/images/');
$file = realpath($base . DIRECTORY_SEPARATOR . $allowed[$raw]);
if ($file === false || strpos($file, $base . DIRECTORY_SEPARATOR) !== 0) { http_response_code(404); exit; }

header('Content-Type: image/png');
readfile($file);
```

The allowlist is the change that matters. Denylist traversal filters lose to encoding variants indefinitely, and this one lost to the first double-encoded payload tried. The `realpath()` containment check is defense in depth for the case where someone later replaces the allowlist with something more permissive.

Better still, avatars do not need to go through PHP at all. Serving them as static files removes the code that resolves a client-supplied string into a path, and the vulnerability class with it.

Short term, ModSecurity with CRS rules 930100 and 930110 plus `t:urlDecodeUni` applied twice, so the WAF normalizes to the same string PHP will eventually see. A WAF that decodes once and PHP that decodes twice reproduces the original bug at a different layer.

### V2, predictable activation code

`srand(time())` seeds a non-cryptographic PRNG with a value the server publishes in the `Date:` header of every response. A 32-character code drawn from a 62-character alphabet has a nominal keyspace of 62^32 and an actual keyspace of about eleven.

```php
function generate_activation_code(): string {
    return bin2hex(random_bytes(32));
}
```

`random_bytes()` and `random_int()` are the only PHP randomness functions appropriate for anything security relevant. `rand()`, `mt_rand()`, `shuffle()`, `str_shuffle()` and `uniqid()` are not, regardless of how they are seeded.

Supporting changes, each of which independently degrades the attack: store the code hashed rather than in cleartext, expire it in 15 to 60 minutes, make it single use, compare with `hash_equals()`, and rate-limit `/activate.php` per source address and per account. Eleven failed activation attempts against one account should raise an alert, not return eleven HTTP 200s.

### V3, PHP object injection

A base64 cookie is passed to `unserialize()` with no signature, no allowlist, and no `allowed_classes` restriction. The `AvatarInterface` class in the same file defines `__wakeup()`, which fires automatically during reconstruction and passes two attacker-controlled properties into a `fopen()`/`fwrite()`/`file_get_contents()` sink.

Ordered best to worst.

**Fix 1, do not serialize objects into client-controlled storage.** A theme preference is a string.

```php
function get_theme(): string {
    $theme = $_COOKIE['user-prefs'] ?? 'light';
    return in_array($theme, ['light', 'dark'], true) ? $theme : 'light';
}
```

**Fix 2, if structured data is genuinely needed, use JSON.** `json_decode($data, true)` returns arrays and invokes no magic methods, so there is no gadget chain to find.

**Fix 3, if `unserialize()` has to stay, restrict classes and authenticate the blob.**

```php
$data = $_COOKIE['user-prefs'] ?? '';
[$mac, $payload] = array_pad(explode('.', $data, 2), 2, '');
if (!hash_equals(hash_hmac('sha256', $payload, $SERVER_SECRET), $mac)) { /* reject */ }
$up = unserialize(base64_decode($payload), ['allowed_classes' => ['UserPrefs']]);
```

**Fix 4, harden the sink independently of the injection point.** `allow_url_fopen = Off` removes the remote-fetch half of the gadget, and `open_basedir` restricts where PHP can write. Neither fixes the deserialization, both break this particular chain.

**Fix 5, remove write access to the document root.** `/var/www/html` owned `root:www-data`, mode 0755. `www-data` needs to read the application, not write to it. This is the single cheapest control on the page and it does not require touching application code.

### V4, hardcoded credentials

`db_connect.php` contains the database host, port, username, password, and the global password salt, all readable through V1 without authenticating. Reading one file yields both the database credentials and the parameter needed to attack the password hashes.

Move secrets out of any web-served directory: `/etc/broscience/db.conf`, mode 0640, owned `root:www-data`, or environment variables injected by systemd, or a secrets manager. Give the application's database role only the privileges it uses, which here is SELECT, INSERT and UPDATE on `users` rather than ownership of the schema. Rotate both the database password and the salt, treating the salt rotation as a password reset cycle since it invalidates every stored hash.

### V5, weak password hashing

`md5($db_salt . $password)` is a single round of a fast hash with one salt shared across every account. A per-credential salt exists so an attacker cannot amortize work across the user table; one global salt means one candidate table computed once serves every user in the database. Combined with MD5's speed, every password in the table that appears in a wordlist falls in the time it takes to read the file.

```php
$hash = password_hash($password, PASSWORD_ARGON2ID);

if (password_verify($password, $row['password'])) {
    if (password_needs_rehash($row['password'], PASSWORD_ARGON2ID)) { /* rehash and store */ }
}
```

`password_hash()` generates a unique random salt per credential and embeds it in the output alongside the algorithm and cost parameters, which is also what makes future migration possible without a flag day. Migrate legacy hashes on next successful login and treat all existing hashes as disclosed.

### V6, command injection in the renewal script

`$commonName` is extracted from a certificate that `bill` controls, passed through several string transformations, and interpolated unquoted into a string handed to `bash -c`. The `bash -c` re-parse is where an injected `$( )` executes.

```bash
#!/bin/bash
set -euo pipefail

CERT="$1"

# Parse structured data with a structured parser, not cut/grep/awk surgery.
commonName="$(openssl x509 -in "$CERT" -noout -subject -nameopt multiline \
              | awk -F' = ' '/commonName/ {print $2}')"

# A CN is a hostname. Reject anything that is not one.
if [[ ! "$commonName" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$ ]]; then
    logger -t renew_cert "REJECTED: invalid commonName in $CERT"
    exit 1
fi

# No bash -c. No re-parsing. Quote every expansion.
mv -- /tmp/temp.crt "/home/bill/Certs/${commonName}.crt"
```

Three things changed and each one independently closes the bug: the value is validated against what a Common Name can actually contain, every expansion is quoted, and the `bash -c` re-parse is gone. `--` before the destination stops a filename that begins with a dash being read as an option.

Structurally, the more important fix is that a root job should not be reading a file out of a user's home directory. Move the certificate store to `/etc/ssl/broscience/`, root-owned, with `bill` unable to write. That removes attacker control of the input entirely and the injection becomes unreachable regardless of how the script is written. Running the renewal as a dedicated non-root service account caps the blast radius if a similar bug is reintroduced.

`shellcheck` flags the unquoted expansion as SC2086. Putting it in CI catches this class before review does.

## Priority

If the fixes have to be sequenced rather than shipped together:

| Order | Fix | Why here |
|---|---|---|
| 1 | Remove `www-data` write access to the document root | Configuration change, no code, no release. Breaks the chain at the foothold even with every application bug still present. |
| 2 | V6, fix or relocate the renewal script | Removes the path to root. Moving the certificate store is a configuration change and closes it without touching the script. |
| 3 | V3, stop deserializing the cookie | The only finding that yields code execution directly. Fix 1 is a three-line replacement. |
| 4 | V1, allowlist the avatar parameter | Closes source disclosure, which is how V3, V4 and V5 were discovered in the first place. |
| 5 | V4, move credentials and the salt out of the web root | Lower value once V1 is closed, but the file remains exposed to any future read primitive. |
| 6 | V2, replace the PRNG and rate-limit activation | Gates account creation rather than privilege. Slower to land because it touches the registration flow. |
| 7 | V5, migrate to Argon2id | Necessary, but requires a migration path and a password reset cycle for the disclosed hashes. |

The ordering is deliberately not severity order. The top two are configuration changes that break the chain without a code release, which is usually what you want in the first 24 hours of a real remediation.

## CVSS

CVSS v3.1 Base is authoritative here, with v4.0 alongside for reference. Scoring assumes a real internet-facing deployment of this application rather than a lab.

### Initial access, unauthenticated to RCE as www-data

Self-service registration, forged activation code (V2), authenticated session, object injection (V3), arbitrary file write, webshell.

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H                       Base 9.8 (Critical)
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N    Base 9.3 (Critical)
```

PR:N because registration is self-service and the activation gate is forgeable, so the attacker mints their own credentials rather than obtaining someone else's. AC:L because the attacker controls the timing, initiating the registration and therefore knowing when the seed was set, reads the seed directly from a response header, and then searches an eleven-candidate space exhaustively with a 100% success rate.

Two alternates worth stating in a report:

- AC:H if the PRNG window is treated as a genuine race condition, giving 8.1 (High). I score AC:L because the attacker observes the seed rather than racing it.
- S:C if the document root is shared with other tenants, or if `www-data` can reach another application's data, giving 10.0 (Critical). On a single-purpose host S:U is correct.

### Privilege escalation, bill to root

```text
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H                       Base 7.8 (High)
CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N    Base 8.5 (High)
```

AV:L because the vulnerability itself requires writing a file into `bill`'s home directory, even though that access was obtained remotely earlier in the chain. UI:N is deliberate: CVSS v3.1 defines User Interaction as action by a human other than the attacker, and a cron job is not a human. Assessors who mark scheduled triggers as UI:R would score this 7.0, and I think that reading is wrong.

### Per finding

| Finding | v3.1 vector | Score | Severity |
|---|---|---|---|
| V1 traversal, file read and source disclosure | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 | High |
| V2 predictable activation code | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | 6.5 | Medium |
| V3 object injection to RCE (authenticated, in isolation) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 | High |
| V4 hardcoded DB credentials and salt | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 | High |
| V5 weak password hashing | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 | High |
| V6 command injection (bill to root) | `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 7.8 | High |
| Composite, internet to root | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 | Critical |

V4 and V5 are both scored PR:N rather than PR:L because V1 exposes the credential file to an anonymous caller. Scored independently of V1, both drop to PR:L and 6.5.

S:C on the composite is justified because the initially vulnerable component, a web application running as `www-data`, is used to compromise a different security authority, the operating system's root account. That is the textbook definition of a scope change, and it is the metric most often scored wrong in reports.
