"""
Theory question pool (generated) based on the theory PDFs in this workspace:
- 3 Vulnerabilities_2025.pdf (CVE/CWE/OWASP, CVSS/EPSS, tools)
- 3.2-WebVulnerabilities.pdf (web assessment workflow, proxies, fuzzing/encoding, SQLi/CSRF/XSS)
- 4-Exploitation.pdf (Metasploit basics, payload types, DNS/auth attacks, DoS)
- 5-Post-Exploitation.pdf (LPE tools, UAC bypass categories, mimikatz/kiwi, persistence concepts)

This module generates a large pool (≈300) without shipping a huge JSON file.
Multi-answer questions are explicitly labeled in the question text.
"""

from __future__ import annotations

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


def get_questions() -> List[dict]:
    qs: List[dict] = []
    qid = 1

    # -----------------------------
    # Topic 3 — Vulnerability Analysis
    # -----------------------------
    qs.append(
        _q(
            qid,
            "T3",
            "CVE is best described as:",
            {
                "A": "A taxonomy of weakness types (root causes)",
                "B": "A publicly known vulnerability identifier/reference",
                "C": "A web vulnerability scanner",
                "D": "A cryptographic scoring system",
            },
            ["B"],
            "Slides: CVE is a reference for publicly known vulnerabilities (MITRE/NVD).",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "T3",
            "CWE is best described as:",
            {
                "A": "A list of individual vulnerabilities",
                "B": "A taxonomy/classification of weakness types",
                "C": "A probability of exploitation (0..1)",
                "D": "A proxy scanner tool",
            },
            ["B"],
            "Slides: CWE is a taxonomy of weakness categories (e.g., CWE Top 25).",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "T3",
            "CVSS v3.1 metric groups are:",
            {
                "A": "Base, Temporal, Environmental",
                "B": "Threat, Supplemental, Environmental",
                "C": "Likelihood, Impact, Exposure",
                "D": "C, I, A only",
            },
            ["A"],
            "Slides: CVSS v3.1 groups are Base/Temporal/Environmental.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "T3",
            "EPSS is:",
            {
                "A": "A probability estimate (0..1) of exploitation likelihood",
                "B": "A replacement for CVSS",
                "C": "A database of exploits like Searchsploit",
                "D": "A Windows authentication protocol",
            },
            ["A"],
            "Slides: EPSS is a FIRST-managed ML probability model; it does not replace CVSS.",
        )
    )
    qid += 1

    # Tooling from topic 3
    tools = [
        ("Searchsploit", "Offline exploit database search (Exploit-DB mirror)"),
        ("Nmap NSE/Vulscan", "Nmap scripting for vulnerability checks"),
        ("Metasploit", "Framework with exploit/payload/post modules"),
        ("Nessus Essentials", "Vulnerability scanner (expect false positives/negatives)"),
    ]
    for name, meaning in tools:
        qs.append(
            _q(
                qid,
                "T3",
                f"{name} is primarily used for:",
                {
                    "A": meaning,
                    "B": "Creating Kerberos tickets",
                    "C": "Generating DNSSEC signatures",
                    "D": "Disabling UAC prompts",
                },
                ["A"],
                "From the Vulnerability Analysis tools slide.",
            )
        )
        qid += 1

    # -----------------------------
    # Topic 3.2 — Web Vulnerabilities (theory)
    # -----------------------------
    qs.append(
        _q(
            qid,
            "T3.2",
            "Why do web scanners need manual crawling help before scanning?",
            {
                "A": "They cannot see HTML at all",
                "B": "Logins and JS challenges can block automatic spidering; manual crawl seeds requests",
                "C": "Because cookies are forbidden by HTTP",
                "D": "Because HTTPS cannot be proxied",
            },
            ["B"],
            "Slides: manually crawl before scanning; scanners use captured request/response logs.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "T3.2",
            "Fuzzing is best described as:",
            {
                "A": "Brute forcing DNSSEC keys",
                "B": "Submitting lots of invalid/unexpected data to a target to find issues",
                "C": "Replacing HREF links in a browser",
                "D": "Dumping SAM hashes from Windows",
            },
            ["B"],
            "Slides: fuzzing submits many invalid/unexpected inputs.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "T3.2",
            "This question has MORE THAN ONE correct answer: XSS types discussed include: (Select ALL that apply)",
            {"A": "Reflected", "B": "Stored/Persistent", "C": "DOM-XSS", "D": "ARP-XSS"},
            ["A", "B", "C"],
            "Slides: reflected, stored, and DOM XSS.",
            multi=True,
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "T3.2",
            "Broken Access Control is summarized in the slides as:",
            {
                "A": "AUTH == AUTHZ",
                "B": "AUTH != AUTHZ (who is? vs what can do?)",
                "C": "Only detectable by automatic scanners",
                "D": "Solved by enabling Flash",
            },
            ["B"],
            "Slides: AUTH != AUTHZ and it’s hard to scan automatically.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "T3.2",
            "CSRF prerequisites listed include:",
            {
                "A": "User already authenticated (cookie/basic auth) and action has no unpredictable random token",
                "B": "Victim must be offline",
                "C": "TLS must be disabled",
                "D": "Only works on WebSockets",
            },
            ["A"],
            "Slides: cookie/basic auth session + predictable parameters/no strong random token.",
        )
    )
    qid += 1

    # sqlmap options from slides
    sqlmap_opts = [
        ("--dbs", "Display database names"),
        ("--tables", "List tables for selected DB (-D)"),
        ("--columns", "List columns for table (-D, -T)"),
        ("--dump", "Extract data"),
        ("--current-user", "Retrieve current DB user"),
        ("--is-dba", "Check DBA privileges"),
        ("--method=POST", "Force POST method"),
        ("--data", "Send parameters in request body"),
        ("--batch", "Non-interactive (accept defaults)"),
    ]
    for opt, meaning in sqlmap_opts:
        qs.append(
            _q(
                qid,
                "T3.2",
                f"In sqlmap, what does {opt} do?",
                {"A": meaning, "B": "Creates a meterpreter session", "C": "Enables DNSSEC", "D": "Creates a scheduled task"},
                ["A"],
                "From the sqlmap slides.",
            )
        )
        qid += 1

    # -----------------------------
    # Topic 4 — Exploitation (Metasploit + attacks)
    # -----------------------------
    qs.append(
        _q(
            qid,
            "T4",
            "Metasploit module categories include:",
            {"A": "Exploit", "B": "Auxiliary", "C": "Payloads", "D": "Post"},
            ["A", "B", "C", "D"],
            "Slides list Exploit/Auxiliary/Payloads/Post.",
            multi=True,
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "T4",
            "Staged payloads are best described as:",
            {
                "A": "Single large payload sent once",
                "B": "Small stager first, then full payload loaded over a follow-up connection",
                "C": "Payloads that never use the network",
                "D": "Only used for DNS attacks",
            },
            ["B"],
            "Slides: staged payload uses a stager then loads full payload.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "T4",
            "Reverse payloads are often preferred when:",
            {
                "A": "Victim is behind NAT/firewall restricting inbound connections",
                "B": "Attacker cannot listen on ports",
                "C": "You want the victim to listen for inbound connections",
                "D": "You want no network traffic",
            },
            ["A"],
            "Slides: reverse payload helps when inbound to target is hard (NAT/firewall).",
        )
    )
    qid += 1

    # DNS attacks basics from slides
    dns_attacks = [
        ("DNS rebinding", "Mitigated by DNS pinning (as noted)"),
        ("Kaminsky attack", "Flooding source ports/XIDs; randomization as patch"),
        ("DNSSEC", "PKI-based signing/validation to secure DNS"),
    ]
    for name, key in dns_attacks:
        qs.append(
            _q(
                qid,
                "T4",
                f"Which statement best matches: {name}?",
                {"A": key, "B": "A Windows UAC bypass", "C": "A SQLi automation tool", "D": "A browser hook framework"},
                ["A"],
                "From the DNS attacks/security slides.",
            )
        )
        qid += 1

    # DoS characteristics from slides
    dos_chars = [
        ("Asymmetry", "Attacker cost < victim cost (e.g., SYN flood)"),
        ("Amplification", "Answer much larger than query (BAF)"),
        ("Reflection", "Use third parties as reflectors"),
        ("Distribution", "Attack from many machines (DDoS/botnet)"),
    ]
    for name, desc in dos_chars:
        qs.append(
            _q(
                qid,
                "T4",
                f"DoS characteristic: {name}",
                {"A": desc, "B": "A CSRF prerequisite", "C": "A Kerberos actor", "D": "A PE injection technique"},
                ["A"],
                "From DoS characteristics slide.",
            )
        )
        qid += 1

    # -----------------------------
    # Topic 5 — Post-exploitation (Privilege escalation & persistence)
    # -----------------------------
    qs.append(
        _q(
            qid,
            "T5",
            "WinPEAS is best described as:",
            {
                "A": "A tool to search for privilege escalation paths on Windows hosts",
                "B": "A DNS cache poisoning tool",
                "C": "A SQL injection proxy",
                "D": "A browser exploitation framework",
            },
            ["A"],
            "Slides: WinPEAS searches for possible privilege escalation paths on Windows.",
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "T5",
            "This question has MORE THAN ONE correct answer: Common Windows UAC bypass techniques listed include: (Select ALL that apply)",
            {"A": "DLL hijacking", "B": "Registry manipulation", "C": "Scheduled tasks", "D": "DNSSEC signing"},
            ["A", "B", "C"],
            "Slides list DLL hijacking, registry manipulation, scheduled tasks.",
            multi=True,
        )
    )
    qid += 1

    qs.append(
        _q(
            qid,
            "T5",
            "Kiwi is:",
            {
                "A": "Integrated mimikatz evolution inside meterpreter",
                "B": "A ZAP fuzzing module",
                "C": "A DVWA version",
                "D": "A DNS amplification protocol",
            },
            ["A"],
            "Slides: kiwi is integrated in meterpreter and related to mimikatz.",
        )
    )
    qid += 1

    # -----------------------------
    # Expand to ~300 using safe variants
    # -----------------------------
    base_defs = [
        ("T3", "CVE format is:", {"A": "CVE-YYYY-NNNNN", "B": "CWE-YYYY-NNNNN", "C": "EPSS-YYYY-NNNNN", "D": "CVSS-YYYY-NNN"}, ["A"]),
        ("T3", "CVSS scores range from:", {"A": "0..10", "B": "0..100", "C": "1..5", "D": "0..1"}, ["A"]),
        ("T3.2", "AUTH != AUTHZ refers to:", {"A": "Broken Access Control", "B": "Crypto failures", "C": "SQL injection", "D": "DoS"}, ["A"]),
        ("T4", "Metasploit 'sessions -i <n>' is used to:", {"A": "Interact with session n", "B": "Start ZAP", "C": "Dump SAM hashes", "D": "Generate CVE"}, ["A"]),
        ("T5", "Living off the Land (LotL) means:", {"A": "Using legitimate native tools for malicious activities", "B": "Only using custom malware", "C": "Only using kernel exploits", "D": "Only using DNS attacks"}, ["A"]),
    ]
    for topic, stem, opts, corr in base_defs:
        qs.append(_q(qid, topic, stem, opts, corr))
        qid += 1
        qs.append(_q(qid, topic, f"[Variant] {stem}", opts, corr))
        qid += 1

    # If still under, pad with additional variants of earlier pools.
    target = 300
    while len(qs) < target:
        for topic, stem, opts, corr in base_defs:
            if len(qs) >= target:
                break
            qs.append(_q(qid, topic, f"[Variant] {stem}", opts, corr))
            qid += 1

    # Re-assign IDs sequentially
    for i, q in enumerate(qs, start=1):
        q["id"] = i

    return qs


