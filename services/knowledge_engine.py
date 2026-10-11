"""
CyberGPT Knowledge Engine — CyBOK v1.1.0 Local Ontology
====================================================================
Provides instant (<10ms, 0 tokens, fully offline) pedagogical
answers for defensive-security concept questions, indexed against
the complete CyBOK v1.1.0 syllabus (21 Knowledge Areas across
5 categories).

Architecture:
  * KnowledgeNode — structured node: concept id, title, CyBOK KA
    mapping, plain definition, everyday analogy, core pillars,
    technical mechanics, detection telemetry (only for
    attack/detection topics — never forced onto pure concepts),
    real-world examples, standards, and mapped lab IDs.
  * Fuzzy query matcher — lowercase + punctuation stripping +
    typo normalization ("secuirty", "zerotrust", "passthehash",
    "sqli", "it vs ot", Roman Urdu variants).
  * Pedagogical renderer — natural Claude/ChatGPT-style markdown:
    plain definition & analogy, core pillars, practical mechanics,
    real-world examples & standards. No forced incident-triage
    headers on concept questions.
  * Dynamic lab chips — up to 2 verified lab objects resolved from
    the real data/labs/*.json catalog (never inline strings).

This module never performs network I/O and never imports the LLM
service, so it remains a hard offline fallback when external
providers return 408/429/503 or time out.
"""

from __future__ import annotations

import re
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

from services.scenario_manager import LAB_REPOSITORY

logger = logging.getLogger(__name__)

ENGINE_ID = "cybok-engine-v1.1.0"

# ============================================================================
# CyBOK v1.1.0 — 21 Knowledge Areas across 5 categories
# ============================================================================
CYBOK_KA_INDEX: Dict[str, Dict[str, str]] = {
    "A1": {"name": "Risk Management & Governance", "category": "Human, Organisational & Regulatory Aspects"},
    "A2": {"name": "Law & Regulation", "category": "Human, Organisational & Regulatory Aspects"},
    "A3": {"name": "Human Factors", "category": "Human, Organisational & Regulatory Aspects"},
    "A4": {"name": "Privacy & Online Rights", "category": "Human, Organisational & Regulatory Aspects"},
    "B5": {"name": "Malware & Attack Technologies", "category": "Attacks & Defences"},
    "B6": {"name": "Adversarial Behaviours", "category": "Attacks & Defences"},
    "B7": {"name": "Security Operations & Incident Management", "category": "Attacks & Defences"},
    "B8": {"name": "Forensics", "category": "Attacks & Defences"},
    "C9": {"name": "Cryptography", "category": "Systems Security"},
    "C10": {"name": "Operating Systems & Virtualisation Security", "category": "Systems Security"},
    "C11": {"name": "Distributed Systems Security", "category": "Systems Security"},
    "C12": {"name": "Formal Methods for Security", "category": "Systems Security"},
    "C13": {"name": "Authentication, Authorisation & Accountability", "category": "Systems Security"},
    "D14": {"name": "Software Security", "category": "Software & Platform Security"},
    "D15": {"name": "Web & Mobile Security", "category": "Software & Platform Security"},
    "D16": {"name": "Secure Software Lifecycle", "category": "Software & Platform Security"},
    "E17": {"name": "Applied Cryptography", "category": "Infrastructure Security"},
    "E18": {"name": "Network Security", "category": "Infrastructure Security"},
    "E19": {"name": "Hardware Security", "category": "Infrastructure Security"},
    "E20": {"name": "Cyber-Physical Systems (CPS) / ICS-SCADA", "category": "Infrastructure Security"},
    "E21": {"name": "Physical Layer & Telecommunications Security", "category": "Infrastructure Security"},
}


# ============================================================================
# Knowledge node model
# ============================================================================
@dataclass
class KnowledgeNode:
    concept_id: str
    title: str
    ka_ref: str                      # CyBOK KA code, e.g. "A1"
    category: str                    # CyBOK category name
    plain_definition: str           # 2-4 sentences, plain language
    analogy: str                     # everyday intuitive analogy
    core_pillars: List[str]          # principles & pillars
    technical_domains: List[str]     # practical mechanics / domains
    real_world: List[str]            # real-world examples & standards
    keywords: List[str]              # matcher aliases (incl. typo variants)
    detection_telemetry: List[str] = field(default_factory=list)  # SOC lens only where relevant
    comparison_table: Optional[Dict[str, Any]] = None              # {"headers": [...], "rows": [[...]]}
    mapped_lab_ids: List[str] = field(default_factory=list)        # validated against LAB_REPOSITORY
    roman_urdu: List[str] = field(default_factory=list)            # Roman Urdu / Urdu aliases


# ============================================================================
# Node catalogue — Category A (Human, Organisational & Regulatory)
# ============================================================================
_NODES: List[KnowledgeNode] = [
    KnowledgeNode(
        concept_id="cybersecurity-fundamentals",
        title="What Is Cyber Security?",
        ka_ref="A1",
        category="Human, Organisational & Regulatory Aspects",
        plain_definition=(
            "Cyber security (information security) is the practice of protecting systems, "
            "networks, programs, and data from digital attacks, unauthorised access, damage, "
            "or disruption. Its core purpose is to preserve the CIA Triad — Confidentiality, "
            "Integrity, and Availability — while managing risk to an acceptable level for the "
            "organisation. It spans technology, processes, and people: firewalls and encryption "
            "are meaningless if staff click phishing links or patching is skipped."
        ),
        analogy=(
            "Think of cyber security like securing a house: locks on the doors (authentication), "
            "curtains on the windows (confidentiality), a home alarm (detection), insurance and "
            "a fireproof safe (recovery), and family rules about not opening the door to "
            "strangers (awareness). No single measure works alone — security is a layered habit."
        ),
        core_pillars=[
            "**Confidentiality** — only authorised people/systems can read data (encryption, access control).",
            "**Integrity** — data and systems are accurate and tamper-evident (hashing, digital signatures, logging).",
            "**Availability** — authorised users can access systems when needed (redundancy, backups, DDoS defence).",
            "**Defense-in-Depth** — multiple overlapping layers so one failure never equals a breach.",
            "**Least Privilege** — every user and process gets the minimum access required, nothing more.",
            "**Risk Management** — controls are chosen by comparing threat likelihood and impact against cost.",
        ],
        technical_domains=[
            "**Network Security** — firewalls, IDS/IPS, segmentation, DNS filtering, Zero Trust access.",
            "**Endpoint Security** — EDR, patching, hardening baselines, application allow-listing.",
            "**Application Security** — secure coding (SAST/DAST), WAFs, input validation, dependency hygiene.",
            "**Identity & Access Management (IAM)** — MFA, Single Sign-On, privileged access management (PAM).",
            "**Data Security** — classification, encryption at rest/in transit, DLP, retention policies.",
            "**Cloud Security** — CSPM, CIEM, workload identity, shared-responsibility mapping.",
            "**Security Operations (SecOps)** — SIEM monitoring, alert triage, SANS PICERL incident response.",
            "**Governance** — policies, awareness training, compliance (ISO 27001, NIST CSF, PCI DSS).",
        ],
        detection_telemetry=[
            "Windows Event IDs 4624/4625 (logon success/failure), 4688 (process creation), 1102 (audit log cleared).",
            "Sysmon Event IDs 1 (process), 3 (network), 7 (image load), 22 (DNS query) for endpoint visibility.",
            "NetFlow/Syslog anomalies and SIEM correlation rules convert raw telemetry into alerts.",
        ],
        real_world=[
            "Frameworks: **NIST Cybersecurity Framework** (Identify-Protect-Detect-Respond-Recover), **ISO/IEC 27001**, **CIS Critical Controls**, **MITRE ATT&CK**.",
            "Real breaches teach the pillars: WannaCry hit *Availability* via unpatched SMB; Equifax lost *Confidentiality* via an unpatched web app; NotPetya destroyed *Integrity* of the M&E global shipping terminal.",
            "Modern posture converges on **Zero Trust** and **continuous monitoring** instead of a hard perimeter.",
        ],
        keywords=[
            "what is cyber security", "cyber security", "cybersecurity", "information security",
            "infosec", "info sec", "what is information security", "define cyber security",
            "cyber secuirty", "cybersecurity basics", "security fundamentals", "introduction to cyber security",
            "what does cyber security mean", "cyber security kya hai", "cyber security meaning",
            "security", "what is security",
        ],
        roman_urdu=["cyber security kya hai", "cyber security samjhao"],
        mapped_lab_ids=["siem-01", "pw-01"],
    ),
    KnowledgeNode(
        concept_id="risk-management-governance",
        title="Risk Management & Governance (CyBOK KA1)",
        ka_ref="A1",
        category="Human, Organisational & Regulatory Aspects",
        plain_definition=(
            "Risk management is the disciplined process of identifying, analysing, evaluating, "
            "and treating uncertainty about cyber threats, then monitoring the results "
            "continuously. Governance is the board-level system that directs it: roles, "
            "accountability, policy, and assurance. Security risk is classically expressed as "
            "a function of Threat, Vulnerability, and Impact — you manage what you can measure."
        ),
        analogy=(
            "It is like deciding whether to drive in a storm: you assess the threat (storm), "
            "your vulnerability (worn tyres), the impact (crash cost), and then choose "
            "treatment — avoid, mitigate (new tyres), transfer (insurance), or accept. "
            "Governance is the family rule that says the decision gets made *before* leaving."
        ),
        core_pillars=[
            "**Risk appetite & tolerance** — how much residual risk the board formally accepts (ALARP/ALARA: as low as reasonably practicable).",
            "**Renn's risk types** — Routine, Complex, Uncertain, and Ambiguous risks need different processes; treating an Ambiguous risk as Routine is a classic failure.",
            "**Rasmussen hierarchy** — work flows from Functional (goals) to Physical (equipment); failures drift when safety work defences erode.",
            "**Just Culture (Dekker)** — punish reckless deviation, not honest error, or staff stop reporting near-misses.",
            "**Security metrics (Jaquith)** — a good metric is cheap to gather, expressed as probabilities or ratios, and speaks to the board in its language.",
        ],
        technical_domains=[
            "**Standards**: ISO 31000 (generic risk), ISO/IEC 27005 (security risk), NIST SP 800-30 (assessment), SP 800-37 (RMF), SP 800-39 (organisation-wide).",
            "**Quantitative methods**: FAIR (Frequency × Magnitude in currency), Octave Allegro (operational, workshop-driven).",
            "**Threat modelling**: STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation), Attack Trees, STAMP/STPA-Sec (system-theoretic safety-security analysis).",
            "**Enterprise architecture alignment**: TOGAF, O-DM (outsourcing DMZ), SABSA (business-driven security architecture).",
            "**Treatment options**: avoid, mitigate, transfer (cyber insurance), accept — always documented with an owner and review date.",
        ],
        real_world=[
            "Boards increasingly use FAIR to price cyber risk in currency, making insurance and control budgets comparable.",
            "Equifax's unpatched Apache Struts became a textbook governance failure: known vulnerability, no owner, no deadline.",
            "CyBOK places risk at the top of Category A because every other KA ultimately reports into it.",
        ],
        keywords=[
            "risk management", "risk governance", "security governance", "risk assessment",
            "iso 27005", "iso 31000", "nist sp 800-30", "nist 800-37", "fair", "octave allegro",
            "stride", "attack tree", "attack trees", "stampa", "stamp", "stpa", "alarp",
            "risk appetite", "risk register", "threat modelling", "threat modeling",
            "risk management kya hai", "what is risk management",
        ],
        roman_urdu=["risk kya hai", "risk management samjhao"],
        mapped_lab_ids=["cloud-02", "siem-03"],
    ),
    KnowledgeNode(
        concept_id="law-regulation",
        title="Law & Regulation (CyBOK KA2)",
        ka_ref="A2",
        category="Human, Organisational & Regulatory Aspects",
        plain_definition=(
            "Cyber security law defines what organisations must do, what they must never do, "
            "and who can enforce it. Legal systems are prescriptive (rules written in advance) "
            "or juridical (courts interpret broad principles after the fact). Jurisdiction may "
            "be enforcement-based, and obligations can follow the data (in rem) or the person "
            "(in personum). Practically: a SOC analyst's triage notes can become court exhibits, "
            "and breach notification has statutory clocks."
        ),
        analogy=(
            "Prescriptive law is like a recipe you must follow exactly; juridical law is like a "
            "judge tasting the cake and deciding if it breaks the rules. Your data is the "
            "traveller: even if it leaves your kitchen, the health inspector (regulator) can "
            "still follow it across borders — unless the law says otherwise."
        ),
        core_pillars=[
            "**GDPR** — territorial scope (Art. 3), principles (Art. 5), privacy by design & default (Art. 25), security of processing (Art. 32), breach notification within 72 hours (Art. 33), international transfers (Arts. 44-49), administrative fines (Art. 83).",
            "**Budapest Convention (ETS 185)** — the first international treaty on cybercrime; procedural powers plus fast cross-border preservation.",
            "**UK Computer Misuse Act 1990** — unauthorised access, access with intent to commit further offences, unauthorised modification (renamed Computer Misuse and Online Safety Act 2023 context).",
            "**US CFAA** — federal anti-hacking statute; courts debate what 'exceeds authorised access' means.",
            "**Data sovereignty & CLOUD Act** — where data physically sits determines whose government can compel it; the US CLOUD Act reaches data held abroad by US providers.",
            "**Private law exposure** — negligence (duty of care; Learned Hand formula B < P×L: no breach if the burden of precaution is less than probability × loss), vicarious liability, breach of contract, warranties.",
        ],
        technical_domains=[
            "**PCI DSS** — contractual, prescriptive card-industry standard; network segmentation, key management, logging all auditable.",
            "Evidence handling: chain of custody, admissibility standards (US: Daubert; UK: Civil/Criminal Procedure Rules).",
            "Cross-border investigation: Mutual Legal Assistance Treaties vs. direct CLOUD Act orders.",
            "Sector overlays: HIPAA (health), GLBA (finance), NIS2/DORA (EU critical infrastructure).",
        ],
        real_world=[
            "British Airways was fined £20M under GDPR after Magecart-skimming breached Art. 32.",
            "The US Supreme Court's *Van Buren* (2021) narrowed the CFAA for authorised users who misuse access.",
            "POLICIES: a SOC lead should know their national breach-notification deadline before an incident, not during one.",
        ],
        keywords=[
            "law", "regulation", "legal", "gdpr", "data protection", "computer misuse act",
            "cfaa", "budapest convention", "pci dss", "data sovereignty", "cloud act",
            "jurisdiction", "negligence", "learned hand", "breach notification",
            "privacy law", "compliance", "what is gdpr", "law and regulation",
            "cyber law", "cybercrime law", "legal aspects of security",
        ],
        roman_urdu=["cyber law kya hai", "kanoon"],
        mapped_lab_ids=["cloud-01", "phish-01"],
    ),
    KnowledgeNode(
        concept_id="human-factors",
        title="Human Factors (CyBOK KA3)",
        ka_ref="A3",
        category="Human, Organisational & Regulatory Aspects",
        plain_definition=(
            "Human factors studies how people actually interact with security, because the "
            "user is both the weakest link and the last line of defence. It covers usable "
            "security (do the secure behaviours even work under pressure?), mental models "
            "(does the user's picture of the threat match reality?), cognitive load (security "
            "that requires thought gets skipped), and measurable awareness programmes rather "
            "than once-a-year slide decks."
        ),
        analogy=(
            "A door with a confusing lock gets propped open with a fire extinguisher. "
            "The lock was not broken — the *design* ignored the human. Usable security "
            "designs the door so the secure path is the easy path."
        ),
        core_pillars=[
            "**Usable security** — if the safe option is harder than the unsafe one, the unsafe one wins.",
            "**Cognitive load & cognitive biases** — phishing exploits urgency, authority, and fear precisely when thinking capacity is lowest.",
            "**Mental models** — users who picture hackers as hooded strangers miss the colleague whose badge was cloned.",
            "**Social engineering** — pretexting, phishing/quishing, vishing, tailgating; attacks on the human protocol, not the code.",
            "**Awareness metrics** — measure simulated-phish click rates over time and reporting rates, not attendance sheets.",
        ],
        technical_domains=[
            "Password policy realism: NIST SP 800-63B favours length + screened-against-breach lists over forced symbol rotation.",
            "Security nudges: password managers auto-filled, MFA prompts contextualised, warning screens written in plain language.",
            "Phishing simulation programmes with immediate, blame-free coaching (Just Culture).",
            "Interface anti-patterns: certificate warnings, 'click Allow' fatigue, and dark patterns that train users to bypass.",
        ],
        detection_telemetry=[
            "User-reported phishing (report-button telemetry) is one of the highest-signal, lowest-cost SOC detections available.",
            "Anomalous mailbox rules (attacker-created forwarding/filters) often follow a successful phish — alert on Mailbox rule creation events.",
        ],
        real_world=[
            "Verizon DBIR consistently attributes a majority of breaches to the human element — phishing, error, stolen credentials.",
            "Multi-factor prompt fatigue (MFA bombing) defeated Uber's defences in 2022 via a contractor's approval fatigue.",
            "Standards: ISO 9241 (ergonomics), NIST SP 800-63B (identity assurance), Loughborough SUS-scale tradition for usability measurement.",
        ],
        keywords=[
            "human factors", "usable security", "usability", "social engineering",
            "security awareness", "phishing psychology", "cognitive load", "mental models",
            "why do people click phishing", "user behavior", "user behaviour", "people weakest link",
            "human element",
        ],
        roman_urdu=["insani factor", "log dhoka kaise khatay hain"],
        mapped_lab_ids=["phish-01", "phish-06"],
    ),
    KnowledgeNode(
        concept_id="privacy-online-rights",
        title="Privacy & Online Rights (CyBOK KA4)",
        ka_ref="A4",
        category="Human, Organisational & Regulatory Aspects",
        plain_definition=(
            "Privacy engineering protects individuals' control over their personal data. It "
            "distinguishes pseudonymisation (still personal data — reversible with a key) "
            "from anonymisation (irreversible, out of GDPR scope when done truly). It applies "
            "Privacy Enhancing Technologies (PETs), minimises what is collected, and worries "
            "about metadata as much as content — who you talk to, when, and from where."
        ),
        analogy=(
            "Pseudonymisation is writing 'Patient 47' on a hospital file while the names live "
            "in a locked drawer — anyone with the drawer key re-identifies everyone. True "
            "anonymisation burns the drawer. Metadata is the envelope: even sealed, the "
            "address, timing, and weight tell a story."
        ),
        core_pillars=[
            "**Data minimisation & purpose limitation** — collect the least data, for the stated purpose, keep it the shortest defensible time.",
            "**Pseudonymisation ≠ anonymisation** — pseudonymised data remains personal data under GDPR Recital 26.",
            "**PETs** — k-anonymity, l-diversity, t-closeness, homomorphic encryption, secure multi-party computation, private set intersection.",
            "**Differential privacy** — add calibrated noise so aggregate statistics stay useful while any single individual's contribution is deniable.",
            "**Inference control & metadata confidentiality** — prevent re-identification by cross-correlation; protect traffic analysis, not just payloads.",
        ],
        technical_domains=[
            "k-anonymity: each record indistinguishable from at least k-1 others on identifying attributes; attacks: homogeneity and background knowledge.",
            "Differential privacy budget (epsilon): smaller epsilon = stronger privacy, noisier results; composition across repeated queries.",
            "Onion routing (Tor), encrypted DNS (DoH/DoT), and padding defend metadata confidentiality.",
            "Consent & preference management as code: purpose binding, retention automation, DSAR (data subject access request) workflows.",
        ],
        real_world=[
            "Netflix Prize de-anonymisation: researchers re-identified users by cross-correlating public IMDb reviews.",
            "Apple and Google deploy local differential privacy in telemetry — aggregate insight without a per-user dossier.",
            "GDPR Art. 25 (privacy by design/default) is the legal forcing function; privacy engineering patterns make it real.",
        ],
        keywords=[
            "privacy", "online privacy", "pets", "privacy enhancing technologies",
            "pseudonymisation", "pseudonymization", "anonymisation", "anonymization",
            "differential privacy", "k anonymity", "k-anonymity", "metadata",
            "data minimisation", "data minimization", "gdpr privacy", "data protection",
            "inference control", "re identification",
        ],
        roman_urdu=["privacy kya hai"],
        mapped_lab_ids=["cloud-01", "phish-03"],
    ),
    KnowledgeNode(
        concept_id="malware-attack-technologies",
        title="Malware & Attack Technologies (CyBOK KA5)",
        ka_ref="B5",
        category="Attacks & Defences",
        plain_definition=(
            "Malware is any software intentionally built to violate confidentiality, integrity, "
            "or availability. CyBOK classifies it by behaviour and propagation: viruses "
            "(infect hosts), worms (self-propagate), trojans (masquerade), rootkits (hide "
            "below the OS), ransomware (extort via encryption), botnets (armies for rent), "
            "fileless malware (code in memory/interpreter), and PUPs (unwanted, grey-zone). "
            "Analysis splits into static (without execution) and dynamic (sandboxed execution)."
        ),
        analogy=(
            "A virus needs you to open the infected attachment; a worm walks through every "
            "unlocked door by itself; a trojan knocks politely dressed as an installer; a "
            "rootkit repaints the hallway so you cannot see it standing there; ransomware "
            "changes all the locks and sells you the key."
        ),
        core_pillars=[
            "**Taxonomy by propagation & payload** — how it spreads defines the outbreak curve; what it does defines the damage.",
            "**Static analysis** — PE header/section inspection, disassembly, string/import mining, YARA signatures; safe but blind to packed logic.",
            "**Dynamic analysis** — detonate in a sandbox, watch API calls, file writes, mutexes, and C2 beacons; catches packed and staged malware.",
            "**Fuzzing & concolic execution** — throw mutated inputs (or symbolic-execution-guided inputs) at parsers to crash out vulnerabilities before attackers do.",
            "**Anti-analysis & evasion** — packing/crypting, anti-VM checks, timing bombs, environment probes (sleep, mouse movement), LOLBins and fileless execution.",
        ],
        technical_domains=[
            "Static triage: PE header anomalies (section entropy, imports like VirtualAlloc + WriteProcessMemory), embedded strings, Packer/compile timestamps, YARA rule authoring.",
            "Dynamic triage: sandbox detonation, API call tracing, mutex and file-drop artefact capture, C2 domain extraction, config deobfuscation.",
            "Persistence inventory: Run keys, services, scheduled tasks, WMI subscriptions, COM hijacks — where every family must eventually live.",
            "Evasion engineering: process injection (DLL/thread hollowing), reflective loading, script interpreters (PowerShell, WSH), and staged loaders that fetch payloads only when needed.",
        ],
        detection_telemetry=[
            "Sysmon Event 1 (process creation) with unusual parent chains, Event 7 (image load) for DLL sideloading, Event 11 (file drop) for staging.",
            "Windows Event 7045 (new service install) is a classic PsExec/worm persistence tell.",
            "Sandbox telemetry: DNS beacons with DGA patterns, encoded PowerShell (-enc), and curl/certutil download cradles.",
        ],
        real_world=[
            "WannaCry combined a worm (EternalBlue SMB) with ransomware — propagation speed beat every human patch cycle.",
            "Emotet evolved from banking trojan to a malware distribution platform for rent — malware-as-a-service economics.",
            "Fileless attacks (PowerShell implants, reflective DLL injection) force defenders to monitor behaviour, not just files.",
        ],
        keywords=[
            "malware", "virus", "worm", "trojan", "rootkit", "botnet", "botnets",
            "fileless malware", "pup", "potentially unwanted", "ransomware", "cryptolocker",
            "static analysis", "dynamic analysis", "sandbox", "packing", "packer",
            "anti analysis", "evasion", "fuzzing", "concolic", "symbolic execution",
            "yara", "malware analysis", "malware taxonomy", "what is malware",
            "virus vs worm", "trojan horse",
        ],
        roman_urdu=["malware kya hai", "virus kya hai"],
        mapped_lab_ids=["endpoint-02", "phish-04", "soc-01"],
    ),
    KnowledgeNode(
        concept_id="ransomware",
        title="Ransomware",
        ka_ref="B5",
        category="Attacks & Defences",
        plain_definition=(
            "Ransomware encrypts or steals data and extorts payment for restoration, "
            "increasingly with double extortion: pay to decrypt AND to keep the stolen data "
            "unpublished. Modern campaigns follow a kill chain: phish or VPN exploit → "
            "credential theft → lateral movement → disable EDR/backups → mass encryption. "
            "Defence is boring and proven: offline backups, segmentation, MFA, and fast patching."
        ),
        analogy=(
            "A burglar who not only locks your valuables in a safe but photographs your "
            "documents first — so even paying for the key does not stop the blackmail. "
            "The only winning move is owning a second house they never found (immutable backups)."
        ),
        core_pillars=[
            "**Initial access** — phishing, exposed RDP, unpatched VPN/edge devices; MFA and patching close the front door.",
            "**Pre-encryption recon** — vssadmin delete shadows, wevtutil clearing logs, EDR tamper attempts — the SOC's last detection window.",
            "**Double/triple extortion** — encryption + data-theft leak site + DDoS pressure.",
            "**Recovery is the real control** — tested, offline, access-controlled backups decide the outcome more than any EDR magic.",
        ],
        technical_domains=[
            "Encryption anatomy: hybrid — symmetric key per file (AES), asymmetric wrap (RSA/ECC) with attacker-held private key.",
            "Staging: kill tasks (taskkill /IM veeam*), safe-mode reboots, GPO-pushed scripts, sleep before detonation to defeat sandboxes.",
            "Detections: mass file-modify events, shadow-copy deletion commands (4719/audit), entropy spikes on shares, new admin accounts + scheduled tasks.",
        ],
        detection_telemetry=[
            "Event 1102 (audit log cleared), 7045 (new service), 4720 (new user), 4728/4732 (admin group adds) — later-stage indicators.",
            "Sysmon 1: vssadmin.exe delete shadows, wbadmin delete catalog, bcdedit recoveryenabled no, wevtutil cl.",
            "File telemetry: rename/move storms on shares; honeypot/canary files trip on first touch.",
        ],
        real_world=[
            "NotPetya masqueraded as ransomware while destroying M&E Maersk's ability to operate — wipers borrow ransomware clothes.",
            "Colonial Pipeline 2021: one leaked VPN password without MFA halted fuel distribution across the US East Coast.",
            "Ransomware economics: RaaS affiliates, initial-access brokers, negotiators — an industry with SLAs.",
        ],
        keywords=[
            "ransomware", "ransom", "cryptowall", "wanna cry", "wannacry", "locky",
            "double extortion", "encrypt files", "ransomware defence", "ransomware defense",
            "how does ransomware work", "ransomware kya hai",
        ],
        roman_urdu=["ransomware kya hai"],
        mapped_lab_ids=["endpoint-02", "endpoint-04"],
    ),
    KnowledgeNode(
        concept_id="adversarial-behaviours",
        title="Adversarial Behaviours & Threat Intelligence (CyBOK KA6)",
        ka_ref="B6",
        category="Attacks & Defences",
        plain_definition=(
            "Adversarial behaviour analysis profiles who attacks you and how they move. "
            "Actors cluster into nation-state APTs (espionage, patience, funding), organised "
            "cybercrime (revenue), hacktivists (ideology), and insiders (access plus motive). "
            "Their campaigns are modelled with the Cyber Kill Chain and, more operationally, "
            "the MITRE ATT&CK matrix — a shared language of tactics, techniques, and procedures."
        ),
        analogy=(
            "Kill Chain is the burglar's plan step by step (pick the target, get a key copy, "
            "enter, find the safe, escape). ATT&CK is the police database of known "
            "modus operandi, so one detective in Lagos can recognise the same housebreaker "
            "who struck in London."
        ),
        core_pillars=[
            "**Actor attribution classes** — nation-state vs cybercrime vs hacktivist vs insider: different motives, budgets, and risk tolerance.",
            "**Cyber Kill Chain (Lockheed Martin)** — Recon → Weaponisation → Delivery → Exploitation → Installation → C2 → Actions on Objectives; break any link, break the campaign.",
            "**MITRE ATT&CK** — 14 enterprise tactics from Reconnaissance to Exfiltration, mapped to techniques (T-numbers) and sub-techniques with detection/asset data.",
            "**Cyber Threat Intelligence (CTI)** — strategic (audience: board), operational (campaigns, actor profiles), tactical (IoCs) — each layer needs a different consumer.",
            "**Pyramid of Pain (Bianco)** — hash/IPs are trivial for adversaries to change; TTPs hurt them to change. Detect up the pyramid.",
        ],
        technical_domains=[
            "TTP mapping: every SIEM alert should link to ATT&CK technique IDs (e.g. T1566 Phishing, T1003 Credential Dumping) for comparability.",
            "Intelligence cycles: requirements → collection → processing → analysis → dissemination → feedback; STIX/TAXII for machine-to-machine sharing.",
            "Actor profiling tradecraft: infrastructure reuse, code lineage, working hours, targets — all attribution signals.",
        ],
        detection_telemetry=[
            "ATT&CK-mapped detections let the SOC measure coverage heat-maps by tactic and close technique-level gaps.",
            "Tactical IoCs (hashed payloads, C2 domains) age fast — automate ingestion, score by Pyramid-of-Pain durability.",
        ],
        real_world=[
            "APT41 blended nation-state espionage with financially motivated intrusions — actor classes are not always clean.",
            "Mitre ATT&CK Evaluations publicly benchmark EDR vendors against emulated actors like FIN7.",
        ],
        keywords=[
            "adversarial behaviour", "adversarial behavior", "threat actor", "apt",
            "advanced persistent threat", "kill chain", "cyber kill chain", "mitre",
            "att&ck", "attack matrix", "threat intelligence", "cti", "cyber threat intelligence",
            "ttp", "ttps", "pyramid of pain", "nation state", "hacktivist", "insider threat",
            "who are the attackers", "threat profiling", "ioc sharing",
        ],
        roman_urdu=["hackers kaun hote hain", "attacker kaise kaam karte hain"],
        mapped_lab_ids=["siem-01", "ad-01"],
    ),
    KnowledgeNode(
        concept_id="security-operations-incident-management",
        title="Security Operations & Incident Management (CyBOK KA7)",
        ka_ref="B7",
        category="Attacks & Defences",
        plain_definition=(
            "Security operations converts telemetry into decisions. Data sources (Syslog, "
            "NetFlow, Windows Event Logs, Sysmon, EDR, cloud audit logs) stream into a SIEM "
            "that normalises, correlates, and alerts; a SOAR automates the response playbook. "
            "Analysts work alerts through a triage pipeline while incidents run the SANS "
            "PICERL lifecycle: Preparation, Identification, Containment, Eradication, "
            "Recovery, Lessons Learned."
        ),
        analogy=(
            "Telemetry is the city's CCTV network; the SIEM is the control room where one "
            "operator watches a thousand screens; correlation rules are the alarm wiring "
            "that turns two harmless-looking clips into one burglary-in-progress. PICERL is "
            "the responder's checklist — from reading the call (Identification) to writing "
            "the after-action report (Lessons Learned)."
        ),
        core_pillars=[
            "**Telemetry fundamentals** — Windows: 4624 (logon), 4625 (failed logon), 4776 (NTLM), 4688 (process), 4672 (special privileges), 7045 (service install), 1102 (log cleared). Sysmon: 1 (process), 3 (network), 7 (image load), 13 (registry set).",
            "**SIEM correlation** — join weak signals: one 4625 is noise; 50 4625s then a 4624 from one source is password spraying.",
            "**SOAR automation** — enrich (VirusTotal, WHOIS), isolate host, disable account, ticket — repeatable playbooks at machine speed.",
            "**Anomaly vs rule-based detection** — rules catch the known, baselines/UMLA catch the novel; both drown without false-positive hygiene.",
            "**PICERL** — the NIST SP 800-61-aligned lifecycle every incident runbook follows.",
        ],
        technical_domains=[
            "Detection engineering: Sigma rules (YAML → any SIEM), tuned thresholds, risk-based alerting with asset criticality multipliers.",
            "False-positive mitigation: allow-listing sanctioned scanners/pen-tests, dedup, suppression windows, feedback loops into rule logic.",
            "Log hygiene: time sync (NTP) is a detection primitive — merged timelines collapse without it.",
            "Metrics: MTTD, MTTR, alert-to-incident ratio, coverage by ATT&CK tactic.",
        ],
        detection_telemetry=[
            "4625 status codes decode the attack: 0xC000006A wrong password, 0xC0000064 no such user (spray or enumeration).",
            "4624 LogonType semantics: 2 interactive, 3 network, 10 RDP — lateral movement writes LogonType 3 across hosts.",
            "Sysmon 3 + 22 together re-create a beacon: which process talked to which domain, when, and how often.",
        ],
        real_world=[
            "SIEM rules that fire on 'any PowerShell' bury analysts; rules that fire on encoded PowerShell from WinWord.exe's child survive triage.",
            "SANS/NIST: Preparation (pre-staged playbooks, contacts, tooling) determines whether Identification becomes minutes or days.",
            "Cloud: CloudTrail/GCP audit log alerts for IMDS-SSRF get-passrole attempts now parallel classic Windows detections.",
        ],
        keywords=[
            "security operations", "soc", "siem", "soar", "incident response",
            "incident management", "picerl", "sans picerl", "nist 800-61",
            "event logs", "windows event logs", "4624", "4625", "4776", "4688",
            "7045", "1102", "sysmon", "netflow", "syslog", "alert triage",
            "false positive", "anomaly detection", "soc analyst", "blue team",
            "what is a siem", "how does a soc work", "security operations center",
        ],
        roman_urdu=["soc kya hai", "siem kya hai", "incident response kya hai"],
        mapped_lab_ids=["siem-01", "siem-02", "siem-03", "soc-01"],
    ),
    KnowledgeNode(
        concept_id="forensics",
        title="Forensics (CyBOK KA8)",
        ka_ref="B8",
        category="Attacks & Defences",
        plain_definition=(
            "Forensics reconstructs what happened on a system from the artefacts an attacker "
            "cannot fully erase: filesystem records (MFT, $LogFile), execution traces "
            "(Prefetch, Amcache, Shimcache), persistence keys (Registry Run keys, scheduled "
            "tasks), and volatile memory. In court, findings must survive admissibility "
            "tests (Daubert in the US: tested, peer-reviewed, known error rates, accepted "
            "standards) and an unbroken chain of custody."
        ),
        analogy=(
            "A suspect can mop the floor, but the MFT still remembers when the file entered "
            "the room, Prefetch remembers it was opened, Amcache remembers its name, and the "
            "chair in memory still holds the warmth of the process that ran. Forensics "
            "interviews furniture that cannot lie easily."
        ),
        core_pillars=[
            "**Order of volatility** — capture RAM first (network state, injected code, true command lines), then disk, then backups/archives.",
            "**Windows artefacts** — MFT ($MFT timestamps, resident data), Prefetch (.pf execution), Amcache (program inventory + first run), Shimcache/AppCompat (execution order), USN journal.",
            "**Persistence locations** — Run/RunOnce keys, services, scheduled tasks, WMI subscriptions, Startup folders.",
            "**Memory forensics** — Volatility plugins (pslist, netscan, malfind, lsass dumping) recover what disk never saw: injected code, plaintext secrets, command history.",
            "**Legal admissibility** — Daubert criteria + documented, verifiable tooling (NIST CFTT tested) + write-blocked acquisition + hashes at every step.",
        ],
        technical_domains=[
            "File carving: recover files from raw bytes by header/footer signatures even without a filesystem — core of photos-never-die forensics.",
            "Timeline analysis: super-timelines (log2timeline/plaso) fuse filesystem, registry, browser, and log timestamps into one narrative.",
            "Anti-forensics to expect: timestomping ($STANDARD_INFORMATION vs $FILE_NAME divergence), log wiping (Event 1102), timestomping and slack-space hiding.",
        ],
        detection_telemetry=[
            "Volatility windows.malfind flags injected/unbacked executable memory pages (VAD tag protections).",
            "LSASS access (Sysmon Event 10 TargetImage lsass.exe) is both a detection event and a memory-acquisition justification.",
        ],
        real_world=[
            "Stuxnet's forensic trail lived in PLC logic and registry artefacts — an OT forensics wake-up call.",
            "NotPetya investigators reconstructed the initial foothold through MFEnx/SMB artefacts and EternalBlue packet captures.",
            "Court-tested toolchains: EnCase, FTK, Autopsy/The Sleuth Kit, Volatility 3 — with NIST CFTT validation behind them.",
        ],
        keywords=[
            "forensics", "digital forensics", "dfir", "mft", "prefetch", "amcache",
            "shimcache", "appcompat", "memory forensics", "volatility", "lsass",
            "file carving", "daubert", "chain of custody", "write blocker",
            "incident forensics", "what is digital forensics", "forensic artefacts",
            "master file table", "evidence admissibility",
        ],
        roman_urdu=["forensics kya hai"],
        mapped_lab_ids=["endpoint-03", "endpoint-05"],
    ),
    KnowledgeNode(
        concept_id="phishing-overview",
        title="Phishing (Social Engineering by Email)",
        ka_ref="A3",
        category="Attacks & Defences",
        plain_definition=(
            "Phishing is social engineering delivered by message: a fraudulent email, SMS "
            "(smishing), voice call (vishing), or QR code (quishing) that manufactures trust "
            "and urgency to steal credentials, install malware, or divert payments. Modern "
            "defence is layered: email authentication (SPF/DKIM/DMARC), URL/attachment "
            "detonation, behavioural analytics (impossible travel, new-rule creation), and "
            "report-button culture that turns every employee into a sensor."
        ),
        analogy=(
            "A con artist's letter dressed as your bank, wearing the bank's actual "
            "letterhead (spoofed domain), postmarked from a forgery workshop (spoofed "
            "headers), demanding you 'confirm your account in 24 hours'. The postmark check "
            "(SPF), the wax seal (DKIM), and the return-address policy (DMARC) are what "
            "separate authentic mail from counterfeit."
        ),
        core_pillars=[
            "**Pretext & urgency** — authority figures, deadlines, fear of loss; engineered to bypass deliberate thinking.",
            "**Credential harvest vs payload vs payment diversion** — three distinct objectives needing different detections.",
            "**Defensive triad** — SPF (sending servers), DKIM (signed content), DMARC (policy alignment + reporting) build a verifiable sender identity.",
            "**BEC (Business Email Compromise)** — no malware at all: thread hijacking and invoice diversion from a compromised mailbox.",
        ],
        technical_domains=[
            "Triage artefacts: Return-Path vs From mismatch, homoglyph domains (rn→m, Cyrillic а), reply-to swaps, tracking-pixel hosts.",
            "Advanced: OAuth consent phishing (illicit consent grants) — the token never carries the password; MFA is bypassed.",
            "Quishing: QR codes sidestep URL sandboxes because the link lives in the victim's camera app.",
        ],
        detection_telemetry=[
            "Impossible-travel logins and new inbox rules created by the attacker post-compromise (Graph API audit events).",
            "SEG detonation verdicts + DMARC aggregate reports (rua) quantify spoofed-sender volume per domain.",
        ],
        real_world=[
            "Quishing surged in 2023-2024 as QR payloads evaded link-time URL scanning.",
            "The Twitter 2021 attack was pure vishing into phone carriers — zero malware, total account takeover.",
        ],
        keywords=[
            "phishing", "spear phishing", "phish", "smishing", "vishing", "quishing",
            "bec", "business email compromise", "email attack", "credential harvesting",
            "what is phishing", "phishing kya hai", "phishing attack",
        ],
        roman_urdu=["phishing kya hai", "dhoka email"],
        mapped_lab_ids=["phish-01", "phish-02", "phish-05"],
    ),
    KnowledgeNode(
        concept_id="pass-the-hash",
        title="Pass-the-Hash (PtH)",
        ka_ref="B6",
        category="Attacks & Defences",
        plain_definition=(
            "Pass-the-Hash is a lateral-movement technique where an attacker authenticates "
            "with a stolen NTLM password hash directly — the plaintext password is never "
            "needed or cracked. The hash is dumped from LSASS memory, the SAM database, or "
            "DCSync replication, then replayed against remote hosts (SMB, WMI, PsExec) "
            "wherever NTLM authentication is still permitted."
        ),
        analogy=(
            "Some hotels accept your room key card without asking for ID. If a thief copies "
            "the card's magnetic stripe, they never need your name or passport — the clone "
            "opens doors because the lock only checks the pattern, not the person. NTLM is "
            "that lock; the hash is the stripe."
        ),
        core_pillars=[
            "**Root cause** — NTLM's challenge-response design proves knowledge of the hash, not the password, so the hash itself is a reusable credential.",
            "**Extraction sources** — LSASS memory (Mimikatz sekurlsa), local SAM dumps, DCSync replication of machine-account hashes.",
            "**Where it burns you** — local accounts with identical passwords across hosts, service accounts, and privileged users still authenticating with NTLM.",
        ],
        technical_domains=[
            "Tooling signatures: PsExec deploying PSEXESVC.exe, atexec/smbexec scheduled-task and service binaries, WMI process creation.",
            "Hardening: disable NTLMv1, restrict NTLM entirely where possible, deploy LAPS for unique local admin passwords, enforce SMB signing.",
            "Kerberos-preferred environments shrink PtH's blast radius — but NTLM fallback must be explicitly constrained, not just ignored.",
        ],
        detection_telemetry=[
            "Windows 4624 LogonType 3 with Authentication Package NTLM from a non-interactive source, followed by ADMIN$ share writes.",
            "Event 7045 (service install) naming PSEXESVC on hosts with no admin work, plus 4648/4688 explicit-credential process chains.",
            "Sysmon 3: outbound SMB (445) from unusual binaries; Sysmon 10: lsass.exe accessed by non-system processes (the upstream theft).",
        ],
        real_world=[
            "PtH remains a top lateral-movement technique (ATT&CK T1550.002) precisely because NTLM outlived its design life.",
            "NotPetya's spread inside hours largely via stolen credentials and PtH-style SMB lateral movement with EternalBlue as fallback.",
        ],
        keywords=[
            "pass the hash", "pth", "passthehash", "pass-the-hash", "ntlm hash",
            "lateral movement", "mimikatz", "sekurlsa", "psexec", "admin$",
            "what is pass the hash", "pass the hash kya hai", "how to detect pass the hash",
        ],
        roman_urdu=["pass the hash kya hai"],
        mapped_lab_ids=["soc-04", "siem-01", "endpoint-03"],
    ),
    KnowledgeNode(
        concept_id="kerberoasting",
        title="Kerberoasting",
        ka_ref="C13",
        category="Systems Security",
        plain_definition=(
            "Kerberoasting abuses a legitimate Kerberos feature: any authenticated domain "
            "user can request a service ticket (TGS) for any SPN, and the ticket is "
            "encrypted with the service account's key. If that account has a weak password "
            "or the domain still permits RC4 (0x17), the attacker cracks the ticket offline "
            "— no alerts, no lockouts, no interaction with the DC after the single request."
        ),
        analogy=(
            "Every employee can walk to reception and ask for a sealed letter addressed to "
            "any manager. The letter is sealed with wax made from that manager's password. "
            "Take the letter home, and you can try thousands of wax recipes offline until "
            "one opens it — reception never even noticed, because asking for letters is "
            "completely normal."
        ),
        core_pillars=[
            "**Prerequisite is minimal** — one valid domain account (often a phished low-privilege user); no admin rights needed to request TGS tickets.",
            "**Weak service accounts are the target** — services forced to use typed passwords (not gMSA) with long lifetimes get weak passphrases.",
            "**RC4 (0x17) vs AES** — RC4 tickets derive from the NT hash directly, making offline cracking dramatically cheaper.",
            "**Silence is the danger** — the only on-domain signal is a TGS request, which is normal traffic volume.",
        ],
        technical_domains=[
            "Tooling: Rubeus kerberoast, Impacket GetUserSPNs — request all SPN tickets in one loop, export as crackable hashes.",
            "Cracking: hashcat mode 13100/18200 against wordlists + masks; success measured in GPU-hours, not domain alerts.",
            "Hardening: gMSA (auto-rotated 256-bit passwords), disable RC4 via msDS-SupportedEncryptionTypes, long random passwords (25+ chars) for legacy SPNs.",
        ],
        detection_telemetry=[
            "Event 4769 spike with Ticket Encryption Type 0x17 (RC4) from a single user — the classic Kerberoasting signature.",
            "4769 volume per user vs per-SPN baseline (one user requesting many SPNs is abnormal).",
            "Sysmon 1: Rubeus.exe / PowerShell Kerberos module; 4688 with setspn/Rubeus command lines.",
        ],
        real_world=[
            "Kerberoasting (ATT&CK T1558.003) is standard in nearly every AD penetration test — a finding means service-account policy failed.",
            "Mitigation priority: gMSA everywhere possible first; monitoring second; because legacy SPNs rarely disappear overnight.",
        ],
        keywords=[
            "kerberoasting", "kerberoast", "tgs", "spn", "service principal name",
            "rc4", "0x17", "golden ticket", "silver ticket", "krbtgt", "as-rep roasting",
            "4769", "what is kerberoasting", "kerberoasting kya hai",
        ],
        roman_urdu=["kerberoasting samjhao"],
        mapped_lab_ids=["soc-03", "ad-02"],
    ),
    KnowledgeNode(
        concept_id="cryptography",
        title="Cryptography (CyBOK KA9)",
        ka_ref="C9",
        category="Systems Security",
        plain_definition=(
            "Cryptography provides the mathematical toolkit for confidentiality, integrity, "
            "authentication, and non-repudiation. Symmetric primitives (AES in GCM, ChaCha20) "
            "encrypt bulk data fast; hashes (SHA-256, SHA-3) fingerprint it; MACs (HMAC) "
            "authenticate it. Asymmetric primitives (RSA, Diffie-Hellman, elliptic curves) "
            "solve key distribution and signatures. Emerging tools — zero-knowledge proofs "
            "and multi-party computation — prove facts without revealing secrets, while "
            "lattice schemes prepare us for post-quantum reality."
        ),
        analogy=(
            "Symmetric encryption is a shared diary lock — fast, but you must secretly hand "
            "the key to your friend first. Asymmetric cryptography is the mailbox with a "
            "public slot (public key) anyone can drop mail into while only you hold the "
            "door key (private key). A hash is a fingerprint — you cannot rebuild the person "
            "from it, but you can always check who left the print."
        ),
        core_pillars=[
            "**Symmetric ciphers** — AES (modes: CBC needs MAC; GCM is authenticated), ChaCha20-Poly1305 for fast software/streaming.",
            "**Hashes** — SHA-2 (256/384/512), SHA-3 sponge construction; collision resistance is the property attackers break first.",
            "**MACs** — HMAC (hash-based) and Poly1305 ( MAC part of AEAD); encrypt-then-MAC ordering matters.",
            "**Asymmetric** — RSA (factorisation hardness), Diffie-Hellman / ECDH (discrete log), ECDSA/EdDSA signatures.",
            "**Advanced primitives** — Zero-Knowledge Proofs (prove without revealing), Multi-Party Computation (compute on joint secrets), fully homomorphic encryption.",
            "**Post-quantum** — lattice-based schemes (Kyber/ML-KEM for key encapsulation, Dilithium/ML-DSA for signatures) standardised by NIST (FIPS 203/204).",
        ],
        technical_domains=[
            "Kerckhoffs's principle: security must live in the key, never in the secrecy of the algorithm.",
            "Randomness is a primitive, not an afterthought — CSPRNG failures (repeated nonces, Debian OpenSSL 2008) doom perfect ciphers.",
            "AEAD or bust: unauthenticated modes (raw CBC/CTR) invite padding-oracle attacks (POODLE-style).",
        ],
        real_world=[
            "Signal's double ratchet layers ECDH forward secrecy so past messages stay safe even if a key leaks today.",
            "SHA-1's SHAttered collision (2017) ended its use in certificates; MD5 died years earlier.",
            "Harvest-now-decrypt-later drives migration to PQC in TLS 1.3 hybrids (X25519MLKEM768).",
        ],
        keywords=[
            "cryptography", "crypto", "encryption", "aes", "aes gcm", "cbc", "chacha20",
            "sha-256", "sha256", "sha-3", "sha3", "hash", "hmac", "rsa", "diffie hellman",
            "elliptic curve", "ecc", "ecdsa", "zero knowledge", "zkp", "zero knowledge proof",
            "multi party computation", "mpc", "post quantum", "lattice", "pqc", "kyber",
            "dilithium", "what is cryptography", "cryptography kya hai", "symmetric",
            "asymmetric", "public key", "private key", "digital signature",
        ],
        roman_urdu=["cryptography samjhao", "encryption kya hai"],
        mapped_lab_ids=["net-02", "pw-02"],
    ),
    KnowledgeNode(
        concept_id="aaa",
        title="Authentication, Authorisation & Accountability (CyBOK KA13)",
        ka_ref="C13",
        category="Systems Security",
        plain_definition=(
            "AAA is the identity backbone of every system. Authentication proves who you "
            "are (passwords, certificates, biometrics, FIDO2 keys). Authorisation decides "
            "what you may do (RBAC, ABAC, policy engines). Accountability records what you "
            "did (audit trails, immutable logs). Kerberos, SAML, OAuth 2.0, and OpenID "
            "Connect each solve a different slice of this problem in the enterprise."
        ),
        analogy=(
            "Authentication shows your passport at the hotel desk; authorisation is the "
            "keycard that opens only your floor; accountability is the door log that says "
            "whose card opened which door at 3 a.m. Lose any one of the three and the "
            "building either locks everyone out or lets anyone in silently."
        ),
        core_pillars=[
            "**Authentication factors** — knowledge, possession, inherence; MFA combines two or more independent channels.",
            "**Kerberos mechanics** — KDC issues a TGT; the user's TGS request per SPN yields service tickets; tickets carry PAC privilege data; time skew tolerance is small (5 min).",
            "**Federation** — SAML 2.0 (enterprise SSO assertions, XML), OAuth 2.0 (delegated *authorisation*, bearer tokens), OIDC (authentication layer on OAuth: id_token), WebAuthn/FIDO2 (phishing-resistant, origin-bound public keys).",
            "**Access control models** — DAC (owner grants), MAC (labels dominate, e.g. SELinux/AppArmor), RBAC (roles), ABAC (attributes/policies, XACML).",
            "**Accountability** — centralised, tamper-evident audit logs (Event 4624/4625, sign-in logs) with retention policy.",
        ],
        technical_domains=[
            "Kerberos abuse paths: Kerberoasting (TGS for SPNs), AS-REP roasting (pre-auth disabled), Golden Tickets (forged TGT via KRBTGT hash), Silver Tickets (forged TGS).",
            "OAuth grants: authorisation code + PKCE for everything user-facing; client_credentials for machines; never implicit.",
            "PAM (privileged access management): vaulted, brokered, session-recorded admin access — the control that contains stolen-credential blast radius.",
        ],
        detection_telemetry=[
            "4768 (TGT request) and 4769 (TGS request) patterns reveal roasting; 4624/4625 with status codes reveal spraying.",
            "Impossible-travel / token replay anomalies in cloud sign-in logs (CloudTrail/Azure AD).",
        ],
        real_world=[
            "FIDO2/WebAuthn neutralises credential phishing because the private key never leaves the device and is bound to the origin.",
            "The OAuth consent-phishing wave (illicit grants) bypassed passwords entirely — tokens, not credentials, became the keys.",
        ],
        keywords=[
            "aaa", "authentication", "authorization", "authorisation", "access control",
            "kerberos", "tgt", "tgs", "kdc", "saml", "oauth", "oauth2", "openid connect",
            "oidc", "webauthn", "fido2", "mfa", "rbac", "abac", "mac", "dac",
            "privilege", "what is authentication", "authentication vs authorization",
            "how does kerberos work", "sso", "single sign on", "identity",
        ],
        roman_urdu=["authentication kya hai", "login system kaise kaam karta hai"],
        mapped_lab_ids=["soc-03", "cloud-03", "pw-03"],
    ),
    KnowledgeNode(
        concept_id="zero-trust",
        title="Zero Trust Architecture",
        ka_ref="E18",
        category="Infrastructure Security",
        plain_definition=(
            "Zero Trust is a security strategy built on one assumption: never trust, always "
            "verify. Location on the 'internal' network grants nothing; every request is "
            "authenticated, authorised, and inspected continuously using identity, device "
            "health, and behavioural context. Coined by Forrester's John Kindervag and "
            "codified by NIST SP 800-207, it replaces the crumbling castle-and-moat "
            "perimeter with per-request, policy-driven access."
        ),
        analogy=(
            "A classic office badge gets you through the front gate once — then every door "
            "inside opens. Zero Trust is a building where every single door inspects your "
            "badge, asks why you are there, checks whether you look unwell (compromised "
            "device), and re-verifies you at the next door too. Being 'inside the building' "
            "means nothing on its own."
        ),
        core_pillars=[
            "**Verify explicitly** — authenticate and authorise every request with all available context (identity, device posture, location, behaviour).",
            "**Least-privilege access** — just-in-time and just-enough access; standing privilege is the enemy.",
            "**Assume breach** — segment aggressively, encrypt internally, minimise blast radius, log everything.",
            "**Continuous re-evaluation** — trust is a per-session score that decays; step-up authentication when risk rises.",
        ],
        technical_domains=[
            "Control plane: policy engine + policy administrator decide; data plane (PEP) enforces per-request access.",
            "Identity-first tooling: SSO/MFA everywhere, device posture (EDR healthy, patched, compliant), micro-segmentation (identity-based segments, not VLANs).",
            "ZTNA replaces VPN: application-level tunnels brokered per-session; users never join the flat network.",
            "Phased rollout: identify protect surfaces (one app, one data store), define policy, then expand — not a big-bang migration.",
        ],
        real_world=[
            "Google's BeyondCorp proved employees could work without privileged network access at all.",
            "NIST SP 800-207 defines the reference architecture; the DoD Zero Trust Strategy targets target-level by 2027.",
            "Zero Trust is a journey of enforcement points: VPN → ZTNA → identity-aware proxy per application.",
        ],
        keywords=[
            "zero trust", "zerotrust", "zero-trust", "zero trust architecture",
            "never trust always verify", "ztna", "beyondcorp", "nist 800-207",
            "what is zero trust", "zero trust kya hai", "explain zero trust",
            "zero trust architecture explain", "microsegmentation", "micro segmentation",
        ],
        roman_urdu=["zero trust kya hai", "zero trust samjhao"],
        mapped_lab_ids=["cloud-02", "net-01"],
    ),
    KnowledgeNode(
        concept_id="cia-triad",
        title="The CIA Triad",
        ka_ref="A1",
        category="Human, Organisational & Regulatory Aspects",
        plain_definition=(
            "The CIA Triad is the foundational model of information security: "
            "**Confidentiality** (only authorised parties can read data), **Integrity** "
            "(data and systems remain accurate and unaltered), and **Availability** "
            "(authorised users can access what they need when they need it). Every security "
            "control maps to at least one pillar, and every attack violates at least one — "
            "which makes the triad a fast common language between engineers, auditors, "
            "and boards."
        ),
        analogy=(
            "A hospital chart: Confidentiality means only your care team may read it; "
            "Integrity means nobody can silently rewrite your allergy list; Availability "
            "means the chart is at the bedside during the emergency, not locked in a "
            "records room. Lose any one, and care collapses in a different way."
        ),
        core_pillars=[
            "**Confidentiality controls** — encryption at rest/in transit, access control, DLP, classification.",
            "**Integrity controls** — hashing, digital signatures, versioning, WORM storage, audit trails.",
            "**Availability controls** — redundancy, load balancing, backups, DDoS protection, disaster recovery.",
            "**Tension is real** — full disk encryption (C) can complicate indexing (A); strict change control (I) slows releases (A). Security engineering is managing the trade-offs explicitly.",
        ],
        technical_domains=[
            "Mapping attacks: phishing → C (credentials), ransomware → A (and I), web defacement → I, DDoS → A.",
            "Extended models: Parker hexad (adds possession, authenticity, utility), AAA as the operational counterpart.",
            "Metrics per pillar: C = access-review coverage; I = signature/hash verification coverage; A = uptime SLOs and RTO/RPO.",
        ],
        real_world=[
            "WannaCry was an Availability catastrophe; Anthem's breach was Confidentiality; SWIFT heists targeted transaction Integrity.",
            "CyBOK notes OT flips the ordering — availability/safety outrank confidentiality on a factory floor.",
        ],
        keywords=[
            "cia triad", "cia", "confidentiality integrity availability",
            "what is cia triad", "cia triad kya hai", "confidentiality", "integrity",
            "availability", "security pillars", "explain cia triad",
        ],
        roman_urdu=["cia triad samjhao"],
        mapped_lab_ids=["endpoint-02", "net-01"],
    ),
    KnowledgeNode(
        concept_id="os-virtualisation-security",
        title="Operating Systems & Virtualisation Security (CyBOK KA10)",
        ka_ref="C10",
        category="Systems Security",
        plain_definition=(
            "The OS is the reference monitor every attacker must eventually fool. Its "
            "primitives — access control lists, capability systems, protection rings — "
            "enforce isolation, while exploit mitigations (ASLR, DEP/NX, stack canaries, "
            "CFI) raise the cost of memory attacks. Virtualisation stacks the stakes "
            "higher: Type-1 hypervisors (Xen, ESXi, Hyper-V) isolate tenants on bare "
            "metal, and containers isolate processes through namespaces and cgroups — "
            "weaker boundaries than VMs, which makes kernel hardening matter more."
        ),
        analogy=(
            "Rings of protection are an airport: ring 3 is the public terminal, ring 0 is "
            "the control tower — passengers never enter, and baggage (system calls) is the "
            "only thing that passes, always X-rayed (syscall filtering). Containers are "
            "gates within the same terminal sharing one roof: cheaper and faster, but a "
            "fire in the shared roof (kernel) touches every gate. VMs are separate "
            "buildings with their own walls."
        ),
        core_pillars=[
            "**OS primitives** — ACLs (owner-based, DAC), capabilities (unforgeable tokens delegating rights), rings of protection (0 kernel / 3 user), syscall interface.",
            "**Memory hardening** — ASLR (randomise layout), DEP/NX (data not executable), stack canaries, CFI (valid call targets), SMEP/SMAP.",
            "**Hypervisors** — Type 1 bare-metal multi-tenant isolation vs Type 2 hosted; side-channel and escape vectors (VENOM, Spectre-class) as residual risks.",
            "**Containers** — namespaces (pid, net, mnt, user) + cgroups (resource limits); shared kernel means a kernel 0-day is every container's 0-day.",
            "**Escape economics** — VM escape costs (and deters) more than container escape; choose boundaries per-sensitivity.",
        ],
        technical_domains=[
            "Rootkits: userland (LD_PRELOAD), kernel (loadable modules), hypervisor (below the OS — hardest to detect, Blue Pill concept).",
            "Hardening baselines: CIS Benchmarks, SELinux/AppArmor MAC policies, seccomp/landlock syscall filters, dropping capabilities per container.",
            "Break-out mitigations: read-only rootfs, no privileged containers, gVisor/Kata for stronger isolation on shared clusters.",
        ],
        detection_telemetry=[
            "Kernel-module load events, unusual auditd executions by root, container escape tells: host-path mounts + subsequent host process creation.",
        ],
        real_world=[
            "Dirty COW (2016) proved a 9-year-old kernel race could root millions of Linux systems.",
            "VENOM (Xen floppy-device escape) reminded cloud providers that hypervisor bugs are tenant-boundary breaches.",
        ],
        keywords=[
            "operating system security", "os security", "virtualisation security",
            "virtualization security", "hypervisor", "type 1 hypervisor", "type 2 hypervisor",
            "container security", "containers", "docker security", "namespaces",
            "cgroups", "aslr", "dep", "nx bit", "cfi", "rings of protection",
            "privilege escalation", "rootkit", "kernel hardening", "vm escape",
            "what is a hypervisor", "container vs vm",
        ],
        roman_urdu=["operating system security samjhao"],
        mapped_lab_ids=["endpoint-05", "cloud-02"],
    ),
    KnowledgeNode(
        concept_id="software-security",
        title="Software Security (CyBOK KA14)",
        ka_ref="D14",
        category="Software & Platform Security",
        plain_definition=(
            "Software security is the discipline of writing programs that remain correct "
            "under adversarial input. The enemy classes are memory corruption (buffer "
            "overflows, use-after-free), race conditions (TOCTOU — time-of-check to "
            "time-of-use), and type confusion — all rooted in C-family languages trusting "
            "the programmer with memory. Modern defence combines memory-safe languages, "
            "compile-time and runtime checks, and pipeline testing (SAST/DAST/SCA)."
        ),
        analogy=(
            "A buffer overflow is a hotel with a fixed number of rooms and a clerk who "
            "never counts guests: the 21st guest gets written into the manager's office "
            "(adjacent memory). Use-after-free is renting a room, checking out, then "
            "keeping the key — and the hotel re-rents the room to a spy. TOCTOU is "
            "checking the parking lot is empty, then walking across while a car arrives "
            "mid-stride."
        ),
        core_pillars=[
            "**Memory corruption** — stack/heap overflows overwrite control data; mitigations: stack canaries, ASLR, DEP/NX, safe linking.",
            "**Use-after-free / double free** — dangling pointers to reallocated memory; mitigations: ownership types (Rust), garbage collection, allocator hardening.",
            "**Race conditions (TOCTOU)** — check and use are separate steps; mitigations: atomic operations, file descriptors instead of paths, capability checks at the point of use.",
            "**Type safety** — confused-deputy attacks live where types are assumed, not enforced.",
            "**Memory-safe languages** — Rust, Go, Java, C# eliminate whole bug classes by construction; Chrome and Android data show UAF/overflow declines after migration.",
        ],
        technical_domains=[
            "SAST: taint analysis finds source→sink flows (user input → SQL query) before code runs.",
            "DAST: black-box probing of running apps (Burp Suite, ZAP) — catches misconfigurations static analysis cannot see.",
            "Fuzzing at scale: coverage-guided fuzzers (AFL++, libFuzzer) with sanitizers (ASan, UBSan, MSan) turn crashes into reproducible reports.",
            "Supply chain: SCA for vulnerable dependencies, SBOM for inventory, signed artefacts (Sigstore) for provenance.",
        ],
        real_world=[
            "Heartbleed (2014): a missing bounds check in OpenSSL leaked 64KB of server memory on request — passwords, keys, sessions.",
            "About 70% of Microsoft/Chrome's high-severity bugs are memory-safety issues — the reason for Rust adoption in Windows and Android.",
        ],
        keywords=[
            "software security", "buffer overflow", "use after free", "memory corruption",
            "race condition", "toctou", "type safety", "memory safety", "rust",
            "sast", "dast", "fuzzing", "secure coding", "what is software security",
            "heap overflow", "stack overflow security", "format string",
        ],
        roman_urdu=["software security samjhao"],
        mapped_lab_ids=["web-01", "soc-01"],
    ),
    KnowledgeNode(
        concept_id="web-mobile-security",
        title="Web & Mobile Security (CyBOK KA15)",
        ka_ref="D15",
        category="Software & Platform Security",
        plain_definition=(
            "Web security protects the browser-server conversation against the OWASP Top "
            "10: broken access control (IDOR), injection (SQLi, XSS), cryptographic "
            "failures, misconfiguration, and SSRF. Mobile security shifts the perimeter to "
            "the device: sandboxing, permission models, insecure local storage, certificate "
            "pinning, and WebView exposure decide whether an attacker needs a server bug "
            "or just a borrowed phone."
        ),
        analogy=(
            "IDOR is a cloakroom that hands you coat number 47 to whoever asks for 47 — "
            "the ticket (session) proves you paid, but nobody checked the stub. SQLi is a "
            "waiter who repeats whatever you mumble straight into the kitchen's ordering "
            "system, including 'and bring me the safe'. XSS is a bulletin board where "
            "anyone can post a sticky note that jumps out and pickpockets whoever reads it."
        ),
        core_pillars=[
            "**OWASP Top 10 (2021)** — A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable Components, A07 Auth Failures, A08 Integrity Failures, A09 Logging Failures, A10 SSRF.",
            "**Same-Origin Policy & XSS** — reflected/stored/DOM XSS defeat SOP; CSP + output encoding + HttpOnly cookies are the countermeasures.",
            "**CSRF** — the browser auto-sends cookies; SameSite cookies + CSRF tokens break the forgery.",
            "**Mobile specifics** — platform sandbox (iOS/Android), permission model abuse, insecure storage (Keychain/Keystore vs plaintext prefs), certificate pinning (and its bypass via Frida), WebView bridge vulnerabilities.",
        ],
        technical_domains=[
            "SSRF: server fetches attacker URLs — block link-local metadata (169.254.169.254), enforce egress allow-lists.",
            "IDOR testing: authorise per object, not per endpoint — every object reference re-checks ownership.",
            "API security: rate limits, schema validation, and object-level authorisation (BOLA in API Top 10).",
        ],
        detection_telemetry=[
            "WAF logs with SQLi/XSS rule hits and unusual user-agent bursts; honeypot parameters that humans never touch.",
            "Mobile: detect pinning bypass via runtime instrumentation signals and cert-pinning error analytics.",
        ],
        real_world=[
            "Capital One 2019: SSRF against the EC2 metadata service minted an IAM role — 100M records exfiltrated.",
            "OWASP reports broken access control in 94% of tested applications — the quiet #1.",
        ],
        keywords=[
            "web security", "owasp", "owasp top 10", "xss", "cross site scripting",
            "csrf", "cross site request forgery", "ssrf", "idor", "broken access control",
            "security misconfiguration", "mobile security", "android security",
            "ios security", "certificate pinning", "webview", "what is owasp",
            "insecure direct object reference", "web application security",
        ],
        roman_urdu=["web security samjhao", "owasp kya hai"],
        mapped_lab_ids=["web-01", "web-02", "web-03"],
    ),
    KnowledgeNode(
        concept_id="sql-injection",
        title="SQL Injection (SQLi)",
        ka_ref="D15",
        category="Software & Platform Security",
        plain_definition=(
            "SQL injection happens when untrusted input changes the structure of a database "
            "query — the classic `' OR 1=1 --`. Because the query string becomes executable "
            "logic, an attacker can bypass authentication, dump tables, modify data, and "
            "with stacked queries sometimes reach operating-system command execution. It is "
            "fully preventable with parameterised queries where data never becomes code."
        ),
        analogy=(
            "Imagine a restaurant where you dictate your order and the waiter types exactly "
            "what you say into the till — including 'and also open the cash register'. "
            "Parameterised queries are a printed order form: you can only fill the blanks; "
            "you can never rewrite the form's instructions."
        ),
        core_pillars=[
            "**Root cause** — string-concatenated SQL lets data cross into the code domain; escaping filters are whack-a-mole, parameterisation is the cure.",
            "**Families** — in-band (UNION-based, error-based), blind (boolean and time-based oracles), out-of-band (DNS/HTTP exfil), stacked queries where drivers allow.",
        ],
        technical_domains=[
            "Detection craft: single quotes causing 500s, `SLEEP()` deltas, UNION column-count probing, error text leaking vendor names.",
            "Prevention: parameterised statements (placeholders), ORM query APIs, least-privilege DB accounts, allow-list validation for identifiers (ORDER BY columns cannot be parameterised).",
            "Defence-in-depth: WAF rules for obvious payloads, generic error pages, DB segmentation, read-only replicas for public endpoints.",
        ],
        detection_telemetry=[
            "Time-based blind needs timing baselines: alert on query-duration distributions, not just error counts.",
            "WAF + DB audit: identical parameter lengths with divergent SQL plans, sudden information_schema activity.",
        ],
        real_world=[
            "Heartland Payment Systems (2008) and TalkTalk (2015) were SQLi at enterprise scale — fines followed.",
            "SQLi remains OWASP A03 because a decade of ORM adoption still leaves raw-query corners in every codebase.",
        ],
        keywords=[
            "sql injection", "sqli", "sqlinjection", "sql-injection", "injection",
            "union select", "or 1 1", "blind sql injection", "what is sql injection",
            "sql injection kya hai", "database injection", "explain sql injection",
        ],
        roman_urdu=["sqli kya hai", "sql injection samjhao"],
        mapped_lab_ids=["web-01"],
    ),
    KnowledgeNode(
        concept_id="email-authentication",
        title="Email Authentication — SPF, DKIM, DMARC",
        ka_ref="E18",
        category="Infrastructure Security",
        plain_definition=(
            "SPF, DKIM, and DMARC are the three DNS-published protocols that let a receiving "
            "mail server verify a sender's identity. SPF lists which IPs may send for a "
            "domain; DKIM signs the message with a private key whose public half lives in "
            "DNS; DMARC ties both to a policy (none/quarantine/reject) plus reporting. "
            "Together they defeat direct domain spoofing — though they cannot authenticate "
            "lookalike domains, which is where human triage earns its keep."
        ),
        analogy=(
            "SPF is the guest list at the club door (only these senders may enter). DKIM "
            "is the wax seal on the letter, verifiable against the seal stamp published "
            "in the town square (DNS). DMARC is the instruction the letter's owner "
            "published: 'if the seal or guest list fails, treat my mail as fake — and "
            "tell me every time it happens.'"
        ),
        core_pillars=[
            "**SPF** — DNS TXT record of authorised sending IPs; evaluated against the envelope-from (Return-Path); fails soft with ~all vs hard with -all.",
            "**DKIM** — cryptographic signature over selected headers + body (d=, s= selectors); survives forwarding better than SPF.",
            "**DMARC** — alignment check (From: domain must match SPF or DKIM signing domain), policy enforcement, and aggregate (rua) reports that quantify abuse.",
            "**Limits** — none of the three stop cousin/homoglyph domains or display-name spoofing; BEC defence needs MFA + process controls too.",
        ],
        technical_domains=[
            "Deployment order: SPF → DKIM (all legitimate streams: marketing, CRM, payroll!) → DMARC p=none with rua monitoring → tighten to quarantine → reject.",
            "ARC (Authenticated Received Chain) preserves verdicts through forwarders and mailing lists.",
            "SPF's 10-lookup limit bites big enterprises — use includes carefully and flatten where necessary.",
        ],
        real_world=[
            "Since 2024, Gmail and Microsoft enforce DMARC (p=quarantine+) for bulk senders — misconfigured domains now lose deliverability, not just security credibility.",
            "DMARC rua reports routinely reveal unknown shadow senders (SaaS tools nobody logged).",
        ],
        keywords=[
            "spf", "dkim", "dmarc", "email authentication", "email spoofing",
            "what is spf", "what is dmarc", "spf dkim dmarc", "compare spf dkim dmarc",
            "spf vs dkim", "domain spoofing", "email security", "arc email",
            "spf record", "spf protect", "what does spf protect against",
        ],
        roman_urdu=["email spoofing samjhao"],
        mapped_lab_ids=["phish-01", "phish-06"],
    ),
    KnowledgeNode(
        concept_id="secure-software-lifecycle",
        title="Secure Software Lifecycle (CyBOK KA16)",
        ka_ref="D16",
        category="Software & Platform Security",
        plain_definition=(
            "Secure software lifecycle (SSDLC) embeds security into every development stage "
            "instead of auditing it afterwards: threat modelling at design, secure coding "
            "standards and SAST at build, DAST and dependency scanning in CI, signed "
            "artefacts at release, and monitoring in production. Mature organisations "
            "measure this with models like Microsoft SDL, BSIMM, and OWASP SAMM, and "
            "automate it through DevSecOps pipelines where security checks are gates, "
            "not suggestions."
        ),
        analogy=(
            "Baking hygiene: you cannot inspect salmonella out of a finished cake. You "
            "control the supply chain (verified ingredients), the recipe (standards), "
            "the oven (pipeline gates), and the packaging (signing). A cake safety "
            "inspector at the end (pen-test only) finds problems when they are already "
            "baked in."
        ),
        core_pillars=[
            "**Threat modelling early** — STRIDE or attack-tree sessions on the design, when a fix costs a whiteboard, not a recall.",
            "**Microsoft SDL** — the canonical stage-gate process (requirements → design → implementation → verification → release → response).",
            "**OWASP SAMM & BSIMM** — maturity models: SAMM prescribes practices; BSIMM benchmarks what peers actually do.",
            "**DevSecOps** — shift-left plus right: CI gates (SAST/SCA/IaC scanning, secret scanning) and runtime guardrails (monitoring, signed deploys, policy-as-code).",
        ],
        technical_domains=[
            "Pipeline anatomy: commit → pre-commit hooks (lint, secret scan) → CI (unit tests, SAST, SCA, container scan) → CD (signed images, provenance/SLSA attestation) → deploy.",
            "Vulnerability management SLAs by severity (e.g. critical 7 days) with exceptions owned and time-boxed.",
            "Security champions programme embeds a trained engineer per squad — scaling security without scaling the security team.",
        ],
        real_world=[
            "SolarWinds (2020) weaponised the build pipeline itself — the reason SLSA provenance and Sigstore signing exist today.",
            "Log4Shell (2021) punished SBOM absences: teams without an inventory could not even answer 'are we affected?'",
        ],
        keywords=[
            "ssdlc", "sdlc security", "secure sdlc", "microsoft sdl", "bsimm", "owasp samm",
            "devsecops", "dev secops", "threat modeling in sdlc", "software development lifecycle security",
            "supply chain security", "sbom", "salsa", "what is devsecops", "secure development",
        ],
        roman_urdu=["devsecops kya hai"],
        mapped_lab_ids=["web-01", "cloud-02"],
    ),
    KnowledgeNode(
        concept_id="distributed-systems-security",
        title="Distributed Systems Security (CyBOK KA11)",
        ka_ref="C11",
        category="Systems Security",
        plain_definition=(
            "Distributed systems security addresses coordination across untrusted nodes. "
            "Consensus protocols (Raft, PBFT and successors) keep replicated state machines "
            "consistent even when some nodes are faulty or malicious. Peer-to-peer networks "
            "face identity attacks — Sybil (one entity forges many identities) and eclipse "
            "(a victim sees only attacker-controlled peers). Availability under load "
            "collapses into DDoS resilience: the system must degrade gracefully instead "
            "of failing loudly."
        ),
        analogy=(
            "Byzantine consensus is a council where some members may lie, yet the honest "
            "majority must still agree on one truth. A Sybil attack is one person filling "
            "the room with cardboard voters; eclipse is surrounding a single councillor "
            "with fake aides so he only hears lies. DDoS is simply shouting so loud that "
            "no conversation can happen."
        ),
        core_pillars=[
            "**Consensus** — Raft (crash faults, leader election, logs) for typical clusters; PBFT-style protocols for Byzantine faults; quorum intersection is the safety core.",
            "**Sybil resistance** — costly identity (proof-of-work/stake) or verified identity (PoR, attestation) before a node's vote counts.",
            "**Eclipse attacks** — adversarial neighbourhood control; mitigated by diverse peer selection and honest-bootstrap guarantees.",
            "**DDoS resilience** — anycast, rate limiting, puzzles, geo/AS filtering; capacity is a security property, not an ops bonus.",
        ],
        technical_domains=[
            "CAP/PACELC trade-offs force security designs to choose which guarantees survive partitions.",
            "Blockchain reuses all three: consensus + Sybil economics + eclipse-resistant gossip.",
        ],
        real_world=[
            "Eclipse-style network partitioning has been demonstrated against Bitcoin and Ethereum node discovery.",
            "Memcached reflection (2018) turned misconfigured distributed services into 1.7 Tbps DDoS amplifiers.",
        ],
        keywords=[
            "distributed systems security", "consensus", "raft", "pbft", "byzantine",
            "sybil", "sybil attack", "eclipse attack", "ddos resilience", "p2p security",
            "peer to peer", "quorum", "what is a sybil attack",
        ],
        roman_urdu=["distributed systems samjhao"],
        mapped_lab_ids=["net-01", "siem-03"],
    ),
    KnowledgeNode(
        concept_id="formal-methods",
        title="Formal Methods for Security (CyBOK KA12)",
        ka_ref="C12",
        category="Systems Security",
        plain_definition=(
            "Formal methods prove security properties mathematically instead of testing "
            "for them empirically. Models are specified in logic, properties are stated "
            "as trace properties (nothing bad ever happens on any execution) or "
            "hyperproperties (relating multiple executions, like non-interference), and "
            "then verified by model checking or theorem proving. Classic security policies "
            "— Bell-LaPadula (confidentiality, no read up / no write down), Biba "
            "(integrity, no read down / no write up), Clark-Wilson (well-formed "
            "transactions) — are all formal models of permitted information flow."
        ),
        analogy=(
            "Testing is walking every corridor of a building to check for holes; a formal "
            "proof is the architect's signed drawing that shows no wall is missing "
            "anywhere, including corridors not yet built. Trace properties check one "
            "walk-through at a time; hyperproperties compare all possible walks against "
            "each other — 'no path ever leaks what another path hides'."
        ),
        core_pillars=[
            "**Specification** — the system and its assumptions written precisely (TLA+, Alloy, Coq, Promela/SPIN).",
            "**Trace properties vs hyperproperties** — safety/liveness per-run vs relational properties such as non-interference and observational determinism.",
            "**Model checking** — exhaustive state-space search (SPIN, NuSMV); automatic but bounded by state explosion.",
            "**Theorem proving** — interactive (Coq, Isabelle) or SMT-assisted (Dafny); unbounded but expert-intensive.",
            "**Information-flow control** — Bell-LaPadula, Biba, Clark-Wilson as lattice/transaction policies; declassification as the hard design question.",
        ],
        technical_domains=[
            "Verified artefacts: seL4 (proof of functional correctness), HACL* crypto library, CompCert compiler.",
            "Protocol verification: Tamarin/ProVerif analyse TLS and Signal's ratchets for attacker traces.",
        ],
        real_world=[
            "The 2008 OpenSSL Debian RNG flaw formal methods would have caught by proving the RNG's entropy contract.",
            "AWS uses TLA+ to specify S3-adjacent workflows; Microsoft ships SLAM/Static Driver Verifier with Windows.",
        ],
        keywords=[
            "formal methods", "formal verification", "model checking", "theorem proving",
            "bell lapadula", "bell-la padula", "biba", "clark wilson", "noninterference",
            "non interference", "information flow control", "tla+", "alloy", "coq",
            "hyperproperties", "trace properties", "what are formal methods",
        ],
        roman_urdu=["formal methods samjhao"],
        mapped_lab_ids=[],
    ),
    KnowledgeNode(
        concept_id="applied-cryptography",
        title="Applied Cryptography (CyBOK KA17)",
        ka_ref="E17",
        category="Infrastructure Security",
        plain_definition=(
            "Applied cryptography is engineering with cryptographic primitives in the real "
            "world: TLS 1.3 protecting data in transit, PKI managing certificate identity "
            "and revocation, and key management doing the unglamorous work — generation, "
            "rotation, derivation, storage — where most real breaches happen. It also "
            "accounts for physical reality: side channels (timing, power, EM) leak secrets "
            "from correct algorithms running on leaky hardware."
        ),
        analogy=(
            "TLS 1.3 is the diplomatic courier protocol: a fast hello to agree on a "
            "briefcase (key exchange), then sealed messages with tamper-evident wax "
            "(AEAD). PKI is the passport office issuing and revoking the passports. Key "
            "management is the vault discipline — rotating guards, no master key under "
            "the doormat. Side channels are reading the courier's breathing pattern to "
            "guess the briefcase code without ever touching it."
        ),
        core_pillars=[
            "**TLS 1.3 handshake** — 1-RTT (or 0-RTT resumption for replay-tolerant data), ECDHE forward secrecy, AEAD-only cipher suites, encrypted extensions/certs.",
            "**PKI lifecycle** — issuance (CSA → CA), validation chains, revocation via OCSP/CRL (and the stapling shortcuts), CT transparency logs.",
            "**Key derivation** — PBKDF2 (older, GPU-cheap), Argon2id (memory-hard, OWASP-recommended: m=64MB, t=3, p=4), bcrypt (cost ≥ 12).",
            "**Side-channel resistance** — constant-time code, blinding, power/EM/timing countermeasures; 'the implementation is the attack surface'.",
        ],
        technical_domains=[
            "TLS pitfalls: disabling renegotiation, 0-RTT replay risk for state-changing requests, certificate pinning trade-offs (mobile only, with backup pins).",
            "Secrets hygiene: KMS/HSM-backed keys, envelope encryption, per-purpose keys, and rotation runbooks.",
            "Password storage: Argon2id/bcrypt always; never raw SHA for credentials.",
        ],
        detection_telemetry=[
            "Alerts on TLS version/cipher downgrades (POODLE/BEAST-class regressions) from proxy telemetry.",
            "OCSP/CRL failures and unexpected self-signed chains are config-drift signals, not just client errors.",
        ],
        real_world=[
            "Heartbleed and ROBOT showed protocol-correct systems failing through implementation memory handling.",
            "Let's Encrypt + Certificate Transparency made unauthorised issuance publicly auditable.",
        ],
        keywords=[
            "applied cryptography", "tls", "tls 1.3", "tls13", "handshake", "pki",
            "certificate authority", "ocsp", "crl", "key management", "pbkdf2", "argon2",
            "argon2id", "bcrypt", "key derivation", "side channel", "timing attack",
            "power analysis", "https", "ssl", "what is tls", "tls kya hai",
            "how does tls work", "0-rtt",
        ],
        roman_urdu=["tls samjhao", "https kaise kaam karta hai"],
        mapped_lab_ids=["net-02", "net-03", "pw-02"],
    ),
    KnowledgeNode(
        concept_id="network-security",
        title="Network Security (CyBOK KA18)",
        ka_ref="E18",
        category="Infrastructure Security",
        plain_definition=(
            "Network security hardens the transport fabric: DNS integrity (DNSSEC), routing "
            "authenticity (RPKI-signed BGP routes), port-based access control (802.1X), "
            "encrypted IP tunnels (IPsec, QUIC), and capacity defences against DoS/DDoS. "
            "The architectural end-state is Zero Trust Network Access — identity-aware, "
            "per-application tunnels replacing flat VPN networks — with segmentation "
            "shrinking whatever blast radius remains."
        ),
        analogy=(
            "DNS is the phone book — DNSSEC signs each entry so you cannot be sent to a "
            "fake office. BGP is the postal routing table — RPKI is the tamper-proof "
            "seal proving a mail truck really belongs where it claims. 802.1X is the ID "
            "badge at the network socket. DDoS defence is flood control; segmentation "
            "is watertight doors; ZTNA is abolishing the master key entirely."
        ),
        core_pillars=[
            "**DNSSEC** — a chain of signatures from the root down; DANE extends trust to TLS, mitigating rogue CAs.",
            "**BGP/RPKI** — route origin authorisation filters hijacks like the Pakistan-YouTube 2008 incident.",
            "**802.1X/EAP** — port authentication (EAP-TLS) before a device gets any network access.",
            "**IPsec & QUIC** — site-to-site/host tunnels with ESP, and QUIC multiplexing TLS 1.3 inside UDP.",
            "**DDoS mitigation** — scrubbing centres, anycast, BCP38 anti-spoofing; upstream cooperation is mandatory.",
            "**ZTNA** — application-level, identity-aware access brokers; users never join the flat corporate network.",
        ],
        technical_domains=[
            "Segmentation models: macro (zones) to micro (workload identity, Cloudflare-style AP segments).",
            "Detection: NetFlow baselines, DNS beaconing (high-entropy subdomains), SNORT/Suricata rules at choke points.",
        ],
        detection_telemetry=[
            "DNS tunneling signature: long random subdomains to one NS, low entropy per query but high NXDOMAIN volume.",
            "BGP anomalies: MOAS (multiple origin AS) announcements and RPKI-invalid routes.",
        ],
        real_world=[
            "The 2016 Mirai Dyn attack took down Twitter/Spotify: IoT + capacity planning failure.",
            "Amazon's 2019 BGP leak swallowed Cloudflare routes — RPKI ROAs would have rejected it.",
        ],
        keywords=[
            "network security", "dnssec", "bgp", "rpki", "802.1x", "ipsec", "quic",
            "ddos", "dos", "ddos mitigation", "ztna", "zero trust network access",
            "segmentation", "firewall", "ids", "ips", "vpn security", "what is network security",
            "dns tunneling", "network security kya hai",
        ],
        roman_urdu=["network security samjhao"],
        mapped_lab_ids=["net-01", "net-02", "net-03"],
    ),
    KnowledgeNode(
        concept_id="hardware-security",
        title="Hardware Security (CyBOK KA19)",
        ka_ref="E19",
        category="Infrastructure Security",
        plain_definition=(
            "Hardware security anchors trust in silicon: a Root of Trust that must be "
            "physically protected because nothing above it can verify it. TPM 2.0 chips "
            "measure boot integrity and seal secrets; HSMs guard crown-jewel keys; ARM "
            "TrustZone splits a CPU into secure and normal worlds. The adversarial "
            "frontier is physical: side channels (timing, power analysis, EM) and PUFs "
            "(silicon fingerprints) that turn manufacturing variation into identity."
        ),
        analogy=(
            "The Root of Trust is the cornerstone: if it can be swapped, the building's "
            "locks mean nothing. A TPM is a tamper-evident notary sealed inside the "
            "computer that only unseals secrets if the construction matches the approved "
            "blueprint (measured boot). Side channels are reading a safe's dial by "
            "listening to the clicks — the lock is correct; the leak is in the hand "
            "turning it."
        ),
        core_pillars=[
            "**Root of Trust** — immutable boot code + unique keys fused at manufacture.",
            "**TPM 2.0** — measured boot (PCR banks), sealed storage, remote attestation quotes.",
            "**HSM** — FIPS 140-3 validated key custody; CA keys and payment switching live here.",
            "**ARM TrustZone** — hardware-isolated secure world for TEEs (DRM, biometrics, Wallet).",
            "**Side channels** — timing, SPA/DPA power analysis, EM, cache (Spectre/Meltdown as microarchitectural side channels); constant-time + masking are countermeasures.",
            "**PUFs** — challenge-response silicon fingerprints for cheap per-device identity.",
        ],
        technical_domains=[
            "Measured vs secure boot: measurement records and reports (attestation); secure boot enforces signatures.",
            "Physical tamper evidence: mesh sensors, epoxy, zeroisation on probe detection (smartcard industry standards).",
        ],
        real_world=[
            "Spectre/Meltdown (2018) showed speculating CPUs leaking kernel memory — a hardware-level confidentiality break requiring OS mitigations.",
            "Console and payment security depend on TrustZone-style TEEs and HSMs respectively.",
        ],
        keywords=[
            "hardware security", "root of trust", "tpm", "tpm 2.0", "hsm",
            "trustzone", "tee", "secure enclave", "side channel attack", "power analysis",
            "puf", "physical unclonable function", "measured boot", "secure boot",
            "attestation", "spectre", "meltdown", "what is a tpm", "hardware root of trust",
        ],
        roman_urdu=["hardware security samjhao"],
        mapped_lab_ids=[],
    ),
    KnowledgeNode(
        concept_id="cps-ics-scada",
        title="Cyber-Physical Systems / ICS-SCADA Security (CyBOK KA20)",
        ka_ref="E20",
        category="Infrastructure Security",
        plain_definition=(
            "Industrial control systems merge computation with physics: PLCs execute "
            "ladder logic that moves real valves and rotors, SCADA supervises them, and "
            "the Purdue Model layers the architecture from field devices (Level 0) to "
            "the enterprise network (Level 5). Security here inverts IT instinct: "
            "Safety and Availability outrank Confidentiality, patch windows are measured "
            "in scheduled shutdowns, and legacy protocols (Modbus, DNP3) were designed "
            "with no authentication at all."
        ),
        analogy=(
            "An IT breach can steal the recipe; an OT breach can burn down the kitchen "
            "mid-service. Imagine patching the bakery's oven only during the annual "
            "maintenance week, while a burglar-proof front door (IT perimeter) means "
            "nothing if the recipe server shares a counter with the dough mixer (flat "
            "Purdue layers). Defence means air-gapped counters (zoning), guards at the "
            "pass-through (DMZ/ historians), and recipes that fail into a safe oven-off "
            "state (fail-safe design)."
        ),
        core_pillars=[
            "**Purdue Model** — L0 sensors/actuators, L1 PLCs, L2 SCADA/HMI, L3 site operations, L3.5 DMZ, L4/L5 enterprise; traffic should never skip levels.",
            "**Safety > Availability > Integrity > Confidentiality** — the CIA ordering flips (see the IT vs OT node).",
            "**Legacy constraints** — decades-old PLCs, vendor-certified patch windows, brittle protocols (Modbus/TCP has no auth by design).",
            "**Zones & conduits (IEC 62443)** — segment by risk zone, police every conduit between them.",
        ],
        technical_domains=[
            "PLC security: signed firmware, protected memory, logic-change detection (integrity baselines of ladder logic).",
            "Detection: protocol allow-listing (only known commands on the wire), physical-process anomaly detection (flow/pressure baselines that a classic IDS never sees).",
            "Case studies: Stuxnet (air-gap jump + centrifuge physics abuse), BlackEnergy (Ukrainian grid breakers), TRITON/Triton (Safety Instrumented System attack — literally attacking the safety layer).",
        ],
        detection_telemetry=[
            "Unrecognised Modbus function codes or write commands from non-engineering workstations.",
            "Historian/HMI login anomalies and PLC firmware/version changes outside maintenance windows.",
        ],
        real_world=[
            "Stuxnet modified converter drives while replaying benign sensor readings to operators — integrity of the HMI display itself was the target.",
            "IEC 62443 is the OT equivalent of ISO 27001: zones, conduits, security levels SL1-SL4.",
        ],
        keywords=[
            "ics security", "scada", "plc", "plc security", "ot security",
            "operational technology", "industrial control systems", "purdue model",
            "stuxnet", "blackenergy", "triton", "trisis", "modbus", "dnp3",
            "iec 62443", "cyber physical systems", "cps", "what is scada",
            "scada security", "industrial security", "62443",
        ],
        roman_urdu=["scada kya hai", "ot security samjhao"],
        mapped_lab_ids=["net-01", "endpoint-01"],
    ),
    KnowledgeNode(
        concept_id="it-vs-ot",
        title="IT vs OT Security — The Priority Inversion",
        ka_ref="E20",
        category="Infrastructure Security",
        plain_definition=(
            "IT (Information Technology) runs data: its loss is measured in money and "
            "reputation, so **Confidentiality usually leads**, followed by Integrity, "
            "then Availability. OT (Operational Technology) runs physics: its failure is "
            "measured in explosions, environmental release, and human life, so "
            "**Safety and Availability lead** and Confidentiality often ranks last. "
            "A leak of a pipeline pressure diagram is embarrassing; a wrongly commanded "
            "valve is catastrophic. Every other OT security difference — patching, "
            "lifecycles, protocols, networks — flows from this priority inversion."
        ),
        analogy=(
            "IT guards a bank vault: the gold must not be *seen* or *touched*, and "
            "occasionally you accept downtime for maintenance. OT guards a hospital's "
            "life-support power: it must keep running even while under attack — you "
            "would rather an intruder read the electrical drawings (confidentiality "
            "loss) than have the lights go out for one second (availability/safety "
            "loss)."
        ),
        core_pillars=[
            "**IT priorities**: Confidentiality ≥ Integrity > Availability; asset = information; breach = data loss/fraud.",
            "**OT priorities**: Safety > Availability > Integrity > Confidentiality; asset = physical process; breach = physical damage or downtime.",
            "**Different clocks** — IT patches weekly; OT patches in scheduled plant shutdowns with vendor recertification.",
            "**Different worlds** — IT: AD-managed, cloud, TLS everywhere; OT: PLCs, serial, unauthenticated protocols, 20-year lifecycles.",
            "**Convergence risk** — Purdue Level 3.5 DMZ exists precisely so enterprise IT problems (a phished laptop) cannot write to Level 1 PLCs.",
        ],
        technical_domains=[
            "OT segmentation: one-way data diodes for reporting up, no direct paths down.",
            "Detection differences: OT values *process* anomalies (pump rpm at 2 a.m.) more than malware hashes.",
            "Incident response: OT containment means isolating zones without tripping the plant; emergency shutdown is a safety decision, not a security one.",
        ],
        real_world=[
            "Colonial Pipeline: the IT ransomware infection forced an OT shutdown because billing could not run — a convergence lesson, not a PLC hack.",
            "Ukraine 2015 (BlackEnergy) and 2016 (Industroyer): direct OT attacks where the kill chain deliberately ended at physical breakers.",
        ],
        comparison_table={
            "caption": "IT vs OT — key contrasts",
            "headers": ["Dimension", "IT Security", "OT Security"],
            "rows": [
                ["Primary objective", "Protect data (CIA, C first)", "Protect people & process (Safety first)"],
                ["Priority order", "Confidentiality ≥ Integrity > Availability", "Safety > Availability > Integrity > Confidentiality"],
                ["Failure mode", "Data loss, fraud, fines", "Physical damage, environmental harm, injury"],
                ["Patching", "Weekly/monthly cycles", "Scheduled shutdowns, vendor-certified"],
                ["Asset lifetime", "3-5 years", "15-30 years"],
                ["Protocols", "TLS, Kerberos, SMB (authenticated)", "Modbus, DNP3, PROFIBUS (often no auth)"],
                ["Architecture", "Cloud/mobile/zero trust", "Purdue Model zones & conduits (IEC 62443)"],
            ],
        },
        keywords=[
            "it vs ot", "ot vs it", "difference between it and ot", "it versus ot",
            "it security vs ot security", "difference between it and ot security",
            "what is ot", "what is the difference between it and ot",
            "operational technology vs information technology", "it ot convergence",
            "it ot difference", "kya difference hai it aur ot",
        ],
        roman_urdu=["it aur ot mein farq", "it vs ot samjhao"],
        mapped_lab_ids=["net-01", "endpoint-01"],
    ),
    KnowledgeNode(
        concept_id="physical-telecom-security",
        title="Physical Layer & Telecommunications Security (CyBOK KA21)",
        ka_ref="E21",
        category="Infrastructure Security",
        plain_definition=(
            "Below the network stack lies electromagnetic and radio reality. RF signals "
            "leak and can be intercepted; TEMPEST studies compromising emanations from "
            "monitors and cables; cellular generations (2G-5G) each carry distinct "
            "security models and weaknesses, with IMSI catchers (fake base stations) "
            "exploiting the trust phones place in towers. GNSS spoofing rewrites the sky: "
            "a receiver can be dragged to false coordinates, which is why distance "
            "bounding and multi-sensor integrity checks exist."
        ),
        analogy=(
            "A phone believes any tower that shouts the loudest — an IMSI catcher is a "
            "fake tower with a megaphone and a clipboard, noting who passes by. GPS "
            "spoofing is a theatrical backdrop of fake stars: the ship's compass never "
            "realises the sky is a projection. TEMPEST is eavesdropping by watching the "
            "light of a lamp flicker with the screen's glow."
        ),
        core_pillars=[
            "**RF interception & emanations** — everything radiating is a signal; shielding, zoning, and filtering (TEMPEST standards) bound the leak.",
            "**Cellular evolution** — 2G GSM's A5/1 weakness and no network auth → 3G mutual auth → 4G SIM-fixed keys → 5G SUCI identifier privacy; every generation hardens the previous decade's mistakes.",
            "**IMSI catchers** — exploit unidirectional trust; detectable via cell-ID anomalies and downgrade attempts.",
            "**GNSS spoofing/jamming** — civil GPS signals are unauthenticated; counter with RAIM checks, multi-constellation, inertial dead-reckoning.",
            "**Distance bounding** — challenge-response timing (Mafia-fraud resistance) bounds how far a credential truly is.",
        ],
        technical_domains=[
            "Drone/geofencing abuse, RF jamming vs spoofing triage; spectrum monitoring as a detective control.",
            "UAV/drone countermeasures: protocol-level RF takeover vs crude jamming; legality varies by jurisdiction.",
        ],
        real_world=[
            "Black Sea and Baltic GNSS spoofing incidents replay phantom waypoints to civilian navigation.",
            "StingRays moved from classified to metropolitan police and then to criminal use — a full lifecycle of technology diffusion.",
        ],
        keywords=[
            "physical layer security", "telecommunications security", "tempest",
            "rf security", "imsi catcher", "stingray", "cellular security",
            "gsm security", "5g security", "gps spoofing", "gnss", "gnss spoofing",
            "distance bounding", "jamming", "what is tempest", "imsi",
        ],
        roman_urdu=["gps spoofing samjhao"],
        mapped_lab_ids=[],
    ),
    KnowledgeNode(
        concept_id="cybok-overview",
        title="CyBOK — The Cyber Security Body of Knowledge v1.1.0",
        ka_ref="A1",
        category="Human, Organisational & Regulatory Aspects",
        plain_definition=(
            "CyBOK (Cyber Security Body of Knowledge, v1.1.0) is the scholarly reference "
            "curriculum for the discipline, funded by the UK's National Cyber Security "
            "Programme and shaped by UK academia, industry, and NCSC. It organises the "
            "field into **21 Knowledge Areas across 5 categories** — from Risk Management "
            "and Law through Attacks & Defences, Systems, Software & Platform, and "
            "Infrastructure Security — so that curricula, certifications, and hiring "
            "frameworks share one authoritative map of what a security professional "
            "should know."
        ),
        analogy=(
            "If cybersecurity were medicine, CyBOK would be the canonical anatomy textbook: "
            "agreeing on the names of the organs (KAs) so every medical school, hospital, "
            "and examiner teaches and tests the same body — literally the *body of "
            "knowledge*."
        ),
        core_pillars=[
            "**Category A — Human, Organisational & Regulatory (4 KAs)**: Risk Management & Governance; Law & Regulation; Human Factors; Privacy & Online Rights.",
            "**Category B — Attacks & Defences (4 KAs)**: Malware & Attack Technologies; Adversarial Behaviours; Security Operations & Incident Management; Forensics.",
            "**Category C — Systems Security (5 KAs)**: Cryptography; Operating Systems & Virtualisation Security; Distributed Systems Security; Formal Methods for Security; Authentication, Authorisation & Accountability.",
            "**Category D — Software & Platform Security (3 KAs)**: Software Security; Web & Mobile Security; Secure Software Lifecycle.",
            "**Category E — Infrastructure Security (5 KAs)**: Applied Cryptography; Network Security; Hardware Security; Cyber-Physical Systems / ICS-SCADA; Physical Layer & Telecommunications Security.",
        ],
        technical_domains=[
            "Each KA is a stand-alone reference with taxonomies, principles, and case studies; KAs cross-link (e.g. AAA ↔ Cryptography ↔ Applied Cryptography).",
            "CyBOK underpins degree accreditation (BCS/NCSC certification of university programmes) and maps cleanly onto NIST/ISO frameworks used in industry.",
            "CyberGPT's knowledge engine indexes every one of the 21 KAs so any concept query can be answered locally, offline, in milliseconds.",
        ],
        real_world=[
            "Version 1.1.0 added and refined KAs across human factors, privacy, and CPS domains — the definitive syllabus snapshot.",
            "Employers increasingly write role profiles against CyBOK KAs; SOC apprenticeship standards reference it directly.",
        ],
        keywords=[
            "cybok", "cybok v1.1", "cybok v1.1.0", "body of knowledge", "cyber security body of knowledge",
            "explain cybok", "what is cybok", "what are the cybok knowledge areas",
            "cybok 21 knowledge areas", "cybok categories", "cybok syllabus", "cybok kya hai",
            "21 knowledge areas", "what is the body of knowledge",
        ],
        roman_urdu=["cybok samjhao"],
        mapped_lab_ids=["siem-01", "web-01"],
    ),
]


# ============================================================================
# Query normalisation — fuzzy, typo-tolerant, multilingual
# ============================================================================
_WORD_RE = re.compile(r"[^a-z0-9\s]+")

# Phrase-level typo/compaction fixes (applied before word-level fixes).
_PHRASE_FIXES: List[Tuple[str, str]] = [
    ("zerotrust", "zero trust"),
    ("zero-trust", "zero trust"),
    ("passthehash", "pass the hash"),
    ("sqli", "sql injection"),
    ("sqlinjection", "sql injection"),
    ("itvsot", "it vs ot"),
    ("otvsit", "ot vs it"),
    ("ciatriad", "cia triad"),
]

# Word-level typo dictionary (common misspellings learners actually type).
_WORD_FIXES: Dict[str, str] = {
    "secuirty": "security",
    "securty": "security",
    "securtiy": "security",
    "cybersecuirty": "cyber security",
    "injeciton": "injection",
    "cryptograpy": "cryptography",
    "cryptogaphy": "cryptography",
    "athentication": "authentication",
    "authentcation": "authentication",
    "autherization": "authorization",
    "forrensics": "forensics",
    "forenscis": "forensics",
    "malaware": "malware",
    "malwere": "malware",
    "randsomware": "ransomware",
    "ransomwere": "ransomware",
    "kerborasting": "kerberoasting",
    "kerberoast": "kerberoasting",
    "fisihing": "phishing",
    "phsihing": "phishing",
    "firewlal": "firewall",
    "encyption": "encryption",
    "encrypton": "encryption",
    "hackng": "hacking",
    "vulnerabilty": "vulnerability",
    "vulnerbility": "vulnerability",
    "thret": "threat",
    "incidant": "incident",
    "incendent": "incident",
}

# Interrogative / conversational prefixes to strip (English + Roman Urdu).
_PREFIX_RE = re.compile(
    r"^(?:what\s+is\s+the\s+difference\s+between|what\s+is\s+difference\s+between|"
    r"what\s+is\s+the\s+|what\s+is\s+|what\s+are\s+|what\s+does\s+|whats\s+|"
    r"difference\s+between|diff\s+between|difference\s+of|"
    r"can\s+you\s+explain|could\s+you\s+explain|please\s+explain|explain\s+to\s+me\s+|explain\s+|"
    r"define\s+|describe\s+|tell\s+me\s+about\s+|tell\s+me\s+|"
    r"how\s+does\s+|how\s+do\s+|why\s+is\s+|why\s+does\s+|"
    r"i\s+want\s+to\s+know\s+about\s+|help\s+me\s+understand\s+|give\s+me\s+an\s+overview\s+of\s+|"
    r"kya\s+hai\s+ye\s+|kya\s+hota\s+hai\s+|kya\s+hai\s+|kia\s+hai\s+|"
    r"samjha\s+do\s+|samjhao\s+|samjha\s+|bata\s+do\s+|batao\s+|"
    r"overview\s+of\s+|about\s+)\s*",
    re.IGNORECASE,
)

# Trailing conversational suffixes (Roman Urdu / politeness).
_SUFFIX_RE = re.compile(
    r"\s*(?:kya\s+hai|kya\s+hota\s+hai|kia\s+hai|samjhao|samjha\s+do|batao|bata\s+do|"
    r"please|plz|means|mean|exactly)\s*[?.!]*\s*$",
    re.IGNORECASE,
)


def _normalize(text: str) -> str:
    """Lowercase, strip punctuation, fix common typos, collapse whitespace."""
    lowered = (text or "").lower().strip()
    out = _WORD_RE.sub(" ", lowered)
    for bad, good in _PHRASE_FIXES:
        if bad != good:
            out = out.replace(bad, good)
    words = [_WORD_FIXES.get(w, w) for w in out.split()]
    out = " ".join(words)
    out = re.sub(r"\s+", " ", out).strip()
    return out


def _query_variants(text: str) -> List[str]:
    """Build every normalized surface form worth matching against."""
    norm = _normalize(text)
    if not norm:
        return []
    stripped = _PREFIX_RE.sub("", norm)
    stripped = _SUFFIX_RE.sub("", stripped)
    stripped = re.sub(r"\s+", " ", stripped).strip(" ?.!")
    variants = [norm]
    if stripped and stripped != norm:
        variants.append(stripped)
    return [v for v in variants if len(v) >= 2]


# ============================================================================
# Pedagogical renderer — natural Claude/ChatGPT-style concept layout
# ============================================================================
def _bullets(items: List[str]) -> str:
    return "\n".join(f"- {item}" for item in items if item)


def _render_table(spec: Dict[str, Any]) -> str:
    headers = spec.get("headers", [])
    rows = spec.get("rows", [])
    caption = spec.get("caption", "")
    if not headers or not rows:
        return ""
    lines: List[str] = []
    if caption:
        lines.append(f"**{caption}**")
        lines.append("")
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


# ============================================================================
# KnowledgeEngine
# ============================================================================
class KnowledgeEngine:
    """Local, offline CyBOK v1.1.0 answer engine.

    Guarantees:
      * No network I/O, no tokens, no external dependency beyond the lab
        catalog (data/labs/*.json).
      * High-confidence matches return fully-rendered pedagogical markdown
        in well under 10 ms.
      * `mapped_lab_ids` are validated against the real lab catalog at
        load time so suggested chips are always real, clickable labs.
    """

    HIGH_CONFIDENCE = 60          # minimum score for an instant engine answer
    MAX_SUGGESTED_LABS = 2

    def __init__(self, nodes: List[KnowledgeNode]):
        self.nodes: List[KnowledgeNode] = list(nodes)
        self._by_id: Dict[str, KnowledgeNode] = {}
        self._validate_labs()
        for node in self.nodes:
            if node.concept_id in self._by_id:
                raise ValueError(f"Duplicate knowledge node id: {node.concept_id}")
            self._by_id[node.concept_id] = node
        # Precompile every keyword pattern once so lookups stay <10ms.
        # Index entry: (node, n_keywords, [(kw_norm, exact_set, pattern)])
        self._index: List[Tuple[KnowledgeNode, int, List[Tuple[str, re.Pattern]]]] = []
        for node in self.nodes:
            entries: List[Tuple[str, re.Pattern]] = []
            seen: set = set()
            for kw in node.keywords:
                kw_norm = _normalize(kw)
                if not kw_norm or kw_norm in seen:
                    continue
                seen.add(kw_norm)
                pattern = re.compile(r"(?:^|\s)" + re.escape(kw_norm) + r"(?:\s|$)")
                entries.append((kw_norm, pattern))
            self._index.append((node, len(entries), entries))

    # ------------------------------------------------------------------
    # Lab catalog binding
    # ------------------------------------------------------------------
    def _validate_labs(self) -> None:
        """Drop mapped lab IDs that are not real catalog entries."""
        for node in self.nodes:
            valid = [lid for lid in node.mapped_lab_ids if lid in LAB_REPOSITORY]
            dropped = set(node.mapped_lab_ids) - set(valid)
            if dropped:
                logger.warning(
                    "Node %s references unknown lab ids %s — dropping them",
                    node.concept_id, sorted(dropped),
                )
            node.mapped_lab_ids = valid

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------
    def lookup(self, query: str) -> Tuple[Optional[KnowledgeNode], float]:
        """Fuzzy-match a query to a knowledge node.

        Returns (node, score) where score is 0..100; node is None when
        nothing clears the noise floor (the caller applies the threshold).

        Tie-breaks prefer the longer matched keyword, then the more
        focused node (fewer keywords), so 'what is ransomware' resolves
        to the dedicated ransomware node rather than the general malware
        KA that happens to share the keyword.
        """
        variants = _query_variants(query)
        if not variants:
            return None, 0.0
        best_key: Tuple[float, float, float] = (0.0, 0.0, 0.0)
        best_node: Optional[KnowledgeNode] = None
        best_score = 0.0
        for node, n_keywords, entries in self._index:
            node_score = 0.0
            matched_len = 0.0
            for kw_norm, pattern in entries:
                candidate = 0.0
                for variant in variants:
                    if variant == kw_norm:
                        candidate = 100.0
                        break
                    if pattern.search(variant):
                        # Longer keyword matches are more specific.
                        candidate = max(candidate, 60.0 + min(float(len(kw_norm)), 39.0))
                if candidate > node_score:
                    node_score = candidate
                    matched_len = float(len(kw_norm))
            if node_score <= 0.0:
                continue
            key = (node_score, matched_len, -float(n_keywords))
            if key > best_key:
                best_key = key
                best_node = node
                best_score = node_score
        return best_node, best_score

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def render(self, node: KnowledgeNode) -> str:
        """Render a node as natural, pedagogical markdown.

        Layout adapts: pure concepts get no forced SOC telemetry section;
        attack/detection topics include the Detection Telemetry lens.
        """
        ka = CYBOK_KA_INDEX.get(node.ka_ref, {})
        ka_name = ka.get("name", node.ka_ref)
        parts: List[str] = []
        parts.append(f"## {node.title}")
        parts.append("")
        parts.append(node.plain_definition)
        parts.append("")
        parts.append(f"> **Everyday analogy:** {node.analogy}")
        parts.append("")
        parts.append("### Core Pillars & Principles")
        parts.append(_bullets(node.core_pillars))
        parts.append("")
        parts.append("### Practical Mechanics & Technical Domains")
        parts.append(_bullets(node.technical_domains))
        parts.append("")
        if node.comparison_table:
            table_md = _render_table(node.comparison_table)
            if table_md:
                parts.append(table_md)
                parts.append("")
        if node.detection_telemetry:
            parts.append("### Detection Telemetry — SOC Lens")
            parts.append(_bullets(node.detection_telemetry))
            parts.append("")
        parts.append("### Real-World Examples & Industry Standards")
        parts.append(_bullets(node.real_world))
        parts.append("")
        parts.append(
            f"*CyBOK v1.1.0 — {ka_name} ({node.ka_ref}) · answered locally by the "
            f"offline knowledge engine in 0 tokens.*"
        )
        return "\n".join(parts).strip()

    # ------------------------------------------------------------------
    # Lab recommendation chips (real catalog objects only)
    # ------------------------------------------------------------------
    def suggest_labs(self, node: Optional[KnowledgeNode], query: str) -> List[Dict[str, str]]:
        """Return up to 2 verified lab objects: {"id", "title", "category"}."""
        chosen: List[Dict[str, str]] = []
        if node is not None:
            for lab_id in node.mapped_lab_ids:
                lab = LAB_REPOSITORY.get(lab_id)
                if not lab:
                    continue
                chosen.append({
                    "id": lab["id"],
                    "title": lab.get("title", lab["id"]),
                    "category": lab.get("category", "General"),
                })
                if len(chosen) >= self.MAX_SUGGESTED_LABS:
                    return chosen
        # Fallback: score the catalog by keyword overlap with the query.
        if len(chosen) < self.MAX_SUGGESTED_LABS:
            norm = _normalize(query)
            tokens = set(norm.split()) if norm else set()
            scored: List[Tuple[float, str]] = []
            for lab_id, lab in LAB_REPOSITORY.items():
                if any(c["id"] == lab_id for c in chosen):
                    continue
                title = lab.get("title", "").lower()
                category = lab.get("category", "").lower()
                objectives = " ".join(lab.get("learning_objectives", [])).lower()
                haystack = f"{title} {category} {objectives}"
                overlap = sum(1 for t in tokens if t and len(t) > 3 and t in haystack)
                if overlap > 0:
                    scored.append((float(overlap), lab_id))
            scored.sort(key=lambda pair: (-pair[0], pair[1]))
            for _, lab_id in scored:
                lab = LAB_REPOSITORY[lab_id]
                chosen.append({
                    "id": lab["id"],
                    "title": lab.get("title", lab["id"]),
                    "category": lab.get("category", "General"),
                })
                if len(chosen) >= self.MAX_SUGGESTED_LABS:
                    break
        return chosen

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def answer(self, query: str) -> Optional[Dict[str, Any]]:
        """High-confidence instant answer, or None to defer to the LLM."""
        started = time.perf_counter()
        if not query or not query.strip():
            return None
        node, score = self.lookup(query)
        if node is None or score < self.HIGH_CONFIDENCE:
            return None
        markdown = self.render(node)
        labs = self.suggest_labs(node, query)
        latency_ms = (time.perf_counter() - started) * 1000.0
        return {
            "node_id": node.concept_id,
            "title": node.title,
            "ka_ref": node.ka_ref,
            "markdown": markdown,
            "suggested_labs": labs,
            "confidence": round(min(score / 100.0, 1.0), 2),
            "latency_ms": round(latency_ms, 2),
            "model_used": ENGINE_ID,
            "tokens_used": 0,
        }

    def get_node(self, concept_id: str) -> Optional[KnowledgeNode]:
        return self._by_id.get(concept_id)

    def stats(self) -> Dict[str, Any]:
        ka_coverage = sorted({n.ka_ref for n in self.nodes})
        return {
            "engine": ENGINE_ID,
            "nodes": len(self.nodes),
            "cybok_version": "1.1.0",
            "ka_covered": len(ka_coverage),
            "ka_total": len(CYBOK_KA_INDEX),
            "labs_in_catalog": len(LAB_REPOSITORY),
            "offline": True,
        }


# Shared singleton (import-safe: no LLM dependency, no network access).
knowledge_engine = KnowledgeEngine(_NODES)


__all__ = [
    "KnowledgeEngine",
    "KnowledgeNode",
    "knowledge_engine",
    "CYBOK_KA_INDEX",
    "ENGINE_ID",
]
