# CyberGPT — Enterprise Architecture Manual & CyBOK v1.1.0 Knowledge Ontology

> **CyberGPT — Defensive Cyber Intelligence & SOC Operations Simulator**
> Canonical engineering handbook, conversational constitution, and complete
> CyBOK v1.1.0 syllabus index. Every module in this repository must comply.

---

## 1. Project Manifesto & Local Governance

| Item | Value |
|---|---|
| **Project** | CyberGPT — Defensive Cyber Intelligence & SOC Operations Simulator |
| **Creator & Architecture Lead** | **Muhammad Umair** |
| **Runtime Environment** | Strictly local (`http://127.0.0.1:5000`) on Kali Linux |
| **Local Branch** | `feature/vibe-cybok-core` (local only — never pushed to any remote) |
| **Core Standard** | Academic rigor aligned with **CyBOK v1.1.0**, **SANS PICERL**, **NIST SP 800-30/39/61**, and **ISO/IEC 27005** |
| **Frontend** | Vanilla JS + native CSS design tokens (`static/css/style.css`) + Lucide SVG icons |
| **Backend** | Flask (Python 3) + `services/` module architecture |
| **Knowledge Engine** | `services/knowledge_engine.py` — local CyBOK v1.1.0 ontology, instant (<10ms, 0 tokens) |
| **LLM Bridge** | `services/llm_service.py` — NVIDIA NIM failover + BYOK (OpenAI / Anthropic) |

### Local Governance Rules

1. **Strictly local work.** All development happens on local branch
   `feature/vibe-cybok-core`. Never run `git push`; never interact with any
   remote git repository. Commits are atomic and follow
   `feat(<scope>): <description>`.
2. **No truncation, no placeholders.** Every file must be complete,
   syntactically valid, and executable. No `TODO`, no `pass`, no stub blocks.
3. **Fail-safe retry limit.** For any failing check, attempt at most 3
   targeted root-cause fixes; then stop and surface the raw error trace.
4. **CSS discipline.** Do not invent Tailwind utility classes that are not
   already proven in `templates/index.html`. New styles use the native CSS
   design tokens (`var(--obsidian)`, `var(--surface)`, `var(--panel)`,
   `var(--edge)`, `var(--ink)`, `var(--accent)`, `var(--cyan)`,
   `var(--emerald)`, `--mono`, `--sans`, `--r-pill`) and existing component
   classes (`.btn-cyber`, `.card`, `.lab-chip`, `.action-chip`).
5. **Secrets hygiene.** Never print, `cat`, log, or commit `.env` or real API
   keys. `.env` is gitignored; `.env.example` contains placeholders only.
6. **No raw emojis in the UI.** Badges, stats, and action buttons use Lucide
   SVG icons via `lucide.createIcons()` to maintain the dark enterprise SOC
   aesthetic.
7. **Vanilla JS conventions.** `static/js/app.js` defines
   `const $ = (sel) => document.querySelector(sel);` and
   `const $$ = (sel) => document.querySelectorAll(sel);`. Never use jQuery
   methods (`.on()`, `.val()`, `.html()`).

---

## 2. Conversational Architecture & Pedagogical Standards

### 2.1 Tone & Voice (Claude / ChatGPT Parity)

- **Pedagogical**: every answer teaches, not just informs.
- **Authoritative yet accessible**: precise terminology is always paired with
  a plain-language restatement.
- **Structured**: headings, tight bullets, concrete artifacts (Event IDs,
  commands, code) — never walls of prose.
- **Empathetic**: acknowledges the analyst's context and guides the next step.

### 2.2 No Forced Incident Templates

**Never** force incident-triage headers ("Vulnerability Mechanics / IoCs /
Mitigation") onto definition, concept, or architectural questions.
`"What is Zero Trust?"` is a *concept* question and receives the adaptive
concept layout below — not a SOC triage template. Incident-triage structure is
reserved for queries that are actually about live incidents, detections,
exploits, or telemetry triage.

### 2.3 Adaptive Response Layout for Concept Questions

When the intent is a definition / concept / architecture question, the
response follows this five-section pedagogical shape:

1. **Plain Language Definition & Core Purpose** — with an everyday intuitive
   analogy (e.g., "Zero Trust is like a bank that checks your ID at every
   door, not just at the entrance").
2. **Core Pillars & Principles** — the governing models (CIA Triad, Zero
   Trust tenets, Defense-in-Depth layers, Safety/Availability-first for OT).
3. **Practical Technical Domains & Mechanics** — how it is actually
   implemented, protocol-level mechanics, concrete artifacts.
4. **Real-world Examples & Industry Standards** — breaches, CVEs, standards
   (NIST, ISO, OWASP, MITRE ATT&CK) that anchor the concept.
5. **Interactive Guidance** — relevant CyBOK lab recommendation chips loaded
   dynamically from `data/labs/*.json` and rendered as clickable badges.

### 2.4 Multilingual Natural Fluidity

CyberGPT natively understands **English**, **Roman Urdu**, and **Urdu**
(سرکاری اردو) with typo tolerance:

- Typos: `"secuirty"`, `"passthehash"`, `"sqli"`, `"zerotrust"`, `"injection"`.
- Roman Urdu: `"kiska bot ho"`, `"tera naam"`, `"tum kaun ho"`.
- Responses mirror the user's language. A Roman Urdu question may receive a
  Roman Urdu reply; an English question receives English.

---

## 3. CyBOK v1.1.0 Knowledge Ontology — 21 Knowledge Areas Across 5 Categories

The Cyber Security Body of Knowledge (CyBOK) v1.1.0 organises the discipline
into **21 Knowledge Areas (KAs)** in **5 categories**. `services/knowledge_engine.py`
indexes every KA below as a structured knowledge node (definition, analogy,
pillars, mechanics, telemetry, mitigations, mapped lab IDs).

### Category A — Human, Organisational & Regulatory Aspects

#### KA 1. Risk Management & Governance
- **Frameworks**: ISO 31000, ISO/IEC 27005, NIST SP 800-30/39, FAIR,
  Octave Allegro, STRIDE, Attack Trees, STAMP/STPA-Sec, TOGAF, O-DM, SABSA.
- **Theory**: Rasmussen hierarchy (Functional → Physical), ALARP/ALARA
  principles, Renn's Risk Types (Routine, Complex, Uncertain, Ambiguous).
- **Culture**: Just Culture (Dekker), concern assessment, Jaquith security
  metrics criteria.
- **Core practice**: risk appetite, treatment (accept / mitigate / transfer /
  avoid), residual risk, security metrics that measure outcome not activity.

#### KA 2. Law & Regulation
- **Legal theory**: prescriptive vsjuridical law, enforcement jurisdiction,
  in rem vs in personum rights, data sovereignty, CLOUD Act.
- **Regulations**: GDPR (Articles 3, 5, 25, 32, 33, 44-49, 83), Budapest
  Convention on Cybercrime (ETS 185), Computer Misuse Act 1990, CFAA,
  US Fourth Amendment.
- **Civil liability**: negligence, duty of care, Learned Hand formula
  (B < P×L), vicarious liability, breach of contract, warranties.
- **Sectoral**: PCI DSS.

#### KA 3. Human Factors
- Usable security, cognitive load, mental models.
- Employee security awareness metrics.
- Social engineering vectors (phishing, pretexting, vishing, tailgating).

#### KA 4. Privacy & Online Rights
- Privacy Enhancing Technologies (PETs), data minimisation.
- Pseudonymisation vs anonymisation.
- Inference control, differential privacy, metadata confidentiality.

### Category B — Attacks & Defences

#### KA 5. Malware & Attack Technologies
- **Taxonomy**: viruses, worms, trojans, rootkits, ransomware, PUPs, botnets,
  fileless malware.
- **Static analysis**: disassembly, PE headers.
- **Dynamic analysis**: sandboxing, API monitoring.
- **Advanced**: fuzzing, symbolic & concolic execution.
- **Evasion**: packing, anti-analysis, timing checks.

#### KA 6. Adversarial Behaviours
- **Threat actor profiling**: nation-state (APT), cybercrime (FIN groups),
  hacktivist, insider.
- **Models**: Cyber Kill Chain (lockheed martin 7 stages), MITRE ATT&CK
  matrix (tactics/techniques/procedures).
- **Cyber Threat Intelligence (CTI)**: strategic / operational / tactical
  feeds, IoC lifecycle, sharing communities (MISP, STIX/TAXII).

#### KA 7. Security Operations & Incident Management
- **Telemetry**: Syslog, NetFlow, Windows Event Logs — 4624 (logon), 4625
  (failed logon), 4776 (NTLM validation), 4688 (process creation), 4672
  (special privileges), 7045 (service install), 1102 (audit log cleared);
  Sysmon Events 1 (process), 3 (network), 7 (image load), 13 (registry set).
- **Operations**: SIEM & SOAR alert correlation, anomaly detection,
  rule-based detection, false-positive mitigation.
- **Lifecycle**: SANS PICERL (Preparation, Identification, Containment,
  Eradication, Recovery, Lessons Learned); NIST SP 800-61r2.

#### KA 8. Forensics
- **Disk**: MFT, Prefetch, Shimcache, Amcache, Registry Run keys.
- **Memory**: Volatility framework, LSASS dumping.
- **Techniques**: file carving, timeline reconstruction.
- **Legal**: Daubert standard for admissibility of expert evidence,
  chain of custody.

### Category C — Systems Security

#### KA 9. Cryptography
- **Symmetric**: block ciphers (AES, modes CBC / GCM), stream ciphers
  (ChaCha20).
- **Hashes & MACs**: SHA-256, SHA-3 sponge construction, HMAC.
- **Asymmetric**: RSA, Diffie-Hellman, ECC.
- **Advanced**: Zero-Knowledge Proofs, Multi-Party Computation,
  lattice-based post-quantum cryptography.

#### KA 10. Operating Systems & Virtualisation Security
- **OS primitives**: ACLs, capabilities, rings of protection, ASLR, DEP/NX,
  CFI.
- **Virtualisation**: Type-1 vs Type-2 hypervisors, hypervisor escape
  vectors.
- **Containers**: cgroups, namespaces, container isolation boundaries.

#### KA 11. Distributed Systems Security
- Consensus protocols: Raft, PBFT.
- P2P network attacks: Sybil, eclipse.
- Distributed denial-of-service resilience.

#### KA 12. Formal Methods for Security
- Mathematical verification, trace properties, hyperproperties.
- Theorem proving, model checking.
- Information flow control: Bell-LaPadula, Biba, Clark-Wilson.

#### KA 13. Authentication, Authorisation & Accountability (AAA)
- **Protocols**: Kerberos (TGT / TGS / SPN mechanics), SAML, OAuth 2.0,
  OpenID Connect, WebAuthn/FIDO2.
- **Access control models**: DAC, MAC, RBAC, ABAC.
- **Practices**: MFA, PAM (privileged access management), password-less.

### Category D — Software & Platform Security

#### KA 14. Software Security
- Memory corruption: buffer overflow, use-after-free.
- Race conditions: TOCTOU (time-of-check to time-of-use).
- Type safety; SAST, DAST; memory-safe languages (Rust, Go).

#### KA 15. Web & Mobile Security
- **OWASP Top 10**: SQLi, XSS, CSRF, SSRF, IDOR, Security Misconfigurations.
- **Mobile**: sandboxing, permission models, insecure storage, certificate
  pinning, WebView vulnerabilities.

#### KA 16. Secure Software Lifecycle
- Microsoft SDL, BSIMM, OWASP SAMM.
- Threat modelling, DevSecOps pipelines, SBOM, dependency scanning.

### Category E — Infrastructure Security

#### KA 17. Applied Cryptography
- TLS 1.3 handshake mechanics (0-RTT, forward secrecy).
- PKI certificate lifecycle (issuance, revocation via OCSP/CRL).
- Key management & derivation: PBKDF2, Argon2id.
- Side-channel resistance.

#### KA 18. Network Security
- DNSSEC, BGP security (RPKI), IEEE 802.1X, IPsec, QUIC.
- DoS/DDoS mitigation.
- Zero Trust Network Access (ZTNA), micro-segmentation.

#### KA 19. Hardware Security
- Root of Trust (RoT), TPM 2.0, HSM, ARM TrustZone.
- Side-channel attacks: timing, power analysis.
- Physical Unclonable Functions (PUFs).

#### KA 20. Cyber-Physical Systems (CPS) / ICS-SCADA
- **OT vs IT priorities**: Safety & Availability > Confidentiality (the
  inverse of IT's CIA ordering).
- PLC programming security, Purdue Model (Levels 0-5).
- Legacy patching constraints; Stuxnet / BlackEnergy case analysis.

#### KA 21. Physical Layer & Telecommunications Security
- RF interception, TEMPEST emanations.
- Cellular security 2G-5G, IMSI catching.
- GPS/GNSS spoofing; distance bounding protocols.

---

## 4. Dual-Mode Intelligence & Intent Routing

### 4.1 Hierarchy of Request Processing

```
User message (validated: <= 8000 chars, delimiters sanitized)
  |
  |-- STEP 1: Case-insensitive Identity & Meta check
  |     ["who are you", "whats your name", "who made you", "who designed you",
  |      "who is your developer", "tera naam", "tera name", "kiska bot ho",
  |      "tum kaun ho"]
  |     => BYPASS LLM. Instant deterministic credit to Muhammad Umair.
  |        No empty template headings.
  |
  |-- STEP 2: Mode check
  |     mode == 'cyber':
  |       a) Query services/knowledge_engine.py.
  |          High-confidence match => instant CyBOK response (<10ms, 0 tokens)
  |          with up to 2 verified lab chips from data/labs/*.json.
  |       b) Unambiguous off-topic (cooking, movies, stock/crypto trading)
  |          => polite 1-line notice + action chip "Switch to Normal Chat &
  |             Ask Again" (Lucide icon, no raw emoji).
  |       c) Complex / novel cyber query => forward to LLM with the adaptive
  |          defensive prompt (concept layout vs incident triage, chosen by
  |          the model per §2.2 / §2.3).
  |
  |     mode == 'normal':
  |       Bypass cyber restrictions. Forward to LLM with a comprehensive
  |       general-assistant prompt (trading, programming, everyday topics in
  |       English, Roman Urdu, or Urdu).
```

### 4.2 Dynamic Lab Recommendation Chips

- Assistant responses never contain inline
  `[CyberGPT Lab Recommendation: ...]` strings — all such patterns are
  stripped server-side.
- Instead, the API returns up to **2 verified lab objects** in the
  `suggested_labs` JSON array, loaded from the real `data/labs/*.json`
  catalog.
- The frontend renders them as styled clickable badges under the assistant
  message bubble; clicking navigates to the matching lab module.

### 4.3 Resilient Failover & BYOK

- **Model priority**: `meta/llama-3.3-70b-instruct` → `z-ai/glm-5.3` → the
  NVIDIA NIM verified fallback queue.
- **Settings modal**: users may store a custom OpenAI or Anthropic API key
  in `localStorage` (`cybergpt_byok`), transmitted per-request and never
  logged or persisted server-side.
- **Graceful degradation**: if every external API fails or returns 503, the
  system falls back to the local CyBOK knowledge engine so defensive
  learning continues offline.

---

## 5. 6-Pillar Application Security Hardening

1. **Rate limiting (classroom & NAT friendly)** — hybrid limiter: 35-40
   requests/min per IP burst combined with weighted client-session tracking;
   HTTP 429 JSON with `Retry-After` header.
2. **Input validation & delimiter sanitization** — server-side payload caps
   (8,000 chars chat, 15,000 chars analyzer); frontend DOMPurify
   sanitization of all markdown; evidence delimiters stripped from user
   input; never emit raw `\user` escape sequences in JS/Python string
   literals.
3. **Secrets management** — zero hardcoded keys; `.env` gitignored;
   `.env.example` placeholders only.
4. **Dependency audit** — `requirements.txt` and `package.json` pass
   integrity audits without breaking contracts.
5. **Error handling & leak prevention** — `DEBUG = False` default; generic
   JSON errors; no stack traces or Kali paths in responses.
6. **File upload safety** — extensions restricted to `.log`, `.txt`, `.json`,
   `.pcap`, `.png`, `.jpg` (max 5 MB); magic-byte verification; strict
   in-memory processing as inert data.

---

## 6. Verification Protocol (4 Cycles)

1. **Static integrity**: `node --check static/js/app.js`;
   `python3 -m py_compile app.py services/*.py` — exit code 0.
2. **Headless E2E**: `node tests/e2e_smoke.mjs`;
   `node tests/e2e_planner.mjs` (Playwright, Chromium AND Firefox) — zero
   pageerror, zero console errors; tab switching, persistent composer dock,
   typing indicator, Study Planner persistence.
3. **Direct API & knowledge assertions** (curl against `http://127.0.0.1:5000`):
   - "WHO is your developer" → Muhammad Umair identity, instant, 0 tokens.
   - "what is cyber security" → CIA triad + core domains from the engine.
   - "Explain CyBOK" → CyBOK v1.1.0 and the 21 Knowledge Areas.
   - "Explain Zero Trust Architecture" → Zero Trust principles, no forced
     Event IDs.
   - "Difference between IT and OT security" → Safety/Availability vs
     Confidentiality per the CyBOK CPS domain.
   - "what is trading" in cyber mode → polite off-topic notice + mode-switch
     action chip.
   - "what is trading" in normal mode → comprehensive trading guide.
4. **Security verification**: burst curl triggering HTTP 429 on `/api/chat`;
   9,000-character payload triggering HTTP 400; `.env` confirmed excluded
   from git tracking.

---

*CyberGPT v2.0 — authored and architecturally governed by **Muhammad Umair**.
All telemetry in labs is simulated; all domains use RFC 2606/5737 reserved
ranges. For educational use only.*
