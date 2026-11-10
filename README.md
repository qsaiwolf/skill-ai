# 🛡️ Skill-AI — Sovereign Agent Skills & Constitutional Kernel

Production-grade AI Agent Skills and Always-On Foundational Guardrails engineered for **Antigravity**, **Claude Code**, **Cursor**, and **Codex**.

---

## 📂 Repository Structure

```text
skill-ai/
├── README.md                                                  # Repository index & installation guide
├── skill-router/                                              # Intelligent Skill Orchestrator v4.0
│   ├── SKILL.md                                               # Context-aware router with Fast-Track & Pipeline modes
│   └── references/
│       └── constitutional-kernel.md                           # Layer-0 Constitutional Kernel specification
├── agy-output-style/                                          # [Kernel 1] Always-On Action-First Communication Engine
│   └── SKILL.md
├── agy-context-optimizer/                                     # [Kernel 2] Token & Context Window Optimization Engine
│   └── SKILL.md
├── agy-code-guard/                                            # [Kernel 3] Pre-Delivery Code Quality & Anti-LLM Failure Gate
│   ├── SKILL.md
│   └── references/
│       ├── ai-failure-modes.md                                # 14 documented LLM coding failure modes
│       └── review-checklist.md                                # Pre-delivery code review checklist
├── agy-error-protocol/                                        # [Kernel 4] 5-Step Surgical Debugging & 3-Strike Stop Engine
│   └── SKILL.md
└── sovereign-auth-architect/                                  # [Sovereign Domain] Tier-0 Zero-Trust Account & Auth System
    ├── SKILL.md                                               # Primary agent skill instructions & execution workflow
    ├── BLUEPRINT.md                                           # Comprehensive architectural blueprint (Arabic reference)
    └── references/                                            # Modular copy-pasteable engineering specifications (7 modules)
        ├── 01-identity-validation-and-forbidden-words.md      # Multi-identifier intake, Gmail/E.164 normalization & 5-category blocklist
        ├── 02-password-cryptography-and-strength.md           # Bounded scrypt/bcrypt worker queue, constant-time dummy hash & zxcvbn
        ├── 03-rate-limiting-lockout-and-antifraud.md          # Dual-bucket rate limiting, progressive lockout & identity graveyard
        ├── 04-otp-2fa-and-email-architecture.md               # Salted HMAC-SHA256 OTP, RFC 6238 TOTP, trusted devices & hardened SMTP
        ├── 05-sessions-jwt-csrf-and-rbac.md                   # Opaque __Host- sessions, JWT rotation, <2ms revocation, CSRF & RBAC
        ├── 06-database-schemas-and-api-contracts.md           # Complete 14-model Prisma/SQL schema, REST API contracts & 12-test suite
        └── 07-advanced-zero-trust-and-passkeys.md             # Passkeys (WebAuthn), Sudo Mode, 72h email revert, freeze & 14d soft-delete
```

---

## 🏛️ Layer 0: The Constitutional Kernel (Always-On Guardrails)

Unlike standard task skills, the **Constitutional Kernel** skills are permanently active across every session and automatically enforced by [`skill-router`](./skill-router/SKILL.md):

| Skill | Layer Role | Enforcement Gate |
|-------|------------|------------------|
| **[`agy-output-style`](./agy-output-style/SKILL.md)** | Communication & Formatting Engine | **Always-On:** Action/path/code first, numbered bounded steps, progress counter (`Step X of Y`), concrete time estimates (`~5m`), zero fluff, and 1 concrete next action (`<2m`). |
| **[`agy-context-optimizer`](./agy-context-optimizer/SKILL.md)** | Context & Token Efficiency Engine | **Pre-Read Gate:** Caps initial file scans (`<= 8` files), enforces `grep`-first on files `> 300 lines`, requires `StartLine`/`EndLine` slicing, and blocks reading `node_modules/`, `dist/`, or lockfiles. |
| **[`agy-code-guard`](./agy-code-guard/SKILL.md)** | Code Quality & Anti-Hallucination Gate | **Post-Write Gate:** Mandatory guard-pass before presenting code. Catches the [14 LLM failure modes](./agy-code-guard/references/ai-failure-modes.md) (hallucinated imports, silent `catch {}`, code duplication `> 5 lines`, `> 30-line` functions, magic values, and partial translations). |
| **[`agy-error-protocol`](./agy-error-protocol/SKILL.md)** | Surgical Debugging & 3-Strike Engine | **On-Error Gate:** Preempts execution on any test/build failure. Enforces the 5-step surgical fix (`Read → Simulate → Inspect ±10 lines → Isolate → Surgical Fix`) and stops after **3 failed attempts**. |

---

## 🚀 Orchestrator & Sovereign Domain Skills

### 1. [`skill-router` (v4.0)](./skill-router/SKILL.md) — Context-Aware Orchestrator
Routes user goals to the optimal specialized skill(s) while permanently enforcing the **Layer-0 Constitutional Kernel** ([`constitutional-kernel.md`](./skill-router/references/constitutional-kernel.md)):
- **Fast-Track Mode (`Confidence >= 90%`):** Skips unnecessary comparison tables when a clear winner or Sovereign Override exists and begins execution immediately.
- **Excluded Skills Recovery:** Automatically inspects skills truncated under `excluded due to context budget limits` by reading their `SKILL.md` frontmatter before scoring.
- **Comparison, Auto-Pilot & Hybrid Modes:** Supports structured 2–4 skill comparison tables, instant Auto-Pilot execution with a destructive-only safety gate, and multi-skill pipelines with `research` subagent delegation.

### 2. [`sovereign-auth-architect`](./sovereign-auth-architect/SKILL.md) — Sovereign Account & Authentication System
An end-to-end, financial-grade authentication and account management skill (**13 Core Pillars + 8 Zero-Trust Extensions**):
- **Multi-Identifier Intake & 5-Category Forbidden Dictionary:** Single-field login (`Email / Username / E.164 Phone`), Gmail canonicalization, 25+ disposable domain blocklist, Unicode Homograph & Zero-Width sanitizer, Leet-Speak filter, and a 5-category bilingual blocklist (System/Admin handles, EN profanity, AR & Franco/Arabizi profanity, sacred religious terms, and global brand names).
- **Password Cryptography & DoS-Resilient Hashing:** `scrypt` (`128 MiB`) or `bcrypt` (`12 rounds`) protected by a **Bounded Worker Queue** (`503 AUTH_BUSY` DoS protection), memory buffer zeroization, constant-time dummy hash verification, contextual `zxcvbn`, privacy-preserving **k-Anonymity HaveIBeenPwned** check, and **Last-1 Password Reuse Prevention (`previousPasswordHash`)**.
- **Dual-Bucket Rate Limiting, Anti-Fraud & Permanent Identity Graveyard:** Dual-Bucket (`IP` + `SHA-256(identifier)`) limits with Redis primary + bounded 10,000-entry memory fallback (`OWASP API4:2023`), 8-second forgot-password timing floor, progressive account lockout, Honeypot + Turnstile, and a **Permanent `RegisteredIdentity` Graveyard** that survives account deletion.
- **Sovereign OTP, Dual-Channel 2FA & WebAuthn Passkeys:** Eastern Arabic/Persian numeral normalization (`٠-٩`), **Purpose-Bound Salted HMAC-SHA256 OTP** with `FOR UPDATE` row locking and 5-attempt burn, **RFC 6238 TOTP + Email OTP**, **WebAuthn / Passkeys (`FIDO2`)** with `signCount` clone detection, `AES-256-GCM` **Trusted Device Cookie** (`30d`), and **Supreme Admin Guard**.
- **Sessions, `<2ms` Global Revocation, Zero-Trust Controls & RBAC:** Hardened `__Host-session` or `JWT Access + Refresh Token Rotation` with reuse detection, `<2ms` global revocation via `tokenVersion`, **Step-Up `Sudo Mode` (10m)**, **Dual-Handshake Email Change** with **72-hour Emergency Revert Link**, **Impossible Travel & One-Click Account Freeze**, **Cryptographic Admin Impersonation (`Shadow Session`)**, and a **14-Day Soft-Delete Grace Period**.

📖 **Arabic Architectural Blueprint:** [`sovereign-auth-architect/BLUEPRINT.md`](./sovereign-auth-architect/BLUEPRINT.md)

---

## ⚙️ Installation

Clone this repository and install the complete skill suite into your agent's skills directory:

### Windows (PowerShell)
```powershell
git clone https://github.com/qsaiwolf/skill-ai.git
foreach ($skill in @("skill-router", "agy-output-style", "agy-context-optimizer", "agy-code-guard", "agy-error-protocol", "sovereign-auth-architect")) {
  Copy-Item -Path ".\skill-ai\$skill" -Destination "$HOME\.gemini\config\skills\$skill" -Recurse -Force
}
```

### macOS / Linux
```bash
git clone https://github.com/qsaiwolf/skill-ai.git
cp -r ./skill-ai/{skill-router,agy-output-style,agy-context-optimizer,agy-code-guard,agy-error-protocol,sovereign-auth-architect} ~/.gemini/config/skills/
```
