---
name: skill-router
description: "Use when the user asks which skill to use, wants a comparison between skills, says 'I don't know where to start', asks for the best approach to a task, or says 'compare skills for X'. Routes to the optimal task skill(s) while permanently enforcing the Layer-0 Constitutional Kernel (agy-output-style, agy-context-optimizer, agy-code-guard, agy-error-protocol, and sovereign-auth-architect)."
risk: safe
source: self
version: "4.0.0"
---

# Skill Router v4.0 — Context-Aware Orchestrator & Constitutional Kernel

## 🏛️ Layer 0: The Constitutional Kernel (النواة التأسيسية الإلزامية الدائمة)

> **CRITICAL ARCHITECTURAL RULE:**  
> Skills are divided into two strict tiers:
> 1. **Layer-0 Constitutional Kernel Skills (مرجعية أساسية إلزامية دائمة):** Never treat these as optional candidates in a comparison table. They are **ALWAYS ON** and automatically enforced in every single task routed or executed by the agent.
> 2. **Layer-1 Task Skills (المهارات التخصصية للمهام):** Domain/framework skills selected dynamically based on the user's goal.

### Always-On Constitutional Kernel (Read [`references/constitutional-kernel.md`](references/constitutional-kernel.md))

| Kernel Skill | Role | Enforcement Gate |
|--------------|------|------------------|
| **`agy-output-style`** | Communication & Formatting Engine | **Always-On (Every Turn):** Action/path/table first, numbered bounded steps, progress counter (`Step X of Y`), numeric time estimates (`~5m`), zero fluff, end with **1 concrete next action (`<2m`)**. |
| **`agy-context-optimizer`** | Context & Token Efficiency Engine | **Pre-Read Gate:** Cap initial context scan to `<= 8` files, grep-first before reading files `> 300 lines`, use `StartLine`/`EndLine` slicing, never read `node_modules/`, `dist/`, `vendor/`, or lockfiles. |
| **`agy-code-guard`** | Code Quality & Anti-LLM Failure Gate | **Post-Write / Pre-Delivery Gate:** Mandatory guard-pass on every code change. Enforces zero silent `catch {}`, zero hallucinated imports, zero code duplication `> 5 lines`, `<= 30-line` functions, `SOLID/DRY/KISS`, and All-or-Nothing localization across all project languages. |
| **`agy-error-protocol`** | Surgical Debugging & 3-Strike Engine | **On-Error Preemption Gate:** Triggered immediately on any test/build/command failure. Enforces the 5-step surgical fix (`Read → Simulate → Inspect ±10 lines → Isolate → Surgical Fix`) and stops after **3 failed attempts** to name the doubtful assumption. |
| **`sovereign-auth-architect`** | Sovereign Account & Auth Override | **Domain Override Gate:** Whenever a request involves Login, Registration, Accounts, Rate-Limiting, Forbidden Words, OTP, 2FA, Passkeys, Sessions, JWT, CSRF, or RBAC, route **100% unconditionally** to [`../sovereign-auth-architect/SKILL.md`](../sovereign-auth-architect/SKILL.md). |

---

## When to Use `skill-router`
- The user asks `"which skill should I use"`, `"compare skills for X"`, `"I don't know where to start"`, `"قارن لي"`, or `"ما الخيارات"`.
- The user says `"you pick the best one"`, `"choose for me"`, `"اختار انت"`, `"نفذ فوراً"`, or `"روح فيها"`.
- The task spans multiple domains and benefits from a chained Multi-Skill Pipeline.

---

## Operating Modes

### Mode 1: Fast-Track Mode (Auto-Triggered when Top Candidate Confidence `>= 90%`)
If a single installed skill (or Sovereign Override) matches the user's goal with **`>= 90%` confidence** and leads the second candidate by **`>= 25` points** (and the user did NOT explicitly ask to `"compare"` / `"قارن"`):
- Do **NOT** waste the user's time with a 4-column comparison table and a manual confirmation pause.
- Output a crisp 3-line selection banner, read the chosen `SKILL.md`, and **execute immediately** under the Layer-0 Constitutional Kernel.

### Mode 2: Comparison Mode (When 2–4 Viable Candidates Compete)
Triggered when multiple skills are close contenders OR when the user explicitly says `"compare"`, `"show options"`, `"قارن لي"`, `"ما الخيارات"`. Present a structured comparison table (2–4 candidates max).

### Mode 3: Auto-Pilot Mode
Triggered when the user says `"you choose"`, `"pick the best"`, `"just go"`, `"اختار انت"`, `"نفذ فوراً"`, `"روح فيها"`, or previously enabled Auto-Pilot in the current session. Picks the top skill and executes immediately.

### Mode 4: Hybrid Mode (Empty Context + Ambiguous Request)
Triggered ONLY when the workspace is empty/unrelated AND the user's goal is genuinely ambiguous. Ask **1 concise question**:
> **"ما الذي تريد إنجازه بالتحديد؟"**
Then route and execute immediately upon receiving the answer.

### Mode Switching Commands
- `"توقف"` / `"stop"` / `"بدّل للوضع اليدوي"` $\rightarrow$ Switch to Comparison Mode.
- `"كمّل لحالك"` / `"اختار انت"` / `"نفذ فوراً"` $\rightarrow$ Switch to Auto-Pilot Mode.

---

## Execution Workflow

### Step 1 — Silent Context Extraction (Governed by `agy-context-optimizer`)
Before asking any question, inspect up to `<= 8` high-signal files:
1. **Layer 1 (Project Identity):** `AGENTS.md` / `GEMINI.md`, `package.json` / `composer.json` / `Cargo.toml` / `requirements.txt`, `README.md` (first 50 lines).
2. **Layer 2 (Technical Stack):** `tsconfig.json`, `next.config.*`, `prisma/schema.prisma`, `.env.example`, or active framework config.
3. **Layer 3 (Active Focus):** Open editor files (first/last 30 lines via `StartLine`/`EndLine`) and top-level directory structure.

### Step 2 — Search, Recover Excluded Skills & Score Candidates
1. **Check Layer-0 Domain Overrides First:** If the task touches Auth/Accounts/Security, select `sovereign-auth-architect` immediately (`100%` score).
2. **Scan Both `Available skills` AND `Excluded due to context budget limits`:**
   - **Excluded Skills Recovery Rule:** Many installed skills appear in the system prompt under `The following items were excluded due to context budget limits` without descriptions. If a skill name in the excluded list looks relevant to the user's goal, read lines `1–15` (YAML frontmatter) of `~/.gemini/config/skills/<skill-name>/SKILL.md` using `read_file` to verify its exact description before scoring!
3. **Score Top 2–4 Task Candidates:**
   - **Relevance (40%):** Exact match to the user's goal.
   - **Project Fit (25%):** Matches the detected language/framework.
   - **Specificity (20%):** Laser-focused skill beats generic skill.
   - **Completeness (15%):** Covers the end-to-end requirement.

### Step 3 — Present & Route (Governed by `agy-output-style`)

#### A. In Fast-Track Mode (`Confidence >= 90%`) or Auto-Pilot Mode:
```markdown
## ⚡ Selected Skill: `<skill-name>` ✅ + Constitutional Kernel (`agy-*`)
1. **السبب:** [1-line project-specific justification] (~Xm)
2. **النواة الإلزامية المفعلة:** `agy-output-style` + `agy-context-optimizer` + `agy-code-guard` + `agy-error-protocol`
```
Immediately read `<skill-name>/SKILL.md` with `read_file` and executeStep 1 of that skill.

> **Destructive Action Safety Gate:** Pause for confirmation ONLY before **destructive or unrequested high-risk operations**:
> - Dropping/truncating existing data (`DROP`, `TRUNCATE`, `rm -rf`, `git reset --hard`, `git push --force`)
> - Modifying production credentials or making paid external API calls
> *(Never pause just because the user asked you to build a new database schema or authentication system—execute what they asked for!)*

#### B. In Comparison Mode (2–4 Competing Task Skills):
```markdown
## 🔍 Skill Comparison for: [User's Goal]

| المعيار | `<skill-a>` ✅ | `<skill-b>` ✅ | `<skill-c>` ✅ |
|---------|---------------|---------------|---------------|
| **التركيز** | [1-line] | [1-line] | [1-line] |
| **ملاءمة المشروع** | ⭐⭐⭐ | ⭐⭐ | ⭐ |
| **تغطية المهمة** | ✅ كاملة | ⚠️ جزئية | ✅ كاملة |
| **الوقت التقريبي** | ~10 دقائق | ~20 دقيقة | ~30 دقيقة |
| **الأفضل عندما** | [scenario] | [scenario] | [scenario] |

### ✅ توصيتي: `<skill-a>` (مع تفعيل النواة التأسيسية `agy-*` تلقائياً)
**السبب:** [1-2 sentences tailored to detected project stack]

### ❌ لماذا استبعدت الخيارات الأخرى؟
- **`<skill-b>`:** [1 concise reason]
- **`<skill-c>`:** [1 concise reason]

### 🔗 مسار التنفيذ الكامل (Pipeline):
`[agy-context-optimizer]` → `<skill-a>` → `[agy-code-guard]`
```
End with: **"أي مهارة نعتمد، أو أبدأ بتنفيذ توصيتي (`<skill-a>`) فوراً؟"**

### Step 4 — Execute, Chain & Delegate to Subagents
1. **Read & Execute:** Read the chosen skill's `SKILL.md` via `read_file` and execute its workflow.
2. **Multi-Skill Pipeline (Max 4 Task Skills):**
   - If the goal requires a sequence (e.g., `concise-planning → sovereign-auth-architect → e2e-testing`), pass created file paths and decisions between stages and announce transitions (`"المرحلة 1 من 3 مكتملة ✅ — الانتقال إلى..."`).
   - **Subagent Delegation:** If a pipeline requires broad codebase exploration before implementation, delegate the read-only survey to the `research` subagent (`invoke_subagent`) to keep the main context window clean.
3. **Mandatory Post-Execution Gate (`agy-code-guard`):**
   - Before presenting any written/modified code, run the `agy-code-guard` checklist (no empty catches, verified imports, functions `<= 30 lines`, all project locales updated).
4. **Auto-Fallback on Skill Failure:**
   - If an error occurs during execution, trigger `agy-error-protocol` (5-step surgical fix, max 3 attempts).

---

## Context-Aware Routing Matrix (Layer-1 Task Skills + Layer-0 Kernel)

> *Note: Every route below automatically runs under the Layer-0 Constitutional Kernel (`agy-output-style`, `agy-context-optimizer`, `agy-code-guard`, `agy-error-protocol`).*

### 🔐 Authentication, Accounts & Security (Sovereign Priority)
| Goal | Primary Skill | Chain With | Est. Time |
|------|--------------|------------|-----------|
| Login / Register / Account System / 2FA / OTP / Passkeys / Sessions / Rate-Limit / RBAC | **`sovereign-auth-architect`** | + `agy-code-guard` | ~30m–1h |
| Web App Security & OWASP Audit | `security-auditor` | + `top-web-vulnerabilities` | ~45m |
| Penetration Testing Checklist | `ethical-hacking-methodology` | + `pentest-checklist` | ~1h |
| PR / Diff Security Review | `differential-review` | + `agy-code-guard` | ~20m |

### 🏗️ Building & Full-Stack Engineering
| Goal | Primary Skill | Chain With | Est. Time |
|------|--------------|------------|-----------|
| Full App From Scratch | `app-builder` | + `concise-planning` | ~1.5h |
| Frontend UI / UX / Components | `frontend-design` | + `react-patterns` or `nextjs-best-practices` | ~30m |
| Backend API / Microservices | `backend-architect` | + `api-patterns` | ~45m |
| Database Schema & Optimization | `database-design` | + `postgresql` or `prisma-expert` | ~30m |
| Full-Stack Feature | `senior-fullstack` | + stack-specific skill | ~1h |
| Mobile App (Flutter / Expo) | `flutter-expert` or `mobile-design` | + `hig-patterns` | ~1h |

### 🐛 Debugging, Refactoring & Performance
| Goal | Primary Skill | Chain With | Est. Time |
|------|--------------|------------|-----------|
| Any Error / Bug / Crash | **`agy-error-protocol`** | + `systematic-debugging` | ~15m |
| Code Quality / Pre-Merge Audit | **`agy-code-guard`** | + `simplify-code` | ~15m |
| Failing Unit / Integration Tests | `test-fixing` | + **`agy-error-protocol`** | ~20m |
| Slow Queries / React Rerenders | `performance-profiling` | + `react-component-performance` | ~30m |

### 🧪 Testing & QA
| Goal | Primary Skill | Chain With | Est. Time |
|------|--------------|------------|-----------|
| Test-Driven Development (TDD) | `tdd-workflow` | + `unit-testing-test-generate` | ~30m |
| End-to-End Playwright Tests | `e2e-testing` | + `webapp-testing` | ~40m |

### 🤖 AI, Agents & Skills Authoring
| Goal | Primary Skill | Chain With | Est. Time |
|------|--------------|------------|-----------|
| Create / Upgrade an Agent Skill | `skill-writer` | + `skill-check` | ~25m |
| Multi-Agent / LLM Architecture | `ai-agents-architect` | + `multi-agent-patterns` | ~45m |
| RAG & Vector Search | `rag-engineer` | + `embedding-strategies` | ~45m |

### 🚀 Planning, Architecture & DevOps
| Goal | Primary Skill | Chain With | Est. Time |
|------|--------------|------------|-----------|
| Fast Atomic Action Checklist | `concise-planning` | — | ~5m |
| Multi-Phase Spec & Execution | `writing-plans` | → `executing-plans` | ~30m |
| System Architecture Review | `senior-architect` | + `architect-review` | ~40m |
| CI/CD & Cloud Deployment | `deployment-engineer` | + `vercel-deployment` or `github-actions-templates` | ~30m |

---

## Hard Rules (Zero Exceptions)

1. **Constitutional Kernel Permanence:** Never turn off or skip `agy-output-style`, `agy-context-optimizer`, `agy-code-guard`, or `agy-error-protocol` regardless of which task skill is chosen.
2. **Sovereign Auth Supremacy:** Always route authentication/account tasks directly to `sovereign-auth-architect`.
3. **Excluded Skills Check:** Always inspect both `Available skills` and `excluded due to context budget limits` (reading lines `1–15` of `SKILL.md` for excluded candidates) before claiming a skill is not installed.
4. **No Single-Item Comparison Tables:** Never draw a comparison table for 1 skill; use Fast-Track Mode when a clear winner (`>= 90%`) exists.
5. **Context Before Questions:** Read project files (`<= 8` files) before asking anything; ask at most **1 question** only when context is genuinely missing.
6. **Session Memory:** Remember the detected tech stack, language, mode preference (`Auto-Pilot`), and any skill rejected by the user for the remainder of the session.
