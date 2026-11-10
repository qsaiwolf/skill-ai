# Layer 0: The Constitutional Kernel (النواة التأسيسية الإلزامية الدائمة)

These 4 Foundational Kernel Skills + 1 QW Domain Override are **NOT** ordinary candidate skills to be compared or voted on. They form the **permanent operating system** of the agent and MUST be enforced automatically across every routed workflow.

---

## 1. `agy-output-style` — Always-On Communication & Formatting Kernel
**Path:** [`../agy-output-style/SKILL.md`](../agy-output-style/SKILL.md)  
**Trigger:** Every single response in every mode (`Comparison`, `Auto-Pilot`, `Hybrid`, `Fast-Track`).

- **Q1 (Action First):** Start every response with the command, file path, table, or code snippet — never conversational filler or preamble.
- **Q2 (Numbered Bounded Steps):** Multi-step work must be numbered, with one bounded action per step.
- **Q3 (Single Next Action):** End every response with **1 concrete action** doable in `< 2 minutes`.
- **Q4 (One Topic at a Time):** Finish the primary task before raising secondary issues at the very end.
- **Q5 (Progress State):** Explicitly state step progress each turn (`"الخطوة 2 من 4 مكتملة..."`).
- **Q6 (Zero Fluff):** Never output `"بالتأكيد!"`, `"سؤال ممتاز!"`, `"Sure!"`, or `"Hope this helps"`.
- **Q7 (Concrete Estimates):** Always provide numeric estimates (`~5m`, `~40 lines changed`).
- **Q8 (Visible Wins):** State exactly what now works after each step, not just `"تم"`.

---

## 2. `agy-context-optimizer` — Pre-Read Context & Token Kernel
**Path:** [`../agy-context-optimizer/SKILL.md`](../agy-context-optimizer/SKILL.md)  
**Trigger:** Automatically enforced BEFORE Step 1 (Context Extraction) and during any routed skill's file exploration.

- **Priority Reading Order:**
  1. `AGENTS.md` / `GEMINI.md`, `package.json` / `composer.json` / `Cargo.toml`, `README.md` (first 50 lines).
  2. Files explicitly named by the user + their direct imports.
  3. Large files (`> 300 lines`) only via `grep` + `StartLine`/`EndLine` slicing.
  4. **Never Read:** `node_modules/`, `vendor/`, `.venv/`, `dist/`, `build/`, lockfiles, or minified bundles.
- **Hard Caps:**
  - Read `<= 8` files for context extraction.
  - List top-level directories at most once; never re-read a file already in session context unless modified.

---

## 3. `agy-code-guard` — Mandatory Pre-Delivery Code Quality Kernel
**Path:** [`../agy-code-guard/SKILL.md`](../agy-code-guard/SKILL.md) | [`../agy-code-guard/references/ai-failure-modes.md`](../agy-code-guard/references/ai-failure-modes.md) | [`../agy-code-guard/references/review-checklist.md`](../agy-code-guard/references/review-checklist.md)  
**Trigger:** Mandatory guard-pass after ANY routed skill writes, edits, or refactors code, BEFORE presenting results.

- **9 Systematic LLM Failure Checks:**
  1. **Zero Code Duplication:** Extract repeated blocks `> 5 lines`.
  2. **Zero Hallucinated Packages:** Verify every `import` / `require` exists in `package.json` / `composer.json` / `Cargo.toml`.
  3. **Zero Swallowed Errors:** `catch (e) {}` or `catch { return null }` without logging/context is strictly forbidden.
  4. **Zero Fake Success:** Never hardcode return values to fake passing tests.
  5. **Small Single-Responsibility Functions:** Target `<= 20–30 lines`, `<= 4 arguments` (use parameter objects for 5+), zero boolean flag arguments.
  6. **Zero Pointless Wrappers:** Follow `YAGNI` / `KISS`.
  7. **Zero Magic Values in Business Logic:** Extract constants/enums (UI spacing/colors exempt).
  8. **Explicit Dependencies (`DIP`):** Avoid hidden global state.
  9. **Meaningful Identifiers & Comments:** Ban vague names (`data`, `item`, `temp`, `helper`, `handle_*` without qualifier); preserve existing valid documentation.
- **All-or-Nothing Localization Gate:** If UI translation keys (`i18n`, `lang`) are added or modified, update **ALL** supported languages in the project synchronously.

---

## 4. `agy-error-protocol` — Surgical Diagnostic & 3-Strike Stop Kernel
**Path:** [`../agy-error-protocol/SKILL.md`](../agy-error-protocol/SKILL.md)  
**Trigger:** Immediately preempts the active workflow whenever any command, build, linter, or test fails.

- **5-Step Surgical Sequence:**
  1. **Read Full Error:** Exact message, `file:line`, error type, and trigger condition.
  2. **Mental Simulation:** Formulate an explicit hypothesis (`"المشكلة في X بسبب Y"`).
  3. **Targeted Code Inspection:** Read `±10 lines` around the stack trace (do not read the whole file).
  4. **Isolate Root Cause:** Fix the root cause, never the symptom.
  5. **Surgical Fix:** Apply the smallest possible diff; NEVER rewrite an entire component just to be safe.
- **The 3-Attempt Hard Stop Rule:** If 3 consecutive fix attempts fail on the same bug, **STOP IMMEDIATELY**, list the failed assumptions, and ask **1 focused question**.

---

## 5. QW Domain Override (`qw-account-system`)
**Path:** [`../qw-account-system/SKILL.md`](../qw-account-system/SKILL.md)  
**Trigger:** Any request involving authentication, login, registration, user accounts, rate limiting, forbidden words/reserved usernames, OTP, 2FA (TOTP/Email/Passkeys), sessions, JWT rotation, CSRF, RBAC, sub-accounts, or security dashboards.

- **Rule:** Route **100% unconditionally** to `qw-account-system` (plus the 4 `agy-*` kernels above). Never dilute or replace it with generic auth skills.

