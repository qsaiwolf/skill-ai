# 🛡️ Skill-AI — Enterprise Agent Skills Repository

مستودع المهارات الهندسية المتقدمة للوكلاء الذكيين (Antigravity / Claude Code / Cursor / Codex).

---

## 📂 هيكل المستودع (Repository Structure)

```text
skill-ai/
├── README.md                                                  # دليل المستودع والتثبيت
├── skill-router                                               # مهارة توجيه واختيار المهارات الذكية (Skill Router v3)
└── sovereign-auth-architect/                                  # المعمارية السيادية لأنظمة الحسابات والمصادقة (Tier-0 Auth)
    ├── SKILL.md                                               # ملف المهارة الرئيسي وتعليمات التنفيذ للوكيل
    ├── BLUEPRINT.md                                           # الدليل المرجعي الشامل باللغة العربية
    └── references/                                            # الوحدات المرجعية والكود المصدري الجاهز (7 مراجع)
        ├── 01-identity-validation-and-forbidden-words.md      # الهوية الموحدة، تطبيع البريد/الهاتف، والقاموس الخماسي للمحظورات
        ├── 02-password-cryptography-and-strength.md           # تشفير scrypt/bcrypt، طابور العمل المحدود، وفحص zxcvbn السياقي
        ├── 03-rate-limiting-lockout-and-antifraud.md          # Rate Limiting مزدوج الوعاء، القفل التدريجي، ومقبرة الهويات الدائمة
        ├── 04-otp-2fa-and-email-architecture.md               # محرك Salted HMAC OTP، التحقق الثنائي (TOTP + Email)، والأجهزة الموثوقة
        ├── 05-sessions-jwt-csrf-and-rbac.md                   # الجلسات الكتومة، تدوير JWT، الطرد اللحظي، CSRF، وهرمية الصلاحيات
        ├── 06-database-schemas-and-api-contracts.md           # مخطط قاعدة البيانات الكامل (14 جدولاً)، عقود API، والاختبارات الـ 12
        └── 07-advanced-zero-trust-and-passkeys.md             # الإضافات الـ 8 المتقدمة (Passkeys, Sudo Mode, 72h Revert, Freeze...)
```

---

## 🚀 المهارات المتوفرة (Included Skills)

### 1. [`sovereign-auth-architect`](./sovereign-auth-architect/SKILL.md) — نظام الحسابات والمصادقة السيادي
مهارة شاملة لبناء وتدقيق أنظمة تسجيل الدخول، التسجيل، وإدارة الحسابات بمستوى أمان البنوك والمنصات الكبرى (**13 ركيزة أساسية + 8 امتدادات Zero-Trust**):
- **الهوية الموحدة والقاموس الخماسي للمحظورات:** دخول بحقل موحد (بريد / اسم مستخدم / هاتف `E.164`)، تطبيع Gmail (إزالة `.` و `+tag`)، حظر البريد المؤقت، فلتر `Leet-Speak`، ومنع التزوير البصري (`Unicode Homograph & Zero-Width Sanitizer`)، مع قاموس خماسي يحظر الأسماء المحجوزة للنظام، الكلمات النابية (عربي/إنجليزي/فرانكو)، الأسماء الدينية المقدسة، وأسماء العلامات التجارية.
- **التشفير وحماية المعالج والذاكرة:** تشفير `scrypt` (`128 MiB`) أو `bcrypt` (`12 rounds`) محمي بطابور عمل محدود (`Bounded Worker Queue` يرجع `503 AUTH_BUSY` لمنع هجمات DoS)، تصفير الذاكرة (`Buffer.fill(0)`)، الهاش الوهمي المتساوي زمنياً لمنع كشف الحسابات، فحص `zxcvbn` السياقي، فحص التسريبات (`k-Anonymity HIBP`)، ومنع إعادة استخدام كلمة المرور الحالية أو السابقة مباشرة (`previousPasswordHash`).
- **Rate Limiting مزدوج ومقبرة الهويات:** تحديد معدل الطلبات عبر وعاء مزدوج (`IP` + `SHA-256(identifier)`) بذاكرة محمية السعة (`10,000` حد أقصى)، أرضية زمنية 8 ثوانٍ لاستعادة كلمة المرور، قفل تدريجي للحساب بعد 5 محاولات، Honeypot + Turnstile، ومقبرة هويات دائمة (`RegisteredIdentity`) تمنع استغلال الفترات التجريبية أو الالتفاف على الحظر بعد حذف الحساب.
- **محرك OTP و 2FA مزدوج القناة + Passkeys (`WebAuthn`):** تطبيع الأرقام العربية/الفارسية (`٠-٩`)، تخزين OTP بـ `Salted HMAC-SHA256` مرتبط بالغرض مع قفل الصف (`FOR UPDATE`) وحرق الرمز بعد 5 محاولات خاطئة، دعم `RFC 6238 TOTP` + `Email OTP` + `Passkeys (FIDO2)`، كوكي الجهاز الموثوق المشفر لمدة 30 يوماً، وحماية الأدمن الأعلى (`Supreme Admin Guard`).
- **الجلسات، الطرد اللحظي، و Zero-Trust:** جلسات `__Host-` أو تدوير `JWT Refresh` مع كشف السرقة (`Reuse Detection`)، طرد عالمي لحظي عبر `tokenVersion` في `< 2ms`، وضع `Sudo Mode` (10 دقائق) للعمليات الحساسة، تغيير البريد المزدوج مع رابط تراجع طارئ صالح لـ 72 ساعة، كاشف السفر المستحيل مع زر تجميد فوري للحساب، تقمص آمن للدعم الفني (`Shadow Session`)، وحذف مؤجل بفترة سماح 14 يوماً.

📖 **اقرأ الدليل العربي الكامل هنا:** [`sovereign-auth-architect/BLUEPRINT.md`](./sovereign-auth-architect/BLUEPRINT.md)

---

### 2. [`skill-router`](./skill-router) — موجه المهارات الذكي (v3.0)
مهارة لتوجيه الوكيل تلقائياً لاختيار المهارة الأنسب للمهمة أو المقارنة بين المهارات المتوفرة أو ربط عدة مهارات في مسار عمل متسلسل.

---

## ⚙️ طريقة التثبيت (Installation)

انسخ مجلد المهارة إلى مسار مهارات الوكيل على جهازك:

### في Windows (PowerShell):
```powershell
git clone https://github.com/qsaiwolf/skill-ai.git
Copy-Item -Path ".\skill-ai\sovereign-auth-architect" -Destination "$HOME\.gemini\config\skills\sovereign-auth-architect" -Recurse -Force
```

### في macOS / Linux:
```bash
git clone https://github.com/qsaiwolf/skill-ai.git
cp -r ./skill-ai/sovereign-auth-architect ~/.gemini/config/skills/sovereign-auth-architect
```
*(أو ضعها داخل `.claude/skills/sovereign-auth-architect` في حال استخدام Claude Code).*
