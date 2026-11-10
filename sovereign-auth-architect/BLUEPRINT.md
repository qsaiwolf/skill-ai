# المرجع الشامل ومعمارية نظام الحسابات والمصادقة السيادي (Sovereign Account & Auth Architecture Blueprint)

> **المهارة الرئيسية (Agent Skill):** [`SKILL.md`](./SKILL.md) (`sovereign-auth-architect`)  
> **المستوى الأمني:** Tier-0 Zero-Trust Enterprise Architecture (13 ركيزة أساسية + 8 امتدادات Zero-Trust متقدمة).

---

## 1. كيفية استدعاء المهارة في أي مشروع

عندما تريد بناء نظام تسجيل دخول وتسجيل وحسابات متكامل في أي مشروع جديد أو قائم، يكفي أن تكتب للوكيل:

```text
صمم نظام تسجيل الدخول والتسجيل والحسابات باستخدام sovereign-auth-architect
```

سيقوم الوكيل تلقائياً بقراءة [`SKILL.md`](./SKILL.md) وملفات المراجع السبعة داخل [`references/`](./references/) وتطبيق المعمارية الكاملة دون إغفال أي تفصيل أمني أو تجربة مستخدم.

---

## 2. هيكلية ملفات المهارة (`sovereign-auth-architect`)

```text
sovereign-auth-architect/
├── SKILL.md                                                   # المحرك الرئيسي وخطوات التنفيذ (Workflow)
├── BLUEPRINT.md                                               # هذا الدليل المرجعي الشامل (بالعربية)
└── references/
    ├── 01-identity-validation-and-forbidden-words.md          # الهوية الموحدة، تطبيع البريد/الهاتف، والقاموس الخماسي للمحظورات
    ├── 02-password-cryptography-and-strength.md               # تشفير scrypt/bcrypt، طابور العمل المحدود، وفحص zxcvbn السياقي
    ├── 03-rate-limiting-lockout-and-antifraud.md              # Rate Limiting مزدوج الوعاء، القفل التدريجي، ومقبرة الهويات الدائمة
    ├── 04-otp-2fa-and-email-architecture.md                   # محرك Salted HMAC OTP، التحقق الثنائي (TOTP + Email)، والأجهزة الموثوقة
    ├── 05-sessions-jwt-csrf-and-rbac.md                       # الجلسات الكتومة، تدوير JWT، الطرد اللحظي، CSRF، وهرمية الصلاحيات
    ├── 06-database-schemas-and-api-contracts.md               # مخطط قاعدة البيانات الكامل (14 جدولاً)، عقود API، والاختبارات الـ 12
    └── 07-advanced-zero-trust-and-passkeys.md                 # الإضافات الـ 8 المتقدمة (Passkeys, Sudo Mode, 72h Revert, Freeze...)
```

---

## 3. تفصيل المراجع السبعة داخل `references/`

### 1. [`01-identity-validation-and-forbidden-words.md`](./references/01-identity-validation-and-forbidden-words.md)
- **تسجيل الدخول الموحد:** قبول البريد الإلكتروني أو اسم المستخدم أو رقم الهاتف في حقل واحد.
- **تطبيع البريد الإلكتروني (`Gmail Canonicalization`):** إزالة النقاط `.` وإزالة `+tag` وتحويل `@googlemail.com` إلى `@gmail.com` لمنع تعدد الحسابات الوهمية.
- **حوكمة النطاقات:** القائمة البيضاء لمزودي البريد المعتمدين + دعم النطاقات الأكاديمية والحكومية (`.edu`, `.gov`) + حظر أكثر من 25 نطاق بريد مؤقت/وهمي (`mailinator`, `yopmail`, `10minutemail`, `mohmal`).
- **تطبيع رقم الهاتف (`E.164`):** عبر `libphonenumber-js` مع رفض الأرقام الوهمية والمتسلسلة (`11111111`, `1234567`).
- **فلتر `Leet-Speak` والقاموس الخماسي للمحظورات:**
  1. أسماء النظام والإدارة المحجوزة بالعربية والإنجليزية (`admin`, `root`, `support`, `official`, `ادمن`, `مدير`, `مشرف`, `دعم`, `رسمي`, `موثق`).
  2. الكلمات النابية الإنجليزية (`Profanity & NSFW`).
  3. الكلمات النابية العربية والفرانكو (`Arabizi`).
  4. الأسماء الدينية المقدسة لمنع الامتهان في المعرفات العامة.
  5. أسماء العلامات التجارية العالمية (`google`, `apple`, `stripe`, `paypal`, `discord`...) لمنع انتحال الهوية.
- **حظر المقاطع النصية للملف الشخصي (`ProfileSubstringBan`):** حظر ديناميكي عبر لوحة التحكم يشمل `username`, `firstName`, `lastName`, `bio`.

### 2. [`02-password-cryptography-and-strength.md`](./references/02-password-cryptography-and-strength.md)
- **سياسة قوة كلمة المرور:** `8–128` حرفاً دون اقتطاع صامت، حروف كبيرة وصغيرة وأرقام ورموز، منع تكرار الحرف 4 مرات، ومنع التسلسلات الشائعة (`qwerty`, `123456`).
- **فحص `zxcvbn` السياقي:** تمرير `[username, email, firstName, lastName, phone]` لمنع تضمين البيانات الشخصية داخل كلمة المرور.
- **تشفير `scrypt` / `bcrypt` مع طابور العمل المحدود (`Bounded Worker Queue`):** أقصى حد عمليتين متزامنتين + 8 في الانتظار، وإرجاع `503 AUTH_BUSY` للطلبات الزائدة لمنع هجمات استنزاف المعالج والذاكرة (`DoS`).
- **تصفير الذاكرة والهاش الوهمي:** مسح المفاتيح المشتقة من الذاكرة (`Buffer.fill(0)`) في بلوك `finally` + التحقق الوهمي المتساوي زمنياً (`verifyAgainstDummyPassword`) عند محاولة الدخول بحساب غير موجود لمنع كشف الحسابات عبر فرق التوقيت.
- **مؤشر القوة التفاعلي في الواجهة:** 4 أشرطة ملونة + قائمة تحقق تفاعلية من 6 شروط.

### 3. [`03-rate-limiting-lockout-and-antifraud.md`](./references/03-rate-limiting-lockout-and-antifraud.md)
- **Rate Limiting مزدوج الوعاء (`Dual-Bucket`: `IP` + `SHA-256(identifier)`):** لجميع نقاط النهاية الحساسة.
- **حماية الذاكرة (`OWASP API4:2023`):** Redis أساسي + ذاكرة محلية محدودة السعة (`MAX_ENTRIES = 10,000` مع مؤقت تنظيف كل 5 دقائق) وإرجاع ترويسات `Retry-After` و `X-RateLimit-*`.
- **أرضية الـ 8 ثوانٍ (`withMinimumDuration(8000)`):** في طلبات استعادة كلمة المرور لمنع كشف وجود البريد عبر سرعة استجابة خادم SMTP.
- **القفل التدريجي للحساب (`Account Lockout`):** قفل الحساب لمدة 15 دقيقة (`lockedUntil`) بعد 5 محاولات خاطئة، مع تصفير عداد الدخول فور الوصول لخطوة التحقق الثنائي (`2FA Checkpoint`).
- **منع البوتات والاحتيال ومقبرة الهويات (`RegisteredIdentity Graveyard`):** حقل Honeypot خفي + Cloudflare Turnstile / reCAPTCHA + تقييم مخاطر MaxMind minFraud + حماية الإحالات من نفس الـ IP + جدول مقبرة الهويات الدائمة الذي لا يُحذف عند حذف الحساب لمنع التلاعب بالفترات التجريبية أو الالتفاف على الحظر.

### 4. [`04-otp-2fa-and-email-architecture.md`](./references/04-otp-2fa-and-email-architecture.md)
- **تطبيع الأرقام العربية والفارسية (`٠-٩` و `۰-۹` -> `0-9`):** تلقائياً مع الحفاظ على الصفر على اليسار (`048291`).
- **محرك OTP المشفر بـ `Salted HMAC-SHA256` والمرتبط بالغرض (`Purpose-Bound`):** تخزين `HMAC-SHA256(secret, "otp:v1:" + purpose + ":" + targetId + ":" + salt + ":" + code)` مع قفل الصف (`SELECT ... FOR UPDATE`) وعداد محاولات فاشلة دائم في قاعدة البيانات يحرق الرمز تلقائياً بعد **5 محاولات خاطئة**، وفترة تهدئة **60 ثانية** بين كل إرسال.
- **التحقق الثنائي مزدوج القناة (`Dual-Channel 2FA`):** تطبيقات المصادقة (`RFC 6238 TOTP` + `RFC 4648 Base32` مع حماية منع إعادة استخدام الرمز في نفس الـ 30 ثانية `lastTotpStep`) + رمز البريد الإلكتروني (`Email OTP`).
- **حوكمة 2FA للأدمن + حماية عدم الحصار (`Anti-Trap Checkpoint Guard`):** سياسة مرنة (`disabled | email_only | totp_only | both`)، فترة سماح بالأيام للحسابات الجديدة، وعدم حبس المستخدم في شاشة Checkpoint إذا كان 2FA إجبارياً ولم يُفعّله بعد، 8 رموز استرداد احتياطية، **كوكي الجهاز الموثوق المشفر بـ `AES-256-GCM` لمدة 30 يوماً**، ورمز طوارئ للأدمن صالح لـ 15 دقيقة مع **حماية الأدمن الأعلى (`Supreme Admin Guard`)**.
- **بنية البريد الصلبة:** إعدادات SMTP مقساة (`TLSv1.2+`, `disableFileAccess`, `disableUrlAccess`)، منع التجاهل الصامت لفشل الإرسال في الإنتاج (`503` + التراجع عن المعاملة)، قائمة حظر الارتداد والشكاوى (`EmailSuppression` + Webhooks)، وقوالب بريد ثنائية اللغة (RTL/LTR).

### 5. [`05-sessions-jwt-csrf-and-rbac.md`](./references/05-sessions-jwt-csrf-and-rbac.md)
- **إدارة الجلسات والتوكنات:** جلسات `__Host-session` الكتومة (تخزين `SHA-256` فقط في قاعدة البيانات) أو `JWT Access (15m) + Refresh Token Rotation (1d/30d)` مع **كشف إعادة استخدام التوكن المسروق (`Reuse Detection`)** وإبطال جميع الجلسات فوراً.
- **الطرد العالمي اللحظي (`tokenVersion`) في `< 2ms`:** عند تغيير كلمة المرور أو حظر الحساب + تدوير مفاتيح التوقيع بدون توقف (`kid` Registry).
- **حماية CSRF ثنائية الطور** + فحص `Origin` و `Sec-Fetch-Site`.
- **هرمية الصلاحيات (`RBAC sortOrder`)** + صلاحيات الـ Bitfield السريعة (`1, 2, 4, 8...`) + الحسابات الفرعية (`Sub-Accounts`) ودعوات الفرق الصالحة لـ 48 ساعة + فصل بوابات الدخول (`WRONG_LOGIN_PORTAL`).
- **منع قفل الحساب عند فك ربط OAuth:** منع إلغاء ربط Google/Discord إذا لم يكن للمستخدم كلمة مرور وبريد مفعل.
- **تجربة المستخدم ولوحة الأمان (`/account/security`):** بانر التفعيل الفوري للحسابات غير المفعلة (`EMAIL_NOT_VERIFIED`)، حماية `sessionRevision`، مؤشر صحة أمان الحساب (`0–100`)، إدارة الجلسات والأجهزة النشطة، سجل التدقيق الأمني (`AuditLog`)، وتصدير بيانات الحساب بصيغة JSON (`GDPR / PDPL`).

### 6. [`06-database-schemas-and-api-contracts.md`](./references/06-database-schemas-and-api-contracts.md)
- مخطط قاعدة البيانات الكامل (`Prisma Schema` يضم الـ 14 جدولاً)، عقود نقاط النهاية (`REST API Contracts`)، وقائمة الاختبارات الآلية الـ 12 (`Automated Test Suite Checklist`).

### 7. [`07-advanced-zero-trust-and-passkeys.md`](./references/07-advanced-zero-trust-and-passkeys.md) (الإضافات الـ 8 المتقدمة — Zero-Trust Tier-0)
1. **منع التزوير البصري والمحارف الخفية (`Unicode Homograph & Zero-Width Sanitizer`):** تجريد المحارف الصفرية وعكس الاتجاه (`RTL Override`) وتوحيد الحروف السيريلية/اليونانية المشابهة بصرياً (`аdmin` -> `admin`) ومنع خلط الأبجديات في الكلمة الواحدة.
2. **وضع التأكيد الفائق (`Sudo Mode / Step-Up Auth` لمدة 10 دقائق):** اشتراط إعادة التحقق (`lastSudoVerifiedAt < 10m`) قبل أي عملية حساسة.
3. **بروتوكول تغيير البريد المزدوج + رابط التراجع الطارئ لمدة 72 ساعة (`EmailChangeRequest`):** تأكيد البريد الجديد بـ OTP مع إرسال رابط تراجع طارئ للبريد القديم صالح لـ 72 ساعة يعيد البريد الأصلي فوراً ويطرد جميع الجلسات (`tokenVersion++`).
4. **دعم مفاتيح المرور والبصمة (`WebAuthn / Passkeys - FIDO2`):** دعم `FaceID` / `TouchID` / `Windows Hello` / `YubiKey` مع فحص عداد التوقيع (`signCount`) لكشف استنساخ المفاتيح.
5. **كاشف السفر المستحيل والأجهزة الجديدة + زر التجميد الفوري (`One-Click Emergency Freeze`):** فرض `Step-Up OTP` عند الدخول من دولة أو جهاز جديد، مع زر تجميد فوري للحساب داخل رسائل التنبيه البريدية.
6. **منع إعادة استخدام آخر كلمة مرور واحدة (`previousPasswordHash`) + فحص `k-Anonymity HIBP`:** منع مطابقة كلمة المرور الجديدة مع كلمة المرور الحالية أو السابقة مباشرة فقط (`previousPasswordHash` على جدول `User`)، مع فحص التسريبات عبر إرسال أول 5 حروف من `SHA-1` فقط لواجهة `HaveIBeenPwned`.
7. **تقمص الحسابات الآمن للدعم الفني (`Cryptographic Admin Impersonation`):** جلسة ظل مؤقتة (15 دقيقة) مع إلزام ذكر السبب، ممنوعة من تعديل أمان الحساب، ومحمية ضد تقمص `isSupremeAdmin`.
8. **الحذف المؤجل مع فترة سماح 14 يوماً (`14-Day Soft-Delete Grace Period`):** تحويل الحساب إلى `PENDING_DELETION` لمدة 14 يوماً مع إمكانية الاسترجاع بضغطة زر عند الدخول، والاحتفاظ بسجل `RegisteredIdentity` (المقبرة) بعد الحذف النهائي.
