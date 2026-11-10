# Pillar 1 & 2: Identity Normalization, Multi-Identifier Intake & Forbidden Words Engine

This reference defines the exact identity intake, normalization, domain governance, phone validation, and 5-category forbidden words/usernames engine extracted across `course_online`, `store`, `vehosts`, `PPU-Complaints-Public`, `pterodactyl`, `fluxer`, and `al-deeb-family`.

---

## 1. Multi-Identifier Intake (Login & Lookup)

Login endpoints must accept a single `identifier` field (or `email`/`username`/`phone`) and automatically detect its type before normalization:

1. **Email Detection:** Contains `@`. Normalize via `EmailValidatorService.normalize(identifier)` and query `WHERE email = normalizedEmail`.
2. **Phone Detection:** Matches `/^[+0-9()\-\s]{7,20}$/`. Normalize via `PhoneValidatorService.validateAndNormalize(identifier)` into E.164 format (`+9665...`) and query `WHERE phone = e164Phone`.
3. **Username Detection:** Otherwise treat as a handle. Trim, convert to lowercase (`identifier.trim().toLowerCase()`), and query `WHERE username = normalizedUsername`.

> **Security Rule:** Regardless of which identifier type is used, if no user is found, the login flow MUST still execute a dummy password hash verification (`verifyPassword(password, DUMMY_HASH)`) and return a generic `"Invalid credentials"` (`401`) message to prevent account enumeration via response timing or error messages.

---

## 2. Email Normalization & Domain Governance

### 2.1 Control-Character & Length Guards
- Reject any email containing ASCII control characters: `/[\u0000-\u001f\u007f]/`.
- Minimum length: `5`, Maximum length: `254` (RFC 5321).
- Structural Regex: `/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/`.

### 2.2 Gmail & Alias Canonicalization (Anti-Multi-Account Farming)
Prevent a single user from creating unlimited accounts using Gmail dot-tricks (`u.s.e.r@gmail.com`), plus-addressing (`user+1@gmail.com`), or domain aliases (`@googlemail.com`):

```typescript
export class EmailValidatorService {
  private static readonly ALLOWED_DOMAINS = new Set([
    // Google
    'gmail.com', 'googlemail.com',
    // Microsoft
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'outlook.sa',
    // Yahoo
    'yahoo.com', 'yahoo.co.uk', 'ymail.com',
    // Apple
    'icloud.com', 'me.com', 'mac.com',
    // Privacy & Business Providers
    'protonmail.com', 'proton.me', 'zoho.com', 'aol.com', 'gmx.com', 'mail.com',
    // Regional ISPs
    'stc.com.sa', 'mobily.com.sa',
  ]);

  private static readonly BLOCKED_DISPOSABLE_DOMAINS = new Set([
    'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 'guerrillamail.info',
    'mailinator.com', 'yopmail.com', '10minutemail.com', 'throwaway.email',
    'fakeinbox.com', 'sharklasers.com', 'guerrillamailblock.com', 'grr.la',
    'dispostable.com', 'mailnesia.com', 'maildrop.cc', 'discard.email',
    'trashmail.com', 'trashmail.net', 'mohmal.com', 'tempail.com',
    'burnermail.io', 'tempmailo.com', 'emailondeck.com', 'crazymailing.com',
  ]);

  private static readonly ALLOWED_TLD_PATTERNS = [
    /\.edu$/,
    /\.edu\.[a-z]{2}$/, // e.g., .edu.ps, .edu.sa, .edu.jo, .edu.eg
    /\.ac\.[a-z]{2}$/,  // e.g., .ac.uk
    /\.gov\.[a-z]{2}$/,
  ];

  /**
   * Canonicalizes email to prevent duplicate accounts via Gmail dots or +tags.
   */
  static normalize(email: string): string {
    const trimmed = String(email || '').trim().toLowerCase();
    const parts = trimmed.split('@');
    if (parts.length !== 2) return trimmed;

    let [local, domain] = parts;

    // Strip +tag subaddressing across all providers
    local = local.split('+')[0];

    // Canonicalize Google domains & strip dots from local part
    if (domain === 'gmail.com' || domain === 'googlemail.com') {
      local = local.replace(/\./g, '');
      domain = 'gmail.com';
    }

    return `${local}@${domain}`;
  }

  static validate(
    email: string,
    options: { enforceWhitelist?: boolean; institutionalRegex?: RegExp } = { enforceWhitelist: true }
  ): { valid: boolean; normalizedEmail?: string; error?: string; errorAr?: string } {
    if (!email || typeof email !== 'string') {
      return { valid: false, error: 'Email is required', errorAr: 'البريد الإلكتروني مطلوب' };
    }
    if (/[\u0000-\u001f\u007f]/.test(email)) {
      return { valid: false, error: 'Invalid characters in email', errorAr: 'البريد الإلكتروني يحتوي على رموز غير صالحة' };
    }

    const trimmed = email.trim().toLowerCase();
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(trimmed) || trimmed.length > 254) {
      return { valid: false, error: 'Invalid email format', errorAr: 'صيغة البريد الإلكتروني غير صحيحة' };
    }

    // Optional strict institutional policy (e.g., PPU University: /^[0-9]{5,9}@ppu\.edu\.ps$/)
    if (options.institutionalRegex && !options.institutionalRegex.test(trimmed)) {
      return {
        valid: false,
        error: 'Email does not match institutional requirements',
        errorAr: 'البريد الإلكتروني لا يطابق شروط المؤسسة',
      };
    }

    const [local, domain] = trimmed.split('@');
    if (local.length < 2) {
      return { valid: false, error: 'Email username is too short', errorAr: 'الجزء الأول من البريد قصير جداً' };
    }

    if (this.BLOCKED_DISPOSABLE_DOMAINS.has(domain)) {
      return {
        valid: false,
        error: 'Disposable email addresses are not allowed',
        errorAr: 'عناوين البريد الإلكتروني المؤقتة أو الوهمية غير مسموح بها',
      };
    }

    if (options.enforceWhitelist) {
      const isAllowedDomain = this.ALLOWED_DOMAINS.has(domain);
      const isAllowedTld = this.ALLOWED_TLD_PATTERNS.some((pattern) => pattern.test(domain));
      if (!isAllowedDomain && !isAllowedTld) {
        return {
          valid: false,
          error: 'Email provider is not supported. Use Gmail, Outlook, Yahoo, iCloud, or an academic email.',
          errorAr: 'مزود البريد غير مدعوم. يرجى استخدام مزود معتمد مثل Gmail أو Outlook أو Yahoo أو iCloud.',
        };
      }
    }

    return { valid: true, normalizedEmail: this.normalize(trimmed) };
  }
}
```

---

## 3. Phone Number Validation & E.164 Normalization

Phone numbers must be validated with `libphonenumber-js` (or equivalent) and stored in strict **E.164** format (`+966512345678`):

```typescript
import { parsePhoneNumberFromString, CountryCode } from 'libphonenumber-js';

export class PhoneValidatorService {
  private static readonly BLOCKED_NUMBERS = new Set([
    '+966000000000', '+966111111111', '+966123456789',
    '+201000000000', '+10000000000', '+970590000000',
  ]);

  static validateAndNormalize(
    phone: string,
    defaultCountry: CountryCode = 'SA'
  ): { valid: boolean; normalizedPhone?: string; country?: string; error?: string; errorAr?: string } {
    if (!phone || typeof phone !== 'string') {
      return { valid: false, error: 'Phone number is required', errorAr: 'رقم الهاتف مطلوب' };
    }

    // Strip spaces, dashes, and parentheses; convert leading 00 to +
    let cleaned = phone.trim().replace(/[\s\-()]/g, '');
    if (cleaned.startsWith('00')) {
      cleaned = '+' + cleaned.slice(2);
    }

    try {
      const parsed = cleaned.startsWith('+')
        ? parsePhoneNumberFromString(cleaned)
        : parsePhoneNumberFromString(cleaned, defaultCountry);

      if (!parsed || !parsed.isValid()) {
        return { valid: false, error: 'Invalid phone number', errorAr: 'رقم الهاتف غير صالح' };
      }

      const e164 = parsed.format('E.164');
      const national = parsed.nationalNumber as string;

      // Reject repeating digits (e.g., 11111111) or simple sequences (1234567)
      if (
        this.BLOCKED_NUMBERS.has(e164) ||
        /^(\d)\1{6,}$/.test(national) ||
        /^1234567/.test(national)
      ) {
        return { valid: false, error: 'Fake or sequential phone numbers are not allowed', errorAr: 'رقم الهاتف غير صالح' };
      }

      return { valid: true, normalizedPhone: e164, country: parsed.country };
    } catch {
      return { valid: false, error: 'Unable to parse phone number', errorAr: 'تعذر التحقق من رقم الهاتف' };
    }
  }
}
```

---

## 4. Username Rules, Leet-Speak Normalization & 5-Category Forbidden Words Engine

Usernames, display names (`firstName`, `lastName`, `global_name`), and profile bios must pass a multi-layered filter covering structural rules, Leet-Speak de-obfuscation, and a 5-category bilingual blocklist.

### 4.1 Structural Username Rules
1. **Length:** `5` to `30` characters (for usernames); `2` to `50` characters (for first/last names).
2. **Case:** Automatically converted to lowercase (`a-z0-9._`).
3. **Start Character:** Must start with an English letter (`/^[a-z]/`).
4. **End Character:** Cannot end with `.` or `_` (`/[._]$/`).
5. **No Consecutive Separators:** Reject `..`, `__`, `._`, `_.` (`/(\.\.|__|_\.|\._)/`).
6. **Minimum Letters:** Must contain at least `3` alphabetic characters (`(username.match(/[a-z]/g) || []).length >= 3`).

### 4.2 Leet-Speak & Unicode Homograph / Zero-Width De-Obfuscation
Before checking any username or display name against the blocklist:
1. Strip all invisible Zero-Width characters (`\u200B-\u200F`, `\uFEFF`) and Bidirectional overrides (`\u202A-\u202E`), normalize with `.normalize('NFKC')`, and fold Cyrillic/Greek homograph lookalikes (`а` -> `a`, `е` -> `e`, `о` -> `o`, `р` -> `p`, `с` -> `c`, `х` -> `x`) using `UnicodeSanitizer` (see [`references/07-advanced-zero-trust-and-passkeys.md`](07-advanced-zero-trust-and-passkeys.md)).
2. Normalize common Leet-Speak character substitutions so attackers cannot bypass filters using `a_d_m_1_n` or `s.h.1.t`:

```typescript
export function normalizeLeetSpeak(input: string): string {
  return input
    .normalize('NFKC')
    .replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g, '')
    .toLowerCase()
    .replace(/[@4]/g, 'a')
    .replace(/3/g, 'e')
    .replace(/[1!|]/g, 'i')
    .replace(/0/g, 'o')
    .replace(/[$5]/g, 's')
    .replace(/7/g, 't')
    .replace(/[._\-\s]/g, ''); // Strip all separators to catch 'a.d.m.i.n'
}
```

### 4.3 The 3-Level / 5-Category Master Forbidden Words Dictionary (1,081 Unique Words)

> **Inviolable Additive Merge Rule (Zero-Deletion Guarantee):**
> When upgrading an existing codebase that already contains a forbidden usernames/words dictionary, you **MUST NEVER delete or shrink existing entries**. Always compute the union `EXISTING_PROJECT_WORDS ∪ SELECTED_TIER_WORDS` so zero existing blocked words are ever lost.

#### The 3 Progressive Enforcement Levels (selectable via Admin Panel or Config)
- **Level 1 (`1` / `'essential'` — ~260 words):** Core system/admin reserved handles (EN + AR), high-severity primary profanity roots (English, Arabic script, and core Arabizi roots), core sacred names, and top impersonated tech brands.
- **Level 2 (`2` / `'standard'` — ~540 words):** Includes **all of Level 1** + infrastructure/network/panel reserved terms (`pterodactyl`, `wings`, `daemon`, `cpanel`, `nginx`, `ssh`, `smtp`, `oauth2`, `2fa`, etc.), expanded English/Arabic profanity, extremism/terrorism/illicit terms, full sacred names (Asmaul Husna & Prophets), and 50+ global tech/gaming/finance brands.
- **Level 3 (`3` / `'maximum'` — 1,081 words, Recommended Default):** Includes **all of Level 1 + Level 2** + the complete, unabridged Arabizi/Franco-Arab inflection matrix (`kos*`, `zeb*`, `ayre*`, `sharmouta*`, `manyook*`, `gahba*`, `9a7ba*`, `3ars*`, `kalb*`, `hmar*`, `7mar*`, `hayawan*`, `khanzir*`, `khara*`, `5ara*`, `zibil*`, `teez*`, `ba3bous*`, `kessrabak*`, `yen3al*`, `ebnel*`, `weldel*`, `ibnelharam*`) and extended English slang/compound slurs.

Include this dictionary in every project (`src/data/forbidden-words.ts` or `config/slender_forbidden_usernames.php`):

```typescript
export type ForbiddenDictionaryTier = 1 | 2 | 3;

// ============================================================================
// CATEGORY 1: SYSTEM, ADMIN, TECHNICAL & OFFICIAL RESERVED HANDLES (EN + AR)
// ============================================================================
export const RESERVED_SYSTEM_WORDS_L1 = [
  // English Administrative & Core System
  'admin', 'administrator', 'administrateur', 'administrador', 'admin1', 'admin2', 'adminroot',
  'root', 'superuser', 'superadmin', 'supervisor', 'sys', 'sysadmin', 'system', 'systemadmin', 'systemuser',
  'master', 'owner', 'coowner', 'founder', 'cofounder', 'creator', 'director', 'executive',
  'staff', 'staffmember', 'team', 'official', 'verified', 'support', 'supportteam', 'helpdesk',
  'help', 'service', 'services', 'desk', 'serviceclient', 'customer', 'care', 'info', 'information',
  'contact', 'contactus', 'inquiry', 'feedback', 'inquiries', 'sales', 'billing', 'finance',
  'payment', 'payments', 'invoice', 'invoices', 'accounting', 'legal', 'law', 'compliance',
  'security', 'securityteam', 'abuse', 'secops', 'devops', 'sysops', 'netops', 'audit', 'auditor',
  'moderator', 'moderation', 'mod', 'mods', 'leadmod', 'headmod', 'community', 'manager',
  'postmaster', 'webmaster', 'hostmaster',
  // Arabic Official & System Terms
  'ادمن', 'أدمن', 'إدمن', 'الادمن', 'الأدمن', 'مدير', 'المدير', 'مدير_النظام', 'إدارة', 'ادارة', 'الإدارة', 'الادارة',
  'مشرف', 'المشرف', 'مشرفة', 'المشرفة', 'مشرفين', 'المشرفين', 'طاقم', 'الطاقم', 'طاقم_العمل',
  'فريق', 'الفريق', 'فريق_العمل', 'دعم', 'الدعم', 'دعم_فني', 'الدعم_الفني', 'خدمة_العملاء',
  'مساعد', 'المساعد', 'مساعدة', 'المساعدة', 'رسمي', 'الرسمي', 'موثق', 'الموثق', 'حساب_رسمي',
  'مالك', 'المالك', 'صاحب_الموقع', 'مؤسس', 'المؤسس', 'مسؤول', 'المسؤول', 'مسؤول_النظام',
  'سيرفر', 'خادم', 'الخادم', 'لوحة_التحكم', 'لوحة', 'نظام', 'النظام', 'بوت', 'روبوت',
  'حساب', 'مستخدم', 'زائر', 'تجريبي', 'تطبيق', 'موقع',
];

export const RESERVED_SYSTEM_WORDS_L2 = [
  'developer', 'developerteam', 'dev', 'devteam', 'engineer', 'architect', 'coder', 'programmer',
  'tester', 'qa', 'test', 'testing', 'staging', 'production', 'prod', 'demo', 'sandbox', 'beta',
  'alpha', 'trial', 'preview', 'internal', 'staging1', 'prod1', 'stage', 'release',
  'pterodactyl', 'ptero', 'wings', 'daemon', 'node', 'nodes', 'panel', 'dashboard', 'console', 'portal', 'cpanel', 'whm',
  'slender', 'slendertheme', 'slenderpanel', 'slendersystem', 'slenderserver', 'slendersoftware',
  'vehosts', 'qsai', 'qsaiwolf', 'jexactyl', 'pelican', 'multicraft', 'tcadmin', 'pterodactylpanel',
  'api', 'apiv1', 'apiv2', 'api-client', 'api-application', 'graphql', 'rest', 'webhook',
  'webhooks', 'endpoint', 'endpoints', 'server', 'servers', 'client', 'clients', 'remote',
  'network', 'gateway', 'router', 'switch', 'firewall', 'proxy', 'reverseproxy', 'nginx',
  'apache', 'caddy', 'cloudflare', 'socket', 'websocket', 'wss', 'ssl', 'tls', 'cert',
  'certificate', 'domain', 'dns', 'nameserver', 'ns1', 'ns2', 'ns3', 'www', 'mx', 'mail', 'ftp', 'sftp',
  'ssh', 'telnet', 'smtp', 'pop', 'pop3', 'imap', 'http', 'https', 'cdn', 'assets', 'static', 'localhost', '127.0.0.1',
  'null', 'undefined', 'void', 'true', 'false', 'nan', 'infinity', 'anonymous', 'anon', 'nobody', 'guest',
  'user', 'users', 'member', 'members', 'account', 'accounts', 'profile', 'profiles', 'setting', 'settings', 'config',
  'configuration', 'install', 'installer', 'setup', 'update', 'updater', 'upgrade', 'patch',
  'auth', 'authenticate', 'authentication', 'authorize', 'authorization', 'login', 'signin',
  'sign-in', 'log-in', 'logout', 'signout', 'sign-out', 'log-out', 'register', 'registration',
  'signup', 'sign-up', 'password', 'passwords', 'passwd', 'reset', 'reset-password', 'forgot-password',
  'verify', 'verification', 'verify-email', 'checkpoint', 'two-factor', 'totp', '2fa', 'mfa',
  'oauth', 'oauth2', 'session', 'sessions', 'cookie', 'cookies', 'token', 'tokens',
  'secret', 'secrets', 'key', 'keys', 'public', 'private', 'storage',
  'database', 'databases', 'db', 'mysql', 'mariadb', 'postgres', 'postgresql', 'redis',
  'cache', 'memcached', 'queue', 'queues', 'worker', 'workers', 'cron', 'cronjob', 'jobs',
  'backup', 'backups', 'restore', 'snapshot', 'activity', 'activity-log', 'audit-log',
  'terms', 'tos', 'privacy', 'privacy-policy', 'rules', 'status', 'uptime', 'maintenance',
  'terms-of-service', 'dmca', 'copyright', 'trademark', 'press', 'careers', 'blog',
  'news', 'announcements', 'discord-bot', 'bot', 'bots', 'robot', 'crawler', 'spider',
];

// Critical substrings that must NEVER appear anywhere inside a non-admin username
export const CRITICAL_BANNED_SUBSTRINGS = [
  'admin', 'administrator', 'superadmin', 'moderator', 'sysadmin',
  'support', 'official', 'verified', 'security', 'helpdesk',
];

// ============================================================================
// CATEGORY 2: ENGLISH PROFANITY, SLURS, NSFW & EXTREMISM (L1 / L2 / L3)
// ============================================================================
export const BANNED_ENGLISH_PROFANITY_L1 = [
  'fuck', 'fucker', 'fuckers', 'fucking', 'fuckoff', 'fuckup', 'fuckyou', 'fck', 'fuk', 'motherfucker', 'mothafucka',
  'shit', 'shits', 'shitty', 'shithead', 'bullshit', 'bitch', 'bitches', 'bitching', 'bitchy',
  'ass', 'asshole', 'arse', 'arsehole', 'bastard', 'cunt', 'cunts', 'dick', 'dicks', 'dickhead',
  'cock', 'cocks', 'cockhead', 'cocksucker', 'pussy', 'pussies', 'whore', 'whores', 'slut', 'sluts', 'slutty',
  'nigger', 'niggers', 'nigga', 'niggas', 'fag', 'faggot', 'faggots', 'faggy', 'dyke', 'kike', 'kyke', 'chink', 'spic',
  'retard', 'retarded', 'rape', 'rapist', 'pedo', 'paedo', 'pedophile',
  'porn', 'porno', 'pornography', 'xxx', 'sex', 'sexy', 'nude', 'nudes', 'naked', 'nsfw', 'hentai',
];

export const BANNED_ENGLISH_PROFANITY_L2 = [
  'hitler', 'stalin', 'nazi', 'nazis', 'swastika', 'holocaust', 'genocide',
  'terrorist', 'terrorism', 'jihadist', 'isis', 'daesh', 'alqaeda', 'al-qaeda', 'taliban',
  'suicide', 'suicidal', 'kill', 'murder', 'killurself', 'killmyself', 'kill-yourself', 'dieinfire',
  'scam', 'scammer', 'cocaine', 'heroin', 'meth', 'methamphetamine', 'crackhead', 'drugdealer', 'weed420',
  'shootup', 'massacre', 'columbine', 'nuke', 'bombthreat', 'bombing', 'explosive',
  'penis', 'vagina', 'vulva', 'clit', 'clitoris', 'boob', 'boobs', 'tit', 'tits', 'titties',
  'anal', 'anus', 'rectum', 'testicle', 'scrotum', 'foreskin', 'dildo', 'orgasm', 'masturbate', 'masturbation',
  'blowjob', 'handjob', 'fellatio', 'ejaculation', 'erection', 'cum', 'cumshot', 'semen', 'jizz',
];

export const BANNED_ENGLISH_PROFANITY_L3 = [
  'asswipe', 'asshat', 'assclown', 'assface', 'bollocks', 'boner', 'booty', 'coon', 'crap',
  'dipshit', 'douche', 'douchebag', 'dumbass', 'fart', 'fatass', 'fudgepacker', 'fudge-packer',
  'goddamn', 'goddamnit', 'damn', 'hell', 'homo', 'hooker', 'horny', 'jackass', 'jerkoff', 'milf',
  'nutsack', 'piss', 'pissed', 'prick', 'queer', 'scumbag', 'slag', 'tosser', 'twat', 'wank', 'wanker',
  'incest', 'bestiality', 'zoophilia', 'necrophilia', 'pecker', 'smegma', 'choad', 'cooter', 'felch',
  'gook', 'wetback', 'beaner', 'camel-jockey', 'raghead', 'towelhead', 'tranny', 'shemale',
  'carpet-muncher', 'skank', 'tramp', 'ho', 'hoe', 'pimp', 'suck', 'sucks', 'suckmy', 'eatshit',
];

// ============================================================================
// CATEGORY 3: ARABIC SCRIPT & FRANCO-ARAB (ARABIZI) PROFANITY (L1 / L2 / L3)
// ============================================================================
export const BANNED_ARABIC_AND_FRANCO_L1 = [
  // Core Arabic Script Slurs
  'شرموط', 'شرموطة', 'شرموطه', 'الشرموطة', 'قحبة', 'قحبه', 'القحبة', 'قحاب', 'عاهرة', 'عاهره', 'العاهرة', 'فاجرة', 'زانية',
  'كسم', 'كسمك', 'كسمكم', 'كس', 'كسختك', 'كس_امك', 'كس_اختك', 'عرص', 'العرص', 'عرصة', 'معرص',
  'خول', 'الخول', 'خولات', 'ديوث', 'الديوث', 'قواد', 'منيوك', 'المنيوك', 'منيوكة', 'متناك', 'متناكة', 'نيك',
  'طيز', 'طيزك', 'زب', 'زبي', 'زبك', 'شاذ', 'لوطي', 'سحاقية',
  // Core Arabizi Roots
  'sharmouta', 'sharmota', 'sharmoota', 'charmouta', 'qa7ba', 'qahba', '9a7ba', 'kahba', 'gahba', 'ga7ba',
  'ksmk', 'ksm', 'kosomak', 'kosomk', 'kossomak', 'kos', 'kuss', 'zob', 'zobi', 'zeb', 'zebbi',
  'teez', 'tiz', 'nayek', 'neek', 'nik', 'manyook', 'manyak', 'mnyak', 'metnak',
  '3ars', 'aars', 'ars', 'khawal', '5awal', 'dayouth', 'gawwad', '9awad', 'khara', '5ara',
];

export const BANNED_ARABIC_AND_FRANCO_L2 = [
  'ابن_الكلب', 'ابن_الحرام', 'ابن_شرموطة', 'ابن_قحبة',
  'يلعن', 'ينعل', 'ملعون', 'لعنة', 'الله_يلعنك', 'يلعن_شكلك', 'يلعن_ميتينك', 'تفو', 'يا_كلب', 'يا_حمار',
  'وسخ', 'سافل', 'واطي', 'حقير', 'منحط', 'نذل', 'قذر', 'زبالة', 'زباله', 'حيوان', 'حمار', 'كلب', 'خنزير',
  'خرا', 'خرة', 'زق', 'اباحي', 'إباحي', 'سكس', 'بورن', 'عاري', 'عارية', 'انتحار', 'ارهاب', 'إرهاب',
  'zag', 'za2', 'kalb', '7mar', 'hmar', 'hmara', 'khanzeer', '5anzeer', 'khanzir', '5anzir',
  'kessrabak', 'kosrabak', 'yen3al', 'yel3an', 'yil3an', 'yal3an', 'keso5tk', 'kosomrabak', 'ksmrabk',
];

export const BANNED_ARABIC_AND_FRANCO_L3 = [
  // Exhaustive "kos" family insults
  'koss', 'koos', 'kous', 'kosom', 'kussumak', 'kosamek', 'kosomko',
  'kosokht', 'kosokhtak', 'kosekhtak', 'kosikhtak', 'kosbayak', 'kosaboo', 'kosabouk',
  'kosemak', 'kusemak', 'kos5tk', 'kosokhtk', 'koso5tk', 'kso5tk',
  'ksoomak', 'ksoomt', 'ksmha', 'ksmo', 'ksmkum', 'kosemkom', 'koskhaltha',
  // Exhaustive "zeb" / "ayr" variants
  'zebb', 'zeby', 'zebby', 'zebak', 'zibik', 'zebi', 'zebou', 'zebhom',
  'zab', 'zabb', 'zabi', 'zaby', 'ayre', 'ayri', 'eire', 'eiry', 'eirak', 'ayrak',
  'airak', 'airfeek', 'ayrfeek', 'zbe', 'zbk', 'zbbk', 'zbb', 'ayr', '3ayr', '3ayre',
  // Exhaustive "sharmouta" variants
  'sharmuta', 'charmuta', 'charmota', 'chrmota', 'shrmota', 'shrmoota', 'sharmot', 'charmot',
  'sharmate', 'shramet', 'sharaamut', 'sharmoot', 'charmoot', 'charmoota', 'chrmoota', 'sharmotin', 'chramit',
  // Exhaustive "manyook" / "neek" variants
  'manyouk', 'mnyook', 'mnyouk', 'manyuk', 'mnyuk', 'manyok', 'mnyok',
  'manyouka', 'manyuka', 'mnyouka', 'manayek', 'mnayek', 'mnaiek', 'mnykeh',
  'manyakeh', 'mnyakeh', 'nyak', 'aneek', 'aneekak', 'aneekek', 'aniko',
  'nikk', 'nek', 'nekk', 'nayk', 'nikak', 'neekak', 'neekik', 'nikhom',
  // Exhaustive "gahba" / "9a7ba" variants
  'gahbeh', 'ga7beh', 'qa7beh', '9a7beh', 'gahbat', 'ga7bat', 'qa7bat', '9a7bat', '9hab', 'ghab', 'qhab', 'gohba', '9ohba',
  // Exhaustive "3ars" variants
  'arss', '3arss', '3arsa', 'arsa', '3arseh', 'arseh', '3ayras', '3aras', '3rs', '3rss', '3aroos', 'ma3roos', 'ma3ros', 'ta3rees', 't3rees',
  // Exhaustive animal & scoundrel insults
  'kelb', 'kalba', 'kelba', 'kleb', 'kileb', 'klab', 'ya-kalb', 'yakkalb',
  '7maar', 'hmaar', '7mara', '7ameer', 'hameer', 'e7mar', 'ehmar', 'ya-hmar', 'ya-7mar',
  'hayawan', '7ayawan', '7yawan', 'hayawen', '7ayawen', 'khenzir', 'khanazer', '5anazer',
  'bheema', 'bheem', 'bhima', 'bhim', 'baghar', 'baghara', 'ba9ara', 'baqara', 'toor', 'tore',
  // Exhaustive filth & body-part insults
  '5arah', 'kharah', 'khra', '5ra', '5raa', 'khraa', 'kolkhara', 'kol-khara', 'kol5ara', 'kol-5ara', 'kol5ra', 'kolkhra', 'yakhora', 'ya5ara',
  'zibil', 'zbel', 'zbeleh', 'zbaleh', 'zbal', 'zabbale', 'shakh5a', 'shakha', 'shakh', '5arafeek', 'kharafeek', '5arat', 'kharat', 'khrat', '5rat',
  'teezak', 'tizak', 'tizek', 'teezek', 'teezhom', 'tash', 'soorm', 'sormak', 'sormek', 'm2akhartek', 'moukhara',
  'ba3bous', 'ba3bousak', 'ba3boos', 'ba3bos', 'khorq', '5orq', 'khroq', '5roq',
  // Exhaustive blasphemous & compound family insults
  'rabak', 'rabek', 'aln3al', 'yen3alrabak', 'yil3anrabak', 'yel3anrabak', 'yal3anrabak', 'yen3al-rabak', 'yil3an-rabak',
  'yen3al-deenak', 'yil3an-deenak', 'yel3andeenak', 'yil3andeenak', 'yal3andeenak', 'al-deenk', 'deenk', 'deeneek',
  'ebnelkalb', 'ebn-el-kalb', 'ebnel7mar', 'ebn-el-7mar', 'ebnelsharmouta', 'ebn-el-sharmouta',
  'ebnelgahba', 'ebn-el-gahba', 'ebnel9a7ba', 'ebn-el-9a7ba', 'ibnelkalb', 'ibnelsharmouta',
  'weldel9a7ba', 'weld-el-9a7ba', 'weldelkalba', 'waldel9ahba', 'ibnelharam', 'ebnelharam',
  'ebn-el-7aram', 'ibnel7aram', 'ibn-el-haram', 'baskoot', 'shaleekh', 'shleekh',
];

// ============================================================================
// CATEGORY 4: SACRED RELIGIOUS NAMES & FIGURES (L1 / L2)
// ============================================================================
export const BANNED_RELIGIOUS_TERMS_L1 = [
  'allah', 'god', 'jesus', 'christ', 'muhammad', 'mohammed', 'moses', 'prophet', 'quran', 'koran', 'islam',
  'الله', 'رب', 'الرب', 'إله', 'اله', 'محمد', 'أحمد', 'رسول_الله', 'نبي', 'قرآن', 'القرآن', 'عيسى', 'موسى',
];

export const BANNED_RELIGIOUS_TERMS_L2 = [
  'bible', 'torah', 'messiah', 'yahweh', 'jehovah',
  'الرحمن', 'الرحيم', 'الملك', 'القدوس', 'السلام', 'المؤمن', 'المهيمن',
  'العزيز', 'الجبار', 'المتكبر', 'الخالق', 'البارئ', 'المصور', 'الغفار', 'القهار',
  'الوهاب', 'الرزاق', 'الفتاح', 'العليم',
  'الإنجيل', 'إنجيل', 'التوراة', 'توراة', 'المسيح', 'إبراهيم', 'ابراهيم', 'نوح', 'آدم',
  'جبريل', 'ميكائيل', 'إسرافيل',
];

// ============================================================================
// CATEGORY 5: GLOBAL BRAND NAMES (ANTI-IMPERSONATION / ANTI-PHISHING) (L1 / L2)
// ============================================================================
export const BANNED_BRAND_NAMES_L1 = [
  'google', 'youtube', 'apple', 'microsoft', 'amazon', 'aws', 'azure', 'meta', 'facebook', 'instagram',
  'whatsapp', 'twitter', 'tiktok', 'discord', 'telegram', 'github', 'gitlab', 'openai', 'chatgpt',
  'anthropic', 'claude', 'stripe', 'paypal', 'cloudflare',
];

export const BANNED_BRAND_NAMES_L2 = [
  'bitbucket', 'windows', 'threads', 'snapchat', 'reddit', 'linkedin', 'visa', 'mastercard',
  'binance', 'coinbase', 'vercel', 'ovh', 'hetzner', 'digitalocean', 'netflix', 'spotify',
  'valve', 'steam', 'mojang', 'minecraft', 'epicgames', 'riotgames', 'ea', 'ubisoft',
  'playstation', 'xbox', 'nintendo',
];

// ============================================================================
// TIER RESOLVER (LEVEL 1 = ESSENTIAL, LEVEL 2 = STANDARD, LEVEL 3 = MAXIMUM)
// ============================================================================
export const TIER_1_ESSENTIAL_WORDS = [
  ...RESERVED_SYSTEM_WORDS_L1,
  ...BANNED_ENGLISH_PROFANITY_L1,
  ...BANNED_ARABIC_AND_FRANCO_L1,
  ...BANNED_RELIGIOUS_TERMS_L1,
  ...BANNED_BRAND_NAMES_L1,
];

export const TIER_2_STANDARD_WORDS = [
  ...TIER_1_ESSENTIAL_WORDS,
  ...RESERVED_SYSTEM_WORDS_L2,
  ...BANNED_ENGLISH_PROFANITY_L2,
  ...BANNED_ARABIC_AND_FRANCO_L2,
  ...BANNED_RELIGIOUS_TERMS_L2,
  ...BANNED_BRAND_NAMES_L2,
];

export const TIER_3_MAXIMUM_WORDS = [
  ...TIER_2_STANDARD_WORDS,
  ...BANNED_ENGLISH_PROFANITY_L3,
  ...BANNED_ARABIC_AND_FRANCO_L3,
];

export const ALL_BANNED_WORDS = new Set(TIER_3_MAXIMUM_WORDS);

export function getBannedWordsSet(
  tier: ForbiddenDictionaryTier = 3,
  customOrExistingProjectWords: string[] = []
): Set<string> {
  const base =
    tier === 1 ? TIER_1_ESSENTIAL_WORDS : tier === 2 ? TIER_2_STANDARD_WORDS : TIER_3_MAXIMUM_WORDS;
  return new Set([...base, ...customOrExistingProjectWords.map((w) => w.trim().toLowerCase())]);
}
```

### 4.4 Complete Username & Display Name Validator (Multi-Tier Aware)

```typescript
export class UsernameValidatorService {
  static validate(
    username: string,
    options: { tier?: ForbiddenDictionaryTier; extraBannedWords?: string[] } = {}
  ): { valid: boolean; normalized?: string; error?: string; errorAr?: string } {
    if (!username || typeof username !== 'string') {
      return { valid: false, error: 'Username is required', errorAr: 'اسم المستخدم مطلوب' };
    }

    const clean = username.trim().toLowerCase();

    if (clean.length < 5 || clean.length > 30) {
      return {
        valid: false,
        error: 'Username must be between 5 and 30 characters',
        errorAr: 'اسم المستخدم يجب أن يكون بين 5 و 30 حرفاً',
      };
    }

    if (!/^[a-z]/.test(clean)) {
      return {
        valid: false,
        error: 'Username must start with an English letter',
        errorAr: 'اسم المستخدم يجب أن يبدأ بحرف إنجليزي',
      };
    }

    if (!/^[a-z0-9._]+$/.test(clean)) {
      return {
        valid: false,
        error: 'Username may only contain letters, numbers, dots (.), and underscores (_)',
        errorAr: 'اسم المستخدم يقبل فقط الحروف الإنجليزية، الأرقام، النقطة (.) والشرطة السفلية (_)',
      };
    }

    if (/[._]$/.test(clean) || /(\.\.|__|_\.|\._)/.test(clean)) {
      return {
        valid: false,
        error: 'Username cannot end with or contain consecutive dots/underscores',
        errorAr: 'لا يمكن أن ينتهي اسم المستخدم بنقطة أو شرطة سفلية أو يحتوي على رموز متتالية',
      };
    }

    const letterCount = (clean.match(/[a-z]/g) || []).length;
    if (letterCount < 3) {
      return {
        valid: false,
        error: 'Username must contain at least 3 letters',
        errorAr: 'اسم المستخدم يجب أن يحتوي على 3 حروف على الأقل',
      };
    }

    const activeSet = getBannedWordsSet(options.tier ?? 3, options.extraBannedWords ?? []);

    // 1. Direct & Separator-Stripped Match
    const stripped = clean.replace(/[._]/g, '');
    const deLeeted = normalizeLeetSpeak(clean);

    if (activeSet.has(clean) || activeSet.has(stripped) || activeSet.has(deLeeted)) {
      return {
        valid: false,
        error: 'This username is reserved or not allowed',
        errorAr: 'اسم المستخدم هذا محجوز أو غير مسموح به',
      };
    }

    // 2. Substring Match against Critical Reserved & Profanity Terms
    const substringCheckPool = [
      ...CRITICAL_BANNED_SUBSTRINGS,
      ...BANNED_ENGLISH_PROFANITY_L1.filter((w) => w.length >= 4),
      ...BANNED_ARABIC_AND_FRANCO_L1.filter((w) => w.length >= 4),
    ];

    for (const banned of substringCheckPool) {
      if (clean.includes(banned) || stripped.includes(banned) || deLeeted.includes(banned)) {
        return {
          valid: false,
          error: 'This username contains restricted words',
          errorAr: 'اسم المستخدم هذا يحتوي على كلمات محظورة أو محجوزة',
        };
      }
    }

    return { valid: true, normalized: clean };
  }
}
```

### 4.5 Dynamic Admin-Managed Profile Substring Bans (`fluxer` Pattern)
For platforms with user profiles (`username`, `global_name`, `bio`, `pronouns`), provide a database-backed `ProfileSubstringBan` table managed from the Admin Panel:
- **Columns:** `id`, `pattern` (case-insensitive substring), `scopes` (`['username', 'global_name', 'bio', 'pronouns']`), `reason` (private audit note), `createdBy`, `createdAt`.
- **Enforcement:** Query cached `ProfileSubstringBan` patterns on registration and profile updates, rejecting any input matching a banned substring for that field's scope.

