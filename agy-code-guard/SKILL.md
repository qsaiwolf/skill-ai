---
name: agy-code-guard
description: "Auto-applied guard-pass after every code write/edit/refactor — before presenting or committing. Catches LLM-specific failure modes (duplication, hallucinated packages, swallowed errors, success-despite-failure) plus Clean Code / SOLID / DRY / KISS / YAGNI violations. Invoke proactively after writing non-trivial code, or use explicitly: 'review this diff', 'is this safe to merge?', 'audit this code'. DO NOT USE for: conceptual questions, CI config, git workflow, prose, data analysis, or test code (use test-guard for tests)."
risk: safe
version: "1.0.0"
tags: "code-quality, guard, review, clean-code, SOLID, LLM-failures"
---

# agy-code-guard

**مستوحى من:** [`guard-skills/clean-code-guard`](https://github.com/amElnagdy/guard-skills) — مُكيَّف مع Antigravity.

### مراجع إضافية:
- [أنماط فشل نماذج الذكاء الاصطناعي الـ 14](references/ai-failure-modes.md)
- [قائمة المراجعة الشاملة للكود](references/review-checklist.md)

---

## متى يعمل هذا السكيل

يُطبَّق تلقائياً في 3 حالات:

| الحالة | الزناد |
|--------|--------|
| **Guard-pass** (الأساسي) | بعد كتابة/تعديل/refactor أي كود قبل التسليم |
| **Live mode** | عند استدعائه صراحةً قبل تعديل خطير |
| **Review mode** | عند "راجع هذا الكود" / "audit" / "is this safe?" |

**لا تستخدمه مع:** أسئلة مفاهيمية، CI/CD config، git workflow، نثر، تحليل بيانات، كود الاختبارات.

---

## أخطاء الـ LLM المنهجية — احفظها عن ظهر قلب

> **اقرأ هذا القسم أولاً — الأعلى أهمية في السكيل بأكمله.**

هذه الأخطاء الـ 9 موثقة ببحوث منشورة:

| # | الخطأ | المصدر | الكشف |
|---|-------|--------|-------|
| 1 | **تكرار الكود** — 8x زيادة في 2021-2024 | GitClear 2025 | ابحث عن blocks متشابهة > 5 أسطر |
| 2 | **هلوسة الحزم** — 19.6% معدل | USENIX Security '25 | تحقق من وجود كل import/require |
| 3 | **ابتلاع الأخطاء** — `catch (e) {}` أو `catch { pass }` | Karpathy | ابحث عن empty catch blocks |
| 4 | **النجاح الكاذب** — يُعلن النجاح رغم فشل الاختبارات | Fowler | تحقق من أن الكود لا يُعيد قيم hardcoded |
| 5 | **دوال ضخمة** — متوسط 267 سطر في AI commits | GitClear | أي دالة > 30 سطر مشبوهة |
| 6 | **تجريد مفرط** — wrappers فوق wrappers بلا قيمة | YAGNI | ابحث عن pass-through methods |
| 7 | **Magic strings/numbers** — قيم مشفرة مباشرة في اللوجيك | Clean Code | ابحث عن literals مجردة |
| 8 | **تبعيات مخفية** — global state، singletons غير مُعلنة | DIP | تحقق من constructor/function params |
| 9 | **توثيق كاذب** — comments تصف ما تم لا لماذا | Clean Code | comments تقول "obvious" |

---

## القواعد الإلزامية — Always-Applied

### الدوال والأسماء

1. **الأسماء تكشف النية.** لا `data`, `result`, `item`, `temp`, `value`, `helper`, `manager`, `utils`, `handle_*`, `process_*`, `do_*` بدون qualifier.
2. **الدوال صغيرة.** الهدف ≤20 سطر، abstraction level واحد، مسؤولية واحدة.
3. **≤4 arguments.** من 5 فأكثر: استخدم request/config object.
4. **لا boolean flag arguments.** بدلاً منها: دالتان منفصلتان.
5. **لا output arguments.** الدالة تُعيد البيانات، لا تُعدّل مُدخلاتها.

### معالجة الأخطاء

6. **لا silent catch.** `catch (e) {}` أو `catch { pass }` أو `catch { return null }` **محظور**.
7. **كل async operation** لها error handling صريح مع context مفيد في رسالة الخطأ.
8. **الأخطاء تُنشر للأعلى** أو تُسجَّل مع context — لا تختفي.

### التكرار (DRY/KISS/YAGNI)

9. **لا نسخ-لصق** لبلوكات أكبر من 5 أسطر. استخرجها لدالة/module.
10. **لا abstraction قبل الحاجة.** ثلاث تكرارات → فكّر في الاستخراج. قبل ذلك: لا.
11. **لا wrappers فارغة.** `doThing() { return thing(); }` بلا منطق إضافي → احذفها.
12. **لا كود ميت.** كود معلق (commented-out) وكود unreachable يُحذف.

### SOLID

13. **SRP:** كل class/module سبب واحد للتغيير. إذا احتجت "و" لوصف ما تفعله — اقسمها.
14. **OCP:** امتداد بلا تعديل. إذا كل feature جديدة تُعدّل نفس الـ switch/if-chain → اعتمد polymorphism.
15. **DIP:** الكود العالي المستوى يعتمد على abstractions، ليس implementations. لا `new ConcreteClass()` في business logic.

### الحزم والـ Imports

16. **تحقق من وجود كل حزمة مُستوردة** في `package.json`/`requirements.txt`/`Cargo.toml` قبل التسليم.
17. **لا wildcard imports** في production code (`import * as X` بدون سبب واضح).

---

## Self-Check قبل التسليم

قبل عرض أي كود على المستخدم، مرّ على هذه القائمة:

```
[ ] لا empty catch blocks
[ ] لا دوال > 30 سطر بدون تعليق جيد
[ ] لا imports لحزم غير موجودة
[ ] لا boolean flags في arguments
[ ] لا كود متكرر > 5 أسطر
[ ] لا magic literals في business logic
[ ] كل async له error handling
[ ] الأسماء تصف النية لا التنفيذ
[ ] لا YAGNI violations (abstractions بدون استخدام حالي)
```

إذا أي بند ❌ → أصلحه قبل التسليم. لا تُبلّغ المستخدم بوجود مشكلة إلا إذا كانت بحاجة لقرار منه.

---

## Findings Format (Review Mode فقط)

```
## Code Review — [filename or diff title]

### 🔴 Critical (يمنع التسليم)
- [L42] Empty catch swallows TypeError — يُخفي أعطال authentication

### 🟡 Important (يجب تصحيحه قبل merge)
- [L17-45] دالة processOrder: 48 سطر، تخلط فعلين منفصلين

### 🔵 Minor (اقتراحات)
- [L8] اسم `data` غير واضح — اقتراح: `userAccountData`

### ✅ Good Patterns
- Error propagation سليم في fetchUser
```

---

## حدود هذا السكيل

- لا يُغني عن linters، type checkers، أو formatters — استخدم أدوات المشروع لذلك.
- لا يراجع كود الاختبارات (استخدم `test-guard` لذلك).
- التقديرات في الـ findings قد لا تكون شاملة للكود كله.
