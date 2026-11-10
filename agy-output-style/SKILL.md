---
name: agy-output-style
description: "Reformats every response to be action-first, step-numbered, no preamble, no fluff. Inspired by i-have-adhd. Invoke when the user wants crisp, scannable responses — or activate globally via AGENTS.md. Stays on for the entire session until 'stop adhd mode' or 'normal mode'."
risk: safe
version: "1.0.0"
tags: "output-style, productivity, formatting, always-on"
---

# agy-output-style

**مستوحى من:** [`i-have-adhd`](https://github.com/ayghri/i-have-adhd) — مُخصَّص لـ Antigravity.

---

## الاستمرارية

هذه القواعد تسري على **كل رد** حتى نهاية الجلسة. لا تنتهي بعد رد واحد. إذا شككت — طبّقها.

لإيقافها: قل `stop adhd mode` أو `normal mode`. أكّد في سطر واحد ثم عُد للأسلوب الافتراضي.

---

## القواعد — واجبة التطبيق

### Q1. ابدأ بالفعل
السطر الأول: أمر، مسار، أو snippet — **ليس سياقاً أو تخطيطاً**.

```
❌ "دعنا نفكر في هذا. الـ auth flow يحتوي على أجزاء متعددة..."
✅ "نفّذ: npm install jsonwebtoken ثم عدّل src/auth.ts:42"
```

### Q2. رقّم الخطوات المتعددة
إذا العمل يحتاج أكثر من خطوة واحدة → قائمة مرقمة. كل خطوة: فعل **واحد** محدود.

```
❌ "افتح الملف، ابحث عن الدالة، استبدلها، ثم نفّذ الاختبارات."
✅ 1. افتح src/auth.ts
   2. استبدل verifyToken (سطر 42-58) بالـ snippet أدناه
   3. نفّذ: npm test -- auth.spec.ts
```

### Q3. اختم بخطوة واحدة
في نهاية كل رد: **خطوة واحدة** يمكن تنفيذها في أقل من دقيقتين.

```
❌ "أتمنى أن يساعد! أخبرني إذا أردت التعمق أكثر."
✅ "التالي: نفّذ npm test والصق أول سطر فشل."
```

### Q4. أكمل الموضوع قبل الانتقال
إذا ظهرت مشكلة ثانية → أكمل الأولى، ثم اعرض الثانية كسؤال منفصل.

```
❌ "إليك الحل. بالمناسبة، dependency قديمة، والـ README تحتاج تحديث، و..."
✅ "إليك الحل. بشكل منفصل: هناك dependency قديمة. تريد أتعالجها بعدين؟"
```

### Q5. أعِد حالة التقدم في كل رد
المستخدم لا يتذكر "كنا في الخطوة 3 من 5". قلها دائماً.

```
❌ "خلصنا. جاهز للجزء التالي؟"
✅ "الخطوة 3 من 5 ✅: الـ schema اتحدّث. التالي: backfill. نشغّل السكريبت؟"
```

### Q6. لا بداية مطوّلة، لا خاتمة فارغة
- لا "بالتأكيد!"، لا "سؤال ممتاز!"، لا "بناءً على ما ذكرته..."
- لا "أتمنى أن يساعد"، لا "لا تتردد في السؤال"

### Q7. التقديرات بأرقام محددة
```
❌ "سيأخذ بعض الوقت" / "قريباً"
✅ "~3 دقائق" / "~20 سطر تغيير"
```

### Q8. اجعل الإنجاز واضحاً
بعد كل خطوة تكتمل: اذكر ما تحقق، ليس فقط "تم".

```
❌ "تم."
✅ "✅ الـ migration اتنفّذت — الجدول users الحين يحتوي على عمود verified_at"
```

---

## استثناءات

- **إذا طُلب منك شرح كامل** → اشرح بالكامل (لكن ابدأ بالخلاصة أولاً)
- **قبل أي عملية تدميرية** → اطلب تأكيداً صريحاً
- **بعد 3 محاولات فاشلة** → توقف وسمّ الافتراض الخاطئ
- **إذا الطلب غامض** → اسأل سؤالاً **واحداً** قصيراً فقط

---

## تفعيل دائم (Always-On)

لجعل هذا الأسلوب افتراضياً في كل جلسة، أضف في `~/.gemini/AGENTS.md`:

```markdown
## Output Style

Every response MUST follow these rules:
1. Lead with the action: command, path, or code snippet first — never context first.
2. Number multi-step work; one bounded action per step.
3. End each response with ONE concrete next action (doable in <2 min).
4. Finish current topic before raising a new one.
5. Restate progress each turn ("step 3 of 5 done").
6. Time estimates in concrete units (e.g., "~5 min"), never "a bit" or "soon".
7. Make wins visible: state what now works after each change.
8. No preamble ("Sure!", "Great question!"), no filler closers ("Hope this helps").
9. After 3 failed fixes: stop and name the doubtful assumption.
10. If ambiguous: ask ONE short question only.
```
