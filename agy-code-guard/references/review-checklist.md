# Comprehensive Code Review Checklist — Reference

**مرجع:** مستوحى من Clean Code و guard-skills و OWASP Top 10.
يُستخدم هذا المرجع عند مراجعة Pull Requests، أو الفحص الذاتي (Self-Check) قبل تسليم الكود البرمجي.

---

## 1. فحص أنماط فشل نماذج الذكاء الاصطناعي (LLM Anti-Patterns)

- [ ] **لا هلوسة في الحزم (No Hallucinated Packages):** جميع الـ imports موجودة في `package.json` / `requirements.txt` / `Cargo.toml`.
- [ ] **لا ابتلاع للأخطاء (No Empty Catch):** لا توجد كتل `catch (e) {}` أو `except: pass` تتجاهل الأخطاء بصمت.
- [ ] **لا نجاح زائف (No False Success):** الدوال لا تعيد بيانات ثابتة (mocked / hardcoded) بدلاً من الاتصال الفعلي بمصادر البيانات.
- [ ] **لا تكرار برمجي (No Copy-Paste Duplication):** لا توجد كتل متشابهة > 5 أسطر كان بالإمكان استخراجها.
- [ ] **لا توابع وهمية (No Pass-Through Wrappers):** لا توجد كلاسات أو دوال وسيطة فارغة لا تقدم أي قيمة (YAGNI).
- [ ] **لا تلوث بيئة الاختبار في الإنتاج:** خلو كود الإنتاج من استثناءات الفحص الخاصة ببيئة الاختبار `if (process.env.NODE_ENV === 'test')`.

---

## 2. النظافة وجودة التسمية (Clean Code & Naming)

- [ ] **الأسماء تكشف النية (Intent-Revealing Names):** تجنب الأسماء المبهمة (`data`, `temp`, `res`, `val`, `item`, `processData`).
- [ ] **حجم الدوال صغير (Small Functions):** الدالة تؤدي وظيفة واحدة ومحددة، وحجمها يفضل أن يكون ≤ 20-30 سطراً.
- [ ] **عدد المدخلات محدود (Parameter Count):** عدد المعاملات ≤ 3-4؛ إذا زادت عن ذلك يتم تجميعها في Object / Struct / DTO.
- [ ] **لا أعلام منطقية كمعاملات (No Boolean Flags):** تجنب `doAction(true)` وتقسيمها إلى دالتين منفصلتين تعبران عن النية.
- [ ] **خلو الكود من الأرقام السحرية (No Magic Numbers/Strings):** استخراج القيم الثابتة في متغيرات ومصفوفات معرّفة بوضوح.
- [ ] **التعليقات تشرح "لماذا" وليس "ماذا":** التعليقات لا تعيد صياغة الكود البديهي بل توضح الأسباب والقرارات المعمارية.

---

## 3. المعمارية والمبادئ الهندسية (Architecture & SOLID)

- [ ] **مسؤولية واحدة (Single Responsibility Principle):** كل صنف أو وحدة لها سبب واحد فقط للتغيير.
- [ ] **مفتوح/مغلق (Open/Closed Principle):** إمكانية التوسيع دون الحاجة لتعديل الكود الأصلي أو شلالات `switch/case` المتكررة.
- [ ] **عكس الاعتمادية (Dependency Inversion Principle):** المنطق الأساسي لا يعتمد على تفاصيل التنفيذ المباشرة أو Singletons خفية.
- [ ] **فصل الاهتمامات (Separation of Concerns):** عزل كود واجهات العرض (Presentation) عن منطق الأعمال (Business Logic) وتخزين البيانات.

---

## 4. الأمان والمتانة (Security & Robustness)

- [ ] **التحقق من صحة المدخلات (Input Validation):** فحص جميع مدخلات المستخدم والـ APIs الخارجية ضد الثغرات وتطهيرها.
- [ ] **معالجة متسقة لعمليات Async:** وجود `await` في كل مكان مطلوب، والتعامل مع حالات الـ rejection أو timeouts.
- [ ] **أمان ضد القيم المعدومة (Null/Undefined Safety):** استخدام Optional Chaining أو Null Checks لمنع انهيارات runtime.
- [ ] **منع تسريب البيانات الحساسة:** عدم طباعة المفاتيح السرية (API Keys) أو كلمات المرور في السجلات (Logs) أو الردود.

---

## 5. بوابة التسليم والاعتماد (Delivery Gate)

- [ ] الكود تم فحصه ذهنياً أو بأدوات linting/type-check بدون تحذيرات جديدة.
- [ ] لا يوجد كود معلّق (Commented-out code) أو استدعاءات `console.log` غير مقصودة.
- [ ] التوثيق والـ Types المحدثة تعكس التغيير الأخير بدقة.
