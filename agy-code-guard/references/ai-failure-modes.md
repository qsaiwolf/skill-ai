# LLM AI Failure Modes — Reference

**مرجع:** مستوحى من [guard-skills/clean-code-guard/references/ai-failure-modes.md](https://github.com/amElnagdy/guard-skills)

هذا المرجع يحتوي على الـ 14 نمط فشل المنهجي الذي تُنتجه LLMs في الكود.
اقرأه كاملاً عند:
- مراجعة كود يبدو "صحيحاً" لكن يشعر أنه هش
- debugging سلوك غريب في production
- تسليم كود agent-generated لأول مرة

---

## 1. Code Duplication Explosion (الأكثر شيوعاً)

**المشكلة:** LLMs تنسخ-تلصق بدلاً من إعادة الاستخدام.
**الإحصاء:** زيادة 8x في code duplication بين 2021-2024 (GitClear 2025).

**الكشف:**
```
# ابحث عن blocks متشابهة > 5 أسطر
# أي دالة تبدو مألوفة → ابحث عن نسخة مشابهة في الكود
```

**الحل:** Extract → Function/Module مع اسم واضح.

---

## 2. Package/Symbol Hallucination

**المشكلة:** LLMs تستورد حزم وتستدعي methods غير موجودة.
**الإحصاء:** معدل 19.6% عبر 16 model مختلف (Spracklen et al., USENIX Security '25).

**الكشف:**
```javascript
// كل import → تحقق في package.json / requirements.txt / Cargo.toml
// كل method call غير مألوف → تحقق من التوثيق الرسمي
import { nonExistentHelper } from 'real-package'; // ← هلوسة شائعة
```

**الحل:** تحقق من كل حزمة مُضافة قبل التسليم.

---

## 3. Swallowed Errors (Silent Catch)

**المشكلة:** LLMs تلف operations خطيرة في catch-all handlers.
**المصدر:** Karpathy — "LLMs wrap risky operations in broad catch-all handlers"

**الكشف:**
```javascript
// 🔴 أنماط خطيرة:
try { ... } catch (e) {}
try { ... } catch (e) { return null; }
try { ... } catch (e) { return false; }

# Python:
try: ...
except: pass
except Exception: pass
```

**الحل:** كل catch يجب أن يُسجّل أو يُنشر أو يتخذ قراراً مقصوداً.

---

## 4. False Success Declaration

**المشكلة:** الـ agent يُعلن النجاح رغم فشل الاختبارات.
**المصدر:** Fowler — "Patterns for Reducing Friction"

**الكشف:**
```javascript
// يُعيد fixture values hardcoded:
function getUserById(id) {
    return { id: 1, name: "Test User" }; // ← لا يجلب من DB فعلاً
}
```

**الحل:** تأكد أن الكود يؤدي العملية الفعلية لا يُحاكيها.

---

## 5. Function Bloat

**المشكلة:** LLMs تكتب دوالاً طويلة جداً.
**الإحصاء:** متوسط نما من 142 إلى 267 LoC في AI-assisted commits (GitClear).
**المعيار:** أي دالة > 30 سطر مشبوهة. > 50 سطر: اقسمها بالإجبار.

**الكشف:** ابحث عن `function` / `def` / `fn` وأحسب الأسطر حتى نهايتها.

---

## 6. Premature Abstraction (Over-Engineering)

**المشكلة:** LLMs تُنشئ abstractions قبل الحاجة لها.
**الكشف:**
```javascript
// Pass-through wrapper بلا قيمة:
class UserServiceWrapper {
    getUserById(id) { return this.userService.getUserById(id); }
}
// Interface بـ method واحدة تُستخدم في مكان واحد فقط
// Factory لـ object نوع واحد فقط
```

**YAGNI:** "You Aren't Gonna Need It" — لا تبنِ ما لا يُستخدم الآن.

---

## 7. Magic Values in Logic

**المشكلة:** قيم literal مشفرة مباشرة في business logic.
**الكشف:**
```javascript
// 🔴 Magic values:
if (user.role === 3) { ... }
setTimeout(fn, 86400000);
if (score > 0.75) { ... }

// ✅ Named constants:
if (user.role === ROLE.ADMIN) { ... }
setTimeout(fn, ONE_DAY_MS);
if (score > CONFIDENCE_THRESHOLD) { ... }
```

---

## 8. Hidden Dependencies (Invisible Coupling)

**المشكلة:** LLMs تخفي dependencies في global state أو singletons.
**الكشف:**
```javascript
// 🔴 Global state مخفي:
function processOrder() {
    const config = globalThis.appConfig; // من أين؟
    const db = Database.getInstance();   // singleton خفي
}

// ✅ Dependencies صريحة:
function processOrder(config, db) { ... }
```

---

## 9. Misleading Comments

**المشكلة:** LLMs تكتب comments تصف *ما* يحدث لا *لماذا*.
**الكشف:**
```javascript
// 🔴 Comment بلا قيمة:
// increment counter
counter++;

// 🔴 Comment outdated:
// returns user object
function getUser() { return null; } // الكود تغيّر والـ comment لا

// ✅ Comment ذو قيمة:
// Rate limit: 3 attempts before lockout per OWASP ASVS 2.1.7
if (attempts >= 3) lockAccount(userId);
```

---

## 10. Broad Exception Catching

**المشكلة:** catch لـ Exception/Error الجذر بدلاً من exceptions محددة.
**الكشف:**
```python
# 🔴 Too broad:
except Exception as e: log(e)

# ✅ Specific:
except (ConnectionError, TimeoutError) as e: handle_connection(e)
except ValidationError as e: return_user_error(e)
```

---

## 11. Inconsistent Error Handling Strategy

**المشكلة:** بعض الأخطاء تُنشر، بعضها تُسجَّل، بعضها تُبتلع — في نفس الكودبيس.
**الكشف:** راجع كيف تتعامل كل catch block مع الأخطاء — يجب أن يكون متسقاً.

---

## 12. Test Pollution in Production Code

**المشكلة:** LLMs تُدرج test fixtures أو mock logic في production code.
**الكشف:**
```javascript
// 🔴 Mock في production:
if (process.env.NODE_ENV !== 'test') {
    // actual logic
} else {
    return mockData; // ← هذا لا يجب أن يكون هنا
}
```

---

## 13. Stale Documentation

**المشكلة:** LLMs تُعدّل الكود لكن لا تُعدّل docstrings/README.
**الكشف:** بعد أي تعديل، تحقق أن:
- docstrings تصف السلوك الحالي
- examples في التوثيق لا تزال صحيحة
- parameter names متطابقة

---

## 14. Concurrency Blindness

**المشكلة:** LLMs تفترض execution sequential في كود async/concurrent.
**الكشف:**
```javascript
// 🔴 Race condition:
let count = 0;
async function increment() { count++; } // ليس atomic في concurrent context

// 🔴 Missing await:
const data = fetchData(); // يُعيد Promise لا data
```

---

## الأولويات عند المراجعة

```
Priority 1 (يمنع التسليم): #3, #4, #14
Priority 2 (يجب إصلاحه): #1, #2, #7, #8
Priority 3 (اقتراحات): #5, #6, #9, #10, #11, #12, #13
```
