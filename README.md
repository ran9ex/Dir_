# درع | Dir' — بوابة حماية الذكاء الاصطناعي للمؤسسات
**Saudi-Arabic Enterprise AI Security Gateway**

**درع (Dir')** هو طبقة حماية أمنية ذكية تعمل كبوابة وسيطة (Security Gateway) بين موظفي المؤسسات ونماذج الذكاء الاصطناعي التوليدي (LLMs). صُمم المشروع خصيصاً لتلبية احتياجات السوق السعودي والعربي، وضمان الاستخدام الآمن والمسؤول لتقنيات الذكاء الاصطناعي دون المساس بخصوصية البيانات أو مخالفة الأنظمة التشريعية.

---

## الرؤية والمشكلة
مع التوسع المتسارع في اعتماد أدوات الذكاء الاصطناعي داخل بيئات العمل، تواجه المؤسسات تحديين رئيسيين:
1. **تسرب البيانات الحساسة:** قيام الموظفين بمشاركة بيانات العملاء، أرقام الهويات الوطنية، الحسابات البنكية (IBAN)، أو المستندات السرية مع نماذج خارجية دون تشفير.
2. **هجمات حقن التعليمات (Prompt Injection):** محاولات اختراق النماذج أو التلاعب بسلوكها عبر نصوص أو مستندات ملغومة باللغة العربية أو الإنجليزية.

---

## الحل والمميزات الرئيسية
يعمل **درع** في أجزاء من الثانية لفحص كل طلب ومرفق قبل وصوله إلى النموذج، ويقدم المزايا التالية:

* **الامتثال لنظام حماية البيانات الشخصية (PDPL):** التعرف التلقائي على صيغ البيانات السعودية (الهوية الوطنية، الإقامة، الآيبان، أرقام الجوال) وتوليد تقارير امتثال وتدقيق شاملة.
* **التعمية الذكية واستعادة البيانات (Tokenization & Masking):** استبدال البيانات الحساسة برموز مشفرة عديمة القيمة قبل إرسالها للذكاء الاصطناعي، ثم استعادة البيانات الأصلية للمستخدم المصرّح له فقط عند عودة الرد.
* **محرك كشف هجين (Hybrid Detection Engine):** يجمع بين القواعد الأمنية الصارمة وطبقة الذكاء الاصطناعي لرصد أساليب الهجوم والتلاعب المموهة باللغة العربية والإنجليزية.
* **فحص وعزل المستندات المرفقة:** تحليل محتوى الملفات والمستندات قبل معالجتها لمنع الهجمات المخفية داخل النصوص.
* **لوحة تحكم ومراقبة للامتثال (CISO Dashboard):** قياس مستوى المخاطر قبل وبعد الحماية، وحفظ سجل تدقيق (Audit Log) لكل عملية.

---

## آلية العمل باختصار
1. **الاعتراض (Intercept):** يرسل الموظف الطلب أو المستند عبر البوابة.
2. **الفحص والتعمية (Inspect & Mask):** يكشف **درع** التهديدات ويحجب البيانات الحساسة.
3. **المعالجة الآمنة (Safe Inference):** يُمرر الطلب المنقّى إلى نموذج الذكاء الاصطناعي.
4. **الاستعادة والتدقيق (Restore & Audit):** يعود الرد آمناً للمستخدم مع تسجيل العملية في لوحة الامتثال.

---

## روابط المشروع والمرفقات (Project Links)

* **تجربة النظام التفاعلية (Live Prototype):**https://l8ujf4dfoagx7cw88k3znb.streamlit.app/ 
* **فيديو العرض التوضيحي (Demo Video):** https://1drv.ms/f/c/b8685bb23b827e3d/IgBHVbt9zd19RKajIeD5KqsTAXAu_jxrvC3-Ft5mP75SeEQ?e=JiL6RS


**Saudi-Arabic Enterprise AI Security Gateway**

**Dir' (درع)** is an intelligent security gateway acting as a protective middleware layer between enterprise employees and Large Language Models (LLMs). Designed specifically for the Saudi and Arab markets, it ensures the safe and responsible adoption of generative AI without compromising data privacy or violating regulatory frameworks.

---

## Vision & Problem Statement
As enterprises rapidly adopt generative AI tools in daily workflows, they face two critical security challenges:
1. **Sensitive Data Leakage:** Employees inadvertently sharing customer records, Saudi National IDs, bank accounts (IBAN), or confidential documents with external AI models without encryption.
2. **Prompt Injection Attacks:** Malicious attempts to hijack model behavior or bypass security guardrails through obfuscated Arabic or English prompts and poisoned documents.

---

## Solution & Key Features
**Dir'** operates in milliseconds to inspect every prompt and attachment before reaching the AI model, offering the following capabilities:

* **Saudi PDPL Compliance:** Automated recognition of Saudi-specific data formats (National IDs, Iqama numbers, IBANs, mobile numbers) alongside comprehensive audit and compliance reporting.
* **Smart Tokenization & Masking:** Replaces sensitive entities with zero-value encrypted tokens prior to model inference, restoring original values exclusively for authorized users upon response.
* **Hybrid Detection Engine:** Combines deterministic security rules with an AI classification layer to detect obfuscated Arabic and English prompt injection and jailbreak attempts.
* **Document Inspection & Quarantine:** Analyzes attached files and documents prior to processing to neutralize hidden instructions and embedded threats.
* **CISO Security & Compliance Dashboard:** Measures inherent versus residual risk scores and maintains an immutable audit log for every transaction.

---

## How It Works
1. **Intercept:** The employee submits a prompt or document through the gateway.
2. **Inspect & Mask:** **Dir'** detects security threats and masks sensitive PII/financial data.
3. **Safe Inference:** The sanitized prompt is forwarded securely to the AI model.
4. **Restore & Audit:** The response is re-hydrated safely for the user while logging the event for compliance auditing.

---

## Project Links & Deliverables

* **تجربة النظام التفاعلية (Live Prototype):**https://l8ujf4dfoagx7cw88k3znb.streamlit.app/ 
* **فيديو العرض التوضيحي (Demo Video):** https://1drv.ms/f/c/b8685bb23b827e3d/IgBHVbt9zd19RKajIeD5KqsTAXAu_jxrvC3-Ft5mP75SeEQ?e=JiL6RS
