# Web Labs — نقطة استئناف

- المرحلة: P1 — عقد معاينة الجاهزية منفذ ومختبر؛ المراجعة والإصدار منفصلان.
- قاعدة العمل: `f863787569a7fcea85f5318f559bdb2890084299`.
- الفرع: `codex/web-labs-preparation-20261003`.
- working copy: `/home/aegisadmin/aegis-web-labs-development` على aegis-prod.
- التغييرات: خدمة/router/تعريف مثبت واختبارات وعقد عربي وربط CI؛ لا تشغيل حي ولا نشر.
- التالي بعد «تابع»: P2 اتصال Burp الحقيقي وتوافق الأدوات وcanonical dispatch بعد إعادة فحص main وPRs.

## ما نعيد استخدامه
Burp gateway، canonical capability execution، Assessment Launcher، Credential Vault، Browser Worker، Evidence وFinding Confirmation وWSTG، وfixture الصلاحيات الحالي.

## نقاط يجب ألا تضيع عند الاستئناف
1. تنفيذ capability لا يبدأ من dispatcher خاص بالمختبر.
2. preview لا يستدعي Launcher prepare لأنه ينشئ الأصل ويمكن أن يفعّل التفويض وفق وضع المختبر.
3. فحص source للهدف ليس حلًا للمختبر؛ mock ليس Burp حقيقيًا.
4. حالة تنفيذ Scan تبقى مصدرها الحالي؛ حكم اللاب حالة مستقلة مرتبطة به.
5. إنشاء provider/configuration عملية إعداد عبر المسار الحالي، وليس واجهة تمنح صلاحيات لنفسها.
6. أول fixture يحتوي vulnerable/fixed بالفعل؛ لا نبني بديلًا قبل استعماله.
7. كل خطوة وتقرير لهما تفسير عربي ودليل أو سبب عدم حسم.
8. المستودع فيه عمل إصدار جارٍ؛ افحص PRs والـchanged files قبل لمس ملف مشترك.

## التحقق
فحص التحضير المحلي: PASS؛ عشرة فحوص على المسارات والعقود ومصدر fixture وربط WSTG وحدود التغيير. لا يدعي هذا السجل CI أو اختبار Burp حيًا.

## إغلاق التنفيذ المحلي لـP1

- عقد: `aegis.web-labs-readiness.v1` عبر `POST /api/v1/web-labs/prepare`.
- التفاصيل: [العقد العربي](WEB_LABS_READINESS_CONTRACT_AR.md).
- الاختبارات: 63 PASS؛ 32 للمعاينة، والباقي regressions للبوابة والمزود وLauncher.
- البيئة: حاويات منفصلة وشبكة داخلية دون host ports أو قواعد بيانات الإنتاج؛ source mount read-only.
- حارس SQL داخل الخدمة وخيط API يرفض الكتابة؛ ciphertext/fingerprint لا يدخلان SELECT الخاص بالمراجع، ولا يفك السر أو يستخدم Celery أو يطلب الهدف.
- `metadata_ready` يفصل إعداد السجلات عن `execution_ready`؛ runtime/fixture binding ما زالا غير متحققين في P1.
- أسماء `web.burp-labs` و`burp.http_request` متطلبات مقترحة لـP2 وغير مسجلة/مدعومة في هذه المرحلة.
- CI: يضاف الاختبار إلى workflow البوابة الحالي؛ حالة PR الحالية هي المرجع، ولا يفترض هذا checkpoint نجاح CI أو الدمج.
- اختبار المزود التجريبي لا يثبت اتصال Burp حقيقي أو حل لاب.
