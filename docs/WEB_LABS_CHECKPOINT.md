# Web Labs — نقطة استئناف

- المرحلة: P0 التجهيز فقط.
- قاعدة العمل: `f863787569a7fcea85f5318f559bdb2890084299`.
- الفرع: `codex/web-labs-preparation-20261003`.
- working copy: `/home/aegisadmin/aegis-web-labs-development` على aegis-prod.
- التغييرات: وثائق وخطة آلة؛ تطبيق المختبر لم يبدأ بعد.
- التالي بعد «تابع»: P1 preview لعقد جاهزية المختبر، واختبارات العزل وعدم الكتابة/dispatch.

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
