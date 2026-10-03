# مختبرات الويب — حزمة تنفيذ مبنية على المشروع الحالي

## الحالة والحدود
- قاعدة التطوير المثبتة: `f863787569a7fcea85f5318f559bdb2890084299`.
- الفرع: `codex/web-labs-preparation-20261003`.
- المرحلة الحالية: P0 تجهيز التصميم والتنفيذ؛ الوظائف الجديدة لم تنفذ بعد.
- ينتهي كل عمل مرحلي بتقرير عربي، ثم انتظار كلمة «تابع» قبل المرحلة التالية.
- الخطة مرتبطة بالمخرجات ومعايير قبولها، دون تقديرات زمنية.

## قرارات الدمج
1. التطبيق داخل `aegis-platform/`، والوثائق داخل `docs/`.
2. يبدأ التنفيذ من `POST /api/v1/capabilities/{capability_id}/execute`؛ التحضير واجهة قراءة جاهزية، وليس dispatcher ثانيًا.
3. البوابة الحالية `/api/v1/burp-mcp` تنفذ العمليات؛ Evidence وFinding Confirmation وWSTG تبقى مصادر الحكم الحالية كل حسب اختصاصه.
4. عند إضافة capability لـBurp نوسع التسجيل والتحقق من الخيارات والـprofile والـdispatch معًا؛ التسجيل وحده لا يثبت جاهزية التنفيذ.
5. أي خطوة فرعية تسجل داخل المهمة القائمة؛ لا scheduler أو queue أو منظومة صلاحيات جديدة.
6. LabAttempt يربط Scan والخطوات وحكم اللاب؛ لا ينشئ نسخة ثانية من حالة تنفيذ Scan أو صلاحيات المستخدم.
7. تبقى Attack Replay الحالية محاكاة دون شبكة؛ HTTP replay الفعلي له عقد محدد فوق التنفيذ القائم.
8. نستعمل Assessment Launcher الموجود لإنشاء أصل عند الحاجة، وفق وضع المختبر الحالي؛ preview للاب لا يستدعي إنشاء أصل أو منح تفويض.
9. لا تفوض capability مجهولة إلى Nuclei أو engine آخر كبديل صامت.

## أول سيناريو
- نعيد استخدام `aegis-platform/e2e/fixtures/bac-target/app.py`؛ لا هدف جديد للنسخة الأولى.
- المصدر يحتوي حسابين ببيانات صناعية ومساري `/vulnerable/orders/{order_id}` و`/fixed/orders/{order_id}`.
- طلب مالك المورد مرجع إيجابي؛ طلب حساب آخر للمورد تجربة الصلاحيات.
- الحالة الضعيفة تتوقع إرجاع مورد لا يملكه الحساب؛ المصححة تتوقع المنع وعدم إرجاع محتواه.
- التحقق يفحص هوية المورد ومالكه وtenant، وليس HTTP 200 وحده.
- نفس الحالة تعاد بعد reset أو تشغيل instance نظيف؛ لا endpoint reset موجود لهذا الهدف حتى نثبت طريقة تشغيله.
- ربط المنهجية: `WSTG-v42-ATHZ-04`، من كتالوج المشروع الحالي.
- الحالة الثانية لاحقًا تستعمل `multi-tenant-target/app.py`؛ ليست شرطًا لإغلاق أول إثبات.
- قراءة مصدر fixture ليست تشغيلًا له أو إثباتًا لنتيجة Burp.

## P0 — تجهيز التنفيذ
**المهام:** تثبيت قاعدة Git، فحص PRs والأعمال الجارية، قراءة حوكمة المستودع، تثبيت نقاط الدمج، إعداد manifest وخطوات قبول.
**المكان:** clone مستقل ووثائق الفرع الحالي.
**المخرج:** خريطة تنفيذ قابلة للمراجعة، عقود مقترحة، fixture مختار، checkpoint محفوظ في Git.
**القبول:** ملفات إعادة الاستخدام موجودة، مرجع الكتالوج صحيح، JSON صالح، diff نظيف، ولا تعديل لتطبيق أو workflow أو compose إنتاج.

## P1 — عقد جاهزية المختبر
**المكان:** خدمة مقترحة `backend/fastapi_app/services/web_labs_preparation.py` وrouter مقترح `routers/web_labs.py` مع تسجيل محدود في `main.py`.
**المهام:** input strict، تحقق project/asset access عبر الخدمات الحالية، مصدر مختبر معروف، متطلبات الجلسات، readiness سببية بالعربية.
**المخرج:** preview منظم يحدد ما يمكن تشغيله وما ينقصه؛ لا Scan أو Celery dispatch أو تعديل AssetAuthorization أو ProviderApproval.
**التكامل:** Assessment Launcher وcapability plan وWSTG catalog وإعداد مزود Burp الحالي.
**الاختبارات المطلوبة:** أصل مشروع آخر، صلاحية منتهية، مزود غير متاح، fixture غير معروف، وعدم أي write/dispatch من preview.
**نقطة الإغلاق:** عقود واختبارات backend ناجحة على الفرع؛ تقرير عربي بالنتيجة ثم توقف.

## P2 — توافق Burp الحقيقي
**المكان:** توسعة `burp_mcp_gateway.py` وtransport adapter مقترح؛ capability/dispatch/profile integration في المسار القائم.
**المهام:** discovery للنقل والأدوات، التوافق مع lifecycle المزود، بيانات edition/version الحقيقية، runner packaging مثبت.
**المخرج:** استدعاء محدود من Burp الفعلي إلى fixture؛ mock server يبقى لاختبارات العقد ولا يمثل اتصالًا حيًا.
**الاختبارات المطلوبة:** tool schema mismatch، provider error/isError، مهلة، endpoint غير جاهز، عدم fallback صامت، وعدم dispatch عند missing prerequisites.
**قيد التصميم:** Java/Burp runtime لم يثبت في kali_web؛ نختار runtime مناسبًا بعد inventory، ولا نفترض GUI أو Pro أو أدوات غير متاحة.
**نقطة الإغلاق:** دليل conformance حي منفصل عن اختبارات المزود التجريبي؛ تقرير ثم توقف.

## P3 — جلسات وطلبات ودليل
**المكان:** عمليات محددة في البوابة، request builder، مدير credential الحالي، hooks داخل worker القائم.
**المهام:** baseline، تغيير field محدد، session A/B، مقارنة response semantics، event لكل خطوة.
**المخرج:** طلبات متعددة الخطوات مرتبطة بمحاولة وبالأصل والعقد ونسخة الهدف؛ artifact مقيد ونسخة عرض محجوبة.
**الاختبارات المطلوبة:** عدم اختلاط identities أو history، إلغاء أثناء التنفيذ، حدود الطلبات، إعادة محاولة بعد رد ضائع دون تكرار أعمى.
**قيد التصميم:** provider token ليس target session؛ single-ref credential modes الحالية تحتاج معالجة صريحة للهوية المتعددة.
**قيد الموثوقية:** claim/commit قصيران حول الاتصال؛ لا إبقاء locks واسعة أثناء اتصال الشبكة؛ لا ضمان exactly-once خارجي دون إثبات.
**نقطة الإغلاق:** خطوات مرتبطة بدليل فعلي، مع استعادة أو حكم غير حاسم واضح؛ تقرير ثم توقف.

## P4 — حكم اللاب والشرح العربي
**المكان:** verifier مقترح داخل services، وتوسعة Evidence الحالية وعقود العرض والتقرير.
**المهام:** فحص ملكية المورد، الضابط المصحح، ربط verdict بـinstance revision، تحويل الأحداث إلى شرح عربي.
**المخرج:** فصل observation وconfirmed finding وsolved lab وmethodology completion.
**الاختبارات المطلوبة:** الحالة الضعيفة/المصححة، content ناقص، evidence لا يخص المحاولة، instance جديد، وحجب الأسرار من العرض.
**بطاقة كل خطوة:** الهدف، السبب، المتطلبات، المدخلات، الإجراء، المتوقع، الفعلي، التفسير، الدليل، الحالة، الحدود، التالي.
**اللغة:** العربية للشرح؛ HTTP/JSON/code كما هي وباتجاه LTR؛ الفرضية ليست نتيجة تنفيذ.
**نقطة الإغلاق:** حكم صحيح على positive وnegative، ودليل قابل للإعادة وتقرير عربي؛ تقرير ثم توقف.

## P5 — دورة حياة الهدف وتجربة الواجهة
**المكان:** إعداد مختبر مستقل وservice reset محدود؛ صفحة WebLabs مقترحة فوق frontend الحالي.
**المهام:** تشغيل/reset/cleanup معروف، fixture revision، ربط صفحة اللاب بـWSTG وEvidence وprogress الحالية.
**المخرج:** تشغيل موجه دون معرفات يدوية؛ targets محلية عند الطلب، ومسار Academy بمراجع instances المستضافة.
**الاختبارات المطلوبة:** fresh state، expiry، عدم وراثة Solved، صحة RTL/LTR، وربط جميع الخطوات بالمحاولة.
**قيد المصدر:** لا افتراض بأن Academy يوفر حزمة عامة لتنزيل backend اللابات؛ المحلي يستخدم المصدر الرسمي أو fixture الشركة.
**نقطة الإغلاق:** مسار واجهة كامل بالتحقق، ثم تقرير وتوقف.

## P6 — قياس وإصدار
**المكان:** tests/E2E/CI الموجودة وتقارير القياس؛ workflow إضافي فقط للفجوة غير المغطاة.
**المهام:** recipes، held-out، patched twins، التكلفة والتدخلات، حالات قطع الاتصال، مقارنة baseline.
**المخرج:** نتائج فعلية على SHA وصور معلومة، لا نسبة تحسن مخترعة أو تعميم من مختبر واحد.
**القبول:** كل نتيجة مرتبطة بدليل؛ الحالات المعلنة تعاد؛ failures/inconclusive تظهر؛ PR محدث وCI المطلوب ناجح قبل الدمج.
**الإصدار:** PR إلى main وفق Required CI Governance؛ بعد الدمج تثبت checks على merged SHA، ولا نشر تلقائي من فرع المختبر.
**نقطة الإغلاق:** قدرة معلنة بنطاق معلوم وتقرير عربي نهائي.

## العقود المقترحة التي لم تنفذ بعد
- Preview input: `project_id, asset_id, lab_definition_id, credential_refs, depth`.
- Preview output: `contract_version, project_ref, asset_ref, lab_ref, fixture_revision, methodology_refs, execution_ready, blockers, requirements, supported_operations, capabilities`.
- blocker: `code, message_ar, requirement_ref, observed_state, suggested_action_ar`.
- step event: `attempt_ref, step_ref, action_ref, target_ref, identity_ref, observed_at, expected_ref, observation_refs, verdict, evidence_refs, explanation_key`.
- مصادقة HTTP الحالية تستمر؛ input preview لا يمنح authority ولا يقبل shell أو credentials خامًا.
- إنشاء الأصل يستخدم Launcher القائم؛ إنشاء Scan فقط عبر capability execution؛ عقد المحاولة لا يعيد تعريف مصدر السلطة.

## بوابة المرحلة التالية
عند «تابع»: نعيد فحص main وPRs والملفات المتداخلة، ونحدّث فرعنا بتغيير غير مدمر إذا لزم، ثم ننفذ P1 فقط.
لا نستعمل نجاح CI لنسخة قديمة كإثبات للنسخة الجديدة. الحالة الخضراء لم تُفترض على base الحالي أثناء CI الجاري.
التفاصيل الآلية والمسارات ومعايير القبول: `docs/web-labs/preparation-v1.json`.
سجل الاستئناف: `docs/WEB_LABS_CHECKPOINT.md`.

## تحديث التنفيذ — P1

نفذ عقد المعاينة وخدمته واختباراته وربطه بالتطبيق وCI الحالي. التفاصيل وشرح كل فحص موجودة في [عقد جاهزية المختبر بالعربية](WEB_LABS_READINESS_CONTRACT_AR.md). نجح 63 اختبارًا في بيئة PostgreSQL/Redis منفصلة؛ لا هدف حي أو نشر أو حل لاب ضمن P1. المراحل P2–P6 ما زالت لاحقة، وتتوقف المتابعة حتى يرسل المستخدم «تابع».
