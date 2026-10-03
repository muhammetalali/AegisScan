# Web Labs — نقطة استئناف

- المرحلة الحالية: P2؛ الاتصال الحي المحلي مثبت، وتصحيحات توافق المزود والـCI اجتازت 174 اختبارًا محليًا. CI الجديد سيؤخذ من أحدث رأس PR #315. بوابة النشر الإنتاجي لم تغلق.
- P1: commit `88d421529ebf5690a3a4203bf0ade8cc7b54c567`، PR #314؛ آخر قراءة 51 SUCCESS و1 SKIPPED، وبوابة الحوكمة المطلوبة SUCCESS.
- فرع P2: `codex/burp-mcp-transport-20261003`، مبني على P1 دون تعديل فرع P1.
- working copy: `/home/aegisadmin/aegis-burp-transport-development` على aegis-prod.
- main وقت إعادة الفحص: `f863787569a7fcea85f5318f559bdb2890084299`.
- checkout الإنتاج: `fc715f5849dcd5e7d206540955991e0d6d10ff00`، نظيف؛ لا نشر أو تعديل DB الإنتاج.
- التفاصيل: [عقد النقل والتكامل العربي](WEB_LABS_BURP_TRANSPORT_AR.md)، [مصادر التشغيل وبصماته](WEB_LABS_BURP_PROVENANCE.json).
- التالي عند «تابع»: إغلاق CI على أحدث commit وتحديد تغليف/مسار المزود داخل topology النشر؛ ثم تقرير وتوقف قبل P3.

## ما نعيد استخدامه

Burp gateway وProviderApprovalDecision وAssetAuthorization وcanonical capability execution وAssessment Launcher وCredential Vault وBrowser Worker وEvidence Qualification وFinding Confirmation وWSTG وfixture الصلاحيات الحالي. لا queue أو scheduler أو منظومة صلاحيات أو أسرار جديدة، ولا migration في P2.

## المنفذ في P2

1. MCP SSE lifecycle: endpoint، initialize، initialized، tools/list، مخطط HTTP/1، tools/call.
2. عملية `burp.http_request` محدودة إلى GET `/health` مجهول الهوية ومبني داخل الخادم.
3. capability `burp.mcp.gateway`، engine `burp-mcp`، profile `web`، dispatch صريح على SCANNER_QUEUE.
4. عقد تنفيذ مربوط بالأصل والمشروع والمستخدم والتفويض وقرار المزود الحالي، وreplay لسجل Scan دون dispatch آخر.
5. نتيجة وأدلة مؤهلة محجوبة؛ `lab_solved=false` و`live_fixture_revision_verified=false`.
6. المعاينة تعتبر HTTP الحالي anonymous probe فقط؛ `web.burp-labs` ما زال غير مسجل.
7. مخطط نوع الأصل لا يعلن جاهزية Burp بمجرد التسجيل؛ يميز متطلبات المزود والتشغيل.
8. توسعة workflow البوابة الحالي، وCLI لإثبات التشغيل على loopback، وlauncher يتحقق من SHA المورد ويعزل data/profile.

## التحقق المحلي

- تشغيل أساسي: **139 PASS**، صفر failed/errors/skipped؛ PostgreSQL وRedis منفصلان وشبكة داخلية ومصدر read-only.
- توزيع التشغيل: SSE 28، execution 22، gateway 10، preview 32، governed contract 4، Evidence Qualification 16، profile 4، Launcher 15، foundation 8.
- بعد مراجعة أنواع manifest: **4 PASS إضافية** لرفض نقل/بصمة malformed مع تفسير عربي؛ مجموع الحالات المختلفة المتحققة 143، عبر تشغيلين.
- خطأ بيانات النقل غير الصالحة ظهر أثناء هذا الاختبار وصحح؛ سجل التشغيل الفاشل محفوظ مع سجل النجاح.
- compile وbash syntax و`git diff --check`: ناجحة.
- JUnit والسجلات محفوظة خارج الشجرة في `/home/aegisadmin/aegis-web-labs-checkpoints/p2-20261003`.
- CI الخاص بـP2 يؤخذ من طلب المراجعة؛ النجاح المحلي لا ينسب إلى CI أو Burp حي.

## دليل التشغيل السابق وحدوده — قبل الاستئناف الحي

- Burp Desktop JAR 2026.9: checksum المورد متطابق؛ CLI يعلن `2026.9-53998 Burp Suite`.
- BApp الرسمي 1.3.0: حمل من المورد؛ manifest الخاص بالـJAR المستخرج يعلن 1.3.0 وبصمته محفوظة. لا ندعي تحقق توقيع/SBOM أو قبول مزود إنتاجي من هذا التحميل.
- Java Temurin 21.0.12.1 portable؛ source image digest محفوظ. ليس تثبيت Java عالميًا.
- Burp شغل على DISPLAY=:0 مع data/profile منفصلين وحد heap 1 GiB؛ نافذة Burp موجودة.
- الهدف المحلي يعمل في الحاوية `aegis-burp-p2-target`، bind على `127.0.0.1:18081`، direct health يعيد علامة bac-target.
- لم يكن منفذ MCP 9876 مستمعًا عند الفحص. CLI الحي خرج 1، `transport_probe_passed=false` و`error_code=transport_failed`.
- لذلك لا initialization/discovery من Burp الحقيقي مثبت، ولا طلب HTTP عبر Burp مثبت، ولا edition مختارة موثقة، ولا حل لاب.
- هذا المانع السابق تجاوزناه في الاستئناف: حملت الإضافة على Ubuntu وتحقق منفذ MCP والطلب الحي.

## خطوات التجهيز السابقة — مكتملة محليًا في الاستئناف

1. على سطح مكتب Ubuntu المفتوح: أكمل إعداد Burp بنسخة Community للمخبر أو ترخيص الشركة الفعلي، ثم جلسة/مشروع مؤقت.
2. Extensions → Add → Java، اختر `/home/aegisadmin/aegis-burp-lab-runtime/burp-mcp-all.jar`.
3. من تبويب MCP تأكد أن الخادم enabled على 127.0.0.1:9876، واقصر سماح HTTP على `127.0.0.1:18081`؛ لا تعطّل الموافقة لكل الأهداف.
4. أرسل «تابع». نعيد التحقق من هوية العملية وport وfixture ونفذ CLI مرة واحدة، ونسجل النسخة والأدوات والرد المحجوب.
5. عند النجاح، نفصل إثبات conformance المحلي عن موافقة المزود والتغليف والنشر. localhost داخل scanner container ليس localhost المضيف؛ بوابة runner packaging ما زالت تحتاج إثبات المسار.
6. لا نستبدل Burp الحقيقي بخادم الاختبارات، ولا ننشئ موافقة مزود وهمية في الإنتاج.

## القيود التي تنتقل إلى P3

حسابا Alice/Bob هما أسرار الهدف، منفصلان عن provider token. البوابة الحالية تمسك locks خلال الاتصال؛ claim/commit والتزامن والاسترجاع بعد رد ضائع ما زالت عمل P3. حراسة الإلغاء قبل وبعد الطلب لا تثبت قطعه أثناء وصوله إلى Burp. علامة /health لا تربط revision الحية أو تثبت صلاحيات المورد. الحكم الضعيف/المصحح وشرح خطوات المحاولة ينفذان في P3/P4.


## نتيجة الاستئناف الحي — الحالة الحالية

- حملت الإضافة الرسمية داخل Burp Community 2026.9، وport 9876 listening للعملية نفسها. السماح التلقائي محصور في 127.0.0.1:18081؛ موافقات بقية أهداف HTTP وبيانات المشروع ما زالت مطلوبة.
- صححت عنوان SSE إلى الجذر `/`، وطبعـت message endpoint للجذر، ودعمت غلاف Montoya للرد مع رفض التبتر أو الفواصل الملتبسة أو طلب مختلف عن /health.
- فحص حي pinned schema: HTTP200 وfixture=bac-target وexit=0، transport_probe_passed=true، retry_count=0. lab_solved=false وlive_fixture_revision_verified=false.
- فحص مستقل من image ID عامل scanner نجح بمصدر التطوير read-only وnetwork host وread-only root وcap-drop ALL. يثبت المسار المختبري؛ لا يثبت topology الإنتاج أو تغليف مصدر P2 في صورة العامل.
- صححت tool-manifest.json ليطابق profile policy، واختبار production readiness ليشترط Burp وحده pending للويب، دون السماح بأي قدرة أخرى غير جاهزة.
- التشغيل النهائي: 174 PASS، صفر failed/errors/skipped، 280.30 ثانية. يشمل مجموعات P2 وP1 والتأسيسية، Production Runtime imports وKali profile contract. JUnit وبصمته مسجلان.
- التشغيل السابق: 161 PASS و4 FAIL من غياب networkx في صورة الاختبار. جهزت networkx==3.6.1 مؤقتًا داخل حاوية الاختبار؛ لم أثبته في الإنتاج. تم تجاوز مهلة تنزيل ومشكلة ملكية مجلد wheel باستخدام UID المضيف، والسجلات السابقة محفوظة.
- نسخة الإنتاج أعيد فحصها: fc715f58، working tree نظيف. لم نسجل مزودًا في DB الإنتاج أو ندمج أو ننشر.
- التالي: نتائج CI على أحدث رأس PR #315، ثم إغلاق مسار endpoint المحكوم والتغليف الإنتاجي قبل ادعاء جاهزية العامل الحالي. P3/P4 لم يبدآ.
