# Web Labs — نقطة استئناف

- المرحلة الحالية: P2 جزئية؛ النقل والربط واختباراتهما منفذة، وإغلاق التشغيل الحي لم يتحقق.
- P1: commit `88d421529ebf5690a3a4203bf0ade8cc7b54c567`، PR #314؛ آخر قراءة 51 SUCCESS و1 SKIPPED، وبوابة الحوكمة المطلوبة SUCCESS.
- فرع P2: `codex/burp-mcp-transport-20261003`، مبني على P1 دون تعديل فرع P1.
- working copy: `/home/aegisadmin/aegis-burp-transport-development` على aegis-prod.
- main وقت إعادة الفحص: `f863787569a7fcea85f5318f559bdb2890084299`.
- checkout الإنتاج: `fc715f5849dcd5e7d206540955991e0d6d10ff00`، نظيف؛ لا نشر أو تعديل DB الإنتاج.
- التفاصيل: [عقد النقل والتكامل العربي](WEB_LABS_BURP_TRANSPORT_AR.md)، [مصادر التشغيل وبصماته](WEB_LABS_BURP_PROVENANCE.json).
- التالي عند «تابع»: استكمال P2 وإثبات Burp الحي، ثم تقرير وتوقف؛ لا يبدأ P3 قبل ذلك.

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

## دليل التشغيل الموجود وحدوده

- Burp Desktop JAR 2026.9: checksum المورد متطابق؛ CLI يعلن `2026.9-53998 Burp Suite`.
- BApp الرسمي 1.3.0: حمل من المورد؛ manifest الخاص بالـJAR المستخرج يعلن 1.3.0 وبصمته محفوظة. لا ندعي تحقق توقيع/SBOM أو قبول مزود إنتاجي من هذا التحميل.
- Java Temurin 21.0.12.1 portable؛ source image digest محفوظ. ليس تثبيت Java عالميًا.
- Burp شغل على DISPLAY=:0 مع data/profile منفصلين وحد heap 1 GiB؛ نافذة Burp موجودة.
- الهدف المحلي يعمل في الحاوية `aegis-burp-p2-target`، bind على `127.0.0.1:18081`، direct health يعيد علامة bac-target.
- لم يكن منفذ MCP 9876 مستمعًا عند الفحص. CLI الحي خرج 1، `transport_probe_passed=false` و`error_code=transport_failed`.
- لذلك لا initialization/discovery من Burp الحقيقي مثبت، ولا طلب HTTP عبر Burp مثبت، ولا edition مختارة موثقة، ولا حل لاب.
- أدوات التحكم المتاحة هنا لا تقدم التحكم في واجهة Burp الأصلية؛ يحتاج إعداد الجلسة وتحميل الإضافة إجراءً من المستخدم.

## الاستئناف العملي

1. على سطح مكتب Ubuntu المفتوح: أكمل إعداد Burp بنسخة Community للمخبر أو ترخيص الشركة الفعلي، ثم جلسة/مشروع مؤقت.
2. Extensions → Add → Java، اختر `/home/aegisadmin/aegis-burp-lab-runtime/burp-mcp-all.jar`.
3. من تبويب MCP تأكد أن الخادم enabled على 127.0.0.1:9876، واقصر سماح HTTP على `127.0.0.1:18081`؛ لا تعطّل الموافقة لكل الأهداف.
4. أرسل «تابع». نعيد التحقق من هوية العملية وport وfixture ونفذ CLI مرة واحدة، ونسجل النسخة والأدوات والرد المحجوب.
5. عند النجاح، نفصل إثبات conformance المحلي عن موافقة المزود والتغليف والنشر. localhost داخل scanner container ليس localhost المضيف؛ بوابة runner packaging ما زالت تحتاج إثبات المسار.
6. لا نستبدل Burp الحقيقي بخادم الاختبارات، ولا ننشئ موافقة مزود وهمية في الإنتاج.

## القيود التي تنتقل إلى P3

حسابا Alice/Bob هما أسرار الهدف، منفصلان عن provider token. البوابة الحالية تمسك locks خلال الاتصال؛ claim/commit والتزامن والاسترجاع بعد رد ضائع ما زالت عمل P3. حراسة الإلغاء قبل وبعد الطلب لا تثبت قطعه أثناء وصوله إلى Burp. علامة /health لا تربط revision الحية أو تثبت صلاحيات المورد. الحكم الضعيف/المصحح وشرح خطوات المحاولة ينفذان في P3/P4.
