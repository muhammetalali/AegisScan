# Web Labs — نقطة استئناف

- المرحلة الحالية: P2؛ التغليف المرشح والمسار الحي داخل namespace معزول مطابق لنمط scanner_egress مثبتان. 174 اختبارًا سابقًا و14 اختبار موثوقية إضافيًا ناجحة؛ CI على الرأس المصحح قيد التحقق. لا نشر أو قبول مزود إنتاجي.
- P1: commit `88d421529ebf5690a3a4203bf0ade8cc7b54c567`، PR #314؛ آخر قراءة 51 SUCCESS و1 SKIPPED، وبوابة الحوكمة المطلوبة SUCCESS.
- فرع P2: `codex/burp-mcp-transport-20261003`، مبني على P1 دون تعديل فرع P1.
- working copy: `/home/aegisadmin/aegis-burp-transport-development` على aegis-prod.
- main وقت إعادة الفحص: `f863787569a7fcea85f5318f559bdb2890084299`.
- checkout الإنتاج: `fc715f5849dcd5e7d206540955991e0d6d10ff00`، نظيف؛ لا نشر أو تعديل DB الإنتاج.
- التفاصيل: [عقد النقل والتكامل العربي](WEB_LABS_BURP_TRANSPORT_AR.md)، [مصادر التشغيل وبصماته](WEB_LABS_BURP_PROVENANCE.json).
- التالي: إغلاق CI على أحدث commit ثم تقرير P2 وتوقف قبل P3. تفعيل المزود/النشر يحتاج بوابة التشغيل الحالية، ولا يستنتج من الدليل المختبري.

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

## التغليف والمسار المحكوم — استئناف P2

- CI على b8df2f9f: 61 مسارًا مسترجعًا، 59 SUCCESS و2 FAILURE. Domain Contract كشف أن قائمة مهام طابور scanner في الاختبار لم تتضمن مهمة Burp؛ الحوكمة المطلوبة تبعت هذا الفشل. صححت القائمة الصارمة دون حذف التحقق؛ مجموعة الموثوقية كاملة 14 PASS في 49.27 ثانية.
- العامل الإنتاجي الحالي يشارك namespace مع scanner_egress. أضفت overlay اختياريًا burp-runtime بنفس النمط، بلا host networking أو منافذ منشورة، non-root وread-only وcap-drop ALL وno-new-privileges، وحدود موارد. الصورة تغلف JAR المورد والإضافة ذات البصمة المسجلة؛ profile وXauthority خارج الصورة.
- بُنيت صورة عامل مرشحة على image ID العامل الإنتاجي المنزوع الأدوات القديمة، مع تضمين fastapi_app/scripts. تطابقت بصمات خمس وحدات حرجة داخل الصورة مع الفرع؛ لا source mount في الفحص. هذا ليس rebuild كامل لصورة release.
- من الصورة المرشحة داخل namespace معزول بنمط الإنتاج: initialize/discovery ومخطط مثبت وGET /health نجحت، HTTP200 وعلامة bac-target، exit0، retry0. فشل أول طلب بسبب موافقة Burp الجديدة بعد إعادة التشغيل؛ سُمح للعنوان:المنفذ المحدد فقط ثم نجحت جلسة جديدة. لا ادعاء أن الموافقة تستمر عبر restart.
- fixture خاص منفصل يعيد200 للحاوية الخارجية، لكنه timeout من namespace العامل تحت سياسة egress؛ MCP غير متاح للحاوية الخارجية، ومستمعه loopback فقط. بقيت قواعد private-range drop دون توسعة.
- docker compose config للbase+production+overlay نجح، وأضيف تحقق دائم للعقد إلى workflow Burp الحالي مع اختبار موثوقية الطابور.
- Community مشروع مؤقت عبر GUI، restart=no، والتشغيل تحت إشراف. الملف README يشرح إعداد profile/الإضافة/الموافقة دون xhost+، وoverride loopback HTTP اختياري وفقط scanner/API؛ لا queue أو auth أو vault جديد.
- source metadata ونتائج الاختبار والعزل وصور candidate في WEB_LABS_BURP_PROVENANCE.json. lab_solved=false وlive_fixture_revision_verified=false؛ لا Findings أو provider approval في DB الإنتاج.


## بوابة صورة release الكاملة — استئناف 2026-10-03

- على الرأس 80b29e5361af: جميع مسارات CI الـ61 المسترجعة ناجحة. الفحوص السابقة 174 PASS و14 PASS موثوقية، دون إعادة احتساب المجموعة الفرعية.
- أُعيد تشغيل Burp في namespace العامل؛ جلسة جديدة بموافقة محددة للعنوان:المنفذ أعادت HTTP200 وعلامة bac-target من صورة candidate دون source mount.
- فحص candidate مستقل offline أكد هوية تطبيق Celery الحقيقي، ارتباط المهمة به، والطابور المحلول scanners وmax_retries=0 وUID10001؛ الأدوات القديمة وحزمة semgrep والقوالب و/app/.env غائبة.
- محاولتا rebuild محلي كامل لصورة production-no-legacy-recon مع تقاعد الأدوات الأربعة فشلتا. الأولى DNS لمورد Docker، والثانية connection reset في تنزيل الطبقات واعتماديات Go. لم تتكون صورة release ولم ينفذ فاحصها؛ لا نحول دليل candidate إلى نجاح rebuild كامل.
- أُضيفت بوابة CI مستقلة إلى Burp MCP Gateway Reality: checkout للرأس المحدد، build بلا cache بالأعلام الأربعة، ثم فحص صورة offline بلا network أو source mounts مع تطابق بصمات الوحدات الخمس وrequirements.txt، وهوية منتج Burp والطابور الفعلي. تحفظ JSON proof مستقلًا. نتيجة هذا التشغيل لم تثبت بعد عند كتابة هذا القسم.
- لا يزال lab_solved=false وlive_fixture_revision_verified=false. لم ينفذ P3/P4 ولم يسجل مزود في الإنتاج أو يدمج أو ينشر هذا الفرع.

---

## Current superseding checkpoint — 2026-10-04

The historical checkpoint above is retained as execution lineage. It is superseded by the verified state below.

- Canonical release branch: `main`.
- P6 PR #319 merged as `a3ebfc58bab98cdef2947c20b17d0501e3869c90`.
- Exact P6 source SHA: `21b9612ecbcf11cdcd8efd0c4bff649f27a5868a`.
- Live P6 acceptance: `PASS`.
- Measurement SHA-256: `0b5e47e3eb4d7008e3dd5b06f690f8332169c34cac77b88ba4bb49515c38f2ec`.
- Closeout SHA-256: `8cc0bc2062c45acfdc6dd3197dde05506570c0ef616245fcb36801da7629073b`.
- Five sealed P6 cases passed with zero human interventions:
  - vulnerable baseline/held-out → vulnerable + finding + solved;
  - patched baseline/held-out → not vulnerable + no finding + unsolved;
  - disconnect held-out → indeterminate + no finding + unsolved.
- No P6 target/runtime/control container remained after closeout.
- Fresh-main on the P6 merge SHA completed 28/28 required workflows successfully.
- Current independent branch: `codex/web-labs-ux-closeout-20261004`.
- This candidate closes the missing P5 guided UX and stale P0–P6 documentation.
- Browser code receives no Docker/lifecycle authority. It uses a read-only, tenant-scoped credential metadata projection, readiness preview, and the existing governed capability execution path.
- Frontend production build: PASS.
- Frontend ESLint with zero warnings: PASS.
- UI contract audit: PASS.
- i18n audit: REVIEW only for pre-existing pages; the new Web Labs page is not listed as an untranslated surface.
- Backend PostgreSQL isolated regression: 87 passed.
- Post-hardening credential tenant-isolation regression: 36 passed.
- Credential option projection exposes only UUID/name/kind/identity/version for active, same-origin, project-scoped credentials and requires active tenant membership.
- No production runtime or production database was changed during candidate validation.
- Next gate: exact-head PR CI for the UX closeout. After merge, verify new main and then perform exact-SHA production promotion/release.
