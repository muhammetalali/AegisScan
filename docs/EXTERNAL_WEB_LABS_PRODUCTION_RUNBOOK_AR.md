# AegisScan — متطلبات تشغيل مختبرات الويب الخارجية عبر Burp MCP

**النوع:** خطة إنتاج، ومرجع قبول، ولا تمنح بذاتها إذنًا بفتح بوابة التنفيذ.
**النطاق الحالي:** Ubuntu aegis-prod؛ AegisScan؛ مشروع mi-kali؛ تطبيق https://challenge.cyberpedia.site/ فقط.
**قاعدة الاختبار:** قواعد صاحب المختبر: التطبيق فقط؛ لا تعطيل خدمة، ولا استهداف خادم أو بنية تحتية، ولا تخمين جماعي أو خروج عن النطاق.
**إصدار الإنتاج الذي فُحص:** da21cfa030b0370a9c602a41ede6c1d8b32740ce.

## 1. نطاق العمل ومبدأ عدم التكرار

المسار المحكوم الملزم: Actor → Organization/Tenant → Project → Asset → latest AssetAuthorization → ProviderApprovalDecision → Capability → Burp Session → Scan / LabAttempt → Evidence → Verification → Report → Audit.

استعمل الخدمات الموجودة: FastAPI/Django، TenantProject، AssetAuthorization، ProviderApprovalDecision، Credential Vault، canonical capability execution، Celery/Scanner Queue، Burp MCP Gateway، WebLabLifecycle، LabAttempt، Evidence Qualification، WSTG، Findings، UI وتقارير AegisScan. لا تنشئ نظام هوية أو Queue أو Vault أو Scanner آخر.

افصل بين حالات: Source present؛ Runtime available؛ Integration verified؛ Governance approved؛ Execution tested؛ Lab solved؛ Independently validated؛ Production accepted. لا يجوز الاستنتاج من مرحلة إلى أخرى دون دليل مستقل.

## 2. الوضع الحقيقي عند الاستئناف

| المكوّن | النتيجة المثبتة | القيد |
|---|---|---|
| Ubuntu Production | Ready، DB وRedis OK، شجرة مصدر نظيفة | ليس حكمًا على المختبر |
| Burp Community 2026.9 | Java تعمل؛ TCP loopback 8080/9876 | لا دليل أنه يعمل بلا مشغل GUI |
| BApp 1.3.0 | SSE init/tools/list، أداة send_http1_request موجودة | لا تعادل موافقة مؤسسة |
| Unix Socket | FastAPI → MCP أعاد HTTP 200/SSE | لم تُنشأ جلسة محكومة |
| Cyberpedia | أصلان مفوّضان بنفس URL | يجب تعيين asset_id واحد صراحة |
| Enterprise Provider | لا قرار Burp موثوق؛ لا BurpMCPSession | التنفيذ الرسمي محجوب |
| Credential Vault | صفر مراجع هوية فعالة مطابقة للنطاق | لا تفترض وجود حساب |
| Web Labs | BAC محلي مثبت، P6 مقبول تاريخيًا | لا يتيح تنفيذ OTP خارجي |
| Cyberpedia solved | غير مثبت؛ لا صورة نجاح | يُمنع إعلان إنجاز |

## 3. متطلبات صلاحيات وأصول ومزوّد Burp

1. حساب فعلي بجلسة مصادقة تخص Project Owner/Admin، وعضوية حوكمة Enterprise Owner/Admin/Manager نشطة. root في Ubuntu لا يعني مستخدم الويب؛ لا تستخدم cookies محفوظة أو DB impersonation لتزوير موافقة.
2. مشروع نشط، TenantProject سليم وفريد، أصل Website/API واحد محدد، أحدث AssetAuthorization صالح ويطابق لقطة الهدف وحالة إعداد الأصل. لا تدمج الأصلين أو تحذف أحدهما قبل فحص علاقات المراجع والأدلة.
3. قبول Burp عبر واجهة Provider Approval الرسمية ومن حساب المالك؛ يجب أن تعيد evaluate قيمة allowed=true وتثبت latest version والـmanifest. أحدث قرار يلغي الأقدم.
4. manifest لمزوّد Burp الحقيقي يصف mcp_transport=sse-unix، mcp_endpoint=http://127.0.0.1:9876/، وربط burp.http_request إلى send_http1_request. اربط مخطط الأداة وبصمات إصدار المزود والـruntime.
5. سلسلة توريد مثبتة: مصدر PortSwigger الأصلي، vendor artifact SHA256، SBOM حقيقي، provenance حقيقي، تحقق تشفيري حقيقي للتوقيع وهوية الموقّع، إثبات البناء المعاد عند ادعائه، وتقييم CVEs/التحديثات. وجود BappSignature.sig لا يكفي لإثبات توقيع موثوق؛ لا تضبط signature_verified أو ci_reproducibility إلى true دون إثبات.
6. status=approved وtrust_state=trusted شرط بوابة التنفيذ الحالية. restricted/experimental لا يكفي لتجاوز هذا الشرط. لا تغير السياسة لمجرد تسهيل المختبر.
7. خزنة المشروع تحفظ مراجع هويات الهدف منفصلة عن اعتماد المزود. لا تطبع أو تخزن كلمات مرور أو OTP أو Cookie أو API Token في المستودع أو سجلات الأوامر أو الأدلة العامة.

## 4. المتطلبات التشغيلية والشبكية

- Burp MCP يستمع على loopback 127.0.0.1:9876 فقط، والاتصال من FastAPI والعامل عبر Unix Socket المسموح. لا تعرض 8080/9876 على الإنترنت.
- لا تعطّل موافقات Burp لكل أهداف HTTP. وافق على الهدف المصرح المحدد فقط، وأعد تقييم السماح بعد restart.
- حافظ على scanner_egress ودفاعات SSRF/DNS rebinding وحظر الوصول للبنية الداخلية، مع منع target host/path غير المصرح. لا تستخدم --network host أو privileged كوسيلة تشغيل عامة.
- مقترح ميزانية لكل تجربة: 10 طلبات بالدقيقة، 25 طلبًا بالمحاولة، timeout عادي 15 ثانية وحد أقصى 30، بدون retry صامت للـPOST؛ يحتاج هذا إلى تفعيل وتوثيق فعلي قبل الادعاء.
- ترفض redirects إلى origin مختلف، والأهداف غير المسجلة، وكل target input حر من المتصفح إلى التنفيذ. يجب مطابقة hostname/port وقرار التفويض قبل كل خطوة.
- Burp Community ليس Burp Professional Scanner؛ لا تَعِد بفحص نشط آلي لكل نوع مختبر دون التحقق من القدرات الفعلية والترخيص.

## 5. ما يجب إضافته للمختبرات المتعددة دون بناء محرك جديد

**Lab Definition Registry:** تعريف مصدري بنسخة وSHA وscope/ROE وتوقعات ومخاطر وميزانية وعدد خطوات وشروط إيقاف ومعيار نجاح. catalog metadata وحده لا يساوي قابلية حل.

**Bounded Step Runner:** توسيع Scan/Attempt/Capability/Burp الحالي ليستوعب تسلسل خطوات مصادق عليها. يحدد method/path/body schema وallowlist؛ يرفض arbitrary raw HTTP في الواجهة؛ ويمتلك timeout/rate budget وidempotency وclaim/commit دون تكرار POST بعد رد ضائع.

**Authentication / MFA:** آلة حالات: anonymous → primary authentication → OTP challenge → OTP verified → protected access. عزل كل cookie jar حسب الهوية، الربط بـCSRF وسياق الجلسة، والتحقق من enforcement على الخادم لا مجرد redirect العميل.

**Other lab classes:** تحتاج وصفات منفصلة لـBAC/IDOR، SQLi، XSS، CSRF، SSRF، file upload، business logic/race، API/GraphQL/WebSocket، session/protocol/cache. كل وصفة يجب أن تعلن target scope والعمليات والضوابط السلبية والعينات المخالفة والمصححة ومعايير الإثبات، وألا تنفذ نشاطًا غير مصرح.

**Evidence & verification:** كل خطوة تربط Attempt/Scan ID، وإصدار التعريف، وبصمة الطلب/الرد المحجوب، والتاريخ والهوية ونتيجة التأهيل، ثم حكم solved/not_solved/indeterminate؛ وليس مجرد HTTP 200. screenshot حقيقي بعد تحقق النجاح، دون تعديل أو إعادة تصنيع.

**UI & operations:** إعادة استخدام صفحات Web Labs وAssessment Launcher وEnterprise Security؛ عرض Scope، أصل واحد، جاهزية، هوية اختيارية، موافقات، خطوات وميزانية، تشغيل واحد، Progress، Partial/Denied/Timeout/Cancelled/Indeterminate، Evidence، Verification، Report. وضع Cancel لا يحذف أدلة تاريخية.

## 6. Cyberpedia — المعطيات المثبتة والخطوات

الملاحظات من الواجهة العامة والـJavaScript: GET / يحوّل إلى /login؛ GET /login يعرض Username/Password؛ GET /js/login.js يوضح POST /api/login بجسم JSON من username/password، ويستخدم redirect من JSON بعد ok؛ GET /js/otp.js يوضح POST /api/otp بجسم JSON يحوي code، ثم redirect عند نجاح المرحلة. مسار صفحة النجاح **غير مثبت**.

التسلسل الآمن بعد الاعتماد: negative control؛ مراقبة مرحلة login؛ ربط جلسة OTP بالجلسة الأولى عند توفر هوية؛ فحص رفض الوصول قبل تحقق المرحلة الثانية على عنوان يستنتج من التطبيق نفسه؛ مقارنة الجلسة الصحيحة وغير الصحيحة؛ بعد النجاح فعليًا، إثبات صفحة التأكيد والتقاط لقطة كاملة ورفعها عبر منصة التحدي بإجراء مصرح.

**ممنوع:** التخمين الكثيف لكلمات المرور أو OTP، المسح عبر المنافذ، عمليات DoS، تجاوز Scope إلى subdomains أخرى، أو ادعاء bypass بمجرد تعديل JavaScript. لا تتجاوز enforcement الخادم عبر redirect ظاهري فقط.

ملف التعريف غير التنفيذي: docs/web-labs/cyberpedia-northwind-auth-otp.v1.json. يجب ألا تقبله آلة BAC القديمة كوصفة قابلة للتنفيذ؛ وجوده مرجع هندسي لا إطلاق.

## 7. مراحل التنفيذ وبوابات الجودة

| أولوية | التغيير | قبول صارم |
|---|---|---|
| P0 | snapshot Git/Runtime وتقرير preflight | read-only، لا network target، SHA نظيف |
| P1 | اختيار أصل واحد صريح | تفويض أحدث ومطابق؛ لا حذف أو نسخ |
| P1 | مراجعة مصدر Burp وSBOM/provenance/signature | أدلة أصلية قابلة للتدقيق |
| P1 | اعتماد المالك الرسمي وتقييمه | Approved + Trusted + allowed=true |
| P2 | جلسة Burp محكومة عبر Unix | Invocation واحد ودليل مؤهل، مع rate gate |
| P2 | تعريف Cyberpedia غير التنفيذي | schema/ROE/allowlist + اختبارات |
| P3 | Generic authentication/OTP bounded adapter | RBAC/tenant، session binding، no retry side effects |
| P4 | واجهة guided Web Labs فوق المحرك القائم | حالات نجاح/رفض/Timeout/Partial/Cancel |
| P5 | اختبارات fixture محلية vulnerable/fixed/held-out | أحكام مستقلة وحالات سلبية وإيجابية |
| P6 | تجربة الهدف المحدد ضمن ميزانية | نجاح مثبت أو NOT_SOLVED |
| P7 | CI وPR ومراجعة ونشر exact-SHA | Recovery/rollback + acceptance + audit |

## 8. الاختبارات الإلزامية

- AuthZ: رفض الأصول غير المتاحة بين tenant، الأصول المكررة دون اختيار، أحدث التفويضات الملغاة والمنتهية، وهوية ممثل غير مخوّل.
- Provider: عدم استخدام قرار أقدم، رفض invalid manifest/hash/schema/endpoint، ولا استبدال Burp بخادم تجريبي.
- Execution: no external MCP، DNS rebinding guard، redirect guard، rate/timeout، idempotency وindeterminate، cancellation قبل وبعد request، وعدم إعادة POST عند اتصال ملتبس.
- Data/Evidence: عدم تسجيل token/OTP/cookie، بصمات وتواقيع إثبات حقيقية، نسخة fixture، negative controls، no fake findings أو screenshots.
- Release: compile/lint/tests/CI exact-head وstaging ثم الإنتاج بإجراءات rollback آمنة؛ recheck runtime بعد النشر دون تغيير backup/PKI/CRL.

## 9. فحص جاهزية قابل للتكرار داخل Ubuntu

أضيف في فرع التطوير، لا في runtime الإنتاج، سكربت aegis-platform/scripts/audit_external_web_lab_readiness.py. يقرأ الحالة الرسمية من aegis-django، ويختبر قناة Unix المحلية فقط، ويقبل asset_id صريحًا. لا يصادق كمستخدم، ولا ينشئ ProviderApprovalDecision/Scan، ولا يرسل أي طلب إلى موقع Cyberpedia.

مثال تشغيل من جذر فرع التطوير:

    python3 aegis-platform/scripts/audit_external_web_lab_readiness.py \
      --project-id 6e1de003-ccf2-4549-a2ce-6520ab9bc046 \
      --asset-id 1ce3b319-fc7d-4d33-9f2e-e67168423b82 \
      --target https://challenge.cyberpedia.site/

رمز خروج 2 يعني وجود موانع؛ 1 خطأ في التدقيق؛ 0 نجاح فحوص metadata الحالية، وليس موافقة تشغيل أو حل المختبر.

## 10. الوضع النهائي الذي يجوز إعلانه الآن

Burp runtime/SSE/UDS شغّال. تفويض Cyberpedia موجود لكن للأصل نسختان. مزود Burp غير مقبول في سجل الحوكمة، وهوية الهدف غير جاهزة في Vault، وgeneric auth/OTP adapter غير موجود. لذا حالة التحدي NOT_SOLVED، وحالة التنفيذ الرسمي BLOCKED.

لا تُكتب موافقة مزود باسم root ولا تضاف signature_verified=true أو reproducibility=true اعتمادًا على SHA وحده. اكتمال ترقية التصميم يتطلب CI ومراجعة PR ونشر exact-SHA ثم تنفيذ Acceptance مستقل.

## 11. المراجع الرسمية

- PortSwigger MCP Server BApp: https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc
- OWASP MFA Testing (WSTG-ATHN-11): https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/11-Multi-Factor_Authentication/
- وثائق المشروع: docs/WEB_LABS_BURP_TRANSPORT_AR.md، docs/WEB_LABS_CHECKPOINT.md، docs/WEB_LABS_READINESS_CONTRACT_AR.md، docs/web-labs-p6-contract.md.
