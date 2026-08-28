from django.db import migrations
from django.utils import timezone


ARTICLES = [
    {
        "category": "Injection Defense",
        "slug": "content-security-policy-policy",
        "title": "Content Security Policy as a Defense-in-Depth Policy",
        "type": "security_policy",
        "difficulty": "advanced",
        "tags": ["CSP", "security-policy", "XSS", "headers"],
        "summary": "Deploy CSP through the HTTP response header and use it as defense in depth against XSS and related browser-side attacks.",
        "content": """# Content Security Policy as a Defense-in-Depth Policy\n\nCSP should be delivered as an HTTP response header when possible. A strict policy using nonces or hashes is preferred over relying on broad allowlists. Report-Only mode can be used during rollout before enforcement.\n\n## Validation layers\n- Confirm the policy is sent on all application responses in the protected scope.\n- Validate `script-src`, `object-src`, `base-uri`, `frame-ancestors` and other directives against actual application behavior.\n- Use Report-Only during safe rollout when policy incompatibilities are expected.\n- Re-test after frontend dependency or asset changes.\n\n## Source\nOWASP Content Security Policy Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html\n""",
        "meta_title": "Content Security Policy | AegisScan Knowledge",
        "meta_description": "Source-backed CSP policy guidance for defense in depth.",
    },
    {
        "category": "Access Control",
        "slug": "deny-by-default-authorization-policy",
        "title": "Deny-by-Default Authorization Policy",
        "type": "security_policy",
        "difficulty": "advanced",
        "tags": ["authorization", "least-privilege", "deny-by-default", "policy"],
        "summary": "Protected application resources should be denied unless an explicit authorization rule permits the requested action for the requesting principal.",
        "content": """# Deny-by-Default Authorization Policy\n\nAuthentication proves identity; authorization decides whether that identity may perform the requested operation on the requested resource. The default for protected resources should be deny.\n\n## Validation layers\n- Check authorization on every request and every object.\n- Scope database lookups to the caller's permitted tenant/project boundary.\n- Test horizontal and vertical privilege escalation with negative integration tests.\n- Keep authorization decisions server-side; client-side guards are only UX aids.\n\n## Source\nOWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html\nOWASP Authorization Regression Testing Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html\n""",
        "meta_title": "Deny-by-Default Authorization | AegisScan Knowledge",
        "meta_description": "Source-backed least privilege and deny-by-default authorization policy.",
    },
    {
        "category": "Access Control",
        "slug": "how-to-validate-api-object-access",
        "title": "FAQ: How should API object access be validated?",
        "type": "faq",
        "difficulty": "intermediate",
        "tags": ["FAQ", "API", "IDOR", "BOLA", "authorization"],
        "summary": "Validate the authenticated principal's authorization for the exact object and operation on every request; never rely on an opaque identifier alone.",
        "content": """# FAQ: How should API object access be validated?\n\nAn object ID does not grant access. The server should resolve the object within the caller's allowed scope and then authorize the specific action.\n\nFor regression testing, create a matrix covering permitted, denied, cross-tenant and privilege-escalation cases. Assert that unauthorized identities receive the expected denial and that no protected record is leaked in the response.\n\n## Sources\nOWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html\nOWASP Authorization Regression Testing Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html\n""",
        "meta_title": "API Object Authorization FAQ | AegisScan Knowledge",
        "meta_description": "FAQ for validating object-level authorization and IDOR/BOLA controls.",
    },
    {
        "category": "Access Control",
        "slug": "authorization-regression-testing-lesson",
        "title": "Lesson Learned: Authorization must be regression-tested",
        "type": "lesson_learned",
        "difficulty": "advanced",
        "tags": ["lesson-learned", "authorization", "regression", "CI"],
        "summary": "Authorization defects frequently reappear as APIs evolve; preserve a machine-readable authorization matrix and run it in integration/CI tests.",
        "content": """# Lesson Learned: Authorization must be regression-tested\n\nAuthorization is a Day-2 problem as much as an implementation problem. New endpoints, refactors and service boundaries can silently change who can access an object.\n\n## Operational lesson\nKeep an explicit authorization matrix covering tenant isolation, horizontal access, vertical escalation and denied-by-default cases. Re-run it whenever API contracts or resource ownership change.\n\n## Sources\nOWASP Authorization Testing Automation Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html\nOWASP Authorization Regression Testing Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html\n""",
        "meta_title": "Authorization Regression Testing Lessons | AegisScan Knowledge",
        "meta_description": "Source-backed lesson about maintaining authorization regression coverage.",
    },
]


def seed(apps, schema_editor):
    Category = apps.get_model("knowledge", "KnowledgeCategory")
    Article = apps.get_model("knowledge", "KnowledgeArticle")
    now = timezone.now()
    slug_map = {
        "Transport Security": "transport-security",
        "Access Control": "access-control",
        "Injection Defense": "injection-defense",
    }
    for item in ARTICLES:
        category = Category.objects.get(slug=slug_map[item["category"]])
        data = {key: value for key, value in item.items() if key != "category"}
        data.update(status="published", category=category, published_at=now, version="1.0")
        Article.objects.update_or_create(slug=item["slug"], defaults=data)


def unseed(apps, schema_editor):
    Article = apps.get_model("knowledge", "KnowledgeArticle")
    Article.objects.filter(slug__in=[item["slug"] for item in ARTICLES]).delete()


class Migration(migrations.Migration):
    dependencies = [("knowledge", "0002_seed_source_backed_knowledge")]
    operations = [migrations.RunPython(seed, unseed)]
