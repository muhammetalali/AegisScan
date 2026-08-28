from django.db import migrations
from django.utils import timezone


ARTICLES = [
    {
        "category": "Transport Security",
        "slug": "hsts-and-transport-security",
        "title": "HTTP Strict Transport Security (HSTS)",
        "type": "best_practice",
        "difficulty": "intermediate",
        "tags": ["HSTS", "HTTPS", "transport-security", "OWASP"],
        "summary": "Use HSTS so supported browsers enforce HTTPS for the protected host and reduce downgrade and man-in-the-middle exposure.",
        "content": """# HTTP Strict Transport Security (HSTS)\n\nHSTS tells supported browsers to use HTTPS for the protected host instead of continuing over HTTP. It should be deployed only after HTTPS is correctly configured across the scope you intend to protect.\n\n## Validation layers\n1. Confirm the application is reachable over HTTPS.\n2. Verify the `Strict-Transport-Security` response header and its policy parameters.\n3. Validate subdomain coverage and preload requirements separately before enabling them.\n4. Re-test redirects and security-sensitive endpoints after deployment.\n\n## Source\nOWASP HTTP Strict Transport Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html\n""",
        "meta_title": "HSTS and HTTP Transport Security | AegisScan Knowledge",
        "meta_description": "Source-backed guidance for validating HSTS and HTTPS transport protection.",
    },
    {
        "category": "Transport Security",
        "slug": "tls-1-2-and-tls-1-3-hardening",
        "title": "TLS 1.2/1.3 Transport Hardening",
        "type": "remediation_guide",
        "difficulty": "advanced",
        "tags": ["TLS", "TLS1.2", "TLS1.3", "crypto", "OWASP"],
        "summary": "Prefer TLS 1.3 and allow TLS 1.2 for compatibility; disable TLS 1.0/1.1 and weak cipher suites.",
        "content": """# TLS 1.2/1.3 Transport Hardening\n\nCurrent transport guidance should center on TLS 1.3, with TLS 1.2 retained where compatibility requires it. Legacy TLS 1.0 and TLS 1.1 should be disabled.\n\n## Validation layers\n- Protocol negotiation must exclude TLS 1.0/1.1.\n- TLS 1.3 should use standard AEAD suites.\n- TLS 1.2 should prefer AEAD-based suites and avoid legacy CBC and non-forward-secret configurations.\n- Re-test external and internal endpoints independently because policy drift often occurs between tiers.\n\n## Source\nOWASP Transport Layer Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html\n""",
        "meta_title": "TLS 1.2/1.3 Hardening | AegisScan Knowledge",
        "meta_description": "Source-backed TLS protocol and cipher hardening guidance.",
    },
    {
        "category": "Access Control",
        "slug": "object-level-authorization-and-idor",
        "title": "Object-Level Authorization and IDOR",
        "type": "remediation_guide",
        "difficulty": "advanced",
        "tags": ["IDOR", "BOLA", "authorization", "API", "OWASP"],
        "summary": "Every object reference must be checked against the authenticated user's allowed dataset; unpredictable IDs alone are not an authorization control.",
        "content": """# Object-Level Authorization and IDOR\n\nAn identifier in a URL or request body is not permission. The API must determine whether the authenticated principal is authorized to access the referenced object.\n\n## Validation layers\n1. Scope the queryset to objects the caller can access.\n2. Apply authorization on read, create, update, delete and export paths.\n3. Test cross-tenant and cross-project object access with distinct users.\n4. Treat UUIDs as defense in depth, not as a replacement for authorization.\n\n## Source\nOWASP Insecure Direct Object Reference Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html\n""",
        "meta_title": "Object-Level Authorization and IDOR | AegisScan Knowledge",
        "meta_description": "Source-backed API object authorization and IDOR prevention guidance.",
    },
    {
        "category": "Injection Defense",
        "slug": "xss-output-encoding-and-safe-sinks",
        "title": "XSS: Output Encoding, Sanitization and Safe Sinks",
        "type": "best_practice",
        "difficulty": "advanced",
        "tags": ["XSS", "CSP", "output-encoding", "sanitization", "OWASP"],
        "summary": "Encode untrusted output for its rendering context, sanitize authored HTML when necessary, and avoid unsafe DOM sinks.",
        "content": """# XSS: Output Encoding, Sanitization and Safe Sinks\n\nA robust XSS defense uses layered controls. Modern frameworks provide automatic escaping in common cases, but unsafe DOM APIs, dynamic HTML and untrusted URLs can reopen the vulnerability.\n\n## Validation layers\n- Validate untrusted input at the server boundary.\n- Use framework-safe rendering and context-appropriate output encoding.\n- Sanitize HTML when rich content is actually required.\n- Use a restrictive Content Security Policy as an additional layer, not as the sole defense.\n- Audit unsafe sinks and dynamic URL handling.\n\n## Source\nOWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html\n""",
        "meta_title": "XSS Prevention | AegisScan Knowledge",
        "meta_description": "Source-backed XSS prevention using encoding, sanitization and safe rendering patterns.",
    },
]


def seed(apps, schema_editor):
    Category = apps.get_model("knowledge", "KnowledgeCategory")
    Article = apps.get_model("knowledge", "KnowledgeArticle")
    now = timezone.now()
    categories = {}
    for slug, name in (
        ("transport-security", "Transport Security"),
        ("access-control", "Access Control"),
        ("injection-defense", "Injection Defense"),
    ):
        categories[slug], _ = Category.objects.get_or_create(
            slug=slug,
            defaults={"name": name, "description": "Source-backed security guidance."},
        )

    for item in ARTICLES:
        category_slug = {
            "Transport Security": "transport-security",
            "Access Control": "access-control",
            "Injection Defense": "injection-defense",
        }[item["category"]]
        Article.objects.update_or_create(
            slug=item["slug"],
            defaults={
                **{key: value for key, value in item.items() if key != "category"},
                "category": categories[category_slug],
                "status": "published",
                "published_at": now,
                "version": "1.0",
            },
        )


def unseed(apps, schema_editor):
    Article = apps.get_model("knowledge", "KnowledgeArticle")
    Article.objects.filter(slug__in=[item["slug"] for item in ARTICLES]).delete()


class Migration(migrations.Migration):
    dependencies = [("knowledge", "0001_initial")]
    operations = [migrations.RunPython(seed, unseed)]
