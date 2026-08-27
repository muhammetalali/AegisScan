# دليل التشغيل على Windows 11 + VS Code - AegisScan Platform

## المتطلبات
- Windows 11
- Python 3.14.3 (مثبت في C:\Python314)
- Node.js 25.7.0 + npm 11.10.1
- VS Code في C:\Users\muham\AppData\Local\Programs\Microsoft VS Code
- Git 2.55

---

## 1. تشغيل النواة (Core Engine) - يعمل الآن 100%

### في VS Code Terminal (Ctrl + `):

```powershell
# تفعيل البيئة
.\.venv\Scripts\Activate.ps1

# التشغيل
$env:PYTHONIOENCODING='utf-8'; $env:PATH += ";C:\Users\muham\AppData\Roaming\Python\Python314\Scripts"

aegis init
aegis scan --code . --markdown report.md --output report.json
aegis validate --code . --markdown platform_report.md --output platform_report.json
aegis findings --severity critical
aegis status
aegis version

# الاختبارات
python -m pytest tests/ -q
# النتيجة المتوقعة: جميع اختبارات النواة ناجحة، مع تخطي اختبارات Docker إذا لم يكن المحرك جاهزاً
```

### المشاكل التي تم حلها:
- تم إنشاء `pyproject.toml` لتعريف الحزمة
- تم إصلاح `requirements.txt` (إزالة [dev] غير الصالح)
- تم تثبيت الحزمة عبر `pip install -e .`
- تم إصلاح ترميز Windows (استبدال ✅ بـ [OK])
- تم حل مشكلة PATH عبر `$env:PATH += ";...Scripts"`

---

## 2. تشغيل الواجهة الاحترافية (Frontend)

```powershell
cd C:\Users\muham\Desktop\AegisScan-1\aegis-platform\frontend

# التثبيت (قد يستغرق 2-3 دقائق)
npm install

# التشغيل للتطوير
npm run dev
# افتح http://localhost:5173

# البناء للإنتاج
npm run build
npm run preview
```

### الميزات المنفذة:
- React 19 + TypeScript + Vite
- Tailwind CSS 4 + Dark Theme
- 23 صفحة (Login, Register, Dashboard, Projects, Assets, Scan, Progress, Results, Vulnerabilities, Reports, Compliance, Knowledge, Digital Twin, Posture, Users, Settings, System, Audit, Notifications)
- Layout مع Sidebar + Header + RTL
- Zustand + TanStack Query + React Hook Form + Zod + Sonner + Framer Motion + ECharts + Monaco Editor
- WebSocket للتقدم اللحظي

---

## 3. تشغيل الخلفية الكاملة (Backend) عبر Docker

```powershell
cd C:\Users\muham\Desktop\AegisScan-1\aegis-platform

# إنشاء ملف البيئة
copy .env.example .env

# التشغيل
docker-compose up -d
docker-compose ps
docker-compose logs -f django
docker-compose logs -f fastapi
docker-compose logs -f celery_worker

# الخدمات:
# - Django (Gunicorn) على 8000
# - FastAPI (Uvicorn) على 8001
# - PostgreSQL على 5432
# - Redis على 6379
# - Celery Worker + Beat
# - Frontend (Nginx) على 80
# - Nginx Proxy على 80/443
```

---

## 4. فتح في VS Code

1. افتح VS Code: `code C:\Users\muham\Desktop\AegisScan-1`
2. افتح المجلد `aegis-platform`
3. استخدم `Ctrl+Shift+P` → `Tasks: Run Task` → اختر `Start AegisScan`

### VS Code Tasks (تم إنشاؤها في .vscode/tasks.json):
- Start Backend (Django + FastAPI)
- Start Frontend (npm run dev)
- Run Tests (pytest)
- Build Frontend (npm run build)

---

## 5. تسلسل الواجهات

```
Login → Dashboard → Projects → Assets → New Validation → Progress Live → Results → Findings → Reports → Security Posture → Digital Twin → Users → Settings
```

كل زر له وظيفة واضحة ومحددة ضمن المنصة.

---

## 6. التحقق من الجاهزية

```powershell
# Backend Django Models: 11 تطبيق (users, projects, assets, scans, vulnerabilities, reports, compliance, knowledge, notifications, audit, system)
# Frontend Pages: 23 صفحة
# Engines: 20 محرك (15 الأصلي + 5 إضافي)
# Tests: شغّل `python -m pytest -q` للحصول على العدد الحالي
# CLI: scan + validate + findings + status + version (كلها تعمل)
```

---

## 7. الإنتاج

```powershell
docker-compose -f docker-compose.prod.yml up -d --build
```

---

**المنصة قابلة للتشغيل على Windows 11 بعد إعداد المتطلبات وتشغيل فحوصات الجاهزية.**
