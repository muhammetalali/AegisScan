# AegisScan Platform — Windows local runtime

هذا الدليل هو المسار المعتمد لتشغيل المنصة الحالية من المستودع. لا تشغّل `docker compose` من جذر المستودع؛ ملف Compose موجود هنا تحديداً:

`packages/platform/docker-compose.yml`

## 1. المتطلبات

- Windows 10/11
- Python 3.14.x
- Node.js + npm
- Docker Desktop مع Docker Compose
- Git

## 2. Core / tests

من جذر المستودع:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pytest tests/ -q
```

## 3. Frontend development

```powershell
cd C:\Users\muham\Desktop\AegisScan-1\packages\web
npm install
npm run dev
```

ثم افتح `http://localhost:5173`.

## 4. Backend + PostgreSQL + Redis عبر Docker

انتقل أولاً إلى مجلد Compose الصحيح:

```powershell
cd C:\Users\muham\Desktop\AegisScan-1\packages\platform
copy .env.example .env
docker compose config
docker compose up -d postgres redis
docker compose ps
```

بعد نجاح PostgreSQL وRedis:

```powershell
docker compose up -d --build
docker compose ps
docker compose logs -f django
docker compose logs -f fastapi
```

الخدمات المحلية:

- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`
- Django: `localhost:8000`
- FastAPI: `localhost:8001`
- Frontend container: `localhost:5173`
- Celery workers + beat

## 5. مشكلة PostgreSQL: password authentication failed

إذا ظهر:

`FATAL: password authentication failed for user "aegis"`

فهذا يعني أن Django وصل فعلياً إلى PostgreSQL على `localhost:5432`، لكن كلمة مرور مستخدم قاعدة البيانات الموجودة على ذلك الخادم لا تطابق إعداد AegisScan. هذه ليست مشكلة migrations أو Django code.

لا تحذف قاعدة البيانات ولا تستخدم `docker compose down -v` لحلها.

أولاً اعرف من يستخدم المنفذ 5432:

```powershell
Get-NetTCPConnection -LocalPort 5432 -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
Get-Process -Id (Get-NetTCPConnection -LocalPort 5432 -State Listen).OwningProcess
```

إذا كان PostgreSQL يعمل كخدمة Windows خارج Docker، وحساب `postgres` الإداري متاح، غيّر كلمة مرور مستخدم التطبيق فقط دون حذف أي بيانات:

```powershell
psql -h localhost -U postgres -d postgres -c "ALTER ROLE aegis WITH LOGIN PASSWORD 'aegis';"
```

ثم تحقق:

```powershell
python manage.py showmigrations
python manage.py migrate
```

إذا كان PostgreSQL المطلوب هو حاوية AegisScan، شغّل Compose من `packages/platform` وليس من جذر المستودع. إعداد Compose يحدد نفس `POSTGRES_DB`, `POSTGRES_USER`, و`POSTGRES_PASSWORD` التي تستخدمها خدمات Django/FastAPI.

> مهم: متغير `POSTGRES_PASSWORD` في Docker Compose يُستخدم لإنشاء كلمة مرور الدور عند تهيئة volume لأول مرة. تغيير المتغير لاحقاً لا يغيّر كلمة مرور role موجودة داخل volume قديم.

## 6. Django مباشرة على Windows

إذا كنت تشغّل Django خارج Docker، نفّذ من:

```powershell
cd C:\Users\muham\Desktop\AegisScan-1\packages\backend
```

ثم:

```powershell
python manage.py check
python manage.py showmigrations
python manage.py migrate
python manage.py runserver 127.0.0.1:8000
```

يجب أن تكون `DATABASE_URL` في `packages/backend/.env` متوافقة مع PostgreSQL الفعلي الذي يعمل على `localhost:5432`.

## 7. ملاحظة مهمة عن ملفات البيئة

`packages/platform/.env.example` هو عقد إعداد التشغيل المحلي لـ Compose.

`packages/backend/.env.example` هو قالب إعداد التطبيق نفسه.

لا تضع أسرار الإنتاج في Git. استخدم `.env` محلياً أو أسرار CI/CD.

## 8. تسلسل التحقق النهائي

```powershell
cd C:\Users\muham\Desktop\AegisScan-1\packages\platform
docker compose config
docker compose up -d postgres redis
docker compose ps

cd ..\backend
python manage.py check
python manage.py showmigrations
python manage.py migrate
```

بعد نجاح قاعدة البيانات فقط انتقل إلى تشغيل Django/FastAPI/Celery والواجهة.
