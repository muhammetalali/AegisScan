import { Link } from 'react-router-dom'

/** Public sign-up is intentionally unavailable for the company deployment. */
export const Register = () => (
  <main className="min-h-screen flex items-center justify-center p-6" dir="rtl">
    <section className="enterprise-card rounded-3xl max-w-md w-full p-8" aria-labelledby="company-registration-title">
      <h1 id="company-registration-title" className="text-2xl font-bold">حسابات AegisScan للشركة فقط</h1>
      <p className="mt-3 leading-7 text-muted-foreground">
        لا يوجد تسجيل عام ولا تفعيل عبر البريد الإلكتروني. ينشئ مالك الشركة حساب كل موظف
        ويحدد كلمة مروره وصفحاته وأنواع الفحص المسموحة له ثم يفعّل الحساب من واجهة المستخدمين.
      </p>
      <Link to="/login" className="mt-6 inline-flex rounded-lg border px-4 py-2 text-primary font-semibold">
        العودة لتسجيل الدخول
      </Link>
    </section>
  </main>
)
