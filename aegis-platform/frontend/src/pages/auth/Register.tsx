import { Link } from 'react-router-dom'
import { useLanguageStore } from '@/stores/languageStore'

/** Public sign-up is intentionally unavailable for the company deployment. */
export const Register = () => {
  const arabic = useLanguageStore(state => state.language === 'ar')
  return (
    <main className="min-h-screen flex items-center justify-center p-6" dir={arabic ? 'rtl' : 'ltr'}>
      <section className="enterprise-card rounded-3xl max-w-md w-full p-8" aria-labelledby="company-registration-title">
        <h1 id="company-registration-title" className="text-2xl font-bold">
          {arabic ? 'حسابات AegisScan للشركة فقط' : 'Company-managed AegisScan accounts only'}
        </h1>
        <p className="mt-3 leading-7 text-muted-foreground">
          {arabic
            ? 'لا يوجد تسجيل عام ولا تفعيل عبر البريد الإلكتروني. ينشئ مالك الشركة حساب كل موظف ويحدد كلمة مروره وصفحاته وأنواع الفحص المسموحة له ثم يفعّل الحساب من واجهة المستخدمين.'
            : 'Public registration and email activation are disabled. The company owner creates each employee account, assigns its password, allowed pages and scan types, and activates it from the users console.'}
        </p>
        <Link to="/login" className="mt-6 inline-flex rounded-lg border px-4 py-2 text-primary font-semibold">
          {arabic ? 'العودة لتسجيل الدخول' : 'Back to sign in'}
        </Link>
      </section>
    </main>
  )
}
