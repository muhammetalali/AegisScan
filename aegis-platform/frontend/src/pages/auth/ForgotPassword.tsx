import { Link } from 'react-router-dom'
import { useLanguageStore } from '@/stores/languageStore'

/** Mail-based reset is not enabled until a verified recovery API and mail transport exist. */
export const ForgotPassword = () => {
  const language = useLanguageStore(state => state.language)
  const arabic = language === 'ar'

  return (
    <main className="min-h-screen flex items-center justify-center p-6" dir={arabic ? 'rtl' : 'ltr'}>
      <section className="enterprise-card rounded-3xl max-w-md w-full p-8" aria-labelledby="recovery-title">
        <h1 id="recovery-title" className="text-2xl font-bold">{arabic ? 'المساعدة في الوصول إلى الحساب' : 'Account access assistance'}</h1>
        <p className="text-muted-foreground mt-3 leading-7">
          {arabic
            ? 'استعادة كلمة المرور عبر البريد الإلكتروني غير مفعّلة حاليًا. تواصل مع مسؤول النظام لاستعادة الوصول إلى حسابك بطريقة آمنة.'
            : 'Email password recovery is not enabled. Contact your system administrator for secure account access assistance.'}
        </p>
        <Link to="/login" className="mt-6 inline-flex items-center text-primary font-semibold hover:underline">
          {arabic ? 'العودة إلى تسجيل الدخول' : 'Back to sign in'}
        </Link>
      </section>
    </main>
  )
}
