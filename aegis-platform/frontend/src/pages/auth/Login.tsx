import React, { FormEvent, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Languages } from 'lucide-react'
import { toast } from 'sonner'
import { useAuthStore } from '@/stores/authStore'
import { useLanguageStore } from '@/stores/languageStore'

export const Login = () => {
  const navigate = useNavigate()
  const { login } = useAuthStore()
  const { language, setLanguage, t } = useLanguageStore()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)

  const toggleLanguage = async () => {
    await setLanguage(language === 'ar' ? 'en' : 'ar')
  }

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return

    setBusy(true)
    try {
      await login(email.trim(), password)
      setPassword('')
      toast.success(t('Signed in successfully'))
      navigate('/dashboard', { replace: true })
    } catch (error: any) {
      const detail = error?.response?.data?.detail
      const message = typeof detail === 'string'
        ? detail
        : detail?.message || error?.response?.data?.error?.message || t('Unable to sign in. Check your credentials and try again.')
      toast.error(message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="auth-page" dir={language === 'ar' ? 'rtl' : 'ltr'}>
      <div className="auth-background" aria-hidden="true">
        <span className="auth-orb auth-orb--one" />
        <span className="auth-orb auth-orb--two" />
        <span className="auth-line auth-line--one" />
        <span className="auth-line auth-line--two" />
      </div>

      <section className="login-surface" aria-labelledby="login-title">
        <button type="button" className="language-switch enterprise-control" onClick={toggleLanguage} aria-label={language === 'ar' ? t('Switch to English') : t('Switch to Arabic')} title={language === 'ar' ? t('Switch to English') : t('Switch to Arabic')}>
          <Languages className="h-4 w-4" />
          <span>{language === 'ar' ? 'EN' : 'العربية'}</span>
        </button>
        <div className="login-brand">
          <div className="login-logo-frame"><img src="/aegis-logo.svg" alt="AegisScan" className="login-logo" /></div>
          <div><strong>AegisScan</strong><span>{t('Security Validation Platform')}</span></div>
        </div>

        <div className="login-content">
          <p className="login-kicker">SECURE ACCESS</p>
          <h1 id="login-title">{t('Sign in')}</h1>
          <p className="login-subtitle">{t('Authenticated access to the security validation platform.')}</p>

          <form onSubmit={submit} className="login-form" noValidate>
            <label className="login-field">
              <span>{t('Email address')}</span>
              <input id="email" name="email" type="email" inputMode="email" autoComplete="username" placeholder="user@company.com" value={email} onChange={(event) => setEmail(event.target.value)} disabled={busy} required />
            </label>

            <label className="login-field">
              <span>{t('Password')}</span>
              <div className="login-password">
                <input id="password" name="password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" placeholder="••••••••" value={password} onChange={(event) => setPassword(event.target.value)} disabled={busy} minLength={8} required />
                <button type="button" className="password-action" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? t('Hide password') : t('Show password')}>
                  {showPassword ? t('Hide') : t('Show')}
                </button>
              </div>
            </label>

            <button type="submit" className="login-submit" disabled={busy}>{busy ? t('Signing in…') : t('Sign in')}</button>
          </form>
        </div>

        <div className="login-footer"><span>{t('Protected session')}</span><span aria-hidden="true">•</span><span>RBAC</span><span aria-hidden="true">•</span><span>{t('Evidence')}</span></div>
      </section>
    </main>
  )
}
