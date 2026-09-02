import React, { FormEvent, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { useAuthStore } from '@/stores/authStore'

export const Login = () => {
  const navigate = useNavigate()
  const { login } = useAuthStore()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return

    setBusy(true)
    try {
      await login(email.trim(), password)
      setPassword('')
      toast.success('تم تسجيل الدخول بنجاح')
      navigate('/dashboard', { replace: true })
    } catch (error: any) {
      const detail = error?.response?.data?.detail
      const message = typeof detail === 'string'
        ? detail
        : detail?.message || error?.response?.data?.error?.message || 'تعذر تسجيل الدخول. تحقق من البيانات وحاول مجددًا.'
      toast.error(message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="auth-page" dir="rtl">
      <div className="auth-background" aria-hidden="true">
        <span className="auth-orb auth-orb--one" />
        <span className="auth-orb auth-orb--two" />
        <span className="auth-line auth-line--one" />
        <span className="auth-line auth-line--two" />
      </div>

      <section className="login-surface" aria-labelledby="login-title">
        <div className="login-brand">
          <div className="login-logo-frame">
            <img src="/aegis-logo.svg" alt="AegisScan" className="login-logo" />
          </div>
          <div>
            <strong>AegisScan</strong>
            <span>Security Validation Platform</span>
          </div>
        </div>

        <div className="login-content">
          <p className="login-kicker">SECURE ACCESS</p>
          <h1 id="login-title">تسجيل الدخول</h1>
          <p className="login-subtitle">الوصول الموثق إلى منصة التحقق الأمني.</p>

          <form onSubmit={submit} className="login-form" noValidate>
            <label className="login-field">
              <span>البريد الإلكتروني</span>
              <input
                id="email"
                name="email"
                type="email"
                inputMode="email"
                autoComplete="username"
                placeholder="user@company.com"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                disabled={busy}
                required
              />
            </label>

            <label className="login-field">
              <span>كلمة المرور</span>
              <div className="login-password">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={busy}
                  minLength={8}
                  required
                />
                <button
                  type="button"
                  className="password-action"
                  onClick={() => setShowPassword((value) => !value)}
                  aria-label={showPassword ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور'}
                >
                  {showPassword ? 'إخفاء' : 'إظهار'}
                </button>
              </div>
            </label>

            <button type="submit" className="login-submit" disabled={busy}>
              {busy ? 'جارٍ التحقق…' : 'دخول'}
            </button>
          </form>
        </div>

        <div className="login-footer">
          <span>Protected session</span>
          <span aria-hidden="true">•</span>
          <span>RBAC</span>
          <span aria-hidden="true">•</span>
          <span>Evidence</span>
        </div>
      </section>
    </main>
  )
}
