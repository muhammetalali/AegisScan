import React, { FormEvent, useEffect, useState } from 'react'
import { Activity, ArrowRight, CheckCircle2, Eye, EyeOff, Fingerprint, LockKeyhole, Mail, Moon, Radio, ShieldCheck, Sun, Zap } from 'lucide-react'
import { toast } from 'sonner'
import { AegisLogo } from '@/components/brand/AegisLogo'
import { useAuthStore } from '@/stores/authStore'

export const Login = () => {
  const { login, logout, isAuthenticated, user } = useAuthStore()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [dark, setDark] = useState(() => {
    if (typeof window === 'undefined') return true
    const stored = window.localStorage.getItem('aegisscan-theme')
    return stored ? stored === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches
  })

  useEffect(() => {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light'
    window.localStorage.setItem('aegisscan-theme', dark ? 'dark' : 'light')
  }, [dark])

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    try {
      await login(email.trim(), password)
      toast.success('تم تسجيل الدخول بنجاح')
      setPassword('')
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

  if (isAuthenticated) {
    return (
      <main className="auth-shell">
        <div className="auth-noise" />
        <div className="auth-grid" />
        <section className="session-card" aria-live="polite">
          <AegisLogo />
          <div className="session-icon"><CheckCircle2 size={28} /></div>
          <p className="eyebrow"><span className="status-dot status-dot--live" /> SESSION ACTIVE</p>
          <h1>الوصول الآمن مفعل</h1>
          <p className="session-copy">تم توثيق الجلسة عبر طبقة المصادقة الحالية. المنصة جاهزة لفتح مسارات التحقق الأمني عند إعادة تفعيل واجهات المنتج.</p>
          <div className="session-principal"><Fingerprint size={16} /><span>{user?.email || 'Authenticated principal'}</span></div>
          <button className="secondary-button" type="button" onClick={() => void logout()}>إنهاء الجلسة</button>
        </section>
      </main>
    )
  }

  return (
    <main className="auth-shell">
      <div className="auth-noise" />
      <div className="auth-grid" />
      <div className="signal signal--one" />
      <div className="signal signal--two" />
      <div className="signal signal--three" />

      <div className="auth-layout">
        <section className="brand-panel">
          <div className="brand-topline">
            <AegisLogo light />
            <button className="icon-button" type="button" onClick={() => setDark((value) => !value)} aria-label={dark ? 'تفعيل الوضع الفاتح' : 'تفعيل الوضع الداكن'}>
              {dark ? <Sun size={16} /> : <Moon size={16} />}
            </button>
          </div>

          <div className="brand-copy">
            <div className="eyebrow"><span className="status-dot" /> SECURITY VALIDATION FABRIC</div>
            <h1>أثبت المخاطر.<br /><em>أثبت الإصلاح.</em><br />اضبط النتيجة.</h1>
            <p>من الـAdversary إلى الـEvidence ثم Risk وGovernance وContinuous Validation — في مسار تشغيلي واحد مبني على نتائج حقيقية.</p>
          </div>

          <div className="signal-grid">
            <div className="signal-card"><Radio size={17} /><span>Live telemetry</span></div>
            <div className="signal-card"><ShieldCheck size={17} /><span>Evidence first</span></div>
            <div className="signal-card"><Activity size={17} /><span>Continuous validation</span></div>
          </div>

          <div className="brand-footer">
            <span>Adversary → Attack Surface → Controls → Detection → Evidence → Risk</span>
            <span className="footer-live"><span className="status-dot status-dot--live" /> secure channel</span>
          </div>
        </section>

        <section className="login-panel">
          <div className="mobile-brand"><AegisLogo /></div>
          <div className="login-card">
            <div className="login-heading">
              <div className="login-badge"><LockKeyhole size={14} /> SECURE ACCESS</div>
              <h2>تسجيل الدخول</h2>
              <p>ادخل إلى AegisScan لبدء جلسة عمل موثقة ومحمية.</p>
            </div>

            <form onSubmit={submit} className="login-form" noValidate>
              <label className="field">
                <span>البريد الإلكتروني</span>
                <div className="input-wrap">
                  <Mail size={17} />
                  <input id="email" name="email" type="email" inputMode="email" autoComplete="username" placeholder="user@company.com" value={email} onChange={(event) => setEmail(event.target.value)} disabled={busy} required />
                </div>
              </label>

              <label className="field">
                <span>كلمة المرور</span>
                <div className="input-wrap">
                  <LockKeyhole size={17} />
                  <input id="password" name="password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" placeholder="••••••••" value={password} onChange={(event) => setPassword(event.target.value)} disabled={busy} minLength={8} required />
                  <button className="password-toggle" type="button" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور'}>
                    {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                  </button>
                </div>
              </label>

              <button className="primary-button" type="submit" disabled={busy}>
                {busy ? <span className="button-spinner" /> : <Zap size={17} />}
                {busy ? 'جاري التحقق...' : 'دخول آمن'}
                {!busy && <ArrowRight size={16} />}
              </button>
            </form>

            <div className="trust-strip">
              <span><ShieldCheck size={14} /> HttpOnly session</span>
              <span><Fingerprint size={14} /> RBAC aware</span>
              <span><CheckCircle2 size={14} /> Evidence driven</span>
            </div>
          </div>
          <p className="login-note">AegisScan • Security Validation Platform • Protected access surface</p>
        </section>
      </div>
    </main>
  )
}
