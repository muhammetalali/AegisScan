import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { motion } from 'framer-motion'
import { Activity, ArrowRight, CheckCircle2, Eye, EyeOff, Fingerprint, Globe2, KeyRound, Lock, Mail, Moon, Network, Radar, Shield, Sparkles, Sun } from 'lucide-react'
import { useAuthStore } from '@/stores/authStore'
import { useThemeStore } from '@/stores/themeStore'
import { useLanguageStore } from '@/stores/languageStore'
import { cn } from '@/utils/cn'

const loginSchema = z.object({
  email: z.string().email('البريد الإلكتروني غير صحيح'),
  password: z.string().min(8, 'كلمة المرور يجب أن تكون 8 أحرف على الأقل'),
  rememberMe: z.boolean().optional(),
})
type LoginForm = z.infer<typeof loginSchema>

export const Login = () => {
  const navigate = useNavigate()
  const { login } = useAuthStore()
  const { resolvedTheme, toggleTheme } = useThemeStore()
  const { language, setLanguage } = useLanguageStore()
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [otp, setOtp] = useState('')
  const [twoFactorRequired, setTwoFactorRequired] = useState(false)
  const { register, handleSubmit, formState: { errors } } = useForm<LoginForm>({ resolver: zodResolver(loginSchema), defaultValues: { rememberMe: true } })

  const onSubmit = async (data: LoginForm) => {
    setLoading(true)
    try {
      const requiresTwoFactor = await login(data.email, data.password, data.rememberMe, twoFactorRequired ? otp : undefined)
      if (requiresTwoFactor) {
        setTwoFactorRequired(true)
        setOtp('')
        toast.info('أدخل رمز التحقق بخطوتين للمتابعة')
        return
      }
      toast.success('تم تسجيل الدخول بنجاح')
      navigate('/dashboard')
    } catch (error: any) {
      const message = error?.response?.data?.detail || error?.response?.data?.error?.message || 'فشل تسجيل الدخول'
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="aegis-page min-h-screen lg:grid lg:grid-cols-[1.08fr_.92fr]">
      <section className="relative hidden min-h-screen overflow-hidden bg-[#07111f] px-10 py-9 text-white lg:flex lg:flex-col lg:justify-between xl:px-14">
        <div className="aegis-grid-bg pointer-events-none absolute inset-0 opacity-30" />
        <div className="pointer-events-none absolute -left-32 top-12 h-[480px] w-[480px] rounded-full bg-primary/20 blur-[120px]" />
        <div className="pointer-events-none absolute bottom-[-120px] right-[-80px] h-[440px] w-[440px] rounded-full bg-cyan-400/10 blur-[120px]" />
        <div className="relative flex items-center justify-between">
          <Brand dark />
          <span className="flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1.5 text-[10px] font-bold uppercase tracking-[.16em] text-emerald-300"><span className="aegis-live-dot" /> Enterprise</span>
        </div>
        <div className="relative max-w-2xl">
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="mb-6 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[.06] px-3 py-1.5 text-xs font-semibold text-white/70"><Sparkles className="h-3.5 w-3.5 text-primary" /> Continuous security assurance</motion.div>
          <motion.h1 initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: .06 }} className="text-5xl font-black leading-[1.03] tracking-[-.05em] xl:text-[4.5rem]">See the risk.<br /><span className="text-white/55">Prove the fix.</span><br />Control the outcome.</motion.h1>
          <motion.p initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: .12 }} className="mt-7 max-w-xl text-sm leading-7 text-white/50">A unified security assurance workspace for validation, evidence, attack-path intelligence and executive decisions.</motion.p>
          <div className="mt-9 grid max-w-xl grid-cols-3 gap-3">
            <Metric icon={<Radar />} value="15+" label="Validation engines" />
            <Metric icon={<Network />} value="10+" label="Assurance layers" />
            <Metric icon={<CheckCircle2 />} value="E2E" label="Evidence driven" />
          </div>
          <div className="mt-4 grid max-w-xl grid-cols-2 gap-3">
            <Status icon={<Activity />} title="Security posture" value="Continuously monitored" />
            <Status icon={<Fingerprint />} title="Evidence integrity" value="Auditable by design" />
          </div>
        </div>
        <div className="relative flex justify-between text-[10px] font-semibold tracking-wide text-white/30"><span>Continuous Assurance Fabric</span><span>Protected · Auditable · Evidence-backed</span></div>
      </section>

      <section className="relative flex min-h-screen items-center justify-center px-5 py-8 sm:px-8">
        <div className="pointer-events-none absolute right-0 top-0 h-96 w-96 rounded-full bg-primary/8 blur-[100px]" />
        <div className="relative w-full max-w-[430px]">
          <header className="mb-8 flex items-center justify-between">
            <div className="lg:hidden"><Brand /></div>
            <div className="ml-auto flex items-center gap-2">
              <button type="button" onClick={() => setLanguage(language === 'ar' ? 'en' : 'ar')} className="aegis-button aegis-button-secondary px-3 text-xs">{language === 'ar' ? 'English' : 'العربية'}</button>
              <button type="button" onClick={toggleTheme} className="aegis-button aegis-button-secondary w-10 px-0" aria-label="Toggle theme">{resolvedTheme === 'dark' ? <Sun className="mx-auto h-4 w-4" /> : <Moon className="mx-auto h-4 w-4" />}</button>
            </div>
          </header>

          <div className="mb-7">
            <div className="aegis-kicker mb-3 flex items-center gap-2"><span className="aegis-live-dot" /> Secure authentication</div>
            <h2 className="aegis-title text-3xl">{twoFactorRequired ? 'تحقق بخطوتين' : 'مرحبًا بعودتك'}</h2>
            <p className="aegis-subtitle mt-2">{twoFactorRequired ? 'أدخل الرمز المؤقت من تطبيق المصادقة لإكمال تسجيل الدخول.' : 'الوصول الآمن إلى مركز التحقيق والضمان الأمني في AegisScan.'}</p>
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="aegis-surface rounded-[1.35rem] p-5 sm:p-7">
            <div className="mb-6 flex items-center gap-3 rounded-xl border border-primary/15 bg-primary/[.045] p-3.5">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary"><Lock className="h-4 w-4" /></span>
              <div><p className="text-xs font-bold">Protected workspace</p><p className="mt-0.5 text-[10px] text-muted-foreground">RBAC · Audit trail · Evidence-first</p></div>
            </div>

            {!twoFactorRequired ? (
              <div className="space-y-5">
                <Field label="البريد الإلكتروني" error={errors.email?.message}>
                  <div className="relative"><Mail className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input {...register('email')} id="email" type="email" autoComplete="email" placeholder="user@company.com" disabled={loading} aria-invalid={Boolean(errors.email)} className={cn('aegis-input pl-11', errors.email && 'border-destructive')} /></div>
                </Field>
                <Field label="كلمة المرور" error={errors.password?.message}>
                  <div className="relative"><Lock className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input {...register('password')} id="password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" placeholder="••••••••" disabled={loading} aria-invalid={Boolean(errors.password)} className={cn('aegis-input pl-11 pr-12', errors.password && 'border-destructive')} /><button type="button" onClick={() => setShowPassword(v => !v)} className="aegis-focus-visible absolute right-3 top-1/2 -translate-y-1/2 rounded-md p-1 text-muted-foreground hover:text-foreground" aria-label={showPassword ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور'}>{showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button></div>
                </Field>
                <div className="flex items-center justify-between gap-3"><label className="flex items-center gap-2 text-xs text-muted-foreground"><input {...register('rememberMe')} type="checkbox" className="h-4 w-4 rounded border-border text-primary focus:ring-primary" />تذكرني</label><Link to="/forgot-password" className="aegis-focus-visible rounded text-xs font-bold text-primary hover:underline">نسيت كلمة المرور؟</Link></div>
              </div>
            ) : (
              <div>
                <label htmlFor="otp" className="mb-2 block text-xs font-bold">رمز التحقق</label>
                <div className="relative"><KeyRound className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input id="otp" value={otp} onChange={e => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" disabled={loading} autoFocus className="aegis-input py-4 pl-11 text-center text-xl font-black tracking-[.45em]" /></div>
                <p className="mt-2 text-xs text-muted-foreground">استخدم الرمز الظاهر في تطبيق المصادقة. لا تشاركه مع أي شخص.</p>
                <button type="button" onClick={() => { setTwoFactorRequired(false); setOtp('') }} className="mt-3 text-xs font-semibold text-primary hover:underline">العودة إلى بيانات الدخول</button>
              </div>
            )}

            <button type="submit" disabled={loading || (twoFactorRequired && otp.length !== 6)} className="aegis-button aegis-button-primary mt-6 flex w-full items-center justify-center gap-2 py-3.5">{loading ? <><span className="h-4 w-4 animate-spin rounded-full border-2 border-primary-foreground/30 border-t-primary-foreground" /> جاري التحقق...</> : twoFactorRequired ? <>تأكيد الرمز <KeyRound className="h-4 w-4" /></> : <>دخول إلى المنصة <ArrowRight className="h-4 w-4" /></>}</button>
          </form>

          <div className="mt-4 grid grid-cols-3 gap-2"><Trust icon={<Shield />} label="RBAC" /><Trust icon={<Lock />} label="Secure" /><Trust icon={<Globe2 />} label="RTL / LTR" /></div>
          <p className="mt-6 text-center text-sm text-muted-foreground">ليس لديك حساب؟ <Link to="/register" className="font-bold text-primary hover:underline">إنشاء حساب جديد</Link></p>
        </div>
      </section>
    </main>
  )
}

function Brand({ dark = false }: { dark?: boolean }) {
  return <div className="flex items-center gap-3"><span className={cn('grid h-10 w-10 place-items-center rounded-xl border', dark ? 'border-white/15 bg-white/10' : 'border-primary/15 bg-primary/8')}><Shield className={cn('h-5 w-5', dark ? 'text-white' : 'text-primary')} /></span><div><div className={cn('font-black tracking-tight', dark ? 'text-lg' : 'text-base')}>AegisScan</div><div className={cn('text-[9px] uppercase tracking-[.2em]', dark ? 'text-white/35' : 'text-muted-foreground')}>Security Assurance Platform</div></div></div>
}
function Metric({ icon, value, label }: { icon: React.ReactNode; value: string; label: string }) { return <div className="rounded-xl border border-white/10 bg-white/[.045] p-3.5"><div className="flex items-center gap-2 text-[10px] text-white/40">{React.cloneElement(icon as React.ReactElement<{ className?: string }>, { className: 'h-3.5 w-3.5' })}{label}</div><div className="mt-1.5 text-xl font-black">{value}</div></div> }
function Status({ icon, title, value }: { icon: React.ReactNode; title: string; value: string }) { return <div className="flex items-center gap-3 rounded-xl border border-white/10 bg-white/[.03] px-3.5 py-3"><span className="text-white/45">{React.cloneElement(icon as React.ReactElement<{ className?: string }>, { className: 'h-4 w-4' })}</span><div><div className="text-[9px] font-bold uppercase tracking-wider text-white/30">{title}</div><div className="text-[11px] text-white/55">{value}</div></div></div> }
function Trust({ icon, label }: { icon: React.ReactNode; label: string }) { return <div className="flex items-center justify-center gap-1.5 rounded-lg border bg-muted/30 px-2 py-2.5 text-[10px] font-bold text-muted-foreground">{React.cloneElement(icon as React.ReactElement<{ className?: string }>, { className: 'h-3.5 w-3.5' })}{label}</div> }
function Field({ label, error, children }: { label: string; error?: string; children: React.ReactNode }) { return <div><label className="mb-2 block text-xs font-bold">{label}</label>{children}{error && <p className="mt-1.5 text-xs font-medium text-destructive">{error}</p>}</div> }
