import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { motion } from 'framer-motion'
import { useAuthStore } from '@/stores/authStore'
import { useThemeStore } from '@/stores/themeStore'
import { useLanguageStore } from '@/stores/languageStore'
import { Activity, ArrowRight, CheckCircle2, Globe2, Lock, Mail, Moon, Radar, Shield, Sparkles, Sun, Eye, EyeOff } from 'lucide-react'
import { cn } from '@/utils/cn'

const loginSchema = z.object({ email: z.string().email('البريد الإلكتروني غير صحيح'), password: z.string().min(8, 'كلمة المرور يجب أن تكون 8 أحرف على الأقل'), rememberMe: z.boolean().optional() })
type LoginForm = z.infer<typeof loginSchema>

export const Login = () => {
  const navigate = useNavigate(); const { login } = useAuthStore(); const { resolvedTheme, toggleTheme } = useThemeStore(); const { language, setLanguage } = useLanguageStore()
  const [showPassword, setShowPassword] = useState(false); const [loading, setLoading] = useState(false)
  const { register, handleSubmit, formState: { errors } } = useForm<LoginForm>({ resolver: zodResolver(loginSchema), defaultValues: { rememberMe: true } })
  const onSubmit = async (data: LoginForm) => { setLoading(true); try { await login(data.email, data.password, data.rememberMe); toast.success('مرحباً بك في AegisScan'); navigate('/dashboard') } catch (error: any) { toast.error(error.response?.data?.error?.message || 'فشل تسجيل الدخول') } finally { setLoading(false) } }

  return <div className="min-h-screen overflow-hidden bg-background lg:grid lg:grid-cols-[1.08fr_.92fr]">
    <section className="relative hidden min-h-screen overflow-hidden border-r bg-gradient-to-br from-primary via-primary/90 to-primary/70 p-10 text-primary-foreground lg:flex lg:flex-col lg:justify-between">
      <div className="pointer-events-none absolute inset-0 opacity-20 [background-image:linear-gradient(rgba(255,255,255,.18)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,.18)_1px,transparent_1px)] [background-size:42px_42px]" />
      <div className="pointer-events-none absolute left-1/2 top-1/2 h-[620px] w-[620px] -translate-x-1/2 -translate-y-1/2 rounded-full border border-white/15" />
      <div className="pointer-events-none absolute left-1/2 top-1/2 h-[420px] w-[420px] -translate-x-1/2 -translate-y-1/2 rounded-full border border-white/10" />
      <div className="relative flex items-center justify-between"><div className="flex items-center gap-3"><span className="grid h-11 w-11 place-items-center rounded-2xl border border-white/15 bg-white/10 shadow-xl"><Shield className="h-5 w-5" /></span><div><div className="text-xl font-black tracking-tight">AegisScan</div><div className="text-[10px] uppercase tracking-[.22em] text-white/60">Security Assurance Platform</div></div></div><div className="rounded-full border border-white/15 bg-white/10 px-3 py-1 text-[10px] font-semibold">ENTERPRISE</div></div>
      <div className="relative max-w-xl"><motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} className="mb-5 inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/10 px-3 py-1.5 text-xs"><Sparkles className="h-3.5 w-3.5" /> Continuous security validation</motion.div><motion.h1 initial={{ opacity: 0, y: 22 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: .08 }} className="text-5xl font-black leading-[1.04] tracking-tight xl:text-6xl">See the risk.<br />Prove the fix.<br />Control the outcome.</motion.h1><motion.p initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: .16 }} className="mt-6 max-w-lg text-base leading-7 text-white/78">Investigate attack paths, correlate evidence, measure remediation, and turn security signals into executive decisions.</motion.p><div className="mt-8 grid grid-cols-3 gap-3"><Signal label="Validation engines" value="15+" icon={<Radar className="h-4 w-4" />} /><Signal label="Assurance layers" value="10+" icon={<Activity className="h-4 w-4" />} /><Signal label="Evidence driven" value="E2E" icon={<CheckCircle2 className="h-4 w-4" />} /></div></div>
      <div className="relative flex items-center justify-between text-[10px] text-white/55"><span>Continuous Assurance Fabric</span><span>Protected • Auditable • Evidence-backed</span></div>
    </section>

    <section className="flex min-h-screen items-center justify-center p-5 sm:p-8"><div className="w-full max-w-md">
      <div className="mb-8 flex items-center justify-between lg:justify-end"><div className="flex items-center gap-2 lg:hidden"><span className="grid h-9 w-9 place-items-center rounded-xl border bg-muted"><Shield className="h-4 w-4 text-primary" /></span><span className="font-bold">AegisScan</span></div><div className="flex items-center gap-2"><button onClick={() => setLanguage(language === 'ar' ? 'en' : 'ar')} className="rounded-lg border bg-muted/60 px-3 py-1.5 text-xs font-semibold hover:bg-muted">{language === 'ar' ? 'English' : 'العربية'}</button><button onClick={toggleTheme} className="rounded-lg border bg-muted/60 p-2 hover:bg-muted" aria-label="Toggle theme">{resolvedTheme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}</button></div></div>
      <div className="mb-8"><div className="mb-4 inline-flex items-center gap-2 rounded-full border bg-muted/50 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground"><span className="h-1.5 w-1.5 rounded-full bg-emerald-500" /> Secure access</div><h2 className="text-3xl font-black tracking-tight">مرحبًا بعودتك</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">سجّل الدخول إلى مركز التحقيق والضمان الأمني في AegisScan.</p></div>
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-5 rounded-2xl border bg-card p-5 shadow-sm sm:p-6">
        <Field label="البريد الإلكتروني" error={errors.email?.message}><div className="relative"><Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input {...register('email')} id="email" type="email" autoComplete="email" placeholder="user@company.com" disabled={loading} className={cn('w-full rounded-xl border bg-background py-3 pl-10 pr-4 text-sm outline-none transition focus:border-primary focus:ring-4 focus:ring-primary/10', errors.email && 'border-destructive')} /></div></Field>
        <Field label="كلمة المرور" error={errors.password?.message}><div className="relative"><Lock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input {...register('password')} id="password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" placeholder="••••••••" disabled={loading} className={cn('w-full rounded-xl border bg-background py-3 pl-10 pr-11 text-sm outline-none transition focus:border-primary focus:ring-4 focus:ring-primary/10', errors.password && 'border-destructive')} /><button type="button" onClick={() => setShowPassword(v => !v)} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" aria-label={showPassword ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور'}>{showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button></div></Field>
        <div className="flex items-center justify-between gap-3"><label className="flex items-center gap-2 text-sm text-muted-foreground"><input {...register('rememberMe')} type="checkbox" className="h-4 w-4 rounded border-border text-primary focus:ring-primary" />تذكرني</label><Link to="/forgot-password" className="text-xs font-semibold text-primary hover:underline">نسيت كلمة المرور؟</Link></div>
        <button type="submit" disabled={loading} className="flex w-full items-center justify-center gap-2 rounded-xl bg-primary px-4 py-3 font-semibold text-primary-foreground shadow-lg shadow-primary/15 transition hover:-translate-y-0.5 hover:bg-primary/90 disabled:pointer-events-none disabled:opacity-60">{loading ? <><span className="h-4 w-4 animate-spin rounded-full border-2 border-primary-foreground/30 border-t-primary-foreground" /> جاري تسجيل الدخول...</> : <>دخول إلى المنصة <ArrowRight className="h-4 w-4" /></>}</button>
      </form>
      <div className="mt-6 grid grid-cols-3 gap-2"><TrustItem icon={<Shield className="h-4 w-4" />} label="RBAC" /><TrustItem icon={<Lock className="h-4 w-4" />} label="Secure" /><TrustItem icon={<Globe2 className="h-4 w-4" />} label="RTL / LTR" /></div>
      <p className="mt-7 text-center text-sm text-muted-foreground">ليس لديك حساب؟ <Link to="/register" className="font-semibold text-primary hover:underline">إنشاء حساب جديد</Link></p>
    </div></section>
  </div>
}
function Signal({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) { return <div className="rounded-2xl border border-white/10 bg-white/10 p-4 backdrop-blur"><div className="flex items-center gap-2 text-[10px] text-white/55">{icon}{label}</div><div className="mt-2 text-2xl font-black">{value}</div></div> }
function TrustItem({ icon, label }: { icon: React.ReactNode; label: string }) { return <div className="flex items-center justify-center gap-2 rounded-xl border bg-muted/30 px-3 py-2.5 text-[10px] font-semibold text-muted-foreground">{icon}{label}</div> }
function Field({ label, error, children }: { label: string; error?: string; children: React.ReactNode }) { return <div><label className="mb-2 block text-xs font-semibold">{label}</label>{children}{error && <p className="mt-1.5 text-xs text-destructive">{error}</p>}</div> }
