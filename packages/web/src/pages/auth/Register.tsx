import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { motion } from 'framer-motion'
import { useAuthStore } from '@/stores/authStore'
import { useThemeStore } from '@/stores/themeStore'
import { useLanguageStore } from '@/stores/languageStore'
import { Shield, Mail, Lock, User, Phone, Eye, EyeOff, ArrowRight, Globe } from 'lucide-react'
import { cn } from '@/utils/cn'

const registerSchema = z.object({
  email: z.string().email('البريد الإلكتروني غير صحيح'),
  password: z.string().min(8, 'كلمة المرور يجب أن تكون 8 أحرف على الأقل'),
  password_confirm: z.string(),
  first_name: z.string().min(2, 'الاسم يجب أن يكون حرفين على الأقل'),
  last_name: z.string().min(2, 'اللقب يجب أن يكون حرفين على الأقل'),
  phone: z.string().optional(),
}).refine(data => data.password === data.password_confirm, {
  message: 'كلمات المرور غير متطابقة',
  path: ['password_confirm'],
})

type RegisterForm = z.infer<typeof registerSchema>

export const Register = () => {
  const navigate = useNavigate()
  const { register: registerUser } = useAuthStore()
  const { resolvedTheme, toggleTheme } = useThemeStore()
  const { language, setLanguage } = useLanguageStore()
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)

  const { register, handleSubmit, formState: { errors } } = useForm<RegisterForm>({ resolver: zodResolver(registerSchema) })

  const onSubmit = async (data: RegisterForm) => {
    setLoading(true)
    try {
      await registerUser({ email: data.email, password: data.password, password_confirm: data.password_confirm, first_name: data.first_name, last_name: data.last_name, phone: data.phone })
      toast.success('تم إنشاء الحساب بنجاح')
      navigate('/dashboard')
    } catch (error: any) {
      toast.error(error.response?.data?.error?.message || error.response?.data?.detail || 'فشل إنشاء الحساب')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex">
      <div className="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-primary via-primary/90 to-primary/70 text-primary-foreground p-12 flex-col justify-between relative overflow-hidden">
        <div className="flex items-center gap-2"><Shield className="h-10 w-10" /><span className="text-2xl font-bold">AegisScan</span></div>
        <div className="flex-1 flex flex-col justify-center items-start max-w-md"><motion.h1 initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="text-5xl font-bold leading-tight mb-6">انضم إلى منصة التحقق الأمني</motion.h1><motion.p initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="text-lg opacity-90">ابدأ في حماية أصولك الرقمية اليوم مع أكثر من 15 محرك تحقق متقدم</motion.p></div>
      </div>
      <div className="flex-1 flex items-center justify-center p-8 bg-background"><motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="w-full max-w-md">
        <div className="flex items-center justify-between mb-8"><div className="flex items-center gap-2"><Shield className="h-8 w-8 text-primary" /><span className="text-xl font-bold">AegisScan</span></div><Link to="/login" className="text-sm text-muted-foreground hover:text-foreground">تسجيل الدخول</Link></div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}><h2 className="text-2xl font-bold mb-2">إنشاء حساب جديد</h2><p className="text-muted-foreground mb-8">املأ النموذج أدناه لبدء رحلتك مع AegisScan</p>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
            <div className="grid grid-cols-2 gap-4">
              <div><label htmlFor="first_name" className="block text-sm font-medium mb-2">الاسم الأول</label><div className="relative"><User className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" /><input {...register('first_name')} id="first_name" type="text" className={cn('w-full pl-10 pr-4 py-3 bg-input border border-border rounded-lg','focus:outline-none focus:ring-2 focus:ring-ring',errors.first_name && 'border-destructive focus:ring-destructive')} placeholder="أحمد" /></div>{errors.first_name && <p className="mt-1 text-sm text-destructive">{errors.first_name.message}</p>}</div>
              <div><label htmlFor="last_name" className="block text-sm font-medium mb-2">اللقب</label><div className="relative"><User className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" /><input {...register('last_name')} id="last_name" type="text" className={cn('w-full pl-10 pr-4 py-3 bg-input border border-border rounded-lg','focus:outline-none focus:ring-2 focus:ring-ring',errors.last_name && 'border-destructive focus:ring-destructive')} placeholder="العلي" /></div>{errors.last_name && <p className="mt-1 text-sm text-destructive">{errors.last_name.message}</p>}</div>
            </div>
            <div><label htmlFor="email" className="block text-sm font-medium mb-2">البريد الإلكتروني</label><div className="relative"><Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" /><input {...register('email')} id="email" type="email" autoComplete="email" className={cn('w-full pl-10 pr-4 py-3 bg-input border border-border rounded-lg','focus:outline-none focus:ring-2 focus:ring-ring',errors.email && 'border-destructive focus:ring-destructive')} placeholder="user@company.com" /></div>{errors.email && <p className="mt-1 text-sm text-destructive">{errors.email.message}</p>}</div>
            <div><label htmlFor="phone" className="block text-sm font-medium mb-2">رقم الهاتف (اختياري)</label><div className="relative"><Phone className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" /><input {...register('phone')} id="phone" type="tel" className="w-full pl-10 pr-4 py-3 bg-input border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-ring" placeholder="+966 50 123 4567" /></div></div>
            <div><label htmlFor="password" className="block text-sm font-medium mb-2">كلمة المرور</label><div className="relative"><Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" /><input {...register('password')} id="password" type={showPassword ? 'text' : 'password'} autoComplete="new-password" className={cn('w-full pl-10 pr-12 py-3 bg-input border border-border rounded-lg','focus:outline-none focus:ring-2 focus:ring-ring',errors.password && 'border-destructive focus:ring-destructive')} placeholder="••••••••" /><button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">{showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}</button></div>{errors.password && <p className="mt-1 text-sm text-destructive">{errors.password.message}</p>}</div>
            <div><label htmlFor="password_confirm" className="block text-sm font-medium mb-2">تأكيد كلمة المرور</label><div className="relative"><Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" /><input {...register('password_confirm')} id="password_confirm" type={showPassword ? 'text' : 'password'} autoComplete="new-password" className={cn('w-full pl-10 pr-4 py-3 bg-input border border-border rounded-lg','focus:outline-none focus:ring-2 focus:ring-ring',errors.password_confirm && 'border-destructive focus:ring-destructive')} placeholder="••••••••" /></div>{errors.password_confirm && <p className="mt-1 text-sm text-destructive">{errors.password_confirm.message}</p>}</div>
            <button type="submit" disabled={loading} className={cn('w-full py-3 px-4 rounded-lg font-medium transition-colors','bg-primary text-primary-foreground hover:bg-primary/90','disabled:opacity-50 disabled:cursor-not-allowed','flex items-center justify-center gap-2')}>{loading ? <><svg className="animate-spin h-5 w-5" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>جاري إنشاء الحساب...</> : <>إنشاء الحساب<ArrowRight className="h-4 w-4" /></>}</button>
          </form>
          <p className="mt-8 text-center text-sm text-muted-foreground">لديك حساب؟ <Link to="/login" className="text-primary font-medium hover:underline">تسجيل الدخول</Link></p>
          <p className="mt-6 text-center text-xs text-muted-foreground">بالضغط على "إنشاء الحساب"، أنت توافق على شروط الخدمة وسياسة الخصوصية الخاصة بـAegisScan.</p>
        </motion.div>
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.5, delay: 0.4 }} className="mt-10 grid grid-cols-3 gap-4 text-center text-xs text-muted-foreground"><div className="flex flex-col items-center gap-1"><Shield className="h-5 w-5 mx-auto" /><span>RBAC متقدم</span></div><div className="flex flex-col items-center gap-1"><Globe className="h-5 w-5 mx-auto" /><span>دعم RTL</span></div><div className="flex flex-col items-center gap-1"><Lock className="h-5 w-5 mx-auto" /><span>2FA متاح</span></div></motion.div>
      </motion.div></div>
    </div>
  )
}
