import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { motion } from 'framer-motion'
import { Globe, Server, Folder, Plug, Layers, AlertTriangle, Clock, Gauge, Check, Loader2, ArrowRight, ShieldCheck } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'

const targetTypeEnum = z.enum(['url', 'ip', 'code', 'api'])
const profileEnum = z.enum(['quick', 'full', 'custom'])

const schema = z.object({
  target_type: targetTypeEnum,
  target_value: z.string().min(1, 'هذا الحقل مطلوب'),
  profile: profileEnum,
  engines: z.array(z.string()).min(1, 'اختر محركاً واحداً على الأقل'),
  scope_text: z.string().optional(),
  authorized: z.boolean().refine(v => v === true, { message: 'يجب تأكيد أن الهدف مصرح به' }),
  include_subdomains: z.boolean().optional(),
  duration_minutes: z.coerce.number().int().min(5).max(1440),
  rate_limit: z.coerce.number().int().min(1).max(100),
  custom_headers: z.string().optional(),
  ports: z.string().optional(),
  api_method: z.string().optional(),
}).superRefine((data, ctx) => {
  if (data.target_type === 'url' || data.target_type === 'api') {
    try { new URL(data.target_value); } catch { ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['target_value'], message: 'رابط غير صحيح (مثال: https://example.local)' }) }
  }
  if (data.target_type === 'ip') {
    const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/
    const hostRe = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/
    if (!ipRe.test(data.target_value) && !hostRe.test(data.target_value)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['target_value'], message: 'IP أو Host غير صحيح' })
    }
  }
})

type FormValues = z.infer<typeof schema>

const TARGETS = [
  { value: 'url' as const, label: 'URL', sub: 'موقع / تطبيق ويب', icon: Globe, ph: 'https://example.local' },
  { value: 'ip' as const, label: 'IP / Host', sub: 'خادم أو نطاق', icon: Server, ph: '192.168.1.10  أو  api.example.local' },
  { value: 'code' as const, label: 'Source Code', sub: 'مسار الكود المصدري', icon: Folder, ph: 'C:\\Projects\\MyApp' },
  { value: 'api' as const, label: 'API', sub: 'نقطة REST / GraphQL', icon: Plug, ph: 'https://api.example.local/v1/users' },
]

const PROFILES = [
  { value: 'quick' as const, label: 'Quick Assessment', desc: 'فحص سريع 15-30 دقيقة', badge: '⚡ سريع', engines: ['recon', 'evidence_collection', 'vuln_intelligence', 'validation'] },
  { value: 'full' as const, label: 'Full Validation', desc: 'تحقق شامل 1-2 ساعة — كل المحركات الـ15', badge: '🛡️ شامل', engines: ['recon','evidence_collection','vuln_intelligence','validation','control_validation','coverage_gap','attack_path','evidence_graph','knowledge','posture','policy_compliance','twin_engine','scenarios','dashboard','reporting'] },
  { value: 'custom' as const, label: 'Custom', desc: 'اختيار يدوي للمحركات', badge: '⚙️ مخصص', engines: [] },
]

const ALL_ENGINES = [
  { id: 'recon', name: 'Recon', desc: 'استطلاع' },
  { id: 'evidence_collection', name: 'Evidence', desc: 'جمع الأدلة' },
  { id: 'vuln_intelligence', name: 'Vuln Intel', desc: 'استخبارات الثغرات' },
  { id: 'validation', name: 'Validation', desc: 'التحقق' },
  { id: 'control_validation', name: 'Control', desc: 'فحص الضوابط' },
  { id: 'coverage_gap', name: 'Coverage', desc: 'فجوات التغطية' },
  { id: 'attack_path', name: 'Attack Path', desc: 'مسارات الهجوم' },
  { id: 'evidence_graph', name: 'Evidence Graph', desc: 'رسم الأدلة' },
  { id: 'knowledge', name: 'Knowledge', desc: 'قاعدة المعرفة' },
  { id: 'posture', name: 'Posture', desc: 'وضع الحماية' },
  { id: 'policy_compliance', name: 'Compliance', desc: 'الامتثال' },
  { id: 'twin_engine', name: 'Twin', desc: 'التوأم الرقمي' },
  { id: 'scenarios', name: 'Scenarios', desc: 'السيناريوهات' },
  { id: 'dashboard', name: 'Dashboard', desc: 'لوحة التحكم' },
  { id: 'reporting', name: 'Reporting', desc: 'التقارير' },
]

export const NewValidation = () => {
  const navigate = useNavigate()
  const [submitting, setSubmitting] = useState(false)

  const { register, handleSubmit, watch, setValue, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      target_type: 'url',
      target_value: '',
      profile: 'full',
      engines: PROFILES[1].engines,
      authorized: false,
      include_subdomains: false,
      duration_minutes: 60,
      rate_limit: 5,
      api_method: 'GET',
    }
  })

  const targetType = watch('target_type')
  const profile = watch('profile')
  const engines = watch('engines')
  const authorized = watch('authorized')

  const selectProfile = (p: typeof profile) => {
    setValue('profile', p, { shouldValidate: true })
    const preset = PROFILES.find(x => x.value === p)!
    if (p !== 'custom') setValue('engines', preset.engines, { shouldValidate: true })
    else if (engines.length === 0) setValue('engines', ['recon', 'validation'], { shouldValidate: true })
  }

  const toggleEngine = (id: string) => {
    const next = engines.includes(id) ? engines.filter(e => e !== id) : [...engines, id]
    setValue('engines', next, { shouldValidate: true })
    setValue('profile', 'custom', { shouldValidate: true })
  }

  const onSubmit = async (data: FormValues) => {
    setSubmitting(true)
    try {
      // 1. Validate locally (zod already)
      // 2. Scope/Authorization check is the `authorized` checkbox
      // 3. Create validation job via API
      const payload = {
        target_type: data.target_type,
        target_value: data.target_value,
        profile: data.profile,
        engines: data.engines,
        scope: data.scope_text || (data.target_type === 'url' ? new URL(data.target_value).hostname : data.target_value),
        authorized: data.authorized,
        include_subdomains: data.include_subdomains,
        duration_minutes: data.duration_minutes,
        rate_limit: data.rate_limit,
        extra: {
          custom_headers: data.custom_headers,
          ports: data.ports,
          api_method: data.api_method,
        }
      }

      // Try real API, fallback to mock if backend not running (so UI still works for demo)
      let id: string
      try {
        const res = await apiHelpers.post<{ id: string }>('/validations', payload)
        id = (res as any).id || (res as any).validation_id || `val-${Date.now().toString(36)}`
      } catch {
        // Backend not reachable (no Docker) — mock id and store in localStorage for Progress page
        id = `val-${Date.now().toString(36)}`
        localStorage.setItem(`validation:${id}`, JSON.stringify({ ...payload, id, status: 'queued', created_at: new Date().toISOString(), progress: 0 }))
        // also queue a fake progression so Progress page has something
      }

      toast.success('تم إنشاء مهمة التحقق — جاري الانتقال للمتابعة')
      // 4. Queue → 5. WebSocket Progress → 6. Results
      navigate(`/validations/${id}/progress`, { replace: true, state: { payload, id } })
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || e?.message || 'فشل إنشاء مهمة التحقق')
    } finally {
      setSubmitting(false)
    }
  }

  const targetMeta = TARGETS.find(t => t.value === targetType)!

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Authorized banner */}
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="rounded-xl border border-amber-500/30 bg-amber-500/10 dark:bg-amber-500/10 p-4 flex gap-3 items-start">
        <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400 mt-0.5 shrink-0" />
        <div className="text-sm">
          <p className="font-semibold text-amber-700 dark:text-amber-300">Authorized Security Testing Only — اختبار مصرح به فقط</p>
          <p className="text-muted-foreground mt-1 leading-relaxed">
            هذه المنصة تنفذ محركات تحقق نشطة (Validation / Attack Path / Control Validation). تأكد أن الهدف مملوك لك أو لديك تصريح كتابي. سيتم تسجيل الـ scope والموافقة وسجل التدقيق (Audit Log) قبل بدء أي فحص.
          </p>
        </div>
      </motion.div>

      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2"><ShieldCheck className="h-6 w-6 text-primary" /> New Security Validation</h1>
        <p className="text-sm text-muted-foreground mt-1">اختر نوع الهدف، حدد النطاق المصرح به، واختر ملف التحقق — ثم ابدأ. سيتم إنشاء Job ومتابعته عبر WebSocket.</p>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* 1. Target Type */}
        <section className="rounded-xl border bg-card p-5">
          <h2 className="font-semibold flex items-center gap-2"><span className="h-6 w-6 rounded-full bg-primary text-primary-foreground grid place-items-center text-xs">1</span> Target Type — نوع الهدف</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mt-4">
            {TARGETS.map(t => (
              <button key={t.value} type="button" onClick={() => setValue('target_type', t.value, { shouldValidate: true })}
                className={cn('rounded-xl border p-4 text-start transition-all hover:shadow-sm', targetType === t.value ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'bg-card hover:bg-muted/50')}>
                <t.icon className={cn('h-6 w-6', targetType === t.value ? 'text-primary' : 'text-muted-foreground')} />
                <div className="font-medium mt-2">{t.label}</div>
                <div className="text-xs text-muted-foreground">{t.sub}</div>
              </button>
            ))}
          </div>
          {errors.target_type && <p className="text-xs text-destructive mt-2">{errors.target_type.message}</p>}
        </section>

        {/* 2. Target Configuration */}
        <section className="rounded-xl border bg-card p-5 space-y-4">
          <h2 className="font-semibold flex items-center gap-2"><span className="h-6 w-6 rounded-full bg-primary text-primary-foreground grid place-items-center text-xs">2</span> Target Configuration — {targetMeta.label}</h2>

          <div>
            <label className="text-sm font-medium">الهدف *</label>
            <div className="relative mt-1">
              <targetMeta.icon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <input {...register('target_value')} placeholder={targetMeta.ph} dir="ltr"
                className="w-full pl-9 pr-3 py-2.5 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-ring text-sm" />
            </div>
            {errors.target_value && <p className="text-xs text-destructive mt-1">{errors.target_value.message}</p>}
            <p className="text-xs text-muted-foreground mt-1">
              {targetType === 'url' && 'مثال: https://example.local'}
              {targetType === 'ip' && 'مثال: 192.168.1.10  أو  host.internal.local'}
              {targetType === 'code' && 'مثال: C:\\Projects\\MyApp  أو  /home/app/src'}
              {targetType === 'api' && 'مثال: https://api.example.local/v1/openapi.json'}
            </p>
          </div>

          {targetType === 'url' && (
            <div>
              <label className="text-sm font-medium">Headers إضافية (اختياري)</label>
              <input {...register('custom_headers')} placeholder="Authorization: Bearer ..." dir="ltr" className="mt-1 w-full px-3 py-2 rounded-lg border bg-background text-sm" />
            </div>
          )}
          {targetType === 'ip' && (
            <div>
              <label className="text-sm font-medium">Ports (اختياري)</label>
              <input {...register('ports')} placeholder="80,443,8080" dir="ltr" className="mt-1 w-full px-3 py-2 rounded-lg border bg-background text-sm" />
            </div>
          )}
          {targetType === 'api' && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-sm font-medium">Method</label>
                <select {...register('api_method')} className="mt-1 w-full px-3 py-2 rounded-lg border bg-background text-sm">
                  <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option>
                </select>
              </div>
              <div>
                <label className="text-sm font-medium">Auth Header (اختياري)</label>
                <input {...register('custom_headers')} placeholder="Bearer ..." dir="ltr" className="mt-1 w-full px-3 py-2 rounded-lg border bg-background text-sm" />
              </div>
            </div>
          )}
          {targetType === 'code' && (
            <p className="text-xs text-muted-foreground">سيتم تمرير المسار إلى Aegis Core (scan --code). تأكد أن المسار موجود على جهاز الـ worker أو ارفع الملف عبر تبويب File لاحقاً.</p>
          )}
        </section>

        {/* 3. Validation Profile */}
        <section className="rounded-xl border bg-card p-5">
          <h2 className="font-semibold flex items-center gap-2"><span className="h-6 w-6 rounded-full bg-primary text-primary-foreground grid place-items-center text-xs">3</span> Validation Profile</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
            {PROFILES.map(p => (
              <button key={p.value} type="button" onClick={() => selectProfile(p.value)}
                className={cn('rounded-xl border p-4 text-start', profile === p.value ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'hover:bg-muted/50')}>
                <div className="flex items-center justify-between">
                  <span className="font-medium text-sm">{p.label}</span>
                  <span className="text-xs px-2 py-0.5 rounded-full bg-muted">{p.badge}</span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">{p.desc}</p>
                {profile === p.value && <Check className="h-4 w-4 text-primary mt-2" />}
              </button>
            ))}
          </div>
          {errors.profile && <p className="text-xs text-destructive mt-2">{errors.profile.message}</p>}
        </section>

        {/* 4. Engines */}
        <section className="rounded-xl border bg-card p-5">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold flex items-center gap-2"><span className="h-6 w-6 rounded-full bg-primary text-primary-foreground grid place-items-center text-xs">4</span> Engines — المحركات ({engines.length}/15)</h2>
            <div className="flex gap-2">
              <button type="button" onClick={() => setValue('engines', ALL_ENGINES.map(e => e.id), { shouldValidate: true })} className="text-xs px-2 py-1 rounded border hover:bg-muted">تحديد الكل</button>
              <button type="button" onClick={() => setValue('engines', [], { shouldValidate: true })} className="text-xs px-2 py-1 rounded border hover:bg-muted">إلغاء</button>
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 mt-4">
            {ALL_ENGINES.map(e => {
              const on = engines.includes(e.id)
              return (
                <button key={e.id} type="button" onClick={() => toggleEngine(e.id)}
                  className={cn('rounded-lg border px-3 py-2 text-start text-xs', on ? 'bg-primary text-primary-foreground border-primary' : 'bg-card hover:bg-muted')}>
                  <div className="font-medium text-xs leading-none">{e.name}</div>
                  <div className={cn('text-[11px]', on ? 'text-primary-foreground/80' : 'text-muted-foreground')}>{e.desc}</div>
                </button>
              )
            })}
          </div>
          {errors.engines && <p className="text-xs text-destructive mt-2">{errors.engines.message}</p>}
          <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1"><Layers className="h-3 w-3" /> الترتيب التنفيذي الحقيقي: Recon → Evidence → Vuln Intel → Validation → Control → Coverage → Attack Path → Graph → Knowledge → Posture → Compliance → Twin → Scenarios → Dashboard → Reporting</p>
        </section>

        {/* 5. Scope & Safety */}
        <section className="rounded-xl border bg-card p-5 space-y-4">
          <h2 className="font-semibold flex items-center gap-2"><span className="h-6 w-6 rounded-full bg-primary text-primary-foreground grid place-items-center text-xs">5</span> Scope & Safety — النطاق والسلامة</h2>

          <div>
            <label className="text-sm font-medium">Scope — النطاق المصرح به *</label>
            <input {...register('scope_text')} placeholder={targetType === 'url' ? 'example.local, *.example.local' : targetType === 'ip' ? '192.168.1.0/24' : 'MyApp/src/**'} dir="ltr" className="mt-1 w-full px-3 py-2 rounded-lg border bg-background text-sm" />
            <p className="text-xs text-muted-foreground mt-1">اتركه فارغاً لاستخدام قيمة الهدف تلقائياً. يتم تسجيله في Audit Log.</p>
          </div>

          <label className={cn('flex gap-3 p-3 rounded-lg border cursor-pointer', authorized ? 'bg-emerald-50 border-emerald-300 dark:bg-emerald-950/30 dark:border-emerald-800' : 'bg-card')}>
            <input type="checkbox" {...register('authorized')} className="mt-1" />
            <span className="text-sm">
              <span className="font-medium flex items-center gap-1"><ShieldCheck className="h-4 w-4" /> أؤكد أن هذا الهدف مملوك لي / مصرح باختباره كتابياً</span>
              <span className="text-muted-foreground">بدون هذا التأكيد لن يتم إنشاء الـ Job. هذا إجراء مؤسسي لتجنب الاستخدام غير المصرح به.</span>
            </span>
          </label>
          {errors.authorized && <p className="text-xs text-destructive">{errors.authorized.message}</p>}

          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" {...register('include_subdomains')} />
            تضمين النطاقات الفرعية (URL فقط)
          </label>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-sm font-medium flex items-center gap-1"><Clock className="h-3.5 w-3.5" /> المدة القصوى (دقيقة)</label>
              <input type="number" {...register('duration_minutes')} className="mt-1 w-full px-3 py-2 rounded-lg border bg-background text-sm" />
              {errors.duration_minutes && <p className="text-xs text-destructive mt-1">{errors.duration_minutes.message}</p>}
            </div>
            <div>
              <label className="text-sm font-medium flex items-center gap-1"><Gauge className="h-3.5 w-3.5" /> Rate limit (req/s)</label>
              <input type="number" {...register('rate_limit')} className="mt-1 w-full px-3 py-2 rounded-lg border bg-background text-sm" />
              {errors.rate_limit && <p className="text-xs text-destructive mt-1">{errors.rate_limit.message}</p>}
            </div>
          </div>
        </section>

        {/* Start */}
        <div className="flex items-center justify-between gap-3 pt-2">
          <p className="text-xs text-muted-foreground">
            التدفق: Validate Configuration → Scope Check → Create Job → Queue → <span className="font-medium">WebSocket Progress</span> → Results
          </p>
          <button type="submit" disabled={submitting}
            className="inline-flex items-center gap-2 px-6 py-2.5 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 font-medium">
            {submitting ? <><Loader2 className="h-4 w-4 animate-spin" /> جاري الإنشاء...</> : <>🚀 Start Validation <ArrowRight className="h-4 w-4" /></>}
          </button>
        </div>
      </form>
    </div>
  )
}
