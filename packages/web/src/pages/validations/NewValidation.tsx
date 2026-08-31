import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { useQuery } from '@tanstack/react-query'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { motion } from 'framer-motion'
import { AlertTriangle, ArrowRight, Check, Clock, Gauge, Globe, Layers, Loader2, Plug, Server, ShieldCheck, X } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'

const schema = z.object({
  project_id: z.string().min(1, 'اختر المشروع أولاً'),
  target_type: z.enum(['url', 'ip', 'code', 'api']),
  target_value: z.string().trim().min(1, 'هذا الحقل مطلوب'),
  profile: z.enum(['quick', 'full', 'custom']),
  engines: z.array(z.string()).min(1, 'اختر محركاً واحداً على الأقل'),
  scope_text: z.string().trim().optional(),
  authorized: z.boolean().refine(Boolean, 'يجب تأكيد أن الهدف مصرح به'),
  include_subdomains: z.boolean(),
  duration_minutes: z.coerce.number().int().min(5).max(1440),
  rate_limit: z.coerce.number().int().min(1).max(100),
  custom_headers: z.string().optional(),
  ports: z.string().optional(),
  api_method: z.string().optional(),
}).superRefine((value, ctx) => {
  if (value.target_type === 'url' || value.target_type === 'api') {
    try { new URL(value.target_value) } catch { ctx.addIssue({ code: 'custom', path: ['target_value'], message: 'الرابط غير صحيح' }) }
  }
})

type FormValues = z.infer<typeof schema>
type Project = { id: string; name: string }
type ProjectsResponse = Project[] | { items?: Project[]; results?: Project[] }

const unwrapProjects = (data: ProjectsResponse | undefined): Project[] => Array.isArray(data) ? data : data?.items ?? data?.results ?? []

const TARGETS = [
  { value: 'url' as const, label: 'URL', sub: 'موقع / تطبيق ويب', icon: Globe, placeholder: 'https://example.com' },
  { value: 'ip' as const, label: 'IP / Host', sub: 'خادم أو نطاق', icon: Server, placeholder: '192.168.1.10 أو api.example.com' },
  { value: 'code' as const, label: 'Source Code', sub: 'مسار كود على worker', icon: Layers, placeholder: 'C:\\Projects\\MyApp' },
  { value: 'api' as const, label: 'API', sub: 'REST / GraphQL endpoint', icon: Plug, placeholder: 'https://api.example.com/v1/users' },
]

const ALL_ENGINES = ['recon','evidence_collection','vuln_intelligence','validation','control_validation','endpoint_discovery','tls_intelligence','dependency_risk','code_quality','runtime_analysis']
const QUICK_ENGINES = ['recon','evidence_collection','vuln_intelligence','validation']

export const NewValidation = () => {
  const navigate = useNavigate()
  const [submitting, setSubmitting] = useState(false)
  const projectsQuery = useQuery<ProjectsResponse>({
    queryKey: ['projects'],
    queryFn: () => apiHelpers.get<ProjectsResponse>('/projects/'),
    staleTime: 30_000,
  })
  const projects = unwrapProjects(projectsQuery.data)

  const { register, handleSubmit, watch, setValue, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { project_id: '', target_type: 'url', target_value: '', profile: 'quick', engines: QUICK_ENGINES, scope_text: '', authorized: false, include_subdomains: false, duration_minutes: 60, rate_limit: 5, api_method: 'GET' },
  })

  useEffect(() => {
    if (!watch('project_id') && projects.length === 1) setValue('project_id', projects[0].id, { shouldValidate: true })
  }, [projects, setValue, watch])

  const targetType = watch('target_type')
  const profile = watch('profile')
  const engines = watch('engines')
  const authorized = watch('authorized')
  const projectId = watch('project_id')
  const targetMeta = TARGETS.find((target) => target.value === targetType) ?? TARGETS[0]

  const selectProfile = (next: FormValues['profile']) => {
    setValue('profile', next, { shouldValidate: true })
    setValue('engines', next === 'quick' ? QUICK_ENGINES : next === 'full' ? ALL_ENGINES : engines.length ? engines : ['recon', 'validation'], { shouldValidate: true })
  }

  const toggleEngine = (engine: string) => {
    const next = engines.includes(engine) ? engines.filter((item) => item !== engine) : [...engines, engine]
    setValue('engines', next, { shouldValidate: true })
    setValue('profile', 'custom', { shouldValidate: true })
  }

  const onSubmit = async (data: FormValues) => {
    if (!projectId) {
      toast.error('يجب اختيار مشروع حقيقي قبل بدء Validation.')
      return
    }
    setSubmitting(true)
    try {
      const payload = {
        project_id: data.project_id,
        target_type: data.target_type,
        target_value: data.target_value,
        profile: data.profile,
        engines: data.engines,
        scope: data.scope_text || (data.target_type === 'url' ? new URL(data.target_value).hostname : data.target_value),
        authorized: data.authorized,
        include_subdomains: data.include_subdomains,
        duration_minutes: data.duration_minutes,
        rate_limit: data.rate_limit,
        extra: { custom_headers: data.custom_headers, ports: data.ports, api_method: data.api_method },
      }
      const response = await apiHelpers.post<{ id?: string }>('/validations', payload)
      const id = response.id
      if (!id) throw new Error('The validation service returned no validation id.')
      toast.success(`تم إنشاء التحقق ${id}`)
      navigate(`/validations/${id}/progress`, { replace: true })
    } catch (error: any) {
      const detail = error?.response?.data?.detail || error?.message || 'فشل إنشاء مهمة التحقق'
      toast.error(typeof detail === 'string' ? detail : JSON.stringify(detail))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-6">
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="flex gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
        <div className="text-sm"><p className="font-semibold">Authorized Security Testing Only</p><p className="mt-1 leading-relaxed text-muted-foreground">لا يبدأ أي تنفيذ إلا بعد تأكيد التصريح والنطاق. كل ما يظهر بعد الإنشاء مصدره التنفيذ الحقيقي.</p></div>
      </motion.div>

      <header><h1 className="flex items-center gap-2 text-2xl font-bold"><ShieldCheck className="h-6 w-6 text-primary" /> New Security Validation</h1><p className="mt-1 text-sm text-muted-foreground">حدد المشروع والهدف والنطاق والمحركات ثم ابدأ التنفيذ الحقيقي.</p></header>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
        <section className="rounded-xl border bg-card p-5">
          <div className="mb-4 flex items-center gap-2 font-semibold"><span className="grid h-6 w-6 place-items-center rounded-full bg-primary text-xs text-primary-foreground">1</span> المشروع</div>
          {projectsQuery.isError ? (
            <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">تعذر تحميل المشاريع الحقيقية من API. لن يتم عرض أي مشروع تجريبي.</div>
          ) : (
            <select {...register('project_id')} disabled={projectsQuery.isLoading || projects.length === 0} className="w-full rounded-lg border bg-background px-3 py-2.5 text-sm">
              <option value="">{projectsQuery.isLoading ? 'جاري تحميل المشاريع…' : projects.length ? 'اختر المشروع' : 'لا توجد مشاريع متاحة'}</option>
              {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
            </select>
          )}
          {errors.project_id && <p className="mt-1 text-xs text-destructive">{errors.project_id.message}</p>}
        </section>

        <section className="rounded-xl border bg-card p-5">
          <div className="mb-4 flex items-center gap-2 font-semibold"><span className="grid h-6 w-6 place-items-center rounded-full bg-primary text-xs text-primary-foreground">2</span> نوع الهدف</div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {TARGETS.map((target) => <button key={target.value} type="button" onClick={() => setValue('target_type', target.value, { shouldValidate: true })} className={cn('rounded-xl border p-4 text-start transition', targetType === target.value ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'hover:bg-muted/50')}><target.icon className={cn('h-6 w-6', targetType === target.value ? 'text-primary' : 'text-muted-foreground')} /><div className="mt-2 font-medium">{target.label}</div><div className="text-xs text-muted-foreground">{target.sub}</div></button>)}
          </div>
        </section>

        <section className="space-y-4 rounded-xl border bg-card p-5">
          <div className="flex items-center gap-2 font-semibold"><span className="grid h-6 w-6 place-items-center rounded-full bg-primary text-xs text-primary-foreground">3</span> الهدف والنطاق</div>
          <div><label className="text-sm font-medium">الهدف *</label><div className="relative mt-1"><targetMeta.icon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><input {...register('target_value')} dir="ltr" placeholder={targetMeta.placeholder} className="w-full rounded-lg border bg-background py-2.5 pl-9 pr-3 text-sm outline-none focus:ring-2 focus:ring-ring" /></div>{errors.target_value && <p className="mt-1 text-xs text-destructive">{errors.target_value.message}</p>}</div>
          <div><label className="text-sm font-medium">Scope — النطاق المصرح به</label><input {...register('scope_text')} dir="ltr" placeholder={targetType === 'url' ? 'example.com, *.example.com' : targetType === 'ip' ? '192.168.1.0/24' : 'مسار أو نطاق التنفيذ'} className="mt-1 w-full rounded-lg border bg-background px-3 py-2 text-sm" /></div>
          <label className={cn('flex cursor-pointer gap-3 rounded-lg border p-3', authorized ? 'border-emerald-300 bg-emerald-50/70 dark:border-emerald-800 dark:bg-emerald-950/20' : '')}><input type="checkbox" {...register('authorized')} className="mt-1" /><span className="text-sm"><span className="flex items-center gap-1 font-medium"><ShieldCheck className="h-4 w-4" /> أؤكد أن الهدف مملوك لي أو لدي تصريح مكتوب</span><span className="text-xs text-muted-foreground">بدون هذا التأكيد سيرفض الخادم إنشاء الـValidation.</span></span></label>{errors.authorized && <p className="text-xs text-destructive">{errors.authorized.message}</p>}
        </section>

        <section className="rounded-xl border bg-card p-5">
          <div className="mb-4 flex items-center gap-2 font-semibold"><span className="grid h-6 w-6 place-items-center rounded-full bg-primary text-xs text-primary-foreground">4</span> ملف التحقق</div>
          <div className="grid gap-3 md:grid-cols-3">
            {(['quick','full','custom'] as const).map((value) => <button key={value} type="button" onClick={() => selectProfile(value)} className={cn('rounded-xl border p-4 text-start', profile === value ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'hover:bg-muted/50')}><div className="flex items-center justify-between"><span className="font-medium">{value === 'quick' ? 'Quick Assessment' : value === 'full' ? 'Full Validation' : 'Custom'}</span>{profile === value && <Check className="h-4 w-4 text-primary" />}</div><p className="mt-1 text-xs text-muted-foreground">{value === 'quick' ? 'مجموعة محركات حقيقية متاحة' : value === 'full' ? 'جميع محركات التنفيذ الحقيقية المتاحة' : 'اختيار يدوي للمحركات'}</p></button>)}
          </div>
          <div className="mt-4 flex items-center justify-between"><span className="flex items-center gap-2 text-sm font-medium"><Layers className="h-4 w-4 text-primary" /> Engines ({engines.length}/{ALL_ENGINES.length})</span><div className="flex gap-2"><button type="button" onClick={() => setValue('engines', ALL_ENGINES, { shouldValidate: true })} className="rounded border px-2 py-1 text-xs hover:bg-muted">الكل</button><button type="button" onClick={() => setValue('engines', [], { shouldValidate: true })} className="rounded border px-2 py-1 text-xs hover:bg-muted">مسح</button></div></div>
          <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">{ALL_ENGINES.map((engine) => { const active = engines.includes(engine); return <button key={engine} type="button" onClick={() => toggleEngine(engine)} className={cn('flex items-center justify-between rounded-lg border px-2.5 py-2 text-start font-mono text-[11px]', active ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-muted')}>{engine}{active ? <Check className="h-3 w-3" /> : <X className="h-3 w-3 opacity-30" />}</button> })}</div>{errors.engines && <p className="mt-2 text-xs text-destructive">{errors.engines.message}</p>}
        </section>

        <section className="rounded-xl border bg-card p-5"><div className="mb-4 flex items-center gap-2 font-semibold"><span className="grid h-6 w-6 place-items-center rounded-full bg-primary text-xs text-primary-foreground">5</span> حدود التنفيذ</div><div className="grid gap-3 sm:grid-cols-2"><div><label className="flex items-center gap-1 text-sm font-medium"><Clock className="h-3.5 w-3.5" /> المدة القصوى بالدقائق</label><input type="number" {...register('duration_minutes')} className="mt-1 w-full rounded-lg border bg-background px-3 py-2 text-sm" /></div><div><label className="flex items-center gap-1 text-sm font-medium"><Gauge className="h-3.5 w-3.5" /> Rate limit</label><input type="number" {...register('rate_limit')} className="mt-1 w-full rounded-lg border bg-background px-3 py-2 text-sm" /></div></div></section>

        <div className="flex items-center justify-between gap-3 pt-2"><p className="text-xs text-muted-foreground">API project → Celery job → real engine → PostgreSQL evidence/findings</p><button type="submit" disabled={submitting || !authorized || !projectId || projectsQuery.isError} className="inline-flex items-center gap-2 rounded-lg bg-primary px-6 py-2.5 font-medium text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50">{submitting ? <><Loader2 className="h-4 w-4 animate-spin" /> جاري الإنشاء…</> : <>Start Validation <ArrowRight className="h-4 w-4" /></>}</button></div>
      </form>
    </div>
  )
}
