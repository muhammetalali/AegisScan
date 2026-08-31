import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import { apiHelpers } from '@/services/api'
import { cn } from '@/utils/cn'
import { Activity, ArrowLeft, ArrowRight, Check, FolderKanban, Globe, Plug, Server, ShieldCheck, SlidersHorizontal, Zap } from 'lucide-react'

type Target = 'url' | 'ip' | 'code' | 'api'
type Profile = 'quick' | 'full' | 'custom'

type Project = { id: string; name: string }
type ProjectResponse = Project[] | { items?: Project[]; results?: Project[] }
type Engine = { name: string; display_name?: string; real_executor_registered?: boolean; status?: string }

type EngineResponse = Engine[] | { items?: Engine[]; results?: Engine[] }

const unwrap = <T,>(data: T[] | { items?: T[]; results?: T[] } | undefined): T[] => Array.isArray(data) ? data : data?.items ?? data?.results ?? []

const targets = [
  { id: 'url' as Target, title: 'Web Application', subtitle: 'HTTP/HTTPS target', icon: Globe, placeholder: 'https://target.example' },
  { id: 'ip' as Target, title: 'Host / IP', subtitle: 'Authorized host', icon: Server, placeholder: '192.168.1.10' },
  { id: 'code' as Target, title: 'Source Code', subtitle: 'Authorized worker workspace', icon: FolderKanban, placeholder: '/authorized/workspace' },
  { id: 'api' as Target, title: 'API', subtitle: 'REST/GraphQL endpoint', icon: Plug, placeholder: 'https://api.example/v1' },
]

const profiles = [
  { id: 'quick' as Profile, title: 'Quick Assessment', desc: 'Run the first executable signal engines available from the backend.', meta: 'Fast', icon: Zap },
  { id: 'full' as Profile, title: 'Full Validation', desc: 'Run every engine currently registered with a real executor.', meta: 'Deep', icon: ShieldCheck },
  { id: 'custom' as Profile, title: 'Custom Profile', desc: 'Choose only executable engines returned by the backend.', meta: 'Advanced', icon: SlidersHorizontal },
]

export const ValidationWizard = () => {
  const navigate = useNavigate()
  const [step, setStep] = useState(1)
  const [projectId, setProjectId] = useState('')
  const [target, setTarget] = useState<Target>('url')
  const [value, setValue] = useState('')
  const [profile, setProfile] = useState<Profile>('quick')
  const [selected, setSelected] = useState<string[]>([])
  const [scope, setScope] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  const projectsQuery = useQuery<ProjectResponse>({
    queryKey: ['validation-projects'],
    queryFn: () => apiHelpers.get<ProjectResponse>('/projects/'),
    staleTime: 30_000,
  })
  const enginesQuery = useQuery<EngineResponse>({
    queryKey: ['validation-engines'],
    queryFn: () => apiHelpers.get<EngineResponse>('/engines'),
    staleTime: 30_000,
  })

  const projects = unwrap(projectsQuery.data)
  const executableEngines = useMemo(
    () => unwrap(enginesQuery.data).filter((engine) => engine.real_executor_registered !== false && engine.status !== 'disabled'),
    [enginesQuery.data],
  )

  useEffect(() => {
    if (!projectId && projects.length === 1) setProjectId(projects[0].id)
  }, [projectId, projects])

  useEffect(() => {
    if (!selected.length && executableEngines.length) {
      setSelected(executableEngines.slice(0, 4).map((engine) => engine.name))
    }
  }, [executableEngines, selected.length])

  const quickEngines = executableEngines.slice(0, 4).map((engine) => engine.name)
  const fullEngines = executableEngines.map((engine) => engine.name)
  const targetMeta = useMemo(() => targets.find((item) => item.id === target) ?? targets[0], [target])

  const chooseProfile = (nextProfile: Profile) => {
    setProfile(nextProfile)
    if (nextProfile === 'quick') setSelected(quickEngines)
    if (nextProfile === 'full') setSelected(fullEngines)
    if (nextProfile === 'custom' && selected.length === fullEngines.length) setSelected(quickEngines)
  }

  const toggle = (id: string) => {
    setProfile('custom')
    setSelected((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id])
  }

  const next = () => {
    if (step === 1 && (!projectId || !value.trim())) return toast.error('اختر مشروعاً حقيقياً وأدخل الهدف أولاً')
    if (step === 2 && selected.length === 0) return toast.error('لا يوجد محرك تنفيذ حقيقي محدد')
    if (step === 3 && !authorized) return toast.error('يجب تأكيد التفويض قبل المتابعة')
    setStep((current) => Math.min(4, current + 1))
  }

  const submit = async () => {
    if (!projectId || !authorized || !selected.length || !value.trim()) return
    setSubmitting(true)
    try {
      const payload = {
        project_id: projectId,
        target_type: target,
        target_value: value.trim(),
        profile,
        engines: selected,
        scope: scope.trim() || value.trim(),
        authorized: true,
      }
      const result = await apiHelpers.post<{ id?: string }>('/validations', payload)
      if (!result?.id) throw new Error('The validation service did not return a validation id.')
      toast.success(`Validation ${result.id} queued for real execution`)
      navigate(`/validations/${result.id}/progress`)
    } catch (error: any) {
      const detail = error?.response?.data?.detail || error?.message || 'تعذر إنشاء مهمة التحقق'
      toast.error(typeof detail === 'string' ? detail : JSON.stringify(detail))
    } finally {
      setSubmitting(false)
    }
  }

  const steps = ['Project & Target', 'Profile', 'Scope & Safety', 'Review']

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 pb-10">
      <div className="flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-[0.18em] text-primary"><Activity className="h-3.5 w-3.5" /> Validation Command Center</div>
          <h1 className="text-3xl font-semibold tracking-tight">New Security Validation</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">Only real projects and executable engines returned by the platform API can be submitted.</p>
        </div>
        <div className="rounded-xl border bg-card/70 px-4 py-3 text-right text-xs text-muted-foreground"><span className="font-medium text-foreground">{selected.length}/{executableEngines.length}</span> executable engines selected</div>
      </div>

      <div className="rounded-2xl border bg-card/70 p-3 shadow-sm">
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
          {steps.map((label, index) => {
            const n = index + 1
            return <button key={label} type="button" disabled={n > step} onClick={() => n < step && setStep(n)} className={cn('flex items-center gap-3 rounded-xl px-3 py-2.5 text-left transition disabled:cursor-default', n === step && 'bg-primary/10', n < step && 'hover:bg-muted')}><span className={cn('grid h-8 w-8 shrink-0 place-items-center rounded-full border text-xs font-semibold', n < step ? 'border-primary bg-primary text-primary-foreground' : n === step ? 'border-primary text-primary' : 'border-border text-muted-foreground')}>{n < step ? <Check className="h-4 w-4" /> : n}</span><span className={cn('text-sm font-medium', n === step && 'text-primary')}>{label}</span></button>
          })}
        </div>
      </div>

      <motion.div key={step} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl border bg-card p-5 shadow-sm md:p-7">
        {step === 1 && <>
          <SectionHeader title="Choose the real project and target" description="The API creates a durable PostgreSQL scan under the selected project before queueing execution." />
          <div className="mt-7 grid gap-4 lg:grid-cols-2">
            <div><label className="text-sm font-medium">Project *</label>{projectsQuery.isError ? <div className="mt-2 rounded-xl border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">Projects could not be loaded from the live API.</div> : <select value={projectId} onChange={(event) => setProjectId(event.target.value)} disabled={projectsQuery.isLoading || !projects.length} className="mt-2 w-full rounded-xl border bg-background px-4 py-3 text-sm"><option value="">{projectsQuery.isLoading ? 'Loading projects…' : projects.length ? 'Select project' : 'No accessible projects'}</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select>}</div>
            <div><label className="text-sm font-medium">Target type *</label><div className="mt-2 grid grid-cols-2 gap-2">{targets.map((item) => <button key={item.id} type="button" onClick={() => setTarget(item.id)} className={cn('rounded-xl border p-3 text-left', target === item.id ? 'border-primary bg-primary/5' : 'hover:bg-muted/40')}><item.icon className={cn('h-5 w-5', target === item.id ? 'text-primary' : 'text-muted-foreground')} /><div className="mt-2 text-sm font-medium">{item.title}</div><div className="text-[11px] text-muted-foreground">{item.subtitle}</div></button>)}</div></div>
          </div>
          <div className="mt-5"><label className="text-sm font-medium">Target *</label><div className="mt-2 flex items-center rounded-xl border bg-background px-4"><input value={value} onChange={(event) => setValue(event.target.value)} dir="ltr" placeholder={targetMeta.placeholder} className="h-12 min-w-0 flex-1 bg-transparent text-sm outline-none" /></div></div>
        </>}

        {step === 2 && <>
          <SectionHeader title="Use only executable engines" description="This list is returned by GET /api/v1/engines. Conceptual engines without a real executor are not selectable." />
          {enginesQuery.isError ? <div className="mt-6 rounded-xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">The engine registry is unavailable. No fallback engines are displayed.</div> : <>
            <div className="mt-6 grid gap-3 lg:grid-cols-3">{profiles.map((item) => <button key={item.id} type="button" onClick={() => chooseProfile(item.id)} className={cn('rounded-2xl border p-5 text-left', profile === item.id ? 'border-primary bg-primary/5' : 'hover:bg-muted/40')}><item.icon className={cn('h-5 w-5', profile === item.id ? 'text-primary' : 'text-muted-foreground')} /><div className="mt-4 font-semibold">{item.title}</div><div className="mt-1 text-xs leading-5 text-muted-foreground">{item.desc}</div><div className="mt-3 text-[10px] uppercase tracking-widest text-muted-foreground">{item.meta}</div></button>)}</div>
            <div className="mt-7 grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">{executableEngines.map((engine) => <button key={engine.name} type="button" onClick={() => toggle(engine.name)} className={cn('rounded-xl border px-3 py-3 text-left transition', selected.includes(engine.name) ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-muted')}><div className="text-sm font-medium">{engine.display_name || engine.name}</div><div className={cn('mt-1 text-[10px] font-mono', selected.includes(engine.name) ? 'text-primary-foreground/70' : 'text-muted-foreground')}>{engine.name}</div></button>)}</div>
            {!executableEngines.length && <div className="mt-6 rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">No real execution engine is currently registered.</div>}
          </>}
        </>}

        {step === 3 && <>
          <SectionHeader title="Scope and authorization" description="The submitted scope and authorization flag become part of the durable scan configuration." />
          <div className="mt-7 grid gap-6 lg:grid-cols-[1fr_360px]"><div><label className="text-sm font-medium">Authorized scope</label><textarea value={scope} onChange={(event) => setScope(event.target.value)} dir="ltr" rows={8} placeholder="Enter only hosts, URLs, paths, repositories or ranges you are authorized to assess." className="mt-2 w-full resize-none rounded-2xl border bg-background p-4 text-sm outline-none focus:ring-2 focus:ring-primary/30" /><p className="mt-2 text-xs text-muted-foreground">Empty scope uses the target value.</p></div><div className="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-5"><ShieldCheck className="h-6 w-6 text-amber-500" /><h3 className="mt-4 font-semibold">Authorization required</h3><p className="mt-2 text-xs leading-5 text-muted-foreground">Do not submit third-party targets without explicit authorization.</p><label className={cn('mt-5 flex cursor-pointer gap-3 rounded-xl border p-4', authorized && 'border-emerald-500/40 bg-emerald-500/5')}><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} className="mt-1" /><span className="text-xs font-medium leading-5">I confirm this target is authorized.</span></label></div></div>
        </>}

        {step === 4 && <>
          <SectionHeader title="Review the real execution contract" description="Nothing is simulated here. Submit creates a PostgreSQL Scan and queues the Celery task." />
          <div className="mt-7 grid gap-3 md:grid-cols-2 lg:grid-cols-4">{[['Project', projects.find((project) => project.id === projectId)?.name || '—'], ['Target', value], ['Profile', profile], ['Engines', `${selected.length} / ${executableEngines.length}`]].map(([key, val]) => <div key={key} className="rounded-2xl border bg-muted/20 p-4"><div className="text-[11px] uppercase tracking-wider text-muted-foreground">{key}</div><div dir="ltr" className="mt-2 truncate text-sm font-semibold">{val}</div></div>)}</div>
          <div className="mt-5 rounded-2xl border p-5"><div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Execution</div><div className="mt-4 grid gap-3 sm:grid-cols-2"><Row label="Scope" value={scope || value} /><Row label="Authorization" value={authorized ? 'Confirmed' : 'Required'} /><Row label="Persistence" value="PostgreSQL Scan record" /><Row label="Queue" value="Celery worker" /></div></div>
        </>}
      </motion.div>

      <div className="flex items-center justify-between gap-3"><button type="button" onClick={() => step === 1 ? navigate(-1) : setStep((current) => current - 1)} className="inline-flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-medium hover:bg-muted"><ArrowLeft className="h-4 w-4" /> Back</button>{step < 4 ? <button type="button" onClick={next} className="inline-flex items-center gap-2 rounded-xl bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground">Continue <ArrowRight className="h-4 w-4" /></button> : <button type="button" onClick={submit} disabled={submitting || !authorized || !projectId || !selected.length} className="inline-flex items-center gap-2 rounded-xl bg-primary px-6 py-2.5 text-sm font-semibold text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50">{submitting ? 'Queueing job…' : 'Create Validation Job'} <ArrowRight className="h-4 w-4" /></button>}</div>
    </div>
  )
}

const SectionHeader = ({ title, description }: { title: string; description: string }) => <div><h2 className="text-2xl font-semibold tracking-tight">{title}</h2><p className="mt-1 max-w-2xl text-sm text-muted-foreground">{description}</p></div>
const Row = ({ label, value }: { label: string; value: string }) => <div className="rounded-xl bg-muted/30 px-4 py-3"><div className="text-[11px] text-muted-foreground">{label}</div><div dir="ltr" className="mt-1 truncate text-sm font-medium">{value}</div></div>
