import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { toast } from 'sonner'
import { apiHelpers } from '@/services/api'
import { cn } from '@/utils/cn'
import { Activity, ArrowLeft, ArrowRight, Check, Globe, Server, FolderCog, Plug, ShieldCheck, SlidersHorizontal, Zap } from 'lucide-react'

type Target = 'url' | 'ip' | 'code' | 'api'
type Profile = 'quick' | 'full' | 'custom'

const targets = [
  { id: 'url' as Target, title: 'Web Application', subtitle: 'Website or web app', icon: Globe, placeholder: 'https://app.example.com' },
  { id: 'ip' as Target, title: 'Host / IP', subtitle: 'Server or network target', icon: Server, placeholder: '192.168.1.10' },
  { id: 'code' as Target, title: 'Source Code', subtitle: 'Repository or local path', icon: FolderCog, placeholder: '/workspace/project' },
  { id: 'api' as Target, title: 'API', subtitle: 'REST or GraphQL endpoint', icon: Plug, placeholder: 'https://api.example.com/v1' },
]

const profiles = [
  { id: 'quick' as Profile, title: 'Quick Assessment', desc: 'Fast signal across the core engines', meta: '~15–30 min', icon: Zap },
  { id: 'full' as Profile, title: 'Full Validation', desc: 'Complete 15-engine assurance workflow', meta: 'Deep coverage', icon: ShieldCheck },
  { id: 'custom' as Profile, title: 'Custom Profile', desc: 'Choose exactly which engines to run', meta: 'Advanced', icon: SlidersHorizontal },
]

const engines = [
  ['recon', 'Recon'], ['evidence_collection', 'Evidence'], ['vuln_intelligence', 'Vuln Intel'], ['validation', 'Validation'],
  ['control_validation', 'Controls'], ['coverage_gap', 'Coverage'], ['attack_path', 'Attack Paths'], ['evidence_graph', 'Evidence Graph'],
  ['knowledge', 'Knowledge'], ['posture', 'Posture'], ['policy_compliance', 'Compliance'], ['twin_engine', 'Digital Twin'],
  ['scenarios', 'Scenarios'], ['dashboard', 'Dashboard'], ['reporting', 'Reporting'],
]

const fullEngines = engines.map(([id]) => id)
const quickEngines = ['recon', 'evidence_collection', 'vuln_intelligence', 'validation']

export const ValidationWizard = () => {
  const navigate = useNavigate()
  const [step, setStep] = useState(1)
  const [target, setTarget] = useState<Target>('url')
  const [value, setValue] = useState('')
  const [profile, setProfile] = useState<Profile>('full')
  const [selected, setSelected] = useState<string[]>(fullEngines)
  const [scope, setScope] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  const targetMeta = useMemo(() => targets.find(x => x.id === target)!, [target])

  const chooseProfile = (next: Profile) => {
    setProfile(next)
    if (next === 'full') setSelected(fullEngines)
    if (next === 'quick') setSelected(quickEngines)
    if (next === 'custom' && selected.length === fullEngines.length) setSelected(quickEngines)
  }

  const toggle = (id: string) => {
    setProfile('custom')
    setSelected(current => current.includes(id) ? current.filter(x => x !== id) : [...current, id])
  }

  const next = () => {
    if (step === 1 && !value.trim()) return toast.error('أدخل الهدف أولاً')
    if (step === 2 && selected.length === 0) return toast.error('اختر محركاً واحداً على الأقل')
    setStep(s => Math.min(4, s + 1))
  }

  const submit = async () => {
    if (!authorized) return toast.error('يجب تأكيد التفويض قبل إنشاء المهمة')
    setSubmitting(true)
    try {
      const payload = {
        target_type: target,
        target_value: value.trim(),
        profile,
        engines: selected,
        scope: scope.trim() || value.trim(),
        authorized: true,
      }
      const result = await apiHelpers.post<any>('/validations', payload)
      const id = result?.id || result?.validation_id
      if (!id) throw new Error('The validation service did not return a job id')
      toast.success('Validation job created')
      navigate(`/validations/${id}/progress`)
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || error?.message || 'تعذر إنشاء مهمة التحقق')
    } finally {
      setSubmitting(false)
    }
  }

  const steps = ['Target', 'Profile', 'Scope & Safety', 'Review']

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 pb-10">
      <div className="flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-[0.18em] text-primary"><Activity className="h-3.5 w-3.5" /> Validation Command Center</div>
          <h1 className="text-3xl font-semibold tracking-tight">New Security Validation</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">Configure an authorized validation job with deliberate scope, engine selection and a review gate before execution.</p>
        </div>
        <div className="rounded-xl border bg-card/70 px-4 py-3 text-right text-xs text-muted-foreground"><span className="font-medium text-foreground">{selected.length}/15</span> engines selected</div>
      </div>

      <div className="rounded-2xl border bg-card/70 p-3 shadow-sm backdrop-blur">
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
          {steps.map((label, index) => {
            const n = index + 1
            const active = n === step
            const done = n < step
            return <button key={label} type="button" onClick={() => n < step && setStep(n)} className={cn('flex items-center gap-3 rounded-xl px-3 py-2.5 text-left transition', active && 'bg-primary/10', done && 'hover:bg-muted')}>
              <span className={cn('grid h-8 w-8 shrink-0 place-items-center rounded-full border text-xs font-semibold', done ? 'border-primary bg-primary text-primary-foreground' : active ? 'border-primary text-primary' : 'border-border text-muted-foreground')}>{done ? <Check className="h-4 w-4" /> : n}</span>
              <span><span className={cn('block text-sm font-medium', active && 'text-primary')}>{label}</span><span className="hidden text-[11px] text-muted-foreground sm:block">Step {n}</span></span>
            </button>
          })}
        </div>
      </div>

      <motion.div key={step} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl border bg-card p-5 shadow-sm md:p-7">
        {step === 1 && <>
          <SectionHeader eyebrow="01 / TARGET" title="What are we validating?" description="Choose the asset class first. This keeps the rest of the workflow context-aware." />
          <div className="mt-7 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            {targets.map(item => <button key={item.id} type="button" onClick={() => setTarget(item.id)} className={cn('group rounded-2xl border p-5 text-left transition-all', target === item.id ? 'border-primary bg-primary/5 shadow-sm' : 'hover:-translate-y-0.5 hover:bg-muted/40')}>
              <item.icon className={cn('h-6 w-6', target === item.id ? 'text-primary' : 'text-muted-foreground')} />
              <div className="mt-5 font-semibold">{item.title}</div><div className="mt-1 text-xs text-muted-foreground">{item.subtitle}</div>
            </button>)}
          </div>
          <div className="mt-6"><label className="text-sm font-medium">Target</label><div className="mt-2 flex items-center rounded-xl border bg-background px-4 focus-within:ring-2 focus-within:ring-primary/30"><span className="mr-3 text-xs text-muted-foreground">{target.toUpperCase()}</span><input value={value} onChange={e => setValue(e.target.value)} dir="ltr" placeholder={targetMeta.placeholder} className="h-12 min-w-0 flex-1 bg-transparent text-sm outline-none" /></div></div>
        </>}

        {step === 2 && <>
          <SectionHeader eyebrow="02 / VALIDATION PROFILE" title="How deep should we go?" description="Start with a proven profile or take full control of the execution graph." />
          <div className="mt-7 grid gap-3 lg:grid-cols-3">
            {profiles.map(item => <button key={item.id} type="button" onClick={() => chooseProfile(item.id)} className={cn('rounded-2xl border p-5 text-left transition-all', profile === item.id ? 'border-primary bg-primary/5 shadow-sm' : 'hover:-translate-y-0.5 hover:bg-muted/40')}>
              <div className="flex items-center justify-between"><item.icon className={cn('h-5 w-5', profile === item.id ? 'text-primary' : 'text-muted-foreground')} /><span className="rounded-full bg-muted px-2 py-1 text-[10px] font-medium">{item.meta}</span></div>
              <div className="mt-5 font-semibold">{item.title}</div><div className="mt-1 text-xs leading-5 text-muted-foreground">{item.desc}</div>
            </button>)}
          </div>
          <div className="mt-7 border-t pt-6"><div className="flex items-center justify-between"><div><h3 className="text-sm font-semibold">Engine orchestration</h3><p className="text-xs text-muted-foreground">Select the engines that should participate in this job.</p></div><span className="text-xs font-medium text-primary">{selected.length} selected</span></div><div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">{engines.map(([id, name]) => <button key={id} type="button" onClick={() => toggle(id)} className={cn('rounded-xl border px-3 py-3 text-left text-xs transition', selected.includes(id) ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-muted')}><div className="font-medium">{name}</div><div className={cn('mt-1 text-[10px]', selected.includes(id) ? 'text-primary-foreground/70' : 'text-muted-foreground')}>{id}</div></button>)}</div></div>
        </>}

        {step === 3 && <>
          <SectionHeader eyebrow="03 / SCOPE & SAFETY" title="Make the authorization explicit" description="Every active validation needs a precise scope and an explicit authorization gate." />
          <div className="mt-7 grid gap-6 lg:grid-cols-[1fr_360px]">
            <div><label className="text-sm font-medium">Authorized scope</label><textarea value={scope} onChange={e => setScope(e.target.value)} dir="ltr" rows={7} placeholder={target === 'url' ? 'example.com\n*.example.com' : 'Define the exact hosts, paths, repositories or ranges included in this validation'} className="mt-2 w-full resize-none rounded-2xl border bg-background p-4 text-sm outline-none focus:ring-2 focus:ring-primary/30" /><p className="mt-2 text-xs text-muted-foreground">If empty, the target itself will be used as the scope.</p></div>
            <div className="space-y-4"><div className="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-5"><ShieldCheck className="h-6 w-6 text-amber-500" /><h3 className="mt-4 font-semibold">Authorization required</h3><p className="mt-2 text-xs leading-5 text-muted-foreground">Only validate systems you own or are explicitly authorized to assess. The authorization state becomes part of the validation record.</p><label className={cn('mt-5 flex cursor-pointer gap-3 rounded-xl border p-4', authorized ? 'border-emerald-500/40 bg-emerald-500/5' : 'hover:bg-muted')}><input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)} className="mt-1" /><span className="text-xs font-medium leading-5">I confirm this target is authorized for security validation.</span></label></div></div>
          </div>
        </>}

        {step === 4 && <>
          <SectionHeader eyebrow="04 / REVIEW" title="Ready to create the validation job?" description="Review the execution contract before anything is queued." />
          <div className="mt-7 grid gap-3 md:grid-cols-2 lg:grid-cols-4">{[['Target', value], ['Type', target.toUpperCase()], ['Profile', profile], ['Engines', `${selected.length} / 15`]].map(([k, v]) => <div key={k} className="rounded-2xl border bg-muted/20 p-4"><div className="text-[11px] uppercase tracking-wider text-muted-foreground">{k}</div><div dir="ltr" className="mt-2 truncate text-sm font-semibold">{v}</div></div>)}</div>
          <div className="mt-5 rounded-2xl border p-5"><div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Execution contract</div><div className="mt-4 grid gap-3 sm:grid-cols-2"><Row label="Scope" value={scope || value} /><Row label="Authorization" value={authorized ? 'Confirmed' : 'Required'} /><Row label="Execution" value="Create Job → Queue → WebSocket" /><Row label="Core" value="Existing Aegis engines + orchestrator" /></div></div>
        </>}
      </motion.div>

      <div className="flex items-center justify-between gap-3"><button type="button" onClick={() => step === 1 ? navigate(-1) : setStep(s => s - 1)} className="inline-flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-medium hover:bg-muted"><ArrowLeft className="h-4 w-4" /> Back</button>{step < 4 ? <button type="button" onClick={next} className="inline-flex items-center gap-2 rounded-xl bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground shadow-sm hover:opacity-90">Continue <ArrowRight className="h-4 w-4" /></button> : <button type="button" onClick={submit} disabled={submitting || !authorized} className="inline-flex items-center gap-2 rounded-xl bg-primary px-6 py-2.5 text-sm font-semibold text-primary-foreground shadow-sm disabled:cursor-not-allowed disabled:opacity-50">{submitting ? 'Creating job…' : 'Create Validation Job'} <ArrowRight className="h-4 w-4" /></button>}</div>
    </div>
  )
}

const SectionHeader = ({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) => <div><div className="text-xs font-semibold tracking-[0.16em] text-primary">{eyebrow}</div><h2 className="mt-2 text-2xl font-semibold tracking-tight">{title}</h2><p className="mt-1 max-w-2xl text-sm text-muted-foreground">{description}</p></div>
const Row = ({ label, value }: { label: string; value: string }) => <div className="rounded-xl bg-muted/30 px-4 py-3"><div className="text-[11px] text-muted-foreground">{label}</div><div dir="ltr" className="mt-1 truncate text-sm font-medium">{value}</div></div>
