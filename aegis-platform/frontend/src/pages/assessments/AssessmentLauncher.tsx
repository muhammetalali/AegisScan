import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useLanguageStore } from '@/stores/languageStore'
import { useQuery } from '@tanstack/react-query'
import { FileCode2, Globe2, Loader2, Network, Radar, Server, ShieldCheck, UploadCloud } from 'lucide-react'
import { toast } from 'sonner'
import { api, apiHelpers } from '@/services/api'
import { cn } from '@/utils/cn'

type Mode='network'|'ip'|'url'|'file'

// The existing API remains authoritative for syntax, scope and authorization.
// This is only a UI convenience: infer the existing mode when a target is pasted.
export const detectAssessmentTargetMode = (value: string): Exclude<Mode, 'file'> | null => {
  const input = value.trim()
  if (!input) return null
  if (input.includes('://')) return 'url'
  if (/^(?:\d{1,3}\.){3}\d{1,3}\/\d+$/.test(input)) return 'network'
  if (input.includes(':') && /^[0-9a-f:]+\/\d+$/i.test(input)) return 'network'
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(input)) return 'ip'
  if (input.includes(':') && /^[0-9a-f:]+$/i.test(input)) return 'ip'
  // A partially typed numeric address should not flip to the URL mode.
  if (/^[0-9.]+$/.test(input)) return null
  return 'url'
}
type Depth='quick'|'standard'|'deep'|'comprehensive'
type Project={id:string;name:string;environment?:string}
type LauncherContext={project_id:string;suggested_networks:string[];modes:Mode[];default_depth:Depth;scope_mode:string;automatic_scope_activation:boolean}
type Prepared={project_id:string;asset:{id:string;name:string;type:string;target:string;created:boolean};authorization:{state:'authorized'|'pending';source:string;id:string|null;target:string;authorized:boolean;request?:any};depth:Depth;recommended_capabilities:string[]}

const modes=[
  {id:'network' as Mode,label:'Internal network',desc:'Discover hosts and exposed services across a CIDR range.',icon:Network,placeholder:'192.168.49.0/24'},
  {id:'ip' as Mode,label:'IP address',desc:'Inspect one host and its reachable services.',icon:Server,placeholder:'192.168.49.10'},
  {id:'url' as Mode,label:'URL / Domain',desc:'Enter one URL or domain and run every eligible web capability for the selected depth.',icon:Globe2,placeholder:'https://app.example.com'},
  {id:'file' as Mode,label:'File / Source bundle',desc:'Upload a source file or ZIP bundle for code analysis.',icon:FileCode2,placeholder:''},
]
const depths:[Depth,string,string][]=[
  ['quick','Quick','Lowest-impact eligible capabilities.'],
  ['standard','Standard','Balanced default for normal assessments.'],
  ['deep','Deep','Adds higher-risk eligible checks.'],
  ['comprehensive','Comprehensive','Runs every execution-ready capability for this target type.'],
]

export const AssessmentLauncher=({ projectOverride, preferredMode='network' }: { projectOverride?: string; preferredMode?: Mode })=>{
  const params=useParams<{id:string}>(); const id=projectOverride || params.id || ''; const navigate=useNavigate(); const t=useLanguageStore(s=>s.t)
  const [mode,setMode]=useState<Mode>(preferredMode); const [depth,setDepth]=useState<Depth>('standard')
  const [target,setTarget]=useState(''); const [file,setFile]=useState<File|null>(null)
  const [busy,setBusy]=useState(false); const [status,setStatus]=useState('')
  const projectQuery=useQuery<any>({queryKey:['assessment-project',id],queryFn:()=>apiHelpers.get('/projects/'+id+'/'),enabled:Boolean(id)})
  const contextQuery=useQuery<LauncherContext>({queryKey:['assessment-context',id],queryFn:()=>apiHelpers.get('/assessment-launcher/context',{params:{project_id:id}}),enabled:Boolean(id)})
  const project:Project|null=useMemo(()=>projectQuery.data?.project??projectQuery.data??null,[projectQuery.data])
  useEffect(()=>{const suggested=contextQuery.data?.suggested_networks?.[0];if(mode==='network'&&!target&&suggested)setTarget(suggested)},[contextQuery.data,mode,target])
  useEffect(()=>{const allowed=contextQuery.data?.modes;if(allowed?.length&&!allowed.includes(mode)){setMode(allowed[0]);setTarget('');setFile(null)}},[contextQuery.data?.modes,mode])
  const choose=(next:Mode)=>{setMode(next);setStatus('');setFile(null);setTarget(next==='network'?(contextQuery.data?.suggested_networks?.[0]||''):'')}
  const updateTarget=(value:string)=>{
    setTarget(value)
    const detected=detectAssessmentTargetMode(value)
    if (detected && (contextQuery.data?.modes ?? ['network','ip','url','file']).includes(detected)) {
      setMode(detected)
    }
  }

  const execute=async(prepared:Prepared)=>{
    const caps=prepared.recommended_capabilities||[]; if(!caps.length)throw new Error('No execution-ready capability is available for this target.')
    const scans:string[]=[]; const failures:string[]=[]
    for(let i=0;i<caps.length;i+=1){
      const capabilityId=caps[i]; setStatus('Launching '+capabilityId+' · '+(i+1)+'/'+caps.length)
      try{
        const result=await apiHelpers.post<any>('/capabilities/'+encodeURIComponent(capabilityId)+'/execute',{project_id:prepared.project_id,asset_id:prepared.asset.id,depth:prepared.depth,options:{},credential_refs:[],idempotency_key:'launcher-'+crypto.randomUUID(),correlation_id:'launcher-corr-'+crypto.randomUUID()})
        if(result?.scan?.id)scans.push(String(result.scan.id))
      }catch(error:any){const detail=error?.response?.data?.detail;failures.push(capabilityId+': '+(typeof detail==='string'?detail:(error?.message||'failed')))}
    }
    if(!scans.length)throw new Error(failures.join(' · ')||'Assessment plan could not be started.')
    if(failures.length)toast.warning(scans.length+' capabilities started; '+failures.length+' were skipped at runtime.');else toast.success('Assessment started · '+scans.length+' capabilities')
    navigate(scans.length===1?'/scan/'+scans[0]+'/progress':'/scan')
  }

  const start=async()=>{
    if(!id)return; if(contextQuery.data&&!contextQuery.data.modes.includes(mode))return void toast.error('This scan type is not enabled for your account.'); if(mode==='file'&&!file)return void toast.error('Choose a file or ZIP bundle.'); if(mode!=='file'&&!target.trim())return void toast.error('Enter a target.')
    const inferred=mode==='file'?null:detectAssessmentTargetMode(target)
    if(inferred&&contextQuery.data&&!contextQuery.data.modes.includes(inferred))return void toast.error('This target type is not enabled for your account.')
    setBusy(true);setStatus('Preparing target, scope and execution plan…')
    try{
      let prepared:Prepared
      if(mode==='file'){const form=new FormData();form.append('project_id',id);form.append('depth',depth);form.append('file',file as File);prepared=(await api.post<Prepared>('/assessment-launcher/file',form,{timeout:120000,headers:{'Content-Type':'multipart/form-data'}})).data}
      else prepared=await apiHelpers.post<Prepared>('/assessment-launcher/prepare',{project_id:id,mode,target:target.trim(),depth})
      if(prepared.authorization?.state!=='authorized'){
        toast.info('Target prepared. Authorization request is ready for governed approval.')
        navigate('/assurance/governance')
        return
      }
      await execute(prepared)
    }catch(error:any){const detail=error?.response?.data?.detail;toast.error(typeof detail==='string'?detail:(error?.message||'Unable to start assessment.'));setStatus('')}finally{setBusy(false)}
  }

  if(projectQuery.isLoading)return <div className="grid min-h-32 place-items-center text-sm text-muted-foreground">{t('Loading...')}</div>
  if(!project)return <div role="alert" className="enterprise-card rounded-2xl p-6">{t('The selected project could not be loaded.')}</div>
  const visibleModes=modes.filter(item=>!contextQuery.data||contextQuery.data.modes.includes(item.id))
  const active=visibleModes.find(item=>item.id===mode)||visibleModes[0]||modes[0]
  if(contextQuery.data && visibleModes.length===0)return <div role="alert" className="enterprise-card rounded-2xl p-6">{t('No assessment types are available for this account.')}</div>
  return <div className="space-y-4">
    <section className="enterprise-card rounded-2xl p-5 md:p-7">
      <h1 className="flex items-center gap-2 text-2xl font-semibold"><Radar className="h-6 w-6 text-primary" />{t('Start a new assessment')}</h1>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">{t('Enter an IP address, web URL or network; AegisScan chooses the eligible scanners and saves results automatically.')}</p>
      <div className="mt-5 flex flex-wrap gap-2" role="group" aria-label={t('Target type')}>
        {visibleModes.map((item)=>{
          const Icon=item.icon
          return <button key={item.id} type="button" onClick={()=>choose(item.id)} aria-pressed={mode===item.id}
            className={cn('inline-flex items-center gap-2 rounded-xl border px-3.5 py-2 text-sm font-medium',mode===item.id?'border-primary bg-primary/10 text-primary':'hover:bg-muted/30')}>
            <Icon className="h-4 w-4" />{t(item.label)}
          </button>
        })}
      </div>

      {mode==='file'?<label className="mt-5 grid min-h-32 cursor-pointer place-items-center rounded-xl border border-dashed p-5 text-center">
        <input type="file" className="sr-only" onChange={e=>setFile(e.target.files?.[0]||null)} />
        <span className="flex items-center gap-2 font-medium"><UploadCloud className="h-5 w-5 text-primary"/>{file?file.name:t('Choose file or ZIP source bundle')}</span>
      </label>:<label className="mt-5 block">
        <span className="text-sm font-medium">{t('Target: IP address, network or website link')}</span>
        <input autoFocus value={target} onChange={e=>updateTarget(e.target.value)} placeholder={active.placeholder} dir="ltr"
          className="mt-2 h-13 min-h-13 w-full rounded-xl border bg-background px-4 py-3 font-mono text-base outline-none focus:ring-2 focus:ring-primary/25"/>
        {mode==='network' && Boolean(contextQuery.data?.suggested_networks?.length) && <div className="mt-3 flex flex-wrap gap-2">
          {contextQuery.data!.suggested_networks.map(item=><button key={item} type="button" onClick={()=>setTarget(item)}
            className="rounded-lg border px-3 py-1.5 text-xs hover:bg-muted">{item}</button>)}
        </div>}
      </label>}

      <details className="mt-5 rounded-xl border p-4">
        <summary className="cursor-pointer text-sm font-medium">{t('Advanced settings (optional)')}</summary>
        <div className="mt-3">
          <div className="mb-2 text-sm font-medium">{t('Assessment depth')}</div>
          <div className="grid gap-2 sm:grid-cols-2">{depths.map(([key,label,desc])=><button key={key} type="button"
            onClick={()=>setDepth(key)} aria-pressed={depth===key}
            className={cn('rounded-xl border p-3 text-start',depth===key?'border-primary bg-primary/10':'hover:bg-muted/20')}>
            <div className="text-sm font-semibold">{t(label)}</div><div className="mt-1 text-xs text-muted-foreground">{t(desc)}</div>
          </button>)}</div>
          <p className="mt-3 text-xs text-muted-foreground">{t('Assets, authorized scope and evidence are handled automatically by the existing platform.')}</p>
        </div>
      </details>
      <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t pt-5">
        <p role="status" className="min-w-0 text-sm text-muted-foreground">{status || t('Ready to start a new assessment. No prior scan is required.')}</p>
        <button type="button" onClick={start} disabled={busy || (mode==='file'?!file:!target.trim())}
          className="inline-flex items-center gap-2 rounded-xl bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground disabled:opacity-50">
          {busy?<Loader2 className="h-4 w-4 animate-spin"/>:<ShieldCheck className="h-4 w-4"/>}{busy?t('Starting assessment…'):'Start Assessment'}
        </button>
      </div>
    </section>
  </div>
}
