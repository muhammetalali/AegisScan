import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Activity, FileCode2, Globe2, Loader2, Network, Radar, Server, ShieldCheck, UploadCloud } from 'lucide-react'
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

export const AssessmentLauncher=()=>{
  const {id=''}=useParams<{id:string}>(); const navigate=useNavigate()
  const [mode,setMode]=useState<Mode>('network'); const [depth,setDepth]=useState<Depth>('standard')
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

  if(projectQuery.isLoading)return <div className="grid min-h-[65vh] place-items-center text-sm text-muted-foreground">Loading project…</div>
  if(!project)return <div className="enterprise-card rounded-3xl p-10 text-center">Project could not be loaded.</div>
  const visibleModes=modes.filter(item=>!contextQuery.data||contextQuery.data.modes.includes(item.id))
  const active=visibleModes.find(item=>item.id===mode)||visibleModes[0]||modes[0]
  if(contextQuery.data && visibleModes.length===0) return <main role="alert" className="enterprise-card rounded-3xl p-10">No assessment types are enabled for this account. Ask the primary company owner to assign scan access.</main>
  return <div className="mx-auto w-full max-w-6xl space-y-6 pb-12">
    <section className="enterprise-card rounded-[2rem] p-6 md:p-8"><div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/5 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em] text-primary"><Radar className="h-3.5 w-3.5"/>Assessment Launcher</div><h1 className="mt-4 text-3xl font-semibold md:text-4xl">What do you want to assess?</h1><p className="mt-2 max-w-3xl text-sm leading-7 text-muted-foreground">{project.name} · choose a target and depth. AegisScan creates the inventory record, binds the project scope, selects eligible scanners and preserves evidence automatically.</p><div className="mt-4 inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[10px] font-semibold text-muted-foreground"><ShieldCheck className="h-3.5 w-3.5 text-primary"/>{contextQuery.data?.automatic_scope_activation?'Ready to run · setup is automatic':'Project access verified automatically'}</div></section>
    <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">{visibleModes.map(item=>{const Icon=item.icon;const selected=mode===item.id;return <button key={item.id} onClick={()=>choose(item.id)} className={cn('enterprise-card rounded-2xl border p-5 text-start transition-all',selected?'border-primary bg-primary/5 shadow-lg':'hover:-translate-y-0.5 hover:border-primary/30')}><Icon className={cn('h-5 w-5',selected?'text-primary':'text-muted-foreground')}/><div className="mt-4 font-semibold">{item.label}</div><p className="mt-1 text-xs leading-5 text-muted-foreground">{item.desc}</p></button>})}</section>
    <section className="enterprise-card rounded-3xl p-6 md:p-8"><div className="grid gap-7 lg:grid-cols-[1.2fr_.8fr]"><div><div className="flex items-center gap-2 text-sm font-semibold">{mode==='file'?<UploadCloud className="h-4 w-4 text-primary"/>:<Activity className="h-4 w-4 text-primary"/>}{active.label}</div>
      {mode==='file'?<label className="mt-4 grid min-h-44 cursor-pointer place-items-center rounded-2xl border border-dashed bg-muted/10 p-6 text-center hover:bg-muted/20"><input type="file" className="hidden" onChange={e=>setFile(e.target.files?.[0]||null)}/><div><UploadCloud className="mx-auto h-8 w-8 text-primary"/><div className="mt-3 font-semibold">{file?file.name:'Choose file or ZIP source bundle'}</div><div className="mt-1 text-xs text-muted-foreground">{file?Math.ceil(file.size/1024)+' KB':'Stored in the bounded code-analysis workspace automatically.'}</div></div></label>:<label className="mt-4 block"><span className="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Target · IP, CIDR, URL or DNS name (auto-detected)</span><input autoFocus value={target} onChange={e=>updateTarget(e.target.value)} placeholder={active.placeholder} dir="ltr" className="mt-2 h-14 w-full rounded-2xl border bg-background px-4 font-mono text-sm outline-none focus:ring-2 focus:ring-primary/20"/>{mode==='network'&&contextQuery.data?.suggested_networks?.length?<div className="mt-2 flex flex-wrap gap-2">{contextQuery.data.suggested_networks.map(item=><button key={item} type="button" onClick={()=>setTarget(item)} className="rounded-full border px-3 py-1 text-[11px] hover:bg-muted">Use {item}</button>)}</div>:null}</label>}
      <div className="mt-7"><div className="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">Assessment depth</div><div className="mt-3 grid gap-2 sm:grid-cols-2">{depths.map(([key,label,detail])=><button key={key} onClick={()=>setDepth(key)} className={cn('rounded-xl border p-3 text-start',depth===key?'border-primary bg-primary/5':'hover:bg-muted/20')}><div className="text-sm font-semibold">{label}</div><div className="mt-1 text-[10px] leading-4 text-muted-foreground">{detail}</div></button>)}</div></div></div>
      <aside className="rounded-2xl border bg-muted/10 p-5"><ShieldCheck className="h-6 w-6 text-primary"/><h2 className="mt-4 font-semibold">Automatic path</h2><div className="mt-4 space-y-3 text-xs text-muted-foreground">{['Normalize target','Create/reuse internal asset','Bind target to project','Open required private path automatically','Build capability plan','Queue scans and evidence'].map((item,index)=><div key={item} className="flex gap-3"><span className="grid h-6 w-6 shrink-0 place-items-center rounded-full border bg-background text-[10px] font-bold text-primary">{index+1}</span><span className="pt-1">{item}</span></div>)}</div><p className="mt-5 text-[10px] leading-5 text-muted-foreground">Assets remain the internal evidence anchor, but they are no longer a required user step.</p></aside></div>
      <div className="mt-8 flex flex-col gap-3 border-t pt-6 sm:flex-row sm:items-center sm:justify-between"><div className="text-xs text-muted-foreground">{status||'Ready to launch.'}</div><button onClick={start} disabled={busy||(mode==='file'?!file:!target.trim())} className="inline-flex min-w-48 items-center justify-center gap-2 rounded-xl bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground disabled:opacity-50">{busy?<Loader2 className="h-4 w-4 animate-spin"/>:<Radar className="h-4 w-4"/>}{busy?'Starting assessment…':'Start Assessment'}</button></div>
    </section>
  </div>
}