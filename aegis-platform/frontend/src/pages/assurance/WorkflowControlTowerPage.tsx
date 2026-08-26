import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { WorkflowControlTower } from '@/components/security/WorkflowControlTower'

type Action = { actionId:string; title:string; owner:string; priority:number; state:string; sla?:{state:string; remainingHours:number; dueAt:string}; requiresApproval?:boolean }
type Payload = { items:Action[]; metrics:{total:number;critical:number;onTrack:number;atRisk:number;breached:number;awaitingApproval:number;verified:number} }

export function WorkflowControlTowerPage() {
 const [data,setData]=useState<Payload|null>(null); const [error,setError]=useState(''); const navigate=useNavigate();
 const load=async()=>{ try{setError(''); const r=await fetch('/api/v1/assurance/actions/overview',{headers:{Authorization:`Bearer ${localStorage.getItem('access_token')||''}`}}); if(!r.ok) throw new Error('Workflow intelligence unavailable'); setData(await r.json())}catch(e:any){setError(e.message||'Unable to load workflow intelligence')}}
 useEffect(()=>{void load()},[])
 if(error) return <div className="mx-auto grid min-h-[70vh] max-w-xl place-items-center p-6 text-center"><div><h1 className="text-lg font-bold">Workflow control tower unavailable</h1><p className="mt-2 text-sm text-muted-foreground">{error}</p><button onClick={()=>void load()} className="mt-4 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold hover:bg-muted"><RefreshCw className="h-3.5 w-3.5"/>Retry</button></div></div>
 if(!data) return <div className="grid min-h-[70vh] place-items-center text-sm text-muted-foreground">Loading workflow control tower…</div>
 return <div className="space-y-5"><header><div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Operations intelligence</div><h1 className="mt-1 text-2xl font-black tracking-tight">Remediation Workflow Control Tower</h1><p className="mt-1 max-w-3xl text-sm text-muted-foreground">See ownership, approval gates, SLA pressure and re-validation readiness across active security decisions.</p></header><WorkflowControlTower actions={data.items} metrics={data.metrics} onOpen={(id)=>navigate(`/assurance/actions/${id}`)}/></div>
}
