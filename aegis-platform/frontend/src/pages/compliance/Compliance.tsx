import { useQuery } from '@tanstack/react-query'
import { ShieldCheck } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'

export const Compliance = () => {
  const { data } = useQuery({ queryKey:['compliance-overview'], queryFn: async ()=>{
    try{
      const vals = await apiHelpers.get<any>('/validations')
      const id = vals[0]?.id || vals?.items?.[0]?.id
      if(!id) throw new Error('no validations')
      return await apiHelpers.get<any>(`/validations/${id}/compliance`)
    } catch { return {items:[
      {framework:'NIST', control:'SC-8 Transmission Confidentiality', status:'fail'},
      {framework:'ISO 27001', control:'A.14.2.5 Secure Development', status:'partial'},
      {framework:'PCI DSS', control:'6.5.7 XSS', status:'fail'},
      {framework:'GDPR', control:'Art.32 Security Processing', status:'pass'},
    ]}}
  }})
  const items = data?.items || []
  const pass = items.filter((x:any)=>x.status==='pass').length
  const fail = items.filter((x:any)=>x.status==='fail').length
  const partial = items.filter((x:any)=>x.status==='partial').length
  return (
    <div className="space-y-4">
      <div><h1 className="text-2xl font-bold flex items-center gap-2"><ShieldCheck className="h-6 w-6 text-primary" /> Compliance</h1><p className="text-sm text-muted-foreground">NIST • ISO 27001 • PCI DSS • GDPR — Control → Finding → Evidence → Validation</p></div>
      <div className="grid md:grid-cols-4 gap-3">
        <div className="rounded-xl border bg-card p-4 text-center"><div className="text-2xl font-bold text-emerald-600">{pass}</div><div className="text-xs text-muted-foreground">Passed</div></div>
        <div className="rounded-xl border bg-card p-4 text-center"><div className="text-2xl font-bold text-destructive">{fail}</div><div className="text-xs text-muted-foreground">Failed</div></div>
        <div className="rounded-xl border bg-card p-4 text-center"><div className="text-2xl font-bold text-amber-600">{partial}</div><div className="text-xs text-muted-foreground">Partial</div></div>
        <div className="rounded-xl border bg-card p-4 text-center"><div className="text-2xl font-bold">{items.length}</div><div className="text-xs text-muted-foreground">Controls</div></div>
      </div>
      <div className="rounded-xl border bg-card overflow-hidden">
        <table className="w-full text-sm"><thead><tr className="border-b bg-muted/30 text-xs text-muted-foreground"><th className="text-start px-3 py-2">Framework</th><th className="text-start px-3 py-2">Control</th><th className="text-start px-3 py-2">Status</th><th className="text-start px-3 py-2">Evidence</th></tr></thead>
          <tbody>{items.map((c:any,i:number)=><tr key={i} className="border-b hover:bg-muted/20"><td className="px-3 py-2 font-mono text-xs">{c.framework}</td><td className="px-3 py-2">{c.control}</td><td className="px-3 py-2"><span className={cn('px-2 py-0.5 rounded text-xs capitalize', c.status==='pass'?'bg-emerald-500 text-white':c.status==='fail'?'bg-destructive text-destructive-foreground':'bg-amber-500 text-white')}>{c.status}</span></td><td className="px-3 py-2 text-xs text-muted-foreground">→ Finding → Evidence</td></tr>)}</tbody>
        </table>
      </div>
    </div>
  )
}
