import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'

export const AuditLogs = () => {
  const [q, setQ] = useState('')
  const { data, isLoading } = useQuery({
    queryKey: ['audit-logs', q],
    queryFn: async () => apiHelpers.get<any>(`/audit/logs?limit=50${q?`&action=${encodeURIComponent(q)}`:''}`),
  })
  const items = data?.items || []
  return (
    <div className="p-6 max-w-6xl mx-auto space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Audit Logs</h1>
        <p className="text-sm text-muted-foreground">User • Action • Project • Target • Timestamp • Result • IP • Request ID — enterprise audit trail</p>
      </div>
      <div className="flex gap-2">
        <div className="relative"><Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" /><input value={q} onChange={e=>setQ(e.target.value)} placeholder="Filter by action (e.g. validation.create)" className="pl-6 pr-3 py-1.5 rounded-lg border bg-background text-xs w-72" /></div>
        <span className="text-xs text-muted-foreground self-center">{data?.total||0} entries</span>
      </div>
      <div className="rounded-xl border bg-card overflow-auto">
        <table className="w-full text-xs">
          <thead><tr className="border-b bg-muted/20 text-muted-foreground"><th className="text-start px-2 py-2">User</th><th className="text-start px-2 py-2">Action</th><th className="text-start px-2 py-2">Project</th><th className="text-start px-2 py-2">Target</th><th className="text-start px-2 py-2">Timestamp</th><th className="text-start px-2 py-2">Result</th><th className="text-start px-2 py-2">IP</th><th className="text-start px-2 py-2">Request ID</th></tr></thead>
          <tbody>
            {isLoading ? <tr><td colSpan={8} className="px-3 py-6 text-center text-muted-foreground">Loading…</td></tr> : items.map((a:any)=> (
              <tr key={a.id} className="border-b hover:bg-muted/30">
                <td className="px-2 py-2 font-mono text-[11px]">{a.user}</td>
                <td className="px-2 py-2"><span className="px-1.5 py-0.5 rounded bg-muted font-mono text-[11px]">{a.action}</span></td>
                <td className="px-2 py-2">{a.project}</td>
                <td className="px-2 py-2 font-mono">{a.target}</td>
                <td className="px-2 py-2 text-[11px]">{new Date(a.timestamp).toLocaleString()}</td>
                <td className="px-2 py-2"><span className={cn('px-1.5 py-0.5 rounded text-[11px]', a.result==='success' ? 'bg-emerald-500 text-white' : 'bg-destructive text-destructive-foreground')}>{a.result}</span></td>
                <td className="px-2 py-2 font-mono">{a.ip}</td>
                <td className="px-2 py-2 font-mono text-[11px]">{a.request_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
