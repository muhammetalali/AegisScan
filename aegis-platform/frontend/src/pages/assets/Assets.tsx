import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Server, Search, Globe, Code2, Network, File, Container, Tag, Play, RefreshCw, AlertTriangle } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'
import { Skeleton } from '@/components/ui/skeleton'

type Asset = {
  id: string
  name: string
  type: string
  environment: string
  project_id: string
  criticality: string
  configuration: Record<string, unknown>
  tags: string[]
  is_active: boolean
  scan_count: number
  last_scanned_at?: string | null
  created_at: string
  updated_at: string
}

const TYPES = [
  { id: 'source_code', label: 'Source Code', icon: Code2 },
  { id: 'website', label: 'Website URL', icon: Globe },
  { id: 'ip_address', label: 'IP Address', icon: Network },
  { id: 'domain', label: 'Domain', icon: Globe },
  { id: 'api_endpoint', label: 'API Endpoint', icon: Server },
  { id: 'file', label: 'Uploaded File', icon: File },
  { id: 'docker_image', label: 'Docker Image', icon: Container },
  { id: 'network_range', label: 'Network Range', icon: Network },
]

export const Assets = () => {
  const [q, setQ] = useState('')
  const [type, setType] = useState('')
  const [env, setEnv] = useState('')

  const assetsQuery = useQuery({
    queryKey: ['assets', { q, type, env }],
    queryFn: () => apiHelpers.get<Asset[]>('/assets/', {
      params: {
        search: q || undefined,
        asset_type: type || undefined,
        environment: env || undefined,
      },
    }),
  })

  const assets = useMemo(() => Array.isArray(assetsQuery.data) ? assetsQuery.data : [], [assetsQuery.data])

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><Server className="h-6 w-6 text-primary" /> Assets</h1>
          <p className="text-sm text-muted-foreground">Assets loaded from the authenticated platform API and persisted in the database.</p>
        </div>
        <button onClick={() => assetsQuery.refetch()} className="px-4 py-2 rounded-lg border bg-card text-sm inline-flex items-center gap-2 hover:bg-accent" disabled={assetsQuery.isFetching}>
          <RefreshCw className={cn('h-4 w-4', assetsQuery.isFetching && 'animate-spin')} /> Refresh
        </button>
      </div>

      <div className="flex flex-wrap gap-2">
        {TYPES.map(t => (
          <button key={t.id} onClick={() => setType(type === t.id ? '' : t.id)} className={cn('px-3 py-1.5 rounded-full border text-xs inline-flex items-center gap-1', type === t.id ? 'bg-primary text-primary-foreground border-primary' : 'bg-card hover:bg-accent')}>
            <t.icon className="h-3.5 w-3.5" />{t.label}
          </button>
        ))}
      </div>

      <div className="rounded-xl border bg-card p-3 flex flex-wrap gap-2">
        <div className="relative flex-1 max-w-sm"><Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" /><input value={q} onChange={e => setQ(e.target.value)} placeholder="Search name, tags, description..." className="w-full pl-8 pr-3 py-2 rounded-lg border bg-background text-sm" /></div>
        <select value={env} onChange={e => setEnv(e.target.value)} className="px-3 py-2 rounded-lg border bg-background text-sm">
          <option value="">All Environments</option><option value="development">Development</option><option value="staging">Staging</option><option value="production">Production</option>
        </select>
        <span className="text-xs text-muted-foreground self-center">{assets.length} assets returned</span>
      </div>

      {assetsQuery.isLoading ? (
        <div className="space-y-2"><Skeleton className="h-12 w-full" /><Skeleton className="h-12 w-full" /><Skeleton className="h-12 w-full" /></div>
      ) : assetsQuery.isError ? (
        <div className="rounded-xl border border-destructive/30 bg-destructive/5 p-8 text-center">
          <AlertTriangle className="mx-auto mb-3 h-8 w-8 text-destructive" />
          <h2 className="font-semibold">Assets unavailable</h2>
          <p className="mt-1 text-sm text-muted-foreground">The backend did not return asset data. No fallback or synthetic records are displayed.</p>
          <button onClick={() => assetsQuery.refetch()} className="mt-4 inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground"><RefreshCw className="h-4 w-4" /> Retry</button>
        </div>
      ) : (
        <div className="rounded-xl border bg-card overflow-hidden">
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b bg-muted/30 text-xs text-muted-foreground">
                <th className="text-start px-4 py-3">Name</th><th className="text-start px-4 py-3">Type</th><th className="text-start px-4 py-3">Environment</th><th className="text-start px-4 py-3">Criticality</th><th className="text-start px-4 py-3">Tags</th><th className="text-start px-4 py-3">Status</th><th className="text-start px-4 py-3">Scans</th><th className="px-4 py-3">Action</th>
              </tr></thead>
              <tbody>
                {assets.map(asset => (
                  <tr key={asset.id} className="border-b hover:bg-muted/20">
                    <td className="px-4 py-3 font-mono text-xs font-medium">{asset.name}</td>
                    <td className="px-4 py-3"><span className="px-2 py-0.5 rounded-full bg-muted text-xs">{asset.type}</span></td>
                    <td className="px-4 py-3"><span className={cn('px-2 py-0.5 rounded-full text-xs', asset.environment === 'production' ? 'bg-red-500 text-white' : asset.environment === 'staging' ? 'bg-amber-500 text-white' : 'bg-emerald-500 text-white')}>{asset.environment}</span></td>
                    <td className="px-4 py-3 capitalize">{asset.criticality}</td>
                    <td className="px-4 py-3"><span className="inline-flex flex-wrap gap-1">{asset.tags.map(tag => <span key={tag} className="px-1.5 py-0.5 rounded bg-muted text-[11px] inline-flex items-center gap-1"><Tag className="h-3 w-3" />{tag}</span>)}</span></td>
                    <td className="px-4 py-3"><span className={cn('px-2 py-0.5 rounded-full text-xs', asset.is_active ? 'bg-emerald-50 border border-emerald-200 text-emerald-700' : 'bg-muted text-muted-foreground')}>{asset.is_active ? 'active' : 'inactive'}</span></td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{asset.scan_count}</td>
                    <td className="px-4 py-3"><Link to={`/validations/new?asset=${encodeURIComponent(asset.id)}`} className="p-1.5 rounded hover:bg-accent inline-flex" title="Validate asset"><Play className="h-4 w-4" /></Link></td>
                  </tr>
                ))}
                {!assets.length && <tr><td colSpan={8} className="px-4 py-12 text-center text-sm text-muted-foreground">No persisted assets match the current filters.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
