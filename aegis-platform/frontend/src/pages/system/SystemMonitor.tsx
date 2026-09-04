import { useQuery } from '@tanstack/react-query'
import { Monitor, Activity, Database, HardDrive, Cpu } from 'lucide-react'
import { apiHelpers } from '@/services/api'

type Metric = { metric_type: string; value: number; unit: string; timestamp: string }
type Service = { service: string; status: string; host: string; port?: number | null; response_time_ms: number; uptime_percentage?: number | null; last_check: string; detail?: string | null }

const metricValue = (metrics: Metric[] | undefined, name: string) => {
  const value = metrics?.find((item) => item.metric_type === name)?.value
  return Number.isFinite(value) ? `${Number(value).toFixed(1)}%` : '—'
}

export const SystemMonitor = () => {
  const { data: metrics, isError: metricsError } = useQuery<Metric[]>({ queryKey: ['sys-metrics'], queryFn: () => apiHelpers.get<Metric[]>('/system/metrics'), refetchInterval: 5000 })
  const { data: services, isError: servicesError } = useQuery<Service[]>({ queryKey: ['sys-services'], queryFn: () => apiHelpers.get<Service[]>('/system/services'), refetchInterval: 5000 })
  const servicesList = services ?? []

  return (
    <div className="space-y-4">
      <div><h1 className="text-2xl font-bold flex items-center gap-2"><Monitor className="h-6 w-6 text-primary" /> System Monitoring</h1><p className="text-sm text-muted-foreground">Live CPU, memory, disk, PostgreSQL, Redis, Celery and API health telemetry.</p></div>
      {(metricsError || servicesError) && <div className="rounded-xl border border-red-500/30 bg-red-500/5 px-4 py-3 text-sm text-red-700 dark:text-red-400">Live telemetry could not be fully retrieved. Values are intentionally not substituted with synthetic data.</div>}
      <div className="grid md:grid-cols-4 gap-3">
        <div className="rounded-xl border bg-card p-4 text-center"><Cpu className="h-5 w-5 mx-auto text-primary" /><div className="text-lg font-bold mt-1">{metricValue(metrics, 'cpu_usage')}</div><div className="text-xs text-muted-foreground">CPU</div></div>
        <div className="rounded-xl border bg-card p-4 text-center"><Activity className="h-5 w-5 mx-auto text-primary" /><div className="text-lg font-bold mt-1">{metricValue(metrics, 'memory_usage')}</div><div className="text-xs text-muted-foreground">Memory</div></div>
        <div className="rounded-xl border bg-card p-4 text-center"><Database className="h-5 w-5 mx-auto text-primary" /><div className="text-lg font-bold mt-1">{servicesList.find((item) => item.service === 'postgresql')?.status ?? '—'}</div><div className="text-xs text-muted-foreground">PostgreSQL</div></div>
        <div className="rounded-xl border bg-card p-4 text-center"><HardDrive className="h-5 w-5 mx-auto text-primary" /><div className="text-lg font-bold mt-1">{metricValue(metrics, 'disk_usage')}</div><div className="text-xs text-muted-foreground">Disk</div></div>
      </div>
      <div className="rounded-xl border bg-card overflow-hidden">
        <table className="w-full text-sm"><thead><tr className="border-b bg-muted/30 text-xs text-muted-foreground"><th className="text-start px-3 py-2">Service</th><th className="text-start px-3 py-2">Status</th><th className="text-start px-3 py-2">Host:Port</th><th className="text-start px-3 py-2">Response</th><th className="text-start px-3 py-2">Uptime</th><th className="text-start px-3 py-2">Detail</th></tr></thead>
          <tbody>{servicesList.map((service) => <tr key={service.service} className="border-b"><td className="px-3 py-2 font-medium">{service.service}</td><td className="px-3 py-2"><span className={`px-2 py-0.5 rounded text-white text-xs ${service.status === 'healthy' ? 'bg-emerald-500' : 'bg-red-600'}`}>{service.status}</span></td><td className="px-3 py-2 font-mono text-xs">{service.host}:{service.port ?? '—'}</td><td className="px-3 py-2">{Number.isFinite(service.response_time_ms) ? `${service.response_time_ms.toFixed(1)}ms` : '—'}</td><td className="px-3 py-2">{service.uptime_percentage == null ? '—' : `${service.uptime_percentage}%`}</td><td className="px-3 py-2 text-xs text-muted-foreground">{service.detail ?? '—'}</td></tr>)}</tbody>
        </table>
        {!servicesList.length && <div className="p-8 text-center text-sm text-muted-foreground">No live service telemetry returned.</div>}
      </div>
    </div>
  )
}
