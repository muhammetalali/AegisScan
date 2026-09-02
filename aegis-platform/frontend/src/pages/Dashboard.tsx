import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ArrowUpRight, Bug, FileText, FolderKanban, Plus, RefreshCw, Server, Settings, ShieldCheck, TrendingUp, Activity } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { motion } from 'framer-motion'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'
import { Skeleton, CardSkeleton } from '@/components/ui/skeleton'
import { SecurityCommandHero } from '@/components/dashboard/SecurityCommandHero'

const StatCard = ({ icon: Icon, label, value, hint, tone = 'default' }: { icon: any; label: string; value: number | string | undefined; hint: string; tone?: 'default' | 'danger' | 'warning' }) => (
  <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .35 }} className="enterprise-card enterprise-card-hover rounded-2xl p-4">
    <div className="flex items-start justify-between gap-3">
      <div className="min-w-0">
        <div className="enterprise-muted flex items-center gap-1.5"><Icon className="h-3.5 w-3.5" />{label}</div>
        <div className={cn('mt-2 text-2xl font-bold tracking-tight', tone === 'danger' && 'text-destructive', tone === 'warning' && 'text-amber-400')}>{value ?? '—'}</div>
      </div>
      <div className="rounded-xl border border-border/60 bg-background/40 p-2 text-muted-foreground shadow-inner"><Icon className="h-4 w-4" /></div>
    </div>
    <div className="mt-2 text-[11px] text-muted-foreground">{hint}</div>
  </motion.div>
)

const ChartEmpty = ({ label }: { label: string }) => <div className="flex h-56 items-center justify-center rounded-xl border border-dashed border-border/70 bg-muted/10 text-sm text-muted-foreground">{label}</div>

export const Dashboard = () => {
  const summaryQuery = useQuery({ queryKey: ['dash-summary'], queryFn: () => apiHelpers.get<any>('/dashboard/summary') })
  const riskQuery = useQuery({ queryKey: ['dash-risk'], queryFn: () => apiHelpers.get<any>('/dashboard/risk-distribution') })
  const trendsQuery = useQuery({ queryKey: ['dash-trends'], queryFn: () => apiHelpers.get<any>('/dashboard/trends?days=30') })
  const recentQuery = useQuery({ queryKey: ['dash-recent'], queryFn: () => apiHelpers.get<any>('/dashboard/recent-validations?limit=5') })

  if (summaryQuery.isLoading) return (
    <div className="space-y-6">
      <div className="h-[430px] rounded-[2rem] bg-muted animate-pulse" />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3 xl:grid-cols-6">{Array.from({ length: 6 }).map((_, i) => <CardSkeleton key={i} />)}</div>
      <div className="grid gap-4 xl:grid-cols-3"><Skeleton className="h-72 xl:col-span-2" /><Skeleton className="h-72" /></div>
    </div>
  )

  if (summaryQuery.isError) return (
    <div className="enterprise-card flex min-h-64 flex-col items-center justify-center rounded-2xl p-8 text-center">
      <AlertTriangle className="mb-3 h-8 w-8 text-destructive" />
      <h2 className="text-lg font-semibold">Dashboard data unavailable</h2>
      <p className="mt-1 max-w-md text-sm text-muted-foreground">The platform API could not provide the security overview. No demo or fallback data was substituted.</p>
      <button onClick={() => summaryQuery.refetch()} className="mt-5 inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-medium text-primary-foreground"><RefreshCw className="h-4 w-4" />Retry</button>
    </div>
  )

  const summary = summaryQuery.data
  const risk = riskQuery.data
  const trends = Array.isArray(trendsQuery.data) ? trendsQuery.data : []
  const recent = Array.isArray(recentQuery.data) ? recentQuery.data : []
  const score = typeof summary?.security_score === 'number' ? summary.security_score : undefined
  const riskValues = risk ? [risk.critical, risk.high, risk.medium, risk.low, risk.informational].map((v: any) => Number(v || 0)) : []

  const trendOption = trends.length ? {
    tooltip: { trigger: 'axis' },
    grid: { left: 12, right: 12, top: 20, bottom: 20, containLabel: true },
    xAxis: { type: 'category', data: trends.map((item: any) => String(item.date).slice(5)), boundaryGap: false, axisLine: { show: false }, axisTick: { show: false } },
    yAxis: { type: 'value', min: 0, max: 100, splitLine: { lineStyle: { type: 'dashed' } } },
    series: [{ type: 'line', data: trends.map((item: any) => item.score), smooth: true, symbol: 'circle', symbolSize: 5, areaStyle: { opacity: 0.08 }, lineStyle: { width: 2 } }],
  } : null

  const severityOption = risk ? {
    tooltip: { trigger: 'axis' },
    grid: { left: 12, right: 12, top: 12, bottom: 20, containLabel: true },
    xAxis: { type: 'category', data: ['Critical', 'High', 'Medium', 'Low', 'Info'], axisLine: { show: false }, axisTick: { show: false } },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { type: 'dashed' } } },
    series: [{ type: 'bar', data: riskValues, barMaxWidth: 34, itemStyle: { borderRadius: [8, 8, 0, 0] } }],
  } : null

  return (
    <div className="space-y-6">
      <SecurityCommandHero
        score={score}
        critical={risk?.critical ?? summary?.critical}
        high={risk?.high ?? summary?.high}
        assets={summary?.total_assets}
        validations={summary?.total_validations}
        recent={recent}
        onExplore={() => document.getElementById('dashboard-insights')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
      />

      <section className="grid grid-cols-1 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <StatCard icon={ShieldCheck} label="Security score" value={score !== undefined ? `${Math.round(score)}/100` : undefined} hint={score !== undefined ? (score >= 80 ? 'Healthy posture' : 'Attention recommended') : 'No score available'} />
        <StatCard icon={FolderKanban} label="Projects" value={summary?.total_projects} hint="Active workspace scope" />
        <StatCard icon={Server} label="Assets" value={summary?.total_assets} hint="Across your projects" />
        <StatCard icon={Activity} label="Validations" value={summary?.total_validations} hint="Recorded executions" />
        <StatCard icon={AlertTriangle} label="Critical" value={risk?.critical ?? summary?.critical} hint="Requires immediate review" tone="danger" />
        <StatCard icon={Bug} label="High" value={risk?.high ?? summary?.high} hint="Priority remediation" tone="warning" />
      </section>

      <section id="dashboard-insights" className="scroll-mt-24 space-y-4">
        <div className="flex items-end justify-between gap-3 px-1">
          <div>
            <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-primary">Operational intelligence</div>
            <h2 className="mt-1 text-xl font-semibold tracking-tight">Signals, risk and validation activity</h2>
          </div>
          <Link to="/reports" className="hidden items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground sm:flex">Open reports <ArrowUpRight className="h-3.5 w-3.5" /></Link>
        </div>

        <section className="grid gap-4 xl:grid-cols-3">
          <div className="enterprise-card rounded-2xl p-5 xl:col-span-2">
            <div className="mb-3 flex items-center justify-between"><div><h2 className="enterprise-section-title flex items-center gap-2"><TrendingUp className="h-4 w-4 text-primary" />Security score trend</h2><p className="enterprise-muted mt-1">Last 30 days</p></div></div>
            {trendsQuery.isLoading ? <Skeleton className="h-56 w-full" /> : trendsQuery.isError ? <ChartEmpty label="Unable to load trend data" /> : trendOption ? <ReactECharts option={trendOption} style={{ height: 224 }} /> : <ChartEmpty label="No trend data yet" />}
          </div>
          <div className="enterprise-card rounded-2xl p-5">
            <div className="mb-3"><h2 className="enterprise-section-title">Risk distribution</h2><p className="enterprise-muted mt-1">Findings by severity</p></div>
            {riskQuery.isLoading ? <Skeleton className="h-56 w-full" /> : riskQuery.isError ? <ChartEmpty label="Unable to load risk data" /> : risk ? <ReactECharts option={{ tooltip: { trigger: 'item' }, legend: { bottom: 0, icon: 'circle', itemWidth: 7, itemHeight: 7 }, series: [{ type: 'pie', radius: ['46%', '70%'], center: ['50%', '45%'], data: [{ value: risk.critical, name: 'Critical' }, { value: risk.high, name: 'High' }, { value: risk.medium, name: 'Medium' }, { value: risk.low, name: 'Low' }, { value: risk.informational, name: 'Info' }], label: { show: false } }] }} style={{ height: 224 }} /> : <ChartEmpty label="No risk data yet" />}
          </div>
        </section>

        <section className="grid gap-4 lg:grid-cols-2">
          <div className="enterprise-card rounded-2xl p-5"><div className="mb-3"><h2 className="enterprise-section-title">Findings by severity</h2><p className="enterprise-muted mt-1">Current open risk distribution</p></div>{severityOption ? <ReactECharts option={severityOption} style={{ height: 208 }} /> : <ChartEmpty label="No findings data yet" />}</div>
          <div className="enterprise-card rounded-2xl p-5"><div className="mb-3 flex items-center justify-between"><div><h2 className="enterprise-section-title">Recent validations</h2><p className="enterprise-muted mt-1">Latest execution activity</p></div><Link to="/scan" className="text-xs font-medium text-primary hover:underline">View all</Link></div><div className="space-y-2">{recent.length ? recent.slice(0, 5).map((item: any) => <Link key={item.id || item.validation_id} to={item.id ? `/validations/${item.id}/results` : '/scan'} className="flex items-center justify-between rounded-xl border border-border/70 bg-background/20 px-3 py-2.5 transition-all hover:-translate-y-0.5 hover:bg-accent"><div className="min-w-0"><div className="truncate font-mono text-xs font-semibold">{item.id || item.validation_id || 'Validation'}</div><div className="mt-0.5 truncate text-xs text-muted-foreground">{item.target_value || item.target || item.project_name || '—'}</div></div><span className="ml-3 shrink-0 rounded-full border border-border/60 bg-muted/50 px-2 py-1 text-[10px] font-semibold uppercase">{item.status || 'unknown'}</span></Link>) : <div className="rounded-xl border border-dashed border-border/70 py-10 text-center text-sm text-muted-foreground">No validation activity yet.</div>}</div></div>
        </section>

        <section className="enterprise-card rounded-2xl p-5"><div className="mb-3"><h2 className="enterprise-section-title">Next actions</h2><p className="enterprise-muted mt-1">Move directly into the next operational workflow</p></div><div className="grid grid-cols-2 gap-2 md:grid-cols-3 lg:grid-cols-6">{[[Plus, 'New validation', '/validations/new'], [FolderKanban, 'Projects', '/projects'], [Server, 'Assets', '/assets'], [Bug, 'Findings', '/vulnerabilities'], [FileText, 'Reports', '/reports'], [Settings, 'Settings', '/settings']].map(([Icon, label, href]) => <Link key={String(label)} to={String(href)} className="group rounded-xl border border-border/70 bg-background/20 p-3 transition-all hover:-translate-y-1 hover:border-primary/30 hover:bg-accent"><Icon className="h-5 w-5 text-muted-foreground transition-colors group-hover:text-primary" /><div className="mt-2 text-xs font-semibold">{String(label)}</div></Link>)}</div></section>
      </section>
    </div>
  )
}
