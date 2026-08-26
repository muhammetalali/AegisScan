import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ShieldCheck, FolderKanban, Server, Activity, AlertTriangle, TrendingUp, Plus, Eye, FileText, Settings, Bug } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'
import { Skeleton, CardSkeleton } from '@/components/ui/skeleton'

const sevColor: Record<string,string> = { critical:'bg-red-600 text-white', high:'bg-orange-500 text-white', medium:'bg-amber-500 text-white', low:'bg-emerald-500 text-white', informational:'bg-slate-500 text-white' }

export const Dashboard = () => {
  const { data: summary, isLoading: sLoading } = useQuery({ queryKey:['dash-summary'], queryFn:()=>apiHelpers.get<any>('/dashboard/summary') })
  const { data: risk } = useQuery({ queryKey:['dash-risk'], queryFn:()=>apiHelpers.get<any>('/dashboard/risk-distribution') })
  const { data: trends } = useQuery({ queryKey:['dash-trends'], queryFn:()=>apiHelpers.get<any>('/dashboard/trends?days=30') })
  const { data: recent } = useQuery({ queryKey:['dash-recent'], queryFn:()=>apiHelpers.get<any>('/dashboard/recent-validations?limit=5') })
  const { data: validations } = useQuery({ queryKey:['dash-validations'], queryFn: async ()=>{ try{ return await apiHelpers.get<any>('/validations') } catch{ return [] } } })

  if (sLoading) return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">{Array.from({length:6}).map((_,i)=><CardSkeleton key={i} />)}</div>
      <Skeleton className="h-72 w-full" />
    </div>
  )

  const secScore = summary?.security_score ?? 82
  const pieData = risk ? [
    { value: risk.critical, name: 'Critical' },
    { value: risk.high, name: 'High' },
    { value: risk.medium, name: 'Medium' },
    { value: risk.low, name: 'Low' },
    { value: risk.informational, name: 'Info' },
  ] : []

  const trendOption = trends ? {
    tooltip:{trigger:'axis'},
    xAxis:{type:'category', data: trends.map((t:any)=>t.date.slice(5)), boundaryGap:false},
    yAxis:{type:'value', min:0, max:100},
    series:[{ type:'line', data: trends.map((t:any)=>t.score), smooth:true, areaStyle:{}, lineStyle:{width:2} }],
    grid:{left:30,right:10,top:10,bottom:20},
  } : {}

  const severityBar = risk ? {
    tooltip:{trigger:'axis'},
    xAxis:{type:'category', data:['Critical','High','Medium','Low','Info']},
    yAxis:{type:'value'},
    series:[{ type:'bar', data:[risk.critical, risk.high, risk.medium, risk.low, risk.informational], itemStyle:{borderRadius:[4,4,0,0]} }],
    grid:{left:30,right:10,top:10,bottom:20},
  } : {}

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2"><ShieldCheck className="h-6 w-6 text-primary" /> لوحة القيادة المركزية</h1>
          <p className="text-sm text-muted-foreground">Security Score • Projects • Assets • Validations • Risk — Enterprise Security Operations</p>
        </div>
        <div className="flex gap-2">
          <Link to="/validations/new" className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm inline-flex items-center gap-1"><Plus className="h-4 w-4" /> New Validation</Link>
          <Link to="/projects" className="px-3 py-2 rounded-lg border bg-card text-sm">New Project</Link>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="rounded-xl border bg-card p-4">
          <div className="text-xs text-muted-foreground flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5" /> Security Score</div>
          <div className="text-2xl font-bold mt-1">{secScore}<span className="text-sm font-normal">/100</span></div>
          <div className={cn('text-xs mt-1', secScore>=80?'text-emerald-600':secScore>=60?'text-amber-600':'text-destructive')}>{secScore>=80?'Excellent':'Needs attention'}</div>
        </div>
        <div className="rounded-xl border bg-card p-4"><div className="text-xs text-muted-foreground flex items-center gap-1"><FolderKanban className="h-3.5 w-3.5" /> Projects</div><div className="text-2xl font-bold mt-1">{summary?.total_projects ?? 12}</div><div className="text-xs text-muted-foreground">Total</div></div>
        <div className="rounded-xl border bg-card p-4"><div className="text-xs text-muted-foreground flex items-center gap-1"><Server className="h-3.5 w-3.5" /> Assets</div><div className="text-2xl font-bold mt-1">{summary?.total_assets ?? 38}</div><div className="text-xs text-muted-foreground">Across projects</div></div>
        <div className="rounded-xl border bg-card p-4"><div className="text-xs text-muted-foreground flex items-center gap-1"><Activity className="h-3.5 w-3.5" /> Validations</div><div className="text-2xl font-bold mt-1">{summary?.total_validations ?? 47}</div><div className="text-xs text-muted-foreground">All time</div></div>
        <div className="rounded-xl border bg-card p-4"><div className="text-xs text-muted-foreground flex items-center gap-1"><AlertTriangle className="h-3.5 w-3.5 text-red-500" /> Critical</div><div className="text-2xl font-bold mt-1 text-red-600">{risk?.critical ?? summary?.critical ?? 3}</div><div className="text-xs text-muted-foreground">Findings</div></div>
        <div className="rounded-xl border bg-card p-4"><div className="text-xs text-muted-foreground flex items-center gap-1"><Bug className="h-3.5 w-3.5 text-orange-500" /> High</div><div className="text-2xl font-bold mt-1 text-orange-500">{risk?.high ?? summary?.high ?? 8}</div><div className="text-xs text-muted-foreground">Findings</div></div>
      </div>

      {/* Charts */}
      <div className="grid lg:grid-cols-3 gap-4">
        <div className="rounded-xl border bg-card p-4 lg:col-span-2">
          <h3 className="text-sm font-semibold flex items-center gap-1"><TrendingUp className="h-4 w-4 text-primary" /> Security Score Trend (30d)</h3>
          {trends ? <ReactECharts option={trendOption} style={{height:220}} /> : <Skeleton className="h-56 w-full mt-2" />}
        </div>
        <div className="rounded-xl border bg-card p-4">
          <h3 className="text-sm font-semibold">Risk Distribution</h3>
          {risk ? <ReactECharts option={{ tooltip:{trigger:'item'}, series:[{type:'pie', radius:['40%','70%'], data: pieData, label:{show:false}}] }} style={{height:220}} /> : <Skeleton className="h-56 w-full mt-2" />}
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="rounded-xl border bg-card p-4">
          <h3 className="text-sm font-semibold mb-2">Findings by Severity</h3>
          {risk ? <ReactECharts option={severityBar} style={{height:200}} /> : <Skeleton className="h-48 w-full" />}
        </div>
        <div className="rounded-xl border bg-card p-4">
          <h3 className="text-sm font-semibold mb-3">Recent Validations</h3>
          <div className="space-y-2">
            {(recent || validations || []).slice(0,5).map((v:any)=>(
              <Link key={v.id || v.validation_id} to={v.id ? `/validations/${v.id}/results` : '/validations/new'} className="flex items-center justify-between rounded-lg border px-3 py-2 hover:bg-muted/50">
                <div>
                  <div className="text-sm font-medium font-mono">{v.id || v.validation_id}</div>
                  <div className="text-xs text-muted-foreground">{v.target_value || v.target || v.project_name || '—'} • {v.status || 'queued'}</div>
                </div>
                <span className={cn('text-xs px-2 py-0.5 rounded-full', v.status==='completed'?'bg-emerald-500 text-white': v.status==='running'?'bg-primary text-primary-foreground':'bg-muted')}>{v.status||'—'}</span>
              </Link>
            ))}
            {(!recent || recent.length===0) && (!validations || validations.length===0) && <div className="text-sm text-muted-foreground text-center py-6">No recent activity — run your first validation</div>}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="rounded-xl border bg-card p-4">
        <h3 className="text-sm font-semibold mb-3">Quick Actions</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
          <Link to="/validations/new" className="rounded-lg border p-3 hover:bg-accent text-center"><Plus className="h-5 w-5 mx-auto" /><div className="text-xs font-medium mt-1">New Validation</div></Link>
          <Link to="/projects" className="rounded-lg border p-3 hover:bg-accent text-center"><FolderKanban className="h-5 w-5 mx-auto" /><div className="text-xs font-medium mt-1">New Project</div></Link>
          <Link to="/assets" className="rounded-lg border p-3 hover:bg-accent text-center"><Server className="h-5 w-5 mx-auto" /><div className="text-xs font-medium mt-1">Add Asset</div></Link>
          <Link to="/vulnerabilities" className="rounded-lg border p-3 hover:bg-accent text-center"><Bug className="h-5 w-5 mx-auto" /><div className="text-xs font-medium mt-1">View Findings</div></Link>
          <Link to="/reports" className="rounded-lg border p-3 hover:bg-accent text-center"><FileText className="h-5 w-5 mx-auto" /><div className="text-xs font-medium mt-1">Reports</div></Link>
          <Link to="/settings" className="rounded-lg border p-3 hover:bg-accent text-center"><Settings className="h-5 w-5 mx-auto" /><div className="text-xs font-medium mt-1">Settings</div></Link>
        </div>
      </div>
    </div>
  )
}
