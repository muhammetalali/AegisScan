import { useQuery } from '@tanstack/react-query'
import ReactECharts from 'echarts-for-react'
import { TrendingUp, Shield, AlertTriangle } from 'lucide-react'
import { apiHelpers } from '@/services/api'

export const SecurityPosture = () => {
  const { data: trends } = useQuery({ queryKey:['posture-trends'], queryFn:()=>apiHelpers.get<any>('/dashboard/trends?days=30').catch(()=>null) })
  const { data: risk } = useQuery({ queryKey:['posture-risk'], queryFn:()=>apiHelpers.get<any>('/dashboard/risk-distribution').catch(()=>null) })
  const score = 78
  return (
    <div className="space-y-4">
      <div><h1 className="text-2xl font-bold flex items-center gap-2"><TrendingUp className="h-6 w-6 text-primary" /> Security Posture</h1><p className="text-sm text-muted-foreground">Security Score • Risk Trend • Maturity • Control Coverage • Before/After Compare</p></div>
      <div className="grid md:grid-cols-4 gap-3">
        <div className="rounded-xl border bg-card p-4 text-center"><div className="text-3xl font-bold">{score}<span className="text-sm">/100</span></div><div className="text-xs text-muted-foreground">Security Score</div></div>
        <div className="rounded-xl border bg-card p-4 text-center"><div className="text-2xl font-bold text-red-600">{risk?.critical ?? 3}</div><div className="text-xs text-muted-foreground">Critical Risk</div></div>
        <div className="rounded-xl border bg-card p-4 text-center"><div className="text-2xl font-bold">72%</div><div className="text-xs text-muted-foreground">Control Coverage</div></div>
        <div className="rounded-xl border bg-card p-4 text-center"><div className="text-2xl font-bold">64%</div><div className="text-xs text-muted-foreground">Remediation Rate</div></div>
      </div>
      <div className="grid lg:grid-cols-2 gap-4">
        <div className="rounded-xl border bg-card p-4"><h3 className="text-sm font-semibold">Risk Trend (30d)</h3>{trends ? <ReactECharts option={{ xAxis:{type:'category', data: trends.map((t:any)=>t.date.slice(5))}, yAxis:{type:'value'}, series:[{type:'line', data: trends.map((t:any)=>t.score), smooth:true, areaStyle:{}}], tooltip:{trigger:'axis'}, grid:{left:30,right:10,top:10,bottom:20} }} style={{height:220}} /> : <div className="h-56 grid place-items-center text-sm text-muted-foreground">No data</div>}</div>
        <div className="rounded-xl border bg-card p-4"><h3 className="text-sm font-semibold">Maturity vs Coverage</h3><div className="mt-4 space-y-2 text-xs"><div className="flex justify-between"><span>Detection Coverage</span><span>68%</span></div><div className="h-2 rounded bg-muted overflow-hidden"><div className="h-full bg-primary" style={{width:'68%'}} /></div><div className="flex justify-between mt-2"><span>Control Coverage</span><span>72%</span></div><div className="h-2 rounded bg-muted overflow-hidden"><div className="h-full bg-emerald-500" style={{width:'72%'}} /></div></div></div>
      </div>
      <div className="rounded-xl border bg-card p-4">
        <h3 className="text-sm font-semibold">Project Comparison</h3>
        <div className="overflow-auto mt-2"><table className="w-full text-sm"><thead><tr className="border-b bg-muted/30 text-xs text-muted-foreground"><th className="text-start px-3 py-2">Project</th><th className="text-start px-3 py-2">Current</th><th className="text-start px-3 py-2">Previous</th><th className="text-start px-3 py-2">Delta</th></tr></thead><tbody><tr className="border-b"><td className="px-3 py-2">E-Commerce</td><td className="px-3 py-2">78</td><td className="px-3 py-2">61</td><td className="px-3 py-2 text-emerald-600">+17 ↑</td></tr><tr className="border-b"><td className="px-3 py-2">API Gateway</td><td className="px-3 py-2">92</td><td className="px-3 py-2">88</td><td className="px-3 py-2 text-emerald-600">+4 ↑</td></tr></tbody></table></div>
      </div>
    </div>
  )
}
