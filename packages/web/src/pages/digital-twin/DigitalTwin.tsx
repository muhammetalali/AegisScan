import { useState } from 'react'
import { GitBranch, Play, Copy, Layers } from 'lucide-react'
export const DigitalTwin = () => {
  const [scenario, setScenario] = useState('HSTS enabled')
  return (
    <div className="space-y-4">
      <div><h1 className="text-2xl font-bold flex items-center gap-2"><GitBranch className="h-6 w-6 text-primary" /> Digital Twin</h1><p className="text-sm text-muted-foreground">Environment • Assets • Services • Relationships • Attack Paths • Controls — What-if Simulation</p></div>
      <div className="grid lg:grid-cols-2 gap-4">
        <div className="rounded-xl border bg-card p-4">
          <h3 className="text-sm font-semibold">Current Environment</h3>
          <div className="mt-3 space-y-2 text-xs">
            <div className="rounded border p-2">Assets: 12 • Services: 18 • Relationships: 24</div>
            <div className="rounded border p-2">Attack Paths: 2 • Controls: 3</div>
          </div>
        </div>
        <div className="rounded-xl border bg-card p-4">
          <h3 className="text-sm font-semibold">Scenario Creation</h3>
          <div className="mt-3 flex gap-2">
            <select value={scenario} onChange={e=>setScenario(e.target.value)} className="flex-1 px-2 py-1.5 rounded border bg-background text-sm">
              <option>HSTS enabled</option><option>TLS 1.0 disabled</option><option>WAF enabled</option><option>IDOR patched</option>
            </select>
            <button className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm inline-flex items-center gap-1"><Play className="h-4 w-4" /> Simulate</button>
          </div>
          <div className="mt-3 rounded border bg-muted/20 p-3 text-xs">
            <div className="font-medium">Impact Analysis — {scenario}</div>
            <div className="mt-1">Before: Risk 64/100 • After: Risk 82/100 • Delta +18 ↑</div>
            <div className="mt-2 flex gap-2"><span className="px-2 py-0.5 rounded bg-emerald-500 text-white text-[11px]">Risk ↓</span><span className="px-2 py-0.5 rounded bg-muted text-[11px]">Findings 9 → 5</span></div>
          </div>
        </div>
      </div>
      <div className="rounded-xl border bg-card p-4">
        <h3 className="text-sm font-semibold flex items-center gap-1"><Layers className="h-4 w-4" /> Before → After Comparison</h3>
        <div className="mt-2 overflow-auto"><table className="w-full text-sm"><thead><tr className="border-b bg-muted/30 text-xs text-muted-foreground"><th className="text-start px-3 py-2">Metric</th><th className="text-start px-3 py-2">Before</th><th className="text-start px-3 py-2">After</th><th className="text-start px-3 py-2">Change</th></tr></thead><tbody><tr className="border-b"><td className="px-3 py-2">Critical Findings</td><td className="px-3 py-2">3</td><td className="px-3 py-2">1</td><td className="px-3 py-2 text-emerald-600">-2</td></tr><tr className="border-b"><td className="px-3 py-2">Risk Score</td><td className="px-3 py-2">64</td><td className="px-3 py-2">82</td><td className="px-3 py-2 text-emerald-600">+18</td></tr></tbody></table></div>
      </div>
    </div>
  )
}
