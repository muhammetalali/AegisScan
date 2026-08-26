import { useState } from 'react'
import { Bell, ChevronLeft, ChevronRight, LayoutDashboard, ScanLine, ShieldCheck, Settings, Boxes, FileWarning, Activity, Search, Plus, Moon } from 'lucide-react'

const navigation = [
  { label: 'Dashboard', icon: LayoutDashboard },
  { label: 'Projects', icon: Boxes },
  { label: 'Validations', icon: ScanLine },
  { label: 'Findings', icon: FileWarning },
  { label: 'Evidence', icon: ShieldCheck },
  { label: 'Activity', icon: Activity },
]

const stats = [
  ['Security Score', '87', 'Strong posture'],
  ['Projects', '12', '+2 this month'],
  ['Active Assets', '248', 'Across 12 projects'],
  ['Critical Findings', '4', '2 require attention'],
]

export default function App() {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div className="app-shell">
      <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
        <div className="brand"><div className="brand-mark"><ShieldCheck size={20} /></div>{!collapsed && <div><strong>AegisScan</strong><span>Security Platform</span></div>}</div>
        <nav>{navigation.map(({ label, icon: Icon }) => <button className={label === 'Dashboard' ? 'nav-item active' : 'nav-item'} key={label}><Icon size={18} />{!collapsed && <span>{label}</span>}</button>)}</nav>
        {!collapsed && <div className="sidebar-section"><span className="eyebrow">Workspace</span><button className="nav-item"><Settings size={18} /><span>Settings</span></button></div>}
        <button className="collapse" onClick={() => setCollapsed(v => !v)}>{collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}</button>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="search"><Search size={17} /><span>Search anything...</span><kbd>⌘ K</kbd></div>
          <div className="top-actions"><button className="icon-button"><Bell size={18} /></button><button className="icon-button"><Moon size={18} /></button><div className="avatar">MA</div></div>
        </header>

        <section className="content">
          <div className="page-heading"><div><p className="eyebrow">Security operations</p><h1>Good morning, Mohammed</h1><p className="muted">Here is your security posture across the organization.</p></div><button className="primary"><Plus size={17} /> New Validation</button></div>

          <div className="stat-grid">{stats.map(([label, value, detail]) => <article className="stat-card" key={label}><span className="muted">{label}</span><strong>{value}</strong><small>{detail}</small></article>)}</div>

          <div className="dashboard-grid">
            <article className="panel score-panel"><div className="panel-header"><div><h2>Security posture</h2><span className="muted">Organization-wide risk overview</span></div><button className="ghost">View details</button></div><div className="score-content"><div className="score-ring"><strong>87</strong><span>/ 100</span></div><div className="risk-list"><div><span>Critical</span><b>4</b></div><div><span>High</span><b>17</b></div><div><span>Medium</span><b>39</b></div><div><span>Low</span><b>82</b></div></div></div></article>
            <article className="panel activity-panel"><div className="panel-header"><div><h2>Recent activity</h2><span className="muted">Latest validation events</span></div><button className="ghost">View all</button></div><div className="activity-list"><div><i className="dot success"/><div><b>Production API validation completed</b><span>12 findings · 8 min ago</span></div></div><div><i className="dot warning"/><div><b>Critical finding confirmed</b><span>Authentication bypass · 31 min ago</span></div></div><div><i className="dot info"/><div><b>New asset discovered</b><span>api.aegisscan.local · 1 hr ago</span></div></div></div></article>
          </div>

          <div className="panel validations"><div className="panel-header"><div><h2>Active validations</h2><span className="muted">Live execution across your projects</span></div><button className="ghost">Open validations</button></div><div className="table"><div className="table-row table-head"><span>Validation</span><span>Project</span><span>Progress</span><span>Status</span></div><div className="table-row"><span><b>Production perimeter</b><small>Full Security Validation</small></span><span>Core Platform</span><span><div className="progress"><i style={{width:'72%'}}/></div></span><span className="status running">Running</span></div><div className="table-row"><span><b>API security baseline</b><small>Standard Validation</small></span><span>Public API</span><span><div className="progress"><i style={{width:'38%'}}/></div></span><span className="status running">Running</span></div></div></div>
        </section>
      </main>
    </div>
  )
}
