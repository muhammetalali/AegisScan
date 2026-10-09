import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Shield, Users2, Key, Clock, Building2, Lock } from 'lucide-react'
import { cn } from '@/utils/cn'
import { apiHelpers } from '@/services/api'
import { KeyManagementPage } from './KeyManagementPage'
import { CompanyAccountControls } from './CompanyAccountControls'
import { useAuthStore } from '@/stores/authStore'

type Tab = 'users'|'teams'|'roles'|'sessions'|'keys'|'attempts'
const TABS: {id:Tab; label:string; icon:any}[] = [
  {id:'users', label:'Users', icon: Users2},
  {id:'teams', label:'Teams', icon: Building2},
  {id:'roles', label:'Roles (7)', icon: Shield},
  {id:'sessions', label:'Sessions', icon: Clock},
  {id:'keys', label:'API Keys', icon: Key},
  {id:'attempts', label:'Login Attempts', icon: Lock},
]

export const Users = () => {
  const [tab, setTab] = useState<Tab>('users')
  const owner = useAuthStore(s=>s.user?.is_company_owner === true)
  const usersQuery = useQuery({ queryKey:['audit-users'], queryFn:()=>apiHelpers.get<any>('/audit/users'), enabled: tab==='users', retry:false })
  const teamsQuery = useQuery({ queryKey:['audit-teams'], queryFn:()=>apiHelpers.get<any>('/audit/teams'), enabled: tab==='teams', retry:false })
  const rolesQuery = useQuery({ queryKey:['audit-roles'], queryFn:()=>apiHelpers.get<any>('/audit/roles'), enabled: tab==='roles', retry:false })
  const sessionsQuery = useQuery({ queryKey:['audit-sessions'], queryFn:()=>apiHelpers.get<any>('/audit/sessions'), enabled: tab==='sessions', retry:false })
  const attemptsQuery = useQuery({ queryKey:['audit-attempts'], queryFn:()=>apiHelpers.get<any>('/audit/login-attempts'), enabled: tab==='attempts', retry:false })

  const users=usersQuery.data, teams=teamsQuery.data, roles=rolesQuery.data, sessions=sessionsQuery.data, attempts=attemptsQuery.data
  const activeQuery=({users:usersQuery,teams:teamsQuery,roles:rolesQuery,sessions:sessionsQuery,attempts:attemptsQuery} as const)[tab as Exclude<Tab,'keys'>]
  return (
    <div className="p-6 max-w-6xl mx-auto space-y-4">
      <div>
        <h1 className="text-2xl font-bold">RBAC & Access</h1>
        <p className="text-sm text-muted-foreground">Users • Teams • 7 Roles • Sessions • API Keys • Login Attempts — with permissions & audit trail</p>
      </div>
      <div className="flex gap-1 border-b overflow-auto">
        {TABS.map(t=> <button key={t.id} onClick={()=>setTab(t.id)} className={cn('px-3 py-2 text-xs font-medium border-b-2 inline-flex items-center gap-1 whitespace-nowrap', tab===t.id ? 'border-primary text-primary' : 'border-transparent text-muted-foreground')}><t.icon className="h-3.5 w-3.5" />{t.label}</button>)}
      </div>

      {tab!=='keys' && activeQuery?.isError && <p role="alert" className="rounded-xl border border-destructive p-4 text-sm text-destructive">{(activeQuery.error as any)?.response?.status===403?'403 · Your role is not allowed to read this audit collection.':'Unable to retrieve this audit collection.'}</p>}
      {tab==='users' && owner && <CompanyAccountControls />}
      {tab==='users' && (
        <div className="rounded-xl border bg-card overflow-hidden">
          <table className="w-full text-xs"><thead><tr className="border-b bg-muted/20 text-muted-foreground"><th className="text-start px-3 py-2">User</th><th className="text-start px-3 py-2">Role</th><th className="text-start px-3 py-2">Team</th><th className="text-start px-3 py-2">Status</th><th className="text-start px-3 py-2">Last login</th></tr></thead>
            <tbody>{(users?.items||[]).map((u:any)=> <tr key={u.id} className="border-b"><td className="px-3 py-2"><div className="font-medium">{u.name}</div><div className="font-mono text-[11px] text-muted-foreground">{u.email}</div></td><td className="px-3 py-2"><span className="px-1.5 py-0.5 rounded bg-primary text-primary-foreground text-[11px]">{u.role}</span></td><td className="px-3 py-2">{u.team||'—'}</td><td className="px-3 py-2">{u.status}</td><td className="px-3 py-2 text-[11px]">{u.last_login?new Date(u.last_login).toLocaleString():'Never'}</td></tr>)}</tbody>
          </table>
        </div>
      )}
      {tab==='teams' && (
        <div className="grid md:grid-cols-3 gap-3">{(teams?.items||[]).map((tm:any)=> <div key={tm.id} className="rounded-xl border bg-card p-4"><div className="font-medium">{tm.name}</div><div className="text-xs text-muted-foreground">{tm.members} members</div></div>)}</div>
      )}
      {tab==='roles' && (
        <div className="rounded-xl border bg-card overflow-hidden">
          <table className="w-full text-xs"><thead><tr className="border-b bg-muted/20 text-muted-foreground"><th className="text-start px-3 py-2">Role</th><th className="text-start px-3 py-2">Description</th><th className="text-start px-3 py-2">Permissions</th></tr></thead>
            <tbody>{(roles?.items||[]).map((r:any)=> <tr key={r.id} className="border-b"><td className="px-3 py-2 font-mono font-medium">{r.id}</td><td className="px-3 py-2">{r.description||r.name||'—'}</td><td className="px-3 py-2 font-mono text-[11px]">{Array.isArray(r.permissions)?r.permissions.join(', '):'Server-enforced role permissions'}</td></tr>)}</tbody>
          </table>
          <div className="px-3 py-2 text-[11px] text-muted-foreground">7 Roles: Super Admin • Admin • Security Manager • Security Analyst • Developer • Auditor • Viewer</div>
        </div>
      )}
      {tab==='sessions' && (
        <div className="rounded-xl border bg-card p-3 space-y-2">{(sessions?.items||[]).map((s:any)=> <div key={s.id} className="rounded border p-2 text-xs font-mono"><div>{s.user} — {s.ip}</div><div className="text-muted-foreground">{s.user_agent}</div></div>)}</div>
      )}
      {tab==='keys' && <KeyManagementPage />}
      {tab==='attempts' && (
        <div className="rounded-xl border bg-card overflow-hidden"><table className="w-full text-xs"><thead><tr className="border-b bg-muted/20 text-muted-foreground"><th className="text-start px-3 py-2">User</th><th className="text-start px-3 py-2">IP</th><th className="text-start px-3 py-2">Result</th><th className="text-start px-3 py-2">Time</th></tr></thead><tbody>{(attempts?.items||[]).map((a:any)=> <tr key={a.id} className="border-b"><td className="px-3 py-2 font-mono">{a.email}</td><td className="px-3 py-2 font-mono">{a.ip}</td><td className="px-3 py-2"><span className={cn('px-1.5 py-0.5 rounded text-[11px]', a.success ? 'bg-emerald-500 text-white' : 'bg-destructive text-destructive-foreground')}>{a.success?'success':'failed'}</span></td><td className="px-3 py-2 text-[11px]">{new Date(a.timestamp).toLocaleString()}</td></tr>)}</tbody></table></div>
      )}
    </div>
  )
}
