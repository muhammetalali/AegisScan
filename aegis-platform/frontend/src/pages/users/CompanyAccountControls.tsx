import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiHelpers } from '@/services/api'
import type { User, UserRole } from '@/types'
import { NAV_GROUPS } from '@/components/layout/navigation'

type Options = { roles: Record<string,string[]>; scan_types: string[] }
type Employee = Pick<User, 'id'|'email'|'first_name'|'last_name'|'role'|'is_active'|'is_company_owner'|'granted_permissions'|'enabled_scan_types'|'enabled_pages'>
type Accounts = { results: Employee[]; next: string | null; count: number }
const displayError = (error: unknown) => {
  const e = error as { response?: { data?: { detail?: string; password?: string[] }; status?: number } }
  const reason = e?.response?.data
  return Array.isArray(reason?.password) ? reason.password.join(' ') : reason?.detail || ('Request denied or failed (' + (e?.response?.status || 'network') + ')')
}
const toggle = (items:string[],item:string) => items.includes(item) ? items.filter(x=>x!==item) : [...items,item]

/** The one canonical company account screen; the Django user API is authoritative. */
export const CompanyAccountControls = () => {
  const cache = useQueryClient()
  const {data:options} = useQuery({queryKey:['company-access-options'],queryFn:()=>apiHelpers.get<Options>('/auth/users/access_options/'),retry:false})
  const [page,setPage]=useState(1)
  const {data:accounts, isError:accountsError} = useQuery({queryKey:['company-accounts',page],queryFn:()=>apiHelpers.get<Accounts>('/auth/users/',{params:{page}}),retry:false})
  const [email,setEmail]=useState('')
  const [first,setFirst]=useState('')
  const [last,setLast]=useState('')
  const [password,setPassword]=useState('')
  const [role,setRole]=useState<UserRole>('viewer')
  const [grants,setGrants]=useState<string[]>([])
  const [scanTypes,setScanTypes]=useState<string[]>([])
  const [pages,setPages]=useState<string[]>([])
  const [selected,setSelected]=useState<Employee|null>(null)
  const [resetPassword,setResetPassword]=useState('')
  const [busy,setBusy]=useState(false)
  const [feedback,setFeedback]=useState('')
  const [failed,setFailed]=useState(false)
  const refresh = ()=>cache.invalidateQueries({queryKey:['company-accounts']})
  const transact=async (action:()=>Promise<unknown>,message:string) => {
    setBusy(true);setFeedback('');setFailed(false)
    try {await action();setFeedback(message);await refresh()}
    catch(e){setFeedback(displayError(e));setFailed(true)}
    finally{setBusy(false)}
  }
  const select=(u:Employee)=>{
    setSelected(u);setRole(u.role)
    setGrants(u.granted_permissions ?? options?.roles[u.role] ?? [])
    setScanTypes(u.enabled_scan_types ?? options?.scan_types ?? [])
    setPages(u.enabled_pages ?? NAV_GROUPS.flatMap(g=>g.items).map(i=>i.href))
    setResetPassword('');setFeedback('')
  }
  const changeRole=(value:UserRole)=>{
    setRole(value)
    setGrants(current=>current.filter(permission=>(options?.roles[value]||[]).includes(permission)))
    const allowedPages=NAV_GROUPS.flatMap(g=>g.items).filter(item=>item.roles.includes(value)||item.roles.includes('all')).map(item=>item.href)
    setPages(current=>current.filter(page=>allowedPages.includes(page)))
  }
  const roleOptions = Object.keys(options?.roles || {}) as UserRole[]
  const pageChoices = NAV_GROUPS.flatMap(group=>group.items).filter(item=>item.href!=='/dashboard' && (item.roles.includes(role) || item.roles.includes('all')))
  const permitted = options?.roles[role] || []

  return <section className="rounded-2xl border border-border bg-card p-5 space-y-4" aria-label="Company account provisioning">
    <div>
      <h2 className="text-lg font-semibold">Company accounts — primary owner</h2>
      <p className="text-sm text-muted-foreground">Create an inactive employee, assign their pages and scan types, then activate explicitly. No public registration, email activation or MFA.</p>
    </div>
    <div className="grid gap-3 sm:grid-cols-2">
      <label className="text-sm">Employee identifier (email-style login)<input aria-label="Employee login" type="email" autoComplete="off" value={email} onChange={e=>setEmail(e.target.value)} className="mt-1 w-full rounded-lg border bg-background p-2"/></label>
      <label className="text-sm">Initial password<input aria-label="Initial employee password" type="password" autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)} className="mt-1 w-full rounded-lg border bg-background p-2"/></label>
      <label className="text-sm">First name<input aria-label="Employee first name" value={first} onChange={e=>setFirst(e.target.value)} className="mt-1 w-full rounded-lg border bg-background p-2"/></label>
      <label className="text-sm">Last name<input aria-label="Employee last name" value={last} onChange={e=>setLast(e.target.value)} className="mt-1 w-full rounded-lg border bg-background p-2"/></label>
    </div>
    <div className="rounded-xl border p-3 space-y-3">
      <label className="text-sm">Assigned role <select aria-label="Employee role" className="ms-2 rounded border bg-background p-2" value={role} onChange={e=>changeRole(e.target.value as UserRole)}>{roleOptions.map(r=><option key={r} value={r}>{r}</option>)}</select></label>
      <fieldset className="grid gap-1 sm:grid-cols-2"><legend className="mb-2 text-sm font-medium">Enabled workspace capabilities and pages</legend>{permitted.map(permission=><label className="flex items-center gap-2 text-xs" key={permission}><input type="checkbox" checked={grants.includes(permission)} onChange={()=>setGrants(x=>toggle(x,permission))}/>{permission}</label>)}</fieldset>
      <fieldset className="grid gap-1 sm:grid-cols-2"><legend className="mb-2 text-sm font-medium">Visible pages</legend>{pageChoices.map(item=><label className="flex items-center gap-2 text-xs" key={item.href}><input type="checkbox" checked={pages.includes(item.href)} onChange={()=>setPages(x=>toggle(x,item.href))}/>{item.name} ({item.href})</label>)}</fieldset>
      <fieldset className="grid gap-1 sm:grid-cols-2"><legend className="mb-2 text-sm font-medium">Allowed scan types</legend>{(options?.scan_types||[]).map(mode=><label className="flex items-center gap-2 text-xs" key={mode}><input type="checkbox" checked={scanTypes.includes(mode)} onChange={()=>setScanTypes(x=>toggle(x,mode))}/>{mode}</label>)}</fieldset>
    </div>
    <button disabled={busy||!email||!password||!first||!last} className="rounded-lg bg-primary px-4 py-2 text-sm text-primary-foreground disabled:opacity-50" onClick={()=>transact(async()=>{
      await apiHelpers.post('/auth/users/',{email,first_name:first,last_name:last,password,password_confirm:password,role,granted_permissions:grants,enabled_scan_types:scanTypes,enabled_pages:pages})
      setEmail('');setPassword('');setFirst('');setLast('');setGrants([]);setScanTypes([]);setPages([])
    },'Employee created inactive. Choose the employee below and activate when ready.')}>Create inactive employee</button>
    {accountsError&&<p role="alert" className="text-sm text-destructive">Employee inventory unavailable. No changes made.</p>}
    <div className="space-y-2">
      <h3 className="font-medium text-sm">Existing company accounts</h3>
      {(accounts?.results||[]).map(u=><button key={u.id} className="block w-full rounded-lg border p-2 text-start text-sm hover:bg-muted" onClick={()=>select(u)}>{u.email} — {u.role} — {u.is_active?'Active':'Inactive'}</button>)}
      <div className="flex items-center gap-3 text-sm"><button className="rounded border px-3 py-1 disabled:opacity-50" disabled={page===1} onClick={()=>setPage(current=>Math.max(1,current-1))}>Previous</button><span>Page {page} · {accounts?.count||0} accounts</span><button className="rounded border px-3 py-1 disabled:opacity-50" disabled={!accounts?.next} onClick={()=>setPage(current=>current+1)}>Next</button></div>
    </div>
    {selected?.is_company_owner&&<p role="status" className="text-sm">The primary owner account is protected. Its settings are not changed through employee controls.</p>}
    {selected&&!selected.is_company_owner&&<div className="space-y-3 rounded-xl border p-3">
      <h3 className="font-medium text-sm">Selected: {selected.email}</h3>
      <p className="text-xs text-muted-foreground">The controls above now edit this account's role, pages and scan types. Only the primary owner can commit changes.</p>
      <div className="flex flex-wrap gap-2">
        <button className="rounded-lg border px-3 py-2 text-sm disabled:opacity-50" disabled={busy} onClick={()=>transact(()=>apiHelpers.patch('/auth/users/'+selected.id+'/',{role,granted_permissions:grants,enabled_scan_types:scanTypes,enabled_pages:pages}),'Employee permissions updated.')}>Save permissions</button>
        <button className="rounded-lg border px-3 py-2 text-sm disabled:opacity-50" disabled={busy} onClick={()=>transact(async()=>{await apiHelpers.post('/auth/users/'+selected.id+'/'+(selected.is_active?'deactivate':'activate')+'/',{});setSelected(current=>current?.id===selected.id?{...current,is_active:!current.is_active}:current)},'Account activation updated.')}>{selected.is_active?'Deactivate':'Activate'} employee</button>
      </div>
      <label className="block text-sm">Set employee password<input aria-label="Replacement employee password" type="password" autoComplete="new-password" value={resetPassword} onChange={e=>setResetPassword(e.target.value)} className="mt-1 w-full rounded-lg border bg-background p-2"/></label>
      <button className="rounded-lg border px-3 py-2 text-sm disabled:opacity-50" disabled={busy||!resetPassword} onClick={()=>transact(async()=>{
        await apiHelpers.post('/auth/users/'+selected.id+'/set_password/',{password:resetPassword})
        setResetPassword('')
      },'Employee password changed; existing refresh sessions revoked.')}>Set new password</button>
    </div>}
    {feedback&&<p role={failed?'alert':'status'} className={'text-sm '+(failed?'text-destructive':'text-muted-foreground')}>{feedback}</p>}
  </section>
}
