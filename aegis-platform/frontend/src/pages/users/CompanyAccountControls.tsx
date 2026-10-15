import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiHelpers } from '@/services/api'
import type { User, UserRole } from '@/types'
import { NAV_GROUPS } from '@/components/layout/navigation'
import { useAuthStore } from '@/stores/authStore'

type Options = { roles: Record<string,string[]>; scan_types: string[] }
type Employee = Pick<User, 'id'|'email'|'first_name'|'last_name'|'role'|'is_active'|'is_company_owner'|'granted_permissions'|'enabled_scan_types'|'enabled_pages'>
type Accounts = { results: Employee[]; next: string | null; count: number }
const displayError = (error: unknown) => {
  const e = error as { response?: { data?: { detail?: string; password?: string[] }; status?: number } }
  const reason = e?.response?.data
  return Array.isArray(reason?.password) ? reason.password.join(' ') : reason?.detail || ('Request denied or failed (' + (e?.response?.status || 'network') + ')')
}
const toggle = (items:string[],item:string) => items.includes(item) ? items.filter(x=>x!==item) : [...items,item]
const cnFilter = (selected:boolean) => 'rounded-md px-3 py-1.5 transition-colors ' + (selected?'bg-primary text-primary-foreground':'text-muted-foreground hover:bg-muted')

/** The one canonical company account screen; the Django user API is authoritative. */
export const CompanyAccountControls = () => {
  const actor = useAuthStore(state => state.user)
  const isOwner = actor?.is_company_owner === true
  const has = (grant: string) => isOwner || actor?.permissions?.includes(grant) === true
  const canCreate = has('user.create')
  const canUpdate = has('user.update')
  const canDelete = has('user.delete')
  const canAssignRoles = has('user.manage_roles')
  const canAssignGrants = has('user.manage_permissions')
  const cache = useQueryClient()
  const {data:options} = useQuery({queryKey:['company-access-options'],queryFn:()=>apiHelpers.get<Options>('/auth/users/access_options/'),retry:false})
  const [page,setPage]=useState(1)
  const [visibility,setVisibility]=useState<'active'|'all'>('active')
  const [search,setSearch]=useState('')
  const [submittedSearch,setSubmittedSearch]=useState('')
  const {data:accounts, isError:accountsError, error:accountsErrorCause} = useQuery({
    queryKey:['company-accounts',page,visibility,submittedSearch],
    queryFn:()=>apiHelpers.get<Accounts>('/auth/users/',{params:{page,status:visibility,q:submittedSearch}}),
    retry:false,
  })
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
  const [additionalKeepEmail,setAdditionalKeepEmail]=useState('')
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
  const revokeOtherActiveAccounts=async()=>{
    if(!isOwner||!canDelete||!actor?.email){setFailed(true);setFeedback('Only the authenticated company owner can run account cleanup.');return}
    const keepEmail=additionalKeepEmail.trim().toLowerCase()
    if(!keepEmail||keepEmail===actor.email.toLowerCase()){
      setFailed(true);setFeedback('Enter the existing second account email to retain in addition to the owner.');return
    }
    setBusy(true);setFailed(false);setFeedback('')
    let revoked=0
    try {
      // Read-only preflight on the canonical owner-scoped list. An exact existing
      // second account must be confirmed before even offering the operation.
      const retained=await apiHelpers.get<Accounts>('/auth/users/',{params:{page:1,status:'all',q:keepEmail}})
      if(retained.count!==1||retained.results.length!==1||retained.results[0].email.toLowerCase()!==keepEmail||retained.results[0].is_company_owner){
        throw new Error('The additional retained account was not found uniquely. No changes made.')
      }
      const active:Employee[]=[]
      const seen=new Set<string>()
      let pageNumber=1
      let next=true
      let expectedCount:number|undefined
      while(next && pageNumber<=30){
        const batch=await apiHelpers.get<Accounts>('/auth/users/',{params:{page:pageNumber,status:'active',q:''}})
        if(expectedCount!==undefined&&batch.count!==expectedCount)throw new Error('Account inventory changed during review. No changes made.')
        expectedCount=batch.count
        for(const account of batch.results){
          if(!account.is_active||seen.has(account.id))throw new Error('Account inventory is inconsistent. No changes made.')
          seen.add(account.id);active.push(account)
        }
        next=Boolean(batch.next)
        pageNumber++
      }
      if(next||expectedCount===undefined||active.length!==expectedCount){
        throw new Error('Could not verify the complete active inventory. No changes made.')
      }
      const owners=active.filter(account=>account.is_company_owner)
      if(owners.length!==1||owners[0].email.toLowerCase()!==actor.email.toLowerCase()){
        throw new Error('The authenticated primary owner could not be verified in the active inventory. No changes made.')
      }
      const toRevoke=active.filter(account=>!account.is_company_owner&&account.email.toLowerCase()!==keepEmail)
      if(!toRevoke.length){setFeedback('No other active accounts need revocation. Existing inactive audit records are retained.');return}
      if(!window.confirm('Revoke sign-in access for '+toRevoke.length+' other active accounts? The owner and '+keepEmail+' will be preserved; audit history stays intact.\n\n'+toRevoke.map(account=>account.email).join('\n'))){
        setFeedback('Cleanup canceled; no accounts changed.');return
      }
      // Reuse the same one-account soft-revocation endpoint and append-only
      // audit flow, sequentially. Stop at the first failure and report partials.
      for(const account of toRevoke){
        await apiHelpers.delete('/auth/users/'+account.id+'/')
        revoked++
      }
      setSelected(null)
      setFeedback('Revoked '+revoked+' active accounts. Both retained identities preserved; audit records remain.')
    }catch(error){
      setFailed(true)
      setFeedback('Cleanup stopped after '+revoked+' revocations. '+(error instanceof Error?error.message:displayError(error)))
    }finally{setBusy(false);void refresh()}
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
  const pageChoices = NAV_GROUPS.flatMap(group=>group.items).filter(item=>
    item.href!=='/dashboard' &&
    (item.roles.includes(role) || item.roles.includes('all')) &&
    (isOwner || actor?.enabled_pages == null || actor.enabled_pages.includes(item.href))
  )
  const permitted = options?.roles[role] || []
  const selectedProtected = selected?.is_company_owner || (!isOwner && selected?.role === 'super_admin')

  return <section className="rounded-2xl border border-border bg-card p-5 space-y-4" aria-label="Company account provisioning">
    <div>
      <h2 className="text-lg font-semibold">Company accounts — authorized management</h2>
      <p className="text-sm text-muted-foreground">Manage employee accounts according to your existing delegated grants. No public registration, email activation or MFA.</p>
    </div>
    {canCreate&&<div className="grid gap-3 sm:grid-cols-2">
      <label className="text-sm">Employee identifier (email-style login)<input aria-label="Employee login" type="email" autoComplete="off" value={email} onChange={e=>setEmail(e.target.value)} className="mt-1 w-full rounded-lg border bg-background p-2"/></label>
      <label className="text-sm">Initial password<input aria-label="Initial employee password" type="password" autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)} className="mt-1 w-full rounded-lg border bg-background p-2"/></label>
      <label className="text-sm">First name<input aria-label="Employee first name" value={first} onChange={e=>setFirst(e.target.value)} className="mt-1 w-full rounded-lg border bg-background p-2"/></label>
      <label className="text-sm">Last name<input aria-label="Employee last name" value={last} onChange={e=>setLast(e.target.value)} className="mt-1 w-full rounded-lg border bg-background p-2"/></label>
    </div>}
    <div className="rounded-xl border p-3 space-y-3">
      {canAssignRoles&&<label className="text-sm">Assigned role <select aria-label="Employee role" className="ms-2 rounded border bg-background p-2" value={role} onChange={e=>changeRole(e.target.value as UserRole)}>{roleOptions.map(r=><option key={r} value={r}>{r}</option>)}</select></label>}
      <details className="rounded-lg border border-dashed p-3"><summary className="cursor-pointer text-xs font-semibold text-muted-foreground">Advanced access: permissions, pages and scan types</summary><div className="mt-3 space-y-3">
      {canAssignGrants&&<fieldset className="grid gap-1 sm:grid-cols-2"><legend className="mb-2 text-sm font-medium">Enabled workspace capabilities and pages</legend>{permitted.map(permission=><label className="flex items-center gap-2 text-xs" key={permission}><input type="checkbox" checked={grants.includes(permission)} onChange={()=>setGrants(x=>toggle(x,permission))}/>{permission}</label>)}</fieldset>}
      <fieldset className="grid gap-1 sm:grid-cols-2"><legend className="mb-2 text-sm font-medium">Visible pages</legend>{pageChoices.map(item=><label className="flex items-center gap-2 text-xs" key={item.href}><input type="checkbox" checked={pages.includes(item.href)} onChange={()=>setPages(x=>toggle(x,item.href))}/>{item.name} ({item.href})</label>)}</fieldset>
      <fieldset className="grid gap-1 sm:grid-cols-2"><legend className="mb-2 text-sm font-medium">Allowed scan types</legend>{(options?.scan_types||[]).map(mode=><label className="flex items-center gap-2 text-xs" key={mode}><input type="checkbox" checked={scanTypes.includes(mode)} onChange={()=>setScanTypes(x=>toggle(x,mode))}/>{mode}</label>)}</fieldset>
      </div></details>
    </div>
    {canCreate&&<button disabled={busy||!email||!password||!first||!last} className="rounded-lg bg-primary px-4 py-2 text-sm text-primary-foreground disabled:opacity-50" onClick={()=>transact(async()=>{
      const created = await apiHelpers.post<Employee>('/auth/users/',{email,first_name:first,last_name:last,password,password_confirm:password,role:canAssignRoles?role:'viewer',granted_permissions:canAssignGrants?grants:[],enabled_scan_types:scanTypes,enabled_pages:pages})
      // The manager already knows this newly created account's ID. Do not
      // require user.read or a second inventory lookup to activate it.
      setEmail('');setPassword('');setFirst('');setLast('');setGrants([]);setScanTypes([]);setPages([])
      // Restore the selected account's real scopes AFTER clearing the create form.
      // Both forms share permission/page state; reversing this order would silently
      // reset the newly selected employee's grants before a subsequent Save.
      if (canUpdate && created?.id) select({...created,is_active:false,is_company_owner:false})
    },canUpdate?'Employee created inactive. Activate it below when ready.':'Employee created inactive. An authorized manager with update permission can activate it.')}>Create inactive employee</button>}
    {accountsError&&<p role="alert" className="text-sm text-destructive">{(accountsErrorCause as any)?.response?.status===403?'403 · Employee inventory requires the user.read grant.':'Employee inventory unavailable. No changes made.'}</p>}
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-medium text-sm">Company accounts</h3>
        <div className="flex rounded-lg border p-0.5 text-xs" aria-label="Account visibility">
          <button type="button" aria-pressed={visibility==='active'} className={cnFilter(visibility==='active')} onClick={()=>{setVisibility('active');setPage(1);setSelected(null)}}>Active accounts</button>
          <button type="button" aria-pressed={visibility==='all'} className={cnFilter(visibility==='all')} onClick={()=>{setVisibility('all');setPage(1);setSelected(null)}}>All history</button>
        </div>
      </div>
      <form className="flex flex-wrap gap-2" onSubmit={event=>{event.preventDefault();setSubmittedSearch(search.trim());setPage(1);setSelected(null)}}>
        <input type="search" aria-label="Search account email" placeholder="Find account by email" value={search} onChange={event=>setSearch(event.target.value)} className="min-w-0 flex-1 rounded-lg border bg-background px-3 py-2 text-sm"/>
        <button type="submit" className="rounded-lg border px-3 py-2 text-xs">Find account</button>
      </form>
      <p className="text-xs text-muted-foreground">{visibility==='active'?'Only active accounts are shown. Use All history to find inactive accounts for activation.':'Inactive records remain available for audit; revoking access does not erase history.'} Select an account to view its actions.</p>
      {(accounts?.results||[]).map(u=><button key={u.id} className="block w-full rounded-lg border p-2 text-start text-sm hover:bg-muted" onClick={()=>select(u)}>{u.email} — {u.role} — {u.is_active?'Active':'Inactive'}</button>)}
      {!accountsError&&accounts?.results?.length===0&&<p className="rounded-lg border border-dashed p-4 text-center text-xs text-muted-foreground">No matching accounts in this view.</p>}
      <div className="flex items-center gap-3 text-sm"><button className="rounded border px-3 py-1 disabled:opacity-50" disabled={page===1} onClick={()=>setPage(current=>Math.max(1,current-1))}>Previous</button><span>Page {page} · {accounts?.count||0} accounts</span><button className="rounded border px-3 py-1 disabled:opacity-50" disabled={!accounts?.next} onClick={()=>setPage(current=>current+1)}>Next</button></div>
    </div>
    {selectedProtected&&<p role="status" className="text-sm">This privileged account is protected from delegated changes.</p>}
    {selected&&!selectedProtected&&canUpdate&&<div className="space-y-3 rounded-xl border p-3">
      <h3 className="font-medium text-sm">Selected: {selected.email}</h3>
      <p className="text-xs text-muted-foreground">Changes are limited to the permissions granted to your account. Privileged accounts remain protected.</p>
      <div className="flex flex-wrap gap-2">
        <button className="rounded-lg border px-3 py-2 text-sm disabled:opacity-50" disabled={busy} onClick={()=>transact(()=>apiHelpers.patch('/auth/users/'+selected.id+'/',{...(canAssignRoles?{role}:{}),...(canAssignGrants?{granted_permissions:grants}:{}),enabled_scan_types:scanTypes,enabled_pages:pages}),'Employee permissions updated.')}>Save permissions</button>
        <button className="rounded-lg border px-3 py-2 text-sm disabled:opacity-50" disabled={busy} onClick={()=>transact(async()=>{await apiHelpers.post('/auth/users/'+selected.id+'/'+(selected.is_active?'deactivate':'activate')+'/',{});setSelected(current=>current?.id===selected.id?{...current,is_active:!current.is_active}:current)},'Account activation updated.')}>{selected.is_active?'Deactivate':'Activate'} employee</button>
      </div>
      <label className="block text-sm">Set employee password<input aria-label="Replacement employee password" type="password" autoComplete="new-password" value={resetPassword} onChange={e=>setResetPassword(e.target.value)} className="mt-1 w-full rounded-lg border bg-background p-2"/></label>
      <button className="rounded-lg border px-3 py-2 text-sm disabled:opacity-50" disabled={busy||!resetPassword} onClick={()=>transact(async()=>{
        await apiHelpers.post('/auth/users/'+selected.id+'/set_password/',{password:resetPassword})
        setResetPassword('')
      },'Employee password changed; existing refresh sessions revoked.')}>Set new password</button>
    </div>}
    {selected&&!selectedProtected&&canDelete&&<div className="rounded-xl border border-destructive/40 p-3 space-y-2">
      <button className="rounded-lg border border-destructive px-3 py-2 text-sm text-destructive disabled:opacity-50" disabled={busy} onClick={()=>{
        if (!window.confirm(`Revoke access for ${selected.email}? The account will become inactive and its audit history will remain. Continue?`)) return
        void transact(async()=>{
          await apiHelpers.delete('/auth/users/'+selected.id+'/')
          setSelected(null)
        },'Account access revoked; the account record is retained for audit.')
      }}>Revoke account access</button>
      <p className="text-xs text-muted-foreground">Revoking access deactivates the account; its history remains protected for audit.</p>
    </div>}
    {isOwner&&canDelete&&<details className="rounded-xl border border-dashed p-3 space-y-2">
      <summary className="cursor-pointer text-sm font-medium">Clean up other active accounts</summary>
      <p className="mt-2 text-xs text-muted-foreground">Keep the signed-in primary owner and one additional existing account. Other active accounts are revoked through the audited account action; inactive historical records remain available in All history.</p>
      <label className="mt-2 block text-sm">Additional account to keep
        <input aria-label="Additional account to keep" type="email" autoComplete="off" value={additionalKeepEmail} onChange={e=>setAdditionalKeepEmail(e.target.value)} placeholder="second-account@example.com" className="mt-1 w-full rounded-lg border bg-background px-3 py-2"/>
      </label>
      <button type="button" disabled={busy||!additionalKeepEmail.trim()} className="mt-3 rounded-lg border border-destructive/60 px-3 py-2 text-sm disabled:opacity-50" onClick={()=>void revokeOtherActiveAccounts()}>Review and revoke other active accounts</button>
    </details>}
    {feedback&&<p role={failed?'alert':'status'} className={'text-sm '+(failed?'text-destructive':'text-muted-foreground')}>{feedback}</p>}
  </section>
}
