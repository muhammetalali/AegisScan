import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiHelpers } from '@/services/api'
import { useAuthStore } from '@/stores/authStore'
import { canManageKeys } from '@/services/routePolicy'

type ApiKey = { id:string; name:string; key_prefix:string; is_active:boolean; permissions:string[]; created_at:string; last_used_at?:string|null }
type VaultCredential = { id:string; credential_ref:string; name:string; kind:string; status:string; version:number; project_id:string }
type Project = { id:string; name:string }
type ListResult<T> = T[] | { items?:T[]; results?:T[]; count?:number }
type ProjectResult = ListResult<Project>
const rowsFrom = <T,>(result?: ListResult<T>):T[] => Array.isArray(result) ? result : result?.results ?? result?.items ?? []
const projectsFrom = (result?: ProjectResult):Project[] => rowsFrom(result)
const errorMessage = (e:unknown):string => {
  const error=e as {response?:{status?:number;data?:{detail?:string|{message?:string}}};message?:string}
  if (error?.response?.status===403) return '403 — Your account is not authorized to manage these keys.'
  const detail=error?.response?.data?.detail
  return (typeof detail==='string' ? detail : detail?.message) || error?.message || 'The operation failed.'
}
const button='rounded-lg border px-3 py-2 text-sm hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50'
const fields='w-full rounded-lg border bg-background px-3 py-2 text-sm'

export const KeyManagementPage = () => {
  const role=useAuthStore(s=>s.user?.role)
  const qc=useQueryClient()
  const [mode,setMode]=useState<'api'|'vault'>('api')
  const [name,setName]=useState('')
  const [secret,setSecret]=useState('')
  const [kind,setKind]=useState('api_key')
  const [project,setProject]=useState('')
  const [rotating,setRotating]=useState('')
  const [replacement,setReplacement]=useState('')
  const [permission,setPermission]=useState('project.read')
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const [revealed,setRevealed]=useState('')
  const apiKeys=useQuery<ListResult<ApiKey>>({queryKey:['owned-api-keys'],queryFn:()=>apiHelpers.get<ListResult<ApiKey>>('/auth/api-keys/'),enabled:canManageKeys(role)&&mode==='api',retry:false})
  const projects=useQuery<ProjectResult>({queryKey:['key-vault-projects'],queryFn:()=>apiHelpers.get<ProjectResult>('/projects/'),enabled:canManageKeys(role)&&mode==='vault',retry:false})
  const vault=useQuery<ListResult<VaultCredential>>({queryKey:['key-vault',project],queryFn:()=>apiHelpers.get<ListResult<VaultCredential>>('/credentials/',{params:{project}}),enabled:canManageKeys(role)&&mode==='vault'&&!!project,retry:false})
  const refresh=async()=>{await qc.invalidateQueries({queryKey:['owned-api-keys']});await qc.invalidateQueries({queryKey:['key-vault']})}
  const transact=async (call:()=>Promise<unknown>,done:string)=>{
    setBusy(true);setError('');setNotice('');setRevealed('')
    try{
      const result=await call() as {key?:string}
      // Access-key material can only be shown in local component state at creation/rotation.
      if(typeof result?.key==='string')setRevealed(result.key)
      setNotice(done);setSecret('');setName('');setReplacement('');setRotating('');await refresh()
    }catch(e){setError(errorMessage(e))}finally{setBusy(false)}
  }
  if(!canManageKeys(role))return <main role="alert" className="rounded-xl border p-8"><h1 className="text-xl font-bold">403 · Access denied</h1><p>Your role cannot manage credentials.</p></main>
  return <main className="mx-auto max-w-5xl space-y-5 pb-10">
    <header><h1 className="text-2xl font-bold">Access keys & project vault</h1>
      <p className="mt-2 text-sm text-muted-foreground">Access keys belong to your user. Scanner credentials are encrypted and scoped to projects. These are separate existing backend stores; no secrets are returned in inventory responses.</p>
    </header>
    <div className="flex flex-wrap gap-2" role="tablist" aria-label="Key management">
      <button role="tab" aria-selected={mode==='api'} className={button} onClick={()=>{setMode('api');setError('');setRevealed('');setSecret('')}}>API access keys</button>
      <button role="tab" aria-selected={mode==='vault'} className={button} onClick={()=>{setMode('vault');setError('');setRevealed('');setSecret('')}}>Project credential vault</button>
    </div>
    {error&&<div role="alert" className="rounded-xl border border-destructive p-4 text-sm text-destructive">{error}</div>}
    {notice&&<div role="status" className="rounded-xl border p-4 text-sm">{notice}</div>}
    {revealed&&<section aria-label="One-time API key" className="rounded-xl border border-primary p-4 space-y-2">
      <h2 className="font-semibold">Copy this new API key now — shown only once</h2>
      <p className="text-xs text-muted-foreground">It is not saved in your browser's persistent storage or returned in future list requests.</p>
      <code className="block break-all select-all rounded-lg bg-muted p-3">{revealed}</code>
      <button className={button} onClick={()=>setRevealed('')}>Dismiss secret</button>
    </section>}
    {mode==='api'&&<>
      <form className="rounded-xl border bg-card p-5 space-y-3" onSubmit={event=>{event.preventDefault();if(!name.trim())return;void transact(()=>apiHelpers.post('/auth/api-keys/',{name:name.trim(),permissions:[permission]}),'Access key created')}}>
        <h2 className="font-semibold">Create access key</h2>
        <p className="text-xs text-muted-foreground">Verified X-API-Key consumer: read-only GET /api/v1/projects/ using project.read, limited by your project membership. Other scopes are reserved for separately reviewed API consumers; they do not currently enable access to scan or report APIs.</p>
        <label className="block text-sm">Key name<input aria-label="New key name" className={fields} maxLength={100} required value={name} onChange={e=>setName(e.target.value)}/></label>
        <label className="block text-sm">Permission<select aria-label="New key permission" className={fields} value={permission} onChange={e=>setPermission(e.target.value)}>
          {['project.read','scan.read','report.read','asset.read','scan.create'].map(v=><option key={v} value={v}>{v}</option>)}
        </select></label>
        <button className={button} type="submit" disabled={busy||!name.trim()}>Create key</button>
      </form>
      <section className="rounded-xl border bg-card p-5 space-y-3"><h2 className="font-semibold">Your API keys</h2>
        {apiKeys.isLoading&&<p role="status">Loading keys…</p>}
        {apiKeys.isError&&<p role="alert" className="text-destructive">Unable to load API keys: {errorMessage(apiKeys.error)}</p>}
        {apiKeys.isSuccess&&rowsFrom(apiKeys.data).length===0&&<p>No access keys found.</p>}
        {rowsFrom(apiKeys.data).map(k=><div key={k.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3">
          <div><div className="font-medium">{k.name}</div><div className="text-xs text-muted-foreground">{k.key_prefix}… · {k.is_active?'Active':'Revoked'} · {k.permissions.join(', ') || 'No granted permissions'}</div></div>
          {k.is_active&&<div className="flex gap-2">
            <button type="button" className={button} disabled={busy} onClick={()=>{if(window.confirm('Rotate this key? The current key will be revoked immediately.'))void transact(()=>apiHelpers.post('/auth/api-keys/'+encodeURIComponent(k.id)+'/rotate/',{}),'Key rotated; prior key revoked')}}>Rotate</button>
            <button type="button" className={button} disabled={busy} onClick={()=>{if(window.confirm('Revoke this key? Existing clients will lose access.'))void transact(()=>apiHelpers.delete('/auth/api-keys/'+encodeURIComponent(k.id)+'/'),'Access key revoked')}}>Revoke</button>
          </div>}
        </div>)}
      </section>
    </>}
    {mode==='vault'&&<>
      <section className="rounded-xl border bg-card p-5 space-y-3"><h2 className="font-semibold">Project-scoped encrypted credentials</h2>
        <p className="text-sm text-muted-foreground">The server enforces vault privileges and project ownership. This interface never reads or displays stored secret material.</p>
        {projects.isError&&<p role="alert">Unable to load your projects: {errorMessage(projects.error)}</p>}
        <label className="block text-sm">Project<select aria-label="Vault project" className={fields} value={project} onChange={e=>{setProject(e.target.value);setError('');setSecret('')}}>
          <option value="">Choose project</option>{projectsFrom(projects.data).map(p=><option value={p.id} key={p.id}>{p.name}</option>)}
        </select></label>
        {project&&<form className="space-y-3" onSubmit={event=>{event.preventDefault();if(!name.trim()||!secret)return;void transact(()=>apiHelpers.post('/credentials/',{project,name:name.trim(),kind,secret,scope:{}}),'Encrypted credential saved under this project')}}>
          <label className="block text-sm">Credential name<input aria-label="Credential name" className={fields} maxLength={200} value={name} onChange={e=>setName(e.target.value)} required/></label>
          <label className="block text-sm">Credential type<select aria-label="Credential kind" className={fields} value={kind} onChange={e=>setKind(e.target.value)}>
            {['api_key','token','password','ssh_private_key','cloud_access_key','kubeconfig','generic'].map(v=><option key={v} value={v}>{v}</option>)}
          </select></label>
          <label className="block text-sm">Secret material<input aria-label="New credential secret" type="password" className={fields} value={secret} autoComplete="off" onChange={e=>setSecret(e.target.value)} required/></label>
          <button className={button} type="submit" disabled={busy||!name.trim()||!secret}>Store encrypted credential</button>
        </form>}
      </section>
      {project&&<section className="rounded-xl border bg-card p-5 space-y-3"><h2 className="font-semibold">Vault references</h2>
        {vault.isLoading&&<p role="status">Loading credential references…</p>}
        {vault.isError&&<p role="alert" className="text-destructive">Unable to load credential references: {errorMessage(vault.error)}</p>}
        {vault.isSuccess&&rowsFrom(vault.data).length===0&&<p>No stored credentials for this project.</p>}
        {rowsFrom(vault.data).map(k=><div className="flex flex-wrap justify-between gap-3 rounded-lg border p-3" key={k.id}>
          <div><div className="font-medium">{k.name}</div><div className="break-all font-mono text-xs">{k.credential_ref}</div><div className="text-xs text-muted-foreground">{k.kind} · v{k.version} · {k.status}</div></div>
          {k.status==='active'&&<div className="flex gap-2">
            <button className={button} type="button" disabled={busy} onClick={()=>{setRotating(k.id);setReplacement('');setError('')}}>Rotate</button>
            <button className={button} type="button" disabled={busy} onClick={()=>{if(window.confirm('Revoke this credential reference? Scanner use will stop.'))void transact(()=>apiHelpers.post('/credentials/'+encodeURIComponent(k.id)+'/revoke/',{reason:'Revoked by authorized operator'}),'Credential revoked')}}>Revoke</button>
          </div>}
          {rotating===k.id&&<form className="w-full space-y-2" onSubmit={event=>{event.preventDefault();if(replacement)void transact(()=>apiHelpers.post('/credentials/'+encodeURIComponent(k.id)+'/rotate/',{secret:replacement}),'Credential rotated securely')}}>
            <label className="block text-sm">Replacement secret<input className={fields} type="password" aria-label="Replacement credential secret" autoComplete="off" required value={replacement} onChange={event=>setReplacement(event.target.value)}/></label>
            <div className="flex gap-2"><button type="submit" className={button} disabled={busy||!replacement}>Confirm rotation</button><button type="button" className={button} onClick={()=>{setRotating('');setReplacement('')}}>Cancel</button></div>
          </form>}
        </div>)}
      </section>}
    </>}
  </main>
}
