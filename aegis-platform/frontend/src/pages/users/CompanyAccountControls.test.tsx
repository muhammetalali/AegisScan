// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiHelpers } from '@/services/api'
import { useAuthStore } from '@/stores/authStore'
import { CompanyAccountControls } from './CompanyAccountControls'

vi.mock('@/services/api',()=>({apiHelpers:{get:vi.fn(),post:vi.fn(),patch:vi.fn(),delete:vi.fn()}}))
const get=vi.mocked(apiHelpers.get)
const post=vi.mocked(apiHelpers.post)
const patch=vi.mocked(apiHelpers.patch)
const remove=vi.mocked(apiHelpers.delete)
const employee={id:'staff-1',email:'staff@company.invalid',first_name:'Staff',last_name:'One',role:'admin',is_active:false,granted_permissions:['project.read'],enabled_scan_types:['url'],enabled_pages:['/projects']}
const renderPage=()=>{
  const client = new QueryClient({defaultOptions:{queries:{retry:false}}})
  return render(<QueryClientProvider client={client}><CompanyAccountControls/></QueryClientProvider>)
}
beforeEach(()=>{
  useAuthStore.setState({user:{role:'super_admin',is_company_owner:true} as never})
  get.mockImplementation(async (path:string)=>{
    if(path==='/auth/users/access_options/')return {roles:{viewer:['project.read'],admin:['project.read','scan.create','system.monitor']},scan_types:['url','file','ip']} as never
    if(path==='/auth/users/')return {count:1,next:null,results:[employee]} as never
    throw Error('unknown '+path)
  })
  post.mockResolvedValue({id:'staff-2',email:'new@company.invalid',role:'admin',is_active:false,granted_permissions:['project.read'],enabled_scan_types:['url'],enabled_pages:['/projects']} as never)
  patch.mockResolvedValue({id:'staff-1'} as never)
  remove.mockResolvedValue(undefined as never)
})
afterEach(()=>{cleanup();vi.clearAllMocks();vi.unstubAllGlobals()})

describe('owner-only company account UI',()=>{
  it('keeps account history available without cluttering the active view',async()=>{
    renderPage()
    await waitFor(()=>expect(get).toHaveBeenCalledWith('/auth/users/',{params:{page:1,status:'active',q:''}}))
    fireEvent.click(screen.getByRole('button',{name:'All history'}))
    await waitFor(()=>expect(get).toHaveBeenCalledWith('/auth/users/',{params:{page:1,status:'all',q:''}}))
    fireEvent.change(screen.getByRole('searchbox',{name:'Search account email'}),{target:{value:'staff@company.invalid'}})
    fireEvent.click(screen.getByRole('button',{name:'Find account'}))
    await waitFor(()=>expect(get).toHaveBeenCalledWith('/auth/users/',{params:{page:1,status:'all',q:'staff@company.invalid'}}))
    expect(screen.getByText(/Inactive records remain available for audit/)).toBeTruthy()
  })
  it('provisions a disabled employee with owner-selected role, password and scan scopes',async()=>{
    renderPage()
    await screen.findByText(/staff@company.invalid/)
    fireEvent.change(screen.getByLabelText('Employee login'),{target:{value:'new@company.invalid'}})
    fireEvent.change(screen.getByLabelText('Initial employee password'),{target:{value:'Strong-New-Password!2026'}})
    fireEvent.change(screen.getByLabelText('Employee first name'),{target:{value:'New'}})
    fireEvent.change(screen.getByLabelText('Employee last name'),{target:{value:'Staff'}})
    fireEvent.change(screen.getByLabelText('Employee role'),{target:{value:'admin'}})
    fireEvent.click(screen.getByLabelText('project.read'))
    fireEvent.click(screen.getByLabelText('url'))
    fireEvent.click(screen.getByText('Create inactive employee'))
    await waitFor(()=>expect(post).toHaveBeenCalledWith('/auth/users/',{
      email:'new@company.invalid',first_name:'New',last_name:'Staff',
      password:'Strong-New-Password!2026',password_confirm:'Strong-New-Password!2026',
      role:'admin',granted_permissions:['project.read'],enabled_scan_types:['url'],enabled_pages:[],
    }))
    expect((await screen.findByRole('status')).textContent).toContain('created inactive')
    expect(await screen.findByText('Selected: new@company.invalid')).toBeTruthy()
    expect(screen.getByText('Activate employee')).toBeTruthy()
    // The selected employee must retain the scopes returned by the backend:
    // clearing the creation form must not clear future Save permissions state.
    expect((screen.getByLabelText('project.read') as HTMLInputElement).checked).toBe(true)
    expect((screen.getByLabelText('url') as HTMLInputElement).checked).toBe(true)
    expect((screen.getByLabelText('Initial employee password') as HTMLInputElement).value).toBe('')
  })
  it('activates an existing employee and updates only existing canonical routes',async()=>{
    renderPage()
    fireEvent.click(await screen.findByText(/staff@company.invalid/))
    fireEvent.click(screen.getByText('Activate employee'))
    await waitFor(()=>expect(post).toHaveBeenCalledWith('/auth/users/staff-1/activate/',{}))
    fireEvent.click(screen.getByText('Save permissions'))
    await waitFor(()=>expect(patch).toHaveBeenCalledWith('/auth/users/staff-1/',{
      role:'admin',granted_permissions:['project.read'],enabled_scan_types:['url'],enabled_pages:['/projects'],
    }))
    fireEvent.change(screen.getByLabelText('Replacement employee password'),{target:{value:'New-Secret-Password!2026'}})
    fireEvent.click(screen.getByText('Set new password'))
    await waitFor(()=>expect(post).toHaveBeenCalledWith('/auth/users/staff-1/set_password/',{password:'New-Secret-Password!2026'}))
  })
  it('does not manufacture a successful response when server denies account access',async()=>{
    post.mockRejectedValueOnce(Object.assign(new Error('forbidden'),{response:{status:403,data:{detail:'Only the owner can manage accounts.'}}}))
    renderPage()
    await screen.findByText(/staff@company.invalid/)
    fireEvent.change(screen.getByLabelText('Employee login'),{target:{value:'new@company.invalid'}})
    fireEvent.change(screen.getByLabelText('Initial employee password'),{target:{value:'Strong-New-Password!2026'}})
    fireEvent.change(screen.getByLabelText('Employee first name'),{target:{value:'New'}})
    fireEvent.change(screen.getByLabelText('Employee last name'),{target:{value:'Staff'}})
    fireEvent.click(screen.getByText('Create inactive employee'))
    expect((await screen.findByRole('alert')).textContent).toContain('Only the owner')
  })
  it('does not send DELETE when the owner cancels the explicit confirmation',async()=>{
    vi.stubGlobal('confirm',vi.fn().mockReturnValue(false))
    renderPage()
    fireEvent.click(await screen.findByText(/staff@company.invalid/))
    fireEvent.click(screen.getByRole('button',{name:'Revoke account access'}))
    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining('staff@company.invalid'))
    expect(remove).not.toHaveBeenCalled()
    expect(screen.getByText('Selected: staff@company.invalid')).toBeTruthy()
  })
  it('uses the canonical DELETE route and reports retention honestly',async()=>{
    vi.stubGlobal('confirm',vi.fn().mockReturnValue(true))
    renderPage()
    fireEvent.click(await screen.findByText(/staff@company.invalid/))
    fireEvent.click(screen.getByRole('button',{name:'Revoke account access'}))
    await waitFor(()=>expect(remove).toHaveBeenCalledWith('/auth/users/staff-1/'))
    await waitFor(()=>expect(screen.getByRole('status').textContent).toContain('record is retained'))
    expect(screen.queryByText('Selected: staff@company.invalid')).toBeNull()
  })
  it('hides delete without user.delete and protects the primary owner',async()=>{
    useAuthStore.setState({user:{role:'admin',is_company_owner:false,permissions:['user.read','user.update']} as never})
    renderPage()
    fireEvent.click(await screen.findByText(/staff@company.invalid/))
    expect(screen.queryByRole('button',{name:'Revoke account access'})).toBeNull()
    cleanup()
    useAuthStore.setState({user:{role:'super_admin',is_company_owner:true} as never})
    get.mockImplementation(async (path:string)=>{
      if(path==='/auth/users/access_options/')return {roles:{viewer:[]},scan_types:[]} as never
      if(path==='/auth/users/')return {count:1,next:null,results:[{...employee,id:'owner-1',email:'owner@company.invalid',is_company_owner:true}]} as never
      throw Error('unknown '+path)
    })
    renderPage()
    fireEvent.click(await screen.findByText(/owner@company.invalid/))
    expect(screen.getByText('This privileged account is protected from delegated changes.')).toBeTruthy()
    expect(screen.queryByRole('button',{name:'Revoke account access'})).toBeNull()
    expect(remove).not.toHaveBeenCalled()
  })
  it('retains selection and shows an error when the server denies deletion',async()=>{
    vi.stubGlobal('confirm',vi.fn().mockReturnValue(true))
    remove.mockRejectedValueOnce(Object.assign(new Error('forbidden'),{response:{status:403,data:{detail:'Account deletion forbidden.'}}}))
    renderPage()
    fireEvent.click(await screen.findByText(/staff@company.invalid/))
    fireEvent.click(screen.getByRole('button',{name:'Revoke account access'}))
    expect((await screen.findByRole('alert')).textContent).toContain('Account deletion forbidden.')
    expect(screen.getByText('Selected: staff@company.invalid')).toBeTruthy()
  })
}
  it('revokes only other active users after verifying both identities and one confirmation',async()=>{
    useAuthStore.setState({user:{role:'super_admin',is_company_owner:true,email:'owner@company.invalid'} as never})
    get.mockImplementation(async (path:string, options?:unknown)=>{
      if(path==='/auth/users/access_options/')return {roles:{viewer:[]},scan_types:[]} as never
      if(path!=='/auth/users/')throw Error('unexpected route '+path)
      const params=(options as {params?:{q?:string;status?:string}})?.params
      if(params?.q==='keep@company.invalid')return {count:1,next:null,results:[{...employee,id:'retained',email:'keep@company.invalid',is_active:false}]} as never
      if(params?.status==='active')return {count:3,next:null,results:[
        {...employee,id:'owner',email:'owner@company.invalid',is_company_owner:true,is_active:true},
        {...employee,id:'one',email:'one@company.invalid',is_active:true},
        {...employee,id:'two',email:'two@company.invalid',is_active:true},
      ]} as never
      throw Error('unexpected account inventory')
    })
    const confirm=vi.fn().mockReturnValue(true)
    vi.stubGlobal('confirm',confirm)
    renderPage()
    fireEvent.click(screen.getByText('Clean up other active accounts'))
    fireEvent.change(screen.getByLabelText('Additional account to keep'),{target:{value:'keep@company.invalid'}})
    fireEvent.click(screen.getByRole('button',{name:'Review and revoke other active accounts'}))
    await waitFor(()=>expect(remove).toHaveBeenCalledTimes(2))
    expect(remove).toHaveBeenNthCalledWith(1,'/auth/users/one/')
    expect(remove).toHaveBeenNthCalledWith(2,'/auth/users/two/')
    expect(confirm).toHaveBeenCalledTimes(1)
    expect(confirm.mock.calls[0][0]).toContain('2 other active accounts')
    expect(confirm.mock.calls[0][0]).toContain('keep@company.invalid')
    expect((await screen.findByRole('status')).textContent).toContain('Revoked 2 active accounts')
  })

  it('refuses account cleanup when retained account is not uniquely verified',async()=>{
    useAuthStore.setState({user:{role:'super_admin',is_company_owner:true,email:'owner@company.invalid'} as never})
    get.mockImplementation(async (path:string)=>{
      if(path==='/auth/users/access_options/')return {roles:{viewer:[]},scan_types:[]} as never
      if(path==='/auth/users/')return {count:0,next:null,results:[]} as never
      throw Error('unexpected route')
    })
    const confirm=vi.fn()
    vi.stubGlobal('confirm',confirm)
    renderPage()
    fireEvent.click(screen.getByText('Clean up other active accounts'))
    fireEvent.change(screen.getByLabelText('Additional account to keep'),{target:{value:'missing@company.invalid'}})
    fireEvent.click(screen.getByRole('button',{name:'Review and revoke other active accounts'}))
    expect((await screen.findByRole('alert')).textContent).toContain('No changes made')
    expect(confirm).not.toHaveBeenCalled()
    expect(remove).not.toHaveBeenCalled()
  })

  it('stops bulk cleanup at the first endpoint failure with partial count',async()=>{
    useAuthStore.setState({user:{role:'super_admin',is_company_owner:true,email:'owner@company.invalid'} as never})
    get.mockImplementation(async (path:string, options?:unknown)=>{
      if(path==='/auth/users/access_options/')return {roles:{viewer:[]},scan_types:[]} as never
      if(path!=='/auth/users/')throw Error('unexpected route')
      const p=(options as {params?:{q?:string}})?.params
      if(p?.q==='keep@company.invalid')return {count:1,next:null,results:[{...employee,email:'keep@company.invalid'}]} as never
      return {count:3,next:null,results:[
        {...employee,id:'owner',email:'owner@company.invalid',is_company_owner:true,is_active:true},
        {...employee,id:'first',email:'first@company.invalid',is_active:true},
        {...employee,id:'failed',email:'failed@company.invalid',is_active:true},
      ]} as never
    })
    vi.stubGlobal('confirm',vi.fn().mockReturnValue(true))
    remove.mockResolvedValueOnce(undefined as never).mockRejectedValueOnce(new Error('Connection lost'))
    renderPage()
    fireEvent.click(screen.getByText('Clean up other active accounts'))
    fireEvent.change(screen.getByLabelText('Additional account to keep'),{target:{value:'keep@company.invalid'}})
    fireEvent.click(screen.getByRole('button',{name:'Review and revoke other active accounts'}))
    expect((await screen.findByRole('alert')).textContent).toContain('stopped after 1 revocations')
    expect(remove).toHaveBeenCalledTimes(2)
  })

  it('does not expose bulk cleanup to delegated administrators',async()=>{
    useAuthStore.setState({user:{role:'super_admin',is_company_owner:false,permissions:['user.delete'],email:'delegate@company.invalid'} as never})
    renderPage()
    await screen.findByText(/staff@company.invalid/)
    expect(screen.queryByText('Clean up other active accounts')).toBeNull()
  })
})
