// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiHelpers } from '@/services/api'
import { CompanyAccountControls } from './CompanyAccountControls'

vi.mock('@/services/api',()=>({apiHelpers:{get:vi.fn(),post:vi.fn(),patch:vi.fn()}}))
const get=vi.mocked(apiHelpers.get)
const post=vi.mocked(apiHelpers.post)
const patch=vi.mocked(apiHelpers.patch)
const employee={id:'staff-1',email:'staff@company.invalid',first_name:'Staff',last_name:'One',role:'admin',is_active:false,granted_permissions:['project.read'],enabled_scan_types:['url'],enabled_pages:['/projects']}
const renderPage=()=>{
  const client = new QueryClient({defaultOptions:{queries:{retry:false}}})
  return render(<QueryClientProvider client={client}><CompanyAccountControls/></QueryClientProvider>)
}
beforeEach(()=>{
  get.mockImplementation(async (path:string)=>{
    if(path==='/auth/users/access_options/')return {roles:{viewer:['project.read'],admin:['project.read','scan.create','system.monitor']},scan_types:['url','file','ip']} as never
    if(path==='/auth/users/')return {count:1,next:null,results:[employee]} as never
    throw Error('unknown '+path)
  })
  post.mockResolvedValue({id:'staff-2'} as never)
  patch.mockResolvedValue({id:'staff-1'} as never)
})
afterEach(()=>{cleanup();vi.clearAllMocks()})

describe('owner-only company account UI',()=>{
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
})
