// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiHelpers } from '@/services/api'
import { AssessmentLauncher } from './AssessmentLauncher'

const navigate=vi.fn()
vi.mock('react-router-dom', async (importOriginal) => {
  const base = await importOriginal<typeof import('react-router-dom')>()
  return {...base, useParams:()=>({id:'project-1'}),useNavigate:()=>navigate}
})
vi.mock('@/services/api',()=>({apiHelpers:{get:vi.fn(),post:vi.fn()},api:{post:vi.fn()}}))
vi.mock('sonner',()=>({toast:{success:vi.fn(),error:vi.fn(),info:vi.fn(),warning:vi.fn()}}))
const get=vi.mocked(apiHelpers.get)
const post=vi.mocked(apiHelpers.post)
const renderLauncher=()=>{
  const client=new QueryClient({defaultOptions:{queries:{retry:false}}})
  return render(<QueryClientProvider client={client}><AssessmentLauncher/></QueryClientProvider>)
}
const context=(modes: string[])=>({
  project_id:'project-1',suggested_networks:[],modes,default_depth:'standard',
  scope_mode:'single-operator-lab',automatic_scope_activation:true,
})
beforeEach(()=>{
  get.mockImplementation(async (path:string)=>{
    if(path==='/projects/project-1/')return {id:'project-1',name:'Authorized lab'} as never
    if(path==='/assessment-launcher/context')return context(['network','ip','url','file']) as never
    throw Error('Unknown API request: '+path)
  })
  post.mockImplementation(async (path:string)=>{
    if(path==='/assessment-launcher/prepare')return {
      project_id:'project-1',asset:{id:'asset-1'},depth:'standard',
      authorization:{state:'authorized'},recommended_capabilities:['network.nmap'],
    } as never
    return {scan:{id:'scan-1'}} as never
  })
})
afterEach(()=>{cleanup();vi.clearAllMocks()})

describe('single target input selects existing assessment mode and respects grants',()=>{
  it.each([
    ['internal.example/path','url'],
    ['192.168.49.10','ip'],
    ['192.168.49.33/24','network'],
  ])('submits %s to the existing backend with mode %s',async(target,mode)=>{
    renderLauncher()
    await screen.findByText(/Authorized lab /)
    const input=screen.getByPlaceholderText('192.168.49.0/24')
    fireEvent.change(input,{target:{value:target}})
    fireEvent.click(screen.getByText('Start Assessment'))
    await waitFor(()=>expect(post).toHaveBeenCalledWith('/assessment-launcher/prepare',{
      project_id:'project-1',mode,target,depth:'standard',
    }))
  })
  it('does not submit a URL under network mode when the URL grant is absent', async()=>{
    get.mockImplementation(async(path:string)=>{
      if(path==='/projects/project-1/')return {id:'project-1',name:'Authorized lab'} as never
      if(path==='/assessment-launcher/context')return context(['network']) as never
      throw Error('Unexpected '+path)
    })
    renderLauncher()
    await screen.findByText(/Authorized lab /)
    fireEvent.change(screen.getByPlaceholderText('192.168.49.0/24'),{target:{value:'https://internal.example'}})
    fireEvent.click(screen.getByText('Start Assessment'))
    const {toast}=await import('sonner')
    await waitFor(()=>expect(toast.error).toHaveBeenCalledWith('This target type is not enabled for your account.'))
    expect(post).not.toHaveBeenCalled()
  })
})
