// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { apiHelpers } from '@/services/api'
import { useAuthStore } from '@/stores/authStore'
import { KeyManagementPage } from './KeyManagementPage'

vi.mock('@/services/api',()=>({apiHelpers:{get:vi.fn(),post:vi.fn(),delete:vi.fn()}}))
const get=vi.mocked(apiHelpers.get)
const post=vi.mocked(apiHelpers.post)
const remove=vi.mocked(apiHelpers.delete)
const renderPage=()=>{
  const client=new QueryClient({defaultOptions:{queries:{retry:false}}})
  return render(<QueryClientProvider client={client}><KeyManagementPage/></QueryClientProvider>)
}
beforeEach(()=>{
  useAuthStore.setState({user:{role:'admin'} as never})
  get.mockImplementation(async (path:string)=>{
    if(path==='/auth/api-keys/')return {count:1,results:[{id:'key-1',name:'Access 1',key_prefix:'aegis_123',is_active:true,permissions:['project.read']}]} as never
    if(path==='/projects/')return {results:[{id:'project-1',name:'Project 1'}]} as never
    if(path==='/credentials/')return {count:1,results:[{id:'ref-1',credential_ref:'ref-1',name:'Service key',kind:'api_key',status:'active',version:1}]} as never
    throw Error('unexpected '+path)
  })
  post.mockResolvedValue({id:'key-2',key:'aegis_once_secret'} as never)
  remove.mockResolvedValue({} as never)
  vi.spyOn(window,'confirm').mockReturnValue(true)
})
afterEach(()=>{cleanup();vi.restoreAllMocks();vi.clearAllMocks()})

describe('live key-management control contracts',()=>{
  it('rejects viewing key-management controls for Viewer',()=>{
    useAuthStore.setState({user:{role:'viewer'} as never})
    renderPage()
    expect(screen.getByRole('alert').textContent).toContain('403')
    expect(get).not.toHaveBeenCalled()
  })
  it('reads paginated server keys and shows newly generated key only once',async()=>{
    renderPage()
    await screen.findByText('Access 1')
    fireEvent.change(screen.getByLabelText('New key name'),{target:{value:'New test key'}})
    fireEvent.click(screen.getByText('Create key'))
    await waitFor(()=>expect(post).toHaveBeenCalledWith('/auth/api-keys/',{name:'New test key',permissions:['project.read']}))
    expect((await screen.findByLabelText('One-time API key')).textContent).toContain('aegis_once_secret')
    fireEvent.click(screen.getByText('Dismiss secret'))
    expect(screen.queryByLabelText('One-time API key')).toBeNull()
  })
  it('rotates keys through the atomic endpoint without exposing old secrets',async()=>{
    renderPage()
    await screen.findByText('Access 1')
    fireEvent.click(screen.getByText('Rotate'))
    await waitFor(()=>expect(post).toHaveBeenCalledWith('/auth/api-keys/key-1/rotate/',{}))
    expect(window.confirm).toHaveBeenCalled()
  })
  it('lists project vault metadata from the existing scoped endpoint',async()=>{
    renderPage()
    fireEvent.click(screen.getByRole('tab',{name:'Project credential vault'}))
    await screen.findByText('Project 1')
    fireEvent.change(screen.getByLabelText('Vault project'),{target:{value:'project-1'}})
    await screen.findByText('Service key')
    expect(get).toHaveBeenCalledWith('/credentials/',{params:{project:'project-1'}})
    expect(screen.queryByText('aegis_once_secret')).toBeNull()
  })
})
