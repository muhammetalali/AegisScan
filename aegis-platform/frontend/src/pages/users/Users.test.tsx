// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useAuthStore } from '@/stores/authStore'
import { apiHelpers } from '@/services/api'
import { Users } from './Users'

vi.mock('@/services/api', () => ({apiHelpers:{get:vi.fn()}}))
vi.mock('./CompanyAccountControls', () => ({CompanyAccountControls:()=>null}))
vi.mock('./KeyManagementPage', () => ({KeyManagementPage:()=> <div data-testid="key-manager">Key controls</div>}))
const get = vi.mocked(apiHelpers.get)
const renderPage = () => {
  const cache = new QueryClient({defaultOptions:{queries:{retry:false}}})
  return render(<QueryClientProvider client={cache}><Users/></QueryClientProvider>)
}
beforeEach(() => {
  get.mockResolvedValue({items:[]} as never)
})
afterEach(() => {cleanup();vi.clearAllMocks()})

describe('Users embedded key-management access is the same as /keys', () => {
  it('hides the tab for an admin without api_key.manage', () => {
    useAuthStore.setState({user:{role:'admin',permissions:['user.read'],enabled_pages:['/users']} as never})
    renderPage()
    expect(screen.queryByRole('button',{name:'API Keys'})).toBeNull()
    expect(screen.queryByTestId('key-manager')).toBeNull()
  })
  it('hides the tab if the owner did not assign /keys', () => {
    useAuthStore.setState({user:{role:'admin',permissions:['user.read','api_key.manage'],enabled_pages:['/users']} as never})
    renderPage()
    expect(screen.queryByRole('button',{name:'API Keys'})).toBeNull()
  })
  it('shows the same key-management page when all grants permit it', () => {
    useAuthStore.setState({user:{role:'admin',permissions:['user.read','api_key.manage'],enabled_pages:['/users','/keys']} as never})
    renderPage()
    fireEvent.click(screen.getByRole('button',{name:'API Keys'}))
    expect(screen.getByTestId('key-manager')).toBeTruthy()
  })
  it('preserves unrestricted company-owner access without manual grants', () => {
    useAuthStore.setState({user:{role:'admin',permissions:[],enabled_pages:[],is_company_owner:true} as never})
    renderPage()
    fireEvent.click(screen.getByRole('button',{name:'API Keys'}))
    expect(screen.getByTestId('key-manager')).toBeTruthy()
  })
})
