// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { NAV_GROUPS } from './navigation'

vi.mock('@/services/api',()=>({apiHelpers:{health:vi.fn().mockResolvedValue({status:'healthy'})}}))
afterEach(()=>cleanup())

const mount=(path='/dashboard')=>{
 const client=new QueryClient({defaultOptions:{queries:{retry:false}}})
 const groups=NAV_GROUPS.map(group=>({...group,items:group.items.map(item=>({...item}))}))
 return render(
  <QueryClientProvider client={client}>
   <MemoryRouter initialEntries={[path]}>
    <Sidebar open onOpenChange={()=>{}} mobileOpen={false} onMobileOpenChange={()=>{}} groups={groups} flatNavigation={groups.flatMap(group=>group.items)} currentPath={path}/>
   </MemoryRouter>
  </QueryClientProvider>
 )
}

describe('focused sidebar navigation',()=>{
 it('shows common workflow routes and keeps advanced links accessible without duplicating them',()=>{
  mount()
  expect(screen.getByRole('link',{name:/Dashboard|لوحة التحكم/})).toBeTruthy()
  expect(screen.getByRole('link',{name:/New Assessment|تقييم جديد/})).toBeTruthy()
  expect(screen.queryByRole('link',{name:/Web Labs|مختبرات الويب/})).toBeNull()
  const more=screen.getByRole('button',{name:/More tools|أدوات إضافية/})
  expect(more.getAttribute('aria-expanded')).toBe('false')
  fireEvent.click(more)
  expect(screen.getByRole('link',{name:/Web Labs|مختبرات الويب/})).toBeTruthy()
  expect(screen.getAllByRole('link',{name:/Dashboard|لوحة التحكم/}).length).toBe(1)
  expect(more.getAttribute('aria-expanded')).toBe('true')
 })
 it('reveals the advanced group automatically for direct links',()=>{
  mount('/evidence')
  expect(screen.getByRole('link',{name:/Evidence|الأدلة/})).toBeTruthy()
  expect(screen.getByRole('button',{name:/More tools|أدوات إضافية/}).getAttribute('aria-expanded')).toBe('true')
 })
})
