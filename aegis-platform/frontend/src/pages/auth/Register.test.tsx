// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it } from 'vitest'
import { useLanguageStore } from '@/stores/languageStore'
import { Register } from './Register'

afterEach(() => {
  cleanup()
  useLanguageStore.setState({ language: 'ar' })
})

describe('company-only registration information', () => {
  it('keeps public sign-up unavailable in Arabic', () => {
    useLanguageStore.setState({ language: 'ar' })
    const { container } = render(<MemoryRouter><Register /></MemoryRouter>)
    expect(container.querySelector('main')?.getAttribute('dir')).toBe('rtl')
    expect(screen.getByRole('heading', { name: 'حسابات AegisScan للشركة فقط' })).toBeTruthy()
    expect(screen.queryByRole('form')).toBeNull()
    expect(screen.queryByRole('button')).toBeNull()
    expect(screen.getByRole('link', { name: 'العودة لتسجيل الدخول' }).getAttribute('href')).toBe('/login')
  })

  it('renders the English policy when English is selected without enabling sign-up', () => {
    useLanguageStore.setState({ language: 'en' })
    const { container } = render(<MemoryRouter><Register /></MemoryRouter>)
    expect(container.querySelector('main')?.getAttribute('dir')).toBe('ltr')
    expect(screen.getByRole('heading', { name: 'Company-managed AegisScan accounts only' })).toBeTruthy()
    expect(screen.getByText(/Public registration and email activation are disabled/)).toBeTruthy()
    expect(screen.queryByRole('form')).toBeNull()
    expect(screen.queryByRole('button')).toBeNull()
    expect(screen.getByRole('link', { name: 'Back to sign in' }).getAttribute('href')).toBe('/login')
  })
})
