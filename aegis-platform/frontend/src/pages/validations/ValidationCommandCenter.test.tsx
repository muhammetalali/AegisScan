// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ValidationCommandCenter } from './ValidationCommandCenter'
import { apiHelpers } from '@/services/api'
import { CATALOGS, useLanguageStore } from '@/stores/languageStore'

vi.mock('@/services/api', () => ({
  apiHelpers: {
    get: vi.fn(),
  },
}))

const mockedGet = vi.mocked(apiHelpers.get)

beforeEach(() => {
  useLanguageStore.setState({ language: 'en', translations: CATALOGS.en })
})

const renderPage = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/validations/validation-1']}>
        <Routes>
          <Route path="/validations/:id" element={<ValidationCommandCenter />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('ValidationCommandCenter canonical evidence contract', () => {
  it('renders the API evidence count and ignores the legacy evidences fallback', async () => {
    mockedGet.mockImplementation(async (path: string) => {
      if (path === '/validations/validation-1/results') {
        return {
          id: 'validation-1',
          status: 'completed',
          target_value: 'aegis-scan-target',
          overview: {
            findings_count: 1,
            risk_score: 20,
            assets_count: 1,
            evidence_count: 3,
            engines_executed: 1,
            severity_counts: { informational: 1 },
          },
          evidences: [{ id: 'legacy-1' }, { id: 'legacy-2' }, { id: 'legacy-3' }, { id: 'legacy-4' }],
          findings: [],
        }
      }

      if (path === '/validations/validation-1/findings') {
        return { items: [] }
      }

      throw new Error(`Unexpected API request: ${path}`)
    })

    renderPage()

    await waitFor(() => expect(screen.getByText('Evidence')).toBeTruthy())

    const evidenceLabel = screen.getByText('Evidence')
    const evidenceCard = evidenceLabel.closest('div.rounded-2xl')
    expect(evidenceCard).not.toBeNull()
    expect(evidenceCard?.textContent).toContain('3')
    expect(evidenceCard?.textContent).not.toContain('4')
  })

  it('shows the real API error state instead of synthetic result data', async () => {
    mockedGet.mockRejectedValue(new Error('validation API unavailable'))

    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Results are unavailable')).toBeTruthy()
    })

    expect(screen.getByText('The validation result could not be loaded from the API. No demo or fallback data is shown.')).toBeTruthy()
    expect(screen.queryByText('Simulation / Demo Data')).toBeNull()
  })
})

describe('ValidationCommandCenter interaction contract', () => {
  it('queries findings with the selected severity filter', async () => {
    mockedGet.mockResolvedValue({
      id: 'validation-1',
      status: 'completed',
      overview: {
        findings_count: 0,
        risk_score: 0,
        assets_count: 0,
        evidence_count: 0,
        engines_executed: 0,
        severity_counts: {},
      },
      findings: [],
    })

    renderPage()

    await waitFor(() => expect(mockedGet).toHaveBeenCalled())
    expect(mockedGet).toHaveBeenCalledWith('/validations/validation-1/results')
    expect(mockedGet).toHaveBeenCalledWith('/validations/validation-1/findings')

    fireEvent.click(screen.getByRole('button', { name: /^high$/i }))

    await waitFor(() => {
      expect(mockedGet).toHaveBeenCalledWith('/validations/validation-1/findings?severity=high')
    })
  })
})
