// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { DashboardBarChart, DashboardDonutChart, DashboardTrendChart } from './DashboardChart'


const points = [
  { label: 'Critical', value: 4 },
  { label: 'High', value: 8 },
  { label: 'Medium', value: 2 },
]

afterEach(cleanup)


describe('dashboard charts', () => {
  it('renders the trend from real point values with an accessible summary', () => {
    const { container } = render(<DashboardTrendChart points={[{ label: 'Sep 1', value: 70 }, { label: 'Sep 2', value: 84 }]} />)

    expect(screen.getByRole('img').getAttribute('aria-label')).toContain('Sep 2 84')
    expect(container.querySelectorAll('circle')).toHaveLength(2)
  })

  it('renders a risk total and every donut legend value', () => {
    render(<DashboardDonutChart points={points} />)

    expect(screen.getByRole('img').getAttribute('aria-label')).toContain('Critical 4')
    expect(screen.getByText('14')).toBeTruthy()
    expect(screen.getByText('High')).toBeTruthy()
  })

  it('renders one severity bar per supplied value', () => {
    const { container } = render(<DashboardBarChart points={points} />)

    expect(screen.getByRole('img').getAttribute('aria-label')).toContain('Medium 2')
    expect(container.querySelectorAll('[aria-hidden="true"]')).toHaveLength(3)
  })
})
