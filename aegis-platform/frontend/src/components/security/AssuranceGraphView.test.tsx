// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AssuranceGraph } from './AssuranceGraph'
import { AssuranceGraphView, readableGraphNodeLabel } from './AssuranceGraphView'

vi.mock('@/stores/languageStore', () => ({
  useLanguageStore: (select: (state: { t: (key: string) => string }) => unknown) => select({ t: (key: string) => key }),
}))
afterEach(cleanup)
const graph: AssuranceGraph = {
  nodes: [
    { id: 'validation:1', label: 'a3cf9a23-5b4e-4d3d-8245-ef97475a299e', type: 'validation', metadata: { validationId: 'validation-1' }, confidence: 86 },
    { id: 'engine:nmap', label: 'nmap', type: 'service', confidence: 92 },
    { id: 'finding:1', label: 'nmap finding', type: 'finding', confidence: 80 },
  ],
  edges: [
    { id: 'a', from: 'validation:1', to: 'engine:nmap', type: 'validated-by' },
    { id: 'b', from: 'engine:nmap', to: 'finding:1', type: 'related-to' },
  ],
}
describe('readable assurance graph UI', () => {
  it('shows every item without initial dimming or automatically opening an investigation', () => {
    const investigate = vi.fn()
    render(<AssuranceGraphView graph={graph} onInvestigate={investigate} />)
    expect(screen.getByText('Validation #1')).toBeTruthy()
    expect(screen.getByText('Finding · NMAP')).toBeTruthy()
    expect(screen.getByText('All items are shown. Select one to focus on its connections.')).toBeTruthy()
    expect(screen.getByRole('region', { name: 'Security relationship diagram' })).toBeTruthy()
    const nodes = screen.getAllByRole('button', { pressed: false })
    expect(nodes).toHaveLength(3)
    for (const node of nodes) expect(node.className).not.toContain('opacity-45')
    expect(investigate).not.toHaveBeenCalled()
  })

  it('highlights connections only after selection and leaves IDs inside technical details', () => {
    const investigate = vi.fn()
    render(<AssuranceGraphView graph={graph} onInvestigate={investigate} />)
    fireEvent.click(screen.getByRole('button', { name: /Validation #1/ }))
    expect(screen.getByText(/Selected entity:/)).toBeTruthy()
    expect(screen.getByText('Technical details')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Show all' })).toBeTruthy()
    expect(investigate).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Open investigation' }))
    expect(investigate).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Show all' }))
    expect(screen.getByText('All items are shown. Select one to focus on its connections.')).toBeTruthy()
  })

  it('keeps meaningful labels and only replaces opaque UUID or engine observation titles', () => {
    const t = (key: string) => key
    expect(readableGraphNodeLabel({ id: 'node-1', label: 'Custom customer asset', type: 'asset' }, 0, t)).toBe('Custom customer asset')
    expect(readableGraphNodeLabel(graph.nodes[0], 0, t)).toBe('Validation #1')
    expect(readableGraphNodeLabel(graph.nodes[2], 2, t)).toBe('Finding · NMAP')
  })
})
