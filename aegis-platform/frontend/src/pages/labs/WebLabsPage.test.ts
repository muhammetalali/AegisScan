import { describe, expect, it } from 'vitest'
import { unwrapWebLabProjects } from './WebLabsPage'

describe('unwrapWebLabProjects', () => {
  const project = { id: '11111111-1111-1111-1111-111111111111', name: 'UAT project' }

  it('preserves the legacy array response shape', () => {
    expect(unwrapWebLabProjects([project])).toEqual([project])
  })

  it('accepts DRF paginated results used by /projects/', () => {
    expect(unwrapWebLabProjects({ results: [project] })).toEqual([project])
  })

  it('accepts item envelopes and fails closed to an empty list', () => {
    expect(unwrapWebLabProjects({ items: [project] })).toEqual([project])
    expect(unwrapWebLabProjects(undefined)).toEqual([])
  })
})
