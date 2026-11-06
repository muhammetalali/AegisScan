import { describe, expect, it } from 'vitest'
import { groupAcademyCategories, unwrapWebLabProjects } from './WebLabsPage'
import { readFileSync } from 'node:fs'

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

describe('Academy topic groups over the canonical catalog', () => {
  const catalog = JSON.parse(
    readFileSync(new URL('../../../../backend/resources/web-labs/portswigger-all-labs.v1.json', import.meta.url), 'utf-8'),
  ) as { category_count: number; lab_count: number; categories: { slug: string; count: number }[] }

  it('groups all 31 official categories without creating or dropping any labs', () => {
    const groups = groupAcademyCategories(catalog.categories)
    const rows = groups.flatMap((group) => group.items)
    expect(catalog.category_count).toBe(31)
    expect(catalog.lab_count).toBe(273)
    expect(catalog.categories.reduce((count, item) => count + item.count, 0)).toBe(273)
    expect(groups.map((group) => group.key)).toEqual(['server-side', 'client-side', 'advanced'])
    expect(rows).toHaveLength(31)
    expect(rows.map((row) => row.slug).sort()).toEqual(catalog.categories.map((row) => row.slug).sort())
    expect(new Set(rows.map((row) => row.slug)).size).toBe(31)
  })

  it('keeps newly added categories visible without inventing verified counts', () => {
    const groups = groupAcademyCategories([{ slug: 'new-official-topic', count: 0 }])
    expect(groups).toEqual([{
      key: 'other',
      label: 'Other official topics',
      items: [{ slug: 'new-official-topic', count: 0 }],
    }])
  })
})
