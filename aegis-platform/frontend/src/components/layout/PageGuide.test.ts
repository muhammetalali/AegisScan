import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { guideForRoute } from './PageGuide'

const routeSource = readFileSync(new URL('../../App.tsx', import.meta.url), 'utf8')
const declaredPaths = [...routeSource.matchAll(/<Route path="([^"]+)"/g)].map((m) => m[1])
const ignored = new Set(['/login', '/register', '/forgot-password', '/', '*'])
const protectedRoutes = declaredPaths.filter((path) => !ignored.has(path))
const asRealPath = (path: string) => path.replace(/:[^/]+/g, 'sample-1')

describe('compact global page guide', () => {
  it('covers all protected routes without adding navigation or permissions', () => {
    expect(protectedRoutes.length).toBeGreaterThan(40)
    for (const path of protectedRoutes) {
      const guide = guideForRoute(asRealPath(path))
      expect(guide, 'Missing guide for '+path).not.toBeNull()
      expect(guide?.title?.length).toBeGreaterThan(2)
      expect(guide?.description?.length).toBeGreaterThan(24)
    }
  })
  it('does not display a guide in public authentication routes', () => {
    expect(guideForRoute('/login')).toBeNull()
    expect(guideForRoute('/register')).toBeNull()
  })
})
