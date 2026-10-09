import { describe, expect, it } from 'vitest'
import { canAccessRoute, canManageKeys } from './routePolicy'

describe('real navigation and deep-link permission parity', () => {
  it('gives only the server-identified company owner access to every workspace page', () => {
    const ownerPages = [
      '/dashboard', '/projects', '/projects/project-1/assess', '/assets',
      '/assess', '/web-labs', '/validations/new', '/scan', '/scan/scan-1/results',
      '/vulnerabilities', '/evidence', '/reports', '/compliance',
      '/assurance/workflow', '/assurance/policies', '/digital-twin',
      '/investigation', '/enterprise-security', '/users', '/keys',
      '/settings', '/system', '/security-events', '/audit',
    ]
    for (const path of ownerPages) {
      expect(canAccessRoute(path, 'super_admin', [], [], true), path).toBe(true)
    }
    expect(canAccessRoute('/users', 'super_admin', [], [], false)).toBe(false)
    expect(canAccessRoute('/assess', 'admin', [], [], false)).toBe(false)
    expect(canAccessRoute('/users', undefined, [], [], true)).toBe(false)
  })
  it('keeps Viewer out of management pages even through direct routes and palette', () => {
    for (const path of ['/users','/settings','/system','/audit','/keys','/assess','/web-labs','/assurance/actions','/enterprise-security','/projects/project-1/assess','/validations/new']) {
      expect(canAccessRoute(path,'viewer'), path).toBe(false)
    }
    for (const path of ['/dashboard','/projects','/assets','/scan','/reports','/notifications']) {
      expect(canAccessRoute(path,'viewer'),path).toBe(true)
    }
  })
  it('permits only genuine key managers to open the one canonical key surface', () => {
    for (const role of ['admin','super_admin','security_manager'] as const) {
      expect(canManageKeys(role)).toBe(true)
      expect(canAccessRoute('/keys',role)).toBe(true)
    }
    for (const role of ['viewer','developer','auditor','security_analyst'] as const) {
      expect(canManageKeys(role)).toBe(false)
      expect(canAccessRoute('/keys',role)).toBe(false)
    }
  })
  it('restricts an Administrator to owner-granted pages even on direct deep links', () => {
    const grants = ['project.read','scan.read']
    expect(canAccessRoute('/dashboard','admin',grants)).toBe(true)
    expect(canAccessRoute('/projects','admin',grants)).toBe(true)
    expect(canAccessRoute('/scan','admin',grants)).toBe(true)
    for (const forbidden of ['/users','/settings','/keys','/audit','/assess','/validations/new','/system']) {
      expect(canAccessRoute(forbidden,'admin',grants),forbidden).toBe(false)
    }
    expect(canAccessRoute('/assess','admin',['scan.create'])).toBe(true)
    expect(canAccessRoute('/projects/project-1/assess','admin',['project.read'])).toBe(false)
    expect(canAccessRoute('/projects/project-1/assess','admin',['project.read','scan.create'])).toBe(true)
  })
  it('fails closed on unassigned deep links, even with matching RBAC grants', () => {
    const analyst = 'security_analyst' as const
    expect(canAccessRoute('/dashboard',analyst,['scan.read'],[])).toBe(true)
    expect(canAccessRoute('/scan/scan-1/progress',analyst,['scan.read'],['/scan'])).toBe(true)
    expect(canAccessRoute('/assurance/graph',analyst,['scan.read'],['/scan'])).toBe(false)
    expect(canAccessRoute('/validations/new',analyst,['scan.create'],['/scan'])).toBe(false)
    expect(canAccessRoute('/validations/new',analyst,['scan.create'],['/assess'])).toBe(true)
    expect(canAccessRoute('/projects/project-1/assess',analyst,['scan.create'],['/projects'])).toBe(false)
  })
  it('keeps scope-specific route access consistent with existing navigation roles', () => {
    expect(canAccessRoute('/users','admin')).toBe(true)
    expect(canAccessRoute('/settings','admin')).toBe(true)
    expect(canAccessRoute('/audit','auditor')).toBe(true)
    expect(canAccessRoute('/assurance/workflow','auditor')).toBe(true)
    expect(canAccessRoute('/assess','security_analyst')).toBe(true)
    expect(canAccessRoute('/projects/project-1/assess','security_analyst')).toBe(true)
    expect(canAccessRoute('/posture','viewer')).toBe(false)
    expect(canAccessRoute('/keys',undefined)).toBe(false)
  })
})
