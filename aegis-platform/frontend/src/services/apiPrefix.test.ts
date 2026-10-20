import { describe, expect, it } from 'vitest'
import { normalizePlatformApiPath } from './api'
describe('one API version prefix for all contracts', () => {
  it('avoids duplicate /api/v1/api/v1 in compliance and other contract requests', () => {
    expect(normalizePlatformApiPath('/api/v1/validations/123/compliance')).toBe('/validations/123/compliance')
    expect(normalizePlatformApiPath('/validations/123/compliance')).toBe('/validations/123/compliance')
    expect(normalizePlatformApiPath('/api/v1')).toBe('/')
  })
  it('does not modify other origins or relative paths', () => {
    expect(normalizePlatformApiPath('https://internal.example/api/v1/health')).toBe('https://internal.example/api/v1/health')
    expect(normalizePlatformApiPath('/auth/refresh/')).toBe('/auth/refresh/')
  })
})