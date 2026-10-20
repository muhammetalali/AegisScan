// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { CATALOGS } from './languageStore'
import { translateExact } from '@/i18n/translateExact'

describe('professional Arabic and English wording', () => {
  it('translates complete titles to Arabic without creating mixed-language suffixes', () => {
    expect(translateExact('System Monitoring', CATALOGS.ar)).toBe('مراقبة النظام')
    expect(translateExact('Evidence registry', CATALOGS.ar)).toBe('سجل الأدلة')
    expect(translateExact('Knowledge Center', CATALOGS.ar)).toBe('مركز المعرفة')
    expect(translateExact('Scan registry', CATALOGS.ar)).toBe('سجل الفحوص')
  })
  it('has no duplicate Arabic translation keys that silently override wording', () => {
    const source = readFileSync('src/stores/languageStore.tsx', 'utf8')
    const arabic = source.split('  ar: {')[1].split('  en: {')[0]
    const matches = [...arabic.matchAll(/(?:'([^'\n]+)'|\b([A-Za-z_][A-Za-z0-9_]*)\b)\s*:\s*'/g)]
    const keys = matches.map((match) => match[1] || match[2])
    expect(keys.length).toBeGreaterThan(100)
    expect(new Set(keys).size).toBe(keys.length)
  })
  it('keeps project names, IP addresses and longer user content unchanged', () => {
    for (const text of ['System Monitoring.dev', '192.168.1.0/24', 'Knowledge Center - custom asset', 'Evidence registry-42']) {
      expect(translateExact(text, CATALOGS.ar)).toBe(text)
    }
  })
})
