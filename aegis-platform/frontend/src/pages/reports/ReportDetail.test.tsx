// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { describeReportType } from './ReportDetail'
describe('report narrative', () => {
  it('states what each stored report type actually contains instead of using unrelated dashboard scores', () => {
    expect(describeReportType('full')).toMatch(/scans, findings/)
    expect(describeReportType('evidence')).toMatch(/provenance/)
    expect(describeReportType('scan')).toMatch(/target/)
    expect(describeReportType('unknown')).toMatch(/saved data/)
  })
})