// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { loadAssessmentProjects, preferAssessmentProject } from './AssessmentEntry'
import { apiHelpers } from '@/services/api'

vi.mock('@/services/api', () => ({ apiHelpers: { get: vi.fn(), post: vi.fn() } }))
describe('one-step assessment project selection', () => {
  it('prefers a real existing workspace without needing an older assessment', () => {
    const projects = [
      {id:'test-1',name:'External E2E abc',status:'active'},
      {id:'real-1',name:'mi-kali',status:'active'},
      {id:'real-2',name:'Customer lab',status:'active'},
    ]
    expect(preferAssessmentProject(projects,'','')?.id).toBe('real-1')
    expect(preferAssessmentProject(projects,'test-1','')?.id).toBe('test-1')
    expect(preferAssessmentProject(projects,'','real-2')?.id).toBe('real-2')
  })
  it('loads all authorized DRF pages instead of displaying only first-page E2E workspaces', async () => {
    const get=vi.mocked(apiHelpers.get)
    get.mockImplementation(async (_path, options) => Number(options?.params?.page)===1
      ? {count:2,next:'/api/v1/projects/?page=2',results:[{id:'e2e',name:'External E2E run',status:'active'}]} as never
      : {count:2,next:null,results:[{id:'real',name:'mi-kali',status:'active'}]} as never)
    const projects = await loadAssessmentProjects()
    expect(projects.map((p)=>p.id)).toEqual(['e2e','real'])
    expect(get).toHaveBeenCalledTimes(2)
    get.mockReset()
  })
})