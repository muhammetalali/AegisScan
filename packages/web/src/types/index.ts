export interface User {
  id: string
  email: string
  first_name: string
  last_name: string
  full_name?: string
  phone?: string
  avatar?: string
  role: UserRole
  permissions?: string[]
  is_active: boolean
  is_verified: boolean
  language: Language
  theme: Theme
  timezone: string
  two_factor_enabled: boolean
  last_login_ip?: string
  last_activity?: string
  date_joined: string
  last_login?: string
}

export type UserRole =
  | 'super_admin'
  | 'admin'
  | 'security_manager'
  | 'security_analyst'
  | 'developer'
  | 'auditor'
  | 'viewer'

export type Language = 'ar' | 'en'
export type Theme = 'light' | 'dark' | 'system'

export interface Project {
  id: string
  name: string
  slug: string
  description: string
  status: ProjectStatus
  environment: ProjectEnvironment
  owner: User
  members: ProjectMembership[]
  tags: string[]
  settings: Record<string, unknown>
  created_at: string
  updated_at: string
  archived_at?: string
}

export type ProjectStatus = 'active' | 'archived' | 'on_hold'
export type ProjectEnvironment = 'development' | 'staging' | 'production'

export interface ProjectMembership {
  id: string
  project: string
  user: User
  role: ProjectRole
  joined_at: string
}

export type ProjectRole = 'owner' | 'admin' | 'member' | 'viewer'

export interface Asset {
  id: string
  project: string
  name: string
  slug: string
  type: AssetType
  description: string
  environment: AssetEnvironment
  criticality: AssetCriticality
  configuration: Record<string, unknown>
  tags: string[]
  owner?: User
  is_active: boolean
  last_scanned_at?: string
  scan_count: number
  created_at: string
  updated_at: string
}

export type AssetType = 'source_code' | 'website' | 'ip_address' | 'domain' | 'api_endpoint' | 'file' | 'docker_image' | 'network_range' | 'repository' | 'cloud_resource' | 'kubernetes' | 'mobile_app'
export type AssetEnvironment = 'development' | 'staging' | 'production'
export type AssetCriticality = 'critical' | 'high' | 'medium' | 'low'

export interface Scan {
  id: string
  project: string
  name: string
  scan_type: ScanType
  status: ScanStatus
  depth: ScanDepth
  asset?: string
  engines: string[]
  config: Record<string, unknown>
  progress: number
  current_phase: string
  current_engine: string
  security_score: number
  risk_level: string
  findings_count: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  started_at?: string
  completed_at?: string
  duration: number
  initiated_by?: User
  created_at: string
  updated_at: string
}

export type ScanType = 'code' | 'url' | 'ip' | 'api' | 'file' | 'docker' | 'network' | 'full_validation'
export type ScanStatus = 'pending' | 'queued' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled' | 'partial'
export type ScanDepth = 'quick' | 'standard' | 'deep' | 'comprehensive'

export interface ScanEngineExecution {
  id: string
  scan: string
  engine: ScanEngine
  status: EngineExecutionStatus
  progress: number
  started_at?: string
  completed_at?: string
  duration: number
  findings_found: number
  evidences_collected: number
}

export type EngineExecutionStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped'

export interface ScanEngine {
  id: string
  name: string
  display_name: string
  description: string
  category: EngineCategory
  version: string
  status: EngineStatus
  is_core: boolean
  requires_docker: boolean
  timeout: number
  order: number
}

export type EngineCategory = 'recon' | 'analysis' | 'intelligence' | 'validation' | 'control' | 'coverage' | 'attack_path' | 'evidence_graph' | 'knowledge' | 'ai_explain' | 'posture' | 'compliance' | 'digital_twin' | 'reporting'
export type EngineStatus = 'active' | 'inactive' | 'deprecated' | 'experimental'

export interface Vulnerability {
  id: string
  scan: string
  project: string
  title: string
  description: string
  severity: VulnerabilitySeverity
  status: VulnerabilityStatus
  confidence: VulnerabilityConfidence
  category: string
  cve_ids: string[]
  cvss_score: number
  risk_score: number
  file_path?: string
  line_start?: number
  line_end?: number
  code_snippet?: string
  remediation: string
  assigned_to?: User
  status_history: VulnerabilityStatusHistory[]
  created_at: string
  updated_at: string
}

export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type VulnerabilityStatus = 'open' | 'confirmed' | 'in_progress' | 'fixed' | 'false_positive' | 'accepted_risk' | 'wont_fix' | 'duplicate'
export type VulnerabilityConfidence = 'confirmed' | 'high' | 'medium' | 'low' | 'unverified'

export interface VulnerabilityStatusHistory { id: string; old_status: VulnerabilityStatus; new_status: VulnerabilityStatus; changed_by: User; reason: string; created_at: string }
export interface Report { id: string; project: string; scan?: string; title: string; description: string; report_type: ReportType; format: ReportFormat; status: ReportStatus; file?: string; file_size: number; generated_by: User; created_at: string }
export type ReportType = 'technical' | 'executive' | 'compliance' | 'remediation' | 'full' | 'comparison' | 'trend'
export type ReportFormat = 'pdf' | 'html' | 'markdown' | 'json' | 'csv' | 'docx'
export type ReportStatus = 'generating' | 'completed' | 'failed'
export interface ComplianceFramework { id: string; name: string; framework_type: FrameworkType; version: string; controls_count: number }
export type FrameworkType = 'nist_800_53' | 'nist_csf' | 'iso_27001' | 'pci_dss' | 'hipaa' | 'gdpr' | 'soc2' | 'cis_controls' | 'custom'
export interface ComplianceAssessment { id: string; project: string; framework: ComplianceFramework; control: ComplianceControl; status: ComplianceStatus; evidence: string; findings: string[]; assessed_at?: string }
export type ComplianceStatus = 'compliant' | 'non_compliant' | 'partial' | 'not_applicable' | 'not_assessed'
export interface ComplianceControl { id: string; framework: string; control_id: string; title: string; description: string; priority: 'mandatory' | 'high' | 'medium' | 'low' | 'informational'; category: string }
export interface KnowledgeArticle { id: string; title: string; slug: string; type: KnowledgeType; status: KnowledgeStatus; category: KnowledgeCategory; summary: string; content: string; content_html: string; author: User; view_count: number; helpful_count: number; published_at?: string; created_at: string }
export type KnowledgeType = 'best_practice' | 'remediation_guide' | 'security_policy' | 'lesson_learned' | 'attack_pattern' | 'defense_gap' | 'tool_guide' | 'faq' | 'template'
export type KnowledgeStatus = 'draft' | 'published' | 'archived' | 'under_review'
export interface KnowledgeCategory { id: string; name: string; slug: string; description: string; icon: string; color: string }
export interface DigitalTwin { id: string; project: string; name: string; status: TwinStatus; environment: Record<string, unknown>; scenarios: TwinScenario[] }
export type TwinStatus = 'building' | 'ready' | 'testing' | 'drifted' | 'destroyed'
export interface TwinScenario { id: string; name: string; change_type: string; affected_nodes: string[]; security_impact: number; risk_reduction: number }
export interface SecurityPosture { id: string; project: string; overall_score: number; rating: PostureRating; metrics: PostureMetric[]; trend: PostureTrend }
export type PostureRating = 'excellent' | 'good' | 'fair' | 'poor' | 'critical'
export interface PostureMetric { name: string; value: number; max_value: number; category: string; trend: 'improving' | 'declining' | 'stable' }
export interface PostureTrend { direction: 'improving' | 'declining' | 'stable'; change_rate: number }
export interface Notification { id: string; event_type: string; title: string; message: string; priority: 'low' | 'normal' | 'high' | 'urgent'; status: 'pending' | 'sent' | 'delivered' | 'failed' | 'read'; created_at: string; read_at?: string; action_url?: string }
export interface AuditLog { id: string; user?: User; action: string; result: 'success' | 'failure' | 'partial'; resource_type: string; resource_id: string; changes: Record<string, unknown>; ip_address: string; created_at: string }
export interface SystemMetric { metric_type: string; value: number; unit: string; timestamp: string }
export interface ServiceStatus { service: string; status: 'healthy' | 'degraded' | 'down' | 'unknown'; response_time_ms: number; uptime_percentage: number }
export interface PaginatedResponse<T> { count: number; next: string | null; previous: string | null; results: T[] }
export interface ApiError { success: false; error: { code: number; message: string; details?: unknown } }
export interface SelectOption { value: string; label: string; disabled?: boolean }
