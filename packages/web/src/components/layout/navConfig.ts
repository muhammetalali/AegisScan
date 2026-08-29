import { LayoutDashboard, FolderKanban, Server, Zap, Activity, Bug, FileText, ShieldCheck, BookOpen, GitBranch, TrendingUp, Users, Settings, Monitor, ClipboardList, Bell, Gauge } from 'lucide-react'
import type { UserRole } from '@/types'

export type NavItem = { name: string; href: string; icon: typeof LayoutDashboard; roles: Array<'all' | UserRole>; permission?: string }

export const NAV_GROUPS: Array<{ label: string; items: NavItem[] }> = [
  { label: 'Overview', items: [{ name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard, roles: ['all'] }] },
  { label: 'Workspace', items: [
    { name: 'Projects', href: '/projects', icon: FolderKanban, roles: ['all'] },
    { name: 'Assets', href: '/assets', icon: Server, roles: ['all'] },
  ] },
  { label: 'Validate', items: [
    { name: 'New Validation', href: '/validations/new', icon: Zap, roles: ['super_admin', 'admin', 'security_manager', 'security_analyst', 'developer'] },
    { name: 'Validations', href: '/scan', icon: Activity, roles: ['all'] },
    { name: 'Findings', href: '/vulnerabilities', icon: Bug, roles: ['all'] },
  ] },
  { label: 'Analyze', items: [
    { name: 'Reports', href: '/reports', icon: FileText, roles: ['all'], permission: 'reports:read' },
    { name: 'Compliance', href: '/compliance', icon: ShieldCheck, roles: ['all'], permission: 'compliance:read' },
    { name: 'Security Assurance', href: '/assurance', icon: Gauge, roles: ['all'], permission: 'assurance:read' },
    { name: 'Security Posture', href: '/posture', icon: TrendingUp, roles: ['super_admin', 'admin', 'security_manager'] },
    { name: 'Digital Twin', href: '/digital-twin', icon: GitBranch, roles: ['super_admin', 'admin', 'security_manager', 'security_analyst', 'developer'] },
    { name: 'Knowledge', href: '/knowledge', icon: BookOpen, roles: ['all'] },
  ] },
  { label: 'Manage', items: [
    { name: 'Users & RBAC', href: '/users', icon: Users, roles: ['super_admin', 'admin'] },
    { name: 'Audit Trail', href: '/audit', icon: ClipboardList, roles: ['super_admin', 'admin', 'auditor'], permission: 'audit:read' },
    { name: 'Notifications', href: '/notifications', icon: Bell, roles: ['all'] },
  ] },
  { label: 'System', items: [
    { name: 'Settings', href: '/settings', icon: Settings, roles: ['super_admin', 'admin', 'security_manager', 'developer'] },
    { name: 'System Monitor', href: '/system', icon: Monitor, roles: ['super_admin', 'admin'] },
  ] },
]
