import React, { Suspense, lazy } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './stores/authStore'
import { ThemeProvider } from './stores/themeStore'
import { LanguageProvider } from './stores/languageStore'
import { Layout } from './components/layout/Layout'
import { RouteGuard } from './components/auth/RouteGuard'
import { LoadingScreen } from './components/ui/LoadingScreen'
import { DashboardRealtime } from './services/dashboardRealtime'
const Login = lazy(() => import('./pages/auth/Login').then(m => ({ default: m.Login })))
const Register = lazy(() => import('./pages/auth/Register').then(m => ({ default: m.Register })))
const ForgotPassword = lazy(() => import('./pages/auth/ForgotPassword').then(m => ({ default: m.ForgotPassword })))
const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })))
const Projects = lazy(() => import('./pages/projects/Projects').then(m => ({ default: m.Projects })))
const ProjectDetail = lazy(() => import('./pages/projects/ProjectDetail').then(m => ({ default: m.ProjectDetail })))
const Assets = lazy(() => import('./pages/assets/Assets').then(m => ({ default: m.Assets })))
const ScanPage = lazy(() => import('./pages/scans/ScanPage').then(m => ({ default: m.ScanPage })))
const ScanProgress = lazy(() => import('./pages/scans/ScanProgress').then(m => ({ default: m.ScanProgress })))
const ScanResults = lazy(() => import('./pages/validations/ValidationCommandCenter').then(m => ({ default: m.ValidationCommandCenter })))
const Vulnerabilities = lazy(() => import('./pages/vulnerabilities/Vulnerabilities').then(m => ({ default: m.Vulnerabilities })))
const VulnerabilityDetail = lazy(() => import('./pages/vulnerabilities/VulnerabilityDetail').then(m => ({ default: m.VulnerabilityDetail })))
const Reports = lazy(() => import('./pages/reports/Reports').then(m => ({ default: m.Reports })))
const ReportDetail = lazy(() => import('./pages/reports/ReportDetail').then(m => ({ default: m.ReportDetail })))
const Compliance = lazy(() => import('./pages/compliance/Compliance').then(m => ({ default: m.Compliance })))
const ComplianceIntelligence = lazy(() => import('./pages/compliance/ComplianceIntelligencePage').then(m => ({ default: m.ComplianceIntelligencePage })))
const SecurityAssurance = lazy(() => import('./pages/compliance/SecurityAssuranceCommandCenterPage').then(m => ({ default: m.SecurityAssuranceCommandCenterPage })))
const ContinuousAssurance = lazy(() => import('./pages/assurance/ContinuousAssurancePage').then(m => ({ default: m.ContinuousAssurancePage })))
const CorrelationConflict = lazy(() => import('./pages/compliance/CorrelationConflictPage').then(m => ({ default: m.CorrelationConflictPage })))
const CorrelatedEvidenceGraph = lazy(() => import('./pages/compliance/CorrelatedEvidenceGraphPage').then(m => ({ default: m.CorrelatedEvidenceGraphPage })))
const AssuranceGraphPage = lazy(() => import('./pages/assurance/AssuranceGraphPage').then(m => ({ default: m.AssuranceGraphPage })))
const AutonomousTriagePage = lazy(() => import('./pages/assurance/AutonomousTriagePage').then(m => ({ default: m.AutonomousTriagePage })))
const SecurityDecisionPage = lazy(() => import('./pages/assurance/SecurityDecisionPage').then(m => ({ default: m.SecurityDecisionPage })))
const DecisionActionPage = lazy(() => import('./pages/assurance/DecisionActionPage').then(m => ({ default: m.DecisionActionPage })))
const DecisionActionDetailPage = lazy(() => import('./pages/assurance/DecisionActionDetailPage').then(m => ({ default: m.DecisionActionDetailPage })))
const WorkflowControlTowerPage = lazy(() => import('./pages/assurance/WorkflowControlTowerPage').then(m => ({ default: m.WorkflowControlTowerPage })))
const GovernancePage = lazy(() => import('./pages/assurance/GovernancePage').then(m => ({ default: m.GovernancePage })))
const PolicyStudioPage = lazy(() => import('./pages/assurance/PolicyStudioPage').then(m => ({ default: m.PolicyStudioPage })))
const PolicySimulationPage = lazy(() => import('./pages/assurance/PolicySimulationPage').then(m => ({ default: m.PolicySimulationPage })))
const KnowledgeBase = lazy(() => import('./pages/knowledge/KnowledgeBase').then(m => ({ default: m.KnowledgeBase })))
const KnowledgeArticle = lazy(() => import('./pages/knowledge/KnowledgeArticle').then(m => ({ default: m.KnowledgeArticle })))
const DigitalTwin = lazy(() => import('./pages/digital-twin/DigitalTwin').then(m => ({ default: m.DigitalTwin })))
const SecurityPosture = lazy(() => import('./pages/posture/SecurityPosture').then(m => ({ default: m.SecurityPosture })))
const CISOExecutivePage = lazy(() => import('./pages/executive/CISOExecutivePage').then(m => ({ default: m.CISOExecutivePage })))
const Users = lazy(() => import('./pages/users/Users').then(m => ({ default: m.Users })))
const Settings = lazy(() => import('./pages/settings/Settings').then(m => ({ default: m.Settings })))
const SystemMonitor = lazy(() => import('./pages/system/SystemMonitor').then(m => ({ default: m.SystemMonitor })))
const AuditLogs = lazy(() => import('./pages/audit/AuditLogs').then(m => ({ default: m.AuditLogs })))
const Notifications = lazy(() => import('./pages/notifications/Notifications').then(m => ({ default: m.Notifications })))
const NewValidation = lazy(() => import('./pages/validations/ValidationWizard').then(m => ({ default: m.ValidationWizard })))
const AegisCommandCenterPage = lazy(() => import('./pages/command/AegisCommandCenterPage').then(m => ({ default: m.AegisCommandCenterPage })))
const PublicRoute = ({ children }: { children: React.ReactNode }) => { const { isAuthenticated, loading } = useAuth(); if (loading) return <LoadingScreen />; if (isAuthenticated) return <Navigate to="/dashboard" replace />; return <>{children}</> }
const Page = ({ children }: { children: React.ReactNode }) => <Suspense fallback={<LoadingScreen />}>{children}</Suspense>
const App = () => <AuthProvider><ThemeProvider><LanguageProvider><DashboardRealtime /><Routes>
<Route path="/login" element={<PublicRoute><Page><Login /></Page></PublicRoute>} /><Route path="/register" element={<PublicRoute><Page><Register /></Page></PublicRoute>} /><Route path="/forgot-password" element={<PublicRoute><Page><ForgotPassword /></Page></PublicRoute>} />
<Route element={<RouteGuard><Layout /></RouteGuard>}>
<Route path="/dashboard" element={<Page><Dashboard /></Page>} /><Route path="/command-center" element={<Page><AegisCommandCenterPage /></Page>} /><Route path="/projects" element={<Page><Projects /></Page>} /><Route path="/projects/:id" element={<Page><ProjectDetail /></Page>} /><Route path="/assets" element={<Page><Assets /></Page>} /><Route path="/validations/new" element={<Page><NewValidation /></Page>} /><Route path="/validations/:id/progress" element={<Page><ScanProgress /></Page>} /><Route path="/validations/:id/results" element={<Page><ScanResults /></Page>} /><Route path="/scan" element={<Page><ScanPage /></Page>} /><Route path="/scan/:id/progress" element={<Page><ScanProgress /></Page>} /><Route path="/scan/:id/results" element={<Page><ScanResults /></Page>} /><Route path="/vulnerabilities" element={<Page><Vulnerabilities /></Page>} /><Route path="/vulnerabilities/:id" element={<Page><VulnerabilityDetail /></Page>} /><Route path="/reports" element={<Page><Reports /></Page>} /><Route path="/reports/:id" element={<Page><ReportDetail /></Page>} /><Route path="/compliance" element={<Page><Compliance /></Page>} /><Route path="/compliance/intelligence" element={<Page><ComplianceIntelligence /></Page>} /><Route path="/assurance" element={<Page><SecurityAssurance /></Page>} /><Route path="/assurance/continuous" element={<Page><ContinuousAssurance /></Page>} /><Route path="/assurance/conflicts" element={<Page><CorrelationConflict /></Page>} /><Route path="/assurance/evidence" element={<Page><CorrelatedEvidenceGraph /></Page>} /><Route path="/assurance/graph" element={<Page><AssuranceGraphPage /></Page>} /><Route path="/assurance/triage" element={<Page><AutonomousTriagePage /></Page>} /><Route path="/assurance/decisions" element={<Page><SecurityDecisionPage /></Page>} /><Route path="/assurance/actions" element={<Page><DecisionActionPage /></Page>} /><Route path="/assurance/actions/:actionId" element={<Page><DecisionActionDetailPage /></Page>} /><Route path="/assurance/workflow" element={<Page><WorkflowControlTowerPage /></Page>} /><Route path="/assurance/governance" element={<Page><GovernancePage /></Page>} /><Route path="/assurance/policies" element={<Page><PolicyStudioPage /></Page>} /><Route path="/assurance/policies/simulate" element={<Page><PolicySimulationPage /></Page>} /><Route path="/knowledge" element={<Page><KnowledgeBase /></Page>} /><Route path="/knowledge/:slug" element={<Page><KnowledgeArticle /></Page>} /><Route path="/digital-twin" element={<Page><DigitalTwin /></Page>} /><Route path="/posture" element={<Page><SecurityPosture /></Page>} /><Route path="/executive" element={<Page><CISOExecutivePage /></Page>} /><Route path="/users" element={<Page><Users /></Page>} /><Route path="/settings" element={<Page><Settings /></Page>} /><Route path="/system" element={<Page><SystemMonitor /></Page>} /><Route path="/audit" element={<Page><AuditLogs /></Page>} /><Route path="/notifications" element={<Page><Notifications /></Page>} /><Route path="/" element={<Navigate to="/dashboard" replace />} />
</Route><Route path="*" element={<Navigate to="/dashboard" replace />} />
</Routes></LanguageProvider></ThemeProvider></AuthProvider>
export default App
