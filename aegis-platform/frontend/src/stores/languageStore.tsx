import React, { useEffect } from 'react'
import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

type Language = 'ar' | 'en'
type Catalog = Record<string, string>

const CATALOGS: Record<Language, Catalog> = {
  ar: {
    AegisScan: 'AegisScan', 'Security Validation': 'التحقق الأمني', 'Security Validation Platform': 'منصة التحقق الأمني', Overview: 'نظرة عامة', Dashboard: 'لوحة التحكم', Workspace: 'مساحة العمل', Projects: 'المشاريع', Assets: 'الأصول', Validate: 'التحقق', 'New Validation': 'تحقق جديد', 'New validation': 'تحقق جديد', Validations: 'عمليات التحقق', Findings: 'الثغرات', Analyze: 'التحليل', Reports: 'التقارير', Compliance: 'الامتثال', 'Security Assurance': 'ضمان الأمن', 'Security Posture': 'الوضع الأمني', 'Digital Twin': 'التوأم الرقمي', Knowledge: 'المعرفة', Manage: 'الإدارة', 'Users & RBAC': 'المستخدمون والصلاحيات', 'Audit Trail': 'سجل التدقيق', Notifications: 'الإشعارات', System: 'النظام', Settings: 'الإعدادات', 'System Monitor': 'مراقبة النظام', Search: 'بحث', 'Search validations, findings, assets...': 'البحث في عمليات التحقق والثغرات والأصول...', 'Search validations, findings, assets…': 'البحث في عمليات التحقق والثغرات والأصول…', 'Search projects…': 'البحث في المشاريع…', 'Search projects': 'البحث في المشاريع', 'View all': 'عرض الكل', Logout: 'تسجيل الخروج', 'Change language': 'تغيير اللغة',
    'Platform operational': 'المنصة تعمل بشكل طبيعي', 'Evidence-driven security validation': 'تحقق أمني قائم على الأدلة', 'Workspace navigation': 'تنقل مساحة العمل', 'Access is filtered by your current RBAC role.': 'يتم تقييد الوصول وفق دور RBAC الحالي.',
    'Create Validation Job': 'إنشاء مهمة تحقق', 'Real Validation': 'تحقق حقيقي', 'Security Validation Results': 'نتائج التحقق الأمني', 'Validation Command Center': 'مركز قيادة التحقق', 'Execution Timeline': 'الخط الزمني للتنفيذ', 'Export JSON': 'تصدير JSON', 'Risk Score': 'درجة المخاطر', Evidence: 'الأدلة', 'Validation coverage': 'تغطية التحقق', 'Finding severity profile': 'توزيع شدة الثغرات', 'Risk intelligence': 'استخبارات المخاطر', 'Risk register': 'سجل المخاطر', 'Findings requiring attention': 'الثغرات التي تتطلب معالجة', 'No findings match this view': 'لا توجد ثغرات مطابقة لهذا العرض', 'Open Findings Center': 'فتح مركز الثغرات', 'Generate a formal report': 'إنشاء تقرير رسمي', Target: 'الهدف', Engine: 'المحرك', Status: 'الحالة', Confidence: 'الثقة', 'Engines executed': 'المحركات المنفذة', 'Validation status': 'حالة التحقق', Summary: 'الملخص', 'Healthy posture': 'وضع أمني جيد', 'Needs review': 'يحتاج إلى مراجعة', Complete: 'مكتمل',
    'Finding source': 'مصدر الثغرة', 'Execution contract': 'عقد التنفيذ', 'Choose a real finding': 'اختر ثغرة حقيقية', 'Create an evidence-linked validation': 'إنشاء تحقق مرتبط بدليل حقيقي', 'Choose a finding first': 'اختر ثغرة أولًا', Retry: 'إعادة المحاولة', Cancel: 'إلغاء', Back: 'رجوع', Continue: 'متابعة', 'Loading...': 'جارٍ التحميل...', 'Finding not found': 'الثغرة غير موجودة', 'Validation not found': 'عملية التحقق غير موجودة', 'No validation results are available from the API yet.': 'لا توجد نتائج تحقق متاحة من واجهة API حتى الآن.', 'Target Configuration': 'إعداد الهدف', 'Authorization required': 'التفويض مطلوب', 'Authorization required before execution': 'التفويض مطلوب قبل التنفيذ', 'Authorized scope': 'النطاق المصرح به', Execution: 'التنفيذ', Authorization: 'التفويض', 'Waiting for engine…': 'بانتظار المحرك…', 'All engines completed — ready for Results': 'اكتملت كل المحركات — النتائج جاهزة', 'New Security Validation': 'تحقق أمني جديد', 'What are we validating?': 'ماذا نتحقق منه؟', 'Execution state': 'حالة التنفيذ', 'Server-authoritative progress': 'تقدم موثوق من الخادم', 'Execution controls': 'عناصر التحكم في التنفيذ', 'API polling': 'تحديث عبر API', 'WebSocket LIVE': 'WebSocket مباشر', 'View Results': 'عرض النتائج',
    'Security workspace': 'مساحة العمل الأمنية', 'Active security workspaces': 'مساحات العمل الأمنية النشطة', 'Tracked attack surface': 'سطح الهجوم المتتبع', 'Average score': 'متوسط الدرجة', 'high-risk workspaces': 'مساحات عمل عالية المخاطر', 'No high-risk workspaces': 'لا توجد مساحات عمل عالية المخاطر', 'Project registry': 'سجل المشاريع', 'Live data from the AegisScan API': 'بيانات حية من واجهة AegisScan API', 'Projects could not be loaded': 'تعذر تحميل المشاريع', 'The API did not return a usable response. Your workspace was not replaced with demo data.': 'لم تُرجع الواجهة استجابة صالحة. لم يتم استبدال مساحة العمل ببيانات تجريبية.', 'No matching projects': 'لا توجد مشاريع مطابقة', 'No projects yet': 'لا توجد مشاريع بعد', 'Try a different name, owner or risk filter.': 'جرّب اسمًا أو مالكًا أو مرشح مخاطر مختلفًا.', 'Create a project to start organizing assets and validations.': 'أنشئ مشروعًا لبدء تنظيم الأصول وعمليات التحقق.', 'Create project': 'إنشاء مشروع', Project: 'المشروع', Owner: 'المالك', 'Last validation': 'آخر تحقق', Score: 'الدرجة', Risk: 'المخاطر', Updated: 'آخر تحديث', Open: 'فتح', Unknown: 'غير معروف', 'Not validated': 'لم يتم التحقق بعد', 'New project': 'مشروع جديد', 'Project name': 'اسم المشروع', Description: 'الوصف', Environment: 'البيئة', Development: 'تطوير', Staging: 'اختبار مرحلي', Production: 'إنتاج', 'Project name is required': 'اسم المشروع مطلوب', 'Production security workspace': 'مساحة عمل أمنية للإنتاج', 'Describe the security scope of this project': 'صف النطاق الأمني لهذا المشروع', 'Create a real project in the current RBAC scope. No client-side project is synthesized.': 'إنشاء مشروع حقيقي ضمن نطاق RBAC الحالي. لا يتم إنشاء مشروع اصطناعي على الواجهة.', 'Project created successfully': 'تم إنشاء المشروع بنجاح', 'Unable to create project': 'تعذر إنشاء المشروع', 'Project service did not return a project id': 'خدمة المشاريع لم تُرجع معرّف المشروع', 'Close': 'إغلاق',
    'The list is sourced only from the vulnerabilities API. No demo results are injected.': 'القائمة مصدرها واجهة الثغرات فقط. لا يتم حقن نتائج تجريبية.', 'Search findings, assets…': 'ابحث في الثغرات والأصول…', 'Asset unavailable': 'الأصل غير متاح', 'No findings available for real validation with the current data.': 'لا توجد ثغرات متاحة للتحقق الحقيقي ضمن البيانات الحالية.', 'Execution stays disabled until a real finding is linked to an asset and supported engine.': 'يبقى التنفيذ معطلاً حتى ترتبط ثغرة حقيقية بأصل ومحرك مدعوم.', 'The backend performs server-side scope authorization. The UI cannot bypass it.': 'ينفذ الخادم تفويض النطاق من جهة الخادم ولا يمكن للواجهة تجاوز ذلك.', 'I confirm this target is authorized': 'أؤكد أن هذا الهدف مصرح به', 'Authorization is persisted with the ValidationRun and the server-side scope check remains mandatory.': 'يتم حفظ التفويض مع ValidationRun ويظل فحص النطاق على الخادم إلزاميًا.', 'Creating job…': 'جارٍ إنشاء المهمة…', 'Real validation job created': 'تم إنشاء مهمة تحقق حقيقية', 'Validation service did not return a finding-linked job': 'خدمة التحقق لم تُرجع مهمة مرتبطة بالثغرة', 'Unable to create validation job': 'تعذر إنشاء مهمة التحقق', 'Finding source engine is not supported for validation': 'محرك مصدر الثغرة غير مدعوم للتحقق', 'The selected finding has no linked asset target': 'الثغرة المحددة لا تحتوي على هدف أصل مرتبط', 'Authorized scope is required': 'النطاق المصرح به مطلوب', 'Validation service did not return a finding-linked job': 'خدمة التحقق لم تُرجع مهمة مرتبطة بالثغرة', 'Choose a real finding': 'اختر ثغرة حقيقية', 'Unable to load findings': 'تعذر تحميل الثغرات', 'Real validation requires finding data from the API. No local or demo data is used.': 'التحقق الحقيقي يتطلب بيانات ثغرة من واجهة API. لا يتم استخدام بيانات محلية أو تجريبية.', 'Choose a finding first': 'اختر ثغرة أولًا', 'Search findings, assets…': 'بحث في الثغرات والأصول…', 'The backend performs server-side scope authorization. The UI cannot bypass it.': 'يقوم الخادم بتفويض النطاق بشكل فعلي ولا يمكن للواجهة تجاوزه.',
  },
  en: {
    AegisScan: 'AegisScan', 'Security Validation': 'Security Validation', 'Security Validation Platform': 'Security Validation Platform', Overview: 'Overview', Dashboard: 'Dashboard', Workspace: 'Workspace', Projects: 'Projects', Assets: 'Assets', Validate: 'Validate', 'New Validation': 'New Validation', 'New validation': 'New validation', Validations: 'Validations', Findings: 'Findings', Analyze: 'Analyze', Reports: 'Reports', Compliance: 'Compliance', 'Security Assurance': 'Security Assurance', 'Security Posture': 'Security Posture', 'Digital Twin': 'Digital Twin', Knowledge: 'Knowledge', Manage: 'Manage', 'Users & RBAC': 'Users & RBAC', 'Audit Trail': 'Audit Trail', Notifications: 'Notifications', System: 'System', Settings: 'Settings', 'System Monitor': 'System Monitor', Search: 'Search', 'Search validations, findings, assets...': 'Search validations, findings, assets...', 'Search validations, findings, assets…': 'Search validations, findings, assets…', 'Search projects…': 'Search projects…', 'Search projects': 'Search projects', 'View all': 'View all', Logout: 'Logout', 'Change language': 'Change language',
    'Platform operational': 'Platform operational', 'Evidence-driven security validation': 'Evidence-driven security validation', 'Workspace navigation': 'Workspace navigation', 'Access is filtered by your current RBAC role.': 'Access is filtered by your current RBAC role.', 'Create Validation Job': 'Create Validation Job', 'Real Validation': 'Real Validation', 'Security Validation Results': 'Security Validation Results', 'Validation Command Center': 'Validation Command Center', 'Execution Timeline': 'Execution Timeline', 'Export JSON': 'Export JSON', 'Risk Score': 'Risk Score', Evidence: 'Evidence', 'Validation coverage': 'Validation coverage', 'Finding severity profile': 'Finding severity profile', 'Risk intelligence': 'Risk intelligence', 'Risk register': 'Risk register', 'Findings requiring attention': 'Findings requiring attention', 'No findings match this view': 'No findings match this view', 'Open Findings Center': 'Open Findings Center', 'Generate a formal report': 'Generate a formal report', Target: 'Target', Engine: 'Engine', Status: 'Status', Confidence: 'Confidence', 'Engines executed': 'Engines executed', 'Validation status': 'Validation status', Summary: 'Summary', 'Healthy posture': 'Healthy posture', 'Needs review': 'Needs review', Complete: 'Complete', 'Finding source': 'Finding source', 'Execution contract': 'Execution contract', 'Choose a real finding': 'Choose a real finding', 'Create an evidence-linked validation': 'Create an evidence-linked validation', 'Choose a finding first': 'Choose a finding first', Retry: 'Retry', Cancel: 'Cancel', Back: 'Back', Continue: 'Continue', 'Loading...': 'Loading...', 'Finding not found': 'Finding not found', 'Validation not found': 'Validation not found', 'No validation results are available from the API yet.': 'No validation results are available from the API yet.', 'Target Configuration': 'Target Configuration', 'Authorization required': 'Authorization required', 'Authorization required before execution': 'Authorization required before execution', 'Authorized scope': 'Authorized scope', Execution: 'Execution', Authorization: 'Authorization', 'Waiting for engine…': 'Waiting for engine…', 'All engines completed — ready for Results': 'All engines completed — ready for Results', 'New Security Validation': 'New Security Validation', 'What are we validating?': 'What are we validating?', 'Execution state': 'Execution state', 'Server-authoritative progress': 'Server-authoritative progress', 'Execution controls': 'Execution controls', 'API polling': 'API polling', 'WebSocket LIVE': 'WebSocket LIVE', 'View Results': 'View Results',
    'Security workspace': 'Security workspace', 'Active security workspaces': 'Active security workspaces', 'Tracked attack surface': 'Tracked attack surface', 'Average score': 'Average score', 'high-risk workspaces': 'high-risk workspaces', 'No high-risk workspaces': 'No high-risk workspaces', 'Project registry': 'Project registry', 'Live data from the AegisScan API': 'Live data from the AegisScan API', 'Projects could not be loaded': 'Projects could not be loaded', 'The API did not return a usable response. Your workspace was not replaced with demo data.': 'The API did not return a usable response. Your workspace was not replaced with demo data.', 'No matching projects': 'No matching projects', 'No projects yet': 'No projects yet', 'Try a different name, owner or risk filter.': 'Try a different name, owner or risk filter.', 'Create a project to start organizing assets and validations.': 'Create a project to start organizing assets and validations.', 'Create project': 'Create project', Project: 'Project', Owner: 'Owner', 'Last validation': 'Last validation', Score: 'Score', Risk: 'Risk', Updated: 'Updated', Open: 'Open', Unknown: 'Unknown', 'Not validated': 'Not validated', 'New project': 'New project', 'Project name': 'Project name', Description: 'Description', Environment: 'Environment', Development: 'Development', Staging: 'Staging', Production: 'Production', 'Project name is required': 'Project name is required', 'Production security workspace': 'Production security workspace', 'Describe the security scope of this project': 'Describe the security scope of this project', 'Create a real project in the current RBAC scope. No client-side project is synthesized.': 'Create a real project in the current RBAC scope. No client-side project is synthesized.', 'Project created successfully': 'Project created successfully', 'Unable to create project': 'Unable to create project', 'Project service did not return a project id': 'Project service did not return a project id', Close: 'Close',
    'The list is sourced only from the vulnerabilities API. No demo results are injected.': 'The list is sourced only from the vulnerabilities API. No demo results are injected.', 'Search findings, assets…': 'Search findings, assets…', 'Asset unavailable': 'Asset unavailable', 'No findings available for real validation with the current data.': 'No findings available for real validation with the current data.', 'Execution stays disabled until a real finding is linked to an asset and supported engine.': 'Execution stays disabled until a real finding is linked to an asset and supported engine.', 'The backend performs server-side scope authorization. The UI cannot bypass it.': 'The backend performs server-side scope authorization. The UI cannot bypass it.', 'I confirm this target is authorized': 'I confirm this target is authorized', 'Authorization is persisted with the ValidationRun and the server-side scope check remains mandatory.': 'Authorization is persisted with the ValidationRun and the server-side scope check remains mandatory.', 'Creating job…': 'Creating job…', 'Real validation job created': 'Real validation job created', 'Validation service did not return a finding-linked job': 'Validation service did not return a finding-linked job', 'Unable to create validation job': 'Unable to create validation job', 'Finding source engine is not supported for validation': 'Finding source engine is not supported for validation', 'The selected finding has no linked asset target': 'The selected finding has no linked asset target', 'Authorized scope is required': 'Authorized scope is required', 'Unable to load findings': 'Unable to load findings', 'Real validation requires finding data from the API. No local or demo data is used.': 'Real validation requires finding data from the API. No local or demo data is used.',
  },
}

const AR_TO_EN: Catalog = Object.fromEntries(Object.entries(CATALOGS.ar).map(([english, arabic]) => [arabic, english]))

interface LanguageState {
  language: Language
  translations: Catalog
  setLanguage: (language: Language) => Promise<void>
  t: (key: string, params?: Record<string, string | number>) => string
}

export const useLanguageStore = create<LanguageState>()(
  persist(
    (set, get) => ({
      language: 'ar',
      translations: CATALOGS.ar,
      setLanguage: async (language) => {
        set({ language, translations: CATALOGS[language] })
        document.documentElement.lang = language
        document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr'
      },
      t: (key, params) => {
        const value = get().translations[key] ?? key
        return params ? Object.entries(params).reduce((result, [name, replacement]) => result.replace(new RegExp(`{{${name}}}`, 'g'), String(replacement)), value) : value
      },
    }),
    { name: 'aegis-language', storage: createJSONStorage(() => localStorage), partialize: state => ({ language: state.language }) },
  ),
)

let translating = false
const translateRenderedText = (language: Language) => {
  if (translating) return
  translating = true
  try {
    const map = language === 'ar' ? CATALOGS.ar : AR_TO_EN
    const entries = Object.entries(map).filter(([from, to]) => from && to && from !== to).sort((a, b) => b[0].length - a[0].length)
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
    const nodes: Text[] = []
    let node: Node | null
    while ((node = walker.nextNode())) nodes.push(node as Text)
    for (const textNode of nodes) {
      const raw = textNode.nodeValue
      const parent = textNode.parentElement
      if (!raw || !parent || raw.trim().length === 0 || raw.trim().length > 500) continue
      if (parent.closest('script,style,noscript,textarea,input,code,pre')) continue
      let next = raw
      for (const [from, to] of entries) {
        if (next.includes(from)) next = next.split(from).join(to)
      }
      if (next !== raw) textNode.nodeValue = next
    }
  } finally {
    translating = false
  }
}

export const LanguageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const language = useLanguageStore(s => s.language)
  useEffect(() => {
    document.documentElement.lang = language
    document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr'
    const run = () => translateRenderedText(language)
    run()
    const observer = new MutationObserver(run)
    observer.observe(document.body, { subtree: true, childList: true, characterData: true })
    return () => observer.disconnect()
  }, [language])
  return children as React.ReactElement
}

export const initLanguage = async () => {
  const { language, setLanguage } = useLanguageStore.getState()
  await setLanguage(language)
}

export { CATALOGS }
