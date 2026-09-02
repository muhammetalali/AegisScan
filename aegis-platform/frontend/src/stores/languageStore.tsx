import React, { useEffect } from 'react'
import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

type Language = 'ar' | 'en'
type Catalog = Record<string, string>

const CATALOGS: Record<Language, Catalog> = {
  ar: {
    AegisScan: 'AegisScan', 'Security Validation': 'التحقق الأمني', Overview: 'نظرة عامة', Dashboard: 'لوحة التحكم', Workspace: 'مساحة العمل', Projects: 'المشاريع', Assets: 'الأصول',
    Validate: 'التحقق', 'New Validation': 'تحقق جديد', Validations: 'عمليات التحقق', Findings: 'الثغرات', Analyze: 'التحليل', Reports: 'التقارير', Compliance: 'الامتثال', 'Security Assurance': 'ضمان الأمن', 'Security Posture': 'الوضع الأمني', 'Digital Twin': 'التوأم الرقمي', Knowledge: 'المعرفة',
    Manage: 'الإدارة', 'Users & RBAC': 'المستخدمون والصلاحيات', 'Audit Trail': 'سجل التدقيق', Notifications: 'الإشعارات', System: 'النظام', Settings: 'الإعدادات', 'System Monitor': 'مراقبة النظام',
    Search: 'بحث', 'Search validations, findings, assets...': 'البحث في عمليات التحقق والثغرات والأصول...', 'View all': 'عرض الكل', Logout: 'تسجيل الخروج',
    'Create Validation Job': 'إنشاء مهمة تحقق', 'Real Validation': 'تحقق حقيقي', 'Security Validation Results': 'نتائج التحقق الأمني', 'Validation Command Center': 'مركز قيادة التحقق', 'Execution Timeline': 'الخط الزمني للتنفيذ', 'Export JSON': 'تصدير JSON', 'Risk Score': 'درجة المخاطر', Evidence: 'الأدلة',
    'Validation coverage': 'تغطية التحقق', 'Finding severity profile': 'توزيع شدة الثغرات', 'Risk intelligence': 'استخبارات المخاطر', 'Risk register': 'سجل المخاطر', 'Findings requiring attention': 'الثغرات التي تتطلب معالجة', 'No findings match this view': 'لا توجد ثغرات مطابقة لهذا العرض', 'Open Findings Center': 'فتح مركز الثغرات', 'Generate a formal report': 'إنشاء تقرير رسمي',
    Target: 'الهدف', Engine: 'المحرك', Status: 'الحالة', Confidence: 'الثقة', 'Engines executed': 'المحركات المنفذة', 'Validation status': 'حالة التحقق', Summary: 'الملخص', 'Healthy posture': 'وضع أمني جيد', 'Needs review': 'يحتاج إلى مراجعة', Complete: 'مكتمل',
    'Finding source': 'مصدر الثغرة', 'Execution contract': 'عقد التنفيذ', 'Choose a real finding': 'اختر Finding حقيقية', 'Create an evidence-linked validation': 'إنشاء تحقق مرتبط بدليل حقيقي', 'Choose a finding first': 'اختر ثغرة أولًا', Retry: 'إعادة المحاولة', Cancel: 'إلغاء', Back: 'رجوع', Continue: 'متابعة', 'Loading...': 'جارٍ التحميل...', 'Finding not found': 'الثغرة غير موجودة', 'Validation not found': 'عملية التحقق غير موجودة',
    'Target Configuration': 'إعداد الهدف', 'Authorization required': 'التفويض مطلوب', 'Authorized scope': 'النطاق المصرح به', Execution: 'التنفيذ', Authorization: 'التفويض', 'Waiting for engine…': 'بانتظار المحرك…', 'All engines completed — ready for Results': 'اكتملت كل المحركات — النتائج جاهزة',
    'New Security Validation': 'تحقق أمني جديد', 'What are we validating?': 'ماذا نتحقق منه؟', 'Authorization required before execution': 'التفويض مطلوب قبل التنفيذ',
  },
  en: {
    AegisScan: 'AegisScan', 'Security Validation': 'Security Validation', Overview: 'Overview', Dashboard: 'Dashboard', Workspace: 'Workspace', Projects: 'Projects', Assets: 'Assets', Validate: 'Validate', 'New Validation': 'New Validation', Validations: 'Validations', Findings: 'Findings', Analyze: 'Analyze', Reports: 'Reports', Compliance: 'Compliance', 'Security Assurance': 'Security Assurance', 'Security Posture': 'Security Posture', 'Digital Twin': 'Digital Twin', Knowledge: 'Knowledge', Manage: 'Manage', 'Users & RBAC': 'Users & RBAC', 'Audit Trail': 'Audit Trail', Notifications: 'Notifications', System: 'System', Settings: 'Settings', 'System Monitor': 'System Monitor', Search: 'Search', 'Search validations, findings, assets...': 'Search validations, findings, assets...', 'View all': 'View all', Logout: 'Logout', 'Create Validation Job': 'Create Validation Job', 'Real Validation': 'Real Validation', 'Security Validation Results': 'Security Validation Results', 'Validation Command Center': 'Validation Command Center', 'Execution Timeline': 'Execution Timeline', 'Export JSON': 'Export JSON', 'Risk Score': 'Risk Score', Evidence: 'Evidence', 'Validation coverage': 'Validation coverage', 'Finding severity profile': 'Finding severity profile', 'Risk intelligence': 'Risk intelligence', 'Risk register': 'Risk register', 'Findings requiring attention': 'Findings requiring attention', 'No findings match this view': 'No findings match this view', 'Open Findings Center': 'Open Findings Center', 'Generate a formal report': 'Generate a formal report', Target: 'Target', Engine: 'Engine', Status: 'Status', Confidence: 'Confidence', 'Engines executed': 'Engines executed', 'Validation status': 'Validation status', Summary: 'Summary', 'Healthy posture': 'Healthy posture', 'Needs review': 'Needs review', Complete: 'Complete', 'Finding source': 'Finding source', 'Execution contract': 'Execution contract', 'Choose a real finding': 'Choose a real finding', 'Create an evidence-linked validation': 'Create an evidence-linked validation', 'Choose a finding first': 'Choose a finding first', Retry: 'Retry', Cancel: 'Cancel', Back: 'Back', Continue: 'Continue', 'Loading...': 'Loading...', 'Finding not found': 'Finding not found', 'Validation not found': 'Validation not found', 'Target Configuration': 'Target Configuration', 'Authorization required': 'Authorization required', 'Authorized scope': 'Authorized scope', Execution: 'Execution', Authorization: 'Authorization', 'Waiting for engine…': 'Waiting for engine…', 'All engines completed — ready for Results': 'All engines completed — ready for Results', 'New Security Validation': 'New Security Validation', 'What are we validating?': 'What are we validating?', 'Authorization required before execution': 'Authorization required before execution',
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
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
    const nodes: Text[] = []
    let node: Node | null
    while ((node = walker.nextNode())) nodes.push(node as Text)
    for (const textNode of nodes) {
      const raw = textNode.nodeValue?.trim()
      const parent = textNode.parentElement
      if (!raw || raw.length > 180 || !parent) continue
      if (parent.closest('script,style,noscript,textarea,input,code,pre')) continue
      const translated = map[raw]
      if (translated && translated !== raw) textNode.nodeValue = textNode.nodeValue!.replace(raw, translated)
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
