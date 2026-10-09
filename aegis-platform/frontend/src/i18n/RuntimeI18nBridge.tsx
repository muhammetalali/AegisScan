import React, { useEffect } from 'react'
import { CATALOGS, useLanguageStore } from '@/stores/languageStore'
import { translateExact } from './translateExact'

type Language = 'ar' | 'en'
type Catalog = Record<string, string>

const EXTRA_AR: Catalog = {
    'System Monitoring': 'مراقبة النظام', 'Findings Center': 'مركز الثغرات',
    'Knowledge Center': 'مركز المعرفة', 'Compliance Intelligence': 'ذكاء الامتثال',
    'Correlated Evidence Graph': 'رسم بياني للأدلة المترابطة',
    'Enterprise Operational Workspace': 'مساحة العمليات المؤسسية',
    'Investigation Workspace': 'مساحة التحقيق', 'Asset registry': 'سجل الأصول',
    'Evidence registry': 'سجل الأدلة', 'Report center': 'مركز التقارير',
    'Finding source': 'مصدر الثغرة', 'Profile': 'الملف', 'Scope & safety': 'النطاق والأمان', 'Review': 'المراجعة',
    'Preserve the assessment criteria': 'استعادة معايير التقييم', 'Choose a real finding': 'اختر ثغرة حقيقية',
    'Search, sort, inspect evidence and launch finding-linked validation from real API data.': 'ابحث ورتّب وافحص الأدلة وابدأ التحقق المرتبط بالثغرة من بيانات API الحقيقية.',
    'Search, Sort, Tags, Status, Project, Asset, Engine': 'البحث والترتيب والوسوم والحالة والمشروع والأصل والمحرك',
    'All severity': 'كل مستويات الشدة', 'Any status': 'أي حالة', 'Sort: Severity': 'ترتيب: الشدة', 'Sort: Confidence': 'ترتيب: الثقة',
    'No findings': 'لا توجد ثغرات', 'Run a real scan or validation to populate the findings registry.': 'شغّل فحصًا أو تحققًا حقيقيًا لملء سجل الثغرات.',
    'Results are unavailable': 'النتائج غير متاحة', 'View execution': 'عرض التنفيذ', 'Retry': 'إعادة المحاولة',
    'The validation result could not be loaded from the API. No demo or fallback data is shown.': 'تعذر تحميل نتيجة التحقق من API. لا يتم عرض بيانات تجريبية أو بديلة.',
    'Not reported': 'غير مُبلغ عنه', 'Unavailable': 'غير متاح', 'Untitled finding': 'ثغرة بدون عنوان', 'Security finding': 'ثغرة أمنية',
    'Inspect': 'فحص', 'Engines executed': 'المحركات المنفذة', 'Validation status': 'حالة التحقق',
    'Prioritize remediation by impact rather than raw finding volume.': 'رتّب المعالجة حسب الأثر وليس حسب عدد الثغرات فقط.',
    'Assurance snapshot': 'لقطة الضمان', 'The vulnerabilities API returned an error. No local or demo fallback is used.': 'أعادت واجهة الثغرات خطأ. لا يتم استخدام بيانات محلية أو تجريبية بديلة.',
    'Execution contract is incomplete.': 'عقد التنفيذ غير مكتمل.', 'Creating job…': 'جارٍ إنشاء المهمة…',
    'Supported findings returned': 'ثغرات مدعومة مُعادة', 'supported findings returned': 'ثغرات مدعومة مُعادة',
    'Authoritative for this Finding': 'المحرك المعتمد لهذه الثغرة', 'Available assessment capability': 'قدرة متاحة ضمن التقييم',
    'I confirm this target is authorized for security validation.': 'أؤكد أن هذا الهدف مصرح به للتحقق الأمني.',
    'Include subdomains': 'تضمين النطاقات الفرعية', 'Title': 'العنوان', 'Severity': 'الشدة',
    'Confirmed': 'مؤكد', 'Required': 'مطلوب', 'Target type': 'نوع الهدف', 'Target': 'الهدف', 'Engine': 'المحرك',
    'Search findings, assets…': 'ابحث في الثغرات والأصول…', 'Search title, asset, category, tags, engine...': 'ابحث في العنوان أو الأصل أو الفئة أو الوسوم أو المحرك…',
    'Validation': 'التحقق', 'Actions': 'الإجراءات', 'View Evidence': 'عرض الأدلة', 'Assign': 'تعيين', 'Validate': 'تحقق', 'More': 'المزيد',
    'Create a real project in the current RBAC scope. No client-side project is synthesized.': 'أنشئ مشروعًا حقيقيًا ضمن نطاق RBAC الحالي. لا يتم إنشاء مشروع اصطناعي على الواجهة.',
}

const reverse = (catalog: Catalog) => Object.fromEntries(Object.entries(catalog).map(([key, value]) => [value, key])) as Catalog
const AR_CATALOG: Catalog = { ...CATALOGS.ar, ...EXTRA_AR }
const EN_CATALOG: Catalog = reverse(AR_CATALOG)

const translateDocument = (language: Language) => {
  // Reuse stable dictionaries and reverse the Arabic catalog on language switch.
  const map = language === 'ar' ? AR_CATALOG : EN_CATALOG
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
  const nodes: Text[] = []
  let node: Node | null
  while ((node = walker.nextNode())) nodes.push(node as Text)
  for (const textNode of nodes) {
    const parent = textNode.parentElement
    const raw = textNode.nodeValue
    if (!parent || !raw || !raw.trim() || raw.trim().length > 500) continue
    if (parent.closest('script,style,noscript,textarea,input,code,pre')) continue
    const next = translateExact(raw, map)
    if (next !== raw) textNode.nodeValue = next
  }
  const selector = 'input[placeholder], textarea[placeholder], [aria-label], [title]'
  document.querySelectorAll<HTMLElement>(selector).forEach((element) => {
    for (const attr of ['placeholder', 'aria-label', 'title']) {
      const raw = element.getAttribute(attr)
      if (!raw) continue
      const next = translateExact(raw, map)
      if (next !== raw) element.setAttribute(attr, next)
    }
  })
}

export const RuntimeI18nBridge: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const language = useLanguageStore((s) => s.language)
  useEffect(() => {
    let scheduled = false
    const run = () => {
      if (scheduled) return
      scheduled = true
      queueMicrotask(() => {
        scheduled = false
        translateDocument(language)
      })
    }
    run()
    const observer = new MutationObserver(run)
    observer.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ['placeholder', 'aria-label', 'title'] })
    return () => observer.disconnect()
  }, [language])
  return children as React.ReactElement
}
