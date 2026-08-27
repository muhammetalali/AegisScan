import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

type Language = 'ar' | 'en'

interface Translations {
  [key: string]: string | Translations
}

interface LanguageState {
  language: Language
  translations: Translations
  setLanguage: (language: Language) => Promise<void>
  t: (key: string, params?: Record<string, string | number>) => string
}

const translationsCache: Record<Language, Translations> = {
  ar: {},
  en: {},
}

export const useLanguageStore = create<LanguageState>()(
  persist(
    (set, get) => ({
      language: 'ar',
      translations: {},

      setLanguage: async (language) => {
        if (translationsCache[language] && Object.keys(translationsCache[language]).length > 0) {
          set({ language, translations: translationsCache[language] })
          document.documentElement.lang = language
          document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr'
          return
        }

        try {
          const response = await fetch(`/locales/${language}.json`)
          const translations = await response.json()
          translationsCache[language] = translations
          set({ language, translations })
          document.documentElement.lang = language
          document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr'
        } catch {
          // Fallback to hardcoded translations
          set({ language })
        }
      },

      t: (key, params) => {
        const { translations } = get()
        const keys = key.split('.')
        let value: any = translations

        for (const k of keys) {
          value = value?.[k]
          if (value === undefined) break
        }

        if (value === undefined) return key

        if (params) {
          return Object.entries(params).reduce(
            (str, [k, v]) => str.replace(new RegExp(`{{${k}}}`, 'g'), String(v)),
            value
          )
        }

        return value
      },
    }),
    {
      name: 'aegis-language',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({ language: state.language }),
    }
  )
)

import React from 'react'
export const LanguageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const language = useLanguageStore(s => s.language)
  React.useEffect(() => { document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr'; document.documentElement.lang = language }, [language])
  return children as React.ReactElement
}

// Initialize language on app load
export const initLanguage = async () => {
  const { language, setLanguage } = useLanguageStore.getState()
  await setLanguage(language)
}