import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

type Theme = 'light' | 'dark' | 'system'

interface ThemeState {
  theme: Theme
  resolvedTheme: 'light' | 'dark'
  setTheme: (theme: Theme) => void
  toggleTheme: () => void
  initTheme: () => void
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set, get) => ({
      theme: 'dark',
      resolvedTheme: 'dark',

      setTheme: (theme) => {
        set({ theme })
        get().initTheme()
      },

      toggleTheme: () => {
        const { theme } = get()
        const newTheme = theme === 'dark' ? 'light' : 'dark'
        get().setTheme(newTheme)
      },

      initTheme: () => {
        const { theme } = get()
        const root = document.documentElement

        let resolved: 'light' | 'dark'
        if (theme === 'system') {
          resolved = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
        } else {
          resolved = theme
        }

        root.classList.remove('light', 'dark')
        root.classList.add(resolved)
        set({ resolvedTheme: resolved })
      },
    }),
    {
      name: 'aegis-theme',
      storage: createJSONStorage(() => localStorage),
    }
  )
)

import React from 'react'
export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const initTheme = useThemeStore(s => s.initTheme)
  React.useEffect(() => { initTheme() }, [initTheme])
  return children as React.ReactElement
}

// Listen for system theme changes
if (typeof window !== 'undefined') {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    const { theme, initTheme } = useThemeStore.getState()
    if (theme === 'system') {
      initTheme()
    }
  })
}