import { create } from 'zustand';

export type ThemeMode = 'dark' | 'light';

export const THEME_STORAGE_KEY = 'sentinelbank_soc_theme';

interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

const memoryFallback = new Map<string, string>();

function getSafeStorage(): StorageLike {
  try {
    if (
      typeof window !== 'undefined' &&
      window.localStorage &&
      typeof window.localStorage.getItem === 'function'
    ) {
      return window.localStorage;
    }
  } catch {
    // Fallback to in-memory map in non-browser test environments
  }
  return {
    getItem: (k: string) => memoryFallback.get(k) ?? null,
    setItem: (k: string, v: string) => {
      memoryFallback.set(k, v);
    },
  };
}

export function applyThemeToDom(theme: ThemeMode): void {
  if (typeof document !== 'undefined' && document.documentElement) {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }
}

function readInitialTheme(): ThemeMode {
  const saved = getSafeStorage().getItem(THEME_STORAGE_KEY);
  const resolved: ThemeMode = saved === 'light' ? 'light' : 'dark';
  applyThemeToDom(resolved);
  return resolved;
}

export interface ThemeState {
  theme: ThemeMode;
  setTheme: (theme: ThemeMode) => void;
  toggleTheme: () => void;
}

export const useThemeStore = create<ThemeState>((set, get) => ({
  theme: readInitialTheme(),
  setTheme: (theme: ThemeMode) => {
    getSafeStorage().setItem(THEME_STORAGE_KEY, theme);
    applyThemeToDom(theme);
    set({ theme });
  },
  toggleTheme: () => {
    const next: ThemeMode = get().theme === 'dark' ? 'light' : 'dark';
    getSafeStorage().setItem(THEME_STORAGE_KEY, next);
    applyThemeToDom(next);
    set({ theme: next });
  },
}));
