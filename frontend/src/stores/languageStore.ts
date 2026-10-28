import { create } from 'zustand';

export type LanguageMode = 'es' | 'en';

export const LANGUAGE_STORAGE_KEY = 'sentinelbank_soc_language';

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

export function applyLanguageToDom(lang: LanguageMode): void {
  if (typeof document !== 'undefined' && document.documentElement) {
    document.documentElement.lang = lang;
    document.documentElement.setAttribute('data-lang', lang);
  }
}

function readInitialLanguage(): LanguageMode {
  const saved = getSafeStorage().getItem(LANGUAGE_STORAGE_KEY);
  const resolved: LanguageMode = saved === 'en' ? 'en' : 'es';
  applyLanguageToDom(resolved);
  return resolved;
}

export interface LanguageState {
  lang: LanguageMode;
  setLang: (lang: LanguageMode) => void;
  toggleLang: () => void;
  t: (es: string, en: string) => string;
}

export const useLanguageStore = create<LanguageState>((set, get) => ({
  lang: readInitialLanguage(),
  setLang: (lang: LanguageMode) => {
    getSafeStorage().setItem(LANGUAGE_STORAGE_KEY, lang);
    applyLanguageToDom(lang);
    set({ lang });
  },
  toggleLang: () => {
    const next: LanguageMode = get().lang === 'es' ? 'en' : 'es';
    getSafeStorage().setItem(LANGUAGE_STORAGE_KEY, next);
    applyLanguageToDom(next);
    set({ lang: next });
  },
  t: (es: string, en: string) => (get().lang === 'es' ? es : en),
}));
