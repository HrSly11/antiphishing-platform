import { describe, expect, it } from 'vitest';
import { applyThemeToDom, useThemeStore } from '../../../src/stores/themeStore';

describe('themeStore Dark SOC & Light Executive persistence', () => {
  it('toggles between dark and light modes cleanly', () => {
    useThemeStore.getState().setTheme('dark');
    expect(useThemeStore.getState().theme).toBe('dark');

    useThemeStore.getState().toggleTheme();
    expect(useThemeStore.getState().theme).toBe('light');

    useThemeStore.getState().toggleTheme();
    expect(useThemeStore.getState().theme).toBe('dark');
  });

  it('applies and removes dark class on documentElement when DOM is present', () => {
    const classSet = new Set<string>();
    const prevDoc = (globalThis as { document?: unknown }).document;
    (globalThis as { document?: unknown }).document = {
      documentElement: {
        classList: {
          add: (c: string) => classSet.add(c),
          remove: (c: string) => classSet.delete(c),
        },
      },
    };

    try {
      applyThemeToDom('dark');
      expect(classSet.has('dark')).toBe(true);
      applyThemeToDom('light');
      expect(classSet.has('dark')).toBe(false);
    } finally {
      (globalThis as { document?: unknown }).document = prevDoc;
    }
  });
});
