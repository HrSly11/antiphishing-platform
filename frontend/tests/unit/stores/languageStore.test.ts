import { beforeEach, describe, expect, it } from 'vitest';
import { translateText } from '../../../src/lib/i18n';
import { useLanguageStore } from '../../../src/stores/languageStore';

describe('languageStore & i18n translation engine', () => {
  beforeEach(() => {
    useLanguageStore.getState().setLang('es');
  });

  it('defaults to Spanish (es) and toggles cleanly between es and en', () => {
    expect(useLanguageStore.getState().lang).toBe('es');
    expect(useLanguageStore.getState().t('Tablero', 'Dashboard')).toBe('Tablero');

    useLanguageStore.getState().toggleLang();
    expect(useLanguageStore.getState().lang).toBe('en');
    expect(useLanguageStore.getState().t('Tablero', 'Dashboard')).toBe('Dashboard');

    useLanguageStore.getState().toggleLang();
    expect(useLanguageStore.getState().lang).toBe('es');
  });

  it('translates SOC interface labels into Spanish when lang is es and preserves English when en', () => {
    expect(translateText('Analytical Dashboard', 'es')).toBe('Dashboard Analítico');
    expect(translateText('Analytical Dashboard', 'en')).toBe('Analytical Dashboard');

    expect(translateText('Malicious Quarantined', 'es')).toBe('Maliciosos en Cuarentena');
    expect(translateText('Verify Cryptographic Chain', 'es')).toBe('Verificar Cadena Criptográfica');
    expect(translateText('15 perms', 'es')).toBe('15 permisos');
  });
});
