import { describe, expect, it } from 'vitest';
import {
  CYRILLIC_HOMOGRAPH_DOMAIN,
  MAIL_SCENARIOS,
  SAMPLE_RAW_EML,
} from '../../../src/lib/mailScenarios';

describe('Banking MTA threat scenarios & RFC 822 EML fixture', () => {
  it('includes legitimate, homograph, BEC, prompt-injection, QR quishing, and double-extension scenarios', () => {
    expect(MAIL_SCENARIOS.length).toBeGreaterThanOrEqual(6);
    const ids = MAIL_SCENARIOS.map((s) => s.id);
    expect(ids).toContain('legit-treasury');
    expect(ids).toContain('phish-homograph');
    expect(ids).toContain('bec-wire-fraud');
    expect(ids).toContain('prompt-injection-evasion');
    expect(ids).toContain('qr-quishing-lure');
    expect(ids).toContain('dangerous-double-ext');
  });

  it('uses authentic Cyrillic U+043E homoglyph in the spoofing scenario', () => {
    expect(CYRILLIC_HOMOGRAPH_DOMAIN).toContain('\u043E');
    expect(CYRILLIC_HOMOGRAPH_DOMAIN).not.toBe('bancocentral.com');
  });

  it('provides a valid RFC 822 sample .eml payload for multipart/raw inspection', () => {
    expect(SAMPLE_RAW_EML).toContain('Authentication-Results:');
    expect(SAMPLE_RAW_EML).toContain('From: soporte@banc0central.com');
  });
});
