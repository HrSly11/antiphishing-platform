import { useEffect } from 'react';
import { translateText } from '../../lib/i18n';
import { useLanguageStore, type LanguageMode } from '../../stores/languageStore';

const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'CODE', 'PRE', 'TEXTAREA']);
const TRANSLATABLE_ATTRS = ['placeholder', 'title', 'aria-label'] as const;

const originalTextMap = new WeakMap<Text, string>();
const lastAppliedTextMap = new WeakMap<Text, string>();
const originalAttrMap = new WeakMap<Element, Map<string, string>>();
const lastAppliedAttrMap = new WeakMap<Element, Map<string, string>>();

function processTextNode(node: Text, lang: LanguageMode): void {
  const parent = node.parentElement;
  if (!parent || SKIP_TAGS.has(parent.tagName)) {
    return;
  }

  const currentVal = node.nodeValue ?? '';
  if (!currentVal.trim()) {
    return;
  }

  const lastApplied = lastAppliedTextMap.get(node);
  if (lastApplied === undefined || currentVal !== lastApplied) {
    originalTextMap.set(node, currentVal);
  }

  const sourceText = originalTextMap.get(node) ?? currentVal;
  const nextText = lang === 'es' ? translateText(sourceText, 'es') : sourceText;

  lastAppliedTextMap.set(node, nextText);
  if (node.nodeValue !== nextText) {
    node.nodeValue = nextText;
  }
}

function processElementAttrs(el: Element, lang: LanguageMode): void {
  if (SKIP_TAGS.has(el.tagName)) {
    return;
  }

  let origMap = originalAttrMap.get(el);
  if (!origMap) {
    origMap = new Map<string, string>();
    originalAttrMap.set(el, origMap);
  }

  let appliedMap = lastAppliedAttrMap.get(el);
  if (!appliedMap) {
    appliedMap = new Map<string, string>();
    lastAppliedAttrMap.set(el, appliedMap);
  }

  for (const attr of TRANSLATABLE_ATTRS) {
    const val = el.getAttribute(attr);
    if (!val || !val.trim()) {
      continue;
    }

    const lastApplied = appliedMap.get(attr);
    if (lastApplied === undefined || val !== lastApplied) {
      origMap.set(attr, val);
    }

    const sourceVal = origMap.get(attr) ?? val;
    const nextVal = lang === 'es' ? translateText(sourceVal, 'es') : sourceVal;

    appliedMap.set(attr, nextVal);
    if (val !== nextVal) {
      el.setAttribute(attr, nextVal);
    }
  }
}

export function applyDomTranslations(root: Node, lang: LanguageMode): void {
  if (typeof document === 'undefined') {
    return;
  }

  if (root.nodeType === Node.TEXT_NODE) {
    processTextNode(root as Text, lang);
    return;
  }

  if (root.nodeType === Node.ELEMENT_NODE) {
    processElementAttrs(root as Element, lang);
  }

  const walker = document.createTreeWalker(
    root,
    NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
  );

  let current: Node | null = walker.nextNode();
  while (current) {
    if (current.nodeType === Node.TEXT_NODE) {
      processTextNode(current as Text, lang);
    } else if (current.nodeType === Node.ELEMENT_NODE) {
      processElementAttrs(current as Element, lang);
    }
    current = walker.nextNode();
  }
}

export default function AutoI18nBridge() {
  const lang = useLanguageStore((s) => s.lang);

  useEffect(() => {
    if (typeof document === 'undefined' || !document.body) {
      return;
    }

    let isApplying = false;

    const runPass = (target: Node = document.body) => {
      if (isApplying) return;
      isApplying = true;
      try {
        applyDomTranslations(target, lang);
      } finally {
        isApplying = false;
      }
    };

    runPass(document.body);

    const observer = new MutationObserver((mutations) => {
      if (isApplying) return;
      isApplying = true;
      try {
        for (const m of mutations) {
          if (m.type === 'characterData') {
            applyDomTranslations(m.target, lang);
          } else if (m.type === 'attributes' && m.target.nodeType === Node.ELEMENT_NODE) {
            processElementAttrs(m.target as Element, lang);
          } else if (m.type === 'childList') {
            m.addedNodes.forEach((n) => applyDomTranslations(n, lang));
          }
        }
      } finally {
        isApplying = false;
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
      attributeFilter: [...TRANSLATABLE_ATTRS],
    });

    return () => {
      observer.disconnect();
    };
  }, [lang]);

  return null;
}
