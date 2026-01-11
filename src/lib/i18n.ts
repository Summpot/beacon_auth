import {
  baseLocale,
  isLocale,
  type locales,
  setLocale,
} from '@/paraglide/runtime';

// Define type helper since runtime.js doesn't export the type directly in a way we can import as type easily without d.ts
export type AvailableLanguageTag = (typeof locales)[number];

export const LOCALE_COOKIE_NAME = 'beaconauth-locale';

export function getLocaleFromCookie(): AvailableLanguageTag | undefined {
  if (typeof document === 'undefined') return undefined;
  const match = document.cookie.match(
    new RegExp(`(^| )${LOCALE_COOKIE_NAME}=([^;]+)`),
  );
  const value = match ? match[2] : undefined;
  if (value && isAvailableLocale(value)) {
    return value;
  }
  return undefined;
}

export function setLocaleCookie(lang: AvailableLanguageTag) {
  if (typeof document === 'undefined') return;
  // Set cookie for 1 year
  document.cookie = `${LOCALE_COOKIE_NAME}=${lang}; path=/; max-age=31536000; SameSite=Lax`;
}

export function isAvailableLocale(lang: string): lang is AvailableLanguageTag {
  return isLocale(lang);
}

export function initializeI18n(preferredLocale?: string) {
  let locale: AvailableLanguageTag = baseLocale;

  // 1. Prefer explicitly passed locale (e.g. from URL param)
  if (preferredLocale && isAvailableLocale(preferredLocale)) {
    locale = preferredLocale;
  }
  // 2. Cookie
  else {
    const cookieLocale = getLocaleFromCookie();
    if (cookieLocale) {
      locale = cookieLocale;
    }
    // 3. Navigator (Browser)
    else if (typeof navigator !== 'undefined') {
      // simplified check for zh
      const navLang = navigator.language;
      if (navLang.startsWith('zh')) {
        if (isAvailableLocale('zh-CN')) locale = 'zh-CN';
      } else if (navLang.startsWith('en')) {
        if (isAvailableLocale('en')) locale = 'en';
      }
    }
  }

  setLocale(locale);

  // Update document attributes
  if (typeof document !== 'undefined') {
    document.documentElement.lang = locale;
    // Optionally set dir="rtl" if needed, but not for EN/ZH
    setLocaleCookie(locale);
  }
}
