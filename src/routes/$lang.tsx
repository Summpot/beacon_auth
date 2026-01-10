import { createFileRoute, notFound } from '@tanstack/react-router';
import { isAvailableLocale, setLocaleCookie } from '@/lib/i18n';
import { setLocale } from '@/paraglide/runtime';
import { HomePage } from './index';

export const Route = createFileRoute('/$lang')({
  beforeLoad: ({ params }) => {
    if (!isAvailableLocale(params.lang)) {
      // If not a valid locale, we treat it as 404 for this route
      // The router might fall through if configured, but here it captures /$lang
      throw notFound();
    }
  },
  loader: ({ params }) => {
    if (isAvailableLocale(params.lang)) {
      setLocale(params.lang);
      setLocaleCookie(params.lang);

      // Update document lang
      if (typeof document !== 'undefined') {
        document.documentElement.lang = params.lang;
      }
    }
  },
  component: HomePage,
});
