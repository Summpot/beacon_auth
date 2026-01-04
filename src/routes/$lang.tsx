import { createFileRoute, notFound } from '@tanstack/react-router';
import { HomePage } from './index';
import { isAvailableLocale, setLocaleCookie } from '@/lib/i18n';
import { setLanguageTag } from '@/paraglide/runtime';

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
        setLanguageTag(params.lang);
        setLocaleCookie(params.lang);
        
        // Update document lang
        if (typeof document !== 'undefined') {
            document.documentElement.lang = params.lang;
        }
    }
  },
  component: HomePage,
});
