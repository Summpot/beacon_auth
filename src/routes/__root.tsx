/// <reference types="vite/client" />
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createRootRoute,
  HeadContent,
  Outlet,
  Scripts,
  useRouterState,
} from '@tanstack/react-router';
import { type ReactNode, useState } from 'react';
import { ThemeProvider } from '@/components/theme-provider';
import { AnimatePresence, MotionConfig, motion } from '@/lib/motion';
import { getLocale } from '@/paraglide/runtime';
import appCss from '../styles.css?url';

function RootComponent() {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 60 * 1000, // 1 minute
            retry: 1,
            refetchOnWindowFocus: false,
          },
        },
      }),
  );

  const pathname = useRouterState({ select: (s) => s.location.pathname });

  return (
    <RootDocument>
      <ThemeProvider defaultTheme="system" storageKey="beaconauth-ui-theme">
        <QueryClientProvider client={queryClient}>
          <MotionConfig reducedMotion="user">
            <div className="min-h-screen bg-background text-foreground relative">
              <AnimatePresence mode="wait" initial={false}>
                <motion.div
                  // Keyed by pathname so route changes animate.
                  key={pathname}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                  transition={{ duration: 0.18, ease: 'easeOut' }}
                >
                  <Outlet />
                </motion.div>
              </AnimatePresence>
            </div>
          </MotionConfig>
        </QueryClientProvider>
      </ThemeProvider>
    </RootDocument>
  );
}

function RootDocument({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang={getLocale()}>
      <head>
        <HeadContent />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  );
}

export const Route = createRootRoute({
  component: RootComponent,
  head: () => ({
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'BeaconAuth' },
    ],
    links: [{ rel: 'stylesheet', href: appCss }],
  }),
});
