import { createRootRoute, Outlet, useRouterState } from '@tanstack/react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { ThemeProvider } from '@/components/theme-provider';

import { ThemeToggle } from '@/components/theme-toggle';
import { LanguageToggle } from '@/components/language-toggle';
import { AnimatePresence, MotionConfig, motion } from '@/lib/motion';

const RootLayout = () => {
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
      })
  );

  const pathname = useRouterState({ select: (s) => s.location.pathname });

  useEffect(() => {
    document.title = 'BeaconAuth';
    // Initialize i18n from cookie/navigator on mount
    import('@/lib/i18n').then(({ initializeI18n }) => {
       initializeI18n();
    });
  }, []);

  return (
    <ThemeProvider defaultTheme="system" storageKey="beaconauth-ui-theme">
      <QueryClientProvider client={queryClient}>
        <MotionConfig reducedMotion="user">
          <div className="min-h-screen bg-background text-foreground relative">
            {/* Toggles (Theme & Language) - Floating on non-home pages */}
            {!['/', '/en', '/zh-CN'].includes(pathname) && (
              <div className="fixed top-4 right-4 z-50 flex gap-2">
                <ThemeToggle />
                <LanguageToggle />
              </div>
            )}

            {/* Theme toggle in top right corner */}


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
  );
};

export const Route = createRootRoute({ component: RootLayout });
