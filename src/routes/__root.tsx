import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createRootRoute,
  HeadContent,
  Outlet,
  useRouterState,
} from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { ThemeProvider } from '@/components/theme-provider';

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
      }),
  );

  const pathname = useRouterState({ select: (s) => s.location.pathname });

  // UseEffect for i18n initialization only, title is handled by router meta
  useEffect(() => {
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
            <HeadContent />
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

export const Route = createRootRoute({
  component: RootLayout,
  head: () => ({
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'BeaconAuth' },
    ],
  }),
});
