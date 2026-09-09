import { Suspense, useEffect, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { PanelLeftOpen } from 'lucide-react';

import { MailAccountProvider } from '@/context/MailAccountContext';
import { TimeRangeProvider } from '@/context/TimeRangeContext';
import { Sidebar } from './Sidebar';
import { MobileTopbar, MobileDrawer } from './MobileNav';
import { PageTransition } from './PageTransition';
import { useSidebarChrome } from '@/hooks/useSidebarChrome';
import { cn } from '@/lib/utils';
import { LoadingState } from '@/components/common/states';

/*
  Routes that render edge-to-edge (no <main> padding, no vertical rhythm
  wrapper). The inbox is a two-pane workspace that owns its full content area
  and manages its own internal scrolling, so the shell must not pad it.

  This is deliberately a plain path list rather than a context flag: the shell
  needs to know the layout mode BEFORE the route renders (it decides the
  wrapper element), and a child-published flag would arrive a commit too late
  and cause a layout flash. Add a path here to opt a route into full-bleed.

  /settings was briefly on this list while it was a two-pane workspace. It is a
  normal single-column settings page again, so it wants the standard padded
  <main> and the page transition, like the dashboard.
*/
const FULL_BLEED_ROUTES = ['/inbox'];

const isFullBleed = (pathname) =>
  FULL_BLEED_ROUTES.some((p) => pathname === p || pathname.startsWith(`${p}/`));

export function AppShell() {
  const location = useLocation();
  const [navOpen, setNavOpen] = useState(false);
  const { width, collapsed, setWidth, toggleCollapsed } = useSidebarChrome();
  const fullBleed = isFullBleed(location.pathname);

  // Close the mobile drawer whenever the route changes.
  useEffect(() => {
    setNavOpen(false);
  }, [location.pathname]);

  return (
    <MailAccountProvider>
      <TimeRangeProvider>
        <div className={cn('flex bg-background', fullBleed ? 'h-dvh overflow-hidden' : 'min-h-screen')}>
          <Sidebar
            width={width}
            collapsed={collapsed}
            onCollapse={toggleCollapsed}
            onResize={setWidth}
          />

          {/* Când coloana e ascunsă, butonul de revenire stă în colţ, iar
              conţinutul primeşte un culoar de 44px ca nimic să nu ajungă
              dedesubtul lui. Doar pe desktop — pe mobil există deja drawer-ul. */}
          {/* Fades in after the column has finished sliding away, so the two
              movements read as one gesture instead of overlapping. */}
          <AnimatePresence>
            {collapsed && (
              <motion.button
                type="button"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.18, delay: 0.12 }}
                onClick={toggleCollapsed}
                aria-label="Show sidebar"
                title="Show sidebar"
                className="fixed left-2.5 top-2.5 z-50 hidden rounded-md border border-border bg-card p-1.5 text-muted-foreground outline-none transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/60 md:block"
              >
                <PanelLeftOpen className="h-4 w-4" />
              </motion.button>
            )}
          </AnimatePresence>

          {/* The padding shifts in step with the sidebar width so the content
              edge travels at the same rate as the column. */}
          <div
            className={cn(
              'flex min-w-0 flex-1 flex-col',
              'transition-[padding] duration-[var(--duration-base)] ease-[var(--ease-out)]',
              collapsed && 'md:pl-11'
            )}
          >
            <MobileTopbar onMenu={() => setNavOpen(true)} />
            {fullBleed ? (
              /* Edge-to-edge: no padding, no space-y wrapper, and no
                 PageTransition (its y-offset would fight a fixed-height pane).
                 The route owns the whole box and scrolls internally. */
              <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
                <Suspense fallback={<LoadingState />}><Outlet /></Suspense>
              </main>
            ) : (
              /* px-5 = the exact 20px mobile gutters; desktop spans full width. */
              <main className="flex min-w-0 flex-1 flex-col px-5 py-6 md:py-8">
                <div className="w-full space-y-6">
                  <AnimatePresence mode="wait" initial={false}>
                    <PageTransition key={location.pathname}>
                      <Suspense fallback={<LoadingState />}><Outlet /></Suspense>
                    </PageTransition>
                  </AnimatePresence>
                </div>
              </main>
            )}
          </div>
        </div>
        <MobileDrawer open={navOpen} onClose={() => setNavOpen(false)} />
      </TimeRangeProvider>
    </MailAccountProvider>
  );
}
