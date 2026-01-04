import { createFileRoute, Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import * as m from '@/paraglide/messages';
import { apiClient, queryKeys } from '../utils/api';
import { BeaconIcon } from '@/components/beacon-icon';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Github, KeyRound, Shield, Gamepad2 } from 'lucide-react';
import { ThemeToggle } from '@/components/theme-toggle';
import { LanguageToggle } from '@/components/language-toggle';

interface UserInfo {
  id: string;
  username: string;
}

export function HomePage() {
  const { data: user } = useQuery({
    queryKey: queryKeys.userMe(),
    queryFn: async (): Promise<UserInfo | null> => {
      try {
        return await apiClient<UserInfo>('/api/v1/user/me', {
          requiresAuth: false,
        });
      } catch {
        return null;
      }
    },
  });

  return (
    <div className="min-h-screen bg-background text-foreground selection:bg-primary/20">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-background/80 backdrop-blur-md border-b border-border">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3 group">
              <BeaconIcon className="w-8 h-8 text-primary transition-transform group-hover:scale-110" />
              <span className="text-xl font-bold tracking-tight">
                {m.app_name()}
              </span>
            </Link>

            <div className="flex items-center gap-4">
              {user ? (
                <>
                  <Link to="/profile">
                    <Button variant="ghost">{user.username}</Button>
                  </Link>
                  <Link to="/settings">
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label={m.nav_settings()}
                    >
                      <ThemeToggle />
                    </Button>
                  </Link>
                </>
              ) : (
                <>
                  <Link to="/login">
                    <Button variant="ghost">{m.nav_login()}</Button>
                  </Link>
                  <Link to="/register">
                    <Button>{m.nav_get_started()}</Button>
                  </Link>
                </>
              )}
              <a
                href="https://github.com/Summpot/beacon_auth"
                target="_blank"
                rel="noopener noreferrer"
                className="hidden md:block"
              >
                <Button variant="ghost" size="icon">
                  <Github className="h-5 w-5" />
                </Button>
              </a>
              <ThemeToggle />
              <LanguageToggle />
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-24 md:pt-48 md:pb-32 overflow-hidden">
        <div className="container mx-auto px-6 relative z-10 text-center">
          <div className="inline-flex items-center justify-center p-2 mb-8 rounded-full bg-secondary/50 border border-border backdrop-blur-sm">
            <span className="px-3 py-1 text-xs font-semibold uppercase tracking-wide text-primary bg-primary/10 rounded-full mr-2">
              New
            </span>
            <span className="text-sm text-muted-foreground mr-2">
              {m.feature_passkeys_desc()}
            </span>
          </div>

          <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight mb-8 text-balance">
            {m.home_hero_title_1()}
            <span className="text-transparent bg-clip-text bg-linear-to-r from-primary to-purple-600">
              {m.home_hero_title_2()}
            </span>
          </h1>

          <p className="text-xl md:text-2xl text-muted-foreground mb-12 max-w-3xl mx-auto leading-relaxed text-balance">
            {m.home_hero_subtitle()}
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
            {user ? (
              <>
                <Link to="/profile">
                  <Button
                    size="lg"
                    className="h-12 px-8 text-lg rounded-full shadow-lg shadow-primary/20 hover:shadow-primary/30 transition-all"
                  >
                    {m.button_view_profile()}
                  </Button>
                </Link>
                <Link to="/settings">
                  <Button
                    variant="outline"
                    size="lg"
                    className="h-12 px-8 text-lg rounded-full"
                  >
                    {m.button_manage_settings()}
                  </Button>
                </Link>
              </>
            ) : (
              <>
                <Link to="/login">
                  <Button
                    size="lg"
                    className="h-12 px-8 text-lg rounded-full shadow-lg shadow-primary/20 hover:shadow-primary/30 transition-all"
                  >
                    {m.button_login_now()}
                  </Button>
                </Link>
                <Link to="/register">
                  <Button
                    variant="outline"
                    size="lg"
                    className="h-12 px-8 text-lg rounded-full"
                  >
                    {m.button_create_account()}
                  </Button>
                </Link>
              </>
            )}
          </div>
        </div>

        {/* Abstract Background Elements */}
        <div className="absolute top-0 left-0 w-full h-full overflow-hidden -z-10 pointer-events-none">
          <div className="absolute top-[-10%] right-[-5%] w-[500px] h-[500px] bg-primary/5 rounded-full blur-3xl opacity-50" />
          <div className="absolute bottom-[-10%] left-[-10%] w-[600px] h-[600px] bg-purple-500/5 rounded-full blur-3xl opacity-50" />
        </div>
      </section>

      {/* Features Section */}
      <section className="py-24 bg-secondary/30">
        <div className="container mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4 tracking-tight">
              {m.why_beaconauth_title()}
            </h2>
            <p className="text-muted-foreground max-w-2xl mx-auto text-lg text-balance">
              {m.why_beaconauth_desc()}
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <Card className="border-0 shadow-none bg-background/50 hover:bg-background transition-colors duration-300">
              <CardContent className="p-8">
                <div className="w-14 h-14 rounded-2xl bg-primary/10 flex items-center justify-center mb-6 text-primary">
                  <KeyRound className="h-7 w-7" />
                </div>
                <h3 className="text-xl font-bold mb-3">
                  {m.card_multi_auth_title()}
                </h3>
                <p className="text-muted-foreground leading-relaxed">
                  {m.card_multi_auth_desc()}
                </p>
              </CardContent>
            </Card>

            <Card className="border-0 shadow-none bg-background/50 hover:bg-background transition-colors duration-300">
              <CardContent className="p-8">
                <div className="w-14 h-14 rounded-2xl bg-blue-500/10 flex items-center justify-center mb-6 text-blue-500">
                  <Shield className="h-7 w-7" />
                </div>
                <h3 className="text-xl font-bold mb-3">
                  {m.card_enterprise_security_title()}
                </h3>
                <p className="text-muted-foreground leading-relaxed">
                  {m.card_enterprise_security_desc()}
                </p>
              </CardContent>
            </Card>

            <Card className="border-0 shadow-none bg-background/50 hover:bg-background transition-colors duration-300">
              <CardContent className="p-8">
                <div className="w-14 h-14 rounded-2xl bg-green-500/10 flex items-center justify-center mb-6 text-green-500">
                  <Gamepad2 className="h-7 w-7" />
                </div>
                <h3 className="text-xl font-bold mb-3">
                  {m.card_seamless_integration_title()}
                </h3>
                <p className="text-muted-foreground leading-relaxed">
                  {m.card_seamless_integration_desc()}
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24 relative overflow-hidden">
        <div className="container mx-auto px-6">
          <div className="bg-primary text-primary-foreground rounded-3xl p-12 md:p-20 text-center relative overflow-hidden">
            {/* Decorative circles */}
            <div className="absolute top-0 right-0 -mt-20 -mr-20 w-96 h-96 bg-white/10 rounded-full blur-3xl opacity-50" />
            <div className="absolute bottom-0 left-0 -mb-20 -ml-20 w-80 h-80 bg-white/10 rounded-full blur-3xl opacity-50" />

            <div className="relative z-10 max-w-3xl mx-auto">
              <h2 className="text-3xl md:text-5xl font-bold mb-6 tracking-tight">
                {m.cta_title()}
              </h2>
              <p className="text-primary-foreground/80 text-lg md:text-xl mb-10 max-w-2xl mx-auto">
                {m.cta_desc()}
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <a
                  href="https://github.com/Summpot/beacon_auth"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Button
                    size="lg"
                    variant="secondary"
                    className="h-12 px-8 text-primary font-semibold rounded-full"
                  >
                    <Github className="mr-2 h-5 w-5" />
                    {m.button_view_github()}
                  </Button>
                </a>
                <Link to="/login">
                  <Button
                    size="lg"
                    className="h-12 px-8 bg-white/20 hover:bg-white/30 text-white border-0 rounded-full backdrop-blur-sm"
                  >
                    {m.button_try_demo()}
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-border bg-background">
        <div className="container mx-auto px-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <BeaconIcon className="w-8 h-8 text-muted-foreground" />
              <div className="flex flex-col">
                <span className="font-semibold text-foreground">
                  BeaconAuth
                </span>
                <span className="text-xs text-muted-foreground">
                  © 2026 Summpot
                </span>
              </div>
            </div>
            <div className="flex items-center gap-8 text-sm text-muted-foreground font-medium">
              <span>{m.footer_open_source()}</span>
              <span>{m.footer_license()}</span>
              <a
                href="https://github.com/Summpot/beacon_auth"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-primary transition-colors"
              >
                {m.footer_contribute()}
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export const Route = createFileRoute('/')({
  component: HomePage,
});
