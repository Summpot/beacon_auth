import { createFileRoute, Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import * as m from '@/paraglide/messages';
import { apiClient, queryKeys } from '../utils/api';
import { BeaconIcon } from '@/components/beacon-icon';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Github, KeyRound, Shield, Gamepad2 } from 'lucide-react';

interface UserInfo {
  id: string;
  username: string;
}

export function HomePage() {
  const { data: user } = useQuery({
    queryKey: queryKeys.userMe(),
    queryFn: async (): Promise<UserInfo | null> => {
      try {
        return await apiClient<UserInfo>('/api/v1/user/me', { requiresAuth: false });
      } catch {
        return null;
      }
    },
  });

  return (
    <div className="min-h-screen">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-background/80 backdrop-blur-md border-b border-border">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3 group">
              <BeaconIcon className="w-10 h-10" />
              <span className="text-2xl font-bold text-primary">{m.app_name()}</span>
            </Link>
            
            <div className="flex items-center gap-4">
              {user ? (
                <>
                  <Link to="/profile">
                    <Button variant="ghost">{user.username}</Button>
                  </Link>
                  <Link to="/settings">
                    <Button variant="ghost">{m.nav_settings()}</Button>
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
              >
                <Button variant="ghost" size="icon">
                  <Github className="h-5 w-5" />
                </Button>
              </a>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-1 h-[600px] bg-linear-to-b from-transparent via-primary/30 to-transparent blur-sm" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-32 h-[500px] bg-linear-to-b from-transparent via-primary/10 to-transparent blur-3xl" />
        
        <div className="container mx-auto px-6 text-center relative">
          <div className="inline-block mb-8">
            <div className="w-32 h-32 mx-auto relative">
              <BeaconIcon className="w-32 h-32" />
              <div className="absolute inset-0 bg-primary/20 rounded-full blur-2xl" />
            </div>
          </div>
          
          <h1 className="text-5xl md:text-7xl font-bold mb-6">
            <span className="text-foreground">{m.home_hero_title_1()}</span>
            <span className="text-primary">{m.home_hero_title_2()}</span>
          </h1>
          
          <p className="text-xl text-muted-foreground mb-10 max-w-2xl mx-auto leading-relaxed">
            {m.home_hero_subtitle({
              password: <span className="text-primary"> {m.home_hero_subtitle_password()}</span>,
              oauth: <span className="text-secondary-foreground"> {m.home_hero_subtitle_oauth()}</span>,
              passkey: <span className="text-muted-foreground"> {m.home_hero_subtitle_passkey()}</span>,
            })}
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            {user ? (
              <>
                <Link to="/profile">
                  <Button size="lg">{m.button_view_profile()}</Button>
                </Link>
                <Link to="/settings">
                  <Button variant="secondary" size="lg">{m.button_manage_settings()}</Button>
                </Link>
              </>
            ) : (
              <>
                <Link to="/login">
                  <Button size="lg">{m.button_login_now()}</Button>
                </Link>
                <Link to="/register">
                  <Button variant="secondary" size="lg">{m.button_create_account()}</Button>
                </Link>
              </>
            )}
          </div>

          {/* Quick stats */}
          <div className="mt-16 grid grid-cols-3 gap-8 max-w-lg mx-auto">
            <div className="text-center">
              <Badge variant="outline" className="text-lg px-3 py-1">{m.feature_signed_sessions_title()}</Badge>
              <div className="text-sm text-muted-foreground mt-2">{m.feature_signed_sessions_desc()}</div>
            </div>
            <div className="text-center">
              <Badge variant="outline" className="text-lg px-3 py-1">{m.feature_oauth_login_title()}</Badge>
              <div className="text-sm text-muted-foreground mt-2">{m.feature_oauth_login_desc()}</div>
            </div>
            <div className="text-center">
              <Badge variant="outline" className="text-lg px-3 py-1">{m.feature_passkeys_title()}</Badge>
              <div className="text-sm text-muted-foreground mt-2">{m.feature_passkeys_desc()}</div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 relative">
        <div className="container mx-auto px-6">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4">
              {m.why_beaconauth_title({ app_name: <span className="text-primary">{m.app_name()}</span> })}
            </h2>
            <p className="text-muted-foreground max-w-xl mx-auto">
              {m.why_beaconauth_desc()}
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6 max-w-5xl mx-auto">
            <Card className="hover:border-primary/50 transition-colors">
              <CardContent className="p-6">
                <div className="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center mb-4">
                  <KeyRound className="h-6 w-6 text-primary" />
                </div>
                <h3 className="text-xl font-bold text-foreground mb-2">{m.card_multi_auth_title()}</h3>
                <p className="text-muted-foreground text-sm">
                  {m.card_multi_auth_desc()}
                </p>
              </CardContent>
            </Card>

            <Card className="hover:border-primary/50 transition-colors">
              <CardContent className="p-6">
                <div className="w-12 h-12 rounded-xl bg-secondary/20 flex items-center justify-center mb-4">
                  <Shield className="h-6 w-6 text-secondary-foreground" />
                </div>
                <h3 className="text-xl font-bold text-foreground mb-2">{m.card_enterprise_security_title()}</h3>
                <p className="text-muted-foreground text-sm">
                  {m.card_enterprise_security_desc()}
                </p>
              </CardContent>
            </Card>

            <Card className="hover:border-primary/50 transition-colors">
              <CardContent className="p-6">
                <div className="w-12 h-12 rounded-xl bg-muted/50 flex items-center justify-center mb-4">
                  <Gamepad2 className="h-6 w-6 text-muted-foreground" />
                </div>
                <h3 className="text-xl font-bold text-foreground mb-2">{m.card_seamless_integration_title()}</h3>
                <p className="text-muted-foreground text-sm">
                  {m.card_seamless_integration_desc()}
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 relative">
        <div className="container mx-auto px-6 text-center">
          <Card className="border-primary/20 inline-block">
            <CardContent className="p-8">
              <h2 className="text-2xl md:text-3xl font-bold text-foreground mb-4">
                {m.cta_title()}
              </h2>
              <p className="text-muted-foreground mb-6">
                {m.cta_desc()}
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <a
                  href="https://github.com/Summpot/beacon_auth"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Button size="lg">
                    <Github className="mr-2 h-5 w-5" />
                    {m.button_view_github()}
                  </Button>
                </a>
                <Link to="/login">
                  <Button variant="secondary" size="lg">{m.button_try_demo()}</Button>
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 border-t border-border">
        <div className="container mx-auto px-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-muted-foreground">
              <BeaconIcon className="w-6 h-6 opacity-50" />
              <span className="text-sm">BeaconAuth © 2024</span>
            </div>
            <div className="flex items-center gap-6 text-sm text-muted-foreground">
              <span>{m.footer_open_source()}</span>
              <span>•</span>
              <span>{m.footer_license()}</span>
              <span>•</span>
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
