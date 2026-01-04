import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { z } from 'zod';
import { apiClient, queryKeys, type ApiError } from '../utils/api';
import * as m from '@/paraglide/messages';
import { BeaconIcon } from '@/components/beacon-icon';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardTitle, CardDescription } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { ThemeToggle } from '@/components/theme-toggle';
import { LanguageToggle } from '@/components/language-toggle';
import { Settings, LogOut, Shield, Gamepad2, Lock, CheckCircle, Loader2 } from 'lucide-react';

const searchParamsSchema = z.object({
  status: z.enum(['success', 'error']).optional(),
  message: z.string().optional(),
});

interface UserInfo {
  id: string;
  username: string;
}

async function fetchUserInfo(): Promise<UserInfo> {
  return apiClient<UserInfo>('/api/v1/user/me');
}

function ProfilePage() {
  const { status, message } = Route.useSearch();
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const { data: user, isLoading, error } = useQuery<UserInfo, ApiError>({
    queryKey: queryKeys.userMe(),
    queryFn: fetchUserInfo,
    retry: (failureCount, err) => {
      if (err?.status === 401) return false;
      return failureCount < 1;
    },
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      await apiClient('/api/v1/logout', { method: 'POST' });
    },
    onSuccess: () => {
      // Ensure we don't get stuck rendering a logged-out /profile state.
      queryClient.removeQueries({ queryKey: queryKeys.userMe() });
      navigate({ to: '/login', replace: true });
    },
  });

  useEffect(() => {
    if (status && message) {
      setStatusMessage({ type: status, text: decodeURIComponent(message.replace(/\+/g, ' ')) });
      const timer = setTimeout(() => setStatusMessage(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [status, message]);

  useEffect(() => {
    if (error?.status === 401) {
      navigate({ to: '/login', replace: true });
    }
  }, [error, navigate]);

  useEffect(() => {
    // If the cached user was cleared (e.g. after logout), redirect rather than rendering nothing.
    if (!isLoading && !error && !user) {
      navigate({ to: '/login', replace: true });
    }
  }, [error, isLoading, navigate, user]);

  const handleLogout = () => logoutMutation.mutate();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center gap-4">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="text-muted-foreground">{m.profile_loading()}</span>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error && error.status !== 401) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <div className="w-full max-w-md">
          <Card className="text-center">
            <CardContent className="pt-6">
              <div className="inline-block mb-6">
                <BeaconIcon className="w-20 h-20 opacity-50" />
              </div>
              <CardTitle className="text-2xl font-bold mb-4">{m.profile_error_title()}</CardTitle>
              <CardDescription className="mb-6">{error.message}</CardDescription>
              <div className="flex flex-col gap-3">
                <Button asChild><Link to="/">{m.profile_back_home()}</Link></Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <div className="w-full max-w-md">
          <Card className="text-center">
            <CardContent className="pt-6">
              <div className="inline-block mb-6">
                <BeaconIcon className="w-20 h-20 opacity-50" />
              </div>
              <CardTitle className="text-2xl font-bold mb-4">{m.profile_signed_out()}</CardTitle>
              <CardDescription className="mb-6">
                {m.profile_redirecting()}
              </CardDescription>
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-2">
              <Button variant="ghost" asChild>
                <Link to="/profile">{m.settings_nav_profile()}</Link>
              </Button>
              <ThemeToggle />
              <LanguageToggle />
            </div>
          </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-4">
      <nav className="fixed top-0 left-0 right-0 z-50 bg-background/80 backdrop-blur-md border-b border-border">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3 group">
              <BeaconIcon className="w-8 h-8" />
              <span className="text-xl text-primary font-bold">BeaconAuth</span>
            </Link>
            <div className="flex items-center gap-2">
              <Button variant="ghost" asChild>
                <Link to="/settings"><Settings className="h-4 w-4 mr-2" />{m.profile_nav_settings()}</Link>
              </Button>
              <Button variant="destructive" size="sm" onClick={handleLogout} disabled={logoutMutation.isPending}>
                <LogOut className="h-4 w-4 mr-2" />
                {logoutMutation.isPending ? m.profile_logging_out() : m.profile_logout()}
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto pt-24 pb-8">
        {statusMessage && (
          <Alert variant={statusMessage.type === 'success' ? 'default' : 'destructive'} className="mb-6">
            <AlertDescription className="flex items-center gap-3">
              <span className="text-xl">{statusMessage.type === 'success' ? '✓' : '✗'}</span>
              <p>{statusMessage.text}</p>
            </AlertDescription>
          </Alert>
        )}

        <Card className="mb-6">
          <CardContent className="pt-6">
            <div className="flex items-center gap-6">
              <div className="relative">
                <Avatar className="h-24 w-24 border-2 border-primary/30">
                  <AvatarFallback className="bg-linear-to-br from-primary/20 to-secondary/20 text-4xl text-primary">
                    {user.username.charAt(0).toUpperCase()}
                  </AvatarFallback>
                </Avatar>
                <div className="absolute -bottom-1 -right-1 w-6 h-6 bg-green-500 rounded-full border-2 border-background flex items-center justify-center">
                  <CheckCircle className="h-3 w-3 text-white" />
                </div>
              </div>
              <div className="flex-1">
                <h1 className="text-3xl font-bold mb-1">{user.username}</h1>
                <p className="text-muted-foreground">{m.profile_user_role()}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="grid md:grid-cols-3 gap-4 mb-6">
          <Card className="bg-card/50 border-border">
            <CardContent className="pt-6">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center">
                  <Lock className="h-6 w-6 text-primary" />
                </div>
                <div>
                  <p className="text-muted-foreground text-sm">{m.profile_account_id()}</p>
                  <p className="font-mono text-xs break-all">#{user.id}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card/50 border-border">
            <CardContent className="pt-6">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-green-500/20 flex items-center justify-center">
                  <CheckCircle className="h-6 w-6 text-green-500" />
                </div>
                <div>
                  <p className="text-muted-foreground text-sm">{m.profile_status()}</p>
                  <Badge variant="outline" className="text-green-500 border-green-500/30">{m.profile_status_authenticated()}</Badge>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card/50 border-border">
            <CardContent className="pt-6">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-secondary/20 flex items-center justify-center">
                  <Gamepad2 className="h-6 w-6 text-secondary-foreground" />
                </div>
                <div>
                  <p className="text-muted-foreground text-sm">{m.profile_minecraft()}</p>
                  <Badge variant="outline">{m.profile_connected()}</Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <Alert className="mt-6">
          <Shield className="h-4 w-4" />
          <AlertDescription>
            <h3 className="font-semibold mb-1">{m.profile_secure_session_title()}</h3>
            <p className="text-sm text-muted-foreground">
              {m.profile_secure_session_desc()}
            </p>
          </AlertDescription>
        </Alert>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/profile')({
  component: ProfilePage,
  validateSearch: searchParamsSchema,
});
