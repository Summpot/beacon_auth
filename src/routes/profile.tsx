import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { z } from 'zod';
import { apiClient, queryKeys, type ApiError } from '../utils/api';
import * as m from '@/paraglide/messages';
import { BeaconIcon } from '@/components/beacon-icon';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardTitle,
  CardDescription,
} from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { ThemeToggle } from '@/components/theme-toggle';
import { LanguageToggle } from '@/components/language-toggle';
import {
  Settings,
  LogOut,
  Shield,
  Gamepad2,
  CheckCircle,
  Loader2,
} from 'lucide-react';

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
  const [statusMessage, setStatusMessage] = useState<{
    type: 'success' | 'error';
    text: string;
  } | null>(null);
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const {
    data: user,
    isLoading,
    error,
  } = useQuery<UserInfo, ApiError>({
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
      setStatusMessage({
        type: status,
        text: decodeURIComponent(message.replace(/\+/g, ' ')),
      });
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
      <div className="flex items-center justify-center min-h-screen p-4 bg-background">
        <Card className="border-0 shadow-lg">
          <CardContent className="pt-6">
            <div className="flex flex-col items-center gap-4">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="text-muted-foreground">
                {m.profile_loading()}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error && error.status !== 401) {
    return (
      <div className="flex items-center justify-center min-h-screen p-6 bg-background">
        <div className="w-full max-w-md">
          <Card className="text-center shadow-lg border-muted">
            <CardContent className="pt-10 pb-10">
              <div className="inline-block mb-6 p-4 rounded-full bg-red-50 text-red-500">
                <BeaconIcon className="w-12 h-12" />
              </div>
              <CardTitle className="text-2xl font-bold mb-4">
                {m.profile_error_title()}
              </CardTitle>
              <CardDescription className="mb-8">
                {error.message}
              </CardDescription>
              <div className="flex flex-col gap-3">
                <Button asChild size="lg" className="rounded-full">
                  <Link to="/">{m.profile_back_home()}</Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (!user) {
    return null; // Will redirect
  }

  return (
    <div className="min-h-screen bg-background pb-20">
      <nav className="sticky top-0 z-50 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3 group">
              <BeaconIcon className="w-8 h-8 text-primary" />
              <span className="text-xl text-primary font-bold">BeaconAuth</span>
            </Link>
            <div className="flex items-center gap-2">
              <Button variant="ghost" asChild className="hidden sm:inline-flex">
                <Link to="/settings">
                  <Settings className="h-4 w-4 mr-2" />
                  {m.profile_nav_settings()}
                </Link>
              </Button>
              <Link to="/settings" className="sm:hidden">
                <Button variant="ghost" size="icon">
                  <Settings className="h-5 w-5" />
                </Button>
              </Link>
              <ThemeToggle />
              <LanguageToggle />
              <Button
                variant="outline"
                size="sm"
                className="text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/20 border-red-200 dark:border-red-900/50"
                onClick={handleLogout}
                disabled={logoutMutation.isPending}
              >
                <LogOut className="h-4 w-4 mr-2" />
                <span className="hidden sm:inline">
                  {logoutMutation.isPending
                    ? m.profile_logging_out()
                    : m.profile_logout()}
                </span>
                <span className="sm:hidden">
                  {m.profile_logout().split(' ')[0]}
                </span>
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <div className="container max-w-5xl mx-auto px-4 md:px-6 pt-12">
        {statusMessage && (
          <Alert
            variant={
              statusMessage.type === 'success' ? 'default' : 'destructive'
            }
            className="mb-8 shadow-sm"
          >
            <AlertDescription className="flex items-center gap-3">
              <span className="text-xl">
                {statusMessage.type === 'success' ? '✓' : '✗'}
              </span>
              <p className="font-medium">{statusMessage.text}</p>
            </AlertDescription>
          </Alert>
        )}

        <div className="flex flex-col md:flex-row gap-8 mb-12 items-center md:items-start text-center md:text-left">
          <div className="relative group">
            <Avatar className="h-32 w-32 border-4 border-background shadow-xl">
              <AvatarFallback className="bg-primary text-5xl text-primary-foreground font-bold">
                {user.username.charAt(0).toUpperCase()}
              </AvatarFallback>
            </Avatar>
            <div
              className="absolute bottom-2 right-2 w-8 h-8 bg-green-500 rounded-full border-4 border-background flex items-center justify-center shadow-sm"
              title={m.profile_status_authenticated()}
            >
              <CheckCircle className="h-4 w-4 text-white" />
            </div>
          </div>
          <div className="flex-1 pt-4">
            <h1 className="text-4xl font-extrabold tracking-tight mb-2 text-foreground">
              {user.username}
            </h1>
            <div className="flex flex-wrap items-center justify-center md:justify-start gap-4 text-muted-foreground">
              <Badge
                variant="secondary"
                className="px-3 py-1 text-sm font-medium rounded-full bg-secondary text-secondary-foreground hover:bg-secondary/80"
              >
                {m.profile_user_role()}
              </Badge>
              <span className="flex items-center gap-2 text-sm font-mono bg-muted/50 px-3 py-1 rounded-full">
                ID: {user.id}
              </span>
            </div>
          </div>
          <Button
            asChild
            size="lg"
            className="rounded-full px-8 shadow-lg shadow-primary/10"
          >
            <Link to="/settings">{m.button_manage_settings()}</Link>
          </Button>
        </div>

        <div className="grid md:grid-cols-2 gap-6 mb-8">
          <Card className="border-0 shadow-md hover:shadow-lg transition-shadow bg-card">
            <CardContent className="p-8 flex items-start gap-5">
              <div className="w-12 h-12 rounded-2xl bg-green-100 dark:bg-green-900/30 flex items-center justify-center shrink-0 text-green-600 dark:text-green-400">
                <CheckCircle className="h-6 w-6" />
              </div>
              <div>
                <h3 className="font-semibold text-lg mb-1">
                  {m.profile_status()}
                </h3>
                <p className="text-muted-foreground mb-3 leading-relaxed">
                  {m.profile_status_verified_desc()}
                </p>
                <Badge
                  variant="outline"
                  className="text-green-600 border-green-200 bg-green-50 dark:bg-green-900/10 dark:text-green-400 dark:border-green-800"
                >
                  {m.profile_status_authenticated()}
                </Badge>
              </div>
            </CardContent>
          </Card>

          <Card className="border-0 shadow-md hover:shadow-lg transition-shadow bg-card">
            <CardContent className="p-8 flex items-start gap-5">
              <div className="w-12 h-12 rounded-2xl bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center shrink-0 text-purple-600 dark:text-purple-400">
                <Gamepad2 className="h-6 w-6" />
              </div>
              <div>
                <h3 className="font-semibold text-lg mb-1">
                  {m.profile_minecraft()}
                </h3>
                <p className="text-muted-foreground mb-3 leading-relaxed">
                  {m.profile_minecraft_connected_desc()}
                </p>
                <Badge
                  variant="outline"
                  className="text-purple-600 border-purple-200 bg-purple-50 dark:bg-purple-900/10 dark:text-purple-400 dark:border-purple-800"
                >
                  {m.profile_connected()}
                </Badge>
              </div>
            </CardContent>
          </Card>
        </div>

        <Alert className="bg-card border-border shadow-sm mb-12">
          <Shield className="h-5 w-5 text-primary" />
          <AlertDescription className="ml-2">
            <h3 className="font-semibold text-foreground mb-1">
              {m.profile_secure_session_title()}
            </h3>
            <p className="text-sm text-muted-foreground leading-relaxed">
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
