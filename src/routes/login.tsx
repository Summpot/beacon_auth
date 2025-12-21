import { zodResolver } from '@hookform/resolvers/zod';
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import { useCallback, useEffect, useState, useRef } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { ApiError, apiClient } from '../utils/api';
import { BeaconIcon } from '@/components/beacon-icon';
import { MinecraftFlowAlert } from '@/components/minecraft/minecraft-flow-alert';
import {
  startAuthentication,
  browserSupportsWebAuthnAutofill,
  WebAuthnError,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { KeyRound, ChevronLeft, Loader2 } from 'lucide-react';

const searchParamsSchema = z.object({
  challenge: z.string().min(1).optional(),
  redirect_port: z.coerce.number().min(1).max(65535).optional(),
});

type SearchParams = z.infer<typeof searchParamsSchema>;

const loginFormSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
});

type LoginFormData = z.infer<typeof loginFormSchema>;

interface ServerConfig {
  database_auth: boolean;
  github_oauth: boolean;
  google_oauth: boolean;
}

const getErrorMessage = (error: unknown, fallback: string) => {
  if (error instanceof ApiError) {
    const data = error.data as { message?: string } | undefined;
    return data?.message ?? error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return fallback;
};

function LoginPage() {
  const searchParams = Route.useSearch();
  const navigate = useNavigate();
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [passkeyError, setPasskeyError] = useState<string>('');
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const conditionalUIStarted = useRef(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError,
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginFormSchema),
  });

  useEffect(() => {
    const initialize = async () => {
      try {
        const configData = await apiClient<ServerConfig>('/api/v1/config', { requiresAuth: false });
        setConfig(configData);
      } catch (error) {
        console.error('Failed to load server config:', error);
      }

      if (searchParams.challenge && searchParams.redirect_port) {
        try {
          const result = await apiClient<{ redirectUrl?: string }>('/api/v1/minecraft-jwt', {
            method: 'POST',
            body: {
              challenge: searchParams.challenge,
              redirect_port: searchParams.redirect_port,
              profile_url: window.location.origin + '/profile',
            },
          });
          if (result.redirectUrl) {
            window.location.href = result.redirectUrl;
            return;
          }
        } catch (error) {
          console.log('Auto-login failed, showing login form', error);
        }
      }
      setConfigLoading(false);
    };
    initialize();
  }, [searchParams.challenge, searchParams.redirect_port]);

  const completePasskeyAuth = useCallback(async (credential: unknown) => {
    await apiClient('/api/v1/passkey/auth/finish', { method: 'POST', requiresAuth: false, body: { credential } });

    if (searchParams.challenge && searchParams.redirect_port) {
      const result = await apiClient<{ redirectUrl?: string }>('/api/v1/minecraft-jwt', {
        method: 'POST',
        body: {
          challenge: searchParams.challenge,
          redirect_port: searchParams.redirect_port,
          profile_url: window.location.origin + '/profile',
        },
      });
      if (result.redirectUrl) {
        window.location.href = result.redirectUrl;
        return;
      }
    } else {
      navigate({ to: '/profile' });
    }
  }, [navigate, searchParams.challenge, searchParams.redirect_port]);

  useEffect(() => {
    const initConditionalUI = async () => {
      if (conditionalUIStarted.current) return;
      if (!browserSupportsWebAuthnAutofill()) return;

      try {
        conditionalUIStarted.current = true;
        const optionsJSON = await apiClient<{ request_options: { publicKey: PublicKeyCredentialRequestOptionsJSON } }>(
          '/api/v1/passkey/auth/start', { method: 'POST', requiresAuth: false, body: {} }
        );
        const credential = await startAuthentication({ optionsJSON: optionsJSON.request_options.publicKey, useBrowserAutofill: true });
        await completePasskeyAuth(credential);
      } catch (err) {
        if (err instanceof WebAuthnError && err.code === 'ERROR_CEREMONY_ABORTED') return;
        console.error('Conditional UI error:', err);
      }
    };
    if (!configLoading) initConditionalUI();
  }, [configLoading, completePasskeyAuth]);

  const tryAutoRegisterPasskey = async () => {
    try {
      const optionsJSON = await apiClient<{ creation_options: { publicKey: PublicKeyCredentialCreationOptionsJSON } }>(
        '/api/v1/passkey/register/start', { method: 'POST', body: { name: 'Auto-registered Passkey' } }
      );
      const { startRegistration } = await import('@simplewebauthn/browser');
      const credential = await startRegistration({ optionsJSON: optionsJSON.creation_options.publicKey, useAutoRegister: true });
      await apiClient('/api/v1/passkey/register/finish', { method: 'POST', body: { credential, name: 'Auto-registered Passkey' } });
    } catch (err) {
      console.log('Auto-register passkey failed (expected):', err);
    }
  };

  const onSubmit = async (data: LoginFormData) => {
    try {
      await apiClient('/api/v1/login', { method: 'POST', requiresAuth: false, body: { username: data.username, password: data.password } });
      tryAutoRegisterPasskey().catch(() => {});

      if (searchParams.challenge && searchParams.redirect_port) {
        const result = await apiClient<{ redirectUrl?: string }>('/api/v1/minecraft-jwt', {
          method: 'POST',
          body: { challenge: searchParams.challenge, redirect_port: searchParams.redirect_port, profile_url: window.location.origin + '/profile' },
        });
        if (result.redirectUrl) window.location.href = result.redirectUrl;
      } else {
        navigate({ to: '/profile' });
      }
    } catch (error) {
      setError('root', { type: 'manual', message: getErrorMessage(error, 'Failed to connect to server') });
    }
  };

  const handlePasskeyLogin = async () => {
    setPasskeyError('');
    setPasskeyLoading(true);
    try {
      const optionsJSON = await apiClient<{ request_options: { publicKey: PublicKeyCredentialRequestOptionsJSON } }>(
        '/api/v1/passkey/auth/start', { method: 'POST', requiresAuth: false, body: {} }
      );
      const credential = await startAuthentication({ optionsJSON: optionsJSON.request_options.publicKey });
      await completePasskeyAuth(credential);
    } catch (err) {
      if (err instanceof WebAuthnError) {
        setPasskeyError(err.code === 'ERROR_CEREMONY_ABORTED' ? 'Passkey authentication was cancelled' : `Passkey error: ${err.message}`);
      } else if (err instanceof Error) {
        setPasskeyError(err.message);
      } else {
        setPasskeyError('An unknown error occurred');
      }
    } finally {
      setPasskeyLoading(false);
    }
  };

  const handleOAuthLogin = async (provider: 'github' | 'google') => {
    try {
      if (searchParams.challenge && searchParams.redirect_port) {
        sessionStorage.setItem('minecraft_challenge', searchParams.challenge);
        sessionStorage.setItem('minecraft_redirect_port', searchParams.redirect_port.toString());
      } else {
        sessionStorage.removeItem('minecraft_challenge');
        sessionStorage.removeItem('minecraft_redirect_port');
      }
      const result = await apiClient<{ authorizationUrl?: string }>('/api/v1/oauth/start', {
        method: 'POST', requiresAuth: false,
        body: { provider, challenge: searchParams.challenge || '', redirect_port: searchParams.redirect_port || 0 },
      });
      if (result.authorizationUrl) window.location.href = result.authorizationUrl;
    } catch (error) {
      console.error(`${provider} login failed:`, error);
    }
  };

  if (configLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center gap-4">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="text-muted-foreground">Loading...</span>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen p-4">
      <div className="w-full max-w-md">
        <Link to="/" className="inline-flex items-center gap-2 text-muted-foreground hover:text-primary transition-colors mb-6">
          <ChevronLeft className="h-4 w-4" />
          Back to Home
        </Link>

        <Card>
          <CardHeader className="text-center pb-4">
            <div className="flex justify-center mb-4">
              <BeaconIcon className="w-16 h-16" />
            </div>
            <CardTitle className="text-3xl font-bold">Welcome Back</CardTitle>
            <CardDescription>Sign in to your BeaconAuth account</CardDescription>
          </CardHeader>

          <CardContent className="space-y-6">
            {searchParams.challenge && searchParams.redirect_port && (
              <MinecraftFlowAlert
                title="Minecraft Login"
                challenge={searchParams.challenge}
                redirectPort={searchParams.redirect_port}
              />
            )}

            {config?.database_auth && (
              <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input id="username" type="text" {...register('username')} placeholder="Enter your username" disabled={isSubmitting} autoComplete="username webauthn" className="bg-background/50 border-input" />
                  {errors.username && <p className="text-sm text-destructive">{errors.username.message}</p>}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <Input id="password" type="password" {...register('password')} placeholder="Enter your password" disabled={isSubmitting} className="bg-background/50 border-input" />
                  {errors.password && <p className="text-sm text-destructive">{errors.password.message}</p>}
                </div>
                {errors.root && <Alert variant="destructive"><AlertDescription>{errors.root.message}</AlertDescription></Alert>}
                <Button type="submit" disabled={isSubmitting} className="w-full">
                  {isSubmitting ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Authenticating...</> : 'Sign In'}
                </Button>
              </form>
            )}

            <div>
              {config?.database_auth && (
                <div className="relative my-4">
                  <div className="absolute inset-0 flex items-center"><Separator className="w-full" /></div>
                  <div className="relative flex justify-center text-xs uppercase"><span className="bg-card px-2 text-muted-foreground">or use</span></div>
                </div>
              )}
              <Button type="button" variant="secondary" onClick={handlePasskeyLogin} disabled={passkeyLoading} className="w-full">
                <KeyRound className="mr-2 h-4 w-4" />
                {passkeyLoading ? 'Authenticating...' : 'Login with Passkey'}
              </Button>
              {passkeyError && <Alert variant="destructive" className="mt-3"><AlertDescription>{passkeyError}</AlertDescription></Alert>}
            </div>

            {(config?.github_oauth || config?.google_oauth) && (
              <div className="space-y-3">
                <div className="relative">
                  <div className="absolute inset-0 flex items-center"><Separator className="w-full" /></div>
                  <div className="relative flex justify-center text-xs uppercase"><span className="bg-card px-2 text-muted-foreground">or continue with</span></div>
                </div>
                <div className={`grid gap-3 ${(config?.github_oauth && config?.google_oauth) ? 'grid-cols-2' : 'grid-cols-1'}`}>
                  {config?.github_oauth && (
                    <Button type="button" variant="outline" onClick={() => handleOAuthLogin('github')} className="bg-[#24292e] hover:bg-[#2f363d] text-white hover:text-white border-gray-600">
                      <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 24 24"><title>GitHub</title><path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" /></svg>
                      GitHub
                    </Button>
                  )}
                  {config?.google_oauth && (
                    <Button type="button" variant="outline" onClick={() => handleOAuthLogin('google')} className="bg-white hover:bg-gray-100 text-gray-700 border-gray-300">
                      <svg className="w-4 h-4 mr-2" viewBox="0 0 24 24"><title>Google</title><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" /><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" /><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" /><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" /></svg>
                      Google
                    </Button>
                  )}
                </div>
              </div>
            )}

            {config?.database_auth && (
              <div className="text-center">
                <p className="text-sm text-muted-foreground">
                  Don't have an account?{' '}
                  <Link to="/register" search={{ challenge: searchParams.challenge, redirect_port: searchParams.redirect_port }} className="text-primary hover:text-primary/80 font-medium transition-colors">
                    Create one
                  </Link>
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/login')({
  component: LoginPage,
  validateSearch: (search: Record<string, unknown>): SearchParams => searchParamsSchema.parse(search),
});
