import { zodResolver } from '@hookform/resolvers/zod';
import {
  type PublicKeyCredentialCreationOptionsJSON,
  startRegistration,
} from '@simplewebauthn/browser';
import { createFileRoute, Link } from '@tanstack/react-router';
import {
  ChevronLeft,
  Chrome,
  Github,
  Key,
  Lightbulb,
  Link2,
  Loader2,
  Plus,
  Trash2,
  X,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { ThemeToggle } from '@/components/theme-toggle';
import { LanguageToggle } from '@/components/language-toggle';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { BeaconIcon } from '@/components/beacon-icon';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardTitle,
} from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ApiError, apiClient } from '../utils/api';
import * as m from '@/paraglide/messages';

const passwordChangeSchema = z
  .object({
    currentPassword: z.string().min(1, 'Current password is required'),
    newPassword: z.string().min(6, 'Password must be at least 6 characters'),
    confirmPassword: z.string().min(1, 'Please confirm your password'),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  });

type PasswordChangeData = z.infer<typeof passwordChangeSchema>;

const passwordSetSchema = z
  .object({
    newPassword: z.string().min(6, 'Password must be at least 6 characters'),
    confirmPassword: z.string().min(1, 'Please confirm your password'),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  });

type PasswordSetData = z.infer<typeof passwordSetSchema>;

const usernameChangeSchema = z.object({
  username: z
    .string()
    .trim()
    .min(3, 'Username must be at least 3 characters')
    .max(16, 'Username must be at most 16 characters')
    .regex(
      /^[A-Za-z0-9_]+$/,
      'Username can only contain letters, numbers, and underscore',
    ),
});

type UsernameChangeData = z.infer<typeof usernameChangeSchema>;

interface UserInfo {
  id: string;
  username: string;
}
interface PasskeyInfo {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

interface ServerConfig {
  database_auth: boolean;
  github_oauth: boolean;
  google_oauth: boolean;
  microsoft_oauth: boolean;
}

interface IdentityInfo {
  id: string;
  provider: string;
  provider_user_id: string;
}

interface IdentitiesResponse {
  identities: IdentityInfo[];
  has_password: boolean;
  passkey_count: number;
}

const getErrorMessage = (
  error: unknown,
  fallback = 'Failed to process request',
) => {
  if (error instanceof ApiError) {
    const data = error.data as { message?: string } | undefined;
    return data?.message ?? error.message;
  }
  if (error instanceof Error) return error.message;
  return fallback;
};

function SettingsPage() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [identities, setIdentities] = useState<IdentitiesResponse | null>(null);
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<{
    type: 'success' | 'error';
    text: string;
  } | null>(null);
  const [showPasskeyModal, setShowPasskeyModal] = useState(false);
  const [passkeyName, setPasskeyName] = useState('');

  const hasPassword = identities?.has_password ?? true;
  const linkedProviders = new Set(
    (identities?.identities ?? []).map((i) => i.provider),
  );
  const isGithubLinked = linkedProviders.has('github');
  const isGoogleLinked = linkedProviders.has('google');
  const isMicrosoftLinked = linkedProviders.has('microsoft');

  const changePasswordForm = useForm<PasswordChangeData>({
    resolver: zodResolver(passwordChangeSchema),
  });

  const setPasswordForm = useForm<PasswordSetData>({
    resolver: zodResolver(passwordSetSchema),
  });

  const changeUsernameForm = useForm<UsernameChangeData>({
    resolver: zodResolver(usernameChangeSchema),
    defaultValues: { username: '' },
  });

  useEffect(() => {
    if (user) {
      changeUsernameForm.reset({ username: user.username });
    }
  }, [user, changeUsernameForm]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [userData, passkeysData, identitiesData, configData] =
          await Promise.all([
            apiClient<UserInfo>('/api/v1/user/me'),
            apiClient<{ passkeys: PasskeyInfo[] }>('/api/v1/passkey/list'),
            apiClient<IdentitiesResponse>('/api/v1/identities'),
            apiClient<ServerConfig>('/api/v1/config', { requiresAuth: false }),
          ]);

        setUser(userData);
        setPasskeys(passkeysData.passkeys || []);
        setIdentities(identitiesData);
        setConfig(configData);
      } catch (error) {
        console.error('Failed to load settings data', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const refreshIdentities = async () => {
    try {
      const identitiesData =
        await apiClient<IdentitiesResponse>('/api/v1/identities');
      setIdentities(identitiesData);
    } catch (error) {
      console.error('Failed to refresh identities', error);
    }
  };

  const onPasswordChange = async (data: PasswordChangeData) => {
    try {
      await apiClient('/api/v1/user/change-password', {
        method: 'POST',
        body: {
          current_password: data.currentPassword,
          new_password: data.newPassword,
        },
      });
      setMessage({ type: 'success', text: 'Password changed successfully!' });
      changePasswordForm.reset();
      await refreshIdentities();
    } catch (error) {
      setMessage({
        type: 'error',
        text: getErrorMessage(error, 'Failed to connect to server'),
      });
    }
  };

  const onPasswordSet = async (data: PasswordSetData) => {
    try {
      await apiClient('/api/v1/user/change-password', {
        method: 'POST',
        body: { current_password: '', new_password: data.newPassword },
      });
      setMessage({ type: 'success', text: 'Password set successfully!' });
      setPasswordForm.reset();
      await refreshIdentities();
    } catch (error) {
      setMessage({
        type: 'error',
        text: getErrorMessage(error, 'Failed to connect to server'),
      });
    }
  };

  const onUsernameChange = async (data: UsernameChangeData) => {
    try {
      const result = await apiClient<{ success: boolean; username: string }>(
        '/api/v1/user/change-username',
        {
          method: 'POST',
          body: { username: data.username },
        },
      );

      setUser((prev) => (prev ? { ...prev, username: result.username } : prev));
      setMessage({ type: 'success', text: 'Username updated successfully!' });
      changeUsernameForm.reset({ username: result.username });
    } catch (error) {
      setMessage({
        type: 'error',
        text: getErrorMessage(error, 'Failed to update username'),
      });
    }
  };

  const handleUnlinkIdentity = async (id: string) => {
    if (!confirm(m.alert_confirm_unlink())) return;
    try {
      await apiClient(`/api/v1/identities/${id}`, { method: 'DELETE' });
      setMessage({ type: 'success', text: 'Login method unlinked.' });
      await refreshIdentities();
    } catch (error) {
      setMessage({
        type: 'error',
        text: getErrorMessage(error, 'Failed to unlink login method'),
      });
    }
  };

  const handleOAuthLink = async (provider: 'github' | 'google' | 'microsoft') => {
    try {
      const result = await apiClient<{ authorizationUrl?: string }>(
        '/api/v1/oauth/link/start',
        {
          method: 'POST',
          body: { provider, challenge: '', redirect_port: 0 },
        },
      );
      if (result.authorizationUrl) {
        window.location.href = result.authorizationUrl;
      }
    } catch (error) {
      setMessage({
        type: 'error',
        text: getErrorMessage(error, 'Failed to start OAuth link flow'),
      });
    }
  };

  const handlePasskeyModalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = passkeyName.trim();
    if (!name) {
      setMessage({ type: 'error', text: 'Passkey name is required' });
      return;
    }
    try {
      const data = await apiClient<{
        creation_options: { publicKey: PublicKeyCredentialCreationOptionsJSON };
      }>('/api/v1/passkey/register/start', { method: 'POST', body: { name } });
      const credential = await startRegistration({
        optionsJSON: data.creation_options.publicKey,
      });
      await apiClient('/api/v1/passkey/register/finish', {
        method: 'POST',
        body: { credential, name },
      });
      setMessage({ type: 'success', text: 'Passkey registered successfully!' });
      setShowPasskeyModal(false);
      setPasskeyName('');
      const passkeysData = await apiClient<{ passkeys: PasskeyInfo[] }>(
        '/api/v1/passkey/list',
      );
      setPasskeys(passkeysData.passkeys || []);
    } catch (error) {
      console.error('Passkey registration failed:', error);
      setMessage({
        type: 'error',
        text: `Failed to register passkey: ${getErrorMessage(error, 'Unknown error')}`,
      });
      setShowPasskeyModal(false);
      setPasskeyName('');
    }
  };

  const handleDeletePasskey = async (id: string, name: string) => {
    if (!confirm(m.alert_confirm_delete_passkey({ name }))) return;
    try {
      await apiClient(`/api/v1/passkey/${id}`, { method: 'DELETE' });
      setMessage({ type: 'success', text: 'Passkey deleted successfully!' });
      setPasskeys(passkeys.filter((p) => p.id !== id));
    } catch (error) {
      setMessage({
        type: 'error',
        text: `Failed to delete passkey: ${getErrorMessage(error, 'Unknown error')}`,
      });
    }
  };

  if (loading) {
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

  if (!user) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-background">
        <div className="w-full max-w-md">
          <Card className="text-center shadow-lg border-muted">
            <CardContent className="pt-8 pb-8">
              <div className="inline-block mb-6 text-muted-foreground opacity-50">
                <BeaconIcon className="w-16 h-16" />
              </div>
              <CardTitle className="text-2xl font-bold mb-4">
                {m.settings_not_authenticated()}
              </CardTitle>
              <CardDescription className="mb-8">
                {m.settings_login_required()}
              </CardDescription>
              <Button asChild size="lg" className="rounded-full">
                <Link to="/login">{m.settings_sign_in()}</Link>
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background pb-20">
      <nav className="sticky top-0 z-50 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3 group">
              <BeaconIcon className="w-8 h-8 text-primary" />
              <span className="text-xl text-primary font-bold">
                {m.app_name()}
              </span>
            </Link>
            <div className="flex items-center gap-2">
              <Button variant="ghost" asChild className="hidden sm:inline-flex">
                <Link to="/profile">
                  <ChevronLeft className="h-4 w-4 mr-1" />
                  {m.settings_nav_profile()}
                </Link>
              </Button>
              <Link to="/profile" className="sm:hidden">
                <Button variant="ghost" size="icon">
                  <ChevronLeft className="h-5 w-5" />
                </Button>
              </Link>
              <ThemeToggle />
              <LanguageToggle />
            </div>
          </div>
        </div>
      </nav>

      <div className="container max-w-5xl mx-auto px-4 md:px-6 pt-12">
        <div className="mb-10">
          <h1 className="text-3xl font-extrabold tracking-tight mb-2">
            {m.settings_title()}
          </h1>
          <p className="text-muted-foreground text-lg">
            {m.settings_subtitle({ username: user.username })}
          </p>
        </div>

        {message && (
          <Alert
            variant={message.type === 'success' ? 'default' : 'destructive'}
            className="mb-8 shadow-sm"
          >
            <AlertDescription className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="text-xl">
                  {message.type === 'success' ? '✓' : '✗'}
                </span>
                <p className="font-medium">{message.text}</p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0"
                onClick={() => setMessage(null)}
              >
                <X className="h-4 w-4" />
              </Button>
            </AlertDescription>
          </Alert>
        )}

        <div className="grid gap-8">
          <section className="space-y-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="h-8 w-1 bg-primary rounded-full" />
              <h2 className="text-xl font-bold">
                {m.settings_change_username_title()}
              </h2>
            </div>
            <Card className="border-0 shadow-md">
              <CardContent className="p-6">
                <p className="text-muted-foreground mb-6 text-sm">
                  {m.settings_change_username_desc()}
                </p>
                <form
                  onSubmit={changeUsernameForm.handleSubmit(onUsernameChange)}
                  className="flex flex-col sm:flex-row gap-4"
                >
                  <div className="flex-1 space-y-2">
                    <Label htmlFor="username" className="sr-only">
                      {m.settings_username_label()}
                    </Label>
                    <Input
                      id="username"
                      {...changeUsernameForm.register('username')}
                      placeholder={m.settings_username_placeholder()}
                      disabled={changeUsernameForm.formState.isSubmitting}
                      className="bg-background/50 h-10"
                    />
                    {changeUsernameForm.formState.errors.username && (
                      <p className="text-sm text-destructive mt-1">
                        {changeUsernameForm.formState.errors.username.message}
                      </p>
                    )}
                  </div>
                  <Button
                    type="submit"
                    disabled={changeUsernameForm.formState.isSubmitting}
                    className="shrink-0 self-start mt-8" // Added mt-8 to align with input since label is sr-only or similar
                  >
                    {changeUsernameForm.formState.isSubmitting ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      m.settings_update_username()
                    )}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </section>

          <section className="space-y-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="h-8 w-1 bg-primary rounded-full" />
              <h2 className="text-xl font-bold">
                {m.settings_login_methods_title()}
              </h2>
            </div>

            <Card className="border-0 shadow-md">
              <CardContent className="p-0">
                <div className="p-6 pb-0">
                  <p className="text-muted-foreground mb-6 text-sm">
                    {m.settings_login_methods_desc()}
                  </p>
                </div>
                <div className="divide-y divide-border">
                  {/* Password Method */}
                  <div className="flex items-center justify-between p-6 bg-green-50/50 dark:bg-green-900/10">
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 rounded-xl bg-background flex items-center justify-center shadow-xs text-primary">
                        <Key className="h-5 w-5" />
                      </div>
                      <div>
                        <h3 className="font-semibold">
                          {m.settings_password_method()}
                        </h3>
                        <p className="text-xs text-muted-foreground">
                          {hasPassword
                            ? m.settings_password_secure_set()
                            : m.settings_password_not_set()}
                        </p>
                      </div>
                    </div>
                    <Badge
                      variant={hasPassword ? 'default' : 'outline'}
                      className={hasPassword ? 'bg-green-600' : ''}
                    >
                      {hasPassword
                        ? m.settings_enabled()
                        : m.settings_not_set()}
                    </Badge>
                  </div>

                  {/* OAuth Methods */}
                  <div className="p-6 space-y-4">
                    <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
                      {m.settings_linked_oauth()}
                    </h3>

                    {(identities?.identities || []).filter(
                      (i) => i.provider !== 'password',
                    ).length === 0 ? (
                      <div className="text-center p-8 border-2 border-dashed rounded-xl text-muted-foreground bg-muted/30">
                        {m.settings_no_oauth()}
                      </div>
                    ) : (
                      <div className="grid gap-3">
                        {(identities?.identities || [])
                          .filter((i) => i.provider !== 'password')
                          .map((i) => (
                            <div
                              key={i.id}
                              className="flex items-center justify-between p-4 rounded-xl border border-border bg-background/50"
                            >
                              <div className="flex items-center gap-4">
                                <div className="w-10 h-10 rounded-lg bg-secondary flex items-center justify-center text-secondary-foreground">
                                  {i.provider === 'github' ? (
                                    <Github className="h-5 w-5" />
                                  ) : i.provider === 'google' ? (
                                    <Chrome className="h-5 w-5" />
                                  ) : i.provider === 'microsoft' ? (
                                    <svg
                                      className="h-5 w-5"
                                      viewBox="0 0 24 24"
                                      aria-label="Microsoft"
                                    >
                                      <path fill="#F25022" d="M2 2h9v9H2z" />
                                      <path fill="#7FBA00" d="M13 2h9v9h-9z" />
                                      <path fill="#00A4EF" d="M2 13h9v9H2z" />
                                      <path fill="#FFB900" d="M13 13h9v9h-9z" />
                                    </svg>
                                  ) : (
                                    <Link2 className="h-5 w-5" />
                                  )}
                                </div>
                                <div>
                                  <h3 className="font-semibold capitalize">
                                    {i.provider}
                                  </h3>
                                  <p className="text-xs text-muted-foreground break-all">
                                    {i.provider_user_id}
                                  </p>
                                </div>
                              </div>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="text-destructive hover:text-destructive hover:bg-destructive/10"
                                onClick={() => handleUnlinkIdentity(i.id)}
                                title="Unlink"
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          ))}
                      </div>
                    )}

                     {/* Link Buttons Row */}
                     {(config?.github_oauth && !isGithubLinked) ||
                     (config?.google_oauth && !isGoogleLinked) ||
                     (config?.microsoft_oauth && !isMicrosoftLinked) ? (
                       <div className="flex flex-wrap gap-3 pt-2">
                         {config?.github_oauth && !isGithubLinked && (
                           <Button
                             variant="outline"
                             onClick={() => handleOAuthLink('github')}
                             className="gap-2"
                           >
                             <Github className="h-4 w-4" />
                             {m.settings_link_github()}
                           </Button>
                         )}
                         {config?.google_oauth && !isGoogleLinked && (
                           <Button
                             variant="outline"
                             onClick={() => handleOAuthLink('google')}
                             className="gap-2"
                           >
                             <Chrome className="h-4 w-4" />
                             {m.settings_link_google()}
                           </Button>
                         )}
                         {config?.microsoft_oauth && !isMicrosoftLinked && (
                           <Button
                             variant="outline"
                             onClick={() => handleOAuthLink('microsoft')}
                             className="gap-2"
                           >
                             <svg
                               className="h-4 w-4"
                               viewBox="0 0 24 24"
                               aria-label="Microsoft"
                             >
                               <path fill="#F25022" d="M2 2h9v9H2z" />
                               <path fill="#7FBA00" d="M13 2h9v9h-9z" />
                               <path fill="#00A4EF" d="M2 13h9v9H2z" />
                               <path fill="#FFB900" d="M13 13h9v9h-9z" />
                             </svg>
                             {m.settings_link_microsoft()}
                           </Button>
                         )}
                       </div>
                     ) : (
                       !config?.github_oauth &&
                       !config?.google_oauth &&
                       !config?.microsoft_oauth && (
                         <p className="text-sm text-muted-foreground italic pt-2">
                           {m.settings_no_providers()}
                         </p>
                       )
                     )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </section>

          <section className="space-y-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="h-8 w-1 bg-primary rounded-full" />
              <h2 className="text-xl font-bold">
                {hasPassword
                  ? m.settings_change_password()
                  : m.settings_set_password()}
              </h2>
            </div>
            <Card className="border-0 shadow-md">
              <CardContent className="p-6">
                {hasPassword ? (
                  <form
                    onSubmit={changePasswordForm.handleSubmit(onPasswordChange)}
                    className="gap-4"
                  >
                    <div className="grid md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="currentPassword">
                          {m.settings_current_password()}
                        </Label>
                        <Input
                          id="currentPassword"
                          type="password"
                          {...changePasswordForm.register('currentPassword')}
                          placeholder="••••••••"
                          disabled={changePasswordForm.formState.isSubmitting}
                          className="bg-background/50"
                        />
                        {changePasswordForm.formState.errors.currentPassword && (
                          <p className="text-sm text-destructive">
                            {
                              changePasswordForm.formState.errors.currentPassword
                                .message
                            }
                          </p>
                        )}
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="newPassword">
                          {m.settings_new_password()}
                        </Label>
                        <Input
                          id="newPassword"
                          type="password"
                          {...changePasswordForm.register('newPassword')}
                          placeholder="••••••••"
                          disabled={changePasswordForm.formState.isSubmitting}
                          className="bg-background/50"
                        />
                        {changePasswordForm.formState.errors.newPassword && (
                          <p className="text-sm text-destructive">
                            {
                              changePasswordForm.formState.errors.newPassword
                                .message
                            }
                          </p>
                        )}
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="confirmPassword">
                          {m.settings_confirm_password()}
                        </Label>
                        <Input
                          id="confirmPassword"
                          type="password"
                          {...changePasswordForm.register('confirmPassword')}
                          placeholder="••••••••"
                          disabled={changePasswordForm.formState.isSubmitting}
                          className="bg-background/50"
                        />
                        {changePasswordForm.formState.errors.confirmPassword && (
                          <p className="text-sm text-destructive">
                            {
                              changePasswordForm.formState.errors.confirmPassword
                                .message
                            }
                          </p>
                        )}
                      </div>
                      <div className="flex items-end justify-end">
                        <Button
                          type="submit"
                          disabled={changePasswordForm.formState.isSubmitting}
                          className="w-full md:w-auto"
                        >
                          {changePasswordForm.formState.isSubmitting ? (
                            <>
                              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                              {m.settings_changing_password()}
                            </>
                          ) : (
                            m.settings_change_password()
                          )}
                        </Button>
                      </div>
                    </div>
                  </form>
                ) : (
                  <form
                    onSubmit={setPasswordForm.handleSubmit(onPasswordSet)}
                    className="space-y-4 max-w-md"
                  >
                    <Alert className="mb-4 bg-primary/5 border-primary/10">
                      <AlertDescription>
                        You currently log in with social accounts. Set a
                        password to log in with username/password as well.
                      </AlertDescription>
                    </Alert>
                    <div className="space-y-2">
                      <Label htmlFor="newPassword">
                        {m.settings_new_password()}
                      </Label>
                      <Input
                        id="newPassword"
                        type="password"
                        {...setPasswordForm.register('newPassword')}
                        placeholder="••••••••"
                        disabled={setPasswordForm.formState.isSubmitting}
                        className="bg-background/50"
                      />
                      {setPasswordForm.formState.errors.newPassword && (
                        <p className="text-sm text-destructive">
                          {setPasswordForm.formState.errors.newPassword.message}
                        </p>
                      )}
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="confirmPassword">
                        {m.settings_confirm_password_simple()}
                      </Label>
                      <Input
                        id="confirmPassword"
                        type="password"
                        {...setPasswordForm.register('confirmPassword')}
                        placeholder="••••••••"
                        disabled={setPasswordForm.formState.isSubmitting}
                        className="bg-background/50"
                      />
                      {setPasswordForm.formState.errors.confirmPassword && (
                        <p className="text-sm text-destructive">
                          {
                            setPasswordForm.formState.errors.confirmPassword
                              .message
                          }
                        </p>
                      )}
                    </div>
                    <div className="flex justify-end pt-2">
                      <Button
                        type="submit"
                        disabled={setPasswordForm.formState.isSubmitting}
                      >
                        {setPasswordForm.formState.isSubmitting ? (
                          <>
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            {m.settings_setting_password()}
                          </>
                        ) : (
                          m.settings_set_password()
                        )}
                      </Button>
                    </div>
                  </form>
                )}
              </CardContent>
            </Card>
          </section>

          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 mb-2">
                <div className="h-8 w-1 bg-primary rounded-full" />
                <h2 className="text-xl font-bold">
                  {m.settings_passkeys_title()}
                </h2>
              </div>
              <Button
                onClick={() => setShowPasskeyModal(true)}
                size="sm"
                className="rounded-full"
              >
                <Plus className="h-4 w-4 mr-2" />
                {m.settings_add_passkey()}
              </Button>
            </div>

            <Card className="border-0 shadow-md">
              <CardContent className="p-6">
                {passkeys.length === 0 ? (
                  <div className="text-center py-12 border-2 border-dashed border-border rounded-xl bg-muted/20">
                    <div className="w-16 h-16 mx-auto bg-muted rounded-full flex items-center justify-center mb-4 text-muted-foreground">
                      <Key className="h-8 w-8" />
                    </div>
                    <p className="text-muted-foreground font-medium mb-1">
                      {m.settings_no_passkeys()}
                    </p>
                    <p className="text-sm text-muted-foreground/80">
                      {m.settings_add_passkey_promo()}
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {passkeys.map((passkey) => (
                      <div
                        key={passkey.id}
                        className="flex items-center justify-between p-4 rounded-xl border border-border bg-background/50"
                      >
                        <div className="flex items-center gap-4">
                          <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                            <Key className="h-5 w-5" />
                          </div>
                          <div>
                            <h3 className="font-semibold">{passkey.name}</h3>
                            <div className="flex items-center gap-4 text-xs text-muted-foreground mt-1">
                              <span>
                                {m.settings_created_at({
                                  date: new Date(
                                    passkey.created_at,
                                  ).toLocaleDateString(),
                                })}
                              </span>
                              {passkey.last_used_at && (
                                <span>
                                  {m.settings_last_used({
                                    date: new Date(
                                      passkey.last_used_at,
                                    ).toLocaleDateString(),
                                  })}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-destructive hover:bg-destructive/10"
                          onClick={() =>
                            handleDeletePasskey(passkey.id, passkey.name)
                          }
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    ))}
                  </div>
                )}

                <Alert className="mt-8 bg-blue-50/50 dark:bg-blue-900/10 border-blue-100 dark:border-blue-900">
                  <Lightbulb className="h-4 w-4 text-blue-500" />
                  <AlertDescription className="text-blue-700 dark:text-blue-300">
                    <h3 className="font-semibold mb-1">
                      {m.settings_what_are_passkeys()}
                    </h3>
                    <p className="text-sm opacity-90">
                      {m.settings_passkeys_help_text()}
                    </p>
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          </section>
        </div>

        <Dialog open={showPasskeyModal} onOpenChange={setShowPasskeyModal}>
          <DialogContent className="bg-card border-border">
            <DialogHeader>
              <DialogTitle>{m.settings_add_new_passkey_title()}</DialogTitle>
              <DialogDescription>
                {m.settings_add_new_passkey_desc()}
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handlePasskeyModalSubmit}>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="passkeyName">
                    {m.settings_passkey_name_label()}
                  </Label>
                  <Input
                    id="passkeyName"
                    type="text"
                    value={passkeyName}
                    onChange={(e) => setPasskeyName(e.target.value)}
                    placeholder={m.settings_passkey_name_placeholder()}
                    className="bg-background/50"
                  />
                </div>
                <div className="flex gap-3">
                  <Button
                    type="button"
                    variant="secondary"
                    className="flex-1"
                    onClick={() => {
                      setShowPasskeyModal(false);
                      setPasskeyName('');
                    }}
                  >
                    {m.settings_cancel()}
                  </Button>
                  <Button type="submit" className="flex-1">
                    {m.settings_continue()}
                  </Button>
                </div>
              </div>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/settings')({ component: SettingsPage });
