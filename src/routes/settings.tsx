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
  Mail,
  Plus,
  Trash2,
  X,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { BeaconIcon } from '@/components/beacon-icon';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
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
import { ApiError, apiClient } from '../utils/api';

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
    if (!confirm('Are you sure you want to unlink this login method?')) return;
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

  const handleOAuthLink = async (provider: 'github' | 'google') => {
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
    if (!confirm(`Are you sure you want to delete passkey "${name}"?`)) return;
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

  if (!user) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <div className="w-full max-w-md">
          <Card className="text-center">
            <CardContent className="pt-6">
              <div className="inline-block mb-6">
                <BeaconIcon className="w-20 h-20 opacity-50" />
              </div>
              <CardTitle className="text-2xl font-bold mb-4">
                Not Authenticated
              </CardTitle>
              <CardDescription className="mb-6">
                Please log in to access settings.
              </CardDescription>
              <Button asChild>
                <Link to="/login">Sign In</Link>
              </Button>
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
            <Button variant="ghost" asChild>
              <Link to="/profile">Profile</Link>
            </Button>
          </div>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto pt-24 pb-8">
        <div className="mb-8">
          <Link
            to="/profile"
            className="inline-flex items-center gap-2 text-muted-foreground hover:text-primary transition-colors mb-4"
          >
            <ChevronLeft className="h-4 w-4" />
            Back to Profile
          </Link>
          <h1 className="text-3xl font-bold">Profile Settings</h1>
          <p className="text-muted-foreground mt-2">
            Manage your password and passkeys for{' '}
            <span className="text-primary">{user.username}</span>
          </p>
        </div>

        {message && (
          <Alert
            variant={message.type === 'success' ? 'default' : 'destructive'}
            className="mb-6"
          >
            <AlertDescription className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="text-xl">
                  {message.type === 'success' ? '✓' : '✗'}
                </span>
                <p>{message.text}</p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setMessage(null)}
              >
                <X className="h-4 w-4" />
              </Button>
            </AlertDescription>
          </Alert>
        )}

        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-xl font-bold flex items-center gap-3">
              <span className="w-2 h-2 bg-primary rounded-full" />
              Change Username
            </CardTitle>
            <CardDescription>
              3-16 characters. Letters, numbers, and underscore only. Usernames
              are unique case-insensitively.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form
              onSubmit={changeUsernameForm.handleSubmit(onUsernameChange)}
              className="space-y-4"
            >
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  {...changeUsernameForm.register('username')}
                  placeholder="Your Minecraft-style username"
                  disabled={changeUsernameForm.formState.isSubmitting}
                  className="bg-background/50"
                />
                {changeUsernameForm.formState.errors.username && (
                  <p className="text-sm text-destructive">
                    {changeUsernameForm.formState.errors.username.message}
                  </p>
                )}
              </div>

              <Button
                type="submit"
                disabled={changeUsernameForm.formState.isSubmitting}
              >
                {changeUsernameForm.formState.isSubmitting ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Updating...
                  </>
                ) : (
                  'Update Username'
                )}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card className="mb-6">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-xl font-bold flex items-center gap-3">
                  <span className="w-2 h-2 bg-primary rounded-full" />
                  Login Methods
                </CardTitle>
                <CardDescription>
                  Link or unlink login methods. All methods are equal — keep at
                  least one enabled so you don&apos;t lock yourself out.
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 rounded-xl border border-border bg-card/50">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
                    <Mail className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-semibold">Password</h3>
                    <p className="text-xs text-muted-foreground">
                      {user.username}
                    </p>
                  </div>
                </div>
                <span
                  className={
                    hasPassword
                      ? 'text-green-600 text-sm font-medium'
                      : 'text-muted-foreground text-sm'
                  }
                >
                  {hasPassword ? 'Enabled' : 'Not set'}
                </span>
              </div>

              <div className="space-y-3">
                <h3 className="font-semibold text-sm text-muted-foreground">
                  Linked OAuth Accounts
                </h3>
                {identities &&
                identities.identities.filter((i) => i.provider !== 'password')
                  .length === 0 ? (
                  <div className="text-sm text-muted-foreground p-4 rounded-xl border border-dashed border-border">
                    No OAuth accounts linked yet.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {(identities?.identities || [])
                      .filter((i) => i.provider !== 'password')
                      .map((i) => (
                        <div
                          key={i.id}
                          className="flex items-center justify-between p-4 rounded-xl border border-border bg-card/50 hover:border-primary/30 transition-colors"
                        >
                          <div className="flex items-center gap-4">
                            <div className="w-10 h-10 rounded-lg bg-secondary/20 flex items-center justify-center">
                              {i.provider === 'github' ? (
                                <Github className="h-5 w-5" />
                              ) : i.provider === 'google' ? (
                                <Chrome className="h-5 w-5" />
                              ) : (
                                <Link2 className="h-5 w-5" />
                              )}
                            </div>
                            <div>
                              <h3 className="font-semibold">{i.provider}</h3>
                              <p className="text-xs text-muted-foreground break-all">
                                {i.provider_user_id}
                              </p>
                            </div>
                          </div>

                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleUnlinkIdentity(i.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      ))}
                  </div>
                )}
              </div>

              <div className="flex flex-wrap gap-2 pt-2">
                {config?.github_oauth && !isGithubLinked && (
                  <Button
                    variant="secondary"
                    onClick={() => handleOAuthLink('github')}
                  >
                    <Github className="h-4 w-4 mr-2" />
                    Link GitHub
                  </Button>
                )}
                {config?.google_oauth && !isGoogleLinked && (
                  <Button
                    variant="secondary"
                    onClick={() => handleOAuthLink('google')}
                  >
                    <Chrome className="h-4 w-4 mr-2" />
                    Link Google
                  </Button>
                )}
                {!config?.github_oauth && !config?.google_oauth && (
                  <p className="text-sm text-muted-foreground">
                    No OAuth providers configured on the server.
                  </p>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-xl font-bold flex items-center gap-3">
              <span className="w-2 h-2 bg-primary rounded-full" />
              {hasPassword ? 'Change Password' : 'Set Password'}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {hasPassword ? (
              <form
                onSubmit={changePasswordForm.handleSubmit(onPasswordChange)}
                className="space-y-4"
              >
                <div className="space-y-2">
                  <Label htmlFor="currentPassword">Current Password</Label>
                  <Input
                    id="currentPassword"
                    type="password"
                    {...changePasswordForm.register('currentPassword')}
                    placeholder="Enter current password"
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
                  <Label htmlFor="newPassword">New Password</Label>
                  <Input
                    id="newPassword"
                    type="password"
                    {...changePasswordForm.register('newPassword')}
                    placeholder="Enter new password (min 6 characters)"
                    disabled={changePasswordForm.formState.isSubmitting}
                    className="bg-background/50"
                  />
                  {changePasswordForm.formState.errors.newPassword && (
                    <p className="text-sm text-destructive">
                      {changePasswordForm.formState.errors.newPassword.message}
                    </p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="confirmPassword">Confirm New Password</Label>
                  <Input
                    id="confirmPassword"
                    type="password"
                    {...changePasswordForm.register('confirmPassword')}
                    placeholder="Confirm new password"
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
                <Button
                  type="submit"
                  disabled={changePasswordForm.formState.isSubmitting}
                  className="w-full"
                >
                  {changePasswordForm.formState.isSubmitting ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Changing Password...
                    </>
                  ) : (
                    'Change Password'
                  )}
                </Button>
              </form>
            ) : (
              <form
                onSubmit={setPasswordForm.handleSubmit(onPasswordSet)}
                className="space-y-4"
              >
                <div className="space-y-2">
                  <Label htmlFor="newPassword">New Password</Label>
                  <Input
                    id="newPassword"
                    type="password"
                    {...setPasswordForm.register('newPassword')}
                    placeholder="Create a password (min 6 characters)"
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
                  <Label htmlFor="confirmPassword">Confirm Password</Label>
                  <Input
                    id="confirmPassword"
                    type="password"
                    {...setPasswordForm.register('confirmPassword')}
                    placeholder="Confirm your password"
                    disabled={setPasswordForm.formState.isSubmitting}
                    className="bg-background/50"
                  />
                  {setPasswordForm.formState.errors.confirmPassword && (
                    <p className="text-sm text-destructive">
                      {setPasswordForm.formState.errors.confirmPassword.message}
                    </p>
                  )}
                </div>
                <Button
                  type="submit"
                  disabled={setPasswordForm.formState.isSubmitting}
                  className="w-full"
                >
                  {setPasswordForm.formState.isSubmitting ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Setting Password...
                    </>
                  ) : (
                    'Set Password'
                  )}
                </Button>
              </form>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-xl font-bold flex items-center gap-3">
                  <span className="w-2 h-2 bg-primary rounded-full" />
                  Passkeys
                </CardTitle>
                <CardDescription>
                  Use biometric authentication for passwordless login
                </CardDescription>
              </div>
              <Button onClick={() => setShowPasskeyModal(true)}>
                <Plus className="h-4 w-4 mr-2" />
                Add Passkey
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {passkeys.length === 0 ? (
              <div className="text-center py-12 border-2 border-dashed border-border rounded-xl">
                <Key className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <p className="text-muted-foreground mb-2">
                  No passkeys registered yet
                </p>
                <p className="text-sm text-muted-foreground">
                  Add a passkey for faster, more secure authentication
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {passkeys.map((passkey) => (
                  <div
                    key={passkey.id}
                    className="flex items-center justify-between p-4 rounded-xl border border-border bg-card/50 hover:border-primary/30 transition-colors"
                  >
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
                        <Key className="h-5 w-5 text-primary" />
                      </div>
                      <div>
                        <h3 className="font-semibold">{passkey.name}</h3>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground mt-1">
                          <span>
                            Created:{' '}
                            {new Date(passkey.created_at).toLocaleDateString()}
                          </span>
                          {passkey.last_used_at && (
                            <span>
                              Last used:{' '}
                              {new Date(
                                passkey.last_used_at,
                              ).toLocaleDateString()}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <Button
                      variant="destructive"
                      size="sm"
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

            <Alert className="mt-6">
              <Lightbulb className="h-4 w-4" />
              <AlertDescription>
                <h3 className="font-semibold mb-1">What are passkeys?</h3>
                <p className="text-sm text-muted-foreground">
                  Passkeys are a secure, passwordless authentication method that
                  uses your device's biometric authentication (fingerprint, face
                  recognition) or PIN. They're more secure than passwords and
                  easier to use.
                </p>
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>

        <Dialog open={showPasskeyModal} onOpenChange={setShowPasskeyModal}>
          <DialogContent className="bg-card border-border">
            <DialogHeader>
              <DialogTitle>Add New Passkey</DialogTitle>
              <DialogDescription>
                Give your passkey a memorable name to identify this device.
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handlePasskeyModalSubmit}>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="passkeyName">Passkey Name</Label>
                  <Input
                    id="passkeyName"
                    type="text"
                    value={passkeyName}
                    onChange={(e) => setPasskeyName(e.target.value)}
                    placeholder='e.g., "My Phone", "YubiKey"'
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
                    Cancel
                  </Button>
                  <Button type="submit" className="flex-1">
                    Continue
                  </Button>
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
