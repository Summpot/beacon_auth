import { zodResolver } from '@hookform/resolvers/zod';
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { ApiError, apiClient } from '../utils/api';
import { BeaconIcon } from '@/components/beacon-icon';
import { MinecraftFlowAlert } from '@/components/minecraft/minecraft-flow-alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ChevronLeft, Loader2 } from 'lucide-react';

const searchParamsSchema = z.object({
  challenge: z.string().min(1).optional(),
  redirect_port: z.coerce.number().min(1).max(65535).optional(),
});

type SearchParams = z.infer<typeof searchParamsSchema>;

const registerFormSchema = z.object({
  username: z.string().min(3, 'Username must be at least 3 characters'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

type RegisterFormData = z.infer<typeof registerFormSchema>;

function RegisterPage() {
  const searchParams = Route.useSearch();
  const navigate = useNavigate();

  const getErrorMessage = (error: unknown, fallback: string) => {
    if (error instanceof ApiError) {
      const data = error.data as { message?: string } | undefined;
      return data?.message ?? error.message;
    }
    if (error instanceof Error) return error.message;
    return fallback;
  };

  const { register, handleSubmit, formState: { errors, isSubmitting }, setError } = useForm<RegisterFormData>({
    resolver: zodResolver(registerFormSchema),
  });

  const onSubmit = async (data: RegisterFormData) => {
    try {
      await apiClient('/api/v1/register', { method: 'POST', requiresAuth: false, body: { username: data.username, password: data.password } });
    } catch (error) {
      setError('root', { type: 'manual', message: getErrorMessage(error, 'Registration failed') });
      return;
    }

    try {
      if (searchParams.challenge && searchParams.redirect_port) {
        const result = await apiClient<{ redirectUrl?: string }>('/api/v1/minecraft-jwt', {
          method: 'POST',
          body: { challenge: searchParams.challenge, redirect_port: searchParams.redirect_port, profile_url: window.location.origin + '/profile' },
        });
        if (result.redirectUrl) {
          window.location.href = result.redirectUrl;
          return;
        }
      }
      navigate({ to: '/profile' });
    } catch (error) {
      setError('root', { type: 'manual', message: getErrorMessage(error, 'Failed to complete registration') });
    }
  };

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
              <BeaconIcon className="w-16 h-16" accentColor="#a855f7" />
            </div>
            <CardTitle className="text-3xl font-bold">Create Account</CardTitle>
            <CardDescription>Join the BeaconAuth community</CardDescription>
          </CardHeader>

          <CardContent className="space-y-6">
            {searchParams.challenge && searchParams.redirect_port && (
              <MinecraftFlowAlert
                title="Minecraft Registration"
                challenge={searchParams.challenge}
                redirectPort={searchParams.redirect_port}
              />
            )}

            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input id="username" type="text" {...register('username')} placeholder="Choose a username" disabled={isSubmitting} className="bg-background/50 border-input" />
                {errors.username && <p className="text-sm text-destructive">{errors.username.message}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input id="password" type="password" {...register('password')} placeholder="Create a password (min 6 chars)" disabled={isSubmitting} className="bg-background/50 border-input" />
                {errors.password && <p className="text-sm text-destructive">{errors.password.message}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirmPassword">Confirm Password</Label>
                <Input id="confirmPassword" type="password" {...register('confirmPassword')} placeholder="Confirm your password" disabled={isSubmitting} className="bg-background/50 border-input" />
                {errors.confirmPassword && <p className="text-sm text-destructive">{errors.confirmPassword.message}</p>}
              </div>

              {errors.root && <Alert variant="destructive"><AlertDescription>{errors.root.message}</AlertDescription></Alert>}

              <Button type="submit" disabled={isSubmitting} className="w-full">
                {isSubmitting ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Creating Account...</> : 'Create Account'}
              </Button>
            </form>

            <div className="text-center">
              <p className="text-sm text-muted-foreground">
                Already have an account?{' '}
                <Link to="/login" search={{ challenge: searchParams.challenge, redirect_port: searchParams.redirect_port }} className="text-primary hover:text-primary/80 font-medium transition-colors">
                  Sign in
                </Link>
              </p>
            </div>
          </CardContent>
        </Card>

        <div className="mt-6 text-center">
          <p className="text-xs text-muted-foreground">🔒 Your password is stored securely</p>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/register')({
  component: RegisterPage,
  validateSearch: (search: Record<string, unknown>): SearchParams => searchParamsSchema.parse(search),
});
