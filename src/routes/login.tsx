import { zodResolver } from '@hookform/resolvers/zod';
import { createFileRoute, Link } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';

// Define search params schema
const searchParamsSchema = z.object({
  challenge: z.string().min(1, 'Challenge is required'),
  redirect_port: z.coerce.number().min(1).max(65535),
});

type SearchParams = z.infer<typeof searchParamsSchema>;

// Define login form schema
const loginFormSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
});

type LoginFormData = z.infer<typeof loginFormSchema>;

// Server config type
interface ServerConfig {
  database_auth: boolean;
  github_oauth: boolean;
  google_oauth: boolean;
}

function LoginPage() {
  const searchParams = Route.useSearch();
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(true);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError,
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginFormSchema),
  });

  // Fetch server configuration and check for auto-login on mount
  useEffect(() => {
    const initialize = async () => {
      try {
        // Fetch config
        const configResponse = await fetch('/api/v1/config');
        if (configResponse.ok) {
          const configData = await configResponse.json();
          setConfig(configData);
        }

        // Try auto-login if we have challenge and redirect_port
        const jwtResponse = await fetch('/api/v1/minecraft-jwt', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({
            challenge: searchParams.challenge,
            redirect_port: searchParams.redirect_port,
          }),
        });

        if (jwtResponse.ok) {
          const result = await jwtResponse.json();
          if (result.redirectUrl) {
            // Auto-login successful, redirect immediately
            window.location.href = result.redirectUrl;
            return; // Don't set configLoading to false, we're redirecting
          }
        }
      } catch (error) {
        console.error('Initialization error:', error);
      } finally {
        setConfigLoading(false);
      }
    };
    initialize();
  }, [searchParams.challenge, searchParams.redirect_port]);

  const onSubmit = async (data: LoginFormData) => {
    try {
      // Step 1: Login and set session cookies
      const loginResponse = await fetch('/api/v1/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include', // Important: include cookies
        body: JSON.stringify({
          username: data.username,
          password: data.password,
        }),
      });

      if (!loginResponse.ok) {
        if (loginResponse.status === 401) {
          setError('root', {
            type: 'manual',
            message: 'Invalid username or password',
          });
        } else {
          const errorData = await loginResponse.json();
          setError('root', {
            type: 'manual',
            message: errorData.message || 'Authentication failed',
          });
        }
        return;
      }

      // Step 2: Get Minecraft JWT using the session cookie
      const jwtResponse = await fetch('/api/v1/minecraft-jwt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include', // Important: include cookies
        body: JSON.stringify({
          challenge: searchParams.challenge,
          redirect_port: searchParams.redirect_port,
          profile_url: window.location.origin + '/profile',
        }),
      });

      if (!jwtResponse.ok) {
        setError('root', {
          type: 'manual',
          message: 'Failed to generate Minecraft token',
        });
        return;
      }

      const result = await jwtResponse.json();
      if (result.redirectUrl) {
        window.location.href = result.redirectUrl;
      }
    } catch (_error) {
      setError('root', {
        type: 'manual',
        message: 'Failed to connect to server',
      });
    }
  };

  const handleOAuthLogin = async (provider: 'github' | 'google') => {
    try {
      // Save challenge and redirect_port to sessionStorage for OAuth callback
      sessionStorage.setItem('minecraft_challenge', searchParams.challenge);
      sessionStorage.setItem('minecraft_redirect_port', searchParams.redirect_port.toString());
      
      const response = await fetch('/api/v1/oauth/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          provider,
          challenge: searchParams.challenge,
          redirect_port: searchParams.redirect_port,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to start OAuth flow');
      }

      const result = await response.json();
      if (result.authorizationUrl) {
        window.location.href = result.authorizationUrl;
      }
    } catch (error) {
      console.error(`${provider} login failed:`, error);
    }
  };

  if (configLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <div className="text-gray-600">Loading...</div>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen p-4">
      <div className="w-full max-w-md">
        <div className="bg-white rounded-lg shadow-xl p-8">
          {/* Header */}
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              🔐 BeaconAuth
            </h1>
            <p className="text-gray-600">Authentication Server</p>
          </div>

          {/* Info Section */}
          <div className="bg-blue-50 rounded-lg p-4 mb-6 text-sm">
            <div className="flex justify-between mb-2">
              <span className="font-medium text-gray-700">Challenge:</span>
              <span className="text-gray-600 font-mono text-xs">
                {searchParams.challenge.substring(0, 16)}...
              </span>
            </div>
            <div className="flex justify-between">
              <span className="font-medium text-gray-700">Redirect Port:</span>
              <span className="text-gray-600">
                {searchParams.redirect_port}
              </span>
            </div>
          </div>

          {/* Login Form - Only show if database auth is enabled */}
          {config?.database_auth && (
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div>
              <label
                htmlFor="username"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                Username
              </label>
              <input
                id="username"
                type="text"
                {...register('username')}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                placeholder="Enter your username"
                disabled={isSubmitting}
              />
              {errors.username && (
                <p className="mt-1 text-sm text-red-600">
                  {errors.username.message}
                </p>
              )}
            </div>

            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                Password
              </label>
              <input
                id="password"
                type="password"
                {...register('password')}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                placeholder="Enter your password"
                disabled={isSubmitting}
              />
              {errors.password && (
                <p className="mt-1 text-sm text-red-600">
                  {errors.password.message}
                </p>
              )}
            </div>

            {errors.root && (
              <div className="bg-red-50 text-red-600 px-4 py-3 rounded-lg text-sm">
                {errors.root.message}
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors font-medium"
            >
              {isSubmitting ? 'Authenticating...' : 'Login'}
            </button>
          </form>
          )}

          {/* OAuth Buttons - Only show if at least one OAuth provider is configured */}
          {(config?.github_oauth || config?.google_oauth) && (
            <div className={config?.database_auth ? "mt-6 space-y-3" : "space-y-3"}>
            {config?.database_auth && (
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-300" />
                </div>
                <div className="relative flex justify-center text-sm">
                  <span className="px-2 bg-white text-gray-500">
                    Or continue with
                  </span>
                </div>
              </div>
            )}

            {config?.github_oauth && (
              <button
                type="button"
                onClick={() => handleOAuthLogin('github')}
                className="w-full bg-gray-900 text-white py-2 px-4 rounded-lg hover:bg-gray-800 transition-colors font-medium flex items-center justify-center gap-2"
              >
              <svg
                className="w-5 h-5"
                fill="currentColor"
                viewBox="0 0 24 24"
                role="img"
                aria-label="GitHub"
              >
                <title>GitHub</title>
                <path
                  fillRule="evenodd"
                  d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                  clipRule="evenodd"
                />
              </svg>
              Login with GitHub
              </button>
            )}

            {config?.google_oauth && (
              <button
                type="button"
                onClick={() => handleOAuthLogin('google')}
                className="w-full bg-white text-gray-900 py-2 px-4 rounded-lg border border-gray-300 hover:bg-gray-50 transition-colors font-medium flex items-center justify-center gap-2"
              >
              <svg
                className="w-5 h-5"
                viewBox="0 0 24 24"
                role="img"
                aria-label="Google"
              >
                <title>Google</title>
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                />
              </svg>
              Login with Google
              </button>
            )}
          </div>
          )}

          {/* Register Link - Only show if database auth is enabled */}
          {config?.database_auth && (
            <div className="mt-6 text-center">
            <p className="text-sm text-gray-600">
              Don't have an account?{' '}
              <Link
                to="/register"
                search={{
                  challenge: searchParams.challenge,
                  redirect_port: searchParams.redirect_port,
                }}
                className="text-blue-600 hover:text-blue-700 font-medium"
              >
                Register here
              </Link>
            </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/login')({
  component: LoginPage,
  validateSearch: (search: Record<string, unknown>): SearchParams => {
    return searchParamsSchema.parse(search);
  },
  onError: () => {
    // Show error component if parameter validation fails
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <div className="w-full max-w-md">
          <div className="bg-white rounded-lg shadow-xl p-8">
            <div className="text-center">
              <div className="text-6xl mb-4">⚠️</div>
              <h1 className="text-2xl font-bold text-gray-900 mb-4">
                Invalid Request
              </h1>
              <p className="text-gray-600 mb-4">
                This page requires valid <code>challenge</code> and{' '}
                <code>redirect_port</code> parameters.
                <br />
                Please access this page through the Minecraft mod.
              </p>
              <div className="bg-red-50 text-red-600 px-4 py-3 rounded-lg text-sm">
                Missing or invalid URL parameters
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  },
});
