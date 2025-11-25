import { zodResolver } from '@hookform/resolvers/zod';
import { createFileRoute } from '@tanstack/react-router';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { fetchWithAuth } from '../utils/api';

// Define search params schema
const searchParamsSchema = z.object({
  challenge: z.string().min(1, 'Challenge is required'),
  redirect_port: z.coerce.number().min(1).max(65535),
});

type SearchParams = z.infer<typeof searchParamsSchema>;

// Define registration form schema
const registerFormSchema = z
  .object({
    username: z.string().min(3, 'Username must be at least 3 characters'),
    password: z.string().min(6, 'Password must be at least 6 characters'),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  });

type RegisterFormData = z.infer<typeof registerFormSchema>;

function RegisterPage() {
  const searchParams = Route.useSearch();

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError,
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerFormSchema),
  });

  const onSubmit = async (data: RegisterFormData) => {
    try {
      // Step 1: Register and set session cookies
      const registerResponse = await fetch('/api/v1/register', {
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

      if (!registerResponse.ok) {
        const errorData = await registerResponse.json();
        setError('root', {
          type: 'manual',
          message: errorData.message || 'Registration failed',
        });
        return;
      }

      // Step 2: Get Minecraft JWT using the session cookie
      const jwtResponse = await fetchWithAuth('/api/v1/minecraft-jwt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
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

  return (
    <div className="flex items-center justify-center min-h-screen p-4">
      <div className="w-full max-w-md">
        <div className="bg-white rounded-lg shadow-xl p-8">
          {/* Header */}
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              📝 Create Account
            </h1>
            <p className="text-gray-600">Join BeaconAuth</p>
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

          {/* Register Form */}
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
                placeholder="Choose a username"
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
                placeholder="Create a password"
                disabled={isSubmitting}
              />
              {errors.password && (
                <p className="mt-1 text-sm text-red-600">
                  {errors.password.message}
                </p>
              )}
            </div>

            <div>
              <label
                htmlFor="confirmPassword"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                Confirm Password
              </label>
              <input
                id="confirmPassword"
                type="password"
                {...register('confirmPassword')}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                placeholder="Confirm your password"
                disabled={isSubmitting}
              />
              {errors.confirmPassword && (
                <p className="mt-1 text-sm text-red-600">
                  {errors.confirmPassword.message}
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
              {isSubmitting ? 'Creating Account...' : 'Register'}
            </button>
          </form>

          {/* Login Link */}
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600">
              Already have an account?{' '}
              <a
                href={`/?challenge=${searchParams.challenge}&redirect_port=${searchParams.redirect_port}`}
                className="text-blue-600 hover:text-blue-700 font-medium"
              >
                Login here
              </a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/register')({
  component: RegisterPage,
  validateSearch: (search: Record<string, unknown>): SearchParams => {
    return searchParamsSchema.parse(search);
  },
});
