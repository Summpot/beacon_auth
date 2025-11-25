import { createFileRoute, Link } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { z } from 'zod';
import { fetchWithAuth, queryKeys } from '../utils/api';

// Define search params schema for status messages
const searchParamsSchema = z.object({
  status: z.enum(['success', 'error']).optional(),
  message: z.string().optional(),
});

interface UserInfo {
  id: number;
  username: string;
}

// Query function to fetch user info
async function fetchUserInfo(): Promise<UserInfo | null> {
  const response = await fetchWithAuth('/api/v1/user/me');

  if (!response.ok) {
    return null;
  }

  return response.json();
}

function ProfilePage() {
  const { status, message } = Route.useSearch();
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const queryClient = useQueryClient();

  // Use TanStack Query to fetch user info
  const { data: user, isLoading } = useQuery({
    queryKey: queryKeys.userMe(),
    queryFn: fetchUserInfo,
  });

  // Logout mutation
  const logoutMutation = useMutation({
    mutationFn: async () => {
      const response = await fetchWithAuth('/api/v1/logout', {
        method: 'POST',
      });
      if (!response.ok) {
        throw new Error('Logout failed');
      }
    },
    onSuccess: () => {
      queryClient.setQueryData(queryKeys.userMe(), null);
    },
  });

  useEffect(() => {
    // Show status message from URL params if present
    if (status && message) {
      setStatusMessage({
        type: status,
        text: decodeURIComponent(message.replace(/\+/g, ' ')),
      });

      // Clear status message after 5 seconds
      const timer = setTimeout(() => {
        setStatusMessage(null);
      }, 5000);

      return () => clearTimeout(timer);
    }
  }, [status, message]);

  const handleLogout = () => {
    logoutMutation.mutate();
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <div className="text-gray-600">Loading...</div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <div className="w-full max-w-md">
          <div className="bg-white rounded-lg shadow-xl p-8">
            <div className="text-center">
              <div className="text-6xl mb-4">🔐</div>
              <h1 className="text-2xl font-bold text-gray-900 mb-4">
                Not Authenticated
              </h1>
              <p className="text-gray-600 mb-6">
                You must log in through the Minecraft mod to access this page.
              </p>
              <div className="bg-blue-50 text-blue-600 px-4 py-3 rounded-lg text-sm">
                This page is only accessible after authenticating through Minecraft.
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-linear-to-br from-blue-50 to-indigo-100 p-4">
      <div className="max-w-4xl mx-auto py-8">
        {/* Status Message */}
        {statusMessage && (
          <div
            className={`mb-6 p-4 rounded-lg ${
              statusMessage.type === 'success'
                ? 'bg-green-50 text-green-800 border border-green-200'
                : 'bg-red-50 text-red-800 border border-red-200'
            }`}
          >
            <div className="flex items-center">
              <span className="text-xl mr-3">
                {statusMessage.type === 'success' ? '✓' : '✗'}
              </span>
              <p>{statusMessage.text}</p>
            </div>
          </div>
        )}

        {/* Header */}
        <div className="bg-white rounded-lg shadow-xl p-8 mb-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 mb-2">
                Welcome, {user.username}! 👋
              </h1>
              <p className="text-gray-600">
                Manage your BeaconAuth account
              </p>
            </div>
            <div className="flex gap-3">
              <Link
                to="/"
                className="px-4 py-2 text-sm font-medium text-gray-600 hover:text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Home
              </Link>
              <button
                type="button"
                onClick={handleLogout}
                className="px-4 py-2 text-sm font-medium text-red-600 hover:text-red-700 border border-red-300 rounded-lg hover:bg-red-50 transition-colors"
              >
                Logout
              </button>
            </div>
          </div>
        </div>

        {/* Account Info Card */}
        <div className="bg-white rounded-lg shadow-xl p-8 mb-6">
          <h2 className="text-xl font-bold text-gray-900 mb-4">
            Account Information
          </h2>
          <div className="space-y-3">
            <div className="flex justify-between border-b border-gray-200 pb-3">
              <span className="font-medium text-gray-700">User ID:</span>
              <span className="text-gray-600">{user.id}</span>
            </div>
            <div className="flex justify-between border-b border-gray-200 pb-3">
              <span className="font-medium text-gray-700">Username:</span>
              <span className="text-gray-600">{user.username}</span>
            </div>
          </div>
        </div>

        {/* Quick Actions Card */}
        <div className="bg-white rounded-lg shadow-xl p-8">
          <h2 className="text-xl font-bold text-gray-900 mb-4">
            Quick Actions
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Link
              to="/settings"
              className="flex items-center justify-between p-4 border-2 border-gray-200 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-all group"
            >
              <div>
                <h3 className="font-semibold text-gray-900 group-hover:text-blue-600">
                  ⚙️ Profile Settings
                </h3>
                <p className="text-sm text-gray-600">
                  Change password and manage passkeys
                </p>
              </div>
              <svg
                className="w-6 h-6 text-gray-400 group-hover:text-blue-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <title>Arrow Right</title>
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 5l7 7-7 7"
                />
              </svg>
            </Link>

            <div className="flex items-center justify-between p-4 border-2 border-gray-200 rounded-lg bg-gray-50">
              <div>
                <h3 className="font-semibold text-gray-500">
                  🎮 Minecraft Server
                </h3>
                <p className="text-sm text-gray-500">
                  Connected via BeaconAuth Mod
                </p>
              </div>
              <svg
                className="w-6 h-6 text-green-500"
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <title>Checkmark</title>
                <path
                  fillRule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                  clipRule="evenodd"
                />
              </svg>
            </div>
          </div>
        </div>

        {/* Info Box */}
        <div className="mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex">
            <svg
              className="w-6 h-6 text-blue-600 mr-3 shrink-0"
              fill="currentColor"
              viewBox="0 0 20 20"
            >
              <title>Information</title>
              <path
                fillRule="evenodd"
                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
                clipRule="evenodd"
              />
            </svg>
            <div className="text-sm text-blue-800">
              <p className="font-medium mb-1">Secure Authentication</p>
              <p>
                Your session is protected with ES256 encryption and secure
                HttpOnly cookies. For enhanced security, consider setting up
                passkey authentication in your profile settings.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/profile')({
  component: ProfilePage,
  validateSearch: searchParamsSchema,
});
