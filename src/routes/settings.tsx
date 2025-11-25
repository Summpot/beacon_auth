import { createFileRoute, Link } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { startRegistration } from '@simplewebauthn/browser';
import { fetchWithAuth } from '../utils/api';

// Password change form schema
const passwordChangeSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string().min(6, 'Password must be at least 6 characters'),
  confirmPassword: z.string().min(1, 'Please confirm your password'),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

type PasswordChangeData = z.infer<typeof passwordChangeSchema>;

interface UserInfo {
  id: number;
  username: string;
}

interface PasskeyInfo {
  id: number;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

function SettingsPage() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [showPasskeyModal, setShowPasskeyModal] = useState(false);
  const [passkeyName, setPasskeyName] = useState('');

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    reset,
  } = useForm<PasswordChangeData>({
    resolver: zodResolver(passwordChangeSchema),
  });

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Fetch user info
        const userResponse = await fetchWithAuth('/api/v1/user/me');

        if (!userResponse.ok) {
          setLoading(false);
          return;
        }

        const userData = await userResponse.json();
        setUser(userData);

        // Fetch passkeys
        const passkeysResponse = await fetchWithAuth('/api/v1/passkey/list');

        if (passkeysResponse.ok) {
          const passkeysData = await passkeysResponse.json();
          setPasskeys(passkeysData.passkeys || []);
        }
      } catch {
        // Error handled by fetchWithAuth (will redirect if needed)
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const onPasswordChange = async (data: PasswordChangeData) => {
    try {
      const response = await fetchWithAuth('/api/v1/user/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          current_password: data.currentPassword,
          new_password: data.newPassword,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        setMessage({
          type: 'error',
          text: errorData.message || 'Failed to change password',
        });
        return;
      }

      setMessage({
        type: 'success',
        text: 'Password changed successfully!',
      });
      reset();
    } catch (error) {
      setMessage({
        type: 'error',
        text: 'Failed to connect to server',
      });
    }
  };

  const handleRegisterPasskey = async () => {
    setShowPasskeyModal(true);
  };

  const handlePasskeyModalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const name = passkeyName.trim();
    if (!name) {
      setMessage({ type: 'error', text: 'Passkey name is required' });
      return;
    }

    try {
      // Step 1: Start registration
      const startResponse = await fetchWithAuth('/api/v1/passkey/register/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name }),
      });

      if (!startResponse.ok) {
        throw new Error('Failed to start passkey registration');
      }

      const data = await startResponse.json();

      // Step 2: Use SimpleWebAuthn to handle the registration ceremony
      // Pass the publicKey field directly (SimpleWebAuthn expects PublicKeyCredentialCreationOptions)
      const credential = await startRegistration(data.creation_options.publicKey);

      // Step 3: Finish registration
      const finishResponse = await fetchWithAuth('/api/v1/passkey/register/finish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          credential,
          name,
        }),
      });

      if (!finishResponse.ok) {
        throw new Error('Failed to complete passkey registration');
      }

      setMessage({
        type: 'success',
        text: 'Passkey registered successfully!',
      });

      // Close modal and reset form
      setShowPasskeyModal(false);
      setPasskeyName('');

      // Refresh passkeys list
      const passkeysResponse = await fetchWithAuth('/api/v1/passkey/list');
      if (passkeysResponse.ok) {
        const passkeysData = await passkeysResponse.json();
        setPasskeys(passkeysData.passkeys || []);
      }
    } catch (error) {
      console.error('Passkey registration failed:', error);
      setMessage({
        type: 'error',
        text: `Failed to register passkey: ${error instanceof Error ? error.message : 'Unknown error'}`,
      });
      setShowPasskeyModal(false);
      setPasskeyName('');
    }
  };

  const handleDeletePasskey = async (id: number, name: string) => {
    if (!confirm(`Are you sure you want to delete passkey "${name}"?`)) {
      return;
    }

    try {
      const response = await fetchWithAuth('/api/v1/passkey/delete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ id }),
      });

      if (!response.ok) {
        throw new Error('Failed to delete passkey');
      }

      setMessage({
        type: 'success',
        text: 'Passkey deleted successfully!',
      });

      // Refresh passkeys list
      setPasskeys(passkeys.filter((p) => p.id !== id));
    } catch (error) {
      console.error('Passkey deletion failed:', error);
      setMessage({
        type: 'error',
        text: `Failed to delete passkey: ${error instanceof Error ? error.message : 'Unknown error'}`,
      });
    }
  };

  if (loading) {
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
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-linear-to-br from-blue-50 to-indigo-100 p-4">
      <div className="max-w-4xl mx-auto py-8">
        {/* Header */}
        <div className="mb-6">
          <Link
            to="/"
            className="inline-flex items-center text-blue-600 hover:text-blue-700 mb-4"
          >
            <svg
              className="w-5 h-5 mr-2"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <title>Back Arrow</title>
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M15 19l-7-7 7-7"
              />
            </svg>
            Back to Home
          </Link>
          <h1 className="text-3xl font-bold text-gray-900">Profile Settings</h1>
          <p className="text-gray-600 mt-2">
            Manage your password and passkeys for {user.username}
          </p>
        </div>

        {/* Message Display */}
        {message && (
          <div
            className={`mb-6 p-4 rounded-lg ${
              message.type === 'success'
                ? 'bg-green-50 text-green-800 border border-green-200'
                : 'bg-red-50 text-red-800 border border-red-200'
            }`}
          >
            <div className="flex items-center">
              <span className="text-xl mr-3">
                {message.type === 'success' ? '✓' : '✗'}
              </span>
              <p>{message.text}</p>
            </div>
          </div>
        )}

        {/* Change Password Card */}
        <div className="bg-white rounded-lg shadow-xl p-8 mb-6">
          <h2 className="text-xl font-bold text-gray-900 mb-4">
            Change Password
          </h2>
          <form onSubmit={handleSubmit(onPasswordChange)} className="space-y-4">
            <div>
              <label
                htmlFor="currentPassword"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                Current Password
              </label>
              <input
                id="currentPassword"
                type="password"
                {...register('currentPassword')}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                placeholder="Enter current password"
                disabled={isSubmitting}
              />
              {errors.currentPassword && (
                <p className="mt-1 text-sm text-red-600">
                  {errors.currentPassword.message}
                </p>
              )}
            </div>

            <div>
              <label
                htmlFor="newPassword"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                New Password
              </label>
              <input
                id="newPassword"
                type="password"
                {...register('newPassword')}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                placeholder="Enter new password (min 6 characters)"
                disabled={isSubmitting}
              />
              {errors.newPassword && (
                <p className="mt-1 text-sm text-red-600">
                  {errors.newPassword.message}
                </p>
              )}
            </div>

            <div>
              <label
                htmlFor="confirmPassword"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                Confirm New Password
              </label>
              <input
                id="confirmPassword"
                type="password"
                {...register('confirmPassword')}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                placeholder="Confirm new password"
                disabled={isSubmitting}
              />
              {errors.confirmPassword && (
                <p className="mt-1 text-sm text-red-600">
                  {errors.confirmPassword.message}
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors font-medium"
            >
              {isSubmitting ? 'Changing Password...' : 'Change Password'}
            </button>
          </form>
        </div>

        {/* Passkeys Card */}
        <div className="bg-white rounded-lg shadow-xl p-8">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-xl font-bold text-gray-900">
                Passkeys
              </h2>
              <p className="text-sm text-gray-600 mt-1">
                Use biometric authentication for passwordless login
              </p>
            </div>
            <button
              type="button"
              onClick={handleRegisterPasskey}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium text-sm"
            >
              + Add Passkey
            </button>
          </div>

          {passkeys.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <div className="text-4xl mb-3">🔑</div>
              <p>No passkeys registered yet</p>
              <p className="text-sm mt-1">
                Add a passkey for faster, more secure authentication
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {passkeys.map((passkey) => (
                <div
                  key={passkey.id}
                  className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50"
                >
                  <div className="flex-1">
                    <h3 className="font-semibold text-gray-900">
                      {passkey.name}
                    </h3>
                    <p className="text-sm text-gray-600">
                      Created: {new Date(passkey.created_at).toLocaleDateString()}
                    </p>
                    {passkey.last_used_at && (
                      <p className="text-sm text-gray-600">
                        Last used: {new Date(passkey.last_used_at).toLocaleDateString()}
                      </p>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => handleDeletePasskey(passkey.id, passkey.name)}
                    className="ml-4 px-3 py-1 text-sm text-red-600 hover:text-red-700 border border-red-300 rounded hover:bg-red-50 transition-colors"
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Info box */}
          <div className="mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex">
              <svg
                className="w-5 h-5 text-blue-600 mr-3 shrink-0 mt-0.5"
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
                <p className="font-medium mb-1">What are passkeys?</p>
                <p>
                  Passkeys are a secure, passwordless authentication method that uses
                  your device's biometric authentication (fingerprint, face recognition)
                  or PIN. They're more secure than passwords and easier to use.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Passkey Name Modal */}
        {showPasskeyModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-lg shadow-xl max-w-md w-full p-6">
              <h3 className="text-xl font-bold text-gray-900 mb-4">
                Add New Passkey
              </h3>
              <form onSubmit={handlePasskeyModalSubmit}>
                <div className="mb-4">
                  <label
                    htmlFor="passkeyName"
                    className="block text-sm font-medium text-gray-700 mb-2"
                  >
                    Passkey Name
                  </label>
                  <input
                    id="passkeyName"
                    type="text"
                    value={passkeyName}
                    onChange={(e) => setPasskeyName(e.target.value)}
                    placeholder='e.g., "My Phone", "YubiKey"'
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                  />
                  <p className="mt-2 text-sm text-gray-600">
                    Give your passkey a memorable name to identify this device or security key.
                  </p>
                </div>
                <div className="flex gap-3">
                  <button
                    type="button"
                    onClick={() => {
                      setShowPasskeyModal(false);
                      setPasskeyName('');
                    }}
                    className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
                  >
                    Continue
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export const Route = createFileRoute('/settings')({
  component: SettingsPage,
});
