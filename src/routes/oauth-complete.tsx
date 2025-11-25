import { createFileRoute } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { fetchWithAuth } from '../utils/api';

function OAuthCompletePage() {
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState('Processing authentication...');

  useEffect(() => {
    const completeAuth = async () => {
      try {
        // Retrieve saved parameters from sessionStorage
        const challenge = sessionStorage.getItem('minecraft_challenge');
        const redirectPortStr = sessionStorage.getItem('minecraft_redirect_port');

        // Check if we're in Minecraft mode or normal web mode
        if (!challenge || !redirectPortStr) {
          // Normal web OAuth login - redirect to home page
          setStatus('success');
          setMessage('Authentication successful! Redirecting to home...');
          
          // Clean up any partial sessionStorage data
          sessionStorage.removeItem('minecraft_challenge');
          sessionStorage.removeItem('minecraft_redirect_port');
          
          setTimeout(() => {
            window.location.href = '/';
          }, 1000);
          return;
        }

        // Minecraft mode - generate JWT and redirect to mod
        const redirect_port = parseInt(redirectPortStr, 10);

        // Get Minecraft JWT using the session cookie (set by OAuth callback)
        const jwtResponse = await fetchWithAuth('/api/v1/minecraft-jwt', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            challenge,
            redirect_port,
            profile_url: window.location.origin + '/profile',
          }),
        });

        if (!jwtResponse.ok) {
          setStatus('error');
          setMessage('Failed to generate Minecraft token. Please try again.');
          return;
        }

        const result = await jwtResponse.json();
        
        // Clean up sessionStorage
        sessionStorage.removeItem('minecraft_challenge');
        sessionStorage.removeItem('minecraft_redirect_port');
        
        if (result.redirectUrl) {
          setStatus('success');
          setMessage('Authentication successful! Redirecting to Minecraft...');
          setTimeout(() => {
            window.location.href = result.redirectUrl;
          }, 1000);
        }
      } catch (error) {
        console.error('OAuth completion error:', error);
        setStatus('error');
        setMessage('An error occurred during authentication. Please try again.');
      }
    };

    completeAuth();
  }, []);

  return (
    <div className="flex items-center justify-center min-h-screen p-4 bg-linear-to-br from-blue-50 to-indigo-100">
      <div className="w-full max-w-md">
        <div className="bg-white rounded-lg shadow-xl p-8">
          <div className="text-center">
            {status === 'loading' && (
              <>
                <div className="inline-block animate-spin rounded-full h-16 w-16 border-4 border-solid border-blue-600 border-r-transparent mb-4" />
                <h2 className="text-2xl font-bold text-gray-900 mb-2">
                  Processing...
                </h2>
              </>
            )}

            {status === 'success' && (
              <>
                <div className="text-6xl mb-4">✓</div>
                <h2 className="text-2xl font-bold text-green-600 mb-2">
                  Success!
                </h2>
              </>
            )}

            {status === 'error' && (
              <>
                <div className="text-6xl mb-4">✗</div>
                <h2 className="text-2xl font-bold text-red-600 mb-2">
                  Authentication Failed
                </h2>
              </>
            )}

            <p className="text-gray-600">{message}</p>
          </div>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/oauth-complete')({
  component: OAuthCompletePage,
});
