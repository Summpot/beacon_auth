import { createFileRoute, Link } from '@tanstack/react-router';
import { CheckCircle2, Home, Loader2, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { BeaconIcon } from '@/components/beacon-icon';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { apiClient } from '../utils/api';

function OAuthCompletePage() {
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>(
    'loading',
  );
  const [message, setMessage] = useState('Processing authentication...');

  useEffect(() => {
    const completeAuth = async () => {
      try {
        // Retrieve saved parameters from sessionStorage
        const challenge = sessionStorage.getItem('minecraft_challenge');
        const redirectPortStr = sessionStorage.getItem(
          'minecraft_redirect_port',
        );

        // Check if we're in Minecraft mode or normal web mode
        if (!challenge || !redirectPortStr) {
          // Normal web OAuth login - redirect to profile page
          setStatus('success');
          setMessage('Authentication successful! Redirecting to profile...');

          // Clean up any partial sessionStorage data
          sessionStorage.removeItem('minecraft_challenge');
          sessionStorage.removeItem('minecraft_redirect_port');

          setTimeout(() => {
            window.location.href = '/profile';
          }, 1000);
          return;
        }

        // Minecraft mode - generate JWT and redirect to mod
        const redirect_port = parseInt(redirectPortStr, 10);

        // Get Minecraft JWT using the session cookie (set by OAuth callback)
        const result = await apiClient<{ redirectUrl?: string }>(
          '/api/v1/minecraft-jwt',
          {
            method: 'POST',
            body: {
              challenge,
              redirect_port,
              profile_url: window.location.origin + '/profile',
            },
          },
        );

        // Clean up sessionStorage
        sessionStorage.removeItem('minecraft_challenge');
        sessionStorage.removeItem('minecraft_redirect_port');

        if (result?.redirectUrl) {
          setStatus('success');
          setMessage('Authentication successful! Redirecting to Minecraft...');
          setTimeout(() => {
            window.location.href = result.redirectUrl as string;
          }, 1000);
        }
      } catch (error) {
        console.error('OAuth completion error:', error);
        setStatus('error');
        setMessage(
          'An error occurred during authentication. Please try again.',
        );
      }
    };

    completeAuth();
  }, []);

  return (
    <div className="flex items-center justify-center min-h-screen p-4">
      <div className="w-full max-w-md">
        <Card>
          <CardContent className="p-8">
            <div className="text-center">
              {status === 'loading' && (
                <>
                  <div className="inline-block mb-6">
                    <BeaconIcon className="w-24 h-24" />
                  </div>
                  <h2 className="text-2xl font-bold text-foreground mb-4">
                    Processing...
                  </h2>
                  <div className="flex items-center justify-center gap-3 mb-4">
                    <Loader2 className="h-5 w-5 text-primary animate-spin" />
                    <span className="text-muted-foreground">Please wait</span>
                  </div>
                </>
              )}

              {status === 'success' && (
                <>
                  <div className="inline-block mb-6">
                    <div className="w-24 h-24 rounded-full bg-green-500/20 flex items-center justify-center border-2 border-green-500/50">
                      <CheckCircle2 className="w-12 h-12 text-green-500" />
                    </div>
                  </div>
                  <h2 className="text-2xl font-bold text-green-500 mb-4">
                    Success!
                  </h2>
                </>
              )}

              {status === 'error' && (
                <>
                  <div className="inline-block mb-6">
                    <div className="w-24 h-24 rounded-full bg-destructive/20 flex items-center justify-center border-2 border-destructive/50">
                      <XCircle className="w-12 h-12 text-destructive" />
                    </div>
                  </div>
                  <h2 className="text-2xl font-bold text-destructive mb-4">
                    Authentication Failed
                  </h2>
                </>
              )}

              <p className="text-muted-foreground mb-6">{message}</p>

              {status === 'error' && (
                <div className="flex flex-col gap-3">
                  <Link to="/login">
                    <Button className="w-full">Try Again</Button>
                  </Link>
                  <Link to="/">
                    <Button variant="outline" className="w-full">
                      <Home className="mr-2 h-4 w-4" />
                      Back to Home
                    </Button>
                  </Link>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/oauth-complete')({
  component: OAuthCompletePage,
});
