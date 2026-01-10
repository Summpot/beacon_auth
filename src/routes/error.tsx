import { createFileRoute } from '@tanstack/react-router';
import { AlertTriangle } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Card, CardContent } from '@/components/ui/card';

function ErrorPage() {
  return (
    <div className="flex items-center justify-center min-h-screen p-4">
      <div className="w-full max-w-md">
        <Card>
          <CardContent className="p-8">
            <div className="text-center">
              <div className="text-6xl mb-4">⚠️</div>
              <h1 className="text-2xl font-bold mb-4">Invalid Request</h1>
              <p className="text-muted-foreground mb-4">
                This page requires valid challenge and redirect_port parameters.
                <br />
                Please access this page through the Minecraft mod.
              </p>
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  Missing required parameters in URL
                </AlertDescription>
              </Alert>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/error')({
  component: ErrorPage,
});
