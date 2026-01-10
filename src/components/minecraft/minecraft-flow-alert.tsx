import { Gamepad2 } from 'lucide-react';

import { Alert, AlertDescription } from '@/components/ui/alert';

export interface MinecraftFlowAlertProps {
  title: string;
  challenge: string;
  redirectPort: number;
}

export function MinecraftFlowAlert({
  title,
  challenge,
  redirectPort,
}: MinecraftFlowAlertProps) {
  const short =
    challenge.length > 16 ? `${challenge.substring(0, 16)}...` : challenge;

  return (
    <Alert>
      <Gamepad2 className="h-4 w-4" />
      <AlertDescription>
        <div className="space-y-2">
          <span className="text-primary font-medium">{title}</span>
          <div className="space-y-1 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Challenge:</span>
              <span className="text-foreground font-mono text-xs">{short}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Port:</span>
              <span className="text-foreground">{redirectPort}</span>
            </div>
          </div>
        </div>
      </AlertDescription>
    </Alert>
  );
}
