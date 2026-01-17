import * as Sentry from '@sentry/cloudflare';
import { createMiddleware, createStart } from '@tanstack/react-start';

const sentryMiddleware = createMiddleware().server(({ next, request }) => {
  if (request.runtime?.cloudflare) {
    const env = request.runtime.cloudflare?.env;
    Sentry.sentryPagesPlugin(() => {
      const { id: versionId } = env.CF_VERSION_METADATA;
      return {
        dsn: 'https://d7cb62a21d7b73d3c3db8dcd262a890b@o4510041882755072.ingest.us.sentry.io/4510726472728576',
        release: versionId,
        sendDefaultPii: true,
      };
    });
  }
  return next();
});

export const startInstance = createStart(() => {
  return {
    requestMiddleware: [sentryMiddleware],
  };
});
