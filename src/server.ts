import handler, { createServerEntry } from '@tanstack/react-start/server-entry';

type Fetcher = {
  fetch(request: Request): Promise<Response>;
};

type ExecutionContextLike = {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException?: () => void;
};

export interface Env {
  BACKEND: Fetcher;
  CF_VERSION_METADATA: WorkerVersionMetadata;
}

declare global {
  interface Request {
    runtime?: {
      name: string;
      cloudflare?: {
        env: Env;
        context: ExecutionContextLike;
      };
    };
  }
}

const PROXY_PREFIXES = ['/api', '/v1', '/.well-known'] as const;

function shouldProxy(pathname: string): boolean {
  for (const p of PROXY_PREFIXES) {
    if (pathname === p || pathname.startsWith(`${p}/`)) return true;
  }
  return false;
}

async function proxyToBackend(request: Request, env: Env): Promise<Response> {
  if (!env.BACKEND || typeof env.BACKEND.fetch !== 'function') {
    return new Response('Missing Pages service binding: BACKEND', {
      status: 500,
    });
  }

  const url = new URL(request.url);
  const upstreamUrl = new URL(request.url);

  const headers = new Headers(request.headers);
  headers.delete('host');
  headers.delete('Host');
  headers.set('X-Forwarded-Host', url.host);
  headers.set('X-Forwarded-Proto', url.protocol.replace(':', ''));

  const init: RequestInit = {
    method: request.method,
    headers,
    redirect: 'manual',
    body:
      request.method === 'GET' || request.method === 'HEAD'
        ? undefined
        : request.body,
  };

  return env.BACKEND.fetch(new Request(upstreamUrl.toString(), init)).catch(
    (err) => {
      console.error('Error proxying request to backend:', err);
      return new Response('Error connecting to backend service', {
        status: 502,
      });
    },
  );
}

export default createServerEntry({
  fetch(request, opts) {
    const url = new URL(request.url);
    if (
      shouldProxy(url.pathname) &&
      request.runtime &&
      request.runtime.cloudflare
    ) {
      return proxyToBackend(request, request.runtime.cloudflare.env);
    }
    return handler.fetch(request, opts);
  },
});
