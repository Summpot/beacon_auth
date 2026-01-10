type Fetcher = {
  fetch(request: Request): Promise<Response>;
};

type ExecutionContextLike = {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException?: () => void;
};

interface Env {
  ASSETS: Fetcher;
  BACKEND: Fetcher;
}

const PROXY_PREFIXES = ['/api', '/v1', '/.well-known'] as const;

function shouldProxy(pathname: string): boolean {
  for (const p of PROXY_PREFIXES) {
    if (pathname === p || pathname.startsWith(`${p}/`)) return true;
  }
  return false;
}

function isHtmlRequest(request: Request): boolean {
  const accept = request.headers.get('Accept') || '';
  return accept.includes('text/html');
}

async function proxyToBackend(request: Request, env: Env): Promise<Response> {
  if (!env.BACKEND || typeof env.BACKEND.fetch !== 'function') {
    return new Response('Missing Pages service binding: BACKEND', {
      status: 500,
    });
  }

  const url = new URL(request.url);
  // Use a service binding for the API Worker (configured in `wrangler.jsonc` as `services = [{ binding: "BACKEND", ... }]`).
  // The Fetcher binding determines routing; we keep the original URL so downstream logic can
  // see the real Pages host.
  const upstreamUrl = new URL(request.url);

  const headers = new Headers(request.headers);
  // Avoid forbidden/host-related header issues; the Request URL determines the host.
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

  return env.BACKEND.fetch(new Request(upstreamUrl.toString(), init));
}

export default {
  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContextLike,
  ): Promise<Response> {
    const url = new URL(request.url);

    if (shouldProxy(url.pathname)) {
      return proxyToBackend(request, env);
    }

    if (!env.ASSETS || typeof env.ASSETS.fetch !== 'function') {
      return new Response('Missing Pages assets binding: ASSETS', {
        status: 500,
      });
    }

    // Serve static assets from Pages.
    const resp = await env.ASSETS.fetch(request);

    // SPA fallback: for HTML navigations, serve index.html on 404.
    if (
      (request.method === 'GET' || request.method === 'HEAD') &&
      resp.status === 404 &&
      isHtmlRequest(request)
    ) {
      const indexReq = new Request(new URL('/index.html', url), request);
      return env.ASSETS.fetch(indexReq);
    }

    return resp;
  },
};
