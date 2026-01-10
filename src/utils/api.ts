import {
  type FetchOptions,
  type FetchRequest,
  type FetchResponse,
  ofetch,
} from 'ofetch';

declare module 'ofetch' {
  interface FetchOptions {
    /**
     * Whether the request should trigger the 401 refresh flow.
     * Defaults to true.
     */
    requiresAuth?: boolean;
    /**
     * Internal flag to prevent infinite retry loops.
     */
    isRetry?: boolean;
  }
}

const baseFetch = ofetch.create({
  credentials: 'include',
  retry: 0,
  ignoreResponseError: true,
});

let refreshPromise: Promise<boolean> | null = null;

async function refreshAccessToken(): Promise<boolean> {
  if (refreshPromise) {
    return refreshPromise;
  }

  refreshPromise = (async () => {
    try {
      const response = await baseFetch.raw('/api/v1/refresh', {
        method: 'POST',
        requiresAuth: false,
        ignoreResponseError: true,
      });

      return response.status === 200;
    } catch (error) {
      console.error('Token refresh failed:', error);
      return false;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public data?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function redirectToLogin(): never {
  window.location.href = '/login';
  throw new ApiError(401, 'Redirecting to login');
}

function createApiClient() {
  const client = baseFetch.create({
    async onResponse(context) {
      const { response, request, options } = context;

      if (!response) {
        return;
      }

      const requiresAuth = options?.requiresAuth !== false;

      if (response.status === 401 && requiresAuth) {
        if (options?.isRetry) {
          redirectToLogin();
        }

        const refreshed = await refreshAccessToken();

        if (refreshed) {
          const retryResponse = await client.raw(request as FetchRequest, {
            ...(options as FetchOptions),
            isRetry: true,
          });

          context.response = retryResponse;
        } else {
          redirectToLogin();
        }
      }

      if (context.response && context.response.status >= 400) {
        const data =
          (context.response as FetchResponse<unknown> & { _data?: unknown })
            ._data ??
          (await context.response
            .clone()
            .json()
            .catch(() => undefined));

        throw new ApiError(
          context.response.status,
          (data as { message?: string } | undefined)?.message ??
            `Request failed with status ${context.response.status}`,
          data,
        );
      }
    },
    async onRequestError({ error }) {
      throw new ApiError(0, error?.message ?? 'Network request failed');
    },
  });

  return client;
}

export const apiClient = createApiClient();

export const queryKeys = {
  user: () => ['user'] as const,
  userMe: () => [...queryKeys.user(), 'me'] as const,
  passkeys: () => ['passkeys'] as const,
  config: () => ['config'] as const,
};
