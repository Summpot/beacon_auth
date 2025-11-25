/**
 * API utility for handling authenticated requests with automatic token refresh
 * Optimized for use with TanStack Query
 */

let isRefreshing = false;
let refreshPromise: Promise<boolean> | null = null;

/**
 * Attempt to refresh the access token using the refresh token
 * @returns true if refresh was successful, false otherwise
 */
async function refreshAccessToken(): Promise<boolean> {
  // If already refreshing, wait for that promise
  if (isRefreshing && refreshPromise) {
    return refreshPromise;
  }

  isRefreshing = true;
  refreshPromise = (async () => {
    try {
      const response = await fetch('/api/v1/refresh', {
        method: 'POST',
        credentials: 'include',
      });

      if (response.ok) {
        return true;
      }
      return false;
    } catch (error) {
      console.error('Token refresh failed:', error);
      return false;
    } finally {
      isRefreshing = false;
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

/**
 * Custom error class for API errors
 */
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public data?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/**
 * Fetch wrapper that automatically handles 401 responses by refreshing tokens
 * If refresh fails, redirects to login page
 * 
 * @param url - The URL to fetch
 * @param options - Fetch options (will automatically add credentials: 'include')
 * @returns Response object
 * @throws Error if the request fails after token refresh
 */
export async function fetchWithAuth(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  // Always include credentials for authenticated requests
  const fetchOptions: RequestInit = {
    ...options,
    credentials: 'include',
  };

  // Make the initial request
  let response = await fetch(url, fetchOptions);

  // If we get 401 Unauthorized, try to refresh the token
  if (response.status === 401) {
    const refreshed = await refreshAccessToken();

    if (refreshed) {
      // Retry the original request with new tokens
      response = await fetch(url, fetchOptions);
      
      // If still 401 after refresh, redirect to login
      if (response.status === 401) {
        redirectToLogin();
      }
    } else {
      // Refresh failed, redirect to login
      redirectToLogin();
    }
  }

  return response;
}

/**
 * Redirect to login page
 * This clears the session and sends user back to login
 */
function redirectToLogin(): void {
  // Redirect to login page
  window.location.href = '/login';
}

/**
 * Type-safe JSON fetch with automatic auth handling
 * Throws ApiError for better error handling in TanStack Query
 */
export async function fetchJsonWithAuth<T = unknown>(
  url: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetchWithAuth(url, options);
  
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new ApiError(
      response.status,
      errorData.message || `Request failed with status ${response.status}`,
      errorData
    );
  }
  
  return response.json();
}

/**
 * Query key factory for consistent cache keys
 * Use this with TanStack Query to ensure proper cache management
 */
export const queryKeys = {
  user: () => ['user'] as const,
  userMe: () => [...queryKeys.user(), 'me'] as const,
  passkeys: () => ['passkeys'] as const,
  config: () => ['config'] as const,
};
