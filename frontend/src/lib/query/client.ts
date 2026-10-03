import { QueryClient } from "@tanstack/react-query";

import { ApiError } from "@/lib/api/errors";

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: false,
        // Retry only network failures and server errors — never 4xx answers.
        retry: (count, error) => count < 2 && (!(error instanceof ApiError) || error.status >= 500),
      },
      mutations: { retry: false },
    },
  });
}

/** Poll quickly at first, then back off (1 s → 2 s → 5 s). */
export function backoffInterval(attempt: number): number {
  return attempt < 5 ? 1000 : attempt < 15 ? 2000 : 5000;
}
