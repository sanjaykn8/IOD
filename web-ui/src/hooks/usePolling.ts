import { useEffect, useState, useCallback } from "react";

export function usePolling<T>(fetcher: () => Promise<T>, intervalMs = 3000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    fetcher()
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e) => setError(e.message || String(e)));
  }, [fetcher]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, intervalMs);
    return () => clearInterval(id);
  }, [refresh, intervalMs]);

  return { data, error, refresh };
}
