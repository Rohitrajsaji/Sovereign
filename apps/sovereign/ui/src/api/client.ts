import type { ErrorResponse } from "./generated";

const CSRF_HEADER = "X-Sovereign-CSRF";

let csrfToken = "";

export function setCsrfToken(token: string): void {
  csrfToken = token;
}

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.method && init.method !== "GET") {
    headers.set("content-type", "application/json");
    if (csrfToken) {
      headers.set(CSRF_HEADER, csrfToken);
    }
  }
  const response = await fetch(path, { ...init, headers });
  const body: unknown = await response.json().catch(() => ({ error: response.statusText }));
  if (!response.ok) {
    const message =
      typeof body === "object" && body && "error" in body
        ? String((body as ErrorResponse).error)
        : response.statusText;
    throw new ApiError(response.status, message);
  }
  return body as T;
}

export function connectEvents(onEvent: (id: string, data: string) => void): () => void {
  let closed = false;
  let source: EventSource | null = null;
  let lastId = "";

  const open = () => {
    if (closed) {
      return;
    }
    const url = lastId ? `/v2/events/stream?after=${encodeURIComponent(lastId)}` : "/v2/events/stream";
    source = new EventSource(url);
    source.onmessage = (event) => {
      if (event.lastEventId) {
        lastId = event.lastEventId;
      }
      onEvent(event.lastEventId, event.data);
    };
    source.onerror = () => {
      source?.close();
      window.setTimeout(open, 1500);
    };
  };

  open();
  return () => {
    closed = true;
    source?.close();
  };
}
