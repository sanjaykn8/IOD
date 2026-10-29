// Thin JSON HTTP client for the Rust core's `iod-server` binary. All
// cryptographic and protocol logic lives in Rust; this file only
// forwards requests and never inspects/transforms secret-shaped fields
// (there aren't any in these responses — the Rust API layer's
// `api::views` module already enforces that no secret ever leaves Rust,
// see rust-core/src/api/views.rs).
import fetch from "node-fetch";
import { config } from "../config";

export interface RustResponse<T = any> {
  ok: boolean;
  status: number;
  body: T;
}

async function call(method: string, path: string, body?: unknown, extra?: Record<string, string>): Promise<RustResponse> {
  const res = await fetch(`${config.rustBaseUrl}${path}`, {
    method,
    headers: body || extra ? { ...(body ? { "Content-Type": "application/json" } : {}), ...(extra ?? {}) } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  let json: any = {};
  try {
    json = await res.json();
  } catch {
    json = { error: "invalid JSON from Rust core" };
  }
  return { ok: res.ok, status: res.status, body: json };
}

export interface RustRawResponse {
  status: number;
  contentType: string;
  body: Buffer;
}

// Raw/text relay for non-JSON bodies (CSV report, image/png artifacts):
// the bytes and Content-Type are passed through unmodified.
async function callRaw(method: string, path: string): Promise<RustRawResponse> {
  const res = await fetch(`${config.rustBaseUrl}${path}`, { method });
  const body = await res.buffer();
  return { status: res.status, contentType: res.headers.get("content-type") || "application/octet-stream", body };
}

export const rust = {
  getRaw: (path: string) => callRaw("GET", path),
  get: (path: string) => call("GET", path),
  post: (path: string, body?: unknown, extra?: Record<string, string>) => call("POST", path, body, extra),
};
