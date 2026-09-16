// Thin JSON HTTP client for the Python RAG/mock-LLM service.
import fetch from "node-fetch";
import { config } from "../config";

export interface PyResponse<T = any> {
  ok: boolean;
  status: number;
  body: T;
}

async function call(method: string, path: string, body?: unknown): Promise<PyResponse> {
  try {
    const res = await fetch(`${config.pythonBaseUrl}${path}`, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    let json: any = {};
    try {
      json = await res.json();
    } catch {
      json = { error: "invalid JSON from Python service" };
    }
    return { ok: res.ok, status: res.status, body: json };
  } catch (e: any) {
    return { ok: false, status: 502, body: { error: `Python RAG service unavailable: ${e.message}` } };
  }
}

export const python = {
  get: (path: string) => call("GET", path),
  post: (path: string, body?: unknown) => call("POST", path, body),
};
