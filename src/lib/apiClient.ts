/**
 * apiClient.ts — Klien HTTP untuk backend Python (FastAPI).
 * Seluruh komputasi kriptografi dikerjakan oleh `backend/rsa_manual.py`
 * (implementasi RSA manual murni); modul ini hanya mengantar data.
 */

interface EnvMeta {
  env?: Record<string, string | undefined>;
}

function apiBase(): string {
  try {
    const meta = import.meta as unknown as EnvMeta;
    return meta.env?.VITE_API_URL ?? "http://localhost:8000";
  } catch {
    return "http://localhost:8000";
  }
}

async function request(path: string, init: RequestInit, timeoutMs: number): Promise<unknown> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(apiBase() + path, { ...init, signal: ctrl.signal });
    const body = (await res.json()) as { detail?: string } & Record<string, unknown>;
    if (!res.ok) {
      throw new Error(typeof body.detail === "string" ? body.detail : `Backend error ${res.status}`);
    }
    return body;
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new Error("Backend tidak merespons (timeout).");
    }
    throw err instanceof Error ? err : new Error(String(err));
  } finally {
    clearTimeout(timer);
  }
}

function fileForm(data: ArrayBuffer, fileName: string, extra?: Record<string, string>): FormData {
  const form = new FormData();
  form.append("file", new Blob([data]), fileName || "upload");
  if (extra) {
    for (const [k, v] of Object.entries(extra)) form.append(k, v);
  }
  return form;
}

export interface GenerateResponse {
  private_key: string;
  public_key: string;
  key_size: number;
}

export interface HashResponse {
  file_name: string;
  size: number;
  sha256: string;
}

export interface SignResponse {
  file_name: string;
  sha256: string;
  signature: string;
}

export interface VerifyResponse {
  valid: boolean;
  computed_hash: string;
}

export interface HealthResponse {
  status: string;
  engine: string;
}

export async function apiHealth(timeoutMs = 4000): Promise<HealthResponse> {
  return (await request("/api/health", { method: "GET" }, timeoutMs)) as HealthResponse;
}

export async function apiGenerate(keySize: 2048 | 4096): Promise<GenerateResponse> {
  return (await request(
    "/api/generate",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key_size: keySize }) },
    300000,
  )) as GenerateResponse;
}

export async function apiHash(data: ArrayBuffer, fileName: string): Promise<HashResponse> {
  return (await request(
    "/api/hash",
    { method: "POST", body: fileForm(data, fileName) },
    120000,
  )) as HashResponse;
}

export async function apiSign(
  privateKeyPEM: string,
  data: ArrayBuffer,
  fileName: string,
): Promise<SignResponse> {
  return (await request(
    "/api/sign",
    { method: "POST", body: fileForm(data, fileName, { private_key: privateKeyPEM }) },
    120000,
  )) as SignResponse;
}

export async function apiVerify(
  publicKeyPEM: string,
  signature: string,
  data: ArrayBuffer,
  fileName: string,
): Promise<VerifyResponse> {
  return (await request(
    "/api/verify",
    { method: "POST", body: fileForm(data, fileName, { public_key: publicKeyPEM, signature }) },
    120000,
  )) as VerifyResponse;
}
