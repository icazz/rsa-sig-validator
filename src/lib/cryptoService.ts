/**
 * cryptoService.ts — Satu pintu untuk seluruh operasi kriptografi di UI.
 *
 * Jalur utama: backend Python (`backend/rsa_manual.py`, implementasi RSA
 * manual murni) melalui `apiClient`. Apabila backend tidak dapat dihubungi,
 * otomatis beralih ke mesin lokal (`rsaCrypto.ts`, implementasi manual yang
 * sama dalam TypeScript) sehingga aplikasi tetap berfungsi. Kedua mesin
 * sama-sama full code tanpa pustaka kriptografi dan saling interoperabel
 * (format PEM SPKI/PKCS#8 + signature PKCS#1 v1.5 yang identik).
 */

import type { KeySize } from "./rsaCrypto";
import {
  generateRSAKeyPair,
  exportPrivateKeyPEM,
  exportPublicKeyPEM,
  importPrivateKeyFromPEM,
  importPublicKeyFromPEM,
  signData,
  verifySignature,
  sha256Hex as localSha256Hex,
} from "./rsaCrypto";
import { apiGenerate, apiHash, apiHealth, apiSign, apiVerify } from "./apiClient";

export type Engine = "backend" | "local";

let backendReachable: boolean | null = null;

/** Memeriksa ketersediaan backend (hasilnya di-cache). */
export async function detectEngine(): Promise<Engine> {
  try {
    const h = await apiHealth(4000);
    backendReachable = h.status === "ok";
  } catch {
    backendReachable = false;
  }
  return backendReachable ? "backend" : "local";
}

export function currentEngine(): Engine | null {
  if (backendReachable === null) return null;
  return backendReachable ? "backend" : "local";
}

async function backendAvailable(): Promise<boolean> {
  if (backendReachable === null) await detectEngine();
  return backendReachable === true;
}

export interface KeyPairPEM {
  privateKeyPEM: string;
  publicKeyPEM: string;
  engine: Engine;
}

export async function generateKeyPairPEM(keySize: KeySize): Promise<KeyPairPEM> {
  if (await backendAvailable()) {
    try {
      const res = await apiGenerate(keySize);
      return { privateKeyPEM: res.private_key, publicKeyPEM: res.public_key, engine: "backend" };
    } catch (err) {
      if (err instanceof Error && /Failed to fetch|timeout|merespons|NetworkError/i.test(err.message)) {
        backendReachable = false;
      } else {
        throw err;
      }
    }
  }
  const pair = await generateRSAKeyPair(keySize);
  const [priv, pub] = await Promise.all([
    exportPrivateKeyPEM(pair.privateKey),
    exportPublicKeyPEM(pair.publicKey),
  ]);
  return { privateKeyPEM: priv, publicKeyPEM: pub, engine: "local" };
}

export async function computeHash(data: ArrayBuffer, fileName = "upload"): Promise<{ hash: string; engine: Engine }> {
  if (await backendAvailable()) {
    try {
      const res = await apiHash(data, fileName);
      return { hash: res.sha256, engine: "backend" };
    } catch (err) {
      if (err instanceof Error && /Failed to fetch|timeout|merespons|NetworkError/i.test(err.message)) {
        backendReachable = false;
      } else {
        throw err;
      }
    }
  }
  return { hash: await localSha256Hex(data), engine: "local" };
}

export interface SignResult {
  signature: string;
  hash: string;
  engine: Engine;
}

export async function signDocument(
  privateKeyPEM: string,
  data: ArrayBuffer,
  fileName: string,
): Promise<SignResult> {
  if (await backendAvailable()) {
    try {
      const res = await apiSign(privateKeyPEM, data, fileName);
      return { signature: res.signature, hash: res.sha256, engine: "backend" };
    } catch (err) {
      // Galat validasi dari server (mis. PEM salah) diteruskan ke UI;
      // hanya galat jaringan yang memicu alihan ke mesin lokal.
      if (err instanceof Error && /Failed to fetch|timeout|merespons|NetworkError/i.test(err.message)) {
        backendReachable = false;
      } else {
        throw err;
      }
    }
  }
  const key = await importPrivateKeyFromPEM(privateKeyPEM);
  const [signature, hash] = await Promise.all([signData(key, data), localSha256Hex(data)]);
  return { signature, hash, engine: "local" };
}

export interface VerifyResult {
  valid: boolean;
  computedHash: string;
  engine: Engine;
}

export async function verifyDocument(
  publicKeyPEM: string,
  signature: string,
  data: ArrayBuffer,
  fileName: string,
): Promise<VerifyResult> {
  if (await backendAvailable()) {
    try {
      const res = await apiVerify(publicKeyPEM, signature, data, fileName);
      return { valid: res.valid, computedHash: res.computed_hash, engine: "backend" };
    } catch (err) {
      if (err instanceof Error && /Failed to fetch|timeout|merespons|NetworkError/i.test(err.message)) {
        backendReachable = false;
      } else {
        throw err;
      }
    }
  }
  const key = await importPublicKeyFromPEM(publicKeyPEM);
  const [valid, computedHash] = await Promise.all([
    verifySignature(key, signature, data),
    localSha256Hex(data),
  ]);
  return { valid, computedHash, engine: "local" };
}
