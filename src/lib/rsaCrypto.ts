/**
 * rsaCrypto.ts
 * Core cryptographic operations using the Web Crypto API (RSA-PSS / SHA-256)
 */

export type KeySize = 2048 | 4096;

// ── Key Generation ──────────────────────────────────────────────────────────

export async function generateRSAKeyPair(keySize: KeySize = 2048): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: keySize,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: 'SHA-256',
    },
    true, // extractable
    ['sign', 'verify'],
  );
}

// ── Key Export → PEM ────────────────────────────────────────────────────────

export async function exportPrivateKeyPEM(privateKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('pkcs8', privateKey);
  return wrapPEM(arrayBufferToBase64(exported), 'PRIVATE KEY');
}

export async function exportPublicKeyPEM(publicKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('spki', publicKey);
  return wrapPEM(arrayBufferToBase64(exported), 'PUBLIC KEY');
}

// ── Key Import from PEM ─────────────────────────────────────────────────────

export async function importPrivateKeyFromPEM(pem: string): Promise<CryptoKey> {
  const b64 = unwrapPEM(pem, 'PRIVATE KEY');
  let der: ArrayBuffer;
  try {
    der = base64ToArrayBuffer(b64);
  } catch {
    throw new Error('Private key is not valid Base64. Check the PEM content.');
  }
  try {
    return await crypto.subtle.importKey(
      'pkcs8',
      der,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      true,
      ['sign'],
    );
  } catch {
    throw new Error('Invalid PKCS#8 private key. Generate a new pair in Tab 1 or check the .pem file.');
  }
}

export async function importPublicKeyFromPEM(pem: string): Promise<CryptoKey> {
  const b64 = unwrapPEM(pem, 'PUBLIC KEY');
  let der: ArrayBuffer;
  try {
    der = base64ToArrayBuffer(b64);
  } catch {
    throw new Error('Public key is not valid Base64. Check the PEM content.');
  }
  try {
    return await crypto.subtle.importKey(
      'spki',
      der,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      true,
      ['verify'],
    );
  } catch {
    throw new Error('Invalid SPKI public key. Use the matching public key from Tab 1.');
  }
}

// ── Hashing ─────────────────────────────────────────────────────────────────

export async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return arrayBufferToHex(hashBuffer);
}

// ── Sign ────────────────────────────────────────────────────────────────────

export async function signData(
  privateKey: CryptoKey,
  data: ArrayBuffer,
): Promise<string> {
  const sigBuffer = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    privateKey,
    data,
  );
  return arrayBufferToBase64(sigBuffer);
}

// ── Verify ──────────────────────────────────────────────────────────────────

export async function verifySignature(
  publicKey: CryptoKey,
  signatureBase64: string,
  data: ArrayBuffer,
): Promise<boolean> {
  try {
    const sigBuffer = base64ToArrayBuffer(signatureBase64);
    return await crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 },
      publicKey,
      sigBuffer,
      data,
    );
  } catch {
    return false;
  }
}

// ── Utility ─────────────────────────────────────────────────────────────────

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64.replace(/\s/g, ''));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function wrapPEM(b64: string, type: string): string {
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${type}-----\n${lines.join('\n')}\n-----END ${type}-----`;
}

function unwrapPEM(pem: string, expectedType?: string): string {
  const trimmed = pem.trim();
  if (!trimmed.includes('BEGIN') || !trimmed.includes('END')) {
    throw new Error(
      `Expected PEM format (-----BEGIN ${expectedType ?? 'KEY'}-----). Paste the full key including headers.`,
    );
  }
  const body = trimmed
    .replace(/-----BEGIN.*?-----/, '')
    .replace(/-----END.*?-----/, '')
    .replace(/\s/g, '');
  if (!body) throw new Error('PEM body is empty. Paste a complete key.');
  if (!/^[A-Za-z0-9+/=]+$/.test(body)) {
    throw new Error('PEM body contains invalid characters. Only Base64 is allowed.');
  }
  return body;
}

// ── Bundle JSON format ──────────────────────────────────────────────────────

export interface SignatureBundle {
  fileName: string;
  sha256Hash: string;
  signature: string;
  timestamp: string;
}

export function createBundle(
  fileName: string,
  sha256Hash: string,
  signature: string,
): SignatureBundle {
  return {
    fileName,
    sha256Hash,
    signature,
    timestamp: new Date().toISOString(),
  };
}

// ── Tamper helper ──────────────────────────────────────────────────────────

/**
 * Flips one byte at position ~20% into the file to simulate tampering.
 * Returns a new ArrayBuffer; the original is not mutated.
 * Throws if the buffer is empty.
 */
export function tamperBuffer(buffer: ArrayBuffer): ArrayBuffer {
  if (buffer.byteLength === 0) {
    throw new Error('Cannot tamper an empty file.');
  }
  const copy = buffer.slice(0);
  const view = new Uint8Array(copy);
  const pos = Math.max(0, Math.floor(view.length * 0.2));
  view[pos] = view[pos] ^ 0xff; // XOR with 0xFF → guaranteed change
  return copy;
}
