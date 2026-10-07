/**
 * rsaCrypto.ts — IMPLEMENTASI RSA MANUAL MURNI (tanpa framework/library kripto).
 *
 * Seluruh algoritma di bawah ditulis dari nol di TypeScript dengan BigInt:
 *  - Pembangkitan bilangan prima (Miller-Rabin + trial division)
 *  - Aritmetika modular (modPow, egcd, invers modular)
 *  - Fungsi hash SHA-256 (ditulis manual, tanpa crypto.subtle)
 *  - Skema tanda tangan PKCS#1 v1.5 + DigestInfo SHA-256
 *  - Encoding DER/PEM standar (SPKI untuk public key, PKCS#8 untuk private key)
 *    sehingga kunci dapat dibuka oleh OpenSSL.
 *
 * Satu-satunya yang diambil dari lingkungan adalah SUMBER ACAK (crypto.getRandomValues)
 * untuk membangkitkan kandidat prima. Matematika RSA-nya 100% kode sendiri —
 * tidak ada pemanggilan crypto.subtle (generateKey/sign/verify/digest) di berkas ini.
 */

export type KeySize = 2048 | 4096;

export interface RsaPublicKey {
  n: bigint;
  e: bigint;
  bitLength: number;
}

export interface RsaPrivateKey {
  n: bigint;
  e: bigint;
  d: bigint;
  p: bigint;
  q: bigint;
  dp: bigint;
  dq: bigint;
  qinv: bigint;
  bitLength: number;
}

export interface RsaKeyPair {
  publicKey: RsaPublicKey;
  privateKey: RsaPrivateKey;
}

const PUBLIC_EXPONENT = 65537n;

// ── Key Generation (manual) ─────────────────────────────────────────────────

/** Bilangan prima kecil untuk trial division sebelum Miller-Rabin. */
const SMALL_PRIMES: number[] = (() => {
  const limit = 1000;
  const sieve = new Array<boolean>(limit + 1).fill(true);
  sieve[0] = sieve[1] = false;
  for (let i = 2; i * i <= limit; i++) {
    if (sieve[i]) {
      for (let j = i * i; j <= limit; j += i) sieve[j] = false;
    }
  }
  const out: number[] = [];
  for (let i = 2; i <= limit; i++) if (sieve[i]) out.push(i);
  return out;
})();

function randomBytes(count: number): Uint8Array {
  const buf = new Uint8Array(count);
  crypto.getRandomValues(buf);
  return buf;
}

/** BigInt acak dengan panjang tepat `bits` bit (bit teratas = 1, ganjil). */
function randomOddBigInt(bits: number): bigint {
  const byteLen = Math.ceil(bits / 8);
  const buf = randomBytes(byteLen);
  const excessBits = byteLen * 8 - bits;
  buf[0] &= 0xff >>> excessBits; // buang bit kelebihan
  buf[0] |= 0x80 >>> excessBits; // pastikan bit teratas = 1
  buf[byteLen - 1] |= 0x01; // pastikan ganjil
  return bytesToBigInt(buf);
}

function randomBigIntBetween(min: bigint, max: bigint): bigint {
  // Mengembalikan nilai acak pada rentang [min, max].
  const range = max - min + 1n;
  const bits = bitLengthOf(range);
  for (;;) {
    const byteLen = Math.ceil(bits / 8);
    const buf = randomBytes(byteLen);
    const excess = byteLen * 8 - bits;
    buf[0] &= 0xff >>> excess;
    const v = bytesToBigInt(buf);
    if (v < range) return min + v;
  }
}

export function bitLengthOf(x: bigint): number {
  if (x <= 0n) return 0;
  return x.toString(2).length;
}

/** Eksponensiasi modular biner: (base^exp) mod mod. */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  let [oldR, r] = [a, b];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return [oldR, oldS, 0n];
}

function gcd(a: bigint, b: bigint): bigint {
  let [x, y] = [a < 0n ? -a : a, b < 0n ? -b : b];
  while (y !== 0n) [x, y] = [y, x % y];
  return x;
}

/** Invers modular: x sehingga (a*x) mod m = 1. Melempar error bila tidak ada. */
export function modInv(a: bigint, m: bigint): bigint {
  const [g, x] = egcd(a, m);
  if (g !== 1n && g !== -1n) throw new Error('Invers modular tidak ada (fp tidak koprima).');
  return ((x % m) + m) % m;
}

/** Uji prima Miller-Rabin dengan `rounds` basis acak. */
export function isProbablePrime(n: bigint, rounds: number): boolean {
  if (n < 2n) return false;
  for (const p of SMALL_PRIMES) {
    const bp = BigInt(p);
    if (n === bp) return true;
    if (n % bp === 0n) return false;
  }
  // Tulis n-1 = 2^r * d (d ganjil).
  let d = n - 1n;
  let r = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    r++;
  }
  witnessLoop: for (let i = 0; i < rounds; i++) {
    const a = randomBigIntBetween(2n, n - 2n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let j = 1; j < r; j++) {
      x = (x * x) % n;
      if (x === n - 1n) continue witnessLoop;
    }
    return false;
  }
  return true;
}

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function generatePrime(bits: number, rounds: number): Promise<bigint> {
  for (let tries = 0; ; tries++) {
    const candidate = randomOddBigInt(bits);
    let smallFactor = false;
    for (const p of SMALL_PRIMES) {
      if (candidate % BigInt(p) === 0n) {
        smallFactor = true;
        break;
      }
    }
    if (!smallFactor && isProbablePrime(candidate, rounds)) return candidate;
    if (tries % 8 === 7) await yieldToEventLoop(); // jaga UI tetap responsif
  }
}

export async function generateRSAKeyPair(keySize: KeySize = 2048): Promise<RsaKeyPair> {
  const primeBits = Math.floor(keySize / 2);
  const rounds = primeBits >= 1024 ? 12 : 16;
  for (;;) {
    const p = await generatePrime(primeBits, rounds);
    let q = await generatePrime(primeBits, rounds);
    if (q === p) continue;
    const n = p * q;
    if (bitLengthOf(n) !== keySize) continue; // pastikan tepat keySize bit
    const phi = (p - 1n) * (q - 1n);
    if (gcd(PUBLIC_EXPONENT, phi) !== 1n) {
      q = await generatePrime(primeBits, rounds);
      void q;
      continue;
    }
    const e = PUBLIC_EXPONENT;
    const d = modInv(e, phi);
    const dp = d % (p - 1n);
    const dq = d % (q - 1n);
    const qinv = modInv(q, p);
    const bitLength = bitLengthOf(n);
    return {
      publicKey: { n, e, bitLength },
      privateKey: { n, e, d, p, q, dp, dq, qinv, bitLength },
    };
  }
}

// ── SHA-256 manual (FIPS 180-4) ─────────────────────────────────────────────

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

/** SHA-256 murni atas byte mentah. Mengembalikan 32 byte digest. */
export function sha256Bytes(data: Uint8Array<ArrayBufferLike>): Uint8Array {
  const bitLenHi = Math.floor((data.length * 8) / 0x100000000);
  const bitLenLo = (data.length * 8) >>> 0;
  const paddedLen = (((data.length + 8) >> 6) + 1) << 6;
  const msg = new Uint8Array(paddedLen);
  msg.set(data);
  msg[data.length] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setUint32(paddedLen - 8, bitLenHi);
  dv.setUint32(paddedLen - 4, bitLenLo);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Array<number>(64);

  for (let off = 0; off < paddedLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = [h0, h1, h2, h3, h4, h5, h6, h7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }

  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, h0); odv.setUint32(4, h1); odv.setUint32(8, h2); odv.setUint32(12, h3);
  odv.setUint32(16, h4); odv.setUint32(20, h5); odv.setUint32(24, h6); odv.setUint32(28, h7);
  return out;
}

export async function sha256Hex(data: ArrayBuffer): Promise<string> {
  return arrayBufferToHex(sha256Bytes(new Uint8Array(data)));
}

// ── Konversi byte/BigInt ────────────────────────────────────────────────────

export function bytesToBigInt(bytes: Uint8Array<ArrayBufferLike>): bigint {
  let v = 0n;
  for (let i = 0; i < bytes.length; i++) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

/** BigInt → byte big-endian dengan panjang tetap `length` (I2OSP). */
export function bigIntToFixedBytes(x: bigint, length: number): Uint8Array {
  if (x < 0n) throw new Error('Nilai negatif tidak dapat dikodekan.');
  const out = new Uint8Array(length);
  let v = x;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error('Bilangan terlalu besar untuk panjang byte yang diminta.');
  return out;
}

/** BigInt → byte minimal tanpa nol di depan (untuk INTEGER DER). */
function bigIntToMinimalBytes(x: bigint): Uint8Array {
  if (x === 0n) return new Uint8Array([0]);
  const hex = x.toString(16);
  const even = hex.length % 2 === 0 ? hex : '0' + hex;
  const out = new Uint8Array(even.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(even.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ── PKCS#1 v1.5 (penandatanganan) ───────────────────────────────────────────

/** DigestInfo SHA-256: SEQUENCE OID sha256 + NULL + OCTET STRING hash. */
const SHA256_DIGESTINFO_PREFIX = new Uint8Array([
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
  0x05, 0x00, 0x04, 0x20,
]);

function emsaPkcs1v15Encode(hash32: Uint8Array<ArrayBufferLike>, emLen: number): Uint8Array {
  const tLen = SHA256_DIGESTINFO_PREFIX.length + hash32.length;
  if (emLen < tLen + 11) {
    throw new Error('Modulus terlalu pendek untuk padding PKCS#1 v1.5 + SHA-256.');
  }
  const em = new Uint8Array(emLen);
  em[0] = 0x00;
  em[1] = 0x01;
  em.fill(0xff, 2, emLen - tLen - 1);
  em[emLen - tLen - 1] = 0x00;
  em.set(SHA256_DIGESTINFO_PREFIX, emLen - tLen);
  em.set(hash32, emLen - hash32.length);
  return em;
}

/** Penandatanganan dengan CRT (cepat): s = m^d mod n via dp/dq/qinv. */
function rsaSignCrt(m: bigint, key: RsaPrivateKey): bigint {
  const s1 = modPow(m, key.dp, key.p);
  const s2 = modPow(m, key.dq, key.q);
  let h = (s1 - s2) % key.p;
  if (h < 0n) h += key.p;
  h = (h * key.qinv) % key.p;
  return s2 + h * key.q;
}

export async function signData(privateKey: RsaPrivateKey, data: ArrayBuffer): Promise<string> {
  const hash = sha256Bytes(new Uint8Array(data));
  const k = Math.ceil(privateKey.bitLength / 8);
  const em = emsaPkcs1v15Encode(hash, k);
  const m = bytesToBigInt(em);
  if (m >= privateKey.n) throw new Error('Nilai padding melebihi modulus (kunci rusak).');
  const s = rsaSignCrt(m, privateKey);
  return arrayBufferToBase64(bigIntToFixedBytes(s, k));
}

function bytesEqual(a: Uint8Array<ArrayBufferLike>, b: Uint8Array<ArrayBufferLike>): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export async function verifySignature(
  publicKey: RsaPublicKey,
  signatureBase64: string,
  data: ArrayBuffer,
): Promise<boolean> {
  try {
    const k = Math.ceil(publicKey.bitLength / 8);
    const sigBytes = new Uint8Array(base64ToArrayBuffer(signatureBase64));
    if (sigBytes.length !== k) return false;
    const s = bytesToBigInt(sigBytes);
    if (s >= publicKey.n) return false;
    const m = modPow(s, publicKey.e, publicKey.n);
    const em = bigIntToFixedBytes(m, k);
    // Periksa struktur 00 01 FF... 00 DigestInfo.
    if (em[0] !== 0x00 || em[1] !== 0x01) return false;
    let i = 2;
    while (i < em.length && em[i] === 0xff) i++;
    const padLen = i - 2;
    if (padLen < 8 || i >= em.length || em[i] !== 0x00) return false;
    const t = em.slice(i + 1);
    const hash = sha256Bytes(new Uint8Array(data));
    const expected = new Uint8Array(SHA256_DIGESTINFO_PREFIX.length + hash.length);
    expected.set(SHA256_DIGESTINFO_PREFIX);
    expected.set(hash, SHA256_DIGESTINFO_PREFIX.length);
    return bytesEqual(t, expected);
  } catch {
    return false;
  }
}

// ── DER/PEM standar (ditulis manual) ────────────────────────────────────────

function encodeLength(len: number): Uint8Array<ArrayBufferLike> {
  if (len < 128) return new Uint8Array([len]);
  const bytes: number[] = [];
  let v = len;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Uint8Array<ArrayBufferLike>): Uint8Array<ArrayBufferLike> {
  const len = encodeLength(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

function concat(...parts: Uint8Array<ArrayBufferLike>[]): Uint8Array<ArrayBufferLike> {
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function encodeIntegerValue(content: Uint8Array<ArrayBufferLike>): Uint8Array<ArrayBufferLike> {
  let i = 0;
  while (i < content.length - 1 && content[i] === 0x00) i++;
  let body: Uint8Array<ArrayBufferLike> = content.slice(i);
  if (body[0] & 0x80) body = concat(new Uint8Array([0x00]), body);
  return tlv(0x02, body);
}

function encodeIntegerBigInt(x: bigint): Uint8Array<ArrayBufferLike> {
  return encodeIntegerValue(bigIntToMinimalBytes(x));
}

function encodeSequence(...items: Uint8Array<ArrayBufferLike>[]): Uint8Array<ArrayBufferLike> {
  return tlv(0x30, concat(...items));
}

// OID rsaEncryption 1.2.840.113549.1.1.1
const OID_RSA_ENCRYPTION = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
const NULL_DER = new Uint8Array([0x05, 0x00]);

function rsaPublicKeyDer(key: RsaPublicKey): Uint8Array {
  return encodeSequence(encodeIntegerBigInt(key.n), encodeIntegerBigInt(key.e));
}

function spkiDer(key: RsaPublicKey): Uint8Array {
  const algId = encodeSequence(OID_RSA_ENCRYPTION, NULL_DER);
  const bitString = tlv(0x03, concat(new Uint8Array([0x00]), rsaPublicKeyDer(key)));
  return encodeSequence(algId, bitString);
}

function rsaPrivateKeyDer(key: RsaPrivateKey): Uint8Array {
  return encodeSequence(
    encodeIntegerBigInt(0n),
    encodeIntegerBigInt(key.n),
    encodeIntegerBigInt(key.e),
    encodeIntegerBigInt(key.d),
    encodeIntegerBigInt(key.p),
    encodeIntegerBigInt(key.q),
    encodeIntegerBigInt(key.dp),
    encodeIntegerBigInt(key.dq),
    encodeIntegerBigInt(key.qinv),
  );
}

function pkcs8Der(key: RsaPrivateKey): Uint8Array {
  const algId = encodeSequence(OID_RSA_ENCRYPTION, NULL_DER);
  const octet = tlv(0x04, rsaPrivateKeyDer(key));
  return encodeSequence(encodeIntegerBigInt(0n), algId, octet);
}

export async function exportPrivateKeyPEM(privateKey: RsaPrivateKey): Promise<string> {
  return wrapPEM(arrayBufferToBase64(pkcs8Der(privateKey)), 'PRIVATE KEY');
}

export async function exportPublicKeyPEM(publicKey: RsaPublicKey): Promise<string> {
  return wrapPEM(arrayBufferToBase64(spkiDer(publicKey)), 'PUBLIC KEY');
}

// ── DER reader (manual) ─────────────────────────────────────────────────────

class DerReader {
  private pos = 0;
  private readonly buf: Uint8Array<ArrayBufferLike>;
  constructor(buf: Uint8Array<ArrayBufferLike>) {
    this.buf = buf;
  }

  get done(): boolean {
    return this.pos >= this.buf.length;
  }

  private readByte(): number {
    if (this.pos >= this.buf.length) throw new Error('DER terpotong.');
    return this.buf[this.pos++];
  }

  readLength(): number {
    const first = this.readByte();
    if (first < 128) return first;
    const count = first & 0x7f;
    if (count === 0 || count > 4) throw new Error('Panjang DER tidak didukung.');
    let len = 0;
    for (let i = 0; i < count; i++) len = (len << 8) | this.readByte();
    return len;
  }

  readTLV(expectedTag: number): Uint8Array<ArrayBufferLike> {
    const tag = this.readByte();
    if (tag !== expectedTag) {
      throw new Error(`Tag DER tak terduga (dapat ${tag}, harap ${expectedTag}).`);
    }
    const len = this.readLength();
    if (this.pos + len > this.buf.length) throw new Error('DER terpotong.');
    const out = this.buf.slice(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }

  readSequence(): DerReader {
    return new DerReader(this.readTLV(0x30));
  }

  readInteger(): bigint {
    const bytes = this.readTLV(0x02);
    return bytesToBigInt(bytes); // INTEGER non-negatif pada kunci RSA
  }

  readNull(): void {
    this.readTLV(0x05);
  }

  readOid(): Uint8Array<ArrayBufferLike> {
    return this.readTLV(0x06);
  }

  readOctetString(): Uint8Array<ArrayBufferLike> {
    return this.readTLV(0x04);
  }

  readBitString(): Uint8Array<ArrayBufferLike> {
    const bytes = this.readTLV(0x03);
    if (bytes.length === 0 || bytes[0] !== 0x00) throw new Error('BIT STRING tidak valid.');
    return bytes.slice(1);
  }
}

function parseRsaPublicKeyFromDer(der: Uint8Array<ArrayBufferLike>): RsaPublicKey {
  const seq = new DerReader(der).readSequence();
  const n = seq.readInteger();
  const e = seq.readInteger();
  if (!seq.done) throw new Error('Struktur kunci publik tidak valid.');
  return { n, e, bitLength: bitLengthOf(n) };
}

function parseRsaPrivateNumbers(der: Uint8Array<ArrayBufferLike>): RsaPrivateKey {
  const seq = new DerReader(der).readSequence();
  const version = seq.readInteger();
  if (version !== 0n) throw new Error('Versi kunci privat tidak didukung.');
  const n = seq.readInteger();
  const e = seq.readInteger();
  const d = seq.readInteger();
  const p = seq.readInteger();
  const q = seq.readInteger();
  const dp = seq.readInteger();
  const dq = seq.readInteger();
  const qinv = seq.readInteger();
  if (!seq.done) throw new Error('Struktur kunci privat tidak valid.');
  if (p * q !== n) throw new Error('Kunci privat tidak konsisten (p*q != n).');
  return { n, e, d, p, q, dp, dq, qinv, bitLength: bitLengthOf(n) };
}

export async function importPrivateKeyFromPEM(pem: string): Promise<RsaPrivateKey> {
  const b64 = unwrapPEM(pem, ['PRIVATE KEY', 'RSA PRIVATE KEY']);
  const header = pem.includes('RSA PRIVATE KEY') ? 'RSA PRIVATE KEY' : 'PRIVATE KEY';
  const der = new Uint8Array(base64ToArrayBuffer(b64));
  try {
    if (header === 'RSA PRIVATE KEY') {
      return parseRsaPrivateNumbers(der); // PKCS#1 tradisional
    }
    // PKCS#8: SEQUENCE { version, algId, octetString(RSAPrivateKey) }
    const outer = new DerReader(der).readSequence();
    const version = outer.readInteger();
    if (version !== 0n) throw new Error('Versi PKCS#8 tidak didukung.');
    const alg = outer.readSequence();
    alg.readOid();
    alg.readNull();
    const inner = outer.readOctetString();
    if (!outer.done) throw new Error('Struktur PKCS#8 tidak valid.');
    return parseRsaPrivateNumbers(inner);
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('Kunci privat')) throw err;
    throw new Error('Private key tidak valid. Gunakan kunci hasil generate Tab 1 (format PKCS#8 / PKCS#1).');
  }
}

export async function importPublicKeyFromPEM(pem: string): Promise<RsaPublicKey> {
  const b64 = unwrapPEM(pem, ['PUBLIC KEY']);
  const der = new Uint8Array(base64ToArrayBuffer(b64));
  try {
    const outer = new DerReader(der).readSequence();
    const alg = outer.readSequence();
    const oid = alg.readOid();
    const expectedOid = OID_RSA_ENCRYPTION.slice(2); // isi OID tanpa tag+panjang
    if (oid.length !== expectedOid.length || !oid.every((v, i) => v === expectedOid[i])) {
      throw new Error('Bukan kunci RSA.');
    }
    alg.readNull();
    const inner = outer.readBitString();
    if (!outer.done) throw new Error('Struktur SPKI tidak valid.');
    return parseRsaPublicKeyFromDer(inner);
  } catch (err) {
    if (err instanceof Error && err.message === 'Bukan kunci RSA.') throw err;
    throw new Error('Public key tidak valid. Gunakan kunci hasil generate Tab 1 (format SPKI).');
  }
}

// ── Utility ─────────────────────────────────────────────────────────────────

export function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const clean = base64.replace(/\s/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 !== 0) {
    throw new Error('Bukan string Base64 yang valid.');
  }
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function arrayBufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function wrapPEM(b64: string, type: string): string {
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${type}-----\n${lines.join('\n')}\n-----END ${type}-----`;
}

function unwrapPEM(pem: string, expectedTypes: string[]): string {
  const trimmed = pem.trim();
  if (!trimmed.includes('BEGIN') || !trimmed.includes('END')) {
    throw new Error(
      `Format PEM tidak ditemukan (diharapkan -----BEGIN ${expectedTypes[0]}-----). Tempel kunci lengkap beserta header-nya.`,
    );
  }
  const body = trimmed
    .replace(/-----BEGIN.*?-----/, '')
    .replace(/-----END.*?-----/, '')
    .replace(/\s/g, '');
  if (!body) throw new Error('Isi PEM kosong. Tempel kunci yang lengkap.');
  if (!/^[A-Za-z0-9+/=]+$/.test(body)) {
    throw new Error('Isi PEM mengandung karakter yang bukan Base64.');
  }
  return body;
}

// ── Format bundle JSON ──────────────────────────────────────────────────────

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

// ── Tamper helper (murni, tidak berubah) ────────────────────────────────────

/**
 * Membalik satu byte pada posisi ~20% dari awal berkas untuk simulasi perusakan.
 * Mengembalikan ArrayBuffer baru; buffer asli tidak diubah.
 */
export function tamperBuffer(buffer: ArrayBuffer): ArrayBuffer {
  if (buffer.byteLength === 0) {
    throw new Error('Berkas kosong tidak dapat dirusak.');
  }
  const copy = buffer.slice(0);
  const view = new Uint8Array(copy);
  const pos = Math.max(0, Math.floor(view.length * 0.2));
  view[pos] = view[pos] ^ 0xff;
  return copy;
}
