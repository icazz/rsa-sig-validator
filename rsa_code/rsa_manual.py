"""
rsa_manual.py -- IMPLEMENTASI RSA MANUAL MURNI (tanpa framework/library kripto).

Seluruh algoritma ditulis dari nol memakai operasi dasar Python:
 - Pembangkitan bilangan prima (trial division + Miller-Rabin, acak dari `secrets`)
 - Aritmetika modular (`pow` tiga argumen, egcd, invers modular)
 - Fungsi hash SHA-256 yang ditulis manual (tanpa `hashlib`)
 - Skema tanda tangan PKCS#1 v1.5 + DigestInfo SHA-256
 - Encoding DER/PEM standar (SPKI untuk public key, PKCS#8 untuk private key)
   sehingga kunci dapat dibuka oleh OpenSSL maupun frontend TypeScript.

Modul ini hanya memakai pustaka standar Python (`secrets`, `base64`).
Tidak ada ketergantungan pada `cryptography`, `pycryptodome`, atau `hashlib`.
"""

from __future__ import annotations

import base64
import secrets

PUBLIC_EXPONENT = 65537


# Utilitas bilangan acak

def _small_primes(limit: int = 1000) -> list[int]:
    sieve = [True] * (limit + 1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            for j in range(i * i, limit + 1, i):
                sieve[j] = False
    return [i for i, p in enumerate(sieve) if p]


SMALL_PRIMES = _small_primes()

_OID_RSA_ENCRYPTION_BODY = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])

_SHA256_DIGESTINFO_PREFIX = bytes([
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
])


def _random_odd(bits: int) -> int:
    """Integer acak dengan panjang tepat `bits` bit (bit teratas 1, ganjil)."""
    nbytes = (bits + 7) // 8
    buf = bytearray(secrets.token_bytes(nbytes))
    excess = nbytes * 8 - bits
    buf[0] &= 0xFF >> excess
    buf[0] |= 0x80 >> excess
    buf[-1] |= 0x01
    return int.from_bytes(buf, "big")


# Aritmetika modular

def _egcd(a: int, b: int) -> tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_r, old_s, 0


def modinv(a: int, m: int) -> int:
    """Invers modular: x sehingga (a*x) mod m = 1."""
    g, x, _ = _egcd(a, m)
    if abs(g) != 1:
        raise ValueError("Invers modular tidak ada.")
    return x % m


def is_probable_prime(n: int, rounds: int) -> bool:
    """Uji prima Miller-Rabin dengan `rounds` basis acak."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, rounds: int) -> int:
    while True:
        cand = _random_odd(bits)
        if any(cand % p == 0 for p in SMALL_PRIMES):
            continue
        if is_probable_prime(cand, rounds):
            return cand


def generate_keypair(key_size: int = 2048) -> dict:
    """Membangkitkan pasangan kunci RSA manual. Mengembalikan dict bilangan bulat."""
    # Algoritma Pencarian Bilangan Prima (Miller-Rabin Primality Test)
    if key_size not in (2048, 4096):
        raise ValueError("Ukuran kunci harus 2048 atau 4096.")
    prime_bits = key_size // 2
    rounds = 12 if prime_bits >= 1024 else 16
    while True:
        p = generate_prime(prime_bits, rounds)
        q = generate_prime(prime_bits, rounds)
        if q == p:
            continue
        n = p * q
        if n.bit_length() != key_size:
            continue
        # Totient Euler
        phi = (p - 1) * (q - 1)
        e = PUBLIC_EXPONENT
        import math
        if math.gcd(e, phi) != 1:
            continue
        # Algoritma Extended Euclidean
        d = modinv(e, phi)
        return {
            "n": n, "e": e, "d": d, "p": p, "q": q,
            "dp": d % (p - 1), "dq": d % (q - 1), "qinv": modinv(q, p),
            "bit_length": n.bit_length(),
        }


# SHA-256 manual (FIPS 180-4)

_SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]
_MASK = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK


def sha256_bytes(data: bytes) -> bytes:
    """SHA-256 murni. Mengembalikan 32 byte digest."""
    msg = bytearray(data)
    bit_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += bit_len.to_bytes(8, "big")

    h = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
         0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

    for off in range(0, len(msg), 64):
        block = msg[off:off + 64]
        w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = (hh + s1 + ch + _SHA256_K[i] + w[i]) & _MASK
            s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (s0 + maj) & _MASK
            hh, g, f = g, f, e
            e = (d + t1) & _MASK
            d, c, b = c, b, a
            a = (t1 + t2) & _MASK
        h = [(x + y) & _MASK for x, y in zip(h, [a, b, c, d, e, f, g, hh])]

    return b"".join(x.to_bytes(4, "big") for x in h)


def sha256_hex(data: bytes) -> str:
    return sha256_bytes(bytes(data)).hex()


# PKCS#1 v1.5 (penandatanganan)

def _emsa_pkcs1v15_encode(digest: bytes, em_len: int) -> bytes:
    t = _SHA256_DIGESTINFO_PREFIX + digest
    if em_len < len(t) + 11:
        raise ValueError("Modulus terlalu pendek untuk PKCS#1 v1.5 + SHA-256.")
    ps_len = em_len - len(t) - 3
    return b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t


def sign_data(private_key: dict, data: bytes) -> str:
    """Menandatangani data. Mengembalikan signature Base64."""
    digest = sha256_bytes(bytes(data))
    k = (private_key["n"].bit_length() + 7) // 8
    em = _emsa_pkcs1v15_encode(digest, k)
    m = int.from_bytes(em, "big")
    if m >= private_key["n"]:
        raise ValueError("Nilai padding melebihi modulus.")
    # Enkripsi RSA = m^d mod n
    # CRT (cepat): s1 = m^dp mod p, s2 = m^dq mod q
    s1 = pow(m, private_key["dp"], private_key["p"])
    s2 = pow(m, private_key["dq"], private_key["q"])
    h = ((s1 - s2) * private_key["qinv"]) % private_key["p"]
    s = s2 + h * private_key["q"]
    return base64.b64encode(s.to_bytes(k, "big")).decode("ascii")


def verify_signature(public_key: dict, signature_b64: str, data: bytes) -> bool:
    """Memverifikasi signature Base64 terhadap data. Mengembalikan True/False."""
    try:
        k = (public_key["n"].bit_length() + 7) // 8
        sig = base64.b64decode(signature_b64.strip(), validate=True)
        if len(sig) != k:
            return False
        s = int.from_bytes(sig, "big")
        if s >= public_key["n"]:
            return False
        # m = s^e mod n
        em = pow(s, public_key["e"], public_key["n"]).to_bytes(k, "big")
        # bongkar paddingnya
        if len(em) < 2 or em[0] != 0x00 or em[1] != 0x01:
            return False
        i = 2
        # cek header, kalau salah buang jauh
        while i < len(em) and em[i] == 0xFF:
            i += 1
        # buang padding
        if i - 2 < 8 or i >= len(em) or em[i] != 0x00:
            return False
        t = em[i + 1:]
        expected = _SHA256_DIGESTINFO_PREFIX + sha256_bytes(bytes(data))
        if len(t) != len(expected):
            return False
        diff = 0
        for x, y in zip(t, expected):
            diff |= x ^ y
        return diff == 0
    except Exception:
        return False


# Encoding DER/PEM standar (ditulis manual)

def _encode_length(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(content)) + content


def _encode_integer_content(content: bytes) -> bytes:
    body = content.lstrip(b"\x00") or b"\x00"
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(0x02, body)


def _encode_integer(x: int) -> bytes:
    if x == 0:
        return _encode_integer_content(b"\x00")
    return _encode_integer_content(x.to_bytes((x.bit_length() + 7) // 8, "big"))


def _encode_sequence(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


_OID_TLV = _tlv(0x06, _OID_RSA_ENCRYPTION_BODY)
_NULL_TLV = bytes([0x05, 0x00])


def _rsa_public_der(key: dict) -> bytes:
    return _encode_sequence(_encode_integer(key["n"]), _encode_integer(key["e"]))


def _spki_der(key: dict) -> bytes:
    alg = _encode_sequence(_OID_TLV, _NULL_TLV)
    bitstring = _tlv(0x03, b"\x00" + _rsa_public_der(key))
    return _encode_sequence(alg, bitstring)


def _rsa_private_der(key: dict) -> bytes:
    return _encode_sequence(
        _encode_integer(0), _encode_integer(key["n"]), _encode_integer(key["e"]),
        _encode_integer(key["d"]), _encode_integer(key["p"]), _encode_integer(key["q"]),
        _encode_integer(key["dp"]), _encode_integer(key["dq"]), _encode_integer(key["qinv"]),
    )


def _pkcs8_der(key: dict) -> bytes:
    alg = _encode_sequence(_OID_TLV, _NULL_TLV)
    return _encode_sequence(_encode_integer(0), alg, _tlv(0x04, _rsa_private_der(key)))


def _wrap_pem(der: bytes, label: str) -> str:
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----"


def export_private_pem(key: dict) -> str:
    return _wrap_pem(_pkcs8_der(key), "PRIVATE KEY")


def export_public_pem(key: dict) -> str:
    return _wrap_pem(_spki_der(key), "PUBLIC KEY")


class _DerReader:
    def __init__(self, buf: bytes):
        self._buf = buf
        self._pos = 0

    @property
    def done(self) -> bool:
        return self._pos >= len(self._buf)

    def _read_byte(self) -> int:
        if self._pos >= len(self._buf):
            raise ValueError("DER terpotong.")
        b = self._buf[self._pos]
        self._pos += 1
        return b

    def read_length(self) -> int:
        first = self._read_byte()
        if first < 128:
            return first
        count = first & 0x7F
        if count == 0 or count > 4:
            raise ValueError("Panjang DER tidak didukung.")
        length = 0
        for _ in range(count):
            length = (length << 8) | self._read_byte()
        return length

    def read_tlv(self, tag: int) -> bytes:
        actual = self._read_byte()
        if actual != tag:
            raise ValueError(f"Tag DER tak terduga (dapat {actual}, harap {tag}).")
        length = self.read_length()
        if self._pos + length > len(self._buf):
            raise ValueError("DER terpotong.")
        out = self._buf[self._pos:self._pos + length]
        self._pos += length
        return out

    def read_sequence(self) -> "_DerReader":
        return _DerReader(self.read_tlv(0x30))

    def read_integer(self) -> int:
        return int.from_bytes(self.read_tlv(0x02), "big")

    def read_null(self) -> None:
        self.read_tlv(0x05)

    def read_oid(self) -> bytes:
        return self.read_tlv(0x06)

    def read_octet_string(self) -> bytes:
        return self.read_tlv(0x04)

    def read_bit_string(self) -> bytes:
        raw = self.read_tlv(0x03)
        if not raw or raw[0] != 0x00:
            raise ValueError("BIT STRING tidak valid.")
        return raw[1:]


def _unwrap_pem(pem: str, labels: list[str]) -> bytes:
    text = pem.strip()
    if "BEGIN" not in text or "END" not in text:
        raise ValueError(f"Format PEM tidak ditemukan (diharapkan -----BEGIN {labels[0]}-----).")
    body = text.split("-----BEGIN", 1)[1].split("-----", 1)[1]
    body = body.rsplit("-----END", 1)[0]
    body = "".join(body.split())
    if not body:
        raise ValueError("Isi PEM kosong.")
    try:
        return base64.b64decode(body, validate=True)
    except Exception:
        raise ValueError("Isi PEM bukan Base64 yang valid.")


def _public_numbers(der: bytes) -> dict:
    seq = _DerReader(der).read_sequence()
    n, e = seq.read_integer(), seq.read_integer()
    if not seq.done:
        raise ValueError("Struktur kunci publik tidak valid.")
    return {"n": n, "e": e, "bit_length": n.bit_length()}


def _private_numbers(der: bytes) -> dict:
    seq = _DerReader(der).read_sequence()
    if seq.read_integer() != 0:
        raise ValueError("Versi kunci privat tidak didukung.")
    n, e, d = seq.read_integer(), seq.read_integer(), seq.read_integer()
    p, q = seq.read_integer(), seq.read_integer()
    dp, dq, qinv = seq.read_integer(), seq.read_integer(), seq.read_integer()
    if not seq.done:
        raise ValueError("Struktur kunci privat tidak valid.")
    if p * q != n:
        raise ValueError("Kunci privat tidak konsisten (p*q != n).")
    return {"n": n, "e": e, "d": d, "p": p, "q": q, "dp": dp, "dq": dq,
            "qinv": qinv, "bit_length": n.bit_length()}


def import_private_pem(pem: str) -> dict:
    is_traditional = "RSA PRIVATE KEY" in pem
    der = _unwrap_pem(pem, ["PRIVATE KEY", "RSA PRIVATE KEY"])
    try:
        if is_traditional:
            return _private_numbers(der)
        outer = _DerReader(der).read_sequence()
        if outer.read_integer() != 0:
            raise ValueError("Versi PKCS#8 tidak didukung.")
        alg = outer.read_sequence()
        alg.read_oid()
        alg.read_null()
        inner = outer.read_octet_string()
        if not outer.done:
            raise ValueError("Struktur PKCS#8 tidak valid.")
        return _private_numbers(inner)
    except ValueError as err:
        msg = str(err)
        if msg.startswith(("Kunci privat", "Versi", "Struktur")):
            raise
        raise ValueError("Private key tidak valid. Gunakan kunci hasil generate (PKCS#8/PKCS#1).")


def import_public_pem(pem: str) -> dict:
    der = _unwrap_pem(pem, ["PUBLIC KEY"])
    try:
        outer = _DerReader(der).read_sequence()
        alg = outer.read_sequence()
        if alg.read_oid() != _OID_RSA_ENCRYPTION_BODY:
            raise ValueError("Bukan kunci RSA.")
        alg.read_null()
        inner = outer.read_bit_string()
        if not outer.done:
            raise ValueError("Struktur SPKI tidak valid.")
        return _public_numbers(inner)
    except ValueError as err:
        if str(err) == "Bukan kunci RSA.":
            raise
        raise ValueError("Public key tidak valid. Gunakan kunci hasil generate (SPKI).")
