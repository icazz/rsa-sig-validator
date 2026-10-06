"""Uji mandiri backend: vektor SHA-256, roundtrip RSA, tamper, wrong-key."""
import json
import sys

sys.path.insert(0, "backend")

import rsa_manual

# 1. Vektor SHA-256 (FIPS 180-4)
assert rsa_manual.sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
assert rsa_manual.sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
print("SHA-256 vectors OK", flush=True)

# 2. Matematika dasar
assert pow(4, 13, 497) == 445
assert (7 * rsa_manual.modinv(7, 40)) % 40 == 1
assert rsa_manual.is_probable_prime(104729, 8) is True
assert rsa_manual.is_probable_prime(104728, 8) is False
print("Math OK", flush=True)

# 3. Roundtrip RSA-2048
import time
t0 = time.time()
key = rsa_manual.generate_keypair(2048)
print(f"keygen-2048: {time.time() - t0:.2f}s", flush=True)
assert key["n"].bit_length() == 2048
assert key["n"] == key["p"] * key["q"]

priv_pem = rsa_manual.export_private_pem(key)
pub_pem = rsa_manual.export_public_pem(key)
assert priv_pem.startswith("-----BEGIN PRIVATE KEY-----")
assert pub_pem.startswith("-----BEGIN PUBLIC KEY-----")
print("PEM export OK", flush=True)

data = "Dokumen kontrak penting #1".encode("utf-8")
sig = rsa_manual.sign_data(rsa_manual.import_private_pem(priv_pem), data)
pub = rsa_manual.import_public_pem(pub_pem)
assert rsa_manual.verify_signature(pub, sig, data) is True
print("Sign/verify roundtrip OK", flush=True)

# 4. Tamper dan kunci salah harus gagal
bad = bytearray(data)
bad[0] ^= 0xFF
assert rsa_manual.verify_signature(pub, sig, bytes(bad)) is False
other = rsa_manual.generate_keypair(2048)
other_pub = {"n": other["n"], "e": other["e"], "bit_length": other["bit_length"]}
assert rsa_manual.verify_signature(other_pub, sig, data) is False
print("Tamper + wrong-key rejection OK", flush=True)

# 5. Tulis bundle untuk uji interop silang dengan frontend (TS)
with open("cross_from_py.json", "w", encoding="utf-8") as f:
    json.dump({"public_key": pub_pem, "signature": sig,
               "data_hex": data.hex(), "sha256": rsa_manual.sha256_hex(data)}, f)
print("ALL PYTHON TESTS PASSED", flush=True)
