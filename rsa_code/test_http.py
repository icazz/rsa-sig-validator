"""Uji endpoint HTTP backend (asumsi server jalan di 127.0.0.1:8001)."""
import json
import urllib.request
import uuid

BASE = "http://127.0.0.1:8001"
BOUND = "----bend" + uuid.uuid4().hex


def multipart(fields, files):
    body = b""
    for k, v in fields.items():
        body += f'--{BOUND}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    for k, (fn, data) in files.items():
        body += (f'--{BOUND}\r\nContent-Disposition: form-data; name="{k}"; filename="{fn}"\r\n'
                 f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + b"\r\n"
    body += f"--{BOUND}--\r\n".encode()
    return body


def post(path, fields=None, files=None, is_json=None):
    if is_json is not None:
        req = urllib.request.Request(BASE + path, data=json.dumps(is_json).encode(),
                                     headers={"Content-Type": "application/json"})
    else:
        body = multipart(fields or {}, files or {})
        req = urllib.request.Request(BASE + path, data=body,
                                     headers={"Content-Type": f"multipart/form-data; boundary={BOUND}"})
    return json.load(urllib.request.urlopen(req, timeout=180))


g = post("/api/generate", is_json={"key_size": 2048})
assert g["private_key"].startswith("-----BEGIN PRIVATE KEY-----"), list(g)
assert g["public_key"].startswith("-----BEGIN PUBLIC KEY-----")
print("generate OK", flush=True)

h = post("/api/hash", files={"file": ("demo.txt", b"abc")})
assert h["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", h
print("hash OK", flush=True)

s = post("/api/sign", fields={"private_key": g["private_key"]}, files={"file": ("demo.txt", b"abc")})
assert s["sha256"] == h["sha256"] and len(s["signature"]) > 100
print("sign OK", flush=True)

v = post("/api/verify", fields={"signature": s["signature"], "public_key": g["public_key"]},
         files={"file": ("demo.txt", b"abc")})
assert v["valid"] is True, v
v2 = post("/api/verify", fields={"signature": s["signature"], "public_key": g["public_key"]},
          files={"file": ("demo.txt", b"abd")})
assert v2["valid"] is False, v2
print("verify OK (valid + tamper ditolak)", flush=True)
print("ALL HTTP TESTS PASSED", flush=True)
