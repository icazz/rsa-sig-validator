"""
app.py -- Backend FastAPI untuk E-Sign Validator.

Seluruh komputasi kriptografi didelegasikan ke `rsa_manual.py` (kode manual murni).
FastAPI di sini hanya berperan sebagai lapisan HTTP (routing + parsing),
bukan sebagai framework kriptografi.

Endpoint:
  GET  /api/health
  POST /api/generate   JSON {key_size}
  POST /api/hash       multipart (file)
  POST /api/sign       multipart (file + private_key)
  POST /api/verify     multipart (file + signature + public_key)

Menjalankan:
  pip install -r requirements.txt
  uvicorn app:app --host 127.0.0.1 --port 8000
  (jalankan dari dalam folder rsa_code/)
"""

from __future__ import annotations

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import rsa_manual

app = FastAPI(title="RSA Manual Backend (E-Sign Validator)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class GenerateRequest(BaseModel):
    key_size: int = 2048


def _read_upload(upload: UploadFile, field: str) -> bytes:
    try:
        data = upload.file.read()
    except Exception:
        raise HTTPException(status_code=400, detail=f"Gagal membaca berkas pada field '{field}'.")
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
        raise HTTPException(status_code=400, detail=f"Berkas pada field '{field}' kosong.")
    return bytes(data)


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "engine": "manual-python-rsa",
        "algorithm": "RSA",
        "hash": "SHA-256 (manual)",
        "padding": "PKCS#1 v1.5",
        "key_sizes": [2048, 4096],
    }


@app.post("/api/generate")
def generate(req: GenerateRequest) -> dict:
    if req.key_size not in (2048, 4096):
        raise HTTPException(status_code=400, detail="Ukuran kunci harus 2048 atau 4096.")
    try:
        key = rsa_manual.generate_keypair(req.key_size)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    return {
        "private_key": rsa_manual.export_private_pem(key),
        "public_key": rsa_manual.export_public_pem(key),
        "key_size": req.key_size,
    }


@app.post("/api/hash")
def compute_hash(file: UploadFile = File(...)) -> dict:
    data = _read_upload(file, "file")
    return {
        "file_name": file.filename or "upload",
        "size": len(data),
        "sha256": rsa_manual.sha256_hex(data),
    }


@app.post("/api/sign")
def sign_document(
    file: UploadFile = File(...),
    private_key: str = Form(...),
) -> dict:
    data = _read_upload(file, "file")
    try:
        key = rsa_manual.import_private_pem(private_key)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    try:
        signature = rsa_manual.sign_data(key, data)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    return {
        "file_name": file.filename or "upload",
        "sha256": rsa_manual.sha256_hex(data),
        "signature": signature,
    }


@app.post("/api/verify")
def verify_document(
    file: UploadFile = File(...),
    signature: str = Form(...),
    public_key: str = Form(...),
) -> dict:
    data = _read_upload(file, "file")
    try:
        key = rsa_manual.import_public_pem(public_key)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    valid = rsa_manual.verify_signature(key, signature, data)
    return {
        "valid": valid,
        "computed_hash": rsa_manual.sha256_hex(data),
    }
