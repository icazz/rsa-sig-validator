# RSA Digital Signature & Data Integrity Verifier (E-Sign Simulator)

Aplikasi web satu halaman (SPA) untuk mendemonstrasikan **validasi integritas data berbasis tanda tangan digital RSA** pada dokumen digital (PDF, TXT, gambar, JSON). Pengguna dapat membuat pasangan kunci RSA, menandatangani berkas untuk menghasilkan tanda tangan digital, memverifikasi keaslian berkas, dan menyimulasikan perusakan berkas (*tampering*) untuk melihat efeknya secara langsung — semuanya berjalan **100% di browser** (client-side, tanpa server, tanpa data yang dikirim ke mana pun).

Tugas mata kuliah **Kriptografi**: implementasi konsep *hash*, *digital signature*, dan *data integrity check* dalam bentuk simulator E-Sign yang interaktif.

## Anggota Kelompok

| No | Nama                   | NRP        |
|----|------------------------|------------|
| 1  | Aditya Reza Daffansyah | 5027241034 |
| 2  | Ica Zika Hamizah       | 5027241058 |
| 3  | Ni'mah Fauziyyah Atok  | 5027241103 |

## Spesifikasi Kriptografi

| Aspek            | Nilai                                              |
|------------------|----------------------------------------------------|
| Algoritma        | RSA (2048-bit default, opsi 4096-bit)              |
| Fungsi hash      | SHA-256 (digest 64 karakter hex)                   |
| Skema padding    | RSA-PSS (salt length 32 bytes)                     |
| Output signature | String Base64                                      |
| Format kunci     | PEM (`-----BEGIN PUBLIC KEY-----` / `-----BEGIN PRIVATE KEY-----`) |
| Engine           | Web Crypto API (`crypto.subtle`), tanpa dependensi kripto eksternal |

> Catatan: pada RSA-PSS, hash asli **tidak dapat** didekripsi kembali dari signature (berbeda dengan textbook PKCS#1 v1.5). Karena itu aplikasi membandingkan **hash saat penandatanganan** (disimpan di bundle JSON / diteruskan dari Tab 2) dengan **hash yang dihitung ulang** dari berkas, sementara keabsahan kriptografis dibuktikan lewat pemanggilan `crypto.subtle.verify()`.

## Fitur & Alur Aplikasi

Aplikasi disusun dalam **3 tab dashboard** + 1 modul demo:

### Tab 1 — Key Management
- Pilih ukuran kunci (`2048-bit` default / `4096-bit`), klik **Generate New RSA Key Pair**.
- Kartu **Private Key** (PKCS#8) dan **Public Key** (SPKI): tampil dalam textarea PEM + tombol **Copy** + **Download `.pem`**.
- Kunci tersimpan di `localStorage` sehingga tidak hilang saat refresh dan otomatis terbawa ke Tab 2/3. Ada tombol **Clear saved keys**.

### Tab 2 — Sign Document (sisi pengirim)
- **Dropzone** upload berkas (semua tipe: `.pdf`, `.txt`, `.png`, `.docx`, `.json`, …).
- Input private key (otomatis terisi dari Tab 1, atau tempel manual / upload `.pem`).
- Otomatis menghitung dan menampilkan **SHA-256 hash dokumen**.
- Tombol **Sign Document** menghasilkan **signature RSA-PSS (Base64)** + tombol **Copy Signature**, **Download `signature.sig`**, **Export Bundle JSON**.
- Format bundle:
  ```json
  {
    "fileName": "contract.pdf",
    "sha256Hash": "a3f5...",
    "signature": "mK7u...",
    "timestamp": "2026-10-06T18:00:00Z"
  }
  ```
- Tombol **Verify Now** melompat ke Tab 3 dengan signature + hash + berkas sudah terisi (demo satu klik).

### Tab 3 — Verify Integrity (sisi penerima)
- Upload dokumen yang diterima, tempel signature Base64 atau upload `.sig` / bundle JSON (hash referensi ikut dipulihkan otomatis), serta input public key milik penanda tangan.
- Tombol **Verify Integrity** menampilkan:
  - ✅ Banner hitam **"Data Integrity Verified — VALID"** (dokumen asli, tak berubah), atau
  - ❌ Banner putih border tebal **"Integrity Violation Detected — INVALID"** (berkas diubah / signature / kunci tidak cocok).
- **Tabel perbandingan hash** bit-for-bit: *signing-time hash* vs *computed hash*, lengkap dengan badge `HASHES MATCH/MISMATCH`, `SIGNATURE VALID/INVALID`, dan statistik jumlah karakter hex yang berbeda.
- Kolom referensi hash bisa diedit manual sehingga alur tanpa bundle tetap bisa dibandingkan.

### Modul Tamper Simulator Playground (Avalanche Effect)
- Tombol **Simulate File Tampering**: membalik 1 byte dokumen, menghitung ulang hash, dan menampilkan perbandingan hash lama vs baru.
- Menampilkan statistik Avalanche riil: **jumlah bit yang berubah / total bit + %** (ideal SHA-256 ≈ 50%) dan posisi byte yang dibalik.
- Setelah tampering, tekan **Verify Integrity** lagi untuk melihat banner berubah dari VALID menjadi INVALID.

## Struktur Proyek

```text
├── src/
│   ├── components/
│   │   ├── KeyGenerator.tsx       # Tab 1: manajemen kunci
│   │   ├── DocumentSigner.tsx     # Tab 2: tanda tangani dokumen
│   │   ├── IntegrityVerifier.tsx  # Tab 3: verifikasi integritas
│   │   ├── TamperSimulator.tsx    # Modul demo perusakan + Avalanche Effect
│   │   └── HashComparison.tsx     # Tabel perbandingan hash bit-for-bit
│   ├── lib/
│   │   ├── rsaCrypto.ts           # Operasi inti: generate, export/import PEM, SHA-256, sign, verify, bundle, tamper
│   │   ├── fileHelpers.ts         # Baca berkas, format ukuran, download, parse bundle, copy clipboard
│   │   └── useToast.ts            # Hook notifikasi toast ringan
│   ├── App.tsx                    # Shell 3-tab + state bersama + persistensi localStorage
│   └── main.tsx
├── index.html
├── package.json
└── vite.config.ts
```

## Cara Menjalankan

Syarat: Node.js 18+ dan browser modern (Chrome / Edge / Firefox) karena memakai Web Crypto API.

```powershell
# install dependensi (sekali saja)
npm install

# mode development
npm run dev
# buka http://localhost:5173

# build produksi + pratinjau
npm run build
npm run preview
# buka http://localhost:4173

# cek lint
npm run lint
```

## Tech Stack

- React 19 + TypeScript + Vite
- Tailwind CSS v4 + Lucide Icons
- Web Crypto API (RSA-PSS / SHA-256) — tanpa backend

## Desain UI

Tema monokrom hitam-putih yang clean (light mode): kartu putih border abu tipis, tombol primer hitam solid, status VALID = banner hitam solid, INVALID = banner putih dengan border hitam tebal — dapat dibedakan tanpa mengandalkan warna.
