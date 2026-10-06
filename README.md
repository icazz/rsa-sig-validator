# RSA Digital Signature dan Data Integrity Verifier (E-Sign Simulator)

Aplikasi web satu halaman untuk mendemonstrasikan cara kerja tanda tangan digital RSA pada dokumen digital. Pengguna dapat membangkitkan pasangan kunci RSA, menandatangani berkas hingga menghasilkan signature, kemudian memverifikasi apakah berkas tersebut masih asli atau telah mengalami perubahan. Tersedia pula fitur untuk memodifikasi berkas secara sengaja agar dampak perubahan satu byte dapat diamati secara langsung.

Seluruh komputasi kriptografi dikerjakan oleh **backend Python** yang implementasinya ditulis manual dari nol (aritmetika RSA dengan operasi dasar Python dan SHA-256 yang ditulis sendiri, tanpa pustaka `cryptography` maupun `PyCryptodome`). Web hanya berperan sebagai antarmuka: mengirim berkas dan kunci ke backend, lalu menampilkan hasilnya. Apabila backend tidak berjalan, aplikasi otomatis beralih ke mesin lokal (`src/lib/rsaCrypto.ts`, implementasi manual yang sama dalam TypeScript) sehingga tetap berfungsi. Kedua mesin saling interoperabel karena memakai format yang identik.

Proyek ini disusun untuk memenuhi tugas mata kuliah Kriptografi mengenai fungsi hash, tanda tangan digital, dan pemeriksaan integritas data.

## Anggota Kelompok

| No | Nama                   | NRP        |
|----|------------------------|------------|
| 1  | Aditya Reza Daffansyah | 5027241034 |
| 2  | Ica Zika Hamizah       | 5027241058 |
| 3  | Ni'mah Fauziyyah Atok  | 5027241103 |

## Spesifikasi Kriptografi

| Aspek            | Keterangan                                            |
|------------------|-------------------------------------------------------|
| Algoritma        | RSA (2048-bit sebagai bawaan, tersedia opsi 4096-bit) |
| Fungsi hash      | SHA-256 manual, ditulis dari nol (keluaran 64 karakter hex) |
| Skema padding    | PKCS#1 v1.5 dengan DigestInfo SHA-256                   |
| Aritmetika       | Manual: Miller-Rabin, perpangkatan modular, invers modular, CRT |
| Bentuk signature | String Base64                                           |
| Format kunci     | PEM standar (public key SPKI, private key PKCS#8, dapat dibuka OpenSSL) |
| Engine utama     | `backend/rsa_manual.py` (Python, tanpa pustaka kripto)  |
| Engine cadangan  | `src/lib/rsaCrypto.ts` (TypeScript, implementasi manual yang sama) |

Aplikasi ini membandingkan hash pada saat penandatanganan (yang tersimpan di berkas bundle JSON atau diteruskan dari Tab 2) dengan hash berkas yang dihitung ulang pada saat verifikasi. Keabsahan kriptografis dibuktikan melalui operasi RSA penuh: eksponensiasi modular dengan kunci publik beserta pemeriksaan struktur padding PKCS#1 v1.5, seluruhnya oleh fungsi `verifySignature` yang ditulis manual.

## Cara Penggunaan Aplikasi

Aplikasi terdiri atas tiga tab yang dirancang untuk digunakan secara berurutan dari kiri ke kanan.

### Tab 1 - Key Management

Pada tab ini pengguna membangkitkan pasangan kunci. Pilih ukuran kunci 2048-bit atau 4096-bit, kemudian tekan tombol Generate. Setelah itu akan ditampilkan dua kartu, yaitu private key dan public key dalam format PEM. Keduanya dapat disalin ke clipboard atau diunduh sebagai berkas .pem.

Private key bersifat rahasia dan tidak boleh disebarluaskan. Public key boleh dibagikan karena digunakan oleh pihak lain untuk memeriksa keaslian tanda tangan.

Kunci yang telah dibangkitkan tersimpan otomatis di peramban (localStorage) sehingga tidak hilang ketika halaman dimuat ulang. Kunci tersebut juga otomatis terbawa ke Tab 2 dan Tab 3. Untuk menghapusnya, gunakan tombol Clear saved keys.

### Tab 2 - Sign Document (Sisi Pengirim)

Pada tab ini pengguna menandatangani dokumen. Unggah berkas dalam format apa pun (PDF, TXT, gambar, JSON, dan lainnya), pastikan kolom private key telah terisi (umumnya terisi otomatis dari Tab 1), kemudian tekan tombol Sign Document.

Segera setelah berkas dipilih, nilai hash SHA-256 dari dokumen akan dihitung dan ditampilkan. Setelah proses penandatanganan selesai, signature dalam bentuk Base64 akan muncul dan dapat disalin, diunduh sebagai signature.sig, atau diekspor menjadi satu berkas bundle JSON yang memuat nama berkas, hash, signature, dan waktu penandatanganan.

Setelah selesai, pengguna dapat menekan tombol Verify Now untuk berpindah ke Tab 3. Signature, hash, dan berkas akan ikut terbawa sehingga tidak perlu diunggah ulang.

### Tab 3 - Verify Integrity (Sisi Penerima)

Pada tab ini pengguna memeriksa keaslian dokumen yang diterima. Siapkan tiga hal berikut: dokumen yang akan diperiksa, signature (dapat ditempel manual atau diunggah dalam bentuk berkas .sig maupun bundle JSON), serta public key milik penanda tangan.

Tekan tombol Verify Integrity, hasilnya akan ditampilkan dalam bentuk banner yang jelas:

- VALID, integritas data terverifikasi. Dokumen dinyatakan asli dan belum mengalami perubahan.
- INVALID, terdeteksi pelanggaran integritas. Dokumen telah diubah, atau signature dan kunci tidak saling cocok.

Di bawah banner terdapat tabel perbandingan hash yang menyandingkan hash pada saat penandatanganan dengan hash berkas yang dihitung ulang, per byte. Tabel ini dilengkapi ringkasan jumlah karakter hex yang berbeda beserta status signature. Kolom hash referensi juga dapat diisi manual sehingga perbandingan tetap dapat dilakukan tanpa berkas bundle.

### Tamper Simulator Playground

Bagian ini digunakan untuk demonstrasi Avalanche Effect. Dengan menekan tombol Simulate File Tampering, aplikasi akan membalik satu byte di dalam dokumen lalu menghitung ulang hash-nya. Pengguna dapat melihat bahwa perubahan sekecil itu menghasilkan nilai hash yang sama sekali berbeda.

Pada bagian ini ditampilkan pula statistik perubahannya, yaitu jumlah bit yang berubah dari total bit beserta persentasenya. Pada SHA-256, nilainya berada di kisaran 50 persen. Setelah itu, tekan kembali tombol Verify Integrity untuk melihat hasil verifikasi berubah dari VALID menjadi INVALID. Untuk mengembalikan kondisi semula, tekan tombol Restore Original.

## Struktur Folder

```text
src/
  components/
    KeyGenerator.tsx       # Tab 1, pembangkitan dan tampilan kunci
    DocumentSigner.tsx     # Tab 2, penandatanganan dokumen
    IntegrityVerifier.tsx  # Tab 3, verifikasi dokumen
    TamperSimulator.tsx    # Fitur modifikasi berkas dan demonstrasi Avalanche Effect
    HashComparison.tsx     # Tabel perbandingan hash
  lib/
    rsaCrypto.ts           # Mesin lokal: pembangkitan kunci, hash, sign, verify, bundle, tamper (manual)
    apiClient.ts           # Klien HTTP menuju backend Python
    cryptoService.ts       # Penentu mesin aktif (backend bila tersedia, bila tidak mesin lokal)
    fileHelpers.ts         # Pembacaan berkas, unduhan, parsing bundle, salin teks
    useToast.ts            # Notifikasi kecil di sudut kanan bawah
  App.tsx                  # Kerangka tiga tab dan state bersama antar tab
  main.tsx
backend/
  rsa_manual.py            # Implementasi RSA manual murni (prima, SHA-256, PKCS#1 v1.5, DER/PEM)
  app.py                   # API FastAPI: /health, /generate, /hash, /sign, /verify
  requirements.txt         # Dependensi HTTP server (bukan dependensi kripto)
  test_manual.py           # Uji mandiri: vektor hash, roundtrip, tamper
  test_http.py             # Uji endpoint HTTP (memerlukan server berjalan)
```

## Cara Menjalankan

Diperlukan Node.js versi 18 atau lebih baru, Python 3.10 atau lebih baru, serta peramban modern seperti Chrome, Edge, atau Firefox.

```powershell
# --- Terminal 1: backend Python ---
cd backend
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000

# --- Terminal 2: frontend web ---
npm install   # cukup dilakukan sekali
npm run dev
# buka http://localhost:5173
```

Indikator mesin kriptografi yang sedang dipakai tampil pada badge di kanan atas halaman: "Python Backend" apabila backend terhubung, atau "Local Engine" apabila berjalan dengan mesin lokal. Alamat backend dapat diubah melalui variabel `VITE_API_URL` (bawaan: `http://localhost:8000`, lihat `.env.example`).

Perintah tambahan:

```powershell
# membangun versi produksi
npm run build
npm run preview
# buka http://localhost:4173

# memeriksa lint
npm run lint

# menguji backend (dari folder utama)
python backend/test_manual.py
# uji endpoint HTTP (server harus berjalan dahulu)
python backend/test_http.py
```

## Tech Stack

- React 19 + TypeScript + Vite (antarmuka)
- Tailwind CSS v4 + Lucide Icons
- Python + FastAPI (API backend; hanya lapisan HTTP, bukan kriptografi)
- Kriptografi manual dari nol di kedua sisi (Python dan TypeScript): prima Miller-Rabin, SHA-256, PKCS#1 v1.5, DER/PEM — tanpa pustaka kripto
