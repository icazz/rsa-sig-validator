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
| Engine utama     | `rsa_code/rsa_manual.py` (Python, tanpa pustaka kripto)  |
| Engine cadangan  | `web/src/lib/rsaCrypto.ts` (TypeScript, implementasi manual yang sama) |

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

## Struktur Repositori

Proyek ini dipisahkan menjadi dua bagian utama:

```text
rsa-sig-validator/
├── rsa_code/                 # [1] IMPLEMENTASI UTAMA TUGAS RSA (PYTHON MURNI)
│   ├── rsa_manual.py         # Algoritma RSA murni (keygen prima Miller-Rabin, SHA-256 manual, sign, verify)
│   ├── cli_demo.py           # Program simulasi terminal interaktif & otomatis (tanpa web)
│   ├── test_manual.py        # Pengujian mandiri via CLI: vektor uji, roundtrip, tamper
│   ├── app.py                # Lapisan HTTP FastAPI (jembatan API jika web ingin memanggil kode Python)
│   ├── test_http.py          # Pengujian endpoint HTTP
│   └── requirements.txt      # Dependensi FastAPI & Uvicorn
│
├── web/                      # [2] APLIKASI WEB VISUAL PENDUKUNG (FRONTEND)
│   ├── src/
│   │   ├── components/       # Komponen UI: KeyGenerator, DocumentSigner, IntegrityVerifier, TamperSimulator
│   │   ├── lib/
│   │   │   ├── rsaCrypto.ts  # Mesin lokal TypeScript (alternatif offline)
│   │   │   ├── apiClient.ts  # Klien HTTP menuju rsa_code Python
│   │   │   └── ...
│   │   └── App.tsx
│   ├── package.json
│   ├── vite.config.ts
│   └── ...
│
├── .gitignore
└── README.md
```

---

## 1. Panduan Simulasi Implementasi Code by Terminal (Tanpa Web)

Implementasi RSA ini dapat dijalankan dan disimulasikan sepenuhnya melalui terminal/CLI tanpa menyentuh web. Ini sangat berguna saat presentasi di hadapan dosen/asisten untuk membuktikan keaslian dan cara kerja algoritma secara murni.

### Cara A: Simulasi Otomatis Step-by-Step (Rekomendasi untuk Demo)
Menjalankan seluruh alur kriptografi dari awal hingga akhir secara berurutan dengan penjelasan interaktif di terminal:
```powershell
python rsa_code/cli_demo.py --auto
```
**Alur yang disimulasikan:**
1. **Tahap 1 (Keygen):** Pembangkitan bilangan prima $p, q$ dengan Miller-Rabin, perhitungan modulus $n$, eksponen publik $e=65537$, dan eksponen privat $d$. Menampilkan kunci dalam format PEM standar.
2. **Tahap 2 (Hash):** Menghitung nilai hash SHA-256 dokumen asli menggunakan implementasi fungsi hash manual dari nol.
3. **Tahap 3 (Signing):** Membuat *Digital Signature* berbasis PKCS#1 v1.5 dengan enkripsi eksponensiasi modular ($s = m^d \pmod n$).
4. **Tahap 4 (Verifikasi Dokumen Asli):** Mendekripsi signature dengan public key ($m' = s^e \pmod n$) dan mencocokkan hash. Status: **VALID**.
5. **Tahap 5 (Tampering & Avalanche Effect):** Memanipulasi 1 byte/karakter pada dokumen, menghitung perubahan bit hash (~50% bit berubah drastis), lalu memverifikasi ulang. Status: **INVALID (Modifikasi Terdeteksi)**.
6. **Tahap 6 (Wrong Key Attack):** Menguji verifikasi dokumen menggunakan public key milik pihak lain. Status: **INVALID (Kunci Ditolak)**.

---

### Cara B: Menu Interaktif Terminal (Bisa Input Teks Bebas)
Menyediakan antarmuka menu di terminal untuk mencoba fitur satu per satu sesuai keinginan:
```powershell
python rsa_code/cli_demo.py
```
**Menu yang tersedia:**
- `[1]` Pembangkitan Pasangan Kunci RSA (pilih 2048-bit atau 4096-bit)
- `[2]` Hitung Hash Dokumen / Teks Bebas (SHA-256 manual)
- `[3]` Tanda Tangani Dokumen Teks dengan Private Key
- `[4]` Verifikasi Tanda Tangan dengan Public Key
- `[5]` Simulasi Avalanche Effect & Modifikasi Dokumen
- `[6]` Jalankan Full Automated Simulation
- `[0]` Keluar

---

### Cara C: Pengujian Logika Matematis & Vektor Uji (Unit Test)
Untuk memastikan seluruh rumus matematika modular, prima, dan vektor uji FIPS 180-4 berfungsi dengan benar:
```powershell
python rsa_code/test_manual.py
```
Jika berhasil, terminal akan menampilkan:
```text
SHA-256 vectors OK
Math OK
keygen-2048: 0.xxs
PEM export OK
Sign/verify roundtrip OK
Tamper + wrong-key rejection OK
ALL PYTHON TESTS PASSED
```

---

## 2. Panduan Menjalankan Web Visual

Aplikasi web di folder `web/` berfungsi sebagai antarmuka pendukung visual untuk mempermudah demonstrasi grafis (upload file drag-and-drop, export `.pem`/`.sig`, simulasi tamper interaktif, dan tabel hex comparison).

### Opsi 1: Menjalankan Web Secara Mandiri (Local Engine / Offline)
Aplikasi web memiliki implementasi mesin RSA mandiri berbasis TypeScript yang identik dan interoperabel. Anda bisa menjalankannya langsung tanpa perlu menyalakan server Python:
```powershell
# 1. Pindah ke folder web
cd web

# 2. Pasang dependensi (hanya perlu sekali)
npm install

# 3. Jalankan server pengembang
npm run dev
```
Setelah itu, buka tautan yang muncul di terminal (biasanya **`http://localhost:5173`**).

---

### Opsi 2: Menjalankan Web Terhubung ke Backend Python (`rsa_code`)
Jika Anda ingin antarmuka web memanggil algoritma Python dari folder `rsa_code/`:

1. **Terminal 1 (Jalankan Server Python):**
   ```powershell
   cd rsa_code
   pip install -r requirements.txt
   uvicorn app:app --host 127.0.0.1 --port 8000
   ```
2. **Terminal 2 (Jalankan Frontend Web):**
   ```powershell
   cd web
   npm run dev
   ```
3. Buka browser di `http://localhost:5173`. Badge status di pojok kanan atas halaman web akan otomatis mendeteksi server dan menampilkan:
   > **`Python Backend · Manual RSA`**

---

## Tech Stack

- **rsa_code**: Python 3.10+, FastAPI (hanya HTTP layer), tanpa pustaka kriptografi eksternal (semua matematika prima Miller-Rabin, padding PKCS#1 v1.5, dan SHA-256 murni manual).
- **web**: React 19 + TypeScript + Vite + Tailwind CSS v4 + Lucide Icons.
