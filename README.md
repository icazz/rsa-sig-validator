# RSA Digital Signature dan Data Integrity Verifier (E-Sign Simulator)

Aplikasi web satu halaman untuk mencoba langsung cara kerja tanda tangan digital RSA pada dokumen. Kamu bisa bikin pasangan kunci RSA, menandatangani file sampai keluar signature-nya, lalu memverifikasi apakah file itu masih asli atau sudah diubah. Ada juga fitur untuk merusak file secara sengaja biar kelihatan jelas apa yang terjadi kalau satu byte saja berubah.

Semua proses jalan murni di browser pakai Web Crypto API. Tidak ada server, tidak ada data yang dikirim ke mana-mana.

Project ini dibuat untuk memenuhi tugas mata kuliah Kriptografi tentang hash, digital signature, dan pengecekan integritas data.

## Anggota Kelompok

| No | Nama                   | NRP        |
|----|------------------------|------------|
| 1  | Aditya Reza Daffansyah | 5027241034 |
| 2  | Ica Zika Hamizah       | 5027241058 |
| 3  | Ni'mah Fauziyyah Atok  | 5027241103 |

## Spesifikasi Kriptografi

| Aspek            | Keterangan                                              |
|------------------|---------------------------------------------------------|
| Algoritma        | RSA (2048-bit bawaan, ada opsi 4096-bit)                |
| Fungsi hash      | SHA-256 (hasilnya 64 karakter hex)                      |
| Skema padding    | RSA-PSS (salt 32 bytes)                                 |
| Bentuk signature | String Base64                                           |
| Format kunci     | PEM (public key dan private key)                        |
| Engine           | Web Crypto API bawaan browser, tanpa library tambahan   |

Satu hal yang perlu dipahami: di RSA-PSS, hash asli tidak bisa dibalikkan lagi dari dalam signature. Jadi aplikasi ini membandingkan hash waktu penandatanganan (yang tersimpan di file bundle JSON atau dikirim dari Tab 2) dengan hash file yang dihitung ulang sekarang. Urusan sah atau tidaknya signature tetap dibuktikan lewat fungsi verify milik Web Crypto.

## Cara Pakai Aplikasinya

Aplikasi dibagi jadi 3 tab yang urutannya memang dibuat mengalir dari kiri ke kanan.

### Tab 1 - Key Management

Di sini kamu bikin kuncinya dulu. Pilih ukuran kunci 2048 atau 4096, lalu tekan Generate. Nanti muncul dua kartu: private key dan public key dalam format PEM. Keduanya bisa di-copy atau di-download sebagai file .pem.

Private key itu rahasia, jangan disebar. Public key boleh dibagikan karena dipakai orang lain untuk memeriksa tanda tanganmu.

Kunci yang sudah dibuat otomatis tersimpan di browser (localStorage), jadi aman kalau halaman di-refresh. Kalau mau hapus, tinggal tekan Clear saved keys.

### Tab 2 - Sign Document (sisi pengirim)

Di sini kamu menandatangani dokumen. Caranya: upload file apa saja (PDF, TXT, gambar, JSON, semuanya bisa), pastikan kolom private key sudah terisi (biasanya otomatis keisi dari Tab 1), lalu tekan Sign Document.

Begitu file dipilih, hash SHA-256-nya langsung dihitung dan ditampilkan. Setelah di-sign, signature Base64-nya muncul dan bisa di-copy, di-download sebagai signature.sig, atau diekspor jadi satu file bundle JSON berisi nama file, hash, signature, dan waktu penandatanganan.

Kalau sudah selesai, tekan Verify Now untuk langsung loncat ke Tab 3. Signature, hash, dan file-nya ikut terbawa, jadi tidak perlu upload ulang.

### Tab 3 - Verify Integrity (sisi penerima)

Di sini kamu memeriksa apakah dokumen yang diterima masih asli. Siapkan tiga hal: dokumennya, signature-nya (bisa tempel manual atau upload file .sig / bundle JSON), dan public key milik si penanda tangan.

Tekan Verify Integrity, hasilnya langsung keluar dalam bentuk banner besar:

- VALID, data terverifikasi. Artinya dokumen asli dan belum diubah.
- INVALID, ada pelanggaran integritas. Artinya dokumen sudah diubah, atau signature dan kuncinya tidak cocok.

Di bawahnya ada tabel perbandingan hash yang menunjukkan hash waktu penandatanganan disandingkan dengan hash file yang baru dihitung, per byte. Lengkap dengan ringkasan berapa karakter hex yang berbeda dan status signature-nya.

### Tamper Simulator Playground

Ini bagian paling seru buat demo. Tekan Simulate File Tampering, aplikasi akan membalik satu byte di dalam dokumen lalu menghitung ulang hash-nya. Kamu bisa lihat sendiri hash-nya berubah total padahal yang diubah cuma satu byte. Namanya Avalanche Effect.

Di bawahnya ada angka statistiknya: berapa bit yang berubah dari total bit, biasanya sekitar 50 persen, sesuai sifat SHA-256. Setelah itu tekan Verify Integrity lagi dan banner-nya akan berubah dari VALID jadi INVALID. Untuk balik lagi, tekan Restore Original.

## Struktur Folder

```text
src/
  components/
    KeyGenerator.tsx       # Tab 1, bikin dan tampilkan kunci
    DocumentSigner.tsx     # Tab 2, tanda tangani dokumen
    IntegrityVerifier.tsx  # Tab 3, verifikasi dokumen
    TamperSimulator.tsx    # Fitur perusakan file dan demo Avalanche Effect
    HashComparison.tsx     # Tabel perbandingan hash
  lib/
    rsaCrypto.ts           # Fungsi inti: generate kunci, hash, sign, verify, bundle, tamper
    fileHelpers.ts         # Baca file, download, parse bundle, copy teks
    useToast.ts            # Notifikasi kecil di pojok kanan bawah
  App.tsx                  # Kerangka 3 tab dan state bersama antar tab
  main.tsx
```

## Cara Menjalankan

Butuh Node.js 18 ke atas dan browser modern seperti Chrome, Edge, atau Firefox.

```powershell
# install sekali saja
npm install

# jalanin mode development
npm run dev
# buka http://localhost:5173

# kalau mau build versi produksi
npm run build
npm run preview
# buka http://localhost:4173

# cek lint
npm run lint
```

## Tech Stack

- React 19 + TypeScript + Vite
- Tailwind CSS v4 + Lucide Icons
- Web Crypto API (RSA-PSS dan SHA-256), tanpa backend

## Tampilan

Sengaja dibuat hitam putih saja biar bersih. Background putih, teks hitam, garis abu tipis. Tombol utama hitam solid. Status VALID tampil sebagai banner hitam, INVALID tampil sebagai banner putih dengan border hitam tebal. Jadi bedanya tetap jelas tanpa perlu warna.
