# RSA Digital Signature dan Data Integrity Verifier (E-Sign Simulator)

Aplikasi web satu halaman untuk mendemonstrasikan cara kerja tanda tangan digital RSA pada dokumen digital. Pengguna dapat membangkitkan pasangan kunci RSA, menandatangani berkas hingga menghasilkan signature, kemudian memverifikasi apakah berkas tersebut masih asli atau telah mengalami perubahan. Tersedia pula fitur untuk memodifikasi berkas secara sengaja agar dampak perubahan satu byte dapat diamati secara langsung.

Seluruh proses kriptografi berjalan di sisi klien menggunakan Web Crypto API bawaan peramban. Aplikasi ini tidak menggunakan server dan tidak mengirim data apa pun ke pihak lain.

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
| Fungsi hash      | SHA-256 (keluaran berupa 64 karakter hex)             |
| Skema padding    | RSA-PSS (salt sepanjang 32 bytes)                     |
| Bentuk signature | String Base64                                         |
| Format kunci     | PEM (kunci publik dan kunci privat)                   |
| Engine           | Web Crypto API bawaan peramban, tanpa pustaka tambahan |

Perlu dicatat bahwa pada RSA-PSS, nilai hash asli tidak dapat dikembalikan dari dalam signature. Oleh karena itu, aplikasi ini membandingkan hash pada saat penandatanganan (yang tersimpan di berkas bundle JSON atau diteruskan dari Tab 2) dengan hash berkas yang dihitung ulang pada saat verifikasi. Keabsahan kriptografis tetap dibuktikan melalui fungsi verify milik Web Crypto.

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
    rsaCrypto.ts           # Fungsi inti: pembangkitan kunci, hash, sign, verify, bundle, tamper
    fileHelpers.ts         # Pembacaan berkas, unduhan, parsing bundle, salin teks
    useToast.ts            # Notifikasi kecil di sudut kanan bawah
  App.tsx                  # Kerangka tiga tab dan state bersama antar tab
  main.tsx
```

## Cara Menjalankan

Diperlukan Node.js versi 18 atau lebih baru serta peramban modern seperti Chrome, Edge, atau Firefox.

```powershell
# pemasangan dependensi (cukup dilakukan sekali)
npm install

# menjalankan mode development
npm run dev
# buka http://localhost:5173

# membangun versi produksi
npm run build
npm run preview
# buka http://localhost:4173

# memeriksa lint
npm run lint
```

## Tech Stack

- React 19 + TypeScript + Vite
- Tailwind CSS v4 + Lucide Icons
- Web Crypto API (RSA-PSS dan SHA-256), tanpa backend
