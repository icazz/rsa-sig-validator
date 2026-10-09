# Panduan Penjelasan Algoritma RSA & Digital Signature (E-Sign Simulator)

Dokumen ini adalah panduan lengkap (contekan presentasi) yang membedah alur sistem **Digital Signature**, mulai dari cara kerjanya, algoritma matematika yang dipakai, hingga di mana letak baris kode tersebut di dalam proyek ini.

Sistem ini didesain dari nol (koding manual murni) tanpa menggunakan *library* kriptografi instan. Segala fungsi matematika berjalan murni secara *native*.

---

## Inti Komputasi (Core Engine)
Seluruh operasi matematika dan algoritma kriptografi terpusat di satu file utama:
👉 **`rsa_code/rsa_manual.py`** 

---

## URUTAN TAHAPAN & PENJELASAN ALGORITMA

### TAHAP 1: Pembangkitan Kunci (Key Generation)
Tahap ini bertujuan membuat pasangan Kunci Publik (Public Key) dan Kunci Privat (Private Key).

- **Proses & Maksud:** 
  Sistem membutuhkan 2 buah bilangan prima acak yang sangat besar ($p$ dan $q$). Jika kita memakai RSA 2048-bit, maka $p$ dan $q$ masing-masing berukuran 1024-bit. Setelah didapat, sistem menghitung Modulus $n = p \times q$, Fungsi Totient Euler $\phi = (p-1)(q-1)$, dan kemudian menetapkan eksponen publik $e = 65537$. Terakhir, sistem mencari eksponen privat $d$ sehingga $e \times d \equiv 1 \pmod \phi$.
- **Algoritma yang dipakai:**
  1. **Miller-Rabin Primality Test**: Algoritma probabilistik untuk memastikan bahwa angka raksasa yang kita peroleh benar-benar prima.
  2. **Extended Euclidean Algorithm (Invers Modular)**: Algoritma matematika untuk mencari nilai $d$ (Kunci Privat) dari nilai $e$ dan $\phi$.
- **Letak Kode:**
  - Fungsi di `rsa_manual.py`: `generate_keypair(key_size)`
  - Fungsi pembantu Miller-Rabin: `is_probable_prime(n, rounds)`
  - Fungsi invers modular: `modinv(a, m)` dan `_egcd(a, b)`

---

### TAHAP 2: Perhitungan Sidik Jari Dokumen (Hashing)
Dokumen asli terlalu besar untuk dienkripsi dengan RSA secara langsung. Oleh karena itu, kita memampatkannya menjadi "Sidik Jari" 32-byte.

- **Proses & Maksud:**
  Dokumen teks asli diubah menjadi format bilangan biner/bytes (`.encode("utf-8")`). Rangkaian *byte* ini kemudian dimasukkan ke dalam algoritma Hashing. Berapa pun besarnya ukuran dokumen tersebut, hasil akhirnya pasti selalu sama: panjang 32 byte (ditulis dalam bentuk 64 karakter Hexadesimal).
- **Algoritma yang dipakai:** 
  **SHA-256 (Secure Hash Algorithm 256-bit)** versi manual berdasarkan standar FIPS 180-4.
  Di dalamnya menggunakan operasi bitwise rumit (Shift, ROTR, XOR) yang dicampur dengan Konstanta K (akar pangkat 3 dari 64 bilangan prima pertama).
- **Letak Kode:**
  - Fungsi di `rsa_manual.py`: `sha256_bytes(data)` dan `sha256_hex(data)`

---

### TAHAP 3: Penandatanganan (Signing - Sisi Pengirim)
Proses penyandian (enkripsi) "Sidik Jari" menggunakan Kunci Privat.

- **Proses & Maksud:**
  Hash 32-byte tidak disandikan secara mentah. Ia pertama-tama dibungkus oleh **Padding** (bantal pengaman) agar panjangnya setara dengan ukuran kunci RSA (2048-bit = 256 byte). Pesan yang sudah diberi *padding* (kita sebut variabel $m$) lalu **dienkripsi menggunakan Kunci Privat** menjadi variabel $s$ (Signature).
- **Enkripsinya Pake Apa?**
  **Enkripsi Modular RSA**. Rumusnya adalah $s = m^d \pmod n$. 
  *(Pesan dipangkatkan Kunci Privat, lalu disisa-bagikan Modulus)*.
- **Algoritma yang dipakai:**
  1. **PKCS#1 v1.5 Padding**: Skema standar internasional untuk menyusun bantalan Hash dengan aturan header khusus (termasuk *DigestInfo SHA-256* dan rentetan `0xFF`).
  2. **Chinese Remainder Theorem (CRT)**: Karena menghitung $m^d$ sangat lambat (memangkatkan angka ratusan digit dengan angka ratusan digit lainnya), kode menggunakan algoritma ini untuk **mempercepat enkripsi 4x lipat**.
- **Letak Kode:**
  - Fungsi enkripsi utama di `rsa_manual.py`: `sign_data(private_key, data)`
  - Fungsi padding: `_emsa_pkcs1v15_encode(digest, em_len)`

---

### TAHAP 4: Verifikasi Dokumen Asli (Verification - Sisi Penerima)
Tahap untuk mengecek validitas dokumen menggunakan Kunci Publik pengirim.

- **Proses & Maksud:**
  Penerima mendapatkan Signature, lalu **mendekripsinya menggunakan Kunci Publik**. Hasil dekripsinya adalah sebuah paket data. Sistem membuang *padding*-nya dan mengambil Hash (Sidik Jari) yang ada di dalamnya.
  Setelah itu, Penerima secara mandiri menghitung Hash dari Dokumen Asli yang mereka terima. Terakhir, jika Hash dari Signature **SAMA PERSIS** dengan Hash Dokumen, maka status **VALID**.
- **Deskripsinya Pake Apa?**
  **Dekripsi Modular RSA**. Rumusnya adalah $m' = s^e \pmod n$.
  *(Signature dipangkatkan Kunci Publik, lalu disisa-bagikan Modulus)*.
- **Letak Kode:**
  - Fungsi verifikasi di `rsa_manual.py`: `verify_signature(public_key, signature_b64, data)`

---

### TAHAP 5: Simulasi Pemalsuan (Tampering & Avalanche Effect)
Menguji kehebatan keamanan RSA.

- **Proses & Maksud:**
  Kita mensimulasikan ada *Hacker* yang mengubah hanya 1 byte (1 karakter huruf) pada dokumen Anda.
- **Algoritma yang didemonstrasikan:**
  Sifat mutlak fungsi hash yang disebut **Avalanche Effect** (Efek Bola Salju). Mengubah 1 byte saja mengakibatkan sekitar 50% dari bentuk biner (bit) Hash Anda rusak seketika. Karena Hash dokumen palsu berbeda total dengan Hash di dalam Signature yang sah, sistem menolak dokumen tersebut (**INVALID**).

---

### TAHAP 6: Simulasi Salah Kunci (Wrong Key Attack)
Membuktikan fungsi Nirpenyangkalan (*Non-Repudiation*).

- **Proses & Maksud:**
  Kita mensimulasikan Signature yang asli dicoba diverifikasi menggunakan Kunci Publik palsu (milik orang lain).
- **Algoritma yang didemonstrasikan:**
  Sifat berpasangan mutlak dari RSA. Sandi dari *Kunci Privat A* hanya bisa dibongkar oleh *Kunci Publik A*. Jika dibongkar paksa menggunakan *Kunci Publik B*, hasil matematikanya menjadi angka sampah *(garbage value)* yang tak bisa dibaca. Verifikasi gagal total (**INVALID**).

---

## Ringkasan Ekspor Kunci (Base64/PEM)
Di dalam kode ada fungsi `export_private_pem` dan `export_public_pem`.
Fungsi ini bukan algoritma enkripsi keamanan, melainkan **Algoritma Serialisasi / Encoding** berbasis ASN.1 DER dan Base64 (untuk PKCS#8 & SPKI). 
Gunanya murni agar kunci matematika yang panjang bisa menjadi huruf abjad agar mudah *di-copy-paste* ke sistem lain atau ke Web. Letak fungsi ini ada di `rsa_manual.py` bagian terbawah.

---

## ALASAN PEMILIHAN ALGORITMA (Untuk Sesi Tanya Jawab / Sidang)
Berikut adalah argumen akademis mengapa rumus atau algoritma tertentu dipilih pada masing-masing tahapan di atas.

### 1. Kenapa Pakai Miller-Rabin dan Extended Euclidean?
- **Kenapa Miller-Rabin Primality Test?**
  Mengecek keprimaan angka raksasa (1024-bit) dengan pembagian konvensional akan memakan waktu ribuan tahun. Miller-Rabin adalah algoritma probabilistik yang mampu memastikan keprimaan angka raksasa hanya dalam sekian milidetik dengan tingkat keakuratan nyaris 100%.
- **Kenapa Extended Euclidean Algorithm?**
  Satu-satunya cara matematis yang paling efisien dan diakui secara global untuk mencari *invers modular* (guna mendapatkan Kunci Privat $d$ dari rumus $e \times d \equiv 1 \pmod \phi$).

### 2. Kenapa Harus Di-Hash? Dan Kenapa Pakai SHA-256?
- **Kenapa butuh Hash? (Kenapa tidak dienkripsi langsung?)**
  RSA punya batasan ukuran. Kunci RSA 2048-bit maksimal hanya bisa menyandikan ~256 byte data. Fungsi Hash memecahkan masalah ini dengan memampatkan dokumen berukuran apa pun (misal: 50 MB) menjadi ukuran tetap (32-byte).
- **Kenapa SHA-256?**
  Karena terbukti *Collision-Resistant* (kebal bentrokan). Mustahil ada 2 dokumen berbeda yang bisa menghasilkan Hash yang sama.

### 3. Kenapa Pakai Padding PKCS#1 v1.5 dan CRT?
- **Kenapa Padding PKCS#1 v1.5?**
  Mengenkripsi Hash mentah (*Textbook RSA*) sangat tidak aman karena rentan manipulasi matematis. Padding memberi keacakan struktural (deretan `0xFF`) dan Header spesifik agar data memenuhi 2048-bit dan kebal dari peretasan matematis.
- **Kenapa Chinese Remainder Theorem (CRT)?**
  Memangkatkan angka ratusan digit dengan Kunci Privat $d$ sangat membebani komputer. CRT memecah perhitungan tersebut menjadi skala yang lebih kecil (memakai variabel $p$ dan $q$), sehingga proses *signing* berjalan **4 kali lebih cepat**.

### 4. Kenapa Membandingkan Hash? (Avalanche Effect)
- Hash berfungsi sebagai pelindung integritas sempurna. Sifat mutlak SHA-256 yang disebut **Avalanche Effect** memastikan bahwa memanipulasi sekecil 1 karakter koma pada dokumen akan mengubah rata-rata 50% struktur Hash-nya. Sehingga, segala bentuk modifikasi (*tampering*) oleh *hacker* saat dokumen dikirim akan otomatis menggagalkan proses verifikasi.
