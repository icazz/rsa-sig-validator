"""
cli_demo.py -- Simulasi Interaktif Implementasi RSA & Tanda Tangan Digital via Terminal.

Dibuat khusus untuk presentasi dan pengujian tugas Kriptografi tanpa perlu membuka web.
Hanya membutuhkan Python standar (tanpa library pihak ketiga).

Cara menjalankan:
  python rsa_code/cli_demo.py          (Mode Menu Interaktif)
  python rsa_code/cli_demo.py --auto   (Mode Simulasi Otomatis Step-by-Step)
"""

from __future__ import annotations

import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import rsa_manual

# Warna terminal (ANSI)
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def header(title: str):
    print(f"\n{CYAN}{'=' * 65}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{CYAN}{'=' * 65}{RESET}\n")


def subheader(title: str):
    print(f"\n{BOLD}{YELLOW}--- {title} ---{RESET}")


def count_bit_difference(hash1_hex: str, hash2_hex: str) -> tuple[int, float]:
    b1 = bytes.fromhex(hash1_hex)
    b2 = bytes.fromhex(hash2_hex)
    diff_bits = 0
    total_bits = len(b1) * 8
    for byte1, byte2 in zip(b1, b2):
        diff_bits += bin(byte1 ^ byte2).count("1")
    percent = (diff_bits / total_bits) * 100
    return diff_bits, percent


def run_full_simulation():
    header("SIMULASI LENGKAP: ALGORITMA RSA & DIGITAL SIGNATURE (TERMINAL)")

    # -------------------------------------------------------------
    # TAHAP 1: PEMBANGKITAN KUNCI RSA
    # -------------------------------------------------------------
    subheader("TAHAP 1: Pembangkitan Pasangan Kunci RSA-2048 (Manual)")
    print("Membangkitkan 2 bilangan prima acak (p, q) 1024-bit dengan Miller-Rabin test...")
    t0 = time.time()
    key = rsa_manual.generate_keypair(2048)
    durasi = time.time() - t0

    print(f"{GREEN}[OK] Kunci berhasil dibangkitkan dalam {durasi:.2f} detik!{RESET}")
    print(f" - Bit length (n) : {key['n'].bit_length()} bit")
    print(f" - Modulus (n)    : {str(key['n'])[:30]}...{str(key['n'])[-30:]} (panjang: {len(str(key['n']))} digit)")
    print(f" - Public exp (e) : {key['e']}")
    print(f" - Private exp (d): {str(key['d'])[:30]}...{str(key['d'])[-30:]}")

    priv_pem = rsa_manual.export_private_pem(key)
    pub_pem = rsa_manual.export_public_pem(key)

    print(f"\nFormat Public Key (SPKI PEM):\n{DIM}{pub_pem.strip()}{RESET}\n")

    # -------------------------------------------------------------
    # TAHAP 2: FUNGSI HASH SHA-256 MANUAL
    # -------------------------------------------------------------
    subheader("TAHAP 2: Perhitungan Hash Dokumen (SHA-256 Manual)")
    pesan_asli = "Dokumen Kontrak Perjanjian Kerjasama Digital Kriptografi #502724"
    data_bytes = pesan_asli.encode("utf-8")
    hash_asli = rsa_manual.sha256_hex(data_bytes)

    print(f"Isi Dokumen  : {BOLD}\"{pesan_asli}\"{RESET}")
    print(f"Ukuran Data  : {len(data_bytes)} byte")
    print(f"SHA-256 Hash : {GREEN}{hash_asli}{RESET}")

    # -------------------------------------------------------------
    # TAHAP 3: SIGNING (PEMBUATAN DIGITAL SIGNATURE)
    # -------------------------------------------------------------
    subheader("TAHAP 3: Penandatanganan Dokumen (Digital Signature PKCS#1 v1.5)")
    print("Langkah: Hash -> DigestInfo + Padding PKCS#1 v1.5 -> Enkripsi dengan Private Key (s = m^d mod n)")
    t0 = time.time()
    priv_dict = rsa_manual.import_private_pem(priv_pem)
    signature = rsa_manual.sign_data(priv_dict, data_bytes)
    durasi_sign = time.time() - t0

    print(f"{GREEN}[OK] Signature berhasil dibuat dalam {durasi_sign:.4f} detik!{RESET}")
    print(f"Digital Signature (Base64):\n{BOLD}{CYAN}{signature[:64]}...\n...{signature[-64:]}{RESET}")

    # -------------------------------------------------------------
    # TAHAP 4: VERIFIKASI DOKUMEN ASLI (SISI PENERIMA)
    # -------------------------------------------------------------
    subheader("TAHAP 4: Verifikasi Integritas Dokumen Asli")
    print("Penerima menerima: (1) Dokumen, (2) Signature, (3) Public Key penandatangan.")
    print("Langkah: Dekripsi signature dengan Public Key (m' = s^e mod n) -> Cocokkan hash.")
    
    pub_dict = rsa_manual.import_public_pem(pub_pem)
    is_valid = rsa_manual.verify_signature(pub_dict, signature, data_bytes)

    if is_valid:
        print(f"\nStatus Verifikasi: {BOLD}{GREEN}[ VALID - INTEGRITAS DOKUMEN TERJAMIN ]{RESET}")
        print("-> Dokumen terbukti asli dan benar-benar ditandatangani oleh pemilik private key.")
    else:
        print(f"\nStatus Verifikasi: {BOLD}{RED}[ INVALID ]{RESET}")

    # -------------------------------------------------------------
    # TAHAP 5: SIMULASI PEMALSUAN DATA (TAMPERING & AVALANCHE EFFECT)
    # -------------------------------------------------------------
    subheader("TAHAP 5: Simulasi Pemalsuan / Modifikasi Data (Tampering Attack)")
    print("Skenario: Penyerang mengubah 1 karakter pada dokumen saat transmisi:")
    
    pesan_tampered = "Dokumen Kontrak Perjanjian Kerjasama Digital Kriptografi #502725" # '4' diubah jadi '5'
    data_tampered = pesan_tampered.encode("utf-8")
    hash_tampered = rsa_manual.sha256_hex(data_tampered)

    diff_bits, diff_pct = count_bit_difference(hash_asli, hash_tampered)

    print(f"Dokumen Asli      : \"{pesan_asli}\"")
    print(f"Dokumen Diubah    : {RED}\"{pesan_tampered}\"{RESET} (berubah 1 karakter)")
    print(f"Hash Asli         : {hash_asli}")
    print(f"Hash Setelah Tamper: {RED}{hash_tampered}{RESET}")
    print(f"Avalanche Effect  : {BOLD}{diff_bits} dari 256 bit berubah ({diff_pct:.1f}%){RESET}")

    print("\nMencoba memverifikasi dokumen yang telah diubah dengan signature semula...")
    is_valid_tampered = rsa_manual.verify_signature(pub_dict, signature, data_tampered)

    if not is_valid_tampered:
        print(f"Status Verifikasi: {BOLD}{RED}[ INVALID - MODIFIKASI TERDETEKSI! ]{RESET}")
        print(f"{GREEN}[SUCCESS] Tanda tangan digital berhasil menggagalkan manipulasi berkas.{RESET}")
    else:
        print(f"Status Verifikasi: {RED}[ LOLOS (GAGAL UJI) ]{RESET}")

    # -------------------------------------------------------------
    # TAHAP 6: SIMULASI KUNCI PUBLIK YANG SALAH (WRONG KEY ATTACK)
    # -------------------------------------------------------------
    subheader("TAHAP 6: Simulasi Verifikasi Menggunakan Public Key Orang Lain")
    print("Skenario: Dokumen asli diverifikasi menggunakan public key milik orang lain:")
    other_key = rsa_manual.generate_keypair(2048)
    other_pub = {"n": other_key["n"], "e": other_key["e"], "bit_length": other_key["bit_length"]}
    is_valid_wrong_key = rsa_manual.verify_signature(other_pub, signature, data_bytes)

    if not is_valid_wrong_key:
        print(f"Status Verifikasi: {BOLD}{RED}[ INVALID - KUNCI TIDAK COCOK! ]{RESET}")
        print(f"{GREEN}[SUCCESS] Signature ditolak karena penandatangan bukan pemilik kunci ini.{RESET}")

    header("SIMULASI TERMINAL SELESAI DENGAN SUKSES!")


def interactive_menu():
    current_key = None
    last_doc = None
    last_sig = None

    while True:
        header("MENU SIMULASI RSA & DIGITAL SIGNATURE (TERMINAL CLI)")
        print(f"1. {BOLD}Pembangkitan Pasangan Kunci RSA (Keygen 2048/4096 bit){RESET}")
        print(f"2. {BOLD}Hitung Hash Dokumen / Teks (SHA-256 Manual){RESET}")
        print(f"3. {BOLD}Tanda Tangani Dokumen (Sign with Private Key){RESET}")
        print(f"4. {BOLD}Verifikasi Tanda Tangan (Verify with Public Key){RESET}")
        print(f"5. {BOLD}Simulasi Modifikasi Data / Avalanche Effect (Tamper Demo){RESET}")
        print(f"6. {BOLD}Jalankan Full Automated Simulation (Semua Tahap Otomatis){RESET}")
        print(f"0. {BOLD}Keluar{RESET}")

        pilihan = input(f"\n{BOLD}Pilih opsi [0-6]: {RESET}").strip()

        if pilihan == "1":
            print("\nPilih bit length:")
            print("  [1] 2048 bit (Rekomendasi - Cepat ~0.2-1.0 detik)")
            print("  [2] 4096 bit (Sangat Aman - Butuh waktu ~2-8 detik)")
            p_bit = input("Pilihan (1/2, default: 1): ").strip()
            bits = 4096 if p_bit == "2" else 2048

            print(f"Sedang membangkitkan RSA-{bits}...")
            t0 = time.time()
            current_key = rsa_manual.generate_keypair(bits)
            dur = time.time() - t0
            print(f"{GREEN}[OK] Pasangan kunci RSA-{bits} berhasil dibuat ({dur:.2f}s)!{RESET}")
            pub_pem = rsa_manual.export_public_pem(current_key)
            print(f"\nPublic Key (SPKI PEM):\n{pub_pem}")

        elif pilihan == "2":
            teks = input("\nMasukkan teks dokumen: ").strip()
            if not teks:
                teks = "Contoh dokumen digital"
            data = teks.encode("utf-8")
            h = rsa_manual.sha256_hex(data)
            print(f"Teks        : \"{teks}\"")
            print(f"SHA-256 Hex : {GREEN}{h}{RESET}")

        elif pilihan == "3":
            if current_key is None:
                print(f"{YELLOW}[!] Belum ada kunci, membangkitkan RSA-2048 baru terlebih dahulu...{RESET}")
                current_key = rsa_manual.generate_keypair(2048)

            teks = input("\nMasukkan teks dokumen yang ingin ditandatangani: ").strip()
            if not teks:
                teks = "Dokumen verifikasi resmi #001"
            last_doc = teks.encode("utf-8")

            t0 = time.time()
            priv_pem = rsa_manual.export_private_pem(current_key)
            priv_dict = rsa_manual.import_private_pem(priv_pem)
            last_sig = rsa_manual.sign_data(priv_dict, last_doc)
            dur = time.time() - t0

            h = rsa_manual.sha256_hex(last_doc)
            print(f"{GREEN}[OK] Dokumen berhasil ditandatangani ({dur:.4f}s)!{RESET}")
            print(f"Dokumen Hash : {h}")
            print(f"Signature    : {CYAN}{last_sig}{RESET}")

        elif pilihan == "4":
            if current_key is None or last_sig is None or last_doc is None:
                print(f"{YELLOW}[!] Harap lakukan langkah [1] dan [3] terlebih dahulu, atau jalankan opsi [6].{RESET}")
                continue

            print(f"\nMemverifikasi dokumen: \"{last_doc.decode('utf-8', errors='ignore')}\"")
            pub_pem = rsa_manual.export_public_pem(current_key)
            pub_dict = rsa_manual.import_public_pem(pub_pem)
            valid = rsa_manual.verify_signature(pub_dict, last_sig, last_doc)

            if valid:
                print(f"Hasil: {BOLD}{GREEN}[ VALID - DOKUMEN ASLI & TERVERIFIKASI ]{RESET}")
            else:
                print(f"Hasil: {BOLD}{RED}[ INVALID - TANDA TANGAN TIDAK COCOK ]{RESET}")

        elif pilihan == "5":
            if current_key is None or last_sig is None or last_doc is None:
                print(f"{YELLOW}[!] Menyiapkan contoh dokumen dan tanda tangan otomatis terlebih dahulu...{RESET}")
                current_key = rsa_manual.generate_keypair(2048)
                last_doc = "Data Transaksi Transfer Rp 1.000.000 ke Rekening A".encode("utf-8")
                priv_dict = rsa_manual.import_private_pem(rsa_manual.export_private_pem(current_key))
                last_sig = rsa_manual.sign_data(priv_dict, last_doc)

            print(f"\nDokumen Asli : \"{last_doc.decode('utf-8', errors='ignore')}\"")
            h_asli = rsa_manual.sha256_hex(last_doc)
            print(f"Hash Asli    : {h_asli}")

            # Tampering: ubah 1 karakter
            tampered_bytes = bytearray(last_doc)
            tampered_bytes[-1] ^= 0x01
            h_tampered = rsa_manual.sha256_hex(bytes(tampered_bytes))

            diff_bits, diff_pct = count_bit_difference(h_asli, h_tampered)
            print(f"\nDokumen Hasil Tamper: {RED}\"{tampered_bytes.decode('utf-8', errors='ignore')}\"{RESET}")
            print(f"Hash Baru           : {RED}{h_tampered}{RESET}")
            print(f"Avalanche Effect    : {diff_bits}/256 bit berubah ({diff_pct:.1f}%)")

            pub_dict = rsa_manual.import_public_pem(rsa_manual.export_public_pem(current_key))
            valid = rsa_manual.verify_signature(pub_dict, last_sig, bytes(tampered_bytes))

            print(f"Verifikasi Dokumen yang Dimodifikasi: {BOLD}{RED}{'VALID' if valid else 'INVALID (DITOLAK!)'}{RESET}")

        elif pilihan == "6":
            run_full_simulation()

        elif pilihan == "0":
            print("\nTerima kasih! Program selesai.")
            break
        else:
            print(f"{RED}Pilihan tidak valid, silakan coba lagi.{RESET}")

        input(f"\n{DIM}Tekan [Enter] untuk melanjutkan...{RESET}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--auto", "-a"):
        run_full_simulation()
    else:
        interactive_menu()
