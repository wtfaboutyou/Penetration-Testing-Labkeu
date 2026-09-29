# Penetration-Testing-Labkeu

Laporan **Vulnerability Assessment** black-box terhadap aplikasi LabKeu di `192.168.1.18`.
Lab pribadi (VM VirtualBox), data fiktif, pengujian dilakukan atas target milik sendiri.

## Isi repo

| Berkas | Isi |
|---|---|
| [`laporan.md`](laporan.md) | **Laporan utama.** 10 bagian + lampiran: ringkasan eksekutif, profil target, 15 temuan, temuan negatif, rekomendasi, catatan otorisasi. |
| [`vuln-temuan.md`](vuln-temuan.md) | Narasi lengkap per langkah. Alur mulai dari nol — recon, foothold, SQLi, brute force, dump, eskalasi. |
| `report/` | Kode Python pembentuk versi DOCX dari laporan ini. |
| `annotate_md.py` | Menyuntik blok status bukti ke `laporan.md` (idempoten). |

Kedua dokumen berasal dari satu pengujian yang sama (2026-09-29, 00:08-00:47 WIB,
12 screenshot). `laporan.md` adalah bentuk ringkas yang enak dibaca; `vuln-temuan.md`
menyimpan seluruh perintahnya apa adanya sehingga setiap temuan bisa diverifikasi ulang.

## Ringkasan temuan

15 temuan, 4 kritis. Yang paling serius:

| # | Temuan | Severity |
|---|---|---|
| 1 | SQLi UNION di `/login-noportal` -> auth bypass tanpa kredensial | Kritis |
| 2 | SSH brute-able, login `root` langsung | Kritis |
| 3 | Dump penuh basis data lewat SQLi | Kritis |
| 4 | Cookie sesi tanpa `HttpOnly` / `Secure` / `SameSite` | Tinggi |

Detail lengkap di [`laporan.md`](laporan.md).

## Credential disclosure

Kredensial yang ditemukan **dicantumkan apa adanya** di kedua laporan, tidak disensor --
`labkeu123`, `rootpass`, `labkeu_pass`, dan seed account `password123` ada di sana.
Repo ini meant sebagai referensi cara kerja, dan nilai-nilai tersebut sudah publik di
repo lab sejenis. Kalau kamu butuh versi bersih: ganti semua ke `REDACTED_*`.

## Code

```bash
pip install python-docx
python3 report/build_report.py
```

Hasil: `Laporan-Vulnerability-Assessment-<target>.docx` di direktori induk.
