#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sisipkan baris status bukti di bawah judul tiap temuan pada laporan.md.

Mengambil pemetaan dari report/evidence.py sehingga markdown dan .docx
tidak mungkin berbeda isi.
"""
import io
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "report"))
import evidence as EV

SRC = "/root/crack/laporan.md"

LABEL = {
    EV.TERBUKTI: "TERBUKTI",
    EV.SEBAGIAN: "SEBAGIAN",
    EV.TIDAK_LANGSUNG: "TIDAK LANGSUNG",
    EV.BELUM: "BELUM DIVERIFIKASI",
}

# Ringkasan singkat per temuan, ditulis merujuk isi yang benar-benar di folder bukti.
SHORT = {
    "F-01": "`5.png` dan `7.png` hanya berisi perintah tanpa output; `6.png` membuktikan HTTP=302 tetapi baris `Masuk sebagai: BlackHat` tidak tercetak. Isi kredensial terbukti ada via `9.png` (MySQL langsung), bukan via SQLi.",
    "F-02": "`3.png` membuktikan kredensial aktif (302 → /dashboard), tetapi `2.png` — yang harus menuntingkan teks `Contoh akun:` — **tidak memuat baris output**. Klaim kredensial tercetak di halaman publik belum terbukti.",
    "F-03": "Tidak ada screenshot permintaan/respons. Hanya artefak tak langsung: akun `zzz_unique_18950` dan `zzz_csrf_31965` di `9.png`.",
    "F-04": "`4.png` memperlihatkan respons JSON `perusahaan_id:2` diambil memakai sesi `individu1` yang `perusahaan_id`-nya NULL. Terbukti.",
    "F-05": "Tidak ada screenshot unggah file maupun XSS tersimpan.",
    "F-06": "Tidak ada screenshot pengujian rate limit. Angka 1.000 permintaan / 946 akun / 5,62 detik berasal dari draf sebelumnya tanpa bukti.",
    "F-07": "Tidak ada screenshot pengujian cookie, logout, session fixation, maupun pemecahan secret.",
    "F-08": "`9.png` memperlihatkan kolom `password` berisi `REDACTED_STORED_PASSWORD` dan `REDACTED_TEST_PASSWORD` dalam teks polos untuk seluruh baris. Terbukti.",
    "F-09": "`scan nmap.png` membuktikan hanya 3 port terbuka tanpa listener TLS. Bukti kredensial terbaca di kabel (tcpdump) tidak direkam.",
    "F-10": "Tidak ada screenshot respons 200 untuk POST lintas-origin. Hanya artefak akun `zzz_csrf_31965` di `9.png`.",
    "F-11": "Tidak ada screenshot permintaan maupun respons `/search`.",
    "F-12": "Tidak ada screenshot pengambilan `/uploads/passwd` maupun kode statusnya.",
    "F-13": "Tidak ada screenshot blok header respons.",
    "F-14": "Tidak ada screenshot pesan error `/register` untuk username ada dan tidak ada.",
    "F-15": "MySQL terbuka (`8.png`, `9.png`) dan SSH root (`10.png`, `11.png`) terbukti. Klaim grup docker, container berjalan sebagai root, dan secret bocor di artefak deployment **tidak** punya screenshot — `11.png` hanya memuat `id`, `uname -a`, `cat /etc/alpine-release`.",
}


def main():
    with io.open(SRC, encoding="utf8") as fh:
        lines = fh.readlines()

    # Buang dulu blok status yang sudah ada agar skrip ini idempoten.
    # Tanpa ini, setiap dijalankan lagi akan menyisipkan blok tambahan.
    cleaned = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("> **Status bukti:"):
            while i < len(lines) and lines[i].startswith(">"):
                i += 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            continue
        cleaned.append(lines[i])
        i += 1
    lines = cleaned

    out = []
    inserted = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = re.match(r"^### (F-\d\d)\b", line)
        if m:
            fid = m.group(1)
            st, shots, _note = EV.FINDING_EVIDENCE[fid]
            ref = ", ".join("`%s`" % s for s in shots) if shots else "**tidak ada berkas bukti**"
            out.append("\n")
            out.append("> **Status bukti: %s** — %s\n" % (LABEL[st], ref))
            out.append(">\n")
            out.append("> %s\n" % SHORT[fid])
            inserted.append(fid)
        i += 1

    with io.open(SRC, "w", encoding="utf8") as fh:
        fh.writelines(out)

    print("annotated: %d temuan" % len(inserted))
    missing = [f for f in ("F-%02d" % n for n in range(1, 16)) if f not in inserted]
    print("tidak ditemukan: %s" % (missing or "tidak ada"))


if __name__ == "__main__":
    main()
