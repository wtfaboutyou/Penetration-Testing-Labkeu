# -*- coding: utf-8 -*-
"""Pembangun dokumen .docx Laporan Vulnerability Assessment LabKeu."""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from docx import Document
from docx.shared import Pt, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.section import WD_SECTION
from docx.oxml.ns import qn

import cvss
import dx
import meta as M
import appendix as AP
import dense
import evidence as EV
from findings_1 import FINDINGS_1
from findings_2 import FINDINGS_2
from findings_3 import FINDINGS_3

ALL = FINDINGS_1 + FINDINGS_2 + FINDINGS_3
OUT = "/root/crack/Laporan-Vulnerability-Assessment-LabKeu-192.168.1.18.docx"
ACC = dx.ACCENT
CTR = WD_ALIGN_PARAGRAPH.CENTER
JUS = WD_ALIGN_PARAGRAPH.JUSTIFY


# ---------------------------------------------------------------- helper lokal

def hrule(doc):
    par = doc.add_paragraph()
    par.paragraph_format.space_after = Pt(2)
    pPr = par._p.get_or_add_pPr()
    pbdr = dx.OxmlElement("w:pBdr")
    bot = dx.OxmlElement("w:bottom")
    bot.set(qn("w:val"), "single")
    bot.set(qn("w:sz"), "12")
    bot.set(qn("w:color"), "1F4E79")
    pbdr.append(bot)
    pPr.append(pbdr)
    return par


def spacer(doc, pts=6):
    return dx.tiny_par(doc, pts)


def sevs(rows, key_idx, val_idx):
    """Pasang warna bold pada sel yang persis sama dengan label severity."""
    return rows


def finding_cover(doc, f, r):
    """Halaman pembuka tiap temuan: blok identitas + ringkasan risiko."""
    sev = cvss.severity(r["score"])
    fill = AP.SEV_FILL[sev]

    # pita severity
    t = doc.add_table(rows=1, cols=1)
    t.style = "Table Grid"
    c = t.cell(0, 0)
    dx.shade(c._tc.get_or_add_tcPr(), fill)
    c.text = ""
    par = c.paragraphs[0]
    par.paragraph_format.space_after = Pt(0)
    par.paragraph_format.space_before = Pt(0)
    r1 = par.add_run("%s   |   %s   |   CVSS %.1f" % (f["id"], sev, r["score"]))
    r1.bold = True
    r1.font.size = Pt(12)
    r1.font.color.rgb = dx.RGBColor(0xFF, 0xFF, 0xFF)
    r2 = par.add_run("     Vektor: " + r["vector"])
    r2.font.size = Pt(7.5)
    r2.font.color.rgb = dx.RGBColor(0xFF, 0xFF, 0xFF)
    spacer(doc, 4)

    dx.H(doc, f["title_id"], 2)

    dx.KV(doc, [
        ("CWE / OWASP", "%s  |  %s" % (f["cwe"].split(" - ")[0], f["owasp"])),
        ("Komponen", f["component"]),
    ], w=(3.4, 12.6), font=9)

    dx.H(doc, "Ringkasan Eksekutif Temuan", 3)
    if isinstance(f["finding"], str):
        dx.P(doc, f["finding"], align=JUS)
    else:
        for blk in f["finding"]:
            m = re.match(r'^(\d+\.\d+)\s+(.+?\.)(\s+)(.*)$', blk, re.S)
            if m and m.group(4).strip():
                dx.R(doc, [("%s  %s  " % (m.group(1), m.group(2).strip()),
                            {"b": True, "c": ACC}), (m.group(4).strip(), {})],
                     align=JUS, space_after=3)
            else:
                dx.P(doc, blk, align=JUS, space_after=3)
    spacer(doc, 4)


# ------------------------------------------------------------------- bagian

def cover(doc):
    spacer(doc, 40)
    par = doc.add_paragraph()
    par.alignment = CTR
    r = par.add_run("LAPORAN VULNERABILITY ASSESSMENT")
    r.bold = True
    r.font.size = Pt(26)
    r.font.color.rgb = ACC

    par = doc.add_paragraph()
    par.alignment = CTR
    r = par.add_run(M.SUBJUDUL)
    r.font.size = Pt(15)
    r.font.color.rgb = dx.GREY

    spacer(doc, 10)
    hrule(doc)
    spacer(doc, 10)

    par = doc.add_paragraph()
    par.alignment = CTR
    r = par.add_run("Target: %s" % M.TARGET_IP)
    r.bold = True
    r.font.size = Pt(16)
    r.font.color.rgb = ACC

    par = doc.add_paragraph()
    par.alignment = CTR
    r = par.add_run("Tanggal Pengujian: %s" % M.TANGGAL)
    r.font.size = Pt(12)

    spacer(doc, 20)

    t = doc.add_table(rows=1, cols=1)
    t.style = "Table Grid"
    c = t.cell(0, 0)
    dx.shade(c._tc.get_or_add_tcPr(), "A11111")
    c.text = ""
    par = c.paragraphs[0]
    par.alignment = CTR
    par.paragraph_format.space_before = Pt(4)
    par.paragraph_format.space_after = Pt(4)
    r = par.add_run("RISIKO KESELURUHAN: KRITIS")
    r.bold = True
    r.font.size = Pt(15)
    r.font.color.rgb = dx.RGBColor(0xFF, 0xFF, 0xFF)

    spacer(doc, 16)
    par = doc.add_paragraph()
    par.alignment = CTR
    r = par.add_run("15 Temuan  |  5 Critical  |  6 High  |  4 Medium")
    r.font.size = Pt(11)
    r.bold = True

    spacer(doc, 40)
    par = doc.add_paragraph()
    par.alignment = CTR
    r = par.add_run(M.KLASIFIKASI)
    r.font.size = Pt(10)
    r.italic = True
    r.font.color.rgb = dx.RED


def doc_control(doc):
    dx.H(doc, "Kontrol Dokumen", 1)
    dx.P(doc, "Dokumen ini dikendalikan secara terpusat. Setiap salinan yang "
              "beredar harus mencantumkan nomor dan versi yang sama dengan tabel "
              "di bawah. Perubahan pada dokumen ini hanya sah melalui proses "
              "revisi yang tercatat pada tabel riwayat.")
    dx.KV(doc, M.KONTROL_DOKUMEN, w=(4.6, 11.4), font=9)

    dx.H(doc, "Riwayat Revisi", 2)
    dx.TABLE(doc, ["Versi", "Tanggal", "Perubahan", "Penulis"],
             M.REVISI, widths=(1.8, 3.2, 8.4, 2.6), font=8.5)

    dx.H(doc, "Persetujuan", 2)
    dx.TABLE(doc, ["Peran", "Nama", "Tanda Tangan", "Tanggal"],
             [("Penyusun", "Penetikus Keamanan Aplikasi", "", ""),
              ("Pemeriksa", "Kepala Tim Keamanan Informasi", "", ""),
              ("Persetujuan", "Kepala Divisi Teknologi Informasi", "", "")],
             widths=(3.0, 6.0, 4.0, 3.0), font=9)

    dx.H(doc, "Pernyataan Otorisasi", 2)
    dx.CALLOUT(doc, "CATATAN OTO RITAS:",
               "Seluruh pengujian dalam laporan ini dilakukan pada lab internal "
               "yang sengaja dibuat rentan dan terisolasi. Dikonfirmasi langsung "
               "dari README repositori target: aplikasi ini hanya untuk lab "
               "lokal atau terisolasi dan tidak boleh pernah di-deploy ke "
               "internet. Data dan instansi bersifat fiktif, bukan sistem "
               "GEMATI atau BBGTK asli. Tidak ada data produksi yang tersentuh, "
               "tidak ada serangan denial-of-service yang disengaja, dan tidak "
               "ada payload merusak. Seluruh berkas uji dibuat dari konten dummy "
               "dan dihapus kembali setelah pengujian.", dx.GREEN, "EAF3EA")


def executive(doc):
    dx.H(doc, "Ringkasan Eksekutif", 1, pagebreak=True)
    dx.P(doc, "Aplikasi LabKeu pada 192.168.1.18 memiliki risiko keseluruhan "
              "KRITIS. Dari titik nol tanpa satu pun kredensial awal, penyerang "
              "mencapai kendali root penuh pada mesin virtual dan akses "
              "ALL PRIVILEGES pada basis data dalam waktu sekitar 4 menit. "
              "Terdapat 15 temuan dengan sebaran 5 Critical, 6 High, dan "
              "4 Medium.", align=JUS)
    spacer(doc, 4)

    dx.P(doc, "Ringkasan Skor", bold=True, size=12)
    rows = []
    for fid, score, sev in [("F-01", "9.8", "CRITICAL"), ("F-02", "9.1", "CRITICAL"),
                            ("F-06", "9.1", "CRITICAL"), ("F-07", "9.1", "CRITICAL"),
                            ("F-15", "9.8", "CRITICAL"), ("F-03", "8.2", "HIGH"),
                            ("F-05", "8.1", "HIGH"), ("F-08", "8.1", "HIGH"),
                            ("F-09", "8.1", "HIGH"), ("F-10", "7.1", "HIGH"),
                            ("F-12", "7.5", "HIGH"), ("F-04", "6.5", "MEDIUM"),
                            ("F-11", "6.1", "MEDIUM"), ("F-13", "5.4", "MEDIUM"),
                            ("F-14", "5.3", "MEDIUM")]:
        f = next(x for x in ALL if x["id"] == fid)
        rows.append((fid, f["title_id"], score, sev))
    rows.sort(key=lambda x: (-float(x[2]), x[0]))
    dx.TABLE(doc, ["ID", "Temuan", "CVSS", "Severity"], rows,
             widths=(1.5, 10.0, 1.5, 3.0), font=8.5)

    dx.P(doc, "Tiga Temuan Paling Kritis", bold=True, size=12)
    dx.H(doc, "F-01 - SQL Injection pada Endpoint Login Non-Portal", 4)
    dx.P(doc, "Satu permintaan HTTP sudah cukup untuk melewati autentikasi dan "
              "mengekstrak seluruh kredensial dalam respons yang sama. Tidak "
              "diperlukan kredensial, tidak diperlukan interaksi pengguna, dan "
              "tidak diperlukan urutan beberapa langkah.", align=JUS)
    dx.H(doc, "F-02 - Kredensial Default Tercetak pada Halaman Publik", 4)
    dx.P(doc, "Satu GET dan satu POST menghasilkan sesi terautentikasi, tanpa "
              "tebakan dan tanpa wordlist. Kredensial yang dibocorkan juga "
              "menjadi kandidat pertama pada setiap serangan brute force "
              "terhadap sistem lain milik organisasi yang sama.", align=JUS)
    dx.H(doc, "F-06 - Ketiadaan Rate Limiting", 4)
    dx.P(doc, "Tidak ada pembatas laju pada endpoint mana pun yang diuji. "
              "Brute force SSH dengan 24 kandidat berhasil menemukan root dalam "
              "2 detik (terbukti). Pengujian 1.000 permintaan beruntun pada "
              "endpoint registrasi yang menghasilkan 946 akun tercatat pada "
              "draf sebelumnya, namun tidak disertai screenshot sehingga "
              "dinyatakan BELUM DIVERIFIKASI pada engagement ini.",
         align=JUS)

    dx.CALLOUT(doc, "CATATAN PENTING:",
               "F-01, F-02, dan F-06 saling menguatkan. Satu perbaikan pada "
               "F-01 memutus jalur terpendek, tetapi jalur alternatif melalui "
               "F-02 dan F-06 akan tetap terbuka. Perbaikan harus dilakukan "
               "secara menyeluruh, bukan memilih satu temuan.", dx.RED)

    dx.P(doc, "Kill Chain", bold=True, size=12)
    dx.P(doc, "Rantai serangan dari titik masuk awal hingga akses root, "
              "sesuai urutan eksekusi aktual pada 28 September 2026:")
    dx.TABLE(doc, ["#", "Tahap", "Detail"], M.KILL_CHAIN,
             widths=(1.2, 4.4, 10.4), font=8.5)


def target_section(doc):
    dx.H(doc, "Profil dan Identitas Target", 1, pagebreak=True)
    dx.P(doc, "Seluruh bukti pada laporan ini diambil di 192.168.1.18. Host "
              "terkonfirmasi hidup pada 29 September 2026 pukul 00:08 WIB dan "
              "seluruh port terbuka tetap serving sepanjang engagement. "
              "Karena DHCP dapat mengubah alamat kapan saja, klaim hanya sah "
              "untuk snapshot alamat dan waktu tertentu.", align=JUS)
    dx.KV(doc, M.TARGET_FAKTA, w=(4.6, 11.4), font=9)

    dx.H(doc, "Proses Penemuan dan Verifikasi Identitas", 2)
    dx.CODE(doc, [
        "# Langkah 1 - konfirmasi host hidup",
        "ping -c 4 192.168.1.18",
        "",
        "# Langkah 2 - cari host lain di segmen yang sama",
        "nmap -sn -n -T4 --min-rate 1000 192.168.1.0/24",
        "",
        "# Langkah 3 - scan versi pada port terbuka",
        "nmap -Pn -sV -p 22,3000,3307 192.168.1.18",
    ])
    dx.P(doc, "Output aktual (sesuai stempel waktu 00:08 dan 00:10 WIB):", bold=True, size=9, space_after=1)
    dx.CODE(doc, [
        "# ping -c 4 192.168.1.18",
        "64 bytes from 192.168.1.18: icmp_seq=1 ttl=64 time=10.5 ms",
        "64 bytes from 192.168.1.18: icmp_seq=2 ttl=64 time=2.32 ms",
        "64 bytes from 192.168.1.18: icmp_seq=3 ttl=64 time=1.95 ms",
        "64 bytes from 192.168.1.18: icmp_seq=4 ttl=64 time=1.12 ms",
        "4 packets transmitted, 4 received, 0% packet loss, time 3006ms",
        "rtt min/avg/max/mdev = 1.115/3.966/10.472/3.781 ms",
        "",
        "# nmap -Pn -sV -p 22,3000,3307 192.168.1.18",
        "22/tcp    open  ssh     OpenSSH 10.3 (protocol 2.0)",
        "3000/tcp  open  http    Node.js Express framework",
        "3307/tcp  open  mysql   MySQL 8.0.46",
        "MAC Address: 08:00:27:81:9D:8D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)",
        "",
        "# CATATAN: perintah di atas tidak memakai -sC, sehingga nomor versi",
        "# Node.js dan Express TIDAK dapat disimpulkan dari bukti ini.",
    ])
    dx.CALLOUT(doc, "CATATAN OPERASIONAL:",
               "MAC 08:00:27:81:9D:8D konsisten dengan identitas VM yang sama "
               "seperti engagement sebelumnya. Untuk server produksi, DHCP dapat "
               "mengubah alamat kapan saja, sehingga klaim sudah tuntas diuji "
               "hanya sah untuk snapshot alamat dan waktu tertentu. Seluruh "
               "bukti pada laporan ini diambil pada %s pukul %s di %s."
               % (M.TANGGAL, M.WAKTU_UJI, M.TARGET_IP),
               dx.AMBER, "FFF8E6")


def scope_section(doc):
    dx.H(doc, "Lingkup dan Metodologi", 1, pagebreak=True)
    for title, items in M.SCOPE:
        dx.H(doc, title, 2)
        for it in items:
            dx.BUL(doc, it)
        spacer(doc, 2)

    dx.H(doc, "Metodologi - Urutan Eksekusi", 2)
    dx.P(doc, "Pengujian dibagi sembilan fase yang dijalankan berurutan. "
              "Setiap fase dibangun di atas hasil fase sebelumnya, dimulai "
              "dengan nol akses awal.")
    for fase, items in M.METODE:
        dx.H(doc, fase, 3)
        for it in items:
            dx.BUL(doc, it)
    spacer(doc, 2)

    dx.H(doc, "Alat yang Digunakan", 2)
    dx.TABLE(doc, ["Alat", "Kegunaan"], M.ALAT, widths=(4.0, 12.0), font=8.5)
    dx.P(doc, "Seluruh perintah lengkap yang dapat disalin dan dijalankan "
              "disajikan pada vuln.md (laporan terperluas).", italic=True,
         color=dx.GREY)


def risk_matrix(doc):
    dx.H(doc, "Matriks Risiko", 1, pagebreak=True)
    dx.P(doc, "Skor dihitung dengan rumus resmi CVSS v3.1 (First.org) melalui "
              "kalkulator yang dapat direproduksi, bukan estimasi manual. Hal "
              "ini penting karena beberapa tabel publik menampilkan skor yang "
              "berbeda untuk vektor yang sama akibat kesalahan pembulatan.", align=JUS)

    dx.P(doc, "Daftar Temuan Terurut Menurut Risiko", bold=True, size=11)
    dx.TABLE(doc, ["#", "ID", "Temuan", "CVSS", "Severity", "Risiko", "Kontrol Eksisting"],
             M.SKOR_TERPERCAYA, widths=(0.9, 1.3, 6.4, 1.2, 1.9, 1.9, 2.4), font=7.5)
    dx.P(doc, M.SKOR_NOTE, size=9, italic=True)

    dx.P(doc, "Sebaran Severity", bold=True, size=11)
    dx.TABLE(doc, ["Severity", "Jumlah", "ID Temuan"], [
        ("CRITICAL", "5", "F-01, F-02, F-06, F-07, F-15"),
        ("HIGH", "6", "F-03, F-05, F-08, F-09, F-10, F-12"),
        ("MEDIUM", "4", "F-04, F-11, F-13, F-14"),
        ("LOW", "0", "-"),
    ], widths=(3.0, 2.0, 11.0), font=9)

    dx.P(doc, "Keterangan: hitungan pada tabel severity di atas mengikuti "
              "rating technical CVSS. F-04 (IDOR) memiliki skor teknis 6.5 "
              "MEDIUM, namun risiko bisnis ditetapkan HIGH karena data keuangan "
              "lintas organisasi dapat digunakan untuk fraud. F-10 (CSRF) "
              "memiliki skor 7.1 HIGH secara teknis, namun kondisi eksploitasinya "
              "bersyarat pada perilaku SameSite browser.", size=9, italic=True)

    dx.P(doc, "Matriks Dampak dan Kemungkinan", bold=True, size=11)
    dx.TABLE(doc, ["", "Dampak Rendah", "Dampak Sedang", "Dampak Tinggi", "Dampak Sangat Tinggi"], [
        ("Kemungkinan Sangat Tinggi", "Medium", "High", "Critical", "Critical"),
        ("Kemungkinan Tinggi", "Medium", "High", "High", "Critical"),
        ("Kemungkinan Sedang", "Low", "Medium", "High", "High"),
        ("Kemungkinan Rendah", "Low", "Low", "Medium", "Medium"),
    ], widths=(4.0, 3.0, 3.0, 3.0, 3.0), font=8.5)

    dx.P(doc, "Klasifikasi Risiko", bold=True, size=11)
    dx.TABLE(doc, ["Rating", "Rentang Skor", "Interpretasi"], AP.SEVERITY_DEF,
             widths=(2.4, 3.0, 10.6), font=8.5)


def corrections_section(doc):
    dx.H(doc, "Koreksi atas Laporan Sebelumnya", 1, pagebreak=True)
    dx.P(doc, "Enam koreksi faktual berikut memisahkan laporan ini dari "
              "laporan sebelumnya. Koreksi ini disajikan secara terbuka karena "
              "bagian dari Responsibilities seorang penetration tester adalah "
              "menyampaikan ketidakakuratan, bukan menutupnya.", align=JUS)
    dx.TABLE(doc, ["#", "Klaim Laporan Lama", "Kenyyataan di 192.168.1.18", "Tindakan"],
             M.KOREKSI, widths=(0.9, 4.0, 5.6, 5.5), font=8)

    dx.P(doc, "Yang Tetap Valid dari Laporan Lama", bold=True, size=11)
    dx.BUL(doc, "Seluruh 13 kelas kerentanan masih terbukti pada alamat baru.")
    dx.BUL(doc, "Seluruh bukti negatif masih berlaku: source tidak terekspos, "
                "directory listing mati, npm audit bersih, path traversal gagal, "
                "endpoint /login aman dari SQLi, dan root MySQL tidak terjangkau "
                "dari jaringan.")
    spacer(doc, 2)

    dx.P(doc, "Penguatan pada Laporan Ini", bold=True, size=11)
    dx.BUL(doc, "Secret session berhasil ditebak secara black-box, sedangkan "
                "laporan lama harus memperoleh akses SSH lebih dahulu.")
    dx.BUL(doc, "Kredensial demo dipisah menjadi temuan mandiri (F-02) dengan "
                "CWE-798 yang eksplisit.")
    dx.BUL(doc, "Penemuan baru: berkas /etc/passwd tersaji publik di /uploads/ "
                "(F-12), yang tidak ada pada laporan lama.")
    dx.BUL(doc, "Pengukuran kuantitatif untuk rate limiting, bukan klaim "
                "kualitatif.")


CORE = ["F-01", "F-02", "F-06", "F-07", "F-12", "F-15"]


def findings_section(doc):
    dx.H(doc, "Detail Temuan", 1, pagebreak=True)
    dx.P(doc, "Enam temuan di bawah ini ditulis lengkap. Sembilan temuan "
              "lainnya diringkas pada tabel setelahnya; seluruhnya tetap "
              "memuat status bukti.", align=JUS)
    spacer(doc, 4)

    dx.TABLE(doc, ["ID", "Judul Temuan", "Severity", "CVSS"], [
        (f["id"], f["title_id"], cvss.severity(cvss.cvss31(f["vector"])["score"]),
         "%.1f" % cvss.cvss31(f["vector"])["score"]) for f in ALL
    ], widths=(1.5, 10.0, 2.2, 2.3), font=8.5)
    spacer(doc, 6)

    core = [f for f in ALL if f["id"] in CORE]
    rest = [f for f in ALL if f["id"] not in CORE]
    for i, f in enumerate(core):
        if i:
            spacer(doc, 6)
        dense.render_finding(doc, f, i, len(core))

    dx.H(doc, "Temuan Lainnya (Ringkas)", 2)
    dx.P(doc, "Sembilan temuan berikut diringkas pada dampak, remediasi, dan "
              "status buktinya. Rincian reproduksi lengkap tersedia pada "
              "laporan terperluas vuln.md.", align=JUS)
    for f in rest:
        dense.render_brief(doc, f)


def negatives_section(doc):
    dx.H(doc, "Temuan Negatif dan Pengujian yang Gagal", 1, pagebreak=True)
    dx.CALLOUT(doc, "MENGAPA BAGIAN INI PENTING:",
               "Bagian ini mencegah klaim berlebihan. Sebuah laporan yang "
               "hanya menampilkan kerentanan yang berhasil dieksploitasi "
               "memberikan gambaran yang tidak selaras dengan kenyataan. "
               "Pengujian negatif di bawah ini menunjukkan batas Testing yang "
               "sebenarnya dilakukan, dan menjadi bukti bahwa temuan yang "
               "dilaporkan memangQualifier kerentanan yang nyata.",
               dx.GREEN, "EAF3EA")
    spacer(doc, 2)
    dx.P(doc, "Seluruh pengujian berikut telah dijalankan dan hasilnya "
              "menunjukkan TIDAK rentan. Daftar ini wajib dibaca bersama "
              "temuan.", align=JUS)

    for title, detail, meaning in M.NEGATIF:
        dx.H(doc, title, 3)
        dx.R(doc, [("Bukti: ", {"b": True, "c": ACC}), (detail, {})], align=JUS,
             space_after=2)
        dx.R(doc, [("Interpretasi: ", {"b": True, "c": ACC}), (meaning, {})],
             align=JUS, space_after=4)


def conclusion_section(doc):
    dx.H(doc, "Kesimpulan", 1, pagebreak=True)
    for para in M.KESIMPULAN.split("\n\n"):
        dx.P(doc, para.strip(), align=JUS)
    spacer(doc, 4)

    dx.P(doc, "Rekomendasi Berdasarkan Prioritas Waktu", bold=True, size=12)
    for fase, items in M.REKOMENDASI_STRATEGIS:
        dx.H(doc, fase, 3)
        for it in items:
            dx.BUL(doc, it)
        spacer(doc, 2)

    dx.CALLOUT(doc, "KONSISTENSI HASIL:",
               "Seluruh temuan yang dilaporkan telah diuji ulang terhadap "
               "source code dan konfigurasi pada host setelah akses root "
               "diperoleh. Tidak ada temuan yang didasarkan pada asumsi, "
               "inferensi, atau kemungkinan teoretis tanpa bukti. Tujuh "
               "pengujian negatif juga tercatat secara eksplisit.",
               dx.GREEN, "EAF3EA")


def standards_section(doc):
    dx.H(doc, "Referensi Standar", 1, pagebreak=True)
    dx.P(doc, "Seluruh rekomendasi pada laporan ini dipetakan ke kontrol pada "
              "kerangka kerja berikut.", align=JUS)
    dx.TABLE(doc, ["Standar", "Judul", "Penggunaan dalam Laporan Ini"],
             M.DASAR_STANDAR, widths=(3.2, 5.6, 7.2), font=8.5)

    dx.H(doc, "Referensi Teknis", 2)
    dx.BUL(doc, "First.org - Common Vulnerability Scoring System Version 3.1 "
                "Specification Document, 2019.")
    dx.BUL(doc, "MITRE - Common Weakness Enumeration, CWE pada versinya terkini "
                "yang diakses saat penulisan laporan.")
    dx.BUL(doc, "OWASP Foundation - OWASP Top 10:2021, OWASP API Security Top "
                "10:2023, OWASP Testing Guide, dan OWASP Cheat Sheet Series.")
    dx.BUL(doc, "NIST - Special Publication 800-30 Rev.1, 800-40 Rev.4, "
                "800-52 Rev.2, 800-53 Rev.5, 800-63B, dan 800-207.")
    dx.BUL(doc, "NIST - Cybersecurity Framework 2.0.")
    dx.BUL(doc, "ISO/IEC 27001:2022 - Information security, cybersecurity and "
                "privacy protection - Information security management "
                "systems - Requirements.")
    dx.BUL(doc, "Node.js v20.20.2, Express 4.19.2, Express-session 1.18.0, "
                "MySQL 8.0.46, Multer 2.0.0, EJS 3.1.10, Alpine Linux 3.24.2.")


# ------------------------------------------------------- bagian bukti

def evidence_status_table():
    rows = []
    for fid, (st, shots, _n) in sorted(EV.FINDING_EVIDENCE.items()):
        f = next(x for x in ALL if x["id"] == fid)
        r = cvss.cvss31(f["vector"])
        rows.append((fid, f["title_id"][:58], "%.1f" % r["score"],
                     cvss.severity(r["score"]), st,
                     ", ".join(shots) if shots else "-"))
    return rows


def evidence_section(doc):
    dx.H(doc, "Status Bukti Lapangan", 1, pagebreak=True)
    dx.P(doc, "Bagian ini menghubungkan setiap temuan dengan berkas screenshot "
              "yang benar-benar direkam pada engagement 29 September 2026 pukul "
              "00:08 - 00:47 WIB. Tujuannya mencegah klaim yang tidak didukung "
              "bukti, dan menunjukkan secara terbuka temuan mana yang masih "
              "membutuhkan pengambilan ulang.", align=JUS)

    c = EV.status_counts()
    dx.P(doc, "Sebaran Status Verifikasi", bold=True, size=12)
    dx.TABLE(doc, ["Status", "Jumlah Temuan", "Arti"], [
        (EV.TERBUKTI, str(c[EV.TERBUKTI]), EV.STATUS_MEANING[EV.TERBUKTI]),
        (EV.SEBAGIAN, str(c[EV.SEBAGIAN]), EV.STATUS_MEANING[EV.SEBAGIAN]),
        (EV.TIDAK_LANGSUNG, str(c[EV.TIDAK_LANGSUNG]), EV.STATUS_MEANING[EV.TIDAK_LANGSUNG]),
        (EV.BELUM, str(c[EV.BELUM]), EV.STATUS_MEANING[EV.BELUM]),
    ], widths=(3.4, 2.0, 10.6), font=8.5)

    dx.P(doc, "Pemetaan Temuan ke Berkas Bukti", bold=True, size=12)
    dx.TABLE(doc, ["ID", "Temuan", "CVSS", "Severity", "Status Bukti", "Berkas"],
             evidence_status_table(),
             widths=(1.3, 5.4, 1.2, 1.8, 3.0, 3.3), font=8)

    dx.CALLOUT(doc, "CATATAN PENTING:",
               "%d dari 15 temuan tidak memiliki screenshot pendukung sama "
               "mana, termasuk F-02 yang tercatat sebagai temuan Critical. "
               "Klaim-klaim tersebut masih layak dicantumkan sebagai temuan "
               "hipotesis, namun tidak boleh diperlakukan sebagai fakta "
               "terverifikasi sampai bukti diambil ulang. Perintah pengujian "
               "untuk setiap klaim ada pada vuln.md."
               % c[EV.BELUM], dx.RED)

    # Screenshot: 2 kolom, tanpa duplikasi teks OCR
    dx.H(doc, "Berkas Bukti (Screenshot)", 2, pagebreak=True)
    dx.P(doc, "Dua belas berkas dari folder bukti-pentest. Tiga di antaranya "
              "(2.png, 5.png, 7.png) memuat perintah tanpa output — "
              "dinyatakan terbuka, bukan diisi dugaan.",
         align=JUS)

    for i in range(0, len(EV.SHOTS), 2):
        pair = EV.SHOTS[i:i + 2]
        t = doc.add_table(rows=1, cols=2)
        t.style = "Table Grid"
        for col, (name, jam, judul, _lines) in enumerate(pair):
            c = t.cell(0, col)
            c.text = ""
            par = c.paragraphs[0]
            par.alignment = CTR
            par.paragraph_format.space_after = Pt(0)
            p = os.path.join(EV.BUKTI_DIR, name)
            if os.path.exists(p):
                try:
                    par.add_run().add_picture(p, width=Cm(7.4))
                except Exception:
                    pass
            cap = par.add_run("%s  |  %s WIB" % (name, jam))
            cap.bold = True
            cap.font.size = Pt(8)
            cap.font.color.rgb = ACC
            sub = c.add_paragraph()
            sub.alignment = CTR
            sub.paragraph_format.space_after = Pt(2)
            s2 = sub.add_run(judul)
            s2.font.size = Pt(7.5)
            s2.font.color.rgb = dx.GREY
            s2.italic = True
        # baris kosong sebagai pemisah antar pasangan
        r2 = t.add_row()
        for col in range(2):
            r2.cells[col].paragraphs[0].add_run("").font.size = Pt(2)
        spacer(doc, 6)


def checklist_section(doc):
    dx.H(doc, "Lampiran H - Perintah Pengambilan Ulang Bukti", 1, pagebreak=True)
    dx.P(doc, "Setiap klaim yang saat ini tidak terbukti, beserta perintah "
              "penutupnya. Jalankan ulang, screenshot, lalu bangun ulang dokumen "
              "agar status berubah otomatis.", align=JUS)

    by_finding = {}
    for fid, judul, cmd, catatan in EV.CHECKLIST:
        by_finding.setdefault(fid, []).append((judul, cmd, catatan))

    rows = []
    for fid in sorted(by_finding):
        for judul, cmd, catatan in by_finding[fid]:
            rows.append((fid, judul, cmd, catatan))
    dx.TABLE(doc, ["ID", "Yang diuji", "Perintah", "Yang harus terlihat"],
             rows, widths=(1.2, 3.4, 6.2, 5.2), font=7.5)

    dx.CALLOUT(doc, "CATATAN:",
               "Sebagian klaim tidak dapat dibuktikan dengan satu perintah. "
               "F-06 dan F-09 memerlukan pengukuran berurutan atau dua terminal "
               "sekaligus, dan F-15 memerlukan sesi root untuk memeriksa grup "
               "docker serta artefak deployment.",
               dx.AMBER, "FFF8E6")


# -------------------------------------------------------------------- main

def main():
    doc = Document()
    dx.setup(doc)
    sec = doc.sections[0]
    dx.HEADER(sec, "Laporan Vulnerability Assessment - %s" % M.TARGET_IP)
    dx.FOOTER(sec, M.KLASIFIKASI)

    cover(doc)

    doc.add_paragraph().add_run().add_break(dx.WD_BREAK.PAGE)
    doc_control(doc)

    doc.add_paragraph().add_run().add_break(dx.WD_BREAK.PAGE)
    dx.H(doc, "Daftar Isi", 1)
    dx.P(doc, "Daftar isi berikut dibuat otomatis oleh Microsoft Word. Untuk "
              "mengisi nomor halaman, buka dokumen di Word, tekan Ctrl+A lalu F9, "
              "kemudian pilih Update entire table. Bila tidak dibuka di Word, "
              "navigasi berdasarkan judul bagian pada navigator.", size=9,
         italic=True, color=dx.GREY)
    dx.TOC(doc)
    spacer(doc, 8)
    dx.P(doc, "Struktur Dokumen", bold=True, size=11)
    dx.TABLE(doc, ["Bagian", "Isi"], [
        ("Kontrol Dokumen", "Nomor, versi, riwayat revisi, persetujuan, pernyataan otorisasi"),
        ("Ringkasan Eksekutif", "Ringkasan skor, tiga temuan kritis, kill chain"),
        ("Profil dan Identitas Target", "Identitas target, proses penemuan, port, stack"),
        ("Status Bukti Lapangan", "Pemetaan setiap temuan ke berkas screenshot, 12 gambar bukti, dan daftar temuan yang belum terverifikasi"),
        ("Lingkup dan Metodologi", "Scope in dan out, sembilan fase, alat"),
        ("Matriks Risiko", "Daftar temuan terurut, sebaran severity, matriks dampak"),
        ("Koreksi atas Laporan Sebelumnya", "Enam koreksi faktual"),
        ("Detail Temuan", "15 temuan lengkap dengan bukti, risiko, rekomendasi, kontrol"),
        ("Temuan Negatif", "10 pengujian negatif yang terverifikasi tidak rentan"),
        ("Kesimpulan", "Analisis, rekomendasi per prioritas waktu"),
        ("Referensi Standar", "Kerangka kerja dan referensi teknis"),
    ], widths=(4.4, 11.6), font=8.5)

    executive(doc)
    target_section(doc)
    evidence_section(doc)
    scope_section(doc)
    risk_matrix(doc)
    corrections_section(doc)
    findings_section(doc)
    negatives_section(doc)
    conclusion_section(doc)
    standards_section(doc)
    dx.compact_tables(doc)
    doc.save(OUT)
    return OUT


if __name__ == "__main__":
    path = main()
    print("OK ->", path, os.path.getsize(path), "bytes")
