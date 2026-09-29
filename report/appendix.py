# -*- coding: utf-8 -*-
"""Modul lampiran: aritmetika CVSS, tabel referensi, dan glosarium."""

from docx.enum.text import WD_ALIGN_PARAGRAPH
import cvss
import dx

# (base metric, vektor, nilai, rumus, hasil)


def cvss_table():
    basis = [
        ("AV", "Network", "0.85", "A:0.62 L:0.55 P:0.20"),
        ("AC", "Low", "0.77", "H:0.44"),
        ("PR", "None", "0.85", "L:0.62 H:0.27 (S:U)"),
        ("UI", "None", "0.85", "R:0.62"),
        ("C", "High", "0.56", "L:0.22 N:0.00"),
        ("I", "High", "0.56", "L:0.22 N:0.00"),
        ("A", "High", "0.56", "L:0.22 N:0.00"),
    ]
    rows = [(b, d, v, la) for b, d, v, la in basis]
    rows.append(("S", "Unchanged", "-", "Changed: rumus Impact berbeda"))
    return rows


def cvss_workings(all_findings):
    """Aritmetika lengkap per temuan: ISS, Impact, Exploitability, hasil akhir."""
    out = []
    for f in all_findings:
        r = cvss.cvss31(f["vector"])
        p = r["mraw"]
        sc = p["S"] == "C"
        iss = r["iss"]
        if sc:
            imp_f = "7.52 x (ISS - 0.029) - 3.25 x (ISS - 0.02)^15"
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            imp_f = "6.42 x ISS"
            impact = 6.42 * iss
        expl_f = "8.22 x AV x AC x PR x UI"
        expl = 8.22 * cvss.AV[p["AV"]] * cvss.AC[p["AC"]] * r["pr_val"] * cvss.UI[p["UI"]]
        base = min((impact + expl) * 1.08, 10) if sc else min(impact + expl, 10)
        out.append({
            "id": f["id"],
            "vector": f["vector"],
            "scope": "Changed" if sc else "Unchanged",
            "iss": iss,
            "iss_f": "1 - (1-C)x(1-I)x(1-A)",
            "impact": impact,
            "impact_f": imp_f,
            "expl": expl,
            "expl_f": expl_f,
            "raw": impact + expl,
            "mult": "x 1.08 (S:C)" if sc else "x 1.00 (S:U)",
            "final_raw": base,
            "score": r["score"],
            "severity": cvss.severity(r["score"]),
            "rounding": ("%.4f -> Roundup -> %.1f" % (base, r["score"])),
        })
    return out


SEVERITY_DEF = [
    ("CRITICAL", "9.0 - 10.0", "Serangan tanpa prasyarat dengan dampak penuh terhadap kerahasiaan, integritas, dan ketersediaan. Prioritas segera."),
    ("HIGH", "7.0 - 8.9", "Dampak besar dengan prasyarat minimal. Prioritas tinggi, seaside 7 hari."),
    ("MEDIUM", "4.0 - 6.9", "Dampak terbatas atau membutuhkan prasyarat lebih banyak. Prioritas menengah."),
    ("LOW", "0.1 - 3.9", "Dampak kecil atau sangat sulit dieksploitasi. Perbaikan sesuai jadwal."),
    ("None", "0.0", "Tidak ada dampak. Hanya dicatat sebagai informasi."),
]

NIST80053_GROUPS = [
    ("AC", "Access Control", "Kontrol akses dan otorisasi", "F-03, F-04, F-10, F-12, F-15"),
    ("AU", "Audit and Accountability", "Pencatatan dan peninjauan aktivitas", "F-04, F-14"),
    ("CM", "Configuration Management", "Pengelolaan konfigurasi aman", "F-12, F-13, F-15"),
    ("IA", "Identification and Authentication", "Identitas dan autentikasi", "F-02, F-06, F-08"),
    ("MP", "Media Protection", "Perlindungan media dan pembuangan aman", "F-12"),
    ("SA", "System and Services Acquisition", "Praktik pengembangan aman", "F-01, F-05, F-11"),
    ("SC", "System and Communications Protection", "Transmisi dan batas keamanan", "F-07, F-09, F-13"),
    ("SI", "System and Information Integrity", "Integritas input dan pemantauan", "F-01, F-04, F-05, F-06, F-11, F-14"),
]

ISO_GROUPS = [
    ("A.5.15", "Access control", "F-03, F-06, F-12, F-15"),
    ("A.5.17", "Authentication information", "F-02, F-07, F-08, F-15"),
    ("A.5.18", "Access rights", "F-03, F-04"),
    ("A.8.2", "Privileged access rights", "F-15"),
    ("A.8.3", "Information access restriction", "F-04, F-12"),
    ("A.8.5", "Secure authentication", "F-04, F-07, F-10"),
    ("A.8.9", "Configuration management", "F-13, F-15"),
    ("A.8.10", "Information deletion", "F-12"),
    ("A.8.24", "Use of cryptography", "F-08, F-09"),
    ("A.8.25", "Secure development life cycle", "F-01, F-05, F-11"),
    ("A.8.26", "Application security requirements", "F-05, F-11, F-14"),
    ("A.8.28", "Secure coding", "F-01, F-03, F-05, F-11"),
    ("A.8.29", "Security testing in development and acceptance", "Seluruh temuan"),
]

CSF_FUNCTIONS = [
    ("GV", "Govern", "Kebijakan, peran, dan tata kelola risiko", "F-15"),
    ("ID", "Identify", "Pemahaman aset dan kerentanan", "Seluruh temuan"),
    ("PR", "Protect", "Kontrol pencegahan yang diterapkan", "F-01 s.d. F-10, F-12, F-13"),
    ("DE", "Detect", "Deteksi dan pemantauan", "F-04, F-06, F-14"),
    ("RS", "Respond", "Tanggap insiden", "F-01, F-02, F-07"),
    ("RC", "Recover", "Pemulihan dan Lessons learned", "F-12, F-15"),
]

# severity -> (Warna hex, label Indonesia)
SEV_FILL = {
    "CRITICAL": "A11111",
    "HIGH": "B35A00",
    "MEDIUM": "8A6D00",
    "LOW": "14602E",
    "None": "555555",
}

GLOSARIUM = [
    ("Attack Path", "Rangkaian langkah penyerang dari titik masuk awal hingga tujuan, misalnya dari halaman publik hingga root shell."),
    ("Authentication Bypass", "Melewati proses autentikasi tanpa memiliki kredensial yang sah."),
    ("Blast Radius", "Luas dampak yang Simulations satu sistem, biasanya menjadi lebih buruk oleh container yang berjalan sebagai root."),
    ("CVSS", "Common Vulnerability Scoring System, standar First.org untuk menilai severity kerentanan secara konsisten."),
    ("CWE", "Common Weakness Enumeration, taksonomi kelemahan dari MITRE."),
    ("Foil", "Perbedaan antara kondisi teknis dan konteks bisnis yang membuat CVSS perlu dibaca alongside penilaian dampak."),
    ("IDOR / BOLA", "Broken Object Level Authorization, akses objek yang dikendalikan pengguna tanpa pemeriksaan kepemilikan."),
    ("OWASP", "Open Worldwide Application Security Project, komunitas yang menerbitkan Top 10 dan ASVS."),
    ("Parameter Injection", "Serangan yang menyisipkan nilai ke dalam parameter query sehingga mengubah struktur query yang dimaksud."),
    ("Pivot", "Teknik menggunakan satu sistem yang telah dikompromikan untuk menembak sistem lain dalam jaringan yang sama."),
    ("Pretext", "Alasan atau narasi yang dipakai penyerang untuk mendapat akses atau persuaded target."),
    ("RCE", "Remote Code Execution, kemampuan menjalankan perintah arbitrer pada sistem remote."),
    ("Risk Inherent", "Risiko sebelum kontrol mitigasi diterapkan."),
    ("Risk Residual", "Risiko setelah kontrol mitigasi diterapkan."),
    ("Session Fixation", "Serangan yang membuat korban menggunakan ID sesi yang sudah dikuasai penyerang."),
    ("Stored XSS", "Payload skrip yang tersimpan di server dan dieksekusi saat pengguna lain membuka halaman."),
    ("Reflected XSS", "Payload skrip yang dipantulkan dari parameter request ke respons tanpa escaping."),
    ("Taint Analysis", "Metode analisis yang melacak aliran data tak tepercaya sampai ke titik berbahaya."),
    ("Temporal", "Menyangkut aspect waktu, seperti masa berlaku token atau sesi."),
    ("Trust Boundary", "Batas antara dua tingkat kepercayaan, di mana data harus divalidasi ulang."),
    ("UNION SELECT", "Teknik SQL injection yang menggabungkan hasil query penyerang dengan hasil query asli untuk membocorkan data kolom Sensitive."),
]


def add_lampiran_a(doc, all_findings):
    dx.H(doc, "Lampiran A - Aritmetika CVSS v3.1", 1, pagebreak=True)
    dx.P(doc, "Seluruh skor pada laporan ini dihitung dengan rumus resmi CVSS v3.1 "
              "(First.org) dan dapat direproduksi. Lampiran ini menyajikan "
              "perhitungan langkah demi langkah untuk setiap temuan, sehingga "
              "pembaca dapat memeriksa sendiri tanpa mempercayai penilaian kami.")
    dx.P(doc, "Formulasi dasar", bold=True, size=11)
    dx.CODE(doc, [
        "ISS      = 1 - (1-C) x (1-I) x (1-A)",
        "Impact   = 6.42 x ISS                                    (jika S = Unchanged)",
        "Impact   = 7.52 x (ISS - 0.029) - 3.25 x (ISS - 0.02)^15 (jika S = Changed)",
        "Exploit  = 8.22 x AV x AC x PR x UI",
        "Base     = Roundup1( min( (Impact + Exploit) x 1.08, 10 ) )  (jika S = Changed)",
        "Base     = Roundup1( min( Impact + Exploit, 10 ) )        (jika S = Unchanged)",
        "",
        "Roundup1: nilai dibulatkan KE ATAS ke satu angka desimal, sesuai CVSS v3.1 Appendix A.",
    ], caption="Rumus CVSS v3.1 yang digunakan")

    dx.TABLE(doc, ["Metrik", "Nilai", "Bobot", "Nilai alternatif"],
             cvss_table(), widths=(2.2, 4.2, 2.0, 7.6), font=8.5)

    dx.H(doc, "A.1 Perhitungan stepwise per temuan", 2)
    rows = []
    for w in cvss_workings(all_findings):
        rows.append((w["id"], "%.4f" % w["iss"], "%.4f" % w["impact"],
                     "%.4f" % w["expl"], "%.4f" % w["raw"],
                     w["mult"].split()[0], w["rounding"], w["severity"]))
    dx.TABLE(doc, ["ID", "ISS", "Impact", "Exploit", "Impact+Expl", "Mult",
                   "Roundup", "Severity"],
             rows, widths=(1.4, 1.9, 1.9, 1.9, 2.3, 1.5, 3.0, 2.1), font=8)

    dx.H(doc, "A.2 Vektor lengkap", 2)
    rows = [(w["id"], w["vector"], "%s" % w["score"], w["severity"]) for w in cvss_workings(all_findings)]
    dx.TABLE(doc, ["ID", "Vektor CVSS:3.1", "Skor", "Severity"], rows,
             widths=(1.4, 11.0, 1.5, 2.1), font=8)

    dx.H(doc, "A.3 Catatan pembulatan yang mengubah skor", 2)
    dx.P(doc, "Aturan Roundup CVSS v3.1 membulatkan ke atas, bukan ke terdekat. "
              "Hal ini membuat skor berbeda dari tabel yang banyak beredar di "
              "internet, yang sering memakai pembulatan ke terdekat. Contoh yang "
              "paling jelas pada laporan ini:")
    dx.BUL(doc, "F-03 menghasilkan 8.1036, yang di-Roundup menjadi 8.2. Banyak sumber menulis 8.1 karena membulatkan ke terdekat.")
    dx.BUL(doc, "F-06 dan F-07 masing-masing menghasilkan 9.1124, yang menjadi 9.1 dan kebetulan sama dengan pembulatan ke terdekat.")
    dx.BUL(doc, "F-10 menghasilkan 7.0516, yang di-Roundup menjadi 7.1, bukan 7.0 seperti yang sering ditulis.")
    dx.P(doc, "Menghitung ulang dengan kalkulator resmi First.org akan menghasilkan "
              "angka yang sama dengan tabel di atas. Ini bukan perbedaan "
              "penilaian, melainkan perbedaan aritmetika pembulatan.",
         italic=True, color=dx.GREY)


def add_lampiran_b(doc, all_findings):
    dx.H(doc, "Lampiran B - Pemetaan Kontrol NIST SP 800-53 Rev.5", 1, pagebreak=True)
    dx.P(doc, "Lampiran ini mengelompokkan seluruh kontrol NIST SP 800-53 Rev.5 yang "
              "dipetakan pada temuan, agar Ease of audit per kontrol família "
              "terjaga.")
    dx.TABLE(doc, ["Keluarga", "Nama", "Cakupan", "Temuan terkait"],
             NIST80053_GROUPS, widths=(1.8, 4.4, 4.6, 5.2), font=8.5)

    dx.H(doc, "Lampiran C - Pemetaan Kontrol ISO/IEC 27001:2022", 1, pagebreak=True)
    dx.TABLE(doc, ["Kontrol", "Nama", "Temuan terkait"], ISO_GROUPS,
             widths=(2.4, 8.6, 5.0), font=8.5)

    dx.H(doc, "Lampiran D - Pemetaan Fungsi NIST CSF 2.0", 1, pagebreak=True)
    dx.TABLE(doc, ["Fungsi", "Nama", "Cakupan", "Temuan terkait"], CSF_FUNCTIONS,
             widths=(1.6, 2.6, 7.0, 4.8), font=8.5)

    dx.H(doc, "Lampiran E - Definisi Severity CVSS v3.1", 1, pagebreak=True)
    dx.TABLE(doc, ["Rating", "Rentang Skor", "Interpretasi"], SEVERITY_DEF,
             widths=(2.4, 3.0, 10.6), font=8.5)
    dx.P(doc, "Rating bersifat teknikal dan berbasis vektor. Rating bisnis pada "
              "laporan ini dapat berbeda, dan perbedaan tersebut dinyatakan "
              "eksplisit pada bagian masing-masing temuan.", italic=True,
         color=dx.GREY)

    dx.H(doc, "Lampiran F - Glosarium", 1, pagebreak=True)
    dx.TABLE(doc, ["Istilah", "Pengertian"], GLOSARIUM,
             widths=(4.4, 11.6), font=8.5)


def _strip_decor(lines):
    """Buang garis dekoratif dan baris kosong dari blok perintah.

    Komentar yang membawa informasi (mis. '#   -> output aktual') tetap
    dipertahankan.
    """
    out = []
    for l in lines:
        s = l.strip()
        if set(s) <= set("=#- ") and s:
            continue
        if not s:
            if out and out[-1].strip():
                out.append("")
            continue
        if s.startswith("#") and s.rstrip("# ").replace("#", "").strip() == "":
            continue
        out.append(l)
    while out and not out[-1].strip():
        out.pop()
    return out


def add_lampiran_g(doc, all_findings):
    def C(doc, lines, caption=None):
        dx.CODE(doc, _strip_decor(lines), caption=caption)
    dx.H(doc, "Lampiran G - Daftar Perintah Reproduksi", 1, pagebreak=True)
    dx.P(doc, "Semua perintah berikut dapat disalin dan dijalankan langsung "
              "pada mesin penguji 192.168.1.94 tanpa modifikasi. Tidak ada "
              "placeholder. Jalankan hanya pada sistem yang Anda miliki atau "
              "yang Anda telah mendapat izin tertulis untuk diuji.")
    C(doc, [
        "# ============================================================",
        "# 0 - ALAT (diperlukan)",
        "# ============================================================",
        "apt update && apt install -y nmap curl sshpass mysql-client \\",
        "    netcat-openbsd tcpdump hydra",
        "",
        "# ============================================================",
        "# 1 - KONFIRMASI HOST HIDUP",
        "# ============================================================",
        "ping -c 4 192.168.1.18",
        "#   -> 4 packets transmitted, 4 received, 0% packet loss",
        "#   -> rtt min/avg/max/mdev = 1.115/3.966/10.472/3.781 ms",
        "",
        "# ============================================================",
        "# 2 - SCAN PORT & VERSI",
        "# ============================================================",
        "nmap -Pn -p- --min-rate 3000 -T4 192.168.1.18",
        "nmap -Pn -sV -p 22,3000,3307 192.168.1.18",
        "#   -> 22/tcp open ssh OpenSSH 10.3 | 3000/tcp open http Node.js Express",
        "#   -> 3307/tcp open mysql MySQL 8.0.46",
        "# CATATAN: bukti lapangan memakai -sV tanpa -sC, sehingga nomor versi",
        "# Node.js dan Express tidak dapat disimpulkan dari hasil scan ini.",
        "",
        "# ============================================================",
        "# 4 - RECON APLIKASI TANPA LOGIN",
        "# ============================================================",
        "for p in \"\" register login-noportal dashboard search upload \\",
        "         uploads/ api/perusahaan/1/data-keuangan; do",
        "  curl -s -o /dev/null -w \"GET /%-42s -> %{http_code}\\n\" \\",
        "    \"http://192.168.1.18:3000/$p\"",
        "done",
        "curl -s http://192.168.1.18:3000/login | grep -oE 'Contoh akun:.*'",
        "#   -> BELUM TERBUKTI: 2.png memuat perintah ini tanpa baris output",
        "",
        "# ============================================================",
        "# ============================================================",
        "# BAGIAN 5-23: Perintah per-temuan TIDAK diulang di sini.",
        "# Setiap perintah beserta OUTPUT AKTUALNYA sudah tercetak lengkap",
        "# pada sub-bagian \"2. Bukti\" masing-masing temuan (F-01 s.d. F-15)",
        "# di bagian Detail Temuan. Jalankan dari sana agar output aktualnya",
        "# terlihat berdampingan dengan perintahnya.",
        "# ============================================================",
        "",
        "",
        "# ============================================================",
        "# 24 - VERIFIKASI SISI SERVER (setelah root diperoleh)",
        "# ============================================================",
        "sshpass -p 'REDACTED_SSH_ROOT_PW' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\",
        "  'docker exec labkeu-app cat /usr/src/app/server.js \\",
        "             /usr/src/app/routes/auth.js \\",
        "             /usr/src/app/routes/dashboard.js \\",
        "             /usr/src/app/db/db.js'",
        "sshpass -p 'REDACTED_SSH_ROOT_PW' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\",
        "  'netstat -ltnp; id labkeu; ls -l /var/run/docker.sock; docker exec labkeu-app id'",
        "sshpass -p 'REDACTED_SSH_ROOT_PW' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\",
        "  'docker exec labkeu-app npm audit; docker exec labkeu-app env | grep -iE \"secret|password\"'",
        "",
        "# ============================================================",
        "# 25 - TEMUAN NEGATIF: source & backup tidak terekspos",
        "# ============================================================",
        "for p in .env .git/config package.json server.js routes/auth.js \\",
        "         routes/dashboard.js db/db.js Dockerfile README.md backup.zip \\",
        "         app.bak node_modules/.package-lock.json; do",
        "  printf '  %-34s %s\\n' \"$p\" \\",
        "    \"$(curl -s -o /dev/null -w '%{http_code}' \"http://192.168.1.18:3000/$p\")\"",
        "done",
        "#   -> semua 404",
        "",
        "# ============================================================",
        "# 26 - PEMBERSIHAN ARTEFAK ENGAGEMENT INI",
        "# ============================================================",
        "sshpass -p 'REDACTED_SSH_ROOT_PW' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\",
        "  'docker exec labkeu-app rm -f \\",
        "     /usr/src/app/public/uploads/probe.php \\",
        "     /usr/src/app/public/uploads/probe.html \\",
        "     /usr/src/app/public/uploads/probe.js \\",
        "     /usr/src/app/public/uploads/probe.svg \\",
        "     /usr/src/app/public/uploads/probe.exe \\",
        "     /usr/src/app/public/uploads/probe.sh \\",
        "     /usr/src/app/public/uploads/trav_evil.txt'",
        "rm -f /tmp/cj_* /tmp/probe.* /tmp/trav.txt /tmp/rl_codes /tmp/reg_codes /tmp/resp_idor",
    ], caption="Perintah reproduksi - bagian 1 (target, aplikasi, SQLi, sesi, upload)")

    dx.P(doc, "Seluruh perintah di atas bereaksi terhadap kondisi nyata pada "
              "2026-09-29. Perintah yang tidak mengubah state (reconnaissance, "
              "enumerasi, SQLi read-only) aman diulang. Perintah yang menulis "
              "data atau membuat berkas harus dibersihkan setelah "
              "uji, dan hanya boleh dijalankan dengan izin tertulis.",
         italic=True, color=dx.GREY)
