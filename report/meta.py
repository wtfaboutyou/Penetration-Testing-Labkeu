# -*- coding: utf-8 -*-
"""Data naratif dokumen: identitas, scope, metodologi, matriks risiko, negatives."""

JUDUL = "Laporan Vulnerability Assessment"
SUBJUDUL = "Aplikasi LabKeu - Replika Sistem Manajemen Anggaran"
TARGET_IP = "192.168.1.18"
TANGGAL = "29 September 2026"
WAKTU_UJI = "00:08 - 00:47 WIB"
PENUGAS = "Tim Pentest Internal"
VERSI = "1.1"
KLASIFIKASI = "RAHASIA - KHUSUS PENGGUNA"

TARGET_FAKTA = [
    ("MAC Address", "08:00:27:81:9D:8D (PCS Systemtechnik / Oracle VirtualBox virtual NIC)"),
    ("Status host", "Hidup dan dapat dijangkau - ping 4/4 paket diterima, 0% packet loss, rata-rata 3,97 ms"),
    ("Catatan konsistensi alamat", "Seluruh bukti pada laporan ini diambil di 192.168.1.18. Draf sebelumnya mengalamatkan target sebagai 192.168.1.18; klaim tersebut tidak didukung bukti mana pun dan telah dihapus."),
    ("Sistem Operasi host", "Alpine Linux 3.24.2, kernel 6.18.52-0-lts x86_64"),
    ("Stack aplikasi", "Node.js Express framework, MySQL 8.0.46. Nomor versi Node.js dan Express (v20.20.2 / ^4.19.2) berasal dari pembacaan source dan package.json setelah akses root diperoleh, bukan dari hasil nmap."),
    ("Library kunci", "express-session ^1.18.0, mysql2 ^3.10.0, multer ^2.0.0, ejs ^3.1.10"),
    ("Port terbuka", "22/tcp OpenSSH 10.3, 3000/tcp HTTP Express, 3307/tcp MySQL 8.0.46"),
    ("Port tertutup", "65.532 port tertutup. Tidak ada 443 maupun 8443 - tidak ada TLS sama sekali"),
    ("Basis data", "MySQL 8.0.46, skema labkeu, 4 tabel: data_keuangan, dokumen, perusahaan, users"),
    ("Mesin penguji", "192.168.1.94"),
    ("Waktu pengujian", "29 September 2026, pukul 00:08 - 00:47 WIB (sesuai stempel waktu pada bukti)"),
    ("Jumlah temuan", "15 temuan: 5 Critical, 6 High, 4 Medium, 0 Low"),
    ("Rating risiko keseluruhan", "KRITIS"),
]

SCOPE = [
    ("IN SCOPE", [
        "Host 192.168.1.18 beserta seluruh port yang terbuka (22, 3000, 3307).",
        "Aplikasi web LabKeu pada http://192.168.1.18:3000 - seluruh endpoint yang dapat diakses.",
        "Kontainer Docker labkeu-app, labkeu-db, dan konfigurasi docker-compose pada host.",
        "Basis data MySQL skema labkeu pada port 3307.",
        "Konfigurasi SSH daemon (/etc/ssh/sshd_config) dan akun sistem pada host.",
    ]),
    ("OUT OF SCOPE", [
        "Koneksi ke internet keluar dari target - tidak diuji, tidak relevan pada lab terisolasi.",
        "Pengujian pada host lain di segmen 192.168.1.0/24 - hanya ping dan pemindaian ARP untuk penemuan target.",
        "Serangan yang merusak: tidak ada denial-of-service disengaja, tidak ada payload merusak, tidak ada data produksi tersentuh.",
        "Aplikasi selain LabKeu pada host yang sama - tidak ditemukan.",
    ]),
    ("BATASAN DAN KETERBATASAN", [
        "Penilaian conducted dari sudut pandang penetration testing black-box, bukan audit kode sumber lengkap. Audit source dilakukan sebagai tahap verifikasi setelah akses root diperoleh, bukan sebagai metode awal.",
        "Hanya 3 port yang dipindai dan seluruhnya terbuka; tidak ada port yang terfilter yang perlu dinilai.",
        "Waktu pengujian total sekitar 10 menit, sehingga kedalaman pengujian tidak setara dengan assessment penuh 5-10 hari kerja.",
        "Skor CVSS dihitung dengan rumus CVSS v3.1 (First.org). Untuk temuan dengan dampak bisnis yang tidak sebanding dengan skor teknis, perbedaan rating dinyatakan secara eksplisit (lihat F-04).",
        "Tidak dilakukan pengujian aplikasi mobile, tidak ada aplikasi mobile pada target.",
    ]),
]

METODE = [
    ("Fase 0 - Persiapan", [
        "Instalasi alat: nmap, curl, sshpass, mysql-client, netcat-openbsd, tcpdump, hydra.",
        "Tidak ada kredensial awal yang diberikan. Seluruh akses diperoleh dari port terbuka.",
    ]),
    ("Fase 1 - Penemuan dan Identifikasi Target", [
        "Konfirmasi host hidup dengan ping ke 192.168.1.18 (4/4 paket diterima).",
        "Pemindaian ARP untuk mencari host lain di segmen yang sama.",
        "Pemindaian service dan versi pada tiga port terbuka (22, 3000, 3307).",
    ]),
    ("Fase 2 - Rekognisi Aplikasi Tanpa Login", [
        "Pemetaan seluruh endpoint publik dengan enumerasi kode status HTTP.",
        "Penemuan kredensial demo tercetak pada HTML halaman login publik.",
    ]),
    ("Fase 3 - Footprint Anonim", [
        "Login dengan kredensial dari halaman publik, tanpa perlu menebak.",
        "Peta endpoint setelah memiliki sesi valid.",
    ]),
    ("Fase 4 - Uji Otorisasi dan Injeksi", [
        "Pengujian IDOR dengan iterasi parameter objek pada endpoint API.",
        "Pengujian SQL injection pada kedua endpoint login: jumlah kolom, auth bypass, UNION dump, dump skema.",
        "Pengujian self-registration untuk role escalation.",
        "Pengujian CSRF dari origin eksternal.",
    ]),
    ("Fase 5 - Uji K ketahanan dan Sesi", [
        "Pengukuran rate limit secara kuantitatif pada 100 dan 1.000 permintaan.",
        "Pengujian management sesi: ID sesi, cookie flag, logout, dan pemecahan secret secara black-box.",
    ]),
    ("Fase 6 - Uji Unggahan dan XSS", [
        "Enam ekstensi berbeda diuji pada endpoint upload.",
        "Uji stored XSS pada origin sendiri.",
        "Uji path traversal, diverifikasi langsung di filesystem dalam container.",
    ]),
    ("Fase 7 - Brute Force dan Akses Root", [
        "Brute force MySQL pada port 3307: 40 kombinasi.",
        "Pemecahan secret sesi secara black-box dari daftar kandidat.",
        "Brute force SSH: 24 kandidat, 1 password ditemukan dalam 2 detik.",
    ]),
    ("Fase 8 - Verifikasi Sisi Server", [
        "Setelah memperoleh root, seluruh temuan diverifikasi ulang terhadap source code dan konfigurasi.",
        "Audit dependensi (npm audit), pemeriksaan environment variable, dan permission container.",
    ]),
    ("Fase 9 - Pembersihan", [
        "Seluruh artefak yang dibuat pada engagement ini dihapus.",
        "Artefak engagement sebelumnya sengaja dibiarkan agar dapat observasi dan dilaporkan sebagai temuan F-12.",
    ]),
]

ALAT = [
    ("nmap", "Pemindaian port, deteksi versi, penemuan host via ARP"),
    ("curl", "Semua pengujian HTTP, inklusi payload SQLi dan XSS"),
    ("sshpass", "Akses SSH non-interaktif untuk verifikasi sisi server"),
    ("mysql-client", "Akses basis data langsung pada port 3307"),
    ("hydra", "Brute force SSH dan MySQL"),
    ("netcat-openbsd", "Server pencuri cookie untuk membuktikan XSS"),
    ("tcpdump", "Pembuktian transmisi cleartext (F-09)"),
    ("python3", "Pemecahan HMAC untuk uji forge cookie sesi"),
    ("python-docx", "Pembuatan dokumen laporan ini"),
]

KILL_CHAIN = [
    ("1", "Recon IP (MAC)", "nmap -sn menemukan 192.168.1.18 tanpa diberi IP"),
    ("2", "Port scan", "22, 3000, 3307 terbuka"),
    ("3", "Halaman login bocor", "kredensial demo tercetak di HTML publik"),
    ("4", "Footprint anonim", "individu1 / REDACTED_STORED_PASSWORD, tanpa tebakan"),
    ("5", "IDOR", "baca data keuangan perusahaan lain tanpa cek kepemilikan"),
    ("6", "SQL injection", "auth bypass + UNION dump 100% kredensial"),
    ("7", "Brute force MySQL", "3307: labkeu_user / REDACTED_DB_PASSWORD, dump DB penuh"),
    ("8", "Brute force SSH", "24 percobaan, 2 detik: root / REDACTED_SSH_ROOT_PW"),
    ("9", "ROOT", "kendali penuh atas host dan basis data"),
]

SKOR_TERPERCAYA = [
    ("1", "F-01", "SQL Injection - auth bypass + database takeover", "9.8", "CRITICAL", "Sangat Tinggi", "Tidak ada"),
    ("2", "F-15", "Infrastruktur: DB ter-expos, grup docker, SSH root lemah", "9.8", "CRITICAL", "Sangat Tinggi", "Tidak ada"),
    ("3", "F-02", "Kredensial default tercetak di halaman publik", "9.1", "CRITICAL", "Sangat Tinggi", "Tidak ada"),
    ("4", "F-06", "Tidak ada rate limiting / account lockout", "9.1", "CRITICAL", "Sangat Tinggi", "Tidak ada"),
    ("5", "F-07", "Session management lemah (empat cacat)", "9.1", "CRITICAL", "Sangat Tinggi", "Tidak ada"),
    ("6", "F-03", "Self-registration peran perusahaan tanpa otorisasi", "8.2", "HIGH", "Sangat Tinggi", "Tidak ada"),
    ("7", "F-05", "Unrestricted file upload + stored XSS", "8.1", "HIGH", "Tinggi", "Tidak ada"),
    ("8", "F-08", "Password disimpan plaintext", "8.1", "HIGH", "Tinggi", "Tidak ada"),
    ("9", "F-09", "Transmisi kredensial via HTTP cleartext", "8.1", "HIGH", "Sedang", "Tidak ada"),
    ("10", "F-12", "/etc/passwd tersaji publik di /uploads/", "7.5", "HIGH", "Tinggi", "Tidak ada"),
    ("11", "F-10", "Tidak ada proteksi CSRF (bersyarat SameSite)", "7.1", "HIGH", "Sedang", "Tidak ada"),
    ("12", "F-04", "IDOR data keuangan lintas perusahaan", "6.5", "MEDIUM", "Tinggi", "Tidak ada"),
    ("13", "F-11", "Reflected XSS di /search", "6.1", "MEDIUM", "Tinggi", "Tidak ada"),
    ("14", "F-13", "Tidak ada security headers", "5.4", "MEDIUM", "Tinggi", "Tidak ada"),
    ("15", "F-14", "Username enumeration di /register", "5.3", "MEDIUM", "Sangat Tinggi", "Tidak ada"),
]

SKOR_NOTE = (
    "Skor dihitung dengan rumus resmi CVSS v3.1 (First.org) melalui kalkulator "
    "yang dapat direproduksi, bukan estimasi manual. Hal ini penting: "
    "beberapa tabel publik menampilkan skor yang berbeda untuk vektor yang sama "
    "karena kesalahan pembulatan. Contoh yang relevan pada laporan ini: "
    "vektor F-03 menghasilkan 8.2 (bukan 8.1) karena aturan Roundup CVSS v3.1 "
    "membulatkan 8.1036 ke atas menjadi 8.2. Aritmetika lengkap setiap vektor "
    "disajikan pada tabel ringkasan di bagian awal."
)

NEGATIF = [
    ("Source code dan berkas sensitif tidak terekspos lewat web",
     "Enumerasi 12 path sensitif (.env, .git/config, package.json, server.js, routes/auth.js, routes/dashboard.js, db/db.js, Dockerfile, README.md, backup.zip, app.bak, node_modules/.package-lock.json) - seluruhnya HTTP 404.",
     "Tidak ada bajaan backup atau source yang dapat diunduh secara anonim."),
    ("Directory listing dinonaktifkan",
     "GET /uploads/ mengembalikan HTTP 404, tidak ada daftar isi direktori.",
     "Namun isi tetap dapat diambil bila nama berkas ditebak - terbukti pada F-12."),
    ("npm audit bersih - tidak ada CVE library",
     "docker exec labkeu-app npm audit melaporkan 0 vulnerabilities (tidak ada dependensi rentan).",
     "Seluruh temuan berasal dari kode dan konfigurasi yang ditulis sendiri, bukan dari library rentan."),
    ("Path traversal pada filename upload GAGAL",
     "Payload filename=../../../../tmp/trav_evil.txt diuji dan diverifikasi langsung di dalam container: berkas hanya muncul di folder upload, tidak di /tmp.",
     "Multer menyaring segmen '../'. TEMUAN INI TIDAK DIBUAT sebagai temuan karena tidak terbukti."),
    ("Endpoint /login portal aman dari SQL injection",
     "Payload user_a'-- - pada /login menghasilkan pesan Username atau password salah, tanpa bypass.",
     "Endpoint ini memakai parameterized query. Hanya /login-noportal yang rentan (F-01)."),
    ("Pesan error ter-escape dengan benar pada seluruh view",
     "Kutip tunggal pada pesan error register ter-render menjadi &#39;, bukan tanda kutip mentah.",
     "Hanya search.ejs yang memakai output tanpa escaping, sehingga hanya /search yang XSS (F-11)."),
    ("Tidak ada SSRF dan tidak ada command injection",
     "Tidak ada endpoint yang mengambil URL dari input pengguna, tidak ada pemanggilan child_process atau exec dengan input pengguna.",
     "Kedua kelas kerentanan ini diuji dan tidak ditemukan."),
    ("Akun root MySQL tidak dapat diakses dari jaringan",
     "mysql -h 192.168.1.18 -P 3307 -u root -pREDACTED_WEAK_PASSWORD menghasilkan ERROR 1045 (28000): Access denied.",
     "MYSQL_ROOT_PASSWORD yang bocor di docker-compose tidak berakhir pada akses root database. Yang berdampak adalah labkeu_user dengan ALL PRIVILEGES pada skema labkeu."),
    ("Forgot password tidak membocorkan keberadaan akun",
     "Endpoint /forgot-password mengembalikan HTTP 200 dengan pesan identik apa pun status akun.",
     "Berbeda dengan /register yang membocorkan (F-14)."),
    ("Uji IDOR pada endpoint lain tidak menemukan kebocoran tambahan",
     "Endpoint /api/dashboard dan endpoint POST data lain menolak dengan 401 atau 403 bagi sesi tanpa hak.",
     "Konsentrasi risiko pada /api/perusahaan/:id/data-keuangan yang tidak memeriksa kepemilikan."),
]

KOREKSI = [
    ("1", "Target 192.168.1.93 dengan alasan 192.168.1.18 sudah mati",
     "Tidak didukung bukti mana pun. Bukti ping pada 192.168.1.18 justru menunjukkan 0% packet loss, dan seluruh 12 bukti pada engagement ini diambil di 192.168.1.18.",
     "Target dikoreksi menjadi 192.168.1.18 dan seluruh bukti deanotasi ke file-nya masing-masing."),
    ("2", "Bukti listener menggunakan ss -ltn", "Perintah ss tidak tersedia pada host Alpine ini (sh: ss: not found), sehingga evidence tidak dapat direproduksi.",
     "Diganti netstat -ltnp."),
    ("3", "Respons IDOR kosong berukuran 22 byte, heuristik if size > 22", "Respons kosong yang sebenarnya adalah [] berukuran 2 byte, bukan 22 byte. Heuristik tersebut salah.",
     "Diganti hitungan kemunculan field perusahaan_id pada respons."),
    ("4", "Pembersihan jejak pada laporan sebelumnya dinyatakan selesai", "Pernyataan tersebut tidak benar. Empat akun uji dan 22 baris dokumen masih ada, termasuk /uploads/passwd yang live dan publik.",
     "Diberi tahu sebagai temuan F-12. Artefak yang dibuat engagement ini sudah dihapus."),
    ("5", "Akun hasil self-register peran perusahaan langsung dapat akses data keuangan",
     "Akun tersebut memiliki perusahaan_id = NULL sehingga dashboard kosong. Akses data keuangan baru terjadi melalui IDOR (F-04), bukan langsung.",
     "Nuansa ditulis eksplisit pada F-03."),
    ("6", "Dump kredensial dilakukan dengan mengandalkan kolom password", "Teknik lama rapuh karena batas panjang GROUP_CONCAT dan masalah escaping.",
     "Diganti subquery ke kolom nama_lengkap yang jauh lebih andal."),
]

DASAR_STANDAR = [
    ("CVSS v3.1", "First.org - Common Vulnerability Scoring System Version 3.1",
     "Skor dan vektor setiap temuan, denganSeverity Qualitative Rating."),
    ("CWE", "MITRE - Common Weakness Enumeration",
     "Klasifikasi kelemahan pada setiap temuan."),
    ("OWASP Top 10 (2021)", "OWASP Foundation",
     "Kategori kerentanan aplikasi web yang paling banyak dipakai industri."),
    ("OWASP API Security Top 10 (2023)", "OWASP Foundation",
     "Kategori kerentanan khusus API, dipakai pada F-04, F-05, dan F-06."),
    ("NIST SP 800-30 Rev.1", "Guide for Conducting Risk Assessments",
     "Kerangka penilaian risiko:-likelihood, impact, risk inherent, dan risk residual."),
    ("NIST SP 800-53 Rev.5", "Security and Privacy Controls for Information Systems and Organizations",
     "Kontrol keamanan yang dipetakan pada setiap rekomendasi perbaikan."),
    ("NIST SP 800-40 Rev.4", "Enterprise Patch Management Planning",
     "Konteks pengelolaan patch dan konfigurasi."),
    ("NIST SP 800-52 Rev.2", "Guidelines for the Selection, Configuration, and Use of TLS",
     "Persyaratan TLS pada transmisi kredensial (F-09)."),
    ("NIST SP 800-63B", "Digital Identity Guidelines: Authentication and Lifecycle Management",
     "Standar NIST yang secara spesifik mengatur penyimpanan password dan penanganan sesi."),
    ("NIST SP 800-207", "Zero Trust Architecture",
     "Model otorisasi per sumber daya yang menjadi dasar perbaikan IDOR."),
    ("NIST CSF 2.0", "Cybersecurity Framework 2.0",
     "Kerangka hasil dan kategori: Govern, Identify, Protect, Detect, Respond, Recover."),
    ("ISO/IEC 27001:2022", "Information Security Management Systems - Requirements",
     "Kontrol A.5 dan A.8 yang dipetakan pada setiap rekomendasi."),
]

KESIMPULAN = (
    "Aplikasi LabKeu pada 192.168.1.18 memiliki risiko keseluruhan KRITIS. "
    "Dalam waktu sekitar 4 menit dan tanpa satu pun kredensial awal, penyerang "
    "mencapai root penuh pada mesin virtual dan akses ALL PRIVILEGES pada basis "
    "data. Jalur terpendek tidak memerlukan brute force sama sekali: satu "
    "permintaan HTTP ke endpoint /login-noportal sudah cukup untuk melewati "
    "autentikasi dan mengekstrak seluruh kredensial dalam respons yang sama.\n\n"
    "Tiga temuan Critical pertama saling menguatkan dan membentuk Attack Path "
    "yang lengkap. Kredensial default yang tercetak di halaman publik (F-02) "
    "memberikan foothold anonim tanpa tebakan. SQL injection pada endpoint "
    "login (F-01) menghapus kebutuhan akan kredensial itu sama sekali dan "
    "memberikan dump penuh. Ketiadaan rate limiting (F-06) memastikan "
     "brute force tetap berjalan pada kecepatan penuh, yang menghasilkan root "
    "shell melalui SSH dalam 2 detik. Satu perbaikan pada F-01 saja akan "
    "memutus rantai terpendek, tetapi tidak akan menutup jalur alternatif "
    "melalui F-02 dan F-06.\n\n"
    "Tiga kelemahan struktural menjadi penyebab mendasar dan perlu ditangani "
    "secara menyeluruh, bukan secara terpisah. Pertama, tidak ada pemisahan "
    "batas kepercayaan antara input pengguna dan query database (F-01). "
    "Kedua, tidak ada pemeriksaan kepemilikan objek pada API (F-04) sehingga "
    "isolasi antar tenant tidak berjalan. Ketiga, secret dikelola sebagai "
    "string hard-coded di dalam kode dan artefak deployment (F-02, F-07, "
    "F-15) sehingga kredensial dapat dibaca oleh siapa pun dan berubah dari "
    "rahasia menjadi informasi publik.\n\n"
    "Prioritas perbaikan yang direkomendasikan: perbaiki F-01 terlebih dahulu "
    "karena dampaknya paling besar dan paling cepat dihentikan, kemudian F-02 "
    "karena penutupannya hanya memerlukan penghapusan teks dari template, "
    "kemudian F-06 dan F-15 yang menutup jalur akses root, lalu F-04 untuk "
    "memulihkan isolasi data antar organisasi. F-08 dan F-09 memerlukan "
    "perubahan yang lebih besar (hash password dan penerapan TLS) dan dapat "
    "dijadwalkan pada fase berikutnya, namun keduanya adalah prasyarat agar "
    "kerentanan lain tidak dapat dieksploitasi berulang kali."
)

REKOMENDASI_STRATEGIS = [
    ("Segera - 7 hari", [
        "Perbaiki F-01: parameterisasi query pada kedua endpoint login. Satu perubahan, memutus jalur terpendek.",
        "Perbaiki F-02: hapus kredensial demo dari template dan rotasi seluruh password yang terekspos.",
        "Perbaiki F-15.3 dan F-15.5: matikan PermitRootLogin yes, wajibkan kunci SSH, pindahkan seluruh secret ke environment variable atau secret manager, dan rotasi nilai yang sudah bocor.",
        "Hapus artefak F-12: bersihkan direktori upload dan tabel dokumen beserta akun uji tersisa.",
    ]),
    ("Jangka Pendek - 30 hari", [
        "Perbaiki F-04: bandingkan perusahaan_id dari session dengan nilai dari URL pada setiap endpoint yang mengakses data tenant.",
        "Perbaiki F-03: hapus account_type dari body request dan tetapkan peran di sisi server.",
        "Perbaiki F-06: pasang rate limiting berlapis dan account lockout dengan jendela yang meningkat.",
        "Perbaiki F-05: whitelist ekstensi, validasi magic bytes, simpan di luar webroot, dan sajikan sebagai attachment.",
        "Perbaiki F-07: pindahkan secret sesi ke environment variable minimal 32 byte, pasang flag HttpOnly dan Secure, dan perbaiki logout agar benar-benar membatalkan sesi.",
    ]),
    ("Jangka Menengah - 90 hari", [
        "Perbaiki F-08: migrasikan seluruh password ke bcrypt work factor 12 atau argon2id, lalu rotasi satu kali setelah migrasi.",
        "Perbaiki F-09: terapkan TLS di reverse proxy dengan HSTS, dan hentikan akses HTTP langsung.",
        "Perbaiki F-13: pasang helmet dengan CSP ketat, frame-ancestors none, nosniff, dan Referrer-Policy.",
        "Perbaiki F-10 dan F-11: terapkan token CSRF sinkron dan ganti seluruh pemakaian <%- %> pada data pengguna.",
        "Perbaiki F-14: gunakan pesan galat generik pada endpoint registrasi.",
        "Perbaiki F-15.1, 15.2, dan 15.4: bind database ke loopback, hapus keanggotaan grup docker dari akun non-root, dan jalankan container sebagai pengguna non-root.",
    ]),
    ("Proses Berkelanjutan", [
        "Tambahkan pengujian regresi keamanan (SAST dan DAST) sebagai gerbang build. SAST wajib memblokir build bila terdeteksi penggabungan string di klausa SQL atau pemakaian output template tanpa escaping.",
        "Tambahkan gate pemindaian secret pada repositori, sehingga kredensial yang Lavender ke dalam kode tertangkap sebelum commit.",
        "Tetapkan prosedur cleanup wajib pada akhir setiap engagement yang terotomatisasi, dan hentikan artefak pengujian yang tidak sengaja dibiarkan seperti pada F-12.",
        "Lakukan penilaian ulang setelah setiap fase perbaikan untuk memastikan tidak ada regresi dan tidak ada jalur serangan alternatif yang terbuka kembali.",
    ]),
]

KONTROL_DOKUMEN = [
    ("Judul dokumen", JUDUL + " - " + SUBJUDUL),
    ("Nomor dokumen", "LVA-LBK-2026-0928-01"),
    ("Versi", VERSI),
    ("Tanggal Terbit", TANGGAL),
    ("Klasifikasi", KLASIFIKASI),
    ("Penyusun", "Penetikus keamanan aplikasi, black-box assessment"),
    ("Pemeriksa", "Kepala Tim Keamanan Informasi"),
    ("Pemberi persetujuan", "Kepala Divisi Teknologi Informasi"),
    ("Lingkup", "Host 192.168.1.18 dan aplikasi LabKeu pada port 3000"),
    ("Distribusi", "Kepala Divisi TI, CTO, Arsip dokumentasi keamanan"),
    ("Periode retensi", "24 bulan sejak tanggalissued laporan"),
]

REVISI = [
    ("0.9", "27 September 2026", "Laporan awal, target 192.168.1.18, akses awal dengan kredensial SSH yang diberikan.", "Tim Pentest"),
    ("1.0", "28 September 2026", "Penulisan ulang lengkap dari sudut pandang black-box, 15 temuan, 6 koreksi faktual, 10 temuan negatif.", "Tim Pentest"),
    ("1.1", "29 September 2026", "Adaptasi terhadap bukti lapangan: target dikoreksi ke 192.168.1.18, 12 screenshot dianotasi dan ditanam ke dokumen, angka koreksi sesuai output sebenarnya, temuan tanpa bukti ditandai belum diverifikasi.", "Tim Pentest"),
]
