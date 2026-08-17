## 📌 Daftar Isi — Bab 11

- [Bab 11 — Network Service & Enterprise Linux](#bab-11--network-service--enterprise-linux)
  - [11.1 Overview & Posisi Bab 11](#111-overview--posisi-bab-11)
  - [11.2 SSH Protocol-Level Forensics (Fondasi)](#112-ssh-protocol-level-forensics-fondasi)
    - [11.2.1 Auth Method — Publickey vs Password vs Keyboard-Interactive](#1121-auth-method--publickey-vs-password-vs-keyboard-interactive)
    - [11.2.2 SSH ControlMaster/Connection Multiplexing](#1122-ssh-controlmasterconnection-multiplexing)
    - [11.2.3 Protocol Version & Cipher Negotiation sebagai Fingerprint 🔴](#1123-protocol-version--cipher-negotiation-sebagai-fingerprint-)
  - [11.3 SSH Lateral Movement — Rekonstruksi Rantai Pivot 🔴](#113-ssh-lateral-movement--rekonstruksi-rantai-pivot-)
    - [11.3.1 Model Dasar Rantai Pivot](#1131-model-dasar-rantai-pivot)
    - [11.3.2 Koreksi: known_hosts Cuma Bukti "Pernah Coba"](#1132-koreksi-known_hosts-cuma-bukti-pernah-coba)
    - [11.3.3 Fingerprint Key sebagai Thread Lintas-Host](#1133-fingerprint-key-sebagai-thread-lintas-host)
    - [11.3.4 Timing Correlation — Pivot Manual vs Otomatis 🔴](#1134-timing-correlation--pivot-manual-vs-otomatis-)
    - [11.3.5 Membangun Tabel/Diagram Rantai Pivot](#1135-membangun-tabeldiagram-rantai-pivot)
  - [11.4 SSH Trust & Bastion/Jump Host](#114-ssh-trust--bastionjump-host)
    - [11.4.1 ProxyJump & ProxyCommand](#1141-proxyjump--proxycommand)
    - [11.4.2 Bastion sebagai Single Point of Pivot](#1142-bastion-sebagai-single-point-of-pivot)
    - [11.4.3 SSH CA & Host Certificates](#1143-ssh-ca--host-certificates)
    - [11.4.4 Rekonstruksi Host A → Bastion → Host B](#1144-rekonstruksi-host-a--bastion--host-b)
  - [11.5 SSH sebagai C2/Tunneling Channel](#115-ssh-sebagai-c2tunneling-channel)
    - [11.5.1 Local/Remote/Dynamic Port Forwarding](#1151-localremotedynamic-port-forwarding)
    - [11.5.2 Deteksi Tunnel Aktif dari Sisi Host 🔴](#1152-deteksi-tunnel-aktif-dari-sisi-host-)
    - [11.5.3 SOCKS Proxy via -D sebagai Jalur Tersembunyi](#1153-socks-proxy-via--d-sebagai-jalur-tersembunyi)
    - [11.5.4 Beda dengan Agent Forwarding](#1154-beda-dengan-agent-forwarding)
  - [11.6 Privilege Escalation After Lateral Movement](#116-privilege-escalation-after-lateral-movement)
    - [11.6.1 sudo Setelah SSH Login — Pola Umum](#1161-sudo-setelah-ssh-login--pola-umum)
    - [11.6.2 Root Transition & Session Boundary](#1162-root-transition--session-boundary)
    - [11.6.3 Korelasi sudo → Command → Persistence](#1163-korelasi-sudo--command--persistence)
  - [11.7 Korelasi Client vs Server Artifact Lintas Host](#117-korelasi-client-vs-server-artifact-lintas-host)
  - [11.8 Enterprise Identity Resolution](#118-enterprise-identity-resolution)
    - [11.8.1 Local User vs LDAP User vs Kerberos Principal](#1181-local-user-vs-ldap-user-vs-kerberos-principal)
    - [11.8.2 getent, id & Resolusi Identitas](#1182-getent-id--resolusi-identitas)
    - [11.8.3 UID/GID → Identity Domain](#1183-uidgid--identity-domain)
    - [11.8.4 Offline Identity/Cache](#1184-offline-identitycache)
  - [11.9 LDAP di Linux — Overview & Arsitektur](#119-ldap-di-linux--overview--arsitektur)
    - [11.9.1 Konsep Dasar — DN, Tree, objectClass](#1191-konsep-dasar--dn-tree-objectclass)
    - [11.9.2 OpenLDAP Server vs Linux sebagai Klien](#1192-openldap-server-vs-linux-sebagai-klien)
    - [11.9.3 Fokus Bab Ini — Sisi Klien 🔴](#1193-fokus-bab-ini--sisi-klien-)
  - [11.10 Linux sebagai Klien LDAP — Konfigurasi & Artefak 🔴](#1110-linux-sebagai-klien-ldap--konfigurasi--artefak-)
    - [11.10.1 /etc/nsswitch.conf Revisited](#11101-etcnsswitchconf-revisited)
    - [11.10.2 Konfigurasi Legacy — ldap.conf, pam_ldap.conf](#11102-konfigurasi-legacy--ldapconf-pam_ldapconf)
    - [11.10.3 Implikasi Forensik — Enumerasi Akun Tidak Lengkap](#11103-implikasi-forensik--enumerasi-akun-tidak-lengkap)
  - [11.11 SSSD — Hub Modern Identitas Enterprise 🔴](#1111-sssd--hub-modern-identitas-enterprise-)
    - [11.11.1 Kenapa SSSD Jadi Standar](#11111-kenapa-sssd-jadi-standar)
    - [11.11.2 /etc/sssd/sssd.conf](#11112-etcsssdsssdconf)
    - [11.11.3 SSSD Cache — Nilai Forensik Tinggi 🔴](#11113-sssd-cache--nilai-forensik-tinggi-)
    - [11.11.4 SSSD Logs](#11114-sssd-logs)
  - [11.12 Kerberos — Konsep Dasar untuk Forensik 🔴](#1112-kerberos--konsep-dasar-untuk-forensik-)
    - [11.12.1 Alur Inti — KDC, TGT, TGS](#11121-alur-inti--kdc-tgt-tgs)
    - [11.12.2 /etc/krb5.conf](#11122-etckrb5conf)
    - [11.12.3 Koreksi — Ticket Bukan Password ⚠️](#11123-koreksi--ticket-bukan-password-)
  - [11.13 Kerberos Authentication Artifacts & Logs](#1113-kerberos-authentication-artifacts--logs)
    - [11.13.1 TGT/TGS Acquisition sebagai Event](#11131-tgttgs-acquisition-sebagai-event)
    - [11.13.2 Log Sukses vs Gagal](#11132-log-sukses-vs-gagal)
    - [11.13.3 Identifikasi KDC/Realm dari Artefak Host](#11133-identifikasi-kdcrealm-dari-artefak-host)
    - [11.13.4 Korelasi Timestamp Ticket dengan SSH/Login](#11134-korelasi-timestamp-ticket-dengan-sshlogin)
  - [11.14 Kerberos Ticket Cache & Keytab Forensics 🔴](#1114-kerberos-ticket-cache--keytab-forensics-)
    - [11.14.1 Ticket Cache — /tmp/krb5cc_uid](#11141-ticket-cache--tmpkrb5cc_uid)
    - [11.14.2 Keytab File](#11142-keytab-file)
    - [11.14.3 Pass-the-Ticket dari Sisi Linux 🔴](#11143-pass-the-ticket-dari-sisi-linux-)
    - [11.14.4 Kerberoasting — Sekilas](#11144-kerberoasting--sekilas)
  - [11.15 Service Account Forensics](#1115-service-account-forensics)
    - [11.15.1 Service Account vs Human Account](#11151-service-account-vs-human-account)
    - [11.15.2 Indikator Identifikasi](#11152-indikator-identifikasi)
    - [11.15.3 Menghindari Salah Atribusi](#11153-menghindari-salah-atribusi)
  - [11.16 Korelasi LDAP/Kerberos dengan Artefak Bab 4](#1116-korelasi-ldapkerberos-dengan-artefak-bab-4)
  - [11.17 Enterprise DNS & Host Identity](#1117-enterprise-dns--host-identity)
    - [11.17.1 Hostname, FQDN & /etc/hosts](#11171-hostname-fqdn--etchosts)
    - [11.17.2 /etc/resolv.conf & DNS Resolution](#11172-etcresolvconf--dns-resolution)
    - [11.17.3 Korelasi IP ↔ Hostname ↔ Host Enterprise](#11173-korelasi-ip--hostname--host-enterprise)
  - [11.18 Network Filesystem Forensics — NFS/SMB](#1118-network-filesystem-forensics--nfssmb)
    - [11.18.1 NFS — Konsep & Artefak](#11181-nfs--konsep--artefak)
    - [11.18.2 SMB/CIFS — Konsep & Artefak](#11182-smbcifs--konsep--artefak)
    - [11.18.3 /etc/fstab, /etc/exports & /proc/mounts](#11183-etcfstab-etcexports--procmounts)
    - [11.18.4 Remote Filesystem sebagai Jalur Akses/Data](#11184-remote-filesystem-sebagai-jalur-aksesdata)
  - [11.19 Enumerasi Network Service Aktif](#1119-enumerasi-network-service-aktif)
  - [11.20 Centralized Logging & Log Forwarding Enterprise 🟡](#1120-centralized-logging--log-forwarding-enterprise-)
  - [11.21 Membangun Timeline Lintas-Host untuk Lateral Movement 🔴](#1121-membangun-timeline-lintas-host-untuk-lateral-movement-)
  - [11.22 Tabel Korelasi — Pertanyaan Investigasi ke Artefak](#1122-tabel-korelasi--pertanyaan-investigasi-ke-artefak)
  - [11.23 Ringkasan Command & Tools Cheat Sheet](#1123-ringkasan-command--tools-cheat-sheet)
  - [11.24 Mini Case Study — Workflow End-to-End](#1124-mini-case-study--workflow-end-to-end)

*(Bab 1: Struktur Linux & Filesystem Dasar. Bab 2: Filesystem Forensics Ext4/XFS. Bab 3: Syslog, Journald & Log Forensics. Bab 4: User, Auth & Shell Artifacts. Bab 5: Browser Forensics Linux. Bab 6: Persistence. Bab 7: Memory Forensics. Bab 8: Malware & Rootkit Analysis. Bab 9: Timeline Correlation & Anti-Forensics. Bab 10: Container & Cloud-Native Forensics.)*

---

## Bab 11 — Network Service & Enterprise Linux

### 11.1 Overview & Posisi Bab 11

> 💡 **Posisi Bab 11 di seri ini:** Bab 1-10 seluruhnya menganalisis **satu mesin** — walau Bab 9 sudah membangun metodologi korelasi timeline yang kuat, sumbernya tetap dari satu host. Bab 11 adalah bab **penutup** yang naik satu level: merekonstruksi pergerakan attacker **lintas banyak mesin** dalam lingkungan enterprise, dan mengenali infrastruktur identitas terpusat (LDAP/Kerberos/SSSD) yang menggantikan `/etc/passwd` lokal (Bab 4) begitu sebuah organisasi tumbuh melampaui satu server.

**Beda Bab 4 §4.13 vs Bab 11:** Bab 4 §4.13 membahas artefak SSH **per-host** — file state (`authorized_keys`, `known_hosts`, `sshd_config`) di **satu** mesin. Bab 11 §11.3-11.7 membahas **rekonstruksi lintas-host** — menyambung artefak dari banyak mesin sekaligus jadi satu rantai pergerakan yang koheren.

**Beda Bab 4 §4.9 vs Bab 11:** Bab 4 §4.9 (`nsswitch.conf`) cuma menunjukkan **bahwa** ada backend eksternal untuk resolusi identitas (`sss`, `ldap`). Bab 11 §11.9-11.16 membahas **isi & mekanisme** backend itu sendiri — bagaimana LDAP/Kerberos/SSSD benar-benar bekerja dan artefak apa yang mereka tinggalkan.

> 📖 **Cross-reference metodologis:** Bab 11 **tidak memperkenalkan metodologi baru** — ini pada dasarnya adalah **studi kasus penerapan** metodologi Bab 9 (evidence reliability, timeline normalization, korelasi multi-sumber) yang diterapkan lintas banyak host sekaligus, dengan tantangan tambahan yang unik untuk konteks itu (clock drift antar-host, §11.21).

---

### 11.2 SSH Protocol-Level Forensics (Fondasi)

#### 11.2.1 Auth Method — Publickey vs Password vs Keyboard-Interactive

**Pengertian & Fungsi:**
SSH mendukung beberapa metode autentikasi berbeda — metode yang dipakai **meninggalkan jejak log yang berbeda** di sisi server, dan punya implikasi keamanan yang berbeda pula.

| Metode | Cara Kerja | Jejak di Log (cross-ref Bab 3 §3.3.1) |
|---|---|---|
| **publickey** | Client membuktikan kepemilikan private key tanpa mengirim key itu sendiri | `Accepted publickey for <user> from <IP> ... ssh2: RSA SHA256:<fingerprint>` |
| **password** | Password dikirim (dalam kanal terenkripsi) untuk diverifikasi server | `Accepted password for <user> from <IP>` |
| **keyboard-interactive** | Challenge-response generik — bisa dipakai untuk password biasa, OTP/2FA, atau PAM conversation kustom | `Accepted keyboard-interactive/pam for <user> from <IP>` — **tidak selalu berarti password sederhana**, bisa jadi 2FA |

```bash
grep "Accepted" /var/log/auth.log
```

> ⚠️ **Kesalahan umum interpretasi:** `keyboard-interactive` sering disalahartikan sebagai "sama dengan password" — padahal method ini adalah **wadah generik** yang bisa membungkus banyak skema, termasuk 2FA/OTP. Jangan simpulkan "tidak ada MFA" hanya karena log menunjukkan `keyboard-interactive` tanpa memeriksa konfigurasi PAM (Bab 4 §4.7) di balik metode ini.

---

#### 11.2.2 SSH ControlMaster/Connection Multiplexing

**Pengertian & Fungsi:**
`ControlMaster` mengizinkan **satu koneksi TCP fisik** dipakai bersama oleh **banyak sesi SSH logic** (multiplexing) — sesi kedua dan seterusnya ke host yang sama tidak membuka koneksi TCP/handshake baru, melainkan "menumpang" koneksi yang sudah ada lewat Unix socket lokal.

```
~/.ssh/config:
Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 10m
```

> ⚠️ **Implikasi krusial untuk penghitungan log:** Kalau `ControlMaster` aktif, membuka 5 terminal berbeda ke host yang sama **bisa jadi cuma menghasilkan SATU baris** `Accepted publickey` di `auth.log` (untuk koneksi master), sementara 4 sesi berikutnya **tidak tercatat sebagai login terpisah** di server. Investigator yang menghitung "berapa kali user X login" murni dari jumlah baris `Accepted` di log **bisa salah hitung drastis** — perlu cross-check dengan `wtmp`/`utmp` (Bab 4) atau `ControlPath` socket file di sisi client untuk konfirmasi jumlah sesi logic sebenarnya.

```bash
# Cek socket ControlMaster aktif di sisi client — indikasi berapa banyak "koneksi induk" ada
ls -la ~/.ssh/sockets/ 2>/dev/null
```

---

#### 11.2.3 Protocol Version & Cipher Negotiation sebagai Fingerprint 🔴

**Pengertian & Fungsi:**
Setiap client SSH (OpenSSH standar, PuTTY, libssh2, paramiko/Python, dst) mengirim **banner string** dan daftar algoritma yang didukung (key exchange, cipher, MAC) saat negosiasi awal koneksi — kombinasi ini cukup unik untuk **fingerprint tool/library** yang dipakai, terlepas dari apa yang diklaim user-agent atau konteks lain.

```
Contoh banner string berbeda:
SSH-2.0-OpenSSH_9.0                    ← OpenSSH standar (client biasa)
SSH-2.0-libssh2_1.10.0                  ← library, sering dipakai script/tool otomatis
SSH-2.0-paramiko_3.1.0                   ← Python paramiko, umum untuk automation/tooling custom
SSH-2.0-Go                                ← implementasi Go (golang.org/x/crypto/ssh), umum untuk malware/C2 custom
```

```bash
# Server mencatat banner client di verbose log (butuh LogLevel VERBOSE di sshd_config)
grep -i "SSH-2.0" /var/log/auth.log

# Cek algoritma yang dinegosiasikan (kalau logging cukup detail, atau dari packet capture)
sshd -T | grep -i "ciphers\|kexalgorithms"
```

> ⚠️ **Kenapa ini penting untuk deteksi:** Login dari akun yang **biasanya** dipakai lewat terminal manusia (OpenSSH standar) tapi tiba-tiba menunjukkan banner `SSH-2.0-Go` atau `libssh2` adalah sinyal kuat bahwa login itu dilakukan **tool otomatis/script**, bukan manusia — konsisten dengan pola lateral movement otomatis (worm-like) yang dibahas di §11.3.4. Fingerprint ini independen dari username/IP, sehingga tetap berguna walau attacker sudah memakai kredensial curian yang "sah".

---

### 11.3 SSH Lateral Movement — Rekonstruksi Rantai Pivot 🔴

#### 11.3.1 Model Dasar Rantai Pivot

**Pengertian & Fungsi:**
Rekonstruksi pergerakan attacker antar-host lewat SSH pada dasarnya adalah proses menyambung **dua sisi bukti** di tiap "hop" — bukti niat di sisi asal (client) dan bukti realisasi di sisi tujuan (server).

```
Host A                                    Host B
──────                                     ──────
~/.ssh/config                                auth.log:
~/.ssh/known_hosts   ──── (niat/percobaan) ────►  "Accepted publickey for root
(Bab 4 §4.13.3/4.13.4)                             from <IP_HostA> ... ssh2:
                                                     RSA SHA256:<fingerprint>"
                                                          │
                                                          ▼
                                                   Host B: ~/.ssh/known_hosts
                                                   (attacker lanjut coba ke Host C
                                                    DARI Host B) ──► Host C: auth.log
                                                                       (hop berikutnya, dst)
```

> 📖 **Cross-reference:** `~/.ssh/known_hosts` dan `~/.ssh/config` sudah dibahas strukturnya di Bab 4 §4.13.3-4.13.4. Bagian ini memakai keduanya sebagai **titik sambung** antar host, bukan mengulang detail strukturnya.

---

#### 11.3.2 Koreksi: `known_hosts` Cuma Bukti "Pernah Coba"

⚠️ **Koreksi metodologis yang wajib ditegaskan:** Entry di `known_hosts` Host A yang menunjuk ke Host B **hanya membuktikan** bahwa dari Host A **pernah ada percobaan koneksi SSH** ke Host B (host key sempat diterima/disimpan) — **BUKAN** bukti bahwa login benar-benar **berhasil**. Percobaan bisa saja gagal (password salah, key ditolak) setelah host key tersimpan.

```
known_hosts Host A → Host B tercatat    =  "PERNAH DICOBA" (necessary, TIDAK sufficient)
auth.log Host B menunjukkan "Accepted"  =  "BERHASIL MASUK" (bukti yang sebenarnya dibutuhkan)

Satu hop rantai pivot dianggap VALID hanya kalau KEDUA bukti ini ada dan waktu-nya konsisten
```

> ⚠️ **Kenapa ini ditegaskan ulang secara eksplisit:** Ini kesalahan metodologis paling umum di rekonstruksi lateral movement SSH — investigator yang berhenti di `known_hosts` saja (tanpa konfirmasi `auth.log` di host tujuan) berisiko melaporkan hop yang **sebenarnya gagal** sebagai bagian rantai kompromi yang valid, atau sebaliknya melewatkan hop yang berhasil lewat metode lain (password, bukan key) yang tidak meninggalkan entry `known_hosts` relevan.

```bash
# WAJIB: konfirmasi silang kedua sisi untuk SETIAP hop yang diklaim
# Sisi A: known_hosts
grep "<hostname_atau_IP_B>" /home/<user>/.ssh/known_hosts

# Sisi B: auth.log, DENGAN rentang waktu yang cocok dengan entry known_hosts di atas
grep "Accepted" /var/log/auth.log | grep "<IP_HostA>"
```

---

#### 11.3.3 Fingerprint Key sebagai Thread Lintas-Host

**Pengertian & Fungsi:**
Fingerprint SSH key (tercatat di baris `Accepted publickey`, §11.2.1) yang **sama** muncul di banyak host berbeda adalah bukti kuat **satu identitas/aktor** yang bergerak, bukan sekumpulan insiden yang kebetulan terlihat mirip.

```bash
# Kumpulkan SEMUA fingerprint yang dipakai untuk login sukses, lintas banyak host
grep "Accepted publickey" /var/log/auth.log | grep -oP "SHA256:\S+"
```

> 💡 **Kenapa ini "thread" yang lebih kuat dari sekadar IP:** IP source bisa berubah (attacker pivot lewat host berbeda, §11.3.1), tapi **key yang sama** dipakai berulang menunjukkan kontinuitas identitas yang tidak bergantung pada infrastruktur jaringan attacker. Kumpulan fingerprint yang sama muncul di Host A, C, dan F (tapi tidak di B, D, E) memberi peta pergerakan yang jelas, bahkan kalau urutan hop-nya sendiri belum sepenuhnya jelas dari log semata.

---

#### 11.3.4 Timing Correlation — Pivot Manual vs Otomatis 🔴

**Pengertian & Fungsi:**
Selisih waktu antara **logout** dari Host A dan **login** ke Host B adalah indikator berharga untuk membedakan pivot yang dilakukan **manual** (attacker mengetik command satu-satu) vs **otomatis** (script/worm yang bergerak sendiri begitu satu host dikompromikan).

| Pola Gap Waktu | Interpretasi |
|---|---|
| **Gap besar & bervariasi** (menit-jam, tidak konsisten antar hop) | Konsisten dengan operator manusia — waktu dipakai untuk eksplorasi, pengambilan keputusan, mengetik command |
| **Gap sangat kecil & konsisten** (detik, hampir sama persis di tiap hop) | Konsisten dengan **script otomatis/worm** — pola pergerakan yang diprogram, tidak menunggu keputusan manusia |
| **Login Host B terjadi SEBELUM logout Host A** (sesi paralel) | Attacker menjaga akses ke Host A tetap terbuka sambil membuka sesi baru — pola operator yang lebih berpengalaman/hati-hati |

```bash
# Ekstrak timestamp logout Host A & login Host B untuk hitung gap
# (kombinasi 'last' untuk sesi lengkap dengan durasi, Bab 4)
last -F | grep "<user>"
```

> 💡 **Nilai forensik gap waktu konsisten:** Kalau ditemukan **3+ hop** dengan gap waktu yang hampir identik (misal selalu ~4 detik antara logout dan login berikutnya), itu bukti kuat **otomatisasi** — sangat relevan untuk membedakan insiden "attacker manual sedang eksplorasi jaringan" (risiko lebih terarah tapi lebih lambat) vs "worm/script self-propagating" (risiko penyebaran jauh lebih cepat dan luas, butuh respons containment berbeda).

---

#### 11.3.5 Membangun Tabel/Diagram Rantai Pivot

**Pengertian & Fungsi:**
Menyatukan §11.3.1-11.3.4 jadi output konkret yang bisa dipakai laporan — bukan sekadar teori, tapi metodologi praktis mengumpulkan data tersebar jadi satu gambaran koheren.

```
Format tabel rekonstruksi (isi tiap baris = satu hop yang SUDAH divalidasi §11.3.2):

| Hop | Host Asal | Host Tujuan | Waktu Login | Key Fingerprint | Metode | Manual/Auto |
|-----|-----------|-------------|-------------|-----------------|--------|--------------|
| 1   | Host A    | Host B      | 14:02:15    | SHA256:abc123.. | pubkey | Manual (gap 3 menit) |
| 2   | Host B    | Host C      | 14:02:19    | SHA256:abc123.. | pubkey | Otomatis (gap 4 detik) |
| 3   | Host C    | Host D      | 14:02:23    | SHA256:abc123.. | pubkey | Otomatis (gap 4 detik) |
```

> 📌 **Prinsip menyusun tabel ini:** Setiap baris harus lolos validasi §11.3.2 (kedua sisi dikonfirmasi) sebelum dimasukkan — fingerprint kolom yang konsisten (§11.3.3) mengonfirmasi satu aktor, dan kolom Manual/Otomatis (§11.3.4) memberi konteks tambahan untuk penilaian risiko. Tabel ini menjadi input langsung untuk §11.21 (timeline lintas-host yang lebih luas, menggabungkan sumber selain SSH).

---

### 11.4 SSH Trust & Bastion/Jump Host

#### 11.4.1 ProxyJump & ProxyCommand

**Pengertian & Fungsi:**
Dua mekanisme SSH client untuk **melompat lewat host perantara** tanpa harus login manual dua kali — `ProxyJump` (disingkat `-J`) adalah versi modern & sederhana, `ProxyCommand` adalah mekanisme lama yang lebih fleksibel (bisa dipakai untuk skenario selain jump host, misal lewat `nc`/`socat`).

```
~/.ssh/config di Host A:
Host hostC
    HostName 10.0.0.5
    ProxyJump bastion.example.com    ← koneksi otomatis lewat bastion dulu

Host bastion.example.com
    HostName bastion.example.com
    User jumpuser

# Setara dengan ProxyCommand (mekanisme lama, sintaks lebih verbose):
Host hostC
    ProxyCommand ssh -W %h:%p bastion.example.com
```

```bash
ssh -J bastion.example.com user@hostC    # ProxyJump langsung dari CLI
```

> ⚠️ **Implikasi forensik krusial:** Dengan `ProxyJump`, **Host A tidak pernah membuka koneksi TCP langsung ke Host C** — semua traffic secara fisik lewat bastion. Ini berarti **`auth.log` di Host C mencatat source IP BASTION**, bukan IP Host A yang sebenarnya jadi titik asal. Investigator yang cuma melihat log Host C akan salah menyimpulkan "attacker datang dari bastion" — padahal bastion cuma jadi perantara sah, dan identitas asal sebenarnya (Host A) cuma bisa ditemukan lewat log **bastion itu sendiri**.

---

#### 11.4.2 Bastion sebagai Single Point of Pivot

**Pengertian & Fungsi:**
Karena semua traffic ProxyJump/ProxyCommand melalui bastion secara fisik, **log bastion menjadi hub korelasi** — satu titik yang mencatat SEMUA percobaan pivot ke berbagai host tujuan, bukan tersebar di banyak pasangan host seperti model direct-hop (§11.3).

```
Model Direct-Hop (§11.3):                    Model Bastion (§11.4):
Host A → auth.log Host B (langsung)             Host A → auth.log BASTION → auth.log Host C
Host B → auth.log Host C (langsung)                          │
(2 titik log terpisah untuk 2 hop)                 Bastion mencatat SEMUA percobaan
                                                     forward ke Host C, D, E, dst — SATU
                                                     titik log paling kaya untuk rekonstruksi
```

> 💡 **Kenapa ini "berkah" sekaligus "kelemahan" untuk investigasi:** Kalau organisasi memakai bastion dengan disiplin (semua akses SERVER internal WAJIB lewat bastion, tidak ada direct access), maka **log bastion saja** sering cukup untuk merekonstruksi seluruh pola pergerakan internal — jauh lebih efisien daripada mengumpulkan log dari puluhan host individual. Sebaliknya, kalau bastion **sendiri** yang dikompromikan (atau log-nya dihapus/tidak ada), investigator kehilangan titik korelasi paling berharga sekaligus — high-value target untuk investigasi maupun untuk attacker.

```bash
# Di sisi bastion — cek SEMUA forward yang terjadi (port forwarding internal ke host lain)
grep "direct-tcpip\|forwarding" /var/log/auth.log
journalctl -u sshd | grep -i "forward"
```

---

#### 11.4.3 SSH CA & Host Certificates

**Pengertian & Fungsi:**
Alternatif model trust dari `known_hosts` biasa (Bab 4 §4.13.4, model Trust-on-First-Use) — organisasi enterprise sering memakai **SSH Certificate Authority (CA)**: satu otoritas menandatangani host certificate untuk semua server, dan client cukup percaya CA tsb (bukan menyimpan host key satu-satu di `known_hosts`).

```
Model known_hosts biasa (TOFU):                Model SSH CA:
Client simpan host key TIAP server               Client cuma perlu TrustedUserCAKeys
secara manual/first-connect                       (satu CA public key)
                                                    │
                                                    ▼
                                                  Semua host certificate yang
                                                  ditandatangani CA tsb OTOMATIS
                                                  dipercaya, TANPA entry known_hosts
                                                  individual per-host
```

```
/etc/ssh/sshd_config (di server):
HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub

~/.ssh/known_hosts (di client, format CA):
@cert-authority *.internal.example.com ssh-rsa AAAA...  (CA public key)
```

> ⚠️ **Kenapa ini penting dipahami sebelum menilai `known_hosts`:** Kalau organisasi memakai SSH CA, `known_hosts` client **TIDAK AKAN** berisi entry individual per-host (§11.3.1-11.3.2 asumsi TOFU biasa) — investigator yang mengharapkan pola `known_hosts` konvensional bisa **salah simpulkan** "tidak ada bukti percobaan koneksi ke Host X" padahal sebenarnya trust model-nya memang berbeda. Selalu cek dulu apakah lingkungan target memakai SSH CA (`@cert-authority` di `known_hosts`, atau `TrustedUserCAKeys` di `sshd_config`) sebelum menerapkan asumsi §11.3.2 secara mentah.

```bash
# Cek apakah lingkungan memakai SSH CA
grep "@cert-authority" ~/.ssh/known_hosts
grep "TrustedUserCAKeys\|HostCertificate" /etc/ssh/sshd_config
```

---

#### 11.4.4 Rekonstruksi Host A → Bastion → Host B

Menggabungkan §11.4.1-11.4.3 jadi alur konkret:

```
[1] Konfirmasi model yang dipakai — cek ~/.ssh/config Host A untuk ProxyJump/ProxyCommand (§11.4.1)
[2] Kalau bastion dipakai, PRIORITASKAN log bastion sebagai sumber utama (§11.4.2)
    grep "<user>" /var/log/auth.log   (di BASTION, bukan di Host tujuan)
[3] Di log bastion, cari BAIK login masuk (dari Host A) MAUPUN forward keluar (ke Host B)
    → korelasikan waktu keduanya untuk konfirmasi Host A memang jadi ASAL forward ke Host B
[4] Konfirmasi di sisi Host B — auth.log akan menunjukkan source IP BASTION (§11.4.1),
    BUKAN IP Host A — ini NORMAL dan EXPECTED untuk model bastion, bukan anomali
[5] Cek model trust (§11.4.3) — kalau SSH CA dipakai, jangan cari known_hosts individual,
    cek sertifikat & log CA/bastion untuk validasi
```

---

### 11.5 SSH sebagai C2/Tunneling Channel

#### 11.5.1 Local/Remote/Dynamic Port Forwarding

| Mode | Command | Cara Kerja | Jejak yang Ditinggalkan |
|---|---|---|---|
| **Local (`-L`)** | `ssh -L 8080:target:80 host` | Port lokal di client di-forward ke port di sisi **server/network server** | Listening port baru di client, koneksi keluar dari server ke `target` |
| **Remote (`-R`)** | `ssh -R 9000:localhost:22 host` | Port di **server** di-forward balik ke client — server "membuka pintu" ke jaringan client | Listening port baru di **server**, sering dipakai untuk **reverse shell/akses balik** dari jaringan tertutup |
| **Dynamic (`-D`)** | `ssh -D 1080 host` | Membuat **SOCKS proxy** — semua traffic app yang dikonfigurasi lewat proxy ini di-tunnel lewat SSH | Listening SOCKS port di client, semua traffic keluar "menyamar" sebagai satu koneksi SSH |

---

#### 11.5.2 Deteksi Tunnel Aktif dari Sisi Host 🔴

```bash
# Cari listening port yang TERIKAT ke proses ssh — indikasi kuat port forwarding aktif
ss -tulpn | grep ssh
netstat -tulpn | grep ssh

# Cek proses ssh dengan argumen -L/-R/-D di command line-nya (kalau masih live)
ps aux | grep -E "ssh.*-[LRD]"
```

```
Contoh output mencurigakan:
tcp   LISTEN  0  128  127.0.0.1:1080  0.0.0.0:*  users:(("ssh",pid=4521,fd=6))
                        │
                        └── Port 1080 terikat proses ssh — pola KHAS Dynamic
                             forwarding (-D) untuk SOCKS proxy (§11.5.3)
```

> ⚠️ **Kenapa ini butuh dicek eksplisit, bukan asumsi dari log biasa:** Port forwarding **tidak menghasilkan baris log terpisah** di `auth.log` — dari sudut pandang log autentikasi, ini terlihat sama seperti sesi SSH interaktif biasa. Satu-satunya cara mendeteksi tunnel aktif adalah lewat **state jaringan live** (`ss`/`netstat`) atau (kalau sistem sudah mati) analisis command line proses SSH dari memory dump (Bab 7 §7.6.4) — bukan dari `auth.log` semata.

---

#### 11.5.3 SOCKS Proxy via `-D` sebagai Jalur Tersembunyi

**Pengertian & Fungsi:**
Dynamic port forwarding (`-D`) adalah teknik **exfiltrasi/pivot paling sulit dideteksi** dari sekadar log — karena semua traffic (bisa berupa banyak koneksi ke banyak tujuan berbeda) di-**bungkus** menjadi satu koneksi SSH tunggal.

> ⚠️ **Kenapa ini sering lolos deteksi berbasis log biasa:** Firewall/IDS yang memonitor koneksi keluar berdasarkan **destination IP/port** akan melihat SATU koneksi SSH normal (ke port 22 host yang mungkin legitimate) — sementara traffic sebenarnya yang di-tunnel di dalamnya (ke puluhan destination berbeda lewat SOCKS) **sama sekali tidak terlihat** sebagai koneksi baru yang mencolok. Deteksi realistis butuh **deep packet inspection** (di luar cakupan seri filesystem-focused ini) atau — dari sisi host forensik — kombinasi §11.5.2 (listening port SOCKS) dengan volume traffic yang tidak wajar untuk satu koneksi SSH "biasa".

```bash
# Volume traffic tidak wajar untuk satu koneksi SSH interaktif biasa (indikasi tunneling aktif)
ss -i | grep -A5 ":22 "    # cek statistik byte transferred pada koneksi SSH
```

---

#### 11.5.4 Beda dengan Agent Forwarding

> 📖 **Cross-reference eksplisit:** Bab 4 §4.13.7 sudah membahas SSH **agent forwarding** (`ForwardAgent yes`) — mekanisme yang **sering tertukar** dengan port forwarding (§11.5.1) padahal konsepnya sama sekali berbeda.

| | Port Forwarding (§11.5.1) | Agent Forwarding (Bab 4 §4.13.7) |
|---|---|---|
| Yang di-tunnel | **Traffic jaringan** (TCP koneksi ke port tertentu) | **Permintaan sign/autentikasi** ke `ssh-agent` di client |
| Tujuan | Akses ke service/port yang tidak langsung reachable | Memakai key SSH di mesin client TANPA copy private key ke server tujuan |
| Risiko forensik | Tunnel bisa dipakai C2/exfiltrasi (§11.5.2-11.5.3) | Server yang terkompromi bisa **menyalahgunakan** agent client untuk sign koneksi BARU ke host lain (relevan ke §11.3 lateral movement) |

> ⚠️ **Kenapa distinction ini penting:** Server yang terkompromi dengan sesi `ForwardAgent yes` aktif memberi attacker kemampuan memakai key milik **user asli** untuk pivot ke host lain (§11.3.3, fingerprint key yang sama) **tanpa pernah mencuri file private key-nya** — investigator yang cuma fokus ke port forwarding (§11.5.1-11.5.3) sebagai "jalur C2" bisa melewatkan agent forwarding sebagai vektor lateral movement yang sama sekali berbeda mekanismenya.

---

### 11.6 Privilege Escalation After Lateral Movement

#### 11.6.1 `sudo` Setelah SSH Login — Pola Umum

**Pengertian & Fungsi:**
Begitu attacker berhasil landing di satu host (via SSH, §11.3-11.4), langkah alami berikutnya sering kali adalah eskalasi privilege lewat `sudo` — korelasi antara sesi SSH dan aktivitas `sudo` berikutnya adalah pola investigasi standar yang menghubungkan "bagaimana masuk" dengan "apa yang dilakukan".

```bash
# Cek aktivitas sudo SEGERA SETELAH satu sesi SSH dimulai (window waktu pendek)
grep "Accepted publickey for <user>" /var/log/auth.log
# catat timestamp, lalu:
grep "sudo:" /var/log/auth.log | awk -v start="<timestamp_login>" '$0 >= start'
```

> 📖 **Cross-reference:** Struktur log `sudo` itu sendiri (`auth.log` entry, `sudoers` config) sudah dibahas di Bab 4. Bagian ini fokus ke **korelasi temporal** antara event login SSH dan aktivitas `sudo` berikutnya sebagai pola investigasi, bukan mengulang struktur dasarnya.

---

#### 11.6.2 Root Transition & Session Boundary

**Pengertian & Fungsi:**
Penting membedakan **batas sesi** yang berbeda — sesi SSH awal (sebagai user biasa) vs sesi setelah `sudo -i`/`su -` (menjadi root) adalah **dua konteks logging yang berbeda**, meski secara fisik satu koneksi TCP/terminal yang sama.

```
Sesi SSH awal (user biasa)
   │  auth.log: "Accepted publickey for lowpriv from ..."
   ▼
sudo -i  atau  su -
   │  auth.log: "lowpriv : TTY=pts/0 ; PWD=/home/lowpriv ; USER=root ; COMMAND=/bin/bash"
   ▼
Sesi ROOT (command berikutnya SEMUA tercatat sebagai root, TIDAK LAGI terikat
langsung ke user asal KECUALI lewat correlation manual ke baris sudo di atas)
```

> ⚠️ **Kenapa boundary ini penting:** Command yang dijalankan **setelah** transisi ke root **tidak otomatis** "terhubung" ke sesi SSH awal di kebanyakan log standar — analis harus **secara eksplisit** mengorelasikan baris `sudo`/`su` (yang mencatat siapa user asal) dengan command-command berikutnya yang dijalankan sebagai root, memakai **TTY/PTS number** yang sama sebagai penghubung.

```bash
# Korelasikan lewat TTY yang sama — command root berikutnya di TTY yang sama dengan baris sudo
grep "TTY=pts/0" /var/log/auth.log
```

---

#### 11.6.3 Korelasi `sudo` → Command → Persistence

**Pengertian & Fungsi:**
Menyatukan §11.6.1-11.6.2 dengan Bab 6 — begitu privilege root tercapai, langkah investigasi alami berikutnya adalah cek apakah root access itu dipakai untuk memasang **persistence**.

```
[1] Login SSH awal (§11.3, §11.4)
      │
      ▼
[2] sudo/su ke root (§11.6.1-11.6.2)
      │
      ▼
[3] Cek command yang dijalankan sebagai root SEGERA setelahnya (TTY correlation)
      │
      ▼
[4] Cross-check ke Bab 6 — apakah ada unit systemd/cron/dll baru dibuat
    dalam window waktu yang sama? (Prinsip Umum Bab 6 §6.2 — owner/mtime)
      │
      ▼
[5] Cross-check ke Bab 4 §4.2 — apakah ada user baru dibuat (useradd) sebagai
    persistence tambahan (akun backdoor)?
```

> 💡 **Kenapa rantai ini sering jadi "tulang punggung" laporan insiden:** Kombinasi SSH login → privilege escalation → persistence adalah pola **paling umum** ditemukan di investigasi kompromi server Linux nyata maupun CTF — rantai lima langkah di atas, kalau semua tautannya berhasil dikonfirmasi dengan timestamp yang konsisten, memberi narasi insiden yang sangat kuat dan sulit dibantah.

---

### 11.7 Korelasi Client vs Server Artifact Lintas Host

**Pengertian & Fungsi:**
Tabel master yang menyatukan §11.2-11.6 — untuk **satu hop** pivot yang sama, artefak apa yang harus diambil dari sisi **client** (host asal) vs sisi **server** (host tujuan), dan kenapa investigasi yang cuma mengambil satu sisi selalu tidak lengkap.

| Artefak | Sisi Client (Host Asal) | Sisi Server (Host Tujuan) |
|---|---|---|
| Bukti percobaan koneksi | `~/.ssh/known_hosts` (Bab 4 §4.13.4) | — |
| Bukti login berhasil | — | `auth.log` "Accepted ..." |
| Identitas key yang dipakai | `~/.ssh/id_*` (private key ADA di sini) | `~/.ssh/authorized_keys` (public key, Bab 4 §4.13.2) + fingerprint di log |
| Konfigurasi pivot | `~/.ssh/config` (ProxyJump, §11.4.1) | — |
| Command yang dijalankan setelah masuk | Command history di client (kalau interaktif) | `auth.log`/`sudo` log, `.bash_history` (Bab 4 §4.10) DI HOST TUJUAN |
| Bukti port forwarding/tunnel | Proses `ssh` dengan flag `-L/-R/-D` (live/memory, §11.5.2) | Listening port yang di-forward (kalau `-R`, listening-nya justru di SERVER) |

> ⚠️ **Kenapa investigasi satu sisi selalu tidak lengkap:** Setiap baris tabel di atas menunjukkan **separasi bukti yang tegas** — client dan server masing-masing memegang **separuh cerita** yang saling melengkapi (persis prinsip §11.3.2). Investigasi yang cuma dapat akses ke satu sisi (misal cuma log server, tanpa bisa akses Host asal) **secara struktural** tidak bisa mengonfirmasi keseluruhan rantai — paling banter bisa membangun hipotesis kuat, bukan bukti tervalidasi penuh.

---

### 11.8 Enterprise Identity Resolution

#### 11.8.1 Local User vs LDAP User vs Kerberos Principal

**Pengertian & Fungsi:**
Sebelum masuk detail LDAP (§11.9) dan Kerberos (§11.12), penting dipahami **tiga jenis identitas** yang mungkin ditemui di lingkungan enterprise — ketiganya bisa merujuk ke "orang yang sama" tapi direpresentasikan berbeda di sistem berbeda.

| Jenis Identitas | Sumber | Contoh |
|---|---|---|
| **Local user** | `/etc/passwd` di mesin itu sendiri (Bab 4 §4.2) | `lowpriv:x:1001:1001::/home/lowpriv:/bin/bash` |
| **LDAP user** | Direktori terpusat (§11.9), diquery lewat NSS/SSSD | `uid=jdoe,ou=people,dc=corp,dc=example,dc=com` |
| **Kerberos principal** | Realm Kerberos (§11.12) — identitas untuk **autentikasi**, terpisah konseptual dari LDAP (walau sering satu paket praktis lewat SSSD/AD) | `jdoe@CORP.EXAMPLE.COM` |

> 💡 **Kenapa distinction ini krusial di awal:** LDAP menjawab pertanyaan **"siapa user ini"** (identity/attribute), Kerberos menjawab **"bagaimana user ini membuktikan dirinya"** (authentication) — dua hal yang **konseptual berbeda** walau di praktiknya sering digabung jadi satu pengalaman login lewat SSSD (§11.11). Memahami mana yang mana penting untuk tahu artefak mana yang harus dicek untuk pertanyaan investigasi yang berbeda.

---

#### 11.8.2 `getent`, `id` & Resolusi Identitas

```bash
# getent — query lewat SELURUH backend nsswitch.conf (files, sss, ldap — Bab 4 §4.9,
# diperdalam §11.10.1), TIDAK PEDULI user itu local atau dari domain
getent passwd <username>
getent group <groupname>

# id — resolusi lengkap UID/GID + SEMUA group membership (termasuk dari domain)
id <username>
```

```
Contoh output getent untuk user LOCAL:
lowpriv:x:1001:1001::/home/lowpriv:/bin/bash

Contoh output getent untuk user LDAP/domain (via SSSD):
jdoe:*:1458601102:1458600513:John Doe:/home/jdoe:/bin/bash
       └── UID besar & tidak sekuensial dengan user lokal — pola khas identitas
            domain (§11.8.3)
```

> 📌 **Kenapa `getent` lebih reliable daripada `cat /etc/passwd` untuk enterprise:** `cat /etc/passwd` **HANYA** menunjukkan user lokal (Bab 4 §4.2) — user LDAP/domain **tidak pernah muncul** di file ini sama sekali (§11.10.3). `getent passwd` menembus semua layer NSS yang dikonfigurasi (`nsswitch.conf`, §11.10.1), memberi gambaran identitas **lengkap** terlepas dari sumbernya.

---

#### 11.8.3 UID/GID → Identity Domain

**Pengertian & Fungsi:**
Pola penomoran UID/GID sering jadi **indikator cepat** apakah sebuah akun berasal dari domain atau lokal, sebelum perlu query eksplisit.

| Rentang UID | Konteks Umum |
|---|---|
| 0 | root |
| 1-999 (bervariasi per-distro) | System/service account lokal (§11.15) |
| 1000-60000 | User lokal biasa (dibuat manual via `useradd`) |
| **UID sangat besar** (jutaan, kadang > 2 miliar untuk sebagian skema SID-mapping) | **Ciri khas identitas domain** — SSSD/Winbind sering memetakan SID Active Directory atau UID LDAP jadi angka besar untuk menghindari tabrakan dengan UID lokal |

```bash
# Cek pola UID untuk semua akun sekaligus, bandingkan lokal vs domain
getent passwd | awk -F: '{print $1, $3}' | sort -k2 -n
```

> ⚠️ **Jangan berasumsi dari angka semata:** Pola UID besar adalah **indikasi kuat** tapi bukan jaminan absolut — beberapa organisasi mengonfigurasi UID mapping range custom. Selalu konfirmasi dengan `getent passwd` (§11.8.2, menunjukkan sumber lewat perilaku resolusi) atau cek langsung ke SSSD cache (§11.11.3) untuk kepastian.

---

#### 11.8.4 Offline Identity/Cache

> 📖 **Preview ke §11.11.3:** Salah satu pertanyaan paling penting dalam identity resolution enterprise adalah — **apa yang terjadi kalau server LDAP/KDC tidak bisa dihubungi?** Jawabannya bergantung penuh pada **cache SSSD**, dibahas detail di §11.11.3. Poin kuncinya di sini: identitas domain **tidak selalu** butuh koneksi live ke server pusat untuk diresolusi — cache lokal bisa menjawab `getent`/`id` bahkan dalam kondisi offline, dengan konsekuensi forensik yang signifikan (bukti login domain tetap ada walau server LDAP sudah tidak bisa diakses investigator).

---

### 11.9 LDAP di Linux — Overview & Arsitektur

#### 11.9.1 Konsep Dasar — DN, Tree, objectClass

**Pengertian & Fungsi:**
LDAP (Lightweight Directory Access Protocol) menyimpan data sebagai **tree hierarkis** dari entry — tiap entry punya alamat unik (**DN**, Distinguished Name) dan sekumpulan atribut yang jenisnya ditentukan oleh **objectClass**.

```
Struktur Tree LDAP (contoh):
dc=corp,dc=example,dc=com                    ← root domain
  └── ou=people                                ← Organizational Unit untuk user
       └── uid=jdoe,ou=people,dc=corp,dc=example,dc=com   ← DN lengkap satu user
             ├── objectClass: posixAccount, inetOrgPerson
             ├── uid: jdoe
             ├── cn: John Doe
             ├── uidNumber: 1458601102
             ├── gidNumber: 1458600513
             └── memberOf: cn=admins,ou=groups,dc=corp,dc=example,dc=com
```

| Istilah | Pengertian |
|---|---|
| **DN (Distinguished Name)** | Alamat unik satu entry dalam tree, dari daun ke akar |
| **objectClass** | Skema yang menentukan atribut apa yang valid/wajib untuk entry ini (`posixAccount` untuk user Unix, dst) |
| **uid, cn** | Atribut umum — `uid` (username), `cn` (common name/nama lengkap) |
| **memberOf** | Menunjukkan keanggotaan group — relevan untuk privilege (mirip `memberOf` Active Directory di seri Windows) |

---

#### 11.9.2 OpenLDAP Server vs Linux sebagai Klien

| Peran | Deskripsi |
|---|---|
| **OpenLDAP sebagai server** | Kalau host yang diperiksa **adalah** server LDAP itu sendiri — administrasi database direktori, replikasi, ACL server-side |
| **Linux sebagai klien LDAP** | Host yang **memakai** LDAP eksternal untuk autentikasi/resolusi identitas — jauh lebih umum ditemui (workstation, server aplikasi yang auth ke LDAP terpusat) |

---

#### 11.9.3 Fokus Bab Ini — Sisi Klien 🔴

> 📌 **Batasan cakupan eksplisit:** Bab 11 fokus **sepenuhnya ke sisi klien Linux** — bagaimana satu mesin Linux **memakai** LDAP untuk auth (§11.10-11.11), bukan administrasi server LDAP itu sendiri (setup OpenLDAP, replikasi, tuning ACL server-side). Ini konsisten dengan batasan seri yang murni **Linux-side**, sama seperti Bab 10 §10.27 yang cuma "menyinggung" cloud metadata service tanpa masuk detail administrasi provider cloud.

---

### 11.10 Linux sebagai Klien LDAP — Konfigurasi & Artefak 🔴

#### 11.10.1 `/etc/nsswitch.conf` Revisited

> 📖 **Cross-reference eksplisit:** Bab 4 §4.9 memperkenalkan `nsswitch.conf` dan menyebut baris `passwd: files sss/ldap` secara sekilas. Bagian ini membedah **penuh** makna baris tersebut.

```
/etc/nsswitch.conf:
passwd:     files sss
group:      files sss
shadow:     files sss

           │        │
           │        └── Backend KEDUA — dicoba kalau TIDAK ketemu di 'files'
           └── Backend PERTAMA — /etc/passwd lokal (Bab 4 §4.2) dicoba DULUAN
```

| Urutan Backend | Perilaku |
|---|---|
| `files sss` | Cek `/etc/passwd` lokal dulu, baru SSSD (§11.11) kalau tidak ketemu — **paling umum** di konfigurasi modern |
| `files ldap` | Cek lokal dulu, baru LDAP **langsung** (tanpa SSSD sebagai perantara) — konfigurasi legacy (§11.10.2) |
| `sss files` | SSSD dicek **DULUAN** — kalau user domain dan lokal kebetulan punya nama sama, domain menang |

```bash
cat /etc/nsswitch.conf | grep -E "^passwd|^group|^shadow"
```

> ⚠️ **Kenapa urutan ini penting untuk investigasi:** Urutan backend menentukan **user mana yang "menang"** kalau ada nama yang sama terdaftar di kedua sumber (kasus edge tapi bisa jadi vektor serangan — user domain sengaja dibuat dengan nama sama dengan user lokal untuk membingungkan). Selalu cek urutan ini sebelum mengasumsikan `getent passwd <nama>` (§11.8.2) merujuk ke sumber yang "seharusnya".

---

#### 11.10.2 Konfigurasi Legacy — `ldap.conf`, `pam_ldap.conf`

**Pengertian & Fungsi:**
Sebelum SSSD jadi standar (§11.11), konfigurasi LDAP dilakukan **langsung** lewat kombinasi `nss_ldap` + `pam_ldap` — masih ditemui di sistem lebih lama atau yang belum migrasi.

```
/etc/ldap.conf  atau  /etc/openldap/ldap.conf:
BASE dc=corp,dc=example,dc=com
URI ldap://ldap.corp.example.com
```

```
/etc/pam_ldap.conf:
(konfigurasi serupa, khusus untuk modul PAM pam_ldap.so — Bab 4 §4.7)
```

> 📖 **Cross-reference:** Struktur `/etc/pam.d/` dan cara membaca modul PAM sudah dibahas Bab 4 §4.7 — kalau ditemukan `pam_ldap.so` di stack PAM, file konfigurasi terkaitnya (`pam_ldap.conf` atau `ldap.conf`) adalah tempat mencari detail server LDAP yang dipercaya.

---

#### 11.10.3 Implikasi Forensik — Enumerasi Akun Tidak Lengkap

⚠️ **Implikasi forensik besar yang wajib dipahami:** User LDAP **tidak pernah muncul** di `/etc/passwd` lokal (Bab 4 §4.2) — mereka sepenuhnya "virtual" dari perspektif file itu. Ini artinya **teknik enumerasi akun ala Bab 4** (`cat /etc/passwd`, loop semua user untuk cek crontab di Bab 6 §6.3.3, dst) **tidak lengkap** tanpa query LDAP/SSSD secara langsung.

```bash
# SALAH (tidak lengkap) — hanya menangkap user lokal
cut -f1 -d: /etc/passwd

# BENAR (lengkap) — menangkap user lokal + domain lewat NSS
getent passwd | cut -f1 -d:
```

> ⚠️ **Konsekuensi langsung ke checklist Bab 6:** Checklist enumerasi cron per-user di Bab 6 §6.3.3 (`for u in $(cut -f1 -d: /etc/passwd); do ...`) **perlu direvisi** di lingkungan LDAP-integrated — ganti sumber daftar user dari `/etc/passwd` mentah menjadi `getent passwd`, supaya user domain yang mungkin punya crontab (kalau home directory-nya ter-mount, §11.18) tidak terlewat begitu saja.

---

### 11.11 SSSD — Hub Modern Identitas Enterprise 🔴

#### 11.11.1 Kenapa SSSD Jadi Standar

**Pengertian & Fungsi:**
SSSD (System Security Services Daemon) adalah **satu daemon terpusat** yang menggantikan kombinasi terpisah `nss_ldap` + `pam_ldap` + `pam_krb5` (§11.10.2) — mengelola LDAP **dan** Kerberos **dan** caching sekaligus dalam satu proses, jadi standar de-facto di distro modern.

```
Arsitektur LAMA (terpisah):                 Arsitektur SSSD (terpadu):
nss_ldap.so  ──► query LDAP langsung          nsswitch.conf → sss ──┐
pam_ldap.so   ──► auth LDAP langsung                                 │
pam_krb5.so    ──► auth Kerberos terpisah      PAM (Bab 4 §4.7) → sss ┤──► SSSD daemon
(3 titik konfigurasi terpisah, TIDAK ada                              │      │
 caching terpadu antar mekanisme)                                     │      ├── LDAP backend
                                                                        │      ├── Kerberos backend
                                                                       ┘      └── Cache lokal (§11.11.3)
```

---

#### 11.11.2 `/etc/sssd/sssd.conf`

```ini
[sssd]
domains = corp.example.com
services = nss, pam

[domain/corp.example.com]
id_provider = ldap
auth_provider = krb5
ldap_uri = ldap://ldap.corp.example.com
krb5_realm = CORP.EXAMPLE.COM
krb5_server = kdc.corp.example.com
cache_credentials = True
```

| Field | Kegunaan Forensik |
|---|---|
| `domains` | Daftar domain yang dipercaya mesin ini — konfirmasi realm mana yang relevan |
| `id_provider` | Backend untuk **identity** (LDAP di contoh ini) — jawab §11.8.1 "siapa" |
| `auth_provider` | Backend untuk **autentikasi** (Kerberos di contoh ini) — jawab §11.8.1 "bagaimana buktikan" — **bisa beda** dari `id_provider`! |
| `cache_credentials` | Kalau `True`, memungkinkan login **offline** pakai cache (§11.11.3) — implikasi forensik besar |

---

#### 11.11.3 SSSD Cache — Nilai Forensik Tinggi 🔴

**Pengertian & Fungsi:**
`/var/lib/sss/db/*.ldb` menyimpan **cache lokal** dari data identitas & (kalau `cache_credentials=True`) kredensial yang di-hash — memungkinkan user domain tetap bisa login walau koneksi ke server LDAP/KDC terputus.

```bash
# Cek isi cache SSSD (format database ldb, butuh tool khusus untuk baca terstruktur)
ls -la /var/lib/sss/db/

# ldbsearch (dari paket ldb-tools) untuk query langsung
ldbsearch -H /var/lib/sss/db/cache_corp.example.com.ldb "(objectClass=user)"
```

> 💡 **Kenapa ini nilai forensik PALING TINGGI di seluruh bagian LDAP/SSSD:** Cache ini membuktikan bahwa **user domain X pernah login ke mesin ini** — **BAHKAN SETELAH** server LDAP/KDC pusat sendiri sudah tidak bisa diakses investigator (misal server itu sudah dimatikan, di luar jangkauan, atau di organisasi berbeda yang tidak kooperatif). Cache lokal ini independen dari ketersediaan infrastruktur pusat — kalau satu-satunya bukti yang tersisa dari sebuah investigasi adalah image disk **satu workstation**, cache SSSD di dalamnya tetap bisa mengonfirmasi identitas domain yang pernah dipakai login di sana.

> ⚠️ **Batasan:** Cache ini menyimpan data sebagaimana **terakhir kali disinkronkan** dari server — kalau atribut user (misal keanggotaan group) berubah **setelah** sinkronisasi terakhir tapi **sebelum** insiden, cache akan menunjukkan data yang **sudah usang**. Selalu catat timestamp cache sebagai bagian interpretasi.

---

#### 11.11.4 SSSD Logs

```bash
ls -la /var/log/sssd/
cat /var/log/sssd/sssd_corp.example.com.log
```

> 📖 **Kenapa terpisah dari `auth.log`:** SSSD punya log domain-nya sendiri (`sssd_<domain>.log`) yang mencatat detail komunikasi dengan backend LDAP/Kerberos (koneksi gagal/berhasil ke server, refresh cache, dst) — **lebih detail** untuk masalah spesifik SSSD dibanding baris ringkas `Accepted publickey ... via sss` di `auth.log` biasa (Bab 3). Cek keduanya untuk gambaran lengkap: `auth.log` untuk event login, SSSD log untuk detail komunikasi backend.

---

### 11.12 Kerberos — Konsep Dasar untuk Forensik 🔴

#### 11.12.1 Alur Inti — KDC, TGT, TGS

> 📌 **Level pembahasan:** Cukup untuk kebutuhan forensik praktis (baca artefak, pahami implikasi) — **bukan** kuliah protokol kriptografi penuh.

```
User Login
   │
   ▼
[1] Request ke KDC (Key Distribution Center) — server yang menangani autentikasi realm
   │
   ▼
[2] KDC beri TGT (Ticket Granting Ticket) — "tiket induk" yang membuktikan
   │   user sudah autentikasi, TANPA perlu kirim password lagi untuk request berikutnya
   ▼
[3] User pakai TGT untuk minta TGS (Ticket Granting Service) — tiket SPESIFIK
   │   untuk mengakses satu service tertentu (misal NFS server, §11.18.1)
   ▼
[4] User pakai TGS untuk akses service yang dituju
```

| Istilah | Pengertian |
|---|---|
| **KDC** | Server yang menangani seluruh proses autentikasi Kerberos untuk satu realm |
| **Realm** | "Domain" Kerberos — biasanya ditulis huruf besar (`CORP.EXAMPLE.COM`) |
| **TGT** | Tiket bukti sudah login, dipakai untuk minta tiket-tiket lain berikutnya |
| **TGS** | Tiket spesifik untuk satu service, didapat dari TGT |

---

#### 11.12.2 `/etc/krb5.conf`

```ini
[libdefaults]
default_realm = CORP.EXAMPLE.COM

[realms]
CORP.EXAMPLE.COM = {
    kdc = kdc.corp.example.com
    admin_server = kdc.corp.example.com
}
```

> 📖 **Nilai forensik:** File ini mengonfirmasi realm mana yang **dipercaya** mesin ini dan **KDC mana** yang jadi otoritas — bandingkan dengan realm yang muncul di ticket cache (§11.14.1) untuk memastikan ticket yang ditemukan memang berasal dari sumber yang sah/diharapkan, bukan realm asing yang mencurigakan.

---

#### 11.12.3 Koreksi — Ticket Bukan Password ⚠️

⚠️ **Koreksi konseptual yang wajib dipahami sebelum menilai temuan:** Kerberos ticket (TGT maupun TGS) **TIDAK MENYIMPAN password** di dalamnya — ticket adalah **bukti otentikasi sementara** (punya masa berlaku, biasanya jam) yang **secara fundamental berbeda** dari kredensial statis seperti password atau private key.

| Aspek | Password/Private Key | Kerberos Ticket |
|---|---|---|
| Masa berlaku | Tidak terbatas sampai diganti manual | **Terbatas** (biasanya beberapa jam, renewable sampai batas tertentu) |
| Kalau dicuri | Attacker bisa pakai **selamanya** sampai kredensial diganti | Attacker cuma bisa pakai **selama ticket masih valid** — tapi tetap berbahaya selama window itu (§11.14.3) |
| Menyimpan password asli? | Ya (atau representasinya) | **TIDAK** — ticket adalah hasil kriptografi yang membuktikan autentikasi SUDAH terjadi, bukan menyimpan rahasia untuk autentikasi ULANG dari nol |

> 📌 **Kenapa koreksi ini penting untuk penilaian risiko temuan:** Menemukan file ticket cache (§11.14.1) yang "bocor"/dicuri **BUKAN** setara dengan menemukan password dalam bentuk plaintext — level risikonya berbeda (terbatas waktu, terbatas ke service yang sudah di-otorisasi ticket tsb) dibanding kebocoran password permanen. Namun tetap serius — selama ticket valid, itu **cukup** untuk impersonasi penuh tanpa perlu tahu password sama sekali (§11.14.3, pass-the-ticket).

---

### 11.13 Kerberos Authentication Artifacts & Logs

#### 11.13.1 TGT/TGS Acquisition sebagai Event

**Pengertian & Fungsi:**
Setiap kali user/service meminta TGT (§11.12.1 langkah 2) atau TGS (langkah 3), itu adalah **event yang bisa dicatat** — baik di sisi KDC (kalau bisa diakses, biasanya di luar cakupan single-host Linux forensics) maupun secara tidak langsung lewat perubahan ticket cache di sisi client (§11.14.1).

```bash
# Sisi CLIENT — cek kapan ticket cache TERAKHIR diperbarui (proxy untuk waktu TGT acquisition)
stat /tmp/krb5cc_$(id -u)
```

> 📖 **Batasan cakupan:** KDC log server-side (di luar scope Linux client forensics seri ini, kecuali mesin yang diperiksa **adalah** KDC itu sendiri) akan mencatat setiap TGT/TGS request secara eksplisit dengan timestamp presisi. Dari sisi **client** (fokus bab ini), bukti tidak langsung lewat `mtime` ticket cache adalah proxy yang tersedia.

---

#### 11.13.2 Log Sukses vs Gagal

```bash
# Percobaan Kerberos yang tercatat di auth.log (via PAM, pam_krb5/sssd)
grep -i "krb5\|kerberos" /var/log/auth.log

# SSSD log (§11.11.4) sering lebih detail untuk kegagalan spesifik Kerberos
grep -i "krb5_child\|authentication failure" /var/log/sssd/*.log
```

| Pola | Interpretasi |
|---|---|
| Sukses autentikasi Kerberos, langsung diikuti resolusi identitas SSSD (§11.11) | Login domain normal |
| **Banyak kegagalan Kerberos beruntun** untuk user yang sama | Indikasi brute force terhadap password domain — beda channel dari brute force SSH biasa (§11.2.1), tapi target akhirnya sama (kredensial domain) |
| Sukses autentikasi tapi **realm tidak dikenal** (bukan realm di `krb5.conf`) | Sangat mencurigakan — kemungkinan ticket dari realm asing dipaksakan masuk (relevan §11.14.3) |

---

#### 11.13.3 Identifikasi KDC/Realm dari Artefak Host

```bash
# Realm default yang dipercaya mesin ini
grep "default_realm" /etc/krb5.conf

# Realm YANG SEBENARNYA tercatat di ticket cache aktif — HARUS dibandingkan dengan di atas
klist | grep "Default principal"
```

> ⚠️ **Kenapa perbandingan ini wajib:** Kalau realm di ticket cache aktif (`klist`) **berbeda** dari `default_realm` yang dikonfigurasi di `krb5.conf`, itu situasi tidak wajar — bisa jadi indikasi ticket dari realm lain (misal hasil trust relationship yang sah, atau — lebih mencurigakan — hasil pass-the-ticket dari luar organisasi, §11.14.3).

---

#### 11.13.4 Korelasi Timestamp Ticket dengan SSH/Login

**Pengertian & Fungsi:**
Menyatukan §11.2-11.6 (SSH) dengan §11.12-11.13 (Kerberos) — untuk login yang memakai autentikasi Kerberos (`auth_provider = krb5` di SSSD, §11.11.2, sering dikombinasikan dengan GSSAPI di SSH), waktu perolehan ticket (§11.13.1) harus **konsisten** dengan waktu login SSH yang tercatat.

```bash
# Bandingkan waktu login SSH (§11.2) dengan waktu TGT valid (klist)
grep "Accepted" /var/log/auth.log | grep "<user>"
klist    # cek 'Valid starting' timestamp ticket
```

> 💡 **Nilai forensik korelasi ini:** Kalau timestamp `Valid starting` TGT **jauh lebih awal** dari waktu login SSH yang tercatat, itu indikasi ticket **sudah ada sebelumnya** (dibawa dari sesi lain, konsisten dengan pass-the-ticket §11.14.3) — bukan diperoleh fresh sebagai bagian dari proses login SSH itu sendiri. Sebaliknya, timestamp yang sangat berdekatan mengonfirmasi alur autentikasi normal.

---

### 11.14 Kerberos Ticket Cache & Keytab Forensics 🔴

#### 11.14.1 Ticket Cache — `/tmp/krb5cc_<uid>`

**Pengertian & Fungsi:**
Lokasi penyimpanan ticket **aktif** milik user saat ini — default-nya di `/tmp` (Bab 1 §1.2.6, area yang juga dibahas sebagai staging attacker), tapi bisa dikustomisasi lewat environment variable `KRB5CCNAME`.

```bash
# Baca isi ticket cache — tool standar 'klist'
klist
klist -e    # tampilkan juga tipe enkripsi tiap ticket

# Cek environment variable custom (kalau ada, ticket disimpan di lokasi non-default)
echo $KRB5CCNAME
```

```
Contoh output klist:
Ticket cache: FILE:/tmp/krb5cc_1001
Default principal: jdoe@CORP.EXAMPLE.COM

Valid starting       Expires              Service principal
08/17/2026 09:15:22  08/17/2026 19:15:22  krbtgt/CORP.EXAMPLE.COM@CORP.EXAMPLE.COM
08/17/2026 09:16:05  08/17/2026 19:15:22  nfs/fileserver.corp.example.com@CORP.EXAMPLE.COM
```

> 💡 **Kolom "Expires" sebagai window investigasi:** Ticket yang ditemukan di cache **hanya valid** dalam window waktu tertentu (§11.12.3) — kalau investigasi dilakukan **setelah** waktu Expires terlewati, ticket sudah tidak bisa dipakai ulang (walau tetap berharga sebagai **bukti historis** bahwa autentikasi pernah terjadi dalam window tsb).

---

#### 11.14.2 Keytab File

**Pengertian & Fungsi:**
Berbeda dari ticket (sementara, §11.12.3), **keytab** adalah file yang menyimpan **kredensial statis** (kunci kriptografi jangka panjang) untuk **service account** — dipakai supaya service (misal cron job, aplikasi otomatis) bisa autentikasi Kerberos **tanpa** interaksi password manual setiap kali.

```bash
# Lokasi umum
/etc/krb5.keytab
# atau custom path untuk service tertentu

# Baca isi keytab (menunjukkan principal & tipe enkripsi, TIDAK menunjukkan key mentah)
klist -k /etc/krb5.keytab
```

> ⚠️ **Kenapa keytab jauh lebih berbahaya dari ticket kalau dicuri:** Berbeda dari ticket yang expire dalam hitungan jam (§11.14.1), keytab adalah kredensial **jangka panjang/statis** — kalau dicuri, attacker mendapat kemampuan **generate ticket baru kapan saja tanpa batas waktu**, setara punya "password permanen" untuk principal tersebut. Ini adalah **persistent access** dalam artian penuh — analog password hash yang dicuri, bukan sesi sementara yang dicuri.

---

#### 11.14.3 Pass-the-Ticket dari Sisi Linux 🔴

**Pengertian & Fungsi:**
Pola serangan — ticket cache dicuri dari satu sesi/user, dipindahkan ke sesi lain lewat manipulasi `KRB5CCNAME`, lalu dipakai untuk **impersonasi tanpa perlu tahu password sama sekali**.

```bash
# Pola yang dicari (BUKAN tutorial serang, murni untuk pengenalan pola deteksi):
# Attacker menyalin file ticket cache dari sesi korban, lalu:
export KRB5CCNAME=/path/ke/ticket_curian
# Sesi attacker sekarang "menjadi" identitas di ticket tsb TANPA proses AS-REQ baru
```

**Pola deteksi (fokus investigasi, bukan tutorial):**

| Indikator | Detail |
|---|---|
| `klist` menunjukkan principal yang **tidak cocok** dengan user OS yang sedang login (`whoami`) | Ticket dipakai oleh sesi yang bukan "pemilik aslinya" |
| `KRB5CCNAME` menunjuk ke path **tidak standar** (bukan `/tmp/krb5cc_<uid>` default) | Indikasi ticket "dipindahkan" secara sengaja dari lokasi asal |
| §11.13.4 — timestamp `Valid starting` ticket jauh lebih awal dari aktivitas sesi saat ini | Ticket "dibawa" dari sesi/waktu lain |
| File ticket cache dengan **permission longgar** (bisa dibaca user lain) di `/tmp` | Kerentanan yang memungkinkan pencurian ticket terjadi (`/tmp` world-readable default, Bab 1 §1.2.6) |

```bash
# Cek permission ticket cache — SEHARUSNYA hanya readable oleh owner
ls -la /tmp/krb5cc_*
```

> ⚠️ **Kenapa ini relevan langsung ke §11.3 SSH lateral movement:** Pass-the-ticket sering jadi **mekanisme di balik** pergerakan lateral yang terlihat "mulus" tanpa jejak percobaan password gagal — attacker yang berhasil curi ticket dari Host A bisa langsung autentikasi Kerberos-based service (termasuk SSH dengan GSSAPI) di Host B **seolah-olah** mereka user asli, tanpa satu pun baris log kegagalan autentikasi.

---

#### 11.14.4 Kerberoasting — Sekilas

> 📌 **Cakupan dibatasi, konsisten dengan Bab 4 §4.3.5:** Kerberoasting (meminta TGS untuk akun service dengan tujuan **crack password offline** dari tiket yang didapat) disebut **sebatas konteks pengenalan** — detail teknik cracking-nya sendiri di luar cakupan seri ini, konsisten dengan prinsip yang sudah ditetapkan di Bab 4 §4.3.5 untuk topik cracking kredensial secara umum.

```bash
# Pola yang bisa diamati dari sisi Linux client/log — permintaan TGS untuk BANYAK
# service principal berbeda dalam waktu singkat (§11.13.1) adalah pola mencurigakan
klist    # kalau ditemukan BANYAK service ticket untuk service yang tidak biasa diakses user ini
```

> 💡 **Nilai forensik yang tetap relevan tanpa masuk ke cracking:** Meski detail cracking di luar cakupan, **pola permintaan TGS yang tidak wajar** (volume tinggi, ke banyak service berbeda, dari satu user dalam waktu singkat) tetap jadi indikator investigasi yang valid — sinyal bahwa TGS-TGS tersebut kemungkinan dikumpulkan untuk tujuan offline cracking, bukan dipakai untuk akses service yang wajar.

---

### 11.15 Service Account Forensics

#### 11.15.1 Service Account vs Human Account

**Pengertian & Fungsi:**
Membedakan akun yang **dipakai manusia** (login interaktif, mengetik command) vs akun yang **dipakai oleh service/aplikasi otomatis** (cron job, systemd service, aplikasi backend) — kesalahan atribusi antara keduanya bisa membuat laporan investigasi menyimpulkan hal yang keliru.

| Aspek | Human Account | Service Account |
|---|---|---|
| Login method | Password/publickey interaktif, sesi SSH normal (§11.2) | Keytab (§11.14.2), API key, atau tanpa login sama sekali (dijalankan via systemd `User=`, Bab 6 §6.4.1) |
| Pola waktu aktivitas | Jam kerja manusia, iregular | 24/7 konstan atau terjadwal presisi (cron/timer, Bab 6 §6.3-6.4.6) |
| Shell | Biasanya `/bin/bash` interaktif | Sering `/usr/sbin/nologin` atau `/bin/false` (Bab 4 §4.2.3) |
| Home directory | Berisi dotfile personal (`.bashrc`, `.ssh/`, browser profile Bab 5) | Sering kosong/minimal, cuma config aplikasi |

---

#### 11.15.2 Indikator Identifikasi

```bash
# Cek shell — indikator paling cepat
getent passwd | awk -F: '$7 !~ /nologin|false/ {print $1, $7}'    # kandidat human account
getent passwd | awk -F: '$7 ~ /nologin|false/ {print $1, $7}'      # kandidat service account

# Cek apakah akun punya keytab terkait (§11.14.2) — indikasi kuat service account
klist -k /etc/krb5.keytab 2>/dev/null | grep -v "^Keytab"

# Cek apakah akun dipakai untuk menjalankan systemd service (Bab 6 §6.4.1, field User=)
grep -r "^User=" /etc/systemd/system/*.service | grep "<nama_akun>"
```

> 📖 **Cross-reference:** Bab 4 §4.2.3 sudah menyinggung shell `nologin` sebagai indikator akun non-interaktif. Bagian ini memperluas jadi profil forensik lebih lengkap, dikombinasikan dengan artefak enterprise (keytab, systemd `User=`).

---

#### 11.15.3 Menghindari Salah Atribusi

⚠️ **Kesalahan investigasi yang harus dihindari secara eksplisit:** Menyimpulkan aktivitas dari service account sebagai **tindakan manusia** (atau sebaliknya) mengarah ke kesimpulan investigasi yang keliru — misal, aktivitas login rutin tiap jam dari akun backup service **BUKAN** indikasi "user X bekerja lembur tiap jam", melainkan job otomatis yang wajar.

```
Kesalahan umum:
"Akun svc_backup login 24 kali sehari, tiap jam, pola sangat konsisten —
 SANGAT MENCURIGAKAN, kemungkinan bot/automation attacker!"

Interpretasi yang benar SETELAH verifikasi §11.15.2:
1. Cek shell svc_backup → /usr/sbin/nologin (indikasi service account)
2. Cek keytab → svc_backup TERDAFTAR di /etc/krb5.keytab
3. Cek systemd → ada backup.timer (Bab 6 §6.4.6) yang menjalankan job SEBAGAI
   svc_backup tiap jam, SUDAH ADA sejak lama (bukan baru dipasang)
→ KESIMPULAN: Pola ini WAJAR — svc_backup memang service account untuk backup
   terjadwal, bukan indikasi kompromi
```

> 💡 **Prinsip umum:** SEBELUM menandai pola aktivitas akun manapun sebagai "mencurigakan", **selalu** jalankan checklist §11.15.2 dulu untuk klasifikasi human vs service — banyak "anomali" yang terlihat mengkhawatirkan di awal ternyata adalah operasi service account yang sepenuhnya normal begitu konteksnya dipahami.

---

### 11.16 Korelasi LDAP/Kerberos dengan Artefak Bab 4

| Pertanyaan | Jawaban ala Bab 4 (Lokal) | Jawaban Lengkap (Enterprise, Bab 11) |
|---|---|---|
| Siapa user ini? | `/etc/passwd` (Bab 4 §4.2) | `getent passwd` (§11.8.2) — gabungan lokal + SSSD cache (§11.11.3) |
| Kapan user ini terakhir login? | `last`/`wtmp` (Bab 4) | Sama, DITAMBAH korelasi waktu ticket Kerberos (§11.13.4) untuk konfirmasi metode auth |
| Apakah user ini beneran ada/sah? | Cek entry di `/etc/passwd` | Cek SSSD cache (§11.11.3) — user bisa jadi valid di domain walau TIDAK PERNAH ada di `/etc/passwd` lokal (§11.10.3) |
| Group apa yang dimiliki user ini? | `/etc/group` lokal | `id <user>` (§11.8.2) — menggabungkan group lokal + `memberOf` LDAP (§11.9.1) |
| Apakah user ini human atau service? | Cek shell di `/etc/passwd` (Bab 4 §4.2.3) | Sama, DITAMBAH cek keytab (§11.14.2) & systemd `User=` (§11.15.2) |

> 💡 **Prinsip yang berlaku sepanjang §11.16:** Setiap pertanyaan identitas yang di Bab 4 dijawab **cukup** dari satu file lokal (`/etc/passwd`), di lingkungan enterprise **selalu** butuh langkah tambahan — cek SSSD cache dan/atau ticket Kerberos untuk gambaran lengkap. Mengandalkan Bab 4 saja di lingkungan domain-joined akan memberi jawaban yang **tidak lengkap**, bukan salah, tapi berpotensi melewatkan identitas domain yang justru paling relevan untuk investigasi.

---

### 11.17 Enterprise DNS & Host Identity

#### 11.17.1 Hostname, FQDN & `/etc/hosts`

```bash
hostname          # hostname pendek
hostname -f        # FQDN (Fully Qualified Domain Name)
cat /etc/hosts       # static hostname-to-IP mapping
```

> 💡 **Nilai forensik `/etc/hosts`:** Entry **manual** yang ditambahkan ke `/etc/hosts` (di luar entry default `127.0.0.1 localhost`) bisa jadi indikasi attacker **menimpa** resolusi DNS untuk host tertentu (misal memaksa domain internal legitimate mengarah ke IP attacker sendiri untuk MITM) — cek `mtime` file ini (Prinsip Umum Bab 6 §6.2) untuk deteksi modifikasi tidak wajar.

---

#### 11.17.2 `/etc/resolv.conf` & DNS Resolution

```bash
cat /etc/resolv.conf
```

> ⚠️ **Nameserver yang tidak dikenal/di luar range internal organisasi** di `/etc/resolv.conf` adalah sinyal serupa dengan `/etc/hosts` yang dimodifikasi — attacker dengan akses root bisa mengarahkan **seluruh** resolusi DNS mesin ini ke server DNS mereka sendiri, membuka jalan untuk MITM yang jauh lebih luas dibanding modifikasi `/etc/hosts` per-entry.

---

#### 11.17.3 Korelasi IP ↔ Hostname ↔ Host Enterprise

**Pengertian & Fungsi:**
Menyatukan §11.17.1-11.17.2 dengan seluruh bagian SSH (§11.2-11.7) — log SSH umumnya mencatat **IP**, sementara `known_hosts`/dokumentasi organisasi sering merujuk **hostname**. Korelasi keduanya perlu eksplisit, terutama kalau DNS lokal (§11.17.1-11.17.2) sudah dicurigai dimanipulasi.

```bash
# Reverse lookup IP yang muncul di log SSH untuk dapat hostname (kalau DNS reliable)
host <IP_dari_auth.log>

# WASPADA: kalau DNS SUDAH dicurigai dimanipulasi (§11.17.2), reverse lookup live
# TIDAK BISA dipercaya — pakai dokumentasi IP-hostname statis organisasi sebagai
# ground truth alih-alih resolusi DNS live yang berpotensi sudah "diracuni"
```

> ⚠️ **Kenapa peringatan ini penting:** Kalau investigasi sudah menemukan indikasi DNS lokal dimanipulasi (§11.17.1-11.17.2), **jangan** percaya hasil resolusi DNS **dari mesin yang sama** untuk mengidentifikasi hop selanjutnya dalam rantai pivot (§11.3) — gunakan IP mentah sebagai identifier utama, dan cross-check hostname lewat sumber independen (dokumentasi CMDB organisasi, atau DNS server terpisah yang belum dicurigai).

---

### 11.18 Network Filesystem Forensics — NFS/SMB

#### 11.18.1 NFS — Konsep & Artefak

**Pengertian & Fungsi:**
NFS (Network File System) mengizinkan direktori di satu server di-mount dan diakses **seolah-olah** lokal dari mesin client — sangat umum di lingkungan enterprise Linux untuk shared storage, home directory terpusat, dst.

```bash
# Cek NFS mount yang aktif
mount | grep nfs
showmount -e <nfs_server>    # list export yang ditawarkan server tertentu
```

| Versi NFS | Karakteristik Forensik |
|---|---|
| NFSv3 | Autentikasi berbasis **UID/GID mentah** — tidak ada enkripsi/otentikasi kuat by default, rawan UID spoofing kalau client bisa mengklaim UID manapun |
| NFSv4 | Mendukung integrasi Kerberos (`sec=krb5`, cross-ref §11.12) untuk autentikasi lebih kuat |

---

#### 11.18.2 SMB/CIFS — Konsep & Artefak

**Pengertian & Fungsi:**
Protokol berasal dari dunia Windows, tapi umum juga di lingkungan Linux campuran (interop dengan Active Directory, storage terpusat berbasis Windows Server/NAS) lewat client `cifs-utils`.

```bash
# Cek SMB mount aktif
mount | grep cifs

# Cek kredensial yang dipakai untuk mount (WASPADA — kadang tersimpan plaintext)
cat /etc/fstab | grep cifs
# credentials=/path/ke/file  ← cek isi file ini, sering menyimpan username/password mount
```

> ⚠️ **Nilai forensik kredensial mount SMB:** File credentials untuk mount SMB (dirujuk lewat opsi `credentials=` di `/etc/fstab`, §11.18.3) **sering** menyimpan username/password **plaintext** — kalau ditemukan, ini adalah kredensial nyata yang valid dan berharga baik untuk investigasi maupun sebagai catatan celah keamanan operasional yang perlu dilaporkan.

---

#### 11.18.3 `/etc/fstab`, `/etc/exports` & `/proc/mounts`

| File | Fungsi | Sisi |
|---|---|---|
| `/etc/fstab` (Bab 1 §1.1.12, diperdalam di sini untuk konteks network) | Konfigurasi mount **otomatis** saat boot, termasuk NFS/SMB share | Client |
| `/etc/exports` | Daftar direktori yang **DIBAGIKAN** mesin ini ke client lain (kalau mesin ini adalah NFS **server**) | Server |
| `/proc/mounts` | State mount **live/aktual** saat ini — bisa berbeda dari `/etc/fstab` kalau ada mount manual (`mount` command langsung, tidak lewat fstab) | Live state |

```bash
cat /etc/fstab | grep -E "nfs|cifs"
cat /etc/exports 2>/dev/null    # kalau mesin ini NFS server
cat /proc/mounts | grep -E "nfs|cifs"
```

> 💡 **Kenapa bandingkan `fstab` vs `/proc/mounts`:** Discrepancy antara **apa yang dikonfigurasi** (`fstab`) dan **apa yang benar-benar ter-mount saat ini** (`/proc/mounts`) bisa mengindikasikan mount **ad-hoc** yang dibuat manual (mis. attacker mount share tambahan untuk eksfiltrasi data) — mount ini tidak akan bertahan setelah reboot (tidak ada di `fstab`), tapi aktif selama sesi berjalan.

---

#### 11.18.4 Remote Filesystem sebagai Jalur Akses/Data

> 💡 **Kenapa NFS/SMB relevan untuk lateral movement:** Direktori NFS/SMB yang di-mount di **banyak host sekaligus** (pola umum untuk home directory terpusat/shared storage) berarti file yang ditulis di satu host (misal payload) **langsung terlihat** dari semua host lain yang me-mount share yang sama — jalur pergerakan/eksekusi lintas host yang **sama sekali tidak melalui SSH** (§11.3-11.7). Kalau home directory user di-mount NFS dari server terpusat, `.bashrc` (Bab 4 §4.10, Bab 6 §6.6.1) yang dimodifikasi di **satu** titik otomatis mempengaruhi **setiap** host yang me-mount home directory tersebut — vektor persistence enterprise-scale yang jauh melampaui satu mesin.

---

### 11.19 Enumerasi Network Service Aktif

```bash
# Enumerasi lengkap service yang listen — dasar untuk banyak analisis di atas
ss -tulpn
netstat -tulpn    # alternatif kalau ss tidak tersedia
```

> 📖 **Cross-reference:** §11.5.2 sudah memakai command yang sama secara spesifik untuk deteksi SSH tunnel. Bagian ini adalah versi **umum** — enumerasi semua service listening apapun, tidak terbatas ke SSH. Silangkan dengan Bab 6 (persistence via service, khususnya §6.4.7 socket/path activation systemd) untuk investigasi kenapa satu port tertentu listening.

**Identifikasi service enterprise umum lain (sekilas) 🟡:**

| Service | Port Umum | Relevansi |
|---|---|---|
| NFS | 2049 | §11.18.1 |
| SMB/CIFS | 445 | §11.18.2 |
| LDAP | 389 (plaintext), 636 (LDAPS) | §11.9-11.10 |
| Kerberos | 88 | §11.12 |
| rsyslog forwarding | 514 (UDP/TCP) | §11.20 |

---

### 11.20 Centralized Logging & Log Forwarding Enterprise 🟡

**Pengertian & Fungsi:**
Konfigurasi `rsyslog`/`syslog-ng` untuk **meneruskan** log ke server terpusat, di luar mesin sumber log itu sendiri — relevansi forensik besar: **log lokal host bisa sudah dihapus attacker** (Bab 9 §9.10-9.11, secure deletion & log tampering), tapi salinan yang **sudah terkirim** ke server terpusat **sebelum** penghapusan tetap ada dan tidak terjangkau attacker yang cuma menguasai satu host.

```bash
# Cek konfigurasi forwarding rsyslog
grep -E "^\*\.\*|@@|@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null
# @server = UDP forwarding, @@server = TCP forwarding
```

> 💡 **Kenapa ini jadi salah satu langkah investigasi paling bernilai kalau tersedia:** Kalau ditemukan konfigurasi forwarding aktif **sebelum** insiden terjadi, **prioritaskan** meminta akses ke server log terpusat tsb — kemungkinan besar log yang sudah "dihilangkan" attacker dari host lokal (Bab 9 §9.11) masih **utuh** di sana, karena attacker yang cuma menguasai satu host **tidak bisa** menghapus salinan yang sudah dikirim ke luar jangkauannya.

> 📖 **Cross-reference:** Format log itu sendiri (syslog, journald) sudah dibahas penuh di Bab 3 — bagian ini murni fokus ke **topologi pengiriman**-nya, bukan mengulang format.

---

### 11.21 Membangun Timeline Lintas-Host untuk Lateral Movement 🔴

**Pengertian & Fungsi:**
Penerapan **langsung** metodologi Bab 9 §9.4 (inventarisasi sumber) dan §9.5 (normalisasi timestamp) — bedanya, sumbernya sekarang **tersebar di banyak mesin sekaligus**, bukan satu host.

```
Alur (extend Bab 9 §9.4-9.5 ke konteks multi-host):

[1] Inventarisasi sumber PER-HOST (Bab 9 §9.4), untuk SETIAP host yang terlibat
      │
      ▼
[2] TAMBAHAN KRITIS untuk multi-host: CEK CLOCK DRIFT ANTAR-HOST DULU
    (cross-ref Bab 9 §9.14 — clock drift DALAM satu sistem; di sini jadi jauh
    lebih kritis karena membandingkan timestamp ANTAR MESIN BERBEDA)
      │
      ▼
[3] Normalisasi timestamp SETIAP host ke UTC (Bab 9 §9.5), KOREKSI drift
    yang ditemukan di langkah 2 SEBELUM menggabungkan timeline
      │
      ▼
[4] Gabungkan semua sumber (SSH §11.3-11.7, Kerberos §11.13-11.14, log lokal
    Bab 3, cache SSSD §11.11.3) jadi satu timeline terurut
      │
      ▼
[5] Terapkan metodologi korelasi Bab 9 (evidence reliability, §9.2) ke
    timeline gabungan ini
```

**Cek clock drift SEBELUM menyusun urutan lintas-host:**

```bash
# Di TIAP host — bandingkan waktu sistem dengan referensi NTP yang sama
timedatectl status
chronyc tracking 2>/dev/null    # kalau pakai chrony
ntpq -p 2>/dev/null              # kalau pakai ntpd
```

> ⚠️ **Kenapa clock drift jauh lebih kritis di sini dibanding Bab 9 §9.14:** Bab 9 §9.14 membahas drift dalam **satu** sistem (jam sistem vs waktu sebenarnya). Di konteks lintas-host, **setiap** mesin punya potensi drift-nya **sendiri-sendiri** — kalau Host A drift +2 menit dan Host B drift -3 menit, urutan kejadian yang **sebenarnya** (Host A duluan, lalu Host B) bisa **terbalik** kalau timestamp mentah dibandingkan langsung tanpa koreksi. Kesalahan ini bisa membuat rekonstruksi rantai pivot (§11.3.4, timing correlation) memberi kesimpulan yang **terbalik** dari kenyataan — misal menyimpulkan "otomatis" padahal sebenarnya "manual" karena gap waktu yang salah dihitung akibat drift yang belum dikoreksi.

---

### 11.22 Tabel Korelasi — Pertanyaan Investigasi ke Artefak

| Pertanyaan | Artefak Utama | Bagian |
|---|---|---|
| Siapa yang login, dan bagaimana caranya? | `auth.log` (Accepted publickey/password), fingerprint key | §11.2.1, §11.3.3 |
| Apakah user ini domain atau lokal? | `getent passwd`, pola UID | §11.8.2-11.8.3 |
| User domain masih bisa dikonfirmasi walau server LDAP mati? | SSSD cache | §11.11.3 |
| Bagaimana attacker berpindah dari Host A ke Host C? | known_hosts + auth.log tiap hop, KONFIRMASI kedua sisi | §11.3.1-11.3.2 |
| Apakah pivot ini manual atau otomatis/worm? | Timing correlation antar-hop | §11.3.4 |
| Attacker pakai bastion — siapa asal sebenarnya? | Log BASTION, bukan log host tujuan | §11.4.1-11.4.2 |
| Apakah ada tunnel/C2 tersembunyi via SSH? | Listening port terikat proses ssh | §11.5.2 |
| Setelah masuk, apakah privilege naik ke root? | Korelasi TTY sudo → command berikutnya | §11.6.1-11.6.2 |
| Apakah ticket Kerberos dicuri & dipakai ulang (pass-the-ticket)? | `klist` principal vs `whoami`, KRB5CCNAME custom | §11.14.3 |
| Apakah aktivitas mencurigakan ini human atau service account? | Shell, keytab, systemd `User=` | §11.15.2 |
| Apakah DNS/hosts dimanipulasi untuk MITM? | mtime `/etc/hosts`/`resolv.conf` | §11.17.1-11.17.2 |
| Apakah ada jalur akses lintas-host TANPA SSH? | NFS/SMB mount bersama | §11.18.4 |
| Log lokal sudah dihapus — masih ada salinan? | Server log terpusat (rsyslog forwarding) | §11.20 |
| Urutan kejadian lintas-host — bisa dipercaya? | Cek clock drift SEBELUM susun timeline | §11.21 |

---

### 11.23 Ringkasan Command & Tools Cheat Sheet

```bash
# ===== SSH — LOG & FINGERPRINT =====
grep "Accepted" /var/log/auth.log
grep "Accepted publickey" /var/log/auth.log | grep -oP "SHA256:\S+"
grep -i "SSH-2.0" /var/log/auth.log

# ===== SSH — LATERAL MOVEMENT =====
grep "<hostname_atau_IP>" ~/.ssh/known_hosts
last -F | grep "<user>"
ls -la ~/.ssh/sockets/ 2>/dev/null    # ControlMaster

# ===== SSH — BASTION/PROXYJUMP =====
grep "@cert-authority" ~/.ssh/known_hosts
grep "TrustedUserCAKeys\|HostCertificate" /etc/ssh/sshd_config
grep "direct-tcpip\|forwarding" /var/log/auth.log

# ===== SSH — TUNNEL DETECTION =====
ss -tulpn | grep ssh
ps aux | grep -E "ssh.*-[LRD]"

# ===== PRIVILEGE ESCALATION =====
grep "sudo:" /var/log/auth.log
grep "TTY=pts/" /var/log/auth.log

# ===== IDENTITY RESOLUTION =====
getent passwd <username>
id <username>
getent passwd | awk -F: '{print $1, $3}' | sort -k2 -n

# ===== LDAP CLIENT CONFIG =====
cat /etc/nsswitch.conf | grep -E "^passwd|^group|^shadow"
cat /etc/ldap.conf /etc/openldap/ldap.conf 2>/dev/null

# ===== SSSD =====
cat /etc/sssd/sssd.conf
ls -la /var/lib/sss/db/
ldbsearch -H /var/lib/sss/db/cache_<domain>.ldb "(objectClass=user)"
cat /var/log/sssd/sssd_<domain>.log

# ===== KERBEROS =====
cat /etc/krb5.conf
klist
klist -e
klist -k /etc/krb5.keytab
echo $KRB5CCNAME
ls -la /tmp/krb5cc_*

# ===== SERVICE ACCOUNT IDENTIFICATION =====
getent passwd | awk -F: '$7 ~ /nologin|false/ {print $1, $7}'
grep -r "^User=" /etc/systemd/system/*.service

# ===== DNS/HOST IDENTITY =====
hostname -f
cat /etc/hosts
cat /etc/resolv.conf
host <IP>

# ===== NETWORK FILESYSTEM =====
mount | grep -E "nfs|cifs"
showmount -e <nfs_server>
cat /etc/fstab | grep -E "nfs|cifs"
cat /etc/exports 2>/dev/null
cat /proc/mounts | grep -E "nfs|cifs"

# ===== NETWORK SERVICE ENUMERATION =====
ss -tulpn
netstat -tulpn

# ===== LOG FORWARDING =====
grep -E "^\*\.\*|@@|@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null

# ===== CLOCK DRIFT (MULTI-HOST) =====
timedatectl status
chronyc tracking 2>/dev/null
ntpq -p 2>/dev/null
```

---

### 11.24 Mini Case Study — Workflow End-to-End

Skenario: akun domain (LDAP+Kerberos) `jdoe` dicurigai dikompromikan — dimulai dari Host A (workstation), berujung ke Host C (server aplikasi kritikal) tanpa satu pun kegagalan login tercatat.

```
Langkah 1 — Konfirmasi kompromi awal Host A (di luar detail Bab 11, lihat Bab 6-8)
   → Diketahui: workstation jdoe kena malware, ticket cache-nya jadi target

Langkah 2 — Cek ticket cache Host A untuk indikasi pencurian
   klist    (di Host A, kalau masih ada akses)
   ls -la /tmp/krb5cc_*
   → Ditemukan: permission /tmp/krb5cc_1001 LONGGAR (world-readable) — celah
     yang memungkinkan pencurian ticket (§11.14.3)

Langkah 3 — Cek Host B (ditemukan lewat SSSD cache / dokumentasi CMDB organisasi)
   untuk indikasi ticket jdoe dipakai di sana
   klist    (di Host B)
   → Principal: jdoe@CORP.EXAMPLE.COM, TAPI 'whoami' di sesi berbeda menunjukkan
     user OS lain yang mengeksport KRB5CCNAME custom — KONFIRMASI PASS-THE-TICKET
     (§11.14.3)

Langkah 4 — Korelasi timestamp (§11.13.4)
   → 'Valid starting' ticket di Host B JAUH LEBIH AWAL dari waktu aktivitas
     sesi di Host B — ticket "dibawa", bukan diperoleh fresh di situ

Langkah 5 — Cek auth.log Host B — TIDAK ADA baris 'Accepted' konvensional
   karena autentikasi lewat GSSAPI/Kerberos (§11.12), BUKAN password/pubkey biasa
   → Konsisten dengan §11.14.3 "tanpa jejak percobaan password gagal"

Langkah 6 — Dari Host B, cek known_hosts + auth.log untuk pivot lanjutan (§11.3.1-11.3.2)
   → Ditemukan: Host B → Host C (server aplikasi), KONFIRMASI kedua sisi
     (known_hosts Host B + auth.log Host C) — hop VALID

Langkah 7 — Cek privilege escalation di Host C (§11.6)
   grep "sudo:" /var/log/auth.log    (di Host C)
   → jdoe (via ticket curian) menjalankan sudo SEGERA setelah masuk, TTY yang sama
     dipakai untuk modifikasi unit systemd (Bab 6 §6.4.5, pola malicious service)

Langkah 8 — Verifikasi bukan false-positive service account (§11.15)
   → jdoe TERKONFIRMASI human account (shell /bin/bash, tidak ada keytab
     terdaftar untuk jdoe) — aktivitas ini BUKAN service account otomatis

Langkah 9 — Timeline lintas-host final (§11.21) — WAJIB cek clock drift dulu
   timedatectl status    (Host A, B, C)
   → Semua host ter-sync NTP dengan baik, drift < 1 detik — timeline bisa
     disusun langsung tanpa koreksi signifikan

Langkah 10 — Cek log terpusat (§11.20) untuk konfirmasi independen
   → rsyslog forwarding aktif dari ketiga host ke server log pusat SEBELUM
     insiden — log Host B/C yang mungkin coba dihapus attacker tetap
     terkonfirmasi di server pusat

KESIMPULAN:
Kompromi dimulai di Host A (workstation jdoe), ticket cache Kerberos dicuri
memanfaatkan permission file yang longgar di /tmp (§11.14.3, cross-ref Bab 1
§1.2.6). Ticket curian dipakai untuk pass-the-ticket ke Host B TANPA satu pun
jejak kegagalan password (menjelaskan kenapa investigasi awal berbasis
auth.log biasa tidak menemukan apapun mencurigakan). Dari Host B, attacker
pivot lagi ke Host C lewat SSH key lokal (rantai TERKONFIRMASI kedua sisi,
§11.3.1-11.3.2), lalu eskalasi privilege dan memasang persistence (Bab 6).
Seluruh rantai dikonfirmasi VALID lewat kombinasi: ticket cache forensics
(§11.14), rekonstruksi SSH (§11.3), privilege escalation (§11.6), dan
timeline lintas-host dengan clock drift sudah diverifikasi (§11.21) — dengan
log terpusat (§11.20) sebagai jaring pengaman independen dari kemungkinan
tampering log lokal.
```

> 💡 **Pelajaran utama studi kasus ini:** Kompromi berbasis Kerberos (pass-the-ticket) secara sengaja **tidak meninggalkan** jejak kegagalan autentikasi konvensional yang biasa jadi andalan investigasi SSH sederhana (§11.2.1) — investigator yang cuma mengandalkan pola "cari banyak `Failed password`" akan **sama sekali melewatkan** rantai kompromi jenis ini. Kombinasi pemahaman identity enterprise (§11.8-11.16) dan metodologi SSH lateral movement (§11.2-11.7) yang diterapkan **bersamaan**, bukan terpisah, adalah kunci merekonstruksi insiden semacam ini secara lengkap.
