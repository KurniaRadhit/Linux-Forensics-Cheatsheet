## 📌 Daftar Isi — Bab 5

- [Bab 5 — Browser Forensics: Linux](#bab-5--browser-forensics-linux)
  - [5.1 Overview & Posisi Bab 5](#51-overview--posisi-bab-5)
  - [5.2 Struktur Umum Profil Browser di Linux](#52-struktur-umum-profil-browser-di-linux)
  - [5.3 Profile Discovery & Enumeration 🔴](#53-profile-discovery--enumeration-)
    - [5.3.1 XDG Environment & Custom Profile Discovery 🔴](#531-xdg-environment--custom-profile-discovery-)
    - [5.3.2 Browser/Profile Enumeration Workflow 🔴](#532-browserprofile-enumeration-workflow-)
  - [5.4 Browser Artifact Acquisition 🔴](#54-browser-artifact-acquisition-)
    - [5.4.1 Live vs Dead Acquisition](#541-live-vs-dead-acquisition)
    - [5.4.2 SQLite Locking & WAL Acquisition Considerations 🔴](#542-sqlite-locking--wal-acquisition-considerations-)
    - [5.4.3 Hot Copy Risk & Cara Aman Mengambil Database Browser](#543-hot-copy-risk--cara-aman-mengambil-database-browser)
    - [5.4.4 Artifact Integrity / SQLite Consistency Check 🟡](#544-artifact-integrity--sqlite-consistency-check-)
  - [5.5 Chromium `Local State` 🔴](#55-chromium-local-state-)
  - [5.6 Chromium-based — File & Database Inventory](#56-chromium-based--file--database-inventory)
  - [5.7 Firefox — File & Database Inventory](#57-firefox--file--database-inventory)
  - [5.8 Browser Timestamp Normalization 🟡](#58-browser-timestamp-normalization-)
  - [5.9 Perbandingan Skema Chromium vs Firefox 🟡](#59-perbandingan-skema-chromium-vs-firefox-)
  - [5.10 Encryption & Credential Protection 🔴](#510-encryption--credential-protection-)
  - [5.11 Sandbox & Containerization — Snap, Flatpak, AppImage 🔴](#511-sandbox--containerization--snap-flatpak-appimage-)
  - [5.12 Root vs Per-User & Multi-user System 🟡](#512-root-vs-per-user--multi-user-system-)
  - [5.13 Download History & Filesystem Correlation](#513-download-history--filesystem-correlation)
  - [5.14 Cache Forensics 🟡](#514-cache-forensics-)
  - [5.15 Chromium Network-related Artifacts 🟡](#515-chromium-network-related-artifacts-)
  - [5.16 Deleted Browser Artifacts / SQLite Recovery 🔴](#516-deleted-browser-artifacts--sqlite-recovery-)
  - [5.17 Browser Process & Live Memory Considerations 🟡](#517-browser-process--live-memory-considerations-)
  - [5.18 Incognito / Private / Guest Artifacts 🔴](#518-incognito--private--guest-artifacts-)
  - [5.19 Browser Sync 🟡](#519-browser-sync-)
  - [5.20 Extensions & Add-ons sebagai Attack Vector (+ Policy Artifacts)](#520-extensions--add-ons-sebagai-attack-vector--policy-artifacts)
  - [5.21 Timeline Correlation — Browser vs Artefak Lain](#521-timeline-correlation--browser-vs-artefak-lain)
  - [5.22 Tabel Korelasi — Pertanyaan Investigasi ke Artefak](#522-tabel-korelasi--pertanyaan-investigasi-ke-artefak)
  - [5.23 Ringkasan Command & Tools Cheat Sheet](#523-ringkasan-command--tools-cheat-sheet)
  - [5.24 Mini Case Study — Workflow End-to-End](#524-mini-case-study--workflow-end-to-end)

---

## Bab 5 — Browser Forensics: Linux

> 💡 **Posisi Bab 5 di seri Linux Forensics:** Struktur inti database browser (SQLite: table, row, WAL journaling, mekanisme recovery baris terhapus) **konsepnya identik** di semua platform — sudah/akan dibahas detail di bab Browser Forensics umum, tidak diulang byte-level di sini. Fokus Bab 5 murni pada hal-hal yang beda secara nyata di Linux: (1) path/lokasi profil yang mengikuti FHS & XDG (Bab 1 §1.2.4, Bab 4 §4.15), (2) lapisan **sandbox/containerization** (Snap/Flatpak/AppImage) yang sama sekali tidak ada padanannya di Windows, dan (3) skema **enkripsi kredensial** yang fundamentally berbeda karena Linux tidak punya DPAPI.

> 📖 **Kalau kamu sudah familiar seri Windows — dengan catatan penting:** Nama file database (`History`, `Cookies`, `Login Data`, `places.sqlite`, dst) **umumnya sama** lintas platform, dan sebagian besar parser bisa dipakai lintas OS. Tapi **jangan disamaratakan mutlak**: skema kolom bisa **berbeda antar versi** browser yang sama (Chrome menambah/mengganti kolom di `urls`/`visits` seiring rilis), dan bahkan antar fork Chromium (Brave, Edge, Opera) ada kolom tambahan spesifik vendor yang tidak ada di Chromium vanilla. Sebelum menjalankan query, **selalu cek skema aktual** file yang sedang diperiksa (`PRAGMA table_info(<table>)`), jangan asumsikan otomatis identik dengan versi/vendor yang parser-nya dipakai.

> ⚠️ **Prinsip dasar yang berlaku di seluruh bab ini — "artifact ≠ event":** Keberadaan sebuah baris/entry di artefak browser **tidak otomatis** berarti event yang direpresentasikannya benar-benar terjadi/selesai sebagaimana adanya. Beberapa contoh yang akan berulang muncul di bab ini: entry di `-wal` (§5.4.2) bisa jadi transaksi yang **belum ter-commit** atau bahkan sempat di-*rollback*; entry `downloads` (§5.13) bisa jadi proses unduhan yang **gagal/terputus** di tengah jalan, bukan file lengkap; entry di `TransportSecurity` (§5.15) cuma bukti host itu "pernah ditemui" lewat request HTTPS, bukan bukti transaksi lengkap terjadi di sana. Prinsip ini setara dengan koreksi `known_hosts` di Bab 4 §4.13.4 — investigator selalu perlu bertanya "artefak ini benar-benar bukti event terjadi, atau cuma bukti *ada usaha ke arah itu*?" sebelum menyimpulkan sesuatu sebagai fakta pasti.

---

### 5.2 Struktur Umum Profil Browser di Linux

#### 5.2.1 Chromium-family

**Pengertian & Fungsi:**
Browser berbasis Chromium (Google Chrome, Chromium open-source, Brave, Microsoft Edge Linux, Opera) menyimpan profil di `~/.config/<vendor>/`, mengikuti konvensi XDG Base Directory — bukan di `~/.local/share/` seperti sebagian aplikasi Linux lain. Ini adalah lokasi **default**; lokasi sebenarnya bisa dikustomisasi, dibahas §5.3.1.

| Browser | Path Profil (default) |
|---|---|
| Google Chrome | `~/.config/google-chrome/` |
| Chromium (open-source) | `~/.config/chromium/` |
| Brave | `~/.config/BraveSoftware/Brave-Browser/` |
| Microsoft Edge | `~/.config/microsoft-edge/` |
| Opera | `~/.config/opera/` |

```bash
ls -la ~/.config/google-chrome/
```

#### 5.2.2 Firefox-family

Firefox menyimpan profil di `~/.mozilla/firefox/<hash>.<nama-profile>/` — nama folder profil punya prefix hash acak (mis. `a1b2c3d4.default-release`), **bukan** nama tetap. `profiles.ini` di `~/.mozilla/firefox/` adalah peta yang menunjukkan profil mana yang aktif/default — **wajib dibaca duluan** sebelum masuk ke folder profil, karena satu instalasi Firefox bisa punya lebih dari satu profil terdaftar dan tidak semuanya "default".

```bash
cat ~/.mozilla/firefox/profiles.ini
```

#### 5.2.3 Multi-profile

- **Chromium:** multi-profile direpresentasikan sebagai subfolder `Default/`, `Profile 1/`, `Profile 2/`, dst di dalam path §5.2.1 — masing-masing folder adalah profil independen lengkap dengan database sendiri-sendiri.
- **Firefox:** multi-profile direpresentasikan sebagai multiple entry blok `[ProfileN]` di `profiles.ini`, masing-masing menunjuk ke folder `<hash>.<nama>` terpisah di §5.2.2.

> ⚠️ Investigator yang cuma cek satu folder profil (mis. `Default/` atau profil `default-release` saja) berisiko melewatkan aktivitas yang tersimpan di profil sekunder — selalu enumerasi **semua** profil yang terdaftar (workflow lengkap di §5.3.2) sebelum menyimpulkan cakupan investigasi selesai.

#### 5.2.4 Tabel Path Quick-Reference

| Browser | Path Config (profil & database) | Path Cache Terpisah |
|---|---|---|
| Google Chrome | `~/.config/google-chrome/<Profile>/` | `~/.cache/google-chrome/<Profile>/` |
| Chromium | `~/.config/chromium/<Profile>/` | `~/.cache/chromium/<Profile>/` |
| Brave | `~/.config/BraveSoftware/Brave-Browser/<Profile>/` | `~/.cache/BraveSoftware/Brave-Browser/<Profile>/` |
| Firefox | `~/.mozilla/firefox/<hash>.<profile>/` | (cache umumnya menyatu di dalam folder profil, `cache2/`, §5.14) |

> 📌 Tabel ini adalah baseline **default** — tapi default bisa dioverride. Sebelum menyimpulkan "path ini tidak ada, berarti browser tidak dipakai", ikuti dulu §5.3 secara penuh.

---

### 5.3 Profile Discovery & Enumeration 🔴

#### 5.3.1 XDG Environment & Custom Profile Discovery 🔴

**Pengertian & Fungsi:**
Path default di §5.2 mengasumsikan environment variable XDG standar dan `$HOME` normal — asumsi ini **bisa salah** dalam beberapa kondisi umum yang sering muncul di investigasi nyata, terutama di server/lingkungan otomasi.

| Sumber Override | Efek |
|---|---|
| `$XDG_CONFIG_HOME` di-set custom (bukan default `~/.config`) | Seluruh path profil Chromium-family di §5.2.1 bergeser mengikuti nilai variabel ini |
| `$HOME` di-override saat proses dijalankan (mis. lewat service/systemd unit dengan `Environment=HOME=/opt/custom`, atau container) | Baik Chromium maupun Firefox mengikuti `$HOME` yang di-override tersebut, bukan home directory akun di `/etc/passwd` |
| Flag `--user-data-dir=<path>` saat Chromium dijalankan | Override eksplisit lokasi profil, sering dipakai di skenario automation/testing (headless Chrome, Selenium/Puppeteer) — profil bisa berada di lokasi arbitrer sama sekali, termasuk `/tmp` atau `/opt` |
| Firefox `-profile <path>` / `MOZ_LEGACY_PROFILES` | Override serupa untuk Firefox, umum dipakai skrip automation |

```bash
# Cek env XDG & HOME untuk proses browser yang sedang berjalan (live system)
cat /proc/<PID>/environ | tr '\0' '\n' | grep -E "^HOME=|^XDG_CONFIG_HOME="

# Cek full command line proses browser untuk flag override eksplisit
cat /proc/<PID>/cmdline | tr '\0' ' '
```

> ⚠️ **Kenapa ini masuk kategori WAJIB:** Di server/lingkungan otomasi (skenario yang justru sering relevan untuk investigasi kompromi, cross-ref §5.24), asumsi "profil selalu ada di `~/.config/`" sering **keliru total** — browser headless yang dipakai untuk automation/scraping/testing kerap dijalankan dengan `--user-data-dir` custom, kadang sengaja di lokasi tersembunyi. Kalau investigator berhenti di path default dan menyimpulkan "tidak ada profil ditemukan", padahal profilnya ada di `/tmp/.chrome-profile-xyz/` misalnya, seluruh rantai bukti berikutnya (§5.6 dst) tidak akan pernah ditemukan.

#### 5.3.2 Browser/Profile Enumeration Workflow 🔴

**Pengertian & Fungsi:**
Menggabungkan §5.2 (path default), §5.3.1 (override), §5.11 (sandbox), dan §5.12 (root vs per-user) jadi satu **prosedur enumerasi** yang harus dijalankan lengkap di setiap investigasi — bukan opsional, karena melewatkan satu langkah saja bisa berarti seluruh profil browser luput dari analisis.

| Langkah | Tindakan | Cross-ref |
|---|---|---|
| 1 | Enumerasi semua akun user di sistem (jangan cuma yang punya folder `/home` — termasuk cek orphaned home) | Bab 4 §4.2, §4.8 |
| 2 | Untuk tiap akun (termasuk `root`), cek path native default (§5.2.1, §5.2.2) | §5.2, §5.12 |
| 3 | Untuk tiap akun, cek path Snap (`~/snap/`) dan Flatpak (`~/.var/app/`) | §5.11 |
| 4 | Cari instalasi AppImage di seluruh sistem (`find / -iname "*.AppImage"`) | §5.11 |
| 5 | Kalau sistem masih live, cek proses browser aktif dan environment/cmdline-nya untuk path custom (§5.3.1) | §5.3.1, §5.17 |
| 6 | Untuk tiap profil yang ditemukan, baca `profiles.ini`/`Local State` untuk enumerasi **sub-profil** yang mungkin belum ketahuan dari nama folder saja | §5.2.3, §5.5 |
| 7 | Susun inventaris lengkap (path, browser, jenis instalasi, akun pemilik) sebelum mulai analisis isi database | — |

```bash
# Contoh sapuan cepat langkah 2-4 untuk satu user
USER_HOME=/home/alice
find "$USER_HOME/.config" "$USER_HOME/.mozilla" "$USER_HOME/snap" "$USER_HOME/.var/app" \
     -maxdepth 3 -iname "*chrome*" -o -iname "*chromium*" -o -iname "*firefox*" \
     -o -iname "*brave*" -o -iname "*.default*" 2>/dev/null
```

> 💡 Hasil dari workflow ini idealnya dicatat sebagai **inventaris** terpisah (tabel path + browser + akun) sebelum lanjut ke §5.4 — supaya proses akuisisi berikutnya punya daftar lengkap target, bukan ditemukan satu-satu secara ad-hoc di tengah analisis.

---

### 5.4 Browser Artifact Acquisition 🔴

#### 5.4.1 Live vs Dead Acquisition

**Pengertian & Fungsi:**
Cara mengambil artefak browser **berbeda konsekuensinya** tergantung apakah browser sedang berjalan (live) atau sistem sudah dimatikan/di-image (dead).

| Kondisi | Risiko | Pendekatan Aman |
|---|---|---|
| **Dead acquisition** (dari disk image, browser tidak berjalan) | Rendah — file dalam kondisi "diam", state konsisten | Copy langsung dari mount point read-only |
| **Live acquisition** (browser sedang berjalan saat pengambilan) | Tinggi — database bisa dalam kondisi sebagian ter-`lock`, transaksi belum di-*commit* penuh ke file utama (§5.4.2) | Ikuti prosedur §5.4.2–5.4.3 |

#### 5.4.2 SQLite Locking & WAL Acquisition Considerations 🔴

**Pengertian & Fungsi:**
Semua database browser (Chromium maupun Firefox) memakai SQLite dalam mode **WAL (Write-Ahead Logging)** secara default modern. Dalam mode ini, perubahan data **tidak langsung** ditulis ke file database utama (mis. `History`) — perubahan ditulis dulu ke file companion `-wal`, baru nanti di-*checkpoint* (digabungkan) ke file utama secara berkala.

```
History          ← file database utama
History-wal      ← write-ahead log, berisi perubahan terbaru yang BELUM di-checkpoint
History-shm      ← shared-memory index untuk koordinasi WAL antar-proses
```

> ⚠️ **Implikasi langsung ke akuisisi:** Kalau investigator **hanya** menyalin file utama (`History`) tanpa ikut menyalin `History-wal` dan `History-shm` yang menyertainya, data yang paling **baru** bisa **hilang** dari hasil analisis. Prinsip mekanisme WAL secara umum mengikuti konsep SQLite generik yang sudah dibahas di bab lain — poin di sini murni soal **konsekuensi akuisisi**: ketiga file harus **selalu diperlakukan sebagai satu paket**.
>
> ⚠️ **Ingat prinsip artifact ≠ event (§5.1):** Baris di dalam `-wal` yang belum ter-checkpoint tidak otomatis berarti "transaksi ini pasti selesai" — bisa jadi transaksi yang sedang berjalan lalu proses browser mati sebelum sempat commit sepenuhnya. Perlakukan baris dari `-wal` sebagai data yang **butuh konfirmasi tambahan**, bukan otomatis dianggap final.

```bash
cp "History" "History-wal" "History-shm" /path/tujuan/ 2>/dev/null
```

#### 5.4.3 Hot Copy Risk & Cara Aman Mengambil Database Browser

**Pengertian & Fungsi:**
Menyalin file database yang sedang aktif ditulis proses lain (`cp` biasa saat browser masih berjalan) berisiko mengambil snapshot dalam kondisi **inkonsisten**.

| Pendekatan | Aman untuk Live Acquisition? | Catatan |
|---|---|---|
| `cp` biasa saat browser masih jalan | ⚠️ Berisiko | Bisa dapat snapshot setengah-tertulis |
| Hentikan proses browser dulu, baru `cp` | Lebih aman, tapi mengubah kondisi sistem live | Cocok kalau mematikan browser bukan masalah investigatif |
| `sqlite3 <db> ".backup <tujuan>"` | ✅ Aman, dirancang khusus untuk snapshot konsisten meski database sedang dipakai proses lain | Pendekatan yang direkomendasikan |

```bash
sqlite3 "History" ".backup '/path/tujuan/History_backup.sqlite'"
```

#### 5.4.4 Artifact Integrity / SQLite Consistency Check 🟡

**Pengertian & Fungsi:**
Setelah file berhasil diakuisisi (§5.4.3), langkah yang sering terlewat adalah **memverifikasi** file hasil salinan benar-benar valid sebelum dianalisis lebih jauh — terutama kalau akuisisi dilakukan lewat metode yang lebih berisiko (hot copy, media rusak, transfer via jaringan tidak stabil).

```bash
# Cek integritas struktural file SQLite hasil akuisisi
sqlite3 History_backup.sqlite "PRAGMA integrity_check;"

# Verifikasi hash file untuk chain of custody
sha256sum History_backup.sqlite
```

> 💡 **Kenapa penting:** `PRAGMA integrity_check` mendeteksi korupsi struktural (page rusak, index tidak konsisten) yang bisa terjadi akibat hot copy yang gagal (§5.4.3) atau media penyimpanan bermasalah. Kalau hasilnya bukan `ok`, hasil query terhadap file tersebut **tidak boleh** dianggap representasi lengkap dari data asli — sebagian baris bisa jadi tidak terbaca sama sekali tanpa error yang jelas, bukan cuma soal "file tidak bisa dibuka".

---

### 5.5 Chromium `Local State` 🔴

**Pengertian & Fungsi:**
`Local State` adalah file JSON di **level atas** folder config Chromium (mis. `~/.config/google-chrome/Local State`) — **di luar** folder profil individual (`Default/`, `Profile 1/`, dst), karena isinya adalah setting yang berlaku **sistem-wide untuk seluruh instalasi**, bukan per-profil.

**Isi kunci yang relevan forensik:**

| Field | Fungsi |
|---|---|
| `os_crypt.encrypted_key` | **Encryption key** (dalam bentuk terenkripsi lagi oleh keyring OS) yang dipakai untuk decrypt value di `Login Data`/`Cookies` semua profil — prasyarat mutlak untuk §5.10 |
| `profile.info_cache` | Daftar semua profil yang pernah dibuat di instalasi ini, termasuk yang sudah tidak dipakai lagi — berguna untuk cross-check kelengkapan enumerasi profil di §5.3.2 |
| `variations_*` | Info A/B testing/feature flag Chrome — jarang relevan forensik langsung |

```bash
cat ~/.config/google-chrome/"Local State" | python3 -m json.tool | grep -A2 "encrypted_key"
```

> 🔗 **Kenapa ditaruh sebelum inventaris §5.6:** Tanpa `Local State`, value terenkripsi di `Login Data` (§5.6.3) dan `Cookies` (§5.6.2) **tidak bisa** didekripsi sama sekali — file ini adalah prasyarat konseptual. Detail proses dekripsinya dibahas penuh di §5.10.

---

### 5.6 Chromium-based — File & Database Inventory

#### 5.6.1 `History`

Database SQLite utama, table kunci: `urls` (daftar URL beserta judul, jumlah kunjungan `visit_count`, waktu kunjungan terakhir), `visits` (histori tiap kunjungan individual dengan transisi navigasi), `visit_source` (sumber kunjungan — sync, lokal, dsb).

> 📌 Nama kolom persis di atas berlaku untuk skema Chromium yang umum ditemui — **selalu verifikasi** dengan `PRAGMA table_info(urls);` pada file yang sedang diperiksa (lihat koreksi §5.1), karena kolom bisa bertambah/berubah di rilis berbeda atau fork vendor tertentu.

#### 5.6.2 `Cookies`

SQLite, kolom `encrypted_value` menyimpan cookie value dalam bentuk terenkripsi — proses dekripsinya dibahas §5.10.

#### 5.6.3 `Login Data`

SQLite, table `logins` menyimpan URL form, username, dan `password_value` terenkripsi — dekripsi §5.10.

#### 5.6.4 `Web Data`

Menyimpan autofill (data form yang pernah diisi), form history, dan kartu kredit tersimpan.

#### 5.6.5 `Bookmarks` ⚠️

> ⚠️ **Koreksi eksplisit:** Berbeda dari kebanyakan artefak Chromium lain yang berbasis SQLite, `Bookmarks` adalah **flat file JSON biasa** — perlakuan parsing-nya beda total (langsung `json.load`, bukan query SQL).

```bash
cat "Bookmarks" | python3 -m json.tool | head -50
```

#### 5.6.6 `Preferences` / `Secure Preferences`

File JSON berisi setting per-profil: default search engine, startup pages, extension terpasang beserta permission-nya (relevan §5.20), dan berbagai flag konfigurasi lain.

#### 5.6.7 Struktur Folder Extensions

```
Default/Extensions/<extension_id>/<version>/
```

#### 5.6.8 `Current Session`/`Current Tabs`, `Last Session`/`Last Tabs` 🔴

**Pengertian & Fungsi:**
File-file ini menyimpan state tab/window untuk fitur "restore session" — formatnya **SNSS** (Session/Snapshot format proprietary Chromium), bukan plain text atau JSON biasa.

| File | Isi |
|---|---|
| `Current Session`/`Current Tabs` | State sesi yang **sedang berjalan** saat file terakhir ditulis |
| `Last Session`/`Last Tabs` | State sesi **sebelumnya**, disimpan saat browser ditutup normal terakhir kali |

> 💡 **Nilai forensik:** File ini bisa mengungkap tab yang **sempat terbuka** tapi **belum sempat** tercatat di `History`.

---

### 5.7 Firefox — File & Database Inventory

#### 5.7.1 `places.sqlite` ⚠️

> ⚠️ **Koreksi struktur beda dari Chromium:** Firefox menggabungkan **history DAN bookmark** dalam satu database yang sama (`places.sqlite`, table `moz_places` untuk history, `moz_bookmarks` untuk bookmark) — berbeda dari Chromium yang memisahkan keduanya jadi dua file terpisah.

#### 5.7.2 `cookies.sqlite`

Setara `Cookies` Chromium — table `moz_cookies`.

#### 5.7.3 `formhistory.sqlite`

Riwayat data form yang pernah diisi.

#### 5.7.4 `key4.db` + `logins.json`

`key4.db` (juga format SQLite, tapi fungsinya sebagai **key store** NSS) menyimpan key enkripsi. `logins.json` menyimpan kredensial dalam format JSON, di-dekripsi memakai key dari `key4.db` — detail §5.10.4.

#### 5.7.5 `sessionstore.jsonlz4` 🔴

**Pengertian & Fungsi:**
Setara fungsi §5.6.8 di Chromium, tapi formatnya **LZ4-compressed JSON** — perlu tool decompress khusus.

```bash
python3 -m mozlz4 sessionstore.jsonlz4 sessionstore_decompressed.json
```

#### 5.7.6 `cache2/` Overview Singkat

Dibahas lebih dalam di §5.14.

#### 5.7.7 `extensions.json`

Daftar add-on/extension terinstal — relevan §5.20.

#### 5.7.8 Profile Metadata — `profiles.ini` & `compatibility.ini` 🟡

**Pengertian & Fungsi:**
Selain `profiles.ini` (§5.2.2), tiap folder profil individual juga punya `compatibility.ini` — berisi metadata versi Firefox dan path instalasi terakhir yang memakai profil tersebut, plus timestamp `LastVersion`.

```
[Compatibility]
LastVersion=115.0_20230101000000/20230615120000
LastOSABI=Linux_x86_64-gcc3
LastPlatformDir=/usr/lib/firefox
LastAppDir=/usr/lib/firefox/browser
```

> 💡 **Nilai forensik:** Bisa memberi petunjuk **kapan terakhir kali** profil ini dibuka dan **dari path instalasi mana** — berguna kalau ada dugaan profil dipindahkan/disalin dari sistem lain.

---

### 5.8 Browser Timestamp Normalization 🟡

**Pengertian & Fungsi:**
Chromium dan Firefox memakai **epoch dan satuan yang berbeda** untuk timestamp — kalau tidak dikonversi dengan benar, tanggal yang muncul bisa salah total (biasanya meleset puluhan tahun, gejala paling mudah dikenali kalau terjadi kesalahan).

| Browser | Basis Epoch | Satuan | Formula Konversi ke Unix Epoch |
|---|---|---|---|
| Chromium (WebKit/Chrome timestamp) | 1 Januari **1601** | Mikrodetik | `unix_epoch = (chrome_time / 1000000) - 11644473600` |
| Firefox (PRTime) | 1 Januari **1970** (sama dengan Unix) | Mikrodetik (bukan detik!) | `unix_epoch = firefox_time / 1000000` |

```bash
# Konversi timestamp Chromium (contoh nilai kolom last_visit_time)
python3 -c "print((13350000000000000/1000000)-11644473600)"

# Query langsung dengan konversi built-in SQLite
sqlite3 History "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url FROM urls LIMIT 5;"

# Firefox places.sqlite (moz_historyvisits.visit_date, sudah mikrodetik sejak 1970)
sqlite3 places.sqlite "SELECT datetime(visit_date/1000000,'unixepoch'), url FROM moz_places, moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id LIMIT 5;"
```

> ⚠️ **Kesalahan umum:** Menerapkan formula konversi Chromium ke database Firefox (atau sebaliknya) menghasilkan tanggal yang **tampak valid** tapi sepenuhnya salah (bisa meleset ke tahun 1600-an atau ribuan tahun ke depan) — investigator perlu selalu tahu **browser mana** sumber file sebelum mengonversi timestamp, jangan mengandalkan satu formula universal untuk semua database.

---

### 5.9 Perbandingan Skema Chromium vs Firefox 🟡

| Fungsi | Chromium | Firefox |
|---|---|---|
| History | `History` (table `urls`, `visits`) | `places.sqlite` (table `moz_places`) — **digabung dengan bookmark**, §5.7.1 |
| Bookmark | `Bookmarks` (JSON, bukan SQLite!) | `places.sqlite` (table `moz_bookmarks`) |
| Cookies | `Cookies` | `cookies.sqlite` |
| Password/Login | `Login Data` + key dari `Local State` | `logins.json` + key dari `key4.db` |
| Form/Autofill | `Web Data` | `formhistory.sqlite` |
| Session recovery | `Current Session`/`Last Session` (SNSS) | `sessionstore.jsonlz4` (LZ4 JSON) |
| Extension metadata | Folder `Extensions/<id>/` + `Preferences` | `extensions.json` |
| Epoch timestamp | 1601, mikrodetik | 1970, mikrodetik |

> 📌 File companion `-wal`/`-shm` (§5.4.2) berlaku sama untuk **semua** database SQLite di tabel ini — teknik akuisisinya identik, tidak diulang per-baris. Sebaliknya, **jangan** menganggap kolom di dalam table-nya identik lintas baris tabel ini — ini murni peta "fungsi setara", bukan jaminan skema sama (§5.1).

---

### 5.10 Encryption & Credential Protection 🔴

#### 5.10.1 Kenapa Beda dari Windows

Windows punya **DPAPI** — mekanisme enkripsi terintegrasi OS yang seragam di semua browser. Linux **tidak punya** padanan tunggal yang seragam — setiap browser mengimplementasikan skemanya sendiri, bergantung pada backend keyring yang terpasang/terdeteksi.

#### 5.10.2 Dua Backend Keyring Utama

| Backend | Desktop Environment Terkait |
|---|---|
| `gnome-keyring` / `libsecret` | GNOME dan kebanyakan distro turunan (default paling umum) |
| `kwallet` | KDE Plasma |

#### 5.10.3 Chromium — Mode Enkripsi Tergantung Backend Runtime

| Mode | Kondisi Terpakai | Implikasi Forensik |
|---|---|---|
| **"Basic"** | Tidak ada keyring backend terdeteksi (server headless, container, minimal desktop) | ⚠️ Key dari `Local State` (§5.5) bisa didekripsi tanpa bergantung keyring eksternal — jauh lebih mudah diakses |
| **GNOME Libsecret** | `gnome-keyring`/`libsecret` terdeteksi aktif | Key di `Local State` dienkripsi lagi oleh keyring, biasanya ter-*unlock* otomatis saat user login desktop session |
| **KWallet** | KDE terdeteksi aktif | Sama prinsipnya dengan GNOME Libsecret, lewat KWallet |

Prefix `v10`/`v11` pada `encrypted_value` menunjukkan versi skema/metode yang dipakai.

#### 5.10.4 Firefox — NSS (`key4.db`)

Firefox memakai NSS sebagai key store sendiri (`key4.db`, §5.7.4) — independen dari keyring OS. Ada/tidaknya **Master Password** menentukan tingkat kesulitan ekstraksi: profil tanpa Master Password (default kebanyakan user) membuat key relatif mudah diekstrak.

#### 5.10.5 Implikasi Kondisi Akuisisi — Live vs Dead

> ⚠️ Kalau keyring dalam keadaan **locked**, proses decrypt value yang bergantung GNOME Libsecret/KWallet bisa **gagal total**. Ini beda dari mode "Basic" yang tidak bergantung kondisi ini sama sekali.

#### 5.10.6 Konteks Tool

Disebut sebatas konteks investigasi: library Python `secretstorage` dan tool `firefox_decrypt` adalah contoh yang umum dipakai investigator dalam skenario yang sah dan diotorisasi — bukan tutorial dekripsi langkah demi langkah.

---

### 5.11 Sandbox & Containerization — Snap, Flatpak, AppImage 🔴

#### 5.11.1 Kenapa Penting Sekarang

Distro modern (contohnya rilis Ubuntu terbaru) meng-ship Chromium/Firefox lewat **Snap secara default**. Kalau investigator masih berasumsi path selalu di §5.2 tanpa cek lapisan sandbox ini, sebagian besar artefak browser bisa **terlewat**.

#### 5.11.2 Snap

```
~/snap/<package-name>/current/.config/<vendor>/...
~/snap/<package-name>/current/.mozilla/firefox/...
```

Snap punya **confinement** (biasanya `strict`) yang membatasi akses filesystem aplikasi ke luar folder snap-nya sendiri.

#### 5.11.3 Flatpak

```
~/.var/app/<app-id>/.config/...
~/.var/app/<app-id>/.mozilla/firefox/...
```

`<app-id>` mengikuti reverse-DNS (mis. `org.mozilla.firefox`, `com.google.Chrome`).

> 🟡 **Catatan `xdg-desktop-portal`:** Aplikasi Flatpak mengakses resource sistem (termasuk kadang keyring/secret storage) lewat portal ini — bisa memengaruhi hasil akses ke backend enkripsi (§5.10) dibanding instalasi native.

#### 5.11.4 AppImage

Umumnya portable dan tetap memakai path config default `$HOME` seperti instalasi native, kecuali dikustomisasi eksplisit (§5.3.1).

> ⚠️ **Implikasi praktis:** Investigator **wajib cek ketiga lokasi** untuk tiap browser sebelum menyimpulkan "browser X tidak pernah dipakai" — ini sudah masuk sebagai langkah wajib di workflow §5.3.2.

```bash
find ~/snap -maxdepth 2 -iname "*chromium*" -o -iname "*firefox*" 2>/dev/null
find ~/.var/app -maxdepth 1 -iname "*chrome*" -o -iname "*firefox*" 2>/dev/null
find / -xdev -iname "*.AppImage" 2>/dev/null
```

---

### 5.12 Root vs Per-User & Multi-user System 🟡

Profil browser milik akun `root` (`/root/.config/...`) sering terlewat karena investigasi cenderung otomatis fokus ke `/home/<user>/` — padahal kalau ada aktivitas browser dari sesi root langsung, artefaknya ada di `/root/`, bukan di `/home`.

> 🔗 **Cross-ref Bab 4 §4.2:** Selalu enumerasi **semua** akun di sistem terlebih dulu sebelum mulai scan path browser per-user — ini sudah masuk langkah 1 workflow §5.3.2.

---

### 5.13 Download History & Filesystem Correlation

#### 5.13.1 Sumber Data per Browser

**Chromium:** table `downloads` di database `History` (§5.6.1) — menyimpan URL sumber, path lokal tempat file disimpan, timestamp mulai/selesai, dan flag `danger_type`.

**Firefox:** informasi terkait tersimpan sebagai anotasi (`moz_annos`) yang terhubung ke `places.sqlite` (§5.7.1).

#### 5.13.2 Download → Filesystem Correlation Workflow

**Pengertian & Fungsi:**
Entry download di database **saja** tidak cukup untuk menyimpulkan file benar-benar ada dan lengkap (ingat prinsip artifact ≠ event, §5.1) — perlu langkah korelasi eksplisit dengan bukti filesystem.

| Langkah | Tindakan | Cross-ref |
|---|---|---|
| 1 | Ekstrak seluruh entry `downloads`/anotasi download, termasuk path tujuan yang tercatat | §5.13.1 |
| 2 | Cek keberadaan file fisik di path tersebut sekarang | Bab 2 |
| 3 | Kalau file ada, bandingkan **ukuran file tercatat vs ukuran file aktual** — mismatch bisa berarti unduhan terputus/dimodifikasi setelahnya | — |
| 4 | Kalau file **tidak** ada, cek apakah kemungkinan dihapus (cross-ref recovery filesystem, Bab 2) — entry database tetap jadi bukti bahwa unduhan **pernah** tercatat, terlepas file fisiknya masih ada atau tidak | Bab 2 |
| 5 | Bandingkan timestamp filesystem (mtime/ctime, Bab 2 §2.1.2) dengan timestamp `start_time`/`end_time` di entry download — ketidaksesuaian signifikan bisa mengindikasikan file dimodifikasi setelah diunduh, atau timestamp asli sudah di-*timestomp* | Bab 2 §2.1.2, §2.1.3 |

> ⚠️ Status `danger_type`/kolom state di entry download menunjukkan apa yang **tercatat** oleh browser saat itu (mis. "COMPLETE") — bukan jaminan mutlak file di disk sekarang identik dengan yang diunduh saat itu. Selalu verifikasi langkah 3–5 sebelum menjadikan entry ini sebagai bukti tunggal.

---

### 5.14 Cache Forensics 🟡

**Chromium — Simple Cache format:** struktur `index` (metadata entri cache) + serangkaian file `data_N` (isi cache sebenarnya).

**Firefox:** `cache2/` (§5.7.6) dengan struktur serupa secara konsep.

> 💡 **Nilai forensik utama cache:** Kemungkinan **recovery resource** (terutama gambar/thumbnail) dari halaman yang entry-nya di History **sudah dihapus user**, tapi file cache-nya belum sempat ter-*clear*.

---

### 5.15 Chromium Network-related Artifacts 🟡

| File | Isi |
|---|---|
| `Network Persistent State` | State koneksi jaringan yang di-*cache* browser |
| `TransportSecurity` | Daftar host yang pernah "diingat" browser sebagai HSTS — mirip fungsinya dengan `.wget-hsts` di Bab 4 §4.11, versi browser GUI |
| `Reporting and NEL` | Data dari fitur Network Error Logging |
| `QuicServerInfo` | Informasi server yang mendukung protokol QUIC |

> 🔗 `TransportSecurity` berguna sebagai pembanding independen kalau History sudah dihapus — **tapi** ingat prinsip artifact ≠ event (§5.1): entry HSTS cuma bukti host itu pernah "ditemui" lewat request HTTPS, bukan bukti transaksi/halaman lengkap benar-benar dimuat di sana.

---

### 5.16 Deleted Browser Artifacts / SQLite Recovery 🔴

**Pengertian & Fungsi:**
Baris yang "dihapus" user dari History/Bookmarks/dsb **tidak serta-merta hilang** secara fisik dari file — SQLite menandai ruang bekas baris terhapus sebagai **freelist page** yang bisa dipakai ulang, tapi data lama bisa jadi masih ada secara fisik sampai halaman itu ditimpa.

**Pendekatan recovery yang relevan:**

| Pendekatan | Cocok Untuk |
|---|---|
| Baca isi `-wal` file mentah (§5.4.2) sebelum di-checkpoint | Perubahan sangat baru, belum sempat masuk file utama |
| Scan freelist page & unallocated space dalam file `.sqlite` | Baris terhapus yang sudah ter-checkpoint, belum ditimpa |
| File carving berbasis signature SQLite di unallocated disk space | File database itu sendiri sudah terhapus dari filesystem |

```bash
sqlite3 History ".recover" > History_recovered.sql
```

> ⚠️ **Koreksi eksplisit — `.recover` bukan jaminan recovery sempurna:** Perintah `.recover` (dan tool sejenis) adalah **best-effort recovery**, bukan proses yang menjamin seluruh data kembali utuh. Beberapa keterbatasan yang perlu dipahami:
> - Halaman yang **sudah ditimpa** data baru (karena freelist-nya sudah dipakai ulang) **tidak bisa** dikembalikan sama sekali — recovery hanya bisa mengambil apa yang **masih ada secara fisik**, bukan mengembalikan sesuatu yang sudah tertimpa.
> - Baris hasil recovery kadang kehilangan **konteks relasional** — misalnya baris `visits` yang berhasil di-recover tapi baris `urls` terkait sudah tertimpa, menyisakan data yang sulit diinterpretasi tanpa join yang lengkap.
> - Hasil recovery perlu diperlakukan dengan tingkat kepercayaan **lebih rendah** dibanding data dari file utama yang normal — selalu dokumentasikan bahwa suatu temuan berasal dari proses recovery, bukan data yang secara aktif masih tercatat sistem, karena ini relevan untuk menilai bobot bukti di laporan akhir.
>
> 📌 Mekanisme detail internal SQLite (struktur page, freelist, cara kerja B-tree) mengikuti pembahasan SQLite generik di bab lain — bagian ini fokus ke **penerapan dan keterbatasannya** khusus pada database browser.

---

### 5.17 Browser Process & Live Memory Considerations 🟡

**Pengertian & Fungsi:**
Selain artefak yang tersimpan di disk (fokus utama Bab 5), proses browser yang **masih berjalan** di sistem live menyimpan data tambahan yang tidak pernah ditulis ke disk sama sekali — relevan sebagai konteks tambahan sebelum memutuskan strategi akuisisi (§5.4.1).

| Sumber Live | Nilai Forensik |
|---|---|
| `/proc/<PID>/cmdline`, `/proc/<PID>/environ` | Flag custom (`--user-data-dir`, dsb, §5.3.1), env override yang tidak tercatat di file config manapun |
| `/proc/<PID>/fd/` | Daftar file yang sedang dibuka proses browser saat ini — bisa mengonfirmasi database mana yang aktif dipakai, termasuk profil non-default yang sedang diakses |
| Memory proses (RAM) | Data yang **belum pernah** ditulis ke disk sama sekali (misalnya isi form yang sedang diketik, konten tab mode incognito yang masih terbuka, §5.18) — di luar cakupan teknis mendalam bab ini, tapi relevan disebutkan sebagai pertimbangan strategi akuisisi |

```bash
# Cek proses browser yang sedang berjalan & file yang dibukanya
ps aux | grep -iE "chrome|chromium|firefox"
ls -la /proc/<PID>/fd/ | grep -iE "sqlite|history|cookies"
```

> ⚠️ **Implikasi ke urutan kerja:** Kalau ditemukan proses browser masih berjalan saat investigasi live response, pertimbangkan **memory capture** (dibahas mendalam di bab Memory Forensics, di luar cakupan Bab 5) **sebelum** mengakhiri proses/mematikan sistem — begitu proses dihentikan, data yang cuma ada di memory (belum ter-checkpoint ke disk, §5.4.2) hilang permanen. Ini adalah alasan konkret lain kenapa §5.4.1 menandai live acquisition sebagai kondisi berisiko lebih tinggi.

---

### 5.18 Incognito / Private / Guest Artifacts 🔴

**Pengertian & Fungsi:**
Mode Incognito (Chromium) / Private Browsing (Firefox) **didesain** untuk tidak menulis history, cookies, atau cache baru ke profil permanen — tapi ini **bukan berarti nol jejak sama sekali**.

| Sumber | Kemungkinan Jejak dari Sesi Incognito/Private |
|---|---|
| Memory (RAM, live system) | Selama sesi masih berjalan, data browsing tetap ada di memori proses — cross-ref §5.17 |
| DNS cache sistem / resolver lokal | Query DNS untuk domain yang diakses lewat incognito tetap melewati resolver sistem |
| Download yang diselesaikan | File yang benar-benar diunduh selama sesi incognito tetap tersimpan fisik di disk |
| Extension yang diizinkan berjalan di incognito | Sebagian data extension berpotensi tetap tersimpan lewat storage milik extension itu sendiri |
| Bookmark yang dibuat manual saat sesi incognito | **Tetap tersimpan permanen** |

**Guest Profile (khusus Chromium):**
Guest Mode punya profil **sendiri** yang persisten selama sesi guest berjalan, tapi **di-reset/dihapus otomatis** setiap sesi guest berakhir. Kalau sistem sempat ditangkap **selagi** sesi guest masih berjalan (live, cross-ref §5.17), profil sementara ini masih bisa diperiksa.

> ⚠️ **Kesimpulan penting:** "Tidak ada entry di History" **tidak sama** dengan "tidak ada aktivitas" — ini penerapan langsung dari prinsip artifact ≠ event (§5.1). Investigator perlu eksplisit mempertimbangkan kemungkinan mode private/incognito/guest saat database utama tampak "terlalu bersih" dibanding indikasi aktivitas dari sumber lain.

---

### 5.19 Browser Sync 🟡

**Pengertian & Fungsi:**
Fitur sync (Chrome Sync, Firefox Sync/Mozilla Account) menyimpan sebagian metadata akun sync lokal di profil.

| Browser | Artefak Sync Lokal |
|---|---|
| Chromium | Info akun Google yang login tersimpan di `Preferences`/`Sync Data` (folder `Sync Data/LevelDB`) |
| Firefox | `signedInUser.json` — info Mozilla Account yang login |

> 💡 **Nilai forensik:** Email akun yang tersimpan bisa jadi titik korelasi penting — menghubungkan aktivitas di sistem yang diperiksa dengan identitas/akun yang sama dipakai di perangkat lain.

```bash
cat "signedInUser.json" 2>/dev/null | python3 -m json.tool
```

---

### 5.20 Extensions & Add-ons sebagai Attack Vector (+ Policy Artifacts)

**Pengertian & Fungsi:**
Extension/add-on browser adalah vektor yang sering diremehkan — extension jahat bisa terpasang lewat social engineering atau lewat **paksaan administratif** kalau attacker sudah punya akses root.

**Review dasar extension:**
Baca `manifest.json` (§5.6.7/§5.7.7) — perhatikan `permissions` (`<all_urls>`, `cookies`, `webRequest`) dan `content_scripts`.

**Policy artifacts — forced-install extension 🟢:**

```
/etc/opt/chrome/policies/managed/
/etc/chromium-browser/policies/managed/
/etc/opt/microsoft-edge/policies/managed/
```

File JSON di direktori ini bisa mengandung `ExtensionInstallForcelist` yang mendaftarkan extension ID + URL sumber instalasi — extension yang terdaftar akan otomatis terpasang ke **semua** profil user tanpa interaksi user apapun.

> 🔴 **Relevansi forensik:** Extension yang dipaksakan lewat policy jauh lebih patut dicurigai dibanding extension pilihan user, terutama kalau URL sumbernya bukan toko ekstensi resmi.

```bash
find /etc -path "*policies/managed*" -iname "*.json" 2>/dev/null -exec cat {} \;
```

---

### 5.21 Timeline Correlation — Browser vs Artefak Lain

- **Bab 3** (log jaringan/journald) — korelasi waktu akses jaringan dengan waktu kunjungan URL, saling mengonfirmasi.
- **Bab 4 §4.11** (`.wget-hsts`, dsb) — bedakan aktivitas CLI (`wget`/`curl`) vs GUI browser secara eksplisit, jangan tercampur seolah satu sumber.

---

### 5.22 Tabel Korelasi — Pertanyaan Investigasi ke Artefak

| Pertanyaan Investigasi | Artefak Utama | Cross-ref |
|---|---|---|
| Apakah ada profil browser di lokasi non-default? | Env `$HOME`/`$XDG_CONFIG_HOME`, flag `--user-data-dir` | §5.3.1 |
| Sudah semua profil di sistem ini dicek? | Workflow enumerasi lengkap | §5.3.2 |
| URL apa saja yang pernah dikunjungi? | `History` / `places.sqlite` | §5.6.1, §5.7.1 |
| Apakah timestamp yang muncul valid? | Formula konversi epoch sesuai browser | §5.8 |
| Apakah ada tab yang terbuka tapi belum tercatat di history? | SNSS / `sessionstore.jsonlz4` | §5.6.8, §5.7.5 |
| Bagaimana cara decrypt password tersimpan? | `Login Data` + `Local State` / `logins.json` + `key4.db` | §5.5, §5.10 |
| Kenapa dekripsi password gagal di sistem ini? | Kondisi keyring locked, atau mode "Basic" | §5.10.3, §5.10.5 |
| Apakah browser diinstal lewat Snap/Flatpak? | Path `~/snap/`, `~/.var/app/` | §5.11 |
| Apakah file hasil akuisisi masih valid/tidak korup? | `PRAGMA integrity_check` | §5.4.4 |
| Apakah ada baris History yang sengaja dihapus? | Freelist/unallocated page recovery | §5.16 |
| Seberapa yakin hasil recovery baris terhapus itu? | Keterbatasan `.recover`, cek konteks relasional | §5.16 |
| Apakah aktivitas dilakukan lewat mode incognito/private? | Ketiadaan entry history + jejak tidak langsung | §5.18 |
| Apakah ada sesi browser live yang perlu ditangkap dulu? | Proses aktif, `/proc/<PID>/fd`, memory | §5.17 |
| Akun apa yang dipakai login sync? | `signedInUser.json`, Sync Data | §5.19 |
| Apakah ada extension mencurigakan? | `manifest.json`, permission | §5.20 |
| Apakah file yang tercatat diunduh benar-benar lengkap di disk? | Korelasi ukuran & timestamp file vs entry download | §5.13.2 |
| Domain apa yang pernah diakses tapi tidak ada di history? | `TransportSecurity` (HSTS cache) | §5.15 |

---

### 5.23 Ringkasan Command & Tools Cheat Sheet

```bash
# --- Enumerasi profil (native + XDG + sandbox) ---
cat /proc/<PID>/environ | tr '\0' '\n' | grep -E "^HOME=|^XDG_CONFIG_HOME="
cat /proc/<PID>/cmdline | tr '\0' ' '
find ~/.config ~/.mozilla ~/snap ~/.var/app -maxdepth 3 \
     -iname "*chrome*" -o -iname "*chromium*" -o -iname "*firefox*" 2>/dev/null

# --- Akuisisi database aman (live) ---
sqlite3 "History" ".backup '/path/tujuan/History_backup.sqlite'"
cp "History" "History-wal" "History-shm" /path/tujuan/ 2>/dev/null

# --- Verifikasi integritas hasil akuisisi ---
sqlite3 History_backup.sqlite "PRAGMA integrity_check;"
sha256sum History_backup.sqlite

# --- Local State (key enkripsi Chromium) ---
cat "Local State" | python3 -m json.tool | grep -A2 "encrypted_key"

# --- Cek skema aktual sebelum query (jangan asumsi identik) ---
sqlite3 History "PRAGMA table_info(urls);"

# --- Konversi timestamp ---
sqlite3 History "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url FROM urls LIMIT 5;"     # Chromium
sqlite3 places.sqlite "SELECT datetime(visit_date/1000000,'unixepoch') FROM moz_historyvisits LIMIT 5;"        # Firefox

# --- Baca Bookmarks (JSON, bukan SQLite) ---
cat "Bookmarks" | python3 -m json.tool

# --- Firefox session recovery (LZ4) ---
python3 -m mozlz4 sessionstore.jsonlz4 sessionstore_decompressed.json

# --- Recovery baris terhapus SQLite (best-effort, lihat §5.16) ---
sqlite3 History ".recover" > History_recovered.sql

# --- Policy forced-install extension ---
find /etc -path "*policies/managed*" -iname "*.json" -exec cat {} \;

# --- Proses & fd browser live ---
ps aux | grep -iE "chrome|chromium|firefox"
ls -la /proc/<PID>/fd/ | grep -iE "sqlite|history|cookies"
```

---

### 5.24 Mini Case Study — Workflow End-to-End

**Skenario:** Server internal (headless, tanpa desktop environment) diduga jadi titik pijak eksfiltrasi kredensial lewat browser otomatis. Chrome ternyata terinstal lewat Snap, dan proses awalnya sempat gagal ditemukan karena investigator hanya cek path native.

**Workflow rekonstruksi:**

1. **Enumerasi penuh (§5.3.2).** Path native `~/.config/google-chrome/` kosong. Mengikuti workflow enumerasi lengkap (bukan cuma cek satu lokasi), ditemukan profil aktif di `~/snap/chromium/current/.config/chromium/` (§5.11.2).

2. **Cek proses live sebelum akuisisi (§5.17).** Server masih live dan proses Chromium headless masih berjalan. `cat /proc/<PID>/cmdline` mengungkap flag `--user-data-dir=/tmp/.chrome-automation/` — ternyata ada **profil kedua** di luar profil Snap yang ditemukan di langkah 1, dipakai khusus untuk automation. Tanpa langkah ini, profil kedua ini tidak akan pernah ditemukan (§5.3.1).

3. **Akuisisi aman + verifikasi (§5.4, §5.4.4).** Investigator menggunakan `sqlite3 ".backup"` untuk `History` dan `Login Data` di kedua profil, menyalin `Local State` beserta file `-wal`/`-shm`, lalu menjalankan `PRAGMA integrity_check` — hasil `ok` untuk semua file, memastikan hasil akuisisi valid sebelum analisis lanjut.

4. **Cek mode enkripsi (§5.10.3).** Karena sistem headless tanpa keyring desktop, `Login Data` terenkripsi mode **"Basic"** — dekripsi berhasil langsung memakai key dari `Local State`.

5. **Cek download → filesystem correlation (§5.13.2).** Entry `downloads` di profil automation menunjukkan beberapa file berstatus "COMPLETE", tapi setelah dicek fisik, dua file berukuran 0 byte — mengindikasikan unduhan sebenarnya **terputus**, bukan lengkap seperti yang tercatat status-nya (penerapan langsung prinsip artifact ≠ event, §5.1).

6. **Cek extension terinstal (§5.20).** Ditemukan extension dengan permission `<all_urls>` + `webRequest`, dipasang paksa lewat policy file di `/etc/chromium-browser/policies/managed/`.

7. **Cek session recovery (§5.6.8).** `Last Session` menunjukkan tab terakhir mengarah ke domain yang sama dengan sumber extension di langkah 6.

8. **Konfirmasi silang HSTS (§5.15), dengan catatan artifact ≠ event.** `TransportSecurity` mengonfirmasi domain tersebut memang pernah diakses lewat HTTPS — tapi investigator tidak menyimpulkan transaksi data lengkap terjadi hanya dari entry ini saja, cukup sebagai penguat korelasi bersama temuan lain.

**Kesimpulan rekonstruksi:** Kombinasi §5.3 (enumerasi penuh, termasuk profil tersembunyi lewat flag custom yang cuma ketahuan dari proses live) + §5.4.4 (verifikasi integritas sebelum percaya hasil akuisisi) + §5.10.3 (mode Basic mempermudah dekripsi) + §5.13.2 (korelasi filesystem membongkar status download yang menyesatkan) + §5.20 (extension paksa) berhasil merekonstruksi rantai kejadian secara menyeluruh — dengan setiap klaim dijaga proporsional terhadap kekuatan buktinya, bukan mengambil nilai field status apa adanya.

> 🔗 **Menuju Bab 6:** Setelah memahami jejak browser (Bab 5), bab berikutnya masuk ke **Persistence** — termasuk pembahasan penuh soal alias/function override shell (Bab 4 §4.12) dan pola-pola persistence lain yang lebih luas.
