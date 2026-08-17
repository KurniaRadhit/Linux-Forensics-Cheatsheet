## 📌 Daftar Isi — Bab 9

- [Bab 9 — Timeline Correlation & Anti-Forensics: Linux](#bab-9--timeline-correlation--anti-forensics-linux)
  - [9.1 Overview & Posisi Bab 9](#91-overview--posisi-bab-9)
  - [9.2 Evidence Reliability / Source Weighting 🔴](#92-evidence-reliability--source-weighting-)
  - [9.3 MACB & Timestamp Semantics 🔴](#93-macb--timestamp-semantics-)
    - [9.3.1 Makna Sebenarnya M/A/C/B](#931-makna-sebenarnya-macb)
    - [9.3.2 Kesalahpahaman Umum yang Wajib Dikoreksi](#932-kesalahpahaman-umum-yang-wajib-dikoreksi)
    - [9.3.3 MACB di Ext4 vs XFS](#933-macb-di-ext4-vs-xfs)
  - [9.4 Inventarisasi Sumber Timeline Lintas Bab 🔴](#94-inventarisasi-sumber-timeline-lintas-bab-)
  - [9.5 Timestamp Normalization at Scale 🔴](#95-timestamp-normalization-at-scale-)
  - [9.6 Metodologi Super Timeline Construction 🔴](#96-metodologi-super-timeline-construction-)
    - [9.6.1 Bodyfile & `mactime` (Sleuthkit)](#961-bodyfile--mactime-sleuthkit)
    - [9.6.2 `plaso`/`log2timeline`](#962-plasolog2timeline)
    - [9.6.3 Event Classification 🔴](#963-event-classification-)
    - [9.6.4 Timeline Noise Reduction 🔴](#964-timeline-noise-reduction-)
    - [9.6.5 Menyatukan Jadi Satu Timeline Final](#965-menyatukan-jadi-satu-timeline-final)
  - [9.7 Timeline Correlation Techniques & Pivot Points 🔴](#97-timeline-correlation-techniques--pivot-points-)
  - [9.8 Anti-Forensics — Taksonomi & Overview 🔴](#98-anti-forensics--taksonomi--overview-)
  - [9.9 Timestomping — Deep Dive 🔴](#99-timestomping--deep-dive-)
  - [9.10 Secure Deletion & Data Wiping 🔴](#910-secure-deletion--data-wiping-)
    - [9.10.1 `shred`/`wipe`/`dd` Overwrite Patterns](#9101-shredwipedd-overwrite-patterns)
    - [9.10.2 Deteksi Bekas Wiping](#9102-deteksi-bekas-wiping)
    - [9.10.3 Unlink vs Overwrite vs TRIM 🟡](#9103-unlink-vs-overwrite-vs-trim-)
  - [9.11 Log Rotation vs Deletion vs Tampering 🔴](#911-log-rotation-vs-deletion-vs-tampering-)
  - [9.12 Data Hiding Techniques 🟡](#912-data-hiding-techniques-)
  - [9.13 Filesystem/Volume Snapshots — LVM/Btrfs/VM 🟡](#913-filesystemvolume-snapshots--lvmbtrfsvm-)
  - [9.14 Clock Drift, NTP & VM Time 🔴](#914-clock-drift-ntp--vm-time-)
  - [9.15 Anti-Forensic Tooling Overview 🟡](#915-anti-forensic-tooling-overview-)
  - [9.16 Evidence Gap Analysis — Formal Methodology 🔴](#916-evidence-gap-analysis--formal-methodology-)
  - [9.17 Reporting — Confidence Level dalam Timeline](#917-reporting--confidence-level-dalam-timeline)
  - [9.18 Tabel Korelasi — Pertanyaan Investigasi ke Teknik](#918-tabel-korelasi--pertanyaan-investigasi-ke-teknik)
  - [9.19 Ringkasan Command & Tools Cheat Sheet](#919-ringkasan-command--tools-cheat-sheet)
  - [9.20 Mini Case Study — Workflow Analisa End-to-End](#920-mini-case-study--workflow-analisa-end-to-end)

*(Bab 1: Struktur Linux & Filesystem Dasar. Bab 2: Filesystem Forensics Ext4/XFS. Bab 3: Syslog, Journald & Log Forensics. Bab 4: User, Auth & Shell Artifacts. Bab 5: Browser Forensics Linux. Bab 6: Persistence. Bab 7: Memory Forensics Linux. Bab 8: Malware & Rootkit Analysis.)*

---

## Bab 9 — Timeline Correlation & Anti-Forensics: Linux

> 💡 **Posisi Bab 9 — capstone, bukan bab teknik baru murni:** Bab 1-8 masing-masing sudah membangun sumber evidence-nya sendiri (filesystem, log, auth, browser, persistence, memory, malware) plus tabel korelasi lokal di penghujung tiap bab. Bab 9 menjawab satu tingkat lebih tinggi: **bagaimana menyatukan SEMUA sumber itu jadi satu timeline koheren**, dan **bagaimana tetap menyimpulkan sesuatu yang valid ketika sebagian sumber sudah sengaja dimanipulasi attacker**. Paruh pertama (§9.2-§9.7) tentang menyatukan; paruh kedua (§9.8-§9.16) tentang menghadapi manipulasi.

> 📖 **Kenapa Evidence Reliability (§9.2) dan MACB Semantics (§9.3) ditaruh duluan, sebelum metodologi:** Kedua bagian ini adalah *lensa* yang dipakai di seluruh sisa bab — tanpa memahami dulu "seberapa saya boleh percaya sumber ini" dan "apa arti sebenarnya tiap timestamp", metodologi super timeline (§9.6) dan deteksi timestomping (§9.9) hanya akan jadi resep mekanis tanpa pemahaman kenapa langkahnya seperti itu.

> ⚠️ **Prinsip yang mengikat seluruh bab ini:** Timeline yang dibangun dari banyak sumber **tidak otomatis lebih benar** hanya karena lebih lengkap — kalau sumbernya dicampur tanpa mempertimbangkan reliability (§9.2) dan precision masing-masing (§9.3, §9.5), hasilnya justru timeline yang terlihat meyakinkan tapi menyesatkan. Volume bukan pengganti rigor.

---

### 9.2 Evidence Reliability / Source Weighting 🔴

**Pengertian & Fungsi:**
Setiap sumber timeline punya "bobot kepercayaan" berbeda tergantung seberapa mudah dimanipulasi, seberapa independen dari sistem yang mungkin sudah dikuasai attacker, dan seberapa presisi timestamp yang dihasilkannya. Bab 3 §3.9 sudah memperkenalkan konsep ini **khusus untuk sumber log** — di sini modelnya digeneralisasi untuk **seluruh** kategori evidence dari Bab 1-8, jadi fondasi tunggal yang dipakai konsisten sepanjang Bab 9.

| Tier | Karakteristik | Contoh Sumber | Bagian/Bab Asal |
|---|---|---|---|
| **Tier 1 — Independen & Sulit Dimanipulasi** | Di luar jangkauan attacker yang cuma kuasai satu host, atau butuh akses/skill sangat tinggi untuk diubah tanpa jejak | Log server terpusat, memory image yang diakuisisi sebelum attacker sadar, hash sampel malware, Ext4 journal (jbd2) sebagai cross-check independen | Bab 3 §3.2.6, Bab 7, Bab 8 §8.2, Bab 2 §2.2 |
| **Tier 2 — Lokal, Butuh Akses Tinggi untuk Manipulasi** | Bisa dimanipulasi tapi butuh root + effort spesifik, biasanya meninggalkan jejak tidak langsung | journald dengan FSS aktif, inode `crtime`, auditd dengan rule immutable | Bab 3 §3.4.8, Bab 2 §2.1.2, Bab 3 §3.5 |
| **Tier 3 — Lokal, Mudah Dimanipulasi** | Plaintext, root bisa edit langsung tanpa tool khusus | Syslog plaintext, `mtime`/`atime` file, shell history | Bab 3 §3.2, Bab 2 §2.1.3, Bab 4 §4.10 |
| **Tier 4 — Inferensial/Tidak Langsung** | Bukan bukti event langsung, hanya indikasi "sesuatu pernah terjadi/ditemui" | `known_hosts` (Bab 4 §4.13.4), `TransportSecurity`/HSTS cache browser (Bab 5 §5.15) | Bab 4, Bab 5 |

```
Prinsip pembobotan saat menulis klaim di timeline:

Klaim didukung ≥2 sumber Tier 1-2 INDEPENDEN     → confidence TINGGI  (§9.17: "confirmed")
Klaim didukung 1 sumber Tier 1-2                  → confidence SEDANG (§9.17: "corroborated" kalau ada penguat Tier 3-4)
Klaim HANYA didukung sumber Tier 3                → confidence RENDAH (§9.17: "single-source")
Klaim hanya dari sumber Tier 4                     → confidence INFERENSIAL, bukan fakta pasti
```

> 📌 **Kenapa ini bukan sekadar "makin banyak sumber makin baik":** Dua sumber Tier 3 yang saling mendukung (misal `mtime` file + `.bash_history`, dua-duanya gampang dimanipulasi attacker yang sama) **tidak** setara kekuatannya dengan satu sumber Tier 1 sendirian. Independensi sumber lebih penting daripada jumlah sumber — attacker yang menguasai satu host bisa memanipulasi banyak sumber Tier 3 sekaligus dengan effort yang sama.

---

### 9.3 MACB & Timestamp Semantics 🔴

#### 9.3.1 Makna Sebenarnya M/A/C/B

**Pengertian & Fungsi:**
MACB adalah singkatan empat kategori timestamp yang jadi bahasa umum di timeline forensik (istilah ini dipopulerkan oleh Sleuthkit `mactime`, §9.6.1) — tapi makna sebenarnya sering disalahpahami, terutama huruf **C**.

| Huruf | Nama | Arti Sebenarnya | Trigger |
|---|---|---|---|
| **M** | Modified | Isi/konten file terakhir diubah | Write ke data file |
| **A** | Accessed | File terakhir dibaca | Read (banyak sistem modern **menonaktifkan** update ini demi performa, lihat §9.3.2) |
| **C** | Changed | **Metadata** inode terakhir diubah — BUKAN "Created" | `chmod`, `chown`, rename, perubahan permission/xattr, atau otomatis ikut berubah saat M berubah |
| **B** | Born/Birth | Waktu inode pertama kali dibuat (crtime) | Hanya ada di Ext4 (dengan fitur yang mendukung) — cross-ref Bab 2 §2.1.2 |

#### 9.3.2 Kesalahpahaman Umum yang Wajib Dikoreksi

> ⚠️ **Koreksi #1 — `ctime` BUKAN "creation time":** Ini kesalahpahaman paling umum, sering terbawa dari asumsi penamaan yang intuitif tapi salah. `ctime` adalah **metadata change time** — berubah setiap kali attribut inode berubah (permission, owner, jumlah link, bahkan **rename** memicu perubahan `ctime` meski isi file tidak disentuh sama sekali). Kalau butuh waktu pembuatan file yang sebenarnya, itu `crtime`/**B** (§9.3.1), bukan `ctime`/**C** — dan `crtime` hanya tersedia di Ext4, tidak ada di banyak filesystem lain.

> ⚠️ **Koreksi #2 — `atime` sering tidak reliable di sistem modern:** Banyak distro Linux mounting filesystem dengan opsi `relatime` (default sejak kernel modern) atau bahkan `noatime` demi performa I/O — `relatime` hanya update `atime` kalau sebelumnya lebih lama dari `mtime` atau lebih dari 24 jam, `noatime` tidak update sama sekali. Artinya `atime` **tidak bisa diasumsikan** mencerminkan akses terakhir yang presisi kecuali sudah dikonfirmasi mount option-nya (`mount | grep <mountpoint>`).

> ⚠️ **Koreksi #3 — Rename memicu C tanpa menyentuh M:** Kalau investigator melihat `mtime` lama tapi `ctime` baru, kesimpulan paling umum yang benar adalah file di-rename/di-`mv`/permission diubah — **bukan otomatis berarti** file dimanipulasi isinya lalu timestamp di-timestomp balik. Perlu dicek lebih lanjut (§9.9) sebelum menyimpulkan anti-forensics.

#### 9.3.3 MACB di Ext4 vs XFS

**Pengertian & Fungsi:**
Cross-ref langsung Bab 2 §2.1.2 (Ext4) dan §2.8.2 (XFS) — di sini dirangkum sebagai tabel perbandingan cepat karena keduanya sering perlu dibandingkan berdampingan dalam satu investigasi (server dengan partisi campuran).

| Aspek | Ext4 | XFS |
|---|---|---|
| Punya `crtime` (Birth)? | Ya (perlu `debugfs`/`statx()` untuk baca, `stat` biasa tidak selalu menampilkan) | Ya, lebih native ditampilkan lewat `statx()` |
| Presisi timestamp | Nanodetik (Ext4 modern) | Nanodetik |
| Cara baca crtime | `debugfs -R "stat <inode>"` atau `stat -c %w` (kernel/util mendukung `statx`) | `stat -c %w` (dukungan native lebih baik) |

```bash
# Cek dukungan crtime via statx (kernel ≥4.11 + util-linux mendukung)
stat -c "M=%Y A=%X C=%Z B=%W" /path/ke/file
# Kalau B menunjukkan "0" atau kosong, filesystem/util tidak mendukung — fallback debugfs (Bab 2 §2.1.2)
```

---

### 9.4 Inventarisasi Sumber Timeline Lintas Bab 🔴

**Pengertian & Fungsi:**
Tabel rujukan cepat seluruh sumber timestamp yang sudah dibahas di Bab 1-8, sekarang dipetakan sekaligus ke tier reliability §9.2 — dipakai sebagai checklist saat membangun super timeline (§9.6).

| Sumber | Jenis Timestamp | Granularitas | Tier (§9.2) | Bab Asal |
|---|---|---|---|---|
| Inode MACB | Filesystem metadata | Nanodetik (Ext4) | 2-3 (C/M gampang, B lebih sulit dimanipulasi) | Bab 2 §2.1.2 |
| Ext4 journal (jbd2) | Transaction commit | Detik-ish, tapi independen dari inode langsung | 1 | Bab 2 §2.2 |
| `auth.log`/syslog plaintext | Event login/sudo | Detik (RFC 3164 tanpa tahun!) | 3 | Bab 3 §3.2 |
| journald | Event terstruktur | Mikrodetik | 2 (3 kalau `Storage=volatile`) | Bab 3 §3.4 |
| `audit.log` | Syscall-level event | Mikrodetik | 2 | Bab 3 §3.5 |
| `/etc/passwd`/`shadow` mtime | Perubahan akun | Detik | 3 | Bab 4 §4.3.2 |
| `wtmp`/`utmp`/`btmp`/`lastlog` | Sesi login | Detik | 3 | Bab 4 §4.14 |
| SQLite browser (`History`, dst) | Kunjungan/download | Mikrodetik (epoch beda-beda per browser!) | 3-4 | Bab 5 §5.8 |
| Unit file/cron mtime | Persistence install | Detik | 3 | Bab 6 |
| Memory image acquisition time | Snapshot proses/koneksi | Momen tunggal, bukan rentang | 1 (kalau diambil sebelum tampering) | Bab 7 |
| Hash/sampel malware + `/proc/PID` | Eksekusi payload | Detik-mikrodetik | 1-2 | Bab 8 §8.2 |

> 📌 **Cara pakai tabel ini:** Sebelum membangun timeline gabungan (§9.6), cek dulu tier tiap sumber yang akan dipakai — ini menentukan bagaimana tiap event nanti diberi label confidence (§9.17) begitu masuk timeline final, bukan diputuskan belakangan setelah semua tercampur.

---

### 9.5 Timestamp Normalization at Scale 🔴

**Pengertian & Fungsi:**
Bab 3 §3.1.3 sudah membahas normalisasi timezone untuk sumber log — di sini prinsip yang sama diterapkan ke **semua** baris di tabel §9.4 sekaligus, termasuk dua sumber yang epoch/formatnya sering jadi jebakan: timestamp browser (beda basis epoch antar vendor) dan timestamp memory image.

```bash
# Basis epoch BERBEDA antar sumber — kesalahan konversi di sini merusak SELURUH timeline
# Unix epoch standar (kebanyakan log Linux, inode)           : detik/mikrodetik sejak 1970-01-01
# Chromium (Bab 5 §5.8)                                       : mikrodetik sejak 1601-01-01 (WebKit epoch)
# Firefox (Bab 5 §5.8)                                         : mikrodetik sejak 1970-01-01 (Unix biasa)
# journald __REALTIME_TIMESTAMP (Bab 3 §3.4.6)                 : mikrodetik sejak 1970-01-01

# Konversi Chromium epoch ke Unix epoch (offset ~11644473600 detik)
python3 -c "
chromium_ts = 13350000000000000
unix_ts = chromium_ts/1000000 - 11644473600
import datetime; print(datetime.datetime.utcfromtimestamp(unix_ts))
"

# SEMUA hasil normalisasi WAJIB direkam dalam UTC di timeline final —
# konversi ke local time (kalau perlu untuk laporan) dilakukan HANYA di tahap presentasi,
# bukan di data mentah yang dipakai analisis
```

> ⚠️ **Kesalahan paling merusak di tahap ini:** Mencampur timestamp yang sudah dikonversi ke local time dengan yang masih UTC di kolom yang sama tanpa penanda jelas — begitu tercampur, urutan kronologis di timeline final bisa salah total tanpa ada tanda visual yang mengingatkan. Selalu simpan raw UTC + kolom terpisah untuk local time kalau memang dibutuhkan.

---

### 9.6 Metodologi Super Timeline Construction 🔴

#### 9.6.1 Bodyfile & `mactime` (Sleuthkit)

**Pengertian & Fungsi:**
Pendekatan manual/lightweight — membangun bodyfile (format standar Sleuthkit berisi MACB semua file) lalu mengurutkannya jadi timeline lewat `mactime`. Cross-ref penuh ke tools yang sudah disinggung Bab 2 §2.5.7.

```bash
# Generate bodyfile dari image/mountpoint
fls -r -m / /dev/sda1 > bodyfile.txt

# Convert bodyfile jadi timeline terurut kronologis
mactime -b bodyfile.txt -d > timeline_filesystem.csv
```

> 📌 **Kelebihan pendekatan manual:** Ringan, tidak butuh instalasi besar, cukup untuk kasus yang scope-nya murni filesystem. Keterbatasannya: `mactime` hanya menangani sumber filesystem — log, browser, memory tidak otomatis masuk, harus digabung manual (§9.6.5).

#### 9.6.2 `plaso`/`log2timeline`

**Pengertian & Fungsi:**
Framework timeline otomatis yang jauh lebih luas cakupannya dibanding `mactime` — punya parser bawaan untuk banyak format sekaligus (filesystem, syslog, browser SQLite, systemd journal, dan puluhan format lain), cocok dipakai kalau scope investigasi lintas-sumber seperti kebanyakan skenario di seri ini.

```bash
# Instalasi (Debian/Ubuntu, lewat PPA resmi GIFT)
sudo add-apt-repository ppa:gift/stable
sudo apt update && sudo apt install plaso-tools

# Ekstraksi timeline dari image/direktori — otomatis mendeteksi & parsing banyak sumber
log2timeline.py --storage-file timeline.plaso /path/ke/image_atau_direktori

# Export ke format yang mudah dibaca/di-filter lebih lanjut
psort.py -o l2tcsv -w timeline_full.csv timeline.plaso

# Filter berdasarkan rentang waktu tertentu langsung dari psort
psort.py -o l2tcsv -w timeline_incident.csv timeline.plaso \
  "date > '2026-08-14 08:00:00' AND date < '2026-08-14 12:00:00'"
```

> 💡 **Kapan pakai `plaso` vs manual (§9.6.1):** `plaso` unggul kalau scope investigasi memang lintas-sumber sejak awal (skenario khas Bab 9). Untuk kasus yang scope-nya sudah jelas sempit (misal cuma butuh timeline filesystem satu direktori), pendekatan manual §9.6.1 lebih cepat setup-nya tanpa overhead parsing sumber yang tidak relevan.

#### 9.6.3 Event Classification 🔴

**Pengertian & Fungsi:**
Timeline mentah dari `plaso`/gabungan manual bisa berisi puluhan ribu baris — tanpa klasifikasi kategori, investigator akan tenggelam sebelum sempat menemukan pola. Klasifikasi ini dilakukan **sebelum** noise reduction (§9.6.4), karena keduanya saling melengkapi: klasifikasi memberi struktur, noise reduction memangkas volume.

| Kategori Event | Contoh | Sumber Tipikal |
|---|---|---|
| **Filesystem** | File dibuat/diubah/dihapus | Bodyfile, `mactime` |
| **Authentication** | Login, sudo, perubahan akun | Bab 3 §3.3, Bab 4 |
| **Process/Execution** | Proses baru, command dijalankan | journald `_EXE`/`_CMDLINE`, `audit.log` EXECVE |
| **Network** | Koneksi masuk/keluar | `tcpdump`/pcap (Bab 8 §8.13), log firewall |
| **Persistence** | Unit file/cron dibuat/diubah | Bab 6 |
| **User Activity** | Browsing, download, shell history | Bab 4 §4.10, Bab 5 |
| **System/Administrative** | Service restart, reboot, perubahan config | journald `_SYSTEMD_UNIT` |

```bash
# Contoh filter kategori di psort (plaso) memakai field parser/source
psort.py -o l2tcsv -w timeline_auth_only.csv timeline.plaso \
  "source_short is 'LOG' AND parser is 'syslog'"
```

#### 9.6.4 Timeline Noise Reduction 🔴

**Pengertian & Fungsi:**
Event volume tinggi yang secara statistik dominan tapi jarang relevan investigasi — kalau tidak difilter, event ini "menenggelamkan" sinyal yang justru dicari. Berbeda dari klasifikasi (§9.6.3) yang mengelompokkan, noise reduction secara aktif **mengecualikan** kategori tertentu dari view utama (tapi tidak menghapusnya dari data mentah — selalu simpan versi lengkap).

| Sumber Noise Umum | Kenapa Dominan | Strategi Filter |
|---|---|---|
| Package manager update rutin | Ratusan-ribuan file `mtime` berubah sekaligus saat `apt upgrade` | Filter berdasarkan window waktu maintenance terjadwal (cross-ref Bab 3 §3.6.3) |
| Log rotation itu sendiri | Setiap rotasi menyentuh banyak file sekaligus | Cross-ref §9.11 — bedakan rotasi wajar dari anomali |
| Temp file volatile aplikasi | Browser cache (Bab 5 §5.14), aplikasi yang sering nulis temp file | Exclude path `/tmp`, `~/.cache/` dari view utama KECUALI sedang investigasi area itu spesifik |
| Cron/systemd timer rutin legitimate | Housekeeping script (logrotate, tmpwatch) jalan terjadwal | Whitelist unit/cron yang sudah dikonfirmasi legitimate (Bab 6 §6.9) |

```bash
# Contoh exclude noise umum di psort
psort.py -o l2tcsv -w timeline_filtered.csv timeline.plaso \
  "NOT (filename contains '/tmp/' OR filename contains '.cache')"
```

> ⚠️ **Noise reduction bukan penghapusan data:** Selalu simpan timeline_full.csv utuh sebagai arsip — filter hanya untuk mempercepat *review awal*. Kesimpulan akhir laporan tetap harus bisa ditelusuri balik ke data lengkap kalau ada pertanyaan/tantangan terhadap temuan.

#### 9.6.5 Menyatukan Jadi Satu Timeline Final

**Pengertian & Fungsi:**
Langkah terakhir — menggabungkan output §9.6.1-§9.6.4 (bodyfile, plaso export, atau kombinasi keduanya kalau sebagian sumber tidak didukung parser plaso) jadi satu file timeline master, terurut kronologis, dengan kolom tambahan tier (§9.2) dan kategori (§9.6.3).

```bash
# Gabungkan CSV dari mactime + psort (kalau format kolom sudah diseragamkan manual)
# lalu sort ulang berdasarkan kolom timestamp
(head -1 timeline_filesystem.csv; tail -n +2 timeline_filesystem.csv; tail -n +2 timeline_full.csv) \
  | sort -t',' -k1,1 > timeline_master.csv
```

---

### 9.7 Timeline Correlation Techniques & Pivot Points 🔴

**Pengertian & Fungsi:**
Setelah timeline master (§9.6.5) siap, teknik ini menjelaskan cara **menavigasinya** secara efektif alih-alih scroll linear dari awal ke akhir.

```
Teknik 1 — PIVOT DARI IOC (cross-ref Bab 8 §8.14)
  IOC (hash/IP/path) ditemukan → cari SEMUA baris timeline yang menyebut IOC itu →
  lihat event SEBELUM dan SESUDAH kemunculan pertama sebagai konteks

Teknik 2 — ANCHOR EVENT
  Pilih satu event yang paling yakin waktunya (Tier 1-2, §9.2) sebagai "jangkar" →
  bangun kronologi maju-mundur relatif terhadap jangkar itu, bukan mencoba
  menetapkan semua waktu absolut sekaligus dari awal

Teknik 3 — GAP ANALYSIS AWAL
  Identifikasi rentang waktu tanpa event sama sekali di kategori yang harusnya aktif →
  jangan simpulkan "tidak ada aktivitas" sebelum diperiksa lewat §9.16 (gap analysis formal)
```

> 💡 **Kenapa Anchor Event (Teknik 2) lebih efektif daripada mencoba membangun timeline absolut dari nol:** Investigasi nyata jarang punya semua timestamp dengan confidence sama tingginya. Memilih satu-dua event Tier 1 sebagai jangkar (misal: waktu akuisisi memory image, Bab 7) memberi titik pasti untuk membangun relasi "sebelum/sesudah" terhadap event lain yang confidence-nya lebih rendah — lebih realistis daripada berusaha memastikan akurasi absolut semua baris sekaligus.

---

### 9.8 Anti-Forensics — Taksonomi & Overview 🔴

**Pengertian & Fungsi:**
Peta besar sebelum masuk detail — teknik anti-forensics dikelompokkan berdasarkan **apa yang coba disembunyikan/dirusak attacker**.

```
├── MENGABURKAN WAKTU
│    ├── Timestomping (manipulasi MACB)                    §9.9
│    └── Clock/timezone manipulation                        §9.14
│
├── MENGHILANGKAN JEJAK
│    ├── Secure deletion & wiping                            §9.10
│    └── Log/audit trail tampering                             §9.11 (+ Bab 3 §3.7)
│
├── MENYEMBUNYIKAN DATA (bukan menghapus)
│    └── Data hiding (slack space, xattr, steganografi)         §9.12
│
└── MERUSAK/MENGACAUKAN PROSES INVESTIGASI ITU SENDIRI
     └── Anti-forensic tooling yang menyasar tool investigator     §9.15
```

> 📌 **Prinsip lintas kategori:** Hampir semua teknik anti-forensics **meninggalkan jejak dari usaha menyembunyikan itu sendiri**, meski jejak asli yang ingin disembunyikan berhasil dihilangkan — prinsip ini yang mendasari §9.9-§9.12 secara konsisten: bukan mencari "yang hilang", tapi mencari "bekas dari proses menghilangkannya".

---

### 9.9 Timestomping — Deep Dive 🔴

**Pengertian & Fungsi:**
Bab 2 §2.1.3 sudah memperkenalkan teknik dasar timestomping di Ext4 dan keterbatasan deteksinya — bagian ini memperdalam **metodologi deteksi** dengan fondasi semantics §9.3 yang sekarang sudah jelas.

```bash
# Teknik dasar (recap, detail di Bab 2 §2.1.3)
touch -t 202001010000 /path/file    # set mtime/atime ke waktu arbitrer

# ===== DETEKSI 1: Inconsistency antar MACB =====
# crtime (B) LEBIH BARU dari mtime (M) adalah MUSTAHIL secara logis kalau tidak
# ada manipulasi — file tidak bisa "diubah" sebelum "dibuat"
stat -c "B=%W M=%Y" /path/file
# Kalau B > M → red flag KUAT mtime di-timestomp mundur

# ===== DETEKSI 2: Cross-check Ext4 journal (jbd2, Bab 2 §2.2) =====
# Journal mencatat transaksi metadata SECARA TERPISAH dari inode itu sendiri —
# kalau ada entry journal yang menyebut modifikasi inode ini pada waktu yang
# TIDAK COCOK dengan mtime yang tercatat sekarang, itu bukti kuat manipulasi
debugfs -R "logdump -i <inode_number>" /dev/sda1

# ===== DETEKSI 3: Presisi nanodetik yang janggal =====
# touch/tools timestomping umum sering menghasilkan presisi BULAT (00000000 nanodetik)
# sementara aktivitas normal sistem hampir selalu punya sisa nanodetik acak
stat -c "%y" /path/file    # perhatikan bagian setelah titik desimal — semua nol
                            # di banyak file berdekatan adalah pola mencurigakan

# ===== DETEKSI 4: Cross-check directory entry vs inode (Bab 2 §2.4.1) =====
# Timestamp di direktori (kalau filesystem/tool investigasi menyimpannya terpisah)
# dibandingkan dengan inode itu sendiri
```

> ⚠️ **Batas realistis deteksi timestomping:** Kalau attacker HANYA mengubah `mtime`/`atime` (yang mana kebanyakan tool timestomping publik memang cuma bisa itu, `crtime` jauh lebih sulit dimanipulasi tanpa akses langsung ke struktur inode), Deteksi 1 di atas sangat efektif. Tapi kalau attacker punya akses cukup dalam untuk memanipulasi `crtime` **dan** journal sekaligus (butuh tool khusus level kernel/raw disk access), deteksi jadi jauh lebih sulit — di titik itu, satu-satunya jalan tersisa adalah korelasi dengan sumber independen di luar filesystem itu sendiri (Tier 1 di §9.2: log server terpusat, memory image).

---

### 9.10 Secure Deletion & Data Wiping 🔴

#### 9.10.1 `shred`/`wipe`/`dd` Overwrite Patterns

**Pengertian & Fungsi:**
Berbeda dari `rm`/`unlink` biasa (yang cuma menghapus directory entry dan menandai blok bebas, isi data masih ada sampai di-overwrite — cross-ref Bab 2 §2.3.2, §2.5.9), tools secure deletion secara aktif **menimpa** isi blok data dengan pola tertentu sebelum menghapus, dirancang supaya recovery jadi mustahil/sangat sulit.

```bash
# shred — overwrite berkali-kali dengan pola berbeda sebelum unlink
shred -vzn 3 /path/file    # 3 pass random + 1 pass zero di akhir, lalu bisa -u untuk hapus juga

# dd untuk wipe blok/partisi mentah
dd if=/dev/zero of=/dev/sdXn bs=1M status=progress
dd if=/dev/urandom of=/dev/sdXn bs=1M status=progress

# wipe — tool khusus lain dengan default pola DoD-style
wipe -rf /path/file
```

#### 9.10.2 Deteksi Bekas Wiping

**Pengertian & Fungsi:**
Meski isi file sudah tertimpa, **pola** overwrite-nya sendiri bisa jadi indikator forensik — blok yang seluruhnya nol atau seluruhnya pola berulang tertentu di tengah-tengah unallocated space yang biasanya berisi data acak sisa file lama adalah tanda mencurigakan.

```bash
# Cari region unallocated space dengan pola seragam (indikasi wiping) —
# blocks_hashdb atau scan manual dengan hexdump pada extent yang teridentifikasi
sudo dd if=/dev/sda1 bs=4096 skip=<block_number> count=1 2>/dev/null | xxd | head -5
# Blok seluruhnya "00 00 00 00..." atau pola berulang jelas ≠ data acak sisa file normal

# Cek journal (Bab 2 §2.2) untuk jejak operasi write besar pada inode yang sekarang
# sudah tidak ada isinya — journal bisa jadi bukti "sesuatu terjadi di sini" meski
# isi filenya sendiri sudah tidak bisa direcover
```

> 📌 **Realita keterbatasan:** Kalau `shred`/`dd` berhasil dijalankan dengan benar dan sistem sudah cukup lama berjalan setelahnya (blok teroverwrite ulang lagi oleh aktivitas normal), deteksi bekas wiping jadi sangat sulit dari sisi filesystem semata. Journal (Bab 2 §2.2) dan log eksekusi command (`.bash_history` kalau belum ikut dibersihkan, atau `audit.log` EXECVE — Bab 8 §8.16 relevan kalau PAM/audit juga jadi target) sering jadi satu-satunya bukti bahwa proses wiping pernah terjadi.

#### 9.10.3 Unlink vs Overwrite vs TRIM 🟡

**Pengertian & Fungsi:**
Tiga mekanisme berbeda yang sering disamaratakan sebagai "data terhapus" padahal implikasi recovery-nya jauh berbeda — pemahaman ini krusial untuk menilai realistis-tidaknya usaha recovery di kasus tertentu.

| Mekanisme | Apa yang Terjadi | Recoverability |
|---|---|---|
| **Unlink** (`rm` biasa) | Directory entry dihapus, inode ditandai bebas, **isi blok data TIDAK disentuh** sampai di-realloc | Tinggi — selama blok belum di-reuse (Bab 2 §2.3, §2.5.9); mirip prinsip "deleted-but-running" Bab 8 §8.5.1 tapi untuk file biasa (bukan proses) |
| **Overwrite** (`shred`, `dd`) | Isi blok data secara aktif ditimpa data lain sebelum/sesudah unlink | Sangat rendah — praktis mustahil recovery isi asli kalau overwrite sempurna |
| **TRIM** (SSD, cross-ref §9.10.4) | Controller SSD diberi tahu blok tidak lagi dipakai, controller **bebas** membersihkannya kapan saja (tidak instan, tidak deterministik) | Tidak dapat diprediksi — bisa langsung hilang total (kalau TRIM segera dieksekusi controller) atau masih ada sesaat (tergantung firmware & timing) |

> ⚠️ **TRIM mengubah total asumsi forensik gaya HDD:** Semua teknik recovery klasik (Bab 2 §2.5.9 inode carving) mengasumsikan blok yang di-unlink **isinya tetap ada** sampai benar-benar di-reuse filesystem. Di SSD dengan TRIM aktif (default di kebanyakan distro modern lewat `fstrim` terjadwal atau opsi mount `discard`), asumsi ini **tidak berlaku** — blok bisa sudah dikosongkan controller dalam hitungan detik-menit setelah unlink, jauh sebelum filesystem sendiri sempat me-reuse-nya secara logis.

```bash
# Cek apakah TRIM aktif di sistem yang diinvestigasi — penentu realistis-tidaknya
# ekspektasi recovery file yang baru saja dihapus
cat /sys/block/sdX/queue/discard_max_bytes    # >0 berarti device mendukung TRIM
systemctl status fstrim.timer                  # cek apakah scheduled TRIM aktif
mount | grep discard                            # cek opsi mount 'discard' (TRIM real-time per-operasi)
```

---

### 9.11 Log Rotation vs Deletion vs Tampering 🔴

**Pengertian & Fungsi:**
Decision tree formal untuk membedakan tiga penyebab berbeda dari "log yang hilang/kosong" — kesalahan paling umum di lapangan adalah langsung menyimpulkan tampering (Bab 3 §3.7) padahal penjelasannya bisa jadi rotasi normal (Bab 3 §3.2.5) yang sepenuhnya wajar.

```
Log ditemukan hilang/kosong/pendek dari yang diharapkan
│
├── Q1: Apakah ada file rotasi (.1, .2.gz, dst) yang mencakup periode tersebut?
│    ├── YA, dan isinya lengkap           → ROTASI NORMAL, bukan masalah (Bab 3 §3.2.5)
│    └── TIDAK ada sama sekali             → lanjut Q2
│
├── Q2: Apakah retention policy (logrotate `rotate N`) memang HANYA mencakup
│        rentang waktu yang lebih pendek dari yang dicari?
│    ├── YA, sudah di luar retention window → DELETION WAJAR (kadaluarsa alami),
│    │                                          BUKAN tampering — cross-ref Bab 3 §3.2.5
│    └── TIDAK, harusnya masih dalam window  → lanjut Q3
│
├── Q3: Apakah mtime file log & ukurannya konsisten dengan pola rotasi normal
│        di periode SEBELUM dan SESUDAHNYA (baseline dari file yang tidak
│        hilang)?
│    ├── YA, konsisten (misal ukuran 0 karena service memang idle)  → WAJAR
│    └── TIDAK, ukuran/mtime janggal dibanding baseline               → lanjut Q4
│
└── Q4: Apakah ada gap logging di journald/log server terpusat (Tier 1-2,
         §9.2) pada RENTANG WAKTU YANG SAMA?
      ├── TIDAK ada gap di sumber independen → kemungkinan besar TAMPERING pada
      │                                         sumber lokal spesifik ini (Bab 3 §3.7)
      └── YA, sumber independen JUGA menunjukkan gap → pertimbangkan penjelasan
                                                         sistemik (service down,
                                                         network outage), bukan
                                                         otomatis tampering bertarget
```

> 💡 **Kenapa decision tree ini penting:** Menuduh tampering padahal sebenarnya rotasi/retention normal merusak kredibilitas laporan investigasi — sebaliknya, mengabaikan gap yang sebenarnya tampering karena "mungkin cuma rotasi biasa" bisa melewatkan bukti kunci. Urutan pertanyaan di atas memaksa eliminasi penjelasan paling sederhana/wajar dulu sebelum melompat ke kesimpulan anti-forensics.

---

### 9.12 Data Hiding Techniques 🟡

**Pengertian & Fungsi:**
Teknik menyembunyikan data **tanpa menghapusnya** — attacker menyimpan payload/informasi di lokasi yang tidak biasa diperiksa tools standar.

```bash
# Slack space — sisa ruang di blok terakhir file yang tidak terpakai penuh
# (ukuran file tidak kelipatan block size) bisa menyimpan data sisa/sengaja disisipkan
sudo blkcat -s /dev/sda1 <inode_number>    # baca slack space spesifik inode (Sleuthkit)

# Extended attributes (xattr) sebagai hiding spot — jarang diperiksa tools standar
getfattr -d -m - /path/file 2>/dev/null
find / -xdev -exec sh -c 'getfattr -d "$1" 2>/dev/null | grep -q . && echo "$1"' _ {} \; 2>/dev/null

# Steganografi dalam file (gambar/audio) — sekilas, deteksi mendalam di luar
# cakupan cheat sheet ini, tapi tanda awal bisa dicek lewat entropy/ukuran anomali
file suspicious_image.jpg
ls -la suspicious_image.jpg    # ukuran jauh lebih besar dari resolusi wajarnya
```

> 📌 **Extended attributes sering luput dari pemeriksaan rutin** karena `ls -la` standar tidak menampilkannya sama sekali (cuma muncul tanda `+` di permission kalau ada xattr) — jadikan `getfattr` bagian rutin checklist untuk file yang sudah dicurigai lewat jalur lain (Bab 8), bukan cuma dicek kalau kebetulan teringat.

---

### 9.13 Filesystem/Volume Snapshots — LVM/Btrfs/VM 🟡

**Pengertian & Fungsi:**
Kebalikan dari kebanyakan bagian di Bab 9 (yang membahas cara attacker menghilangkan jejak) — snapshot adalah **counter anti-forensics**: kalau tersedia dan sempat diambil sebelum insiden atau secara terjadwal, snapshot menyimpan state filesystem/volume di titik waktu tertentu **terlepas** dari apapun yang attacker lakukan ke live filesystem sesudahnya.

```bash
# LVM snapshot — cek keberadaan snapshot yang mungkin menyimpan state sebelum insiden
lvs -a -o +lv_time    # daftar logical volume termasuk snapshot, dengan waktu pembuatan
lvdisplay /dev/vgname/snapshot_name

# Mount snapshot LVM secara read-only untuk perbandingan dengan live filesystem
sudo mount -o ro /dev/vgname/snapshot_name /mnt/snapshot_analysis

# Btrfs snapshot
sudo btrfs subvolume list -a /
sudo btrfs subvolume show /path/ke/snapshot

# VM-level snapshot (kalau host adalah hypervisor) — cek metadata snapshot
# di luar guest OS, bukan dari dalam sistem yang diinvestigasi
# (contoh gaya command tergantung hypervisor: virsh, VBoxManage, vmware-cmd, dst)
virsh snapshot-list <nama_vm>
```

> 💡 **Kenapa ini penting dicek di AWAL investigasi, bukan belakangan:** Kalau timestomping (§9.9) atau wiping (§9.10) sudah dilakukan attacker di live filesystem, snapshot yang diambil **sebelum** insiden — kalau kebetulan ada, baik dari kebijakan backup rutin maupun snapshot pre-maintenance yang lupa dihapus — bisa jadi jalan pintas untuk mem-bypass semua usaha anti-forensics itu sekaligus. Selalu cek keberadaan snapshot sebelum menyimpulkan bahwa evidence tertentu "sudah hilang total".

---

### 9.14 Clock Drift, NTP & VM Time 🔴

**Pengertian & Fungsi:**
Menggabungkan dua sisi: (1) **drift alami** yang perlu diukur dan dikompensasi sebelum timeline dipercaya, dan (2) **manipulasi clock yang disengaja** sebagai teknik anti-forensics — keduanya sama-sama berujung pada timestamp yang tidak mencerminkan waktu nyata, tapi penyebab dan cara deteksinya beda.

```bash
# ===== DRIFT ALAMI =====
# Bab 3 §3.1.3 sudah memperkenalkan pengecekan dasar — di sini diperdalam untuk
# KUANTIFIKASI seberapa jauh drift-nya, bukan cuma cek sinkron/tidak
chronyc tracking
# Perhatikan field "System time" (offset saat ini) dan "Frequency" (laju drift)
ntpq -p    # kalau pakai ntpd, kolom "offset" menunjukkan selisih dalam milidetik

# ===== VM TIME — ISU KHUSUS GUEST vs HOST =====
# Guest VM bisa punya clock yang drift lebih cepat dari host karena virtualisasi
# timer yang tidak sepresisi hardware fisik — terutama kalau clean boot/snapshot
# restore mengacaukan referensi waktu guest sesaat
cat /sys/hypervisor/uuid 2>/dev/null   # indikasi berjalan sebagai Xen guest
systemd-detect-virt                     # deteksi platform virtualisasi secara umum
systemctl status qemu-guest-agent 2>/dev/null    # time sync agent untuk QEMU/KVM
systemctl status vmtoolsd 2>/dev/null             # VMware Tools, termasuk time sync

# ===== MANIPULASI SENGAJA (ANTI-FORENSICS) =====
# Riwayat perubahan clock manual — kalau tercatat di journald sebelum dimatikan/diubah
journalctl -u systemd-timesyncd -u chronyd --no-pager | grep -i "step\|jump\|offset"
# 'date -s' manual meninggalkan jejak di shell history (Bab 4 §4.10) & audit EXECVE (Bab 8)
grep -E "^date |^timedatectl set-time" /root/.bash_history /home/*/.bash_history 2>/dev/null
```

> ⚠️ **Kenapa VM time jadi isu khusus, bukan cuma "drift biasa":** Snapshot restore VM (§9.13) bisa membuat guest clock "melompat mundur" ke waktu snapshot diambil, lalu perlahan re-sync ke waktu sebenarnya — kalau investigator tidak sadar sistem yang diperiksa adalah VM yang baru saja di-restore dari snapshot, lompatan waktu ini bisa disalahartikan sebagai bukti clock manipulation yang disengaja oleh attacker, padahal artefak virtualisasi biasa.

> 📌 **Membedakan drift alami dari manipulasi sengaja:** Drift alami biasanya **kecil dan gradual** (order milidetik-detik per hari tanpa NTP), sementara manipulasi sengaja biasanya **melompat besar dan tiba-tiba** (`date -s` mengubah jam berjam-jam/berhari-hari sekaligus). Kombinasikan dengan §9.9 Deteksi 3 (presisi nanodetik janggal) — clock yang di-set manual sering menghasilkan timestamp berikutnya dengan presisi sub-detik yang "terlalu bulat" dibanding kalau berjalan natural dari NTP-synced clock.

---

### 9.15 Anti-Forensic Tooling Overview 🟡

**Pengertian & Fungsi:**
Katalog singkat kategori tools yang umum dipakai attacker untuk teknik-teknik §9.9-§9.12 — sekadar awareness supaya investigator tahu apa yang mungkin dihadapi, bukan tutorial penggunaan.

| Kategori | Contoh Tool/Teknik | Target |
|---|---|---|
| Timestomping script | Script custom berbasis `touch`/syscall `utimensat()` langsung | MACB (§9.9) |
| Log wiper | Script yang selektif menghapus baris log spesifik (bukan seluruh file) | Log plaintext (Bab 3 §3.7.1) |
| Anti-forensic LKM | Rootkit yang sekaligus punya fungsi menghapus jejak dirinya sendiri | Kernel-level (Bab 8 §8.8) |
| History cleaner | Script yang membersihkan `.bash_history` DAN turunan lain (`.python_history`, dst — Bab 4 §4.11) selektif | Shell artifacts |

> 📌 **Nilai forensik dari keberadaan tool ini sendiri:** Kalau ditemukan sisa-sisa tool anti-forensics (di `.bash_history` yang lupa dibersihkan, atau di direktori staging seperti Bab 1 §1.2.6), itu sendiri jadi bukti kuat **niat** (intent) — melengkapi bukti teknis dari §9.9-§9.12 dengan konteks bahwa penghilangan jejak memang disengaja, bukan kebetulan/human error administratif.

---

### 9.16 Evidence Gap Analysis — Formal Methodology 🔴

**Pengertian & Fungsi:**
Generalisasi penuh dari Bab 3 §3.9 (yang tadinya khusus sumber log) — sekarang metodologi formal yang berlaku ke **seluruh** kategori evidence di Bab 1-8, memakai source weighting §9.2 sebagai dasar perhitungan.

```
Proses Formal Evidence Gap Analysis:

LANGKAH 1 — Identifikasi klaim/pertanyaan investigasi spesifik
   (contoh: "Apakah attacker mengakses file X pada waktu Y?")

LANGKAH 2 — Daftar SEMUA sumber yang seharusnya punya jejak kalau klaim benar
   Cross-ref §9.4 (inventarisasi sumber) — jangan cuma sumber yang kebetulan sudah dicek

LANGKAH 3 — Untuk tiap sumber di Langkah 2, tentukan statusnya:
   ├── ADA & mendukung klaim
   ├── ADA & bertentangan dengan klaim
   ├── TIDAK ADA karena scope-nya memang tidak mencakup ini (mis. auditd tidak aktif,
   │     Bab 8 §8.16 — bukan gap yang mencurigakan, cuma keterbatasan by design)
   └── TIDAK ADA padahal SEHARUSNYA ada (gap sesungguhnya)

LANGKAH 4 — Untuk tiap "gap sesungguhnya" di Langkah 3, jalankan §9.11 (kalau
   terkait log) atau evaluasi tampering lain (§9.9, §9.10) sebelum menyimpulkan

LANGKAH 5 — Hitung confidence akhir berdasarkan kombinasi Tier (§9.2) sumber
   yang MENDUKUNG klaim, dikurangi bobot dari gap yang tidak terjelaskan
```

> 💡 **Beda formal method ini dengan sekadar "mencatat keterbatasan" secara informal:** Metodologi terstruktur ini memaksa investigator memeriksa **semua** sumber yang relevan (Langkah 2) sebelum menyimpulkan gap benar-benar ada, bukan cuma mencatat "tidak ketemu" di satu-dua tempat yang kebetulan sudah dicek. Ini konsisten dengan prinsip §9.2 bahwa independensi sumber lebih penting daripada jumlah sumber yang dicek.

---

### 9.17 Reporting — Confidence Level dalam Timeline

**Pengertian & Fungsi:**
Standar penulisan level keyakinan untuk tiap klaim di laporan akhir — output langsung dari §9.2 (source weighting) dan §9.16 (gap analysis), supaya laporan tidak menyamaratakan semua klaim dengan bahasa yang sama pastinya.

| Label | Kriteria | Bahasa Laporan |
|---|---|---|
| **Confirmed** | ≥2 sumber Tier 1-2 independen sepakat | "Terkonfirmasi bahwa..." |
| **Corroborated** | 1 sumber Tier 1-2 + penguat Tier 3-4 | "Didukung kuat oleh bukti bahwa..." |
| **Single-source** | Hanya sumber Tier 3, tidak ada penguat independen | "Berdasarkan satu sumber (X), diduga..." |
| **Inferred** | Hanya sumber Tier 4 (inferensial) | "Ada indikasi tidak langsung bahwa... namun tidak dapat dipastikan" |
| **Unresolved gap** | Evidence yang seharusnya ada tapi tidak ditemukan, tidak terjelaskan oleh §9.11 | "Tidak dapat ditentukan karena keterbatasan evidence: [sebutkan gap spesifik]" |

> ⚠️ **Jangan pernah menyamaratakan label ini demi laporan terlihat lebih meyakinkan** — kredibilitas laporan forensik justru dibangun dari kejujuran proporsional tentang kekuatan tiap klaim, bukan dari kepastian yang seragam di semua bagian.

---

### 9.18 Tabel Korelasi — Pertanyaan Investigasi ke Teknik

| Pertanyaan | Bagian Utama | Cross-ref |
|---|---|---|
| Seberapa saya boleh percaya sumber ini? | §9.2 | Bab 3 §3.9 |
| Apa arti sebenarnya timestamp yang saya lihat? | §9.3 | Bab 2 §2.1.2 |
| Bagaimana menyatukan log+filesystem+browser jadi satu timeline? | §9.6 | Bab 2, 3, 5 |
| Timeline saya kebanjiran noise, bagaimana mempersempit? | §9.6.4 | — |
| Bagaimana mulai menavigasi timeline besar dari satu temuan? | §9.7 | Bab 8 §8.14 |
| Apakah timestamp file ini dimanipulasi? | §9.9 | Bab 2 §2.1.3 |
| Apakah data yang hilang benar-benar terhapus atau masih recoverable? | §9.10.3 | Bab 2 §2.3, §2.5.9 |
| Log ini hilang karena rotasi wajar atau sengaja dihapus? | §9.11 | Bab 3 §3.2.5, §3.7 |
| Apakah ada data tersembunyi (bukan dihapus) di sistem ini? | §9.12 | — |
| Apakah ada state lama yang masih bisa diselamatkan lewat snapshot? | §9.13 | — |
| Apakah clock sistem ini bisa dipercaya? | §9.14 | Bab 3 §3.1.3 |
| Bagaimana menyimpulkan sesuatu meski sebagian evidence hilang/dimanipulasi? | §9.16 | Bab 3 §3.9 |
| Bagaimana menulis level keyakinan yang jujur di laporan? | §9.17 | — |

---

### 9.19 Ringkasan Command & Tools Cheat Sheet

```bash
# ===== MACB & TIMESTAMP SEMANTICS =====
stat -c "M=%Y A=%X C=%Z B=%W" /path/file
mount | grep <mountpoint>    # cek relatime/noatime

# ===== SUPER TIMELINE — MANUAL (SLEUTHKIT) =====
fls -r -m / /dev/sda1 > bodyfile.txt
mactime -b bodyfile.txt -d > timeline_filesystem.csv

# ===== SUPER TIMELINE — PLASO =====
log2timeline.py --storage-file timeline.plaso /path/ke/image
psort.py -o l2tcsv -w timeline_full.csv timeline.plaso
psort.py -o l2tcsv -w timeline_incident.csv timeline.plaso \
  "date > '2026-08-14 08:00:00' AND date < '2026-08-14 12:00:00'"

# ===== TIMESTAMP NORMALIZATION =====
python3 -c "print(13350000000000000/1000000 - 11644473600)"   # Chromium epoch -> Unix

# ===== TIMESTOMPING DETECTION =====
stat -c "B=%W M=%Y" /path/file
debugfs -R "logdump -i <inode_number>" /dev/sda1

# ===== SECURE DELETION / WIPING =====
shred -vzn 3 /path/file
sudo dd if=/dev/sda1 bs=4096 skip=<block> count=1 2>/dev/null | xxd | head -5
cat /sys/block/sdX/queue/discard_max_bytes
systemctl status fstrim.timer

# ===== LOG ROTATION VS TAMPERING =====
ls -la /var/log/auth.log*
stat /var/log/auth.log

# ===== DATA HIDING =====
sudo blkcat -s /dev/sda1 <inode_number>
getfattr -d -m - /path/file

# ===== SNAPSHOTS =====
lvs -a -o +lv_time
sudo btrfs subvolume list -a /
virsh snapshot-list <nama_vm>

# ===== CLOCK DRIFT & VM TIME =====
chronyc tracking
systemd-detect-virt
journalctl -u systemd-timesyncd -u chronyd --no-pager | grep -i "step\|jump"
grep -E "^date |^timedatectl set-time" /root/.bash_history 2>/dev/null

# ===== EVIDENCE GAP / SOURCE WEIGHTING (WORKFLOW, BUKAN COMMAND TUNGGAL) =====
# 1. Daftar sumber relevan (§9.4)  2. Cek status tiap sumber  3. Jalankan §9.11 kalau
#    terkait log  4. Hitung confidence (§9.17) sebelum tulis kesimpulan
```

---

### 9.20 Mini Case Study — Workflow Analisa End-to-End

**Skenario (lanjutan langsung dari Bab 6 §6.11 → Bab 8 §8.22):** Infection chain sudah direkonstruksi sampai ditemukan PAM backdoor (Bab 8 §8.16). Investigator sekarang membangun timeline final penuh dan curiga attacker sempat mencoba anti-forensics sebelum investigasi dimulai.

```
Langkah 1 — Inventarisasi & timbang sumber yang tersedia (§9.2, §9.4)
   Tersedia: auth.log (Tier 3), journald (Tier 2), memory image sempat diambil
   sebelum sistem sempat di-reboot investigator lain (Tier 1), audit.log dengan
   PAM backdoor rule TIDAK aktif untuk EXECVE (Tier 2 tapi cakupan terbatas)

Langkah 2 — Bangun super timeline (§9.6)
   log2timeline.py --storage-file timeline.plaso /mnt/evidence/
   psort.py -o l2tcsv -w timeline_full.csv timeline.plaso
   → Timeline mentah 40.000+ baris, terlalu banyak noise dari package update rutin

Langkah 3 — Klasifikasi & noise reduction (§9.6.3, §9.6.4)
   Filter exclude /tmp, /var/cache, window maintenance terjadwal
   → Timeline turun ke ~800 baris relevan, terbagi kategori Authentication/
     Process/Persistence/Filesystem

Langkah 4 — Pivot dari IOC yang sudah ada dari Bab 8 (§9.7 Teknik 1)
   IOC: hash sample_001, IP 203.0.113.5, path /tmp/.cache/sync
   → Ditemukan seluruh rangkaian event dari SSH login sampai payload eksekusi,
     konsisten dengan rekonstruksi Bab 6/Bab 8 sebelumnya

Langkah 5 — Cek indikasi timestomping pada file terkait (§9.9)
   stat -c "B=%W M=%Y" /tmp/.cache/sync
   → B (crtime) TERNYATA LEBIH BARU dari M (mtime) — MUSTAHIL secara logis,
     konfirmasi kuat mtime file ini di-timestomp mundur oleh attacker
   debugfs -R "logdump -i <inode>" /dev/sda1
   → Journal mengonfirmasi waktu modifikasi SEBENARNYA cocok dengan crtime,
     bukan mtime yang ditampilkan `ls -la` biasa

Langkah 6 — Cek log rotation vs tampering untuk auth.log yang tampak "terlalu pendek"
   di sekitar waktu insiden (§9.11 decision tree)
   Q1: Ada file rotasi mencakup periode itu? → TIDAK
   Q2: Masih dalam retention window? → YA, harusnya masih ada
   Q3: mtime/ukuran konsisten baseline? → TIDAK, ukuran jauh lebih kecil dari biasa
   Q4: Ada gap di journald (sumber independen) pada waktu sama? → TIDAK ADA gap
       di journald — auth.log lokal sudah ditrim/tampering, journald tetap utuh
   → KESIMPULAN: auth.log lokal TERBUKTI di-tampering (bukan rotasi wajar),
     journald jadi sumber pengganti yang lebih dipercaya (Tier 2 vs Tier 3)

Langkah 7 — Cek clock manipulation sebagai penjelasan alternatif dulu (§9.14)
   chronyc tracking → NTP sync normal, tidak ada drift besar
   grep "date -s\|timedatectl set-time" .bash_history → NIHIL
   → Eliminasi clock manipulation sebagai penjelasan, memperkuat kesimpulan
     Langkah 5 & 6 murni timestomping + log tampering langsung, bukan geser jam sistem

Langkah 8 — Cek snapshot yang mungkin menyimpan state sebelum tampering (§9.13)
   lvs -a -o +lv_time
   → Ditemukan SATU snapshot LVM otomatis dari backup terjadwal, diambil SEBELUM
     waktu insiden — mount read-only, bandingkan auth.log di snapshot vs live
   sudo mount -o ro /dev/vg0/snap_pre_incident /mnt/snapshot_analysis
   diff /mnt/snapshot_analysis/var/log/auth.log /var/log/auth.log
   → Snapshot BERISI baris-baris auth.log yang hilang di versi live — recovery
     penuh berhasil lewat jalur yang sama sekali tidak terduga attacker

Langkah 9 — Evidence gap analysis formal & confidence level (§9.16, §9.17)
   Klaim: "Attacker melakukan timestomping pada payload dan tampering pada auth.log"
   → Didukung: crtime>mtime (Tier 2, filesystem) + journal jbd2 cross-check (Tier 1)
     + journald tidak menunjukkan gap sementara auth.log lokal ya (Tier 2 vs 3)
     + recovery dari snapshot LVM (Tier 1, independen total dari live filesystem)
   → Label: CONFIRMED (≥2 sumber Tier 1-2 independen sepakat)

KESIMPULAN AKHIR (menutup seluruh rangkaian Bab 6→8→9):
Attacker mendapat akses awal via SSH, memasang persistence lewat drop-in override
systemd (Bab 6), menjalankan payload dengan process masquerading dan child process
fileless (Bab 8), memasang PAM backdoor sebagai jalur cadangan (Bab 8 §8.16), LALU
mencoba anti-forensics dengan timestomping payload dan tampering auth.log lokal
(Bab 9 §9.9, §9.11) — namun usaha ini TIDAK BERHASIL sepenuhnya karena: (1) Ext4
journal menyimpan bukti independen dari inode itu sendiri, (2) journald sebagai
sumber log terpisah tidak ikut ter-tampering, dan (3) snapshot LVM rutin yang
sudah ada sebelum insiden menyimpan salinan auth.log utuh. Kombinasi tiga sumber
independen ini (Tier 1-2, §9.2) menghasilkan confidence CONFIRMED untuk seluruh
rantai kejadian, membuktikan bahwa usaha anti-forensics attacker — meski cukup
canggih untuk melewati pemeriksaan `ls -la` sepintas — tidak cukup untuk melewati
metodologi cross-source yang dibangun sejak Bab 3 (source weighting) sampai Bab 9
(evidence gap analysis formal).
```

> 💡 **Pelajaran penutup seri:** Anti-forensics yang paling canggih sekalipun hanya efektif melawan investigator yang mengandalkan **satu** sumber atau **satu** cara pandang. Seluruh metodologi Bab 9 — source weighting (§9.2), cross-view (gaya yang sama dengan Bab 8 §8.9), decision tree formal (§9.11), dan evidence gap analysis (§9.16) — pada dasarnya adalah satu prinsip yang sama diterapkan berulang-ulang di level berbeda: **jangan pernah percaya satu sumber sendirian saat sumber itu bisa dikuasai pihak yang sama yang sedang diinvestigasi.**
