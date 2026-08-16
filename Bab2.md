## 📌 Daftar Isi — Bab 2

- [Bab 2 — Filesystem Forensics: Ext4 & XFS](#bab-2--filesystem-forensics-ext4--xfs)
  - [2.1 Ext4 Filesystem Fundamentals](#21-ext4-filesystem-fundamentals)
    - [2.1.0 Layout Ext4 Volume](#210-layout-ext4-volume)
    - [2.1.1 Struktur Khusus Ext4 (Superblock, GDT, Bitmap)](#211-struktur-khusus-ext4-superblock-gdt-bitmap)
    - [2.1.2 Timestamps Ext4](#212-timestamps-ext4)
    - [2.1.3 Timestomping di Ext4 & Keterbatasan Deteksinya](#213-timestomping-di-ext4--keterbatasan-deteksinya)
    - [2.1.4 xattr + POSIX ACL + Linux Capabilities](#214-xattr--posix-acl--linux-capabilities)
    - [2.1.5 Inode Flags (chattr/lsattr)](#215-inode-flags-chattrlsattr)
    - [2.1.6 Inode Fields (Semua Field Penting)](#216-inode-fields-semua-field-penting)
    - [2.1.7 Extent Tree vs Block Mapping](#217-extent-tree-vs-block-mapping)
    - [2.1.8 fscrypt (Encryption)](#218-fscrypt-encryption)
    - [2.1.9 Hard Link & Symbolic Link di Ext4](#219-hard-link--symbolic-link-di-ext4)
    - [2.1.10 Sparse File & File Holes](#2110-sparse-file--file-holes)
  - [2.2 Ext4 Journal Forensics (jbd2)](#22-ext4-journal-forensics-jbd2)
    - [2.2.1 jbd2 Overview & Posisi di Filesystem](#221-jbd2-overview--posisi-di-filesystem)
    - [2.2.2 Transaction, Descriptor Block & Commit Block](#222-transaction-descriptor-block--commit-block)
    - [2.2.3 Journal Replay & Nilai Forensiknya](#223-journal-replay--nilai-forensiknya)
    - [2.2.4 Analisa Journal — debugfs logdump & Tools Lain](#224-analisa-journal--debugfs-logdump--tools-lain)
  - [2.3 Deleted & Orphan Inode](#23-deleted--orphan-inode)
    - [2.3.1 Inode Allocation/Deallocation Lifecycle](#231-inode-allocationdeallocation-lifecycle)
    - [2.3.2 unlink() & Link Count](#232-unlink--link-count)
    - [2.3.3 Inode Reuse & Konsekuensi Forensik](#233-inode-reuse--konsekuensi-forensik)
    - [2.3.4 Orphan Inode List](#234-orphan-inode-list)
  - [2.4 Deleted Directory Entries](#24-deleted-directory-entries)
    - [2.4.1 Struktur Dirent — Filename ↔ Inode Relationship](#241-struktur-dirent--filename--inode-relationship)
    - [2.4.2 Deleted Dirent & Cara Recovery](#242-deleted-dirent--cara-recovery)
    - [2.4.3 Directory Slack Space](#243-directory-slack-space)
  - [2.5 Inode Table — Ekuivalen $MFT di Ext4](#25-inode-table--ekuivalen-mft-di-ext4)
    - [2.5.1 Cara Kerja Inode Table](#251-cara-kerja-inode-table)
    - [2.5.2 Inode Header & Mode Field](#252-inode-header--mode-field)
    - [2.5.3 Isi Tiap Inode](#253-isi-tiap-inode)
    - [2.5.4 Extent Tree — Lokasi Data di Disk](#254-extent-tree--lokasi-data-di-disk)
    - [2.5.5 Inode Number & Generation Number](#255-inode-number--generation-number)
    - [2.5.6 Directory Entry Structure](#256-directory-entry-structure)
    - [2.5.7 Tools untuk Analisa Ext4](#257-tools-untuk-analisa-ext4)
    - [2.5.8 Output Sleuth Kit — Kolom Penting](#258-output-sleuth-kit--kolom-penting)
    - [2.5.9 Inode Carving & Recovery File Terhapus](#259-inode-carving--recovery-file-terhapus)
  - [2.6 XFS Internal Structure](#26-xfs-internal-structure)
    - [2.6.1 Filosofi & Perbedaan Utama dari Ext4](#261-filosofi--perbedaan-utama-dari-ext4)
    - [2.6.2 Allocation Group (AG) & Layout](#262-allocation-group-ag--layout)
    - [2.6.3 AG Superblock](#263-ag-superblock)
    - [2.6.4 AGF (Allocation Group Free Space)](#264-agf-allocation-group-free-space)
    - [2.6.5 AGI (Allocation Group Inode)](#265-agi-allocation-group-inode)
    - [2.6.6 AGFL (Allocation Group Free List)](#266-agfl-allocation-group-free-list)
  - [2.7 XFS Log/Journaling](#27-xfs-logjournaling)
    - [2.7.1 XFS Log Overview](#271-xfs-log-overview)
    - [2.7.2 Transaction & Recovery Overview](#272-transaction--recovery-overview)
  - [2.8 XFS Inode & Data Structures](#28-xfs-inode--data-structures)
    - [2.8.1 XFS Inode & Data/Attribute Fork](#281-xfs-inode--dataattribute-fork)
    - [2.8.2 XFS Timestamp & Metadata](#282-xfs-timestamp--metadata)
    - [2.8.3 XFS Reflink & Sparse File](#283-xfs-reflink--sparse-file)
  - [2.9 XFS Deleted File & Recovery](#29-xfs-deleted-file--recovery)
    - [2.9.1 Bagaimana Deletion Berbeda dari Ext4](#291-bagaimana-deletion-berbeda-dari-ext4)
    - [2.9.2 Keterbatasan Recovery XFS](#292-keterbatasan-recovery-xfs)
    - [2.9.3 Tools Analisa XFS](#293-tools-analisa-xfs)
  - [2.10 Filesystem Metadata vs File Content](#210-filesystem-metadata-vs-file-content)
  - [2.11 Korelasi Ext4/XFS Artifact (Tabel Cepat)](#211-korelasi-ext4xfs-artifact-tabel-cepat)
  - [2.12 Ringkasan Command & Tools Cheat Sheet](#212-ringkasan-command--tools-cheat-sheet)
  - [2.13 Mini Case Study — Workflow Analisa End-to-End](#213-mini-case-study--workflow-analisa-end-to-end)

*(Bab 1: Struktur Linux & Filesystem Dasar — `bab1_linux.md`.)*

---

## Bab 2 — Filesystem Forensics: Ext4 & XFS

> 💡 **Posisi Bab 2 di seri ini:** Bab 1 sudah menunjukkan "di mana lokasinya" (FHS, mount point, layer disk). Bab 2 masuk ke "bagaimana strukturnya" — persis peran Bab 2 Windows yang membedah `$MFT`/NTFS internals. Fokus utama ada di **Ext4** (filesystem default hampir semua distro modern), dengan **XFS** dibahas sebagai perbandingan karena umum di server enterprise (RHEL/CentOS) — relevan kalau kamu nanti menyambungkan seri ini ke skenario domain-joined Linux (sssd/winbind) atau server production.

> 📖 **Kalau kamu familiar seri Windows:** Ext4 **inode** adalah padanan konsep dari **MFT record** NTFS — satu struktur tetap per file yang menyimpan metadata. Bedanya paling mendasar: Ext4 **tidak punya duplikasi SI/FN** seperti NTFS (§2.1.3 akan bahas kenapa ini bikin deteksi timestomping jauh lebih sulit), dan nama file **tidak disimpan di inode sama sekali** — melainkan di struktur terpisah bernama **directory entry (dirent)** yang cuma berisi pemetaan nama↔nomor inode (§2.4).

---

### 2.1 Ext4 Filesystem Fundamentals

#### 2.1.0 Layout Ext4 Volume

**Pengertian & Fungsi:**
Sebelum masuk ke detail tiap struktur, lihat dulu peta besarnya — bagaimana sebuah partisi Ext4 dibagi secara fisik.

```
Ext4 Volume
│
├── Boot Sector (1024 byte pertama, reserved — tidak dipakai Ext4 sendiri)
│
├── Block Group 0
│   ├── Superblock (primary)          ← metadata volume keseluruhan
│   ├── Group Descriptor Table (GDT)   ← "daftar isi" semua block group
│   ├── Reserved GDT Blocks             ← ruang cadangan untuk resize online
│   ├── Block Bitmap                    ← peta block terpakai/kosong (per-group)
│   ├── Inode Bitmap                    ← peta inode terpakai/kosong (per-group)
│   ├── Inode Table                     ← array inode fisik (§2.5)
│   └── Data Blocks                      ← isi file & directory entries
│
├── Block Group 1
│   ├── Superblock (backup, di group tertentu — 1, 3, 5, 7... power of 3/5/7)
│   ├── GDT (backup)
│   ├── Block Bitmap, Inode Bitmap, Inode Table, Data Blocks
│
├── Block Group 2, 3, ... N              (pola berulang)
│
└── Journal (jbd2)                        ← biasanya inode khusus (inode #8), lihat §2.2
```

| Konsep | Analogi NTFS (Windows Bab 2) |
|---|---|
| Superblock | `$Volume` + `$Boot` (info volume) |
| Group Descriptor Table | Tidak ada padanan langsung — NTFS tidak dibagi "block group" |
| Block Bitmap | `$Bitmap` |
| Inode Table | `$MFT` (tapi terdistribusi per-block-group, bukan satu file besar) |
| Journal (jbd2) | `$LogFile` |

> 💡 **Kenapa dibagi "block group":** Ext4 membagi volume jadi banyak block group (biasanya 128MB per group) supaya data terkait (inode + isi filenya) cenderung disimpan **berdekatan secara fisik** — mengurangi seek time disk mekanikal. Ini beda filosofi dari NTFS yang punya satu `$MFT` besar di satu lokasi (walau bisa fragmented).

```bash
# Cek layout block group sebuah filesystem Ext4
sudo dumpe2fs /dev/sda3 | less
```

---

#### 2.1.1 Struktur Khusus Ext4 (Superblock, GDT, Bitmap)

**Pengertian & Fungsi:**
Detail tiap komponen yang disebutkan di §2.1.0 — ini adalah "file sistem" Ext4 sendiri, analog `$MFT`, `$Bitmap`, dll di NTFS (Windows Bab 2 §2.1.1), meski di Ext4 tidak direpresentasikan sebagai file tersembunyi yang bisa di-`ls`, melainkan struktur biner yang cuma bisa dibaca lewat tool khusus (`debugfs`, `dumpe2fs`).

| Struktur | Isi | Nilai Forensik |
|---|---|---|
| **Superblock** | Ukuran filesystem, block size, jumlah inode, mount count, waktu mount/unmount terakhir, UUID, state (clean/error) | `Last mount time` & `Last write time` bisa jadi anchor timeline; `State` yang "not clean" indikasi shutdown tidak normal |
| **Group Descriptor Table (GDT)** | Lokasi bitmap & inode table tiap block group, jumlah block/inode bebas per-group | Jarang jadi fokus langsung, tapi diperlukan tool untuk navigasi struktur |
| **Block Bitmap** | 1 bit per data block — menandai terpakai/kosong | Dasar identifikasi unallocated space (setara `$Bitmap` NTFS, Bab 1 §1.1.9) |
| **Inode Bitmap** | 1 bit per inode slot — menandai terpakai/kosong | Inode yang statusnya "kosong" di bitmap tapi datanya masih ada = kandidat kuat file terhapus (§2.3) |

```bash
# Lihat detail lengkap superblock
sudo dumpe2fs -h /dev/sda3

# Lihat info tambahan termasuk timestamp mount/write terakhir
sudo tune2fs -l /dev/sda3
```

**Field superblock paling relevan untuk forensik:**

| Field | Kegunaan |
|---|---|
| `Filesystem UUID` | Identitas permanen — sama fungsinya dengan Volume Serial Number NTFS (Windows Bab 1 §1.1.7), sering muncul lagi di `/etc/fstab` (Linux Bab 1 §1.1.12) |
| `Last mount time` | Kapan filesystem terakhir di-mount |
| `Last write time` | Kapan filesystem terakhir ditulis — berguna sebagai batas atas timeline kalau image diambil setelah sistem dimatikan |
| `Mount count` / `Maximum mount count` | Berapa kali sudah di-mount sejak fsck terakhir |
| `Filesystem state` | `clean` vs `not clean` — indikasi apakah unmount terjadi normal atau tiba-tiba (crash/cabut paksa) |

> ⚠️ **Kenapa journal disinggung di sini tapi dibahas penuh di §2.2:** Superblock menyimpan **pointer** ke inode journal (biasanya inode #8), tapi detail transaksi & isi journal itu sendiri cukup kompleks untuk jadi bahasan sendiri — persis kenapa `$LogFile` NTFS juga dapat pembahasan tersendiri di Windows Bab 2 §2.1.1, bukan cuma disebut sekilas.

---

#### 2.1.2 Timestamps Ext4

**Pengertian & Fungsi:**
Setiap inode Ext4 menyimpan timestamp — tapi strukturnya **berbeda mendasar** dari NTFS yang punya 2 set (SI & FN) yang saling silang cek (Windows Bab 2 §2.1.2). Ext4 cuma punya **satu set** timestamp per inode.

| Timestamp | Singkatan Umum | Berubah Saat |
|---|---|---|
| `atime` (Access Time) | A | File dibaca/diakses — **sering dinonaktifkan** demi performa (`noatime` mount option, lihat §2.1.5) |
| `mtime` (Modify Time) | M | Isi file berubah |
| `ctime` (Change Time) | C | **Metadata** inode berubah — permission, owner, atau isi file (BUKAN "created time" walau namanya mirip — ini kesalahpahaman paling umum bagi yang baru pindah dari Windows) |
| `crtime` (Creation Time) | — | Waktu file dibuat — **hanya ada di Ext4** (extension `ext4`, tidak ada di Ext2/Ext3), tersimpan di extra inode space |

```
Perbandingan penamaan yang sering membingungkan:
ctime  ≠ "Created time"  →  ctime sebenarnya "Change time" (metadata change)
crtime = "Created time"   →  ini yang benar-benar analog "Created" di Windows
```

```bash
# Lihat MACB timestamp lengkap sebuah file (termasuk crtime jika didukung)
stat /path/to/file

# Output stat mentah menampilkan Access, Modify, Change, dan Birth (crtime)
```

> ⚠️ **Perbedaan paling penting dari NTFS:** Karena cuma ada **satu set** timestamp (bukan SI+FN terpisah), Ext4 **tidak punya mekanisme cross-check bawaan** seperti SI vs FN mismatch di NTFS (Windows Bab 2 §2.1.3). Ini konsekuensi besar yang dibahas detail di §2.1.3 berikutnya — deteksi timestomping di Ext4 jauh lebih terbatas dibanding NTFS.

---

#### 2.1.3 Timestomping di Ext4 & Keterbatasan Deteksinya

**Pengertian:**
Sama seperti NTFS, timestamp Ext4 (§2.1.2) bisa dimanipulasi attacker (`touch -t`, `debugfs`, syscall `utimensat`) untuk menyamarkan waktu aktivitas file. Tapi **cara deteksinya jauh lebih terbatas** dibanding NTFS karena tidak ada pasangan SI/FN untuk disilangkan.

| Metode Deteksi | Ketersediaan di Ext4 | Catatan |
|---|---|---|
| **SI vs FN mismatch** (ala NTFS) | ❌ Tidak ada | Ext4 cuma satu set timestamp per inode — tidak ada pembanding internal |
| **Cross-check ke Journal (jbd2)** | ✅ Terbatas | Journal Ext4 (§2.2) circular buffer kecil, window waktunya jauh lebih pendek dari `$LogFile` NTFS — hanya berguna untuk aktivitas sangat baru |
| **crtime vs mtime/ctime logically inconsistent** | ✅ Parsial | Kalau `crtime` (Created) lebih baru dari `mtime`/`ctime` yang tercatat, itu tidak masuk akal secara logis — indikasi kuat manipulasi (mirip prinsip "Created > Modified" di NTFS) |
| **Cross-check ke command history** | ✅ Tidak langsung | Bandingkan waktu file dengan `.bash_history` (kalau ada) atau auditd log (kalau `sys_enter_utimensat`/`sys_enter_utime` di-audit) |
| **Cross-check ke aplikasi lain** | ✅ Tidak langsung | Log aplikasi (web server, package manager) yang independen dari filesystem bisa jadi pembanding eksternal |
| **Extended attribute residu** | ✅ Jarang | Beberapa tool timestomp murahan meninggalkan xattr atau tidak konsisten mengubah semua field — perlu dicek manual |

```bash
# Cek 4 timestamp inode secara detail
stat /path/to/suspicious/file

# Cek raw inode langsung lewat debugfs (kalau perlu verifikasi lebih dalam dari 'stat')
sudo debugfs -R "stat <inode_number>" /dev/sda3
```

> ⚠️ **Implikasi metodologis:** Karena Ext4 tidak punya pembanding internal setara SI/FN, kesimpulan "file ini di-timestomp" di Linux **jauh lebih sering bergantung pada bukti eksternal** (journal, log aplikasi, command history, korelasi dengan artefak lain di bab-bab berikutnya) dibanding NTFS yang bisa langsung membuktikan lewat satu file saja. Ini salah satu alasan kenapa prinsip korelasi multi-sumber (nanti dibahas penuh di bab Timeline Correlation) jauh lebih krusial di forensik Linux dibanding Windows.

> 📌 **auditd sebagai mitigasi:** Kalau sistem target punya `auditd` aktif dengan rule memantau syscall `utimensat`/`utime`, itu satu-satunya cara **langsung** menangkap aksi timestomping saat terjadi — tanpa itu, deteksi post-mortem murni dari filesystem sangat terbatas seperti dijelaskan di atas.

---

#### 2.1.4 xattr + POSIX ACL + Linux Capabilities

**Pengertian & Fungsi:**
Extended attribute (xattr) adalah mekanisme Ext4 (dan sebagian besar filesystem Linux modern) untuk menyimpan metadata **tambahan** di luar field inode standar — sedikit analog ADS di NTFS (Windows Bab 2 §2.1.4) dari sisi "data tambahan yang menempel ke file", tapi fungsinya lebih terstruktur (bukan stream data bebas, melainkan key-value pair bernamespace).

```
File
 └── xattr (key-value pairs, dikelompokkan per-namespace)
      ├── user.*        ← xattr custom, bisa diset user biasa
      ├── security.*     ← dipakai SELinux, capabilities, dll — butuh privilege
      ├── system.*        ← dipakai kernel untuk POSIX ACL
      └── trusted.*        ← hanya root/CAP_SYS_ADMIN yang bisa akses
```

| Namespace | Contoh Key | Kegunaan |
|---|---|---|
| `user.*` | `user.comment`, `user.mime_type` | Custom metadata bebas — **bisa disalahgunakan untuk menyembunyikan data kecil**, mirip prinsip ADS |
| `security.*` | `security.selinux` | Label SELinux context |
| `security.capability` | — | Menyimpan Linux Capabilities yang di-assign ke binary (lihat di bawah) |
| `system.*` | `system.posix_acl_access`, `system.posix_acl_default` | Representasi kernel untuk POSIX ACL |
| `trusted.*` | (bervariasi) | Dipakai aplikasi privileged, tidak terlihat oleh user biasa |

```bash
# Cek semua xattr sebuah file
getfattr -d /path/to/file

# Cek xattr termasuk namespace yang butuh privilege (security.*, trusted.*)
sudo getfattr -d -m - /path/to/file

# Set xattr custom (untuk pemahaman — bisa disalahgunakan attacker untuk staging kecil)
setfattr -n user.comment -v "data tersembunyi" /path/to/file
```

**POSIX ACL (Access Control List):**

Ext4 mendukung permission lebih granular dari mode bit standar (`rwxrwxrwx`) lewat POSIX ACL — mengizinkan permission spesifik per-user/per-group di luar owner/group/other biasa.

```bash
# Cek ACL sebuah file (kalau ada tambahan di luar permission standar, muncul tanda "+")
ls -l /path/to/file
# -rw-rwxr--+ 1 user user  ...    ← tanda "+" menunjukkan ada ACL tambahan

getfacl /path/to/file
```

> ⚠️ **Nilai forensik ACL:** File dengan permission terlihat "aman" (`rw-r--r--`) tapi punya ACL tambahan yang memberi akses ke user lain bisa jadi backdoor privilege — `ls -l` biasa **tidak menampilkan** ACL, cuma tanda `+` kecil yang gampang terlewat kalau tidak jeli. Selalu jalankan `getfacl` di file sensitif kalau ada tanda `+`.

**Linux Capabilities (`security.capability`):**

Mekanisme granular yang memberi binary **sebagian** privilege root (bukan full setuid) — misal `cap_net_raw` untuk binary yang butuh raw socket tanpa perlu jadi root sepenuhnya.

```bash
# Cek capabilities yang di-assign ke sebuah binary
getcap /path/to/binary

# Cari semua binary dengan capabilities di seluruh sistem (analog cek SUID binary)
sudo getcap -r / 2>/dev/null
```

> ⚠️ **Relevansi privilege escalation:** Binary dengan capability seperti `cap_setuid+ep` yang di-assign ke binary tidak standar (bukan bagian dari paket sistem resmi) adalah indikator kuat **privilege escalation backdoor** — attacker bisa memberi binary biasa kemampuan setara root tanpa perlu flag SUID yang lebih mudah dicurigai oleh audit standar (`find / -perm -4000`).

---

#### 2.1.5 Inode Flags (chattr/lsattr)

**Pengertian & Fungsi:**
Ext4 punya sekumpulan flag khusus di level inode yang mengatur perilaku file **di luar** permission Unix biasa — diset lewat `chattr`, dilihat lewat `lsattr`. Beberapa di antaranya relevan langsung untuk anti-forensik/persistence.

| Flag | Simbol `lsattr` | Efek | Relevansi Forensik |
|---|---|---|---|
| `immutable` | `i` | File **tidak bisa diubah/dihapus sama sekali**, bahkan oleh root, sampai flag dicabut | Attacker bisa pakai ini untuk **melindungi payload** dari dihapus tool remediation otomatis |
| `append-only` | `a` | File hanya bisa ditambah (append), tidak bisa di-overwrite/dipotong | Kadang dipakai untuk melindungi log dari tampering — tapi juga bisa disalahgunakan malware untuk melindungi file konfigurasi C2 |
| `nodump` | `d` | Memberi tahu utility backup (`dump`) untuk **skip** file ini | Attacker bisa flag payload mereka `nodump` supaya tidak ikut ter-backup dan lebih sulit ditemukan lewat analisis backup |
| `noatime` | — (biasanya mount option, bukan per-file flag) | Access time tidak diupdate | Kalau di-set per-filesystem, mengurangi granularitas timeline berbasis atime |
| `secure deletion` | `s` | (Jarang diimplementasi penuh di kernel modern) — menandai block ditimpa nol saat file dihapus | Kalau aktif dan berfungsi, mengurangi peluang recovery (§2.3, §2.5.9) |
| `compressed` | `c` | Menandai file dikompresi (jarang dipakai default Ext4, lebih umum di Btrfs) | Perlu tool yang aware kompresi untuk baca isi sebenarnya |

```bash
# Cek flag inode sebuah file
lsattr /path/to/file

# Cari semua file immutable/append-only di seluruh sistem — cek persistence/anti-tamper
sudo lsattr -R / 2>/dev/null | grep -E "^----i|^----a"

# Set/cabut flag (untuk pemahaman command, bukan panduan serang)
chattr +i /path/to/file    # set immutable
chattr -i /path/to/file    # cabut immutable
```

> 💡 **Kenapa `immutable` flag jadi indikator persistence yang sering terlewat:** Investigator yang mencoba menghapus/mengganti file malware yang sudah di-flag `immutable` akan mendapat error `Operation not permitted` **bahkan sebagai root** — kalau tidak familiar dengan `chattr`/`lsattr`, ini bisa membingungkan dan menghabiskan waktu. Selalu cek `lsattr` di awal saat menemukan file yang "menolak dihapus" secara aneh.

---

#### 2.1.6 Inode Fields (Semua Field Penting)

**Pengertian & Fungsi:**
Sama seperti NTFS Attributes (Windows Bab 2 §2.1.5), tapi Ext4 tidak membagi metadata jadi banyak attribute terpisah — semua field ada **langsung** di dalam satu struktur inode tetap.

| Field | Isi | Nilai Forensik |
|---|---|---|
| `i_mode` | Tipe file (regular/directory/symlink/dll) + permission bits | Tipe file & permission — dasar analisis akses |
| `i_uid` / `i_gid` | Owner user ID & group ID | Siapa pemilik file — cross-check ke `/etc/passwd` (Bab 1 §1.2.3) |
| `i_size` | Ukuran file (bisa sampai 64-bit dengan extension) | Ukuran data sebenarnya |
| `i_atime`, `i_mtime`, `i_ctime`, `i_crtime` | 4 timestamp (§2.1.2) | Timeline aktivitas file |
| `i_links_count` | Jumlah hard link menunjuk inode ini (§2.1.9, §2.3.2) | >1 = ada nama lain untuk file yang sama |
| `i_blocks` | Jumlah block fisik yang dialokasikan | Bisa beda dari `i_size` kalau ada sparse file (§2.1.10) |
| `i_flags` | Flag khusus (§2.1.5) — immutable, append-only, dll | Indikator anti-tamper/persistence |
| `i_generation` | Generation number (§2.5.5) | Membedakan inode number yang dipakai ulang |
| `i_block[]` / extent tree | Pointer ke lokasi data (§2.1.7, §2.5.4) | Lokasi fisik isi file |
| `i_extra_isize` | Ukuran area extra inode (tempat `crtime` & xattr kecil disimpan) | Menentukan apakah inode mendukung fitur Ext4 modern (crtime, nsec precision) |
| `i_dtime` | **Deletion time** — hanya terisi setelah file dihapus | **Sangat penting untuk forensik** (§2.3) — nilai 0 berarti file masih ada |

```bash
# Lihat SEMUA field inode mentah untuk satu file, termasuk yang tidak muncul di 'stat'
sudo debugfs -R "stat <inode_number>" /dev/sda3
```

> 💡 **`i_dtime` sebagai penanda paling langsung file terhapus:** Berbeda dari NTFS yang pakai flag `InUse` di header record (Windows Bab 2 §2.2.2), Ext4 punya field khusus `i_dtime` (deletion time) yang **hanya terisi nilai non-zero setelah file dihapus** — ini jadi salah satu sinyal pertama yang dicek saat mencari file terhapus lewat `debugfs`, dibahas lebih dalam di §2.3.

---

#### 2.1.7 Extent Tree vs Block Mapping

**Pengertian & Fungsi:**
Analog **Data Runs** NTFS (Windows Bab 2 §2.2.4) — mekanisme untuk menunjuk lokasi data sebenarnya di disk. Ext4 mendukung **dua skema**: block mapping (legacy, dari Ext2/Ext3) dan extent tree (modern, default Ext4).

```
Block Mapping (Legacy — Ext2/Ext3, masih didukung Ext4)
inode
 └── i_block[0..11]     ← 12 direct pointer ke block data
     i_block[12]         ← indirect pointer (menunjuk block berisi banyak pointer lagi)
     i_block[13]         ← double indirect
     i_block[14]         ← triple indirect

Extent Tree (Modern — default Ext4)
inode
 └── Extent Header + up to 4 extent entries inline
      └── (kalau file besar/fragmented) → Extent Index → Extent Leaf Block(s)
           Setiap extent = {block_awal_logis, panjang_run, block_awal_fisik}
```

| Aspek | Block Mapping | Extent Tree |
|---|---|---|
| Efisiensi untuk file besar/kontinu | Buruk — perlu banyak pointer individual | **Baik** — satu extent bisa cover ribuan block kontinu sekaligus |
| Analogi NTFS | Mirip pointer per-cluster tanpa run-length encoding | **Mirip persis Data Runs NTFS** (Windows Bab 2 §2.2.4) — sama-sama run-length based |
| Default di | Ext2, Ext3 | Ext4 (flag `extents` di superblock) |

```bash
# Cek apakah sebuah file pakai extent tree, dan lihat detail extent-nya
sudo filefrag -v /path/to/file

# Lewat debugfs, extent tree juga terlihat di output stat inode
sudo debugfs -R "stat <inode_number>" /dev/sda3
```

**Nilai forensik (sama prinsipnya dengan Data Runs NTFS):**

- **Recovery file terhapus:** kalau inode masih ada (belum ditimpa) dan extent tree-nya masih utuh, lokasi data fisik masih diketahui persis — recovery jauh lebih presisi daripada carving signature murni.
- **Fragmented file:** extent tree yang terdiri banyak extent leaf terpisah menunjukkan file fragmented — sama seperti NTFS, recovery harus ambil **semua** extent, bukan cuma yang pertama.

> ⚠️ **Tip yang sama seperti NTFS (Windows Bab 2 §2.2.4):** Soal CTF yang minta "recover file X yang sudah dihapus" kadang sengaja pakai file fragmented — selalu cek `filefrag -v` atau output `debugfs stat` untuk memastikan semua extent sudah diambil sebelum menyimpulkan recovery selesai.

---

#### 2.1.8 fscrypt (Encryption)

**Pengertian & Fungsi:**
Setara EFS di NTFS (Windows Bab 2 §2.1.7) — enkripsi **per-direktori** native Ext4 (juga didukung F2FS), berbeda dari LUKS (Linux Bab 1 §1.1.11) yang enkripsi **seluruh block device**.

| Aspek | fscrypt | LUKS (Bab 1 §1.1.11) |
|---|---|---|
| Level enkripsi | Per-direktori (policy di-set per-folder) | Seluruh partisi/volume |
| Terlihat saat mount tanpa key | Nama file **terenkripsi** (tampil sebagai base64 gibberish), isi tidak bisa dibaca | Partisi seluruhnya tidak bisa di-mount sama sekali |
| Key management | Terikat ke keyring kernel per-user/session | Terikat ke passphrase/keyfile saat unlock volume |

```bash
# Cek apakah sebuah direktori punya fscrypt policy aktif
sudo fscryptctl get_policy /path/to/encrypted/dir
```

> ⚠️ **Sama seperti EFS di Windows dan LUKS di Bab 1:** Bagian ini cuma overview posisi & identifikasi — kalau ditemukan direktori dengan fscrypt aktif tanpa key tersedia, itu kondisi "dead end" untuk analisis isi file, dicatat sebagai keterbatasan investigasi (bukan di-bypass paksa), sama persis prinsip yang sudah ditegaskan untuk LUKS di Bab 1.

---

#### 2.1.9 Hard Link & Symbolic Link di Ext4

**Pengertian & Fungsi:**
Sama seperti NTFS (Windows Bab 2 §2.1.9), Ext4 mendukung hard link — beberapa nama menunjuk ke **inode yang sama persis**. Ext4 juga mendukung symbolic link, digabung di sini karena konsepnya saling melengkapi.

```
Hard Link:
report.txt  ─┐
              ├──►  Inode #5678  ──►  Data yang SAMA persis
secret.txt  ─┘

Symbolic Link:
shortcut.txt  ──►  (isi file cuma berupa STRING path)  ──►  /home/user/target.txt
                     (inode terpisah, i_mode menandai symlink, size = panjang path)
```

| Aspek | Hard Link | Symbolic Link |
|---|---|---|
| Inode | **Sama** dengan target — `i_links_count` bertambah (§2.1.6, §2.3.2) | **Terpisah** dari target, isi datanya cuma path string |
| Lintas filesystem/partisi | ❌ Tidak bisa (harus 1 filesystem yang sama) | ✅ Bisa |
| Hard link ke directory | ❌ Tidak diizinkan (kecuali `.`/`..` oleh kernel sendiri) | ✅ Bisa (symlink ke folder manapun) |
| Kalau target dihapus | File tetap ada (data masih ada selama masih ada 1 nama lagi menunjuknya) | Symlink jadi "broken" (menunjuk ke path yang tidak ada) |

```bash
# Cek jumlah hard link & inode number sebuah file
stat /path/to/file
ls -li /path/to/file    # kolom pertama = inode number

# Cari semua file dengan inode number yang sama (hard link satu sama lain)
find / -inum <inode_number> 2>/dev/null

# Baca isi symlink (target path)
readlink /path/to/symlink
```

> 💡 **Nilai forensik sama seperti NTFS:** File yang "terlihat berbeda" (path beda) tapi punya `inode number` sama (dari `ls -li`) dan hash identik → itu hard link, bukan duplikat biasa — attacker sering pakai ini untuk membuat payload "terlihat legit" di banyak lokasi tanpa perlu copy data.

---

#### 2.1.10 Sparse File & File Holes

**Pengertian & Fungsi:**
Konsep yang **tidak ada padanannya secara eksplisit** di Windows Bab 2 — Ext4 (dan filesystem Linux umumnya) mengizinkan file punya "lubang" (hole) di tengahnya yang **tidak benar-benar dialokasikan** di disk, walau `i_size` menunjukkan ukuran penuh termasuk hole tersebut.

```
Logical view file (i_size = 1 GB):
[data][ HOLE — tidak dialokasikan sama sekali ][data]

Physical blocks di disk (i_blocks jauh lebih kecil dari i_size):
[block][block]                                  [block][block]
```

```bash
# Bandingkan ukuran logis (i_size) vs ukuran fisik terpakai (i_blocks)
ls -lsh /path/to/sparse/file    # kolom pertama (blocks) vs kolom size

# Cek detail sparse-ness lewat du (disk usage aktual) vs ls (ukuran logis)
du -h --apparent-size /path/to/file    # ukuran logis (termasuk hole)
du -h /path/to/file                     # ukuran fisik sebenarnya (tanpa hole)
```

> ⚠️ **Relevansi forensik:** Disk image (`.img`, `.qcow2` — Bab 1 §1.1.8), file swap, dan file database besar sering sparse. Kalau carving/hashing tidak sadar konsep ini, bisa salah interpretasi ukuran file atau salah membaca offset data. Sparse file juga **kadang disalahgunakan** untuk membuat file "terlihat" berukuran raksasa (misal untuk DoS storage/quota) padahal alokasi fisik sebenarnya kecil.

---

### 2.2 Ext4 Journal Forensics (jbd2)

> 📖 **Kenapa dapat section sendiri:** Sama seperti `$LogFile` NTFS dapat pembahasan detail tersendiri (disinggung di Windows Bab 2 §2.1.1 tapi kompleksitasnya besar), journal Ext4 (`jbd2` — Journaling Block Device v2) menyimpan bukti transaksi filesystem paling granular dan **sering jadi satu-satunya cara** merekonstruksi aktivitas yang sudah hilang dari inode/dirent utama.

#### 2.2.1 jbd2 Overview & Posisi di Filesystem

**Pengertian & Fungsi:**
`jbd2` adalah layer journaling generik yang dipakai Ext4 (juga OCFS2) — filenya sendiri biasanya berupa **inode khusus** (umumnya inode #8) di dalam filesystem yang sama, bukan file terpisah yang bisa di-`ls` biasa (mirip `$LogFile` NTFS yang juga hidden system file).

```
Ext4 Volume
 └── Journal Inode (biasanya inode #8)
      └── Circular buffer transaksi:
           [Descriptor Block] → [Data Blocks] → [Commit Block]
           [Descriptor Block] → [Data Blocks] → [Commit Block]
           ... (berputar, entry lama ditimpa entry baru)
```

| Mode Journaling | Yang Dicatat di Journal | Implikasi Forensik |
|---|---|---|
| `journal` (data=journal) | **Metadata + isi data** | Paling lengkap untuk forensik, tapi paling lambat performanya — jarang dipakai default |
| `ordered` (data=ordered, **default** kebanyakan distro) | **Metadata saja**, tapi data ditulis ke disk SEBELUM metadata di-commit | Journal tidak menyimpan isi file, tapi urutan commit tetap terjamin konsisten |
| `writeback` (data=writeback) | **Metadata saja**, tanpa jaminan urutan data vs metadata | Journal paling minim untuk forensik — risiko data tidak konsisten setelah crash |

```bash
# Cek mode journaling yang aktif
sudo dumpe2fs -h /dev/sda3 | grep "Default mount options"
mount | grep " / " # cek opsi data=ordered/journal/writeback di output mount
```

> ⚠️ **Kenapa mode journaling penting dicek di awal:** Kalau sistem target pakai `data=writeback` (jarang tapi ada), ekspektasi soal "apa yang bisa direkonstruksi dari journal" harus diturunkan — beda jauh dari `data=journal` yang bisa memberi isi data penuh.

---

#### 2.2.2 Transaction, Descriptor Block & Commit Block

**Pengertian & Fungsi:**
Journal Ext4 bekerja dalam unit **transaction** — sekelompok perubahan filesystem yang di-treat sebagai satu unit atomik (semua berhasil atau semua batal, tidak ada kondisi setengah-jalan).

```
Satu Transaction di Journal:
┌─────────────────────┐
│ Descriptor Block      │  ← header transaksi: daftar block mana saja yang akan diubah
├─────────────────────┤
│ Journaled Data Block 1 │  ← salinan block metadata (atau data, tergantung mode §2.2.1)
│ Journaled Data Block 2 │     yang AKAN ditulis ke lokasi aslinya
│ ...                     │
├─────────────────────┤
│ Commit Block            │  ← penanda "transaksi ini selesai ditulis penuh & valid"
└─────────────────────┘
```

| Blok | Fungsi | Nilai Forensik |
|---|---|---|
| **Descriptor Block** | Header yang mendaftar block tujuan tiap block data di transaksi ini | Menunjukkan **block mana di filesystem asli** yang terpengaruh — bisa dipetakan balik ke inode tertentu |
| **Journaled Block(s)** | Salinan konten yang akan ditulis | Kalau mode `data=journal`, ini bisa berisi **isi file** yang sudah dihapus/diubah — recovery langsung dari journal |
| **Commit Block** | Penanda transaksi valid & lengkap | Kalau commit block **tidak ada** untuk suatu transaksi (misal karena crash di tengah), transaksi itu **tidak akan di-replay** saat recovery (§2.2.3) |

> 💡 **Kenapa struktur ini penting untuk forensik:** Descriptor block secara efektif adalah **"log perubahan"** yang independen dari inode/dirent utama — mirip prinsip `$UsnJrnl` NTFS (Windows Bab 2 §2.1.1) yang mencatat perubahan bahkan setelah file dihapus dari struktur normalnya. Selama entry journal belum tertimpa entry baru (circular buffer, ukuran journal terbatas — biasanya beberapa puluh MB), riwayat perubahan block tertentu masih bisa direkonstruksi.

---

#### 2.2.3 Journal Replay & Nilai Forensiknya

**Pengertian & Fungsi:**
Journal replay adalah proses **otomatis** yang terjadi saat filesystem di-mount setelah shutdown tidak normal — kernel membaca journal, menemukan transaksi yang punya commit block lengkap, lalu menulis ulang perubahan itu ke lokasi aslinya (redo), memastikan filesystem konsisten.

```
Skenario Crash:
[Transaction A: Descriptor → Data → Commit]  ✅ LENGKAP → di-replay saat mount berikutnya
[Transaction B: Descriptor → Data → (crash sebelum Commit)]  ❌ TIDAK LENGKAP → dibuang, tidak di-replay
```

> ⚠️ **Implikasi krusial untuk akuisisi image:** Kalau image di-mount **read-write** (kesalahan fatal yang sudah diperingatkan di Linux Bab 1 §1.1.8), kernel akan **otomatis menjalankan journal replay** — ini mengubah isi filesystem (menuliskan transaksi pending ke lokasi aslinya) **sebelum investigator sempat menganalisis journal itu sendiri**, sehingga bukti mentah di journal hilang atau berubah. Ini alasan tambahan kenapa mount read-only (`-o ro`) mutlak wajib.

**Nilai forensik journal replay & analisis manual journal:**

- **Rekonstruksi aktivitas mendekati waktu crash/imaging:** Transaksi yang belum sempat direplay (kalau image diambil dari disk mati tanpa mount live dulu) adalah snapshot "niat terakhir" sistem sebelum mati — berguna untuk kasus di mana sistem dimatikan paksa di tengah aktivitas mencurigakan.
- **Window waktu terbatas:** Berbeda dari `$UsnJrnl` NTFS yang bisa disetel besar, journal Ext4 defaultnya relatif kecil (order puluhan MB) — hanya berguna untuk aktivitas **sangat baru**, bukan riwayat panjang.

```bash
# Cek apakah filesystem butuh journal recovery (biasanya otomatis saat mount)
sudo dumpe2fs -h /dev/sda3 | grep "needs_recovery"
```

---

#### 2.2.4 Analisa Journal — debugfs logdump & Tools Lain

```bash
# Dump seluruh isi journal secara mentah (butuh akses ke device/image langsung, BUKAN mount point)
sudo debugfs -R "logdump -a" /dev/sda3 > journal_dump.txt

# Dump journal untuk satu inode/block spesifik saja (lebih fokus)
sudo debugfs -R "logdump -i <inode_number>" /dev/sda3

# Cek statistik singkat journal (ukuran, lokasi, sequence number terakhir)
sudo debugfs -R "show_super_stats -h" /dev/sda3 | grep -A5 -i journal
```

| Tool | Fungsi | Catatan |
|---|---|---|
| **debugfs (logdump)** | Tool bawaan `e2fsprogs`, dump journal mentah ke teks yang bisa dibaca | Paling umum tersedia di semua distro — analog `LogFileParser.exe` untuk NTFS |
| **jls / jcat (Sleuth Kit)** | `jls` list entry journal, `jcat` extract konten block tertentu | Bagian dari The Sleuth Kit, terintegrasi dengan tool TSK lain (§2.5.7) |
| **extundelete** | Menggunakan info journal + inode untuk recovery file terhapus otomatis | Lebih fokus ke recovery daripada analisis journal murni — lihat §2.5.9 |

```bash
# Sleuth Kit — list entry journal
jls /dev/sda3

# Sleuth Kit — extract konten satu block journal spesifik
jcat /dev/sda3 <block_number>
```

> 💡 **Cara baca output `logdump`:** Cari pola `descriptor block`, diikuti beberapa block data, diakhiri `commit block` — setiap kelompok ini satu transaksi (§2.2.2). Perhatikan juga **sequence number** transaksi untuk menyusun urutan kronologis, karena journal adalah circular buffer dan urutan fisik di disk **belum tentu** urutan kronologis kalau sudah "berputar".

---

### 2.3 Deleted & Orphan Inode

> 📖 **Kenapa dapat section sendiri:** Konsep penghapusan file di Ext4 melibatkan beberapa langkah berbeda (dealokasi dirent, dealokasi inode, update link count) yang **tidak instan/atomik** dari sudut pandang investigator — memahami tiap tahap ini krusial untuk tahu **apa yang mungkin masih recoverable** tergantung tahap mana yang "sempat" terjadi sebelum image diambil.

#### 2.3.1 Inode Allocation/Deallocation Lifecycle

**Pengertian & Fungsi:**
Siklus hidup sebuah inode dari dialokasikan sampai benar-benar "hilang" dari sudut pandang forensik.

```
1. ALLOCATED         → Inode bitmap (§2.1.1) menandai slot ini "terpakai"
                          i_dtime = 0, i_links_count ≥ 1

2. FILE DIHAPUS       → unlink() dipanggil (§2.3.2)
   (jika link count    i_links_count berkurang 1
    jadi 0)

3. DEALLOCATED         → Kalau i_links_count mencapai 0:
                          - i_dtime diisi waktu penghapusan
                          - Inode bitmap ditandai "kosong" kembali
                          - Block data terkait ditandai kosong di block bitmap
                          NAMUN: data field inode (termasuk pointer ke block data lama)
                          BELUM TENTU langsung ditimpa nol — tergantung implementasi

4. REUSED               → Kernel mengalokasikan slot inode ini untuk file BARU
   (kapan saja setelah   Semua field inode ditimpa data file baru
    langkah 3)             (§2.3.3 — inode reuse)
```

> 💡 **Titik krusial untuk recovery:** Antara tahap 3 dan 4 adalah **jendela recovery** — selama slot inode belum di-reuse, field-nya (termasuk extent tree/block pointer, §2.1.7) berpotensi **masih terbaca**, walau flag bitmap sudah bilang "kosong". Ini alasan `debugfs stat` bisa menampilkan inode yang sudah dihapus tapi belum di-reuse.

---

#### 2.3.2 unlink() & Link Count

**Pengertian & Fungsi:**
`unlink()` adalah syscall yang dipanggil saat user menjalankan `rm` — **tidak langsung menghapus data**, melainkan **menghapus satu dirent** (§2.4) yang menunjuk ke inode tersebut, lalu mengurangi `i_links_count` (§2.1.6) sebanyak 1.

```
Kondisi awal:
  file.txt  ──►  Inode #5678 (i_links_count = 1)

Setelah `rm file.txt` (unlink):
  (dirent "file.txt" dihapus dari parent directory)
  Inode #5678 (i_links_count = 0)   ← karena tidak ada dirent lain yang menunjuknya
  → Inode ini SEKARANG resmi "terhapus" (masuk siklus §2.3.1 tahap 3)
```

**Kasus dengan hard link (§2.1.9) — link count > 1:**

```
Kondisi awal:
  report.txt  ─┐
                ├──►  Inode #5678 (i_links_count = 2)
  secret.txt  ─┘

Setelah `rm report.txt`:
  secret.txt  ──►  Inode #5678 (i_links_count = 1)
  → Inode BELUM dihapus (masih ada 1 nama lagi menunjuknya, i_dtime tetap 0)

Setelah `rm secret.txt` juga:
  Inode #5678 (i_links_count = 0)
  → BARU SEKARANG inode benar-benar dianggap terhapus
```

> ⚠️ **Konsekuensi penting untuk investigasi:** File dengan `i_links_count > 1` **tidak akan hilang** hanya karena satu nama-nya dihapus — investigator perlu tahu semua "nama" (dirent) yang menunjuk ke satu inode sebelum menyimpulkan "file ini masih ada/sudah hilang total". Ini juga berarti attacker bisa membuat hard link tambahan ke payload mereka sebagai bentuk "asuransi" — bahkan kalau satu salinan ditemukan & dihapus investigator, salinan lain (nama lain, inode sama) tetap ada.

```bash
# Cek link count sebuah file
stat /path/to/file | grep Links

# Cari SEMUA dirent yang menunjuk ke inode yang sama (semua "nama" file ini)
find / -inum <inode_number> 2>/dev/null
```

---

#### 2.3.3 Inode Reuse & Konsekuensi Forensik

**Pengertian & Fungsi:**
Sama seperti konsep Sequence Number di NTFS FRN (Windows Bab 2 §2.2.5), Ext4 punya mekanisme untuk membedakan inode number yang sudah dipakai ulang — tapi jauh **lebih sederhana** dan kurang eksplisit.

```
Inode #1234, generasi 1   → file_lama.txt (dibuat, dihapus)
        ↓ inode #1234 di-reuse untuk file baru
Inode #1234, generasi 2   → file_baru.exe (dibuat)
```

| Mekanisme | Ext4 | NTFS (Windows Bab 2 §2.2.5) |
|---|---|---|
| Field pembeda reuse | `i_generation` | `SequenceNumber` |
| Selalu bertambah otomatis? | Ya, tapi mekanismenya lebih terkait NFS file handle daripada dirancang khusus forensik | Ya, dirancang eksplisit untuk validasi referensi FRN |
| Sejauh mana dipakai artefak lain untuk cross-reference | **Sangat terbatas** — kebanyakan tool Linux tidak secara rutin menyertakan `i_generation` di output-nya | **Eksplisit** — LNK file, JumpList, `$UsnJrnl` semua menyimpan FRN lengkap dengan sequence number |

> ⚠️ **Perbedaan penting dari NTFS:** Karena `i_generation` jarang dicatat/dirujuk oleh artefak lain di Linux (beda dari FRN yang eksplisit dipakai LNK/JumpList Windows), **tidak ada mekanisme bawaan yang kuat** untuk memastikan "inode #1234 yang saya lihat sekarang adalah entitas yang sama dengan yang direferensikan artefak lain di masa lalu". Investigator harus lebih mengandalkan **kombinasi** timestamp + ukuran + isi data untuk memvalidasi kontinuitas identitas file, bukan cuma nomor inode.

**Implikasi paling langsung: pentingnya kecepatan akuisisi.**

Begitu slot inode di-reuse (langkah 4 di siklus §2.3.1), semua data forensik dari file lama **hilang permanen** — extent tree ditimpa, timestamp ditimpa, bahkan `i_dtime` lama pun tertimpa nilai baru. Tidak ada cara membedakan "inode ini belum pernah dipakai" vs "inode ini sudah di-reuse berkali-kali" tanpa bukti eksternal (journal §2.2, dirent lama di slack space §2.4.3).

---

#### 2.3.4 Orphan Inode List

**Pengertian & Fungsi:**
Kondisi khusus yang terjadi saat sistem **crash** ketika sebuah file sedang dalam proses dihapus (misal proses masih punya file descriptor terbuka ke file yang sudah di-`unlink()`, tapi crash terjadi sebelum kernel sempat benar-benar mendealokasikan inode-nya). Ext4 menyimpan daftar **orphan inode** ini di superblock (§2.1.1) untuk dibersihkan saat mount berikutnya.

```
Skenario: proses masih punya file descriptor terbuka ke file yang sudah di-unlink()
   (pola umum: `some_process` buka file, lalu file itu di-`rm` oleh proses lain/dirinya
    sendiri, tapi `some_process` belum menutup file descriptor-nya)
        │
        ▼
   File resmi "terhapus" dari dirent, tapi inode BELUM didealokasi penuh
   (karena kernel masih perlu file itu tetap ada selama ada proses yang membukanya)
        │
        ▼ (SISTEM CRASH di titik ini)
        ▼
   Inode masuk "orphan inode list" di superblock
        │
        ▼ (mount berikutnya)
   Kernel membersihkan orphan list — inode benar-benar didealokasi
```

> 💡 **Kenapa ini relevan untuk forensik:** Orphan inode adalah **jendela recovery tambahan** yang sangat spesifik — kalau image diambil **sebelum** mount berikutnya sempat membersihkan orphan list, inode yang secara teknis "sudah dihapus user" tapi belum sempat dibersihkan kernel **masih bisa ditemukan lengkap** lewat pemeriksaan superblock orphan list, bukan cuma lewat inode bitmap biasa.

```bash
# Cek daftar orphan inode di superblock (kalau ada)
sudo dumpe2fs -h /dev/sda3 | grep -i orphan

# debugfs juga bisa dipakai untuk investigasi manual lebih dalam
sudo debugfs -R "show_super_stats -h" /dev/sda3
```

> ⚠️ **Konteks umum kemunculan orphan inode:** Paling sering terjadi pada file log yang sedang aktif ditulis proses (`some_service.log` dihapus manual sementara service masih berjalan dan menulis ke file descriptor lama) — pola ini legal dan umum, tapi kondisi crash di titik yang sama juga bisa terjadi pada skenario attacker yang menghapus payload sementara proses payload itu sendiri masih berjalan.

---

### 2.4 Deleted Directory Entries

#### 2.4.1 Struktur Dirent — Filename ↔ Inode Relationship

**Pengertian & Fungsi:**
Ini adalah **perbedaan paling fundamental** dari NTFS: nama file **tidak pernah disimpan di inode** (§2.1.6 tidak punya field nama file sama sekali). Nama file hidup di struktur terpisah bernama **directory entry (dirent)**, yang disimpan sebagai bagian dari **isi data** directory (directory sendiri adalah file spesial berisi daftar dirent).

```
Directory "/home/user/" (sebagai FILE, isinya adalah daftar dirent berikut):
┌─────────────────────────────────────────┐
│ inode: 1234  | rec_len: 16 | name_len: 8  | file_type: 1 | name: "file.txt"    │
│ inode: 5678  | rec_len: 20 | name_len: 12 | file_type: 2 | name: "subfolder"    │
│ inode: 9012  | rec_len: 12 | name_len: 4  | file_type: 1 | name: ".bak"          │
└─────────────────────────────────────────┘
```

| Field Dirent | Isi |
|---|---|
| `inode` | Nomor inode yang direferensikan (§2.1.6, §2.5.5) |
| `rec_len` | Panjang total record ini dalam byte (termasuk padding) |
| `name_len` | Panjang nama file sebenarnya |
| `file_type` | Tipe file (regular, directory, symlink, dll) — redundan dengan `i_mode` di inode, tapi disimpan di sini juga untuk efisiensi baca direktori |
| `name` | Nama file (variable length, sepanjang `name_len`) |

> ⚠️ **Konsekuensi mendasar:** Karena nama file hidup di dirent (bagian dari isi directory), **satu inode bisa punya banyak nama** (hard link, §2.1.9, §2.3.2) — dan sebaliknya, kalau semua dirent yang menunjuk ke inode tertentu hilang, **nama file itu hilang** walau inode-nya sendiri (dengan `i_dtime=0`, isi data lengkap) masih ada. Kondisi "inode ada tapi nama tidak diketahui" ini spesifik untuk struktur seperti Ext4 — tidak ada padanan langsung di NTFS yang menyatukan nama+metadata dalam satu `$FILE_NAME` attribute per record.

---

#### 2.4.2 Deleted Dirent & Cara Recovery

**Pengertian & Fungsi:**
Sama seperti prinsip `$I30` di NTFS (Windows Bab 2 §2.2.6), ketika sebuah file dihapus, entry-nya di directory (dirent) **tidak langsung hilang secara fisik** — Ext4 hanya mengubah `rec_len` dari dirent SEBELUMNYA supaya "melompati" (menyerap) ruang dirent yang dihapus, alih-alih benar-benar menghapus byte-nya.

```
Sebelum dihapus:
[dirent A: rec_len=16] [dirent B "secret.txt": rec_len=20] [dirent C: rec_len=16]

Setelah "secret.txt" dihapus (rm):
[dirent A: rec_len=36 (16+20, "menelan" slot dirent B)] [dirent C: rec_len=16]
                          │
                          └── Byte lama dirent B (termasuk nama "secret.txt" dan
                              inode number yang direferensikan) SECARA FISIK
                              MASIH ADA di dalam block data directory ini —
                              cuma tidak lagi "dianggap" valid oleh parser normal
                              karena sudah "ditelan" record sebelumnya
```

> 💡 **Ini jendela recovery yang sangat kuat:** Selama block data directory itu sendiri belum ditimpa (misal belum ada file baru dibuat di folder yang sama dalam jumlah cukup untuk menimpa byte tersebut), nama file yang dihapus **masih bisa dibaca langsung dari raw block directory** — bahkan kalau inode aslinya sendiri sudah di-reuse (§2.3.3) untuk file lain sama sekali.

```bash
# Sleuth Kit fls — list entry directory TERMASUK yang sudah dihapus (ditandai dengan *)
fls -rd /dev/sda3

# debugfs — dump raw directory block untuk parsing manual dirent yang "tertelan"
sudo debugfs -R "stat <inode_number_folder>" /dev/sda3    # cari block number directory
sudo debugfs -R "bdump <block_number>" /dev/sda3           # dump raw block untuk analisis manual
```

**Tabel opsi flag `fls`:**

| Flag | Fungsi |
|---|---|
| `-r` | Rekursif ke sub-direktori |
| `-d` | Tampilkan HANYA entry yang sudah dihapus |
| `-p` | Tampilkan full path |

> 📌 **Cara baca output `fls`:** Entry yang sudah dihapus ditandai `*` di awal baris. Kalau inode number yang direferensikan entry terhapus **masih menunjuk ke data yang valid** (belum di-reuse, §2.3.3), file itu masih bisa di-recover isinya lewat `icat` (§2.5.7) — tapi kalau `fls` cuma menunjukkan nama tanpa inode yang valid (atau inode sudah berisi data lain), recovery isi file **tidak mungkin**, hanya namanya saja yang diketahui pernah ada.

---

#### 2.4.3 Directory Slack Space

**Pengertian & Fungsi:**
Sama seperti File Slack di NTFS (Windows Bab 1 §1.1.11), tapi versi khusus untuk block directory — ruang sisa di **akhir block directory** yang tidak lagi ditempati dirent aktif, tapi menyimpan **sisa byte dari dirent lama** sebelum block ini "menyusut" muatannya.

```
Directory Block (ukuran tetap, misal 4096 byte):
[dirent aktif 1][dirent aktif 2][dirent aktif 3]  ← total terpakai, misal 2000 byte
                                                     [SLACK — 2096 byte SISA]
                                                      ← bisa berisi sisa dirent LAMA
                                                        dari sebelum banyak file dihapus
```

> 💡 **Kenapa ini berbeda konsepnya dari §2.4.2:** §2.4.2 membahas dirent yang "ditelan" oleh record sebelumnya (masih dalam rentang panjang block yang aktif digunakan). Directory slack space adalah kondisi **lebih ekstrem** — ketika banyak file dihapus sekaligus sehingga area terpakai block menyusut jauh, menyisakan area besar di akhir block yang tidak lagi "terjangkau" oleh rantai `rec_len` manapun, tapi byte lamanya tetap fisik ada sampai block itu sendiri ditimpa penuh.

```bash
# Dump seluruh raw block directory (termasuk slack) untuk pemeriksaan manual/carving
sudo debugfs -R "bdump <block_number>" /dev/sda3 > directory_block.raw

# Cari string yang terlihat seperti nama file di slack area (heuristik sederhana)
strings directory_block.raw
```

> ⚠️ **Nilai forensik:** Directory slack adalah sumber recovery "generasi lebih lama" dibanding deleted dirent biasa (§2.4.2) — berguna untuk merekonstruksi isi folder di titik waktu yang **jauh lebih jauh ke belakang**, tapi juga lebih tidak terstruktur (tidak selalu ada `rec_len` yang valid untuk dipandu parser otomatis), sehingga sering butuh analisis manual/`strings`-based daripada tool otomatis.

---

### 2.5 Inode Table — Ekuivalen $MFT di Ext4

**Pengertian & Fungsi:** Setelah §2.1-2.4 membahas komponen-komponen terpisah, section ini menyatukan semuanya dari sudut pandang **inode table** sebagai satu struktur — persis peran `$MFT` di Windows Bab 2 §2.2.

#### 2.5.1 Cara Kerja Inode Table

```
[Disk]
  └── Ext4 Volume
        └── Block Group 0, 1, 2, ... N (§2.1.0)
              └── Inode Table (per-group, array inode berukuran tetap, biasanya 256 byte/inode)
                    ├── Inode #1  → Reserved (bad blocks inode)
                    ├── Inode #2  → Root directory "/"
                    ├── Inode #3-#7 → Reserved (journal, resize, dll — bervariasi per-implementasi)
                    ├── Inode #8  → Journal (jbd2, §2.2)
                    ├── ...
                    └── Inode #N  → File/folder biasa (dokumen user, executable, dll)
```

> 📖 **Perbedaan struktural dari `$MFT`:** NTFS punya **satu** `$MFT` besar (walau bisa fragmented) di satu lokasi konseptual. Ext4 mendistribusikan inode table **per-block-group** — artinya "database inode" Ext4 secara fisik tersebar di banyak lokasi across volume, bukan satu file monolitik. Tool seperti `debugfs`/Sleuth Kit menangani abstraksi ini secara transparan, tapi penting dipahami saat analisis manual/carving.

---

#### 2.5.2 Inode Header & Mode Field

Setiap inode diawali field `i_mode` yang menentukan tipe & permission — analog "flag" di header MFT record (Windows Bab 2 §2.2.2), walau Ext4 tidak punya signature string literal seperti `"FILE"`.

```
i_mode (16-bit)
├── 4 bit tertinggi  → Tipe file:
│     0x8000 = Regular file
│     0x4000 = Directory
│     0xA000 = Symbolic link
│     0x2000 = Character device
│     0x6000 = Block device
│     0x1000 = FIFO
│     0xC000 = Socket
└── 12 bit sisanya    → Permission bits (setuid, setgid, sticky, rwxrwxrwx)
```

```bash
# Cek tipe & mode inode langsung
sudo debugfs -R "stat <inode_number>" /dev/sda3 | grep Mode
```

> 💡 **Nilai carving untuk unallocated space:** Berbeda dari NTFS yang punya signature `"FILE"` yang mudah di-grep (Windows Bab 2 §2.2.2), Ext4 **tidak punya signature literal** seperti itu di awal tiap inode — carving inode orphan dari unallocated space jauh lebih bergantung pada **heuristik** (pola `i_mode` yang masuk akal + `i_links_count` wajar + timestamp yang masuk akal) daripada pencarian byte pattern sederhana. Ini salah satu alasan tool khusus (`extundelete`, Sleuth Kit) jauh lebih diandalkan daripada `grep`/`bulk_extractor` manual untuk kasus Ext4.

---

#### 2.5.3 Isi Tiap Inode

Rangkuman field yang sudah dibahas di §2.1.6, disusun ulang dari sudut pandang "satu paket metadata lengkap" — persis format Windows Bab 2 §2.2.3.

| Bagian | Isi | Rujukan |
|---|---|---|
| Tipe & permission | `i_mode` | §2.5.2 |
| Owner | `i_uid`, `i_gid` | §2.1.6 |
| Ukuran | `i_size`, `i_blocks` | §2.1.6, §2.1.10 (sparse) |
| Timestamp | `i_atime`, `i_mtime`, `i_ctime`, `i_crtime` | §2.1.2 |
| Link count | `i_links_count` | §2.1.9, §2.3.2 |
| Status dihapus | `i_dtime` (non-zero = dihapus) | §2.1.6, §2.3.1 |
| Flag khusus | `i_flags` (immutable, dll) | §2.1.5 |
| Generation | `i_generation` | §2.5.5 |
| Lokasi data | Extent tree / block pointer | §2.1.7, §2.5.4 |
| xattr kecil | Area extra inode | §2.1.4 |

> ⚠️ **Yang TIDAK ada di inode (beda dari MFT record NTFS):** **Nama file** dan **path**. Keduanya harus direkonstruksi dari dirent (§2.4) di directory induk — inode sendirian **tidak bisa** memberi tahu "file ini namanya apa" tanpa mencari dirent yang menunjuk ke nomor inode tersebut.

---

#### 2.5.4 Extent Tree — Lokasi Data di Disk

> 📖 Sudah dibahas detail di §2.1.7. Ringkasan posisinya dalam konteks inode table: extent tree adalah bagian dari isi inode (biasanya inline di `i_block[]` array untuk file kecil, atau menunjuk ke extent leaf block terpisah untuk file besar/fragmented) — perannya identik dengan Data Runs NTFS.

```bash
sudo filefrag -v /path/to/file
```

---

#### 2.5.5 Inode Number & Generation Number

**Inode Number** adalah "alamat" unik sebuah file di dalam inode table — analog `EntryNumber` NTFS (Windows Bab 2 §2.2.5), tapi **tanpa** sequence number terintegrasi yang eksplisit dipakai artefak lain (sudah dibahas keterbatasannya di §2.3.3).

```bash
# Cek inode number sebuah file
ls -li /path/to/file
stat /path/to/file | grep Inode

# Cari file berdasarkan inode number (kebalikan arah)
find / -inum <inode_number> 2>/dev/null
```

| Artefak | Kegunaan Inode Number di Sana |
|---|---|
| Dirent (§2.4.1) | Setiap dirent menyimpan inode number yang direferensikan |
| `$UsnJrnl`-equivalent | Ext4 **tidak punya** change journal setara `$UsnJrnl` NTFS secara native — jbd2 (§2.2) fungsinya lebih ke crash consistency, bukan audit trail perubahan file jangka panjang. Ini gap fungsional yang perlu diisi oleh auditd (dibahas di bab Log Forensics) |
| Sleuth Kit output (`fls`, `istat`) | Semua tool TSK merujuk file lewat inode number sebagai identifier utama |

> ⚠️ **Perbedaan fungsional penting dari Windows:** NTFS punya `$UsnJrnl` yang secara native mencatat histori perubahan per-FRN dalam jangka waktu relatif panjang (Windows Bab 2 §2.1.1). Ext4 **tidak punya padanan native setara itu** — jbd2 journal (§2.2) ukurannya kecil dan fokus ke crash recovery, bukan audit trail. Ini artinya untuk mendapatkan "riwayat perubahan file dari waktu ke waktu" di Linux, investigator jauh lebih bergantung pada **auditd** (kalau dikonfigurasi aktif sebelum insiden) daripada berharap filesystem sendiri menyimpannya — beda mendasar dari NTFS yang punya `$UsnJrnl` aktif by default di banyak konfigurasi.

---

#### 2.5.6 Directory Entry Structure

> 📖 Sudah dibahas detail penuh di §2.4.1-2.4.3. Section ini cuma menegaskan posisinya dalam hierarki inode table: directory adalah **file spesial** (`i_mode` bertipe direktori) yang isinya (dirujuk lewat extent tree/block pointer seperti file biasa, §2.5.4) berupa daftar dirent — bukan struktur terpisah dari mekanisme inode.

---

#### 2.5.7 Tools untuk Analisa Ext4

```bash
# debugfs — tool interaktif bawaan e2fsprogs, serbaguna untuk semua kebutuhan manual
sudo debugfs /dev/sda3
debugfs: stat <5678>          # detail inode
debugfs: ls -l /home/user      # list directory dengan detail
debugfs: cat <5678>            # dump isi file (kalau masih ada datanya)
debugfs: bdump <block_number>  # dump raw block

# The Sleuth Kit — suite tool CLI, masing-masing fokus satu tugas
fsstat /dev/sda3                      # info filesystem-level (setara dumpe2fs tapi cross-filesystem)
fls -r /dev/sda3                       # list semua file (termasuk terhapus dengan -d)
istat /dev/sda3 <inode_number>         # detail satu inode (setara debugfs stat)
icat /dev/sda3 <inode_number> > out    # ekstrak isi file dari inode number langsung
ils -r /dev/sda3                       # list semua inode (termasuk unallocated)
```

| Tool | Fungsi | Analog Windows |
|---|---|---|
| **debugfs** | Swiss-army-knife interaktif Ext4 — baca metadata, dump block, navigasi manual | Kombinasi `MFTExplorer` + akses hex manual |
| **fsstat** (TSK) | Info filesystem-level (superblock, block group) | `dumpe2fs -h`, sedikit mirip `fsutil fsinfo ntfsinfo` |
| **fls** (TSK) | List file & directory, termasuk yang terhapus | Mirip fungsi `MFTECmd` untuk listing, tapi cross-filesystem |
| **istat** (TSK) | Detail satu inode | `debugfs stat`, analog lihat satu MFT record di `MFTExplorer` |
| **icat** (TSK) | Ekstrak isi file langsung dari inode number | Analog export file dari `$MFT` record langsung (kalau resident, Windows Bab 2 §2.1.6) |
| **ils** (TSK) | List semua inode termasuk unallocated | Analog scan semua record `$MFT` termasuk `InUse=False` |

> 💡 **Kenapa Sleuth Kit jadi pilihan populer di Linux forensics:** Berbeda dari `debugfs` yang spesifik Ext-family, tool TSK (`fls`, `istat`, `icat`, dll) dirancang **cross-filesystem** — command yang sama bisa dipakai untuk Ext4 maupun (dengan dukungan terbatas) XFS/lainnya, memudahkan workflow kalau investigasi melibatkan lebih dari satu jenis filesystem sekaligus.

---

#### 2.5.8 Output Sleuth Kit — Kolom Penting

Contoh output `istat` dan kolom pentingnya (analog tabel kolom `MFTECmd`, Windows Bab 2 §2.2.8):

| Field Output `istat` | Keterangan |
|---|---|
| `Inode:` | Nomor inode |
| `Allocated` / `Not Allocated` | Status — setara `InUse` NTFS |
| `Group:` | Block group tempat inode ini berada (§2.1.0) |
| `Generation Id:` | `i_generation` (§2.5.5) |
| `uid / gid` | Owner |
| `mode:` | Permission & tipe file |
| `size:` | Ukuran file |
| `num of links:` | `i_links_count` (§2.3.2) |
| `Inode Times:` | Access/Modify/Change/(Create jika ada crtime) — §2.1.2 |
| `Direct Blocks:` / extent listing | Lokasi data fisik (§2.5.4) |

Output `fls` dengan flag `-d` (deleted only):

```
r/r * 5678(realloc):  secret.txt
```

| Simbol | Arti |
|---|---|
| `r/r` | Tipe file (regular/regular) |
| `*` | Menandakan entry sudah dihapus |
| `5678` | Inode number |
| `(realloc)` | Menandakan inode ini **sudah di-reuse** (§2.3.3) — recovery isi data **tidak mungkin lagi**, cuma nama historisnya yang diketahui |

> ⚠️ **Perhatikan tag `(realloc)`:** Ini penanda paling penting untuk membedakan "file terhapus yang masih recoverable" (tanpa tag ini, inode masih murni menunjuk data lama) vs "file terhapus yang cuma tersisa jejak nama" (dengan tag `realloc`, inode number yang sama sudah dipakai file lain — §2.3.3).

---

#### 2.5.9 Inode Carving & Recovery File Terhapus

**Pengertian & Fungsi:** Sama seperti §2.2.9 di Windows Bab 2, ini adalah alur bertingkat mengumpulkan semua opsi recovery yang sudah dibahas di section-section sebelumnya jadi satu workflow.

```
Skenario recovery bertingkat (Ext4):
1. Cek dirent aktif dulu — file mungkin masih ada dan cuma "hilang" di tempat lain
   fls -r /dev/sda3 | grep nama_file

2. Cek dirent terhapus (§2.4.2) — file dihapus tapi dirent masih "tertelan" di block directory
   fls -rd /dev/sda3
   → kalau ada tag "(realloc)" di sebelah inode number, lanjut ke langkah 4 (nama saja)
   → kalau TIDAK ada tag realloc, lanjut ke langkah 3 (recovery penuh masih mungkin)

3. Ekstrak isi file langsung dari inode (kalau belum di-reuse)
   icat /dev/sda3 <inode_number> > recovered_file

4. Kalau inode sudah di-reuse ("realloc"), cuma nama & metadata historis yang tersisa
   → Cek Directory Slack Space (§2.4.3) untuk versi dirent yang lebih lama
   → Cek Journal (§2.2.4) kalau mode data=journal aktif — mungkin ada salinan isi file
     tersimpan sementara di journal sebelum tertimpa

5. Kalau semua di atas gagal, carving generik dari unallocated space
   photorec disk.dd
   # PhotoRec bekerja berdasarkan signature isi file (magic bytes), TIDAK bergantung
   # pada struktur inode/dirent sama sekali — opsi terakhir kalau metadata sudah hilang total
```

**Tools tambahan khusus recovery Ext4:**

```bash
# extundelete — otomatisasi kombinasi inode + journal untuk recovery
sudo extundelete /dev/sda3 --restore-file path/to/file.txt
sudo extundelete /dev/sda3 --restore-all    # recovery semua file terhapus yang masih mungkin

# testdisk — GUI/TUI interaktif, mendukung banyak filesystem termasuk Ext4
sudo testdisk disk.dd
```

| Tool | Kelebihan | Keterbatasan |
|---|---|---|
| **extundelete** | Otomatis kombinasikan inode + journal, cukup satu command | Butuh unmount filesystem dulu (tidak bisa jalan di filesystem live yang di-mount) |
| **testdisk** | Interaktif, mendukung banyak filesystem, bagus untuk eksplorasi manual | Lebih lambat untuk recovery massal dibanding `extundelete` |
| **PhotoRec** | Signature-based, tidak butuh struktur filesystem sama sekali | Tidak bisa pulihkan nama file asli (beda dari metode berbasis inode/dirent) |

> ⚠️ **Batasan sama seperti NTFS (Windows Bab 2 §2.2.9):** Recovery cuma berhasil selama block data & slot inode belum ditimpa. Ext4 punya satu keuntungan tambahan dibanding NTFS untuk kasus tertentu — directory slack (§2.4.3) dan journal (§2.2) memberi **lapisan recovery tambahan** yang independen dari kondisi inode itu sendiri, tapi juga satu kerugian — tidak adanya `$UsnJrnl` setara (§2.5.5) berarti riwayat perubahan jangka panjang jauh lebih terbatas dibanding NTFS.

---

### 2.6 XFS Internal Structure

> 💡 **Kenapa XFS relevan:** Default filesystem di RHEL/CentOS/Fedora modern — kalau kamu nanti masuk ke skenario server enterprise/domain-joined Linux (relevan dengan minat kamu di AD/enterprise forensics), kemungkinan besar akan ketemu XFS, bukan Ext4. Struktur internalnya **cukup berbeda** dari Ext4 meski konsep tingkat tinggi (inode, extent, journal) tetap serupa.

#### 2.6.1 Filosofi & Perbedaan Utama dari Ext4

| Aspek | Ext4 | XFS |
|---|---|---|
| Struktur alokasi | Block group sederhana (§2.1.0) | **Allocation Group (AG)** — konsepnya mirip tapi lebih kompleks, dirancang untuk paralelisme tinggi |
| Struktur data internal | Extent tree sederhana, dirent linear/htree | **B+Tree** dipakai luas — untuk free space, inode, bahkan directory besar |
| Target use-case awal | General purpose, desktop & server kecil-menengah | Server besar, file besar, I/O paralel tinggi (dirancang awal oleh SGI untuk workload video/storage besar) |
| Journal | jbd2, terintegrasi erat dengan Ext4 (§2.2) | XFS log, arsitektur terpisah (§2.7) |
| Dukungan Sleuth Kit | Lengkap (`fls`, `icat`, `istat` semua berfungsi) | **Terbatas** — banyak tool TSK tidak full-support XFS (§2.9.3) |

> ⚠️ **Konsekuensi paling praktis untuk investigator:** Karena dukungan tooling forensik XFS jauh lebih terbatas dibanding Ext4 (khususnya Sleuth Kit), analisis XFS **lebih sering bergantung pada tool native XFS sendiri** (`xfs_db`, `xfs_repair -n` untuk diagnosa read-only) daripada tool DFIR umum lintas-filesystem.

---

#### 2.6.2 Allocation Group (AG) & Layout

**Pengertian & Fungsi:** Analog block group Ext4 (§2.1.0), tapi setiap AG adalah **filesystem mini yang hampir independen** — desain ini yang memungkinkan XFS menangani operasi paralel di banyak AG sekaligus tanpa lock contention besar.

```
XFS Volume
│
├── AG 0
│   ├── AG Superblock       ← §2.6.3
│   ├── AGF (Free Space)     ← §2.6.4
│   ├── AGI (Inode Info)      ← §2.6.5
│   ├── AGFL (Free List)       ← §2.6.6
│   ├── Inode B+Tree            ← lokasi inode di AG ini
│   └── Data Blocks
│
├── AG 1  (struktur sama persis, independen dari AG 0)
├── AG 2  ...
└── AG N
```

```bash
# Cek jumlah & ukuran Allocation Group sebuah filesystem XFS
sudo xfs_info /dev/sda3
```

> 💡 **Beda mendasar dari block group Ext4:** Block group Ext4 (§2.1.0) berbagi **satu** superblock utama (dengan backup di beberapa group tertentu). Setiap AG XFS punya **superblock sendiri-sendiri** yang independen — ini konsekuensi langsung dari filosofi "AG sebagai filesystem mini".

---

#### 2.6.3 AG Superblock

Mirip fungsi superblock Ext4 (§2.1.1), tapi khusus untuk satu AG — menyimpan info dasar AG tersebut (bukan seluruh volume, kecuali AG 0 yang superblock-nya berperan ganda sebagai superblock utama volume).

| Field | Isi |
|---|---|
| Magic number | Identifier struktur (`XFSB`) |
| Block size, sector size | Parameter dasar filesystem |
| AG count, AG size | Jumlah & ukuran total AG di volume ini |
| UUID | Identitas volume (sama fungsinya dengan UUID Ext4, Bab 1 §1.1.12) |

```bash
sudo xfs_db -r -c "sb 0" -c "print" /dev/sda3
```

---

#### 2.6.4 AGF (Allocation Group Free Space)

**Pengertian & Fungsi:** Menyimpan info **free space** dalam AG ini — analog gabungan Block Bitmap + sebagian Group Descriptor Ext4 (§2.1.1), tapi direpresentasikan sebagai **B+Tree** (dua B+Tree sebenarnya — satu diurutkan berdasarkan block awal free extent, satu lagi berdasarkan panjang free extent, untuk pencarian cepat dari dua arah berbeda).

```bash
sudo xfs_db -r -c "agf 0" -c "print" /dev/sda3
```

> 💡 **Nilai forensik:** AGF adalah titik awal untuk memahami unallocated space (Bab 1 §1.1.9) dalam konteks XFS — free extent yang tercatat di sini adalah kandidat area untuk carving, mirip peran `$Bitmap` di NTFS/Ext4 tapi dengan struktur B+Tree yang lebih kompleks untuk dinavigasi manual.

---

#### 2.6.5 AGI (Allocation Group Inode)

**Pengertian & Fungsi:** Analog Inode Bitmap Ext4 (§2.1.1), tapi juga direpresentasikan sebagai B+Tree — menyimpan info inode mana yang terpakai/kosong dalam AG ini, plus (relevan untuk §2.9) daftar **unlinked inode list** — inode yang sudah di-`unlink()` tapi belum sepenuhnya dibersihkan, konsepnya mirip orphan inode Ext4 (§2.3.4) tapi jadi mekanisme **default** XFS untuk semua penghapusan, bukan cuma kasus crash.

```bash
sudo xfs_db -r -c "agi 0" -c "print" /dev/sda3
```

> ⚠️ **Perbedaan penting dari Ext4:** Ext4 cuma punya orphan inode list untuk kasus crash spesifik (§2.3.4). XFS **selalu** memakai unlinked inode list sebagai bagian normal dari proses penghapusan file (dibahas lebih dalam di §2.9.1) — ini konsekuensi arsitektural yang membuat proses deletion XFS punya karakteristik forensik yang cukup berbeda dari Ext4.

---

#### 2.6.6 AGFL (Allocation Group Free List)

**Pengertian & Fungsi:** Daftar kecil block bebas yang di-reserve khusus untuk **kebutuhan internal B+Tree** (misal saat B+Tree perlu split/merge node dan butuh block tambahan segera, tanpa harus mencari lewat AGF dulu yang lebih lambat).

> 📌 **Relevansi forensik terbatas:** AGFL murni struktur operasional internal — jarang jadi fokus langsung investigasi, tapi penting dipahami keberadaannya supaya tidak bingung saat melihat listing AG lengkap di `xfs_db`.

---

### 2.7 XFS Log/Journaling

#### 2.7.1 XFS Log Overview

**Pengertian & Fungsi:** Setara jbd2 (§2.2), tapi arsitekturnya berbeda — XFS log biasanya berupa **area khusus** di dalam filesystem (internal log, paling umum) atau bisa juga device terpisah (external log, jarang di CTF).

```bash
# Cek apakah XFS log internal atau eksternal, dan ukurannya
sudo xfs_info /dev/sda3 | grep -A2 "^log"
```

| Aspek | jbd2 (Ext4, §2.2) | XFS Log |
|---|---|---|
| Lokasi umum | Inode khusus dalam filesystem yang sama | Area block khusus (internal) atau device terpisah (external) |
| Unit transaksi | Descriptor/Data/Commit block (§2.2.2) | Log record dengan struktur berbeda (§2.7.2) |
| Dukungan tool DFIR umum | Baik (`debugfs logdump`, Sleuth Kit `jls`/`jcat`) | **Terbatas** — kebanyakan analisis butuh tool native XFS |

---

#### 2.7.2 Transaction & Recovery Overview

**Pengertian & Fungsi:** Prinsip dasarnya **sama** dengan jbd2 (§2.2.3) — transaksi atomik, replay otomatis saat mount setelah unclean shutdown — tapi implementasi detailnya beda dan kurang terdokumentasi untuk tujuan forensik dibanding Ext4.

```bash
# Cek apakah XFS filesystem butuh log recovery (biasanya otomatis saat mount)
sudo xfs_repair -n /dev/sda3    # mode read-only/dry-run, TIDAK mengubah apapun
```

> ⚠️ **PENTING — selalu pakai flag `-n`:** `xfs_repair` **tanpa** flag `-n` akan **mengubah filesystem** (memperbaiki inkonsistensi, termasuk menjalankan log recovery) — untuk tujuan forensik, **SELALU** pakai `-n` (dry-run/no-modify) supaya cuma mendapat laporan kondisi tanpa benar-benar mengubah evidence. Ini setara pentingnya dengan aturan mount read-only (Linux Bab 1 §1.1.8).

> 📌 **Keterbatasan dokumentasi forensik XFS log:** Dibanding jbd2 yang punya tool dedicated (`debugfs logdump`, Sleuth Kit `jls`/`jcat`) dan dokumentasi forensik luas, analisis mendalam XFS log jauh lebih jarang dibahas di literatur DFIR — kalau butuh recovery data spesifik dari log XFS, `xfs_logprint` adalah titik awal paling realistis.

```bash
# Dump isi log XFS secara mentah (mirip logdump Ext4, tapi output & interpretasinya berbeda)
sudo xfs_logprint /dev/sda3
```

---

### 2.8 XFS Inode & Data Structures

#### 2.8.1 XFS Inode & Data/Attribute Fork

**Pengertian & Fungsi:** Konsep unik XFS — setiap inode punya sampai **dua "fork"** (cabang data terpisah): **data fork** (isi file sebenarnya, analog `i_block`/extent Ext4 §2.1.7) dan **attribute fork** (khusus menyimpan extended attribute, §2.1.4, terpisah secara struktural dari data fork).

```
XFS Inode
├── Core (metadata dasar — mode, uid, gid, timestamp, dst — mirip inode Ext4 §2.1.6)
├── Data Fork          ← isi file (bisa inline, extent list, atau B+Tree tergantung ukuran)
└── Attribute Fork       ← xattr (§2.1.4), terpisah dari data fork — bisa juga inline/extent/B+Tree
```

| Ukuran Data | Representasi Data Fork |
|---|---|
| Sangat kecil (muat di inode) | **Inline** — langsung di dalam inode, mirip resident attribute NTFS (Windows Bab 2 §2.1.6) |
| Sedang, sedikit extent | **Extent list** langsung di inode |
| Besar/fragmented banyak | **B+Tree of extents** — extent list-nya sendiri disimpan sebagai B+Tree terpisah |

```bash
sudo xfs_db -r -c "inode <inode_number>" -c "print" /dev/sda3
```

> 💡 **Kenapa dual-fork ini penting dipahami:** Karena attribute fork terpisah dari data fork, xattr besar (termasuk ACL kompleks, §2.1.4) tidak "bersaing ruang" dengan isi file itu sendiri — beda dari beberapa filesystem lain yang menyimpan xattr sebagai bagian dari struktur data yang sama.

---

#### 2.8.2 XFS Timestamp & Metadata

Konsepnya **sama** dengan Ext4 (§2.1.2) — atime, mtime, ctime — dengan satu perbedaan penting:

| Timestamp | Ext4 | XFS |
|---|---|---|
| atime, mtime, ctime | ✅ Ada | ✅ Ada |
| crtime (Creation/Birth time) | ✅ Ada (extension modern) | ✅ Ada (XFS sudah mendukung sejak lama, disebut juga `crtime`) |

```bash
# Sama seperti Ext4, 'stat' menampilkan semua timestamp termasuk Birth (crtime) jika didukung
stat /path/to/file
```

> 📌 **Keterbatasan deteksi timestomping sama seperti Ext4 (§2.1.3):** XFS juga tidak punya mekanisme cross-check internal setara SI/FN NTFS — prinsip keterbatasan deteksi yang sudah dibahas di §2.1.3 berlaku sama persis di sini.

---

#### 2.8.3 XFS Reflink & Sparse File

**Pengertian & Fungsi:** XFS modern mendukung **reflink** — mekanisme copy-on-write di level filesystem, mirip clone Btrfs, **tidak ada padanannya** di Ext4 standar.

```
cp --reflink=always file.txt file_copy.txt

Hasilnya:
file.txt      ─┐
                ├──►  Extent data FISIK yang SAMA (belum ada duplikasi nyata)
file_copy.txt ─┘

Begitu salah satu file dimodifikasi:
file.txt (dimodifikasi)  ──►  Extent BARU (copy-on-write terjadi di titik ini)
file_copy.txt (asli)      ──►  Extent LAMA (tetap tidak berubah)
```

| Aspek | Reflink | Hard Link (§2.1.9) |
|---|---|---|
| Inode | **Berbeda** (2 inode terpisah) | **Sama** (1 inode) |
| Bisa dimodifikasi independen? | ✅ Ya (copy-on-write otomatis saat salah satu diubah) | ❌ Tidak (mengubah salah satu nama = mengubah semua nama, karena data sama) |
| Terlihat sebagai file terpisah? | ✅ Ya, punya inode & metadata sendiri | ✅ Ya, tapi data fisik selalu identik |

```bash
# Cek apakah dua file berbagi extent fisik (reflink) tanpa harus modifikasi dulu
sudo xfs_io -c "fiemap -v" file.txt
```

> ⚠️ **Nilai forensik:** Dua file dengan **hash identik** tapi **inode number berbeda** di XFS bisa jadi indikasi reflink (bukan file yang benar-benar di-copy independen) — penting dibedakan dari hard link (inode sama) maupun copy biasa (extent fisik berbeda sejak awal) saat menjelaskan hubungan antar file di laporan investigasi.

Sparse file (§2.1.10) juga didukung penuh di XFS dengan prinsip yang sama — file holes yang tidak dialokasikan fisik walau `i_size` (analog) menunjukkan ukuran penuh.

---

### 2.9 XFS Deleted File & Recovery

#### 2.9.1 Bagaimana Deletion Berbeda dari Ext4

**Pengertian & Fungsi:** Ini adalah perbedaan **paling signifikan** secara praktis antara Ext4 dan XFS dari sudut pandang forensik — bukan cuma detail struktur, tapi **filosofi desain** yang berdampak langsung ke peluang recovery.

| Tahap | Ext4 (§2.3.1) | XFS |
|---|---|---|
| unlink() dipanggil | Dirent dihapus, link count berkurang (§2.3.2) | Sama — dirent dihapus, link count berkurang |
| Link count mencapai 0 | Inode masuk kondisi "dihapus", `i_dtime` diisi (§2.1.6) | Inode masuk **unlinked inode list** di AGI (§2.6.5) — mekanisme **standar**, bukan cuma untuk kasus crash |
| Pembersihan lanjutan | Bisa "menggantung" di kondisi terhapus tanpa batas waktu sampai di-reuse (§2.3.3) | XFS **secara aktif dan cepat** membersihkan inode dari unlinked list & **secara agresif menimpa/mendealokasi extent** terkait, seringkali **hampir seketika** |

> ⚠️ **Konsekuensi paling penting untuk investigator:** XFS **jauh lebih agresif** membersihkan struktur setelah penghapusan dibanding Ext4 — desain ini optimal untuk performa (tidak ada "sampah" metadata menumpuk), tapi **buruk untuk peluang recovery forensik**. File yang dihapus di XFS cenderung jauh lebih cepat "benar-benar hilang" (extent didealokasi & berpeluang ditimpa) dibanding Ext4 yang bisa "menggantung" lebih lama di kondisi dihapus-tapi-belum-ditimpa.

---

#### 2.9.2 Keterbatasan Recovery XFS

Sebagai konsekuensi langsung §2.9.1:

| Skenario | Ext4 | XFS |
|---|---|---|
| File baru saja dihapus, image diambil segera | Peluang recovery **tinggi** (§2.5.9) | Peluang recovery **sedang** — tergantung seberapa cepat kernel sempat membersihkan |
| File dihapus, beberapa menit/jam berlalu sebelum imaging | Peluang recovery **sedang-tinggi**, tergantung aktivitas disk lain | Peluang recovery **rendah** — extent sudah kemungkinan besar didealokasi & berpotensi ditimpa |
| Directory slack space (§2.4.3) | Konsep ini ada dan cukup berguna | Konsep serupa ada (B+Tree directory XFS juga punya "slack"), tapi kurang terdokumentasi/tooling untuk eksploitasi forensik dibanding Ext4 |

> 📌 **Implikasi metodologis untuk investigasi XFS:** Kalau target adalah server XFS (umum di RHEL/CentOS enterprise) dan ada dugaan file penting dihapus, **kecepatan akuisisi jauh lebih kritis** dibanding kalau target Ext4 — pertimbangkan live triage/memory capture (§1.2.7 Bab 1, live-only artifacts) sebagai prioritas lebih tinggi daripada mengandalkan post-mortem disk recovery semata.

---

#### 2.9.3 Tools Analisa XFS

| Tool | Fungsi | Catatan |
|---|---|---|
| **xfs_db** | Tool interaktif utama, setara `debugfs` untuk Ext4 | Paling serbaguna, tapi kurva belajar lebih curam karena struktur XFS lebih kompleks |
| **xfs_info** | Info filesystem-level cepat | Setara `xfs_db -c "sb 0" -c print`, tapi lebih ringkas |
| **xfs_repair -n** | Diagnosa konsistensi filesystem TANPA mengubah apapun (§2.7.2) | **Selalu** pakai flag `-n` untuk tujuan forensik |
| **xfs_logprint** | Dump isi log XFS (§2.7.2) | Analog `debugfs logdump` tapi untuk XFS |
| **xfs_io** | Query info I/O-level seperti extent mapping, reflink (§2.8.3) | `xfs_io -c "fiemap -v" file` |
| **The Sleuth Kit** | Dukungan **terbatas** — beberapa command dasar mungkin berfungsi, tapi tidak seandal untuk Ext4 | Selalu verifikasi hasil TSK di XFS dengan tool native sebagai cross-check |
| **PhotoRec** | Signature-based carving, **filesystem-agnostic** | Tetap jadi opsi terakhir yang reliable terlepas dari keterbatasan dukungan XFS di tool lain |

```bash
# Contoh workflow dasar investigasi XFS
sudo xfs_info /dev/sda3                              # info umum
sudo xfs_db -r -c "sb 0" -c "print" /dev/sda3          # detail superblock
sudo xfs_repair -n /dev/sda3                           # cek konsistensi (read-only!)
sudo xfs_logprint /dev/sda3 | less                     # cek log
```

> ⚠️ **Kenapa dukungan tool jadi keterbatasan nyata:** Berbeda dari Ext4 yang ekosistem forensiknya matang (Sleuth Kit, `extundelete`, `debugfs` semua terdokumentasi baik untuk kebutuhan DFIR), XFS lebih sering butuh kombinasi tool **native filesystem** (dirancang untuk sysadmin, bukan forensik) yang dipakai secara hati-hati (selalu read-only/`-n`) untuk tujuan investigasi.

---

### 2.10 Filesystem Metadata vs File Content

**Pengertian & Fungsi:**
Sebagai penutup konseptual Bab 2 — satu prinsip yang berlaku sama persis baik di Ext4 maupun XFS (dan sebenarnya juga NTFS, Windows Bab 2): **metadata dan isi file adalah dua lapisan yang independen**, masing-masing dengan siklus hidup, lokasi penyimpanan, dan peluang recovery yang berbeda.

```
                    METADATA                          FILE CONTENT
                    ────────                          ────────────
Ext4:      Inode (i_mode, timestamp,       Extent tree menunjuk ke
           i_links_count, dst — §2.1.6)     Data Blocks (§2.1.7)

XFS:       Inode Core + AGI (§2.6.5,       Data Fork menunjuk ke
           §2.8.1)                          Data Blocks (§2.8.1)

           Nama file HIDUP TERPISAH LAGI
           di dirent (§2.4) — bahkan
           metadata sendiri punya 2 "sub-layer"
```

| Prinsip | Implikasi |
|---|---|
| Metadata bisa hilang, isi data masih ada | Kalau dirent hilang (§2.4.2) tapi inode belum di-reuse (§2.3.3), isi file **masih bisa** direcover lewat `icat`, walau nama aslinya sudah tidak diketahui pasti |
| Isi data bisa hilang, metadata masih ada | Kalau extent/data fork sudah ditimpa tapi inode belum di-reuse, metadata (`stat`/`istat`) **masih bisa dibaca** — investigator tahu "file apa yang pernah ada, kapan, seukuran apa" walau isinya sudah tidak bisa dipulihkan |
| Keduanya independen dari **nama** | Karena nama hidup di layer ketiga (dirent), bahkan kalau metadata DAN isi data sama-sama utuh, **nama file** bisa jadi satu-satunya yang hilang (kalau semua dirent yang menunjuk ke inode itu terhapus permanen) |

> 💡 **Kenapa prinsip ini penting sebagai penutup Bab 2:** Setiap kali investigator menemukan artefak "sebagian" (cuma nama tanpa isi, cuma isi tanpa nama, atau metadata tanpa keduanya), pertanyaan yang harus langsung muncul adalah **"lapisan mana yang hilang, dan kenapa?"** — jawabannya akan selalu mengarah balik ke salah satu dari tiga struktur independen ini (inode/metadata, extent/data fork, dirent/nama), bukan "file ini rusak" secara umum. Prinsip yang sama ini yang nanti dipakai lagi saat membahas korelasi timeline di bab-bab selanjutnya — memahami filesystem sebagai **beberapa lapisan independen**, bukan satu blok monolitik "file", adalah fondasi berpikir yang paling penting dari keseluruhan Bab 2.

---

### 2.11 Korelasi Ext4/XFS Artifact (Tabel Cepat)

| Pertanyaan | Artefak Utama (Ext4) | Artefak Utama (XFS) | Bagian |
|---|---|---|---|
| File dibuat kapan | `crtime` inode | `crtime` inode | §2.1.2, §2.8.2 |
| File dihapus kapan | `i_dtime` inode | Unlinked inode list (AGI) — waktu tidak selalu eksplisit | §2.1.6, §2.6.5 |
| File pernah ada walau inode sudah di-reuse | Deleted dirent (§2.4.2) / Directory Slack (§2.4.3) | Struktur serupa, dukungan tooling lebih terbatas | §2.4 |
| Rename file | Dirent lama dihapus + dirent baru dibuat (inode number sama) | Sama, prinsip inode number tetap sama | §2.4.1, §2.5.5 |
| Isi file terhapus | Extent tree (kalau inode belum di-reuse) → `icat` | Data fork (kalau belum didealokasi — window lebih sempit, §2.9.1) | §2.1.7, §2.5.9, §2.8.1 |
| Timestomp / manipulasi waktu | Cross-check journal/log aplikasi (keterbatasan native, §2.1.3) | Sama, keterbatasan serupa | §2.1.3, §2.8.2 |
| File kecil/payload tersembunyi | Inline data / xattr (§2.1.4) | Inline data fork (§2.8.1) / xattr | §2.1.4, §2.8.1 |
| File "duplikat" tapi hash sama | Hard link (§2.1.9) | Hard link ATAU Reflink (§2.8.3) — beda inode number | §2.1.9, §2.8.3 |
| Transaksi filesystem paling granular | jbd2 Journal (§2.2) | XFS Log (§2.7) | §2.2, §2.7 |
| File dilindungi dari dihapus/diubah | Inode flags — immutable/append-only (§2.1.5) | Konsep serupa didukung sebagian | §2.1.5 |
| Privilege escalation via file capability | `security.capability` xattr (§2.1.4) | Sama, xattr di attribute fork (§2.8.1) | §2.1.4, §2.8.1 |

> 💡 **Cara pakai tabel ini:** Sama seperti tabel korelasi Windows Bab 2 §2.3 — mulai dari kolom pertanyaan (sesuai soal/kasus), lompat ke bagian yang relevan sesuai filesystem target (Ext4 atau XFS), tanpa perlu baca ulang seluruh bab dari awal.

---

### 2.12 Ringkasan Command & Tools Cheat Sheet

```bash
# ===== EXT4 — SUPERBLOCK & LAYOUT =====
sudo dumpe2fs -h /dev/sda3
sudo tune2fs -l /dev/sda3

# ===== EXT4 — INODE INSPECTION =====
sudo debugfs -R "stat <inode_number>" /dev/sda3
stat /path/to/file
ls -li /path/to/file

# ===== EXT4 — XATTR, ACL, CAPABILITIES =====
getfattr -d /path/to/file
getfacl /path/to/file
getcap /path/to/binary
sudo getcap -r / 2>/dev/null

# ===== EXT4 — INODE FLAGS =====
lsattr /path/to/file
sudo lsattr -R / 2>/dev/null | grep -E "^----i|^----a"

# ===== EXT4 — EXTENT / DATA LOCATION =====
sudo filefrag -v /path/to/file

# ===== EXT4 — JOURNAL (jbd2) =====
sudo debugfs -R "logdump -a" /dev/sda3 > journal_dump.txt
jls /dev/sda3
jcat /dev/sda3 <block_number>

# ===== EXT4 — DELETED FILE / DIRENT =====
fls -rd /dev/sda3
sudo debugfs -R "bdump <block_number>" /dev/sda3

# ===== EXT4 — RECOVERY =====
sudo extundelete /dev/sda3 --restore-file path/to/file.txt
sudo extundelete /dev/sda3 --restore-all
sudo testdisk disk.dd
photorec disk.dd

# ===== SLEUTH KIT (CROSS Ext4/XFS TERBATAS) =====
fsstat /dev/sda3
fls -r /dev/sda3
istat /dev/sda3 <inode_number>
icat /dev/sda3 <inode_number> > output_file
ils -r /dev/sda3

# ===== XFS — INFO & LAYOUT =====
sudo xfs_info /dev/sda3
sudo xfs_db -r -c "sb 0" -c "print" /dev/sda3
sudo xfs_db -r -c "agf 0" -c "print" /dev/sda3
sudo xfs_db -r -c "agi 0" -c "print" /dev/sda3

# ===== XFS — INODE =====
sudo xfs_db -r -c "inode <inode_number>" -c "print" /dev/sda3

# ===== XFS — LOG =====
sudo xfs_logprint /dev/sda3

# ===== XFS — CONSISTENCY CHECK (READ-ONLY!) =====
sudo xfs_repair -n /dev/sda3

# ===== XFS — REFLINK / EXTENT MAPPING =====
sudo xfs_io -c "fiemap -v" /path/to/file
```

---

### 2.13 Mini Case Study — Workflow Analisa End-to-End

Contoh alur berpikir kalau soal CTF bilang: *"attacker meng-upload payload ke server, menjalankannya, lalu menghapusnya dan menghapus barisnya dari bash history — buktikan!"* (target: Ext4, server Ubuntu).

```
Langkah 1 — Cari eksekusi program (mendahului bab User/Auth/Shell Artifacts, tapi konsepnya
   relevan di sini): cek auditd log kalau ada, atau evidence tidak langsung dari journal

Langkah 2 — Cari inode file payload tersebut
   fls -rd /dev/sda3 | grep -i "payload\|\.sh\|\.py"
   → temukan entry terhapus, catat inode number

Langkah 3 — Cek status inode (masih recoverable atau sudah "realloc"?)
   istat /dev/sda3 <inode_number>
   → kalau output menunjukkan Allocated & data fork/extent masih valid → lanjut langkah 4
   → kalau muncul tag "(realloc)" di fls sebelumnya → lompat ke langkah 6

Langkah 4 — Ekstrak isi file dari inode
   icat /dev/sda3 <inode_number> > recovered_payload
   file recovered_payload
   strings recovered_payload | less
   → dapat isi payload asli untuk analisis lebih lanjut (bab Malware Analysis)

Langkah 5 — Cek timestamp inode untuk membangun timeline
   sudo debugfs -R "stat <inode_number>" /dev/sda3
   → crtime (upload/dibuat), mtime (terakhir diubah), i_dtime (waktu dihapus, §2.1.6)

Langkah 6 — Kalau inode sudah realloc, cek Directory Slack (§2.4.3) di folder upload
   sudo debugfs -R "bdump <block_number_folder>" /dev/sda3 > dirblock.raw
   strings dirblock.raw
   → cari sisa nama file di slack space, walau isi datanya sudah tidak bisa direcover

Langkah 7 — Cross-check ke journal (§2.2.4) — kalau mode data=journal aktif,
   mungkin ada salinan sementara isi file sebelum benar-benar hilang
   sudo debugfs -R "logdump -a" /dev/sda3 | grep -A20 -i "<inode_number>"

Langkah 8 — Verifikasi command penghapusan bash history (walau file .bash_history
   sendiri diedit user, cek juga apakah shell command tercatat di auditd/journal
   systemd — akan dibahas detail di bab Log Forensics & User/Auth Artifacts)

Kesimpulan yang bisa ditulis di laporan:
"Payload diupload pada waktu X (crtime inode #NNNN), dieksekusi (evidence dari log
aplikasi/auditd), lalu dihapus pada waktu Y (i_dtime). Inode belum sempat di-reuse
saat akuisisi, sehingga isi file berhasil di-recover penuh via icat dan menunjukkan
[hasil analisis payload]. Nama file dikonfirmasi lewat entry deleted dirent di folder
upload (fls -rd), dengan timestamp yang konsisten terhadap i_dtime inode."
```

> 💡 **Prinsip umum (sama semangatnya dengan Windows Bab 2 §2.5):** Jangan cuma andalkan satu sumber. Inode (§2.1, §2.5) kasih "kondisi metadata", dirent (§2.4) kasih "riwayat nama", journal (§2.2) kasih "jejak transaksi paling granular tapi window pendek". Kombinasi semuanya jauh lebih kuat daripada berhenti begitu satu sumber gagal — terutama di Ext4/XFS yang (beda dari NTFS `$UsnJrnl`) tidak punya satu sumber tunggal yang mencakup riwayat perubahan jangka panjang secara native.
