## 📌 Daftar Isi — Bab 1

- [Bab 1 — Struktur Linux & Filesystem Dasar](#bab-1--struktur-linux--filesystem-dasar)
  - [1.1 Struktur Disk & Partisi di Linux](#11-struktur-disk--partisi-di-linux)
    - [1.1.1 Block Device Naming](#111-block-device-naming)
    - [1.1.2 MBR vs GPT di Linux](#112-mbr-vs-gpt-di-linux)
    - [1.1.3 Partition Table & Numbering](#113-partition-table--numbering)
    - [1.1.4 LVM (Logical Volume Manager)](#114-lvm-logical-volume-manager)
    - [1.1.5 Swap Partition vs Swap File](#115-swap-partition-vs-swap-file)
    - [1.1.6 Filesystem Overview Singkat](#116-filesystem-overview-singkat)
    - [1.1.7 Boot Process Overview](#117-boot-process-overview)
    - [1.1.8 Disk Image Format Linux](#118-disk-image-format-linux)
    - [1.1.9 Unallocated Space & Slack Space di Linux](#119-unallocated-space--slack-space-di-linux)
    - [1.1.10 Big Picture — Hubungan Antar-Layer Storage](#1110-big-picture--hubungan-antar-layer-storage)
    - [1.1.11 Encryption Layer — LUKS/dm-crypt (Overview)](#1111-encryption-layer--luksdm-crypt-overview)
    - [1.1.12 UUID, LABEL & Mount Point](#1112-uuid-label--mount-point)
  - [1.2 Filesystem Hierarchy Standard (FHS) — Struktur Direktori Root](#12-filesystem-hierarchy-standard-fhs--struktur-direktori-root)
    - [1.2.1 Root / — Overview](#121-root--overview)
    - [1.2.2 /bin, /sbin, /usr/bin, /usr/sbin — Binary & Symlink Modern](#122-bin-sbin-usrbin-usrsbin--binary--symlink-modern)
    - [1.2.3 /etc — Configuration Files](#123-etc--configuration-files)
    - [1.2.4 /home & /root — Profil User](#124-home--root--profil-user)
    - [1.2.5 /var — Log, Cache, Spool](#125-var--log-cache-spool)
    - [1.2.6 /tmp & /dev/shm — Staging Area Favorit Attacker](#126-tmp--devshm--staging-area-favorit-attacker)
    - [1.2.7 /proc & /sys — Virtual Filesystem](#127-proc--sys--virtual-filesystem)
    - [1.2.8 /dev — Device Files](#128-dev--device-files)
    - [1.2.9 /opt, /mnt, /media — Third-party & Removable Media](#129-opt-mnt-media--third-party--removable-media)
    - [1.2.10 /boot — Kernel & Bootloader Files](#1210-boot--kernel--bootloader-files)
    - [1.2.11 Tabel Prioritas Investigasi](#1211-tabel-prioritas-investigasi)
    - [1.2.12 Persistent vs Volatile — Ringkasan](#1212-persistent-vs-volatile--ringkasan)
    - [1.2.13 Full Path Tree — Master Reference](#1213-full-path-tree--master-reference)
  - [📎 Lampiran Bab 1 — Master Acquisition & Export Workflow (Linux)](#-lampiran-bab-1--master-acquisition--export-workflow-linux)
  - [📍 Penutup Bab 1 — Linux Storage Architecture (Big Picture)](#-penutup-bab-1--linux-storage-architecture-big-picture)

---

## Bab 1 — Struktur Linux & Filesystem Dasar

> 💡 **Posisi Bab 1 di seri Linux Forensics:** Bab ini adalah fondasi paling dasar — sama perannya dengan Bab 1 di seri Windows. Fokusnya cuma dua hal: **layer disk/partisi/boot** (§1.1) dan **peta direktori root** (§1.2). Detail internal filesystem Ext4/XFS (inode table, journal, extent) **sengaja tidak dibahas di sini** — itu porsi penuh Bab 2, supaya Bab 1 tetap ringan dan bisa dijadikan referensi cepat "di mana lokasinya", bukan "bagaimana strukturnya secara byte-level".

> 📖 **Kalau kamu sudah familiar seri Windows:** Konsep sector/cluster/LBA/MBR/GPT di §1.1 **persis sama** secara fisik dengan Windows Bab 1 §1.1 — bedanya cuma di penamaan device dan tool yang dipakai untuk membacanya. Perbedaan besar justru ada di §1.2, karena Linux tidak punya Registry — hampir semua "peran" Registry (config sistem, service definition, user info) digantikan oleh **plaintext file** yang tersebar di `/etc`, `/var`, dan `/proc`.

---

### 1.1 Struktur Disk & Partisi di Linux

#### 1.1.1 Block Device Naming

**Pengertian & Fungsi:**
Beda dengan Windows yang pakai drive letter (`C:`, `D:`), Linux merepresentasikan setiap disk sebagai **file device** di `/dev/`. Penamaan ini adalah hal pertama yang harus dikenali sebelum masuk ke partition table, karena skema penamaannya beda tergantung jenis controller/storage.

| Prefix Device | Jenis Storage | Contoh |
|---|---|---|
| `/dev/sd*` | SATA/SCSI/USB (termasuk sebagian besar HDD/SSD lama & flashdisk) | `/dev/sda`, `/dev/sdb` |
| `/dev/nvme*` | NVMe SSD (modern, koneksi PCIe langsung) | `/dev/nvme0n1` |
| `/dev/vd*` | Virtual disk di lingkungan virtualisasi (KVM/QEMU virtio) | `/dev/vda` — **umum ditemui di image CTF/VPS** |
| `/dev/xvd*` | Virtual disk Xen (AWS EC2 instance lama) | `/dev/xvda` |
| `/dev/mmcblk*` | eMMC/SD Card (embedded device, Raspberry Pi, dll) | `/dev/mmcblk0` |
| `/dev/loop*` | Loop device — dipakai untuk mount file image (`.img`, `.iso`) sebagai block device | `/dev/loop0` |

```bash
# Cek semua block device yang terdeteksi sistem
lsblk

# Cek info detail per-disk (ukuran, model, serial)
sudo fdisk -l
```

> 💡 **Kenapa penting dikenali dari awal:** Nama device ini akan terus muncul di seluruh proses akuisisi & mounting image forensik. Salah asumsi (mengira image dari VPS QEMU pasti `/dev/sda`, padahal virtio biasanya `/dev/vda`) bisa bikin bingung di langkah paling awal.

---

#### 1.1.2 MBR vs GPT di Linux

**Pengertian & Fungsi:**
Skema partition table di Linux **konsepnya identik** dengan Windows (dibahas di Windows Bab 1 §1.1.5) — MBR dan GPT adalah standar yang sama, bukan format khusus OS tertentu. Yang beda cuma tool untuk membacanya.

| Aspek | MBR | GPT |
|---|---|---|
| Lokasi | Sector 0 (LBA 0), 512 byte | Mulai LBA 1, ada backup di akhir disk |
| Maks partisi primer | 4 | Sampai 128 |
| Bootloader terkait | GRUB Legacy / GRUB2 BIOS mode | GRUB2 UEFI mode (butuh partisi EFI System Partition) |
| Tool baca (Linux) | `fdisk`, `parted` | `gdisk`, `parted` (dengan `mklabel gpt`) |

```bash
# Cek skema partition table sebuah disk/image
sudo parted /dev/sda print
# atau
sudo gdisk -l /dev/sda
```

> 📌 Karena konsepnya sama persis dengan Windows §1.1.5, tidak diulang detail struktur byte-nya di sini — cukup diingat bahwa GPT modern Linux **juga** menyertakan **EFI System Partition (ESP)** berformat FAT32 kalau sistem boot via UEFI, isinya bootloader (`grubx64.efi`/`shimx64.efi`), bukan `bootmgfw.efi` seperti Windows.

---

#### 1.1.3 Partition Table & Numbering

**Pengertian & Fungsi:**
Penomoran partisi Linux mengikuti nama block device dasarnya, dengan pola akhiran yang beda tergantung jenis device.

```
Skema /dev/sd* dan /dev/vd* (SATA/virtio):
/dev/sda        ← disk utuh
/dev/sda1       ← partisi 1
/dev/sda2       ← partisi 2

Skema /dev/nvme* dan /dev/mmcblk* (butuh huruf "p" sebelum nomor partisi,
karena nama device-nya sendiri sudah diakhiri angka):
/dev/nvme0n1     ← disk utuh
/dev/nvme0n1p1   ← partisi 1
/dev/nvme0n1p2   ← partisi 2
```

> ⚠️ **Kesalahan umum pemula:** Mencoba mount `/dev/nvme0n1` + `1` jadi `/dev/nvme0n11` — salah, karena nama device NVMe sudah diakhiri angka (`n1`), butuh separator huruf `p` supaya tidak ambigu dengan nomor disk itu sendiri.

**Contoh layout partisi umum Linux modern (GPT + UEFI):**

```
/dev/sda
├── /dev/sda1   ← EFI System Partition (FAT32, ~100-500 MB)
├── /dev/sda2   ← /boot (kadang terpisah dari root, format Ext2/Ext4)
└── /dev/sda3   ← Root filesystem "/" (bisa langsung Ext4, atau LVM Physical Volume — lihat §1.1.4)
```

```bash
# Cek mapping partisi ke mount point yang sedang aktif
lsblk -f
mount | grep "^/dev"
```

---

#### 1.1.4 LVM (Logical Volume Manager)

**Pengertian & Fungsi:**
LVM adalah layer abstraksi **tambahan** antara partisi fisik dan filesystem — sangat umum dipakai di server/VPS/distro enterprise (RHEL, Ubuntu Server) karena memungkinkan resize volume tanpa perlu partisi ulang disk fisik. Ini **tidak ada padanannya** di Windows standar (agak mirip Storage Spaces, tapi jarang dipakai).

```
Physical Volume (PV)         ← partisi fisik/disk mentah yang "didaftarkan" ke LVM
   │  (mis. /dev/sda3)
   ▼
Volume Group (VG)             ← kumpulan satu/lebih PV, jadi "pool" storage gabungan
   │  (mis. vg_system)
   ▼
Logical Volume (LV)           ← "partisi virtual" yang dipotong dari VG, inilah yang di-mount
   (mis. /dev/vg_system/lv_root, /dev/vg_system/lv_home, /dev/vg_system/lv_swap)
```

| Perintah | Fungsi |
|---|---|
| `pvdisplay` / `pvs` | Menampilkan Physical Volume |
| `vgdisplay` / `vgs` | Menampilkan Volume Group |
| `lvdisplay` / `lvs` | Menampilkan Logical Volume |

```bash
# Enumerasi lengkap struktur LVM pada disk/image
sudo pvs
sudo vgs
sudo lvs

# Aktivasi VG dari image forensik yang belum ter-mount otomatis
sudo vgchange -ay
```

> ⚠️ **Relevansi forensik:** Kalau image disk dibuka tapi partisi root tidak langsung terlihat (cuma ada satu partisi besar tak dikenal), kemungkinan besar itu **LVM Physical Volume** yang perlu di-**activate** dulu (`vgchange -ay`) sebelum Logical Volume di dalamnya bisa di-mount dan dianalisis. Ini langkah yang sering terlewat investigator yang baru pindah dari forensik Windows.

---

#### 1.1.5 Swap Partition vs Swap File

**Pengertian & Fungsi:**
Setara `pagefile.sys` di Windows (Windows Bab 1 §1.2.13) — tempat kernel menyimpan halaman memori yang di-swap keluar dari RAM. Bedanya, Linux bisa pakai **partisi dedicated** ATAU **file biasa**.

| Bentuk | Lokasi Umum | Cara Deteksi |
|---|---|---|
| Swap Partition | Partisi terpisah, biasanya bertipe `Linux swap` di partition table | `blkid` menunjukkan `TYPE="swap"` |
| Swap File | File biasa di dalam filesystem (umum di VPS/cloud modern, lebih fleksibel) | `/swapfile` atau `/swap.img`, dicek lewat `cat /proc/swaps` |

```bash
# Cek swap yang aktif di live system
cat /proc/swaps
swapon --show
```

> 💡 **Nilai forensik sama seperti pagefile.sys Windows:** Swap (partition maupun file) berpotensi menyimpan fragmen data RAM — password, command yang pernah dijalankan, isi memori proses — sehingga sering jadi target `strings`/carving kalau memory image langsung tidak tersedia.

---

#### 1.1.6 Filesystem Overview Singkat

> 📖 **Detail penuh Ext4 (inode, journal, extent tree) dibahas mendalam di Bab 2.** Bagian ini cuma orientasi singkat supaya paham filesystem apa yang mungkin ditemui sebelum masuk ke internals.

| Filesystem | Umum Dipakai Untuk | Catatan Forensik |
|---|---|---|
| **Ext4** | Root filesystem default hampir semua distro modern (Ubuntu, Debian, dll) | Journaling aktif, kaya metadata → **fokus utama Bab 2** |
| Ext3 / Ext2 | Sistem lama, embedded, sebagian `/boot` partition | Ext2 tanpa journal, Ext3 punya journal tapi lebih sederhana dari Ext4 |
| **XFS** | Default di RHEL/CentOS/Fedora modern, umum di server enterprise | Performa tinggi untuk file besar, struktur B-tree berbeda dari Ext4 — dibahas kalau relevan di Bab 2 |
| Btrfs | Distro modern yang butuh snapshot native (openSUSE, sebagian Fedora) | Copy-on-write, punya snapshot bawaan (mirip VSS Windows — relevan untuk recovery data) |
| tmpfs | `/tmp`, `/dev/shm` — filesystem **di RAM**, hilang saat reboot | Data di sini **tidak persisten** — kalau relevan, harus ditangkap sebelum shutdown/reboot (lihat §1.2.6) |
| FAT32/exFAT | EFI System Partition, removable media lintas-OS | Sama seperti di Windows — metadata timestamp terbatas |
| ISO9660 | CD/DVD image, kadang muncul di initramfs/live boot media | Read-only, jarang jadi fokus utama investigasi |

> ⚠️ **Perbedaan mendasar dari Windows:** Windows nyaris seragam pakai NTFS untuk OS volume. Linux jauh lebih beragam — filesystem root bisa Ext4, XFS, atau Btrfs tergantung distro, dan ini **mengubah tool serta teknik parsing** yang harus dipakai (Bab 2 akan fokus Ext4/XFS sebagai dua yang paling umum).

---

#### 1.1.7 Boot Process Overview

**Pengertian & Fungsi:**
Menyambungkan MBR/GPT (§1.1.2), bootloader, sampai kernel menyerahkan kontrol ke `init`/`systemd` — paralel dengan Windows Bab 1 §1.1.8, tapi komponennya beda total.

```
Power On
   │
   ▼
BIOS / UEFI                 ← firmware, sama seperti Windows
   │
   ▼
MBR / GPT + ESP               ← partition table (§1.1.2)
   │
   ▼
GRUB Stage 1                  ← boot code kecil di MBR, atau file di ESP untuk UEFI
   │
   ▼
GRUB Stage 2                  ← baca /boot/grub/grub.cfg, tampilkan menu boot
   │
   ▼
Kernel Linux (vmlinuz)        ← dimuat ke memori bersama initramfs
   │
   ▼
initramfs (initial RAM filesystem)   ← filesystem sementara di RAM, berisi driver/tools
   │                                    minimal untuk mount root filesystem asli
   ▼
switch_root                    ← pindah dari initramfs ke root filesystem sesungguhnya
   │
   ▼
init / systemd (PID 1)         ← proses pertama userspace, mengorkestrasi semua service lain
```

| Komponen | Fungsi | Lokasi File |
|---|---|---|
| **GRUB** | Bootloader utama hampir semua distro modern | `/boot/grub/grub.cfg`, `/boot/efi/EFI/<distro>/grubx64.efi` |
| **vmlinuz** | Kernel image terkompresi | `/boot/vmlinuz-<versi>` |
| **initramfs / initrd** | Filesystem sementara di RAM untuk boot awal | `/boot/initrd.img-<versi>` |
| **systemd (PID 1)** | Init system modern (menggantikan SysV init di kebanyakan distro) | `/lib/systemd/`, `/etc/systemd/system/` |

> 💡 **Relevansi forensik:** `/boot/grub/grub.cfg` yang dimodifikasi bisa jadi indikasi **bootkit/persistence level bootloader** (setara modifikasi BCD di Windows, Windows Bab 1 §1.1.8). Modifikasi `initramfs` (custom hook/script yang di-inject) adalah teknik persistence tingkat lanjut yang jarang tapi sangat sulit dideteksi tool antivirus userspace biasa, karena dijalankan sebelum root filesystem normal bahkan ter-mount.

---

#### 1.1.8 Disk Image Format Linux

**Pengertian & Fungsi:**
Sebagian besar format sama dengan yang sudah dibahas di Windows Bab 1 §1.1.13 (karena format image bersifat lintas-OS) — tabel ini fokus ke tool khas Linux untuk menangani format-format tersebut.

| Format | Ciri Khas | Tool Akuisisi/Buka (Linux) |
|---|---|---|
| `.dd` / `.img` | Raw bit-for-bit, paling umum di dunia Linux forensics | `dd`, `dc3dd`, `dcfldd` (akuisisi); `mount -o loop` (buka) |
| `.E01` / `.EX01` | Sama seperti Windows, kadang dipakai kalau akuisisi pakai tool cross-platform | `ewfmount` (dari `libewf-tools`) |
| `.qcow2` | Umum untuk VM berbasis QEMU/KVM — banyak ditemui di CTF self-hosted | `qemu-nbd`, `qemu-img convert` |
| `.vmdk` | VM berbasis VMware | `qemu-img convert`, atau mount lewat `libguestfs` (`guestmount`) |
| `.vdi` | VM berbasis VirtualBox | `qemu-img convert`, atau native VirtualBox tools |

```bash
# Akuisisi live disk ke image raw (dengan hashing built-in)
sudo dc3dd if=/dev/sda hash=sha256 log=acquisition.log of=disk.dd

# Mount image raw langsung (kalau single partition tanpa partition table)
sudo mount -o ro,loop disk.dd /mnt/evidence

# Kalau image berisi partition table penuh — cek offset partisi dulu
sudo fdisk -l disk.dd
sudo mount -o ro,loop,offset=$((2048*512)) disk.dd /mnt/evidence

# Mount qcow2 (VM QEMU/KVM) via network block device
sudo modprobe nbd max_part=8
sudo qemu-nbd --connect=/dev/nbd0 disk.qcow2
sudo mount -o ro /dev/nbd0p1 /mnt/evidence

# Konversi VMDK/VDI ke raw untuk kompatibilitas tool lain
qemu-img convert -O raw disk.vmdk disk.raw
```

> ⚠️ **Selalu mount read-only (`-o ro`):** Kesalahan paling fatal di forensik Linux adalah mount image tanpa flag `ro` — filesystem Linux modern (terutama Ext4 dengan journal) bisa otomatis menulis perubahan (replay journal, update access time) begitu di-mount read-write, merusak integritas evidence.

---

#### 1.1.9 Unallocated Space & Slack Space di Linux

**Pengertian & Fungsi:**
Konsepnya **identik** dengan Windows Bab 1 §1.1.11 (unallocated space, file slack) — perbedaan sebenarnya sudah tuntas dijelaskan di sana secara device-agnostic. Bagian ini cuma memetakan tool Linux-nya.

| Istilah | Tool Analisa (Linux) |
|---|---|
| Unallocated Space (carving file terhapus) | `photorec`, `foremost`, `scalpel`, `bulk_extractor` |
| Partition Gap | `mmls` (Sleuth Kit) |
| File Slack | `blkls` (Sleuth Kit) — ekstrak slack space per-file |

```bash
# List partition table & area unallocated (Sleuth Kit)
mmls disk.dd

# Ekstrak seluruh unallocated space dari sebuah volume/image
blkls -A disk.dd > unallocated.raw

# Carving file dari area unallocated
photorec disk.dd
foremost -t all -i disk.dd -o output_folder/
```

> 📌 **Sama seperti Windows:** Kalau soal CTF bilang "flag tidak ada di file manapun di sistem", cek dulu unallocated space via carving sebelum menyerah — prinsipnya sama persis, cuma toolnya Linux-native.

---

#### 1.1.10 Big Picture — Hubungan Antar-Layer Storage

**Pengertian & Fungsi:**
Sub-bab §1.1.1 sampai §1.1.9 membahas tiap layer secara terpisah — bagian ini menyatukan semuanya jadi satu diagram, supaya jelas urutan dan hubungan tiap layer sebelum data akhirnya bisa dibaca sebagai file.

```
Physical Disk
      │
      ▼
Partition Table  (MBR/GPT — §1.1.2)
      │
      ▼
Partition  (/dev/sda3, §1.1.3)
      │
      ├── Filesystem  (langsung, tanpa LVM)
      │      │
      │      ▼
      │   Mount Point  (/, /home, dst)
      │      │
      │      ▼
      │   Directory
      │      │
      │      ▼
      │     File
      │
      └── LVM  (opsional, §1.1.4)
           │
       PV → VG → LV
           │
           ▼
       Filesystem
           │
           ▼
       Mount Point → Directory → File
```

> 💡 **Cara baca diagram ini:** Satu partisi punya **dua jalur yang mungkin** menuju filesystem — langsung (kebanyakan `/boot` atau setup sederhana), atau lewat LVM dulu (umum di server/enterprise, §1.1.4). Investigator perlu tahu jalur mana yang dipakai **sebelum** mencoba mount — kalau partisi ternyata LVM Physical Volume, mount langsung akan gagal sampai LV di dalamnya diaktifkan dulu (`vgchange -ay`).

> 📖 **Encryption sebagai layer tambahan:** Diagram di atas belum menyertakan kemungkinan enkripsi (LUKS) yang bisa disisipkan antara Partition dan Filesystem/LVM — dibahas ringkas di §1.1.11.

---

#### 1.1.11 Encryption Layer — LUKS/dm-crypt (Overview)

**Pengertian & Fungsi:**
LUKS (Linux Unified Key Setup) adalah standar enkripsi disk paling umum di Linux — setara BitLocker di Windows (disinggung Windows Bab 1 §1.1.14). Bagian ini **cuma overview posisi layer-nya**, bukan pembahasan cracking/dekripsi (di luar scope Bab 1).

```
Partition
   │
   ▼
LUKS / dm-crypt        ← optional layer
   │
   ▼
LVM                     ← optional layer
   │
   ▼
Filesystem
```

| Layer | Contoh |
|---|---|
| Disk | `/dev/nvme0n1` |
| Partition | `/dev/nvme0n1p3` |
| Encryption | LUKS |
| Volume manager | LVM |
| Logical volume | `/dev/mapper/vg-root` |
| Filesystem | Ext4 |
| Mount point | `/` |

```bash
# Cek apakah sebuah partisi terenkripsi LUKS (tanpa perlu password)
sudo cryptsetup isLuks /dev/sda3 && echo "LUKS terdeteksi"
sudo cryptsetup luksDump /dev/sda3   # header info — versi, cipher, tanpa buka isi
```

> ⚠️ **Batas scope Bab 1:** Kalau partisi target ternyata LUKS-encrypted dan tidak ada key/password yang tersedia, isi di baliknya **tidak bisa dianalisis** lewat teknik Bab 1-2 biasa — itu kondisi "dead end" yang perlu dicatat sebagai keterbatasan investigasi, bukan dipaksa bypass. Detail lanjut soal kapan key LUKS mungkin bisa didapat (misal dari RAM saat sistem live) ada di ranah Memory Forensics, bukan bagian ini.

---

#### 1.1.12 UUID, LABEL & Mount Point

**Pengertian & Fungsi:**
Linux tidak selalu merujuk partisi lewat nama device (`/dev/sda3`) — karena nama itu **bisa berubah** antar boot (urutan deteksi device tidak selalu konsisten, apalagi kalau ada USB/disk tambahan). Sistem modern lebih sering merujuk lewat **UUID** atau **LABEL** yang permanen menempel ke filesystem itu sendiri.

```bash
lsblk -f
```

```
NAME        FSTYPE   LABEL   UUID                                   MOUNTPOINTS
sda
├─sda1      vfat             AAAA-BBBB                              /boot/efi
├─sda2      ext4     boot    1a2b3c4d-5e6f-7890-abcd-ef1234567890   /boot
└─sda3      ext4     root    9f8e7d6c-5b4a-3210-fedc-ba9876543210   /
```

| Kolom | Pengertian |
|---|---|
| `NAME` | Nama device (bisa berubah antar boot) |
| `FSTYPE` | Jenis filesystem (ext4, xfs, vfat, swap, dll) |
| `LABEL` | Nama custom yang diberikan admin saat format (opsional, bisa kosong) |
| `UUID` | Identifier unik permanen, tidak berubah selama filesystem tidak di-format ulang |
| `MOUNTPOINTS` | Lokasi mount saat ini (kosong kalau tidak sedang di-mount) |

> 📌 **Kenapa ini wajib dikenali sebelum Bab 2 dst:** `/etc/fstab` (disinggung §1.2.3) dan konfigurasi GRUB (§1.1.7) hampir selalu merujuk partisi lewat UUID, bukan `/dev/sdaX` — jadi begitu ketemu baris seperti `UUID=9f8e7d6c-... / ext4 defaults 0 1`, investigator harus bisa langsung mencocokkan UUID itu ke device fisik lewat `lsblk -f` atau `blkid`. Sepanjang seri Linux Forensics ini, notasi `UUID=xxxx` akan terus muncul berulang di berbagai config file.

```bash
# Alternatif lain untuk cek UUID/LABEL per-device
sudo blkid
```

---

### 1.2 Filesystem Hierarchy Standard (FHS) — Struktur Direktori Root

#### 1.2.1 Root / — Overview

**Pengertian & Fungsi:**
Berbeda dari Windows yang punya banyak drive letter terpisah (`C:`, `D:`, dst), Linux punya **satu hierarki tunggal** dimulai dari `/` (root) — semua storage lain (partisi terpisah, removable media, network share) di-**mount** sebagai sub-direktori di dalam hierarki ini, bukan drive letter baru.

```
/
├── bin -> usr/bin       (symlink di distro modern, lihat §1.2.2)
├── sbin -> usr/sbin     (symlink di distro modern)
├── boot/                 ← Kernel & bootloader (§1.2.10)
├── dev/                   ← Device files (§1.2.8)
├── etc/                   ← Configuration files (§1.2.3)
├── home/                  ← Profil user (§1.2.4)
├── lib -> usr/lib        (symlink di distro modern)
├── media/                 ← Removable media auto-mount (§1.2.9)
├── mnt/                   ← Manual mount point (§1.2.9)
├── opt/                   ← Software third-party (§1.2.9)
├── proc/                  ← Virtual filesystem — proses & kernel state (§1.2.7)
├── root/                  ← Home direktori superuser (§1.2.4)
├── run/                   ← Runtime data (PID file, socket) — tmpfs, hilang saat reboot
├── srv/                   ← Data service (web server, FTP) — jarang dipakai
├── sys/                   ← Virtual filesystem — device & kernel subsystem (§1.2.7)
├── tmp/                   ← Temporary file, biasanya tmpfs (§1.2.6)
├── usr/                   ← User programs — binary, library, dokumentasi (bulk terbesar sistem)
└── var/                   ← Log, cache, spool — data yang sering berubah (§1.2.5)
```

> ⭐ **Perbedaan paling mendasar dari Windows:** Linux **tidak punya Registry**. Hampir semua peran yang di Windows dipegang Registry (konfigurasi sistem, daftar service, startup program) di Linux tersebar sebagai **plaintext file** di `/etc` dan unit file `systemd` — ini konsekuensi besar untuk metodologi investigasi: lebih banyak `cat`/`grep` file teks, lebih sedikit parsing binary hive.

> 📌 **Prinsip FHS:** Struktur ini distandarkan lintas-distro (Filesystem Hierarchy Standard) — artinya lokasi `/etc/passwd` atau `/var/log/` **konsisten** di Ubuntu, Debian, RHEL, Fedora, dst, walau isi detailnya (nama paket, format log) bisa sedikit berbeda per-distro.

---

#### 1.2.2 /bin, /sbin, /usr/bin, /usr/sbin — Binary & Symlink Modern

**Pengertian & Fungsi:**
Historically, `/bin` (binary penting untuk single-user mode) dan `/usr/bin` (binary umum) adalah direktori terpisah secara fisik. Distro modern (Ubuntu 16.04+, Fedora, Arch, Debian sejak beberapa rilis) sudah menerapkan **usrmerge** — menyatukan semuanya jadi symlink.

```
/bin    -> /usr/bin       (symlink)
/sbin   -> /usr/sbin      (symlink)
/lib    -> /usr/lib       (symlink)
/lib64  -> /usr/lib64     (symlink, kalau ada)
```

| Direktori (Legacy) | Isi | Kondisi di Distro Modern |
|---|---|---|
| `/bin` | Binary esensial (`ls`, `cp`, `bash`) | Symlink ke `/usr/bin` |
| `/sbin` | Binary administratif (`fdisk`, `iptables`) | Symlink ke `/usr/sbin` |
| `/usr/bin` | Binary aplikasi umum | Lokasi fisik sebenarnya (post-usrmerge) |
| `/usr/sbin` | Binary administratif tambahan | Lokasi fisik sebenarnya (post-usrmerge) |

```bash
# Cek apakah sistem sudah usrmerge
ls -la /bin
# Kalau hasilnya "bin -> usr/bin", berarti sudah usrmerge
```

> ⚠️ **Relevansi forensik:** Saat investigasi timeline eksekusi (evidence of execution, akan dibahas di bab-bab berikutnya), path lengkap binary yang tercatat di log **bisa berbeda tampilan** (`/bin/bash` vs `/usr/bin/bash`) tergantung apakah sistem sudah usrmerge — keduanya menunjuk file fisik yang sama, jangan sampai dikira dua binary berbeda.

---

#### 1.2.3 /etc — Configuration Files

**Pengertian & Fungsi:**
Ini adalah **direktori paling analog dengan Registry Windows** dari sisi fungsi (walau format-nya plaintext, bukan binary hive) — hampir semua konfigurasi sistem-wide ada di sini.

```
/etc/
├── passwd                  ← Daftar user & UID/GID (TANPA password hash)
├── shadow                  ← Password hash user (readable root only)
├── group                    ← Daftar group & keanggotaan
├── sudoers / sudoers.d/     ← Konfigurasi privilege sudo
├── hostname                 ← Nama host sistem
├── hosts                    ← Static DNS mapping (setara hosts file Windows)
├── fstab                    ← Konfigurasi mount otomatis saat boot
├── crontab, cron.d/, cron.daily/  ← Scheduled task (persistence populer)
├── systemd/system/          ← Unit file systemd custom (service, timer — persistence)
├── ssh/                     ← Konfigurasi SSH daemon (sshd_config) & host key
├── network/ atau netplan/   ← Konfigurasi jaringan (beda per-distro)
├── resolv.conf               ← Konfigurasi DNS resolver
├── profile, bash.bashrc     ← Script yang dijalankan saat shell start (persistence populer)
└── skel/                     ← Template file default untuk user baru
```

| File/Folder | Nilai Forensik |
|---|---|
| `/etc/passwd` + `/etc/shadow` | Daftar semua akun sistem — cek akun baru mencurigakan (UID 0 selain root = red flag) |
| `/etc/sudoers` + `/etc/sudoers.d/` | Privilege escalation — user yang diberi akses sudo tanpa password (`NOPASSWD`) |
| `/etc/crontab`, `/etc/cron.d/` | Persistence via scheduled task — setara Scheduled Task Windows |
| `/etc/systemd/system/*.service` | Persistence via custom service — setara Windows Service |
| `/etc/ssh/sshd_config` | Konfigurasi akses SSH — cek apakah root login diizinkan, port custom, dll |
| `/etc/ld.so.preload` | Mekanisme LD_PRELOAD system-wide — teknik rootkit userspace klasik |

```bash
# Cek user dengan UID 0 selain root (red flag privilege escalation)
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Cek semua crontab sistem sekaligus
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
```

> 💡 **Kenapa `/etc` jadi salah satu direktori paling awal dicek:** Sama seperti registry `Run`/`RunOnce` key jadi cek pertama di Windows, `/etc` menyimpan hampir semua titik persistence system-wide di Linux (cron, systemd service, shell startup script, LD_PRELOAD) dalam satu tempat yang mudah di-`grep`.

---

#### 1.2.4 /home & /root — Profil User

**Pengertian & Fungsi:**
Setara `Users\` di Windows (Windows Bab 1 §1.2.5) — tempat data & aktivitas personal tiap user. `/root` terpisah khusus untuk superuser karena alasan keamanan (supaya tetap accessible walau `/home` gagal di-mount).

```
/home/
└── <username>/
    ├── .bash_history           ← History command shell (setara PSReadLine Windows)
    ├── .bashrc, .bash_profile  ← Script startup shell — persistence populer
    ├── .ssh/
    │   ├── authorized_keys      ← Public key yang diizinkan login — backdoor SSH klasik
    │   ├── known_hosts           ← Riwayat host yang pernah dikoneksi via SSH
    │   └── id_rsa / id_ed25519  ← Private key (kalau ada, kredensial berharga)
    ├── .config/                 ← Config aplikasi user (setara AppData\Roaming)
    ├── .cache/                  ← Cache aplikasi (setara AppData\Local)
    ├── .local/share/             ← Data aplikasi user (setara AppData\Local juga)
    ├── Desktop/, Documents/, Downloads/  ← File user langsung (kalau pakai desktop environment)
    └── .viminfo, .python_history, dll    ← History tool spesifik

/root/                            ← Home direktori superuser, struktur sama dengan /home/<user>
```

| File | Nilai Forensik |
|---|---|
| `.bash_history` (juga `.zsh_history`, dsb) | Command yang pernah diketik user — **sangat rawan dihapus attacker**, cek juga `HISTFILE`/`HISTSIZE` env var untuk tahu apakah logging dinonaktifkan |
| `.ssh/authorized_keys` | SSH key attacker yang ditambahkan untuk akses persisten — cek apakah ada entry yang tidak dikenali |
| `.bash_profile`, `.bashrc`, `.profile` | Sering disisipi command berbahaya yang jalan tiap kali shell dibuka |

```bash
# Cek semua bash history di seluruh home directory sekaligus
sudo find /home /root -name "*.bash_history" -o -name "*.zsh_history" 2>/dev/null

# Cek isi authorized_keys semua user
sudo find / -name "authorized_keys" 2>/dev/null -exec cat {} \;
```

> ⚠️ **Kenapa `.bash_history` tidak selalu bisa dipercaya penuh:** Attacker yang cukup paham sering export `HISTFILE=/dev/null` atau `unset HISTFILE` di awal sesi sebelum beraksi — kekosongan history yang mencurigakan (user aktif tapi history kosong/terlalu pendek) adalah sinyal sendiri, mirip prinsip "absence of evidence" yang nanti dibahas di bab Timeline Correlation.

---

#### 1.2.5 /var — Log, Cache, Spool

**Pengertian & Fungsi:**
Direktori untuk data yang **sering berubah** selama sistem berjalan — dan yang paling penting untuk forensik, ini rumah dari hampir semua **log sistem**.

```
/var/
├── log/
│   ├── syslog atau messages       ← Log sistem umum (beda nama per-distro)
│   ├── auth.log atau secure       ← Log autentikasi (login, sudo, SSH)
│   ├── kern.log                    ← Log kernel
│   ├── dpkg.log / yum.log          ← Log instalasi paket software
│   ├── apache2/ atau httpd/        ← Log web server (kalau ada)
│   ├── audit/audit.log             ← Log auditd (kalau diaktifkan — setara Sysmon Windows)
│   └── journal/                     ← Binary journal systemd (journald)
├── spool/
│   ├── cron/                        ← Crontab per-user (tambahan dari /etc/cron*)
│   └── mail/                        ← Local mail queue
├── cache/                            ← Cache aplikasi & package manager
├── lib/
│   ├── dpkg/ atau rpm/               ← Database package manager
│   └── docker/, containerd/          ← Data container (relevan untuk bab Container Forensics)
└── www/                               ← Root direktori web server default (kalau ada)
```

| Sub-area | Nilai Forensik | Detail Lanjutan |
|---|---|---|
| `/var/log/auth.log` (Debian/Ubuntu) atau `/var/log/secure` (RHEL/CentOS) | Login SSH, penggunaan `sudo`, percobaan gagal | Bab Log Forensics |
| `/var/log/journal/` | Binary log systemd — superset dari banyak log teks lain | `journalctl`, Bab Log Forensics |
| `/var/log/audit/audit.log` | Log auditd — syscall-level, setara Sysmon di Windows kalau dikonfigurasi | Bab Log Forensics / Malware Analysis |
| `/var/lib/dpkg/status` (atau rpm database) | Riwayat instalasi software — kapan paket di-install | Cross-reference evidence of existence |

```bash
# Quick check login gagal (brute force indicator)
grep "Failed password" /var/log/auth.log

# Quick check penggunaan sudo
grep "sudo:" /var/log/auth.log
```

> 📖 **Detail parsing mendalam semua log ini** (format syslog, journald binary structure, auditd rule, korelasi lintas-log) dibahas penuh di bab **Log Forensics — Syslog & Journald**. Bagian ini cuma peta lokasi.

---

#### 1.2.6 /tmp & /dev/shm — Staging Area Favorit Attacker

**Pengertian & Fungsi:**
Direktori dengan permission **world-writable** (`777`) — siapapun user bisa nulis di sini, menjadikannya lokasi favorit attacker untuk staging payload sebelum eksekusi.

| Direktori | Karakteristik |
|---|---|
| `/tmp` | Biasanya di-mount sebagai `tmpfs` (RAM) di distro modern, tapi bisa juga persisten di disk tergantung konfigurasi — **isi hilang saat reboot kalau tmpfs** |
| `/dev/shm` | **Selalu** tmpfs (shared memory) — sering dipakai malware fileless untuk menghindari jejak disk sama sekali |

```bash
# Cek apakah /tmp adalah tmpfs (hilang saat reboot) atau disk persisten
mount | grep " /tmp "

# Cari file executable mencurigakan di /tmp dan /dev/shm
find /tmp /dev/shm -type f -executable 2>/dev/null
```

> ⚠️ **Konsekuensi forensik dari tmpfs:** Kalau `/tmp`/`/dev/shm` adalah tmpfs dan sistem sudah di-reboot sejak insiden, **bukti fisiknya hilang permanen** — tidak seperti file yang dihapus di disk (masih bisa di-carve dari unallocated space, §1.1.9). Ini alasan kuat kenapa memory forensics (RAM capture) jadi krusial di Linux kalau ada indikasi payload staging di tmpfs sebelum sempat di-image.

---

#### 1.2.7 /proc & /sys — Virtual Filesystem

**Pengertian & Fungsi:**
Dua direktori ini **bukan filesystem fisik** — mereka adalah representasi **live state kernel & proses** yang di-generate on-the-fly. Tidak ada padanan langsung di Windows (paling dekat: Task Manager + WMI, tapi diakses lewat API, bukan filesystem).

```
/proc/
├── <PID>/                    ← Satu folder per proses yang sedang berjalan
│   ├── cmdline                 ← Command line lengkap yang menjalankan proses
│   ├── environ                  ← Environment variable proses tsb
│   ├── exe                       ← Symlink ke binary yang dijalankan (bisa "(deleted)" — indikasi fileless malware!)
│   ├── fd/                       ← File descriptor terbuka (termasuk koneksi network sebagai socket)
│   ├── maps                       ← Memory mapping proses
│   └── status                     ← Info status proses (UID, memory usage, dll)
├── net/tcp, net/udp            ← Koneksi jaringan aktif (level kernel, tanpa perlu netstat)
├── mounts                        ← Daftar filesystem yang sedang di-mount
└── version                        ← Versi kernel

/sys/
├── class/                     ← Info device per-kelas (network interface, block device, dll)
├── block/                      ← Info block device
└── module/                     ← Kernel module yang ter-load (relevan untuk deteksi rootkit LKM)
```

> ⚠️ **Karakteristik paling penting:** `/proc` dan `/sys` **hanya ada saat sistem live/berjalan** — begitu mesin di-shutdown atau di-image sebagai disk mati, kedua direktori ini **kosong total** di dalam image (mereka bukan data yang tersimpan di disk). Ini artinya analisis `/proc` cuma bisa dilakukan di sistem live atau lewat memory dump (Bab Memory Forensics), **tidak bisa** dilakukan lewat static disk image forensik biasa.

```bash
# Cari proses dengan binary yang sudah dihapus dari disk tapi masih berjalan (fileless indicator)
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Cek koneksi network aktif langsung dari kernel (tanpa netstat)
cat /proc/net/tcp
```

> 💡 **Kenapa `/proc/*/exe` menunjukkan "(deleted)" itu sinyal kuat:** Attacker sering menjalankan payload lalu langsung menghapus file fisiknya dari disk (`rm payload; ./payload` sudah dijalankan sebelumnya, atau exec-then-unlink) — proses tetap berjalan di memori (Linux tidak masalah menjalankan binary yang filenya sudah dihapus), tapi jejak file di disk hilang. Ini teknik anti-forensik khas Linux yang **tidak ada padanan langsung** di Windows.

---

#### 1.2.8 /dev — Device Files

**Pengertian & Fungsi:**
Representasi semua hardware & device virtual sebagai file — filosofi khas Unix "everything is a file".

| Device | Fungsi |
|---|---|
| `/dev/sda`, `/dev/nvme0n1`, dst | Block device disk (§1.1.1) |
| `/dev/null` | "Black hole" — data yang ditulis ke sini langsung dibuang |
| `/dev/zero` | Sumber byte nol tak terbatas |
| `/dev/random`, `/dev/urandom` | Sumber data acak (untuk enkripsi, dll) |
| `/dev/tty*`, `/dev/pts/*` | Terminal session — bisa dikorelasikan dengan sesi login aktif |
| `/dev/shm` | Shared memory (tmpfs, dibahas §1.2.6) |

> 💡 **Relevansi forensik terbatas tapi ada:** `/dev/null` kadang disalahgunakan attacker untuk "menyembunyikan" output command (`command > /dev/null 2>&1`) di script persistence — kalau ditemukan pola ini di crontab/systemd unit file, itu indikasi attacker sengaja membungkam output supaya tidak meninggalkan jejak di log manapun.

---

#### 1.2.9 /opt, /mnt, /media — Third-party & Removable Media

**Pengertian & Fungsi:**
Tiga direktori dengan peran berbeda tapi sering disebut bersamaan karena semuanya "bukan bagian inti sistem".

| Direktori | Fungsi | Analog Windows |
|---|---|---|
| `/opt` | Instalasi software third-party yang self-contained (tidak ikut package manager distro) | `Program Files\` |
| `/mnt` | Mount point manual (biasanya oleh admin, sementara) | Drive letter tambahan (manual mount) |
| `/media` | Mount point otomatis untuk removable media (USB, CD) | Auto-mount drive letter USB |

```bash
# Cek riwayat device removable yang pernah tersambung (dari kernel log)
dmesg | grep -i usb
journalctl -k | grep -i usb

# Cek device yang sedang ter-mount
lsblk -f
```

> 📖 **Detail forensik USB device history** (kapan dicolok, serial number, korelasi ke file yang diakses) dibahas lebih dalam di bab User/Auth/Shell Artifacts — bagian ini cuma menunjukkan lokasi mount point-nya.

---

#### 1.2.10 /boot — Kernel & Bootloader Files

**Pengertian & Fungsi:**
Sudah disinggung di §1.1.7 (boot process) — bagian ini detail isinya sebagai direktori.

```
/boot/
├── vmlinuz-<versi>              ← Kernel image
├── initrd.img-<versi>            ← Initial RAM filesystem
├── System.map-<versi>             ← Symbol table kernel (debugging)
├── config-<versi>                  ← Konfigurasi kernel saat kompilasi
├── grub/
│   └── grub.cfg                     ← Konfigurasi menu boot GRUB
└── efi/EFI/<distro>/                ← (kalau UEFI) bootloader .efi, mirror dari ESP
```

> ⚠️ **Kenapa relevan untuk persistence tingkat lanjut:** Modifikasi `grub.cfg` bisa menyisipkan boot parameter berbahaya (misal `init=/bin/bash` untuk bypass login, atau kernel parameter yang melemahkan security module). Kernel/initramfs custom yang di-inject adalah teknik paling sulit dideteksi karena berjalan sebelum hampir semua tooling forensik userspace relevan.

---

#### 1.2.11 Tabel Prioritas Investigasi

Paralel dengan Windows Bab 1 §1.2.12 — urutan umum kalau baru mulai investigasi Linux dan bingung mulai dari mana:

| Prioritas | Direktori/File | Alasan |
|---|---|---|
| 1 | `/var/log/` (auth.log, syslog, journal) | Timeline aktivitas sistem paling lengkap |
| 2 | `/etc/passwd`, `/etc/shadow`, `/etc/sudoers*` | Akun & privilege — deteksi user/privesc mencurigakan |
| 3 | `/etc/crontab`, `/etc/cron.d/`, `/etc/systemd/system/` | Persistence — setara Registry Run key & Scheduled Task |
| 4 | `/home/<user>/.bash_history`, `.ssh/` | Aktivitas & akses user spesifik |
| 5 | `/tmp`, `/dev/shm` | Staging area attacker (cek dulu sebelum reboot menghapusnya) |
| 6 | `/var/lib/dpkg/` atau rpm database | Riwayat instalasi software |
| 7 | `/proc/*/exe`, `/proc/net/tcp` (kalau sistem live) | Proses & koneksi aktif, indikasi fileless malware |
| 8 | `/opt/` | Software third-party non-standar |

---

#### 1.2.12 Persistent vs Volatile — Ringkasan

**Pengertian & Fungsi:**
Sepanjang §1.2, sudah disinggung beberapa kali secara tersebar bahwa sebagian direktori **hilang saat reboot** (`/tmp` kalau tmpfs, §1.2.6) dan sebagian lagi **tidak pernah ada di disk image mati sama sekali** (`/proc`, `/sys`, §1.2.7). Tabel ini merangkum semuanya jadi satu referensi cepat — penting dipahami sebelum lanjut ke bab Memory Forensics nanti, karena menentukan **kapan** suatu bukti harus ditangkap (live capture vs bisa menyusul lewat disk image).

| PERSISTENT (ada di disk image) | VOLATILE / LIVE (butuh sistem live atau memory capture) |
|---|---|
| `/etc` | `/proc` |
| `/home` | `/sys` |
| `/var` | `/run` |
| `/usr` | `/dev/shm` |
| `/boot` | `/tmp` (kalau di-mount sebagai tmpfs) |
| `/opt` | — |

> ⚠️ **Implikasi langsung untuk urutan kerja investigasi:** Begitu ada indikasi bukti kemungkinan ada di kolom VOLATILE (proses mencurigakan masih jalan, payload di `/dev/shm`, koneksi network aktif di `/proc/net/tcp`), itu harus **ditangkap duluan** (live triage atau memory dump) **sebelum** mesin dimatikan untuk imaging disk — karena begitu shutdown/reboot, seluruh isi kolom kanan hilang permanen dan tidak bisa direkonstruksi dari disk image manapun. Kolom PERSISTENT bisa menyusul kapan saja karena tersimpan fisik di disk.

---

#### 1.2.13 Full Path Tree — Master Reference

Rangkuman satu tree besar seluruh path yang sudah dibahas di Bab 1 — dipakai sebagai referensi cepat.

```
/
├── boot/                                     (§1.2.10)
│   ├── vmlinuz-*, initrd.img-*
│   └── grub/grub.cfg
│
├── etc/                                       (§1.2.3)
│   ├── passwd, shadow, group
│   ├── sudoers, sudoers.d/
│   ├── crontab, cron.d/, cron.daily/
│   ├── systemd/system/*.service
│   ├── ssh/sshd_config
│   ├── hosts, hostname, resolv.conf, fstab
│   ├── ld.so.preload
│   └── profile, bash.bashrc
│
├── home/                                       (§1.2.4)
│   └── <username>/
│       ├── .bash_history, .zsh_history
│       ├── .bashrc, .bash_profile, .profile
│       ├── .ssh/authorized_keys, known_hosts, id_rsa
│       ├── .config/, .cache/, .local/share/
│       └── Desktop/, Documents/, Downloads/
│
├── root/                                       (§1.2.4 — struktur sama dengan /home/<user>)
│
├── var/                                         (§1.2.5)
│   ├── log/
│   │   ├── syslog / messages, auth.log / secure, kern.log
│   │   ├── audit/audit.log
│   │   └── journal/ (binary systemd journal)
│   ├── spool/cron/, spool/mail/
│   ├── cache/
│   └── lib/dpkg/ atau rpm/, lib/docker/
│
├── tmp/  &  dev/shm/                            (§1.2.6 — staging area, sering tmpfs)
│
├── proc/                                         (§1.2.7 — live-only, kosong di disk image mati)
│   └── <PID>/cmdline, exe, fd/, environ, maps
│
├── sys/                                          (§1.2.7 — live-only)
│   └── module/ (deteksi rootkit LKM)
│
├── dev/                                          (§1.2.8)
│   ├── sda*, nvme0n1p*, vda*                     (block device, §1.1.1)
│   ├── null, zero, random, urandom
│   └── tty*, pts/*
│
├── opt/                                          (§1.2.9)
├── mnt/  &  media/                               (§1.2.9)
│
├── usr/
│   ├── bin/, sbin/                               (lokasi fisik binary post-usrmerge, §1.2.2)
│   └── lib/
│
├── bin -> usr/bin, sbin -> usr/sbin              (symlink, §1.2.2)
│
└── run/                                          (tmpfs, PID file & socket runtime)
```

> 📝 Sama seperti Windows Bab 1, tree ini adalah rangkuman navigasi — pengertian, fungsi, dan tools masing-masing path kembali ke sub-bab yang tertera.

---

## 📎 Lampiran Bab 1 — Master Acquisition & Export Workflow (Linux)

> Paralel dengan Lampiran di Windows Bab 1 — alur generik ini dirujuk berulang di bab-bab Linux berikutnya, supaya tidak ditulis ulang tiap bab.

```
1. Akuisisi image dari disk fisik/live system
   sudo dc3dd if=/dev/sda hash=sha256 log=acquisition.log of=disk.dd
   (atau pakai Guymager untuk workflow GUI, hasil bisa .dd/.E01)

2. Cek struktur partisi & aktivasi LVM kalau perlu
   sudo fdisk -l disk.dd
   sudo losetup -fP disk.dd        # buat loop device dengan partition mapping otomatis
   sudo vgchange -ay                # aktivasi LVM kalau terdeteksi (§1.1.4)

3. Mount READ-ONLY ke direktori evidence terpisah
   sudo mkdir /mnt/evidence
   sudo mount -o ro /dev/loop0p1 /mnt/evidence

4. Copy/export artefak target dari dalam mount point
   (path spesifik tiap jenis artefak dibahas di bab masing-masing:
    /etc/, /var/log/, /home/<user>/, dll)

5. Analisis file teks langsung (grep/awk/cat), atau load log terstruktur
   ke tool timeline (Timeline Explorer bisa dipakai lintas-platform untuk CSV hasil parsing)

6. SELALU unmount & lepas loop device setelah selesai
   sudo umount /mnt/evidence
   sudo losetup -d /dev/loop0
```

> 💡 **Perbedaan filosofi dari workflow Windows:** Di Windows, banyak artefak butuh parser khusus (RECmd, EvtxECmd) karena formatnya binary. Di Linux, sebagian besar artefak inti (`/etc/passwd`, log syslog, crontab) adalah **plaintext** — bisa langsung dibaca dengan `cat`/`grep`/`awk` tanpa tool tambahan. Parser khusus baru dibutuhkan untuk data terstruktur/binary seperti journald (`journalctl`), Ext4 metadata (Bab 2), atau memory dump (bab Memory Forensics).

---

## 📍 Penutup Bab 1 — Linux Storage Architecture (Big Picture)

Satu diagram besar merangkum seluruh isi Bab 1, sekaligus peta mental penghubung ke bab-bab berikutnya (Filesystem Forensics Ext4/XFS, Log Forensics, User/Auth Artifacts, dst).

```
Physical Disk / Image
│
├── Block Device Naming — /dev/sd*, /dev/nvme*, /dev/vd*  (§1.1.1)
│
├── Partition Table — MBR / GPT  (§1.1.2 — §1.1.3)
│
├── (opsional) LVM layer — PV → VG → LV  (§1.1.4)
│
├── Boot Chain — BIOS/UEFI → GRUB → kernel + initramfs → systemd  (§1.1.7)
│
├── Filesystem — Ext4 / XFS / Btrfs  (§1.1.6, detail penuh di Bab 2)
│
└── Root Hierarchy "/"  (§1.2.1)
     │
     ├── etc/        ← Config sistem (analog Registry, tapi plaintext)  (§1.2.3)
     ├── home/, root/ ← Aktivitas user  (§1.2.4)
     ├── var/log/     ← Log sistem (fokus bab Log Forensics)  (§1.2.5)
     ├── tmp/, dev/shm/ ← Staging area, sering tmpfs (hilang saat reboot)  (§1.2.6)
     ├── proc/, sys/  ← Live state kernel/proses (tidak ada di disk image mati)  (§1.2.7)
     ├── dev/         ← Device files  (§1.2.8)
     ├── boot/        ← Kernel & GRUB config  (§1.2.10)
     └── usr/, opt/   ← Binary & software third-party  (§1.2.2, §1.2.9)
```

> 🔗 **Menuju Bab 2:** Setelah paham "di mana lokasinya" (Bab 1), Bab 2 masuk ke "bagaimana strukturnya" — inode table, extent tree, journal Ext4 (`jbd2`), dan superblock XFS — level detail yang sama dengan bagaimana Windows Bab 2 membedah `$MFT` dan `$LogFile` NTFS.
