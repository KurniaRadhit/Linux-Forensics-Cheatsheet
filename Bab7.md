## 📌 Daftar Isi — Bab 7

- [Bab 7 — Memory Forensics: Linux (Volatility, /proc)](#bab-7--memory-forensics-linux-volatility-proc)
  - [7.1 Model Mental Memory Forensics Linux](#71-model-mental-memory-forensics-linux)
    - [7.1.1 Kenapa & Kapan Capture RAM](#711-kenapa--kapan-capture-ram)
    - [7.1.2 Apa yang Cuma Ada di Memory](#712-apa-yang-cuma-ada-di-memory)
    - [7.1.3 Live /proc vs Memory Dump — Perbedaan Fundamental](#713-live-proc-vs-memory-dump--perbedaan-fundamental)
  - [7.2 Akuisisi Memory (RAM Acquisition)](#72-akuisisi-memory-ram-acquisition)
    - [7.2.1 LiME & AVML](#721-lime--avml)
    - [7.2.2 Format Output](#722-format-output)
    - [7.2.3 Acquisition Integrity — Hashing & Chain of Custody](#723-acquisition-integrity--hashing--chain-of-custody)
    - [7.2.4 Tantangan Akuisisi](#724-tantangan-akuisisi)
    - [7.2.5 VM Memory Snapshot](#725-vm-memory-snapshot)
  - [7.3 Identifikasi Sistem Target Sebelum Analisis](#73-identifikasi-sistem-target-sebelum-analisis)
    - [7.3.1 Identifikasi Versi Kernel & Build](#731-identifikasi-versi-kernel--build)
    - [7.3.2 Identifikasi Arsitektur](#732-identifikasi-arsitektur)
    - [7.3.3 Kenapa Ini Prasyarat Wajib untuk Volatility](#733-kenapa-ini-prasyarat-wajib-untuk-volatility)
  - [7.4 Volatility 3 Framework Overview](#74-volatility-3-framework-overview)
    - [7.4.1 Arsitektur — Symbol Table vs Profile Lama](#741-arsitektur--symbol-table-vs-profile-lama)
    - [7.4.2 ISF & dwarf2json](#742-isf--dwarf2json)
    - [7.4.3 Plugin Namespace linux.*](#743-plugin-namespace-linux)
    - [7.4.4 Workflow Umum](#744-workflow-umum)
  - [7.5 Kernel vs User Memory — Address Space Overview](#75-kernel-vs-user-memory--address-space-overview)
  - [7.6 Process Analysis via Volatility](#76-process-analysis-via-volatility)
    - [7.6.1 pslist / psaux / pstree](#761-pslist--psaux--pstree)
    - [7.6.2 Hidden/Unlinked Process Detection](#762-hiddenunlinked-process-detection)
    - [7.6.3 Process Lifecycle — Fork/Exec, Zombie & Exited Process Remnants](#763-process-lifecycle--forkexec-zombie--exited-process-remnants)
    - [7.6.4 Command Line & Environment/Secret Recovery](#764-command-line--environmentsecret-recovery)
    - [7.6.5 Memory Maps, ELF Mapping & malfind](#765-memory-maps-elf-mapping--malfind)
    - [7.6.6 Heap & Stack Artifacts](#766-heap--stack-artifacts)
  - [7.7 Filesystem & File Handle Artifacts](#77-filesystem--file-handle-artifacts)
    - [7.7.1 Live Triage vs Memory Analysis — lsof vs linux.lsof](#771-live-triage-vs-memory-analysis--lsof-vs-linuxlsof)
    - [7.7.2 Recovering Deleted-but-Open Files dari Memory](#772-recovering-deleted-but-open-files-dari-memory)
    - [7.7.3 Mount & Filesystem State](#773-mount--filesystem-state)
  - [7.8 Network Artifacts dari Memory](#78-network-artifacts-dari-memory)
    - [7.8.1 Koneksi Aktif](#781-koneksi-aktif)
    - [7.8.2 Korelasi ke /proc/net Live & Log](#782-korelasi-ke-procnet-live--log)
  - [7.9 Malware & Rootkit Hunting via Memory](#79-malware--rootkit-hunting-via-memory)
    - [7.9.1 Kernel Module Enumeration & Hidden Module](#791-kernel-module-enumeration--hidden-module)
    - [7.9.2 Syscall Table Hooking Detection](#792-syscall-table-hooking-detection)
    - [7.9.3 eBPF sebagai Vektor Modern](#793-ebpf-sebagai-vektor-modern)
    - [7.9.4 /proc Comparison — Live vs Memory Dump](#794-proc-comparison--live-vs-memory-dump)
  - [7.10 Credential & Secret Recovery dari Memory](#710-credential--secret-recovery-dari-memory)
    - [7.10.1 Bash History dalam Memory](#7101-bash-history-dalam-memory)
    - [7.10.2 LUKS Key Recovery — Best-Effort, Bukan Jaminan](#7102-luks-key-recovery--best-effort-bukan-jaminan)
    - [7.10.3 Kredensial Lain di Memory](#7103-kredensial-lain-di-memory)
  - [7.11 Deep Dive /proc — Live System Analysis](#711-deep-dive-proc--live-system-analysis)
    - [7.11.1 Per-Process Detail Lengkap](#7111-per-process-detail-lengkap)
    - [7.11.2 /proc Anomaly sebagai Indikator Rootkit Userspace](#7112-proc-anomaly-sebagai-indikator-rootkit-userspace)
    - [7.11.3 /proc/net/* Deep Dive](#7113-procnet-deep-dive)
    - [7.11.4 Kernel-level /proc](#7114-kernel-level-proc)
  - [7.12 Swap & Hibernation Analysis](#712-swap--hibernation-analysis)
    - [7.12.1 Swap sebagai Sumber Tambahan](#7121-swap-sebagai-sumber-tambahan)
    - [7.12.2 Extracting Data dari Swap](#7122-extracting-data-dari-swap)
    - [7.12.3 Hibernation Image](#7123-hibernation-image)
    - [7.12.4 Keterbatasan Lebih Dalam](#7124-keterbatasan-lebih-dalam)
  - [7.13 Korelasi Memory vs Disk vs Log (Tabel Master)](#713-korelasi-memory-vs-disk-vs-log-tabel-master)
  - [7.14 Ringkasan Command & Tools Cheat Sheet](#714-ringkasan-command--tools-cheat-sheet)
  - [7.15 Mini Case Study — Workflow Analisa End-to-End](#715-mini-case-study--workflow-analisa-end-to-end)

*(Bab 1: Struktur Linux & Filesystem Dasar. Bab 2: Filesystem Forensics Ext4/XFS. Bab 3: Syslog, Journald & Log Forensics. Bab 4: User, Auth & Shell Artifacts. Bab 5: Browser Forensics Linux. Bab 6: Persistence — Cron, Systemd, Init Scripts, LD_PRELOAD.)*

---

## Bab 7 — Memory Forensics: Linux (Volatility, /proc)

> 💡 **Posisi Bab 7 di seri ini:** Bab 1-6 seluruhnya bekerja dengan bukti **persisten** — sesuatu yang masih ada setelah mesin dimatikan (disk image, log file, unit file). Bab 7 masuk ke ranah **volatile** — bukti yang cuma ada selama sistem menyala, dan hilang permanen begitu listrik/proses berhenti. Ini bukan bab opsional: beberapa temuan di Bab 1 §1.2.12 (kolom VOLATILE), Bab 1 §1.1.11 (LUKS "dead end"), dan Bab 4 §4.10.2 (evasion `HISTFILE`) secara eksplisit **menunggu** pembahasan di sini untuk ditutup.

> 📖 **Kalau kamu familiar seri Windows:** Volatility 3 dipakai sama persis (framework yang sama, lintas-platform) — bedanya di Linux, Volatility butuh **symbol table spesifik kernel target** (ISF, §7.4.2) yang harus di-generate manual, beda dari Windows yang punya symbol server Microsoft otomatis. Ini salah satu friksi teknis terbesar yang bikin memory forensics Linux terasa lebih "manual" dibanding Windows.

---

### 7.1 Model Mental Memory Forensics Linux

#### 7.1.1 Kenapa & Kapan Capture RAM

**Pengertian & Fungsi:**
RAM menyimpan **state aktif** sistem — proses berjalan, koneksi jaringan terbuka, kunci enkripsi yang sedang dipakai, command yang baru diketik, bahkan payload yang sudah dihapus dari disk tapi masih dieksekusi. Begitu mesin di-shutdown atau di-reboot, seluruh data ini **hilang permanen** — tidak ada cara merekonstruksinya dari disk image manapun.

```
Prioritas akuisisi (urutan volatility Locard — data paling "rapuh" duluan):
1. RAM (isi hilang dalam hitungan detik-menit setelah power loss)
2. Koneksi jaringan aktif & routing table
3. Proses berjalan
4. Disk (persisten, bisa menyusul — Bab 1-2)
5. Log remote/backup (paling tahan lama)
```

> ⚠️ **Keputusan paling kritis di awal investigasi live:** Begitu ada indikasi proses mencurigakan masih berjalan, koneksi jaringan aktif ke IP asing, atau payload di `/dev/shm`/`/tmp` (Bab 1 §1.2.6) yang belum sempat di-disk-image, **RAM harus di-capture SEBELUM mesin dimatikan** — mematikan mesin untuk "mengamankannya" justru menghancurkan bukti paling berharga yang tersisa.

> 📖 **Cross-reference langsung:** Bab 1 §1.2.12 sudah memberi tabel Persistent vs Volatile sebagai pengantar — Bab 7 ini adalah pembahasan penuh dari kolom VOLATILE tersebut.

---

#### 7.1.2 Apa yang Cuma Ada di Memory

| Kategori | Contoh Konkret | Kenapa Tidak Ada di Disk |
|---|---|---|
| Kunci enkripsi aktif | Master key LUKS (§7.10.2), key SSH agent yang di-unlock | Kunci didekripsi ke memory saat dipakai, tidak pernah ditulis plaintext ke disk |
| Command history yang "dihapus" | Command shell walau `HISTFILE=/dev/null` (Bab 4 §4.10.2) | Buffer readline/history tetap ada di memory proses shell selama sesi berjalan, terlepas dari konfigurasi file |
| Proses & file yang sudah di-unlink | Payload yang di-`exec` lalu file-nya dihapus dari disk (Bab 1 §1.2.7) | Kernel tetap menjaga proses berjalan di memory walau inode file sumbernya sudah tidak ada |
| Isi packet jaringan/buffer koneksi | Data yang sedang ditransfer, koneksi TCP aktif | Data transient, tidak pernah "disimpan" ke disk sama sekali |
| Kode yang di-inject ke proses lain | Shellcode hasil process injection, payload fileless (Bab 6 konteks persistence) | Tidak pernah eksis sebagai file — murni hidup di address space proses target |
| Kredensial plaintext sementara | Password yang baru diketik user sebelum di-hash, token session aktif | Sengaja tidak persisten by design untuk keamanan normal — tapi karena itu, sangat berharga forensik |

> 💡 **Kenapa tabel ini jadi justifikasi utama Bab 7:** Setiap baris di atas adalah kelas bukti yang **secara struktural mustahil** ditemukan lewat Bab 1-6 manapun — bukan karena Bab 1-6 kurang lengkap, tapi karena bukti ini memang tidak pernah menyentuh disk sama sekali.

---

#### 7.1.3 Live `/proc` vs Memory Dump — Perbedaan Fundamental

**Pengertian & Fungsi:**
Ini adalah **kesalahpahaman paling umum** bagi yang baru masuk memory forensics Linux: menganggap `/proc` (sudah diperkenalkan di Bab 1 §1.2.7) dan "RAM dump" (hasil LiME/AVML, dianalisis Volatility) adalah **hal yang sama**. Keduanya **sama sekali berbeda** secara mekanisme, walau sama-sama "soal memory".

```
/proc (Live Virtual Filesystem)                    Memory Dump (Raw Physical RAM Snapshot)
─────────────────────────────                       ──────────────────────────────────────
Diakses lewat SYSCALL NORMAL                          Diakses lewat AKUISISI KHUSUS
(read(), open() — sama seperti file biasa)            (LiME/AVML membaca /dev/mem atau /proc/kcore
                                                        raw, TIDAK lewat abstraksi /proc)

BUTUH sistem LIVE & KERNEL BERFUNGSI NORMAL             TIDAK butuh kernel berfungsi —
untuk menjawab query                                     sudah berupa file statis setelah akuisisi

Kernel BISA BERBOHONG lewat interface ini                Physical memory TIDAK BISA "berbohong" —
— rootkit userspace/kernel bisa memanipulasi              apa yang tertulis di byte fisik, itulah
output /proc secara selektif (§7.11.2, §7.9.4)            yang terbaca (walau tetap perlu diinterpretasi
                                                            benar lewat struktur kernel — §7.4)

Snapshot "SEKARANG" — berubah tiap detik,                Snapshot BEKU di satu titik waktu — bisa
tidak bisa diperiksa ulang persis sama                    dianalisis berulang kali, hasil konsisten

Tidak butuh tool tambahan (cat, ls sudah cukup)            Butuh Volatility 3 + ISF yang tepat (§7.3-7.4)
                                                            untuk MEREKONSTRUKSI struktur dari byte mentah
```

> ⚠️ **Konsekuensi paling penting dari perbedaan ini:** Kalau sistem sudah dicurigai terkompromi dengan rootkit level kernel, **`/proc` tidak bisa dipercaya penuh** — rootkit yang hook syscall (§7.9.2) bisa membuat `/proc` "berbohong" (menyembunyikan proses/koneksi tertentu dari output normal). Memory dump mentah yang dianalisis Volatility **membaca struktur data kernel langsung dari byte fisik**, melewati layer syscall yang berpotensi dimanipulasi — inilah alasan kenapa temuan `pslist`/`psscan` Volatility bisa berbeda dari `ps aux` di sistem live yang sama (§7.9.4), dan kenapa perbedaan itu sendiri jadi sinyal forensik yang sangat kuat.

> 📖 **Implikasi metodologis:** `/proc` (§7.11) tetap sangat berguna untuk **triage cepat** di sistem live yang diasumsikan belum terkompromi parah — tapi begitu ada dugaan kompromi level kernel, memory dump + Volatility adalah satu-satunya cara mendapat "kebenaran fisik" yang tidak bisa dimanipulasi oleh sistem yang sedang diperiksa.

---

### 7.2 Akuisisi Memory (RAM Acquisition)

#### 7.2.1 LiME & AVML

**Pengertian & Fungsi:**
Dua tool paling umum untuk mengambil raw memory dump dari sistem Linux live — keduanya bekerja sebagai **kernel module** (LiME) atau **static binary** (AVML) yang membaca physical memory langsung.

| Tool | Cara Kerja | Kelebihan | Keterbatasan |
|---|---|---|---|
| **LiME** (Linux Memory Extractor) | Loadable Kernel Module (`.ko`) — harus di-**compile khusus** untuk versi kernel target sebelum dipakai | Paling matang, banyak didukung Volatility | Butuh kernel headers & compiler tersedia (atau precompile di sistem identik) — sering jadi kendala di CTF/produksi minimal |
| **AVML** (Azure VM Memory acquisition) | Static binary (Rust), tidak butuh kernel module | Tidak butuh compile ulang per-kernel, lebih portable | Dikembangkan Microsoft untuk konteks Azure, tapi bekerja di Linux umum |

```bash
# LiME — compile modul untuk kernel yang SEDANG berjalan (butuh kernel headers cocok)
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# LiME — jalankan akuisisi, output format lime (§7.2.2)
sudo insmod lime.ko "path=/mnt/evidence/memory.lime format=lime"

# AVML — langsung jalankan tanpa compile
sudo ./avml /mnt/evidence/memory.raw
```

> ⚠️ **Kendala praktis LiME di lapangan:** Modul LiME **harus** dikompilasi persis untuk versi kernel target (`uname -r` harus cocok) — kalau tidak ada kernel headers tersedia di sistem target (umum di server production minimal/hardened), compile harus dilakukan di sistem **terpisah** dengan kernel identik, lalu modul dipindahkan. Ini salah satu alasan AVML (static binary, tidak butuh compile) sering jadi pilihan lebih cepat untuk skenario darurat.

---

#### 7.2.2 Format Output

| Format | Karakteristik | Kompatibilitas Volatility |
|---|---|---|
| **Raw/Padded** | Dump mentah byte-for-byte, termasuk "lubang" memory-mapped I/O diisi padding | Didukung penuh, format paling universal |
| **LiME format** | Wrapper dengan header metadata (alamat awal/akhir tiap range memory) di sekitar data raw | Didukung native oleh plugin LiME Volatility |
| **ELF core dump** | Format core dump standar (mirip core dump proses biasa, tapi untuk seluruh kernel memory) | Didukung, umum untuk output `virsh dump`/`gcore` level kernel |

```bash
# Verifikasi format & ukuran file hasil akuisisi
file memory.lime
ls -lh memory.lime
```

---

#### 7.2.3 Acquisition Integrity — Hashing & Chain of Custody

**Pengertian & Fungsi:**
Sama pentingnya dengan akuisisi disk image (Bab 1 §1.1.8) — memory dump **wajib** di-hash segera setelah akuisisi untuk membuktikan integritasnya tidak berubah selama proses analisis, dan dicatat sebagai bagian chain of custody formal.

```bash
# Hash SEGERA setelah akuisisi selesai, SEBELUM file dipindah/disalin kemanapun
sha256sum memory.lime > memory.lime.sha256
sha256sum -c memory.lime.sha256    # verifikasi kapanpun diperlukan

# Catat metadata akuisisi (log terpisah, bagian chain of custody)
echo "Acquisition time: $(date -u)
Tool: LiME v1.9.x
Kernel: $(uname -r)
Hostname: $(hostname)
Investigator: <nama>
SHA256: $(sha256sum memory.lime | awk '{print $1}')" > acquisition_log.txt
```

> ⚠️ **Kenapa ini bukan langkah opsional:** Berbeda dari disk image yang bisa di-mount read-only berulang kali untuk verifikasi (Bab 1 §1.1.8), memory dump **tidak bisa diambil ulang** — begitu proses akuisisi selesai (dan apalagi kalau mesin sudah dimatikan/reboot setelahnya), tidak ada "second chance". Hash yang dicatat di titik ini adalah **satu-satunya** cara membuktikan integritas evidence di pengadilan/laporan formal kalau nanti dipertanyakan.

---

#### 7.2.4 Tantangan Akuisisi

| Tantangan | Detail |
|---|---|
| **KASLR (Kernel Address Space Layout Randomization)** | Kernel modern mengacak alamat base memory kernel setiap boot — Volatility butuh cara menemukan offset yang benar (biasanya otomatis lewat ISF yang tepat, §7.4.2, tapi bisa gagal kalau symbol table tidak cocok persis) |
| **Restricted `/dev/mem` access** | Kernel modern (dengan `CONFIG_STRICT_DEVMEM`) membatasi akses langsung ke `/dev/mem` — LiME/AVML perlu privilege tinggi (root, kadang butuh module signing di-disable) untuk bypass ini |
| **Ukuran RAM besar** | Server modern dengan RAM puluhan-ratusan GB — akuisisi bisa makan waktu lama & butuh storage tujuan yang cukup besar, pertimbangkan kompresi on-the-fly kalau storage terbatas |
| **Cloud/VM tanpa akses fisik** | Instance cloud (AWS/GCP/Azure) sering tidak mengizinkan akuisisi RAM langsung dari dalam guest — solusinya lewat snapshot level hypervisor (§7.2.5) |

---

#### 7.2.5 VM Memory Snapshot

**Pengertian & Fungsi:**
Alternatif akuisisi untuk sistem yang berjalan sebagai **virtual machine** (sangat umum di CTF self-hosted maupun cloud) — mengambil snapshot memory dari sisi **hypervisor**, bukan dari dalam guest OS itu sendiri.

| Platform | Command/Metode |
|---|---|
| **QEMU/KVM** | `virsh dump --memory-only <vm_name> output.dump` — cross-reference Bab 1 §1.1.8 (format `.qcow2`) |
| **VMware** | File `.vmem` yang otomatis dibuat saat VM di-suspend, atau snapshot manual |
| **VirtualBox** | `VBoxManage debugvm <vm_name> dumpvmcore --filename=output.elf` |

```bash
# QEMU/KVM — dump memory tanpa perlu masuk ke dalam guest sama sekali
sudo virsh dump --memory-only --live vm_target /mnt/evidence/vm_memory.dump

# VirtualBox
VBoxManage debugvm "vm_target" dumpvmcore --filename=/mnt/evidence/vm_memory.elf
```

> 💡 **Kenapa metode ini sering lebih disukai untuk CTF/lab:** Snapshot level hypervisor **tidak butuh akses/privilege apapun di dalam guest OS** (tidak perlu compile LiME, tidak perlu khawatir kernel headers) — kalau target investigasi adalah VM yang kamu kontrol hypervisor-nya (skenario umum self-hosted CTF), ini jauh lebih sederhana daripada akuisisi in-guest.

---

### 7.3 Identifikasi Sistem Target Sebelum Analisis

> ⚠️ **Kenapa section ini WAJIB sebelum §7.4:** Volatility 3 **tidak bisa** menganalisis memory dump tanpa tahu persis kernel & arsitektur apa yang menghasilkannya — beda dari beberapa tool forensik lain yang "auto-detect" segalanya. Melewatkan langkah ini adalah penyebab paling umum Volatility gagal total di awal ("no symbol table found").

#### 7.3.1 Identifikasi Versi Kernel & Build

```bash
# Kalau MASIH punya akses live ke sistem sumber (sebelum/segera setelah akuisisi)
uname -a
cat /proc/version
cat /etc/os-release

# Kalau HANYA punya memory dump (tanpa akses live), banner version string sering
# masih bisa di-carve langsung dari raw dump
strings memory.lime | grep -i "Linux version"
```

```
Contoh output yang dicari:
Linux version 5.15.0-91-generic (buildd@lcy02-amd64-076) (gcc (Ubuntu 11.4.0) ...) #101-Ubuntu SMP ...
```

| Info yang Dibutuhkan | Kegunaan |
|---|---|
| Versi kernel lengkap (`5.15.0-91-generic`) | Menentukan ISF (§7.4.2) yang harus dipakai — **harus cocok persis**, bukan cuma "mirip" |
| Distro & versi (`Ubuntu 22.04`) | Konteks tambahan untuk cari/generate symbol table kalau belum tersedia |
| Build ID/timestamp compiler | Verifikasi tambahan kalau ada keraguan kernel telah di-patch/dimodifikasi dari versi resmi |

> ⚠️ **Kenapa "harus cocok persis":** Struktur data kernel internal (`task_struct`, dll — dipakai untuk `pslist`, §7.6.1) **berubah antar versi kernel**, bahkan antar minor patch version sekalipun. ISF yang dibuat untuk `5.15.0-91` berpotensi gagal total atau (lebih berbahaya) memberi hasil **salah tanpa error jelas** kalau dipakai untuk `5.15.0-89`.

---

#### 7.3.2 Identifikasi Arsitektur

```bash
uname -m
# Output umum: x86_64, aarch64 (ARM64), armv7l, dst
```

| Arsitektur | Konteks Umum |
|---|---|
| `x86_64` | Server/desktop/cloud instance mainstream |
| `aarch64` (ARM64) | Cloud instance modern (AWS Graviton, dst), Raspberry Pi 64-bit, banyak perangkat embedded modern |
| `armv7l` (ARM 32-bit) | Perangkat embedded/IoT lebih lama |

> ⚠️ **Kenapa arsitektur mempengaruhi semuanya:** Layout memory, ukuran pointer, calling convention, bahkan struktur beberapa data kernel **berbeda antar arsitektur** — ISF yang benar untuk x86_64 **tidak akan berfungsi** untuk dump ARM64, meski kernel version-nya kebetulan sama persis. Kombinasi (kernel version + arsitektur) adalah dua identitas yang **sama-sama wajib** dicocokkan sebelum lanjut ke Volatility.

---

#### 7.3.3 Kenapa Ini Prasyarat Wajib untuk Volatility

```
Alur ketergantungan:

Kernel Version + Arsitektur (§7.3.1-7.3.2)
        │
        ▼
ISF (Intermediate Symbol File) yang COCOK (§7.4.2)
        │
        ▼
Volatility bisa MENERJEMAHKAN byte mentah di memory dump
menjadi struktur bermakna (task_struct → proses, dst)
        │
        ▼
Plugin linux.* (§7.4.3) baru bisa berfungsi dengan benar
```

> 📌 **Ringkasan praktis:** Jangan pernah jalankan Volatility ke memory dump Linux tanpa terlebih dulu mengonfirmasi §7.3.1 dan §7.3.2 — kalau info ini tidak tercatat saat akuisisi (§7.2.3 seharusnya sudah mencatatnya), langkah pertama sebelum analisis apapun adalah mencoba mengekstraknya dari dump itu sendiri lewat `strings` seperti dicontohkan di §7.3.1.

---

### 7.4 Volatility 3 Framework Overview

#### 7.4.1 Arsitektur — Symbol Table vs Profile Lama

**Pengertian & Fungsi:**
Volatility 2 (versi lama) memakai konsep **"profile"** — bundel signature yang harus dibuat manual dan di-package ke dalam instalasi Volatility itu sendiri. Volatility 3 menggantinya dengan **symbol table (ISF)** yang lebih fleksibel — file JSON terkompresi yang bisa dimuat secara dinamis tanpa perlu modifikasi instalasi tool.

| Aspek | Volatility 2 (Profile) | Volatility 3 (ISF) |
|---|---|---|
| Format | Package Python custom, harus diinstal ke source Volatility | File JSON (`.json.xz`) berdiri sendiri |
| Cara pakai | Copy ke folder profile Volatility, restart tool | Cukup taruh di folder symbols, langsung terbaca |
| Update kernel baru | Butuh rebuild profile & reinstall | Cukup generate ISF baru, tidak sentuh instalasi |
| Status pengembangan | Sudah tidak dikembangkan aktif | **Aktif dikembangkan**, jadi standar saat ini |

> 📌 **Rekomendasi:** Seluruh Bab 7 ini berasumsi memakai **Volatility 3** — Volatility 2 dianggap legacy dan tidak direkomendasikan untuk kasus baru kecuali ada kebutuhan kompatibilitas khusus.

---

#### 7.4.2 ISF & dwarf2json

**Pengertian & Fungsi:**
ISF (Intermediate Symbol File) adalah representasi terstruktur dari **struktur data kernel** (offset field di `task_struct`, dll) — dibuat dari file debug kernel (`vmlinux` dengan simbol debug, atau kombinasi `System.map` + header) lewat tool `dwarf2json`.

```
Sumber untuk generate ISF:
vmlinux (dengan debug symbols)  ────┐
                                       ├──►  dwarf2json  ────►  <nama_kernel>.json  ────►  (xz-compress)
System.map + kernel headers      ────┘                          <nama_kernel>.json.xz
```

```bash
# Generate ISF dari vmlinux yang punya debug symbols
dwarf2json linux --linux /path/to/vmlinux > ubuntu-5.15.0-91-generic.json
xz ubuntu-5.15.0-91-generic.json    # kompresi, hasil .json.xz

# Taruh di direktori symbols Volatility 3
mv ubuntu-5.15.0-91-generic.json.xz ~/.local/share/volatility3/symbols/linux/
```

| Sumber `vmlinux` | Cara Mendapatkan |
|---|---|
| Sistem sama masih tersedia (paling ideal) | Package `linux-image-*-dbgsym` (Ubuntu/Debian) atau `kernel-debuginfo` (RHEL) |
| Repository publik symbol Volatility | https://github.com/Abyss-W4tcher/volatility3-symbols (community-maintained, banyak distro umum sudah tersedia) |
| Kernel custom/jarang | Harus di-generate manual dari sistem identik atau dari source kernel yang di-compile ulang dengan debug info |

> ⚠️ **Friksi terbesar memory forensics Linux dibanding Windows:** Windows punya Microsoft Symbol Server yang otomatis menyediakan symbol untuk hampir semua versi Windows. Linux **tidak punya** pusat simbol terpusat setara itu — investigator sering harus generate ISF sendiri dari sistem target (kalau masih bisa diakses) atau berharap komunitas sudah mem-publish symbol untuk kernel version yang persis sama. Ini alasan §7.3 (identifikasi kernel dulu) begitu krusial — tanpa itu, langkah ini tidak bisa dimulai sama sekali.

---

#### 7.4.3 Plugin Namespace `linux.*`

```bash
# List semua plugin Linux yang tersedia
vol3 --help | grep "^linux\."
```

| Kategori Plugin | Contoh | Dibahas di |
|---|---|---|
| Process | `linux.pslist`, `linux.psscan`, `linux.pstree`, `linux.psaux` | §7.6 |
| Filesystem | `linux.lsof`, `linux.mountinfo` | §7.7 |
| Network | `linux.sockstat`, `linux.netscan` (kalau didukung versi kernel) | §7.8 |
| Malware/Rootkit | `linux.lsmod`, `linux.check_modules`, `linux.check_syscall`, `linux.malfind` | §7.9 |
| Kredensial | `linux.bash` | §7.10 |

---

#### 7.4.4 Workflow Umum

```bash
# Format dasar pemanggilan Volatility 3
vol3 -f memory.lime -s ~/.local/share/volatility3/symbols/linux/ linux.<nama_plugin>

# Contoh konkret
vol3 -f memory.lime linux.pslist
vol3 -f memory.lime linux.bash

# Cek apakah symbol table terdeteksi cocok SEBELUM jalankan plugin lain
vol3 -f memory.lime banners.Banners
# Bandingkan output banner ini dengan versi kernel yang diidentifikasi di §7.3.1
```

> 💡 **`banners.Banners` sebagai langkah verifikasi pertama:** Plugin ini membaca kembali banner version string langsung dari memory dump (mirip cara manual `strings | grep "Linux version"` di §7.3.1, tapi terintegrasi Volatility) — jalankan ini **duluan** sebagai sanity check bahwa symbol table yang dipakai memang cocok, sebelum berinvestasi waktu ke plugin analisis yang lebih berat.

---

### 7.5 Kernel vs User Memory — Address Space Overview

**Pengertian & Fungsi:**
Setiap proses di Linux punya **virtual address space** yang secara konseptual terbagi dua: **userspace** (memory milik proses itu sendiri — kode, heap, stack, §7.6.6) dan **kernel space** (memory milik kernel, di-share/dipetakan sebagian ke semua proses tapi tidak bisa diakses langsung dari userspace tanpa syscall).

```
Virtual Address Space (per-proses, disederhanakan, x86_64):

0xFFFFFFFF...  ┌─────────────────────┐
               │   KERNEL SPACE        │  ← sama untuk semua proses, HANYA kernel yang
               │   (kode kernel,        │     boleh baca/tulis langsung, userspace harus
               │    driver, struktur     │     lewat syscall
               │    task_struct, dst)     │
               ├─────────────────────┤
0x7FFFFFFF...  │   USERSPACE            │  ← UNIK per-proses:
               │   ├── Stack (§7.6.6)     │     - Stack: tumbuh ke bawah, local variable,
               │   ├── mmap/shared libs    │       return address (target klasik buffer overflow)
               │   ├── Heap (§7.6.6)       │     - Heap: alokasi dinamis (malloc)
               │   └── Code (ELF, §7.6.5)   │     - Code: instruksi program dari file ELF
0x00000000     └─────────────────────┘
```

| Aspek | Userspace | Kernel Space |
|---|---|---|
| Akses dari proses biasa | Langsung (read/write normal) | **Tidak bisa** langsung — harus lewat syscall |
| Terlihat di `/proc/PID/maps` (live) | ✅ Ya | ❌ Tidak (transparan bagi userspace) |
| Terlihat di raw memory dump | ✅ Ya | ✅ **Ya** — inilah kelebihan physical dump |
| Dipakai untuk analisis | `malfind` (§7.6.5), heap/stack (§7.6.6) | `lsmod`/`check_syscall` (§7.9), `task_struct` traversal (§7.6.1-7.6.3) |

> 💡 **Kenapa distinction ini penting untuk memahami kekuatan Volatility:** Physical memory dump berisi **KEDUANYA** — userspace semua proses SEKALIGUS kernel space itu sendiri, dalam satu snapshot. Ini yang memungkinkan Volatility melakukan hal yang mustahil dilakukan proses userspace manapun (termasuk `ps`/`lsof` biasa) — membaca struktur kernel internal (`task_struct` linked list, syscall table) langsung, tanpa terikat pembatasan syscall normal yang bisa dimanipulasi rootkit (§7.1.3, §7.9.2).

---

### 7.6 Process Analysis via Volatility

#### 7.6.1 pslist / psaux / pstree

```bash
# List proses dasar — membaca linked list task_struct kernel
vol3 -f memory.lime linux.pslist

# Sertakan command line lengkap tiap proses (setara 'ps aux' tapi dari memory dump)
vol3 -f memory.lime linux.psaux

# Tampilkan hierarki parent-child
vol3 -f memory.lime linux.pstree
```

| Plugin | Cara Kerja Internal | Analog Live Command |
|---|---|---|
| `linux.pslist` | Traverse **linked list** `task_struct` kernel (`init_task` sebagai titik awal) | `ps -ef` (tapi dari snapshot beku) |
| `linux.psaux` | Sama seperti `pslist`, plus ekstraksi argumen command line dari memory proses | `ps aux` |
| `linux.pstree` | Sama seperti `pslist`, direpresentasikan sebagai hierarki | `pstree` |

---

#### 7.6.2 Hidden/Unlinked Process Detection

**Pengertian & Fungsi:**
`pslist` (§7.6.1) bekerja dengan **traverse linked list** — kalau rootkit **secara sengaja meng-unlink** entry proses tertentu dari linked list ini (teknik klasik "DKOM" — Direct Kernel Object Manipulation), proses itu jadi **invisible** bagi `pslist`, walau proses itu **masih benar-benar berjalan** dan masih menggunakan CPU/memory.

```bash
# psscan TIDAK bergantung pada linked list — scan RAW MEMORY untuk pola struktur
# task_struct yang valid (signature-based, mirip carving), TIDAK PEDULI apakah
# struct itu masih "terhubung" ke linked list utama atau sudah di-unlink
vol3 -f memory.lime linux.psscan

# BANDINGKAN kedua hasil — proses yang muncul di psscan TAPI TIDAK di pslist
# adalah kandidat kuat HIDDEN PROCESS
```

```
pslist  → [PID 1] [PID 234] [PID 891] [PID 1502]
psscan  → [PID 1] [PID 234] [PID 891] [PID 1502] [PID 6666]  ← PID 6666 di-unlink dari
                                                                 linked list (hidden dari pslist)
                                                                 tapi struct-nya MASIH ADA
                                                                 secara fisik di memory
```

> ⚠️ **Ini bukti paling kuat dari prinsip §7.1.3:** Kalau `ps aux` di sistem live **juga** tidak menunjukkan PID 6666 (karena `ps` sendiri mengandalkan mekanisme serupa `pslist` lewat `/proc`), tapi `psscan` terhadap memory dump menemukannya — itu bukti definitif bahwa sistem sudah dikompromikan dengan rootkit yang memanipulasi struktur kernel, bukan sekadar proses yang "kebetulan tersembunyi" dari user biasa.

---

#### 7.6.3 Process Lifecycle — Fork/Exec, Zombie & Exited Process Remnants

**Pengertian & Fungsi:**
Proses Linux punya siklus hidup yang meninggalkan jejak di kernel bahkan setelah proses itu sendiri "selesai" — memahami siklus ini penting untuk menginterpretasi temuan `pslist`/`psscan` dengan benar.

```
Siklus Hidup Proses:

fork()  ──►  Proses ANAK dibuat, task_struct baru dialokasikan, PPID = proses induk
   │
   ▼
exec()  ──►  Image proses diganti dengan binary baru (PID SAMA, tapi kode/memory
   │           map berubah total — ini titik yang direkam Amcache-nya-Linux
   │           kalau ada auditd, Bab 3 §3.5)
   │
   ▼
(proses berjalan normal, bisa fork() lagi untuk anak lebih lanjut)
   │
   ▼
exit()  ──►  Proses SELESAI — tapi task_struct TIDAK LANGSUNG dihapus dari kernel
   │           sampai proses INDUK memanggil wait()/waitpid() untuk "mengambil"
   │           exit status-nya (mekanisme reaping)
   ▼
ZOMBIE STATE  ──►  Task_struct MASIH ADA di memory (status Z di 'ps'), berisi
   │                 EXIT CODE dan METADATA TERAKHIR proses tsb — JENDELA FORENSIK
   │                 tambahan selama proses induk belum reap
   ▼
Reaped oleh induk  ──►  task_struct BARU SEKARANG benar-benar didealokasi dari
                          kernel memory
```

| State | Terlihat di `pslist`? | Nilai Forensik |
|---|---|---|
| Running/Sleeping | ✅ Ya | Analisis standar (§7.6.1-7.6.2) |
| **Zombie** | ✅ Ya (status `Z`) | **Jendela tambahan** — exit code & metadata proses yang sudah "selesai" tapi belum di-reap masih bisa dibaca, memberi petunjuk proses tsb berakhir normal atau di-kill paksa |
| Sudah di-reap sepenuhnya | ❌ Tidak lagi | Kalau proses attacker sengaja dibuat singkat & langsung di-reap (parent yang "rapi"), jejak di `pslist` hilang — tapi jejak LAIN (file yang sempat dibuka §7.7, koneksi jaringan §7.8, command line di history §7.10.1) bisa jadi lebih tahan lama |

> 💡 **Kenapa memahami siklus ini penting:** Proses yang berumur sangat pendek (fork-exec-exit cepat, pola umum dropper/loader) mungkin **tidak lagi muncul** di `pslist` pada saat memory dump diambil — tapi jejaknya bisa tersebar di tempat lain (file descriptor yang sempat terbuka, entry di bash history proses induk yang men-spawn-nya). Jangan simpulkan "tidak ada aktivitas mencurigakan" hanya karena `pslist` bersih — proses cepat butuh korelasi ke sumber lain (§7.13).

---

#### 7.6.4 Command Line & Environment/Secret Recovery

**Pengertian & Fungsi:**
Selain command line (`psaux`, §7.6.1), setiap proses juga menyimpan **environment variable**-nya di memory — sumber yang sangat berharga untuk forensik, terutama mengingat pembahasan LD_PRELOAD di Bab 6 §6.7.2 yang menyebutkan environment variable sebagai metode yang "tersebar dan sulit dicek menyeluruh" dari sisi disk/live saja.

```bash
# Volatility 3 tidak selalu punya plugin envars dedicated di semua versi —
# environment variable proses bisa diekstrak lewat kombinasi psaux (untuk beberapa
# versi menampilkan env) atau analisis manual memory maps proses (§7.6.5)
vol3 -f memory.lime linux.psaux
```

| Sumber di Memory | Jenis Data | Relevansi |
|---|---|---|
| Command line arguments | Full command yang dipakai menjalankan proses | Bisa mengandung password/token diketik langsung di CLI (`mysql -p password123`) — kesalahan umum yang sering dieksploitasi forensik |
| Environment variables proses | `LD_PRELOAD` (Bab 6 §6.7.2), `API_KEY`, `AWS_SECRET_ACCESS_KEY`, dst | Kredensial yang sengaja tidak ditulis ke disk/config file tapi di-set sebagai env var — **hanya** terlihat lewat memory (live `/proc/PID/environ`, §7.11.1, atau memory dump) |
| Argv[0] vs argv sebenarnya | Proses yang menyamar (`argv[0]` di-spoof jadi nama proses legit tapi command asli beda) | Indikasi proses berusaha menyembunyikan identitas aslinya dari `ps` casual |

> 📖 **Cross-reference eksplisit ke Bab 6 §6.7.2:** Checklist LD_PRELOAD di Bab 6 menyebutkan "cek proses yang SEDANG BERJALAN" sebagai salah satu sumber (lewat `/proc/PID/environ` live). Bagian ini adalah versi **post-mortem**-nya — kalau sistem sudah dimatikan tapi memory dump sempat diambil sebelumnya, environment variable proses (termasuk `LD_PRELOAD` yang di-set) tetap bisa direkonstruksi dari dump tersebut, bukan cuma dari sistem live.

---

#### 7.6.5 Memory Maps, ELF Mapping & malfind

**Pengertian & Fungsi:**
Setiap proses punya peta memori (`memory maps`) yang menunjukkan region mana untuk apa — termasuk mapping ke file ELF binary/library yang dimuat (§7.5). `malfind` adalah plugin yang mencari **anomali** di peta ini — pola khas kode yang di-inject (bukan dimuat normal dari file ELF resmi).

```bash
# Tampilkan memory map lengkap satu/semua proses
vol3 -f memory.lime linux.proc.Maps --pid <PID>

# Cari region memory mencurigakan (executable + writable, TANPA backing file ELF resmi)
vol3 -f memory.lime linux.malfind
```

```
Memory map proses NORMAL (region terhubung ke file ELF di disk):
0x400000-0x401000  r-xp  /usr/bin/legit_program    ← text segment, executable, dari FILE
0x601000-0x602000  rw-p  /usr/bin/legit_program     ← data segment, dari FILE juga
0x7f8a...-0x7f8b... rw-p  [heap]                      ← heap, TIDAK ada backing file (NORMAL untuk heap)

Memory map MENCURIGAKAN (indikasi code injection):
0x7f1234560000-0x7f1234570000  rwxp  [anonymous, TIDAK ADA backing file]
                                        ← EXECUTABLE + WRITABLE + tidak terhubung file ELF apapun
                                          = pola KLASIK shellcode/payload yang di-inject
```

| Sinyal `malfind` | Signifikansi |
|---|---|
| Region `rwx` (read-write-execute sekaligus) | Kombinasi permission yang **jarang legitimate** — binary normal biasanya memisahkan region executable (read-only) dari writable (data/heap) |
| Tidak ada backing file ELF | Kode yang "seharusnya" datang dari file di disk (Bab 2), tapi region ini tidak terhubung file manapun — cocok dengan konsep fileless malware (Bab 1 §1.2.7 `/proc/*/exe` "(deleted)") |
| Signature MZ/ELF di tengah region anonymous | Indikasi payload berupa executable lengkap yang di-inject, bukan sekadar shellcode kecil |

> 💡 **Cross-reference ke ELF sebagai konsep:** §7.5 sudah menjelaskan bahwa userspace "Code" normal berasal dari file ELF yang di-map. `malfind` pada dasarnya mencari **pengecualian** dari pola normal ini — memory yang berperilaku seperti kode (executable) tapi tidak punya identitas file ELF yang sah di baliknya.

---

#### 7.6.6 Heap & Stack Artifacts

**Pengertian & Fungsi:**
Dua region memory per-proses yang sudah disinggung di §7.5 — heap (alokasi dinamis) dan stack (local variable, return address) sering menyimpan **data sementara** yang sangat berharga forensik, karena keduanya adalah tempat data "hidup" selama proses berjalan sebelum (kalau pernah) ditulis ke disk.

| Region | Isi Umum | Nilai Forensik |
|---|---|---|
| **Heap** | Alokasi dinamis (`malloc`) — buffer, struktur data, string yang dibuat program saat runtime | String password/token yang sempat di-buffer sebelum diproses; sisa data yang sudah "dibebaskan" (`free()`) tapi belum ditimpa alokasi baru masih terbaca |
| **Stack** | Local variable, argumen fungsi, return address | Command/input yang baru diketik user tapi belum di-commit ke storage manapun; pada kasus exploit development (relevan minat CTF binary exploitation kamu), stack adalah target utama analisis buffer overflow |

```bash
# Dump region heap/stack spesifik untuk analisis manual (mis. dengan strings/hex editor)
vol3 -f memory.lime linux.proc.Maps --pid <PID> --dump
strings <hasil_dump_heap_atau_stack> | less
```

> 💡 **Relevansi ke minat CTF kamu:** Heap/stack forensics di memory dump adalah irisan menarik antara **memory forensics** (bab ini) dan **binary exploitation** — teknik yang dipakai untuk menganalisis heap layout demi mencari sisa data forensik (string password, dst) memakai prinsip dasar yang sama dengan analisis heap untuk exploit development, walau tujuannya berbeda (recovery data vs mencari primitive exploitasi).

---

### 7.7 Filesystem & File Handle Artifacts

#### 7.7.1 Live Triage vs Memory Analysis — `lsof` vs `linux.lsof`

**Pengertian & Fungsi:**
⚠️ **Koreksi penting:** `lsof` (List Open Files) sebagai **command** adalah tool **live analysis** — dijalankan langsung di sistem yang sedang berjalan, membaca state saat ini lewat `/proc` (§7.11). Ini **BUKAN** bagian dari Volatility. Volatility punya plugin **terpisah** bernama `linux.lsof` yang secara independen merekonstruksi informasi serupa **dari memory dump** — dua cara yang **secara mekanisme sama sekali berbeda** (persis prinsip §7.1.3), walau tujuannya mirip.

| | `lsof` (live command) | `linux.lsof` (plugin Volatility) |
|---|---|---|
| Dijalankan di mana | Sistem live, langsung di shell | Terhadap file memory dump, bisa offline kapan saja |
| Sumber data | Syscall ke kernel real-time, lewat `/proc/PID/fd/` | Traverse struktur `task_struct` → `file descriptor table` langsung dari byte memory |
| Bisa dimanipulasi rootkit? | ✅ Ya, rentan (§7.1.3) | Lebih tahan (walau tidak 100% imun kalau rootkit sangat canggih memanipulasi struktur di memory juga) |
| Kapan dipakai | Triage cepat saat masih ada akses live | Analisis mendalam/post-mortem, atau saat curiga `/proc` sudah dimanipulasi |

```bash
# LIVE — dijalankan langsung di sistem yang sedang diperiksa
lsof
lsof -p <PID>

# VOLATILITY — dijalankan terhadap file memory dump, TIDAK butuh sistem target menyala
vol3 -f memory.lime linux.lsof
vol3 -f memory.lime linux.lsof --pid <PID>
```

> 📌 **Kenapa koreksi ini penting ditulis eksplisit:** Materi/tutorial yang kurang teliti sering menyamakan kedua hal ini begitu saja karena nama outputnya mirip — padahal keduanya punya tempat yang berbeda dalam metodologi investigasi (§7.2 workflow: live triage duluan kalau memungkinkan, memory dump untuk analisis mendalam/kalau live sudah tidak bisa dipercaya).

---

#### 7.7.2 Recovering Deleted-but-Open Files dari Memory

> 📖 **Cross-reference eksplisit:** Bab 1 §1.2.7 sudah memperkenalkan konsep `/proc/*/exe` yang menunjukkan "(deleted)" sebagai indikator fileless-style execution, dan Bab 2 §2.3 membahas siklus hidup inode setelah `unlink()`. Bagian ini menyatukan keduanya lewat memory forensics.

```bash
# Volatility — cari file descriptor yang merujuk ke inode yang sudah "dihapus" tapi
# masih dipegang proses (persis konsep §1.2.7, tapi versi memory dump/offline)
vol3 -f memory.lime linux.lsof | grep -i "deleted"

# Kalau file masih dipegang open, ISI FISIKNYA seringkali MASIH BISA di-recover
# langsung dari memory (halaman file di-cache kernel selama file descriptor terbuka)
vol3 -f memory.lime linux.elfs    # kalau file yang dimaksud adalah executable ELF
```

> 💡 **Kenapa ini "jendela recovery ketiga" setelah Bab 2:** Bab 2 §2.5.9 sudah membahas recovery lewat inode (kalau belum di-reuse) dan journal. Memory dump menawarkan **jendela ketiga** yang independen — selama proses masih memegang file descriptor terbuka ke file yang sudah di-unlink dari disk, **isi file itu sendiri** (bukan cuma metadata) berpotensi masih ada di page cache kernel, yang terekam utuh dalam memory dump.

---

#### 7.7.3 Mount & Filesystem State

```bash
# Rekonstruksi state mount filesystem PERSIS SAAT dump diambil
vol3 -f memory.lime linux.mountinfo
```

> 📖 **Nilai forensik:** Berguna untuk memverifikasi apakah ada filesystem yang di-mount secara tidak wajar saat insiden (misal attacker mount device eksternal, atau mount bind tersembunyi) — dikorelasikan dengan `/etc/fstab` (Bab 1 §1.1.12) untuk membedakan mount yang "seharusnya ada" vs mount ad-hoc yang muncul saat insiden.

---

### 7.8 Network Artifacts dari Memory

#### 7.8.1 Koneksi Aktif

```bash
# sockstat — traverse struktur socket kernel (mirip pslist tapi untuk koneksi)
vol3 -f memory.lime linux.sockstat

# netscan — signature-based scanning (mirip psscan §7.6.2), bisa menemukan koneksi
# yang sudah "ditutup" secara normal tapi struktur socket-nya belum ditimpa,
# ATAU koneksi yang disembunyikan dari sockstat oleh rootkit
vol3 -f memory.lime linux.netscan
```

> ⚠️ **Prinsip sama seperti `pslist` vs `psscan` (§7.6.2):** Bandingkan hasil `sockstat` (linked-list-based) dengan `netscan` (signature-based) — koneksi yang muncul di salah satu tapi tidak di yang lain adalah sinyal investigasi lebih lanjut, baik karena teknik anti-forensik aktif maupun karena koneksi sudah dalam proses ditutup saat dump diambil.

---

#### 7.8.2 Korelasi ke `/proc/net` Live & Log

> 📖 **Cross-reference:** Bab 1 §1.2.7 sudah menyebut `/proc/net/tcp` sebagai sumber live koneksi jaringan. Bagian ini menegaskan alur korelasi: kalau sistem masih live, bandingkan `linux.sockstat`/`netscan` (dari dump yang baru saja diambil) dengan `/proc/net/tcp` **live** pada saat yang sama — perbedaan di antara keduanya adalah sinyal manipulasi (§7.1.3). Untuk konteks waktu lebih luas, korelasikan lebih lanjut ke log koneksi/firewall (di luar cakupan seri filesystem-focused ini) atau ke auditd (Bab 3 §3.5) kalau ada rule yang memantau syscall jaringan.

---

### 7.9 Malware & Rootkit Hunting via Memory

#### 7.9.1 Kernel Module Enumeration & Hidden Module

```bash
# List module kernel yang ter-load — traverse linked list module (mirip prinsip pslist)
vol3 -f memory.lime linux.lsmod

# Deteksi module yang di-unlink dari linked list tapi struct-nya masih ada di memory
# (persis prinsip psscan §7.6.2, tapi untuk kernel module bukan proses)
vol3 -f memory.lime linux.check_modules
```

> ⚠️ **Rootkit level kernel klasik menyembunyikan diri lewat teknik ini:** Setelah kernel module (LKM) berhasil di-load untuk mendapat kontrol level kernel, module itu sendiri sering **meng-unlink dirinya** dari linked list module (`lsmod` live tidak akan menunjukkannya) — `check_modules` yang bekerja lewat scanning fisik memory (bukan traverse linked list) adalah cara utama menangkap teknik ini.

---

#### 7.9.2 Syscall Table Hooking Detection

**Pengertian & Fungsi:**
Teknik rootkit klasik — mengganti pointer di **syscall table** kernel supaya syscall tertentu (misal `open()`, `read()`, `getdents()` untuk listing direktori) memanggil fungsi **milik rootkit** dulu sebelum (atau bukannya) fungsi kernel asli — inilah mekanisme yang memungkinkan `/proc` "berbohong" seperti disinggung di §7.1.3.

```bash
# Bandingkan alamat tiap entry syscall table dengan alamat yang SEHARUSNYA
# (berdasarkan symbol kernel resmi di ISF) — entry yang menunjuk ke alamat
# di LUAR range kernel/module resmi adalah indikasi hooking
vol3 -f memory.lime linux.check_syscall
```

```
Syscall table NORMAL:
sys_open   →  0xffffffff81234560  (dalam range kernel image resmi)
sys_read    →  0xffffffff81234789  (dalam range kernel image resmi)

Syscall table DI-HOOK:
sys_getdents →  0xffffffffc0891234  (dalam range MODULE, bukan kernel image utama —
                                       kalau module ini TIDAK terdaftar di lsmod/check_modules
                                       yang legitimate, ini indikasi kuat hooking)
```

> 💡 **Kenapa ini "akar" dari banyak temuan sebelumnya:** Kalau `check_syscall` menemukan `getdents`/`getdents64` (syscall yang dipakai `ls`, dan tidak langsung tapi mendasari cara `/proc` menampilkan listing proses) di-hook, itu menjelaskan **kenapa** `/proc` bisa menyembunyikan proses/file dari command live biasa — mengonfirmasi kecurigaan yang muncul dari discrepancy `pslist` vs `psscan` (§7.6.2) atau `sockstat` vs `netscan` (§7.8.1) di section-section sebelumnya.

---

#### 7.9.3 eBPF sebagai Vektor Modern

**Pengertian & Fungsi:**
eBPF (extended Berkeley Packet Filter) adalah fitur kernel modern yang mengizinkan kode **berjalan di dalam kernel** secara aman (ter-verifikasi) tanpa perlu menulis kernel module tradisional — awalnya untuk networking/observability (`tcpdump` modern, dst), tapi kemampuannya untuk **hook syscall dan memfilter/memanipulasi output** membuatnya jadi vektor rootkit generasi baru yang semakin umum dibahas di riset keamanan.

```
Rootkit LKM Tradisional (§7.9.1-7.9.2)          Rootkit berbasis eBPF (Modern)
─────────────────────────────────────             ──────────────────────────
Perlu compile module (.ko) khusus kernel            Bytecode eBPF ter-verifikasi kernel,
target — rentan gagal load kalau versi              lebih portable antar versi kernel
kernel tidak cocok persis

Terdeteksi lewat lsmod/check_modules                TIDAK muncul di lsmod (bukan kernel
(§7.9.1)                                              module tradisional) — butuh tool
                                                        khusus untuk enumerasi program eBPF
                                                        yang ter-attach

Hooking manipulasi syscall table langsung             Memakai mekanisme eBPF resmi (kprobe,
(§7.9.2)                                                tracepoint) yang "sah" secara desain,
                                                          tapi disalahgunakan untuk filtering
                                                          data mirip tujuan rootkit klasik
```

```bash
# Enumerasi program eBPF yang ter-attach (kalau tool/plugin tersedia dan didukung
# versi kernel dump) — dukungan Volatility untuk area ini masih berkembang aktif
vol3 -f memory.lime linux.bpf 2>/dev/null
# (nama plugin bisa berbeda tergantung versi Volatility — cek 'vol3 --help' untuk
# ketersediaan plugin eBPF terbaru)
```

> ⚠️ **Kenapa disebut sebagai kesadaran, bukan panduan teknik mendalam:** Forensik eBPF adalah area yang **masih berkembang aktif** di komunitas DFIR — dukungan tool (termasuk Volatility) belum semapan `lsmod`/`check_syscall` untuk rootkit tradisional. Poin penting untuk dibawa dari sub-bab ini: kalau `lsmod`/`check_modules` (§7.9.1) bersih tapi masih ada indikasi kuat perilaku rootkit (`/proc` tidak konsisten, dst), pertimbangkan eBPF sebagai kemungkinan yang butuh investigasi lebih lanjut dengan tool spesialis (`bpftool` di sistem live, kalau masih bisa diakses) — bukan langsung menyimpulkan "tidak ada rootkit" hanya karena metode deteksi tradisional negatif.

---

#### 7.9.4 `/proc` Comparison — Live vs Memory Dump

**Pengertian & Fungsi:**
Menyatukan seluruh prinsip §7.1.3, §7.6.2, §7.8.1, §7.9.1-7.9.3 jadi satu metodologi eksplisit: **bandingkan sistematis** semua yang terlihat dari `/proc` live dengan yang terekonstruksi dari memory dump, untuk kategori yang sama.

| Kategori | Sumber Live (`/proc`) | Sumber Memory Dump (Volatility) | Bagian |
|---|---|---|---|
| Proses | `ps aux`, `/proc/*/` | `linux.pslist` vs `linux.psscan` | §7.6.1-7.6.2 |
| File descriptor | `lsof`, `/proc/PID/fd/` | `linux.lsof` | §7.7.1 |
| Koneksi jaringan | `/proc/net/tcp`, `ss` | `linux.sockstat` vs `linux.netscan` | §7.8 |
| Kernel module | `lsmod` | `linux.lsmod` vs `linux.check_modules` | §7.9.1 |
| Syscall table | (tidak ada cara live yang reliable untuk verifikasi ini) | `linux.check_syscall` | §7.9.2 |

> 📌 **Metodologi final:** **Setiap** discrepancy antara kolom "Live" dan kolom "Memory Dump" pada tabel di atas adalah kandidat investigasi lanjutan — baik itu karena rootkit aktif memanipulasi output live (§7.1.3), atau karena timing (proses/koneksi berubah state di antara waktu observasi live dan waktu dump diambil, §7.6.3). Membedakan dua kemungkinan ini butuh konteks tambahan (timestamp dump, log, §7.13), tapi discrepancy itu sendiri **selalu** layak dicatat sebagai temuan.

---

### 7.10 Credential & Secret Recovery dari Memory

#### 7.10.1 Bash History dalam Memory

> 📖 **Cross-reference eksplisit:** Bab 4 §4.10.2 sudah membahas teknik evasion attacker (`HISTFILE=/dev/null`, `unset HISTFILE`) yang membuat file `.bash_history` di disk kosong/tidak ada. Bagian ini menutup celah tersebut.

**Pengertian & Fungsi:**
Terlepas dari konfigurasi `HISTFILE`, shell interaktif (Bash) menyimpan buffer history **di memory proses shell itu sendiri** (struktur readline) selama sesi berjalan — buffer ini sama sekali tidak bergantung pada apakah file history di disk aktif atau tidak.

```bash
# Plugin khusus Volatility 3 untuk merekonstruksi command history dari memory
# proses bash, LANGSUNG dari struktur readline di memory — TIDAK PEDULI
# HISTFILE di-disable atau tidak
vol3 -f memory.lime linux.bash
```

> ⚠️ **Kenapa ini salah satu temuan paling bernilai di seluruh Bab 7:** Attacker yang paham forensik dasar sering menonaktifkan history file sebagai langkah anti-forensik pertama (persis yang dibahas Bab 4 §4.10.2) — tapi ini **hanya** mencegah command tersimpan ke **disk**. Command yang **sudah diketik** selama sesi shell attacker masih berjalan **tetap ada** di memory proses bash tersebut, dan bisa direkonstruksi penuh selama memory dump diambil **sebelum** proses shell itu berakhir (exit/logout menutup dan pada akhirnya membebaskan memory tersebut).

---

#### 7.10.2 LUKS Key Recovery — Best-Effort, Bukan Jaminan

> 📖 **Cross-reference eksplisit:** Bab 1 §1.1.11 secara sengaja menyebut LUKS sebagai "dead end" untuk Bab 1, dengan catatan "detail lanjut soal kapan key LUKS mungkin bisa didapat ada di ranah Memory Forensics". Bagian ini menutup janji tersebut — **dengan catatan penting yang harus digarisbawahi**.

**Pengertian & Fungsi:**
Saat volume LUKS ter-mount (unlocked), **master key** untuk dekripsi disimpan di kernel memory (`dm-crypt` subsystem) — secara teori, key ini bisa diekstrak dari memory dump untuk membuka volume tanpa perlu passphrase asli.

```bash
# Volatility tidak selalu punya plugin dm-crypt/LUKS dedicated built-in di semua versi —
# pendekatan umum kombinasi carving pola key size yang wajar + tool spesialis
# eksternal seperti 'cryptsetup' dgn key file hasil ekstraksi manual

# Pendekatan generik — cari region memory dengan entropi tinggi berukuran sesuai
# key length (256-bit/512-bit umum untuk AES) sebagai kandidat
vol3 -f memory.lime linux.malfind    # bisa dipakai heuristik tambahan, bukan tool dedicated
```

> ⚠️ **PENTING — koreksi eksplisit terhadap ekspektasi berlebih:** Recovery LUKS key dari memory **BUKAN proses yang dijamin berhasil**. Beberapa alasan:
> - Key bisa saja **sudah tidak ada** di memory pada saat dump diambil — kernel tidak menjamin key tetap di lokasi/dalam bentuk yang sama selamanya, tergantung aktivitas sistem sejak volume di-mount.
> - Tidak ada plugin Volatility 3 **standar & teruji luas** yang secara otomatis mengekstrak LUKS master key dengan reliable untuk semua versi kernel/skema LUKS — kebanyakan pendekatan bersifat **heuristik/manual** (mencari pola byte dengan karakteristik key kriptografi), bukan ekstraksi terstruktur seperti `pslist`.
> - Bahkan kalau kandidat key ditemukan, **verifikasi** apakah key itu benar (dengan mencoba dekripsi) tetap diperlukan — false positive sangat mungkin terjadi pada data beroentropi tinggi lainnya.
>
> **Kesimpulan yang tepat:** LUKS key recovery dari memory adalah opsi **best-effort** yang **layak dicoba** kalau volume terenkripsi adalah bukti krusial dan sistem masih live/memory sempat di-capture saat volume ter-mount — tapi **tidak boleh** dijadikan asumsi/rencana utama investigasi. Kalau gagal, itu bukan berarti metodologinya salah, melainkan memang keterbatasan yang melekat pada teknik ini.

---

#### 7.10.3 Kredensial Lain di Memory

| Sumber | Detail |
|---|---|
| SSH agent | Private key yang sudah di-`ssh-add` tersimpan di memory proses `ssh-agent` selama agent berjalan — bisa direkonstruksi/dipakai ulang selama proses masih ada |
| Password manager/browser (cross-ref Bab 5) | Browser dengan master password ter-unlock (Bab 5 §5.10) menyimpan kredensial terdekripsi di memory proses browser selama sesi berjalan |
| Token sesi web/API | Bearer token, session cookie yang aktif dipakai, tersimpan sementara di memory proses aplikasi/browser |
| Password diketik CLI | Argumen command line yang mengandung password langsung (§7.6.4) — kesalahan operasional umum yang jadi berkah forensik |

> 📌 **Prinsip umum §7.10:** Semua kredensial yang **sedang aktif dipakai** oleh proses manapun, secara definisi, harus ada dalam bentuk yang bisa dipakai (biasanya plaintext atau bentuk yang bisa langsung dipakai ulang) **di suatu tempat di memory proses tersebut** — ini hukum dasar yang membuat memory forensics begitu bernilai untuk investigasi kredensial, terlepas dari seberapa baik enkripsi di level disk (Bab 1-2).

---

### 7.11 Deep Dive `/proc` — Live System Analysis

> 📖 **Melengkapi Bab 1 §1.2.7:** Bab 1 memberi overview `/proc` sebagai konsep live-only filesystem dengan beberapa contoh dasar. Bagian ini memperdalam untuk kebutuhan investigasi live yang lebih menyeluruh — dengan diingatkan kembali prinsip §7.1.3 bahwa semua ini **bisa dimanipulasi** kalau sistem sudah dikompromikan level kernel.

#### 7.11.1 Per-Process Detail Lengkap

| Path | Isi | Nilai Forensik |
|---|---|---|
| `/proc/<PID>/cmdline` | Command line lengkap | Sama seperti `psaux` (§7.6.1) tapi versi live |
| `/proc/<PID>/environ` | Environment variable proses | Sama seperti §7.6.4, versi live — cek `LD_PRELOAD` (Bab 6 §6.7.2) di sini |
| `/proc/<PID>/exe` | Symlink ke binary yang dijalankan | "(deleted)" jadi indikasi fileless (Bab 1 §1.2.7) |
| `/proc/<PID>/fd/` | Daftar file descriptor terbuka | Setara `lsof -p <PID>` (§7.7.1) |
| `/proc/<PID>/maps` | Memory map proses | Setara `linux.proc.Maps` (§7.6.5), versi live |
| `/proc/<PID>/status` | Status proses (UID, state, memory usage) | Info ringkas tanpa perlu parse `stat` mentah |
| `/proc/<PID>/task/` | Thread individual dalam proses (untuk proses multi-threaded) | Detail granular kalau proses mencurigakan multi-threaded |

```bash
# Dump semua info penting satu proses sekaligus untuk investigasi live cepat
for f in cmdline environ exe fd maps status; do
    echo "=== /proc/<PID>/$f ==="
    cat /proc/<PID>/$f 2>/dev/null
done
```

---

#### 7.11.2 `/proc` Anomaly sebagai Indikator Rootkit Userspace

**Pengertian & Fungsi:**
Selain rootkit level kernel (§7.9), ada juga rootkit **userspace** yang bekerja lebih sederhana — memanipulasi `LD_PRELOAD` (Bab 6 §6.7) untuk hook fungsi library yang dipakai tool seperti `ps`/`ls` (bukan syscall kernel langsung), sehingga tool tersebut "berbohong" walau kernel-nya sendiri tidak dimodifikasi.

```bash
# Bandingkan jumlah proses menurut /proc langsung (bypass 'ps' yang mungkin di-hook)
# vs menurut 'ps' itu sendiri
ls -d /proc/[0-9]* | wc -l
ps aux | wc -l
# Selisih signifikan = indikasi 'ps' sendiri sudah di-hook (userspace rootkit),
# BUKAN /proc yang berbohong — karena /proc di sini diakses langsung lewat 'ls',
# bukan lewat binary 'ps' yang berpotensi sudah di-trojan
```

> 💡 **Distinction penting dari rootkit kernel (§7.9):** Kalau `ls -d /proc/[0-9]*` **juga** tidak menunjukkan proses tersembunyi (beda dari kasus kernel-level di §7.6.2 di mana bahkan akses `/proc` langsung pun bisa "dibohongi" lewat syscall hooking), tapi `ps aux` berbeda — itu mengarah ke rootkit userspace yang lebih sederhana (LD_PRELOAD hijacking `libproc`/fungsi terkait, Bab 6 §6.7) dibanding rootkit kernel penuh yang butuh syscall table hooking (§7.9.2).

---

#### 7.11.3 `/proc/net/*` Deep Dive

| Path | Isi |
|---|---|
| `/proc/net/tcp`, `/proc/net/tcp6` | Koneksi TCP aktif (IPv4/IPv6), format hex untuk IP:port |
| `/proc/net/udp`, `/proc/net/udp6` | Koneksi UDP |
| `/proc/net/unix` | Unix domain socket (komunikasi antar-proses lokal) |
| `/proc/net/arp` | ARP table — berguna untuk deteksi ARP spoofing/lateral movement di jaringan lokal |

```bash
# Baca /proc/net/tcp mentah (format hex, butuh decode manual atau tool bantu)
cat /proc/net/tcp
# Kolom 'local_address' & 'rem_address' dalam format HEXIP:HEXPORT little-endian

# Lebih praktis pakai 'ss'/'netstat' yang sudah decode otomatis (tapi ingat,
# tool ini bisa di-hook seperti 'ps' — §7.11.2)
ss -tulpn
```

---

#### 7.11.4 Kernel-level `/proc`

| Path | Isi | Relevansi |
|---|---|---|
| `/proc/modules` | Daftar kernel module ter-load — versi live dari `lsmod` (§7.9.1) | Bandingkan dengan `linux.lsmod`/`check_modules` dari memory dump untuk deteksi hidden module |
| `/proc/kallsyms` | Symbol table kernel yang sedang berjalan (alamat fungsi kernel) | Berguna untuk verifikasi manual apakah alamat syscall table (§7.9.2) sesuai ekspektasi |
| `/proc/version` | Versi kernel (sudah disebut di §7.3.1) | Identifikasi awal |
| `/proc/kcore` | Representasi virtual seluruh physical memory sebagai "file" ELF core | **Bisa** dipakai sebagai sumber akuisisi live alternatif (mirip fungsi LiME, §7.2.1), tapi kurang umum dipakai langsung dibanding tool dedicated |

> ⚠️ **`/proc/kallsyms` bisa di-restrict:** Kernel modern sering membatasi akses `/proc/kallsyms` untuk user biasa (menampilkan alamat sebagai `0` alih-alih nilai asli) sebagai mitigasi keamanan terhadap KASLR bypass (§7.2.4) — butuh privilege root untuk melihat nilai sebenarnya.

---

### 7.12 Swap & Hibernation Analysis

#### 7.12.1 Swap sebagai Sumber Tambahan

> 📖 **Cross-reference:** Bab 1 §1.1.5 sudah memperkenalkan konsep swap partition/file. Bagian ini membahas nilai forensiknya — swap pada dasarnya adalah **"RAM yang meluap ke disk"**, jadi berpotensi berisi fragmen data yang sama berharganya dengan RAM aktif, tapi dengan karakteristik akses yang berbeda (persisten sampai ditimpa, mirip disk biasa).

```bash
# Identifikasi swap yang aktif/pernah aktif
cat /proc/swaps
swapon --show

# Kalau swap berupa partition terpisah, bisa langsung di-image seperti partisi biasa (Bab 1)
sudo dc3dd if=/dev/sda2 of=swap.dd hash=sha256
```

---

#### 7.12.2 Extracting Data dari Swap

```bash
# Pendekatan paling sederhana — string search untuk kandidat kredensial/command
strings swap.dd | grep -iE "password|BEGIN.*PRIVATE KEY|LUKS"

# bulk_extractor untuk carving lebih terstruktur (email, URL, kredensial pola umum)
bulk_extractor -o output_dir/ swap.dd
```

> 💡 **Kenapa swap kadang lebih "kaya" dari RAM aktif untuk data lama:** Data yang di-swap keluar dari RAM cenderung adalah data yang **kurang aktif dipakai** — termasuk kemungkinan sisa proses yang sudah lama tidak disentuh tapi belum benar-benar dibersihkan. Kombinasi RAM dump (snapshot "sekarang") + swap (potensi riwayat lebih lama) memberi cakupan waktu yang lebih luas dibanding RAM saja.

---

#### 7.12.3 Hibernation Image

**Pengertian & Fungsi:**
Untuk laptop/desktop Linux (jarang di server) yang memakai hibernation (suspend-to-disk), **seluruh isi RAM** ditulis ke disk (biasanya ke swap juga, atau partisi khusus) saat hibernasi — secara efektif ini adalah "memory dump resmi" yang dibuat sistem itu sendiri.

```bash
# Cek apakah hibernation pernah dipakai & di mana image-nya disimpan
cat /sys/power/resume 2>/dev/null    # menunjuk device swap yang dipakai untuk resume
```

> 📌 **Nilai forensik:** Kalau ditemukan bukti hibernation pernah terjadi, image hibernasi (di dalam swap yang sama, §7.12.1) berpotensi berisi snapshot RAM **lengkap** dari titik waktu tertentu di masa lalu — bisa dianalisis dengan pendekatan sama seperti swap biasa (§7.12.2), meski formatnya lebih terstruktur (bukan sekadar fragmen acak).

---

#### 7.12.4 Keterbatasan Lebih Dalam

| Keterbatasan | Detail |
|---|---|
| **Data tidak kontinu** | Swap tidak menyimpan memory secara berurutan/utuh seperti RAM dump — halaman memory yang di-swap tersebar dan terpotong-potong (page-level), berbeda dari struktur linear yang diharapkan Volatility untuk analisis terstruktur |
| **Tidak bisa dianalisis Volatility layaknya RAM dump** | Volatility dirancang untuk physical memory dump yang utuh — swap file/partition **umumnya tidak bisa** langsung dijadikan input Volatility untuk analisis struktural (`pslist`, dst); pendekatan swap lebih ke **carving/string search** (§7.12.2), bukan rekonstruksi struktur kernel |
| **zswap/compressed swap** | Beberapa sistem modern memakai `zswap`/`zram` (kompresi swap di memory itu sendiri sebelum benar-benar ditulis ke disk) — data di swap fisik pada kasus ini bisa jadi **lebih sedikit** dari yang diharapkan, karena sebagian besar sudah "diserap" kompresi di memory |
| **Swap encryption** | Kalau swap di-enkripsi (umum dikombinasikan dengan LUKS full-disk encryption, Bab 1 §1.1.11), analisis langsung terhadap swap **tidak mungkin** tanpa key yang sama — sama persis keterbatasan §7.10.2 |
| **Overwrite cepat** | Swap aktif digunakan terus-menerus oleh sistem yang berjalan — data lama bisa tertimpa jauh lebih cepat dibanding disk biasa, tergantung tekanan memory sistem |

> ⚠️ **Ekspektasi yang tepat:** Swap analysis adalah pelengkap **best-effort** untuk RAM dump (§7.2), bukan pengganti — perlakukan sama seperti LUKS key recovery (§7.10.2): layak dicoba, tapi jangan jadi rencana utama, dan selalu siapkan ekspektasi bahwa hasilnya bisa jadi minim/nihil tergantung konfigurasi sistem (zswap, enkripsi, dst).

---

### 7.13 Korelasi Memory vs Disk vs Log (Tabel Master)

| Pertanyaan Investigasi | Sumber Memory (Bab 7) | Sumber Disk (Bab 1-2) | Sumber Log (Bab 3) |
|---|---|---|---|
| Proses apa yang berjalan saat insiden | `linux.pslist`/`psscan` (§7.6.1-7.6.2) | Evidence of execution tidak langsung (Amcache-nya-Linux tidak ada, andalkan §7.13 kombinasi) | auditd `execve` (Bab 3 §3.5) |
| Command apa yang diketik, walau history dihapus | `linux.bash` (§7.10.1) | `.bash_history` (Bab 4 §4.10, bisa kosong kalau evasion) | auditd command logging kalau dikonfigurasi |
| Koneksi jaringan apa yang aktif | `linux.sockstat`/`netscan` (§7.8.1) | — (tidak ada jejak disk untuk koneksi transient) | Firewall/proxy log (di luar cakupan seri ini) |
| Apakah ada proses tersembunyi (rootkit) | `pslist` vs `psscan` discrepancy (§7.6.2) | — | Anomali start/stop service (Bab 3, Bab 6) |
| Apakah ada persistence yang baru dipasang | Cross-check proses berjalan dengan unit/cron (Bab 6) | Isi file persistence itu sendiri (Bab 6) | journald untuk unit systemd (Bab 3 §3.4) |
| File yang sudah dihapus dari disk tapi masih dieksekusi | `/proc/PID/exe` "(deleted)" live (§7.11.1), atau isi file dari page cache (§7.7.2) | Inode sudah dihapus/di-reuse (Bab 2 §2.3) | — |
| Kunci enkripsi LUKS | Best-effort dari memory dump (§7.10.2) | — (kunci tidak pernah di disk secara desain) | — |
| Kredensial/token aktif | Environment variable, heap proses (§7.6.4, §7.6.6, §7.10.3) | Config file (kalau ceroboh disimpan plaintext, Bab 4/6) | — |
| LD_PRELOAD yang aktif | Environment variable proses live/memory dump (§7.6.4) | `/etc/ld.so.preload` (Bab 6 §6.7.2) | — |
| Kernel module/syscall hooking | `check_modules`/`check_syscall` (§7.9.1-7.9.2) | Modul di disk (`/lib/modules/`, kalau belum dihapus) | dmesg/kernel log untuk load module |

> 💡 **Cara pakai tabel ini:** Sama seperti tabel korelasi bab-bab sebelumnya — perhatikan bahwa banyak baris punya kolom Disk/Log **kosong** ("—"), menegaskan bahwa memory forensics bukan sekadar pelengkap, tapi **satu-satunya** sumber untuk beberapa kategori bukti paling krusial (koneksi transient, kunci enkripsi aktif, kredensial runtime).

---

### 7.14 Ringkasan Command & Tools Cheat Sheet

```bash
# ===== AKUISISI =====
sudo insmod lime.ko "path=/mnt/evidence/memory.lime format=lime"    # LiME
sudo ./avml /mnt/evidence/memory.raw                                  # AVML
sha256sum memory.lime > memory.lime.sha256                             # hashing wajib

# VM snapshot (hypervisor-level, tidak butuh akses in-guest)
sudo virsh dump --memory-only --live vm_target output.dump             # QEMU/KVM
VBoxManage debugvm "vm_target" dumpvmcore --filename=output.elf         # VirtualBox

# ===== IDENTIFIKASI SISTEM (WAJIB SEBELUM VOLATILITY) =====
uname -a; uname -m
cat /proc/version
strings memory.lime | grep -i "Linux version"

# ===== SYMBOL TABLE (ISF) =====
dwarf2json linux --linux /path/to/vmlinux > kernel.json
xz kernel.json
mv kernel.json.xz ~/.local/share/volatility3/symbols/linux/

# ===== VERIFIKASI SYMBOL TABLE =====
vol3 -f memory.lime banners.Banners

# ===== PROSES =====
vol3 -f memory.lime linux.pslist
vol3 -f memory.lime linux.psaux
vol3 -f memory.lime linux.pstree
vol3 -f memory.lime linux.psscan          # deteksi hidden process
vol3 -f memory.lime linux.malfind          # deteksi code injection
vol3 -f memory.lime linux.proc.Maps --pid <PID>

# ===== FILE & MOUNT =====
vol3 -f memory.lime linux.lsof
vol3 -f memory.lime linux.mountinfo

# ===== JARINGAN =====
vol3 -f memory.lime linux.sockstat
vol3 -f memory.lime linux.netscan

# ===== ROOTKIT/MALWARE =====
vol3 -f memory.lime linux.lsmod
vol3 -f memory.lime linux.check_modules
vol3 -f memory.lime linux.check_syscall

# ===== KREDENSIAL =====
vol3 -f memory.lime linux.bash

# ===== LIVE /proc (kalau sistem masih menyala) =====
cat /proc/<PID>/cmdline /proc/<PID>/environ
ls -la /proc/<PID>/fd/
cat /proc/<PID>/maps
ls -d /proc/[0-9]* | wc -l    # cross-check jumlah proses, bypass 'ps' yang mungkin di-hook
cat /proc/net/tcp
cat /proc/modules

# ===== SWAP =====
cat /proc/swaps
strings swap.dd | grep -iE "password|PRIVATE KEY"
bulk_extractor -o output_dir/ swap.dd
```

---

### 7.15 Mini Case Study — Workflow Analisa End-to-End

Skenario: server produksi dicurigai kompromi — proses `ps aux` tidak menunjukkan apapun mencurigakan, tapi monitoring jaringan eksternal melaporkan traffic keluar periodik yang tidak bisa dijelaskan.

```
Langkah 1 — Prioritaskan akuisisi RAM SEBELUM tindakan apapun lain (§7.1.1)
   sudo ./avml /mnt/evidence/memory.raw
   sha256sum /mnt/evidence/memory.raw > memory.raw.sha256    (§7.2.3, wajib)

Langkah 2 — Identifikasi kernel & arsitektur (§7.3, WAJIB sebelum Volatility)
   uname -a
   → Linux 5.15.0-91-generic x86_64
   dwarf2json linux --linux /usr/lib/debug/boot/vmlinux-5.15.0-91-generic > kernel.json
   xz kernel.json && mv kernel.json.xz ~/.local/share/volatility3/symbols/linux/

Langkah 3 — Verifikasi symbol table cocok
   vol3 -f memory.raw banners.Banners
   → Output cocok dengan uname -a di Langkah 2, lanjut

Langkah 4 — Bandingkan proses live vs memory dump (§7.6.2, §7.9.4)
   vol3 -f memory.raw linux.pslist > pslist_output.txt
   vol3 -f memory.raw linux.psscan > psscan_output.txt
   diff <(awk '{print $2}' pslist_output.txt) <(awk '{print $2}' psscan_output.txt)
   → DITEMUKAN: PID 8842 muncul di psscan, TIDAK ADA di pslist — HIDDEN PROCESS

Langkah 5 — Investigasi PID 8842 lebih dalam
   vol3 -f memory.raw linux.psaux | grep 8842
   → Command line: /tmp/.X11-cache/agent --daemon
   (path /tmp — Bab 1 §1.2.6, staging area favorit attacker, konsisten dengan pola)

Langkah 6 — Cek network artifact untuk proses ini (§7.8)
   vol3 -f memory.raw linux.sockstat | grep 8842
   → Koneksi TCP aktif ke IP eksternal, port tidak umum — cocok dengan laporan
     monitoring traffic periodik

Langkah 7 — Cek indikasi rootkit level kernel (kenapa proses ini "hidden" dari pslist)
   vol3 -f memory.raw linux.check_modules
   → DITEMUKAN module "usbcore_helper" tidak terdaftar di lsmod normal — nama
     menyamar modul resmi tapi tidak ada di paket kernel resmi manapun
   vol3 -f memory.raw linux.check_syscall
   → sys_getdents64 di-hook, menunjuk alamat di dalam range module mencurigakan
     di atas — INI PENJELASAN kenapa PID 8842 tidak muncul di 'ps aux' MAUPUN
     'pslist' versi userspace (walau psscan tetap menemukannya secara fisik)

Langkah 8 — Cek command history untuk rekonstruksi bagaimana attacker masuk (§7.10.1)
   vol3 -f memory.raw linux.bash
   → Ditemukan history proses shell yang masih berjalan, menunjukkan urutan
     command: download payload → chmod +x → jalankan dengan nama disamarkan →
     load kernel module custom

KESIMPULAN:
Sistem dikompromikan dengan rootkit LEVEL KERNEL (bukan sekadar userspace) —
modul kernel custom "usbcore_helper" berhasil hook syscall table (§7.9.2) untuk
menyembunyikan proses PID 8842 dari SEMUA observasi live standar (ps, /proc
langsung sekalipun karena getdents64 di-hook, bukan cuma binary 'ps' yang
ditrojan). Traffic periodik yang dilaporkan monitoring eksternal terkonfirmasi
berasal dari proses ini via linux.sockstat. Temuan ini TIDAK MUNGKIN didapat
dari analisis disk (Bab 1-2) atau log (Bab 3) semata — modul kernel custom
kemungkinan besar sudah dihapus dari disk setelah di-load (evidence of
execution di disk minim), dan hooking syscall table membuat auditd/log
standar pun berpotensi tidak lengkap mencatat aktivitas terkait.
```

> 💡 **Pelajaran utama studi kasus ini:** Kasus ini adalah skenario paling ekstrem yang membenarkan keberadaan Bab 7 sebagai bab tersendiri — rootkit level kernel yang canggih bisa membuat **seluruh metodologi Bab 1-6** (disk, log, live command biasa) memberi gambaran yang tidak lengkap atau bahkan menyesatkan. Physical memory dump, dianalisis lewat struktur kernel langsung (bukan lewat syscall yang berpotensi dimanipulasi), adalah satu-satunya cara mendapat "kebenaran fisik" yang tidak bisa dibohongi sistem yang sudah terkompromi — prinsip yang sudah ditegaskan sejak §7.1.3 di awal bab ini.
