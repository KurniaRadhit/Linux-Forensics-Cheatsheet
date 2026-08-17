## 📌 Daftar Isi — Bab 8

- [Bab 8 — Malware & Rootkit Analysis: Linux](#bab-8--malware--rootkit-analysis-linux)
  - [8.1 Overview & Posisi Bab 8](#81-overview--posisi-bab-8)
  - [8.2 Malware Triage & Evidence Handling 🔴](#82-malware-triage--evidence-handling-)
    - [8.2.1 Order of Volatility Terapan untuk Malware](#821-order-of-volatility-terapan-untuk-malware)
    - [8.2.2 Isolasi & Containment Sebelum Analisis](#822-isolasi--containment-sebelum-analisis)
    - [8.2.3 Safe Handling — Akuisisi Sampel Tanpa Eksekusi Tidak Sengaja](#823-safe-handling--akuisisi-sampel-tanpa-eksekusi-tidak-sengaja)
    - [8.2.4 Chain of Custody untuk Sampel Malware](#824-chain-of-custody-untuk-sampel-malware)
  - [8.3 Klasifikasi Rootkit & Malware Linux 🔴](#83-klasifikasi-rootkit--malware-linux-)
  - [8.4 Process Injection & Masquerading 🔴](#84-process-injection--masquerading-)
    - [8.4.1 Process Masquerading — `_COMM` vs `_EXE` vs Realita](#841-process-masquerading--_comm-vs-_exe-vs-realita)
    - [8.4.2 `ptrace`-Based Code Injection](#842-ptrace-based-code-injection)
    - [8.4.3 Runtime LD_PRELOAD Injection ke Proses Berjalan](#843-runtime-ld_preload-injection-ke-proses-berjalan)
    - [8.4.4 Process Hollowing Gaya Linux](#844-process-hollowing-gaya-linux)
  - [8.5 Fileless / Memory-Resident Malware 🔴](#85-fileless--memory-resident-malware-)
    - [8.5.1 Deleted-but-Running Binary](#851-deleted-but-running-binary)
    - [8.5.2 `memfd_create()` — Eksekusi Tanpa Pernah Menyentuh Disk](#852-memfd_create--eksekusi-tanpa-pernah-menyentuh-disk)
    - [8.5.3 tmpfs-Only Payload](#853-tmpfs-only-payload)
    - [8.5.4 Implikasi Forensik Fileless Malware](#854-implikasi-forensik-fileless-malware)
  - [8.6 Deteksi Userland Rootkit 🔴](#86-deteksi-userland-rootkit-)
  - [8.7 Deteksi LD_PRELOAD & Library Hijacking dari Sudut Malware 🔴](#87-deteksi-ld_preload--library-hijacking-dari-sudut-malware-)
  - [8.8 Deteksi Kernel-Level Rootkit (LKM) 🔴](#88-deteksi-kernel-level-rootkit-lkm-)
  - [8.9 Cross-View Rootkit Detection 🔴](#89-cross-view-rootkit-detection-)
  - [8.10 Automated Rootkit Scanner Tools 🟡](#810-automated-rootkit-scanner-tools-)
  - [8.11 Static Malware Analysis (ELF Binary) 🔴](#811-static-malware-analysis-elf-binary-)
    - [8.11.1 Anatomi ELF Ringkas](#8111-anatomi-elf-ringkas)
    - [8.11.2 `readelf`/`objdump` — Header, Symbol, Disassembly Dasar](#8112-readelfobjdump--header-symbol-disassembly-dasar)
    - [8.11.3 String & IOC Extraction Awal](#8113-string--ioc-extraction-awal)
    - [8.11.4 Deteksi Packer/Obfuscation](#8114-deteksi-packerobfuscation)
    - [8.11.5 Hash-Based Identification & Threat Intel Lookup](#8115-hash-based-identification--threat-intel-lookup)
  - [8.12 ELF Dynamic Linking — DT_NEEDED/RPATH/RUNPATH 🟡](#812-elf-dynamic-linking--dt_neededrpathrunpath-)
    - [8.12.1 Cara Kerja Dynamic Linker Mencari Shared Library](#8121-cara-kerja-dynamic-linker-mencari-shared-library)
    - [8.12.2 `DT_NEEDED` — Daftar Dependency & Manipulasinya](#8122-dt_needed--daftar-dependency--manipulasinya)
    - [8.12.3 `RPATH` vs `RUNPATH` — Beda Krusial untuk Hijacking](#8123-rpath-vs-runpath--beda-krusial-untuk-hijacking)
    - [8.12.4 Forensik Dynamic Linking Hijack](#8124-forensik-dynamic-linking-hijack)
  - [8.13 Dynamic/Behavioral Analysis 🔴](#813-dynamicbehavioral-analysis-)
  - [8.14 IOC Extraction & Correlation 🟡](#814-ioc-extraction--correlation-)
  - [8.15 Memory-Based Detection — Pointer ke Bab 7 🔧](#815-memory-based-detection--pointer-ke-bab-7-)
  - [8.16 PAM Backdoor](#816-pam-backdoor)
  - [8.17 Persistence Recap dari Sudut Pandang Malware 🟡](#817-persistence-recap-dari-sudut-pandang-malware-)
  - [8.18 MITRE ATT&CK Mapping (Linux)](#818-mitre-attck-mapping-linux)
  - [8.19 Case Study Pattern — Infection Chain Reconstruction](#819-case-study-pattern--infection-chain-reconstruction)
  - [8.20 Tabel Korelasi — Pertanyaan Investigasi ke Teknik Analisis](#820-tabel-korelasi--pertanyaan-investigasi-ke-teknik-analisis)
  - [8.21 Ringkasan Command & Tools Cheat Sheet](#821-ringkasan-command--tools-cheat-sheet)
  - [8.22 Mini Case Study — Workflow Analisa End-to-End](#822-mini-case-study--workflow-analisa-end-to-end)

*(Bab 1: Struktur Linux & Filesystem Dasar. Bab 2: Filesystem Forensics Ext4/XFS. Bab 3: Syslog, Journald & Log Forensics. Bab 4: User, Auth & Shell Artifacts. Bab 5: Browser Forensics Linux. Bab 6: Persistence — Cron, systemd, Init Scripts, LD_PRELOAD. Bab 7: Memory Forensics Linux.)*

---

## Bab 8 — Malware & Rootkit Analysis: Linux

> 💡 **Posisi Bab 8 di seri ini:** Bab 6 §6.1 sudah eksplisit menjanjikan ini — Bab 6 menjawab **"di mana attacker menanam titik eksekusi otomatis"**, Bab 8 menjawab **"apa isi payload-nya dan bagaimana dia menyembunyikan diri setelah berjalan"**. Kalau Bab 6 itu peta lokasi, Bab 8 adalah bedah isi kontennya — mulai dari cara triage sampel dengan aman, klasifikasi rootkit, teknik evasion modern (fileless, process injection), sampai analisis statis/dinamis binary itu sendiri.

> 📖 **Janji dari bab-bab sebelumnya yang dituntaskan di sini:** Bab 3 §3.4.5 menyinggung mismatch `_COMM` vs `_EXE` sebagai "relevan untuk Bab 8" — dituntaskan di §8.4.1. Bab 3 §3.5.4 menyinggung audit rule `init_module` "relevan deteksi rootkit LKM (Bab 8)" — dituntaskan di §8.8. Bab 4 §4.7.4 secara eksplisit men-defer detail teknis PAM backdoor ke sini — dituntaskan di §8.16. Bab 6 §6.7 sudah membahas forensik LD_PRELOAD sebagai *mekanisme persistence*; §8.7 di sini **tidak mengulang** workflow itu, hanya merujuk balik dan menambahkan sudut pandang *behavior* yang dihasilkan.

> ⚠️ **Prinsip "artifact ≠ event" (Bab 5) tetap berlaku di sini, dengan variasi:** Di Bab 8, prinsip yang setara adalah **"binary/proses terlihat normal ≠ benar-benar normal"**. Nama proses, path, bahkan hash yang familiar semuanya bisa dipalsukan oleh rootkit yang cukup canggih (§8.9). Investigator perlu selalu bertanya "apakah saya melihat data ini lewat jalur yang bisa di-hook attacker, atau lewat jalur yang independen?" — pertanyaan inilah yang mendasari seluruh metodologi Cross-View Detection di §8.9.

---

### 8.2 Malware Triage & Evidence Handling 🔴

> 🔧 **Kenapa bagian ini ditaruh di paling awal, bukan setelah klasifikasi:** Berbeda dari bab lain di seri ini yang bisa langsung masuk teknis, Bab 8 melibatkan objek yang **aktif berbahaya** (bisa dieksekusi ulang tanpa sengaja, bisa menyebar, bisa merusak bukti kalau ditangani sembarangan). Prinsip triage harus dikuasai **sebelum** menyentuh teknik apapun di §8.3 dan seterusnya — sama seperti alasan Lampiran akuisisi selalu ditaruh sebagai fondasi di bab-bab sebelumnya.

#### 8.2.1 Order of Volatility Terapan untuk Malware

**Pengertian & Fungsi:**
Order of volatility (evidence paling "mudah hilang" harus diambil paling dulu) yang sudah jadi prinsip umum forensik, punya penerapan spesifik untuk investigasi malware — karena banyak indikator (proses berjalan, koneksi jaringan aktif, malware fileless di §8.5) **hanya ada selama sistem masih hidup**.

```
Urutan akuisisi untuk kasus dugaan malware (paling volatile duluan):

1. Memory image (RAM)              — proses, koneksi, hidden module (Bab 7)
2. Proses & koneksi jaringan live   — ps, /proc, ss (sebelum reboot/kill)
3. Sampel binary (kalau exist di disk) — §8.2.3, sebelum kena rotasi/cleanup attacker
4. Log terkait (Bab 3)              — auth.log, journald, audit.log
5. Filesystem image penuh (Bab 2)   — paling terakhir, paling tidak volatile
```

> ⚠️ **Kesalahan paling umum:** Mematikan/reboot sistem duluan "supaya aman" sebelum akuisisi memory — ini justru menghancurkan evidence paling berharga untuk kasus malware fileless (§8.5) yang oleh definisi **tidak meninggalkan jejak di disk sama sekali**. Kalau sistem harus diisolasi cepat karena masih aktif menyerang (§8.2.2), isolasi jaringan dulu, **bukan** mematikan sistem.

#### 8.2.2 Isolasi & Containment Sebelum Analisis

**Pengertian & Fungsi:**
Sebelum analisis mendalam dimulai, sistem yang dicurigai terinfeksi perlu diisolasi dari jaringan produksi — tapi isolasi yang salah caranya bisa memicu "dead man's switch" pada malware yang dirancang mendeteksi hilangnya konektivitas.

```bash
# Isolasi jaringan TANPA mematikan interface sepenuhnya (hindari trigger dead man's switch
# pada malware yang memonitor status link) — arahkan traffic ke jaringan terisolasi/honeypot
# jika memungkinkan, atau gunakan firewall DROP semua traffic keluar KECUALI ke server forensik

# Cara paling aman: cabut secara fisik/VLAN isolation di level switch (di luar OS),
# supaya OS/malware tidak "sadar" ada perubahan konfigurasi jaringan

# Kalau harus lewat OS, catat dulu state jaringan SEBELUM isolasi (untuk §8.13.3)
ss -tulpn > /mnt/evidence/network_state_before_isolation.txt
```

> 📌 **Analisis idealnya dilakukan di lingkungan terisolasi (sandbox/VM analysis), bukan di sistem produksi asli** — §8.13 (behavioral analysis) secara eksplisit mengasumsikan ini. Bagian §8.2 ini murni tentang *penanganan sistem korban asli*, bukan tentang cara membangun sandbox.

#### 8.2.3 Safe Handling — Akuisisi Sampel Tanpa Eksekusi Tidak Sengaja

**Pengertian & Fungsi:**
Sampel binary yang dicurigai harus di-copy dan diamankan dengan cara yang **mencegah eksekusi tidak sengaja** — baik oleh investigator sendiri (klik tidak sengaja, tab-complete yang mengeksekusi) maupun oleh proses otomatis (antivirus scanner, indexing service).

```bash
# Hash SEBELUM disentuh lebih jauh — baseline integritas
sha256sum /path/ke/sampel_dicurigai > /tmp/sample_hash_before.txt

# Copy dengan permission executable DICABUT segera
sudo cp -a /path/ke/sampel_dicurigai /mnt/evidence/malware/sample_001
chmod 000 /mnt/evidence/malware/sample_001

# Konvensi umum: encode/archive dengan password supaya scanner otomatis tidak
# ikut memproses ulang (mencegah alert flood atau auto-quarantine yang menghapus evidence)
zip --password infected /mnt/evidence/malware/sample_001.zip /mnt/evidence/malware/sample_001

# Verifikasi hash tetap konsisten setelah proses copy/archive
sha256sum /mnt/evidence/malware/sample_001 >> /tmp/sample_hash_after.txt
diff /tmp/sample_hash_before.txt /tmp/sample_hash_after.txt
```

> ⚠️ **Jangan pernah `chmod +x` dan jalankan sampel di sistem yang sama dengan investigasi berlangsung** — bahkan untuk "sekadar lihat behavior", tanpa isolasi penuh (§8.2.2) risikonya reinfeksi atau kontaminasi evidence yang sedang dianalisis.

#### 8.2.4 Chain of Custody untuk Sampel Malware

**Pengertian & Fungsi:**
Sama seperti prinsip preservation di Bab 3 §3.11, tapi dengan konteks tambahan khusus malware — hash sampel jadi identitas unik yang akan dirujuk terus-menerus (matching ke threat intel, §8.11.5).

```bash
# Tiga hash sekaligus sebagai standar identifikasi malware (bukan cuma SHA-256)
md5sum /mnt/evidence/malware/sample_001
sha1sum /mnt/evidence/malware/sample_001
sha256sum /mnt/evidence/malware/sample_001

# Fuzzy hash (ssdeep) — berguna mendeteksi varian yang mirip tapi tidak identik byte-per-byte
ssdeep /mnt/evidence/malware/sample_001
```

> 💡 **Kenapa tiga jenis hash:** MD5/SHA-1 masih jadi standar lookup di banyak platform threat intel lama meski sudah tidak dianggap collision-resistant untuk keperluan lain, sementara SHA-256 jadi standar modern. Menyimpan ketiganya memaksimalkan kemungkinan match saat cross-check ke database eksternal (§8.11.5).

---

### 8.3 Klasifikasi Rootkit & Malware Linux 🔴

**Pengertian & Fungsi:**
Peta konsep sebelum masuk detail teknik — rootkit/malware Linux dikelompokkan berdasarkan **level operasi**, yang secara langsung menentukan kesulitan deteksi dan tools yang relevan.

```
Level Operasi Malware/Rootkit Linux (dari paling "dangkal" ke paling "dalam")
│
├── USERLAND — BINARY REPLACEMENT           §8.6
│    └── Trojanized ps/ls/netstat/sshd, gampang dideteksi via integrity check
│
├── USERLAND — LIBRARY HIJACKING             §8.7 (cross-ref Bab 6 §6.7)
│    └── LD_PRELOAD hook fungsi libc (readdir, stat) — lebih senyap dari replacement
│
├── USERLAND — PROCESS-LEVEL EVASION          §8.4, §8.5
│    ├── Process injection & masquerading (§8.4)
│    └── Fileless / memory-resident (§8.5)
│
├── KERNEL-LEVEL — LOADABLE KERNEL MODULE       §8.8
│    └── Syscall table hooking, hidden PID/port/file di level kernel — paling sulit
│         dideteksi dari userland, butuh cross-view (§8.9) atau memory forensics (§8.15)
│
└── KERNEL-LEVEL — eBPF-BASED (TREN MODERN) 🟡
     └── Memanfaatkan eBPF untuk hooking tanpa perlu load kernel module tradisional —
         makin sulit dideteksi tools rootkit-scanner klasik yang cuma cek lsmod/kallsyms;
         disebut sebagai tren yang perlu diwaspadai, detail teknik di luar cakupan cheat
         sheet ini karena masih berkembang cepat dan tooling forensiknya belum matang
```

| Level | Kesulitan Deteksi | Kesulitan Removal | Bagian Terkait |
|---|---|---|---|
| Binary replacement | Rendah (integrity check langsung ketahuan) | Rendah (restore dari package manager) | §8.6 |
| LD_PRELOAD hijack | Sedang | Sedang | §8.7 |
| Process injection/masquerading | Sedang-Tinggi | Sedang | §8.4 |
| Fileless | Tinggi (kalau sistem sudah reboot, evidence hilang) | Rendah setelah reboot (tidak persisten sendiri, tapi cek persistence lain di Bab 6) | §8.5 |
| Kernel-level (LKM) | Tinggi | Tinggi (butuh reboot/clean boot media) | §8.8 |
| eBPF-based | Sangat tinggi | Tinggi | — (sekilas) |

> 📌 **Prinsip umum lintas level:** Makin dalam level operasi, makin besar kemungkinan **tools deteksi standar ikut ter-hook** oleh malware itu sendiri — inilah kenapa §8.9 (Cross-View Detection) dan §8.15 (memory forensics offline) jadi krusial untuk level kernel ke atas, sementara level userland masih bisa cukup diandalkan dengan tools live biasa.

---

### 8.4 Process Injection & Masquerading 🔴

#### 8.4.1 Process Masquerading — `_COMM` vs `_EXE` vs Realita

**Pengertian & Fungsi:**
Bentuk evasion paling sederhana: proses malware dinamai menyerupai proses sistem legitimate (`sshd`, `kworker`, `systemd`) supaya luput dari pemeriksaan visual `ps`/`top`. Ini menuntaskan yang sudah disinggung Bab 3 §3.4.5.

```bash
# _COMM (nama proses, bisa dipalsukan lewat argv[0] atau prctl(PR_SET_NAME))
# vs _EXE (path binary SEBENARNYA yang dieksekusi, jauh lebih sulit dipalsukan)
# — field trusted journald ini sudah dibahas Bab 3 §3.4.6, sekarang diterapkan ke live process:

ps -eo pid,comm,cmd | grep -i "kworker\|sshd\|systemd"
for pid in $(pgrep -f .); do
    echo "PID $pid: comm=$(cat /proc/$pid/comm 2>/dev/null) exe=$(readlink /proc/$pid/exe 2>/dev/null)"
done | awk -F'exe=' '{if ($2 !~ /^\/usr\/|^\/bin\/|^\/sbin\//) print}'

# Kernel thread ASLI (kworker, ksoftirqd, dst) TIDAK PUNYA /proc/PID/exe sama sekali
# (karena bukan proses userland) — kalau ada "kworker" palsu dengan /proc/PID/exe yang
# valid menunjuk ke path userland, itu red flag KUAT proses menyamar sebagai kernel thread
ls -la /proc/<pid>/exe   # kernel thread asli: "No such file or directory" atau tidak ada link
```

> ⚠️ **Kernel thread palsu adalah pola sangat umum di malware Linux:** Nama seperti `[kworker/0:1]`, `[kthreadd]` dengan bracket adalah konvensi penamaan kernel thread asli — kalau ditemukan proses dengan nama serupa TAPI muncul di `ps aux` dengan CPU/memory usage userland yang tidak wajar untuk kernel thread, atau punya `/proc/PID/exe` yang valid, itu kemungkinan besar malware yang sengaja meniru pola penamaan ini.

#### 8.4.2 `ptrace`-Based Code Injection

**Pengertian & Fungsi:**
Teknik menyuntikkan kode ke proses lain yang sudah berjalan memakai syscall `ptrace()` — attacker/malware attach ke proses korban, menulis shellcode ke memory space-nya, lalu mengarahkan eksekusi ke situ. Proses "terlihat normal" dari luar (nama, PID, path exe tidak berubah) karena kode berjalan **di dalam** proses legitimate yang sudah ada.

```bash
# Indikator tidak langsung — proses yang di-ptrace biasanya punya TracerPid non-nol
# sesaat setelah proses attach (meski banyak tool langsung detach setelah injeksi selesai)
cat /proc/<pid>/status | grep TracerPid

# Cek maps memory proses untuk region yang janggal (RWX, anonymous, tidak terhubung ke file)
cat /proc/<pid>/maps | grep "rwxp"
# Region rwxp (read-write-execute) anonymous adalah pola SANGAT mencurigakan —
# memory legitimate normalnya tidak butuh writable+executable sekaligus

# Bandingkan maps dengan binary asli di disk (kalau exe masih ada)
readelf -l $(readlink /proc/<pid>/exe) | grep LOAD
```

> 📌 **Kenapa ini sulit dideteksi retroaktif:** Kalau proses yang di-inject sudah lama berjalan sebelum diperiksa, region memory injeksi bisa saja sudah dibersihkan/di-unmap oleh malware setelah payload selesai dieksekusi — hanya terlihat jelas kalau diperiksa **saat masih aktif**, atau lewat memory image (Bab 7) yang menangkap state persis di momen akuisisi.

#### 8.4.3 Runtime LD_PRELOAD Injection ke Proses Berjalan

**Pengertian & Fungsi:**
Beda dari LD_PRELOAD persistence (Bab 6 §6.7, yang bekerja saat proses BARU dieksekusi), teknik ini menyuntikkan shared library ke proses yang **sudah berjalan**, biasanya dikombinasikan dengan `ptrace()` (§8.4.2) untuk memanggil `dlopen()` dari dalam proses korban.

```bash
# Cek shared library yang di-load proses live, bandingkan dengan yang seharusnya
cat /proc/<pid>/maps | grep "\.so"
# Cari library dengan path tidak wajar (/tmp, /dev/shm, /var/tmp) dimuat oleh proses
# yang sedianya tidak butuh library dari lokasi tersebut
cat /proc/<pid>/maps | grep -E "\.so" | grep -E "/tmp/|/dev/shm/|/var/tmp/"
```

> 🔗 **Cross-ref:** Ini adalah varian *live/runtime* dari mekanisme yang sudah dibahas penuh dari sisi persistence di **Bab 6 §6.7.1-§6.7.2** — bagian itu fokus ke "bagaimana LD_PRELOAD dipasang supaya bertahan", bagian ini fokus ke "bagaimana mendeteksi injeksi yang terjadi di proses yang sudah berjalan, tanpa menyentuh `/etc/ld.so.preload` sama sekali".

#### 8.4.4 Process Hollowing Gaya Linux

**Pengertian & Fungsi:**
Analog konsep process hollowing Windows (spawn proses legitimate dalam suspended state, ganti isi memory-nya) — di Linux realisasinya berbeda karena tidak ada API setara `CreateProcess` suspended, tapi efek serupa bisa dicapai lewat kombinasi `ptrace()` + manipulasi `execve()` atau replace isi segment `.text` proses yang sudah berjalan.

```bash
# Indikator: entry point proses di memory tidak cocok dengan entry point di binary disk
readelf -h $(readlink /proc/<pid>/exe) | grep "Entry point"
# vs isi memory di alamat tersebut (butuh /proc/<pid>/mem, akses root)
sudo dd if=/proc/<pid>/mem bs=1 skip=$((0x<entry_point_addr>)) count=16 2>/dev/null | xxd
```

> ⚠️ Teknik ini paling reliable dideteksi lewat **memory forensics offline** (Bab 7) dibanding pemeriksaan live — proses live yang sudah di-hollow biasanya sengaja dirancang supaya pemeriksaan dasar (`ps`, `readlink /proc/PID/exe`) tetap menunjukkan hasil "normal".

---

### 8.5 Fileless / Memory-Resident Malware 🔴

#### 8.5.1 Deleted-but-Running Binary

**Pengertian & Fungsi:**
Teknik klasik: attacker menjalankan binary, lalu menghapus file-nya dari disk **selagi proses masih berjalan**. Karena Linux tidak menghapus inode selama masih ada file descriptor terbuka ke situ (konsep unlink vs delete, Bab 2), proses tetap bisa jalan normal walau entry file-nya sudah tidak ada di direktori manapun.

```bash
# Deteksi proses yang exe-nya sudah dihapus — pola paling klasik & paling mudah dicek
ls -alR /proc/*/exe 2>/dev/null | grep deleted

# Recovery isi binary yang sudah dihapus SELAMA proses masih berjalan —
# baca langsung dari /proc/PID/exe (masih valid selama proses hidup)
cp /proc/<pid>/exe /mnt/evidence/malware/recovered_deleted_binary
sha256sum /mnt/evidence/malware/recovered_deleted_binary
```

> 💡 **Ini salah satu win forensik termudah di seluruh Bab 8:** Selama proses masih berjalan, `cp /proc/<pid>/exe <tujuan>` akan berhasil merecover binary lengkap meski file aslinya sudah tidak ada entry-nya di filesystem manapun — jangan pernah kill proses mencurigakan sebelum langkah ini dilakukan (konsisten dengan order of volatility §8.2.1).

#### 8.5.2 `memfd_create()` — Eksekusi Tanpa Pernah Menyentuh Disk

**Pengertian & Fungsi:**
Syscall `memfd_create()` membuat file descriptor anonim yang hidup di memory (bukan di filesystem manapun), lalu bisa di-`execve()` langsung dari situ — binary **tidak pernah** tertulis ke disk sama sekali, dari awal sampai akhir. Ini level fileless yang lebih ekstrem dari §8.5.1 (yang setidaknya sempat ada file di disk sebelum dihapus).

```bash
# /proc/PID/exe untuk proses hasil memfd_create menunjuk ke path unik "memfd:<name>"
# alih-alih path filesystem normal — ini SANGAT mencolok begitu ditemukan
ls -la /proc/*/exe 2>/dev/null | grep "memfd:"

# Recovery isinya sama seperti §8.5.1 — masih bisa di-copy selama proses hidup
cp /proc/<pid>/exe /mnt/evidence/malware/recovered_memfd_binary
```

> 📌 **Teknik ini populer di malware/dropper modern** (termasuk beberapa worm cryptomining Linux yang beredar luas) justru karena kesederhanaannya — tidak butuh exploit kernel apapun, cukup syscall standar yang tersedia di semua kernel modern, tapi efeknya setara "fileless execution" yang di Windows biasanya butuh teknik jauh lebih kompleks (reflective DLL injection, dst).

#### 8.5.3 tmpfs-Only Payload

**Pengertian & Fungsi:**
Payload yang sengaja hanya diletakkan di filesystem berbasis memory (`/tmp` kalau di-mount sebagai tmpfs, `/dev/shm`) — secara teknis "ada" di filesystem (beda dari §8.5.2), tapi tetap tidak meninggalkan jejak di disk fisik karena tmpfs sepenuhnya di RAM (cross-ref Bab 1 §1.2.6 soal `/tmp` sebagai direktori staging umum).

```bash
# Cek apakah /tmp memang di-mount sebagai tmpfs (banyak distro default begini)
mount | grep -E "on /tmp |on /dev/shm "

# Payload di /dev/shm sangat umum karena lokasi ini SELALU tmpfs, dan sering tidak
# termonitor seketat /tmp oleh tools EDR/security
find /dev/shm -type f -exec file {} \; 2>/dev/null
```

> ⚠️ **Implikasi kritis:** Kalau sistem shutdown/reboot normal (bukan crash), **seluruh isi tmpfs hilang otomatis** — payload jenis ini efektif "menghapus diri sendiri" tanpa perlu perintah eksplisit dari attacker begitu sistem restart. Ini alasan kuat lain kenapa order of volatility §8.2.1 menempatkan akuisisi live di atas segalanya untuk kasus dugaan fileless malware.

#### 8.5.4 Implikasi Forensik Fileless Malware

**Pengertian & Fungsi:**
Rangkuman kenapa §8.5.1-§8.5.3 secara kolektif mengubah prioritas investigasi dibanding malware berbasis file biasa.

| Teknik | Bertahan Reboot? | Recovery Kalau Sistem Sudah Reboot |
|---|---|---|
| Deleted-but-running (§8.5.1) | Tidak | Mustahil dari disk; hanya dari memory image yang diambil SEBELUM reboot (Bab 7) |
| `memfd_create` (§8.5.2) | Tidak | Sama — hanya dari memory image sebelum reboot |
| tmpfs-only (§8.5.3) | Tidak | Sama — tmpfs kosong total setelah reboot normal |

> 🔗 **Cross-ref krusial:** Ketiga teknik ini adalah alasan utama kenapa Bab 7 (Memory Forensics) **bukan pelengkap opsional** untuk kasus dugaan malware canggih — untuk fileless malware, memory image yang diambil selagi sistem masih hidup **adalah satu-satunya** sumber evidence yang mungkin ada sama sekali.

---

### 8.6 Deteksi Userland Rootkit 🔴

**Pengertian & Fungsi:**
Level paling dasar — rootkit yang bekerja dengan mengganti binary sistem (`ps`, `ls`, `netstat`, `sshd`) dengan versi trojan yang menyembunyikan aktivitas attacker dari output normalnya.

```bash
# Verifikasi integritas binary via package manager — cross-ref Bab 3 §3.6.3 (package log)
# Debian/Ubuntu
dpkg --verify
dpkg -V coreutils net-tools openssh-server

# RHEL/CentOS
rpm -Va
rpm -V $(rpm -qf /usr/sbin/sshd)

# Static analysis awal binary yang dicurigai
file /bin/ps
strings /bin/ps | grep -iE "hidden|backdoor" 2>/dev/null   # heuristik kasar, jarang berhasil
md5sum /bin/ps    # bandingkan dengan hash resmi dari repositori distro/checksums.txt
```

> 📌 **Verifikasi package manager punya batasan:** Kalau attacker cukup canggih untuk mengganti binary DAN memanipulasi database package manager (metadata hash yang disimpan `dpkg`/`rpm`), verifikasi ini bisa dilewati. Untuk kasus itu, `md5sum`/`sha256sum` harus dibandingkan terhadap sumber **eksternal** (checksum resmi dari mirror distro, bukan database lokal sistem yang mungkin sudah dikompromikan) — prinsip yang sama dengan pentingnya sumber log terpusat di Bab 3 §3.2.6.

---

### 8.7 Deteksi LD_PRELOAD & Library Hijacking dari Sudut Malware 🔴

> 🔗 **Workflow forensik lengkap sudah dibahas Bab 6 §6.7.2 dan §6.7.5** — bagian ini **tidak mengulang** cara cek `/etc/ld.so.preload` atau env var, cukup merujuk balik. Fokus di sini murni pada *behavior yang dihasilkan* dan cara mengenalinya dari sisi output tool yang ter-hook.

**Pengertian & Fungsi:**
LD_PRELOAD rootkit bekerja dengan meng-hook fungsi libc level rendah (`readdir()`, `stat()`, `open()`) sehingga tool standar seperti `ps`/`ls`/`netstat` "berbohong" tanpa binary-nya sendiri diubah sama sekali — beda dari §8.6 yang mengganti binary, ini mengubah *apa yang binary asli lihat*.

```bash
# Bandingkan output tool yang RENTAN di-hook (lewat readdir()/libc) vs cara akses langsung
# yang lebih sulit di-intercept — prinsip dasar untuk §8.9 diterapkan spesifik ke LD_PRELOAD

# ps (rentan hook) vs baca /proc langsung dengan tool minimal dependency
ps aux | wc -l
ls -d /proc/[0-9]* | wc -l
# Selisih jumlah antara keduanya adalah indikator KUAT ada proses yang disembunyikan

# netstat/ss (rentan hook) vs baca /proc/net langsung
ss -tulpn | wc -l
cat /proc/net/tcp /proc/net/tcp6 | tail -n +2 | wc -l
```

> 💡 **Tool statis (busybox) sebagai "second opinion":** Karena LD_PRELOAD hanya bekerja pada binary yang **dynamically linked**, binary static (seperti build statis `busybox` atau `ps` versi static) tidak terpengaruh hook LD_PRELOAD sama sekali — bawa binary trusted static dari luar sistem (di flashdisk/read-only media) sebagai pembanding independen, ini praktik standar incident response Linux.

---

### 8.8 Deteksi Kernel-Level Rootkit (LKM) 🔴

**Pengertian & Fungsi:**
Level paling dalam yang masih realistis ditemukan di lapangan — Loadable Kernel Module yang meng-hook syscall table langsung di kernel space, sehingga **bahkan static binary pun bisa "dibohongi"** karena hook terjadi di bawah level libc.

```bash
# Enumerasi modul yang ter-load — TAPI rootkit LKM bisa unlink diri dari linked list
# modul kernel (teknik DKOM-style), sehingga TIDAK MUNCUL di sini sama sekali
lsmod
cat /proc/modules

# Cross-check dengan /sys/module/ — kadang beda hasil dengan /proc/modules
# tergantung teknik hiding yang dipakai rootkit
ls /sys/module/

# Cek symbol table kernel untuk syscall yang address-nya tidak wajar
# (dibandingkan baseline kernel bersih — butuh referensi eksternal)
cat /proc/kallsyms | grep -E "sys_call_table|sys_read|sys_write|sys_getdents"

# Jejak insmod/modprobe di log — cross-ref Bab 3 §3.5.4 (audit rule init_module/finit_module)
sudo ausearch -m SYSCALL -sc init_module,finit_module 2>/dev/null
dmesg | grep -iE "module.*loaded|taint"
```

> ⚠️ **Kenapa deteksi live LKM rootkit dari dalam sistem yang sama SANGAT tidak reliable:** Kalau rootkit sudah berhasil hook syscall table, dia bisa mengontrol **apa yang dilihat semua tool di atas** — termasuk `lsmod`, `cat /proc/kallsyms`, bahkan `dmesg`. Ini bukan skenario hipotetis, ini kategori rootkit paling umum ditemukan justru punya kapabilitas ini. §8.9 dan §8.15 adalah jawaban terhadap keterbatasan ini.

---

### 8.9 Cross-View Rootkit Detection 🔴

**Pengertian & Fungsi:**
Metodologi yang menyatukan §8.6-§8.8 menjadi satu prinsip: **bandingkan beberapa "cara pandang" berbeda terhadap data yang sama** — kalau rootkit hanya meng-hook satu jalur (misal `readdir()` via libc) tapi tidak (atau tidak bisa) meng-hook jalur lain (misal syscall langsung, atau data di level berbeda), maka selisih antara kedua cara pandang itu **mengungkap keberadaan rootkit** meski rootkit-nya sendiri tidak pernah "terlihat" langsung.

```
Prinsip Cross-View:  View A  ≠  View B   →  SELISIH = indikasi hiding

┌─────────────────────────┬──────────────────────────┬─────────────────────────────┐
│ Objek yang Dicek         │ View "Rentan Hook"        │ View "Independen/Low-Level"  │
├─────────────────────────┼──────────────────────────┼─────────────────────────────┤
│ Proses berjalan          │ ps aux                    │ ls -d /proc/[0-9]*           │
│ Modul kernel             │ lsmod                     │ /sys/module/ (§8.8) ATAU     │
│                           │                            │ diff terhadap memory image   │
│                           │                            │ offline (Bab 7, §8.15)       │
│ Koneksi jaringan          │ netstat / ss              │ cat /proc/net/tcp[6]          │
│ File di direktori         │ ls -la                    │ find (kadang sama-sama rentan │
│                           │                            │ hook readdir — pakai debugfs/ │
│                           │                            │ akses inode langsung, Bab 2)  │
│ Port yang di-listen       │ ss -tulpn                  │ Baca socket inode langsung dari│
│                           │                            │ /proc/net/tcp + /proc/PID/fd  │
└─────────────────────────┴──────────────────────────┴─────────────────────────────┘
```

```bash
# Contoh konkret cross-view proses — sudah disinggung §8.7, dirangkum di sini sebagai
# metodologi umum yang berlaku untuk SEMUA level rootkit (§8.6-§8.8), bukan cuma LD_PRELOAD

diff <(ps aux --no-headers | awk '{print $2}' | sort -n) \
     <(ls -d /proc/[0-9]* 2>/dev/null | grep -oE '[0-9]+' | sort -n)
# PID yang muncul HANYA di kolom kedua (langsung dari /proc) tapi TIDAK di ps aux
# adalah proses yang berhasil disembunyikan dari ps
```

> 📌 **Batas metodologi ini:** Cross-view efektif melawan hook yang **tidak lengkap/tidak konsisten** (hook satu jalur tapi lupa jalur lain) — rootkit yang sangat canggih dan konsisten bisa saja meng-hook **semua** jalur yang dicek dari dalam sistem yang sama. Untuk skenario itu, satu-satunya "view" yang benar-benar independen adalah yang diambil **dari luar sistem sama sekali** — memory image dianalisis di mesin analis terpisah (Bab 7, §8.15), bukan tool apapun yang dijalankan di sistem yang dicurigai.

---

### 8.10 Automated Rootkit Scanner Tools 🟡

**Pengertian & Fungsi:**
Tools siap pakai yang mengotomasi sebagian pengecekan §8.6-§8.9 — berguna sebagai langkah cepat awal, tapi punya keterbatasan signature-based yang harus dipahami sebelum terlalu mengandalkannya.

| Tool | Fokus | Keterbatasan |
|---|---|---|
| `rkhunter` | Signature database rootkit dikenal + beberapa heuristik | Tidak efektif untuk rootkit baru/custom di luar database |
| `chkrootkit` | Mirip rkhunter, cek string signature & beberapa cross-view dasar | Sama — signature-based, bisa false negative untuk varian baru |
| `Unhide` | Fokus cross-view detection proses tersembunyi (mirip §8.9 tapi otomatis) | Lebih general-purpose, kadang false positive di sistem dengan banyak container/namespace |

```bash
sudo rkhunter --check --sk
sudo chkrootkit
sudo unhide proc
sudo unhide sys
```

> ⚠️ **Jangan jadikan hasil "clean" dari tools ini sebagai kesimpulan akhir** — terutama untuk kasus yang sudah menunjukkan indikator kuat di §8.4-§8.9. Tools signature-based ini paling berguna untuk triage cepat/eliminasi kasus umum, bukan pengganti analisis manual untuk kasus yang sudah dicurigai serius.

---

### 8.11 Static Malware Analysis (ELF Binary) 🔴

#### 8.11.1 Anatomi ELF Ringkas

**Pengertian & Fungsi:**
Pemahaman dasar struktur ELF (Executable and Linkable Format) yang cukup untuk keperluan investigasi — bukan kursus reverse engineering penuh.

```
Struktur ELF (disederhanakan):
├── ELF Header       — magic number, arsitektur, entry point, tipe (EXEC/DYN/CORE)
├── Program Headers   — segment untuk loader (LOAD, DYNAMIC, INTERP)
└── Section Headers    — .text (kode), .data (data terinisialisasi), .bss (uninitialized),
                          .rodata (read-only), .symtab/.dynsym (symbol table)
```

#### 8.11.2 `readelf`/`objdump` — Header, Symbol, Disassembly Dasar

```bash
readelf -h sample_001          # ELF header — arsitektur, entry point, tipe
readelf -l sample_001          # program headers/segments
readelf -S sample_001          # section headers
readelf -d sample_001          # dynamic section — lihat §8.12 untuk detail DT_NEEDED/RPATH
readelf -s sample_001 | head -50   # symbol table

objdump -d sample_001 | less    # disassembly dasar
objdump -T sample_001            # dynamic symbol table (fungsi yang di-import/export)
```

#### 8.11.3 String & IOC Extraction Awal

```bash
strings -a sample_001 | grep -E "^https?://|^[0-9]{1,3}(\.[0-9]{1,3}){3}$"
strings -a sample_001 | grep -iE "\.onion|cmd\.exe|/bin/sh|wget|curl"
```

> 🔗 Ekstraksi IOC yang lebih sistematis (bukan sekadar `grep` sekali jalan) dibahas penuh di **§8.14**.

#### 8.11.4 Deteksi Packer/Obfuscation

**Pengertian & Fungsi:**
Malware sering dibungkus packer (UPX dan variannya, atau custom packer) untuk menyulitkan analisis statis — section count sangat sedikit, entropy tinggi, dan entry point mengarah ke kode unpacking stub adalah indikator umum.

```bash
# UPX punya signature yang mudah dikenali kalau tidak di-strip
strings sample_001 | grep -i "UPX"
upx -t sample_001    # test apakah bisa di-unpack UPX standar

# Entropy check kasar — packer/encryption biasanya menghasilkan section dengan
# entropy mendekati maksimum (~8.0), section kode normal biasanya lebih rendah
readelf -S sample_001    # bandingkan ukuran section .text vs total file size —
                          # section yang jauh lebih kecil dari total file dengan
                          # sisa "data" besar adalah indikator packed payload
```

#### 8.11.5 Hash-Based Identification & Threat Intel Lookup

```bash
sha256sum sample_001
# Cross-check manual ke platform reputasi (VirusTotal, dst) — TIDAK upload sampel
# ke platform publik kalau kasus melibatkan kerahasiaan/APT yang sensitif, cukup
# query berdasarkan HASH saja (banyak platform mendukung hash-only lookup tanpa upload)
```

> ⚠️ **Pertimbangan kerahasiaan:** Untuk investigasi yang melibatkan potensi actor bertarget (bukan malware umum/komoditas), meng-upload sampel ke platform publik bisa **membocorkan** ke attacker bahwa sampelnya sudah ditemukan (banyak platform threat intel yang notifikasi submitter atau bisa diakses attacker juga). Selalu cek kebijakan organisasi/kasus sebelum submit sampel secara penuh.

---

### 8.12 ELF Dynamic Linking — DT_NEEDED/RPATH/RUNPATH 🟡

#### 8.12.1 Cara Kerja Dynamic Linker Mencari Shared Library

**Pengertian & Fungsi:**
Saat binary dynamically-linked dijalankan, dynamic linker (`ld.so`) mencari shared library yang dibutuhkan lewat urutan pencarian tertentu — memahami urutan ini penting karena attacker bisa "menyelipkan" library jahat di salah satu titik pencarian sebelum linker menemukan library asli.

```
Urutan pencarian library oleh ld.so (disederhanakan, dari prioritas tertinggi):
1. RPATH binary (kalau ada, DAN RUNPATH tidak ada — lihat §8.12.3)
2. LD_LIBRARY_PATH (environment variable)
3. RUNPATH binary (kalau ada)
4. Cache dari ldconfig (/etc/ld.so.cache) — dibangun dari /etc/ld.so.conf.d/*
   (cross-ref Bab 6 §6.7.3 — jalur ini yang dibahas dari sudut PERSISTENCE di sana)
5. Path default (/lib, /usr/lib, dst)
```

#### 8.12.2 `DT_NEEDED` — Daftar Dependency & Manipulasinya

**Pengertian & Fungsi:**
`DT_NEEDED` adalah entry di dynamic section ELF yang mendaftar nama-nama shared library yang dibutuhkan binary saat load time — analisis daftar ini penting untuk (1) memahami dependency asli binary, dan (2) mendeteksi kalau binary sudah dimodifikasi untuk menambah dependency jahat.

```bash
readelf -d sample_001 | grep NEEDED
# Contoh output:
#  0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]
#  0x0000000000000001 (NEEDED)  Shared library: [libevil.so.1]   <- MENCURIGAKAN

# Bandingkan dengan output ldd (hati-hati — ldd sendiri MENGEKSEKUSI binary secara
# terbatas untuk resolve dependency, JANGAN dipakai untuk sampel tidak trusted;
# untuk sampel malware gunakan readelf/objdump yang murni statis, BUKAN ldd)
```

> ⚠️ **`ldd` tidak aman untuk sampel malware:** Berbeda dari `readelf -d` yang murni membaca metadata statis, `ldd` di beberapa implementasi bisa memicu eksekusi terbatas binary target untuk resolve dependency — untuk sampel yang statusnya belum dikonfirmasi aman, **selalu gunakan `readelf -d` atau `objdump -p`**, jangan `ldd`.

#### 8.12.3 `RPATH` vs `RUNPATH` — Beda Krusial untuk Hijacking

**Pengertian & Fungsi:**
Dua atribut yang terlihat mirip tapi punya perbedaan prioritas pencarian yang signifikan untuk analisis hijacking — kesalahan umum investigator adalah menganggap keduanya setara.

| Atribut | Prioritas vs `LD_LIBRARY_PATH` | Diwariskan ke Dependency Transitif? |
|---|---|---|
| `RPATH` (legacy) | **Lebih tinggi** — dicari SEBELUM `LD_LIBRARY_PATH` | Ya — berlaku juga untuk library yang di-load oleh binary ini |
| `RUNPATH` (modern, menggantikan RPATH) | **Lebih rendah** — `LD_LIBRARY_PATH` dicek duluan | Tidak — hanya berlaku untuk binary itu sendiri, bukan dependency transitifnya |

```bash
readelf -d sample_001 | grep -E "RPATH|RUNPATH"

# Kalau RPATH mengarah ke direktori yang writable oleh user biasa (/tmp, home dir,
# direktori aplikasi dengan permission longgar) — itu potensi library hijacking:
# attacker taruh .so jahat dengan nama sama persis di direktori tersebut, linker
# akan memuat versi jahat itu DULUAN sebelum sempat mencari ke lokasi sistem asli
readelf -d sample_001 | grep RPATH | grep -E "/tmp|/home|/var/tmp"
```

> 💡 **Kenapa distinction ini penting untuk investigasi:** Binary dengan `RPATH` yang menunjuk direktori writable adalah kandidat privilege escalation/persistence yang jauh lebih senyap dibanding LD_PRELOAD (Bab 6 §6.7) — tidak perlu modifikasi `/etc/ld.so.preload` sama sekali, cukup taruh file `.so` dengan nama yang tepat di direktori yang di-referensikan RPATH binary target (terutama kalau binary itu setuid/setgid, cross-ref Bab 6 §6.7.4).

#### 8.12.4 Forensik Dynamic Linking Hijack

```bash
# Cari binary setuid/setgid dengan RPATH/RUNPATH mencurigakan sekaligus —
# kombinasi ini adalah target privilege escalation klasik
for f in $(find / -perm -4000 -o -perm -2000 2>/dev/null); do
    rp=$(readelf -d "$f" 2>/dev/null | grep -E "RPATH|RUNPATH")
    [ -n "$rp" ] && echo "$f -> $rp"
done

# Cek juga direktori yang dirujuk RPATH/RUNPATH — apakah ada file .so BARU
# di sana dengan mtime mencurigakan (Bab 2 §2.1.2)
stat /path/dari/rpath/libtarget.so.1
```

---

### 8.13 Dynamic/Behavioral Analysis 🔴

**Pengertian & Fungsi:**
Analisis dengan cara **menjalankan** sampel di lingkungan terisolasi (§8.2.2) untuk mengamati perilaku aktualnya — melengkapi keterbatasan analisis statis (§8.11-§8.12) terutama untuk sampel yang di-obfuscate/packed.

```bash
# Syscall & library call tracing
strace -f -o /tmp/strace_output.txt ./sample_001
ltrace -f -o /tmp/ltrace_output.txt ./sample_001

# Network behavior — jalankan capture SEBELUM eksekusi sampel
sudo tcpdump -i any -w /mnt/evidence/network_capture.pcap &
./sample_001
# hentikan capture setelah observasi selesai, analisis pcap terpisah

# Pola child-process spawning — indikasi dropper/downloader
strace -f -e trace=execve,fork,clone -o /tmp/spawn_trace.txt ./sample_001
```

> ⚠️ **Wajib dilakukan hanya di lingkungan terisolasi penuh (§8.2.2)** — VM terpisah tanpa akses ke jaringan produksi, idealnya dengan snapshot yang bisa di-rollback. Jangan pernah menjalankan sampel di sistem investigasi utama.

---

### 8.14 IOC Extraction & Correlation 🟡

**Pengertian & Fungsi:**
Mengumpulkan Indicator of Compromise (IP, domain, hash, path file, mutex/lock file khas, User-Agent string) dari hasil §8.11-§8.13 secara terstruktur, lalu mengorelasikannya balik ke sumber lain di seri ini — mengubah temuan analisis malware jadi bagian dari timeline investigasi yang lebih besar, bukan laporan terisolasi.

```
Kategori IOC yang Dikumpulkan:
├── Network IOC     — IP/domain C2 (dari §8.11.3 strings, §8.13 tcpdump)
├── File IOC        — hash sampel (§8.2.4), path staging (Bab 1 §1.2.6)
├── Host IOC        — mutex/lock file khas, nama proses masquerading (§8.4.1)
└── Persistence IOC  — cross-ref langsung ke Bab 6 (unit file, cron entry, dst)
```

```bash
# Setelah IOC network terkumpul, korelasikan balik ke log koneksi (Bab 3)
grep -E "203\.0\.113\.5|evil-c2\.example" /var/log/auth.log /var/log/syslog 2>/dev/null
journalctl -o json | jq -r 'select(.MESSAGE | test("203\\.0\\.113\\.5"))'

# Korelasikan hash sampel dengan artefak filesystem lain yang mungkin punya hash sama
# (varian sampel yang sudah menyebar ke lokasi lain di sistem yang sama)
find / -type f -exec sha256sum {} \; 2>/dev/null | grep "<hash_sampel>"

# Korelasikan path staging IOC dengan crtime inode (Bab 2 §2.1.2) untuk timeline
sudo debugfs -R "stat <inode>" /dev/sda1
```

> 📌 **IOC extraction bukan tujuan akhir, tapi jembatan.** Nilai sebenarnya IOC muncul saat dikorelasikan ke sumber lain: `auth.log`/journald (Bab 3) untuk konfirmasi kapan koneksi C2 aktif, artefak persistence (Bab 6) untuk konfirmasi bagaimana malware bertahan, dan timeline filesystem (Bab 2) untuk kapan setiap komponen muncul di disk. Tabel korelasi §8.20 merangkum pemetaan ini.

---

### 8.15 Memory-Based Detection — Pointer ke Bab 7 🔧

**Pengertian & Fungsi:**
Bagian ini sengaja singkat — bukan karena tidak penting (justru sebaliknya, untuk kasus §8.5 fileless dan §8.8 kernel-level rootkit canggih, ini **satu-satunya** sumber evidence yang benar-benar independen dari sistem yang mungkin sudah dikompromikan penuh), tapi karena detail teknik akuisisi dan analisis memory image sudah/akan dibahas mendalam di **Bab 7 — Memory Forensics Linux**, dan Bab 8 tidak menduplikasinya.

> 🔧 **Kenapa jadi satu-satunya bagian "placeholder" di Bab 8:** Beda dari cross-reference lain di bab ini (Bab 3, Bab 6) yang sudah bisa dirujuk presisi ke nomor bagian spesifik, referensi ke Bab 7 di sini masih bersifat umum — begitu isi Bab 7 final, bagian ini perlu diperbarui dengan pointer presisi ke sub-bagian yang relevan (analisis `linux_pslist` vs `linux_psscan` untuk hidden process, enumerasi kernel module dari memory image, ekstraksi binary dari memory region untuk kasus fileless §8.5).

**Highlight kenapa memory image lebih reliable dibanding command live untuk kasus di Bab 8:**

| Temuan di Bab 8 | Kenapa Live Detection Bisa Gagal | Kenapa Memory Image Lebih Kuat |
|---|---|---|
| Hidden process (§8.9) | Kalau semua "view" live sudah di-hook rootkit | Volatility membaca struktur kernel `task_struct` langsung dari image, tidak lewat syscall yang bisa di-hook |
| Hidden kernel module (§8.8) | `lsmod` bisa dimanipulasi rootkit (unlink dari linked list) | Memory image bisa di-scan cari signature module yang tidak terhubung ke linked list resmi (`psscan`-equivalent untuk module) |
| Fileless payload (§8.5) | Tidak ada file untuk di-`cp` setelah proses mati/sistem reboot | Payload di memory bisa diekstrak langsung dari region proses yang tertangkap image, selama akuisisi dilakukan SEBELUM proses berakhir |

---

### 8.16 PAM Backdoor

> 📖 **Menuntaskan janji Bab 4 §4.7.4:** Bab 4 membahas struktur `/etc/pam.d/` dan stack auth sebatas overview, secara eksplisit men-defer detail teknis modul PAM jahat ke sini. Bab 6 §6.6.3 membahas **di mana** PAM-based persistence dipasang (titik lokasi). Bagian ini menjawab **bagaimana modul jahatnya bekerja secara teknis**.

**Pengertian & Fungsi:**
PAM backdoor bekerja dengan menyisipkan modul jahat ke salah satu stack (`auth`, `account`, `password`, `session`) di `/etc/pam.d/`, biasanya di modul yang menangani autentikasi (`pam_unix.so` atau custom module) — modul jahat ini bisa dirancang untuk (1) menerima **password master** rahasia yang selalu berhasil login terlepas dari password asli user, atau (2) mencatat/exfiltrate setiap password yang diketik user secara plaintext sebelum diteruskan ke verifikasi normal.

```bash
# Cek modul non-standar di stack PAM — bandingkan dengan daftar modul resmi distro
ls -la /lib/x86_64-linux-gnu/security/*.so 2>/dev/null    # Debian/Ubuntu
ls -la /lib64/security/*.so 2>/dev/null                    # RHEL/CentOS

# Modul dengan mtime jauh lebih baru dari modul sistem sekitarnya — indikator kuat
find /lib*/security/ /usr/lib*/security/ -name "*.so" -newer /etc/hostname 2>/dev/null

# Cek isi /etc/pam.d/common-auth (Debian) atau /etc/pam.d/system-auth (RHEL) —
# baris tambahan yang merujuk modul di luar path standar sangat mencurigakan
cat /etc/pam.d/common-auth
grep -r "pam_exec\|pam_unix" /etc/pam.d/ | grep -v "^#"
```

> ⚠️ **Pola paling umum ditemukan di CTF/insiden nyata — modifikasi source `pam_unix.so` itu sendiri (recompiled dengan backdoor tertanam), bukan menambah modul baru.** Ini jauh lebih sulit dideteksi karena nama file dan path-nya **identik** dengan modul resmi — satu-satunya cara deteksi reliable adalah membandingkan **hash** modul dengan checksum resmi distro (sama prinsipnya dengan verifikasi binary §8.6), karena pemeriksaan visual nama file tidak akan menunjukkan apapun yang janggal.

```bash
# Verifikasi hash modul PAM terhadap package manager — deteksi modifikasi tersembunyi
dpkg -V libpam-modules 2>/dev/null
rpm -V pam 2>/dev/null
```

> 🔗 **Cross-ref:** Kalau modul jahat ditemukan, cek balik **Bab 6 §6.6.3** untuk memahami bagaimana modul ini "dipanggil" dalam alur autentikasi normal, dan **Bab 3 §3.3.1** untuk memeriksa apakah login yang lewat backdoor ini tercatat berbeda (atau justru sama sekali tidak tercatat) di `auth.log` dibanding login normal — perbedaan pola log itu sendiri jadi indikator tambahan.

---

### 8.17 Persistence Recap dari Sudut Pandang Malware 🟡

**Pengertian & Fungsi:**
Bukan pengulangan Bab 6, murni tabel index cepat — begitu malware/rootkit ditemukan lewat §8.3-§8.16, titik mana di Bab 6 yang paling relevan dicek sebagai kelanjutan investigasi (attacker jarang berhenti di satu titik persistence saja).

| Jenis Malware Ditemukan | Titik Persistence yang Wajib Dicek Balik |
|---|---|
| Userland trojan binary (§8.6) | Package manager hook (Bab 6 §6.8), cron (§6.3) untuk auto-reinstall kalau file di-restore |
| LD_PRELOAD hijack (§8.7) | Bab 6 §6.7.2 (`/etc/ld.so.preload`), §6.7.3 (`ld.so.conf.d`) |
| Kernel-level LKM (§8.8) | Modul auto-load saat boot — cek `/etc/modules-load.d/`, systemd service yang me-`modprobe` (Bab 6 §6.4) |
| Fileless (§8.5) | Biasanya di-drop ulang oleh persistence lain (cron/systemd, §6.3-§6.4) — fileless sendiri jarang persisten tanpa "peluncur" |
| PAM backdoor (§8.16) | Bab 6 §6.6.3 |

---

### 8.18 MITRE ATT&CK Mapping (Linux)

| Teknik di Bab 8 | Tactic | Technique ID |
|---|---|---|
| Userland rootkit/binary replacement (§8.6) | Defense Evasion | T1036 (Masquerading), T1553 (Subvert Trust Controls) |
| LD_PRELOAD hijacking (§8.7, Bab 6 §6.7) | Persistence / Defense Evasion | T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking) |
| Process injection via ptrace (§8.4.2) | Defense Evasion / Privilege Escalation | T1055 (Process Injection) |
| Process masquerading (§8.4.1) | Defense Evasion | T1036 (Masquerading) |
| Fileless via memfd_create (§8.5.2) | Defense Evasion | T1027 (Obfuscated Files or Information) |
| Kernel-level rootkit/LKM (§8.8) | Defense Evasion / Persistence | T1014 (Rootkit) |
| RPATH/RUNPATH library hijacking (§8.12) | Persistence / Privilege Escalation | T1574.006 (Hijack Execution Flow) |
| PAM backdoor (§8.16) | Credential Access / Persistence | T1556 (Modify Authentication Process) |

> 💡 **Kegunaan tabel ini:** Standarisasi bahasa laporan investigasi — konsisten dengan gaya yang sudah dipakai di seri Windows kamu, memudahkan laporan dibaca lintas tim/organisasi yang familiar dengan framework ATT&CK.

---

### 8.19 Case Study Pattern — Infection Chain Reconstruction

**Pengertian & Fungsi:**
Pola umum yang berulang di kebanyakan kasus nyata/CTF — dipetakan ke bagian mana di Bab 8 yang relevan tiap fase, sebagai kerangka berpikir sebelum masuk ke skenario spesifik (§8.22).

```
Fase 1: Initial Dropper           → di luar cakupan Bab 8 (root cause di Bab 3/4)
Fase 2: Privilege Escalation       → di luar cakupan Bab 8 (Bab 4 §4.6 sudoers, dst)
Fase 3: Payload Delivery            → §8.11 (static analysis payload), §8.12 (kalau via
                                        library hijacking)
Fase 4: Execution & Hiding            → §8.4 (injection/masquerading), §8.5 (fileless),
                                          §8.6-§8.8 (rootkit level)
Fase 5: Persistence Installation       → cross-ref Bab 6 penuh, §8.17 sebagai index
Fase 6: C2 Communication                → §8.13 (behavioral), §8.14 (IOC extraction)
Fase 7: Anti-Forensics/Cleanup           → cross-ref Bab 3 §3.7 (log tampering)
```

---

### 8.20 Tabel Korelasi — Pertanyaan Investigasi ke Teknik Analisis

| Pertanyaan | Bagian Utama | Cross-ref |
|---|---|---|
| Bagaimana menangani sampel tanpa merusak evidence/reinfeksi? | §8.2 | — |
| Proses ini asli atau menyamar sebagai proses sistem? | §8.4.1 | Bab 3 §3.4.6 |
| Apakah ada kode yang disuntikkan ke proses yang sudah berjalan? | §8.4.2-§8.4.4 | Bab 7 |
| Apakah ada malware yang tidak pernah tersimpan di disk? | §8.5 | Bab 7 |
| Apakah binary sistem sudah dimodifikasi? | §8.6 | Bab 3 §3.6.3 |
| Apakah ada library hijacking lewat LD_PRELOAD? | §8.7 | Bab 6 §6.7 |
| Apakah ada rootkit level kernel? | §8.8, §8.9 | Bab 3 §3.5.4, Bab 7 |
| Tools live saya bisa dipercaya di sistem ini? | §8.9 | — |
| Bagaimana cara cepat triage tanpa tools khusus? | §8.10 | — |
| Bagaimana menganalisis binary tanpa menjalankannya? | §8.11 | — |
| Apakah ada privilege escalation lewat RPATH/RUNPATH? | §8.12 | Bab 6 §6.7.4 |
| Apa yang sebenarnya dilakukan malware saat berjalan? | §8.13 | — |
| Bagaimana menghubungkan temuan malware ke log/timeline lain? | §8.14 | Bab 2, Bab 3 |
| Bagaimana kalau semua tools live sudah tidak bisa dipercaya sama sekali? | §8.15 | Bab 7 |
| Apakah ada backdoor di sistem autentikasi? | §8.16 | Bab 4 §4.7.4, Bab 6 §6.6.3 |
| Setelah malware ditemukan, di mana lagi harus dicek? | §8.17 | Bab 6 (penuh) |
| Bagaimana menulis temuan dalam bahasa standar industri? | §8.18 | — |

---

### 8.21 Ringkasan Command & Tools Cheat Sheet

```bash
# ===== TRIAGE & EVIDENCE HANDLING =====
sha256sum /path/ke/sampel > /tmp/hash_before.txt
sudo cp -a /path/ke/sampel /mnt/evidence/malware/sample_001 && chmod 000 /mnt/evidence/malware/sample_001
ss -tulpn > /mnt/evidence/network_state_before_isolation.txt
md5sum sha1sum sha256sum ssdeep /mnt/evidence/malware/sample_001

# ===== PROCESS MASQUERADING & INJECTION =====
for pid in $(pgrep -f .); do echo "$pid: comm=$(cat /proc/$pid/comm) exe=$(readlink /proc/$pid/exe)"; done
ls -la /proc/*/exe 2>/dev/null | grep deleted
ls -la /proc/*/exe 2>/dev/null | grep "memfd:"
cat /proc/<pid>/maps | grep "rwxp"
cat /proc/<pid>/status | grep TracerPid

# ===== FILELESS =====
cp /proc/<pid>/exe /mnt/evidence/malware/recovered_binary
mount | grep -E "on /tmp |on /dev/shm "
find /dev/shm -type f -exec file {} \;

# ===== USERLAND ROOTKIT =====
dpkg --verify ; rpm -Va
strings /bin/ps | grep -iE "hidden|backdoor"

# ===== LD_PRELOAD BEHAVIOR (lihat juga Bab 6 §6.7) =====
ps aux | wc -l ; ls -d /proc/[0-9]* | wc -l
ss -tulpn | wc -l ; cat /proc/net/tcp /proc/net/tcp6 | tail -n +2 | wc -l

# ===== LKM ROOTKIT =====
lsmod ; cat /proc/modules ; ls /sys/module/
sudo ausearch -m SYSCALL -sc init_module,finit_module

# ===== CROSS-VIEW DETECTION =====
diff <(ps aux --no-headers | awk '{print $2}' | sort -n) \
     <(ls -d /proc/[0-9]* 2>/dev/null | grep -oE '[0-9]+' | sort -n)

# ===== SCANNER OTOMATIS =====
sudo rkhunter --check --sk ; sudo chkrootkit ; sudo unhide proc

# ===== STATIC ANALYSIS ELF =====
readelf -h sample_001 ; readelf -d sample_001 ; readelf -S sample_001
objdump -d sample_001 | less ; objdump -T sample_001
strings -a sample_001 | grep -E "^https?://|^[0-9]{1,3}(\.[0-9]{1,3}){3}$"

# ===== DYNAMIC LINKING HIJACK (DT_NEEDED/RPATH/RUNPATH) =====
readelf -d sample_001 | grep -E "NEEDED|RPATH|RUNPATH"
for f in $(find / -perm -4000 -o -perm -2000 2>/dev/null); do
    readelf -d "$f" 2>/dev/null | grep -E "RPATH|RUNPATH" && echo "  ^ $f"
done

# ===== DYNAMIC/BEHAVIORAL (SANDBOX SAJA) =====
strace -f -o /tmp/strace_out.txt ./sample_001
sudo tcpdump -i any -w /mnt/evidence/network_capture.pcap

# ===== IOC CORRELATION =====
grep -E "<ip_ioc>|<domain_ioc>" /var/log/auth.log /var/log/syslog
journalctl -o json | jq -r 'select(.MESSAGE | test("<ip_ioc>"))'

# ===== PAM BACKDOOR =====
dpkg -V libpam-modules ; rpm -V pam
find /lib*/security/ /usr/lib*/security/ -name "*.so" -newer /etc/hostname
```

---

### 8.22 Mini Case Study — Workflow Analisa End-to-End

**Skenario (lanjutan dari Bab 6 §6.11):** Investigasi sebelumnya di Bab 6 menemukan drop-in override systemd yang menjalankan payload `/tmp/.cache/sync` (ELF binary, disamarkan sebagai file cache). Bab 8 melanjutkan analisis payload itu sendiri, karena `ps aux` ternyata masih menunjukkan proses "sync" berjalan tapi entah kenapa terlihat "generik" dan hampir luput dari investigator.

```
Langkah 1 — Triage aman sebelum analisis lanjut (§8.2)
   sha256sum /tmp/.cache/sync > /tmp/hash_before.txt
   sudo cp -a /tmp/.cache/sync /mnt/evidence/malware/sample_001 && chmod 000 ...
   → sampel diamankan, order of volatility diikuti — proses live BELUM di-kill (§8.2.1)

Langkah 2 — Cek apakah ini masquerading atau sesuatu yang lebih dalam (§8.4.1)
   ps -eo pid,comm,cmd | grep sync
   readlink /proc/<pid>/exe
   → comm="sync" tapi exe menunjuk ke /tmp/.cache/sync (BUKAN /bin/sync asli) — 
     konfirmasi proses menyamar dengan nama generik, bukan proses sistem asli

Langkah 3 — Cek apakah exe sudah dihapus sementara proses masih jalan (§8.5.1)
   ls -alR /proc/*/exe 2>/dev/null | grep deleted
   → NIHIL, file masih ada di /tmp/.cache/sync — bukan kasus deleted-but-running,
     tapi tetap tmpfs-only (§8.5.3) yang akan hilang saat reboot

Langkah 4 — Static analysis payload (§8.11)
   readelf -h /mnt/evidence/malware/sample_001
   strings -a /mnt/evidence/malware/sample_001 | grep -E "^https?://|^[0-9]{1,3}(\.[0-9]{1,3}){3}$"
   → Ditemukan hardcoded IP 203.0.113.5, konsisten dengan traffic periodik yang
     dilaporkan di skenario Bab 6 §6.11

Langkah 5 — Cek dynamic linking untuk kemungkinan hijacking tambahan (§8.12)
   readelf -d /mnt/evidence/malware/sample_001 | grep -E "NEEDED|RPATH|RUNPATH"
   → RPATH kosong, NEEDED cuma libc standar — payload ini self-contained (statically
     dominant), bukan bergantung library hijacking

Langkah 6 — Cross-view detection untuk pastikan tidak ada proses lain tersembunyi (§8.9)
   diff <(ps aux --no-headers | awk '{print $2}' | sort -n) \
        <(ls -d /proc/[0-9]* 2>/dev/null | grep -oE '[0-9]+' | sort -n)
   → Ditemukan SATU PID tambahan yang tidak muncul di ps aux — proses kedua
   readlink /proc/<pid_tersembunyi>/exe
   → menunjuk ke path memfd: (§8.5.2) — proses kedua ini fileless total, di-spawn
     oleh sample_001 sebagai proses anak untuk keperluan terpisah (kemungkinan
     credential harvesting berjalan paralel dengan C2 beacon utama)

Langkah 7 — Behavioral analysis di sandbox terpisah untuk sample_001 (§8.13)
   [dipindah ke VM terisolasi, TIDAK dijalankan lagi di sistem investigasi]
   strace -f -o /tmp/strace_out.txt ./sample_001
   → Konfirmasi pola: connect() periodik ke 203.0.113.5, diselingi fork() yang
     match dengan temuan proses kedua fileless di Langkah 6

Langkah 8 — Cek balik PAM & auth stack untuk memastikan tidak ada backdoor tambahan (§8.16)
   dpkg -V libpam-modules
   → Ditemukan MISMATCH pada pam_unix.so — hash tidak cocok dengan package resmi
   → Modifikasi tertanam di modul autentikasi itu sendiri, bukan modul terpisah baru,
     menjelaskan kenapa investigasi awal Bab 4 tidak langsung mencurigainya

KESIMPULAN:
Infection chain lengkap (§8.19): initial access SSH (Bab 3/4) → persistence via
drop-in override systemd (Bab 6 §6.11) → payload utama /tmp/.cache/sync yang
melakukan process masquerading (§8.4.1) dan men-spawn child process fileless
tambahan lewat memfd_create (§8.5.2) untuk aktivitas paralel → C2 beacon terkonfirmasi
lewat static + behavioral analysis (§8.11, §8.13) → DAN attacker juga memasang PAM
backdoor (§8.16) sebagai jalur akses cadangan independen dari payload utama —
ditemukan HANYA karena verifikasi hash modul sistem dilakukan sebagai bagian rutin
checklist, bukan karena ada indikator mencolok yang menunjuk ke sana secara langsung.
```

> 💡 **Pelajaran utama studi kasus ini:** Rantai infeksi jarang berhenti di satu payload — cross-view detection (§8.9) yang dilakukan **setelah** payload utama ditemukan berhasil mengungkap proses kedua yang nyaris terlewat, dan verifikasi PAM (§8.16) yang dilakukan sebagai **checklist rutin** (bukan karena kecurigaan spesifik) mengungkap jalur akses cadangan independen. Prinsip "jangan berhenti di temuan pertama" yang sudah muncul di Bab 6 §6.9 berlaku sama kuatnya di sini.

> 🔗 **Menuju Bab 9:** Setelah memahami malware/rootkit itu sendiri (Bab 8), bab berikutnya masuk ke **Timeline Correlation & Anti-Forensics** — menyatukan seluruh sumber evidence dari Bab 1-8 (filesystem, log, user/auth, browser, persistence, memory, malware) menjadi satu timeline koheren, sekaligus membahas teknik anti-forensics lanjutan yang belum tercakup di bab-bab sebelumnya.
