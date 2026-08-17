## 📌 Daftar Isi — Bab 10

- [Bab 10 — Container & Cloud-Native Forensics (Docker/K8s)](#bab-10--container--cloud-native-forensics-dockerk8s)
  - [10.1 Overview & Posisi Bab 10](#101-overview--posisi-bab-10)
  - [10.2 Fondasi Kernel — Namespace & Cgroup](#102-fondasi-kernel--namespace--cgroup)
    - [10.2.1 Jenis Namespace](#1021-jenis-namespace)
    - [10.2.2 Cgroup v1 vs v2](#1022-cgroup-v1-vs-v2)
    - [10.2.3 `/proc/<PID>/ns/*` — Melihat Namespace Membership dari Host](#1023-procpidns--melihat-namespace-membership-dari-host)
    - [10.2.4 Kenapa Fondasi Ini Wajib 🔴](#1024-kenapa-fondasi-ini-wajib-)
  - [10.3 Container Runtime Forensics 🔴](#103-container-runtime-forensics-)
    - [10.3.1 `containerd`](#1031-containerd)
    - [10.3.2 CRI-O](#1032-cri-o)
    - [10.3.3 `runc`](#1033-runc)
    - [10.3.4 Perbedaan Artefak Docker vs containerd/CRI-O](#1034-perbedaan-artefak-docker-vs-containerdcri-o)
    - [10.3.5 Runtime Metadata & Logs](#1035-runtime-metadata--logs)
  - [10.4 Docker Architecture & Storage Layer](#104-docker-architecture--storage-layer)
    - [10.4.1 Pembagian Layer](#1041-pembagian-layer)
    - [10.4.2 Storage Driver — overlay2](#1042-storage-driver--overlay2)
    - [10.4.3 Image Read-only vs Container Writable Layer ⚠️](#1043-image-read-only-vs-container-writable-layer-)
  - [10.5 Struktur `/var/lib/docker/` — Filesystem Inventory 🔴](#105-struktur-varlibdocker--filesystem-inventory-)
  - [10.6 Docker Metadata & Inspect-based Artifacts](#106-docker-metadata--inspect-based-artifacts)
    - [10.6.1 `docker inspect`](#1061-docker-inspect)
    - [10.6.2 Image History](#1062-image-history)
    - [10.6.3 `.dockerignore`/`Dockerfile` Residu 🟡](#1063-dockerignoredockerfile-residu-)
  - [10.7 Container Logs 🔴](#107-container-logs-)
    - [10.7.1 JSON File Logging Driver (Default)](#1071-json-file-logging-driver-default)
    - [10.7.2 Logging Driver Lain](#1072-logging-driver-lain)
    - [10.7.3 Log Hilang Permanen Setelah Container Dihapus ⚠️](#1073-log-hilang-permanen-setelah-container-dihapus-)
  - [10.8 Container Evidence Acquisition & Preservation 🔴](#108-container-evidence-acquisition--preservation-)
    - [10.8.1 Live vs Offline Acquisition](#1081-live-vs-offline-acquisition)
    - [10.8.2 Host Filesystem](#1082-host-filesystem)
    - [10.8.3 Container Writable Layer 🔴](#1083-container-writable-layer-)
    - [10.8.4 Image/Layers](#1084-imagelayers)
    - [10.8.5 Volumes](#1085-volumes)
    - [10.8.6 Metadata](#1086-metadata)
    - [10.8.7 Logs](#1087-logs)
    - [10.8.8 Runtime State](#1088-runtime-state)
    - [10.8.9 Hash & Preservation](#1089-hash--preservation)
  - [10.9 Image vs Container vs Volume Evidence](#109-image-vs-container-vs-volume-evidence)
  - [10.10 Container Lifecycle Forensics](#1010-container-lifecycle-forensics)
    - [10.10.1 Artefak yang Tersisa Setelah Container Dihapus](#10101-artefak-yang-tersisa-setelah-container-dihapus)
    - [10.10.2 Docker Daemon Event Log sebagai Jejak Lifecycle Independen](#10102-docker-daemon-event-log-sebagai-jejak-lifecycle-independen)
    - [10.10.3 Implikasi Ephemeral by Design 🔴](#10103-implikasi-ephemeral-by-design-)
  - [10.11 Docker Socket & Privilege Escalation 🔴](#1011-docker-socket--privilege-escalation-)
    - [10.11.1 `/var/run/docker.sock`](#10111-varrundockersock)
    - [10.11.2 Container dengan Socket Ter-mount ke Dirinya Sendiri](#10112-container-dengan-socket-ter-mount-ke-dirinya-sendiri)
    - [10.11.3 Deteksi](#10113-deteksi)
  - [10.12 Container Escape Techniques 🔴](#1012-container-escape-techniques-)
    - [10.12.1 Overview Taksonomi](#10121-overview-taksonomi)
    - [10.12.2 Artefak yang Tersisa di Host Setelah Escape Berhasil](#10122-artefak-yang-tersisa-di-host-setelah-escape-berhasil)
  - [10.13 Image Provenance & Registry Artifacts 🟡](#1013-image-provenance--registry-artifacts-)
    - [10.13.1 Image Digest/Hash](#10131-image-digesthash)
    - [10.13.2 Layer Command History sebagai Bukti Modifikasi](#10132-layer-command-history-sebagai-bukti-modifikasi)
    - [10.13.3 Pulled Image Cache](#10133-pulled-image-cache)
  - [10.14 Melihat Container dari Sisi Host — Proses & Jaringan](#1014-melihat-container-dari-sisi-host--proses--jaringan)
    - [10.14.1 Cross-View: Proses Container Terlihat di Host](#10141-cross-view-proses-container-terlihat-di-host)
    - [10.14.2 Identifikasi Proses Milik Container Mana](#10142-identifikasi-proses-milik-container-mana)
    - [10.14.3 Network Namespace — `nsenter`](#10143-network-namespace--nsenter)
  - [10.15 Docker Compose & Multi-container Artifacts 🟡](#1015-docker-compose--multi-container-artifacts-)
  - [10.16 Snapshot/Backup Evidence 🟡](#1016-snapshotbackup-evidence-)
  - [10.17 Kubernetes — Arsitektur Forensik Dasar](#1017-kubernetes--arsitektur-forensik-dasar)
    - [10.17.1 Control Plane vs Node](#10171-control-plane-vs-node)
    - [10.17.2 K8s Bukan Container Engine ⚠️](#10172-k8s-bukan-container-engine-)
  - [10.18 Kubelet & Node-level Artifacts 🔴](#1018-kubelet--node-level-artifacts-)
    - [10.18.1 `/var/lib/kubelet/pods/<pod_uid>/`](#10181-varlibkubeletpodspod_uid)
    - [10.18.2 Static Pod Manifest 🔴](#10182-static-pod-manifest-)
    - [10.18.3 Kubelet Logs & Container Runtime Logs](#10183-kubelet-logs--container-runtime-logs)
  - [10.19 Kubernetes Object Forensics 🔴](#1019-kubernetes-object-forensics-)
    - [10.19.1 Pod](#10191-pod)
    - [10.19.2 Deployment](#10192-deployment)
    - [10.19.3 ReplicaSet](#10193-replicaset)
    - [10.19.4 DaemonSet](#10194-daemonset)
    - [10.19.5 StatefulSet](#10195-statefulset)
    - [10.19.6 Job/CronJob](#10196-jobcronjob)
    - [10.19.7 Service](#10197-service)
    - [10.19.8 ConfigMap](#10198-configmap)
    - [10.19.9 Secret ⚠️](#10199-secret-)
    - [10.19.10 ServiceAccount](#101910-serviceaccount)
    - [10.19.11 RBAC](#101911-rbac)
  - [10.20 etcd — Cluster State Forensics 🟡](#1020-etcd--cluster-state-forensics-)
  - [10.21 Kubernetes Timeline & Attribution 🔴](#1021-kubernetes-timeline--attribution-)
    - [10.21.1 API Audit Log](#10211-api-audit-log)
    - [10.21.2 Kubernetes User](#10212-kubernetes-user)
    - [10.21.3 ServiceAccount](#10213-serviceaccount)
    - [10.21.4 Pod UID](#10214-pod-uid)
    - [10.21.5 Container ID](#10215-container-id)
    - [10.21.6 Node](#10216-node)
    - [10.21.7 Korelasi Rantai Penuh](#10217-korelasi-rantai-penuh)
  - [10.22 Pod Logs & kubectl-based Artifacts](#1022-pod-logs--kubectl-based-artifacts)
  - [10.23 Kubernetes Node vs Control-Plane Evidence 🟡](#1023-kubernetes-node-vs-control-plane-evidence-)
  - [10.24 Kubernetes Network Forensics 🟡](#1024-kubernetes-network-forensics-)
    - [10.24.1 Pod IP](#10241-pod-ip)
    - [10.24.2 Service IP](#10242-service-ip)
    - [10.24.3 Network Namespace](#10243-network-namespace)
    - [10.24.4 CNI (Container Network Interface)](#10244-cni-container-network-interface)
    - [10.24.5 veth](#10245-veth)
    - [10.24.6 kube-proxy](#10246-kube-proxy)
    - [10.24.7 DNS/Network Policy](#10247-dnsnetwork-policy)
  - [10.25 Container Security Configuration Forensics 🟡](#1025-container-security-configuration-forensics-)
  - [10.26 Container/Pod sebagai Vektor Persistence 🔴](#1026-containerpod-sebagai-vektor-persistence-)
  - [10.27 Cloud Metadata Service sebagai Target (Sekilas) 🟡](#1027-cloud-metadata-service-sebagai-target-sekilas-)
  - [10.28 Anti-Forensik Container-Specific](#1028-anti-forensik-container-specific)
  - [10.29 Container/K8s Timeline Correlation — Menuju Bab 9](#1029-containerk8s-timeline-correlation--menuju-bab-9)
  - [10.30 Tabel Korelasi — Pertanyaan Investigasi ke Artefak](#1030-tabel-korelasi--pertanyaan-investigasi-ke-artefak)
  - [10.31 Ringkasan Command & Tools Cheat Sheet](#1031-ringkasan-command--tools-cheat-sheet)
  - [10.32 Mini Case Study — Workflow End-to-End](#1032-mini-case-study--workflow-end-to-end)

---

## Bab 10 — Container & Cloud-Native Forensics (Docker/K8s)

> 💡 **Posisi Bab 10:** Semua bab sebelumnya berasumsi satu sistem operasi Linux dengan satu ruang proses/filesystem/network yang koheren. Bab 10 memecah asumsi itu — satu host bisa menjalankan **puluhan container**, masing-masing dengan pandangan proses/filesystem/network yang **terisolasi secara logis** tapi tetap berbagi **kernel fisik yang sama**. Cross-ref Bab 1 §1.2.5 (`/var/lib/docker/` sudah disinggung sekilas) dan Bab 8 §8.9 (noise container di cross-view rootkit detection) — keduanya dibahas tuntas di bab ini.

> ⚠️ **Koreksi mindset umum — "container itu kayak VM mini":** Ini salah kaprah yang berbahaya secara forensik. VM diisolasi hypervisor di level hardware virtualization — proses di dalam VM **benar-benar tidak terlihat** dari host tanpa masuk ke VM itu sendiri. Container **berbagi kernel** dengan host — isolasinya murni namespace & cgroup (§10.2), bukan hardware. Konsekuensinya: proses container **terlihat** di `ps aux` host (§10.14), koneksi jaringannya bisa dilacak dari network namespace host, dan filesystem-nya (writable layer) ada sebagai direktori biasa di disk host (§10.5). Investigator yang memperlakukan container "seolah VM tertutup total" akan melewatkan sebagian besar artefak yang justru paling mudah diakses justru dari sisi host.

> ⚠️ **Prinsip kedua — container ephemeral by design:** Berbeda dari akun user (Bab 4) atau file biasa (Bab 2) yang punya siklus hidup relatif lambat, container didesain untuk dibuat dan dihancurkan dalam hitungan detik sebagai bagian normal operasional (bukan tanda kompromi). Ini punya implikasi forensik besar yang berulang di seluruh bab ini: banyak artefak (writable layer, runtime state, sebagian log) **hilang permanen** begitu container dihapus, kecuali sempat diawetkan sebelum itu terjadi (§10.8).

---

### 10.2 Fondasi Kernel — Namespace & Cgroup

**Pengertian & Fungsi:**
Semua container engine (Docker, containerd, CRI-O, Podman) dan Kubernetes dibangun di atas **primitif kernel Linux yang sama** — memahami ini adalah prasyarat sebelum masuk ke artefak spesifik tiap tool.

#### 10.2.1 Jenis Namespace

| Namespace | Mengisolasi Apa |
|---|---|
| PID | Ruang nomor proses — proses di dalam container melihat dirinya sebagai PID 1, meski di host punya PID lain yang jauh lebih besar |
| net | Interface jaringan, routing table, port — tiap container bisa punya IP & port space sendiri |
| mnt | Mount point filesystem — pandangan filesystem container terpisah dari host |
| UTS | Hostname & domain name |
| IPC | Shared memory, semaphore, message queue antar-proses |
| user | Pemetaan UID/GID — UID 0 di dalam container **belum tentu** UID 0 yang sama di host (tergantung apakah user namespace remapping diaktifkan) |

#### 10.2.2 Cgroup v1 vs v2

Cgroup (control group) membatasi & mengukur pemakaian resource (CPU, memory, I/O) per grup proses — **bukan** mekanisme isolasi pandangan seperti namespace, tapi mekanisme pembatasan. Cgroup v2 (hierarki unified, default di distro modern) menggantikan v1 (hierarki terpisah per-controller) — perbedaan versi ini memengaruhi **path** yang perlu dicek saat mengidentifikasi proses (§10.2.3).

#### 10.2.3 `/proc/<PID>/ns/*` — Melihat Namespace Membership dari Host

```bash
# Lihat namespace yang dipakai sebuah proses
ls -la /proc/<PID>/ns/

# Bandingkan inode namespace dua proses — sama berarti satu container/pod yang sama
readlink /proc/<PID1>/ns/pid /proc/<PID2>/ns/pid
```

#### 10.2.4 Kenapa Fondasi Ini Wajib 🔴

Setiap kali bab ini membahas "cara mengidentifikasi proses container dari host" (§10.14), "cara mendeteksi container escape" (§10.12), atau "cara Kubernetes mengisolasi Pod" (§10.17), semuanya kembali ke mekanisme namespace & cgroup ini. Tanpa fondasi ini, artefak Docker/K8s akan terasa seperti "black box" yang sulit dikorelasikan balik ke level kernel/proses host.

---

### 10.3 Container Runtime Forensics 🔴

**Pengertian & Fungsi:**
"Docker" bukan satu-satunya container engine, dan bahkan Docker sendiri **tidak** menjalankan container secara langsung — ada rantai layer runtime di baliknya. Memahami rantai ini penting karena **artefak yang tersisa berbeda** tergantung runtime mana yang dipakai host yang sedang diperiksa.

#### 10.3.1 `containerd`

Container runtime tingkat menengah (high-level runtime) yang dipakai Docker **di baliknya**, dan juga dipakai langsung oleh Kubernetes tanpa Docker sama sekali (skema umum di cluster modern setelah Dockershim dihapus dari K8s). Menyimpan state & metadata sendiri, independen dari struktur `/var/lib/docker/`.

```bash
# Path state containerd (default)
ls /var/lib/containerd/

# CLI untuk inspeksi langsung containerd (bypass Docker CLI)
ctr -n k8s.io containers list
ctr -n moby containers list    # namespace "moby" dipakai kalau di-drive oleh Docker
```

#### 10.3.2 CRI-O

Runtime alternatif yang didesain khusus untuk Kubernetes (implementasi CRI — Container Runtime Interface — tanpa fitur tambahan di luar kebutuhan K8s, beda dari containerd yang lebih general-purpose). Umum ditemukan di cluster OpenShift/Red Hat.

```bash
# Path state CRI-O
ls /var/lib/containers/storage/

# CLI inspeksi CRI-O
crictl ps
crictl inspect <container_id>
```

#### 10.3.3 `runc`

Low-level runtime — komponen paling bawah yang benar-benar memanggil syscall kernel (`clone()` dengan flag namespace, setup cgroup) untuk membuat container berjalan. Baik containerd maupun CRI-O sama-sama memanggil `runc` (atau runtime kompatibel OCI lain) di lapisan paling bawah. Jejak `runc` biasanya berupa direktori state sementara di `/run/runc/<container_id>/` selama container berjalan.

#### 10.3.4 Perbedaan Artefak Docker vs containerd/CRI-O

| Aspek | Docker (dockerd + containerd) | containerd Langsung (tanpa Docker, umum di K8s) | CRI-O |
|---|---|---|---|
| Path metadata utama | `/var/lib/docker/containers/<id>/` | `/var/lib/containerd/io.containerd.*/` | `/var/lib/containers/storage/` |
| CLI inspeksi | `docker inspect` | `ctr` atau `crictl` | `crictl` |
| Log default | JSON file per-container di path Docker (§10.7) | Umumnya diarahkan ke `/var/log/pods/` lewat kubelet (§10.22) | Sama, lewat kubelet |
| Socket kontrol | `/var/run/docker.sock` (§10.11) | `/run/containerd/containerd.sock` | `/var/run/crio/crio.sock` |

> ⚠️ **Implikasi investigasi:** Kalau host yang diperiksa adalah **node Kubernetes** (bukan server Docker standalone), jangan otomatis mencari struktur `/var/lib/docker/` — kemungkinan besar tidak ada sama sekali kalau cluster memakai containerd/CRI-O langsung. Selalu **identifikasi runtime yang terpasang dulu** (`crictl` tersedia? `ctr` tersedia? proses `dockerd` berjalan?) sebelum menentukan struktur mana yang berlaku.

#### 10.3.5 Runtime Metadata & Logs

Terlepas dari runtime mana yang dipakai, tiga jenis artefak berikut **selalu** ada dalam bentuk tertentu, hanya lokasinya beda:
- **Metadata konfigurasi** container (command, env, mount) — dibahas per-runtime di §10.5–10.6 & §10.19.
- **Log daemon runtime itu sendiri** (bukan log aplikasi di dalam container) — biasanya lewat systemd journal (`journalctl -u docker`, `journalctl -u containerd`, `journalctl -u crio`), mencatat event lifecycle (start/stop/create/delete) independen dari isi container, cross-ref Bab 3.
- **Runtime state** proses yang sedang berjalan — dibahas §10.8.8.

```bash
journalctl -u docker.service --no-pager | tail -50
journalctl -u containerd.service --no-pager | tail -50
```

---

### 10.4 Docker Architecture & Storage Layer

#### 10.4.1 Pembagian Layer

`dockerd` (daemon, menerima perintah CLI/API) → `containerd` (mengelola lifecycle container) → `runc` (benar-benar membuat container jalan lewat syscall kernel). Docker CLI yang biasa dipakai user (`docker run`, dst) sebenarnya cuma **front-end** — eksekusi sesungguhnya berjalan lewat rantai ini (§10.3).

#### 10.4.2 Storage Driver — overlay2

Storage driver paling umum di Docker modern adalah **overlay2**, memakai OverlayFS kernel untuk menyusun image sebagai tumpukan layer:

```
lower/   ← layer read-only dari image (bisa berlapis banyak)
upper/   ← writable layer milik container ini (perubahan runtime ditulis di sini)
merged/  ← pandangan gabungan yang benar-benar dilihat proses di dalam container
work/    ← area kerja internal OverlayFS
```

#### 10.4.3 Image Read-only vs Container Writable Layer ⚠️

> ⚠️ **Koreksi penting:** Layer image (`lower/`) bersifat **read-only** dan **dibagi** antar semua container yang dijalankan dari image yang sama — perubahan yang dilakukan attacker di dalam container berjalan (install tool, buat file, modifikasi config) **tidak pernah** mengubah image asalnya. Semua perubahan itu masuk ke `upper/` (writable layer) milik container spesifik tersebut. Ini kenapa dua container dari image identik bisa punya isi berbeda total setelah berjalan — dan kenapa writable layer (bukan image) adalah tempat pertama yang harus diperiksa untuk aktivitas runtime attacker (§10.8.3).

---

### 10.5 Struktur `/var/lib/docker/` — Filesystem Inventory 🔴

| Path | Isi | Nilai Forensik |
|---|---|---|
| `containers/<container_id>/config.v2.json` | Konfigurasi lengkap container — command, env var, mount, network, restart policy | Rekonstruksi penuh "container ini dijalankan dengan parameter apa" |
| `containers/<container_id>/hostconfig.json` | Konfigurasi host-level — privilege, capability, resource limit | Deteksi `--privileged`, capability berlebih (§10.25) |
| `containers/<container_id>/<container_id>-json.log` | Log stdout/stderr container (§10.7) | Aktivitas aplikasi di dalam container |
| `image/overlay2/imagedb/` | Metadata image — digest, layer chain, config | Provenance image (§10.13) |
| `overlay2/<layer_id>/` | Isi fisik tiap layer (termasuk writable layer container aktif) | Data mentah filesystem — §10.4.2/10.4.3 |
| `volumes/<volume_name>/_data/` | Data volume — **selamat** meski container dihapus | Nilai forensik tinggi, §10.9 |
| `network/files/` | Konfigurasi network Docker (bridge, custom network) | Rekonstruksi topologi jaringan antar-container |

```bash
cat /var/lib/docker/containers/<id>/config.v2.json | python3 -m json.tool
```

---

### 10.6 Docker Metadata & Inspect-based Artifacts

#### 10.6.1 `docker inspect`

Cara paling langsung membaca `config.v2.json`/`hostconfig.json` dalam format yang sudah diparsing rapi — mengungkap env var (kadang berisi credential yang ditanam langsung), mount (termasuk bind mount berbahaya, §10.25.6), command yang dijalankan, dan network config.

```bash
docker inspect <container_id> | python3 -m json.tool
docker inspect --format '{{json .HostConfig}}' <container_id> | python3 -m json.tool
```

#### 10.6.2 Image History

```bash
docker history --no-trunc <image_name>
```

Menunjukkan command yang dipakai membangun tiap layer image — kalau image dibangun/dimodifikasi lokal oleh attacker (bukan pull murni dari registry publik), command yang mencurigakan bisa terlihat di sini.

#### 10.6.3 `.dockerignore`/`Dockerfile` Residu 🟡

Kalau image di-build lokal di host yang diperiksa (bukan sekadar `docker pull`), residu `Dockerfile` dan `.dockerignore` yang dipakai proses build **kadang** masih tersisa di direktori kerja tempat `docker build` dijalankan — bukan bagian dari `/var/lib/docker/` itu sendiri, tapi layak dicari di sekitar lokasi kerja yang dicurigai.

---

### 10.7 Container Logs 🔴

#### 10.7.1 JSON File Logging Driver (Default)

```
/var/lib/docker/containers/<container_id>/<container_id>-json.log
```

Format: satu baris JSON per entry log, field `log` (isi baris log asli), `stream` (`stdout`/`stderr`), `time` (timestamp RFC3339). Cross-ref prinsip parsing log umum di Bab 3.

```bash
cat /var/lib/docker/containers/<id>/<id>-json.log | python3 -c "
import json,sys
for line in sys.stdin:
    d = json.loads(line)
    print(d['time'], d['stream'], d['log'].rstrip())
"
```

#### 10.7.2 Logging Driver Lain

Docker mendukung logging driver alternatif (`journald`, `syslog`, `fluentd`, dst) yang dikonfigurasi di level daemon atau per-container — kalau driver ini dipakai, log **tidak** berada di path JSON default sama sekali, melainkan diteruskan ke sistem logging yang ditunjuk (mis. `journalctl CONTAINER_NAME=<nama>` kalau driver `journald` dipakai).

#### 10.7.3 Log Hilang Permanen Setelah Container Dihapus ⚠️

> ⚠️ **Koreksi eksplisit:** Dengan logging driver default (`json-file`), log **disimpan sebagai file di dalam direktori container itu sendiri** — begitu `docker rm` dijalankan, file log tersebut **ikut terhapus** kecuali sistem memakai log forwarding eksternal (driver `syslog`/`fluentd`/dst yang mengirim log keluar dari container secara real-time). Ini beda dari asumsi umum "semua log sistem otomatis tersimpan aman terpisah" yang berlaku untuk log OS biasa (Bab 3) — log container **terikat langsung ke siklus hidup container itu sendiri** kalau tidak dikonfigurasi forwarding.

---

### 10.8 Container Evidence Acquisition & Preservation 🔴

**Pengertian & Fungsi:**
Karena prinsip *ephemeral by design* (§10.1), akuisisi bukti container **harus** dilakukan secepat mungkin setelah insiden terdeteksi dan **mengikuti urutan prioritas** berdasarkan apa yang paling cepat hilang — mengikuti semangat *order of volatility* yang sudah dibahas Bab 8 §8.2.1, diterapkan khusus ke konteks container.

#### 10.8.1 Live vs Offline Acquisition

| Kondisi | Pendekatan |
|---|---|
| **Live** — container/host masih berjalan | Prioritas tinggi: tangkap runtime state (§10.8.8) dan writable layer (§10.8.3) **sebelum** container dihentikan/dihapus — begitu `docker rm` dijalankan, sebagian besar hilang permanen |
| **Offline** — host sudah dimatikan/di-image | Rekonstruksi dari disk image `/var/lib/docker/` (atau path runtime lain, §10.3.4) — writable layer & volume kemungkinan masih ada fisik di disk selama belum di-*prune*, tapi runtime state (proses aktif) sudah hilang total |

#### 10.8.2 Host Filesystem

Akuisisi dasar mengikuti prinsip Bab 2 — image seluruh `/var/lib/docker/` (atau path runtime yang relevan, §10.3.4) sebagai bagian dari akuisisi disk host secara umum.

#### 10.8.3 Container Writable Layer 🔴

Prioritas **tertinggi** untuk container yang masih aktif — ini tempat aktivitas attacker paling mungkin terekam (file yang dibuat/dimodifikasi selama runtime, §10.4.3).

```bash
# Export filesystem container (termasuk writable layer) sebagai tar
docker export <container_id> -o container_snapshot.tar

# Alternatif: langsung copy folder overlay2 upper layer dari host (offline/live)
docker inspect --format '{{.GraphDriver.Data.UpperDir}}' <container_id>
```

#### 10.8.4 Image/Layers

```bash
docker save <image_name> -o image_snapshot.tar
```

Mengawetkan seluruh layer image (bukan cuma writable layer) — penting untuk provenance (§10.13) dan sebagai baseline pembanding "apa yang berasal dari image asli vs apa yang ditambahkan runtime".

#### 10.8.5 Volumes

```bash
tar -czf volume_snapshot.tar.gz -C /var/lib/docker/volumes/<volume_name>/_data .
```

Volume **tidak** ikut hilang saat `docker rm` (§10.9) — tapi tetap perlu diawetkan eksplisit kalau ada kemungkinan volume itu sendiri akan dihapus terpisah (`docker volume rm`).

#### 10.8.6 Metadata

Salin `config.v2.json`, `hostconfig.json`, dan hasil `docker inspect` (§10.6.1) sebagai snapshot terpisah — metadata ini hilang bersamaan dengan penghapusan container, sama seperti writable layer.

#### 10.8.7 Logs

Salin file log JSON (§10.7.1) sebelum container dihapus — mengikuti keterbatasan §10.7.3.

#### 10.8.8 Runtime State

Untuk container yang **masih berjalan**, informasi proses live (PID mapping ke host, koneksi jaringan aktif, cgroup path) hanya bisa ditangkap **selagi container masih hidup** — begitu dihentikan, informasi ini tidak bisa direkonstruksi dari disk sama sekali (beda dari writable layer yang setidaknya punya jejak fisik).

```bash
docker top <container_id>
cat /proc/<container_PID>/cgroup
```

#### 10.8.9 Hash & Preservation

Setiap file snapshot yang diakuisisi (§10.8.3–10.8.7) harus di-hash segera setelah diambil untuk chain of custody — mengikuti prinsip yang sama dengan Bab 8 §8.2.4 (chain of custody sampel malware), diterapkan ke seluruh artefak container.

```bash
sha256sum container_snapshot.tar image_snapshot.tar volume_snapshot.tar.gz
```

---

### 10.9 Image vs Container vs Volume Evidence

**Pengertian & Fungsi:**
Ringkasan eksplisit — bagian mana dari "sebuah container" yang tetap ada dan mana yang hilang setelah `docker rm` dijalankan, karena ini pertanyaan paling sering muncul di awal investigasi container.

| Jenis Evidence | Tetap Ada Setelah `docker rm`? | Tetap Ada Setelah `docker rmi` (hapus image)? |
|---|---|---|
| **Image** (layer read-only) | ✅ Ya (image tidak terikat siklus hidup container manapun) | ❌ Tidak — image dan seluruh layer-nya terhapus |
| **Container writable layer** | ❌ Tidak — terhapus bersamaan dengan container | N/A |
| **Container metadata** (`config.v2.json`, dst) | ❌ Tidak | N/A |
| **Container logs** (JSON file default) | ❌ Tidak (kecuali forwarding, §10.7.2) | N/A |
| **Volume** | ✅ Ya — volume punya siklus hidup independen, harus dihapus eksplisit dengan `docker volume rm` | ✅ Ya |
| **Network config custom** | ✅ Ya kalau bukan network default yang dibuat otomatis | N/A |

> 💡 **Implikasi investigatif langsung:** Kalau container sudah dihapus tapi **image** asalnya masih ada, investigator setidaknya bisa merekonstruksi "apa yang seharusnya berjalan di dalam container itu" dari image (§10.13) — meski aktivitas runtime spesifik (writable layer) sudah hilang. Kalau **volume** masih ada, data yang di-mount ke dalamnya (sering berisi data aplikasi/database) tetap bisa diperiksa penuh terlepas nasib container-nya.

---

### 10.10 Container Lifecycle Forensics

#### 10.10.1 Artefak yang Tersisa Setelah Container Dihapus

Mengacu langsung ke tabel §10.9 — image dan volume bisa jadi sumber rekonstruksi utama kalau container sudah tidak ada.

#### 10.10.2 Docker Daemon Event Log sebagai Jejak Lifecycle Independen

```bash
journalctl -u docker.service | grep -E "container (create|start|die|destroy)"
```

> 🔗 **Cross-ref Bab 4 §4.8:** Pola yang sama persis dengan account lifecycle forensics — file/state container memberi kondisi **sekarang**, sementara event log daemon memberi **kapan** container dibuat/dihapus. Kalau container sudah terhapus total (§10.9), log daemon inilah satu-satunya sumber yang masih bisa mengonfirmasi bahwa container itu **pernah ada**, kapan, dan dari image apa.

#### 10.10.3 Implikasi Ephemeral by Design 🔴

Attacker bisa `docker run` → jalankan aksi jahat → `docker rm` dalam hitungan detik. Kalau investigator tidak sempat melakukan akuisisi live (§10.8) sebelum penghapusan terjadi, satu-satunya jejak yang tersisa adalah entry di event log daemon (§10.10.2) — cukup untuk membuktikan **container itu ada**, tapi tidak cukup untuk merekonstruksi **apa isinya** secara detail.

---

### 10.11 Docker Socket & Privilege Escalation 🔴

#### 10.11.1 `/var/run/docker.sock`

Socket Unix yang dipakai untuk berkomunikasi dengan `dockerd` — akses ke socket ini **setara akses root di host**, karena lewat socket ini siapapun bisa memerintahkan Docker menjalankan container baru dengan mount arbitrer ke filesystem host. Cross-ref Bab 4 §4.5.1 (grup `docker` sudah disinggung sebagai grup privileged).

#### 10.11.2 Container dengan Socket Ter-mount ke Dirinya Sendiri

Vektor container escape klasik: container dijalankan dengan `-v /var/run/docker.sock:/var/run/docker.sock` — dari **dalam** container yang seharusnya terisolasi, proses bisa memerintahkan daemon di **host** untuk membuat container baru dengan privilege penuh, efektif membuka jalan keluar dari isolasi.

#### 10.11.3 Deteksi

```bash
# Cek apakah docker.sock ter-mount ke dalam container manapun
docker inspect --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' <container_id> | grep docker.sock

# Cek capability yang diberikan (CapAdd) — cross-ref §10.25.2
docker inspect --format '{{.HostConfig.CapAdd}}' <container_id>
```

---

### 10.12 Container Escape Techniques 🔴

> Disebut sebatas **taksonomi & pattern recognition untuk kebutuhan deteksi forensik**, bukan tutorial eksploitasi — konsisten dengan prinsip Bab 8 soal malware/rootkit.

#### 10.12.1 Overview Taksonomi

| Kategori | Contoh Pola |
|---|---|
| Kernel exploit | Memanfaatkan bug kernel yang dipakai bersama host & container untuk keluar dari namespace |
| Misconfiguration | `--privileged` (§10.25.1), `hostPID`/`hostNetwork`/`hostIPC` (§10.25.5) |
| Docker socket mounted | §10.11.2 |
| Symlink race / mount manipulation | Manipulasi bind mount untuk mengakses path di luar yang dimaksudkan |

#### 10.12.2 Artefak yang Tersisa di Host Setelah Escape Berhasil

- Proses **di host** (bukan lagi di dalam namespace container) dengan cgroup path yang masih menunjukkan asal container tertentu — kombinasi janggal ini (proses di luar namespace container tapi cgroup masih menunjuk ke container) adalah indikator kuat.
- File asing muncul di root filesystem **host** (bukan sekadar di dalam container) yang waktunya berdekatan dengan aktivitas container tertentu.
- Cross-ref §10.14 untuk teknik melihat proses container dari sisi host secara umum, dipakai juga di sini untuk mendeteksi anomali post-escape.

---

### 10.13 Image Provenance & Registry Artifacts 🟡

#### 10.13.1 Image Digest/Hash

```bash
docker inspect --format '{{.RepoDigests}}' <image_name>
```

Verifikasi apakah image yang berjalan sesuai persis dengan yang tercatat resmi di registry (lewat digest), atau sudah dimodifikasi lokal.

#### 10.13.2 Layer Command History sebagai Bukti Modifikasi

`docker history` (§10.6.2) bisa mengungkap command yang dimasukkan attacker ke image kalau image dibangun/dimodifikasi lokal (mis. menambahkan backdoor ke layer baru di atas image dasar yang sah).

#### 10.13.3 Pulled Image Cache

Image yang **pernah** di-pull ke host tetap tercatat di metadata lokal (`image/overlay2/imagedb/`, §10.5) meski **tidak pernah dijalankan sebagai container sama sekali** — bukti bahwa image tersebut pernah ditarik ke sistem, berguna kalau ada dugaan persiapan (staging) yang belum sempat dieksekusi.

---

### 10.14 Melihat Container dari Sisi Host — Proses & Jaringan

#### 10.14.1 Cross-View: Proses Container Terlihat di Host

```bash
ps aux | grep -v grep
# Proses milik container tetap muncul dengan PID host asli (beda dari PID di dalam namespace)
```

> 🔗 **Cross-ref Bab 8 §8.9 (Cross-View Rootkit Detection):** Prinsipnya identik — bandingkan hasil enumerasi dari sudut pandang berbeda untuk temukan anomali. Di sini, "sudut pandang berbeda" adalah PID host vs PID di dalam namespace container; keduanya **harus** bisa direkonsiliasi lewat cgroup/namespace mapping (§10.14.2). Kalau ada proses yang terlihat aktif di level kernel host tapi **tidak** bisa dipetakan ke container manapun yang terdaftar di runtime, itu pola yang sama persis dengan indikasi rootkit yang dibahas Bab 8 — proses "tersembunyi" dari sudut pandang normal.

#### 10.14.2 Identifikasi Proses Milik Container Mana

```bash
cat /proc/<PID>/cgroup
# Output berisi path cgroup yang biasanya mengandung container_id
```

#### 10.14.3 Network Namespace — `nsenter`

```bash
# Masuk ke network namespace container dari host tanpa lewat docker exec
PID=$(docker inspect --format '{{.State.Pid}}' <container_id>)
nsenter -t $PID -n ip addr
```

> ⚠️ Relevan kalau `docker exec` sendiri dicurigai sudah dimanipulasi (mis. binary Docker di-trojan) — `nsenter` memungkinkan masuk ke namespace container langsung lewat mekanisme kernel, tanpa bergantung pada Docker CLI/daemon yang berpotensi sudah tidak bisa dipercaya.

---

### 10.15 Docker Compose & Multi-container Artifacts 🟡

Docker Compose menandai container yang dijalankannya dengan label khusus (`com.docker.compose.project`, `com.docker.compose.service`) — bisa dipakai merekonstruksi arsitektur multi-container (container mana saja yang merupakan bagian dari satu deployment yang sama) meski file `docker-compose.yml` aslinya sudah tidak ada di disk.

```bash
docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' <container_id>
```

---

### 10.16 Snapshot/Backup Evidence 🟡

**Pengertian & Fungsi:**
Sumber recovery **di luar** artefak container itu sendiri — relevan kalau container/volume sudah terhapus total dan akuisisi langsung (§10.8) tidak sempat dilakukan.

| Sumber Snapshot | Relevansi |
|---|---|
| LVM snapshot (host) | Kalau `/var/lib/docker/` berada di volume LVM yang di-snapshot berkala, state lama container/image/volume berpotensi direcover dari snapshot sebelum insiden |
| Btrfs snapshot | Sama prinsipnya dengan LVM, relevan kalau storage driver Docker memakai `btrfs` (bukan overlay2) atau filesystem host secara umum memakai Btrfs dengan snapshot terjadwal |
| VM-level snapshot | Kalau host container itu sendiri adalah VM, snapshot hypervisor (di luar cakupan teknis Linux murni) bisa jadi sumber recovery tambahan |
| Kubernetes backup (Velero, dst) | Backup tingkat cluster K8s — bisa berisi manifest object (§10.19) dan bahkan data volume persisten, tergantung konfigurasi tool backup yang dipakai |

> 📌 Mekanisme detail LVM/Btrfs snapshot sendiri mengikuti pembahasan filesystem snapshot generik yang sudah/akan dicakup di bab lain — di sini fokus pada **kenapa** sumber ini relevan khusus untuk recovery evidence container yang sudah hilang dari lokasi utamanya.

---

### 10.17 Kubernetes — Arsitektur Forensik Dasar

#### 10.17.1 Control Plane vs Node

| Komponen | Peran | Lokasi |
|---|---|---|
| `kube-apiserver` | Gerbang semua request ke cluster (termasuk `kubectl`) | Control plane |
| `etcd` | Database state cluster (§10.20) | Control plane |
| `kube-scheduler` | Menentukan node mana yang menjalankan Pod baru | Control plane |
| `kube-controller-manager` | Menjaga state aktual sesuai state yang diinginkan (reconciliation loop) | Control plane |
| `kubelet` | Agen di tiap node, benar-benar menjalankan Pod lewat container runtime (§10.18) | Node |
| `kube-proxy` | Mengatur routing Service ke Pod (§10.24.6) | Node |

#### 10.17.2 K8s Bukan Container Engine ⚠️

> ⚠️ **Koreksi eksplisit:** Kubernetes **adalah orkestrator**, bukan pengganti container engine — di baliknya tetap memanggil containerd/CRI-O/runc (§10.3) untuk benar-benar menjalankan container. Konsekuensinya: **semua** artefak level container/runtime yang sudah dibahas §10.3–10.16 **tetap berlaku penuh** di node Kubernetes — K8s menambahkan **layer artefak baru** di atasnya (object API, etcd, audit log), bukan menggantikan yang sudah ada.

---

### 10.18 Kubelet & Node-level Artifacts 🔴

#### 10.18.1 `/var/lib/kubelet/pods/<pod_uid>/`

Struktur direktori per-Pod di tiap node — berisi volume mount, secret yang di-mount (§10.19.9), dan metadata terkait Pod tersebut secara lokal.

```bash
ls /var/lib/kubelet/pods/<pod_uid>/volumes/
```

#### 10.18.2 Static Pod Manifest 🔴

```
/etc/kubernetes/manifests/
```

**Pengertian & Fungsi:** Static pod adalah Pod yang didefinisikan langsung lewat file manifest di node, **dijalankan otomatis oleh kubelet tanpa perlu API server sama sekali**. Ini adalah vektor persistence yang khas Kubernetes: file YAML yang ditaruh di direktori ini akan otomatis dijalankan ulang oleh kubelet setiap kali dihapus/dimatikan, bahkan kalau API server/etcd sedang down — cross-ref §10.26.

#### 10.18.3 Kubelet Logs & Container Runtime Logs

Log kubelet sendiri (aktivitas mengelola Pod) terpisah dari log aplikasi di dalam Pod (§10.22) — biasa diakses lewat `journalctl -u kubelet`.

---

### 10.19 Kubernetes Object Forensics 🔴

**Pengertian & Fungsi:**
Kubernetes merepresentasikan segala sesuatu sebagai **object** yang disimpan di etcd (§10.20) dan diekspos lewat API server. Memahami fungsi tiap jenis object — dan nilai forensiknya masing-masing — adalah prasyarat untuk investigasi cluster K8s.

#### 10.19.1 Pod

Unit terkecil deployment — satu/lebih container yang berjalan bersama, berbagi network namespace. Objek yang paling langsung berkorelasi ke artefak level container (§10.3–10.16).

#### 10.19.2 Deployment

Mengelola ReplicaSet (§10.19.3) untuk memastikan sejumlah replika Pod tertentu selalu berjalan — perubahan pada Deployment (`kubectl edit`, dst) tercatat di **revision history**, berguna untuk melihat siapa mengubah apa dan kapan.

#### 10.19.3 ReplicaSet

Memastikan jumlah replika Pod sesuai spesifikasi — biasanya dikelola otomatis oleh Deployment, jarang dimanipulasi langsung, tapi manipulasi langsung ke ReplicaSet (bypass Deployment) bisa jadi indikasi upaya menghindari audit trail Deployment normal.

#### 10.19.4 DaemonSet

Memastikan **satu** Pod berjalan di **setiap** node cluster — vektor persistence yang kuat karena otomatis menyebar ke node baru yang bergabung ke cluster. Attacker yang berhasil membuat DaemonSet jahat efektif mendapat persistence di seluruh cluster sekaligus.

#### 10.19.5 StatefulSet

Seperti Deployment tapi untuk workload yang butuh identitas stabil & storage persisten (database, dst) — Pod StatefulSet punya nama predictable (bukan random hash) dan biasanya terhubung ke PersistentVolume, relevan kalau investigasi menyangkut data yang harus tetap ada meski Pod di-restart.

#### 10.19.6 Job/CronJob

Job menjalankan task sekali sampai selesai; CronJob menjalankan Job berjadwal berulang — **CronJob adalah vektor persistence klasik ala cron tapi versi Kubernetes** (cross-ref Bab 6 persistence umum), bisa dipakai menjalankan payload berkala tanpa perlu Pod yang terus-menerus terlihat berjalan.

#### 10.19.7 Service

Abstraksi networking yang mengarahkan trafik ke sekumpulan Pod (lewat label selector) — dibahas detail dari sisi jaringan di §10.24.2.

#### 10.19.8 ConfigMap

Menyimpan data konfigurasi non-sensitif dalam bentuk key-value — bisa jadi tempat attacker menyisipkan script/config berbahaya yang nantinya di-mount ke dalam Pod sebagai file.

#### 10.19.9 Secret ⚠️

> ⚠️ **Koreksi eksplisit — Secret bukan terenkripsi secara default:** Kubernetes Secret **hanya di-encode base64**, **bukan dienkripsi**, kecuali cluster secara eksplisit dikonfigurasi dengan *encryption at rest* untuk etcd (§10.20). Kesalahpahaman umum yang menganggap "Secret" otomatis berarti aman perlu diluruskan — siapapun dengan akses baca ke object Secret (lewat API atau langsung ke etcd tanpa encryption at rest) bisa **decode** isinya secara trivial (`base64 -d`), tidak perlu proses cracking apapun.

```bash
kubectl get secret <name> -o jsonpath='{.data.password}' | base64 -d
```

#### 10.19.10 ServiceAccount

Identitas yang dipakai **Pod** (bukan manusia) untuk berinteraksi dengan API server — setiap Pod otomatis mendapat token ServiceAccount ter-mount kecuali dinonaktifkan eksplisit. Detail sebagai vektor serangan di §10.19.11 dan §10.21.3.

#### 10.19.11 RBAC

Role-Based Access Control — mendefinisikan **apa yang boleh dilakukan** suatu identitas (user atau ServiceAccount) terhadap object apa. `Role`/`ClusterRole` mendefinisikan permission; `RoleBinding`/`ClusterRoleBinding` mengaitkan permission itu ke identitas tertentu.

> 🔴 **RBAC & ServiceAccount Token sebagai vektor:** Token ServiceAccount otomatis ter-mount ke tiap Pod di `/var/run/secrets/kubernetes.io/serviceaccount/token` — kalau sebuah Pod dikompromikan dan ServiceAccount-nya kebetulan diberi RBAC binding yang terlalu luas (mis. `cluster-admin`), attacker bisa memakai token itu untuk **pivot langsung ke API server** dengan privilege tinggi, tanpa perlu credential manusia sama sekali. Mengecek RBAC binding suatu ServiceAccount adalah langkah wajib untuk menilai **blast radius** kalau satu Pod dikompromikan.

```bash
kubectl auth can-i --list --as=system:serviceaccount:<namespace>:<sa_name>
```

---

### 10.20 etcd — Cluster State Forensics 🟡

**Pengertian & Fungsi:**
etcd adalah database key-value terdistribusi yang menyimpan **seluruh** state cluster — semua object di §10.19 pada akhirnya adalah entry di etcd. Akses ke etcd (biasanya hanya dari node control plane) setara akses ke "database utama" seluruh cluster.

```bash
ETCDCTL_API=3 etcdctl get / --prefix --keys-only | head -50
```

> 🔗 Cross-ref §10.19.9 — kalau *encryption at rest* untuk etcd **tidak** dikonfigurasi, Secret yang tersimpan di etcd bisa dibaca langsung dalam bentuk base64 tanpa hambatan tambahan sama sekali, memperkuat kenapa akses ke etcd sangat sensitif secara forensik (baik sebagai target attacker maupun sumber bukti investigator).

---

### 10.21 Kubernetes Timeline & Attribution 🔴

**Pengertian & Fungsi:**
Merekonstruksi **siapa melakukan apa** di cluster Kubernetes memerlukan korelasi berlapis — beda dari sistem Linux tunggal (Bab 3/Bab 9) karena satu "aksi" bisa melibatkan banyak identitas & lapisan berbeda sebelum akhirnya berwujud sebagai proses nyata di sebuah node.

#### 10.21.1 API Audit Log

Log audit K8s (kalau *audit policy* diaktifkan di API server) mencatat **setiap** request ke API server — siapa (`user`/ServiceAccount), object apa yang diakses/diubah, kapan, dan hasilnya (allowed/denied). Ini adalah sumber log paling sentral untuk attribution di level cluster, konsepnya setara `auth.log`/`journald` di Bab 3 tapi untuk API Kubernetes.

```bash
# Lokasi umum kalau audit log diarahkan ke file (tergantung konfigurasi apiserver)
tail -f /var/log/kubernetes/audit.log | python3 -m json.tool
```

#### 10.21.2 Kubernetes User

Identitas manusia yang terautentikasi ke cluster (lewat client cert, token OIDC, dst) — tercatat di field `user` pada audit log. Kubernetes **tidak** menyimpan daftar user built-in seperti `/etc/passwd` (Bab 4) — identitas user sepenuhnya bergantung pada mekanisme autentikasi eksternal yang dikonfigurasi.

#### 10.21.3 ServiceAccount

Identitas non-manusia (§10.19.10) — tercatat di audit log dengan format `system:serviceaccount:<namespace>:<name>`, membedakannya jelas dari user manusia biasa.

#### 10.21.4 Pod UID

Setiap Pod punya UID unik (berbeda dari nama Pod, yang bisa dipakai ulang) — dipakai untuk melacak Pod spesifik meski nama yang sama pernah dipakai Pod lain sebelumnya (mis. setelah restart/recreate).

#### 10.21.5 Container ID

Di dalam satu Pod bisa ada lebih dari satu container — Container ID (dari runtime, §10.3) adalah identitas paling granular, menghubungkan balik ke artefak level runtime (§10.5–10.8).

#### 10.21.6 Node

Node tempat Pod benar-benar dijalankan — informasi ini penting untuk tahu **di mesin fisik/VM mana** harus mencari artefak level host (§10.18) untuk Pod tertentu.

#### 10.21.7 Korelasi Rantai Penuh

```
API request (Kubernetes User / ServiceAccount, §10.21.1–10.21.3)
        ↓
Object (Pod/Deployment/dst, §10.19) — tercatat perubahannya di API audit log & etcd
        ↓
Pod (Pod UID, §10.21.4) — dijadwalkan ke Node tertentu (§10.21.6)
        ↓
Container (Container ID, §10.21.5) — dijalankan lewat runtime (§10.3) di node tersebut
        ↓
Process (PID di host, §10.14) — proses nyata di kernel host
        ↓
Host — artefak level OS Linux biasa (Bab 1–9 berlaku penuh dari titik ini)
```

> 💡 **Kenapa rantai ini penting:** Investigasi K8s yang solid **selalu** bisa menelusuri dari ujung API (siapa yang meminta) sampai ke ujung proses nyata di host (apa yang benar-benar berjalan) — memutus rantai di tengah (misalnya cuma tahu "ada proses mencurigakan di host" tanpa tahu Pod/ServiceAccount asalnya) berarti kehilangan konteks attribution yang justru paling bernilai di lingkungan cloud-native.

---

### 10.22 Pod Logs & kubectl-based Artifacts

```bash
kubectl logs <pod_name> -c <container_name>
```

**Path di level node** (kalau akses langsung ke node, bukan lewat API):

```
/var/log/pods/<namespace>_<pod_name>_<pod_uid>/<container_name>/
/var/log/containers/<pod_name>_<namespace>_<container_name>-<container_id>.log   ← symlink ke path di atas
```

> ⚠️ Sama seperti keterbatasan §10.7.3 tapi versi K8s: Pod yang sudah **dihapus** (bukan sekadar di-restart) bisa kehilangan log-nya tergantung retention policy log di level node dan apakah ada log aggregation eksternal (Fluentd, Loki, dst) yang mengumpulkan log keluar dari node sebelum terhapus.

---

### 10.23 Kubernetes Node vs Control-Plane Evidence 🟡

| Artefak | Lokasi | Bab/Section Terkait |
|---|---|---|
| API audit log | Control plane (`kube-apiserver`) | §10.21.1 |
| etcd data | Control plane | §10.20 |
| Object manifest (state "keinginan" cluster) | Control plane (etcd), diakses lewat API dari mana saja | §10.19 |
| Static pod manifest | **Node individual** (`/etc/kubernetes/manifests/`) | §10.18.2 |
| Container runtime state & log | **Node tempat Pod dijadwalkan** | §10.3, §10.5–10.8, §10.22 |
| Kubelet log | **Node individual** | §10.18.3 |
| ServiceAccount token (yang sedang dipakai Pod) | **Node tempat Pod berjalan**, di dalam filesystem Pod | §10.19.10 |
| CNI konfigurasi & state network namespace | **Node individual** | §10.24 |

> 💡 Tabel ini penting untuk perencanaan akuisisi: kalau investigator hanya punya akses ke **satu** node dari cluster berisi banyak node, sebagian besar artefak (log audit, etcd, object manifest) tetap bisa diakses lewat API server (asal kredensial API tersedia) — tapi artefak yang sifatnya **lokal ke node** (runtime state, kubelet log, static pod manifest) **hanya** bisa didapat dari node yang bersangkutan secara spesifik.

---

### 10.24 Kubernetes Network Forensics 🟡

#### 10.24.1 Pod IP

Setiap Pod mendapat IP sendiri dari CNI (§10.24.4) — bersifat **ephemeral**, berubah setiap kali Pod di-recreate. IP saja **tidak cukup** untuk investigasi historis; harus dikorelasikan dengan Pod UID (§10.21.4) yang memegang IP itu pada waktu tertentu.

#### 10.24.2 Service IP

IP virtual (ClusterIP) yang stabil, diarahkan oleh `kube-proxy` (§10.24.6) ke salah satu Pod backend yang sesuai label selector — trafik yang tercatat menuju Service IP perlu ditelusuri lebih lanjut ke Pod IP mana yang sebenarnya menangani request pada waktu itu.

#### 10.24.3 Network Namespace

Tiap Pod punya network namespace sendiri (§10.2.1) — semua container dalam satu Pod **berbagi** network namespace yang sama (beda dari isolasi filesystem yang tetap per-container).

#### 10.24.4 CNI (Container Network Interface)

Plugin yang bertanggung jawab memberi IP & menyambungkan network namespace Pod ke jaringan cluster (Calico, Flannel, Cilium, dst) — konfigurasi & log plugin ini (lokasi bervariasi per-plugin) relevan untuk merekonstruksi topologi jaringan cluster dan kebijakan yang berlaku.

#### 10.24.5 veth

Virtual ethernet pair yang menghubungkan network namespace Pod ke namespace root/host — satu ujung ada di dalam Pod, satu ujung terlihat sebagai interface biasa di host (`ip link` di host akan menampilkan banyak interface `veth*`, masing-masing terhubung ke satu Pod).

```bash
ip link show | grep veth
```

#### 10.24.6 kube-proxy

Mengelola aturan routing (lewat `iptables` atau `IPVS`, tergantung mode) yang mewujudkan abstraksi Service IP (§10.24.2) jadi trafik nyata ke Pod backend.

```bash
iptables -t nat -L -n | grep KUBE-SVC
```

#### 10.24.7 DNS/Network Policy

CoreDNS menyediakan resolusi nama internal cluster (`<service>.<namespace>.svc.cluster.local`) — query DNS internal ini bisa jadi jejak komunikasi antar-Pod. `NetworkPolicy` mendefinisikan aturan **siapa boleh bicara dengan siapa** di level Pod — kalau ditemukan `NetworkPolicy` yang tiba-tiba dilonggarkan/dihapus, itu layak dicurigai sebagai bagian dari upaya memperluas akses lateral attacker di dalam cluster.

---

### 10.25 Container Security Configuration Forensics 🟡

| Konfigurasi | Fungsi Normal | Risiko Kalau Disalahgunakan |
|---|---|---|
| `privileged` | Menjalankan container dengan hampir semua kapabilitas kernel host | Praktis setara akses root penuh ke host, vektor escape utama (§10.12) |
| Linux Capabilities | Granular permission kernel (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, dst) — pengganti model "root vs non-root" biner | Capability berlebih yang di-`CapAdd` (§10.11.3) bisa dipakai untuk aksi setara privileged tanpa menandai container sebagai `--privileged` secara eksplisit |
| `seccomp` | Membatasi syscall yang boleh dipanggil proses dalam container | Profile `Unconfined` (dinonaktifkan) membuka seluruh permukaan syscall kernel yang normalnya dibatasi |
| AppArmor/SELinux | Mandatory Access Control tambahan di level proses | Profile yang dinonaktifkan/terlalu longgar mengurangi lapisan pertahanan meski namespace/cgroup tetap berfungsi |
| `hostPID` | Pod berbagi PID namespace **dengan host** | Pod bisa melihat (dan berpotensi menyerang) **semua proses host**, bukan cuma proses dirinya sendiri |
| `hostNetwork` | Pod berbagi network namespace **dengan host** | Pod mendapat akses langsung ke interface jaringan host, bypass isolasi §10.24.3 sepenuhnya |
| `hostIPC` | Pod berbagi IPC namespace dengan host | Berpotensi mengakses shared memory milik proses host lain |
| Bind mount | Memasukkan path dari host langsung ke dalam container | Bind mount ke path sensitif host (`/`, `/etc`, `/var/run/docker.sock` §10.11.2) adalah vektor escape/persistence |
| Read-only filesystem | Root filesystem container di-mount read-only, mencegah modifikasi runtime | **Ketiadaan** flag ini di container yang seharusnya tidak perlu menulis apapun adalah tanda hardening lemah |

```bash
# Cek kombinasi konfigurasi berisiko sekaligus
docker inspect --format '{{.HostConfig.Privileged}} {{.HostConfig.CapAdd}} {{.HostConfig.PidMode}} {{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}}' <container_id>

# Versi Kubernetes — cek securityContext Pod
kubectl get pod <pod_name> -o jsonpath='{.spec.securityContext}{"\n"}{.spec.hostPID}{"\n"}{.spec.hostNetwork}'
```

---

### 10.26 Container/Pod sebagai Vektor Persistence 🔴

**Pengertian & Fungsi:**
Cross-ref Bab 6 (persistence umum di Linux) — Kubernetes menambahkan mekanisme persistence yang **khas cloud-native**, tidak ada padanannya di sistem Linux tunggal.

| Mekanisme | Kenapa Efektif sebagai Persistence |
|---|---|
| Static pod manifest (§10.18.2) | Dijalankan ulang otomatis oleh kubelet **tanpa perlu API server** — bertahan bahkan kalau kontrol akses API sudah diperbaiki |
| DaemonSet (§10.19.4) | Otomatis menyebar ke **setiap node**, termasuk node baru yang bergabung ke cluster setelahnya |
| CronJob (§10.19.6) | Payload berjalan berkala tanpa perlu proses yang terus-menerus terlihat berjalan (mirip cron biasa, tapi tersebar di seluruh cluster) |
| ServiceAccount dengan RBAC binding longgar (§10.19.11) | Bukan persistence dalam arti "kode berjalan", tapi persistence dalam arti **akses** — token yang dicuri tetap valid dan berprivilege tinggi selama tidak di-revoke eksplisit |

---

### 10.27 Cloud Metadata Service sebagai Target (Sekilas) 🟡

`169.254.169.254` adalah alamat metadata service yang disediakan hampir semua cloud provider (AWS, GCP, Azure) — bisa diakses dari dalam Pod/container kalau `hostNetwork` aktif (§10.25) atau lewat SSRF di aplikasi yang berjalan di dalamnya, berpotensi membocorkan credential IAM/role yang terikat ke instance/node tersebut. Disebut sekilas sebagai **konteks** kenapa isolasi jaringan Pod (§10.24) dan pembatasan `hostNetwork` itu penting — detail penuh mekanisme cloud provider spesifik **di luar cakupan** bab ini yang murni fokus sisi Linux.

---

### 10.28 Anti-Forensik Container-Specific

Cross-ref Bab 9 (anti-forensik umum) — container punya bentuk anti-forensik **bawaan** tanpa attacker perlu usaha tambahan sama sekali:

- **Ephemeral by design (§10.1, §10.10.3)** sudah dengan sendirinya menghapus sebagian besar jejak begitu container dihapus — ini "anti-forensik gratis" yang justru **desain normal**, bukan teknik yang sengaja dipakai attacker (meski attacker tentu bisa memanfaatkannya secara sadar).
- `docker system prune -a --volumes` — satu command yang membersihkan image tidak terpakai, container berhenti, network yatim, dan volume tidak terpakai **sekaligus**, setara "wiping" multi-artefak dalam satu langkah.
- Di K8s, menghapus namespace (`kubectl delete namespace <ns>`) menghapus **seluruh** object di dalamnya (Pod, Deployment, Secret, ConfigMap, dst) sekaligus — satu perintah dengan cakupan penghapusan yang sangat luas.

---

### 10.29 Container/K8s Timeline Correlation — Menuju Bab 9

**Pengertian & Fungsi:**
Menyambungkan seluruh sumber waktu yang sudah dibahas bab ini ke metodologi *super timeline* Bab 9, supaya event container/K8s tidak dianalisis terisolasi dari timeline sistem Linux secara keseluruhan.

| Sumber Waktu di Bab 10 | Cross-ref Metodologi Bab 9 |
|---|---|
| Docker daemon event log (§10.10.2) | Masuk sebagai salah satu sumber di inventarisasi timeline lintas-bab, Bab 9 §9.4 |
| Container log JSON (`time` field, §10.7.1) | Perlu normalisasi format timestamp sebelum digabung ke super timeline, Bab 9 §9.5 |
| API audit log K8s (§10.21.1) | Sumber timeline tingkat tertinggi untuk attribution cluster — timestamp API request sebagai anchor utama korelasi §10.21.7 |
| mtime file di `/var/lib/docker/`, `/var/lib/kubelet/` | Berlaku prinsip MACB yang sama seperti Bab 9 §9.3, dengan catatan filesystem overlay (§10.4.2) bisa punya perilaku timestamp sedikit berbeda tergantung storage driver — perlu diverifikasi, bukan diasumsikan sama persis dengan filesystem non-overlay |

> 🔗 Prinsip *evidence reliability/source weighting* (Bab 9 §9.2) berlaku penuh di sini — API audit log (kalau aktif) umumnya adalah sumber dengan reliabilitas tertinggi untuk attribution cluster, sementara timestamp dari log container individual perlu diperlakukan dengan bobot lebih rendah karena lebih mudah dimanipulasi dari dalam container itu sendiri (attacker dengan kontrol penuh di dalam container bisa memalsukan waktu sistem lokal yang memengaruhi timestamp log aplikasinya).

---

### 10.30 Tabel Korelasi — Pertanyaan Investigasi ke Artefak

| Pertanyaan Investigasi | Artefak Utama | Cross-ref |
|---|---|---|
| Container/Pod apa saja yang berjalan di host ini? | `docker ps`/`crictl ps`, cross-view proses host | §10.3.4, §10.14 |
| Apa isi konfigurasi runtime sebuah container? | `config.v2.json`, `docker inspect` | §10.5, §10.6.1 |
| Container ini dijalankan dengan privilege berlebih? | `HostConfig.Privileged`, `CapAdd`, `securityContext` K8s | §10.25 |
| Apakah container ini bisa jadi vektor escape? | Mount `docker.sock`, `hostPID`/`hostNetwork` | §10.11, §10.12, §10.25 |
| Container sudah dihapus — apa yang tersisa? | Image, volume, event log daemon | §10.9, §10.10 |
| Bagaimana cara aman ambil bukti container yang masih live? | Prosedur akuisisi berurutan | §10.8 |
| Log aplikasi di dalam container ke mana? | JSON file log / `/var/log/pods/` | §10.7, §10.22 |
| Siapa yang membuat/mengubah object K8s ini? | API audit log | §10.21.1 |
| Apakah Secret ini benar-benar aman tersimpan? | Base64 encoding, bukan enkripsi (kecuali encryption at rest etcd) | §10.19.9, §10.20 |
| ServiceAccount ini punya akses apa saja? | RBAC binding | §10.19.11 |
| Bagaimana attribution dari API request sampai proses di host? | Rantai korelasi penuh | §10.21.7 |
| Apakah ada mekanisme persistence khas K8s terpasang? | Static pod manifest, DaemonSet, CronJob | §10.18.2, §10.26 |
| Pod ini berkomunikasi dengan siapa saja di jaringan? | Pod IP, CNI, NetworkPolicy | §10.24 |
| Artefak ini harus dicari di node mana atau di control plane? | Tabel lokasi | §10.23 |

---

### 10.31 Ringkasan Command & Tools Cheat Sheet

```bash
# --- Fondasi namespace/cgroup ---
ls -la /proc/<PID>/ns/
cat /proc/<PID>/cgroup

# --- Identifikasi runtime ---
systemctl status docker containerd crio 2>/dev/null
crictl ps
ctr -n k8s.io containers list

# --- Docker inventory & metadata ---
docker ps -a
docker inspect <container_id> | python3 -m json.tool
docker history --no-trunc <image_name>
cat /var/lib/docker/containers/<id>/config.v2.json | python3 -m json.tool

# --- Logs ---
cat /var/lib/docker/containers/<id>/<id>-json.log
journalctl -u docker.service --no-pager | tail -50
journalctl -u kubelet --no-pager | tail -50

# --- Akuisisi & preservation ---
docker export <container_id> -o container_snapshot.tar
docker save <image_name> -o image_snapshot.tar
tar -czf volume_snapshot.tar.gz -C /var/lib/docker/volumes/<vol>/_data .
sha256sum container_snapshot.tar image_snapshot.tar volume_snapshot.tar.gz

# --- Privilege & escape indicators ---
docker inspect --format '{{.HostConfig.Privileged}} {{.HostConfig.CapAdd}} {{.HostConfig.PidMode}}' <container_id>

# --- Host-side cross-view ---
ps aux
ip link show | grep veth
nsenter -t <host_PID> -n ip addr

# --- Kubernetes ---
kubectl get pods -A -o wide
kubectl describe pod <pod_name> -n <namespace>
kubectl get secret <name> -o jsonpath='{.data.password}' | base64 -d
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
kubectl logs <pod_name> -c <container_name>
ls /etc/kubernetes/manifests/
ls /var/lib/kubelet/pods/

# --- etcd ---
ETCDCTL_API=3 etcdctl get / --prefix --keys-only
```

---

### 10.32 Mini Case Study — Workflow End-to-End

**Skenario:** Cluster Kubernetes internal menunjukkan trafik keluar tak wajar dari sebuah namespace produksi. Investigasi dimulai dari API audit log, ditelusuri sampai ke proses nyata di host, dan container asal ternyata sudah dihapus sebelum investigator sempat melakukan akuisisi live penuh.

**Workflow rekonstruksi:**

1. **API audit log sebagai titik awal (§10.21.1).** Ditemukan request `create` untuk sebuah Pod baru dari identitas `system:serviceaccount:ci-pipeline:deployer` di luar jam kerja normal pipeline CI biasa berjalan — anomali waktu ini jadi starting point.

2. **Cek RBAC ServiceAccount tersebut (§10.19.11).** Ternyata `deployer` diberi `ClusterRoleBinding` ke `cluster-admin` — privilege jauh lebih luas dari yang dibutuhkan pipeline CI biasa, indikasi kuat misconfiguration yang dimanfaatkan (atau token ServiceAccount ini yang dicuri dari Pod CI yang kompromi, §10.19.10).

3. **Pod yang dibuat ternyata static pod manifest (§10.18.2), bukan lewat Deployment normal.** File manifest ditemukan di `/etc/kubernetes/manifests/backup-agent.yaml` pada salah satu node — nama disamarkan seperti tooling backup legit, tapi command di dalamnya mengarah ke binary mencurigakan.

4. **Container dari static pod tersebut ternyata sudah tidak berjalan saat investigator tiba di node (§10.9, §10.10.3).** `docker ps -a`/`crictl ps -a` tidak menampilkan container itu lagi — kemungkinan besar dihapus manual atau kubelet sudah melakukan garbage collection.

5. **Rekonstruksi lewat event log daemon (§10.10.2).** `journalctl -u containerd` mengonfirmasi container **pernah** dibuat dan dihentikan, dengan image digest tertentu — cukup untuk membuktikan eksistensinya meski writable layer sudah hilang.

6. **Image masih ada di cache lokal node (§10.13.3).** Karena image belum di-`rmi`, investigator berhasil menjalankan `docker history` terhadap image tersebut — mengungkap layer tambahan berisi script yang mengarah ke domain eksfiltrasi, mengonfirmasi tujuan sebenarnya di balik nama "backup-agent" yang menyamar.

7. **Cross-view proses di host (§10.14) tidak lagi relevan** karena container sudah berhenti sepenuhnya — investigator mencatat keterbatasan ini secara eksplisit di laporan (prinsip *evidence gap analysis*, Bab 9 §9.16), bukan memaksakan kesimpulan dari data yang tidak tersedia.

**Kesimpulan rekonstruksi:** Kombinasi §10.21.1 (audit log sebagai anchor waktu & identitas) + §10.19.11 (RBAC binding yang terlalu longgar sebagai akar masalah) + §10.18.2 (static pod manifest sebagai mekanisme persistence yang lolos dari kontrol Deployment normal) + §10.13.3 (image cache sebagai sumber rekonstruksi setelah container dihapus) berhasil merekonstruksi rantai kejadian dari titik akses awal sampai indikasi tujuan akhir — dengan pengakuan jujur soal artefak yang memang sudah tidak tersedia lagi (langkah 7), konsisten dengan prinsip kejujuran evidentiary yang dipegang di seluruh seri ini.

> 🔗 **Menuju Bab 11:** Setelah memahami isolasi container/orkestrasi K8s (Bab 10), bab berikutnya memperluas cakupan ke **Network Service & Enterprise Linux** — termasuk SSH lateral movement (memperdalam Bab 4 §4.13.7) dan integrasi LDAP/Kerberos yang sempat disinggung sekilas di Bab 4 §4.9 soal `/etc/nsswitch.conf`.
