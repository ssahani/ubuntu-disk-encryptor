# vmdk2kvm

**VMware → KVM/QEMU conversion, repair, and automation toolkit**

`vmdk2kvm` is a production-oriented toolkit for migrating VMware virtual machines  
(**VMDK / OVA / OVF / ESXi / vCenter**, plus **VHD** and **AMI/cloud tarballs**) into  
**KVM/QEMU-bootable images** — reliably, repeatably, and **without relying on boot-time luck**.

It exists for the part that usually hurts: what happens *after* a “successful” conversion.

- boots that fail even though the copy “worked”
- unstable device naming under a new hypervisor
- missing or misordered drivers
- snapshot chains that look valid until exercised
- Windows guests that blue-screen on first KVM boot
- long transfers that die late and force restarts

This repository is intentionally **not** “click migrate and pray”.  
It is “convert, repair, validate — and make it replayable”.

---

## Table of contents

1. Scope and non-goals  
2. Design principles  
3. Supported inputs and execution modes  
4. Pipeline model  
5. Control-plane vs data-plane (vSphere)  
6. Conversion and image outputs  
7. Linux repairs  
8. Windows handling (automatic VirtIO loader)  
9. Archives, VHD, and AMI/cloud tarballs  
10. Snapshots and flattening  
11. YAML configuration model  
12. vSphere integration and actions  
13. virt-v2v integration strategy  
14. Recovery, safety mechanisms, and checkpoints  
15. Validation (libvirt and QEMU)  
16. Daemon mode and systemd integration  
17. Troubleshooting and failure modes  
18. When not to use this tool  
19. Documentation index  
20. License  

---

## 1. Scope and non-goals

### What this tool does

- Converts VMware disks into KVM-usable formats (**qcow2 / raw / vdi**)
- Supports **VMDK, OVA, OVF, VHD, and AMI/cloud tarballs**
- Repairs Linux and Windows guests **offline**
- Applies selected Linux fixes **live over SSH** (live-fix mode)
- Stabilizes storage identifiers (`fstab` rewrite modes)
- Supports **automatic Windows VirtIO driver injection when configured**
- Flattens VMware snapshot chains deterministically
- Supports long operations with **checkpoint/recovery**
- Operates via **mergeable YAML/JSON configs**
- Validates results using **libvirt** and/or **direct QEMU** smoke tests
- Integrates with vSphere using **govc / pyvmomi** and multiple data transports

### What this tool does not do

- No GUI wizard
- Not a cloud importer
- Not “just virt-v2v with flags”
- Not a zero-touch Windows promise
- Not a complexity hider

If you want *fast over correct*, this tool will disagree — politely, with logs.

---

## 2. Design principles

1. **Boot failures are configuration problems, not copy problems**
2. **Device naming must survive hypervisor changes**
3. **Snapshot chains lie unless flattened or verified**
4. **Windows storage must be BOOT_START before first KVM boot**
5. **Every destructive step needs a safe mode**
6. **Configurations must be replayable**
7. **Control-plane and data-plane must never be mixed**

---

## 3. Supported inputs and execution modes

The tool is **YAML-driven**.  
`cmd:` selects the operation; CLI flags override or refine behavior.

Supported `cmd` values:

- `local` — local VMDK
- `fetch-and-fix` — fetch from remote host (SSH/SCP) and process
- `ova` — extract and process OVA
- `ovf` — process OVF + disks
- `vhd` — process a `.vhd` (or tarball containing one)
- `ami` — process AMI/cloud tarball payloads
- `live-fix` — apply live Linux fixes over SSH
- `vsphere` — vCenter / ESXi inventory, download, CBT, export
- `daemon` — watch mode automation
- `generate-systemd` — emit systemd unit

---

## 4. Pipeline model

All modes map to a single internal pipeline:

```

FETCH → FLATTEN → INSPECT → FIX → CONVERT → VALIDATE

````

Stages are optional. **Order is not.**

- **FETCH**: obtain disks and metadata
- **FLATTEN**: collapse snapshot chains
- **INSPECT**: detect OS, layout, firmware
- **FIX**: deterministic guest repairs
- **CONVERT**: produce final images
- **VALIDATE**: boot-level verification

---

## 5. Control-plane vs data-plane (vSphere)

This separation is the structural backbone of vSphere support.

```mermaid
flowchart TB
  %% Control-plane vs Data-plane (vSphere) — GitHub-safe Mermaid

  subgraph CP
    CP_TITLE["CONTROL PLANE<br/>(what exists, what to do)"]
    GOVC["govc<br/>(primary control-plane)"]
    PYVM["pyvmomi / pyVim<br/>(fallback + deep inspection)"]
    INV["inventory & snapshots"]
    CBT["CBT planning<br/>(ranges, change-ids)"]
    DS["datastore inspection<br/>(paths, artifacts)"]

    GOVC --> INV
    GOVC --> CBT
    GOVC --> DS
    PYVM --> INV
    PYVM --> CBT
    PYVM --> DS
  end

  META["plans, ranges,<br/>metadata"]

  subgraph DP
    DP_TITLE["DATA PLANE<br/>(move bytes reliably)"]
    V2V["virt-v2v"]
    VDDK["VDDK reads"]
    HTTP["HTTP /folder<br/>(+ Range GET)"]
    SSH["SSH / SCP"]
    RESUME["resume & verify<br/>.part → final"]
  end

  CP --> META --> DP
  V2V --> RESUME
  VDDK --> RESUME
  HTTP --> RESUME
  SSH --> RESUME
````

* Control-plane **never moves large data**
* Data-plane **never makes inventory decisions**

---

## 6. Conversion and image outputs

Supported output formats:

* **qcow2** (recommended)
* **raw**
* **vdi**

Key flags:

* `--out-format`
* `--to-output`
* `--compress`, `--compress-level`
* `--checksum`

---

## 7. Linux repairs

Offline and live Linux fixes include:

* `/etc/fstab` rewrite (`UUID=` / `PARTUUID=`)
* GRUB root stabilization (BIOS + UEFI)
* initramfs regeneration (distro-aware)
* VMware tools removal
* cloud-init config injection
* filesystem resize (enlarge only)

Live-fix mode operates over SSH with optional sudo escalation.

---

## 8. Windows handling (automatic VirtIO loader)

Windows is a **first-class target**.

Features:

* Automatic VirtIO driver injection **when `--virtio-drivers-dir` is provided**
* Offline registry and hive edits
* `CriticalDeviceDatabase` fixes
* Storage drivers forced to **BOOT_START**
* No blind binary patching

The goal is explicit: the **first KVM boot must succeed**.

---

## 9. Archives, VHD, and AMI/cloud tarballs

### OVA / OVF

* Optional disk inspection logging
* Optional pre-conversion to qcow2
* Compression support

### VHD

* Direct `.vhd`
* Or tarballs containing a VHD payload

### AMI / cloud tarballs

* Optional nested tar extraction
* Optional payload conversion to qcow2
* Compression support

---

## 10. Snapshots and flattening

* Recursive descriptor resolution
* Parent chain verification
* Explicit flatten step (`--flatten`)
* Atomic outputs

Flattening is strongly recommended for reliability.

---

## 11. YAML configuration model

YAML/JSON is treated as **code**:

* mergeable
* reviewable
* replayable

```bash
vmdk2kvm --config base.yaml --config vm.yaml --config overrides.yaml
```

Support tooling:

* `--dump-config`
* `--dump-args`

---

## 12. vSphere integration and actions

Core identity:

* vCenter / ESXi host
* credentials (env-aware)
* TLS verification controls

Supported actions include:

* inventory queries
* snapshot creation
* CBT enablement and sync
* datastore downloads
* VDDK raw disk extraction
* download-only folder sync
* virt-v2v export from vSphere

---

## 13. virt-v2v integration strategy

* Optional use of virt-v2v for conversion
* Optional post-fix virt-v2v stage
* Parallel virt-v2v jobs (experimental)
* Direct vSphere to virt-v2v exports (VDDK or SSH)

---

## 14. Recovery, safety mechanisms, and checkpoints

* `--dry-run`
* backups enabled by default
* explicit `--no-backup` escape hatch
* resumable downloads
* `.part → final` promotion
* optional SHA256 verification

### Encrypted disks (LUKS)

* passphrase or keyfile support
* env-based secret handling
* configurable mapper naming

---

## 15. Validation

* libvirt smoke boots
* direct QEMU boots
* BIOS and UEFI coverage
* headless support
* timeout and resource controls

---

## 16. Daemon mode and systemd integration

* Watch-directory daemon mode
* systemd unit generation
* suitable for unattended pipelines

---

## 17. Troubleshooting and failure modes

* broken snapshot chains
* unstable device naming
* Windows `INACCESSIBLE_BOOT_DEVICE`
* partial or interrupted transfers
* CBT mismatches

Failures are surfaced explicitly; nothing is silently ignored.

---

## 18. When not to use this tool

* You need a GUI
* You want a cloud-specific importer
* You want “fire-and-forget” Windows conversion
* You do not care about reproducibility

---

## 19. Documentation index

See `docs/` for:

* examples
* YAML schemas
* common repair patterns
* vSphere workflows

---

## 20. License

**LGPL (Lesser General Public License)**

---

*Convert with intent. Repair with evidence. Boot without luck.*

```
```
