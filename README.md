# Panasonic / Matshita UJ870BJ Firmware Research & Dump Toolkit

A low-level hardware research, dynamic binary hooking, and firmware extraction toolkit developed for the **Panasonic / Matshita UJ870BJ** series slimline optical drives.

This repository provides tools to intercept Win32 ASPI calls, forward them directly to modern Windows SCSI Pass-Through Direct (`IOCTL_SCSI_PASS_THROUGH_DIRECT` / SPTI), bypass hardware whitelist verification via runtime memory patching, spoof tray/door event states, and extract the complete 2 MB firmware and buffer RAM address space using direct SCSI commands.

---

## 📑 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Repository Structure](#repository-structure)
- [Memory Visualizations & Analysis](#memory-visualizations--analysis)
- [Hardware & Software Prerequisites](#hardware--software-prerequisites)
- [Building & Compilation](#building--compilation)
- [Usage Guide](#usage-guide)
  - [Method A: Standalone 2 MB Dump (Python)](#method-a-standalone-2-mb-dump-python)
  - [Method B: ASPI Hooking & Whitelist Bypass (Shim DLL)](#method-b-aspi-hooking--whitelist-bypass-shim-dll)
- [SCSI Opcode & Vendor Protocol Reference](#scsi-opcode--vendor-protocol-reference)
- [Troubleshooting & Notes](#troubleshooting--notes)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## 🔍 Overview

OEM flasher utilities for Matshita/Panasonic optical drives often enforce aggressive restrictions:
- They require legacy 32-bit ASPI managers (`wnaspi32.dll`) that are absent or dysfunctional on modern Windows versions.
- They execute rigid model/subsystem verification functions (`sub_401395`), rejecting drives with non-matching vendor strings or region locks.
- They halt execution unless specific tray event conditions are met (`GET_EVENT_STATUS`).

This toolkit solves these constraints by providing both an **in-memory hooking shim** to intercept and manipulate original vendor flasher communications, and a **pure-Python standalone dumper** capable of performing an authenticated handshake to dump the entire 2 MB memory address space.

---

## ⚡ Key Features

### 1. ASPI-to-SPTI Dynamic Shim (`wnaspi32.dll`)
* **ASPI Translation:** Seamlessly bridges legacy Win32 ASPI requests (`SRB_HAInquiry`, `SRB_GDEVBlock`, `SRB_ExecSCSICmd`) directly to SPTI `DeviceIoControl` calls.
* **In-Memory Whitelist Bypass:** Hooks and patches function `sub_401395` in memory on execution, forcing the target validation variable (`byte_515C7E`) to `0x06` and returning `0x07` (`mov al, 7; ret`).
* **Two-Stage Door Spoofing (`0x4A`):** Intercepts `GET_EVENT_STATUS` queries; returns "Tray Closed" for the first 2 inquiries to satisfy initialization, then dynamically flips bit 0 to report "Tray Open" to satisfy flasher confirmation triggers.
* **Automatic 0xEA Payload Capture:** Strips the 48-byte proprietary header from outgoing `0xEA` (RAM write) commands and dumps raw firmware binary chunks directly to `firmware_dump_raw.bin`.
* **Deep Telemetry & Logging:** Real-time ANSI color-coded console logs and full hex dump tracing saved to `aspi_shim_log.txt`.

### 2. Standalone 2 MB SCSI Memory Dumper (`ram_dump.py`)
* **No Dependencies:** Built with pure Python and `ctypes` accessing `\\.\CDROM0`.
* **Dynamic Time-Keyed Unlock Handshake:** Implements the real-time proprietary `0xED` unlock calculation:
  $$a_1 = \sim\text{sec}, \quad a_2 = \sim\text{min}, \quad a_3 = 89 - \text{sec}, \quad a_4 = -\text{min} - 92, \quad a_5 = 118 - \text{sec}, \quad a_6 = 101 - \text{min}$$
* **Memory Bridge Priming:** Establishes bridge state across optical registers via sequential `0x2D` control bytes and `0xEA` null-padding.
* **Granular Extraction:** Dumps 2048 individual 1024-byte chunks across `0x000000` to `0x1FFFFF` via opcode `0xE8`.
* **Header Segregation:** Splices incoming 0x430-byte chunks into `0x30` metadata headers (`uj870_headers_2mb_*.bin`) and `0x400` pure payload blocks (`uj870_full_2mb_*.bin`).

---

## 📂 Repository Structure

```text
├── uj870a_v102.exe               # OEM Flasher Program
├── wnaspi32.cpp                  # C++ ASPI Shim, in-memory patcher & SPTI proxy
├── ram_dump.py                   # Standalone Python 2 MB firmware/RAM extraction script
├── before_firmware_update.jpg    # 2D Bitmapped RAM dump visualization (Baseline state)
├── after_fw_update.jpg           # 2D Bitmapped RAM dump visualization (Active flash state)
├── after_reboot.jpg              # 2D Bitmapped RAM dump visualization (Post-reboot stable state)
├── aspi_shim_log.txt             # (Generated) Diagnostic log with complete hex records
├── firmware_dump_raw.bin         # (Generated) Captured raw payload from 0xEA commands
├── uj870_full_2mb_<ts>.bin       # (Generated) Complete 2 MB firmware image
├── uj870_headers_2mb_<ts>.bin    # (Generated) Extracted 48-byte block metadata headers
└── README.md                     # Documentation & MIT License
```

---

## 📊 Memory Visualizations & Analysis

The included raster bitmaps illustrate raw 2D byte-entropy representations of the buffer RAM across critical flashing phases:

| Stage | Image Reference | Description |
| :--- | :--- | :--- |
| **Pre-Flash** | `before_firmware_update.jpg` | Structured RAM state showing recurring patterns, jump tables, and static drive lookup buffers. |
| **During/Post-Write** | `after_fw_update.jpg` | High-entropy state reflecting unpacked binary payloads. |
| **Post-Reboot** | `after_reboot.jpg` | Return to low-entropy structured state as runtime buffers and vector tables reinitialize. |

---

## 🛠️ Hardware & Software Prerequisites

- **OS:** Windows 7 / 10 / 11 (32-bit or 64-bit).
- **Privileges:** **Administrator privileges are strictly required** to issue `IOCTL_SCSI_PASS_THROUGH_DIRECT` IOCTLs to physical drive handles (`\\.\CdRom0`).
- **Build Environment:** MinGW-w64 32-bit target (`i686-w64-mingw32-gcc`).
- **Python:** Python 3.8+ (x86 or x64).

---

## ⚙️ Building & Compilation

The shim must be compiled as a 32-bit PE dynamic link library (`wnaspi32.dll`) to match the architecture of legacy flashing utilities.

### Compiling on Linux / WSL / MSYS2:

```bash
i686-w64-mingw32-gcc -shared -o wnaspi32.dll wnaspi32.cpp \
    -static -static-libgcc -static-libstdc++ \
    -Wl,--kill-at -Wl,--enable-stdcall-fixup \
    -O2 -Wall
```

> **Note:** The compiler flags `-Wl,--kill-at` and `-Wl,--enable-stdcall-fixup` ensure that standard export symbols (`GetASPI32SupportInfo`, `SendASPI32Command`, `GetASPI32DLLVersion`) are generated without `@ordinal` suffixes, which legacy callers require.

---

## 🚀 Usage Guide

### Method A: Standalone 2 MB Dump (Python)

Use this method to extract the drive's memory image directly without running third-party software.

1. Connect your **UJ870BJ** optical drive to your computer (SATA or compatible USB-to-SATA bridge supporting SCSI pass-through).
2. Open an **Administrator PowerShell** or Command Prompt.
3. Run the extractor:
   ```bash
   python ram_dump.py
   ```
4. The script will perform the sequence:
   - Unlock check (`0xED`)
   - Initialization sequence (`0x2D`)
   - Prime bridge (`0xEA`)
   - Stream 2048 blocks (`0xE8`)
5. Output files will be generated with Unix timestamps:
   - `uj870_full_2mb_<timestamp>.bin`
   - `uj870_headers_2mb_<timestamp>.bin`

---

### Method B: ASPI Hooking & Whitelist Bypass (Shim DLL)

Use this method to run an OEM flasher utility on an unsupported or mismatched firmware version.

1. Place the compiled `wnaspi32.dll` directly into the folder containing the OEM vendor executable.
2. Launch the vendor flasher as **Administrator**.
3. The shim intercepts process initialization and performs:
   - Scanner checks against `\\.\CdRom0` through `\\.\CdRom9`.
   - In-memory hot-patching of validation routine `sub_401395`.
   - Response manipulation on `GET_EVENT_STATUS` (`0x4A`) to emulate tray opening on demand.
   - Transparent capture of all transmitted firmware code blocks to `firmware_dump_raw.bin`.
4. Detailed execution logs are recorded in `aspi_shim_log.txt`.

---

## 🔬 SCSI Opcode & Vendor Protocol Reference

| Opcode | Mnemonic | Direction | Description |
| :--- | :--- | :--- | :--- |
| `0x12` | `INQUIRY` | IN | Standard SCSI device identification and revision querying. |
| `0x2D` | `VENDOR_2D` | NONE | Internal buffer and bridge setup sequence (`0x81 0x7D`, `0x82 0x00`, `0x82 0x10`). |
| `0x4A` | `GET_EVENT_STATUS` | IN | Polled by flasher to confirm tray open/close mechanics. Spoofed by shim. |
| `0xE8` | `VENDOR_E8_READ_RAM` | IN | Reads raw memory from the specified 24-bit target address. |
| `0xEA` | `VENDOR_EA_WRITE_RAM` | OUT | Writes raw buffer packets and primes memory bridge structures. |
| `0xED` | `VENDOR_ED_UNLOCK` | IN | Proprietary vendor challenge-response authentication based on time metrics. |
| `0xFA` | `VENDOR_FA_ERASE` | NONE | **Destructive Flash Erase.** Clears non-volatile storage sectors. |

---

## ⚠️ Disclaimer

This repository is provided for research, reverse engineering, hardware preservation, and educational purposes only. Direct manipulation of optical drive firmware and buffer memory using raw SCSI vendor commands can lead to unrecoverable drive failure (bricking). The authors assume no liability for damaged hardware, corrupted data, or bricked devices resulting from the use of these tools.

---

## 📄 License

This project is licensed under the **MIT License**.

```text
MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```