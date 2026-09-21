# Panasonic / Matshita UJ870BJ Firmware Research & Dump Toolkit

A low-level hardware research, dynamic binary hooking, and firmware extraction toolkit developed for the **Panasonic / Matshita UJ870BJ** series slimline optical drives.

This repository provides tools to intercept Win32 ASPI calls, forward them directly to modern Windows SCSI Pass-Through Direct (`IOCTL_SCSI_PASS_THROUGH_DIRECT` / SPTI), bypass hardware whitelist verification via runtime memory patching, spoof tray/door event states, and extract the complete 2 MB firmware and buffer RAM address space using direct SCSI commands.

---

## 📑 Table of Contents

* [Overview](#overview)
* [Key Features](#key-features)
* [Repository Structure](#repository-structure)
* [Memory Visualizations & Bitmaps](#memory-visualizations--bitmaps)
* [Hardware & Software Prerequisites](#hardware--software-prerequisites)
* [Building & Compilation](#building--compilation)
* [Usage Guide](#usage-guide)
  * [Method A: Standalone 2 MB Dump (Python)](#method-a-standalone-2-mb-dump-python)
  * [Method B: ASPI Hooking & Whitelist Bypass (Shim DLL)](#method-b-aspi-hooking--whitelist-bypass-shim-dll)
* [Flasher Execution Flow & Known Behaviors](#flasher-execution-flow--known-behaviors)
  * [Two Consecutive Tray Open Prompts](#1-two-consecutive-tray-open-prompts)
  * [Opcode 0xF5, RAM Cleansing & Download Error. (13)](#2-opcode-0xf5-ram-cleansing--download-error-13)
* [SCSI Opcode & Vendor Protocol Reference](#scsi-opcode--vendor-protocol-reference)
* [Disclaimer](#disclaimer)
* [License](#license)

---

## 🔍 Overview

OEM flasher utilities for Matshita/Panasonic optical drives often enforce aggressive restrictions:

* They rely on legacy 32-bit ASPI managers (`wnaspi32.dll`) that are absent or dysfunctional on modern 64-bit Windows platforms.
* They execute rigid model and subsystem verification routines (`sub_401395`), rejecting drives with mismatched OEM strings, subsystem IDs, or cross-flashed designations.
* They block execution unless physical tray mechanics report strict conditions via `GET_EVENT_STATUS`.

This toolkit resolves these constraints by providing both an **in-memory hooking shim** to intercept and manipulate original vendor flasher communications, and a **pure-Python standalone dumper** capable of performing an authenticated handshake to dump the entire 2 MB memory address space.

---

## ⚡ Key Features

### 1. ASPI-to-SPTI Dynamic Shim (`wnaspi32.dll`)
* **ASPI Translation:** Seamlessly bridges legacy Win32 ASPI requests (`SRB_HAInquiry`, `SRB_GDEVBlock`, `SRB_ExecSCSICmd`) directly to SPTI `DeviceIoControl` calls.
* **In-Memory Whitelist Bypass:** Hooks and patches function `sub_401395` in memory at runtime, forcing the target validation variable (`byte_515C7E`) to `0x06` and returning `0x07` (`mov al, 7; ret`).
* **Two-Stage Door Spoofing (`0x4A`):** Intercepts `GET_EVENT_STATUS` queries; returns "Tray Closed" for the first 2 inquiries to satisfy drive initialization, then dynamically flips bit 0 to report "Tray Open" to satisfy flasher update triggers.
* **Automatic 0xEA Payload Capture:** Strips the 48-byte proprietary header from outgoing `0xEA` (RAM write) commands and dumps raw firmware binary chunks directly to `firmware_dump_raw.bin`.
* **Deep Telemetry & Logging:** Real-time ANSI color-coded console logs and full hex dump tracing saved to `aspi_shim_log.txt`.

### 2. Standalone 2 MB SCSI Memory Dumper (`ram_dump.py`)
* **Zero External Dependencies:** Built with pure Python and `ctypes` accessing `\\.\CDROM0`.
* **Dynamic Time-Keyed Unlock Handshake:** Implements the proprietary real-time `0xED` unlock calculation:
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

## 📊 Memory Visualizations & Bitmaps

The included bitmaps illustrate raw 2D byte-entropy representations of the buffer RAM across critical flashing phases. Below is a side-by-side comparison of the memory layouts:

| Baseline (Pre-Flash) | Active Flash (During / Post-Write) | Post-Reboot (Stable) |
| :---: | :---: | :---: |
| <img src="before_firmware_update.jpg" width="230" alt="Baseline RAM State" /> | <img src="after_fw_update.jpg" width="230" alt="Active Flash State" /> | <img src="after_reboot.jpg" width="230" alt="Post-Reboot State" /> |
| **`before_firmware_update.jpg`** | **`after_fw_update.jpg`** | **`after_reboot.jpg`** |
| Structured RAM layout showing recurring register patterns, jump tables, and static lookup buffers prior to code transfer. | High-entropy data distribution reflecting unpacked binary firmware payloads loaded into RAM via opcode `0xEA`. | Return to low-entropy structured state as runtime execution vectors and operational buffers reinitialize. |

---

## 🛠️ Hardware & Software Prerequisites

* **OS:** Windows 7 / 10 / 11 (32-bit or 64-bit).
* **Privileges:** **Administrator privileges are strictly required** to issue `IOCTL_SCSI_PASS_THROUGH_DIRECT` IOCTLs to physical drive handles (`\\.\CdRom0`).
* **Build Environment:** MinGW-w64 32-bit target (`i686-w64-mingw32-gcc`).
* **Python:** Python 3.8+ (x86 or x64).

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

> **Note:** The compiler flags `-Wl,--kill-at` and `-Wl,--enable-stdcall-fixup` ensure that standard export symbols (`GetASPI32SupportInfo`, `SendASPI32Command`, `GetASPI32DLLVersion`) are exported without `@ordinal` suffixes, which legacy ASPI callers require.

---

## 🚀 Usage Guide

### Method A: Standalone 2 MB Dump (Python)

Use this method to extract the drive's entire memory image directly without running vendor flashing software:

1. Connect your **UJ870BJ** optical drive to your computer (direct SATA or a bridge chipset supporting SCSI Pass-Through).
2. Open an **Administrator PowerShell** or Command Prompt.
3. Run the extractor:
   ```bash
   python ram_dump.py
   ```
4. The script executes the following stages:
   * Proprietary unlock calculation (`0xED`).
   * Initialization sequence (`0x2D`).
   * Memory bridge priming (`0xEA`).
   * Sequential streaming of 2048 blocks (`0xE8`).
5. Two timestamped binary files will be generated in your working directory:
   * `uj870_full_2mb_<timestamp>.bin` — Raw firmware memory image.
   * `uj870_headers_2mb_<timestamp>.bin` — Extracted 48-byte block metadata headers.

---

### Method B: ASPI Hooking & Whitelist Bypass (Shim DLL)

Use this method to force an OEM flasher utility to flash or dump an unverified or cross-flashed drive:

1. Place the compiled `wnaspi32.dll` directly into the directory containing the OEM flasher executable.
2. Launch the OEM flasher utility as **Administrator**.
3. The shim automatically intercepts execution:
   * Scans and maps `\\.\CdRom0` through `\\.\CdRom9`.
   * Hot-patches memory address `sub_401395` to disable drive model whitelist checks.
   * Spoofs tray event states via `0x4A`.
   * Captures transmitted firmware code blocks to `firmware_dump_raw.bin`.
4. Inspect `aspi_shim_log.txt` for real-time CDB commands, sense codes, and data transfers.

---

## ⚠️ Flasher Execution Flow & Known Behaviors

When running an OEM flasher tool with the shim DLL, you will encounter the following critical behavioral patterns:

### 1. Two Consecutive "Tray Open" Prompts
During execution, the OEM flasher utility will display a popup prompt asking to **open/close the drive tray twice**:
* **Why it happens:** The flasher queries the drive's mechanical status using opcode `0x4A` (`GET_EVENT_STATUS`).
* The shim's two-stage spoofing logic intercepts these calls:
  * Calls **#1 and #2** return `0x00` in bit 0 of byte 5 (reporting the tray as **CLOSED**) so the utility can complete its initial hardware handshake.
  * Calls **#3 and onwards** force bit 0 to `0x01` (reporting the tray as **OPEN**) to trigger the flasher's update readiness.
* **Action Required:** When the flasher displays the tray notification dialog, simply acknowledge/click through it **both times**. Do not interrupt the process.

### 2. Opcode 0xF5, RAM Cleansing & "Download Error. (13)"
Near the end of the update procedure, the flasher program will terminate with an error dialog stating:
```text
Download Error. (13)
```
* **Root Cause Analysis:**
  1. The flasher successfully sends the primary write payload using vendor opcode `0xF5` (`VENDOR_F5_FLASH_WRITE`).
  2. Once the flash command is executed, the utility attempts to perform a **RAM wipe/cleansing routine** by writing the encrypted firmware container back into volatile buffer memory.
  3. Because the drive's controller is either resetting its internal microcode engine or has already entered its post-write latch state, it ceases acknowledging subsequent write requests.
  4. The flasher detects the unacknowledged transfer and throws **`Download Error. (13)`**.
* **Status:** This error is an expected artifact of the failed RAM-scrub phase. The flash execution command (`0xF5`) and prior RAM writes (`0xEA`) have already completed before this error is thrown.

---

## 🔬 SCSI Opcode & Vendor Protocol Reference

| Opcode | Mnemonic | Direction | Risk Level | Description |
| :---: | :--- | :---: | :---: | :--- |
| `0x12` | `INQUIRY` | IN | Safe | Standard SCSI device identification and vendor query. |
| `0x2D` | `VENDOR_2D` | NONE | Low | Memory bridge setup sequence (`0x81 0x7D`, `0x82 0x00`, `0x82 0x10`). |
| `0x4A` | `GET_EVENT_STATUS` | IN | Safe | Polled for tray door status. Spoofed by shim to satisfy flasher gates. |
| `0xE8` | `VENDOR_E8_READ_RAM` | IN | Safe | Reads raw buffer memory from specified 24-bit physical addresses. |
| `0xEA` | `VENDOR_EA_WRITE_RAM` | OUT | Medium | Writes raw buffer packets; used to prime memory bridge and upload blocks. |
| `0xED` | `VENDOR_ED_UNLOCK` | IN | Safe | Dynamic time-keyed challenge-response authentication handshake. |
| `0xF5` | `VENDOR_F5_FLASH_WRITE` | OUT | **Critical** | Triggers firmware write/flash commit inside the drive controller. |
| `0xFA` | `VENDOR_FA_ERASE` | NONE | **Critical** | **Destructive Flash Erase.** Clears internal flash sectors. |

---

## ⚠️ Disclaimer

This repository is provided solely for reverse engineering, hardware preservation, and educational research purposes. Directly issuing low-level vendor SCSI commands, executing unverified flash write opcodes (`0xF5`), or running erase routines (`0xFA`) carries a substantial risk of permanently bricking optical drives. The authors assume no liability for damaged hardware, lost data, or inoperable devices resulting from the use of this software.

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