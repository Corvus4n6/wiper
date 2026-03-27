# 🦉 OWL — Optimized Wipe and Logging

**Forensic media sterilization utility for Linux**  

OWL is a field-grade tool for verified overwriting of block devices. It performs stuck-bit detection, supports hardware-level erase commands for ATA and NVMe drives, captures SMART health data before and after wiping, and generates tamper-resistant PDF wipe certificates for chain-of-custody documentation.

---

## Features

- **Double-pass software wipe** — writes `0xFF` then `0x00` with read-back verification after each pass, designed to detect stuck bits on any storage media
- **Hardware erase** — ATA Security Erase and NVMe User Data Erase / Block Erase Sanitize, auto-detected by device type
- **SMART capture** — records drive health data before and after the wipe in the certificate
- **PDF wipe certificate** — encrypted, read-only PDF with operator name, device details, SMART data, and NIST SP 800-88r2 standard classification
- **Pre-flight checks** — validates hardware erase capability and drive state before the confirmation prompt
- **Mount guard** — refuses to wipe devices with mounted partitions
- **Device enumeration** — `--list` shows all block devices with model, serial, transport, size, and mount status
- **Rich terminal output** — live progress bars, colour-coded status, and styled device info panels

---

## Requirements

### Python
Python 3.10 or later.

### Python packages
```bash
pip install -r requirements.txt
```

| Package | Purpose |
|---------|---------|
| `blkinfo` | Block device enumeration |
| `pypdf` | PDF certificate encryption |
| `reportlab` | PDF certificate generation |
| `rich` | Terminal output and progress bars |

### System tools
Install via your package manager. All are optional at runtime — OWL will report a clear error if a needed tool is missing.

```bash
# ATA/SATA hardware erase (--hw-erase, --hw-secure)
sudo apt install hdparm

# NVMe hardware erase (--hw-erase, --hw-secure)
sudo apt install nvme-cli

# SMART data capture (--report)
sudo apt install smartmontools
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/corvusforensics/wiper.git
cd wiper

# Install Python dependencies
pip install -r requirements.txt

# Install the script and man page
sudo cp wiper.py /usr/local/bin/wiper
sudo chmod +x /usr/local/bin/wiper
sudo cp wiper.1 /usr/local/share/man/man1/
sudo mandb
```

---

## Usage

```
wiper [OPTIONS] DEVICE
wiper --list
```

OWL must be run as root. All destructive operations require you to confirm by typing the exact device path before the wipe begins.

### Wipe Operations

| Flag | Operation | NIST SP 800-88r2 |
|------|-----------|-----------------|
| `-f`, `--full` | Double-pass `0xFF`→`0x00` + verify each pass **[default]** | Clear |
| `-z`, `--zero` | Single-pass `0x00` + verify | Clear |
| `-s`, `--smart` | Selective null overwrite (rewrites non-zero sectors only) | Non-standard |
| `-c`, `--check` | Read-only scan — reports clean/dirty ratio, no writes | N/A |
| `--hw-erase` | Hardware erase + software verify (ATA or NVMe, auto-detected) | Clear |
| `--hw-secure` | Thorough hardware erase + software verify (ATA or NVMe, auto-detected) | Purge |

### Options

| Flag | Description |
|------|-------------|
| `--list` | Enumerate block devices and exit (no root required) |
| `-l FILE`, `--logfile FILE` | Append timestamped log to FILE |
| `-b SIZE`, `--blocksize SIZE` | Override working block size in bytes (default: 1048576) |
| `--report PATH` | Write a PDF wipe certificate to PATH (or auto-name in a directory) |
| `--operator NAME` | Operator name to record on the certificate |

---

## Examples

**List available block devices:**
```bash
wiper --list
```

**Full double-pass wipe with stuck-bit detection (default):**
```bash
sudo wiper /dev/sdb
```

**Full wipe with log file and PDF certificate:**
```bash
sudo wiper /dev/sdb -l /var/log/wipe.log --report /cases/certs/
```

**Full wipe with certificate and operator name:**
```bash
sudo wiper /dev/sdb --report ./certs/ --operator "Jane Smith"
```

**Hardware erase — auto-detects ATA or NVMe:**
```bash
sudo wiper /dev/sdb --hw-erase --report ./certs/
```

**Hardware secure erase on NVMe (Block Erase + software verify):**
```bash
sudo wiper /dev/nvme0n1 --hw-secure --report ./certs/
```

**Check if a drive is already clear (read-only, no writes):**
```bash
sudo wiper /dev/sdb --check
```

**Smart wipe — only overwrites non-null sectors:**
```bash
sudo wiper /dev/sdc --smart
```

---

## Stuck Bits

The `--full` operation is specifically designed to detect **stuck bits** — storage cells permanently fixed in either a high (`1`) or low (`0`) state that cannot be reliably overwritten. A stuck bit in the wrong location may cause a sector to read back incorrectly regardless of what is written to it, which can compromise the integrity of evidence stored on that media.

OWL detects stuck bits by exploiting their fundamental property: a cell that is stuck cannot hold both states. By writing `0xFF` (all bits high), verifying, then writing `0x00` (all bits low) and verifying again, any sector that fails either pass has cells that could not change state. Stuck bits have been observed on all types of storage media — hard drives, SSDs, USB flash drives, and SD cards.

> **Note:** Hardware erase commands (`--hw-erase`, `--hw-secure`) do not perform a stuck-bit test. They delegate erasure to the drive controller and serve a different forensic purpose: erasing overprovisioned areas inaccessible to the OS. For stuck-bit detection, use `--full`.

---

## Hardware Erase vs. Software Wipe

Storage devices contain more physical capacity than they expose to the OS. Hidden areas — wear-leveling reserves, overprovisioning, and remapped bad sectors — cannot be reached by software overwriting but are erased by hardware commands.

| Method | Stuck-bit detection | Reaches hidden areas | NIST SP 800-88r2 |
|--------|--------------------|--------------------|-----------------|
| `--full` (software) | ✅ Yes | ❌ No | Clear |
| `--hw-erase` | ❌ No | ✅ Yes | Clear |
| `--hw-secure` | ❌ No | ✅ Yes (deeper) | Purge |

`--hw-erase` and `--hw-secure` automatically select the appropriate command based on device type:

| Device | `--hw-erase` | `--hw-secure` |
|--------|-------------|--------------|
| ATA/SATA | `hdparm --security-erase` + verify | `hdparm --security-erase-enhanced` (no verify — erase pattern is vendor-defined) |
| NVMe | `nvme format --ses=1` + verify | `nvme sanitize --sanact=2` + verify (falls back to format if sanitize unsupported) |

---

## Wipe Certificate

When `--report` is specified, OWL generates a PDF certificate containing:

- Operation performed and NIST SP 800-88r2 classification
- Start and end timestamps with UTC offset
- Operator name and host
- Device path, size, model, vendor, serial, and transport
- SMART health data captured before and after the wipe
- Notes explaining the method used (including why ATA Enhanced Secure Erase skips software verification)

The certificate is encrypted with a random owner password to prevent editing. It opens without a password and may be freely viewed, copied, and printed. The owner password is never displayed or logged, making the certificate permanently read-only.

```bash
sudo wiper /dev/sdb --full --report ./certs/ --operator "Jane Smith"

# Auto-named output: ./certs/owl_cert_dev_sdb_20260325_114733.pdf
```

---

## Wipe Standards

Standards are automatically assigned on the certificate based on the operation. No user input is required.

| Operation | Standard |
|-----------|---------|
| `--full` | Two-pass overwrite (0xFF/0x00) with verification — meets NIST SP 800-88r2 Clear; designed for stuck-bit detection |
| `--zero` | NIST SP 800-88r2 — Clear |
| `--hw-erase` | NIST SP 800-88r2 — Clear |
| `--hw-secure` | NIST SP 800-88r2 — Purge |
| `--smart` | Non-standard (partial overwrite, selective sectors only) |
| `--check` | N/A — read-only operation |

**Reference:** Chandramouli R, Hibbard EA (2025). *Guidelines for Media Sanitization*. NIST SP 800-88r2. https://doi.org/10.6028/NIST.SP.800-88r2

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (device not found, permission denied, I/O failure, unsupported hardware) |
| `130` | Interrupted by user (Ctrl+C) |
