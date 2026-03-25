#!/usr/bin/python3
'''
   , _ ,
  ( o o )   Optimized
//'` ' `'\\ Wipe &
||'''''''|| Logging
||\\---//|| LightweighT version
    """
OWL - Optimized Wiping and Logging
forensic drive wiper program by Corvus Forensics LLC
designed to wipe, verify, optional logging
LightweighT version for offline use in the field
'''
import os
import sys
import signal
import argparse
import time
import datetime
import math
import re
import subprocess
import atexit
import socket
from dataclasses import dataclass, field
from typing import Optional
from blkinfo import BlkDiskInfo
from rich.console import Console
from rich.progress import (
    Progress, BarColumn, TextColumn, TimeRemainingColumn,
    TransferSpeedColumn, TaskProgressColumn,
)
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console(highlight=False)


@dataclass
class WipeRecord:
    '''
    Accumulates all facts about a wipe session so they can be written
    to a certificate at the end. Passed through main() and populated
    as each stage completes.
    '''
    # Identity
    operator_host: str  = field(default_factory=lambda: socket.gethostname())
    operator_name: str  = ""
    start_time: str     = field(default_factory=lambda: datetime.datetime.now().isoformat(timespec='seconds'))
    end_time: str       = ""

    # Operation
    operation: str      = ""
    dry_run: bool       = False
    command: str        = ""

    # Device
    device_path: str    = ""
    device_size: int    = 0
    block_size: int     = 0
    model: str          = "—"
    vendor: str         = "—"
    serial: str         = "—"
    transport: str      = "—"

    # Outcome
    success: bool       = False
    notes: str          = ""


def generate_certificate(record: WipeRecord, report_path: str, logfile):
    '''
    Write a plain-text wipe certificate to report_path.
    The certificate is human-readable and suitable for printing or archiving.
    '''
    width = 72
    border = "=" * width

    def centre(text):
        return text.center(width)

    def row(label, value, indent=2):
        label_str = f"{' ' * indent}{label:<22}"
        return f"{label_str}{value}"

    size_gib = record.device_size / 1024 / 1024 / 1024

    lines = [
        border,
        centre("O.W.L. — MEDIA STERILIZATION CERTIFICATE"),
        centre("Optimized Wipe and Logging — Corvus Forensics LLC"),
        border,
        "",
        centre("OPERATION DETAILS"),
        "-" * width,
        row("Operation:",        record.operation),
        row("Status:",           "DRY RUN (no data written)" if record.dry_run
                                 else ("COMPLETED SUCCESSFULLY" if record.success
                                 else "FAILED / INCOMPLETE")),
        row("Command:",          record.command),
        row("Start time:",       record.start_time),
        row("End time:",         record.end_time or "—"),
        row("Operator:",         record.operator_name or "—"),
        row("Operator host:",    record.operator_host),
        "",
        centre("DEVICE DETAILS"),
        "-" * width,
        row("Device path:",      record.device_path),
        row("Size (bytes):",     f"{record.device_size:,}"),
        row("Size (GiB):",       f"{size_gib:.2f} GiB"),
        row("Block size:",       f"{record.block_size:,} bytes"),
        row("Model:",            record.model),
        row("Vendor:",           record.vendor),
        row("Serial:",           record.serial),
        row("Transport:",        record.transport),
        "",
    ]

    if record.notes:
        lines += [
            centre("NOTES"),
            "-" * width,
            *[f"  {line}" for line in record.notes.splitlines()],
            "",
        ]

    lines += [
        border,
        centre("END OF CERTIFICATE"),
        border,
        "",
    ]

    cert_text = "\n".join(lines)

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(cert_text)
        console.print(f"\n[bold green]✓ Certificate written to:[/] {report_path}")
        logging(logfile, f"Certificate written to {report_path}")
    except OSError as exc:
        console.print(f"[bold red]✗ Could not write certificate to {report_path}: {exc}[/]")
        logging(logfile, f"ERROR: Could not write certificate: {exc}")


def _sigint_handler(sig, frame):
    '''
    Handle Ctrl+C gracefully - restore cursor and exit with a clean message
    rather than leaving the terminal in a broken state mid-wipe.
    '''
    console.print("\n[bold red]Interrupted by user. Exiting.[/]")
    sys.exit(130)  # 130 = 128 + SIGINT, standard shell convention


signal.signal(signal.SIGINT, _sigint_handler)


def checkblock(block, blocksize, devsize, logfile, dry_run=False):
    '''
    --smart / -s
    Single pass overwriting non-clean sectors with nulls. Not verified.
    Ideal for flash media where we want to limit writes.
    If dry_run is True, detects dirty sectors but does not overwrite them.
    '''
    if dry_run:
        logging(logfile, "DRY RUN: Smart wipe simulation started")
    else:
        logging(logfile, "Smart wipe started")
    nullbytes = bytes(blocksize)
    flushcaches()
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time()
    blockwrites = 0
    devpos = 0
    dry_tag = " [bold yellow][DRY RUN][/]" if dry_run else ""

    with Progress(
        TextColumn(f"[bold cyan]Smart wipe[/]{dry_tag}"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        TextColumn("[green]{task.fields[mbps]:.2f} MB/s"),
        TextColumn("[yellow]{task.fields[writes]} rewrites"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Smart wipe", total=devsize, mbps=0.0, writes=0)

        for _ in range(0, devsize, blocksize):
            devpos = os.lseek(block, 0, os.SEEK_CUR)
            if devpos + blocksize > devsize:
                blocksize = devsize - devpos
                nullbytes = bytes(blocksize)
            bytesin = os.read(block, blocksize)
            runtime = time.time() - starttime
            mbps = (devpos + blocksize) / runtime / 1024 / 1024 if runtime > 0 else 0.0

            if bytesin != nullbytes:
                if not dry_run:
                    devpos = os.lseek(block, -blocksize, os.SEEK_CUR)
                    os.write(block, nullbytes)
                blockwrites += 1

            progress.update(task, completed=devpos + blocksize, mbps=mbps, writes=blockwrites)

    console.print("[dim]Syncing...[/]")
    if not dry_run:
        os.sync()
    flushcaches()

    runtime = time.time() - starttime
    runtimefmt = str(datetime.timedelta(seconds=math.floor(runtime)))
    mbps = (devpos + blocksize) / runtime / 1024 / 1024 if runtime > 0 else 0.0
    if dry_run:
        summary = (f"DRY RUN — smart wipe scan: {devpos + blocksize:,} bytes checked, "
                   f"{blockwrites} dirty blocks found (not overwritten). "
                   f"~{runtimefmt} @ {mbps:.2f} MB/s")
        console.print(f"[bold yellow]~[/] {summary}")
    else:
        summary = (f"Smart wipe complete. {devpos + blocksize:,} bytes checked. "
                   f"{blockwrites} blocks rewritten. {runtimefmt} @ {mbps:.2f} MB/s")
        console.print(f"[bold green]✓[/] {summary}")
    logging(logfile, summary)
    logging(logfile, "Clean. Single pass overwriting non-clear sectors with nulls. Not verified.")



def flushcaches():
    '''
    flush cache so we read from disk rather than buffer.
    Silently skips if /proc/sys/vm/drop_caches is not writable (e.g. non-root
    context or restricted environment) rather than crashing.
    '''
    try:
        with open('/proc/sys/vm/drop_caches', 'w', encoding="ascii") as file_object:
            file_object.write("1\n")
    except OSError:
        pass  # non-fatal: cache flush is a best-effort optimization

def wipefail(block, position, blocksize, pattern, logfile):
    '''
    Called when a read-back verification mismatch is detected.
    Attempts a single rewrite of the failed block. If that also fails
    (bad sector / I/O error), logs the failure and exits rather than
    silently continuing over unwritable media.
    '''
    console.print(f"\n[bold yellow]⚠ Write mismatch at position {position:,} — attempting rewrite...[/]")
    logging(logfile, f"Write failure detected in block at {position} - rewrite attempted")
    if pattern == "00":
        bytepattern = bytes(blocksize)
    else:
        bytepattern = bytes(blocksize).replace(b'\x00', b'\xff')
    try:
        os.lseek(block, position, os.SEEK_SET)
        os.write(block, bytepattern)
        os.sync()
        flushcaches()
        os.lseek(block, position, os.SEEK_SET)
        bytesin = os.read(block, blocksize)
    except OSError as exc:
        msg = f"I/O error during rewrite at position {position}: {exc}"
        console.print(f"[bold red]✗ {msg}[/]")
        logging(logfile, msg)
        logging(logfile, "Exiting due to I/O error.")
        sys.exit(1)
    if bytesin != bytepattern:
        msg = f"Re-write attempt failed at position {position} — sector may be bad."
        console.print(f"[bold red]✗ {msg}[/]")
        logging(logfile, msg)
        logging(logfile, "Exiting.")
        sys.exit(1)
    return

def drivemap(block, blocksize, devsize, logfile):
    '''
    --check / -c
    Quick mapping of the data on the drive for stats.
    '''
    logging(logfile, "Drive mapping started")
    cleancount = 0
    dirtycount = 0
    keepmapping = False
    nullbytes = bytes(blocksize)
    os.lseek(block, 0, os.SEEK_SET)
    flushcaches()

    with Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        TextColumn("[green]Clean: {task.fields[cleanpct]}"),
        TextColumn("[red]Dirty: {task.fields[dirtypct]}"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Drive map", total=devsize, cleanpct="0.000%", dirtypct="0.000%")

        for dev_pos in range(0, devsize, blocksize):
            if dev_pos + blocksize > devsize:
                blocksize = devsize - dev_pos
                nullbytes = bytes(blocksize)
            bytesin = os.read(block, blocksize)

            if bytesin == nullbytes:
                cleancount += blocksize
            else:
                dirtycount += blocksize
                if not keepmapping:
                    progress.stop()
                    logging(logfile, f"Non-clear sectors found in block starting at {dev_pos:,}")
                    console.print(f"\n[bold yellow]⚠ Non-clear sectors found at position {dev_pos:,}[/]")
                    check = console.input("[bold]Continue mapping? [y/N][/] ")
                    if check.strip().lower() == "y":
                        keepmapping = True
                        logging(logfile, "User chose to continue mapping.")
                        progress.start()
                    else:
                        console.print("[bold red]Drive is not clear. Exiting.[/]")
                        logging(logfile, "User chose to terminate mapping.")
                        logging(logfile, "Drive mapped. Drive is dirty and contains non-clear sectors.")
                        sys.exit()

            cleanpct = f"{cleancount / devsize:.3%}"
            dirtypct = f"{dirtycount / devsize:.3%}"
            progress.update(task, completed=dev_pos + blocksize,
                            cleanpct=cleanpct, dirtypct=dirtypct)

    console.print()
    if dirtycount == 0:
        console.print("[bold green]✓ Drive is clear and only contains 0x00.[/]")
        logging(logfile, "Drive mapped. Drive is clear and only contains 0x00.")
    else:
        console.print("[bold red]✗ Drive is not clear.[/]")
        logging(logfile, f"Drive mapped. Drive is dirty and contains non-nulled "
            f"data. {cleanpct} clean and {dirtypct} dirty ({dirtycount:,} bytes).")



def command_line(cmd, cmdtimeout=None):
    '''
    subprocess helper
    '''
    try:
        spobj = subprocess.run(cmd, capture_output=True, timeout=cmdtimeout, check=True)
        spout = spobj.stdout
        return spout.strip()
    except subprocess.CalledProcessError:
        return b''
    except subprocess.TimeoutExpired:
        return b'Timeout'

def atasecure(devname, logfile):
    '''
    call hdparm and ATA Secure-Erase the drive
    ###
    hdparm -I <device>
    hdparm --user-master user --security-set-pass pass <device>
    hdparm --user-master user --security-erase-enhanced pass <device>
     - or if enhanced is not supported -
    hdparm --user-master user --security-erase pass <device>
     - afterwards, remove passwords from drive -
    hdparm --user-master user --security-disable pass <device>
    hdparm --user-master user --security-set-pass NULL <device>
    '''
    logging(logfile, "Performing ATA Secure Erase on drive.")
    hdpcheck = command_line(['which', 'hdparm'])
    if hdpcheck == b'':
        console.print("[bold red]ERROR: hdparm utility not found. Exiting.[/]")
        logging(logfile, "ERROR: hdparm utility not found. Exiting.")
        sys.exit(1)
    hdpi = command_line(['hdparm', '-I', devname]).decode(errors='replace')
    if re.search(r'not\tsupported: enhanced erase', hdpi):
        console.print("[bold red]ERROR: ATA Secure Erase not supported for this device. Exiting.[/]")
        logging(logfile, "ERROR: ATA Secure Erase not supported for this device. Exiting.")
        sys.exit(1)
    if not re.search(r'not\tfrozen', hdpi):
        console.print("[bold red]ERROR: Drive is currently frozen. Exiting.[/]")
        logging(logfile, "ERROR: Drive is currently frozen. Exiting.")
        sys.exit(1)
    if not re.search(r'not\tlocked', hdpi):
        console.print("[bold red]ERROR: Drive is currently locked. Exiting.[/]")
        logging(logfile, "ERROR: Drive is currently locked. Exiting.")
        sys.exit(1)
    setime = re.search(r'([0-9]+min for ENHANCED SECURITY ERASE)', hdpi).group(1)
    console.print(f"[cyan]Drive reports {setime}[/]")
    logging(logfile, f"Drive reports {setime}")
    command_line(['hdparm', '--user-master', 'user', '--security-set-pass', 'pass', devname])
    logging(logfile, "ATA password set to 'pass'")
    logging(logfile, "ATA Secure Erase command sent")
    command_line(['hdparm', '--user-master', 'user', '--security-erase-enhanced', 'pass', devname])
    logging(logfile, "ATA Secure Erase completed")
    command_line(['hdparm', '--user-master', 'user', '--security-set-pass', 'NULL', devname])
    logging(logfile, "ATA password removed.")
    command_line(['hdparm', '--user-master', 'user', '--security-disable', 'NULL', devname])
    logging(logfile, "ATA security disabled")
    console.print("[bold green]✓ ATA Secure Erase completed.[/]")
    logging(logfile, "ATA Secure Erase completed.")
    # note: we can't call this 'clean' or 'clear' because the pattern may not be zeroes

def ataerase(devname, logfile):
    '''
    # call hdparm and ATA Erase (null) the drive
    '''
    logging(logfile, "Performing ATA Erase on drive.")
    hdpcheck = command_line(['which', 'hdparm'])
    if hdpcheck == b'':
        console.print("[bold red]ERROR: hdparm utility not found. Exiting.[/]")
        logging(logfile, "ERROR: hdparm utility not found. Exiting.")
        sys.exit(1)
    hdpi = command_line(['hdparm', '-I', devname]).decode(errors='replace')
    if not re.search(r'(?<!not\t)supported: enhanced erase', hdpi):
        console.print("[bold red]ERROR: ATA Erase not supported for this device. Exiting.[/]")
        logging(logfile, "ERROR: ATA Erase not supported for this device. Exiting.")
        sys.exit(1)
    if not re.search(r'not\tfrozen', hdpi):
        console.print("[bold red]ERROR: Drive is currently frozen. Exiting.[/]")
        logging(logfile, "ERROR: Drive is currently frozen. Exiting.")
        sys.exit(1)
    if not re.search(r'not\tlocked', hdpi):
        console.print("[bold red]ERROR: Drive is currently locked. Exiting.[/]")
        logging(logfile, "ERROR: Drive is currently locked. Exiting.")
        sys.exit(1)
    setime = re.search(r'([0-9]+min for SECURITY ERASE)', hdpi).group(1)
    console.print(f"[cyan]Drive reports {setime}[/]")
    logging(logfile, f"Drive reports {setime}")
    command_line(['hdparm', '--user-master', 'user', '--security-set-pass', 'pass', devname])
    logging(logfile, "ATA password set to 'pass'")
    logging(logfile, "ATA Erase command sent")
    command_line(['hdparm', '--user-master', 'user', '--security-erase', 'pass', devname])
    logging(logfile, "ATA Erase command completed")
    command_line(['hdparm', '--user-master', 'user', '--security-set-pass', 'NULL', devname])
    logging(logfile, "ATA password removed")
    command_line(['hdparm', '--user-master', 'user', '--security-disable', 'NULL', devname])
    logging(logfile, "ATA Security disabled.")
    console.print("[bold green]✓ ATA Erase completed.[/]")
    logging(logfile, "ATA Erase completed.")
    # note: we can't call this 'clean' or 'clear' because the pattern may not be zeroes

def writeloop(block, blocksize, devsize, pattern, logfile, dry_run=False):
    '''
    Full disk write pass — writes a single byte pattern across the entire device.
    If dry_run is True, seeks and reads normally but skips all os.write() calls.
    '''
    if dry_run:
        logging(logfile, f"DRY RUN: Would write 0x{pattern} to drive.")
    else:
        logging(logfile, f"Writing 0x{pattern} to drive.")
    color = "red" if pattern == "FF" else "cyan"
    dry_tag = " [bold yellow][DRY RUN][/]" if dry_run else ""
    if pattern == "00":
        writepattern = bytes(blocksize)
    else:
        writepattern = bytes(blocksize).replace(b'\x00', b'\xff')
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time()

    with Progress(
        TextColumn(f"[bold {color}]Write 0x{pattern}[/]{dry_tag}"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        TextColumn("[dim]{task.fields[mbps]:.2f} MB/s"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(f"Write 0x{pattern}", total=devsize, mbps=0.0)
        for dev_pos in range(0, devsize, blocksize):
            if dev_pos + blocksize > devsize:
                blocksize = devsize - dev_pos
                if pattern == "00":
                    writepattern = bytes(blocksize)
                else:
                    writepattern = bytes(blocksize).replace(b'\x00', b'\xff')
            if not dry_run:
                try:
                    os.write(block, writepattern)
                except OSError as exc:
                    msg = f"I/O write error at position {dev_pos}: {exc}"
                    console.print(f"[bold red]✗ {msg}[/]")
                    logging(logfile, msg)
                    logging(logfile, "Exiting due to I/O error.")
                    sys.exit(1)
            else:
                # simulate the time cost of a seek without writing
                os.lseek(block, dev_pos + blocksize, os.SEEK_SET)
            runtime = time.time() - starttime
            mbps = (dev_pos + blocksize) / runtime / 1024 / 1024 if runtime > 0 else 0.0
            progress.update(task, completed=dev_pos + blocksize, mbps=mbps)

    runtime = time.time() - starttime
    mbps = devsize / runtime / 1024 / 1024 if runtime > 0 else 0.0
    runtimefmt = str(datetime.timedelta(seconds=math.floor(runtime)))
    if dry_run:
        summary = f"DRY RUN — would write 0x{pattern}: {devsize:,} bytes in ~{runtimefmt} @ {mbps:.2f} MB/s"
        console.print(f"[bold yellow]~[/] {summary}")
    else:
        summary = f"Wrote 0x{pattern}: {devsize:,} bytes in {runtimefmt} @ {mbps:.2f} MB/s"
        console.print(f"[bold green]✓[/] {summary}")
    logging(logfile, summary)

def readloop(block, blocksize, devsize, pattern, logfile):
    '''
    Full disk verify pass — reads back every block and checks against expected pattern.
    '''
    logging(logfile, f"Verifying 0x{pattern} on drive.")
    if pattern == "00":
        writepattern = bytes(blocksize)
    else:
        writepattern = bytes(blocksize).replace(b'\x00', b'\xff')
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time()

    with Progress(
        TextColumn("[bold green]Verify 0x{task.fields[pat]}[/]"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        TextColumn("[dim]{task.fields[mbps]:.2f} MB/s"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(f"Verify 0x{pattern}", total=devsize, mbps=0.0, pat=pattern)
        for dev_pos in range(0, devsize, blocksize):
            if dev_pos + blocksize > devsize:
                blocksize = devsize - dev_pos
                if pattern == "00":
                    writepattern = bytes(blocksize)
                else:
                    writepattern = bytes(blocksize).replace(b'\x00', b'\xff')
            try:
                bytesin = os.read(block, blocksize)
            except OSError as exc:
                msg = f"I/O read error at position {dev_pos}: {exc}"
                console.print(f"[bold red]✗ {msg}[/]")
                logging(logfile, msg)
                logging(logfile, "Exiting due to I/O error.")
                sys.exit(1)
            if bytesin != writepattern:
                wipefail(block, dev_pos, blocksize, pattern, logfile)
            runtime = time.time() - starttime
            mbps = (dev_pos + blocksize) / runtime / 1024 / 1024 if runtime > 0 else 0.0
            progress.update(task, completed=dev_pos + blocksize, mbps=mbps)

    runtime = time.time() - starttime
    mbps = devsize / runtime / 1024 / 1024 if runtime > 0 else 0.0
    runtimefmt = str(datetime.timedelta(seconds=math.floor(runtime)))
    summary = f"Verified 0x{pattern}: {devsize:,} bytes in {runtimefmt} @ {mbps:.2f} MB/s"
    console.print(f"[bold green]✓[/] {summary}")
    logging(logfile, summary)



def fulltest(block, blocksize, devsize, logfile, dry_run=False):
    '''
    --full / -f - check all bits flip both ways and verify
    '''
    logging(logfile, "Full drive double-wipe and verify started")

    writeloop(block, blocksize, devsize, "FF", logfile, dry_run)
    console.print("[dim]Syncing...[/]")
    if not dry_run:
        os.sync()
    flushcaches()

    readloop(block, blocksize, devsize, "FF", logfile)

    writeloop(block, blocksize, devsize, "00", logfile, dry_run)

    console.print("[dim]Syncing...[/]")
    if not dry_run:
        os.sync()
    flushcaches()

    readloop(block, blocksize, devsize, "00", logfile)

    logging(logfile, "Double wipe and verify completed.")

def singlepass(block, blocksize, devsize, logfile, dry_run=False):
    '''
    --zero / -z - write a null to every sector and then verify
    '''
    logging(logfile, "Single-pass null and verify started")

    writeloop(block, blocksize, devsize, "00", logfile, dry_run)

    console.print("[dim]Syncing...[/]")
    if not dry_run:
        os.sync()
    flushcaches()

    readloop(block, blocksize, devsize, "00", logfile)

    logging(logfile, "Single-pass null and verify completed. Drive is clear.")

def rootcheck():
    '''
    make sure we are running as root
    '''
    if os.getuid() != 0:
        console.print("[bold red]Error: This program must be run as root. Exiting.[/]")
        sys.exit(1)

def cleanup():
    '''
    Ensure terminal is restored on any exit path.
    Rich handles cursor management during Progress blocks,
    but we restore it explicitly here as a final safety net.
    '''
    # Raw escape intentional here — runs outside any rich context on exit
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()


def prettyheader(devname, devsize, blocksize, logfile):
    '''
    Styled startup banner using rich Panel and Table.
    '''
    owl = Text()
    owl.append("   , _ ,\n", style="bold yellow")
    owl.append("  ( o o )\n", style="bold yellow")
    owl.append(" /'` ' `'\\\n", style="bold yellow")
    owl.append(" |'''''''|\n", style="bold yellow")
    owl.append(" |\\'''//|\n\n", style="bold yellow")
    owl.append("O.W.L.", style="bold white")
    owl.append(" — Optimized Wipe and Logging\n", style="white")
    owl.append("Forensic Media Sterilization Utility", style="dim")

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan", justify="right")
    info.add_column(style="white")
    info.add_row("Device:", devname)
    info.add_row("Size:", f"{devsize:,} bytes  ({devsize / 1024 / 1024 / 1024:.2f} GiB)")
    info.add_row("Block size:", f"{blocksize:,} bytes")

    console.print(Panel.fit(owl, border_style="yellow", padding=(0, 2)))
    console.print(info)
    console.print()

    logging(logfile, "=" * 80)
    logging(logfile, "O.W.L. - Optimized Wipe and Logging - Forensic Media Sterilization Utility")
    logging(logfile, f"Command: {' '.join(sys.argv)}")
    logging(logfile, f"Device: {devname}")
    logging(logfile, f"Device size: {devsize:,} bytes")
    logging(logfile, f"Block size set to {blocksize:,} bytes")


def confirm_wipe(devname, devsize, operation, logfile):
    '''
    Safety gate before any destructive operation.
    Displays a clear warning panel and requires the user to type the exact
    device path to proceed. Bails out on anything that doesn't match.
    '''
    size_gib = devsize / 1024 / 1024 / 1024

    warning = Text()
    warning.append("  ⚠  WARNING: DESTRUCTIVE OPERATION  ⚠\n\n", style="bold red")
    warning.append("Operation : ", style="bold white")
    warning.append(f"{operation}\n", style="bold yellow")
    warning.append("Device    : ", style="bold white")
    warning.append(f"{devname}\n", style="bold yellow")
    warning.append("Data size : ", style="bold white")
    warning.append(f"{devsize:,} bytes  ({size_gib:.2f} GiB)\n\n", style="bold yellow")
    warning.append("ALL DATA ON THIS DEVICE WILL BE PERMANENTLY DESTROYED.\n", style="bold red")
    warning.append("This action cannot be undone.", style="red")

    console.print(Panel(warning, border_style="bold red", padding=(1, 2)))
    console.print(f"[bold]To confirm, type the device path exactly:[/] ", end="")

    try:
        response = input()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[bold red]Aborted.[/]")
        logging(logfile, "Wipe confirmation aborted by user (EOF/interrupt).")
        sys.exit(1)

    if response.strip() != devname:
        console.print(
            f"\n[bold red]✗ Input did not match '{devname}'. Aborting.[/]\n"
        )
        logging(logfile, f"Wipe confirmation failed. User entered '{response.strip()}' "
            f"instead of '{devname}'. Aborting.")
        sys.exit(1)

    console.print(f"[bold green]✓ Confirmed. Starting {operation}...[/]\n")
    logging(logfile, f"Wipe confirmed by user. Starting {operation}.")


def list_devices():
    '''
    --list
    Enumerate all block devices visible to the system and print a rich table.
    Uses blkinfo as the primary source; falls back to parsing lsblk output
    if blkinfo raises or returns nothing.
    '''
    console.print()

    try:
        blk = BlkDiskInfo()
        disks = blk.get_disks()
    except Exception as exc:
        console.print(f"[yellow]blkinfo unavailable ({exc}), falling back to lsblk.[/]")
        disks = []

    if disks:
        table = Table(
            title="Available Block Devices",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
            show_lines=False,
        )
        table.add_column("Device",     style="bold white",  no_wrap=True)
        table.add_column("Model",      style="white")
        table.add_column("Vendor",     style="dim white")
        table.add_column("Serial",     style="dim white")
        table.add_column("Transport",  style="cyan",        no_wrap=True)
        table.add_column("Size",       style="green",       justify="right", no_wrap=True)
        table.add_column("Mounted",    style="yellow",      no_wrap=True)

        for disk in disks:
            devname   = f"/dev/{disk.get('name', '?')}"
            model     = str(disk.get('model',  '') or '').strip() or '—'
            vendor    = str(disk.get('vendor', '') or '').strip() or '—'
            serial    = str(disk.get('serial', '') or '').strip() or '—'
            transport = str(disk.get('tran',   '') or '').strip() or '—'

            # size: blkinfo gives bytes as a string in 'size'
            try:
                size_bytes = int(disk.get('size', 0))
                size_gib   = size_bytes / 1024 / 1024 / 1024
                size_str   = f"{size_gib:.1f} GiB"
            except (ValueError, TypeError):
                size_str = str(disk.get('size', '—'))

            # mount status: walk children for any mounted partition
            mounts = _collect_mounts(disk)
            if mounts:
                mounted_str = "[bold red]YES[/]"
            else:
                mounted_str = "[green]no[/]"

            table.add_row(devname, model, vendor, serial, transport, size_str, mounted_str)

        console.print(table)

    else:
        # blkinfo fallback — parse lsblk -d -o NAME,MODEL,SERIAL,TRAN,SIZE,TYPE
        lsblk_out = command_line(
            ['lsblk', '-d', '-o', 'NAME,MODEL,SERIAL,TRAN,SIZE,TYPE,MOUNTPOINT'],
            cmdtimeout=5
        )
        if not lsblk_out:
            console.print("[bold red]Could not enumerate block devices. "
                "Is lsblk available?[/]")
            return

        lines = lsblk_out.decode(errors='replace').splitlines()

        table = Table(
            title="Available Block Devices",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
        )
        # Parse the header row to build columns dynamically
        if lines:
            for col in lines[0].split():
                table.add_column(col, style="white", no_wrap=True)
            for line in lines[1:]:
                parts = line.split()
                # colour the NAME column bold, flag mounted devices
                if parts:
                    parts[0] = f"[bold]/dev/{parts[0]}[/]"
                table.add_row(*parts)

        console.print(table)

    console.print()
    console.print("[dim]Devices marked [bold yellow]Mounted: YES[/] have active partitions "
        "— OWL will refuse to wipe them.[/]")
    console.print()


def _collect_mounts(node):
    '''
    Recursively walk a blkinfo disk dict and collect all non-empty mountpoints.
    '''
    mounts = []
    for key, value in node.items():
        if key == 'mountpoint' and value:
            mounts.append(value)
        elif key == 'children' and isinstance(value, list):
            for child in value:
                mounts.extend(_collect_mounts(child))
        elif isinstance(value, dict):
            mounts.extend(_collect_mounts(value))
    return mounts


def parse_arguments():
    '''
    handle command line args
    '''
    arghelpdesc = ("Health check, sterilization, verification, and logging for"
        " data storage devices.")
    parser = argparse.ArgumentParser(description=arghelpdesc)
    parser.add_argument("target", help="Path to block device", nargs="?", default=None)
    parser.add_argument("-f", "--full",
        help="Full double wipe and verify [default]",
        action="store_true")
    parser.add_argument("-s", "--smart", help="Perform smart wipe",
        action="store_true")
    parser.add_argument("-z", "--zero", help="Single pass of null bytes",
        action="store_true")
    parser.add_argument("-c", "--check", help="verify media contains only nulls",
        action="store_true")
    parser.add_argument("-l", "--logfile", help="write/append info to log file")
    parser.add_argument("-b", "--blocksize",
        help="override default working blocksize")
    parser.add_argument("--ataerase", help="Perform ATA Erase",
        action="store_true")
    parser.add_argument("--atasecure", help="Perform ATA Secure Erase",
        action="store_true")
    parser.add_argument("--dry-run", help="Simulate wipe without writing any data",
        action="store_true", dest="dry_run")
    parser.add_argument("--list", help="List available block devices and exit",
        action="store_true")
    parser.add_argument("--report", help="Write a wipe certificate to this file path "
        "(auto-named if path is a directory or omitted with this flag)",
        metavar="PATH", default=None)
    parser.add_argument("--operator", help="Name of the operator performing the wipe "
        "(recorded in the certificate, requires --report)",
        metavar="NAME", default=None)

    return parser.parse_args()

def logging(logfile, message):
    '''
    optional logging to file
    '''
    if logfile is None:
        return
    with open(logfile, "a", encoding="ascii") as log:
        timestamp = datetime.datetime.now().isoformat()
        log.write(f"{timestamp} {message}\n")

def diskinfo(devname, logfile):
    '''
    get additional info about the target drive.
    Gracefully handles devices not recognized by blkinfo (e.g. unusual
    block device paths) rather than crashing with an IndexError.
    Returns a dict of disk fields, or an empty dict if info is unavailable.
    '''
    try:
        blk = BlkDiskInfo()
        filters = { 'name' : devname[5:] } # trim /dev/ to make shortname 'sdx'
        disks = blk.get_disks(filters)
        if not disks:
            console.print("[yellow]Warning: Device not found in block device list "
                "(blkinfo). Skipping disk info.[/]")
            logging(logfile, "Warning: Device not recognized by blkinfo - disk info skipped.")
            return {}
        blkdata = disks[0]
    except Exception as exc:
        console.print(f"[yellow]Warning: Could not retrieve disk info: {exc}[/]")
        logging(logfile, f"Warning: Could not retrieve disk info: {exc}")
        return {}

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan", justify="right")
    info.add_column(style="white")
    info.add_row("Model:", str(blkdata['model']))
    info.add_row("Vendor:", str(blkdata['vendor']))
    info.add_row("Serial:", str(blkdata['serial']))
    info.add_row("Transport:", str(blkdata['tran']))
    console.print(info)

    logging(logfile, f"Model: {blkdata['model']}")
    logging(logfile, f"Vendor: {blkdata['vendor']}")
    logging(logfile, f"Serial: {blkdata['serial']}")
    logging(logfile, f"Transport: {blkdata['tran']}")

    if mountcheck(blkdata, logfile, 0) > 0:
        console.print("[bold red]Device has mounted partitions. Exiting.[/]")
        logging(logfile, "Exiting.")
        sys.exit()

    return blkdata

def mountcheck(blkdata, logfile, mountct):
    '''
    check if anything is mounted on this device by walking the block device dict
    this returns the count of mounts - anything greater than 0 triggers an exit.
    '''
    # recursively walk the device dict looking for mountpoints
    for key, value in blkdata.items():
        if isinstance(value, dict):
            mountct=mountcheck(value, logfile, mountct)
        elif key == 'children':
            for child in value:
                mountct=mountcheck(child, logfile, mountct)
        elif key == 'mountpoint' and value != '':
            console.print(f"[bold red]⚠ Device has a partition mounted at {value}[/]")
            logging(logfile, f"Device has a partition mounted at {value}")
            mountct += 1
    return mountct

def main():
    '''
    Entry point. Parses arguments, opens the device, and dispatches to the
    appropriate wipe/check function.
    '''
    args = parse_arguments()

    # --list needs no target and no root — handle and exit immediately
    if args.list:
        list_devices()
        sys.exit(0)

    # All other operations require a target device
    if args.target is None:
        console.print("[bold red]ERROR: A target device is required. "
            "Use --list to see available devices.[/]")
        sys.exit(1)

    devname = os.path.abspath(args.target)
    if not os.path.exists(devname):
        console.print(f"[bold red]ERROR: Target device {devname} not found. "
            "Use --list to see available devices.[/]")
        sys.exit(1)

    logfile = args.logfile  # None if not provided by user
    dry_run = args.dry_run

    # Determine operation label early for the record
    if args.check:
        operation = "Drive Map / Null Check (read-only)"
    elif args.smart:
        operation = "Smart Wipe (selective null overwrite)"
    elif args.zero:
        operation = "Single-Pass Zero + Verify"
    elif args.full:
        operation = "Full Double Wipe + Verify (FF then 00)"
    elif args.atasecure:
        operation = "ATA Secure Erase (Enhanced)"
    elif args.ataerase:
        operation = "ATA Erase"
    else:
        operation = "Full Double Wipe + Verify (FF then 00) [default]"

    record = WipeRecord(
        operation=operation,
        dry_run=dry_run,
        command=' '.join(sys.argv),
        device_path=devname,
        operator_name=args.operator or "",
    )

    if args.operator and args.report is None:
        console.print("[yellow]⚠ --operator was specified but --report was not. "
            "The operator name will not be saved unless --report is also used.[/]")

    atexit.register(cleanup)
    rootcheck()

    # In dry-run mode open read-only — we will never write to the device
    open_flags = os.O_RDONLY if dry_run else os.O_RDWR | os.O_SYNC
    try:
        block = os.open(devname, open_flags)
    except PermissionError:
        console.print(f"[bold red]ERROR: Permission denied opening {devname}. "
            "Are you running as root?[/]")
        logging(logfile, f"ERROR: Permission denied opening {devname}.")
        sys.exit(1)
    except OSError as exc:
        console.print(f"[bold red]ERROR: Could not open {devname}: {exc}[/]")
        logging(logfile, f"ERROR: Could not open {devname}: {exc}")
        sys.exit(1)

    devsize = os.lseek(block, 0, os.SEEK_END)
    os.lseek(block, 0, os.SEEK_SET)
    record.device_size = devsize

    if args.blocksize:
        try:
            blocksize = int(args.blocksize)
            if blocksize <= 0:
                raise ValueError
        except ValueError:
            console.print("[bold red]ERROR: --blocksize must be a positive integer.[/]")
            sys.exit(1)
    else:
        blocksize = 4096 * 256  # default 1MB

    record.block_size = blocksize

    prettyheader(devname, devsize, blocksize, logfile)

    if dry_run:
        console.print(Panel(
            "[bold yellow]DRY RUN MODE[/] — Device will be read but [bold]never written to.[/]\n"
            "Progress bars show estimated timing. Verification passes use real reads.",
            border_style="yellow", padding=(0, 2)
        ))
        console.print()
        logging(logfile, "DRY RUN mode active — no writes will occur.")

    blkdata = diskinfo(devname, logfile)
    if blkdata:
        record.model     = str(blkdata.get('model',  '') or '—').strip()
        record.vendor    = str(blkdata.get('vendor', '') or '—').strip()
        record.serial    = str(blkdata.get('serial', '') or '—').strip()
        record.transport = str(blkdata.get('tran',   '') or '—').strip()

    if args.check:
        drivemap(block, blocksize, devsize, logfile)
        record.success = True
        record.notes   = "Read-only check. No data was written."
    elif args.smart:
        if not dry_run:
            confirm_wipe(devname, devsize, operation, logfile)
        checkblock(block, blocksize, devsize, logfile, dry_run)
        record.success = True
    elif args.zero:
        if not dry_run:
            confirm_wipe(devname, devsize, operation, logfile)
        singlepass(block, blocksize, devsize, logfile, dry_run)
        record.success = True
    elif args.full:
        if not dry_run:
            confirm_wipe(devname, devsize, operation, logfile)
        fulltest(block, blocksize, devsize, logfile, dry_run)
        record.success = True
    elif args.atasecure:
        if dry_run:
            console.print("[yellow]⚠ --dry-run has no effect with --atasecure "
                "(ATA commands are issued by hdparm, not OWL). Skipping.[/]")
        else:
            confirm_wipe(devname, devsize, operation, logfile)
            atasecure(devname, logfile)
            record.success = True
    elif args.ataerase:
        if dry_run:
            console.print("[yellow]⚠ --dry-run has no effect with --ataerase "
                "(ATA commands are issued by hdparm, not OWL). Skipping.[/]")
        else:
            confirm_wipe(devname, devsize, operation, logfile)
            ataerase(devname, logfile)
            record.success = True
    else:
        if not dry_run:
            confirm_wipe(devname, devsize, operation, logfile)
        fulltest(block, blocksize, devsize, logfile, dry_run)
        record.success = True

    record.end_time = datetime.datetime.now().isoformat(timespec='seconds')

    # Generate certificate if --report was requested
    if args.report is not None:
        report_path = args.report
        # If the user gave a directory, auto-name the file inside it
        if os.path.isdir(report_path):
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            devshort = devname.replace('/', '_').strip('_')
            report_path = os.path.join(report_path, f"owl_cert_{devshort}_{ts}.txt")
        generate_certificate(record, report_path, logfile)

    logging(logfile, "Exited")

if __name__ == "__main__":
    main()
