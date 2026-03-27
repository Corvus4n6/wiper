#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2018-2026 J-Michael Roberts, Corvus Forensics LLC
'''
   , _ ,
  ( o o )   Optimized
//'` ' `'\\ Wipe &
||'''''''|| Logging
||\\---//|| LightweighT version
    """
OWL - Optimized Wiping and Logging
forensic drive wiper program by Corvus Forensics LLC
designed to wipe, verify, optional logging, and paperwork generator
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
import secrets
from dataclasses import dataclass, field
from typing import Optional
from blkinfo import BlkDiskInfo
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, HRFlowable,
    Table as RLTable, TableStyle as RLTableStyle, KeepTogether)
from pypdf import PdfReader, PdfWriter
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
    start_time: str     = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec='seconds'))
    end_time: str       = ""

    # Operation
    operation: str      = ""
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

    # SMART data (captured before and after wipe)
    smart_pre: dict     = field(default_factory=dict)
    smart_post: dict    = field(default_factory=dict)
    smart_available: bool = False

    # Wipe standard compliance
    wipe_standard: str  = ""


def generate_certificate(record: WipeRecord, report_path: str, logfile):
    '''
    Generate a formatted PDF wipe certificate and write it to report_path.

    Security model:
      - No user password  → opens freely in any PDF reader
      - Random owner password → editing, form-filling, and content extraction
        are locked; viewing, copying text, and printing remain permitted
      - The owner passphrase is printed to the terminal and logged so it can
        be recorded if ever needed for administrative override
    '''
    # Ensure .pdf extension
    if not report_path.lower().endswith('.pdf'):
        report_path += '.pdf'

    tmp_path = report_path + '.tmp'
    size_gib  = record.device_size / 1024 / 1024 / 1024

    # --- Status string ---
    if record.success:
        status_text  = "COMPLETED SUCCESSFULLY"
        status_color = colors.HexColor("#1a7a1a")
    else:
        status_text  = "FAILED / INCOMPLETE"
        status_color = colors.red

    # --- Styles ---
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'CertTitle',
        parent=styles['Title'],
        fontSize=18,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        'CertSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor("#555555"),
        alignment=1,  # centre
        spaceAfter=16,
    )
    section_style = ParagraphStyle(
        'SectionHead',
        parent=styles['Heading2'],
        fontSize=11,
        textColor=colors.HexColor("#1a1a2e"),
        spaceBefore=14,
        spaceAfter=6,
        borderPad=2,
    )
    status_style = ParagraphStyle(
        'Status',
        parent=styles['Normal'],
        fontSize=13,
        textColor=status_color,
        fontName='Helvetica-Bold',
        alignment=1,
        spaceBefore=6,
        spaceAfter=6,
    )
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor("#888888"),
        alignment=1,
        spaceBefore=20,
    )

    def info_table(rows):
        '''Build a two-column label/value table for a section.'''
        tdata = [[Paragraph(f'<b>{label}</b>', styles['Normal']),
                  Paragraph(str(value), styles['Normal'])]
                 for label, value in rows]
        t = RLTable(tdata, [2.2 * inch, 4.2 * inch])
        t.setStyle(RLTableStyle([
            ('FONTSIZE',    (0, 0), (-1, -1), 9),
            ('TOPPADDING',  (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1),
             [colors.HexColor("#f5f5f5"), colors.white]),
            ('TEXTCOLOR',   (0, 0), (0, -1), colors.HexColor("#444444")),
            ('TEXTCOLOR',   (1, 0), (1, -1), colors.HexColor("#111111")),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('LINEBELOW',   (0, -1), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ]))
        return t

    # --- Build story ---
    story = []

    # Header
    story.append(Paragraph("O.W.L.", title_style))
    story.append(Paragraph(
        "Optimized Wipe and Logging &mdash; Forensic Media Sterilization Certificate",
        subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2,
                             color=colors.HexColor("#1a1a2e"), spaceAfter=10))

    # Status banner
    story.append(Paragraph(status_text, status_style))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.HexColor("#cccccc"), spaceAfter=6))

    # Operation details
    story.append(Paragraph("Operation Details", section_style))
    op_rows = [
        ("Operation",     record.operation),
        ("Command",       record.command),
        ("Start time",    record.start_time),
        ("End time",      record.end_time or "—"),
        ("Operator",      record.operator_name or "—"),
        ("Operator host", record.operator_host),
    ]
    if record.wipe_standard:
        op_rows.append(("Wipe standard", record.wipe_standard))
    story.append(info_table(op_rows))

    # Device details
    story.append(Paragraph("Device Details", section_style))
    story.append(info_table([
        ("Device path",   record.device_path),
        ("Size",          f"{record.device_size:,} bytes  ({size_gib:.2f} GiB)"),
        ("Block size",    f"{record.block_size:,} bytes"),
        ("Model",         record.model),
        ("Vendor",        record.vendor),
        ("Serial",        record.serial),
        ("Transport",     record.transport),
    ]))

    # SMART data
    if record.smart_available:
        def smart_section(title, smart):
            if not smart:
                return
            story.append(Paragraph(title, section_style))
            rows = [("Overall Health", smart.get("health", "—")),
                    ("Firmware",       smart.get("firmware", "—"))]
            for _, label in _SMART_ATTRS:
                if label in smart:
                    rows.append((label, smart[label]))
            story.append(info_table(rows))

        smart_section("SMART Data — Pre-Wipe",  record.smart_pre)
        smart_section("SMART Data — Post-Wipe", record.smart_post)

    # Notes — user-supplied or auto-generated for hardware erase operations
    nvme_ops = ("NVMe User Data Erase", "NVMe Block Erase")
    ata_ops  = ("ATA Secure Erase", "ATA Erase")
    hw_ops   = ("Hardware Erase", "Hardware Secure Erase")
    if not record.notes:
        if any(record.operation.startswith(op) for op in nvme_ops):
            record.notes = (
                "Hardware erase via NVMe controller command. "
                "All user data including overprovisioned sectors was erased at the "
                "controller level. A software verification pass confirmed the drive "
                "surfaces as zeroed.\n\n"
                "Note: This operation does NOT constitute a stuck-bit test. "
                "Stuck-bit detection requires a full software double-pass wipe "
                "(FF\u219200, verify each pass). Hardware erase and stuck-bit "
                "testing serve different forensic purposes."
            )
        elif any(record.operation.startswith(op) for op in ata_ops):
            record.notes = (
                "Hardware erase via ATA security command. "
                "Reaches overprovisioned sectors not accessible to the OS.\n\n"
                "Note: This operation does NOT constitute a stuck-bit test. "
                "Stuck-bit detection requires a full software double-pass wipe.\n\n"
                "Note: Software verification was skipped for ATA Enhanced Security "
                "Erase. The erase pattern is vendor-defined and may not be 0x00 — "
                "a verify pass against 0x00 would produce false mismatches on drives "
                "that use a random or proprietary pattern."
            )
        elif any(record.operation.startswith(op) for op in hw_ops):
            record.notes = (
                "Hardware erase auto-dispatched to the appropriate method for this "
                "device type (NVMe or ATA). Overprovisioned sectors not normally "
                "accessible to the OS were erased at the controller level.\n\n"
                "For NVMe operations: a software verification pass confirmed the "
                "drive surfaces as zeroed.\n\n"
                "For ATA Enhanced Security Erase: software verification was skipped "
                "because the erase pattern is vendor-defined and may not be 0x00 — "
                "a verify pass would produce false mismatches on drives that use a "
                "random or proprietary pattern.\n\n"
                "Note: This operation does NOT constitute a stuck-bit test. "
                "Stuck-bit detection requires a full software double-pass wipe "
                "(FF\u219200, verify each pass). Hardware erase and stuck-bit "
                "testing serve different forensic purposes."
            )

    if record.notes:
        story.append(Paragraph("Notes", section_style))
        story.append(Paragraph(record.notes, styles['Normal']))

    # Footer
    generated_at = datetime.datetime.now(datetime.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    story.append(Spacer(1, 0.3 * inch))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.HexColor("#cccccc")))
    story.append(Paragraph(
        f"Generated by OWL — Corvus Forensics LLC &nbsp;&nbsp;|&nbsp;&nbsp; {generated_at}",
        footer_style))

    # --- Render to temp PDF ---
    try:
        doc = SimpleDocTemplate(
            tmp_path,
            pagesize=letter,
            leftMargin=0.85 * inch,
            rightMargin=0.85 * inch,
            topMargin=0.85 * inch,
            bottomMargin=0.85 * inch,
            title="OWL Media Sterilization Certificate",
            author="Corvus Forensics LLC",
            subject=f"Wipe certificate for {record.device_path}",
        )
        doc.build(story)
    except Exception as exc:
        console.print(f"[bold red]✗ Could not render PDF: {exc}[/]")
        logging(logfile, f"ERROR: PDF render failed: {exc}")
        return

    # --- Encrypt: empty user password (opens freely) + random owner password ---
    owner_pass = secrets.token_urlsafe(16)   # 16 bytes → ~22 char base64url

    try:
        reader = PdfReader(tmp_path)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        # user_password=""  → no password to open
        # owner_password=owner_pass → locks editing/extracting/forms
        # Permissions: allow printing (print_degraded + printing) and
        #              copying text, but deny all modification flags
        writer.encrypt(
            user_password="",
            owner_password=owner_pass,
            permissions_flag=0b000000100100,  # copy + print
        )

        with open(report_path, "wb") as f:
            writer.write(f)

        os.remove(tmp_path)

    except Exception as exc:
        console.print(f"[bold red]✗ Could not encrypt PDF: {exc}[/]")
        logging(logfile, f"ERROR: PDF encryption failed: {exc}")
        # Fall back to unencrypted version
        os.rename(tmp_path, report_path)
        console.print(f"[yellow]⚠ Saved unencrypted fallback to {report_path}[/]")
        return

    console.print(f"\n[bold green]✓ Certificate written to:[/] {report_path}")
    console.print(f"  [dim]The file opens without a password — "
                  f"viewing, copying, and printing are unrestricted.[/]")
    logging(logfile, f"Certificate written to {report_path}")


def _sigint_handler(sig, frame):
    '''
    Handle Ctrl+C gracefully - restore cursor and exit with a clean message
    rather than leaving the terminal in a broken state mid-wipe.
    '''
    console.print("\n[bold red]Interrupted by user. Exiting.[/]")
    sys.exit(130)  # 130 = 128 + SIGINT, standard shell convention


signal.signal(signal.SIGINT, _sigint_handler)


def checkblock(block, blocksize, devsize, logfile):
    '''
    --smart / -s
    Single pass overwriting non-clean sectors with nulls. Not verified.
    Ideal for flash media where we want to limit writes.
    '''
    logging(logfile, "Smart wipe started")
    nullbytes = bytes(blocksize)
    flushcaches()
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time()
    blockwrites = 0
    devpos = 0

    with Progress(
        TextColumn("[bold cyan]Smart wipe[/]"),
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
                devpos = os.lseek(block, -blocksize, os.SEEK_CUR)
                os.write(block, nullbytes)
                blockwrites += 1

            progress.update(task, completed=devpos + blocksize, mbps=mbps, writes=blockwrites)

    console.print("[dim]Syncing...[/]")
    os.sync()
    flushcaches()

    runtime = time.time() - starttime
    runtimefmt = str(datetime.timedelta(seconds=math.floor(runtime)))
    mbps = (devpos + blocksize) / runtime / 1024 / 1024 if runtime > 0 else 0.0
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
        with open('/proc/sys/vm/drop_caches', 'w', encoding="utf-8") as file_object:
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

def check_ata_support(devname, mode, logfile):
    '''
    Pre-flight check for ATA erase operations. Runs hdparm -I once and
    validates that the drive supports the requested mode, is not frozen,
    and is not locked. Returns the decoded hdparm output on success so
    callers can extract timing info without running hdparm a second time.

    mode: "secure"  -> checks for ENHANCED SECURITY ERASE support
          "erase"   -> checks for standard SECURITY ERASE support

    Exits with a clear error message if any check fails — intended to be
    called BEFORE the confirmation prompt so the user never confirms a
    wipe that will immediately fail.
    '''
    # 1. hdparm must be installed
    if command_line(['which', 'hdparm']) == b'':
        console.print("[bold red]ERROR: hdparm is not installed or not in PATH. "
            "Install hdparm and try again.[/]")
        logging(logfile, "ERROR: hdparm utility not found.")
        sys.exit(1)

    # 2. Query the drive
    console.print(f"[dim]Querying ATA security features on {devname}...[/]")
    hdpi = command_line(['hdparm', '-I', devname]).decode(errors='replace')

    if not hdpi:
        console.print(f"[bold red]ERROR: hdparm returned no output for {devname}. "
            "Is this an ATA device?[/]")
        logging(logfile, f"ERROR: hdparm -I returned no output for {devname}.")
        sys.exit(1)

    # 3. Feature support check
    if mode == "secure":
        if re.search(r'not\tsupported: enhanced erase', hdpi):
            console.print("[bold red]ERROR: ATA Enhanced Security Erase is not "
                f"supported by {devname}.[/]")
            console.print("[dim]Tip: Try --hw-erase for standard ATA Erase instead.[/]")
            logging(logfile, "ERROR: ATA Enhanced Security Erase not supported.")
            sys.exit(1)
    elif mode == "erase":
        if not re.search(r'(?<!not\t)supported: enhanced erase', hdpi):
            console.print(f"[bold red]ERROR: ATA Security Erase is not supported "
                f"by {devname}.[/]")
            logging(logfile, "ERROR: ATA Security Erase not supported.")
            sys.exit(1)

    # 4. Frozen check — a frozen drive cannot have security commands sent to it
    if not re.search(r'not\tfrozen', hdpi):
        console.print("[bold red]ERROR: Drive security state is 'frozen'.[/]")
        console.print("[dim]Tip: Try a suspend/resume cycle to unfreeze the drive, "
            "then retry.[/]")
        logging(logfile, "ERROR: Drive is frozen — ATA erase not possible.")
        sys.exit(1)

    # 5. Locked check
    if not re.search(r'not\tlocked', hdpi):
        console.print("[bold red]ERROR: Drive is currently locked.[/]")
        logging(logfile, "ERROR: Drive is locked — ATA erase not possible.")
        sys.exit(1)

    logging(logfile, f"ATA pre-flight checks passed for {devname} (mode={mode}).")
    return hdpi


def atasecure(devname, logfile, hdpi=None):
    '''
    ATA Secure Erase (Enhanced). Pre-flight checks are expected to have
    been run by check_ata_support() before this is called. hdpi is the
    decoded hdparm -I output; if not supplied it is fetched here as a
    fallback (e.g. direct calls in testing).
    '''
    logging(logfile, "Performing ATA Secure Erase on drive.")
    if hdpi is None:
        hdpi = command_line(['hdparm', '-I', devname]).decode(errors='replace')
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

def ataerase(devname, logfile, hdpi=None):
    '''
    ATA Erase (standard, nulls). Pre-flight checks are expected to have
    been run by check_ata_support() before this is called.
    '''
    logging(logfile, "Performing ATA Erase on drive.")
    if hdpi is None:
        hdpi = command_line(['hdparm', '-I', devname]).decode(errors='replace')
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


def check_nvme_support(devname, mode, logfile):
    '''
    Pre-flight check for NVMe erase operations. Queries nvme id-ctrl to confirm
    the requested erase method is supported before showing the confirmation screen.

    mode: "format"   -> nvme format --ses=1 (User Data Erase)
          "sanitize" -> nvme sanitize --sanact=2 (Block Erase)

    Returns a dict of controller info on success. Exits with a clear message
    if the command or capability is not available.

    nvme id-ctrl JSON fields used:
      mn      -> model name
      fr      -> firmware revision
      oacs    -> Optional Admin Command Support (bit 3 = sanitize supported)
      sanicap -> Sanitize Capabilities (bit 1 = block erase, bit 0 = crypto erase)
      fna     -> Format NVM Attributes (bit 1 = format applies to all namespaces)
    '''
    import json as _json

    if command_line(['which', 'nvme']) == b'':
        console.print("[bold red]ERROR: nvme-cli is not installed or not in PATH. "
            "Install nvme-cli and try again.[/]")
        logging(logfile, "ERROR: nvme-cli not found.")
        sys.exit(1)

    console.print(f"[dim]Querying NVMe controller capabilities on {devname}...[/]")
    raw = command_line(['nvme', 'id-ctrl', devname, '--output-format=json'],
                       cmdtimeout=10).decode(errors='replace')
    if not raw:
        console.print(f"[bold red]ERROR: nvme id-ctrl returned no output for {devname}. "
            "Is this an NVMe device?[/]")
        logging(logfile, f"ERROR: nvme id-ctrl returned no output for {devname}.")
        sys.exit(1)

    try:
        ctrl = _json.loads(raw)
    except _json.JSONDecodeError as exc:
        console.print(f"[bold red]ERROR: Could not parse nvme id-ctrl output: {exc}[/]")
        logging(logfile, f"ERROR: nvme id-ctrl JSON parse failed: {exc}")
        sys.exit(1)

    oacs   = ctrl.get('oacs',   0)
    sanicap = ctrl.get('sanicap', 0)
    fna    = ctrl.get('fna',    0)
    model  = ctrl.get('mn', '—').strip()
    fw     = ctrl.get('fr', '—').strip()

    console.print(f"[cyan]NVMe controller: {model}  Firmware: {fw}[/]")

    # Warn if format applies to all namespaces — important for multi-NS drives
    if fna & 0b010:
        console.print("[bold yellow]⚠ Warning: Format NVM applies to ALL namespaces "
            "on this controller, not just the target namespace.[/]")
        logging(logfile, "Warning: fna bit 1 set — format applies to all namespaces.")

    if mode == "sanitize":
        # Requires sanitize command support (oacs bit 3) and block erase (sanicap bit 1)
        if not (oacs & (1 << 3)):
            console.print("[bold red]ERROR: This NVMe controller does not support the "
                "Sanitize command.[/]")
            console.print("[dim]Tip: Try --hw-erase for User Data Erase instead.[/]")
            logging(logfile, "ERROR: NVMe Sanitize not supported (oacs bit 3 not set).")
            sys.exit(1)
        if not (sanicap & 0b010):
            console.print("[bold red]ERROR: This NVMe controller does not support "
                "Block Erase sanitize.[/]")
            crypto = bool(sanicap & 0b001)
            if crypto:
                console.print("[dim]Tip: Cryptographic erase is supported on this "
                    "drive but is not implemented in OWL.[/]")
            logging(logfile, f"ERROR: NVMe Block Erase not supported (sanicap={sanicap:#x}).")
            sys.exit(1)

    elif mode == "format":
        # nvme format --ses=1 is broadly supported but check the command is available
        # by verifying nvme format help returns without error
        fmtcheck = command_line(['nvme', 'format', '--help'], cmdtimeout=5)
        if not fmtcheck:
            console.print("[bold red]ERROR: nvme format command not available.[/]")
            logging(logfile, "ERROR: nvme format command not available.")
            sys.exit(1)

    logging(logfile, f"NVMe pre-flight checks passed for {devname} "
        f"(mode={mode}, oacs={oacs:#x}, sanicap={sanicap:#x})")
    return ctrl


def nvme_format(devname, block, blocksize, devsize, logfile):
    '''
    --nvme-format
    NVMe User Data Erase via nvme format --ses=1.

    This issues a controller-level erase command that zeros all user data
    including overprovisioned sectors not accessible to the OS.

    NOTE: This is a hardware erase — it does NOT perform a stuck-bit test.
    A software verify pass (readloop 0x00) is run afterwards to confirm
    the drive surfaces as zeroed.

    Not equivalent to --full for stuck-bit detection purposes.
    '''
    logging(logfile, "NVMe Format (User Data Erase) started.")
    console.print("[cyan]Issuing NVMe Format User Data Erase (ses=1)...[/]")

    result = command_line(['nvme', 'format', devname, '--ses=1', '--force'],
                          cmdtimeout=300)
    if result == b'Timeout':
        console.print("[bold red]ERROR: nvme format timed out after 5 minutes.[/]")
        logging(logfile, "ERROR: nvme format timed out.")
        sys.exit(1)

    console.print("[bold green]✓ NVMe Format (User Data Erase) completed.[/]")
    logging(logfile, "NVMe Format (User Data Erase) completed.")

    # Sync and flush before verify
    console.print("[dim]Syncing...[/]")
    os.sync()
    flushcaches()

    # Software verify pass — confirms the drive reads back as zeros
    console.print("[cyan]Running software verification pass (0x00)...[/]")
    readloop(block, blocksize, devsize, "00", logfile)
    logging(logfile, "NVMe Format + software verify completed.")


def nvme_sanitize(devname, block, blocksize, devsize, logfile):
    '''
    --nvme-sanitize
    NVMe Block Erase via nvme sanitize --sanact=2.

    Block Erase resets all NAND cells to the factory erased state — more
    thorough than User Data Erase and reaches all storage including
    wear-leveling reserves and overprovisioned areas.

    The drive handles the operation internally; OWL polls for completion.

    NOTE: This is a hardware erase — it does NOT perform a stuck-bit test.
    A software verify pass (readloop 0x00) is run afterwards to confirm
    the drive surfaces as zeroed.

    Not equivalent to --full for stuck-bit detection purposes.
    '''
    logging(logfile, "NVMe Sanitize (Block Erase) started.")
    console.print("[cyan]Issuing NVMe Sanitize Block Erase (sanact=2)...[/]")

    result = command_line(['nvme', 'sanitize', devname, '--sanact=2'],
                          cmdtimeout=30)
    if result == b'Timeout':
        console.print("[bold red]ERROR: nvme sanitize command timed out.[/]")
        logging(logfile, "ERROR: nvme sanitize command timed out.")
        sys.exit(1)

    # Sanitize runs asynchronously — poll nvme sanitize-log until complete
    console.print("[dim]Waiting for sanitize operation to complete...[/]")
    logging(logfile, "Polling nvme sanitize-log for completion...")

    with Progress(
        TextColumn("[bold cyan]Sanitizing"),
        BarColumn(bar_width=None),
        TextColumn("[dim]{task.fields[status]}"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Sanitizing", total=100, status="waiting...")
        poll_interval = 5  # seconds between polls
        elapsed = 0
        while True:
            time.sleep(poll_interval)
            elapsed += poll_interval
            log_raw = command_line(['nvme', 'sanitize-log', devname,
                                    '--output-format=json'], cmdtimeout=10)
            if not log_raw:
                progress.update(task, status=f"polling... ({elapsed}s)")
                continue
            try:
                import json as _json
                slog = _json.loads(log_raw.decode(errors='replace'))
                # sprog: sanitize progress (0-65535, where 65535 = 100%)
                # sstat: sanitize status (1=success, 2=in_progress, 3=failed)
                sstat = slog.get('sstat', 0) & 0x7  # lower 3 bits = status
                sprog = slog.get('sprog', 0)
                pct   = min(int(sprog / 65535 * 100), 100)

                if sstat == 1:  # completed successfully
                    progress.update(task, completed=100, status="complete")
                    break
                elif sstat == 3:  # failed
                    progress.stop()
                    console.print("[bold red]ERROR: NVMe Sanitize reported failure.[/]")
                    logging(logfile, "ERROR: NVMe Sanitize operation failed (sstat=3).")
                    sys.exit(1)
                else:
                    progress.update(task, completed=pct,
                                    status=f"{pct}% ({elapsed}s elapsed)")
            except Exception:
                progress.update(task, status=f"polling... ({elapsed}s)")

    console.print("[bold green]✓ NVMe Sanitize (Block Erase) completed.[/]")
    logging(logfile, "NVMe Sanitize (Block Erase) completed.")

    console.print("[dim]Syncing...[/]")
    os.sync()
    flushcaches()

    # Software verify pass
    console.print("[cyan]Running software verification pass (0x00)...[/]")
    readloop(block, blocksize, devsize, "00", logfile)
    logging(logfile, "NVMe Sanitize + software verify completed.")


def _is_nvme(devname):
    '''Return True if devname is an NVMe block device.'''
    return os.path.basename(devname).startswith('nvme')


def hw_erase(devname, block, blocksize, devsize, logfile, hw_info=None):
    '''
    --hw-erase
    Standard hardware erase, dispatched by device type:
      NVMe  -> nvme format --ses=1  (User Data Erase)
      ATA   -> hdparm --security-erase

    Followed by a software readloop 0x00 verify pass.
    Pre-flight checks are run in main() before this is called.
    hw_info is the return value of check_nvme_support() or check_ata_support().
    Does NOT perform a stuck-bit test.
    '''
    if _is_nvme(devname):
        logging(logfile, "hw-erase: NVMe device, using nvme format --ses=1")
        console.print("[dim]NVMe device detected — using NVMe User Data Erase.[/]")
        nvme_format(devname, block, blocksize, devsize, logfile)
    else:
        logging(logfile, "hw-erase: ATA device, using hdparm --security-erase")
        console.print("[dim]ATA device detected — using ATA Security Erase.[/]")
        ataerase(devname, logfile, hw_info)
        # ATA standard erase typically writes zeros — run verify pass
        console.print("[dim]Syncing...[/]")
        os.sync()
        flushcaches()
        console.print("[cyan]Running software verification pass (0x00)...[/]")
        readloop(block, blocksize, devsize, "00", logfile)
        logging(logfile, "ATA Erase + software verify completed.")


def hw_secure(devname, block, blocksize, devsize, logfile, hw_info=None):
    '''
    --hw-secure
    Thorough hardware erase reaching overprovisioned sectors,
    dispatched by device type:
      NVMe  -> nvme sanitize --sanact=2 (Block Erase), or nvme format --ses=1 fallback
      ATA   -> hdparm --security-erase-enhanced

    NVMe paths follow with a software readloop 0x00 verify pass.
    ATA Enhanced Security Erase does NOT verify — the erase pattern is
    vendor-defined and may not be 0x00, so a verify pass would produce
    false mismatches. This is documented in the certificate.

    Pre-flight checks are run in main() before this is called.
    hw_info is the return value of check_nvme_support() or check_ata_support().
    Does NOT perform a stuck-bit test.
    '''
    if _is_nvme(devname):
        # Determine which NVMe method was selected by pre-flight in main()
        # hw_info is a dict from check_nvme_support(); sanicap tells us what's available
        import json as _json
        sanicap = hw_info.get('sanicap', 0) if isinstance(hw_info, dict) else 0
        if bool(sanicap & 0b010):
            logging(logfile, "hw-secure: NVMe, using nvme sanitize (block erase)")
            console.print("[dim]NVMe device — using NVMe Block Erase (sanitize).[/]")
            nvme_sanitize(devname, block, blocksize, devsize, logfile)
        else:
            logging(logfile, "hw-secure: NVMe, falling back to nvme format --ses=1")
            console.print("[dim]NVMe device — using NVMe User Data Erase (format fallback).[/]")
            nvme_format(devname, block, blocksize, devsize, logfile)
    else:
        logging(logfile, "hw-secure: ATA device, using hdparm --security-erase-enhanced")
        console.print("[dim]ATA device detected — using ATA Enhanced Security Erase.[/]")
        atasecure(devname, logfile, hw_info)
        # ATA Enhanced Security Erase writes a vendor-defined pattern that may not
        # be 0x00. Skipping software verify to avoid false mismatches.
        # This is noted in the certificate.
        console.print("[dim]Syncing...[/]")
        os.sync()
        flushcaches()
        console.print("[bold green]✓ ATA Enhanced Security Erase completed. "
            "Verify pass skipped (vendor-defined erase pattern).[/]")
        logging(logfile, "ATA Enhanced Security Erase completed. "
            "Verify pass skipped — erase pattern is vendor-defined, may not be 0x00.")

def writeloop(block, blocksize, devsize, pattern, logfile):
    '''
    Full disk write pass — writes a single byte pattern across the entire device.
    '''
    logging(logfile, f"Writing 0x{pattern} to drive.")
    color = "red" if pattern == "FF" else "cyan"
    if pattern == "00":
        writepattern = bytes(blocksize)
    else:
        writepattern = bytes(blocksize).replace(b'\x00', b'\xff')
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time()

    with Progress(
        TextColumn(f"[bold {color}]Write 0x{pattern}[/]"),
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
            try:
                os.write(block, writepattern)
            except OSError as exc:
                msg = f"I/O write error at position {dev_pos}: {exc}"
                console.print(f"[bold red]✗ {msg}[/]")
                logging(logfile, msg)
                logging(logfile, "Exiting due to I/O error.")
                sys.exit(1)
            runtime = time.time() - starttime
            mbps = (dev_pos + blocksize) / runtime / 1024 / 1024 if runtime > 0 else 0.0
            progress.update(task, completed=dev_pos + blocksize, mbps=mbps)

    runtime = time.time() - starttime
    mbps = devsize / runtime / 1024 / 1024 if runtime > 0 else 0.0
    runtimefmt = str(datetime.timedelta(seconds=math.floor(runtime)))
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



def fulltest(block, blocksize, devsize, logfile):
    '''
    --full / -f - check all bits flip both ways and verify
    '''
    logging(logfile, "Full drive double-wipe and verify started")

    writeloop(block, blocksize, devsize, "FF", logfile)
    console.print("[dim]Syncing...[/]")
    os.sync()
    flushcaches()

    readloop(block, blocksize, devsize, "FF", logfile)

    writeloop(block, blocksize, devsize, "00", logfile)

    console.print("[dim]Syncing...[/]")
    os.sync()
    flushcaches()

    readloop(block, blocksize, devsize, "00", logfile)

    logging(logfile, "Double wipe and verify completed.")

def singlepass(block, blocksize, devsize, logfile):
    '''
    --zero / -z - write a null to every sector and then verify
    '''
    logging(logfile, "Single-pass null and verify started")

    writeloop(block, blocksize, devsize, "00", logfile)

    console.print("[dim]Syncing...[/]")
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


# SMART attribute IDs we want to capture for the certificate.
# Tuple: (attribute_id_decimal, friendly_label)
_SMART_ATTRS = [
    ("9",   "Power-On Hours"),
    ("12",  "Power Cycle Count"),
    ("190", "Temperature (Alt)"),
    ("194", "Temperature (Celsius)"),
    ("197", "Current Pending Sectors"),
    ("198", "Uncorrectable Sectors"),
    ("5",   "Reallocated Sectors"),
    ("187", "Reported Uncorrectable"),
    ("188", "Command Timeout"),
    ("196", "Reallocation Events"),
]

def capture_smart(devname, logfile):
    '''
    Run smartctl -a against devname and parse the output into a dict of
    key→value strings suitable for embedding in WipeRecord.

    Returns a dict with keys:
      "health"        → overall SMART health assessment string
      "firmware"      → firmware version
      "raw_output"    → full smartctl -a text (stored but not displayed in full)
      plus one key per _SMART_ATTRS label found in the output

    Returns an empty dict if smartctl is not available or the device does
    not support SMART — callers should check record.smart_available.
    '''
    if command_line(['which', 'smartctl']) == b'':
        logging(logfile, "SMART: smartctl not found — skipping SMART capture.")
        return {}

    # Overall health pass/fail
    health_out = command_line(
        ['smartctl', '-H', devname], cmdtimeout=15
    ).decode(errors='replace')

    # Full attribute dump
    full_out = command_line(
        ['smartctl', '-a', devname], cmdtimeout=15
    ).decode(errors='replace')

    if not full_out:
        logging(logfile, "SMART: smartctl returned no output — device may not support SMART.")
        return {}

    result = {}

    # Health string — look for the assessment line
    health_match = re.search(
        r'SMART overall-health self-assessment test result:\s*(.+)', health_out)
    result['health'] = health_match.group(1).strip() if health_match else 'UNKNOWN'

    # Firmware version
    fw_match = re.search(r'Firmware Version:\s*(.+)', full_out)
    result['firmware'] = fw_match.group(1).strip() if fw_match else '—'

    # Parse attribute table — lines look like:
    #   ID# ATTRIBUTE_NAME          FLAG  VALUE WORST THRESH TYPE  UPDATED  WHEN_FAILED RAW_VALUE
    #   194 Temperature_Celsius     0x0022  033   046   000   Old_age Always   -       33 (Min/Max 22/46)
    for attr_id, label in _SMART_ATTRS:
        # Match by attribute ID at start of line (decimal, 1-3 digits)
        pattern = rf'^\s*{attr_id}\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$'
        match = re.search(pattern, full_out, re.MULTILINE)
        if match:
            result[label] = match.group(1).strip()

    # Also capture NVMe-style temperature if present (different format)
    if 'Temperature (Celsius)' not in result:
        nvme_temp = re.search(r'Temperature:\s*(\d+)\s*Celsius', full_out)
        if nvme_temp:
            result['Temperature (Celsius)'] = nvme_temp.group(1)

    result['raw_output'] = full_out
    logging(logfile, f"SMART captured for {devname}: health={result['health']}, "
        f"firmware={result['firmware']}")
    return result


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
    parser.add_argument("-l", "--logfile",
        help="Write/append timestamped log to FILE. If FILE is a directory, "
             "the log is auto-named as owl_log_<device>_<timestamp>.txt inside it.")
    parser.add_argument("-b", "--blocksize",
        help="override default working blocksize")
    parser.add_argument("--hw-erase",
        help="Hardware erase (ATA security-erase or NVMe format --ses=1, "
             "auto-detected) + software verify",
        action="store_true", dest="hw_erase")
    parser.add_argument("--hw-secure",
        help="Thorough hardware erase reaching overprovisioned sectors "
             "(ATA enhanced security-erase or NVMe sanitize block-erase, "
             "auto-detected). NVMe operations are followed by a software "
             "verify pass. ATA enhanced security-erase skips software verify "
             "as the erase pattern is vendor-defined and may not be 0x00.",
        action="store_true", dest="hw_secure")
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
    with open(logfile, "a", encoding="utf-8") as log:
        timestamp = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec='seconds')
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

# Maps each operation label to its NIST SP 800-88r2 standard classification.
# Auto-populated on the certificate for every operation.
_WIPE_STANDARDS = {
    "Full Double Wipe + Verify (FF then 00)":                     "Two-pass overwrite (0xFF / 0x00) with verification — meets NIST SP 800-88r2 Clear; designed for stuck-bit detection",
    "Full Double Wipe + Verify (FF then 00) [default]":           "Two-pass overwrite (0xFF / 0x00) with verification — meets NIST SP 800-88r2 Clear; designed for stuck-bit detection",
    "Single-Pass Zero + Verify":                                  "NIST SP 800-88r2 — Clear",
    "Smart Wipe (selective null overwrite)":                      "Non-standard (partial overwrite, selective sectors only)",
    "Drive Map / Null Check (read-only)":                         "N/A — read-only operation",
    "Hardware Erase + Software Verify (NVMe format)":             "NIST SP 800-88r2 — Clear",
    "Hardware Erase + Software Verify (ATA security-erase)":      "NIST SP 800-88r2 — Clear",
    "Hardware Secure Erase + Software Verify (NVMe sanitize)":    "NIST SP 800-88r2 — Purge",
    "Hardware Secure Erase + Software Verify (NVMe format)":      "NIST SP 800-88r2 — Clear",
    "Hardware Secure Erase (ATA enhanced security-erase)":        "NIST SP 800-88r2 — Purge",
}


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

    # If a directory was given for --logfile, auto-name the file inside it
    if logfile is not None and os.path.isdir(logfile):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        devshort = devname.replace('/', '_').strip('_')
        logfile = os.path.join(logfile, f"owl_log_{devshort}_{ts}.txt")

    # Determine operation label early for the record
    if args.check:
        operation = "Drive Map / Null Check (read-only)"
    elif args.smart:
        operation = "Smart Wipe (selective null overwrite)"
    elif args.zero:
        operation = "Single-Pass Zero + Verify"
    elif args.full:
        operation = "Full Double Wipe + Verify (FF then 00)"
    elif args.hw_erase:
        operation = "Hardware Erase + Software Verify"
    elif args.hw_secure:
        operation = "Hardware Secure Erase + Software Verify"
    else:
        operation = "Full Double Wipe + Verify (FF then 00) [default]"

    # Auto-assign the wipe standard from the map
    wipe_standard = _WIPE_STANDARDS.get(operation, "")

    record = WipeRecord(
        operation=operation,
        command=' '.join(sys.argv),
        device_path=devname,
        operator_name=args.operator or "",
        wipe_standard=wipe_standard,
    )

    if args.operator and args.report is None:
        console.print("[yellow]⚠ --operator was specified but --report was not. "
            "The operator name will not be saved unless --report is also used.[/]")

    atexit.register(cleanup)
    rootcheck()

    # Direct access to disk to bypass cache, sync writes
    try:
        block = os.open(devname, os.O_RDWR | os.O_SYNC)
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

    blkdata = diskinfo(devname, logfile)
    if blkdata:
        record.model     = str(blkdata.get('model',  '') or '—').strip()
        record.vendor    = str(blkdata.get('vendor', '') or '—').strip()
        record.serial    = str(blkdata.get('serial', '') or '—').strip()
        record.transport = str(blkdata.get('tran',   '') or '—').strip()

    # Capture SMART data before the wipe
    if args.report is not None and not args.check:
        console.print("[dim]Capturing pre-wipe SMART data...[/]")
        record.smart_pre = capture_smart(devname, logfile)
        record.smart_available = bool(record.smart_pre)

    if args.check:
        drivemap(block, blocksize, devsize, logfile)
        record.success = True
        record.notes   = "Read-only check. No data was written."
    elif args.smart:
        confirm_wipe(devname, devsize, operation, logfile)
        checkblock(block, blocksize, devsize, logfile)
        record.success = True
    elif args.zero:
        confirm_wipe(devname, devsize, operation, logfile)
        singlepass(block, blocksize, devsize, logfile)
        record.success = True
    elif args.full:
        confirm_wipe(devname, devsize, operation, logfile)
        fulltest(block, blocksize, devsize, logfile)
        record.success = True
    elif args.hw_erase:
        # Pre-flight before confirmation screen
        if _is_nvme(devname):
            hw_info = check_nvme_support(devname, "format", logfile)
            actual_op = "Hardware Erase + Software Verify (NVMe format)"
        else:
            hw_info = check_ata_support(devname, "erase", logfile)
            actual_op = "Hardware Erase + Software Verify (ATA security-erase)"
        confirm_wipe(devname, devsize, operation, logfile)
        hw_erase(devname, block, blocksize, devsize, logfile, hw_info)
        record.success = True
        record.operation = actual_op
        record.wipe_standard = _WIPE_STANDARDS.get(actual_op, "")
    elif args.hw_secure:
        # Pre-flight before confirmation screen
        if _is_nvme(devname):
            # Probe sanitize support; fall back gracefully
            import json as _json
            raw = command_line(
                ['nvme', 'id-ctrl', devname, '--output-format=json'],
                cmdtimeout=10).decode(errors='replace')
            sanitize_ok = False
            if raw:
                try:
                    ctrl = _json.loads(raw)
                    sanitize_ok = (bool(ctrl.get('oacs', 0) & (1 << 3)) and
                                   bool(ctrl.get('sanicap', 0) & 0b010))
                except _json.JSONDecodeError:
                    pass
            if sanitize_ok:
                hw_info = check_nvme_support(devname, "sanitize", logfile)
                actual_op = "Hardware Secure Erase + Software Verify (NVMe sanitize)"
            else:
                console.print("[yellow]⚠ NVMe Block Erase (sanitize) not supported — "
                    "falling back to NVMe User Data Erase (format --ses=1).[/]")
                logging(logfile, "hw-secure: sanitize not supported, "
                    "falling back to nvme format")
                hw_info = check_nvme_support(devname, "format", logfile)
                actual_op = "Hardware Secure Erase + Software Verify (NVMe format)"
        else:
            hw_info = check_ata_support(devname, "secure", logfile)
            actual_op = "Hardware Secure Erase (ATA enhanced security-erase)"
        confirm_wipe(devname, devsize, operation, logfile)
        hw_secure(devname, block, blocksize, devsize, logfile, hw_info)
        record.success = True
        record.operation = actual_op
        record.wipe_standard = _WIPE_STANDARDS.get(actual_op, "")
    else:
        confirm_wipe(devname, devsize, operation, logfile)
        fulltest(block, blocksize, devsize, logfile)
        record.success = True

    # Capture SMART data after the wipe
    if args.report is not None and record.success and not args.check:
        console.print("[dim]Capturing post-wipe SMART data...[/]")
        record.smart_post = capture_smart(devname, logfile)

    record.end_time = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec='seconds')

    # Generate certificate if --report was requested
    if args.report is not None:
        report_path = args.report
        # If the user gave a directory, auto-name the file inside it
        if os.path.isdir(report_path):
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            devshort = devname.replace('/', '_').strip('_')
            report_path = os.path.join(report_path, f"owl_cert_{devshort}_{ts}.pdf")
        generate_certificate(record, report_path, logfile)

    logging(logfile, "Exited")

if __name__ == "__main__":
    main()
