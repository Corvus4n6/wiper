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
        TextColumn("[bold cyan]{task.description}"),
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

    console.print("\n[dim]Syncing...[/]", end="\r")
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
    # this will run the media through a full wipe and verify test
    # FF,verify,00,verify - designed for full drive
    # testing or first-time wipe and verify of new media or hunting for stuck
    # bits

    # write ones to disk first
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
    # this will run the media through a full wipe and verify test
    # FF,verify,00,verify - designed for full drive
    # testing or first-time wipe and verify of new media or hunting for stuck
    # bits

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


def parse_arguments():
    '''
    handle command line args
    '''
    arghelpdesc = ("Health check, sterilization, verification, and logging for"
        " data storage devices.")
    parser = argparse.ArgumentParser(description=arghelpdesc)
    parser.add_argument("target", help="Path to block device", nargs=1)
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
    '''
    try:
        blk = BlkDiskInfo()
        filters = { 'name' : devname[5:] } # trim /dev/ to make shortname 'sdx'
        disks = blk.get_disks(filters)
        if not disks:
            console.print("[yellow]Warning: Device not found in block device list "
                "(blkinfo). Skipping disk info.[/]")
            logging(logfile, "Warning: Device not recognized by blkinfo - disk info skipped.")
            return
        blkdata = disks[0]
    except Exception as exc:
        console.print(f"[yellow]Warning: Could not retrieve disk info: {exc}[/]")
        logging(logfile, f"Warning: Could not retrieve disk info: {exc}")
        return

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

    devname = os.path.abspath(args.target[0])
    if not os.path.exists(devname):
        console.print(f"[bold red]ERROR: Target device {devname} not found.[/]")
        sys.exit(1)

    logfile = args.logfile  # None if not provided by user

    atexit.register(cleanup)
    rootcheck()

    # direct access to disk to bypass cache, sync writes
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

    prettyheader(devname, devsize, blocksize, logfile)
    diskinfo(devname, logfile)

    if args.check:
        drivemap(block, blocksize, devsize, logfile)
    elif args.smart:
        checkblock(block, blocksize, devsize, logfile)
    elif args.zero:
        singlepass(block, blocksize, devsize, logfile)
    elif args.full:
        fulltest(block, blocksize, devsize, logfile)
    elif args.atasecure:
        atasecure(devname, logfile)
    elif args.ataerase:
        ataerase(devname, logfile)
    else:
        fulltest(block, blocksize, devsize, logfile)

    logging(logfile, "Exited")

if __name__ == "__main__":
    main()
