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
import argparse
import time
import datetime
import math
import re
import subprocess
import atexit
from blkinfo import BlkDiskInfo

# Set the color bits we need for outputting to the terminal
TRMRED = "\x1B[1m\x1B[31m"  # Bold Red (ANSI) - malware
TRMGRN = "\x1B[0m\x1B[32m"  # Normal Green (ANSI) - clean
TRMCYN = "\x1B[1m\x1B[36m"  # Bold Cyan (ANSI)
TRMYEL = "\x1B[0m\x1B[33m"  # Normal Yellow (ANSI) - unknown
TRMMAG = "\x1B[35m"  # Magenta (ANSI)
TRMBMAG = "\x1B[1m\x1B[35m"  # Bold Magenta (ANSI) - errors
TRMBNORM = "\x1B[0m"  # Normal (ANSI) - normal
TRMCLR = "\x1B[K" # clear from here to end of line


def checkblock(block, blocksize, devsize, logfile):
    '''
    --smart / -s
    "Single pass overwriting non-clean sectors with nulls. Not verified."
    "smart" option - ideal for flash media where we want to limit writes
    override blocksize to be nice to flash media - assume 4k native
    '''
    logging(logfile, "Smart wipe started")
    #orig_blocksize = blocksize
    nullbytes = bytes(blocksize)
    flushcaches()
    os.lseek(block, 0, os.SEEK_SET)
    # loop this whole process
    starttime = time.time() # reset the clock
    blockwrites = 0
    for _ in range(0, (devsize), blocksize):
        # seek blocksize from current position - loop this part while less than devsize
        devpos = os.lseek(block, 0, os.SEEK_CUR)
        if devpos+blocksize > (devsize):
            # taking care of the last block if it's past the end
            blocksize = (devsize)-devpos
            nullbytes = bytes(blocksize)
        bytesin = os.read(block,blocksize)
        # calc runtime
        runtime = (time.time() - starttime)
        # calc time remaining
        if runtime > 0 and devpos > 0:
            etasec = math.floor((devsize - devpos) / (devpos / runtime))
            etatime = str(datetime.timedelta(seconds=etasec))
        else:
            etatime = "-:--:--"

        if bytesin == nullbytes:
            # calculate percentage complete
            status = (f"Position: {(devpos+blocksize):,} ("
                f"{((devpos+blocksize) / devsize):.3%})  State: {TRMGRN}O"
                f"{TRMBNORM}  TTC: {etatime} @ "
                f"{((devpos+blocksize) / runtime / 1024 / 1024):0.2f} MBps ("
                f"{blockwrites:,} blocks written){TRMCLR}\r")
            sys.stdout.write(status)
        else:
            # block is not nulled - rewind blocksize and re-write
            devpos = os.lseek(block, -blocksize, os.SEEK_CUR)
            # write nulls
            os.write(block, nullbytes)
            blockwrites += 1
            # calculate percentage complete
            status = (f"Position: {(devpos+blocksize):,} ("
                f"{((devpos+blocksize) / devsize):.3%})  State: {TRMRED}X"
                f"{TRMBNORM}  TTC: {etatime} @ "
                f"{((devpos+blocksize) / runtime / 1024 / 1024):0.2f} MBps ("
                f"{blockwrites:,} blocks written){TRMCLR}\r")
            sys.stdout.write(status)
    # sync all writes
    sys.stdout.write("\n Syncing...\r")
    os.sync()
    # flush the cache
    flushcaches()
    # at the end gof the write pass show the elapsed time on the command line
    runtime = (time.time() - starttime)
    runtimesec = math.floor(runtime)
    runtimefmt = str(datetime.timedelta(seconds=runtimesec))
    status = (f"Checked:  {(devpos+blocksize):,} ("
        f"{((devpos+blocksize) / devsize):.3%})  State: {TRMGRN}-{TRMBNORM}"
        f"  RT:  {runtimefmt} @ "
        f"{((devpos+blocksize) / runtime / 1024 / 1024):0.2f} MBps ("
        f"{blockwrites} blocks written){TRMCLR}\n")
    sys.stdout.write(status)
    logging(logfile, f"{str(status).strip()}")
    logging(logfile, "Clean. Single pass overwriting non-clear sectors with "
        "nulls. Not verified.")

def flushcaches():
    '''
    flush cache so we read from disk rather than buffer
    '''
    with open('/proc/sys/vm/drop_caches', 'w', encoding="ascii") as file_object:
        file_object.write("1\n")

def wipefail(block, position, blocksize, pattern, logfile):
    '''
    this will get called when a write fails
    '''
    print("\nWrite failed at position", position, "- attempting rewrite")
    logging(logfile, f"Write failure detected in block at {position} - rewrite attempted")
    # attempt rewipe the failed block
    if pattern == "00":
        bytepattern = bytes(blocksize)
    else:
        bytepattern = bytepattern.replace(b'\x00', b'\xff')
    os.lseek(block, position, os.SEEK_SET)
    os.write(block, bytepattern)
    os.sync()
    # flush the caches
    flushcaches()
    # recheck
    os.lseek(block, position, os.SEEK_SET)
    bytesin = os.read(block,blocksize)
    if bytesin != bytepattern:
        print("\nRe-Write attempt failed at position", position, "\n")
        logging(logfile, f"Re-write attempt at position {position} failed. Exiting.")
        sys.exit()
    else:
        return

def drivemap(block, blocksize, devsize, logfile):
    '''
    --check / -c
    quick mapping of the data on the drive for stats
    '''
    logging(logfile, "Drive mapping started")
    cleancount = 0
    dirtycount = 0
    keepmapping = 0
    nullbytes = bytes(blocksize)
    os.lseek(block, 0, os.SEEK_SET)
    flushcaches()
    #starttime = time.time() # reset the clock
    for dev_pos in range(0, (devsize), blocksize):
        if dev_pos+blocksize > (devsize):
            # taking care of the last block if it's past the end
            blocksize = (devsize)-dev_pos
            nullbytes = bytes(blocksize)
        bytesin = os.read(block,blocksize)
        if bytesin == nullbytes:
            cleancount = cleancount + blocksize
        else:
            dirtycount = dirtycount + blocksize
            # drive is dirty - see if we should continue mapping
            if keepmapping == 0:
                logging(logfile, f"Non-clear sectors found in block starting at {dev_pos:,}")
                check = input("Non-clear sectors found in block starting at " +
                    str(dev_pos) + ". Continue? (y/n) ")
                if check.lower() == "y":
                    keepmapping = 1
                    logging(logfile, "User chose to continue mapping.")
                else:
                    print(TRMRED + "Drive is not clear. Exiting." + TRMBNORM)
                    logging(logfile, "User chose to terminate mapping.")
                    logging(logfile, "Drive mapped. Drive is dirty and contains non-clear sectors.")
                    logging(logfile, "Exiting.")
                    sys.exit()

        percentdone = f"{((dev_pos+blocksize) / devsize):.3%}"
        # calc percent dirty / clean
        cleanpct = f"{(cleancount / devsize):.3%}"
        dirtypct = f"{(dirtycount / devsize):.3%}"
        position = f"{(dev_pos+blocksize):,}"
        status = (f"Mapping: {position} ({percentdone})  Dirty: {TRMRED}"
            f"{dirtypct} {TRMBNORM}Clean: {TRMGRN}{cleanpct}{TRMBNORM}{TRMCLR}\r")
        sys.stdout.write(status)
    sys.stdout.write("\n")
    if dirtycount == 0:
        print(TRMGRN + "Drive is clear and only contains 0x00." + TRMBNORM)
        logging(logfile, "Drive mapped. Drive is clear and only contains 0x00.")
        return
    print(TRMRED + "Drive is not clear." + TRMBNORM)
    logging(logfile, "Drive mapped. Drive is dirty and contains non-nulled "
        "data. " + cleanpct + "% clean and " + dirtypct + "% dirty (" +
        str(dirtycount) + " blocks).")
    return

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
    hdpcheck = command_line(['which','hdparm'])
    if hdpcheck == b'':
        logging(logfile, "ERROR: hdparm utility not found. Exiting.")
        sys.exit("ERROR: hdparm utility not found. Exiting.")
    # get current drive status
    hdpi = command_line(['hdparm','-I', devname]).decode(errors='replace')
    if re.search('not\tsupported: enhanced erase', hdpi):
        # 	not\tsupported: enhanced erase
        logging(logfile, "ERROR: ATA Secure Erase not supported for this device. Exiting.")
        sys.exit("ERROR: ATA Secure Erase not supported for this device. Exiting.")
    if not re.search('(not\tfrozen)', hdpi):
        logging(logfile, "ERROR: Drive is currently frozen. Exiting.")
        sys.exit("ERROR: Drive is currently frozen. Exiting.")
    if not re.search('(not\tlocked)', hdpi):
        logging(logfile, "ERROR: Drive is currently locked. Exiting.")
        sys.exit("ERROR: Drive is currently locked. Exiting.")
    # get time to secure-erase drive
    setime = re.search('([0-9]+min for ENHANCED SECURITY ERASE)', hdpi).group(1)
    logging(logfile, f"Drive reports {setime}")
    print('Drive reports ' + setime)
    # enable security - set password
    command_line(['hdparm', '--user-master', 'user', '--security-set-pass',
        'pass', devname]).decode()
    logging(logfile, "ATA password set to 'pass'")
    # send erase command
    logging(logfile, "ATA Secure Erase command sent")
    command_line(['hdparm', '--user-master', 'user', '--security-erase-enhanced',
        'pass', devname]).decode()
    logging(logfile, "ATA Secure Erase completed")
    # erase password
    command_line(['hdparm', '--user-master', 'user', '--security-set-pass',
        'NULL', devname]).decode()
    logging(logfile, "ATA password removed.")
    # disable security
    command_line(['hdparm', '--user-master', 'user', '--security-disable',
        'NULL', devname]).decode()
    logging(logfile, "ATA security disabled")
    print("ATA Secure Erase completed.")
    logging(logfile, "ATA Secure Erase completed.")
    # we can't call this 'clean' or 'clear' because it may not be zeroes

def ataerase(devname, logfile):
    '''
    # call hdparm and ATA Erase (null) the drive
    '''
    logging(logfile, "Performing ATA Erase on drive.")
    hdpcheck = command_line(['which','hdparm'])
    if hdpcheck == b'':
        logging(logfile, "ERROR: hdparm utility not found. Exiting.")
        sys.exit("ERROR: hdparm utility not found. Exiting.")
    # get current drive status
    hdpi = command_line(['hdparm','-I', devname]).decode(errors='replace')
    if not re.search('supported: enhanced erase', hdpi):
        logging(logfile, "ERROR: ATA Secure Erase not supported for this device. "
            "Exiting.")
        sys.exit("ERROR: ATA Secure Erase not supported for this device. "
            "Exiting.")
    if not re.search('(not\tfrozen)', hdpi):
        logging(logfile, "ERROR: Drive is currently frozen. Exiting.")
        sys.exit("ERROR: Drive is currently frozen. Exiting.")
    if not re.search('(not\tlocked)', hdpi):
        logging(logfile, "ERROR: Drive is currently locked. Exiting.")
        sys.exit("ERROR: Drive is currently locked. Exiting.")
    # get time to secure-erase drive
    setime = re.search('([0-9]+min for SECURITY ERASE)', hdpi).group(1)
    print('Drive reports ' + setime)
    logging(logfile, f"Drive reports {setime}")
    # enable security - set password
    command_line(['hdparm', '--user-master', 'user', '--security-set-pass',
        'pass', devname]).decode()
    logging(logfile, "ATA passsword set to 'pass'")
    # run erase command
    logging(logfile, "ATA Erase command sent")
    command_line(['hdparm', '--user-master', 'user', '--security-erase',
        'pass', devname]).decode()
    logging(logfile, "ATA Erase command completed")
    # remove password
    command_line(['hdparm', '--user-master', 'user', '--security-set-pass',
        'NULL', devname]).decode()
    logging(logfile,"ATA password removed")
    # disable security
    command_line(['hdparm', '--user-master', 'user',
        '--security-disable', 'NULL', devname]).decode()
    logging(logfile, "ATA Security disabled.")
    print("ATA Secure Erase completed.")
    logging(logfile, "ATA Secure Erase completed.")
    # we can't call this 'clean' or 'clear' because it may not be zeroes

def writeloop(block, blocksize, devsize, pattern, logfile):
    '''
    breaking out full disk writing into separate functions
    '''
    logging(logfile, f"Writing 0x{pattern} to drive.")
    if pattern=="00":
        writepattern = bytes(blocksize)
    else:
        writepattern = bytes(blocksize).replace(b'\x00', b'\xff')
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time() # reset the clock
    for dev_pos in range(0, (devsize), blocksize):
        if dev_pos+blocksize > (devsize):
            # taking care of the last block if it's past the end
            blocksize = (devsize)-dev_pos
            if pattern=="00":
                writepattern = bytes(blocksize)
            else:
                writepattern = bytes(blocksize).replace(b'\x00', b'\xff')
        # calc runtime
        runtime = (time.time() - starttime)
        # calc time remaining
        if runtime > 0 and dev_pos > 0:
            etasec = math.floor((devsize - dev_pos) / ((dev_pos+blocksize) / runtime))
            etatime = str(datetime.timedelta(seconds=etasec))
        else:
            etatime = "-:--:--"
        #writing pattern
        os.write(block, writepattern)
        status = (f"Writing 0x{pattern}: {(dev_pos+blocksize):,} ("
            f"{((dev_pos+blocksize) / devsize):.3%})  State: {TRMRED}{pattern}"
            f"{TRMBNORM}  TTC: {etatime} @ "
            f"{((dev_pos+blocksize) / runtime / 1024 / 1024):0.2f} MBps{TRMCLR}"
            f"\r")
        sys.stdout.write(status)

    # at the end of the write pass show the elapsed time on the command line
    runtimefmt = str(datetime.timedelta(seconds=math.floor(runtime)))
    status = (f"Wrote 0x{pattern}: {(dev_pos+blocksize):,} ("
        f"{((dev_pos+blocksize) / devsize):.3%})  State: {TRMGRN}--"
        f"{TRMBNORM}  ET: {runtimefmt} @ "
        f"{((dev_pos+blocksize) / runtime / 1024 / 1024):0.2f} MBps{TRMCLR}\r")
    logging(logfile, status.strip())

def readloop(block, blocksize, devsize, pattern, logfile):
    '''
    breaking out full disk verification into separate functions
    '''
    logging(logfile, f"Verifying 0x{pattern} on drive.")
    if pattern=="00":
        writepattern = bytes(blocksize)
    else:
        writepattern = bytes(blocksize).replace(b'\x00', b'\xff')
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time()
    for dev_pos in range(0, (devsize), blocksize):
        if dev_pos+blocksize > (devsize):
            # taking care of the last block if it's past the end
            blocksize = (devsize)-dev_pos
            if pattern=="00":
                writepattern = bytes(blocksize)
            else:
                writepattern = bytes(blocksize).replace(b'\x00', b'\xff')
        # calc runtime
        runtime = (time.time() - starttime)
        # calc time remaining
        if runtime > 0 and dev_pos > 0:
            etasec = math.floor((devsize - dev_pos) / (dev_pos / runtime))
            etatime = str(datetime.timedelta(seconds=etasec))
        else:
            etatime = "-:--:--"

        #reading ones
        bytesin = os.read(block, blocksize)
        if bytesin != writepattern:
            # this write fails - throw an error and stop
            wipefail(block, dev_pos, blocksize, pattern, logfile)
        status = (f"Verifying 0x{pattern}: {(dev_pos+blocksize):,} ("
            f"{((dev_pos+blocksize) / devsize):.3%})  State: {TRMGRN}"
            f"{pattern}{TRMBNORM}  TTC: {etatime} @ "
            f"{((dev_pos+blocksize) / runtime / 1024 / 1024):0.2f} MBps"
            f"{TRMCLR}\r")
        sys.stdout.write(status)
    runtimefmt = str(datetime.timedelta(seconds=math.floor(runtime)))
    status = (f"Verified 0x{pattern}: {(dev_pos+blocksize):,} ("
        f"{((dev_pos+blocksize) / devsize):.3%})  State: {TRMGRN}--"
        f"{TRMBNORM}  ET: {runtimefmt} @ "
        f"{((dev_pos+blocksize) / runtime / 1024 / 1024):0.2f} MBps{TRMCLR}\r")
    logging(logfile, status.strip())
    print()

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
    # sync all writes
    sys.stdout.write("\nSyncing...\r")
    os.sync()
    # flush the cache
    flushcaches()

    readloop(block, blocksize, devsize, "FF", logfile)

    writeloop(block, blocksize, devsize, "00", logfile)

    # sync all writes
    sys.stdout.write("\nSyncing...\r")
    os.sync()
    # flush the cache
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

    # sync all writes
    sys.stdout.write("\nSyncing...\r")
    os.sync()
    # Then read back every block and verify - if there are any mismatches, die.
    # flush the cache
    flushcaches()

    readloop(block, blocksize, devsize, "00", logfile)

    logging(logfile, "Single-pass null and verify completed. Drive is clear.")

def hidecursor():
    '''
    terminal escape codes to hide the cursor
    '''
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()

def showcursor():
    '''
    terminal escape codes to unhide the cursor
    '''
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()

def rootcheck():
    '''
    make sure we are running as root
    '''
    if os.getuid() != 0:
        print("Error: This program must be run as root. Exiting.")
        showcursor()
        sys.exit()

def cleanup():
    '''
    things we need to do on exit
    '''
    showcursor()

def prettyheader(devname, devsize, blocksize, logfile):
    '''
    command line splash of color
    '''
    print(f"{TRMYEL}  , _ ,")
    print(" ( o o )")
    print("/'` ' `'\\")
    print("|'''''''|")
    print("|\\\\'''//|")
    print(f"   \"\"\"{TRMBNORM}")
    print("O.W.L. - Optimized Wipe and Logging - Forensic Media Sterilization "
        "Utility")
    print(f"Device: {devname}")
    print(f"Device size: {devsize:,} bytes")
    print(f"Block size set to {blocksize:,} bytes")
    logging(logfile, f"{('=' * 80)}")
    logging(logfile,
        "O.W.L. - Optimized Wipe and Logging - Forensic Media Sterilization "
        "Utility")
    logging(logfile, f"Command: {' '.join(sys.argv[0:])}")
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
    if logfile is False:
        return
    with open(logfile, "a", encoding="ascii") as log:
        timestamp = datetime.datetime.now().isoformat()
        log.write(f"{timestamp} {message}\n")

def diskinfo(devname, logfile):
    '''
    get additional info about the target drive
    '''
    blk = BlkDiskInfo()
    filters = { 'name' : devname[5:] } # trim /dev/ to make shortname 'sdx'
    blkdata =  blk.get_disks(filters)[0] #dict
    print(f"Model: {blkdata['model']}")
    logging(logfile, f"Model: {blkdata['model']}")
    print(f"Vendor: {blkdata['vendor']}")
    logging(logfile, f"Vendor: {blkdata['vendor']}")
    print(f"Serial: {blkdata['serial']}")
    logging(logfile, f"Serial: {blkdata['serial']}")
    print(f"Transport: {blkdata['tran']}")
    logging(logfile, f"Transport: {blkdata['tran']}")

    if mountcheck(blkdata, logfile, 0) > 0:
        print("Exiting.")
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
            print(f"Device has a partition mounted at {value}")
            logging(logfile, f"Device has a partition mounted at {value}")
            mountct += 1
    return mountct

def main():
    '''
    docstrings about main keep linters happy. This is main.
    '''
    args = parse_arguments()

    devname = os.path.abspath(args.target[0])
    if not os.path.exists(devname):
        print("ERROR: Target device ", devname, "not found.")
        sys.exit(1)

    try:
        logfile = args.logfile
    except NameError:
        logfile = False

    atexit.register(cleanup)
    # calling main functions here - need to do this with arguments eventually
    rootcheck()
    hidecursor()

    # direct access to disk to bypass cache, sync writes
    block = os.open(devname, os.O_RDWR|os.O_SYNC)
    # figure out the total size of the target
    devsize = os.lseek(block, 0, os.SEEK_END)
    # seek back to the beginning
    os.lseek(block, 0, os.SEEK_SET)

    # user has the option to override
    if args.blocksize:
        blocksize = int(args.blocksize)
    else:
        # set default blocksize to 1MB = 4096*256
        blocksize = 4096 * 256

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

    showcursor()

    logging(logfile, "Exited")

if __name__ == "__main__":
    main()
