#!/usr/bin/python3
#
#   , _ ,
#  ( o o )  Optimized
# /'` ' `'\  Wipe &
# |'''''''| Logging
# |\\'''//|
#    """
#
# OWL - Optimized Wiping and Logging
# thanks to Hasan Eray Dogan for the name
#
# forensic drive wiper program for Corvus Forensics LLC
# designed to wipe, verify, gather stats, update database, notify admin of results
##
import os, sys, argparse, time, datetime, math, re
import json
from blkinfo import BlkDiskInfo
import configparser
import requests
import urllib.parse

# pip3 install pySMART
# apt install python3-pymongo
# pip3 install blkinfo
# pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib

# todo program in options for:
# target device
# block size
# hash method for paranoid types?
# full overwrite and verify all blocks
# double overwrite and verify all blocks (stress test)
# stats about number of bytes overwritten

config = configparser.RawConfigParser()
configured=False
# TODO - compile this and move to /usr/local/sbin
# TODO - add to BH but with the database option omitted?
# compile with pyinstaller -F to make a standalone version

# build a search array where local config will override the more global
searcharray = []
searcharray.append(os.curdir)
searcharray.append(os.path.expanduser("~"))
searcharray.append("/usr/local/etc/")
searcharray.append("/etc/")
for loc in searcharray:
    try:
        with open(os.path.join(loc,'wiper.conf')) as source:
            config.read_file(source)
            configured=True
    except IOError:
        pass
#config.read('wiper.conf')

if configured:
    # mongo databse config
    if config.get('mongo', 'enabled') == "1":
        mongohost = config.get('mongo', 'host')
        mongoport = config.get('mongo', 'port')
        mongodatabase = config.get('mongo', 'database')
        mongocollection = config.get('mongo', 'collection')
        from pymongo import MongoClient
        client = MongoClient(mongohost, int(mongoport))
        db = client[mongodatabase]
        collection = db[mongocollection]
    else:
        mongohost="0"
    # mail server config
    if config.get('smtp', 'enabled') == "1":
        mailactive="1"
        mailserver = config.get('smtp', 'server')
        maillogin = config.get('smtp', 'login')
        mailpassword = config.get('smtp', 'password')
        mailto = config.get('smtp', 'to')
        mailfrom = config.get('smtp', 'from')
        import smtplib
    else:
        mailactive="0"
    # asset management API config
    if config.get('amapi', 'enabled') == "1":
        assman = config.get('amapi', 'enabled')
        asssvr = config.get('amapi', 'server')
        asstok = config.get('amapi', 'token')
    else:
        assman="0"

    # chat SPI for notifications
    if config.get('chatapi', 'enabled') == "1":
        chatty = config.get('chatapi', 'enabled')
        chatendp = config.get('chatapi', 'endpoint')
        chatauth = config.get('chatapi', 'authorization')
        chathead = config.get('chatapi', 'headers')
        chatmeth = config.get('chatapi', 'method')
    else:
        chatty="0"

else:
    print("Configuration file wiper.conf not found.")
    mailactive="0"
    mongohost="0"
    assman="0"
    chatty="0"

global devsize
global devpos
global nullbytes
global onesbytes
global blocksize

starttime = time.time()

# parse arguments
# TODO add args to specify different wiping options:

# drivemap - don't wipe, just verify
# checkblock - the default wiping loop to check and wipe non-zero sectors
# singlepass - single wiping pass across the entire drive all sectors
# fulltest - Media certification: write 0xFF, verify, 0x00, verify.

# This block of code can move all the way to the bottom by the main func calls
arghelpdesc = 'Health check, sterilization, verification, and logging for data storage devices.'
parser = argparse.ArgumentParser(description=arghelpdesc)
parser.add_argument("target", help="Path to block device", nargs=1)
# TODO - if target not provided, list possible targets to wipe
parser.add_argument("-f", "--full", help="Full double wipe and verify [default]", action="store_true")
parser.add_argument("-s", "--smart", help="Perform smart wipe", action="store_true")
parser.add_argument("-z", "--zero", help="Single pass of null bytes", action="store_true")
parser.add_argument("-c", "--check", help="verify media contains only nulls", action="store_true")
parser.add_argument("-i", "--inventory", help="add media inventory number to record")
args = parser.parse_args()
# print(args.fname[0])
devname = os.path.abspath(args.target[0])
#print(target)
if not os.path.exists(devname):
    print("ERROR: Target device ", devname, "not found.")
    sys.exit(1)
try:
    inventory = args.inventory
except:
    inventory = ""

# Set the color bits we need for outputting to the terminal
trmred = "\x1B[1m\x1B[31m"  # Bold Red (ANSI) - malware
trmgrn = "\x1B[0m\x1B[32m"  # Normal Green (ANSI) - clean
trmcyn = "\x1B[1m\x1B[36m"  # Bold Cyan (ANSI)
trmyel = "\x1B[0m\x1B[33m"  # Normal Yellow (ANSI) - unknown
trmmag = "\x1B[35m"  # Magenta (ANSI)
trmbmag = "\x1B[1m\x1B[35m"  # Bold Magenta (ANSI) - errors
trmnorm = "\x1B[0m"  # Normal (ANSI) - normal

print(trmyel + "  , _ ,")
print(" ( o o )")
print("/'` ' `'\\")
print("|'''''''|")
print("|\\\\'''//|")
print("   \"\"\"" + trmnorm)
print('O.W.L. - Optimized Wipe and Logging - Forensic Media Sterilization Utility')

print("Device:", devname)
# devstat = os.stat(devname)

# direct access to disk to bypass cache
block = os.open(devname, os.O_RDWR)
# figure out the total size of the target
devsize = os.lseek(block, 0, os.SEEK_END)
# seek back to the beginning
devpos = os.lseek(block, 0, os.SEEK_SET)
# print("Position:", devpos)
print("Device size:", ('{:,}'.format(devsize)), "bytes")

# calculate the optimal blocksize here via modulus
blockcheck = 1
# starting at the preferred optimal maximum
blocksize = 4096 * 64
decrementval = 4096
while blockcheck != 0:
    blockcheck = devsize % blocksize
    #print("blocksize: ", blocksize, "blockcheck: ", blockcheck)
    if blockcheck == 0:
        break
    # add a check in case we are dealing with older drives or odd number
    if blocksize == decrementval:
        decrementval = 512
    blocksize -= decrementval
    if blocksize == 0:
        # if we can't calculate a reasonable block size set the default:
        blocksize = 512
        break
    # odd problem to note here - if the last block is smaller than the
    # blocksize variable, then it will flag as 'dirty'

if blocksize == 512:
    # try to find a bigger divisor on this oddly sized drive
    blockcheck = 1
    # starting at the preferred optimal maximum
    blocksize = 4096 * 64
    decrementval = 512
    while blockcheck != 0:
        blockcheck = devsize % blocksize
        #print("blocksize: ", blocksize, "blockcheck: ", blockcheck)
        if blockcheck == 0:
            break
        # add a check in case we are dealing with older drives or odd number
        if blocksize == decrementval:
            decrementval = 512
        blocksize -= decrementval
        if blocksize == 0:
            # if we can't calculate a reasonable block size set the default:
            blocksize = 512
            break
        # odd problem to note here - if the last block is smaller than the
        # blocksize variable, then it will flag as 'dirty'

print("Block size set to", blocksize, " bytes")
#sys.exit(0)
# define null4k block
nullbytes = bytes(blocksize)
# define 4k block of FF for the full overwrite tests
onesbytes = nullbytes.replace(b'\x00', b'\xff')
# byteshash = hashlib.md5(null4k).hexdigest()
# bytescrc = crc16.crc16xmodem(null4k)
# print("null md5:", byteshash, "- null crc16:", bytescrc)

# bytesin = os.read(block,4096)
# byteshash = hashlib.md5(bytesin).hexdigest()
# print("md5:" , byteshash , "- crc16:" , crc16.crc16xmodem(bytesin))
# os.lseek(dev,0,os.SEEK_SET)


def checkblock():
    # ideal for flash media where we want to limit writes
    flushcaches()
    os.lseek(block, 0, os.SEEK_SET)
    # loop this whole process
    starttime = time.time() # reset the clock
    for xx in range(0, (devsize), blocksize):
        # seek 4k from current position - loop this part while less than devsize
        devpos = os.lseek(block, 0, os.SEEK_CUR)
        ##if devpos == devsize:
        ##    print("\n")
        ##    sys.exit(0)
        bytesin = os.read(block,blocksize)
        # byteshash = hashlib.md5(bytesin).hexdigest()
        # todo - might be even faster to simply compare the strings of nulls and provide feedback visually 0/1
        # todo - also guaranteed to be accurate with no math issues
        # bytescrc = crc16.crc16xmodem(bytesin)
        # testing - remove hashing functions when checking simple bstring comparison
        percentdone = ("%6.3f" % (((devpos+blocksize) / devsize) * 100))
        # calc runtime
        runtime = (time.time() - starttime)
        # calc average speed
        avgspd = ("%0.2f" % ((devpos+blocksize) / runtime / 1024 / 1024))
        # calc time remaining
        if runtime > 0 and devpos > 0:
            etasec = math.floor((devsize - devpos) / (devpos / runtime))
            etatime = str(datetime.timedelta(seconds=etasec))
        else:
            etatime = "-:--:--"

        if bytesin == nullbytes:
            # calculate percentage complete
            status = "Position: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmgrn + "O " + \
                     trmnorm + " TTC: " + etatime + " @ " + avgspd + " MBps  \r"
            sys.stdout.write(status)
        else:
            ## double hashes note where I took out syncing for speed - sync at end for speed follow by verify
            ## if no sectors were overwritten, there is no need to verify since we just did.
            #if bytescrc > 0:
            # rewind 4k and write
            devpos = os.lseek(block, -blocksize, os.SEEK_CUR)
            # print("Position:", devpos)
            # write 4k nulls and sync
            os.write(block, nullbytes)
            ##os.sync()
            # back up 4k and recheck
            ##devpos = os.lseek(block, -4096, os.SEEK_CUR)
            ##bytesin = os.read(block,4096)
            # byteshash = hashlib.md5(bytesin).hexdigest()
            #bytescrc = crc16.crc16xmodem(bytesin)
            # calculate percentage complete
            status = "Position: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmred + "X " + \
                     trmnorm + " TTC: " + etatime + " @ " + avgspd + " MBps  \r"
            sys.stdout.write(status)
            ##if bytesin != nullbytes:
                # this write failed - throw an error and stop
            ##    wipefail(devpos)
    # sync all writes
    sys.stdout.write("\n Syncing...\r")
    os.sync()
    # flush the cache
    flushcaches()
    # at the end gof the write pass show the elapsed time on the command line
    runtime = (time.time() - starttime)
    runtimesec = math.floor(runtime)
    runtimefmt = str(datetime.timedelta(seconds=runtimesec))
    status = "Checked: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmgrn + "- " + \
                    trmnorm + " RT: " + runtimefmt + " @ " + avgspd + " MBps   \r"
    return "clean", "Single pass overwriting non-clean sectors with nulls. Not verified."

def flushcaches():
    # flush cache so we read from disk rather than buffer
    with open('/proc/sys/vm/drop_caches', 'w') as f:
        f.write("1\n")
    return

def wipefail(block, position, blocksize, pattern):
    # this will get called when the write fails
    print("\nWrite failed at position", position, "- attempting rewrite")
    # attempt rewipe the failed block
    if pattern == "00":
        bytepattern = nullbytes
    else:
        bytepattern = onesbytes
    os.lseek(block, position, os.SEEK_SET)
    os.write(block, bytepattern)
    os.sync()
    # flush the cache
    flushcaches()
    # recheck
    os.lseek(block, position, os.SEEK_SET)
    bytesin = os.read(block,blocksize)
    if bytesin != bytepattern:
        print("\nRe-Write attempt failed at position", position, "\n")
        # TODO email notify of failure
        sys.exit(1)
    else:
        return


def healthcheck(passno):
    # TODO : add option to continue wiping even if SMART fails for final destruction pass
    # get drive info and health status using smartmontools via pySMART
    # https://github.com/freenas/py-SMART/blob/master/pySMART/device.py

    from pySMART import Device
    smart = Device(devname)
    if smart.model == None:
        # usb drives can be problematic - switch interface type
        smart = Device(devname, interface='scsi')
    # blkinfo to get more data that smart might miss
    blk = BlkDiskInfo()
    filters = { 'name' : smart.name } # shortname 'sda'
    blkdata =  blk.get_disks(filters)[0]
    # add data to smart json and fix empty fields
    smart.lsblk = blkdata
    if smart.model == None:
        smart['model'] = blkdata['model']
    if smart.serial == None:
        smart.serial = blkdata['serial']
    #import pprint
    #pprint.pprint(smart.__dict__)
    print("Device: " + str(smart.name))
    print("Model: " + str(smart.model))
    print("Serial: " + str(smart.serial))
    print("SMART health check: " + str(smart.assessment))

    # mountcheck! On some systems the response is_mounted does not appear to be there
    # TODO - write more detailed mount check to include add'l types, lvm, dm...
    try:
        mountcheck = blk.get_disks({ 'name' : smart.name, 'is_mounted' : True })
        if mountcheck:
            print( trmred + devname + " has mounted partitions. Exiting." + trmnorm )
            showcursor()
            sys.exit(0)
    except:
        pass

    #print(smart)
    # <NVME device on /dev/nvme0n1 mod:SAMSUNG MZVLB512HBJQ-00A00 sn:S5EGNE0MC08271>
    #print(smart.assessment)
    if str(smart.assessment) == "FAIL":
        print("SMART check *FAILED* for " + str(devname))
        if passno == 1:
            smartfail = input("SMART detects drive as failing. Continue? (y/n) ")
            if smartfail.lower() != "y":
                sys.exit(0)

    # Reallocated Sectors Count - not reported in nvme drives
    try:
        RSC = re.search('(\d+)$', str(smart.attributes[5])).group(1)
        if RSC != "0" and str(smart.attributes[5]) != "None":
            print("Reallocated Sectors Count: " + RSC)
            if passno == 1:
                smartfail = input("SMART reports drive issues. Continue? (y/n) ")
                if smartfail.lower() != "y":
                    sys.exit(0)
    except:
        pass

    # Reported Uncorrectable Errors
    try:
        RUE = re.search('(\d+)$', str(smart.attributes[187])).group(1)
        if RUE != "0" and str(smart.attributes[187]) != "None":
            print("Reported Uncorrectable Errors: " + RUE)
            if passno == 1:
                smartfail = input("SMART reports drive issues. Continue? (y/n) ")
                if smartfail.lower() != "y":
                    sys.exit(0)
    except:
        pass

    # Command Timeout
    try:
        SCT = re.search('(\d+)$', str(smart.attributes[188])).group(1)
        if SCT != "0" and str(smart.attributes[188]) != "None":
            print("SMART Command Timeout: " + SCT)
            if passno == 1:
                smartfail = input("SMART reports drive issues. Continue? (y/n) ")
                if smartfail.lower() != "y":
                    sys.exit(0)
    except:
        pass

    # Current Pending Sector Count
    try:
        CPSC = re.search('(\d+)$', str(smart.attributes[197])).group(1)
        if CPSC != "0" and str(smart.attributes[197]) != "None":
            print("Current Pending Sector Count: " + CPSC)
            smartfail = input("SMART reports drive issues. Continue? (y/n) ")
            if passno == 1:
                if smartfail.lower() != "y":
                    sys.exit(0)
    except:
        pass

    # Uncorrectable Sector Count
    try:
        USC = re.search('(\d+)$', str(smart.attributes[198])).group(1)
        if USC != "0" and str(smart.attributes[198]) != "None":
            print("Uncorrectable Sector Count: " + USC)
            if passno == 1:
                smartfail = input("SMART reports drive issues. Continue? (y/n) ")
                if smartfail.lower() != "y":
                    sys.exit(0)
    except:
        pass

    # Power On Hours - informational
    try:
        POH = re.search('(\d+)$', str(smart.attributes[9])).group(1)
        print("Power On Hours: " + POH)
    except:
        pass

    #print(smart.attributes[9])
    #print(smart.all_attributes())
    #print(smart.tests[0])
    #print(smart.all_selftests())
    # some devices do not support SMART attributes - so that will need to be handled
    #print(smart.name)
    #print(smart.model)
    #print(smart.serial)
    #print(smart.smart_capable)
    #print(smart.smart_enabled)
    #print(smart.messages)
    #print(dir(smart))
    smartdict = smart.__dict__
    try:
        if smartdict['diagnostics']:
            smartdict['diagnostics'] = smart.diagnostics.__dict__
    except:
        pass
    try:
        if smartdict['smartctl']:
            smartdict['smartctl'] = smart.smartctl.__dict__
    except:
        pass
    try:
        if smartdict['tests']:
            # loop through the array and replace
            for i in smart.tests:
                smartdict['tests'][int(i.num)-1] = smart.tests[int(i.num)-1].__dict__
    except:
        pass

    #print(dir(smart.attributes))
    # TODO - this breaks with pySMART v1.3.0
    for i in smart.attributes:
        if i:
            smartdict['attributes'][int(i.num)] = i.__dict__
    #import pprint
    #pprint.pprint(smartdict)
    #print()
    return smartdict

def drivemap():
    # quick mapping of the data on the drive for stats
    cleancount = 0
    dirtycount = 0
    os.lseek(block, 0, os.SEEK_SET)
    flushcaches()
    starttime = time.time() # reset the clock
    for devpos in range(0, (devsize), blocksize):
        bytesin = os.read(block,blocksize)
        if bytesin == nullbytes:
            cleancount = cleancount + blocksize
        else:
            dirtycount = dirtycount + blocksize
        percentdone = ("%6.3f" % (((devpos+blocksize) / devsize) * 100))
        # calc runtime
        runtime = (time.time() - starttime)
        # calc average speed
        # avgspd = ("%0.2f" % (devpos / runtime / 1024 / 1024))
        # calc time remaining
        #if runtime > 0 and devpos > 0:
        #    etasec = math.floor((devsize - devpos) / (devpos / runtime))
        #    etatime = str(datetime.timedelta(seconds=etasec))
        #else:
        #    etatime = "-:--:--"
        # calc percent dirty / clean
        cleanpct = ("%3.3f" % ((cleancount / devsize) * 100))
        dirtypct = ("%3.3f" % ((dirtycount / devsize) * 100))

        status = "Mapping: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  Dirty: " + trmred + \
                 dirtypct + "% " + trmnorm + " Clean: " + trmgrn + cleanpct + "%" + trmnorm + "\r"
        sys.stdout.write(status)
    sys.stdout.write("\n")
    if dirtycount == 0:
        print(trmgrn + "Drive is sterile and only contains 0x00." + trmnorm)
        return "clean","Drive mapped. Drive is sterile and only contains 0x00."
    else:
        print(trmred + "Drive is not sterile." + trmnorm)
        return "dirty","Drive mapped. Drive is dirty and contains non-nulled data. " + cleanpct + "% clean and " + dirtypct + "% dirty."

def fulltest():
    # this will run the media through a full wipe and verify test FF,verify,00,verify - designed for full drive
    # testing or first-time wipe and verify of new media or hunting for stuck bits
    #devsize = 1073741824 # DEBUG override 1GB
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time() # reset the clock
    for devpos in range(0, (devsize), blocksize):
        #print(devpos, devsize)
        #if devpos == devsize:
        #    print("\n")
        #    exit()
        percentdone = ("%6.3f" % (((devpos+blocksize) / devsize) * 100))
        # calc runtime
        runtime = (time.time() - starttime)
        # calc average speed
        avgspd = ("%0.2f" % ((devpos+blocksize) / runtime / 1024 / 1024))
        # calc time remaining
        if runtime > 0 and devpos > 0:
            etasec = math.floor((devsize - devpos) / ((devpos+blocksize) / runtime))
            etatime = str(datetime.timedelta(seconds=etasec))
        else:
            etatime = "-:--:--"

        #writing ones
        os.write(block, onesbytes)
        # sync can wait for the end
        #os.sync()
        status = "Writing 0xFF: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmred + "FF " + \
                trmnorm + " TTC: " + etatime + " @ " + avgspd + " MBps  \r"
        sys.stdout.write(status)

    # at the end gof the write pass show the elapsed time on the command line
    runtimesec = math.floor(runtime)
    runtimefmt = str(datetime.timedelta(seconds=runtimesec))
    status = "Wrote 0xFF: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmgrn + "-- " + \
                    trmnorm + " ET: " + runtimefmt + " @ " + avgspd + " MBps   \r"
    # sync all writes
    sys.stdout.write("\nSyncing...\r")
    os.sync()
    ffwriteruntime = (time.time() - starttime)
    # flush the cache
    flushcaches()
    # Then read back every block and verify - if there are any mismatches, die.
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time()
    for devpos in range(0, (devsize), blocksize):
        #print(devpos, devsize)
        percentdone = ("%6.3f" % (((devpos+blocksize) / devsize) * 100))
        # calc runtime
        runtime = (time.time() - starttime)
        # calc average speed
        avgspd = ("%0.2f" % ((devpos+blocksize) / runtime / 1024 / 1024))
        # calc time remaining
        if runtime > 0 and devpos > 0:
            etasec = math.floor((devsize - devpos) / (devpos / runtime))
            etatime = str(datetime.timedelta(seconds=etasec))
        else:
            etatime = "-:--:--"

        #reading ones
        bytesin = os.read(block, blocksize)
        if bytesin != onesbytes:
            # this write failed - throw an error and stop
            wipefail(block, devpos, blocksize, "FF")
        # sync can wait for the end
        #os.sync()
        status = "Verifying 0xFF: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmgrn + "-- " + \
                trmnorm + " TTC: " + etatime + " @ " + avgspd + " MBps  \r"
        sys.stdout.write(status)
    ffverifyruntime = (time.time() - starttime)
    print()
    # Now repeat for x00 across the whole drive
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time()
    for devpos in range(0, (devsize), blocksize):
        #print(xx, devsize)
        percentdone = ("%6.3f" % (((devpos+blocksize) / devsize) * 100))
        # calc runtime
        runtime = (time.time() - starttime)
        # calc average speed
        avgspd = ("%0.2f" % ((devpos+blocksize) / runtime / 1024 / 1024))
        # calc time remaining
        if runtime > 0 and devpos > 0:
            etasec = math.floor((devsize - devpos) / (devpos / runtime))
            etatime = str(datetime.timedelta(seconds=etasec))
        else:
            etatime = "-:--:--"

        # writing zeroes
        os.write(block, nullbytes)
        # sync can wait for the end
        #os.sync()
        status = "Writing 0x00: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmred + "00 " + \
                trmnorm + " TTC: " + etatime + " @ " + avgspd + " MBps  \r"
        sys.stdout.write(status)

    # at the end gof the write pass show the elapsed time on the command line
    runtimesec = math.floor(runtime)
    runtimefmt = str(datetime.timedelta(seconds=runtimesec))
    status = "Wrote 0x00: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmgrn + "-- " + \
                    trmnorm + " ET: " + runtimefmt + " @ " + avgspd + " MBps   \r"
    # sync all writes
    sys.stdout.write("\nSyncing...\r")
    os.sync()
    zzwriteruntime = (time.time() - starttime)
    # flush the cache
    flushcaches()
    # Then read back every block and verify - if there are any mismatches, die.
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time()
    for devpos in range(0, (devsize), blocksize):
        #print(xx, devsize)
        percentdone = ("%6.3f" % (((devpos+blocksize) / devsize) * 100))
        # calc runtime
        runtime = (time.time() - starttime)
        # calc average speed
        avgspd = ("%0.2f" % ((devpos+blocksize) / runtime / 1024 / 1024))
        # calc time remaining
        if runtime > 0 and devpos > 0:
            etasec = math.floor((devsize - devpos) / (devpos / runtime))
            etatime = str(datetime.timedelta(seconds=etasec))
        else:
            etatime = "-:--:--"

        #reading ones
        bytesin = os.read(block, blocksize)
        if bytesin != nullbytes:
            # this write failed - throw an error and stop
            wipefail(block, devpos, blocksize, "00")
        # sync can wait for the end
        #os.sync()
        status = "Verifying 0x00: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmgrn + "00 " + \
                trmnorm + " TTC: " + etatime + " @ " + avgspd + " MBps  \r"
        sys.stdout.write(status)
    # at the end gof the write pass show the elapsed time on the command line
    runtimesec = math.floor(runtime)
    runtimefmt = str(datetime.timedelta(seconds=runtimesec))
    status = "Verified 0x00: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmgrn + "00 " + \
                    trmnorm + " ET: " + runtimefmt + " @ " + avgspd + " MBps   \r"
    zzverifyruntime = (time.time() - starttime)
    print()
    mailsubject = "[wiper] Double wipe and verification completed"
    mailbody = "Device " + str(devname) + " has completed and is sterile.\n\n"
    # drivedict variables are available to fill in more details
    if inventory != "":
        mailbody += "Inventory No: " + str(inventory) + "\n"
    mailbody += "Model: " + str(drivedict['model']) + "\n"
    mailbody += "Serial: " + str(drivedict['serial']) + "\n"
    mailbody += "SMART health check: " + str(drivedict['assessment']) + "\n"
    mailbody += "Device size: " + ('{:,}'.format(devsize)) + " bytes\n"
    mailbody += "Block size: " + str(blocksize) + "\n"
    ffwritespeed = ("%0.2f" % (devsize / ffwriteruntime / 1024 / 1024))
    mailbody += "FF Writes: " + str(datetime.timedelta(seconds=int(ffwriteruntime))) + " @ " + ffwritespeed + " MBps\n"
    ffverifyspeed = ("%0.2f" % (devsize / ffverifyruntime / 1024 / 1024))
    mailbody += "FF Vertfy: " + str(datetime.timedelta(seconds=int(ffverifyruntime))) + " @ " + ffverifyspeed + " MBps\n"
    zzwritespeed = ("%0.2f" % (devsize / zzwriteruntime / 1024 / 1024))
    mailbody += "00 Writes: " + str(datetime.timedelta(seconds=int(zzwriteruntime))) + " @ " + zzwritespeed + " MBps\n"
    zzverifyspeed = ("%0.2f" % (devsize / zzverifyruntime / 1024 / 1024))
    mailbody += "00 Vertfy: " + str(datetime.timedelta(seconds=int(zzverifyruntime))) + " @ " + zzverifyspeed + " MBps\n"
    totalruntime = ffwriteruntime + ffverifyruntime + zzwriteruntime + zzverifyruntime
    mailbody += "Total run: " + str(datetime.timedelta(seconds=totalruntime)) + "\n"
    averagewrite = ("%0.2f" % ((devsize*2) / (ffwriteruntime + zzwriteruntime) / 1024 / 1024))
    averageread = ("%0.2f" % ((devsize*2) / (ffverifyruntime + zzverifyruntime) / 1024 / 1024))
    mailbody += "Average R/W speed: " + str(averageread) + " / " + str(averagewrite) + " MBps\n"

    if mailactive != "0":
        email_notify(mailactive, mailserver, maillogin, mailpassword, mailfrom, mailto, mailsubject, mailbody)
    return "verified", "Double wiped and fully verified."

def singlepass():
    # this will run the media through a full wipe and verify test FF,verify,00,verify - designed for full drive
    # testing or first-time wipe and verify of new media or hunting for stuck bits
    os.lseek(block, 0, os.SEEK_SET)
    starttime = time.time() # reset the clock
    for devpos in range(0, (devsize), blocksize):
        #print(devpos, devsize)
        #if devpos == devsize:
        #    print("\n")
        #    exit()
        percentdone = ("%6.3f" % (((devpos+blocksize) / devsize) * 100))
        # calc runtime
        runtime = (time.time() - starttime)
        # calc average speed
        avgspd = ("%0.2f" % ((devpos+blocksize) / runtime / 1024 / 1024))
        # calc time remaining
        if runtime > 0 and devpos > 0:
            etasec = math.floor((devsize - devpos) / (devpos / runtime))
            etatime = str(datetime.timedelta(seconds=etasec))
        else:
            etatime = "-:--:--"

        #writing zeroes
        os.write(block, nullbytes)
        # sync can wait for the end
        #os.sync()
        status = "Writing 0x00: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmred + "00 " + \
                trmnorm + " TTC: " + etatime + " @ " + avgspd + " MBps  \r"
        sys.stdout.write(status)

    # at the end gof the write pass show the elapsed time on the command line
    runtimesec = math.floor(runtime)
    runtimefmt = str(datetime.timedelta(seconds=runtimesec))
    status = "Wrote 0x00: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmgrn + "-- " + \
                    trmnorm + " ET: " + runtimefmt + " @ " + avgspd + " MBps   \r"
    # sync all writes
    sys.stdout.write("\nSyncing...\r")
    os.sync()
    # Then read back every block and verify - if there are any mismatches, die.
    # flush the cache
    flushcaches()
    os.lseek(block, 0, os.SEEK_SET)
    for devpos in range(0, (devsize), blocksize):
        #print(devpos, devsize)
        percentdone = ("%6.3f" % (((devpos+blocksize) / devsize) * 100))
        # calc runtime
        runtime = (time.time() - starttime)
        # calc average speed
        avgspd = ("%0.2f" % ((devpos+blocksize) / runtime / 1024 / 1024))
        # calc time remaining
        if runtime > 0 and devpos > 0:
            etasec = math.floor((devsize - devpos) / (devpos / runtime))
            etatime = str(datetime.timedelta(seconds=etasec))
        else:
            etatime = "-:--:--"

        #reading ones
        bytesin = os.read(block, blocksize)
        if bytesin != nullbytes:
            # this write failed - throw an error and stop
            wipefail(block, devpos, blocksize, "00")
        # sync can wait for the end
        #os.sync()
        status = "Verifying 0x00: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmgrn + "00 " + \
                trmnorm + " TTC: " + etatime + " @ " + avgspd + " MBps  \r"
        sys.stdout.write(status)
    # at the end gof the write pass show the elapsed time on the command line
    runtimesec = math.floor(runtime)
    runtimefmt = str(datetime.timedelta(seconds=runtimesec))
    status = "Verified 0x00: " + ('{:,}'.format(devpos+blocksize)) + " (" + percentdone + "%)  State: " + trmgrn + "00 " + \
                    trmnorm + " ET: " + runtimefmt + " @ " + avgspd + " MBps   \r"
    print()
    return "clean", "Single pass with nulls. Verified clean."

def hidecursor():
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()

def showcursor():
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()

def rootcheck():
    # make sure we are running as root
    if os.getuid() != 0:
        print("Error: This program must be run as root. Exiting.")
        showcursor()
        sys.exit(1)
    return

def rewipe():
    # sometimes a sector fails to wipe correctly and needs a little help
    # call this when a verification on a sector fails
    # TODO
    # get: sector, blocksize, pattern
    # seek to sector, write pattern of blocksize, os.sync() ...
    # re-seek to sector, check blocksize for pattern
    # return if it checks out, die if it fails again.
    # this will require some interesting logging and testing
    return

def dbcheck(client):
    # see if the database is online and set a var for the updater
    print("Checking database connection...")
    try:
        serverinfo = client.server_info()
    except:
        nodb = input("Database unreachable. Continue? (y/n) ")
        if nodb.lower() == "y":
            return False
        else:
            sys.exit(1)
    return True

def dbupdate(collection, drivedict):
    if mongohost != "0":
        print("Updating database...")
        collection.insert_one(drivedict)
        return
    else:
        return

def email_notify(mailactive, mailserver, maillogin, mailpassword, mailfrom, mailto, mailsubject, mailbody):
    if mailactive != "1":
        return

    # Prepare message
    message = """From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (mailfrom, mailto, mailsubject, mailbody)

    try:
        server = smtplib.SMTP(mailserver)
        server.starttls()
        server.login(maillogin, mailpassword)
        server.sendmail(mailfrom, mailto, message)
        server.quit()
        return
    except:
        print("Failed sending email message")
        return

def cleanup():
    # things we need to do on exit
    showcursor()

# TODO - consolidate API functions for asset management
def insertass(assdata):
    # update asset management system - add maintainence record at end
    assreq = asssvr + 'hardware'
    asshed = { 'Authorization' : 'Bearer ' + asstok , 'accept' : 'application/json', 'content-type' : 'application/json' }
    response = requests.post(assreq, headers=asshed, json=assdata)
    if response.status_code == 200:
        pass
    elif response.status_code == 404:
        sys.exit('Error: Asset server endpoint ' + asssvr + ' not found. ' + response.text )
    elif response.status_code == 401:
        sys.exit('Error: Asset server authorization failed. Check your API token. ' + response.text )
    else:
        sys.exit('Unexpected response from API: ' + str(response.status_code) + ' ' + response.text )
    respdict = response.json()
    if 'status' in respdict.keys():
        if respdict['status'] == 'error':
            sys.exit('Asset server error: ' + json.dumps(respdict['messages']))
    print("Asset management skeleton record inserted. Please review.")
    return respdict['payload']['id'] #int

def assupdate(assdata):
    # update asset management system - add maintainence record at end
    assreq = asssvr + 'maintenances'
    asshed = { 'Authorization' : 'Bearer ' + asstok , 'accept' : 'application/json', 'content-type' : 'application/json' }
    response = requests.post(assreq, headers=asshed, json=assdata)
    if response.status_code == 200:
        pass
    elif response.status_code == 404:
        sys.exit('Error: Asset server endpoint ' + asssvr + ' not found. ' + response.text )
    elif response.status_code == 401:
        sys.exit('Error: Asset server authorization failed. Check your API token. ' + response.text )
    else:
        sys.exit('Unexpected response from API: ' + str(response.status_code) + ' ' + response.text )
    respdict = response.json()
    if 'status' in respdict.keys():
        if respdict['status'] == 'error':
            sys.exit('Asset server error: ' + json.dumps(respdict['messages']))
    print("Asset management records updated.")
    return

def chatnotify(message):
    # internal corvus spreed server - I expect you will need to adjust to suit your needs to send notifications
    print("Notifying via chat.")
    chathed = json.loads(chathead)
    messageenc = urllib.parse.quote(message)
    chatreq = chatendp + messageenc
    if chatmeth == "POST":
        response = requests.post(chatreq, headers=chathed)
    elif chatmeth == "GET":
        response = requests.get(chatreq, headers=chathed)
    return

import atexit
atexit.register(cleanup)

# calling main functions here - need to do this with arguments eventually
rootcheck()
hidecursor()
if mongohost != "0":
    dblive = dbcheck(client)
else:
    nodb = input("Logging database unreachable or not configured. Continue? (y/n) ")
    if nodb.lower() == "y":
        dblive = False
    else:
        sys.exit(1)
drivedict = healthcheck(1)
# try to fix badly named keys
try:
    drivedict['capacity'] = drivedict.pop('_capacity')
except:
    pass
# append vars to dict
drivedict['timestamp'] = int(time.time())
drivedict['wipestate'] = "precheck"
if inventory:
    drivedict['inventory'] = inventory

    # check asset management
    if assman == "1":
        # try to connect and get information about the drive from asset management
        # lookup by asset tag
        assreq = asssvr + 'hardware/bytag/' + inventory + '/?deleted=false'
        asshed = { 'Authorization' : 'Bearer ' + asstok , 'accept' : 'application/json' }
        response = requests.get(assreq, headers=asshed)
        if response.status_code == 200:
            pass
        elif response.status_code == 404:
            sys.exit('Error: Asset server endpoint ' + asssvr + ' not found. ' + response.text )
        elif response.status_code == 401:
            sys.exit('Error: Asset server authorization failed. Check your API token. ' + response.text )
        else:
            sys.exit('Unexpected response from API: ' + str(response.status_code) + ' ' + response.text )
        respdict = response.json()

        if 'status' in respdict.keys():
            if respdict['status'] == 'error' and respdict['messages'] == 'Asset does not exist.':
                # ask if they want to create an asset with this inventory number
                setid = input("Device with inventory number " + inventory + " not found in asset management.\nCreate a new record for this device? (y/n/q) ")
                if setid.lower() == "y":
                    drivenotes = ""
                    if '_vendor' in drivedict.keys():
                        drivenotes += 'Vendor: ' + str(drivedict['_vendor']) + '\n'
                    if 'model' in drivedict.keys():
                        drivenotes += 'Model: ' + drivedict['model'] + '\n'
                    if 'capacity' in drivedict.keys():
                        drivenotes += 'Capacity: ' + str(drivedict['capacity'])
                    if '_capacity_human' in drivedict.keys():
                        drivenotes += ' (' + drivedict['_capacity_human'] + ')'
                    else:
                        drivenotes += ''
                    assdata = { 'asset_tag' : inventory, 'status_id' : 1, 'model_id' : 32, 'serial' : drivedict['serial'], 'notes' : drivenotes }
                    # insert record and get id
                    assid = insertass(assdata)

                elif setid.lower() == 'n':
                    pass
                else:
                    # a non yes or no answer will quit
                    sys.exit("Exiting.")

        elif 'id' in respdict.keys():
            assid = respdict['id'] # integer

        elif respdict['status'] == 'error':
            sys.exit('Asset server error: ' + json.dumps(respdict['messages']))
else:
    # if inventory is not specified - check by serial number just in case
    if assman == "1":
        assreq = asssvr + 'hardware/byserial/' + drivedict['serial'] + '/?deleted=false'
        asshed = { 'Authorization' : 'Bearer ' + asstok , 'accept' : 'application/json' }
        response = requests.get(assreq, headers=asshed)
        if response.status_code == 200:
            pass
        elif response.status_code == 404:
            sys.exit('Error: Asset server endpoint ' + asssvr + ' not found. ' + response.text )
        elif response.status_code == 401:
            sys.exit('Error: Asset server authorization failed. Check your API token. ' + response.text )
        else:
            sys.exit('Unexpected response from API: ' + str(response.status_code) + ' ' + response.text )

        respdict = response.json()
        # this may return multiple rows from the database

        if 'status' in respdict.keys():
            if respdict['status'] == 'error' and respdict['messages'] == 'Asset does not exist.':
                # ask if they want to create an asset? no. specify -i instead
                pass # its fine.

        if 'total' in respdict.keys():
            if respdict['total'] == 1:
                # only 1 row - makes things easy
                foundid = respdict['rows'][0]['id']
                foundinv = respdict['rows'][0]['asset_tag']
                setid = input("Drive with matching serial number " + drivedict['serial'] + " found in asset management with inventory number " + foundinv + ".\nUse this inventory number? (y/n/q) ")
                if setid.lower() == "y":
                    assid = foundid
                    inventory = foundinv
                    drivedict['inventory'] = inventory
                elif setid.lower() == 'n':
                    pass
                else:
                    # a non yes or no answer will quit
                    sys.exit("Exiting.")
            elif respdict['total'] > 1:
                # multiple entries - which should not happen.
                print('Multiple records with the same serial number are in the database:')
                tmpdic = {} # quick cheater map
                for row in respdict['rows']:
                    tmpdic[str(row['id'])] = row['asset_tag']
                    print('ID: ' + str(row['id'])  + '\tINV: ' + row['asset_tag'] + '\tSerial: ' + row['serial'])
                getinv = input("Please enter the record ID number to associate with this device or leave blank to ignore: ")
                if getinv != "":
                    assid=int(getinv.strip())
                    inventory=tmpdic[getinv.strip()]
                else:
                    inventory = False
                    assman = "0"

        #if 'status' in respdict.keys():
        #    if respdict['status'] == 'error':
        #        sys.exit('Asset server error: ' + json.dumps(respdict['messages']))
        # get the asset database id for later use and updating records

if dblive:
    dbupdate(collection, drivedict)
wipestate = '' # clean, dirty, verified, error
wipenotes = ''
#TODO: Feed this program some very problematic drives for testing.
#wipestate, wipenotes = checkblock() # check, write 00 if not nulled - intended for flash/ssd/nvme

start_date = datetime.date.today()

if args.check:
    wipestate, wipenotes = drivemap()
elif args.smart:
    wipestate, wipenotes = checkblock()
elif args.zero:
    wipestate, wipenotes = singlepass()
elif args.full:
    wipestate, wipenotes = fulltest()
else:
    wipestate, wipenotes = fulltest()

#wipestate, wipenotes = fulltest() # ff, check, 00, check - all sectors - full verification - modified "NIST 800-88 Advanced" or half "Bit Toggle"
#wipestate, wipenotes = singlepass() # 00, check - all sectors "NIST SP 800-88 Rev. 1"
#wipestate, wipenotes = drivemap() # read-only check if drive is clean
drivedict = healthcheck(2) # second health check post-wipe
# try to fix badly named keys
try:
    drivedict['capacity'] = drivedict.pop('_capacity')
except:
    pass
# append vars to dict
drivedict['timestamp'] = int(time.time())
drivedict['wipestate'] = wipestate
drivedict['wipenotes'] = wipenotes
if inventory:
    drivedict['inventory'] = inventory
if dblive:
    dbupdate(collection, drivedict)
showcursor()
# TODO notify() # that wipe is completed and state of process

# update asset management if applicable
if assman != "0" and inventory:
    completion_date = datetime.date.today()
    maintnotes = wipenotes
    maintnotes += "\nSMART Check: " + drivedict['assessment']
    assdata = { 'asset_id' : assid, 'supplier_id' : 3, 'start_date' : str(start_date), 'completion_date' : str(completion_date), 'asset_maintenance_type' : 'Maintainance', 'title' : wipestate.capitalize() , 'notes' : maintnotes }
    assupdate(assdata)

if chatty != "0":
    # notify via chat channel api that the drive is done
    message = "Media Sanitization Notification:"
    if inventory:
        message += "\nInventory: " + inventory
    if '_vendor' in drivedict:
        message += "\nVendor: " + str(drivedict['_vendor'])
    if 'model' in drivedict:
        message += "\nModel: " + str(drivedict['model'])
    if 'family' in drivedict:
        message += "\nFamily: " + str(drivedict['family'])
    if 'capacity' in drivedict:
        message += "\nSize: " + str(drivedict['capacity'])
    if '_capacity_human' in drivedict:
        message += " (" + str(drivedict['_capacity_human']) + ")"
    message += "\nState: " + wipestate.capitalize()
    message += "\n" + wipenotes
    message += "\nSMART Check: " + drivedict['assessment']
    chatnotify(message)
