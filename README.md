# wiper

OWL - Optimized Wipe and Logging forensic hard drive sterilizer and tester.

**This code will irretrievably destroy data on the target media by design. Use at your own risk. Corvus Forensics assumes zero responsibility for misuse.**

This is a copy of the code developed and used by Corvus Forensics to wipe and verify digital media, including the tracking of usage and disk health with drive inventory numbers. It must be run either as root or a user with sufficient privileges to access block devices and query SMART disk health.

Usage:

```
wiper.py [-h] [-f] [-s] [-z] [-c] [-i INVENTORY] target

Health check, sterilization, verification, and logging for data storage devices.

positional arguments:
  target                Path to block device

options:
  -h, --help            show this help message and exit
  -f, --full            Full double wipe and verify [default]
  -s, --smart           Perform smart wipe
  -z, --zero            Single pass of null bytes
  -c, --check           verify media contains only nulls
  -i INVENTORY, --inventory INVENTORY
                        add media inventory number to record
```

Default 'full' wipe pattern is write 0xFF, read verify, write 0x00, read verify.

The 'smart' option reads each block of data to determine if wiping is required or if the block is already forensically sterile and full of 0x00 or null-bytes. This option is intended for use with flash-based media such as SSDs where regular overwriting of blocks will shorten the media lifetime.

This program was developed to be consistent with NIST SP 800-88 R1 Guidelines for Media Sanitization "Clear" method for attached storage where a single pass with a fixed data value to the target media is sufficient to render the original data unreadable, even under laboratory conditions. The 'smart' and 'zero' options will overwrite data with zeros or null (hex 0x00) values. The 'full' double-wipe and verification method is the default to confirm all sectors of the drive are writeable, readable, and do not have any 'stuck' bits.
