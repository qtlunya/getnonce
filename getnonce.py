#!/usr/bin/env python3

import base64
import os
import shutil
import subprocess
import time
import sys
from typing import Optional

import xmltodict


def wait_for_device() -> None:
    """Wait for a device that's connected over USB and unlocked."""
    print('[*] Waiting for USB device (make sure the device is unlocked)')
    while True:
        # Run a dummy command to make sure the device is connected and unlocked.
        # `idevice_id -l` doesn't appear to be enough.
        p = subprocess.run(['idevicediagnostics', 'diagnostics'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if p.returncode == 0:
            return
        time.sleep(1)


def mobilegestalt_read_bytes(key: str, endianness: str) -> Optional[str]:
    """Read bytes with the specified endianness from MobileGestalt and return it as a hex string."""
    p = subprocess.run(['idevicediagnostics', 'mobilegestalt', key], stdout=subprocess.PIPE)
    xml = xmltodict.parse(p.stdout)
    try:
        value = base64.b64decode(xml['plist']['dict']['dict']['data'])
    except KeyError:
        return None
    return '{:x}'.format(int.from_bytes(value, endianness))


if __name__ == '__main__':
    os.environ['PATH'] = os.pathsep.join(['.', os.environ['PATH']])
    if not shutil.which('idevicediagnostics'):
        print('[-] ERROR: idevicediagnostics not found. Please place the binary in your PATH or the same folder as the script and try again.')
        sys.exit(1)

    wait_for_device()
    print('[+] Getting ApNonce')
    apnonce = mobilegestalt_read_bytes('ApNonce', 'big')
    if apnonce:
        print(f'ApNonce = {apnonce}')
    else:
        print('[-] ERROR: Unable to read ApNonce')
        sys.exit(1)

    print('[+] Rebooting device')
    p = subprocess.run(['idevicediagnostics', 'restart'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        print('[-] ERROR: ' + p.stdout.decode('utf-8'))
        sys.exit(1)

    wait_for_device()
    print('[+] Getting BootNonce')
    bootnonce = mobilegestalt_read_bytes('BootNonce', 'little')
    if bootnonce:
        print(f'BootNonce = 0x{bootnonce}')
    else:
        print('[-] ERROR: Unable to read BootNonce')
        sys.exit(1)
