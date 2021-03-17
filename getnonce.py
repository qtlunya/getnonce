#!/usr/bin/env python3

import base64
import os
import shutil
import subprocess
import time
import sys

import xmltodict


os.environ['PATH'] = os.pathsep.join(['.', os.environ['PATH']])
if not shutil.which('idevicediagnostics'):
    print('[-] ERROR: idevicediagnostics not found. Please place the binary in your PATH or the same folder as the script and try again.')
    sys.exit(1)


def wait_for_device():
    print('[*] Waiting for USB device (make sure the device is unlocked)')
    while True:
        # Run a dummy command to make sure the device is connected and unlocked.
        # `idevice_id -l` doesn't appear to be enough.
        p = subprocess.run(['idevicediagnostics', 'diagnostics'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if p.returncode == 0:
            return True
        time.sleep(1)


wait_for_device()
print('[+] Getting ApNonce')
#p = subprocess.run(['igetnonce'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
#sys.stdout.write(p.stdout.decode('utf-8'))
#if p.returncode != 0:
#    print('[-] ERROR: ' + p.stdout.decode('utf-8'))
#    sys.exit(1)
p = subprocess.run(['idevicediagnostics', 'mobilegestalt', 'ApNonce'], stdout=subprocess.PIPE)
xml = xmltodict.parse(p.stdout)
try:
    apnonce = f"{int.from_bytes(base64.b64decode(xml['plist']['dict']['dict']['data']), 'big'):x}"
except KeyError:
    print('[-] ERROR: Unable to read ApNonce')
    sys.exit(1)
else:
    print(f'ApNonce = {apnonce}')

print('[+] Rebooting device')
p = subprocess.run(['idevicediagnostics', 'restart'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
if p.returncode != 0:
    print('[-] ERROR: ' + p.stdout.decode('utf-8'))
    sys.exit(1)

wait_for_device()
print('[+] Getting BootNonce')
p = subprocess.run(['idevicediagnostics', 'mobilegestalt', 'BootNonce'], stdout=subprocess.PIPE)
xml = xmltodict.parse(p.stdout)
try:
    bootnonce = f"{int.from_bytes(base64.b64decode(xml['plist']['dict']['dict']['data']), 'little'):x}"
except KeyError:
    print('[-] ERROR: Unable to read BootNonce')
    sys.exit(1)
else:
    print(f'BootNonce = 0x{bootnonce}')
