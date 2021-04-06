#!/usr/bin/env python3

import base64
import os
import shutil
import subprocess
import time
import sys
from typing import Optional

import xmltodict
from termcolor import colored


def run_process(command: str, *args: str, silence_errors: bool = False) -> Optional[str]:
    """Run a command with the specified arguments."""

    p = subprocess.run([command, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8')

    if p.returncode != 0:
        if silence_errors:
            return None
        else:
            print(colored(p.stdout, 'red'))
            sys.exit(1)

    return p.stdout.strip()


def wait_for_device(mode: str) -> None:
    """Wait for a device to be connected over USB and unlocked."""

    if mode == 'normal':
        print(colored('Waiting for device to be connected and unlocked', 'yellow'), end='', flush=True)

        while not run_process('idevicediagnostics', 'diagnostics', silence_errors=True):
            print(colored('.', 'yellow'), end='', flush=True)
            time.sleep(1)
    elif mode == 'recovery':
        print('Waiting for device', end='', flush=True)

        while not run_process('irecovery', '-m', silence_errors=True):
            print('.', end='', flush=True)

    print()


def mobilegestalt_read_bytes(key: str, endianness: str) -> Optional[str]:
    """Read bytes with the specified endianness from MobileGestalt and return it as a hex string."""

    xml = xmltodict.parse(run_process('idevicediagnostics', 'mobilegestalt', key))

    try:
        value = base64.b64decode(xml['plist']['dict']['dict']['data'])
    except KeyError:
        return None
    else:
        return '{:x}'.format(int.from_bytes(value, endianness))


def pad_apnonce(apnonce: str) -> str:
    """Pad an ApNonce to 64 characters (A10 and above) or 40 characters (A9 and below)."""

    padded = apnonce.zfill(64)

    if padded[0:24] == '000000000000000000000000':
        return padded[24:]
    else:
        return padded


def get_recovery_apnonce(old_apnonce) -> str:
    """Read the ApNonce in recovery mode."""

    apnonce = None

    wait_for_device(mode='recovery')

    info = run_process('irecovery', '-q')

    if not info:
        print(colored('ERROR: Unable to read ApNonce', 'red'))
        sys.exit(1)

    for line in info.splitlines():
        key, value = line.split(': ')
        if key == 'NONC':
            apnonce = value
            break

    if apnonce:
        print(colored(f'ApNonce = {apnonce}', 'green'))
    else:
        print(colored('ERROR: Unable to read ApNonce', 'red'))
        sys.exit(1)

    if old_apnonce and apnonce != old_apnonce:
        print(colored('ERROR: ApNonce does not match', 'red'))

        print('Exiting recovery mode')
        run_process('irecovery', '-n')

        sys.exit(1)

    return apnonce


if __name__ == '__main__':
    os.environ['PATH'] = os.pathsep.join(['.', os.environ['PATH']])
    for binary in ['idevice_id', 'idevicediagnostics', 'irecovery']:
        if not shutil.which(binary):
            print(colored(f'ERROR: {binary} not found. Please place the binary in your PATH or the same folder as the script and try again.', 'red'))
            sys.exit(1)

    answer = input('Is your device jailbroken? [y/n] ')
    if answer.lower() == 'y':
        jailbroken = True
    elif answer.lower() == 'n':
        jailbroken = False
    else:
        print(colored('ERROR: Invalid input', 'red'))
        sys.exit(1)

    # If the device is not jailbroken, get the ApNonce in normal mode, which will set a new random generator.
    if jailbroken:
        apnonce = None
    else:
        wait_for_device(mode='normal')
        apnonce = mobilegestalt_read_bytes('ApNonce', 'big')
        if apnonce:
            apnonce = pad_apnonce(apnonce)
            print(colored(f'ApNonce = {apnonce}', 'green'))
        else:
            print(colored('ERROR: Unable to read ApNonce', 'red'))
            sys.exit(1)

    # Read the ApNonce in recovery mode to confirm it matches.
    # Only try and enter recovery if it's not already in recovery
    if run_process('irecovery', '-m', silence_errors=True) != 'Recovery Mode':
        print('Entering recovery mode')
        udid = run_process('idevice_id', '-l')
        if not udid:
            print(colored('ERROR: Unable to find device', 'red'))
            sys.exit(1)
        run_process('ideviceenterrecovery', udid)
    apnonce = get_recovery_apnonce(apnonce)

    # Reset and read it again to make sure the generator was set properly.
    print('Sending reset command')
    run_process('irecovery', '-c', 'reset')
    # Wait a bit, otherwise it thinks the device is already in recovery, tries to get nonce, device reboots, gets N/A
    time.sleep(5)
    apnonce = get_recovery_apnonce(apnonce)

    # Return to normal mode and get the generator.
    print('Exiting recovery mode')
    run_process('irecovery', '-n')
    wait_for_device(mode='normal')
    generator = mobilegestalt_read_bytes('BootNonce', 'little')
    if generator:
        print(colored(f'Generator = 0x{generator.zfill(16)}', 'green'))
    else:
        print(colored('ERROR: Unable to read generator', 'red'))
        sys.exit(1)
