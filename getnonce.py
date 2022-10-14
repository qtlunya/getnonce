#!/usr/bin/env python3

import atexit
import base64
import os
import plistlib
import shutil
import signal
import subprocess
import sys
import time

from rich.console import Console
from rich.markup import escape
from rich.prompt import Confirm


signal.signal(signal.SIGINT, signal.SIG_DFL)

console = Console(highlight=False)
print = console.print


@atexit.register
def finish():
    print("\nPress Enter to exit.")
    input()


def run_process(command, *args, silence_errors=False, timeout=None):
    """Run a command with the specified arguments."""
    try:
        p = subprocess.run(
            [command, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return None

    if p.returncode != 0:
        if silence_errors:
            return None
        else:
            print(f"[red]{escape(p.stdout)}[/red]")
            sys.exit(1)

    return p.stdout.strip()


def wait_for_device(mode):
    """Wait for a device to be connected over USB and unlocked."""

    if mode == "normal":
        print("[yellow]Waiting for device to be connected and unlocked[/yellow]", end="")

        while not run_process("idevicediagnostics", "diagnostics", silence_errors=True):
            print("[yellow].[/yellow]", end="")
            time.sleep(1)
    elif mode == "recovery":
        print("Waiting for device", end="")

        while not run_process("irecovery", "-m", silence_errors=True):
            print(".", end="")

    print()


def lockdownd_read_int(key):
    """Read an integer from lockdownd."""

    value = run_process("ideviceinfo", "-k", key).encode()
    return int(value) if value else None


def _format_bytes(value, endianness):
    return "{:x}".format(int.from_bytes(value, endianness)) if value else None


def lockdownd_read_bytes(key, endianness):
    """Read bytes with the specified endianness from lockdownd and return it as a hex string."""

    value = base64.b64decode(run_process("ideviceinfo", "-k", key).encode())
    return _format_bytes(value, endianness)


def mobilegestalt_read_bytes(key, endianness):
    """Read bytes with the specified endianness from MobileGestalt and return it as a hex string."""

    value = plistlib.loads(run_process("idevicediagnostics", "mobilegestalt", key).encode())["MobileGestalt"][key]
    return _format_bytes(value, endianness)


def pad_apnonce(apnonce):
    """Pad an ApNonce to 64 characters (A10 and above) or 40 characters (A9 and below)."""

    padded = apnonce.zfill(64)

    if padded[0:24] == "000000000000000000000000":
        return padded[24:]
    else:
        return padded


def get_recovery_apnonce(old_apnonce):
    """Read the ApNonce in recovery mode."""

    apnonce = None

    wait_for_device(mode="recovery")

    info = run_process("irecovery", "-q")

    if not info:
        print("[red]ERROR: Unable to read ApNonce[/red]")
        sys.exit(1)

    for line in info.splitlines():
        key, value = line.split(": ")
        if key == "NONC":
            apnonce = value
            break

    if apnonce:
        print(f"[green]ApNonce = [bold]{apnonce}[/bold][/green]")
    else:
        print("[red]ERROR: Unable to read ApNonce[/red]")
        sys.exit(1)

    if old_apnonce and apnonce != old_apnonce:
        print("[red]ERROR: ApNonce does not match[/red]")

        print("Exiting recovery mode")
        run_process("irecovery", "-n")

        sys.exit(1)

    return apnonce


if __name__ == "__main__":
    os.environ["PATH"] = os.pathsep.join([".", os.environ["PATH"]])
    for binary in ["idevice_id", "idevicediagnostics", "ideviceinfo", "irecovery"]:
        if not shutil.which(binary):
            print(
                f"[red]ERROR: {binary} not found. Please place the binary in your PATH "
                f"or the same folder as the script and try again.[/red]"
            )
            sys.exit(1)

    jailbroken = Confirm.ask("Is your device jailbroken?")

    # If the device is in recovery mode, exit it.
    print("\n[bold]\\[1/5] Checking device state[/bold]")
    if run_process("irecovery", "-m", silence_errors=True, timeout=1) == "Recovery Mode":
        print("Exiting recovery mode")
        run_process("irecovery", "-n")
    wait_for_device(mode="normal")

    print("\n[bold]\\[2/5] Getting ECID[/bold]")
    ecid = lockdownd_read_int("UniqueChipID")
    print(f"[green]ECID (hex) = [bold]{ecid:X}[/bold][/green]")

    # If the device is not jailbroken, get the ApNonce in normal mode, which will set a new random generator.
    print("\n[bold]\\[3/5] Getting ApNonce[/bold]")
    if jailbroken:
        print("Skipping on jailbroken device")
        apnonce = None
    else:
        apnonce = lockdownd_read_bytes("ApNonce", "big")
        if apnonce:
            apnonce = pad_apnonce(apnonce)
            print(f"[green]ApNonce = [bold]{apnonce}[/bold][/green]")
        else:
            print("[red]ERROR: Unable to read ApNonce[/red]")
            sys.exit(1)

    print("\n[bold]\\[4/5] Getting generator[/bold]")
    cpid = lockdownd_read_int("ChipID")
    if 0x8020 <= cpid < 0x8720:
        # A12+ device, we can take a shortcut and avoid rebooting
        # Note: This value is only available via MobileGestalt and not the regular lockdownd interface
        generator = mobilegestalt_read_bytes("ApNonceRetrieve", "little")
    else:
        # A11- device, we must reboot to obtain the up to date generator value
        print("Rebooting device")
        run_process("idevicediagnostics", "restart")
        wait_for_device(mode="normal")
        generator = lockdownd_read_bytes("BootNonce", "little")
    if generator:
        print(f"[green]Generator = [bold]0x{generator:016}[/bold][/green]")
    else:
        print("[red]ERROR: Unable to read generator[/red]")
        sys.exit(1)

    # Read the ApNonce in recovery mode to confirm it matches.
    print("\n[bold]\\[5/5] Verifying ApNonce[/bold]")
    print("Entering recovery mode")
    udid = run_process("idevice_id", "-l")
    if not udid:
        print("[red]ERROR: Unable to find device[/red]")
        sys.exit(1)
    run_process("ideviceenterrecovery", udid)
    apnonce = get_recovery_apnonce(apnonce)

    # Reset and read it again to make sure the generator was set properly.
    print("Rebooting device")
    run_process("irecovery", "-c", "reset")
    time.sleep(5)  # A delay is needed here to make sure it doesn't catch the device before it started exiting recovery
    apnonce = get_recovery_apnonce(apnonce)

    # Return to normal mode.
    print("Exiting recovery mode")
    run_process("irecovery", "-n")

    print("\n[bold]All done! You can go to https://tsssaver.1conan.com/v2/ to save blobs.[/bold]")
    print("Make sure to specify the ECID, ApNonce and generator values you got above.")
