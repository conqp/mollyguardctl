#! /usr/bin/env python3
"""Systemd molly guard suite to prevent accidental
reboots and provide autodecrypt option for LUKS.
"""
from argparse import ArgumentParser
from sys import exit    # pylint: disable=W0622
from json import load
from logging import getLogger
from pathlib import Path
from subprocess import CalledProcessError, check_call
from typing import Iterable, List


CONFIG_FILE = Path('/etc/smollyguardl.conf')
CONFIG = {}
CRYPTSETUP = '/usr/bin/cryptsetup'
DEFAULT_UNITS = {
    'halt.target', 'hibernate.target', 'poweroff.target', 'reboot.target',
    'shutdown.target', 'suspend.target', 'suspend-then-hibernate.target'
}
DEVRANDOM = Path('/dev/random')
ETC_HOSTNAME = Path('/etc/hostname')
LOGGER = getLogger('smollyguarl')
SYSTEMCTL = '/usr/bin/systemctl'


class ConfigurationError(Exception):
    """Indicates an error in the configuration."""


class LUKSNotConfigured(Exception):
    """Indicates that LUKS is not configured."""


def load_config():
    """Reads the config file."""

    try:
        with CONFIG_FILE.open('r') as config:
            CONFIG.update(load(config))
    except FileNotFoundError:
        LOGGER.warning('Configuration file does not exist.')


def get_units() -> Iterable[str]:
    """Returns the respective units."""

    return CONFIG.get('units', DEFAULT_UNITS)


def get_luks_settings():
    """Returns the LUKS settings."""

    luks_settings = CONFIG.get('luks')

    if luks_settings is None:
        raise LUKSNotConfigured()

    try:
        device, keyfile, keysize = luks_settings
    except ValueError:
        try:
            device, keyfile = luks_settings
        except ValueError:
            LOGGER.error('Invalid LUKS settings: %s', luks_settings)
            raise ConfigurationError()

        keysize = 2048

    return (device, keyfile, keysize)


def systemctl(action: str, *units: str):
    """Invokes systemctl on the respective units."""

    return check_call((CONFIG.get('systemctl', SYSTEMCTL), action, *units))


def cryptsetup(action: str, *args: str):
    """Runs cryptsetup."""

    return check_call((CONFIG.get('cryptsetup', CRYPTSETUP), action, *args))


def start(units: List[str] = None):
    """Masks the configured units."""

    units = get_units() if units is None else units

    try:
        systemctl('mask', *units)
    except CalledProcessError as cpe:
        LOGGER.error('Could not mask some units.')
        LOGGER.debug(cpe)


def stop(units: List[str] = None):
    """Unmasks the configured units."""

    units = get_units() if units is None else units

    try:
        systemctl('unmask', *units)
    except CalledProcessError as cpe:
        LOGGER.warning('Could not unmask some units.')
        LOGGER.debug(cpe)


def prepare_luks(device: str, keyfile: str, keysize: int):
    """Prepares the auto-unlocking of the respective LUKS volume."""

    with DEVRANDOM.open('rb') as random, Path(keyfile).open('wb') as key:
        key.write(random.read(keysize))

    return cryptsetup('luksAddKey', device, keyfile)


def clear_luks():
    """Clears the LUKS auto-decrypt key from the LUKS device."""

    device, keyfile, *_ = get_luks_settings()
    return cryptsetup('luksRemoveKey', device, keyfile)


def challenge_hostname():
    """Challenge the user to enter the correct host name."""

    try:
        user_hostname = input('Enter hostname: ')
    except KeyboardInterrupt:
        print(flush=True)
        LOGGER.error('Aborted by user.')
        return False
    except EOFError:
        print(flush=True)
        LOGGER.error('No host name entered.')
        return False

    with ETC_HOSTNAME.open('r') as file:
        hostname = file.read()

    return hostname.strip() == user_hostname


def reboot(*, ask_hostname: bool = True):
    """Reboots the device."""

    try:
        prepare_luks(*get_luks_settings())
    except LUKSNotConfigured:
        pass
    except ConfigurationError:
        return

    if ask_hostname and not challenge_hostname():
        return

    try:
        systemctl('unmask', 'reboot.target')
    except CalledProcessError as cpe:
        LOGGER.warning('Could not unmask reboot.target.')
        LOGGER.debug(cpe)
        return

    try:
        systemctl('reboot')
    except CalledProcessError as cpe:
        LOGGER.warning('Could not reboot.')
        LOGGER.debug(cpe)


def get_args():
    """Returns the command line arguments."""

    parser = ArgumentParser(description='Molly guard control CLI.')
    subparsers = parser.add_subparsers(dest='action')
    start_parser = subparsers.add_parser('start', help='start mollyguarding')
    start_parser.add_argument('unit', nargs='*', help='a list of units to mask')
    stop_parser = subparsers.add_parser('stop', help='stop mollyguarding')
    stop_parser.add_argument('unit', nargs='*', help='a list of units to mask')
    reboot_parser = subparsers.add_parser(
        'reboot', help='safely reboot the system')
    reboot_parser.add_argument(
        '-n', '--no-ask-hostname', action='store_true',
        help='do not ask the host name before rebooting')
    subparsers.add(
        'clear-luks',
        help='clears the LUKS auto-decryption key from the LUKS volume')
    return parser.parse_args()


def main():
    """Runs the main program."""

    args = get_args()
    load_config()

    if args.mode == 'start':
        return start(args.unit)

    if args.mode == 'stop':
        return stop(args.unit)

    if args.mode == 'reboot':
        return reboot(ask_hostname=not args.no_ask_host_name)

    if args.mode == 'clear-luks':
        try:
            return clear_luks()
        except LUKSNotConfigured:
            LOGGER.warning('LUKS is not configured.')
            exit(1)
        except ConfigurationError:
            exit(2)
        except CalledProcessError as cpe:
            LOGGER.error('Could not clear LUKS key.')
            LOGGER.debug(cpe)
            exit(3)

    return None
