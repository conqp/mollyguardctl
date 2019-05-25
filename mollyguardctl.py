#! /usr/bin/env python3
"""Systemd molly guard suite to prevent accidental
reboots and provide autodecrypt option for LUKS.
"""
from argparse import ArgumentParser
from sys import exit    # pylint: disable=W0622
from json import load
from logging import getLogger
from pathlib import Path
from socket import gethostname
from subprocess import CalledProcessError, check_call
from typing import Iterable, List


CONFIG_FILE = Path('/etc/mollyguardctl.json')
CONFIG = {}
CRYPTSETUP = '/usr/bin/cryptsetup'
DEFAULT_UNITS = {
    'halt.target', 'hibernate.target', 'poweroff.target', 'reboot.target',
    'shutdown.target', 'suspend.target', 'suspend-then-hibernate.target'
}
DEVRANDOM = Path('/dev/random')
LOGGER = getLogger('mollyguardctl')
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

    units = units or get_units()

    try:
        systemctl('mask', *units)
    except CalledProcessError as cpe:
        LOGGER.error('Could not mask some units.')
        LOGGER.debug(cpe)
        return False

    return True


def stop(units: List[str] = None):
    """Unmasks the configured units."""

    units = units or get_units()

    try:
        systemctl('unmask', *units)
    except CalledProcessError as cpe:
        LOGGER.warning('Could not unmask some units.')
        LOGGER.debug(cpe)
        return False

    return True


def prepare_luks():
    """Prepares the auto-unlocking of the respective LUKS volume."""

    try:
        device, keyfile, keysize = get_luks_settings()
    except ConfigurationError:
        return False

    with DEVRANDOM.open('rb') as random, Path(keyfile).open('wb') as key:
        key.write(random.read(keysize))

    try:
        cryptsetup('luksAddKey', device, keyfile)
    except CalledProcessError:
        LOGGER.error('Could not add auto-decrypt key to LUKS volume.')
        return False

    return True


def clear_luks():
    """Clears the LUKS auto-decrypt key from the LUKS device."""

    device, keyfile, *_ = get_luks_settings()

    try:
        cryptsetup('luksRemoveKey', device, keyfile)
    except CalledProcessError:
        LOGGER.error('Could not clear LUKS key from %s.', device)
        return False
    except LUKSNotConfigured:
        LOGGER.warning('LUKS is not configured.')
        return False
    except ConfigurationError:
        return False

    return True


def challenge_hostname():
    """Challenge the user to enter the correct host name."""

    try:
        hostname = input('Enter hostname: ')
    except KeyboardInterrupt:
        print(flush=True)
        LOGGER.error('Aborted by user.')
        return False
    except EOFError:
        print(flush=True)
        LOGGER.error('No host name entered.')
        return False

    return hostname == gethostname()


def reboot(*, ask_hostname: bool = True):
    """Reboots the device."""

    if ask_hostname and not challenge_hostname():
        LOGGER.error('Wrong host name. Not rebooting "%s".', gethostname())
        return

    try:
        if not prepare_luks():
            return
    except LUKSNotConfigured:
        pass

    try:
        systemctl('unmask', 'reboot.target')
        systemctl('unmask', 'shutdown.target')
    except CalledProcessError as cpe:
        LOGGER.warning('Could not unmask necessary targets.')
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
    start_parser.add_argument(
        'unit', nargs='*', help='a list of units to mask')
    stop_parser = subparsers.add_parser('stop', help='stop mollyguarding')
    stop_parser.add_argument('unit', nargs='*', help='a list of units to mask')
    reboot_parser = subparsers.add_parser(
        'reboot', help='safely reboot the system')
    reboot_parser.add_argument(
        '-n', '--no-ask-hostname', action='store_true',
        help='do not ask the host name before rebooting')
    subparsers.add_parser(
        'clear-luks',
        help='clears the LUKS auto-decryption key from the LUKS volume')
    return parser.parse_args()


def main():
    """Runs the main program."""

    args = get_args()
    load_config()

    if args.action == 'start':
        if start(args.unit):
            exit(0)

        exit(1)

    if args.action == 'stop':
        if stop(args.unit):
            exit(0)

        exit(1)

    if args.action == 'reboot':
        if reboot(ask_hostname=not args.no_ask_hostname):
            exit(0)

        exit(1)

    if args.action == 'clear-luks':
        if clear_luks():
            exit(0)

        exit(1)
