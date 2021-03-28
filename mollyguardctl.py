"""Systemd molly guard suite to prevent accidental
reboots and provide autodecrypt option for LUKS.
"""
from argparse import ArgumentParser, Namespace
from configparser import ConfigParser
from os import urandom
from sys import argv
from logging import getLogger
from pathlib import Path
from socket import gethostname
from subprocess import CalledProcessError, check_call
from typing import Iterator, Union


CONFIG_FILE = '/etc/mollyguardctl.conf'
CONFIG = ConfigParser()
CRYPTSETUP = '/usr/bin/cryptsetup'
DEFAULT_UNITS = {
    'halt.target',
    'hibernate.target',
    'poweroff.target',
    'reboot.target',
    'shutdown.target',
    'suspend.target',
    'suspend-then-hibernate.target'
}
LOGGER = getLogger(Path(argv[0]).name or __file__)
SYSTEMCTL = '/usr/bin/systemctl'


class ConfigurationError(Exception):
    """Indicates an error in the configuration."""


class LUKSNotConfigured(Exception):
    """Indicates that LUKS is not configured."""


class ChallengeFailed(Exception):
    """Indicates that a user challenge failed."""


class UserAbort(Exception):
    """Indicates that the user aborted a challenge."""


def get_units() -> list[str]:
    """Returns the respective units."""

    try:
        units = CONFIG['MollyGuard']['units']
    except KeyError:
        return DEFAULT_UNITS

    return units.split()


def get_luks_settings() -> Iterator[Union[str, int]]:
    """Returns the LUKS settings."""

    try:
        luks = CONFIG['LUKS']
    except KeyError:
        raise LUKSNotConfigured() from None

    try:
        yield luks['device']
    except KeyError:
        raise ConfigurationError('Missing LUKS device.') from None

    try:
        yield luks['keyfile']
    except KeyError:
        raise ConfigurationError('Missing LUKS key file.') from None

    try:
        yield luks.getint('keysize', fallback=2048)
    except ValueError:
        raise ConfigurationError('Key size is not an integer.') from None


def systemctl(action: str, *units: str) -> int:
    """Invokes systemctl on the respective units."""

    systemctl_ = CONFIG.get('MollyGuard', 'systemctl', fallback=SYSTEMCTL)
    return check_call((systemctl_, action, *units))


def cryptsetup(action: str, *args: str) -> int:
    """Runs cryptsetup."""

    cryptsetup_ = CONFIG.get('MollyGuard', 'cryptsetup', fallback=CRYPTSETUP)
    return check_call((cryptsetup_, action, *args))


def start() -> bool:
    """Masks the configured units."""

    try:
        systemctl('mask', *get_units())
    except CalledProcessError as cpe:
        LOGGER.error('Could not mask some units.')
        LOGGER.debug(cpe)
        return False

    return True


def stop() -> bool:
    """Unmasks the configured units."""

    try:
        systemctl('unmask', *get_units())
    except CalledProcessError as cpe:
        LOGGER.warning('Could not unmask some units.')
        LOGGER.debug(cpe)
        return False

    return True


def prepare_luks() -> bool:
    """Prepares the auto-unlocking of the respective LUKS volume."""

    try:
        device, keyfile, keysize = get_luks_settings()
    except ConfigurationError as error:
        LOGGER.error(error)
        return False

    with Path(keyfile).open('wb') as key:
        key.write(urandom(keysize))

    try:
        cryptsetup('luksAddKey', device, keyfile)
    except CalledProcessError:
        LOGGER.error('Could not add auto-decrypt key to LUKS volume.')
        return False
    except KeyboardInterrupt:
        raise UserAbort() from None

    return True


def clear_luks() -> bool:
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
    except ConfigurationError as error:
        LOGGER.error(error)
        return False

    return True


def challenge_hostname() -> bool:
    """Challenge the user to enter the correct host name."""

    try:
        hostname = input('Enter hostname: ')
    except (EOFError, KeyboardInterrupt):
        print(flush=True)
        raise UserAbort() from None

    return hostname == gethostname()


def mollyguard(force_luks: bool = False) -> None:
    """Runs mollyguard checks."""

    ch_hostname = CONFIG.getboolean('MollyGuard', 'hostname', fallback=True)

    if ch_hostname and not challenge_hostname():
        LOGGER.error('Wrong host name. It actually is: "%s".', gethostname())
        raise ChallengeFailed('hostname')

    try:
        if not prepare_luks():
            raise ChallengeFailed('LUKS')
    except LUKSNotConfigured:
        if force_luks:
            raise ChallengeFailed('Enforced LUKS') from None


def unlock() -> bool:
    """Unlocks the LUKS device for a reboot."""

    try:
        systemctl('unmask', 'reboot.target', 'shutdown.target')
    except CalledProcessError as cpe:
        LOGGER.warning('Could not unmask necessary targets.')
        LOGGER.debug(cpe)
        return False

    return True


def reboot() -> bool:
    """Reboots the device."""

    if not unlock():
        return False

    try:
        systemctl('reboot')
    except CalledProcessError as cpe:
        LOGGER.warning('Could not reboot.')
        LOGGER.debug(cpe)
        return False

    return True


def get_args() -> Namespace:
    """Returns the command line arguments."""

    parser = ArgumentParser(description='Molly guard control CLI.')
    subparsers = parser.add_subparsers(dest='action')
    subparsers.add_parser('start', help='start mollyguarding')
    subparsers.add_parser('stop', help='stop mollyguarding')
    subparsers.add_parser('unlock', help='unlock LUKS')
    reboot_parser = subparsers.add_parser('reboot', help='reboot the system')
    reboot_parser.add_argument(
        '-l', '--force-luks', action='store_true',
        help='require LUKS auto-decryption')
    subparsers.add_parser(
        'clear-luks', help='clear the LUKS auto-decryption key')
    return parser.parse_args()


def mollyguard_functions(args: Namespace) -> int:
    """Runs mollyguarded functions."""

    try:
        mollyguard(force_luks=args.force_luks)
    except ChallengeFailed as challenge:
        LOGGER.error('Challenge %s failed.', challenge)
        return 1
    except UserAbort:
        LOGGER.error('Aborted by user.')
        return 2

    if args.action == 'unlock':
        return 0 if unlock() else 1

    if args.action == 'reboot':
        return 0 if reboot() else 1

    return 1


def main() -> int:
    """Runs the main program."""

    args = get_args()
    CONFIG.read(CONFIG_FILE)

    if args.action == 'start':
        return 0 if start() else 1

    if args.action == 'stop':
        return 0 if stop() else 1

    if args.action == 'clear-luks':
        return 0 if clear_luks() else 1

    return mollyguard_functions(args)
