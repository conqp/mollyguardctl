"""Systemd molly guard suite to prevent accidental
reboots and provide autodecrypt option for LUKS.
"""
from argparse import ArgumentParser
from contextlib import suppress
from functools import wraps
from os import urandom
from sys import argv, exit  # pylint: disable=W0622
from json import load
from logging import getLogger
from pathlib import Path
from socket import gethostname
from subprocess import CalledProcessError, check_call
from typing import Iterable


CONFIG_FILE = Path('/etc/mollyguardctl.json')
CONFIG = {}
CRYPTSETUP = '/usr/bin/cryptsetup'
DEFAULT_UNITS = {
    'halt.target', 'hibernate.target', 'poweroff.target', 'reboot.target',
    'shutdown.target', 'suspend.target', 'suspend-then-hibernate.target'
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

    luks = CONFIG.get('luks')

    if luks is None:
        raise LUKSNotConfigured()

    try:
        yield luks['device']
    except KeyError:
        raise ConfigurationError('Missing LUKS device.')

    try:
        yield luks['keyfile']
    except KeyError:
        raise ConfigurationError('Missing LUKS key file.')

    yield luks.get('keysize', 2048)


def systemctl(action: str, *units: str):
    """Invokes systemctl on the respective units."""

    return check_call((CONFIG.get('systemctl', SYSTEMCTL), action, *units))


def cryptsetup(action: str, *args: str):
    """Runs cryptsetup."""

    return check_call((CONFIG.get('cryptsetup', CRYPTSETUP), action, *args))


def start():
    """Masks the configured units."""

    try:
        systemctl('mask', *get_units())
    except CalledProcessError as cpe:
        LOGGER.error('Could not mask some units.')
        LOGGER.debug(cpe)
        return False

    return True


def stop():
    """Unmasks the configured units."""

    try:
        systemctl('unmask', *get_units())
    except CalledProcessError as cpe:
        LOGGER.warning('Could not unmask some units.')
        LOGGER.debug(cpe)
        return False

    return True


def prepare_luks():
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
        raise UserAbort()

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
    except ConfigurationError as error:
        LOGGER.error(error)
        return False

    return True


def challenge_hostname():
    """Challenge the user to enter the correct host name."""

    try:
        hostname = input('Enter hostname: ')
    except (EOFError, KeyboardInterrupt):
        print(flush=True)
        raise UserAbort()

    return hostname == gethostname()


def mollyguard():
    """Runs mollyguard checks."""

    if CONFIG.get('ask_hostname', True) and not challenge_hostname():
        LOGGER.error('Wrong host name. It actually is: "%s".', gethostname())
        raise ChallengeFailed('hostname')

    with suppress(LUKSNotConfigured):
        if not prepare_luks():
            raise ChallengeFailed('LUKS')


def mollyguarded(function):
    """Decorator factory to molly-guard a function."""

    @wraps(function)
    def wrapper(*args, **kwargs):
        """Wraps the original function."""
        try:
            mollyguard()
        except ChallengeFailed as challenge:
            LOGGER.error('Challenge %s failed.', challenge)
        except UserAbort:
            LOGGER.error('Aborted by user.')
        else:
            function(*args, **kwargs)

    return wrapper


@mollyguarded
def reboot():
    """Reboots the device."""

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
    subparsers.add_parser('start', help='start mollyguarding')
    subparsers.add_parser('stop', help='stop mollyguarding')
    subparsers.add_parser('reboot', help='safely reboot the system')
    subparsers.add_parser(
        'clear-luks', help='clear the LUKS auto-decryption key')
    return parser.parse_args()


def main():
    """Runs the main program."""

    args = get_args()
    load_config()

    if args.action == 'start':
        if start():
            exit(0)

        exit(1)

    if args.action == 'stop':
        if stop():
            exit(0)

        exit(1)

    if args.action == 'reboot':
        if reboot():
            exit(0)

        exit(1)

    if args.action == 'clear-luks':
        if clear_luks():
            exit(0)

        exit(1)
