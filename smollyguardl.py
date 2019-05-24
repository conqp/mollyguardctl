"""Systemd molly guard suite to prevent accidental
reboots and provide autodecrypt option for LUKS.
"""
from contextlib import suppress
from json import load
from logging import getLogger
from pathlib import Path
from subprocess import CalledProcessError, check_call
from typing import Iterable


__all__ = ['CONFIG', 'reboot', 'start', 'stop']


CONFIG_FILE = Path('/etc/smollyguardl.conf')
CONFIG = {}
CRYPTSETUP = '/usr/bin/cryptsetup'
DEFAULT_UNITS = {
    'halt.target', 'hibernate.target', 'poweroff.target', 'reboot.target',
    'shutdown.target', 'suspend.target', 'suspend-then-hibernate.target'
}
DEVRANDOM = Path('/dev/random')
LOGGER = getLogger('smollyguarl')
SYSTEMCTL = '/usr/bin/systemctl'


def load_config():
    """Reads the config file."""

    with suppress(FileNotFoundError):
        with CONFIG_FILE.open('r') as config:
            CONFIG.update(load(config))


def get_units() -> Iterable[str]:
    """Returns the respective units."""

    return CONFIG.get('units', DEFAULT_UNITS)


def systemctl(action: str, *units: str):
    """Invokes systemctl on the respective units."""

    return check_call((CONFIG.get('systemctl', SYSTEMCTL), action, *units))


def start():
    """Masks the configured units."""

    try:
        systemctl('mask', *get_units())
    except CalledProcessError as cpe:
        LOGGER.error('Could not mask some units.')
        LOGGER.debug(cpe)


def stop():
    """Unmasks the configured units."""

    try:
        systemctl('unmask', *get_units())
    except CalledProcessError as cpe:
        LOGGER.warning('Could not unmask some units.')
        LOGGER.debug(cpe)


def generate_luks_key(keyfile: Path, keysize: int = 2048):
    """Generates a LUKS key."""

    with DEVRANDOM.open('rb') as random, keyfile.open('wb') as key:
        key.write(random.read(keysize))


def add_luks_key(device: Path, keyfile: Path):
    """Adds the key file to the respective device."""

    cryptsetup = CONFIG.get('cryptsetup', CRYPTSETUP)
    return check_call((cryptsetup, 'luksAddKey', str(device), str(keyfile)))


def reboot(device: Path, keyfile: Path, *, keysize: int = 2048):
    """Reboots the device."""

    generate_luks_key(keyfile, keysize=keysize)

    try:
        add_luks_key(device, keyfile)
    except CalledProcessError as cpe:
        LOGGER.error('Could not add key file.')
        LOGGER.debug(cpe)
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
