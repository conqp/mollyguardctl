#! /usr/bin/env python3
"""Installation script."""


from setuptools import setup


setup(
    name='mollyguardctl',
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    author='Richard Neumann',
    author_email='mail@richard-neumann.de',
    python_requires='>=3.8',
    py_modules=['mollyguardctl'],
    entry_points={'console_scripts': ['mollyguardctl = mollyguardctl:main']},
    data_files=[
        ('/usr/lib/systemd/system', [
            'clear-luks-autodecrypt-key.service',
            'mollyguard.service'
        ])
    ],
    url='https://github.com/conqp/',
    license='GPLv3',
    description='Mollyguards your system.'
)
