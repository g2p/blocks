#!/usr/bin/env python3.3

from setuptools import setup

setup(
    name='blocks',
    version='0.0.1',
    author='Gabriel de Perthuis',
    author_email='g2p.code+blocks@gmail.com',
    url='https://github.com/g2p/blocks',
    license='GNU GPL',
    keywords='bcache lvm storage partitioning ssd',
    description='Conversion tools for block devices',
    entry_points={
        'console_scripts': [
            'blocks = blocks.__main__:script_main']},
    packages=[
        'blocks',
    ],
    include_package_data=True,
    install_requires=[
        'python-augeas', 'pyparted'],
    classifiers='''
        Programming Language :: Python :: 3
        License :: OSI Approved :: GNU General Public License (GPL)
        Operating System :: POSIX :: Linux
        Intended Audience :: System Administrators
        Intended Audience :: End Users/Desktop
        Topic :: System :: Filesystems
        Topic :: Utilities
        Environment :: Console
    '''.strip().splitlines(),
    long_description='''
    Conversion tools for block devices.
    Convert partitions to LVM or bcache in place.

    See `github.com/g2p/blocks <https://github.com/g2p/blocks#readme>`_
    for usage instructions.''')

