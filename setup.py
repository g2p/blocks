#!/usr/bin/env python3.3

from setuptools import setup

setup(
    name='lvmify',
    version='0.0.1',
    author='Gabriel de Perthuis',
    author_email='g2p.code+lvmify@gmail.com',
    url='https://github.com/g2p/lvmify',
    license='GNU GPL',
    keywords='lvm partitioning',
    description='Convert partitions to LVM',
    entry_points={
        'console_scripts': [
            'lvmify = lvmify.__main__:script_main']},
    packages=[
        'lvmify',
    ],
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
    Convert partitions to LVM.

    See `github.com/g2p/lvmify <https://github.com/g2p/lvmify#readme>`_
    for usage instructions.''')

