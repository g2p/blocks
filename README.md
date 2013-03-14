# blocks

Conversion tools for block devices.

## LVM conversion

`blocks to-lvm` takes a partition containing a filesystem, shrinks the
filesystem by a small amount, and converts the partition to LVM in
place.  LVM gives you extra flexibility by allowing you to grow the
filesystem to multiple disks or to follow up with an in-place RAID
conversion.

A new volume group is created, the partition is converted to a physical
volume and the filesystem is converted to a logical volume.

The new volume group can then be merged with other volume groups using
`vgmerge`, or extended with `vgextend`.  RAID can be enabled with
`lvconvert`.

## bcache conversion

`blocks to-bcache` converts a partition to a bcache backing device.
This is done by inserting a bcache superblock before the partition
(resizing filesystems as necessary) then shifting the start of the
partition.  Development versions of bcache-tools and pyparted are
required:

* <https://github.com/g2p/bcache-tools>
* <https://github.com/g2p/pyparted> (thanks hayseed)

## LV to bcache conversion

`blocks lv-to-bcache` converts a logical volume to a bcache backing
device.  Because the current version of bcache can't use an arbitrary
data offset, this is done by sandwitching a GPT partition table between
the LV and the bcache device; `kpartx -a` is required to activate it.

This requires a development version of python-augeas, as well as the
augeas library and headers (which your distribution may package) and the
above bcache dependencies.

* <https://github.com/g2p/python-augeas>

# Requirements

Python 3.3.  Command-line tools for LVM2, LUKS, filesystem resizing are
needed if those features are used.

# Installation

    pip install --user blocks
    cp -lt ~/bin ~/.local/bin/blocks

`pip` can be replaced with `pip-3.3` or `python3.3 -m pip.runner` to
invoke the correct Python version.

Or get the latest version:

    git clone https://github.com/g2p/blocks.git
    cd blocks
    python3.3 setup.py develop --user
    cp -lt ~/bin ~/.local/bin/blocks

# Usage (LVM conversion)

    blocks --help
    blocks to-lvm --help
    sudo blocks to-lvm /dev/sdaN

If `blocks` isn't in your path, replace with:

    sudo python3.3 -m blocks

Don't forget to update `/etc/fstab` (no change is necessary if
filesystems are mounted by uuid). If necessary, rebuild the grub config
(grub2 needs to install some modules to boot to LVM directly) and your
initramfs.

