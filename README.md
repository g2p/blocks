# lvmify

Convert partitions in place

## LVM conversion

`lvmify to-lvm` takes a partition containing a filesystem, shrinks the
filesystem by a small amount, and converts the partition to LVM in
place.  This gives you extra flexibility, by allowing you to grow the
filesystem to multiple disks, or to follow-up with an in place RAID
conversion.

A new volume group is created, the partition is converted to a physical
volume and the filesystem is converted to a logical volume.

The new volume group can then be merged with other volume groups using
`vgmerge`, or extended with `vgextend`. RAID can be enabled with
`lvconvert`.

## bcache conversion

`lvmify to-bcache` converts a partition to a bcache backing device.
This is done by inserting a bcache superblock before the partition
(resizing filesystems as necessary) then shifting the start of the
partition.  Development versions of bcache-tools and pyparted are
required:

* <https://github.com/g2p/bcache-tools>
* <https://github.com/g2p/pyparted> (thanks hayseed)

# Requirements

Python 3.3, LVM 2

# Installation

    pip install --user lvmify
    cp -lt ~/bin ~/.local/bin/lvmify

`pip` can be replaced with `pip-3.3` or `python3.3 -m pip.runner` to
invoke the correct Python version.

Or get the latest version:

    git clone https://github.com/g2p/lvmify.git
    cd lvmify
    python3.3 setup.py develop --user
    cp -lt ~/bin ~/.local/bin/lvmify

# Usage

    lvmify --help
    sudo lvmify to-lvm /dev/sdaN

If `lvmify` isn't in your path, replace with:

    sudo python3.3 -m lvmify

Don't forget to update `/etc/fstab` (no change is necessary if
filesystems are mounted by uuid). If necessary, rebuild the grub config
(grub2 needs to install some modules to boot to LVM directly) and your
initramfs.

