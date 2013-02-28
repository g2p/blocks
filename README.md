# lvmify

Convert partitions to LVM

`lvmify` takes a partition containing a filesystem, makes sure the
filesystem leaves some extra room at the end of the partition, and
converts the partition to LVM. This gives you extra flexibility,
such as the ability to grow the filesystem to multiple disks, or
the ability to do a raid conversion.

A new volume group is created, the partition is converted to a physical
volume and the filesystem is converted to a logical volume.

The new volume group can then be merged with other volume groups using
`vgmerge`, or extended with `vgextend`. Raid can be enabled with
`lvconvert`.

# Requirements

Python 3.3, LVM 2

# Installation

    pip install --user lvmify

Or get the latest version:

    git clone https://github.com/g2p/lvmify.git
    cd lvmify
    python3.3 setup.py develop --user

# Usage

    lvmify --help

If lvmify isn't in your path, replace with:

    sudo python3.3 -m lvmify

    sudo lvmify /dev/sdaN [NewVolumeName]

NewVolumeName defaults to sdaN, and is used for the new LV and the new
VG.

Don't forget to update `/etc/fstab` (no change is necessary if it uses
the filesystem uuid). If necessary, rebuild the grub config (grub2
needs to install some modules to boot to lvm directly) and your
initramfs.

