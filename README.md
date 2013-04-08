# blocks

Conversion tools for block devices.

Convert between raw partitions, logical volumes, and bcache devices
witout moving data.  `blocks` shuffles blocks and sprouts superblocks.

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
partition.  A development version of `bcache-tools` (bcache cli
utilities) is required.  At runtime (but not during conversion),
you need a kernel that reads a slightly updated bcache format:

* <https://github.com/g2p/bcache-tools>
* <https://github.com/g2p/linux/tree/bcache-for-upstream>

## LV to bcache conversion

`blocks lv-to-bcache` converts a logical volume to a bcache backing
device.

# Requirements

Python 3.3, pip and Git are required before installing.

You will also need libparted (2.3 or newer, library and headers) and
libaugeas (library only, 1.0 or newer).

On Debian/Ubuntu (raring is recommended):

    sudo aptitude install python3.3 python3-pip git libparted-dev libaugeas0 \
        pkg-config libpython3.3-dev
    sudo aptitude install cryptsetup lvm2 \
        nilfs-tools reiserfsprogs xfsprogs e2fsprogs  # optional
    type pip-3.3 || alias pip-3.3='python3.3 -m pip.runner'

Command-line tools for LVM2, LUKS, bcache (see above), filesystem
resizing (see below for btrfs) are needed if those formats are involved.
Kernel support isn't required however, so you can do bcache conversions
from a live-cd/live-usb for example.

For btrfs resizing, you need a package that provides `btrfs-show-super`,
or you can install from source:

* <http://git.kernel.org/cgit/linux/kernel/git/mason/btrfs-progs.git>

# Installation

    pip-3.3 install --user -r <(wget -O- https://raw.github.com/g2p/blocks/master/requirements.txt)
    cp -lt ~/bin ~/.local/bin/blocks

# Usage (LVM conversion)

    blocks --help
    blocks to-lvm --help
    sudo blocks to-lvm /dev/sdaN

If `blocks` isn't in the shell's command path, replace with:

    sudo python3.3 -m blocks

Don't forget to update `/etc/fstab` (no change is needed if filesystems
are mounted by uuid). If necessary, rebuild the grub config (grub2 needs
to install some modules to boot to LVM directly) and your initramfs.

