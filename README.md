# blocks

Conversion tools for block devices.

Convert between raw partitions, logical volumes, and bcache devices
witout moving data.  `blocks` shuffles blocks and sprouts superblocks.

## LVM conversion

`blocks to-lvm` (alias: `lvmify`) takes a block device (partition or
whole disk) containing a filesystem, shrinks the filesystem by a small
amount, and converts it to LVM in place.

The block device is converted to a physical volume and the filesystem is
converted to a logical volume.  If `--join=<VG>` is used the volumes
join an existing volume group.

An LVM conversion can be followed by other changes to the volume,
growing it to multiple disks with `vgextend` and `lvextend`, or
converting it to various RAID levels with `lvconvert --type=raidN
-m<extra-copies>`.

## bcache conversion

`blocks to-bcache` converts a block device (partition, logical volume,
LUKS device) to use bcache.  If `--join=<cset-uuid>` is used the device
joins an existing cache set.  Otherwise you will need to [create
and attach the cache device
manually](http://atlas.evilpiepirate.org/git/linux-bcache.git/tree/Documentation/bcache.txt?h=bcache-dev#n80).

blocks will pick one of several conversion strategies:

* one for partitions, which requires a shrinkable filesystem or free space
immediately before the partition to convert
* one for LUKS volumes
* one for LVM logical volumes

When the first two strategies are unavailable, you can still convert
to bcache by converting to LVM first, then converting the new LV to
bcache.

You will need to install bcache-tools:

* <http://atlas.evilpiepirate.org/git/bcache-tools.git/>

Conversion makes no demands on the kernel, but to use bcache, you need
Linux 3.10 or newer.  [My own branch](https://github.com/g2p/linux/commits/for-3.11/bcache) currently adds
resizing support on top of [Kent Overstreet's upstream branch](http://atlas.evilpiepirate.org/git/linux-bcache.git/).

# Requirements

Python 3.3, pip and Git are required before installing.

You will also need libparted (2.3 or newer, library and headers) and
libaugeas (library only, 1.0 or newer).

On Debian/Ubuntu (Ubuntu raring is recommended):

    sudo aptitude install python3.3 python3-pip git libparted-dev libaugeas0 \
        pkg-config libpython3.3-dev gcc
    sudo aptitude install cryptsetup lvm2 liblzo2-dev \
        nilfs-tools reiserfsprogs xfsprogs e2fsprogs btrfs-tools  # optional
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

# Usage

## Converting your root filesystem to LVM

Install LVM.

Edit your `/etc/fstab` to refer to filesystems by UUID, and regenerate
your initramfs so that it picks up the new tools and the new fstab.

With grub2, you don't need to switch to a separate boot
partition, but make sure grub2 installs `lvm.mod` inside your `/boot`.

Make sure your backups are up to date, boot to live media ([Ubuntu raring
liveusb](http://cdimage.ubuntu.com/daily-live/current/) is a good
choice), install blocks, and convert.

## Converting your root filesystem to bcache

Install bcache-tools and a recent kernel (3.10 or newer).
If your distribution uses Dracut (Fedora), you need Dracut 0.31 or newer.

Edit your `/etc/fstab` to refer to filesystems by UUID, and regenerate
your initramfs so that it picks up the new tools and the new fstab.
On Debian, Ubuntu, and OpenSUSE, this is done with `update-initramfs -k all`.
With Dracut, this is done with `dracut -f`.

Edit your `grub.cfg` to refer to filesystems by UUID on the kernel
command-line (this is often the case, except when you are already using
LVM, in which case `update-grub` tends to write a logical path).  Make
sure you have a separate `/boot` partition.

Make sure your backups are up to date, boot to live media ([Ubuntu raring
liveusb](http://cdimage.ubuntu.com/daily-live/current/) is a good
choice), install blocks, and convert.

## bcache on a fresh install

When using a distro installer that doesn't support bcache
at the partitioning stage, make sure the installer creates a
separate `/boot` partition.

Once the installer is done, you can follow the steps at
[converting your root filesystem to bcache](#converting-your-root-filesystem-to-bcache).

## Subcommand help

    blocks --help
    blocks <subcommand> --help

If `blocks` isn't in the shell's command path, replace with:

    sudo python3.3 -m blocks

# Build status

[![Build Status](https://travis-ci.org/g2p/blocks.png)](https://travis-ci.org/g2p/blocks)

