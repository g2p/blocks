# blocks

Conversion tools for block devices.

Convert between raw partitions, logical volumes, and bcache devices
witout moving data.  `blocks` shuffles blocks and sprouts superblocks.

## LVM conversion

`blocks to-lvm` takes a block device (partition or whole disk)
containing a filesystem, shrinks the filesystem by a small amount, and
converts it to LVM in place.

The block device is converted to a physical volume and the filesystem is
converted to a logical volume.  If `--join=<VG>` is used the volumes
join an existing volume group.

An LVM conversion can be followed by other changes to the volume,
growing it to multiple disks with `vgextend` and `lvextend`, or
converting it to various RAID levels with `lvconvert --type=raidN
-m<extra-copies>`.

## bcache conversion

**The extended bcache format we need is changing while being merged upstream.
Please wait a few days before making bcache conversions.**

`blocks to-bcache` converts a block device (partition or logical
volume) to use bcache.  If `--join=<cset>` is used the device joins an
existing cache set.

A development version of the bcache cli utilities is required.  At
runtime (but not during conversion), you need a kernel that reads a
slightly updated bcache format:

* <https://github.com/g2p/bcache-tools>
* <https://github.com/g2p/linux/tree/bcache-for-upstream>

# Requirements

Python 3.3, pip and Git are required before installing.

You will also need libparted (2.3 or newer, library and headers) and
libaugeas (library only, 1.0 or newer).

On Debian/Ubuntu (raring is recommended):

    sudo aptitude install python3.3 python3-pip git libparted-dev libaugeas0 \
        pkg-config libpython3.3-dev gcc
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
to install some modules if /boot is within a logical volume) and your
initramfs.

# Usage (bcache conversion)

    blocks --help
    blocks to-bcache --help
    sudo blocks to-bcache /dev/sdaN
    # Or
    sudo blocks to-bcache /dev/VG/LV

When converting to bcache, keep in mind you need the development kernel
given above.  If you convert your root filesystem, you need to
re-run update-initramfs after installing bcache-tools from the above
link.  Finally, when converting your root filesystem from a logical
volume, make sure grub.cfg doesn't reference the root filesystem using
its volume path in the kernel command-line.  `root=UUID=<UUID>` works,
and `root=/dev/bcache0` will also work if you have a single bcache
volume.

