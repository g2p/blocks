# Python 3.3

import argparse
import contextlib
import os
import re
import stat
import string
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid

import pkg_resources


# 4MiB PE, for vgmerge compatibility
LVM_PE_SIZE = 4 * 1024 ** 2

ASCII_ALNUM_WHITELIST = string.ascii_letters + string.digits


# Fairly strict, snooping an incorrect mapping would be bad
dm_crypt_re = re.compile(
    r'^0 (?P<plainsize>\d+) crypt (?P<cipher>[a-z0-9:-]+) 0+ 0'
    ' (?P<major>\d+):(?P<minor>\d+) (?P<offset>\d+)(?P<options> [^\n]*)?\n\Z',
    re.ASCII)

dm_kpartx_re = re.compile(
    r'^0 (?P<partsize>\d+) linear'
    ' (?P<major>\d+):(?P<minor>\d+) (?P<offset>\d+)\n\Z',
    re.ASCII)


def bytes_to_sector(by):
    sectors, rem = divmod(by, 512)
    assert rem == 0
    return sectors


def intdiv_up(num, denom):
    return (num - 1) // denom + 1


def align_up(size, align):
    return intdiv_up(size, align) * align


def align(size, align):
    return (size // align) * align


class UnsupportedSuperblock(Exception):
    def __init__(self, device):
        self.device = device


class CantShrink(Exception):
    pass


class OverlappingPartition(Exception):
    pass


# SQLa, compatible license
class memoized_property(object):
    """A read-only @property that is only evaluated once."""
    def __init__(self, fget, doc=None):
        self.fget = fget
        self.__doc__ = doc or fget.__doc__
        self.__name__ = fget.__name__

    def __get__(self, obj, cls):
        if obj is None:
            return self
        obj.__dict__[self.__name__] = result = self.fget(obj)
        return result

    def _reset(self, obj):
        obj.__dict__.pop(self.__name__, None)


def quiet_call(cmd, *args, **kwargs):
    # universal_newlines is used to enable io decoding in the current locale
    proc = subprocess.Popen(
        cmd, *args, universal_newlines=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    odat, edat = proc.communicate()
    if proc.returncode != 0:
        print(
            'Command {!r} has failed with status {}\n'
            'Standard output:\n{}\n'
            'Standard error:\n{}'.format(
                cmd, proc.returncode, odat, edat), file=sys.stderr)
        raise subprocess.CalledProcessError(proc.returncode, cmd, odat)


def mk_dm(devname, table, readonly, exit_stack):
    cmd = 'dmsetup create --noudevsync --'.split() + [devname]
    if readonly:
        cmd[2:2] = ['--readonly']
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    proc.communicate(table.encode('ascii'))
    assert proc.returncode == 0
    exit_stack.callback(
        lambda: quiet_call(
            'dmsetup remove --noudevsync --'.split() + [devname]))


def devpath_from_sysdir(sd):
    with open(sd + '/dev') as fi:
        return os.path.realpath('/dev/block/' + fi.read().rstrip())


class BlockDevice:
    def __init__(self, devpath):
        assert os.path.exists(devpath), devpath
        self.devpath = devpath

    def open_excl(self):
        # O_EXCL on a block device takes the device lock,
        # exclusive against mounts and the like.
        # O_SYNC on a block device provides durability, see:
        # http://www.codeproject.com/Articles/460057/HDD-FS-O_SYNC-Throughput-vs-Integrity
        # O_DIRECT would bypass the block cache, which is irrelevant here
        return os.open(
            self.devpath, os.O_SYNC | os.O_RDWR | os.O_EXCL)

    @memoized_property
    def ptable_type(self):
        # TODO: also detect an MBR other than protective,
        # and refuse to edit that.
        rv = subprocess.check_output(
            'blkid -p -o value -s PTTYPE --'.split() + [self.devpath]
        ).rstrip().decode('ascii')
        if rv:
            return rv

    @memoized_property
    def superblock_type(self):
        return self.superblock_at(0)

    def superblock_at(self, offset):
        try:
            return subprocess.check_output(
                'blkid -p -o value -s TYPE -O'.split()
                + ['%d' % offset, '--', self.devpath]
            ).rstrip().decode('ascii')
        except subprocess.CalledProcessError as err:
            # No recognised superblock
            assert err.returncode == 2, err

    @memoized_property
    def has_bcache_superblock(self):
        # blkid doesn't detect bcache, so special-case it.
        # To keep dependencies light, don't use bcache-tools for detection,
        # only require the tools after a successful detection.
        if self.size <= 8192:
            return False
        sbfd = os.open(self.devpath, os.O_RDONLY)
        magic, = struct.unpack('16s', os.pread(sbfd, 16, 4096 + 24))
        os.close(sbfd)
        return magic == b'\xc6\x85s\xf6N\x1aE\xca\x82e\xf5\x7fH\xbam\x81'

    @memoized_property
    def size(self):
        rv = int(subprocess.check_output(
            'blockdev --getsize64'.split() + [self.devpath]))
        assert rv % 512 == 0
        return rv

    def reset_size(self):
        type(self).size._reset(self)

    @property
    def sysfspath(self):
        # pyudev would also work
        st = os.stat(self.devpath)
        assert stat.S_ISBLK(st.st_mode)
        return '/sys/dev/block/%d:%d' % self.devnum

    @property
    def devnum(self):
        st = os.stat(self.devpath)
        assert stat.S_ISBLK(st.st_mode)
        return (os.major(st.st_rdev), os.minor(st.st_rdev))

    def iter_holders(self):
        for hld in os.listdir(self.sysfspath + '/holders'):
            yield BlockDevice('/dev/' + hld)

    @memoized_property
    def is_dm(self):
        return os.path.exists(self.sysfspath + '/dm')

    @memoized_property
    def is_lv(self):
        if not self.is_dm:
            return False
        try:
            pe_size = int(subprocess.check_output(
                'lvm lvs --noheadings --rows --units=b --nosuffix '
                '-o vg_extent_size --'.split()
                + [self.devpath], universal_newlines=True))
        except subprocess.CalledProcessError:
            return False
        else:
            return True


    def dm_table(self):
        return subprocess.check_output(
            'dmsetup table --'.split() + [self.devpath],
            universal_newlines=True)

    def dm_deactivate(self):
        return quiet_call(
            'dmsetup remove --'.split() + [self.devpath])

    def dm_setup(self, table, readonly):
        cmd = 'dmsetup create --'.split() + [self.devpath]
        if readonly:
            cmd[2:2] = ['--readonly']
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        proc.communicate(table.encode('ascii'))
        assert proc.returncode == 0

    @memoized_property
    def is_partition(self):
        return (
            os.path.exists(self.sysfspath + '/partition') and
            bool(int(open(self.sysfspath + '/partition').read())))

    def ptable_context(self):
        # the outer ptable and our offset within that
        import parted.disk

        assert self.is_partition

        ptable_device = PartitionedDevice(
            devpath_from_sysdir(self.sysfspath + '/..'))

        part_start = int(open(self.sysfspath + '/start').read()) * 512
        ptable = PartitionTable(
            device=ptable_device,
            parted_disk=parted.disk.Disk(ptable_device.parted_device))
        return ptable, part_start

    def dev_resize(self, newsize, shrink):
        newsize = align_up(newsize, 512)
        # Be explicit about the intended direction;
        # shrink is more dangerous
        if self.is_partition:
            ptable, part_start = self.ptable_context()
            ptable.part_resize(part_start, newsize, shrink)
        elif self.is_lv:
            if shrink:
                cmd = ['lvm', 'lvreduce', '-f']
            else:
                # Alloc policy / dest PVs might be useful here,
                # but difficult to expose cleanly.
                # Just don't use --resize-device and do it manually.
                cmd = ['lvm', 'lvextend']
            quiet_call(cmd + ['--size=%db' % newsize, '--', self.devpath])
        else:
            raise NotImplementedError('Only partitions and LVs can be resized')
        self.reset_size()


class PartitionedDevice(BlockDevice):
    @memoized_property
    def parted_device(self):
        import parted.device
        return parted.device.Device(self.devpath)


class BlockData:
    def __init__(self, device):
        self.device = device


class PartitionTable(BlockData):
    def __init__(self, device, parted_disk):
        super(PartitionTable, self).__init__(device=device)
        self.parted_disk = parted_disk

    @classmethod
    def mkgpt(cls, device):
        import parted
        ptable_device = PartitionedDevice(device.devpath)
        return cls(
            device=ptable_device,
            parted_disk=parted.freshDisk(ptable_device.parted_device, 'gpt'))

    def _iter_range(self, start_sector, end_sector):
        # Loop on partitions overlapping with the range, excluding free space

        # Careful: end_sector is exclusive here,
        # but parted geometry uses inclusive ends.

        import _ped
        while start_sector < end_sector:
            part = self.parted_disk.getPartitionBySector(start_sector)
            if not (part.type & _ped.PARTITION_FREESPACE):
                yield part
            # inclusive, so add one
            start_sector = part.geometry.end + 1

    def _reserve_range(self, start, end, progress):
        import _ped
        assert 0 <= start <= end

        # round down
        start_sector = start // 512

        # round up
        end_sector = intdiv_up(end, 512)

        part = None
        for part in self._iter_range(start_sector, end_sector):
            if part.geometry.start >= start_sector:
                err = OverlappingPartition(start, end, part)
                progress.notify_error(
                    'The range we want to reserve overlaps with '
                    'the start of partition {} ({}), the shrinking strategy '
                    'will not work.'.format(
                        part.path, _ped.partition_type_get_name(part.type)),
                    err)
                raise err

        if part is None:
            # No partitions inside the range, we're good
            return

        # There's a single overlapping partition,
        # and it starts outside the range. Shrink it.

        part_newsize = (start_sector - part.geometry.start) * 512

        block_stack = get_block_stack(BlockDevice(part.path), progress)

        block_stack.read_superblocks()
        block_stack.stack_reserve_end_area(part_newsize, progress)

    def reserve_space_before(self, part_start, length, progress):
        assert part_start >= length, (part_start, length)

        start_sector = bytes_to_sector(part_start)

        # Just check part_start is indeed the start of a partition
        part = self.parted_disk.getPartitionBySector(start_sector)
        if part.geometry.start != start_sector:
            raise KeyError(part_start, self)

        return self._reserve_range(part_start - length, part_start, progress)

    def part_resize(self, part_start, newsize, shrink):
        import parted.geometry
        import parted.constraint

        start_sector = bytes_to_sector(part_start)
        part = self.parted_disk.getPartitionBySector(start_sector)
        # Parted uses inclusive ends, so substract one
        new_end = part.geometry.start + bytes_to_sector(newsize) - 1
        if shrink:
            assert new_end < part.geometry.end
        else:
            assert new_end > part.geometry.end
        geom = parted.geometry.Geometry(
            device=self.device.parted_device,
            start=part.geometry.start,
            end=new_end)
        # We want an aligned region at least as large as newsize
        # TODO: add a CLI arg for simply getting the max region
        # The user could get the max region wrong if aligning
        # makes it slightly smaller for example
        optim = self.device.parted_device.optimalAlignedConstraint
        solve_max = parted.constraint.Constraint(minGeom=geom)
        cons = optim.intersect(solve_max)
        assert self.parted_disk.setPartitionGeometry(
            part, cons, geom.start, geom.end) is True
        self.parted_disk.commit()

    def shift_left(self, part_start, part_start1):
        assert part_start1 < part_start
        start_sector = bytes_to_sector(part_start)
        start_sector1 = bytes_to_sector(part_start1)

        import parted.geometry
        import parted.constraint
        import _ped

        left_part = self.parted_disk.getPartitionBySector(start_sector1)
        right_part = self.parted_disk.getPartitionBySector(start_sector)

        if left_part.type != _ped.PARTITION_FREESPACE:
            geom = parted.geometry.Geometry(
                device=self.device.parted_device,
                start=left_part.geometry.start,
                end=start_sector1 - 1)
            cons = parted.constraint.Constraint(exactGeom=geom)
            assert self.parted_disk.setPartitionGeometry(
                left_part, cons, geom.start, geom.end) is True

        geom = parted.geometry.Geometry(
            device=self.device.parted_device,
            start=start_sector1,
            end=right_part.geometry.end)
        cons = parted.constraint.Constraint(exactGeom=geom)
        assert self.parted_disk.setPartitionGeometry(
            right_part, cons, geom.start, geom.end) is True

        # commitToDevice (atomic) + commitToOS (not atomic, less important)
        self.parted_disk.commit()


class Filesystem(BlockData):
    resize_needs_mpoint = False
    sb_size_in_bytes = False

    def reserve_end_area_nonrec(self, pos):
        # align to a block boundary that doesn't encroach
        pos = align(pos, self.block_size)

        if self.fssize <= pos:
            return

        if not self.can_shrink:
            raise CantShrink(self)

        self._mount_and_resize(pos)
        return pos

    @contextlib.contextmanager
    def temp_mount(self):
        # Don't use TemporaryDirectory, recursive cleanup
        # on a mountpoint would be bad
        mpoint = tempfile.mkdtemp(suffix='.privmnt')
        # Don't pass -n, Nilfs relies on /etc/mtab to find its mountpoint
        # TODO: use unshare() here
        quiet_call(
            ['mount', '-t', self.vfstype, '-o', 'noatime,noexec,nodev',
             '--', self.device.devpath, mpoint])
        try:
            yield mpoint
        finally:
            quiet_call('umount -- '.split() + [mpoint])
            os.rmdir(mpoint)

    def is_mounted(self):
        dn = '%d:%d' % self.device.devnum
        with open('/proc/self/mountinfo') as mounts:
            for line in mounts:
                items = line.split()
                if False:
                    idx = items.index('-')
                    fs_type = items[idx + 1]
                    opts1 = items[5].split(',')
                    opts2 = items[idx + 3].split(',')
                    readonly = 'ro' in opts1 + opts2
                    intpath = items[3]
                    mpoint = items[4]
                    dev = os.path.realpath(items[idx + 2])
                devnum = items[2]
                if dn == devnum:
                    return True
        return False


    def _mount_and_resize(self, pos):
        if self.resize_needs_mpoint and not self.is_mounted():
            with self.temp_mount():
                self._resize(pos)
        else:
            self._resize(pos)

        # measure size again
        self.read_superblock()
        assert self.fssize == pos

    def grow_nonrec(self, upper_bound):
        newsize = align(upper_bound, self.block_size)
        assert self.fssize <= newsize
        if self.fssize == newsize:
            return
        self._mount_and_resize(newsize)
        return newsize

    @property
    def fssize(self):
        if self.sb_size_in_bytes:
            assert self.size_bytes % self.block_size == 0
            return self.size_bytes
        else:
            return self.block_size * self.block_count

    @memoized_property
    def fslabel(self):
        return subprocess.check_output(
            'blkid -o value -s LABEL --'.split() + [self.device.devpath]
        ).rstrip().decode('ascii')

    @memoized_property
    def fsuuid(self):
        return subprocess.check_output(
            'blkid -o value -s UUID --'.split() + [self.device.devpath]
        ).rstrip().decode('ascii')


class SimpleContainer(BlockData):
    # A single block device that wraps a single block device
    # (luks is one, but not lvm, lvm is m2m)

    offset = None


class BCacheBacking(SimpleContainer):
    def read_superblock(self):
        self.offset = None

        proc = subprocess.Popen(
            ['bcache-super-show', '--', self.device.devpath],
            stdout=subprocess.PIPE)
        for line in proc.stdout:
            if line.startswith(b'dev.data.first_sector'):
                line = line.decode('ascii')
                self.offset = int(line.split(maxsplit=1)[1]) * 512
        proc.wait()
        assert proc.returncode == 0


class LUKS(SimpleContainer):
    """
    pycryptsetup isn't used because:
        it isn't in PyPI, or in Debian or Ubuntu
        it isn't Python 3
        it's incomplete (resize not included)
    """

    _superblock_read = False

    def activate(self, dmname):
        # cs.activate
        subprocess.check_call(
            ['cryptsetup', 'luksOpen', '--', self.device.devpath, dmname])

    def deactivate(self):
        while True:
            dev = self.snoop_activated()
            if dev is None:
                break
            subprocess.check_call(
                ['cryptsetup', 'remove', '--', dev.devpath])
        type(self).cleartext_device._reset(self)

    def snoop_activated(self):
        for hld in self.device.iter_holders():
            if not self._superblock_read:
                self.read_superblock()
            match = dm_crypt_re.match(hld.dm_table())
            # Having the correct offset ensures we're not getting
            # the size of a smaller filesystem inside the partition
            if (
                match and
                int(match.group('offset')) == bytes_to_sector(self.offset)
           ):
                return hld

    @memoized_property
    def cleartext_device(self):
        # If the device is already activated we won't have
        # to prompt for a passphrase.
        dev = self.snoop_activated()
        if dev is None:
            dmname = 'cleartext-{}'.format(uuid.uuid1())
            self.activate(dmname)
            dev = BlockDevice('/dev/mapper/' + dmname)
        return dev

    def read_superblock(self):
        # read the cyphertext's luks superblock
        #self.offset = cs.info()['offset']  # pycryptsetup
        self.offset = None

        proc = subprocess.Popen(
            ['cryptsetup', 'luksDump', '--', self.device.devpath],
            stdout=subprocess.PIPE)
        for line in proc.stdout:
            if line.startswith(b'Payload offset:'):
                line = line.decode('ascii')
                self.offset = int(line.split(':', 1)[1]) * 512
        proc.wait()
        assert proc.returncode == 0
        self._superblock_read = True

    def read_superblock_ll(self, fd):
        # Low-level
        # https://cryptsetup.googlecode.com/git/docs/on-disk-format.pdf

        magic, version = struct.unpack('>6sH', os.pread(fd, 8, 0))
        assert magic == b'LUKS\xBA\xBE', magic
        assert version == 1

        payload_start_sectors, key_bytes = struct.unpack(
            '>2I', os.pread(fd, 8, 104))
        sb_end = 592

        for key_slot in range(8):
            key_offset, key_stripes = struct.unpack(
                '>2I', os.pread(fd, 8, 208 + 48 * key_slot + 40))
            assert key_stripes == 4000
            key_size = key_stripes * key_bytes
            key_end = key_offset * 512 + key_size
            if key_end > sb_end:
                sb_end = key_end

        ll_offset = payload_start_sectors * 512
        assert ll_offset == self.offset, (ll_offset, self.offset)
        assert ll_offset >= sb_end
        self.sb_end = sb_end

    def shift_sb(self, fd, shift_by):
        assert shift_by > 0
        assert shift_by % 512 == 0
        assert self.offset % 512 == 0
        assert self.sb_end + shift_by <= self.offset

        # Read the superblock
        sb = os.pread(fd, self.sb_end, 0)
        assert len(sb) == self.sb_end

        # Edit the sb
        offset_sectors, = struct.unpack_from('>I', sb, 104)
        assert offset_sectors * 512 == self.offset
        sb = bytearray(sb)
        struct.pack_into(
            '>I', sb, 104, offset_sectors - shift_by // 512)
        sb = bytes(sb)

        # Wipe the magic and write the shifted, edited superblock
        wr_len = os.pwrite(fd, b'\0' * shift_by + sb, 0)
        assert wr_len == shift_by + self.sb_end

        # Wipe the results of read_superblock_ll
        # Keep self.offset for now
        del self.sb_end

    def grow_nonrec(self, upper_bound):
        return self.reserve_end_area_nonrec(upper_bound)

    def reserve_end_area_nonrec(self, pos):
        # cryptsetup uses the inner size
        inner_size = pos - self.offset
        sectors = bytes_to_sector(inner_size)

        # pycryptsetup is useless, no resize support
        # otoh, size doesn't appear in the superblock,
        # and updating the dm table is only useful if
        # we want to do some fsck before deactivating
        subprocess.check_call(
            ['cryptsetup', 'resize', '--size=%d' % sectors,
             '--', self.cleartext_device.devpath])
        if self.snoop_activated():
            self.cleartext_device.reset_size()
            assert self.cleartext_device.size == inner_size
        return pos


class XFS(Filesystem):
    can_shrink = False
    resize_needs_mpoint = True
    vfstype = 'xfs'

    def read_superblock(self):
        self.block_size = None
        self.block_count = None

        proc = subprocess.Popen(
            ['xfs_db', '-c', 'sb 0', '-c', 'p dblocks blocksize',
             '--', self.device.devpath], stdout=subprocess.PIPE)
        for line in proc.stdout:
            if line.startswith(b'dblocks ='):
                line = line.decode('ascii')
                self.block_count = int(line.split('=', 1)[1])
            elif line.startswith(b'blocksize ='):
                line = line.decode('ascii')
                self.block_size = int(line.split('=', 1)[1])
        proc.wait()
        assert proc.returncode == 0

    def _resize(self, target_size):
        assert target_size % self.block_size == 0
        target_blocks = target_size // self.block_size
        quiet_call(
            ['xfs_growfs', '-D', '%d' % target_blocks,
             '--', self.device.devpath])


class NilFS(Filesystem):
    can_shrink = True
    sb_size_in_bytes = True
    resize_needs_mpoint = True
    vfstype = 'nilfs2'

    def read_superblock(self):
        self.block_size = None
        self.size_bytes = None

        proc = subprocess.Popen(
            'nilfs-tune -l --'.split() + [self.device.devpath],
            stdout=subprocess.PIPE)

        for line in proc.stdout:
            if line.startswith(b'Block size:'):
                line = line.decode('ascii')
                self.block_size = int(line.split(':', 1)[1])
            elif line.startswith(b'Device size:'):
                line = line.decode('ascii')
                self.size_bytes = int(line.split(':', 1)[1])
        proc.wait()
        assert proc.returncode == 0

    def _resize(self, target_size):
        assert target_size % self.block_size == 0
        quiet_call(
            ['nilfs-resize', '--yes', '--',
             self.device.devpath, '%d' % target_size])


class BtrFS(Filesystem):
    can_shrink = True
    sb_size_in_bytes = True
    # We'll get the mpoint ourselves
    resize_needs_mpoint = False
    vfstype = 'btrfs'

    def read_superblock(self):
        self.block_size = None
        self.size_bytes = None
        self.devid = None

        proc = subprocess.Popen(
            'btrfs-show-super --'.split() + [self.device.devpath],
            stdout=subprocess.PIPE)

        for line in proc.stdout:
            if line.startswith(b'dev_item.devid'):
                line = line.decode('ascii')
                self.devid = int(line.split(maxsplit=1)[1])
            elif line.startswith(b'sectorsize'):
                line = line.decode('ascii')
                self.block_size = int(line.split(maxsplit=1)[1])
            elif line.startswith(b'dev_item.total_bytes'):
                line = line.decode('ascii')
                self.size_bytes = int(line.split(maxsplit=1)[1])
        proc.wait()
        assert proc.returncode == 0

    def _resize(self, target_size):
        assert target_size % self.block_size == 0
        # XXX The device is unavailable (EBUSY)
        # immediately after unmounting.
        # Bug introduced in Linux 3.0, fixed in 3.9.
        # Tracked down by Eric Sandeen in
        # http://comments.gmane.org/gmane.comp.file-systems.btrfs/23987
        with self.temp_mount() as mpoint:
            quiet_call(
                'btrfs filesystem resize'.split()
                + ['{}:{}'.format(self.devid, target_size), mpoint])


class ReiserFS(Filesystem):
    can_shrink = True

    def read_superblock(self):
        self.block_size = None
        self.block_count = None

        proc = subprocess.Popen(
            'reiserfstune --'.split() + [self.device.devpath],
            stdout=subprocess.PIPE)

        for line in proc.stdout:
            if line.startswith(b'Blocksize:'):
                line = line.decode('ascii')
                self.block_size = int(line.split(':', 1)[1])
            elif line.startswith(b'Count of blocks on the device:'):
                line = line.decode('ascii')
                self.block_count = int(line.split(':', 1)[1])
        proc.wait()
        assert proc.returncode == 0

    def _resize(self, target_size):
        assert target_size % self.block_size == 0
        subprocess.check_call(
            ['resize_reiserfs', '-q', '-s', '%d' % target_size,
             '--', self.device.devpath])


class ExtFS(Filesystem):
    can_shrink = True

    def read_superblock(self):
        self.block_size = None
        self.block_count = None
        self.state = None
        self.mount_tm = None
        self.check_tm = None

        proc = subprocess.Popen(
            'tune2fs -l --'.split() + [self.device.devpath],
            stdout=subprocess.PIPE)

        for line in proc.stdout:
            if line.startswith(b'Block size:'):
                line = line.decode('ascii')
                self.block_size = int(line.split(':', 1)[1])
            elif line.startswith(b'Block count:'):
                line = line.decode('ascii')
                self.block_count = int(line.split(':', 1)[1])
            elif line.startswith(b'Filesystem state:'):
                line = line.decode('ascii')
                self.state = line.split(':', 1)[1].strip()
            elif line.startswith(b'Last mount time:'):
                line = line.decode('ascii')
                date = line.split(':', 1)[1].strip()
                if date == 'n/a':
                    self.mount_tm = time.gmtime(0)
                else:
                    self.mount_tm = time.strptime(date)
            elif line.startswith(b'Last checked:'):
                line = line.decode('ascii')
                self.check_tm = time.strptime(line.split(':', 1)[1].strip())
        proc.wait()
        assert proc.returncode == 0

    def _resize(self, target_size):
        block_count, rem = divmod(target_size, self.block_size)
        assert rem == 0

        # resize2fs requires that the filesystem was checked
        if not self.is_mounted() and (self.state != 'clean' or self.check_tm < self.mount_tm):
            print('Checking the filesystem before resizing it')
            # Can't use the -n flag, it is strictly read-only and won't
            # update check_tm in the superblock
            # XXX Without either of -n -p -y, e2fsck will require a
            # terminal on stdin
            subprocess.check_call(
                'e2fsck -f --'.split() + [self.device.devpath])
            # Another option:
            #quiet_call('e2fsck -fp --'.split() + [self.device.devpath])
            self.check_tm = self.mount_tm
        quiet_call(
            'resize2fs --'.split() + [self.device.devpath, '%d' % block_count])


class BlockStack:
    def __init__(self, stack):
        self.stack = stack

    @property
    def wrappers(self):
        return self.stack[:-1]

    @property
    def overhead(self):
        return sum(wrapper.offset for wrapper in self.wrappers)

    @property
    def topmost(self):
        return self.stack[-1]

    @property
    def fsuuid(self):
        return self.topmost.fsuuid

    @property
    def fslabel(self):
        return self.topmost.fslabel

    def iter_pos(self, pos):
        for block_data in self.wrappers:
            yield pos, block_data
            pos -= block_data.offset
        yield pos, self.topmost

    # Don't memoize this one (fssize changes)
    @property
    def total_data_size(self):
        return self.topmost.fssize + self.overhead

    def stack_resize(self, pos, *, shrink, progress):
        if shrink:
            self.stack_reserve_end_area(pos, progress)
        else:
            self.stack_grow(pos, progress)

    def stack_grow(self, newsize, progress):
        for block_data in self.wrappers:
            newsize = block_data.grow_nonrec(newsize)
            newsize -= block_data.offset
        self.topmost.grow_nonrec(newsize)

    def stack_reserve_end_area(self, pos, progress):
        inner_pos = align(pos - self.overhead, self.topmost.block_size)
        shrink_size = self.topmost.fssize - inner_pos
        fstype = self.topmost.device.superblock_type

        if self.topmost.fssize > inner_pos:
            if self.topmost.can_shrink:
                progress.notify(
                    'Will shrink the filesystem ({}) by {} bytes'
                    .format(fstype, shrink_size))
            else:
                err = CantShrink(self.topmost)
                progress.notify_error(
                    'Can\'t shrink filesystem ({}), but need another {} bytes '
                    'at the end'.format(fstype, shrink_size), err)
                raise err
        else:
            progress.notify(
                'The filesystem ({}) leaves enough room, '
                'no need to shrink it'.format(fstype))

        # While there may be no need to shrink the topmost fs,
        # the wrapper stack needs to be updated for the new size
        for inner_pos, block_data in reversed(list(self.iter_pos(pos))):
            block_data.reserve_end_area_nonrec(inner_pos)

    def read_superblocks(self):
        for wrapper in self.wrappers:
            wrapper.read_superblock()
        self.topmost.read_superblock()

    def deactivate(self):
        for wrapper in reversed(self.wrappers):
            wrapper.deactivate()
        # Salt the earth, our devpaths are obsolete now
        del self.stack


def get_block_stack(device, progress):
    # this cries for a conslist
    stack = []
    while True:
        if device.superblock_type == 'crypto_LUKS':
            wrapper = LUKS(device)
            stack.append(wrapper)
            device = wrapper.cleartext_device
            continue

        if device.superblock_type in {'ext2', 'ext3', 'ext4'}:
            stack.append(ExtFS(device))
        elif device.superblock_type == 'reiserfs':
            stack.append(ReiserFS(device))
        elif device.superblock_type == 'btrfs':
            stack.append(BtrFS(device))
        elif device.superblock_type == 'nilfs2':
            stack.append(NilFS(device))
        elif device.superblock_type == 'xfs':
            stack.append(XFS(device))
        else:
            err = UnsupportedSuperblock(device=device)
            if device.superblock_type is None:
                progress.notify_error('Unrecognised superblock', err)
            else:
                progress.notify_error(
                    'Unsupported superblock type: {}'
                    .format(err.device.superblock_type), err)
            raise err

        # only reached when we ended on a filesystem
        return BlockStack(stack)


class SyntheticDevice(BlockDevice):
    def copy_to_physical(
        self, dev_fd, *, shift_by=0, reserved_area=None, other_device=False
    ):
        assert (
            len(self.data) == self.writable_hdr_size + self.writable_end_size)
        start_data = self.data[:self.writable_hdr_size]
        end_data = self.data[self.writable_hdr_size:]
        wrend_offset = self.writable_hdr_size + self.rz_size + shift_by
        size = self.writable_hdr_size + self.rz_size + self.writable_end_size

        if shift_by < 0:
            assert not other_device

            # Means we should rotate to the left
            # Update shift_by *after* setting wrend_offset
            shift_by += size

        if reserved_area is not None:
            assert shift_by >= reserved_area
            assert wrend_offset >= reserved_area

        if not other_device:
            assert 0 <= shift_by < shift_by + self.writable_hdr_size <= size
            if self.writable_end_size != 0:
                assert 0 <= wrend_offset < (
                    wrend_offset + self.writable_end_size) <= size

        # Write then read back
        assert os.pwrite(
            dev_fd, start_data, shift_by) == self.writable_hdr_size
        assert os.pread(dev_fd, self.writable_hdr_size, shift_by) == start_data

        if self.writable_end_size != 0:
            assert os.pwrite(
                dev_fd, end_data, wrend_offset) == self.writable_end_size
            assert os.pread(
                dev_fd, self.writable_end_size, wrend_offset) == end_data


class ProgressListener:
    pass


class CLIProgressHandler(ProgressListener):
    """A progress listener that prints messages and exits on error.
    """

    def notify(self, msg):
        print(msg)

    def notify_error(self, msg, err):
        """Takes an exception so ProgressListener callers remember to raise it.

        Even though this implementation won't return, others would.
        """

        print(msg, file=sys.stderr)
        sys.exit(2)


@contextlib.contextmanager
def synth_device(writable_hdr_size, rz_size, writable_end_size=0):
    writable_sectors = bytes_to_sector(writable_hdr_size)
    wrend_sectors = bytes_to_sector(writable_end_size)
    rz_sectors = bytes_to_sector(rz_size)
    wrend_sectors_offset = writable_sectors + rz_sectors

    with contextlib.ExitStack() as st:
        imgf = st.enter_context(tempfile.NamedTemporaryFile(suffix='.img'))
        imgf.truncate(writable_hdr_size + writable_end_size)

        lo_dev = subprocess.check_output(
            'losetup -f --show --'.split() + [imgf.name]
        ).rstrip().decode('ascii')
        st.callback(
            lambda: quiet_call('losetup -d --'.split() + [lo_dev]))
        rozeros_devname = 'rozeros-{}'.format(uuid.uuid1())
        synth_devname = 'synthetic-{}'.format(uuid.uuid1())
        synth_devpath = '/dev/mapper/' + synth_devname

        # The readonly flag is ignored when stacked under a linear
        # target, so the use of an intermediate device does not bring
        # the expected benefit. This forces us to use the 'error'
        # target to catch writes that are out of bounds.
        # LVM will ignore read errors in the discovery phase (we hide
        # the output), and will fail on write errors appropriately.
        mk_dm(
            rozeros_devname,
            '0 {rz_sectors} error\n'
            .format(
                rz_sectors=rz_sectors),
            readonly=True,
            exit_stack=st)
        dm_table_format = (
            '0 {writable_sectors} linear {lo_dev} 0\n'
            '{writable_sectors} {rz_sectors} linear {rozeros_devpath} 0\n')
        if writable_end_size:
            dm_table_format += (
                '{wrend_sectors_offset} {wrend_sectors} '
                'linear {lo_dev} {writable_sectors}\n')
        mk_dm(
            synth_devname,
            dm_table_format.format(
                writable_sectors=writable_sectors, lo_dev=lo_dev,
                rz_sectors=rz_sectors, wrend_sectors=wrend_sectors,
                wrend_sectors_offset=wrend_sectors_offset,
                rozeros_devpath='/dev/mapper/' + rozeros_devname),
            readonly=False,
            exit_stack=st)

        synth = SyntheticDevice(synth_devpath)
        yield synth

        data = imgf.read()
        assert len(data) == writable_hdr_size + writable_end_size

        # Expose the data outside of the with statement
        synth.data = data
        synth.rz_size = rz_size
        synth.writable_hdr_size = writable_hdr_size
        synth.writable_end_size = writable_end_size


def rotate_aug(aug, forward, size):
    segment_count = aug.get_int('$lv/segment_count')
    pe_sectors = aug.get_int('$vg/extent_size')
    extent_total = 0

    aug.incr('$lv/segment_count')

    # checking all segments are linear
    for i in range(1, segment_count + 1):
        assert aug.get(
            '$lv/segment{}/dict/type/str'.format(i)) == 'striped'
        assert aug.get_int(
            '$lv/segment{}/dict/stripe_count'.format(i)) == 1
        extent_total += aug.get_int(
            '$lv/segment{}/dict/extent_count'.format(i))

    assert extent_total * pe_sectors == bytes_to_sector(size)
    assert extent_total > 1

    if forward:
        # Those definitions can't be factored out,
        # because we move nodes and the vars would follow
        aug.defvar('first', '$lv/segment1/dict')
        # shifting segments
        for i in range(2, segment_count + 1):
            aug.decr('$lv/segment{}/dict/start_extent'.format(i))

        # shrinking first segment by one PE
        aug.decr('$first/extent_count')

        # inserting new segment at the end
        aug.insert(
            '$lv/segment{}'.format(segment_count),
            'segment{}'.format(segment_count + 1),
            before=False)
        aug.set_int(
            '$lv/segment{}/dict/start_extent'.format(segment_count + 1),
            extent_total - 1)
        aug.defvar('last', '$lv/segment{}/dict'.format(segment_count + 1))
        aug.set_int('$last/extent_count', 1)
        aug.set('$last/type/str', 'striped')
        aug.set_int('$last/stripe_count', 1)

        # repossessing the first segment's first PE
        aug.set(
            '$last/stripes/list/1/str',
            aug.get('$first/stripes/list/1/str'))
        aug.set_int(
            '$last/stripes/list/2',
            aug.get_int('$first/stripes/list/2'))
        aug.incr('$first/stripes/list/2')

        # Cleaning up an empty first PE
        if aug.get_int('$first/extent_count') == 0:
            aug.remove('$lv/segment1')
            for i in range(2, segment_count + 2):
                aug.rename('$lv/segment{}'.format(i), 'segment{}'.format(i - 1))
            aug.decr('$lv/segment_count')
    else:
        # shifting segments
        for i in range(segment_count, 0, -1):
            aug.incr('$lv/segment{}/dict/start_extent'.format(i))
            aug.rename('$lv/segment{}'.format(i), 'segment{}'.format(i + 1))
        aug.defvar('last', '$lv/segment{}/dict'.format(segment_count + 1))

        # shrinking last segment by one PE
        aug.decr('$last/extent_count')
        last_count = aug.get_int('$last/extent_count')

        # inserting new segment at the beginning
        aug.insert('$lv/segment2', 'segment1')
        aug.set_int('$lv/segment1/dict/start_extent', 0)
        aug.defvar('first', '$lv/segment1/dict')
        aug.set_int('$first/extent_count', 1)
        aug.set('$first/type/str', 'striped')
        aug.set_int('$first/stripe_count', 1)

        # repossessing the last segment's last PE
        aug.set(
            '$first/stripes/list/1/str',
            aug.get('$last/stripes/list/1/str'))
        aug.set_int(
            '$first/stripes/list/2',
            aug.get_int('$last/stripes/list/2') + last_count)

        # Cleaning up an empty last PE
        if last_count == 0:
            aug.remove('$lv/segment{}'.format(segment_count + 1))
            aug.decr('$lv/segment_count')


def rotate_lv(*, device, size, debug, forward):
    """Rotate a logical volume by a single PE.

    If forward:
        Move the first physical extent of an LV to the end
    else:
        Move the last physical extent of a LV to the start

    then poke LVM to refresh the mapping.
    """

    import augeas
    class Augeas(augeas.Augeas):
        def get_int(self, key):
            return int(self.get(key + '/int'))

        def set_int(self, key, val):
            return self.set(key + '/int', '%d' % val)

        def incr(self, key, by=1):
            orig = self.get_int(key)
            self.set_int(key, orig + by)

        def decr(self, key):
            self.incr(key, by=-1)

    lv_info = subprocess.check_output(
        'lvm lvs --noheadings --rows --units=b --nosuffix '
        '-o vg_name,vg_uuid,lv_name,lv_uuid,lv_attr --'.split()
        + [device.devpath], universal_newlines=True).splitlines()
    vgname, vg_uuid, lvname, lv_uuid, lv_attr = (fi.lstrip() for fi in lv_info)
    active = lv_attr[4] == 'a'

    # Make sure the volume isn't in use by unmapping it
    quiet_call(
        ['lvm', 'lvchange', '-an', '--', '{}/{}'.format(vgname, lvname)])

    with tempfile.TemporaryDirectory(suffix='.blocks') as tdname:
        vgcfgname = tdname + '/vg.cfg'
        print('Loading LVM metadata... ', end='', flush=True)
        quiet_call(
            ['lvm', 'vgcfgbackup', '--file', vgcfgname, '--', vgname])
        aug = Augeas(
            loadpath=pkg_resources.resource_filename('blocks', 'augeas'),
            root='/dev/null',
            flags=augeas.Augeas.NO_MODL_AUTOLOAD | augeas.Augeas.SAVE_NEWFILE)
        vgcfg = open(vgcfgname)
        vgcfg_orig = vgcfg.read()
        aug.set('/raw/vgcfg', vgcfg_orig)

        aug.text_store('LVM.lns', '/raw/vgcfg', '/vg')
        print('ok')

        # There is no easy way to quote for XPath, so whitelist
        assert all(ch in ASCII_ALNUM_WHITELIST for ch in vgname), vgname
        assert all(ch in ASCII_ALNUM_WHITELIST for ch in lvname), lvname

        aug.defvar('vg', '/vg/{}/dict'.format(vgname))
        assert aug.get('$vg/id/str') == vg_uuid
        aug.defvar('lv', '$vg/logical_volumes/dict/{}/dict'.format(lvname))
        assert aug.get('$lv/id/str') == lv_uuid

        rotate_aug(aug, forward, size)
        aug.text_retrieve('LVM.lns', '/raw/vgcfg', '/vg', '/raw/vgcfg.new')
        open(vgcfgname + '.new', 'w').write(aug.get('/raw/vgcfg.new'))
        rotate_aug(aug, not forward, size)
        aug.text_retrieve('LVM.lns', '/raw/vgcfg', '/vg', '/raw/vgcfg.backagain')
        open(vgcfgname + '.backagain', 'w').write(aug.get('/raw/vgcfg.backagain'))

        if debug:
            print('CHECK STABILITY')
            subprocess.call(
                ['git', '--no-pager', 'diff', '--no-index', '--patience', '--color-words',
                 '--', vgcfgname, vgcfgname + '.backagain'])
            if forward:
                print('CHECK CORRECTNESS (forward)')
            else:
                print('CHECK CORRECTNESS (backward)')
            subprocess.call(
                ['git', '--no-pager', 'diff', '--no-index', '--patience', '--color-words',
                 '--', vgcfgname, vgcfgname + '.new'])

        if forward:
            print(
                'Rotating the second extent to be the first... ',
                end='', flush=True)
        else:
            print(
                'Rotating the last extent to be the first... ',
                end='', flush=True)
        quiet_call(
            ['lvm', 'vgcfgrestore', '--file', vgcfgname + '.new', '--', vgname])
        # Make sure LVM updates the mapping, this is pretty critical
        quiet_call(
            ['lvm', 'lvchange', '--refresh', '--', '{}/{}'.format(vgname, lvname)])
        if active:
            quiet_call(
                ['lvm', 'lvchange', '-ay', '--', '{}/{}'.format(vgname, lvname)])
        print('ok')


def make_bcache_sb(bsb_size, data_size, join):
    with synth_device(bsb_size, data_size) as synth_bdev:
        cmd = ['make-bcache', '--bdev', '--data_offset',
               '%d' % bytes_to_sector(bsb_size), synth_bdev.devpath]
        if join is not None:
            cmd[1:1] = ['--cset-uuid', join]
        quiet_call(cmd)
        bcache_backing = BCacheBacking(synth_bdev)
        bcache_backing.read_superblock()
        assert bcache_backing.offset == bsb_size
    return synth_bdev


def lv_to_bcache(device, debug, progress, join):
    pe_size = int(subprocess.check_output(
        'lvm lvs --noheadings --rows --units=b --nosuffix '
        '-o vg_extent_size --'.split()
        + [device.devpath], universal_newlines=True))

    assert device.size % pe_size == 0
    data_size = device.size - pe_size

    block_stack = get_block_stack(device, progress)
    block_stack.read_superblocks()
    block_stack.stack_reserve_end_area(data_size, progress)
    block_stack.deactivate()
    del block_stack

    dev_fd = device.open_excl()

    synth_bdev = make_bcache_sb(pe_size, data_size, join)
    print('Copying the bcache superblock... ', end='', flush=True)
    synth_bdev.copy_to_physical(dev_fd, shift_by=-pe_size)
    print('ok')

    os.close(dev_fd)
    del dev_fd

    rotate_lv(
        device=device, size=device.size, debug=debug, forward=False)


def luks_to_bcache(device, debug, progress, join):
    luks = LUKS(device)
    luks.deactivate()
    dev_fd = device.open_excl()
    luks.read_superblock()
    luks.read_superblock_ll(dev_fd)
    # The smallest and most compatible bcache offset
    shift_by = 512*16
    assert luks.sb_end + shift_by <= luks.offset
    data_size = device.size - shift_by
    synth_bdev = make_bcache_sb(shift_by, data_size, join)

    # XXX not atomic
    print('Shifting and editing the LUKS superblock... ', end='', flush=True)
    luks.shift_sb(dev_fd, shift_by=shift_by)
    print('ok')

    print('Copying the bcache superblock... ', end='', flush=True)
    synth_bdev.copy_to_physical(dev_fd)
    os.close(dev_fd)
    del dev_fd
    print('ok')


def part_to_bcache(device, debug, progress, join):
    # Detect the alignment parted would use?
    # I don't think it can be greater than 1MiB, in which case
    # there is no need.
    bsb_size = 1024**2
    data_size = device.size

    ptable, part_start = device.ptable_context()
    ptable.reserve_space_before(part_start, bsb_size, progress)
    part_start1 = part_start - bsb_size

    import _ped
    write_part = ptable.parted_disk.getPartitionBySector(part_start1 // 512)

    if write_part.type == _ped.PARTITION_NORMAL:
        write_offset = part_start1 - (512 * write_part.geometry.start)
        dev_fd = os.open(write_part.path, os.O_SYNC|os.O_RDWR|os.O_EXCL)
    elif write_part.type == _ped.PARTITION_FREESPACE:
        # XXX Can't open excl if one of the partitions is used by dm, apparently
        dev_fd = ptable.device.open_excl()
        write_offset = part_start1
    else:
        print(
            'Can\'t write outside of a normal partition (marked {})'
            .format(_ped.partition_type_get_name(write_part.type)),
            file=sys.stderr)
        return 1

    synth_bdev = make_bcache_sb(bsb_size, data_size, join)
    print('Copying the bcache superblock... ', end='', flush=True)
    synth_bdev.copy_to_physical(
        dev_fd, shift_by=write_offset, other_device=True)
    os.close(dev_fd)
    del dev_fd
    print('ok')

    # Check the partition we're about to convert isn't in use either,
    # otherwise the partition table couldn't be reloaded.
    dev_fd = device.open_excl()
    os.close(dev_fd)
    del dev_fd

    print(
        'Shifting partition to start on the bcache superblock... ',
        end='', flush=True)
    ptable.shift_left(part_start, part_start1)
    print('ok')
    device.reset_size()


SIZE_RE = re.compile(r'^(\d+)([bkmgtpe])?\Z')


def parse_size_arg(size):
    match = SIZE_RE.match(size.lower())
    if not match:
        raise argparse.ArgumentTypeError(
            'Size must be a decimal integer '
            'and a one-character unit suffix (bkmgtpe)')
    val = int(match.group(1))
    unit = match.group(2)
    if unit is None:
        unit = 'b'
    # reserving uppercase in case decimal units are needed
    return val * 1024**'bkmgtpe'.find(unit)


def main():
    try:
        assert False
    except AssertionError:
        pass
    else:
        print('Assertions need to be enabled', file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    commands = parser.add_subparsers(dest='command', metavar='command')

    sp_to_lvm = commands.add_parser(
        'to-lvm', aliases=['lvmify'],
        help='Convert to LVM')
    sp_to_lvm.add_argument('device')
    vg_flags = sp_to_lvm.add_mutually_exclusive_group()
    vg_flags.add_argument('--vg-name', dest='vgname', type=str)
    vg_flags.add_argument('--join', metavar='VG-NAME-OR-UUID')
    sp_to_lvm.set_defaults(action=cmd_to_lvm)

    sp_to_bcache = commands.add_parser(
        'to-bcache',
        help='Convert to bcache')
    sp_to_bcache.add_argument('device')
    sp_to_bcache.add_argument('--join', metavar='CSET-UUID')
    sp_to_bcache.set_defaults(action=cmd_to_bcache)

    # Undoes an lv to bcache conversion; useful to migrate from the GPT
    # format to the bcache-offset format.
    # No help, keep this undocumented for now
    sp_rotate = commands.add_parser(
        'rotate')
        #help='Rotate LV contents to start at the second PE')
    sp_rotate.add_argument('device')
    sp_rotate.set_defaults(action=cmd_rotate)

    sp_resize = commands.add_parser('resize')
    sp_resize.add_argument('device')
    sp_resize.add_argument(
        '--resize-device', action='store_true',
        help='Resize the device, not just the contents.'
        ' The device must be a partition or a logical volume.')
    sp_resize.add_argument(
        'newsize', type=parse_size_arg,
        help='new size in byte units;'
        ' bkmgtpe suffixes are accepted, in powers of 1024 units')
    sp_resize.set_defaults(action=cmd_resize)

    # Give help when no subcommand is given
    if not sys.argv[1:]:
        parser.print_help()
        return

    args = parser.parse_args()
    return args.action(args)


def cmd_resize(args):
    device = BlockDevice(args.device)
    newsize = args.newsize
    resize_device = args.resize_device
    debug = args.debug
    progress = CLIProgressHandler()

    block_stack = get_block_stack(device, progress)

    device_delta = newsize - device.size

    if device_delta > 0 and resize_device:
        device.dev_resize(newsize, shrink=False)
        # May have been rounded up for the sake of partition alignment
        # LVM rounds up as well (and its LV metadata uses PE units)
        newsize = device.size

    block_stack.read_superblocks()
    assert block_stack.total_data_size <= device.size
    data_delta = newsize - block_stack.total_data_size
    block_stack.stack_resize(newsize, shrink=data_delta < 0, progress=progress)

    if device_delta < 0 and resize_device:
        tds = block_stack.total_data_size
        # LVM should be able to reload in-use devices,
        # but the kernel's partition handling can't.
        if device.is_partition:
            block_stack.deactivate()
            del block_stack
        device.dev_resize(tds, shrink=True)


def cmd_rotate(args):
    device = BlockDevice(args.device)
    debug = args.debug
    progress = CLIProgressHandler()

    pe_size = int(subprocess.check_output(
        'lvm lvs --noheadings --rows --units=b --nosuffix '
        '-o vg_extent_size --'.split()
        + [device.devpath], universal_newlines=True))

    if device.superblock_at(pe_size) is None:
        print('No superblock on the second PE, exiting', file=sys.stderr)
        return 1

    rotate_lv(
        device=device, size=device.size, debug=debug, forward=True)


def cmd_to_bcache(args):
    device = BlockDevice(args.device)
    debug = args.debug
    join = args.join
    progress = CLIProgressHandler()

    if device.has_bcache_superblock:
        print(
            'Device {} already has a bcache super block.'
            .format(device.devpath), file=sys.stderr)
        return 1

    if device.is_partition:
        return part_to_bcache(device, debug, progress, join)
    elif device.is_lv:
        return lv_to_bcache(device, debug, progress, join)
    elif device.superblock_type == 'crypto_LUKS':
        return luks_to_bcache(device, debug, progress, join)
    else:
        print(
            'Device {} is not a partition or a logical volume'
            .format(device.devpath),
            file=sys.stderr)
        return 1


def cmd_to_lvm(args):
    device = BlockDevice(args.device)
    debug = args.debug

    if args.join is not None:
        vg_info = subprocess.check_output(
            'lvm vgs --noheadings --rows --units=b --nosuffix '
            '-o vg_name,vg_uuid,vg_extent_size --'.split()
            + [args.join], universal_newlines=True).splitlines()
        join_name, join_uuid, pe_size = (fi.lstrip() for fi in vg_info)
        # Pick something unique, temporary until vgmerge
        vgname = uuid.uuid1().hex
        pe_size = int(pe_size)
    elif args.vgname is not None:
        # Check no VG with that name exists?
        # No real need, vgrename uuid newname would fix any collision
        vgname = args.vgname
        pe_size = LVM_PE_SIZE
    else:
        vgname = os.path.basename(device.devpath)
        pe_size = LVM_PE_SIZE

    assert vgname
    assert all(ch in ASCII_ALNUM_WHITELIST for ch in vgname)

    assert device.size % 512 == 0

    if device.superblock_type == 'LVM2_member':
        print(
            'Already a physical volume', file=sys.stderr)
        return 1

    progress = CLIProgressHandler()

    block_stack = get_block_stack(device, progress)

    if block_stack.fslabel:
        lvname = block_stack.fslabel
    else:
        lvname = os.path.basename(device.devpath)
    assert all(ch in ASCII_ALNUM_WHITELIST for ch in lvname)

    pe_sectors = bytes_to_sector(pe_size)
    # -1 because we reserve pe_size for the lvm label and one metadata area
    pe_count = device.size // pe_size - 1
    # The position of the moved pe
    pe_newpos = pe_count * pe_size

    if debug:
        print(
            'pe {} pe_newpos {} devsize {}'
            .format(pe_size, pe_newpos, device.size))

    block_stack.read_superblocks()
    block_stack.stack_reserve_end_area(pe_newpos, progress)

    fsuuid = block_stack.topmost.fsuuid
    block_stack.deactivate()
    del block_stack

    dev_fd = device.open_excl()
    print(
        'Copying {} bytes from pos 0 to pos {}... '
        .format(pe_size, pe_newpos),
        end='', flush=True)
    pe_data = os.pread(dev_fd, pe_size, 0)
    assert len(pe_data) == pe_size
    wr_len = os.pwrite(dev_fd, pe_data, pe_newpos)
    assert wr_len == pe_size
    print('ok')

    print('Preparing LVM metadata... ', end='', flush=True)

    # The changes so far (fs resize, possibly an fsck, and the copy)
    # should have no user-visible effects.

    # Create a virtual device to do the lvm setup
    with contextlib.ExitStack() as st:
        synth_pv = st.enter_context(
            synth_device(pe_size, device.size - pe_size))
        cfgf = st.enter_context(
            tempfile.NamedTemporaryFile(
                suffix='.vgcfg', mode='w', encoding='ascii',
                delete=not debug))

        pv_uuid = uuid.uuid1()
        vg_uuid = uuid.uuid1()
        lv_uuid = uuid.uuid1()

        cfgf.write(textwrap.dedent(
            '''
            contents = "Text Format Volume Group"
            version = 1

            {vgname} {{
                id = "{vg_uuid}"
                seqno = 0
                status = ["RESIZEABLE", "READ", "WRITE"]
                extent_size = {pe_sectors}
                max_lv = 0
                max_pv = 0

                physical_volumes {{
                    pv0 {{
                        id = "{pv_uuid}"
                        status = ["ALLOCATABLE"]

                        pe_start = {pe_sectors}
                        pe_count = {pe_count}
                    }}
                }}
                logical_volumes {{
                    {lvname} {{
                        id = "{lv_uuid}"
                        status = ["READ", "WRITE", "VISIBLE"]
                        segment_count = 2

                        segment1 {{
                            start_extent = 0
                            extent_count = 1
                            type = "striped"
                            stripe_count = 1 # linear
                            stripes = [
                                "pv0", {pe_count_pred}
                            ]
                        }}
                        segment2 {{
                            start_extent = 1
                            extent_count = {pe_count_pred}
                            type = "striped"
                            stripe_count = 1 # linear
                            stripes = [
                                "pv0", 0
                            ]
                        }}
                    }}
                }}
            }}
            '''.format(
                vgname=vgname,
                lvname=lvname,
                pe_sectors=pe_sectors,
                pv_uuid=pv_uuid,
                vg_uuid=vg_uuid,
                lv_uuid=lv_uuid,
                pe_count=pe_count,
                pe_count_pred=pe_count - 1,
            )))
        cfgf.flush()

        # Prevent the next two commands from scanning every device (slow),
        # we already know lvm should write only to the synthetic pv.
        # Also work in the presence of a broken udev; udev inside uml
        # appears to be fragile.
        lvm_cfg = ('--config='
                   'devices {{ filter=["a/^{synth_re}$/", "r/.*/"] }}'
                   'activation {{ verify_udev_operations = 1 }}'
                   .format(synth_re=re.escape(synth_pv.devpath)))

        quiet_call(
            ['lvm', 'pvcreate', lvm_cfg, '--restorefile', cfgf.name,
             '--uuid', str(pv_uuid), '--zero', 'y', '--',
             synth_pv.devpath])
        quiet_call(
            ['lvm', 'vgcfgrestore', lvm_cfg, '--file', cfgf.name, '--', vgname])
    print('ok')  # after 'Preparing LVM metadata'

    # Recovery: copy back the PE we had moved to the end of the device.
    print(
        'If the next stage is interrupted, it can be reverted with:\n'
        '    dd if={devpath} of={devpath} bs={pe_size} count=1 skip={pe_count} conv=notrunc'
        .format(
            devpath=device.devpath, pe_size=pe_size, pe_count=pe_count))

    print('Installing LVM metadata... ', end='', flush=True)
    # This had better be atomic
    # Though technically, only physical sector writes are guaranteed atomic
    synth_pv.copy_to_physical(dev_fd)
    print('ok')
    os.close(dev_fd)
    del dev_fd

    print('LVM conversion successful!')
    if args.join is not None:
        quiet_call(
            ['lvm', 'vgmerge', '--', join_name, vgname])
        vgname = join_name
    if False:
        print('Enable the volume group with\n'
              '    sudo lvm vgchange -ay -- {}'.format(vgname))
    elif False:
        print('Enable the logical volume with\n'
              '    sudo lvm lvchange -ay -- {}/{}'.format(vgname, lvname))
    else:
        print('Volume group name: {}\n'
              'Logical volume name: {}\n'
              'Filesystem uuid: {}'
              .format(vgname, lvname, fsuuid))


def script_main():
    sys.exit(main())


if __name__ == '__main__':
    script_main()

