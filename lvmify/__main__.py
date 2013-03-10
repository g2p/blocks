# Python 3.3

import argparse
import contextlib
import os
import re
import string
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid


# 4MiB PE, for vgmerge compatibility
LVM_PE = 4 * 1024**2


ASCII_ALNUM_WHITELIST = string.ascii_letters + string.digits


# Fairly strict, snooping an incorrect mapping would be bad
dm_crypt_re = re.compile(
    r'^0 (?P<plainsize>\d+) crypt (?P<cipher>[a-z0-9-]+) 0+ 0'
    ' (?P<major>\d+):(?P<minor>\d+) (?P<offset>\d+)\n$',
    re.ASCII)


def bytes_to_sector(by):
    sectors, rem = divmod(by, 512)
    assert rem == 0
    return sectors


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


class BlockDevice:
    def __init__(self, devpath):
        self.devpath = devpath

    @memoized_property
    def superblock_type(self):
        return subprocess.check_output(
            'blkid -o value -s TYPE --'.split() + [self.devpath]
        ).rstrip().decode('ascii')

    @memoized_property
    def has_bcache_superblock(self):
        # blkid doesn't detect bcache, so special-case it.
        # Exit status is always 0, check if there is output
        return bool(subprocess.check_output(
            ['probe-bcache', '--', self.devpath]))

    @memoized_property
    def size(self):
        rv = int(subprocess.check_output(
            'blockdev --getsize64'.split() + [self.devpath]))
        assert rv % 512 == 0
        return rv

    @property
    def sysfspath(self):
        # XXX Only works on /dev/sd?? style
        di, ba = os.path.split(self.devpath)
        assert di == '/dev'  # or realpath but yagni
        assert ba
        return '/sys/class/block/' + ba

    def iter_holders(self):
        for hld in os.listdir(self.sysfspath + '/holders'):
            yield BlockDevice('/dev/' + hld)

    def dm_table(self):
        return subprocess.check_output(
            'dmsetup table --'.split() + [self.devpath],
            universal_newlines=True)

    @memoized_property
    def is_partition(self):
        return os.path.exists(self.sysfspath + '/start')


def ptable_devpath(bdev):
    assert bdev.is_partition

    with open(bdev.sysfspath + '/../dev') as fi:
        devnum = fi.read().rstrip()
    return os.path.realpath('/dev/block/' + devnum)


def ptable_from_partition_device(bdev):
    return PartitionTable(PartitionedDevice(ptable_devpath(bdev)))


def start_of_partition(bdev):
    return int(open(bdev.sysfspath + '/start').read()) * 512


class PartitionedDevice(BlockDevice):
    @memoized_property
    def ptable_type(self):
        # TODO: also detect an MBR other than protective,
        # and refuse to edit that.
        return subprocess.check_output(
            'blkid -p -o value -s PTTYPE --'.split() + [self.devpath]
        ).rstrip().decode('ascii')

    @memoized_property
    def parted_device(self):
        import parted.device
        return parted.device.Device(self.devpath)


class BlockData:
    def __init__(self, device):
        self.device = device


class OverlappingPartition(Exception):
    pass


class PartitionTable(BlockData):
    @memoized_property
    def parted_disk(self):
        import parted.disk
        return parted.disk.Disk(self.device.parted_device)

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
        # round down
        start_sector = start // 512

        # round up
        end_sector = (end - 1) // 512 + 1

        part = None
        for part in self._iter_range(start_sector, end_sector):
            if part.geometry.start >= start_sector:
                err = OverlappingPartition(start, end, part)
                progress.notify_error(
                    'The range we want to reserve overlaps with '
                    'the start of partition {}, the shrinking strategy '
                    'will not work.'.format(part.path), err)
                raise err

        if part is None:
            # No partitions inside the range, we're good
            return

        # There's a single overlapping partition,
        # and it starts outside the range. Shrink it.

        part_newsize = (start_sector - part.geometry.start) * 512

        block_stack = get_block_stack(BlockDevice(part.path), progress)

        block_stack.read_superblocks()
        block_stack.reserve_end_area_verbose(part_newsize, progress)

    def reserve_space_before(self, part_start, length, progress):
        start_sector, rem = divmod(part_start, 512)
        assert rem == 0

        # Just check part_start is indeed the start of a partition
        part = self.parted_disk.getPartitionBySector(start_sector)
        if part.geometry.start != start_sector:
            raise KeyError(part_start, self)

        return self._reserve_range(part_start - length, part_start, progress)

    def shift_left(self, part_start, part_start1):
        assert part_start1 < part_start
        start_sector = bytes_to_sector(part_start)
        start_sector1 = bytes_to_sector(part_start1)

        import parted.geometry
        import parted.constraint

        left_part = self.parted_disk.getPartitionBySector(start_sector1)
        right_part = self.parted_disk.getPartitionBySector(start_sector)

        geom = parted.geometry.Geometry(
            device=self.device.parted_device,
            start=left_part.geometry.start,
            end=start_sector1 - 1)
        cons = parted.Constraint(exactGeom=geom)
        assert self.parted_disk.setPartitionGeometry(
            left_part, cons, geom.start, geom.end) == True

        geom = parted.geometry.Geometry(
            device=self.device.parted_device,
            start=start_sector1,
            end=right_part.geometry.end)
        cons = parted.Constraint(exactGeom=geom)
        assert self.parted_disk.setPartitionGeometry(
            right_part, cons, geom.start, geom.end) == True

        # commitToDevice (atomic) + commitToOS (not atomic, less important)
        self.parted_disk.commit()


class CantShrink(Exception):
    pass


class Filesystem(BlockData):
    resize_needs_mpoint = False

    def reserve_end_area_nonrec(self, pos):
        return self.reserve_end_area(pos)

    def reserve_end_area(self, pos):
        # XXX Non-reentrant (self.mpoint)

        # align to a block boundary that doesn't encroach
        pos = (pos // self.block_size) * self.block_size

        if self.fssize <= pos:
            return

        if not self.can_shrink:
            raise CantShrink(self)

        with contextlib.ExitStack() as st:
            if self.resize_needs_mpoint:
                self.mpoint = st.enter_context(
                    tempfile.TemporaryDirectory(suffix='.privmnt'))
                # TODO: use unshare() here
                quiet_call(
                    ['mount', '-t', self.vfstype, '-o', 'noatime,noexec,nodev',
                     '-n', '--', self.device.devpath, self.mpoint])
                st.callback(lambda:
                    quiet_call('umount -n -- '.split() + [self.mpoint]))
            self._resize(pos)


        # measure size again
        self.read_superblock()
        assert self.fssize == pos

    @property
    def fssize(self):
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
        subprocess.check_call(
            ['cryptsetup', 'remove', '--', self.cleartext_device.devpath])

    def snoop_activated(self):
        for hld in self.device.iter_holders():
            if not self._superblock_read:
                self.read_superblock()
            match = dm_crypt_re.match(hld.dm_table())
            # Having the correct offset ensures we're not getting
            # the size of a smaller filesystem inside the partition
            if match and int(match.group('offset')) == self.offset:
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
                self.offset = int(line.split(':', 1)[1])
        proc.wait()
        assert proc.returncode == 0
        self._superblock_read = True

    def reserve_end_area_nonrec(self, pos):
        sectors = bytes_to_sector(pos)
        # pycryptsetup is useless, no resize support
        # otoh, size doesn't appear in the superblock,
        # and updating the dm table is only useful if
        # we want to do some fsck before deactivating
        subprocess.check_call(
            ['cryptsetup', 'resize', '--size=%d' % sectors,
             '--', self.cleartext_device.devpath])


class XFS(Filesystem):
    can_shrink = False

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


class NilFS(Filesystem):
    can_shrink = True
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

    @property
    def fssize(self):
        assert self.size_bytes % self.block_size == 0
        return self.size_bytes

    def _resize(self, target_size):
        assert target_size % self.block_size == 0
        quiet_call(
            ['nilfs-resize', '--yes', '--',
             self.device.devpath, '%d' % target_size])


class BtrFS(Filesystem):
    can_shrink = True
    resize_needs_mpoint = True
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

    @property
    def fssize(self):
        assert self.size_bytes % self.block_size == 0
        return self.size_bytes

    def _resize(self, target_size):
        assert target_size % self.block_size == 0
        # XXX The device is unavailable (EBUSY)
        # immediately after unmounting.
        # Bug introduced in Linux 3.0, fixed in 3.9.
        # Tracked down by Eric Sandeen in
        # http://comments.gmane.org/gmane.comp.file-systems.btrfs/23987
        quiet_call(
            'btrfs filesystem resize'.split()
            + ['{}:{}'.format(self.devid, target_size), self.mpoint])


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
        if self.state != 'clean' or self.check_tm < self.mount_tm:
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


def mk_dm(devname, table, readonly, exit_stack):
    cmd = 'dmsetup create --noudevsync --'.split() + [devname]
    if readonly:
        cmd[2:2] = ['--readonly']
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    proc.communicate(table.encode('ascii'))
    assert proc.returncode == 0
    exit_stack.callback(lambda:
        quiet_call(
            'dmsetup remove --noudevsync --'.split() + [devname]))


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


@contextlib.contextmanager
def setenv(var, val):
    old = os.environ.get(var)
    os.environ[var] = val
    yield
    if old is not None:
        os.environ[var] = old
    else:
        del os.environ[var]


class UnsupportedSuperblock(Exception):
    def __init__(self, device):
        self.device = device


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

    def reserve_end_area(self, pos):
        # resizes
        for inner_pos, block_data in reversed(list(self.iter_pos(pos))):
            block_data.reserve_end_area_nonrec(inner_pos)

    def reserve_end_area_verbose(self, pos, progress):
        bs = self.topmost.block_size
        inner_pos = ((pos - self.overhead) // bs) * bs
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
        self.reserve_end_area(pos)

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
            progress.notify_error(
                'Unsupported superblock type: {}'
                .format(err.device.superblock_type), err)
            raise err

        # only reached when we ended on a filesystem
        return BlockStack(stack)


class ConvertStrategy:
    pass


class RotateConvertStrategy(ConvertStrategy):
    pass


class ShiftConvertStrategy(ConvertStrategy):
    pass


class SyntheticDevice(BlockDevice):
    pass


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
def synth_device(writable_size, rozeros_size):
    writable_sectors = bytes_to_sector(writable_size)
    rz_sectors = bytes_to_sector(rozeros_size)

    with contextlib.ExitStack() as st:
        imgf = st.enter_context(tempfile.NamedTemporaryFile(suffix='.img'))
        imgf.truncate(writable_size)

        lo_dev = subprocess.check_output(
            'losetup -f --show --'.split() + [imgf.name]
        ).rstrip().decode('ascii')
        st.callback(lambda:
            quiet_call('losetup -d --'.split() + [lo_dev]))
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
        mk_dm(
            synth_devname,
            '0 {writable_sectors} linear {lo_dev} 0\n'
            '{writable_sectors} {rz_sectors} linear {rozeros_devpath} 0\n'
            .format(
                writable_sectors=writable_sectors, lo_dev=lo_dev,
                rz_sectors=rz_sectors,
                rozeros_devpath='/dev/mapper/' + rozeros_devname),
            readonly=False,
            exit_stack=st)

        synth = SyntheticDevice(synth_devpath)
        yield synth

        data = imgf.read()
        assert len(data) == writable_size

        # Expose the data outside of the with statement
        synth.data = data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    commands = parser.add_subparsers(dest='command', metavar='command')

    sp_to_lvm = commands.add_parser('to-lvm', help='Convert to LVM')
    sp_to_lvm.add_argument('device')
    sp_to_lvm.add_argument('--vg-name', dest='vgname', type=str)
    sp_to_lvm.set_defaults(action=cmd_to_lvm)

    sp_to_bcache = commands.add_parser('to-bcache', help='Convert to LVM')
    sp_to_bcache.add_argument('device')
    sp_to_bcache.set_defaults(action=cmd_to_bcache)

    args = parser.parse_args()
    return args.action(args)


def cmd_to_bcache(args):
    device = BlockDevice(args.device)
    debug = args.debug

    if device.has_bcache_superblock:
        print(
            'Device {} already has a bcache super block.'
            .format(device.devpath), file=sys.stderr)
        return 1

    if not device.is_partition:
        print(
            'Device {} is not a partition'.format(device.devpath),
            file=sys.stderr)
        return 1

    # TODO: use make-bcache with a custom sb_size so that
    # we can keep the partition-start alignment.
    # Alignment inside the bdev doesn't change, but some partitioning
    # tools (like parted) autodetect ptable alignment from start
    # sectors and it would be bad to break that.
    sb_size = 512 * 16

    # So that part_start1 is sector-aligned
    assert sb_size % 512 == 0

    progress = CLIProgressHandler()
    ptable = ptable_from_partition_device(device)
    part_start = start_of_partition(device)
    ptable.reserve_space_before(part_start, sb_size, progress)
    part_start1 = part_start - sb_size

    # Make a synthetic backing device
    with synth_device(sb_size, device.size) as synth_bdev:
        quiet_call(
            ['make-bcache', '--bdev', synth_bdev.devpath])
        bcache_backing = BCacheBacking(synth_bdev)
        bcache_backing.read_superblock()
        assert bcache_backing.offset == sb_size

    import _ped
    write_part = ptable.parted_disk.getPartitionBySector(part_start1 // 512)
    if write_part.type != _ped.PARTITION_NORMAL:
        # Free space, or something else we can't touch
        print('Can\'t write outside of a partition', file=sys.stderr)
        return 1

    sb_write_offset = part_start1 - (512 * write_part.geometry.start)

    dev_fd = os.open(write_part.path, os.O_SYNC|os.O_RDWR|os.O_EXCL)

    print('Copying the bcache superblock... ', end='', flush=True)
    assert len(synth_bdev.data) == sb_size
    wr_len = os.pwrite(dev_fd, synth_bdev.data, sb_write_offset)
    assert wr_len == sb_size
    # read back for the hell of it
    assert os.pread(dev_fd, sb_size, sb_write_offset) == synth_bdev.data
    os.close(dev_fd)
    del dev_fd
    print('ok')

    # Check the partition we're about to convert isn't in use either,
    # otherwise the partition table couldn't be reloaded.
    dev_fd = os.open(device.devpath, os.O_SYNC|os.O_RDWR|os.O_EXCL)
    os.close(dev_fd)
    del dev_fd

    print('Modifying the partition table... ', end='', flush=True)
    ptable.shift_left(part_start, part_start1)
    print('ok')


def cmd_to_lvm(args):
    device = BlockDevice(args.device)
    debug = args.debug

    if args.vgname is not None:
        vgname = args.vgname
    else:
        vgname = os.path.basename(device.devpath)
    assert vgname
    assert all(ch in ASCII_ALNUM_WHITELIST for ch in vgname)
    # TODO: check no VG with that name exists?
    # Anyway, vgrename uuid newname should fix any problems

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
        lvname = vgname
    assert all(ch in ASCII_ALNUM_WHITELIST for ch in lvname)

    pe_size = LVM_PE
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
    block_stack.reserve_end_area_verbose(pe_newpos, progress)

    fsuuid = block_stack.topmost.fsuuid
    block_stack.deactivate()
    del block_stack

    # O_EXCL on a block device takes the device lock,
    # exclusive against mounts and the like.
    # O_SYNC on a block device provides durability, see:
    # http://www.codeproject.com/Articles/460057/HDD-FS-O_SYNC-Throughput-vs-Integrity
    # O_DIRECT would bypass the block cache, which is irrelevant here
    dev_fd = os.open(device.devpath, os.O_SYNC|os.O_RDWR|os.O_EXCL)
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

        lvmcfgdir = st.enter_context(
            tempfile.TemporaryDirectory(suffix='.lvmconf'))

        with open(os.path.join(lvmcfgdir, 'lvm.conf'), 'w') as conffile:
            conffile.write(
               'devices {{ filter=["a/^{synth_re}$/", "r/.*/"] }}'
                .format(synth_re=re.escape(synth_pv.devpath)))

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

        # Prevent the next too commands from scanning every device (slow),
        # we already know lvm should write only to the synthetic pv.
        st.enter_context(setenv('LVM_SYSTEM_DIR', lvmcfgdir))

        quiet_call(
            ['pvcreate', '--restorefile', cfgf.name,
             '--uuid', str(pv_uuid), '--zero', 'y', '--',
             synth_pv.devpath])
        quiet_call(
            ['vgcfgrestore', '--file', cfgf.name, '--', vgname])
    print('ok')  # after 'Preparing LVM metadata'

    # Recovery: copy back the PE we had moved to the end of the device.
    print(
        'If the next stage is interrupted, it can be reverted with:\n'
        '    dd if={devpath} of={devpath} bs={pe_size} count=1 skip={pe_count}'
        .format(
            devpath=device.devpath, pe_size=pe_size, pe_count=pe_count))

    print('Installing LVM metadata... ', end='', flush=True)
    # This had better be atomic
    # Though technically, only physical sector writes are guaranteed atomic
    wr_len = os.pwrite(dev_fd, synth_pv.data, 0)
    assert wr_len == pe_size
    # read back for the hell of it
    assert os.pread(dev_fd, pe_size, 0) == synth_pv.data
    print('ok')
    print('LVM conversion successful!')
    if False:
        print('Enable the volume group with\n'
              '    sudo vgchange -ay -- {}'.format(vgname))
    elif False:
        print('Enable the logical volume with\n'
              '    sudo lvchange -ay -- {}/{}'.format(vgname, lvname))
    else:
        print('Volume group name: {}\n'
              'Logical volume name: {}\n'
              'Filesystem uuid: {}'
              .format(vgname, lvname, fsuuid))


def script_main():
    sys.exit(main())


if __name__ == '__main__':
    script_main()

