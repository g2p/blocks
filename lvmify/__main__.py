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


class Filesystem:
    def __init__(self, device):
        self.device = device

    @property
    def fssize(self):
        return self.block_size * self.block_count


class XFS(Filesystem):
    can_shrink = False

    def read_superblock(self):
        self.block_size = None
        self.block_count = None

        proc = subprocess.Popen(
            ['xfs_db', '-c', 'sb 0', '-c', 'p dblocks blocksize',
             '--', self.device], stdout=subprocess.PIPE)
        for line in proc.stdout:
            if line.startswith(b'dblocks ='):
                line = line.decode('ascii')
                self.block_count = int(line.split('=', 1)[1])
            elif line.startswith(b'blocksize ='):
                line = line.decode('ascii')
                self.block_size = int(line.split('=', 1)[1])
        proc.wait()
        assert proc.returncode == 0


class BtrFS(Filesystem):
    can_shrink = True

    def read_superblock(self):
        self.block_size = None
        self.size_bytes = None
        self.devid = None

        proc = subprocess.Popen(
            'btrfs-show-super --'.split() + [self.device],
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
        return self.size_bytes

    def resize(self, target_size):
        assert target_size % self.block_size == 0
        with contextlib.ExitStack() as st:
            mpoint = st.enter_context(
                tempfile.TemporaryDirectory(suffix='.privmnt'))
            # TODO: use unshare() here
            quiet_call(
                'mount -t btrfs -o noatime,noexec,nodev -n --'.split()
                + [self.device, mpoint])
            # XXX It seems the device is still unavailable
            # immediately after unmounting.
            st.callback(lambda:
                quiet_call('umount -n -- '.split() + [mpoint]))
            quiet_call(
                'btrfs filesystem resize'.split()
                + ['{}:{}'.format(self.devid, target_size), mpoint])
        # Update self.size_bytes, used by self.fssize
        self.read_superblock()
        assert self.fssize == target_size


class ReiserFS(Filesystem):
    can_shrink = True

    def read_superblock(self):
        self.block_size = None
        self.block_count = None

        proc = subprocess.Popen(
            'reiserfstune --'.split() + [self.device], stdout=subprocess.PIPE)

        for line in proc.stdout:
            if line.startswith(b'Blocksize:'):
                line = line.decode('ascii')
                self.block_size = int(line.split(':', 1)[1])
            elif line.startswith(b'Count of blocks on the device:'):
                line = line.decode('ascii')
                self.block_count = int(line.split(':', 1)[1])
        proc.wait()
        assert proc.returncode == 0

    def resize(self, target_size):
        assert target_size % self.block_size == 0
        subprocess.check_call(
            ['resize_reiserfs', '-q', '-s', '%d' % target_size,
             '--', self.device])
        # Update self.block_count, used by self.fssize
        self.read_superblock()
        assert self.fssize == target_size


class ExtFS(Filesystem):
    can_shrink = True

    def read_superblock(self):
        self.block_size = None
        self.block_count = None
        self.state = None
        self.mount_tm = None
        self.check_tm = None

        proc = subprocess.Popen(
            'tune2fs -l --'.split() + [self.device], stdout=subprocess.PIPE)

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
                self.mount_tm = time.strptime(line.split(':', 1)[1].strip())
            elif line.startswith(b'Last checked:'):
                line = line.decode('ascii')
                self.check_tm = time.strptime(line.split(':', 1)[1].strip())
        proc.wait()
        assert proc.returncode == 0

    def resize(self, target_size):
        block_count, rem = divmod(target_size, self.block_size)
        assert rem == 0

        # resize2fs requires that the filesystem was checked
        if self.state != 'clean' or self.check_tm < self.mount_tm:
            print('Checking the filesystem before resizing it')
            # Can't use the -n flag, it is strictly read-only and won't
            # update check_tm in the superblock
            # XXX Without either of -n -p -y, e2fsck will require a
            # terminal on stdin
            subprocess.check_call('e2fsck -f --'.split() + [self.device])
            # Another option:
            #quiet_call('e2fsck -fp --'.split() + [self.device])
            self.check_tm = self.mount_tm
        quiet_call(
            'resize2fs --'.split() + [self.device, '%d' % block_count])

        # Update self.block_count, used by self.fssize
        self.read_superblock()
        assert self.fssize == target_size


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('device')
    parser.add_argument('--vg-name', dest='vgname', type=str)
    parser.add_argument('--debug', action='store_true')

    args = parser.parse_args()
    device = args.device
    debug = args.debug
    if args.vgname is not None:
        vgname = args.vgname
    else:
        vgname = os.path.basename(device)
    assert vgname
    assert all(ch in ASCII_ALNUM_WHITELIST for ch in vgname)
    # TODO: check no VG with that name exists?
    # Anyway, vgrename uuid newname should fix any problems

    fstype = subprocess.check_output(
        'blkid -o value -s TYPE --'.split() + [device]
    ).rstrip().decode('ascii')
    fslabel = subprocess.check_output(
        'blkid -o value -s LABEL --'.split() + [device]
    ).rstrip().decode('ascii')
    fsuuid = subprocess.check_output(
        'blkid -o value -s UUID --'.split() + [device]
    ).rstrip().decode('ascii')
    if fslabel:
        lvname = fslabel
    else:
        lvname = vgname
    assert all(ch in ASCII_ALNUM_WHITELIST for ch in lvname)
    partsize = int(subprocess.check_output(
        'blockdev --getsize64'.split() + [device]))
    assert partsize % 512 == 0

    if fstype in {'ext2', 'ext3', 'ext4'}:
        fs = ExtFS(device)
    elif fstype == 'reiserfs':
        fs = ReiserFS(device)
    elif fstype == 'btrfs':
        fs = BtrFS(device)
    elif fstype == 'xfs':
        fs = XFS(device)
    elif fstype == 'LVM2_member':
        print(
            'Already an LVM partition', file=sys.stderr)
        return 1
    else:
        print(
            'Unsupported filesystem type: {}'.format(fstype), file=sys.stderr)
        return 1

    fs.read_superblock()
    pe_size = LVM_PE
    assert pe_size % 512 == 0
    pe_sectors = pe_size // 512
    # -1 because we reserve pe_size for the lvm label and one metadata area
    pe_count = partsize // pe_size - 1
    # The position of the moved pe
    pe_newpos = pe_count * pe_size
    fssize_lim = (pe_newpos // fs.block_size) * fs.block_size

    if debug:
        print(
            'pe {} bs {} fssize {} fssize_lim {} pe_newpos {} partsize {}'
            .format(
                pe_size, fs.block_size, fs.fssize,
                fssize_lim, pe_newpos, partsize))

    if fs.fssize > fssize_lim:
        if fs.can_shrink:
            print(
                'Will shrink the filesystem ({}) by {} bytes'.format(
                    fstype, fs.fssize - fssize_lim))
            fs.resize(fssize_lim)
        else:
            print(
                'Can\'t shrink filesystem ({}), but need another {} bytes '
                'at the end'.format(fstype, fs.fssize - fssize_lim))
            return 1
    else:
        print(
            'The filesystem ({}) leaves enough room, '
            'no need to shrink it'.format(fstype))
    # O_EXCL on a block device takes the device lock,
    # exclusive against mounts and the like.
    # O_SYNC on a block device provides durability, see:
    # http://www.codeproject.com/Articles/460057/HDD-FS-O_SYNC-Throughput-vs-Integrity
    # O_DIRECT would bypass the block cache, which is irrelevant here
    dev_fd = os.open(device, os.O_SYNC|os.O_RDWR|os.O_EXCL)
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
        imgf = st.enter_context(tempfile.NamedTemporaryFile(suffix='.pvimg'))
        imgf.truncate(pe_size)

        cfgf = st.enter_context(
            tempfile.NamedTemporaryFile(
                suffix='.vgcfg', mode='w', encoding='ascii',
                delete=not debug))

        lo_dev = subprocess.check_output(
            'losetup -f --show --'.split() + [imgf.name]
        ).rstrip().decode('ascii')
        st.callback(lambda:
            quiet_call('losetup -d --'.split() + [lo_dev]))
        pv_uuid = uuid.uuid1()
        vg_uuid = uuid.uuid1()
        lv_uuid = uuid.uuid1()
        rozeros_devname = 'rozeros-{}'.format(uuid.uuid1())
        synth_devname = 'synthetic-{}'.format(uuid.uuid1())
        synth_devpath = '/dev/mapper/' + synth_devname

        lvmcfgdir = st.enter_context(
            tempfile.TemporaryDirectory(suffix='.lvmconf'))

        with open(os.path.join(lvmcfgdir + 'lvm.conf'), 'w') as conffile:
            conffile.write(
               'devices {{ filter=["a/{synth_re}/", "r/.*/"] }}'
                .format(synth_re=re.escape(synth_devpath)))

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

        mk_dm(
            rozeros_devname,
            '0 {extra_sectors} zero\n'
            .format(
                extra_sectors=(partsize - pe_size) // 512),
            readonly=True,
            exit_stack=st)
        mk_dm(
            synth_devname,
            '0 {pe_sectors} linear {lo_dev} 0\n'
            '{pe_sectors} {extra_sectors} linear {rozeros_devpath} 0\n'
            .format(
                pe_sectors=pe_sectors, lo_dev=lo_dev,
                extra_sectors=(partsize - pe_size) // 512,
                rozeros_devpath='/dev/mapper/' + rozeros_devname),
            readonly=False,
            exit_stack=st)

        # Prevent the next too commands from scanning every device (slow),
        # we already know lvm should write only to the synthetic pv.
        st.enter_context(setenv('LVM_SYSTEM_DIR', lvmcfgdir))

        quiet_call(
            ['pvcreate', '--restorefile', cfgf.name,
             '--uuid', str(pv_uuid), '--zero', 'y', '--',
             synth_devpath])
        quiet_call(
            ['vgcfgrestore', '--file', cfgf.name, '--', vgname])

        lvm_data = imgf.read()
        assert len(lvm_data) == pe_size
    print('ok')  # after 'Preparing LVM metadata'

    # Recovery: copy back the PE we had moved to the end of the device.
    print(
        'If the next stage is interrupted, it can be reverted with:\n'
        '    dd if={device} of={device} bs={pe_size} count=1 skip={pe_count}'
        .format(
            device=device, pe_size=pe_size, pe_count=pe_count))

    print('Installing LVM metadata... ', end='', flush=True)
    # This had better be atomic
    # Though technically, only sector writes are guaranteed atomic
    wr_len = os.pwrite(dev_fd, lvm_data, 0)
    assert wr_len == pe_size
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

