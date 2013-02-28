# Python 3.3

import argparse
import contextlib
import os
import string
import subprocess
import sys
import tempfile
import textwrap
import uuid


# 4MiB PE, for vgmerge compatibility
LVM_PE = 4 * 1024**2


ASCII_ALNUM_WHITELIST = string.ascii_letters + string.digits


class Filesystem:
    def __init__(self, device):
        self.device = device


class ExtFS(Filesystem):
    def get_size(self):
        cmd = subprocess.Popen(
            'tune2fs -l --'.split() + [self.device], stdout=subprocess.PIPE)
        self.block_size = None
        self.block_count = None
        for line in cmd.stdout:
            if line.startswith(b'Block size:'):
                line = line.decode('ascii')
                self.block_size = int(line.split(':', 1)[1])
            elif line.startswith(b'Block count:'):
                line = line.decode('ascii')
                self.block_count = int(line.split(':', 1)[1])
        return self.block_size * self.block_count

    def resize(self, target_size):
        # resize2fs will require that the filesystem was checked
        # immediately before.
        block_count, rem = divmod(target_size, self.block_size)
        assert rem == 0
        subprocess.check_call(
            'resize2fs -p --'.split() + [self.device, '%d' % block_count])
        assert self.get_size() == target_size


def mk_dm(devname, table, readonly, exit_stack):
    cmd = 'dmsetup create --'.split() + [devname]
    if readonly:
        cmd[2:2] = ['--readonly']
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    proc.communicate(table.encode('ascii'))
    assert proc.returncode == 0
    exit_stack.callback(lambda:
        subprocess.check_call(
            'dmsetup remove --'.split() + [devname]))


def quiet_call(cmd, *args, **kwargs):
    proc = subprocess.Popen(
        cmd, *args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    odat, edat = proc.communicate()
    if proc.returncode != 0:
        print(
            'Command {!r} has failed with status {}\n'
            'Standard output:\n{}\n'
            'Standard error:\n{}'.format(
                cmd, proc.returncode, odat, edat), file=sys.stderr)
        raise subprocess.CalledProcessError(proc.returncode, cmd, odat)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('device')
    parser.add_argument('volname', nargs='?')
    parser.add_argument('--debug', action='store_true')

    args = parser.parse_args()
    device = args.device
    if args.volname is not None:
        volname = args.volname
    else:
        volname = os.path.basename(device)
    assert volname
    assert all(ch in ASCII_ALNUM_WHITELIST for ch in volname)
    # TODO: check no VG with that name exists?

    fstype = subprocess.check_output(
        'blkid -o value -s TYPE --'.split() + [device]
    ).rstrip().decode('ascii')
    partsize = int(subprocess.check_output(
        'blockdev --getsize64'.split() + [device]))
    assert partsize % 512 == 0
    if fstype in {'ext2', 'ext3', 'ext4'}:
        fs = ExtFS(device)
    else:
        print(
            'Unsupported filesystem type: {}'.format(fstype), file=sys.stderr)
        return 1
    fssize = fs.get_size()
    pe_size = LVM_PE
    assert pe_size % 512 == 0
    pe_sectors = pe_size // 512
    # -1 because we reserve pe_size for the lvm label and one metadata area
    pe_count = partsize // pe_size - 1
    # The position of the moved pe
    pe_newpos = pe_count * pe_size
    fssize_lim = (pe_newpos // fs.block_size) * fs.block_size

    if args.debug:
        print(
            'pe {} bs {} fssize {} fssize_lim {} pe_newpos {} partsize {}'
            .format(
                pe_size, fs.block_size, fssize,
                fssize_lim, pe_newpos, partsize))

    if fssize > fssize_lim:
        print(
            'Will shrink the filesystem by {} bytes'.format(
                fssize - fssize_lim))
        fs.resize(fssize_lim)
    # O_EXCL on a block device takes the device lock,
    # exclusive against mounts and the like.
    # I'm not sure which of O_SYNC and O_DIRECT will ensure durability.
    # O_DIRECT has inconvenient alignment constraints.
    dev_fd = os.open(device, os.O_SYNC|os.O_RDWR|os.O_EXCL)
    print('Copying {} bytes from pos 0 to pos {}'.format(pe_size, pe_newpos))
    pe_data = os.pread(dev_fd, pe_size, 0)
    assert len(pe_data) == pe_size
    wr_len = os.pwrite(dev_fd, pe_data, pe_newpos)
    assert wr_len == pe_size

    # The changes so far (fs resize, possibly an fsck, and the copy)
    # should have no user-visible effects.

    # Create a virtual device to do the lvm setup
    with contextlib.ExitStack() as st:
        imgf = st.enter_context(tempfile.NamedTemporaryFile(suffix='.pvimg'))
        imgf.truncate(pe_size)

        cfgf = st.enter_context(
            tempfile.NamedTemporaryFile(
                suffix='.vgcfg', mode='w', encoding='ascii',
                delete=not args.debug))

        lo_dev = subprocess.check_output(
            'losetup -f --show --'.split() + [imgf.name]
        ).rstrip().decode('ascii')
        st.callback(lambda:
            subprocess.check_call('losetup -d --'.split() + [lo_dev]))
        pv_uuid = uuid.uuid1()
        vg_uuid = uuid.uuid1()
        lv_uuid = uuid.uuid1()
        rozeros_devname = 'rozeros-{}'.format(uuid.uuid1())
        synth_devname = 'synthetic-{}'.format(uuid.uuid1())

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
                vgname=volname,
                lvname=volname,
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

        quiet_call(
            ['pvcreate', '--restorefile', cfgf.name,
             '--uuid', str(pv_uuid), '--zero', 'y', '--',
             '/dev/mapper/' + synth_devname])
        quiet_call(
            ['vgcfgrestore', '--file', cfgf.name, '--', volname])
        lvm_data = imgf.read()
        assert len(lvm_data) == pe_size

    # Recovery: copy back the PE we had moved to the end of the device.
    print(
        'If the next stage is interrupted, it can be reverted with:\n'
        '    dd if={device} of={device} bs={pe_size} count=1 skip={pe_count}'
        .format(
            device=device, pe_size=pe_size, pe_count=pe_count))

    # This had better be atomic
    # Though technically, only sector writes are guaranteed atomic
    wr_len = os.pwrite(dev_fd, lvm_data, 0)
    assert wr_len == pe_size
    print('LVM conversion successful!')


if __name__ == '__main__':
    sys.exit(main())

