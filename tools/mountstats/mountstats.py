#!/usr/bin/env python
# -*- python-mode -*-
"""Parse /proc/self/mountstats and display it in human readable form
"""

from __future__ import print_function

__copyright__ = """
Copyright (C) 2005, Chuck Lever <cel@netapp.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301 USA
"""

import sys, os, time
from operator import itemgetter

Mountstats_version = '0.2'

def difference(x, y):
    """Used for a map() function
    """
    return x - y

NfsEventCounters = [
    'inoderevalidates',
    'dentryrevalidates',
    'datainvalidates',
    'attrinvalidates',
    'vfsopen',
    'vfslookup',
    'vfspermission',
    'vfsupdatepage',
    'vfsreadpage',
    'vfsreadpages',
    'vfswritepage',
    'vfswritepages',
    'vfsreaddir',
    'vfssetattr',
    'vfsflush',
    'vfsfsync',
    'vfslock',
    'vfsrelease',
    'congestionwait',
    'setattrtrunc',
    'extendwrite',
    'sillyrenames',
    'shortreads',
    'shortwrites',
    'delay',
    'pnfsreads',
    'pnfswrites'
]

NfsByteCounters = [
    'normalreadbytes',
    'normalwritebytes',
    'directreadbytes',
    'directwritebytes',
    'serverreadbytes',
    'serverwritebytes',
    'readpages',
    'writepages'
]

XprtUdpCounters = [
    'port',
    'bind_count',
    'rpcsends',
    'rpcreceives',
    'badxids',
    'inflightsends',
    'backlogutil'
]

XprtTcpCounters = [
    'port',
    'bind_count',
    'connect_count',
    'connect_time',
    'idle_time',
    'rpcsends',
    'rpcreceives',
    'badxids',
    'inflightsends',
    'backlogutil'
]

XprtRdmaCounters = [
    'port',
    'bind_count',
    'connect_count',
    'connect_time',
    'idle_time',
    'rpcsends',
    'rpcreceives',
    'badxids',
    'backlogutil',
    'read_chunks',
    'write_chunks',
    'reply_chunks',
    'total_rdma_req',
    'total_rdma_rep',
    'pullup',
    'fixup',
    'hardway',
    'failed_marshal',
    'bad_reply'
]

Nfsv3ops = [
    'NULL',
    'GETATTR',
    'SETATTR',
    'LOOKUP',
    'ACCESS',
    'READLINK',
    'READ',
    'WRITE',
    'CREATE',
    'MKDIR',
    'SYMLINK',
    'MKNOD',
    'REMOVE',
    'RMDIR',
    'RENAME',
    'LINK',
    'READDIR',
    'READDIRPLUS',
    'FSSTAT',
    'FSINFO',
    'PATHCONF',
    'COMMIT'
]

Nfsv4ops = [
    'NULL',
    'READ',
    'WRITE',
    'COMMIT',
    'OPEN',
    'OPEN_CONFIRM',
    'OPEN_NOATTR',
    'OPEN_DOWNGRADE',
    'CLOSE',
    'SETATTR',
    'FSINFO',
    'RENEW',
    'SETCLIENTID',
    'SETCLIENTID_CONFIRM',
    'LOCK',
    'LOCKT',
    'LOCKU',
    'ACCESS',
    'GETATTR',
    'LOOKUP',
    'LOOKUP_ROOT',
    'REMOVE',
    'RENAME',
    'LINK',
    'SYMLINK',
    'CREATE',
    'PATHCONF',
    'STATFS',
    'READLINK',
    'READDIR',
    'SERVER_CAPS',
    'DELEGRETURN',
    'GETACL',
    'SETACL',
    'FS_LOCATIONS',
    'RELEASE_LOCKOWNER',
    'SECINFO',
    'FSID_PRESENT',
    'EXCHANGE_ID',
    'CREATE_SESSION',
    'DESTROY_SESSION',
    'SEQUENCE',
    'GET_LEASE_TIME',
    'RECLAIM_COMPLETE',
    'LAYOUTGET',
    'GETDEVICEINFO',
    'LAYOUTCOMMIT',
    'LAYOUTRETURN',
    'SECINFO_NO_NAME',
    'TEST_STATEID',
    'FREE_STATEID',
    'GETDEVICELIST',
    'BIND_CONN_TO_SESSION',
    'DESTROY_CLIENTID'
]

class DeviceData:
    """DeviceData objects provide methods for parsing and displaying
    data for a single mount grabbed from /proc/self/mountstats
    """
    def __init__(self):
        self.__nfs_data = dict()
        self.__rpc_data = dict()
        self.__rpc_data['ops'] = []

    def __parse_nfs_line(self, words):
        if words[0] == 'device':
            self.__nfs_data['export'] = words[1]
            self.__nfs_data['mountpoint'] = words[4]
            self.__nfs_data['fstype'] = words[7]
            if words[7].find('nfs') != -1:
                self.__nfs_data['statvers'] = words[8]
        elif 'nfs' in words or 'nfs4' in words:
            self.__nfs_data['export'] = words[0]
            self.__nfs_data['mountpoint'] = words[3]
            self.__nfs_data['fstype'] = words[6]
            if words[6].find('nfs') != -1:
                self.__nfs_data['statvers'] = words[7]
        elif words[0] == 'age:':
            self.__nfs_data['age'] = int(words[1])
        elif words[0] == 'opts:':
            self.__nfs_data['mountoptions'] = ''.join(words[1:]).split(',')
        elif words[0] == 'caps:':
            self.__nfs_data['servercapabilities'] = ''.join(words[1:]).split(',')
        elif words[0] == 'nfsv4:':
            self.__nfs_data['nfsv4flags'] = ''.join(words[1:]).split(',')
        elif words[0] == 'sec:':
            keys = ''.join(words[1:]).split(',')
            self.__nfs_data['flavor'] = int(keys[0].split('=')[1])
            self.__nfs_data['pseudoflavor'] = 0
            if self.__nfs_data['flavor'] == 6:
                self.__nfs_data['pseudoflavor'] = int(keys[1].split('=')[1])
        elif words[0] == 'events:':
            i = 1
            for key in NfsEventCounters:
                try:
                    self.__nfs_data[key] = int(words[i])
                except IndexError as err:
                    self.__nfs_data[key] = 0
                i += 1
        elif words[0] == 'bytes:':
            i = 1
            for key in NfsByteCounters:
                self.__nfs_data[key] = int(words[i])
                i += 1

    def __parse_rpc_line(self, words):
        if words[0] == 'RPC':
            self.__rpc_data['statsvers'] = float(words[3])
            self.__rpc_data['programversion'] = words[5]
        elif words[0] == 'xprt:':
            self.__rpc_data['protocol'] = words[1]
            if words[1] == 'udp':
                i = 2
                for key in XprtUdpCounters:
                    self.__rpc_data[key] = int(words[i])
                    i += 1
            elif words[1] == 'tcp':
                i = 2
                for key in XprtTcpCounters:
                    self.__rpc_data[key] = int(words[i])
                    i += 1
            elif words[1] == 'rdma':
                i = 2
                for key in XprtRdmaCounters:
                    self.__rpc_data[key] = int(words[i])
                    i += 1
        elif words[0] == 'per-op':
            self.__rpc_data['per-op'] = words
        else:
            op = words[0][:-1]
            self.__rpc_data['ops'] += [op]
            self.__rpc_data[op] = [int(word) for word in words[1:]]

    def parse_stats(self, lines):
        """Turn a list of lines from a mount stat file into a 
        dictionary full of stats, keyed by name
        """
        found = False
        for line in lines:
            words = line.split()
            if len(words) == 0:
                continue
            if (not found and words[0] != 'RPC'):
                self.__parse_nfs_line(words)
                continue

            found = True
            self.__parse_rpc_line(words)

    def is_nfs_mountpoint(self):
        """Return True if this is an NFS or NFSv4 mountpoint,
        otherwise return False
        """
        if self.__nfs_data['fstype'] == 'nfs':
            return True
        elif self.__nfs_data['fstype'] == 'nfs4':
            return True
        return False

    def display_nfs_options(self):
        """Pretty-print the NFS options
        """
        print('Stats for %s mounted on %s:' % \
            (self.__nfs_data['export'], self.__nfs_data['mountpoint']))

        print('  NFS mount options: %s' % ','.join(self.__nfs_data['mountoptions']))
        print('  NFS server capabilities: %s' % ','.join(self.__nfs_data['servercapabilities']))
        if 'nfsv4flags' in self.__nfs_data:
            print('  NFSv4 capability flags: %s' % ','.join(self.__nfs_data['nfsv4flags']))
        if 'pseudoflavor' in self.__nfs_data:
            print('  NFS security flavor: %d  pseudoflavor: %d' % \
                (self.__nfs_data['flavor'], self.__nfs_data['pseudoflavor']))
        else:
            print('  NFS security flavor: %d' % self.__nfs_data['flavor'])

    def display_nfs_events(self):
        """Pretty-print the NFS event counters
        """
        print()
        print('Cache events:')
        print('  data cache invalidated %d times' % self.__nfs_data['datainvalidates'])
        print('  attribute cache invalidated %d times' % self.__nfs_data['attrinvalidates'])
        print()
        print('VFS calls:')
        print('  VFS requested %d inode revalidations' % self.__nfs_data['inoderevalidates'])
        print('  VFS requested %d dentry revalidations' % self.__nfs_data['dentryrevalidates'])
        print()
        print('  VFS called nfs_readdir() %d times' % self.__nfs_data['vfsreaddir'])
        print('  VFS called nfs_lookup() %d times' % self.__nfs_data['vfslookup'])
        print('  VFS called nfs_permission() %d times' % self.__nfs_data['vfspermission'])
        print('  VFS called nfs_file_open() %d times' % self.__nfs_data['vfsopen'])
        print('  VFS called nfs_file_flush() %d times' % self.__nfs_data['vfsflush'])
        print('  VFS called nfs_lock() %d times' % self.__nfs_data['vfslock'])
        print('  VFS called nfs_fsync() %d times' % self.__nfs_data['vfsfsync'])
        print('  VFS called nfs_file_release() %d times' % self.__nfs_data['vfsrelease'])
        print()
        print('VM calls:')
        print('  VFS called nfs_readpage() %d times' % self.__nfs_data['vfsreadpage'])
        print('  VFS called nfs_readpages() %d times' % self.__nfs_data['vfsreadpages'])
        print('  VFS called nfs_writepage() %d times' % self.__nfs_data['vfswritepage'])
        print('  VFS called nfs_writepages() %d times' % self.__nfs_data['vfswritepages'])
        print()
        print('Generic NFS counters:')
        print('  File size changing operations:')
        print('    truncating SETATTRs: %d  extending WRITEs: %d' % \
            (self.__nfs_data['setattrtrunc'], self.__nfs_data['extendwrite']))
        print('  %d silly renames' % self.__nfs_data['sillyrenames'])
        print('  short reads: %d  short writes: %d' % \
            (self.__nfs_data['shortreads'], self.__nfs_data['shortwrites']))
        print('  NFSERR_DELAYs from server: %d' % self.__nfs_data['delay'])

    def display_nfs_bytes(self):
        """Pretty-print the NFS event counters
        """
        print()
        print('NFS byte counts:')
        print('  applications read %d bytes via read(2)' % self.__nfs_data['normalreadbytes'])
        print('  applications wrote %d bytes via write(2)' % self.__nfs_data['normalwritebytes'])
        print('  applications read %d bytes via O_DIRECT read(2)' % self.__nfs_data['directreadbytes'])
        print('  applications wrote %d bytes via O_DIRECT write(2)' % self.__nfs_data['directwritebytes'])
        print('  client read %d bytes via NFS READ' % self.__nfs_data['serverreadbytes'])
        print('  client wrote %d bytes via NFS WRITE' % self.__nfs_data['serverwritebytes'])

    def display_rpc_generic_stats(self):
        """Pretty-print the generic RPC stats
        """
        sends = self.__rpc_data['rpcsends']

        print()
        print('RPC statistics:')

        print('  %d RPC requests sent, %d RPC replies received (%d XIDs not found)' % \
            (sends, self.__rpc_data['rpcreceives'], self.__rpc_data['badxids']))
        if sends != 0:
            print('  average backlog queue length: %d' % \
                (float(self.__rpc_data['backlogutil']) / sends))

    def display_rpc_op_stats(self):
        """Pretty-print the per-op stats
        """
        sends = self.__rpc_data['rpcsends']

        allstats = []
        for op in self.__rpc_data['ops']:
            allstats.append([op] + self.__rpc_data[op])

        print()
        for stats in sorted(allstats, key=itemgetter(1), reverse=True):
            count = stats[1]
            if count != 0:
                print('%s:' % stats[0])
                print('\t%d ops (%d%%)' % \
                    (count, ((count * 100) / sends)), end=' ')
                retrans = stats[2] - count
                if retrans != 0:
                    print('\t%d retrans (%d%%)' % (retrans, ((retrans * 100) / count)), end=' ')
                    print('\t%d major timeouts' % stats[3])
                else:
                    print('')
                print('\tavg bytes sent per op: %d\tavg bytes received per op: %d' % \
                    (stats[4] / count, stats[5] / count))
                print('\tbacklog wait: %f' % (float(stats[6]) / count), end=' ')
                print('\tRTT: %f' % (float(stats[7]) / count), end=' ')
                print('\ttotal execute time: %f (milliseconds)' % \
                    (float(stats[8]) / count))

    def compare_iostats(self, old_stats):
        """Return the difference between two sets of stats
        """
        result = DeviceData()

        # copy self into result
        for key, value in self.__nfs_data.items():
            result.__nfs_data[key] = value
        for key, value in self.__rpc_data.items():
            result.__rpc_data[key] = value

        # compute the difference of each item in the list
        # note the copy loop above does not copy the lists, just
        # the reference to them.  so we build new lists here
        # for the result object.
        for op in result.__rpc_data['ops']:
            result.__rpc_data[op] = list(map(difference, self.__rpc_data[op], old_stats.__rpc_data[op]))

        # update the remaining keys we care about
        result.__rpc_data['rpcsends'] -= old_stats.__rpc_data['rpcsends']
        result.__rpc_data['backlogutil'] -= old_stats.__rpc_data['backlogutil']
        result.__nfs_data['serverreadbytes'] -= old_stats.__nfs_data['serverreadbytes']
        result.__nfs_data['serverwritebytes'] -= old_stats.__nfs_data['serverwritebytes']

        return result

    def display_iostats(self, sample_time):
        """Display NFS and RPC stats in an iostat-like way
        """
        sends = float(self.__rpc_data['rpcsends'])
        if sample_time == 0:
            sample_time = float(self.__nfs_data['age'])

        print()
        print('%s mounted on %s:' % \
            (self.__nfs_data['export'], self.__nfs_data['mountpoint']))

        print('\top/s\trpc bklog')
        print('\t%.2f' % (sends / sample_time), end=' ')
        if sends != 0:
            print('\t%.2f' % \
                ((float(self.__rpc_data['backlogutil']) / sends) / sample_time))
        else:
            print('\t0.00')

        # reads:  ops/s, kB/s, avg rtt, and avg exe
        # XXX: include avg xfer size and retransmits?
        read_rpc_stats = self.__rpc_data['READ']
        ops = float(read_rpc_stats[0])
        kilobytes = float(self.__nfs_data['serverreadbytes']) / 1024
        rtt = float(read_rpc_stats[6])
        exe = float(read_rpc_stats[7])

        print('\treads:\tops/s\t\tkB/s\t\tavg RTT (ms)\tavg exe (ms)')
        print('\t\t%.2f' % (ops / sample_time), end=' ')
        print('\t\t%.2f' % (kilobytes / sample_time), end=' ')
        if ops != 0:
            print('\t\t%.2f' % (rtt / ops), end=' ')
            print('\t\t%.2f' % (exe / ops))
        else:
            print('\t\t0.00', end=' ')
            print('\t\t0.00')

        # writes:  ops/s, kB/s, avg rtt, and avg exe
        # XXX: include avg xfer size and retransmits?
        write_rpc_stats = self.__rpc_data['WRITE']
        ops = float(write_rpc_stats[0])
        kilobytes = float(self.__nfs_data['serverwritebytes']) / 1024
        rtt = float(write_rpc_stats[6])
        exe = float(write_rpc_stats[7])

        print('\twrites:\tops/s\t\tkB/s\t\tavg RTT (ms)\tavg exe (ms)')
        print('\t\t%.2f' % (ops / sample_time), end=' ')
        print('\t\t%.2f' % (kilobytes / sample_time), end=' ')
        if ops != 0:
            print('\t\t%.2f' % (rtt / ops), end=' ')
            print('\t\t%.2f' % (exe / ops))
        else:
            print('\t\t0.00', end=' ')
            print('\t\t0.00')

def parse_stats_file(filename):
    """pop the contents of a mountstats file into a dictionary,
    keyed by mount point.  each value object is a list of the
    lines in the mountstats file corresponding to the mount
    point named in the key.
    """
    ms_dict = dict()
    key = ''

    f = open(filename)
    for line in f.readlines():
        words = line.split()
        if len(words) == 0:
            continue
        if words[0] == 'device':
            key = words[4]
            new = [ line.strip() ]
        elif 'nfs' in words or 'nfs4' in words:
            key = words[3]
            new = [ line.strip() ]
        else:
            new += [ line.strip() ]
        ms_dict[key] = new
    f.close

    return ms_dict

def print_mountstats_help(name):
    print('usage: %s [ options ] <mount point>' % name)
    print()
    print(' Version %s' % Mountstats_version)
    print()
    print(' Display NFS client per-mount statistics.')
    print()
    print('  --version    display the version of this command')
    print('  --nfs        display only the NFS statistics')
    print('  --rpc        display only the RPC statistics')
    print('  --start      sample and save statistics')
    print('  --end        resample statistics and compare them with saved')
    print()

def mountstats_command():
    """Mountstats command
    """
    mountpoints = []
    nfs_only = False
    rpc_only = False

    for arg in sys.argv:
        if arg in ['-h', '--help', 'help', 'usage']:
            print_mountstats_help(prog)
            return

        if arg in ['-v', '--version', 'version']:
            print('%s version %s' % (sys.argv[0], Mountstats_version))
            sys.exit(0)

        if arg in ['-n', '--nfs']:
            nfs_only = True
            continue

        if arg in ['-r', '--rpc']:
            rpc_only = True
            continue

        if arg in ['-s', '--start']:
            raise Exception('Sampling is not yet implemented')

        if arg in ['-e', '--end']:
            raise Exception('Sampling is not yet implemented')

        if arg == sys.argv[0]:
            continue

        mountpoints += [arg]

    if mountpoints == []:
        print_mountstats_help(prog)
        return

    if rpc_only == True and nfs_only == True:
        print_mountstats_help(prog)
        return

    mountstats = parse_stats_file('/proc/self/mountstats')

    for mp in mountpoints:
        if mp not in mountstats:
            print('Statistics for mount point %s not found' % mp)
            continue

        stats = DeviceData()
        stats.parse_stats(mountstats[mp])

        if not stats.is_nfs_mountpoint():
            print('Mount point %s exists but is not an NFS mount' % mp)
            continue

        if nfs_only:
           stats.display_nfs_options()
           stats.display_nfs_events()
           stats.display_nfs_bytes()
        elif rpc_only:
           stats.display_rpc_generic_stats()
           stats.display_rpc_op_stats()
        else:
           stats.display_nfs_options()
           stats.display_nfs_bytes()
           stats.display_rpc_generic_stats()
           stats.display_rpc_op_stats()

def print_nfsstat_help(name):
    print('usage: %s [ options ]' % name)
    print()
    print(' Version %s' % Mountstats_version)
    print()
    print(' nfsstat-like program that uses NFS client per-mount statistics.')
    print()

def nfsstat_command():
    print_nfsstat_help(prog)

def print_iostat_help(name):
    print('usage: %s [ <interval> [ <count> ] ] [ <mount point> ] ' % name)
    print()
    print(' Version %s' % Mountstats_version)
    print()
    print(' iostat-like program to display NFS client per-mount statistics.')
    print()
    print(' The <interval> parameter specifies the amount of time in seconds between')
    print(' each report.  The first report contains statistics for the time since each')
    print(' file system was mounted.  Each subsequent report contains statistics')
    print(' collected during the interval since the previous report.')
    print()
    print(' If the <count> parameter is specified, the value of <count> determines the')
    print(' number of reports generated at <interval> seconds apart.  If the interval')
    print(' parameter is specified without the <count> parameter, the command generates')
    print(' reports continuously.')
    print()
    print(' If one or more <mount point> names are specified, statistics for only these')
    print(' mount points will be displayed.  Otherwise, all NFS mount points on the')
    print(' client are listed.')
    print()

def print_iostat_summary(old, new, devices, time):
    for device in devices:
        stats = DeviceData()
        stats.parse_stats(new[device])
        if not old:
            stats.display_iostats(time)
        else:
            old_stats = DeviceData()
            old_stats.parse_stats(old[device])
            diff_stats = stats.compare_iostats(old_stats)
            diff_stats.display_iostats(time)

def iostat_command():
    """iostat-like command for NFS mount points
    """
    mountstats = parse_stats_file('/proc/self/mountstats')
    devices = []
    interval_seen = False
    count_seen = False

    for arg in sys.argv:
        if arg in ['-h', '--help', 'help', 'usage']:
            print_iostat_help(prog)
            return

        if arg in ['-v', '--version', 'version']:
            print('%s version %s' % (sys.argv[0], Mountstats_version))
            return

        if arg == sys.argv[0]:
            continue

        if arg in mountstats:
            devices += [arg]
        elif not interval_seen:
            interval = int(arg)
            if interval > 0:
                interval_seen = True
            else:
                print('Illegal <interval> value')
                return
        elif not count_seen:
            count = int(arg)
            if count > 0:
                count_seen = True
            else:
                print('Illegal <count> value')
                return

    # make certain devices contains only NFS mount points
    if len(devices) > 0:
        check = []
        for device in devices:
            stats = DeviceData()
            stats.parse_stats(mountstats[device])
            if stats.is_nfs_mountpoint():
                check += [device]
        devices = check
    else:
        for device, descr in mountstats.items():
            stats = DeviceData()
            stats.parse_stats(descr)
            if stats.is_nfs_mountpoint():
                devices += [device]
    if len(devices) == 0:
        print('No NFS mount points were found')
        return

    old_mountstats = None
    sample_time = 0

    if not interval_seen:
        print_iostat_summary(old_mountstats, mountstats, devices, sample_time)
        return

    if count_seen:
        while count != 0:
            print_iostat_summary(old_mountstats, mountstats, devices, sample_time)
            old_mountstats = mountstats
            time.sleep(interval)
            sample_time = interval
            mountstats = parse_stats_file('/proc/self/mountstats')
            count -= 1
    else: 
        while True:
            print_iostat_summary(old_mountstats, mountstats, devices, sample_time)
            old_mountstats = mountstats
            time.sleep(interval)
            sample_time = interval
            mountstats = parse_stats_file('/proc/self/mountstats')

#
# Main
#
prog = os.path.basename(sys.argv[0])

try:
    if prog == 'mountstats':
        mountstats_command()
    elif prog == 'ms-nfsstat':
        nfsstat_command()
    elif prog == 'ms-iostat':
        iostat_command()
    sys.stdout.close()
    sys.stderr.close()
except KeyboardInterrupt:
    print('Caught ^C... exiting')
    sys.exit(1)
except IOError:
    pass

sys.exit(0)
