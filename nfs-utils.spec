Summary: The utilities for Linux NFS client and server.
Name: nfs-utils
Version: 0.1.3
Release: 1
Source0: ftp://ftp.valinux.com/pub/support/hjl/nfs/%{name}-%{version}.tar.gz
Group: System Environment/Daemons
Obsoletes: nfs-server nfs-server-clients knfsd knfsd-clients knfsd-lock
Provides: nfs-server nfs-server-clients knfsd knfsd-clients knfsd-lock
Copyright: GPL
ExcludeArch: armv4l
Buildroot: /var/tmp/%{name}-root
Serial: 1
Requires: kernel >= 2.2.5, portmap >= 4.0

%description
The nfs-utils package provides the utilities for Linux NFS client and
server.

%prep
%setup -q

%build
./configure
make all

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT{/sbin,/usr/{sbin,man/man5,man/man8}}
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
mkdir -p $RPM_BUILD_ROOT/dev

make install install_prefix=$RPM_BUILD_ROOT
install -s -m 755 tools/rpcdebug/rpcdebug $RPM_BUILD_ROOT/sbin
install -m 755 etc/redhat/nfsd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/nfs
install -m 755 etc/redhat/nfslock.init $RPM_BUILD_ROOT/etc/rc.d/init.d/nfslock

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/chkconfig --add nfs
/sbin/chkconfig --add nfslock

%preun
if [ "$1" = "0" ]; then
    /sbin/chkconfig --del nfs
    /sbin/chkconfig --del nfslock
fi

%files
%defattr(-,root,root)
/sbin/rpcdebug
/usr/sbin/exportfs
/usr/sbin/nfsstat
/usr/sbin/nhfsstone
/usr/sbin/rpc.lockd
/usr/sbin/rpc.mountd
/usr/sbin/rpc.nfsd
/usr/sbin/rpc.rquotad
/usr/sbin/rpc.statd
/usr/sbin/showmount
/usr/man/man5/exports.5
/usr/man/man8/exportfs.8
/usr/man/man8/mountd.8
/usr/man/man8/nfsd.8
/usr/man/man8/nfsstat.8
/usr/man/man8/rpc.mountd.8
/usr/man/man8/rpc.nfsd.8
/usr/man/man8/rpc.statd.8
/usr/man/man8/rpc.rquotad.8
/usr/man/man8/rquotad.8
/usr/man/man8/showmount.8
/usr/man/man8/statd.8
%config /etc/rc.d/init.d/nfs
%config /etc/rc.d/init.d/nfslock
%dir /var/lib/nfs
%config(noreplace) /var/lib/nfs/xtab
%config(noreplace) /var/lib/nfs/etab
%config(noreplace) /var/lib/nfs/rmtab
%doc README
