%define rquotad 0
%{?do_rquotad:%define rquotad 1}

# We don't use libtool. 
%define __libtoolize :

Summary: NFS utlilities and supporting daemons for the kernel NFS server.
Name: nfs-utils
Version: 1.0.1
Release: 1
Source0: ftp://nfs.sourceforge.net/pub/nfs/%{name}-%{version}.tar.gz
Group: System Environment/Daemons
Obsoletes: nfs-server
Obsoletes: knfsd
Obsoletes: knfsd-clients
Obsoletes: nfs-server-clients 
Obsoletes: knfsd-lock
Provides: nfs-server 
Provides: nfs-server-clients 
Provides: knfsd-lock 
Provides: knfsd-clients 
Provides: knfsd
Copyright: GPL
Buildroot: /var/tmp/%{name}-root
Requires: kernel >= 2.2.7, portmap >= 4.0

%description
The nfs-utils package provides a daemon for the kernel NFS server and
related tools, which provides a much higher level of performance than the
traditional Linux NFS server used by most users.

This package also contains the showmount program.  Showmount queries the
mount daemon on a remote host for information about the NFS (Network File
System) server on the remote host.  For example, showmount can display the
clients which are mounted on that host.

%prep
%setup -q

%build
CC=%{__cc}; export CC
CC_FOR_BUILD=gcc; export CC_FOR_BUILD
%configure \
%if !%{rquotad}
	--disable-rquotad \
%endif
	--build=%{_build_alias}

make all

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/{/sbin,/usr/sbin}
mkdir -p $RPM_BUILD_ROOT%{_mandir}/{man5,man8}
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
mkdir -p $RPM_BUILD_ROOT/etc/sysconfig
mkdir -p $RPM_BUILD_ROOT/var/lib/nfs
make install_prefix=$RPM_BUILD_ROOT MANDIR=$RPM_BUILD_ROOT%{_mandir} SBINDIR=$RPM_BUILD_ROOT%{_prefix}/sbin install
install -s -m 755 tools/rpcdebug/rpcdebug $RPM_BUILD_ROOT/sbin
install -m 755 etc/redhat/nfs.init $RPM_BUILD_ROOT/etc/rc.d/init.d/nfs
install -m 755 etc/redhat/nfs $RPM_BUILD_ROOT/etc/sysconfig/nfs
install -m 755 etc/redhat/nfslock.init $RPM_BUILD_ROOT/etc/rc.d/init.d/nfslock
touch $RPM_BUILD_ROOT/var/lib/nfs/rmtab
mv $RPM_BUILD_ROOT/usr/sbin/{rpc.lockd,rpc.statd} $RPM_BUILD_ROOT/sbin

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

%triggerpostun -- nfs-server
/sbin/chkconfig --add nfs

%triggerpostun -- knfsd
/sbin/chkconfig --add nfs

%triggerpostun -- knfsd-clients
/sbin/chkconfig --add nfslock

%files
%defattr(-,root,root)
%config /etc/rc.d/init.d/nfs
%dir /var/lib/nfs
%config(noreplace) /etc/sysconfig/nfs
%config(noreplace) /var/lib/nfs/xtab
%config(noreplace) /var/lib/nfs/etab
%config(noreplace) /var/lib/nfs/rmtab
/sbin/rpcdebug
/sbin/rpc.lockd
/sbin/rpc.statd
/usr/sbin/exportfs
/usr/sbin/nfsstat
/usr/sbin/nhfsstone
/usr/sbin/rpc.mountd
/usr/sbin/rpc.nfsd
%if %{rquotad}
/usr/sbin/rpc.rquotad
%endif
/usr/sbin/showmount
%{_mandir}/man?/*
%config /etc/rc.d/init.d/nfslock
%doc README ChangeLog COPYING
