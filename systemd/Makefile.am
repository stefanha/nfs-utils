## Process this file with automake to produce Makefile.in

MAINTAINERCLEANFILES = Makefile.in

unit_files =  \
    nfs-blkmap.target \
    nfs-client.target \
    \
    auth-rpcgss-module.service \
    nfs-blkmap.service \
    nfs-config.service \
    nfs-idmapd.service \
    nfs-mountd.service \
    nfs-server.service \
    nfs-utils.service \
    rpc-gssd.service \
    rpc-statd-notify.service \
    rpc-statd.service \
    rpc-svcgssd.service \
    \
    proc-fs-nfsd.mount \
    var-lib-nfs-rpc_pipefs.mount

EXTRA_DIST = $(unit_files)

unit_dir = /usr/lib/systemd/system

if INSTALL_SYSTEMD
install-data-hook: $(unit_files)
	mkdir -p $(DESTDIR)/$(unitdir)
	cp $(unit_files) $(DESTDIR)/$(unitdir)
endif
