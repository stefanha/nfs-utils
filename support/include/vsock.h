/*
 * AF_VSOCK constants and struct definitions
 *
 * Copyright (C) 2007-2013 VMware, Inc. All rights reserved.
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation version 2 and no later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _VSOCK_H
#define _VSOCK_H

/*
 * This header includes the vsock system headers.  Distros have been known to
 * ship with:
 * 1. vsock-capable kernels but no AF_VSOCK constant
 * 2. AF_VSOCK but no <linux/vm_sockets.h>
 *
 * Define constants and structs ourselves, if necessary.  This avoids #ifdefs
 * in many places throughout the code.  If the kernel really does not support
 * AF_VSOCK then socket(2) returns an EAFNOSUPPORT errno.
 */

#include <sys/socket.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#ifdef HAVE_LINUX_VM_SOCKETS_H
#include <linux/vm_sockets.h>
#else /* !HAVE_LINUX_VM_SOCKETS_H */

#define VMADDR_CID_ANY (-1U)

struct sockaddr_vm
{
	sa_family_t svm_family;
	unsigned short svm_reserved1;
	unsigned int svm_port;
	unsigned int svm_cid;
	unsigned char svm_zero[sizeof(struct sockaddr) -
			       sizeof(sa_family_t) -
			       sizeof(unsigned short) -
			       sizeof(unsigned int) - sizeof(unsigned int)];
};

#define IOCTL_VM_SOCKETS_GET_LOCAL_CID _IO(7, 0xb9)

#endif /* !HAVE_LINUX_VM_SOCKETS_H */

#endif /* !_VSOCK_H */
