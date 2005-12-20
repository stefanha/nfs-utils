/*
 * QUOTA    An implementation of the diskquota system for the LINUX
 *          operating system. QUOTA is implemented using the BSD systemcall
 *          interface as the means of communication with the user level.
 *          Should work for all filesystems because of integration into the
 *          VFS layer of the operating system.
 *          This is based on the Melbourne quota system wich uses both user and
 *          group quota files.
 *
 *          System call interface.
 *
 * Version: $Id: quotactl.c,v 2.3 1995/07/23 09:58:06 mvw Exp mvw $
 *
 * Author:  Marco van Wieringen <mvw@planets.ow.nl> <mvw@tnix.net>
 *
 *          This program is free software; you can redistribute it and/or
 *          modify it under the terms of the GNU General Public License
 *          as published by the Free Software Foundation; either version
 *          2 of the License, or (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

int quotactl(int cmd, const char * special, int id, caddr_t addr)
{
	return syscall(SYS_quotactl, cmd, special, id, addr);
}
