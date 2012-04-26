/*
 * nfsdcld.c -- NFSv4 client name tracking daemon
 *
 * Copyright (C) 2011  Red Hat, Jeff Layton <jlayton@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <event.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "xlog.h"
#include "nfslib.h"
#include "cld.h"

#ifndef PIPEFS_DIR
#define PIPEFS_DIR NFS_STATEDIR "/rpc_pipefs"
#endif

#define DEFAULT_CLD_PATH	PIPEFS_DIR "/nfsd/cld"

#define UPCALL_VERSION		1

/* private data structures */
struct cld_client {
	int			cl_fd;
	struct event		cl_event;
	struct cld_msg	cl_msg;
};

/* global variables */
static char *pipepath = DEFAULT_CLD_PATH;

static struct option longopts[] =
{
	{ "help", 0, NULL, 'h' },
	{ "foreground", 0, NULL, 'F' },
	{ "debug", 0, NULL, 'd' },
	{ "pipe", 1, NULL, 'p' },
	{ "storagedir", 1, NULL, 's' },
	{ NULL, 0, 0, 0 },
};

/* forward declarations */
static void cldcb(int UNUSED(fd), short which, void *data);

static void
usage(char *progname)
{
	printf("%s [ -hFd ] [ -p pipe ] [ -s dir ]\n", progname);
}

static int
cld_pipe_open(struct cld_client *clnt)
{
	int fd;

	xlog(D_GENERAL, "%s: opening upcall pipe %s", __func__, pipepath);
	fd = open(pipepath, O_RDWR, 0);
	if (fd < 0) {
		xlog(L_ERROR, "%s: open of %s failed: %m", __func__, pipepath);
		return -errno;
	}

	if (clnt->cl_event.ev_flags & EVLIST_INIT)
		event_del(&clnt->cl_event);
	if (clnt->cl_fd >= 0)
		close(clnt->cl_fd);

	clnt->cl_fd = fd;
	event_set(&clnt->cl_event, clnt->cl_fd, EV_READ, cldcb, clnt);
	/* event_add is done by the caller */
	return 0;
}

static int
cld_pipe_init(struct cld_client *clnt)
{
	int ret;

	clnt->cl_fd = -1;
	ret = cld_pipe_open(clnt);
	if (ret)
		return ret;

	event_add(&clnt->cl_event, NULL);
	return 0;
}

static void
cld_not_implemented(struct cld_client *clnt)
{
	int ret;
	ssize_t bsize, wsize;
	struct cld_msg *cmsg = &clnt->cl_msg;

	xlog(D_GENERAL, "%s: downcalling with not implemented error", __func__);

	/* set up reply */
	cmsg->cm_status = -EOPNOTSUPP;

	bsize = sizeof(*cmsg);

	wsize = atomicio((void *)write, clnt->cl_fd, cmsg, bsize);
	if (wsize != bsize)
		xlog(L_ERROR, "%s: problem writing to cld pipe (%ld): %m",
			 __func__, wsize);

	/* reopen pipe, just to be sure */
	ret = cld_pipe_open(clnt);
	if (ret) {
		xlog(L_FATAL, "%s: unable to reopen pipe: %d", __func__, ret);
		exit(ret);
	}
}

static void
cld_create(struct cld_client *clnt)
{
	int ret;
	ssize_t bsize, wsize;
	struct cld_msg *cmsg = &clnt->cl_msg;

	xlog(D_GENERAL, "%s: create client record.", __func__);

	ret = sqlite_insert_client(cmsg->cm_u.cm_name.cn_id,
				   cmsg->cm_u.cm_name.cn_len);

	cmsg->cm_status = ret ? -EREMOTEIO : ret;

	bsize = sizeof(*cmsg);

	xlog(D_GENERAL, "Doing downcall with status %d", cmsg->cm_status);
	wsize = atomicio((void *)write, clnt->cl_fd, cmsg, bsize);
	if (wsize != bsize) {
		xlog(L_ERROR, "%s: problem writing to cld pipe (%ld): %m",
			 __func__, wsize);
		ret = cld_pipe_open(clnt);
		if (ret) {
			xlog(L_FATAL, "%s: unable to reopen pipe: %d",
					__func__, ret);
			exit(ret);
		}
	}
}

static void
cld_remove(struct cld_client *clnt)
{
	int ret;
	ssize_t bsize, wsize;
	struct cld_msg *cmsg = &clnt->cl_msg;

	xlog(D_GENERAL, "%s: remove client record.", __func__);

	ret = sqlite_remove_client(cmsg->cm_u.cm_name.cn_id,
				   cmsg->cm_u.cm_name.cn_len);

	cmsg->cm_status = ret ? -EREMOTEIO : ret;

	bsize = sizeof(*cmsg);

	xlog(D_GENERAL, "%s: downcall with status %d", __func__,
			cmsg->cm_status);
	wsize = atomicio((void *)write, clnt->cl_fd, cmsg, bsize);
	if (wsize != bsize) {
		xlog(L_ERROR, "%s: problem writing to cld pipe (%ld): %m",
			 __func__, wsize);
		ret = cld_pipe_open(clnt);
		if (ret) {
			xlog(L_FATAL, "%s: unable to reopen pipe: %d",
					__func__, ret);
			exit(ret);
		}
	}
}

static void
cldcb(int UNUSED(fd), short which, void *data)
{
	ssize_t len;
	struct cld_client *clnt = data;
	struct cld_msg *cmsg = &clnt->cl_msg;

	if (which != EV_READ)
		goto out;

	len = atomicio(read, clnt->cl_fd, cmsg, sizeof(*cmsg));
	if (len <= 0) {
		xlog(L_ERROR, "%s: pipe read failed: %m", __func__);
		cld_pipe_open(clnt);
		goto out;
	}

	if (cmsg->cm_vers != UPCALL_VERSION) {
		xlog(L_ERROR, "%s: unsupported upcall version: %hu",
				cmsg->cm_vers);
		cld_pipe_open(clnt);
		goto out;
	}

	switch(cmsg->cm_cmd) {
	case Cld_Create:
		cld_create(clnt);
		break;
	case Cld_Remove:
		cld_remove(clnt);
		break;
	default:
		xlog(L_WARNING, "%s: command %u is not yet implemented",
				__func__, cmsg->cm_cmd);
		cld_not_implemented(clnt);
	}
out:
	event_add(&clnt->cl_event, NULL);
}

int
main(int argc, char **argv)
{
	char arg;
	int rc = 0;
	bool foreground = false;
	char *progname;
	char *storagedir = NULL;
	struct cld_client clnt;

	memset(&clnt, 0, sizeof(clnt));

	progname = strdup(basename(argv[0]));
	if (!progname) {
		fprintf(stderr, "%s: unable to allocate memory.\n", argv[0]);
		return 1;
	}

	event_init();
	xlog_syslog(0);
	xlog_stderr(1);

	/* process command-line options */
	while ((arg = getopt_long(argc, argv, "hdFp:s:", longopts,
				  NULL)) != EOF) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			break;
		case 'F':
			foreground = true;
			break;
		case 'p':
			pipepath = optarg;
			break;
		case 's':
			storagedir = optarg;
			break;
		default:
			usage(progname);
			return 0;
		}
	}


	xlog_open(progname);
	if (!foreground) {
		xlog_syslog(1);
		xlog_stderr(0);
		rc = daemon(0, 0);
		if (rc) {
			xlog(L_ERROR, "Unable to daemonize: %m");
			goto out;
		}
	}

	/* set up storage db */
	rc = sqlite_maindb_init(storagedir);
	if (rc) {
		xlog(L_ERROR, "Failed to open main database: %d", rc);
		goto out;
	}

	/* set up event handler */
	rc = cld_pipe_init(&clnt);
	if (rc)
		goto out;

	xlog(D_GENERAL, "%s: Starting event dispatch handler.", __func__);
	rc = event_dispatch();
	if (rc < 0)
		xlog(L_ERROR, "%s: event_dispatch failed: %m", __func__);

	close(clnt.cl_fd);
out:
	free(progname);
	return rc;
}
