/*
 * utils/mountd/rmtab.c
 *
 * Manage the rmtab file for mountd.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "xmalloc.h"
#include "misc.h"
#include "exportfs.h"
#include "xio.h"
#include "mountd.h"

void
mountlist_add(nfs_export *exp, const char *path)
{
	struct rmtabent	xe;
	struct rmtabent	*rep;
	int		lockid;

	if ((lockid = xflock(_PATH_RMTAB, "a")) < 0)
		return;
	setrmtabent("r");
	while ((rep = getrmtabent(1)) != NULL) {
		if (strcmp (rep->r_client,
			    exp->m_client->m_hostname) == 0
		    && strcmp(rep->r_path, path) == 0) {
			endrmtabent();
			xfunlock(lockid);
			return;
		}
	}
	endrmtabent();
	strncpy(xe.r_client, exp->m_client->m_hostname,
		sizeof (xe.r_client) - 1);
	xe.r_client [sizeof (xe.r_client) - 1] = '\0';
	strncpy(xe.r_path, path, sizeof (xe.r_path) - 1);
	xe.r_path [sizeof (xe.r_path) - 1] = '\0';
	if (setrmtabent("a")) {
		putrmtabent(&xe);
		endrmtabent();
	}
	xfunlock(lockid);
}

void
mountlist_del(nfs_export *exp, const char *path)
{
	struct rmtabent	*rep;
	FILE		*fp;
	char		*hname = exp->m_client->m_hostname;
	int		lockid;

	if ((lockid = xflock(_PATH_RMTAB, "w")) < 0)
		return;
	if (!setrmtabent("r")) {
		xfunlock(lockid);
		return;
	}
	if (!(fp = fsetrmtabent(_PATH_RMTABTMP, "w"))) {
		endrmtabent();
		xfunlock(lockid);
		return;
	}
	while ((rep = getrmtabent(1)) != NULL) {
		if (strcmp (rep->r_client, hname)
		    || strcmp(rep->r_path, path))
			fputrmtabent(fp, rep);
	}
	if (rename(_PATH_RMTABTMP, _PATH_RMTAB) < 0) {
		xlog(L_ERROR, "couldn't rename %s to %s",
				_PATH_RMTABTMP, _PATH_RMTAB);
	}
	endrmtabent();	/* close & unlink */
	fendrmtabent(fp);
	xfunlock(lockid);
}

void
mountlist_del_all(struct sockaddr_in *sin)
{
	struct in_addr	addr = sin->sin_addr;
	struct hostent	*hp;
	struct rmtabent	*rep;
	nfs_export	*exp;
	FILE		*fp;
	int		lockid;

	if ((lockid = xflock(_PATH_RMTAB, "w")) < 0)
		return;
	if (!(hp = gethostbyaddr((char *)&addr, sizeof(addr), AF_INET))) {
		xlog(L_ERROR, "can't get hostname of %s", inet_ntoa(addr));
		xfunlock(lockid);
		return;
	}
	else
		hp = hostent_dup (hp);

	if (!setrmtabent("r")) {
		xfunlock(lockid);
		free (hp);
		return;
	}
	if (!(fp = fsetrmtabent(_PATH_RMTABTMP, "w"))) {
		endrmtabent();
		xfunlock(lockid);
		free (hp);
		return;
	}
	while ((rep = getrmtabent(1)) != NULL) {
		if (strcmp(rep->r_client, hp->h_name) == 0 &&
		    (exp = auth_authenticate("umountall", sin, rep->r_path))) {
			export_reset(exp);
			continue;
		}
		fputrmtabent(fp, rep);
	}
	if (rename(_PATH_RMTABTMP, _PATH_RMTAB) < 0) {
		xlog(L_ERROR, "couldn't rename %s to %s",
				_PATH_RMTABTMP, _PATH_RMTAB);
	}
	endrmtabent();	/* close & unlink */
	fendrmtabent(fp);
	xfunlock(lockid);
	free (hp);
}

mountlist
mountlist_list(void)
{
	static mountlist	mlist = NULL;
	static time_t		last_mtime = 0;
	mountlist		m;
	struct rmtabent		*rep;
	struct stat		stb;
	int			lockid;

	if ((lockid = xflock(_PATH_RMTAB, "r")) < 0)
		return NULL;
	if (stat(_PATH_RMTAB, &stb) < 0) {
		xlog(L_ERROR, "can't stat %s", _PATH_RMTAB);
		return NULL;
	}
	if (stb.st_mtime != last_mtime) {
		while (mlist) {
			mlist = (m = mlist)->ml_next;
			xfree(m->ml_hostname);
			xfree(m->ml_directory);
			xfree(m);
		}
		last_mtime = stb.st_mtime;

		setrmtabent("r");
		while ((rep = getrmtabent(1)) != NULL) {
			m = (mountlist) xmalloc(sizeof(*m));
			m->ml_hostname = xstrdup(rep->r_client);
			m->ml_directory = xstrdup(rep->r_path);
			m->ml_next = mlist;
			mlist = m;
		}
		endrmtabent();
	}
	xfunlock(lockid);

	return mlist;
}
