/*
 * utils/mountd/auth.c
 *
 * Authentication procedures for mountd.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "misc.h"
#include "nfslib.h"
#include "exportfs.h"
#include "mountd.h"
#include "xmalloc.h"

enum auth_error
{
  bad_path,
  unknown_host,
  no_entry,
  not_exported,
  illegal_port,
  success
};

static void		auth_fixpath(char *path);
static char	*export_file = NULL;

void
auth_init(char *exports)
{

	export_file = exports;
	auth_reload();
	xtab_mount_write();
}

int
auth_reload()
{
	struct stat		stb;
	static time_t		last_modified = 0;

	if (stat(_PATH_ETAB, &stb) < 0)
		xlog(L_FATAL, "couldn't stat %s", _PATH_ETAB);
	if (stb.st_mtime == last_modified)
		return 0;
	last_modified = stb.st_mtime;

	export_freeall();
	// export_read(export_file);
	xtab_export_read();

	return 1;
}

static nfs_export *
auth_authenticate_internal(char *what, struct sockaddr_in *caller,
			   char *path, struct hostent *hp,
			   enum auth_error *error)
{
	nfs_export		*exp;

	if (!(exp = export_find(hp, path))) {
		*error = no_entry;
		return NULL;
	}
	if (!exp->m_mayexport) {
		*error = not_exported;
		return NULL;
	}

	if (!(exp->m_export.e_flags & NFSEXP_INSECURE_PORT) &&
	    (ntohs(caller->sin_port) <  IPPORT_RESERVED/2 ||
	     ntohs(caller->sin_port) >= IPPORT_RESERVED)) {
		*error = illegal_port;
		return NULL;
	}

	*error = success;

	return exp;
}

nfs_export *
auth_authenticate(char *what, struct sockaddr_in *caller, char *path)
{
	nfs_export	*exp = NULL;
	char		epath[MAXPATHLEN+1];
	char		*p = NULL;
	struct hostent	*hp = NULL;
	struct in_addr	addr = caller->sin_addr;
	enum auth_error	error;

	if (path [0] != '/') {
		xlog(L_WARNING, "bad path in %s request from %s: \"%s\"",
		     what, inet_ntoa(addr), path);
		return exp;
	}

	strncpy(epath, path, sizeof (epath) - 1);
	epath[sizeof (epath) - 1] = '\0';
	auth_fixpath(epath); /* strip duplicate '/' etc */

	hp = get_reliable_hostbyaddr((const char*)&caller->sin_addr, sizeof(struct in_addr),
				     AF_INET);
	if (!hp)
		hp = get_hostent((const char*)&caller->sin_addr, sizeof(struct in_addr),
				     AF_INET);
	if (!hp)
		return exp;

	/* Try the longest matching exported pathname. */
	while (1) {
		exp = auth_authenticate_internal(what, caller, epath,
						 hp, &error);
		if (exp || (error != not_exported && error != no_entry))
			break;
		/* We have to treat the root, "/", specially. */
		if (p == &epath[1]) break;
		p = strrchr(epath, '/');
		if (p == epath) p++;
		*p = '\0';
	}
	free(hp);

	switch (error) {
	case bad_path:
		xlog(L_WARNING, "bad path in %s request from %s: \"%s\"",
		     what, inet_ntoa(addr), path);
		break;

	case unknown_host:
		xlog(L_WARNING, "%s request from unknown host %s for %s (%s)",
		     what, inet_ntoa(addr), path, epath);
		break;

	case no_entry:
		xlog(L_WARNING, "refused %s request from %s for %s (%s): no export entry",
		     what, hp->h_name, path, epath);
		break;

	case not_exported:
		xlog(L_WARNING, "refused %s request from %s for %s (%s): not exported",
		     what, hp->h_name, path, epath);
		break;

	case illegal_port:
		xlog(L_WARNING, "refused %s request from %s for %s (%s): illegal port %d",
		     what, hp->h_name, path, epath, ntohs(caller->sin_port));
		break;

	case success:
		xlog(L_NOTICE, "authenticated %s request from %s:%d for %s (%s)",
		     what, hp->h_name, ntohs(caller->sin_port), path, epath);
		break;
	default:
		xlog(L_NOTICE, "%s request from %s:%d for %s (%s) gave %d",
		     what, hp->h_name, ntohs(caller->sin_port), path, epath, error);
	}

	if (hp)
		free (hp);

	return exp;
}

static void
auth_fixpath(char *path)
{
	char	*sp, *cp;

	for (sp = cp = path; *sp; sp++) {
		if (*sp != '/' || sp[1] != '/')
			*cp++ = *sp;
	}
	while (cp > path+1 && cp[-1] == '/')
		cp--;
	*cp = '\0';
}
