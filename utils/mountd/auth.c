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

enum auth_error
{
  bad_path,
  unknown_host,
  no_entry,
  not_exported,
  illegal_port,
  faked_hostent,
  no_forward_dns,
  success
};

static void		auth_fixpath(char *path);
static nfs_export*	auth_authenticate_internal
  (char *what, struct sockaddr_in *caller, char *path,
   struct hostent **hpp, enum auth_error *error);
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
			   char *path, struct hostent **hpp,
			   enum auth_error *error)
{
	struct in_addr		addr = caller->sin_addr;
	nfs_export		*exp;

	if (path[0] != '/') {
		*error = bad_path;
		return NULL;
	}
	auth_fixpath(path);

	if (!(*hpp = gethostbyaddr((const char *)&addr, sizeof(addr), AF_INET)))
		*hpp = get_hostent((const char *)&addr, sizeof(addr),
				   AF_INET);
	else {
		/* must make sure the hostent is authorative. */
		char **sp;
		struct hostent *forward;

		forward = gethostbyname((*hpp)->h_name);
		if (forward) {
			/* now make sure the "addr" is in the list */
			for (sp = forward->h_addr_list ; *sp ; sp++) {
				if (memcmp(*sp, &addr, forward->h_length)==0)
					break;
			}
		
			if (!*sp) {
				/* it was a FAKE */
				*error = faked_hostent;
				*hpp = hostent_dup (*hpp);
				return NULL;
			}
			*hpp = hostent_dup (forward);
		}
		else {
			/* never heard of it. misconfigured DNS? */
			*error = no_forward_dns;
			*hpp = hostent_dup (*hpp);
			return NULL;
		}
	}

	if (!(exp = export_find(*hpp, path))) {
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

	if (path [0] != '/') return exp;

	strncpy(epath, path, sizeof (epath) - 1);
	epath[sizeof (epath) - 1] = '\0';

	/* Try the longest matching exported pathname. */
	while (1) {
		if (hp) {
			free (hp);
			hp = NULL;
		}
		exp = auth_authenticate_internal(what, caller, epath,
						 &hp, &error);
		if (exp || (error != not_exported && error != no_entry))
			break;
		/* We have to treat the root, "/", specially. */
		if (p == &epath[1]) break;
		p = strrchr(epath, '/');
		if (p == epath) p++;
		*p = '\0';
	}

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

	case faked_hostent:
		xlog(L_WARNING, "refused %s request from %s (%s) for %s (%s): DNS forward lookup does't match with reverse",
		     what, inet_ntoa(addr), hp->h_name, path, epath);
		break;

	case no_forward_dns:
		xlog(L_WARNING, "refused %s request from %s (%s) for %s (%s): no DNS forward lookup",
		     what, inet_ntoa(addr), hp->h_name, path, epath);
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
