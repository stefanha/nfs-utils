/*
 * support/export/rmntab.c
 *
 * Interface to the rmnt file.
 *
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "xmalloc.h"
#include "misc.h"
#include "nfslib.h"
#include "exportfs.h"
#include "xio.h"
#include "xlog.h"

int
rmtab_read(void)
{
	struct rmtabent		*rep;
	nfs_export		*exp;

	setrmtabent("r");
	while ((rep = getrmtabent(1, NULL)) != NULL) {
		struct exportent	*xp;
		struct hostent		*hp = NULL;
		int			htype;
		
		htype = client_gettype(rep->r_client);
		if (htype == MCL_FQDN
		    && (hp = gethostbyname (rep->r_client))
		    && (hp = hostent_dup (hp),
			xp = export_allowed (hp, rep->r_path))) {
			/* see if the entry already exists, otherwise this was an instantiated
			 * wild card, and we must add it
			 */
			exp = export_lookup(rep->r_client, xp->e_path, 0);
			if (!exp) {
				strncpy (xp->e_hostname, rep->r_client,
					 sizeof (xp->e_hostname) - 1);
				xp->e_hostname[sizeof (xp->e_hostname) -1] = '\0';
				exp = export_create(xp, 0);
			}
			free (hp);

			if (!exp)
				continue;
			exp->m_mayexport = 1;
		} else if (hp) /* export_allowed failed */
			free(hp);
	}
	if (errno == EINVAL) {
		/* Something goes wrong. We need to fix the rmtab
		   file. */
		int	lockid;
		FILE	*fp;
		if ((lockid = xflock(_PATH_RMTAB, "w")) < 0)
			return -1;
		rewindrmtabent();
		if (!(fp = fsetrmtabent(_PATH_RMTABTMP, "w"))) {
			endrmtabent ();
			xfunlock(lockid);
			return -1;
		}
		while ((rep = getrmtabent(0, NULL)) != NULL) {
			fputrmtabent(fp, rep, NULL);
		}
		if (rename(_PATH_RMTABTMP, _PATH_RMTAB) < 0) {
			xlog(L_ERROR, "couldn't rename %s to %s",
			     _PATH_RMTABTMP, _PATH_RMTAB);
		}
		endrmtabent();
		fendrmtabent(fp);
		xfunlock(lockid);
	}
	else {
		endrmtabent();
	}
	return 0;
}
