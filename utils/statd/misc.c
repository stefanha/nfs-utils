/* 
 * Copyright (C) 1995-1999 Jeffrey A. Uphoff
 * Modified by Olaf Kirch, 1996.
 * Modified by H.J. Lu, 1998.
 *
 * NSM for Linux.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include "statd.h"
#include "notlist.h"

/*
 * Error-checking malloc() wrapper.
 */
void *
xmalloc (size_t size)
{
  void *ptr;

  if (size == 0)
    return ((void *)NULL);

  if (!(ptr = malloc (size)))
    xlog_err ("malloc failed");

  return (ptr);
}


/* 
 * Error-checking strdup() wrapper.
 */
char *
xstrdup (const char *string)
{
  char *result;

  /* Will only fail if underlying malloc() fails (ENOMEM). */
  if (!(result = strdup (string)))
    xlog_err ("strdup failed");

  return (result);
}


/*
 * Unlinking a file.
 */
void
xunlink (char *path, char *host)
{
	char *tozap;

	tozap = malloc(strlen(path)+strlen(host)+2);
	if (tozap == NULL) {
		xlog(L_ERROR, "xunlink: malloc failed: errno %d (%m)", errno);
		return;
	}
	sprintf (tozap, "%s/%s", path, host);

	if (unlink (tozap) == -1)
		xlog(L_ERROR, "unlink (%s): %m", tozap);
	else
		xlog(D_GENERAL, "Unlinked %s", tozap);

	free(tozap);
}
