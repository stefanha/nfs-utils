/* 
 * Copyright (C) 1995-1999 Jeffrey A. Uphoff
 * Modified by Olaf Kirch, 1996.
 * Modified by H.J. Lu, 1998.
 *
 * NSM for Linux.
 */

#include "config.h"

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
    /* SHIT!  SHIT!  SHIT! */
    die ("malloc failed");

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
    die ("strdup failed");

  return (result);
}


/*
 * Call with check=1 to verify that this host is not still on the rtnl
 * before unlinking file.
 */
void
xunlink (char *path, char *host, short int check)
{
  char *tozap;

  tozap=alloca (strlen(path)+strlen(host)+2);
  sprintf (tozap, "%s/%s", path, host);

  if (!check || !nlist_gethost(rtnl, host, 0)) {
    if (unlink (tozap) == -1)
      log (L_ERROR, "unlink (%s): %s", tozap, strerror (errno));
    else
      dprintf (L_DEBUG, "Unlinked %s", tozap);
  }
  else
    dprintf (L_DEBUG, "Not unlinking %s--host still monitored.", tozap);
}
