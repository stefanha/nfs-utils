/*
 * support/nfs/xmalloc.c
 *
 * malloc with NULL checking.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include "xmalloc.h"
#include "xlog.h"

void *
xmalloc(size_t size)
{
	void	*ptr;

	if (!(ptr = malloc(size)))
		xlog(L_FATAL, "malloc: out of memory");
	return ptr;
}

void *
xrealloc(void *ptr, size_t size)
{
	if (!(ptr = realloc(ptr, size)))
		xlog(L_FATAL, "realloc: out of memory");
	return ptr;
}

void
xfree(void *ptr)
{
	free(ptr);
}

char *
xstrdup(const char *str)
{
	char	*ret;

	if (!(ret = strdup(str)))
		xlog(L_FATAL, "strdup: out of memory");
	return ret;
}
