/*
 * xmalloc	Module for memory allocation. Drop in your
 *		debugging malloc module if you feel like it.
 *
 * Copyright (C) 1995 Olaf Kirch <okir@monad.swb.de>
 */

#ifndef XMALLOC_H
#define XMALLOC_H

void	*xmalloc(size_t size);
void	*xrealloc(void *ptr, size_t size);
char	*xstrdup(const char *s);
void	xfree(void *ptr);

#endif /* XMALLOC_H */
