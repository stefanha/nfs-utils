/*
 * ypupdate.h	This file contains the public declarations for the
 *		ypupdate client side RPC stubs.
 *
 * Copyright (C) 1995 Olaf Kirch <okir@monad.swb.de>
 */

#ifndef YPUPDATE_H
#define YPUPDATE_H

#include <rpcsvc/ypclnt.h>

int	yp_update(char *domain, char *map, unsigned int ypop,
			char *key, int keylen, char *data, int datalen);

#endif YPUPDATE_H
