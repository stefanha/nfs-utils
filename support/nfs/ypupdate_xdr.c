/*
 * support/nfs/ypupdate_xdr.c
 *
 * This file contains the XDR code for the ypupdate protocol.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <ypupdate.h>

bool_t
xdr_ypupdate_args(XDR *xdrs, ypupdate_args *objp)
{
	 return xdr_string(xdrs, &objp->mapname, MAXMAPNAMELEN) &&
	 	xdr_bytes(xdrs, &objp->key.yp_buf_val,
				&objp->key.yp_buf_len, MAXYPDATALEN) &&
	 	xdr_bytes(xdrs, &objp->datum.yp_buf_val,
				&objp->datum.yp_buf_len, MAXYPDATALEN);
}

bool_t
xdr_ypdelete_args(XDR *xdrs, ypdelete_args *objp)
{
	 return xdr_string(xdrs, &objp->mapname, MAXMAPNAMELEN) &&
	 	xdr_bytes(xdrs, &objp->key.yp_buf_val,
				&objp->key.yp_buf_len, MAXYPDATALEN);
}
