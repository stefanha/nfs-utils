/*
 *	nlm_dispatch	This is a generic RPC call dispatcher.
 *			It is loosely based on the dispatch mechanism I
 *			first encountered in the UNFSD source.
 *
 *	Cyopright (C) 1995, Olaf Kirch <okir@monad.swb.de>
 *
 *	24.05.95	okir
 *
 */

#ifndef RPCDISPATCH_H
#define RPCDISPATCH_H

#include <rpc/rpc.h>

#ifdef __STDC__
#   define CONCAT(a,b)		a##b
#   define CONCAT3(a,b,c)	a##b##c
#   define STRING(a)		#a
#else
#   define CONCAT(a,b)		a/**/b
#   define CONCAT3(a,b,c)	a/**/b/**/c
#   define STRING(a)		"a"
#endif

#ifdef __STDC__
typedef bool_t	(*rpcsvc_fn_t)(struct svc_req *, void *argp, void *resp);
#else
typedef bool_t	(*rpcsvc_fn_t)();
#endif

#define table_ent(func, vers, arg_type, res_type) \
	{	STRING(func), \
		(rpcsvc_fn_t)CONCAT(func,_svc), vers,\
		(xdrproc_t)CONCAT(xdr_, arg_type), sizeof(arg_type), \
		(xdrproc_t)CONCAT(xdr_, res_type), sizeof(res_type), \
	}
#define nlm_undef_svc	NULL
#define xdr_nlm_void	xdr_void

struct dispatch_entry {
	const char	*name;
	rpcsvc_fn_t	func;
	unsigned int	versions;		/* bitmap of versions */
	xdrproc_t	xdr_arg_fn;		/* argument XDR */
	size_t		xdr_arg_size;
	xdrproc_t	xdr_res_fn;		/* result XDR */
	size_t		xdr_res_size;
};

void	rpc_dispatch(struct svc_req *rq, SVCXPRT *tp,
			struct dispatch_entry *dtable, int nproc,
			void *argp, void *resp);
void	rpc_svcrun(void);

#endif /* RPCDISPATCH_H */
