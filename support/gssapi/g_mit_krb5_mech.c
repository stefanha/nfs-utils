/*
 *  g_mit_krb5_mech.c
 *
 *  Copyright (c) 2004 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Kevin Coffman <kwc@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "config.h"
#include <stdio.h>
#include <dlfcn.h>
#include "mglueP.h"

/*
 * Table of function names that we need to locate within a mechanism's
 * shared library if it does not support the xxx_gss_initialize function.
 */
static char *glue_func_names[] = {
	"gss_acquire_cred",
	"gss_release_cred",
	"gss_init_sec_context",
	"gss_accept_sec_context",
	"gss_process_context_token",
	"gss_delete_sec_context",
	"gss_context_time",
	"gss_sign",
	"gss_verify",
	"gss_seal",
	"gss_unseal",
	"gss_display_status",
	"gss_indicate_mechs",
	"gss_compare_name",
	"gss_display_name",
	"gss_import_name",
	"gss_release_name",
	"gss_inquire_cred",
	"gss_add_cred",
	"gss_export_sec_context",
	"gss_import_sec_context",
	"gss_inquire_cred_by_mech",
	"gss_inquire_names_for_mech",
	"gss_inquire_context",
	"gss_internal_release_oid",
	"gss_wrap_size_limit",
	"pname_to_uid",
	"gss_duplicate_name",
	"gss_set_allowable_enctypes",
	"gss_verify_mic",
	NULL
};

#ifdef HAVE_KRB5
/*
 * The MIT code does not support the krb5_gss_initialize function, so
 * we need to locate the functions within the gssapi_krb5.so library
 * and fill in this structure.
 */
static struct gss_config mit_krb5_mechanism = {
	{9, "\052\206\110\206\367\022\001\002\002"},
	NULL,		/* mechanism context -- we don't currently use this */
	NULL,		/* gss_acquire_cred */
	NULL,		/* gss_release_cred */
	NULL,		/* gss_init_sec_context */
	NULL,		/* gss_accept_sec_context */
	NULL,		/* gss_process_context_token */
	NULL,		/* gss_delete_sec_context */
	NULL,		/* gss_context_time */
	NULL,		/* gss_sign */
	NULL,		/* gss_verify */
	NULL,		/* gss_seal */
	NULL,		/* gss_unseal */
	NULL,		/* gss_display_status */
	NULL,		/* gss_indicate_mechs */
	NULL,		/* gss_compare_name */
	NULL,		/* gss_display_name */
	NULL,		/* gss_import_name */
	NULL,		/* gss_release_name */
	NULL,		/* gss_inquire_cred */
	NULL,		/* gss_add_cred */
	NULL,		/* gss_export_sec_context */
	NULL,		/* gss_import_sec_context */
	NULL,		/* gss_inquire_cred_by_mech */
	NULL,		/* gss_inquire_names_for_mech */
	NULL,		/* gss_inquire_context */
	NULL,		/* gss_internal_release_oid */
	NULL,		/* gss_wrap_size_limit */
	NULL,		/* pname_to_uid */
	NULL,		/* gss_duplicate_name */
	NULL,		/* gss_set_allowable_enctypes */
	NULL,		/* gss_verify_mic */
};
#endif

#ifdef HAVE_HEIMDAL
/*
 * The heimdal code does not support the krb5_gss_initialize function, so
 * we need to locate the functions within the libgssapi.so library
 * and fill in this structure.
 */
static struct gss_config heimdal_krb5_mechanism = {
	{9, "\052\206\110\206\367\022\001\002\002"},
	NULL,		/* mechanism context -- we don't currently use this */
	NULL,		/* gss_acquire_cred */
	NULL,		/* gss_release_cred */
	NULL,		/* gss_init_sec_context */
	NULL,		/* gss_accept_sec_context */
	NULL,		/* gss_process_context_token */
	NULL,		/* gss_delete_sec_context */
	NULL,		/* gss_context_time */
	NULL,		/* gss_sign */
	NULL,		/* gss_verify */
	NULL,		/* gss_seal */
	NULL,		/* gss_unseal */
	NULL,		/* gss_display_status */
	NULL,		/* gss_indicate_mechs */
	NULL,		/* gss_compare_name */
	NULL,		/* gss_display_name */
	NULL,		/* gss_import_name */
	NULL,		/* gss_release_name */
	NULL,		/* gss_inquire_cred */
	NULL,		/* gss_add_cred */
	NULL,		/* gss_export_sec_context */
	NULL,		/* gss_import_sec_context */
	NULL,		/* gss_inquire_cred_by_mech */
	NULL,		/* gss_inquire_names_for_mech */
	NULL,		/* gss_inquire_context */
	NULL,		/* gss_internal_release_oid */
	NULL,		/* gss_wrap_size_limit */
	NULL,		/* pname_to_uid */
	NULL,		/* gss_duplicate_name */
	NULL,		/* gss_set_allowable_enctypes */
	NULL,		/* gss_verify_mic */
};
#endif


/*
 * Given a handle to a dynamic library (dl) and a symbol
 * name (symname), return its address.  Returns -1 if the
 * symbol cannot be located.  (Note that the value of the
 * symbol could be NULL, which is valid.)
 */
void *
locate_symbol(void *dl, char *symname, char *prefix)
{
	void *sym;
	const char *err_string;
	char fullname[256];

	snprintf(fullname, sizeof(fullname), "%s%s", prefix, symname);

	if ((sym = dlsym(dl, fullname)) == NULL) {
		if ((sym = dlsym(dl, symname)) == NULL) {
			if ((err_string = dlerror()) != NULL) {
				return (void *)-1;
			}
			else {
				return NULL;
			}
		}
	}
	return sym;
}

#ifdef HAVE_KRB5
/*
 * Locate all the symbols in the MIT gssapi library and
 * fill in the gss_config (gss_mechanism) structure.
 */
gss_mechanism
internal_krb5_gss_initialize(void *dl)
{
	char *fname;
	void *p;
	void **fptr;
	int i;
	static int mit_krb5_initialized = 0;

	if (mit_krb5_initialized)
		return (&mit_krb5_mechanism);

	fptr = (void *) &mit_krb5_mechanism.gss_acquire_cred;


	for (i = 0, fname = glue_func_names[i];
	     fname;
	     i++, fname = glue_func_names[i]) {
		if ((p = locate_symbol(dl, fname, "krb5_")) != (void *)-1) {
			*fptr++ = p;
		}
		else {
			*fptr++ = NULL;
		}
	}
	if (mit_krb5_mechanism.gss_internal_release_oid == NULL ||
	    mit_krb5_mechanism.gss_internal_release_oid == (void *) -1) {
	    fprintf(stderr, "WARNING: unable to locate function "
		"krb5_gss_internal_release_oid in krb5 mechanism library: "
		"there will be problems if multiple mechanisms are used!\n");
	    p = locate_symbol(dl, "krb5_gss_release_oid", "");
	    if (p == NULL || p == (void *) -1) {
		fprintf(stderr, "ERROR: Unable to locate function "
			"krb5_gss_internal_release_oid or "
			"krb5_gss_release_oid in krb5 mechanism library\n");
		return NULL;
	    }
	}
#ifdef HAVE_SET_ALLOWABLE_ENCTYPES
	/*
	 * Special case for set_allowable_enctypes which has a different
	 * name format than the rest of the gss routines :-/
	 */
	if ((p = locate_symbol(dl, "gss_krb5_set_allowable_enctypes", ""))
							!= (void *)-1) {
		mit_krb5_mechanism.gss_set_allowable_enctypes = p;
	}
#endif
	mit_krb5_initialized = 1;
	return (&mit_krb5_mechanism);
}
#endif

#ifdef HAVE_HEIMDAL
/*
 * Locate all the symbols in the MIT gssapi library and
 * fill in the gss_config (gss_mechanism) structure.
 */
gss_mechanism
internal_heimdal_gss_initialize(void *dl)
{
	char *fname;
	void *p;
	void **fptr;
	int i;
	static int heimdal_krb5_initialized = 0;

	if (heimdal_krb5_initialized)
		return (&heimdal_krb5_mechanism);

	fptr = (void *) &heimdal_krb5_mechanism.gss_acquire_cred;


	for (i = 0, fname = glue_func_names[i];
	     fname;
	     i++, fname = glue_func_names[i]) {
		if ((p = locate_symbol(dl, fname, "")) != (void *)-1) {
			*fptr++ = p;
		}
		else {
printf("Failed to locate function '%s' !!!\n", fname);
			*fptr++ = NULL;
		}
	}
	if (heimdal_krb5_mechanism.gss_internal_release_oid == NULL ||
	    heimdal_krb5_mechanism.gss_internal_release_oid == (void *) -1) {
	    fprintf(stderr, "WARNING: unable to locate function "
		"gss_internal_release_oid in krb5 mechanism library: "
		"there will be problems if multiple mechanisms are used!\n");
	    p = locate_symbol(dl, "krb5_gss_release_oid", "");
	    if (p == NULL || p == (void *) -1) {
		fprintf(stderr, "ERROR: Unable to locate function "
			"gss_internal_release_oid or "
			"gss_release_oid in krb5 mechanism library\n");
		return NULL;
	    }
	}
	heimdal_krb5_initialized = 1;
	return (&heimdal_krb5_mechanism);
}
#endif
