/*
  Copyright (c) 2004 The Regents of the University of Michigan.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. Neither the name of the University nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "config.h"
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_KRB5
#include <krb5.h>
#endif
#include <rpc/rpc.h>
#include <rpc/auth_gss.h>
#include "gss_util.h"
#include "gss_oids.h"
#include "err_util.h"
#include "context.h"

/* spkm3 seems to actually want it this big, yipes. */
#define MAX_CTX_LEN 4096

#ifdef HAVE_KRB5		/* MIT Kerberos */

#ifdef HAVE_LUCID_CONTEXT_SUPPORT

/* Don't use the private structure, use the exported lucid structure */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

#elif (KRB5_VERSION > 131)
/* XXX argggg, there's gotta be a better way than just duplicating this
 * whole struct.  Unfortunately, this is in a "private" header file,
 * so this is our best choice at this point :-/
 *
 * XXX Does this match the Heimdal definition?  */

typedef struct _krb5_gss_ctx_id_rec {
   unsigned int initiate : 1;   /* nonzero if initiating, zero if accepting */
   unsigned int established : 1;
   unsigned int big_endian : 1;
   unsigned int have_acceptor_subkey : 1;
   unsigned int seed_init : 1;  /* XXX tested but never actually set */
#ifdef CFX_EXERCISE
   unsigned int testing_unknown_tokid : 1; /* for testing only */
#endif
   OM_uint32 gss_flags;
   unsigned char seed[16];
   krb5_principal here;
   krb5_principal there;
   krb5_keyblock *subkey;
   int signalg;
   size_t cksum_size;
   int sealalg;
   krb5_keyblock *enc;
   krb5_keyblock *seq;
   krb5_timestamp endtime;
   krb5_flags krb_flags;
   /* XXX these used to be signed.  the old spec is inspecific, and
      the new spec specifies unsigned.  I don't believe that the change
      affects the wire encoding. */
   uint64_t seq_send;		/* gssint_uint64 */
   uint64_t seq_recv;		/* gssint_uint64 */
   void *seqstate;
   krb5_auth_context auth_context;
   gss_buffer_desc *mech_used;	/* gss_OID_desc */
    /* Protocol spec revision
       0 => RFC 1964 with 3DES and RC4 enhancements
       1 => draft-ietf-krb-wg-gssapi-cfx-01
       No others defined so far.  */
   int proto;
   krb5_cksumtype cksumtype;    /* for "main" subkey */
   krb5_keyblock *acceptor_subkey; /* CFX only */
   krb5_cksumtype acceptor_subkey_cksumtype;
#ifdef CFX_EXERCISE
    gss_buffer_desc init_token;
#endif
} krb5_gss_ctx_id_rec, *krb5_gss_ctx_id_t;

#else	/* KRB5_VERSION */

typedef struct _krb5_gss_ctx_id_rec {
	int initiate;
	u_int32_t gss_flags;
	int seed_init;
	unsigned char seed[16];
	krb5_principal here;
	krb5_principal there;
	krb5_keyblock *subkey;
	int signalg;
	int cksum_size;
	int sealalg;
	krb5_keyblock *enc;
	krb5_keyblock *seq;
	krb5_timestamp endtime;
	krb5_flags krb_flags;
	krb5_ui_4 seq_send;
	krb5_ui_4 seq_recv;
	void *seqstate;
	int established;
	int big_endian;
	krb5_auth_context auth_context;
	gss_buffer_desc *mech_used;
	int nctypes;
	krb5_cksumtype *ctypes;
} krb5_gss_ctx_id_rec, *krb5_gss_ctx_id_t;

#endif /* KRB5_VERSION */
#endif /* HAVE_KRB5 */

/* XXX We have the same issue as above.  We can require SPKM-3 source
 * at the time we compile gssd, or copy the context structure definitions
 * here.
 */

/* structure typedefs */

typedef struct spkm3_ctx_id_t {
    int length;
    unsigned char *data;
} spkm3_ctx_id,
 *spkm3_ctx_id_t;

/* first pass at spkm3 context. will add a bunch of stuff .... */

typedef struct spkm3_gss_ctx_id_desc_t {
    spkm3_ctx_id ctx_id;        /* per spkm token contextid */
    int established;
    int qop;                    /* negotiated qop */
    gss_OID mech_used;
    OM_uint32 ret_flags;
    OM_uint32 req_flags;
    /* DH should be abstracted to an EVP_ struct able to hold
     * various kalg results */
    /* XXX The following is defined as "DH *dh" in the original
     * header we're gonna cheat and use "void *dh" here. */
    void *dh;
    gss_buffer_desc share_key;
    /* derived keys are result from applying the owf_alg to the
     * shared key - see spkm3_derive_supkey */
    gss_buffer_desc derived_conf_key;
    gss_buffer_desc derived_integ_key;
    /* openssl NID's of the negotiated algorithms */
    int keyestb_alg;            /* key establishment */
    int owf_alg;                /* one way function */
    int intg_alg;               /* integrity */
    int conf_alg;               /* privacy */
    /* der encoded REQ_TOKEN reqcontets and length */
    unsigned char *der_reqcontents;
    int der_req_len;
} spkm3_gss_ctx_id_desc;


/* adapted from mit kerberos 5 ../lib/gssapi/mechglue/mglueP.h
 * this is what gets passed around when the mechglue code is enabled : */
typedef struct gss_union_ctx_id_t {
	gss_OID		mech_type;
	gss_ctx_id_t	internal_ctx_id;
} gss_union_ctx_id_desc, *gss_union_ctx_id_t;

#ifdef HAVE_KRB5		/* MIT Kerberos */
#ifdef HAVE_LUCID_CONTEXT_SUPPORT /* Lucid context support */
static int
write_lucid_keyblock(char **p, char *end, gss_krb5_lucid_key_t *key)
{
	gss_buffer_desc tmp;

	if (WRITE_BYTES(p, end, key->type)) return -1;
	tmp.length = key->length;
	tmp.value = key->data;
	if (write_buffer(p, end, &tmp)) return -1;
	return 0;
}

#else	/* lucid context support */

static int
write_keyblock(char **p, char *end, struct _krb5_keyblock *arg)
{
	gss_buffer_desc tmp;

	if (WRITE_BYTES(p, end, arg->enctype)) return -1;
	tmp.length = arg->length;
	tmp.value = arg->contents;
	if (write_buffer(p, end, &tmp)) return -1;
	return 0;
}
#endif	/* lucid context support */
#endif	/* HAVE_KRB5 */

#ifdef HAVE_KRB5
#ifdef HAVE_LUCID_CONTEXT_SUPPORT /* Lucid context support */
static int
prepare_krb5_rfc1964_buffer(gss_krb5_lucid_context_v1_t *lctx,
	gss_buffer_desc *buf)
{
	char *p, *end;
	static int constant_zero = 0;
	unsigned char fakeseed[16];
	uint32_t word_send_seq;
	gss_krb5_lucid_key_t enc_key;
	int i;
	char *skd, *dkd;
	gss_buffer_desc fakeoid;

	/*
	 * The new Kerberos interface to get the gss context
	 * does not include the seed or seed_init fields
	 * because we never really use them.  But for now,
	 * send down a fake buffer so we can use the same
	 * interface to the kernel.
	 */
	memset(&enc_key, 0, sizeof(enc_key));
	memset(&fakeoid, 0, sizeof(fakeoid));

	if (!(buf->value = calloc(1, MAX_CTX_LEN)))
		goto out_err;
	p = buf->value;
	end = buf->value + MAX_CTX_LEN;

	if (WRITE_BYTES(&p, end, lctx->initiate)) goto out_err;

	/* seed_init and seed not used by kernel anyway */
	if (WRITE_BYTES(&p, end, constant_zero)) goto out_err;
	if (write_bytes(&p, end, &fakeseed, 16)) goto out_err;

	if (WRITE_BYTES(&p, end, lctx->rfc1964_kd.sign_alg)) goto out_err;
	if (WRITE_BYTES(&p, end, lctx->rfc1964_kd.seal_alg)) goto out_err;
	if (WRITE_BYTES(&p, end, lctx->endtime)) goto out_err;
	word_send_seq = lctx->send_seq;	/* XXX send_seq is 64-bit */
	if (WRITE_BYTES(&p, end, word_send_seq)) goto out_err;
	if (write_buffer(&p, end, (gss_buffer_desc*)&krb5oid)) goto out_err;

	/* derive the encryption key and copy it into buffer */
	enc_key.type = lctx->rfc1964_kd.ctx_key.type;
	enc_key.length = lctx->rfc1964_kd.ctx_key.length;
	if ((enc_key.data = calloc(1, enc_key.length)) == NULL)
		goto out_err;
	skd = (char *) lctx->rfc1964_kd.ctx_key.data;
	dkd = (char *) enc_key.data;
	for (i = 0; i < enc_key.length; i++)
		dkd[i] = skd[i] ^ 0xf0;
	if (write_lucid_keyblock(&p, end, &enc_key)) {
		free(enc_key.data);
		goto out_err;
	}
	free(enc_key.data);

	if (write_lucid_keyblock(&p, end, &lctx->rfc1964_kd.ctx_key))
		goto out_err;

	buf->length = p - (char *)buf->value;
	return 0;
out_err:
	printerr(0, "ERROR: failed serializing krb5 context for kernel\n");
	if (buf->value) free(buf->value);
	buf->length = 0;
	if (enc_key.data) free(enc_key.data);
	return -1;
}

static int
prepare_krb5_rfc_cfx_buffer(gss_krb5_lucid_context_v1_t *lctx,
	gss_buffer_desc *buf)
{
	printerr(0, "ERROR: prepare_krb5_rfc_cfx_buffer: not implemented\n");
	return -1;
}

static int
serialize_krb5_ctx(gss_ctx_id_t ctx, gss_buffer_desc *buf)
{
	OM_uint32 maj_stat, min_stat;
	void *return_ctx = 0;
	OM_uint32 vers;
	gss_krb5_lucid_context_v1_t *lctx = 0;
	int retcode = 0;

	printerr(2, "DEBUG: serialize_krb5_ctx: lucid version!\n");
	maj_stat = gss_krb5_export_lucid_sec_context(&min_stat, &ctx,
						     1, &return_ctx);
	if (maj_stat != GSS_S_COMPLETE)
		goto out_err;

	/* Check the version returned, we only support v1 right now */
	vers = ((gss_krb5_lucid_context_version_t *)return_ctx)->version;
	switch (vers) {
	case 1:
		lctx = (gss_krb5_lucid_context_v1_t *) return_ctx;
		break;
	default:
		printerr(0, "ERROR: unsupported lucid sec context version %d\n",
			vers);
		goto out_err;
		break;
	}

	/* Now lctx points to a lucid context that we can send down to kernel */
	if (lctx->protocol == 0)
		retcode = prepare_krb5_rfc1964_buffer(lctx, buf);
	else
		retcode = prepare_krb5_rfc_cfx_buffer(lctx, buf);

	maj_stat = gss_krb5_free_lucid_sec_context(&min_stat,
						   (void *)lctx);
	if (maj_stat != GSS_S_COMPLETE)
		printerr(0, "WARN: failed to free lucid sec context\n");
	if (retcode)
		goto out_err;

	return 0;

out_err:
	printerr(0, "ERROR: failed serializing krb5 context for kernel\n");
	return -1;
}


#else /* lucid context support */

static int
serialize_krb5_ctx(gss_ctx_id_t ctx, gss_buffer_desc *buf)
{
	krb5_gss_ctx_id_t       kctx = (krb5_gss_ctx_id_t)ctx;
	char *p, *end;
	static int constant_one = 1;
	static int constant_zero = 0;
	uint32_t word_seq_send;

	if (!(buf->value = calloc(1, MAX_CTX_LEN)))
		goto out_err;
	p = buf->value;
	end = buf->value + MAX_CTX_LEN;

	if (kctx->initiate) {
		if (WRITE_BYTES(&p, end, constant_one)) goto out_err;
	}
	else {
		if (WRITE_BYTES(&p, end, constant_zero)) goto out_err;
	}
	if (kctx->seed_init) {
		if (WRITE_BYTES(&p, end, constant_one)) goto out_err;
	}
	else {
		if (WRITE_BYTES(&p, end, constant_zero)) goto out_err;
	}
	if (write_bytes(&p, end, &kctx->seed, sizeof(kctx->seed)))
		goto out_err;
	if (WRITE_BYTES(&p, end, kctx->signalg)) goto out_err;
	if (WRITE_BYTES(&p, end, kctx->sealalg)) goto out_err;
	if (WRITE_BYTES(&p, end, kctx->endtime)) goto out_err;
	word_seq_send = kctx->seq_send;
	if (WRITE_BYTES(&p, end, word_seq_send)) goto out_err;
	if (write_buffer(&p, end, kctx->mech_used)) goto out_err;
	if (write_keyblock(&p, end, kctx->enc)) goto out_err;
	if (write_keyblock(&p, end, kctx->seq)) goto out_err;

	buf->length = p - (char *)buf->value;
	return 0;
out_err:
	printerr(0, "ERROR: failed serializing krb5 context for kernel\n");
	if (buf->value) free(buf->value);
	buf->length = 0;
	return -1;
}
#endif /* lucid context support */
#endif /* HAVE_KRB5 */


/* ANDROS: need to determine which fields of the spkm3_gss_ctx_id_desc_t
 * are needed in the kernel for get_mic, validate, wrap, unwrap, and destroy
 * and only export those fields to the kernel.
 */
static int
serialize_spkm3_ctx(gss_ctx_id_t ctx, gss_buffer_desc *buf)
{
	spkm3_gss_ctx_id_desc      *sctx = (spkm3_gss_ctx_id_desc *)ctx;
	char *p, *end;

	printerr(1, "serialize_spkm3_ctx called\n");

	if (!(buf->value = calloc(1, MAX_CTX_LEN)))
		goto out_err;
	p = buf->value;
	end = buf->value + MAX_CTX_LEN;
/* buf->length
ctx_id 4 + 12
qop 4
mech_used 4 + 7
ret_fl  4
req_fl  4
share   4 + 16
conf_alg 4
d_conf_key 4 + 0
intg_alg 4
d_intg_key 4 + 0
kyestb 4
owl alg 4
*/
	if (write_buffer(&p, end, (gss_buffer_desc *)&sctx->ctx_id))
		goto out_err;
	if (WRITE_BYTES(&p, end, sctx->qop)) goto out_err;
	if (write_buffer(&p, end, (gss_buffer_desc *)sctx->mech_used)) goto out_err;
	if (WRITE_BYTES(&p, end, sctx->ret_flags)) goto out_err;
	if (WRITE_BYTES(&p, end, sctx->req_flags)) goto out_err;
	if (write_buffer(&p, end, &sctx->share_key))
		goto out_err;

	if (WRITE_BYTES(&p, end, sctx->conf_alg)) goto out_err;
	if (write_buffer(&p, end, &sctx->derived_conf_key))
		goto out_err;

	if (WRITE_BYTES(&p, end, sctx->intg_alg)) goto out_err;
	if (write_buffer(&p, end, &sctx->derived_integ_key))
		goto out_err;

	if (WRITE_BYTES(&p, end, sctx->keyestb_alg)) goto out_err;
	if (WRITE_BYTES(&p, end, sctx->owf_alg)) goto out_err;

	buf->length = p - (char *)buf->value;
	return 0;
out_err:
	if (buf->value) free(buf->value);
	buf->length = 0;
	return -1;
}

int
serialize_context_for_kernel(gss_ctx_id_t ctx, gss_buffer_desc *buf)
{
	gss_union_ctx_id_t      uctx = (gss_union_ctx_id_t)ctx;

	if (g_OID_equal(&krb5oid, uctx->mech_type))
		return serialize_krb5_ctx(uctx->internal_ctx_id, buf);
	else if (g_OID_equal(&spkm3oid, uctx->mech_type))
		return serialize_spkm3_ctx(uctx->internal_ctx_id, buf);
	else {
		printerr(0, "ERROR: attempting to serialize context with "
				"unknown mechanism oid\n");
		return -1;
	}
}
