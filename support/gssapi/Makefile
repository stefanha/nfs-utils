#
# libgssapi.a
# gssapi mechanism-switching layer
#

LIBNAME	= libgssapi.a
SRCS	= g_accept_sec_context.c g_acquire_cred.c g_compare_name.c \
	g_context_time.c g_delete_sec_context.c g_dsp_name.c g_dsp_status.c \
	g_dup_name.c gen_oids.c g_exp_sec_context.c g_glue.c g_imp_name.c \
	g_imp_sec_context.c g_indicate_mechs.c g_initialize.c \
	g_init_sec_context.c g_inq_context.c g_inq_cred.c g_inq_names.c \
	g_mechname.c g_mit_krb5_mech.c g_oid_ops.c g_process_context.c \
	g_rel_buffer.c g_rel_cred.c g_rel_name.c g_rel_oid_set.c g_seal.c \
	g_sign.c gssd_pname_to_uid.c g_unseal.c g_verify.c oid_ops.c \
	g_set_allowable_enctypes.c

OBJS	= $(SRCS:.c=.o)

include $(TOP)rules.mk

CFLAGS += -DKRB5_VERSION=$(KRB5_VERSION) -I$(TOP)/support/include

install::
	@:
