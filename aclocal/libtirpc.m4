dnl Checks for TI-RPC library and headers
dnl
AC_DEFUN([AC_LIBTIRPC], [

  dnl if --enable-tirpc was specifed, the following components
  dnl must be present, and we set up HAVE_ macros for them.

  if test "$enable_tirpc" = yes; then

    dnl look for the library; add to LIBS if found
    AC_CHECK_LIB([tirpc], [clnt_tli_create], ,
                 [AC_MSG_ERROR([libtirpc not found.])])

    dnl also must have the headers installed where we expect
    AC_CHECK_HEADERS([tirpc/netconfig.h], ,
                     [AC_MSG_ERROR([libtirpc headers not found.])])

    dnl set up HAVE_FOO for various functions
    AC_CHECK_FUNCS([getnetconfig \
                    clnt_create clnt_create_timed \
                    clnt_vc_create clnt_dg_create xdr_rpcb])

  fi

])dnl
