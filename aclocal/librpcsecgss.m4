dnl Checks for rpcsecgss library and headers
dnl KRB5LIBS must be set before this function is invoked.
dnl
AC_DEFUN([AC_LIBRPCSECGSS], [

  dnl Check for library, but do not add -lrpcsecgss to LIBS
  AC_CHECK_LIB([rpcsecgss], [authgss_create_default], [librpcsecgss=1],
               [AC_MSG_ERROR([librpcsecgss not found.])],
               [-lgssglue -ldl])

  AC_CHECK_LIB([rpcsecgss], [authgss_set_debug_level],
  	       [AC_DEFINE([HAVE_AUTHGSS_SET_DEBUG_LEVEL], 1,
               [Define to 1 if you have the `authgss_set_debug_level' function.])],,
               [-lgssglue -ldl])

])dnl
