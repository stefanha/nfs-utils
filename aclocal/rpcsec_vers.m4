dnl Checks librpcsec version
AC_DEFUN([AC_RPCSEC_VERSION], [

  dnl TI-RPC replaces librpcsecgss
  if test "$enable_tirpc" = no; then
    PKG_CHECK_MODULES([RPCSECGSS], [librpcsecgss >= 0.16], ,
                      [AC_MSG_ERROR([Unable to locate information required to use librpcsecgss.  If you have pkgconfig installed, you might try setting environment variable PKG_CONFIG_PATH to /usr/local/lib/pkgconfig])])
  fi

  PKG_CHECK_MODULES([GSSGLUE], [libgssglue >= 0.1])

])dnl
