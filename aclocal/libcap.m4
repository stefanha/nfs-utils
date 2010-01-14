dnl Checks for libcap.so
dnl
AC_DEFUN([AC_LIBCAP], [

  dnl look for prctl
  AC_CHECK_FUNC([prctl], , )

  dnl look for the library; do not add to LIBS if found
  AC_CHECK_LIB([cap], [cap_get_proc], [LIBCAP=-lcap], ,)
  AC_SUBST(LIBCAP)

  AC_CHECK_HEADERS([sys/capability.h], ,
                   [AC_MSG_ERROR([libcap headers not found.])])

])dnl
