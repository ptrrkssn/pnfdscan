AC_PREREQ([2.71])
AC_INIT([pnfdscan],[1.1.2],[pen@lysator.liu.se],[pnfdscan],[https://github.com/ptrrkssn/pnfdscan])
AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_SRCDIR([pnfdscan.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_LN_S
AC_PROG_INSTALL
AC_PROG_MAKE_SET

PKG_CHECK_MODULES([ICU], [icu-uc], [],
  [AC_MSG_ERROR([icu-uc library is required but not found.])])
  
AC_SUBST(ICU_CFLAGS)
AC_SUBST(ICU_LIBS)

AC_SEARCH_LIBS([unorm2_isNormalized],[icuuc])

# Checks for header files.
AC_CHECK_HEADERS([unicode/utypes.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_FUNCS([strndup lstat])
AC_CHECK_FUNCS([])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
