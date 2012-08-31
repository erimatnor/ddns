AC_INIT([ddns], [0.1], [erik.nordstrom@gmail.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Use the silent-rules feature when possible.
m4_ifndef([AM_SILENT_RULES], [m4_define([AM_SILENT_RULES],[])])
AM_SILENT_RULES([yes])

AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_HEADERS([src/config.h])
AM_PROG_AR
LT_INIT

# Set some sane default compiler flags
CFLAGS="-Wall"
CXXFLAGS="-Wall"
EXTRA_DEFINES=

platform_result=no

AC_MSG_CHECKING([for Linux])
case $host in
  *-*-linux*)
	platform=linux
	platform_result=yes
	;;
esac

AC_MSG_RESULT([$platform_result])

AC_MSG_CHECKING([for Mac OS X])
case $host in
  *-*-darwin*)
  	platform=macosx
	platform_result=yes
	AC_DEFINE(OS_MACOSX, [1], [Mac OS X])
	;;
esac
AC_MSG_RESULT([$platform_result])

AM_CONDITIONAL([OS_LINUX], [test x$platform = xlinux])
AM_CONDITIONAL([OS_MACOSX], [test x$platform = xmacosx])

dnl Option to set debugging
AC_ARG_ENABLE([debug],
AS_HELP_STRING([--enable-debug],[Turn on debugging]),
[case "${enableval}" in
  yes) debug=yes ;;
  no)  debug=no ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],[debug=no])

AM_CONDITIONAL([DEBUG], [test x$debug = xyes])

if test x$debug = xyes
then      
     CPPFLAGS="$CPPFLAGS -DENABLE_DEBUG"
     CFLAGS="$CFLAGS -g -O0 -fno-inline"  
     CXXFLAGS="$CXXFLAGS -g -O0 -fno-inline"
else
     CFLAGS="$CFLAGS -O2"  
     CXXFLAGS="$CXXFLAGS -O2"
fi

AC_ARG_WITH([csocket],
            [AS_HELP_STRING([--with-csocket=DIR],
              [Path to csocket library])],
            [csocket_path=$withval],
            [csocket_path=])

AC_MSG_CHECKING([for csocket library])

csocketdirs="$csocket_path /usr/local /opt/local /usr"
found=false

if ! $found; then
    CSOCKET_INCLUDES=
    for dir in $csocketdirs; do
        AC_MSG_CHECKING([for csocket/socket.h in $dir])
        if test -f "$dir/include/csocket/socket.h"; then
            CSOCKET_INCLUDES="-I$dir/include"
            CSOCKET_LDFLAGS="-L$dir/lib"
            CSOCKET_LIBS="-lcsocket"
            found=true
            AC_MSG_RESULT([yes])
            break
        else
            AC_MSG_RESULT([no])
        fi
    done
fi

AC_MSG_RESULT([$found])

if ! $found; then
   AC_MSG_ERROR([csocket library not found. Please install from https://github.com/erimatnor/csocket.])
fi

AC_SUBST([CSOCKET_INCLUDES])
AC_SUBST([CSOCKET_LIBS])
AC_SUBST([CSOCKET_LDFLAGS])

AX_CHECK_OPENSSL([have_openssl=yes], [have_openssl=no])
AM_CONDITIONAL([HAVE_OPENSSL], [test x$have_openssl = xyes])

if test x$have_openssl = xyes
then
        AC_DEFINE([HAVE_OPENSSL], [1], [OpenSSL])
else
        AC_DEFINE([HAVE_OPENSSL], [0], [OpenSSL])
fi

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT

echo
echo "Enable debug output.......................$debug"
