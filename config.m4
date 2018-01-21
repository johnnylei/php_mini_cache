dnl $Id$
dnl config.m4 for extension mini_cache

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(mini_cache, for mini_cache support,
dnl Make sure that the comment is aligned:
[  --with-mini_cache             Include mini_cache support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(mini_cache, whether to enable mini_cache support,
dnl Make sure that the comment is aligned:
dnl [  --enable-mini_cache           Enable mini_cache support])

if test "$PHP_MINI_CACHE" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-mini_cache -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/mini_cache.h"  # you most likely want to change this
  dnl if test -r $PHP_MINI_CACHE/$SEARCH_FOR; then # path given as parameter
  dnl   MINI_CACHE_DIR=$PHP_MINI_CACHE
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for mini_cache files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       MINI_CACHE_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$MINI_CACHE_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the mini_cache distribution])
  dnl fi

  dnl # --with-mini_cache -> add include path
  dnl PHP_ADD_INCLUDE($MINI_CACHE_DIR/include)

  dnl # --with-mini_cache -> check for lib and symbol presence
  dnl LIBNAME=mini_cache # you may want to change this
  dnl LIBSYMBOL=mini_cache # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $MINI_CACHE_DIR/$PHP_LIBDIR, MINI_CACHE_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_MINI_CACHELIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong mini_cache lib version or lib not found])
  dnl ],[
  dnl   -L$MINI_CACHE_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  dnl PHP_SUBST(MINI_CACHE_SHARED_LIBADD)

  PHP_NEW_EXTENSION(mini_cache, mini_cache.c MiniCache.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi

if test -z "$PHP_DEBUG"; then
        AC_ARG_ENABLE(debug,
                [--enable-debg  compile with debugging system],
                [PHP_DEBUG=$enableval], [PHP_DEBUG=no]
        )
fi
