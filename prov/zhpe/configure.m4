dnl Configury specific to the libfabric zhpe provider

dnl Called to configure this provider
dnl
dnl Arguments:
dnl
dnl $1: action if configured successfully
dnl $2: action if not configured successfully
dnl
AC_DEFUN([FI_ZHPE_CONFIGURE],
[
  # Determine if we can support the zhpe provider
  zhpe_happy=0
  AS_IF([test x"$enable_zhpe" != x"no"],
  [
    zhpe_happy=1
    FI_CHECK_PACKAGE([zhpe], [zhpeq.h], [zhpeq], [zhpeq_alloc], [],
                     [$zhpe_PREFIX], [$zhpe_LIBDIR],, [zhpe_happy=0])
  ])
  AS_IF([test $zhpe_happy -eq 1], [$1], [$2])
])
