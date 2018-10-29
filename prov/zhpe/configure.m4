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
    # Allow path to simulator headers to be specified
    AC_ARG_WITH(
      [zhpe-sim],
      [AS_HELP_STRING(
        [--with-zhpe-sim=@<:@Path to simulator headers@:>@],
        [Provide path to option simulator headers])],
      [zhpe_CPPFLAGS="$zhpe_CPPFLAGS -I$with_zhpe_sim -DHAVE_ZHPE_SIM"])
    # ummunotify needed for now to support registration cache
    AC_CHECK_HEADER(
      [linux/ummunotify.h],
      [zhpe_CPPFLAGS="$zhpe_CPPFLAGS -DHAVE_LINUX_UMMUNOTIFY_H"])
    zhpe_happy=1
    FI_CHECK_PACKAGE([zhpe], [zhpeq.h], [zhpeq], [zhpeq_alloc], [],
                     [$zhpe_PREFIX], [$zhpe_LIBDIR],, [zhpe_happy=0])
  ])
  AS_IF([test $zhpe_happy -eq 1], [$1], [$2])
])
