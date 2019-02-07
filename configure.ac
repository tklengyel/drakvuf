#********************IMPORTANT DRAKVUF LICENSE TERMS**********************#
#                                                                         #
# DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  #
# Tamas K Lengyel is hereinafter referred to as the author.               #
# This program is free software; you may redistribute and/or modify it    #
# under the terms of the GNU General Public License as published by the   #
# Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   #
# CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   #
# right to use, modify, and redistribute this software under certain      #
# conditions.  If you wish to embed DRAKVUF technology into proprietary   #
# software, alternative licenses can be aquired from the author.          #
#                                                                         #
# Note that the GPL places important restrictions on "derivative works",  #
# yet it does not provide a detailed definition of that term.  To avoid   #
# misunderstandings, we interpret that term as broadly as copyright law   #
# allows.  For example, we consider an application to constitute a        #
# derivative work for the purpose of this license if it does any of the   #
# following with any software or content covered by this license          #
# ("Covered Software"):                                                   #
#                                                                         #
# o Integrates source code from Covered Software.                         #
#                                                                         #
# o Reads or includes copyrighted data files.                             #
#                                                                         #
# o Is designed specifically to execute Covered Software and parse the    #
# results (as opposed to typical shell or execution-menu apps, which will #
# execute anything you tell them to).                                     #
#                                                                         #
# o Includes Covered Software in a proprietary executable installer.  The #
# installers produced by InstallShield are an example of this.  Including #
# DRAKVUF with other software in compressed or archival form does not     #
# trigger this provision, provided appropriate open source decompression  #
# or de-archiving software is widely available for no charge.  For the    #
# purposes of this license, an installer is considered to include Covered #
# Software even if it actually retrieves a copy of Covered Software from  #
# another source during runtime (such as by downloading it from the       #
# Internet).                                                              #
#                                                                         #
# o Links (statically or dynamically) to a library which does any of the  #
# above.                                                                  #
#                                                                         #
# o Executes a helper program, module, or script to do any of the above.  #
#                                                                         #
# This list is not exclusive, but is meant to clarify our interpretation  #
# of derived works with some common examples.  Other people may interpret #
# the plain GPL differently, so we consider this a special exception to   #
# the GPL that we apply to Covered Software.  Works which meet any of     #
# these conditions must conform to all of the terms of this license,      #
# particularly including the GPL Section 3 requirements of providing      #
# source code and allowing free redistribution of the work as a whole.    #
#                                                                         #
# Any redistribution of Covered Software, including any derived works,    #
# must obey and carry forward all of the terms of this license, including #
# obeying all GPL rules and restrictions.  For example, source code of    #
# the whole work must be provided and free redistribution must be         #
# allowed.  All GPL references to "this License", are to be treated as    #
# including the terms and conditions of this license text as well.        #
#                                                                         #
# Because this license imposes special exceptions to the GPL, Covered     #
# Work may not be combined (even as part of a larger work) with plain GPL #
# software.  The terms, conditions, and exceptions of this license must   #
# be included as well.  This license is incompatible with some other open #
# source licenses as well.  In some cases we can relicense portions of    #
# DRAKVUF or grant special permissions to use it in other open source     #
# software.  Please contact tamas.k.lengyel@gmail.com with any such       #
# requests.  Similarly, we don't incorporate incompatible open source     #
# software into Covered Software without special permission from the      #
# copyright holders.                                                      #
#                                                                         #
# If you have any questions about the licensing restrictions on using     #
# DRAKVUF in other works, are happy to help.  As mentioned above,         #
# alternative license can be requested from the author to integrate       #
# DRAKVUF into proprietary applications and appliances.  Please email     #
# tamas.k.lengyel@gmail.com for further information.                      #
#                                                                         #
# If you have received a written license agreement or contract for        #
# Covered Software stating terms other than these, you may choose to use  #
# and redistribute Covered Software under those terms instead of these.   #
#                                                                         #
# Source is provided to this software because we believe users have a     #
# right to know exactly what a program is going to do before they run it. #
# This also allows you to audit the software for security holes.          #
#                                                                         #
# Source code also allows you to port DRAKVUF to new platforms, fix bugs, #
# and add new features.  You are highly encouraged to submit your changes #
# on https://github.com/tklengyel/drakvuf, or by other methods.           #
# By sending these changes, it is understood (unless you specify          #
# otherwise) that you are offering unlimited, non-exclusive right to      #
# reuse, modify, and relicense the code.  DRAKVUF will always be          #
# available Open Source, but this is important because the inability to   #
# relicense code has caused devastating problems for other Free Software  #
# projects (such as KDE and NASM).                                        #
# To specify special license conditions of your contributions, just say   #
# so when you send them.                                                  #
#                                                                         #
# This program is distributed in the hope that it will be useful, but     #
# WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   #
# license file for more details (it's in a COPYING file included with     #
# DRAKVUF, and also available from                                        #
# https://github.com/tklengyel/drakvuf/COPYING)                           #
#                                                                         #
#*************************************************************************#

AC_PREREQ([2.60])
AC_INIT([DRAKVUF], [0.6-m4_esyscmd_s([git describe --always])], [tamas@tklengyel.com], [], [https://drakvuf.com])
AM_INIT_AUTOMAKE([1.10 no-define foreign subdir-objects])
LT_INIT
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC_STDC
AC_PROG_CXX(clang++)
AX_REQUIRE_DEFINED([AX_CXX_COMPILE_STDCXX_11])
AX_CXX_COMPILE_STDCXX_11

######################################################

AC_ARG_ENABLE([plugin_syscalls],
  [AS_HELP_STRING([--disable-plugin-syscalls],
    [Enable the syscall tracing plugin @<:@yes@:>@])],
  [plugin_syscalls="$enableval"],
  [plugin_syscalls="yes"])
AM_CONDITIONAL([PLUGIN_SYSCALLS], [test x$plugin_syscalls = xyes])
if test x$plugin_syscalls = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_SYSCALLS, 1, "")
fi

AC_ARG_ENABLE([plugin_poolmon],
  [AS_HELP_STRING([--disable-plugin-poolmon],
    [Enable the kernel heap allocation tracer @<:@yes@:>@])],
  [plugin_poolmon="$enableval"],
  [plugin_poolmon="yes"])
AM_CONDITIONAL([PLUGIN_POOLMON], [test x$plugin_poolmon = xyes])
if test x$plugin_poolmon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_POOLMON, 1, "")
fi

AC_ARG_ENABLE([plugin_filetracer],
  [AS_HELP_STRING([--disable-plugin-filetracer],
    [Enable the file tracer plugin @<:@yes@:>@])],
  [plugin_filetracer="$enableval"],
  [plugin_filetracer="yes"])
AM_CONDITIONAL([PLUGIN_FILETRACER], [test x$plugin_filetracer = xyes])
if test x$plugin_filetracer = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_FILETRACER, 1, "")
fi

AC_ARG_ENABLE([plugin_filedelete],
  [AS_HELP_STRING([--disable-plugin-filedelete],
    [Enable the file delete catching plugin @<:@yes@:>@])],
  [plugin_filedelete="$enableval"],
  [plugin_filedelete="yes"])
AM_CONDITIONAL([PLUGIN_FILEDELETE], [test x$plugin_filedelete = xyes])
if test x$plugin_filedelete = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_FILEDELETE, 1, "")
fi

AC_ARG_ENABLE([plugin_objmon],
  [AS_HELP_STRING([--disable-plugin-objmon],
    [Enable the ObCreateObject watching plugin @<:@yes@:>@])],
  [plugin_objmon="$enableval"],
  [plugin_objmon="yes"])
AM_CONDITIONAL([PLUGIN_OBJMON], [test x$plugin_objmon = xyes])
if test x$plugin_objmon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_OBJMON, 1, "")
fi

AC_ARG_ENABLE([plugin_exmon],
  [AS_HELP_STRING([--disable-plugin-exmon],
    [Enable the KiDispatchException watching plugin @<:@yes@:>@])],
  [plugin_exmon="$enableval"],
  [plugin_exmon="yes"])
AM_CONDITIONAL([PLUGIN_EXMON], [test x$plugin_exmon = xyes])
if test x$plugin_exmon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_EXMON, 1, "")
fi

AC_ARG_ENABLE([plugin_ssdtmon],
  [AS_HELP_STRING([--disable-plugin-ssdtmon],
    [Enable the KiServiceTable watching plugin @<:@yes@:>@])],
  [plugin_ssdtmon="$enableval"],
  [plugin_ssdtmon="yes"])
AM_CONDITIONAL([PLUGIN_SSDTMON], [test x$plugin_ssdtmon = xyes])
if test x$plugin_ssdtmon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_SSDTMON, 1, "")
fi

AC_ARG_ENABLE([plugin_debugmon],
  [AS_HELP_STRING([--disable-plugin-debugmon],
    [Enable the debug exception watching plugin @<:@yes@:>@])],
  [plugin_debugmon="$enableval"],
  [plugin_debugmon="yes"])
AM_CONDITIONAL([PLUGIN_DEBUGMON], [test x$plugin_debugmon = xyes])
if test x$plugin_debugmon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_DEBUGMON, 1, "")
fi

AC_ARG_ENABLE([plugin_delaymon],
  [AS_HELP_STRING([--disable-plugin-delaymon],
    [Enable the debug exception watching plugin @<:@yes@:>@])],
  [plugin_delaymon="$enableval"],
  [plugin_delaymon="yes"])
AM_CONDITIONAL([PLUGIN_DELAYMON], [test x$plugin_delaymon = xyes])
if test x$plugin_delaymon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_DELAYMON, 1, "")
fi

AC_ARG_ENABLE([plugin_cpuidmon],
  [AS_HELP_STRING([--disable-plugin-cpuidmon],
    [Enable the CPUID watching plugin @<:@yes@:>@])],
  [plugin_cpuidmon="$enableval"],
  [plugin_cpuidmon="yes"])
AM_CONDITIONAL([PLUGIN_CPUIDMON], [test x$plugin_cpuidmon = xyes])
if test x$plugin_cpuidmon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_CPUIDMON, 1, "")
fi

AC_ARG_ENABLE([plugin_socketmon],
  [AS_HELP_STRING([--disable-plugin-socketmon],
    [Enable the network socket watching plugin @<:@yes@:>@])],
  [plugin_socketmon="$enableval"],
  [plugin_socketmon="yes"])
AM_CONDITIONAL([PLUGIN_SOCKETMON], [test x$plugin_socketmon = xyes])
if test x$plugin_socketmon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_SOCKETMON, 1, "")
fi

AC_ARG_ENABLE([plugin_regmon],
  [AS_HELP_STRING([--disable-plugin-regmon],
    [Enable the windows registry watching plugin @<:@yes@:>@])],
  [plugin_regmon="$enableval"],
  [plugin_regmon="yes"])
AM_CONDITIONAL([PLUGIN_REGMON], [test x$plugin_regmon = xyes])
if test x$plugin_regmon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_REGMON, 1, "")
fi

AC_ARG_ENABLE([plugin_procmon],
  [AS_HELP_STRING([--disable-plugin-procmon],
    [Enable the windows process lifecycle watching plugin @<:@yes@:>@])],
  [plugin_procmon="$enableval"],
  [plugin_procmon="yes"])
AM_CONDITIONAL([PLUGIN_PROCMON], [test x$plugin_procmon = xyes])
if test x$plugin_procmon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_PROCMON, 1, "")
fi

AC_ARG_ENABLE([plugin_bsodmon],
  [AS_HELP_STRING([--disable-plugin-bsodmon],
    [Enable the windows kernel bugcheck watching plugin @<:@yes@:>@])],
  [plugin_bsodmon="$enableval"],
  [plugin_bsodmon="yes"])
AM_CONDITIONAL([PLUGIN_BSODMON], [test x$plugin_bsodmon = xyes])
if test x$plugin_bsodmon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_BSODMON, 1, "")
fi

AC_ARG_ENABLE([plugin_crashmon],
  [AS_HELP_STRING([--disable-plugin-crashmon],
    [Enable the windows error reporting tool WerFault.exe watching plugin @<:@yes@:>@])],
  [plugin_crashmon="$enableval"],
  [plugin_crashmon="yes"])
AM_CONDITIONAL([PLUGIN_CRASHMON], [test x$plugin_crashmon = xyes])
if test x$plugin_crashmon = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_PLUGIN_CRASHMON, 1, "")
fi

#####################################################

AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--enable-hardening],
    [Enable compiler and linker options to frustrate memory corruption exploits @<:@yes@:>@])],
  [hardening="$enableval"],
  [hardening="yes"])
AM_CONDITIONAL([HARDENING], [test x$hardening = xyes])

AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug],
    [Enable verbose debug output to be compiled @<:@no@:>@])],
  [debug="$enableval"],
  [debug="no"])
AM_CONDITIONAL([DEBUG], [test x$debug = xyes])

AC_ARG_ENABLE([doppelganging],
  [AS_HELP_STRING([--enable-doppelganging-injection],
    [Enable doppelganging injection @<:@no@:>@])],
  [doppelganging="$enableval"],
  [doppelganging="no"])
if test x$doppelganging = xyes; then
  AC_DEFINE_UNQUOTED(ENABLE_DOPPELGANGING, 1, "")
fi

AC_ARG_WITH([stdlib],
  [AS_HELP_STRING([--with-stdlib=LIB], [specify the C++ standard library to use [default=system]])],
  [], [with_stdlib=system])
AS_IF([test "x$with_stdlib" != "xsystem"],
  [CXXFLAGS="$CXXFLAGS -stdlib=$with_stdlib"])

#####################################################
# AUTOHARDEN START
# We want to check for compiler flag support, but there is no way to make
# clang's "argument unused" warning fatal.  So we invoke the compiler through a
# wrapper script that greps for this message.
saved_CC="$CC"
saved_CXX="$CXX"
saved_LD="$LD"
flag_wrap="$srcdir/scripts/wrap-compiler-for-flag-check"
CC="$flag_wrap $CC"
CXX="$flag_wrap $CXX"
LD="$flag_wrap $LD"

# We use the same hardening flags for C and C++.  We must check that each flag
# is supported by both compilers.
AC_DEFUN([check_cc_cxx_flag],
 [AC_LANG_PUSH(C)
  AX_CHECK_COMPILE_FLAG([$1],
   [AC_LANG_PUSH(C++)
    AX_CHECK_COMPILE_FLAG([$1], [$2], [$3], [-Werror $4])
    AC_LANG_POP(C++)],
   [$3], [-Werror $4])
  AC_LANG_POP(C)])
AC_DEFUN([check_link_flag],
 [AX_CHECK_LINK_FLAG([$1], [$2], [$3], [-Werror $4])])

HARDEN_CFLAGS=""
HARDEN_LDFLAGS=""
AS_IF([test x"$hardening" != x"no"], [
  check_cc_cxx_flag([-fno-strict-overflow], [HARDEN_CFLAGS="$HARDEN_CFLAGS -fno-strict-overflow"])

# This one will likely succeed, even on platforms where it does nothing.
  check_cc_cxx_flag([-D_FORTIFY_SOURCE=2], [HARDEN_CFLAGS="$HARDEN_CFLAGS -D_FORTIFY_SOURCE=2"])

  check_cc_cxx_flag([-fstack-protector-all],
   [check_link_flag([-fstack-protector-all],
     [HARDEN_CFLAGS="$HARDEN_CFLAGS -fstack-protector-all"
      check_cc_cxx_flag([-Wstack-protector], [HARDEN_CFLAGS="$HARDEN_CFLAGS -Wstack-protector"],
        [], [-fstack-protector-all])
      check_cc_cxx_flag([--param ssp-buffer-size=1], [HARDEN_CFLAGS="$HARDEN_CFLAGS --param ssp-buffer-size=1"],
        [], [-fstack-protector-all])])])

  # At the link step, we might want -pie (GCC) or -Wl,-pie (Clang on OS X)
  #
  # The linker checks also compile code, so we need to include -fPIE as well.
  check_cc_cxx_flag([-fPIE],
   [check_link_flag([-fPIE -pie],
     [HARDEN_CFLAGS="$HARDEN_CFLAGS -fPIE"
      HARDEN_LDFLAGS="$HARDEN_LDFLAGS -pie"],
     [check_link_flag([-fPIE -Wl,-pie],
       [HARDEN_CFLAGS="$HARDEN_CFLAGS -fPIE"
        HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-pie"])])])

  check_link_flag([-Wl,-z,relro],
   [HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-z,relro"
    check_link_flag([-Wl,-z,now], [HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-z,now"])])])

AC_SUBST([HARDEN_CFLAGS])
AC_SUBST([HARDEN_LDFLAGS])

# End of flag tests.
CC="$saved_CC"
CXX="$saved_CXX"
LD="$saved_LD"
# AUTOHARDEN END
#####################################################

AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h malloc.h stdio.h stdlib.h string.h sys/time.h sys/mman.h sys/inotify.h syslog.h unistd.h errno.h pthread.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_MALLOC

# Make sure we get standard PRI... definitions.
AH_VERBATIM([__STDC_FORMAT_MACROS],
            [/* C99 says: define this to get the PRI... macros from stdint.h */
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS 1
#endif])

AC_CHECK_LIB(pthread, pthread_create, [], [AC_ERROR([Pthread library is not functional!])])

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.28], [], [AC_ERROR([glib-2.0 (version 2.28+) has to be installed!])])
AC_CHECK_LIB(glib-2.0, [g_malloc0, g_tree_lookup], [], [AC_ERROR([glib-2.0 library is not functional!])]) 

PKG_CHECK_MODULES([VMI], [libvmi >= 0.11], [], [AC_ERROR([LibVMI not found])])
AC_CHECK_HEADERS([libvmi/events.h], [], [AC_ERROR([LibVMI doesn't have events support.])], [#include <libvmi/libvmi.h>])
AC_CHECK_LIB(vmi, [vmi_register_event], [], [AC_ERROR([LibVMI doesn't have required events support. Please update LibVMI!])])
AC_CHECK_LIB(vmi, [vmi_events_version], [], [AC_ERROR([LibVMI doesn't have required events support. Please update LibVMI!])])

AC_CHECK_LIB(json-c, json_object_get_int64,, [AC_ERROR([libjson-c-dev is missing])])
AC_CHECK_HEADERS([json-c/json.h], [], [AC_ERROR([libjson-c-dev is missing])])

AC_CHECK_LIB([xencall], [xencall_buffers_never_fault])
AC_CHECK_LIB([xenforeignmemory], [xenforeignmemory_map_resource])

#AC_CHECK_HEADER([xenstore.h])
#AC_CHECK_LIB(xenstore, [xc_read, xs_transaction_start], [], [AC_ERROR([Xenstore not found!])])

# Check for Xenctrl
AC_CHECK_HEADERS([xenctrl.h], [], [AC_ERROR([XenCtrl missing! Did you install Xen yet?])])
AC_CHECK_LIB([xenctrl],
	[xc_interface_open, xc_monitor_debug_exceptions],
	[], [AC_ERROR([XenCtrl is unusable! Do you have Xen 4.7 installed?])])

# Check for memsharing
AC_CHECK_LIB([xenctrl],
	[xc_memshr_control, xc_memshr_nominate_gfn, xc_memshr_share_gfns],
	[], [AC_ERROR([XenCtrl is unusable! Do you have Xen 4.2+ installed?])])

AC_CHECK_HEADERS([libxl_utils.h], [], [AC_ERROR([Xenlight (libxl) headers are not usable])])
AC_CHECK_LIB(xenlight, libxl_name_to_domid, [], [AC_ERROR([Xenlight does not have required features!])])

AC_CHECK_LIB([xentoollog], [xtl_logger_destroy])

#####################################################

AC_CONFIG_FILES([Makefile src/Makefile
                 src/libdrakvuf/Makefile
                 src/libinjector/Makefile
                 src/xen_helper/Makefile
                 src/plugins/Makefile
                 src/dirwatch/Makefile
               ])

AC_OUTPUT

AC_MSG_RESULT([-------------------------------------------------------------------------------
DRAKVUF is configured as follows. Please verify that this configuration
matches your expectations.

Host system type: $host
Build system type: $build
Installation prefix: $prefix
-------------------------------------------------------------------------------
DRAKVUF Plugins
Syscalls:   $plugin_syscalls
Poolmon:    $plugin_poolmon
Filetracer: $plugin_filetracer
Filedelete: $plugin_filedelete
Objmon:     $plugin_objmon
Exmon:      $plugin_exmon
SSDTmon:    $plugin_ssdtmon
CPUIDmon:   $plugin_cpuidmon
Debugmon:   $plugin_debugmon
Socketmon:  $plugin_socketmon
Regmon:     $plugin_regmon
Procmon:    $plugin_procmon
BSODmon:    $plugin_bsodmon
CrashMon:   $plugin_crashmon
-------------------------------------------------------------------------------])
