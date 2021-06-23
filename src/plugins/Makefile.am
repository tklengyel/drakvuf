#********************IMPORTANT DRAKVUF LICENSE TERMS**********************#
#                                                                         #
# DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  #
# Tamas K Lengyel is hereinafter referred to as the author.               #
# This program is free software; you may redistribute and/or modify it    #
# under the terms of the GNU General Public License as published by the   #
# Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   #
# CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   #
# right to use, modify, and redistribute this software under certain      #
# conditions.  If you wish to embed DRAKVUF technology into proprietary   #
# software, alternative licenses can be acquired from the author.         #
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

sources =

###############################################################################

if PLUGIN_SYSCALLS
sources += syscalls/syscalls.cpp
sources += syscalls/syscalls.h
sources += syscalls/linux.cpp
sources += syscalls/linux.h
sources += syscalls/win.cpp
sources += syscalls/win.h
sources += syscalls/private.h
endif

if PLUGIN_POOLMON
sources += poolmon/poolmon.cpp
sources += poolmon/poolmon.h
sources += poolmon/private.h
endif

if PLUGIN_FILETRACER
sources += filetracer/filetracer.cpp
sources += filetracer/filetracer.h
sources += filetracer/private.h
sources += filetracer/linux.cpp
sources += filetracer/linux.h
sources += filetracer/win.cpp
sources += filetracer/win.h
sources += filetracer/win_acl.cpp
sources += filetracer/win_acl.h
endif

if PLUGIN_FILEDELETE
sources += filedelete/filedelete.cpp
sources += filedelete/filedelete.h
sources += filedelete/private.h
sources += filedelete/filedelete2_helpers.cpp
endif

if PLUGIN_OBJMON
sources += objmon/objmon.cpp
sources += objmon/objmon.h
endif

if PLUGIN_EXMON
sources += exmon/exmon.cpp
sources += exmon/exmon.h
sources += exmon/private.h
endif

if PLUGIN_SSDTMON
sources += ssdtmon/ssdtmon.cpp
sources += ssdtmon/ssdtmon.h
sources += ssdtmon/private.h
endif

if PLUGIN_DEBUGMON
sources += debugmon/debugmon.cpp
sources += debugmon/debugmon.h
sources += debugmon/private.h
endif

if PLUGIN_DELAYMON
sources += delaymon/delaymon.cpp
sources += delaymon/delaymon.h
endif

if PLUGIN_CPUIDMON
sources += cpuidmon/cpuidmon.cpp
sources += cpuidmon/cpuidmon.h
sources += cpuidmon/private.h
endif

if PLUGIN_SOCKETMON
sources += socketmon/socketmon.cpp
sources += socketmon/socketmon.h
sources += socketmon/private.h
endif

if PLUGIN_REGMON
sources += regmon/regmon.cpp
sources += regmon/regmon.h
endif

if PLUGIN_PROCMON
sources += procmon/procmon.cpp
sources += procmon/procmon.h
sources += procmon/winnt.cpp
sources += procmon/winnt.h
sources += procmon/privileges.cpp
sources += procmon/privileges.h
endif

if PLUGIN_BSODMON
sources += bsodmon/bsodmon.cpp
sources += bsodmon/bsodmon.h
sources += bsodmon/private.h
sources += bsodmon/bugcheck.cpp
sources += bsodmon/bugcheck.h
endif

if PLUGIN_ENVMON
sources += envmon/envmon.cpp
sources += envmon/envmon.h
sources += envmon/private.h
endif

if PLUGIN_CRASHMON
sources += crashmon/crashmon.cpp
sources += crashmon/crashmon.h
endif

if PLUGIN_CLIPBOARDMON
sources += clipboardmon/clipboardmon.cpp
sources += clipboardmon/clipboardmon.h
endif

if PLUGIN_WINDOWMON
sources += windowmon/windowmon.cpp
sources += windowmon/windowmon.h
endif

if PLUGIN_LIBRARYMON
sources += librarymon/librarymon.cpp
sources += librarymon/librarymon.h
endif

if PLUGIN_DKOMMON
sources += dkommon/dkommon.cpp
sources += dkommon/dkommon.h
endif

if PLUGIN_WMIMON
sources += wmimon/wmimon.cpp
sources += wmimon/wmimon.h
sources += wmimon/private.h
endif

if PLUGIN_MEMDUMP
sources += memdump/memdump.cpp
sources += memdump/memdump.h
sources += memdump/private.h
sources += memdump/stack_util.cpp
sources += memdump/userhook.cpp
endif

if PLUGIN_APIMON
sources += apimon/apimon.cpp
sources += apimon/apimon.h
sources += apimon/crypto.cpp
sources += apimon/crypto.h
endif

if PLUGIN_PROCDUMP
sources += procdump/procdump.cpp
sources += procdump/procdump.h
sources += procdump/private.h
sources += procdump/writer.cpp
sources += procdump/writer.h
sources += procdump/minidump.h
endif

if PLUGIN_RPCMON
sources += rpcmon/rpcmon.cpp
sources += rpcmon/rpcmon.h
sources += rpcmon/private.h
endif

if PLUGIN_TLSMON
sources += tlsmon/tlsmon.cpp
sources += tlsmon/tlsmon.h
sources += tlsmon/private.h
endif

if PLUGIN_CODEMON
sources += codemon/codemon.cpp
sources += codemon/codemon.h
sources += codemon/private.h
endif

if PLUGIN_LIBHOOKTEST
sources += libhooktest/libhooktest.h
sources += libhooktest/libhooktest.cpp
endif

if PLUGIN_EXPLOITMON
sources += exploitmon/exploitmon.cpp
sources += exploitmon/exploitmon.h
sources += exploitmon/private.h
endif

if PLUGIN_IPT
sources += ipt/ipt.cpp
sources += ipt/ipt.h
endif

if PLUGIN_HIDSIM
sources += hidsim/keymap_evdev_to_qapi.h
sources += hidsim/hid_injection.cpp
sources += hidsim/hid_injection.h
sources += hidsim/qmp_connection.cpp
sources += hidsim/qmp_connection.h
sources += hidsim/hidsim.cpp
sources += hidsim/hidsim.h
endif

###############################################################################
sources += plugins.cpp plugins.h plugins_ex.cpp plugins_ex.h plugin_utils.cpp plugin_utils.h private.h type_traits_helpers.h filesystem.hpp hook_helpers.h
sources += output_format.h output_format/common.h output_format/csvfmt.h output_format/deffmt.h output_format/jsonfmt.h output_format/kvfmt.h
sources += output_format/xfmt.h output_format/ostream.h output_format/ostream.cpp

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src -I$(srcdir)
AM_CPPFLAGS += $(CPPFLAGS)
AM_CPPFLAGS += $(VMI_CFLAGS)
AM_CPPFLAGS += $(GLIB_CFLAGS)
AM_CPPFLAGS += $(JSONC_CFLAGS)
AM_CPPFLAGS += $(PTHREAD_CFLAGS)

AM_LDFLAGS =  $(LDFLAGS)
AM_LDFLAGS += $(GLIB_LIBS)
AM_LDFLAGS += $(VMI_LIBS)
AM_LDFLAGS += $(JSONC_LIBS)
AM_LDFLAGS += $(STDCPPFSLIB)

AM_LDFLAGS += $(PTHREAD_CFLAGS)

AM_CXXFLAGS = $(CXXFLAGS)

if HARDENING
AM_CXXFLAGS += $(HARDEN_CFLAGS) -DHARDENING
AM_LDFLAGS += $(HARDEN_LDFLAGS)
endif

if SANITIZE
AM_CXXFLAGS += $(SANITIZE_CFLAGS)
AM_LDFLAGS += $(SANITIZE_LDFLAGS)
endif

if !DEBUG
AM_CXXFLAGS += -Wno-c99-designator -Wno-reorder-init-list
AM_CXXFLAGS += -Wno-unknown-warning-option
else
AM_CXXFLAGS += -DDRAKVUF_DEBUG -Werror -Wall -Wextra -g -ggdb3
AM_CXXFLAGS += -ferror-limit=0
AM_CXXFLAGS += -Wno-unused-parameter -Wno-unknown-warning-option
AM_CXXFLAGS += -Wno-c99-designator -Wno-reorder-init-list
AM_CXXFLAGS += -Wcast-qual -Wcast-align -Wstrict-aliasing \
               -Wpointer-arith -Winit-self -Wshadow \
               -Wredundant-decls -Wfloat-equal -Wundef \
               -Wvla -Wformat -Wformat-security
# Note that -pg is incompatible with HARDENING
if !HARDENING
AM_CXXFLAGS += -pg
endif
endif

noinst_LTLIBRARIES= libdrakvufplugins.la
libdrakvufplugins_la_SOURCES= $(sources)
libdrakvufplugins_la_LIBADD = ../xen_helper/libxenhelper.la
libdrakvufplugins_la_LIBADD += ../libdrakvuf/libdrakvuf.la
