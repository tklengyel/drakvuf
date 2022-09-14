#********************IMPORTANT DRAKVUF LICENSE TERMS**********************#
#                                                                         #
# DRAKVUF (C) 2014-2022 Tamas K Lengyel.                                  #
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

bin_PROGRAMS = drakvuf injector proc_stat

SUBDIRS = xen_helper libdrakvuf libinjector plugins dirwatch libusermode libhook helpers/hiddump

drakvuf_SOURCES = main.cpp drakvuf.cpp drakvuf.h exitcodes.h
injector_SOURCES = injector.cpp
proc_stat_SOURCES = proc_stat.cpp

AM_CPPFLAGS = $(CPPFLAGS)
AM_CPPFLAGS += $(VMI_CFLAGS)
AM_CPPFLAGS += $(GLIB_CFLAGS)
AM_CPPFLAGS += $(JSONC_CFLAGS)
AM_CPPFLAGS += $(ZLIB_CFLAGS)
AM_CPPFLAGS += -I$(top_srcdir) -I$(srcdir)

AM_LDFLAGS =  $(LDFLAGS)
AM_LDFLAGS += $(VMI_LIBS)
AM_LDFLAGS += $(GLIB_LIBS)
AM_LDFLAGS += $(JSONC_LIBS)
AM_LDFLAGS += $(ZLIB_LIBS)

AM_CFLAGS = $(CFLAGS)
AM_CXXFLAGS = $(CXXFLAGS)

if HARDENING
AM_CFLAGS += $(HARDEN_CFLAGS) -DHARDENING
AM_CXXFLAGS += $(HARDEN_CFLAGS) -DHARDENING
AM_LDFLAGS += $(HARDEN_LDFLAGS)
endif

if SANITIZE
AM_CFLAGS += $(SANITIZE_CFLAGS)
AM_CXXFLAGS += $(SANITIZE_CFLAGS)
AM_LDFLAGS += $(SANITIZE_LDFLAGS)
endif

# Note that -pg is incompatible with HARDENING
if !DEBUG
AM_CXXFLAGS += -Wno-c99-designator -Wno-reorder-init-list
AM_CXXFLAGS += -Wno-unknown-warning-option
else
AM_CFLAGS += -DDRAKVUF_DEBUG -Werror -Wall -Wextra -g -ggdb3
AM_CXXFLAGS += -DDRAKVUF_DEBUG -Werror -Wall -Wextra -g -ggdb3
AM_CXXFLAGS += -Wformat -Wformat-security
AM_CXXFLAGS += -ferror-limit=0 -Wno-unknown-warning-option
AM_CXXFLAGS += -Wno-c99-designator -Wno-reorder-init-list
if !HARDENING
AM_CFLAGS += -pg
AM_CXXFLAGS += -pg
endif
endif

drakvuf_LDADD = libdrakvuf/libdrakvuf.la
drakvuf_LDADD += xen_helper/libxenhelper.la
drakvuf_LDADD += plugins/libdrakvufplugins.la
drakvuf_LDADD += libinjector/libinjector.la
drakvuf_LDADD += libusermode/libusermode.la
drakvuf_LDADD += libhook/libhook.la

injector_LDADD = libdrakvuf/libdrakvuf.la
injector_LDADD += libinjector/libinjector.la

proc_stat_LDADD = libdrakvuf/libdrakvuf.la

if XTF
bin_PROGRAMS += xtf
xtf_SOURCES = xtf.c
xtf_LDADD = libdrakvuf/libdrakvuf.la
endif

if REPL
bin_PROGRAMS += repl

SUBDIRS += librepl

repl_SOURCES = repl.cpp

drakvuf_LDADD += librepl/librepl.la

repl_LDADD = librepl/librepl.la
repl_LDADD += libdrakvuf/libdrakvuf.la

repl_CXXFLAGS = $(AM_CXXFLAGS) -fpie
repl_LDFLAGS = $(AM_LDFLAGS) -Wl,-E
endif
