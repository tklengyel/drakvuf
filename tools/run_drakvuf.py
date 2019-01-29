#!/usr/bin/env python3

#********************IMPORTANT DRAKVUF LICENSE TERMS*********************#
#                                                                        #
# DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                 #
# Tamas K Lengyel is hereinafter referred to as the author.              #
# This program is free software; you may redistribute and/or modify it   #
# under the terms of the GNU General Public License as published by the  #
# Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE  #
# CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your  #
# right to use, modify, and redistribute this software under certain     #
# conditions.  If you wish to embed DRAKVUF technology into proprietary  #
# software, alternative licenses can be aquired from the author.         #
#                                                                        #
# Note that the GPL places important restrictions on "derivative works", #
# yet it does not provide a detailed definition of that term.  To avoid  #
# misunderstandings, we interpret that term as broadly as copyright law  #
# allows.  For example, we consider an application to constitute a       #
# derivative work for the purpose of this license if it does any of the  #
# following with any software or content covered by this license         #
# ("Covered Software"):                                                  #
#                                                                        #
# o Integrates source code from Covered Software.                        #
#                                                                        #
# o Reads or includes copyrighted data files.                            #
#                                                                        #
# o Is designed specifically to execute Covered Software and parse the   #
# results (as opposed to typical shell or execution-menu apps, which will#
# execute anything you tell them to).                                    #
#                                                                        #
# o Includes Covered Software in a proprietary executable installer.  The#
# installers produced by InstallShield are an example of this.  Including#
# DRAKVUF with other software in compressed or archival form does not    #
# trigger this provision, provided appropriate open source decompression #
# or de-archiving software is widely available for no charge.  For the   #
# purposes of this license, an installer is considered to include Covered#
# Software even if it actually retrieves a copy of Covered Software from #
# another source during runtime (such as by downloading it from the      #
# Internet).                                                             #
#                                                                        #
# o Links (statically or dynamically) to a library which does any of the #
# above.                                                                 #
#                                                                        #
# o Executes a helper program, module, or script to do any of the above. #
#                                                                        #
# This list is not exclusive, but is meant to clarify our interpretation #
# of derived works with some common examples.  Other people may interpret#
# the plain GPL differently, so we consider this a special exception to  #
# the GPL that we apply to Covered Software.  Works which meet any of    #
# these conditions must conform to all of the terms of this license,     #
# particularly including the GPL Section 3 requirements of providing     #
# source code and allowing free redistribution of the work as a whole.   #
#                                                                        #
# Any redistribution of Covered Software, including any derived works,   #
# must obey and carry forward all of the terms of this license, including#
# obeying all GPL rules and restrictions.  For example, source code of   #
# the whole work must be provided and free redistribution must be        #
# allowed.  All GPL references to "this License", are to be treated as   #
# including the terms and conditions of this license text as well.       #
#                                                                        #
# Because this license imposes special exceptions to the GPL, Covered    #
# Work may not be combined (even as part of a larger work) with plain GPL#
# software.  The terms, conditions, and exceptions of this license must  #
# be included as well.  This license is incompatible with some other open#
# source licenses as well.  In some cases we can relicense portions of   #
# DRAKVUF or grant special permissions to use it in other open source    #
# software.  Please contact tamas.k.lengyel@gmail.com with any such      #
# requests.  Similarly, we don't incorporate incompatible open source    #
# software into Covered Software without special permission from the     #
# copyright holders.                                                     #
#                                                                        #
# If you have any questions about the licensing restrictions on using    #
# DRAKVUF in other works, are happy to help.  As mentioned above,        #
# alternative license can be requested from the author to integrate      #
# DRAKVUF into proprietary applications and appliances.  Please email    #
# tamas.k.lengyel@gmail.com for further information.                     #
#                                                                        #
# If you have received a written license agreement or contract for       #
# Covered Software stating terms other than these, you may choose to use #
# and redistribute Covered Software under those terms instead of these.  #
#                                                                        #
# Source is provided to this software because we believe users have a    #
# right to know exactly what a program is going to do before they run it.#
# This also allows you to audit the software for security holes.         #
#                                                                        #
# Source code also allows you to port DRAKVUF to new platforms, fix bugs,#
# and add new features.  You are highly encouraged to submit your changes#
# on https://github.com/tklengyel/drakvuf, or by other methods.          #
# By sending these changes, it is understood (unless you specify         #
# otherwise) that you are offering unlimited, non-exclusive right to     #
# reuse, modify, and relicense the code.  DRAKVUF will always be         #
# available Open Source, but this is important because the inability to  #
# relicense code has caused devastating problems for other Free Software #
# projects (such as KDE and NASM).                                       #
# To specify special license conditions of your contributions, just say  #
# so when you send them.                                                 #
#                                                                        #
# This program is distributed in the hope that it will be useful, but    #
# WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF  #
# license file for more details (it's in a COPYING file included with    #
# DRAKVUF, and also available from                                       #
# https://github.com/tklengyel/drakvuf/COPYING)                          #
#                                                                        #
#************************************************************************#

##
## Spawns DRAKVUF and parses its outbound messages via pipe.
##

## @TODO:
## - add async support (poll on outpipe)
## - improve ^C support
## - remote breakpoints, verify correct handling of bad input


import os
import sys
import signal

import json
import logging

import subprocess # ???

if not (sys.version_info.major >= 3 and sys.version_info.minor >= 6):
    print("This script required Python 3.6+")
    sys.exit(1)

import curio
import curio.subprocess # ???
import asyncio
import selectors


proc = None # handle to DRAKVUF process

def signal_handler(sig, frame):
    global proc
    logging.info("Handling signal %d: stopping DRAKVUF", sig)
    if proc:
        proc.terminate()
    sys.exit(0)

i = 0

def get_event_nojson(outpipe):
    global i
    line = b''

    while True:
        line = outpipe.readline()
        if not line:
            break

        i += 1
        # try:
        #     dline = line.decode("utf-8")
        # except UnicodeDecodeError as e:
        #     logging.warning("Failed to decode message %d [%s...]: %s", i, line[:40], e)
        #     import pdb;pdb.set_trace()
        #     break
        yield line

    # all done...
    yield None

def get_event(outpipe):
    global i

    line = b''
    prevcol = -1 # column of previous error
    while True:
        line += outpipe.readline()
        if not line:
            break

        i += 1
        try:
            dline = line.decode("utf-8")
        except UnicodeDecodeError as e:
            logging.warning("Failed to decode message %d [%s...]: %s", i, line[:40], e)
            break
        try:
            j = json.loads(dline)
            line = b''
            #print(j)
        except json.decoder.JSONDecodeError as e:
            logging.info("Failed to parse JSON from message %d [%s...]: %s", i, dline[:40], e)
            if prevcol == e.colno:
                logging.warning("Giving up an malformed JSON document:\n%s", dline)
                line = b''
                prevcol = -1
            else:
                prevcol = e.colno
            continue
            # break
        return j

    # all done...
    return None

def parse_event(event):
    global i

    i += 1
    if i % 1000 == 0:
        print("Parsed {} events".format(i))

def handle_output(outpipe):
    json = get_event(outpipe)
    print(json)
    parse_event(json)

def read_nop(outpipe):
    line = outpipe.readline()
    try:
        dline = line.decode("utf-8")
    except UnicodeDecodeError as e:
        logging.warning("Failed to decode message %d [%s...]: %s", i, line[:40], e)
        return

    print("Error: {}".format(dline))
    return True

def spawn_drakvuf(profile, domid):
    global proc

    fmt = 'json'
    #fmt = 'kv'

    cmd  = ['drakvuf', '-r', profile, '-d', domid, '-o', fmt]
    #cmd.append('-v')

    logging.info("Running %s", ' '.join(cmd))

    # proc = curio.subprocess.Popen(cmd,
    #                               stdout=curio.subprocess.PIPE,
    #                               stderr=curio.subprocess.PIPE)

    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    stdout, stderr = proc.stdout, proc.stderr

    #stdout.setblocking(False)
    #stderr.setblocking(False)

    sel = selectors.DefaultSelector()
    sel.register(stdout, selectors.EVENT_READ, handle_output)
    sel.register(stderr, selectors.EVENT_READ, read_nop)

    process = True
    while process:
        events = sel.select()
        for key, mask in events:
            callback = key.data
            val = callback(key.fileobj)
            if val is None:
                # fall out of outer loop
                process = False
                break

    # #for e in get_event(proc.stdout):
    # for e in get_event_nojson(proc.stdout):
    #     if not e:
    #         break

    #     parse_event(e)

    # No more input...
    rc = proc.wait()
    if rc:
        logging.warn("Returned %d, stderr: %s", rc, proc.stderr.read())
    proc.terminate()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: {} <rekall_profile> <domid>".format(sys.argv[0]))
        print("Run as root (sudo)!")
        sys.exit(1)

    logging.basicConfig(level=logging.INFO)

    (profile, domid) = sys.argv[1:]

    signal.signal(signal.SIGHUP,  signal_handler)
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGABRT, signal_handler)

    spawn_drakvuf(profile, domid)
