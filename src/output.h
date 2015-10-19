/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014 Tamas K Lengyel.       *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be aquired from the author.          *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/

#ifndef OUTPUT_H
#define OUTPUT_H

#include "drakvuf.h"
#include "structures.h"

enum output_strings {
    INT3_CB_STRING,
    FOUND_PROCESS_STRING,
    HEAPALLOC_KNOWN_STRING,
    HEAPALLOC_UNKNOWN_STRING,
    HEAPALLOC_VERIFIED_STRING,
    HEAPALLOC_BIGPOOL_STRING,
    HEAPALLOC_MANGLED_STRING,
    HEAPFREE_STRING,
    OBJCREATE_KNOWN_STRING,
    OBJCREATE_UNKNOWN_STRING,
    INJECTION_START_STRING,
    INJECTION_STACK_INFO_STRING,
    INJECTION_STACK_PUSHED_STRING,
    INJECTION_TRAPFRAME_STRING,
    INJECTION_SUCCESS_STRING,
    __STRINGS_MAX
};

static const char *strings_list[__OUTPUT_MAX][__STRINGS_MAX] = {
    [OUTPUT_DEFAULT] = {
        [0 ... __STRINGS_MAX-1] = NULL,
        [INT3_CB_STRING] = "int3cb CR3=0x%lx RIP=0x%lx %s!%s\n",
        [FOUND_PROCESS_STRING] = "Found process: [PID: %5d, CR3: 0x%x] %s\n",
        [HEAPALLOC_KNOWN_STRING] = "Heap allocation with known pool tag:"
                                   " '%s' (%u), %s, %s.\n",
        [HEAPALLOC_UNKNOWN_STRING] = "Heap allocation with unknown pool tag: "
                                     "'%s' \\x%x\\x%x\\x%x\\x%x\n",
        [HEAPALLOC_VERIFIED_STRING] = "\t'%c%c%c%c' heap allocation verified @"
                                      " PA 0x%lx. Size: %u\n",
        [HEAPALLOC_BIGPOOL_STRING] = "Allocation in big pool: %u, '%c%c%c%c'\n",
        [HEAPALLOC_MANGLED_STRING] = "Pool tag mangling detected: got '%c%c%c%c'"
                                     ", expected '%c%c%c%c'\n",
        [HEAPFREE_STRING] = "Freeing object on heap: 0x%lx, %s\n",
        [OBJCREATE_KNOWN_STRING] = "Object create: %u -> %s\n",
        [OBJCREATE_UNKNOWN_STRING] = "Object create: %u\n",
        [INJECTION_START_STRING] = "Hijacking thread of PID %u on vCPU %u to "
                                   "execute CreateProcessA at 0x%lx!\n",
        [INJECTION_STACK_INFO_STRING] = "FS/GS: 0x%lx RSP: 0x%lx RIP: 0x%lx "
                                        "RCX: 0x%lx RBP: 0x%lx\n"
                                        "Stack base: 0x%lx Limit: 0x%lx\n",
        [INJECTION_STACK_PUSHED_STRING] = "\tArgument '%s' pushed on stack at 0x%lx.\n"
                                          "\tProcess information pushed on stack at 0x%lx\n"
                                          "\tStartup information pushed on stack at 0x%lx\n"
                                          "\tReturn address 0x%lx pushed on stack at 0x%lx\n",
        [INJECTION_TRAPFRAME_STRING] = "Trapping userspace return of Thread:"
                                       " %lu @ VA 0x%lx -> PA 0x%lx\n",
        [INJECTION_SUCCESS_STRING] = "-- CreateProcessA SUCCESS --\n"
                                     "\tProcess handle: 0x%x. Thread handle: 0x%x\n"
                                     "\tPID: %u. TID: %u\n"
                                     "\tInjected process DTB: 0x%lx\n",
    },
    [OUTPUT_CSV] = {
        [0 ... __STRINGS_MAX-1] = NULL,
        [INT3_CB_STRING] = "int3cb,0x%lx,0x%lx,%s,%s\n",
        [FOUND_PROCESS_STRING] = "process,%d,0x%x,%s\n",
        [HEAPALLOC_KNOWN_STRING] = "heapalloc,known,%s,%u,%s,%s\n",
        [HEAPALLOC_UNKNOWN_STRING] = "heapalloc,unknown,%s,\\x%x,\\x%x,\\x%x,\\x%x\n",
        [HEAPALLOC_VERIFIED_STRING] = "heapalloc,verified,%c,%c,%c,%c,0x%lx,%u\n",
        [HEAPALLOC_BIGPOOL_STRING] = "heapalloc,bigpool,%u,%c,%c,%c,%c\n",
        [HEAPALLOC_MANGLED_STRING] = "heapalloc,mangled,%c%c%c%c,%c%c%c%c\n",
        [HEAPFREE_STRING] = "heapfree,0x%lx,%s\n",
        [OBJCREATE_KNOWN_STRING] = "objcreate,known,%u,%s\n",
        [OBJCREATE_UNKNOWN_STRING] = "objcreate,unknown,%u\n",
        [INJECTION_SUCCESS_STRING] = "injection,0x%lx,0x%lx,%u,%u,0x%lx\n",
    },
};

#define PRINT(drakvuf, string, args...) \
    do { \
        if ( strings_list[drakvuf->output_format][string] ) \
            printf(strings_list[drakvuf->output_format][string], ##args); \
    } while (0)

#define PRINT_DEBUG(args...) \
    do { \
        if (verbose) fprintf (stderr, args); \
    } while (0)

#endif
