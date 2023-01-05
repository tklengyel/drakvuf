/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2023 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
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

#ifndef PTRACEMON_PRIVATE_H
#define PTRACEMON_PRIVATE_H

#define PTRACE_SYSCALL_NUM 101

namespace ptracemon_ns
{

enum linux_pt_regs
{
    PT_REGS_R15,
    PT_REGS_R14,
    PT_REGS_R13,
    PT_REGS_R12,
    PT_REGS_RBP,
    PT_REGS_RBX,

    PT_REGS_R11,
    PT_REGS_R10,
    PT_REGS_R9,
    PT_REGS_R8,
    PT_REGS_RAX,
    PT_REGS_RCX,
    PT_REGS_RDX,
    PT_REGS_RSI,
    PT_REGS_RDI,

    PT_REGS_ORIG_RAX,

    PT_REGS_RIP,
    PT_REGS_CS,
    PT_REGS_EFLAGS,
    PT_REGS_RSP,
    PT_REGS_SS,

    __PT_REGS_MAX
};

static const char* pt_regs_offsets_name[__PT_REGS_MAX][2] =
{
    [PT_REGS_R15]      = {"pt_regs", "r15"},
    [PT_REGS_R14]      = {"pt_regs", "r14"},
    [PT_REGS_R13]      = {"pt_regs", "r13"},
    [PT_REGS_R12]      = {"pt_regs", "r12"},
    [PT_REGS_RBP]      = {"pt_regs", "bp"},
    [PT_REGS_RBX]      = {"pt_regs", "bx"},

    [PT_REGS_R11]      = {"pt_regs", "r11"},
    [PT_REGS_R10]      = {"pt_regs", "r10"},
    [PT_REGS_R9]       = {"pt_regs", "r9"},
    [PT_REGS_R8]       = {"pt_regs", "r8"},
    [PT_REGS_RAX]      = {"pt_regs", "ax"},
    [PT_REGS_RCX]      = {"pt_regs", "cx"},
    [PT_REGS_RDX]      = {"pt_regs", "dx"},
    [PT_REGS_RSI]      = {"pt_regs", "si"},
    [PT_REGS_RDI]      = {"pt_regs", "di"},

    [PT_REGS_ORIG_RAX] = {"pt_regs", "orig_ax"},

    [PT_REGS_RIP]      = {"pt_regs", "ip"},
    [PT_REGS_CS]       = {"pt_regs", "cs"},
    [PT_REGS_EFLAGS]   = {"pt_regs", "flags"},
    [PT_REGS_RSP]      = {"pt_regs", "sp"},
    [PT_REGS_SS]       = {"pt_regs", "ss"},
};

typedef enum ptrace_request
{
    PTRACE_TRACEME                  = 0,
    PTRACE_PEEKTEXT                 = 1,
    PTRACE_PEEKDATA                 = 2,
    PTRACE_PEEKUSER                 = 3,
    PTRACE_POKETEXT                 = 4,
    PTRACE_POKEDATA                 = 5,
    PTRACE_POKEUSER                 = 6,
    PTRACE_CONT                     = 7,
    PTRACE_KILL                     = 8,
    PTRACE_SINGLESTEP               = 9,
    PTRACE_GETREGS                  = 12,
    PTRACE_SETREGS                  = 13,
    PTRACE_GETFPREGS                = 14,
    PTRACE_SETFPREGS                = 15,
    PTRACE_ATTACH                   = 16,
    PTRACE_DETACH                   = 17,
    PTRACE_GETFPXREGS               = 18,
    PTRACE_SETFPXREGS               = 19,
    PTRACE_OLDSETOPTIONS            = 21,
    PTRACE_SYSCALL                  = 24,
    PTRACE_GET_THREAD_AREA          = 25,
    PTRACE_SET_THREAD_AREA          = 26,
    PTRACE_ARCH_PRCTL               = 30,
    PTRACE_SYSEMU                   = 31,
    PTRACE_SYSEMU_SINGLESTEP        = 32,
    PTRACE_SINGLEBLOCK              = 33,
    PTRACE_SETOPTIONS               = 0x4200,
    PTRACE_GETEVENTMSG              = 0x4201,
    PTRACE_GETSIGINFO               = 0x4202,
    PTRACE_SETSIGINFO               = 0x4203,
    PTRACE_GETREGSET                = 0x4204,
    PTRACE_SETREGSET                = 0x4205,
    PTRACE_SEIZE                    = 0x4206,
    PTRACE_INTERRUPT                = 0x4207,
    PTRACE_LISTEN                   = 0x4208,
    PTRACE_PEEKSIGINFO              = 0x4209,
    PTRACE_GETSIGMASK               = 0x420a,
    PTRACE_SETSIGMASK               = 0x420b,
    PTRACE_SECCOMP_GET_FILTER       = 0x420c,
    PTRACE_SECCOMP_GET_METADATA     = 0x420d,
    PTRACE_GET_SYSCALL_INFO         = 0x420e,
} ptrace_request_t;

static inline const char* ptrace_request_to_str(ptrace_request_t request)
{
    switch (request)
    {
        case PTRACE_TRACEME:
            return "PTRACE_TRACEME";
        case PTRACE_PEEKTEXT:
            return "PTRACE_PEEKTEXT";
        case PTRACE_PEEKDATA:
            return "PTRACE_PEEKDATA";
        case PTRACE_PEEKUSER:
            return "PTRACE_PEEKUSER";
        case PTRACE_POKETEXT:
            return "PTRACE_POKETEXT";
        case PTRACE_POKEDATA:
            return "PTRACE_POKEDATA";
        case PTRACE_POKEUSER:
            return "PTRACE_POKEUSER";
        case PTRACE_CONT:
            return "PTRACE_CONT";
        case PTRACE_KILL:
            return "PTRACE_KILL";
        case PTRACE_SINGLESTEP:
            return "PTRACE_SINGLESTEP";
        case PTRACE_GETREGS:
            return "PTRACE_GETREGS";
        case PTRACE_SETREGS:
            return "PTRACE_SETREGS";
        case PTRACE_GETFPREGS:
            return "PTRACE_GETFPREGS";
        case PTRACE_SETFPREGS:
            return "PTRACE_SET_FPREGS";
        case PTRACE_ATTACH:
            return "PTRACE_ATTACH";
        case PTRACE_DETACH:
            return "PTRACE_DETACH";
        case PTRACE_GETFPXREGS:
            return "PTRACE_GETFPXREGS";
        case PTRACE_SETFPXREGS:
            return "PTRACE_SETFPXREGS";
        case PTRACE_OLDSETOPTIONS:
            return "PTRACE_OLDSETOPTIONS";
        case PTRACE_SYSCALL:
            return "PTRACE_SYSCALL";
        case PTRACE_GET_THREAD_AREA:
            return "PTRACE_GET_THREAD_AREA";
        case PTRACE_SET_THREAD_AREA:
            return "PTRACE_SET_THREAD_AREA";
        case PTRACE_ARCH_PRCTL:
            return "PTRACE_ARCH_PRCTL";
        case PTRACE_SYSEMU:
            return "PTRACE_SYSEMU";
        case PTRACE_SYSEMU_SINGLESTEP:
            return "PTRACE_SYSEMU_SINGLESTEP";
        case PTRACE_SINGLEBLOCK:
            return "PTRACE_SINGLEBLOCK";
        case PTRACE_SETOPTIONS:
            return "PTRACE_SETOPTIONS";
        case PTRACE_GETEVENTMSG:
            return "PTRACE_GETEVENTMSG";
        case PTRACE_GETSIGINFO:
            return "PTRACE_GETSIGINFO";
        case PTRACE_SETSIGINFO:
            return "PTRACE_SETSIGINFO";
        case PTRACE_GETREGSET:
            return "PTRACE_GETREGSET";
        case PTRACE_SETREGSET:
            return "PTRACE_SETREGSET";
        case PTRACE_SEIZE:
            return "PTRACE_SEIZE";
        case PTRACE_INTERRUPT:
            return "PTRACE_INTERRUPT";
        case PTRACE_LISTEN:
            return "PTRACE_LISTEN";
        case PTRACE_PEEKSIGINFO:
            return "PTRACE_PEEKSIGINFO";
        case PTRACE_GETSIGMASK:
            return "PTRACE_GETSIGMASK";
        case PTRACE_SETSIGMASK:
            return "PTRACE_SETSIGMASK";
        case PTRACE_SECCOMP_GET_FILTER:
            return "PTRACE_SECCOMP_GET_FILTER";
        case PTRACE_SECCOMP_GET_METADATA:
            return "PTRACE_SECCOMP_GET_METADATA";
        case PTRACE_GET_SYSCALL_INFO:
            return "PTRACE_GET_SYSCALL_INFO";
    }
    return NULL;
}
}; // ptracemon_ns

#endif