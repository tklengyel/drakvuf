/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
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
 * This file was created by Manorit Chawdhry.                              *
 * It is distributed as part of DRAKVUF under the same license             *
 ***************************************************************************/


#include <libinjector/debug_helpers.h>

void print_hex(const char* array, size_t len)
{
    PRINT_DEBUG("Total length: %ld\n", len);
    PRINT_DEBUG("Data: \n");
    for (size_t i=0; i<len; i++)
    {
        PRINT_DEBUG("%02x ", *(array + i) & 0xff);
    }
    PRINT_DEBUG("\n");
}

void print_stack(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr)
{
#ifdef DRAKVUF_DEBUG
    PRINT_DEBUG("Stack\n");
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    for (int i=0; i < 16; i++)
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_PID,
            .pid = info->proc_data.pid,
            .addr = (addr + i*8)
        );
        addr_t val = 0;
        vmi_read_64(vmi, &ctx, &val);
        if ((i%4)==0)
            fprintf(stderr, "\n%016lx:", addr + (i/4)*32);
        fprintf(stderr, " %016lx", val);
    }
    fprintf(stderr, "\n");

    drakvuf_release_vmi(drakvuf);
#endif
}

void print_registers(drakvuf_trap_info_t* info)
{
#ifdef DRAKVUF_DEBUG
    const char* fmt = "%s:\t%016lx\n";
    PRINT_DEBUG(fmt, "rax",    info->regs->rax);
    PRINT_DEBUG(fmt, "rcx",    info->regs->rcx);
    PRINT_DEBUG(fmt, "rdx",    info->regs->rdx);
    PRINT_DEBUG(fmt, "rbx",    info->regs->rbx);
    PRINT_DEBUG(fmt, "rsp",    info->regs->rsp);
    PRINT_DEBUG(fmt, "rbp",    info->regs->rbp);
    PRINT_DEBUG(fmt, "rsi",    info->regs->rsi);
    PRINT_DEBUG(fmt, "rdi",    info->regs->rdi);
    PRINT_DEBUG(fmt, "r8",     info->regs->r8);
    PRINT_DEBUG(fmt, "r9",     info->regs->r9);
    PRINT_DEBUG(fmt, "r10",    info->regs->r10);
    PRINT_DEBUG(fmt, "r11",    info->regs->r11);
    PRINT_DEBUG(fmt, "r12",    info->regs->r12);
    PRINT_DEBUG(fmt, "r13",    info->regs->r13);
    PRINT_DEBUG(fmt, "r14",    info->regs->r14);
    PRINT_DEBUG(fmt, "r15",    info->regs->r15);
    PRINT_DEBUG(fmt, "rflags", info->regs->rflags);
    PRINT_DEBUG(fmt, "dr6",    info->regs->dr6);
    PRINT_DEBUG(fmt, "dr7",    info->regs->dr7);
    PRINT_DEBUG(fmt, "rip",    info->regs->rip);
    PRINT_DEBUG(fmt, "cr0",    info->regs->cr0);
    PRINT_DEBUG(fmt, "cr2",    info->regs->cr2);
    PRINT_DEBUG(fmt, "cr3",    info->regs->cr3);
    PRINT_DEBUG(fmt, "cr4",    info->regs->cr4);
#endif
}
