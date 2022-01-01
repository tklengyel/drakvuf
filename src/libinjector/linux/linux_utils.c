/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2022 Tamas K Lengyel.                                  *
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


#define _GNU_SOURCE // required for memmem
#include <libinjector/debug_helpers.h>

#include "linux_injector.h"
#include <sys/mman.h>
#include <fcntl.h>

addr_t find_vdso(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t process_base = drakvuf_get_current_process(drakvuf, info);
    PRINT_DEBUG("Process base: %lx\n", process_base);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = info->proc_data.pid
    );

    addr_t addr = 0;
    size_t offset = 0;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    // task_struct to mm
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "task_struct", "mm", &offset))
    {
        PRINT_DEBUG("Failed to get mm offset\n");
        goto find_vdso_failure;
    }

    PRINT_DEBUG("mm offset: %ld\n", offset);
    ctx.addr = process_base + offset;

    // since mm is a pointer
    if (VMI_SUCCESS != vmi_read_64(vmi, &ctx, &addr))
    {
        PRINT_DEBUG("Failed to read mm address\n");
        goto find_vdso_failure;
    }

    PRINT_DEBUG("Got mm address: %lx\n", addr);

    // mm_struct to vdso ( it will directly parse the anonymous structure of context in between )
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "mm_struct", "vdso", &offset))
    {
        PRINT_DEBUG("Failed to get vdso offset\n");
        goto find_vdso_failure;
    }

    PRINT_DEBUG("vdso offset: %ld\n", offset);
    ctx.addr = addr + offset;

    // since vdso is a pointer
    if (VMI_SUCCESS != vmi_read_64(vmi, &ctx, &addr))
    {
        PRINT_DEBUG("Failed to read vdso address\n");
        goto find_vdso_failure;
    }

    PRINT_DEBUG("Got vdso address: %lx\n", addr);
    drakvuf_release_vmi(drakvuf);

    return addr;

find_vdso_failure:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

addr_t find_syscall(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t vdso)
{
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = info->proc_data.pid,
        .addr = vdso
    );

    size_t size = 4096;
    size_t bytes_read = 0;
    void* vdso_memory = g_malloc(size);

    // read the vdso memory
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, size, vdso_memory, &bytes_read))
    {
        fprintf(stderr, "Could not read vdso memory\n");
        drakvuf_release_vmi(drakvuf);
        g_free(vdso_memory);
        return 0;
    }

    PRINT_DEBUG("vdso memory read successful\n");
    drakvuf_release_vmi(drakvuf);

    char syscall[] = { 0xf, 0x5 };
    void* syscall_substring_address = memmem(vdso_memory, size, (void*)syscall, 2);
    int syscall_offset = 0;
    if (!syscall_substring_address)
    {
        PRINT_DEBUG("Failed to get syscall offset\n");
        g_free(vdso_memory);
        return 0;
    }
    syscall_offset = syscall_substring_address - vdso_memory;
    injector_t injector = info->trap->data;
    injector->syscall_addr = vdso + syscall_offset;

    PRINT_DEBUG("syscall offset: %d\n", syscall_offset);
    PRINT_DEBUG("syscall addr: %lx\n", injector->syscall_addr);
    g_free(vdso_memory);

    return injector->syscall_addr;
}

bool setup_post_syscall_trap(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t syscall_addr)
{
    injector_t injector = info->trap->data;

    injector->bp = g_malloc0(sizeof(drakvuf_trap_t));

    injector->bp->type = BREAKPOINT;
    injector->bp->name = "injector_post_syscall_trap";
    injector->bp->cb = injector_int3_userspace_cb;
    injector->bp->data = injector;
    injector->bp->breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp->breakpoint.dtb = info->regs->cr3;
    injector->bp->breakpoint.addr_type = ADDR_VA;
    injector->bp->breakpoint.addr = syscall_addr + 2;
    injector->bp->ttl = UNLIMITED_TTL;
    injector->bp->ah_cb = NULL;

    if ( drakvuf_add_trap(drakvuf, injector->bp) )
    {
        PRINT_DEBUG("Post syscall trap success\n");
        return true;
    }
    else
    {
        fprintf(stderr, "Couldn't trap next instruction after syscall\n");
        return false;
    }
}

bool save_rip_for_ret(drakvuf_t drakvuf, x86_registers_t* regs)
{
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = regs->cr3,
        .addr = regs->rsp - 0x8
    );

    bool success = false;
    if (VMI_SUCCESS == vmi_write_64(vmi, &ctx, &regs->rip))
    {
        success = true;
        regs->rsp -= 0x8;
    }
    else
        PRINT_DEBUG("Couldn't save rip for ret\n");

    drakvuf_release_vmi(drakvuf);
    return success;
}

void free_bp_trap(drakvuf_t drakvuf, injector_t injector, drakvuf_trap_t* trap)
{
    drakvuf_remove_trap(drakvuf, trap, (drakvuf_trap_free_t)g_free);
    injector->bp = NULL;
}

void injector_free_linux(injector_t injector)
{
    if (!injector) return;

    PRINT_DEBUG("Injector freed\n");

    g_free((void*)injector->bp);
    g_free((void*)injector->args);
    g_free((void*)injector->buffer.data);
    g_free((void*)injector->child_data.name);

    if (injector->fp)
        fclose(injector->fp);

    g_free((void*)injector);

    injector = NULL;
}

bool is_syscall_error(addr_t rax, const char* err)
{
    if (rax > -MAX_ERRNO)
    {
        fprintf(stderr, "syscall return code: %ld\n", (int64_t)rax);
        fprintf(stderr, "%s\n", err);
        return true;
    }
    return false;
}
