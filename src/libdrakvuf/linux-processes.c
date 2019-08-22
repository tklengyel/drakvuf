/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  *
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

#include <libvmi/libvmi.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <glib.h>
#include <limits.h>

#include "private.h"
#include "linux.h"
#include "linux-offsets.h"

#define STACK_SIZE_8K  0x1fff
#define STACK_SIZE_16K 0x3fff
#define MIN_KERNEL_BOUNDARY 0x80000000

static addr_t read_process_base(drakvuf_t drakvuf, addr_t rsp, access_context_t* ctx)
{
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t process = 0;

    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &process) || process < MIN_KERNEL_BOUNDARY )
    {
        /*
         * The kernel stack also has a structure called thread_info that points
         * to a task_struct but it doesn't seem to always agree with current_task.
         * However, when current_task obviously is wrong (for example during a CPUID)
         * we can fall back to it to find the correct process.
         * On most newer kernels the kernel stack size is 16K. This is just a guess
         * so for older kernels this may not work as well if the VA happens to map
         * something that resembles a kernel-address.
         * See https://www.cs.columbia.edu/~smb/classes/s06-4118/l06.pdf for more info.
         */
        ctx->addr = rsp & ~STACK_SIZE_16K;
        if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &process) || process < MIN_KERNEL_BOUNDARY )
        {
            ctx->addr = rsp & ~STACK_SIZE_8K;
            if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &process) || process < MIN_KERNEL_BOUNDARY )
                process = 0;
        }
    }

    return process;
}

addr_t linux_get_current_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t process = 0;
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
    };

    if (info->regs->cs_sel & 3)
    {
        // Let's assume a modern kernel with KPTI enabled first
        ctx.dtb = info->regs->cr3 & ~0x1fffull;
        ctx.addr = info->regs->shadow_gs;
    }
    else
    {
        // Mask PCID bits
        ctx.dtb = info->regs->cr3 & ~0xfffull;
        ctx.addr = info->regs->gs_base;
    }

    ctx.addr += drakvuf->offsets[CURRENT_TASK];

    process = read_process_base(drakvuf, info->regs->rsp, &ctx);

    if ( !process && (info->regs->cs_sel & 3) )
    {
        // If that didn't work and we are in usermode, try without masking KPTI bits
        ctx.dtb |= 0x1000ull;
        process = read_process_base(drakvuf, info->regs->rsp, &ctx);
    }

    return process;
}

/*
 * Threads are really just processes on Linux.
 */
addr_t linux_get_current_thread(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return linux_get_current_process(drakvuf, info);
}

char* linux_get_process_name(drakvuf_t drakvuf, addr_t process_base, bool fullpath)
{
    UNUSED(fullpath);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 0,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_COMM]
    };

    return vmi_read_str(drakvuf->vmi, &ctx);
}

bool linux_get_process_pid(drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* pid )
{
    /*
     * On Linux PID is actually a thread ID, while the TGID (Thread Group-ID) is
     * what getpid() would return. Because THAT makes sense.
     */
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 0,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_TGID]
    };

    if ( VMI_SUCCESS == vmi_read_32(drakvuf->vmi, &ctx, (uint32_t*)pid) )
        return true;

    return false;
}

char* linux_get_current_process_name(drakvuf_t drakvuf, drakvuf_trap_info_t* info, bool fullpath)
{
    UNUSED(fullpath);
    addr_t process_base = linux_get_current_process(drakvuf, info);
    if ( !process_base )
        return NULL;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_COMM]
    };

    return vmi_read_str(drakvuf->vmi, &ctx);
}

int64_t linux_get_process_userid(drakvuf_t drakvuf, addr_t process_base)
{
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 0,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_CRED]
    };

    addr_t cred;
    if ( VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &cred) )
        return -1;

    uint32_t uid;
    ctx.addr = cred + drakvuf->offsets[CRED_UID];
    if ( VMI_FAILURE == vmi_read_32(drakvuf->vmi, &ctx, &uid) )
        return -1;

    return uid;
};

int64_t linux_get_current_process_userid(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t process_base = linux_get_current_process(drakvuf, info);
    if ( !process_base )
        return -1;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_CRED]
    };

    addr_t cred;
    if ( VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &cred) )
        return -1;

    uint32_t uid;
    ctx.addr = cred + drakvuf->offsets[CRED_UID];
    if ( VMI_FAILURE == vmi_read_32(drakvuf->vmi, &ctx, &uid) )
        return -1;

    return uid;
}

bool linux_get_current_thread_id( drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* thread_id )
{
    /*
     * On Linux PID is actually the thread ID....... ... ...
     */
    addr_t process_base = linux_get_current_process(drakvuf, info);
    if ( !process_base )
        return false;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_PID]
    };
    uint32_t _thread_id;

    if ( VMI_FAILURE == vmi_read_32(drakvuf->vmi, &ctx, &_thread_id) )
        return false;

    *thread_id = _thread_id;

    return true;
}

bool linux_get_process_ppid( drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* ppid )
{
    status_t status;
    addr_t parent_proc_base = 0 ;
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 0,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_REALPARENT]
    };

    status = vmi_read_addr( drakvuf->vmi, &ctx, &parent_proc_base );

    /* If we were unable to get the "proc->real_parent *" get "proc->parent *"... */
    /* Assuming a parent_proc_base == 0 is a fail... */
    if ( VMI_FAILURE == status || ! parent_proc_base )
    {
        ctx.addr = process_base + drakvuf->offsets[TASK_STRUCT_PARENT];
        status = vmi_read_addr( drakvuf->vmi, &ctx, &parent_proc_base );
    }

    /* Get pid from parent/real_parent...*/
    if ( VMI_SUCCESS == status && parent_proc_base )
    {
        ctx.addr = parent_proc_base + drakvuf->offsets[TASK_STRUCT_TGID];
        if ( VMI_SUCCESS == vmi_read_32( drakvuf->vmi, &ctx, (uint32_t*)ppid ) )
            return true;
    }

    return false;
}

bool linux_get_process_data( drakvuf_t drakvuf, addr_t base_addr, proc_data_priv_t* proc_data )
{
    proc_data->base_addr = base_addr;

    if ( !base_addr )
        return false;

    if ( !linux_get_process_pid(drakvuf, base_addr, &proc_data->pid) )
        return false;

    proc_data->name = linux_get_process_name(drakvuf, base_addr, true);

    if ( !proc_data->name )
        return false;

    proc_data->userid = linux_get_process_userid(drakvuf, base_addr);

    if ( !linux_get_process_ppid(drakvuf, base_addr, &proc_data->ppid) )
        PRINT_DEBUG("Failed to gather parent process' PID for %s:%u\n", proc_data->name, proc_data->pid);

    return false;
}

