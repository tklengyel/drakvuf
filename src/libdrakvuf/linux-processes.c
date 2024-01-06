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
#define PAGE_OFFSET 0xffff800000000000
#define PF_EXITING		0x00000004	/* Getting shut down */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */

enum
{
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};

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
    addr_t dtb, gs_base;
    if (info->regs->cs_sel & 3)
    {
        // Let's assume a modern kernel with KPTI enabled first
        dtb = info->regs->cr3 & ~0x1fffull;
        gs_base = info->regs->shadow_gs;
    }
    else
    {
        // Mask PCID bits
        dtb = info->regs->cr3 & ~0xfffull;
        // We might trap before swapgs
        gs_base = VMI_GET_BIT(info->regs->gs_base, 47) ? info->regs->gs_base : info->regs->shadow_gs;
    }

    addr_t current_task_offset = drakvuf->offsets[CURRENT_TASK];
    // for kernel 6.2+ need use new structure
    // https://elixir.bootlin.com/linux/v6.2-rc1/source/arch/x86/include/asm/current.h
    if (!current_task_offset)
        current_task_offset = drakvuf->offsets[PCPU_HOT] + drakvuf->offsets[PCPU_HOT_CURRENT_TASK];

    addr_t addr = gs_base + current_task_offset;

    addr_t process;
    if ( VMI_SUCCESS == vmi_read_addr_va(drakvuf->vmi, addr, 0, &process) && process >= MIN_KERNEL_BOUNDARY )
        return process;

    // NOTE The old method is leaved here as is to make diff as little as possible.
    // This also allows to make more robust research before removing old method.

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = dtb,
        .addr = addr
    );
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

static bool get_kernel_struct_field_pointer(drakvuf_t drakvuf, addr_t struct_addr, int offset_field, addr_t* addr)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd,
        .addr = struct_addr + drakvuf->offsets[offset_field]);

    return (VMI_SUCCESS == vmi_read_addr(drakvuf->vmi, &ctx, addr));
}

static bool get_mm_struct(drakvuf_t drakvuf, addr_t process_base, addr_t* mm_struct)
{
    return get_kernel_struct_field_pointer(drakvuf, process_base, TASK_STRUCT_MMSTRUCT, mm_struct);
}

static bool get_active_mm_struct(drakvuf_t drakvuf, addr_t process_base, addr_t* mm_struct)
{
    return get_kernel_struct_field_pointer(drakvuf, process_base, TASK_STRUCT_ACTIVE_MMSTRUCT, mm_struct);
}

static void prepend_path(drakvuf_t drakvuf, addr_t path, addr_t root, GString* b)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd,
        .addr = path + drakvuf->offsets[PATH_DENTRY]);
    addr_t dentry;
    if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &dentry))
    {
        PRINT_DEBUG("Can't get path->dentry from struct path\n");
        return;
    }

    ctx.addr = path + drakvuf->offsets[PATH_MNT];
    addr_t vfsmnt;
    if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &vfsmnt))
    {
        PRINT_DEBUG("Can't get path->mnt from struct path\n");
        return;
    }

    addr_t root_dentry;
    ctx.addr = root + drakvuf->offsets[PATH_DENTRY];
    if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &root_dentry))
    {
        PRINT_DEBUG("Can't get root->dentry from root\n");
        return;
    }

    addr_t root_mnt;
    ctx.addr = root + drakvuf->offsets[PATH_MNT];
    if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &root_mnt))
    {
        PRINT_DEBUG("Can't get root->mnt from root\n");
        return;
    }

    while (dentry != root_dentry || vfsmnt != root_mnt)
    {
        addr_t mnt_mnt_root;
        ctx.addr = vfsmnt + drakvuf->offsets[VFSMOUNT_MNT_ROOT];
        if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &mnt_mnt_root))
        {
            PRINT_DEBUG("Can't read path->mnt->mnt_root from vfsmnt\n");
            return;
        }

        addr_t dentry_parent;
        ctx.addr = dentry + drakvuf->offsets[DENTRY_D_PARENT];
        if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &dentry_parent))
        {
            PRINT_DEBUG("Can't read path->dentry->d_parent\n");
            return;
        }

        // End of cycle
        if (dentry == mnt_mnt_root || dentry == dentry_parent)
            break;

        addr_t qname_addr;
        ctx.addr = dentry + drakvuf->offsets[DENTRY_D_NAME] + drakvuf->offsets[QSTR_NAME];
        if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &qname_addr))
        {
            PRINT_DEBUG("Can't read path->dentry->qstr->name pointer\n");
            return;
        }

        ctx.addr = qname_addr;
        gchar* res = vmi_read_str(drakvuf->vmi, &ctx);
        if (!res)
        {
            PRINT_DEBUG("Can't read path->dentry->qstr->name string\n");
            return;
        }

        g_string_prepend(b, res);
        g_string_prepend(b, "/");

        g_free(res);

        addr_t parent;
        ctx.addr = dentry + drakvuf->offsets[DENTRY_D_PARENT];
        if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &parent))
        {
            PRINT_DEBUG("Can't read path->dentry->d_parent\n");
            return;
        }

        dentry = parent;
    }
}

static bool get_fs_root_rcu(drakvuf_t drakvuf, addr_t process_base, addr_t* root)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_FS]);

    addr_t fs_struct;
    if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &fs_struct))
        return false;

    *root = fs_struct + drakvuf->offsets[FS_STRUCT_ROOT];
    return true;
}

/**
 * @brief Just implementation of https://elixir.bootlin.com/linux/v5.10.39/source/fs/d_path.c#L38
 *
 * @param drakvuf drakvuf instanse
 * @param process_base task_struct of searching process
 * @param path pointer to struct
 * @return char* - full path of binary
 */
static char* d_path(drakvuf_t drakvuf, addr_t process_base, addr_t path)
{
    addr_t root;
    if (!get_fs_root_rcu(drakvuf, process_base, &root))
        return NULL;

    GString* b = g_string_new("");
    prepend_path(drakvuf, path, root, b);
    return g_string_free(b, 0);
}

static char* linux_get_short_process_name(drakvuf_t drakvuf, addr_t process_base)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_COMM]);

    return vmi_read_str(drakvuf->vmi, &ctx);
}

static bool linux_get_process_flags(drakvuf_t drakvuf, addr_t process_base, uint64_t* pflags)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_FLAGS]);

    uint64_t flags;
    if (VMI_FAILURE == vmi_read_64(drakvuf->vmi, &ctx, &flags))
    {
        PRINT_DEBUG("Can't read flags from task_struct.\n");
        return false;
    }

    if (pflags)
        *pflags = flags;
    return true;
}

// solution: https://stackoverflow.com/questions/18658295/full-process-name-from-task-struct
static char* linux_get_full_process_name(drakvuf_t drakvuf, addr_t process_base)
{
    uint64_t flags;
    if (!linux_get_process_flags(drakvuf, process_base, &flags))
        return NULL;

    // This is a kernel thread (with null pointer to mm_struct)
    bool is_kernel_thread = (flags & PF_KTHREAD);

    if (is_kernel_thread)
        return linux_get_short_process_name(drakvuf, process_base);

    // The terminating process has no name due to the fact that its structures have already been cleared in memory
    bool is_exiting = (flags & PF_EXITING);
    if (is_exiting)
    {
        vmi_pid_t pid;
        if (linux_get_process_pid(drakvuf, process_base, &pid))
        {
            gchar tmp[32] = {0};

            if (g_snprintf(tmp, 32, "process-%d", pid))
                return g_strdup(tmp);
            else
                return NULL;
        }
        else
            return NULL;
    }

    addr_t mm_struct;
    if (!get_mm_struct(drakvuf, process_base, &mm_struct))
    {
        PRINT_DEBUG("Can't get mm_struct from task_struct\n");
        return NULL;
    }

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd,
        .addr = mm_struct + drakvuf->offsets[MM_STRUCT_EXE_FILE]);

    addr_t exe_file;
    if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &exe_file))
    {
        PRINT_DEBUG("Can't get exe_file from mm_struct\n");
        return NULL;
    }

    addr_t f_path = exe_file + drakvuf->offsets[FILE_F_PATH];
    return d_path(drakvuf, process_base, f_path);
}

char* linux_get_process_name(drakvuf_t drakvuf, addr_t process_base, bool fullpath)
{
    if (fullpath)
        return linux_get_full_process_name(drakvuf, process_base);
    return linux_get_short_process_name(drakvuf, process_base);
}

bool linux_get_process_pid(drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* pid )
{
    /*
     * On Linux PID is actually a thread ID, while the TGID (Thread Group-ID) is
     * what getpid() would return. Because THAT makes sense.
     */
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_TGID]);

    return ( VMI_SUCCESS == vmi_read_32(drakvuf->vmi, &ctx, (uint32_t*)pid) );
}

bool linux_get_process_tid(drakvuf_t drakvuf, addr_t process_base, uint32_t* tid )
{
    /*
     * On Linux TASK_STRUCT_PID is actually the thread ID.
     */
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_PID]);

    return ( VMI_SUCCESS == vmi_read_32(drakvuf->vmi, &ctx, tid) );
}

static bool linux_get_task_pid(drakvuf_t drakvuf, addr_t process_base, addr_t* thread_pid)
{
    return get_kernel_struct_field_pointer(drakvuf, process_base, TASK_STRUCT_THREAD_PID, thread_pid);
}

static bool linux_get_task_pgrp(drakvuf_t drakvuf, addr_t process_base, addr_t* struct_pid)
{
    addr_t signal;
    if (!get_kernel_struct_field_pointer(drakvuf, process_base, TASK_STRUCT_SIGNAL, &signal))
        return false;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd
    );

    ctx.addr = signal + drakvuf->offsets[SIGNAL_STRUCT_PIDS] + sizeof(addr_t) * PIDTYPE_PGID;

    if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, struct_pid))
        return false;

    return true;
}

static bool linux_get_ns_of_pid(drakvuf_t drakvuf, addr_t struct_pid, addr_t* ns)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd
    );

    uint32_t level;
    ctx.addr = struct_pid + drakvuf->offsets[PID_LEVEL];
    if (VMI_FAILURE == vmi_read_32(drakvuf->vmi, &ctx, &level))
        return false;

    // In the version before 4.15, the "struct upid" has a different size, but this version is not supported
    // https://elixir.bootlin.com/linux/v6.5.7/source/include/linux/pid.h#L54
    const uint32_t size_of_upid = 8;

    ctx.addr = struct_pid + drakvuf->offsets[PID_NUMBERS] + level * size_of_upid + drakvuf->offsets[UPID_NS];
    return ( VMI_SUCCESS == vmi_read_addr(drakvuf->vmi, &ctx, ns) );
}

static bool linux_get_pid_ns(drakvuf_t drakvuf, addr_t process_base, addr_t* ns)
{
    addr_t thread_pid;
    if (!linux_get_task_pid(drakvuf, process_base, &thread_pid))
        return false;

    return linux_get_ns_of_pid(drakvuf, thread_pid, ns);
}

/*
 * get process group id
 * by default return zero: https://elixir.bootlin.com/linux/v6.5.7/source/kernel/pid.c#L475
 */
bool linux_get_process_pgid(drakvuf_t drakvuf, addr_t process_base, uint32_t* pgid)
{
    *pgid = 0;
    const kernel_version_t* version = linux_get_kernel_version_from_process(drakvuf, process_base);
    if (version->major <= 4 && version->minor < 19)
    {
        PRINT_DEBUG("Failed to extract PGID (unsupported kernel version)\n");
        return false;
    }

    addr_t struct_pid;
    if (!linux_get_task_pgrp(drakvuf, process_base, &struct_pid))
        return false;

    addr_t ns;
    if (!linux_get_pid_ns(drakvuf, process_base, &ns))
        return false;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd
    );

    uint32_t ns_level;
    ctx.addr = ns + drakvuf->offsets[PID_NAMESPACE_LEVEL];
    if (VMI_FAILURE == vmi_read_32(drakvuf->vmi, &ctx, &ns_level))
        return false;

    uint32_t pid_level;
    ctx.addr = struct_pid + drakvuf->offsets[PID_LEVEL];
    if (VMI_FAILURE == vmi_read_32(drakvuf->vmi, &ctx, &pid_level))
        return false;

    if (ns_level <= pid_level)
    {
        // TODO: maybe ns_level incorrect (usually 0)
        addr_t upid = struct_pid + drakvuf->offsets[PID_NUMBERS] + ns_level;

        addr_t upid_ns;
        ctx.addr = upid + drakvuf->offsets[UPID_NS];
        if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &upid_ns))
            return false;

        ctx.addr = upid + drakvuf->offsets[UPID_NR];
        if (upid_ns == ns)
            return ( VMI_SUCCESS == vmi_read_32(drakvuf->vmi, &ctx, pgid) );
    }

    return true;
}


char* linux_get_current_process_name(drakvuf_t drakvuf, drakvuf_trap_info_t* info, bool fullpath)
{
    UNUSED(fullpath);
    addr_t process_base = linux_get_current_process(drakvuf, info);
    if ( !process_base )
        return NULL;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_COMM]
    );

    return vmi_read_str(drakvuf->vmi, &ctx);
}

int64_t linux_get_process_userid(drakvuf_t drakvuf, addr_t process_base)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 0,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_CRED]
    );

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

    return linux_get_process_userid(drakvuf, process_base);
}

bool linux_get_current_thread_id( drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* thread_id )
{
    addr_t process_base = linux_get_current_process(drakvuf, info);
    if ( !process_base )
        return false;

    return linux_get_process_tid(drakvuf, process_base, thread_id);
}

bool linux_get_process_ppid( drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* ppid )
{
    status_t status;
    addr_t parent_proc_base = 0;
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 0,
        .addr = process_base + drakvuf->offsets[TASK_STRUCT_REALPARENT]
    );

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

    if ( base_addr )
    {
        if ( linux_get_process_pid( drakvuf, base_addr, &proc_data->pid ) )
        {
            proc_data->name = linux_get_process_name(drakvuf, base_addr, true);
            if ( linux_get_process_ppid(drakvuf, base_addr, &proc_data->ppid))
            {
                if (drakvuf->get_userid)
                    proc_data->userid = linux_get_process_userid(drakvuf, base_addr);
                else
                    proc_data->userid = 0;
                return linux_get_process_tid(drakvuf, base_addr, &proc_data->tid);
            }
            else
                PRINT_DEBUG("Failed to gather info for %s:%u\n", proc_data->name, proc_data->pid);
        }
    }

    return false;
}

bool linux_get_process_dtb(drakvuf_t drakvuf, addr_t process_base, addr_t* dtb)
{
    // based on: https://carteryagemann.com/pid-to-cr3.html
    addr_t mm;
    if (!get_mm_struct(drakvuf, process_base, &mm))
        return false;
    if (!mm && !get_active_mm_struct(drakvuf, process_base, &mm))
        return false;
    if (!mm)
        return false;

    addr_t pgd;
    if (!get_kernel_struct_field_pointer(drakvuf, mm, MM_STRUCT_PGD, &pgd))
        return false;

    *dtb = pgd - PAGE_OFFSET;
    return true;
}


bool linux_find_process_list(drakvuf_t drakvuf, addr_t* list_head)
{
    addr_t kernel_base = drakvuf_get_kernel_base(drakvuf);
    addr_t init_task = (kernel_base - drakvuf->offsets[_TEXT]) + drakvuf->offsets[INIT_TASK];
    *list_head = init_task + drakvuf->offsets[TASK_STRUCT_TASKS];
    return true;
}

bool linux_find_next_process_list_entry(drakvuf_t drakvuf, addr_t current_list_entry, addr_t* next_list_entry)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 0,
        .addr = current_list_entry);
    return (VMI_SUCCESS == vmi_read_addr(drakvuf->vmi, &ctx, next_list_entry));
}

static addr_t linux_process_list_entry_to_process(drakvuf_t drakvuf, addr_t list_entry)
{
    return list_entry - drakvuf->offsets[TASK_STRUCT_TASKS];
}

bool linux_enumerate_processes(drakvuf_t drakvuf, void (*visitor_func)(drakvuf_t drakvuf, addr_t eprocess, void* visitor_ctx), void* visitor_ctx)
{
    addr_t list_head;
    if (!linux_find_process_list(drakvuf, &list_head))
        return false;

    addr_t current_list_entry = list_head;
    addr_t next_list_entry;

    do
    {
        addr_t process_base = linux_process_list_entry_to_process(drakvuf, current_list_entry);

        visitor_func(drakvuf, process_base, visitor_ctx);

        if (!linux_find_next_process_list_entry(drakvuf, current_list_entry, &next_list_entry))
        {
            PRINT_DEBUG("Failed to find next task!\n");
            return false;
        }
        current_list_entry = next_list_entry;
    } while (list_head != next_list_entry);

    return true;
}

static bool linux_get_process_env_start_end(drakvuf_t drakvuf, addr_t process_base, addr_t* env_start, addr_t* env_end)
{
    addr_t mm_struct;
    if (!get_mm_struct(drakvuf, process_base, &mm_struct))
        return false;

    return (get_kernel_struct_field_pointer(drakvuf, mm_struct, MM_STRUCT_ENV_START, env_start)
            && get_kernel_struct_field_pointer(drakvuf, mm_struct, MM_STRUCT_ENV_END, env_end));
}

static bool linux_get_process_environ_buffer(drakvuf_t drakvuf, addr_t process_base, addr_t process_dtb, void** buffer, size_t* size)
{
    addr_t env_start, env_end;
    if (!linux_get_process_env_start_end(drakvuf, process_base, &env_start, &env_end) ||
        !env_start || env_start >= env_end)
    {
        PRINT_DEBUG("Failed to get env_start and env_end\n");
        return false;
    }

    size_t buffer_size = env_end - env_start;
    void* _buffer = g_new0(char, buffer_size);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = process_dtb,
        .addr = env_start);

    if (VMI_SUCCESS != vmi_read(drakvuf->vmi, &ctx, buffer_size, _buffer, NULL))
    {
        PRINT_DEBUG("Failed to read environ buffer\n");
        g_free(_buffer);
        return false;
    }

    *buffer = _buffer;
    *size = buffer_size;
    return true;
}

bool linux_get_current_process_environ(drakvuf_t drakvuf, drakvuf_trap_info_t* info, GHashTable** environ)
{
    addr_t process_base = info->proc_data.base_addr;
    addr_t process_dtb = info->regs->cr3;

    void* buffer = NULL;
    size_t buffer_size = 0;
    if (!linux_get_process_environ_buffer(drakvuf, process_base, process_dtb, &buffer, &buffer_size))
        return false;

    *environ = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    for (size_t offset = 0;
        offset < buffer_size;
        offset += strlen((char*)((uint64_t)buffer + offset)) + 1)
    {
        gchar* var_str = (char*)((uint64_t)buffer + offset);
        gchar** var_kv = g_strsplit(var_str, "=", 2);
        g_hash_table_insert(*environ, g_strdup(var_kv[0]), g_strdup(var_kv[1]));
        g_strfreev(var_kv);
    }

    g_free(buffer);
    return true;
}

bool linux_get_process_arguments(drakvuf_t drakvuf, addr_t process_base, addr_t* argv)
{
    addr_t mm_struct;
    if (!get_mm_struct(drakvuf, process_base, &mm_struct))
        return false;

    *argv = mm_struct + drakvuf->offsets[MM_STRUCT_ARG_START];
    return true;
}
