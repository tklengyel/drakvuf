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

#include <stdlib.h>
#include <sys/prctl.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <glib.h>

#include "private.h"
#include "linux-exports.h"
#include "linux.h"
#include "linux-offsets.h"
#include "linux-offsets-map.h"

addr_t linux_get_function_argument(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t narg)
{
    switch (narg)
    {
        case 1:
            return info->regs->rdi;
        case 2:
            return info->regs->rsi;
        case 3:
            return info->regs->rdx;
        case 4:
            return info->regs->rcx;
        case 5:
            return info->regs->r8;
        case 6:
            return info->regs->r9;
    }

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = info->regs->rsp + narg * 8
    );

    uint64_t ret;
    if (VMI_FAILURE == vmi_read_64(drakvuf->vmi, &ctx, &ret))
        return 0;
    return ret;
}

addr_t linux_get_function_return_address(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t ret_addr;
    if (VMI_FAILURE == vmi_read_addr_va(drakvuf->vmi, info->regs->rsp, 0, &ret_addr))
        return 0;
    return ret_addr;
}

bool linux_check_return_context(drakvuf_trap_info_t* info, vmi_pid_t pid, uint32_t tid, addr_t rsp)
{
    return (info->proc_data.pid == pid)
        && (info->proc_data.tid == tid)
        && (!rsp || info->regs->rip == rsp);
}

bool linux_get_kernel_symbol_rva(drakvuf_t drakvuf, const char* function, addr_t* rva)
{
    json_object* kernel_json = vmi_get_kernel_json(drakvuf->vmi);
    if (VMI_FAILURE == vmi_get_symbol_addr_from_json(drakvuf->vmi, kernel_json, function, rva))
    {
        bool find = false;
        for (uint8_t i = 0; i < 255; i++)
        {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "%s.isra.%d", function, i);
            if (VMI_SUCCESS == vmi_get_symbol_addr_from_json(drakvuf->vmi, kernel_json, tmp, rva))
            {
                find = true;
                break;
            }
        }
        if (!find)
            return false;
    }
    return true;
}

/**
 * @brief Function for extract absolute path from "struct dentry"
 * https://elixir.bootlin.com/linux/v5.9.14/source/fs/d_path.c#L329
 *
 * @param drakvuf drakvuf instanse
 * @param dentry_addr address of "struct dentry"
 * @return char* - absolute path of filename
*/
char* linux_get_filepath_from_dentry(drakvuf_t drakvuf, addr_t dentry_addr)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd);

    addr_t parent;
    GString* b = g_string_new(NULL);

    ctx.addr = dentry_addr + drakvuf->offsets[DENTRY_D_PARENT];
    while (VMI_SUCCESS == vmi_read_addr(drakvuf->vmi, &ctx, &parent) && parent != dentry_addr)
    {
        gchar* name = NULL;
        addr_t qstr_str_addr;
        ctx.addr = dentry_addr + drakvuf->offsets[DENTRY_D_NAME] + drakvuf->offsets[QSTR_NAME];
        if (VMI_SUCCESS == vmi_read_addr(drakvuf->vmi, &ctx, &qstr_str_addr))
        {
            ctx.addr = qstr_str_addr;
            name = vmi_read_str(drakvuf->vmi, &ctx);
        }

        if (name == NULL)
            break;

        g_string_prepend(b, name);
        g_string_prepend(b, "/");

        g_free(name);

        dentry_addr = parent;
        ctx.addr = dentry_addr + drakvuf->offsets[DENTRY_D_PARENT];
    }

    return g_string_free(b, 0);
}

bool linux_get_kernel_symbol_va(drakvuf_t drakvuf, const char* function, addr_t* va)
{
    if (!linux_get_kernel_symbol_rva(drakvuf, function, va))
        return false;

    addr_t _text;
    if (!linux_get_kernel_symbol_rva(drakvuf, "_text", &_text))
        return false;

    addr_t kaslr = drakvuf->kernbase - _text;
    if (!kaslr)
        return false;

    *va += kaslr;
    return true;
}

#ifdef DRAKVUF_DEBUG
static char* linux_get_banner(drakvuf_t drakvuf)
{
    addr_t linux_banner_addr;
    if (!linux_get_kernel_symbol_va(drakvuf, "linux_banner", &linux_banner_addr))
    {
        PRINT_DEBUG("Failed to receive addr of linux banner\n");
        return NULL;
    }

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd,
        .addr = linux_banner_addr);

    return vmi_read_str(drakvuf->vmi, &ctx);
}
#endif

static char* linux_read_kernel_version(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t process_base = linux_get_current_process(drakvuf, info);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = drakvuf->kpgd);

    ctx.addr = process_base + drakvuf->offsets[TASK_STRUCT_NSPROXY];
    addr_t nsproxy_addr;
    if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &nsproxy_addr))
        return NULL;

    ctx.addr = nsproxy_addr + drakvuf->offsets[NSPROXY_UTS_NS];
    addr_t uts_ns_addr;
    if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &uts_ns_addr))
        return NULL;

    ctx.addr = uts_ns_addr + drakvuf->offsets[UTS_NAMESPACE_NAME] + drakvuf->offsets[NEW_UTSNAME_RELEASE];
    return vmi_read_str(drakvuf->vmi, &ctx);
}

const kernel_version_t* linux_get_kernel_version(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if (!drakvuf->kernel_ver_initialized)
    {
        char* version = linux_read_kernel_version(drakvuf, info);
        if (!version)
        {
            PRINT_DEBUG("Failed to extract linux kernel version\n");
            return NULL;
        }

        int major, minor, patch;
        int scanned = sscanf(version, "%d.%d.%d", &major, &minor, &patch);
        g_free(version);

        if (scanned == 3)
        {
            drakvuf->kernel_ver.major = major;
            drakvuf->kernel_ver.minor = minor;
            drakvuf->kernel_ver.patch = patch;
            drakvuf->kernel_ver_initialized = true;
        }
    }
    return &drakvuf->kernel_ver;
}

static bool find_kernbase(drakvuf_t drakvuf)
{
    if ( VMI_FAILURE == vmi_translate_ksym2v(drakvuf->vmi, "_text", &drakvuf->kernbase) )
        return 0;

    return !!drakvuf->kernbase;
}

bool set_os_linux(drakvuf_t drakvuf)
{
    if ( !find_kernbase(drakvuf) )
        return 0;

    if ( !drakvuf->kpgd && VMI_FAILURE == vmi_get_offset(drakvuf->vmi, "kpgd", &drakvuf->kpgd) )
        return 0;

    // Get the offsets from the Rekall profile
    if ( !fill_kernel_offsets(drakvuf, __LINUX_OFFSETS_MAX, linux_offset_names) )
        return 0;

    drakvuf->osi.get_current_thread = linux_get_current_thread;
    drakvuf->osi.get_current_process = linux_get_current_process;
    drakvuf->osi.get_process_name = linux_get_process_name;
    drakvuf->osi.get_current_process_name = linux_get_current_process_name;
    drakvuf->osi.get_process_userid = linux_get_process_userid;
    drakvuf->osi.get_current_process_userid = linux_get_current_process_userid;
    drakvuf->osi.get_current_thread_id = linux_get_current_thread_id;
    drakvuf->osi.get_process_pid = linux_get_process_pid;
    drakvuf->osi.get_process_tid = linux_get_process_tid;
    drakvuf->osi.get_process_ppid = linux_get_process_ppid;
    drakvuf->osi.get_process_data = linux_get_process_data;
    drakvuf->osi.get_process_dtb = linux_get_process_dtb;
    drakvuf->osi.exportsym_to_va = linux_eprocess_sym2va;
    drakvuf->osi.export_lib_address = get_lib_address;
    drakvuf->osi.get_function_argument = linux_get_function_argument;
    drakvuf->osi.get_function_return_address = linux_get_function_return_address;
    drakvuf->osi.check_return_context = linux_check_return_context;
    drakvuf->osi.enumerate_processes = linux_enumerate_processes;
    drakvuf->osi.get_current_process_environ = linux_get_current_process_environ;
    drakvuf->osi.get_process_arguments = linux_get_process_arguments;
    drakvuf->osi.get_kernel_symbol_rva = linux_get_kernel_symbol_rva;
    drakvuf->osi.get_kernel_symbol_va = linux_get_kernel_symbol_va;
    drakvuf->osi.get_kernel_version = linux_get_kernel_version;
    drakvuf->osi.get_filepath_from_dentry = linux_get_filepath_from_dentry;

    PRINT_DEBUG("LINUX BANNER: %s", linux_get_banner(drakvuf));

    return 1;
}
