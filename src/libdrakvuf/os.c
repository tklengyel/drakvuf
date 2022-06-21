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

bool fill_kernel_offsets(drakvuf_t drakvuf, size_t size, const char* names [][2])
{
    drakvuf->offsets = (addr_t*)g_try_malloc0(sizeof(addr_t) * size );
    if ( !drakvuf->offsets )
        return false;

    if (!drakvuf_get_kernel_struct_members_array_rva(
            drakvuf, names, size, drakvuf->offsets))
    {
        PRINT_DEBUG("Failed to find offsets for array of structure names and subsymbols.\n");
    }

    return true;
}

bool fill_kernel_bitfields(drakvuf_t drakvuf, size_t size, const char* names [][2])
{
    drakvuf->bitfields = (bitfield_t)g_try_malloc0(sizeof(struct bitfield) * size );
    if ( !drakvuf->bitfields )
        return false;

    for (size_t i = 0; i < size; i++)
        if (!drakvuf_get_bitfield_offset_and_size(drakvuf, names[i][0], names[i][1], &(drakvuf->bitfields[i].offset), &(drakvuf->bitfields[i].start_bit), &(drakvuf->bitfields[i].end_bit)))
        {
            PRINT_DEBUG("Failed to find offsets for of bitfield: %s:%s.\n", names[i][0], names[i][1]);
        }

    return true;
}

bool drakvuf_get_current_irql(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint8_t* irql)
{
    bool ret = false;

    if ( drakvuf->osi.get_current_irql )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_current_irql(drakvuf, info, irql);
        drakvuf_release_vmi(drakvuf);
    }
    return ret;
}

addr_t drakvuf_get_current_thread(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t ret = 0;

    if ( drakvuf->osi.get_current_thread )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_current_thread(drakvuf, info);
        drakvuf_release_vmi(drakvuf);
    }
    return ret;
}

addr_t drakvuf_get_current_thread_teb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t ret = 0;

    if ( drakvuf->osi.get_current_thread_teb )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_current_thread_teb(drakvuf, info);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

addr_t drakvuf_get_current_thread_stackbase(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t ret = 0;

    if ( drakvuf->osi.get_current_thread_stackbase )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_current_thread_stackbase(drakvuf, info);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_last_error(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* err, const char** err_str)
{
    bool ret = false;

    if ( drakvuf->osi.get_last_error )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_last_error(drakvuf, info, err, err_str);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

addr_t drakvuf_export_lib_address(drakvuf_t drakvuf, addr_t process_addr, const char* lib)
{
    addr_t ret = 0;

    if (drakvuf->osi.export_lib_address)
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.export_lib_address(drakvuf, process_addr, lib);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

addr_t drakvuf_get_current_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t ret = 0;

    if ( drakvuf->osi.get_current_process )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_current_process(drakvuf, info);
        drakvuf_lock_and_get_vmi(drakvuf);
    }

    return ret;
}

addr_t drakvuf_get_current_attached_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t ret = 0;

    if ( drakvuf->osi.get_current_attached_process )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_current_attached_process(drakvuf, info);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

char* drakvuf_get_process_name(drakvuf_t drakvuf, addr_t process_base, bool fullpath)
{
    char* ret = NULL;

    if ( drakvuf->osi.get_process_name )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_process_name(drakvuf, process_base, fullpath);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

char* drakvuf_get_process_commandline(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t eprocess_base)
{
    char* ret = NULL;

    if ( drakvuf->osi.get_process_commandline )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_process_commandline(drakvuf, info, eprocess_base);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_process_pid(drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* pid)
{
    bool ret = false;

    if ( drakvuf->osi.get_process_pid )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_process_pid(drakvuf, process_base, pid);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

typedef struct pass_context
{
    addr_t dtb;
    addr_t process;
    vmi_pid_t pid;
    bool found;
} pass_context_t;

static void process_visitor(drakvuf_t drakvuf, addr_t eprocess, void* visitor_ctx)
{
    pass_context_t* ctx = (pass_context_t*)(visitor_ctx);

    vmi_pid_t temp_pid;
    if (!drakvuf_get_process_pid(drakvuf, eprocess, &temp_pid))
    {
        PRINT_DEBUG("[LIBDRAKVUF] Failed to get process pid\n");
        return;
    }
    if (temp_pid == ctx->pid)
    {
        PRINT_DEBUG("[LIBDRAKVUF] Found remote process base! Getting dtb..\n");
        if (!drakvuf_get_process_dtb(drakvuf, eprocess, &ctx->dtb))
        {
            PRINT_DEBUG("[LIBDRAKVUF] Failed to get process dtb\n");
            return;
        }
        ctx->process = eprocess;
        ctx->found = true;
    }
}

bool drakvuf_get_process_by_handle(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint64_t handle, addr_t* process, addr_t* dtb)
{
    // Remote process
    if (handle != ~0ULL)
    {
        vmi_pid_t pid;
        if (!drakvuf_get_pid_from_handle(drakvuf, info, handle, &pid))
        {
            PRINT_DEBUG("[LIBDRAKVUF] Failed to get remote process pid\n");
            return false;
        }

        return drakvuf_get_process_by_pid(drakvuf, pid, process, dtb);
    }

    // Self process
    if (process)
        *process = info->attached_proc_data.base_addr;
    if (dtb)
        *dtb = info->regs->cr3;
    return true;
}

bool drakvuf_get_process_by_pid(drakvuf_t drakvuf, vmi_pid_t pid, addr_t* process, addr_t* dtb)
{
    pass_context_t pctx =
    {
        .pid = pid,
    };
    // Get process by pid
    drakvuf_enumerate_processes(drakvuf, process_visitor, (void*)(&pctx));

    if (pctx.found)
    {
        if (process)
            *process = pctx.process;
        if (dtb)
            *dtb = pctx.dtb;
        return true;
    }
    return false;
}

bool drakvuf_get_process_thread_id(drakvuf_t drakvuf, addr_t process_base, uint32_t* tid)
{
    bool ret = false;

    if ( drakvuf->osi.get_process_tid )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_process_tid(drakvuf, process_base, tid);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

char* drakvuf_get_current_process_name(drakvuf_t drakvuf, drakvuf_trap_info_t* info, bool fullpath)
{
    char* ret = NULL;

    if ( drakvuf->osi.get_current_process_name )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_current_process_name(drakvuf, info, fullpath);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

int64_t drakvuf_get_process_userid(drakvuf_t drakvuf, addr_t process_base)
{
    int64_t ret = ~0l;

    if ( drakvuf->osi.get_process_userid )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_process_userid(drakvuf, process_base);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

unicode_string_t* drakvuf_get_process_csdversion(drakvuf_t drakvuf, addr_t process_base)
{
    unicode_string_t* ret = NULL;

    if ( drakvuf->osi.get_process_csdversion )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_process_csdversion(drakvuf, process_base);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

int64_t drakvuf_get_current_process_userid(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    int64_t ret = ~0l;

    if ( drakvuf->osi.get_current_process_userid )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_current_process_userid(drakvuf, info);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_process_dtb(drakvuf_t drakvuf, addr_t process_base, addr_t* dtb)
{
    bool ret = false;

    if ( drakvuf->osi.get_process_dtb )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_process_dtb(drakvuf, process_base, dtb);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_current_thread_id( drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* thread_id )
{
    bool ret = false;
    if ( drakvuf->osi.get_current_thread_id )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_current_thread_id(drakvuf, info, thread_id);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}


bool drakvuf_get_thread_previous_mode( drakvuf_t drakvuf, addr_t kthread, privilege_mode_t* previous_mode )
{
    bool ret = false;

    if ( drakvuf->osi.get_thread_previous_mode )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_thread_previous_mode(drakvuf, kthread, previous_mode);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_current_thread_previous_mode( drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    privilege_mode_t* previous_mode )
{
    bool ret = false;

    if ( drakvuf->osi.get_current_thread_previous_mode )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_current_thread_previous_mode(drakvuf, info, previous_mode);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_is_thread( drakvuf_t drakvuf, addr_t dtb, addr_t thread_addr )
{
    bool ret = false;

    if ( drakvuf->osi.is_thread )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.is_thread(drakvuf, dtb, thread_addr);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_is_process( drakvuf_t drakvuf, addr_t dtb, addr_t process_addr )
{
    bool ret = false;

    if ( drakvuf->osi.is_process )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.is_process(drakvuf, dtb, process_addr);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_is_process_suspended(drakvuf_t drakvuf, addr_t process, bool* status)
{
    bool ret = false;

    if ( drakvuf->osi.is_process_suspended )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.is_process_suspended(drakvuf, process, status);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_module_list(drakvuf_t drakvuf, addr_t process_base, addr_t* module_list)
{
    bool ret = false;

    if ( drakvuf->osi.get_module_list )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_module_list(drakvuf, process_base, module_list);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_module_list_wow( drakvuf_t drakvuf, access_context_t* ctx, addr_t wow_peb, addr_t* module_list )
{
    bool ret = false;

    if ( drakvuf->osi.get_module_list_wow )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_module_list_wow(drakvuf, ctx, wow_peb, module_list);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_find_process(drakvuf_t drakvuf, vmi_pid_t find_pid, const char* find_procname, addr_t* process_addr)
{
    bool ret = false;

    if ( drakvuf->osi.find_process )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.find_process(drakvuf, find_pid, find_procname, process_addr);
        drakvuf_lock_and_get_vmi(drakvuf);
    }

    return ret;
}

bool inject_traps_modules(drakvuf_t drakvuf, drakvuf_trap_t* trap, addr_t list_head, vmi_pid_t pid)
{
    bool ret = false;

    if ( drakvuf->osi.inject_traps_modules )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.inject_traps_modules(drakvuf, trap, list_head, pid);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_module_base_addr(drakvuf_t drakvuf, addr_t module_list_head, const char* module_name, addr_t* base_addr_out)
{
    bool ret = false;

    if ( drakvuf->osi.get_module_base_addr )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_module_base_addr(drakvuf, module_list_head, module_name, base_addr_out);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_module_base_addr_ctx(drakvuf_t drakvuf, addr_t module_list_head, access_context_t* ctx, const char* module_name, addr_t* base_addr_out)
{
    bool ret = false;

    if ( drakvuf->osi.get_module_base_addr_ctx )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_module_base_addr_ctx(drakvuf, module_list_head, ctx, module_name, base_addr_out);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

addr_t drakvuf_exportksym_to_va(drakvuf_t drakvuf, const vmi_pid_t pid, const char* proc_name,
    const char* mod_name, addr_t rva)
{
    addr_t ret = 0;

    if ( drakvuf->osi.exportksym_to_va )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.exportksym_to_va(drakvuf, pid, proc_name, mod_name, rva);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

addr_t drakvuf_exportsym_to_va(drakvuf_t drakvuf, addr_t process_addr,
    const char* module, const char* sym)
{
    addr_t ret = 0;

    if ( drakvuf->osi.exportsym_to_va )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.exportsym_to_va(drakvuf, process_addr, module, sym);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_process_ppid(drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* ppid)
{
    bool ret = false;

    if ( drakvuf->osi.get_process_ppid )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_process_ppid( drakvuf, process_base, ppid );
    }

    return ret;
}

bool drakvuf_get_process_data_priv(drakvuf_t drakvuf, addr_t process_base, proc_data_priv_t* proc_data)
{
    bool ret = false;

    if ( drakvuf->osi.get_process_data )
    {
        ret = drakvuf->osi.get_process_data( drakvuf, process_base, proc_data );
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

char* drakvuf_reg_keyhandle_path(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint64_t key_handle)
{
    char* ret = NULL;

    if ( drakvuf->osi.get_registry_keyhandle_path )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_registry_keyhandle_path( drakvuf, info, key_handle );
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

char* drakvuf_get_filename_from_handle(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle)
{
    char* ret = NULL;

    if ( drakvuf->osi.get_filename_from_handle )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_filename_from_handle( drakvuf, info, handle );
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

char* drakvuf_get_filename_from_object_attributes(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t attrs)
{
    char* ret = NULL;

    if ( drakvuf->osi.get_filename_from_object_attributes )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_filename_from_object_attributes( drakvuf, info, attrs );
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_is_wow64(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    bool ret = false;

    if (drakvuf->osi.is_wow64)
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.is_wow64(drakvuf, info);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

addr_t drakvuf_get_function_argument(drakvuf_t drakvuf, drakvuf_trap_info_t* info, int narg)
{
    addr_t ret = 0;

    if ( drakvuf->osi.get_function_argument )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_function_argument( drakvuf, info, narg );
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

addr_t drakvuf_get_function_return_address(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t ret = 0;

    if ( drakvuf->osi.get_function_return_address )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_function_return_address( drakvuf, info );
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_enumerate_processes(drakvuf_t drakvuf, void (*visitor_func)(drakvuf_t drakvuf, addr_t process, void* visitor_ctx), void* visitor_ctx)
{
    bool ret = false;

    if ( drakvuf->osi.enumerate_processes )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.enumerate_processes(drakvuf, visitor_func, visitor_ctx);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_enumerate_processes_with_module(drakvuf_t drakvuf, const char* module_name, bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx), void* visitor_ctx)
{
    bool ret = false;

    if ( drakvuf->osi.enumerate_processes_with_module )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.enumerate_processes_with_module( drakvuf, module_name, visitor_func, visitor_ctx );
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_enumerate_drivers(drakvuf_t drakvuf, void (*visitor_func)(drakvuf_t drakvuf, addr_t driver, void* visitor_ctx), void* visitor_ctx)
{
    bool ret = false;

    if ( drakvuf->osi.enumerate_drivers )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.enumerate_drivers(drakvuf, visitor_func, visitor_ctx);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_enumerate_process_modules(drakvuf_t drakvuf, addr_t eprocess, bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, bool* need_free, bool* need_stop, void* visitor_ctx), void* visitor_ctx)
{
    bool ret = false;

    if ( drakvuf->osi.enumerate_process_modules )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.enumerate_process_modules( drakvuf, eprocess, visitor_func, visitor_ctx );
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_is_crashreporter(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t* pid)
{
    bool ret = false;
    *pid = 0;

    if ( drakvuf->osi.is_crashreporter )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.is_crashreporter( drakvuf, info, pid );
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_find_mmvad(drakvuf_t drakvuf, addr_t eprocess, addr_t vaddr, mmvad_info_t* out_mmvad)
{
    bool ret = false;

    if ( drakvuf->osi.find_mmvad )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.find_mmvad(drakvuf, eprocess, vaddr, out_mmvad);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_traverse_mmvad(drakvuf_t drakvuf, addr_t eprocess, mmvad_callback callback, void* callback_data)
{
    bool ret = false;

    if ( drakvuf->osi.traverse_mmvad )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.traverse_mmvad(drakvuf, eprocess, callback, callback_data);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_is_mmvad_commited(drakvuf_t drakvuf, mmvad_info_t* mmvad)
{
    bool ret = false;

    if ( drakvuf->osi.is_mmvad_commited )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.is_mmvad_commited(drakvuf, mmvad);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

uint32_t drakvuf_mmvad_type(drakvuf_t drakvuf, mmvad_info_t* mmvad)
{
    uint32_t ret = 0;

    if ( drakvuf->osi.mmvad_type )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.mmvad_type(drakvuf, mmvad);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

uint64_t drakvuf_mmvad_commit_charge(drakvuf_t drakvuf, mmvad_info_t* mmvad, uint64_t* width)
{
    uint64_t ret = 0;

    if ( drakvuf->osi.mmvad_commit_charge )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.mmvad_commit_charge(drakvuf, mmvad, width);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_pid_from_handle(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle, vmi_pid_t* pid)
{
    bool ret = false;

    if ( drakvuf->osi.get_pid_from_handle )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_pid_from_handle(drakvuf, info, handle, pid);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_tid_from_handle(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle, uint32_t* tid)
{
    bool ret = false;

    if ( drakvuf->osi.get_tid_from_handle )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_tid_from_handle(drakvuf, info, handle, tid);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_wow_context(drakvuf_t drakvuf, addr_t ethread, addr_t* wow_ctx)
{
    bool ret = false;

    if ( drakvuf->osi.get_wow_context )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_wow_context(drakvuf, ethread, wow_ctx);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_user_stack32(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* stack_ptr, addr_t* frame_ptr)
{
    bool ret = false;

    if ( drakvuf->osi.get_user_stack32 )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_user_stack32(drakvuf, info, stack_ptr, frame_ptr);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_get_user_stack64(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* stack_ptr)
{
    bool ret = false;

    if ( drakvuf->osi.get_user_stack64 )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_user_stack64(drakvuf, info, stack_ptr);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

addr_t drakvuf_get_wow_peb(drakvuf_t drakvuf, access_context_t* ctx, addr_t eprocess)
{
    addr_t ret = 0;

    if ( drakvuf->osi.get_wow_peb )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.get_wow_peb(drakvuf, ctx, eprocess);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}

bool drakvuf_check_return_context(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid, uint32_t tid, addr_t rsp)
{
    bool ret = false;

    if ( drakvuf->osi.check_return_context )
    {
        drakvuf_lock_and_get_vmi(drakvuf);
        ret = drakvuf->osi.check_return_context(info, pid, tid, rsp);
        drakvuf_release_vmi(drakvuf);
    }

    return ret;
}
