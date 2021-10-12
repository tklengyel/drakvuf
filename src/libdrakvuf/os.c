/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
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
        return 0;

    if (!drakvuf_get_kernel_struct_members_array_rva(
            drakvuf, names, size, drakvuf->offsets))
    {
        PRINT_DEBUG("Failed to find offsets for array of structure names and subsymbols.\n");
    }

    return 1;
}

bool fill_kernel_bitfields(drakvuf_t drakvuf, size_t size, const char* names [][2])
{
    drakvuf->bitfields = (bitfield_t)g_try_malloc0(sizeof(struct bitfield) * size );
    if ( !drakvuf->bitfields )
        return 0;

    for (size_t i = 0; i < size; i++)
        if (!drakvuf_get_bitfield_offset_and_size(drakvuf, names[i][0], names[i][1], &(drakvuf->bitfields[i].offset), &(drakvuf->bitfields[i].start_bit), &(drakvuf->bitfields[i].end_bit)))
        {
            PRINT_DEBUG("Failed to find offsets for of bitfield: %s:%s.\n", names[i][0], names[i][1]);
        }

    return 1;
}

bool drakvuf_get_current_irql(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint8_t* irql)
{
    if ( drakvuf->osi.get_current_irql )
        return drakvuf->osi.get_current_irql(drakvuf, info, irql);
    return false;
}

addr_t drakvuf_get_current_thread(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if ( drakvuf->osi.get_current_thread )
        return drakvuf->osi.get_current_thread(drakvuf, info);

    return 0;
}

addr_t drakvuf_get_current_thread_teb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if ( drakvuf->osi.get_current_thread_teb )
        return drakvuf->osi.get_current_thread_teb(drakvuf, info);

    return 0;
}

addr_t drakvuf_get_current_thread_stackbase(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if ( drakvuf->osi.get_current_thread_stackbase )
        return drakvuf->osi.get_current_thread_stackbase(drakvuf, info);

    return 0;
}

bool drakvuf_get_last_error(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* err, const char** err_str)
{
    if ( drakvuf->osi.get_last_error )
        return drakvuf->osi.get_last_error(drakvuf, info, err, err_str);

    return false;
}

addr_t drakvuf_export_lib_address(drakvuf_t drakvuf, addr_t process_addr, const char* lib)
{
    if (drakvuf->osi.export_lib_address)
        return drakvuf->osi.export_lib_address(drakvuf, process_addr, lib);

    return 0;
}

addr_t drakvuf_get_current_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if ( drakvuf->osi.get_current_process )
        return drakvuf->osi.get_current_process(drakvuf, info);

    return 0;
}

addr_t drakvuf_get_current_attached_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if ( drakvuf->osi.get_current_attached_process )
        return drakvuf->osi.get_current_attached_process(drakvuf, info);

    return 0;
}

char* drakvuf_get_process_name(drakvuf_t drakvuf, addr_t process_base, bool fullpath)
{
    if ( drakvuf->osi.get_process_name )
        return drakvuf->osi.get_process_name(drakvuf, process_base, fullpath);

    return NULL;
}

char* drakvuf_get_process_commandline(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t eprocess_base)
{
    if ( drakvuf->osi.get_process_commandline )
        return drakvuf->osi.get_process_commandline(drakvuf, info, eprocess_base);

    return NULL;
}

bool drakvuf_get_process_pid(drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* pid)
{
    if ( drakvuf->osi.get_process_pid )
        return drakvuf->osi.get_process_pid(drakvuf, process_base, pid);

    return false;
}

typedef struct pass_context
{
    addr_t* dtb;
    addr_t* process;
    vmi_pid_t* pid;
} pass_context_t;

static void process_visitor(drakvuf_t drakvuf, addr_t eprocess, void* visitor_ctx)
{
    vmi_pid_t temp_pid;
    pass_context_t* ctx = (pass_context_t*)(visitor_ctx);

    if (!drakvuf_get_process_pid(drakvuf, eprocess, &temp_pid))
    {
        PRINT_DEBUG("[LIBDRAKVUF] Failed to get process pid\n");
        return;
    }
    if (temp_pid == *ctx->pid)
    {
        PRINT_DEBUG("[LIBDRAKVUF] Found remote process base! Getting dtb..\n");
        drakvuf_get_process_dtb(drakvuf, eprocess, ctx->dtb);
        *ctx->process = eprocess;
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
            return VMI_EVENT_RESPONSE_NONE;
        }

        pass_context_t pctx =
        {
            .pid = &pid,
            .process = process,
            .dtb = dtb
        };
        // Get process by pid
        drakvuf_enumerate_processes(drakvuf, process_visitor, (void*)(&pctx));
    }
    // Self process
    else
    {
        *process = info->attached_proc_data.base_addr;
        *dtb     = info->regs->cr3;
    }

    if (!*process || !*dtb)
        return false;
    return true;
}

bool drakvuf_get_process_by_pid(drakvuf_t drakvuf, vmi_pid_t pid, addr_t* process, addr_t* dtb)
{
    pass_context_t pctx =
    {
        .pid = &pid,
        .process = process,
        .dtb = dtb
    };
    // Get process by pid
    drakvuf_enumerate_processes(drakvuf, process_visitor, (void*)(&pctx));

    if (!*process || !*dtb)
        return false;
    return true;
}

bool drakvuf_get_process_thread_id(drakvuf_t drakvuf, addr_t process_base, uint32_t* tid)
{
    if ( drakvuf->osi.get_process_tid )
        return drakvuf->osi.get_process_tid(drakvuf, process_base, tid);

    return VMI_FAILURE;
}

char* drakvuf_get_current_process_name(drakvuf_t drakvuf, drakvuf_trap_info_t* info, bool fullpath)
{
    if ( drakvuf->osi.get_current_process_name )
        return drakvuf->osi.get_current_process_name(drakvuf, info, fullpath);

    return NULL;
}

int64_t drakvuf_get_process_userid(drakvuf_t drakvuf, addr_t process_base)
{
    if ( drakvuf->osi.get_process_userid )
        return drakvuf->osi.get_process_userid(drakvuf, process_base);

    return ~0l;
}

unicode_string_t* drakvuf_get_process_csdversion(drakvuf_t drakvuf, addr_t process_base)
{
    if ( drakvuf->osi.get_process_csdversion )
        return drakvuf->osi.get_process_csdversion(drakvuf, process_base);

    return NULL;
}

int64_t drakvuf_get_current_process_userid(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if ( drakvuf->osi.get_current_process_userid )
        return drakvuf->osi.get_current_process_userid(drakvuf, info);

    return ~0l;
}

bool drakvuf_get_process_dtb(drakvuf_t drakvuf, addr_t process_base, addr_t* dtb)
{
    if ( drakvuf->osi.get_process_dtb )
        return drakvuf->osi.get_process_dtb(drakvuf, process_base, dtb);

    return 0;
}

bool drakvuf_get_current_thread_id( drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* thread_id )
{
    if ( drakvuf->osi.get_current_thread_id )
        return drakvuf->osi.get_current_thread_id(drakvuf, info, thread_id);

    return 0;
}


bool drakvuf_get_thread_previous_mode( drakvuf_t drakvuf, addr_t kthread, privilege_mode_t* previous_mode )
{
    if ( drakvuf->osi.get_thread_previous_mode )
        return drakvuf->osi.get_thread_previous_mode(drakvuf, kthread, previous_mode);

    return 0;
}

bool drakvuf_get_current_thread_previous_mode( drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    privilege_mode_t* previous_mode )
{
    if ( drakvuf->osi.get_current_thread_previous_mode )
        return drakvuf->osi.get_current_thread_previous_mode(drakvuf, info, previous_mode);

    return 0;
}

bool drakvuf_is_thread( drakvuf_t drakvuf, addr_t dtb, addr_t thread_addr )
{
    if ( drakvuf->osi.is_thread )
        return drakvuf->osi.is_thread(drakvuf, dtb, thread_addr);

    return 0;
}

bool drakvuf_is_process( drakvuf_t drakvuf, addr_t dtb, addr_t process_addr )
{
    if ( drakvuf->osi.is_process )
        return drakvuf->osi.is_process(drakvuf, dtb, process_addr);

    return 0;
}

bool drakvuf_is_process_suspended(drakvuf_t drakvuf, addr_t process, bool* status)
{
    if ( drakvuf->osi.is_process_suspended )
        return drakvuf->osi.is_process_suspended(drakvuf, process, status);

    return false;
}

bool drakvuf_get_module_list(drakvuf_t drakvuf, addr_t process_base, addr_t* module_list)
{
    if ( drakvuf->osi.get_module_list )
        return drakvuf->osi.get_module_list(drakvuf, process_base, module_list);

    return 0;
}

bool drakvuf_get_module_list_wow( drakvuf_t drakvuf, access_context_t* ctx, addr_t wow_peb, addr_t* module_list )
{
    if ( drakvuf->osi.get_module_list_wow )
        return drakvuf->osi.get_module_list_wow(drakvuf, ctx, wow_peb, module_list);

    return 0;
}

bool drakvuf_find_process(drakvuf_t drakvuf, vmi_pid_t find_pid, const char* find_procname, addr_t* process_addr)
{
    if ( drakvuf->osi.find_process )
        return drakvuf->osi.find_process(drakvuf, find_pid, find_procname, process_addr);

    return 0;
}

bool inject_traps_modules(drakvuf_t drakvuf, drakvuf_trap_t* trap, addr_t list_head, vmi_pid_t pid)
{
    if ( drakvuf->osi.inject_traps_modules )
        return drakvuf->osi.inject_traps_modules(drakvuf, trap, list_head, pid);

    return 0;
}

bool drakvuf_get_module_base_addr(drakvuf_t drakvuf, addr_t module_list_head, const char* module_name, addr_t* base_addr_out)
{
    if ( drakvuf->osi.get_module_base_addr )
        return drakvuf->osi.get_module_base_addr(drakvuf, module_list_head, module_name, base_addr_out);

    return 0;
}

bool drakvuf_get_module_base_addr_ctx(drakvuf_t drakvuf, addr_t module_list_head, access_context_t* ctx, const char* module_name, addr_t* base_addr_out)
{
    if ( drakvuf->osi.get_module_base_addr_ctx )
        return drakvuf->osi.get_module_base_addr_ctx(drakvuf, module_list_head, ctx, module_name, base_addr_out);

    return 0;
}

addr_t drakvuf_exportksym_to_va(drakvuf_t drakvuf, const vmi_pid_t pid, const char* proc_name,
    const char* mod_name, addr_t rva)
{
    if ( drakvuf->osi.exportksym_to_va )
        return drakvuf->osi.exportksym_to_va(drakvuf, pid, proc_name, mod_name, rva);

    return 0;
}

addr_t drakvuf_exportsym_to_va(drakvuf_t drakvuf, addr_t process_addr,
    const char* module, const char* sym)
{
    if ( drakvuf->osi.exportsym_to_va )
        return drakvuf->osi.exportsym_to_va(drakvuf, process_addr, module, sym);

    return 0;
}

bool drakvuf_get_process_ppid(drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* ppid)
{
    if ( drakvuf->osi.get_process_ppid )
        return drakvuf->osi.get_process_ppid( drakvuf, process_base, ppid );

    return false;
}

bool drakvuf_get_process_data_priv(drakvuf_t drakvuf, addr_t process_base, proc_data_priv_t* proc_data)
{
    if ( drakvuf->osi.get_process_data )
        return drakvuf->osi.get_process_data( drakvuf, process_base, proc_data );

    return false;
}

char* drakvuf_reg_keyhandle_path(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint64_t key_handle)
{
    if ( drakvuf->osi.get_registry_keyhandle_path )
        return drakvuf->osi.get_registry_keyhandle_path( drakvuf, info, key_handle );

    return NULL;
}

char* drakvuf_get_filename_from_handle(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle)
{
    if ( drakvuf->osi.get_filename_from_handle )
        return drakvuf->osi.get_filename_from_handle( drakvuf, info, handle );

    return NULL;
}

bool drakvuf_is_wow64(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if (drakvuf->osi.is_wow64)
        return drakvuf->osi.is_wow64(drakvuf, info);
    return 0;
}

addr_t drakvuf_get_function_argument(drakvuf_t drakvuf, drakvuf_trap_info_t* info, int narg)
{
    if ( drakvuf->osi.get_function_argument )
        return drakvuf->osi.get_function_argument( drakvuf, info, narg );

    return 0;
}

addr_t drakvuf_get_function_return_address(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if ( drakvuf->osi.get_function_return_address )
        return drakvuf->osi.get_function_return_address( drakvuf, info );

    return 0;
}

bool drakvuf_enumerate_processes(drakvuf_t drakvuf, void (*visitor_func)(drakvuf_t drakvuf, addr_t process, void* visitor_ctx), void* visitor_ctx)
{
    if ( drakvuf->osi.enumerate_processes )
        return drakvuf->osi.enumerate_processes(drakvuf, visitor_func, visitor_ctx);

    return false;
}

bool drakvuf_enumerate_processes_with_module(drakvuf_t drakvuf, const char* module_name, bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx), void* visitor_ctx)
{
    if ( drakvuf->osi.enumerate_processes_with_module )
        return drakvuf->osi.enumerate_processes_with_module( drakvuf, module_name, visitor_func, visitor_ctx );

    return false;
}

bool drakvuf_enumerate_drivers(drakvuf_t drakvuf, void (*visitor_func)(drakvuf_t drakvuf, addr_t driver, void* visitor_ctx), void* visitor_ctx)
{
    if ( drakvuf->osi.enumerate_drivers )
        return drakvuf->osi.enumerate_drivers(drakvuf, visitor_func, visitor_ctx);

    return false;
}

bool drakvuf_enumerate_process_modules(drakvuf_t drakvuf, addr_t eprocess, bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, bool* need_free, bool* need_stop, void* visitor_ctx), void* visitor_ctx)
{
    if ( drakvuf->osi.enumerate_process_modules )
        return drakvuf->osi.enumerate_process_modules( drakvuf, eprocess, visitor_func, visitor_ctx );

    return false;
}

bool drakvuf_is_crashreporter(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t* pid)
{
    *pid = 0;

    if ( drakvuf->osi.is_crashreporter )
        return drakvuf->osi.is_crashreporter( drakvuf, info, pid );

    return false;
}

bool drakvuf_find_mmvad(drakvuf_t drakvuf, addr_t eprocess, addr_t vaddr, mmvad_info_t* out_mmvad)
{
    if ( drakvuf->osi.find_mmvad )
        return drakvuf->osi.find_mmvad(drakvuf, eprocess, vaddr, out_mmvad);

    return false;
}

bool drakvuf_traverse_mmvad(drakvuf_t drakvuf, addr_t eprocess, mmvad_callback callback, void* callback_data)
{
    if ( drakvuf->osi.traverse_mmvad )
        return drakvuf->osi.traverse_mmvad(drakvuf, eprocess, callback, callback_data);

    return false;
}

bool drakvuf_is_mmvad_commited(drakvuf_t drakvuf, mmvad_info_t* mmvad)
{
    if ( drakvuf->osi.is_mmvad_commited )
        return drakvuf->osi.is_mmvad_commited(drakvuf, mmvad);

    return false;
}

uint32_t drakvuf_mmvad_type(drakvuf_t drakvuf, mmvad_info_t* mmvad)
{
    if ( drakvuf->osi.mmvad_type )
        return drakvuf->osi.mmvad_type(drakvuf, mmvad);

    return false;
}

uint64_t drakvuf_mmvad_commit_charge(drakvuf_t drakvuf, mmvad_info_t* mmvad, uint64_t* width)
{
    if ( drakvuf->osi.mmvad_commit_charge )
        return drakvuf->osi.mmvad_commit_charge(drakvuf, mmvad, width);

    return false;
}

bool drakvuf_get_pid_from_handle(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle, vmi_pid_t* pid)
{
    if ( drakvuf->osi.get_pid_from_handle )
        return drakvuf->osi.get_pid_from_handle(drakvuf, info, handle, pid);

    return false;
}

bool drakvuf_get_tid_from_handle(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle, uint32_t* tid)
{
    if ( drakvuf->osi.get_tid_from_handle )
        return drakvuf->osi.get_tid_from_handle(drakvuf, info, handle, tid);

    return false;
}

bool drakvuf_get_wow_context(drakvuf_t drakvuf, addr_t ethread, addr_t* wow_ctx)
{
    if ( drakvuf->osi.get_wow_context )
        return drakvuf->osi.get_wow_context(drakvuf, ethread, wow_ctx);

    return 0;
}

bool drakvuf_get_user_stack32(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* stack_ptr, addr_t* frame_ptr)
{
    if ( drakvuf->osi.get_user_stack32 )
        return drakvuf->osi.get_user_stack32(drakvuf, info, stack_ptr, frame_ptr);

    return 0;
}

bool drakvuf_get_user_stack64(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* stack_ptr)
{
    if ( drakvuf->osi.get_user_stack64 )
        return drakvuf->osi.get_user_stack64(drakvuf, info, stack_ptr);

    return 0;
}

addr_t drakvuf_get_wow_peb(drakvuf_t drakvuf, access_context_t* ctx, addr_t eprocess)
{
    if ( drakvuf->osi.get_wow_peb )
        return drakvuf->osi.get_wow_peb(drakvuf, ctx, eprocess);

    return 0;
}

bool drakvuf_check_return_context(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t pid, uint32_t tid, addr_t rsp)
{
    if ( drakvuf->osi.check_return_context )
        return drakvuf->osi.check_return_context(info, pid, tid, rsp);

    return false;
}
