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

#include <config.h>
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
#include "win.h"
#include "win-offsets.h"
#include "win-offsets-map.h"
#include "win-wow-offsets.h"
#include "win-wow-offsets-map.h"

bool fill_wow_offsets_from_rekall( drakvuf_t drakvuf, size_t size, const char* names [][2] );

bool win_inject_traps_modules(drakvuf_t drakvuf, drakvuf_trap_t* trap,
                              addr_t list_head, vmi_pid_t pid)
{
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t next_module = list_head;
    addr_t tmp_next;
    addr_t dllbase;

    while (1)
    {

        if ( VMI_FAILURE == vmi_read_addr_va(vmi, next_module, pid, &tmp_next) )
            break;

        if (list_head == tmp_next)
            break;

        if ( VMI_FAILURE == vmi_read_addr_va(vmi, next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE], pid, &dllbase) )
            break;

        if (!dllbase)
            break;

        unicode_string_t* us = vmi_read_unicode_str_va(vmi, next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME], pid);
        unicode_string_t out = { .contents = NULL };

        if (us)
        {
            status_t status = vmi_convert_str_encoding(us, &out, "UTF-8");
            if (VMI_SUCCESS == status)
                PRINT_DEBUG("\t%s @ 0x%" PRIx64 "\n", out.contents, dllbase);

            vmi_free_unicode_str(us);
        }

        if (out.contents && !strcmp((char*)out.contents, trap->breakpoint.module))
        {
            g_free(out.contents);
            return inject_trap(drakvuf, trap, dllbase, pid);
        }

        next_module = tmp_next;
    }

    return 0;
}

bool win_get_module_base_addr_ctx(drakvuf_t drakvuf, addr_t module_list_head, access_context_t* ctx, const char* module_name, addr_t* base_addr_out)
{
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t next_module = module_list_head;
    /* walk the module list */
    while (1)
    {
        /* follow the next pointer */
        addr_t tmp_next = 0;
        ctx->addr = next_module;
        if (VMI_FAILURE == vmi_read_addr(vmi, ctx, &tmp_next))
            break;

        /* if we are back at the list head, we are done */
        if (module_list_head == tmp_next || !tmp_next)
        {
            break;
        }

        addr_t dllbase;
        ctx->addr = next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE];
        if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &dllbase) )
            break;

        bool found = false;

        ctx->addr = next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME];
        unicode_string_t* us = vmi_read_unicode_str(vmi, ctx);

        if (us)
        {
            unicode_string_t out = { .contents = NULL };
            if (VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8"))
            {
                PRINT_DEBUG("Found module %s at 0x%lx\n", out.contents, dllbase);
                found = !strcasecmp((char*) out.contents, module_name);
            }
            free(out.contents);

            vmi_free_unicode_str(us);
        }

        if (found)
        {
            *base_addr_out = dllbase;
            return true;
        }

        next_module = tmp_next;
    }

    PRINT_DEBUG("Failed to find %s in list starting at 0x%lx\n", module_name, module_list_head);
    return false;
}

bool win_get_module_base_addr(drakvuf_t drakvuf, addr_t module_list_head, const char* module_name, addr_t* base_addr_out)
{
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 4,
    };

    return win_get_module_base_addr_ctx(drakvuf, module_list_head, &ctx, module_name, base_addr_out);
}


module_info_t* win_get_module_info_ctx( drakvuf_t drakvuf, addr_t module_list_head, access_context_t* ctx, const char* module_name )
{
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t next_module = module_list_head;

    /* walk the module list */
    while (1)
    {
        /* follow the next pointer */
        addr_t tmp_next = 0;
        ctx->addr = next_module;
        if (VMI_FAILURE == vmi_read_addr(vmi, ctx, &tmp_next))
            break;

        /* if we are back at the list head, we are done */
        if (module_list_head == tmp_next || !tmp_next)
        {
            break;
        }

        module_info_t* ret_module_info = (module_info_t*)g_malloc0( sizeof( module_info_t ) );

        if ( ret_module_info )
        {
            ctx->addr = next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE];
            if ( vmi_read_addr( vmi, ctx, &ret_module_info->base_addr ) == VMI_SUCCESS )
            {
                ctx->addr                  = next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME];
                ret_module_info->base_name = drakvuf_read_unicode_common( vmi, ctx );

                if ( ret_module_info->base_name )
                {
                    PRINT_DEBUG("Found module %s at 0x%lx\n", ret_module_info->base_name->contents, ret_module_info->base_addr );

                    if ( !strcasecmp( (char*)ret_module_info->base_name->contents, module_name ) )
                    {
                        ctx->addr                  = next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_FULLDLLNAME];
                        ret_module_info->full_name = drakvuf_read_unicode_common( vmi, ctx );

                        return ret_module_info ;
                    }

                    vmi_free_unicode_str( ret_module_info->base_name );
                }
            }
            g_free( ret_module_info );
        }

        next_module = tmp_next;
    }

    PRINT_DEBUG("Failed to find %s in list starting at 0x%lx\n", module_name, module_list_head);

    return NULL;
}

module_info_t* win_get_module_info_ctx_wow( drakvuf_t drakvuf, addr_t module_list_head, access_context_t* ctx, const char* module_name )
{
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t next_module = module_list_head;

    /* walk the module list */
    while (1)
    {
        /* follow the next pointer */
        addr_t tmp_next = 0;
        ctx->addr = next_module;
        if (VMI_FAILURE == vmi_read_32(vmi, ctx, (uint32_t*)&tmp_next))
            break;

        /* if we are back at the list head, we are done */
        if (module_list_head == tmp_next || !tmp_next)
        {
            break;
        }

        module_info_t* ret_module_info = (module_info_t*)g_malloc0( sizeof( module_info_t ) );

        if ( ret_module_info )
        {
            ctx->addr = next_module + drakvuf->wow_offsets[WOW_LDR_DATA_TABLE_ENTRY_DLLBASE];
            if ( vmi_read_32( vmi, ctx, (uint32_t*)&ret_module_info->base_addr ) == VMI_SUCCESS )
            {
                ctx->addr                  = next_module + drakvuf->wow_offsets[WOW_LDR_DATA_TABLE_ENTRY_BASEDLLNAME];
                ret_module_info->base_name = drakvuf_read_unicode32_common( vmi, ctx );

                if ( ret_module_info->base_name )
                {
                    PRINT_DEBUG("Found WoW64 module %s at 0x%lx\n", ret_module_info->base_name->contents, ret_module_info->base_addr );

                    if ( !strcasecmp( (char*)ret_module_info->base_name->contents, module_name ) )
                    {
                        ctx->addr                  = next_module + drakvuf->wow_offsets[WOW_LDR_DATA_TABLE_ENTRY_FULLDLLNAME];
                        ret_module_info->full_name = drakvuf_read_unicode32_common( vmi, ctx );

                        return ret_module_info ;
                    }

                    vmi_free_unicode_str( ret_module_info->base_name );
                }
            }
            g_free( ret_module_info );
        }

        next_module = tmp_next;
    }

    PRINT_DEBUG("Failed to find %s in WoW64 list starting at 0x%lx\n", module_name, module_list_head);

    return NULL;
}

static bool find_kernbase(drakvuf_t drakvuf)
{
    addr_t sysproc_rva;
    addr_t sysproc;
    if ( VMI_FAILURE == vmi_translate_ksym2v(drakvuf->vmi, "PsInitialSystemProcess", &sysproc) )
    {
        printf("LibVMI failed to get us the VA of PsInitialSystemProcess!\n");
        return 0;
    }

    if ( !drakvuf_get_constant_rva(drakvuf, "PsInitialSystemProcess", &sysproc_rva) )
    {
        fprintf(stderr, "Failed to get PsInitialSystemProcess RVA from Rekall profile!\n");
        return 0;
    }

    drakvuf->kernbase = sysproc - sysproc_rva;
    PRINT_DEBUG("Windows kernel base address is 0x%lx\n", drakvuf->kernbase);

    return 1;
}

addr_t win_get_function_argument(drakvuf_t drakvuf, drakvuf_trap_info_t* info, int narg)
{
    page_mode_t pm = drakvuf_get_page_mode(drakvuf);
    if (pm == VMI_PM_IA32E)
    {
        switch (narg)
        {
            case 1:
                return info->regs->rcx;
            case 2:
                return info->regs->rdx;
            case 3:
                return info->regs->r8;
            case 4:
                return info->regs->r9;
        }
    }

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = info->regs->rsp + narg * drakvuf_get_address_width(drakvuf),
    };

    addr_t addr;
    if (VMI_FAILURE == vmi_read_addr(drakvuf->vmi, &ctx, &addr))
        return 0;
    return addr;
}

bool fill_wow_offsets_from_rekall( drakvuf_t drakvuf, size_t size, const char* names [][2] )
{
    drakvuf->wow_offsets = (size_t*)g_malloc0(sizeof(addr_t) * size );

    if ( !drakvuf->wow_offsets )
        return 0;

    if ( !rekall_get_struct_members_array_rva( drakvuf->rekall_wow_profile_json, names, size, drakvuf->wow_offsets ) )
    {
        PRINT_DEBUG("Failed to find WoW64 offsets for array of structure names and subsymbols.\n");
    }

    return 1 ;
}

bool set_os_windows(drakvuf_t drakvuf)
{

    if ( !find_kernbase(drakvuf) )
        return 0;

    // Get the offsets from the Rekall profile
    if ( !fill_offsets_from_rekall(drakvuf, __WIN_OFFSETS_MAX, win_offset_names) )
        return 0;

    drakvuf->sizes = (size_t*)g_malloc0(sizeof(size_t) * __WIN_SIZES_MAX);
    if ( !drakvuf->sizes )
        return 0;

    // Get the WoW64 offsets if WoW64 profile is provided...
    if ( drakvuf->rekall_wow_profile_json )
    {
        if ( !fill_wow_offsets_from_rekall(drakvuf, __WIN_WOW_OFFSETS_MAX, win_wow_offset_names) )
            return 0;
        PRINT_DEBUG("Loaded WoW64 offsets...\n");
    }

    if ( !drakvuf_get_struct_size(drakvuf, "_HANDLE_TABLE_ENTRY", &drakvuf->sizes[HANDLE_TABLE_ENTRY]) )
        return 0;

    drakvuf->osi.get_current_thread = win_get_current_thread;
    drakvuf->osi.get_current_process = win_get_current_process;
    drakvuf->osi.get_last_error = win_get_last_error;
    drakvuf->osi.get_process_name = win_get_process_name;
    drakvuf->osi.get_process_commandline = win_get_process_commandline;
    drakvuf->osi.get_current_process_name = win_get_current_process_name;
    drakvuf->osi.get_process_userid = win_get_process_userid;
    drakvuf->osi.get_current_process_userid = win_get_current_process_userid;
    drakvuf->osi.get_current_thread_id = win_get_current_thread_id;
    drakvuf->osi.get_thread_previous_mode = win_get_thread_previous_mode;
    drakvuf->osi.get_current_thread_previous_mode = win_get_current_thread_previous_mode;
    drakvuf->osi.get_module_base_addr = win_get_module_base_addr;
    drakvuf->osi.get_module_base_addr_ctx = win_get_module_base_addr_ctx;
    drakvuf->osi.is_process = win_is_eprocess;
    drakvuf->osi.is_thread = win_is_ethread;
    drakvuf->osi.get_module_list = win_get_module_list;
    drakvuf->osi.find_process = win_find_eprocess;
    drakvuf->osi.inject_traps_modules = win_inject_traps_modules;
    drakvuf->osi.exportksym_to_va = ksym2va;
    drakvuf->osi.exportsym_to_va = eprocess_sym2va;
    drakvuf->osi.get_process_pid = win_get_process_pid;
    drakvuf->osi.get_process_ppid = win_get_process_ppid;
    drakvuf->osi.get_process_data = win_get_process_data;
    drakvuf->osi.get_registry_keyhandle_path = win_reg_keyhandle_path;
    drakvuf->osi.get_filename_from_handle = win_get_filename_from_handle;
    drakvuf->osi.get_function_argument = win_get_function_argument;
    drakvuf->osi.enumerate_processes = win_enumerate_processes;
    drakvuf->osi.enumerate_processes_with_module = win_enumerate_processes_with_module;
    drakvuf->osi.is_crashreporter = win_is_crashreporter;
    drakvuf->osi.find_mmvad = win_find_mmvad;
    drakvuf->osi.get_pid_from_handle = win_get_pid_from_handle;
    drakvuf->osi.get_wow_context = win_get_wow_context;
    drakvuf->osi.get_user_stack32 = win_get_user_stack32;
    drakvuf->osi.get_user_stack64 = win_get_user_stack64;

    return true;
}
