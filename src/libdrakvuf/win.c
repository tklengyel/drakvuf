/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2016 Tamas K Lengyel.                                  *
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

bool win_inject_traps_modules(drakvuf_t drakvuf, drakvuf_trap_t *trap,
                              addr_t list_head, vmi_pid_t pid)
{
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t next_module = list_head;
    addr_t tmp_next;
    addr_t dllbase;

    while (1) {

        if ( VMI_FAILURE == vmi_read_addr_va(vmi, next_module, pid, &tmp_next) )
            break;

        if (list_head == tmp_next)
            break;

        if ( VMI_FAILURE == vmi_read_addr_va(vmi, next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE], pid, &dllbase) )
            break;

        if (!dllbase)
            break;

        unicode_string_t *us = vmi_read_unicode_str_va(vmi, next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME], pid);
        unicode_string_t out = { .contents = NULL };

        if (us) {
            status_t status = vmi_convert_str_encoding(us, &out, "UTF-8");
            if(VMI_SUCCESS == status)
                PRINT_DEBUG("\t%s @ 0x%" PRIx64 "\n", out.contents, dllbase);

            vmi_free_unicode_str(us);
        }

        if(out.contents && !strcmp((char*)out.contents,trap->breakpoint.module)) {
            g_free(out.contents);
            return inject_trap(drakvuf, trap, dllbase, pid);
        }

        next_module = tmp_next;
    }

    return 0;
}

bool win_get_module_base_addr( drakvuf_t drakvuf, addr_t module_list_head, const char *module_name, addr_t *base_addr_out ) {
    addr_t base_addr ;
    size_t name_len = strlen( module_name );
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t next_module = module_list_head;
    int limit = 100, counter = 0;

    while( counter < limit )
    {
        addr_t tmp_next = 0;

        if ( vmi_read_addr_va( vmi, next_module, 4, &tmp_next ) != VMI_SUCCESS )
            break;

        if ( module_list_head == tmp_next )
            break;

        base_addr = 0 ;

        if ( vmi_read_addr_va( vmi, next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE], 4, &base_addr ) != VMI_SUCCESS )
            break;

        if ( ! base_addr )
            break;

        unicode_string_t *us = vmi_read_unicode_str_va( vmi, next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME], 4 );

        if ( us )
        {
            unicode_string_t out = { 0 };
            if ( VMI_FAILURE == vmi_convert_str_encoding( us, &out, "UTF-8" ) )
            {
                vmi_free_unicode_str(us);
                break;
            }

            if ( ! strncasecmp( (char *)out.contents, module_name, name_len ) )
            {
                free( out.contents );
                vmi_free_unicode_str( us );
                *base_addr_out = base_addr ;
                return true ;
            }

            free( out.contents );
            vmi_free_unicode_str( us );
        }

        next_module = tmp_next;
        counter++;
    }

    PRINT_DEBUG("Failed to find %s in list starting at 0x%lx\n", module_name, module_list_head);
    return false ;
}

static bool find_kernbase(drakvuf_t drakvuf) {
    addr_t sysproc_rva;
    addr_t sysproc = vmi_translate_ksym2v(drakvuf->vmi, "PsInitialSystemProcess");
    if ( !sysproc ) {
        printf("LibVMI failed to get us the VA of PsInitialSystemProcess!\n");
        return 0;
    }

    if ( !drakvuf_get_constant_rva(drakvuf->rekall_profile, "PsInitialSystemProcess", &sysproc_rva) ) {
        fprintf(stderr, "Failed to get PsInitialSystemProcess RVA from Rekall profile!\n");
        return 0;
    }

    drakvuf->kernbase = sysproc - sysproc_rva;
    PRINT_DEBUG("Windows kernel base address is 0x%lx\n", drakvuf->kernbase);

    return 1;
}

bool set_os_windows(drakvuf_t drakvuf) {

    if ( !find_kernbase(drakvuf) )
        return 0;

    // Get the offsets from the Rekall profile
    if ( !fill_offsets_from_rekall(drakvuf, __WIN_OFFSETS_MAX, win_offset_names) )
        return 0;

    drakvuf->osi.get_current_thread = win_get_current_thread;
    drakvuf->osi.get_current_process = win_get_current_process;
    drakvuf->osi.get_process_name = win_get_process_name;
    drakvuf->osi.get_current_process_name = win_get_current_process_name;
    drakvuf->osi.get_process_userid = win_get_process_userid;
    drakvuf->osi.get_current_process_userid = win_get_current_process_userid;
    drakvuf->osi.get_current_thread_id = win_get_current_thread_id;
    drakvuf->osi.get_thread_previous_mode = win_get_thread_previous_mode;
    drakvuf->osi.get_current_thread_previous_mode = win_get_current_thread_previous_mode;
    drakvuf->osi.get_module_base_addr = win_get_module_base_addr;
    drakvuf->osi.is_process = win_is_eprocess;
    drakvuf->osi.is_thread = win_is_ethread;
    drakvuf->osi.get_module_list = win_get_module_list;
    drakvuf->osi.find_process = win_find_eprocess;
    drakvuf->osi.inject_traps_modules = win_inject_traps_modules;
    drakvuf->osi.exportsym_to_va = eprocess_sym2va;

    return 1;
};
