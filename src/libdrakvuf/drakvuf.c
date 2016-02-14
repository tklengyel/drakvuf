/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014-2015 Tamas K Lengyel.  *
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

#include <glib.h>
#include "../xen_helper/xen_helper.h"

#include "libdrakvuf.h"
#include "private.h"
#include "vmi.h"
#include "win-symbols.h"

void drakvuf_close(drakvuf_t drakvuf) {
    if (!drakvuf)
        return;

    if (drakvuf->vmi)
        close_vmi(drakvuf);

    if (drakvuf->xen)
        xen_free_interface(drakvuf->xen);

    g_mutex_clear(&drakvuf->vmi_lock);
    free(drakvuf->dom_name);
    free(drakvuf->rekall_profile);
    free(drakvuf);
}

bool drakvuf_init(drakvuf_t *drakvuf, const char *domain, const char *rekall_profile) {

    if ( !domain || !rekall_profile )
        return 0;

    *drakvuf = g_malloc0(sizeof(struct drakvuf));
    (*drakvuf)->rekall_profile = g_strdup(rekall_profile);

    g_mutex_init(&(*drakvuf)->vmi_lock);

    if ( !xen_init_interface(&(*drakvuf)->xen) )
        goto err;

    get_dom_info((*drakvuf)->xen, domain, &(*drakvuf)->domID, &(*drakvuf)->dom_name);
    domid_t test = ~0;
    if ( (*drakvuf)->domID == test )
        goto err;

    if (!init_vmi(*drakvuf))
        goto err;

    (*drakvuf)->output = OUTPUT_DEFAULT;

    return 1;

err:
    drakvuf_close(*drakvuf);
    *drakvuf = NULL;
    return 0;
}

void drakvuf_interrupt(drakvuf_t drakvuf, int sig) {
    drakvuf->interrupted = sig;
}

void drakvuf_add_trap(drakvuf_t drakvuf, drakvuf_trap_t *trap) {

    vmi_pause_vm(drakvuf->vmi);

    if (!trap)
        goto done;

    if(g_hash_table_lookup(drakvuf->remove_traps, &trap)) {
        g_hash_table_remove(drakvuf->remove_traps, &trap);
        goto done;
    }

    if (trap->type == BREAKPOINT) {
        if(trap->lookup_type == LOOKUP_NONE) {
            inject_trap_pa(drakvuf, trap, trap->u2.addr);
            goto done;
        }

        if(trap->lookup_type == LOOKUP_PID && trap->u.pid == 4) {
            if (trap->module) {
                vmi_instance_t vmi = drakvuf->vmi;

                // Loop kernel modules
                addr_t kernel_list_head;
                vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &kernel_list_head);
                inject_traps_modules(drakvuf, NULL, trap, kernel_list_head, 4, "System");
            }

            goto done;
        }
    } else {
        inject_trap_mem(drakvuf, trap);
    }

done:
    vmi_resume_vm(drakvuf->vmi);
}

void drakvuf_add_traps(drakvuf_t drakvuf, GSList *traps) {
    addr_t kernel_list_head;
    vmi_instance_t vmi = drakvuf->vmi;
    vmi_pause_vm(vmi);

    // Loop kernel modules
    vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &kernel_list_head);
    inject_traps_modules(drakvuf, traps, NULL, kernel_list_head, 4, "System");

    // TODO TODO TODO
    /*addr_t current_process = 0, next_list_entry = 0;
    vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);

    addr_t list_head = current_process + offsets[EPROCESS_TASKS];
    addr_t current_list_entry = list_head;

    status_t status = vmi_read_addr_va(vmi, current_list_entry, 0,
            &next_list_entry);
    if (status == VMI_FAILURE) {
        PRINT_DEBUG(
                "Failed to read next pointer at 0x%"PRIx64" before entering loop\n",
                current_list_entry);
        return;
    }

    do {

        vmi_pid_t pid;
        uint32_t dtb;
        vmi_read_32_va(vmi, current_process + offsets[EPROCESS_PID], 0, (uint32_t*)&pid);
        vmi_read_32_va(vmi, current_process + offsets[EPROCESS_PDBASE], 0, &dtb);

        char *procname = vmi_read_str_va(vmi, current_process + offsets[EPROCESS_PNAME], 0);

        if (!procname) {
            goto exit;
        }

        PRINT(drakvuf, FOUND_PROCESS_STRING, pid, dtb, procname);

        free(procname);

        addr_t imagebase = 0, peb = 0, ldr = 0, modlist = 0;
        vmi_read_addr_va(vmi, current_process + offsets[EPROCESS_PEB], 0, &peb);
        vmi_read_addr_va(vmi, peb + offsets[PEB_IMAGEBASADDRESS], pid,
                &imagebase);
        vmi_read_addr_va(vmi, peb + offsets[PEB_LDR], pid, &ldr);
        vmi_read_addr_va(vmi, ldr + offsets[PEB_LDR_DATA_INLOADORDERMODULELIST],
                pid, &modlist);

        inject_traps_pe(drakvuf, traps, imagebase, pid, NULL);
        inject_traps_modules(drakvuf, traps, modlist, pid);

        current_list_entry = next_list_entry;
        current_process = current_list_entry - offsets[EPROCESS_TASKS];

        status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            PRINT_DEBUG("Failed to read next pointer in loop at %"PRIx64"\n",
                    current_list_entry);
            return;
        }

    } while (next_list_entry != list_head);*/

done:
    vmi_resume_vm(drakvuf->vmi);
    return;
}

void drakvuf_remove_trap(drakvuf_t drakvuf, drakvuf_trap_t *trap,
                         void(*free_routine)(drakvuf_trap_t *trap))
{
    if ( drakvuf->in_callback) {
        struct free_trap_wrapper *free_wrapper =
            g_hash_table_lookup(drakvuf->remove_traps, &trap);

        if (!free_wrapper) {
            free_wrapper = g_malloc0(sizeof(struct free_trap_wrapper));
            free_wrapper->free_routine = free_routine;
            free_wrapper->trap = trap;
            g_hash_table_insert(drakvuf->remove_traps,
                                g_memdup(&trap, sizeof(void*)),
                                free_wrapper);
        }

        free_wrapper->counter++;
    } else {
        remove_trap(drakvuf, trap);
        if(free_routine)
            free_routine(trap);
    }
}

void drakvuf_remove_traps(drakvuf_t drakvuf, GSList *traps) {
    while (traps) {
        remove_trap(drakvuf, traps->data);
        traps = traps->next;
    }
}

vmi_instance_t drakvuf_lock_and_get_vmi(drakvuf_t drakvuf) {
    g_mutex_lock(&drakvuf->vmi_lock);
    return drakvuf->vmi;
}

void drakvuf_release_vmi(drakvuf_t drakvuf) {
    g_mutex_unlock(&drakvuf->vmi_lock);
}

void drakvuf_pause (drakvuf_t drakvuf) {
    vmi_pause_vm(drakvuf->vmi);
}

void drakvuf_resume (drakvuf_t drakvuf) {
    vmi_resume_vm(drakvuf->vmi);
}

void drakvuf_set_output_format(drakvuf_t drakvuf, output_format_t output) {
    drakvuf->output = output;
}

output_format_t drakvuf_get_output_format(drakvuf_t drakvuf) {
    return drakvuf->output;
}

status_t drakvuf_get_struct_size(const char *rekall_profile,
                                 const char *struct_name,
                                 size_t *size)
{
    return windows_system_map_lookup(
                rekall_profile,
                struct_name,
                NULL,
                NULL,
                size);
}

status_t drakvuf_get_struct_member_rva(const char *rekall_profile,
                                       const char *struct_name,
                                       const char *symbol,
                                       addr_t *rva)
{
    return windows_system_map_lookup(
                rekall_profile,
                struct_name,
                symbol,
                rva,
                NULL);
}
