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
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>

#include "private.h"
#include "win-exports.h"
#include "win-offsets.h"

#define MAX_HEADER_SIZE 1024

// search for the given module+symbol in the given module list
static status_t
modlist_sym2va(drakvuf_t drakvuf, addr_t list_head, access_context_t *ctx,
               const char *mod_name, const char *symbol, addr_t *va) {

    vmi_instance_t vmi = drakvuf->vmi;
    addr_t next_module = list_head;
    /* walk the module list */
    while (1) {

        /* follow the next pointer */
        addr_t tmp_next = 0;

        ctx->addr = next_module;
        if(VMI_FAILURE==vmi_read_addr(vmi, ctx, &tmp_next))
            break;

        /* if we are back at the list head, we are done */
        if (list_head == tmp_next || !tmp_next) {
            break;
        }

        ctx->addr = next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME];
        unicode_string_t *us = vmi_read_unicode_str(vmi, ctx);
        unicode_string_t out = { .contents = NULL };

        if (us && VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8")) {

            PRINT_DEBUG("Found module %s\n", out.contents);

            if (!strcasecmp((char*) out.contents, mod_name)) {

                addr_t dllbase;

                ctx->addr = next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE];
                vmi_read_addr(vmi, ctx, &dllbase);

                ctx->addr = dllbase;
                *va = vmi_translate_sym2v(vmi, ctx, (char *) symbol);

                PRINT_DEBUG("\t%s @ 0x%lx\n", symbol, *va);

                free(out.contents);
                vmi_free_unicode_str(us);
                return VMI_SUCCESS;
            }

            free(out.contents);
        }

        if (us)
            vmi_free_unicode_str(us);

        next_module = tmp_next;
    }

    return VMI_FAILURE;
}

addr_t eprocess_sym2va (drakvuf_t drakvuf, addr_t eprocess_base, const char *mod_name, const char *symbol) {
    addr_t peb, ldr, inloadorder, ret = 0;
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
    };

    if(VMI_FAILURE==vmi_read_addr_va(drakvuf->vmi, eprocess_base + drakvuf->offsets[EPROCESS_PDBASE], 0, &ctx.dtb))
        return 0;
    if(VMI_FAILURE==vmi_read_addr_va(drakvuf->vmi, eprocess_base + drakvuf->offsets[EPROCESS_PEB], 0, &peb))
        return 0;

    ctx.addr = peb + drakvuf->offsets[PEB_LDR];
    if(VMI_FAILURE==vmi_read_addr(drakvuf->vmi, &ctx, &ldr))
        return 0;

    ctx.addr = ldr + drakvuf->offsets[PEB_LDR_DATA_INLOADORDERMODULELIST];
    if(VMI_FAILURE==vmi_read_addr(drakvuf->vmi, &ctx, &inloadorder))
        return 0;

    PRINT_DEBUG("Found PEB @ 0x%lx. LDR @ 0x%lx. INLOADORDER @ 0x%lx.\n",
                peb, ldr, inloadorder);

    modlist_sym2va(drakvuf, inloadorder, &ctx, mod_name, symbol, &ret);
    return ret;
}

addr_t sym2va(drakvuf_t drakvuf, vmi_pid_t target_pid, const char *mod_name, const char *symbol) {
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t ret = 0;
    addr_t list_head;
    status_t status;

    size_t pid_offset = vmi_get_offset(vmi, "win_pid");
    size_t tasks_offset = vmi_get_offset(vmi, "win_tasks");

    addr_t current_process, current_list_entry, next_list_entry;
    vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);

    /* walk the task list */
    list_head = current_process + tasks_offset;
    current_list_entry = list_head;

    status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
    if (status == VMI_FAILURE) {
        PRINT_DEBUG("Failed to read next pointer at 0x%lx before entering loop\n",
                current_list_entry);
        return ret;
    }

    do {
        current_list_entry = next_list_entry;
        current_process = current_list_entry - tasks_offset;

        /* follow the next pointer */

        vmi_pid_t pid = -1;
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        if (pid == target_pid) {
            return eprocess_sym2va(drakvuf, current_process, mod_name, symbol);
        }

        status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            PRINT_DEBUG("Failed to read next pointer in loop at %lx\n",
                    current_list_entry);
            return ret;
        }
    } while (next_list_entry != list_head);

    return ret;
}

// search for the given module+symbol in the given module list
static status_t
modlist_va2sym(drakvuf_t drakvuf, addr_t list_head, addr_t va,
               access_context_t *ctx, char **out_mod, char **out_sym) {

    vmi_instance_t vmi = drakvuf->vmi;
    addr_t next_module = list_head;

    /* walk the module list */
    while (1) {

        /* follow the next pointer */
        addr_t tmp_next = 0;
        ctx->addr = next_module;
        if(VMI_FAILURE == vmi_read_addr(vmi, ctx, &tmp_next))
            break;

        /* if we are back at the list head, we are done */
        if (list_head == tmp_next || !tmp_next) {
            break;
        }

        ctx->addr = next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME];
        unicode_string_t *us = vmi_read_unicode_str(vmi, ctx);
        unicode_string_t out = { .contents = NULL };

        if (us && VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8")) {
            addr_t dllbase;
            ctx->addr = next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE];
            if(VMI_FAILURE == vmi_read_addr(vmi, ctx, &dllbase)) {
                free(us);
                break;
            }

            ctx->addr = dllbase;
            const char *sym = vmi_translate_v2sym(vmi, ctx, va);

            if (sym) {
                *out_mod = g_strdup((char*)out.contents);
                *out_sym = (char*) sym;
                free(out.contents);
                vmi_free_unicode_str(us);
                return VMI_SUCCESS;
            } else {
                free(out.contents);
            }
        }

        if (us)
            vmi_free_unicode_str(us);

        next_module = tmp_next;
    }

    return VMI_FAILURE;
}

status_t va2sym(drakvuf_t drakvuf, addr_t va, vmi_pid_t target_pid,
        char **out_mod, char **out_sym) {

    vmi_instance_t vmi = drakvuf->vmi;
    addr_t list_head;

    size_t pid_offset = vmi_get_offset(vmi, "win_pid");
    size_t tasks_offset = vmi_get_offset(vmi, "win_tasks");

    addr_t current_process, current_list_entry, next_list_entry;
    vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);

    /* walk the task list */
    list_head = current_process + tasks_offset;
    current_list_entry = list_head;

    if (VMI_FAILURE == vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry)) {
        PRINT_DEBUG("Failed to read next pointer at 0x%lx before entering loop\n",
                    current_list_entry);
        return VMI_FAILURE;
    }

    do {
        current_list_entry = next_list_entry;
        current_process = current_list_entry - tasks_offset;

        /* follow the next pointer */

        addr_t peb, ldr, inloadorder;
        vmi_pid_t pid;
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        if (pid == target_pid) {

            vmi_read_addr_va(vmi, current_process + drakvuf->offsets[EPROCESS_PEB], 0, &peb);
            vmi_read_addr_va(vmi, peb + drakvuf->offsets[PEB_LDR], pid, &ldr);
            vmi_read_addr_va(vmi,
                    ldr + drakvuf->offsets[PEB_LDR_DATA_INLOADORDERMODULELIST], pid,
                    &inloadorder);

            access_context_t ctx = {
                .translate_mechanism = VMI_TM_PROCESS_PID,
                .pid = pid,
            };

            return modlist_va2sym(drakvuf, inloadorder, va, &ctx, out_mod, out_sym);
        }

        if (VMI_FAILURE
                == vmi_read_addr_va(vmi, current_list_entry, 0,
                        &next_list_entry)) {
            PRINT_DEBUG("Failed to read next pointer in loop at %lx\n",
                    current_list_entry);
            return VMI_FAILURE;
        }
    } while (next_list_entry != list_head);

    return VMI_FAILURE;
}
