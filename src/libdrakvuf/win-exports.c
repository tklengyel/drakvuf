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

// search for the given module+symbol in the given module list
static status_t
modlist_sym2va(drakvuf_t drakvuf, addr_t list_head, access_context_t* ctx,
               const char* mod_name, const char* symbol, addr_t* va)
{

    vmi_instance_t vmi = drakvuf->vmi;
    addr_t next_module = list_head;
    /* walk the module list */
    while (1)
    {

        /* follow the next pointer */
        addr_t tmp_next = 0;

        ctx->addr = next_module;
        if (VMI_FAILURE==vmi_read_addr(vmi, ctx, &tmp_next))
            break;

        /* if we are back at the list head, we are done */
        if (list_head == tmp_next || !tmp_next)
        {
            break;
        }

        ctx->addr = next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME];
        unicode_string_t* us = vmi_read_unicode_str(vmi, ctx);

        if ( us )
        {
            unicode_string_t out = { .contents = NULL };

            if ( VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8"))
            {
                PRINT_DEBUG("Found module %s\n", out.contents);

                if (!strcasecmp((char*) out.contents, mod_name))
                {
                    status_t ret ;
                    addr_t dllbase;

                    ctx->addr = next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE];
                    ret = vmi_read_addr(vmi, ctx, &dllbase);

                    if ( ret == VMI_SUCCESS )
                    {
                        ctx->addr = dllbase;

                        ret = vmi_translate_sym2v(vmi, ctx, (char*) symbol, va);
                        if ( ret == VMI_SUCCESS )
                            PRINT_DEBUG("\t%s @ 0x%lx\n", symbol, *va);
                    }

                    g_free(out.contents);
                    vmi_free_unicode_str(us);
                    return ret ;
                }

                g_free(out.contents);
            }

            vmi_free_unicode_str(us);
        }

        next_module = tmp_next;
    }

    return VMI_FAILURE;
}

addr_t ksym2va(drakvuf_t drakvuf, vmi_pid_t pid, const char* proc_name, const char* mod_name, addr_t rva)
{
    addr_t module_list = 0;

    if (4 == pid || !strcmp(proc_name, "System"))
    {
        if (VMI_FAILURE == vmi_read_addr_ksym(drakvuf->vmi, "PsLoadedModuleList", &module_list))
            return 0;
    }
    else
    {
        /* Process library */
        addr_t process_base;

        if ( !drakvuf_find_process(drakvuf, pid, proc_name, &process_base) )
            return 0;

        if (pid == -1)
        {
            if ( drakvuf_get_process_pid(drakvuf, process_base, &pid) == VMI_FAILURE )
                return 0;
        }

        if ( !drakvuf_get_module_list(drakvuf, process_base, &module_list) )
            return 0;
    }

    vmi_instance_t vmi = drakvuf->vmi;
    addr_t next_module = module_list;
    addr_t tmp_next;
    addr_t dllbase;

    while (1)
    {

        if ( VMI_FAILURE == vmi_read_addr_va(vmi, next_module, pid, &tmp_next) )
            break;

        if (module_list == tmp_next)
            break;

        if ( VMI_FAILURE == vmi_read_addr_va(vmi, next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE], pid, &dllbase) )
            break;

        if (!dllbase)
            break;

        unicode_string_t* us = vmi_read_unicode_str_va(vmi, next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME], pid);

        if (us)
        {
            unicode_string_t out = { .contents = NULL };
            addr_t ret_addr = 0 ;

            if (VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8") )
            {
                PRINT_DEBUG("\t%s @ 0x%" PRIx64 "\n", out.contents, dllbase);

                if ( !strcmp((char*)out.contents, mod_name) )
                    ret_addr =  dllbase + rva;

                g_free(out.contents);
            }

            vmi_free_unicode_str(us);

            if ( ret_addr )
                return ret_addr;
        }

        next_module = tmp_next;
    }

    return 0;
}

addr_t eprocess_sym2va (drakvuf_t drakvuf, addr_t eprocess_base, const char* mod_name, const char* symbol)
{
    addr_t peb, ldr, inloadorder, ret = 0;
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
    };

    if (VMI_FAILURE==vmi_read_addr_va(drakvuf->vmi, eprocess_base + drakvuf->offsets[EPROCESS_PDBASE], 0, &ctx.dtb))
        return 0;
    if (VMI_FAILURE==vmi_read_addr_va(drakvuf->vmi, eprocess_base + drakvuf->offsets[EPROCESS_PEB], 0, &peb))
        return 0;

    ctx.addr = peb + drakvuf->offsets[PEB_LDR];
    if (VMI_FAILURE==vmi_read_addr(drakvuf->vmi, &ctx, &ldr))
        return 0;

    ctx.addr = ldr + drakvuf->offsets[PEB_LDR_DATA_INLOADORDERMODULELIST];
    if (VMI_FAILURE==vmi_read_addr(drakvuf->vmi, &ctx, &inloadorder))
        return 0;

    PRINT_DEBUG("Found PEB @ 0x%lx. LDR @ 0x%lx. INLOADORDER @ 0x%lx.\n",
                peb, ldr, inloadorder);

    modlist_sym2va(drakvuf, inloadorder, &ctx, mod_name, symbol, &ret);
    return ret;
}
