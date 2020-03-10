/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2020 Tamas K Lengyel.                                  *
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

#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include <libvmi/libvmi.h>
#include <json-c/json.h>
#include <glib.h>

#include "libdrakvuf.h"
#include "private.h"
#include "json-profile.h"

bool json_lookup_array(
    drakvuf_t drakvuf,
    json_object* json,
    const char* symbol_subsymbol_array[][2],
    addr_t array_size,
    addr_t* rva,
    addr_t* size)
{
    bool ret = false;

    if (!json)
    {
        fprintf(stderr, "JSON profile is NULL!\n");
        return ret;
    }

    int errors = 0;
    for (size_t i = 0; i < array_size; i++)
    {
        if (!symbol_subsymbol_array[i][0])
        {
            errors++;
            continue;
        }

        if (!symbol_subsymbol_array[i][1])
        {
            if ( rva && VMI_FAILURE == vmi_get_symbol_addr_from_json(drakvuf->vmi, json, symbol_subsymbol_array[i][0], &rva[i]) )
            {
                errors++;
                PRINT_DEBUG("Failed to find address for symbol %s\n", symbol_subsymbol_array[i][0]);
            }

            if ( size && VMI_FAILURE == vmi_get_struct_size_from_json(drakvuf->vmi, json, symbol_subsymbol_array[i][0], &size[i]) )
            {
                errors++;
                PRINT_DEBUG("Failed to find address for symbol %s\n", symbol_subsymbol_array[i][0]);
            }
        }
        else if ( rva && VMI_FAILURE == vmi_get_struct_member_offset_from_json(drakvuf->vmi, json, symbol_subsymbol_array[i][0], symbol_subsymbol_array[i][1], &rva[i]) )
        {
            errors++;
            PRINT_DEBUG("Failed to find offset for %s:%s\n", symbol_subsymbol_array[i][0], symbol_subsymbol_array[i][1]);
        }
    }

    if (errors == 0)
        ret = true;

    return ret;
}

symbols_t* json_get_symbols(json_object* json)
{
    bool ist = true;

    if (!json)
    {
        fprintf(stderr, "No json object specified!\n");
        return NULL;
    }

    symbols_t* ret = (symbols_t*)g_try_malloc0(sizeof(symbols_t));
    if ( !ret )
        return NULL;

    json_object* symbols = NULL;
    if (!json_object_object_get_ex(json, "symbols", &symbols))
    {
        ist = false;
        if (!json_object_object_get_ex(json, "$FUNCTIONS", &symbols))
        {
            if (!json_object_object_get_ex(json, "$CONSTANTS", &symbols))
                goto err_exit;
        }
    }

    ret->count = json_object_object_length(symbols);
    ret->symbols = (symbol_t*)g_try_malloc0(sizeof(symbol_t) * ret->count);

    PRINT_DEBUG("JSON defines %lu symbols\n", ret->count);

    struct json_object_iterator it = json_object_iter_begin(symbols);
    struct json_object_iterator itEnd = json_object_iter_end(symbols);
    uint32_t i=0;

    while (!json_object_iter_equal(&it, &itEnd) && i < ret->count)
    {
        if ( ist )
        {
            json_object* address = NULL;

            if (!json_object_object_get_ex(json_object_iter_peek_value(&it), "address", &address))
            {
                PRINT_DEBUG("No address found for %s section found\n", json_object_iter_peek_name(&it));
                goto err_exit;
            }

            ret->symbols[i].name = g_strdup(json_object_iter_peek_name(&it));
            ret->symbols[i].rva = json_object_get_int64(address);
        }
        else
        {
            ret->symbols[i].name = g_strdup(json_object_iter_peek_name(&it));
            ret->symbols[i].rva = json_object_get_int64(json_object_iter_peek_value(&it));
        }

        /* This may not be an rva but a full VA that needs to made canonical (Linux addr) */
        if ( VMI_GET_BIT(ret->symbols[i].rva, 47) )
            ret->symbols[i].rva |= 0xffff000000000000;

        i++;
        json_object_iter_next(&it);
    }

    return ret;

err_exit:
    free(ret);
    return NULL;
}

void drakvuf_free_symbols(symbols_t* symbols)
{
    uint32_t i;
    if (!symbols) return;

    for (i=0; i < symbols->count; i++)
    {
        g_free((gchar*)symbols->symbols[i].name);
    }
    g_free(symbols->symbols);
    g_free(symbols);
}

bool drakvuf_get_kernel_symbol_rva(drakvuf_t drakvuf,
                                   const char* function,
                                   addr_t* rva)
{
    return VMI_SUCCESS == vmi_get_symbol_addr_from_json(drakvuf->vmi, vmi_get_kernel_json(drakvuf->vmi), function, rva);
}

bool drakvuf_get_kernel_struct_size(drakvuf_t drakvuf,
                                    const char* struct_name,
                                    size_t* size)
{
    return VMI_SUCCESS == vmi_get_struct_size_from_json(drakvuf->vmi, vmi_get_kernel_json(drakvuf->vmi), struct_name, size);
}

bool drakvuf_get_kernel_struct_member_rva(drakvuf_t drakvuf,
        const char* struct_name,
        const char* symbol,
        addr_t* rva)
{
    return VMI_SUCCESS == vmi_get_struct_member_offset_from_json(drakvuf->vmi, vmi_get_kernel_json(drakvuf->vmi), struct_name, symbol, rva);
}

bool json_get_symbol_rva(drakvuf_t drakvuf,
                         json_object* json,
                         const char* function,
                         addr_t* rva)
{
    return VMI_SUCCESS == vmi_get_symbol_addr_from_json(drakvuf->vmi, json, function, rva);
}

bool json_get_struct_size(drakvuf_t drakvuf,
                          json_object* json,
                          const char* struct_name,
                          size_t* size)
{
    return VMI_SUCCESS == vmi_get_struct_size_from_json(drakvuf->vmi, json, struct_name, size);
}

bool json_get_struct_member_rva(drakvuf_t drakvuf,
                                json_object* json,
                                const char* struct_name,
                                const char* symbol,
                                addr_t* rva)
{
    return VMI_SUCCESS == vmi_get_struct_member_offset_from_json(drakvuf->vmi, json, struct_name, symbol, rva);
}
