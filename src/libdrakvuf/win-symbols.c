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

#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include <libvmi/libvmi.h>
#include <json-c/json.h>
#include <glib.h>

#include "libdrakvuf.h"
#include "private.h"

status_t rekall_lookup(
        const char *rekall_profile,
        const char *symbol,
        const char *subsymbol,
        addr_t *rva,
        addr_t *size)
{
    status_t ret = VMI_FAILURE;
    addr_t mask = 0;
    if(!rekall_profile || !symbol) {
        return ret;
    }

    json_object *root = json_object_from_file(rekall_profile);
    if(!root) {
        fprintf(stderr, "Rekall profile '%s' couldn't be opened!\n", rekall_profile);
        return ret;
    }

    if(!subsymbol && !size) {
        json_object *constants = NULL, *jsymbol = NULL;
        if (!json_object_object_get_ex(root, "$CONSTANTS", &constants)) {
            PRINT_DEBUG("Rekall profile: no $CONSTANTS section found\n");
            goto exit;
        }

        if (!json_object_object_get_ex(constants, symbol, &jsymbol)){
            PRINT_DEBUG("Rekall profile: symbol '%s' not found\n", symbol);
            goto exit;
        }

        *rva = json_object_get_int64(jsymbol);

        ret = VMI_SUCCESS;

        json_object_put(jsymbol);
        json_object_put(constants);
    } else {
        json_object *structs = NULL, *jstruct = NULL, *jstruct2 = NULL, *jmember = NULL, *jvalue = NULL;
        if (!json_object_object_get_ex(root, "$STRUCTS", &structs)) {
            PRINT_DEBUG("Rekall profile: no $STRUCTS section found\n");
            goto exit;
        }
        if (!json_object_object_get_ex(structs, symbol, &jstruct)) {
            PRINT_DEBUG("Rekall profile: no '%s' found\n", symbol);
            json_object_put(structs);
            goto exit;
        }

        if (size) {
            json_object *jsize = json_object_array_get_idx(jstruct, 0);
            *size = json_object_get_int64(jsize);
            json_object_put(jsize);
            json_object_put(structs);

            ret = VMI_SUCCESS;
            goto exit;
        }

        jstruct2 = json_object_array_get_idx(jstruct, 1);
        if (!jstruct2) {
            PRINT_DEBUG("Rekall profile: struct '%s' has no second element\n", symbol);
            json_object_put(jstruct);
            json_object_put(structs);
            goto exit;
        }

        if (!json_object_object_get_ex(jstruct2, subsymbol, &jmember)) {
            PRINT_DEBUG("Rekall profile: '%s' has no '%s' member\n", symbol, subsymbol);
            json_object_put(jstruct2);
            json_object_put(jstruct);
            json_object_put(structs);
            goto exit;
        }

        jvalue = json_object_array_get_idx(jmember, 0);
        if (!jvalue) {
            PRINT_DEBUG("Rekall profile: '%s'.'%s' has no RVA defined\n", symbol, subsymbol);
            json_object_put(jmember);
            json_object_put(jstruct2);
            json_object_put(jstruct);
            json_object_put(structs);
            goto exit;
        }

        *rva = json_object_get_int64(jvalue);

        ret = VMI_SUCCESS;

        json_object_put(jmember);
        json_object_put(jstruct2);
        json_object_put(jstruct);
        json_object_put(structs);
    }

exit:
    json_object_put(root);
    return ret;
}

symbols_t* drakvuf_get_symbols_from_rekall(const char *rekall_profile)
{

    symbols_t *ret = g_malloc0(sizeof(symbols_t));;
    json_object *root = json_object_from_file(rekall_profile);
    if(!root) {
        fprintf(stderr, "Rekall profile couldn't be opened!\n");
        goto err_exit;
    }

    json_object *functions = NULL;
    if (!json_object_object_get_ex(root, "$FUNCTIONS", &functions)) {
        PRINT_DEBUG("Rekall profile: no $FUNCTIONS section found\n");
        goto err_exit;
    }

    ret->count = json_object_object_length(functions);
    ret->symbols = g_malloc0(sizeof(symbols_t) * ret->count);

    struct json_object_iterator it = json_object_iter_begin(functions);
    struct json_object_iterator itEnd = json_object_iter_end(functions);
    uint32_t i=0;

    while (!json_object_iter_equal(&it, &itEnd) && i < ret->count) {
        ret->symbols[i].name = g_strdup(json_object_iter_peek_name(&it));
        ret->symbols[i].rva = json_object_get_int64(json_object_iter_peek_value(&it));
        i++;
        json_object_iter_next(&it);
    }

    json_object_put(functions);

    return ret;

    err_exit: free(ret);
    return NULL;
}

status_t drakvuf_get_function_rva(const char *rekall_profile, const char *function, addr_t *rva)
{

    json_object *root = json_object_from_file(rekall_profile);
    if(!root) {
        fprintf(stderr, "Rekall profile couldn't be opened!\n");
        goto err_exit;
    }

    json_object *functions = NULL, *jsymbol = NULL;
    if (!json_object_object_get_ex(root, "$FUNCTIONS", &functions)) {
        PRINT_DEBUG("Rekall profile: no $FUNCTIONS section found\n");
        goto err_exit;
    }

    if (!json_object_object_get_ex(functions, function, &jsymbol)) {
        PRINT_DEBUG("Rekall profile: no '%s' found\n", function);
        json_object_put(functions);
        goto err_exit;
    }

    *rva = json_object_get_int64(jsymbol);
    json_object_put(functions);
    json_object_put(jsymbol);
    return VMI_SUCCESS;

    err_exit:
    return VMI_FAILURE;
}

status_t drakvuf_get_constant_rva(const char *rekall_profile, const char *constant, addr_t *rva)
{

    json_object *root = json_object_from_file(rekall_profile);
    if(!root) {
        fprintf(stderr, "Rekall profile couldn't be opened!\n");
        goto err_exit;
    }

    json_object *constants = NULL, *jsymbol = NULL;
    if (!json_object_object_get_ex(root, "$CONSTANTS", &constants)) {
        PRINT_DEBUG("Rekall profile: no $CONSTANTS section found\n");
        goto err_exit;
    }

    if (!json_object_object_get_ex(constants, constant, &jsymbol)) {
        PRINT_DEBUG("Rekall profile: no '%s' found\n", constant);
        json_object_put(constants);
        goto err_exit;
    }

    *rva = json_object_get_int64(jsymbol);
    json_object_put(constants);
    json_object_put(jsymbol);
    return VMI_SUCCESS;

    err_exit:
    return VMI_FAILURE;
}

void drakvuf_free_symbols(symbols_t *symbols) {
    uint32_t i;
    if (!symbols) return;

    for (i=0; i < symbols->count; i++) {
        free((char*)symbols->symbols[i].name);
    }
    free(symbols->symbols);
    free(symbols);
}
