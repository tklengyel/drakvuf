/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014 Tamas K Lengyel.       *
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
#include <jansson.h>

#include "structures.h"

status_t windows_system_map_symbol_to_address(
        const char *rekall_profile,
        const char *symbol,
        const char *subsymbol,
        addr_t *address,
        addr_t *size)
{

    status_t ret = VMI_FAILURE;

    json_error_t error;
    json_t *root = json_load_file(rekall_profile, 0, &error);
    if (!root) {
        printf("Rekall profile error on line %d: %s\n", error.line, error.text);
        goto exit;
    }

    if (!json_is_object(root)) {
        printf("Rekall profile: root is not an objet\n");
        goto err_exit;
    }

    if (!subsymbol) {
        json_t *constants = json_object_get(root, "$CONSTANTS");
        json_t *jsymbol = json_object_get(constants, symbol);
        if (!jsymbol) {
            printf("Rekall profile: symbol '%s' not found\n", symbol);
            goto err_exit;
        }

        *address = json_integer_value(jsymbol);
        ret = VMI_SUCCESS;

    } else {
        json_t *structs = json_object_get(root, "$STRUCTS");
        json_t *jstruct = json_object_get(structs, symbol);
        if (!jstruct) {
            printf("Rekall profile: structure '%s' not found\n", symbol);
            goto err_exit;
        }

        if (size) {
            json_t *jsize = json_array_get(jstruct, 0);
            *size = json_integer_value(jsize);
        } else {
            json_t *jstruct2 = json_array_get(jstruct, 1);
            json_t *jmember = json_object_get(jstruct2, subsymbol);
            if (!jmember) {
                printf("Rekall profile: structure member '%s' not found\n", subsymbol);
                goto err_exit;
            }
            json_t *jvalue = json_array_get(jmember, 0);

            *address = json_integer_value(jvalue);
        }
        ret = VMI_SUCCESS;

    }

    err_exit: json_decref(root);

    exit: return ret;
}

struct sym_config* get_all_symbols(const char *rekall_profile)
{

    struct sym_config *ret = g_malloc0(sizeof(struct sym_config));

    json_error_t error;
    json_t *root = json_load_file(rekall_profile, 0, &error);
    if (!root) {
        printf("Rekall profile error on line %d: %s\n", error.line, error.text);
        goto err_exit;
    }

    if (!json_is_object(root)) {
        printf("Rekall profile: root is not an objet\n");
        goto err_exit;
    }

    json_t *constants = json_object_get(root, "$FUNCTIONS");

    ret->sym_count = json_object_size(constants);
    printf("The Rekall profile defines %lu functions\n", ret->sym_count);

    ret->syms = g_malloc0(sizeof(struct symbol) * ret->sym_count);

    const char *key;
    json_t *value;
    void *iter = json_object_iter(constants);
    int i = 0;
    while (iter) {
        key = json_object_iter_key(iter);
        value = json_object_iter_value(iter);

        ret->syms[i].name = strdup(key);
        ret->syms[i].rva = json_integer_value(value);

        /* use key and value ... */
        iter = json_object_iter_next(constants, iter);
        i++;
    }

    return ret;

    err_exit: free(ret);
    return NULL;
}
