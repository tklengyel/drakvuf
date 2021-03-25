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

#include <config.h>
#include <libvmi/libvmi.h>

#include "memdump.h"
#include "private.h"

sptr_type_t check_module_linked_wow(drakvuf_t drakvuf,
    vmi_instance_t vmi,
    memdump* plugin,
    drakvuf_trap_info_t* info,
    addr_t dll_base)
{
    // WOW64 NTDLL profile not provided
    if (!plugin->dll_base_wow_rva)
        return ERROR;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    addr_t wow_peb = drakvuf_get_wow_peb(drakvuf, &ctx, info->proc_data.base_addr);

    if (!wow_peb)
        return ERROR;

    addr_t module_list_head;

    if (!drakvuf_get_module_list_wow(drakvuf, &ctx, wow_peb, &module_list_head))
        return ERROR;

    addr_t next_module = module_list_head;
    bool is_first = true;
    sptr_type_t ret = UNLINKED;

    while (1)
    {
        uint32_t tmp_next = 0;
        ctx.addr = next_module;
        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &tmp_next))
        {
            ret = ERROR;
            break;
        }

        if (module_list_head == (addr_t)tmp_next || !tmp_next)
            break;

        uint32_t tmp_dll_base;
        ctx.addr = next_module + plugin->dll_base_wow_rva;
        if (vmi_read_32(vmi, &ctx, &tmp_dll_base) == VMI_SUCCESS)
        {
            if (dll_base == (addr_t)tmp_dll_base)
            {
                ret = LINKED;
                break;
            }
        }

        next_module = (addr_t)tmp_next;
        is_first = false;
    }

    if (is_first && ret == LINKED)
        ret = MAIN;

    return ret;
}

sptr_type_t check_module_linked(drakvuf_t drakvuf,
    vmi_instance_t vmi,
    memdump* plugin,
    drakvuf_trap_info_t* info,
    addr_t dll_base)
{
    sptr_type_t sub_ret = check_module_linked_wow(drakvuf, vmi, plugin, info, dll_base);

    if (sub_ret != ERROR && sub_ret != UNLINKED)
        return sub_ret;

    addr_t module_list_head;
    if (!drakvuf_get_module_list(drakvuf, info->proc_data.base_addr, &module_list_head))
        return ERROR;

    addr_t next_module = module_list_head;
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    bool is_first = true;
    sptr_type_t ret = UNLINKED;

    while (1)
    {
        addr_t tmp_next = 0;
        ctx.addr = next_module;
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &tmp_next))
        {
            ret = ERROR;
            break;
        }

        if (module_list_head == tmp_next || !tmp_next)
            break;

        addr_t tmp_dll_base;
        ctx.addr = next_module + plugin->dll_base_rva;
        if (vmi_read_addr(vmi, &ctx, &tmp_dll_base) == VMI_SUCCESS)
        {
            if (dll_base == tmp_dll_base)
            {
                ret = LINKED;
                break;
            }
        }

        is_first = false;
        next_module = tmp_next;
    }

    if (is_first && ret == LINKED)
        ret = MAIN;

    return ret;
}
