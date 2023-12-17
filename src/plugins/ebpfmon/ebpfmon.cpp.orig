/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2023 Tamas K Lengyel.                                  *
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

#include "plugins/output_format.h"
#include <libdrakvuf/libdrakvuf.h>

#include "ebpfmon.h"
#include "private.h"

static const char* bpf_attr_get_type(drakvuf_t drakvuf, drakvuf_trap_info_t* info, bpf_cmd_t cmd, addr_t attr)
{
    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = attr
    );

    const char* type = nullptr;

    switch (cmd)
    {
        case BPF_MAP_CREATE:
            uint32_t map_type;
            if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &map_type))
            {
                PRINT_DEBUG("[EBPFMON] Failed to read map_type\n");
                break;
            }
            type = bpf_map_type_to_str((bpf_map_type_t)map_type);
            break;
        case BPF_PROG_LOAD:
            uint32_t prog_type;
            if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &prog_type))
            {
                PRINT_DEBUG("[EBPFMON] Failed to read prog_type\n");
                break;
            }
            type = bpf_prog_type_to_str((bpf_prog_type_t) prog_type);
            break;
        case BPF_PROG_ATTACH:
        case BPF_PROG_DETACH:
        case BPF_LINK_CREATE:
        {
            uint32_t attach_type;
            ctx.addr = attr + 8;
            if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &attach_type))
            {
                PRINT_DEBUG("[EBPFMON] Failed to read attach type\n");
                break;
            }
            type = bpf_attach_type_to_str((bpf_attach_type_t) attach_type);
            break;
        }
        case BPF_PROG_QUERY:
        {
            uint32_t attach_type;
            if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &attach_type))
            {
                PRINT_DEBUG("[EBPFMON] Failed to read attach type\n");
                break;
            }
            type = bpf_attach_type_to_str((bpf_attach_type_t) attach_type);
            break;
        }
        default:
            break;
    }

    return type;
}

event_response_t ebpfmon::sys_bpf_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    bpf_cmd_t cmd = (bpf_cmd_t) drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t attr = drakvuf_get_function_argument(drakvuf, info, 2);


    const char* bpf_cmd_str = bpf_cmd_to_str(cmd);
    const char* type = bpf_attr_get_type(drakvuf, info, cmd, attr);

    std::vector<std::pair<std::string, fmt::Aarg>> arguments;
    arguments.emplace_back("Value", fmt::Rstr(bpf_cmd_str));

    if (nullptr != type)
        arguments.emplace_back("Type", fmt::Rstr(type));

    fmt::print(this->m_output_format, "ebpfmon", drakvuf, info,
        arguments
    );

    return VMI_EVENT_RESPONSE_NONE;
}

ebpfmon::ebpfmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output)
{
    ebpfhook = createSyscallHook("__do_sys_bpf", &ebpfmon::sys_bpf_cb, "bpf");
    if (nullptr == ebpfhook)
    {
        PRINT_DEBUG("[EBPFMON] Method __do_sys_bpf not found.\n");
        return;
    }
}