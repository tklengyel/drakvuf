/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2022 Tamas K Lengyel.                                  *
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

#include <libdrakvuf/libdrakvuf.h>
#include <libvmi/libvmi.h>
#include <algorithm>
#include "memaccessmon.h"
#include "private.h"
#include "plugins/output_format.h"
#include <fstream>

void memaccessmon::print_result(MMVAD_ENTRY* mmvad, drakvuf_trap_info_t* info)
{
    fmt::print(this->format, "memaccessmon", drakvuf, info,
        keyval("TargetName", fmt::Qstr(mmvad->process_name)),
        keyval("TargetPID", fmt::Nval(mmvad->pid)),
        keyval("FileName", fmt::Qstr(mmvad->filename)),
        keyval("Bytes", fmt::Xval(mmvad->bytes))
    );
}

static bool traverse_mmvad(drakvuf_t drakvuf, mmvad_info_t* mmvad, void* callback_data)
{
    MMVAD_CB_DATA* cb_data = static_cast<MMVAD_CB_DATA*>(callback_data);
    memaccessmon* plugin = cb_data->plugin;
    addr_t starting_va = mmvad->starting_vpn * VMI_PS_4KB;
    addr_t ending_va = mmvad->ending_vpn * VMI_PS_4KB;
    unicode_string_t* filepath = nullptr;
    std::string sFilepath = "None";
    if (mmvad->file_name_ptr)
    {
        filepath = drakvuf_read_unicode_va(drakvuf, mmvad->file_name_ptr, 0);
        if (filepath)
        {
            sFilepath = std::string((const char*) filepath->contents);
            vmi_free_unicode_str(filepath);
        }
    }

    plugin->vads[cb_data->target_pid].push_back(MMVAD_ENTRY
    {
        .starting_va = starting_va,
        .ending_va = ending_va,
        .process = cb_data->target_process,
        .pid = cb_data->target_pid,
        .filename = sFilepath,
        .bytes = cb_data->bytes,
        .process_name = drakvuf_get_process_name(drakvuf, cb_data->target_process, true)
    });

    return false;
}

event_response_t memaccessmon::readwrite_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    vmi_pid_t pid = 0;
    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t base_address = drakvuf_get_function_argument(drakvuf, info, 2);
    size_t bytes = drakvuf_get_function_argument(drakvuf, info, 4);

    // Ignore self reading
    if (handle == -1UL)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }
    if (!drakvuf_get_pid_from_handle(drakvuf, info, handle, &pid))
    {
        PRINT_DEBUG("[MEMACCESSMON] Failed to get pid from handle\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    addr_t process, dtb;
    if (!drakvuf_get_process_by_pid(drakvuf, pid, &process, &dtb))
    {
        PRINT_DEBUG("[MEMACCESSMON] Failed to get process by pid\n");
        return VMI_EVENT_RESPONSE_NONE;
    };

    if (!this->vads.count(pid))
    {
        MMVAD_CB_DATA data = MMVAD_CB_DATA
        {
            .info = info,
            .plugin = this,
            .target_pid = pid,
            .target_process = process,
            .target_va = base_address,
            .bytes = bytes
        };
        drakvuf_traverse_mmvad(drakvuf, process, traverse_mmvad, &data);
    }
    for (auto& it : vads[pid])
    {
        if (base_address >= it.starting_va && base_address <= it.ending_va)
        {
            this->print_result(&it, info);
            break;
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

memaccessmon::memaccessmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output), format(output)
{
    PRINT_DEBUG("[MEMACCESSMON] Starting initialization...\n");
    this->readHook = createSyscallHook("NtReadVirtualMemory", &memaccessmon::readwrite_cb);
    this->writeHook = createSyscallHook("NtWriteVirtualMemory", &memaccessmon::readwrite_cb);
}
