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


#include <fstream>
#include <sstream>
#include <map>
#include <string>
#include <optional>

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <libdrakvuf/libdrakvuf.h>
#include <assert.h>

#include "userhook.hpp"
#include "uh-private.hpp"



struct eh_data_t
{
    // Arguments provided by the user.
    addr_t target_process;
    std::string dll_name;
    std::string func_name;
    callback_t cb;
    void *extra;

    // Additional data. Stored here for optimalization.
    target_hook_state state;
    vmi_pid_t target_process_pid;
    addr_t target_process_dtb;
    addr_t func_addr;

    // We need to pass this around as we need offsets.
    userhook* userhook_plugin;

    eh_data_t(userhook* userhook_plugin, addr_t target_process, vmi_pid_t target_process_pid, 
        std::string dll_name, std::string func_name, callback_t cb, void *extra):
        userhook_plugin(userhook_plugin), target_process(target_process), target_process_pid(target_process_pid),
        dll_name(dll_name), func_name(func_name), state(HOOK_FIRST_TRY), cb(cb), extra(extra){}
};


static
void free_trap(drakvuf_trap_t *trap)
{
    if (!trap)
        return;

    if (trap->data)
        delete (eh_data_t*) trap->data;

    delete trap;
}


static
bool get_dll_base(
    drakvuf_t drakvuf,
    const size_t *offsets,
    addr_t process_base,
    const std::string& dll_name,
    addr_t *res_dll_base)
{
    addr_t process_dtb = 0;
    if (!drakvuf_get_process_dtb(drakvuf, process_base, &process_dtb))
        return false;

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = process_dtb
    };
    vmi_lock_guard lg(drakvuf);

    addr_t module_list_head = 0;
    if (!drakvuf_get_module_list(drakvuf, process_base, &module_list_head))
        return false;
    addr_t act_module = module_list_head;

    do {
        // Read dll base.
        addr_t dll_base;
        ctx.addr = act_module + offsets[LDR_DATA_TABLE_ENTRY_DLLBASE];
        if (VMI_SUCCESS != vmi_read_addr(lg.vmi, &ctx, &dll_base))
            return false;

        // Read dll base name.
        ctx.addr = act_module + offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME];
        unicode_string_t* dll_name_utf16 = vmi_read_unicode_str(lg.vmi, &ctx);
        unicode_string_t dll_name_utf8 = {0};
        if (dll_name_utf16) {
            if (VMI_SUCCESS != vmi_convert_str_encoding(dll_name_utf16, &dll_name_utf8, "UTF-8")) {
                vmi_free_unicode_str(dll_name_utf16);
                return false;
            }
            vmi_free_unicode_str(dll_name_utf16);

            if (!strncmp(dll_name.c_str(), (const char*)dll_name_utf8.contents, dll_name.size())) {
                *res_dll_base = dll_base;
                return true;
            }
        }

        ctx.addr = act_module;
        if (VMI_SUCCESS != vmi_read_addr(lg.vmi, &ctx, &act_module))
            return false;

    } while (act_module != module_list_head);

    return false;
}


static
bool get_func_addr(
    drakvuf_t drakvuf,
    const size_t *offsets,
    access_context_t ctx,
    addr_t dll_base,
    const std::string &func_name,
    addr_t *res_func_addr)
{
    vmi_lock_guard lg(drakvuf);

    struct export_table et;
    ctx.addr = dll_base;
    if (VMI_SUCCESS != peparse_get_export_table(lg.vmi, &ctx, &et, nullptr, nullptr))
        return false;

    uint32_t name_pos;
    for (name_pos = 0; name_pos < et.number_of_functions; name_pos++) {
        // Read rva of exported function name.
        uint32_t func_name_rva = 0;
        ctx.addr = dll_base + et.address_of_names + name_pos * sizeof(uint32_t);
        if (VMI_SUCCESS != vmi_read_32(lg.vmi, &ctx, &func_name_rva))
            return false;
        
        // And check the name.
        ctx.addr = dll_base + func_name_rva;
        char *act_func_name = vmi_read_str(lg.vmi, &ctx);
        if (!strncmp(act_func_name, func_name.c_str(), func_name.size())) {
            // We found function we have been looking for.
            free(act_func_name);
            break;
        }
        free(act_func_name);
    }
    if (name_pos == et.number_of_functions) {
        // We havn't found the function with such name.
        return false;
    }

    uint16_t ordinal_number = 0;
    ctx.addr = dll_base + et.address_of_name_ordinals + sizeof(uint16_t) * name_pos;
    if (VMI_SUCCESS != vmi_read_16(lg.vmi, &ctx, &ordinal_number))
        return false;

    uint32_t func_addr_rva = 0;
    ctx.addr = dll_base + et.address_of_functions + ordinal_number * sizeof(uint32_t);
    if (VMI_SUCCESS != vmi_read_32(lg.vmi, &ctx, &func_addr_rva))
        return false;

    *res_func_addr = dll_base + func_addr_rva;
    return true;
}

static
event_response_t hook_process_cb(
    drakvuf_t drakvuf, 
    drakvuf_trap_info_t* info)
{
    eh_data_t *eh_data = static_cast<eh_data_t*>(info->trap->data);
    const size_t *offsets = eh_data->userhook_plugin->offsets;

    if (eh_data->state == HOOK_FIRST_TRY) {
        // This is first time we are trying to create a hook on process.
        // Find target function virtual address and store it in trap data, so we don't have to 
        // calculate it again on retry.
        addr_t dll_base = 0;
        if (!get_dll_base(drakvuf, offsets, eh_data->target_process, eh_data->dll_name, &dll_base)) {
            drakvuf_remove_trap(drakvuf, info->trap, free_trap);
            return VMI_EVENT_RESPONSE_NONE;
        }

        if (!drakvuf_get_process_dtb(drakvuf, eh_data->target_process, &eh_data->target_process_dtb)) {
            drakvuf_remove_trap(drakvuf, info->trap, free_trap);
            return VMI_EVENT_RESPONSE_NONE;
        }

        access_context_t ctx = {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = eh_data->target_process_dtb
        };
        if (!get_func_addr(drakvuf, offsets, ctx, dll_base, eh_data->func_name, &eh_data->func_addr)) {
            drakvuf_remove_trap(drakvuf, info->trap, free_trap);
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    // Now let's try to resolve physical address of the target function.
    addr_t func_pa = 0;
    vmi_lock_guard lg(drakvuf);
    if (VMI_SUCCESS != vmi_pagetable_lookup(lg.vmi, eh_data->target_process_dtb, eh_data->func_addr, &func_pa)) {
        if (eh_data->state == HOOK_PAGEFAULT_RETRY) {
            // We have already tried requesting page fault, so nothing more we can do.
            drakvuf_remove_trap(drakvuf, info->trap, free_trap);
            return VMI_EVENT_RESPONSE_NONE;
        }

        // Otherwise request page fault.
        if (VMI_SUCCESS != vmi_request_page_fault(lg.vmi, info->vcpu, eh_data->func_addr, 0)) {
            drakvuf_remove_trap(drakvuf, info->trap, free_trap);
            return VMI_EVENT_RESPONSE_NONE;
        }
        eh_data->state = HOOK_PAGEFAULT_RETRY;
        return VMI_EVENT_RESPONSE_NONE;
    }

    drakvuf_trap_t* trap = new drakvuf_trap_t();
    trap->type = BREAKPOINT;
    trap->name = eh_data->func_name.c_str();
    trap->cb = eh_data->cb;
    trap->data = eh_data->extra;
    trap->breakpoint.lookup_type = LOOKUP_NONE;
    trap->breakpoint.addr_type = ADDR_PA;
    trap->breakpoint.addr = func_pa;

    if (!drakvuf_add_trap(drakvuf, trap))
        delete trap;

    drakvuf_remove_trap(drakvuf, info->trap, free_trap);
    return VMI_EVENT_RESPONSE_NONE;
}

static
event_response_t wait_for_target_process_cb(
    drakvuf_t drakvuf, 
    drakvuf_trap_info_t* info)
{
    eh_data_t *eh_data = static_cast<eh_data_t*>(info->trap->data);
    // Wait for target_process.
    if (info->proc_data.pid != eh_data->target_process_pid)
        return VMI_EVENT_RESPONSE_NONE;

    // At this point we are is still in kernel mode, so
    // we need to place yet another trap to catch the moment when
    // target process enters usermode.
    addr_t thread = drakvuf_get_current_thread(drakvuf, info);
    if (!thread)
        return VMI_EVENT_RESPONSE_NONE;

    const size_t *offsets = eh_data->userhook_plugin->offsets;
    vmi_lock_guard lg(drakvuf);
    addr_t trap_frame = 0;
    if (VMI_SUCCESS != vmi_read_addr_va(lg.vmi, thread + offsets[KTHREAD_TRAPFRAME], 0, &trap_frame)) {
        drakvuf_remove_trap(drakvuf, info->trap, free_trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t rip = 0;
    if (VMI_SUCCESS != vmi_read_addr_va(lg.vmi, trap_frame + offsets[KTRAP_FRAME_RIP], 0, &rip)) {
        drakvuf_remove_trap(drakvuf, info->trap, free_trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    drakvuf_trap_t *trap = new drakvuf_trap_t();
    trap->type = BREAKPOINT;
    trap->name = "Hook process trap";
    trap->cb = hook_process_cb;
    trap->data = new eh_data_t(*eh_data);
    trap->breakpoint.lookup_type = LOOKUP_DTB;
    trap->breakpoint.dtb = info->regs->cr3;
    trap->breakpoint.addr_type = ADDR_VA;
    trap->breakpoint.addr = rip;
    if (!drakvuf_add_trap(drakvuf, trap)) {
        delete (eh_data_t*) trap->data;
        delete trap;
    }

    drakvuf_remove_trap(drakvuf, info->trap, free_trap);
    return VMI_EVENT_RESPONSE_NONE;
}


void userhook::request_userhook_on_exisitng_process(
    drakvuf_t drakvuf,
    addr_t target_process,
    std::string dll_name,
    std::string func_name,
    callback_t cb, 
    void *extra)
{
    // We must first switch to target_process context as we might need to use page faults.
    // We hook on context switch.
    drakvuf_trap_t *trap = new drakvuf_trap_t();
    trap->type = REGISTER;
    trap->reg = CR3;
    trap->cb = wait_for_target_process_cb;

    // Find target process pid, so we don't have to calculate it every time in the wait_for_target_process_cb.
    vmi_pid_t target_pid;
    if (!drakvuf_get_process_pid(drakvuf, target_process, &target_pid)) {
        delete trap;
        return;
    }

    trap->data = new eh_data_t(this, target_process, target_pid, dll_name, func_name, cb, extra);
    if (!drakvuf_add_trap(drakvuf, trap)) {
        free_trap(trap);
        return;
    }
}


bool drakvuf_request_userhook_on_exisitng_process(
    drakvuf_t drakvuf,
    addr_t target_process,
    std::string dll_name,
    std::string func_name,
    callback_t cb,
    void* extra)
{
    if (!instance || !instance->initialized)
    {
        return false;
    }

    instance->request_userhook_on_exisitng_process(drakvuf, target_process, dll_name, func_name, cb, extra);
    return true;
}