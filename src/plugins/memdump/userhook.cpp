/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  *
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

/**
 * User mode hooking module of MEMDUMP plugin.
 *
 * (1) Observes when a process is loading a new DLL through the side effects
 * of NtMapViewOfSection or NtProtectVirtualMemory being called.
 * (2) Finds the DLL export information and checks if it's fully readable,
 * if not, triggers a page fault to force system to load it into memory.
 * (3) Translates given export symbols to virtual addresses, checks if
 * the underlying memory is available (if not, again triggers page fault)
 * and finally adds a standard DRAKVUF trap.
 */

#include <fstream>
#include <sstream>

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <assert.h>

#include "memdump.h"
#include "private.h"

static event_response_t usermode_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;

    if (target->pid != info->proc_data.pid)
        return VMI_EVENT_RESPONSE_NONE;

    PRINT_DEBUG("[MEMDUMP-USER] Usermode callback called %d!%s\n", info->proc_data.pid, info->trap->name);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    bool is_syswow = false;
    addr_t wow_ctx;

    addr_t ethread = drakvuf_get_current_thread(drakvuf, info);

    if (drakvuf_get_wow_context(drakvuf, ethread, &wow_ctx))
    {
        is_syswow = true;
    }

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = info->regs->rsp
    };

    bool success = false;
    addr_t ret_addr = 0;

    if (is_syswow)
    {
        uint32_t ret_addr_tmp;

        if (vmi_read_32(vmi, &ctx, &ret_addr_tmp) == VMI_SUCCESS)
        {
            success = true;
            ret_addr = ret_addr_tmp;
        }
    }
    else
    {
        success = vmi_read_64(vmi, &ctx, &ret_addr) == VMI_SUCCESS;
    }

    PRINT_DEBUG("[MEMDUMP] Return address %llx\n", (unsigned long long)ret_addr);
    drakvuf_release_vmi(drakvuf);

    mmvad_info_t mmvad;
    if (!drakvuf_find_mmvad(drakvuf, info->proc_data.base_addr, ret_addr, &mmvad))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to find MMVAD\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    ctx.addr = mmvad.starting_vpn << 12;
    size_t buffer_size = (mmvad.ending_vpn - mmvad.starting_vpn + 1) << 12;

    if (!dump_memory_region(drakvuf, vmi, info, target->plugin, &ctx, buffer_size, "Usermode heuristic", nullptr, nullptr))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
    }

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * Check if this thread is currently in process of loading a DLL.
 * If so, return a pointer to the associated metadata.
 */
static user_dll_t* get_pending_dll(drakvuf_t drakvuf, drakvuf_trap_info* info, memdump* plugin)
{
    uint32_t thread_id;
    if (!drakvuf_get_current_thread_id(drakvuf, info, &thread_id))
        return nullptr;

    auto vec_it = plugin->loaded_dlls.find(info->regs->cr3);

    if (vec_it == plugin->loaded_dlls.end())
        return nullptr;

    for (auto& dll_meta : vec_it->second)
    {
        if (!dll_meta.is_hooked && dll_meta.thread_id == thread_id)
            return &dll_meta;
    }

    return nullptr;
}

static bool populate_hook_targets(drakvuf_t drakvuf, memdump* plugin, const mmvad_info_t& mmvad, user_dll_t* dll_meta)
{
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    unicode_string_t* dll_name = drakvuf_read_unicode_va(vmi, mmvad.file_name_ptr, 0);

    if (dll_name && dll_name->contents)
    {
        for (auto const& wanted_hook : plugin->wanted_hooks)
        {
            if (strstr((const char*) dll_name->contents, wanted_hook.dll_name.c_str()) != 0)
            {
                dll_meta->targets.emplace_back(wanted_hook.function_name.c_str(), usermode_hook_cb, plugin);
            }
        }
    }

    if (dll_name)
        vmi_free_unicode_str(dll_name);

    drakvuf_release_vmi(drakvuf);
    return !dll_meta->targets.empty();
}

/**
 * Check if DLL is interesting, if so, build a "hooking context" of a DLL. Such context is needed,
 * because user mode hooking is a stateful operation which requires a VM to be un-paused many times.
 */
static user_dll_t* create_dll_meta(drakvuf_t drakvuf, drakvuf_trap_info* info, memdump* plugin, addr_t dll_base)
{
    mmvad_info_t mmvad;
    if (!drakvuf_find_mmvad(drakvuf, info->proc_data.base_addr, dll_base, &mmvad))
        return nullptr;

    if (mmvad.file_name_ptr == 0)
        return nullptr;

    auto vec_it = plugin->loaded_dlls.find(info->regs->cr3);

    if (vec_it != plugin->loaded_dlls.end())
    {
        for (auto const& dll_meta : vec_it->second)
        {
            if (dll_meta.real_dll_base == mmvad.starting_vpn << 12)
            {
                PRINT_DEBUG("[MEMDUMP-USER] DLL %d!%llx is already hooked\n", info->proc_data.pid, (unsigned long long)mmvad.starting_vpn << 12);
                return nullptr;
            }
        }
    }

    uint32_t thread_id;
    if (!drakvuf_get_current_thread_id(drakvuf, info, &thread_id))
        return nullptr;

    user_dll_t dll_meta =
    {
        .dtb = info->regs->cr3,
        .thread_id = thread_id,
        .real_dll_base = (mmvad.starting_vpn << 12),
        .is_hooked = false
    };

    if (!populate_hook_targets(drakvuf, plugin, mmvad, &dll_meta))
        return nullptr;

    PRINT_DEBUG("[MEMDUMP-USER] Found DLL which is worth processing %llx\n", (unsigned long long)mmvad.starting_vpn << 12);
    addr_t vad_start = mmvad.starting_vpn << 12;
    size_t vad_length = (mmvad.ending_vpn - mmvad.starting_vpn + 1) << 12;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = vad_start
    };

    addr_t export_header_rva = 0;
    size_t export_header_size = 0;

    constexpr int MAX_HEADER_BYTES = 1024;   // keep under 1 page
    uint8_t image[MAX_HEADER_BYTES];

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool status = (VMI_SUCCESS == peparse_get_image(vmi, &ctx, MAX_HEADER_BYTES, image));
    drakvuf_release_vmi(drakvuf);

    if (!status)
        return nullptr;

    void* optional_header = NULL;
    uint16_t magic = 0;

    peparse_assign_headers(image, NULL, NULL, &magic, &optional_header, NULL, NULL);
    export_header_rva = peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_EXPORT, &magic, optional_header, NULL, NULL);
    export_header_size = peparse_get_idd_size(IMAGE_DIRECTORY_ENTRY_EXPORT, &magic, optional_header, NULL, NULL);

    if (export_header_rva >= vad_length)
    {
        PRINT_DEBUG("[MEMDUMP-USER] Export header RVA is forwarded outside VAD\n");
        return nullptr;
    }
    else if (export_header_size >= vad_length - export_header_rva)
    {
        PRINT_DEBUG("[MEMDUMP-USER] Export header size is forwarded outside VAD\n");
        return nullptr;
    }

    dll_meta.pf_current_addr = vad_start + export_header_rva & ~(VMI_PS_4KB - 1);
    dll_meta.pf_max_addr = vad_start + export_header_rva + export_header_size;

    if (dll_meta.pf_max_addr & VMI_PS_4KB)
    {
        dll_meta.pf_max_addr += VMI_PS_4KB;
        dll_meta.pf_max_addr = dll_meta.pf_max_addr & ~(VMI_PS_4KB - 1);
    }

    auto it = plugin->loaded_dlls.emplace(info->regs->cr3, std::vector<user_dll_t>()).first;
    it->second.push_back(std::move(dll_meta));
    return &it->second.back();
}

static bool make_trap(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info* info, hook_target_entry_t* target, addr_t exec_func)
{
    target->pid = info->proc_data.pid;

    drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    trap->type = BREAKPOINT;
    trap->name = target->target_name.c_str();
    trap->cb = target->callback;
    trap->data = target;

    // during CoW we need to find all traps placed on the same physical page
    // that's why we'll manually resolve vaddr and strore paddr under trap->breakpoint.addr
    addr_t pa = vmi_pagetable_lookup(vmi, info->regs->cr3, exec_func);

    if (pa == 0)
    {
        goto fail;
    }

    trap->breakpoint.lookup_type = LOOKUP_NONE;
    trap->breakpoint.addr_type = ADDR_PA;
    trap->breakpoint.addr = pa;

    if (drakvuf_add_trap(drakvuf, trap))
    {
        target->trap = trap;
        return true;
    }

fail:
    PRINT_DEBUG("[MEMDUMP-USER] Failed to add trap :(\n");
    return false;
}

static event_response_t perform_hooking(drakvuf_t drakvuf, drakvuf_trap_info* info, memdump* plugin, user_dll_t* dll_meta)
{
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    // we have to make sure that addresses between [pf_current_addr, pf_max_addr]
    // are available for reading otherwise vmi_translate_sym2v will fail unconditionally
    // and we will be unable to add hooks

    while (dll_meta->pf_current_addr <= dll_meta->pf_max_addr)
    {
        page_info_t pinfo;
        addr_t pa;
        if (vmi_pagetable_lookup_extended(vmi, info->regs->cr3, dll_meta->pf_current_addr, &pinfo) == VMI_SUCCESS)
        {
            PRINT_DEBUG("[MEMDUMP-USER] Export info accessible OK %llx\n", (unsigned long long)dll_meta->pf_current_addr);
            dll_meta->pf_current_addr += VMI_PS_4KB;
            continue;
        }

        pa = pinfo.paddr;

        if (vmi_request_page_fault(vmi, info->vcpu, dll_meta->pf_current_addr, 0) == VMI_SUCCESS)
        {
            PRINT_DEBUG("[MEMDUMP-USER] Export info not accessible, page fault %llx\n", (unsigned long long)dll_meta->pf_current_addr);
            dll_meta->pf_current_addr += VMI_PS_4KB;
        }
        else
        {
            PRINT_DEBUG("[MEMDUMP-USER] Failed to request page fault for DTB %llx, address %llx\n", (unsigned long long)info->regs->cr3, (unsigned long long)dll_meta->pf_current_addr);
        }

        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // export info should be available, try hooking DLLs
    for (auto& target : dll_meta->targets)
    {
        if (target.state == HOOK_FIRST_TRY || target.state == HOOK_PAGEFAULT_RETRY)
        {
            addr_t exec_func;
            access_context_t ctx =
            {
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3,
                .addr = dll_meta->real_dll_base
            };

            status_t translate_ret = vmi_translate_sym2v(vmi, &ctx, target.target_name.c_str(), &exec_func);

            if (translate_ret == VMI_SUCCESS && target.state == HOOK_FIRST_TRY)
            {
                target.state = HOOK_FAILED;

                page_info_t pinfo;
                if (vmi_pagetable_lookup_extended(vmi, info->regs->cr3, exec_func, &pinfo) != VMI_SUCCESS)
                {
                    if (vmi_request_page_fault(vmi, info->vcpu, exec_func, 0) == VMI_SUCCESS)
                    {
                        target.state = HOOK_PAGEFAULT_RETRY;
                        drakvuf_release_vmi(drakvuf);
                        return VMI_EVENT_RESPONSE_NONE;
                    }
                }
                else
                {
                    if (make_trap(vmi, drakvuf, info, &target, exec_func))
                        target.state = HOOK_OK;
                }
            }
            else if (translate_ret == VMI_SUCCESS && target.state == HOOK_PAGEFAULT_RETRY)
            {
                target.state = HOOK_FAILED;
                page_info_t pinfo;

                if (vmi_pagetable_lookup_extended(vmi, info->regs->cr3, exec_func, &pinfo) == VMI_SUCCESS)
                {
                    if (make_trap(vmi, drakvuf, info, &target, exec_func))
                        target.state = HOOK_OK;
                }
            }
            else
            {
                target.state = HOOK_FAILED;
            }

            PRINT_DEBUG("[MEMDUMP-USER] Hook %s (vaddr = 0x%llx, dll_base = 0x%llx, result = %s)\n",
                        target.target_name.c_str(),
                        (unsigned long long)exec_func,
                        (unsigned long long)dll_meta->real_dll_base,
                        target.state == HOOK_OK ? "OK" : "FAIL");
        }
    }

    drakvuf_release_vmi(drakvuf);
    PRINT_DEBUG("[MEMDUMP-USER] Done, flag DLL as hooked\n");
    dll_meta->is_hooked = true;
    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * This is used in order to observe when SysWOW64 process is loading a new DLL.
 * If the DLL is interesting, we perform further investigation and try to equip user mode hooks.
 */
static event_response_t protect_virtual_memory_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // IN HANDLE ProcessHandle
    uint64_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    // IN OUT PVOID *BaseAddress
    addr_t base_address_ptr = drakvuf_get_function_argument(drakvuf, info, 2);

    if (process_handle != ~0ULL)
        return VMI_EVENT_RESPONSE_NONE;

    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    user_dll_t* dll_meta = get_pending_dll(drakvuf, info, plugin);

    if (!dll_meta)
    {
        addr_t base_address;

        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = base_address_ptr
        };

        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        bool success = (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &base_address));
        drakvuf_release_vmi(drakvuf);

        if (!success)
            return VMI_EVENT_RESPONSE_NONE;

        dll_meta = create_dll_meta(drakvuf, info, plugin, base_address);
    }

    if (dll_meta)
        return perform_hooking(drakvuf, info, plugin, dll_meta);

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * This is used in order to observe when 64 bit process is loading a new DLL.
 * If the DLL is interesting, we perform further investigation and try to equip user mode hooks.
 */
static event_response_t map_view_of_section_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<memdump, map_view_of_section_result_t<memdump>>(info);
    memdump* plugin = data->plugin();
    if (!data || !plugin)
    {
        PRINT_DEBUG("[MEMDUMP-USER] map_view_of_section_ret_cb invalid trap params!\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!data->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    user_dll_t* dll_meta = get_pending_dll(drakvuf, info, plugin);

    if (!dll_meta)
    {
        addr_t base_address;

        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = data->base_address_ptr
        };

        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        bool success = (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &base_address));
        drakvuf_release_vmi(drakvuf);

        if (!success)
            return VMI_EVENT_RESPONSE_NONE;

        dll_meta = create_dll_meta(drakvuf, info, plugin, base_address);
    }

    if (dll_meta)
        return perform_hooking(drakvuf, info, plugin, dll_meta);

    plugin->destroy_trap(drakvuf, info->trap);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t map_view_of_section_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    auto trap = plugin->register_trap<memdump, map_view_of_section_result_t<memdump>>(
                    drakvuf,
                    info,
                    plugin,
                    map_view_of_section_ret_cb,
                    breakpoint_by_pid_searcher());
    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto data = get_trap_params<memdump, map_view_of_section_result_t<memdump>>(trap);
    if (!data)
    {
        plugin->destroy_plugin_params(plugin->detach_plugin_params(trap));
        return VMI_EVENT_RESPONSE_NONE;
    }

    data->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));

    // IN HANDLE SectionHandle
    data->section_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    // IN HANDLE ProcessHandle
    data->process_handle = drakvuf_get_function_argument(drakvuf, info, 2);
    // IN OUT PVOID *BaseAddress
    data->base_address_ptr = drakvuf_get_function_argument(drakvuf, info, 3);

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * As we may accidentally trigger an exception in the kernel by using vmi_request_page_fault,
 * we hook KiSystemServiceHandler to account for that situation. Inside this hook,
 * we check if it was "our fault" and if so, we forcefully return EXCEPTION_CONTINUE_EXECUTION.
 * In any other case, we just pass the control to the original exception handler.
 */
static event_response_t system_service_handler_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("[MEMDUMP-USER] Entered system service handler\n");

    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    uint32_t thread_id;

    if (!drakvuf_get_current_thread_id(drakvuf, info, &thread_id))
    {
        PRINT_DEBUG("[MEMDUMP-USER] Failed to get thread id in system service handler!\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    bool our_fault = false;

    auto vec_it = plugin->loaded_dlls.find(info->regs->cr3);

    if (vec_it != plugin->loaded_dlls.end())
    {
        for (auto const& dll_meta : vec_it->second)
        {
            if (dll_meta.dtb == info->regs->cr3 && dll_meta.thread_id == thread_id)
            {
                our_fault = true;
                break;
            }
        }
    }

    if (!our_fault)
    {
        PRINT_DEBUG("[MEMDUMP-USER] Not suppressing service exception - not our fault\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // emulate `ret` instruction
    addr_t saved_rip = 0;
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = info->regs->rsp,
    };

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool success = (VMI_SUCCESS == vmi_read(vmi, &ctx, sizeof(addr_t), &saved_rip, NULL));
    drakvuf_release_vmi(drakvuf);

    if ( !success )
    {
        PRINT_DEBUG("[MEMDUMP-USER] Error while reading the saved RIP in system service handler\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    constexpr int EXCEPTION_CONTINUE_EXECUTION = 0;
    info->regs->rip = saved_rip;
    info->regs->rsp += sizeof(addr_t);
    info->regs->rax = EXCEPTION_CONTINUE_EXECUTION;
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

/**
 * Observe process exit and remove all user mode hooks
 */
static event_response_t terminate_process_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    auto vec_it = plugin->loaded_dlls.find(info->regs->cr3);

    if (vec_it == plugin->loaded_dlls.end())
        return VMI_EVENT_RESPONSE_NONE;

    for (auto& it : vec_it->second)
    {
        for (auto& target : it.targets)
        {
            PRINT_DEBUG("[MEMDUMP-USER] Erased trap for pid %d %s\n", info->proc_data.pid, target.target_name.c_str());
            drakvuf_remove_trap(drakvuf, target.trap, NULL);
        }
    }

    plugin->loaded_dlls.erase(vec_it);
    return VMI_EVENT_RESPONSE_NONE;
}

void memdump::load_wanted_targets(const memdump_config* c)
{
    if (!c->dll_hooks_list)
        return;

    std::ifstream ifs(c->dll_hooks_list, std::ifstream::in);

    if (!ifs)
    {
        throw -1;
    }

    std::string line;
    while (std::getline(ifs, line))
    {
        if (line.empty() || line[0] == '#')
            continue;

        std::stringstream ss(line);
        target_config_entry_t e;

        if (!std::getline(ss, e.dll_name, ',') || e.dll_name.empty())
            throw -1;
        if (!std::getline(ss, e.function_name, ',') || e.function_name.empty())
            throw -1;

        this->wanted_hooks.push_back(e);
    }
}

static event_response_t copy_on_write_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<memdump, copy_on_write_result_t<memdump>>(info);
    memdump* plugin = data->plugin();
    if (!data || !plugin)
    {
        PRINT_DEBUG("[MEMDUMP-USER] copy_on_write_ret_cb invalid trap params!\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!data->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    plugin->destroy_trap(drakvuf, info->trap);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    // sometimes the physical address was incorrectly cached in this moment, so we need to flush it
    vmi_v2pcache_flush(vmi);
    addr_t pa = vmi_pagetable_lookup(vmi, info->regs->cr3, data->vaddr);

    if (pa == 0)
    {
        PRINT_DEBUG("[MEMDUMP-USER] failed to get pa");
        goto end;
    }

    pa = pinfo.paddr;

    if (data->old_cow_pa == pa)
    {
        PRINT_DEBUG("[MEMDUMP-USER] PA after CoW remained the same, wtf? Nothing to do here...\n");
        goto end;
    }

    PRINT_DEBUG("[MEMDUMP-USER] new PA %lx\n", pa);

    for (auto& hook : data->hooks)
    {
        addr_t hook_va = ((data->vaddr >> 12) << 12) + (hook->trap->breakpoint.addr & 0xFFF);
        PRINT_DEBUG("adding hook at %lx\n", hook_va);

        make_trap(vmi, drakvuf, info, hook, hook_va);
    }

end:
    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t copy_on_write_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t vaddr = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t pte = drakvuf_get_function_argument(drakvuf, info, 2);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    addr_t pa = vmi_pagetable_lookup(vmi, info->regs->cr3, vaddr);

    if (pa == 0)
    {
        PRINT_DEBUG("[MEMDUMP-USER] failed to get pa");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    drakvuf_release_vmi(drakvuf);


    std::vector < hook_target_entry_t* > hooks;
    for (auto& dll : plugin->loaded_dlls[info->regs->cr3])
    {
        for (auto& hook : dll.targets)
        {
            addr_t hook_addr = hook.trap->breakpoint.addr;
            if (hook_addr >> 12 == pa >> 12)
            {
                hooks.push_back(&hook);
            }
        }
    }

    PRINT_DEBUG("[MEMDUMP-USER] copy on write called: vaddr: %llx pte: %llx, pid: %d, cr3: %llx\n", (unsigned long long)vaddr, (unsigned long long)pte, info->proc_data.pid, (unsigned long long)info->regs->cr3);
    PRINT_DEBUG("[MEMDUMP-USER] old CoW PA: %llx\n", (unsigned long long)pa);

    if (!hooks.empty())
    {
        PRINT_DEBUG("MEMDUMP-USER] Found %zu hooks on CoW page, registering return trap\n", hooks.size());

        auto trap = plugin->register_trap<memdump, copy_on_write_result_t<memdump>>(
                        drakvuf,
                        info,
                        plugin,
                        copy_on_write_ret_cb,
                        breakpoint_by_pid_searcher());
        if (!trap)
            return VMI_EVENT_RESPONSE_NONE;

        auto data = get_trap_params<memdump, copy_on_write_result_t<memdump>>(trap);
        if (!data)
        {
            plugin->destroy_plugin_params(plugin->detach_plugin_params(trap));
            return VMI_EVENT_RESPONSE_NONE;
        }

        data->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));

        data->vaddr = vaddr;
        data->pte = pte;
        data->old_cow_pa = pa;
        data->hooks = hooks;
    }

    return VMI_EVENT_RESPONSE_NONE;
}

void memdump::userhook_init(drakvuf_t drakvuf, const memdump_config* c, output_format_t output)
{
    try
    {
        this->load_wanted_targets(c);
    }
    catch (int e)
    {
        fprintf(stderr, "Malformed DLL hook configuration for MEMDUMP plugin\n");
        throw -1;
    }

    if (this->wanted_hooks.empty())
    {
        // don't load this part of plugin if there is nothing to do
        return;
    }

    breakpoint_in_system_process_searcher bp;
    if (!register_trap<memdump>(drakvuf, nullptr, this, protect_virtual_memory_hook_cb, bp.for_syscall_name("NtProtectVirtualMemory")) ||
        !register_trap<memdump>(drakvuf, nullptr, this, map_view_of_section_hook_cb, bp.for_syscall_name("NtMapViewOfSection")) ||
        !register_trap<memdump>(drakvuf, nullptr, this, system_service_handler_hook_cb, bp.for_syscall_name("KiSystemServiceHandler")) ||
        !register_trap<memdump>(drakvuf, nullptr, this, terminate_process_hook_cb, bp.for_syscall_name("NtTerminateProcess")) ||
        !register_trap<memdump>(drakvuf, nullptr, this, copy_on_write_handler, bp.for_syscall_name("MiCopyOnWrite")))
    {
        throw -1;
    }
}
