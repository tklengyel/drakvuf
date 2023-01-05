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

#ifdef LIBUSERMODE_USE_INJECTION

#include <libinjector/libinjector.h>
#include "userhook.hpp"
#include "uh-private.hpp"


bool inject_copy_memory(userhook* plugin, drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    event_response_t (*cb)(drakvuf_t, drakvuf_trap_info_t*),
    uint64_t* stack_marker,
    addr_t addr,
    addr_t* stack_pointer)
{
    x86_registers_t regs;
    memcpy(&regs, info->regs, sizeof(x86_registers_t));

    uint64_t buffer = 0;
    uint64_t read_bytes = 0;
    struct argument args[7] = {};
    init_int_argument(&args[0], info->attached_proc_data.base_addr);
    init_int_argument(&args[1], addr);
    init_int_argument(&args[2], info->attached_proc_data.base_addr);
    init_struct_argument(&args[3], buffer);
    init_int_argument(&args[4], sizeof(buffer));
    init_int_argument(&args[5], 0);
    init_struct_argument(&args[6], read_bytes);

    if (!inject_function_call(drakvuf, info, cb, &regs, args, 7, plugin->copy_virt_mem_va, stack_marker))
    {
        PRINT_DEBUG("[USERHOOK] [%8zu] [%d:%d:%#lx]  "
            "Failed to inject MmCopyVirtualMemory\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid, info->regs->rsp
        );
        return false;
    }
    *stack_pointer = regs.rsp;

    return true;
}

/**
 * This is used in order to observe when 64 bit process is loading a new DLL.
 * If the DLL is interesting, we perform further investigation and try to equip user mode hooks.
 */
static event_response_t map_view_of_section_ret_cb_2(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = get_trap_params<map_view_of_section_result_t>(info);

    if (!params->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    return hook_dll(drakvuf, info, params->base_address_ptr);
}

static void check_stack_marker(
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    vmi_lock_guard& vmi,
    dll_t* task)
{
    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = task->stack_marker_va();
    uint64_t stack_marker;

    if ( VMI_SUCCESS == vmi_read_64(vmi, &ctx, &stack_marker) &&
        stack_marker != task->stack_marker())
    {
        PRINT_DEBUG("[USERHOOK] [%8zu] [%d:%d] "
            "Stack marker check failed at %#lx: "
            "expected %#lx, result %#lx\n"
            , info->event_uid
            , info->attached_proc_data.pid, info->attached_proc_data.tid
            , task->stack_marker_va(), task->stack_marker()
            , stack_marker
        );
    }
}

event_response_t internal_perform_hooking(drakvuf_t drakvuf, drakvuf_trap_info* info, userhook* plugin, dll_t* dll_meta)
{
    auto vmi = vmi_lock_guard(drakvuf);

    // we have to make sure that addresses between [pf_current_addr, pf_max_addr]
    // are available for reading otherwise vmi_translate_sym2v will fail unconditionally
    // and we will be unable to add hooks

    if (drakvuf_lookup_injection(drakvuf, info))
    {
        check_stack_marker(drakvuf, info, vmi, dll_meta);
        drakvuf_remove_injection(drakvuf, info);
    }

    drakvuf_trap_t* trap = nullptr;
    map_view_of_section_result_t* params = nullptr;
    if (!dll_meta->in_progress)
    {
        if (plugin->is_stopping())
        {
            PRINT_DEBUG("[USERHOOK] Premature stop\n");
            return VMI_EVENT_RESPONSE_NONE;
        }

        PRINT_DEBUG("[USERHOOK] Start processing this dll_meta\n");
        memcpy(&dll_meta->regs, info->regs, sizeof(x86_registers_t));
        dll_meta->in_progress = true;

        breakpoint_by_dtb_searcher bp;
        trap = plugin->register_trap<map_view_of_section_result_t>(
                info,
                map_view_of_section_ret_cb_2,
                bp.for_virt_addr(info->regs->rip).for_dtb(info->regs->cr3),
                "NtMapViewOfSection ret v2");
        if (!trap)
            return VMI_EVENT_RESPONSE_NONE;
    }
    else
    {
        trap = info->trap;
        if (plugin->is_stopping())
        {
            PRINT_DEBUG("[USERHOOK] Premature stop\n");
            drakvuf_vmi_response_set_gpr_registers(drakvuf, info, &dll_meta->regs, true);
            dll_meta->in_progress = false;
            plugin->destroy_trap(trap);
            return VMI_EVENT_RESPONSE_NONE;
        }

        PRINT_DEBUG("[USERHOOK] Continue processing this dll_meta\n");
    }


    params = get_trap_params<map_view_of_section_result_t>(trap);
    if (!params)
        return VMI_EVENT_RESPONSE_NONE;

    while (dll_meta->pf_current_addr <= dll_meta->pf_max_addr)
    {
        page_info_t pinfo;
        if (vmi_pagetable_lookup_extended(vmi, info->regs->cr3, dll_meta->pf_current_addr, &pinfo) == VMI_SUCCESS)
        {
            PRINT_DEBUG("[USERHOOK] Export info accessible OK %llx\n", (unsigned long long)dll_meta->pf_current_addr);
            dll_meta->pf_current_addr += VMI_PS_4KB;
            continue;
        }

        addr_t stack_pointer;
        if (inject_copy_memory(plugin, drakvuf, info, trap->cb, dll_meta->set_stack_marker(), dll_meta->pf_current_addr, &stack_pointer))
        {
            PRINT_DEBUG("[USERHOOK] Export info not accessible, page fault %llx\n", (unsigned long long)dll_meta->pf_current_addr);
            dll_meta->pf_current_addr += VMI_PS_4KB;
            params->set_result_call_params(info, stack_pointer);
            return VMI_EVENT_RESPONSE_NONE;
        }
        else
        {
            PRINT_DEBUG("[USERHOOK] Failed to request page fault for DTB %llx, address %llx\n", (unsigned long long)info->regs->cr3, (unsigned long long)dll_meta->pf_current_addr);
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    // export info should be available, try hooking DLLs
    for (auto& target : dll_meta->targets)
    {
        if (target.state == HOOK_FIRST_TRY || target.state == HOOK_PAGEFAULT_RETRY)
        {
            addr_t exec_func = 0;

            if (target.type == HOOK_BY_NAME)
            {
                ACCESS_CONTEXT(ctx,
                    .translate_mechanism = VMI_TM_PROCESS_DTB,
                    .dtb = info->regs->cr3,
                    .addr = dll_meta->v.real_dll_base
                );

                if (vmi_translate_sym2v(vmi, &ctx, target.target_name.c_str(), &exec_func) != VMI_SUCCESS)
                {
                    target.state = HOOK_FAILED;
                    PRINT_DEBUG("[USERHOOK] Failed to hook %s: failed to translate symbol to address\n", target.target_name.c_str());
                    continue;
                }

                target.offset = exec_func - dll_meta->v.real_dll_base;
            }
            else // HOOK_BY_OFFSET
            {
                exec_func = dll_meta->v.real_dll_base + target.offset;
            }

            if (target.state == HOOK_FIRST_TRY)
            {
                target.state = HOOK_FAILED;

                if (is_pagetable_loaded(vmi, info, exec_func))
                {
                    if (make_trap(vmi, drakvuf, info, &target, exec_func))
                        target.state = HOOK_OK;
                }
                else
                {
                    addr_t stack_pointer;
                    if (inject_copy_memory(plugin, drakvuf, info, trap->cb, dll_meta->set_stack_marker(), exec_func, &stack_pointer))
                    {
                        target.state = HOOK_PAGEFAULT_RETRY;
                        params->set_result_call_params(info, stack_pointer);
                        return VMI_EVENT_RESPONSE_NONE;
                    }
                    else
                    {
                        PRINT_DEBUG("[USERHOOK] Failed to request page fault for DTB %llx, address %llx\n",
                            (unsigned long long)info->regs->cr3, (unsigned long long)dll_meta->pf_current_addr);
                        drakvuf_vmi_response_set_gpr_registers(drakvuf, info, &dll_meta->regs, true);
                        dll_meta->in_progress = false;
                        plugin->destroy_trap(trap);
                        return VMI_EVENT_RESPONSE_NONE;
                    }
                }
            }
            else if (target.state == HOOK_PAGEFAULT_RETRY)
            {
                target.state = HOOK_FAILED;

                if (is_pagetable_loaded(vmi, info, exec_func))
                {
                    if (make_trap(vmi, drakvuf, info, &target, exec_func))
                        target.state = HOOK_OK;
                }
            }
            else
            {
                target.state = HOOK_FAILED;
            }

            PRINT_DEBUG("[USERHOOK] Hook %s (vaddr = 0x%llx, dll_base = 0x%llx, result = %s)\n",
                target.target_name.c_str(),
                (unsigned long long)exec_func,
                (unsigned long long)dll_meta->v.real_dll_base,
                target.state == HOOK_OK ? "OK" : "FAIL");
        }
    }

    PRINT_DEBUG("[USERHOOK] Done, flag DLL as hooked\n");
    drakvuf_vmi_response_set_gpr_registers(drakvuf, info, &dll_meta->regs, true);
    dll_meta->in_progress = false;
    dll_meta->v.is_hooked = true;
    plugin->destroy_trap(trap);
    return VMI_EVENT_RESPONSE_NONE;
}

#endif