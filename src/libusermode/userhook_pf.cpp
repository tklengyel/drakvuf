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

#ifndef LIBUSERMODE_USE_INJECTION

#include "userhook.hpp"
#include "uh-private.hpp"


/**
 * As we may accidentally trigger an exception in the kernel by using vmi_request_page_fault,
 * we hook KiSystemServiceHandler to account for that situation. Inside this hook,
 * we check if it was "our fault" and if so, we forcefully return EXCEPTION_CONTINUE_EXECUTION.
 * In any other case, we just pass the control to the original exception handler.
 */
event_response_t system_service_handler_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("[USERHOOK] Entered system service handler\n");

    auto plugin = get_trap_plugin<userhook>(info);

    proc_data_t proc_data = get_proc_data(drakvuf, info);

    uint32_t thread_id = proc_data.tid;

    if (!thread_id)
    {
        PRINT_DEBUG("[USERHOOK] Failed to get thread id in system service handler!\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    bool our_fault = plugin->pf_in_progress.find(std::make_pair(proc_data.pid, proc_data.tid)) != plugin->pf_in_progress.end();
    if (!our_fault)
    {
        PRINT_DEBUG("[USERHOOK] Not suppressing service exception - not our fault\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // emulate `ret` instruction
    addr_t saved_rip = drakvuf_get_function_return_address(drakvuf, info);

    if (!saved_rip)
    {
        PRINT_DEBUG("[USERHOOK] Error while reading the saved RIP in system service handler\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    page_mode_t pm = drakvuf_get_page_mode(drakvuf);
    bool is32 = (pm != VMI_PM_IA32E);

    constexpr int EXCEPTION_CONTINUE_EXECUTION = 0;
    info->regs->rip = saved_rip;
    info->regs->rsp += (is32 ? 4 : 8);
    info->regs->rax = EXCEPTION_CONTINUE_EXECUTION;
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

event_response_t internal_perform_hooking(drakvuf_t drakvuf, drakvuf_trap_info* info, userhook* plugin, dll_t* dll_meta)
{
    proc_data_t proc_data = get_proc_data(drakvuf, info);

    auto vmi = vmi_lock_guard(drakvuf);

    // we have to make sure that addresses between [pf_current_addr, pf_max_addr]
    // are available for reading otherwise vmi_translate_sym2v will fail unconditionally
    // and we will be unable to add hooks

    plugin->pf_in_progress.erase(std::make_pair(proc_data.pid, proc_data.tid));

    while (dll_meta->pf_current_addr <= dll_meta->pf_max_addr)
    {
        page_info_t pinfo;
        if (vmi_pagetable_lookup_extended(vmi, info->regs->cr3, dll_meta->pf_current_addr, &pinfo) == VMI_SUCCESS)
        {
            PRINT_DEBUG("[USERHOOK] Export info accessible OK %llx\n", (unsigned long long)dll_meta->pf_current_addr);
            dll_meta->pf_current_addr += VMI_PS_4KB;
            continue;
        }

        if (vmi_request_page_fault(vmi, info->vcpu, dll_meta->pf_current_addr, 0) == VMI_SUCCESS)
        {
            PRINT_DEBUG("[USERHOOK] Export info not accessible, page fault %llx\n", (unsigned long long)dll_meta->pf_current_addr);
            plugin->pf_in_progress.insert(std::make_pair(proc_data.pid, proc_data.tid));
            dll_meta->pf_current_addr += VMI_PS_4KB;
        }
        else
        {
            PRINT_DEBUG("[USERHOOK] Failed to request page fault for DTB %llx, address %llx\n", (unsigned long long)info->regs->cr3, (unsigned long long)dll_meta->pf_current_addr);
        }

        return VMI_EVENT_RESPONSE_NONE;
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

                page_info_t pinfo;
                if (vmi_pagetable_lookup_extended(vmi, info->regs->cr3, exec_func, &pinfo) != VMI_SUCCESS)
                {
                    if (vmi_request_page_fault(vmi, info->vcpu, exec_func, 0) == VMI_SUCCESS)
                    {
                        target.state = HOOK_PAGEFAULT_RETRY;
                        plugin->pf_in_progress.insert(std::make_pair(proc_data.pid, proc_data.tid));
                        return VMI_EVENT_RESPONSE_NONE;
                    }
                    else
                    {
                        PRINT_DEBUG("[USERHOOK] Failed to request page fault for DTB %llx, address %llx\n",
                            (unsigned long long)info->regs->cr3, (unsigned long long)dll_meta->pf_current_addr);
                        return VMI_EVENT_RESPONSE_NONE;
                    }
                }
                else
                {
                    if (make_trap(vmi, drakvuf, info, &target, exec_func))
                        target.state = HOOK_OK;
                }
            }
            else if (target.state == HOOK_PAGEFAULT_RETRY)
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

            PRINT_DEBUG("[USERHOOK] Hook %s (vaddr = 0x%llx, dll_base = 0x%llx, result = %s)\n",
                target.target_name.c_str(),
                (unsigned long long)exec_func,
                (unsigned long long)dll_meta->v.real_dll_base,
                target.state == HOOK_OK ? "OK" : "FAIL");
        }
    }

    PRINT_DEBUG("[USERHOOK] Done, flag DLL as hooked\n");
    dll_meta->v.is_hooked = true;
    return VMI_EVENT_RESPONSE_NONE;
}

#endif