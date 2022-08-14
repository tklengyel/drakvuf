/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
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

#include "win_injector.h"
#include "win_functions.h"
#include "methods/win_shellcode.h"
#include "methods/win_read_file.h"
#include "methods/win_write_file.h"
#include "methods/win_createproc.h"
#include "methods/win_shellexec.h"
#include "methods/win_terminate.h"
#include "methods/win_exitthread.h"

static bool injector_set_hijacked(injector_t injector, drakvuf_trap_info_t* info)
{
    if (!injector->target_tid)
    {
        uint32_t threadid = 0;
        if (!drakvuf_get_current_thread_id(injector->drakvuf, info, &threadid) || !threadid)
            return false;

        injector->target_tid = threadid;
    }

    injector->hijacked = true;

    return true;
}

static bool setup_int3_trap(injector_t injector, drakvuf_trap_info_t* info, addr_t bp_addr)
{
    injector->bp.type = BREAKPOINT;
    injector->bp.name = "entry";
    injector->bp.cb = injector_int3_cb;
    injector->bp.data = injector;
    injector->bp.breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp.breakpoint.dtb = info->regs->cr3;
    injector->bp.breakpoint.addr_type = ADDR_VA;
    injector->bp.breakpoint.addr = bp_addr;
    injector->bp.ttl = UNLIMITED_TTL;
    injector->bp.ah_cb = NULL;

    return drakvuf_add_trap(injector->drakvuf, &injector->bp);
}

static event_response_t mem_callback(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    (void)drakvuf;
    injector_t injector = info->trap->data;

    if ( info->proc_data.pid != injector->target_pid || ( injector->target_tid && (uint32_t)info->proc_data.tid != injector->target_tid ))
    {
        PRINT_DEBUG("MemX received but PID:TID (%u:%u) doesn't match target process (%u:%u)\n",
            info->proc_data.pid, info->proc_data.tid, injector->target_pid, injector->target_tid);
        return 0;
    }

    PRINT_DEBUG("MemX at 0x%lx\n", info->regs->rip);

    /* We might have already hijacked a thread on another vCPU */
    if (injector->hijacked)
        return 0;

    free_memtraps(injector);

    if (!setup_int3_trap(injector, info, info->regs->rip))
    {
        fprintf(stderr, "Failed to trap return location of injected function call @ 0x%lx!\n",
            info->regs->rip);
        return 0;
    }

    if (!injector_set_hijacked(injector, info))
        return 0;

    event_response_t event;
    switch (injector->method)
    {
        case INJECT_METHOD_READ_FILE: // UNTESTED on 32bit
        {
            event = handle_readfile_x64(drakvuf, info);
            break;
        }
        case INJECT_METHOD_WRITE_FILE:
        {
            event = handle_writefile(drakvuf, info);
            break;
        }
        case INJECT_METHOD_CREATEPROC:
        {
            event = handle_createproc(drakvuf, info);
            break;
        }
        case INJECT_METHOD_SHELLEXEC:
        {
            event = handle_shellexec(drakvuf, info);
            break;
        }
        default:
        {
            fprintf(stderr, "This method is not implemented for 32bit\n");
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
            event = VMI_EVENT_RESPONSE_NONE;
            break;
        }
    }

    if (!injector->step_override)
        injector->step+=1;

    injector->step_override = false;
    return handle_gprs_registers(drakvuf, info, event);
}

static event_response_t wait_for_crash_of_target_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    vmi_pid_t crashed_pid = 0;
    if (drakvuf_is_crashreporter(drakvuf, info, &crashed_pid) && crashed_pid == injector->target_pid)
    {
        injector->rc = INJECTOR_FAILED;
        injector->detected = false;

        drakvuf_interrupt(drakvuf, SIGDRAKVUFCRASH);
    }

    return 0;
}

static event_response_t wait_for_target_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 ". PID: %u PPID: %u TID: %u\n",
        info->regs->cr3, info->proc_data.pid, info->proc_data.ppid, info->proc_data.tid);

    if (info->proc_data.pid != injector->target_pid)
        return 0;

    if (injector->target_tid && injector->target_tid != (uint32_t)info->proc_data.tid)
        return 0;

    addr_t thread = drakvuf_get_current_thread(drakvuf, info);
    if (!thread)
    {
        PRINT_DEBUG("Failed to find current thread\n");
        return 0;
    }

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    /*
     * At this point the process is still in kernel mode, so
     * we need to trap when it enters into user mode.
     * For this we use different mechanisms on 32-bit and 64-bit.
     * The reason for this is that the same methods are not equally
     * reliable.
     *
     * For 64-bit Windows we use the trapframe approach, where we read
     * the saved RIP from the stack trap frame and breakpoint it.
     * When this address is hit, we hijack the flow and afterwards return
     * the registers to the original values, thus the process continues to run.
     * This method is workable on 32-bit Windows as well but finding the trapframe
     * sometimes fail for yet unknown reasons.
     */
    if (!injector->is32bit)
    {
        addr_t trapframe = 0;
        status_t status;
        status = vmi_read_addr_va(vmi,
                thread + injector->offsets[KTHREAD_TRAPFRAME],
                0, &trapframe);

        if (status == VMI_FAILURE || !trapframe)
        {
            PRINT_DEBUG("cr3_cb: failed to read trapframe (0x%lx)\n", trapframe);
            goto done;
        }

        addr_t bp_addr;
        status = vmi_read_addr_va(vmi,
                trapframe + injector->offsets[KTRAP_FRAME_RIP],
                0, &bp_addr);

        if (status == VMI_FAILURE || !bp_addr)
        {
            PRINT_DEBUG("Failed to read RIP from trapframe or RIP is NULL!\n");
            goto done;
        }

        if (setup_int3_trap(injector, info, bp_addr))
        {
            PRINT_DEBUG("Got return address 0x%lx from trapframe and it's now trapped!\n",
                bp_addr);

            // Unsubscribe from the CR3 trap
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
        }
        else
            fprintf(stderr, "Failed to trap trapframe return address\n");
    }
    else
    {
        drakvuf_pause(drakvuf);

        GSList* va_pages = vmi_get_va_pages(vmi, info->regs->cr3);
        GSList* loop = va_pages;
        while (loop)
        {
            page_info_t* page = loop->data;
            if (page->vaddr < 0x80000000 && USER_SUPERVISOR(page->x86_pae.pte_value))
            {
                drakvuf_trap_t* new_trap = g_try_malloc0(sizeof(drakvuf_trap_t));
                new_trap->type = MEMACCESS;
                new_trap->cb = mem_callback;
                new_trap->data = injector;
                new_trap->ttl = UNLIMITED_TTL;
                new_trap->ah_cb = NULL;
                new_trap->memaccess.access = VMI_MEMACCESS_X;
                new_trap->memaccess.type = POST;
                new_trap->memaccess.gfn = page->paddr >> 12;
                if ( drakvuf_add_trap(injector->drakvuf, new_trap) )
                    injector->memtraps = g_slist_prepend(injector->memtraps, new_trap);
                else
                    g_free(new_trap);
            }
            g_free(page);
            loop = loop->next;
        }
        g_slist_free(va_pages);

        // Unsubscribe from the CR3 trap
        drakvuf_remove_trap(drakvuf, info->trap, NULL);

        drakvuf_resume(drakvuf);
    }

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

bool check_int3_trap(injector_t injector, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx. vcpu %i. TID %u\n",
        info->regs->rip, info->regs->cr3, info->vcpu, info->proc_data.tid);

    if ( info->proc_data.pid != injector->target_pid )
    {
        PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
            info->proc_data.name, info->proc_data.pid, injector->target_pid);
        return false;
    }

    if (info->regs->rip != info->trap->breakpoint.addr)
        return false;

    if (injector->target_tid && (uint32_t)info->proc_data.tid != injector->target_tid)
    {
        PRINT_DEBUG("INT3 received but '%s' TID (%u) doesn't match target process (%u)\n",
            info->proc_data.name, info->proc_data.tid, injector->target_tid);
        return false;
    }
    else if (!injector->target_tid)
    {
        PRINT_DEBUG("Target TID not provided by the user, pinning TID to %u\n",
            info->proc_data.tid);
        injector->target_tid = info->proc_data.tid;
    }

    if (injector->target_rsp && info->regs->rsp <= injector->target_rsp)
    {
        PRINT_DEBUG("INT3 received but RSP (0x%lx) doesn't match target rsp (0x%lx)\n",
            info->regs->rsp, injector->target_rsp);
        return false;
    }
    return true;
}

event_response_t injector_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    if (!check_int3_trap(injector, info))
        return VMI_EVENT_RESPONSE_NONE;

    if (!injector_set_hijacked(injector, info))
        return 0;

    event_response_t event;
    switch (injector->method)
    {
        case INJECT_METHOD_READ_FILE:
        {
            event = handle_readfile_x64(drakvuf, info);
            break;
        }
        case INJECT_METHOD_WRITE_FILE:
        {
            event = handle_writefile(drakvuf, info);
            break;
        }
        case INJECT_METHOD_CREATEPROC:
        {
            event = handle_createproc(drakvuf, info);
            break;
        }
        case INJECT_METHOD_SHELLEXEC:
        {
            event = handle_shellexec(drakvuf, info);
            break;
        }
        case INJECT_METHOD_SHELLCODE:
        {
            event = handle_win_shellcode(drakvuf, info);
            break;
        }
        case INJECT_METHOD_TERMINATEPROC:
        {
            event = handle_win_terminate(drakvuf, info);
            break;
        }
        case INJECT_METHOD_EXITTHREAD:
        {
            event = handle_win_exitthread(drakvuf, info);
            break;
        }
        default:
        {
            fprintf(stderr, "This method is not implemented for 64bit\n");
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
            event = VMI_EVENT_RESPONSE_NONE;
            break;
        }
    }

    if (!injector->hijacked)
        return 0;

    if (!injector->step_override)
        injector->step+=1;

    injector->step_override = false;
    return handle_gprs_registers(drakvuf, info, event);

}

static bool is_interrupted(drakvuf_t drakvuf, void* data __attribute__((unused)))
{
    return drakvuf_is_interrupted(drakvuf);
}

static bool inject(drakvuf_t drakvuf, injector_t injector)
{
    injector->hijacked = 0;

    drakvuf_trap_t trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = wait_for_target_process_cb,
        .data = injector,
    };
    if (!drakvuf_add_trap(drakvuf, &trap))
        return false;

    drakvuf_trap_t trap_crashreporter =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = wait_for_crash_of_target_process,
        .data = injector,
    };
    if (!drakvuf_add_trap(drakvuf, &trap_crashreporter))
        return false;

    if (!drakvuf_is_interrupted(drakvuf))
    {
#ifdef DRAKVUF_DEBUG
        const char* method = injector->method == INJECT_METHOD_TERMINATEPROC ? "termination" : ( injector->method == INJECT_METHOD_EXITTHREAD ? "exitthread" : "injection");
#endif
        PRINT_DEBUG("Starting %s loop\n", method);
        drakvuf_loop(drakvuf, is_interrupted, NULL);
        PRINT_DEBUG("Finished %s loop\n", method);
    }

    if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        injector->rc = INJECTOR_TIMEOUTED;

    free_memtraps(injector);

    drakvuf_remove_trap(drakvuf, &trap, NULL);
    drakvuf_remove_trap(drakvuf, &trap_crashreporter, NULL);

    return true;
}

static bool initialize_injector_functions(drakvuf_t drakvuf, injector_t injector, const char* file)
{
    addr_t eprocess_base = 0;
    if ( !drakvuf_find_process(drakvuf, injector->target_pid, NULL, &eprocess_base) )
    {
        fprintf(stderr, "Process not found\n");
        return false;
    }

    if (!injector->is32bit)
    {
        // Get the offsets from the Rekall profile
        if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_KTHREAD", "TrapFrame", &injector->offsets[KTHREAD_TRAPFRAME]))
            PRINT_DEBUG("Failed to find _KTHREAD:TrapFrame.\n");

        if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_KTRAP_FRAME", "Rip", &injector->offsets[KTRAP_FRAME_RIP]))
            PRINT_DEBUG("Failed to find _KTRAP_FRAME:Rip.\n");
    }

    PRINT_DEBUG("Initializing function addresses\n");
    switch (injector->method)
    {
        case INJECT_METHOD_CREATEPROC:
        {
            injector->resume_thread = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "ResumeThread", injector->global_search);
            if (!injector->resume_thread) return false;
            injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "CreateProcessW", injector->global_search);
            break;
        }
        case INJECT_METHOD_TERMINATEPROC:
        {
            injector->open_process = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "OpenProcess", injector->global_search);
            if (!injector->open_process) return false;
            injector->exit_process = get_function_va(drakvuf, eprocess_base, "ntdll.dll", "RtlExitUserProcess", injector->global_search);
            if (!injector->exit_process) return false;
            injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "CreateRemoteThread", injector->global_search);
            break;
        }
        case INJECT_METHOD_EXITTHREAD:
        {
            injector->exit_thread = get_function_va(drakvuf, eprocess_base, "ntdll.dll", "RtlExitUserThread", injector->global_search);
            if (!injector->exit_thread) return false;
            break;
        }
        case INJECT_METHOD_SHELLEXEC:
        {
            injector->exec_func = get_function_va(drakvuf, eprocess_base, "shell32.dll", "ShellExecuteW", injector->global_search);
            break;
        }
        case INJECT_METHOD_SHELLCODE:
        {
            // Read shellcode from a file
            if ( !load_file_to_memory(&injector->payload, &injector->payload_size, file) )
            {
                PRINT_DEBUG("Could not load file to memory\n");
                return false;
            }

            injector->memset = get_function_va(drakvuf, eprocess_base, "ntdll.dll", "memset", injector->global_search);
            if (!injector->memset) return false;
            injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "VirtualAlloc", injector->global_search);
            break;
        }
        case INJECT_METHOD_WRITE_FILE:
        {
            injector->write_file = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "WriteFile", injector->global_search);
            if (!injector->write_file) return false;
            goto file_methods_init;
        }
        case INJECT_METHOD_READ_FILE:
        {
            injector->read_file = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "ReadFile", injector->global_search);
            if (!injector->read_file) return false;
            goto file_methods_init;
        }
file_methods_init:
        {
            injector->payload_size = FILE_BUF_SIZE;

            injector->memset = get_function_va(drakvuf, eprocess_base, "ntdll.dll", "memset", injector->global_search);
            if (!injector->memset) return false;
            injector->create_file = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "CreateFileW", injector->global_search);
            if (!injector->create_file) return false;
            injector->expand_env = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "ExpandEnvironmentStringsW", injector->global_search);
            if (!injector->expand_env) return false;


            injector->close_handle = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "CloseHandle", injector->global_search);
            if (!injector->close_handle) return false;
            injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "VirtualAlloc", injector->global_search);
            break;
        }
        default:
        {
            PRINT_DEBUG("Should not be here");
            assert(false);
        }
    }

    return injector->exec_func != 0;
}

injector_status_t injector_start_app_on_win(
    drakvuf_t drakvuf,
    vmi_pid_t pid,
    uint32_t tid,
    const char* file,
    const char* cwd,
    injection_method_t method,
    output_format_t format,
    const char* binary_path,
    const char* target_process,
    bool break_loop_on_detection,
    injector_t* to_be_freed_later,
    bool global_search,
    bool wait_for_exit,
    vmi_pid_t* injected_pid)
{
    injector_status_t rc = 0;
    PRINT_DEBUG("Target PID %u to start '%s'\n", pid, file);

    unicode_string_t* target_file_us = convert_utf8_to_utf16(file);
    if (!target_file_us)
    {
        PRINT_DEBUG("Unable to convert file path from utf8 to utf16\n");
        return 0;
    }

    unicode_string_t* cwd_us = NULL;
    if (cwd)
    {
        cwd_us = convert_utf8_to_utf16(cwd);
        if (!cwd_us)
        {
            PRINT_DEBUG("Unable to convert cwd from utf8 to utf16\n");
            vmi_free_unicode_str(target_file_us);
            return 0;
        }
    }

    injector_t injector = (injector_t)g_try_malloc0(sizeof(struct injector));
    if (!injector)
    {
        vmi_free_unicode_str(target_file_us);
        vmi_free_unicode_str(cwd_us);
        return 0;
    }

    injector->drakvuf = drakvuf;
    injector->target_pid = pid;
    injector->target_tid = tid;
    injector->target_file_us = target_file_us;
    injector->cwd_us = cwd_us;
    injector->method = method;
    injector->global_search = global_search;
    injector->wait_for_exit = wait_for_exit;
    injector->binary_path = binary_path;
    injector->target_process = target_process;
    injector->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    injector->break_loop_on_detection = break_loop_on_detection;
    injector->error_code.valid = false;
    injector->error_code.code = -1;
    injector->error_code.string = "<UNKNOWN>";
    injector->step = STEP1;
    injector->step_override = false;
    injector->set_gprs_only = true;

    if (!initialize_injector_functions(drakvuf, injector, file))
    {
        PRINT_DEBUG("Unable to initialize injector functions\n");
        injector->result = INJECT_RESULT_INIT_FAIL;
        print_win_injection_info(format, file, injector);
        free_injector(injector);
        return 0;
    }

    if (inject(drakvuf, injector) && injector->rc == INJECTOR_SUCCEEDED)
    {
        injector->result = INJECT_RESULT_SUCCESS;
        print_win_injection_info(format, file, injector);
    }
    else
    {
        if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        {
            PRINT_DEBUG("Injection timeout\n");
            injector->result = INJECT_RESULT_TIMEOUT;
            print_win_injection_info(format, file, injector);
        }
        else if (SIGDRAKVUFCRASH == drakvuf_is_interrupted(drakvuf))
        {
            PRINT_DEBUG("Target process crash detected\n");
            injector->result = INJECT_RESULT_CRASH;
            print_win_injection_info(format, file, injector);
        }
        else if (injector->error_code.valid)
        {
            PRINT_DEBUG("Injection failed with error '%s' (%d)\n",
                injector->error_code.string,
                injector->error_code.code);
            injector->result = INJECT_RESULT_ERROR_CODE;
            print_win_injection_info(format, file, injector);
        }
        else
        {
            PRINT_DEBUG("Injection premature break\n");
            injector->result = INJECT_RESULT_PREMATURE;
            print_win_injection_info(format, file, injector);
        }
    }

    rc = injector->rc;
    if (injected_pid)
        *injected_pid = injector->pid;
    PRINT_DEBUG("Finished with injection. Ret: %i.\n", rc);

    switch (method)
    {
        case INJECT_METHOD_CREATEPROC:
            if ( break_loop_on_detection )
                if ( injector->resumed && injector->detected )
                {
                    free_injector(injector);
                }
                else
                {
                    *to_be_freed_later = injector;
                }
            else
                free_injector(injector);
            break;
        default:
            free_injector(injector);
            break;
    }

    return rc;
}

void injector_terminate_on_win(drakvuf_t drakvuf,
    vmi_pid_t injection_pid,
    uint32_t injection_tid,
    vmi_pid_t pid)
{
    PRINT_DEBUG("Target PID %u to terminate %u\n", injection_pid, pid);
    drakvuf_interrupt(drakvuf, 0); // clean

    injector_t injector = (injector_t)g_try_malloc0(sizeof(struct injector));

    injector->method = INJECT_METHOD_TERMINATEPROC;
    injector->drakvuf = drakvuf;
    injector->target_pid = injection_pid;
    injector->target_tid = injection_tid;
    injector->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    injector->terminate_pid = pid;
    injector->step_override = false;
    injector->step = STEP1;

    if (!initialize_injector_functions(drakvuf, injector, NULL))
    {
        PRINT_DEBUG("Unable to initialize injector functions\n");
        free_injector(injector);
        return;
    }

    inject(drakvuf, injector);
    PRINT_DEBUG("Finished with termination. Ret: %i.\n", injector->rc);

    free_injector(injector);
}

void injector_exitthread_on_win(drakvuf_t drakvuf,
    vmi_pid_t injection_pid,
    uint32_t injection_tid)
{
    PRINT_DEBUG("Target PID %u to terminate TID %u\n", injection_pid, injection_tid);
    drakvuf_interrupt(drakvuf, 0); // clean

    injector_t injector = (injector_t)g_try_malloc0(sizeof(struct injector));

    injector->method = INJECT_METHOD_EXITTHREAD;
    injector->drakvuf = drakvuf;
    injector->target_pid = injection_pid;
    injector->target_tid = injection_tid;
    injector->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    injector->step_override = false;
    injector->step = STEP1;

    if (!initialize_injector_functions(drakvuf, injector, NULL))
    {
        PRINT_DEBUG("Unable to initialize injector functions\n");
        free_injector(injector);
        return;
    }

    inject(drakvuf, injector);
    PRINT_DEBUG("Finished with termination. Ret: %i.\n", injector->rc);

    free_injector(injector);
}
