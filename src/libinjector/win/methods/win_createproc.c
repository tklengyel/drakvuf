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

#include "win_createproc.h"
#include "win_functions.h"
#include "method_helpers.h"

static bool fill_created_process_info(injector_t injector, drakvuf_trap_info_t* info);
static event_response_t wait_for_termination_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
static event_response_t wait_for_injected_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
static bool setup_wait_for_injected_process_trap(injector_t injector);
static event_response_t cleanup(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

event_response_t handle_createproc(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;
    base_injector_t base_injector = &injector->base_injector;

    switch (base_injector->step)
    {
        case STEP1:
        {
            // save registers
            PRINT_DEBUG("Saving registers\n");
            memcpy_s(&injector->x86_saved_regs, sizeof(injector->x86_saved_regs), info->regs, sizeof(x86_registers_t));

            if (!setup_create_process_stack(injector, info->regs))
            {
                fprintf(stderr, "Failed to setup create process stack\n");
                return cleanup(drakvuf, info);
            }

            injector->target_rsp = info->regs->rsp;
            info->regs->rip = injector->exec_func;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP2:
        {
            // We are now in the return path from CreateProcessW
            if (is_fun_error(drakvuf, info, "CreateProcessW Failed"))
                return cleanup(drakvuf, info);

            if (!fill_created_process_info(injector, info))
                return cleanup(drakvuf, info);

            if (!injector->pid || !injector->tid)
            {
                fprintf(stderr, "Failed to inject\n");
                return cleanup(drakvuf, info);
            }

            PRINT_DEBUG("Injected PID: %i. TID: %i\n", injector->pid, injector->tid);

            if (!setup_resume_thread_stack(injector, info->regs))
            {
                fprintf(stderr, "Failed to setup stack for passing inputs!\n");
                return cleanup(drakvuf, info);
            }

            injector->target_rsp = info->regs->rsp;

            if (!setup_wait_for_injected_process_trap(injector))
                return cleanup(drakvuf, info);

            info->regs->rip = injector->resume_thread;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP3: // We are now in the return path from ResumeThread
        {
            PRINT_DEBUG("Resume RAX: 0x%lx\n", info->regs->rax);

            injector->rc = (info->regs->rax == 1) ? INJECTOR_SUCCEEDED : INJECTOR_FAILED;

            if (injector->rc == INJECTOR_FAILED)
            {
                fprintf(stderr, "Failed to resume\n");
                return cleanup(drakvuf, info);
            }
            PRINT_DEBUG("Resume successful\n");
            memcpy_s(info->regs, sizeof(*info->regs), &injector->x86_saved_regs, sizeof(x86_registers_t));

            injector->resumed = true;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP4: // exit loop
        {
            PRINT_DEBUG("Detected: %d\n", injector->detected);
            PRINT_DEBUG("Break on detection: %d\n", injector->break_loop_on_detection);
            // It will keep running until the injected process is detected
            // It ensures that we don't get in the main drakvuf loop somehow
            if (injector->detected)
            {
                PRINT_DEBUG("Removing traps and exiting injector\n");
                drakvuf_remove_trap(drakvuf, info->trap, NULL);
                drakvuf_interrupt(drakvuf, SIGINT);
            }
            return override_step(base_injector, STEP4, VMI_EVENT_RESPONSE_SET_REGISTERS);
        }
        default:
        {
            PRINT_DEBUG("Should not be here\n");
            assert(false);
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t cleanup(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    fprintf(stderr, "Exiting prematurely\n");

    if (injector->rc == INJECTOR_SUCCEEDED)
        injector->rc = INJECTOR_FAILED;

    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);

    memcpy_s(info->regs, sizeof(*info->regs), &injector->x86_saved_regs, sizeof(x86_registers_t));
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}


static bool fill_created_process_info(injector_t injector, drakvuf_trap_info_t* info)
{
    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = injector->process_info;
    bool success = false;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(injector->drakvuf);

    if (injector->is32bit)
    {
        struct process_information_32 pip = { 0 };
        if ( VMI_SUCCESS == vmi_read(vmi, &ctx, sizeof(struct process_information_32), &pip, NULL) )
        {
            injector->pid = pip.dwProcessId;
            injector->tid = pip.dwThreadId;
            injector->hProc = pip.hProcess;
            injector->hThr = pip.hThread;
            success = true;
        }

    }
    else
    {
        struct process_information_64 pip = { 0 };
        if ( VMI_SUCCESS == vmi_read(vmi, &ctx, sizeof(struct process_information_64), &pip, NULL) )
        {
            injector->pid = pip.dwProcessId;
            injector->tid = pip.dwThreadId;
            injector->hProc = pip.hProcess;
            injector->hThr = pip.hThread;
            success = true;
        }
    }

    drakvuf_release_vmi(injector->drakvuf);

    if (!success)
        fprintf(stderr, "Failed to fill created process info\n");

    return success;
}

static event_response_t wait_for_termination_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;
    addr_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    uint64_t exit_code = drakvuf_get_function_argument(drakvuf, info, 2);
    exit_code &= 0xFFFFFFFF;

    vmi_pid_t exit_pid;
    if (!drakvuf_get_pid_from_handle(drakvuf, info, process_handle, &exit_pid))
        exit_pid = info->proc_data.pid;

    if ((int)injector->pid != exit_pid)
        return 0;

    PRINT_DEBUG("Termination of process detected\n");
    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);

    if (!exit_code)
    {
        injector->rc = INJECTOR_SUCCEEDED;
    }
    else
    {
        injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
        injector->error_code.valid = true;
        injector->error_code.code = exit_code;
        injector->error_code.string = "PROGRAM_FAILED";
    }

    injector->detected = true;

    return 0;
}

static event_response_t wait_for_injected_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    if (injector->pid != (uint32_t)info->proc_data.pid || injector->tid != (uint32_t)info->proc_data.tid)
        return 0;

    PRINT_DEBUG("Process start detected %i -> 0x%lx\n", injector->pid, info->regs->cr3);
    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);

    if (injector->wait_for_exit)
    {
        addr_t rva;

        if (!drakvuf_get_kernel_symbol_rva(drakvuf, "NtTerminateProcess", &rva))
        {
            fprintf(stderr, "Failed to find NtTerminateProcess RVA!\n");
            return 0;
        }

        drakvuf_trap_t* trap = g_try_malloc0(sizeof(drakvuf_trap_t));
        trap->type = BREAKPOINT;
        trap->name = "terminate_proc";
        trap->cb = wait_for_termination_cb;
        trap->data = injector;
        trap->breakpoint.lookup_type = LOOKUP_PID;
        trap->breakpoint.pid = 4;
        trap->breakpoint.addr_type = ADDR_RVA;
        trap->breakpoint.module = "ntoskrnl.exe";
        trap->breakpoint.rva = rva;
        trap->ttl = UNLIMITED_TTL;

        if (!drakvuf_add_trap(injector->drakvuf, trap))
        {
            fprintf(stderr, "Failed to setup wait_for_termination_cb trap!\n");
            return 0;
        }
    }
    else
    {
        injector->rc = INJECTOR_SUCCEEDED;
        injector->detected = true;
    }

    return 0;
}

// Setup callback for waiting for first occurence of resumed thread
static bool setup_wait_for_injected_process_trap(injector_t injector)
{
    drakvuf_trap_t* trap = g_try_malloc0(sizeof(drakvuf_trap_t));
    trap->type = REGISTER;
    trap->reg = CR3;
    trap->cb = wait_for_injected_process_cb;
    trap->data = injector;
    if (!drakvuf_add_trap(injector->drakvuf, trap))
    {
        fprintf(stderr, "Failed to setup wait_for_injected_process trap!\n");
        return false;
    }
    PRINT_DEBUG("Waiting for injected process\n");
    return true;
}
