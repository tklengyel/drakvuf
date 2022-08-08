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
 * This file was created by Manorit Chawdhry.                              *
 * It is distributed as part of DRAKVUF under the same license             *
 ***************************************************************************/


#include <libinjector/debug_helpers.h>

#include "linux_execve.h"
#include "linux_syscalls.h"

static event_response_t cleanup(injector_t injector, x86_registers_t* regs);
bool is_child_process(injector_t injector,  drakvuf_trap_info_t* info)
{
    if (info->proc_data.ppid == injector->target_pid)
    {
        PRINT_DEBUG("Inside child process\n");
        return true;
    }
    PRINT_DEBUG("Inside parent process: %d\n", info->proc_data.pid);
    PRINT_DEBUG("Step of injector: %d\n", injector->step + 1);
    return false;
}

/* This function handles execve syscalls, it does so in a total of 5 steps
 *
 * STEP1:
 * It initialises the syscalls and then it calls mmap to reserve some space for keeping
 * the string arguments to be passed in execve
 *
 * STEP2:
 * This step vforks the process and loosens the check around check_userspace_int3_trap
 * but setting injector->fork = true. This helps us get the pid of the child process
 * as soon as we get it, we use that child pid to tighten the checks again
 *
 * STEP3:
 * We get the pid in this as this trap should only hit in the child process as per the
 * checks in check_userspace_int3_trap. So we can now store the pid of the child process
 * and setup execve calls
 *
 * STEP4:
 * This step is considered a part of the cleanup, It checks if execve succeeded or not,
 * if it did not then it will exit the child process and then keep the step so that we
 * can restore the parent process in the next callback. If the child process executes
 * execve successfully, parent process gets active again and we hit parent process
 * restoring it's state
 *
 * STEP6:
 * We free the initial trap and interrupt drakvuf
 */
event_response_t handle_execve(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = (injector_t)info->trap->data;

    switch (injector->step)
    {
        case STEP1: // Finds vdso and sets up mmap
        {
            injector->target_process = info->proc_data.base_addr;
            memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

            if (!init_syscalls(drakvuf, info))
            {
                injector->injection_failed = true;
                return override_step(injector, STEP5, VMI_EVENT_RESPONSE_NONE);
            }

            // don't remove the initial trap
            // it is used for cleanup after restoring registers

            if (!setup_mmap_syscall(injector, info->regs, FILE_BUF_SIZE))
            {
                injector->injection_failed = true;
                // clear post_syscall_trap
                free_bp_trap(drakvuf, injector, injector->bp);
                return override_step(injector, STEP5, VMI_EVENT_RESPONSE_NONE);
            }

            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP2: // forks the process
        {
            if (!call_mmap_syscall_cb(injector, info->regs, FILE_BUF_SIZE))
            {
                injector->injection_failed = true;
                return cleanup(injector, info->regs);
            }

            char* proc_name = strdup(info->proc_data.name);

            PRINT_DEBUG("vForking the process\n");
            setup_vfork_syscall(injector, info->regs, proc_name, info->proc_data.pid);

            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP3: // get child pid and runs execve
        {
            if (!call_vfork_syscall_cb(injector, info->regs, info->proc_data.pid, info->proc_data.tid))
            {
                injector->injection_failed = true;
                return cleanup(injector, info->regs);
            }

            GHashTable* env_htable = get_injection_environ(injector, info);

            if (!setup_execve_syscall(injector, info->regs, injector->host_file, env_htable))
            {
                injector->injection_failed = true;
                g_hash_table_destroy(env_htable);
                return cleanup(injector, info->regs);
            }

            g_hash_table_destroy(env_htable);
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP4: // handles execve and restores parent
        {
            if (is_child_process(injector, info))
            {
                if (is_syscall_error(info->regs->rax, "execve syscall failed"))
                    injector->injection_failed = true;

                PRINT_DEBUG("Exiting child process\n");
                if (!setup_exit_syscall(injector, info->regs, 0))
                {
                    fprintf(stderr, "Fatal error: Could not cleanup properly\n");
                    drakvuf_interrupt(drakvuf, SIGINT);
                    return VMI_EVENT_RESPONSE_NONE;
                }

                // this is being done so that the parent can also be cleared
                return override_step(injector, STEP4, VMI_EVENT_RESPONSE_SET_REGISTERS);
            }
            else
            {
                PRINT_DEBUG("Restoring parent registers\n");
                copy_gprs(info->regs, &injector->saved_regs);

                // free the post_syscall_trap
                free_bp_trap(drakvuf, injector, info->trap);
            }

            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP5: // exit drakvuf loop
        {
            if (is_child_process(injector, info))
            {
                fprintf(stderr, "Assertion: Should never happen, Child process alive\n");
                drakvuf_interrupt(drakvuf, SIGINT);
                return VMI_EVENT_RESPONSE_NONE;
            }

            PRINT_DEBUG("Removing traps and exiting\n");

            // remove the initial trap here
            free_bp_trap(drakvuf, injector, info->trap);
            drakvuf_interrupt(drakvuf, SIGINT);

            if (injector->injection_failed)
            {
                injector->rc = INJECTOR_FAILED;
            }
            else
            {
                injector->rc = INJECTOR_SUCCEEDED;
                injector->pid = injector->child_data.pid;
                injector->tid = injector->child_data.tid;
            }

            return VMI_EVENT_RESPONSE_NONE;
        }
        default:
        {
            PRINT_DEBUG("Should not be here\n");
            assert(false);
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

/* This function handles cleanup incase something goes wrong. This seems to be a difficult
 * task compared to other methods as this time there is also a child process that we need
 * to exit in case of some error. For this, we will be going to STEP4. STEP4 handles the
 * cleanup of both the parent as well as the child process.
 */
static event_response_t cleanup(injector_t injector, x86_registers_t* regs)
{
    fprintf(stderr, "Doing premature cleanup\n");

    copy_gprs(regs, &injector->saved_regs);

    return override_step(injector, STEP4, VMI_EVENT_RESPONSE_SET_REGISTERS);
}
