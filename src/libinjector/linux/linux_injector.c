/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
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

#include "linux_injector.h"
#include "methods/linux_shellcode.h"
#include "methods/linux_write_file.h"
#include "methods/linux_read_file.h"
#include "methods/linux_execve.h"

static bool check_userspace_int3_trap(linux_injector_t injector, drakvuf_trap_info_t* info)
{
    // check CPL
    short CPL = info->regs->cs_sel & 3;
    PRINT_DEBUG("CPL 0x%x\n", CPL);

    if ( CPL != 0)
    {
        PRINT_DEBUG("Inside INT3 userspace\n");
    }
    else
    {
        PRINT_DEBUG("INT3 received but CPL is not 0x3\n");
        return false;
    }

    if (injector->fork)
    {
        if ( injector->child_data.ppid != info->proc_data.ppid )
        {
            PRINT_DEBUG("INT3 received but forked process parent pid (%d) doesn't match the target pid (%d)\n",
                info->proc_data.ppid, injector->child_data.ppid);
            return false;
        }
        if ( strcmp(injector->child_data.name, info->proc_data.name))
        {
            PRINT_DEBUG("INT3 received but forked process name (%s) doesn't match the target process name (%s)\n",
                info->proc_data.name, injector->child_data.name);
            return false;
        }
        injector->fork = false;
        return true;
    }

    bool is_target = (info->proc_data.pid == injector->target_pid && info->proc_data.tid == injector->target_tid);
    bool is_child = (info->proc_data.pid == injector->child_data.pid && info->proc_data.tid == injector->child_data.tid);

    if ( !is_target && !is_child )
    {
        PRINT_DEBUG("INT3 received but '%s' PID:TID (%u:%u) doesn't match target process (%u:%u) or child process (%u:%u)\n",
            info->proc_data.name, info->proc_data.pid, info->proc_data.tid,
            injector->target_pid, injector->target_tid,
            injector->child_data.pid, injector->child_data.tid);
        return false;
    }

    if (info->regs->rip != info->trap->breakpoint.addr)
    {
        PRINT_DEBUG("INT3 received but BP_ADDR (%lx) doesn't match RIP (%lx)\n",
            info->trap->breakpoint.addr, info->regs->rip);
        if (is_child && !injector->execve)
            PRINT_DEBUG("Trap child process in not execve stage\n");
    }

    return true;
}

event_response_t injector_int3_userspace_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    linux_injector_t injector = info->trap->data;
    base_injector_t base_injector = &injector->base_injector;

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx. vcpu %i. TID %u\n",
        info->regs->rip, info->regs->cr3, info->vcpu, info->proc_data.tid);

    if (!check_userspace_int3_trap(injector, info))
        return VMI_EVENT_RESPONSE_NONE;

    // reset the override on every run
    base_injector->step_override = false;

    event_response_t event = 0;
    switch (injector->method)
    {
        case INJECT_METHOD_SHELLCODE:
        {
            event = handle_shellcode(drakvuf, info);
            break;
        }
        case INJECT_METHOD_WRITE_FILE:
        {
            event = handle_write_file(drakvuf, info);
            break;
        }
        case INJECT_METHOD_READ_FILE:
        {
            event = handle_read_file(drakvuf, info);
            break;
        }
        case INJECT_METHOD_EXECPROC:
        {
            event = handle_execve(drakvuf, info);
            break;
        }
        default:
        {
            PRINT_DEBUG("Should not be here\n");
            assert(false);
        }
    }

    // increase the step only if there is no manual override
    if (!base_injector->step_override)
        base_injector->step += 1;

    return event;
}

static event_response_t wait_for_target_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    linux_injector_t injector = info->trap->data;

    // right now we are in kernel space
    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 ". PID: %u PPID: %u TID: %u\n",
        info->regs->cr3, info->proc_data.pid, info->proc_data.ppid, info->proc_data.tid);

    if (info->proc_data.pid != injector->target_pid || info->proc_data.tid != injector->target_tid)
        return VMI_EVENT_RESPONSE_NONE;

    // rcx register should have the address for userspace rip
    // for x64 systems
    // if rcx doesn't have it, TODO: try to extract it from stack
    addr_t bp_addr = info->regs->rcx;

    drakvuf_trap_t* bp = g_malloc0(sizeof(drakvuf_trap_t));

    // setup int3 trap
    bp->type = BREAKPOINT;
    bp->name = "injector_int3_userspace_cb";
    bp->cb = injector_int3_userspace_cb;
    bp->data = injector;
    bp->breakpoint.lookup_type = LOOKUP_DTB;
    bp->breakpoint.dtb = info->regs->cr3;
    bp->breakpoint.addr_type = ADDR_VA;
    bp->breakpoint.addr = bp_addr;
    bp->ttl = UNLIMITED_TTL;
    bp->ah_cb = NULL;

    if ( drakvuf_add_trap(injector->drakvuf, bp) )
    {
        PRINT_DEBUG("Usermode Trap Addr: %lx\n", info->regs->rcx);
        injector->bp = bp;

        // Unsubscribe from the trap
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
    }
    else
    {
        fprintf(stderr, "Failed to trap trapframe return address\n");
        PRINT_DEBUG("Will keep trying in next callback\n");
        print_registers(info);
        print_stack(drakvuf, info, info->regs->rsp);
        g_free(bp);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t kernel_panic_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // right now we are in kernel space
    PRINT_DEBUG("Kernel panic. PID: %u PPID: %u TID: %u\n",
        info->proc_data.pid, info->proc_data.ppid, info->proc_data.tid);

    drakvuf_interrupt(drakvuf, SIGDRAKVUFKERNELPANIC);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t kernel_exit_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    linux_injector_t injector = info->trap->data;

    if (info->proc_data.pid != injector->target_pid || info->proc_data.tid != injector->target_tid)
        return VMI_EVENT_RESPONSE_NONE;

    // right now we are in kernel space
    PRINT_DEBUG("Target thread exit. PID: %u PPID: %u TID: %u\n",
        info->proc_data.pid, info->proc_data.ppid, info->proc_data.tid);

    drakvuf_interrupt(drakvuf, SIGDRAKVUFCRASH);

    return VMI_EVENT_RESPONSE_NONE;
}

static bool is_interrupted(drakvuf_t drakvuf, void* data __attribute__((unused)))
{
    return drakvuf_is_interrupted(drakvuf);
}

static bool inject(drakvuf_t drakvuf, linux_injector_t injector)
{
    reg_t lstar;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool status = VMI_SUCCESS == vmi_get_vcpureg(vmi, &lstar, MSR_LSTAR, 0);
    drakvuf_release_vmi(drakvuf);
    if (!status)
    {
        fprintf(stderr, "Failed to get MSR_LSTAR\n");
        return false;
    }

    drakvuf_trap_t trap =
    {
        .type = BREAKPOINT,
        .breakpoint.lookup_type = LOOKUP_KERNEL,
        .breakpoint.addr_type = ADDR_VA,
        .breakpoint.addr = lstar,
        .name = "entry_SYSCALL_64",
        .cb = wait_for_target_process_cb,
        .data = injector
    };

    if (!drakvuf_add_trap(drakvuf, &trap))
    {
        fprintf(stderr, "Failed to set trap wait_for_target_process_cb callback\n");
        return false;
    }

    addr_t kernel_base = drakvuf_get_kernel_base(drakvuf);

    addr_t _text;
    if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "_text", &_text) )
    {
        PRINT_DEBUG("Failed to get RVA of _text\n");
        return false;
    }

    addr_t kaslr = kernel_base - _text;

    addr_t panic;
    if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "panic", &panic) )
    {
        PRINT_DEBUG("Failed to get RVA of panic\n");
        return false;
    }

    drakvuf_trap_t trap_panic =
    {
        .type = BREAKPOINT,
        .breakpoint.lookup_type = LOOKUP_PID,
        .breakpoint.pid = 0,
        .breakpoint.addr_type = ADDR_VA,
        .breakpoint.addr = panic + kaslr,
        .name = "panic",
        .cb = kernel_panic_cb,
        .data = injector
    };

    if (!drakvuf_add_trap(drakvuf, &trap_panic))
    {
        fprintf(stderr, "Failed to set trap kernel_panic_cb callback\n");
        return false;
    }

    addr_t exit;
    if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "do_exit", &exit) )
    {
        PRINT_DEBUG("Failed to get RVA of do_exit\n");
        return false;
    }

    drakvuf_trap_t trap_exit =
    {
        .type = BREAKPOINT,
        .breakpoint.lookup_type = LOOKUP_PID,
        .breakpoint.pid = 0,
        .breakpoint.addr_type = ADDR_VA,
        .breakpoint.addr = exit + kaslr,
        .name = "do_exit",
        .cb = kernel_exit_cb,
        .data = injector
    };

    if (!drakvuf_add_trap(drakvuf, &trap_exit))
    {
        fprintf(stderr, "Failed to set trap kernel_exit_cb callback\n");
        return false;
    }

    if (!drakvuf_is_interrupted(drakvuf))
    {
        PRINT_DEBUG("Starting drakvuf loop\n");
        drakvuf_loop(drakvuf, is_interrupted, NULL);
        PRINT_DEBUG("Finished drakvuf loop\n");
    }

    drakvuf_remove_trap(drakvuf, &trap_panic, NULL);
    drakvuf_remove_trap(drakvuf, &trap_exit, NULL);

    if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        injector->rc = INJECTOR_TIMEOUTED;

    return true;
}

static bool init_injector(linux_injector_t injector)
{
    switch (injector->method)
    {
        case INJECT_METHOD_SHELLCODE:
        {
            // ret will be appended to shellcode here
            return load_shellcode_from_file(injector, injector->host_file);
            break;
        }
        case INJECT_METHOD_EXECPROC:
        {
            if (!injector->host_file)
            {
                fprintf(stderr, "Inject file is required\n");
                return false;
            }
            return true;
            break;
        }
        case INJECT_METHOD_WRITE_FILE:
        {
            if (!injector->target_file)
            {
                fprintf(stderr, "Target File is missing");
                return false;
            }
            if (!injector->host_file)
            {
                fprintf(stderr, "Host File is missing");
                return false;
            }
            return init_write_file_method(injector, injector->host_file);
            break;
        }
        case INJECT_METHOD_READ_FILE:
        {
            if (!injector->target_file)
            {
                fprintf(stderr, "Target File is missing");
                return false;
            }
            if (!injector->host_file)
            {
                fprintf(stderr, "Host File is missing");
                return false;
            }
            return init_read_file_method(injector, injector->host_file);
        }
        default:
        {
            fprintf(stderr, "Method not supported for [LINUX]\n");
            return false;
        }
    }
    return true;
}

injector_status_t injector_start_app_on_linux(
    drakvuf_t drakvuf,
    vmi_pid_t pid,
    uint32_t tid,
    const char* file,
    injection_method_t method,
    output_format_t format,
    const char* binary_path,
    int args_count,
    const char** args,
    vmi_pid_t* injected_pid
)
{
    linux_injector_t injector = (linux_injector_t)g_malloc0(sizeof(struct linux_injector));
    base_injector_t base_injector = &injector->base_injector;
    injector->drakvuf = drakvuf;
    injector->target_pid = pid;
    injector->target_tid = tid;
    if (method == INJECT_METHOD_WRITE_FILE || method == INJECT_METHOD_READ_FILE)
    {
        // since in these two, -B gives the path to host file
        injector->host_file = binary_path;
        injector->target_file = file;
    }
    else
    {
        // in other methods, -e gives the path to host file
        injector->host_file = file;
        injector->target_file = NULL;
    }
    if (!injector->target_tid)
        injector->target_tid = pid;
    injector->args_count = args_count;

    injector->args = (const char**)g_new0(const char*, args_count + 1);

    for ( int i = 0; i<args_count; i++ )
        injector->args[i] = args[i];
    injector->method = method;
    base_injector->step = STEP1;

    if (!init_injector(injector))
    {
        injector->result = INJECT_RESULT_INIT_FAIL;
        print_linux_injection_info(format, injector);
        injector_free_linux(injector);
        return 0;
    }

    if (inject(drakvuf, injector) && injector->rc == INJECTOR_SUCCEEDED)
    {
        injector->result = INJECT_RESULT_SUCCESS;
        print_linux_injection_info(format, injector);
    }
    else
    {
        if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        {
            PRINT_DEBUG("Injection timeout\n");
            injector->result = INJECT_RESULT_TIMEOUT;
            print_linux_injection_info(format, injector);
        }
        else
        {
            PRINT_DEBUG("Injection premature break\n");
            injector->result = INJECT_RESULT_PREMATURE;
            print_linux_injection_info(format, injector);
        }
    }

    injector_status_t rc = injector->rc;
    if (injected_pid)
        *injected_pid = injector->pid;
    PRINT_DEBUG("Finished with injection. Ret: %i.\n", rc);

    injector_free_linux(injector);
    return rc;
}
