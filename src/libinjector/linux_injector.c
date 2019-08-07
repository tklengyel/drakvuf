/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
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

#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/x86.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <inttypes.h>
#include <glib.h>
#include <json-c/json.h>

#include "libdrakvuf/libdrakvuf.h"
#include <libinjector/libinjector.h>
#include "private.h"

typedef enum
{
    INJECT_RESULT_SUCCESS,
    INJECT_RESULT_TIMEOUT,
    INJECT_RESULT_CRASH,
    INJECT_RESULT_PREMATURE,
    INJECT_RESULT_ERROR_CODE,
} inject_result_t;

struct injector
{
    // Inputs:
    const char* target_file;
    vmi_pid_t target_pid;
    addr_t target_base;
    uint32_t target_tid;

    // Internal:
    drakvuf_t drakvuf;
    bool hijacked, detected;
    injection_method_t method;
    addr_t exec_func;
    reg_t target_rsp, target_rip;

    // for exec()
    const char* args[10];
    int args_count;

    // For shellcode execution
    addr_t payload, payload_addr, memset;
    size_t payload_size;
    uint32_t status;

    x86_registers_t saved_regs;

    drakvuf_trap_t bp;
    GSList* memtraps;

    // Results:
    int rc;
    inject_result_t result;
    struct
    {
        bool valid;
        uint32_t code;
        const char* string;
    } error_code;

    uint32_t pid, tid;
};

static void free_memtraps(injector_t injector)
{
    GSList* loop = injector->memtraps;
    injector->memtraps = NULL;

    while (loop)
    {
        drakvuf_remove_trap(injector->drakvuf, loop->data, (drakvuf_trap_free_t)free);
        loop = loop->next;
    }
    g_slist_free(loop);
}

static void free_injector(injector_t injector)
{
    if (!injector) return;

    PRINT_DEBUG("Injector freed\n");

    free_memtraps(injector);

    g_free((void*)injector->payload);
    g_free((void*)injector);
}

// Linux - injector - exec process setup
static bool setup_create_process_regs_and_stack(injector_t injector, drakvuf_trap_info_t* info)
{
    int total_args = injector->args_count + 3;
    struct argument arguments[13] = {{0}};

    // int execlp(const char *file, const char *arg, ...);

    PRINT_DEBUG("Target file : %s\n", injector->target_file);
    size_t sz = strlen(injector->target_file);
    init_argument(&arguments[0], ARGUMENT_STRING, sz, (char*)injector->target_file);
    init_argument(&arguments[1], ARGUMENT_STRING, sz, (char*)injector->target_file);
    if (injector->args_count > 0)
    {
        for (int i=0; i<injector->args_count; i++)
        {
            PRINT_DEBUG("Argument %d : %s\n", i+1, (injector->args[i]));
            sz = strlen(injector->args[i]);
            init_argument(&arguments[i+2], ARGUMENT_STRING, sz, (char*)injector->args[i]);
        }
    }
    init_int_argument(&arguments[total_args-1], 0);
    bool success = setup_linux_stack(injector->drakvuf, info, arguments, total_args);
    return success;
}

static bool setup_malloc_function_stack(injector_t injector, drakvuf_trap_info_t* info)
{
    struct argument args[2] = { {0} };

    // void *malloc(size_t size);

    init_int_argument(&args[0], injector->payload_size); // check for size to be allocated (binary size)
    init_int_argument(&args[1], 0);

    return setup_linux_stack(injector->drakvuf, info, args, ARRAY_SIZE(args));
}

static bool setup_linux_memset_stack(injector_t injector, drakvuf_trap_info_t* info)
{
    struct argument args[4] = { {0} };

    // void *memset(void *s, int c, size_t n);

    init_int_argument(&args[0], injector->payload_addr);
    init_int_argument(&args[1], 0);
    init_int_argument(&args[2], injector->payload_size); // check for (binary size)
    init_int_argument(&args[3], 0);

    return setup_linux_stack(injector->drakvuf, info, args, ARRAY_SIZE(args));
}

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

static event_response_t linux_injector_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

static bool setup_linux_int3_trap(injector_t injector, drakvuf_trap_info_t* info, addr_t bp_addr)
{
    injector->bp.type = BREAKPOINT;
    injector->bp.name = "entry";
    injector->bp.cb = linux_injector_int3_cb;
    injector->bp.data = injector;
    injector->bp.breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp.breakpoint.dtb = info->regs->cr3;
    injector->bp.breakpoint.addr_type = ADDR_VA;
    injector->bp.breakpoint.addr = bp_addr;

    return drakvuf_add_trap(injector->drakvuf, &injector->bp);
}

static event_response_t wait_for_target_linux_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 ". TID: %u PID: %u PPID: %u\n",
                info->regs->cr3, info->proc_data.tid, info->proc_data.pid, info->proc_data.ppid);

    if (info->proc_data.pid != injector->target_pid || (uint32_t)info->proc_data.tid != injector->target_tid)
    {
        return 0;
    }

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    // if (!drakvuf_get_struct_members_array_rva(drakvuf, linux_offset_names, LINUX_OFFSET_MAX, injector->linux_offsets))
    // {
    //     PRINT_DEBUG("Could not populate offset names! \n");
    //     goto done;
    // }

    addr_t rip = info->regs->rip;
    vmi_get_vcpureg(vmi, &rip, RIP, 0);
    PRINT_DEBUG("Rip is 0x%lx \n", rip);

    // exec offset reference
    // 00000000000e5160 -> GLIBC_2.2.5 execl
    // 00000000000e4fa0 -> GLIBC_2.2.5 execv
    // 00000000000e5490 -> GLIBC_2.11  execvpe
    // 00000000000e4fb0 -> GLIBC_2.2.5 execle
    // 00000000000e5300 -> GLIBC_2.2.5 execlp
    // 00000000000e4e30 -> GLIBC_2.2.5 execve
    // 00000000000e52f0 -> GLIBC_2.2.5 execvp

    // 0000000000097070 -> malloc@@GLIBC_2.2.5
    // 000000000009ed40 -> memset@@GLIBC_2.2.5


    if (injector->method == INJECT_METHOD_EXECPROC)
    {
        injector->exec_func = drakvuf_export_linux_sym_to_va(drakvuf, info, injector->target_pid, "libc-2.27.so", "execlp");
        PRINT_DEBUG("Address of execlp symbol is: 0x%lx \n", injector->exec_func);
    }

    // failing to grab some symbols due to relocation
    else if (injector->method == INJECT_METHOD_SHELLCODE_LINUX)
    {
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
        printf("Under Construction!!");
        drakvuf_release_vmi(drakvuf);
        return 0;
        injector->exec_func = drakvuf_export_linux_sym_to_va(drakvuf, info, injector->target_pid, "libc-2.27.so", "malloc");
        PRINT_DEBUG("Address of malloc symbol is: 0x%lx \n", injector->exec_func);
    }

    injector->target_base = drakvuf_get_current_process(drakvuf, info);
    PRINT_DEBUG("Injector->target_base = 0x%lx \n", injector->target_base);

    if (setup_linux_int3_trap(injector, info, rip))
    {
        PRINT_DEBUG("Got return address 0x%lx and it's now trapped!\n", rip);
        // Unsubscribe from the CR3 trap
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
    }
    else
        PRINT_DEBUG("Failed to trap trapframe return address\n");

    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t wait_for_injected_process_cb_linux(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("Injected process callback !!\n");
    injector_t injector = info->trap->data;
    PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);

    if (injector->target_pid != info->proc_data.pid || injector->target_tid != (uint32_t)info->proc_data.pid)
    {
        PRINT_DEBUG("%u|%u|%u|%u \n", info->proc_data.pid, injector->target_pid, info->proc_data.tid, injector->target_tid);
        return 0;
    }

    if (injector->method == INJECT_METHOD_EXECPROC && injector->status == STATUS_CREATE_OK)
    {
        if (info->regs->rax == 0xffffffff)
        {
            printf("Process start failed!! Exec returned -1 \n");
            injector->rc = 0;
            injector->detected = false;
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);
            drakvuf_interrupt(drakvuf, SIGINT);
            return 0;
        }
        if (strncmp(info->proc_data.name, injector->target_file, 15) != 0)
        {
            PRINT_DEBUG("%s || %s \n", info->proc_data.name, injector->target_file);
            return 0;
        }
    }

    injector->pid = injector->target_pid;
    injector->tid = injector->target_tid;

    printf("Process start detected %i -> 0x%lx\n", injector->pid, info->regs->cr3);
    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);
    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);
    drakvuf_interrupt(drakvuf, SIGINT);

    injector->rc = 1;
    injector->detected = true;

    return 0;
}

static bool setup_wait_for_injected_process_trap_linux(injector_t injector)
{
    drakvuf_trap_t* trap = g_malloc0(sizeof(drakvuf_trap_t));
    trap->type = REGISTER;
    trap->reg = CR3;
    trap->cb = wait_for_injected_process_cb_linux;
    trap->data = injector;
    if (!drakvuf_add_trap(injector->drakvuf, trap))
    {
        PRINT_DEBUG("Failed to setup wait_for_injected_process trap!\n");
        return false;
    }
    PRINT_DEBUG("Waiting for injected process\n");
    return true;
}

static event_response_t inject_payload_linux(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    // injector->payload_addr = info->regs->rax;
    // Doesnt work?
    // input value was 0x555555768280
    // while returned was 0x7ffff77e9f50

    // Write payload into guest's memory
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = injector->payload_addr,
    };
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool success = ( VMI_SUCCESS == vmi_write(vmi, &ctx, injector->payload_size, (void*)injector->payload, NULL) );
    drakvuf_release_vmi(drakvuf);

    if ( !success )
    {
        PRINT_DEBUG("Failed to write the payload into memory!\n");
        return 0;
    }

    info->regs->rip = injector->target_rip;

    // struct argument args[6] = { {0} };
    // init_int_argument(&args[0], 0);
    // init_int_argument(&args[1], 0);
    // init_int_argument(&args[2], 0);
    // init_int_argument(&args[3], 0);
    // init_int_argument(&args[4], 0);
    // init_int_argument(&args[5], 0);

    if (!setup_linux_stack(injector->drakvuf, info, NULL, 6))
    {
        PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
        return 0;
    }

    info->regs->rip = injector->payload_addr;


    if (!injector_set_hijacked(injector, info))
        return 0;
    injector->status = STATUS_EXEC_OK;


    PRINT_DEBUG("Executing the payload..\n");

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t wait_for_process_in_userspace(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("Injected process callback in usermode!!\n");
    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx.\n", info->regs->rip, info->regs->cr3);
    PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);
    if (info->regs->rip != info->trap->breakpoint.addr)
    {
        return 0;
    }
    injector_t injector = info->trap->data;


    if (!injector->hijacked && injector->status == STATUS_NULL)
    {
        memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));
        bool success = false;
        switch (injector->method)
        {
            case INJECT_METHOD_EXECPROC:
                success = setup_create_process_regs_and_stack(injector, info);
                injector->target_rsp = info->regs->rsp;
                break;
            case INJECT_METHOD_SHELLEXEC:
                // TODO
                break;
            case INJECT_METHOD_SHELLCODE_LINUX:
                success = setup_malloc_function_stack(injector, info);
                break;
            default:
                PRINT_DEBUG("Goes to default set injection->method correctly \n");
                success = false;
                break;
        }

        if (!success)
        {
            // God forgive me
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
            return 0;
        }

        injector->target_rip = info->regs->rip;
        info->regs->rip = injector->exec_func;
        PRINT_DEBUG("Rip is  : 0x%lx \n", info->regs->rip);

        if (injector->method == INJECT_METHOD_EXECPROC)
        {
            if (!injector_set_hijacked(injector, info))
                return 0;
            injector->status = STATUS_CREATE_OK;

            if (!setup_wait_for_injected_process_trap_linux(injector))
                return 0;
        }
        else if (injector->method == INJECT_METHOD_SHELLCODE_LINUX)
        {
            injector->status = STATUS_ALLOC_OK;
        }

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    if (injector->method == INJECT_METHOD_SHELLCODE_LINUX && injector->status == STATUS_ALLOC_OK)
    {
        PRINT_DEBUG("Writing to allocated virtual memory to allocate physical memory..\n");

        injector->payload_addr = info->regs->rax;

        // Add memset offset to libc address
        // 000000000009ed40 -> memset@@GLIBC_2.2.5
        // injector->exec_func = injector->libc_addr + 0x9ed40;
        // injector->exec_func = drakvuf_export_linux_sym_to_va(drakvuf, info, injector->target_pid, "libc-2.27.so", "memset");

        info->regs->rip = injector->target_rip;

        if (!setup_linux_memset_stack(injector, info))
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        info->regs->rip = injector->exec_func;

        injector->status = STATUS_PHYS_ALLOC_OK;

        PRINT_DEBUG("Payload is at: 0x%lx\n", injector->payload_addr);

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    if (injector->status == STATUS_PHYS_ALLOC_OK)
    {
        return inject_payload_linux(drakvuf, info);
    }

    if (injector->method == INJECT_METHOD_EXECPROC && injector->status == STATUS_CREATE_OK)
    {
        PRINT_DEBUG("Return back after execve() execution!!\n");
        PRINT_DEBUG("*RAX: 0x%lx\n", info->regs->rax);

        if (info->regs->rax == 0xffffffff)
        {
            PRINT_DEBUG("\n*Process start failed!! as execve() returned -1 \n");
            injector->rc = 0;
            injector->detected = false;
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_interrupt(drakvuf, SIGINT);
            // reset the process registers, if exec fails
            memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        return 0;
    }

    if (injector->method == INJECT_METHOD_SHELLCODE_LINUX && injector->status == STATUS_EXEC_OK)
    {
        printf("Shellcode executed successfully\n");
        injector->rc = 1;
    }

    // Unexpected state
    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    PRINT_DEBUG("Setting back register to orginial state \n");
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static bool setup_linux_int3_trap_in_userspace(injector_t injector, drakvuf_trap_info_t* info, addr_t bp_addr)
{
    drakvuf_trap_t* new_trap = g_malloc0(sizeof(drakvuf_trap_t));
    new_trap->type = BREAKPOINT;
    new_trap->name = "entry";
    new_trap->breakpoint.lookup_type = LOOKUP_PID;
    new_trap->breakpoint.pid = info->proc_data.tid;
    new_trap->breakpoint.addr_type = ADDR_VA;
    new_trap->breakpoint.addr = bp_addr;
    new_trap->cb = wait_for_process_in_userspace;
    new_trap->data = injector;

    return drakvuf_add_trap(injector->drakvuf, new_trap);
}

static event_response_t linux_injector_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx.\n", info->regs->rip, info->regs->cr3);

    // pid is thread group id in linux, and tid is thread id
    if ((uint32_t)info->proc_data.tid == injector->target_tid && info->proc_data.pid == injector->target_pid)
    {
        PRINT_DEBUG("%u|%u|%u|%u \n", info->proc_data.pid, injector->target_pid, info->proc_data.tid, injector->target_tid);

        // kernel mode

        // rcx -> value of rip in usermode && kernelmode
        // TESTING REQUIRED FOR 100% ASSURITY
        // otherwise acquire it from stack now

        // setting TRAP on BP addr -> rcx -> rip
        addr_t bp_addr = info->regs->rcx;
        injector->target_rip = bp_addr;
        PRINT_DEBUG("Usermode Breakpoint addr: %lx \n", bp_addr);

        if (setup_linux_int3_trap_in_userspace(injector, info, bp_addr))
        {
            PRINT_DEBUG("Got return address 0x%lx and it's now trapped in usermode!\n", bp_addr);
            // Unsubscribe from the CR3 trap
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
        }
        else
            PRINT_DEBUG("Failed to trap trapframe return address\n");
    }
    return 0;
}


static bool inject(drakvuf_t drakvuf, injector_t injector)
{
    injector->hijacked = 0;
    injector->status = STATUS_NULL;

    drakvuf_trap_t trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = wait_for_target_linux_process_cb,
        .data = injector,
    };

    if (!drakvuf_add_trap(drakvuf, &trap))
        return false;

    if (!drakvuf_is_interrupted(drakvuf))
    {
        PRINT_DEBUG("Starting injection loop\n");
        drakvuf_loop(drakvuf);
    }

    free_memtraps(injector);

    // drakvuf_remove_trap(drakvuf, &trap, NULL);
    return true;
}

static bool load_file_to_memory(addr_t* output, size_t* size, const char* file)
{
    size_t payload_size = 0;
    unsigned char* data = NULL;
    FILE* fp = fopen(file, "rb");

    if (!fp)
        return false;

    // obtain file size:
    fseek (fp, 0, SEEK_END);
    payload_size = ftell (fp);
    rewind (fp);

    data = g_malloc0(payload_size);
    if ( !data )
    {
        fclose(fp);
        return false;
    }

    if ( payload_size != fread(data, 1, payload_size, fp))
    {
        g_free(data);
        fclose(fp);
        return false;
    }

    *output = (addr_t)data;
    *size = payload_size;

    PRINT_DEBUG("Size of file read: %lu\n", payload_size);

    fclose(fp);

    return true;
}

static void print_injection_info(output_format_t format, const char* file, injector_t injector)
{
    GTimeVal t;
    g_get_current_time(&t);

    char* process_name = NULL;
    char* arguments = NULL;

    char* splitter = " ";
    const char* begin_proc_name = &file[0];

    if (file[0] == '"')
    {
        splitter = "\"";
        begin_proc_name = &file[1];
    }

    char** split_results = g_strsplit_set(begin_proc_name, splitter, 2);
    char** split_results_iterator = split_results;

    if (*split_results_iterator)
    {
        process_name = *(split_results_iterator++);
    }

    if (*split_results_iterator)
    {
        arguments = *(split_results_iterator++);
        if (arguments[0] == ' ')
            arguments++;
    }
    else
    {
        arguments = "";
    }

    char* escaped_arguments = g_strescape(arguments, NULL);

    switch (injector->result)
    {
        case INJECT_RESULT_SUCCESS:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Success,%u,\"%s\",\"%s\",%u,%u\n",
                           UNPACK_TIMEVAL(t), injector->target_pid, process_name, escaped_arguments, injector->pid, injector->tid);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Success,PID=%u,ProcessName=\"%s\",Arguments=\"%s\",InjectedPid=%u,InjectedTid=%u\n",
                           UNPACK_TIMEVAL(t), injector->target_pid, process_name, escaped_arguments, injector->pid, injector->tid);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:SUCCESS PID:%u FILE:\"%s\" ARGUMENTS:\"%s\" INJECTED_PID:%u INJECTED_TID:%u\n",
                           UNPACK_TIMEVAL(t), injector->target_pid, process_name, escaped_arguments, injector->pid, injector->tid);
                    break;
            }
            break;
        case INJECT_RESULT_TIMEOUT:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Timeout\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Timeout\n", UNPACK_TIMEVAL(t));
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:Timeout\n", UNPACK_TIMEVAL(t));
                    break;
            }
            break;
        case INJECT_RESULT_CRASH:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Crash\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Crash\n", UNPACK_TIMEVAL(t));
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:Crash\n", UNPACK_TIMEVAL(t));
                    break;
            }
            break;
        case INJECT_RESULT_PREMATURE:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",PrematureBreak\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=PrematureBreak\n", UNPACK_TIMEVAL(t));
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:PrematureBreak\n", UNPACK_TIMEVAL(t));
                    break;
            }
            break;
        case INJECT_RESULT_ERROR_CODE:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Error,%d,\"%s\"\n",
                           UNPACK_TIMEVAL(t), injector->error_code.code, injector->error_code.string);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Error,ErrorCode=%d,Error=\"%s\"\n",
                           UNPACK_TIMEVAL(t), injector->error_code.code, injector->error_code.string);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:Error ERROR_CODE:%d ERROR:\"%s\"\n",
                           UNPACK_TIMEVAL(t), injector->error_code.code, injector->error_code.string);
                    break;
            }
            break;
    }

    g_free(escaped_arguments);
    g_strfreev(split_results);
}

static bool initialize_linux_injector_functions(injector_t injector)
{
    if (injector->method == INJECT_METHOD_SHELLCODE_LINUX)
    {
        PRINT_DEBUG("File is %s\n", injector->target_file);
        if ( !load_file_to_memory(&injector->payload, &injector->payload_size, injector->target_file) )
        {
            PRINT_DEBUG("Failed to load file into memory\n");
            return false;
        }
        PRINT_DEBUG("File address in memory %lx\n", injector->payload);
        PRINT_DEBUG("File size in memory %lx\n", injector->payload_size);
        return true;
    }
    return true;
}

int injector_start_app_on_linux(
    drakvuf_t drakvuf,
    vmi_pid_t pid,
    uint32_t tid,
    const char* file,
    injection_method_t method,
    output_format_t format,
    const char* args[],
    int args_count)
{
    int rc = 0;
    printf("Target PID %u to inject '%s'\n", pid, file);
    injector_t injector = (injector_t)g_malloc0(sizeof(struct injector));
    if (!injector)
    {
        printf("Injector NOT initialized \n");
        return 0;
    }
    injector->drakvuf = drakvuf;
    injector->target_pid = pid;  // Pid = Thread Group Id in Linux
    injector->target_tid = tid;
    injector->method = method;
    injector->target_file = file;
    injector->status = STATUS_NULL;
    injector->error_code.valid = false;
    injector->error_code.code = -1;
    injector->error_code.string = "<UNKNOWN>";
    injector->args_count = args_count;
    // injector->args = args;
    for (int i=0; i<args_count; i++)
        injector->args[i] = args[i];

    if (!initialize_linux_injector_functions(injector))
    {
        PRINT_DEBUG("Unable to initialize injector functions\n");
        free_injector(injector);
        return 0;
    }

    if (inject(drakvuf, injector) && injector->rc)
    {
        injector->result = INJECT_RESULT_SUCCESS;
        print_injection_info(format, file, injector);
    }
    else
    {
        if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        {
            injector->result = INJECT_RESULT_TIMEOUT;
            print_injection_info(format, file, injector);
        }
        else if (SIGDRAKVUFCRASH == drakvuf_is_interrupted(drakvuf))
        {
            injector->result = INJECT_RESULT_CRASH;
            print_injection_info(format, file, injector);
        }
        else if (injector->error_code.valid)
        {
            injector->result = INJECT_RESULT_ERROR_CODE;
            print_injection_info(format, file, injector);
        }
        else
        {
            injector->result = INJECT_RESULT_PREMATURE;
            print_injection_info(format, file, injector);
        }
    }

    rc = injector->rc;
    printf("Finished with injection. Ret: %i.\n", rc);

    free_injector(injector);

    return rc;
}