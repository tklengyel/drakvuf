/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
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

#include "linux_injector.h"
#include "linux_debug.h"
#include "methods/linux_shellcode.h"

bool check_userspace_int3_trap(injector_t injector, drakvuf_trap_info_t* info)
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

    if ( info->proc_data.pid != injector->target_pid )
    {
        PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
            info->proc_data.name, info->proc_data.pid, injector->target_pid);
        return false;
    }

    if (info->regs->rip != info->trap->breakpoint.addr)
    {
        PRINT_DEBUG("INT3 received but BP_ADDR (%lx) doesn't match RIP (%lx)",
            info->trap->breakpoint.addr, info->regs->rip);
        assert(false);
    }

    if (injector->target_tid && (uint32_t)info->proc_data.tid != injector->target_tid)
    {
        PRINT_DEBUG("INT3 received but '%s' TID (%u) doesn't match target process (%u)\n",
            info->proc_data.name, info->proc_data.tid, injector->target_tid);
        return false;
    }

    return true;
}

event_response_t injector_int3_userspace_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx. vcpu %i. TID %u\n",
        info->regs->rip, info->regs->cr3, info->vcpu, info->proc_data.tid);

    if (!check_userspace_int3_trap(injector, info))
        return VMI_EVENT_RESPONSE_NONE;

    // reset the override on every run
    injector->step_override = false;

    event_response_t event;
    switch (injector->method)
    {
        case INJECT_METHOD_SHELLCODE:
        {
            event = handle_shellcode(drakvuf, info);
            break;
        }
        default:
        {
            PRINT_DEBUG("Should not be here\n");
            assert(false);
        }
    }

    // increase the step only if there is no manual override
    if (!injector->step_override)
        injector->step += 1;

    return event;
}

static event_response_t wait_for_target_process_cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    // right now we are in kernel space
    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 ". PID: %u PPID: %u TID: %u\n",
        info->regs->cr3, info->proc_data.pid, info->proc_data.ppid, info->proc_data.tid);

    if (info->proc_data.pid != injector->target_pid && info->proc_data.tid != injector->target_tid)
        return 0;

    // rcx register should have the address for userspace rip
    // for x64 systems
    // if rcx doesn't have it, TODO: try to extract it from stack
    addr_t bp_addr = info->regs->rcx;

    injector->bp = g_malloc0(sizeof(drakvuf_trap_t));

    // setup int3 trap
    injector->bp->type = BREAKPOINT;
    injector->bp->name = "injector_int3_userspace_cb";
    injector->bp->cb = injector_int3_userspace_cb;
    injector->bp->data = injector;
    injector->bp->breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp->breakpoint.dtb = info->regs->cr3;
    injector->bp->breakpoint.addr_type = ADDR_VA;
    injector->bp->breakpoint.addr = bp_addr;
    injector->bp->ttl = UNLIMITED_TTL;
    injector->bp->ah_cb = NULL;

    if ( drakvuf_add_trap(injector->drakvuf, injector->bp) )
    {
        PRINT_DEBUG("Usermode Trap Addr: %lx\n", info->regs->rcx);

        // Unsubscribe from the CR3 trap
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
    }
    else
    {
        fprintf(stderr, "Failed to trap trapframe return address\n");
        PRINT_DEBUG("Will keep trying in next callback\n");
        print_registers(info);
        print_stack(drakvuf, info, info->regs->rsp);
        g_free(injector->bp);
        injector->bp = NULL;
    }

    return 0;
}

static bool is_interrupted(drakvuf_t drakvuf, void* data __attribute__((unused)))
{
    return drakvuf_is_interrupted(drakvuf);
}

static bool inject(drakvuf_t drakvuf, injector_t injector)
{
    drakvuf_trap_t trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = wait_for_target_process_cr3_cb,
        .data = injector,
    };

    if (!drakvuf_add_trap(drakvuf, &trap))
    {
        fprintf(stderr, "Failed to set trap wait_for_target_process_cr3_cb callback");
        return false;
    }

    if (!drakvuf_is_interrupted(drakvuf))
    {
        PRINT_DEBUG("Starting drakvuf loop\n");
        drakvuf_loop(drakvuf, is_interrupted, NULL);
        PRINT_DEBUG("Finished drakvuf loop\n");
    }

    if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        injector->rc = INJECTOR_TIMEOUTED;

    return true;
}

bool init_injector(injector_t injector)
{
    switch (injector->method)
    {
        case INJECT_METHOD_SHELLCODE:
        {
            // ret will be appended to shellcode here
            return load_shellcode_from_file(injector, injector->target_file);
            break;
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
    int args_count,
    const char** args
)
{
    injector_t injector = (injector_t)g_malloc0(sizeof(struct injector));
    injector->drakvuf = drakvuf;
    injector->target_pid = pid;
    injector->target_tid = tid;
    injector->target_file = file;
    if (!injector->target_tid)
        injector->target_tid = pid;
    injector->args_count = args_count;

    injector->args = (const char**)g_new0(const char*, args_count);

    for ( int i = 0; i<args_count; i++ )
        injector->args[i] = args[i];
    injector->method = method;
    injector->format = format;
    injector->step = STEP1;

    if (init_injector(injector))
    {
        inject(drakvuf, injector);
        injector->result = INJECT_RESULT_SUCCESS;
        injector->rc = INJECTOR_SUCCEEDED;
    }
    else
    {
        injector->result = INJECT_RESULT_METHOD_UNSUPPORTED;
        injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
    }

    injector_status_t rc = injector->rc;
    free_injector(injector);
    return rc;
}
