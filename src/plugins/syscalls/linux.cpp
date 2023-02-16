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

#include <inttypes.h>
#include <assert.h>
#include <string>
#include <vector>

#include "plugins/output_format.h"

#include "linux.h"

using namespace syscalls_ns;

static uint64_t make_hook_id(drakvuf_trap_info_t* info)
{
    uint64_t u64_pid = info->proc_data.pid;
    uint64_t u64_tid = info->proc_data.tid;
    return (u64_pid << 32) | u64_tid;
}

bool linux_syscalls::get_pt_regs_addr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* pt_regs_addr, addr_t* nr)
{
    auto vmi = vmi_lock_guard(drakvuf);

    if ( VMI_GET_BIT(info->regs->rdi, 47) )
    {
        /*
         * On older kernels: __visible void do_syscall_64(struct pt_regs *regs)
         */
        *pt_regs_addr = info->regs->rdi;
        return VMI_SUCCESS == vmi_read_addr_va(vmi, *pt_regs_addr + this->regs[PT_REGS_ORIG_RAX], 0, nr);
    }

    /*
    * On newer kernels: __visible void do_syscall_64(unsigned long nr, struct pt_regs *regs)
    */
    *nr = info->regs->rdi;
    *pt_regs_addr = info->regs->rsi;
    return true;
}

std::vector<uint64_t> linux_syscalls::build_arguments_buffer(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t pt_regs_addr, addr_t nr)
{
    std::vector<uint64_t> arguments;

    // unknown syscall, so skip
    if (nr > NUM_SYSCALLS_LINUX)
        return arguments;

    auto vmi = vmi_lock_guard(drakvuf);
    auto params = libhook::GetTrapParams<linux_syscall_data>(info);
    int nargs = params->sc->num_args;

    // get arguments only if we know how many to get
    if (!nargs)
        return arguments;

    // Now now, only support legacy syscall arg passing on 32 bit
    if ( 4 == this->register_size )
    {
        if ( nargs > 0 )
            arguments.push_back(info->regs->rbx);
        if ( nargs > 1 )
            arguments.push_back(info->regs->rcx);
        if ( nargs > 2 )
            arguments.push_back(info->regs->rdx);
        if ( nargs > 3 )
            arguments.push_back(info->regs->rsi);
        if ( nargs > 4 )
            arguments.push_back(info->regs->rdi);
    }
    else if ( 8 == this->register_size )
    {
        // Support both calling conventions for 64 bit Linux syscalls
        if (pt_regs_addr)
        {
            // The syscall args are passed via a struct pt_regs *, which is in %rdi upon entry
            size_t pt_regs[__PT_REGS_MAX] = {0};
            ACCESS_CONTEXT(ctx,
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3
            );

            for ( int i = 0; i < __PT_REGS_MAX; i++)
            {
                ctx.addr = pt_regs_addr + this->regs[i];
                if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &pt_regs[i]) )
                {
                    fprintf(stderr, "vmi_read_va(%p) failed\n", (void*)ctx.addr);
                    return arguments;
                }
            }

            // The order of the arguments is different when processing x32 syscalls
            // https://elixir.bootlin.com/linux/v5.10.166/source/arch/x86/include/asm/syscall_wrapper.h#L24
            // Assume if it is not x32 syscall, then we will use the standard convention for x64
            if ( params->type == SYSCALL_TYPE_LINUX_X32 ) {
                if ( nargs > 0 )
                    arguments.push_back(pt_regs[PT_REGS_RBX]);
                if ( nargs > 1 )
                    arguments.push_back(pt_regs[PT_REGS_RCX]);
                if ( nargs > 2 )
                    arguments.push_back(pt_regs[PT_REGS_RDX]);
                if ( nargs > 3 )
                    arguments.push_back(pt_regs[PT_REGS_RSI]);
                if ( nargs > 4 )
                    arguments.push_back(pt_regs[PT_REGS_RDI]);
                if ( nargs > 5 )
                    arguments.push_back(pt_regs[PT_REGS_RBP]);
            } else {
                if ( nargs > 0 )
                    arguments.push_back(pt_regs[PT_REGS_RDI]);
                if ( nargs > 1 )
                    arguments.push_back(pt_regs[PT_REGS_RSI]);
                if ( nargs > 2 )
                    arguments.push_back(pt_regs[PT_REGS_RDX]);
                if ( nargs > 3 )
                    arguments.push_back(pt_regs[PT_REGS_RCX]);
                if ( nargs > 4 )
                    arguments.push_back(pt_regs[PT_REGS_R8]);
                if ( nargs > 5 )
                    arguments.push_back(pt_regs[PT_REGS_R9]);
            }
        }
        else
        {
            // The args are passed directly via registers in sycall context
            if ( nargs > 0 )
                arguments.push_back(info->regs->rdi);
            if ( nargs > 1 )
                arguments.push_back(info->regs->rsi);
            if ( nargs > 2 )
                arguments.push_back(info->regs->rdx);
            if ( nargs > 3 )
                arguments.push_back(info->regs->rcx);
            if ( nargs > 4 )
                arguments.push_back(info->regs->r8);
            if ( nargs > 5 )
                arguments.push_back(info->regs->r9);
        }
    }

    return arguments;
}

void linux_syscalls::print_syscall(drakvuf_t drakvuf, drakvuf_trap_info_t* info, std::vector<uint64_t> arguments)
{
    auto params = libhook::GetTrapParams<linux_syscall_data>(info);

    this->fmt_args.clear();
    if (arguments.size() > 0) {
        for (size_t i = 0; i < arguments.size(); i++)
        {
            auto str = this->parse_argument(drakvuf, info, params->sc->args[i], arguments[i]);
            if (!str.empty())
                this->fmt_args.push_back(keyval(params->sc->args[i].name, fmt::Estr(str)));
            else {
                uint64_t value = this->transform_value(drakvuf, info, params->sc->args[i], arguments[i]);
                this->fmt_args.push_back(keyval(params->sc->args[i].name, fmt::Xval(value)));
            }
        }
    }

    char* tmp = drakvuf_get_process_name(drakvuf, info->proc_data.base_addr, false);
    std::string thread_name = tmp ?: "";
    g_free(tmp);

    fmt::print(this->m_output_format, "syscall", drakvuf, info,
        keyval("ThreadName", fmt::Estr(thread_name)),
        keyval("Module", fmt::Qstr(std::move(info->trap->breakpoint.module))),
        keyval("vCPU", fmt::Nval(info->vcpu)),
        keyval("CR3", fmt::Xval(info->regs->cr3)),
        keyval("Syscall", fmt::Nval((uint64_t)(params->num))),
        keyval("NArgs", fmt::Nval(params->sc->num_args)), 
        keyval("Type", fmt::Estr(params->type)),
        this->fmt_args
    );
}

event_response_t linux_syscalls::linux_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<linux_syscall_data>(info);
    if(!drakvuf_check_return_context(drakvuf, info, params->pid, params->tid, params->rsp))
        return VMI_EVENT_RESPONSE_NONE;

    this->print_sysret(drakvuf, info, (uint64_t)params->num);

    auto hookID = make_hook_id(info);
    this->ret_hooks.erase(hookID);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_syscalls::linux_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t pt_regs_addr = 0;
    addr_t nr = ~0;

    if (!get_pt_regs_addr(drakvuf, info, &pt_regs_addr, &nr))
    {
        PRINT_DEBUG("[SYSCALLS] Failed to get pt_regs_addr in %s\n", info->trap->name);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto arguments = build_arguments_buffer(drakvuf, info, pt_regs_addr, nr);
    this->print_syscall(drakvuf, info, arguments);

    if (this->disable_sysret)
        return VMI_EVENT_RESPONSE_NONE;

    auto hook = this->createReturnHook<linux_syscall_data>(info, &linux_syscalls::linux_ret_cb);
    auto params = libhook::GetTrapParams<linux_syscall_data>(hook->trap_);
    params->rsp = drakvuf_get_function_return_address(drakvuf, info);
    params->pid = info->proc_data.pid;
    params->tid = info->proc_data.tid;

    hook->trap_->name = info->trap->name;
    
    auto hookID = make_hook_id(info);
    this->ret_hooks[hookID] = std::move(hook);

    return VMI_EVENT_RESPONSE_NONE;
}

bool linux_syscalls::register_hook(char* syscall_name, uint64_t syscall_number, const syscall_t* syscall_definition, bool is_x64)
{
    auto hook = createSyscallHook<linux_syscall_data>(syscall_name, &linux_syscalls::linux_cb, syscall_definition->name);
    if (!hook)
    {
        PRINT_DEBUG("[SYSCALLS] Failed to register %s\n", syscall_name);
        return false;
    }

    // Populate params to hook
    auto params = libhook::GetTrapParams<linux_syscall_data>(hook->trap_);
    params->num = syscall_number;
    params->type = is_x64 ? SYSCALL_TYPE_LINUX_X64 : SYSCALL_TYPE_LINUX_X32;
    params->sc = syscall_definition;

    // If there is a collision when two functions point to the same address (for example getpid/getppid),
    // then we will take only the last one that got into the map, in this case __x64_sys_*
    this->hooks[hook->trap_->breakpoint.addr] = std::move(hook);
    return true;
}

bool linux_syscalls::trap_syscall_table_entries(drakvuf_t drakvuf)
{
    bool check = true;
    // Iterate over all syscalls and setup breakpoint on each function instead of do_syscall_64
    // This increase performance, especially with filter file
    char syscall_name[256] = {0};
    for (uint64_t syscall_number = 0; syscall_number < NUM_SYSCALLS_LINUX; syscall_number++)
    {
        const syscall_t* syscall_defintion = linuxsc::linux_syscalls_table[syscall_number];
        // Setup filter
        if (!this->filter.empty() && (this->filter.find(syscall_defintion->name) == this->filter.end()))
            continue;
        
        // x32 syscall breakpoint
        snprintf(syscall_name, sizeof(syscall_name), "__ia32_sys_%s", syscall_defintion->name);
        if (!this->register_hook(syscall_name, syscall_number, syscall_defintion, false))
            check = false;
        memset(syscall_name, sizeof(char), sizeof(syscall_name));

        // If only 32bit system we don't have x64 symbols so skip
        if (this->is32bit) continue;

        // x64 syscall breakpoint
        snprintf(syscall_name, sizeof(syscall_name), "__x64_sys_%s", syscall_defintion->name);
        if (!this->register_hook(syscall_name, syscall_number, syscall_defintion, true))
            check = false;
        memset(syscall_name, sizeof(char), sizeof(syscall_name));
    }
    return check;
}


linux_syscalls::linux_syscalls(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output) : syscalls_base(drakvuf, config, output)
{
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_pt_regs_offsets_name, this->regs.size(), this->regs.data()))
    {
        PRINT_DEBUG("[SYSCALLS] Failed to get register offsets.\n");
        return;
    }

    if(!this->trap_syscall_table_entries(drakvuf))
        PRINT_DEBUG("[SYSCALLS] Failed to set breakpoints on some syscalls.\n");
}