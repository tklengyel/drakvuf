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
 ***************************************************************************/

#include <libvmi/libvmi.h>
#include <assert.h>
#include <map>
#include <string>
#include <glib.h>

#include "linux.h"
#include "plugins/output_format.h"
#include "plugins/hook_helpers.h"

using namespace procmon_ns;

namespace
{

struct process_visitor_ctx
{
    output_format_t format;
};

void process_visitor(drakvuf_t drakvuf, addr_t process, void* visitor_ctx)
{
    struct process_visitor_ctx* ctx = reinterpret_cast<struct process_visitor_ctx*>(visitor_ctx);

    proc_data_t data = {};
    if (!drakvuf_get_process_data(drakvuf, process, &data))
    {
        PRINT_DEBUG("Failed to get PID of process 0x%" PRIx64 "\n", process);
        return;
    }

    gint64 t = g_get_real_time();

    fmt::print_running_process(ctx->format, "procmon", drakvuf, t, data);

    g_free(const_cast<char*>(data.name));
}

} // namespace

uint64_t make_hook_id(drakvuf_trap_info_t* info)
{
    uint64_t u64_pid = info->proc_data.pid;
    uint64_t u64_tid = info->proc_data.tid;
    return (u64_pid << 32) | u64_tid;
}

static std::string get_command_line(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t argv = drakvuf_get_function_argument(drakvuf, info, 4);

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3);

    std::string command_line;
    for (uint32_t argc = 0; argc < ARG_MAX; argc++, argv += sizeof(addr_t))
    {
        addr_t current_argv_ptr;
        ctx.addr = argv;
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &current_argv_ptr))
            break;

        ctx.addr = current_argv_ptr;
        char* argument = vmi_read_str(vmi, &ctx);
        if (argument == nullptr)
            break;

        command_line.append(argument);
        command_line.push_back(' ');

        g_free(argument);
    }

    // Just remove last space
    if (!command_line.empty())
        command_line.pop_back();

    return command_line;
}

static std::map<std::string, std::string> parse_environment(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // drakvuf_get_function_argument - return incorrect value. Real envp stored in r9. Gather with debug
    addr_t envp = info->regs->r9;

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = envp);

    std::map<std::string, std::string> envp_map;

    for (uint32_t envpc = 0; envpc < ARG_MAX; envpc++, envp += sizeof(addr_t))
    {
        std::string::size_type key_pos = 0;
        std::string::size_type key_end;
        std::string::size_type val_pos;
        std::string::size_type val_end;

        addr_t env_str_ptr;
        ctx.addr = envp;
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &env_str_ptr))
            break;

        ctx.addr = env_str_ptr;
        char* env_string = vmi_read_str(vmi, &ctx);
        if (env_string == nullptr)
            break;

        // based on: https://stackoverflow.com/questions/38812780/split-string-into-key-value-pairs-using-c
        std::string s(env_string);
        key_pos = 0;

        key_end = s.find('=', key_pos);
        if (key_end == std::string::npos)
            break;

        if ((val_pos = s.find_first_not_of("= ", key_end)) == std::string::npos)
            break;

        val_end = s.find('\1', val_pos);
        envp_map.emplace(s.substr(key_pos, key_end - key_pos), s.substr(val_pos, val_end - val_pos));

        g_free(env_string);
    }
    return envp_map;
}

void linux_procmon::print_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<execve_data>(info);

    std::vector<std::pair<std::string, fmt::Estr<std::string>>> extra_args;
    if (params->envp.find("PWD") != params->envp.end())
        extra_args.emplace_back("CWD", fmt::Estr(params->envp["PWD"]));
    if (params->envp.find("OLDPWD") != params->envp.end())
        extra_args.emplace_back("OLDCWD", fmt::Estr(params->envp["OLDPWD"]));
    if (params->envp.find("LD_PRELOAD") != params->envp.end())
        extra_args.emplace_back("LD_PRELOAD", fmt::Estr(params->envp["LD_PRELOAD"]));

    auto proc_data_backup = info->proc_data;

    // Fake caller process data to print correct data
    info->proc_data.pid = params->pid;
    info->proc_data.tid = params->tid;
    info->proc_data.ppid = params->ppid;
    info->proc_data.name = params->process_name.c_str();

    fmt::print(this->m_output_format, "procmon", drakvuf, info,
        keyval("ThreadName", fmt::Estr(params->thread_name)),
        keyval("NewPid", fmt::Nval(params->new_pid)),
        keyval("NewTid", fmt::Nval(params->new_tid)),
        keyval("CommandLine", fmt::Estr(params->command_line)),
        keyval("ImagePathName", fmt::Estr(params->image_path_name)),
        extra_args);

    // restore original proc_data
    info->proc_data = proc_data_backup;
}

/*
    exec-family
*/
event_response_t do_open_execat_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<execve_data>(info);
    if (!drakvuf_check_return_context(drakvuf, info, params->new_pid, params->new_tid, params->execat_rsp))
        return VMI_EVENT_RESPONSE_NONE;

    if (params->cr3 != info->regs->cr3)
        return VMI_EVENT_RESPONSE_NONE;

    // At this point we have correct ImagePathName
    addr_t file_struct = info->regs->rax;

    // Check for errors: https://elixir.bootlin.com/linux/v5.9.14/source/fs/exec.c#L1930
    // This is normal behavior for the kernel. In case of an error, the binary will not be executed.
    // So we can just skip this event
    auto plugin = GetTrapPlugin<linux_procmon>(info);
    auto vmi = vmi_lock_guard(drakvuf);
    if ((unsigned long)(void*)(file_struct) >= (unsigned long)(-MAX_ERRNO))
    {
        PRINT_DEBUG("[PROCMON] do_execveat_common kernel error. Not an error, just skipping the event.\n");
        params->is_error = true;
    }
    else
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = file_struct + plugin->offsets[_FILE_F_PATH] + plugin->offsets[_PATH_DENTRY]);

        addr_t dentry_addr;

        if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &dentry_addr))
        {
            char* tmp = drakvuf_get_filepath_from_dentry(drakvuf, file_struct);
            params->image_path_name = tmp ?: "";
            g_free(tmp);
        }
        else
            PRINT_DEBUG("[PROCMON] Failed to read ImagePathName.\n");
    }

    drakvuf_remove_trap(drakvuf, info->trap, nullptr);
    auto hookID = make_hook_id(info);
    plugin->internal_ret_traps.erase(hookID);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t do_open_execat_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    static struct file *do_open_execat(
        int fd,
        struct filename *name,
        int flags
    )
    */
    auto params = libhook::GetTrapParams<execve_data>(info);
    // Check same context: do_execveat_common -> bprm_execve -> do_open_execat
    // Can't use drakvuf_check_return_context because haven't rsp at function start
    if (params->cr3 != info->regs->cr3)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if (!ret_addr)
    {
        PRINT_DEBUG("[PROCMON] Failed to get return address for do_open_execat.\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // Save return address of this function
    params->execat_rsp = ret_addr;

    // Register return trap
    auto trap = new drakvuf_trap_t();
    trap->name = "do_open_execat_ret_trap";
    trap->ttl = drakvuf_get_limited_traps_ttl(drakvuf);
    trap->ah_cb = nullptr;
    trap->type = BREAKPOINT;
    trap->breakpoint.pid = 0;
    trap->breakpoint.lookup_type = LOOKUP_PID;
    trap->breakpoint.addr_type = ADDR_VA;
    trap->breakpoint.addr = ret_addr;
    trap->breakpoint.module = "linux";
    trap->cb = do_open_execat_ret_cb;
    // Pass the params through the do_open_execat functions
    trap->data = params;

    if (!drakvuf_add_trap(drakvuf, trap))
    {
        PRINT_DEBUG("[PROCMON] Failed to register return trap from do_open_execat.\n");
        throw -1;
    }

    drakvuf_remove_trap(drakvuf, info->trap, nullptr);
    auto plugin = GetTrapPlugin<linux_procmon>(info);
    auto hookID = make_hook_id(info);
    plugin->internal_ret_traps[hookID] = trap;
    plugin->internal_traps.erase(hookID);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_procmon::do_execveat_common_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("[PROCMON] Callback: %s\n", info->trap->name);

    auto params = libhook::GetTrapParams<execve_data>(info);
    // params->new_pid/params->new_tid store actual pid/tid of running process
    if (!drakvuf_check_return_context(drakvuf, info, params->new_pid, params->new_tid, params->rsp))
        return VMI_EVENT_RESPONSE_NONE;

    if (!params->is_error)
        linux_procmon::print_info(drakvuf, info);

    uint64_t hookID = make_hook_id(info);
    ret_hooks.erase(hookID);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_procmon::do_execveat_common_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    static int do_execveat_common(
        int fd,
        struct filename *filename,
        struct user_arg_ptr argv,
        struct user_arg_ptr envp,
        int flags
    )
     */
    PRINT_DEBUG("[PROCMON] Callback: %s\n", info->trap->name);

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if (!ret_addr)
        return VMI_EVENT_RESPONSE_NONE;

    // Gather information about parent process
    vmi_pid_t parent_pid = info->proc_data.ppid;
    addr_t parent_process;
    if (!drakvuf_get_process_by_pid(drakvuf, parent_pid, &parent_process, nullptr))
    {
        PRINT_DEBUG("[PROCMON] Failed to get process by pid\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    proc_data_t parent_proc_data;
    if (!drakvuf_get_process_data(drakvuf, parent_process, &parent_proc_data))
    {
        PRINT_DEBUG("[PROCMON] Failed to get process data of parent process\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // Create new trap for return callback
    auto hookID = make_hook_id(info);
    auto hook = this->createReturnHook<execve_data>(info, &linux_procmon::do_execveat_common_ret_cb);
    auto params = libhook::GetTrapParams<execve_data>(hook->trap_);

    params->pid = parent_proc_data.pid;
    params->tid = parent_proc_data.tid;
    params->ppid = parent_proc_data.ppid;
    params->new_pid = info->proc_data.pid;
    params->new_tid = info->proc_data.tid;
    params->rsp = ret_addr;
    params->cr3 = info->regs->cr3;

    params->command_line = get_command_line(drakvuf, info);
    params->envp = parse_environment(drakvuf, info);

    if (parent_proc_data.name)
        params->process_name = parent_proc_data.name;
    g_free(const_cast<char*>(parent_proc_data.name));

    char* thread_name = drakvuf_get_process_name(drakvuf, parent_process, false);
    if (thread_name)
        params->thread_name = thread_name;
    g_free(thread_name);

    hook->trap_->name = info->trap->name;
    this->ret_hooks[hookID] = std::move(hook);

    // Create trap to intercept function on do_open_execat
    auto trap = new drakvuf_trap_t();
    trap->name = "do_open_execat_trap";
    trap->ttl = drakvuf_get_limited_traps_ttl(drakvuf);
    trap->ah_cb = nullptr;
    trap->type = BREAKPOINT;
    trap->breakpoint.pid = 0;
    trap->breakpoint.lookup_type = LOOKUP_PID;
    trap->breakpoint.addr_type = ADDR_VA;
    trap->breakpoint.addr = kernel_base - _text + do_open_execat_addr;
    trap->breakpoint.module = "linux";
    trap->cb = do_open_execat_cb;
    // Pass the params through the do_open_execat functions
    trap->data = params;

    if (!drakvuf_add_trap(drakvuf, trap))
    {
        PRINT_DEBUG("[PROCMON] Failed to regsiter trap for do_open_execat.\n");
        throw -1;
    }

    internal_traps[hookID] = trap;
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_procmon::do_exit_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    /*
    void __noreturn do_exit(long code)
    */
    PRINT_DEBUG("[PROCMON] Callback: %s\n", info->trap->name);

    addr_t code = drakvuf_get_function_argument(drakvuf, info, 1);
    uint32_t exit_status = (uint32_t)(code >> 8);
    auto exit_status_str = exit_status_to_string((exit_status_t)exit_status);

    char* thread_name = drakvuf_get_process_name(drakvuf, info->proc_data.base_addr, false);

    fmt::print(this->m_output_format, "procmon", drakvuf, info,
        keyval("ThreadName", fmt::Estr(thread_name)),
        keyval("ExitStatus", fmt::Nval(exit_status)),
        keyval("ExitStatusStr", fmt::Rstr(exit_status_str))
    );

    g_free(thread_name);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_procmon::send_signal_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<send_signal_data>(info);
    if (!drakvuf_check_return_context(drakvuf, info, params->pid, params->tid, params->rsp))
        return VMI_EVENT_RESPONSE_NONE;

    auto signal_str = signal_to_string((signal_t)params->signal);

    fmt::print(this->m_output_format, "procmon", drakvuf, info,
        keyval("ThreadName", fmt::Estr(params->thread_name)),
        keyval("TargetPID", fmt::Nval(params->target_pid)),
        keyval("TargetTID", fmt::Nval(params->target_tid)),
        keyval("TargetPPID", fmt::Nval(params->target_ppid)),
        keyval("TargetProcessName", fmt::Estr(params->target_process_name)),
        keyval("TargetThreadName", fmt::Estr(params->target_thread_name)),
        keyval("Signal", fmt::Nval(params->signal)),
        keyval("SignalStr", fmt::Rstr(signal_str))
    );

    uint64_t hookID = make_hook_id(info);
    this->ret_hooks.erase(hookID);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_procmon::send_signal_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    static int __send_signal(
        int sig,
        struct kernel_siginfo *info,
        struct task_struct *t,
        enum pid_type type,
        bool force
    )
    */
    PRINT_DEBUG("[PROCMON] Callback: %s\n", info->trap->name);

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if (!ret_addr)
        return VMI_EVENT_RESPONSE_NONE;

    uint64_t signal = (uint64_t)drakvuf_get_function_argument(drakvuf, info, 1);

    /* Gather information about target process */
    addr_t process_base_of_target_process = drakvuf_get_function_argument(drakvuf, info, 3);
    if (!process_base_of_target_process)
    {
        PRINT_DEBUG("[PROCMON] Failed to get process_base of affected process\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    proc_data_t target_proc_data;
    if (!drakvuf_get_process_data(drakvuf, process_base_of_target_process, &target_proc_data))
    {
        PRINT_DEBUG("[PROCMON] Failed to get data of affected process\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    char* target_thread_name = drakvuf_get_process_name(drakvuf, process_base_of_target_process, false);

    /* Gather information about current process */
    addr_t process_base_of_current_process = info->proc_data.base_addr;
    if (!process_base_of_current_process)
    {
        PRINT_DEBUG("[PROCMON] Failed to get process_base of affected process\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    char* current_thread_name = drakvuf_get_process_name(drakvuf, process_base_of_current_process, false);

    // Create new trap for return callback
    uint64_t hookID = make_hook_id(info);
    auto hook = this->createReturnHook<send_signal_data>(info, &linux_procmon::send_signal_ret_cb);
    auto params = libhook::GetTrapParams<send_signal_data>(hook->trap_);

    // Save data about current process
    params->pid = info->proc_data.pid;
    params->tid = info->proc_data.tid;
    params->thread_name = current_thread_name ?: "";
    params->rsp = ret_addr;

    // Save data about target process
    params->target_process_name = target_proc_data.name;
    params->target_thread_name = target_thread_name ?: "";
    params->target_pid = target_proc_data.pid;
    params->target_tid = target_proc_data.tid;
    params->target_ppid = target_proc_data.ppid;
    params->signal = signal;

    hook->trap_->name = info->trap->name;
    this->ret_hooks[hookID] = std::move(hook);

    g_free(const_cast<char*>(target_proc_data.name));
    g_free(target_thread_name);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_procmon::kernel_clone_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<kernel_clone_data>(info);
    if (!drakvuf_check_return_context(drakvuf, info, params->pid, params->tid, params->rsp))
        return VMI_EVENT_RESPONSE_NONE;

    uint64_t new_pid = info->regs->rax;

    fmt::print(this->m_output_format, "procmon", drakvuf, info,
        keyval("Flags", fmt::Estr(parse_flags(params->flags, kernel_clone_flags, this->m_output_format))),
        keyval("SignalStr", fmt::Estr(signal_to_string((signal_t) params->exit_signal))),
        keyval("NewPid", fmt::Nval(new_pid))
    );

    uint64_t hookID = make_hook_id(info);
    this->ret_hooks.erase(hookID);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_procmon::kernel_clone_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    pid_t kernel_clone(
        struct kernel_clone_args *args
    )
    */
    PRINT_DEBUG("[PROCMON] Callback: %s\n", info->trap->name);
    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if (!ret_addr)
        return VMI_EVENT_RESPONSE_NONE;

    uint64_t args = drakvuf_get_function_argument(drakvuf, info, 1);

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    uint64_t flags;
    ctx.addr = args + this->offsets[_KERNEL_CLONE_ARGS_FLAGS];
    if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &flags))
    {
        PRINT_DEBUG("[PROCMON] Failed to read kernel_clone flags.\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    uint32_t exit_signal;
    ctx.addr = args + this->offsets[_KERNEL_CLONE_ARGS_EXIT_SIGNAL];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &exit_signal))
    {
        PRINT_DEBUG("[PROCMON] Failed to read kernel_clone exit_signal.\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    uint64_t hookID = make_hook_id(info);
    auto hook = this->createReturnHook<kernel_clone_data>(info, &linux_procmon::kernel_clone_ret_cb);
    auto params = libhook::GetTrapParams<kernel_clone_data>(hook->trap_);

    params->pid = info->proc_data.pid;
    params->tid = info->proc_data.tid,
            params->rsp = ret_addr;
    params->flags = flags;
    params->exit_signal = exit_signal;

    hook->trap_->name = info->trap->name;
    this->ret_hooks[hookID] = std::move(hook);
    return VMI_EVENT_RESPONSE_NONE;
}

linux_procmon::linux_procmon(drakvuf_t drakvuf, output_format_t output) : pluginex(drakvuf, output)
{
    struct process_visitor_ctx ctx = { .format = output };
    drakvuf_enumerate_processes(drakvuf, process_visitor, &ctx);

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_offset_names, this->offsets.size(), this->offsets.data()))
    {
        PRINT_DEBUG("[PROCMON] Failed to get offsets.\n");
        return;
    }

    if (!drakvuf_get_kernel_symbol_rva(drakvuf, "__do_open_execat", &do_open_execat_addr))
    {
        PRINT_DEBUG("[PROCMON] Failed to get symbol of do_open_execat.\n");
        return;
    }

    if (!drakvuf_get_kernel_symbol_rva(drakvuf, "_text", &_text))
    {
        PRINT_DEBUG("[PROCMON] Failed to get symbol of _text.\n");
        return;
    }

    kernel_base = drakvuf_get_kernel_base(drakvuf);
    if (!kernel_base)
    {
        PRINT_DEBUG("[PROCMON] Failed to get kernel_base.\n");
        return;
    }

    exec_hook = createSyscallHook("do_execveat_common", &linux_procmon::do_execveat_common_cb);
    if (nullptr == exec_hook)
    {
        PRINT_DEBUG("[PROCMON] Method do_execveat_common not found. You are probably using an older kernel version below 5.9\n");
        return;
    }

    // exit_hook = createSyscallHook("do_exit", &linux_procmon::do_exit_cb);
    // if (nullptr == exit_hook)
    // {
    //     PRINT_DEBUG("[PROCMON] Method do_exit not found.\n");
    //     return;
    // }

    // signal_hook = createSyscallHook("__send_signal", &linux_procmon::send_signal_cb, "send_signal");
    // if (nullptr == signal_hook)
    // {
    //     PRINT_DEBUG("[PROCMON] Method __send_signal not found.\n");
    //     return;
    // }

    // kernel_clone_hook = createSyscallHook("kernel_clone", &linux_procmon::kernel_clone_cb);
    // if (nullptr == kernel_clone_hook)
    // {
    //     PRINT_DEBUG("[PROCMON] Method kernel_clone not found.\n");
    //     return;
    // }
}
