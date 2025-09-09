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
 ***************************************************************************/

#include <libvmi/libvmi.h>
#include <map>
#include <string>
#include <fstream>
#include <utility>
#include <cstring>
#include <string.h>
#include <assert.h>
#include <glib.h>

#include "linux.h"
#include "linux_utils.h"
#include "plugins/output_format.h"
#include "plugins/helpers/hooks.h"

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

bool linux_procmon::get_struct_field_pointer(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t struct_addr, int offset_field, addr_t* value)
{
    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = struct_addr + this->offsets[offset_field]
    );

    return (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, value));
}

bool linux_procmon::get_cred_value(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t struct_cred, int offset_field, uint32_t* value)
{
    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = struct_cred + this->offsets[offset_field]
    );
    return ( VMI_SUCCESS == vmi_read_32(vmi, &ctx, value) );
}

task_creds linux_procmon::get_current_credentials(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t struct_cred;
    if (!get_struct_field_pointer(drakvuf, info, info->proc_data.base_addr, _TASK_STRUCT_REAL_CRED, &struct_cred))
        return {};

    task_creds creds = {};

    if (!get_cred_value(drakvuf, info, struct_cred, _CRED_UID, &creds.uid))
        return {};

    if (!get_cred_value(drakvuf, info, struct_cred, _CRED_SUID, &creds.suid))
        return {};

    if (!get_cred_value(drakvuf, info, struct_cred, _CRED_EUID, &creds.euid))
        return {};

    return creds;
}

std::string linux_procmon::get_string_from_struct(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t struct_base, int offset_field)
{
    addr_t struct_string_ptr;
    if (!get_struct_field_pointer(drakvuf, info, struct_base, offset_field, &struct_string_ptr))
        return {};

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = struct_string_ptr
    );

    auto tmp = vmi_read_str(vmi, &ctx);
    std::string result = tmp ?: "";
    g_free(tmp);

    return result;
}

static std::pair<std::string, std::map<std::string, std::string>> parse_top_stack(drakvuf_t drakvuf, drakvuf_trap_info_t* info, std::unordered_set<std::string> filter, uint64_t p, uint32_t argc, uint32_t envc)
{
    if (!p)
        return {};

    // setup variables
    auto vmi = vmi_lock_guard(drakvuf);
    auto stack = p;

    // parse argv
    std::string command_line;
    for (uint32_t i = 0; i < argc; i++)
    {
        auto tmp = vmi_read_str_va(vmi, stack, info->proc_data.pid);
        if (tmp == nullptr)
            break;

        stack += strnlen(tmp, MAX_ARG_STRLEN) + 1; // null byte
        command_line.append(tmp);
        command_line.push_back(' ');

        g_free(tmp);
    }

    // Just remove last space
    if (!command_line.empty())
        command_line.pop_back();

    // parse envp
    std::map<std::string, std::string> envp_map;
    for (uint32_t i = 0; i < envc; i++)
    {
        auto env_string = vmi_read_str_va(vmi, stack, info->proc_data.pid);
        if (env_string == nullptr)
            break;

        stack += strnlen(env_string, MAX_ARG_STRLEN) + 1; // null byte
        auto [key, value] = parse_environment_variable(env_string);
        g_free(env_string);

        if (key.empty() || filter.find(key) == filter.end())
            continue;

        envp_map.emplace(key, value);
    }

    return make_pair(command_line, envp_map);
}

static std::string map_to_str(const std::map<std::string, std::string>& map, output_format_t format, const std::string& empty = "")
{
    std::string output;

    for (const auto& el: map)
        output += el.first + "=" + el.second + ",";

    if (output.empty())
        output = empty;
    else
        output.resize(output.size() - 1);

    return output;
}

void linux_procmon::configure_filter(const procmon_config* cfg)
{
    if (cfg->procmon_filter_file)
    {
        if (!this->read_procmon_filter(cfg->procmon_filter_file))
        {
            PRINT_DEBUG("[PROCMON] Failed to read given file\n");
            throw -1;
        }
    }
    else
        this->filter = {"LD_PRELOAD", "PWD", "OLDPWD"};
}

bool linux_procmon::read_procmon_filter(const char* filter_file)
{
    std::ifstream file(filter_file);
    if (!file.is_open())
        return false;

    std::string line;
    while (std::getline(file, line))
        this->filter.insert(line);

    return true;
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

    fmt::print(
        this->m_output_format,
        "procmon",
        drakvuf,
        info,
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
    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    auto signal_str = signal_to_string((signal_t)params->signal);

    fmt::print(
        this->m_output_format,
        "procmon",
        drakvuf,
        info,
        keyval("ThreadName", fmt::Estr(params->thread_name)),
        keyval("TargetPID", fmt::Nval(params->target_proc_pid)),
        keyval("TargetTID", fmt::Nval(params->target_proc_tid)),
        keyval("TargetPPID", fmt::Nval(params->target_proc_ppid)),
        keyval("TargetProcessName", fmt::Estr(params->target_process_name)),
        keyval("TargetThreadName", fmt::Estr(params->target_thread_name)),
        keyval("Signal", fmt::Nval(params->signal)),
        keyval("SignalStr", fmt::Rstr(signal_str))
    );

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks.erase(hookID);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_procmon::send_signal_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    int do_send_sig_info(
        int sig,
        struct kernel_siginfo *info,
        struct task_struct *p,
        enum pid_type type
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
        g_free(target_thread_name);
        PRINT_DEBUG("[PROCMON] Failed to get process_base of affected process\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    char* current_thread_name = drakvuf_get_process_name(drakvuf, process_base_of_current_process, false);

    // Create new trap for return callback
    auto hook = this->createReturnHook<send_signal_data>(info, &linux_procmon::send_signal_ret_cb, info->trap->name);
    auto params = libhook::GetTrapParams<send_signal_data>(hook->trap_);

    // Save data about current process
    params->thread_name = current_thread_name ?: "";

    // Save data about target process
    params->target_process_name = target_proc_data.name ?: "";
    params->target_thread_name = target_thread_name ?: "";
    params->target_proc_pid = target_proc_data.pid;
    params->target_proc_tid = target_proc_data.tid;
    params->target_proc_ppid = target_proc_data.ppid;
    params->signal = signal;

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks[hookID] = std::move(hook);

    g_free(const_cast<char*>(target_proc_data.name));
    g_free(target_thread_name);
    g_free(current_thread_name);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linux_procmon::kernel_clone_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<kernel_clone_data>(info);
    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    uint64_t new_pid = info->regs->rax;

    fmt::print(
        this->m_output_format,
        "procmon",
        drakvuf,
        info,
        keyval("Flags", fmt::Estr(parse_flags(params->flags, kernel_clone_flags, this->m_output_format))),
        keyval("Signal", fmt::Nval(params->exit_signal)),
        keyval("SignalStr", fmt::Estr(signal_to_string((signal_t) params->exit_signal))),
        keyval("NewPid", fmt::Nval(new_pid))
    );

    auto hookID = make_hook_id(info, params->target_rsp);
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

    auto hook = this->createReturnHook<kernel_clone_data>(info, &linux_procmon::kernel_clone_ret_cb, info->trap->name);
    auto params = libhook::GetTrapParams<kernel_clone_data>(hook->trap_);

    params->flags = flags;
    params->exit_signal = exit_signal;

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks[hookID] = std::move(hook);
    return VMI_EVENT_RESPONSE_NONE;
}

void linux_procmon::print_info(
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    std::vector<std::pair<std::string, std::variant<fmt::Nval<int>, fmt::Nval<unsigned int>, fmt::Estr<std::string>>>> extra_args
)
{
    auto params = libhook::GetTrapParams<execve_data>(info);

    std::vector<std::pair<std::string, fmt::Estr<std::string>>> envp;
    if (!params->envp.empty())
        envp.emplace_back(keyval("Environment", fmt::Estr(map_to_str(params->envp, this->m_output_format))));

    auto proc_data_backup = info->proc_data;
    // Fake caller process data to print correct data
    info->proc_data.name = params->process_name.c_str();

    fmt::print(
        this->m_output_format,
        "procmon",
        drakvuf,
        info,
        keyval("ThreadName", fmt::Estr(params->thread_name)),
        keyval("CommandLine", fmt::Estr(params->command_line)),
        keyval("ImagePathName", fmt::Estr(params->image_path_name)),
        keyval("ouid", fmt::Nval(params->old_creds.uid)),
        keyval("osuid", fmt::Nval(params->old_creds.suid)),
        keyval("oeuid", fmt::Nval(params->old_creds.euid)),
        keyval("suid", fmt::Nval(params->new_creds.suid)),
        keyval("euid", fmt::Nval(params->new_creds.euid)),
        std::move(envp),
        std::move(extra_args)
    );

    // restore original proc_data
    info->proc_data = proc_data_backup;
}


/*
 * callback for execve
*/
event_response_t linux_procmon::execve_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<execve_data>(info);
    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3);

    uint32_t argc;
    ctx.addr = params->bprm + offsets[_LINUX_BINPRM_ARGC];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &argc))
        return VMI_EVENT_RESPONSE_NONE;

    uint32_t envc;
    ctx.addr = params->bprm + offsets[_LINUX_BINPRM_ENVC];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &envc))
        return VMI_EVENT_RESPONSE_NONE;

    uint64_t p;
    ctx.addr = params->bprm + offsets[_LINUX_BINPRM_P];
    if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &p))
        return VMI_EVENT_RESPONSE_NONE;

    // collect main information
    auto [command_line, envp] = parse_top_stack(drakvuf, info, this->filter, p, argc, envc);
    params->command_line = command_line;
    params->envp = envp;
    params->image_path_name = info->proc_data.name;
    params->new_creds = get_current_credentials(drakvuf, info);

    // collect extra usefull information
    // std::vector<std::pair<std::string, fmt::Estr<std::string>>> extra_args;
    std::vector<std::pair<std::string, std::variant<fmt::Nval<int>, fmt::Nval<unsigned int>, fmt::Estr<std::string>>>> extra_args;
    auto interp = get_string_from_struct(drakvuf, info, params->bprm, _LINUX_BINPRM_INTERP);
    if (!interp.empty())
        extra_args.emplace_back(keyval("interp", fmt::Estr(interp)));

    auto fdpath = get_string_from_struct(drakvuf, info, params->bprm, _LINUX_BINPRM_FDPATH);
    if (!fdpath.empty())
        extra_args.emplace_back(keyval("fdpath", fmt::Estr(fdpath)));

    auto filename = get_string_from_struct(drakvuf, info, params->bprm, _LINUX_BINPRM_FILENAME);
    if (!filename.empty())
        extra_args.emplace_back(keyval("FileName", fmt::Estr(filename)));

    uint32_t pgid;
    if (drakvuf_get_process_group_id(drakvuf, info->proc_data.base_addr, &pgid))
        extra_args.emplace_back(keyval("PGID", fmt::Nval(pgid)));

    uint8_t special_flags;
    ctx.addr = params->bprm + offsets[_LINUX_BINPRM_HAVE_EXECFD];
    if (VMI_SUCCESS == vmi_read_8(vmi, &ctx, &special_flags))
    {
        // check if have_execfd set
        if (VMI_GET_BIT(special_flags, 0))
        {
            extra_args.emplace_back(keyval("have_execfd", fmt::Nval(1)));

            uint32_t execfd;
            ctx.addr = params->bprm + offsets[_LINUX_BINPRM_EXECFD];
            if (VMI_SUCCESS == vmi_read_32(vmi, &ctx, &execfd))
                extra_args.emplace_back(keyval("execfd", fmt::Nval(execfd)));
        }

        // check if secureexec set
        if (VMI_GET_BIT(special_flags, 2))
            extra_args.emplace_back(keyval("secureexec", fmt::Nval(1)));
    }

    print_info(drakvuf, info, extra_args);

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks.erase(hookID);

    return VMI_EVENT_RESPONSE_NONE;
}

/*
 * A very conceptual approach, since the interception occurs very deep in the kernel and before the actual execution of the program
 * source: https://elixir.bootlin.com/linux/v6.5.7/source/fs/exec.c#L1245
 *
 * How this logic works:
 * 1. Before begin_new_exec, the current variable contains the process that called execve
 *    At this stage, it is impossible to read bprm->p as a virtual address, since it is not bound to any process
 * 2. After begin_new_exec, the current variable already contains the "new" process,
 *    and the old one was successfully cleaned by the system, so now bprm->p can be read as a virtual address
 * 3. It is important to understand that when the callback function is called, the process has not
 *    actually started by the system yet, so we can safely extract argv, envp
 *
 * Probably there is an implementation much simpler and more elegant, but...
*/
event_response_t linux_procmon::execve_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
        int begin_new_exec(struct linux_binprm * bprm)
     */

    auto hook = this->createReturnHook<execve_data>(info, &linux_procmon::execve_ret_cb, info->trap->name);
    auto params = libhook::GetTrapParams<execve_data>(hook->trap_);

    // We save information about the current process before replacement
    params->setResultCallParams(drakvuf, info);
    params->bprm = drakvuf_get_function_argument(drakvuf, info, 1);
    params->process_name = info->proc_data.name;
    char* thread_name = drakvuf_get_process_name(drakvuf, info->proc_data.base_addr, false);
    params->thread_name = thread_name ?: "";
    params->old_creds = get_current_credentials(drakvuf, info);

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks[hookID] = std::move(hook);

    g_free(thread_name);
    return VMI_EVENT_RESPONSE_NONE;
}

linux_procmon::linux_procmon(drakvuf_t drakvuf, const procmon_config* config, output_format_t output) : pluginex(drakvuf, output)
{
    struct process_visitor_ctx ctx = { .format = output };
    drakvuf_enumerate_processes(drakvuf, process_visitor, &ctx);
    configure_filter(config);

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, linux_offset_names, this->offsets.size(), this->offsets.data()))
    {
        PRINT_DEBUG("[PROCMON] Failed to get offsets.\n");
        return;
    }

    // to maintain backward compatibility
    exec_hook = createSyscallHook("begin_new_exec", &linux_procmon::execve_cb, "do_execveat_common");
    if (nullptr == exec_hook)
    {
        PRINT_DEBUG("[PROCMON] Method begin_new_exec not found.\n");
        return;
    }

    exit_hook = createSyscallHook("do_exit", &linux_procmon::do_exit_cb);
    if (nullptr == exit_hook)
    {
        PRINT_DEBUG("[PROCMON] Method do_exit not found.\n");
        return;
    }

    signal_hook = createSyscallHook("do_send_sig_info", &linux_procmon::send_signal_cb, "send_signal");
    if (nullptr == signal_hook)
    {
        PRINT_DEBUG("[PROCMON] Method do_send_sig_info not found.\n");
        return;
    }

    kernel_clone_hook = createSyscallHook("kernel_clone", &linux_procmon::kernel_clone_cb);
    if (nullptr == kernel_clone_hook)
    {
        PRINT_DEBUG("[PROCMON] Method kernel_clone not found.\n");
        return;
    }
}
