/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
*                                                                         *
* DRAKVUF (C) 2014-2020 Tamas K Lengyel.                                  *
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

#include <glib.h>
#include <config.h>
#include <inttypes.h>
#include <libvmi/x86.h>
#include <assert.h>

#include <libdrakvuf/ntstatus.h>

#include "../plugins.h"
#include "plugins/output_format.h"
#include "procmon.h"
#include "winnt.h"
#include "privileges.h"

namespace
{

struct open_process_result_t: public call_result_t
{
    open_process_result_t() : call_result_t(), process_handle_addr(), desired_access(), object_attributes_addr(), client_id{} {}

    addr_t process_handle_addr;
    uint32_t desired_access;
    addr_t object_attributes_addr;
    uint32_t client_id;
};

struct open_thread_result_t: public call_result_t
{
    open_thread_result_t() : call_result_t(), thread_handle_addr(), desired_access(), object_attributes_addr(), client_id(), unique_thread() {}

    addr_t thread_handle_addr;
    uint32_t desired_access;
    addr_t object_attributes_addr;
    uint32_t client_id;
    uint32_t unique_thread;
};

struct process_creation_result_t: public call_result_t
{
    process_creation_result_t() : call_result_t(), new_process_handle_addr(), new_thread_handle_addr(), user_process_parameters_addr() {}

    addr_t new_process_handle_addr;
    addr_t new_thread_handle_addr;
    addr_t user_process_parameters_addr;
};

struct process_create_ex_result_t: public call_result_t
{
    process_create_ex_result_t() : call_result_t(), process_handle_addr(), desired_access(), object_attributes_addr(), parent_process(), flags(), section_handle(), debug_port(), exception_port(), job_member_level() {}

    addr_t process_handle_addr;
    uint32_t desired_access;
    addr_t object_attributes_addr;
    uint64_t parent_process;
    uint32_t flags;
    uint64_t section_handle;
    uint64_t debug_port;
    uint64_t exception_port;
    uint32_t job_member_level;
};

struct process_visitor_ctx
{
    output_format_t format;
};

} // namespace

static char* read_cmd_line(vmi_instance_t vmi, drakvuf_trap_info_t* info, addr_t addr)
{
    char* cmd = NULL;
    access_context_t ctx2 =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr,
    };
    addr_t cmdline_addr = ctx2.addr;
    uint16_t cmd_len = 0;
    if (VMI_SUCCESS == vmi_read_16(vmi, &ctx2, &cmd_len))
    {
        ctx2.addr = cmdline_addr+8; // _UNICODE_STRING->Buffer
        addr_t buffer_adr = 0;
        if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx2, &buffer_adr))
        {
            ctx2.addr = buffer_adr;
            char* buf_ret;
            buf_ret = (char*)g_try_malloc0(cmd_len+1);
            if (!buf_ret) return NULL;
            if (VMI_SUCCESS == vmi_read(vmi, &ctx2, cmd_len, buf_ret, NULL))
            {
                cmd = (char*)g_try_malloc0(cmd_len+1);
                if (!cmd)
                {
                    g_free(buf_ret);
                    return NULL;
                }
                int i;
                for (i = 0; i<cmd_len; i++)
                {
                    strncat(cmd, &buf_ret[i], 1);
                }
            }
            g_free(buf_ret);
        }
    }
    return cmd;
}
static void print_process_creation_result(
    procmon* f, drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    reg_t status, addr_t new_process_handle, vmi_pid_t new_pid,
    addr_t new_thread_handle, uint32_t new_tid,
    addr_t user_process_parameters_addr)
{
    addr_t cmdline_addr = user_process_parameters_addr + f->command_line;
    addr_t imagepath_addr = user_process_parameters_addr + f->image_path_name;
    addr_t dllpath_addr = user_process_parameters_addr + f->dll_path;
    addr_t curdir_handle_addr = user_process_parameters_addr + f->current_directory_handle;
    addr_t curdir_dospath_addr = user_process_parameters_addr + f->current_directory_dospath;

    unicode_string_t* cmdline_us = drakvuf_read_unicode(drakvuf, info, cmdline_addr);
    unicode_string_t* imagepath_us = drakvuf_read_unicode(drakvuf, info, imagepath_addr);
    unicode_string_t* dllpath_us = drakvuf_read_unicode(drakvuf, info, dllpath_addr);

    vmi_lock_guard vmi_lg(drakvuf);
    char* cmd = read_cmd_line(vmi_lg.vmi, info, cmdline_addr);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = curdir_handle_addr,
    };
    addr_t curdir_handle = 0;
    char* curdir = nullptr;

    if (VMI_SUCCESS == vmi_read_addr(vmi_lg.vmi, &ctx, &curdir_handle))
        curdir = drakvuf_get_filename_from_handle(drakvuf, info, curdir_handle);

    if (!curdir)
    {
        unicode_string_t* curdir_us = drakvuf_read_unicode(drakvuf, info, curdir_dospath_addr);
        if (curdir_us)
        {
            curdir = (char*)curdir_us->contents;
            curdir_us->contents = nullptr;
            vmi_free_unicode_str(curdir_us);
        }
        else
            curdir = g_strdup("");
    }

    gchar* cmdline = g_strescape(cmdline_us ? reinterpret_cast<char const*>(cmdline_us->contents) : cmd, NULL);
    char const* imagepath = imagepath_us ? reinterpret_cast<char const*>(imagepath_us->contents) : "";
    char const* dllpath = dllpath_us ? reinterpret_cast<char const*>(dllpath_us->contents) : "";

    fmt::print(f->m_output_format, "procmon", drakvuf, info,
               keyval("Status", fmt::Xval(status)),
               keyval("NewProcessHandle", fmt::Xval(new_process_handle)),
               keyval("NewPid", fmt::Nval(new_pid)),
               keyval("NewThreadHandle", fmt::Xval(new_thread_handle)),
               keyval("NewTid", fmt::Nval(new_tid)),
               keyval("CommandLine", fmt::Qstr(cmdline)),
               keyval("ImagePathName", fmt::Qstr(imagepath)),
               keyval("DllPath", fmt::Qstr(dllpath)),
               keyval("CWD", fmt::Qstr(curdir))
              );

    g_free(cmdline);
    g_free(curdir);
    g_free(cmd);
    if (cmdline_us)
        vmi_free_unicode_str(cmdline_us);

    if (imagepath_us)
        vmi_free_unicode_str(imagepath_us);

    if (dllpath_us)
        vmi_free_unicode_str(dllpath_us);
}

static event_response_t process_creation_return_hook(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<procmon>(info);
    auto params = get_trap_params<process_creation_result_t>(info);

    if (!params->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    addr_t user_process_parameters_addr = params->user_process_parameters_addr;
    addr_t new_thread_handle_addr = params->new_thread_handle_addr;
    addr_t new_process_handle_addr = params->new_process_handle_addr;
    reg_t status = info->regs->rax;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = new_process_handle_addr,
    };

    addr_t new_process_handle;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &new_process_handle))
        new_process_handle = 0;

    ctx.addr = new_thread_handle_addr;
    addr_t new_thread_handle;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &new_thread_handle))
        new_thread_handle = 0;

    drakvuf_release_vmi(drakvuf);

    vmi_pid_t new_pid;
    if (!drakvuf_get_pid_from_handle(drakvuf, info, new_process_handle, &new_pid))
        new_pid = 0;

    uint32_t new_tid;
    if (!drakvuf_get_tid_from_handle(drakvuf, info, new_thread_handle, &new_tid))
        new_tid = 0;

    print_process_creation_result(plugin, drakvuf, info, status, new_process_handle, new_pid, new_thread_handle, new_tid, user_process_parameters_addr);
    plugin->destroy_trap(info->trap);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t process_create_ex_return_hook(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<procmon>(info);
    auto params = get_trap_params<process_create_ex_result_t>(info);

    if (!params->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    addr_t process_handle_addr = params->process_handle_addr;
    reg_t status = info->regs->rax;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = process_handle_addr,
    };

    addr_t process_handle;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &process_handle))
        process_handle = 0;

    drakvuf_release_vmi(drakvuf);

    vmi_pid_t new_pid;
    if (!drakvuf_get_pid_from_handle(drakvuf, info, process_handle, &new_pid))
        new_pid = 0;

    fmt::print(plugin->m_output_format, "procmon", drakvuf, info,
               keyval("Status", fmt::Xval(status)),
               keyval("ProcessHandle", fmt::Xval(process_handle)),
               keyval("DesiredAccess", fmt::Xval(params->desired_access)),
               keyval("ObjectAttributes", fmt::Xval(params->object_attributes_addr)),
               keyval("ParentProcess", fmt::Xval(params->parent_process)),
               keyval("Flags", fmt::Xval(params->flags)),
               keyval("SectionHandle", fmt::Xval(params->section_handle)),
               keyval("DebugPort", fmt::Xval(params->debug_port)),
               keyval("ExceptionPort", fmt::Xval(params->exception_port)),
               keyval("JobMemberLevel", fmt::Nval(params->job_member_level)),
               keyval("NewPid", fmt::Nval(new_pid))
              );

    plugin->destroy_trap(info->trap);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t create_user_process_hook(
    drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    addr_t process_handle_addr,
    addr_t thread_handle_addr,
    addr_t user_process_parameters_addr)
{
    auto plugin = get_trap_plugin<procmon>(info);
    auto trap = plugin->register_trap<process_creation_result_t>(
                    info,
                    process_creation_return_hook,
                    breakpoint_by_pid_searcher());

    auto params = get_trap_params<process_creation_result_t>(trap);
    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    params->new_process_handle_addr = process_handle_addr;
    params->new_thread_handle_addr = thread_handle_addr;
    params->user_process_parameters_addr = user_process_parameters_addr;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t create_process_ex_hook(
    drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    addr_t process_handle_addr,
    uint32_t desired_access,
    addr_t object_attributes_addr,
    uint64_t parent_process,
    uint32_t flags,
    uint64_t section_handle,
    uint64_t debug_port,
    uint64_t exception_port,
    uint32_t job_member_level)
{
    auto plugin = get_trap_plugin<procmon>(info);
    auto trap = plugin->register_trap<process_create_ex_result_t>(
                    info,
                    process_create_ex_return_hook,
                    breakpoint_by_pid_searcher());

    auto params = get_trap_params<process_create_ex_result_t>(trap);

    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    params->process_handle_addr = process_handle_addr;
    params->desired_access = desired_access;
    params->object_attributes_addr = object_attributes_addr;
    params->parent_process = parent_process;
    params->flags = flags;
    params->section_handle = section_handle;
    params->debug_port = debug_port;
    params->exception_port = exception_port;
    params->job_member_level = job_member_level;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t terminate_process_hook(
    drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    addr_t process_handle, addr_t exit_status)
{
    auto plugin = get_trap_plugin<procmon>(info);

    vmi_pid_t exit_pid;
    if (!drakvuf_get_pid_from_handle(drakvuf, info, process_handle, &exit_pid))
        exit_pid = 0;

    char exit_status_buf[NTSTATUS_MAX_FORMAT_STR_SIZE] = {0};
    const char* exit_status_str = ntstatus_to_string(ntstatus_t(exit_status));
    if (!exit_status_str)
        exit_status_str = ntstatus_format_string(ntstatus_t(exit_status), exit_status_buf, sizeof(exit_status_buf));

    fmt::print(plugin->m_output_format, "procmon", drakvuf, info,
               keyval("ExitPid", fmt::Nval(exit_pid)),
               keyval("ExitStatus", fmt::Xval(exit_status)),
               keyval("ExitStatusStr", fmt::Qstr(exit_status_str))
              );

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t create_user_process_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // PHANDLE ProcessHandle
    addr_t process_handle_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t thread_handle_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    // PRTL_USER_PROCESS_PARAMETERS RtlUserProcessParameters
    addr_t user_process_parameters_addr = drakvuf_get_function_argument(drakvuf, info, 9);
    return create_user_process_hook(drakvuf, info, process_handle_addr, thread_handle_addr, user_process_parameters_addr);
}

static event_response_t create_process_ex_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // PHANDLE ProcessHandle
    addr_t process_handle_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    uint32_t desired_access  = drakvuf_get_function_argument(drakvuf, info, 2);
    addr_t object_attributes_addr  = drakvuf_get_function_argument(drakvuf, info, 3);
    uint64_t parent_process  = drakvuf_get_function_argument(drakvuf, info, 4);
    uint32_t flags  = drakvuf_get_function_argument(drakvuf, info, 5);
    uint64_t section_handle  = drakvuf_get_function_argument(drakvuf, info, 6);
    uint64_t debug_port  = drakvuf_get_function_argument(drakvuf, info, 7);
    uint64_t exception_port  = drakvuf_get_function_argument(drakvuf, info, 8);
    uint32_t job_member_level  = drakvuf_get_function_argument(drakvuf, info, 9);
    return create_process_ex_hook(drakvuf, info, process_handle_addr, desired_access, object_attributes_addr, parent_process, flags, section_handle, debug_port, exception_port, job_member_level);
}

static event_response_t terminate_process_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // HANDLE ProcessHandle
    addr_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    // NTSTATUS ExitStatus
    addr_t exit_status = drakvuf_get_function_argument(drakvuf, info, 2);
    return terminate_process_hook(drakvuf, info, process_handle, exit_status);
}

static event_response_t open_process_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<procmon>(info);
    auto params = get_trap_params<open_process_result_t>(info);

    if (!params->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = params->process_handle_addr,
    };

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    addr_t process_handle;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &process_handle))
        process_handle = 0;

    drakvuf_release_vmi(drakvuf);

    char* name = nullptr;
    addr_t client_process = 0;
    if (drakvuf_find_process(drakvuf, params->client_id, nullptr, &client_process))
        name = drakvuf_get_process_name(drakvuf, client_process, true);

    if (!name)
        name = g_strdup("<UNKNOWN>");

    fmt::print(plugin->m_output_format, "procmon", drakvuf, info,
               keyval("ProcessHandle", fmt::Xval(process_handle)),
               keyval("DesiredAccess", fmt::Xval(params->desired_access)),
               keyval("ObjectAttributes", fmt::Xval(params->object_attributes_addr)),
               keyval("ClientID", fmt::Nval(params->client_id)),
               keyval("ClientName", fmt::Qstr(name))
              );

    g_free(name);
    plugin->destroy_trap(info->trap);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t open_process_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<procmon>(info);
    auto trap = plugin->register_trap<open_process_result_t>(
                    info,
                    open_process_return_hook_cb,
                    breakpoint_by_pid_searcher());

    auto params = get_trap_params<open_process_result_t>(trap);

    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));

    // PHANDLE ProcessHandle
    params->process_handle_addr = drakvuf_get_function_argument(drakvuf, info, 1);

    // ACCESS_MASK DesiredAccess
    params->desired_access = drakvuf_get_function_argument(drakvuf, info, 2);

    // POBJECT_ATTRIBUTES ObjectAttributes
    params->object_attributes_addr = drakvuf_get_function_argument(drakvuf, info, 3);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB, .dtb = info->regs->cr3 };

    // PCLIENT_ID ClientId
    params->client_id = 0;
    ctx.addr = drakvuf_get_function_argument(drakvuf, info, 4);
    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, (uint32_t*)&params->client_id))
        PRINT_DEBUG("[PROCMON] Failed to read CLIENT_ID\n");

    if (!params->client_id)
        params->client_id = info->attached_proc_data.pid;

    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t open_thread_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<procmon>(info);
    auto params = get_trap_params<open_thread_result_t>(info);

    if (!params->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = params->thread_handle_addr,
    };

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    addr_t thread_handle;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &thread_handle))
        thread_handle = 0;

    drakvuf_release_vmi(drakvuf);

    char* name = nullptr;
    addr_t client_process = 0;
    if (drakvuf_find_process(drakvuf, params->client_id, nullptr, &client_process))
        name = drakvuf_get_process_name(drakvuf, client_process, true);

    if (!name)
        name = g_strdup("<UNKNOWN>");

    fmt::print(plugin->m_output_format, "procmon", drakvuf, info,
               keyval("ThreadHandle", fmt::Xval(thread_handle)),
               keyval("DesiredAccess", fmt::Xval(params->desired_access)),
               keyval("ObjectAttributes", fmt::Xval(params->object_attributes_addr)),
               keyval("ClientID", fmt::Nval(params->client_id)),
               keyval("ClientName", fmt::Qstr(name)),
               keyval("UniqueThread", fmt::Nval(params->unique_thread))
              );
    g_free(name);
    plugin->destroy_trap(info->trap);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t open_thread_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<procmon>(info);
    auto trap = plugin->register_trap<open_thread_result_t>(
                    info,
                    open_thread_return_hook_cb,
                    breakpoint_by_pid_searcher());

    auto params = get_trap_params<open_thread_result_t>(trap);

    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));

    // PHANDLE ProcessHandle
    params->thread_handle_addr = drakvuf_get_function_argument(drakvuf, info, 1);

    // ACCESS_MASK DesiredAccess
    params->desired_access = drakvuf_get_function_argument(drakvuf, info, 2);

    // POBJECT_ATTRIBUTES ObjectAttributes
    params->object_attributes_addr = drakvuf_get_function_argument(drakvuf, info, 3);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB, .dtb = info->regs->cr3 };

    // PCLIENT_ID ClientId
    params->client_id = 0;
    ctx.addr = drakvuf_get_function_argument(drakvuf, info, 4);
    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, (uint32_t*)&params->client_id))
        PRINT_DEBUG("[PROCMON] Failed to read CLIENT_ID\n");

    ctx.addr += plugin->cid_tid;
    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, (uint32_t*)&params->unique_thread))
        PRINT_DEBUG("[PROCMON] Failed to read CLIENT_ID.UniqueThread\n");

    if (!params->client_id)
        params->client_id = info->attached_proc_data.pid;

    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t protect_virtual_memory_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // HANDLE ProcessHandle
    uint64_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    // WIN32_PROTECTION_MASK NewProtectWin32
    uint32_t new_protect = drakvuf_get_function_argument(drakvuf, info, 4);

    auto plugin = get_trap_plugin<procmon>(info);

    fmt::print(plugin->m_output_format, "procmon", drakvuf, info,
               keyval("ProcessHandle", fmt::Xval(process_handle)),
               keyval("NewProtectWin32", fmt::Qstr(stringify_protection_attributes(new_protect)))
              );

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t adjust_privileges_token_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    std::vector<std::pair<std::string, fmt::Aarg>> privileges;
    struct TOKEN_PRIVILEGES* newstate = nullptr;
    // HANDLE TokenHandle
    uint32_t token_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    bool disable_all = drakvuf_get_function_argument(drakvuf, info, 2);
    addr_t newstate_va = drakvuf_get_function_argument(drakvuf, info, 3);

    auto plugin = get_trap_plugin<procmon>(info);

    if (disable_all)
        privileges.push_back(keyval("DisableAll", fmt::Nval(1UL)));
    else
    {
        auto vmi = vmi_lock_guard(drakvuf);

        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = newstate_va,
        };

        newstate = (struct TOKEN_PRIVILEGES*)g_malloc0(sizeof(struct TOKEN_PRIVILEGES));
        if (!newstate ||
            VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(struct TOKEN_PRIVILEGES), newstate, nullptr) ||
            !newstate->privilege_count)
            goto done;
        if (newstate->privilege_count > 1)
        {
            auto count = newstate->privilege_count - 1;
            auto size = sizeof(struct TOKEN_PRIVILEGES) + sizeof(struct LUID_AND_ATTRIBUTES) * count;
            g_free(newstate);
            newstate = (struct TOKEN_PRIVILEGES*)g_malloc0(size);
            if (!newstate ||
                VMI_SUCCESS != vmi_read(vmi, &ctx, size, newstate, nullptr) ||
                !newstate->privilege_count)
                goto done;
        }

        for (size_t i = 0; i < newstate->privilege_count; ++i)
            privileges.push_back(stringify_privilege(newstate->privileges[i]));
    }

    fmt::print(plugin->m_output_format, "procmon", drakvuf, info,
               keyval("ProcessHandle", fmt::Nval(token_handle)),
               keyval("NewState", privileges)
              );

done:
    if (newstate)
        g_free(newstate);
    return VMI_EVENT_RESPONSE_NONE;
}

static void process_visitor(drakvuf_t drakvuf, addr_t process, void* visitor_ctx)
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

procmon::procmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output)
{
    struct process_visitor_ctx ctx = { .format = output };
    drakvuf_enumerate_processes(drakvuf, process_visitor, &ctx);

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "CommandLine", &this->command_line))
        throw -1;

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName", &this->image_path_name))
        throw -1;

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "DllPath", &this->dll_path))
        throw -1;

    addr_t current_directory_offset;
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "CurrentDirectory", &current_directory_offset))
        throw -1;

    addr_t curdir_handle_offset;
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_CURDIR", "Handle", &curdir_handle_offset))
        throw -1;

    addr_t curdir_dospath_offset;
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_CURDIR", "DosPath", &curdir_dospath_offset))
        throw -1;

    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_CLIENT_ID", "UniqueThread", &this->cid_tid))
        throw -1;

    this->current_directory_handle = current_directory_offset + curdir_handle_offset;
    this->current_directory_dospath = current_directory_offset + curdir_dospath_offset;

    breakpoint_in_system_process_searcher bp;
    if (!register_trap(nullptr, create_user_process_hook_cb, bp.for_syscall_name("NtCreateUserProcess")) ||
        !register_trap(nullptr, create_process_ex_hook_cb, bp.for_syscall_name("NtCreateProcessEx")) ||
        !register_trap(nullptr, terminate_process_hook_cb, bp.for_syscall_name("NtTerminateProcess")) ||
        !register_trap(nullptr, open_process_hook_cb, bp.for_syscall_name("NtOpenProcess")) ||
        !register_trap(nullptr, open_thread_hook_cb, bp.for_syscall_name("NtOpenThread")) ||
        !register_trap(nullptr, protect_virtual_memory_hook_cb, bp.for_syscall_name("NtProtectVirtualMemory")) ||
        !register_trap(nullptr, adjust_privileges_token_cb, bp.for_syscall_name("NtAdjustPrivilegesToken")))
    {
        throw -1;
    }
}
