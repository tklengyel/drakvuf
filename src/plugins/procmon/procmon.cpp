/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
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

#include <glib.h>
#include <config.h>
#include <inttypes.h>
#include <libvmi/x86.h>
#include <assert.h>

#include "../plugins.h"
#include "ntstatus.h"
#include "procmon.h"
#include "winnt.h"

namespace
{

template<typename T>
struct call_result_t : public plugin_params<T>
{
    call_result_t(T* src) : plugin_params<T>(src), target_cr3(), target_thread(), target_rsp() {}

    void set_result_call_params(const drakvuf_trap_info_t* info, addr_t thread)
    {
        target_thread = thread;
        target_cr3 = info->regs->cr3;
        target_rsp = info->regs->rsp;
    }

    bool verify_result_call_params(const drakvuf_trap_info_t* info, addr_t thread)
    {
        return (info->regs->cr3 != target_cr3 ||
                !thread || thread != target_thread ||
                info->regs->rsp <= target_rsp) ? false : true;
    }

    reg_t target_cr3;
    addr_t target_thread;
    addr_t target_rsp;
};

template<typename T>
struct open_process_result_t: public call_result_t<T>
{
    open_process_result_t(T* src) : call_result_t<T>(src), process_handle_addr(), desired_access(), object_attributes_addr(), client_id{} {}

    addr_t process_handle_addr;
    uint32_t desired_access;
    addr_t object_attributes_addr;
    uint32_t client_id;
};

template<typename T>
struct process_creation_result_t: public call_result_t<T>
{
    process_creation_result_t(T* src) : call_result_t<T>(src), new_process_handle_addr(), user_process_parameters_addr() {}

    addr_t new_process_handle_addr;
    addr_t user_process_parameters_addr;
};

struct process_visitor_ctx
{
    output_format_t format;
};

} // namespace

static void print_process_creation_result(
    procmon* f, drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    reg_t status, vmi_pid_t new_pid, addr_t user_process_parameters_addr)
{
    addr_t cmdline_addr = user_process_parameters_addr + f->command_line;
    addr_t imagepath_addr = user_process_parameters_addr + f->image_path_name;
    addr_t dllpath_addr = user_process_parameters_addr + f->dll_path;
    addr_t curdir_handle_addr = user_process_parameters_addr + f->current_directory_handle;
    addr_t curdir_dospath_addr = user_process_parameters_addr + f->current_directory_dospath;

    unicode_string_t* cmdline_us = drakvuf_read_unicode(drakvuf, info, cmdline_addr);
    unicode_string_t* imagepath_us = drakvuf_read_unicode(drakvuf, info, imagepath_addr);
    unicode_string_t* dllpath_us = drakvuf_read_unicode(drakvuf, info, dllpath_addr);

    gchar* escaped_pname = NULL;
    gchar* escaped_cmdline = NULL;
    gchar* escaped_ipath = NULL;
    gchar* escaped_dllpath = NULL;
    gchar* escaped_curdir = NULL;

    vmi_lock_guard vmi_lg(drakvuf);
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

    gchar* cmdline = g_strescape(cmdline_us ? reinterpret_cast<char const*>(cmdline_us->contents) : "", NULL);
    char const* imagepath = imagepath_us ? reinterpret_cast<char const*>(imagepath_us->contents) : "";
    char const* dllpath = dllpath_us ? reinterpret_cast<char const*>(dllpath_us->contents) : "";

    switch (f->m_output_format)
    {
        case OUTPUT_CSV:
            printf("procmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,0x%" PRIx64 ",%d,%s,%s,%s,%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, info->trap->name, status, new_pid, cmdline, imagepath, dllpath, curdir);
            break;

        case OUTPUT_KV:
            printf("procmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\","
                   "Method=%s,Status=0x%" PRIx64 ",NewPid=%d,CommandLine=\"%s\",ImagePathName=\"%s\",DllPath=\"%s\",CWD=\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name, status, new_pid, cmdline, imagepath, dllpath, curdir);
            break;

        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            escaped_cmdline = drakvuf_escape_str(cmdline);
            escaped_ipath   = drakvuf_escape_str(imagepath);
            escaped_dllpath = drakvuf_escape_str(dllpath);
            escaped_curdir  = drakvuf_escape_str(curdir);
            printf( "{"
                    "\"Plugin\" : \"procmon\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"ProcessName\": %s,"
                    "\"UserName\": \"%s\","
                    "\"UserId\": %" PRIu64 ","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"Method\" : \"%s\","
                    "\"Status\" : %" PRIu64 ","
                    "\"NewPid\" : %d,"
                    "\"CmdLine\" : %s,"
                    "\"ImagePathName\" : %s,"
                    "\"DllPath\" : %s,"
                    "\"CurDir\" : %s"
                    "}\n",
                    UNPACK_TIMEVAL(info->timestamp),
                    escaped_pname,
                    USERIDSTR(drakvuf), info->proc_data.userid,
                    info->proc_data.pid, info->proc_data.ppid,
                    info->trap->name, status, new_pid,
                    escaped_cmdline,
                    escaped_ipath,
                    escaped_dllpath,
                    escaped_curdir);

            g_free(escaped_pname);
            g_free(escaped_curdir);
            g_free(escaped_dllpath);
            g_free(escaped_ipath);
            g_free(escaped_cmdline);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[PROCMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ", EPROCESS:0x%" PRIx64
                   ", PID:%d, PPID:%d, \"%s\" %s:%" PRIi64 " %s:0x%" PRIx64 ":%d:%s:%s:%s:%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.base_addr,
                   info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, info->trap->name, status, new_pid,
                   cmdline, imagepath, dllpath, curdir);
            break;
    }

    g_free(cmdline);
    g_free(curdir);
    if (cmdline_us)
        vmi_free_unicode_str(cmdline_us);

    if (imagepath_us)
        vmi_free_unicode_str(imagepath_us);

    if (dllpath_us)
        vmi_free_unicode_str(dllpath_us);
}

static vmi_pid_t get_pid_from_handle(procmon* f, drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle)
{
    if (handle == 0 || handle == UINT64_MAX)
        return info->proc_data.pid;

    if (!info->proc_data.base_addr)
        return 0;

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, info->proc_data.base_addr, handle);
    if (!obj)
        return 0;

    vmi_pid_t pid;
    addr_t eprocess_base = obj + f->object_header_body;
    if (VMI_FAILURE == drakvuf_get_process_pid(drakvuf, eprocess_base, &pid))
        return 0;

    return pid;
}

static event_response_t process_creation_return_hook(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<procmon, process_creation_result_t<procmon>>(info);
    if (!data)
    {
        PRINT_DEBUG("procmon process_creation_return_hook invalid trap params!\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!data->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    auto* plugin = data->plugin();
    addr_t user_process_parameters_addr = data->user_process_parameters_addr;
    addr_t new_process_handle_addr = data->new_process_handle_addr;
    reg_t status = info->regs->rax;

    plugin->destroy_trap(drakvuf, info->trap);
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

    drakvuf_release_vmi(drakvuf);

    vmi_pid_t new_pid = get_pid_from_handle(plugin, drakvuf, info, new_process_handle);

    print_process_creation_result(plugin, drakvuf, info, status, new_pid, user_process_parameters_addr);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t create_user_process_hook(
    drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    addr_t process_handle_addr,
    addr_t user_process_parameters_addr)
{
    auto plugin = get_trap_plugin<procmon>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    auto trap = plugin->register_trap<procmon, process_creation_result_t<procmon>>(
                    drakvuf,
                    info,
                    plugin,
                    process_creation_return_hook,
                    breakpoint_by_pid_searcher());
    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto data = get_trap_params<procmon, process_creation_result_t<procmon>>(trap);
    if (!data)
    {
        plugin->destroy_plugin_params(plugin->detach_plugin_params(trap));
        return VMI_EVENT_RESPONSE_NONE;
    }

    data->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    data->new_process_handle_addr = process_handle_addr;
    data->user_process_parameters_addr = user_process_parameters_addr;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t terminate_process_hook(
    drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    addr_t process_handle, addr_t exit_status)
{
    gchar* escaped_pname = NULL;
    auto plugin = get_trap_plugin<procmon>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    vmi_pid_t exit_pid = get_pid_from_handle(plugin, drakvuf, info, process_handle);

    char exit_status_buf[NTSTATUS_MAX_FORMAT_STR_SIZE] = {0};
    const char* exit_status_str = ntstatus_to_string(ntstatus_t(exit_status));
    if (!exit_status_str)
        exit_status_str = ntstatus_format_string(ntstatus_t(exit_status), exit_status_buf, sizeof(exit_status_buf));

    switch (plugin->m_output_format)
    {
        case OUTPUT_CSV:
            printf("procmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,%d,0x%" PRIx64 ",%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, info->trap->name, exit_pid, exit_status, exit_status_str);
            break;

        case OUTPUT_KV:
            printf("procmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\","
                   "Method=%s,ExitPid=%d,ExitStatus=0x%" PRIx64 ",ExitStatusStr=%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name, exit_pid, exit_status, exit_status_str);
            break;

        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            printf( "{"
                    "\"Plugin\" : \"procmon\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"ProcessName\": %s,"
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"Method\" : \"%s\","
                    "\"ExitStatus\" : %" PRIu64 ","
                    "\"ExitPid\" : %d"
                    "}\n",
                    UNPACK_TIMEVAL(info->timestamp),
                    escaped_pname,
                    info->proc_data.pid, info->proc_data.ppid,
                    info->trap->name, exit_status, exit_pid);
            g_free(escaped_pname);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[PROCMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ", EPROCESS:0x%" PRIx64
                   ", PID:%d, PPID:%d, \"%s\" %s:%" PRIi64 " %s:%d:0x%" PRIx64 ":%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.base_addr,
                   info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, info->trap->name, exit_pid, exit_status, exit_status_str);
            break;
    }
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t create_user_process_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // PHANDLE ProcessHandle
    addr_t process_handle_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    // PRTL_USER_PROCESS_PARAMETERS RtlUserProcessParameters
    addr_t user_process_parameters_addr = drakvuf_get_function_argument(drakvuf, info, 9);
    return create_user_process_hook(drakvuf, info, process_handle_addr, user_process_parameters_addr);
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
    auto data = get_trap_params<procmon, open_process_result_t<procmon>>(info);
    procmon* plugin = data->plugin();
    if (!data || !plugin)
    {
        PRINT_DEBUG("procmon open_process_return_hook_cb invalid trap params!\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!data->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    plugin->destroy_trap(drakvuf, info->trap);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = data->process_handle_addr,
    };

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    addr_t process_handle;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &process_handle))
        process_handle = 0;

    drakvuf_release_vmi(drakvuf);

    gchar* escaped_pname = NULL;
    gchar* escaped_client_name = NULL;
    char* name = nullptr;
    addr_t client_process = 0;
    if (drakvuf_find_process(drakvuf, data->client_id, nullptr, &client_process))
        name = drakvuf_get_process_name(drakvuf, client_process, true);

    if (!name)
        name = g_strdup("<UNKNOWN>");

    switch (plugin->m_output_format)
    {
        case OUTPUT_CSV:
            printf("procmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,0x%" PRIx32 "0x%" PRIx64 "%d,\"%s\",0x%" PRIx64 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, info->trap->name, data->desired_access, data->object_attributes_addr, data->client_id, name, process_handle);
            break;

        case OUTPUT_KV:
            printf("procmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\","
                   "Method=%s,ProcessHandle=0x%" PRIx64 ",DesiredAccess=0x%" PRIx32 ",ObjectAttributes=0x%" PRIx64 ",ClientID=%d,ClientName=\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name, process_handle, data->desired_access, data->object_attributes_addr, data->client_id, name);
            break;

        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            escaped_client_name = drakvuf_escape_str(name);
            printf( "{"
                    "\"Plugin\" : \"procmon\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"ProcessName\": %s,"
                    "\"Method\" : \"%s\","
                    "\"DesiredAccess\" : %" PRIu32 ","
                    "\"ObjectAttributes\" : %" PRIu64 ","
                    "\"ClientID\" : %d,"
                    "\"ClientName\": %s"
                    "}\n",
                    UNPACK_TIMEVAL(info->timestamp),
                    info->proc_data.pid, info->proc_data.ppid, escaped_pname,
                    info->trap->name, data->desired_access, data->object_attributes_addr, data->client_id, escaped_client_name);
            g_free(escaped_client_name);
            g_free(escaped_pname);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[PROCMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ", EPROCESS:0x%" PRIx64
                   ", PID:%d, PPID:%d, \"%s\" %s:%" PRIi64 " %s:0x%" PRIx32 ":0x%" PRIx64 ":%d:\"%s\":0x%" PRIx64 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.base_addr,
                   info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, info->trap->name,
                   data->desired_access, data->object_attributes_addr, data->client_id, name, process_handle);
            break;
    }
    g_free(name);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t open_process_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<procmon>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    auto trap = plugin->register_trap<procmon, open_process_result_t<procmon>>(
                    drakvuf,
                    info,
                    plugin,
                    open_process_return_hook_cb,
                    breakpoint_by_pid_searcher());
    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto data = get_trap_params<procmon, open_process_result_t<procmon>>(trap);
    if (!data)
    {
        plugin->destroy_plugin_params(plugin->detach_plugin_params(trap));
        return VMI_EVENT_RESPONSE_NONE;
    }

    data->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));

    // PHANDLE ProcessHandle
    data->process_handle_addr = drakvuf_get_function_argument(drakvuf, info, 1);

    // ACCESS_MASK DesiredAccess
    data->desired_access = drakvuf_get_function_argument(drakvuf, info, 2);

    // POBJECT_ATTRIBUTES ObjectAttributes
    data->object_attributes_addr = drakvuf_get_function_argument(drakvuf, info, 3);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB, .dtb = info->regs->cr3 };

    // PCLIENT_ID ClientId
    data->client_id = 0;
    ctx.addr = drakvuf_get_function_argument(drakvuf, info, 4);
    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, (uint32_t*)&data->client_id))
        PRINT_DEBUG("[PROCMON] Failed to read CLIENT_ID\n");

    if (!data->client_id)
        data->client_id = info->proc_data.pid;

    drakvuf_release_vmi(drakvuf);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t protect_virtual_memory_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    gchar* escaped_pname = NULL;
    // HANDLE ProcessHandle
    uint64_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    // WIN32_PROTECTION_MASK NewProtectWin32
    uint32_t new_protect = drakvuf_get_function_argument(drakvuf, info, 4);

    auto plugin = get_trap_plugin<procmon>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    switch (plugin->m_output_format)
    {
        case OUTPUT_CSV:
            printf("procmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,0x%" PRIx64 ",%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, info->trap->name, process_handle, stringify_protection_attributes(new_protect).c_str());
            break;

        case OUTPUT_KV:
            printf("procmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\","
                   "Method=%s,ProcessHandle=0x%" PRIx64 ",NewProtectWin32=%s",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name, process_handle, stringify_protection_attributes(new_protect).c_str());
            break;

        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            printf( "{"
                    "\"Plugin\" : \"procmon\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"ProcessName\": %s,"
                    "\"Method\" : \"%s\","
                    "\"ProcessHandle\" : %" PRIu64 ","
                    "\"NewProtectWin32\" : \"%s\""
                    "}",
                    UNPACK_TIMEVAL(info->timestamp),
                    info->proc_data.pid, info->proc_data.ppid, escaped_pname,
                    info->trap->name,  process_handle, stringify_protection_attributes(new_protect).c_str());
            g_free(escaped_pname);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[PROCMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ", EPROCESS:0x%" PRIx64
                   ", PID:%d, PPID:%d, \"%s\" %s:%" PRIi64 ":%s:0x%" PRIx64 ":%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.base_addr,
                   info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, info->trap->name, process_handle,
                   stringify_protection_attributes(new_protect).c_str());
            break;
    }
    printf("\n");
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

    GTimeVal t;
    g_get_current_time(&t);

    switch (ctx->format)
    {
        case OUTPUT_CSV:
            printf("procmon," FORMAT_TIMEVAL ",Process,%u,%u,\"%s\"\n",
                   UNPACK_TIMEVAL(t), data.pid, data.ppid, data.name);
            break;

        case OUTPUT_KV:
            printf("procmon Time=" FORMAT_TIMEVAL ",RunningProcess=\"%s\",PID=%u,PPID=%u\n",
                   UNPACK_TIMEVAL(t), data.name, data.pid, data.ppid);
            break;

        case OUTPUT_JSON:
            //TODO
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[PROCMON] TIME:" FORMAT_TIMEVAL " PROCESS PID:%u PPID:%u FILE:\"%s\"\n",
                   UNPACK_TIMEVAL(t), data.pid, data.ppid, data.name);
            break;
    }

    g_free(const_cast<char*>(data.name));
}

procmon::procmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output)
{
    struct process_visitor_ctx ctx = { .format = output };
    drakvuf_enumerate_processes(drakvuf, process_visitor, &ctx);

    if (!drakvuf_get_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "CommandLine", &this->command_line))
        throw -1;

    if (!drakvuf_get_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName", &this->image_path_name))
        throw -1;

    if (!drakvuf_get_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "DllPath", &this->dll_path))
        throw -1;

    addr_t current_directory_offset;
    if (!drakvuf_get_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "CurrentDirectory", &current_directory_offset))
        throw -1;

    addr_t curdir_handle_offset;
    if (!drakvuf_get_struct_member_rva(drakvuf, "_CURDIR", "Handle", &curdir_handle_offset))
        throw -1;

    addr_t curdir_dospath_offset;
    if (!drakvuf_get_struct_member_rva(drakvuf, "_CURDIR", "DosPath", &curdir_dospath_offset))
        throw -1;

    this->current_directory_handle = current_directory_offset + curdir_handle_offset;
    this->current_directory_dospath = current_directory_offset + curdir_dospath_offset;
    if (!drakvuf_get_struct_member_rva(drakvuf, "_OBJECT_HEADER", "Body", &this->object_header_body))
        throw -1;

    breakpoint_in_system_process_searcher bp;
    if (!register_trap<procmon>(drakvuf, nullptr, this, create_user_process_hook_cb, bp.for_syscall_name("NtCreateUserProcess")) ||
            !register_trap<procmon>(drakvuf, nullptr, this, terminate_process_hook_cb, bp.for_syscall_name("NtTerminateProcess")) ||
            !register_trap<procmon>(drakvuf, nullptr, this, open_process_hook_cb, bp.for_syscall_name("NtOpenProcess")) ||
            !register_trap<procmon>(drakvuf, nullptr, this, protect_virtual_memory_hook_cb, bp.for_syscall_name("NtProtectVirtualMemory")))
    {
        throw -1;
    }
}
