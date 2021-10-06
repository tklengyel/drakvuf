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
***************************************************************************/

#include <libvmi/libvmi.h>
#include "libdrakvuf/libdrakvuf.h"
#include "plugins/output_format.h"
#include <algorithm>

#include "dkommon.h"
#include "private.h"

static void print_hidden_process_information(drakvuf_t drakvuf, drakvuf_trap_info_t* info, dkommon* plugin, vmi_pid_t pid)
{
    fmt::print(plugin->format, "dkommon", drakvuf, info,
        keyval("Message", fmt::Qstr("Hidden Process")),
        keyval("HiddenPID", fmt::Nval(pid))
    );
}

static void print_driver_information(drakvuf_t drakvuf, drakvuf_trap_info_t* info, output_format_t format, const char* message, const char* name)
{
    fmt::print(format, "dkommon", drakvuf, info,
        keyval("Message", fmt::Qstr(message)),
        keyval("DriverName", fmt::Qstr(name))
    );
}
static std::vector<std::string> split_string(std::string value, const std::string& delimiter)
{
    std::vector<std::string> splitted;
    size_t pos = 0;
    while ((pos = value.find(delimiter)) != std::string::npos)
    {
        splitted.push_back(value.substr(0, pos));
        value.erase(0, pos + delimiter.size());
    }

    if (!value.empty())
        splitted.push_back(value);

    if (splitted.empty())
        splitted.push_back(value);

    return splitted;
};

static std::set<std::string> enumerate_drivers(dkommon* plugin, drakvuf_t drakvuf)
{
    std::set<std::string> drivers_list;
    vmi_lock_guard vmi(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 4,
    );

    addr_t list_head = 0;
    if (VMI_SUCCESS != vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &list_head))
    {
        PRINT_DEBUG("dkommon:enumerate drivers: failed to read PsLoadedModuleList value\n");
        return drivers_list;
    }

    list_head -= plugin->offsets[LDR_DATA_TABLE_ENTRY_INLOADORDERLINKS];

    addr_t entry = list_head;
    do
    {
        ctx.addr = entry + plugin->offsets[LDR_DATA_TABLE_ENTRY_INLOADORDERLINKS] + plugin->offsets[LIST_ENTRY_FLINK];
        if (VMI_SUCCESS != vmi_read_addr(vmi.vmi, &ctx, &entry))
        {
            PRINT_DEBUG("dkommon:enumerate drivers: failed to read next entry (VA 0x%lx)\n", ctx.addr);
            return drivers_list;
        }

        ctx.addr = entry + plugin->offsets[LDR_DATA_TABLE_ENTRY_FULLDLLNAME];
        auto name = drakvuf_read_unicode_common(vmi.vmi, &ctx);
        if (name && name->contents)
        {
            auto drv = std::string(reinterpret_cast<char*>(name->contents));
            drivers_list.insert(split_string(drv, "\\").back());
            vmi_free_unicode_str(name);
        }
    } while (entry != list_head);

    return drivers_list;
}

static event_response_t notify_zero_page_write(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = static_cast<dkommon*>(info->trap->data);
    fmt::print(plugin->format, "dkommon", drakvuf, info,
        keyval("Message", fmt::Qstr("Zero Page Write"))
    );
    return 0;
}

static void process_visitor(drakvuf_t drakvuf, addr_t process, void* pass_ctx)
{
    auto plugin = static_cast<dkommon*>(pass_ctx);
    vmi_pid_t pid;
    if (!drakvuf_get_process_pid(drakvuf, process, &pid))
    {
        PRINT_DEBUG("[DKOMMON] Failed to read process pid\n");
        return;
    }
    plugin->live_processes.insert(pid);
}

static event_response_t driver_load_unload_return_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<dkommon>(info);
    auto params = get_trap_params<driver_call_result>(info);
    if (!params->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    drakvuf_remove_trap(drakvuf, info->trap, nullptr);

    // If call was successful (NTSTATUS STATUS_SUCCESS)
    if (info->regs->rax == 0)
    {
        std::string drv = split_string({ (const char*)params->driver_name->contents }, "\\").back();
        vmi_free_unicode_str(params->driver_name);

        if (params->call_type == driver_call_type::LOAD)
        {
            plugin->loaded_drivers.insert(drv);
            plugin->unloaded_drivers.erase(drv);
        }
        else if (params->call_type == driver_call_type::UNLOAD)
        {
            if (std::find(plugin->unloaded_drivers.begin(), plugin->unloaded_drivers.end(), drv) == plugin->unloaded_drivers.end())
            {
                plugin->loaded_drivers.erase(drv);
                plugin->unloaded_drivers.insert(drv);
            }
        }
    }
    return VMI_EVENT_RESPONSE_NONE;
}

static void hook_driver_return(drakvuf_t drakvuf, drakvuf_trap_info_t* info, dkommon* plugin, unicode_string_t* drvname, driver_call_type call_type)
{
    auto trap = plugin->register_trap<driver_call_result>(
            info,
            driver_load_unload_return_cb,
            breakpoint_by_pid_searcher());

    auto params = get_trap_params<driver_call_result>(trap);
    params->set_result_call_params(info);
    params->driver_name = drvname;
    params->call_type = call_type;
}

static event_response_t load_driver_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<dkommon>(info);
    addr_t drvname_ptr = drakvuf_get_function_argument(drakvuf, info, 1);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = drvname_ptr
    );

    vmi_lock_guard vmi(drakvuf);
    unicode_string_t* drvname = drakvuf_read_unicode_common(vmi, &ctx);
    if (drvname)
        hook_driver_return(drakvuf, info, plugin, drvname, driver_call_type::LOAD);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t unload_driver_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<dkommon>(info);
    addr_t drvname_ptr = drakvuf_get_function_argument(drakvuf, info, 1);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = drvname_ptr
    );

    vmi_lock_guard vmi(drakvuf);
    unicode_string_t* drvname = drakvuf_read_unicode_common(vmi, &ctx);
    if (drvname)
        hook_driver_return(drakvuf, info, plugin, drvname, driver_call_type::UNLOAD);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t delete_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<dkommon>(info);
    uint64_t process = drakvuf_get_function_argument(drakvuf, info, 1);

    vmi_pid_t pid;
    if (!drakvuf_get_process_pid(drakvuf, process, &pid))
    {
        PRINT_DEBUG("[DKOMMON] Failed to read process pid\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // Skip if already dead
    if (std::find(plugin->dead_processes.begin(), plugin->dead_processes.end(), pid) != plugin->dead_processes.end())
        return VMI_EVENT_RESPONSE_NONE;

    addr_t list_entry_va = process + plugin->offsets[EPROCESS_ACTIVEPROCESSLINKS];
    addr_t flink = 0;
    addr_t blink = 0;

    vmi_lock_guard vmi(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 4,
    );

    ctx.addr = list_entry_va + plugin->offsets[LIST_ENTRY_FLINK];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &flink))
        goto done;

    ctx.addr = list_entry_va + plugin->offsets[LIST_ENTRY_BLINK];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &blink))
        goto done;

    if (list_entry_va == flink && flink == blink && flink && blink)
    {
        print_hidden_process_information(drakvuf, info, plugin, pid);
    }

done:
    plugin->live_processes.erase(pid);
    plugin->dead_processes.insert(pid);

    PRINT_DEBUG("[DKOMMON] Terminating process %d\n", (vmi_pid_t)pid);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t insert_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<dkommon>(info);
    addr_t process = drakvuf_get_function_argument(drakvuf, info, 1);

    vmi_pid_t pid;
    if (!drakvuf_get_process_pid(drakvuf, process, &pid))
    {
        PRINT_DEBUG("[DKOMMON] Failed to read process pid\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    PRINT_DEBUG("[DKOMMON] Inserting process %d\n", pid);
    plugin->live_processes.insert(pid);
    // In case new process is created with the same pid
    plugin->dead_processes.erase(pid);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t final_check_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // Process only first callback call
    auto plugin = get_trap_plugin<dkommon>(info);
    if (plugin->is_stopping() && !plugin->done_final_analysis)
    {
        // Check hidden processes
        //
        auto temp_processes = std::move(plugin->live_processes);
        plugin->live_processes.clear();
        drakvuf_enumerate_processes(drakvuf, process_visitor, static_cast<void*>(plugin));

        for (vmi_pid_t pid : temp_processes)
        {
            if (std::find(plugin->live_processes.begin(), plugin->live_processes.end(), pid) == plugin->live_processes.end())
            {
                print_hidden_process_information(drakvuf, info, plugin, pid);
            }
        }

        // Check hidden drivers
        //
        auto temp_drivers = enumerate_drivers(plugin, drakvuf);
        for (const auto& drvname : plugin->loaded_drivers)
        {
            if (std::find(temp_drivers.begin(), temp_drivers.end(), drvname) == temp_drivers.end())
                print_driver_information(drakvuf, info, plugin->format, "Hidden Driver", drvname.c_str());
        }

        plugin->done_final_analysis = true;
    }
    return VMI_EVENT_RESPONSE_NONE;
}

dkommon::dkommon(drakvuf_t drakvuf, const void* config, output_format_t output)
    : pluginex(drakvuf, output), format(output), offsets(new size_t[__OFFSET_MAX])
{
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, __OFFSET_MAX, offsets))
        throw -1;

    drakvuf_enumerate_processes(drakvuf, process_visitor, static_cast<void*>(this));

    this->loaded_drivers = enumerate_drivers(this, drakvuf);

    breakpoint_in_system_process_searcher bp;
    if (!register_trap(nullptr, delete_process_cb, bp.for_syscall_name("PspProcessDelete")) ||
        !register_trap(nullptr, insert_process_cb, bp.for_syscall_name("PspInsertProcess")) ||
        !register_trap(nullptr, load_driver_cb, bp.for_syscall_name("NtLoadDriver")) ||
        !register_trap(nullptr, unload_driver_cb, bp.for_syscall_name("NtUnloadDriver")))
    {
        PRINT_DEBUG("[DKOMMON] Failed to setup critical traps\n");
        throw -1;
    }

    zeropage_trap.cb = notify_zero_page_write;
    if (!drakvuf_add_trap(drakvuf, &zeropage_trap)) throw -1;
}

dkommon::~dkommon()
{
    delete[] offsets;
}

bool dkommon::stop()
{
    if (!is_stopping() && !done_final_analysis)
    {
        m_is_stopping = true;
        PRINT_DEBUG("[dkommon] Injecting KiDeliverApc\n");
        // Hook dummy function so we could make final system analysis
        breakpoint_in_system_process_searcher bp;
        register_trap(nullptr, final_check_cb, bp.for_syscall_name("KiDeliverApc"));
        // Return status `Pending`
        return false;
    }
    return done_final_analysis;
}
