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

        ctx.addr = entry + plugin->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME];
        auto name = drakvuf_read_unicode_common(vmi.vmi, &ctx);
        if (name && name->contents)
        {
            auto drv = std::string(reinterpret_cast<char*>(name->contents));
            drivers_list.insert(std::move(drv));
            vmi_free_unicode_str(name);
        }
    } while (entry != list_head);

    return drivers_list;
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

static event_response_t load_unload_driver_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<dkommon>(info);
    addr_t entry = drakvuf_get_function_argument(drakvuf, info, 1);
    bool i_insert = drakvuf_get_function_argument(drakvuf, info, 2);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 4,
        .addr = entry + plugin->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME]
    );

    vmi_lock_guard vmi(drakvuf);
    unicode_string_t* drvname = drakvuf_read_unicode_common(vmi, &ctx);
    if (drvname && drvname->contents)
    {
        std::string drvname_str{ reinterpret_cast<char*>(drvname->contents) };
        if (i_insert)
        {
            PRINT_DEBUG("[DKOMMON] Loading %s\n", drvname_str.c_str());
            plugin->loaded_drivers.insert(drvname_str);
        }
        else
        {
            PRINT_DEBUG("[DKOMMON] Unloading %s\n", drvname_str.c_str());
            plugin->loaded_drivers.erase(drvname_str);
        }
        vmi_free_unicode_str(drvname);
    }

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
        !register_trap(nullptr, load_unload_driver_cb, bp.for_syscall_name("MiProcessLoaderEntry")))
    {
        PRINT_DEBUG("[DKOMMON] Failed to setup critical traps\n");
        throw -1;
    }
}

dkommon::~dkommon()
{
    delete[] offsets;
}

bool dkommon::stop_impl()
{
    if (!is_stopping())
    {
        auto temp_processes = std::move(this->live_processes);
        this->live_processes.clear();
        drakvuf_enumerate_processes(drakvuf, process_visitor, static_cast<void*>(this));

        for (vmi_pid_t pid : temp_processes)
        {
            if (std::find(this->live_processes.begin(), this->live_processes.end(), pid) == this->live_processes.end())
            {
                print_hidden_process_information(drakvuf, nullptr, this, pid);
            }
        }

        // Check hidden drivers
        //
        auto temp_drivers = enumerate_drivers(this, drakvuf);
        for (const auto& drvname : this->loaded_drivers)
        {
            if (std::find(temp_drivers.begin(), temp_drivers.end(), drvname) == temp_drivers.end())
                print_driver_information(drakvuf, nullptr, this->format, "Hidden Driver", drvname.c_str());
        }
    }
    return pluginex::stop_impl();
}
