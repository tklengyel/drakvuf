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

#include <libvmi/libvmi.h>
#include "libdrakvuf/libdrakvuf.h"
#include "plugins/output_format.h"
#include <algorithm>

#include "dkommon.h"
#include "private.h"

static constexpr uint16_t win_7_sp1_ver   = 7601;
static constexpr uint16_t win_10_1803_ver = 17134;

static const std::vector<uint8_t> win_7_srv_signature
{
    0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,   // mov     rbx, cs:g_serviceDB
    0xEB, 0x00,                                 // jmp     short loc_1000017C0
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90,         // nop
    0x90, 0x90, 0x90,                           // nop
    0x48, 0x85, 0xDB,                           // test    rbx, rbx
    0x74, 0x00,                                 // jz      short loc_1000017E3
    0x48, 0x8B, 0x4B, 0x08,                     // mov     rcx, [rbx+8]    ; String1
    0x48, 0x8B, 0xD6,                           // mov     rdx, rsi        ; String2
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00          // call    cs:__imp__wcsicmp
};

static const std::vector<uint8_t> win_10_srv_signature
{
    0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,   // mov     rbx, qword ptr cs:g_ServicesDB
    0x48, 0x85, 0xDB,                           // test    rbx, rbx
    0x74, 0x00,                                 // jz      short loc_7FF78BAE1E61
    0x8B, 0x43, 0x34,                           // mov     eax, [rbx+34h]
    0x0F, 0xBA, 0xE0, 0x15                      // bt      eax, 15h
};

// Map of Windows version -> [name offset, next pointer offset in `SERVICE_RECORD` structure]
static const std::map<uint64_t, std::pair<uint64_t, uint64_t>> srv_offsets =
{
    { win_7_sp1_ver, { 0x08, 0x80 } },
    { win_10_1803_ver, { 0x40, 0x18 } }
};

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
        .pid = 4
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
        if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &entry))
        {
            PRINT_DEBUG("dkommon:enumerate drivers: failed to read next entry (VA 0x%lx)\n", ctx.addr);
            return drivers_list;
        }

        ctx.addr = entry + plugin->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME];
        auto name = drakvuf_read_unicode_common(drakvuf, &ctx);
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
    // Locate services.exe process.
    auto name = drakvuf_get_process_name(drakvuf, process, true);
    if (name)
    {
        if (strstr(name, "\\Windows\\System32\\services.exe"))
        {
            plugin->srv_pid = pid;
            // Get services.exe module base address.
            addr_t module_list{ 0 };
            drakvuf_get_module_list(drakvuf, process, &module_list);
            ACCESS_CONTEXT(ctx,
                .translate_mechanism = VMI_TM_PROCESS_PID,
                .pid = pid
            );
            drakvuf_get_module_base_addr_ctx(drakvuf, module_list, &ctx, "services.exe", &plugin->srv_module_base);
            PRINT_DEBUG("[DKOMMON] Found services.exe: 0x%lx\n", plugin->srv_module_base);
        }
        g_free(name);
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
    unicode_string_t* drvname = drakvuf_read_unicode_common(drakvuf, &ctx);
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
        .pid = 4
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

static event_response_t delete_service_return_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = get_trap_params<srv_result_t>(info);
    if (!params->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    auto plugin = get_trap_plugin<dkommon>(info);
    if (info->regs->rax == 0)
        plugin->loaded_services.erase(params->srv_record);
    plugin->destroy_trap(info->trap);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t delete_service_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = static_cast<dkommon*>(info->trap->data);
    auto srv_record = drakvuf_get_function_argument(drakvuf, info, 2);
    // In case of Windows 10 we have to make sure "remove" function returned 0.
    if (plugin->winver == win_10_1803_ver)
    {
        auto trap = plugin->register_trap<srv_result_t>(info, delete_service_return_cb, breakpoint_by_pid_searcher());
        auto params = get_trap_params<srv_result_t>(trap);
        params->set_result_call_params(info);
        params->srv_record = srv_record;
    }
    else
    {
        plugin->loaded_services.erase(srv_record);
    }
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t add_service_return_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = get_trap_params<srv_result_t>(info);
    if (!params->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    auto plugin = get_trap_plugin<dkommon>(info);
    vmi_lock_guard vmi(drakvuf);
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, params->srv_record, info->proc_data.pid, &params->srv_record))
        return VMI_EVENT_RESPONSE_NONE;


    if (info->regs->rax == 0)
        plugin->loaded_services.insert(params->srv_record);
    plugin->destroy_trap(info->trap);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t add_service_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = static_cast<dkommon*>(info->trap->data);
    addr_t srv_record;
    if (plugin->winver == win_7_sp1_ver)
    {
        auto srv_record_ptr = drakvuf_get_function_argument(drakvuf, info, 3);
        auto trap = plugin->register_trap<srv_result_t>(info, add_service_return_cb, breakpoint_by_pid_searcher());
        auto params = get_trap_params<srv_result_t>(trap);
        params->set_result_call_params(info);
        params->srv_record = srv_record_ptr;
    }
    else
    {
        srv_record = drakvuf_get_function_argument(drakvuf, info, 2);
        plugin->loaded_services.insert(srv_record);
    }
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

static inline bool is_matched(const uint8_t* memory, const std::vector<uint8_t>& signature)
{
    for (size_t i = 0; i < signature.size(); i++)
        if (signature[i] != 0x00 && memory[i] != signature[i])
            return false;
    return true;
}

bool dkommon::find_services_db(vmi_instance_t vmi)
{
    if (!srv_module_base)
        return false;

    // Locate pattern within first 3 pages.
    std::vector<void*> access_ptrs(3, nullptr);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = srv_pid,
        .addr = srv_module_base
    );

    if (VMI_SUCCESS != vmi_mmap_guest(vmi, &ctx, access_ptrs.size(), access_ptrs.data()))
        return false;

    const auto& signature = this->winver == win_7_sp1_ver ? win_7_srv_signature : win_10_srv_signature;
    std::vector<addr_t> hits;
    for (size_t n_page = 0; n_page < access_ptrs.size(); n_page++)
    {
        if (access_ptrs[n_page])
        {
            auto page = static_cast<const uint8_t*>(access_ptrs[n_page]);
            for (size_t i = 0; i < VMI_PS_4KB - signature.size(); i++)
            {
                // Save guest memory location
                if (is_matched(&page[i], signature))
                    hits.push_back(srv_module_base + VMI_PS_4KB * n_page + i);
            }
            munmap(access_ptrs[n_page], VMI_PS_4KB);
        }
    }
    // Make sure only 1 pattern is found.
    if (hits.size() != 1)
    {
        PRINT_DEBUG("[DKOMMON] Failed to match pattern: %zu\n", hits.size());
        return false;
    }

    uint32_t srv_db_offset = 0;
    if (VMI_SUCCESS != vmi_read_32_va(vmi, hits[0] + 3, srv_pid, &srv_db_offset))
        return false;
    PRINT_DEBUG("[DKOMMON] DB Offset: 0x%x\n", srv_db_offset);

    this->srv_db_va = srv_db_offset + hits[0] + 7;
    PRINT_DEBUG("[DKOMMON] DB VA: 0x%lx\n", srv_db_va);
    return true;
}

std::set<addr_t> dkommon::enumerate_services(vmi_instance_t vmi)
{
    std::set<addr_t> out;
    // Walk linked list of service records.
    if (srv_offsets.find(this->winver) == srv_offsets.end())
        return {};

    const auto [name_off, next_off] = srv_offsets.at(this->winver);
    addr_t srv_record;
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, srv_db_va, srv_pid, &srv_record))
        return {};
    while (true)
    {
        out.insert(srv_record);
        vmi_read_addr_va(vmi, srv_record + next_off, srv_pid, &srv_record);
        if (!srv_record)
            break;
    }
    return out;
}

dkommon::dkommon(drakvuf_t drakvuf, const dkommon_config* config, output_format_t output)
    : pluginex(drakvuf, output), format(output), offsets(new size_t[__OFFSET_MAX]), srv_pid(0), srv_module_base(0)
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

    auto hook_usermode = [&](vmi_instance_t vmi, addr_t hook_addr, drakvuf_trap_t* trap, hook_cb_t cb) -> bool
    {
        trap->cb = cb;
        trap->type = BREAKPOINT;
        trap->data = (void*)this;
        trap->breakpoint.lookup_type = LOOKUP_PID;
        trap->breakpoint.addr_type = ADDR_VA;
        trap->breakpoint.module = "services.exe";
        trap->breakpoint.pid = srv_pid;
        trap->breakpoint.addr = hook_addr;
        return drakvuf_add_trap(drakvuf, trap);
    };

    vmi_lock_guard vmi(drakvuf);
    this->winver = vmi_get_win_buildnumber(vmi);
    // Before we procced with hooks from json-profile, make sure we can locate services database.
    if (srv_pid && config->services_profile && drakvuf_get_address_width(drakvuf) == 8 && find_services_db(vmi))
    {
        // Only win7 sp1 x64 and win10 1803 x64 are supported
        if (this->winver == win_7_sp1_ver || this->winver == win_10_1803_ver)
        {
            auto profile_json = json_object_from_file(config->services_profile);
            if (profile_json)
            {
                addr_t fn_srv_add, fn_srv_del;
                if (this->winver == win_7_sp1_ver)
                {
                    if (!json_get_symbol_rva(drakvuf, profile_json, "?ScCreateServiceRecord@@YAKPEAGHPEAPEAU_SERVICE_RECORD@@@Z", &fn_srv_add) ||
                        !json_get_symbol_rva(drakvuf, profile_json, "?Add@DEFER_LIST@@QEAAXPEAU_SERVICE_RECORD@@@Z", &fn_srv_del))
                    {
                        PRINT_DEBUG("[DKOMMON] Failed to resolve symbols\n");
                        throw -1;
                    }
                }
                else
                {
                    if (!json_get_symbol_rva(drakvuf, profile_json, "?Add@CServiceDatabase@@QEAAKPEAVCServiceRecord@@@Z", &fn_srv_add) ||
                        !json_get_symbol_rva(drakvuf, profile_json, "?Remove@CServiceDatabase@@QEAAKPEAVCServiceRecord@@@Z", &fn_srv_del))
                    {
                        PRINT_DEBUG("[DKOMMON] Failed to resolve symbols\n");
                        throw -1;
                    }
                }
                json_object_put(profile_json);
                if (!hook_usermode(vmi, fn_srv_add + srv_module_base, &srv_trap[0], add_service_cb))
                {
                    PRINT_DEBUG("[DKOMMON] Failed to hook add_service fn\n");
                    return;
                }
                if (!hook_usermode(vmi, fn_srv_del + srv_module_base, &srv_trap[1], delete_service_cb))
                {
                    PRINT_DEBUG("[DKOMMON] Failed to hook delete_service fn\n");
                    drakvuf_remove_trap(drakvuf, &srv_trap[0], nullptr);
                    return;
                }
            }
        }
        loaded_services = enumerate_services(vmi);
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
        // Check hidden services
        //
        vmi_lock_guard vmi(drakvuf);
        if (!loaded_services.empty() && srv_offsets.find(this->winver) != srv_offsets.end())
        {
            auto temp_services = enumerate_services(vmi);
            auto [name_off, next_off] = srv_offsets.at(this->winver);
            for (auto srv : loaded_services)
            {
                if (temp_services.find(srv) == temp_services.end())
                {
                    // Get service name.
                    addr_t name_va;
                    if (VMI_SUCCESS != vmi_read_addr_va(vmi, srv + name_off, srv_pid, &name_va))
                        continue;
                    ACCESS_CONTEXT(ctx,
                        .translate_mechanism = VMI_TM_PROCESS_PID,
                        .pid = srv_pid,
                        .addr = name_va);
                    auto name = drakvuf_read_wchar_string(drakvuf, &ctx);
                    if (name)
                    {
                        print_driver_information(drakvuf, nullptr, this->format, "Hidden Service", (const char*)name->contents);
                        vmi_free_unicode_str(name);
                    }
                    else
                        print_driver_information(drakvuf, nullptr, this->format, "Hidden Service", "<Anonymous>");
                }
            }
        }
    }
    return pluginex::stop_impl();
}
