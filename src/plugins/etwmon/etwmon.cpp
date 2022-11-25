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
#include <libdrakvuf/libdrakvuf.h>
#include <plugins/plugins_ex.h>
#include <plugins/output_format.h>
#include <algorithm>

#include "etwmon.h"
#include "private.h"

using namespace etwmon_ns;

static constexpr auto logger_count     = 0x40;
static constexpr auto hashbucket_count = 0x40;
static constexpr auto wmi_logger_off   = 0x10;

static const std::vector<const char*> win10_global_handles =
{
    "EtwpEventTracingProvRegHandle",
    "EtwKernelProvRegHandle",
    "EtwpPsProvRegHandle",
    "EtwpNetProvRegHandle",
    "EtwpFileProvRegHandle",
    "EtwpRegTraceHandle",
    "EtwpMemoryProvRegHandle",
    "EtwAppCompatProvRegHandle",
    "EtwApiCallsProvRegHandle",
    "EtwCVEAuditProvRegHandle",
    "EtwThreatIntProvRegHandle",
    "EtwLpacProvRegHandle",
    "EtwAdminlessProvRegHandle",
    "EtwSecurityMitigationsRegHandle",
    "KiIntSteerEtwHandle",
    "HvlGlobalSystemEventsHandle",
    "PopDiagSleepStudyHandle",
    "WdipSemRegHandle",
    "IoTraceHandle",
    "IoMgrTraceHandle",
    "KitEtwHandle",
    "IopLiveDumpEtwRegHandle",
    "KseEtwHandle",
    "PopDiagHandle",
    "PopTriggerDiagHandle",
    "PpmEtwHandle",
    "PopBatteryEtwHandle",
    "PerfDiagGlobals",
};

static const std::vector<const char*> win7_global_handles =
{
    "EtwKernelProvRegHandle",
    "EtwPsProvRegHandle",
    "EtwNetProvRegHandle",
    "EtwDiskProvRegHandle",
    "EtwFileProvRegHandle",
    "EtwMemoryProvRegHandle",
    "g_EtwHandle",
    "g_AeLupSvcTriggerHandle",
    "TmpEtwHandle",
    "TmpTriggerHandle",
    "EtwpRegTraceHandle",
    "WdipSemRegHandle",
    "PpmEtwHandle",
    "PnpEtwHandle",
    "PopDiagHandle",
    "WheapEtwHandle",
    "PerfDiagGlobals",
};

static const std::vector<std::pair<const char*, size_t>> win7_global_callbacks =
{
    { "EtwpDiskIoNotifyRoutines",    4 },
    { "RtlpSafeMachineFrameEntries", 8 },
    { "EtwpFileIoNotifyRoutines",    4 },
    { "EtwpSplitIoNotifyRoutines",   1 },
};

static const std::vector<std::pair<const char*, size_t>> win10_global_callbacks =
{
    { "EtwpDiskIoNotifyRoutines", 2 },
    { "EtwpFileIoNotifyRoutines", 6 },
};

wmi_logger_t::wmi_logger_t(etwmon* plugin, vmi_instance_t vmi, addr_t base) : base(base), cb_ctx(0)
{
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, base + plugin->offsets[WMI_LOGGER_CONTEXT_GETCPUCLOCK], 0, &this->clock_fn))
    {
        PRINT_DEBUG("[ETWMON] Failed to read _WMI_LOGGER_CONTEXT!GetCpuClock\n");
        throw -1;
    }

    if (plugin->logger_cb_ctx_rva)
    {
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, base + plugin->logger_cb_ctx_rva, 0, &this->cb_ctx))
        {
            PRINT_DEBUG("[ETWMON] Failed to read _WMI_LOGGER_CONTEXT!CallbackContext\n");
            throw -1;
        }
    }

    this->name.assign("Unknown");
    auto unicode_name = drakvuf_read_unicode_va(plugin->drakvuf, base + plugin->offsets[WMI_LOGGER_CONTEXT_LOGGERNAME], 0);
    if (unicode_name && unicode_name->contents)
    {
        this->name.assign(reinterpret_cast<const char*>(unicode_name->contents));
        vmi_free_unicode_str(unicode_name);
    }
}

provider_t::provider_t(etwmon* plugin, vmi_instance_t vmi, addr_t base) : base(base)
{
    // Read provider guid.
    //
    if (VMI_SUCCESS != vmi_read_va(vmi, base + plugin->offsets[ETW_GUID_ENTRY_GUID], 0, sizeof(guid_t), &this->guid, nullptr))
    {
        PRINT_DEBUG("[ETWMON] Failed to read provider guid 0x%lx\n", base);
        throw -1;
    }

    if (VMI_SUCCESS != vmi_read_va(vmi, base + plugin->offsets[ETW_GUID_ENTRY_PROVENABLEINFO], 0, sizeof(enable_info), &this->enable_info, nullptr))
    {
        PRINT_DEBUG("[ETWMON] Failed to read provider enable info 0x%lx\n", base);
        throw -1;
    }

    addr_t entry{};
    addr_t reglisthead = base + plugin->offsets[ETW_GUID_ENTRY_REGLISTHEAD];
    // Collect _ETW_REG_ENTRY callbacks.
    //
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, reglisthead, 0, &entry))
    {
        PRINT_DEBUG("[ETWMON] Failed to read first element of _ETW_GUID_ENTRY!RegListHead 0x%lx\n", reglisthead);
        throw -1;
    }

    while (entry != reglisthead && entry && reglisthead)
    {
        addr_t cb{}, process{};

        if (VMI_SUCCESS != vmi_read_addr_va(vmi, entry + plugin->offsets[ETW_REG_ENTRY_PROCESS], 0, &process))
        {
            PRINT_DEBUG("[ETWMON] Failed to read _ETW_REG_ENTRY!Process 0x%lx\n", entry);
        }

        if (VMI_SUCCESS == vmi_read_addr_va(vmi, entry + plugin->offsets[ETW_REG_ENTRY_CALLBACK], 0, &cb) && cb && cb != ~0ull)
        {
            regs.push_back({ entry, process, cb });
        }
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, entry, 0, &entry))
        {
            PRINT_DEBUG("[ETWMON] Failed to read next entry 0x%lx\n", entry);
            break;
        }
    }
}

void etwmon::report(drakvuf_t drakvuf, const char* type, const char* name, const char* action)
{
    fmt::print(format, "etwmon", drakvuf, nullptr,
        keyval("Type",   fmt::Qstr(type)),
        keyval("Name",   fmt::Estr(name)),
        keyval("Action", fmt::Qstr(action))
    );
}

void etwmon::enumerate_loggers(vmi_instance_t vmi)
{
    addr_t logger_array{};
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, this->etw_debugger_data_va + wmi_logger_off, 0, &logger_array))
    {
        PRINT_DEBUG("[ETWMON] Failed to read global _WMI_LOGGER_CONTEXT pointer\n");
        return;
    }

    for (unsigned i = 0; i < logger_count; i++)
    {
        addr_t logger{}, logger_ptr = logger_array + i * this->address_width;
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, logger_ptr, 0, &logger))
        {
            PRINT_DEBUG("[ETWMON] Failed to read logger %d 0x%lx\n", i, logger_ptr);
            break;
        }
        // 0: kd> dq fffff800`02a6c060 L4
        // fffff800`02a6c060  00000000`00000001 00000000`00000001
        // fffff800`02a6c070  fffffa80`62cf07c0 fffffa80`611443c0
        if (logger > 1)
        {
            loggers.push_back(wmi_logger_t(this, vmi, logger));
        }
    }
}

void etwmon::enumerate_providers(vmi_instance_t vmi)
{
    // Get provider from PspHostSiloGlobals struct. Providers are stored in hash table in EtwSiloState structure.
    //
    if (this->winver.version != VMI_OS_WINDOWS_7)
    {
        addr_t etw_state{};

        if (VMI_SUCCESS != vmi_read_addr_va(vmi, this->silo_globals_va + this->etw_state_rva, 0, &etw_state))
        {
            PRINT_DEBUG("[ETWMON] Failed to read _ESERVERSILO_GLOBALS!EtwSiloState 0x%lx\n", this->silo_globals_va);
            return;
        }

        if (VMI_SUCCESS != vmi_read_32_va(vmi, etw_state + this->logger_settings_rva + this->active_loggers_rva, 0, &this->active_system_loggers))
        {
            PRINT_DEBUG("[ETWMON] Failed to read _ETW_SILODRIVERSTATE!SystemLoggerSettings\n");
        }

        // Iterate hash table.
        //
        for (int i = 0; i < hashbucket_count; i++)
        {
            // struct _ETW_HASH_BUCKET
            // {
            //     struct _LIST_ENTRY ListHead[3];
            //     struct _EX_PUSH_LOCK BucketLock;
            // };
            for (int j = 0; j < 3; j++)
            {
                addr_t entry{};

                addr_t head = etw_state + this->hash_table_rva + i * this->bucket_size + j * this->list_entry_size;

                if (VMI_SUCCESS != vmi_read_addr_va(vmi, head, 0, &entry))
                {
                    PRINT_DEBUG("[ETWMON] Failed to read bucket entry 0x%lx\n", head);
                    return;
                }

                while (entry != head && entry && head)
                {
                    providers.push_back(provider_t(this, vmi, entry));

                    if (VMI_SUCCESS != vmi_read_addr_va(vmi, entry, 0, &entry))
                    {
                        PRINT_DEBUG("[ETWMON] Failed to read next flink address 0x%lx\n", entry);
                        break;
                    }
                }
            }
        }
    }
    // On windows 7 providers stored in global variable EtwpGuidListHead.
    //
    else
    {
        addr_t entry{};

        if (VMI_SUCCESS != vmi_read_addr_va(vmi, this->guid_list_head_va, 0, &entry))
        {
            PRINT_DEBUG("[ETWMON] Failed to read first element of EtwpGuidListHead 0x%lx\n", this->guid_list_head_va);
            return;
        }

        while (entry != this->guid_list_head_va && entry)
        {
            providers.push_back(provider_t(this, vmi, entry));

            if (VMI_SUCCESS != vmi_read_addr_va(vmi, entry, 0, &entry))
            {
                PRINT_DEBUG("[ETWMON] Failed to read next entry 0x%lx\n", entry);
                break;
            }
        }
    }
}

void etwmon::enumerate_callbacks(vmi_instance_t vmi)
{
    for (const auto callback_va : global_callbacks_va)
    {
        addr_t value{};
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, callback_va, 0, &value))
        {
            PRINT_DEBUG("[ETWMON] Failed to read callback 0x%lx\n", callback_va);
        }
        global_callbacks.push_back(value);
    }
}

void etwmon::enumerate_handles(vmi_instance_t vmi)
{
    for (const auto handle_va : global_handles_va)
    {
        addr_t value{};
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, handle_va, 0, &value))
        {
            PRINT_DEBUG("[ETWMON] Failed to read handle 0x%lx\n", handle_va);
        }
        global_handles.push_back(value);
    }
}

etwmon::etwmon(const etwmon& other) : pluginex(other.drakvuf, other.format)
{
    this->format                = other.format;
    this->winver                = other.winver;
    this->address_width         = other.address_width;
    this->offsets               = other.offsets;
    this->logger_cb_ctx_rva     = other.logger_cb_ctx_rva;
    this->etw_state_rva         = other.etw_state_rva;
    this->hash_table_rva        = other.hash_table_rva;
    this->logger_settings_rva   = other.logger_settings_rva;
    this->active_loggers_rva    = other.active_loggers_rva;
    this->silo_globals_va       = other.silo_globals_va;
    this->bucket_size           = other.bucket_size;
    this->list_entry_size       = other.list_entry_size;
    this->guid_list_head_va     = other.guid_list_head_va;
    this->etw_debugger_data_va  = other.etw_debugger_data_va;
    this->active_system_loggers = other.active_system_loggers;
    this->global_handles_va     = other.global_handles_va;
    this->global_callbacks_va   = other.global_callbacks_va;
}

bool etwmon::is_supported(drakvuf_t drakvuf, bool quite = false)
{
    if (this->address_width != 8)
    {
        if (!quite)
            PRINT_DEBUG("[ETWMON] x86 is not supported\n");
        return false;
    }
    if (this->winver.version == VMI_OS_WINDOWS_7)
        return true;
    if (this->winver.version == VMI_OS_WINDOWS_10 && this->winver.buildnumber > 14393)
        return true;

    if (!quite)
        PRINT_DEBUG("[ETWMON] plugin supports only Windows 7 and Windows 10 (>1607)\n");
    return false;
}

etwmon::etwmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output), format{ output },
      logger_cb_ctx_rva{}, etw_state_rva{}, hash_table_rva{},
      logger_settings_rva{}, active_loggers_rva{}, silo_globals_va{},
      bucket_size{}, list_entry_size{}, guid_list_head_va{},
      etw_debugger_data_va{}, active_system_loggers{}
{
    this->address_width = drakvuf_get_address_width(drakvuf);

    vmi_lock_guard vmi(drakvuf);
    if (!vmi_get_windows_build_info(vmi, &this->winver))
    {
        PRINT_DEBUG("[ETWMON] Failed to get windows build info\n");
        throw -1;
    }

    if (!is_supported(drakvuf))
        return;

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, this->offsets.size(), this->offsets.data()))
    {
        PRINT_DEBUG("[ETWMON] Failed to get kernel struct member offsets\n");
        throw -1;
    }

    if (this->winver.version != VMI_OS_WINDOWS_7)
    {
        if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_ESERVERSILO_GLOBALS", "EtwSiloState", &this->etw_state_rva) ||
            !drakvuf_get_kernel_struct_member_rva(drakvuf, "_ETW_SILODRIVERSTATE", "EtwpGuidHashTable", &this->hash_table_rva) ||
            !drakvuf_get_kernel_struct_member_rva(drakvuf, "_ETW_SILODRIVERSTATE", "SystemLoggerSettings", &this->logger_settings_rva) ||
            !drakvuf_get_kernel_struct_member_rva(drakvuf, "_ETW_SYSTEM_LOGGER_SETTINGS", "EtwpActiveSystemLoggers", &this->active_loggers_rva))
        {
            PRINT_DEBUG("[ETWMON] Failed to resolve win10 etw struct rva\n");
            throw -1;
        }

        if (!drakvuf_get_kernel_symbol_va(drakvuf, "PspHostSiloGlobals", &this->silo_globals_va))
        {
            PRINT_DEBUG("[ETWMON] Failed to read PspHostSiloGlobals va\n");
            throw -1;
        }

        if (!drakvuf_get_kernel_struct_size(drakvuf, "_ETW_HASH_BUCKET", &this->bucket_size) ||
            !drakvuf_get_kernel_struct_size(drakvuf, "_LIST_ENTRY", &this->list_entry_size))
        {
            PRINT_DEBUG("[ETWMON] Failed to get _ETW_HASH_BUCKET || _LIST_ENTRY size\n");
            throw -1;
        }
        // This field is only present on most resent windows 10 versions so we continue if its not found.
        //
        if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_WMI_LOGGER_CONTEXT", "CallbackContext", &this->logger_cb_ctx_rva))
        {
            PRINT_DEBUG("[ETWMON] Failed to read _WMI_LOGGER_CONTEXT!CallbackContext rva\n");
        }
    }
    else
    {
        if (!drakvuf_get_kernel_symbol_va(drakvuf, "EtwpGuidListHead", &this->guid_list_head_va))
        {
            PRINT_DEBUG("[ETWMON] Failed to read EtwpGuidListHead\n");
            throw -1;
        }
    }

    if (!drakvuf_get_kernel_symbol_va(drakvuf, "EtwpDebuggerData", &this->etw_debugger_data_va))
    {
        PRINT_DEBUG("[ETWMON] Failed to read EtwpDebuggerData va\n");
        throw -1;
    }

    this->enumerate_loggers(vmi);
    this->enumerate_providers(vmi);

    const std::vector<const char*>*                    handles_names   = nullptr;
    const std::vector<std::pair<const char*, size_t>>* callbacks_names = nullptr;

    switch (this->winver.version)
    {
        case VMI_OS_WINDOWS_7:
            handles_names   = &win7_global_handles;
            callbacks_names = &win7_global_callbacks;
            break;
        case VMI_OS_WINDOWS_10:
            handles_names   = &win10_global_handles;
            callbacks_names = &win10_global_callbacks;
            break;
        default:
            break;
    }

    if (handles_names)
    {
        for (const auto& name : *handles_names)
        {
            addr_t entry{};
            if (!drakvuf_get_kernel_symbol_va(drakvuf, name, &entry))
            {
                PRINT_DEBUG("[ETWMON] Failed to resolve %s\n", name);
                throw -1;
            }
            this->global_handles_va.push_back(entry);
        }
    }

    if (callbacks_names)
    {
        for (const auto& [name, size] : *callbacks_names)
        {
            addr_t entry{};
            if (!drakvuf_get_kernel_symbol_va(drakvuf, name, &entry))
            {
                PRINT_DEBUG("[ETWMON] Failed to resolve %s\n", name);
                throw -1;
            }
            for (size_t i = 0; i < size; i++)
            {
                this->global_callbacks_va.push_back(entry + i * this->address_width);
            }
        }
    }

    this->enumerate_handles(vmi);
    this->enumerate_callbacks(vmi);
}

bool etwmon::stop_impl()
{
    if (!is_supported(drakvuf, true))
        return true;

    try
    {
        vmi_lock_guard vmi(drakvuf);
        auto snapshot = std::make_unique<etwmon>(*this);
        snapshot->enumerate_loggers(vmi);
        snapshot->enumerate_providers(vmi);
        snapshot->enumerate_handles(vmi);
        snapshot->enumerate_callbacks(vmi);

        for (const auto& logger : this->loggers)
        {
            auto n_logger = std::find_if(snapshot->loggers.begin(), snapshot->loggers.end(), [base=logger.base](const auto& l)
            {
                return l.base == base;
            });
            if (n_logger != snapshot->loggers.end())
            {
                if (logger.clock_fn != n_logger->clock_fn)
                {
                    report(drakvuf, "GetCpuClock", n_logger->name.c_str(), "Modified");
                }
                else if (logger.cb_ctx == n_logger->cb_ctx)
                {
                    report(drakvuf, "CallbackContext", n_logger->name.c_str(), "Modified");
                }
            }
        }

        for (const auto& provider : this->providers)
        {
            auto n_provider = std::find_if(snapshot->providers.begin(), snapshot->providers.end(), [base=provider.base](const auto& p)
            {
                return p.base == base;
            });
            if (n_provider != snapshot->providers.end())
            {
                for (unsigned i = 0; i < sizeof(provider.enable_info) / sizeof(provider.enable_info[0]); i++)
                {
                    if ((provider.enable_info[i].enabled != n_provider->enable_info[i].enabled) ||
                        (provider.enable_info[i].level   != n_provider->enable_info[i].level))
                    {
                        report(drakvuf, "Provider", provider.guid.str().c_str(), "Modified");
                    }
                }

                for (const auto reg : provider.regs)
                {
                    auto n_reg = std::find_if(n_provider->regs.begin(), n_provider->regs.end(), [&](const reg_entry_t& r)
                    {
                        return r.base == reg.base;
                    });
                    if (n_reg != n_provider->regs.end())
                    {
                        if (n_reg->callback != reg.callback)
                            report(drakvuf, "RegCallback", provider.guid.str().c_str(), "Modified");
                    }
                }
            }
        }

        for (size_t i = 0; i < this->global_callbacks.size(); i++)
        {
            if (this->global_callbacks.at(i) != snapshot->global_callbacks.at(i))
                report(drakvuf, "GlobalCallback", "Anonymous", "Modified");
        }

        for (size_t i = 0; i < this->global_callbacks.size(); i++)
        {
            if (this->global_handles.at(i) != snapshot->global_handles.at(i))
                report(drakvuf, "GlobalHandle", "Anonymous", "Modified");
        }

        if (this->active_system_loggers != snapshot->active_system_loggers)
            report(drakvuf, "SystemLoggerSettings", "ActiveSystemLoggers", "Modified");
    }
    catch (const std::exception& e)
    {
        PRINT_DEBUG("[ETWMON] Failed to perform final analysis. err: %s\n", e.what());
    }
    return true;
}
