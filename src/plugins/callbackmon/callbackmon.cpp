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
#include <libdrakvuf/libdrakvuf.h>
#include <plugins/plugins_ex.h>
#include <plugins/output_format.h>
#include <mutex>

#include "callbackmon.h"
#include "private.h"

static constexpr uint16_t win_vista_ver     = 6000;
static constexpr uint16_t win_vista_sp1_ver = 6001;
static constexpr uint16_t win_7_sp1_ver     = 7601;
static constexpr uint16_t win_8_1_ver       = 9600;
static constexpr uint16_t win_10_rs1_ver    = 14393;
static constexpr uint16_t win_10_1803_ver   = 17134;

static const std::vector<const char*> callout_syms =
{
    "PspW32ProcessCallout",
    "PspW32ThreadCallout",
    "ExGlobalAtomTableCallout",
    "KeGdiFlushUserBatch",
    "PopEventCallout",
    "PopStateCallout",
    "PopWin32InfoCallout",
    "PspW32JobCallout",
    "ExDesktopOpenProcedureCallout",
    "ExDesktopOkToCloseProcedureCallout",
    "ExDesktopCloseProcedureCallout",
    "ExDesktopDeleteProcedureCallout",
    "ExWindowStationOkToCloseProcedureCallout",
    "ExWindowStationCloseProcedureCallout",
    "ExWindowStationDeleteProcedureCallout",
    "ExWindowStationParseProcedureCallout",
    "ExWindowStationOpenProcedureCallout",
    "ExLicensingWin32Callout"
};

// Map of Windows version -> [callout structure size, callout size offset, callout base offset]
static const std::unordered_map<uint16_t, std::tuple<size_t, size_t, size_t>> wfp_offsets =
{
    { win_7_sp1_ver, { 0x40, 0x548, 0x550 } },
    { win_10_1803_ver, { 0x50, 0x190, 0x198 } },
};

namespace
{
struct pass_ctx
{
    addr_t cb_va;
    std::string name = "<Unknown>";
    addr_t base_va = 0;
    callbackmon const* plugin;

    pass_ctx(callbackmon const* plugin, addr_t cb_va) : cb_va(cb_va), plugin{plugin}
    {
    }
};
}

static inline size_t get_process_cb_table_size(uint16_t winver)
{
    if (winver >= win_vista_sp1_ver)
        return 64;
    else if (winver == win_vista_ver)
        return 12;
    else
        return 8;
}

static inline size_t get_thread_cb_table_size(uint16_t winver)
{
    return (winver >= win_vista_ver ? 64 : 8);
}

static inline size_t get_image_cb_table_size(uint16_t winver)
{
    return (winver >= win_8_1_ver ? 64 : 8);
}

static inline size_t get_cb_table_size(vmi_instance_t vmi, const std::string& type)
{
    uint16_t winver = vmi_get_win_buildnumber(vmi);
    if (type == "image")
        return get_image_cb_table_size(winver);
    else if (type == "process")
        return get_process_cb_table_size(winver);
    else
        return get_thread_cb_table_size(winver);
}

static inline size_t get_power_cb_offset(vmi_instance_t vmi)
{
    uint16_t winver = vmi_get_win_buildnumber(vmi);

    if (winver >= win_10_rs1_ver)
        return vmi_get_address_width(vmi) == 8 ? 0x50 : 0x38;
    else
        return vmi_get_address_width(vmi) == 8 ? 0x40 : 0x28;
}

static void driver_visitor(drakvuf_t drakvuf, addr_t ldr_table, void* ctx)
{
    auto data = static_cast<pass_ctx*>(ctx);

    vmi_lock_guard vmi(drakvuf);
    addr_t base;
    uint32_t size;
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, ldr_table + data->plugin->ldr_data_base_rva, 4, &base) ||
        VMI_SUCCESS != vmi_read_32_va(vmi, ldr_table + data->plugin->ldr_data_size_rva, 4, &size))
    {
        PRINT_DEBUG("[CALLBACKMON] Can't read driver base and size for ldr_table %" PRIx64 "\n", ldr_table);
        return;
    }

    if (data->cb_va >= base && data->cb_va < base + size)
    {
        unicode_string_t* module_name = drakvuf_read_unicode_va(drakvuf, ldr_table + data->plugin->ldr_data_name_rva, 4);
        if (module_name && module_name->contents)
        {
            data->name.assign(reinterpret_cast<char*>(module_name->contents));
            vmi_free_unicode_str(module_name);
        }

        data->base_va = base;
    }
}

static inline std::pair<std::string, addr_t> get_module_by_addr(drakvuf_t drakvuf, callbackmon* plugin, addr_t addr)
{
    pass_ctx ctx{ plugin, addr };
    drakvuf_enumerate_drivers(drakvuf, driver_visitor, &ctx);
    return { ctx.name, ctx.base_va };
}

static protocol_cb_t collect_protocol_callbacks(drakvuf_t drakvuf, vmi_instance_t vmi, callbackmon* plugin, addr_t protocol_block)
{
    protocol_cb_t out;
    // Read first open block.
    //
    addr_t open_block{};
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, protocol_block + plugin->generic_offsets[NDIS_PROTOCOL_BLOCK_OPENQUEUE], 0, &open_block) || !open_block)
    {
        return out;
    }

    while (open_block)
    {
        // Read all callbacks.
        //
        std::vector<api_bind_t> callbacks;
        for (int i = 0; i < __OFFSET_OPEN_MAX; i++)
        {
            // We don't care about struct name so we use w7 by default.
            //
            const auto [_, cb_name] = offset_open_names_w7[i];
            addr_t cb;
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, open_block + plugin->open_offsets[i], 0, &cb))
            {
                PRINT_DEBUG("[CALLBACKMON] Failed to read api\n");
                throw -1;
            }
            callbacks.push_back(std::make_pair(cb_name, cb));
        }

        // Read corresponding miniport block.
        //
        addr_t miniport_block{};
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, open_block + plugin->generic_offsets[NDIS_OPEN_BLOCK_MINIPORTHANDLE], 0, &miniport_block) || !miniport_block)
        {
            PRINT_DEBUG("[CALLBACKMON] Failed to read miniport block!\n");
            throw -1;
        }

        for (int i = 0; i < __OFFSET_MINIPORT_MAX; i++)
        {
            const auto [_, cb_name] = offset_miniport_names[i];
            addr_t cb;
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, miniport_block + plugin->miniport_offsets[i], 0, &cb))
            {
                PRINT_DEBUG("[CALLBACKMON] Failed to read miniport api\n");
                throw -1;
            }
            callbacks.push_back(std::make_pair(cb_name, cb));
        }

        out.insert({ open_block, std::move(callbacks) });

        if (VMI_SUCCESS != vmi_read_addr_va(vmi, open_block + plugin->generic_offsets[NDIS_OPEN_BLOCK_PROTOCOLNEXTOPEN], 0, &open_block))
        {
            PRINT_DEBUG("[CALLBACKMON] Failed to read protocol next open\n");
            throw -1;
        }
    }
    return out;
}

static bool consume_ndis_protocols(drakvuf_t drakvuf, vmi_instance_t vmi, callbackmon* plugin, const char* profile)
{
    addr_t ndis_protocol_list_rva;

    const auto winver = vmi_get_winver(vmi);

    const char* protocol_symname  = winver == VMI_OS_WINDOWS_10 ? "?ndisProtocolList@@3PEAU_NDIS_PROTOCOL_BLOCK@@EA" : "ndisProtocolList";

    auto profile_json = json_object_from_file(profile);
    if (!profile_json)
    {
        PRINT_DEBUG("[CALLBACKMON] Failed to load profile\n");
        return false;
    }

    // Locate core symbols.
    //
    if (winver == VMI_OS_WINDOWS_10)
    {
        if (!json_get_struct_members_array_rva(drakvuf, profile_json, offset_generic_names_w10, __OFFSET_GENERIC_MAX, plugin->generic_offsets) ||
            !json_get_struct_members_array_rva(drakvuf, profile_json, offset_open_names_w10,    __OFFSET_OPEN_MAX,    plugin->open_offsets))
        {
            json_object_put(profile_json);
            return false;
        }
    }
    else
    {
        if (!json_get_struct_members_array_rva(drakvuf, profile_json, offset_generic_names_w7, __OFFSET_GENERIC_MAX, plugin->generic_offsets) ||
            !json_get_struct_members_array_rva(drakvuf, profile_json, offset_open_names_w7,    __OFFSET_OPEN_MAX,    plugin->open_offsets))
        {
            json_object_put(profile_json);
            return false;
        }
    }

    if (!json_get_struct_members_array_rva(drakvuf, profile_json, offset_miniport_names, __OFFSET_MINIPORT_MAX, plugin->miniport_offsets) ||
        !json_get_symbol_rva(drakvuf, profile_json, protocol_symname, &ndis_protocol_list_rva))
    {
        json_object_put(profile_json);
        return false;
    }
    json_object_put(profile_json);
    // Read global values.
    //
    addr_t list_head, ndis_base, protocol_head;
    if (VMI_SUCCESS != vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &list_head)  ||
        !drakvuf_get_module_base_addr(drakvuf, list_head, "NDIS.SYS", &ndis_base) ||
        VMI_SUCCESS != vmi_read_addr_va(vmi, ndis_base + ndis_protocol_list_rva, 0, &protocol_head))
    {
        return false;
    }
    // Iterate all installed protocols.
    //
    while (protocol_head)
    {
        plugin->ndis_protocol_cb.insert({ protocol_head, collect_protocol_callbacks(drakvuf, vmi, plugin, protocol_head) });
        // Read next protocol address.
        //
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, protocol_head + plugin->generic_offsets[NDIS_PROTOCOL_BLOCK_NEXTPROTOCOL], 0, &protocol_head))
        {
            PRINT_DEBUG("[CALLBACKMON] Failed to read next protocol\n");
            throw -1;
        }
    }
    return true;
}

void callbackmon::report(drakvuf_t drakvuf, const char* list_name, addr_t addr, const char* action)
{
    const auto& [name, base] = get_module_by_addr(drakvuf, this, addr);
    fmt::print(format, "callbackmon", drakvuf, nullptr,
        keyval("Type", fmt::Qstr("Callback")),
        keyval("ListName", fmt::Qstr(list_name)),
        keyval("Module", fmt::Qstr(name)),
        keyval("RVA", fmt::Xval(base ? addr - base : 0)),
        keyval("Action", fmt::Qstr(action))
    );
}

callbackmon::callbackmon(drakvuf_t drakvuf, const callbackmon_config* config, output_format_t output)
    : pluginex(drakvuf, output), config{ *config }, format{ output },
      generic_offsets(new size_t[__OFFSET_GENERIC_MAX]),
      open_offsets(new size_t[__OFFSET_OPEN_MAX]),
      miniport_offsets(new size_t[__OFFSET_MINIPORT_MAX])
{
    const addr_t krnl_base = drakvuf_get_kernel_base(drakvuf);
    const size_t ptrsize   = drakvuf_get_address_width(drakvuf);
    const size_t fast_ref  = (ptrsize == 8 ? 15 : 7);
    addr_t drv_obj_rva, mj_array_rva;
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_DEVICE_OBJECT", "DriverObject",       &drv_obj_rva)       ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "_DRIVER_OBJECT", "MajorFunction",      &mj_array_rva)      ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "_LDR_DATA_TABLE_ENTRY", "FullDllName", &ldr_data_name_rva) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "_LDR_DATA_TABLE_ENTRY", "DllBase",     &ldr_data_base_rva) ||
        !drakvuf_get_kernel_struct_member_rva(drakvuf, "_LDR_DATA_TABLE_ENTRY", "SizeOfImage", &ldr_data_size_rva))
    {
        throw -1;
    }

    vmi_lock_guard vmi(drakvuf);
    const uint16_t ver = vmi_get_win_buildnumber(vmi);

    auto get_ksymbol_va = [&](const char* symb) -> addr_t
    {
        addr_t rva = 0;
        if (!drakvuf_get_kernel_symbol_rva(drakvuf, symb, &rva))
            throw -1;
        return rva + krnl_base;
    };
    // Linked list based callbacks
    auto consume_callbacks = [&](const char* symb, const int64_t cb_off) -> std::vector<addr_t>
    {
        std::vector<addr_t> out;
        addr_t head = get_ksymbol_va(symb);
        addr_t entry = 0;
        // Read flink entry
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, head, 4, &entry))
            throw -1;
        while (entry != head && entry)
        {
            addr_t callback = 0;
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, entry + cb_off, 4, &callback) ||
                VMI_SUCCESS != vmi_read_addr_va(vmi, entry, 4, &entry))
                throw -1;
            if (callback) out.push_back(callback);
        }
        return out;
    };
    // Array based callbacks
    auto consume_callbacks_ex = [&](const char* symb, const size_t count) -> std::vector<addr_t>
    {
        std::vector<addr_t> out;
        addr_t cb_base = get_ksymbol_va(symb);

        for (size_t i = 0; i < count; i++)
        {
            addr_t entry = 0, callback = 0;
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, cb_base + i * ptrsize, 4, &entry))
                throw -1;

            // Strip ref count
            entry &= ~fast_ref;
            if (!entry)
                continue;

            if (VMI_SUCCESS != vmi_read_addr_va(vmi, entry + ptrsize, 4, &callback))
                throw -1;
            out.push_back(callback);
        }
        return out;
    };
    // Extract IRP_MJ_SHUTDOWN from device objects
    auto extract_cb = [&](std::vector<addr_t> dev_objs) -> std::vector<addr_t>
    {
        constexpr size_t irp_mj_shutdown = 0x10;
        for (auto& dev_obj : dev_objs)
        {
            addr_t drv_obj = 0;
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, dev_obj + drv_obj_rva, 4, &drv_obj) ||
                VMI_SUCCESS != vmi_read_addr_va(vmi, drv_obj + mj_array_rva + irp_mj_shutdown * ptrsize, 4, &dev_obj))
                throw -1;
        }
        return dev_objs;
    };
    // Extract PsWin32Callouts
    auto consume_w32callouts = [&]() -> std::vector<addr_t>
    {
        std::vector<addr_t> out;
        if (vmi_get_win_buildnumber(vmi) < win_8_1_ver)
        {
            for (const auto& sym : callout_syms)
            {
                addr_t fn = 0;
                if (VMI_SUCCESS != vmi_read_addr_va(vmi, get_ksymbol_va(sym), 4, &fn))
                    throw -1;
                out.push_back(fn);
            }
        }
        else
        {
            addr_t cb_block, fn;
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, get_ksymbol_va("PsWin32CallBack"), 4, &cb_block))
                throw -1;
            // Strip ref count
            cb_block &= ~fast_ref;
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, cb_block + ptrsize, 4, &fn))
                throw -1;
            out.push_back(fn);
        }
        return out;
    };
    // Extract Wfp Callouts
    auto consume_wfpcallouts = [&](const char* profile) -> std::vector<addr_t>
    {
        std::vector<addr_t> out;
        // only Windows 7 sp1 x64 and Windows 10 1803 x64 currently supported
        if (wfp_offsets.find(ver) == wfp_offsets.end() || !profile)
            return {};
        // Get gWfpGlobal RVA
        auto profile_json = json_object_from_file(profile);
        if (!profile_json)
            throw -1;

        addr_t gwfp_rva;
        json_get_symbol_rva(drakvuf, profile_json, "gWfpGlobal", &gwfp_rva);
        json_object_put(profile_json);

        addr_t list_head;
        if (VMI_SUCCESS != vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &list_head))
            throw -1;
        addr_t netio_base;
        if (!drakvuf_get_module_base_addr(drakvuf, list_head, "netio.sys", &netio_base))
            throw -1;
        addr_t gwfp;
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, netio_base + gwfp_rva, 4, &gwfp))
            throw -1;

        const auto& [callout_size, size_off, callout_off] = wfp_offsets.at(ver);
        addr_t callout_base, callout_count;
        // Read callout count and callout base address
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, gwfp + size_off, 4, &callout_count) ||
            VMI_SUCCESS != vmi_read_addr_va(vmi, gwfp + callout_off, 4, &callout_base))
            throw -1;

        for (addr_t callout = callout_base; callout < callout_base + callout_count* callout_size; callout += callout_size)
        {
            addr_t cb1 = 0, cb2 = 0;
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, callout + 2 * ptrsize, 4, &cb1) ||
                VMI_SUCCESS != vmi_read_addr_va(vmi, callout + 2 * ptrsize + ptrsize, 4, &cb2))
                throw -1;

            if (cb1) out.push_back(cb1);
            if (cb2) out.push_back(cb2);
        }
        return out;
    };

    if (config->ndis_profile && (ver == win_7_sp1_ver || ver == win_10_1803_ver))
    {
        if (!consume_ndis_protocols(drakvuf, vmi, this, config->ndis_profile))
        {
            PRINT_DEBUG("[CALLBACKMON] Failed to process ndis callbacks\n");
            throw -1;
        }
    }
    this->process_cb   = consume_callbacks_ex("PspCreateProcessNotifyRoutine", get_cb_table_size(vmi, "process"));
    this->thread_cb    = consume_callbacks_ex("PspCreateThreadNotifyRoutine",  get_cb_table_size(vmi, "thread"));
    this->image_cb     = consume_callbacks_ex("PspLoadImageNotifyRoutine",     get_cb_table_size(vmi, "image"));
    this->bugcheck_cb  = consume_callbacks("KeBugCheckCallbackListHead", 2 * ptrsize);
    this->bcreason_cb  = consume_callbacks("KeBugCheckReasonCallbackListHead", 2 * ptrsize);
    this->registry_cb  = consume_callbacks("CallbackListHead", 5 * ptrsize);
    this->logon_cb     = consume_callbacks("SeFileSystemNotifyRoutinesHead", 1 * ptrsize);
    this->power_cb     = consume_callbacks("PopRegisteredPowerSettingCallbacks", get_power_cb_offset(vmi));
    this->shtdwn_cb    = extract_cb(consume_callbacks("IopNotifyShutdownQueueHead", 2 * ptrsize));
    this->shtdwn_lst_cb= extract_cb(consume_callbacks("IopNotifyLastChanceShutdownQueueHead", 2 * ptrsize));
    this->dbgprint_cb  = consume_callbacks("RtlpDebugPrintCallbackList", -2 * ptrsize);
    this->fschange_cb  = consume_callbacks("IopFsNotifyChangeQueueHead", 3 * ptrsize);
    this->drvreinit_cb = consume_callbacks("IopDriverReinitializeQueueHead", 3 * ptrsize);
    this->drvreinit2_cb= consume_callbacks("IopBootDriverReinitializeQueueHead", 3 * ptrsize);
    this->nmi_cb       = consume_callbacks("KiNmiCallbackListHead", 1 * ptrsize);
    this->priority_cb  = consume_callbacks_ex("IopUpdatePriorityCallbackRoutine", 8);
    this->pnp_prof_cb  = consume_callbacks("PnpProfileNotifyList", 4 * ptrsize);
    this->pnp_class_cb = consume_callbacks("PnpDeviceClassNotifyList", 5 * ptrsize);
    this->emp_cb       = consume_callbacks("EmpCallbackListHead", -3 * ptrsize);
    this->w32callouts  = consume_w32callouts();
    this->wfpcallouts  = consume_wfpcallouts(this->config.netio_profile);
}

bool callbackmon::stop_impl()
{
    std::unique_ptr<callbackmon> snapshot;
    try
    {
        snapshot = std::make_unique<callbackmon>(drakvuf, &config, format);
    }
    catch (const std::exception& e)
    {
        PRINT_DEBUG("[CALLBACKMON] Failed to perform final analsys. err: %s\n", e.what());
        return true;
    }

    uint16_t winver;
    {
        vmi_lock_guard vmi(drakvuf);
        winver = vmi_get_win_buildnumber(vmi);
    }

    auto check_callbacks = [&](const auto& previous, const auto& current, const auto& list_name)
    {
        auto walk_list = [&](const auto& previous, const auto& current, const auto& action)
        {
            for (const auto& cb : current)
                if (std::find(previous.begin(), previous.end(), cb) == previous.end())
                    report(drakvuf, list_name, cb, action);
        };
        walk_list(previous, current, "Added");
        walk_list(current, previous, "Removed");
    };

    auto check_callouts = [&](const auto& previous, const auto& current)
    {
        if (winver < win_8_1_ver)
        {
            for (size_t i = 0; i < callout_syms.size(); i++)
                if (previous[i] != current[i])
                    report(drakvuf, callout_syms[i], current[i], "Replaced");
        }
        else
        {
            if (previous[0] != current[0])
                report(drakvuf, "PsWin32CallBack", current[0], "Replaced");
        }
    };

    auto check_ndis_cbs = [&](const auto& previous, const auto& current)
    {
        for (const auto& [prot_addr, callbacks] : previous)
        {
            if (current.find(prot_addr) == current.end())
                continue;

            const auto& curr_prot = current.at(prot_addr);

            for (const auto& [openblk, cbs] : callbacks)
            {
                if (curr_prot.find(openblk) == curr_prot.end())
                    continue;

                const auto& curr_openblk = curr_prot.at(openblk);

                for (const auto& cb : cbs)
                {
                    if (std::find(curr_openblk.begin(), curr_openblk.end(), cb) == curr_openblk.end())
                        report(drakvuf, cb.first, cb.second, "Modified");
                }
            }
        }
    };

    check_callbacks(this->process_cb,   snapshot->process_cb,    "ProcessNotify");
    check_callbacks(this->thread_cb,    snapshot->thread_cb,     "ThreadNotify");
    check_callbacks(this->image_cb,     snapshot->image_cb,      "ImageNotify");
    check_callbacks(this->bugcheck_cb,  snapshot->bugcheck_cb,   "BugCheck");
    check_callbacks(this->bcreason_cb,  snapshot->bcreason_cb,   "BugCheckReason");
    check_callbacks(this->registry_cb,  snapshot->registry_cb,   "Registry");
    check_callbacks(this->logon_cb,     snapshot->logon_cb,      "LogonSession");
    check_callbacks(this->power_cb,     snapshot->power_cb,      "PowerSettings");
    check_callbacks(this->shtdwn_cb,    snapshot->shtdwn_cb,     "Shutdown");
    check_callbacks(this->shtdwn_lst_cb, snapshot->shtdwn_lst_cb, "ShutdownLast");
    check_callbacks(this->dbgprint_cb,  snapshot->dbgprint_cb,   "DbgPrint");
    check_callbacks(this->fschange_cb,  snapshot->fschange_cb,   "FsChange");
    check_callbacks(this->drvreinit_cb, snapshot->drvreinit_cb,  "DriverReinit");
    check_callbacks(this->drvreinit2_cb, snapshot->drvreinit2_cb, "DriverReinitBoot");
    check_callbacks(this->nmi_cb,       snapshot->nmi_cb,        "NMI");
    check_callbacks(this->priority_cb,  snapshot->priority_cb,   "UpdatePriority");
    check_callbacks(this->pnp_prof_cb,  snapshot->pnp_prof_cb,   "PnPProfile");
    check_callbacks(this->pnp_class_cb, snapshot->pnp_class_cb,  "PnPClass");
    check_callbacks(this->emp_cb,       snapshot->emp_cb,        "EMP");
    check_callbacks(this->wfpcallouts,  snapshot->wfpcallouts,   "WfpCallouts");
    check_callouts (this->w32callouts,  snapshot->w32callouts);
    check_ndis_cbs (this->ndis_protocol_cb, snapshot->ndis_protocol_cb);

    return true;
}

callbackmon::~callbackmon()
{
    delete[] generic_offsets;
    delete[] open_offsets;
    delete[] miniport_offsets;
}
