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
#include <libdrakvuf/libdrakvuf.h>
#include <libdrakvuf/win.h>
#include <plugins/plugins_ex.h>
#include <plugins/output_format.h>
#include <mutex>

#include "callbackmon.h"
#include "private.h"

using namespace callbackmon_ns;

static constexpr uint16_t win_vista_ver     = 6000;
static constexpr uint16_t win_vista_sp1_ver = 6001;
static constexpr uint16_t win_vista_sp2_ver = 6002;
static constexpr uint16_t win_7_sp1_ver     = 7601;
static constexpr uint16_t win_8_1_ver       = 9600;
static constexpr uint16_t win_10_rs1_ver    = 14393;
static constexpr uint16_t win_10_1803_ver   = 17134;

static const std::vector<const char*> callout_symbols =
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

static std::vector<addr_t> get_win32_callouts_vista(vmi_instance_t vmi, const std::vector<const char*>& symbols, std::function<addr_t(const char*)> get_ksymbol_va)
{
    std::vector<addr_t> out;
    for (const auto& symbol : symbols)
    {
        addr_t fn = 0;
        addr_t va = 0;
        try
        {
            va = get_ksymbol_va(symbol);
        }
        catch (...)
        {
            continue; // Skip if symbol not found
        }
        if (!va || VMI_SUCCESS != vmi_read_addr_va(vmi, va, 4, &fn))
            continue;
        out.push_back(fn);
    }
    return out;
}

static std::vector<addr_t> get_win32_callouts_pre_win81(vmi_instance_t vmi, const std::vector<const char*>& symbols, std::function<addr_t(const char*)> get_ksymbol_va)
{
    std::vector<addr_t> out;
    for (const auto& symbol : symbols)
    {
        addr_t fn = 0;
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, get_ksymbol_va(symbol), 4, &fn))
            throw -1;
        out.push_back(fn);
    }
    return out;
}

static std::vector<addr_t> get_win32_callouts_win81_and_newer(vmi_instance_t vmi, std::function<addr_t(const char*)> get_ksymbol_va, size_t ptrsize, size_t fast_ref)
{
    std::vector<addr_t> out;
    addr_t cb_block, fn;
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, get_ksymbol_va("PsWin32CallBack"), 4, &cb_block))
        throw -1;
    // Strip ref count
    cb_block &= ~fast_ref;
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, cb_block + ptrsize, 4, &fn))
        throw -1;
    out.push_back(fn);
    return out;
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
        if (!json_get_struct_members_array_rva(drakvuf, profile_json, offset_generic_names_w10, plugin->generic_offsets.size(), plugin->generic_offsets.data()) ||
            !json_get_struct_members_array_rva(drakvuf, profile_json, offset_open_names_w10,    plugin->open_offsets.size(),    plugin->open_offsets.data()))
        {
            json_object_put(profile_json);
            return false;
        }
    }
    else
    {
        if (!json_get_struct_members_array_rva(drakvuf, profile_json, offset_generic_names_w7, plugin->generic_offsets.size(), plugin->generic_offsets.data()) ||
            !json_get_struct_members_array_rva(drakvuf, profile_json, offset_open_names_w7,    plugin->open_offsets.size(),    plugin->open_offsets.data()))
        {
            json_object_put(profile_json);
            return false;
        }
    }

    if (!json_get_struct_members_array_rva(drakvuf, profile_json, offset_miniport_names, plugin->miniport_offsets.size(), plugin->miniport_offsets.data()) ||
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
            return false;
        }
    }
    return true;
}

static std::vector<addr_t> get_callback_object_callbacks(drakvuf_t drakvuf, callbackmon* plugin, addr_t object)
{
    std::vector<addr_t> out;
    // typedef struct _CALLBACK_OBJECT <- undocumented
    // {
    //   ULONG Signature;                   // 0x00
    //   KSPIN_LOCK Lock;                   // 0x08
    //   LIST_ENTRY RegisteredCallbacks;    // 0x10
    //   BOOLEAN AllowMultipleCallbacks;
    //   UCHAR reserved[3];
    // } CALLBACK_OBJECT, *PCALLBACK_OBJECT;
    const addr_t callbacks_off = drakvuf_get_address_width(drakvuf) * 2;
    // typedef struct _CALLBACK_REGISTRATION <- undocumented
    // {
    //   LIST_ENTRY Link;                       // 0x00
    //   PCALLBACK_OBJECT CallbackObject;       // 0x10
    //   PCALLBACK_FUNCTION CallbackFunction;   // 0x18
    //   PVOID CallbackContext;
    //   ULONG Busy;
    //   BOOLEAN UnregisterWaiting;
    // } CALLBACK_REGISTRATION, *PCALLBACK_REGISTRATION;
    const addr_t callback_fn_off = drakvuf_get_address_width(drakvuf) * 3;
    // Read flink entry.
    //
    addr_t head  = object + callbacks_off;
    addr_t entry = 0;

    vmi_lock_guard vmi(drakvuf);

    if (VMI_SUCCESS != vmi_read_addr_va(vmi, head, 0, &entry))
        return out;

    while (entry != head && entry)
    {
        addr_t callback{};
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, entry + callback_fn_off, 0, &callback) ||
            VMI_SUCCESS != vmi_read_addr_va(vmi, entry, 0, &entry))
            return out;
        if (callback)
        {
            out.push_back(callback);
        }
    }
    return out;
}

// Vista: store unique OBJECT_TYPE addresses because
// ObTypeIndexTable is not available in Vista, and
// collect callback objects.
static void vista_enumerate_object_types_and_callbacks(drakvuf_t drakvuf, const object_info_t* info, void* ctx)
{
    auto plugin = static_cast<callbackmon*>(ctx);
    addr_t obj_type = win_get_object_type_address(drakvuf, info->base_addr);
    if (obj_type)
        plugin->vista_object_type_addresses.insert(obj_type);

    // Enumerate callback objects.
    if (!strcmp((const char*)info->name->contents, "Callback"))
    {
        auto name = drakvuf_get_object_name(drakvuf, info->base_addr);
        plugin->object_cb.push_back(
        {
            .base = info->base_addr,
            .name = name ? (const char*)name->contents : "Anonymous",
            .callbacks = get_callback_object_callbacks(drakvuf, plugin, info->base_addr)
        });
        if (name) vmi_free_unicode_str(name);
    }

    drakvuf_release_vmi(drakvuf);
}

static bool fill_object_type_callbacks(vmi_instance_t vmi, drakvuf_t drakvuf, callbackmon* plugin, addr_t ob_type_base)
{
    object_type_t ob_type{};
    ob_type.base = ob_type_base;

    // Collect type initializer callbacks.
    //
    for (size_t cb_n = 0; cb_n < 8; cb_n++)
    {
        addr_t callback{};
        if (VMI_SUCCESS != vmi_read_addr_va(vmi, ob_type.base + plugin->offsets[OBJECT_TYPE_TYPEINFO] + plugin->offsets[OBJECT_TYPE_INITIALIZER_DUMP_CB] + cb_n * drakvuf_get_address_width(drakvuf), 0, &callback))
        {
            return false;
        }
        if (callback)
        {
            ob_type.initializer.push_back(callback);
        }
    }
    // Collect object type callbacks.
    //
    addr_t head = ob_type.base + plugin->offsets[OBJECT_TYPE_CALLBACKLIST];
    addr_t entry{};
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, head, 0, &entry))
        return false;

    while (entry != head && entry)
    {
        uint32_t active{};
        addr_t pre_cb{}, post_cb{};
        // Undocumented structure. No symbols.
        // typedef struct _CALLBACK_ENTRY_ITEM
        // {
        //     LIST_ENTRY CallbackList; // 0x0
        //     OB_OPERATION Operations; // 0x10
        //     DWORD Active; // 0x14
        //     CALLBACK_ENTRY *CallbackEntry; // 0x18
        //     PVOID ObjectType; // 0x20
        //     POB_PRE_OPERATION_CALLBACK PreOperation; // 0x28
        //     POB_POST_OPERATION_CALLBACK PostOperation; // 0x30
        //     QWORD unk1; // 0x38
        // } CALLBACK_ENTRY_ITEM, *PCALLBACK_ENTRY_ITEM; // size: 0x40
        if (VMI_SUCCESS != vmi_read_32_va  (vmi, entry + 0x14, 0, &active)  ||
            VMI_SUCCESS != vmi_read_addr_va(vmi, entry + 0x28, 0, &pre_cb)  ||
            VMI_SUCCESS != vmi_read_addr_va(vmi, entry + 0x30, 0, &post_cb) ||
            VMI_SUCCESS != vmi_read_addr_va(vmi, entry, 0, &entry))
        {
            return false;
        }

        if (active)
        {
            if (pre_cb)
                ob_type.callbacks.push_back({ .base = entry, .callback = pre_cb  });
            if (post_cb)
                ob_type.callbacks.push_back({ .base = entry, .callback = post_cb });
        }
    }
    // Fill object type name.
    //
    if (auto name = drakvuf_get_object_name(drakvuf, ob_type.base))
    {
        ob_type.name = (const char*)name->contents;
        vmi_free_unicode_str(name);
    }
    else
    {
        ob_type.name = "Anonymous";
    }
    plugin->object_type.push_back(std::move(ob_type));
    return true;
}

static bool consume_object_callbacks(drakvuf_t drakvuf, vmi_instance_t vmi, callbackmon* plugin)
{
    if (drakvuf_get_address_width(drakvuf) != 8)
        return true;
    // Enumerate callback objects.
    //
    if (vmi_get_winver(vmi) == VMI_OS_WINDOWS_VISTA)
    {
        if (!drakvuf_enumerate_object_directory(drakvuf, vista_enumerate_object_types_and_callbacks, plugin))
        {
            return false;
        }
    }
    else
    {
        if (!drakvuf_enumerate_object_directory(drakvuf, [](drakvuf_t drakvuf, const object_info_t* info, void* ctx)
    {
        auto plugin = static_cast<callbackmon*>(ctx);

            if (!strcmp((const char*)info->name->contents, "Callback"))
            {
                auto name = drakvuf_get_object_name(drakvuf, info->base_addr);
                plugin->object_cb.push_back(
                {
                    .base = info->base_addr,
                    .name = name ? (const char*)name->contents : "Anonymous",
                    .callbacks = get_callback_object_callbacks(drakvuf, plugin, info->base_addr)
                });
                if (name) vmi_free_unicode_str(name);
            }
        }, plugin))
        {
            return false;
        }
    }
    // Enumerate every object type.
    //
    if (vmi_get_winver(vmi) == VMI_OS_WINDOWS_VISTA)
    {
        for (addr_t obj_type_addr : plugin->vista_object_type_addresses)
        {
            if (!fill_object_type_callbacks(vmi, drakvuf, plugin, obj_type_addr))
                return false;
        }
    }
    else
    {
        // First 2 entries are not used.
        for (size_t i = 2; ; i++)
        {
            object_type_t ob_type{};
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, plugin->ob_type_table_va + i * drakvuf_get_address_width(drakvuf), 0, &ob_type.base))
                return false;
            // if reached the end.
            //
            if (!ob_type.base)
                break;
            if (!fill_object_type_callbacks(vmi, drakvuf, plugin, ob_type.base))
                return false;
        }
    }
    return true;
}

event_response_t callbackmon::load_unload_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto entry = drakvuf_get_function_argument(drakvuf, info, 1);

    vmi_lock_guard vmi(drakvuf);

    if (drakvuf_get_function_argument(drakvuf, info, 2))
    {
        callbackmon_module_t module_info{};
        if (VMI_SUCCESS == vmi_read_addr_va(vmi, entry + offsets[LDR_TABLE_ENTRY_DLLBASE],     info->proc_data.pid, &module_info.base) &&
            VMI_SUCCESS == vmi_read_addr_va(vmi, entry + offsets[LDR_TABLE_ENTRY_SIZEOFIMAGE], info->proc_data.pid, &module_info.size))
        {
            if (auto name = vmi_read_unicode_str_va(vmi, entry + offsets[LDR_TABLE_ENTRY_FULLDLLNAME], info->proc_data.pid))
            {
                module_info.name.assign((const char*)name->contents);
                drivers.push_back(std::move(module_info));
                vmi_free_unicode_str(name);
            }
        }
    }
    return VMI_EVENT_RESPONSE_NONE;
}

void callbackmon::report(drakvuf_t drakvuf, const char* list_name, addr_t addr, const char* action)
{
    auto get_module_by_addr = [&]() -> callbackmon_module_t
    {
        for (const auto& module : this->drivers)
        {
            if (addr >= module.base && addr < module.base + module.size)
            {
                return module;
            }
        }
        return { .base = 0, .size = 0, .name = "<Unknown>" };
    };

    const auto& module = get_module_by_addr();
    fmt::print(format, "callbackmon", drakvuf, nullptr,
        keyval("Type", fmt::Rstr("Callback")),
        keyval("ListName", fmt::Estr(list_name)),
        keyval("Module", fmt::Estr(module.name)),
        keyval("RVA", fmt::Xval(module.base ? addr - module.base : 0)),
        keyval("Action", fmt::Estr(action))
    );
}

callbackmon::callbackmon(drakvuf_t drakvuf, const callbackmon_config* config, output_format_t output)
    : pluginex(drakvuf, output), config{ *config }, format{ output }
{
    const addr_t krnl_base = drakvuf_get_kernel_base(drakvuf);
    const size_t ptrsize   = drakvuf_get_address_width(drakvuf);
    const size_t fast_ref  = (ptrsize == 8 ? 15 : 7);

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, offsets.size(), offsets.data()))
    {
        PRINT_DEBUG("[CALLBACKMON] Failed to get kernel struct member offsets\n");
        throw -1;
    }

    vmi_lock_guard vmi(drakvuf);

    if (!drakvuf_get_kernel_symbol_va(drakvuf, "ObTypeIndexTable", &ob_type_table_va) && (vmi_get_winver(vmi) != VMI_OS_WINDOWS_VISTA))
    {
        throw -1;
    }

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
    auto extract_cb = [&](std::vector<addr_t> devices) -> std::vector<addr_t>
    {
        constexpr size_t irp_mj_shutdown = 0x10;
        for (auto& device : devices)
        {
            addr_t driver{};
            if (VMI_SUCCESS != vmi_read_addr_va(vmi, device + offsets[DEVICE_OBJECT_DRIVER_OBJECT], 0, &driver) ||
                VMI_SUCCESS != vmi_read_addr_va(vmi, device + offsets[DRIVER_OBJECT_MAJOR_FUNCTION] + irp_mj_shutdown * ptrsize, 0, &device))
                throw -1;
        }
        return devices;
    };
    // Extract PsWin32Callouts
    auto consume_w32callouts = [&]() -> std::vector<addr_t>
    {
        std::vector<addr_t> out;
        if (vmi_get_winver(vmi) == VMI_OS_WINDOWS_VISTA)
        {
            return get_win32_callouts_vista(vmi, callout_symbols, get_ksymbol_va);
        }
        else if (vmi_get_win_buildnumber(vmi) < win_8_1_ver)
        {
            return get_win32_callouts_pre_win81(vmi, callout_symbols, get_ksymbol_va);
        }
        else
        {
            return get_win32_callouts_win81_and_newer(vmi, get_ksymbol_va, ptrsize, fast_ref);
        }
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
        bool res = json_get_symbol_rva(drakvuf, profile_json, "gWfpGlobal", &gwfp_rva);
        json_object_put(profile_json);
        if (!res)
            throw -1;

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

    if (!consume_object_callbacks(drakvuf, vmi, this))
    {
        PRINT_DEBUG("[CALLBACKMON] Failed to process object callbacks\n");
        throw -1;
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
    // This callback doesn't exist in Vista
    if (vmi_get_winver(vmi) != VMI_OS_WINDOWS_VISTA)
    {
        this->priority_cb  = consume_callbacks_ex("IopUpdatePriorityCallbackRoutine", 8);
    }
    this->pnp_prof_cb  = consume_callbacks("PnpProfileNotifyList", 4 * ptrsize);
    this->pnp_class_cb = consume_callbacks("PnpDeviceClassNotifyList", 5 * ptrsize);
    this->emp_cb       = consume_callbacks("EmpCallbackListHead", -3 * ptrsize);
    this->w32callouts  = consume_w32callouts();
    this->wfpcallouts  = consume_wfpcallouts(this->config.netio_profile);

    drakvuf_enumerate_drivers(drakvuf, [](drakvuf_t drakvuf, const module_info_t* info, bool*, bool*, void* ctx)
    {
        static_cast<callbackmon*>(ctx)->drivers.push_back(
        {
            .base = info->base_addr,
            .size = info->size,
            .name = (const char*)info->full_name->contents
        });
        return true;
    }, this);
    this->driver_hook = createSyscallHook("MiProcessLoaderEntry", &callbackmon::load_unload_cb);
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
            if (winver >= win_vista_ver && winver <= win_vista_sp2_ver)
            {
                // Some symbols had to be skipped for Vista
                for (size_t i = 0; i < std::min(previous.size(), current.size()); i++)
                    if (previous[i] != current[i])
                        report(drakvuf, callout_symbols[i], current[i], "Replaced");
            }
            else
            {
                for (size_t i = 0; i < callout_symbols.size(); i++)
                    if (previous[i] != current[i])
                        report(drakvuf, callout_symbols[i], current[i], "Replaced");
            }
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

    for (const auto& past_object : this->object_cb)
    {
        const auto& new_object = std::find_if(snapshot->object_cb.begin(), snapshot->object_cb.end(),
                [&past_object](const auto& object)
        {
            return object.base == past_object.base;
        });

        if (new_object != snapshot->object_cb.end())
        {
            check_callbacks(past_object.callbacks, new_object->callbacks, past_object.name.c_str());
        }
    }

    for (const auto& past_object : this->object_type)
    {
        const auto& new_object = std::find_if(snapshot->object_type.begin(), snapshot->object_type.end(),
                [&past_object](const auto& object)
        {
            return object.base == past_object.base;
        });

        if (new_object != snapshot->object_type.end())
        {
            check_callbacks(past_object.callbacks, new_object->callbacks, past_object.name.c_str());
            check_callbacks(past_object.initializer, new_object->initializer, past_object.name.c_str());
        }
    }
    return true;
}