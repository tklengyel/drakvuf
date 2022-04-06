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

#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <libdrakvuf/json-util.h>
#include <optional>
#include <memory>

#include "plugins/output_format.h"
#include "rpcmon.h"
#include "private.h"


static void free_trap(drakvuf_trap_t* trap)
{
    return_hook_target_entry_t* ret_target = (return_hook_target_entry_t*)trap->data;
    delete ret_target;
    delete trap;
}

struct _GUID
{
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];

    std::string str() const
    {
        const int sz = 64;
        char stream[sz] = {0};
        snprintf(stream, sz, "\"%08X-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\"",
            Data1, Data2, Data3, Data4[0], Data4[1],
            Data4[2], Data4[3], Data4[4],
            Data4[5], Data4[6], Data4[7]);

        return std::string(stream);
    }
} __attribute__((packed, aligned(4)));

struct RPC_SYNTAX_IDENTIFIER
{
    struct _GUID SyntaxGuid;
    uint16_t SyntaxVersion;
} __attribute__((packed, aligned(4)));

struct _RPC_CLIENT_INTERFACE
{
    uint32_t Length;
    RPC_SYNTAX_IDENTIFIER InterfaceId;
    RPC_SYNTAX_IDENTIFIER TransferSyntax;
} __attribute__((packed, aligned(4)));

struct _MIDL_STUB_DESC
{
    addr_t RpcInterfaceInformation;
} __attribute__((packed, aligned(4)));

struct _MIDL_STUB_DESC_32
{
    uint32_t RpcInterfaceInformation;
} __attribute__((packed, aligned(4)));

struct _MIDL_STUBLESS_PROXY_INFO
{
    addr_t pStubDesc;
} __attribute__((packed, aligned(4)));

struct _MIDL_STUBLESS_PROXY_INFO_32
{
    uint32_t pStubDesc;
} __attribute__((packed, aligned(4)));

struct rpc_info_t
{
    std::string InterfaceIdGuid;
    std::string TransferSyntaxGuid;
};

template<typename T>
static std::optional<T> read_struct(vmi_instance_t vmi, access_context_t const* ctx)
{
    T v;
    size_t bytes_read = 0;
    if (VMI_SUCCESS == vmi_read(vmi, ctx, sizeof(v), &v, &bytes_read) || bytes_read != sizeof(v))
        return v;
    return {};
}

template<typename T>
static std::optional<T> read_struct(vmi_instance_t vmi, drakvuf_trap_info* info, addr_t arg)
{
    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = arg;

    return read_struct<T>(vmi, &ctx);
}

static addr_t get_rpc_interface_information_addr(drakvuf_t drakvuf, drakvuf_trap_info* info, addr_t arg)
{
    bool is32bit = drakvuf_process_is32bit(drakvuf, info);

    auto vmi = vmi_lock_guard(drakvuf);

    if (is32bit)
    {
        auto s = read_struct<_MIDL_STUB_DESC_32>(vmi, info, arg);
        if (s) return s->RpcInterfaceInformation;
    }
    else
    {
        auto s = read_struct<_MIDL_STUB_DESC>(vmi, info, arg);
        if (s) return s->RpcInterfaceInformation;
    }

    return 0;
}

static addr_t get_rpc_proxy_info_addr(drakvuf_t drakvuf, drakvuf_trap_info* info, addr_t arg)
{
    bool is32bit = drakvuf_process_is32bit(drakvuf, info);

    auto vmi = vmi_lock_guard(drakvuf);

    if (is32bit)
    {
        auto s = read_struct<_MIDL_STUBLESS_PROXY_INFO_32>(vmi, info, arg);
        if (s) return s->pStubDesc;
    }
    else
    {
        auto s = read_struct<_MIDL_STUBLESS_PROXY_INFO>(vmi, info, arg);
        if (s) return s->pStubDesc;
    }

    return 0;
}

static std::optional<rpc_info_t> parse_MIDL_STUB_DESC(drakvuf_t drakvuf, drakvuf_trap_info* info, addr_t arg)
{
    addr_t rpc_interface_information_addr = get_rpc_interface_information_addr(drakvuf, info, arg);
    if (!rpc_interface_information_addr)
        return {};

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = rpc_interface_information_addr
    );

    auto vmi = vmi_lock_guard(drakvuf);

    auto rpc_iface = read_struct<_RPC_CLIENT_INTERFACE>(vmi, &ctx);
    if (!rpc_iface)
        return {};

    return {{rpc_iface->InterfaceId.SyntaxGuid.str(), rpc_iface->TransferSyntax.SyntaxGuid.str()}};
}

static std::optional<rpc_info_t> parse_MIDL_STUBLESS_PROXY_INFO(drakvuf_t drakvuf, drakvuf_trap_info* info, addr_t arg)
{
    addr_t rpc_proxy_info_addr = get_rpc_proxy_info_addr(drakvuf, info, arg);
    if (!rpc_proxy_info_addr)
        return {};

    return parse_MIDL_STUB_DESC(drakvuf, info, rpc_proxy_info_addr);
}

static std::optional<uint64_t> parse_FORMAT_STRING(drakvuf_t drakvuf, drakvuf_trap_info* info, addr_t arg)
{
    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    uint8_t oi_flags;
    ctx.addr = arg + Oi_FLAGS_FIELD_OFFSET;
    if (VMI_SUCCESS != vmi_read_8(vmi, &ctx, &oi_flags))
        return {};

    int proc_num_field_offset = (oi_flags & Oi_HAS_RPCFLAGS)
        ? Oi_PROCNUM_FIELD_OFFSET_WITH_RPCFLAGS
        : Oi_PROCNUM_FIELD_OFFSET_WITHOUT_RPCFLAGS;

    uint16_t proc_num;
    ctx.addr = arg + proc_num_field_offset;
    if (VMI_SUCCESS != vmi_read_16(vmi, &ctx, &proc_num))
        return {};

    return proc_num;
}

struct rpc_message_t
{
    uint64_t ProcNum;
    std::string InterfaceIdGuid;
};

static std::optional<rpc_message_t> parse_RPC_MESSAGE(drakvuf_t drakvuf, drakvuf_trap_info* info, addr_t arg)
{
    struct rpc_message_t r;

    bool is32bit = drakvuf_process_is32bit(drakvuf, info);

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx, .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3);

    uint32_t proc_num;
    if (is32bit)
        ctx.addr = arg + RPC_MESSAGE_PROCNUM_OFFSET_X86;
    else
        ctx.addr = arg + RPC_MESSAGE_PROCNUM_OFFSET_X64;
    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &proc_num))
        return {};
    r.ProcNum = proc_num;

    if (is32bit)
        ctx.addr = arg + RPC_MESSAGE_RPCINTERFACEINFO_OFFSET_X86;
    else
        ctx.addr = arg + RPC_MESSAGE_RPCINTERFACEINFO_OFFSET_X64;
    auto rpc_iface = read_struct<_RPC_CLIENT_INTERFACE>(vmi, &ctx);
    if (!rpc_iface)
        return {};
    r.InterfaceIdGuid = rpc_iface->InterfaceId.SyntaxGuid.str();

    return r;
}

static event_response_t usermode_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    return_hook_target_entry_t* ret_target = (return_hook_target_entry_t*)info->trap->data;

    if (!drakvuf_check_return_context(drakvuf, info, ret_target->pid, ret_target->tid, ret_target->rsp))
        return VMI_EVENT_RESPONSE_NONE;

    auto plugin = (rpcmon*)ret_target->plugin;

    std::vector<std::pair<std::string, fmt::Rstr<std::string>>> fmt_extra{};
    std::vector<std::pair<std::string, fmt::Nval<uint64_t>>> fmt_extra_num;
    std::vector<fmt::Rstr<std::string>> fmt_args{};
    {
        const auto& args = ret_target->arguments;
        const auto& printers = ret_target->argument_printers;
        for (auto [arg, printer] = std::tuple(std::cbegin(args), std::cbegin(printers));
            arg != std::cend(args) && printer != std::cend(printers);
            ++arg, ++printer)
        {
            fmt_args.push_back(fmt::Rstr((*printer)->print(drakvuf, info, *arg)));

            if (std::string("pStubDescriptor") == (*printer)->get_name())
            {
                auto r = parse_MIDL_STUB_DESC(drakvuf, info, *arg);
                if (!r) continue;

                fmt_extra.push_back(std::make_pair("InterfaceId", r->InterfaceIdGuid));
                fmt_extra.push_back(std::make_pair("TransferSyntax", r->TransferSyntaxGuid));
            }
            else if (std::string("pStubProxy") == (*printer)->get_name())
            {
                auto r = parse_MIDL_STUBLESS_PROXY_INFO(drakvuf, info, *arg);
                if (!r) continue;

                fmt_extra.push_back(std::make_pair("InterfaceId", r->InterfaceIdGuid));
                fmt_extra.push_back(std::make_pair("TransferSyntax", r->TransferSyntaxGuid));
            }
            else if (std::string("pFormat") == (*printer)->get_name())
            {
                auto r = parse_FORMAT_STRING(drakvuf, info, *arg);
                if (!r) continue;

                fmt_extra_num.push_back(std::make_pair("ProcedureNumber", fmt::Nval(*r)));
            }
            else if (std::string("RpcMessage") == (*printer)->get_name())
            {
                auto r = parse_RPC_MESSAGE(drakvuf, info, *arg);
                if (!r) continue;

                fmt_extra_num.push_back(std::make_pair("ProcNum", fmt::Nval(r->ProcNum)));
                fmt_extra.push_back(std::make_pair("InterfaceId", r->InterfaceIdGuid));
            }
        }
    }

    fmt::print(plugin->m_output_format, "rpcmon", drakvuf, info,
        keyval("Event", fmt::Qstr("api_called")),
        keyval("CalledFrom", fmt::Xval(info->regs->rip)),
        keyval("ReturnValue", fmt::Xval(info->regs->rax)),
        keyval("Arguments", fmt_args),
        keyval("Extra", fmt_extra),
        keyval("ExtraNum", fmt_extra_num)
    );

    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free_trap);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t usermode_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;

    if (target->pid != info->attached_proc_data.pid)
        return VMI_EVENT_RESPONSE_NONE;

    auto vmi = vmi_lock_guard(drakvuf);
    vmi_v2pcache_flush(vmi, info->regs->cr3);

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if (!ret_addr)
    {
        PRINT_DEBUG("[RPCMON-USER] Failed to read return address from the stack.\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    return_hook_target_entry_t* ret_target = new (std::nothrow) return_hook_target_entry_t(
        info->attached_proc_data.pid, info->attached_proc_data.tid, info->regs->rsp,
        target->clsid, target->plugin, target->argument_printers);

    if (!ret_target)
    {
        PRINT_DEBUG("[RPCMON-USER] Failed to allocate memory for return_hook_target_entry_t\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    drakvuf_trap_t* trap = new (std::nothrow) drakvuf_trap_t;

    if (!trap)
    {
        PRINT_DEBUG("[RPCMON-USER] Failed to allocate memory for drakvuf_trap_t\n");
        delete ret_target;
        return VMI_EVENT_RESPONSE_NONE;
    }

    for (size_t i = 1; i <= target->argument_printers.size(); i++)
    {
        uint64_t argument = drakvuf_get_function_argument(drakvuf, info, i);
        ret_target->arguments.push_back(argument);
    }

    addr_t paddr;

    if ( VMI_SUCCESS != vmi_pagetable_lookup(vmi, info->regs->cr3, ret_addr, &paddr) )
    {
        delete trap;
        delete ret_target;
        return VMI_EVENT_RESPONSE_NONE;
    }

    trap->type = BREAKPOINT;
    trap->name = target->target_name.c_str();
    trap->cb = usermode_return_hook_cb;
    trap->data = ret_target;
    trap->breakpoint.lookup_type = LOOKUP_DTB;
    trap->breakpoint.dtb = info->regs->cr3;
    trap->breakpoint.addr_type = ADDR_VA;
    trap->breakpoint.addr = ret_addr;
    trap->ttl = drakvuf_get_limited_traps_ttl(drakvuf);
    trap->ah_cb = nullptr;

    if (drakvuf_add_trap(drakvuf, trap))
    {
        ret_target->trap = trap;
    }
    else
    {
        PRINT_DEBUG("[RPCMON-USER] Failed to add trap :(\n");
        delete trap;
        delete ret_target;
    }

    return VMI_EVENT_RESPONSE_NONE;
}

static void on_dll_discovered(drakvuf_t drakvuf, std::string const& dll_name, const dll_view_t* dll, void* extra)
{
    rpcmon* plugin = (rpcmon*)extra;

    plugin->wanted_hooks.visit_hooks_for(dll_name, [&](const auto& e)
    {
        drakvuf_request_usermode_hook(drakvuf, dll, &e, usermode_hook_cb, plugin);
    });
}

static void on_dll_hooked(drakvuf_t drakvuf, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets, void* extra)
{
    PRINT_DEBUG("[RPCMON] DLL hooked - done\n");
}

static auto rpc_call_args()
{
    PrinterConfig config{};
    config.numeric_format = PrinterConfig::NumericFormat::DECIMAL;

    std::vector<std::unique_ptr<ArgumentPrinter>> args;
    args.emplace_back(std::make_unique<ArgumentPrinter>("pStubDescriptor", config));
    args.emplace_back(std::make_unique<ArgumentPrinter>("pFormat", config));
    return args;
}

static auto rpc_call3_args()
{
    PrinterConfig config{};
    config.numeric_format = PrinterConfig::NumericFormat::DECIMAL;

    std::vector<std::unique_ptr<ArgumentPrinter>> args;
    args.emplace_back(std::make_unique<ArgumentPrinter>("pStubProxy", config));
    args.emplace_back(std::make_unique<ArgumentPrinter>("ProcedureNumber", config));
    return args;
}

static auto i_rpc_args()
{
    PrinterConfig config{};
    config.numeric_format = PrinterConfig::NumericFormat::DECIMAL;

    std::vector<std::unique_ptr<ArgumentPrinter>> args;
    args.emplace_back(std::make_unique<ArgumentPrinter>("RpcMessage", config));
    return args;
}

rpcmon::rpcmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output)
{
    if (!drakvuf_are_userhooks_supported(drakvuf))
    {
        PRINT_DEBUG("[RPCMON] Usermode hooking not supported.\n");
        return;
    }

    const auto log = HookActions::empty().set_log();
    wanted_hooks.add_hook("rpcrt4.dll", "NdrAsyncClientCall", log, rpc_call_args());
    wanted_hooks.add_hook("rpcrt4.dll", "NdrAsyncClientCall2", log, rpc_call_args());
    wanted_hooks.add_hook("rpcrt4.dll", "NdrClientCall", log, rpc_call_args());
    wanted_hooks.add_hook("rpcrt4.dll", "NdrClientCall2", log, rpc_call_args());
    wanted_hooks.add_hook("rpcrt4.dll", "NdrClientCall3", log, rpc_call3_args());
    wanted_hooks.add_hook("rpcrt4.dll", "NdrClientCall4", log, rpc_call_args());
    wanted_hooks.add_hook("rpcrt4.dll", "I_RpcReceive", log, i_rpc_args());
    wanted_hooks.add_hook("rpcrt4.dll", "I_RpcSend", log, i_rpc_args());
    wanted_hooks.add_hook("rpcrt4.dll", "I_RpcSendReceive", log, i_rpc_args());

    usermode_cb_registration reg =
    {
        .pre_cb = on_dll_discovered,
        .post_cb = on_dll_hooked,
        .extra = (void*)this
    };
    drakvuf_register_usermode_callback(drakvuf, &reg);
}

rpcmon::~rpcmon()
{

}
