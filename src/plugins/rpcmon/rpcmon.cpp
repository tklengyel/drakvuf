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

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <assert.h>
#include <libdrakvuf/json-util.h>

#include "plugins/output_format.h"
#include "rpcmon.h"


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

static event_response_t usermode_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    return_hook_target_entry_t* ret_target = (return_hook_target_entry_t*)info->trap->data;

    // TODO check thread_id and cr3?
    if (info->proc_data.pid != ret_target->pid)
        return VMI_EVENT_RESPONSE_NONE;

    auto plugin = (rpcmon*)ret_target->plugin;

    std::vector<std::pair<std::string, fmt::Rstr<std::string>>> fmt_extra{};
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
                vmi_lock_guard vmi(drakvuf);

                size_t bytes_read = 0;
                access_context_t ctx;
                ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
                ctx.dtb = info->regs->cr3;
                ctx.addr = *arg;

                struct _MIDL_STUB_DESC stub_desc;
                if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(struct _MIDL_STUB_DESC), &stub_desc, &bytes_read) || bytes_read != sizeof(struct _MIDL_STUB_DESC))
                    continue;

                ctx.addr = stub_desc.RpcInterfaceInformation;
                struct _RPC_CLIENT_INTERFACE rpc_iface;
                if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(struct _RPC_CLIENT_INTERFACE), &rpc_iface, &bytes_read) || bytes_read != sizeof(struct _RPC_CLIENT_INTERFACE))
                    continue;

                fmt_extra.push_back(std::make_pair("InterfaceId", rpc_iface.InterfaceId.SyntaxGuid.str()));
                fmt_extra.push_back(std::make_pair("TransferSyntax", rpc_iface.TransferSyntax.SyntaxGuid.str()));
            }
        }
    }

    fmt::print(plugin->m_output_format, "rpcmon", drakvuf, info,
               keyval("Event", fmt::Qstr("api_called")),
               keyval("CalledFrom", fmt::Xval(info->regs->rip)),
               keyval("ReturnValue", fmt::Xval(info->regs->rax)),
               keyval("Arguments", fmt_args),
               keyval("Extra", fmt_extra)
              );

    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free_trap);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t usermode_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;

    if (target->pid != info->proc_data.pid)
        return VMI_EVENT_RESPONSE_NONE;

    vmi_lock_guard lg(drakvuf);
    vmi_v2pcache_flush(lg.vmi, info->regs->cr3);

    bool is_syswow = drakvuf_is_wow64(drakvuf, info);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = info->regs->rsp
    };

    bool success = false;
    addr_t ret_addr = 0;

    if (is_syswow)
        success = (vmi_read_32(lg.vmi, &ctx, (uint32_t*)&ret_addr) == VMI_SUCCESS);
    else
        success = (vmi_read_64(lg.vmi, &ctx, &ret_addr) == VMI_SUCCESS);

    if (!success)
    {
        PRINT_DEBUG("[RPCMON-USER] Failed to read return address from the stack.\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    return_hook_target_entry_t* ret_target = new (std::nothrow) return_hook_target_entry_t(target->pid, target->clsid, target->plugin, target->argument_printers);

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

    if ( VMI_SUCCESS != vmi_pagetable_lookup(lg.vmi, info->regs->cr3, ret_addr, &paddr) )
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

static void print_addresses(drakvuf_t drakvuf, rpcmon* plugin, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets)
{
    unicode_string_t* dll_name;
    json_object* j_root;
    json_object* j_rvas;
    vmi_pid_t pid;
    vmi_lock_guard lg(drakvuf);

    dll_name = drakvuf_read_unicode_va(lg.vmi, dll->mmvad.file_name_ptr, 0);

    if (plugin->m_output_format != OUTPUT_JSON)
        return;

    if (!dll_name || !dll_name->contents)
        goto out;

    vmi_dtb_to_pid(lg.vmi, dll->dtb, &pid);

    j_root = json_object_new_object();
    j_rvas = json_object_new_object();

    for (auto const& target : targets)
    {
        if (target.state == HOOK_OK)
            json_object_object_add(j_rvas, target.target_name.c_str(), json_object_new_int(target.offset));
    }

    json_object_object_add(j_root, "Plugin", json_object_new_string("rpcmon"));
    json_object_object_add(j_root, "Event", json_object_new_string("dll_loaded"));
    json_object_object_add(j_root, "Rva", j_rvas);
    json_object_object_add(j_root, "DllBase", json_object_new_string_fmt("0x%lx", dll->real_dll_base));
    json_object_object_add(j_root, "DllName", json_object_new_string((const char*)dll_name->contents));
    json_object_object_add(j_root, "PID", json_object_new_int(pid));

    printf("%s\n", json_object_to_json_string(j_root));

    json_object_put(j_root);

out:
    if (dll_name)
        vmi_free_unicode_str(dll_name);
}

static void on_dll_discovered(drakvuf_t drakvuf, const dll_view_t* dll, void* extra)
{
    rpcmon* plugin = (rpcmon*)extra;

    vmi_lock_guard lg(drakvuf);
    unicode_string_t* dll_name = drakvuf_read_unicode_va(lg.vmi, dll->mmvad.file_name_ptr, 0);

    if (dll_name && dll_name->contents)
    {
        for (auto const& wanted_hook : plugin->wanted_hooks)
        {
            if (strstr((const char*)dll_name->contents, wanted_hook.dll_name.c_str()) != 0)
            {
                drakvuf_request_usermode_hook(drakvuf, dll, &wanted_hook, usermode_hook_cb, plugin);
            }
        }
    }

    if (dll_name)
        vmi_free_unicode_str(dll_name);
}

static void on_dll_hooked(drakvuf_t drakvuf, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets, void* extra)
{
    rpcmon* plugin = (rpcmon*)extra;
    print_addresses(drakvuf, plugin, dll, targets);
    PRINT_DEBUG("[RPCMON] DLL hooked - done\n");
}

rpcmon::rpcmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output)
{
    std::vector< std::unique_ptr < ArgumentPrinter > > arg_vec;

    arg_vec.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter("pStubDescriptor", false)));
    arg_vec.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter("pFormat", false)));
    wanted_hooks.emplace_back("rpcrt4.dll", "NdrAsyncClientCall", "log", std::move(arg_vec));

    arg_vec.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter("pStubDescriptor", false)));
    arg_vec.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter("pFormat", false)));
    wanted_hooks.emplace_back("rpcrt4.dll", "NdrAsyncClientCall2", "log", std::move(arg_vec));

    arg_vec.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter("pStubDescriptor", false)));
    arg_vec.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter("pFormat", false)));
    wanted_hooks.emplace_back("rpcrt4.dll", "NdrClientCall", "log", std::move(arg_vec));

    arg_vec.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter("pStubDescriptor", false)));
    arg_vec.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter("pFormat", false)));
    wanted_hooks.emplace_back("rpcrt4.dll", "NdrClientCall2", "log", std::move(arg_vec));

    arg_vec.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter("pStubDescriptor", false)));
    arg_vec.push_back(std::unique_ptr < ArgumentPrinter>(new ArgumentPrinter("pFormat", false)));
    wanted_hooks.emplace_back("rpcrt4.dll", "NdrClientCall4", "log", std::move(arg_vec));

    usermode_cb_registration reg =
    {
        .pre_cb = on_dll_discovered,
        .post_cb = on_dll_hooked,
        .extra = (void*)this
    };

    usermode_reg_status_t status = drakvuf_register_usermode_callback(drakvuf, &reg);

    switch (status)
    {
        case USERMODE_REGISTER_SUCCESS:
            // success, nothing to do
            break;
        case USERMODE_ARCH_UNSUPPORTED:
        case USERMODE_OS_UNSUPPORTED:
            PRINT_DEBUG("[RPCMON] Usermode hooking is not supported on this architecture/bitness/os version, these features will be disabled\n");
            break;
        default:
            PRINT_DEBUG("[RPCMON] Failed to subscribe to libusermode\n");
            throw -1;
    }
}

rpcmon::~rpcmon()
{

}
