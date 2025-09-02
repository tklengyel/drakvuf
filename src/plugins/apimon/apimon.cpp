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

#include <iostream>
#include <stdexcept>
#include <inttypes.h>
#include <assert.h>

#include "plugins/output_format.h"
#include "apimon.h"
#include "crypto.h"


namespace
{

struct ApimonReturnHookData : PluginResult
{
    std::vector<uint64_t> arguments;
    hook_target_entry_t* target = nullptr;
};

}


static event_response_t delete_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin  = get_trap_plugin<apimon>(info);
    auto process = drakvuf_get_function_argument(drakvuf, info, 1);

    vmi_pid_t pid;
    if (!drakvuf_get_process_pid(drakvuf, process, &pid))
    {
        PRINT_DEBUG("[APIMON] Failed to read process pid\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    plugin->procs.erase(pid);
    return VMI_EVENT_RESPONSE_NONE;
}

void apimon::usermode_print(drakvuf_trap_info* info, std::vector<uint64_t>& args, hook_target_entry_t* target)
{
    std::map < std::string, std::string > extra_data;

    if (!strcmp(info->trap->name, "CryptGenKey"))
        extra_data = CryptGenKey_hook(drakvuf, info, args);

    std::optional<fmt::Qstr<std::string>> clsid;

    if (!target->clsid.empty())
        clsid = fmt::Qstr(target->clsid);

    std::vector<fmt::Rstr<std::string>> fmt_args{};
    {
        const auto& printers = target->argument_printers;
        for (auto [arg, printer] = std::tuple(std::cbegin(args), std::cbegin(printers));
            arg != std::cend(args) && printer != std::cend(printers);
            ++arg, ++printer)
        {
            fmt_args.push_back(fmt::Rstr((*printer)->print(drakvuf, info, *arg)));
        }
    }

    std::map<std::string, fmt::Qstr<std::string>> fmt_extra{};
    for (const auto& extra : extra_data)
    {
        fmt_extra.insert(std::make_pair(extra.first, fmt::Qstr(extra.second)));
    }

    auto module_name = resolve_module(drakvuf, info->proc_data.base_addr, info->regs->rip, info->proc_data.pid);

    std::optional<fmt::Qstr<std::string>> module_opt;
    if (module_name.has_value())
    {
        module_opt = module_name.value();
    }

    fmt::print(m_output_format, "apimon", drakvuf, info,
        keyval("Event", fmt::Rstr("api_called")),
        keyval("CLSID", clsid),
        keyval("CalledFrom", fmt::Xval(info->regs->rip)),
        keyval("ReturnValue", fmt::Xval(info->regs->rax)),
        keyval("FromModule", module_opt),
        keyval("Arguments", fmt_args),
        keyval("Extra", fmt_extra)
    );
}

event_response_t apimon::usermode_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    auto params = libhook::GetTrapParams<ApimonReturnHookData>(info);

    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    usermode_print(info, params->arguments, params->target);

    auto hookID = make_hook_id(info, params->target_rsp);
    ret_hooks.erase(hookID);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t usermode_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;
    auto plugin = (apimon*)target->plugin;

    if (target->pid != info->attached_proc_data.pid)
        return VMI_EVENT_RESPONSE_NONE;

    if (plugin->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    auto vmi = vmi_lock_guard(drakvuf);
    vmi_v2pcache_flush(vmi, info->regs->cr3);

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);

    if (!ret_addr)
    {
        PRINT_DEBUG("[APIMON-USER] Failed to read return address from the stack.\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t ret_paddr;
    if ( VMI_SUCCESS != vmi_pagetable_lookup(vmi, info->regs->cr3, ret_addr, &ret_paddr) )
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    std::vector<uint64_t> arguments;
    arguments.reserve(target->argument_printers.size());
    for (size_t i = 1; i <= target->argument_printers.size(); i++)
    {
        uint64_t argument = drakvuf_get_function_argument(drakvuf, info, i);
        arguments.push_back(argument);
    }

    if (target->no_retval)
    {
        plugin->usermode_print(info, arguments, target);
    }
    else
    {
        auto hook = plugin->createReturnHook<ApimonReturnHookData>(info,
                &apimon::usermode_return_hook_cb, target->target_name.data(), drakvuf_get_limited_traps_ttl(drakvuf));
        auto params = libhook::GetTrapParams<ApimonReturnHookData>(hook->trap_);
        auto hookID = make_hook_id(info, params->target_rsp);

        params->arguments = std::move(arguments);
        params->target = target;

        plugin->ret_hooks[hookID] = std::move(hook);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

static void print_addresses(drakvuf_t drakvuf, apimon* plugin, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets)
{
    unicode_string_t* dll_name;
    json_object* j_root;
    json_object* j_rvas;
    vmi_pid_t pid;
    auto vmi = vmi_lock_guard(drakvuf);

    dll_name = drakvuf_read_unicode_va(drakvuf, dll->mmvad.file_name_ptr, 0);

    if (plugin->m_output_format != OUTPUT_JSON)
        goto out;

    if (!dll_name || !dll_name->contents)
        goto out;

    vmi_dtb_to_pid(vmi, dll->dtb, &pid);

    j_root = json_object_new_object();
    j_rvas = json_object_new_object();

    for (auto const& target : targets)
    {
        if (target.state == HOOK_OK)
            json_object_object_add(j_rvas, target.target_name.c_str(), json_object_new_int(target.offset));
    }

    json_object_object_add(j_root, "Plugin", json_object_new_string("apimon"));
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

static void on_dll_discovered(drakvuf_t drakvuf, const std::string& dll_name, const dll_view_t* dll, void* extra)
{
    apimon* plugin = (apimon*)extra;

    vmi_pid_t pid;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        vmi_dtb_to_pid(vmi, dll->dtb, &pid);
    }

    fmt::print(plugin->m_output_format, "apimon", drakvuf, nullptr,
        keyval("Event", fmt::Rstr("dll_discovered")),
        keyval("DllName", fmt::Estr(dll_name)),
        keyval("DllBase", fmt::Xval(dll->real_dll_base)),
        keyval("PID", fmt::Nval(pid))
    );

    plugin->wanted_hooks.visit_hooks_for(dll_name, [&](const auto& e)
    {
        drakvuf_request_usermode_hook(drakvuf, dll, &e, usermode_hook_cb, plugin);
    });
}

static void on_dll_hooked(drakvuf_t drakvuf, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets, void* extra)
{
    apimon* plugin = (apimon*)extra;
    print_addresses(drakvuf, plugin, dll, targets);
    PRINT_DEBUG("[APIMON] DLL hooked - done\n");
}

std::optional<std::string> apimon::resolve_module(drakvuf_t drakvuf, addr_t process, addr_t addr, vmi_pid_t pid)
{
    auto lookup = [&]() -> std::optional<std::string>
    {
        const auto& mods = this->procs.find(pid);
        if (mods != this->procs.end())
        {
            for (const auto& module : mods->second)
            {
                if (addr >= module.base && addr < module.base + module.size)
                {
                    return module.name;
                }
            }
        }
        return {};
    };
    if (auto name = lookup())
    {
        return name.value();
    }
    // Didn't find in cache, try to resolve.
    //
    if (mmvad_info_t mmvad{}; drakvuf_find_mmvad(drakvuf, process, addr, &mmvad))
    {
        auto& mods = this->procs[pid];
        if (mmvad.file_name_ptr)
        {
            if (auto u_name = drakvuf_read_unicode_va(drakvuf, mmvad.file_name_ptr, 0))
            {
                std::string name = (const char*)u_name->contents;

                if (auto sub = name.find_last_of("/\\"); sub != std::string::npos)
                {
                    name.erase(0, sub + 1);
                }
                mods.push_back(
                {
                    .name = std::move(name),
                    .base = mmvad.starting_vpn << 12,
                        .size = (mmvad.ending_vpn - mmvad.starting_vpn) << 12
                });
                vmi_free_unicode_str(u_name);
                return mods.back().name;
            }
        }
    }
    return {};
}

apimon::apimon(drakvuf_t drakvuf, const apimon_config* c, output_format_t output)
    : pluginex(drakvuf, output)
{
    if (!drakvuf_are_userhooks_supported(drakvuf))
    {
        PRINT_DEBUG("[APIMON] Usermode hooking not supported.\n");
        return;
    }

    try
    {
        auto noLog = [](const auto& entry)
        {
            return !entry.actions.log;
        };
        drakvuf_load_dll_hook_config(drakvuf, c->dll_hooks_list, c->print_no_addr, noLog, this->wanted_hooks);
    }
    catch (const std::runtime_error& exc)
    {
        std::cerr << "Loading DLL hook configuration for APIMON plugin failed\n"
            << "Reason: " << exc.what() << "\n";
        throw -1;
    }

    if (this->wanted_hooks.empty())
    {
        // don't load this plugin if there is nothing to do
        return;
    }

    usermode_cb_registration reg =
    {
        .pre_cb = on_dll_discovered,
        .post_cb = on_dll_hooked,
        .extra = (void*)this
    };
    drakvuf_register_usermode_callback(drakvuf, &reg);

    breakpoint_in_system_process_searcher bp;
    register_trap(nullptr, delete_process_cb, bp.for_syscall_name("PspProcessDelete"));
}

bool apimon::stop_impl()
{
    return drakvuf_stop_userhooks(drakvuf) && pluginex::stop_impl();
}

apimon::~apimon()
{

}
