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

#ifndef PLUGIN_EX_H
#define PLUGIN_EX_H

#include <string>
#include <bitset>
#include <map>
#include <memory>
#include <vector>
#include <algorithm>
#include <functional>
#include <optional>

#include "plugins.h"
#include "helpers/hooks.h"


// Errors
extern char ERROR_MSG_ADDING_TRAP[];

namespace print
{

template<std::size_t N>
std::string FieldToString(const std::map<uint64_t, std::string>& maps, const std::bitset<N>& value)
{
    std::string str;
    std::size_t indexes = value.size();
    for (std::size_t i = 0; i < indexes; i++)
    {
        uint64_t v = value[i];

        if (!v)
            continue;

        auto it = maps.find(v << i);
        if (it == maps.end())
            continue;

        str += it->second + "=1" + ",";
    }

    if (!str.empty())
        str.resize(str.size() - 1);

    return str;
}

std::string FieldToString(const std::map<uint64_t, std::string>& maps, uint64_t value);

} // namespace print

struct breakpoint_in_system_process_searcher
{
    breakpoint_in_system_process_searcher() : m_pid(), m_syscall_name(), m_virt_addr() {}

    breakpoint_in_system_process_searcher& for_syscall_name(const char* syscall_name)
    {
        if (syscall_name)
            m_syscall_name = syscall_name;

        return *this;
    }

    breakpoint_in_system_process_searcher& for_linux(vmi_pid_t pid, addr_t addr)
    {
        m_pid = pid;
        m_virt_addr = addr;
        return *this;
    }

    drakvuf_trap_t* operator()(drakvuf_t drakvuf, drakvuf_trap_info_t* info, drakvuf_trap_t* trap) const
    {
        if (trap)
        {
            if (!drakvuf_get_kernel_symbol_rva(drakvuf, m_syscall_name, &trap->breakpoint.rva))
            {
                PRINT_DEBUG("Failed to receive addr of function %s\n", m_syscall_name);
                return nullptr;
            }

            trap->type = BREAKPOINT;

            if (m_virt_addr)
            {
                trap->breakpoint.lookup_type = LOOKUP_PID;
                trap->breakpoint.pid = m_pid;
                trap->breakpoint.addr_type = ADDR_VA;
                trap->breakpoint.addr = m_virt_addr;
            }
            else
            {
                trap->breakpoint.lookup_type = LOOKUP_PID;
                trap->breakpoint.pid = 4;
                trap->breakpoint.addr_type = ADDR_RVA;
                trap->breakpoint.module = "ntoskrnl.exe";

                trap->name = m_syscall_name;
            }

            if (!drakvuf_add_trap(drakvuf, trap))
                return nullptr;
        }
        return trap;
    }

    vmi_pid_t m_pid;
    const char* m_syscall_name;
    addr_t m_virt_addr;
};

struct breakpoint_in_dll_module_searcher
{
    breakpoint_in_dll_module_searcher(json_object* json,
        const char* module,
        bool wow = false)
        : m_is_wow(wow), m_json(json), m_module_name(module), m_syscall_name()
    {}

    static bool module_visitor(drakvuf_t drakvuf, const module_info_t* module_info, void* ctx)
    {
        auto data = reinterpret_cast<context*>(ctx);
        if (!data || module_info->is_wow != data->m_is_wow)
            return false;

        data->m_trap->breakpoint.pid = module_info->pid;
        data->m_trap->breakpoint.addr = module_info->base_addr + data->m_function_rva;

        return drakvuf_add_trap(drakvuf, data->m_trap);
    }

    breakpoint_in_dll_module_searcher& for_syscall_name(const char* syscall_name)
    {
        if (syscall_name)
            m_syscall_name = syscall_name;

        return *this;
    }

    drakvuf_trap_t* operator()(drakvuf_t drakvuf, drakvuf_trap_info_t* info, drakvuf_trap_t* trap) const
    {
        if (trap)
        {
            context ctx(trap, m_is_wow);
            if (!json_get_symbol_rva(drakvuf, m_json, m_syscall_name, &ctx.m_function_rva))
            {
                PRINT_DEBUG("Failed to find a function %s::%s. %s\n", m_module_name, m_syscall_name, m_is_wow ? "WoW64 " : "");
                return nullptr;
            }

            trap->type = BREAKPOINT;
            trap->breakpoint.lookup_type = LOOKUP_PID;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->breakpoint.module = m_module_name;

            trap->name = m_syscall_name;

            if (!drakvuf_enumerate_processes_with_module(drakvuf, m_module_name, module_visitor, &ctx))
            {
                PRINT_DEBUG("Failed to set a trap for function %s::%s in PID: %u\n", m_module_name, m_syscall_name, trap->breakpoint.pid);
                return nullptr;
            }
        }
        return trap;
    }

    struct context
    {
        context(drakvuf_trap_t* t, bool w) : m_is_wow(w), m_function_rva(), m_trap(t) {}

        bool m_is_wow;
        addr_t m_function_rva;
        drakvuf_trap_t* m_trap;
    };

    bool m_is_wow;
    json_object* m_json;
    const char* m_module_name;
    const char* m_syscall_name;
};

struct breakpoint_by_dtb_searcher
{
    breakpoint_by_dtb_searcher() : m_addr(), m_dtb() {}

    breakpoint_by_dtb_searcher& for_virt_addr(addr_t addr)
    {
        if (addr)
            m_addr = addr;

        return *this;
    }

    breakpoint_by_dtb_searcher& for_dtb(addr_t dtb)
    {
        if (dtb)
            m_dtb = dtb;

        return *this;
    }

    drakvuf_trap_t* operator()(drakvuf_t drakvuf, drakvuf_trap_info_t* info, drakvuf_trap_t* trap) const
    {
        if (trap)
        {
            // NOTE This is rather ugly solution but is backword compatible.
            // TODO Add "for_ret_addr" method and use it.
            addr_t addr = m_addr;
            if (!addr)
            {
                addr = drakvuf_get_function_return_address(drakvuf, info);
                if (!addr)
                    return nullptr;
            }

            addr_t dtb = m_dtb;
            if (!dtb)
            {
                if (info && info->regs)
                    dtb = info->regs->cr3;
                else
                    return nullptr;
            }

            trap->type = BREAKPOINT;
            trap->breakpoint.lookup_type = LOOKUP_DTB;
            trap->breakpoint.dtb = dtb;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->breakpoint.addr = addr;

            if (!trap->name && info && info->trap)
                trap->name = info->trap->name;

            if (!drakvuf_add_trap(drakvuf, trap))
                return nullptr;
        }
        return trap;
    }

    addr_t m_addr;
    addr_t m_dtb;
};

struct breakpoint_by_pid_searcher
{
    drakvuf_trap_t* operator()(drakvuf_t drakvuf, drakvuf_trap_info_t* info, drakvuf_trap_t* trap) const
    {
        if (trap)
        {
            addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
            if (!ret_addr)
                return nullptr;

            trap->type = BREAKPOINT;
            trap->breakpoint.lookup_type = LOOKUP_PID;
            trap->breakpoint.pid = info->trap->breakpoint.pid;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->breakpoint.addr = ret_addr;
            trap->breakpoint.module = info->trap->breakpoint.module;

            if (!trap->name)
                trap->name = info->trap->name;

            if (!drakvuf_add_trap(drakvuf, trap))
                return nullptr;
        }
        return trap;
    }
};

struct memaccess_trap
{
    memaccess_trap& for_gfn(uint64_t _gfn, vmi_mem_access_t vmi_access_type, memaccess_type_t memaccess_type = POST)
    {
        gfn = _gfn;
        access = vmi_access_type;
        access_type = memaccess_type;
        return *this;
    }

    drakvuf_trap_t* operator()(drakvuf_t drakvuf, drakvuf_trap_info_t* info, drakvuf_trap_t* trap) const
    {
        if (trap)
        {
            if (access == VMI_MEMACCESS_INVALID)
                return nullptr;

            trap->type = MEMACCESS;
            trap->memaccess.access = access;
            trap->memaccess.type = access_type;
            trap->memaccess.gfn = gfn;

            if (!trap->name && info && info->trap)
                trap->name = info->trap->name;

            if (!drakvuf_add_trap(drakvuf, trap))
                return nullptr;
        }

        return trap;
    }

    uint64_t gfn;
    vmi_mem_access_t access;
    memaccess_type_t access_type;
};

struct call_result_t
{
    call_result_t()
        : target_pid(), target_tid(), target_rsp()
    {}

    virtual ~call_result_t()
    {};

    void set_result_call_params(const drakvuf_trap_info_t* info)
    {
        target_pid = info->attached_proc_data.pid;
        target_tid = info->attached_proc_data.tid;
        target_rsp = info->regs->rsp;
    }

    void set_result_call_params(const drakvuf_trap_info_t* info, addr_t stack_pointer)
    {
        target_pid = info->attached_proc_data.pid;
        target_tid = info->attached_proc_data.tid;
        target_rsp = stack_pointer;
    }

    bool verify_result_call_params(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
    {
        return drakvuf_check_return_context(drakvuf, info, target_pid, target_tid, target_rsp);
    }

    vmi_pid_t target_pid;
    uint32_t target_tid;
    addr_t target_rsp;
};

struct plugin_data
{
    class pluginex* plugin;
    call_result_t* params;

    plugin_data(pluginex* plugin, call_result_t* params)
        : plugin(plugin), params(params)
    {};

    virtual ~plugin_data()
    {
        delete params;
    };
};

class pluginex : public plugin
{
public:
    typedef event_response_t(*hook_cb_t)(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    typedef void(*ah_cb_t)(drakvuf_t drakvuf, drakvuf_trap_t* trap);

    pluginex(drakvuf_t drakvuf, output_format_t output);
    virtual ~pluginex();
    virtual bool stop_impl() override;
    void destroy_all_traps();

    /**********************************
     *        Libhook RAII API        *
     **********************************/

    [[nodiscard]]
    std::unique_ptr<libhook::ManualHook> createManualHook(drakvuf_trap_t* info, drakvuf_trap_free_t free_routine);

    template<typename Params = PluginResult, typename Callback>
    [[nodiscard]]
    std::unique_ptr<libhook::ReturnHook> createReturnHook(drakvuf_trap_info* info, Callback cb, const char* display_name = nullptr, int ttl = UNLIMITED_TTL);

    template<typename Params = PluginResult, typename Callback>
    [[nodiscard]]
    std::unique_ptr<libhook::SyscallHook> createSyscallHook(const std::string& syscall_name, Callback cb, const std::optional<std::string>& display_name = {}, int ttl = UNLIMITED_TTL);

    template<typename Params = PluginResult, typename Callback>
    [[nodiscard]]
    std::unique_ptr<libhook::Cr3Hook> createCr3Hook(Callback cb, int ttl = UNLIMITED_TTL);

    template<typename Params = PluginResult, typename Callback>
    [[nodiscard]]
    std::unique_ptr<libhook::CpuidHook> createCpuidHook(Callback cb, int ttl = UNLIMITED_TTL);

    template<typename Params = PluginResult, typename Callback>
    [[nodiscard]]
    std::unique_ptr<libhook::CatchAllHook> createCatchAllHook(Callback cb, int ttl = UNLIMITED_TTL);

    template<typename Params = PluginResult, typename Callback>
    [[nodiscard]]
    std::unique_ptr<libhook::MemAccessHook> createMemAccessHook(Callback cb, addr_t gfn, memaccess_type_t mem_access_type, vmi_mem_access_t mem_access, int ttl = UNLIMITED_TTL);

private:
    template<typename Callback>
    [[nodiscard]]
    libhook::cb_wrapper_t wrap_plugin_cb(Callback cb);

    /************************************
     *        Legacy hooking API        *
     ************************************/

public:
    // Params property is optional
    template<typename Params = void, typename IB>
    drakvuf_trap_t* register_trap(drakvuf_trap_info_t* info,
        hook_cb_t hook_cb,
        IB init_breakpoint,
        const char* trap_name,
        int64_t ttl,
        ah_cb_t ah_cb = nullptr);

    // Params property is optional
    template<typename Params = void, typename IB>
    drakvuf_trap_t* register_trap(drakvuf_trap_info_t* info,
        hook_cb_t hook_cb,
        IB init_breakpoint,
        const char* trap_name = nullptr);

    // Params property is optional
    template<typename Params = void>
    void register_trap(drakvuf_trap_t* trap);

    void destroy_trap(drakvuf_trap_t* target);

    const output_format_t m_output_format;
    drakvuf_t drakvuf;

private:
    std::vector<drakvuf_trap_t*> traps;

    void delete_trap(drakvuf_trap_t* target);
};

template<typename Params>
Params* get_trap_params(const drakvuf_trap_t* trap)
{
    static_assert(std::is_base_of_v<call_result_t, Params>, "Params must derive from call_result_t");

    if (!trap || !trap->data)
        return nullptr;

    auto params = dynamic_cast<Params*>(static_cast<plugin_data*>(trap->data)->params);
    if (!params)
    {
        PRINT_DEBUG("[PLUGINEX] nullptr at get_trap_params, this should never happen");
        throw -1;
    }
    return params;
}

template<typename Params>
Params* get_trap_params(const drakvuf_trap_info_t* info)
{
    static_assert(std::is_base_of_v<call_result_t, Params>, "Params must derive from call_result_t");

    if (!info || !info->trap || !info->trap->data)
        return nullptr;

    auto params = dynamic_cast<Params*>(static_cast<plugin_data*>(info->trap->data)->params);
    if (!params)
    {
        PRINT_DEBUG("[PLUGINEX] nullptr at get_trap_params, this should never happen");
        throw -1;
    }
    return params;
}

template<typename Plugin>
Plugin* get_trap_plugin(const drakvuf_trap_info_t* info)
{
    static_assert(std::is_base_of_v<pluginex, Plugin>, "Plugin must derive from pluginex");

    if (!info || !info->trap || !info->trap->data)
        return nullptr;

    auto plugin = dynamic_cast<Plugin*>(static_cast<plugin_data*>(info->trap->data)->plugin);
    if (!plugin)
    {
        PRINT_DEBUG("[PLUGINEX] nullptr at get_trap_plugin, this should never happen");
        throw -1;
    }
    return plugin;
}

template<typename Params, typename Callback>
std::unique_ptr<libhook::ReturnHook> pluginex::createReturnHook(drakvuf_trap_info* info, Callback cb, const char* display_name, int ttl)
{
    static_assert(std::is_base_of_v<PluginResult, Params>, "Params must derive from PluginResult");

    auto hook = libhook::ReturnHook::create<Params>(this->drakvuf, info, this->wrap_plugin_cb(cb), display_name, ttl);
    if (hook)
    {
        static_cast<Params*>(hook->trap_->data)->plugin_ = this;
        auto params = libhook::GetTrapParams(hook->trap_);
        params->setResultCallParams(drakvuf, info);
    }
    else
        PRINT_DEBUG("[WARNING] libhook failed to setup a trap, returning nullptr!\n");
    return hook;
}

template<typename Params, typename Callback>
std::unique_ptr<libhook::SyscallHook> pluginex::createSyscallHook(const std::string& syscall_name, Callback cb, const std::optional<std::string>& display_name, int ttl)
{
    static_assert(std::is_base_of_v<PluginResult, Params>, "Params must derive from PluginResult");

    auto hook = libhook::SyscallHook::create<Params>(this->drakvuf, syscall_name, this->wrap_plugin_cb(cb), ttl, display_name);
    if (hook)
        static_cast<Params*>(hook->trap_->data)->plugin_ = this;
    else
        PRINT_DEBUG("[WARNING] libhook failed to setup a trap, returning nullptr!\n");
    return hook;
}

template<typename Params, typename Callback>
std::unique_ptr<libhook::Cr3Hook> pluginex::createCr3Hook(Callback cb, int ttl)
{
    static_assert(std::is_base_of_v<PluginResult, Params>, "Params must derive from PluginResult");

    auto hook = libhook::Cr3Hook::create<Params>(this->drakvuf, this->wrap_plugin_cb(cb), ttl);
    if (hook)
        static_cast<Params*>(hook->trap_->data)->plugin_ = this;
    else
        PRINT_DEBUG("[WARNING] libhook failed to setup a trap, returning nullptr!\n");
    return hook;
}

template<typename Params, typename Callback>
std::unique_ptr<libhook::CpuidHook> pluginex::createCpuidHook(Callback cb, int ttl)
{
    static_assert(std::is_base_of_v<PluginResult, Params>, "Params must derive from PluginResult");

    auto hook = libhook::CpuidHook::create<Params>(this->drakvuf, this->wrap_plugin_cb(cb), ttl);
    if (hook)
        static_cast<Params*>(hook->trap_->data)->plugin_ = this;
    else
        PRINT_DEBUG("[WARNING] libhook failed to setup a trap, returning nullptr!\n");
    return hook;
}

template<typename Params, typename Callback>
std::unique_ptr<libhook::CatchAllHook> pluginex::createCatchAllHook(Callback cb, int ttl)
{
    static_assert(std::is_base_of_v<PluginResult, Params>, "Params must derive from PluginResult");

    auto hook = libhook::CatchAllHook::create<Params>(this->drakvuf, this->wrap_plugin_cb(cb), ttl);
    if (hook)
        static_cast<Params*>(hook->trap_->data)->plugin_ = this;
    else
        PRINT_DEBUG("[WARNING] libhook failed to setup a trap, returning nullptr!\n");
    return hook;
}

template<typename Params, typename Callback>
std::unique_ptr<libhook::MemAccessHook> pluginex::createMemAccessHook(Callback cb, addr_t gfn, memaccess_type_t mem_access_type, vmi_mem_access_t mem_access, int ttl)
{
    static_assert(std::is_base_of_v<PluginResult, Params>, "Params must derive from PluginResult");

    auto hook = libhook::MemAccessHook::create<Params>(this->drakvuf, wrap_plugin_cb(cb), gfn, mem_access_type, mem_access, ttl);
    if (hook)
        static_cast<Params*>(hook->trap_->data)->plugin_ = this;
    else
        PRINT_DEBUG("[WARNING] libhook failed to setup a trap, returning nullptr!\n");
    return hook;
}

template<typename Callback>
libhook::cb_wrapper_t pluginex::wrap_plugin_cb(Callback cb)
{
    static_assert(std::is_same_v<Callback, hook_cb_t> || std::is_member_function_pointer_v<Callback>,
        "Unexpected callback type passed into wrap_plugin_cb");

    if constexpr (std::is_same_v<Callback, hook_cb_t>)
        return cb;

    if constexpr (std::is_member_function_pointer_v<Callback>)
    {
        // we have a member function pointer, we need to wrap it in a lambda
        // to call it with "this" as an additional argument
        return [=](auto&& ...args) -> event_response_t
        {
            return std::invoke(cb, static_cast<typename class_type<Callback>::type*>(this), args...);
        };
    }
}

template<typename Params, typename IB>
drakvuf_trap_t* pluginex::register_trap(drakvuf_trap_info_t* info,
    hook_cb_t hook_cb,
    IB init_breakpoint,
    const char* trap_name,
    int64_t ttl,
    ah_cb_t ah_cb)
{
    auto trap = new drakvuf_trap_t();

    if constexpr (std::is_same_v<Params, void>)
    {
        trap->data = new plugin_data(this, nullptr);
    }
    else
    {
        static_assert(std::is_base_of_v<call_result_t, Params>, "Params must derive from call_result_t");
        trap->data = new plugin_data(this, new Params);
    }

    trap->name = trap_name;
    trap->cb = hook_cb;
    trap->ttl = ttl;
    trap->ah_cb = ah_cb;

    if (!init_breakpoint(drakvuf, info, trap))
    {
        PRINT_DEBUG("%s for %s\n", ERROR_MSG_ADDING_TRAP, trap_name ? trap_name : trap->name);
        delete static_cast<plugin_data*>(trap->data);
        delete trap;
        return nullptr;
    }

    traps.push_back(std::move(trap));
    return traps.back();
}

template<typename Params, typename IB>
drakvuf_trap_t* pluginex::register_trap(drakvuf_trap_info_t* info,
    hook_cb_t hook_cb,
    IB init_breakpoint,
    const char* trap_name)
{
    int64_t limited_traps_ttl = drakvuf_get_limited_traps_ttl(drakvuf);
    return register_trap<Params, IB>(info, hook_cb, init_breakpoint, trap_name, limited_traps_ttl, nullptr);
}

template<typename Params>
void pluginex::register_trap(drakvuf_trap_t* trap)
{
    if constexpr (std::is_same_v<Params, void>)
    {
        trap->data = new plugin_data(this, nullptr);
    }
    else
    {
        static_assert(std::is_base_of_v<call_result_t, Params>, "Params must derive from call_result_t");
        trap->data = new plugin_data(this, new Params);
    }

    traps.push_back(std::move(trap));
}

#endif // PLUGIN_EX_H
