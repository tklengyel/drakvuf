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

#ifndef PLUGIN_EX_H
#define PLUGIN_EX_H

#include <string>
#include <bitset>
#include <map>
#include <new>
#include <memory>

#include "private.h"
#include "plugins.h"


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

template<typename T>
struct allocator
{
    allocator() noexcept {}
    ~allocator() {}

    template<typename... _Args>
    inline T* allocate(std::size_t n, _Args&& ... args);
    void deallocate(T* p, std::size_t n)
    {
        delete[] p;
    }
};

template<typename T>
template<typename... _Args>
inline T* allocator<T>::allocate(std::size_t n, _Args&& ... args)
{
    if (n == 1)
        return new (std::nothrow) T(args...);
    else
    {
        auto p = new (std::nothrow) char(sizeof (T) * n);
        if (p)
        {
            for (std::size_t i = 0; i < n; ++i)
            {
                auto t = reinterpret_cast<T*>(p + sizeof(T) * i);
                new (t)T(args...);
            }
        }
        return reinterpret_cast<T*>(p);
    }
}

template<typename T>
struct plugin_params
{
private:
    T* source;

public:
    plugin_params(T* src) : source(src) {}
    virtual ~plugin_params() {}

    T* operator()() const noexcept
    {
        return source;
    }
    T* plugin() const noexcept
    {
        return source;
    }
};

struct breakpoint_in_system_process_searcher
{
    breakpoint_in_system_process_searcher() : m_syscall_name() {}

    breakpoint_in_system_process_searcher& for_syscall_name(const char* syscall_name)
    {
        if (syscall_name)
            m_syscall_name = syscall_name;

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

            trap->breakpoint.lookup_type = LOOKUP_PID;
            trap->breakpoint.pid = 4;
            trap->breakpoint.addr_type = ADDR_RVA;
            trap->breakpoint.module = "ntoskrnl.exe";

            trap->name = m_syscall_name;

            if (!drakvuf_add_trap(drakvuf, trap))
                return nullptr;
        }
        return trap;
    }

    const char* m_syscall_name;
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
    drakvuf_trap_t* operator()(drakvuf_t drakvuf, drakvuf_trap_info_t* info, drakvuf_trap_t* trap) const
    {
        if (trap)
        {
            access_context_t ctx =
            {
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3,
                .addr = info->regs->rsp,
            };

            addr_t ret_addr = 0;
            vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
            size_t ptr_width = drakvuf_is_wow64(drakvuf, info) ? 4 : 8;
            status_t status = vmi_read(vmi, &ctx, ptr_width, &ret_addr, nullptr);
            drakvuf_release_vmi(drakvuf);

            if (status != VMI_SUCCESS)
                return nullptr;

            trap->breakpoint.lookup_type = LOOKUP_DTB;
            trap->breakpoint.dtb = info->regs->cr3;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->breakpoint.addr = ret_addr;
            trap->breakpoint.module = info->trap->breakpoint.module;

            trap->name = info->trap->name;

            if (!drakvuf_add_trap(drakvuf, trap))
                return nullptr;
        }
        return trap;
    }
};

struct breakpoint_by_pid_searcher
{
    drakvuf_trap_t* operator()(drakvuf_t drakvuf, drakvuf_trap_info_t* info, drakvuf_trap_t* trap) const
    {
        if (trap)
        {
            access_context_t ctx =
            {
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3,
                .addr = info->regs->rsp,
            };

            addr_t ret_addr = 0;
            vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
            size_t ptr_width = drakvuf_is_wow64(drakvuf, info) ? 4 : 8;
            status_t status = vmi_read_addr(vmi, &ctx, ptr_width, &ret_addr, nullptr);
            drakvuf_release_vmi(drakvuf);

            if (status != VMI_SUCCESS)
                return nullptr;

            trap->breakpoint.lookup_type = LOOKUP_PID;
            trap->breakpoint.pid = info->trap->breakpoint.pid;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->breakpoint.addr = ret_addr;
            trap->breakpoint.module = info->trap->breakpoint.module;

            trap->name = info->trap->name;

            if (!drakvuf_add_trap(drakvuf, trap))
                return nullptr;
        }
        return trap;
    }
};

class pluginex : public plugin
{
public:
    typedef event_response_t(*hook_cb_t)(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

public:
    pluginex(drakvuf_t drakvuf, output_format_t output);
    virtual ~pluginex();

public:
    template<typename P = pluginex, typename Params = plugin_params<P>, typename IB,
             typename AP = allocator<Params>, typename AT = allocator<drakvuf_trap_t>>
    drakvuf_trap_t* register_trap(drakvuf_t drakvuf,
                                  drakvuf_trap_info_t* info,
                                  P* plugin,
                                  hook_cb_t hook_cb,
                                  IB init_breakpoint,
                                  const char* trap_name = nullptr,
                                  AP ap = allocator<Params>(),
                                  AT at = allocator<drakvuf_trap_t>())
    {
        std::unique_ptr<Params> params;
        std::unique_ptr<drakvuf_trap_t> trap;
        if (!init_memory(plugin, trap, params, hook_cb, trap_name, ap, at))
            return nullptr;

        if (!init_breakpoint(drakvuf, info, trap.get()))
        {
            PRINT_DEBUG("%s for %s\n", ERROR_MSG_ADDING_TRAP, trap_name ? trap_name : trap->name);
            return nullptr;
        }

        attach_plugin_params(trap.get());
        params.release();
        return trap.release();
    }

    virtual void destroy_trap(drakvuf_t drakvuf, drakvuf_trap_t* trap);
    drakvuf_trap_t* detach_plugin_params(drakvuf_trap_t* data);
    static void destroy_plugin_params(drakvuf_trap_t* data);

protected:
    void attach_plugin_params(drakvuf_trap_t* data);

    template<typename Plugin, typename Params, typename AP = allocator<Params>, typename AT = allocator<drakvuf_trap_t>>
    bool init_memory(Plugin* plugin,
                     std::unique_ptr<drakvuf_trap_t>& trap,
                     std::unique_ptr<Params>& params,
                     hook_cb_t hook_cb,
                     const char* trap_name = nullptr,
                     AP ap = allocator<Params>(),
                     AT at = allocator<drakvuf_trap_t>())
    {
        trap.reset(at.allocate(1));
        if (!trap)
        {
            PRINT_DEBUG("%s. Failed to allocate a memory for trap of %s\n", ERROR_MSG_ADDING_TRAP, trap_name);
            return false;
        }

        params.reset(ap.allocate(1, plugin));
        if (!params)
        {
            PRINT_DEBUG("%s. Failed to allocate a memory for trap params of %s\n", ERROR_MSG_ADDING_TRAP, trap_name);
            trap.reset();
            return false;
        }

        trap->cb = hook_cb;
        trap->data = params.get();
        trap->name = trap_name;
        trap->type = BREAKPOINT;
        return true;
    }

public:
    const output_format_t m_output_format;

private:
    GSList* m_params;
};

template<typename P, typename T = plugin_params<P>>
T* get_trap_params(const drakvuf_trap_t* trap)
{
    if (!trap || !trap->data)
        return nullptr;

    return reinterpret_cast<T*>(trap->data);
}

template<typename P, typename T = plugin_params<P>>
T* get_trap_params(const drakvuf_trap_info_t* info)
{
    if (!info || !info->trap || !info->trap->data)
        return nullptr;

    return reinterpret_cast<T*>(info->trap->data);
}

template<typename P, typename T = plugin_params<P>>
P* get_trap_plugin(const drakvuf_trap_info_t* info)
{
    if (!info || !info->trap || !info->trap->data)
        return nullptr;

    return (*reinterpret_cast<T*>(info->trap->data))();
}

template<typename T>
struct call_result_t : public plugin_params<T>
{
    call_result_t(T* src) : plugin_params<T>(src), target_cr3(), target_thread(), target_rsp() {}

    void set_result_call_params(const drakvuf_trap_info_t* info, addr_t thread)
    {
        target_thread = thread;
        target_cr3 = info->regs->cr3;
        target_rsp = info->regs->rsp;
    }

    bool verify_result_call_params(const drakvuf_trap_info_t* info, addr_t thread)
    {
        if (info->regs->cr3 != target_cr3 ||
            !thread || thread != target_thread ||
            info->regs->rsp <= target_rsp)
        {
            return false;
        }

        return true;
    }

    reg_t target_cr3;
    addr_t target_thread;
    addr_t target_rsp;
};

#endif // PLUGIN_EX_H
