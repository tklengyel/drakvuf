/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  *
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

#include "private.h"
#include "plugins.h"

namespace print
{

template<std::size_t N>
std::string FieldToString(const std::map<uint64_t, std::string>& maps, const std::bitset<N>& value)
{
    std::string str;
    std::size_t indexes = value.size();
    for (std::size_t i = 0; i < indexes; i++)
    {
        if (!value[i])
            continue;

        auto it = maps.find(value[i] << i);
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
struct plugin_params
{
private:
    T* source;

public:
    plugin_params(T* src) : source(src) {}
    virtual ~plugin_params() {}

    T* operator()() const noexcept { return source; }
    T* plugin() const noexcept { return source; }
};

class pluginex : public plugin
{
public:
    typedef event_response_t(*hook_cb_t)(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

public:
    pluginex(drakvuf_t drakvuf, output_format_t output);
    virtual ~pluginex();

public:
    struct allocate_default_trap
    {
        drakvuf_trap_t* operator()() const
        {
            return new (std::nothrow) drakvuf_trap_t;
        }
    };

    struct initialize_trap_params
    {
        drakvuf_trap_t* operator()(drakvuf_trap_t* trap, const char* syscall_name) const
        {
            if (trap)
            {
                trap->breakpoint.lookup_type = LOOKUP_PID;
                trap->breakpoint.pid = 4;
                trap->breakpoint.addr_type = ADDR_RVA;
                trap->breakpoint.module = "ntoskrnl.exe";
                trap->type = BREAKPOINT;
                trap->name = syscall_name;
            }
            return trap;
        }
    };

    struct initialize_dll_trap_params
    {
        drakvuf_trap_t* operator()(drakvuf_trap_t* trap, const char* syscall_name, const char* module_name) const
        {
            if (trap)
            {
                trap->breakpoint.lookup_type = LOOKUP_PID;
                trap->breakpoint.addr_type = ADDR_VA;
                trap->breakpoint.module = module_name;
                trap->type = BREAKPOINT;
                trap->name = syscall_name;
            }
            return trap;
        }
    };

    struct initialize_result_trap_params_by_DTB
    {
        drakvuf_trap_t* operator()(drakvuf_trap_t* trap, drakvuf_trap_info_t* info, addr_t ret_addr) const
        {
            if (trap)
            {
                trap->breakpoint.lookup_type = LOOKUP_DTB;
                trap->breakpoint.dtb = info->regs->cr3;
                trap->breakpoint.addr_type = ADDR_VA;
                trap->breakpoint.addr = ret_addr;
                trap->breakpoint.module = info->trap->breakpoint.module;
                trap->type = BREAKPOINT;
                trap->name = info->trap->name;
            }
            return trap;
        }
    };

    struct initialize_result_trap_params_by_PID
    {
        drakvuf_trap_t* operator()(drakvuf_trap_t* trap, drakvuf_trap_info_t* info, addr_t ret_addr) const
        {
            if (trap)
            {
                trap->breakpoint.lookup_type = LOOKUP_PID;
                trap->breakpoint.pid = info->trap->breakpoint.pid;
                trap->breakpoint.addr_type = ADDR_VA;
                trap->breakpoint.addr = ret_addr;
                trap->breakpoint.module = info->trap->breakpoint.module;
                trap->type = BREAKPOINT;
                trap->name = info->trap->name;
            }
            return trap;
        }
    };

    template<typename P, typename PMS = plugin_params<pluginex>, typename SP = initialize_result_trap_params_by_PID, typename AT = allocate_default_trap>
    drakvuf_trap_t* register_result_trap(drakvuf_t drakvuf, drakvuf_trap_info_t* info, hook_cb_t hook_cb, P* plugin,
                                         SP set_params = initialize_result_trap_params_by_PID(), AT allocate_trap = allocate_default_trap())
    {
        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = info->regs->rsp,
        };

        addr_t ret_addr;
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        status_t status = vmi_read_addr(vmi, &ctx, &ret_addr);
        drakvuf_release_vmi(drakvuf);

        if (status != VMI_SUCCESS)
            return nullptr;

        auto trap = allocate_trap();
        if (!trap)
        {
            PRINT_DEBUG("Failed to allocate a memory for trap of %s\n", info->trap->breakpoint.module);
            return nullptr;
        }

        auto params = new (std::nothrow) PMS(plugin);
        if (!params)
        {
            PRINT_DEBUG("Failed to allocate a memory for params of trap\n");
            delete trap;
            return nullptr;
        }

        set_params(trap, info, ret_addr);
        trap->cb = hook_cb;
        trap->data = params;

        attach_plugin_params(trap);

        if (!drakvuf_add_trap(drakvuf, trap))
        {
            PRINT_DEBUG("Failed to create a trap\n");
            destroy_plugin_params(detach_plugin_params(trap));
            return nullptr;
        }
        return trap;
    }

    virtual void destroy_trap(drakvuf_t drakvuf, drakvuf_trap_t* trap);
    drakvuf_trap_t* detach_plugin_params(drakvuf_trap_t* data);
    static void destroy_plugin_params(drakvuf_trap_t* data);

protected:
    template<typename P = pluginex, typename PMS = plugin_params<P>, typename SP = initialize_trap_params, typename AT = allocate_default_trap>
    drakvuf_trap_t* register_trap(drakvuf_t drakvuf, const char* syscall_name, hook_cb_t hook_cb, P* plugin,
                                  SP set_params = initialize_trap_params(), AT allocate_trap = allocate_default_trap())
    {
        auto trap = allocate_trap();
        if (!trap)
        {
            PRINT_DEBUG("Failed to allocate a memory for trap of %s\n", syscall_name);
            throw -1;
        }

        auto params = new (std::nothrow) PMS(plugin);
        if (!params)
        {
            PRINT_DEBUG("Failed to allocate a memory for params of trap\n");
            delete trap;
            throw -1;
        }

        set_params(trap, syscall_name);
        trap->cb = hook_cb;
        trap->data = params;

        attach_plugin_params(trap);
        if (!drakvuf_get_function_rva(drakvuf, syscall_name, &trap->breakpoint.rva))
        {
            PRINT_DEBUG("Failed to receive addr of breakpoint.rva\n");
            destroy_plugin_params(detach_plugin_params(trap));
            throw -1;
        }

        if (!drakvuf_add_trap(drakvuf, trap))
        {
            PRINT_DEBUG("Failed to create a trap\n");
            destroy_plugin_params(detach_plugin_params(trap));
            throw -1;
        }
        return trap;
    }

    template<typename P = pluginex, typename PMS = plugin_params<P>, typename SP = initialize_dll_trap_params, typename AT = allocate_default_trap>
    drakvuf_trap_t* register_dll_trap(drakvuf_t drakvuf, json_object* rekall_profile, const char* module_name,
                                      const char* syscall_name, event_response_t(*cb)(drakvuf_t, drakvuf_trap_info_t*), P* plugin, bool wow = false,
                                      SP set_params = initialize_dll_trap_params(), AT allocate_trap = allocate_default_trap())
    {
        auto trap = allocate_trap();
        if (!trap)
        {
            PRINT_DEBUG("Failed to allocate a memory for trap of %s\n", syscall_name);
            throw -1;
        }

        auto params = new (std::nothrow) PMS(plugin);
        if (!params)
        {
            PRINT_DEBUG("Failed to allocate a memory for params of trap\n");
            delete trap;
            throw -1;
        }

        set_params(trap, syscall_name, module_name);
        trap->cb = cb;
        trap->data = params;

        attach_plugin_params(trap);

        trap_context_dll ctx(trap, wow);
        PRINT_DEBUG("[PLUGIN_EX] Search for %s'%s!%s'\n", wow ? "WoW64 " : "", trap->breakpoint.module, syscall_name);
        if (!rekall_get_function_rva(rekall_profile, syscall_name, &ctx.function_rva))
        {
            PRINT_DEBUG("[PLUGIN_EX] Failed to get function %s address\n", syscall_name);
            destroy_plugin_params(detach_plugin_params(trap));
            throw -1;
        }

        if (!drakvuf_enumerate_processes_with_module(drakvuf, trap->breakpoint.module, module_trap_visitor, &ctx))
        {
            PRINT_DEBUG("[PLUGIN_EX] Failed to trap function %s!%s\n", trap->breakpoint.module, syscall_name);
            destroy_plugin_params(detach_plugin_params(trap));
            throw -1;
        }
        return trap;
    }

    void attach_plugin_params(drakvuf_trap_t* data);

protected:
    struct trap_context_dll
    {
        trap_context_dll(drakvuf_trap_t* t, bool w) : wow(w), function_rva(), trap(t) {}

        bool wow;
        addr_t function_rva;
        drakvuf_trap_t* trap;
    };

    static bool module_trap_visitor(drakvuf_t drakvuf, const module_info_t* module_info, void* ctx);

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

#endif // PLUGIN_EX_H
