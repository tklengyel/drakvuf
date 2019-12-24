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

#include "wmimon.h"
#include "private.h"

bool FAILED(unsigned long rax)
{
    return (rax & 0x80000000) != 0;
}

int uuid_compare(const uuid_t uu1, const uuid_t uu2)
{
    int res;
    for (std::size_t i = 0; i < 16; ++i)
    {
        if ((res = static_cast<char>(uu1[i]) - static_cast<char>(uu2[i])))
            return res;
    }

    return 0;
}

static char* search_module_name_by_addr(drakvuf_t drakvuf, const size_t* offsets, vmi_pid_t pid, addr_t addr)
{
    addr_t module_list = 0;
    addr_t process_addr = 0;
    if (!drakvuf_find_process(drakvuf, pid, nullptr, &process_addr))
        return nullptr;

    if (!drakvuf_get_module_list(drakvuf, process_addr, &module_list))
        return nullptr;

    addr_t next_module = module_list;
    addr_t tmp_next;
    addr_t image_base;
    addr_t image_size;

    while (true)
    {
        vmi_lock_guard wmi_lock(drakvuf);
        if (VMI_FAILURE == vmi_read_addr_va(wmi_lock, next_module, pid, &tmp_next))
            break;

        if (module_list == tmp_next)
            break;

        if (VMI_FAILURE == vmi_read_addr_va(wmi_lock, next_module + offsets[LDR_DATA_TABLE_ENTRY_DLLBASE], pid, &image_base))
            break;

        if (!image_base)
            break;

        if (VMI_FAILURE == vmi_read_addr_va(wmi_lock, next_module + offsets[LDR_DATA_TABLE_ENTRY_SIZEOFIMAGE], pid, &image_size))
            break;

        if (!image_size)
            break;

        unicode_string_t* us = vmi_read_unicode_str_va(wmi_lock, next_module + offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME], pid);
        unicode_string_t out = { .contents = NULL };

        if (us)
        {
            status_t status = vmi_convert_str_encoding(us, &out, "UTF-8");
            if (VMI_SUCCESS == status)
                PRINT_DEBUG("\t%s @ 0x%" PRIx64 "\n", out.contents, image_base);

            vmi_free_unicode_str(us);
        }

        if (image_base < addr && addr < image_base + image_size)
            return reinterpret_cast<char*>(out.contents);

        g_free(out.contents);
        next_module = tmp_next;
    }

    return nullptr;
}

struct search_breakpoint_by_addr
{
    search_breakpoint_by_addr() : m_addr(), m_plugin() {}
    search_breakpoint_by_addr(const wmimon* plugin, addr_t addr) : m_addr(addr), m_plugin(plugin) {}

    search_breakpoint_by_addr& set_addr(addr_t addr)
    {
        m_addr = addr;
        return *this;
    }

    static bool module_visitor(drakvuf_t drakvuf, const module_info_t* module_info, void* ctx)
    {
        const auto* data = reinterpret_cast<context*>(ctx);
        if (!data || module_info->is_wow != data->m_is_wow || module_info->pid == data->m_pid)
            return false;

        data->m_trap->breakpoint.lookup_type = LOOKUP_PID;
        data->m_trap->breakpoint.pid = module_info->pid;

        return drakvuf_add_trap(drakvuf, data->m_trap);
    }

    drakvuf_trap_t* operator()(drakvuf_t drakvuf, drakvuf_trap_info_t* info, drakvuf_trap_t* trap) const
    {
        if (trap)
        {
            addr_t addr;
            access_context_t ctx =
            {
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3,
                .addr = m_addr
            };

            trap->breakpoint.addr = m_addr;
            trap->breakpoint.addr_type = ADDR_VA;

            auto vmi = drakvuf_lock_and_get_vmi(drakvuf);
            status_t stt = vmi_read_64(vmi, &ctx, &addr);
            drakvuf_release_vmi(drakvuf);

            if (stt == VMI_SUCCESS)
            {
                PRINT_DEBUG("Register trap in self process. PID: %u\n", info->proc_data.pid);
                trap->breakpoint.lookup_type = LOOKUP_DTB;
                trap->breakpoint.dtb = info->regs->cr3;
                trap->breakpoint.module = info->trap->breakpoint.module;
                if (!drakvuf_add_trap(drakvuf, trap))
                    return nullptr;
            }
            else
            {
                auto module_name = search_module_name_by_addr(drakvuf, m_plugin->Offsets(), info->proc_data.pid, m_addr);
                if (!module_name)
                {
                    PRINT_DEBUG("Failed to search a module by image base %lx\n", m_addr);
                    return nullptr;
                }
                else
                {
                    context _ctx(info->proc_data.pid, trap, false);
                    if (!drakvuf_enumerate_processes_with_module(drakvuf, module_name, module_visitor, &_ctx))
                    {
                        PRINT_DEBUG("Failed to search a other process with loaded module %s\n", module_name);
                        g_free(module_name);
                        return nullptr;
                    }
                }
                g_free(module_name);
            }
        }
        return trap;
    }

    struct context
    {
        context(vmi_pid_t pid, drakvuf_trap_t* trap, bool w) : m_is_wow(w), m_pid(pid), m_trap(trap) {}

        bool m_is_wow;
        vmi_pid_t m_pid;
        drakvuf_trap_t* m_trap;
    };

    addr_t m_addr;
    const wmimon* m_plugin;
};

template <typename T>
struct CoCreateInstanse : public call_result_t<T>
{
    CoCreateInstanse(T* src) : call_result_t<T>(src), CLSID(), IID(), m_vtable() {}

    addr_t CLSID;
    addr_t IID;
    addr_t m_vtable;
};

template <typename T>
struct ConnectServerParams : public call_result_t<T>
{
    ConnectServerParams(T* src) : call_result_t<T>(src), m_resource(), m_vtable() {}

    addr_t m_resource;
    addr_t m_vtable;
};

template <typename T>
struct ExecQueryParams : public call_result_t<T>
{
    ExecQueryParams(T* src) : call_result_t<T>(src), m_command(), m_vtable() {}

    addr_t m_command;
    addr_t m_vtable;
};

template <typename T>
struct ExecMethodParams : public call_result_t<T>
{
    ExecMethodParams(T* src) : call_result_t<T>(src), m_object(), m_method(), m_vtable() {}

    addr_t m_object;
    addr_t m_method;
    addr_t m_vtable;
};

class vtable
{
public:
    vtable(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t va, size_t count)
        : m_address_width(drakvuf_get_address_width(drakvuf))
        , m_mask((1ULL << m_address_width * 8) - 1)
        , m_buffer(count * m_address_width)
    {
        if (!read_vtable_elements(drakvuf, info, va, count))
            throw std::runtime_error("[WMIMon] Failed to read a vtable\n");
    }

    uint64_t operator[](size_t index) const
    {
        return *reinterpret_cast<const uint64_t*>(&m_buffer[index * m_address_width]) & m_mask;
    }

private:
    int m_address_width;
    uint64_t m_mask;
    std::vector<uint8_t> m_buffer;

    inline bool read_vtable_elements(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t va, size_t count)
    {
        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = va
        };

        addr_t vtable_addr;
        vmi_lock_guard lock(drakvuf);
        if (VMI_SUCCESS != vmi_read_addr(lock, &ctx, &vtable_addr))
        {
            PRINT_DEBUG("[WMIMon] Failed to read addr of vtable. Step 1\n");
            return false;
        }

        ctx.addr = vtable_addr;
        if (VMI_SUCCESS != vmi_read_addr(lock, &ctx, &vtable_addr))
        {
            PRINT_DEBUG("[WMIMon] Failed to read addr of vtable. Step 2\n");
            return false;
        }

        ctx.addr = vtable_addr;
        if (VMI_SUCCESS != vmi_read(lock, &ctx, count * m_address_width, m_buffer.data(), nullptr))
        {
            PRINT_DEBUG("[WMIMon] Failed to read addr of vtable. Step 3\n");
            return false;
        }

        return true;
    }
};

event_response_t ExecMethod_return_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<wmimon, ExecMethodParams<wmimon>>(info);
    auto plugin = get_trap_plugin<wmimon, ExecMethodParams<wmimon>>(info);
    if (!plugin || !data)
    {
        PRINT_DEBUG("[WMIMon] ExecMethodReturn invalid trap params\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!data->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    plugin->destroy_trap(drakvuf, info->trap);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = data->m_object
    };

    vmi_lock_guard wmi_lock(drakvuf);
    auto object = drakvuf_read_wchar_string(wmi_lock, &ctx);
    if (!object)
    {
        PRINT_DEBUG("[WMIMon] ExecMethodReturn failed to receive a name of object!\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    ctx.addr = data->m_method;
    auto method = drakvuf_read_wchar_string(wmi_lock, &ctx);
    if (!method)
    {
        PRINT_DEBUG("[WMIMon] ExecMethodReturn failed to receive a name of method!\n");
        vmi_free_unicode_str(object);
        return VMI_EVENT_RESPONSE_NONE;
    }

    wmi_lock.unlock();

    switch (plugin->m_output_format)
    {
        case OUTPUT_CSV:
            printf("wmimon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%s,%s,%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->trap->name, reinterpret_cast<char*>(object->contents), reinterpret_cast<char*>(method->contents));
            break;
        case OUTPUT_KV:
            printf("wmimon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,Object=\"%s\",Function=\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->trap->name, reinterpret_cast<char*>(object->contents),
                   reinterpret_cast<char*>(method->contents));
            break;
        case OUTPUT_JSON:
        {
            char proc_name[] = "invalid";
            printf("{"
                   "\"Plugin\" : \"wmimon\","
                   "\"TimeStamp\" :"
                   "\"" FORMAT_TIMEVAL "\","
                   "\"ProcessName\": \"%s\","
                   "\"PID\" : %d,"
                   "\"PPID\": %d,"
                   "\"Method\" : \"%s\","
                   "\"Object\": \"%s\", "
                   "\"Function\": \"%s\","
                   "}\n",
                   UNPACK_TIMEVAL(info->timestamp),
                   proc_name,
                   info->proc_data.pid,
                   info->proc_data.ppid,
                   info->trap->name,
                   reinterpret_cast<char*>(object->contents),
                   reinterpret_cast<char*>(method->contents));
            break;
        }
        default:
        case OUTPUT_DEFAULT:
            printf("[WMIMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\":%s,Object:\"%s\",Function:\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->trap->name, reinterpret_cast<char*>(object->contents), reinterpret_cast<char*>(method->contents));
            break;
    }

    vmi_free_unicode_str(object);
    vmi_free_unicode_str(method);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t ExecMethod_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<wmimon>(info);
    auto plugin = get_trap_plugin<wmimon>(info);
    if (!plugin || !data)
    {
        PRINT_DEBUG("[WMIMon] ExecMethod invalid trap params!\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto trap = plugin->register_trap<wmimon, ExecMethodParams<wmimon>>(
                    drakvuf,
                    info,
                    plugin,
                    ExecMethod_return_handler,
                    breakpoint_by_dtb_searcher());

    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto params = get_trap_params<wmimon, ExecMethodParams<wmimon>>(trap);
    if (!params)
    {
        plugin->destroy_trap(drakvuf, trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    params->m_object = drakvuf_get_function_argument(drakvuf, info, 2);
    params->m_method = drakvuf_get_function_argument(drakvuf, info, 3);
    params->m_vtable = drakvuf_get_function_argument(drakvuf, info, 6);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t GetObject_return_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<wmimon, ExecMethodParams<wmimon>>(info);
    auto plugin = get_trap_plugin<wmimon, ExecMethodParams<wmimon>>(info);
    if (!plugin || !data)
    {
        PRINT_DEBUG("[WMIMon] GetObjectReturn invalid trap params\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!data->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    plugin->destroy_trap(drakvuf, info->trap);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = data->m_object
    };

    auto vmi = drakvuf_lock_and_get_vmi(drakvuf);
    auto object = drakvuf_read_wchar_string(vmi, &ctx);
    drakvuf_release_vmi(drakvuf);

    if (!object)
    {
        PRINT_DEBUG("[WMIMon] ExecQueryReturn failed to receive a name of object!\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    switch (plugin->m_output_format)
    {
        case OUTPUT_CSV:
            printf("wmimon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%s,%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->trap->name, reinterpret_cast<char*>(object->contents));
            break;
        case OUTPUT_KV:
            printf("wmimon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,Object=\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->trap->name, reinterpret_cast<char*>(object->contents));
            break;
        case OUTPUT_JSON:
        {
            char proc_name[] = "invalid";
            printf("{"
                   "\"Plugin\" : \"wmimon\","
                   "\"TimeStamp\" :"
                   "\"" FORMAT_TIMEVAL "\","
                   "\"ProcessName\": \"%s\","
                   "\"PID\" : %d,"
                   "\"PPID\": %d,"
                   "\"Method\" : \"%s\","
                   "\"Object\": \"%s\""
                   "}\n",
                   UNPACK_TIMEVAL(info->timestamp),
                   proc_name,
                   info->proc_data.pid,
                   info->proc_data.ppid,
                   info->trap->name,
                   reinterpret_cast<char*>(object->contents));
            break;
        }
        default:
        case OUTPUT_DEFAULT:
            printf("[WMIMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\":%s,Object:\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->trap->name, reinterpret_cast<char*>(object->contents));
            break;
    }

    vmi_free_unicode_str(object);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t GetObject_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<wmimon>(info);
    auto plugin = get_trap_plugin<wmimon>(info);
    if (!plugin || !data)
    {
        PRINT_DEBUG("[WMIMon] GetObject invalid trap params!\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto trap = plugin->register_trap<wmimon, ExecMethodParams<wmimon>>(
                    drakvuf,
                    info,
                    plugin,
                    GetObject_return_handler,
                    breakpoint_by_dtb_searcher());

    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto params = get_trap_params<wmimon, ExecMethodParams<wmimon>>(trap);
    if (!params)
    {
        plugin->destroy_trap(drakvuf, trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    params->m_object = drakvuf_get_function_argument(drakvuf, info, 2);
    params->m_vtable = drakvuf_get_function_argument(drakvuf, info, 5);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t ExecQuery_return_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<wmimon, ExecQueryParams<wmimon>>(info);
    auto plugin = get_trap_plugin<wmimon, ExecQueryParams<wmimon>>(info);
    if (!plugin || !data)
    {
        PRINT_DEBUG("[WMIMon] ExecQueryReturn invalid trap params\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!data->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    plugin->destroy_trap(drakvuf, info->trap);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = data->m_command
    };

    auto vmi = drakvuf_lock_and_get_vmi(drakvuf);
    auto command = drakvuf_read_wchar_string(vmi, &ctx);
    drakvuf_release_vmi(drakvuf);

    if (!command)
    {
        PRINT_DEBUG("[WMIMon] ExecQueryReturn failed to receive command!\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    switch (plugin->m_output_format)
    {
        case OUTPUT_CSV:
            printf("wmimon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%s,%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->trap->name, reinterpret_cast<char*>(command->contents));
            break;
        case OUTPUT_KV:
            printf("wmimon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,Command=\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->trap->name, reinterpret_cast<char*>(command->contents));
            break;
        case OUTPUT_JSON:
        {
            char proc_name[] = "invalid";
            printf("{"
                   "\"Plugin\" : \"wmimon\","
                   "\"TimeStamp\" :"
                   "\"" FORMAT_TIMEVAL "\","
                   "\"ProcessName\": \"%s\","
                   "\"PID\" : %d,"
                   "\"PPID\": %d,"
                   "\"Method\" : \"%s\","
                   "\"Command\": \"%s\""
                   "}\n",
                   UNPACK_TIMEVAL(info->timestamp),
                   proc_name,
                   info->proc_data.pid,
                   info->proc_data.ppid,
                   info->trap->name,
                   reinterpret_cast<char*>(command->contents));
            break;
        }
        default:
        case OUTPUT_DEFAULT:
            printf("[WMIMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\":%s,Command:\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->trap->name, reinterpret_cast<char*>(command->contents));
            break;
    }

    vmi_free_unicode_str(command);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t ExecQuery_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<wmimon>(info);
    auto plugin = get_trap_plugin<wmimon>(info);
    if (!plugin || !data)
    {
        PRINT_DEBUG("[WMIMon] ExecQuery invalid trap params!\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto trap = plugin->register_trap<wmimon, ExecQueryParams<wmimon>>(
                    drakvuf,
                    info,
                    plugin,
                    ExecQuery_return_handler,
                    breakpoint_by_dtb_searcher());

    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto params = get_trap_params<wmimon, ExecQueryParams<wmimon>>(trap);
    if (!params)
    {
        plugin->destroy_trap(drakvuf, trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    params->m_command = drakvuf_get_function_argument(drakvuf, info, 3);
    params->m_vtable = drakvuf_get_function_argument(drakvuf, info, 6);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t ConnectServer_return_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<wmimon, ConnectServerParams<wmimon>>(info);
    auto plugin = get_trap_plugin<wmimon, ConnectServerParams<wmimon>>(info);
    if (!plugin || !data)
    {
        PRINT_DEBUG("[WMIMon] ConnectServerReturn invalid trap params\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!data->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
        return VMI_EVENT_RESPONSE_NONE;

    plugin->destroy_trap(drakvuf, info->trap);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = data->m_resource
    };

    auto vmi = drakvuf_lock_and_get_vmi(drakvuf);
    auto resource = drakvuf_read_wchar_string(vmi, &ctx);
    drakvuf_release_vmi(drakvuf);

    if (!resource)
    {
        PRINT_DEBUG("[WMIMon] ConnectServerReturn failed to receive resource!\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    switch (plugin->m_output_format)
    {
        case OUTPUT_CSV:
            printf("wmimon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%s,%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->trap->name, reinterpret_cast<char*>(resource->contents));
            break;
        case OUTPUT_KV:
            printf("wmimon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,Resource=\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->trap->name, reinterpret_cast<char*>(resource->contents));
            break;
        case OUTPUT_JSON:
        {
            char proc_name[] = "invalid";
            printf("{"
                   "\"Plugin\" : \"wmimon\","
                   "\"TimeStamp\" :"
                   "\"" FORMAT_TIMEVAL "\","
                   "\"ProcessName\": \"%s\","
                   "\"PID\" : %d,"
                   "\"PPID\": %d,"
                   "\"Method\" : \"%s\","
                   "\"Resource\" : \"%s\""
                   "}\n",
                   UNPACK_TIMEVAL(info->timestamp),
                   proc_name,
                   info->proc_data.pid,
                   info->proc_data.ppid,
                   info->trap->name,
                   reinterpret_cast<char*>(resource->contents));
            break;
        }
        default:
        case OUTPUT_DEFAULT:
            printf("[WMIMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\":%s,Resource:%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->trap->name, reinterpret_cast<char*>(resource->contents));
            break;
    }

    vmi_free_unicode_str(resource);

    try
    {
        vtable vt(drakvuf, info, data->m_vtable, 26);

        search_breakpoint_by_addr bp(plugin, vt[20]);
        plugin->register_trap<wmimon>(drakvuf, info, plugin, ExecQuery_handler,
                                      bp, "ExecQuery");

        plugin->register_trap<wmimon>(drakvuf, info, plugin, GetObject_handler,
                                      bp.set_addr(vt[6]), "GetObject");

        plugin->register_trap<wmimon>(drakvuf, info, plugin, ExecMethod_handler,
                                      bp.set_addr(vt[24]), "ExecMethod");
    }
    catch (const std::exception& e)
    {
        PRINT_DEBUG("[WMIMon] Failed to read a vtable of IWbemServices\n");
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t ConnectServer_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<wmimon>(info);
    auto plugin = get_trap_plugin<wmimon>(info);
    if (!plugin || !data)
    {
        PRINT_DEBUG("[WMIMon] ConnectServer invalid trap params!\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto trap = plugin->register_trap<wmimon, ConnectServerParams<wmimon>>(
                    drakvuf,
                    info,
                    plugin,
                    ConnectServer_return_handler,
                    breakpoint_by_dtb_searcher());

    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto params = get_trap_params<wmimon, ConnectServerParams<wmimon>>(trap);
    if (!params)
    {
        plugin->destroy_trap(drakvuf, trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    params->m_resource = drakvuf_get_function_argument(drakvuf, info, 2);
    params->m_vtable = drakvuf_get_function_argument(drakvuf, info, 9);

    plugin->destroy_trap(drakvuf, info->trap);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t CoCreateInstanse_return_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto data = get_trap_params<wmimon, CoCreateInstanse<wmimon>>(info);
    auto plugin = get_trap_plugin<wmimon, CoCreateInstanse<wmimon>>(info);
    if (!plugin || !data)
    {
        PRINT_DEBUG("[WMIMon] CoCreateInstanse_return invalid trap params!\n");
        drakvuf_remove_trap(drakvuf, info->trap, nullptr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!data->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)) || FAILED(info->regs->rax))
        return VMI_EVENT_RESPONSE_NONE;

    plugin->destroy_trap(drakvuf, info->trap);

    try
    {
        vtable vt(drakvuf, info, data->m_vtable, 4);

        plugin->register_trap<wmimon>(drakvuf, info, plugin, ConnectServer_handler,
                                      search_breakpoint_by_addr(plugin, vt[3]), "ConnectServer");
    }
    catch (const std::exception& e)
    {
        PRINT_DEBUG("[WMIMon] Failed to read a vtable of IWbemLocator\n");
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t CoCreateInstanse_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<wmimon>(info);
    if (!plugin)
    {
        PRINT_DEBUG("[WMIMon] CoCreateInstanse invalid trap params!\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = drakvuf_get_function_argument(drakvuf, info, 1)
    };

    {
        uuid_t guid;
        vmi_lock_guard lock(drakvuf);
        if (VMI_SUCCESS != vmi_read(lock, &ctx, sizeof(guid), &guid, nullptr))
        {
            PRINT_DEBUG("[WMIMon] CoCreateInstanse. Failed to read CLSID\n");
            return VMI_EVENT_RESPONSE_NONE;
        }

        if (uuid_compare(guid, CLSID_WbemLocator))
            return VMI_EVENT_RESPONSE_NONE;

        ctx.addr = drakvuf_get_function_argument(drakvuf, info, 4);
        if (VMI_SUCCESS != vmi_read(lock, &ctx, sizeof(guid), &guid, nullptr))
        {
            PRINT_DEBUG("[WMIMon] CreateInstanse. Failed to read IID\n");
            return VMI_EVENT_RESPONSE_NONE;
        }

        if (uuid_compare(guid, IID_IWbemLocator))
            return VMI_EVENT_RESPONSE_NONE;
    }

    auto trap = plugin->register_trap<wmimon, CoCreateInstanse<wmimon>>(drakvuf,
                info,
                plugin,
                CoCreateInstanse_return_handler,
                breakpoint_by_dtb_searcher());

    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto params = get_trap_params<wmimon, CoCreateInstanse<wmimon>>(trap);
    if (!params)
    {
        plugin->destroy_trap(drakvuf, trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    params->CLSID = drakvuf_get_function_argument(drakvuf, info, 1);
    params->IID = drakvuf_get_function_argument(drakvuf, info, 4);
    params->m_vtable = drakvuf_get_function_argument(drakvuf, info, 5);

    plugin->destroy_trap(drakvuf, info->trap);
    return VMI_EVENT_RESPONSE_NONE;
}

wmimon::wmimon(drakvuf_t drakvuf, const wmimon_config* c, output_format_t output)
    : pluginex(drakvuf, output)
    , m_offsets(new size_t[__OFFSET_MAX])
{
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, __OFFSET_MAX, m_offsets))
    {
        PRINT_DEBUG("[WMIMon] plugin failed to receive the offset a members of eprocess struct\n");
        return;
    }

    uint8_t addr_width = 0;
    win_ver_t winver;
    {
        vmi_lock_guard guard(drakvuf);
        winver = vmi_get_winver(guard);
        addr_width = vmi_get_address_width(guard);
    }

    if (!c->ole32_profile)
    {
        PRINT_DEBUG("[WMIMon] plugin requires the JSON debug info for \"ole32.dll\"!\n");
        return;
    }

    if (addr_width == 8 && !c->wow_ole32_profile)
    {
        PRINT_DEBUG("[WMIMon] plugin requires the JSON debug info for \"SysWOW64/ole32.dll\"!\n");
        return;
    }

    if (VMI_OS_WINDOWS_7 < winver && !c->combase_profile)
    {
        PRINT_DEBUG("[WMIMon] plugin fails to load JSON debug info for \"combase.dll\"\n");
        return;
    }

    auto dll_profile = VMI_OS_WINDOWS_7 < winver ? c->combase_profile : c->ole32_profile;
    auto dll_name = VMI_OS_WINDOWS_7 < winver ? "combase.dll" : "ole32.dll";
    json_object* profile = json_object_from_file(dll_profile);
    if (!profile)
    {
        PRINT_DEBUG("[WMIMon] plugin fails to load JSON debug info for \"%s\"\n", dll_name);
        throw - 1;
    }

    PRINT_DEBUG("[WMIMon] attempt to setup a trap for \"%s::CoCreateInstance\"\n", dll_name);
    breakpoint_in_dll_module_searcher bp(profile, dll_name);
    if (!register_trap<wmimon>(drakvuf, nullptr, this, CoCreateInstanse_handler, bp.for_syscall_name("CoCreateInstance")))
        throw -1;

    // if (c->wow_ole32_profile)
    // {
    //     PRINT_DEBUG("[WMIMon] plugin JSON debug info for \"SysWOW64/ole32.dll\":%s\n", c->wow_ole32_profile);
    //     json_object* wow_ole32_profile = json_object_from_file(c->wow_ole32_profile);
    //     if (!wow_ole32_profile)
    //     {
    //         PRINT_DEBUG("[WMIMon] plugin failed to load JSON debug info for \"SysWOW64/ole32.dll\"\n");
    //         throw -1;
    //     }

    //     if (VMI_OS_WINDOWS_7 < winver)
    //     {
    //         PRINT_DEBUG("[WMIMon] attempt to setup a trap for \"SysWOW64/ole32.dll\"\n");
    //         register_dll_trap(drakvuf, wow_ole32_profile, "ole32.dll", "CoCreateInstance", trap_CoCreateInstance, this);
    //     }
    //     json_object_put(wow_ole32_profile);
    // }

    json_object_put(profile);
}
