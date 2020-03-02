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

/**
 * User mode hooking module of MEMDUMP plugin.
 *
 * (1) Observes when a process is loading a new DLL through the side effects
 * of NtMapViewOfSection or NtProtectVirtualMemory being called.
 * (2) Finds the DLL export information and checks if it's fully readable,
 * if not, triggers a page fault to force system to load it into memory.
 * (3) Translates given export symbols to virtual addresses, checks if
 * the underlying memory is available (if not, again triggers page fault)
 * and finally adds a standard DRAKVUF trap.
 */

#include <fstream>
#include <sstream>
#include <map>
#include <string>

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <libdrakvuf/private.h>
#include <libusermode/userhook.hpp>
#include <assert.h>

#include "memdump.h"
#include "private.h"
#include "crypto.h"

void print_arguments(std::vector < uint64_t > arguments)
{
    size_t i = 0;
    for (auto it = arguments.begin(); it != arguments.end(); it++, i++)
    {
        printf("0x%lX", *it);
        if (i < arguments.size() - 1)
            printf(",");
    }
}

void print_extra_data(std::map < std::string, std::string > extra_data)
{
    size_t i = 0;
    for (auto it = extra_data.begin(); it != extra_data.end(); it++, i++)
    {
        printf("\"%s\": \"%s\"", it->first.c_str(), it->second.c_str());
        if (i < extra_data.size() - 1)
            printf(", ");
    }
}

static event_response_t usermode_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    return_hook_target_entry_t* ret_target = (return_hook_target_entry_t*)info->trap->data;
    if (info->proc_data.pid != ret_target->pid)
        return VMI_EVENT_RESPONSE_NONE;

    auto plugin = (memdump*)ret_target->plugin;

    std::map < std::string, std::string > extra_data;

    if(!strcmp(info->trap->name, "CryptGenKey"))
        extra_data = CryptGenKey_hook(drakvuf, info, ret_target->arguments);

    gchar* escaped_pname;
    switch (plugin->m_output_format)
    {
        case OUTPUT_CSV:
            printf("memdump-userhok," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",\"%s\",0x%" PRIx64 ",0x%" PRIx64 ",\"",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, info->trap->name, info->regs->rax, info->regs->rip);
            print_arguments(ret_target->arguments);
            printf("\"");
            break;
        case OUTPUT_KV:
            printf("memdump, Time=" FORMAT_TIMEVAL ",VCPU=%" PRIu32 ",CR3=0x%" PRIx64 ",ProcessName=\"%s\",UserID=%" PRIi64 ",Method=\"%s\",CalledFrom=0x%" PRIx64 ",ReturnValue=0x%" PRIx64 ",Arguments=\"",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, info->trap->name, info->regs->rip, info->regs->rax);
            print_arguments(ret_target->arguments);
            printf("\"");
            break;
        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            printf( "{"
                    "\"Plugin\": \"memdump-userhook\", "
                    "\"TimeStamp\":" "\"" FORMAT_TIMEVAL "\", "
                    "\"ProcessName\": %s, "
                    "\"UserName\": \"%s\", "
                    "\"UserId\": %" PRIu64 ", "
                    "\"PID\": %d, "
                    "\"PPID\": %d, "
                    "\"Method\": \"%s\", "
                    "\"CalledFrom\": 0x%" PRIx64 ", "
                    "\"ReturnValue\": 0x%" PRIx64 ", "
                    "\"Arguments\": [",
                    UNPACK_TIMEVAL(info->timestamp),
                    escaped_pname,
                    USERIDSTR(drakvuf), info->proc_data.userid,
                    info->proc_data.pid, info->proc_data.ppid,
                    info->trap->name,
                    info->regs->rip,
                    info->regs->rax);

            print_arguments(ret_target->arguments);
            printf("], "
                   "\"Extra\": {");
            print_extra_data(extra_data);
            printf("}}");
            g_free(escaped_pname);
            break;
        default:
        case OUTPUT_DEFAULT:
            printf("[MEMDUMP-USERHOOK] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 " ProcessName:\"%s\" UserID:%" PRIi64 " Method:\"%s\" CalledFrom:0x%" PRIx64 " ReturnValue:0x%" PRIx64 " Arguments:\"",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, info->trap->name, info->regs->rax, info->regs->rip);
            print_arguments(ret_target->arguments);
            printf("\"");
            break;
    }
    printf("\n");

    drakvuf_remove_trap(drakvuf, info->trap, nullptr);
    delete ret_target;
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t usermode_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;

    if (target->pid != info->proc_data.pid)
        return VMI_EVENT_RESPONSE_NONE;

    dump_from_stack(drakvuf, info, (memdump*)target->plugin);

    auto vmi = drakvuf_lock_and_get_vmi(drakvuf);
    vmi_v2pcache_flush(vmi, info->regs->cr3);

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
    {
        uint32_t ret_addr_tmp;

        if (vmi_read_32(vmi, &ctx, &ret_addr_tmp) == VMI_SUCCESS)
        {
            success = true;
            ret_addr = ret_addr_tmp;
        }
    }
    else
    {
        success = vmi_read_64(vmi, &ctx, &ret_addr) == VMI_SUCCESS;
    }
    drakvuf_release_vmi(drakvuf);

    return_hook_target_entry_t* ret_target = new return_hook_target_entry_t();
    drakvuf_trap_t* trap = new drakvuf_trap_t;

    for (size_t i = 1; i <= target->args_num; i++)
    {
        uint64_t argument = drakvuf_get_function_argument(drakvuf, info, i);
        ret_target->arguments.push_back(argument);
    }
    ret_target->plugin = target->plugin;

    addr_t paddr;
    vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if ( VMI_SUCCESS != vmi_pagetable_lookup(vmi, info->regs->cr3, ret_addr, &paddr) )
    {
        delete ret_target;
        delete trap;
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;

    }
    drakvuf_release_vmi(drakvuf);

    ret_target->pid = target->pid;

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
        PRINT_DEBUG("[MEMDUMP-USER] Failed to add trap :(\n");
        delete trap;
        delete ret_target;
    }

    return VMI_EVENT_RESPONSE_NONE;
}

void on_dll_discovered(drakvuf_t drakvuf, const dll_view_t* dll, void* extra)
{
    memdump* plugin = (memdump*)extra;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    unicode_string_t* dll_name = drakvuf_read_unicode_va(vmi, dll->mmvad.file_name_ptr, 0);

    if (dll_name && dll_name->contents)
    {
        for (auto const& wanted_hook : plugin->wanted_hooks)
        {
            if (strstr((const char*)dll_name->contents, wanted_hook.dll_name.c_str()) != 0)
                drakvuf_request_usermode_hook(drakvuf, dll, wanted_hook.function_name.c_str(), usermode_hook_cb, wanted_hook.args_num, plugin);
        }
    }

    if (dll_name)
        vmi_free_unicode_str(dll_name);

    drakvuf_release_vmi(drakvuf);
}

void on_dll_hooked(drakvuf_t drakvuf, const dll_view_t* dll, void* extra)
{
    PRINT_DEBUG("[MEMDUMP] DLL hooked - done\n");
}

void memdump::load_wanted_targets(const memdump_config* c)
{
    if (!c->dll_hooks_list)
    {
        // if the DLL hook list was not provided, we provide some simple defaults
        this->wanted_hooks.emplace_back("ws2_32.dll", "WSAStartup", 2);
        this->wanted_hooks.emplace_back("ntdll.dll", "RtlExitUserProcess", 1);
        return;
    }

    std::ifstream ifs(c->dll_hooks_list, std::ifstream::in);

    if (!ifs)
    {
        throw -1;
    }

    std::string line;
    while (std::getline(ifs, line))
    {
        if (line.empty() || line[0] == '#')
            continue;

        std::stringstream ss(line);
        target_config_entry_t e;

        std::string args_num_s;
        if (!std::getline(ss, e.dll_name, ',') || e.dll_name.empty())
            throw -1;
        if (!std::getline(ss, e.function_name, ',') || e.function_name.empty())
            throw -1;
        if (!std::getline(ss, args_num_s, ',') || args_num_s.empty())
            throw - 1;

        e.args_num = std::stoi(args_num_s);

        this->wanted_hooks.push_back(e);
    }
}

void memdump::userhook_init(drakvuf_t drakvuf, const memdump_config* c, output_format_t output)
{
    try
    {
        this->load_wanted_targets(c);
    }
    catch (int e)
    {
        fprintf(stderr, "Malformed DLL hook configuration for MEMDUMP plugin\n");
        throw -1;
    }

    if (this->wanted_hooks.empty())
    {
        // don't load this part of plugin if there is nothing to do
        return;
    }

    usermode_cb_registration reg = {
        .pre_cb = on_dll_discovered,
        .post_cb = on_dll_hooked,
        .extra = (void *)this
    };

    usermode_reg_status_t status = drakvuf_register_usermode_callback(drakvuf, &reg);

    if (status == USERMODE_ARCH_UNSUPPORTED) {
        PRINT_DEBUG("[MEMDUMP] Usermode hooking is not supported on this architecture/bitness, these features will be disabled\n");
    } else if (status != USERMODE_REGISTER_SUCCESS) {
        PRINT_DEBUG("[MEMDUMP] Failed to subscribe to libusermode\n");
        throw -1;
    }
}

void memdump::userhook_destroy(memdump* plugin)
{

}
