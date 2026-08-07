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


#include "win.h"

using namespace syscalls_ns;


static void parse_pchar(
    void* base_ptr,
    void* original_args_ptr,
    void* extra_args_ptr,
    const syscall_t* sc,
    const arg_t& arg,
    void* info_ptr,
    uint64_t value,
    const void* all_args_ptr)
{
    if (value == 0) return;

    auto* base = static_cast<syscalls_base*>(base_ptr);
    auto& original_args = *static_cast<syscalls_base::fmt_args_t*>(original_args_ptr);
    auto* info = static_cast<drakvuf_trap_info_t*>(info_ptr);

    char* cstr = drakvuf_read_ascii_str(base->drakvuf, info, value);
    if (cstr)
    {
        syscalls_base::find_replace_arg(original_args, std::string(arg.name), fmt::Estr(std::string(cstr)));
        g_free(cstr);
    }
}

static void parse_punicode_string(
    void* base_ptr,
    void* original_args_ptr,
    void* extra_args_ptr,
    const syscall_t* sc,
    const arg_t& arg,
    void* info_ptr,
    uint64_t value,
    const void* all_args_ptr)
{
    if (value == 0) return;

    auto* base = static_cast<syscalls_base*>(base_ptr);
    auto& original_args = *static_cast<syscalls_base::fmt_args_t*>(original_args_ptr);
    auto* info = static_cast<drakvuf_trap_info_t*>(info_ptr);

    unicode_string_t* us = drakvuf_read_unicode(base->drakvuf, info, value);
    if (us)
    {
        syscalls_base::find_replace_arg(original_args, std::string(arg.name), fmt::Estr(std::string((char*)us->contents)));
        vmi_free_unicode_str(us);
    }
}

static void parse_pobject_attributes(
    void* base_ptr,
    void* original_args_ptr,
    void* extra_args_ptr,
    const syscall_t* sc,
    const arg_t& arg,
    void* info_ptr,
    uint64_t value,
    const void* all_args_ptr)
{
    if (value == 0) return;

    auto* base = static_cast<syscalls_base*>(base_ptr);
    auto& original_args = *static_cast<syscalls_base::fmt_args_t*>(original_args_ptr);
    auto* info = static_cast<drakvuf_trap_info_t*>(info_ptr);

    char* cstr = drakvuf_get_filename_from_object_attributes(base->drakvuf, info, value);
    if (cstr)
    {
        syscalls_base::find_replace_arg(original_args, std::string(arg.name), fmt::Estr(std::string(cstr)));
        g_free(cstr);
    }
}

static void parse_pcontext(
    void* base_ptr,
    void* original_args_ptr,
    void* extra_args_ptr,
    const syscall_t* sc,
    const arg_t& arg,
    void* info_ptr,
    uint64_t value,
    const void* all_args_ptr)
{
    auto* base = static_cast<syscalls_base*>(base_ptr);

    if (!base->dereference_args || value == 0)
        return;

    auto& extra_args = *static_cast<syscalls_base::fmt_args_t*>(extra_args_ptr);
    auto* info = static_cast<drakvuf_trap_info_t*>(info_ptr);

    addr_t rip = 0, rcx = 0;
    syscalls_base::fmt_args_t context_map;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    ctx.addr = value + 0xf8; // rip offset in CONTEXT
    if (VMI_SUCCESS == drakvuf_read_addr(base->drakvuf, info, &ctx, &rip))
    {
        context_map.push_back(keyval("rip", fmt::Xval(rip)));
    }

    ctx.addr = value + 0x80; // rcx offset in CONTEXT
    if (VMI_SUCCESS == drakvuf_read_addr(base->drakvuf, info, &ctx, &rcx))
    {
        context_map.push_back(keyval("rcx", fmt::Xval(rcx)));
    }

    if (!context_map.empty())
    {
        extra_args.push_back(keyval("Context", fmt::Skey(std::move(context_map))));
    }
}


static void parse_process_handle(
    void* base_ptr,
    void* original_args_ptr,
    void* extra_args_ptr,
    const syscall_t* sc,
    const arg_t& arg,
    void* info_ptr,
    uint64_t value,
    const void* all_args_ptr)
{
    auto* base = static_cast<syscalls_base*>(base_ptr);

    if (!base->dereference_args || value == 0)
        return;

    auto& extra_args = *static_cast<syscalls_base::fmt_args_t*>(extra_args_ptr);
    auto* info = static_cast<drakvuf_trap_info_t*>(info_ptr);

    addr_t handle_to_resolve = 0;

    if (arg.type == HANDLE)
    {
        handle_to_resolve = value;
    }

    if (handle_to_resolve)
    {
        vmi_pid_t resolved_pid = 0;
        if (drakvuf_get_pid_from_handle(base->drakvuf, info, handle_to_resolve, &resolved_pid) && resolved_pid != 0)
        {
            extra_args.push_back(keyval(std::string(arg.name) + "_PID", fmt::Nval(static_cast<unsigned long>(resolved_pid))));
        }
    }
}

static void parse_thread_handle(
    void* base_ptr,
    void* original_args_ptr,
    void* extra_args_ptr,
    const syscall_t* sc,
    const arg_t& arg,
    void* info_ptr,
    uint64_t value,
    const void* all_args_ptr)
{
    auto* base = static_cast<syscalls_base*>(base_ptr);

    if (!base->dereference_args || value == 0)
        return;

    auto& extra_args = *static_cast<syscalls_base::fmt_args_t*>(extra_args_ptr);
    auto* info = static_cast<drakvuf_trap_info_t*>(info_ptr);

    addr_t handle_to_resolve = 0;

    if (arg.type == HANDLE)
    {
        handle_to_resolve = value;
    }

    if (handle_to_resolve)
    {
        uint32_t resolved_tid = 0;
        if (drakvuf_get_tid_from_handle(base->drakvuf, info, handle_to_resolve, &resolved_tid) && resolved_tid != 0)
        {
            extra_args.push_back(keyval(std::string(arg.name) + "_TID", fmt::Nval(static_cast<unsigned long>(resolved_tid))));
        }

        vmi_pid_t resolved_pid = 0;
        if (drakvuf_get_pid_from_thread_handle(base->drakvuf, info, handle_to_resolve, &resolved_pid) && resolved_pid != 0)
        {
            extra_args.push_back(keyval(std::string(arg.name) + "_PID", fmt::Nval(static_cast<unsigned long>(resolved_pid))));
        }
    }
}

static void parse_file_handle(
    void* base_ptr,
    void* original_args_ptr,
    void* extra_args_ptr,
    const syscall_t* sc,
    const arg_t& arg,
    void* info_ptr,
    uint64_t value,
    const void* all_args_ptr)
{
    if (value == 0) return;

    auto* base = static_cast<syscalls_base*>(base_ptr);
    auto& original_args = *static_cast<syscalls_base::fmt_args_t*>(original_args_ptr);
    auto* info = static_cast<drakvuf_trap_info_t*>(info_ptr);

    char* cstr = drakvuf_get_filename_from_handle(base->drakvuf, info, value);
    if (cstr)
    {
        syscalls_base::find_replace_arg(original_args, std::string(arg.name), fmt::Estr(std::string(cstr)));
        g_free(cstr);
    }
}

static void parse_set_information_thread_wow64(
    void* base_ptr,
    void* original_args_ptr,
    void* extra_args_ptr,
    const syscall_t* sc,
    const arg_t& arg_to_parse,
    void* info_ptr,
    uint64_t value_to_parse,
    const void* all_args_ptr)
{
    auto* base = static_cast<syscalls_base*>(base_ptr);

    if (!base->dereference_args)
        return;

    auto& extra_args = *static_cast<syscalls_base::fmt_args_t*>(extra_args_ptr);
    auto* info = static_cast<drakvuf_trap_info_t*>(info_ptr);
    auto& all_args = *static_cast<const std::vector<uint64_t>*>(all_args_ptr);

    auto tic_opt = syscalls_base::get_arg_value_by_name(sc, all_args, "ThreadInformationClass");
    if (!tic_opt)
        return;

    constexpr uint64_t ThreadWow64Context = 0x1d;
    if (*tic_opt != ThreadWow64Context)
        return;

    const addr_t wow64_context_addr = value_to_parse;
    if (wow64_context_addr == 0)
        return;

    syscalls_base::fmt_args_t context_map;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    addr_t wow_eax = 0;
    ctx.addr = wow64_context_addr + 0xb0; // eax offset in Wow64Context
    if (VMI_SUCCESS == drakvuf_read_addr(base->drakvuf, info, &ctx, &wow_eax))
    {
        context_map.push_back(keyval("eax", fmt::Xval((uint64_t)wow_eax)));
    }

    addr_t wow_eip = 0;
    ctx.addr = wow64_context_addr + 0xb8; // eip offset in Wow64Context
    if (VMI_SUCCESS == drakvuf_read_addr(base->drakvuf, info, &ctx, &wow_eip))
    {
        context_map.push_back(keyval("eip", fmt::Xval((uint64_t)wow_eip)));
    }

    if (!context_map.empty())
    {
        extra_args.push_back(keyval("Wow64Context", fmt::Skey(std::move(context_map))));
    }
}

static void register_parsers_for_table(const syscall_t** syscalls, unsigned int count)
{
    for (unsigned int i = 0; i < count; i++)
    {
        const syscall_t* sc = syscalls[i];
        if (!sc) continue;

        arg_t* args = const_cast<arg_t*>(sc->args);

        for (unsigned int j = 0; j < sc->num_args; j++)
        {
            // Syscall-specific + arg name parsers (highest priority)
            if (strcmp(sc->name, "NtSetInformationThread") == 0 && strcmp(args[j].name, "ThreadInformation") == 0)
            {
                args[j].parser = parse_set_information_thread_wow64;
            }

            // Arg name-based parsers
            if (!args[j].parser)
            {
                if (strcmp(args[j].name, "ProcessHandle") == 0)
                {
                    args[j].parser = parse_process_handle;
                }
                else if (strcmp(args[j].name, "ThreadHandle") == 0)
                {
                    args[j].parser = parse_thread_handle;
                }
                else if (strcmp(args[j].name, "FileHandle") == 0)
                {
                    args[j].parser = parse_file_handle;
                }
            }

            // Type-based parsers (lowest priority)
            if (!args[j].parser)
            {
                switch (args[j].type)
                {
                    case PCHAR:
                        args[j].parser = parse_pchar;
                        break;
                    case PUNICODE_STRING:
                        args[j].parser = parse_punicode_string;
                        break;
                    case POBJECT_ATTRIBUTES:
                        args[j].parser = parse_pobject_attributes;
                        break;
                    case PCONTEXT:
                        args[j].parser = parse_pcontext;
                        break;
                    default:
                        break;
                }
            }
        }
    }
}

void win_syscalls::register_parsers()
{
    register_parsers_for_table(nt, NUM_SYSCALLS_NT);
    register_parsers_for_table(win32k, NUM_SYSCALLS_WIN32K);
}
