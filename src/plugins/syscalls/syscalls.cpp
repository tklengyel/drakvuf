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

#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>
#include <string>
#include <variant>
#include <fstream>
#include <iostream>

#include "syscalls.h"
#include "private.h"

using namespace syscalls_ns;


void syscalls_base::print_sysret(drakvuf_t drakvuf, drakvuf_trap_info_t* info, int nr, const char* extra_info)
{
    fmt::print(this->m_output_format, "sysret", drakvuf, info,
        keyval("Module", fmt::Qstr(std::move(info->trap->breakpoint.module))),
        keyval("vCPU", fmt::Nval(info->vcpu)),
        keyval("CR3", fmt::Xval(info->regs->cr3)),
        keyval("Syscall", fmt::Nval(nr)),
        keyval("Ret", fmt::Xval(info->regs->rax)),
        keyval("Info", fmt::Rstr(extra_info ?: ""))
    );
}

std::optional<uint64_t> syscalls_base::get_arg_value_by_name(
    const syscall_t* sc, const std::vector<uint64_t>& all_args, const std::string& name)
{
    for (size_t i = 0; i < sc->num_args; ++i)
    {
        if (strcmp(sc->args[i].name, name.c_str()) == 0)
        {
            if (i < all_args.size())
            {
                return all_args[i];
            }
            return std::nullopt;
        }
    }
    return std::nullopt;
}


void syscalls_base::fill_fmt_args(
    fmt_args_t& original_args, fmt_args_t& extra_args, const syscall_t* sc, drakvuf_trap_info_t* info,
    const std::vector<uint64_t>& args, bool is_ret, bool ret_success)
{
    for (size_t i = 0; i < args.size(); ++i)
    {
        const auto& original_arg = sc->args[i];
        uint64_t raw_value = this->value_from_uint64(original_arg.type, args[i]);

        auto type_info = arg_types.at(original_arg.type);
        if (original_arg.dir == DIR_OUT && !type_info.is_ptr && !is_ret)
        {
            original_args.push_back(keyval(std::string(original_arg.name), fmt::Estr("<out>")));
            continue;
        }

        auto arg_to_parse = original_arg;
        uint64_t value_to_parse = raw_value;
        std::optional<uint64_t> dereferenced_value;

        bool is_value_complete = (original_arg.dir != DIR_OUT) || is_ret;

        if (this->dereference_args && raw_value && type_info.is_ptr && type_info.ptr_for_type != Void && is_value_complete && ret_success)
        {
            auto vmi = vmi_lock_guard(drakvuf);
            ACCESS_CONTEXT(ctx, .translate_mechanism = VMI_TM_PROCESS_DTB, .dtb = info->regs->cr3, .addr = raw_value);

            uint64_t temp_val;
            if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &temp_val))
            {
                dereferenced_value = temp_val;
                arg_to_parse.type = type_info.ptr_for_type;
                value_to_parse = *dereferenced_value;
            }
            else
            {
                PRINT_DEBUG("VMI read failed for address 0x%lx\n", raw_value);
            }
        }

        original_args.push_back(keyval(std::string(original_arg.name), fmt::Xval(raw_value)));

        arg_parser_t parser;
        auto syscall_arg_it = m_syscall_arg_parsers.find({sc->name, original_arg.name});
        if (syscall_arg_it != m_syscall_arg_parsers.end())
        {
            parser = syscall_arg_it->second;
        }
        else
        {
            auto name_it = m_name_parsers.find(original_arg.name);
            if (name_it != m_name_parsers.end())
            {
                parser = name_it->second;
            }
            else
            {
                auto type_it = m_type_parsers.find(arg_to_parse.type);
                if (type_it != m_type_parsers.end())
                {
                    parser = type_it->second;
                }
            }
        }

        if (parser)
        {
            parser(this, extra_args, sc, arg_to_parse, info, value_to_parse, args);
        }
        else if (dereferenced_value)
        {
            extra_args.push_back(keyval(std::string("*") + std::string(original_arg.name), fmt::Xval(*dereferenced_value)));
        }
    }
}

uint64_t syscalls_base::value_from_uint64(arg_type_t type, uint64_t val)
{
    switch (arg_types.at(type).size)
    {
        case ARG_SIZE_8:
            return val & 0xff;
        case ARG_SIZE_16:
            return val & 0xffff;
        case ARG_SIZE_32:
            return val & 0xffffffff;
        case ARG_SIZE_64:
        case ARG_SIZE_NATIVE:
            return val;
        default:
            assert(false && "Unknown size for type");
            return val;
    }
}

static std::string rstrip(std::string s)
{
    while (!s.empty() && isspace(s.back()))
        s.pop_back();
    return s;
}

bool syscalls_base::read_syscalls_list(const char* syscall_list_file)
{
    std::ifstream file(syscall_list_file);
    if (!file.is_open())
    {
        fprintf(stderr, "[SYSCALLS] failed to open syscalls file, does it exist?\n");
        return false;
    }

    std::string line;
    while (std::getline(file, line))
    {
        line = rstrip(std::move(line));
        if (line.empty())
            continue;

        size_t pos = line.find(',');
        if (pos == std::string::npos)
        {
            this->syscall_list.emplace(line, false);
            continue;
        }

        auto syscall = line.substr(0, pos);
        auto param = line.substr(pos + 1);
        bool is_ret = param == "retval";

        this->syscall_list.emplace(syscall, is_ret);
    }

    return true;
}

void syscalls_base::register_parsers()
{
    auto ascii_string_parser = [](
            syscalls_base* base, fmt_args_t& extra_args, const syscalls_ns::syscall_t* sc,
            const syscalls_ns::arg_t& arg, drakvuf_trap_info_t* info, uint64_t value,
            const std::vector<uint64_t>& all_args)
    {
        if (value == 0) return;

        char* cstr = drakvuf_read_ascii_str(base->drakvuf, info, value);
        if (cstr)
        {
            extra_args.push_back(keyval(std::string(arg.name), fmt::Estr(std::string(cstr))));
            g_free(cstr);
        }
    };

    m_type_parsers[PCHAR] = ascii_string_parser;
    m_type_parsers[linux_char_ptr] = ascii_string_parser;
}

syscalls_base::syscalls_base(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output) : pluginex(drakvuf, output)
{
    this->os = drakvuf_get_os_type(drakvuf);
    this->kernel_base = drakvuf_get_kernel_base(drakvuf);
    this->register_size = drakvuf_get_address_width(drakvuf); // 4 or 8 (bytes)
    this->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    this->disable_sysret = config->disable_sysret;
    this->dereference_args = config->syscalls_dereference_args;
    this->nested_args = config->syscalls_nested_args;


    if (config->syscalls_list_file && !this->read_syscalls_list(config->syscalls_list_file))
        throw -1;
}

syscalls::syscalls(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output) : pluginex(drakvuf, output)
{
    os_t os = drakvuf_get_os_type(drakvuf);
    if (os == VMI_OS_WINDOWS)
        this->_win_syscalls = std::make_unique<win_syscalls>(drakvuf, config, output);
    else
        this->_linux_syscalls = std::make_unique<linux_syscalls>(drakvuf, config, output);
}