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

void syscalls_base::fill_fmt_args(
    fmt_args_t& fmt_args, const syscall_t* sc, drakvuf_trap_info_t* info,
    const std::vector<uint64_t>& args, bool is_ret, bool ret_success
)
{
    for (size_t i = 0; i < args.size(); ++i)
    {
        bool is_complete_value =
            (sc->args[i].dir == DIR_IN) ||
            (sc->args[i].dir == DIR_OUT || sc->args[i].dir == DIR_INOUT) && is_ret && ret_success;

        uint64_t value = this->value_from_uint64(sc->args[i].type, args[i]);
        std::string value_str;

        if (is_complete_value)
            value_str = this->parse_argument(drakvuf, info, sc->args[i], value);

        auto type_info = arg_types.at(sc->args[i].type);

        if (value && is_complete_value &&
            type_info.is_ptr && type_info.ptr_for_type != Void &&
            this->dereference_args != SYSCALLS_DEREFERENCE_ARGS_NONE)
        {
            auto vmi = vmi_lock_guard(drakvuf);
            ACCESS_CONTEXT(ctx,
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3,
                .addr = value
            );

            uint64_t actual_value;
            if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &actual_value))
            {
                auto actual_arg = sc->args[i];
                actual_arg.type = type_info.ptr_for_type;

                actual_value = this->value_from_uint64(type_info.ptr_for_type, actual_value);
                auto actual_value_str = this->parse_argument(drakvuf, info, actual_arg, actual_value);

                if (this->dereference_args == SYSCALLS_DEREFERENCE_ARGS_ADD_FIELD)
                {
                    auto arg_name = std::string("*") + sc->args[i].name;

                    if (actual_value_str.empty())
                        fmt_args.emplace(arg_name, fmt::Xval(actual_value));
                    else
                        fmt_args.emplace(arg_name, fmt::Estr(actual_value_str));
                }
                else // SYSCALLS_DEREFERENCE_ARGS_REPLACE_FIELD
                {
                    value = actual_value;
                    value_str = actual_value_str;
                }
            }
            else
                fprintf(stderr, "Failed to read value by address (%p)\n", (void*)value);
        }

        if (value_str.empty())
            fmt_args.emplace(sc->args[i].name, fmt::Xval(value));
        else
            fmt_args.emplace(sc->args[i].name, fmt::Estr(value_str));
    }
}

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

std::string syscalls_base::parse_argument(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val)
{
    char* cstr = nullptr;

    switch (arg.type)
    {
        case PUNICODE_STRING:
        {
            unicode_string_t* us = drakvuf_read_unicode(drakvuf, info, val);
            if ( us )
            {
                cstr = (char*)us->contents;
                us->contents = nullptr;
                vmi_free_unicode_str(us);
            }
            break;
        }
        case PCHAR:
        case linux_char_ptr:
            cstr = drakvuf_read_ascii_str(drakvuf, info, val);
            break;
        case linux_intmask_prot_:
            // PROT_NONE == 0, so incorrect for parsing flags
            return val == 0 ? "PROT_NONE" : parse_flags(val, mmap_prot, m_output_format);
        case linux_intopt_pr_:
            return prctl_option.find(val) != prctl_option.end() ? prctl_option.at(val) : std::to_string(val);
        case linux_intopt_arch_:
            return arch_prctl_code.find(val) != arch_prctl_code.end() ? arch_prctl_code.at(val) : std::to_string(val);
        default:
            if (this->os == VMI_OS_WINDOWS)
                cstr = win_extract_string(drakvuf, info, arg, val);
            break;
    }

    if (cstr)
    {
        std::string str = std::string(cstr);
        g_free(cstr);
        return str;
    }
    return {};
}

uint64_t syscalls_base::value_from_uint64(syscalls_ns::arg_type_t type, uint64_t val)
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


syscalls_base::syscalls_base(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output) : pluginex(drakvuf, output)
{
    this->os = drakvuf_get_os_type(drakvuf);
    this->kernel_base = drakvuf_get_kernel_base(drakvuf);
    this->register_size = drakvuf_get_address_width(drakvuf); // 4 or 8 (bytes)
    this->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    this->disable_sysret = config->disable_sysret;
    this->dereference_args = config->syscalls_dereference_args;

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