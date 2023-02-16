/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2023 Tamas K Lengyel.                                  *
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

std::string syscalls_base::parse_argument(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val)
{
    char* cstr = nullptr;
    std::string str;

    if ( arg.dir == DIR_IN || arg.dir == DIR_INOUT )
    {
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
                cstr = drakvuf_read_ascii_str(drakvuf, info, val);
                break;
            case MMAP_PROT:
                // PROT_NONE == 0, so incorrect for parsing flags
                str = val == 0 ? "PROT_NONE" : parse_flags(val, mmap_prot, m_output_format);
                break;
            case PRCTL_OPTION:
                return prctl_option.find(val) != prctl_option.end() ? prctl_option.at(val) : std::to_string(val);
            case ARCH_PRCTL_CODE:
                return arch_prctl_code.find(val) != arch_prctl_code.end() ? arch_prctl_code.at(val) : std::to_string(val);
            default:
                if (this->os == VMI_OS_WINDOWS)
                    cstr = win_extract_string(drakvuf, info, arg, val);
                break;
        }
    }

    if (cstr)
    {
        str = std::string(cstr);
        g_free(cstr);
    }
    return str;
}

uint64_t syscalls_base::mask_value(const arg_t& arg, uint64_t val)
{
    switch (arg.type)
    {
        case BYTE:
        case BOOLEAN:
            return val & 0xff;
        case SHORT:
        case USHORT:
        case WORD:
            return val & 0xffff;
        case DWORD:
        case INT:
        case UINT:
        case LONG:
        case ULONG:
        case WIN32_PROTECTION_MASK:
            return val & 0xffffffff;
        default:
            return val;
    }
}

uint64_t syscalls_base::transform_value(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, uint64_t val)
{
    if ((arg.type == PPVOID) && val)
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = val
        );

        uint64_t _val;

        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &_val))
        {
            fprintf(stderr, "Failed to read address (%p)\n", (void*) val);
            _val = 0;
        }

        val = _val;
    }
    return mask_value(arg, val);
}

bool syscalls_base::read_syscalls_filter(const char* filter_file)
{
    std::ifstream file(filter_file);
    if (!file.is_open())
        return false;

    std::string line;
    while (std::getline(file, line))
        this->filter.insert(line);

    return true;
}


syscalls_base::syscalls_base(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output) : pluginex(drakvuf, output)
{
    this->os = drakvuf_get_os_type(drakvuf);
    this->kernel_base = drakvuf_get_kernel_base(drakvuf);
    this->register_size = drakvuf_get_address_width(drakvuf); // 4 or 8 (bytes)
    this->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    this->disable_sysret = config->disable_sysret;

    if (config->syscalls_filter_file)
    {
        if (!this->read_syscalls_filter(config->syscalls_filter_file))
        {
            PRINT_DEBUG("[SYSCALLS] Failed to read given file\n");
            throw -1;
        }
    }
}

syscalls::syscalls(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output) : pluginex(drakvuf, output)
{
    os_t os = drakvuf_get_os_type(drakvuf);
    if (os == VMI_OS_WINDOWS)
        this->_win_syscalls = std::make_unique<win_syscalls>(drakvuf, config, output);
    else
        this->_linux_syscalls = std::make_unique<linux_syscalls>(drakvuf, config, output);
}