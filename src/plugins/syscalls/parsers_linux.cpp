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


#include "linux.h"

using namespace syscalls_ns;

namespace syscalls_ns
{

static void parse_linux_char_ptr(
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

static void parse_linux_prot_flags(
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
    auto& original_args = *static_cast<syscalls_base::fmt_args_t*>(original_args_ptr);

    linux_syscalls* linux_base = dynamic_cast<linux_syscalls*>(base);
    if (!linux_base) return;

    if (value == 0)
    {
        syscalls_base::find_replace_arg(original_args, std::string(arg.name), fmt::Qstr("PROT_NONE"));
    }
    else
    {
        syscalls_base::find_replace_arg(original_args, std::string(arg.name),
            fmt::Qstr(parse_flags(value, mmap_prot, linux_base->m_output_format)));
    }
}

static void parse_linux_prctl_option(
    void* base_ptr,
    void* original_args_ptr,
    void* extra_args_ptr,
    const syscall_t* sc,
    const arg_t& arg,
    void* info_ptr,
    uint64_t value,
    const void* all_args_ptr)
{
    auto& original_args = *static_cast<syscalls_base::fmt_args_t*>(original_args_ptr);

    if (prctl_option.find(value) != prctl_option.end())
    {
        syscalls_base::find_replace_arg(original_args, std::string(arg.name), fmt::Qstr(prctl_option.at(value)));
    }
}

static void parse_linux_arch_prctl_code(
    void* base_ptr,
    void* original_args_ptr,
    void* extra_args_ptr,
    const syscall_t* sc,
    const arg_t& arg,
    void* info_ptr,
    uint64_t value,
    const void* all_args_ptr)
{
    auto& original_args = *static_cast<syscalls_base::fmt_args_t*>(original_args_ptr);

    if (arch_prctl_code.find(value) != arch_prctl_code.end())
    {
        syscalls_base::find_replace_arg(original_args, std::string(arg.name), fmt::Qstr(arch_prctl_code.at(value)));
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
            // Type-based parsers
            if (!args[j].parser)
            {
                switch (args[j].type)
                {
                    case linux_char_ptr:
                        args[j].parser = parse_linux_char_ptr;
                        break;
                    case linux_intmask_prot_:
                        args[j].parser = parse_linux_prot_flags;
                        break;
                    case linux_intopt_pr_:
                        args[j].parser = parse_linux_prctl_option;
                        break;
                    case linux_intopt_arch_:
                        args[j].parser = parse_linux_arch_prctl_code;
                        break;
                    default:
                        break;
                }
            }
        }
    }
}

} // namespace syscalls_ns

void linux_syscalls::register_parsers()
{
    register_parsers_for_table(linuxsc::linux_syscalls_table_x32, NUM_SYSCALLS_LINUX_X32);
    register_parsers_for_table(linuxsc::linux_syscalls_table_x64, NUM_SYSCALLS_LINUX_X64);
}
