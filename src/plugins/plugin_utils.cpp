/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2022 Tamas K Lengyel.                                  *
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

#include "plugin_utils.h"
#include <algorithm>
#include <cctype>
#include <iostream>

using std::string;
using std::cout;
using std::endl;

void dump_buffer(const uint8_t buffer[], const size_t count, const size_t columns, addr_t base_addr, std::string header, std::string footer)
{
    if (!header.empty())
    {
        // cout << header << endl;
        fprintf(stderr, "%s", header.data());
    }
    fprintf(stderr, "\n");

    for (size_t r = 0; r < count; r += columns)
    {
        // Print base address
        fprintf(stderr, "\n\t0x%08lX | +0x%04zX |", base_addr + r, r);

        // Print memory contents as bytes in hex format
        size_t c;
        for (c = 0; c != std::min(columns, count -r); ++c)
            fprintf(stderr, " %02X", buffer[r + c]);

        // Print spaces if row is "short"
        for (size_t s = 0; s != columns - c; ++s)
            fprintf(stderr, "   ");

        // Print bytes as ASCII characters
        fprintf(stderr, " | ");
        for (size_t a = 0; a != c; ++a)
        {
            auto v = buffer[r + a];
            if (std::isprint(v))
                fprintf(stderr, "%c", v);
            else
                fprintf(stderr, ".");
        }
    }

    if (!footer.empty())
    {
        // cout << endl << footer << endl;
        fprintf(stderr, "%s", footer.data());
    }
    fprintf(stderr, "\n");
}

void dump_va(vmi_instance_t vmi, access_context_t* ctx, const size_t count, const size_t columns, std::string header, std::string footer)
{
    std::unique_ptr<uint8_t[]> buffer(new uint8_t[count] {0});
    if (VMI_SUCCESS == vmi_read(vmi, ctx, count, buffer.get(), nullptr))
        dump_buffer(buffer.get(), count, columns, ctx->addr, header, footer);
}

void dump_registers(const x86_registers_t* regs, string header, string footer)
{
    fprintf(stderr, "%s\n"
        "rax 0x%016lx rbx 0x%016lx rcx 0x%016lx rdx 0x%016lx\n"
        "rsi 0x%016lx rdi 0x%016lx rbp 0x%016lx rsp 0x%016lx\n"
        "r8  0x%016lx r9  0x%016lx r10 0x%016lx r11 0x%016lx\n"
        "r12 0x%016lx r13 0x%016lx r14 0x%016lx r15 0x%016lx\n"
        "rip 0x%016lx rflags 0x%016lx\n"
        "CS 0x%04lx DS 0x%04lx ES 0x%04lx SS 0x%04lx FS 0x%04lx GS 0x%04lx\n"
        "FS_BASE 0x%016lx GS_BASE 0x%016lx SHADOW_GS 0x%016lx\n"
        "CR0 0x%016lx CR2 0x%016lx CR3 0x%016lx CR4 0x%016lx\n"
        "%s\n",
        header.data(),
        regs->rax, regs->rbx, regs->rcx, regs->rdx,
        regs->rsi, regs->rdi, regs->rbp, regs->rsp,
        regs->r8, regs->r9, regs->r10, regs->r11,
        regs->r12, regs->r13, regs->r14, regs->r15,
        regs->rip, regs->rflags,
        regs->cs_sel, regs->ds_sel, regs->es_sel, regs->ss_sel,
        regs->fs_sel, regs->gs_sel,
        regs->fs_base, regs->gs_base, regs->shadow_gs,
        regs->cr0, regs->cr2, regs->cr3, regs->cr4,
        footer.data()
    );
}

static std::string format_flag(string flag, output_format_t format)
{
    if ( format == OUTPUT_KV )
        return flag + "=1,";

    return flag + " | ";
}

std::string parse_flags(uint64_t flags, const flags_str_t& flags_map, output_format_t format, std::string empty)
{
    string output;

    for (const auto& flag: flags_map)
        if ((flag.first & flags) == flag.first)
            output += format_flag(flag.second, format);

    if (output.empty())
    {
        output = empty;
    }
    else
    {
        if (format == OUTPUT_KV)
            output.resize(output.size() - 1);
        else
            output.resize(output.size() - 3);
    }

    return output;
}
