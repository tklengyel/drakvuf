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

#include "printers.hpp"
#include "utils.hpp"
#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <libvmi/libvmi.h>
#include <libdrakvuf/libdrakvuf.h>
#include "plugins/plugins.h"

ArgumentPrinter::ArgumentPrinter(std::string arg_name, PrinterConfig config) :
    config(config), name(arg_name)
{
    // intentionally empty
}

std::string ArgumentPrinter::get_name() const
{
    return name;
}

std::string ArgumentPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    std::stringstream stream;
    stream << name << "=";
    if (config.numeric_format == PrinterConfig::NumericFormat::HEX)
        stream << "0x" << std::hex;
    stream << argument;
    return stream.str();
}

ArgumentPrinter::~ArgumentPrinter() {}

std::string StringPrinterInterface::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    std::string str = getBuffer(drakvuf, &ctx);
    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"" << escape_str(str) << "\"";
    return stream.str();
}

std::string AsciiPrinter::getBuffer(drakvuf_t drakvuf, const access_context_t* ctx) const
{
    auto vmi = vmi_lock_guard(drakvuf);
    char* str = vmi_read_str(vmi, ctx);
    std::string ret = str ? str : "";
    g_free(str);
    return ret;
}

std::string WideStringPrinter::getBuffer(drakvuf_t drakvuf, const access_context_t* ctx) const
{
    auto vmi = vmi_lock_guard(drakvuf);
    auto str_obj = drakvuf_read_wchar_string(drakvuf, ctx);
    std::string ret = str_obj == NULL ? "" : (char*)str_obj->contents;
    if (str_obj)
        vmi_free_unicode_str(str_obj);
    return ret;
}

std::string Binary16StringPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    auto vmi = vmi_lock_guard(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"";
    const size_t BUF_SIZE = 16;
    std::array<uint8_t, BUF_SIZE> buffer;
    if (VMI_SUCCESS == vmi_read(vmi, &ctx, 16, buffer.data(), nullptr))
    {
        for (auto i: buffer)
            stream << std::setw(2) << std::setfill('0') << (int)i;
    }
    stream << "\"";
    return stream.str();
}

std::string UnicodePrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    bool is32bit = drakvuf_process_is32bit(drakvuf, info);

    unicode_string_t* str_us = is32bit ? drakvuf_read_unicode32(drakvuf, info, argument)
        : drakvuf_read_unicode(drakvuf, info, argument);

    std::string str = str_us ? (char*)str_us->contents : "";
    if (str_us)
        vmi_free_unicode_str(str_us);

    std::stringstream stream;
    stream << name << "=";
    if (!config.print_no_addr)
        stream << "0x" << std::hex << argument << ":";
    stream << "\"" << escape_str(str) << "\"";
    return stream.str();
}

std::string UlongPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    auto vmi = vmi_lock_guard(drakvuf);
    uint32_t value;
    if (vmi_read_32(vmi, &ctx, &value) != VMI_SUCCESS)
        value = 0;
    return ArgumentPrinter::print(drakvuf, info, value);
}

std::string UlongLongPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );
    auto vmi = vmi_lock_guard(drakvuf);
    uint64_t value;
    if (vmi_read_64(vmi, &ctx, &value) != VMI_SUCCESS)
        value = 0;
    return ArgumentPrinter::print(drakvuf, info, value);
}

std::string PointerToPointerPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );

    addr_t value = 0;
    int ret = drakvuf_read_addr(drakvuf, info, &ctx, &value);
    if (ret != VMI_SUCCESS)
        value = 0;

    return ArgumentPrinter::print(drakvuf, info, value);
}

std::string GuidPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = argument
    );

    struct
    {
        uint32_t Data1;
        uint16_t Data2;
        uint16_t Data3;
        uint8_t Data4[8];
    } __attribute__((packed, aligned(4))) guid;

    auto vmi = vmi_lock_guard(drakvuf);
    if (vmi_read(vmi, &ctx, sizeof(guid), &guid, nullptr) != VMI_SUCCESS)
        memset(&guid, 0, sizeof(guid));

    const int sz = 64;
    char stream[sz] = {0};
    snprintf(stream, sz, "\"%08X-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\"",
        guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1],
        guid.Data4[2], guid.Data4[3], guid.Data4[4],
        guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return name + "=" + std::string(stream);
}

BitMaskPrinter::BitMaskPrinter(
    std::string arg_name,
    std::map < uint64_t, std::string > dict,
    PrinterConfig config)
    : ArgumentPrinter(arg_name, config)
    , dict(dict)
{
    // intentionally empty
}

std::string BitMaskPrinter::print(drakvuf_t drakvuf, drakvuf_trap_info* info, uint64_t argument) const
{
    std::stringstream stream;
    stream << name << "=0x" << std::hex << argument << ": ";
    if (argument == 0 && this->dict.find(0) != this->dict.end())
    {
        stream << this->dict.at(0);
    }
    else
    {
        bool first = true;
        for (std::pair<uint64_t, std::string> element : this->dict)
        {
            if (argument & element.first)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    stream << "|";
                }
                stream << element.second;
            }
        }
    }
    return stream.str();
}
