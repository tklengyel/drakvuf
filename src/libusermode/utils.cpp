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

#include "utils.hpp"
#include "printers/printers.hpp"

#include <algorithm>
#include <iterator>
#include <optional>
#include <cctype>

bool is_dll_name_matched(const std::string& dll_name, const std::string& pattern)
{
    auto it = std::find_end(dll_name.begin(), dll_name.end(), pattern.begin(), pattern.end(),
            [](char x, char y)
    {
        return std::toupper(x) == std::toupper(y);
    });
    // matched last part of DLL name
    bool match_end = static_cast<size_t>(std::distance(it, dll_name.end())) == pattern.size();
    return match_end && (it == dll_name.begin() || *(it - 1) == '\\');
}

namespace
{

std::optional<HookActions> get_hook_actions(const std::string& str)
{
    if (str == "log")
    {
        return HookActions::empty().set_log();
    }
    else if (str == "log+stack")
    {
        return HookActions::empty().set_log().set_stack();
    }

    return std::nullopt;
}

std::optional<std::string> try_parse_token(std::stringstream& ss)
{
    const char SEPARATOR = ',';
    std::string result;
    if (!std::getline(ss, result, SEPARATOR) || result.empty())
    {
        return std::nullopt;
    }
    return result;
}

std::string parse_token(std::stringstream& ss)
{
    auto maybe_token = try_parse_token(ss);
    if (!maybe_token)
    {
        throw std::runtime_error{"Expected a token"};
    }
    return *maybe_token;
}

std::unique_ptr<ArgumentPrinter> make_arg_printer(
    const PrinterConfig& config,
    const std::string& type,
    const std::string& name)
{
    if (type == "lpstr" || type == "lpcstr" || type == "lpctstr")
    {
        return std::make_unique<AsciiPrinter>(name, config);
    }
    else if (type == "lpcwstr" || type == "lpwstr" || type == "bstr")
    {
        return std::make_unique<WideStringPrinter>(name, config);
    }
    else if (type == "punicode_string")
    {
        return std::make_unique<UnicodePrinter>(name, config);
    }
    else if (type == "pulong")
    {
        return std::make_unique<UlongPrinter>(name, config);
    }
    else if (type == "pulonglong")
    {
        return std::make_unique<UlongLongPrinter>(name, config);
    }
    else if (type == "lpvoid*")
    {
        return std::make_unique<PointerToPointerPrinter>(name, config);
    }
    else if (type == "refclsid" || type == "refiid")
    {
        return std::make_unique<GuidPrinter>(name, config);
    }
    else if (type == "binary16")
    {
        return std::make_unique<Binary16StringPrinter>(name, config);
    }

    return std::make_unique<ArgumentPrinter>(name, config);
}

std::vector<std::unique_ptr<ArgumentPrinter>> parse_arguments(
        const PrinterConfig& config,
        std::stringstream& ss)
{
    std::vector<std::unique_ptr<ArgumentPrinter>> argument_printers;

    for (size_t arg_idx = 0; ; arg_idx++)
    {
        auto maybe_arg = try_parse_token(ss);
        if (!maybe_arg) break;

        const std::string arg = *maybe_arg;
        std::string arg_name;
        std::string arg_type;
        const auto pos = arg.find_first_of(':');

        if (pos == std::string::npos)
        {
            arg_name = std::string("Arg") + std::to_string(arg_idx);
            arg_type = arg;
        }
        else
        {
            arg_name = arg.substr(0, pos);
            arg_type = arg.substr(pos + 1);
        }

        argument_printers.emplace_back(make_arg_printer(config, arg_type, arg_name));
    }
    return argument_printers;
}

} // namespace

plugin_target_config_entry_t parse_entry(
    std::stringstream& ss,
    PrinterConfig& config)
{
    plugin_target_config_entry_t entry{};

    entry.dll_name = parse_token(ss);
    entry.function_name = parse_token(ss);
    entry.type = HOOK_BY_NAME;

    for (;;)
    {
        std::string token = parse_token(ss);

        if (token == "clsid")
        {
            entry.clsid = parse_token(ss);
        }
        else if (token == "no-retval")
        {
            entry.no_retval = true;
        }
        else
        {
            std::optional<HookActions> actions = get_hook_actions(token);
            if (actions)
            {
                entry.actions = *actions;
                break;
            }

            // offset found
            entry.type = HOOK_BY_OFFSET;
            try
            {
                entry.offset = std::stoull(token, 0, 16);
            }
            catch (const std::logic_error& exc)
            {
                throw std::runtime_error{"Invalid offset"};
            }
        }
    }

    entry.argument_printers = parse_arguments(config, ss);

    return entry;
}
