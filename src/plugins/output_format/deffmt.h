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

#ifndef PLUGINS_OUTPUT_FORMAT_DEFFMT_H
#define PLUGINS_OUTPUT_FORMAT_DEFFMT_H

#include "common.h"

#include "plugins/helpers/type_traits.h"

namespace deffmt
{

template <class T>
constexpr bool print_data(std::ostream& os, const T& data, char sep);


template<class T, std::size_t N>
struct TuplePrinter
{
    static bool print(std::ostream& os, const T& data, char sep)
    {
        if constexpr (N > 0)
        {
            bool printed_prev = TuplePrinter<T, N-1>::print(os, data, sep);
            if (printed_prev)
                os << sep;
            bool printed = print_data(os, std::get<N-1>(data), sep);
            if (!printed && printed_prev)
                fmt::unputc(os);
            return printed;
        }
        return false;
    }
};

template <class T, class = void, class...>
struct DataPrinter
{

    static bool print(std::ostream& os, const TimeVal& t, char)
    {
        auto restore_flags = fmt::RestoreFlags(os);
        os << t.tv_sec << '.' << std::setfill('0')
            << std::setw(6) << t.tv_usec;
        return true;
    }

    static bool print(std::ostream& os, const flagsval& flags, char sep)
    {
        return print_data(os, keyval(flags.name, fmt::Rstr(flags.values)), sep);
    }

    template <class Tv = T>
    static bool print(std::ostream& os, const fmt::Nval<Tv>& data, char)
    {
        os << data.value;
        return true;
    }

    template <class Tv = T>
    static bool print(std::ostream& os, const fmt::Xval<Tv>& data, char)
    {
        auto restore_flags = fmt::RestoreFlags(os);
        auto base = data.withbase ? "0x" : "";
        os << base << std::uppercase << std::hex << data.value;
        return true;
    }

    template <class Tv = T>
    static bool print(std::ostream& os, const fmt::Fval<Tv>& data, char)
    {
        auto restore_flags = fmt::RestoreFlags(os);
        os << std::fixed << data.value;
        return true;
    }

    template <class Tv = T>
    static bool print(std::ostream& os, const fmt::Rstr<Tv>& data, char)
    {
        os << data.value;
        return true;
    }

    template <class Tv = T>
    static bool print(std::ostream& os, const fmt::Qstr<Tv>& data, char)
    {
        os << '"' << data.value << '"';
        return true;
    }

    template <class Tv = T>
    static bool print(std::ostream& os, const fmt::BinaryString<Tv>& data, char)
    {
        data.format(os);
        return true;
    }

    template <class Tv = T>
    static bool print(std::ostream& os, const fmt::Estr<Tv>& data, char)
    {
        gchar* escaped = drakvuf_escape_str(data.value.c_str());
        os << escaped;
        g_free(escaped);
        return true;
    }

    template <class Tv = T>
    static bool print(std::ostream& os, const std::function<bool(std::ostream&)>& printer, char)
    {
        auto pos = os.tellp();
        bool printed = printer(os);
        if (!printed)
            os.seekp(pos);
        return printed;
    }

    template <class Tv = T>
    static bool print(std::ostream& os, const std::optional<Tv>& data, char sep)
    {
        return data.has_value() && print_data(os, data.value(), sep);
    }

    template <class Tk, class Tv>
    static bool print(std::ostream& os, const std::pair<Tk, Tv>& data, char)
    {
        static_assert(
            std::is_same_v<Tk, const char*> ||
            std::is_same_v<std::decay_t<Tk>, std::string> ||
            std::is_same_v<std::decay_t<Tk>, std::string_view>,
            "Unsupported DEFAULT printer key type");

        auto pos = os.tellp();
        if (print_data(os, fmt::Rstr(data.first), 0))
        {
            os << ':';
            if (print_data(os, data.second, ';'))
            {
                return true;
            }
        }
        os.seekp(pos);
        return false;
    }

    template <class... Ts>
    static bool print(std::ostream& os, const std::tuple<Ts...>& data, char sep)
    {
        return TuplePrinter<decltype(data), sizeof...(Ts)>::print(os, data, sep);
    }

    template <class... Ts>
    static bool print(std::ostream& os, const std::variant<Ts...>& data, char sep)
    {
        return std::visit([&os, sep](auto&& arg) mutable
        {
            return print_data(os, arg, sep);
        }, data);
    }
};

template <class T>
struct DataPrinter<T, std::enable_if_t<is_iterable<T>::value, void>>
{
    static bool print(std::ostream& os, const T& data, char sep)
    {
        bool printed = false;
        for (const auto& v : data)
        {
            bool printed_prev = printed;
            if (printed)
                os << sep;
            printed = print_data(os, v, sep);
            if (!printed && printed_prev)
                fmt::unputc(os);
        }
        return true;
    }
};

template <class T>
constexpr bool print_data(std::ostream& os, const T& data, char sep)
{
    return DataPrinter<T>::print(os, data, sep);
}

/**/

template <class T, class... Ts>
constexpr bool print_data(std::ostream& os, const T& data, const Ts& ... rest)
{
    constexpr char sep = ' ';
    bool printed = print_data(os, data, sep);
    bool printed_rest = false;

    if constexpr (sizeof...(rest) > 0)
    {
        if (printed)
            os << sep;
        printed_rest = print_data(os, rest...);
        if (!printed_rest && printed)
            fmt::unputc(os);
    }
    return printed || printed_rest;
}

/**/

inline void print_common_data(std::ostream& os, drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if (info)
    {
        proc_data_t* proc_data = drakvuf_get_os_type(drakvuf) == VMI_OS_WINDOWS ? &info->attached_proc_data : &info->proc_data;
        const char* method = info->trap->name ?: "";
        std::string procname = "\"";
        procname += proc_data->name ?: "NOPROC";
        procname += "\"";

        print_data(os,
            keyval("TIME", TimeVal{UNPACK_TIMEVAL(info->timestamp)}),
            keyval("VCPU", fmt::Nval(info->vcpu)),
            keyval("CR3", fmt::Xval(info->regs->cr3)),
            keyval(procname.c_str(), fmt::Rstr(method)),
            keyval(USERIDSTR(drakvuf), fmt::Nval(info->proc_data.userid)),
            keyval("PID", fmt::Nval(proc_data->pid)),
            keyval("PPID", fmt::Nval(proc_data->ppid))
        );
    }
}

template<class... Args>
void print(const char* plugin_name, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const Args& ... args)
{
    std::string up_name(plugin_name);
    std::transform(up_name.begin(), up_name.end(), up_name.begin(),
        [](uint8_t c)
    {
        return std::toupper(c);
    });

    fmt::cout << '[' << up_name << ']' << ' ';

    bool printed = false;
    if (info)
    {
        print_common_data(fmt::cout, drakvuf, info);
        printed = true;
    }

    if constexpr (sizeof...(args) > 0)
    {
        constexpr char sep = ' ';
        if (printed)
            fmt::cout << sep;
        if (!print_data(fmt::cout, args...))
            fmt::unputc(fmt::cout);
    }

    fmt::cout << std::endl;
}

inline void print_running_process(const char* plugin_name, drakvuf_t drakvuf, gint64 timestamp, proc_data_t const& proc_data)
{
    print(plugin_name, drakvuf, nullptr,
        keyval("TIME", TimeVal{UNPACK_TIMEVAL(timestamp)}),
        keyval("PID", fmt::Nval(proc_data.pid)),
        keyval("PPID", fmt::Nval(proc_data.ppid)),
        keyval("RunningProcess", fmt::Qstr(proc_data.name))
    );
}

} // namespace deffmt

#endif // PLUGINS_OUTPUT_FORMAT_DEFFMT_H
