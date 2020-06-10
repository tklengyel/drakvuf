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

#ifndef SYSCALLS_ARGS_WALKER_H
#define SYSCALLS_ARGS_WALKER_H
#pragma once

#include "private.h"

#include <libdrakvuf/libdrakvuf.h>

#include <functional>


inline const char* extract_string(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val)
{
   if (arg.dir == DIR_IN || arg.dir == DIR_INOUT)
   {
       if (arg.type == PUNICODE_STRING)
       {
           unicode_string_t* us = drakvuf_read_unicode(drakvuf, info, val);
           if (us)
           {
               char* str = (char*)us->contents;
               us->contents = nullptr;
               vmi_free_unicode_str(us);
               return str;
            }
       }
       else if (arg.type == PCHAR)
       {
           char* str = drakvuf_read_ascii_str(drakvuf, info, val);
           return str;
       }

       if (!strcmp(arg.name, "FileHandle"))
       {
           char* filename = drakvuf_get_filename_from_handle(drakvuf, info, val);
           if (filename) return filename;
       }
    }

    return nullptr;
}

template <class R>
class ArgsWalker
{
public:
    using HandlerType = std::function<R(const arg_t*, const char*, addr_t)>;

public:
    class Iterator
    {
        size_t i;
        const ArgsWalker<R>& walker;
    public:
        Iterator(size_t i, const ArgsWalker<R>& w): i(i), walker(w)
        {}

        R operator*() const
        {
            return walker.arg_invoke(i);
        }

        bool operator!=(const Iterator& rhs) const
        {
            return i != rhs.i;
        }

        Iterator& operator++()
        {
            ++i;
            return *this;
        }
    };

    ArgsWalker()
        : drakvuf(nullptr)
        , info(nullptr)
        , sc(nullptr)
        , args_data(nullptr)
        , reg_size(0)
        , nargs(0)
    {}

    ArgsWalker(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const syscall_t* sc, void* args_data, uint8_t reg_size, HandlerType&& handler)
        : drakvuf(drakvuf)
        , info(info)
        , sc(sc)
        , args_data(args_data)
        , reg_size(reg_size)
        , nargs(args_data ? sc->num_args : 0)
        , arg_handler(std::forward<HandlerType>(handler))
    {}

    Iterator begin() const {
        return Iterator(0, *this);
    }

    Iterator end() const {
        return Iterator(nargs, *this);
    }

    R arg_invoke(size_t i) const
    {
        return arg_handler(arg(i), arg_str(i), arg_val(i));
    }

private:
    const arg_t* arg(size_t i) const
    {
        if (i >= nargs) return nullptr;
        return &sc->args[i];
    }

    const char* arg_str(size_t i) const
    {
        if (i >= nargs) return nullptr;
        return extract_string(drakvuf, info, sc->args[i], arg_val(i));
    }

    addr_t arg_val(size_t i) const
    {
        if (i >= nargs) return 0;
        return reg_size == 4
            ? static_cast<const uint32_t*>(args_data)[i]
            : static_cast<const uint64_t*>(args_data)[i];
    }

private:
    drakvuf_t drakvuf;
    drakvuf_trap_info_t* info;
    const syscall_t* sc;
    const void* args_data;
    uint8_t reg_size;
    size_t nargs;

    HandlerType arg_handler;
};

#endif // SYSCALLS_ARGS_WALKER_H
