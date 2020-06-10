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

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>

#include <sstream>
#include <functional>
#include <string>
#include <utility>

#include "syscalls.h"
#include "private.h"
#include "win.h"
#include "linux.h"
#include "plugins/output_format.h"
#include "args_walker.h"


using csvarg_t = std::vector<std::variant<fmt::Rstr<std::string>, fmt::Xval<uint64_t>>>;

static csvarg_t csv_arg(const arg_t* arg, const char* str, addr_t val)
{
    csvarg_t args =
    {
        std::string(arg_direction_names[arg->dir]),
        std::string(type_names[arg->type]),
        std::string(arg->name),
        val
    };
    if (str)
    {
        args.emplace_back(std::string(str));
    }
    return args;
}

using kvarg_t = std::pair<std::string, std::variant<fmt::Qstr<std::string>, fmt::Xval<uint64_t>>>;

static kvarg_t kv_arg(const arg_t* arg, const char* str, addr_t val)
{
    if (str)
    {
        return {std::string(arg->name), std::string(str)};
    }
    return {std::string(arg->name), val};
}

using jsonarg_t = std::pair<std::string, std::variant<fmt::Qstr<std::string>, fmt::Nval<uint64_t>>>;

static jsonarg_t json_arg(const arg_t* arg, const char* str, addr_t val)
{
    if (str)
    {
        return {std::string(arg->name), std::string(str)};
    }
    return {std::string(arg->name), val};
}

using defarg_t = fmt::Rstr<std::string>;

static defarg_t default_arg(const arg_t* arg, const char* str, addr_t val)
{
    std::ostringstream ss;
/*
    ss  << "\t"
        << arg_direction_names[arg->dir]
        << " "
        << type_names[arg->type]
        << " "
        << arg->name
        << ": "
        << std::showbase << std::hex << val;
*/
    if (str)
    {
        ss << " -> '" << str << "'";
    }
    ss << "\n";

    return ss.str();
}

void print_syscall(output_format_t format, drakvuf_t drakvuf,
                   bool syscall, drakvuf_trap_info_t* info,
                   int nr, uint32_t nargs, void* args_data, const char* module, syscalls* s, const syscall_t* sc,
                   uint64_t ret, const char* extra_info)
{
    const char* old_name = info->trap->name;
    if (sc)
        info->trap->name = sc->name;

    switch (format)
    {
        case OUTPUT_CSV:
            if (syscall)
            {
                std::optional<fmt::Nval<uint32_t>> args_n;
                std::optional<ArgsWalker<csvarg_t>> args_walker;
                if (nargs)
                {
                    args_n = nargs;
                    args_walker = ArgsWalker<csvarg_t>(drakvuf, info, sc, args_data, s->reg_size, csv_arg);
                }
                csvfmt::print("syscall", drakvuf, info,
                              keyval("Module", fmt::Qstr(module)),
                              keyval("vCPU", fmt::Nval(info->vcpu)),
                              keyval("CR3", fmt::Xval(info->regs->cr3)),
                              keyval("Syscall", fmt::Nval(nr)),
                              keyval("NArgs", args_n),
                              keyval("Args", args_walker)
                             );
            }
            else
            {
                csvfmt::print("sysret", drakvuf, info,
                              keyval("Module", fmt::Qstr(module)),
                              keyval("vCPU", fmt::Nval(info->vcpu)),
                              keyval("CR3", fmt::Xval(info->regs->cr3)),
                              keyval("Syscall", fmt::Nval(nr)),
                              keyval("Ret", fmt::Nval(ret)),
                              keyval("Info", fmt::Rstr(extra_info ?: ""))
                             );
            }
            break;
        case OUTPUT_KV:
            if (syscall)
            {
                std::optional<ArgsWalker<kvarg_t>> args_walker;
                if (nargs)
                {
                    args_walker = ArgsWalker<kvarg_t>(drakvuf, info, sc, args_data, s->reg_size, kv_arg);
                }
                kvfmt::print("syscall", drakvuf, info,
                             keyval("Module", fmt::Qstr(module)),
                             keyval("vCPU", fmt::Nval(info->vcpu)),
                             keyval("CR3", fmt::Xval(info->regs->cr3)),
                             keyval("Syscall", fmt::Nval(nr)),
                             args_walker
                            );
            }
            else
            {
                kvfmt::print("sysret", drakvuf, info,
                             keyval("Module", fmt::Qstr(module)),
                             keyval("vCPU", fmt::Nval(info->vcpu)),
                             keyval("CR3", fmt::Xval(info->regs->cr3)),
                             keyval("Syscall", fmt::Nval(nr)),
                             keyval("Ret", fmt::Nval(ret)),
                             keyval("Info", fmt::Rstr(extra_info ?: ""))
                            );
            }
            break;
        case OUTPUT_JSON:
            if (syscall)
            {
                auto args_walker = ArgsWalker<jsonarg_t>(drakvuf, info, sc, args_data, s->reg_size, json_arg);

                jsonfmt::print("syscall", drakvuf, info,
                               keyval("Module", fmt::Qstr(module)),
                               keyval("VCPU", fmt::Nval(info->vcpu)),
                               keyval("CR3", fmt::Nval(info->regs->cr3)),
                               keyval("Args", args_walker)
                              );
            }
            else
            {
                jsonfmt::print("sysret", drakvuf, info,
                               keyval("Module", fmt::Qstr(module)),
                               keyval("VCPU", fmt::Nval(info->vcpu)),
                               keyval("CR3", fmt::Nval(info->regs->cr3)),
                               keyval("Ret", fmt::Nval(ret)),
                               keyval("Info", fmt::Qstr(extra_info ?: ""))
                              );
            }
            break;

        case OUTPUT_DEFAULT:
        default:
            if (syscall)
            {
                std::optional<ArgsWalker<defarg_t>> args_walker;
                if (nargs)
                {
                    args_walker = ArgsWalker<defarg_t>(drakvuf, info, sc, args_data, s->reg_size, default_arg);
                }
                deffmt::print("syscall", drakvuf, info,
                              keyval("Module", fmt::Rstr(module)),
                              keyval("Arguments", args_walker)
                             );
            }
            else
            {
                deffmt::print("sysret", drakvuf, info,
                              keyval("Module", fmt::Rstr(module)),
                              keyval("Ret", fmt::Nval(ret)),
                              keyval("Info", fmt::Rstr(extra_info ?: ""))
                             );
            }
            break;
    }
    info->trap->name = old_name;
}

static GHashTable* read_syscalls_filter(const char* filter_file)
{
    GHashTable* table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    if (!table) return NULL;

    FILE* f = fopen(filter_file, "r");
    if (!f)
    {
        g_hash_table_destroy(table);
        return NULL;
    }
    ssize_t bytes_read;
    do
    {
        char* line = NULL;
        size_t len = 0;
        bytes_read = getline(&line, &len, f);
        while (bytes_read > 0 && (line[bytes_read - 1] == '\n' || line[bytes_read - 1] == '\r')) bytes_read--;
        if (bytes_read > 0)
        {
            line[bytes_read] = '\0';
            g_hash_table_insert(table, line, NULL);
        }
        else
            free(line);
    } while (bytes_read != -1);

    fclose(f);
    return table;
}

void free_trap(gpointer p)
{
    if ( !p )
        return;

    drakvuf_trap_t* t = (drakvuf_trap_t*)p;
    if ( t->data )
        g_slice_free(struct wrapper, t->data);

    g_slice_free(drakvuf_trap_t, t);
}

syscalls::syscalls(drakvuf_t drakvuf, const syscalls_config* c, output_format_t output)
    : traps(NULL)
    , filter(NULL)
    , win32k_json(NULL)
    , format{output}
    , offsets(NULL)
{
    this->os = drakvuf_get_os_type(drakvuf);
    this->kernel_base = drakvuf_get_kernel_base(drakvuf);
    this->reg_size = drakvuf_get_address_width(drakvuf); // 4 or 8 (bytes)
    this->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);

    if ( c->syscalls_filter_file )
        this->filter = read_syscalls_filter(c->syscalls_filter_file);
    if ( c->win32k_profile )
        this->win32k_json = json_object_from_file(c->win32k_profile);

    if ( this->os == VMI_OS_WINDOWS )
        setup_windows(drakvuf, this);
    else
        setup_linux(drakvuf, this);

    if ( !this->traps )
    {
        PRINT_DEBUG("No traps were added by setup\n");
        throw -1;
    }
}

syscalls::~syscalls()
{
    GSList* loop = this->traps;
    while (loop)
    {
        free_trap(loop->data);
        loop = loop->next;
    }

    if ( this->filter )
        g_hash_table_destroy(this->filter);

    g_free(this->offsets);
    g_slist_free(this->traps);
}
