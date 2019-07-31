/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  *
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

#ifndef MEMDUMP_H
#define MEMDUMP_H

#include <vector>

#include <glib.h>
#include "plugins/private.h"
#include "plugins/plugins_ex.h"

template<typename T>
struct call_result_t : public plugin_params<T>
{
    call_result_t(T* src) : plugin_params<T>(src), target_cr3(), target_thread(), target_rsp() {}

    void set_result_call_params(const drakvuf_trap_info_t* info, addr_t thread)
    {
        target_thread = thread;
        target_cr3 = info->regs->cr3;
        target_rsp = info->regs->rsp;
    }

    bool verify_result_call_params(const drakvuf_trap_info_t* info, addr_t thread)
    {
        return (info->regs->cr3 != target_cr3 ||
                !thread || thread != target_thread ||
                info->regs->rsp <= target_rsp) ? false : true;
    }

    reg_t target_cr3;
    addr_t target_thread;
    addr_t target_rsp;
};

template<typename T>
struct copy_on_write_result_t: public call_result_t<T>
{
    copy_on_write_result_t(T* src) : call_result_t<T>(src), vaddr(), pte(), old_cow_pa() {}

    addr_t vaddr;
    addr_t pte;
    addr_t old_cow_pa;
};

template<typename T>
struct map_view_of_section_result_t: public call_result_t<T>
{
    map_view_of_section_result_t(T* src) : call_result_t<T>(src), section_handle(), process_handle(), base_address_ptr() {}

    uint64_t section_handle;
    uint64_t process_handle;
    addr_t base_address_ptr;
};

enum target_hook_state
{
    HOOK_FIRST_TRY,
    HOOK_PAGEFAULT_RETRY,
    HOOK_FAILED,
    HOOK_OK
};

typedef event_response_t (*callback_t)(drakvuf_t drakvuf, drakvuf_trap_info* info);
class memdump;

typedef struct hook_target_entry
{
    vmi_pid_t pid;
    std::string target_name;
    callback_t callback;
    target_hook_state state;
    drakvuf_trap_t* trap;
    memdump* plugin;

    hook_target_entry(std::string target_name, callback_t callback, memdump* plugin)
        : target_name(target_name), callback(callback), state(HOOK_FIRST_TRY), plugin(plugin) {}
} hook_target_entry_t;

typedef struct user_dll
{
    // relevant while loading
    addr_t dtb;
    uint32_t thread_id;
    addr_t real_dll_base;
    bool is_hooked;

    // internal, for page faults
    addr_t pf_current_addr;
    addr_t pf_max_addr;

    // one entry per hooked function
    std::vector<hook_target_entry_t> targets;
} user_dll_t;

struct memdump_config
{
    const char* memdump_dir;
};

class memdump: public pluginex
{
public:
    // for memdump.cpp
    const char* memdump_dir;
    int memdump_counter;

    // for userhook.cpp
    // map dtb -> list of hooked dlls
    std::map<addr_t, std::vector<user_dll_t>> loaded_dlls;

    memdump(drakvuf_t drakvuf, const memdump_config* config, output_format_t output);
    void userhook_init(drakvuf_t drakvuf, const memdump_config* c, output_format_t output);
};

bool dump_memory_region(
        drakvuf_t drakvuf,
        vmi_instance_t vmi,
        drakvuf_trap_info_t* info,
        memdump* plugin,
        access_context_t* ctx,
        size_t len_bytes,
        const char* reason,
        void* extras,
        void (*printout_extras)(drakvuf_t drakvuf, output_format_t format, void* extras));

#endif
