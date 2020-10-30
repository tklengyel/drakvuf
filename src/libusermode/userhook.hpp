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

#ifndef WIN_USERHOOK_H
#define WIN_USERHOOK_H

#include <vector>
#include <memory>

#include <glib.h>
#include "plugins/private.h"
#include "plugins/plugins_ex.h"
#include "printers/printers.hpp"

typedef event_response_t (*callback_t)(drakvuf_t drakvuf, drakvuf_trap_info* info);

enum target_hook_type
{
    HOOK_BY_NAME,
    HOOK_BY_OFFSET
};

struct HookActions
{
    bool log;
    bool stack;

    HookActions() : log{false}, stack{false} {}

    static HookActions empty()
    {
        return HookActions{};
    }
    HookActions& set_log()
    {
        this->log = true;
        return *this;
    }
    HookActions& set_stack()
    {
        this->stack = true;
        return *this;
    }
};

struct plugin_target_config_entry_t
{
    std::string dll_name;
    target_hook_type type;
    std::string function_name;
    std::string clsid;
    addr_t offset;
    HookActions actions;
    std::vector< std::unique_ptr< ArgumentPrinter > > argument_printers;

    plugin_target_config_entry_t()
        : dll_name(), function_name(), offset(), actions(), argument_printers()
    {}

    plugin_target_config_entry_t(std::string&& dll_name, std::string&& function_name, addr_t offset, HookActions hook_actions, std::vector< std::unique_ptr< ArgumentPrinter > >&& argument_printers)
        : dll_name(std::move(dll_name)), type(HOOK_BY_OFFSET), function_name(std::move(function_name)), offset(offset), actions(hook_actions), argument_printers(std::move(argument_printers))
    {}

    plugin_target_config_entry_t(std::string&& dll_name, std::string&& function_name, HookActions hook_actions, std::vector< std::unique_ptr< ArgumentPrinter > >&& argument_printers)
        : dll_name(std::move(dll_name)), type(HOOK_BY_NAME), function_name(std::move(function_name)), offset(), actions(hook_actions), argument_printers(std::move(argument_printers))
    {}
};

enum target_hook_state
{
    HOOK_FIRST_TRY,
    HOOK_PAGEFAULT_RETRY,
    HOOK_FAILED,
    HOOK_OK
};

struct hook_target_entry_t
{
    vmi_pid_t pid;
    target_hook_type type;
    std::string target_name;
    std::string clsid;
    addr_t offset;
    callback_t callback;
    const std::vector < std::unique_ptr < ArgumentPrinter > >& argument_printers;
    target_hook_state state;
    drakvuf_trap_t* trap;
    void* plugin;

    hook_target_entry_t(std::string target_name, std::string clsid, callback_t callback, const std::vector < std::unique_ptr < ArgumentPrinter > >& argument_printers, void* plugin)
        : pid(0), type(HOOK_BY_NAME), target_name(target_name), clsid(clsid), offset(0), callback(callback), argument_printers(argument_printers), state(HOOK_FIRST_TRY), trap(nullptr), plugin(plugin)
    {}

    hook_target_entry_t(std::string target_name, std::string clsid, addr_t offset, callback_t callback, const std::vector < std::unique_ptr < ArgumentPrinter > >& argument_printers, void* plugin)
        : pid(0), type(HOOK_BY_OFFSET), target_name(target_name), clsid(clsid), offset(offset), callback(callback), argument_printers(argument_printers), state(HOOK_FIRST_TRY), trap(nullptr), plugin(plugin)
    {}
};

struct return_hook_target_entry_t
{
    vmi_pid_t pid;
    drakvuf_trap_t* trap;
    std::string clsid;
    void* plugin;
    std::vector < uint64_t > arguments;
    const std::vector < std::unique_ptr < ArgumentPrinter > >& argument_printers;

    return_hook_target_entry_t(vmi_pid_t pid, std::string clsid, void* plugin, const std::vector < std::unique_ptr < ArgumentPrinter > >& argument_printers) :
        pid(pid), trap(nullptr), clsid(clsid), plugin(plugin), argument_printers(argument_printers) {}
};

struct hook_target_view_t
{
    std::string target_name;
    addr_t offset;
    target_hook_state state;

    hook_target_view_t(std::string target_name, addr_t offset, target_hook_state state)
        : target_name(target_name), offset(offset), state(state) {}
};

struct dll_view_t
{
    // relevant while loading
    addr_t dtb;
    uint32_t thread_id;
    addr_t real_dll_base;
    mmvad_info_t mmvad;
    bool is_hooked;
};

typedef void (*dll_pre_hook_cb)(drakvuf_t, const dll_view_t*, void*);
typedef void (*dll_post_hook_cb)(drakvuf_t, const dll_view_t*, const std::vector<hook_target_view_t>& targets, void*);

struct usermode_cb_registration
{
    dll_pre_hook_cb pre_cb;
    dll_post_hook_cb post_cb;
    void* extra;
};

typedef enum usermode_reg_status
{
    USERMODE_REGISTER_ERROR,
    USERMODE_REGISTER_SUCCESS,
    USERMODE_ARCH_UNSUPPORTED,
    USERMODE_OS_UNSUPPORTED,
} usermode_reg_status_t;

usermode_reg_status_t drakvuf_register_usermode_callback(drakvuf_t drakvuf, usermode_cb_registration* reg);
bool drakvuf_request_usermode_hook(drakvuf_t drakvuf, const dll_view_t* dll, const plugin_target_config_entry_t* target, callback_t callback, void* extra);
void drakvuf_load_dll_hook_config(drakvuf_t drakvuf, const char* dll_hooks_list_path, const bool print_no_addr, std::vector<plugin_target_config_entry_t>* wanted_hooks);

bool drakvuf_request_userhook_on_exisitng_process(drakvuf_t drakvuf, addr_t target_process, std::string dll_name, std::string func_name, callback_t cb, void* extra);
#endif
