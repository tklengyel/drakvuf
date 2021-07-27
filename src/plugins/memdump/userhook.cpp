/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
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

/**
 * User mode hooking module of MEMDUMP plugin.
 *
 * (1) Observes when a process is loading a new DLL through the side effects
 * of NtMapViewOfSection or NtProtectVirtualMemory being called.
 * (2) Finds the DLL export information and checks if it's fully readable,
 * if not, triggers a page fault to force system to load it into memory.
 * (3) Translates given export symbols to virtual addresses, checks if
 * the underlying memory is available (if not, again triggers page fault)
 * and finally adds a standard DRAKVUF trap.
 */

#include <fstream>
#include <sstream>
#include <map>
#include <string>
#include <iostream>
#include <stdexcept>

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <libdrakvuf/private.h>
#include <libusermode/userhook.hpp>
#include <assert.h>

#include "memdump.h"
#include "private.h"

static event_response_t usermode_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;

    if (target->pid != info->attached_proc_data.pid)
        return VMI_EVENT_RESPONSE_NONE;

    if (target->target_name == "AssemblyNative::LoadImage")
        dotnet_assembly_native_load_image_cb(drakvuf, info, (memdump*)target->plugin);

    dump_from_stack(drakvuf, info, (memdump*)target->plugin);
    return VMI_EVENT_RESPONSE_NONE;
}

static void on_dll_discovered(drakvuf_t drakvuf, std::string const& dll_name, const dll_view_t* dll, void* extra)
{
    memdump* plugin = (memdump*)extra;

    plugin->wanted_hooks.visit_hooks_for(dll_name, [&](const auto& e)
    {
        drakvuf_request_usermode_hook(drakvuf, dll, &e, usermode_hook_cb, plugin);
    });
}

static void on_dll_hooked(drakvuf_t drakvuf, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets, void* extra)
{
    PRINT_DEBUG("[MEMDUMP] DLL hooked - done\n");
}

void memdump::userhook_init(drakvuf_t drakvuf, const memdump_config* c, output_format_t output)
{
    if (!drakvuf_are_userhooks_supported(drakvuf))
    {
        PRINT_DEBUG("[MEMDUMP] Usermode hooking not supported. Some features will be disabled.\n");
        return;
    }

    try
    {
        auto noStack = [](const auto& entry)
        {
            return !entry.actions.stack;
        };
        drakvuf_load_dll_hook_config(drakvuf, c->dll_hooks_list, c->print_no_addr, noStack, this->wanted_hooks);
    }
    catch (const std::runtime_error& exc)
    {
        std::cerr << "Loading DLL hook configuration for MEMDUMP plugin failed\n"
            << "Reason: " << exc.what() << "\n";
        throw -1;
    }

    if (this->wanted_hooks.empty())
    {
        // don't load this part of plugin if there is nothing to do
        return;
    }

    usermode_cb_registration reg =
    {
        .pre_cb = on_dll_discovered,
        .post_cb = on_dll_hooked,
        .extra = (void*)this
    };
    drakvuf_register_usermode_callback(drakvuf, &reg);
}

void memdump::setup_dotnet_hooks(drakvuf_t drakvuf, const char* dll_name, const char* profile)
{
    PRINT_DEBUG("%s profile found, will setup usermode hooks for .NET\n", dll_name);

    addr_t func_rva = 0;
    {
        auto profile_json = json_object_from_file(profile);
        if (!profile_json)
        {
            PRINT_DEBUG("[MEMDUMP] Failed to load JSON debug info for %s\n", dll_name);
            return;
        }

        // LoadImage_1 => AssemblyNative::LoadImage
        if (!json_get_symbol_rva(drakvuf, profile_json, "LoadImage_1", &func_rva))
        {
            PRINT_DEBUG("[MEMDUMP] Failed to find LoadImage_1 (AssemblyNative::LoadImage) RVA in json for %s\n", dll_name);
            json_object_put(profile_json);
            return;
        }
        json_object_put(profile_json);
    }

    auto actions = HookActions::empty().set_log().set_stack();
    this->wanted_hooks.add_hook(dll_name, "AssemblyNative::LoadImage", func_rva, actions, std::vector< std::unique_ptr< ArgumentPrinter > > {});
}

void memdump::userhook_destroy()
{

}
