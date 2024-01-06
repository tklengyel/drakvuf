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

#ifndef WIN_USERHOOK_PRIVATE_H
#define WIN_USERHOOK_PRIVATE_H

#include <vector>
#include <memory>
#include <set>
#include <map>

#include <glib.h>
#include "plugins/plugins_ex.h"

class userhook; // Forward declaration.

#define VAD_TYPE_DLL 2

enum offset
{
    KTHREAD_TRAPFRAME,
    KTRAP_FRAME_RIP,
    __OFFSET_MAX
};

static const char* offset_names[__OFFSET_MAX][2] =
{
    [KTHREAD_TRAPFRAME] = { "_KTHREAD", "TrapFrame" },
    [KTRAP_FRAME_RIP] = {"_KTRAP_FRAME", "Rip"},
};

/**
 * Running hook helper data structure.
 * Used for passing user arguments and additional data between callbacks.
 */
struct rh_data_t
{
    // Arguments provided by the user.
    addr_t target_process;
    std::string dll_name;
    std::string func_name;
    callback_t cb;
    void* extra;

    // Additional data. Stored here for optimalization.
    target_hook_state state;
    vmi_pid_t target_process_pid;
    uint32_t target_process_tid;
    uint64_t target_process_rsp;
    addr_t target_process_dtb;
    addr_t func_addr;
    x86_registers_t regs;
    bool inject_in_progress{false};

    // We need to pass this around as we need offsets.
    userhook* userhook_plugin;

    rh_data_t(userhook* userhook_plugin, addr_t target_process, vmi_pid_t target_process_pid,
        std::string dll_name, std::string func_name, callback_t cb, void* extra):
        target_process(target_process), dll_name(dll_name), func_name(func_name), cb(cb),
        extra(extra), state(HOOK_FIRST_TRY), target_process_pid(target_process_pid),
        target_process_dtb(), func_addr(), userhook_plugin(userhook_plugin) {}


    static void free_trap(drakvuf_trap_t* trap)
    {
        if (!trap)
            return;

        if (trap->data)
            delete (rh_data_t*) trap->data;

        delete trap;
    }
};

struct dll_t
{
    dll_view_t v;

    // one entry per hooked function
    std::vector<hook_target_entry_t> targets;

    // internal, for page faults
    addr_t pf_current_addr;
    addr_t pf_max_addr;

    bool in_progress{false};
    x86_registers_t regs;

    uint64_t stack_marker()
    {
        // TODO Set initial random value and print this to log
        return 0x1aef05de1aef05de;
    }

    uint64_t* set_stack_marker()
    {
        m_stack_marker = stack_marker();
        return &m_stack_marker;
    }

    uint64_t stack_marker_va()
    {
        return m_stack_marker;
    }

    uint64_t m_stack_marker;
};

struct protect_virtual_memory_result_t : public call_result_t
{
    protect_virtual_memory_result_t() : call_result_t(), base_address() {}

    addr_t base_address;
};

struct map_view_of_section_result_t : public call_result_t
{
    map_view_of_section_result_t() : call_result_t(), section_handle(), process_handle(), base_address_ptr() {}

    uint64_t section_handle;
    uint64_t process_handle;
    addr_t base_address_ptr;
};

struct copy_on_write_result_t : public call_result_t
{
    copy_on_write_result_t() : call_result_t(), vaddr(), pte(), old_cow_pa() {}

    addr_t vaddr;
    addr_t pte;
    addr_t old_cow_pa;
    std::vector<hook_target_entry_t*> hooks;
};

class userhook : public pluginex
{
public:
    addr_t copy_virt_mem_va{0};

    userhook(userhook const&) = delete;
    userhook& operator=(userhook const&) = delete;

    virtual bool stop_impl() override;

    std::array<size_t, __OFFSET_MAX> offsets;

    std::vector<usermode_cb_registration> plugins;

    // map pid -> list of loaded/hooked dlls
    std::map<vmi_pid_t, std::vector<dll_t>> loaded_dlls;

    struct module_context_t
    {
        std::optional<mmvad_info_t> mmvad;
        bool is_hooked;
    };

    std::map<vmi_pid_t, module_context_t> proc_ntdll;

    const bool injection_mode;
    int injection_in_progress = 0;
    std::set<std::pair<vmi_pid_t, uint32_t /*tid*/>> pf_in_progress;

    void increment_injection_in_progress_count(const proc_data_t& proc_data);
    void decrement_injection_in_progress_count(const proc_data_t& proc_data);
    bool is_injection_in_progress(drakvuf_t drakvuf, drakvuf_trap_info_t* info) const;
    bool no_injection_in_progress() const;

    static userhook& get_instance(drakvuf_t drakvuf);

    static bool is_supported(drakvuf_t drakvuf);
    void register_plugin(drakvuf_t drakvuf, usermode_cb_registration reg);
    void request_usermode_hook(drakvuf_t drakvuf, const dll_view_t* dll, const plugin_target_config_entry_t* target, callback_t callback, void* extra);
    void request_userhook_on_running_process(drakvuf_t drakvuf, addr_t target_process, const std::string& dll_name, const std::string& func_name, callback_t cb, void* extra);

    bool add_running_trap(drakvuf_t drakvuf, drakvuf_trap_t* trap);
    void remove_running_trap(drakvuf_t drakvuf, drakvuf_trap_t* trap, drakvuf_trap_free_t free_routine);
    bool add_running_rh_trap(drakvuf_t drakvuf, drakvuf_trap_t* trap);
    void remove_running_rh_trap(drakvuf_t drakvuf, drakvuf_trap_t* trap);

private:
    userhook(drakvuf_t drakvuf, bool injection_mode_enabled); // Force get_instance().
    ~userhook();

    // We need to keep these for memory management purposes.
    // running_rh_traps are traps with data field set to rh_data_t and are used
    // internaly inside library.
    std::vector<drakvuf_trap_t*> running_traps;
    std::vector<drakvuf_trap_t*> running_rh_traps;
};

proc_data_t get_proc_data(drakvuf_t drakvuf, const drakvuf_trap_info_t* info);
bool make_trap(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info* info, hook_target_entry_t* target, addr_t exec_func);
bool is_pagetable_loaded(vmi_instance_t vmi, const drakvuf_trap_info* info, addr_t vaddr);

event_response_t internal_perform_hooking_pf(drakvuf_t drakvuf, drakvuf_trap_info* info, userhook* plugin, dll_t* dll_meta);
event_response_t internal_perform_hooking_injection(drakvuf_t drakvuf, drakvuf_trap_info* info, userhook* plugin, dll_t* dll_meta);

bool inject_copy_memory(userhook* plugin, drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    event_response_t (*cb)(drakvuf_t, drakvuf_trap_info_t*),
    uint64_t* stack_marker,
    addr_t addr,
    addr_t* stack_pointer);

event_response_t system_service_handler_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

#endif
