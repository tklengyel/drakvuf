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

#pragma once

#include <vector>
#include <memory>
#include <set>
#include <filesystem>
#include <optional>
#include <string>
#include <array>
#include <glib.h>
#include "plugins/private.h"
#include "plugins/plugins_ex.h"

//Struct to pass the parameters
struct codemon_config_struct
{
    //Dir to save extracted frames to
    const std::string dump_dir;

    //Executable to filter
    const std::string filter_executable;

    //Enables logging (to shell) of pagefaults and writefaults. Additionally, logs of analysed pages can be printed regardless if malware was detected or not.
    bool log_everything;

    //By default only page sized areas are dumped. By setting this flag whole VAD nodes can be dumped instead.
    bool dump_vad;

    //Can be utilised to enforce the analysis of vads, which names (paths of mapped dlls / exes) contain System32 or SysWOW64
    bool analyse_system_dll_vad;

    //By default we assume everything to be malware. If this flag is enabled we assume all analysed memory areas to be goodware instead. This flag should be just set if a classifier is integrated.
    bool default_benign;
};

class codemon : public pluginex
{
public:
    codemon(drakvuf_t drakvuf, const codemon_config_struct* config, output_format_t output);

    std::filesystem::path dump_dir;

    std::optional<std::string> filter_executable;

    //a temporary dump file
    std::string tmp_file_path;

    //Counts how often an actual dump occured
    unsigned int dump_id = 0;

    // hooks and callbacks for MmAccessFault
    std::unique_ptr<libhook::SyscallHook> mmAccessFaultHook;
    std::unique_ptr<libhook::ReturnHook> mmAccessFaultReturnHook;
    event_response_t mm_access_fault_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info);
    event_response_t mm_access_fault_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info);

    // hooks and callbacks for memory execution/write
    std::set<std::unique_ptr<libhook::MemAccessHook>> memaccess_hooks;
    event_response_t execute_faulted_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info);
    event_response_t write_faulted_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* trap_info);

    // responsible for removing traps from memaccess_hooks field based on drakvuf_trap_info_t
    void remove_memaccess_hook(drakvuf_trap_info_t* trap_info);

    // used for forcing windows to load swapped pages
    event_response_t ki_system_service_handler_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    std::unique_ptr<libhook::SyscallHook> kiSystemServiceHandlerHook;
    x86_registers_t backup_regs;
    std::set<std::pair<vmi_pid_t, uint32_t /*thread_id*/>> pf_in_progress;

    // Keeps track of monitored pages. Prevents duplicate traps.
    std::set<std::pair<addr_t, addr_t>> monitored_pages;

    // Keeps track of the data which was already dumped, used to prevent duplicate dump files.
    // Uses the hash as key and the dumped file stem (without extension) as value.
    std::unordered_map<std::string, std::string> dumped_memory_map;

    // processing
    void save_file_metadata(const drakvuf_trap_info_t* trap_info, const struct dump_metadata_struct* dump_metadata, addr_t page_va);
    void log_all_to_console(const drakvuf_trap_info* trap_info, struct dump_metadata_struct* dump_metadata, addr_t page_va);
    bool analyse_memory(const drakvuf_trap_info_t* trap_info, struct dump_metadata_struct* dump_metadata, addr_t page_va);
};
