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

#ifndef FILEDELETE_H
#define FILEDELETE_H

#include "plugins/private.h"
#include "plugins/plugins.h"
#include "plugins/plugins_ex.h"

#include <map>
#include <utility>
#include <cstdint>

using handle_t = uint64_t;
using task_id = uint64_t;

struct filedelete_config
{
    const char* dump_folder;
    bool dump_modified_files;
    bool filedelete_use_injector;
};

struct task_t;

class filedelete: public pluginex
{
public:
    filedelete(drakvuf_t drakvuf, const filedelete_config* config, output_format_t output);
    filedelete(const filedelete&) = delete;
    filedelete& operator=(const filedelete&) = delete;
    ~filedelete();

    virtual bool stop_impl() override;

private:
    enum class error
    {
        success,
        none,
        error,
    };

    /* Internal data */
    drakvuf_t drakvuf{nullptr};
    std::unordered_map<uint64_t, std::unique_ptr<libhook::ReturnHook>> ret_hooks;
    std::unordered_map<task_id, std::unique_ptr<task_t>> tasks;
    bool is32bit{false};
    // Maps virtual address of buffer to free flag:
    // * `true` means pools is free;
    // * `false` otherwise.
    std::map<addr_t, bool> pools;

    size_t* offsets;
    size_t control_area_size = 0;
    size_t mmpte_size = 0;

    const char* dump_folder;
    output_format_t format;
    bool use_injector = false;

    int sequence_number = 0;

    /* Hooks */
    std::unique_ptr<libhook::SyscallHook> setinformation_hook;
    std::unique_ptr<libhook::SyscallHook> writefile_hook;
    std::unique_ptr<libhook::SyscallHook> close_hook;
    std::unique_ptr<libhook::SyscallHook> createsection_hook;
    std::unique_ptr<libhook::SyscallHook> createfile_hook;
    std::unique_ptr<libhook::SyscallHook> openfile_hook;

    /* VA of functions to be injected */
    addr_t queryvolumeinfo_va = 0;
    addr_t queryinfo_va = 0;
    addr_t createsection_va = 0;
    addr_t close_handle_va = 0;
    addr_t mapview_va = 0;
    addr_t unmapview_va = 0;
    addr_t readfile_va = 0;
    addr_t waitobject_va = 0;
    addr_t exallocatepool_va = 0;
    addr_t exfreepool_va = 0;
    addr_t memcpy_va = 0;

    /* Hook handlers */
    event_response_t setinformation_cb(drakvuf_t, drakvuf_trap_info_t*);
    event_response_t writefile_cb(drakvuf_t, drakvuf_trap_info_t*);
    event_response_t close_cb(drakvuf_t, drakvuf_trap_info_t*);
    event_response_t createsection_cb (drakvuf_t, drakvuf_trap_info_t*);
    event_response_t createfile_cb (drakvuf_t, drakvuf_trap_info_t*);
    event_response_t openfile_cb (drakvuf_t, drakvuf_trap_info_t*);
    event_response_t createfile_ret_cb(drakvuf_t, drakvuf_trap_info_t*);
    void createfile_cb_impl(drakvuf_t, drakvuf_trap_info_t*, addr_t handle);

    /* Dispatchers */
    // TODO Maybe remove "response" in flavor of "error"?
    error dispatch_pending(vmi_instance_t, drakvuf_trap_info_t*, task_t&);
    error dispatch_queryvolumeinfo(vmi_instance_t, drakvuf_trap_info_t*, task_t&);
    error dispatch_queryinfo(vmi_instance_t, drakvuf_trap_info_t*, task_t&);
    error dispatch_createsection(vmi_instance_t, drakvuf_trap_info_t*, task_t&);
    error dispatch_mapview(vmi_instance_t, drakvuf_trap_info_t*, task_t&);
    error dispatch_allocate_pool(vmi_instance_t, drakvuf_trap_info_t*, task_t&);
    error dispatch_memcpy(vmi_instance_t, drakvuf_trap_info_t*, task_t&);
    error dispatch_unmapview(vmi_instance_t, drakvuf_trap_info_t*, task_t&);
    error dispatch_close_handle(vmi_instance_t, drakvuf_trap_info_t*, task_t&);

    /* Injection helpers */
    bool inject_queryvolumeinfo(drakvuf_trap_info_t*, vmi_instance_t, task_t&);
    bool inject_queryinfo(drakvuf_trap_info_t*, vmi_instance_t, task_t&);
    bool inject_createsection(drakvuf_trap_info_t*, vmi_instance_t, task_t&);
    bool inject_mapview(drakvuf_trap_info_t*, vmi_instance_t, task_t&);
    bool inject_allocate_pool(drakvuf_trap_info_t*, vmi_instance_t, task_t&);
    bool inject_memcpy(drakvuf_trap_info_t*, vmi_instance_t, task_t&);
    bool inject_unmapview(drakvuf_trap_info_t*, vmi_instance_t, task_t&);
    bool inject_close_handle(drakvuf_trap_info_t*, vmi_instance_t, task_t&);

    /* Routines */
    bool get_file_object_handle_count(drakvuf_trap_info_t*,
        handle_t,
        uint64_t* handle_count);

    bool get_file_object_flags(drakvuf_trap_info_t*,
        vmi_instance_t,
        handle_t,
        uint64_t* flags);
    std::string get_file_name(vmi_instance_t,
        drakvuf_trap_info_t*,
        addr_t handle,
        addr_t* out_file,
        addr_t* out_filetype);
    void print_filedelete_information(drakvuf_trap_info_t*, task_t&);
    void print_extraction_failure(drakvuf_trap_info_t*,
        const std::string& filename,
        const std::string& message);
    void save_file_metadata(drakvuf_trap_info_t*, addr_t control_area, task_t&);
    bool save_file_chunk(int file_sequence_number,
        void* buffer,
        size_t size);
    addr_t get_function_va(const char* lib, const char* func_name);
    uint64_t make_hook_id(drakvuf_trap_info_t*);
    uint64_t make_task_id(vmi_pid_t pid, handle_t handle);
    uint64_t make_task_id(task_t&);
    void free_pool(addr_t va);
    addr_t find_pool();
    void free_resources(drakvuf_trap_info_t*, task_t&);
    void read_vm(vmi_instance_t, drakvuf_trap_info_t*, task_t&);

    void grab_file_by_handle(vmi_instance_t, drakvuf_trap_info_t*, task_t&);
    void extract_file(drakvuf_trap_info_t*, vmi_instance_t, task_t&);
    void extract_ca_file(drakvuf_trap_info_t*,
        vmi_instance_t,
        addr_t control_area,
        task_t&);
    event_response_t close_cb_injector(drakvuf_trap_info_t*);
    event_response_t close_cb_no_injector(drakvuf_trap_info_t*);
    bool is_handle_valid(handle_t);
};

#endif
