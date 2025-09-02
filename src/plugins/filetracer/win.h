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

#ifndef FILETRACER_WIN_H
#define FILETRACER_WIN_H

#include "plugins/plugins_ex.h"
#include "private.h"

using namespace filetracer_ns;

struct filetracer_config
{
    const char* ole32_profile;
};

class win_filetracer : public pluginex
{
public:
    std::array<size_t, __OFFSET_MAX> offsets;

    bool has_ole32 = false;
    std::array<size_t, __OLE32_OFFSET_MAX> ole32_offsets;

    /* Hooks */
    std::unique_ptr<libhook::SyscallHook> create_file_hook;
    std::unique_ptr<libhook::SyscallHook> open_file_hook;
    std::unique_ptr<libhook::SyscallHook> open_directory_object_hook;
    std::unique_ptr<libhook::SyscallHook> query_attributes_file_hook;
    std::unique_ptr<libhook::SyscallHook> query_full_attributes_file_hook;
    std::unique_ptr<libhook::SyscallHook> set_information_file_hook;
    std::unique_ptr<libhook::SyscallHook> read_file_hook;
    std::unique_ptr<libhook::SyscallHook> write_file_hook;
    std::unique_ptr<libhook::SyscallHook> query_information_file_hook;

    /* Return hooks */
    std::map<std::pair<uint64_t, addr_t>, std::unique_ptr<libhook::ReturnHook>> ret_hooks;

    /* Callbacks */
    event_response_t create_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t open_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t open_directory_object_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t query_attributes_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t query_full_attributes_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t set_information_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t read_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t write_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t query_information_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    /* Return callbacks */
    event_response_t create_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t open_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t query_attributes_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t query_full_attributes_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t query_information_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    /* File info parsing */
    std::tuple<bool, win_objattrs_t> objattr_read(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t attrs);
    std::tuple<bool, file_basic_information_t> basic_file_info_read(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t basic_file_info);
    std::tuple<bool, file_network_open_information_t> net_file_info_read(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t net_file_info);

    /* Helper functions */
    void print_file_obj_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const win_objattrs_t& attrs);
    void print_create_file_obj_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t handle, uint32_t io_information, const win_objattrs_t& attrs, win_data* params, uint64_t status);
    void print_open_file_obj_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t handle, uint32_t io_information, const win_objattrs_t& attrs, win_data* params, uint64_t status);
    void print_file_read_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t handle);
    void print_file_query_full_attributes(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const win_objattrs_t& attrs, const file_network_open_information_t& file_info, uint64_t status);
    void print_file_query_attributes(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const win_objattrs_t& attrs, const file_basic_information_t& file_info, uint64_t status);
    void print_delete_file_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t handle, addr_t fileinfo);
    void print_basic_file_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t src_file_handle, const file_basic_information_t& basic_file_info, uint64_t status);
    void print_file_net_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t src_file_handle, const file_network_open_information_t& file_info, uint64_t status);
    void print_rename_file_info(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t src_file_handle, addr_t fileinfo);
    void print_eof_file_info(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t src_file_handle, addr_t fileinfo);

    win_filetracer(drakvuf_t drakvuf, const filetracer_config* config, output_format_t output);
    win_filetracer(const win_filetracer&) = delete;
    win_filetracer& operator=(const win_filetracer&) = delete;
};

#endif
