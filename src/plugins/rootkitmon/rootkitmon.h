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
#pragma once

#include "plugins/plugins_ex.h"
#include "private.h"

struct rootkitmon_config
{
    const char* fwpkclnt_profile;
    const char* fltmgr_profile;
};

class rootkitmon : public pluginex
{
public:
    rootkitmon(drakvuf_t drakvuf, const rootkitmon_config* config, output_format_t output);
    rootkitmon(const rootkitmon&) = delete;
    rootkitmon& operator=(const rootkitmon&) = delete;
    ~rootkitmon();

    event_response_t callback_hooks_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t final_check_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    std::unique_ptr<libhook::ManualHook> register_profile_hook(drakvuf_t drakvuf, const char* profile, const char* dll_name,
        const char* func_name, hook_cb_t callback);
    std::unique_ptr<libhook::ManualHook> register_reg_hook(hook_cb_t callback, register_t reg);
    std::unique_ptr<libhook::ManualHook> register_mem_hook(hook_cb_t callback, addr_t pa, vmi_mem_access_t access);

    std::set<driver_t> enumerate_driver_objects(vmi_instance_t vmi);
    std::set<driver_t> enumerate_directory(vmi_instance_t vmi, addr_t addr);
    unicode_string_t* get_object_type_name(vmi_instance_t vmi, addr_t object);
    device_stack_t enumerate_driver_stacks(vmi_instance_t vmi, addr_t driver_object);
    bool enumerate_cores(vmi_instance_t vmi);

    void check_driver_integrity(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    void check_driver_objects(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    void check_descriptors(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    virtual bool stop_impl() override;

    const output_format_t format;
    win_ver_t winver;

    size_t* offsets;
    size_t guest_ptr_size;
    bool is32bit;
    size_t object_header_size;

    bool done_final_analysis;
    bool not_supported;

    addr_t halprivatetable;
    addr_t type_idx_table;
    uint8_t ob_header_cookie;

    std::unordered_map<driver_t, std::vector<checksum_data_t>> driver_sections_checksums;
    std::unordered_map<driver_t, sha256_checksum_t> driver_object_checksums;
    // _DRIVER_OBJECT -> _DEVICE_OBJECT -> [_DEVICE_OBJECT, ...]
    std::unordered_map<driver_t, device_stack_t> driver_stacks;
    // VCPU -> Descriptor
    std::unordered_map<unsigned int, descriptors_t> descriptors;
    // VCPU -> MSR_LSTAR
    std::unordered_map<unsigned int, addr_t> msr_lstar;
    std::vector<std::unique_ptr<libhook::ManualHook>> manual_hooks;
    std::vector<std::unique_ptr<libhook::SyscallHook>> syscall_hooks;
};
