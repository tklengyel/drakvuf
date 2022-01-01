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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dirent.h>
#include <glib.h>
#include <err.h>

#include <libvmi/libvmi.h>
#include "objmon.h"
#include "plugins/output_format.h"

/*
NTSYSAPI NTSTATUS ZwDuplicateObject(
  HANDLE      SourceProcessHandle,
  HANDLE      SourceHandle,
  HANDLE      TargetProcessHandle,
  PHANDLE     TargetHandle,
  ACCESS_MASK DesiredAccess,
  ULONG       HandleAttributes,
  ULONG       Options
);
*/

struct duplicate_result_t : public call_result_t
{
    duplicate_result_t() : call_result_t()
    {}
    addr_t source_process_handle = 0;
    addr_t source_handle = 0;
    addr_t target_process_handle = 0;
    addr_t target_handle_va = 0;
    uint32_t desired_access = 0;
    uint32_t handle_attributes = 0;
    uint32_t options = 0;
};

static event_response_t ntduplicateobject_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    //Loads a pointer to the plugin, which is responsible for the trap
    auto plugin = get_trap_plugin<objmon>(info);

    //get_trap_params reinterprets the pointer of info->trap->data as a pointer to duplicate_result_t
    auto params = get_trap_params<duplicate_result_t>(info);

    //Verifies that the params we got above (preset by the previous trap) match the trap_information this cb got called with.
    if (!params->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    vmi_lock_guard lg(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = params->target_handle_va
    );

    addr_t target_handle;
    if (VMI_SUCCESS != vmi_read_addr(lg.vmi, &ctx, &target_handle))
    {
        PRINT_DEBUG("[OBJMON] Failed to read HANDLE at %#lx\n", params->target_handle_va);
        return VMI_EVENT_RESPONSE_NONE;
    }

    fmt::print(plugin->format, "objmon", drakvuf, info,
        keyval("SourceProcessHandle", fmt::Xval(params->source_process_handle)),
        keyval("SourceHandle", fmt::Xval(params->source_handle)),
        keyval("TargetProcessHandle", fmt::Xval(params->target_process_handle)),
        keyval("TargetHandle", fmt::Xval(target_handle)),
        keyval("DesiredAccess", fmt::Xval(params->desired_access)),
        keyval("HandleAttributes", fmt::Xval(params->handle_attributes)),
        keyval("Options", fmt::Xval(params->options))
    );

    //Destroys this return trap, because it is specific for the RIP and not usable anymore. This was the trap being called when the physical address got computed.
    //Deletes this trap from the list of existing traps traps
    //Additionally removes the trap and frees the memory
    plugin->destroy_trap(info->trap);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t ntduplicateobject_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<objmon>(info);
    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);
    if ( !ret_addr )
        return VMI_EVENT_RESPONSE_NONE;

    //Adds a return hook, a hook which will be called after function completes and returns.
    //Each time registers a trap, which is just for the process at the current step -> specific for the RIP
    auto trap = plugin->register_trap<duplicate_result_t>(
            info,
            ntduplicateobject_ret_cb,
            breakpoint_by_dtb_searcher());

    //If trap creation failed
    if (!trap)
    {
        PRINT_DEBUG("[OBJMON] Could not create NtDuplicateObject return hook\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    //After the trap got constructed, enrich its details already with some information we already (and just) know here (at this point).

    //duplicate_result_t extends from call_result_t which extends from plugin_params
    //get_trap_params reinterprets the pointer of trap->data as a pointer to duplicate_result_t
    //Load the information that is saved by hitting the first trap.
    //With params we can preset the params that the newly risen second breakpoint will receive.
    auto params = get_trap_params<duplicate_result_t>(trap);

    //Save the address of the target thread, address of the rsp (this was the rip-address, which we used for construction) and the value of the CR3 register to the params.
    params->set_result_call_params(info);

    //enrich the params of the new/next trap. This information is used later.
    params->source_process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    params->source_handle = drakvuf_get_function_argument(drakvuf, info, 2);
    params->target_process_handle = drakvuf_get_function_argument(drakvuf, info, 3);
    params->target_handle_va = drakvuf_get_function_argument(drakvuf, info, 4);
    params->desired_access = drakvuf_get_function_argument(drakvuf, info, 5);
    params->handle_attributes = drakvuf_get_function_argument(drakvuf, info, 6);
    params->options = drakvuf_get_function_argument(drakvuf, info, 7);

    return VMI_EVENT_RESPONSE_NONE;
}

/*
 NTKERNELAPI
 NTSTATUS
 ObCreateObject (
 IN KPROCESSOR_MODE ObjectAttributesAccessMode OPTIONAL,
 IN POBJECT_TYPE ObjectType,
 IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
 IN KPROCESSOR_MODE AccessMode,
 IN PVOID Reserved,
 IN ULONG ObjectSizeToAllocate,
 IN ULONG PagedPoolCharge OPTIONAL,
 IN ULONG NonPagedPoolCharge OPTIONAL,
 OUT PVOID *Object
 );
 */

struct ckey
{
    union
    {
        uint32_t key;
        char _key[4];
    };
};

static event_response_t obcreateobject_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    auto o = get_trap_plugin<objmon>(info);
    struct ckey ckey = {};

    addr_t addr = drakvuf_get_function_argument(drakvuf, info, 2);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr + o->key_offset
    );

    auto vmi = vmi_lock_guard(drakvuf);
    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &ckey.key))
        return 0;

    auto key = std::string(ckey._key, 4);

    fmt::print(o->format, "objmon", drakvuf, info,
        keyval("Key", fmt::Qstr(key))
    );

    return 0;
}

/* ----------------------------------------------------- */

objmon::objmon(drakvuf_t drakvuf, const objmon_config* config, output_format_t output)
    : pluginex(drakvuf, output)
    , format(output)
{
    breakpoint_in_system_process_searcher bp;

    if (!config->disable_obcreateobject)
    {
        if ( !drakvuf_get_kernel_struct_member_rva(drakvuf, "_OBJECT_TYPE", "Key", &this->key_offset) )
            throw -1;

        if (!register_trap(nullptr, obcreateobject_cb, bp.for_syscall_name("ObCreateObject")))
            throw -1;
    }

    if (!config->disable_ntduplicateobject &&
        !register_trap(nullptr, ntduplicateobject_cb, bp.for_syscall_name("NtDuplicateObject")))
    {
        throw -1;
    }
}

objmon::~objmon() {}
