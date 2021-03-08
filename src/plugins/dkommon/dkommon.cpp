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

#include <libvmi/libvmi.h>

#include "dkommon.h"
#include "plugins/output_format.h"

#include <algorithm>

enum offset
{
    EPROCESS_ACTIVEPROCESSLINKS,
    LIST_ENTRY_BLINK,
    LIST_ENTRY_FLINK,
    LDR_DATA_TABLE_ENTRY_INLOADORDERLINKS,
    LDR_DATA_TABLE_ENTRY_FULLDLLNAME,
    __OFFSET_MAX
};

static const char* offset_names[__OFFSET_MAX][2] =
{
    [EPROCESS_ACTIVEPROCESSLINKS] = {"_EPROCESS", "ActiveProcessLinks"},
    [LIST_ENTRY_BLINK] = {"_LIST_ENTRY", "Blink"},
    [LIST_ENTRY_FLINK] = {"_LIST_ENTRY", "Flink"},
    [LDR_DATA_TABLE_ENTRY_INLOADORDERLINKS] = {"_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"},
    [LDR_DATA_TABLE_ENTRY_FULLDLLNAME] = {"_LDR_DATA_TABLE_ENTRY", "FullDllName"},
};

static void print_hidden_process_information(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    dkommon* d = static_cast<dkommon*>(info->trap->data);

    fmt::print(d->format, "dkommon", drakvuf, info,
               keyval("Message", fmt::Qstr("Hidden Process"))
              );
}

static event_response_t check_hidden_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    dkommon* d = static_cast<dkommon*>(info->trap->data);
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    addr_t list_entry_va = info->attached_proc_data.base_addr + d->offsets[EPROCESS_ACTIVEPROCESSLINKS];
    addr_t flink = 0;
    addr_t blink = 0;

    ctx.addr = list_entry_va + d->offsets[LIST_ENTRY_FLINK];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &flink) )
        goto err;

    ctx.addr = list_entry_va + d->offsets[LIST_ENTRY_BLINK];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &blink) )
        goto err;

    if (list_entry_va == flink && flink == blink &&
        std::find(d->processes_list.begin(), d->processes_list.end(), info->attached_proc_data.pid) == d->processes_list.end())
    {
        d->processes_list.push_back(info->attached_proc_data.pid);
        print_hidden_process_information(drakvuf, info);
    }
    else
    {
        goto done;
    }

err:
    PRINT_DEBUG("[DKOMmon] Error. Failed to read virtual address.\n");

done:
    drakvuf_release_vmi(drakvuf);

    return 0;
}

static event_response_t notify_zero_page_write(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    dkommon* d = static_cast<dkommon*>(info->trap->data);

    fmt::print(d->format, "dkommon", drakvuf, info,
               keyval("Message", fmt::Qstr("Zero Page Write"))
              );

    return 0;
}

static void print_driver(drakvuf_t drakvuf, drakvuf_trap_info_t* info, output_format_t format, const char* message, const char* name)
{
    fmt::print(format, "dkommon", drakvuf, info,
               keyval("Message", fmt::Qstr(message)),
               keyval("DriverName", fmt::Qstr(name))
              );
}

static std::vector<std::string> enumerate_drivers(dkommon* d, drakvuf_t drakvuf)
{
    std::vector<std::string> drivers_list;

    vmi_lock_guard vmi(drakvuf);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
    };

    if (VMI_SUCCESS != vmi_pid_to_dtb(vmi.vmi, 4, &ctx.dtb))
    {
        PRINT_DEBUG("dkommon:enumerate drivers: failed to get CR3 for System process\n");
        return drivers_list;
    }

    addr_t list_head = 0;
    ctx.addr = d->modules_list_va;
    if ( VMI_SUCCESS != vmi_read_addr(vmi.vmi, &ctx, &list_head) )
    {
        PRINT_DEBUG("dkommon:enumerate drivers: failed to read PsLoadedModuleList (VA 0x%lx)\n", ctx.addr);
        return drivers_list;
    }
    list_head -= d->offsets[LDR_DATA_TABLE_ENTRY_INLOADORDERLINKS];

    addr_t entry = list_head;
    do
    {
        ctx.addr = entry + d->offsets[LDR_DATA_TABLE_ENTRY_INLOADORDERLINKS] + d->offsets[LIST_ENTRY_FLINK];
        if ( VMI_SUCCESS != vmi_read_addr(vmi.vmi, &ctx, &entry) )
        {
            PRINT_DEBUG("dkommon:enumerate drivers: failed to read next entry (VA 0x%lx)\n", ctx.addr);
            return drivers_list;
        }

        ctx.addr = entry + d->offsets[LDR_DATA_TABLE_ENTRY_FULLDLLNAME];
        auto name = drakvuf_read_unicode_common(vmi.vmi, &ctx);
        if (name && name->contents)
        {
            drivers_list.push_back(std::string(reinterpret_cast<char*>(name->contents)));
            vmi_free_unicode_str(name);
        }
    } while (entry != list_head);

    return drivers_list;
}

static event_response_t check_hidden_drivers(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    dkommon* d = static_cast<dkommon*>(info->trap->data);

    auto list = enumerate_drivers(d, drakvuf);

    // Check for new drivers
    for (auto i: list)
        if (std::find(d->drivers_list.begin(), d->drivers_list.end(), i) == d->drivers_list.end())
            print_driver(drakvuf, info, d->format, "Driver Added", i.c_str());

    // Check for deleted drivers
    for (auto i: d->drivers_list)
        if (std::find(list.begin(), list.end(), i) == list.end())
            print_driver(drakvuf, info, d->format, "Driver Removed", i.c_str());

    d->drivers_list = list;

    return VMI_EVENT_RESPONSE_NONE;
}

dkommon::dkommon(drakvuf_t drakvuf, const void* config, output_format_t output)
    : format(output)
    , offsets(new size_t[__OFFSET_MAX])
{
    if ( !drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, __OFFSET_MAX, offsets) )
        throw -1;

    addr_t ml_rva = 0;
    if ( !drakvuf_get_kernel_symbol_rva( drakvuf, "PsLoadedModuleList", &ml_rva) )
        throw -1;

    if (!(modules_list_va = drakvuf_exportksym_to_va(drakvuf, 4, nullptr, "ntoskrnl.exe", ml_rva)))
        throw -1;

    drivers_list = enumerate_drivers(this, drakvuf);
    for (auto i: drivers_list)
        PRINT_DEBUG("[DKOMmon] Found driver '%s'\n", i.c_str());

    /* Setup trap for thread switch */
    processes_trap.cb = check_hidden_process;
    if (!drakvuf_add_trap(drakvuf, &processes_trap)) throw -1;

    drivers_trap.cb = check_hidden_drivers;
    if (!drakvuf_add_trap(drakvuf, &drivers_trap)) throw -1;

    zeropage_trap.cb = notify_zero_page_write;
    if (!drakvuf_add_trap(drakvuf, &zeropage_trap)) throw -1;
}

dkommon::~dkommon()
{
    delete[] offsets;
}
