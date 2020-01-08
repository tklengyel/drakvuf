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

#include <libvmi/libvmi.h>
#include <cassert>

#include "clipboardmon.h"

static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    clipboardmon* c = static_cast<clipboardmon*>(info->trap->data);

    gchar* escaped_pname = NULL;

    switch (c->format)
    {
        case OUTPUT_CSV:
            printf("clipboardmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid);
            break;
        case OUTPUT_KV:
            printf("clipboardmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name);
            break;
        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            printf( "{"
                    "\"Plugin\" : \"clipboardmon\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"ProcessName\": %s,"
                    "\"UserName\": \"%s\","
                    "\"UserId\": %" PRIu64 ","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"Method\" : \"%s\","
                    "}\n",
                    UNPACK_TIMEVAL(info->timestamp),
                    escaped_pname,
                    USERIDSTR(drakvuf), info->proc_data.userid,
                    info->proc_data.pid, info->proc_data.ppid,
                    info->trap->name);
            g_free(escaped_pname);
            break;
        default:
        case OUTPUT_DEFAULT:
            printf("[CLIPBOARDMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid);
            break;
    }

    return VMI_EVENT_RESPONSE_NONE;
}

static bool register_trap( drakvuf_t drakvuf, json_object* profile_json, const char* function_name,
                           drakvuf_trap_t* trap,
                           event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    addr_t func_rva = 0;
    if ( !json_get_symbol_rva(drakvuf, profile_json, function_name, &func_rva) )
    {
        PRINT_DEBUG("[CLIPBOARDMON] Failed to get RVA of win32k!%s\n", function_name);
        return false;
    }

    addr_t w32pst_rva = 0;
    if ( !json_get_symbol_rva(drakvuf, profile_json, "W32pServiceTable", &w32pst_rva) )
    {
        PRINT_DEBUG("[CLIPBOARDMON] Failed to get RVA of win32k!W32pServiceTable\n");
        return false;
    }

    addr_t sdt_rva = 0;
    if ( !drakvuf_get_kernel_symbol_rva( drakvuf, "KeServiceDescriptorTableShadow", &sdt_rva) )
    {
        PRINT_DEBUG("[CLIPBOARDMON] [Init] Failed to get RVA of nt!KeServiceDescriptorTableShadow\n");
        return false;
    }

    addr_t sdt_va = 0;
    if (!(sdt_va = drakvuf_exportksym_to_va(drakvuf, 4, nullptr, "ntoskrnl.exe", sdt_rva)))
    {
        PRINT_DEBUG("[CLIPBOARDMON] [Init] Failed to get VA of nt!KeServiceDescriptorTableShadow\n");
        return false;
    }

    const int SYSTEM_SERVICE_TABLE_32 = 16;
    const int SYSTEM_SERVICE_TABLE_64 = 32;
    bool is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    addr_t offset = is32bit ? SYSTEM_SERVICE_TABLE_32 : SYSTEM_SERVICE_TABLE_64;
    addr_t ssdt_ptr_va = sdt_va + offset;

    addr_t eprocess_base = 0;
    if (!drakvuf_find_process(drakvuf, ~0, "explorer.exe", &eprocess_base))
    {
        PRINT_DEBUG("[CLIPBOARDMON] [Init] Failed to find EPROCESS of \"explorer.exe\"\n");
        return false;
    }

    vmi_pid_t pid = 0;
    if (!drakvuf_get_process_pid(drakvuf, eprocess_base, &pid))
    {
        PRINT_DEBUG("[CLIPBOARDMON] [Init] Failed to get PID of \"explorer.exe\"\n");
        return false;
    }

    vmi_lock_guard vmi(drakvuf);

    if (VMI_SUCCESS != vmi_pid_to_dtb(vmi.vmi, pid, &trap->breakpoint.dtb))
    {
        PRINT_DEBUG("[CLIPBOARDMON] [Init] Failed to get CR3 of \"explorer.exe\"\n");
        return false;
    }

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .addr = ssdt_ptr_va,
        .dtb = trap->breakpoint.dtb,
    };
    addr_t ssdt_va = 0;
    if (VMI_SUCCESS != vmi_read_addr(vmi.vmi, &ctx, &ssdt_va))
    {
        PRINT_DEBUG("[CLIPBOARDMON] Failed to read the address of SSDT (VA 0x%lx)\n", ssdt_ptr_va);
        return false;
    }

    trap->name = function_name;
    trap->cb   = hook_cb;
    trap->breakpoint.addr = ssdt_va - w32pst_rva + func_rva;

    if ( !drakvuf_add_trap( drakvuf, trap ) )
    {
        PRINT_DEBUG("[CLIPBOARDMON] Failed to trap VA 0x%lx\n", trap->breakpoint.addr);
        return false;
    }

    return true;
}

clipboardmon::clipboardmon(drakvuf_t drakvuf, const clipboardmon_config* c, output_format_t output)
    : format(output)
{
    if ( !c->win32k_profile )
    {
        PRINT_DEBUG("Clipboardmon plugin requires the JSON debug info for win32k.sys!\n");
        return;
    }

    json_object* profile_json = json_object_from_file(c->win32k_profile);
    if (!profile_json)
    {
        PRINT_DEBUG("Clipboardmon plugin fails to load JSON debug info for win32k.sys\n");
        throw -1;
    }

    assert(sizeof(traps) / sizeof(traps[0]) >= 4);
    if ( !register_trap(drakvuf, profile_json, "NtUserGetClipboardData", &traps[0], cb) )
        throw -1;
    if ( !register_trap(drakvuf, profile_json, "NtUserAddClipboardFormatListener", &traps[1], cb) )
        throw -1;
    if ( !register_trap(drakvuf, profile_json, "NtUserSetClipboardViewer", &traps[2], cb) )
        throw -1;
    if ( !register_trap(drakvuf, profile_json, "NtUserSetClipboardData", &traps[3], cb) )
        throw -1;
}
