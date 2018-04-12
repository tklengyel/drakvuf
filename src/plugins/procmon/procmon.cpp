/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
*                                                                         *
* DRAKVUF (C) 2014-2017 Tamas K Lengyel.                                  *
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

#include <glib.h>
#include <config.h>
#include <inttypes.h>
#include <libvmi/x86.h>
#include <assert.h>

#include "../plugins.h"
#include "procmon.h"

static event_response_t create_user_process_hook(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t user_process_parameters_addr)
{
    const char* syscall_name = info->trap->name;
    procmon* f = (procmon*)info->trap->data;

    addr_t cmdline_addr = user_process_parameters_addr + f->command_line;
    addr_t imagepath_addr = user_process_parameters_addr + f->image_path_name;

    unicode_string_t* cmdline_us = drakvuf_read_unicode(drakvuf, info, cmdline_addr);
    unicode_string_t* imagepath_us = drakvuf_read_unicode(drakvuf, info, imagepath_addr);

    char const* cmdline = cmdline_us ? reinterpret_cast<char const*>(cmdline_us->contents) : "";
    char const* imagepath = imagepath_us ? reinterpret_cast<char const*>(imagepath_us->contents) : "";

    switch ( f->format )
    {
        case OUTPUT_CSV:
            printf("procmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64",%s,%s,%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   info->proc_data.userid, syscall_name, cmdline, imagepath);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[PROCMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ", EPROCESS:0x%" PRIx64 ", PID:%d, PPID:%d, %s %s:%" PRIi64 " %s:%s:%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.base_addr,
                   info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, syscall_name, cmdline, imagepath);
            break;
    }

    if (cmdline_us) vmi_free_unicode_str(cmdline_us);
    if (imagepath_us) vmi_free_unicode_str(imagepath_us);

    return 0;
}

static addr_t get_parameter_addr_win64(drakvuf_t drakvuf, const drakvuf_trap_info_t* info, int narg)
{
    procmon* f = (procmon*)info->trap->data;
    if (f->pm == VMI_PM_IA32E)
    {
        switch (narg)
        {
            case 1:
                return info->regs->rcx;
            case 2:
                return info->regs->rdx;
            case 3:
                return info->regs->r8;
            case 4:
                return info->regs->r9;
        }

        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = info->regs->rsp + narg * 8,
        };

        addr_t addr;
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &addr))
        {
            addr = 0;
        }
        drakvuf_release_vmi(drakvuf);
        return addr;
    }
    else
    {
        // TODO: Implement and test for 32bit guests.
        return 0;
    }
}

static event_response_t create_user_process_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // PRTL_USER_PROCESS_PARAMETERS RtlUserProcessParameters
    addr_t user_process_parameters_addr = get_parameter_addr_win64(drakvuf, info, 9);
    return create_user_process_hook(drakvuf, info, user_process_parameters_addr);
}

static void register_trap( drakvuf_t drakvuf, const char* rekall_profile, const char* syscall_name,
                           drakvuf_trap_t* trap,
                           event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !drakvuf_get_function_rva( rekall_profile, syscall_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = syscall_name;
    trap->cb   = hook_cb;

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}


procmon::procmon(drakvuf_t drakvuf, const void* config, output_format_t output)
{
    const char* rekall_profile = (const char*)config;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->pm = vmi_get_page_mode(vmi, 0);
    drakvuf_release_vmi(drakvuf);

    this->format = output;

    if (!drakvuf_get_struct_member_rva(rekall_profile, "_RTL_USER_PROCESS_PARAMETERS", "CommandLine", &this->command_line))
        throw -1;
    if (!drakvuf_get_struct_member_rva(rekall_profile, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName", &this->image_path_name))
        throw -1;

    assert(sizeof(traps) / sizeof(traps[0]) > 0);
    register_trap(drakvuf, rekall_profile, "NtCreateUserProcess", &traps[0], create_user_process_hook_cb);
}

procmon::~procmon() {}
