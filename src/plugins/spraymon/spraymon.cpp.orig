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

#include <libvmi/libvmi.h>
#include <libdrakvuf/libdrakvuf.h>
#include <json-c/json_object.h>

#include "spraymon.h"
#include "plugins/output_format.h"

bool spraymon::read_counter(drakvuf_t drakvuf, addr_t vaddr, vmi_pid_t pid, uint16_t* value)
{
    vmi_lock_guard vmi(drakvuf);
    return (VMI_SUCCESS == vmi_read_16_va(vmi, vaddr, pid, value));
}

bool spraymon::read_kernel_addr(drakvuf_t drakvuf, addr_t in_address, vmi_pid_t pid, addr_t* out_address)
{
    vmi_lock_guard vmi(drakvuf);
    return (VMI_SUCCESS == vmi_read_addr_va(vmi, in_address, pid, out_address));
}

bool spraymon::get_counters(drakvuf_t drakvuf, addr_t process, vmi_pid_t pid, uint16_t* gdi_max_count, uint16_t* usr_max_count)
{
    addr_t win32process;

    if (!read_kernel_addr(drakvuf, process + this->eprocess_win32process, pid, &win32process))
    {
        PRINT_DEBUG("[SPRAYMON] Failed to read EPROCESS->Win32Process\n");
        return false;
    }

    if (!win32process)
    {
        PRINT_DEBUG("[SPRAYMON] Win32Process is NULL\n");
        return false;
    }
    if (!read_counter(drakvuf, win32process + this->gdihandlecountpeak, pid, gdi_max_count))
    {
        PRINT_DEBUG("[SPRAYMON] Failed to read GDI peak handle count\n");
        return false;
    }

    if (!read_counter(drakvuf, win32process + this->userhandlecountpeak, pid, usr_max_count))
    {
        PRINT_DEBUG("[SPRAYMON] Failed to read USER peak handle count\n");
        return false;
    }
    return true;
}

void spraymon::log(drakvuf_t drakvuf, uint16_t gdi_max_count, uint16_t usr_max_count, char* process_name, vmi_pid_t pid)
{
    if (gdi_max_count > this->gdi_threshold || usr_max_count > this->usr_threshold)
    {
        fmt::print(this->format, "spraymon", drakvuf, nullptr,
            keyval("PID", fmt::Nval(pid)),
            keyval("ProcessName", fmt::Qstr(process_name)),
            keyval("Reason", fmt::Qstr("High graphic objects count")));
    }
}

static void process_visitor(drakvuf_t drakvuf, addr_t process, void* ctx)
{
    auto eprocess_list = static_cast<std::vector<addr_t>*>(ctx);
    eprocess_list->push_back(process);
}

event_response_t spraymon::hook_setwin32process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t process = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t w32new = drakvuf_get_function_argument(drakvuf, info, 2);

    if (w32new != 0)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    vmi_pid_t pid;
    uint16_t gdi_max_count;
    uint16_t usr_max_count;

    auto process_name = drakvuf_get_process_name(drakvuf, process, true);

    if (!drakvuf_get_process_pid(drakvuf, process, &pid))
    {
        PRINT_DEBUG("[SPRAYMON] Failed to get process PID");
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!get_counters(drakvuf, process, pid, &gdi_max_count, &usr_max_count))
    {
        PRINT_DEBUG("[SPRAYMON] (fail) Process name -> %s\n", process_name);
        return VMI_EVENT_RESPONSE_NONE;
    }

    log(drakvuf, gdi_max_count, usr_max_count, process_name, pid);

    PRINT_DEBUG("[SPRAYMON] (success) Process name -> %s\nGDI count -> %du\nUSER count -> %du\n",
        process_name, gdi_max_count, usr_max_count);

    g_free(const_cast<char*>(process_name));
    return VMI_EVENT_RESPONSE_NONE;
}

spraymon::spraymon(drakvuf_t drakvuf, const spraymon_config* config,
    output_format_t output)
    : pluginex(drakvuf, output)
    , format(output)
    , do_final_analysis(true)
    , gdi_threshold(config->gdi_threshold)
    , usr_threshold(config->usr_threshold)

{
    win_ver_t winver;
    uint16_t build;
    {
        vmi_lock_guard vmi(drakvuf);
        win_build_info_t build_info;
        if (!vmi_get_windows_build_info(vmi, &build_info))
            throw -1;

        winver = build_info.version;
        build = build_info.buildnumber;
    }

    //https://www.geoffchappell.com/studies/windows/km/win32k/structs/processinfo/index.htm
    if (winver != VMI_OS_WINDOWS_7 && !(winver == VMI_OS_WINDOWS_10 && build >= 14393))
    {
        PRINT_DEBUG("[SPRAYMON] Spraymon plugin supports only Windows 7 and Windows 10 (=>1607)\n");
        do_final_analysis = false;
        return;
    }

    if (!config->win32k_profile)
    {
        PRINT_DEBUG("[SPRAYMON] Win32k json profile required to run the plugin.\n");
        do_final_analysis = false;
        return;
    }
    json_object* win32k_profile = json_object_from_file(config->win32k_profile);

    if (!win32k_profile)
    {
        PRINT_DEBUG("[SPRAYMON] Failed to load JSON debug info for win32k.sys.\n");
        throw -1;
    }

    // Collect win32k offsets
    if (!json_get_struct_member_rva(drakvuf, win32k_profile, "_W32PROCESS", "GDIHandleCountPeak", &this->gdihandlecountpeak) ||
        !json_get_struct_member_rva(drakvuf, win32k_profile, "_W32PROCESS", "UserHandleCountPeak", &this->userhandlecountpeak)
    )
    {
        PRINT_DEBUG("[SPRAYMON] Failed to win32k members offsets.\n");
        throw -1;
    }
    json_object_put(win32k_profile);

    // Collect kernel struct member offsets
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_EPROCESS", "Win32Process", &this->eprocess_win32process))
    {
        PRINT_DEBUG("[SPRAYMON] Failed to get kernel struct member offsets.\n");
        throw -1;
    }
    syscall = createSyscallHook("PsSetProcessWin32Process", &spraymon::hook_setwin32process_cb);
    PRINT_DEBUG("[SPRAYMON]  PLUGIN STARTED\n");
}

bool spraymon::stop_impl()
{
    if (!this->is_stopping() && do_final_analysis)
    {
        std::vector<addr_t> process_list;
        vmi_pid_t pid;
        uint16_t gdi_max_count;
        uint16_t usr_max_count;
        proc_data_t data{};

        PRINT_DEBUG("[SPRAYMON] Starting final analysis\n");
        drakvuf_enumerate_processes(drakvuf, process_visitor, &process_list);
        for (const auto& process : process_list)
        {
            gdi_max_count = 0;
            usr_max_count = 0;

            if (!drakvuf_get_process_data(drakvuf, process, &data))
            {
                PRINT_DEBUG("[SPRAYMON] Failed to get process data.\n");
                g_free(const_cast<char*>(data.name));
                continue;
            }

            if (!drakvuf_get_process_pid(drakvuf, process, &pid))
            {
                PRINT_DEBUG("[SPRAYMON] Failed to get process pid.\n");
                g_free(const_cast<char*>(data.name));
                continue;
            }

            if (!get_counters(drakvuf, process, pid, &gdi_max_count, &usr_max_count))
            {
                PRINT_DEBUG("[SPRAYMON] (fail) Process name -> %s\n", data.name);
                g_free(const_cast<char*>(data.name));
                continue;
            }
            log(drakvuf, gdi_max_count, usr_max_count, const_cast<char*>(data.name), data.pid);

            PRINT_DEBUG("[SPRAYMON] Process name -> %s\nGDI count -> %du\nUSER count -> %du\n",
                data.name, gdi_max_count, usr_max_count);

            g_free(const_cast<char*>(data.name));

        }
    }
    return true;
}
