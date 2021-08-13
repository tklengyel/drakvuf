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
 * This file was created by Jan Gruber.                                    *
 * It is distributed as part of DRAKVUF under the same license             *
 ***************************************************************************/

#include <sys/time.h>    /* timeval... */
#include <unistd.h>      /* usleep... */

#include <libdrakvuf/libdrakvuf.h>  /* eprint_current_time */
#include <json-c/json_object.h>     /* json_object_put,... */

/* Plugin code */
#include "../plugins.h"
#include "../private.h"             /* PRINT_DEBUG */

/* GUI reconstruction specific code */
#include "gui/vmi_win_gui_offsets.h"
#include "gui/vmi_win_gui_parser.h"
#include "gui/vmi_win_gui_utils.h"

#include "gui_monitor.h"

#define TRAP_FUNC "NtUserShowWindow"

/* Signifies, whether a GUI update has occured */
static volatile sig_atomic_t has_gui_update = false;

/* Timestamp of last drawing action */
static struct timeval last;

/* Synchronizes access to struct timeval last */
static std::mutex lock;

/* Trap on NtUserShowWindow */
static drakvuf_trap_t gui_trap =
{
    .breakpoint.lookup_type = LOOKUP_DTB,
    .breakpoint.addr_type = ADDR_VA,
    .type = BREAKPOINT,
    .data = NULL,
};

/* Callback triggered on NtUserShowWindow(...) */
static event_response_t on_draw(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    has_gui_update = true;
    {
        std::lock_guard<std::mutex> guard(lock);
        /* Keeps track of the last event */
        gettimeofday(&last, NULL);
    }
    return VMI_EVENT_RESPONSE_NONE;
}

/*
 * Registers a trap for the system call for NtUserShowWindow of win32k.sys by
 * utilizing the following routine:
 *
 *     1.  Find RVA of the function of interest (here NtUserShowWindow) from
 *         win32k-IST-JSON
 *     2.  Find RVA of the GUI SSDT called W32pServiceTable from
 *         win32k-IST-JSON
 *     3.  Find VA of KeServiceDescriptorTableShadow-symbol
 *     4.  Retrieve DTB of an arbitrary interactive process by reading CR3
 *     5.  Use this DTB to resolve the pointer to the GUI SSDT
 *     6.  Find the address to trap by subtracting the RVA of W32pServiceTable
 *         from the VA of the GUI SSDT and then adding the function offset
 *
 * For a thorough description of the inner workings of the SSDT and
 * the W32pServiceTable (aka GUI SSDT), see ERNWs blogpost at
 * https://insinuator.net/2015/12/\
 * investigating-memory-analysis-tools-ssdt-hooking-via-pointer-replacement/
 */
static bool register_NtUserShowWindow_trap( drakvuf_t drakvuf, json_object* profile_json,
    const char* function_name, drakvuf_trap_t* trap,
    event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info))
{

    addr_t func_rva = 0;
    if (!json_get_symbol_rva(drakvuf, profile_json, function_name, &func_rva))
    {
        PRINT_DEBUG("[HIDSIM] [MONITOR] Failed to get RVA of win32k!%s\n",
            function_name);
        return false;
    }

    addr_t w32pst_rva = 0;
    if (!json_get_symbol_rva(drakvuf, profile_json, "W32pServiceTable", &w32pst_rva))
    {
        PRINT_DEBUG("[HIDSIM] [MONITOR] Failed to get RVA of win32k!W32pServiceTable\n");
        return false;
    }

    addr_t sdt_rva = 0;
    if (!drakvuf_get_kernel_symbol_rva(drakvuf, "KeServiceDescriptorTableShadow", &sdt_rva))
    {
        PRINT_DEBUG("[HIDSIM] [MONITOR] Failed to get RVA of nt!KeServiceDescriptorTableShadow\n");
        return false;
    }

    addr_t sdt_va = 0;
    if (!(sdt_va = drakvuf_exportksym_to_va(drakvuf, 4, nullptr, "ntoskrnl.exe", sdt_rva)))
    {
        PRINT_DEBUG("[HIDSIM] [Init] Failed to get VA of nt!KeServiceDescriptorTableShadow\n");
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
        PRINT_DEBUG("[HIDSIM] [MONITOR] Failed to find EPROCESS of \"y.exe\"\n");
        return false;
    }

    vmi_pid_t pid = 0;
    if (!drakvuf_get_process_pid(drakvuf, eprocess_base, &pid))
    {
        PRINT_DEBUG("[HIDSIM] [MONITOR] Failed to get PID of \"explorer.exe\"\n");
        return false;
    }

    addr_t ssdt_va = 0;
    {
        vmi_instance_t vmi = vmi_lock_guard(drakvuf);

        if (VMI_SUCCESS != vmi_pid_to_dtb(vmi, pid, &trap->breakpoint.dtb))
        {
            PRINT_DEBUG("[HIDSIM] [Init] Failed to get CR3 of \"explorer.exe\"\n");
            return false;
        }

        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .addr = ssdt_ptr_va,
            .dtb = trap->breakpoint.dtb
        );

        if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &ssdt_va))
        {
            PRINT_DEBUG("[HIDSIM] [MONITOR] Failed to read the address of SSDT "
                "(VA 0x%lx)\n", ssdt_ptr_va);
            return false;
        }
    }

    trap->name = function_name;
    trap->cb   = hook_cb;
    trap->breakpoint.addr = ssdt_va - w32pst_rva + func_rva;
    trap->ttl = drakvuf_get_limited_traps_ttl(drakvuf);

    if (!drakvuf_add_trap(drakvuf, trap))
    {
        PRINT_DEBUG("[HIDSIM] [MONITOR] Failed to trap VA 0x%lx\n", trap->breakpoint.addr);
        return false;
    }

    return true;
}

/*
 * Checks, if GUI reconstruction is supported for the system under
 * investigation
 */
bool check_platform_support(drakvuf_t drakvuf)
{
    win_build_info_t wbi;

    {
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

        if (VMI_FAILURE == vmi_get_windows_build_info(vmi, &wbi))
        {
            drakvuf_release_vmi(drakvuf);
            return false;
        }
    }

    if (wbi.version == VMI_OS_WINDOWS_7)
    {

        PRINT_DEBUG("[HIDSIM] GUI reconstruction supported"
            "on Windows 7\n");
        return true;
    }

    PRINT_DEBUG("[HIDSIM] GUI reconstruction is NOT supported "
        "on this guest system\n");

    return false;
}

/*
 * Initializes the offsets to the needed kernel-structures and sets up the trap,
 * so that the callback is triggered on NtUserShowWindow-calls
 */
int gui_init_reconstruction(drakvuf_t drakvuf, const char* win32k_path, bool is_x86)
{
    json_object* win32k_json = json_object_from_file(win32k_path);
    json_object* kernel_profile = NULL;

    if (!win32k_json)
    {
        PRINT_DEBUG("[HIDSIM] [MONITOR] Plugin failed to load JSON debug info for win32k.sys\n");
        return -1;
    }
    {
        /* Populates the kernel offsets */
        vmi_instance_t vmi = vmi_lock_guard(drakvuf);
        kernel_profile = vmi_get_kernel_json(vmi);

        if (VMI_FAILURE == initialize_offsets(vmi, kernel_profile, win32k_json, is_x86))
        {
            PRINT_DEBUG("[HIDSIM] [MONITOR] Failed to populate offsets for GUI reconstruction\n");
            json_object_put(win32k_json);
            return -1;
        }
    }

    /*
     * Registers trap for window creation
     *
     * General info on window creation
     * https://www.coresecurity.com/sites/default/files/private-files/\
     * publications/2016/05/2x1MicrosoftBug-Economou.pdf, page 11
     */
    bool success = register_NtUserShowWindow_trap(drakvuf, win32k_json, TRAP_FUNC,
            &gui_trap, on_draw);
    json_object_put(win32k_json);

    if (!success)
    {
        PRINT_DEBUG("[HIDSIM] [MONITOR] Failed to trap NtUserShowWindow\n");
        return -1;
    }

    PRINT_DEBUG("[HIDSIM] [MONITOR] Successfully initialized GUI reconstruction\n");

    return 0;
}

/*
 * Worker function to monitor and reconstruct the GUIs, when NtUserShowWindow-
 * calls have occured
 */
int gui_monitor(drakvuf_t drakvuf, volatile sig_atomic_t* coords,
    volatile sig_atomic_t* has_to_stop)
{
    PRINT_DEBUG("[HIDSIM] [MONITOR] Started GUI reconstruction thread\n");

    int res = -1;
    vmi_instance_t vmi;
    struct desktop d = {};
    {
        vmi = vmi_lock_guard(drakvuf);
        /*
         * The PID, provided by the desktop struct, is required for accessing the
         * desktop heap in user mode. Since explorer.exe, dwm.exe or other always
         * existing processes are used due to their low-order PIDs, those are fairly
         * stable, so it has not to be recreated in each iteration
         */
        if (VMI_FAILURE == find_first_active_desktop(vmi, &d))
        {
            return -1;
        }
    }
    *coords = 0;

    /* Keeps track of time to meet delays */
    struct timeval curr;
    struct timeval diff;
    long elapsed = 0;

    uint32_t x, y;

    struct wnd btn = {};

    while (!*has_to_stop)
    {
        if (!has_gui_update)
        {
            usleep(DELAY);
            continue;
        }

        /*
         * Checks how many usecs have been elapsed since the last
         * NtUserShowWindow-call.
         */
        gettimeofday(&curr, NULL);

        {
            std::lock_guard<std::mutex> guard(lock);
            timersub(&curr, &last, &diff);
        }


        elapsed = diff.tv_sec * 1000000 + diff.tv_usec;

        /*
         * Delays the reconstruction for DELAY usecs to wait
         * until all buttons and windows are drawn
         */
        if (elapsed >= DELAY)
        {
            PRINT_DEBUG("[HIDSIM] [MONITOR] Detected GUI update\n");
            {
                vmi = vmi_lock_guard(drakvuf);
                res = scan_for_clickable_button(vmi, &d, &btn);
            }
            has_gui_update = false;

            if (res >  0)
            {
                /* Sets coordinates to click next */
                x = btn.r.x0 + btn.r.w/2;
                y = btn.r.y0 + btn.r.h/2;
                *coords = x << 16 | y;

                PRINT_DEBUG("[HIDSIM] [MONITOR] Found \"%S\"-button to click at"
                    "(%d, %d)\n", btn.text, btn.r.x0, btn.r.y0);

            }
            /* Some error occured */
            else if (res < 0)
            {
                PRINT_DEBUG("[HIDSIM] [MONITOR] Error reconstructing GUI:"
                    "%d\n", res);
                break;
            }
        }
        else
        {
            usleep(DELAY - elapsed);
        }
    }

    /* Frees dynamically allocated members of stack-allocated structs */
    clear_wnd_container(&btn);
    clear_desktop_container(&d);

    return res;
}
