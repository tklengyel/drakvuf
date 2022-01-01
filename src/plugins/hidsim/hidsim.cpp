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
 * This file was created by Jan Gruber.                                    *
 * It is distributed as part of DRAKVUF under the same license             *
 ***************************************************************************/

#include <libdrakvuf/libdrakvuf.h>  /* eprint_current_time */
#include "../private.h"             /* PRINT_DEBUG */
#include "hid_injection.h"          /* hid_inject */
#include "gui_monitor.h"            /* gui_reconstruct */

#include "hidsim.h"

/*
 * Checks, if GUI reconstruction is supported on the system under
 * investigation
 */
bool hidsim::check_platform_support(drakvuf_t drakvuf)
{
    win_build_info_t bi;
    {
        vmi_lock_guard vmi(drakvuf);
        if (!vmi_get_windows_build_info(vmi.vmi, &bi))
            return false;
    }

    if (bi.version == VMI_OS_WINDOWS_7)
    {
        PRINT_DEBUG("[HIDSIM] GUI reconstruction supported"
            "on Windows 7\n");
        return true;
    }

    PRINT_DEBUG("[HIDSIM] GUI reconstruction is NOT supported "
        "on this guest system\n");
    return false;
}

bool hidsim::prepare_gui_reconstruction(drakvuf_t drakvuf, const char* win32k_profile)
{
    if (!win32k_profile)
    {
        PRINT_DEBUG("[HIDSIM] No win32k-profile provided. Unable to monitor the GUI\n");
        return false;
    }

    this->win32k_json_path = win32k_profile;

    this->is_gui_support = this->check_platform_support(drakvuf);

    page_mode_t pm = drakvuf_get_page_mode(drakvuf);
    bool is_x86 = pm == VMI_PM_PAE;

    if (this->is_gui_support)
    {
        /* Initializes reconstruction  */
        return gui_init_reconstruction(drakvuf, this->win32k_json_path.c_str(),
                is_x86) == 0;
    }
    return false;
}

/* Infers socket path from drakvuf's actual domID */
std::string construct_sock_path(drakvuf_t drakvuf)
{
    /* Retrieves domid as string */
    std::string sock_path(SOCK_STUB);
    sock_path.append(std::to_string(drakvuf_get_dom_id(drakvuf)));
    return sock_path;
}

hidsim::hidsim(drakvuf_t drakvuf, const hidsim_config* config) :
    has_to_stop{false}, coords{0}
{
    /* Constructs path to Unix domain socket of Xen guest under investigation */
    this->sock_path = construct_sock_path(drakvuf);
    PRINT_DEBUG("[HIDSIM] Using Unix domain socket: %s\n", this->sock_path.c_str());

    if (config->template_fp)
    {
        this->template_path = config->template_fp;
        PRINT_DEBUG("[HIDSIM] Using template file: %s\n",
            this->template_path.c_str());
    }

    this->is_rand_clicks = config->is_rand_clicks;

    /* Prepares monitoring, if requested */
    if (config->is_monitor)
    {
        PRINT_DEBUG("[HIDSIM] GUI monitoring requested\n");
        this->is_monitor = prepare_gui_reconstruction(drakvuf, config->win32k_profile);

    }
    else
        this->is_monitor = false;

    /* Starts injection thread */
    this->thread_inject = std::thread(hid_inject, sock_path.c_str(),
            template_path.c_str(), is_rand_clicks, &coords, &has_to_stop);

    /* GUI Reconstruction thread */
    if (this->is_monitor && this->is_gui_support)
        this->thread_reconstruct = std::thread(gui_monitor, drakvuf, &coords,
                &has_to_stop);

    PRINT_DEBUG("[HIDSIM] HID injection started\n");
}

hidsim::~hidsim()
{
    this->stop();
};

bool hidsim::stop_impl()
{
    PRINT_DEBUG("[HIDSIM] Stopping HID injection\n");

    if (!is_stopping())
    {
        this->has_to_stop = true;

        if (this->thread_inject.joinable())
            this->thread_inject.join();

        if (this->is_monitor && this->thread_reconstruct.joinable())
            this->thread_reconstruct.join();
    }
    PRINT_DEBUG("[HIDSIM] Successfully joined thread \n");

    return true;
}
