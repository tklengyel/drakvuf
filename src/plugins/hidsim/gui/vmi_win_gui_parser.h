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

#ifndef VMI_WIN_GUI_PARSER_H
#define VMI_WIN_GUI_PARSER_H

/* Datastructures */
#include <glib.h>

#include <libvmi/libvmi.h>

/* Flags indicating window style */
#define WS_MINIMIZE 0x20000000
#define WS_VISIBLE 0x10000000
#define WS_DISABLED 0x08000000

/* Window extended style (exstyle) */
#define WS_EX_DLGMODALFRAME 0x00000001
#define WS_EX_NOPARENTNOTIFY 0x00000004
#define WS_EX_TOPMOST 0x00000008
#define WS_EX_ACCEPTFILES 0x00000010
#define WS_EX_TRANSPARENT 0x00000020

/* Factor of desktop - button, used for simple filtering */
#define BTN_RATIO 4

/* Holds struct-offsets, needed to access relevant fields */
extern struct Offsets symbol_offsets;

/*
 * The following structs encapsulate only the information needed for the purpose
 * of reconstructing the GUI to a level, where dialogs could be identified for
 * clicking
 */
struct winsta
{
    addr_t addr;
    /*
     * For each GUI thread, win32k maps, the associated desktop heap into
     * usermode http://mista.nu/research/mandt-win32k-slides.pdf
     *
     * Therefore do it like volatility: Find a process with matching sessionID
     * and take its VA as _MM_SESSION_SPACE for the WinSta
     * https://github.com/volatilityfoundation/volatility/blob/\
     * a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/\
     * gui/sessions.py#L49
     *
     * To accomplish this, it's the most easy way to use vmi_read_xx_va
     */
    vmi_pid_t providing_pid;
    uint32_t session_id;
    addr_t atom_table;
    bool is_interactive;
    size_t len_desktops;
    addr_t* desktops;
    char* name;
};

/* Just the minimal information needed to retrieve windows */
struct desktop
{
    addr_t addr;
    vmi_pid_t providing_pid;
    char* name;
#ifndef DISABLE_ATOMS
    GHashTable* atom_table;
#endif
};

struct rect
{
    int32_t x0;
    int32_t x1;
    int32_t y0;
    int32_t y1;

    /* For convenience */
    uint32_t w;
    uint32_t h;
};

struct wnd
{
    addr_t spwnd_addr;
    uint32_t style;
    uint32_t exstyle;
    int level;
    uint16_t atom;
    struct rect r;
    struct rect rclient;
    wchar_t* text;
};

void clear_wnd_container(struct wnd* w);
void free_wnd_container(struct wnd* w);
void clear_winsta_container(struct winsta** w);
void free_winsta_container(struct winsta* w);
void clear_desktop_container(struct desktop* d);

/*
 * Reads relevant data from tagWINDOWSTATION-structs and the children of
 * type tagDESKTOP
 */
status_t populate_winsta(vmi_instance_t vmi, struct winsta* winsta, addr_t addr,
    vmi_pid_t providing_pid);

/* Iterates over process list an retrieves all tagWINDOWSTATION-structs */
status_t retrieve_winstas_from_procs(vmi_instance_t vmi, GArray** resulting_winstas);

status_t find_first_active_desktop(vmi_instance_t vmi, struct desktop* d);

int scan_for_clickable_button(vmi_instance_t vmi, struct desktop* d,
    struct wnd* btn);

#endif // VMI_WIN_GUI_PARSER_H
