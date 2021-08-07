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

#include <stdio.h>
#include <inttypes.h>

#include "vmi_win_gui_offsets.h"

extern struct Offsets symbol_offsets;

/*
 * Checks, whether the _OBJECT_HEADER, which precedes every executive object,
 * is preceded by an optional header of type _OBJECT_HEADER_NAME_INFO.
 * If this is the case, the name of the executive object is read and returned.
 *
 */
char* retrieve_objhdr_name(vmi_instance_t vmi, addr_t addr)
{
    addr_t obj_hdr = 0;
    addr_t obj_hdr_nameinfo_addr= 0;
    uint8_t im = 0;
    char* name = NULL;
    unicode_string_t* us = NULL;
    unicode_string_t out = { .contents = NULL };

    /*
     * Retrieves the beginning of the _OBJECT_HEADER, to find it subtract the
     * offset to the body from current address. Since the current executive
     * object is _partly_ incorporated in the size of the _OBJECT_HEADER-struct
     *
     * See "The Art of Memory Forensics", p. 119 ff. for a description
     */
    obj_hdr = addr - symbol_offsets.objhdr_body_offset;
    obj_hdr_nameinfo_addr = obj_hdr;

    if (VMI_FAILURE == vmi_read_8_va(vmi, obj_hdr + symbol_offsets.objhdr_infomask_offset,
            0, &im))
    {
        fprintf(stderr, "Error reading InfoMask from _OBJECT_HEADER at: %" PRIx64
            "\n", obj_hdr);
        return NULL;
    }

    /*
     * Checks, if there comes an optional _OBJECT_HEADER_CREATOR_INFO after
     * _OBJECT_HEADER_NAME_INFO, which has to added to the offset to subtract
     * from the address signifying the start of the _OBJECT_HEADER
     */
    if (im & OBJ_HDR_INFOMASK_CREATOR_INFO)
        obj_hdr_nameinfo_addr -= symbol_offsets.objhdr_creator_info_length;

    /* Returns NULL immediately, if there is no _OBJECT_HEADER_NAME_INFO */
    if (!(im & OBJ_HDR_INFOMASK_NAME))
        return NULL;

    obj_hdr_nameinfo_addr -= symbol_offsets.objhdr_name_info_length;

    us = vmi_read_unicode_str_va(vmi, obj_hdr_nameinfo_addr +
            symbol_offsets.objhdr_name_info_name_offset, 0);

    if (us && VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8"))
    {
        name = strndup((char*) out.contents, out.length);
        free(out.contents);
    }

    if (us)
        vmi_free_unicode_str(us);

    return name;
}

/*
 * Reads a Windows wchar-string into a wchar_t*, since vmi_read_unicode_str_va
 * fails to parse _RTL_ATOM_ENTRY's name-string or _LARGE_UNICODE_STRINGs.
 * Expansion is performed since Windows' wchar is 2 bytes versus 4 bytes on
 * 64bit-Linux
 */
wchar_t* read_wchar_str_pid(vmi_instance_t vmi, addr_t start, size_t len, vmi_pid_t pid)
{
    wchar_t* s = (wchar_t*) calloc(len, sizeof(wchar_t));
    if (!s)
    {
        printf("[HIDSIM][MONITOR] Memory allocation for wchar-string failed\n");
        return NULL;
    }

    for (size_t i = 0; i < len; i++)
    {
        uint16_t c = 0;
        if (VMI_FAILURE == vmi_read_16_va(vmi, start + i * 2, pid, &c))
        {
            free(s);
            return NULL;
        }

        s[i] = (wchar_t)c;

        if (s[i] == L'\0')
            break;
    }
    return s;
}

wchar_t* read_wchar_str(vmi_instance_t vmi, addr_t start, size_t len)
{
    return read_wchar_str_pid(vmi, start, len, 0);
}
