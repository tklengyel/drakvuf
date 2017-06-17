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
#include "plugins/plugins.h"
#include "private.h"
#include "filetracer.h"

/*static event_response_t file_name_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    struct file_watch *watch = (struct file_watch*)info->trap->data;
    filetracer *f = watch->f;

    if (info->trap_pa == watch->file_name_buffer)
    {
        addr_t file_name = 0;
        uint16_t length = 0;
        vmi_read_addr_pa(vmi, watch->file_name_buffer, &file_name);
        vmi_read_16_pa(vmi, watch->file_name_length, &length);

        //printf("File name @ 0x%lx. Length: %u\n", file_name, length);

        if (file_name && length > 0 && length < VMI_PS_4KB) {
            unicode_string_t str = { .contents = NULL };
            str.length = length;
            str.encoding = "UTF-16";
            str.contents = (unsigned char *)g_malloc0(length);
            vmi_read_va(vmi, file_name, 0, str.contents, length);
            unicode_string_t str2 = { .contents = NULL };
            status_t rc = vmi_convert_str_encoding(&str, &str2, "UTF-8");

            if (VMI_SUCCESS == rc) {

                switch(f->format) {
                case OUTPUT_CSV:
                    printf("filetracer,%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64",%s\n",
                           info->vcpu, info->regs->cr3, info->procname, info->userid, str2.contents);
                    break;
                default:
                case OUTPUT_DEFAULT:
                    printf("[FILETRACER] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s:%" PRIi64 " %s\n",
                           info->vcpu, info->regs->cr3, info->procname,
                           USERIDSTR(drakvuf), info->userid, str2.contents);
                    break;
                };

                g_free(str2.contents);
            }

            free(str.contents);
            //printf("Requesting to free writetrap @ %p\n", info->trap);
            info->trap->data=f;
            drakvuf_remove_trap(drakvuf, info->trap, free_writetrap);
        }
    }

    drakvuf_release_vmi(drakvuf);
    return 0;
}*/

static event_response_t objattr_read(drakvuf_t drakvuf, drakvuf_trap_info_t *info, addr_t attr)
{
    filetracer *f = (filetracer*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    addr_t name = 0;

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    if ( !attr ) {
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    ctx.addr = attr + f->objattr_name;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &name) )
        printf("Nothing at 0x%lx\n", ctx.addr);

    uint16_t length = 0;

    ctx.addr = name;
    status_t rc = vmi_read_16(vmi, &ctx, &length);

    if ( VMI_FAILURE == rc || length > VMI_PS_4KB ) {
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    unicode_string_t str, str2 = { .contents = NULL };
    str.contents = (unsigned char*)g_malloc0(length + 2);
    str.length = length;
    str.encoding = "UTF-16";

    ctx.addr = name + f->unicode_buf;
    rc = vmi_read_addr(vmi, &ctx, &ctx.addr);
    if ( VMI_FAILURE == rc ) {
        g_free(str.contents);
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    if ( length != vmi_read(vmi, &ctx, str.contents, length) ) {
        g_free(str.contents);
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    rc = vmi_convert_str_encoding(&str, &str2, "UTF-8");
    g_free(str.contents);

    if (VMI_SUCCESS == rc) {
        switch(f->format) {
        case OUTPUT_CSV:
            printf("filetracer,%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64",%s\n",
                    info->vcpu, info->regs->cr3, info->procname, info->userid, str2.contents);
            break;
        default:
        case OUTPUT_DEFAULT:
            printf("[FILETRACER] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s:%" PRIi64 " %s\n",
                    info->vcpu, info->regs->cr3, info->procname,
                    USERIDSTR(drakvuf), info->userid, str2.contents);
            break;
        };

        g_free(str2.contents);
    }

    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    filetracer *f = (filetracer*)info->trap->data;
    addr_t attr = 0;

    if ( f->pm == VMI_PM_IA32E )
        attr = info->regs->r8;
    else {
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        vmi_read_32_va(vmi, info->regs->rsp + sizeof(uint32_t)*3, 0, (uint32_t*)&attr);
        drakvuf_release_vmi(drakvuf);
    }

    objattr_read(drakvuf, info, attr);

    return 0;
}

static event_response_t cb2(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    filetracer *f = (filetracer*)info->trap->data;
    addr_t attr = 0;

    if ( f->pm == VMI_PM_IA32E )
        attr = info->regs->rcx;
    else {
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        vmi_read_32_va(vmi, info->regs->rsp + sizeof(uint32_t), 0, (uint32_t*)&attr);
        drakvuf_release_vmi(drakvuf);
    }

    objattr_read(drakvuf, info, attr);

    return 0;
}

/* ----------------------------------------------------- */

filetracer::filetracer(drakvuf_t drakvuf, const void* config, output_format_t output) {
    const char *rekall_profile = (const char *)config;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->pm = vmi_get_page_mode(vmi, 0);
    drakvuf_release_vmi(drakvuf);
    this->format = output;

    unsigned long i;
    for (i=0; i < 6; i++)
        this->trap[i].cb = cb;
    for (i=6; i < 8; i++)
        this->trap[i].cb = cb2;

    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_OBJECT_ATTRIBUTES", "ObjectName", &this->objattr_name) )
        throw -1;
    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_UNICODE_STRING", "Buffer", &this->unicode_buf) )
        throw -1;
    if ( !drakvuf_get_function_rva(rekall_profile, "NtCreateFile", &this->trap[0].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(rekall_profile, "ZwCreateFile", &this->trap[1].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(rekall_profile, "NtOpenFile", &this->trap[2].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(rekall_profile, "ZwOpenFile", &this->trap[3].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(rekall_profile, "NtOpenDirectoryObject", &this->trap[4].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(rekall_profile, "ZwOpenDirectoryObject", &this->trap[5].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(rekall_profile, "NtQueryAttributesFile", &this->trap[6].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(rekall_profile, "ZwQueryAttributesFile", &this->trap[7].breakpoint.rva) )
        throw -1;

    for (i=0; i < sizeof(this->trap)/sizeof(drakvuf_trap_t); i++)
        if ( !drakvuf_add_trap(drakvuf, &this->trap[i]) )
            throw -1;
}

filetracer::~filetracer() {
}
