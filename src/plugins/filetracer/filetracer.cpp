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
#include <assert.h>

#include <libvmi/libvmi.h>
#include "plugins/plugins.h"
#include "private.h"
#include "filetracer.h"

static unicode_string_t* read_wchar_array(vmi_instance_t vmi, const access_context_t* ctx, size_t length)
{
    unicode_string_t* us = (unicode_string_t*)g_malloc0(sizeof(unicode_string_t));
    if ( !us )
        return NULL;

    us->length = length * 2;
    us->contents = (uint8_t*)g_malloc0(sizeof(uint8_t) * (length * 2 + 2));

    if ( !us->contents )
    {
        vmi_free_unicode_str(us);
        return NULL;
    }

    if ( VMI_FAILURE == vmi_read(vmi, ctx, us->length, us->contents, NULL) )
    {
        vmi_free_unicode_str(us);
        return NULL;
    }

    // end with NUL symbol
    us->contents[us->length] = 0;
    us->contents[us->length + 1] = 0;
    us->encoding = "UTF-16";

    unicode_string_t* out = (unicode_string_t*)g_malloc0(sizeof(unicode_string_t));

    if ( !out )
    {
        vmi_free_unicode_str(us);
        return NULL;
    }

    status_t rc = vmi_convert_str_encoding(us, out, "UTF-8");
    vmi_free_unicode_str(us);

    if (VMI_SUCCESS != rc)
    {
        g_free(out);
        return NULL;
    }

    return out;
}

static unicode_string_t* get_filename_from_handle(
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    addr_t handle)
{
    filetracer* f = (filetracer*)info->trap->data;
    addr_t process=drakvuf_get_current_process(drakvuf, info->vcpu);

    if (!process)
        return NULL;

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, process, handle);
    if ( !obj )
        return NULL;

    return drakvuf_read_unicode(drakvuf, info, obj + f->object_header_body + f->file_object_filename);
}

static void safe_free_unicode_str(unicode_string_t* us)
{
    if (us) vmi_free_unicode_str(us);
}

static event_response_t objattr_read(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t attr)
{
    if ( !attr )
        return 0;

    const char* syscall_name = info->trap->name;
    filetracer* f = (filetracer*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    addr_t file_root_handle = 0;
    ctx.addr = attr + f->objattr_root;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &file_root_handle) )
    {
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    unicode_string_t* file_root_us = get_filename_from_handle(drakvuf, info, file_root_handle);

    ctx.addr = attr + f->objattr_name;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ctx.addr) )
    {
        safe_free_unicode_str(file_root_us);
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    unicode_string_t* file_name_us = drakvuf_read_unicode(drakvuf, info, ctx.addr);
    if ( !file_name_us )
    {
        safe_free_unicode_str(file_root_us);
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    const char* file_root = file_root_us ? (const char*)file_root_us->contents : "";
    const char* file_name = file_name_us ? (const char*)file_name_us->contents : "";
    const char* file_sep = file_root_us ? "\\" : "";

    switch (f->format)
    {
        case OUTPUT_CSV:
            printf("filetracer,%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%s%s%s\n",
                   info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, syscall_name, file_root, file_sep, file_name);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[FILETRACER] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " %s,%s%s%s\n",
                   info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, syscall_name, file_root, file_sep, file_name);
            break;
    }

    safe_free_unicode_str(file_name_us);
    safe_free_unicode_str(file_root_us);
    drakvuf_release_vmi(drakvuf);
    return 0;
}

static bool is_absolute_path(char const* file_name)
{
    // TODO: need more strong way determing that the @file_name is absolute path.
    return file_name && file_name[0] == '\\';
}

static char* get_parent_folder(char const* file_name)
{
    // TODO: need more strong way getting parent folder for @file_name.
    if (file_name)
    {
        char* end = g_strrstr(file_name, "\\");
        if (end && end != file_name)
            return g_strndup(file_name, end - file_name);
    }
    return g_strdup("\\");
}


static void print_rename_file_info(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t src_file_handle, addr_t fileinfo)
{
    filetracer* f = (filetracer*)info->trap->data;
    const char* syscall_name = info->trap->name;
    const char* operation_name = "FileRenameInformation";

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    addr_t dst_file_root_handle = 0;
    ctx.addr = fileinfo + f->newfile_root_offset;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &dst_file_root_handle) )
        return;

    uint32_t dst_file_name_length = 0;
    ctx.addr = fileinfo + f->newfile_name_length_offset;
    if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &dst_file_name_length) )
        return;

    ctx.addr = fileinfo + f->newfile_name_offset;
    unicode_string_t* dst_file_name_us = read_wchar_array(vmi, &ctx, dst_file_name_length);
    if ( !dst_file_name_us )
        return;

    unicode_string_t* src_file_us = get_filename_from_handle(drakvuf, info, src_file_handle);
    if ( !src_file_us )
    {
        vmi_free_unicode_str(dst_file_name_us);
        return;
    }

    char* dst_file_p = NULL;
    if (dst_file_root_handle)
    {
        unicode_string_t* dst_file_root_us = get_filename_from_handle(drakvuf, info, dst_file_root_handle);
        dst_file_p = g_strdup_printf("%s\\%s", dst_file_root_us->contents, dst_file_name_us->contents);
        vmi_free_unicode_str(dst_file_root_us);
    }
    else if (is_absolute_path(reinterpret_cast<char*>(dst_file_name_us->contents)))
    {
        dst_file_p = g_strdup(reinterpret_cast<char*>(dst_file_name_us->contents));
    }
    else
    {
        char* dst_file_root_p = get_parent_folder(reinterpret_cast<char*>(src_file_us->contents));
        dst_file_p = g_strdup_printf("%s\\%s", dst_file_root_p, dst_file_name_us->contents);
        g_free(dst_file_root_p);
    }
    vmi_free_unicode_str(dst_file_name_us);

    switch (f->format)
    {
        case OUTPUT_CSV:
            printf("filetracer,%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%s,%s,%s\n",
                   info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid,
                   syscall_name, operation_name, src_file_us->contents, dst_file_p);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[FILETRACER] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " %s,%s,%s,%s\n",
                   info->vcpu, info->regs->cr3, info->proc_data.name, USERIDSTR(drakvuf), info->proc_data.userid,
                   syscall_name, operation_name, src_file_us->contents, dst_file_p);
            break;
    }

    g_free(dst_file_p);
    vmi_free_unicode_str(src_file_us);
}

static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    filetracer* f = (filetracer*)info->trap->data;
    addr_t attr = 0;

    if ( f->pm == VMI_PM_IA32E )
        attr = info->regs->r8;
    else
    {
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        vmi_read_32_va(vmi, info->regs->rsp + sizeof(uint32_t)*3, 0, (uint32_t*)&attr);
        drakvuf_release_vmi(drakvuf);
    }

    objattr_read(drakvuf, info, attr);

    return 0;
}

static event_response_t cb2(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    filetracer* f = (filetracer*)info->trap->data;
    addr_t attr = 0;

    if ( f->pm == VMI_PM_IA32E )
        attr = info->regs->rcx;
    else
    {
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        vmi_read_32_va(vmi, info->regs->rsp + sizeof(uint32_t), 0, (uint32_t*)&attr);
        drakvuf_release_vmi(drakvuf);
    }

    objattr_read(drakvuf, info, attr);

    return 0;
}

#define FILE_RENAME_INFORMATION 10

static event_response_t setinformation_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    filetracer* f = (filetracer*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    uint32_t fileinfoclass = 0;
    reg_t handle = 0, fileinfo = 0;

    if (f->pm == VMI_PM_IA32E)
    {
        handle = info->regs->rcx;
        fileinfo = info->regs->r8;

        ctx.addr = info->regs->rsp + 5 * sizeof(addr_t); // addr of fileinfoclass
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &fileinfoclass) )
            goto done;
    }
    else
    {
        ctx.addr = info->regs->rsp + sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &handle) )
            goto done;
        ctx.addr += 2 * sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &fileinfo) )
            goto done;
        ctx.addr += 2 * sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &fileinfoclass) )
            goto done;
    }

    if (fileinfoclass == FILE_RENAME_INFORMATION)
    {
        print_rename_file_info(vmi, drakvuf, info, handle, fileinfo);
    }

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

/* ----------------------------------------------------- */

static void register_trap( drakvuf_t drakvuf, const char* rekall_profile, const char* syscall_name,
                           drakvuf_trap_t* trap,
                           event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !drakvuf_get_function_rva( rekall_profile, syscall_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = syscall_name;
    trap->cb   = hook_cb;

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}

filetracer::filetracer(drakvuf_t drakvuf, const void* config, output_format_t output)
{
    const char* rekall_profile = (const char*)config;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->pm = vmi_get_page_mode(vmi, 0);
    int addr_size = vmi_get_address_width(vmi); // 4 or 8 (bytes)
    drakvuf_release_vmi(drakvuf);
    this->format = output;

    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_OBJECT_ATTRIBUTES", "ObjectName", &this->objattr_name) )
        throw -1;
    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_OBJECT_ATTRIBUTES", "RootDirectory", &this->objattr_root) )
        throw -1;
//    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_FILE_RENAME_INFORMATION", "RootDirectory", &this->newfile_root_offset ) )
//        throw -1;
    this->newfile_root_offset = addr_size;
//    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_FILE_RENAME_INFORMATION", "FileName", &this->newfile_name_offset ) )
//        throw -1;
    this->newfile_name_offset = addr_size * 2 + 4;
//    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_FILE_RENAME_INFORMATION", "FileNameLength", &this->newfile_name_length_offset ) )
//        throw -1;
    this->newfile_name_length_offset = addr_size * 2;

    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_OBJECT_HEADER", "Body", &this->object_header_body) )
        throw -1;
    if ( !drakvuf_get_struct_member_rva(rekall_profile, "_FILE_OBJECT", "FileName", &this->file_object_filename) )
        throw -1;

    assert(sizeof(trap)/sizeof(trap[0]) > 9);
    register_trap(drakvuf, rekall_profile, "NtCreateFile",          &trap[0], cb);
    register_trap(drakvuf, rekall_profile, "ZwCreateFile",          &trap[1], cb);
    register_trap(drakvuf, rekall_profile, "NtOpenFile",            &trap[2], cb);
    register_trap(drakvuf, rekall_profile, "ZwOpenFile",            &trap[3], cb);
    register_trap(drakvuf, rekall_profile, "NtOpenDirectoryObject", &trap[4], cb);
    register_trap(drakvuf, rekall_profile, "ZwOpenDirectoryObject", &trap[5], cb);
    register_trap(drakvuf, rekall_profile, "NtQueryAttributesFile", &trap[6], cb2);
    register_trap(drakvuf, rekall_profile, "ZwQueryAttributesFile", &trap[7], cb2);
    register_trap(drakvuf, rekall_profile, "NtSetInformationFile",  &trap[8], setinformation_cb);
    register_trap(drakvuf, rekall_profile, "ZwSetInformationFile",  &trap[9], setinformation_cb);
}

filetracer::~filetracer()
{
}
