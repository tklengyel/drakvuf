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

#include "plugins/plugins.h"
#include "plugins/output_format.h"

#include "linkmon.h"
#include "private.h"

using namespace linkmon_ns;

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

event_response_t linkmon::setinformation_cb(drakvuf_t,
    drakvuf_trap_info_t* info)
{
    uint32_t file_information_class = drakvuf_get_function_argument(drakvuf, info, 5);

    if (file_information_class != FileLinkInformation)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t target_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t file_information = drakvuf_get_function_argument(drakvuf, info, 3);

    char* target_file_name = drakvuf_get_filename_from_handle(drakvuf, info, target_handle);
    if (!target_file_name)
    {
        PRINT_DEBUG("[LINKMON] Failed to read Target FileName\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    std::string target_file_name_str {target_file_name};
    g_free(target_file_name);

    vmi_lock_guard vmi(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = file_information + this->offsets[FILE_LINK_INFORMATION_ROOTDIRECTORY],
    );

    addr_t root_dir_handle = 0;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &root_dir_handle))
    {
        PRINT_DEBUG("[LINKMON] Failed to read RootDirectory\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    uint32_t file_name_length = 0;
    ctx.addr = file_information + this->offsets[FILE_LINK_INFORMATION_FILENAMELENGTH];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &file_name_length))
    {
        PRINT_DEBUG("[LINKMON] Failed to read FileNameLength\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    ctx.addr = file_information + this->offsets[FILE_LINK_INFORMATION_FILENAME];
    unicode_string_t* file_name = NULL;
    file_name = drakvuf_read_wchar_array(drakvuf, &ctx, file_name_length/2);
    if (!file_name)
    {
        PRINT_DEBUG("[LINKMON] Failed to read FileName\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    char* file_name_full = NULL;
    if (root_dir_handle)
    {
        char* file_root = drakvuf_get_filename_from_handle(drakvuf, info, root_dir_handle);
        file_name_full = g_strdup_printf("%s\\%s", file_root ?: "", file_name->contents);
        g_free(file_root);
    }
    else if (is_absolute_path(reinterpret_cast<char*>(file_name->contents)))
    {
        file_name_full = g_strdup(reinterpret_cast<char*>(file_name->contents));
    }
    else
    {
        char* file_root_p = get_parent_folder(target_file_name_str.c_str());
        file_name_full = g_strdup_printf("%s\\%s", file_root_p ?: "", file_name->contents);
        g_free(file_root_p);
    }
    vmi_free_unicode_str(file_name);

    fmt::print(this->m_output_format, "linkmon", drakvuf, info,
        keyval("FileName", fmt::Qstr(file_name_full)),
        keyval("LinkType", fmt::Qstr("hardlink")),
        keyval("LinkTarget", fmt::Qstr(target_file_name_str)));

    g_free(file_name_full);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linkmon::print_junction(drakvuf_t,
    drakvuf_trap_info_t* info,
    addr_t input_buffer)
{
    addr_t file_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    char* file_name = drakvuf_get_filename_from_handle(drakvuf, info, file_handle);
    if (!file_name)
    {
        PRINT_DEBUG("[LINKMON] Failed to read FileName\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    std::string file_name_str {file_name};
    g_free(file_name);

    addr_t struct_offset = input_buffer + this->offsets[REPARSE_DATA_BUFFER_MOUNTPOINTREPARSEBUFFER];
    vmi_lock_guard vmi(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = struct_offset + this->offsets[REPARSE_DATA_BUFFER_SUBSTITUTENAMEOFFSET]
    );

    uint16_t substitute_name_offset = 0;
    if (VMI_FAILURE == vmi_read_16(vmi, &ctx, &substitute_name_offset))
    {
        PRINT_DEBUG("[LINKMON] Failed to read SubstituteNameOffset\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    uint16_t substitute_name_length = 0;
    ctx.addr = struct_offset + this->offsets[REPARSE_DATA_BUFFER_SUBSTITUTENAMELENGTH];
    if (VMI_FAILURE == vmi_read_16(vmi, &ctx, &substitute_name_length))
    {
        PRINT_DEBUG("[LINKMON] Failed to read SubstituteNameLength\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    unicode_string_t* substitute_name = NULL;
    ctx.addr = struct_offset + this->offsets[REPARSE_DATA_BUFFER_PATHBUFFER] + substitute_name_offset;
    substitute_name = drakvuf_read_wchar_array(drakvuf, &ctx, substitute_name_length/2);
    if (!substitute_name)
    {
        PRINT_DEBUG("[LINKMON] Failed to read SubstituteName\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    std::string target_file_name_str {(char*)substitute_name->contents};
    vmi_free_unicode_str(substitute_name);

    fmt::print(this->m_output_format, "linkmon", drakvuf, info,
        keyval("FileName", fmt::Qstr(file_name_str)),
        keyval("LinkType", fmt::Qstr("junction")),
        keyval("LinkTarget", fmt::Qstr(target_file_name_str)));

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linkmon::print_symlink(drakvuf_t,
    drakvuf_trap_info_t* info,
    addr_t input_buffer)
{
    addr_t file_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    char* file_name = drakvuf_get_filename_from_handle(drakvuf, info, file_handle);
    if (!file_name)
    {
        PRINT_DEBUG("[LINKMON] Failed to read FileName\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    std::string file_name_str {file_name};
    g_free(file_name);

    addr_t struct_offset = input_buffer + this->offsets[REPARSE_DATA_BUFFER_SYMBOLICLINKREPARSEBUFFER];
    vmi_lock_guard vmi(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = struct_offset + this->offsets[REPARSE_DATA_BUFFER_SUBSTITUTENAMEOFFSET_SYMLINK]
    );

    uint16_t substitute_name_offset = 0;
    if (VMI_FAILURE == vmi_read_16(vmi, &ctx, &substitute_name_offset))
    {
        PRINT_DEBUG("[LINKMON] Failed to read SubstituteNameOffset\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    uint16_t substitute_name_length = 0;
    ctx.addr = struct_offset + this->offsets[REPARSE_DATA_BUFFER_SUBSTITUTENAMELENGTH_SYMLINK];
    if (VMI_FAILURE == vmi_read_16(vmi, &ctx, &substitute_name_length))
    {
        PRINT_DEBUG("[LINKMON] Failed to read SubstituteNameLength\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    uint32_t flags = 0;
    ctx.addr = struct_offset + this->offsets[REPARSE_DATA_BUFFER_FLAGS_SYMLINK];
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &flags))
    {
        PRINT_DEBUG("[LINKMON] Failed to read Flags\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    unicode_string_t* substitute_name = NULL;
    ctx.addr = struct_offset + this->offsets[REPARSE_DATA_BUFFER_PATHBUFFER_SYMLINK] + substitute_name_offset;
    substitute_name = drakvuf_read_wchar_array(drakvuf, &ctx, substitute_name_length/2);
    if (!substitute_name)
    {
        PRINT_DEBUG("[LINKMON] Failed to read SubstituteName\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    std::string target_file_name_str {(char*)substitute_name->contents};
    vmi_free_unicode_str(substitute_name);

    fmt::print(this->m_output_format, "linkmon", drakvuf, info,
        keyval("FileName", fmt::Qstr(file_name_str)),
        keyval("LinkType", fmt::Qstr("symlink")),
        keyval("Flags", fmt::Xval(flags)),
        keyval("LinkTarget", fmt::Qstr(target_file_name_str)));

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t linkmon::ntfscontrolfile_cb(drakvuf_t,
    drakvuf_trap_info_t* info)
{
    uint32_t fs_control_code = drakvuf_get_function_argument(drakvuf, info, 6);
    if (fs_control_code != FSCTL_SET_REPARSE_POINT)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t input_buffer = drakvuf_get_function_argument(drakvuf, info, 7);
    vmi_lock_guard vmi(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = input_buffer + this->offsets[REPARSE_DATA_BUFFER_REPARSETAG]
    );

    uint32_t reparse_tag = 0;
    if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &reparse_tag))
    {
        PRINT_DEBUG("[LINKMON] Failed to read ReparseTag\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    switch (reparse_tag)
    {
        case IO_REPARSE_TAG_SYMLINK:
            print_symlink(drakvuf, info, input_buffer);
            break;
        case IO_REPARSE_TAG_MOUNT_POINT:
            print_junction(drakvuf, info, input_buffer);
            break;
        default:
            PRINT_DEBUG("[LINKMON] Unsupported ReparseTag\n");
            break;
    }

    return VMI_EVENT_RESPONSE_NONE;
}

linkmon::linkmon(drakvuf_t drakvuf,
    const linkmon_config* c,
    output_format_t output)
    : pluginex(drakvuf, output)
{
    if (!c->ole32_profile)
    {
        PRINT_DEBUG("[LINKMON] plugin requires the JSON debug info for \"ole32.dll\"!\n");
        return;
    }

    json_object* ole32_profile_json = json_object_from_file(c->ole32_profile);
    if (!json_get_struct_members_array_rva(drakvuf, ole32_profile_json,
            offset_names_1, this->offsets.size(), this->offsets.data()))
    {
        PRINT_DEBUG("[LINKMON] Second attempt to get offsets\n");
        if (!json_get_struct_members_array_rva(drakvuf, ole32_profile_json,
                offset_names_2, this->offsets.size(), this->offsets.data()))
            throw -1;
    }

    this->ntfscontrolfile_hook = createSyscallHook("NtFsControlFile",
            &linkmon::ntfscontrolfile_cb);
    this->setinformation_hook = createSyscallHook("NtSetInformationFile",
            &linkmon::setinformation_cb);
}
