/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
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

#include "plugins/output_format.h"

#include "private.h"
#include "win.h"
#include "win_acl.h"

using namespace filetracer_ns;

extern const flags_str_t generic_ar;

static uint64_t windows_tick_to_unix(long long windowsTicks)
{
    uint64_t windows_tick = 10000000UL;
    uint64_t sec_to_unix_epoch = 11644473600UL;

    return (uint64_t)(windowsTicks / windows_tick - sec_to_unix_epoch);
}

static auto build_security_descriptor(const win_objattrs_t& attrs)
{
    std::vector<flagsval> security_descriptor;
    if (!attrs.security_flags.empty())
        security_descriptor.emplace_back("Control", attrs.security_flags);
    if (!attrs.owner.empty())
        security_descriptor.emplace_back("Owner", attrs.owner);
    if (!attrs.group.empty())
        security_descriptor.emplace_back("Group", attrs.group);
    if (!attrs.sacl.empty())
        security_descriptor.emplace_back("Sacl", attrs.sacl);
    if (!attrs.dacl.empty())
        security_descriptor.emplace_back("Dacl", attrs.dacl);
    return security_descriptor;
}

void win_filetracer::print_file_obj_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const win_objattrs_t& attrs)
{
    auto security_descriptor = build_security_descriptor(attrs);
    fmt::print(this->m_output_format, "filetracer", drakvuf, info,
        keyval("FileName", fmt::Estr(attrs.file_path)),
        flagsval("ObjectAttributes", attrs.obj_attrs),
        keyval("SecurityDescriptor", security_descriptor)
    );
}

void win_filetracer::print_create_file_obj_info(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    uint32_t handle,
    uint32_t io_information,
    const win_objattrs_t& attrs,
    win_data* params,
    uint64_t status)
{
    auto file_attrs = parse_flags(params->file_attrs, file_flags_and_attrs, this->m_output_format);
    auto share_access = parse_flags(params->share_access, share_mode, this->m_output_format);
    auto create_disposition = parse_flags(params->create_disposition, disposition, this->m_output_format);
    auto create_opts = parse_flags(params->create_opts, create_options, this->m_output_format);
    auto desired_access = params->create_opts & FILE_DIRECTORY_FILE
        ? parse_flags(params->desired_access, directory_ar, this->m_output_format)
        : parse_flags(params->desired_access, file_ar, this->m_output_format);
    auto security_descriptor = build_security_descriptor(attrs);
    std::optional<fmt::Nval<int>> io_information_opt;
    if (!status)
        io_information_opt = fmt::Nval((int)io_information);

    fmt::print(this->m_output_format, "filetracer", drakvuf, info,
        keyval("FileName", fmt::Estr(attrs.file_path)),
        keyval("FileHandle", fmt::Xval(handle)),
        flagsval("ObjectAttributes", attrs.obj_attrs),
        keyval("IoStatusBlock", io_information_opt),
        keyval("SecurityDescriptor", security_descriptor),
        flagsval("DesiredAccess", desired_access),
        flagsval("FileAttributes", file_attrs),
        flagsval("ShareAccess", share_access),
        flagsval("CreateDisposition", create_disposition),
        flagsval("CreateOptions", create_opts),
        keyval("Status", fmt::Xval(status))
    );
}

void win_filetracer::print_open_file_obj_info(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    uint32_t handle,
    uint32_t io_information,
    const win_objattrs_t& attrs,
    win_data* params,
    uint64_t status)
{
    auto share_access = parse_flags(params->share_access, share_mode, this->m_output_format);
    auto open_opts = parse_flags(params->open_opts, create_options, this->m_output_format);
    auto desired_access = params->open_opts & FILE_DIRECTORY_FILE
        ? parse_flags(params->desired_access, directory_ar, this->m_output_format)
        : parse_flags(params->desired_access, file_ar, this->m_output_format);
    std::optional<fmt::Nval<int>> io_information_opt;
    if (!status)
        io_information_opt = fmt::Nval((int)io_information);

    fmt::print(this->m_output_format, "filetracer", drakvuf, info,
        keyval("FileName", fmt::Estr(attrs.file_path)),
        keyval("FileHandle", fmt::Xval(handle)),
        flagsval("ObjectAttributes", attrs.obj_attrs),
        keyval("IoStatusBlock", io_information_opt),
        flagsval("DesiredAccess", desired_access),
        flagsval("ShareAccess", share_access),
        flagsval("OpenOptions", open_opts),
        keyval("Status", fmt::Xval(status))
    );
}

std::tuple<bool, win_objattrs_t> win_filetracer::objattr_read(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t attrs)
{
    if (!attrs) return {};

    char* file_path = drakvuf_get_filename_from_object_attributes(drakvuf, info, attrs);
    if (!file_path)
        return {};

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    //==========================
    // Read security descriptor
    //==========================

    std::string security_flags;
    std::string owner;
    std::string group;
    std::string sacl;
    std::string dacl;

    // Get address of security descriptor
    addr_t security_descriptor = 0;
    ctx.addr = attrs + this->offsets[_OBJECT_ATTRIBUTES_SecurityDescriptor];
    if ( VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &security_descriptor)
        && security_descriptor )
    {
        // Get flags of security descriptor
        uint16_t se_ctrl = 0;
        ctx.addr = security_descriptor + this->offsets[_SECURITY_DESCRIPTOR_Control];
        if ( VMI_SUCCESS == vmi_read_16(vmi, &ctx, &se_ctrl) )
            security_flags = parse_flags(se_ctrl, security_controls, this->m_output_format, "SecurityControl=0");

        // Get owner SID
        addr_t powner = 0;
        ctx.addr = security_descriptor + this->offsets[_SECURITY_DESCRIPTOR_Owner];
        if ( VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &powner) && powner)
        {
            ctx.addr = powner;
            owner = read_sid(vmi, &ctx, this->offsets.data());
        }

        // Get group SID
        addr_t pgroup = 0;
        ctx.addr = security_descriptor + this->offsets[_SECURITY_DESCRIPTOR_Group];
        if ( VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &pgroup) && pgroup)
        {
            ctx.addr = pgroup;
            group = read_sid(vmi, &ctx, this->offsets.data());
        }

        // Get DACL
        addr_t pdacl = 0;
        ctx.addr = security_descriptor + this->offsets[_SECURITY_DESCRIPTOR_Dacl];
        if ( VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &pdacl) && pdacl)
        {
            ctx.addr = pdacl;
            dacl = read_acl(vmi, &ctx, this->offsets.data(), "Dacl", this->m_output_format);
        }

        // Get SACL
        addr_t psacl = 0;
        ctx.addr = security_descriptor + this->offsets[_SECURITY_DESCRIPTOR_Sacl];
        if ( VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &psacl) && psacl)
        {
            ctx.addr = psacl;
            sacl = read_acl(vmi, &ctx, this->offsets.data(), "Sacl", this->m_output_format);
        }
    }

    uint32_t obj_attr = 0;
    ctx.addr = attrs + this->offsets[_OBJECT_ATTRIBUTES_Attributes];
    if ( VMI_SUCCESS != vmi_read_32(vmi, &ctx, &obj_attr) )
        return {};

    auto file_attr = parse_flags(obj_attr, object_attrs, this->m_output_format, "Attributes=0");

    win_objattrs_t ret{file_path, file_attr, security_flags, owner, group, sacl, dacl};
    g_free(file_path);

    return std::make_tuple(true, std::move(ret));
}

std::tuple<bool, file_basic_information_t> win_filetracer::basic_file_info_read(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t basic_file_info)
{
    if (!basic_file_info) return {};

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    uint64_t creation_time = 0;
    uint64_t last_access_time = 0;
    uint64_t last_write_time = 0;
    uint64_t change_time = 0;
    uint32_t file_attributes = 0;

    ctx.addr = basic_file_info + this->offsets[_FILE_BASIC_INFORMATION_CreationTime];
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &creation_time) )
        return {};

    ctx.addr = basic_file_info + this->offsets[_FILE_BASIC_INFORMATION_LastAccessTime];
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &last_access_time) )
        return {};

    ctx.addr = basic_file_info + this->offsets[_FILE_BASIC_INFORMATION_LastWriteTime];
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &last_write_time) )
        return {};

    ctx.addr = basic_file_info + this->offsets[_FILE_BASIC_INFORMATION_ChangeTime];
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &change_time) )
        return {};

    ctx.addr = basic_file_info + this->offsets[_FILE_BASIC_INFORMATION_FileAttributes];
    if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &file_attributes) )
        return {};

    auto str_file_attr = parse_flags(file_attributes, file_flags_and_attrs, this->m_output_format, "FileAttributes=0");

    file_basic_information_t ret{windows_tick_to_unix(creation_time), windows_tick_to_unix(last_access_time), windows_tick_to_unix(last_write_time), windows_tick_to_unix(change_time), str_file_attr};

    return std::make_tuple(true, std::move(ret));
}

std::tuple<bool, file_network_open_information_t> win_filetracer::net_file_info_read(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t net_file_info)
{
    if (!net_file_info) return {};

    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    uint64_t creation_time = 0;
    uint64_t last_access_time = 0;
    uint64_t last_write_time = 0;
    uint64_t change_time = 0;
    uint64_t allocation_size = 0;
    uint64_t end_of_file = 0;
    uint32_t file_attributes = 0;

    ctx.addr = net_file_info + this->offsets[_FILE_NETWORK_OPEN_INFORMATION_CreationTime];
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &creation_time) )
        return {};

    ctx.addr = net_file_info + this->offsets[_FILE_NETWORK_OPEN_INFORMATION_LastAccessTime];
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &last_access_time) )
        return {};

    ctx.addr = net_file_info + this->offsets[_FILE_NETWORK_OPEN_INFORMATION_LastWriteTime];
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &last_write_time) )
        return {};

    ctx.addr = net_file_info + this->offsets[_FILE_NETWORK_OPEN_INFORMATION_ChangeTime];
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &change_time) )
        return {};

    ctx.addr = net_file_info + this->offsets[_FILE_NETWORK_OPEN_INFORMATION_AllocationSize];
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &allocation_size) )
        return {};

    ctx.addr = net_file_info + this->offsets[_FILE_NETWORK_OPEN_INFORMATION_EndOfFile];
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &end_of_file) )
        return {};

    ctx.addr = net_file_info + this->offsets[_FILE_NETWORK_OPEN_INFORMATION_FileAttributes];
    if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &file_attributes) )
        return {};

    auto str_file_attr = parse_flags(file_attributes, file_flags_and_attrs, this->m_output_format, "FileAttributes=0");

    file_network_open_information_t ret{windows_tick_to_unix(creation_time), windows_tick_to_unix(last_access_time), windows_tick_to_unix(last_write_time), windows_tick_to_unix(change_time), allocation_size, end_of_file, str_file_attr};

    return std::make_tuple(true, std::move(ret));
}

void win_filetracer::print_file_read_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t handle)
{
    char* file = drakvuf_get_filename_from_handle(drakvuf, info, handle);
    if ( !file )
        return;

    fmt::print(this->m_output_format, "filetracer", drakvuf, info,
        keyval("FileName", fmt::Qstr(file)),
        keyval("FileHandle", fmt::Xval(handle))
    );

    g_free(file);
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

void win_filetracer::print_delete_file_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t handle, addr_t fileinfo)
{
    const char* operation_name = "FileDispositionInformation";
    char* file = drakvuf_get_filename_from_handle(drakvuf, info, handle);
    if ( !file )
        return;

    fmt::print(this->m_output_format, "filetracer", drakvuf, info,
        keyval("Operation", fmt::Rstr(operation_name)),
        keyval("FileName", fmt::Qstr(file)),
        keyval("FileHandle", fmt::Xval(handle))
    );

    g_free(file);
}

void win_filetracer::print_basic_file_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t src_file_handle, const file_basic_information_t& basic_file_info, uint64_t status)
{
    const char* operation_name = "FileBasicInformation";
    char* filename_ = drakvuf_get_filename_from_handle(drakvuf, info, src_file_handle);
    const char* filename = filename_ ? : "<UNKNOWN>";
    if (!status)
    {
        fmt::print(this->m_output_format, "filetracer", drakvuf, info,
            keyval("Operation", fmt::Rstr(operation_name)),
            keyval("FileHandle", fmt::Xval(src_file_handle)),
            keyval("FileName", fmt::Qstr(filename)),
            keyval("CreationTime", fmt::Nval(basic_file_info.creation_time)),
            keyval("LastAccessTime", fmt::Nval(basic_file_info.last_access_time)),
            keyval("LastWriteTime", fmt::Nval(basic_file_info.last_write_time)),
            keyval("ChangeTime", fmt::Nval(basic_file_info.change_time)),
            flagsval("FileAttributes", basic_file_info.file_attributes)
        );
    }
    else
    {
        fmt::print(this->m_output_format, "filetracer", drakvuf, info,
            keyval("Operation", fmt::Rstr(operation_name)),
            keyval("FileHandle", fmt::Xval(src_file_handle)),
            keyval("FileName", fmt::Qstr(filename)),
            keyval("Status", fmt::Xval(status))
        );
    }

    g_free(filename_);
}

void win_filetracer::print_file_net_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t src_file_handle, const file_network_open_information_t& file_info, uint64_t status)
{
    const char* operation_name = "FileNetworkInformation";
    char* filename_ = drakvuf_get_filename_from_handle(drakvuf, info, src_file_handle);
    const char* filename = filename_ ? : "<UNKNOWN>";

    if (!status)
    {
        fmt::print(this->m_output_format, "filetracer", drakvuf, info,
            keyval("Operation", fmt::Rstr(operation_name)),
            keyval("FileHandle", fmt::Xval(src_file_handle)),
            keyval("FileName", fmt::Qstr(filename)),
            keyval("CreationTime", fmt::Nval(file_info.creation_time)),
            keyval("LastAccessTime", fmt::Nval(file_info.last_access_time)),
            keyval("LastWriteTime", fmt::Nval(file_info.last_write_time)),
            keyval("ChangeTime", fmt::Nval(file_info.change_time)),
            keyval("AllocationSize", fmt::Xval(file_info.allocation_size)),
            keyval("EndOfFile", fmt::Xval(file_info.end_of_file)),
            flagsval("FileAttributes", file_info.file_attributes)
        );
    }
    else
    {
        fmt::print(this->m_output_format, "filetracer", drakvuf, info,
            keyval("Operation", fmt::Rstr(operation_name)),
            keyval("FileHandle", fmt::Xval(src_file_handle)),
            keyval("FileName", fmt::Qstr(filename)),
            keyval("Status", fmt::Xval(status))
        );
    }
}

void win_filetracer::print_file_query_attributes(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const win_objattrs_t& attrs, const file_basic_information_t& file_info, uint64_t status)
{
    auto security_descriptor = build_security_descriptor(attrs);

    if (!status)
    {
        fmt::print(this->m_output_format, "filetracer", drakvuf, info,
            keyval("FileName", fmt::Estr(attrs.file_path)),
            flagsval("ObjectAttributes", attrs.obj_attrs),
            keyval("SecurityDescriptor", security_descriptor),
            keyval("CreationTime", fmt::Nval(file_info.creation_time)),
            keyval("LastAccessTime", fmt::Nval(file_info.last_access_time)),
            keyval("LastWriteTime", fmt::Nval(file_info.last_write_time)),
            keyval("ChangeTime", fmt::Nval(file_info.change_time)),
            flagsval("FileAttributes", file_info.file_attributes)
        );
    }
    else
    {
        fmt::print(this->m_output_format, "filetracer", drakvuf, info,
            keyval("FileName", fmt::Estr(attrs.file_path)),
            flagsval("ObjectAttributes", attrs.obj_attrs),
            keyval("SecurityDescriptor", security_descriptor),
            keyval("Status", fmt::Xval(status))
        );
    }
}

void win_filetracer::print_file_query_full_attributes(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const win_objattrs_t& attrs, const file_network_open_information_t& file_info, uint64_t status)
{
    auto security_descriptor = build_security_descriptor(attrs);

    if (!status)
    {
        fmt::print(this->m_output_format, "filetracer", drakvuf, info,
            keyval("FileName", fmt::Estr(attrs.file_path)),
            flagsval("ObjectAttributes", attrs.obj_attrs),
            keyval("SecurityDescriptor", security_descriptor),
            keyval("CreationTime", fmt::Nval(file_info.creation_time)),
            keyval("LastAccessTime", fmt::Nval(file_info.last_access_time)),
            keyval("LastWriteTime", fmt::Nval(file_info.last_write_time)),
            keyval("ChangeTime", fmt::Nval(file_info.change_time)),
            keyval("AllocationSize", fmt::Xval(file_info.allocation_size)),
            keyval("EndOfFile", fmt::Xval(file_info.end_of_file)),
            flagsval("FileAttributes", file_info.file_attributes)
        );
    }
    else
    {
        fmt::print(this->m_output_format, "filetracer", drakvuf, info,
            keyval("FileName", fmt::Estr(attrs.file_path)),
            flagsval("ObjectAttributes", attrs.obj_attrs),
            keyval("SecurityDescriptor", security_descriptor),
            keyval("Status", fmt::Xval(status))
        );
    }
}

void win_filetracer::print_rename_file_info(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t src_file_handle, addr_t fileinfo)
{
    if (!this->has_ole32) return;

    const char* operation_name = "FileRenameInformation";

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    addr_t dst_file_root_handle = 0;
    ctx.addr = fileinfo + this->ole32_offsets[_FILE_RENAME_INFORMATION_RootDirectory];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &dst_file_root_handle) )
        return;

    uint32_t dst_file_name_length = 0;
    ctx.addr = fileinfo + this->ole32_offsets[_FILE_RENAME_INFORMATION_FileNameLength];
    if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &dst_file_name_length) )
        return;

    // convert length in bytes to length in wchar symbols
    dst_file_name_length /= 2;

    ctx.addr = fileinfo + this->ole32_offsets[_FILE_RENAME_INFORMATION_FileName];
    unicode_string_t* dst_file_name_us = drakvuf_read_wchar_array(drakvuf, &ctx, dst_file_name_length);
    if ( !dst_file_name_us )
        return;

    char* src_file = drakvuf_get_filename_from_handle(drakvuf, info, src_file_handle);
    if ( !src_file )
    {
        vmi_free_unicode_str(dst_file_name_us);
        return;
    }

    char* dst_file_p = NULL;
    if (dst_file_root_handle)
    {
        char* dst_file_root = drakvuf_get_filename_from_handle(drakvuf, info, dst_file_root_handle);
        dst_file_p = g_strdup_printf("%s\\%s", dst_file_root ?: "", dst_file_name_us->contents);
        g_free(dst_file_root);
    }
    else if (is_absolute_path(reinterpret_cast<char*>(dst_file_name_us->contents)))
    {
        dst_file_p = g_strdup(reinterpret_cast<char*>(dst_file_name_us->contents));
    }
    else
    {
        char* dst_file_root_p = get_parent_folder(src_file);
        dst_file_p = g_strdup_printf("%s\\%s", dst_file_root_p ?: "", dst_file_name_us->contents);
        g_free(dst_file_root_p);
    }
    vmi_free_unicode_str(dst_file_name_us);

    fmt::print(this->m_output_format, "filetracer", drakvuf, info,
        keyval("Operation", fmt::Rstr(operation_name)),
        keyval("FileSrc", fmt::Qstr(src_file)),
        keyval("FileDst", fmt::Qstr(dst_file_p)),
        keyval("FileHandle", fmt::Xval(src_file_handle))
    );

    g_free(dst_file_p);
    g_free(src_file);
}

void win_filetracer::print_eof_file_info(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t src_file_handle, addr_t fileinfo)
{
    const char* operation_name = "FileEndOfFileInformation";

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.addr = fileinfo;
    ctx.dtb = info->regs->cr3;

    uint64_t file_size = 0;
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &file_size))
        return;

    char* filename_ = drakvuf_get_filename_from_handle(drakvuf, info, src_file_handle);
    const char* filename = filename_ ? : "<UNKNOWN>";

    fmt::print(this->m_output_format, "filetracer", drakvuf, info,
        keyval("Operation", fmt::Rstr(operation_name)),
        keyval("FileHandle", fmt::Xval(src_file_handle)),
        keyval("FileName", fmt::Qstr(filename)),
        keyval("FileSize", fmt::Nval(file_size))
    );

    g_free(filename_);
}

event_response_t win_filetracer::create_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<win_data>(info);

    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    uint32_t handle = 0;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = params->handle
        );
        if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &handle))
            PRINT_DEBUG("filetracer: Failed to read pHandle at 0x%lx (PID %d, TID %d)\n", params->handle, params->pid, params->tid);
    }

    auto [succ, file_attrs] = objattr_read(drakvuf, info, params->obj_attr);

    uint32_t io_information = 0;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = params->io_status_block + this->offsets[_IO_STATUS_BLOCK_Information]
        );
        if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &io_information))
            PRINT_DEBUG("filetracer: Failed to read _IO_STATUS_BLOCK Information at 0x%lx (PID %d, TID %d)\n", params->io_status_block + this->offsets[_IO_STATUS_BLOCK_Information], params->pid, params->tid);
    }

    if (succ)
        print_create_file_obj_info(drakvuf, info, handle, io_information, file_attrs, params, info->regs->rax);

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks.erase(hookID);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_filetracer::create_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    __kernel_entry NTSTATUS NtCreateFile(
      OUT PHANDLE           FileHandle,
      IN ACCESS_MASK        DesiredAccess,
      IN POBJECT_ATTRIBUTES ObjectAttributes,
      OUT PIO_STATUS_BLOCK  IoStatusBlock,
      IN PLARGE_INTEGER     AllocationSize,
      IN ULONG              FileAttributes,
      IN ULONG              ShareAccess,
      IN ULONG              CreateDisposition,
      IN ULONG              CreateOptions,
      IN PVOID              EaBuffer,
      IN ULONG              EaLength
    );
    */

    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    auto desired_access = drakvuf_get_function_argument(drakvuf, info, 2);
    auto attrs = drakvuf_get_function_argument(drakvuf, info, 3);
    auto io_status_block = drakvuf_get_function_argument(drakvuf, info, 4);
    auto file_attrs = drakvuf_get_function_argument(drakvuf, info, 6);
    auto share_access = drakvuf_get_function_argument(drakvuf, info, 7);
    auto create_disposition = drakvuf_get_function_argument(drakvuf, info, 8);
    auto create_opts = drakvuf_get_function_argument(drakvuf, info, 9);

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);

    if (!handle)
    {
        PRINT_DEBUG("filetracer: Null pointer pHandle in CreateFile\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    // Create new trap for return callback
    auto hook = this->createReturnHook<win_data>(info, &win_filetracer::create_file_ret_cb, info->trap->name);
    auto params = libhook::GetTrapParams<win_data>(hook->trap_);

    // Save data
    params->handle = handle;
    params->pid = info->attached_proc_data.pid;
    params->tid = info->attached_proc_data.tid;
    params->obj_attr = attrs;
    params->io_status_block = io_status_block;
    params->file_attrs = file_attrs;
    params->share_access = share_access;
    params->create_disposition = create_disposition;
    params->create_opts = create_opts;
    params->desired_access = desired_access;
    params->rsp = ret_addr;

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks[hookID] = std::move(hook);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_filetracer::open_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<win_data>(info);

    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    uint32_t handle = 0;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = params->handle
        );
        if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &handle))
            PRINT_DEBUG("filetracer: Failed to read pHandle at 0x%lx (PID %d, TID %d)\n", params->handle, params->pid, params->tid);
    }

    auto [succ, file_attrs] = objattr_read(drakvuf, info, params->obj_attr);

    uint32_t io_information = 0;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = params->io_status_block + this->offsets[_IO_STATUS_BLOCK_Information]
        );
        if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &io_information))
            PRINT_DEBUG("filetracer: Failed to read _IO_STATUS_BLOCK Information at 0x%lx (PID %d, TID %d)\n", params->io_status_block + this->offsets[_IO_STATUS_BLOCK_Information], params->pid, params->tid);
    }

    if (succ)
        print_open_file_obj_info(drakvuf, info, handle, io_information, file_attrs, params, info->regs->rax);

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks.erase(hookID);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_filetracer::open_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    __kernel_entry NTSTATUS NtOpenFile(
      OUT PHANDLE           FileHandle,
      IN ACCESS_MASK        DesiredAccess,
      IN POBJECT_ATTRIBUTES ObjectAttributes,
      OUT PIO_STATUS_BLOCK  IoStatusBlock,
      IN ULONG              ShareAccess,
      IN ULONG              OpenOptions
    );
    */
    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    auto desired_access = drakvuf_get_function_argument(drakvuf, info, 2);
    auto attrs = drakvuf_get_function_argument(drakvuf, info, 3);
    auto io_status_block = drakvuf_get_function_argument(drakvuf, info, 4);
    auto share_access = drakvuf_get_function_argument(drakvuf, info, 5);
    auto open_opts = drakvuf_get_function_argument(drakvuf, info, 6);

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);

    if (!handle)
    {
        PRINT_DEBUG("filetracer: Null pointer pHandle in NtOpenFile\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto hook = this->createReturnHook<win_data>(info, &win_filetracer::open_file_ret_cb, info->trap->name);
    auto params = libhook::GetTrapParams<win_data>(hook->trap_);

    // Save data
    params->handle = handle;
    params->pid = info->attached_proc_data.pid;
    params->tid = info->attached_proc_data.tid;
    params->obj_attr = attrs;
    params->io_status_block = io_status_block;
    params->share_access = share_access;
    params->open_opts = open_opts;
    params->desired_access = desired_access;
    params->rsp = ret_addr;

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks[hookID] = std::move(hook);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_filetracer::open_directory_object_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    NTSTATUS WINAPI NtOpenDirectoryObject(
      _Out_ PHANDLE            DirectoryHandle,
      _In_  ACCESS_MASK        DesiredAccess,
      _In_  POBJECT_ATTRIBUTES ObjectAttributes
    );
    */
    addr_t attrs = drakvuf_get_function_argument(drakvuf, info, 3);

    auto [succ, file_attrs] = objattr_read(drakvuf, info, attrs);
    if (succ)
        print_file_obj_info(drakvuf, info, file_attrs);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_filetracer::query_attributes_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<win_data>(info);

    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    auto [succ_1, file_attrs] = objattr_read(drakvuf, info, params->obj_attr);
    auto [succ_2, file_info] = basic_file_info_read(drakvuf, info, params->file_information);

    if (succ_1 && succ_2)
        print_file_query_attributes(drakvuf, info, file_attrs, file_info, info->regs->rax);

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks.erase(hookID);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_filetracer::query_attributes_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    NTSTATUS NtQueryAttributesFile(
      _In_  POBJECT_ATTRIBUTES      ObjectAttributes,
      _Out_ PFILE_BASIC_INFORMATION FileInformation
    );
    */
    addr_t attrs = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t file_information = drakvuf_get_function_argument(drakvuf, info, 2);

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);

    auto hook = this->createReturnHook<win_data>(info, &win_filetracer::query_attributes_file_ret_cb, info->trap->name);
    auto params = libhook::GetTrapParams<win_data>(hook->trap_);

    // Save data
    params->pid = info->attached_proc_data.pid;
    params->tid = info->attached_proc_data.tid;
    params->obj_attr = attrs;
    params->file_information = file_information;
    params->rsp = ret_addr;

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks[hookID] = std::move(hook);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_filetracer::query_full_attributes_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<win_data>(info);

    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    auto [succ_1, file_attrs] = objattr_read(drakvuf, info, params->obj_attr);
    auto [succ_2, file_info] = net_file_info_read(drakvuf, info, params->file_information);

    if (succ_1 && succ_2)
        print_file_query_full_attributes(drakvuf, info, file_attrs, file_info, info->regs->rax);

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks.erase(hookID);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_filetracer::query_full_attributes_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    NTSTATUS NtQueryFullAttributesFile(
        [in]  POBJECT_ATTRIBUTES             ObjectAttributes,
        [out] PFILE_NETWORK_OPEN_INFORMATION FileInformation
    );
    */
    addr_t attrs = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t file_information = drakvuf_get_function_argument(drakvuf, info, 2);

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);

    auto hook = this->createReturnHook<win_data>(info, &win_filetracer::query_attributes_file_ret_cb, info->trap->name);
    auto params = libhook::GetTrapParams<win_data>(hook->trap_);

    // Save data
    params->pid = info->attached_proc_data.pid;
    params->tid = info->attached_proc_data.tid;
    params->obj_attr = attrs;
    params->file_information = file_information;
    params->rsp = ret_addr;

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks[hookID] = std::move(hook);

    return VMI_EVENT_RESPONSE_NONE;
}

// TODO Remove hard-code. Retrieve from Volatility3 profile: profile["enums"]["_FILE_INFORMATION_CLASS"]
#define FILE_BASIC_INFORMATION 4
#define FILE_RENAME_INFORMATION 10
#define FILE_DISPOSITION_INFORMATION 13
#define FILE_END_OF_FILE_INFORMATION 20

event_response_t win_filetracer::set_information_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t fileinfo = drakvuf_get_function_argument(drakvuf, info, 3);
    uint32_t fileinfoclass = drakvuf_get_function_argument(drakvuf, info, 5);


    switch (fileinfoclass)
    {
        case FILE_BASIC_INFORMATION:
        {
            auto [succ, file_info] = basic_file_info_read(drakvuf, info, fileinfo);
            if (succ)
                print_basic_file_info(drakvuf, info, handle, file_info, 0);
        }
        break;

        case FILE_RENAME_INFORMATION:
            if (this->has_ole32)
            {
                auto vmi = vmi_lock_guard(drakvuf);
                print_rename_file_info(vmi, drakvuf, info, handle, fileinfo);
            }
            break;

        case FILE_DISPOSITION_INFORMATION:
        {
            print_delete_file_info(drakvuf, info, handle, fileinfo);
        }
        break;

        case FILE_END_OF_FILE_INFORMATION:
        {
            auto vmi = vmi_lock_guard(drakvuf);
            print_eof_file_info(vmi, drakvuf, info, handle, fileinfo);
        }
        break;
        default:
            break;
    };

    return 0;
}

event_response_t win_filetracer::read_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    NTSTATUS NtReadFile(
      _In_     HANDLE           FileHandle,
      _In_opt_ HANDLE           Event,
      _In_opt_ PIO_APC_ROUTINE  ApcRoutine,
      _In_opt_ PVOID            ApcContext,
      _Out_    PIO_STATUS_BLOCK IoStatusBlock,
      _Out_    PVOID            Buffer,
      _In_     ULONG            Length,
      _In_opt_ PLARGE_INTEGER   ByteOffset,
      _In_opt_ PULONG           Key
    );
    */
    uint64_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    if (handle)
        print_file_read_info(drakvuf, info, handle);
    return 0;
}

event_response_t win_filetracer::write_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    __kernel_entry NTSYSCALLAPI NTSTATUS NtWriteFile(
      HANDLE           FileHandle,
      HANDLE           Event,
      PIO_APC_ROUTINE  ApcRoutine,
      PVOID            ApcContext,
      PIO_STATUS_BLOCK IoStatusBlock,
      PVOID            Buffer,
      ULONG            Length,
      PLARGE_INTEGER   ByteOffset,
      PULONG           Key
    );
    */
    uint64_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    if (handle)
        print_file_read_info(drakvuf, info, handle);
    return 0;
}

#define FileBasicInformation 4
#define FileAllInformation 18
#define FileNetworkOpenInformation 34

event_response_t win_filetracer::query_information_file_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<win_data>(info);

    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    switch (params->file_information_class )
    {
        case FileBasicInformation:
        {
            auto [succ, file_info] = basic_file_info_read(drakvuf, info, params->file_information);
            if (succ)
                print_basic_file_info(drakvuf, info, params->handle, file_info, info->regs->rax);
            break;
        }
        case FileNetworkOpenInformation:
        {
            auto [succ, file_info] = net_file_info_read(drakvuf, info, params->file_information);
            if (succ)
                print_file_net_info(drakvuf, info, params->handle, file_info, info->regs->rax);
            break;
        }
        case FileAllInformation:
            if ( this->has_ole32 )
            {
                auto [succ, file_info] = basic_file_info_read(drakvuf, info, params->file_information + this->ole32_offsets[_FILE_ALL_INFORMATION_BasicInformation]);
                if (succ)
                    print_basic_file_info(drakvuf, info, params->handle, file_info, info->regs->rax);
            }
            break;
        default:
            break;
    };

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks.erase(hookID);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_filetracer::query_information_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
        __kernel_entry NTSYSCALLAPI NTSTATUS NtQueryInformationFile(
        [in]  HANDLE                 FileHandle,
        [out] PIO_STATUS_BLOCK       IoStatusBlock,
        [out] PVOID                  FileInformation,
        [in]  ULONG                  Length,
        [in]  FILE_INFORMATION_CLASS FileInformationClass
        );
    */
    uint32_t fileinfoclass = drakvuf_get_function_argument(drakvuf, info, 5);

    if (fileinfoclass == FileBasicInformation || fileinfoclass == FileAllInformation || fileinfoclass == FileNetworkOpenInformation)
    {
        uint64_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
        addr_t fileinfo = drakvuf_get_function_argument(drakvuf, info, 3);
        addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);

        // Create new trap for return callback
        auto hook = this->createReturnHook<win_data>(info, &win_filetracer::query_information_file_ret_cb, info->trap->name);
        auto params = libhook::GetTrapParams<win_data>(hook->trap_);

        // Save data
        params->handle = handle;
        params->rsp = ret_addr;
        params->pid = info->attached_proc_data.pid;
        params->tid = info->attached_proc_data.tid;
        params->file_information = fileinfo;
        params->file_information_class = fileinfoclass;

        auto hookID = make_hook_id(info, params->target_rsp);
        this->ret_hooks[hookID] = std::move(hook);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

/* ----------------------------------------------------- */

win_filetracer::win_filetracer(drakvuf_t drakvuf, const filetracer_config* c, output_format_t output)
    : pluginex(drakvuf, output)
{
    if ( !drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, this->offsets.size(), this->offsets.data()) )
        throw -1;

    if ( c->ole32_profile )
    {
        auto ole32_profile_json = profile_guard(c->ole32_profile);
        if (!json_get_struct_members_array_rva(drakvuf, ole32_profile_json, ole32_offset_names, this->ole32_offsets.size(), this->ole32_offsets.data()))
            throw -1;

        this->has_ole32 = true;
    }

    create_file_hook = createSyscallHook("NtCreateFile", &win_filetracer::create_file_cb);
    open_file_hook = createSyscallHook("NtOpenFile", &win_filetracer::open_file_cb);
    open_directory_object_hook = createSyscallHook("NtOpenDirectoryObject", &win_filetracer::open_directory_object_cb);
    query_attributes_file_hook = createSyscallHook("NtQueryAttributesFile", &win_filetracer::query_attributes_file_cb);
    query_full_attributes_file_hook = createSyscallHook("NtQueryFullAttributesFile", &win_filetracer::query_full_attributes_file_cb);
    set_information_file_hook = createSyscallHook("NtSetInformationFile", &win_filetracer::set_information_file_cb);
    read_file_hook = createSyscallHook("NtReadFile", &win_filetracer::read_file_cb);
    write_file_hook = createSyscallHook("NtWriteFile", &win_filetracer::write_file_cb);
    query_information_file_hook = createSyscallHook("NtQueryInformationFile", &win_filetracer::query_information_file_cb);
}
