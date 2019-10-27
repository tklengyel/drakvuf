/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  *
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
#include <algorithm>
#include <assert.h>
#include <sstream>

#include <libvmi/libvmi.h>
#include "plugins/plugins.h"
#include "private.h"
#include "filetracer.h"
#include "win_acl.h"

static const char* offset_names[__OFFSET_MAX][2] =
{
    [_OBJECT_ATTRIBUTES_ObjectName] = {"_OBJECT_ATTRIBUTES", "ObjectName"},
    [_OBJECT_ATTRIBUTES_RootDirectory] = {"_OBJECT_ATTRIBUTES", "RootDirectory"},
    [_OBJECT_ATTRIBUTES_Attributes] = {"_OBJECT_ATTRIBUTES", "Attributes"},
    [_OBJECT_ATTRIBUTES_SecurityDescriptor] = {"_OBJECT_ATTRIBUTES", "SecurityDescriptor"},
    [_SECURITY_DESCRIPTOR_Control] = {"_SECURITY_DESCRIPTOR", "Control"},
    [_SECURITY_DESCRIPTOR_Owner] = {"_SECURITY_DESCRIPTOR", "Owner"},
    [_SECURITY_DESCRIPTOR_Group] = {"_SECURITY_DESCRIPTOR", "Group"},
    [_SECURITY_DESCRIPTOR_Sacl] = {"_SECURITY_DESCRIPTOR", "Sacl"},
    [_SECURITY_DESCRIPTOR_Dacl] = {"_SECURITY_DESCRIPTOR", "Dacl"},
    [_SID_Revision] = {"_SID", "Revision"},
    [_SID_SubAuthorityCount] = {"_SID", "SubAuthorityCount"},
    [_SID_IdentifierAuthority] = {"_SID", "IdentifierAuthority"},
    [_SID_SubAuthority] = {"_SID", "SubAuthority"},
    [_ACL_AceCount] = {"_ACL", "AceCount"},
    [_ACL_AclSize] = {"_ACL", "AclSize"},
};

static const flags_str_t object_attrs =
{
    REGISTER_FLAG(OBJ_INHERIT           ),
    REGISTER_FLAG(OBJ_PERMANENT         ),
    REGISTER_FLAG(OBJ_EXCLUSIVE         ),
    REGISTER_FLAG(OBJ_CASE_INSENSITIVE  ),
    REGISTER_FLAG(OBJ_OPENIF            ),
    REGISTER_FLAG(OBJ_OPENLINK          ),
    REGISTER_FLAG(OBJ_KERNEL_HANDLE     ),
    REGISTER_FLAG(OBJ_FORCE_ACCESS_CHECK),
    REGISTER_FLAG(OBJ_VALID_ATTRIBUTES  ),
};

static const flags_str_t file_flags_and_attrs =
{
    REGISTER_FLAG(FILE_ATTRIBUTE_READONLY             ),
    REGISTER_FLAG(FILE_ATTRIBUTE_HIDDEN               ),
    REGISTER_FLAG(FILE_ATTRIBUTE_SYSTEM               ),
    REGISTER_FLAG(FILE_ATTRIBUTE_DIRECTORY            ),
    REGISTER_FLAG(FILE_ATTRIBUTE_ARCHIVE              ),
    REGISTER_FLAG(FILE_ATTRIBUTE_DEVICE               ),
    REGISTER_FLAG(FILE_ATTRIBUTE_NORMAL               ),
    REGISTER_FLAG(FILE_ATTRIBUTE_TEMPORARY            ),
    REGISTER_FLAG(FILE_ATTRIBUTE_SPARSE_FILE          ),
    REGISTER_FLAG(FILE_ATTRIBUTE_REPARSE_POINT        ),
    REGISTER_FLAG(FILE_ATTRIBUTE_COMPRESSED           ),
    REGISTER_FLAG(FILE_ATTRIBUTE_OFFLINE              ),
    REGISTER_FLAG(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  ),
    REGISTER_FLAG(FILE_ATTRIBUTE_ENCRYPTED            ),
    REGISTER_FLAG(FILE_ATTRIBUTE_INTEGRITY_STREAM     ),
    REGISTER_FLAG(FILE_ATTRIBUTE_VIRTUAL              ),
    REGISTER_FLAG(FILE_ATTRIBUTE_NO_SCRUB_DATA        ),
    REGISTER_FLAG(FILE_ATTRIBUTE_RECALL_ON_OPEN       ),
    REGISTER_FLAG(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS),
    REGISTER_FLAG(FILE_FLAG_OPEN_NO_RECALL            ),
    REGISTER_FLAG(FILE_FLAG_OPEN_REPARSE_POINT        ),
    REGISTER_FLAG(FILE_FLAG_POSIX_SEMANTICS           ),
    REGISTER_FLAG(FILE_FLAG_BACKUP_SEMANTICS          ),
    REGISTER_FLAG(FILE_FLAG_DELETE_ON_CLOSE           ),
    REGISTER_FLAG(FILE_FLAG_SEQUENTIAL_SCAN           ),
    REGISTER_FLAG(FILE_FLAG_RANDOM_ACCESS             ),
    REGISTER_FLAG(FILE_FLAG_NO_BUFFERING              ),
    REGISTER_FLAG(FILE_FLAG_OVERLAPPED                ),
    REGISTER_FLAG(FILE_FLAG_WRITE_THROUGH             ),
};

const flags_str_t generic_ar =
{
    REGISTER_FLAG(DELETE                ),
    REGISTER_FLAG(READ_CONTROL          ),
    REGISTER_FLAG(WRITE_DAC             ),
    REGISTER_FLAG(WRITE_OWNER           ),
    REGISTER_FLAG(SYNCHRONIZE           ),
    REGISTER_FLAG(ACCESS_SYSTEM_SECURITY),
    REGISTER_FLAG(GENERIC_ALL           ),
    REGISTER_FLAG(GENERIC_EXECUTE       ),
    REGISTER_FLAG(GENERIC_WRITE         ),
    REGISTER_FLAG(GENERIC_READ          ),
    REGISTER_FLAG(SPECIFIC_RIGHTS_ALL   ),
    REGISTER_FLAG(STANDARD_RIGHTS_ALL   ),
};

static const flags_str_t file_ar =
{
    REGISTER_FLAG(DELETE                ),
    REGISTER_FLAG(READ_CONTROL          ),
    REGISTER_FLAG(WRITE_DAC             ),
    REGISTER_FLAG(WRITE_OWNER           ),
    REGISTER_FLAG(SYNCHRONIZE           ),
    REGISTER_FLAG(ACCESS_SYSTEM_SECURITY),
    REGISTER_FLAG(GENERIC_ALL           ),
    REGISTER_FLAG(GENERIC_EXECUTE       ),
    REGISTER_FLAG(GENERIC_WRITE         ),
    REGISTER_FLAG(GENERIC_READ          ),
    REGISTER_FLAG(SPECIFIC_RIGHTS_ALL   ),
    REGISTER_FLAG(STANDARD_RIGHTS_ALL   ),
    REGISTER_FLAG(FILE_READ_DATA        ),
    REGISTER_FLAG(FILE_WRITE_DATA       ),
    REGISTER_FLAG(FILE_APPEND_DATA      ),
    REGISTER_FLAG(FILE_READ_EA          ),
    REGISTER_FLAG(FILE_WRITE_EA         ),
    REGISTER_FLAG(FILE_EXECUTE          ),
    REGISTER_FLAG(FILE_READ_ATTRIBUTES  ),
    REGISTER_FLAG(FILE_WRITE_ATTRIBUTES ),
};

static const flags_str_t directory_ar =
{
    REGISTER_FLAG(DELETE                ),
    REGISTER_FLAG(READ_CONTROL          ),
    REGISTER_FLAG(WRITE_DAC             ),
    REGISTER_FLAG(WRITE_OWNER           ),
    REGISTER_FLAG(SYNCHRONIZE           ),
    REGISTER_FLAG(ACCESS_SYSTEM_SECURITY),
    REGISTER_FLAG(GENERIC_ALL           ),
    REGISTER_FLAG(GENERIC_EXECUTE       ),
    REGISTER_FLAG(GENERIC_WRITE         ),
    REGISTER_FLAG(GENERIC_READ          ),
    REGISTER_FLAG(SPECIFIC_RIGHTS_ALL   ),
    REGISTER_FLAG(STANDARD_RIGHTS_ALL   ),
    REGISTER_FLAG(FILE_LIST_DIRECTORY   ),
    REGISTER_FLAG(FILE_ADD_FILE         ),
    REGISTER_FLAG(FILE_ADD_SUBDIRECTORY ),
    REGISTER_FLAG(FILE_TRAVERSE         ),
    REGISTER_FLAG(FILE_DELETE_CHILD     ),
};

static const flags_str_t share_mode =
{
    REGISTER_FLAG(FILE_SHARE_READ  ),
    REGISTER_FLAG(FILE_SHARE_WRITE ),
    REGISTER_FLAG(FILE_SHARE_DELETE),
};

static const flags_str_t disposition =
{
    REGISTER_FLAG(FILE_OPEN        ),
    REGISTER_FLAG(FILE_CREATE      ),
    REGISTER_FLAG(FILE_OPEN_IF     ),
    REGISTER_FLAG(FILE_OVERWRITE   ),
    REGISTER_FLAG(FILE_OVERWRITE_IF),
};

static const flags_str_t create_options =
{
    REGISTER_FLAG(FILE_DIRECTORY_FILE           ),
    REGISTER_FLAG(FILE_WRITE_THROUGH            ),
    REGISTER_FLAG(FILE_SEQUENTIAL_ONLY          ),
    REGISTER_FLAG(FILE_NO_INTERMEDIATE_BUFFERING),
    REGISTER_FLAG(FILE_SYNCHRONOUS_IO_ALERT     ),
    REGISTER_FLAG(FILE_SYNCHRONOUS_IO_NONALERT  ),
    REGISTER_FLAG(FILE_NON_DIRECTORY_FILE       ),
    REGISTER_FLAG(FILE_CREATE_TREE_CONNECTION   ),
    REGISTER_FLAG(FILE_COMPLETE_IF_OPLOCKED     ),
    REGISTER_FLAG(FILE_NO_EA_KNOWLEDGE          ),
    REGISTER_FLAG(FILE_OPEN_REMOTE_INSTANCE     ),
    REGISTER_FLAG(FILE_RANDOM_ACCESS            ),
    REGISTER_FLAG(FILE_DELETE_ON_CLOSE          ),
    REGISTER_FLAG(FILE_OPEN_BY_FILE_ID          ),
    REGISTER_FLAG(FILE_OPEN_FOR_BACKUP_INTENT   ),
    REGISTER_FLAG(FILE_NO_COMPRESSION           ),
    REGISTER_FLAG(FILE_OPEN_REQUIRING_OPLOCK    ),
    REGISTER_FLAG(FILE_RESERVE_OPFILTER         ),
    REGISTER_FLAG(FILE_OPEN_REPARSE_POINT       ),
    REGISTER_FLAG(FILE_OPEN_NO_RECALL           ),
    REGISTER_FLAG(FILE_OPEN_FOR_FREE_SPACE_QUERY)
};

static const flags_str_t security_controls =
{
    REGISTER_FLAG(SE_OWNER_DEFAULTED      ),
    REGISTER_FLAG(SE_GROUP_DEFAULTED      ),
    REGISTER_FLAG(SE_DACL_PRESENT         ),
    REGISTER_FLAG(SE_DACL_DEFAULTED       ),
    REGISTER_FLAG(SE_SACL_PRESENT         ),
    REGISTER_FLAG(SE_SACL_DEFAULTED       ),
    REGISTER_FLAG(SE_DACL_AUTO_INHERIT_REQ),
    REGISTER_FLAG(SE_SACL_AUTO_INHERIT_REQ),
    REGISTER_FLAG(SE_DACL_AUTO_INHERITED  ),
    REGISTER_FLAG(SE_SACL_AUTO_INHERITED  ),
    REGISTER_FLAG(SE_DACL_PROTECTED       ),
    REGISTER_FLAG(SE_SACL_PROTECTED       ),
    REGISTER_FLAG(SE_RM_CONTROL_VALID     ),
    REGISTER_FLAG(SE_SELF_RELATIVE        ),
};

static void print_file_obj_info(drakvuf_t drakvuf,
                                drakvuf_trap_info_t* info,
                                char const* file_path,
                                string file_attr = string(),
                                string security_flags = string(),
                                string owner = string(),
                                string group = string(),
                                string sacl = string(),
                                string dacl = string())
{
    filetracer* f = (filetracer*)info->trap->data;
    gchar* escaped_pname = NULL;
    gchar* escaped_fname = NULL;

    switch (f->format)
    {
        case OUTPUT_CSV:
            printf("filetracer," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, info->trap->name, file_path);
            if (!file_attr.empty()) printf(",\"%s\"", file_attr.data());
            if (!security_flags.empty()) printf(",\"%s\"", security_flags.data());
            if (!owner.empty()) printf(",%s", owner.data());
            if (!group.empty()) printf(",%s", group.data());
            if (!sacl.empty()) printf(",%s", sacl.data());
            if (!dacl.empty()) printf(",%s", dacl.data());
            printf("\n");
            break;

        case OUTPUT_KV:
            printf("filetracer Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,File=\"%s\"",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name, file_path);
            if (!file_attr.empty()) printf(",%s", file_attr.data());
            if (!security_flags.empty()) printf(",%s", security_flags.data());
            if (!owner.empty()) printf(",%s", owner.data());
            if (!group.empty()) printf(",%s", group.data());
            if (!sacl.empty()) printf(",%s", sacl.data());
            if (!dacl.empty()) printf(",%s", dacl.data());
            printf("\n");
            break;

        case OUTPUT_JSON:
            escaped_fname = drakvuf_escape_str(file_path);
            escaped_pname = drakvuf_escape_str(info->proc_data.name);

            printf( "{"
                    "\"Plugin\" : \"filetracer\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"ProcessName\": %s,"
                    "\"UserName\": \"%s\","
                    "\"UserId\": %" PRIu64 ","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"Method\": \"%s\","
                    "\"FileName\": %s",
                    UNPACK_TIMEVAL(info->timestamp),
                    escaped_pname,
                    USERIDSTR(drakvuf), info->proc_data.userid,
                    info->proc_data.pid, info->proc_data.ppid,
                    info->trap->name, escaped_fname);

            if (!file_attr.empty())
                printf(",\"ObjectAttributes\" : \"%s\"", file_attr.data());
            if (!security_flags.empty() || !owner.empty() || !group.empty())
            {
                printf(",\"SecurityDescriptor\" : {");

                if (!security_flags.empty())
                    printf("\"Control\" : \"%s\"", security_flags.data());
                else
                    printf("\"Control\" : null");
                if (!owner.empty()) printf(",%s", owner.data());
                if (!group.empty()) printf(",%s", group.data());
                if (!sacl.empty()) printf(",%s", sacl.data());
                if (!dacl.empty()) printf(",%s", dacl.data());

                printf("}");
            }

            printf("}\n");
            g_free(escaped_fname);
            g_free(escaped_pname);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[FILETRACER] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " %s,%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, info->trap->name, file_path);
            if (!file_attr.empty()) printf(",\"%s\"", file_attr.data());
            if (!security_flags.empty()) printf(",\"%s\"", security_flags.data());
            if (!owner.empty()) printf(",%s", owner.data());
            if (!group.empty()) printf(",%s", group.data());
            if (!sacl.empty()) printf(",%s", sacl.data());
            if (!dacl.empty()) printf(",%s", dacl.data());
            printf("\n");
            break;
    }
}

string objattr_read(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t attrs)
{
    if (!attrs) return string();

    filetracer* f = (filetracer*)info->trap->data;

    vmi_lock_guard vmi_lg(drakvuf);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    //==========================
    // Read security descriptor
    //==========================

    string security_flags_str;
    string owner;
    string group;
    string sacl;
    string dacl;

    // Get address of security descriptor
    addr_t security_descriptor = 0;
    ctx.addr = attrs + f->offsets[_OBJECT_ATTRIBUTES_SecurityDescriptor];
    if ( VMI_SUCCESS == vmi_read_addr(vmi_lg.vmi, &ctx, &security_descriptor)
         && security_descriptor )
    {
        // Get flags of security descriptor
        uint16_t se_ctrl = 0;
        ctx.addr = security_descriptor + f->offsets[_SECURITY_DESCRIPTOR_Control];
        if ( VMI_SUCCESS == vmi_read_16(vmi_lg.vmi, &ctx, &se_ctrl) )
            security_flags_str = parse_flags(se_ctrl, security_controls, f->format, "SecurityControl=0");

        // Get owner SID
        addr_t powner = 0;
        ctx.addr = security_descriptor + f->offsets[_SECURITY_DESCRIPTOR_Owner];
        if ( VMI_SUCCESS == vmi_read_addr(vmi_lg.vmi, &ctx, &powner) && powner)
        {
            ctx.addr = powner;
            owner = read_sid(vmi_lg.vmi, &ctx, f->offsets);
        }

        // Get group SID
        addr_t pgroup = 0;
        ctx.addr = security_descriptor + f->offsets[_SECURITY_DESCRIPTOR_Group];
        if ( VMI_SUCCESS == vmi_read_addr(vmi_lg.vmi, &ctx, &pgroup) && pgroup)
        {
            ctx.addr = pgroup;
            group = read_sid(vmi_lg.vmi, &ctx, f->offsets);
        }

        // Get DACL
        addr_t pdacl = 0;
        ctx.addr = security_descriptor + f->offsets[_SECURITY_DESCRIPTOR_Dacl];
        if ( VMI_SUCCESS == vmi_read_addr(vmi_lg.vmi, &ctx, &pdacl) && pdacl)
        {
            ctx.addr = pdacl;
            dacl = read_acl(vmi_lg.vmi, &ctx, f->offsets, "Dacl", f->format);
        }

        // Get SACL
        addr_t psacl = 0;
        ctx.addr = security_descriptor + f->offsets[_SECURITY_DESCRIPTOR_Sacl];
        if ( VMI_SUCCESS == vmi_read_addr(vmi_lg.vmi, &ctx, &psacl) && psacl)
        {
            ctx.addr = psacl;
            sacl = read_acl(vmi_lg.vmi, &ctx, f->offsets, "Sacl", f->format);
        }
    }

    //==========================
    // Get file name
    //==========================
    addr_t file_root_handle = 0;
    ctx.addr = attrs + f->offsets[_OBJECT_ATTRIBUTES_RootDirectory];
    if ( VMI_FAILURE == vmi_read_addr(vmi_lg.vmi, &ctx, &file_root_handle) )
        return string();

    char* file_root = drakvuf_get_filename_from_handle(drakvuf, info, file_root_handle);

    ctx.addr = attrs + f->offsets[_OBJECT_ATTRIBUTES_ObjectName];
    if ( VMI_FAILURE == vmi_read_addr(vmi_lg.vmi, &ctx, &ctx.addr) )
    {
        g_free(file_root);
        return string();
    }

    unicode_string_t* file_name_us = drakvuf_read_unicode(drakvuf, info, ctx.addr);

    if ( !file_name_us )
    {
        g_free(file_root);
        return string();
    }

    uint32_t obj_attr = 0;
    ctx.addr = attrs + f->offsets[_OBJECT_ATTRIBUTES_Attributes];
    if ( VMI_FAILURE == vmi_read_32(vmi_lg.vmi, &ctx, &obj_attr) )
    {
        g_free(file_root);
        return string();
    }

    char* file_path = g_strdup_printf("%s%s%s",
                                      file_root ?: "",
                                      file_root ? "\\" : "",
                                      file_name_us->contents);
    string ret{file_path};

    vmi_free_unicode_str(file_name_us);
    g_free(file_root);

    auto a = parse_flags(obj_attr, object_attrs, f->format, "Attributes=0");

    print_file_obj_info(drakvuf, info, file_path, a, security_flags_str, owner, group, sacl, dacl);

    g_free(file_path);

    return ret;
}

static event_response_t handle_read(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint64_t handle)
{
    if (!handle) return 0;

    char* file_path = drakvuf_get_filename_from_handle(drakvuf, info, handle);

    print_file_obj_info(drakvuf, info, file_path);

    g_free(file_path);

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


static void print_delete_file_info(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle, addr_t fileinfo)
{
    gchar* escaped_pname = NULL;
    gchar* escaped_fname = NULL;
    const char* syscall_name = info->trap->name;
    const char* operation_name = "FileDispositionInformation";
    filetracer* f = (filetracer*)info->trap->data;
    char* file = drakvuf_get_filename_from_handle(drakvuf, info, handle);
    if ( !file )
        return;

    switch (f->format)
    {
        case OUTPUT_CSV:
            printf("filetracer," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%s,%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid,
                   syscall_name, operation_name, file);
            break;

        case OUTPUT_KV:
            printf("filetracer Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,Operation=%s,File=\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   syscall_name, operation_name, file);
            break;

        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            escaped_fname = drakvuf_escape_str(file);
            printf( "{"
                    "\"Plugin\" : \"filetracer\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"ProcessName\": %s,"
                    "\"UserName\": \"%s\","
                    "\"UserId\": %" PRIu64 ","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"Method\" : \"%s\","
                    "\"Operation\" : \"%s\","
                    "\"FileName\" : %s"
                    "}\n",
                    UNPACK_TIMEVAL(info->timestamp),
                    escaped_pname,
                    USERIDSTR(drakvuf), info->proc_data.userid,
                    info->proc_data.pid, info->proc_data.ppid,
                    syscall_name, operation_name, escaped_fname);

            g_free(escaped_fname);
            g_free(escaped_pname);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[FILETRACER] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " %s,%s,%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, USERIDSTR(drakvuf), info->proc_data.userid,
                   syscall_name, operation_name, file);
            break;
    }

    g_free(file);
}

static void print_rename_file_info(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t src_file_handle, addr_t fileinfo)
{
    gchar* escaped_pname = NULL;
    gchar* escaped_fname_src = NULL;
    gchar* escaped_fname_dst = NULL;

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

    // convert length in bytes to length in wchar symbols
    dst_file_name_length /= 2;

    ctx.addr = fileinfo + f->newfile_name_offset;
    unicode_string_t* dst_file_name_us = drakvuf_read_wchar_array(vmi, &ctx, dst_file_name_length);
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

    switch (f->format)
    {
        case OUTPUT_CSV:
            printf("filetracer," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%s,%s,%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid,
                   syscall_name, operation_name, src_file, dst_file_p);
            break;

        case OUTPUT_KV:
            printf("filetracer Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,Operation=%s,FileSrc=\"%s\",FileDst=\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   syscall_name, operation_name,
                   src_file, dst_file_p);
            break;
        case OUTPUT_JSON:
            escaped_pname = drakvuf_escape_str(info->proc_data.name);
            escaped_fname_src = drakvuf_escape_str(src_file);
            escaped_fname_dst = drakvuf_escape_str(dst_file_p);
            printf( "{"
                    "\"Plugin\" : \"filetracer\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"ProcessName\": %s,"
                    "\"UserName\": \"%s\","
                    "\"UserId\": %" PRIu64 ","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"Method\" : \"%s\","
                    "\"Operation\" : \"%s\","
                    "\"SrcFileName\" : %s,"
                    "\"DstFileName\" : %s"
                    "}\n",
                    UNPACK_TIMEVAL(info->timestamp),
                    escaped_pname,
                    USERIDSTR(drakvuf), info->proc_data.userid,
                    info->proc_data.pid, info->proc_data.ppid,
                    syscall_name, operation_name, escaped_fname_src, escaped_fname_dst );

            g_free(escaped_fname_dst);
            g_free(escaped_fname_src);
            g_free(escaped_pname);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[FILETRACER] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " %s,%s,%s,%s\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, USERIDSTR(drakvuf), info->proc_data.userid,
                   syscall_name, operation_name, src_file, dst_file_p);
            break;
    }

    g_free(dst_file_p);
    g_free(src_file);
}

static event_response_t create_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
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
    addr_t obj_attr = drakvuf_get_function_argument(drakvuf, info, 3);
    auto file_path = objattr_read(drakvuf, info, obj_attr);

    filetracer* f = (filetracer*)info->trap->data;

    auto attrs_value = drakvuf_get_function_argument(drakvuf, info, 6);
    auto attrs = parse_flags(attrs_value, file_flags_and_attrs, f->format);
    auto share_value = drakvuf_get_function_argument(drakvuf, info, 7);
    auto share = parse_flags(share_value, share_mode, f->format);
    auto disp_value = drakvuf_get_function_argument(drakvuf, info, 8);
    auto disp = parse_flags(disp_value, disposition, f->format);
    auto opts_value = drakvuf_get_function_argument(drakvuf, info, 9);
    auto opts = parse_flags(opts_value, create_options, f->format);
    auto access_value = drakvuf_get_function_argument(drakvuf, info, 2);
    auto access = opts_value & FILE_DIRECTORY_FILE
                  ? parse_flags(access_value, directory_ar, f->format)
                  : parse_flags(access_value, file_ar, f->format);

    gchar* escaped_pname = NULL;
    gchar* escaped_fname = NULL;

    switch (f->format)
    {
        case OUTPUT_CSV:
            printf("filetracer," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%s,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, info->trap->name,
                   file_path.c_str(), access.c_str(), attrs.c_str(), share.c_str(), disp.c_str(), opts.c_str());
            printf("\n");
            break;

        case OUTPUT_KV:
            printf("filetracer Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Method=%s,File=\"%s\""
                   ",%s,%s,%s,%s,%s",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   info->trap->name, file_path.c_str(), access.c_str(), attrs.c_str(), share.c_str(), disp.c_str(), opts.c_str());
            printf("\n");
            break;

        case OUTPUT_JSON:
            escaped_fname = drakvuf_escape_str(file_path.c_str());
            escaped_pname = drakvuf_escape_str(info->proc_data.name);

            printf( "{"
                    "\"Plugin\" : \"filetracer\","
                    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                    "\"ProcessName\": %s,"
                    "\"UserName\": \"%s\","
                    "\"UserId\": %" PRIu64 ","
                    "\"PID\" : %d,"
                    "\"PPID\": %d,"
                    "\"Method\": \"%s\","
                    "\"FileName\": %s,"
                    "\"DesiredAccess\": \"%s\","
                    "\"FileAttributes\": \"%s\","
                    "\"ShareAccess\": \"%s\","
                    "\"CreateDisposition\": \"%s\","
                    "\"CreateOptions\": \"%s\"",
                    UNPACK_TIMEVAL(info->timestamp),
                    escaped_pname,
                    USERIDSTR(drakvuf), info->proc_data.userid,
                    info->proc_data.pid, info->proc_data.ppid,
                    info->trap->name, escaped_fname,
                    access.c_str(), attrs.c_str(), share.c_str(), disp.c_str(), opts.c_str());

            printf("}\n");
            g_free(escaped_fname);
            g_free(escaped_pname);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[FILETRACER] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " %s,%s"
                   " DESIREDACCESS:\"%s\" FILEATTRIBUTES:\"%s\" SHAREACCESS:\"%s\" CREATEDISPOSITION:\"%s\" CREATEOPTIONS:\"%s\"",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid, info->trap->name, file_path.c_str(),
                   access.c_str(), attrs.c_str(), share.c_str(), disp.c_str(), opts.c_str());
            printf("\n");
            break;
    }

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t open_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
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
    addr_t attrs = drakvuf_get_function_argument(drakvuf, info, 3);
    objattr_read(drakvuf, info, attrs);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t open_directory_object_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    NTSTATUS WINAPI NtOpenDirectoryObject(
      _Out_ PHANDLE            DirectoryHandle,
      _In_  ACCESS_MASK        DesiredAccess,
      _In_  POBJECT_ATTRIBUTES ObjectAttributes
    );
    */
    addr_t attrs = drakvuf_get_function_argument(drakvuf, info, 3);
    objattr_read(drakvuf, info, attrs);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t query_attributes_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    /*
    NTSTATUS NtQueryAttributesFile(
      _In_  POBJECT_ATTRIBUTES      ObjectAttributes,
      _Out_ PFILE_BASIC_INFORMATION FileInformation
    );
    */
    addr_t attrs = drakvuf_get_function_argument(drakvuf, info, 1);
    objattr_read(drakvuf, info, attrs);

    return VMI_EVENT_RESPONSE_NONE;
}

#define FILE_RENAME_INFORMATION 10
#define FILE_DISPOSITION_INFORMATION 13

static event_response_t set_information_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t fileinfo = drakvuf_get_function_argument(drakvuf, info, 3);
    uint64_t fileinfoclass = drakvuf_get_function_argument(drakvuf, info, 5);

    if (fileinfoclass == FILE_RENAME_INFORMATION)
    {
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        print_rename_file_info(vmi, drakvuf, info, handle, fileinfo);
        drakvuf_release_vmi(drakvuf);
    }

    if (fileinfoclass == FILE_DISPOSITION_INFORMATION)
    {
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        print_delete_file_info(vmi, drakvuf, info, handle, fileinfo);
        drakvuf_release_vmi(drakvuf);
    }

    return 0;
}

static event_response_t read_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
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
    return handle_read(drakvuf, info, handle);
}

static event_response_t write_file_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
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
    return handle_read(drakvuf, info, handle);
}

/* ----------------------------------------------------- */

static void register_trap( drakvuf_t drakvuf, const char* syscall_name,
                           drakvuf_trap_t* trap,
                           event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !drakvuf_get_function_rva( drakvuf, syscall_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = syscall_name;
    trap->cb   = hook_cb;

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}

filetracer::filetracer(drakvuf_t drakvuf, output_format_t output)
    : format{output}
    , offsets(new size_t[__OFFSET_MAX])
{
    int addr_size = drakvuf_get_address_width(drakvuf); // 4 or 8 (bytes)

    if ( !drakvuf_get_struct_members_array_rva(drakvuf, offset_names, __OFFSET_MAX, offsets) )
        throw -1;
    // Offset of the RootDirectory field in _FILE_RENAME_INFORMATION structure
    this->newfile_root_offset = addr_size;
    // Offset of the FileName field in _FILE_RENAME_INFORMATION structure
    this->newfile_name_offset = addr_size * 2 + 4;
    // Offset of the FileNameLength field in _FILE_RENAME_INFORMATION structure
    this->newfile_name_length_offset = addr_size * 2;

    assert(sizeof(trap)/sizeof(trap[0]) > 6);
    register_trap(drakvuf, "NtCreateFile",          &trap[0], create_file_cb);
    register_trap(drakvuf, "NtOpenFile",            &trap[1], open_file_cb);
    register_trap(drakvuf, "NtOpenDirectoryObject", &trap[2], open_directory_object_cb);
    register_trap(drakvuf, "NtQueryAttributesFile", &trap[3], query_attributes_file_cb);
    register_trap(drakvuf, "NtSetInformationFile",  &trap[4], set_information_file_cb);
    register_trap(drakvuf, "NtReadFile",            &trap[5], read_file_cb);
    register_trap(drakvuf, "NtWriteFile",           &trap[6], write_file_cb);
}

filetracer::~filetracer()
{
    delete[] offsets;
}
