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
 ***************************************************************************/

#ifndef FILETRACER_PRIVATE_H
#define FILETRACER_PRIVATE_H

#include <string>
#include "plugins/plugin_utils.h"
#include "win.h"
#include "linux.h"

struct win_objattrs_t
{
    std::string file_path;
    std::string obj_attrs;

    std::string security_flags;
    std::string owner;
    std::string group;
    std::string sacl;
    std::string dacl;
};

struct wrapper
{
    win_filetracer* f;

    vmi_pid_t pid;
    uint32_t tid;
    uint64_t rsp;

    addr_t handle;

    addr_t obj_attr;
    uint64_t file_attrs;
    uint64_t share_access;
    uint64_t create_disposition;
    uint64_t create_opts;
    uint64_t desired_access;
};

struct linux_wrapper
{
    vmi_pid_t pid = 0;
    uint32_t tid = 0;
    uint64_t rsp = 0;
    int permissions = 0;

    linux_filetracer* f;
    GString* filename = g_string_new(NULL);
    GString* flags = g_string_new(NULL);
    GString* modes = g_string_new(NULL);
    GString* uid = g_string_new(NULL);
    GString* gid = g_string_new(NULL);
    std::map<std::string, GString*> args;
};

struct pool_header_x86
{
    union
    {
        struct
        {
            uint16_t previous_size : 9;
            uint16_t pool_index : 7;
            uint16_t block_size : 9; // bits 0-9
            uint16_t pool_type : 7;  // bits 10-16
        };
        uint16_t flags;
    };
    uint32_t pool_tag;
} __attribute__((packed));

struct pool_header_x64
{
    union
    {
        struct
        {
            uint32_t previous_size : 8;
            uint32_t pool_index : 8;
            uint32_t block_size : 8;
            uint32_t pool_type : 8;
        };
        uint32_t flags;
    };
    uint32_t pool_tag;
    uint64_t process_billed; // _EPROCESS *
} __attribute__((packed));

enum
{
    _OBJECT_ATTRIBUTES_Attributes,
    _OBJECT_ATTRIBUTES_SecurityDescriptor,
    _SECURITY_DESCRIPTOR_Control,
    _SECURITY_DESCRIPTOR_Owner,
    _SECURITY_DESCRIPTOR_Group,
    _SECURITY_DESCRIPTOR_Sacl,
    _SECURITY_DESCRIPTOR_Dacl,
    _SID_Revision,
    _SID_SubAuthorityCount,
    _SID_IdentifierAuthority,
    _SID_SubAuthority,
    _ACL_AceCount,
    _ACL_AclSize,
    __OFFSET_MAX
};

enum
{
    OBJ_INHERIT = 0x002L,
    OBJ_PERMANENT = 0x010L,
    OBJ_EXCLUSIVE = 0x020L,
    OBJ_CASE_INSENSITIVE = 0x040L,
    OBJ_OPENIF = 0x080L,
    OBJ_OPENLINK = 0x100L,
    OBJ_KERNEL_HANDLE = 0x200L,
    OBJ_FORCE_ACCESS_CHECK = 0x400L,
    OBJ_VALID_ATTRIBUTES = 0x7F2L,
};

// File Attributes
enum
{
    FILE_ATTRIBUTE_READONLY = 0x00000001,
    FILE_ATTRIBUTE_HIDDEN = 0x00000002,
    FILE_ATTRIBUTE_SYSTEM = 0x00000004,
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010,
    FILE_ATTRIBUTE_ARCHIVE = 0x00000020,
    FILE_ATTRIBUTE_DEVICE = 0x00000040,
    FILE_ATTRIBUTE_NORMAL = 0x00000080,
    FILE_ATTRIBUTE_TEMPORARY = 0x00000100,
    FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200,
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400,
    FILE_ATTRIBUTE_COMPRESSED = 0x00000800,
    FILE_ATTRIBUTE_OFFLINE = 0x00001000,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000,
    FILE_ATTRIBUTE_ENCRYPTED = 0x00004000,
    FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x00008000,
    FILE_ATTRIBUTE_VIRTUAL = 0x00010000,
    FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x00020000,
    FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000,
};

// Flags
enum
{
    FILE_FLAG_OPEN_NO_RECALL = 0x00100000,
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000,
    FILE_FLAG_POSIX_SEMANTICS = 0x01000000,
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000,
    FILE_FLAG_DELETE_ON_CLOSE = 0x04000000,
    FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000,
    FILE_FLAG_RANDOM_ACCESS = 0x10000000,
    FILE_FLAG_NO_BUFFERING = 0x20000000,
    FILE_FLAG_OVERLAPPED = 0x40000000,
    FILE_FLAG_WRITE_THROUGH = 0x80000000,
};

// Generic Access Rights
enum
{
    DELETE = 0x00010000,
    READ_CONTROL = 0x00020000,
    WRITE_DAC = 0x00040000,
    WRITE_OWNER = 0x00080000,
    SYNCHRONIZE = 0x00100000,
    ACCESS_SYSTEM_SECURITY = 0x01000000,
    GENERIC_ALL = 0x10000000,
    GENERIC_EXECUTE = 0x20000000,
    GENERIC_WRITE = 0x40000000,
    GENERIC_READ = 0x80000000,
    SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
    STANDARD_RIGHTS_ALL = 0x001F0000,
};

// File Access Rights
enum
{
    FILE_ANY_ACCESS = 0x00000000,
    FILE_READ_DATA = 0x00000001,
    FILE_WRITE_DATA = 0x00000002,
    FILE_APPEND_DATA = 0x00000004,
    FILE_READ_EA = 0x00000008,
    FILE_WRITE_EA = 0x00000010,
    FILE_EXECUTE = 0x00000020,
    FILE_READ_ATTRIBUTES = 0x00000080,
    FILE_WRITE_ATTRIBUTES = 0x00000100,
};

// Directory Access Rights
enum
{
    FILE_LIST_DIRECTORY = 0x00000001,
    FILE_ADD_FILE = 0x00000002,
    FILE_ADD_SUBDIRECTORY = 0x00000004,
    FILE_TRAVERSE = 0x00000020,
    FILE_DELETE_CHILD = 0x00000040,
};

// Share Mode
enum
{
    FILE_SHARE_NONE = 0x00000000,
    FILE_SHARE_READ = 0x00000001,
    FILE_SHARE_WRITE = 0x00000002,
    FILE_SHARE_DELETE = 0x00000004,
};

// Disposition
enum
{
    FILE_SUPERSEDE = 0x00000000,
    FILE_OPEN = 0x00000001,
    FILE_CREATE = 0x00000002,
    FILE_OPEN_IF = 0x00000003,
    FILE_OVERWRITE = 0x00000004,
    FILE_OVERWRITE_IF = 0x00000005,
};

// Create Options
enum
{
    FILE_DIRECTORY_FILE = 0x00000001,
    FILE_WRITE_THROUGH = 0x00000002,
    FILE_SEQUENTIAL_ONLY = 0x00000004,
    FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008,
    FILE_SYNCHRONOUS_IO_ALERT = 0x00000010,
    FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020,
    FILE_NON_DIRECTORY_FILE = 0x00000040,
    FILE_CREATE_TREE_CONNECTION = 0x00000080,
    FILE_COMPLETE_IF_OPLOCKED = 0x00000100,
    FILE_NO_EA_KNOWLEDGE = 0x00000200,
    FILE_OPEN_REMOTE_INSTANCE = 0x00000400,
    FILE_RANDOM_ACCESS = 0x00000800,
    FILE_DELETE_ON_CLOSE = 0x00001000,
    FILE_OPEN_BY_FILE_ID = 0x00002000,
    FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000,
    FILE_NO_COMPRESSION = 0x00008000,
    FILE_OPEN_REQUIRING_OPLOCK = 0x00010000,
    FILE_RESERVE_OPFILTER = 0x00100000,
    FILE_OPEN_REPARSE_POINT = 0x00200000,
    FILE_OPEN_NO_RECALL = 0x00400000,
    FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000
};

// Security Descriptor Controls
enum
{
    SE_OWNER_DEFAULTED = 0x0001,
    SE_GROUP_DEFAULTED = 0x0002,
    SE_DACL_PRESENT = 0x0004,
    SE_DACL_DEFAULTED = 0x0008,
    SE_SACL_PRESENT = 0x0010,
    SE_SACL_DEFAULTED = 0x0020,
    SE_DACL_AUTO_INHERIT_REQ = 0x0100,
    SE_SACL_AUTO_INHERIT_REQ = 0x0200,
    SE_DACL_AUTO_INHERITED = 0x0400,
    SE_SACL_AUTO_INHERITED = 0x0800,
    SE_DACL_PROTECTED = 0x1000,
    SE_SACL_PROTECTED = 0x2000,
    SE_RM_CONTROL_VALID = 0x4000,
    SE_SELF_RELATIVE = 0x8000,
};

static const char* offset_names[__OFFSET_MAX][2] =
{
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
    REGISTER_FLAG(OBJ_INHERIT),
    REGISTER_FLAG(OBJ_PERMANENT),
    REGISTER_FLAG(OBJ_EXCLUSIVE),
    REGISTER_FLAG(OBJ_CASE_INSENSITIVE),
    REGISTER_FLAG(OBJ_OPENIF),
    REGISTER_FLAG(OBJ_OPENLINK),
    REGISTER_FLAG(OBJ_KERNEL_HANDLE),
    REGISTER_FLAG(OBJ_FORCE_ACCESS_CHECK),
    REGISTER_FLAG(OBJ_VALID_ATTRIBUTES),
};

static const flags_str_t file_flags_and_attrs =
{
    REGISTER_FLAG(FILE_ATTRIBUTE_READONLY),
    REGISTER_FLAG(FILE_ATTRIBUTE_HIDDEN),
    REGISTER_FLAG(FILE_ATTRIBUTE_SYSTEM),
    REGISTER_FLAG(FILE_ATTRIBUTE_DIRECTORY),
    REGISTER_FLAG(FILE_ATTRIBUTE_ARCHIVE),
    REGISTER_FLAG(FILE_ATTRIBUTE_DEVICE),
    REGISTER_FLAG(FILE_ATTRIBUTE_NORMAL),
    REGISTER_FLAG(FILE_ATTRIBUTE_TEMPORARY),
    REGISTER_FLAG(FILE_ATTRIBUTE_SPARSE_FILE),
    REGISTER_FLAG(FILE_ATTRIBUTE_REPARSE_POINT),
    REGISTER_FLAG(FILE_ATTRIBUTE_COMPRESSED),
    REGISTER_FLAG(FILE_ATTRIBUTE_OFFLINE),
    REGISTER_FLAG(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED),
    REGISTER_FLAG(FILE_ATTRIBUTE_ENCRYPTED),
    REGISTER_FLAG(FILE_ATTRIBUTE_INTEGRITY_STREAM),
    REGISTER_FLAG(FILE_ATTRIBUTE_VIRTUAL),
    REGISTER_FLAG(FILE_ATTRIBUTE_NO_SCRUB_DATA),
    REGISTER_FLAG(FILE_ATTRIBUTE_RECALL_ON_OPEN),
    REGISTER_FLAG(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS),
    REGISTER_FLAG(FILE_FLAG_OPEN_NO_RECALL),
    REGISTER_FLAG(FILE_FLAG_OPEN_REPARSE_POINT),
    REGISTER_FLAG(FILE_FLAG_POSIX_SEMANTICS),
    REGISTER_FLAG(FILE_FLAG_BACKUP_SEMANTICS),
    REGISTER_FLAG(FILE_FLAG_DELETE_ON_CLOSE),
    REGISTER_FLAG(FILE_FLAG_SEQUENTIAL_SCAN),
    REGISTER_FLAG(FILE_FLAG_RANDOM_ACCESS),
    REGISTER_FLAG(FILE_FLAG_NO_BUFFERING),
    REGISTER_FLAG(FILE_FLAG_OVERLAPPED),
    REGISTER_FLAG(FILE_FLAG_WRITE_THROUGH),
};

const flags_str_t generic_ar =
{
    REGISTER_FLAG(DELETE),
    REGISTER_FLAG(READ_CONTROL),
    REGISTER_FLAG(WRITE_DAC),
    REGISTER_FLAG(WRITE_OWNER),
    REGISTER_FLAG(SYNCHRONIZE),
    REGISTER_FLAG(ACCESS_SYSTEM_SECURITY),
    REGISTER_FLAG(GENERIC_ALL),
    REGISTER_FLAG(GENERIC_EXECUTE),
    REGISTER_FLAG(GENERIC_WRITE),
    REGISTER_FLAG(GENERIC_READ),
    REGISTER_FLAG(SPECIFIC_RIGHTS_ALL),
    REGISTER_FLAG(STANDARD_RIGHTS_ALL),
};

static const flags_str_t file_ar =
{
    REGISTER_FLAG(DELETE),
    REGISTER_FLAG(READ_CONTROL),
    REGISTER_FLAG(WRITE_DAC),
    REGISTER_FLAG(WRITE_OWNER),
    REGISTER_FLAG(SYNCHRONIZE),
    REGISTER_FLAG(ACCESS_SYSTEM_SECURITY),
    REGISTER_FLAG(GENERIC_ALL),
    REGISTER_FLAG(GENERIC_EXECUTE),
    REGISTER_FLAG(GENERIC_WRITE),
    REGISTER_FLAG(GENERIC_READ),
    REGISTER_FLAG(SPECIFIC_RIGHTS_ALL),
    REGISTER_FLAG(STANDARD_RIGHTS_ALL),
    REGISTER_FLAG(FILE_READ_DATA),
    REGISTER_FLAG(FILE_WRITE_DATA),
    REGISTER_FLAG(FILE_APPEND_DATA),
    REGISTER_FLAG(FILE_READ_EA),
    REGISTER_FLAG(FILE_WRITE_EA),
    REGISTER_FLAG(FILE_EXECUTE),
    REGISTER_FLAG(FILE_READ_ATTRIBUTES),
    REGISTER_FLAG(FILE_WRITE_ATTRIBUTES),
};

static const flags_str_t directory_ar =
{
    REGISTER_FLAG(DELETE),
    REGISTER_FLAG(READ_CONTROL),
    REGISTER_FLAG(WRITE_DAC),
    REGISTER_FLAG(WRITE_OWNER),
    REGISTER_FLAG(SYNCHRONIZE),
    REGISTER_FLAG(ACCESS_SYSTEM_SECURITY),
    REGISTER_FLAG(GENERIC_ALL),
    REGISTER_FLAG(GENERIC_EXECUTE),
    REGISTER_FLAG(GENERIC_WRITE),
    REGISTER_FLAG(GENERIC_READ),
    REGISTER_FLAG(SPECIFIC_RIGHTS_ALL),
    REGISTER_FLAG(STANDARD_RIGHTS_ALL),
    REGISTER_FLAG(FILE_LIST_DIRECTORY),
    REGISTER_FLAG(FILE_ADD_FILE),
    REGISTER_FLAG(FILE_ADD_SUBDIRECTORY),
    REGISTER_FLAG(FILE_TRAVERSE),
    REGISTER_FLAG(FILE_DELETE_CHILD),
};

static const flags_str_t share_mode =
{
    REGISTER_FLAG(FILE_SHARE_READ),
    REGISTER_FLAG(FILE_SHARE_WRITE),
    REGISTER_FLAG(FILE_SHARE_DELETE),
};

static const flags_str_t disposition =
{
    REGISTER_FLAG(FILE_OPEN),
    REGISTER_FLAG(FILE_CREATE),
    REGISTER_FLAG(FILE_OPEN_IF),
    REGISTER_FLAG(FILE_OVERWRITE),
    REGISTER_FLAG(FILE_OVERWRITE_IF),
};

static const flags_str_t create_options =
{
    REGISTER_FLAG(FILE_DIRECTORY_FILE),
    REGISTER_FLAG(FILE_WRITE_THROUGH),
    REGISTER_FLAG(FILE_SEQUENTIAL_ONLY),
    REGISTER_FLAG(FILE_NO_INTERMEDIATE_BUFFERING),
    REGISTER_FLAG(FILE_SYNCHRONOUS_IO_ALERT),
    REGISTER_FLAG(FILE_SYNCHRONOUS_IO_NONALERT),
    REGISTER_FLAG(FILE_NON_DIRECTORY_FILE),
    REGISTER_FLAG(FILE_CREATE_TREE_CONNECTION),
    REGISTER_FLAG(FILE_COMPLETE_IF_OPLOCKED),
    REGISTER_FLAG(FILE_NO_EA_KNOWLEDGE),
    REGISTER_FLAG(FILE_OPEN_REMOTE_INSTANCE),
    REGISTER_FLAG(FILE_RANDOM_ACCESS),
    REGISTER_FLAG(FILE_DELETE_ON_CLOSE),
    REGISTER_FLAG(FILE_OPEN_BY_FILE_ID),
    REGISTER_FLAG(FILE_OPEN_FOR_BACKUP_INTENT),
    REGISTER_FLAG(FILE_NO_COMPRESSION),
    REGISTER_FLAG(FILE_OPEN_REQUIRING_OPLOCK),
    REGISTER_FLAG(FILE_RESERVE_OPFILTER),
    REGISTER_FLAG(FILE_OPEN_REPARSE_POINT),
    REGISTER_FLAG(FILE_OPEN_NO_RECALL),
    REGISTER_FLAG(FILE_OPEN_FOR_FREE_SPACE_QUERY)
};

static const flags_str_t security_controls =
{
    REGISTER_FLAG(SE_OWNER_DEFAULTED),
    REGISTER_FLAG(SE_GROUP_DEFAULTED),
    REGISTER_FLAG(SE_DACL_PRESENT),
    REGISTER_FLAG(SE_DACL_DEFAULTED),
    REGISTER_FLAG(SE_SACL_PRESENT),
    REGISTER_FLAG(SE_SACL_DEFAULTED),
    REGISTER_FLAG(SE_DACL_AUTO_INHERIT_REQ),
    REGISTER_FLAG(SE_SACL_AUTO_INHERIT_REQ),
    REGISTER_FLAG(SE_DACL_AUTO_INHERITED),
    REGISTER_FLAG(SE_SACL_AUTO_INHERITED),
    REGISTER_FLAG(SE_DACL_PROTECTED),
    REGISTER_FLAG(SE_SACL_PROTECTED),
    REGISTER_FLAG(SE_RM_CONTROL_VALID),
    REGISTER_FLAG(SE_SELF_RELATIVE),
};

// Offsets Enum
enum
{
    _FILE_F_FLAGS,
    _FILE_F_PATH,
    _FILE_F_MODE,

    _INODE_I_GID,
    _INODE_I_UID,
    _INODE_I_MODE,
    _INODE_I_FLAGS,

    _PATH_DENTRY,
    _DENTRY_D_NAME,
    _DENTRY_D_INODE,
    _QSTR_NAME,
    // _TIMESPEC64_TV_SEC,

    __LINUX_OFFSET_MAX,
};

// Linux Offsets
static const char* linux_offset_names[__OFFSET_MAX][2] =
{
    [_FILE_F_FLAGS] = {"file", "f_flags"},
    [_FILE_F_PATH] = {"file", "f_path"},
    [_FILE_F_MODE] = {"file", "f_mode"},

    [_INODE_I_GID] = {"inode", "i_gid"},
    [_INODE_I_UID] = {"inode", "i_uid"},
    [_INODE_I_MODE] = {"inode", "i_mode"},
    [_INODE_I_FLAGS] = {"inode", "i_flags"},

    [_PATH_DENTRY] = {"path", "dentry"},
    [_DENTRY_D_NAME] = {"dentry", "d_name"},
    [_DENTRY_D_INODE] = {"dentry", "d_inode"},
    [_QSTR_NAME] = {"qstr", "name"},
    // [_TIMESPEC64_TV_SEC] = {"timespec64", "tv_sec"},
};

// Linux Inode Flags
enum
{
    FLAG_O_ACCMODE = 0x000000003,
    FLAG_O_RDONLY = 0x000000000,
    FLAG_O_WRONLY = 0x000000001,
    FLAG_O_RDWR = 0x000000002,
    FLAG_O_CREAT = 0x000000100,
    FLAG_O_EXCL = 0x000000200,
    FLAG_O_NOCTTY = 0x000000400,
    FLAG_O_TRUNC = 0x000001000,
    FLAG_O_APPEND = 0x000002000,
    FLAG_O_NONBLOCK = 0x000004000,
    FLAG_O_DSYNC = 0x000010000,
    FLAG_FASYNC = 0x000020000,
    FLAG_O_DIRECT = 0x000040000,
    FLAG_O_LARGEFILE = 0x000100000,
    FLAG_O_DIRECTORY = 0x000200000,
    FLAG_O_NOFOLLOW = 0x000400000,
    FLAG_O_NOATIME = 0x001000000,
    FLAG_O_CLOEXEC = 0x002000000,
    FLAG___O_SYNC = 0x004000000,
    FLAG_O_PATH = 0x010000000,
    FLAG___O_TMPFILE = 0x020000000,
};

static const flags_str_t linux_inode_flags =
{
    REGISTER_FLAG(FLAG_O_ACCMODE),
    REGISTER_FLAG(FLAG_O_RDONLY),
    REGISTER_FLAG(FLAG_O_WRONLY),
    REGISTER_FLAG(FLAG_O_RDWR),
    REGISTER_FLAG(FLAG_O_CREAT),
    REGISTER_FLAG(FLAG_O_EXCL),
    REGISTER_FLAG(FLAG_O_NOCTTY),
    REGISTER_FLAG(FLAG_O_TRUNC),
    REGISTER_FLAG(FLAG_O_APPEND),
    REGISTER_FLAG(FLAG_O_NONBLOCK),
    REGISTER_FLAG(FLAG_O_DSYNC),
    REGISTER_FLAG(FLAG_FASYNC),
    REGISTER_FLAG(FLAG_O_DIRECT),
    REGISTER_FLAG(FLAG_O_LARGEFILE),
    REGISTER_FLAG(FLAG_O_DIRECTORY),
    REGISTER_FLAG(FLAG_O_NOFOLLOW),
    REGISTER_FLAG(FLAG_O_NOATIME),
    REGISTER_FLAG(FLAG_O_CLOEXEC),
    REGISTER_FLAG(FLAG___O_SYNC),
    REGISTER_FLAG(FLAG_O_PATH),
    REGISTER_FLAG(FLAG___O_TMPFILE),
};

// Linux File Permission Modes
enum
{
    // Mutually-Exclusive file types:
    MODE_S_IFMT = 0170000,
    MODE_S_IFSOCK = 0140000,
    MODE_S_IFLNK = 0120000,
    MODE_S_IFREG = 0100000,
    MODE_S_IFBLK = 0060000,
    MODE_S_IFDIR = 0040000,
    MODE_S_IFCHR = 0020000,
    MODE_S_IFIFO = 0010000,
};

static const flags_str_t linux_file_modes =
{
    // Mutually-Exclusive file types:
    REGISTER_FLAG(MODE_S_IFMT),
    REGISTER_FLAG(MODE_S_IFSOCK),
    REGISTER_FLAG(MODE_S_IFLNK),
    REGISTER_FLAG(MODE_S_IFREG),
    REGISTER_FLAG(MODE_S_IFBLK),
    REGISTER_FLAG(MODE_S_IFDIR),
    REGISTER_FLAG(MODE_S_IFCHR),
    REGISTER_FLAG(MODE_S_IFIFO),
};

// Linux lseek directive whence
enum
{
    LSEEK_SET = 0,  /* seek relative to beginning of file */
    LSEEK_CUR = 1,  /* seek relative to current file position */
    LSEEK_END = 2,  /* seek relative to end of file */
    LSEEK_DATA = 3, /* seek to the next data */
    LSEEK_HOLE = 4, /* seek to the next hole */
};

static const flags_str_t linux_lseek_whence =
{
    // Mutually-Exclusive file types:
    REGISTER_FLAG(LSEEK_SET),
    REGISTER_FLAG(LSEEK_CUR),
    REGISTER_FLAG(LSEEK_END),
    REGISTER_FLAG(LSEEK_DATA),
    REGISTER_FLAG(LSEEK_HOLE),
};

#endif
