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

#ifndef FILETRACER_PRIVATE_H
#define FILETRACER_PRIVATE_H

#include "plugins/plugin_utils.h"

struct pool_header_x86
{
    union
    {
        struct
        {
            uint16_t previous_size :9;
            uint16_t pool_index :7;
            uint16_t block_size :9; // bits 0-9
            uint16_t pool_type :7; // bits 10-16
        };
        uint16_t flags;
    };
    uint32_t pool_tag;
} __attribute__ ((packed));

struct pool_header_x64
{
    union
    {
        struct
        {
            uint32_t previous_size :8;
            uint32_t pool_index :8;
            uint32_t block_size :8;
            uint32_t pool_type :8;
        };
        uint32_t flags;
    };
    uint32_t pool_tag;
    uint64_t process_billed; // _EPROCESS *
} __attribute__ ((packed));

enum
{
    _OBJECT_ATTRIBUTES_ObjectName,
    _OBJECT_ATTRIBUTES_RootDirectory,
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
    OBJ_INHERIT            = 0x002L,
    OBJ_PERMANENT          = 0x010L,
    OBJ_EXCLUSIVE          = 0x020L,
    OBJ_CASE_INSENSITIVE   = 0x040L,
    OBJ_OPENIF             = 0x080L,
    OBJ_OPENLINK           = 0x100L,
    OBJ_KERNEL_HANDLE      = 0x200L,
    OBJ_FORCE_ACCESS_CHECK = 0x400L,
    OBJ_VALID_ATTRIBUTES   = 0x7F2L,
};

// File Attributes
enum
{
    FILE_ATTRIBUTE_READONLY              = 0x00000001,
    FILE_ATTRIBUTE_HIDDEN                = 0x00000002,
    FILE_ATTRIBUTE_SYSTEM                = 0x00000004,
    FILE_ATTRIBUTE_DIRECTORY             = 0x00000010,
    FILE_ATTRIBUTE_ARCHIVE               = 0x00000020,
    FILE_ATTRIBUTE_DEVICE                = 0x00000040,
    FILE_ATTRIBUTE_NORMAL                = 0x00000080,
    FILE_ATTRIBUTE_TEMPORARY             = 0x00000100,
    FILE_ATTRIBUTE_SPARSE_FILE           = 0x00000200,
    FILE_ATTRIBUTE_REPARSE_POINT         = 0x00000400,
    FILE_ATTRIBUTE_COMPRESSED            = 0x00000800,
    FILE_ATTRIBUTE_OFFLINE               = 0x00001000,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED   = 0x00002000,
    FILE_ATTRIBUTE_ENCRYPTED             = 0x00004000,
    FILE_ATTRIBUTE_INTEGRITY_STREAM      = 0x00008000,
    FILE_ATTRIBUTE_VIRTUAL               = 0x00010000,
    FILE_ATTRIBUTE_NO_SCRUB_DATA         = 0x00020000,
    FILE_ATTRIBUTE_RECALL_ON_OPEN        = 0x00040000,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000,
};

// Flags
enum
{
    FILE_FLAG_OPEN_NO_RECALL     = 0x00100000,
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000,
    FILE_FLAG_POSIX_SEMANTICS    = 0x01000000,
    FILE_FLAG_BACKUP_SEMANTICS   = 0x02000000,
    FILE_FLAG_DELETE_ON_CLOSE    = 0x04000000,
    FILE_FLAG_SEQUENTIAL_SCAN    = 0x08000000,
    FILE_FLAG_RANDOM_ACCESS      = 0x10000000,
    FILE_FLAG_NO_BUFFERING       = 0x20000000,
    FILE_FLAG_OVERLAPPED         = 0x40000000,
    FILE_FLAG_WRITE_THROUGH      = 0x80000000,
};

// Generic Access Rights
enum
{
    DELETE                 = 0x00010000,
    READ_CONTROL           = 0x00020000,
    WRITE_DAC              = 0x00040000,
    WRITE_OWNER            = 0x00080000,
    SYNCHRONIZE            = 0x00100000,
    ACCESS_SYSTEM_SECURITY = 0x01000000,
    GENERIC_ALL            = 0x10000000,
    GENERIC_EXECUTE        = 0x20000000,
    GENERIC_WRITE          = 0x40000000,
    GENERIC_READ           = 0x80000000,
    SPECIFIC_RIGHTS_ALL    = 0x0000FFFF,
    STANDARD_RIGHTS_ALL    = 0x001F0000,
};

// File Access Rights
enum
{
    FILE_ANY_ACCESS       = 0x00000000,
    FILE_READ_DATA        = 0x00000001,
    FILE_WRITE_DATA       = 0x00000002,
    FILE_APPEND_DATA      = 0x00000004,
    FILE_READ_EA          = 0x00000008,
    FILE_WRITE_EA         = 0x00000010,
    FILE_EXECUTE          = 0x00000020,
    FILE_READ_ATTRIBUTES  = 0x00000080,
    FILE_WRITE_ATTRIBUTES = 0x00000100,
};

// Directory Access Rights
enum
{
    FILE_LIST_DIRECTORY   = 0x00000001,
    FILE_ADD_FILE         = 0x00000002,
    FILE_ADD_SUBDIRECTORY = 0x00000004,
    FILE_TRAVERSE         = 0x00000020,
    FILE_DELETE_CHILD     = 0x00000040,
};

// Share Mode
enum
{
    FILE_SHARE_NONE   = 0x00000000,
    FILE_SHARE_READ   = 0x00000001,
    FILE_SHARE_WRITE  = 0x00000002,
    FILE_SHARE_DELETE = 0x00000004,
};

// Disposition
enum
{
    FILE_SUPERSEDE    = 0x00000000,
    FILE_OPEN         = 0x00000001,
    FILE_CREATE       = 0x00000002,
    FILE_OPEN_IF      = 0x00000003,
    FILE_OVERWRITE    = 0x00000004,
    FILE_OVERWRITE_IF = 0x00000005,
};

// Create Options
enum
{
    FILE_DIRECTORY_FILE            = 0x00000001,
    FILE_WRITE_THROUGH             = 0x00000002,
    FILE_SEQUENTIAL_ONLY           = 0x00000004,
    FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008,
    FILE_SYNCHRONOUS_IO_ALERT      = 0x00000010,
    FILE_SYNCHRONOUS_IO_NONALERT   = 0x00000020,
    FILE_NON_DIRECTORY_FILE        = 0x00000040,
    FILE_CREATE_TREE_CONNECTION    = 0x00000080,
    FILE_COMPLETE_IF_OPLOCKED      = 0x00000100,
    FILE_NO_EA_KNOWLEDGE           = 0x00000200,
    FILE_OPEN_REMOTE_INSTANCE      = 0x00000400,
    FILE_RANDOM_ACCESS             = 0x00000800,
    FILE_DELETE_ON_CLOSE           = 0x00001000,
    FILE_OPEN_BY_FILE_ID           = 0x00002000,
    FILE_OPEN_FOR_BACKUP_INTENT    = 0x00004000,
    FILE_NO_COMPRESSION            = 0x00008000,
    FILE_OPEN_REQUIRING_OPLOCK     = 0x00010000,
    FILE_RESERVE_OPFILTER          = 0x00100000,
    FILE_OPEN_REPARSE_POINT        = 0x00200000,
    FILE_OPEN_NO_RECALL            = 0x00400000,
    FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000
};

// Security Descriptor Controls
enum
{
    SE_OWNER_DEFAULTED       = 0x0001,
    SE_GROUP_DEFAULTED       = 0x0002,
    SE_DACL_PRESENT          = 0x0004,
    SE_DACL_DEFAULTED        = 0x0008,
    SE_SACL_PRESENT          = 0x0010,
    SE_SACL_DEFAULTED        = 0x0020,
    SE_DACL_AUTO_INHERIT_REQ = 0x0100,
    SE_SACL_AUTO_INHERIT_REQ = 0x0200,
    SE_DACL_AUTO_INHERITED   = 0x0400,
    SE_SACL_AUTO_INHERITED   = 0x0800,
    SE_DACL_PROTECTED        = 0x1000,
    SE_SACL_PROTECTED        = 0x2000,
    SE_RM_CONTROL_VALID      = 0x4000,
    SE_SELF_RELATIVE         = 0x8000,
};

extern const flags_str_t generic_ar;

#endif
