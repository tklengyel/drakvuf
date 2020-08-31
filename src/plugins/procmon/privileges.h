/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2020 Tamas K Lengyel.                                  *
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

#ifndef PRIVILEGE_H
#define PRIVILEGE_H

#include <inttypes.h>
#include <string>

enum privilege_attributes
{
    SE_PRIVILEGE_DISABLED           = 0x00000000L,
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001L,
    SE_PRIVILEGE_ENABLED            = 0x00000002L,
    SE_PRIVILEGE_REMOVED            = 0x00000004L,
    SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000L,
};

enum privileges
{
    SE_CREATE_TOKEN_PRIVILEGE           = 2L,
    SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     = 3L,
    SE_LOCK_MEMORY_PRIVILEGE            = 4L,
    SE_INCREASE_QUOTA_PRIVILEGE         = 5L,
    SE_MACHINE_ACCOUNT_PRIVILEGE        = 6L,
    SE_TCB_PRIVILEGE                    = 7L,
    SE_SECURITY_PRIVILEGE               = 8L,
    SE_TAKE_OWNERSHIP_PRIVILEGE         = 9L,
    SE_LOAD_DRIVER_PRIVILEGE            = 10L,
    SE_SYSTEM_PROFILE_PRIVILEGE         = 11L,
    SE_SYSTEMTIME_PRIVILEGE             = 12L,
    SE_PROF_SINGLE_PROCESS_PRIVILEGE    = 13L,
    SE_INC_BASE_PRIORITY_PRIVILEGE      = 14L,
    SE_CREATE_PAGEFILE_PRIVILEGE        = 15L,
    SE_CREATE_PERMANENT_PRIVILEGE       = 16L,
    SE_BACKUP_PRIVILEGE                 = 17L,
    SE_RESTORE_PRIVILEGE                = 18L,
    SE_SHUTDOWN_PRIVILEGE               = 19L,
    SE_DEBUG_PRIVILEGE                  = 20L,
    SE_AUDIT_PRIVILEGE                  = 21L,
    SE_SYSTEM_ENVIRONMENT_PRIVILEGE     = 22L,
    SE_CHANGE_NOTIFY_PRIVILEGE          = 23L,
    SE_REMOTE_SHUTDOWN_PRIVILEGE        = 24L,
    SE_UNDOCK_PRIVILEGE                 = 25L,
    SE_SYNC_AGENT_PRIVILEGE             = 26L,
    SE_ENABLE_DELEGATION_PRIVILEGE      = 27L,
    SE_MANAGE_VOLUME_PRIVILEGE          = 28L,
    SE_IMPERSONATE_PRIVILEGE            = 29L,
    SE_CREATE_GLOBAL_PRIVILEGE          = 30L,
    SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE = 31L,
    SE_RELABEL_PRIVILEGE                = 32L,
    SE_INC_WORKING_SET_PRIVILEGE        = 33L,
    SE_TIME_ZONE_PRIVILEGE              = 34L,
    SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   = 35L,
};

struct LUID_AND_ATTRIBUTES
{
    uint64_t luid;
    uint32_t attributes;
} __attribute__((packed));

struct TOKEN_PRIVILEGES
{
    uint32_t privilege_count;
    struct LUID_AND_ATTRIBUTES privileges[1];
} __attribute__((packed));

std::pair<std::string, fmt::Aarg> stringify_privilege(struct LUID_AND_ATTRIBUTES& privilege);

#endif
