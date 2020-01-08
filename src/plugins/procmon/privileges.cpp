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

#include "privileges.h"
#include <stdio.h>

std::string stringify_privilege(struct LUID_AND_ATTRIBUTES& privilege)
{
    std::string attribute;
    switch (privilege.attributes)
    {
        case SE_PRIVILEGE_DISABLED:
            attribute = "SE_PRIVILEGE_DISABLED";
            break;
        case SE_PRIVILEGE_ENABLED_BY_DEFAULT:
            attribute = "SE_PRIVILEGE_ENABLED_BY_DEFAULT";
            break;
        case SE_PRIVILEGE_ENABLED:
            attribute = "SE_PRIVILEGE_ENABLED";
            break;
        case SE_PRIVILEGE_REMOVED:
            attribute = "SE_PRIVILEGE_REMOVED";
            break;
        case SE_PRIVILEGE_USED_FOR_ACCESS:
            attribute = "SE_PRIVILEGE_USED_FOR_ACCESS";
            break;
        default:
        {
            char tmp[32] = {0};
            snprintf(tmp, 32, "0x%" PRIx32, privilege.attributes);
            attribute = tmp;
        }
    }

    switch (privilege.luid)
    {
        case SE_CREATE_TOKEN_PRIVILEGE:
            return std::string("SE_CREATE_TOKEN_PRIVILEGE") + std::string("=") + attribute;
        case SE_ASSIGNPRIMARYTOKEN_PRIVILEGE:
            return std::string("SE_ASSIGNPRIMARYTOKEN_PRIVILEGE") + std::string("=") + attribute;
        case SE_LOCK_MEMORY_PRIVILEGE:
            return std::string("SE_LOCK_MEMORY_PRIVILEGE") + std::string("=") + attribute;
        case SE_INCREASE_QUOTA_PRIVILEGE:
            return std::string("SE_INCREASE_QUOTA_PRIVILEGE") + std::string("=") + attribute;
        case SE_MACHINE_ACCOUNT_PRIVILEGE:
            return std::string("SE_MACHINE_ACCOUNT_PRIVILEGE") + std::string("=") + attribute;
        case SE_TCB_PRIVILEGE:
            return std::string("SE_TCB_PRIVILEGE") + std::string("=") + attribute;
        case SE_SECURITY_PRIVILEGE:
            return std::string("SE_SECURITY_PRIVILEGE") + std::string("=") + attribute;
        case SE_TAKE_OWNERSHIP_PRIVILEGE:
            return std::string("SE_TAKE_OWNERSHIP_PRIVILEGE") + std::string("=") + attribute;
        case SE_LOAD_DRIVER_PRIVILEGE:
            return std::string("SE_LOAD_DRIVER_PRIVILEGE") + std::string("=") + attribute;
        case SE_SYSTEM_PROFILE_PRIVILEGE:
            return std::string("SE_SYSTEM_PROFILE_PRIVILEGE") + std::string("=") + attribute;
        case SE_SYSTEMTIME_PRIVILEGE:
            return std::string("SE_SYSTEMTIME_PRIVILEGE") + std::string("=") + attribute;
        case SE_PROF_SINGLE_PROCESS_PRIVILEGE:
            return std::string("SE_PROF_SINGLE_PROCESS_PRIVILEGE") + std::string("=") + attribute;
        case SE_INC_BASE_PRIORITY_PRIVILEGE:
            return std::string("SE_INC_BASE_PRIORITY_PRIVILEGE") + std::string("=") + attribute;
        case SE_CREATE_PAGEFILE_PRIVILEGE:
            return std::string("SE_CREATE_PAGEFILE_PRIVILEGE") + std::string("=") + attribute;
        case SE_CREATE_PERMANENT_PRIVILEGE:
            return std::string("SE_CREATE_PERMANENT_PRIVILEGE") + std::string("=") + attribute;
        case SE_BACKUP_PRIVILEGE:
            return std::string("SE_BACKUP_PRIVILEGE") + std::string("=") + attribute;
        case SE_RESTORE_PRIVILEGE:
            return std::string("SE_RESTORE_PRIVILEGE") + std::string("=") + attribute;
        case SE_SHUTDOWN_PRIVILEGE:
            return std::string("SE_SHUTDOWN_PRIVILEGE") + std::string("=") + attribute;
        case SE_DEBUG_PRIVILEGE:
            return std::string("SE_DEBUG_PRIVILEGE") + std::string("=") + attribute;
        case SE_AUDIT_PRIVILEGE:
            return std::string("SE_AUDIT_PRIVILEGE") + std::string("=") + attribute;
        case SE_SYSTEM_ENVIRONMENT_PRIVILEGE:
            return std::string("SE_SYSTEM_ENVIRONMENT_PRIVILEGE") + std::string("=") + attribute;
        case SE_CHANGE_NOTIFY_PRIVILEGE:
            return std::string("SE_CHANGE_NOTIFY_PRIVILEGE") + std::string("=") + attribute;
        case SE_REMOTE_SHUTDOWN_PRIVILEGE:
            return std::string("SE_REMOTE_SHUTDOWN_PRIVILEGE") + std::string("=") + attribute;
        case SE_UNDOCK_PRIVILEGE:
            return std::string("SE_UNDOCK_PRIVILEGE") + std::string("=") + attribute;
        case SE_SYNC_AGENT_PRIVILEGE:
            return std::string("SE_SYNC_AGENT_PRIVILEGE") + std::string("=") + attribute;
        case SE_ENABLE_DELEGATION_PRIVILEGE:
            return std::string("SE_ENABLE_DELEGATION_PRIVILEGE") + std::string("=") + attribute;
        case SE_MANAGE_VOLUME_PRIVILEGE:
            return std::string("SE_MANAGE_VOLUME_PRIVILEGE") + std::string("=") + attribute;
        case SE_IMPERSONATE_PRIVILEGE:
            return std::string("SE_IMPERSONATE_PRIVILEGE") + std::string("=") + attribute;
        case SE_CREATE_GLOBAL_PRIVILEGE:
            return std::string("SE_CREATE_GLOBAL_PRIVILEGE") + std::string("=") + attribute;
        case SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE:
            return std::string("SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE") + std::string("=") + attribute;
        case SE_RELABEL_PRIVILEGE:
            return std::string("SE_RELABEL_PRIVILEGE") + std::string("=") + attribute;
        case SE_INC_WORKING_SET_PRIVILEGE:
            return std::string("SE_INC_WORKING_SET_PRIVILEGE") + std::string("=") + attribute;
        case SE_TIME_ZONE_PRIVILEGE:
            return std::string("SE_TIME_ZONE_PRIVILEGE") + std::string("=") + attribute;
        case SE_CREATE_SYMBOLIC_LINK_PRIVILEGE:
            return std::string("SE_CREATE_SYMBOLIC_LINK_PRIVILEGE") + std::string("=") + attribute;
        default:
        {
            char tmp[64] = {0};
            snprintf(tmp, 64, "0x%" PRIx64, privilege.luid);
            return std::string(tmp) + std::string("=") + attribute;
        }
    }
}
