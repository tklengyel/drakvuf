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

#ifndef SYSCALLS_WIN_H
#define SYSCALLS_WIN_H

void setup_windows(drakvuf_t drakvuf, syscalls *s);

#define NUMBER_SERVICE_TABLES   2
#define NTOS_SERVICE_INDEX      0
#define WIN32K_SERVICE_INDEX    1
#define TABLE_NUMBER_BITS       1
#define TABLE_OFFSET_BITS       12
#define BITS_PER_ENTRY          4
#define SERVICE_TABLE_SHIFT     (12 - BITS_PER_ENTRY)
#define SERVICE_TABLE_MASK      (((1 << TABLE_NUMBER_BITS) - 1) << BITS_PER_ENTRY)
#define SERVICE_TABLE_TEST      (WIN32K_SERVICE_INDEX << BITS_PER_ENTRY)
#define SERVICE_NUMBER_MASK     ((1 << TABLE_OFFSET_BITS) - 1)

#include "private.h"

typedef struct sst_x64 {
    uint64_t ServiceTable;
    uint64_t CounterTable;
    uint64_t ServiceLimit;
    uint64_t ArgumentTable;
} __attribute__((packed)) system_service_table_x64;

typedef struct sst_x86 {
    uint32_t ServiceTable;
    uint32_t CounterTable;
    uint32_t ServiceLimit;
    uint32_t ArgumentTable;
} __attribute__((packed)) system_service_table_x86;

static const syscall_definition_t nt[] =
{
    { .name = "NtFlushProcessWriteBuffers", .ret = VOID, .num_args = 0  },
    { .name = "NtGetCurrentProcessorNumber", .ret = ULONG, .num_args = 0  },
    {
        .name = "NtGetEnvironmentVariableEx", .ret = MISSING, .num_args = 1, .args =
        {
            {.name = "Missing", .dir = DIR_MISSING, .dir_opt = "", .type = MISSING}
        }
    },
    {
        .name = "NtIsSystemResumeAutomatic", .ret = MISSING, .num_args = 1, .args =
        {
            {.name = "Missing", .dir = DIR_MISSING, .dir_opt = "", .type = MISSING}
        }
    },
    {
        .name = "NtQueryEnvironmentVariableInfoEx", .ret = MISSING, .num_args = 1, .args =
        {
            {.name = "Missing", .dir = DIR_MISSING, .dir_opt = "", .type = MISSING}
        }
    },
    {
        .name = "NtAcceptConnectPort", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "PortHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "PortContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ConnectionRequest", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE},
            {.name = "AcceptConnection", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "ServerView", .dir = DIR_INOUT, .dir_opt = "opt", .type = PPORT_VIEW},
            {.name = "ClientView", .dir = DIR_OUT, .dir_opt = "opt", .type = PREMOTE_PORT_VIEW}
        }
    },
    {
        .name = "NtAccessCheckAndAuditAlarm", .ret = NTSTATUS, .num_args = 11, .args =
        {
            {.name = "SubsystemName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "HandleId", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ObjectTypeName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "ObjectName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "SecurityDescriptor", .dir = DIR_IN, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "GenericMapping", .dir = DIR_IN, .dir_opt = "", .type = PGENERIC_MAPPING},
            {.name = "ObjectCreation", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "GrantedAccess", .dir = DIR_OUT, .dir_opt = "", .type = PACCESS_MASK},
            {.name = "AccessStatus", .dir = DIR_OUT, .dir_opt = "", .type = PNTSTATUS},
            {.name = "GenerateOnClose", .dir = DIR_OUT, .dir_opt = "", .type = PBOOLEAN}
        }
    },
    {
        .name = "NtAccessCheckByTypeAndAuditAlarm", .ret = NTSTATUS, .num_args = 16, .args =
        {
            {.name = "SubsystemName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "HandleId", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ObjectTypeName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "ObjectName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "SecurityDescriptor", .dir = DIR_IN, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
            {.name = "PrincipalSelfSid", .dir = DIR_IN, .dir_opt = "opt", .type = PSID},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "AuditType", .dir = DIR_IN, .dir_opt = "", .type = AUDIT_EVENT_TYPE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ObjectTypeList", .dir = DIR_IN, .dir_opt = "ecount_opt(ObjectTypeListLength)", .type = POBJECT_TYPE_LIST},
            {.name = "ObjectTypeListLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "GenericMapping", .dir = DIR_IN, .dir_opt = "", .type = PGENERIC_MAPPING},
            {.name = "ObjectCreation", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "GrantedAccess", .dir = DIR_OUT, .dir_opt = "", .type = PACCESS_MASK},
            {.name = "AccessStatus", .dir = DIR_OUT, .dir_opt = "", .type = PNTSTATUS},
            {.name = "GenerateOnClose", .dir = DIR_OUT, .dir_opt = "", .type = PBOOLEAN}
        }
    },
    {
        .name = "NtAccessCheckByType", .ret = NTSTATUS, .num_args = 11, .args =
        {
            {.name = "SecurityDescriptor", .dir = DIR_IN, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
            {.name = "PrincipalSelfSid", .dir = DIR_IN, .dir_opt = "opt", .type = PSID},
            {.name = "ClientToken", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectTypeList", .dir = DIR_IN, .dir_opt = "ecount(ObjectTypeListLength)", .type = POBJECT_TYPE_LIST},
            {.name = "ObjectTypeListLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "GenericMapping", .dir = DIR_IN, .dir_opt = "", .type = PGENERIC_MAPPING},
            {.name = "PrivilegeSet", .dir = DIR_OUT, .dir_opt = "bcount(*PrivilegeSetLength)", .type = PPRIVILEGE_SET},
            {.name = "PrivilegeSetLength", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG},
            {.name = "GrantedAccess", .dir = DIR_OUT, .dir_opt = "", .type = PACCESS_MASK},
            {.name = "AccessStatus", .dir = DIR_OUT, .dir_opt = "", .type = PNTSTATUS}
        }
    },
    {
        .name = "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", .ret = NTSTATUS, .num_args = 17, .args =
        {
            {.name = "SubsystemName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "HandleId", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ClientToken", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ObjectTypeName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "ObjectName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "SecurityDescriptor", .dir = DIR_IN, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
            {.name = "PrincipalSelfSid", .dir = DIR_IN, .dir_opt = "opt", .type = PSID},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "AuditType", .dir = DIR_IN, .dir_opt = "", .type = AUDIT_EVENT_TYPE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ObjectTypeList", .dir = DIR_IN, .dir_opt = "ecount_opt(ObjectTypeListLength)", .type = POBJECT_TYPE_LIST},
            {.name = "ObjectTypeListLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "GenericMapping", .dir = DIR_IN, .dir_opt = "", .type = PGENERIC_MAPPING},
            {.name = "ObjectCreation", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "GrantedAccess", .dir = DIR_OUT, .dir_opt = "ecount(ObjectTypeListLength)", .type = PACCESS_MASK},
            {.name = "AccessStatus", .dir = DIR_OUT, .dir_opt = "ecount(ObjectTypeListLength)", .type = PNTSTATUS},
            {.name = "GenerateOnClose", .dir = DIR_OUT, .dir_opt = "", .type = PBOOLEAN}
        }
    },
    {
        .name = "NtAccessCheckByTypeResultListAndAuditAlarm", .ret = NTSTATUS, .num_args = 16, .args =
        {
            {.name = "SubsystemName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "HandleId", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ObjectTypeName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "ObjectName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "SecurityDescriptor", .dir = DIR_IN, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
            {.name = "PrincipalSelfSid", .dir = DIR_IN, .dir_opt = "opt", .type = PSID},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "AuditType", .dir = DIR_IN, .dir_opt = "", .type = AUDIT_EVENT_TYPE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ObjectTypeList", .dir = DIR_IN, .dir_opt = "ecount_opt(ObjectTypeListLength)", .type = POBJECT_TYPE_LIST},
            {.name = "ObjectTypeListLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "GenericMapping", .dir = DIR_IN, .dir_opt = "", .type = PGENERIC_MAPPING},
            {.name = "ObjectCreation", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "GrantedAccess", .dir = DIR_OUT, .dir_opt = "ecount(ObjectTypeListLength)", .type = PACCESS_MASK},
            {.name = "AccessStatus", .dir = DIR_OUT, .dir_opt = "ecount(ObjectTypeListLength)", .type = PNTSTATUS},
            {.name = "GenerateOnClose", .dir = DIR_OUT, .dir_opt = "", .type = PBOOLEAN}
        }
    },
    {
        .name = "NtAccessCheckByTypeResultList", .ret = NTSTATUS, .num_args = 11, .args =
        {
            {.name = "SecurityDescriptor", .dir = DIR_IN, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
            {.name = "PrincipalSelfSid", .dir = DIR_IN, .dir_opt = "opt", .type = PSID},
            {.name = "ClientToken", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectTypeList", .dir = DIR_IN, .dir_opt = "ecount(ObjectTypeListLength)", .type = POBJECT_TYPE_LIST},
            {.name = "ObjectTypeListLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "GenericMapping", .dir = DIR_IN, .dir_opt = "", .type = PGENERIC_MAPPING},
            {.name = "PrivilegeSet", .dir = DIR_OUT, .dir_opt = "bcount(*PrivilegeSetLength)", .type = PPRIVILEGE_SET},
            {.name = "PrivilegeSetLength", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG},
            {.name = "GrantedAccess", .dir = DIR_OUT, .dir_opt = "ecount(ObjectTypeListLength)", .type = PACCESS_MASK},
            {.name = "AccessStatus", .dir = DIR_OUT, .dir_opt = "ecount(ObjectTypeListLength)", .type = PNTSTATUS}
        }
    },
    {
        .name = "NtAccessCheck", .ret = NTSTATUS, .num_args = 8, .args =
        {
            {.name = "SecurityDescriptor", .dir = DIR_IN, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
            {.name = "ClientToken", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "GenericMapping", .dir = DIR_IN, .dir_opt = "", .type = PGENERIC_MAPPING},
            {.name = "PrivilegeSet", .dir = DIR_OUT, .dir_opt = "bcount(*PrivilegeSetLength)", .type = PPRIVILEGE_SET},
            {.name = "PrivilegeSetLength", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG},
            {.name = "GrantedAccess", .dir = DIR_OUT, .dir_opt = "", .type = PACCESS_MASK},
            {.name = "AccessStatus", .dir = DIR_OUT, .dir_opt = "", .type = PNTSTATUS}
        }
    },
    {
        .name = "NtAddAtom", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "AtomName", .dir = DIR_IN, .dir_opt = "bcount_opt(Length)", .type = PWSTR},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Atom", .dir = DIR_OUT, .dir_opt = "opt", .type = PRTL_ATOM}
        }
    },
    {
        .name = "NtAddBootEntry", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "BootEntry", .dir = DIR_IN, .dir_opt = "", .type = PBOOT_ENTRY},
            {.name = "Id", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtAddDriverEntry", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "DriverEntry", .dir = DIR_IN, .dir_opt = "", .type = PEFI_DRIVER_ENTRY},
            {.name = "Id", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtAdjustGroupsToken", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "TokenHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ResetToDefault", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "NewState", .dir = DIR_IN, .dir_opt = "", .type = PTOKEN_GROUPS},
            {.name = "BufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "PreviousState", .dir = DIR_OUT, .dir_opt = "bcount_part_opt(BufferLength,*ReturnLength)", .type = PTOKEN_GROUPS},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtAdjustPrivilegesToken", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "TokenHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DisableAllPrivileges", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "NewState", .dir = DIR_IN, .dir_opt = "opt", .type = PTOKEN_PRIVILEGES},
            {.name = "BufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "PreviousState", .dir = DIR_OUT, .dir_opt = "bcount_part_opt(BufferLength,*ReturnLength)", .type = PTOKEN_PRIVILEGES},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtAlertResumeThread", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PreviousSuspendCount", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtAlertThread", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtAllocateLocallyUniqueId", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "Luid", .dir = DIR_OUT, .dir_opt = "", .type = PLUID}
        }
    },
    {
        .name = "NtAllocateReserveObject", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "MemoryReserveHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "Type", .dir = DIR_IN, .dir_opt = "", .type = MEMORY_RESERVE_TYPE}
        }
    },
    {
        .name = "NtAllocateUserPhysicalPages", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "NumberOfPages", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG_PTR},
            {.name = "UserPfnArra;", .dir = DIR_OUT, .dir_opt = "ecount(*NumberOfPages)", .type = PULONG_PTR}
        }
    },
    {
        .name = "NtAllocateUuids", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "Time", .dir = DIR_OUT, .dir_opt = "", .type = PULARGE_INTEGER},
            {.name = "Range", .dir = DIR_OUT, .dir_opt = "", .type = PULONG},
            {.name = "Sequence", .dir = DIR_OUT, .dir_opt = "", .type = PULONG},
            {.name = "Seed", .dir = DIR_OUT, .dir_opt = "", .type = PCHAR}
        }
    },
    {
        .name = "NtAllocateVirtualMemory", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*BaseAddress", .dir = DIR_INOUT, .dir_opt = "", .type = PVOID},
            {.name = "ZeroBits", .dir = DIR_IN, .dir_opt = "", .type = ULONG_PTR},
            {.name = "RegionSize", .dir = DIR_INOUT, .dir_opt = "", .type = PSIZE_T},
            {.name = "AllocationType", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Protect", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtAlpcAcceptConnectPort", .ret = NTSTATUS, .num_args = 9, .args =
        {
            {.name = "PortHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "ConnectionPortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "PortAttributes", .dir = DIR_IN, .dir_opt = "", .type = PALPC_PORT_ATTRIBUTES},
            {.name = "PortContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ConnectionRequest", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE},
            {.name = "ConnectionMessageAttributes", .dir = DIR_INOUT, .dir_opt = "opt", .type = PALPC_MESSAGE_ATTRIBUTES},
            {.name = "AcceptConnection", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtAlpcCancelMessage", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "MessageContext", .dir = DIR_IN, .dir_opt = "", .type = PALPC_CONTEXT_ATTR}
        }
    },
    {
        .name = "NtAlpcConnectPort", .ret = NTSTATUS, .num_args = 11, .args =
        {
            {.name = "PortHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "PortName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "PortAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = PALPC_PORT_ATTRIBUTES},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "RequiredServerSid", .dir = DIR_IN, .dir_opt = "opt", .type = PSID},
            {.name = "ConnectionMessage", .dir = DIR_INOUT, .dir_opt = "", .type = PPORT_MESSAGE},
            {.name = "BufferLength", .dir = DIR_INOUT, .dir_opt = "opt", .type = PULONG},
            {.name = "OutMessageAttributes", .dir = DIR_INOUT, .dir_opt = "opt", .type = PALPC_MESSAGE_ATTRIBUTES},
            {.name = "InMessageAttributes", .dir = DIR_INOUT, .dir_opt = "opt", .type = PALPC_MESSAGE_ATTRIBUTES},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtAlpcCreatePort", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PortHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "PortAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = PALPC_PORT_ATTRIBUTES}
        }
    },
    {
        .name = "NtAlpcCreatePortSection", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "SectionHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "SectionSize", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "AlpcSectionHandle", .dir = DIR_OUT, .dir_opt = "", .type = PALPC_HANDLE},
            {.name = "ActualSectionSize", .dir = DIR_OUT, .dir_opt = "", .type = PSIZE_T}
        }
    },
    {
        .name = "NtAlpcCreateResourceReserve", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "MessageSize", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "ResourceId", .dir = DIR_OUT, .dir_opt = "", .type = PALPC_HANDLE}
        }
    },
    {
        .name = "NtAlpcCreateSectionView", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "ViewAttributes", .dir = DIR_INOUT, .dir_opt = "", .type = PALPC_DATA_VIEW_ATTR}
        }
    },
    {
        .name = "NtAlpcCreateSecurityContext", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "SecurityAttribute", .dir = DIR_INOUT, .dir_opt = "", .type = PALPC_SECURITY_ATTR}
        }
    },
    {
        .name = "NtAlpcDeletePortSection", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "SectionHandle", .dir = DIR_IN, .dir_opt = "", .type = ALPC_HANDLE}
        }
    },
    {
        .name = "NtAlpcDeleteResourceReserve", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "ResourceId", .dir = DIR_IN, .dir_opt = "", .type = ALPC_HANDLE}
        }
    },
    {
        .name = "NtAlpcDeleteSectionView", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "ViewBase", .dir = DIR_IN, .dir_opt = "", .type = PVOID}
        }
    },
    {
        .name = "NtAlpcDeleteSecurityContext", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "ContextHandle", .dir = DIR_IN, .dir_opt = "", .type = ALPC_HANDLE}
        }
    },
    {
        .name = "NtAlpcDisconnectPort", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtAlpcImpersonateClientOfPort", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PortMessage", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE},
            {.name = "Reserved", .dir = DIR_RESERVED, .dir_opt = "", .type = PVOID}
        }
    },
    {
        .name = "NtAlpcOpenSenderProcess", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PortMessage", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE},
            {.name = "Flags", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtAlpcOpenSenderThread", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PortMessage", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE},
            {.name = "Flags", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtAlpcQueryInformation", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PortInformationClass", .dir = DIR_IN, .dir_opt = "", .type = ALPC_PORT_INFORMATION_CLASS},
            {.name = "PortInformation", .dir = DIR_OUT, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtAlpcQueryInformationMessage", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PortMessage", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE},
            {.name = "MessageInformationClass", .dir = DIR_IN, .dir_opt = "", .type = ALPC_MESSAGE_INFORMATION_CLASS},
            {.name = "MessageInformation", .dir = DIR_OUT, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtAlpcRevokeSecurityContext", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "ContextHandle", .dir = DIR_IN, .dir_opt = "", .type = ALPC_HANDLE}
        }
    },
    {
        .name = "NtAlpcSendWaitReceivePort", .ret = NTSTATUS, .num_args = 8, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "SendMessage", .dir = DIR_IN, .dir_opt = "opt", .type = PPORT_MESSAGE},
            {.name = "SendMessageAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = PALPC_MESSAGE_ATTRIBUTES},
            {.name = "ReceiveMessage", .dir = DIR_INOUT, .dir_opt = "opt", .type = PPORT_MESSAGE},
            {.name = "BufferLength", .dir = DIR_INOUT, .dir_opt = "opt", .type = PULONG},
            {.name = "ReceiveMessageAttributes", .dir = DIR_INOUT, .dir_opt = "opt", .type = PALPC_MESSAGE_ATTRIBUTES},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtAlpcSetInformation", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PortInformationClass", .dir = DIR_IN, .dir_opt = "", .type = ALPC_PORT_INFORMATION_CLASS},
            {.name = "PortInformation", .dir = DIR_IN, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtApphelpCacheControl", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "type", .dir = DIR_IN, .dir_opt = "", .type = APPHELPCOMMAND},
            {.name = "buf", .dir = DIR_IN, .dir_opt = "", .type = PVOID}
        }
    },
    {
        .name = "NtAreMappedFilesTheSame", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "File1MappedAsAnImage", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "File2MappedAsFile", .dir = DIR_IN, .dir_opt = "", .type = PVOID}
        }
    },
    {
        .name = "NtAssignProcessToJobObject", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "JobHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtCallbackReturn", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "OutputBuffer", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "OutputLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Status", .dir = DIR_IN, .dir_opt = "", .type = NTSTATUS}
        }
    },
    {
        .name = "NtCancelIoFileEx", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoRequestToCancel", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_STATUS_BLOCK},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK}
        }
    },
    {
        .name = "NtCancelIoFile", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK}
        }
    },
    {
        .name = "NtCancelSynchronousIoFile", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoRequestToCancel", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_STATUS_BLOCK},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK}
        }
    },
    {
        .name = "NtCancelTimer", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "TimerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "CurrentState", .dir = DIR_OUT, .dir_opt = "opt", .type = PBOOLEAN}
        }
    },
    {
        .name = "NtClearEvent", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "EventHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtClose", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "Handle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtCloseObjectAuditAlarm", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "SubsystemName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "HandleId", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "GenerateOnClose", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtCommitComplete", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TmVirtualClock", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtCommitEnlistment", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TmVirtualClock", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtCommitTransaction", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "TransactionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Wait", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtCompactKeys", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "Count", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "KeyArray[;", .dir = DIR_IN, .dir_opt = "ecount(Count)", .type = HANDLE}
        }
    },
    {
        .name = "NtCompareTokens", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "FirstTokenHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "SecondTokenHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Equal", .dir = DIR_OUT, .dir_opt = "", .type = PBOOLEAN}
        }
    },
    {
        .name = "NtCompleteConnectPort", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtCompressKey", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "Key", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtConnectPort", .ret = NTSTATUS, .num_args = 8, .args =
        {
            {.name = "PortHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "PortName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "SecurityQos", .dir = DIR_IN, .dir_opt = "", .type = PSECURITY_QUALITY_OF_SERVICE},
            {.name = "ClientView", .dir = DIR_INOUT, .dir_opt = "opt", .type = PPORT_VIEW},
            {.name = "ServerView", .dir = DIR_INOUT, .dir_opt = "opt", .type = PREMOTE_PORT_VIEW},
            {.name = "MaxMessageLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG},
            {.name = "ConnectionInformation", .dir = DIR_INOUT, .dir_opt = "opt", .type = PVOID},
            {.name = "ConnectionInformationLength", .dir = DIR_INOUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtContinue", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ContextRecord", .dir = DIR_IN, .dir_opt = "", .type = PCONTEXT},
            {.name = "TestAlert", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtCreateDebugObject", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "DebugObjectHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_OUT, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_OUT, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "Flags", .dir = DIR_OUT, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtCreateDirectoryObject", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "DirectoryHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtCreateEnlistment", .ret = NTSTATUS, .num_args = 8, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ResourceManagerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TransactionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "CreateOptions", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG},
            {.name = "NotificationMask", .dir = DIR_IN, .dir_opt = "", .type = NOTIFICATION_MASK},
            {.name = "EnlistmentKey", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID}
        }
    },
    {
        .name = "NtCreateEvent", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "EventHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "EventType", .dir = DIR_IN, .dir_opt = "", .type = EVENT_TYPE},
            {.name = "InitialState", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtCreateEventPair", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "EventPairHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtCreateFile", .ret = NTSTATUS, .num_args = 11, .args =
        {
            {.name = "FileHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "AllocationSize", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER},
            {.name = "FileAttributes", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ShareAccess", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "CreateDisposition", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "CreateOptions", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "EaBuffer", .dir = DIR_IN, .dir_opt = "bcount_opt(EaLength)", .type = PVOID},
            {.name = "EaLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtCreateIoCompletion", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "IoCompletionHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "Count", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtCreateJobObject", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "JobHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtCreateJobSet", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "NumJob", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "UserJobSet", .dir = DIR_IN, .dir_opt = "ecount(NumJob)", .type = PJOB_SET_ARRAY},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtCreateKeyedEvent", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "KeyedEventHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtCreateKey", .ret = NTSTATUS, .num_args = 7, .args =
        {
            {.name = "KeyHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "TitleIndex", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "Class", .dir = DIR_IN, .dir_opt = "opt", .type = PUNICODE_STRING},
            {.name = "CreateOptions", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Disposition", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtCreateKeyTransacted", .ret = NTSTATUS, .num_args = 8, .args =
        {
            {.name = "KeyHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "TitleIndex", .dir = DIR_RESERVED, .dir_opt = "", .type = ULONG},
            {.name = "Class", .dir = DIR_IN, .dir_opt = "opt", .type = PUNICODE_STRING},
            {.name = "CreateOptions", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "TransactionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Disposition", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtCreateMailslotFile", .ret = NTSTATUS, .num_args = 8, .args =
        {
            {.name = "FileHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "CreateOptions", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "MailslotQuota", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "MaximumMessageSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReadTimeout", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtCreateMutant", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "MutantHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "InitialOwner", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtCreateNamedPipeFile", .ret = NTSTATUS, .num_args = 14, .args =
        {
            {.name = "FileHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "ShareAccess", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "CreateDisposition", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "CreateOptions", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "NamedPipeType", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReadMode", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "CompletionMode", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "MaximumInstances", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "InboundQuota", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "OutboundQuota", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "DefaultTimeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtCreatePagingFile", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "PageFileName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "MinimumSize", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER},
            {.name = "MaximumSize", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER},
            {.name = "Priority", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtCreatePort", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "PortHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "MaxConnectionInfoLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "MaxMessageLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "MaxPoolUsage", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG}
        }
    },
    {
        .name = "NtCreatePrivateNamespace", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "NamespaceHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "BoundaryDescriptor", .dir = DIR_IN, .dir_opt = "", .type = PVOID}
        }
    },
    {
        .name = "NtCreateProcessEx", .ret = NTSTATUS, .num_args = 9, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "ParentProcess", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "SectionHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "DebugPort", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ExceptionPort", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "JobMemberLevel", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtCreateProcess", .ret = NTSTATUS, .num_args = 8, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "ParentProcess", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "InheritObjectTable", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "SectionHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "DebugPort", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ExceptionPort", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE}
        }
    },
    {
        .name = "NtCreateProfileEx", .ret = NTSTATUS, .num_args = 10, .args =
        {
            {.name = "ProfileHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "Process", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ProfileBase", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "ProfileSize", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "BucketSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Buffer", .dir = DIR_IN, .dir_opt = "", .type = PULONG},
            {.name = "BufferSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ProfileSource", .dir = DIR_IN, .dir_opt = "", .type = KPROFILE_SOURCE},
            {.name = "GroupAffinityCount", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "GroupAffinity", .dir = DIR_IN, .dir_opt = "opt", .type = PGROUP_AFFINITY}
        }
    },
    {
        .name = "NtCreateProfile", .ret = NTSTATUS, .num_args = 9, .args =
        {
            {.name = "ProfileHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "Process", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "RangeBase", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "RangeSize", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "BucketSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Buffer", .dir = DIR_IN, .dir_opt = "", .type = PULONG},
            {.name = "BufferSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ProfileSource", .dir = DIR_IN, .dir_opt = "", .type = KPROFILE_SOURCE},
            {.name = "Affinity", .dir = DIR_IN, .dir_opt = "", .type = KAFFINITY}
        }
    },
    {
        .name = "NtCreateResourceManager", .ret = NTSTATUS, .num_args = 7, .args =
        {
            {.name = "ResourceManagerHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "TmHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "RmGuid", .dir = DIR_IN, .dir_opt = "", .type = LPGUID},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "CreateOptions", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG},
            {.name = "Description", .dir = DIR_IN, .dir_opt = "opt", .type = PUNICODE_STRING}
        }
    },
    {
        .name = "NtCreateSection", .ret = NTSTATUS, .num_args = 7, .args =
        {
            {.name = "SectionHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "MaximumSize", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER},
            {.name = "SectionPageProtection", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "AllocationAttributes", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE}
        }
    },
    {
        .name = "NtCreateSemaphore", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "SemaphoreHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "InitialCount", .dir = DIR_IN, .dir_opt = "", .type = LONG},
            {.name = "MaximumCount", .dir = DIR_IN, .dir_opt = "", .type = LONG}
        }
    },
    {
        .name = "NtCreateSymbolicLinkObject", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "LinkHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "LinkTarget", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING}
        }
    },
    {
        .name = "NtCreateThreadEx", .ret = NTSTATUS, .num_args = 11, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "StartRoutine", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "Argument", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "CreateFlags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ZeroBits", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG_PTR},
            {.name = "StackSize", .dir = DIR_IN, .dir_opt = "opt", .type = SIZE_T},
            {.name = "MaximumStackSize", .dir = DIR_IN, .dir_opt = "opt", .type = SIZE_T},
            {.name = "AttributeList", .dir = DIR_IN, .dir_opt = "opt", .type = PPS_ATTRIBUTE_LIST}
        }
    },
    {
        .name = "NtCreateThread", .ret = NTSTATUS, .num_args = 8, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ClientId", .dir = DIR_OUT, .dir_opt = "", .type = PCLIENT_ID},
            {.name = "ThreadContext", .dir = DIR_IN, .dir_opt = "", .type = PCONTEXT},
            {.name = "InitialTeb", .dir = DIR_IN, .dir_opt = "", .type = PINITIAL_TEB},
            {.name = "CreateSuspended", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtCreateTimer", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "TimerHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "TimerType", .dir = DIR_IN, .dir_opt = "", .type = TIMER_TYPE}
        }
    },
    {
        .name = "NtCreateToken", .ret = NTSTATUS, .num_args = 13, .args =
        {
            {.name = "TokenHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "TokenType", .dir = DIR_IN, .dir_opt = "", .type = TOKEN_TYPE},
            {.name = "AuthenticationId", .dir = DIR_IN, .dir_opt = "", .type = PLUID},
            {.name = "ExpirationTime", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER},
            {.name = "User", .dir = DIR_IN, .dir_opt = "", .type = PTOKEN_USER},
            {.name = "Groups", .dir = DIR_IN, .dir_opt = "", .type = PTOKEN_GROUPS},
            {.name = "Privileges", .dir = DIR_IN, .dir_opt = "", .type = PTOKEN_PRIVILEGES},
            {.name = "Owner", .dir = DIR_IN, .dir_opt = "opt", .type = PTOKEN_OWNER},
            {.name = "PrimaryGroup", .dir = DIR_IN, .dir_opt = "", .type = PTOKEN_PRIMARY_GROUP},
            {.name = "DefaultDacl", .dir = DIR_IN, .dir_opt = "opt", .type = PTOKEN_DEFAULT_DACL},
            {.name = "TokenSource", .dir = DIR_IN, .dir_opt = "", .type = PTOKEN_SOURCE}
        }
    },
    {
        .name = "NtCreateTransactionManager", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "TmHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "LogFileName", .dir = DIR_IN, .dir_opt = "opt", .type = PUNICODE_STRING},
            {.name = "CreateOptions", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG},
            {.name = "CommitStrength", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG}
        }
    },
    {
        .name = "NtCreateTransaction", .ret = NTSTATUS, .num_args = 10, .args =
        {
            {.name = "TransactionHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "Uow", .dir = DIR_IN, .dir_opt = "opt", .type = LPGUID},
            {.name = "TmHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "CreateOptions", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG},
            {.name = "IsolationLevel", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG},
            {.name = "IsolationFlags", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER},
            {.name = "Description", .dir = DIR_IN, .dir_opt = "opt", .type = PUNICODE_STRING}
        }
    },
    {
        .name = "NtCreateUserProcess", .ret = NTSTATUS, .num_args = 11, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "ThreadHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "ProcessDesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ThreadDesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ProcessObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "ThreadObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "ProcessFlags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ThreadFlags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ProcessParameters", .dir = DIR_IN, .dir_opt = "opt", .type = PRTL_USER_PROCESS_PARAMETERS},
            {.name = "CreateInfo", .dir = DIR_IN, .dir_opt = "opt", .type = PPROCESS_CREATE_INFO},
            {.name = "AttributeList", .dir = DIR_IN, .dir_opt = "opt", .type = PPROCESS_ATTRIBUTE_LIST}
        }
    },
    {
        .name = "NtCreateWaitablePort", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "PortHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "MaxConnectionInfoLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "MaxMessageLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "MaxPoolUsage", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG}
        }
    },
    {
        .name = "NtCreateWorkerFactory", .ret = NTSTATUS, .num_args = 10, .args =
        {
            {.name = "WorkerFactoryHandleReturn", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "CompletionPortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "WorkerProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "StartRoutine", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "StartParameter", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "MaxThreadCount", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG},
            {.name = "StackReserve", .dir = DIR_IN, .dir_opt = "opt", .type = SIZE_T},
            {.name = "StackCommit", .dir = DIR_IN, .dir_opt = "opt", .type = SIZE_T}
        }
    },
    {
        .name = "NtDebugActiveProcess", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_OUT, .dir_opt = "", .type = HANDLE},
            {.name = "DebugObjectHandle", .dir = DIR_OUT, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtDebugContinue", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "DebugObjectHandle", .dir = DIR_OUT, .dir_opt = "", .type = HANDLE},
            {.name = "ClientId", .dir = DIR_OUT, .dir_opt = "", .type = PCLIENT_ID},
            {.name = "ContinueStatus", .dir = DIR_OUT, .dir_opt = "", .type = NTSTATUS}
        }
    },
    {
        .name = "NtDelayExecution", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "Alertable", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "DelayInterval", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtDeleteAtom", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "Atom", .dir = DIR_IN, .dir_opt = "", .type = RTL_ATOM}
        }
    },
    {
        .name = "NtDeleteBootEntry", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "Id", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtDeleteDriverEntry", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "Id", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtDeleteFile", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtDeleteKey", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtDeleteObjectAuditAlarm", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "SubsystemName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "HandleId", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "GenerateOnClose", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtDeletePrivateNamespace", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "NamespaceHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtDeleteValueKey", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ValueName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING}
        }
    },
    {
        .name = "NtDeviceIoControlFile", .ret = NTSTATUS, .num_args = 10, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "IoControlCode", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "InputBuffer", .dir = DIR_IN, .dir_opt = "bcount_opt(InputBufferLength)", .type = PVOID},
            {.name = "InputBufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "OutputBuffer", .dir = DIR_OUT, .dir_opt = "bcount_opt(OutputBufferLength)", .type = PVOID},
            {.name = "OutputBufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    { .name = "NtDisableLastKnownGood", .ret = NTSTATUS, .num_args = 0  },
    {
        .name = "NtDisplayString", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "String", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING}
        }
    },
    {
        .name = "NtDrawText", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "Text", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING}
        }
    },
    {
        .name = "NtDuplicateObject", .ret = NTSTATUS, .num_args = 7, .args =
        {
            {.name = "SourceProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "SourceHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TargetProcessHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "TargetHandle", .dir = DIR_OUT, .dir_opt = "opt", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "HandleAttributes", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Options", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtDuplicateToken", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "ExistingTokenHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "EffectiveOnly", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "TokenType", .dir = DIR_IN, .dir_opt = "", .type = TOKEN_TYPE},
            {.name = "NewTokenHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE}
        }
    },
    { .name = "NtEnableLastKnownGood", .ret = NTSTATUS, .num_args = 0  },
    {
        .name = "NtEnumerateBootEntries", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount_opt(*BufferLength)", .type = PVOID},
            {.name = "BufferLength", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtEnumerateDriverEntries", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount(*BufferLength)", .type = PVOID},
            {.name = "BufferLength", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtEnumerateKey", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Index", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "KeyInformationClass", .dir = DIR_IN, .dir_opt = "", .type = KEY_INFORMATION_CLASS},
            {.name = "KeyInformation", .dir = DIR_OUT, .dir_opt = "bcount_opt(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ResultLength", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtEnumerateSystemEnvironmentValuesEx", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "InformationClass", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "", .type = PVOID},
            {.name = "BufferLength", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtEnumerateTransactionObject", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "RootObjectHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "QueryType", .dir = DIR_IN, .dir_opt = "", .type = KTMOBJECT_TYPE},
            {.name = "ObjectCursor", .dir = DIR_INOUT, .dir_opt = "bcount(ObjectCursorLength)", .type = PKTMOBJECT_CURSOR},
            {.name = "ObjectCursorLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtEnumerateValueKey", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Index", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "KeyValueInformationClass", .dir = DIR_IN, .dir_opt = "", .type = KEY_VALUE_INFORMATION_CLASS},
            {.name = "KeyValueInformation", .dir = DIR_OUT, .dir_opt = "bcount_opt(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ResultLength", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtExtendSection", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "SectionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "NewSectionSize", .dir = DIR_INOUT, .dir_opt = "", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtFilterToken", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "ExistingTokenHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "SidsToDisable", .dir = DIR_IN, .dir_opt = "opt", .type = PTOKEN_GROUPS},
            {.name = "PrivilegesToDelete", .dir = DIR_IN, .dir_opt = "opt", .type = PTOKEN_PRIVILEGES},
            {.name = "RestrictedSids", .dir = DIR_IN, .dir_opt = "opt", .type = PTOKEN_GROUPS},
            {.name = "NewTokenHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE}
        }
    },
    {
        .name = "NtFindAtom", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "AtomName", .dir = DIR_IN, .dir_opt = "bcount_opt(Length)", .type = PWSTR},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Atom", .dir = DIR_OUT, .dir_opt = "opt", .type = PRTL_ATOM}
        }
    },
    {
        .name = "NtFlushBuffersFile", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK}
        }
    },
    {
        .name = "NtFlushInstallUILanguage", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "InstallUILanguage", .dir = DIR_IN, .dir_opt = "", .type = LANGID},
            {.name = "SetComittedFlag", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtFlushInstructionCache", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "BaseAddress", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T}
        }
    },
    {
        .name = "NtFlushKey", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    { .name = "NtFlushProcessWriteBuffers", .ret = VOID, .num_args = 0  },
    {
        .name = "NtFlushVirtualMemory", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*BaseAddress", .dir = DIR_INOUT, .dir_opt = "", .type = PVOID},
            {.name = "RegionSize", .dir = DIR_INOUT, .dir_opt = "", .type = PSIZE_T},
            {.name = "IoStatus", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK}
        }
    },
    { .name = "NtFlushWriteBuffer", .ret = NTSTATUS, .num_args = 0  },
    {
        .name = "NtFreeUserPhysicalPages", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "NumberOfPages", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG_PTR},
            {.name = "UserPfnArra;", .dir = DIR_IN, .dir_opt = "ecount(*NumberOfPages)", .type = PULONG_PTR}
        }
    },
    {
        .name = "NtFreeVirtualMemory", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*BaseAddress", .dir = DIR_INOUT, .dir_opt = "", .type = PVOID},
            {.name = "RegionSize", .dir = DIR_INOUT, .dir_opt = "", .type = PSIZE_T},
            {.name = "FreeType", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtFreezeRegistry", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "TimeOutInSeconds", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtFreezeTransactions", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "FreezeTimeout", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER},
            {.name = "ThawTimeout", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtFsControlFile", .ret = NTSTATUS, .num_args = 10, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "IoControlCode", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "InputBuffer", .dir = DIR_IN, .dir_opt = "bcount_opt(InputBufferLength)", .type = PVOID},
            {.name = "InputBufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "OutputBuffer", .dir = DIR_OUT, .dir_opt = "bcount_opt(OutputBufferLength)", .type = PVOID},
            {.name = "OutputBufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtGetContextThread", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ThreadContext", .dir = DIR_INOUT, .dir_opt = "", .type = PCONTEXT}
        }
    },
    { .name = "NtGetCurrentProcessorNumber", .ret = ULONG, .num_args = 0  },
    {
        .name = "NtGetDevicePowerState", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "Device", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*State", .dir = DIR_OUT, .dir_opt = "", .type = DEVICE_POWER_STATE}
        }
    },
    {
        .name = "NtGetMUIRegistryInfo", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "DataSize", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG},
            {.name = "Data", .dir = DIR_OUT, .dir_opt = "", .type = PVOID}
        }
    },
    {
        .name = "NtGetNextProcess", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "HandleAttributes", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "NewProcessHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE}
        }
    },
    {
        .name = "NtGetNextThread", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "HandleAttributes", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "NewThreadHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE}
        }
    },
    {
        .name = "NtGetNlsSectionPtr", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "SectionType", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "SectionData", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ContextData", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "*SectionPointer", .dir = DIR_OUT, .dir_opt = "", .type = PVOID},
            {.name = "SectionSize", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtGetNotificationResourceManager", .ret = NTSTATUS, .num_args = 7, .args =
        {
            {.name = "ResourceManagerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TransactionNotification", .dir = DIR_OUT, .dir_opt = "", .type = PTRANSACTION_NOTIFICATION},
            {.name = "NotificationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG},
            {.name = "Asynchronous", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "AsynchronousContext", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG_PTR}
        }
    },
    {
        .name = "NtGetPlugPlayEvent", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "EventHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Context", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "EventBlock", .dir = DIR_OUT, .dir_opt = "bcount(EventBufferSize)", .type = PPLUGPLAY_EVENT_BLOCK},
            {.name = "EventBufferSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtGetWriteWatch", .ret = NTSTATUS, .num_args = 7, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "BaseAddress", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "RegionSize", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "*UserAddressArray", .dir = DIR_OUT, .dir_opt = "ecount(*EntriesInUserAddressArray)", .type = PVOID},
            {.name = "EntriesInUserAddressArray", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG_PTR},
            {.name = "Granularity", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtImpersonateAnonymousToken", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtImpersonateClientOfPort", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Message", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE}
        }
    },
    {
        .name = "NtImpersonateThread", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "ServerThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ClientThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "SecurityQos", .dir = DIR_IN, .dir_opt = "", .type = PSECURITY_QUALITY_OF_SERVICE}
        }
    },
    {
        .name = "NtInitializeNlsFiles", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "*BaseAddress", .dir = DIR_OUT, .dir_opt = "", .type = PVOID},
            {.name = "DefaultLocaleId", .dir = DIR_OUT, .dir_opt = "", .type = PLCID},
            {.name = "DefaultCasingTableSize", .dir = DIR_OUT, .dir_opt = "", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtInitializeRegistry", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "BootCondition", .dir = DIR_IN, .dir_opt = "", .type = USHORT}
        }
    },
    {
        .name = "NtInitiatePowerAction", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "SystemAction", .dir = DIR_IN, .dir_opt = "", .type = POWER_ACTION},
            {.name = "MinSystemState", .dir = DIR_IN, .dir_opt = "", .type = SYSTEM_POWER_STATE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Asynchronous", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtIsProcessInJob", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "JobHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE}
        }
    },
    { .name = "NtIsSystemResumeAutomatic", .ret = BOOLEAN, .num_args = 0  },
    { .name = "NtIsUILanguageComitted", .ret = NTSTATUS, .num_args = 0  },
    {
        .name = "NtListenPort", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ConnectionRequest", .dir = DIR_OUT, .dir_opt = "", .type = PPORT_MESSAGE}
        }
    },
    {
        .name = "NtLoadDriver", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "DriverServiceName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING}
        }
    },
    {
        .name = "NtLoadKey2", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "TargetKey", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "SourceFile", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtLoadKeyEx", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "TargetKey", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "SourceFile", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "TrustClassKey", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE}
        }
    },
    {
        .name = "NtLoadKey", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "TargetKey", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "SourceFile", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtLockFile", .ret = NTSTATUS, .num_args = 10, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "ByteOffset", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER},
            {.name = "Key", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "FailImmediately", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "ExclusiveLock", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtLockProductActivationKeys", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "*pPrivateVer", .dir = DIR_INOUT, .dir_opt = "opt", .type = ULONG},
            {.name = "*pSafeMode", .dir = DIR_OUT, .dir_opt = "opt", .type = ULONG}
        }
    },
    {
        .name = "NtLockRegistryKey", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtLockVirtualMemory", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*BaseAddress", .dir = DIR_INOUT, .dir_opt = "", .type = PVOID},
            {.name = "RegionSize", .dir = DIR_INOUT, .dir_opt = "", .type = PSIZE_T},
            {.name = "MapType", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtMakePermanentObject", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "Handle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtMakeTemporaryObject", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "Handle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtMapCMFModule", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "What", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Index", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "CacheIndexOut", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG},
            {.name = "CacheFlagsOut", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG},
            {.name = "ViewSizeOut", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG},
            {.name = "*BaseAddress", .dir = DIR_OUT, .dir_opt = "opt", .type = PVOID}
        }
    },
    {
        .name = "NtMapUserPhysicalPages", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "VirtualAddress", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "NumberOfPages", .dir = DIR_IN, .dir_opt = "", .type = ULONG_PTR},
            {.name = "UserPfnArra;", .dir = DIR_IN, .dir_opt = "ecount_opt(NumberOfPages)", .type = PULONG_PTR}
        }
    },
    {
        .name = "NtMapUserPhysicalPagesScatter", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "*VirtualAddresses", .dir = DIR_IN, .dir_opt = "ecount(NumberOfPages)", .type = PVOID},
            {.name = "NumberOfPages", .dir = DIR_IN, .dir_opt = "", .type = ULONG_PTR},
            {.name = "UserPfnArray", .dir = DIR_IN, .dir_opt = "ecount_opt(NumberOfPages)", .type = PULONG_PTR}
        }
    },
    {
        .name = "NtMapViewOfSection", .ret = NTSTATUS, .num_args = 10, .args =
        {
            {.name = "SectionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*BaseAddress", .dir = DIR_INOUT, .dir_opt = "", .type = PVOID},
            {.name = "ZeroBits", .dir = DIR_IN, .dir_opt = "", .type = ULONG_PTR},
            {.name = "CommitSize", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "SectionOffset", .dir = DIR_INOUT, .dir_opt = "opt", .type = PLARGE_INTEGER},
            {.name = "ViewSize", .dir = DIR_INOUT, .dir_opt = "", .type = PSIZE_T},
            {.name = "InheritDisposition", .dir = DIR_IN, .dir_opt = "", .type = SECTION_INHERIT},
            {.name = "AllocationType", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Win32Protect", .dir = DIR_IN, .dir_opt = "", .type = WIN32_PROTECTION_MASK}
        }
    },
    {
        .name = "NtModifyBootEntry", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "BootEntry", .dir = DIR_IN, .dir_opt = "", .type = PBOOT_ENTRY}
        }
    },
    {
        .name = "NtModifyDriverEntry", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "DriverEntry", .dir = DIR_IN, .dir_opt = "", .type = PEFI_DRIVER_ENTRY}
        }
    },
    {
        .name = "NtNotifyChangeDirectoryFile", .ret = NTSTATUS, .num_args = 9, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "CompletionFilter", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "WatchTree", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtNotifyChangeKey", .ret = NTSTATUS, .num_args = 10, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "CompletionFilter", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "WatchTree", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount_opt(BufferSize)", .type = PVOID},
            {.name = "BufferSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Asynchronous", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtNotifyChangeMultipleKeys", .ret = NTSTATUS, .num_args = 12, .args =
        {
            {.name = "MasterKeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Count", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG},
            {.name = "SlaveObjects[]", .dir = DIR_IN, .dir_opt = "ecount_opt(Count)", .type = OBJECT_ATTRIBUTES},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "CompletionFilter", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "WatchTree", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount_opt(BufferSize)", .type = PVOID},
            {.name = "BufferSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Asynchronous", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtNotifyChangeSession", .ret = NTSTATUS, .num_args = 8, .args =
        {
            {.name = "Session", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStateSequence", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Reserved", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "Action", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "IoState", .dir = DIR_IN, .dir_opt = "", .type = IO_SESSION_STATE},
            {.name = "IoState2", .dir = DIR_IN, .dir_opt = "", .type = IO_SESSION_STATE},
            {.name = "Buffer", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "BufferSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtOpenDirectoryObject", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "DirectoryHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenEnlistment", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ResourceManagerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "EnlistmentGuid", .dir = DIR_IN, .dir_opt = "", .type = LPGUID},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenEvent", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "EventHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenEventPair", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "EventPairHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenFile", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "FileHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "ShareAccess", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "OpenOptions", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtOpenIoCompletion", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "IoCompletionHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenJobObject", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "JobHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenKeyedEvent", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "KeyedEventHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenKeyEx", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "KeyHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "OpenOptions", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtOpenKey", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "KeyHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenKeyTransactedEx", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "KeyHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "OpenOptions", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "TransactionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtOpenKeyTransacted", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "KeyHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "TransactionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtOpenMutant", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "MutantHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenObjectAuditAlarm", .ret = NTSTATUS, .num_args = 12, .args =
        {
            {.name = "SubsystemName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "HandleId", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ObjectTypeName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "ObjectName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "SecurityDescriptor", .dir = DIR_IN, .dir_opt = "opt", .type = PSECURITY_DESCRIPTOR},
            {.name = "ClientToken", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "GrantedAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "Privileges", .dir = DIR_IN, .dir_opt = "opt", .type = PPRIVILEGE_SET},
            {.name = "ObjectCreation", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "AccessGranted", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "GenerateOnClose", .dir = DIR_OUT, .dir_opt = "", .type = PBOOLEAN}
        }
    },
    {
        .name = "NtOpenPrivateNamespace", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "NamespaceHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "BoundaryDescriptor", .dir = DIR_IN, .dir_opt = "", .type = PVOID}
        }
    },
    {
        .name = "NtOpenProcess", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "ClientId", .dir = DIR_IN, .dir_opt = "opt", .type = PCLIENT_ID}
        }
    },
    {
        .name = "NtOpenProcessTokenEx", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "HandleAttributes", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "TokenHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE}
        }
    },
    {
        .name = "NtOpenProcessToken", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "TokenHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE}
        }
    },
    {
        .name = "NtOpenResourceManager", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "ResourceManagerHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "TmHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ResourceManagerGuid", .dir = DIR_IN, .dir_opt = "opt", .type = LPGUID},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenSection", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "SectionHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenSemaphore", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "SemaphoreHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenSession", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "SessionHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenSymbolicLinkObject", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "LinkHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenThread", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "ClientId", .dir = DIR_IN, .dir_opt = "opt", .type = PCLIENT_ID}
        }
    },
    {
        .name = "NtOpenThreadTokenEx", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "OpenAsSelf", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "HandleAttributes", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "TokenHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE}
        }
    },
    {
        .name = "NtOpenThreadToken", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "OpenAsSelf", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "TokenHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE}
        }
    },
    {
        .name = "NtOpenTimer", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "TimerHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtOpenTransactionManager", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "TmHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
            {.name = "LogFileName", .dir = DIR_IN, .dir_opt = "opt", .type = PUNICODE_STRING},
            {.name = "TmIdentity", .dir = DIR_IN, .dir_opt = "opt", .type = LPGUID},
            {.name = "OpenOptions", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG}
        }
    },
    {
        .name = "NtOpenTransaction", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "TransactionHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "Uow", .dir = DIR_IN, .dir_opt = "", .type = LPGUID},
            {.name = "TmHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE}
        }
    },
    {
        .name = "NtPlugPlayControl", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PnPControlClass", .dir = DIR_IN, .dir_opt = "", .type = PLUGPLAY_CONTROL_CLASS},
            {.name = "PnPControlData", .dir = DIR_INOUT, .dir_opt = "bcount(PnPControlDataLength)", .type = PVOID},
            {.name = "PnPControlDataLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtPowerInformation", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "InformationLevel", .dir = DIR_IN, .dir_opt = "", .type = POWER_INFORMATION_LEVEL},
            {.name = "InputBuffer", .dir = DIR_IN, .dir_opt = "bcount_opt(InputBufferLength)", .type = PVOID},
            {.name = "InputBufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "OutputBuffer", .dir = DIR_OUT, .dir_opt = "bcount_opt(OutputBufferLength)", .type = PVOID},
            {.name = "OutputBufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtPrepareComplete", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TmVirtualClock", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtPrepareEnlistment", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TmVirtualClock", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtPrePrepareComplete", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TmVirtualClock", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtPrePrepareEnlistment", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TmVirtualClock", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtPrivilegeCheck", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "ClientToken", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "RequiredPrivileges", .dir = DIR_INOUT, .dir_opt = "", .type = PPRIVILEGE_SET},
            {.name = "Result", .dir = DIR_OUT, .dir_opt = "", .type = PBOOLEAN}
        }
    },
    {
        .name = "NtPrivilegedServiceAuditAlarm", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "SubsystemName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "ServiceName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "ClientToken", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Privileges", .dir = DIR_IN, .dir_opt = "", .type = PPRIVILEGE_SET},
            {.name = "AccessGranted", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtPrivilegeObjectAuditAlarm", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "SubsystemName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "HandleId", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ClientToken", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DesiredAccess", .dir = DIR_IN, .dir_opt = "", .type = ACCESS_MASK},
            {.name = "Privileges", .dir = DIR_IN, .dir_opt = "", .type = PPRIVILEGE_SET},
            {.name = "AccessGranted", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtPropagationComplete", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ResourceManagerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "RequestCookie", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "BufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Buffer", .dir = DIR_IN, .dir_opt = "", .type = PVOID}
        }
    },
    {
        .name = "NtPropagationFailed", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "ResourceManagerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "RequestCookie", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "PropStatus", .dir = DIR_IN, .dir_opt = "", .type = NTSTATUS}
        }
    },
    {
        .name = "NtProtectVirtualMemory", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*BaseAddress", .dir = DIR_INOUT, .dir_opt = "", .type = PVOID},
            {.name = "RegionSize", .dir = DIR_INOUT, .dir_opt = "", .type = PSIZE_T},
            {.name = "NewProtectWin32", .dir = DIR_IN, .dir_opt = "", .type = WIN32_PROTECTION_MASK},
            {.name = "OldProtect", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtPulseEvent", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EventHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PreviousState", .dir = DIR_OUT, .dir_opt = "opt", .type = PLONG}
        }
    },
    {
        .name = "NtQueryAttributesFile", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "FileInformation", .dir = DIR_OUT, .dir_opt = "", .type = PFILE_BASIC_INFORMATION}
        }
    },
    {
        .name = "NtQueryBootEntryOrder", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "Ids", .dir = DIR_OUT, .dir_opt = "ecount_opt(*Count)", .type = PULONG},
            {.name = "Count", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQueryBootOptions", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "BootOptions", .dir = DIR_OUT, .dir_opt = "bcount_opt(*BootOptionsLength)", .type = PBOOT_OPTIONS},
            {.name = "BootOptionsLength", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQueryDebugFilterState", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ComponentId", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Level", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtQueryDefaultLocale", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "UserProfile", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "DefaultLocaleId", .dir = DIR_OUT, .dir_opt = "", .type = PLCID}
        }
    },
    {
        .name = "NtQueryDefaultUILanguage", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "*DefaultUILanguageId", .dir = DIR_OUT, .dir_opt = "", .type = LANGID}
        }
    },
    {
        .name = "NtQueryDirectoryFile", .ret = NTSTATUS, .num_args = 11, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "FileInformation", .dir = DIR_OUT, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "FileInformationClass", .dir = DIR_IN, .dir_opt = "", .type = FILE_INFORMATION_CLASS},
            {.name = "ReturnSingleEntry", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "FileName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "RestartScan", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtQueryDirectoryObject", .ret = NTSTATUS, .num_args = 7, .args =
        {
            {.name = "DirectoryHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount_opt(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnSingleEntry", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "RestartScan", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "Context", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryDriverEntryOrder", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "Ids", .dir = DIR_OUT, .dir_opt = "ecount(*Count)", .type = PULONG},
            {.name = "Count", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQueryEaFile", .ret = NTSTATUS, .num_args = 9, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnSingleEntry", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "EaList", .dir = DIR_IN, .dir_opt = "bcount_opt(EaListLength)", .type = PVOID},
            {.name = "EaListLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "EaIndex", .dir = DIR_IN, .dir_opt = "opt", .type = PULONG},
            {.name = "RestartScan", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtQueryEvent", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "EventHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "EventInformationClass", .dir = DIR_IN, .dir_opt = "", .type = EVENT_INFORMATION_CLASS},
            {.name = "EventInformation", .dir = DIR_OUT, .dir_opt = "bcount(EventInformationLength)", .type = PVOID},
            {.name = "EventInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryFullAttributesFile", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ObjectAttributes", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "FileInformation", .dir = DIR_OUT, .dir_opt = "", .type = PFILE_NETWORK_OPEN_INFORMATION}
        }
    },
    {
        .name = "NtQueryInformationAtom", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "Atom", .dir = DIR_IN, .dir_opt = "", .type = RTL_ATOM},
            {.name = "InformationClass", .dir = DIR_IN, .dir_opt = "", .type = ATOM_INFORMATION_CLASS},
            {.name = "AtomInformation", .dir = DIR_OUT, .dir_opt = "bcount(AtomInformationLength)", .type = PVOID},
            {.name = "AtomInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryInformationEnlistment", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "EnlistmentInformationClass", .dir = DIR_IN, .dir_opt = "", .type = ENLISTMENT_INFORMATION_CLASS},
            {.name = "EnlistmentInformation", .dir = DIR_OUT, .dir_opt = "bcount(EnlistmentInformationLength)", .type = PVOID},
            {.name = "EnlistmentInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryInformationFile", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "FileInformation", .dir = DIR_OUT, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "FileInformationClass", .dir = DIR_IN, .dir_opt = "", .type = FILE_INFORMATION_CLASS}
        }
    },
    {
        .name = "NtQueryInformationJobObject", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "JobHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "JobObjectInformationClass", .dir = DIR_IN, .dir_opt = "", .type = JOBOBJECTINFOCLASS},
            {.name = "JobObjectInformation", .dir = DIR_OUT, .dir_opt = "bcount(JobObjectInformationLength)", .type = PVOID},
            {.name = "JobObjectInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryInformationPort", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PortInformationClass", .dir = DIR_IN, .dir_opt = "", .type = PORT_INFORMATION_CLASS},
            {.name = "PortInformation", .dir = DIR_OUT, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryInformationProcess", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ProcessInformationClass", .dir = DIR_IN, .dir_opt = "", .type = PROCESSINFOCLASS},
            {.name = "ProcessInformation", .dir = DIR_OUT, .dir_opt = "bcount(ProcessInformationLength)", .type = PVOID},
            {.name = "ProcessInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryInformationResourceManager", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "ResourceManagerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ResourceManagerInformationClass", .dir = DIR_IN, .dir_opt = "", .type = RESOURCEMANAGER_INFORMATION_CLASS},
            {.name = "ResourceManagerInformation", .dir = DIR_OUT, .dir_opt = "bcount(ResourceManagerInformationLength)", .type = PVOID},
            {.name = "ResourceManagerInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryInformationThread", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ThreadInformationClass", .dir = DIR_IN, .dir_opt = "", .type = THREADINFOCLASS},
            {.name = "ThreadInformation", .dir = DIR_OUT, .dir_opt = "bcount(ThreadInformationLength)", .type = PVOID},
            {.name = "ThreadInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryInformationToken", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "TokenHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TokenInformationClass", .dir = DIR_IN, .dir_opt = "", .type = TOKEN_INFORMATION_CLASS},
            {.name = "TokenInformation", .dir = DIR_OUT, .dir_opt = "bcount_part_opt(TokenInformationLength,*ReturnLength)", .type = PVOID},
            {.name = "TokenInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQueryInformationTransaction", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "TransactionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TransactionInformationClass", .dir = DIR_IN, .dir_opt = "", .type = TRANSACTION_INFORMATION_CLASS},
            {.name = "TransactionInformation", .dir = DIR_OUT, .dir_opt = "bcount(TransactionInformationLength)", .type = PVOID},
            {.name = "TransactionInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryInformationTransactionManager", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "TransactionManagerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TransactionManagerInformationClass", .dir = DIR_IN, .dir_opt = "", .type = TRANSACTIONMANAGER_INFORMATION_CLASS},
            {.name = "TransactionManagerInformation", .dir = DIR_OUT, .dir_opt = "bcount(TransactionManagerInformationLength)", .type = PVOID},
            {.name = "TransactionManagerInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryInformationWorkerFactory", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "WorkerFactoryHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "WorkerFactoryInformationClass", .dir = DIR_IN, .dir_opt = "", .type = WORKERFACTORYINFOCLASS},
            {.name = "WorkerFactoryInformation", .dir = DIR_OUT, .dir_opt = "bcount(WorkerFactoryInformationLength)", .type = PVOID},
            {.name = "WorkerFactoryInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryInstallUILanguage", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "*InstallUILanguageId", .dir = DIR_OUT, .dir_opt = "", .type = LANGID}
        }
    },
    {
        .name = "NtQueryIntervalProfile", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ProfileSource", .dir = DIR_IN, .dir_opt = "", .type = KPROFILE_SOURCE},
            {.name = "Interval", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQueryIoCompletion", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "IoCompletionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoCompletionInformationClass", .dir = DIR_IN, .dir_opt = "", .type = IO_COMPLETION_INFORMATION_CLASS},
            {.name = "IoCompletionInformation", .dir = DIR_OUT, .dir_opt = "bcount(IoCompletionInformationLength)", .type = PVOID},
            {.name = "IoCompletionInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryKey", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "KeyInformationClass", .dir = DIR_IN, .dir_opt = "", .type = KEY_INFORMATION_CLASS},
            {.name = "KeyInformation", .dir = DIR_OUT, .dir_opt = "bcount_opt(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ResultLength", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQueryLicenseValue", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "Name", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "Type", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount(ReturnedLength)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnedLength", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQueryMultipleValueKey", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ValueEntries", .dir = DIR_INOUT, .dir_opt = "ecount(EntryCount)", .type = PKEY_VALUE_ENTRY},
            {.name = "EntryCount", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ValueBuffer", .dir = DIR_OUT, .dir_opt = "bcount(*BufferLength)", .type = PVOID},
            {.name = "BufferLength", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG},
            {.name = "RequiredBufferLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryMutant", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "MutantHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "MutantInformationClass", .dir = DIR_IN, .dir_opt = "", .type = MUTANT_INFORMATION_CLASS},
            {.name = "MutantInformation", .dir = DIR_OUT, .dir_opt = "bcount(MutantInformationLength)", .type = PVOID},
            {.name = "MutantInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryObject", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "Handle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ObjectInformationClass", .dir = DIR_IN, .dir_opt = "", .type = OBJECT_INFORMATION_CLASS},
            {.name = "ObjectInformation", .dir = DIR_OUT, .dir_opt = "bcount_opt(ObjectInformationLength)", .type = PVOID},
            {.name = "ObjectInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryOpenSubKeysEx", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "TargetKey", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "BufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount(BufferLength)", .type = PVOID},
            {.name = "RequiredSize", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQueryOpenSubKeys", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "TargetKey", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "HandleCount", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQueryPerformanceCounter", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "PerformanceCounter", .dir = DIR_OUT, .dir_opt = "", .type = PLARGE_INTEGER},
            {.name = "PerformanceFrequency", .dir = DIR_OUT, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    { .name = "NtQueryPortInformationProcess", .ret = NTSTATUS, .num_args = 0  },
    {
        .name = "NtQueryQuotaInformationFile", .ret = NTSTATUS, .num_args = 9, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnSingleEntry", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "SidList", .dir = DIR_IN, .dir_opt = "bcount_opt(SidListLength)", .type = PVOID},
            {.name = "SidListLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "StartSid", .dir = DIR_IN, .dir_opt = "opt", .type = PULONG},
            {.name = "RestartScan", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtQuerySection", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "SectionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "SectionInformationClass", .dir = DIR_IN, .dir_opt = "", .type = SECTION_INFORMATION_CLASS},
            {.name = "SectionInformation", .dir = DIR_OUT, .dir_opt = "bcount(SectionInformationLength)", .type = PVOID},
            {.name = "SectionInformationLength", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PSIZE_T}
        }
    },
    {
        .name = "NtQuerySecurityAttributesToken", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "TokenHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Attributes", .dir = DIR_IN, .dir_opt = "ecount_opt(NumberOfAttributes)", .type = PUNICODE_STRING},
            {.name = "NumberOfAttributes", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQuerySecurityObject", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "Handle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "SecurityInformation", .dir = DIR_IN, .dir_opt = "", .type = SECURITY_INFORMATION},
            {.name = "SecurityDescriptor", .dir = DIR_OUT, .dir_opt = "bcount_opt(Length)", .type = PSECURITY_DESCRIPTOR},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "LengthNeeded", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQuerySemaphore", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "SemaphoreHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "SemaphoreInformationClass", .dir = DIR_IN, .dir_opt = "", .type = SEMAPHORE_INFORMATION_CLASS},
            {.name = "SemaphoreInformation", .dir = DIR_OUT, .dir_opt = "bcount(SemaphoreInformationLength)", .type = PVOID},
            {.name = "SemaphoreInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQuerySymbolicLinkObject", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "LinkHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "LinkTarget", .dir = DIR_INOUT, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "ReturnedLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQuerySystemEnvironmentValueEx", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "VariableName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "VendorGuid", .dir = DIR_IN, .dir_opt = "", .type = LPGUID},
            {.name = "Value", .dir = DIR_OUT, .dir_opt = "bcount_opt(*ValueLength)", .type = PVOID},
            {.name = "ValueLength", .dir = DIR_INOUT, .dir_opt = "", .type = PULONG},
            {.name = "Attributes", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQuerySystemEnvironmentValue", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "VariableName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "VariableValue", .dir = DIR_OUT, .dir_opt = "bcount(ValueLength)", .type = PWSTR},
            {.name = "ValueLength", .dir = DIR_IN, .dir_opt = "", .type = USHORT},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PUSHORT}
        }
    },
    {
        .name = "NtQuerySystemInformationEx", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "SystemInformationClass", .dir = DIR_IN, .dir_opt = "", .type = SYSTEM_INFORMATION_CLASS},
            {.name = "QueryInformation", .dir = DIR_IN, .dir_opt = "bcount(QueryInformationLength)", .type = PVOID},
            {.name = "QueryInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "SystemInformation", .dir = DIR_OUT, .dir_opt = "bcount_opt(SystemInformationLength)", .type = PVOID},
            {.name = "SystemInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQuerySystemInformation", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "SystemInformationClass", .dir = DIR_IN, .dir_opt = "", .type = SYSTEM_INFORMATION_CLASS},
            {.name = "SystemInformation", .dir = DIR_OUT, .dir_opt = "bcount_opt(SystemInformationLength)", .type = PVOID},
            {.name = "SystemInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQuerySystemTime", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "SystemTime", .dir = DIR_OUT, .dir_opt = "", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtQueryTimer", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "TimerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TimerInformationClass", .dir = DIR_IN, .dir_opt = "", .type = TIMER_INFORMATION_CLASS},
            {.name = "TimerInformation", .dir = DIR_OUT, .dir_opt = "bcount(TimerInformationLength)", .type = PVOID},
            {.name = "TimerInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtQueryTimerResolution", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "MaximumTime", .dir = DIR_OUT, .dir_opt = "", .type = PULONG},
            {.name = "MinimumTime", .dir = DIR_OUT, .dir_opt = "", .type = PULONG},
            {.name = "CurrentTime", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQueryValueKey", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ValueName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "KeyValueInformationClass", .dir = DIR_IN, .dir_opt = "", .type = KEY_VALUE_INFORMATION_CLASS},
            {.name = "KeyValueInformation", .dir = DIR_OUT, .dir_opt = "bcount_opt(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ResultLength", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtQueryVirtualMemory", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "BaseAddress", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "MemoryInformationClass", .dir = DIR_IN, .dir_opt = "", .type = MEMORY_INFORMATION_CLASS},
            {.name = "MemoryInformation", .dir = DIR_OUT, .dir_opt = "bcount(MemoryInformationLength)", .type = PVOID},
            {.name = "MemoryInformationLength", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PSIZE_T}
        }
    },
    {
        .name = "NtQueryVolumeInformationFile", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "FsInformation", .dir = DIR_OUT, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "FsInformationClass", .dir = DIR_IN, .dir_opt = "", .type = FS_INFORMATION_CLASS}
        }
    },
    {
        .name = "NtQueueApcThreadEx", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "UserApcReserveHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "", .type = PPS_APC_ROUTINE},
            {.name = "ApcArgument1", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ApcArgument2", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ApcArgument3", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID}
        }
    },
    {
        .name = "NtQueueApcThread", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "", .type = PPS_APC_ROUTINE},
            {.name = "ApcArgument1", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ApcArgument2", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "ApcArgument3", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID}
        }
    },
    {
        .name = "NtRaiseException", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "ExceptionRecord", .dir = DIR_OUT, .dir_opt = "", .type = PEXCEPTION_RECORD},
            {.name = "ContextRecord", .dir = DIR_OUT, .dir_opt = "", .type = PCONTEXT},
            {.name = "FirstChance", .dir = DIR_OUT, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtRaiseHardError", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "ErrorStatus", .dir = DIR_IN, .dir_opt = "", .type = NTSTATUS},
            {.name = "NumberOfParameters", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "UnicodeStringParameterMask", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Parameters", .dir = DIR_IN, .dir_opt = "ecount(NumberOfParameters)", .type = PULONG_PTR},
            {.name = "ValidResponseOptions", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Response", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtReadFile", .ret = NTSTATUS, .num_args = 9, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ByteOffset", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER},
            {.name = "Key", .dir = DIR_IN, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtReadFileScatter", .ret = NTSTATUS, .num_args = 9, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "SegmentArray", .dir = DIR_IN, .dir_opt = "", .type = PFILE_SEGMENT_ELEMENT},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ByteOffset", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER},
            {.name = "Key", .dir = DIR_IN, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtReadOnlyEnlistment", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TmVirtualClock", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtReadRequestData", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Message", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE},
            {.name = "DataEntryIndex", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount(BufferSize)", .type = PVOID},
            {.name = "BufferSize", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "NumberOfBytesRead", .dir = DIR_OUT, .dir_opt = "opt", .type = PSIZE_T}
        }
    },
    {
        .name = "NtReadVirtualMemory", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "BaseAddress", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "Buffer", .dir = DIR_OUT, .dir_opt = "bcount(BufferSize)", .type = PVOID},
            {.name = "BufferSize", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "NumberOfBytesRead", .dir = DIR_OUT, .dir_opt = "opt", .type = PSIZE_T}
        }
    },
    {
        .name = "NtRecoverEnlistment", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "EnlistmentKey", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID}
        }
    },
    {
        .name = "NtRecoverResourceManager", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "ResourceManagerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtRecoverTransactionManager", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "TransactionManagerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtRegisterProtocolAddressInformation", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "ResourceManager", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ProtocolId", .dir = DIR_IN, .dir_opt = "", .type = PCRM_PROTOCOL_ID},
            {.name = "ProtocolInformationSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ProtocolInformation", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "CreateOptions", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG}
        }
    },
    {
        .name = "NtRegisterThreadTerminatePort", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtReleaseKeyedEvent", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "KeyedEventHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "KeyValue", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "Alertable", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtReleaseMutant", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "MutantHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PreviousCount", .dir = DIR_OUT, .dir_opt = "opt", .type = PLONG}
        }
    },
    {
        .name = "NtReleaseSemaphore", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "SemaphoreHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ReleaseCount", .dir = DIR_IN, .dir_opt = "", .type = LONG},
            {.name = "PreviousCount", .dir = DIR_OUT, .dir_opt = "opt", .type = PLONG}
        }
    },
    {
        .name = "NtReleaseWorkerFactoryWorker", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "WorkerFactoryHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtRemoveIoCompletionEx", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "IoCompletionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoCompletionInformation", .dir = DIR_OUT, .dir_opt = "ecount(Count)", .type = PFILE_IO_COMPLETION_INFORMATION},
            {.name = "Count", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "NumEntriesRemoved", .dir = DIR_OUT, .dir_opt = "", .type = PULONG},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER},
            {.name = "Alertable", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtRemoveIoCompletion", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "IoCompletionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*KeyContext", .dir = DIR_OUT, .dir_opt = "", .type = PVOID},
            {.name = "*ApcContext", .dir = DIR_OUT, .dir_opt = "", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtRemoveProcessDebug", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_OUT, .dir_opt = "", .type = HANDLE},
            {.name = "DebugObjectHandle", .dir = DIR_OUT, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtRenameKey", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "NewName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING}
        }
    },
    {
        .name = "NtRenameTransactionManager", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "LogFileName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "ExistingTransactionManagerGuid", .dir = DIR_IN, .dir_opt = "", .type = LPGUID}
        }
    },
    {
        .name = "NtReplaceKey", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "NewFile", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "TargetHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "OldFile", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtReplacePartitionUnit", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "TargetInstancePath", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "SpareInstancePath", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtReplyPort", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ReplyMessage", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE}
        }
    },
    {
        .name = "NtReplyWaitReceivePortEx", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*PortContext", .dir = DIR_OUT, .dir_opt = "opt", .type = PVOID},
            {.name = "ReplyMessage", .dir = DIR_IN, .dir_opt = "opt", .type = PPORT_MESSAGE},
            {.name = "ReceiveMessage", .dir = DIR_OUT, .dir_opt = "", .type = PPORT_MESSAGE},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtReplyWaitReceivePort", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*PortContext", .dir = DIR_OUT, .dir_opt = "opt", .type = PVOID},
            {.name = "ReplyMessage", .dir = DIR_IN, .dir_opt = "opt", .type = PPORT_MESSAGE},
            {.name = "ReceiveMessage", .dir = DIR_OUT, .dir_opt = "", .type = PPORT_MESSAGE}
        }
    },
    {
        .name = "NtReplyWaitReplyPort", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ReplyMessage", .dir = DIR_INOUT, .dir_opt = "", .type = PPORT_MESSAGE}
        }
    },
    {
        .name = "NtRequestPort", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "RequestMessage", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE}
        }
    },
    {
        .name = "NtRequestWaitReplyPort", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "RequestMessage", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE},
            {.name = "ReplyMessage", .dir = DIR_OUT, .dir_opt = "", .type = PPORT_MESSAGE}
        }
    },
    {
        .name = "NtResetEvent", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EventHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PreviousState", .dir = DIR_OUT, .dir_opt = "opt", .type = PLONG}
        }
    },
    {
        .name = "NtResetWriteWatch", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "BaseAddress", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "RegionSize", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T}
        }
    },
    {
        .name = "NtRestoreKey", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtResumeProcess", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtResumeThread", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PreviousSuspendCount", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtRollbackComplete", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TmVirtualClock", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtRollbackEnlistment", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TmVirtualClock", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtRollbackTransaction", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "TransactionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Wait", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtRollforwardTransactionManager", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "TransactionManagerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TmVirtualClock", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtSaveKeyEx", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Format", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSaveKey", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtSaveMergedKeys", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "HighPrecedenceKeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "LowPrecedenceKeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtSecureConnectPort", .ret = NTSTATUS, .num_args = 9, .args =
        {
            {.name = "PortHandle", .dir = DIR_OUT, .dir_opt = "", .type = PHANDLE},
            {.name = "PortName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "SecurityQos", .dir = DIR_IN, .dir_opt = "", .type = PSECURITY_QUALITY_OF_SERVICE},
            {.name = "ClientView", .dir = DIR_INOUT, .dir_opt = "opt", .type = PPORT_VIEW},
            {.name = "RequiredServerSid", .dir = DIR_IN, .dir_opt = "opt", .type = PSID},
            {.name = "ServerView", .dir = DIR_INOUT, .dir_opt = "opt", .type = PREMOTE_PORT_VIEW},
            {.name = "MaxMessageLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG},
            {.name = "ConnectionInformation", .dir = DIR_INOUT, .dir_opt = "opt", .type = PVOID},
            {.name = "ConnectionInformationLength", .dir = DIR_INOUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    { .name = "NtSerializeBoot", .ret = NTSTATUS, .num_args = 0  },
    {
        .name = "NtSetBootEntryOrder", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "Ids", .dir = DIR_IN, .dir_opt = "ecount(Count)", .type = PULONG},
            {.name = "Count", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetBootOptions", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "BootOptions", .dir = DIR_IN, .dir_opt = "", .type = PBOOT_OPTIONS},
            {.name = "FieldsToChange", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetContextThread", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ThreadContext", .dir = DIR_IN, .dir_opt = "", .type = PCONTEXT}
        }
    },
    {
        .name = "NtSetDebugFilterState", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "ComponentId", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Level", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "State", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN}
        }
    },
    {
        .name = "NtSetDefaultHardErrorPort", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "DefaultHardErrorPort", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtSetDefaultLocale", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "UserProfile", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "DefaultLocaleId", .dir = DIR_IN, .dir_opt = "", .type = LCID}
        }
    },
    {
        .name = "NtSetDefaultUILanguage", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "DefaultUILanguageId", .dir = DIR_IN, .dir_opt = "", .type = LANGID}
        }
    },
    {
        .name = "NtSetDriverEntryOrder", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "Ids", .dir = DIR_IN, .dir_opt = "ecount(Count)", .type = PULONG},
            {.name = "Count", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetEaFile", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "Buffer", .dir = DIR_IN, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetEventBoostPriority", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "EventHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtSetEvent", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EventHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PreviousState", .dir = DIR_OUT, .dir_opt = "opt", .type = PLONG}
        }
    },
    {
        .name = "NtSetHighEventPair", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "EventPairHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtSetHighWaitLowEventPair", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "EventPairHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtSetInformationDebugObject", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "DebugObjectHandle", .dir = DIR_OUT, .dir_opt = "", .type = HANDLE},
            {.name = "DebugObjectInformationClass", .dir = DIR_OUT, .dir_opt = "", .type = DEBUGOBJECTINFOCLASS},
            {.name = "DebugInformation", .dir = DIR_OUT, .dir_opt = "", .type = PVOID},
            {.name = "DebugInformationLength", .dir = DIR_OUT, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtSetInformationEnlistment", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "EnlistmentInformationClass", .dir = DIR_IN, .dir_opt = "", .type = ENLISTMENT_INFORMATION_CLASS},
            {.name = "EnlistmentInformation", .dir = DIR_IN, .dir_opt = "bcount(EnlistmentInformationLength)", .type = PVOID},
            {.name = "EnlistmentInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetInformationFile", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "FileInformation", .dir = DIR_IN, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "FileInformationClass", .dir = DIR_IN, .dir_opt = "", .type = FILE_INFORMATION_CLASS}
        }
    },
    {
        .name = "NtSetInformationJobObject", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "JobHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "JobObjectInformationClass", .dir = DIR_IN, .dir_opt = "", .type = JOBOBJECTINFOCLASS},
            {.name = "JobObjectInformation", .dir = DIR_IN, .dir_opt = "bcount(JobObjectInformationLength)", .type = PVOID},
            {.name = "JobObjectInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetInformationKey", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "KeySetInformationClass", .dir = DIR_IN, .dir_opt = "", .type = KEY_SET_INFORMATION_CLASS},
            {.name = "KeySetInformation", .dir = DIR_IN, .dir_opt = "bcount(KeySetInformationLength)", .type = PVOID},
            {.name = "KeySetInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetInformationObject", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "Handle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ObjectInformationClass", .dir = DIR_IN, .dir_opt = "", .type = OBJECT_INFORMATION_CLASS},
            {.name = "ObjectInformation", .dir = DIR_IN, .dir_opt = "bcount(ObjectInformationLength)", .type = PVOID},
            {.name = "ObjectInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetInformationProcess", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ProcessInformationClass", .dir = DIR_IN, .dir_opt = "", .type = PROCESSINFOCLASS},
            {.name = "ProcessInformation", .dir = DIR_IN, .dir_opt = "bcount(ProcessInformationLength)", .type = PVOID},
            {.name = "ProcessInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetInformationResourceManager", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ResourceManagerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ResourceManagerInformationClass", .dir = DIR_IN, .dir_opt = "", .type = RESOURCEMANAGER_INFORMATION_CLASS},
            {.name = "ResourceManagerInformation", .dir = DIR_IN, .dir_opt = "bcount(ResourceManagerInformationLength)", .type = PVOID},
            {.name = "ResourceManagerInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetInformationThread", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ThreadInformationClass", .dir = DIR_IN, .dir_opt = "", .type = THREADINFOCLASS},
            {.name = "ThreadInformation", .dir = DIR_IN, .dir_opt = "bcount(ThreadInformationLength)", .type = PVOID},
            {.name = "ThreadInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetInformationToken", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "TokenHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TokenInformationClass", .dir = DIR_IN, .dir_opt = "", .type = TOKEN_INFORMATION_CLASS},
            {.name = "TokenInformation", .dir = DIR_IN, .dir_opt = "bcount(TokenInformationLength)", .type = PVOID},
            {.name = "TokenInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetInformationTransaction", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "TransactionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TransactionInformationClass", .dir = DIR_IN, .dir_opt = "", .type = TRANSACTION_INFORMATION_CLASS},
            {.name = "TransactionInformation", .dir = DIR_IN, .dir_opt = "bcount(TransactionInformationLength)", .type = PVOID},
            {.name = "TransactionInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetInformationTransactionManager", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "TmHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "TransactionManagerInformationClass", .dir = DIR_IN, .dir_opt = "", .type = TRANSACTIONMANAGER_INFORMATION_CLASS},
            {.name = "TransactionManagerInformation", .dir = DIR_IN, .dir_opt = "bcount(TransactionManagerInformationLength)", .type = PVOID},
            {.name = "TransactionManagerInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetInformationWorkerFactory", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "WorkerFactoryHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "WorkerFactoryInformationClass", .dir = DIR_IN, .dir_opt = "", .type = WORKERFACTORYINFOCLASS},
            {.name = "WorkerFactoryInformation", .dir = DIR_IN, .dir_opt = "bcount(WorkerFactoryInformationLength)", .type = PVOID},
            {.name = "WorkerFactoryInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetIntervalProfile", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "Interval", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Source", .dir = DIR_IN, .dir_opt = "", .type = KPROFILE_SOURCE}
        }
    },
    {
        .name = "NtSetIoCompletionEx", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "IoCompletionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoCompletionReserveHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "KeyContext", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatus", .dir = DIR_IN, .dir_opt = "", .type = NTSTATUS},
            {.name = "IoStatusInformation", .dir = DIR_IN, .dir_opt = "", .type = ULONG_PTR}
        }
    },
    {
        .name = "NtSetIoCompletion", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "IoCompletionHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "KeyContext", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatus", .dir = DIR_IN, .dir_opt = "", .type = NTSTATUS},
            {.name = "IoStatusInformation", .dir = DIR_IN, .dir_opt = "", .type = ULONG_PTR}
        }
    },
    {
        .name = "NtSetLdtEntries", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "Selector0", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Entry0Low", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Entry0Hi", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Selector1", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Entry1Low", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Entry1Hi", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetLowEventPair", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "EventPairHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtSetLowWaitHighEventPair", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "EventPairHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtSetQuotaInformationFile", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "Buffer", .dir = DIR_IN, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetSecurityObject", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "Handle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "SecurityInformation", .dir = DIR_IN, .dir_opt = "", .type = SECURITY_INFORMATION},
            {.name = "SecurityDescriptor", .dir = DIR_IN, .dir_opt = "", .type = PSECURITY_DESCRIPTOR}
        }
    },
    {
        .name = "NtSetSystemEnvironmentValueEx", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "VariableName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "VendorGuid", .dir = DIR_IN, .dir_opt = "", .type = LPGUID},
            {.name = "Value", .dir = DIR_IN, .dir_opt = "bcount_opt(ValueLength)", .type = PVOID},
            {.name = "ValueLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Attributes", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetSystemEnvironmentValue", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "VariableName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "VariableValue", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING}
        }
    },
    {
        .name = "NtSetSystemInformation", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "SystemInformationClass", .dir = DIR_IN, .dir_opt = "", .type = SYSTEM_INFORMATION_CLASS},
            {.name = "SystemInformation", .dir = DIR_IN, .dir_opt = "bcount_opt(SystemInformationLength)", .type = PVOID},
            {.name = "SystemInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetSystemPowerState", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "SystemAction", .dir = DIR_IN, .dir_opt = "", .type = POWER_ACTION},
            {.name = "MinSystemState", .dir = DIR_IN, .dir_opt = "", .type = SYSTEM_POWER_STATE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetSystemTime", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "SystemTime", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER},
            {.name = "PreviousTime", .dir = DIR_OUT, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtSetThreadExecutionState", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "esFlags", .dir = DIR_IN, .dir_opt = "", .type = EXECUTION_STATE},
            {.name = "*PreviousFlags", .dir = DIR_OUT, .dir_opt = "", .type = EXECUTION_STATE}
        }
    },
    {
        .name = "NtSetTimerEx", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "TimerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TimerSetInformationClass", .dir = DIR_IN, .dir_opt = "", .type = TIMER_SET_INFORMATION_CLASS},
            {.name = "TimerSetInformation", .dir = DIR_INOUT, .dir_opt = "bcount(TimerSetInformationLength)", .type = PVOID},
            {.name = "TimerSetInformationLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetTimer", .ret = NTSTATUS, .num_args = 7, .args =
        {
            {.name = "TimerHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "DueTime", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER},
            {.name = "TimerApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PTIMER_APC_ROUTINE},
            {.name = "TimerContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "WakeTimer", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "Period", .dir = DIR_IN, .dir_opt = "opt", .type = LONG},
            {.name = "PreviousState", .dir = DIR_OUT, .dir_opt = "opt", .type = PBOOLEAN}
        }
    },
    {
        .name = "NtSetTimerResolution", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "DesiredTime", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "SetResolution", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "ActualTime", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtSetUuidSeed", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "Seed", .dir = DIR_IN, .dir_opt = "", .type = PCHAR}
        }
    },
    {
        .name = "NtSetValueKey", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "KeyHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ValueName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING},
            {.name = "TitleIndex", .dir = DIR_IN, .dir_opt = "opt", .type = ULONG},
            {.name = "Type", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Data", .dir = DIR_IN, .dir_opt = "bcount_opt(DataSize)", .type = PVOID},
            {.name = "DataSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtSetVolumeInformationFile", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "FsInformation", .dir = DIR_IN, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "FsInformationClass", .dir = DIR_IN, .dir_opt = "", .type = FS_INFORMATION_CLASS}
        }
    },
    {
        .name = "NtShutdownSystem", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "Action", .dir = DIR_IN, .dir_opt = "", .type = SHUTDOWN_ACTION}
        }
    },
    {
        .name = "NtShutdownWorkerFactory", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "WorkerFactoryHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*PendingWorkerCount", .dir = DIR_INOUT, .dir_opt = "", .type = LONG}
        }
    },
    {
        .name = "NtSignalAndWaitForSingleObject", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "SignalHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "WaitHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Alertable", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtSinglePhaseReject", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "EnlistmentHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "TmVirtualClock", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtStartProfile", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "ProfileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtStopProfile", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "ProfileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtSuspendProcess", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtSuspendThread", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "PreviousSuspendCount", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtSystemDebugControl", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "Command", .dir = DIR_IN, .dir_opt = "", .type = SYSDBG_COMMAND},
            {.name = "InputBuffer", .dir = DIR_INOUT, .dir_opt = "bcount_opt(InputBufferLength)", .type = PVOID},
            {.name = "InputBufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "OutputBuffer", .dir = DIR_OUT, .dir_opt = "bcount_opt(OutputBufferLength)", .type = PVOID},
            {.name = "OutputBufferLength", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtTerminateJobObject", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "JobHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "ExitStatus", .dir = DIR_IN, .dir_opt = "", .type = NTSTATUS}
        }
    },
    {
        .name = "NtTerminateProcess", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ExitStatus", .dir = DIR_IN, .dir_opt = "", .type = NTSTATUS}
        }
    },
    {
        .name = "NtTerminateThread", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ThreadHandle", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ExitStatus", .dir = DIR_IN, .dir_opt = "", .type = NTSTATUS}
        }
    },
    { .name = "NtTestAlert", .ret = NTSTATUS, .num_args = 0  },
    { .name = "NtThawRegistry", .ret = NTSTATUS, .num_args = 0  },
    { .name = "NtThawTransactions", .ret = NTSTATUS, .num_args = 0  },
    {
        .name = "NtTraceControl", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "FunctionCode", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "InBuffer", .dir = DIR_IN, .dir_opt = "bcount_opt(InBufferLen)", .type = PVOID},
            {.name = "InBufferLen", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "OutBuffer", .dir = DIR_OUT, .dir_opt = "bcount_opt(OutBufferLen)", .type = PVOID},
            {.name = "OutBufferLen", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ReturnLength", .dir = DIR_OUT, .dir_opt = "", .type = PULONG}
        }
    },
    {
        .name = "NtTraceEvent", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "TraceHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "FieldSize", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Fields", .dir = DIR_IN, .dir_opt = "", .type = PVOID}
        }
    },
    {
        .name = "NtTranslateFilePath", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "InputFilePath", .dir = DIR_IN, .dir_opt = "", .type = PFILE_PATH},
            {.name = "OutputType", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "OutputFilePath", .dir = DIR_OUT, .dir_opt = "bcount_opt(*OutputFilePathLength)", .type = PFILE_PATH},
            {.name = "OutputFilePathLength", .dir = DIR_INOUT, .dir_opt = "opt", .type = PULONG}
        }
    },
    { .name = "NtUmsThreadYield", .ret = NTSTATUS, .num_args = 0  },
    {
        .name = "NtUnloadDriver", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "DriverServiceName", .dir = DIR_IN, .dir_opt = "", .type = PUNICODE_STRING}
        }
    },
    {
        .name = "NtUnloadKey2", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "TargetKey", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "Flags", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtUnloadKeyEx", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "TargetKey", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE}
        }
    },
    {
        .name = "NtUnloadKey", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "TargetKey", .dir = DIR_IN, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
        }
    },
    {
        .name = "NtUnlockFile", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "ByteOffset", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = PLARGE_INTEGER},
            {.name = "Key", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtUnlockVirtualMemory", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "*BaseAddress", .dir = DIR_INOUT, .dir_opt = "", .type = PVOID},
            {.name = "RegionSize", .dir = DIR_INOUT, .dir_opt = "", .type = PSIZE_T},
            {.name = "MapType", .dir = DIR_IN, .dir_opt = "", .type = ULONG}
        }
    },
    {
        .name = "NtUnmapViewOfSection", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "BaseAddress", .dir = DIR_IN, .dir_opt = "", .type = PVOID}
        }
    },
    {
        .name = "NtVdmControl", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "Service", .dir = DIR_IN, .dir_opt = "", .type = VDMSERVICECLASS},
            {.name = "ServiceData", .dir = DIR_INOUT, .dir_opt = "", .type = PVOID}
        }
    },
    {
        .name = "NtWaitForDebugEvent", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "DebugObjectHandle", .dir = DIR_OUT, .dir_opt = "", .type = HANDLE},
            {.name = "Alertable", .dir = DIR_OUT, .dir_opt = "", .type = BOOLEAN},
            {.name = "Timeout", .dir = DIR_OUT, .dir_opt = "", .type = PLARGE_INTEGER},
            {.name = "WaitStateChange", .dir = DIR_OUT, .dir_opt = "", .type = PDBGUI_WAIT_STATE_CHANGE}
        }
    },
    {
        .name = "NtWaitForKeyedEvent", .ret = NTSTATUS, .num_args = 4, .args =
        {
            {.name = "KeyedEventHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "KeyValue", .dir = DIR_IN, .dir_opt = "", .type = PVOID},
            {.name = "Alertable", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtWaitForMultipleObjects32", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "Count", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Handles[]", .dir = DIR_IN, .dir_opt = "ecount(Count)", .type = LONG},
            {.name = "WaitType", .dir = DIR_IN, .dir_opt = "", .type = WAIT_TYPE},
            {.name = "Alertable", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtWaitForMultipleObjects", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "Count", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Handles[]", .dir = DIR_IN, .dir_opt = "ecount(Count)", .type = HANDLE},
            {.name = "WaitType", .dir = DIR_IN, .dir_opt = "", .type = WAIT_TYPE},
            {.name = "Alertable", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtWaitForSingleObject", .ret = NTSTATUS, .num_args = 3, .args =
        {
            {.name = "Handle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Alertable", .dir = DIR_IN, .dir_opt = "", .type = BOOLEAN},
            {.name = "Timeout", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER}
        }
    },
    {
        .name = "NtWaitForWorkViaWorkerFactory", .ret = NTSTATUS, .num_args = 2, .args =
        {
            {.name = "WorkerFactoryHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "MiniPacket", .dir = DIR_OUT, .dir_opt = "", .type = PFILE_IO_COMPLETION_INFORMATION}
        }
    },
    {
        .name = "NtWaitHighEventPair", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "EventPairHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtWaitLowEventPair", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "EventPairHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtWorkerFactoryWorkerReady", .ret = NTSTATUS, .num_args = 1, .args =
        {
            {.name = "WorkerFactoryHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE}
        }
    },
    {
        .name = "NtWriteFileGather", .ret = NTSTATUS, .num_args = 9, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "SegmentArray", .dir = DIR_IN, .dir_opt = "", .type = PFILE_SEGMENT_ELEMENT},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ByteOffset", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER},
            {.name = "Key", .dir = DIR_IN, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtWriteFile", .ret = NTSTATUS, .num_args = 9, .args =
        {
            {.name = "FileHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Event", .dir = DIR_IN, .dir_opt = "opt", .type = HANDLE},
            {.name = "ApcRoutine", .dir = DIR_IN, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
            {.name = "ApcContext", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "IoStatusBlock", .dir = DIR_OUT, .dir_opt = "", .type = PIO_STATUS_BLOCK},
            {.name = "Buffer", .dir = DIR_IN, .dir_opt = "bcount(Length)", .type = PVOID},
            {.name = "Length", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "ByteOffset", .dir = DIR_IN, .dir_opt = "opt", .type = PLARGE_INTEGER},
            {.name = "Key", .dir = DIR_IN, .dir_opt = "opt", .type = PULONG}
        }
    },
    {
        .name = "NtWriteRequestData", .ret = NTSTATUS, .num_args = 6, .args =
        {
            {.name = "PortHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "Message", .dir = DIR_IN, .dir_opt = "", .type = PPORT_MESSAGE},
            {.name = "DataEntryIndex", .dir = DIR_IN, .dir_opt = "", .type = ULONG},
            {.name = "Buffer", .dir = DIR_IN, .dir_opt = "bcount(BufferSize)", .type = PVOID},
            {.name = "BufferSize", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "NumberOfBytesWritten", .dir = DIR_OUT, .dir_opt = "opt", .type = PSIZE_T}
        }
    },
    {
        .name = "NtWriteVirtualMemory", .ret = NTSTATUS, .num_args = 5, .args =
        {
            {.name = "ProcessHandle", .dir = DIR_IN, .dir_opt = "", .type = HANDLE},
            {.name = "BaseAddress", .dir = DIR_IN, .dir_opt = "opt", .type = PVOID},
            {.name = "Buffer", .dir = DIR_IN, .dir_opt = "bcount(BufferSize)", .type = PVOID},
            {.name = "BufferSize", .dir = DIR_IN, .dir_opt = "", .type = SIZE_T},
            {.name = "NumberOfBytesWritten", .dir = DIR_OUT, .dir_opt = "opt", .type = PSIZE_T}
        }
    },

    // TODO: create full description for these functions
    { .name = "NtYieldExecution", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtAcquireProcessActivityReference", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtAddAtomEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtAlertThreadByThreadId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtAllocateVirtualMemoryEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtAlpcConnectPortEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtAlpcImpersonateClientContainerOfPort", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtAssociateWaitCompletionPacket", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCallEnclave", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCancelTimer2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCancelWaitCompletionPacket", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCommitRegistryTransaction", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCompareObjects", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCompareSigningLevels", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateDirectoryObjectEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateEnclave", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateIRTimer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateLowBoxToken", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreatePartition", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateRegistryTransaction", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateTimer2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateTokenEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateWaitCompletionPacket", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateWnfStateName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDeleteWnfStateData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDeleteWnfStateName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFilterBootOption", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlushBuffersFileEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGetCachedSigningLevel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGetCompleteWnfStateSubscription", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGetCurrentProcessorNumberEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtInitializeEnclave", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtLoadEnclaveData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtLoadHotPatch", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtManagePartition", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMapViewOfSectionEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtNotifyChangeDirectoryFileEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtOpenPartition", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtOpenRegistryTransaction", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryAuxiliaryCounterFrequency", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryDirectoryFileEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryInformationByName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQuerySecurityPolicy", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryWnfStateData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryWnfStateNameInformation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRevertContainerImpersonation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRollbackRegistryTransaction", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCachedSigningLevel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCachedSigningLevel2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetIRTimer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetInformationSymbolicLink", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetInformationVirtualMemory", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetTimer2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetWnfProcessNotificationEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSubscribeWnfStateChange", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTerminateEnclave", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUnmapViewOfSectionEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUnsubscribeWnfStateChange", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUpdateWnfStateData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtWaitForAlertByThreadId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateSectionEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtManageHotPatch", .ret = NTSTATUS, .num_args = 0 },

    // TODO: investigate what these functions are and why they appear in the SSDT (Windows 10)
    { .name = "BvgaSetVirtualFrameBuffer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "CmpCleanUpHigherLayerKcbCachesPreCallback", .ret = NTSTATUS, .num_args = 0 },
    { .name = "GetPnpProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "ArbPreprocessEntry", .ret = NTSTATUS, .num_args = 0 },
    { .name = "ArbAddReserved", .ret = NTSTATUS, .num_args = 0 },
};

static const syscall_definition_t win32k[] =
{
    { .name = "NtBindCompositionSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCloseCompositionInputSink", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCompositionInputThread", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCompositionSetDropTarget", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtConfigureInputSpace", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateCompositionInputSink", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateCompositionSurfaceHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtCreateImplicitCompositionInputSink", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionAddCrossDeviceVisualChild", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionAddVisualChild", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionAttachMouseWheelToHwnd", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionBeginFrame", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCapturePointer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCommitChannel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCommitSynchronizationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionConfirmFrame", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionConnectPipe", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCreateAndBindSharedSection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCreateChannel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCreateConnection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCreateConnectionContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCreateDwmChannel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCreateResource", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCreateSharedResourceHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCreateSharedVisualHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCreateSynchronizationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionCurrentBatchId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionDestroyChannel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionDestroyConnection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionDestroyConnectionContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionDiscardFrame", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionDuplicateHandleToProcess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionDuplicateSwapchainHandleToDwm", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionDwmSyncFlush", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionEnableDDASupport", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionEnableMMCSS", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionGetAnimationTime", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionGetBatchId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionGetChannels", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionGetConnectionBatch", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionGetConnectionContextBatch", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionGetDeletedResources", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionGetFrameLegacyTokens", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionGetFrameStatistics", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionGetFrameSurfaceUpdates", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionGetMaterialProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionOpenSharedResource", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionOpenSharedResourceHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionProcessChannelBatchBuffer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionReferenceSharedResourceOnDwmChannel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionRegisterThumbnailVisual", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionRegisterVirtualDesktopVisual", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionReleaseAllResources", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionReleaseResource", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionRemoveCrossDeviceVisualChild", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionRemoveVisualChild", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionReplaceVisualChildren", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionRetireFrame", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetChannelCallbackId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetChannelCommitCompletionEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetChannelConnectionId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetChildRootVisual", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetDebugCounter", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetMaterialProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetResourceAnimationProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetResourceBufferProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetResourceCallbackId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetResourceDeletedNotificationTag", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetResourceFloatProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetResourceHandleProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetResourceIntegerProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetResourceReferenceArrayProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetResourceReferenceProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSetVisualInputSink", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSignalGpuFence", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSubmitDWMBatch", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSuspendAnimations", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionSynchronize", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionTelemetryAnimationScenarioBegin", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionTelemetryAnimationScenarioReference", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionTelemetryAnimationScenarioUnreference", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionTelemetrySetApplicationId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionTelemetryTouchInteractionBegin", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionTelemetryTouchInteractionEnd", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionTelemetryTouchInteractionUpdate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionUpdatePointerCapture", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionValidateAndReferenceSystemVisualForHwndTarget", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDCompositionWaitForChannel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDWMBindCursorToOutputConfig", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDWMCommitInputSystemOutputConfig", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDWMSetCursorOrientation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDWMSetInputSystemOutputConfig", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDesktopCaptureBits", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDuplicateCompositionInputSink", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkCreateTrackedWorkload", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkDestroyTrackedWorkload", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkDispMgrOperation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkEndTrackedWorkload", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkGetAvailableTrackedWorkloadIndex", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkGetProcessList", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkGetTrackedWorkloadStatistics", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkOutputDuplPresentToHwQueue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkRegisterVailProcess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkResetTrackedWorkload", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkSubmitPresentBltToHwQueue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkSubmitPresentToHwQueue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkUpdateTrackedWorkload", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkVailConnect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkVailDisconnect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtDxgkVailPromoteCompositionSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtEnableOneCoreTransformMode", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectAddContent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectAddPoolBuffer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectConsumerAcquirePresent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectConsumerAdjustUsageReference", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectConsumerBeginProcessPresent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectConsumerEndProcessPresent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectConsumerPostMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectConsumerQueryBufferInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectCreate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectDisconnectEndpoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectOpen", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectPresentCancel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectQueryBufferAvailableEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectQueryEndpointConnected", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectQueryNextMessageToProducer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectReadNextMessageToProducer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectRemoveContent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectRemovePoolBuffer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtFlipObjectSetContent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiAbortDoc", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiAbortPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiAddEmbFontToDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiAddFontMemResourceEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiAddFontResourceW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiAddInitialFonts", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiAddRemoteFontToDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiAddRemoteMMInstanceToDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiAlphaBlend", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiAngleArc", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiAnyLinkedFonts", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiArcInternal", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiBRUSHOBJ_DeleteRbrush", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiBRUSHOBJ_hGetColorTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiBRUSHOBJ_pvAllocRbrush", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiBRUSHOBJ_pvGetRbrush", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiBRUSHOBJ_ulGetBrushColor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiBeginGdiRendering", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiBeginPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiBitBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCLIPOBJ_bEnum", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCLIPOBJ_cEnumStart", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCLIPOBJ_ppoGetPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCancelDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiChangeGhostFont", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCheckBitmapBits", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiClearBitmapAttributes", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiClearBrushAttributes", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCloseFigure", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiColorCorrectPalette", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCombineRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCombineTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiComputeXformCoefficients", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiConfigureOPMProtectedOutput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiConsoleTextOut", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiConvertMetafileRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateBitmap", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateBitmapFromDxSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateBitmapFromDxSurface2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateClientObj", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateColorSpace", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateColorTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateCompatibleBitmap", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateCompatibleDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateDIBBrush", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateDIBSection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateDIBitmapInternal", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateEllipticRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateHalftonePalette", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateHatchBrushInternal", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateMetafileDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateOPMProtectedOutput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateOPMProtectedOutputs", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreatePaletteInternal", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreatePatternBrushInternal", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreatePen", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateRectRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateRoundRectRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateServerMetaFile", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateSessionMappedDIBSection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiCreateSolidBrush", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiD3dContextCreate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiD3dContextDestroy", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiD3dContextDestroyAll", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiD3dDrawPrimitives2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiD3dValidateTextureStageState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDDCCIGetCapabilitiesString", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDDCCIGetCapabilitiesStringLength", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDDCCIGetTimingReport", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDDCCIGetVCPFeature", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDDCCISaveCurrentSettings", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDDCCISetVCPFeature", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdAddAttachedSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdAlphaBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdAttachSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdBeginMoCompFrame", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdCanCreateD3DBuffer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdCanCreateSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdColorControl", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdCreateD3DBuffer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdCreateDirectDrawObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdCreateFullscreenSprite", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdCreateMoComp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdCreateSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdCreateSurfaceEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdCreateSurfaceObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIAbandonSwapChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIAcquireKeyedMutex", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIAcquireKeyedMutex2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIAcquireSwapChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIAddSurfaceToSwapChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIAdjustFullscreenGamma", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICacheHybridQueryValue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIChangeVideoMemoryReservation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICheckExclusiveOwnership", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICheckMonitorPowerState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICheckMultiPlaneOverlaySupport", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICheckMultiPlaneOverlaySupport2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICheckMultiPlaneOverlaySupport3", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICheckOcclusion", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICheckSharedResourceAccess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICheckVidPnExclusiveOwnership", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICloseAdapter", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIConfigureSharedResource", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateAllocation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateBundleObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateContextVirtual", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateDCFromMemory", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateDevice", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateHwContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateHwQueue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateKeyedMutex", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateKeyedMutex2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateOutputDupl", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateOverlay", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreatePagingQueue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateProtectedSession", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateSwapChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDICreateSynchronizationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDDisplayEnum", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyAllocation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyAllocation2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyDCFromMemory", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyDevice", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyHwContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyHwQueue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyKeyedMutex", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyOutputDupl", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyOverlay", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyPagingQueue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroyProtectedSession", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDestroySynchronizationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDispMgrCreate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDispMgrSourceOperation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIDispMgrTargetOperation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIEnumAdapters", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIEnumAdapters2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIEscape", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIEvict", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIExtractBundleObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIFlipOverlay", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIFlushHeapTransitions", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIFreeGpuVirtualAddress", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetAllocationPriority", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetCachedHybridQueryValue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetContextInProcessSchedulingPriority", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetContextSchedulingPriority", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetDWMVerticalBlankEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetDeviceState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetDisplayModeList", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetMemoryBudgetTarget", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetMultiPlaneOverlayCaps", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetMultisampleMethodList", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetOverlayState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetPostCompositionCaps", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetPresentHistory", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetPresentQueueEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetProcessDeviceLostSupport", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetProcessDeviceRemovalSupport", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetProcessSchedulingPriorityBand", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetProcessSchedulingPriorityClass", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetResourcePresentPrivateDriverData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetRuntimeData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetScanLine", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetSetSwapChainMetadata", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetSharedPrimaryHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetSharedResourceAdapterLuid", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetSharedResourceAdapterLuidFlipManager", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIGetYieldPercentage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIInvalidateActiveVidPn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIInvalidateCache", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDILock", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDILock2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIMakeResident", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIMapGpuVirtualAddress", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIMarkDeviceAsError", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDINetDispGetNextChunkInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDINetDispQueryMiracastDisplayDeviceStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDINetDispQueryMiracastDisplayDeviceSupport", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDINetDispStartMiracastDisplayDevice", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDINetDispStartMiracastDisplayDeviceEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDINetDispStopMiracastDisplayDevice", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDINetDispStopSessions", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOfferAllocations", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenAdapterFromDeviceName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenAdapterFromHdc", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenAdapterFromLuid", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenBundleObjectNtHandleFromName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenKeyedMutex", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenKeyedMutex2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenKeyedMutexFromNtHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenNtHandleFromName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenProtectedSessionFromNtHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenResource", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenResourceFromNtHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenSwapChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenSyncObjectFromNtHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenSyncObjectFromNtHandle2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenSyncObjectNtHandleFromName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOpenSynchronizationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOutputDuplGetFrameInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOutputDuplGetMetaData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOutputDuplGetPointerShapeData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOutputDuplPresent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIOutputDuplReleaseFrame", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIPinDirectFlipResources", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIPollDisplayChildren", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIPresent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIPresentMultiPlaneOverlay", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIPresentMultiPlaneOverlay2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIPresentMultiPlaneOverlay3", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIPresentRedirected", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryAdapterInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryAllocationResidency", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryClockCalibration", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryFSEBlock", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryProcessOfferInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryProtectedSessionInfoFromNtHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryProtectedSessionStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryRemoteVidPnSourceFromGdiDisplayName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryResourceInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryResourceInfoFromNtHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryStatistics", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryVidPnExclusiveOwnership", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIQueryVideoMemoryInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIReclaimAllocations", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIReclaimAllocations2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIReleaseKeyedMutex", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIReleaseKeyedMutex2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIReleaseProcessVidPnSourceOwners", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIReleaseSwapChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIRemoveSurfaceFromSwapChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIRender", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIReserveGpuVirtualAddress", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetAllocationPriority", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetContextInProcessSchedulingPriority", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetContextSchedulingPriority", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetDeviceLostSupport", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetDisplayMode", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetDisplayPrivateDriverFormat", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetDodIndirectSwapchain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetFSEBlock", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetGammaRamp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetHwProtectionTeardownRecovery", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetMemoryBudgetTarget", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetMonitorColorSpaceTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetProcessDeviceRemovalSupport", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetProcessSchedulingPriorityBand", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetProcessSchedulingPriorityClass", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetQueuedLimit", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetStablePowerState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetStereoEnabled", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetSyncRefreshCountWaitTarget", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetVidPnSourceHwProtection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetVidPnSourceOwner", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetVidPnSourceOwner1", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISetYieldPercentage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIShareObjects", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISharedPrimaryLockNotification", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISharedPrimaryUnLockNotification", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISignalSynchronizationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISignalSynchronizationObjectFromCpu", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISignalSynchronizationObjectFromGpu", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISignalSynchronizationObjectFromGpu2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISubmitCommand", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISubmitCommandToHwQueue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISubmitSignalSyncObjectsToHwQueue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDISubmitWaitForSyncObjectsToHwQueue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDITrimProcessCommitment", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIUnOrderedPresentSwapChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIUnlock", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIUnlock2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIUnpinDirectFlipResources", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIUpdateAllocationProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIUpdateGpuVirtualAddress", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIUpdateOverlay", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIWaitForIdle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIWaitForSynchronizationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIWaitForSynchronizationObjectFromCpu", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIWaitForSynchronizationObjectFromGpu", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIWaitForVerticalBlankEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDDIWaitForVerticalBlankEvent2", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDeleteDirectDrawObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDeleteSurfaceObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDestroyD3DBuffer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDestroyFullscreenSprite", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDestroyMoComp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdDestroySurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdEndMoCompFrame", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdFlip", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdFlipToGDISurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetAvailDriverMemory", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetBltStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetDriverInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetDriverState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetDxHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetFlipStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetInternalMoCompInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetMoCompBuffInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetMoCompFormats", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetMoCompGuids", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdGetScanLine", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdLock", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdLockD3D", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdNotifyFullscreenSpriteUpdate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdQueryDirectDrawObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdQueryMoCompStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdQueryVisRgnUniqueness", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdReenableDirectDrawObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdReleaseDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdRenderMoComp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdResetVisrgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdSetColorKey", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdSetExclusiveMode", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdSetGammaRamp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdSetOverlayPosition", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdUnattachSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdUnlock", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdUnlockD3D", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdUpdateOverlay", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDdWaitForVerticalBlank", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDeleteClientObj", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDeleteColorSpace", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDeleteColorTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDeleteObjectApp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDescribePixelFormat", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDestroyOPMProtectedOutput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDestroyPhysicalMonitor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDoBanding", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDoPalette", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDrawEscape", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDrawStream", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpAcquireNotification", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpCanCreateVideoPort", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpColorControl", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpCreateVideoPort", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpDestroyVideoPort", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpFlipVideoPort", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpGetVideoPortBandwidth", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpGetVideoPortConnectInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpGetVideoPortField", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpGetVideoPortFlipStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpGetVideoPortInputFormats", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpGetVideoPortLine", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpGetVideoPortOutputFormats", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpGetVideoSignalStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpReleaseNotification", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpUpdateVideoPort", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDvpWaitForVideoPortSync", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDwmCreatedBitmapRemotingOutput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDwmGetDirtyRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDwmGetSurfaceData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiDxgGenericThunk", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEllipse", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEnableEudc", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEndDoc", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEndGdiRendering", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEndPage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEndPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngAlphaBlend", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngAssociateSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngBitBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngCheckAbort", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngComputeGlyphSet", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngCopyBits", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngCreateBitmap", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngCreateClip", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngCreateDeviceBitmap", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngCreateDeviceSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngCreatePalette", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngDeleteClip", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngDeletePalette", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngDeletePath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngDeleteSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngEraseSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngFillPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngGradientFill", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngLineTo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngLockSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngMarkBandingSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngPaint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngPlgBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngStretchBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngStretchBltROP", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngStrokeAndFillPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngStrokePath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngTextOut", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngTransparentBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEngUnlockSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEnsureDpiDepDefaultGuiFontForPlateau", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEnumFontChunk", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEnumFontClose", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEnumFontOpen", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEnumFonts", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEnumObjects", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEqualRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiEudcLoadUnloadLink", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiExcludeClipRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiExtCreatePen", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiExtCreateRegion", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiExtEscape", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiExtFloodFill", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiExtGetObjectW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiExtSelectClipRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiExtTextOutW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFONTOBJ_cGetAllGlyphHandles", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFONTOBJ_cGetGlyphs", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFONTOBJ_pQueryGlyphAttrs", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFONTOBJ_pfdg", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFONTOBJ_pifi", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFONTOBJ_pvTrueTypeFontFile", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFONTOBJ_pxoGetXform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFONTOBJ_vGetInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFillPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFillRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFlattenPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFlush", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFontIsLinked", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiForceUFIMapping", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFrameRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiFullscreenControl", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetAndSetDCDword", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetAppClipBox", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetAppliedDeviceGammaRamp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetBitmapBits", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetBitmapDimension", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetBitmapDpiScaleValue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetBoundsRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetCOPPCompatibleOPMInformation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetCertificate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetCertificateByHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetCertificateSize", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetCertificateSizeByHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetCharABCWidthsW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetCharSet", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetCharWidthInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetCharWidthW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetCharacterPlacementW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetColorAdjustment", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetColorSpaceforBitmap", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetCurrentDpiInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetDCDpiScaleValue", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetDCDword", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetDCObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetDCPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetDCforBitmap", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetDIBitsInternal", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetDeviceCaps", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetDeviceCapsAll", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetDeviceGammaRamp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetDeviceWidth", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetDhpdev", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetETM", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetEmbUFI", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetEmbedFonts", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetEntry", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetEudcTimeStampEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetFontData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetFontFileData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetFontFileInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetFontResourceInfoInternalW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetFontUnicodeRanges", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetGammaRampCapability", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetGlyphIndicesW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetGlyphIndicesWInternal", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetGlyphOutline", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetKerningPairs", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetLinkedUFIs", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetMiterLimit", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetMonitorID", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetNearestColor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetNearestPaletteIndex", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetNumberOfPhysicalMonitors", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetOPMInformation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetOPMRandomNumber", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetObjectBitmapHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetOutlineTextMetricsInternalW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetPerBandInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetPhysicalMonitorDescription", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetPhysicalMonitors", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetPixel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetProcessSessionFonts", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetPublicFontTableChangeCookie", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetRandomRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetRasterizerCaps", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetRealizationInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetRegionData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetRgnBox", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetServerMetaFileBits", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetSpoolMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetStats", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetStockObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetStringBitmapW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetSuggestedOPMProtectedOutputArraySize", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetSystemPaletteUse", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetTextCharsetInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetTextExtent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetTextExtentExW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetTextFaceW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetTextMetricsW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetUFI", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetUFIPathname", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGetWidthTable", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiGradientFill", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiHLSurfGetInformation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiHLSurfSetInformation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiHT_Get8BPPFormatPalette", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiHT_Get8BPPMaskPalette", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiHfontCreate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiIcmBrushInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiInit", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiInitSpool", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiIntersectClipRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiInvertRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiLineTo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiMakeFontDir", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiMakeInfoDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiMakeObjectUnXferable", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiMakeObjectXferable", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiMaskBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiMirrorWindowOrg", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiModifyWorldTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiMonoBitmap", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiMoveTo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiOffsetClipRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiOffsetRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiOpenDCW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPATHOBJ_bEnum", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPATHOBJ_bEnumClipLines", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPATHOBJ_vEnumStart", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPATHOBJ_vEnumStartClipLines", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPATHOBJ_vGetBounds", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPatBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPathToRegion", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPlgBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPolyDraw", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPolyPatBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPolyPolyDraw", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPolyTextOutW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPtInRegion", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiPtVisible", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiQueryFontAssocInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiQueryFonts", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiRectInRegion", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiRectVisible", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiRectangle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiRemoveFontMemResourceEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiRemoveFontResourceW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiRemoveMergeFont", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiResetDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiResizePalette", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiRestoreDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiRoundRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSTROBJ_bEnum", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSTROBJ_bEnumPositionsOnly", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSTROBJ_bGetAdvanceWidths", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSTROBJ_dwGetCodePage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSTROBJ_vEnumStart", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSaveDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiScaleRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiScaleValues", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiScaleViewportExtEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiScaleWindowExtEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSelectBitmap", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSelectBrush", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSelectClipPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSelectFont", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSelectPen", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetBitmapAttributes", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetBitmapBits", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetBitmapDimension", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetBoundsRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetBrushAttributes", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetBrushOrg", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetColorAdjustment", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetColorSpace", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetDIBitsToDeviceInternal", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetDeviceGammaRamp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetFontEnumeration", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetFontXform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetIcmMode", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetLayout", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetLinkedUFIs", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetMagicColors", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetMetaRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetMiterLimit", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetOPMSigningKeyAndSequenceNumbers", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetPUMPDOBJ", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetPixel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetPixelFormat", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetPrivateDeviceGammaRamp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetRectRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetSizeDevice", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetSystemPaletteUse", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetTextJustification", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetUMPDSandboxState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetVirtualResolution", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSetupPublicCFONT", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSfmGetNotificationTokens", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiStartDoc", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiStartPage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiStretchBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiStretchDIBitsInternal", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiStrokeAndFillPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiStrokePath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiSwapBuffers", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiTransformPoints", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiTransparentBlt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiUMPDEngFreeUserMem", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiUnloadPrinterDriver", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiUnmapMemFont", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiUnrealizeObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiUpdateColors", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiUpdateTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiWidenPath", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiXFORMOBJ_bApplyXform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiXFORMOBJ_iGetXform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiXLATEOBJ_cGetPalette", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiXLATEOBJ_hGetColorTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtGdiXLATEOBJ_iXlate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtHWCursorUpdatePointer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtIsOneCoreTransformMode", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITActivateInputProcessing", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITBindInputTypeToMonitors", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITCoreMsgKGetConnectionHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITCoreMsgKOpenConnectionTo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITCoreMsgKSend", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITDeactivateInputProcessing", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITDisableMouseIntercept", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITDispatchCompletion", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITEnableMouseIntercept", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITGetCursorUpdateHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITSetInputCallbacks", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITSetInputDelegationMode", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITSetInputSuppressionState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITSetKeyboardInputRoutingPolicy", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITSetKeyboardOverriderState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITSetLastInputRecipient", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITSynthesizeKeyboardInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITSynthesizeMouseInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITSynthesizeMouseWheel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITSynthesizeTouchInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITUpdateInputGlobals", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMITWaitForMultipleObjectsEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtMapVisualRelativePoints", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtNotifyPresentToCompositionSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtOpenCompositionSurfaceDirtyRegion", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtOpenCompositionSurfaceSectionInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtOpenCompositionSurfaceSwapChainHandleInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryCompositionInputIsImplicit", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryCompositionInputQueueAndTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryCompositionInputSink", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryCompositionInputSinkLuid", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryCompositionInputSinkViewId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryCompositionSurfaceBinding", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryCompositionSurfaceHDRMetaData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryCompositionSurfaceRenderingRealization", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtQueryCompositionSurfaceStatistics", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMAddInputObserver", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMAreSiblingDevices", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMDeviceIoControl", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMEnableMonitorMappingForDevice", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMFreeInputBuffer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMGetDevicePreparsedData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMGetDevicePreparsedDataLockfree", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMGetDeviceProperties", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMGetDevicePropertiesLockfree", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMGetPhysicalDeviceRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMGetSourceProcessId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMObserveNextInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMOnPnpNotification", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMOnTimerNotification", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMReadInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMRegisterForInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMRemoveInputObserver", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMSetExtendedDeviceProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMSetTestModeStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMUnregisterForInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtRIMUpdateInputObserverRegistration", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCompositionSurfaceAnalogExclusive", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCompositionSurfaceBufferCompositionMode", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCompositionSurfaceBufferCompositionModeAndOrientation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCompositionSurfaceBufferUsage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCompositionSurfaceDirectFlipState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCompositionSurfaceHDRMetaData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCompositionSurfaceIndependentFlipInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCompositionSurfaceOutOfFrameDirectFlipNotification", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCompositionSurfaceStatistics", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetCursorInputSpace", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetPointerDeviceInputSpace", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtSetShellCursorState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerConfirmOutstandingAnalogToken", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerCreateCompositionTokenHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerCreateFlipObjectReturnTokenHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerCreateFlipObjectTokenHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerDeleteOutstandingDirectFlipTokens", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerGetAnalogExclusiveSurfaceUpdates", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerGetAnalogExclusiveTokenEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerGetOutOfFrameDirectFlipSurfaceUpdates", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerOpenEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerOpenSection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerOpenSectionAndEvents", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtTokenManagerThread", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUnBindCompositionSurface", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUpdateInputSinkTransforms", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserAcquireIAMKey", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserAcquireInteractiveControlBackgroundAccess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserActivateKeyboardLayout", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserAddClipboardFormatListener", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserAddVisualIdentifier", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserAlterWindowStyle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserAssociateInputContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserAttachThreadInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserAutoPromoteMouseInPointer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserAutoRotateScreen", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserBeginLayoutUpdate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserBeginPaint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserBitBltSysBmp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserBlockInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserBroadcastThemeChangeEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserBuildHimcList", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserBuildHwndList", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserBuildNameList", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserBuildPropList", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCalcMenuBar", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCalculatePopupWindowPosition", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallHwnd", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallHwndLock", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallHwndLockSafe", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallHwndOpt", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallHwndParam", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallHwndParamLock", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallHwndParamLockSafe", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallHwndSafe", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallMsgFilter", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallNextHookEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallNoParam", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallOneParam", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCallTwoParam", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCanBrokerForceForeground", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserChangeClipboardChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserChangeDisplaySettings", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserChangeWindowMessageFilterEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCheckAccessForIntegrityLevel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCheckDesktopByThreadId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCheckImeHotKey", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCheckMenuItem", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCheckProcessForClipboardAccess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCheckProcessSession", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCheckWindowThreadDesktop", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserChildWindowFromPointEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserClearForeground", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserClipCursor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCloseClipboard", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCloseDesktop", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCloseWindowStation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCompositionInputSinkLuidFromPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCompositionInputSinkViewInstanceIdFromPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserConfigureActivationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserConfirmResizeCommit", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserConsoleControl", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserConvertMemHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCopyAcceleratorTable", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCountClipboardFormats", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateAcceleratorTable", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateActivationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateCaret", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateDCompositionHwndTarget", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateDesktop", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateDesktopEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateEmptyCursorObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateInputContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateLocalMemHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreatePalmRejectionDelayZone", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateWindowEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateWindowGroup", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCreateWindowStation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserCtxDisplayIOCtl", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDdeGetQualityOfService", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDdeInitialize", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDdeSetQualityOfService", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDefSetText", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDeferWindowDpiChanges", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDeferWindowPos", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDeferWindowPosAndBand", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDelegateCapturePointers", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDelegateInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDeleteMenu", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDeleteWindowGroup", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDestroyAcceleratorTable", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDestroyActivationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDestroyCursor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDestroyDCompositionHwndTarget", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDestroyInputContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDestroyMenu", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDestroyPalmRejectionDelayZone", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDestroyWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDisableImmersiveOwner", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDisableProcessWindowFiltering", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDisableThreadIme", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDiscardPointerFrameMessages", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDispatchMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDisplayConfigGetDeviceInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDisplayConfigSetDeviceInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDoSoundConnect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDoSoundDisconnect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDownlevelTouchpad", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDragDetect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDragObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDrawAnimatedRects", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDrawCaption", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDrawCaptionTemp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDrawIconEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDrawMenuBarTemp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDwmGetDxRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDwmGetRemoteSessionOcclusionEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDwmGetRemoteSessionOcclusionState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDwmHintDxUpdate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDwmKernelShutdown", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDwmKernelStartup", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDwmStartRedirection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDwmStopRedirection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserDwmValidateWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEmptyClipboard", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableChildWindowDpiMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableIAMAccess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableMenuItem", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableMouseInPointer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableMouseInputForCursorSuppression", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableNonClientDpiScaling", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableResizeLayoutSynchronization", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableScrollBar", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableSoftwareCursorForScreenCapture", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableTouchPad", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableWindowGDIScaledDpiMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableWindowGroupPolicy", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnableWindowResizeOptimization", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEndDeferWindowPosEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEndMenu", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEndPaint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEndTouchOperation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnumDisplayDevices", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnumDisplayMonitors", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEnumDisplaySettings", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserExcludeUpdateRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserFillWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserFindExistingCursorIcon", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserFindWindowEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserFlashWindowEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserForceWindowToDpiForTest", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserFrostCrashedWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserFunctionalizeDisplayConfig", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetActiveProcessesDpis", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetAltTabInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetAncestor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetAppImeLevel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetAsyncKeyState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetAtomName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetAutoRotationState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetCIMSSM", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetCPD", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetCaretBlinkTime", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetCaretPos", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetClassInfoEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetClassName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetClipCursor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetClipboardAccessToken", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetClipboardData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetClipboardFormatName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetClipboardOwner", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetClipboardSequenceNumber", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetClipboardViewer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetComboBoxInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetControlBrush", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetControlColor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetCurrentDpiInfoForWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetCurrentInputMessageSource", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetCursor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetCursorDims", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetCursorFrameInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetCursorInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetDCEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetDManipHookInitFunction", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetDesktopID", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetDisplayAutoRotationPreferences", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetDisplayAutoRotationPreferencesByProcessId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetDisplayConfigBufferSizes", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetDoubleClickTime", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetDpiForCurrentProcess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetDpiForMonitor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetDpiSystemMetrics", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetExtendedPointerDeviceProperty", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetForegroundWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetGUIThreadInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetGestureConfig", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetGestureExtArgs", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetGestureInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetGlobalIMEStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetGuiResources", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetHDevName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetHimetricScaleFactorFromPixelLocation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetIconInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetIconSize", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetImeHotKey", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetImeInfoEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetInputContainerId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetInputLocaleInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetInteractiveControlDeviceInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetInteractiveControlInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetInteractiveCtrlSupportedWaveforms", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetInternalWindowPos", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetKeyNameText", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetKeyState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetKeyboardLayout", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetKeyboardLayoutList", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetKeyboardLayoutName", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetKeyboardState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetLayeredWindowAttributes", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetListBoxInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetMenuBarInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetMenuIndex", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetMenuItemRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetMonitorBrightness", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetMouseMovePointsEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetObjectInformation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetOemBitmapSize", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetOpenClipboardWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetOwnerTransformedMonitorRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPhysicalDeviceRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerCursorId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerDevice", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerDeviceCursors", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerDeviceOrientation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerDeviceProperties", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerDeviceRects", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerDevices", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerFrameArrivalTimes", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerFrameTimes", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerInfoList", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerInputTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerProprietaryId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPointerType", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPrecisionTouchPadConfiguration", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetPriorityClipboardFormat", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetProcessDpiAwareness", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetProcessDpiAwarenessContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetProcessUIContextInformation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetProcessWindowStation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetProp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetQueueEventStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetQueueStatusReadonly", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetRawInputBuffer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetRawInputData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetRawInputDeviceInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetRawInputDeviceList", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetRawPointerDeviceData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetRegisteredRawInputDevices", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetRequiredCursorSizes", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetResizeDCompositionSynchronizationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetScrollBarInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetSystemDpiForProcess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetSystemMenu", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetThreadDesktop", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetThreadState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetTitleBarInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetTopLevelWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetTouchInputInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetTouchValidationStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetUniformSpaceMapping", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetUpdateRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetUpdateRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetUpdatedClipboardFormats", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWOWClass", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWindowBand", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWindowCompositionAttribute", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWindowCompositionInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWindowDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWindowDisplayAffinity", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWindowFeedbackSetting", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWindowGroupId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWindowMinimizeRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWindowPlacement", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWindowProcessHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGetWindowRgnEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserGhostWindowFromHungWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserHandleDelegatedInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserHardErrorControl", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserHideCaret", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserHidePointerContactVisualization", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserHiliteMenuItem", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserHungWindowFromGhostWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserHwndQueryRedirectionInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserHwndSetRedirectionInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserImpersonateDdeClientWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInheritWindowMonitor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInitTask", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInitialize", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInitializeClientPfnArrays", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInitializeGenericHidInjection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInitializeInputDeviceInjection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInitializePointerDeviceInjection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInitializePointerDeviceInjectionEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInitializeTouchInjection", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInjectDeviceInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInjectGenericHidInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInjectGesture", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInjectKeyboardInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInjectMouseInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInjectPointerInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInjectTouchInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInteractiveControlQueryUsage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInternalClipCursor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInternalGetWindowIcon", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInternalGetWindowText", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInvalidateRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserInvalidateRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserIsChildWindowDpiMessageEnabled", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserIsClipboardFormatAvailable", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserIsMouseInPointerEnabled", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserIsMouseInputEnabled", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserIsNonClientDpiScalingEnabled", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserIsResizeLayoutSynchronizationEnabled", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserIsTopLevelWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserIsTouchWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserIsWindowBroadcastingDpiToChildren", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserIsWindowGDIScaledDpiMessageEnabled", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserKillTimer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserLayoutCompleted", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserLinkDpiCursor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserLoadKeyboardLayoutEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserLockCursor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserLockWindowStation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserLockWindowUpdate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserLockWorkStation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserLogicalToPerMonitorDPIPhysicalPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserLogicalToPhysicalDpiPointForWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserLogicalToPhysicalPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMNDragLeave", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMNDragOver", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMagControl", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMagGetContextInformation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMagSetContextInformation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserManageGestureHandlerWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMapPointsByVisualIdentifier", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMapVirtualKeyEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMenuItemFromPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMessageCall", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMinMaximize", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserModifyUserStartupInfoFlags", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserModifyWindowTouchCapability", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMoveWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserMsgWaitForMultipleObjectsEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserNavigateFocus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserNotifyIMEStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserNotifyProcessCreate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserNotifyWinEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserOpenClipboard", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserOpenDesktop", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserOpenInputDesktop", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserOpenThreadDesktop", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserOpenWindowStation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPaintDesktop", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPaintMenuBar", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPaintMonitor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPeekMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPerMonitorDPIPhysicalToLogicalPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPhysicalToLogicalDpiPointForWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPhysicalToLogicalPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPostMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPostThreadMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPrintWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserProcessConnect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserProcessInkFeedbackCommand", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPromoteMouseInPointer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserPromotePointer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserQueryActivationObject", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserQueryBSDRWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserQueryDisplayConfig", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserQueryInformationThread", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserQueryInputContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserQuerySendMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserQueryWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRealChildWindowFromPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRealInternalGetMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRealWaitMessageEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRedrawWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterBSDRWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterClassExWOW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterDManipHook", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterEdgy", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterErrorReportingDialog", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterHotKey", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterManipulationThread", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterPointerDeviceNotifications", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterPointerInputTarget", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterRawInputDevices", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterServicesProcess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterSessionPort", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterShellPTPListener", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterTasklist", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterTouchHitTestingWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterTouchPadCapable", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterUserApiHook", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRegisterWindowMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserReleaseDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserReleaseDwmHitTestWaiters", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRemoteConnect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRemoteRedrawRectangle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRemoteRedrawScreen", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRemoteStopScreenUpdates", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRemoveClipboardFormatListener", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRemoveInjectionDevice", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRemoveMenu", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRemoveProp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRemoveVisualIdentifier", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserReportInertia", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRequestMoveSizeOperation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserResolveDesktop", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserResolveDesktopForWOW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserRestoreWindowDpiChanges", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSBGetParms", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserScrollDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserScrollWindowEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSelectPalette", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSendEventMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSendInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSendInteractiveControlHapticsReport", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSendTouchInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetActivationFilter", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetActiveProcess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetActiveProcessForMonitor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetActiveWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetAppImeLevel", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetAutoRotation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetBridgeWindowChild", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetBrokeredForeground", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetCalibrationData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetCapture", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetChildWindowNoActivate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetClassLong", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetClassLongPtr", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetClassWord", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetClipboardData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetClipboardViewer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetConsoleReserveKeys", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetCoreWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetCoreWindowPartner", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetCursor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetCursorContents", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetCursorIconData", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetCursorPos", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetDesktopColorTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetDialogControlDpiChangeBehavior", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetDimUndimTransitionTime", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetDisplayAutoRotationPreferences", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetDisplayConfig", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetDisplayMapping", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetFallbackForeground", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetFeatureReportResponse", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetFocus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetForegroundWindowForApplication", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetGestureConfig", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetImeHotKey", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetImeInfoEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetImeOwnerWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetImmersiveBackgroundWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetInformationProcess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetInformationThread", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetInteractiveControlFocus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetInteractiveCtrlRotationAngle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetInternalWindowPos", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetKeyboardState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetLayeredWindowAttributes", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetLogonNotifyWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetMagnificationDesktopMagnifierOffsetsDWMUpdated", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetManipulationInputTarget", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetMenu", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetMenuContextHelpId", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetMenuDefaultItem", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetMenuFlagRtoL", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetMirrorRendering", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetMonitorBrightness", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetObjectInformation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetParent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetPrecisionTouchPadConfiguration", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetProcessDPIAware", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetProcessDpiAwareness", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetProcessDpiAwarenessContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetProcessInteractionFlags", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetProcessMousewheelRoutingMode", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetProcessRestrictionExemption", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetProcessUIAccessZorder", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetProcessWindowStation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetProp", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetScrollInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetSensorPresence", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetShellWindowEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetSysColors", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetSystemCursor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetSystemMenu", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetSystemTimer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetTargetForResourceBrokering", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetThreadDesktop", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetThreadInputBlocked", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetThreadLayoutHandles", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetThreadState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetTimer", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWinEventHook", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowArrangement", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowBand", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowCompositionAttribute", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowCompositionTransition", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowDisplayAffinity", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowFNID", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowFeedbackSetting", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowGroup", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowLong", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowLongPtr", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowPlacement", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowPos", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowRgn", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowRgnEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowShowState", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowStationUser", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowWord", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowsHookAW", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSetWindowsHookEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSfmDestroyLogicalSurfaceBinding", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSfmDxBindSwapChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSfmDxGetSwapChainStats", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSfmDxOpenSwapChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSfmDxQuerySwapChainBindingStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSfmDxReleaseSwapChain", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSfmDxReportPendingBindingsToDwm", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSfmDxSetSwapChainBindingStatus", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSfmDxSetSwapChainStats", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSfmGetLogicalSurfaceBinding", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserShowCaret", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserShowCursor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserShowScrollBar", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserShowSystemCursor", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserShowWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserShowWindowAsync", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserShutdownBlockReasonCreate", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserShutdownBlockReasonQuery", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserShutdownReasonDestroy", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSignalRedirectionStartComplete", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSlicerControl", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSoundSentry", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserStopAndEndInertia", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSwitchDesktop", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSystemParametersInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserSystemParametersInfoForDpi", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserTestForInteractiveUser", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserThunkedMenuInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserThunkedMenuItemInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserToUnicodeEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserTrackMouseEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserTrackPopupMenuEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserTransformPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserTransformRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserTranslateAccelerator", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserTranslateMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUndelegateInput", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUnhookWinEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUnhookWindowsHookEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUnloadKeyboardLayout", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUnlockWindowStation", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUnregisterClass", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUnregisterHotKey", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUnregisterSessionPort", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUnregisterUserApiHook", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUpdateDefaultDesktopThumbnail", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUpdateInputContext", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUpdateInstance", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUpdateLayeredWindow", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUpdatePerUserSystemParameters", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUpdateWindowInputSinkHints", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUpdateWindowTrackingInfo", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUpdateWindowTransform", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserUserHandleGrantAccess", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserValidateHandleSecure", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserValidateRect", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserValidateTimerCallback", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserVkKeyScanEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserWOWCleanup", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserWaitAvailableMessageEx", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserWaitForInputIdle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserWaitForMsgAndEvent", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserWaitForRedirectionStartComplete", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserWaitMessage", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserWin32PoolAllocationStats", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserWindowFromDC", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserWindowFromPhysicalPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserWindowFromPoint", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtUserYieldTask", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtValidateCompositionSurfaceHandle", .ret = NTSTATUS, .num_args = 0 },
    { .name = "NtVisualCaptureBits", .ret = NTSTATUS, .num_args = 0 },
};

#define NUM_SYSCALLS_NT sizeof(nt)/sizeof(syscall_definition_t)
#define NUM_SYSCALLS_WIN32K sizeof(win32k)/sizeof(syscall_definition_t)

#endif
