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

#ifndef SYSCALLS_WIN_H
#define SYSCALLS_WIN_H

namespace syscalls_ns
{

void setup_windows(drakvuf_t drakvuf, syscalls* s, const syscalls_config* c);
char* win_extract_string(syscalls* s, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val);

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

typedef struct sst_x64
{
    uint64_t ServiceTable;
    uint64_t CounterTable;
    uint64_t ServiceLimit;
    uint64_t ArgumentTable;
} __attribute__((packed)) system_service_table_x64;

typedef struct sst_x86
{
    uint32_t ServiceTable;
    uint32_t CounterTable;
    uint32_t ServiceLimit;
    uint32_t ArgumentTable;
} __attribute__((packed)) system_service_table_x86;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"

SYSCALL(NtAcceptConnectPort, NTSTATUS,
    "PortHandle", "", DIR_OUT, PHANDLE,
    "PortContext", "opt", DIR_IN, PVOID,
    "ConnectionRequest", "", DIR_IN, PPORT_MESSAGE,
    "AcceptConnection", "", DIR_IN, BOOLEAN,
    "ServerView", "opt", DIR_INOUT, PPORT_VIEW,
    "ClientView", "opt", DIR_OUT, PREMOTE_PORT_VIEW,
);
SYSCALL(NtAccessCheckAndAuditAlarm, NTSTATUS,
    "SubsystemName", "", DIR_IN, PUNICODE_STRING,
    "HandleId", "opt", DIR_IN, PVOID,
    "ObjectTypeName", "", DIR_IN, PUNICODE_STRING,
    "ObjectName", "", DIR_IN, PUNICODE_STRING,
    "SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "GenericMapping", "", DIR_IN, PGENERIC_MAPPING,
    "ObjectCreation", "", DIR_IN, BOOLEAN,
    "GrantedAccess", "", DIR_OUT, PACCESS_MASK,
    "AccessStatus", "", DIR_OUT, PNTSTATUS,
    "GenerateOnClose", "", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtAccessCheckByTypeAndAuditAlarm, NTSTATUS,
    "SubsystemName", "", DIR_IN, PUNICODE_STRING,
    "HandleId", "opt", DIR_IN, PVOID,
    "ObjectTypeName", "", DIR_IN, PUNICODE_STRING,
    "ObjectName", "", DIR_IN, PUNICODE_STRING,
    "SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR,
    "PrincipalSelfSid", "opt", DIR_IN, PSID,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "AuditType", "", DIR_IN, AUDIT_EVENT_TYPE,
    "Flags", "", DIR_IN, ULONG,
    "ObjectTypeList", "ecount_opt(ObjectTypeListLength)", DIR_IN, POBJECT_TYPE_LIST,
    "ObjectTypeListLength", "", DIR_IN, ULONG,
    "GenericMapping", "", DIR_IN, PGENERIC_MAPPING,
    "ObjectCreation", "", DIR_IN, BOOLEAN,
    "GrantedAccess", "", DIR_OUT, PACCESS_MASK,
    "AccessStatus", "", DIR_OUT, PNTSTATUS,
    "GenerateOnClose", "", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtAccessCheckByType, NTSTATUS,
    "SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR,
    "PrincipalSelfSid", "opt", DIR_IN, PSID,
    "ClientToken", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectTypeList", "ecount(ObjectTypeListLength)", DIR_IN, POBJECT_TYPE_LIST,
    "ObjectTypeListLength", "", DIR_IN, ULONG,
    "GenericMapping", "", DIR_IN, PGENERIC_MAPPING,
    "PrivilegeSet", "bcount(*PrivilegeSetLength)", DIR_OUT, PPRIVILEGE_SET,
    "PrivilegeSetLength", "", DIR_INOUT, PULONG,
    "GrantedAccess", "", DIR_OUT, PACCESS_MASK,
    "AccessStatus", "", DIR_OUT, PNTSTATUS,
);
SYSCALL(NtAccessCheckByTypeResultListAndAuditAlarmByHandle, NTSTATUS,
    "SubsystemName", "", DIR_IN, PUNICODE_STRING,
    "HandleId", "opt", DIR_IN, PVOID,
    "ClientToken", "", DIR_IN, HANDLE,
    "ObjectTypeName", "", DIR_IN, PUNICODE_STRING,
    "ObjectName", "", DIR_IN, PUNICODE_STRING,
    "SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR,
    "PrincipalSelfSid", "opt", DIR_IN, PSID,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "AuditType", "", DIR_IN, AUDIT_EVENT_TYPE,
    "Flags", "", DIR_IN, ULONG,
    "ObjectTypeList", "ecount_opt(ObjectTypeListLength)", DIR_IN, POBJECT_TYPE_LIST,
    "ObjectTypeListLength", "", DIR_IN, ULONG,
    "GenericMapping", "", DIR_IN, PGENERIC_MAPPING,
    "ObjectCreation", "", DIR_IN, BOOLEAN,
    "GrantedAccess", "ecount(ObjectTypeListLength)", DIR_OUT, PACCESS_MASK,
    "AccessStatus", "ecount(ObjectTypeListLength)", DIR_OUT, PNTSTATUS,
    "GenerateOnClose", "", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtAccessCheckByTypeResultListAndAuditAlarm, NTSTATUS,
    "SubsystemName", "", DIR_IN, PUNICODE_STRING,
    "HandleId", "opt", DIR_IN, PVOID,
    "ObjectTypeName", "", DIR_IN, PUNICODE_STRING,
    "ObjectName", "", DIR_IN, PUNICODE_STRING,
    "SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR,
    "PrincipalSelfSid", "opt", DIR_IN, PSID,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "AuditType", "", DIR_IN, AUDIT_EVENT_TYPE,
    "Flags", "", DIR_IN, ULONG,
    "ObjectTypeList", "ecount_opt(ObjectTypeListLength)", DIR_IN, POBJECT_TYPE_LIST,
    "ObjectTypeListLength", "", DIR_IN, ULONG,
    "GenericMapping", "", DIR_IN, PGENERIC_MAPPING,
    "ObjectCreation", "", DIR_IN, BOOLEAN,
    "GrantedAccess", "ecount(ObjectTypeListLength)", DIR_OUT, PACCESS_MASK,
    "AccessStatus", "ecount(ObjectTypeListLength)", DIR_OUT, PNTSTATUS,
    "GenerateOnClose", "", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtAccessCheckByTypeResultList, NTSTATUS,
    "SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR,
    "PrincipalSelfSid", "opt", DIR_IN, PSID,
    "ClientToken", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectTypeList", "ecount(ObjectTypeListLength)", DIR_IN, POBJECT_TYPE_LIST,
    "ObjectTypeListLength", "", DIR_IN, ULONG,
    "GenericMapping", "", DIR_IN, PGENERIC_MAPPING,
    "PrivilegeSet", "bcount(*PrivilegeSetLength)", DIR_OUT, PPRIVILEGE_SET,
    "PrivilegeSetLength", "", DIR_INOUT, PULONG,
    "GrantedAccess", "ecount(ObjectTypeListLength)", DIR_OUT, PACCESS_MASK,
    "AccessStatus", "ecount(ObjectTypeListLength)", DIR_OUT, PNTSTATUS,
);
SYSCALL(NtAccessCheck, NTSTATUS,
    "SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR,
    "ClientToken", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "GenericMapping", "", DIR_IN, PGENERIC_MAPPING,
    "PrivilegeSet", "bcount(*PrivilegeSetLength)", DIR_OUT, PPRIVILEGE_SET,
    "PrivilegeSetLength", "", DIR_INOUT, PULONG,
    "GrantedAccess", "", DIR_OUT, PACCESS_MASK,
    "AccessStatus", "", DIR_OUT, PNTSTATUS,
);
SYSCALL(NtAddAtom, NTSTATUS,
    "AtomName", "bcount_opt(Length)", DIR_IN, PWSTR,
    "Length", "", DIR_IN, ULONG,
    "Atom", "opt", DIR_OUT, PRTL_ATOM,
);
SYSCALL(NtAddBootEntry, NTSTATUS,
    "BootEntry", "", DIR_IN, PBOOT_ENTRY,
    "Id", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAddDriverEntry, NTSTATUS,
    "DriverEntry", "", DIR_IN, PEFI_DRIVER_ENTRY,
    "Id", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAdjustGroupsToken, NTSTATUS,
    "TokenHandle", "", DIR_IN, HANDLE,
    "ResetToDefault", "", DIR_IN, BOOLEAN,
    "NewState", "", DIR_IN, PTOKEN_GROUPS,
    "BufferLength", "", DIR_IN, ULONG,
    "PreviousState", "bcount_part_opt(BufferLength,*ReturnLength)", DIR_OUT, PTOKEN_GROUPS,
    "ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtAdjustPrivilegesToken, NTSTATUS,
    "TokenHandle", "", DIR_IN, HANDLE,
    "DisableAllPrivileges", "", DIR_IN, BOOLEAN,
    "NewState", "opt", DIR_IN, PTOKEN_PRIVILEGES,
    "BufferLength", "", DIR_IN, ULONG,
    "PreviousState", "bcount_part_opt(BufferLength,*ReturnLength)", DIR_OUT, PTOKEN_PRIVILEGES,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAlertResumeThread, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "PreviousSuspendCount", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAlertThread, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtAllocateLocallyUniqueId, NTSTATUS,
    "Luid", "", DIR_OUT, PLUID,
);
SYSCALL(NtAllocateReserveObject, NTSTATUS,
    "MemoryReserveHandle", "", DIR_OUT, PHANDLE,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "Type", "", DIR_IN, MEMORY_RESERVE_TYPE,
);
SYSCALL(NtAllocateUserPhysicalPages, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "NumberOfPages", "", DIR_INOUT, PULONG_PTR,
    "UserPfnArra;", "ecount(*NumberOfPages)", DIR_OUT, PULONG_PTR,
);
SYSCALL(NtAllocateUuids, NTSTATUS,
    "Time", "", DIR_OUT, PULARGE_INTEGER,
    "Range", "", DIR_OUT, PULONG,
    "Sequence", "", DIR_OUT, PULONG,
    "Seed", "", DIR_OUT, PCHAR,
);
SYSCALL(NtAllocateVirtualMemory, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "*BaseAddress", "", DIR_INOUT, PPVOID,
    "ZeroBits", "", DIR_IN, ULONG_PTR,
    "RegionSize", "", DIR_INOUT, PSIZE_T,
    "AllocationType", "", DIR_IN, DWORD,
    "Protect", "", DIR_IN, DWORD,
);
SYSCALL(NtAlpcAcceptConnectPort, NTSTATUS,
    "PortHandle", "", DIR_OUT, PHANDLE,
    "ConnectionPortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_IN, ULONG,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "PortAttributes", "", DIR_IN, PALPC_PORT_ATTRIBUTES,
    "PortContext", "opt", DIR_IN, PVOID,
    "ConnectionRequest", "", DIR_IN, PPORT_MESSAGE,
    "ConnectionMessageAttributes", "opt", DIR_INOUT, PALPC_MESSAGE_ATTRIBUTES,
    "AcceptConnection", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtAlpcCancelMessage, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_IN, ULONG,
    "MessageContext", "", DIR_IN, PALPC_CONTEXT_ATTR,
);
SYSCALL(NtAlpcConnectPort, NTSTATUS,
    "PortHandle", "", DIR_OUT, PHANDLE,
    "PortName", "", DIR_IN, PUNICODE_STRING,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "PortAttributes", "opt", DIR_IN, PALPC_PORT_ATTRIBUTES,
    "Flags", "", DIR_IN, ULONG,
    "RequiredServerSid", "opt", DIR_IN, PSID,
    "ConnectionMessage", "", DIR_INOUT, PPORT_MESSAGE,
    "BufferLength", "opt", DIR_INOUT, PULONG,
    "OutMessageAttributes", "opt", DIR_INOUT, PALPC_MESSAGE_ATTRIBUTES,
    "InMessageAttributes", "opt", DIR_INOUT, PALPC_MESSAGE_ATTRIBUTES,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtAlpcCreatePort, NTSTATUS,
    "PortHandle", "", DIR_OUT, PHANDLE,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "PortAttributes", "opt", DIR_IN, PALPC_PORT_ATTRIBUTES,
);
SYSCALL(NtAlpcCreatePortSection, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_IN, ULONG,
    "SectionHandle", "opt", DIR_IN, HANDLE,
    "SectionSize", "", DIR_IN, SIZE_T,
    "AlpcSectionHandle", "", DIR_OUT, PALPC_HANDLE,
    "ActualSectionSize", "", DIR_OUT, PSIZE_T,
);
SYSCALL(NtAlpcCreateResourceReserve, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_RESERVED, ULONG,
    "MessageSize", "", DIR_IN, SIZE_T,
    "ResourceId", "", DIR_OUT, PALPC_HANDLE,
);
SYSCALL(NtAlpcCreateSectionView, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_RESERVED, ULONG,
    "ViewAttributes", "", DIR_INOUT, PALPC_DATA_VIEW_ATTR,
);
SYSCALL(NtAlpcCreateSecurityContext, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_RESERVED, ULONG,
    "SecurityAttribute", "", DIR_INOUT, PALPC_SECURITY_ATTR,
);
SYSCALL(NtAlpcDeletePortSection, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_RESERVED, ULONG,
    "SectionHandle", "", DIR_IN, ALPC_HANDLE,
);
SYSCALL(NtAlpcDeleteResourceReserve, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_RESERVED, ULONG,
    "ResourceId", "", DIR_IN, ALPC_HANDLE,
);
SYSCALL(NtAlpcDeleteSectionView, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_RESERVED, ULONG,
    "ViewBase", "", DIR_IN, PVOID,
);
SYSCALL(NtAlpcDeleteSecurityContext, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_RESERVED, ULONG,
    "ContextHandle", "", DIR_IN, ALPC_HANDLE,
);
SYSCALL(NtAlpcDisconnectPort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtAlpcImpersonateClientOfPort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "PortMessage", "", DIR_IN, PPORT_MESSAGE,
    "Reserved", "", DIR_RESERVED, PVOID,
);
SYSCALL(NtAlpcOpenSenderProcess, NTSTATUS,
    "ProcessHandle", "", DIR_OUT, PHANDLE,
    "PortHandle", "", DIR_IN, HANDLE,
    "PortMessage", "", DIR_IN, PPORT_MESSAGE,
    "Flags", "", DIR_RESERVED, ULONG,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtAlpcOpenSenderThread, NTSTATUS,
    "ThreadHandle", "", DIR_OUT, PHANDLE,
    "PortHandle", "", DIR_IN, HANDLE,
    "PortMessage", "", DIR_IN, PPORT_MESSAGE,
    "Flags", "", DIR_RESERVED, ULONG,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtAlpcQueryInformation, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "PortInformationClass", "", DIR_IN, ALPC_PORT_INFORMATION_CLASS,
    "PortInformation", "bcount(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAlpcQueryInformationMessage, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "PortMessage", "", DIR_IN, PPORT_MESSAGE,
    "MessageInformationClass", "", DIR_IN, ALPC_MESSAGE_INFORMATION_CLASS,
    "MessageInformation", "bcount(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAlpcRevokeSecurityContext, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_RESERVED, ULONG,
    "ContextHandle", "", DIR_IN, ALPC_HANDLE,
);
SYSCALL(NtAlpcSendWaitReceivePort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_IN, ULONG,
    "SendMessage", "opt", DIR_IN, PPORT_MESSAGE,
    "SendMessageAttributes", "opt", DIR_IN, PALPC_MESSAGE_ATTRIBUTES,
    "ReceiveMessage", "opt", DIR_INOUT, PPORT_MESSAGE,
    "BufferLength", "opt", DIR_INOUT, PULONG,
    "ReceiveMessageAttributes", "opt", DIR_INOUT, PALPC_MESSAGE_ATTRIBUTES,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtAlpcSetInformation, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "PortInformationClass", "", DIR_IN, ALPC_PORT_INFORMATION_CLASS,
    "PortInformation", "bcount(Length)", DIR_IN, PVOID,
    "Length", "", DIR_IN, ULONG,
);
SYSCALL(NtApphelpCacheControl, NTSTATUS,
    "type", "", DIR_IN, APPHELPCOMMAND,
    "buf", "", DIR_IN, PVOID,
);
SYSCALL(NtAreMappedFilesTheSame, NTSTATUS,
    "File1MappedAsAnImage", "", DIR_IN, PVOID,
    "File2MappedAsFile", "", DIR_IN, PVOID,
);
SYSCALL(NtAssignProcessToJobObject, NTSTATUS,
    "JobHandle", "", DIR_IN, HANDLE,
    "ProcessHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtCallbackReturn, NTSTATUS,
    "OutputBuffer", "opt", DIR_IN, PVOID,
    "OutputLength", "", DIR_IN, ULONG,
    "Status", "", DIR_IN, NTSTATUS,
);
SYSCALL(NtCancelIoFileEx, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoRequestToCancel", "opt", DIR_IN, PIO_STATUS_BLOCK,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
);
SYSCALL(NtCancelIoFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
);
SYSCALL(NtCancelSynchronousIoFile, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "IoRequestToCancel", "opt", DIR_IN, PIO_STATUS_BLOCK,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
);
SYSCALL(NtCancelTimer, NTSTATUS,
    "TimerHandle", "", DIR_IN, HANDLE,
    "CurrentState", "opt", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtClearEvent, NTSTATUS,
    "EventHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtClose, NTSTATUS,
    "Handle", "", DIR_IN, HANDLE,
);
SYSCALL(NtCloseObjectAuditAlarm, NTSTATUS,
    "SubsystemName", "", DIR_IN, PUNICODE_STRING,
    "HandleId", "opt", DIR_IN, PVOID,
    "GenerateOnClose", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCommitComplete, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtCommitEnlistment, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtCommitTransaction, NTSTATUS,
    "TransactionHandle", "", DIR_IN, HANDLE,
    "Wait", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCompactKeys, NTSTATUS,
    "Count", "", DIR_IN, ULONG,
    "KeyArray[;", "ecount(Count)", DIR_IN, HANDLE,
);
SYSCALL(NtCompareTokens, NTSTATUS,
    "FirstTokenHandle", "", DIR_IN, HANDLE,
    "SecondTokenHandle", "", DIR_IN, HANDLE,
    "Equal", "", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtCompleteConnectPort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtCompressKey, NTSTATUS,
    "Key", "", DIR_IN, HANDLE,
);
SYSCALL(NtConnectPort, NTSTATUS,
    "PortHandle", "", DIR_OUT, PHANDLE,
    "PortName", "", DIR_IN, PUNICODE_STRING,
    "SecurityQos", "", DIR_IN, PSECURITY_QUALITY_OF_SERVICE,
    "ClientView", "opt", DIR_INOUT, PPORT_VIEW,
    "ServerView", "opt", DIR_INOUT, PREMOTE_PORT_VIEW,
    "MaxMessageLength", "opt", DIR_OUT, PULONG,
    "ConnectionInformation", "opt", DIR_INOUT, PVOID,
    "ConnectionInformationLength", "opt", DIR_INOUT, PULONG,
);
SYSCALL(NtContinue, NTSTATUS,
    "ContextRecord", "", DIR_IN, PCONTEXT,
    "TestAlert", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCreateDebugObject, NTSTATUS,
    "DebugObjectHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_OUT, ACCESS_MASK,
    "ObjectAttributes", "", DIR_OUT, POBJECT_ATTRIBUTES,
    "Flags", "", DIR_OUT, ULONG,
);
SYSCALL(NtCreateDirectoryObject, NTSTATUS,
    "DirectoryHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtCreateEnlistment, NTSTATUS,
    "EnlistmentHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ResourceManagerHandle", "", DIR_IN, HANDLE,
    "TransactionHandle", "", DIR_IN, HANDLE,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "CreateOptions", "opt", DIR_IN, ULONG,
    "NotificationMask", "", DIR_IN, NOTIFICATION_MASK,
    "EnlistmentKey", "opt", DIR_IN, PVOID,
);
SYSCALL(NtCreateEvent, NTSTATUS,
    "EventHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "EventType", "", DIR_IN, EVENT_TYPE,
    "InitialState", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCreateEventPair, NTSTATUS,
    "EventPairHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtCreateFile, NTSTATUS,
    "FileHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "AllocationSize", "opt", DIR_IN, PLARGE_INTEGER,
    "FileAttributes", "", DIR_IN, ULONG,
    "ShareAccess", "", DIR_IN, ULONG,
    "CreateDisposition", "", DIR_IN, ULONG,
    "CreateOptions", "", DIR_IN, ULONG,
    "EaBuffer", "bcount_opt(EaLength)", DIR_IN, PVOID,
    "EaLength", "", DIR_IN, ULONG,
);
SYSCALL(NtCreateIoCompletion, NTSTATUS,
    "IoCompletionHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "Count", "", DIR_IN, ULONG,
);
SYSCALL(NtCreateJobObject, NTSTATUS,
    "JobHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtCreateJobSet, NTSTATUS,
    "NumJob", "", DIR_IN, ULONG,
    "UserJobSet", "ecount(NumJob)", DIR_IN, PJOB_SET_ARRAY,
    "Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtCreateKeyedEvent, NTSTATUS,
    "KeyedEventHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtCreateKey, NTSTATUS,
    "KeyHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "TitleIndex", "", DIR_RESERVED, ULONG,
    "Class", "opt", DIR_IN, PUNICODE_STRING,
    "CreateOptions", "", DIR_IN, ULONG,
    "Disposition", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtCreateKeyTransacted, NTSTATUS,
    "KeyHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "TitleIndex", "", DIR_RESERVED, ULONG,
    "Class", "opt", DIR_IN, PUNICODE_STRING,
    "CreateOptions", "", DIR_IN, ULONG,
    "TransactionHandle", "", DIR_IN, HANDLE,
    "Disposition", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtCreateMailslotFile, NTSTATUS,
    "FileHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ULONG,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "CreateOptions", "", DIR_IN, ULONG,
    "MailslotQuota", "", DIR_IN, ULONG,
    "MaximumMessageSize", "", DIR_IN, ULONG,
    "ReadTimeout", "", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtCreateMutant, NTSTATUS,
    "MutantHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "InitialOwner", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCreateNamedPipeFile, NTSTATUS,
    "FileHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ULONG,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "ShareAccess", "", DIR_IN, ULONG,
    "CreateDisposition", "", DIR_IN, ULONG,
    "CreateOptions", "", DIR_IN, ULONG,
    "NamedPipeType", "", DIR_IN, ULONG,
    "ReadMode", "", DIR_IN, ULONG,
    "CompletionMode", "", DIR_IN, ULONG,
    "MaximumInstances", "", DIR_IN, ULONG,
    "InboundQuota", "", DIR_IN, ULONG,
    "OutboundQuota", "", DIR_IN, ULONG,
    "DefaultTimeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtCreatePagingFile, NTSTATUS,
    "PageFileName", "", DIR_IN, PUNICODE_STRING,
    "MinimumSize", "", DIR_IN, PLARGE_INTEGER,
    "MaximumSize", "", DIR_IN, PLARGE_INTEGER,
    "Priority", "", DIR_IN, ULONG,
);
SYSCALL(NtCreatePort, NTSTATUS,
    "PortHandle", "", DIR_OUT, PHANDLE,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "MaxConnectionInfoLength", "", DIR_IN, ULONG,
    "MaxMessageLength", "", DIR_IN, ULONG,
    "MaxPoolUsage", "opt", DIR_IN, ULONG,
);
SYSCALL(NtCreatePrivateNamespace, NTSTATUS,
    "NamespaceHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "BoundaryDescriptor", "", DIR_IN, PVOID,
);
SYSCALL(NtCreateProcessEx, NTSTATUS,
    "ProcessHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "ParentProcess", "", DIR_IN, HANDLE,
    "Flags", "", DIR_IN, ULONG,
    "SectionHandle", "opt", DIR_IN, HANDLE,
    "DebugPort", "opt", DIR_IN, HANDLE,
    "ExceptionPort", "opt", DIR_IN, HANDLE,
    "JobMemberLevel", "", DIR_IN, ULONG,
);
SYSCALL(NtCreateProcess, NTSTATUS,
    "ProcessHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "ParentProcess", "", DIR_IN, HANDLE,
    "InheritObjectTable", "", DIR_IN, BOOLEAN,
    "SectionHandle", "opt", DIR_IN, HANDLE,
    "DebugPort", "opt", DIR_IN, HANDLE,
    "ExceptionPort", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtCreateProfileEx, NTSTATUS,
    "ProfileHandle", "", DIR_OUT, PHANDLE,
    "Process", "opt", DIR_IN, HANDLE,
    "ProfileBase", "", DIR_IN, PVOID,
    "ProfileSize", "", DIR_IN, SIZE_T,
    "BucketSize", "", DIR_IN, ULONG,
    "Buffer", "", DIR_IN, PULONG,
    "BufferSize", "", DIR_IN, ULONG,
    "ProfileSource", "", DIR_IN, KPROFILE_SOURCE,
    "GroupAffinityCount", "", DIR_IN, ULONG,
    "GroupAffinity", "opt", DIR_IN, PGROUP_AFFINITY,
);
SYSCALL(NtCreateProfile, NTSTATUS,
    "ProfileHandle", "", DIR_OUT, PHANDLE,
    "Process", "", DIR_IN, HANDLE,
    "RangeBase", "", DIR_IN, PVOID,
    "RangeSize", "", DIR_IN, SIZE_T,
    "BucketSize", "", DIR_IN, ULONG,
    "Buffer", "", DIR_IN, PULONG,
    "BufferSize", "", DIR_IN, ULONG,
    "ProfileSource", "", DIR_IN, KPROFILE_SOURCE,
    "Affinity", "", DIR_IN, KAFFINITY,
);
SYSCALL(NtCreateResourceManager, NTSTATUS,
    "ResourceManagerHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "TmHandle", "", DIR_IN, HANDLE,
    "RmGuid", "", DIR_IN, LPGUID,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "CreateOptions", "opt", DIR_IN, ULONG,
    "Description", "opt", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtCreateSection, NTSTATUS,
    "SectionHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "MaximumSize", "opt", DIR_IN, PLARGE_INTEGER,
    "SectionPageProtection", "", DIR_IN, ULONG,
    "AllocationAttributes", "", DIR_IN, ULONG,
    "FileHandle", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtCreateSemaphore, NTSTATUS,
    "SemaphoreHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "InitialCount", "", DIR_IN, LONG,
    "MaximumCount", "", DIR_IN, LONG,
);
SYSCALL(NtCreateSymbolicLinkObject, NTSTATUS,
    "LinkHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "LinkTarget", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtCreateThreadEx, NTSTATUS,
    "ThreadHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "StartRoutine", "", DIR_IN, PVOID,
    "Argument", "opt", DIR_IN, PVOID,
    "CreateFlags", "", DIR_IN, ULONG,
    "ZeroBits", "opt", DIR_IN, ULONG_PTR,
    "StackSize", "opt", DIR_IN, SIZE_T,
    "MaximumStackSize", "opt", DIR_IN, SIZE_T,
    "AttributeList", "opt", DIR_IN, PPS_ATTRIBUTE_LIST,
);
SYSCALL(NtCreateThread, NTSTATUS,
    "ThreadHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "ClientId", "", DIR_OUT, PCLIENT_ID,
    "ThreadContext", "", DIR_IN, PCONTEXT,
    "InitialTeb", "", DIR_IN, PINITIAL_TEB,
    "CreateSuspended", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCreateTimer, NTSTATUS,
    "TimerHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "TimerType", "", DIR_IN, TIMER_TYPE,
);
SYSCALL(NtCreateToken, NTSTATUS,
    "TokenHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "TokenType", "", DIR_IN, TOKEN_TYPE,
    "AuthenticationId", "", DIR_IN, PLUID,
    "ExpirationTime", "", DIR_IN, PLARGE_INTEGER,
    "User", "", DIR_IN, PTOKEN_USER,
    "Groups", "", DIR_IN, PTOKEN_GROUPS,
    "Privileges", "", DIR_IN, PTOKEN_PRIVILEGES,
    "Owner", "opt", DIR_IN, PTOKEN_OWNER,
    "PrimaryGroup", "", DIR_IN, PTOKEN_PRIMARY_GROUP,
    "DefaultDacl", "opt", DIR_IN, PTOKEN_DEFAULT_DACL,
    "TokenSource", "", DIR_IN, PTOKEN_SOURCE,
);
SYSCALL(NtCreateTransactionManager, NTSTATUS,
    "TmHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "LogFileName", "opt", DIR_IN, PUNICODE_STRING,
    "CreateOptions", "opt", DIR_IN, ULONG,
    "CommitStrength", "opt", DIR_IN, ULONG,
);
SYSCALL(NtCreateTransaction, NTSTATUS,
    "TransactionHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "Uow", "opt", DIR_IN, LPGUID,
    "TmHandle", "opt", DIR_IN, HANDLE,
    "CreateOptions", "opt", DIR_IN, ULONG,
    "IsolationLevel", "opt", DIR_IN, ULONG,
    "IsolationFlags", "opt", DIR_IN, ULONG,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
    "Description", "opt", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtCreateUserProcess, NTSTATUS,
    "ProcessHandle", "", DIR_OUT, PHANDLE,
    "ThreadHandle", "", DIR_OUT, PHANDLE,
    "ProcessDesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ThreadDesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ProcessObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "ThreadObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "ProcessFlags", "", DIR_IN, ULONG,
    "ThreadFlags", "", DIR_IN, ULONG,
    "ProcessParameters", "opt", DIR_IN, PRTL_USER_PROCESS_PARAMETERS,
    "CreateInfo", "opt", DIR_IN, PPROCESS_CREATE_INFO,
    "AttributeList", "opt", DIR_IN, PPROCESS_ATTRIBUTE_LIST,
);
SYSCALL(NtCreateWaitablePort, NTSTATUS,
    "PortHandle", "", DIR_OUT, PHANDLE,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "MaxConnectionInfoLength", "", DIR_IN, ULONG,
    "MaxMessageLength", "", DIR_IN, ULONG,
    "MaxPoolUsage", "opt", DIR_IN, ULONG,
);
SYSCALL(NtCreateWorkerFactory, NTSTATUS,
    "WorkerFactoryHandleReturn", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "CompletionPortHandle", "", DIR_IN, HANDLE,
    "WorkerProcessHandle", "", DIR_IN, HANDLE,
    "StartRoutine", "", DIR_IN, PVOID,
    "StartParameter", "opt", DIR_IN, PVOID,
    "MaxThreadCount", "opt", DIR_IN, ULONG,
    "StackReserve", "opt", DIR_IN, SIZE_T,
    "StackCommit", "opt", DIR_IN, SIZE_T,
);
SYSCALL(NtDebugActiveProcess, NTSTATUS,
    "ProcessHandle", "", DIR_OUT, HANDLE,
    "DebugObjectHandle", "", DIR_OUT, HANDLE,
);
SYSCALL(NtDebugContinue, NTSTATUS,
    "DebugObjectHandle", "", DIR_OUT, HANDLE,
    "ClientId", "", DIR_OUT, PCLIENT_ID,
    "ContinueStatus", "", DIR_OUT, NTSTATUS,
);
SYSCALL(NtDelayExecution, NTSTATUS,
    "Alertable", "", DIR_IN, BOOLEAN,
    "DelayInterval", "", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtDeleteAtom, NTSTATUS,
    "Atom", "", DIR_IN, RTL_ATOM,
);
SYSCALL(NtDeleteBootEntry, NTSTATUS,
    "Id", "", DIR_IN, ULONG,
);
SYSCALL(NtDeleteDriverEntry, NTSTATUS,
    "Id", "", DIR_IN, ULONG,
);
SYSCALL(NtDeleteFile, NTSTATUS,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtDeleteKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtDeleteObjectAuditAlarm, NTSTATUS,
    "SubsystemName", "", DIR_IN, PUNICODE_STRING,
    "HandleId", "opt", DIR_IN, PVOID,
    "GenerateOnClose", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtDeletePrivateNamespace, NTSTATUS,
    "NamespaceHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtDeleteValueKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "ValueName", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtDeviceIoControlFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "IoControlCode", "", DIR_IN, ULONG,
    "InputBuffer", "bcount_opt(InputBufferLength)", DIR_IN, PVOID,
    "InputBufferLength", "", DIR_IN, ULONG,
    "OutputBuffer", "bcount_opt(OutputBufferLength)", DIR_OUT, PVOID,
    "OutputBufferLength", "", DIR_IN, ULONG,
);
SYSCALL(NtDisplayString, NTSTATUS,
    "String", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtDrawText, NTSTATUS,
    "Text", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtDuplicateObject, NTSTATUS,
    "SourceProcessHandle", "", DIR_IN, HANDLE,
    "SourceHandle", "", DIR_IN, PHANDLE,
    "TargetProcessHandle", "opt", DIR_IN, HANDLE,
    "TargetHandle", "opt", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "HandleAttributes", "", DIR_IN, ULONG,
    "Options", "", DIR_IN, ULONG,
);
SYSCALL(NtDuplicateToken, NTSTATUS,
    "ExistingTokenHandle", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "EffectiveOnly", "", DIR_IN, BOOLEAN,
    "TokenType", "", DIR_IN, TOKEN_TYPE,
    "NewTokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtEnumerateBootEntries, NTSTATUS,
    "Buffer", "bcount_opt(*BufferLength)", DIR_OUT, PVOID,
    "BufferLength", "", DIR_INOUT, PULONG,
);
SYSCALL(NtEnumerateDriverEntries, NTSTATUS,
    "Buffer", "bcount(*BufferLength)", DIR_OUT, PVOID,
    "BufferLength", "", DIR_INOUT, PULONG,
);
SYSCALL(NtEnumerateKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "Index", "", DIR_IN, ULONG,
    "KeyInformationClass", "", DIR_IN, KEY_INFORMATION_CLASS,
    "KeyInformation", "bcount_opt(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ResultLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtEnumerateSystemEnvironmentValuesEx, NTSTATUS,
    "InformationClass", "", DIR_IN, ULONG,
    "Buffer", "", DIR_OUT, PVOID,
    "BufferLength", "", DIR_INOUT, PULONG,
);
SYSCALL(NtEnumerateTransactionObject, NTSTATUS,
    "RootObjectHandle", "opt", DIR_IN, HANDLE,
    "QueryType", "", DIR_IN, KTMOBJECT_TYPE,
    "ObjectCursor", "bcount(ObjectCursorLength)", DIR_INOUT, PKTMOBJECT_CURSOR,
    "ObjectCursorLength", "", DIR_IN, ULONG,
    "ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtEnumerateValueKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "Index", "", DIR_IN, ULONG,
    "KeyValueInformationClass", "", DIR_IN, KEY_VALUE_INFORMATION_CLASS,
    "KeyValueInformation", "bcount_opt(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ResultLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtExtendSection, NTSTATUS,
    "SectionHandle", "", DIR_IN, HANDLE,
    "NewSectionSize", "", DIR_INOUT, PLARGE_INTEGER,
);
SYSCALL(NtFilterToken, NTSTATUS,
    "ExistingTokenHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_IN, ULONG,
    "SidsToDisable", "opt", DIR_IN, PTOKEN_GROUPS,
    "PrivilegesToDelete", "opt", DIR_IN, PTOKEN_PRIVILEGES,
    "RestrictedSids", "opt", DIR_IN, PTOKEN_GROUPS,
    "NewTokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtFindAtom, NTSTATUS,
    "AtomName", "bcount_opt(Length)", DIR_IN, PWSTR,
    "Length", "", DIR_IN, ULONG,
    "Atom", "opt", DIR_OUT, PRTL_ATOM,
);
SYSCALL(NtFlushBuffersFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
);
SYSCALL(NtFlushInstallUILanguage, NTSTATUS,
    "InstallUILanguage", "", DIR_IN, LANGID,
    "SetComittedFlag", "", DIR_IN, ULONG,
);
SYSCALL(NtFlushInstructionCache, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "BaseAddress", "opt", DIR_IN, PVOID,
    "Length", "", DIR_IN, SIZE_T,
);
SYSCALL(NtFlushKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtFlushVirtualMemory, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "*BaseAddress", "", DIR_INOUT, PPVOID,
    "RegionSize", "", DIR_INOUT, PSIZE_T,
    "IoStatus", "", DIR_OUT, PIO_STATUS_BLOCK,
);
SYSCALL(NtFreeUserPhysicalPages, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "NumberOfPages", "", DIR_INOUT, PULONG_PTR,
    "UserPfnArra;", "ecount(*NumberOfPages)", DIR_IN, PULONG_PTR,
);
SYSCALL(NtFreeVirtualMemory, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "*BaseAddress", "", DIR_INOUT, PPVOID,
    "RegionSize", "", DIR_INOUT, PSIZE_T,
    "FreeType", "", DIR_IN, ULONG,
);
SYSCALL(NtFreezeRegistry, NTSTATUS,
    "TimeOutInSeconds", "", DIR_IN, ULONG,
);
SYSCALL(NtFreezeTransactions, NTSTATUS,
    "FreezeTimeout", "", DIR_IN, PLARGE_INTEGER,
    "ThawTimeout", "", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtFsControlFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "IoControlCode", "", DIR_IN, ULONG,
    "InputBuffer", "bcount_opt(InputBufferLength)", DIR_IN, PVOID,
    "InputBufferLength", "", DIR_IN, ULONG,
    "OutputBuffer", "bcount_opt(OutputBufferLength)", DIR_OUT, PVOID,
    "OutputBufferLength", "", DIR_IN, ULONG,
);
SYSCALL(NtGdiBitBlt, INT,
    "hdcDst", "", DIR_IN, HANDLE,
    "x", "", DIR_IN, INT,
    "y", "", DIR_IN, INT,
    "cx", "", DIR_IN, INT,
    "cy", "", DIR_IN, INT,
    "hdcSrc", "", DIR_IN, HANDLE,
    "xSrc", "", DIR_IN, INT,
    "ySrc", "", DIR_IN, INT,
    "rop4", "", DIR_IN, DWORD,
    "crBackColor", "", DIR_IN, DWORD,
    "fl", "", DIR_IN, ULONG);
SYSCALL(NtGetContextThread, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "ThreadContext", "", DIR_INOUT, PCONTEXT,
);
SYSCALL(NtGetDevicePowerState, NTSTATUS,
    "Device", "", DIR_IN, HANDLE,
    "*State", "", DIR_OUT, DEVICE_POWER_STATE,
);
SYSCALL(NtGetMUIRegistryInfo, NTSTATUS,
    "Flags", "", DIR_IN, ULONG,
    "DataSize", "", DIR_INOUT, PULONG,
    "Data", "", DIR_OUT, PVOID,
);
SYSCALL(NtGetNextProcess, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "HandleAttributes", "", DIR_IN, ULONG,
    "Flags", "", DIR_IN, ULONG,
    "NewProcessHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtGetNextThread, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "HandleAttributes", "", DIR_IN, ULONG,
    "Flags", "", DIR_IN, ULONG,
    "NewThreadHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtGetNlsSectionPtr, NTSTATUS,
    "SectionType", "", DIR_IN, ULONG,
    "SectionData", "", DIR_IN, ULONG,
    "ContextData", "", DIR_IN, PVOID,
    "*SectionPointer", "", DIR_OUT, PVOID,
    "SectionSize", "", DIR_OUT, PULONG,
);
SYSCALL(NtGetNotificationResourceManager, NTSTATUS,
    "ResourceManagerHandle", "", DIR_IN, HANDLE,
    "TransactionNotification", "", DIR_OUT, PTRANSACTION_NOTIFICATION,
    "NotificationLength", "", DIR_IN, ULONG,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
    "ReturnLength", "opt", DIR_OUT, PULONG,
    "Asynchronous", "", DIR_IN, ULONG,
    "AsynchronousContext", "opt", DIR_IN, ULONG_PTR,
);
SYSCALL(NtGetPlugPlayEvent, NTSTATUS,
    "EventHandle", "", DIR_IN, HANDLE,
    "Context", "opt", DIR_IN, PVOID,
    "EventBlock", "bcount(EventBufferSize)", DIR_OUT, PPLUGPLAY_EVENT_BLOCK,
    "EventBufferSize", "", DIR_IN, ULONG,
);
SYSCALL(NtGetWriteWatch, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_IN, ULONG,
    "BaseAddress", "", DIR_IN, PVOID,
    "RegionSize", "", DIR_IN, SIZE_T,
    "*UserAddressArray", "ecount(*EntriesInUserAddressArray)", DIR_OUT, PVOID,
    "EntriesInUserAddressArray", "", DIR_INOUT, PULONG_PTR,
    "Granularity", "", DIR_OUT, PULONG,
);
SYSCALL(NtImpersonateAnonymousToken, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtImpersonateClientOfPort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Message", "", DIR_IN, PPORT_MESSAGE,
);
SYSCALL(NtImpersonateThread, NTSTATUS,
    "ServerThreadHandle", "", DIR_IN, HANDLE,
    "ClientThreadHandle", "", DIR_IN, HANDLE,
    "SecurityQos", "", DIR_IN, PSECURITY_QUALITY_OF_SERVICE,
);
SYSCALL(NtInitializeNlsFiles, NTSTATUS,
    "*BaseAddress", "", DIR_OUT, PVOID,
    "DefaultLocaleId", "", DIR_OUT, PLCID,
    "DefaultCasingTableSize", "", DIR_OUT, PLARGE_INTEGER,
);
SYSCALL(NtInitializeRegistry, NTSTATUS,
    "BootCondition", "", DIR_IN, USHORT,
);
SYSCALL(NtInitiatePowerAction, NTSTATUS,
    "SystemAction", "", DIR_IN, POWER_ACTION,
    "MinSystemState", "", DIR_IN, SYSTEM_POWER_STATE,
    "Flags", "", DIR_IN, ULONG,
    "Asynchronous", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtIsProcessInJob, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "JobHandle", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtListenPort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "ConnectionRequest", "", DIR_OUT, PPORT_MESSAGE,
);
SYSCALL(NtLoadDriver, NTSTATUS,
    "DriverServiceName", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtLoadKey2, NTSTATUS,
    "TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
    "SourceFile", "", DIR_IN, POBJECT_ATTRIBUTES,
    "Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtLoadKeyEx, NTSTATUS,
    "TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
    "SourceFile", "", DIR_IN, POBJECT_ATTRIBUTES,
    "Flags", "", DIR_IN, ULONG,
    "TrustClassKey", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtLoadKey, NTSTATUS,
    "TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
    "SourceFile", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtLockFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "ByteOffset", "", DIR_IN, PLARGE_INTEGER,
    "Length", "", DIR_IN, PLARGE_INTEGER,
    "Key", "", DIR_IN, ULONG,
    "FailImmediately", "", DIR_IN, BOOLEAN,
    "ExclusiveLock", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtLockProductActivationKeys, NTSTATUS,
    "*pPrivateVer", "opt", DIR_INOUT, ULONG,
    "*pSafeMode", "opt", DIR_OUT, ULONG,
);
SYSCALL(NtLockRegistryKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtLockVirtualMemory, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "*BaseAddress", "", DIR_INOUT, PPVOID,
    "RegionSize", "", DIR_INOUT, PSIZE_T,
    "MapType", "", DIR_IN, ULONG,
);
SYSCALL(NtMakePermanentObject, NTSTATUS,
    "Handle", "", DIR_IN, HANDLE,
);
SYSCALL(NtMakeTemporaryObject, NTSTATUS,
    "Handle", "", DIR_IN, HANDLE,
);
SYSCALL(NtMapCMFModule, NTSTATUS,
    "What", "", DIR_IN, ULONG,
    "Index", "", DIR_IN, ULONG,
    "CacheIndexOut", "opt", DIR_OUT, PULONG,
    "CacheFlagsOut", "opt", DIR_OUT, PULONG,
    "ViewSizeOut", "opt", DIR_OUT, PULONG,
    "*BaseAddress", "opt", DIR_OUT, PVOID,
);
SYSCALL(NtMapUserPhysicalPages, NTSTATUS,
    "VirtualAddress", "", DIR_IN, PVOID,
    "NumberOfPages", "", DIR_IN, ULONG_PTR,
    "UserPfnArra;", "ecount_opt(NumberOfPages)", DIR_IN, PULONG_PTR,
);
SYSCALL(NtMapUserPhysicalPagesScatter, NTSTATUS,
    "*VirtualAddresses", "ecount(NumberOfPages)", DIR_IN, PVOID,
    "NumberOfPages", "", DIR_IN, ULONG_PTR,
    "UserPfnArray", "ecount_opt(NumberOfPages)", DIR_IN, PULONG_PTR,
);
SYSCALL(NtMapViewOfSection, NTSTATUS,
    "SectionHandle", "", DIR_IN, HANDLE,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "*BaseAddress", "", DIR_INOUT, PPVOID,
    "ZeroBits", "", DIR_IN, ULONG_PTR,
    "CommitSize", "", DIR_IN, SIZE_T,
    "SectionOffset", "opt", DIR_INOUT, PLARGE_INTEGER,
    "ViewSize", "", DIR_INOUT, PSIZE_T,
    "InheritDisposition", "", DIR_IN, SECTION_INHERIT,
    "AllocationType", "", DIR_IN, ULONG,
    "Win32Protect", "", DIR_IN, WIN32_PROTECTION_MASK,
);
SYSCALL(NtModifyBootEntry, NTSTATUS,
    "BootEntry", "", DIR_IN, PBOOT_ENTRY,
);
SYSCALL(NtModifyDriverEntry, NTSTATUS,
    "DriverEntry", "", DIR_IN, PEFI_DRIVER_ENTRY,
);
SYSCALL(NtNotifyChangeDirectoryFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "Buffer", "bcount(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "CompletionFilter", "", DIR_IN, ULONG,
    "WatchTree", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtNotifyChangeKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "CompletionFilter", "", DIR_IN, ULONG,
    "WatchTree", "", DIR_IN, BOOLEAN,
    "Buffer", "bcount_opt(BufferSize)", DIR_OUT, PVOID,
    "BufferSize", "", DIR_IN, ULONG,
    "Asynchronous", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtNotifyChangeMultipleKeys, NTSTATUS,
    "MasterKeyHandle", "", DIR_IN, HANDLE,
    "Count", "opt", DIR_IN, ULONG,
    "SlaveObjects[]", "ecount_opt(Count)", DIR_IN, OBJECT_ATTRIBUTES,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "CompletionFilter", "", DIR_IN, ULONG,
    "WatchTree", "", DIR_IN, BOOLEAN,
    "Buffer", "bcount_opt(BufferSize)", DIR_OUT, PVOID,
    "BufferSize", "", DIR_IN, ULONG,
    "Asynchronous", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtNotifyChangeSession, NTSTATUS,
    "Session", "", DIR_IN, HANDLE,
    "IoStateSequence", "", DIR_IN, ULONG,
    "Reserved", "", DIR_IN, PVOID,
    "Action", "", DIR_IN, ULONG,
    "IoState", "", DIR_IN,  IO_SESSION_STATE,
    "IoState2", "", DIR_IN,  IO_SESSION_STATE,
    "Buffer", "", DIR_IN, PVOID,
    "BufferSize", "", DIR_IN, ULONG,
);
SYSCALL(NtOpenDirectoryObject, NTSTATUS,
    "DirectoryHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenEnlistment, NTSTATUS,
    "EnlistmentHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ResourceManagerHandle", "", DIR_IN, HANDLE,
    "EnlistmentGuid", "", DIR_IN, LPGUID,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenEvent, NTSTATUS,
    "EventHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenEventPair, NTSTATUS,
    "EventPairHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenFile, NTSTATUS,
    "FileHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "ShareAccess", "", DIR_IN, ULONG,
    "OpenOptions", "", DIR_IN, ULONG,
);
SYSCALL(NtOpenIoCompletion, NTSTATUS,
    "IoCompletionHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenJobObject, NTSTATUS,
    "JobHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenKeyedEvent, NTSTATUS,
    "KeyedEventHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenKeyEx, NTSTATUS,
    "KeyHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "OpenOptions", "", DIR_IN, ULONG,
);
SYSCALL(NtOpenKey, NTSTATUS,
    "KeyHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenKeyTransactedEx, NTSTATUS,
    "KeyHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "OpenOptions", "", DIR_IN, ULONG,
    "TransactionHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtOpenKeyTransacted, NTSTATUS,
    "KeyHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "TransactionHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtOpenMutant, NTSTATUS,
    "MutantHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenObjectAuditAlarm, NTSTATUS,
    "SubsystemName", "", DIR_IN, PUNICODE_STRING,
    "HandleId", "opt", DIR_IN, PVOID,
    "ObjectTypeName", "", DIR_IN, PUNICODE_STRING,
    "ObjectName", "", DIR_IN, PUNICODE_STRING,
    "SecurityDescriptor", "opt", DIR_IN, PSECURITY_DESCRIPTOR,
    "ClientToken", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "GrantedAccess", "", DIR_IN, ACCESS_MASK,
    "Privileges", "opt", DIR_IN, PPRIVILEGE_SET,
    "ObjectCreation", "", DIR_IN, BOOLEAN,
    "AccessGranted", "", DIR_IN, BOOLEAN,
    "GenerateOnClose", "", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtOpenPrivateNamespace, NTSTATUS,
    "NamespaceHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "BoundaryDescriptor", "", DIR_IN, PVOID,
);
SYSCALL(NtOpenProcess, NTSTATUS,
    "ProcessHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "ClientId", "opt", DIR_IN, PCLIENT_ID,
);
SYSCALL(NtOpenProcessTokenEx, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "HandleAttributes", "", DIR_IN, ULONG,
    "TokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtOpenProcessToken, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "TokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtOpenResourceManager, NTSTATUS,
    "ResourceManagerHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "TmHandle", "", DIR_IN, HANDLE,
    "ResourceManagerGuid", "opt", DIR_IN, LPGUID,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenSection, NTSTATUS,
    "SectionHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenSemaphore, NTSTATUS,
    "SemaphoreHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenSession, NTSTATUS,
    "SessionHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenSymbolicLinkObject, NTSTATUS,
    "LinkHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenThread, NTSTATUS,
    "ThreadHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "ClientId", "opt", DIR_IN, PCLIENT_ID,
);
SYSCALL(NtOpenThreadTokenEx, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "OpenAsSelf", "", DIR_IN, BOOLEAN,
    "HandleAttributes", "", DIR_IN, ULONG,
    "TokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtOpenThreadToken, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "OpenAsSelf", "", DIR_IN, BOOLEAN,
    "TokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtOpenTimer, NTSTATUS,
    "TimerHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenTransactionManager, NTSTATUS,
    "TmHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
    "LogFileName", "opt", DIR_IN, PUNICODE_STRING,
    "TmIdentity", "opt", DIR_IN, LPGUID,
    "OpenOptions", "opt", DIR_IN, ULONG,
);
SYSCALL(NtOpenTransaction, NTSTATUS,
    "TransactionHandle", "", DIR_OUT, PHANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "Uow", "", DIR_IN, LPGUID,
    "TmHandle", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtPlugPlayControl, NTSTATUS,
    "PnPControlClass", "", DIR_IN, PLUGPLAY_CONTROL_CLASS,
    "PnPControlData", "bcount(PnPControlDataLength)", DIR_INOUT, PVOID,
    "PnPControlDataLength", "", DIR_IN, ULONG,
);
SYSCALL(NtPowerInformation, NTSTATUS,
    "InformationLevel", "", DIR_IN, POWER_INFORMATION_LEVEL,
    "InputBuffer", "bcount_opt(InputBufferLength)", DIR_IN, PVOID,
    "InputBufferLength", "", DIR_IN, ULONG,
    "OutputBuffer", "bcount_opt(OutputBufferLength)", DIR_OUT, PVOID,
    "OutputBufferLength", "", DIR_IN, ULONG,
);
SYSCALL(NtPrepareComplete, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtPrepareEnlistment, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtPrePrepareComplete, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtPrePrepareEnlistment, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtPrivilegeCheck, NTSTATUS,
    "ClientToken", "", DIR_IN, HANDLE,
    "RequiredPrivileges", "", DIR_INOUT, PPRIVILEGE_SET,
    "Result", "", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtPrivilegedServiceAuditAlarm, NTSTATUS,
    "SubsystemName", "", DIR_IN, PUNICODE_STRING,
    "ServiceName", "", DIR_IN, PUNICODE_STRING,
    "ClientToken", "", DIR_IN, HANDLE,
    "Privileges", "", DIR_IN, PPRIVILEGE_SET,
    "AccessGranted", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtPrivilegeObjectAuditAlarm, NTSTATUS,
    "SubsystemName", "", DIR_IN, PUNICODE_STRING,
    "HandleId", "opt", DIR_IN, PVOID,
    "ClientToken", "", DIR_IN, HANDLE,
    "DesiredAccess", "", DIR_IN, ACCESS_MASK,
    "Privileges", "", DIR_IN, PPRIVILEGE_SET,
    "AccessGranted", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtPropagationComplete, NTSTATUS,
    "ResourceManagerHandle", "", DIR_IN, HANDLE,
    "RequestCookie", "", DIR_IN, ULONG,
    "BufferLength", "", DIR_IN, ULONG,
    "Buffer", "", DIR_IN, PVOID,
);
SYSCALL(NtPropagationFailed, NTSTATUS,
    "ResourceManagerHandle", "", DIR_IN, HANDLE,
    "RequestCookie", "", DIR_IN, ULONG,
    "PropStatus", "", DIR_IN, NTSTATUS,
);
SYSCALL(NtProtectVirtualMemory, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "*BaseAddress", "", DIR_INOUT, PPVOID,
    "RegionSize", "", DIR_INOUT, PSIZE_T,
    "NewProtectWin32", "", DIR_IN, WIN32_PROTECTION_MASK,
    "OldProtect", "", DIR_OUT, PULONG,
);
SYSCALL(NtPulseEvent, NTSTATUS,
    "EventHandle", "", DIR_IN, HANDLE,
    "PreviousState", "opt", DIR_OUT, PLONG,
);
SYSCALL(NtQueryAttributesFile, NTSTATUS,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "FileInformation", "", DIR_OUT, PFILE_BASIC_INFORMATION,
);
SYSCALL(NtQueryBootEntryOrder, NTSTATUS,
    "Ids", "ecount_opt(*Count)", DIR_OUT, PULONG,
    "Count", "", DIR_INOUT, PULONG,
);
SYSCALL(NtQueryBootOptions, NTSTATUS,
    "BootOptions", "bcount_opt(*BootOptionsLength)", DIR_OUT, PBOOT_OPTIONS,
    "BootOptionsLength", "", DIR_INOUT, PULONG,
);
SYSCALL(NtQueryDebugFilterState, NTSTATUS,
    "ComponentId", "", DIR_IN, ULONG,
    "Level", "", DIR_IN, ULONG,
);
SYSCALL(NtQueryDefaultLocale, NTSTATUS,
    "UserProfile", "", DIR_IN, BOOLEAN,
    "DefaultLocaleId", "", DIR_OUT, PLCID,
);
SYSCALL(NtQueryDefaultUILanguage, NTSTATUS,
    "*DefaultUILanguageId", "", DIR_OUT, LANGID,
);
SYSCALL(NtQueryDirectoryFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "FileInformation", "bcount(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "FileInformationClass", "", DIR_IN, FILE_INFORMATION_CLASS,
    "ReturnSingleEntry", "", DIR_IN, BOOLEAN,
    "FileName", "", DIR_IN, PUNICODE_STRING,
    "RestartScan", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtQueryDirectoryObject, NTSTATUS,
    "DirectoryHandle", "", DIR_IN, HANDLE,
    "Buffer", "bcount_opt(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ReturnSingleEntry", "", DIR_IN, BOOLEAN,
    "RestartScan", "", DIR_IN, BOOLEAN,
    "Context", "", DIR_INOUT, PULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryDriverEntryOrder, NTSTATUS,
    "Ids", "ecount(*Count)", DIR_OUT, PULONG,
    "Count", "", DIR_INOUT, PULONG,
);
SYSCALL(NtQueryEaFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "Buffer", "bcount(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ReturnSingleEntry", "", DIR_IN, BOOLEAN,
    "EaList", "bcount_opt(EaListLength)", DIR_IN, PVOID,
    "EaListLength", "", DIR_IN, ULONG,
    "EaIndex", "opt", DIR_IN, PULONG,
    "RestartScan", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtQueryEvent, NTSTATUS,
    "EventHandle", "", DIR_IN, HANDLE,
    "EventInformationClass", "", DIR_IN, EVENT_INFORMATION_CLASS,
    "EventInformation", "bcount(EventInformationLength)", DIR_OUT, PVOID,
    "EventInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryFullAttributesFile, NTSTATUS,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "FileInformation", "", DIR_OUT, PFILE_NETWORK_OPEN_INFORMATION,
);
SYSCALL(NtQueryInformationAtom, NTSTATUS,
    "Atom", "", DIR_IN, RTL_ATOM,
    "InformationClass", "", DIR_IN, ATOM_INFORMATION_CLASS,
    "AtomInformation", "bcount(AtomInformationLength)", DIR_OUT, PVOID,
    "AtomInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationEnlistment, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "EnlistmentInformationClass", "", DIR_IN, ENLISTMENT_INFORMATION_CLASS,
    "EnlistmentInformation", "bcount(EnlistmentInformationLength)", DIR_OUT, PVOID,
    "EnlistmentInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "FileInformation", "bcount(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "FileInformationClass", "", DIR_IN, FILE_INFORMATION_CLASS,
);
SYSCALL(NtQueryInformationJobObject, NTSTATUS,
    "JobHandle", "opt", DIR_IN, HANDLE,
    "JobObjectInformationClass", "", DIR_IN, JOBOBJECTINFOCLASS,
    "JobObjectInformation", "bcount(JobObjectInformationLength)", DIR_OUT, PVOID,
    "JobObjectInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationPort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "PortInformationClass", "", DIR_IN, PORT_INFORMATION_CLASS,
    "PortInformation", "bcount(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationProcess, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "ProcessInformationClass", "", DIR_IN, PROCESSINFOCLASS,
    "ProcessInformation", "bcount(ProcessInformationLength)", DIR_OUT, PVOID,
    "ProcessInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationResourceManager, NTSTATUS,
    "ResourceManagerHandle", "", DIR_IN, HANDLE,
    "ResourceManagerInformationClass", "", DIR_IN, RESOURCEMANAGER_INFORMATION_CLASS,
    "ResourceManagerInformation", "bcount(ResourceManagerInformationLength)", DIR_OUT, PVOID,
    "ResourceManagerInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationThread, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "ThreadInformationClass", "", DIR_IN, THREADINFOCLASS,
    "ThreadInformation", "bcount(ThreadInformationLength)", DIR_OUT, PVOID,
    "ThreadInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationToken, NTSTATUS,
    "TokenHandle", "", DIR_IN, HANDLE,
    "TokenInformationClass", "", DIR_IN, TOKEN_INFORMATION_CLASS,
    "TokenInformation", "bcount_part_opt(TokenInformationLength,*ReturnLength)", DIR_OUT, PVOID,
    "TokenInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationTransaction, NTSTATUS,
    "TransactionHandle", "", DIR_IN, HANDLE,
    "TransactionInformationClass", "", DIR_IN, TRANSACTION_INFORMATION_CLASS,
    "TransactionInformation", "bcount(TransactionInformationLength)", DIR_OUT, PVOID,
    "TransactionInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationTransactionManager, NTSTATUS,
    "TransactionManagerHandle", "", DIR_IN, HANDLE,
    "TransactionManagerInformationClass", "", DIR_IN, TRANSACTIONMANAGER_INFORMATION_CLASS,
    "TransactionManagerInformation", "bcount(TransactionManagerInformationLength)", DIR_OUT, PVOID,
    "TransactionManagerInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationWorkerFactory, NTSTATUS,
    "WorkerFactoryHandle", "", DIR_IN, HANDLE,
    "WorkerFactoryInformationClass", "", DIR_IN, WORKERFACTORYINFOCLASS,
    "WorkerFactoryInformation", "bcount(WorkerFactoryInformationLength)", DIR_OUT, PVOID,
    "WorkerFactoryInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInstallUILanguage, NTSTATUS,
    "*InstallUILanguageId", "", DIR_OUT, LANGID,
);
SYSCALL(NtQueryIntervalProfile, NTSTATUS,
    "ProfileSource", "", DIR_IN, KPROFILE_SOURCE,
    "Interval", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryIoCompletion, NTSTATUS,
    "IoCompletionHandle", "", DIR_IN, HANDLE,
    "IoCompletionInformationClass", "", DIR_IN, IO_COMPLETION_INFORMATION_CLASS,
    "IoCompletionInformation", "bcount(IoCompletionInformationLength)", DIR_OUT, PVOID,
    "IoCompletionInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "KeyInformationClass", "", DIR_IN, KEY_INFORMATION_CLASS,
    "KeyInformation", "bcount_opt(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ResultLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryLicenseValue, NTSTATUS,
    "Name", "", DIR_IN, PUNICODE_STRING,
    "Type", "opt", DIR_OUT, PULONG,
    "Buffer", "bcount(ReturnedLength)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ReturnedLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryMultipleValueKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "ValueEntries", "ecount(EntryCount)", DIR_INOUT, PKEY_VALUE_ENTRY,
    "EntryCount", "", DIR_IN, ULONG,
    "ValueBuffer", "bcount(*BufferLength)", DIR_OUT, PVOID,
    "BufferLength", "", DIR_INOUT, PULONG,
    "RequiredBufferLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryMutant, NTSTATUS,
    "MutantHandle", "", DIR_IN, HANDLE,
    "MutantInformationClass", "", DIR_IN, MUTANT_INFORMATION_CLASS,
    "MutantInformation", "bcount(MutantInformationLength)", DIR_OUT, PVOID,
    "MutantInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryObject, NTSTATUS,
    "Handle", "", DIR_IN, HANDLE,
    "ObjectInformationClass", "", DIR_IN, OBJECT_INFORMATION_CLASS,
    "ObjectInformation", "bcount_opt(ObjectInformationLength)", DIR_OUT, PVOID,
    "ObjectInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryOpenSubKeysEx, NTSTATUS,
    "TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
    "BufferLength", "", DIR_IN, ULONG,
    "Buffer", "bcount(BufferLength)", DIR_OUT, PVOID,
    "RequiredSize", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryOpenSubKeys, NTSTATUS,
    "TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
    "HandleCount", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryPerformanceCounter, NTSTATUS,
    "PerformanceCounter", "", DIR_OUT, PLARGE_INTEGER,
    "PerformanceFrequency", "opt", DIR_OUT, PLARGE_INTEGER,
);
SYSCALL(NtQueryQuotaInformationFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "Buffer", "bcount(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ReturnSingleEntry", "", DIR_IN, BOOLEAN,
    "SidList", "bcount_opt(SidListLength)", DIR_IN, PVOID,
    "SidListLength", "", DIR_IN, ULONG,
    "StartSid", "opt", DIR_IN, PULONG,
    "RestartScan", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtQuerySection, NTSTATUS,
    "SectionHandle", "", DIR_IN, HANDLE,
    "SectionInformationClass", "", DIR_IN, SECTION_INFORMATION_CLASS,
    "SectionInformation", "bcount(SectionInformationLength)", DIR_OUT, PVOID,
    "SectionInformationLength", "", DIR_IN, SIZE_T,
    "ReturnLength", "opt", DIR_OUT, PSIZE_T,
);
SYSCALL(NtQuerySecurityAttributesToken, NTSTATUS,
    "TokenHandle", "", DIR_IN, HANDLE,
    "Attributes", "ecount_opt(NumberOfAttributes)", DIR_IN, PUNICODE_STRING,
    "NumberOfAttributes", "", DIR_IN, ULONG,
    "Buffer", "bcount(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySecurityObject, NTSTATUS,
    "Handle", "", DIR_IN, HANDLE,
    "SecurityInformation", "", DIR_IN, SECURITY_INFORMATION,
    "SecurityDescriptor", "bcount_opt(Length)", DIR_OUT, PSECURITY_DESCRIPTOR,
    "Length", "", DIR_IN, ULONG,
    "LengthNeeded", "", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySemaphore, NTSTATUS,
    "SemaphoreHandle", "", DIR_IN, HANDLE,
    "SemaphoreInformationClass", "", DIR_IN, SEMAPHORE_INFORMATION_CLASS,
    "SemaphoreInformation", "bcount(SemaphoreInformationLength)", DIR_OUT, PVOID,
    "SemaphoreInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySymbolicLinkObject, NTSTATUS,
    "LinkHandle", "", DIR_IN, HANDLE,
    "LinkTarget", "", DIR_INOUT, PUNICODE_STRING,
    "ReturnedLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySystemEnvironmentValueEx, NTSTATUS,
    "VariableName", "", DIR_IN, PUNICODE_STRING,
    "VendorGuid", "", DIR_IN, LPGUID,
    "Value", "bcount_opt(*ValueLength)", DIR_OUT, PVOID,
    "ValueLength", "", DIR_INOUT, PULONG,
    "Attributes", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySystemEnvironmentValue, NTSTATUS,
    "VariableName", "", DIR_IN, PUNICODE_STRING,
    "VariableValue", "bcount(ValueLength)", DIR_OUT, PWSTR,
    "ValueLength", "", DIR_IN, USHORT,
    "ReturnLength", "opt", DIR_OUT, PUSHORT,
);
SYSCALL(NtQuerySystemInformationEx, NTSTATUS,
    "SystemInformationClass", "", DIR_IN, SYSTEM_INFORMATION_CLASS,
    "QueryInformation", "bcount(QueryInformationLength)", DIR_IN, PVOID,
    "QueryInformationLength", "", DIR_IN, ULONG,
    "SystemInformation", "bcount_opt(SystemInformationLength)", DIR_OUT, PVOID,
    "SystemInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySystemInformation, NTSTATUS,
    "SystemInformationClass", "", DIR_IN, SYSTEM_INFORMATION_CLASS,
    "SystemInformation", "bcount_opt(SystemInformationLength)", DIR_OUT, PVOID,
    "SystemInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySystemTime, NTSTATUS,
    "SystemTime", "", DIR_OUT, PLARGE_INTEGER,
);
SYSCALL(NtQueryTimer, NTSTATUS,
    "TimerHandle", "", DIR_IN, HANDLE,
    "TimerInformationClass", "", DIR_IN, TIMER_INFORMATION_CLASS,
    "TimerInformation", "bcount(TimerInformationLength)", DIR_OUT, PVOID,
    "TimerInformationLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryTimerResolution, NTSTATUS,
    "MaximumTime", "", DIR_OUT, PULONG,
    "MinimumTime", "", DIR_OUT, PULONG,
    "CurrentTime", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryValueKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "ValueName", "", DIR_IN, PUNICODE_STRING,
    "KeyValueInformationClass", "", DIR_IN, KEY_VALUE_INFORMATION_CLASS,
    "KeyValueInformation", "bcount_opt(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ResultLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryVirtualMemory, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "BaseAddress", "", DIR_IN, PVOID,
    "MemoryInformationClass", "", DIR_IN, MEMORY_INFORMATION_CLASS,
    "MemoryInformation", "bcount(MemoryInformationLength)", DIR_OUT, PVOID,
    "MemoryInformationLength", "", DIR_IN, SIZE_T,
    "ReturnLength", "opt", DIR_OUT, PSIZE_T,
);
SYSCALL(NtQueryVolumeInformationFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "FsInformation", "bcount(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "FsInformationClass", "", DIR_IN, FS_INFORMATION_CLASS,
);
SYSCALL(NtQueueApcThreadEx, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "UserApcReserveHandle", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "", DIR_IN, PPS_APC_ROUTINE,
    "ApcArgument1", "opt", DIR_IN, PVOID,
    "ApcArgument2", "opt", DIR_IN, PVOID,
    "ApcArgument3", "opt", DIR_IN, PVOID,
);
SYSCALL(NtQueueApcThread, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "ApcRoutine", "", DIR_IN, PPS_APC_ROUTINE,
    "ApcArgument1", "opt", DIR_IN, PVOID,
    "ApcArgument2", "opt", DIR_IN, PVOID,
    "ApcArgument3", "opt", DIR_IN, PVOID,
);
SYSCALL(NtRaiseException, NTSTATUS,
    "ExceptionRecord", "", DIR_OUT, PEXCEPTION_RECORD,
    "ContextRecord", "", DIR_OUT, PCONTEXT,
    "FirstChance", "", DIR_OUT, BOOLEAN,
);
SYSCALL(NtRaiseHardError, NTSTATUS,
    "ErrorStatus", "", DIR_IN, NTSTATUS,
    "NumberOfParameters", "", DIR_IN, ULONG,
    "UnicodeStringParameterMask", "", DIR_IN, ULONG,
    "Parameters", "ecount(NumberOfParameters)", DIR_IN, PULONG_PTR,
    "ValidResponseOptions", "", DIR_IN, ULONG,
    "Response", "", DIR_OUT, PULONG,
);
SYSCALL(NtReadFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "Buffer", "bcount(Length)", DIR_OUT, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ByteOffset", "opt", DIR_IN, PLARGE_INTEGER,
    "Key", "opt", DIR_IN, PULONG,
);
SYSCALL(NtReadFileScatter, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "SegmentArray", "", DIR_IN, PFILE_SEGMENT_ELEMENT,
    "Length", "", DIR_IN, ULONG,
    "ByteOffset", "opt", DIR_IN, PLARGE_INTEGER,
    "Key", "opt", DIR_IN, PULONG,
);
SYSCALL(NtReadOnlyEnlistment, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtReadRequestData, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Message", "", DIR_IN, PPORT_MESSAGE,
    "DataEntryIndex", "", DIR_IN, ULONG,
    "Buffer", "bcount(BufferSize)", DIR_OUT, PVOID,
    "BufferSize", "", DIR_IN, SIZE_T,
    "NumberOfBytesRead", "opt", DIR_OUT, PSIZE_T,
);
SYSCALL(NtReadVirtualMemory, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "BaseAddress", "opt", DIR_IN, PVOID,
    "Buffer", "bcount(BufferSize)", DIR_OUT, PVOID,
    "BufferSize", "", DIR_IN, SIZE_T,
    "NumberOfBytesRead", "opt", DIR_OUT, PSIZE_T,
);
SYSCALL(NtRecoverEnlistment, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "EnlistmentKey", "opt", DIR_IN, PVOID,
);
SYSCALL(NtRecoverResourceManager, NTSTATUS,
    "ResourceManagerHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtRecoverTransactionManager, NTSTATUS,
    "TransactionManagerHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtRegisterProtocolAddressInformation, NTSTATUS,
    "ResourceManager", "", DIR_IN, HANDLE,
    "ProtocolId", "", DIR_IN, PCRM_PROTOCOL_ID,
    "ProtocolInformationSize", "", DIR_IN, ULONG,
    "ProtocolInformation", "", DIR_IN, PVOID,
    "CreateOptions", "opt", DIR_IN, ULONG,
);
SYSCALL(NtRegisterThreadTerminatePort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtReleaseKeyedEvent, NTSTATUS,
    "KeyedEventHandle", "", DIR_IN, HANDLE,
    "KeyValue", "", DIR_IN, PVOID,
    "Alertable", "", DIR_IN, BOOLEAN,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtReleaseMutant, NTSTATUS,
    "MutantHandle", "", DIR_IN, HANDLE,
    "PreviousCount", "opt", DIR_OUT, PLONG,
);
SYSCALL(NtReleaseSemaphore, NTSTATUS,
    "SemaphoreHandle", "", DIR_IN, HANDLE,
    "ReleaseCount", "", DIR_IN, LONG,
    "PreviousCount", "opt", DIR_OUT, PLONG,
);
SYSCALL(NtReleaseWorkerFactoryWorker, NTSTATUS,
    "WorkerFactoryHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtRemoveIoCompletionEx, NTSTATUS,
    "IoCompletionHandle", "", DIR_IN, HANDLE,
    "IoCompletionInformation", "ecount(Count)", DIR_OUT, PFILE_IO_COMPLETION_INFORMATION,
    "Count", "", DIR_IN, ULONG,
    "NumEntriesRemoved", "", DIR_OUT, PULONG,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
    "Alertable", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtRemoveIoCompletion, NTSTATUS,
    "IoCompletionHandle", "", DIR_IN, HANDLE,
    "*KeyContext", "", DIR_OUT, PVOID,
    "*ApcContext", "", DIR_OUT, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtRemoveProcessDebug, NTSTATUS,
    "ProcessHandle", "", DIR_OUT, HANDLE,
    "DebugObjectHandle", "", DIR_OUT, HANDLE,
);
SYSCALL(NtRenameKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "NewName", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtRenameTransactionManager, NTSTATUS,
    "LogFileName", "", DIR_IN, PUNICODE_STRING,
    "ExistingTransactionManagerGuid", "", DIR_IN, LPGUID,
);
SYSCALL(NtReplaceKey, NTSTATUS,
    "NewFile", "", DIR_IN, POBJECT_ATTRIBUTES,
    "TargetHandle", "", DIR_IN, HANDLE,
    "OldFile", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtReplacePartitionUnit, NTSTATUS,
    "TargetInstancePath", "", DIR_IN, PUNICODE_STRING,
    "SpareInstancePath", "", DIR_IN, PUNICODE_STRING,
    "Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtReplyPort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "ReplyMessage", "", DIR_IN, PPORT_MESSAGE,
);
SYSCALL(NtReplyWaitReceivePortEx, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "*PortContext", "opt", DIR_OUT, PVOID,
    "ReplyMessage", "opt", DIR_IN, PPORT_MESSAGE,
    "ReceiveMessage", "", DIR_OUT, PPORT_MESSAGE,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtReplyWaitReceivePort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "*PortContext", "opt", DIR_OUT, PVOID,
    "ReplyMessage", "opt", DIR_IN, PPORT_MESSAGE,
    "ReceiveMessage", "", DIR_OUT, PPORT_MESSAGE,
);
SYSCALL(NtReplyWaitReplyPort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "ReplyMessage", "", DIR_INOUT, PPORT_MESSAGE,
);
SYSCALL(NtRequestPort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "RequestMessage", "", DIR_IN, PPORT_MESSAGE,
);
SYSCALL(NtRequestWaitReplyPort, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "RequestMessage", "", DIR_IN, PPORT_MESSAGE,
    "ReplyMessage", "", DIR_OUT, PPORT_MESSAGE,
);
SYSCALL(NtResetEvent, NTSTATUS,
    "EventHandle", "", DIR_IN, HANDLE,
    "PreviousState", "opt", DIR_OUT, PLONG,
);
SYSCALL(NtResetWriteWatch, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "BaseAddress", "", DIR_IN, PVOID,
    "RegionSize", "", DIR_IN, SIZE_T,
);
SYSCALL(NtRestoreKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "FileHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtResumeProcess, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtResumeThread, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "PreviousSuspendCount", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtRollbackComplete, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtRollbackEnlistment, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtRollbackTransaction, NTSTATUS,
    "TransactionHandle", "", DIR_IN, HANDLE,
    "Wait", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtRollforwardTransactionManager, NTSTATUS,
    "TransactionManagerHandle", "", DIR_IN, HANDLE,
    "TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtSaveKeyEx, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "FileHandle", "", DIR_IN, HANDLE,
    "Format", "", DIR_IN, ULONG,
);
SYSCALL(NtSaveKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "FileHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSaveMergedKeys, NTSTATUS,
    "HighPrecedenceKeyHandle", "", DIR_IN, HANDLE,
    "LowPrecedenceKeyHandle", "", DIR_IN, HANDLE,
    "FileHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSecureConnectPort, NTSTATUS,
    "PortHandle", "", DIR_OUT, PHANDLE,
    "PortName", "", DIR_IN, PUNICODE_STRING,
    "SecurityQos", "", DIR_IN, PSECURITY_QUALITY_OF_SERVICE,
    "ClientView", "opt", DIR_INOUT, PPORT_VIEW,
    "RequiredServerSid", "opt", DIR_IN, PSID,
    "ServerView", "opt", DIR_INOUT, PREMOTE_PORT_VIEW,
    "MaxMessageLength", "opt", DIR_OUT, PULONG,
    "ConnectionInformation", "opt", DIR_INOUT, PVOID,
    "ConnectionInformationLength", "opt", DIR_INOUT, PULONG,
);
SYSCALL(NtSetBootEntryOrder, NTSTATUS,
    "Ids", "ecount(Count)", DIR_IN, PULONG,
    "Count", "", DIR_IN, ULONG,
);
SYSCALL(NtSetBootOptions, NTSTATUS,
    "BootOptions", "", DIR_IN, PBOOT_OPTIONS,
    "FieldsToChange", "", DIR_IN, ULONG,
);
SYSCALL(NtSetContextThread, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "ThreadContext", "", DIR_IN, PCONTEXT,
);
SYSCALL(NtSetDebugFilterState, NTSTATUS,
    "ComponentId", "", DIR_IN, ULONG,
    "Level", "", DIR_IN, ULONG,
    "State", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtSetDefaultHardErrorPort, NTSTATUS,
    "DefaultHardErrorPort", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetDefaultLocale, NTSTATUS,
    "UserProfile", "", DIR_IN, BOOLEAN,
    "DefaultLocaleId", "", DIR_IN, LCID,
);
SYSCALL(NtSetDefaultUILanguage, NTSTATUS,
    "DefaultUILanguageId", "", DIR_IN, LANGID,
);
SYSCALL(NtSetDriverEntryOrder, NTSTATUS,
    "Ids", "ecount(Count)", DIR_IN, PULONG,
    "Count", "", DIR_IN, ULONG,
);
SYSCALL(NtSetEaFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "Buffer", "bcount(Length)", DIR_IN, PVOID,
    "Length", "", DIR_IN, ULONG,
);
SYSCALL(NtSetEventBoostPriority, NTSTATUS,
    "EventHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetEvent, NTSTATUS,
    "EventHandle", "", DIR_IN, HANDLE,
    "PreviousState", "opt", DIR_OUT, PLONG,
);
SYSCALL(NtSetHighEventPair, NTSTATUS,
    "EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetHighWaitLowEventPair, NTSTATUS,
    "EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetInformationDebugObject, NTSTATUS,
    "DebugObjectHandle", "", DIR_OUT, HANDLE,
    "DebugObjectInformationClass", "", DIR_OUT, DEBUGOBJECTINFOCLASS,
    "DebugInformation", "", DIR_OUT, PVOID,
    "DebugInformationLength", "", DIR_OUT, ULONG,
    "ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtSetInformationEnlistment, NTSTATUS,
    "EnlistmentHandle", "opt", DIR_IN, HANDLE,
    "EnlistmentInformationClass", "", DIR_IN, ENLISTMENT_INFORMATION_CLASS,
    "EnlistmentInformation", "bcount(EnlistmentInformationLength)", DIR_IN, PVOID,
    "EnlistmentInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "FileInformation", "bcount(Length)", DIR_IN, PVOID,
    "Length", "", DIR_IN, ULONG,
    "FileInformationClass", "", DIR_IN, FILE_INFORMATION_CLASS,
);
SYSCALL(NtSetInformationJobObject, NTSTATUS,
    "JobHandle", "", DIR_IN, HANDLE,
    "JobObjectInformationClass", "", DIR_IN, JOBOBJECTINFOCLASS,
    "JobObjectInformation", "bcount(JobObjectInformationLength)", DIR_IN, PVOID,
    "JobObjectInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "KeySetInformationClass", "", DIR_IN, KEY_SET_INFORMATION_CLASS,
    "KeySetInformation", "bcount(KeySetInformationLength)", DIR_IN, PVOID,
    "KeySetInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationObject, NTSTATUS,
    "Handle", "", DIR_IN, HANDLE,
    "ObjectInformationClass", "", DIR_IN, OBJECT_INFORMATION_CLASS,
    "ObjectInformation", "bcount(ObjectInformationLength)", DIR_IN, PVOID,
    "ObjectInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationProcess, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "ProcessInformationClass", "", DIR_IN, PROCESSINFOCLASS,
    "ProcessInformation", "bcount(ProcessInformationLength)", DIR_IN, PVOID,
    "ProcessInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationResourceManager, NTSTATUS,
    "ResourceManagerHandle", "", DIR_IN, HANDLE,
    "ResourceManagerInformationClass", "", DIR_IN, RESOURCEMANAGER_INFORMATION_CLASS,
    "ResourceManagerInformation", "bcount(ResourceManagerInformationLength)", DIR_IN, PVOID,
    "ResourceManagerInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationThread, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "ThreadInformationClass", "", DIR_IN, THREADINFOCLASS,
    "ThreadInformation", "bcount(ThreadInformationLength)", DIR_IN, PVOID,
    "ThreadInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationToken, NTSTATUS,
    "TokenHandle", "", DIR_IN, HANDLE,
    "TokenInformationClass", "", DIR_IN, TOKEN_INFORMATION_CLASS,
    "TokenInformation", "bcount(TokenInformationLength)", DIR_IN, PVOID,
    "TokenInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationTransaction, NTSTATUS,
    "TransactionHandle", "", DIR_IN, HANDLE,
    "TransactionInformationClass", "", DIR_IN, TRANSACTION_INFORMATION_CLASS,
    "TransactionInformation", "bcount(TransactionInformationLength)", DIR_IN, PVOID,
    "TransactionInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationTransactionManager, NTSTATUS,
    "TmHandle", "opt", DIR_IN, HANDLE,
    "TransactionManagerInformationClass", "", DIR_IN, TRANSACTIONMANAGER_INFORMATION_CLASS,
    "TransactionManagerInformation", "bcount(TransactionManagerInformationLength)", DIR_IN, PVOID,
    "TransactionManagerInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationWorkerFactory, NTSTATUS,
    "WorkerFactoryHandle", "", DIR_IN, HANDLE,
    "WorkerFactoryInformationClass", "", DIR_IN, WORKERFACTORYINFOCLASS,
    "WorkerFactoryInformation", "bcount(WorkerFactoryInformationLength)", DIR_IN, PVOID,
    "WorkerFactoryInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetIntervalProfile, NTSTATUS,
    "Interval", "", DIR_IN, ULONG,
    "Source", "", DIR_IN, KPROFILE_SOURCE,
);
SYSCALL(NtSetIoCompletionEx, NTSTATUS,
    "IoCompletionHandle", "", DIR_IN, HANDLE,
    "IoCompletionReserveHandle", "", DIR_IN, HANDLE,
    "KeyContext", "", DIR_IN, PVOID,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatus", "", DIR_IN, NTSTATUS,
    "IoStatusInformation", "", DIR_IN, ULONG_PTR,
);
SYSCALL(NtSetIoCompletion, NTSTATUS,
    "IoCompletionHandle", "", DIR_IN, HANDLE,
    "KeyContext", "", DIR_IN, PVOID,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatus", "", DIR_IN, NTSTATUS,
    "IoStatusInformation", "", DIR_IN, ULONG_PTR,
);
SYSCALL(NtSetLdtEntries, NTSTATUS,
    "Selector0", "", DIR_IN, ULONG,
    "Entry0Low", "", DIR_IN, ULONG,
    "Entry0Hi", "", DIR_IN, ULONG,
    "Selector1", "", DIR_IN, ULONG,
    "Entry1Low", "", DIR_IN, ULONG,
    "Entry1Hi", "", DIR_IN, ULONG,
);
SYSCALL(NtSetLowEventPair, NTSTATUS,
    "EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetLowWaitHighEventPair, NTSTATUS,
    "EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetQuotaInformationFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "Buffer", "bcount(Length)", DIR_IN, PVOID,
    "Length", "", DIR_IN, ULONG,
);
SYSCALL(NtSetSecurityObject, NTSTATUS,
    "Handle", "", DIR_IN, HANDLE,
    "SecurityInformation", "", DIR_IN, SECURITY_INFORMATION,
    "SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR,
);
SYSCALL(NtSetSystemEnvironmentValueEx, NTSTATUS,
    "VariableName", "", DIR_IN, PUNICODE_STRING,
    "VendorGuid", "", DIR_IN, LPGUID,
    "Value", "bcount_opt(ValueLength)", DIR_IN, PVOID,
    "ValueLength", "", DIR_IN, ULONG,
    "Attributes", "", DIR_IN, ULONG,
);
SYSCALL(NtSetSystemEnvironmentValue, NTSTATUS,
    "VariableName", "", DIR_IN, PUNICODE_STRING,
    "VariableValue", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtSetSystemInformation, NTSTATUS,
    "SystemInformationClass", "", DIR_IN, SYSTEM_INFORMATION_CLASS,
    "SystemInformation", "bcount_opt(SystemInformationLength)", DIR_IN, PVOID,
    "SystemInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetSystemPowerState, NTSTATUS,
    "SystemAction", "", DIR_IN, POWER_ACTION,
    "MinSystemState", "", DIR_IN, SYSTEM_POWER_STATE,
    "Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtSetSystemTime, NTSTATUS,
    "SystemTime", "opt", DIR_IN, PLARGE_INTEGER,
    "PreviousTime", "opt", DIR_OUT, PLARGE_INTEGER,
);
SYSCALL(NtSetThreadExecutionState, NTSTATUS,
    "esFlags", "", DIR_IN, EXECUTION_STATE,
    "*PreviousFlags", "", DIR_OUT, EXECUTION_STATE,
);
SYSCALL(NtSetTimerEx, NTSTATUS,
    "TimerHandle", "", DIR_IN, HANDLE,
    "TimerSetInformationClass", "", DIR_IN, TIMER_SET_INFORMATION_CLASS,
    "TimerSetInformation", "bcount(TimerSetInformationLength)", DIR_INOUT, PVOID,
    "TimerSetInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetTimer, NTSTATUS,
    "TimerHandle", "", DIR_IN, HANDLE,
    "DueTime", "", DIR_IN, PLARGE_INTEGER,
    "TimerApcRoutine", "opt", DIR_IN, PTIMER_APC_ROUTINE,
    "TimerContext", "opt", DIR_IN, PVOID,
    "WakeTimer", "", DIR_IN, BOOLEAN,
    "Period", "opt", DIR_IN, LONG,
    "PreviousState", "opt", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtSetTimerResolution, NTSTATUS,
    "DesiredTime", "", DIR_IN, ULONG,
    "SetResolution", "", DIR_IN, BOOLEAN,
    "ActualTime", "", DIR_OUT, PULONG,
);
SYSCALL(NtSetUuidSeed, NTSTATUS,
    "Seed", "", DIR_IN, PCHAR,
);
SYSCALL(NtSetValueKey, NTSTATUS,
    "KeyHandle", "", DIR_IN, HANDLE,
    "ValueName", "", DIR_IN, PUNICODE_STRING,
    "TitleIndex", "opt", DIR_IN, ULONG,
    "Type", "", DIR_IN, ULONG,
    "Data", "bcount_opt(DataSize)", DIR_IN, PVOID,
    "DataSize", "", DIR_IN, ULONG,
);
SYSCALL(NtSetVolumeInformationFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "FsInformation", "bcount(Length)", DIR_IN, PVOID,
    "Length", "", DIR_IN, ULONG,
    "FsInformationClass", "", DIR_IN, FS_INFORMATION_CLASS,
);
SYSCALL(NtShutdownSystem, NTSTATUS,
    "Action", "", DIR_IN, SHUTDOWN_ACTION,
);
SYSCALL(NtShutdownWorkerFactory, NTSTATUS,
    "WorkerFactoryHandle", "", DIR_IN, HANDLE,
    "*PendingWorkerCount", "", DIR_INOUT, LONG,
);
SYSCALL(NtSignalAndWaitForSingleObject, NTSTATUS,
    "SignalHandle", "", DIR_IN, HANDLE,
    "WaitHandle", "", DIR_IN, HANDLE,
    "Alertable", "", DIR_IN, BOOLEAN,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtSinglePhaseReject, NTSTATUS,
    "EnlistmentHandle", "", DIR_IN, HANDLE,
    "TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtStartProfile, NTSTATUS,
    "ProfileHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtStopProfile, NTSTATUS,
    "ProfileHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSuspendProcess, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSuspendThread, NTSTATUS,
    "ThreadHandle", "", DIR_IN, HANDLE,
    "PreviousSuspendCount", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtSystemDebugControl, NTSTATUS,
    "Command", "", DIR_IN, SYSDBG_COMMAND,
    "InputBuffer", "bcount_opt(InputBufferLength)", DIR_INOUT, PVOID,
    "InputBufferLength", "", DIR_IN, ULONG,
    "OutputBuffer", "bcount_opt(OutputBufferLength)", DIR_OUT, PVOID,
    "OutputBufferLength", "", DIR_IN, ULONG,
    "ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtTerminateJobObject, NTSTATUS,
    "JobHandle", "", DIR_IN, HANDLE,
    "ExitStatus", "", DIR_IN, NTSTATUS,
);
SYSCALL(NtTerminateProcess, NTSTATUS,
    "ProcessHandle", "opt", DIR_IN, HANDLE,
    "ExitStatus", "", DIR_IN, NTSTATUS,
);
SYSCALL(NtTerminateThread, NTSTATUS,
    "ThreadHandle", "opt", DIR_IN, HANDLE,
    "ExitStatus", "", DIR_IN, NTSTATUS,
);
SYSCALL(NtTraceControl, NTSTATUS,
    "FunctionCode", "", DIR_IN, ULONG,
    "InBuffer", "bcount_opt(InBufferLen)", DIR_IN, PVOID,
    "InBufferLen", "", DIR_IN, ULONG,
    "OutBuffer", "bcount_opt(OutBufferLen)", DIR_OUT, PVOID,
    "OutBufferLen", "", DIR_IN, ULONG,
    "ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtTraceEvent, NTSTATUS,
    "TraceHandle", "", DIR_IN, HANDLE,
    "Flags", "", DIR_IN, ULONG,
    "FieldSize", "", DIR_IN, ULONG,
    "Fields", "", DIR_IN, PVOID,
);
SYSCALL(NtTranslateFilePath, NTSTATUS,
    "InputFilePath", "", DIR_IN, PFILE_PATH,
    "OutputType", "", DIR_IN, ULONG,
    "OutputFilePath", "bcount_opt(*OutputFilePathLength)", DIR_OUT, PFILE_PATH,
    "OutputFilePathLength", "opt", DIR_INOUT, PULONG,
);
SYSCALL(NtUnloadDriver, NTSTATUS,
    "DriverServiceName", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtUnloadKey2, NTSTATUS,
    "TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
    "Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtUnloadKeyEx, NTSTATUS,
    "TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
    "Event", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtUnloadKey, NTSTATUS,
    "TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtUnlockFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "ByteOffset", "", DIR_IN, PLARGE_INTEGER,
    "Length", "", DIR_IN, PLARGE_INTEGER,
    "Key", "", DIR_IN, ULONG,
);
SYSCALL(NtUnlockVirtualMemory, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "*BaseAddress", "", DIR_INOUT, PPVOID,
    "RegionSize", "", DIR_INOUT, PSIZE_T,
    "MapType", "", DIR_IN, ULONG,
);
SYSCALL(NtUnmapViewOfSection, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "BaseAddress", "", DIR_IN, PVOID,
);
SYSCALL(NtUnmapViewOfSectionEx, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "BaseAddress", "", DIR_IN, PVOID,
    "Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtUserBlockInput, NTSTATUS,
    "BlockIt", "", DIR_IN, BOOLEAN
);
SYSCALL(NtUserCallNextHookEx, NTSTATUS,
    "Code", "", DIR_IN, INT,
    "wParam", "", DIR_IN, WPARAM,
    "lParam", "", DIR_IN, LPARAM,
    "Ansi", "", DIR_IN, BOOLEAN);
SYSCALL(NtUserCallTwoParam, NTSTATUS,
    "Param1", "", DIR_IN, DWORD,
    "Param2", "", DIR_IN, DWORD,
    "Routine", "", DIR_IN, DWORD);
SYSCALL(NtUserCreateDesktop, NTSTATUS,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "lpszDevice", "", DIR_IN, PUNICODE_STRING,
    "devmode", "", DIR_IN, PVOID,
    "dwflags", "", DIR_IN, DWORD,
    "access", "", DIR_IN, ACCESS_MASK,
    "heapsize", "", DIR_IN, DWORD);
SYSCALL(NtUserCreateDesktopEx, NTSTATUS,
    "ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
    "lpszDevice", "", DIR_IN, PUNICODE_STRING,
    "devmode", "", DIR_IN, PVOID,
    "dwflags", "", DIR_IN, DWORD,
    "access", "", DIR_IN, ACCESS_MASK,
    "heapsize", "", DIR_IN, DWORD);
SYSCALL(NtUserGetAsyncKeyState, SHORT,
    "Key", "", DIR_IN, INT
);
SYSCALL(NtUserGetDC, HANDLE,
    "hWnd", "", DIR_IN, HWND);
SYSCALL(NtUserGetKeyState, SHORT,
    "VirtKey", "", DIR_IN, INT
);
SYSCALL(NtUserLoadKeyboardLayoutEx, NTSTATUS,
    "Handle", "", DIR_IN, HANDLE,
    "offTable", "", DIR_IN, DWORD,
    "puszKeyboardName", "", DIR_IN, PUNICODE_STRING,
    "hKL", "", DIR_IN, HANDLE,
    "puszKLID", "", DIR_IN, PUNICODE_STRING,
    "dwKLID", "", DIR_IN, DWORD,
    "Flags", "", DIR_IN, UINT
);
SYSCALL(NtUserMessageCall, NTSTATUS,
    "hWnd", "", DIR_IN, HWND,
    "Msg", "", DIR_IN, UINT,
    "wParam", "", DIR_IN, WPARAM,
    "lParam", "", DIR_IN, LPARAM,
    "ResultInfo", "", DIR_IN, ULONG_PTR,
    "dwType", "", DIR_IN, DWORD,
    "Ansi", "", DIR_IN, BOOLEAN);
SYSCALL(NtUserSetWindowLong, NTSTATUS,
    "hWnd", "", DIR_IN, HWND,
    "nIndex", "", DIR_IN, INT,
    "dwNewLong", "", DIR_IN, LONG,
    "Ansi", "", DIR_IN, BOOLEAN);
SYSCALL(NtUserSetWindowsHookEx, HHOOK,
    "Mod", "", DIR_IN, HINSTANCE,
    "UnsafeModuleName", "", DIR_IN, PUNICODE_STRING,
    "ThreadId", "", DIR_IN, DWORD,
    "HookId", "", DIR_IN, INT,
    "HookProc", "", DIR_IN, HOOKPROC,
    "Ansi", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtUserShowWindow, NTSTATUS,
    "hWnd", "", DIR_IN, HWND,
    "nCmdShow", "", DIR_IN, LONG
);
SYSCALL(NtVdmControl, NTSTATUS,
    "Service", "", DIR_IN, VDMSERVICECLASS,
    "ServiceData", "", DIR_INOUT, PVOID,
);
SYSCALL(NtWaitForDebugEvent, NTSTATUS,
    "DebugObjectHandle", "", DIR_OUT, HANDLE,
    "Alertable", "", DIR_OUT, BOOLEAN,
    "Timeout", "", DIR_OUT, PLARGE_INTEGER,
    "WaitStateChange", "", DIR_OUT, PDBGUI_WAIT_STATE_CHANGE,
);
SYSCALL(NtWaitForKeyedEvent, NTSTATUS,
    "KeyedEventHandle", "", DIR_IN, HANDLE,
    "KeyValue", "", DIR_IN, PVOID,
    "Alertable", "", DIR_IN, BOOLEAN,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtWaitForMultipleObjects32, NTSTATUS,
    "Count", "", DIR_IN, ULONG,
    "Handles[]", "ecount(Count)", DIR_IN, LONG,
    "WaitType", "", DIR_IN, WAIT_TYPE,
    "Alertable", "", DIR_IN, BOOLEAN,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtWaitForMultipleObjects, NTSTATUS,
    "Count", "", DIR_IN, ULONG,
    "Handles[]", "ecount(Count)", DIR_IN, HANDLE,
    "WaitType", "", DIR_IN, WAIT_TYPE,
    "Alertable", "", DIR_IN, BOOLEAN,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtWaitForSingleObject, NTSTATUS,
    "Handle", "", DIR_IN, HANDLE,
    "Alertable", "", DIR_IN, BOOLEAN,
    "Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtWaitForWorkViaWorkerFactory, NTSTATUS,
    "WorkerFactoryHandle", "", DIR_IN, HANDLE,
    "MiniPacket", "", DIR_OUT, PFILE_IO_COMPLETION_INFORMATION,
);
SYSCALL(NtWaitHighEventPair, NTSTATUS,
    "EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtWaitLowEventPair, NTSTATUS,
    "EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtWorkerFactoryWorkerReady, NTSTATUS,
    "WorkerFactoryHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtWriteFileGather, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "SegmentArray", "", DIR_IN, PFILE_SEGMENT_ELEMENT,
    "Length", "", DIR_IN, ULONG,
    "ByteOffset", "opt", DIR_IN, PLARGE_INTEGER,
    "Key", "opt", DIR_IN, PULONG,
);
SYSCALL(NtWriteFile, NTSTATUS,
    "FileHandle", "", DIR_IN, HANDLE,
    "Event", "opt", DIR_IN, HANDLE,
    "ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE,
    "ApcContext", "opt", DIR_IN, PVOID,
    "IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
    "Buffer", "bcount(Length)", DIR_IN, PVOID,
    "Length", "", DIR_IN, ULONG,
    "ByteOffset", "opt", DIR_IN, PLARGE_INTEGER,
    "Key", "opt", DIR_IN, PULONG,
);
SYSCALL(NtWriteRequestData, NTSTATUS,
    "PortHandle", "", DIR_IN, HANDLE,
    "Message", "", DIR_IN, PPORT_MESSAGE,
    "DataEntryIndex", "", DIR_IN, ULONG,
    "Buffer", "bcount(BufferSize)", DIR_IN, PVOID,
    "BufferSize", "", DIR_IN, SIZE_T,
    "NumberOfBytesWritten", "opt", DIR_OUT, PSIZE_T,
);
SYSCALL(NtWriteVirtualMemory, NTSTATUS,
    "ProcessHandle", "", DIR_IN, HANDLE,
    "BaseAddress", "opt", DIR_IN, PVOID,
    "Buffer", "bcount(BufferSize)", DIR_IN, PVOID,
    "BufferSize", "", DIR_IN, SIZE_T,
    "NumberOfBytesWritten", "opt", DIR_OUT, PSIZE_T,
);

// TODO: fill in argument information
SYSCALL(NtUmsThreadYield, NTSTATUS);
SYSCALL(NtThawTransactions, NTSTATUS);
SYSCALL(NtThawRegistry, NTSTATUS);
SYSCALL(NtTestAlert, NTSTATUS);
SYSCALL(NtSerializeBoot, NTSTATUS);
SYSCALL(NtQueryPortInformationProcess, NTSTATUS);
SYSCALL(NtFlushWriteBuffer, NTSTATUS);
SYSCALL(NtEnableLastKnownGood, NTSTATUS);
SYSCALL(NtDisableLastKnownGood, NTSTATUS);
SYSCALL(NtFlushProcessWriteBuffers, VOID);
SYSCALL(NtGetCurrentProcessorNumber, ULONG);
SYSCALL(NtGetEnvironmentVariableEx, MISSING);
SYSCALL(NtIsSystemResumeAutomatic, BOOLEAN);
SYSCALL(NtIsUILanguageComitted, NTSTATUS);
SYSCALL(NtQueryEnvironmentVariableInfoEx, MISSING);
SYSCALL(NtYieldExecution, NTSTATUS);
SYSCALL(NtAcquireProcessActivityReference, NTSTATUS);
SYSCALL(NtAddAtomEx, NTSTATUS);
SYSCALL(NtAlertThreadByThreadId, NTSTATUS);
SYSCALL(NtAllocateVirtualMemoryEx, NTSTATUS);
SYSCALL(NtAlpcConnectPortEx, NTSTATUS);
SYSCALL(NtAlpcImpersonateClientContainerOfPort, NTSTATUS);
SYSCALL(NtAssociateWaitCompletionPacket, NTSTATUS);
SYSCALL(NtCallEnclave, NTSTATUS);
SYSCALL(NtCancelTimer2, NTSTATUS);
SYSCALL(NtCancelWaitCompletionPacket, NTSTATUS);
SYSCALL(NtCommitRegistryTransaction, NTSTATUS);
SYSCALL(NtCompareObjects, NTSTATUS);
SYSCALL(NtCompareSigningLevels, NTSTATUS);
SYSCALL(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter, NTSTATUS);
SYSCALL(NtCreateDirectoryObjectEx, NTSTATUS);
SYSCALL(NtCreateEnclave, NTSTATUS);
SYSCALL(NtCreateIRTimer, NTSTATUS);
SYSCALL(NtCreateLowBoxToken, NTSTATUS);
SYSCALL(NtCreatePartition, NTSTATUS);
SYSCALL(NtCreateRegistryTransaction, NTSTATUS);
SYSCALL(NtCreateTimer2, NTSTATUS);
SYSCALL(NtCreateTokenEx, NTSTATUS);
SYSCALL(NtCreateWaitCompletionPacket, NTSTATUS);
SYSCALL(NtCreateWnfStateName, NTSTATUS);
SYSCALL(NtDeleteWnfStateData, NTSTATUS);
SYSCALL(NtDeleteWnfStateName, NTSTATUS);
SYSCALL(NtFilterBootOption, NTSTATUS);
SYSCALL(NtFlushBuffersFileEx, NTSTATUS);
SYSCALL(NtGetCachedSigningLevel, NTSTATUS);
SYSCALL(NtGetCompleteWnfStateSubscription, NTSTATUS);
SYSCALL(NtGetCurrentProcessorNumberEx, NTSTATUS);
SYSCALL(NtInitializeEnclave, NTSTATUS);
SYSCALL(NtLoadEnclaveData, NTSTATUS);
SYSCALL(NtLoadHotPatch, NTSTATUS);
SYSCALL(NtManagePartition, NTSTATUS);
SYSCALL(NtMapViewOfSectionEx, NTSTATUS);
SYSCALL(NtNotifyChangeDirectoryFileEx, NTSTATUS);
SYSCALL(NtOpenPartition, NTSTATUS);
SYSCALL(NtOpenRegistryTransaction, NTSTATUS);
SYSCALL(NtQueryAuxiliaryCounterFrequency, NTSTATUS);
SYSCALL(NtQueryDirectoryFileEx, NTSTATUS);
SYSCALL(NtQueryInformationByName, NTSTATUS);
SYSCALL(NtQuerySecurityPolicy, NTSTATUS);
SYSCALL(NtQueryWnfStateData, NTSTATUS);
SYSCALL(NtQueryWnfStateNameInformation, NTSTATUS);
SYSCALL(NtRevertContainerImpersonation, NTSTATUS);
SYSCALL(NtRollbackRegistryTransaction, NTSTATUS);
SYSCALL(NtSetCachedSigningLevel, NTSTATUS);
SYSCALL(NtSetCachedSigningLevel2, NTSTATUS);
SYSCALL(NtSetIRTimer, NTSTATUS);
SYSCALL(NtSetInformationSymbolicLink, NTSTATUS);
SYSCALL(NtSetInformationVirtualMemory, NTSTATUS);
SYSCALL(NtSetTimer2, NTSTATUS);
SYSCALL(NtSetWnfProcessNotificationEvent, NTSTATUS);
SYSCALL(NtSubscribeWnfStateChange, NTSTATUS);
SYSCALL(NtTerminateEnclave, NTSTATUS);
SYSCALL(NtUnsubscribeWnfStateChange, NTSTATUS);
SYSCALL(NtUpdateWnfStateData, NTSTATUS);
SYSCALL(NtWaitForAlertByThreadId, NTSTATUS);
SYSCALL(NtCreateSectionEx, NTSTATUS);
SYSCALL(NtManageHotPatch, NTSTATUS);
SYSCALL(BvgaSetVirtualFrameBuffer, NTSTATUS);
SYSCALL(CmpCleanUpHigherLayerKcbCachesPreCallback, NTSTATUS);
SYSCALL(GetPnpProperty, NTSTATUS);
SYSCALL(ArbPreprocessEntry, NTSTATUS);
SYSCALL(ArbAddReserved, NTSTATUS);

// WIN32K

SYSCALL(NtBindCompositionSurface, NTSTATUS);
SYSCALL(NtCloseCompositionInputSink, NTSTATUS);
SYSCALL(NtCompositionInputThread, NTSTATUS);
SYSCALL(NtCompositionSetDropTarget, NTSTATUS);
SYSCALL(NtConfigureInputSpace, NTSTATUS);
SYSCALL(NtCreateCompositionInputSink, NTSTATUS);
SYSCALL(NtCreateCompositionSurfaceHandle, NTSTATUS);
SYSCALL(NtCreateImplicitCompositionInputSink, NTSTATUS);
SYSCALL(NtDCompositionAddCrossDeviceVisualChild, NTSTATUS);
SYSCALL(NtDCompositionAddVisualChild, NTSTATUS);
SYSCALL(NtDCompositionAttachMouseWheelToHwnd, NTSTATUS);
SYSCALL(NtDCompositionBeginFrame, NTSTATUS);
SYSCALL(NtDCompositionCapturePointer, NTSTATUS);
SYSCALL(NtDCompositionCommitChannel, NTSTATUS);
SYSCALL(NtDCompositionCommitSynchronizationObject, NTSTATUS);
SYSCALL(NtDCompositionConfirmFrame, NTSTATUS);
SYSCALL(NtDCompositionConnectPipe, NTSTATUS);
SYSCALL(NtDCompositionCreateAndBindSharedSection, NTSTATUS);
SYSCALL(NtDCompositionCreateChannel, NTSTATUS);
SYSCALL(NtDCompositionCreateConnection, NTSTATUS);
SYSCALL(NtDCompositionCreateConnectionContext, NTSTATUS);
SYSCALL(NtDCompositionCreateDwmChannel, NTSTATUS);
SYSCALL(NtDCompositionCreateResource, NTSTATUS);
SYSCALL(NtDCompositionCreateSharedResourceHandle, NTSTATUS);
SYSCALL(NtDCompositionCreateSharedVisualHandle, NTSTATUS);
SYSCALL(NtDCompositionCreateSynchronizationObject, NTSTATUS);
SYSCALL(NtDCompositionCurrentBatchId, NTSTATUS);
SYSCALL(NtDCompositionDestroyChannel, NTSTATUS);
SYSCALL(NtDCompositionDestroyConnection, NTSTATUS);
SYSCALL(NtDCompositionDestroyConnectionContext, NTSTATUS);
SYSCALL(NtDCompositionDiscardFrame, NTSTATUS);
SYSCALL(NtDCompositionDuplicateHandleToProcess, NTSTATUS);
SYSCALL(NtDCompositionDuplicateSwapchainHandleToDwm, NTSTATUS);
SYSCALL(NtDCompositionDwmSyncFlush, NTSTATUS);
SYSCALL(NtDCompositionEnableDDASupport, NTSTATUS);
SYSCALL(NtDCompositionEnableMMCSS, NTSTATUS);
SYSCALL(NtDCompositionGetAnimationTime, NTSTATUS);
SYSCALL(NtDCompositionGetBatchId, NTSTATUS);
SYSCALL(NtDCompositionGetChannels, NTSTATUS);
SYSCALL(NtDCompositionGetConnectionBatch, NTSTATUS);
SYSCALL(NtDCompositionGetConnectionContextBatch, NTSTATUS);
SYSCALL(NtDCompositionGetDeletedResources, NTSTATUS);
SYSCALL(NtDCompositionGetFrameLegacyTokens, NTSTATUS);
SYSCALL(NtDCompositionGetFrameStatistics, NTSTATUS);
SYSCALL(NtDCompositionGetFrameSurfaceUpdates, NTSTATUS);
SYSCALL(NtDCompositionGetMaterialProperty, NTSTATUS);
SYSCALL(NtDCompositionOpenSharedResource, NTSTATUS);
SYSCALL(NtDCompositionOpenSharedResourceHandle, NTSTATUS);
SYSCALL(NtDCompositionProcessChannelBatchBuffer, NTSTATUS);
SYSCALL(NtDCompositionReferenceSharedResourceOnDwmChannel, NTSTATUS);
SYSCALL(NtDCompositionRegisterThumbnailVisual, NTSTATUS);
SYSCALL(NtDCompositionRegisterVirtualDesktopVisual, NTSTATUS);
SYSCALL(NtDCompositionReleaseAllResources, NTSTATUS);
SYSCALL(NtDCompositionReleaseResource, NTSTATUS);
SYSCALL(NtDCompositionRemoveCrossDeviceVisualChild, NTSTATUS);
SYSCALL(NtDCompositionRemoveVisualChild, NTSTATUS);
SYSCALL(NtDCompositionReplaceVisualChildren, NTSTATUS);
SYSCALL(NtDCompositionRetireFrame, NTSTATUS);
SYSCALL(NtDCompositionSetChannelCallbackId, NTSTATUS);
SYSCALL(NtDCompositionSetChannelCommitCompletionEvent, NTSTATUS);
SYSCALL(NtDCompositionSetChannelConnectionId, NTSTATUS);
SYSCALL(NtDCompositionSetChildRootVisual, NTSTATUS);
SYSCALL(NtDCompositionSetDebugCounter, NTSTATUS);
SYSCALL(NtDCompositionSetMaterialProperty, NTSTATUS);
SYSCALL(NtDCompositionSetResourceAnimationProperty, NTSTATUS);
SYSCALL(NtDCompositionSetResourceBufferProperty, NTSTATUS);
SYSCALL(NtDCompositionSetResourceCallbackId, NTSTATUS);
SYSCALL(NtDCompositionSetResourceDeletedNotificationTag, NTSTATUS);
SYSCALL(NtDCompositionSetResourceFloatProperty, NTSTATUS);
SYSCALL(NtDCompositionSetResourceHandleProperty, NTSTATUS);
SYSCALL(NtDCompositionSetResourceIntegerProperty, NTSTATUS);
SYSCALL(NtDCompositionSetResourceReferenceArrayProperty, NTSTATUS);
SYSCALL(NtDCompositionSetResourceReferenceProperty, NTSTATUS);
SYSCALL(NtDCompositionSetVisualInputSink, NTSTATUS);
SYSCALL(NtDCompositionSignalGpuFence, NTSTATUS);
SYSCALL(NtDCompositionSubmitDWMBatch, NTSTATUS);
SYSCALL(NtDCompositionSuspendAnimations, NTSTATUS);
SYSCALL(NtDCompositionSynchronize, NTSTATUS);
SYSCALL(NtDCompositionTelemetryAnimationScenarioBegin, NTSTATUS);
SYSCALL(NtDCompositionTelemetryAnimationScenarioReference, NTSTATUS);
SYSCALL(NtDCompositionTelemetryAnimationScenarioUnreference, NTSTATUS);
SYSCALL(NtDCompositionTelemetrySetApplicationId, NTSTATUS);
SYSCALL(NtDCompositionTelemetryTouchInteractionBegin, NTSTATUS);
SYSCALL(NtDCompositionTelemetryTouchInteractionEnd, NTSTATUS);
SYSCALL(NtDCompositionTelemetryTouchInteractionUpdate, NTSTATUS);
SYSCALL(NtDCompositionUpdatePointerCapture, NTSTATUS);
SYSCALL(NtDCompositionValidateAndReferenceSystemVisualForHwndTarget, NTSTATUS);
SYSCALL(NtDCompositionWaitForChannel, NTSTATUS);
SYSCALL(NtDWMBindCursorToOutputConfig, NTSTATUS);
SYSCALL(NtDWMCommitInputSystemOutputConfig, NTSTATUS);
SYSCALL(NtDWMSetCursorOrientation, NTSTATUS);
SYSCALL(NtDWMSetInputSystemOutputConfig, NTSTATUS);
SYSCALL(NtDesktopCaptureBits, NTSTATUS);
SYSCALL(NtDuplicateCompositionInputSink, NTSTATUS);
SYSCALL(NtDxgkCreateTrackedWorkload, NTSTATUS);
SYSCALL(NtDxgkDestroyTrackedWorkload, NTSTATUS);
SYSCALL(NtDxgkDispMgrOperation, NTSTATUS);
SYSCALL(NtDxgkEndTrackedWorkload, NTSTATUS);
SYSCALL(NtDxgkGetAvailableTrackedWorkloadIndex, NTSTATUS);
SYSCALL(NtDxgkGetProcessList, NTSTATUS);
SYSCALL(NtDxgkGetTrackedWorkloadStatistics, NTSTATUS);
SYSCALL(NtDxgkOutputDuplPresentToHwQueue, NTSTATUS);
SYSCALL(NtDxgkRegisterVailProcess, NTSTATUS);
SYSCALL(NtDxgkResetTrackedWorkload, NTSTATUS);
SYSCALL(NtDxgkSubmitPresentBltToHwQueue, NTSTATUS);
SYSCALL(NtDxgkSubmitPresentToHwQueue, NTSTATUS);
SYSCALL(NtDxgkUpdateTrackedWorkload, NTSTATUS);
SYSCALL(NtDxgkVailConnect, NTSTATUS);
SYSCALL(NtDxgkVailDisconnect, NTSTATUS);
SYSCALL(NtDxgkVailPromoteCompositionSurface, NTSTATUS);
SYSCALL(NtEnableOneCoreTransformMode, NTSTATUS);
SYSCALL(NtFlipObjectAddContent, NTSTATUS);
SYSCALL(NtFlipObjectAddPoolBuffer, NTSTATUS);
SYSCALL(NtFlipObjectConsumerAcquirePresent, NTSTATUS);
SYSCALL(NtFlipObjectConsumerAdjustUsageReference, NTSTATUS);
SYSCALL(NtFlipObjectConsumerBeginProcessPresent, NTSTATUS);
SYSCALL(NtFlipObjectConsumerEndProcessPresent, NTSTATUS);
SYSCALL(NtFlipObjectConsumerPostMessage, NTSTATUS);
SYSCALL(NtFlipObjectConsumerQueryBufferInfo, NTSTATUS);
SYSCALL(NtFlipObjectCreate, NTSTATUS);
SYSCALL(NtFlipObjectDisconnectEndpoint, NTSTATUS);
SYSCALL(NtFlipObjectOpen, NTSTATUS);
SYSCALL(NtFlipObjectPresentCancel, NTSTATUS);
SYSCALL(NtFlipObjectQueryBufferAvailableEvent, NTSTATUS);
SYSCALL(NtFlipObjectQueryEndpointConnected, NTSTATUS);
SYSCALL(NtFlipObjectQueryNextMessageToProducer, NTSTATUS);
SYSCALL(NtFlipObjectReadNextMessageToProducer, NTSTATUS);
SYSCALL(NtFlipObjectRemoveContent, NTSTATUS);
SYSCALL(NtFlipObjectRemovePoolBuffer, NTSTATUS);
SYSCALL(NtFlipObjectSetContent, NTSTATUS);
SYSCALL(NtGdiAbortDoc, NTSTATUS);
SYSCALL(NtGdiAbortPath, NTSTATUS);
SYSCALL(NtGdiAddEmbFontToDC, NTSTATUS);
SYSCALL(NtGdiAddFontMemResourceEx, NTSTATUS);
SYSCALL(NtGdiAddFontResourceW, NTSTATUS);
SYSCALL(NtGdiAddInitialFonts, NTSTATUS);
SYSCALL(NtGdiAddRemoteFontToDC, NTSTATUS);
SYSCALL(NtGdiAddRemoteMMInstanceToDC, NTSTATUS);
SYSCALL(NtGdiAlphaBlend, NTSTATUS);
SYSCALL(NtGdiAngleArc, NTSTATUS);
SYSCALL(NtGdiAnyLinkedFonts, NTSTATUS);
SYSCALL(NtGdiArcInternal, NTSTATUS);
SYSCALL(NtGdiBRUSHOBJ_DeleteRbrush, NTSTATUS);
SYSCALL(NtGdiBRUSHOBJ_hGetColorTransform, NTSTATUS);
SYSCALL(NtGdiBRUSHOBJ_pvAllocRbrush, NTSTATUS);
SYSCALL(NtGdiBRUSHOBJ_pvGetRbrush, NTSTATUS);
SYSCALL(NtGdiBRUSHOBJ_ulGetBrushColor, NTSTATUS);
SYSCALL(NtGdiBeginGdiRendering, NTSTATUS);
SYSCALL(NtGdiBeginPath, NTSTATUS);
SYSCALL(NtGdiCLIPOBJ_bEnum, NTSTATUS);
SYSCALL(NtGdiCLIPOBJ_cEnumStart, NTSTATUS);
SYSCALL(NtGdiCLIPOBJ_ppoGetPath, NTSTATUS);
SYSCALL(NtGdiCancelDC, NTSTATUS);
SYSCALL(NtGdiChangeGhostFont, NTSTATUS);
SYSCALL(NtGdiCheckBitmapBits, NTSTATUS);
SYSCALL(NtGdiClearBitmapAttributes, NTSTATUS);
SYSCALL(NtGdiClearBrushAttributes, NTSTATUS);
SYSCALL(NtGdiCloseFigure, NTSTATUS);
SYSCALL(NtGdiColorCorrectPalette, NTSTATUS);
SYSCALL(NtGdiCombineRgn, NTSTATUS);
SYSCALL(NtGdiCombineTransform, NTSTATUS);
SYSCALL(NtGdiComputeXformCoefficients, NTSTATUS);
SYSCALL(NtGdiConfigureOPMProtectedOutput, NTSTATUS);
SYSCALL(NtGdiConsoleTextOut, NTSTATUS);
SYSCALL(NtGdiConvertMetafileRect, NTSTATUS);
SYSCALL(NtGdiCreateBitmap, NTSTATUS);
SYSCALL(NtGdiCreateBitmapFromDxSurface, NTSTATUS);
SYSCALL(NtGdiCreateBitmapFromDxSurface2, NTSTATUS);
SYSCALL(NtGdiCreateClientObj, NTSTATUS);
SYSCALL(NtGdiCreateColorSpace, NTSTATUS);
SYSCALL(NtGdiCreateColorTransform, NTSTATUS);
SYSCALL(NtGdiCreateCompatibleBitmap, NTSTATUS);
SYSCALL(NtGdiCreateCompatibleDC, NTSTATUS);
SYSCALL(NtGdiCreateDIBBrush, NTSTATUS);
SYSCALL(NtGdiCreateDIBSection, NTSTATUS);
SYSCALL(NtGdiCreateDIBitmapInternal, NTSTATUS);
SYSCALL(NtGdiCreateEllipticRgn, NTSTATUS);
SYSCALL(NtGdiCreateHalftonePalette, NTSTATUS);
SYSCALL(NtGdiCreateHatchBrushInternal, NTSTATUS);
SYSCALL(NtGdiCreateMetafileDC, NTSTATUS);
SYSCALL(NtGdiCreateOPMProtectedOutput, NTSTATUS);
SYSCALL(NtGdiCreateOPMProtectedOutputs, NTSTATUS);
SYSCALL(NtGdiCreatePaletteInternal, NTSTATUS);
SYSCALL(NtGdiCreatePatternBrushInternal, NTSTATUS);
SYSCALL(NtGdiCreatePen, NTSTATUS);
SYSCALL(NtGdiCreateRectRgn, NTSTATUS);
SYSCALL(NtGdiCreateRoundRectRgn, NTSTATUS);
SYSCALL(NtGdiCreateServerMetaFile, NTSTATUS);
SYSCALL(NtGdiCreateSessionMappedDIBSection, NTSTATUS);
SYSCALL(NtGdiCreateSolidBrush, NTSTATUS);
SYSCALL(NtGdiD3dContextCreate, NTSTATUS);
SYSCALL(NtGdiD3dContextDestroy, NTSTATUS);
SYSCALL(NtGdiD3dContextDestroyAll, NTSTATUS);
SYSCALL(NtGdiD3dDrawPrimitives2, NTSTATUS);
SYSCALL(NtGdiD3dValidateTextureStageState, NTSTATUS);
SYSCALL(NtGdiDDCCIGetCapabilitiesString, NTSTATUS);
SYSCALL(NtGdiDDCCIGetCapabilitiesStringLength, NTSTATUS);
SYSCALL(NtGdiDDCCIGetTimingReport, NTSTATUS);
SYSCALL(NtGdiDDCCIGetVCPFeature, NTSTATUS);
SYSCALL(NtGdiDDCCISaveCurrentSettings, NTSTATUS);
SYSCALL(NtGdiDDCCISetVCPFeature, NTSTATUS);
SYSCALL(NtGdiDdAddAttachedSurface, NTSTATUS);
SYSCALL(NtGdiDdAlphaBlt, NTSTATUS);
SYSCALL(NtGdiDdAttachSurface, NTSTATUS);
SYSCALL(NtGdiDdBeginMoCompFrame, NTSTATUS);
SYSCALL(NtGdiDdBlt, NTSTATUS);
SYSCALL(NtGdiDdCanCreateD3DBuffer, NTSTATUS);
SYSCALL(NtGdiDdCanCreateSurface, NTSTATUS);
SYSCALL(NtGdiDdColorControl, NTSTATUS);
SYSCALL(NtGdiDdCreateD3DBuffer, NTSTATUS);
SYSCALL(NtGdiDdCreateDirectDrawObject, NTSTATUS);
SYSCALL(NtGdiDdCreateFullscreenSprite, NTSTATUS);
SYSCALL(NtGdiDdCreateMoComp, NTSTATUS);
SYSCALL(NtGdiDdCreateSurface, NTSTATUS);
SYSCALL(NtGdiDdCreateSurfaceEx, NTSTATUS);
SYSCALL(NtGdiDdCreateSurfaceObject, NTSTATUS);
SYSCALL(NtGdiDdDDIAbandonSwapChain, NTSTATUS);
SYSCALL(NtGdiDdDDIAcquireKeyedMutex, NTSTATUS);
SYSCALL(NtGdiDdDDIAcquireKeyedMutex2, NTSTATUS);
SYSCALL(NtGdiDdDDIAcquireSwapChain, NTSTATUS);
SYSCALL(NtGdiDdDDIAddSurfaceToSwapChain, NTSTATUS);
SYSCALL(NtGdiDdDDIAdjustFullscreenGamma, NTSTATUS);
SYSCALL(NtGdiDdDDICacheHybridQueryValue, NTSTATUS);
SYSCALL(NtGdiDdDDIChangeVideoMemoryReservation, NTSTATUS);
SYSCALL(NtGdiDdDDICheckExclusiveOwnership, NTSTATUS);
SYSCALL(NtGdiDdDDICheckMonitorPowerState, NTSTATUS);
SYSCALL(NtGdiDdDDICheckMultiPlaneOverlaySupport, NTSTATUS);
SYSCALL(NtGdiDdDDICheckMultiPlaneOverlaySupport2, NTSTATUS);
SYSCALL(NtGdiDdDDICheckMultiPlaneOverlaySupport3, NTSTATUS);
SYSCALL(NtGdiDdDDICheckOcclusion, NTSTATUS);
SYSCALL(NtGdiDdDDICheckSharedResourceAccess, NTSTATUS);
SYSCALL(NtGdiDdDDICheckVidPnExclusiveOwnership, NTSTATUS);
SYSCALL(NtGdiDdDDICloseAdapter, NTSTATUS);
SYSCALL(NtGdiDdDDIConfigureSharedResource, NTSTATUS);
SYSCALL(NtGdiDdDDICreateAllocation, NTSTATUS);
SYSCALL(NtGdiDdDDICreateBundleObject, NTSTATUS);
SYSCALL(NtGdiDdDDICreateContext, NTSTATUS);
SYSCALL(NtGdiDdDDICreateContextVirtual, NTSTATUS);
SYSCALL(NtGdiDdDDICreateDCFromMemory, NTSTATUS);
SYSCALL(NtGdiDdDDICreateDevice, NTSTATUS);
SYSCALL(NtGdiDdDDICreateHwContext, NTSTATUS);
SYSCALL(NtGdiDdDDICreateHwQueue, NTSTATUS);
SYSCALL(NtGdiDdDDICreateKeyedMutex, NTSTATUS);
SYSCALL(NtGdiDdDDICreateKeyedMutex2, NTSTATUS);
SYSCALL(NtGdiDdDDICreateOutputDupl, NTSTATUS);
SYSCALL(NtGdiDdDDICreateOverlay, NTSTATUS);
SYSCALL(NtGdiDdDDICreatePagingQueue, NTSTATUS);
SYSCALL(NtGdiDdDDICreateProtectedSession, NTSTATUS);
SYSCALL(NtGdiDdDDICreateSwapChain, NTSTATUS);
SYSCALL(NtGdiDdDDICreateSynchronizationObject, NTSTATUS);
SYSCALL(NtGdiDdDDIDDisplayEnum, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyAllocation, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyAllocation2, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyContext, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyDCFromMemory, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyDevice, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyHwContext, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyHwQueue, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyKeyedMutex, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyOutputDupl, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyOverlay, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyPagingQueue, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroyProtectedSession, NTSTATUS);
SYSCALL(NtGdiDdDDIDestroySynchronizationObject, NTSTATUS);
SYSCALL(NtGdiDdDDIDispMgrCreate, NTSTATUS);
SYSCALL(NtGdiDdDDIDispMgrSourceOperation, NTSTATUS);
SYSCALL(NtGdiDdDDIDispMgrTargetOperation, NTSTATUS);
SYSCALL(NtGdiDdDDIEnumAdapters, NTSTATUS);
SYSCALL(NtGdiDdDDIEnumAdapters2, NTSTATUS);
SYSCALL(NtGdiDdDDIEscape, NTSTATUS);
SYSCALL(NtGdiDdDDIEvict, NTSTATUS);
SYSCALL(NtGdiDdDDIExtractBundleObject, NTSTATUS);
SYSCALL(NtGdiDdDDIFlipOverlay, NTSTATUS);
SYSCALL(NtGdiDdDDIFlushHeapTransitions, NTSTATUS);
SYSCALL(NtGdiDdDDIFreeGpuVirtualAddress, NTSTATUS);
SYSCALL(NtGdiDdDDIGetAllocationPriority, NTSTATUS);
SYSCALL(NtGdiDdDDIGetCachedHybridQueryValue, NTSTATUS);
SYSCALL(NtGdiDdDDIGetContextInProcessSchedulingPriority, NTSTATUS);
SYSCALL(NtGdiDdDDIGetContextSchedulingPriority, NTSTATUS);
SYSCALL(NtGdiDdDDIGetDWMVerticalBlankEvent, NTSTATUS);
SYSCALL(NtGdiDdDDIGetDeviceState, NTSTATUS);
SYSCALL(NtGdiDdDDIGetDisplayModeList, NTSTATUS);
SYSCALL(NtGdiDdDDIGetMemoryBudgetTarget, NTSTATUS);
SYSCALL(NtGdiDdDDIGetMultiPlaneOverlayCaps, NTSTATUS);
SYSCALL(NtGdiDdDDIGetMultisampleMethodList, NTSTATUS);
SYSCALL(NtGdiDdDDIGetOverlayState, NTSTATUS);
SYSCALL(NtGdiDdDDIGetPostCompositionCaps, NTSTATUS);
SYSCALL(NtGdiDdDDIGetPresentHistory, NTSTATUS);
SYSCALL(NtGdiDdDDIGetPresentQueueEvent, NTSTATUS);
SYSCALL(NtGdiDdDDIGetProcessDeviceLostSupport, NTSTATUS);
SYSCALL(NtGdiDdDDIGetProcessDeviceRemovalSupport, NTSTATUS);
SYSCALL(NtGdiDdDDIGetProcessSchedulingPriorityBand, NTSTATUS);
SYSCALL(NtGdiDdDDIGetProcessSchedulingPriorityClass, NTSTATUS);
SYSCALL(NtGdiDdDDIGetResourcePresentPrivateDriverData, NTSTATUS);
SYSCALL(NtGdiDdDDIGetRuntimeData, NTSTATUS);
SYSCALL(NtGdiDdDDIGetScanLine, NTSTATUS);
SYSCALL(NtGdiDdDDIGetSetSwapChainMetadata, NTSTATUS);
SYSCALL(NtGdiDdDDIGetSharedPrimaryHandle, NTSTATUS);
SYSCALL(NtGdiDdDDIGetSharedResourceAdapterLuid, NTSTATUS);
SYSCALL(NtGdiDdDDIGetSharedResourceAdapterLuidFlipManager, NTSTATUS);
SYSCALL(NtGdiDdDDIGetYieldPercentage, NTSTATUS);
SYSCALL(NtGdiDdDDIInvalidateActiveVidPn, NTSTATUS);
SYSCALL(NtGdiDdDDIInvalidateCache, NTSTATUS);
SYSCALL(NtGdiDdDDILock, NTSTATUS);
SYSCALL(NtGdiDdDDILock2, NTSTATUS);
SYSCALL(NtGdiDdDDIMakeResident, NTSTATUS);
SYSCALL(NtGdiDdDDIMapGpuVirtualAddress, NTSTATUS);
SYSCALL(NtGdiDdDDIMarkDeviceAsError, NTSTATUS);
SYSCALL(NtGdiDdDDINetDispGetNextChunkInfo, NTSTATUS);
SYSCALL(NtGdiDdDDINetDispQueryMiracastDisplayDeviceStatus, NTSTATUS);
SYSCALL(NtGdiDdDDINetDispQueryMiracastDisplayDeviceSupport, NTSTATUS);
SYSCALL(NtGdiDdDDINetDispStartMiracastDisplayDevice, NTSTATUS);
SYSCALL(NtGdiDdDDINetDispStartMiracastDisplayDeviceEx, NTSTATUS);
SYSCALL(NtGdiDdDDINetDispStopMiracastDisplayDevice, NTSTATUS);
SYSCALL(NtGdiDdDDINetDispStopSessions, NTSTATUS);
SYSCALL(NtGdiDdDDIOfferAllocations, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenAdapterFromDeviceName, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenAdapterFromHdc, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenAdapterFromLuid, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenBundleObjectNtHandleFromName, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenKeyedMutex, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenKeyedMutex2, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenKeyedMutexFromNtHandle, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenNtHandleFromName, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenProtectedSessionFromNtHandle, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenResource, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenResourceFromNtHandle, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenSwapChain, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenSyncObjectFromNtHandle, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenSyncObjectFromNtHandle2, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenSyncObjectNtHandleFromName, NTSTATUS);
SYSCALL(NtGdiDdDDIOpenSynchronizationObject, NTSTATUS);
SYSCALL(NtGdiDdDDIOutputDuplGetFrameInfo, NTSTATUS);
SYSCALL(NtGdiDdDDIOutputDuplGetMetaData, NTSTATUS);
SYSCALL(NtGdiDdDDIOutputDuplGetPointerShapeData, NTSTATUS);
SYSCALL(NtGdiDdDDIOutputDuplPresent, NTSTATUS);
SYSCALL(NtGdiDdDDIOutputDuplReleaseFrame, NTSTATUS);
SYSCALL(NtGdiDdDDIPinDirectFlipResources, NTSTATUS);
SYSCALL(NtGdiDdDDIPollDisplayChildren, NTSTATUS);
SYSCALL(NtGdiDdDDIPresent, NTSTATUS);
SYSCALL(NtGdiDdDDIPresentMultiPlaneOverlay, NTSTATUS);
SYSCALL(NtGdiDdDDIPresentMultiPlaneOverlay2, NTSTATUS);
SYSCALL(NtGdiDdDDIPresentMultiPlaneOverlay3, NTSTATUS);
SYSCALL(NtGdiDdDDIPresentRedirected, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryAdapterInfo, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryAllocationResidency, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryClockCalibration, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryFSEBlock, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryProcessOfferInfo, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryProtectedSessionInfoFromNtHandle, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryProtectedSessionStatus, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryRemoteVidPnSourceFromGdiDisplayName, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryResourceInfo, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryResourceInfoFromNtHandle, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryStatistics, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryVidPnExclusiveOwnership, NTSTATUS);
SYSCALL(NtGdiDdDDIQueryVideoMemoryInfo, NTSTATUS);
SYSCALL(NtGdiDdDDIReclaimAllocations, NTSTATUS);
SYSCALL(NtGdiDdDDIReclaimAllocations2, NTSTATUS);
SYSCALL(NtGdiDdDDIReleaseKeyedMutex, NTSTATUS);
SYSCALL(NtGdiDdDDIReleaseKeyedMutex2, NTSTATUS);
SYSCALL(NtGdiDdDDIReleaseProcessVidPnSourceOwners, NTSTATUS);
SYSCALL(NtGdiDdDDIReleaseSwapChain, NTSTATUS);
SYSCALL(NtGdiDdDDIRemoveSurfaceFromSwapChain, NTSTATUS);
SYSCALL(NtGdiDdDDIRender, NTSTATUS);
SYSCALL(NtGdiDdDDIReserveGpuVirtualAddress, NTSTATUS);
SYSCALL(NtGdiDdDDISetAllocationPriority, NTSTATUS);
SYSCALL(NtGdiDdDDISetContextInProcessSchedulingPriority, NTSTATUS);
SYSCALL(NtGdiDdDDISetContextSchedulingPriority, NTSTATUS);
SYSCALL(NtGdiDdDDISetDeviceLostSupport, NTSTATUS);
SYSCALL(NtGdiDdDDISetDisplayMode, NTSTATUS);
SYSCALL(NtGdiDdDDISetDisplayPrivateDriverFormat, NTSTATUS);
SYSCALL(NtGdiDdDDISetDodIndirectSwapchain, NTSTATUS);
SYSCALL(NtGdiDdDDISetFSEBlock, NTSTATUS);
SYSCALL(NtGdiDdDDISetGammaRamp, NTSTATUS);
SYSCALL(NtGdiDdDDISetHwProtectionTeardownRecovery, NTSTATUS);
SYSCALL(NtGdiDdDDISetMemoryBudgetTarget, NTSTATUS);
SYSCALL(NtGdiDdDDISetMonitorColorSpaceTransform, NTSTATUS);
SYSCALL(NtGdiDdDDISetProcessDeviceRemovalSupport, NTSTATUS);
SYSCALL(NtGdiDdDDISetProcessSchedulingPriorityBand, NTSTATUS);
SYSCALL(NtGdiDdDDISetProcessSchedulingPriorityClass, NTSTATUS);
SYSCALL(NtGdiDdDDISetQueuedLimit, NTSTATUS);
SYSCALL(NtGdiDdDDISetStablePowerState, NTSTATUS);
SYSCALL(NtGdiDdDDISetStereoEnabled, NTSTATUS);
SYSCALL(NtGdiDdDDISetSyncRefreshCountWaitTarget, NTSTATUS);
SYSCALL(NtGdiDdDDISetVidPnSourceHwProtection, NTSTATUS);
SYSCALL(NtGdiDdDDISetVidPnSourceOwner, NTSTATUS);
SYSCALL(NtGdiDdDDISetVidPnSourceOwner1, NTSTATUS);
SYSCALL(NtGdiDdDDISetYieldPercentage, NTSTATUS);
SYSCALL(NtGdiDdDDIShareObjects, NTSTATUS);
SYSCALL(NtGdiDdDDISharedPrimaryLockNotification, NTSTATUS);
SYSCALL(NtGdiDdDDISharedPrimaryUnLockNotification, NTSTATUS);
SYSCALL(NtGdiDdDDISignalSynchronizationObject, NTSTATUS);
SYSCALL(NtGdiDdDDISignalSynchronizationObjectFromCpu, NTSTATUS);
SYSCALL(NtGdiDdDDISignalSynchronizationObjectFromGpu, NTSTATUS);
SYSCALL(NtGdiDdDDISignalSynchronizationObjectFromGpu2, NTSTATUS);
SYSCALL(NtGdiDdDDISubmitCommand, NTSTATUS);
SYSCALL(NtGdiDdDDISubmitCommandToHwQueue, NTSTATUS);
SYSCALL(NtGdiDdDDISubmitSignalSyncObjectsToHwQueue, NTSTATUS);
SYSCALL(NtGdiDdDDISubmitWaitForSyncObjectsToHwQueue, NTSTATUS);
SYSCALL(NtGdiDdDDITrimProcessCommitment, NTSTATUS);
SYSCALL(NtGdiDdDDIUnOrderedPresentSwapChain, NTSTATUS);
SYSCALL(NtGdiDdDDIUnlock, NTSTATUS);
SYSCALL(NtGdiDdDDIUnlock2, NTSTATUS);
SYSCALL(NtGdiDdDDIUnpinDirectFlipResources, NTSTATUS);
SYSCALL(NtGdiDdDDIUpdateAllocationProperty, NTSTATUS);
SYSCALL(NtGdiDdDDIUpdateGpuVirtualAddress, NTSTATUS);
SYSCALL(NtGdiDdDDIUpdateOverlay, NTSTATUS);
SYSCALL(NtGdiDdDDIWaitForIdle, NTSTATUS);
SYSCALL(NtGdiDdDDIWaitForSynchronizationObject, NTSTATUS);
SYSCALL(NtGdiDdDDIWaitForSynchronizationObjectFromCpu, NTSTATUS);
SYSCALL(NtGdiDdDDIWaitForSynchronizationObjectFromGpu, NTSTATUS);
SYSCALL(NtGdiDdDDIWaitForVerticalBlankEvent, NTSTATUS);
SYSCALL(NtGdiDdDDIWaitForVerticalBlankEvent2, NTSTATUS);
SYSCALL(NtGdiDdDeleteDirectDrawObject, NTSTATUS);
SYSCALL(NtGdiDdDeleteSurfaceObject, NTSTATUS);
SYSCALL(NtGdiDdDestroyD3DBuffer, NTSTATUS);
SYSCALL(NtGdiDdDestroyFullscreenSprite, NTSTATUS);
SYSCALL(NtGdiDdDestroyMoComp, NTSTATUS);
SYSCALL(NtGdiDdDestroySurface, NTSTATUS);
SYSCALL(NtGdiDdEndMoCompFrame, NTSTATUS);
SYSCALL(NtGdiDdFlip, NTSTATUS);
SYSCALL(NtGdiDdFlipToGDISurface, NTSTATUS);
SYSCALL(NtGdiDdGetAvailDriverMemory, NTSTATUS);
SYSCALL(NtGdiDdGetBltStatus, NTSTATUS);
SYSCALL(NtGdiDdGetDC, NTSTATUS);
SYSCALL(NtGdiDdGetDriverInfo, NTSTATUS);
SYSCALL(NtGdiDdGetDriverState, NTSTATUS);
SYSCALL(NtGdiDdGetDxHandle, NTSTATUS);
SYSCALL(NtGdiDdGetFlipStatus, NTSTATUS);
SYSCALL(NtGdiDdGetInternalMoCompInfo, NTSTATUS);
SYSCALL(NtGdiDdGetMoCompBuffInfo, NTSTATUS);
SYSCALL(NtGdiDdGetMoCompFormats, NTSTATUS);
SYSCALL(NtGdiDdGetMoCompGuids, NTSTATUS);
SYSCALL(NtGdiDdGetScanLine, NTSTATUS);
SYSCALL(NtGdiDdLock, NTSTATUS);
SYSCALL(NtGdiDdLockD3D, NTSTATUS);
SYSCALL(NtGdiDdNotifyFullscreenSpriteUpdate, NTSTATUS);
SYSCALL(NtGdiDdQueryDirectDrawObject, NTSTATUS);
SYSCALL(NtGdiDdQueryMoCompStatus, NTSTATUS);
SYSCALL(NtGdiDdQueryVisRgnUniqueness, NTSTATUS);
SYSCALL(NtGdiDdReenableDirectDrawObject, NTSTATUS);
SYSCALL(NtGdiDdReleaseDC, NTSTATUS);
SYSCALL(NtGdiDdRenderMoComp, NTSTATUS);
SYSCALL(NtGdiDdResetVisrgn, NTSTATUS);
SYSCALL(NtGdiDdSetColorKey, NTSTATUS);
SYSCALL(NtGdiDdSetExclusiveMode, NTSTATUS);
SYSCALL(NtGdiDdSetGammaRamp, NTSTATUS);
SYSCALL(NtGdiDdSetOverlayPosition, NTSTATUS);
SYSCALL(NtGdiDdUnattachSurface, NTSTATUS);
SYSCALL(NtGdiDdUnlock, NTSTATUS);
SYSCALL(NtGdiDdUnlockD3D, NTSTATUS);
SYSCALL(NtGdiDdUpdateOverlay, NTSTATUS);
SYSCALL(NtGdiDdWaitForVerticalBlank, NTSTATUS);
SYSCALL(NtGdiDeleteClientObj, NTSTATUS);
SYSCALL(NtGdiDeleteColorSpace, NTSTATUS);
SYSCALL(NtGdiDeleteColorTransform, NTSTATUS);
SYSCALL(NtGdiDeleteObjectApp, NTSTATUS);
SYSCALL(NtGdiDescribePixelFormat, NTSTATUS);
SYSCALL(NtGdiDestroyOPMProtectedOutput, NTSTATUS);
SYSCALL(NtGdiDestroyPhysicalMonitor, NTSTATUS);
SYSCALL(NtGdiDoBanding, NTSTATUS);
SYSCALL(NtGdiDoPalette, NTSTATUS);
SYSCALL(NtGdiDrawEscape, NTSTATUS);
SYSCALL(NtGdiDrawStream, NTSTATUS);
SYSCALL(NtGdiDvpAcquireNotification, NTSTATUS);
SYSCALL(NtGdiDvpCanCreateVideoPort, NTSTATUS);
SYSCALL(NtGdiDvpColorControl, NTSTATUS);
SYSCALL(NtGdiDvpCreateVideoPort, NTSTATUS);
SYSCALL(NtGdiDvpDestroyVideoPort, NTSTATUS);
SYSCALL(NtGdiDvpFlipVideoPort, NTSTATUS);
SYSCALL(NtGdiDvpGetVideoPortBandwidth, NTSTATUS);
SYSCALL(NtGdiDvpGetVideoPortConnectInfo, NTSTATUS);
SYSCALL(NtGdiDvpGetVideoPortField, NTSTATUS);
SYSCALL(NtGdiDvpGetVideoPortFlipStatus, NTSTATUS);
SYSCALL(NtGdiDvpGetVideoPortInputFormats, NTSTATUS);
SYSCALL(NtGdiDvpGetVideoPortLine, NTSTATUS);
SYSCALL(NtGdiDvpGetVideoPortOutputFormats, NTSTATUS);
SYSCALL(NtGdiDvpGetVideoSignalStatus, NTSTATUS);
SYSCALL(NtGdiDvpReleaseNotification, NTSTATUS);
SYSCALL(NtGdiDvpUpdateVideoPort, NTSTATUS);
SYSCALL(NtGdiDvpWaitForVideoPortSync, NTSTATUS);
SYSCALL(NtGdiDwmCreatedBitmapRemotingOutput, NTSTATUS);
SYSCALL(NtGdiDwmGetDirtyRgn, NTSTATUS);
SYSCALL(NtGdiDwmGetSurfaceData, NTSTATUS);
SYSCALL(NtGdiDxgGenericThunk, NTSTATUS);
SYSCALL(NtGdiEllipse, NTSTATUS);
SYSCALL(NtGdiEnableEudc, NTSTATUS);
SYSCALL(NtGdiEndDoc, NTSTATUS);
SYSCALL(NtGdiEndGdiRendering, NTSTATUS);
SYSCALL(NtGdiEndPage, NTSTATUS);
SYSCALL(NtGdiEndPath, NTSTATUS);
SYSCALL(NtGdiEngAlphaBlend, NTSTATUS);
SYSCALL(NtGdiEngAssociateSurface, NTSTATUS);
SYSCALL(NtGdiEngBitBlt, NTSTATUS);
SYSCALL(NtGdiEngCheckAbort, NTSTATUS);
SYSCALL(NtGdiEngComputeGlyphSet, NTSTATUS);
SYSCALL(NtGdiEngCopyBits, NTSTATUS);
SYSCALL(NtGdiEngCreateBitmap, NTSTATUS);
SYSCALL(NtGdiEngCreateClip, NTSTATUS);
SYSCALL(NtGdiEngCreateDeviceBitmap, NTSTATUS);
SYSCALL(NtGdiEngCreateDeviceSurface, NTSTATUS);
SYSCALL(NtGdiEngCreatePalette, NTSTATUS);
SYSCALL(NtGdiEngDeleteClip, NTSTATUS);
SYSCALL(NtGdiEngDeletePalette, NTSTATUS);
SYSCALL(NtGdiEngDeletePath, NTSTATUS);
SYSCALL(NtGdiEngDeleteSurface, NTSTATUS);
SYSCALL(NtGdiEngEraseSurface, NTSTATUS);
SYSCALL(NtGdiEngFillPath, NTSTATUS);
SYSCALL(NtGdiEngGradientFill, NTSTATUS);
SYSCALL(NtGdiEngLineTo, NTSTATUS);
SYSCALL(NtGdiEngLockSurface, NTSTATUS);
SYSCALL(NtGdiEngMarkBandingSurface, NTSTATUS);
SYSCALL(NtGdiEngPaint, NTSTATUS);
SYSCALL(NtGdiEngPlgBlt, NTSTATUS);
SYSCALL(NtGdiEngStretchBlt, NTSTATUS);
SYSCALL(NtGdiEngStretchBltROP, NTSTATUS);
SYSCALL(NtGdiEngStrokeAndFillPath, NTSTATUS);
SYSCALL(NtGdiEngStrokePath, NTSTATUS);
SYSCALL(NtGdiEngTextOut, NTSTATUS);
SYSCALL(NtGdiEngTransparentBlt, NTSTATUS);
SYSCALL(NtGdiEngUnlockSurface, NTSTATUS);
SYSCALL(NtGdiEnsureDpiDepDefaultGuiFontForPlateau, NTSTATUS);
SYSCALL(NtGdiEnumFontChunk, NTSTATUS);
SYSCALL(NtGdiEnumFontClose, NTSTATUS);
SYSCALL(NtGdiEnumFontOpen, NTSTATUS);
SYSCALL(NtGdiEnumFonts, NTSTATUS);
SYSCALL(NtGdiEnumObjects, NTSTATUS);
SYSCALL(NtGdiEqualRgn, NTSTATUS);
SYSCALL(NtGdiEudcLoadUnloadLink, NTSTATUS);
SYSCALL(NtGdiExcludeClipRect, NTSTATUS);
SYSCALL(NtGdiExtCreatePen, NTSTATUS);
SYSCALL(NtGdiExtCreateRegion, NTSTATUS);
SYSCALL(NtGdiExtEscape, NTSTATUS);
SYSCALL(NtGdiExtFloodFill, NTSTATUS);
SYSCALL(NtGdiExtGetObjectW, NTSTATUS);
SYSCALL(NtGdiExtSelectClipRgn, NTSTATUS);
SYSCALL(NtGdiExtTextOutW, NTSTATUS);
SYSCALL(NtGdiFONTOBJ_cGetAllGlyphHandles, NTSTATUS);
SYSCALL(NtGdiFONTOBJ_cGetGlyphs, NTSTATUS);
SYSCALL(NtGdiFONTOBJ_pQueryGlyphAttrs, NTSTATUS);
SYSCALL(NtGdiFONTOBJ_pfdg, NTSTATUS);
SYSCALL(NtGdiFONTOBJ_pifi, NTSTATUS);
SYSCALL(NtGdiFONTOBJ_pvTrueTypeFontFile, NTSTATUS);
SYSCALL(NtGdiFONTOBJ_pxoGetXform, NTSTATUS);
SYSCALL(NtGdiFONTOBJ_vGetInfo, NTSTATUS);
SYSCALL(NtGdiFillPath, NTSTATUS);
SYSCALL(NtGdiFillRgn, NTSTATUS);
SYSCALL(NtGdiFlattenPath, NTSTATUS);
SYSCALL(NtGdiFlush, NTSTATUS);
SYSCALL(NtGdiFontIsLinked, NTSTATUS);
SYSCALL(NtGdiForceUFIMapping, NTSTATUS);
SYSCALL(NtGdiFrameRgn, NTSTATUS);
SYSCALL(NtGdiFullscreenControl, NTSTATUS);
SYSCALL(NtGdiGetAndSetDCDword, NTSTATUS);
SYSCALL(NtGdiGetAppClipBox, NTSTATUS);
SYSCALL(NtGdiGetAppliedDeviceGammaRamp, NTSTATUS);
SYSCALL(NtGdiGetBitmapBits, NTSTATUS);
SYSCALL(NtGdiGetBitmapDimension, NTSTATUS);
SYSCALL(NtGdiGetBitmapDpiScaleValue, NTSTATUS);
SYSCALL(NtGdiGetBoundsRect, NTSTATUS);
SYSCALL(NtGdiGetCOPPCompatibleOPMInformation, NTSTATUS);
SYSCALL(NtGdiGetCertificate, NTSTATUS);
SYSCALL(NtGdiGetCertificateByHandle, NTSTATUS);
SYSCALL(NtGdiGetCertificateSize, NTSTATUS);
SYSCALL(NtGdiGetCertificateSizeByHandle, NTSTATUS);
SYSCALL(NtGdiGetCharABCWidthsW, NTSTATUS);
SYSCALL(NtGdiGetCharSet, NTSTATUS);
SYSCALL(NtGdiGetCharWidthInfo, NTSTATUS);
SYSCALL(NtGdiGetCharWidthW, NTSTATUS);
SYSCALL(NtGdiGetCharacterPlacementW, NTSTATUS);
SYSCALL(NtGdiGetColorAdjustment, NTSTATUS);
SYSCALL(NtGdiGetColorSpaceforBitmap, NTSTATUS);
SYSCALL(NtGdiGetCurrentDpiInfo, NTSTATUS);
SYSCALL(NtGdiGetDCDpiScaleValue, NTSTATUS);
SYSCALL(NtGdiGetDCDword, NTSTATUS);
SYSCALL(NtGdiGetDCObject, NTSTATUS);
SYSCALL(NtGdiGetDCPoint, NTSTATUS);
SYSCALL(NtGdiGetDCforBitmap, NTSTATUS);
SYSCALL(NtGdiGetDIBitsInternal, NTSTATUS);
SYSCALL(NtGdiGetDeviceCaps, NTSTATUS);
SYSCALL(NtGdiGetDeviceCapsAll, NTSTATUS);
SYSCALL(NtGdiGetDeviceGammaRamp, NTSTATUS);
SYSCALL(NtGdiGetDeviceWidth, NTSTATUS);
SYSCALL(NtGdiGetDhpdev, NTSTATUS);
SYSCALL(NtGdiGetETM, NTSTATUS);
SYSCALL(NtGdiGetEmbUFI, NTSTATUS);
SYSCALL(NtGdiGetEmbedFonts, NTSTATUS);
SYSCALL(NtGdiGetEntry, NTSTATUS);
SYSCALL(NtGdiGetEudcTimeStampEx, NTSTATUS);
SYSCALL(NtGdiGetFontData, NTSTATUS);
SYSCALL(NtGdiGetFontFileData, NTSTATUS);
SYSCALL(NtGdiGetFontFileInfo, NTSTATUS);
SYSCALL(NtGdiGetFontResourceInfoInternalW, NTSTATUS);
SYSCALL(NtGdiGetFontUnicodeRanges, NTSTATUS);
SYSCALL(NtGdiGetGammaRampCapability, NTSTATUS);
SYSCALL(NtGdiGetGlyphIndicesW, NTSTATUS);
SYSCALL(NtGdiGetGlyphIndicesWInternal, NTSTATUS);
SYSCALL(NtGdiGetGlyphOutline, NTSTATUS);
SYSCALL(NtGdiGetKerningPairs, NTSTATUS);
SYSCALL(NtGdiGetLinkedUFIs, NTSTATUS);
SYSCALL(NtGdiGetMiterLimit, NTSTATUS);
SYSCALL(NtGdiGetMonitorID, NTSTATUS);
SYSCALL(NtGdiGetNearestColor, NTSTATUS);
SYSCALL(NtGdiGetNearestPaletteIndex, NTSTATUS);
SYSCALL(NtGdiGetNumberOfPhysicalMonitors, NTSTATUS);
SYSCALL(NtGdiGetOPMInformation, NTSTATUS);
SYSCALL(NtGdiGetOPMRandomNumber, NTSTATUS);
SYSCALL(NtGdiGetObjectBitmapHandle, NTSTATUS);
SYSCALL(NtGdiGetOutlineTextMetricsInternalW, NTSTATUS);
SYSCALL(NtGdiGetPath, NTSTATUS);
SYSCALL(NtGdiGetPerBandInfo, NTSTATUS);
SYSCALL(NtGdiGetPhysicalMonitorDescription, NTSTATUS);
SYSCALL(NtGdiGetPhysicalMonitors, NTSTATUS);
SYSCALL(NtGdiGetPixel, NTSTATUS);
SYSCALL(NtGdiGetProcessSessionFonts, NTSTATUS);
SYSCALL(NtGdiGetPublicFontTableChangeCookie, NTSTATUS);
SYSCALL(NtGdiGetRandomRgn, NTSTATUS);
SYSCALL(NtGdiGetRasterizerCaps, NTSTATUS);
SYSCALL(NtGdiGetRealizationInfo, NTSTATUS);
SYSCALL(NtGdiGetRegionData, NTSTATUS);
SYSCALL(NtGdiGetRgnBox, NTSTATUS);
SYSCALL(NtGdiGetServerMetaFileBits, NTSTATUS);
SYSCALL(NtGdiGetSpoolMessage, NTSTATUS);
SYSCALL(NtGdiGetStats, NTSTATUS);
SYSCALL(NtGdiGetStockObject, NTSTATUS);
SYSCALL(NtGdiGetStringBitmapW, NTSTATUS);
SYSCALL(NtGdiGetSuggestedOPMProtectedOutputArraySize, NTSTATUS);
SYSCALL(NtGdiGetSystemPaletteUse, NTSTATUS);
SYSCALL(NtGdiGetTextCharsetInfo, NTSTATUS);
SYSCALL(NtGdiGetTextExtent, NTSTATUS);
SYSCALL(NtGdiGetTextExtentExW, NTSTATUS);
SYSCALL(NtGdiGetTextFaceW, NTSTATUS);
SYSCALL(NtGdiGetTextMetricsW, NTSTATUS);
SYSCALL(NtGdiGetTransform, NTSTATUS);
SYSCALL(NtGdiGetUFI, NTSTATUS);
SYSCALL(NtGdiGetUFIPathname, NTSTATUS);
SYSCALL(NtGdiGetWidthTable, NTSTATUS);
SYSCALL(NtGdiGradientFill, NTSTATUS);
SYSCALL(NtGdiHLSurfGetInformation, NTSTATUS);
SYSCALL(NtGdiHLSurfSetInformation, NTSTATUS);
SYSCALL(NtGdiHT_Get8BPPFormatPalette, NTSTATUS);
SYSCALL(NtGdiHT_Get8BPPMaskPalette, NTSTATUS);
SYSCALL(NtGdiHfontCreate, NTSTATUS);
SYSCALL(NtGdiIcmBrushInfo, NTSTATUS);
SYSCALL(NtGdiInit, NTSTATUS);
SYSCALL(NtGdiInitSpool, NTSTATUS);
SYSCALL(NtGdiIntersectClipRect, NTSTATUS);
SYSCALL(NtGdiInvertRgn, NTSTATUS);
SYSCALL(NtGdiLineTo, NTSTATUS);
SYSCALL(NtGdiMakeFontDir, NTSTATUS);
SYSCALL(NtGdiMakeInfoDC, NTSTATUS);
SYSCALL(NtGdiMakeObjectUnXferable, NTSTATUS);
SYSCALL(NtGdiMakeObjectXferable, NTSTATUS);
SYSCALL(NtGdiMaskBlt, NTSTATUS);
SYSCALL(NtGdiMirrorWindowOrg, NTSTATUS);
SYSCALL(NtGdiModifyWorldTransform, NTSTATUS);
SYSCALL(NtGdiMonoBitmap, NTSTATUS);
SYSCALL(NtGdiMoveTo, NTSTATUS);
SYSCALL(NtGdiOffsetClipRgn, NTSTATUS);
SYSCALL(NtGdiOffsetRgn, NTSTATUS);
SYSCALL(NtGdiOpenDCW, NTSTATUS);
SYSCALL(NtGdiPATHOBJ_bEnum, NTSTATUS);
SYSCALL(NtGdiPATHOBJ_bEnumClipLines, NTSTATUS);
SYSCALL(NtGdiPATHOBJ_vEnumStart, NTSTATUS);
SYSCALL(NtGdiPATHOBJ_vEnumStartClipLines, NTSTATUS);
SYSCALL(NtGdiPATHOBJ_vGetBounds, NTSTATUS);
SYSCALL(NtGdiPatBlt, NTSTATUS);
SYSCALL(NtGdiPathToRegion, NTSTATUS);
SYSCALL(NtGdiPlgBlt, NTSTATUS);
SYSCALL(NtGdiPolyDraw, NTSTATUS);
SYSCALL(NtGdiPolyPatBlt, NTSTATUS);
SYSCALL(NtGdiPolyPolyDraw, NTSTATUS);
SYSCALL(NtGdiPolyTextOutW, NTSTATUS);
SYSCALL(NtGdiPtInRegion, NTSTATUS);
SYSCALL(NtGdiPtVisible, NTSTATUS);
SYSCALL(NtGdiQueryFontAssocInfo, NTSTATUS);
SYSCALL(NtGdiQueryFonts, NTSTATUS);
SYSCALL(NtGdiRectInRegion, NTSTATUS);
SYSCALL(NtGdiRectVisible, NTSTATUS);
SYSCALL(NtGdiRectangle, NTSTATUS);
SYSCALL(NtGdiRemoveFontMemResourceEx, NTSTATUS);
SYSCALL(NtGdiRemoveFontResourceW, NTSTATUS);
SYSCALL(NtGdiRemoveMergeFont, NTSTATUS);
SYSCALL(NtGdiResetDC, NTSTATUS);
SYSCALL(NtGdiResizePalette, NTSTATUS);
SYSCALL(NtGdiRestoreDC, NTSTATUS);
SYSCALL(NtGdiRoundRect, NTSTATUS);
SYSCALL(NtGdiSTROBJ_bEnum, NTSTATUS);
SYSCALL(NtGdiSTROBJ_bEnumPositionsOnly, NTSTATUS);
SYSCALL(NtGdiSTROBJ_bGetAdvanceWidths, NTSTATUS);
SYSCALL(NtGdiSTROBJ_dwGetCodePage, NTSTATUS);
SYSCALL(NtGdiSTROBJ_vEnumStart, NTSTATUS);
SYSCALL(NtGdiSaveDC, NTSTATUS);
SYSCALL(NtGdiScaleRgn, NTSTATUS);
SYSCALL(NtGdiScaleValues, NTSTATUS);
SYSCALL(NtGdiScaleViewportExtEx, NTSTATUS);
SYSCALL(NtGdiScaleWindowExtEx, NTSTATUS);
SYSCALL(NtGdiSelectBitmap, NTSTATUS);
SYSCALL(NtGdiSelectBrush, NTSTATUS);
SYSCALL(NtGdiSelectClipPath, NTSTATUS);
SYSCALL(NtGdiSelectFont, NTSTATUS);
SYSCALL(NtGdiSelectPen, NTSTATUS);
SYSCALL(NtGdiSetBitmapAttributes, NTSTATUS);
SYSCALL(NtGdiSetBitmapBits, NTSTATUS);
SYSCALL(NtGdiSetBitmapDimension, NTSTATUS);
SYSCALL(NtGdiSetBoundsRect, NTSTATUS);
SYSCALL(NtGdiSetBrushAttributes, NTSTATUS);
SYSCALL(NtGdiSetBrushOrg, NTSTATUS);
SYSCALL(NtGdiSetColorAdjustment, NTSTATUS);
SYSCALL(NtGdiSetColorSpace, NTSTATUS);
SYSCALL(NtGdiSetDIBitsToDeviceInternal, NTSTATUS);
SYSCALL(NtGdiSetDeviceGammaRamp, NTSTATUS);
SYSCALL(NtGdiSetFontEnumeration, NTSTATUS);
SYSCALL(NtGdiSetFontXform, NTSTATUS);
SYSCALL(NtGdiSetIcmMode, NTSTATUS);
SYSCALL(NtGdiSetLayout, NTSTATUS);
SYSCALL(NtGdiSetLinkedUFIs, NTSTATUS);
SYSCALL(NtGdiSetMagicColors, NTSTATUS);
SYSCALL(NtGdiSetMetaRgn, NTSTATUS);
SYSCALL(NtGdiSetMiterLimit, NTSTATUS);
SYSCALL(NtGdiSetOPMSigningKeyAndSequenceNumbers, NTSTATUS);
SYSCALL(NtGdiSetPUMPDOBJ, NTSTATUS);
SYSCALL(NtGdiSetPixel, NTSTATUS);
SYSCALL(NtGdiSetPixelFormat, NTSTATUS);
SYSCALL(NtGdiSetPrivateDeviceGammaRamp, NTSTATUS);
SYSCALL(NtGdiSetRectRgn, NTSTATUS);
SYSCALL(NtGdiSetSizeDevice, NTSTATUS);
SYSCALL(NtGdiSetSystemPaletteUse, NTSTATUS);
SYSCALL(NtGdiSetTextJustification, NTSTATUS);
SYSCALL(NtGdiSetUMPDSandboxState, NTSTATUS);
SYSCALL(NtGdiSetVirtualResolution, NTSTATUS);
SYSCALL(NtGdiSetupPublicCFONT, NTSTATUS);
SYSCALL(NtGdiSfmGetNotificationTokens, NTSTATUS);
SYSCALL(NtGdiStartDoc, NTSTATUS);
SYSCALL(NtGdiStartPage, NTSTATUS);
SYSCALL(NtGdiStretchBlt, NTSTATUS);
SYSCALL(NtGdiStretchDIBitsInternal, NTSTATUS);
SYSCALL(NtGdiStrokeAndFillPath, NTSTATUS);
SYSCALL(NtGdiStrokePath, NTSTATUS);
SYSCALL(NtGdiSwapBuffers, NTSTATUS);
SYSCALL(NtGdiTransformPoints, NTSTATUS);
SYSCALL(NtGdiTransparentBlt, NTSTATUS);
SYSCALL(NtGdiUMPDEngFreeUserMem, NTSTATUS);
SYSCALL(NtGdiUnloadPrinterDriver, NTSTATUS);
SYSCALL(NtGdiUnmapMemFont, NTSTATUS);
SYSCALL(NtGdiUnrealizeObject, NTSTATUS);
SYSCALL(NtGdiUpdateColors, NTSTATUS);
SYSCALL(NtGdiUpdateTransform, NTSTATUS);
SYSCALL(NtGdiWidenPath, NTSTATUS);
SYSCALL(NtGdiXFORMOBJ_bApplyXform, NTSTATUS);
SYSCALL(NtGdiXFORMOBJ_iGetXform, NTSTATUS);
SYSCALL(NtGdiXLATEOBJ_cGetPalette, NTSTATUS);
SYSCALL(NtGdiXLATEOBJ_hGetColorTransform, NTSTATUS);
SYSCALL(NtGdiXLATEOBJ_iXlate, NTSTATUS);
SYSCALL(NtHWCursorUpdatePointer, NTSTATUS);
SYSCALL(NtIsOneCoreTransformMode, NTSTATUS);
SYSCALL(NtMITActivateInputProcessing, NTSTATUS);
SYSCALL(NtMITBindInputTypeToMonitors, NTSTATUS);
SYSCALL(NtMITCoreMsgKGetConnectionHandle, NTSTATUS);
SYSCALL(NtMITCoreMsgKOpenConnectionTo, NTSTATUS);
SYSCALL(NtMITCoreMsgKSend, NTSTATUS);
SYSCALL(NtMITDeactivateInputProcessing, NTSTATUS);
SYSCALL(NtMITDisableMouseIntercept, NTSTATUS);
SYSCALL(NtMITDispatchCompletion, NTSTATUS);
SYSCALL(NtMITEnableMouseIntercept, NTSTATUS);
SYSCALL(NtMITGetCursorUpdateHandle, NTSTATUS);
SYSCALL(NtMITSetInputCallbacks, NTSTATUS);
SYSCALL(NtMITSetInputDelegationMode, NTSTATUS);
SYSCALL(NtMITSetInputSuppressionState, NTSTATUS);
SYSCALL(NtMITSetKeyboardInputRoutingPolicy, NTSTATUS);
SYSCALL(NtMITSetKeyboardOverriderState, NTSTATUS);
SYSCALL(NtMITSetLastInputRecipient, NTSTATUS);
SYSCALL(NtMITSynthesizeKeyboardInput, NTSTATUS);
SYSCALL(NtMITSynthesizeMouseInput, NTSTATUS);
SYSCALL(NtMITSynthesizeMouseWheel, NTSTATUS);
SYSCALL(NtMITSynthesizeTouchInput, NTSTATUS);
SYSCALL(NtMITUpdateInputGlobals, NTSTATUS);
SYSCALL(NtMITWaitForMultipleObjectsEx, NTSTATUS);
SYSCALL(NtMapVisualRelativePoints, NTSTATUS);
SYSCALL(NtNotifyPresentToCompositionSurface, NTSTATUS);
SYSCALL(NtOpenCompositionSurfaceDirtyRegion, NTSTATUS);
SYSCALL(NtOpenCompositionSurfaceSectionInfo, NTSTATUS);
SYSCALL(NtOpenCompositionSurfaceSwapChainHandleInfo, NTSTATUS);
SYSCALL(NtQueryCompositionInputIsImplicit, NTSTATUS);
SYSCALL(NtQueryCompositionInputQueueAndTransform, NTSTATUS);
SYSCALL(NtQueryCompositionInputSink, NTSTATUS);
SYSCALL(NtQueryCompositionInputSinkLuid, NTSTATUS);
SYSCALL(NtQueryCompositionInputSinkViewId, NTSTATUS);
SYSCALL(NtQueryCompositionSurfaceBinding, NTSTATUS);
SYSCALL(NtQueryCompositionSurfaceHDRMetaData, NTSTATUS);
SYSCALL(NtQueryCompositionSurfaceRenderingRealization, NTSTATUS);
SYSCALL(NtQueryCompositionSurfaceStatistics, NTSTATUS);
SYSCALL(NtRIMAddInputObserver, NTSTATUS);
SYSCALL(NtRIMAreSiblingDevices, NTSTATUS);
SYSCALL(NtRIMDeviceIoControl, NTSTATUS);
SYSCALL(NtRIMEnableMonitorMappingForDevice, NTSTATUS);
SYSCALL(NtRIMFreeInputBuffer, NTSTATUS);
SYSCALL(NtRIMGetDevicePreparsedData, NTSTATUS);
SYSCALL(NtRIMGetDevicePreparsedDataLockfree, NTSTATUS);
SYSCALL(NtRIMGetDeviceProperties, NTSTATUS);
SYSCALL(NtRIMGetDevicePropertiesLockfree, NTSTATUS);
SYSCALL(NtRIMGetPhysicalDeviceRect, NTSTATUS);
SYSCALL(NtRIMGetSourceProcessId, NTSTATUS);
SYSCALL(NtRIMObserveNextInput, NTSTATUS);
SYSCALL(NtRIMOnPnpNotification, NTSTATUS);
SYSCALL(NtRIMOnTimerNotification, NTSTATUS);
SYSCALL(NtRIMReadInput, NTSTATUS);
SYSCALL(NtRIMRegisterForInput, NTSTATUS);
SYSCALL(NtRIMRemoveInputObserver, NTSTATUS);
SYSCALL(NtRIMSetExtendedDeviceProperty, NTSTATUS);
SYSCALL(NtRIMSetTestModeStatus, NTSTATUS);
SYSCALL(NtRIMUnregisterForInput, NTSTATUS);
SYSCALL(NtRIMUpdateInputObserverRegistration, NTSTATUS);
SYSCALL(NtSetCompositionSurfaceAnalogExclusive, NTSTATUS);
SYSCALL(NtSetCompositionSurfaceBufferCompositionMode, NTSTATUS);
SYSCALL(NtSetCompositionSurfaceBufferCompositionModeAndOrientation, NTSTATUS);
SYSCALL(NtSetCompositionSurfaceBufferUsage, NTSTATUS);
SYSCALL(NtSetCompositionSurfaceDirectFlipState, NTSTATUS);
SYSCALL(NtSetCompositionSurfaceHDRMetaData, NTSTATUS);
SYSCALL(NtSetCompositionSurfaceIndependentFlipInfo, NTSTATUS);
SYSCALL(NtSetCompositionSurfaceOutOfFrameDirectFlipNotification, NTSTATUS);
SYSCALL(NtSetCompositionSurfaceStatistics, NTSTATUS);
SYSCALL(NtSetCursorInputSpace, NTSTATUS);
SYSCALL(NtSetPointerDeviceInputSpace, NTSTATUS);
SYSCALL(NtSetShellCursorState, NTSTATUS);
SYSCALL(NtTokenManagerConfirmOutstandingAnalogToken, NTSTATUS);
SYSCALL(NtTokenManagerCreateCompositionTokenHandle, NTSTATUS);
SYSCALL(NtTokenManagerCreateFlipObjectReturnTokenHandle, NTSTATUS);
SYSCALL(NtTokenManagerCreateFlipObjectTokenHandle, NTSTATUS);
SYSCALL(NtTokenManagerDeleteOutstandingDirectFlipTokens, NTSTATUS);
SYSCALL(NtTokenManagerGetAnalogExclusiveSurfaceUpdates, NTSTATUS);
SYSCALL(NtTokenManagerGetAnalogExclusiveTokenEvent, NTSTATUS);
SYSCALL(NtTokenManagerGetOutOfFrameDirectFlipSurfaceUpdates, NTSTATUS);
SYSCALL(NtTokenManagerOpenEvent, NTSTATUS);
SYSCALL(NtTokenManagerOpenSection, NTSTATUS);
SYSCALL(NtTokenManagerOpenSectionAndEvents, NTSTATUS);
SYSCALL(NtTokenManagerThread, NTSTATUS);
SYSCALL(NtUnBindCompositionSurface, NTSTATUS);
SYSCALL(NtUpdateInputSinkTransforms, NTSTATUS);
SYSCALL(NtUserAcquireIAMKey, NTSTATUS);
SYSCALL(NtUserAcquireInteractiveControlBackgroundAccess, NTSTATUS);
SYSCALL(NtUserActivateKeyboardLayout, NTSTATUS);
SYSCALL(NtUserAddClipboardFormatListener, NTSTATUS);
SYSCALL(NtUserAddVisualIdentifier, NTSTATUS);
SYSCALL(NtUserAlterWindowStyle, NTSTATUS);
SYSCALL(NtUserAssociateInputContext, NTSTATUS);
SYSCALL(NtUserAttachThreadInput, NTSTATUS);
SYSCALL(NtUserAutoPromoteMouseInPointer, NTSTATUS);
SYSCALL(NtUserAutoRotateScreen, NTSTATUS);
SYSCALL(NtUserBeginLayoutUpdate, NTSTATUS);
SYSCALL(NtUserBeginPaint, NTSTATUS);
SYSCALL(NtUserBitBltSysBmp, NTSTATUS);
SYSCALL(NtUserBroadcastThemeChangeEvent, NTSTATUS);
SYSCALL(NtUserBuildHimcList, NTSTATUS);
SYSCALL(NtUserBuildHwndList, NTSTATUS);
SYSCALL(NtUserBuildNameList, NTSTATUS);
SYSCALL(NtUserBuildPropList, NTSTATUS);
SYSCALL(NtUserCalcMenuBar, NTSTATUS);
SYSCALL(NtUserCalculatePopupWindowPosition, NTSTATUS);
SYSCALL(NtUserCallHwnd, NTSTATUS);
SYSCALL(NtUserCallHwndLock, NTSTATUS);
SYSCALL(NtUserCallHwndLockSafe, NTSTATUS);
SYSCALL(NtUserCallHwndOpt, NTSTATUS);
SYSCALL(NtUserCallHwndParam, NTSTATUS);
SYSCALL(NtUserCallHwndParamLock, NTSTATUS);
SYSCALL(NtUserCallHwndParamLockSafe, NTSTATUS);
SYSCALL(NtUserCallHwndSafe, NTSTATUS);
SYSCALL(NtUserCallMsgFilter, NTSTATUS);
SYSCALL(NtUserCallNoParam, NTSTATUS);
SYSCALL(NtUserCallOneParam, NTSTATUS);
SYSCALL(NtUserCanBrokerForceForeground, NTSTATUS);
SYSCALL(NtUserChangeClipboardChain, NTSTATUS);
SYSCALL(NtUserChangeDisplaySettings, NTSTATUS);
SYSCALL(NtUserChangeWindowMessageFilterEx, NTSTATUS);
SYSCALL(NtUserCheckAccessForIntegrityLevel, NTSTATUS);
SYSCALL(NtUserCheckDesktopByThreadId, NTSTATUS);
SYSCALL(NtUserCheckImeHotKey, NTSTATUS);
SYSCALL(NtUserCheckMenuItem, NTSTATUS);
SYSCALL(NtUserCheckProcessForClipboardAccess, NTSTATUS);
SYSCALL(NtUserCheckProcessSession, NTSTATUS);
SYSCALL(NtUserCheckWindowThreadDesktop, NTSTATUS);
SYSCALL(NtUserChildWindowFromPointEx, NTSTATUS);
SYSCALL(NtUserClearForeground, NTSTATUS);
SYSCALL(NtUserClipCursor, NTSTATUS);
SYSCALL(NtUserCloseClipboard, NTSTATUS);
SYSCALL(NtUserCloseDesktop, NTSTATUS);
SYSCALL(NtUserCloseWindowStation, NTSTATUS);
SYSCALL(NtUserCompositionInputSinkLuidFromPoint, NTSTATUS);
SYSCALL(NtUserCompositionInputSinkViewInstanceIdFromPoint, NTSTATUS);
SYSCALL(NtUserConfigureActivationObject, NTSTATUS);
SYSCALL(NtUserConfirmResizeCommit, NTSTATUS);
SYSCALL(NtUserConsoleControl, NTSTATUS);
SYSCALL(NtUserConvertMemHandle, NTSTATUS);
SYSCALL(NtUserCopyAcceleratorTable, NTSTATUS);
SYSCALL(NtUserCountClipboardFormats, NTSTATUS);
SYSCALL(NtUserCreateAcceleratorTable, NTSTATUS);
SYSCALL(NtUserCreateActivationObject, NTSTATUS);
SYSCALL(NtUserCreateCaret, NTSTATUS);
SYSCALL(NtUserCreateDCompositionHwndTarget, NTSTATUS);
SYSCALL(NtUserCreateEmptyCursorObject, NTSTATUS);
SYSCALL(NtUserCreateInputContext, NTSTATUS);
SYSCALL(NtUserCreateLocalMemHandle, NTSTATUS);
SYSCALL(NtUserCreatePalmRejectionDelayZone, NTSTATUS);
SYSCALL(NtUserCreateWindowEx, NTSTATUS);
SYSCALL(NtUserCreateWindowGroup, NTSTATUS);
SYSCALL(NtUserCreateWindowStation, NTSTATUS);
SYSCALL(NtUserCtxDisplayIOCtl, NTSTATUS);
SYSCALL(NtUserDdeGetQualityOfService, NTSTATUS);
SYSCALL(NtUserDdeInitialize, NTSTATUS);
SYSCALL(NtUserDdeSetQualityOfService, NTSTATUS);
SYSCALL(NtUserDefSetText, NTSTATUS);
SYSCALL(NtUserDeferWindowDpiChanges, NTSTATUS);
SYSCALL(NtUserDeferWindowPos, NTSTATUS);
SYSCALL(NtUserDeferWindowPosAndBand, NTSTATUS);
SYSCALL(NtUserDelegateCapturePointers, NTSTATUS);
SYSCALL(NtUserDelegateInput, NTSTATUS);
SYSCALL(NtUserDeleteMenu, NTSTATUS);
SYSCALL(NtUserDeleteWindowGroup, NTSTATUS);
SYSCALL(NtUserDestroyAcceleratorTable, NTSTATUS);
SYSCALL(NtUserDestroyActivationObject, NTSTATUS);
SYSCALL(NtUserDestroyCursor, NTSTATUS);
SYSCALL(NtUserDestroyDCompositionHwndTarget, NTSTATUS);
SYSCALL(NtUserDestroyInputContext, NTSTATUS);
SYSCALL(NtUserDestroyMenu, NTSTATUS);
SYSCALL(NtUserDestroyPalmRejectionDelayZone, NTSTATUS);
SYSCALL(NtUserDestroyWindow, NTSTATUS);
SYSCALL(NtUserDisableImmersiveOwner, NTSTATUS);
SYSCALL(NtUserDisableProcessWindowFiltering, NTSTATUS);
SYSCALL(NtUserDisableThreadIme, NTSTATUS);
SYSCALL(NtUserDiscardPointerFrameMessages, NTSTATUS);
SYSCALL(NtUserDispatchMessage, NTSTATUS);
SYSCALL(NtUserDisplayConfigGetDeviceInfo, NTSTATUS);
SYSCALL(NtUserDisplayConfigSetDeviceInfo, NTSTATUS);
SYSCALL(NtUserDoSoundConnect, NTSTATUS);
SYSCALL(NtUserDoSoundDisconnect, NTSTATUS);
SYSCALL(NtUserDownlevelTouchpad, NTSTATUS);
SYSCALL(NtUserDragDetect, NTSTATUS);
SYSCALL(NtUserDragObject, NTSTATUS);
SYSCALL(NtUserDrawAnimatedRects, NTSTATUS);
SYSCALL(NtUserDrawCaption, NTSTATUS);
SYSCALL(NtUserDrawCaptionTemp, NTSTATUS);
SYSCALL(NtUserDrawIconEx, NTSTATUS);
SYSCALL(NtUserDrawMenuBarTemp, NTSTATUS);
SYSCALL(NtUserDwmGetDxRgn, NTSTATUS);
SYSCALL(NtUserDwmGetRemoteSessionOcclusionEvent, NTSTATUS);
SYSCALL(NtUserDwmGetRemoteSessionOcclusionState, NTSTATUS);
SYSCALL(NtUserDwmHintDxUpdate, NTSTATUS);
SYSCALL(NtUserDwmKernelShutdown, NTSTATUS);
SYSCALL(NtUserDwmKernelStartup, NTSTATUS);
SYSCALL(NtUserDwmStartRedirection, NTSTATUS);
SYSCALL(NtUserDwmStopRedirection, NTSTATUS);
SYSCALL(NtUserDwmValidateWindow, NTSTATUS);
SYSCALL(NtUserEmptyClipboard, NTSTATUS);
SYSCALL(NtUserEnableChildWindowDpiMessage, NTSTATUS);
SYSCALL(NtUserEnableIAMAccess, NTSTATUS);
SYSCALL(NtUserEnableMenuItem, NTSTATUS);
SYSCALL(NtUserEnableMouseInPointer, NTSTATUS);
SYSCALL(NtUserEnableMouseInputForCursorSuppression, NTSTATUS);
SYSCALL(NtUserEnableNonClientDpiScaling, NTSTATUS);
SYSCALL(NtUserEnableResizeLayoutSynchronization, NTSTATUS);
SYSCALL(NtUserEnableScrollBar, NTSTATUS);
SYSCALL(NtUserEnableSoftwareCursorForScreenCapture, NTSTATUS);
SYSCALL(NtUserEnableTouchPad, NTSTATUS);
SYSCALL(NtUserEnableWindowGDIScaledDpiMessage, NTSTATUS);
SYSCALL(NtUserEnableWindowGroupPolicy, NTSTATUS);
SYSCALL(NtUserEnableWindowResizeOptimization, NTSTATUS);
SYSCALL(NtUserEndDeferWindowPosEx, NTSTATUS);
SYSCALL(NtUserEndMenu, NTSTATUS);
SYSCALL(NtUserEndPaint, NTSTATUS);
SYSCALL(NtUserEndTouchOperation, NTSTATUS);
SYSCALL(NtUserEnumDisplayDevices, NTSTATUS);
SYSCALL(NtUserEnumDisplayMonitors, NTSTATUS);
SYSCALL(NtUserEnumDisplaySettings, NTSTATUS);
SYSCALL(NtUserEvent, NTSTATUS);
SYSCALL(NtUserExcludeUpdateRgn, NTSTATUS);
SYSCALL(NtUserFillWindow, NTSTATUS);
SYSCALL(NtUserFindExistingCursorIcon, NTSTATUS);
SYSCALL(NtUserFindWindowEx, NTSTATUS);
SYSCALL(NtUserFlashWindowEx, NTSTATUS);
SYSCALL(NtUserForceWindowToDpiForTest, NTSTATUS);
SYSCALL(NtUserFrostCrashedWindow, NTSTATUS);
SYSCALL(NtUserFunctionalizeDisplayConfig, NTSTATUS);
SYSCALL(NtUserGetActiveProcessesDpis, NTSTATUS);
SYSCALL(NtUserGetAltTabInfo, NTSTATUS);
SYSCALL(NtUserGetAncestor, NTSTATUS);
SYSCALL(NtUserGetAppImeLevel, NTSTATUS);
SYSCALL(NtUserGetAtomName, NTSTATUS);
SYSCALL(NtUserGetAutoRotationState, NTSTATUS);
SYSCALL(NtUserGetCIMSSM, NTSTATUS);
SYSCALL(NtUserGetCPD, NTSTATUS);
SYSCALL(NtUserGetCaretBlinkTime, NTSTATUS);
SYSCALL(NtUserGetCaretPos, NTSTATUS);
SYSCALL(NtUserGetClassInfoEx, NTSTATUS);
SYSCALL(NtUserGetClassName, NTSTATUS);
SYSCALL(NtUserGetClipCursor, NTSTATUS);
SYSCALL(NtUserGetClipboardAccessToken, NTSTATUS);
SYSCALL(NtUserGetClipboardData, NTSTATUS);
SYSCALL(NtUserGetClipboardFormatName, NTSTATUS);
SYSCALL(NtUserGetClipboardOwner, NTSTATUS);
SYSCALL(NtUserGetClipboardSequenceNumber, NTSTATUS);
SYSCALL(NtUserGetClipboardViewer, NTSTATUS);
SYSCALL(NtUserGetComboBoxInfo, NTSTATUS);
SYSCALL(NtUserGetControlBrush, NTSTATUS);
SYSCALL(NtUserGetControlColor, NTSTATUS);
SYSCALL(NtUserGetCurrentDpiInfoForWindow, NTSTATUS);
SYSCALL(NtUserGetCurrentInputMessageSource, NTSTATUS);
SYSCALL(NtUserGetCursor, NTSTATUS);
SYSCALL(NtUserGetCursorDims, NTSTATUS);
SYSCALL(NtUserGetCursorFrameInfo, NTSTATUS);
SYSCALL(NtUserGetCursorInfo, NTSTATUS);
SYSCALL(NtUserGetDCEx, NTSTATUS);
SYSCALL(NtUserGetDManipHookInitFunction, NTSTATUS);
SYSCALL(NtUserGetDesktopID, NTSTATUS);
SYSCALL(NtUserGetDisplayAutoRotationPreferences, NTSTATUS);
SYSCALL(NtUserGetDisplayAutoRotationPreferencesByProcessId, NTSTATUS);
SYSCALL(NtUserGetDisplayConfigBufferSizes, NTSTATUS);
SYSCALL(NtUserGetDoubleClickTime, NTSTATUS);
SYSCALL(NtUserGetDpiForCurrentProcess, NTSTATUS);
SYSCALL(NtUserGetDpiForMonitor, NTSTATUS);
SYSCALL(NtUserGetDpiSystemMetrics, NTSTATUS);
SYSCALL(NtUserGetExtendedPointerDeviceProperty, NTSTATUS);
SYSCALL(NtUserGetForegroundWindow, NTSTATUS);
SYSCALL(NtUserGetGUIThreadInfo, NTSTATUS);
SYSCALL(NtUserGetGestureConfig, NTSTATUS);
SYSCALL(NtUserGetGestureExtArgs, NTSTATUS);
SYSCALL(NtUserGetGestureInfo, NTSTATUS);
SYSCALL(NtUserGetGlobalIMEStatus, NTSTATUS);
SYSCALL(NtUserGetGuiResources, NTSTATUS);
SYSCALL(NtUserGetHDevName, NTSTATUS);
SYSCALL(NtUserGetHimetricScaleFactorFromPixelLocation, NTSTATUS);
SYSCALL(NtUserGetIconInfo, NTSTATUS);
SYSCALL(NtUserGetIconSize, NTSTATUS);
SYSCALL(NtUserGetImeHotKey, NTSTATUS);
SYSCALL(NtUserGetImeInfoEx, NTSTATUS);
SYSCALL(NtUserGetInputContainerId, NTSTATUS);
SYSCALL(NtUserGetInputLocaleInfo, NTSTATUS);
SYSCALL(NtUserGetInteractiveControlDeviceInfo, NTSTATUS);
SYSCALL(NtUserGetInteractiveControlInfo, NTSTATUS);
SYSCALL(NtUserGetInteractiveCtrlSupportedWaveforms, NTSTATUS);
SYSCALL(NtUserGetInternalWindowPos, NTSTATUS);
SYSCALL(NtUserGetKeyNameText, NTSTATUS);
SYSCALL(NtUserGetKeyboardLayout, NTSTATUS);
SYSCALL(NtUserGetKeyboardLayoutList, NTSTATUS);
SYSCALL(NtUserGetKeyboardLayoutName, NTSTATUS);
SYSCALL(NtUserGetKeyboardState, NTSTATUS);
SYSCALL(NtUserGetLayeredWindowAttributes, NTSTATUS);
SYSCALL(NtUserGetListBoxInfo, NTSTATUS);
SYSCALL(NtUserGetMenuBarInfo, NTSTATUS);
SYSCALL(NtUserGetMenuIndex, NTSTATUS);
SYSCALL(NtUserGetMenuItemRect, NTSTATUS);
SYSCALL(NtUserGetMessage, NTSTATUS);
SYSCALL(NtUserGetMonitorBrightness, NTSTATUS);
SYSCALL(NtUserGetMouseMovePointsEx, NTSTATUS);
SYSCALL(NtUserGetObjectInformation, NTSTATUS);
SYSCALL(NtUserGetOemBitmapSize, NTSTATUS);
SYSCALL(NtUserGetOpenClipboardWindow, NTSTATUS);
SYSCALL(NtUserGetOwnerTransformedMonitorRect, NTSTATUS);
SYSCALL(NtUserGetPhysicalDeviceRect, NTSTATUS);
SYSCALL(NtUserGetPointerCursorId, NTSTATUS);
SYSCALL(NtUserGetPointerDevice, NTSTATUS);
SYSCALL(NtUserGetPointerDeviceCursors, NTSTATUS);
SYSCALL(NtUserGetPointerDeviceOrientation, NTSTATUS);
SYSCALL(NtUserGetPointerDeviceProperties, NTSTATUS);
SYSCALL(NtUserGetPointerDeviceRects, NTSTATUS);
SYSCALL(NtUserGetPointerDevices, NTSTATUS);
SYSCALL(NtUserGetPointerFrameArrivalTimes, NTSTATUS);
SYSCALL(NtUserGetPointerFrameTimes, NTSTATUS);
SYSCALL(NtUserGetPointerInfoList, NTSTATUS);
SYSCALL(NtUserGetPointerInputTransform, NTSTATUS);
SYSCALL(NtUserGetPointerProprietaryId, NTSTATUS);
SYSCALL(NtUserGetPointerType, NTSTATUS);
SYSCALL(NtUserGetPrecisionTouchPadConfiguration, NTSTATUS);
SYSCALL(NtUserGetPriorityClipboardFormat, NTSTATUS);
SYSCALL(NtUserGetProcessDpiAwareness, NTSTATUS);
SYSCALL(NtUserGetProcessDpiAwarenessContext, NTSTATUS);
SYSCALL(NtUserGetProcessUIContextInformation, NTSTATUS);
SYSCALL(NtUserGetProcessWindowStation, NTSTATUS);
SYSCALL(NtUserGetProp, NTSTATUS);
SYSCALL(NtUserGetQueueEventStatus, NTSTATUS);
SYSCALL(NtUserGetQueueStatusReadonly, NTSTATUS);
SYSCALL(NtUserGetRawInputBuffer, NTSTATUS);
SYSCALL(NtUserGetRawInputData, NTSTATUS);
SYSCALL(NtUserGetRawInputDeviceInfo, NTSTATUS);
SYSCALL(NtUserGetRawInputDeviceList, NTSTATUS);
SYSCALL(NtUserGetRawPointerDeviceData, NTSTATUS);
SYSCALL(NtUserGetRegisteredRawInputDevices, NTSTATUS);
SYSCALL(NtUserGetRequiredCursorSizes, NTSTATUS);
SYSCALL(NtUserGetResizeDCompositionSynchronizationObject, NTSTATUS);
SYSCALL(NtUserGetScrollBarInfo, NTSTATUS);
SYSCALL(NtUserGetSystemDpiForProcess, NTSTATUS);
SYSCALL(NtUserGetSystemMenu, NTSTATUS);
SYSCALL(NtUserGetThreadDesktop, NTSTATUS);
SYSCALL(NtUserGetThreadState, NTSTATUS);
SYSCALL(NtUserGetTitleBarInfo, NTSTATUS);
SYSCALL(NtUserGetTopLevelWindow, NTSTATUS);
SYSCALL(NtUserGetTouchInputInfo, NTSTATUS);
SYSCALL(NtUserGetTouchValidationStatus, NTSTATUS);
SYSCALL(NtUserGetUniformSpaceMapping, NTSTATUS);
SYSCALL(NtUserGetUpdateRect, NTSTATUS);
SYSCALL(NtUserGetUpdateRgn, NTSTATUS);
SYSCALL(NtUserGetUpdatedClipboardFormats, NTSTATUS);
SYSCALL(NtUserGetWOWClass, NTSTATUS);
SYSCALL(NtUserGetWindowBand, NTSTATUS);
SYSCALL(NtUserGetWindowCompositionAttribute, NTSTATUS);
SYSCALL(NtUserGetWindowCompositionInfo, NTSTATUS);
SYSCALL(NtUserGetWindowDC, NTSTATUS);
SYSCALL(NtUserGetWindowDisplayAffinity, NTSTATUS);
SYSCALL(NtUserGetWindowFeedbackSetting, NTSTATUS);
SYSCALL(NtUserGetWindowGroupId, NTSTATUS);
SYSCALL(NtUserGetWindowMinimizeRect, NTSTATUS);
SYSCALL(NtUserGetWindowPlacement, NTSTATUS);
SYSCALL(NtUserGetWindowProcessHandle, NTSTATUS);
SYSCALL(NtUserGetWindowRgnEx, NTSTATUS);
SYSCALL(NtUserGhostWindowFromHungWindow, NTSTATUS);
SYSCALL(NtUserHandleDelegatedInput, NTSTATUS);
SYSCALL(NtUserHardErrorControl, NTSTATUS);
SYSCALL(NtUserHideCaret, NTSTATUS);
SYSCALL(NtUserHidePointerContactVisualization, NTSTATUS);
SYSCALL(NtUserHiliteMenuItem, NTSTATUS);
SYSCALL(NtUserHungWindowFromGhostWindow, NTSTATUS);
SYSCALL(NtUserHwndQueryRedirectionInfo, NTSTATUS);
SYSCALL(NtUserHwndSetRedirectionInfo, NTSTATUS);
SYSCALL(NtUserImpersonateDdeClientWindow, NTSTATUS);
SYSCALL(NtUserInheritWindowMonitor, NTSTATUS);
SYSCALL(NtUserInitTask, NTSTATUS);
SYSCALL(NtUserInitialize, NTSTATUS);
SYSCALL(NtUserInitializeClientPfnArrays, NTSTATUS);
SYSCALL(NtUserInitializeGenericHidInjection, NTSTATUS);
SYSCALL(NtUserInitializeInputDeviceInjection, NTSTATUS);
SYSCALL(NtUserInitializePointerDeviceInjection, NTSTATUS);
SYSCALL(NtUserInitializePointerDeviceInjectionEx, NTSTATUS);
SYSCALL(NtUserInitializeTouchInjection, NTSTATUS);
SYSCALL(NtUserInjectDeviceInput, NTSTATUS);
SYSCALL(NtUserInjectGenericHidInput, NTSTATUS);
SYSCALL(NtUserInjectGesture, NTSTATUS);
SYSCALL(NtUserInjectKeyboardInput, NTSTATUS);
SYSCALL(NtUserInjectMouseInput, NTSTATUS);
SYSCALL(NtUserInjectPointerInput, NTSTATUS);
SYSCALL(NtUserInjectTouchInput, NTSTATUS);
SYSCALL(NtUserInteractiveControlQueryUsage, NTSTATUS);
SYSCALL(NtUserInternalClipCursor, NTSTATUS);
SYSCALL(NtUserInternalGetWindowIcon, NTSTATUS);
SYSCALL(NtUserInternalGetWindowText, NTSTATUS);
SYSCALL(NtUserInvalidateRect, NTSTATUS);
SYSCALL(NtUserInvalidateRgn, NTSTATUS);
SYSCALL(NtUserIsChildWindowDpiMessageEnabled, NTSTATUS);
SYSCALL(NtUserIsClipboardFormatAvailable, NTSTATUS);
SYSCALL(NtUserIsMouseInPointerEnabled, NTSTATUS);
SYSCALL(NtUserIsMouseInputEnabled, NTSTATUS);
SYSCALL(NtUserIsNonClientDpiScalingEnabled, NTSTATUS);
SYSCALL(NtUserIsResizeLayoutSynchronizationEnabled, NTSTATUS);
SYSCALL(NtUserIsTopLevelWindow, NTSTATUS);
SYSCALL(NtUserIsTouchWindow, NTSTATUS);
SYSCALL(NtUserIsWindowBroadcastingDpiToChildren, NTSTATUS);
SYSCALL(NtUserIsWindowGDIScaledDpiMessageEnabled, NTSTATUS);
SYSCALL(NtUserKillTimer, NTSTATUS);
SYSCALL(NtUserLayoutCompleted, NTSTATUS);
SYSCALL(NtUserLinkDpiCursor, NTSTATUS);
SYSCALL(NtUserLockCursor, NTSTATUS);
SYSCALL(NtUserLockWindowStation, NTSTATUS);
SYSCALL(NtUserLockWindowUpdate, NTSTATUS);
SYSCALL(NtUserLockWorkStation, NTSTATUS);
SYSCALL(NtUserLogicalToPerMonitorDPIPhysicalPoint, NTSTATUS);
SYSCALL(NtUserLogicalToPhysicalDpiPointForWindow, NTSTATUS);
SYSCALL(NtUserLogicalToPhysicalPoint, NTSTATUS);
SYSCALL(NtUserMNDragLeave, NTSTATUS);
SYSCALL(NtUserMNDragOver, NTSTATUS);
SYSCALL(NtUserMagControl, NTSTATUS);
SYSCALL(NtUserMagGetContextInformation, NTSTATUS);
SYSCALL(NtUserMagSetContextInformation, NTSTATUS);
SYSCALL(NtUserManageGestureHandlerWindow, NTSTATUS);
SYSCALL(NtUserMapPointsByVisualIdentifier, NTSTATUS);
SYSCALL(NtUserMapVirtualKeyEx, NTSTATUS);
SYSCALL(NtUserMenuItemFromPoint, NTSTATUS);
SYSCALL(NtUserMinMaximize, NTSTATUS);
SYSCALL(NtUserModifyUserStartupInfoFlags, NTSTATUS);
SYSCALL(NtUserModifyWindowTouchCapability, NTSTATUS);
SYSCALL(NtUserMoveWindow, NTSTATUS);
SYSCALL(NtUserMsgWaitForMultipleObjectsEx, NTSTATUS);
SYSCALL(NtUserNavigateFocus, NTSTATUS);
SYSCALL(NtUserNotifyIMEStatus, NTSTATUS);
SYSCALL(NtUserNotifyProcessCreate, NTSTATUS);
SYSCALL(NtUserNotifyWinEvent, NTSTATUS);
SYSCALL(NtUserOpenClipboard, NTSTATUS);
SYSCALL(NtUserOpenDesktop, NTSTATUS);
SYSCALL(NtUserOpenInputDesktop, NTSTATUS);
SYSCALL(NtUserOpenThreadDesktop, NTSTATUS);
SYSCALL(NtUserOpenWindowStation, NTSTATUS);
SYSCALL(NtUserPaintDesktop, NTSTATUS);
SYSCALL(NtUserPaintMenuBar, NTSTATUS);
SYSCALL(NtUserPaintMonitor, NTSTATUS);
SYSCALL(NtUserPeekMessage, NTSTATUS);
SYSCALL(NtUserPerMonitorDPIPhysicalToLogicalPoint, NTSTATUS);
SYSCALL(NtUserPhysicalToLogicalDpiPointForWindow, NTSTATUS);
SYSCALL(NtUserPhysicalToLogicalPoint, NTSTATUS);
SYSCALL(NtUserPostMessage, NTSTATUS);
SYSCALL(NtUserPostThreadMessage, NTSTATUS);
SYSCALL(NtUserPrintWindow, NTSTATUS);
SYSCALL(NtUserProcessConnect, NTSTATUS);
SYSCALL(NtUserProcessInkFeedbackCommand, NTSTATUS);
SYSCALL(NtUserPromoteMouseInPointer, NTSTATUS);
SYSCALL(NtUserPromotePointer, NTSTATUS);
SYSCALL(NtUserQueryActivationObject, NTSTATUS);
SYSCALL(NtUserQueryBSDRWindow, NTSTATUS);
SYSCALL(NtUserQueryDisplayConfig, NTSTATUS);
SYSCALL(NtUserQueryInformationThread, NTSTATUS);
SYSCALL(NtUserQueryInputContext, NTSTATUS);
SYSCALL(NtUserQuerySendMessage, NTSTATUS);
SYSCALL(NtUserQueryWindow, NTSTATUS);
SYSCALL(NtUserRealChildWindowFromPoint, NTSTATUS);
SYSCALL(NtUserRealInternalGetMessage, NTSTATUS);
SYSCALL(NtUserRealWaitMessageEx, NTSTATUS);
SYSCALL(NtUserRedrawWindow, NTSTATUS);
SYSCALL(NtUserRegisterBSDRWindow, NTSTATUS);
SYSCALL(NtUserRegisterClassExWOW, NTSTATUS);
SYSCALL(NtUserRegisterDManipHook, NTSTATUS);
SYSCALL(NtUserRegisterEdgy, NTSTATUS);
SYSCALL(NtUserRegisterErrorReportingDialog, NTSTATUS);
SYSCALL(NtUserRegisterHotKey, NTSTATUS);
SYSCALL(NtUserRegisterManipulationThread, NTSTATUS);
SYSCALL(NtUserRegisterPointerDeviceNotifications, NTSTATUS);
SYSCALL(NtUserRegisterPointerInputTarget, NTSTATUS);
SYSCALL(NtUserRegisterRawInputDevices, NTSTATUS);
SYSCALL(NtUserRegisterServicesProcess, NTSTATUS);
SYSCALL(NtUserRegisterSessionPort, NTSTATUS);
SYSCALL(NtUserRegisterShellPTPListener, NTSTATUS);
SYSCALL(NtUserRegisterTasklist, NTSTATUS);
SYSCALL(NtUserRegisterTouchHitTestingWindow, NTSTATUS);
SYSCALL(NtUserRegisterTouchPadCapable, NTSTATUS);
SYSCALL(NtUserRegisterUserApiHook, NTSTATUS);
SYSCALL(NtUserRegisterWindowMessage, NTSTATUS);
SYSCALL(NtUserReleaseDC, NTSTATUS);
SYSCALL(NtUserReleaseDwmHitTestWaiters, NTSTATUS);
SYSCALL(NtUserRemoteConnect, NTSTATUS);
SYSCALL(NtUserRemoteRedrawRectangle, NTSTATUS);
SYSCALL(NtUserRemoteRedrawScreen, NTSTATUS);
SYSCALL(NtUserRemoteStopScreenUpdates, NTSTATUS);
SYSCALL(NtUserRemoveClipboardFormatListener, NTSTATUS);
SYSCALL(NtUserRemoveInjectionDevice, NTSTATUS);
SYSCALL(NtUserRemoveMenu, NTSTATUS);
SYSCALL(NtUserRemoveProp, NTSTATUS);
SYSCALL(NtUserRemoveVisualIdentifier, NTSTATUS);
SYSCALL(NtUserReportInertia, NTSTATUS);
SYSCALL(NtUserRequestMoveSizeOperation, NTSTATUS);
SYSCALL(NtUserResolveDesktop, NTSTATUS);
SYSCALL(NtUserResolveDesktopForWOW, NTSTATUS);
SYSCALL(NtUserRestoreWindowDpiChanges, NTSTATUS);
SYSCALL(NtUserSBGetParms, NTSTATUS);
SYSCALL(NtUserScrollDC, NTSTATUS);
SYSCALL(NtUserScrollWindowEx, NTSTATUS);
SYSCALL(NtUserSelectPalette, NTSTATUS);
SYSCALL(NtUserSendEventMessage, NTSTATUS);
SYSCALL(NtUserSendInput, NTSTATUS);
SYSCALL(NtUserSendInteractiveControlHapticsReport, NTSTATUS);
SYSCALL(NtUserSendTouchInput, NTSTATUS);
SYSCALL(NtUserSetActivationFilter, NTSTATUS);
SYSCALL(NtUserSetActiveProcess, NTSTATUS);
SYSCALL(NtUserSetActiveProcessForMonitor, NTSTATUS);
SYSCALL(NtUserSetActiveWindow, NTSTATUS);
SYSCALL(NtUserSetAppImeLevel, NTSTATUS);
SYSCALL(NtUserSetAutoRotation, NTSTATUS);
SYSCALL(NtUserSetBridgeWindowChild, NTSTATUS);
SYSCALL(NtUserSetBrokeredForeground, NTSTATUS);
SYSCALL(NtUserSetCalibrationData, NTSTATUS);
SYSCALL(NtUserSetCapture, NTSTATUS);
SYSCALL(NtUserSetChildWindowNoActivate, NTSTATUS);
SYSCALL(NtUserSetClassLong, NTSTATUS);
SYSCALL(NtUserSetClassLongPtr, NTSTATUS);
SYSCALL(NtUserSetClassWord, NTSTATUS);
SYSCALL(NtUserSetClipboardData, NTSTATUS);
SYSCALL(NtUserSetClipboardViewer, NTSTATUS);
SYSCALL(NtUserSetConsoleReserveKeys, NTSTATUS);
SYSCALL(NtUserSetCoreWindow, NTSTATUS);
SYSCALL(NtUserSetCoreWindowPartner, NTSTATUS);
SYSCALL(NtUserSetCursor, NTSTATUS);
SYSCALL(NtUserSetCursorContents, NTSTATUS);
SYSCALL(NtUserSetCursorIconData, NTSTATUS);
SYSCALL(NtUserSetCursorPos, NTSTATUS);
SYSCALL(NtUserSetDesktopColorTransform, NTSTATUS);
SYSCALL(NtUserSetDialogControlDpiChangeBehavior, NTSTATUS);
SYSCALL(NtUserSetDimUndimTransitionTime, NTSTATUS);
SYSCALL(NtUserSetDisplayAutoRotationPreferences, NTSTATUS);
SYSCALL(NtUserSetDisplayConfig, NTSTATUS);
SYSCALL(NtUserSetDisplayMapping, NTSTATUS);
SYSCALL(NtUserSetFallbackForeground, NTSTATUS);
SYSCALL(NtUserSetFeatureReportResponse, NTSTATUS);
SYSCALL(NtUserSetFocus, NTSTATUS);
SYSCALL(NtUserSetForegroundWindowForApplication, NTSTATUS);
SYSCALL(NtUserSetGestureConfig, NTSTATUS);
SYSCALL(NtUserSetImeHotKey, NTSTATUS);
SYSCALL(NtUserSetImeInfoEx, NTSTATUS);
SYSCALL(NtUserSetImeOwnerWindow, NTSTATUS);
SYSCALL(NtUserSetImmersiveBackgroundWindow, NTSTATUS);
SYSCALL(NtUserSetInformationProcess, NTSTATUS);
SYSCALL(NtUserSetInformationThread, NTSTATUS);
SYSCALL(NtUserSetInteractiveControlFocus, NTSTATUS);
SYSCALL(NtUserSetInteractiveCtrlRotationAngle, NTSTATUS);
SYSCALL(NtUserSetInternalWindowPos, NTSTATUS);
SYSCALL(NtUserSetKeyboardState, NTSTATUS);
SYSCALL(NtUserSetLayeredWindowAttributes, NTSTATUS);
SYSCALL(NtUserSetLogonNotifyWindow, NTSTATUS);
SYSCALL(NtUserSetMagnificationDesktopMagnifierOffsetsDWMUpdated, NTSTATUS);
SYSCALL(NtUserSetManipulationInputTarget, NTSTATUS);
SYSCALL(NtUserSetMenu, NTSTATUS);
SYSCALL(NtUserSetMenuContextHelpId, NTSTATUS);
SYSCALL(NtUserSetMenuDefaultItem, NTSTATUS);
SYSCALL(NtUserSetMenuFlagRtoL, NTSTATUS);
SYSCALL(NtUserSetMirrorRendering, NTSTATUS);
SYSCALL(NtUserSetMonitorBrightness, NTSTATUS);
SYSCALL(NtUserSetObjectInformation, NTSTATUS);
SYSCALL(NtUserSetParent, NTSTATUS);
SYSCALL(NtUserSetPrecisionTouchPadConfiguration, NTSTATUS);
SYSCALL(NtUserSetProcessDPIAware, NTSTATUS);
SYSCALL(NtUserSetProcessDpiAwareness, NTSTATUS);
SYSCALL(NtUserSetProcessDpiAwarenessContext, NTSTATUS);
SYSCALL(NtUserSetProcessInteractionFlags, NTSTATUS);
SYSCALL(NtUserSetProcessMousewheelRoutingMode, NTSTATUS);
SYSCALL(NtUserSetProcessRestrictionExemption, NTSTATUS);
SYSCALL(NtUserSetProcessUIAccessZorder, NTSTATUS);
SYSCALL(NtUserSetProcessWindowStation, NTSTATUS);
SYSCALL(NtUserSetProp, NTSTATUS);
SYSCALL(NtUserSetScrollInfo, NTSTATUS);
SYSCALL(NtUserSetSensorPresence, NTSTATUS);
SYSCALL(NtUserSetShellWindowEx, NTSTATUS);
SYSCALL(NtUserSetSysColors, NTSTATUS);
SYSCALL(NtUserSetSystemCursor, NTSTATUS);
SYSCALL(NtUserSetSystemMenu, NTSTATUS);
SYSCALL(NtUserSetSystemTimer, NTSTATUS);
SYSCALL(NtUserSetTargetForResourceBrokering, NTSTATUS);
SYSCALL(NtUserSetThreadDesktop, NTSTATUS);
SYSCALL(NtUserSetThreadInputBlocked, NTSTATUS);
SYSCALL(NtUserSetThreadLayoutHandles, NTSTATUS);
SYSCALL(NtUserSetThreadState, NTSTATUS);
SYSCALL(NtUserSetTimer, NTSTATUS);
SYSCALL(NtUserSetWinEventHook, NTSTATUS);
SYSCALL(NtUserSetWindowArrangement, NTSTATUS);
SYSCALL(NtUserSetWindowBand, NTSTATUS);
SYSCALL(NtUserSetWindowCompositionAttribute, NTSTATUS);
SYSCALL(NtUserSetWindowCompositionTransition, NTSTATUS);
SYSCALL(NtUserSetWindowDisplayAffinity, NTSTATUS);
SYSCALL(NtUserSetWindowFNID, NTSTATUS);
SYSCALL(NtUserSetWindowFeedbackSetting, NTSTATUS);
SYSCALL(NtUserSetWindowGroup, NTSTATUS);
SYSCALL(NtUserSetWindowLongPtr, NTSTATUS);
SYSCALL(NtUserSetWindowPlacement, NTSTATUS);
SYSCALL(NtUserSetWindowPos, NTSTATUS);
SYSCALL(NtUserSetWindowRgn, NTSTATUS);
SYSCALL(NtUserSetWindowRgnEx, NTSTATUS);
SYSCALL(NtUserSetWindowShowState, NTSTATUS);
SYSCALL(NtUserSetWindowStationUser, NTSTATUS);
SYSCALL(NtUserSetWindowWord, NTSTATUS);
SYSCALL(NtUserSetWindowsHookAW, NTSTATUS);
SYSCALL(NtUserSfmDestroyLogicalSurfaceBinding, NTSTATUS);
SYSCALL(NtUserSfmDxBindSwapChain, NTSTATUS);
SYSCALL(NtUserSfmDxGetSwapChainStats, NTSTATUS);
SYSCALL(NtUserSfmDxOpenSwapChain, NTSTATUS);
SYSCALL(NtUserSfmDxQuerySwapChainBindingStatus, NTSTATUS);
SYSCALL(NtUserSfmDxReleaseSwapChain, NTSTATUS);
SYSCALL(NtUserSfmDxReportPendingBindingsToDwm, NTSTATUS);
SYSCALL(NtUserSfmDxSetSwapChainBindingStatus, NTSTATUS);
SYSCALL(NtUserSfmDxSetSwapChainStats, NTSTATUS);
SYSCALL(NtUserSfmGetLogicalSurfaceBinding, NTSTATUS);
SYSCALL(NtUserShowCaret, NTSTATUS);
SYSCALL(NtUserShowCursor, NTSTATUS);
SYSCALL(NtUserShowScrollBar, NTSTATUS);
SYSCALL(NtUserShowSystemCursor, NTSTATUS);
SYSCALL(NtUserShowWindowAsync, NTSTATUS);
SYSCALL(NtUserShutdownBlockReasonCreate, NTSTATUS);
SYSCALL(NtUserShutdownBlockReasonQuery, NTSTATUS);
SYSCALL(NtUserShutdownReasonDestroy, NTSTATUS);
SYSCALL(NtUserSignalRedirectionStartComplete, NTSTATUS);
SYSCALL(NtUserSlicerControl, NTSTATUS);
SYSCALL(NtUserSoundSentry, NTSTATUS);
SYSCALL(NtUserStopAndEndInertia, NTSTATUS);
SYSCALL(NtUserSwitchDesktop, NTSTATUS);
SYSCALL(NtUserSystemParametersInfo, NTSTATUS);
SYSCALL(NtUserSystemParametersInfoForDpi, NTSTATUS);
SYSCALL(NtUserTestForInteractiveUser, NTSTATUS);
SYSCALL(NtUserThunkedMenuInfo, NTSTATUS);
SYSCALL(NtUserThunkedMenuItemInfo, NTSTATUS);
SYSCALL(NtUserToUnicodeEx, NTSTATUS);
SYSCALL(NtUserTrackMouseEvent, NTSTATUS);
SYSCALL(NtUserTrackPopupMenuEx, NTSTATUS);
SYSCALL(NtUserTransformPoint, NTSTATUS);
SYSCALL(NtUserTransformRect, NTSTATUS);
SYSCALL(NtUserTranslateAccelerator, NTSTATUS);
SYSCALL(NtUserTranslateMessage, NTSTATUS);
SYSCALL(NtUserUndelegateInput, NTSTATUS);
SYSCALL(NtUserUnhookWinEvent, NTSTATUS);
SYSCALL(NtUserUnhookWindowsHookEx, NTSTATUS);
SYSCALL(NtUserUnloadKeyboardLayout, NTSTATUS);
SYSCALL(NtUserUnlockWindowStation, NTSTATUS);
SYSCALL(NtUserUnregisterClass, NTSTATUS);
SYSCALL(NtUserUnregisterHotKey, NTSTATUS);
SYSCALL(NtUserUnregisterSessionPort, NTSTATUS);
SYSCALL(NtUserUnregisterUserApiHook, NTSTATUS);
SYSCALL(NtUserUpdateDefaultDesktopThumbnail, NTSTATUS);
SYSCALL(NtUserUpdateInputContext, NTSTATUS);
SYSCALL(NtUserUpdateInstance, NTSTATUS);
SYSCALL(NtUserUpdateLayeredWindow, NTSTATUS);
SYSCALL(NtUserUpdatePerUserSystemParameters, NTSTATUS);
SYSCALL(NtUserUpdateWindowInputSinkHints, NTSTATUS);
SYSCALL(NtUserUpdateWindowTrackingInfo, NTSTATUS);
SYSCALL(NtUserUpdateWindowTransform, NTSTATUS);
SYSCALL(NtUserUserHandleGrantAccess, NTSTATUS);
SYSCALL(NtUserValidateHandleSecure, NTSTATUS);
SYSCALL(NtUserValidateRect, NTSTATUS);
SYSCALL(NtUserValidateTimerCallback, NTSTATUS);
SYSCALL(NtUserVkKeyScanEx, NTSTATUS);
SYSCALL(NtUserWOWCleanup, NTSTATUS);
SYSCALL(NtUserWaitAvailableMessageEx, NTSTATUS);
SYSCALL(NtUserWaitForInputIdle, NTSTATUS);
SYSCALL(NtUserWaitForMsgAndEvent, NTSTATUS);
SYSCALL(NtUserWaitForRedirectionStartComplete, NTSTATUS);
SYSCALL(NtUserWaitMessage, NTSTATUS);
SYSCALL(NtUserWin32PoolAllocationStats, NTSTATUS);
SYSCALL(NtUserWindowFromDC, NTSTATUS);
SYSCALL(NtUserWindowFromPhysicalPoint, NTSTATUS);
SYSCALL(NtUserWindowFromPoint, NTSTATUS);
SYSCALL(NtUserYieldTask, NTSTATUS);
SYSCALL(NtValidateCompositionSurfaceHandle, NTSTATUS);
SYSCALL(NtVisualCaptureBits, NTSTATUS);
SYSCALL(NtAcquireCrossVmMutant, NTSTATUS);
SYSCALL(NtAllocateUserPhysicalPagesEx, NTSTATUS);
SYSCALL(NtContinueEx, NTSTATUS);
SYSCALL(NtCreateCrossVmEvent, NTSTATUS);
SYSCALL(NtCreateCrossVmMutant, NTSTATUS);
SYSCALL(NtPssCaptureVaSpaceBulk, NTSTATUS);
SYSCALL(NtLoadKey3, NTSTATUS);

#pragma clang diagnostic pop

static const syscall_t* nt[] =
{
    &NtFlushProcessWriteBuffers,
    &NtGetCurrentProcessorNumber,
    &NtGetEnvironmentVariableEx,
    &NtIsSystemResumeAutomatic,
    &NtQueryEnvironmentVariableInfoEx,
    &NtAcceptConnectPort,
    &NtAccessCheckAndAuditAlarm,
    &NtAccessCheckByTypeAndAuditAlarm,
    &NtAccessCheckByType,
    &NtAccessCheckByTypeResultListAndAuditAlarmByHandle,
    &NtAccessCheckByTypeResultListAndAuditAlarm,
    &NtAccessCheckByTypeResultList,
    &NtAccessCheck,
    &NtAddAtom,
    &NtAddBootEntry,
    &NtAddDriverEntry,
    &NtAdjustGroupsToken,
    &NtAdjustPrivilegesToken,
    &NtAlertResumeThread,
    &NtAlertThread,
    &NtAllocateLocallyUniqueId,
    &NtAllocateReserveObject,
    &NtAllocateUserPhysicalPages,
    &NtAllocateUuids,
    &NtAllocateVirtualMemory,
    &NtAlpcAcceptConnectPort,
    &NtAlpcCancelMessage,
    &NtAlpcConnectPort,
    &NtAlpcCreatePort,
    &NtAlpcCreatePortSection,
    &NtAlpcCreateResourceReserve,
    &NtAlpcCreateSectionView,
    &NtAlpcCreateSecurityContext,
    &NtAlpcDeletePortSection,
    &NtAlpcDeleteResourceReserve,
    &NtAlpcDeleteSectionView,
    &NtAlpcDeleteSecurityContext,
    &NtAlpcDisconnectPort,
    &NtAlpcImpersonateClientOfPort,
    &NtAlpcOpenSenderProcess,
    &NtAlpcOpenSenderThread,
    &NtAlpcQueryInformation,
    &NtAlpcQueryInformationMessage,
    &NtAlpcRevokeSecurityContext,
    &NtAlpcSendWaitReceivePort,
    &NtAlpcSetInformation,
    &NtApphelpCacheControl,
    &NtAreMappedFilesTheSame,
    &NtAssignProcessToJobObject,
    &NtCallbackReturn,
    &NtCancelIoFileEx,
    &NtCancelIoFile,
    &NtCancelSynchronousIoFile,
    &NtCancelTimer,
    &NtClearEvent,
    &NtClose,
    &NtCloseObjectAuditAlarm,
    &NtCommitComplete,
    &NtCommitEnlistment,
    &NtCommitTransaction,
    &NtCompactKeys,
    &NtCompareTokens,
    &NtCompleteConnectPort,
    &NtCompressKey,
    &NtConnectPort,
    &NtContinue,
    &NtCreateDebugObject,
    &NtCreateDirectoryObject,
    &NtCreateEnlistment,
    &NtCreateEvent,
    &NtCreateEventPair,
    &NtCreateFile,
    &NtCreateIoCompletion,
    &NtCreateJobObject,
    &NtCreateJobSet,
    &NtCreateKeyedEvent,
    &NtCreateKey,
    &NtCreateKeyTransacted,
    &NtCreateMailslotFile,
    &NtCreateMutant,
    &NtCreateNamedPipeFile,
    &NtCreatePagingFile,
    &NtCreatePort,
    &NtCreatePrivateNamespace,
    &NtCreateProcessEx,
    &NtCreateProcess,
    &NtCreateProfileEx,
    &NtCreateProfile,
    &NtCreateResourceManager,
    &NtCreateSection,
    &NtCreateSemaphore,
    &NtCreateSymbolicLinkObject,
    &NtCreateThreadEx,
    &NtCreateThread,
    &NtCreateTimer,
    &NtCreateToken,
    &NtCreateTransactionManager,
    &NtCreateTransaction,
    &NtCreateUserProcess,
    &NtCreateWaitablePort,
    &NtCreateWorkerFactory,
    &NtDebugActiveProcess,
    &NtDebugContinue,
    &NtDelayExecution,
    &NtDeleteAtom,
    &NtDeleteBootEntry,
    &NtDeleteDriverEntry,
    &NtDeleteFile,
    &NtDeleteKey,
    &NtDeleteObjectAuditAlarm,
    &NtDeletePrivateNamespace,
    &NtDeleteValueKey,
    &NtDeviceIoControlFile,
    &NtDisableLastKnownGood,
    &NtDisplayString,
    &NtDrawText,
    &NtDuplicateObject,
    &NtDuplicateToken,
    &NtEnableLastKnownGood,
    &NtEnumerateBootEntries,
    &NtEnumerateDriverEntries,
    &NtEnumerateKey,
    &NtEnumerateSystemEnvironmentValuesEx,
    &NtEnumerateTransactionObject,
    &NtEnumerateValueKey,
    &NtExtendSection,
    &NtFilterToken,
    &NtFindAtom,
    &NtFlushBuffersFile,
    &NtFlushInstallUILanguage,
    &NtFlushInstructionCache,
    &NtFlushKey,
    &NtFlushProcessWriteBuffers,
    &NtFlushVirtualMemory,
    &NtFlushWriteBuffer,
    &NtFreeUserPhysicalPages,
    &NtFreeVirtualMemory,
    &NtFreezeRegistry,
    &NtFreezeTransactions,
    &NtFsControlFile,
    &NtGetContextThread,
    &NtGetCurrentProcessorNumber,
    &NtGetDevicePowerState,
    &NtGetMUIRegistryInfo,
    &NtGetNextProcess,
    &NtGetNextThread,
    &NtGetNlsSectionPtr,
    &NtGetNotificationResourceManager,
    &NtGetPlugPlayEvent,
    &NtGetWriteWatch,
    &NtImpersonateAnonymousToken,
    &NtImpersonateClientOfPort,
    &NtImpersonateThread,
    &NtInitializeNlsFiles,
    &NtInitializeRegistry,
    &NtInitiatePowerAction,
    &NtIsProcessInJob,
    &NtIsSystemResumeAutomatic,
    &NtIsUILanguageComitted,
    &NtListenPort,
    &NtLoadDriver,
    &NtLoadKey2,
    &NtLoadKeyEx,
    &NtLoadKey,
    &NtLockFile,
    &NtLockProductActivationKeys,
    &NtLockRegistryKey,
    &NtLockVirtualMemory,
    &NtMakePermanentObject,
    &NtMakeTemporaryObject,
    &NtMapCMFModule,
    &NtMapUserPhysicalPages,
    &NtMapUserPhysicalPagesScatter,
    &NtMapViewOfSection,
    &NtModifyBootEntry,
    &NtModifyDriverEntry,
    &NtNotifyChangeDirectoryFile,
    &NtNotifyChangeKey,
    &NtNotifyChangeMultipleKeys,
    &NtNotifyChangeSession,
    &NtOpenDirectoryObject,
    &NtOpenEnlistment,
    &NtOpenEvent,
    &NtOpenEventPair,
    &NtOpenFile,
    &NtOpenIoCompletion,
    &NtOpenJobObject,
    &NtOpenKeyedEvent,
    &NtOpenKeyEx,
    &NtOpenKey,
    &NtOpenKeyTransactedEx,
    &NtOpenKeyTransacted,
    &NtOpenMutant,
    &NtOpenObjectAuditAlarm,
    &NtOpenPrivateNamespace,
    &NtOpenProcess,
    &NtOpenProcessTokenEx,
    &NtOpenProcessToken,
    &NtOpenResourceManager,
    &NtOpenSection,
    &NtOpenSemaphore,
    &NtOpenSession,
    &NtOpenSymbolicLinkObject,
    &NtOpenThread,
    &NtOpenThreadTokenEx,
    &NtOpenThreadToken,
    &NtOpenTimer,
    &NtOpenTransactionManager,
    &NtOpenTransaction,
    &NtPlugPlayControl,
    &NtPowerInformation,
    &NtPrepareComplete,
    &NtPrepareEnlistment,
    &NtPrePrepareComplete,
    &NtPrePrepareEnlistment,
    &NtPrivilegeCheck,
    &NtPrivilegedServiceAuditAlarm,
    &NtPrivilegeObjectAuditAlarm,
    &NtPropagationComplete,
    &NtPropagationFailed,
    &NtProtectVirtualMemory,
    &NtPulseEvent,
    &NtQueryAttributesFile,
    &NtQueryBootEntryOrder,
    &NtQueryBootOptions,
    &NtQueryDebugFilterState,
    &NtQueryDefaultLocale,
    &NtQueryDefaultUILanguage,
    &NtQueryDirectoryFile,
    &NtQueryDirectoryObject,
    &NtQueryDriverEntryOrder,
    &NtQueryEaFile,
    &NtQueryEvent,
    &NtQueryFullAttributesFile,
    &NtQueryInformationAtom,
    &NtQueryInformationEnlistment,
    &NtQueryInformationFile,
    &NtQueryInformationJobObject,
    &NtQueryInformationPort,
    &NtQueryInformationProcess,
    &NtQueryInformationResourceManager,
    &NtQueryInformationThread,
    &NtQueryInformationToken,
    &NtQueryInformationTransaction,
    &NtQueryInformationTransactionManager,
    &NtQueryInformationWorkerFactory,
    &NtQueryInstallUILanguage,
    &NtQueryIntervalProfile,
    &NtQueryIoCompletion,
    &NtQueryKey,
    &NtQueryLicenseValue,
    &NtQueryMultipleValueKey,
    &NtQueryMutant,
    &NtQueryObject,
    &NtQueryOpenSubKeysEx,
    &NtQueryOpenSubKeys,
    &NtQueryPerformanceCounter,
    &NtQueryPortInformationProcess,
    &NtQueryQuotaInformationFile,
    &NtQuerySection,
    &NtQuerySecurityAttributesToken,
    &NtQuerySecurityObject,
    &NtQuerySemaphore,
    &NtQuerySymbolicLinkObject,
    &NtQuerySystemEnvironmentValueEx,
    &NtQuerySystemEnvironmentValue,
    &NtQuerySystemInformationEx,
    &NtQuerySystemInformation,
    &NtQuerySystemTime,
    &NtQueryTimer,
    &NtQueryTimerResolution,
    &NtQueryValueKey,
    &NtQueryVirtualMemory,
    &NtQueryVolumeInformationFile,
    &NtQueueApcThreadEx,
    &NtQueueApcThread,
    &NtRaiseException,
    &NtRaiseHardError,
    &NtReadFile,
    &NtReadFileScatter,
    &NtReadOnlyEnlistment,
    &NtReadRequestData,
    &NtReadVirtualMemory,
    &NtRecoverEnlistment,
    &NtRecoverResourceManager,
    &NtRecoverTransactionManager,
    &NtRegisterProtocolAddressInformation,
    &NtRegisterThreadTerminatePort,
    &NtReleaseKeyedEvent,
    &NtReleaseMutant,
    &NtReleaseSemaphore,
    &NtReleaseWorkerFactoryWorker,
    &NtRemoveIoCompletionEx,
    &NtRemoveIoCompletion,
    &NtRemoveProcessDebug,
    &NtRenameKey,
    &NtRenameTransactionManager,
    &NtReplaceKey,
    &NtReplacePartitionUnit,
    &NtReplyPort,
    &NtReplyWaitReceivePortEx,
    &NtReplyWaitReceivePort,
    &NtReplyWaitReplyPort,
    &NtRequestPort,
    &NtRequestWaitReplyPort,
    &NtResetEvent,
    &NtResetWriteWatch,
    &NtRestoreKey,
    &NtResumeProcess,
    &NtResumeThread,
    &NtRollbackComplete,
    &NtRollbackEnlistment,
    &NtRollbackTransaction,
    &NtRollforwardTransactionManager,
    &NtSaveKeyEx,
    &NtSaveKey,
    &NtSaveMergedKeys,
    &NtSecureConnectPort,
    &NtSerializeBoot,
    &NtSetBootEntryOrder,
    &NtSetBootOptions,
    &NtSetContextThread,
    &NtSetDebugFilterState,
    &NtSetDefaultHardErrorPort,
    &NtSetDefaultLocale,
    &NtSetDefaultUILanguage,
    &NtSetDriverEntryOrder,
    &NtSetEaFile,
    &NtSetEventBoostPriority,
    &NtSetEvent,
    &NtSetHighEventPair,
    &NtSetHighWaitLowEventPair,
    &NtSetInformationDebugObject,
    &NtSetInformationEnlistment,
    &NtSetInformationFile,
    &NtSetInformationJobObject,
    &NtSetInformationKey,
    &NtSetInformationObject,
    &NtSetInformationProcess,
    &NtSetInformationResourceManager,
    &NtSetInformationThread,
    &NtSetInformationToken,
    &NtSetInformationTransaction,
    &NtSetInformationTransactionManager,
    &NtSetInformationWorkerFactory,
    &NtSetIntervalProfile,
    &NtSetIoCompletionEx,
    &NtSetIoCompletion,
    &NtSetLdtEntries,
    &NtSetLowEventPair,
    &NtSetLowWaitHighEventPair,
    &NtSetQuotaInformationFile,
    &NtSetSecurityObject,
    &NtSetSystemEnvironmentValueEx,
    &NtSetSystemEnvironmentValue,
    &NtSetSystemInformation,
    &NtSetSystemPowerState,
    &NtSetSystemTime,
    &NtSetThreadExecutionState,
    &NtSetTimerEx,
    &NtSetTimer,
    &NtSetTimerResolution,
    &NtSetUuidSeed,
    &NtSetValueKey,
    &NtSetVolumeInformationFile,
    &NtShutdownSystem,
    &NtShutdownWorkerFactory,
    &NtSignalAndWaitForSingleObject,
    &NtSinglePhaseReject,
    &NtStartProfile,
    &NtStopProfile,
    &NtSuspendProcess,
    &NtSuspendThread,
    &NtSystemDebugControl,
    &NtTerminateJobObject,
    &NtTerminateProcess,
    &NtTerminateThread,
    &NtTestAlert,
    &NtThawRegistry,
    &NtThawTransactions,
    &NtTraceControl,
    &NtTraceEvent,
    &NtTranslateFilePath,
    &NtUmsThreadYield,
    &NtUnloadDriver,
    &NtUnloadKey2,
    &NtUnloadKeyEx,
    &NtUnloadKey,
    &NtUnlockFile,
    &NtUnlockVirtualMemory,
    &NtUnmapViewOfSection,
    &NtVdmControl,
    &NtWaitForDebugEvent,
    &NtWaitForKeyedEvent,
    &NtWaitForMultipleObjects32,
    &NtWaitForMultipleObjects,
    &NtWaitForSingleObject,
    &NtWaitForWorkViaWorkerFactory,
    &NtWaitHighEventPair,
    &NtWaitLowEventPair,
    &NtWorkerFactoryWorkerReady,
    &NtWriteFileGather,
    &NtWriteFile,
    &NtWriteRequestData,
    &NtWriteVirtualMemory,
    &NtYieldExecution,
    &NtAcquireProcessActivityReference,
    &NtAddAtomEx,
    &NtAlertThreadByThreadId,
    &NtAllocateVirtualMemoryEx,
    &NtAlpcConnectPortEx,
    &NtAlpcImpersonateClientContainerOfPort,
    &NtAssociateWaitCompletionPacket,
    &NtCallEnclave,
    &NtCancelTimer2,
    &NtCancelWaitCompletionPacket,
    &NtCommitRegistryTransaction,
    &NtCompareObjects,
    &NtCompareSigningLevels,
    &NtConvertBetweenAuxiliaryCounterAndPerformanceCounter,
    &NtCreateDirectoryObjectEx,
    &NtCreateEnclave,
    &NtCreateIRTimer,
    &NtCreateLowBoxToken,
    &NtCreatePartition,
    &NtCreateRegistryTransaction,
    &NtCreateTimer2,
    &NtCreateTokenEx,
    &NtCreateWaitCompletionPacket,
    &NtCreateWnfStateName,
    &NtDeleteWnfStateData,
    &NtDeleteWnfStateName,
    &NtFilterBootOption,
    &NtFlushBuffersFileEx,
    &NtGetCachedSigningLevel,
    &NtGetCompleteWnfStateSubscription,
    &NtGetCurrentProcessorNumberEx,
    &NtInitializeEnclave,
    &NtLoadEnclaveData,
    &NtLoadHotPatch,
    &NtManagePartition,
    &NtMapViewOfSectionEx,
    &NtNotifyChangeDirectoryFileEx,
    &NtOpenPartition,
    &NtOpenRegistryTransaction,
    &NtQueryAuxiliaryCounterFrequency,
    &NtQueryDirectoryFileEx,
    &NtQueryInformationByName,
    &NtQuerySecurityPolicy,
    &NtQueryWnfStateData,
    &NtQueryWnfStateNameInformation,
    &NtRevertContainerImpersonation,
    &NtRollbackRegistryTransaction,
    &NtSetCachedSigningLevel,
    &NtSetCachedSigningLevel2,
    &NtSetIRTimer,
    &NtSetInformationSymbolicLink,
    &NtSetInformationVirtualMemory,
    &NtSetTimer2,
    &NtSetWnfProcessNotificationEvent,
    &NtSubscribeWnfStateChange,
    &NtTerminateEnclave,
    &NtUnmapViewOfSectionEx,
    &NtUnsubscribeWnfStateChange,
    &NtUpdateWnfStateData,
    &NtWaitForAlertByThreadId,
    &NtCreateSectionEx,
    &NtManageHotPatch,
    &BvgaSetVirtualFrameBuffer,
    &CmpCleanUpHigherLayerKcbCachesPreCallback,
    &GetPnpProperty,
    &ArbPreprocessEntry,
    &ArbAddReserved,
    &NtAcquireCrossVmMutant,
    &NtAllocateUserPhysicalPagesEx,
    &NtContinueEx,
    &NtCreateCrossVmEvent,
    &NtCreateCrossVmMutant,
    &NtPssCaptureVaSpaceBulk,
    &NtLoadKey3,
};

static const syscall_t* win32k[] =
{
    &NtBindCompositionSurface,
    &NtCloseCompositionInputSink,
    &NtCompositionInputThread,
    &NtCompositionSetDropTarget,
    &NtConfigureInputSpace,
    &NtCreateCompositionInputSink,
    &NtCreateCompositionSurfaceHandle,
    &NtCreateImplicitCompositionInputSink,
    &NtDCompositionAddCrossDeviceVisualChild,
    &NtDCompositionAddVisualChild,
    &NtDCompositionAttachMouseWheelToHwnd,
    &NtDCompositionBeginFrame,
    &NtDCompositionCapturePointer,
    &NtDCompositionCommitChannel,
    &NtDCompositionCommitSynchronizationObject,
    &NtDCompositionConfirmFrame,
    &NtDCompositionConnectPipe,
    &NtDCompositionCreateAndBindSharedSection,
    &NtDCompositionCreateChannel,
    &NtDCompositionCreateConnection,
    &NtDCompositionCreateConnectionContext,
    &NtDCompositionCreateDwmChannel,
    &NtDCompositionCreateResource,
    &NtDCompositionCreateSharedResourceHandle,
    &NtDCompositionCreateSharedVisualHandle,
    &NtDCompositionCreateSynchronizationObject,
    &NtDCompositionCurrentBatchId,
    &NtDCompositionDestroyChannel,
    &NtDCompositionDestroyConnection,
    &NtDCompositionDestroyConnectionContext,
    &NtDCompositionDiscardFrame,
    &NtDCompositionDuplicateHandleToProcess,
    &NtDCompositionDuplicateSwapchainHandleToDwm,
    &NtDCompositionDwmSyncFlush,
    &NtDCompositionEnableDDASupport,
    &NtDCompositionEnableMMCSS,
    &NtDCompositionGetAnimationTime,
    &NtDCompositionGetBatchId,
    &NtDCompositionGetChannels,
    &NtDCompositionGetConnectionBatch,
    &NtDCompositionGetConnectionContextBatch,
    &NtDCompositionGetDeletedResources,
    &NtDCompositionGetFrameLegacyTokens,
    &NtDCompositionGetFrameStatistics,
    &NtDCompositionGetFrameSurfaceUpdates,
    &NtDCompositionGetMaterialProperty,
    &NtDCompositionOpenSharedResource,
    &NtDCompositionOpenSharedResourceHandle,
    &NtDCompositionProcessChannelBatchBuffer,
    &NtDCompositionReferenceSharedResourceOnDwmChannel,
    &NtDCompositionRegisterThumbnailVisual,
    &NtDCompositionRegisterVirtualDesktopVisual,
    &NtDCompositionReleaseAllResources,
    &NtDCompositionReleaseResource,
    &NtDCompositionRemoveCrossDeviceVisualChild,
    &NtDCompositionRemoveVisualChild,
    &NtDCompositionReplaceVisualChildren,
    &NtDCompositionRetireFrame,
    &NtDCompositionSetChannelCallbackId,
    &NtDCompositionSetChannelCommitCompletionEvent,
    &NtDCompositionSetChannelConnectionId,
    &NtDCompositionSetChildRootVisual,
    &NtDCompositionSetDebugCounter,
    &NtDCompositionSetMaterialProperty,
    &NtDCompositionSetResourceAnimationProperty,
    &NtDCompositionSetResourceBufferProperty,
    &NtDCompositionSetResourceCallbackId,
    &NtDCompositionSetResourceDeletedNotificationTag,
    &NtDCompositionSetResourceFloatProperty,
    &NtDCompositionSetResourceHandleProperty,
    &NtDCompositionSetResourceIntegerProperty,
    &NtDCompositionSetResourceReferenceArrayProperty,
    &NtDCompositionSetResourceReferenceProperty,
    &NtDCompositionSetVisualInputSink,
    &NtDCompositionSignalGpuFence,
    &NtDCompositionSubmitDWMBatch,
    &NtDCompositionSuspendAnimations,
    &NtDCompositionSynchronize,
    &NtDCompositionTelemetryAnimationScenarioBegin,
    &NtDCompositionTelemetryAnimationScenarioReference,
    &NtDCompositionTelemetryAnimationScenarioUnreference,
    &NtDCompositionTelemetrySetApplicationId,
    &NtDCompositionTelemetryTouchInteractionBegin,
    &NtDCompositionTelemetryTouchInteractionEnd,
    &NtDCompositionTelemetryTouchInteractionUpdate,
    &NtDCompositionUpdatePointerCapture,
    &NtDCompositionValidateAndReferenceSystemVisualForHwndTarget,
    &NtDCompositionWaitForChannel,
    &NtDWMBindCursorToOutputConfig,
    &NtDWMCommitInputSystemOutputConfig,
    &NtDWMSetCursorOrientation,
    &NtDWMSetInputSystemOutputConfig,
    &NtDesktopCaptureBits,
    &NtDuplicateCompositionInputSink,
    &NtDxgkCreateTrackedWorkload,
    &NtDxgkDestroyTrackedWorkload,
    &NtDxgkDispMgrOperation,
    &NtDxgkEndTrackedWorkload,
    &NtDxgkGetAvailableTrackedWorkloadIndex,
    &NtDxgkGetProcessList,
    &NtDxgkGetTrackedWorkloadStatistics,
    &NtDxgkOutputDuplPresentToHwQueue,
    &NtDxgkRegisterVailProcess,
    &NtDxgkResetTrackedWorkload,
    &NtDxgkSubmitPresentBltToHwQueue,
    &NtDxgkSubmitPresentToHwQueue,
    &NtDxgkUpdateTrackedWorkload,
    &NtDxgkVailConnect,
    &NtDxgkVailDisconnect,
    &NtDxgkVailPromoteCompositionSurface,
    &NtEnableOneCoreTransformMode,
    &NtFlipObjectAddContent,
    &NtFlipObjectAddPoolBuffer,
    &NtFlipObjectConsumerAcquirePresent,
    &NtFlipObjectConsumerAdjustUsageReference,
    &NtFlipObjectConsumerBeginProcessPresent,
    &NtFlipObjectConsumerEndProcessPresent,
    &NtFlipObjectConsumerPostMessage,
    &NtFlipObjectConsumerQueryBufferInfo,
    &NtFlipObjectCreate,
    &NtFlipObjectDisconnectEndpoint,
    &NtFlipObjectOpen,
    &NtFlipObjectPresentCancel,
    &NtFlipObjectQueryBufferAvailableEvent,
    &NtFlipObjectQueryEndpointConnected,
    &NtFlipObjectQueryNextMessageToProducer,
    &NtFlipObjectReadNextMessageToProducer,
    &NtFlipObjectRemoveContent,
    &NtFlipObjectRemovePoolBuffer,
    &NtFlipObjectSetContent,
    &NtGdiAbortDoc,
    &NtGdiAbortPath,
    &NtGdiAddEmbFontToDC,
    &NtGdiAddFontMemResourceEx,
    &NtGdiAddFontResourceW,
    &NtGdiAddInitialFonts,
    &NtGdiAddRemoteFontToDC,
    &NtGdiAddRemoteMMInstanceToDC,
    &NtGdiAlphaBlend,
    &NtGdiAngleArc,
    &NtGdiAnyLinkedFonts,
    &NtGdiArcInternal,
    &NtGdiBRUSHOBJ_DeleteRbrush,
    &NtGdiBRUSHOBJ_hGetColorTransform,
    &NtGdiBRUSHOBJ_pvAllocRbrush,
    &NtGdiBRUSHOBJ_pvGetRbrush,
    &NtGdiBRUSHOBJ_ulGetBrushColor,
    &NtGdiBeginGdiRendering,
    &NtGdiBeginPath,
    &NtGdiBitBlt,
    &NtGdiCLIPOBJ_bEnum,
    &NtGdiCLIPOBJ_cEnumStart,
    &NtGdiCLIPOBJ_ppoGetPath,
    &NtGdiCancelDC,
    &NtGdiChangeGhostFont,
    &NtGdiCheckBitmapBits,
    &NtGdiClearBitmapAttributes,
    &NtGdiClearBrushAttributes,
    &NtGdiCloseFigure,
    &NtGdiColorCorrectPalette,
    &NtGdiCombineRgn,
    &NtGdiCombineTransform,
    &NtGdiComputeXformCoefficients,
    &NtGdiConfigureOPMProtectedOutput,
    &NtGdiConsoleTextOut,
    &NtGdiConvertMetafileRect,
    &NtGdiCreateBitmap,
    &NtGdiCreateBitmapFromDxSurface,
    &NtGdiCreateBitmapFromDxSurface2,
    &NtGdiCreateClientObj,
    &NtGdiCreateColorSpace,
    &NtGdiCreateColorTransform,
    &NtGdiCreateCompatibleBitmap,
    &NtGdiCreateCompatibleDC,
    &NtGdiCreateDIBBrush,
    &NtGdiCreateDIBSection,
    &NtGdiCreateDIBitmapInternal,
    &NtGdiCreateEllipticRgn,
    &NtGdiCreateHalftonePalette,
    &NtGdiCreateHatchBrushInternal,
    &NtGdiCreateMetafileDC,
    &NtGdiCreateOPMProtectedOutput,
    &NtGdiCreateOPMProtectedOutputs,
    &NtGdiCreatePaletteInternal,
    &NtGdiCreatePatternBrushInternal,
    &NtGdiCreatePen,
    &NtGdiCreateRectRgn,
    &NtGdiCreateRoundRectRgn,
    &NtGdiCreateServerMetaFile,
    &NtGdiCreateSessionMappedDIBSection,
    &NtGdiCreateSolidBrush,
    &NtGdiD3dContextCreate,
    &NtGdiD3dContextDestroy,
    &NtGdiD3dContextDestroyAll,
    &NtGdiD3dDrawPrimitives2,
    &NtGdiD3dValidateTextureStageState,
    &NtGdiDDCCIGetCapabilitiesString,
    &NtGdiDDCCIGetCapabilitiesStringLength,
    &NtGdiDDCCIGetTimingReport,
    &NtGdiDDCCIGetVCPFeature,
    &NtGdiDDCCISaveCurrentSettings,
    &NtGdiDDCCISetVCPFeature,
    &NtGdiDdAddAttachedSurface,
    &NtGdiDdAlphaBlt,
    &NtGdiDdAttachSurface,
    &NtGdiDdBeginMoCompFrame,
    &NtGdiDdBlt,
    &NtGdiDdCanCreateD3DBuffer,
    &NtGdiDdCanCreateSurface,
    &NtGdiDdColorControl,
    &NtGdiDdCreateD3DBuffer,
    &NtGdiDdCreateDirectDrawObject,
    &NtGdiDdCreateFullscreenSprite,
    &NtGdiDdCreateMoComp,
    &NtGdiDdCreateSurface,
    &NtGdiDdCreateSurfaceEx,
    &NtGdiDdCreateSurfaceObject,
    &NtGdiDdDDIAbandonSwapChain,
    &NtGdiDdDDIAcquireKeyedMutex,
    &NtGdiDdDDIAcquireKeyedMutex2,
    &NtGdiDdDDIAcquireSwapChain,
    &NtGdiDdDDIAddSurfaceToSwapChain,
    &NtGdiDdDDIAdjustFullscreenGamma,
    &NtGdiDdDDICacheHybridQueryValue,
    &NtGdiDdDDIChangeVideoMemoryReservation,
    &NtGdiDdDDICheckExclusiveOwnership,
    &NtGdiDdDDICheckMonitorPowerState,
    &NtGdiDdDDICheckMultiPlaneOverlaySupport,
    &NtGdiDdDDICheckMultiPlaneOverlaySupport2,
    &NtGdiDdDDICheckMultiPlaneOverlaySupport3,
    &NtGdiDdDDICheckOcclusion,
    &NtGdiDdDDICheckSharedResourceAccess,
    &NtGdiDdDDICheckVidPnExclusiveOwnership,
    &NtGdiDdDDICloseAdapter,
    &NtGdiDdDDIConfigureSharedResource,
    &NtGdiDdDDICreateAllocation,
    &NtGdiDdDDICreateBundleObject,
    &NtGdiDdDDICreateContext,
    &NtGdiDdDDICreateContextVirtual,
    &NtGdiDdDDICreateDCFromMemory,
    &NtGdiDdDDICreateDevice,
    &NtGdiDdDDICreateHwContext,
    &NtGdiDdDDICreateHwQueue,
    &NtGdiDdDDICreateKeyedMutex,
    &NtGdiDdDDICreateKeyedMutex2,
    &NtGdiDdDDICreateOutputDupl,
    &NtGdiDdDDICreateOverlay,
    &NtGdiDdDDICreatePagingQueue,
    &NtGdiDdDDICreateProtectedSession,
    &NtGdiDdDDICreateSwapChain,
    &NtGdiDdDDICreateSynchronizationObject,
    &NtGdiDdDDIDDisplayEnum,
    &NtGdiDdDDIDestroyAllocation,
    &NtGdiDdDDIDestroyAllocation2,
    &NtGdiDdDDIDestroyContext,
    &NtGdiDdDDIDestroyDCFromMemory,
    &NtGdiDdDDIDestroyDevice,
    &NtGdiDdDDIDestroyHwContext,
    &NtGdiDdDDIDestroyHwQueue,
    &NtGdiDdDDIDestroyKeyedMutex,
    &NtGdiDdDDIDestroyOutputDupl,
    &NtGdiDdDDIDestroyOverlay,
    &NtGdiDdDDIDestroyPagingQueue,
    &NtGdiDdDDIDestroyProtectedSession,
    &NtGdiDdDDIDestroySynchronizationObject,
    &NtGdiDdDDIDispMgrCreate,
    &NtGdiDdDDIDispMgrSourceOperation,
    &NtGdiDdDDIDispMgrTargetOperation,
    &NtGdiDdDDIEnumAdapters,
    &NtGdiDdDDIEnumAdapters2,
    &NtGdiDdDDIEscape,
    &NtGdiDdDDIEvict,
    &NtGdiDdDDIExtractBundleObject,
    &NtGdiDdDDIFlipOverlay,
    &NtGdiDdDDIFlushHeapTransitions,
    &NtGdiDdDDIFreeGpuVirtualAddress,
    &NtGdiDdDDIGetAllocationPriority,
    &NtGdiDdDDIGetCachedHybridQueryValue,
    &NtGdiDdDDIGetContextInProcessSchedulingPriority,
    &NtGdiDdDDIGetContextSchedulingPriority,
    &NtGdiDdDDIGetDWMVerticalBlankEvent,
    &NtGdiDdDDIGetDeviceState,
    &NtGdiDdDDIGetDisplayModeList,
    &NtGdiDdDDIGetMemoryBudgetTarget,
    &NtGdiDdDDIGetMultiPlaneOverlayCaps,
    &NtGdiDdDDIGetMultisampleMethodList,
    &NtGdiDdDDIGetOverlayState,
    &NtGdiDdDDIGetPostCompositionCaps,
    &NtGdiDdDDIGetPresentHistory,
    &NtGdiDdDDIGetPresentQueueEvent,
    &NtGdiDdDDIGetProcessDeviceLostSupport,
    &NtGdiDdDDIGetProcessDeviceRemovalSupport,
    &NtGdiDdDDIGetProcessSchedulingPriorityBand,
    &NtGdiDdDDIGetProcessSchedulingPriorityClass,
    &NtGdiDdDDIGetResourcePresentPrivateDriverData,
    &NtGdiDdDDIGetRuntimeData,
    &NtGdiDdDDIGetScanLine,
    &NtGdiDdDDIGetSetSwapChainMetadata,
    &NtGdiDdDDIGetSharedPrimaryHandle,
    &NtGdiDdDDIGetSharedResourceAdapterLuid,
    &NtGdiDdDDIGetSharedResourceAdapterLuidFlipManager,
    &NtGdiDdDDIGetYieldPercentage,
    &NtGdiDdDDIInvalidateActiveVidPn,
    &NtGdiDdDDIInvalidateCache,
    &NtGdiDdDDILock,
    &NtGdiDdDDILock2,
    &NtGdiDdDDIMakeResident,
    &NtGdiDdDDIMapGpuVirtualAddress,
    &NtGdiDdDDIMarkDeviceAsError,
    &NtGdiDdDDINetDispGetNextChunkInfo,
    &NtGdiDdDDINetDispQueryMiracastDisplayDeviceStatus,
    &NtGdiDdDDINetDispQueryMiracastDisplayDeviceSupport,
    &NtGdiDdDDINetDispStartMiracastDisplayDevice,
    &NtGdiDdDDINetDispStartMiracastDisplayDeviceEx,
    &NtGdiDdDDINetDispStopMiracastDisplayDevice,
    &NtGdiDdDDINetDispStopSessions,
    &NtGdiDdDDIOfferAllocations,
    &NtGdiDdDDIOpenAdapterFromDeviceName,
    &NtGdiDdDDIOpenAdapterFromHdc,
    &NtGdiDdDDIOpenAdapterFromLuid,
    &NtGdiDdDDIOpenBundleObjectNtHandleFromName,
    &NtGdiDdDDIOpenKeyedMutex,
    &NtGdiDdDDIOpenKeyedMutex2,
    &NtGdiDdDDIOpenKeyedMutexFromNtHandle,
    &NtGdiDdDDIOpenNtHandleFromName,
    &NtGdiDdDDIOpenProtectedSessionFromNtHandle,
    &NtGdiDdDDIOpenResource,
    &NtGdiDdDDIOpenResourceFromNtHandle,
    &NtGdiDdDDIOpenSwapChain,
    &NtGdiDdDDIOpenSyncObjectFromNtHandle,
    &NtGdiDdDDIOpenSyncObjectFromNtHandle2,
    &NtGdiDdDDIOpenSyncObjectNtHandleFromName,
    &NtGdiDdDDIOpenSynchronizationObject,
    &NtGdiDdDDIOutputDuplGetFrameInfo,
    &NtGdiDdDDIOutputDuplGetMetaData,
    &NtGdiDdDDIOutputDuplGetPointerShapeData,
    &NtGdiDdDDIOutputDuplPresent,
    &NtGdiDdDDIOutputDuplReleaseFrame,
    &NtGdiDdDDIPinDirectFlipResources,
    &NtGdiDdDDIPollDisplayChildren,
    &NtGdiDdDDIPresent,
    &NtGdiDdDDIPresentMultiPlaneOverlay,
    &NtGdiDdDDIPresentMultiPlaneOverlay2,
    &NtGdiDdDDIPresentMultiPlaneOverlay3,
    &NtGdiDdDDIPresentRedirected,
    &NtGdiDdDDIQueryAdapterInfo,
    &NtGdiDdDDIQueryAllocationResidency,
    &NtGdiDdDDIQueryClockCalibration,
    &NtGdiDdDDIQueryFSEBlock,
    &NtGdiDdDDIQueryProcessOfferInfo,
    &NtGdiDdDDIQueryProtectedSessionInfoFromNtHandle,
    &NtGdiDdDDIQueryProtectedSessionStatus,
    &NtGdiDdDDIQueryRemoteVidPnSourceFromGdiDisplayName,
    &NtGdiDdDDIQueryResourceInfo,
    &NtGdiDdDDIQueryResourceInfoFromNtHandle,
    &NtGdiDdDDIQueryStatistics,
    &NtGdiDdDDIQueryVidPnExclusiveOwnership,
    &NtGdiDdDDIQueryVideoMemoryInfo,
    &NtGdiDdDDIReclaimAllocations,
    &NtGdiDdDDIReclaimAllocations2,
    &NtGdiDdDDIReleaseKeyedMutex,
    &NtGdiDdDDIReleaseKeyedMutex2,
    &NtGdiDdDDIReleaseProcessVidPnSourceOwners,
    &NtGdiDdDDIReleaseSwapChain,
    &NtGdiDdDDIRemoveSurfaceFromSwapChain,
    &NtGdiDdDDIRender,
    &NtGdiDdDDIReserveGpuVirtualAddress,
    &NtGdiDdDDISetAllocationPriority,
    &NtGdiDdDDISetContextInProcessSchedulingPriority,
    &NtGdiDdDDISetContextSchedulingPriority,
    &NtGdiDdDDISetDeviceLostSupport,
    &NtGdiDdDDISetDisplayMode,
    &NtGdiDdDDISetDisplayPrivateDriverFormat,
    &NtGdiDdDDISetDodIndirectSwapchain,
    &NtGdiDdDDISetFSEBlock,
    &NtGdiDdDDISetGammaRamp,
    &NtGdiDdDDISetHwProtectionTeardownRecovery,
    &NtGdiDdDDISetMemoryBudgetTarget,
    &NtGdiDdDDISetMonitorColorSpaceTransform,
    &NtGdiDdDDISetProcessDeviceRemovalSupport,
    &NtGdiDdDDISetProcessSchedulingPriorityBand,
    &NtGdiDdDDISetProcessSchedulingPriorityClass,
    &NtGdiDdDDISetQueuedLimit,
    &NtGdiDdDDISetStablePowerState,
    &NtGdiDdDDISetStereoEnabled,
    &NtGdiDdDDISetSyncRefreshCountWaitTarget,
    &NtGdiDdDDISetVidPnSourceHwProtection,
    &NtGdiDdDDISetVidPnSourceOwner,
    &NtGdiDdDDISetVidPnSourceOwner1,
    &NtGdiDdDDISetYieldPercentage,
    &NtGdiDdDDIShareObjects,
    &NtGdiDdDDISharedPrimaryLockNotification,
    &NtGdiDdDDISharedPrimaryUnLockNotification,
    &NtGdiDdDDISignalSynchronizationObject,
    &NtGdiDdDDISignalSynchronizationObjectFromCpu,
    &NtGdiDdDDISignalSynchronizationObjectFromGpu,
    &NtGdiDdDDISignalSynchronizationObjectFromGpu2,
    &NtGdiDdDDISubmitCommand,
    &NtGdiDdDDISubmitCommandToHwQueue,
    &NtGdiDdDDISubmitSignalSyncObjectsToHwQueue,
    &NtGdiDdDDISubmitWaitForSyncObjectsToHwQueue,
    &NtGdiDdDDITrimProcessCommitment,
    &NtGdiDdDDIUnOrderedPresentSwapChain,
    &NtGdiDdDDIUnlock,
    &NtGdiDdDDIUnlock2,
    &NtGdiDdDDIUnpinDirectFlipResources,
    &NtGdiDdDDIUpdateAllocationProperty,
    &NtGdiDdDDIUpdateGpuVirtualAddress,
    &NtGdiDdDDIUpdateOverlay,
    &NtGdiDdDDIWaitForIdle,
    &NtGdiDdDDIWaitForSynchronizationObject,
    &NtGdiDdDDIWaitForSynchronizationObjectFromCpu,
    &NtGdiDdDDIWaitForSynchronizationObjectFromGpu,
    &NtGdiDdDDIWaitForVerticalBlankEvent,
    &NtGdiDdDDIWaitForVerticalBlankEvent2,
    &NtGdiDdDeleteDirectDrawObject,
    &NtGdiDdDeleteSurfaceObject,
    &NtGdiDdDestroyD3DBuffer,
    &NtGdiDdDestroyFullscreenSprite,
    &NtGdiDdDestroyMoComp,
    &NtGdiDdDestroySurface,
    &NtGdiDdEndMoCompFrame,
    &NtGdiDdFlip,
    &NtGdiDdFlipToGDISurface,
    &NtGdiDdGetAvailDriverMemory,
    &NtGdiDdGetBltStatus,
    &NtGdiDdGetDC,
    &NtGdiDdGetDriverInfo,
    &NtGdiDdGetDriverState,
    &NtGdiDdGetDxHandle,
    &NtGdiDdGetFlipStatus,
    &NtGdiDdGetInternalMoCompInfo,
    &NtGdiDdGetMoCompBuffInfo,
    &NtGdiDdGetMoCompFormats,
    &NtGdiDdGetMoCompGuids,
    &NtGdiDdGetScanLine,
    &NtGdiDdLock,
    &NtGdiDdLockD3D,
    &NtGdiDdNotifyFullscreenSpriteUpdate,
    &NtGdiDdQueryDirectDrawObject,
    &NtGdiDdQueryMoCompStatus,
    &NtGdiDdQueryVisRgnUniqueness,
    &NtGdiDdReenableDirectDrawObject,
    &NtGdiDdReleaseDC,
    &NtGdiDdRenderMoComp,
    &NtGdiDdResetVisrgn,
    &NtGdiDdSetColorKey,
    &NtGdiDdSetExclusiveMode,
    &NtGdiDdSetGammaRamp,
    &NtGdiDdSetOverlayPosition,
    &NtGdiDdUnattachSurface,
    &NtGdiDdUnlock,
    &NtGdiDdUnlockD3D,
    &NtGdiDdUpdateOverlay,
    &NtGdiDdWaitForVerticalBlank,
    &NtGdiDeleteClientObj,
    &NtGdiDeleteColorSpace,
    &NtGdiDeleteColorTransform,
    &NtGdiDeleteObjectApp,
    &NtGdiDescribePixelFormat,
    &NtGdiDestroyOPMProtectedOutput,
    &NtGdiDestroyPhysicalMonitor,
    &NtGdiDoBanding,
    &NtGdiDoPalette,
    &NtGdiDrawEscape,
    &NtGdiDrawStream,
    &NtGdiDvpAcquireNotification,
    &NtGdiDvpCanCreateVideoPort,
    &NtGdiDvpColorControl,
    &NtGdiDvpCreateVideoPort,
    &NtGdiDvpDestroyVideoPort,
    &NtGdiDvpFlipVideoPort,
    &NtGdiDvpGetVideoPortBandwidth,
    &NtGdiDvpGetVideoPortConnectInfo,
    &NtGdiDvpGetVideoPortField,
    &NtGdiDvpGetVideoPortFlipStatus,
    &NtGdiDvpGetVideoPortInputFormats,
    &NtGdiDvpGetVideoPortLine,
    &NtGdiDvpGetVideoPortOutputFormats,
    &NtGdiDvpGetVideoSignalStatus,
    &NtGdiDvpReleaseNotification,
    &NtGdiDvpUpdateVideoPort,
    &NtGdiDvpWaitForVideoPortSync,
    &NtGdiDwmCreatedBitmapRemotingOutput,
    &NtGdiDwmGetDirtyRgn,
    &NtGdiDwmGetSurfaceData,
    &NtGdiDxgGenericThunk,
    &NtGdiEllipse,
    &NtGdiEnableEudc,
    &NtGdiEndDoc,
    &NtGdiEndGdiRendering,
    &NtGdiEndPage,
    &NtGdiEndPath,
    &NtGdiEngAlphaBlend,
    &NtGdiEngAssociateSurface,
    &NtGdiEngBitBlt,
    &NtGdiEngCheckAbort,
    &NtGdiEngComputeGlyphSet,
    &NtGdiEngCopyBits,
    &NtGdiEngCreateBitmap,
    &NtGdiEngCreateClip,
    &NtGdiEngCreateDeviceBitmap,
    &NtGdiEngCreateDeviceSurface,
    &NtGdiEngCreatePalette,
    &NtGdiEngDeleteClip,
    &NtGdiEngDeletePalette,
    &NtGdiEngDeletePath,
    &NtGdiEngDeleteSurface,
    &NtGdiEngEraseSurface,
    &NtGdiEngFillPath,
    &NtGdiEngGradientFill,
    &NtGdiEngLineTo,
    &NtGdiEngLockSurface,
    &NtGdiEngMarkBandingSurface,
    &NtGdiEngPaint,
    &NtGdiEngPlgBlt,
    &NtGdiEngStretchBlt,
    &NtGdiEngStretchBltROP,
    &NtGdiEngStrokeAndFillPath,
    &NtGdiEngStrokePath,
    &NtGdiEngTextOut,
    &NtGdiEngTransparentBlt,
    &NtGdiEngUnlockSurface,
    &NtGdiEnsureDpiDepDefaultGuiFontForPlateau,
    &NtGdiEnumFontChunk,
    &NtGdiEnumFontClose,
    &NtGdiEnumFontOpen,
    &NtGdiEnumFonts,
    &NtGdiEnumObjects,
    &NtGdiEqualRgn,
    &NtGdiEudcLoadUnloadLink,
    &NtGdiExcludeClipRect,
    &NtGdiExtCreatePen,
    &NtGdiExtCreateRegion,
    &NtGdiExtEscape,
    &NtGdiExtFloodFill,
    &NtGdiExtGetObjectW,
    &NtGdiExtSelectClipRgn,
    &NtGdiExtTextOutW,
    &NtGdiFONTOBJ_cGetAllGlyphHandles,
    &NtGdiFONTOBJ_cGetGlyphs,
    &NtGdiFONTOBJ_pQueryGlyphAttrs,
    &NtGdiFONTOBJ_pfdg,
    &NtGdiFONTOBJ_pifi,
    &NtGdiFONTOBJ_pvTrueTypeFontFile,
    &NtGdiFONTOBJ_pxoGetXform,
    &NtGdiFONTOBJ_vGetInfo,
    &NtGdiFillPath,
    &NtGdiFillRgn,
    &NtGdiFlattenPath,
    &NtGdiFlush,
    &NtGdiFontIsLinked,
    &NtGdiForceUFIMapping,
    &NtGdiFrameRgn,
    &NtGdiFullscreenControl,
    &NtGdiGetAndSetDCDword,
    &NtGdiGetAppClipBox,
    &NtGdiGetAppliedDeviceGammaRamp,
    &NtGdiGetBitmapBits,
    &NtGdiGetBitmapDimension,
    &NtGdiGetBitmapDpiScaleValue,
    &NtGdiGetBoundsRect,
    &NtGdiGetCOPPCompatibleOPMInformation,
    &NtGdiGetCertificate,
    &NtGdiGetCertificateByHandle,
    &NtGdiGetCertificateSize,
    &NtGdiGetCertificateSizeByHandle,
    &NtGdiGetCharABCWidthsW,
    &NtGdiGetCharSet,
    &NtGdiGetCharWidthInfo,
    &NtGdiGetCharWidthW,
    &NtGdiGetCharacterPlacementW,
    &NtGdiGetColorAdjustment,
    &NtGdiGetColorSpaceforBitmap,
    &NtGdiGetCurrentDpiInfo,
    &NtGdiGetDCDpiScaleValue,
    &NtGdiGetDCDword,
    &NtGdiGetDCObject,
    &NtGdiGetDCPoint,
    &NtGdiGetDCforBitmap,
    &NtGdiGetDIBitsInternal,
    &NtGdiGetDeviceCaps,
    &NtGdiGetDeviceCapsAll,
    &NtGdiGetDeviceGammaRamp,
    &NtGdiGetDeviceWidth,
    &NtGdiGetDhpdev,
    &NtGdiGetETM,
    &NtGdiGetEmbUFI,
    &NtGdiGetEmbedFonts,
    &NtGdiGetEntry,
    &NtGdiGetEudcTimeStampEx,
    &NtGdiGetFontData,
    &NtGdiGetFontFileData,
    &NtGdiGetFontFileInfo,
    &NtGdiGetFontResourceInfoInternalW,
    &NtGdiGetFontUnicodeRanges,
    &NtGdiGetGammaRampCapability,
    &NtGdiGetGlyphIndicesW,
    &NtGdiGetGlyphIndicesWInternal,
    &NtGdiGetGlyphOutline,
    &NtGdiGetKerningPairs,
    &NtGdiGetLinkedUFIs,
    &NtGdiGetMiterLimit,
    &NtGdiGetMonitorID,
    &NtGdiGetNearestColor,
    &NtGdiGetNearestPaletteIndex,
    &NtGdiGetNumberOfPhysicalMonitors,
    &NtGdiGetOPMInformation,
    &NtGdiGetOPMRandomNumber,
    &NtGdiGetObjectBitmapHandle,
    &NtGdiGetOutlineTextMetricsInternalW,
    &NtGdiGetPath,
    &NtGdiGetPerBandInfo,
    &NtGdiGetPhysicalMonitorDescription,
    &NtGdiGetPhysicalMonitors,
    &NtGdiGetPixel,
    &NtGdiGetProcessSessionFonts,
    &NtGdiGetPublicFontTableChangeCookie,
    &NtGdiGetRandomRgn,
    &NtGdiGetRasterizerCaps,
    &NtGdiGetRealizationInfo,
    &NtGdiGetRegionData,
    &NtGdiGetRgnBox,
    &NtGdiGetServerMetaFileBits,
    &NtGdiGetSpoolMessage,
    &NtGdiGetStats,
    &NtGdiGetStockObject,
    &NtGdiGetStringBitmapW,
    &NtGdiGetSuggestedOPMProtectedOutputArraySize,
    &NtGdiGetSystemPaletteUse,
    &NtGdiGetTextCharsetInfo,
    &NtGdiGetTextExtent,
    &NtGdiGetTextExtentExW,
    &NtGdiGetTextFaceW,
    &NtGdiGetTextMetricsW,
    &NtGdiGetTransform,
    &NtGdiGetUFI,
    &NtGdiGetUFIPathname,
    &NtGdiGetWidthTable,
    &NtGdiGradientFill,
    &NtGdiHLSurfGetInformation,
    &NtGdiHLSurfSetInformation,
    &NtGdiHT_Get8BPPFormatPalette,
    &NtGdiHT_Get8BPPMaskPalette,
    &NtGdiHfontCreate,
    &NtGdiIcmBrushInfo,
    &NtGdiInit,
    &NtGdiInitSpool,
    &NtGdiIntersectClipRect,
    &NtGdiInvertRgn,
    &NtGdiLineTo,
    &NtGdiMakeFontDir,
    &NtGdiMakeInfoDC,
    &NtGdiMakeObjectUnXferable,
    &NtGdiMakeObjectXferable,
    &NtGdiMaskBlt,
    &NtGdiMirrorWindowOrg,
    &NtGdiModifyWorldTransform,
    &NtGdiMonoBitmap,
    &NtGdiMoveTo,
    &NtGdiOffsetClipRgn,
    &NtGdiOffsetRgn,
    &NtGdiOpenDCW,
    &NtGdiPATHOBJ_bEnum,
    &NtGdiPATHOBJ_bEnumClipLines,
    &NtGdiPATHOBJ_vEnumStart,
    &NtGdiPATHOBJ_vEnumStartClipLines,
    &NtGdiPATHOBJ_vGetBounds,
    &NtGdiPatBlt,
    &NtGdiPathToRegion,
    &NtGdiPlgBlt,
    &NtGdiPolyDraw,
    &NtGdiPolyPatBlt,
    &NtGdiPolyPolyDraw,
    &NtGdiPolyTextOutW,
    &NtGdiPtInRegion,
    &NtGdiPtVisible,
    &NtGdiQueryFontAssocInfo,
    &NtGdiQueryFonts,
    &NtGdiRectInRegion,
    &NtGdiRectVisible,
    &NtGdiRectangle,
    &NtGdiRemoveFontMemResourceEx,
    &NtGdiRemoveFontResourceW,
    &NtGdiRemoveMergeFont,
    &NtGdiResetDC,
    &NtGdiResizePalette,
    &NtGdiRestoreDC,
    &NtGdiRoundRect,
    &NtGdiSTROBJ_bEnum,
    &NtGdiSTROBJ_bEnumPositionsOnly,
    &NtGdiSTROBJ_bGetAdvanceWidths,
    &NtGdiSTROBJ_dwGetCodePage,
    &NtGdiSTROBJ_vEnumStart,
    &NtGdiSaveDC,
    &NtGdiScaleRgn,
    &NtGdiScaleValues,
    &NtGdiScaleViewportExtEx,
    &NtGdiScaleWindowExtEx,
    &NtGdiSelectBitmap,
    &NtGdiSelectBrush,
    &NtGdiSelectClipPath,
    &NtGdiSelectFont,
    &NtGdiSelectPen,
    &NtGdiSetBitmapAttributes,
    &NtGdiSetBitmapBits,
    &NtGdiSetBitmapDimension,
    &NtGdiSetBoundsRect,
    &NtGdiSetBrushAttributes,
    &NtGdiSetBrushOrg,
    &NtGdiSetColorAdjustment,
    &NtGdiSetColorSpace,
    &NtGdiSetDIBitsToDeviceInternal,
    &NtGdiSetDeviceGammaRamp,
    &NtGdiSetFontEnumeration,
    &NtGdiSetFontXform,
    &NtGdiSetIcmMode,
    &NtGdiSetLayout,
    &NtGdiSetLinkedUFIs,
    &NtGdiSetMagicColors,
    &NtGdiSetMetaRgn,
    &NtGdiSetMiterLimit,
    &NtGdiSetOPMSigningKeyAndSequenceNumbers,
    &NtGdiSetPUMPDOBJ,
    &NtGdiSetPixel,
    &NtGdiSetPixelFormat,
    &NtGdiSetPrivateDeviceGammaRamp,
    &NtGdiSetRectRgn,
    &NtGdiSetSizeDevice,
    &NtGdiSetSystemPaletteUse,
    &NtGdiSetTextJustification,
    &NtGdiSetUMPDSandboxState,
    &NtGdiSetVirtualResolution,
    &NtGdiSetupPublicCFONT,
    &NtGdiSfmGetNotificationTokens,
    &NtGdiStartDoc,
    &NtGdiStartPage,
    &NtGdiStretchBlt,
    &NtGdiStretchDIBitsInternal,
    &NtGdiStrokeAndFillPath,
    &NtGdiStrokePath,
    &NtGdiSwapBuffers,
    &NtGdiTransformPoints,
    &NtGdiTransparentBlt,
    &NtGdiUMPDEngFreeUserMem,
    &NtGdiUnloadPrinterDriver,
    &NtGdiUnmapMemFont,
    &NtGdiUnrealizeObject,
    &NtGdiUpdateColors,
    &NtGdiUpdateTransform,
    &NtGdiWidenPath,
    &NtGdiXFORMOBJ_bApplyXform,
    &NtGdiXFORMOBJ_iGetXform,
    &NtGdiXLATEOBJ_cGetPalette,
    &NtGdiXLATEOBJ_hGetColorTransform,
    &NtGdiXLATEOBJ_iXlate,
    &NtHWCursorUpdatePointer,
    &NtIsOneCoreTransformMode,
    &NtMITActivateInputProcessing,
    &NtMITBindInputTypeToMonitors,
    &NtMITCoreMsgKGetConnectionHandle,
    &NtMITCoreMsgKOpenConnectionTo,
    &NtMITCoreMsgKSend,
    &NtMITDeactivateInputProcessing,
    &NtMITDisableMouseIntercept,
    &NtMITDispatchCompletion,
    &NtMITEnableMouseIntercept,
    &NtMITGetCursorUpdateHandle,
    &NtMITSetInputCallbacks,
    &NtMITSetInputDelegationMode,
    &NtMITSetInputSuppressionState,
    &NtMITSetKeyboardInputRoutingPolicy,
    &NtMITSetKeyboardOverriderState,
    &NtMITSetLastInputRecipient,
    &NtMITSynthesizeKeyboardInput,
    &NtMITSynthesizeMouseInput,
    &NtMITSynthesizeMouseWheel,
    &NtMITSynthesizeTouchInput,
    &NtMITUpdateInputGlobals,
    &NtMITWaitForMultipleObjectsEx,
    &NtMapVisualRelativePoints,
    &NtNotifyPresentToCompositionSurface,
    &NtOpenCompositionSurfaceDirtyRegion,
    &NtOpenCompositionSurfaceSectionInfo,
    &NtOpenCompositionSurfaceSwapChainHandleInfo,
    &NtQueryCompositionInputIsImplicit,
    &NtQueryCompositionInputQueueAndTransform,
    &NtQueryCompositionInputSink,
    &NtQueryCompositionInputSinkLuid,
    &NtQueryCompositionInputSinkViewId,
    &NtQueryCompositionSurfaceBinding,
    &NtQueryCompositionSurfaceHDRMetaData,
    &NtQueryCompositionSurfaceRenderingRealization,
    &NtQueryCompositionSurfaceStatistics,
    &NtRIMAddInputObserver,
    &NtRIMAreSiblingDevices,
    &NtRIMDeviceIoControl,
    &NtRIMEnableMonitorMappingForDevice,
    &NtRIMFreeInputBuffer,
    &NtRIMGetDevicePreparsedData,
    &NtRIMGetDevicePreparsedDataLockfree,
    &NtRIMGetDeviceProperties,
    &NtRIMGetDevicePropertiesLockfree,
    &NtRIMGetPhysicalDeviceRect,
    &NtRIMGetSourceProcessId,
    &NtRIMObserveNextInput,
    &NtRIMOnPnpNotification,
    &NtRIMOnTimerNotification,
    &NtRIMReadInput,
    &NtRIMRegisterForInput,
    &NtRIMRemoveInputObserver,
    &NtRIMSetExtendedDeviceProperty,
    &NtRIMSetTestModeStatus,
    &NtRIMUnregisterForInput,
    &NtRIMUpdateInputObserverRegistration,
    &NtSetCompositionSurfaceAnalogExclusive,
    &NtSetCompositionSurfaceBufferCompositionMode,
    &NtSetCompositionSurfaceBufferCompositionModeAndOrientation,
    &NtSetCompositionSurfaceBufferUsage,
    &NtSetCompositionSurfaceDirectFlipState,
    &NtSetCompositionSurfaceHDRMetaData,
    &NtSetCompositionSurfaceIndependentFlipInfo,
    &NtSetCompositionSurfaceOutOfFrameDirectFlipNotification,
    &NtSetCompositionSurfaceStatistics,
    &NtSetCursorInputSpace,
    &NtSetPointerDeviceInputSpace,
    &NtSetShellCursorState,
    &NtTokenManagerConfirmOutstandingAnalogToken,
    &NtTokenManagerCreateCompositionTokenHandle,
    &NtTokenManagerCreateFlipObjectReturnTokenHandle,
    &NtTokenManagerCreateFlipObjectTokenHandle,
    &NtTokenManagerDeleteOutstandingDirectFlipTokens,
    &NtTokenManagerGetAnalogExclusiveSurfaceUpdates,
    &NtTokenManagerGetAnalogExclusiveTokenEvent,
    &NtTokenManagerGetOutOfFrameDirectFlipSurfaceUpdates,
    &NtTokenManagerOpenEvent,
    &NtTokenManagerOpenSection,
    &NtTokenManagerOpenSectionAndEvents,
    &NtTokenManagerThread,
    &NtUnBindCompositionSurface,
    &NtUpdateInputSinkTransforms,
    &NtUserAcquireIAMKey,
    &NtUserAcquireInteractiveControlBackgroundAccess,
    &NtUserActivateKeyboardLayout,
    &NtUserAddClipboardFormatListener,
    &NtUserAddVisualIdentifier,
    &NtUserAlterWindowStyle,
    &NtUserAssociateInputContext,
    &NtUserAttachThreadInput,
    &NtUserAutoPromoteMouseInPointer,
    &NtUserAutoRotateScreen,
    &NtUserBeginLayoutUpdate,
    &NtUserBeginPaint,
    &NtUserBitBltSysBmp,
    &NtUserBlockInput,
    &NtUserBroadcastThemeChangeEvent,
    &NtUserBuildHimcList,
    &NtUserBuildHwndList,
    &NtUserBuildNameList,
    &NtUserBuildPropList,
    &NtUserCalcMenuBar,
    &NtUserCalculatePopupWindowPosition,
    &NtUserCallHwnd,
    &NtUserCallHwndLock,
    &NtUserCallHwndLockSafe,
    &NtUserCallHwndOpt,
    &NtUserCallHwndParam,
    &NtUserCallHwndParamLock,
    &NtUserCallHwndParamLockSafe,
    &NtUserCallHwndSafe,
    &NtUserCallMsgFilter,
    &NtUserCallNextHookEx,
    &NtUserCallNoParam,
    &NtUserCallOneParam,
    &NtUserCallTwoParam,
    &NtUserCanBrokerForceForeground,
    &NtUserChangeClipboardChain,
    &NtUserChangeDisplaySettings,
    &NtUserChangeWindowMessageFilterEx,
    &NtUserCheckAccessForIntegrityLevel,
    &NtUserCheckDesktopByThreadId,
    &NtUserCheckImeHotKey,
    &NtUserCheckMenuItem,
    &NtUserCheckProcessForClipboardAccess,
    &NtUserCheckProcessSession,
    &NtUserCheckWindowThreadDesktop,
    &NtUserChildWindowFromPointEx,
    &NtUserClearForeground,
    &NtUserClipCursor,
    &NtUserCloseClipboard,
    &NtUserCloseDesktop,
    &NtUserCloseWindowStation,
    &NtUserCompositionInputSinkLuidFromPoint,
    &NtUserCompositionInputSinkViewInstanceIdFromPoint,
    &NtUserConfigureActivationObject,
    &NtUserConfirmResizeCommit,
    &NtUserConsoleControl,
    &NtUserConvertMemHandle,
    &NtUserCopyAcceleratorTable,
    &NtUserCountClipboardFormats,
    &NtUserCreateAcceleratorTable,
    &NtUserCreateActivationObject,
    &NtUserCreateCaret,
    &NtUserCreateDCompositionHwndTarget,
    &NtUserCreateDesktop,
    &NtUserCreateDesktopEx,
    &NtUserCreateEmptyCursorObject,
    &NtUserCreateInputContext,
    &NtUserCreateLocalMemHandle,
    &NtUserCreatePalmRejectionDelayZone,
    &NtUserCreateWindowEx,
    &NtUserCreateWindowGroup,
    &NtUserCreateWindowStation,
    &NtUserCtxDisplayIOCtl,
    &NtUserDdeGetQualityOfService,
    &NtUserDdeInitialize,
    &NtUserDdeSetQualityOfService,
    &NtUserDefSetText,
    &NtUserDeferWindowDpiChanges,
    &NtUserDeferWindowPos,
    &NtUserDeferWindowPosAndBand,
    &NtUserDelegateCapturePointers,
    &NtUserDelegateInput,
    &NtUserDeleteMenu,
    &NtUserDeleteWindowGroup,
    &NtUserDestroyAcceleratorTable,
    &NtUserDestroyActivationObject,
    &NtUserDestroyCursor,
    &NtUserDestroyDCompositionHwndTarget,
    &NtUserDestroyInputContext,
    &NtUserDestroyMenu,
    &NtUserDestroyPalmRejectionDelayZone,
    &NtUserDestroyWindow,
    &NtUserDisableImmersiveOwner,
    &NtUserDisableProcessWindowFiltering,
    &NtUserDisableThreadIme,
    &NtUserDiscardPointerFrameMessages,
    &NtUserDispatchMessage,
    &NtUserDisplayConfigGetDeviceInfo,
    &NtUserDisplayConfigSetDeviceInfo,
    &NtUserDoSoundConnect,
    &NtUserDoSoundDisconnect,
    &NtUserDownlevelTouchpad,
    &NtUserDragDetect,
    &NtUserDragObject,
    &NtUserDrawAnimatedRects,
    &NtUserDrawCaption,
    &NtUserDrawCaptionTemp,
    &NtUserDrawIconEx,
    &NtUserDrawMenuBarTemp,
    &NtUserDwmGetDxRgn,
    &NtUserDwmGetRemoteSessionOcclusionEvent,
    &NtUserDwmGetRemoteSessionOcclusionState,
    &NtUserDwmHintDxUpdate,
    &NtUserDwmKernelShutdown,
    &NtUserDwmKernelStartup,
    &NtUserDwmStartRedirection,
    &NtUserDwmStopRedirection,
    &NtUserDwmValidateWindow,
    &NtUserEmptyClipboard,
    &NtUserEnableChildWindowDpiMessage,
    &NtUserEnableIAMAccess,
    &NtUserEnableMenuItem,
    &NtUserEnableMouseInPointer,
    &NtUserEnableMouseInputForCursorSuppression,
    &NtUserEnableNonClientDpiScaling,
    &NtUserEnableResizeLayoutSynchronization,
    &NtUserEnableScrollBar,
    &NtUserEnableSoftwareCursorForScreenCapture,
    &NtUserEnableTouchPad,
    &NtUserEnableWindowGDIScaledDpiMessage,
    &NtUserEnableWindowGroupPolicy,
    &NtUserEnableWindowResizeOptimization,
    &NtUserEndDeferWindowPosEx,
    &NtUserEndMenu,
    &NtUserEndPaint,
    &NtUserEndTouchOperation,
    &NtUserEnumDisplayDevices,
    &NtUserEnumDisplayMonitors,
    &NtUserEnumDisplaySettings,
    &NtUserEvent,
    &NtUserExcludeUpdateRgn,
    &NtUserFillWindow,
    &NtUserFindExistingCursorIcon,
    &NtUserFindWindowEx,
    &NtUserFlashWindowEx,
    &NtUserForceWindowToDpiForTest,
    &NtUserFrostCrashedWindow,
    &NtUserFunctionalizeDisplayConfig,
    &NtUserGetActiveProcessesDpis,
    &NtUserGetAltTabInfo,
    &NtUserGetAncestor,
    &NtUserGetAppImeLevel,
    &NtUserGetAsyncKeyState,
    &NtUserGetAtomName,
    &NtUserGetAutoRotationState,
    &NtUserGetCIMSSM,
    &NtUserGetCPD,
    &NtUserGetCaretBlinkTime,
    &NtUserGetCaretPos,
    &NtUserGetClassInfoEx,
    &NtUserGetClassName,
    &NtUserGetClipCursor,
    &NtUserGetClipboardAccessToken,
    &NtUserGetClipboardData,
    &NtUserGetClipboardFormatName,
    &NtUserGetClipboardOwner,
    &NtUserGetClipboardSequenceNumber,
    &NtUserGetClipboardViewer,
    &NtUserGetComboBoxInfo,
    &NtUserGetControlBrush,
    &NtUserGetControlColor,
    &NtUserGetCurrentDpiInfoForWindow,
    &NtUserGetCurrentInputMessageSource,
    &NtUserGetCursor,
    &NtUserGetCursorDims,
    &NtUserGetCursorFrameInfo,
    &NtUserGetCursorInfo,
    &NtUserGetDC,
    &NtUserGetDCEx,
    &NtUserGetDManipHookInitFunction,
    &NtUserGetDesktopID,
    &NtUserGetDisplayAutoRotationPreferences,
    &NtUserGetDisplayAutoRotationPreferencesByProcessId,
    &NtUserGetDisplayConfigBufferSizes,
    &NtUserGetDoubleClickTime,
    &NtUserGetDpiForCurrentProcess,
    &NtUserGetDpiForMonitor,
    &NtUserGetDpiSystemMetrics,
    &NtUserGetExtendedPointerDeviceProperty,
    &NtUserGetForegroundWindow,
    &NtUserGetGUIThreadInfo,
    &NtUserGetGestureConfig,
    &NtUserGetGestureExtArgs,
    &NtUserGetGestureInfo,
    &NtUserGetGlobalIMEStatus,
    &NtUserGetGuiResources,
    &NtUserGetHDevName,
    &NtUserGetHimetricScaleFactorFromPixelLocation,
    &NtUserGetIconInfo,
    &NtUserGetIconSize,
    &NtUserGetImeHotKey,
    &NtUserGetImeInfoEx,
    &NtUserGetInputContainerId,
    &NtUserGetInputLocaleInfo,
    &NtUserGetInteractiveControlDeviceInfo,
    &NtUserGetInteractiveControlInfo,
    &NtUserGetInteractiveCtrlSupportedWaveforms,
    &NtUserGetInternalWindowPos,
    &NtUserGetKeyNameText,
    &NtUserGetKeyState,
    &NtUserGetKeyboardLayout,
    &NtUserGetKeyboardLayoutList,
    &NtUserGetKeyboardLayoutName,
    &NtUserGetKeyboardState,
    &NtUserGetLayeredWindowAttributes,
    &NtUserGetListBoxInfo,
    &NtUserGetMenuBarInfo,
    &NtUserGetMenuIndex,
    &NtUserGetMenuItemRect,
    &NtUserGetMessage,
    &NtUserGetMonitorBrightness,
    &NtUserGetMouseMovePointsEx,
    &NtUserGetObjectInformation,
    &NtUserGetOemBitmapSize,
    &NtUserGetOpenClipboardWindow,
    &NtUserGetOwnerTransformedMonitorRect,
    &NtUserGetPhysicalDeviceRect,
    &NtUserGetPointerCursorId,
    &NtUserGetPointerDevice,
    &NtUserGetPointerDeviceCursors,
    &NtUserGetPointerDeviceOrientation,
    &NtUserGetPointerDeviceProperties,
    &NtUserGetPointerDeviceRects,
    &NtUserGetPointerDevices,
    &NtUserGetPointerFrameArrivalTimes,
    &NtUserGetPointerFrameTimes,
    &NtUserGetPointerInfoList,
    &NtUserGetPointerInputTransform,
    &NtUserGetPointerProprietaryId,
    &NtUserGetPointerType,
    &NtUserGetPrecisionTouchPadConfiguration,
    &NtUserGetPriorityClipboardFormat,
    &NtUserGetProcessDpiAwareness,
    &NtUserGetProcessDpiAwarenessContext,
    &NtUserGetProcessUIContextInformation,
    &NtUserGetProcessWindowStation,
    &NtUserGetProp,
    &NtUserGetQueueEventStatus,
    &NtUserGetQueueStatusReadonly,
    &NtUserGetRawInputBuffer,
    &NtUserGetRawInputData,
    &NtUserGetRawInputDeviceInfo,
    &NtUserGetRawInputDeviceList,
    &NtUserGetRawPointerDeviceData,
    &NtUserGetRegisteredRawInputDevices,
    &NtUserGetRequiredCursorSizes,
    &NtUserGetResizeDCompositionSynchronizationObject,
    &NtUserGetScrollBarInfo,
    &NtUserGetSystemDpiForProcess,
    &NtUserGetSystemMenu,
    &NtUserGetThreadDesktop,
    &NtUserGetThreadState,
    &NtUserGetTitleBarInfo,
    &NtUserGetTopLevelWindow,
    &NtUserGetTouchInputInfo,
    &NtUserGetTouchValidationStatus,
    &NtUserGetUniformSpaceMapping,
    &NtUserGetUpdateRect,
    &NtUserGetUpdateRgn,
    &NtUserGetUpdatedClipboardFormats,
    &NtUserGetWOWClass,
    &NtUserGetWindowBand,
    &NtUserGetWindowCompositionAttribute,
    &NtUserGetWindowCompositionInfo,
    &NtUserGetWindowDC,
    &NtUserGetWindowDisplayAffinity,
    &NtUserGetWindowFeedbackSetting,
    &NtUserGetWindowGroupId,
    &NtUserGetWindowMinimizeRect,
    &NtUserGetWindowPlacement,
    &NtUserGetWindowProcessHandle,
    &NtUserGetWindowRgnEx,
    &NtUserGhostWindowFromHungWindow,
    &NtUserHandleDelegatedInput,
    &NtUserHardErrorControl,
    &NtUserHideCaret,
    &NtUserHidePointerContactVisualization,
    &NtUserHiliteMenuItem,
    &NtUserHungWindowFromGhostWindow,
    &NtUserHwndQueryRedirectionInfo,
    &NtUserHwndSetRedirectionInfo,
    &NtUserImpersonateDdeClientWindow,
    &NtUserInheritWindowMonitor,
    &NtUserInitTask,
    &NtUserInitialize,
    &NtUserInitializeClientPfnArrays,
    &NtUserInitializeGenericHidInjection,
    &NtUserInitializeInputDeviceInjection,
    &NtUserInitializePointerDeviceInjection,
    &NtUserInitializePointerDeviceInjectionEx,
    &NtUserInitializeTouchInjection,
    &NtUserInjectDeviceInput,
    &NtUserInjectGenericHidInput,
    &NtUserInjectGesture,
    &NtUserInjectKeyboardInput,
    &NtUserInjectMouseInput,
    &NtUserInjectPointerInput,
    &NtUserInjectTouchInput,
    &NtUserInteractiveControlQueryUsage,
    &NtUserInternalClipCursor,
    &NtUserInternalGetWindowIcon,
    &NtUserInternalGetWindowText,
    &NtUserInvalidateRect,
    &NtUserInvalidateRgn,
    &NtUserIsChildWindowDpiMessageEnabled,
    &NtUserIsClipboardFormatAvailable,
    &NtUserIsMouseInPointerEnabled,
    &NtUserIsMouseInputEnabled,
    &NtUserIsNonClientDpiScalingEnabled,
    &NtUserIsResizeLayoutSynchronizationEnabled,
    &NtUserIsTopLevelWindow,
    &NtUserIsTouchWindow,
    &NtUserIsWindowBroadcastingDpiToChildren,
    &NtUserIsWindowGDIScaledDpiMessageEnabled,
    &NtUserKillTimer,
    &NtUserLayoutCompleted,
    &NtUserLinkDpiCursor,
    &NtUserLoadKeyboardLayoutEx,
    &NtUserLockCursor,
    &NtUserLockWindowStation,
    &NtUserLockWindowUpdate,
    &NtUserLockWorkStation,
    &NtUserLogicalToPerMonitorDPIPhysicalPoint,
    &NtUserLogicalToPhysicalDpiPointForWindow,
    &NtUserLogicalToPhysicalPoint,
    &NtUserMNDragLeave,
    &NtUserMNDragOver,
    &NtUserMagControl,
    &NtUserMagGetContextInformation,
    &NtUserMagSetContextInformation,
    &NtUserManageGestureHandlerWindow,
    &NtUserMapPointsByVisualIdentifier,
    &NtUserMapVirtualKeyEx,
    &NtUserMenuItemFromPoint,
    &NtUserMessageCall,
    &NtUserMinMaximize,
    &NtUserModifyUserStartupInfoFlags,
    &NtUserModifyWindowTouchCapability,
    &NtUserMoveWindow,
    &NtUserMsgWaitForMultipleObjectsEx,
    &NtUserNavigateFocus,
    &NtUserNotifyIMEStatus,
    &NtUserNotifyProcessCreate,
    &NtUserNotifyWinEvent,
    &NtUserOpenClipboard,
    &NtUserOpenDesktop,
    &NtUserOpenInputDesktop,
    &NtUserOpenThreadDesktop,
    &NtUserOpenWindowStation,
    &NtUserPaintDesktop,
    &NtUserPaintMenuBar,
    &NtUserPaintMonitor,
    &NtUserPeekMessage,
    &NtUserPerMonitorDPIPhysicalToLogicalPoint,
    &NtUserPhysicalToLogicalDpiPointForWindow,
    &NtUserPhysicalToLogicalPoint,
    &NtUserPostMessage,
    &NtUserPostThreadMessage,
    &NtUserPrintWindow,
    &NtUserProcessConnect,
    &NtUserProcessInkFeedbackCommand,
    &NtUserPromoteMouseInPointer,
    &NtUserPromotePointer,
    &NtUserQueryActivationObject,
    &NtUserQueryBSDRWindow,
    &NtUserQueryDisplayConfig,
    &NtUserQueryInformationThread,
    &NtUserQueryInputContext,
    &NtUserQuerySendMessage,
    &NtUserQueryWindow,
    &NtUserRealChildWindowFromPoint,
    &NtUserRealInternalGetMessage,
    &NtUserRealWaitMessageEx,
    &NtUserRedrawWindow,
    &NtUserRegisterBSDRWindow,
    &NtUserRegisterClassExWOW,
    &NtUserRegisterDManipHook,
    &NtUserRegisterEdgy,
    &NtUserRegisterErrorReportingDialog,
    &NtUserRegisterHotKey,
    &NtUserRegisterManipulationThread,
    &NtUserRegisterPointerDeviceNotifications,
    &NtUserRegisterPointerInputTarget,
    &NtUserRegisterRawInputDevices,
    &NtUserRegisterServicesProcess,
    &NtUserRegisterSessionPort,
    &NtUserRegisterShellPTPListener,
    &NtUserRegisterTasklist,
    &NtUserRegisterTouchHitTestingWindow,
    &NtUserRegisterTouchPadCapable,
    &NtUserRegisterUserApiHook,
    &NtUserRegisterWindowMessage,
    &NtUserReleaseDC,
    &NtUserReleaseDwmHitTestWaiters,
    &NtUserRemoteConnect,
    &NtUserRemoteRedrawRectangle,
    &NtUserRemoteRedrawScreen,
    &NtUserRemoteStopScreenUpdates,
    &NtUserRemoveClipboardFormatListener,
    &NtUserRemoveInjectionDevice,
    &NtUserRemoveMenu,
    &NtUserRemoveProp,
    &NtUserRemoveVisualIdentifier,
    &NtUserReportInertia,
    &NtUserRequestMoveSizeOperation,
    &NtUserResolveDesktop,
    &NtUserResolveDesktopForWOW,
    &NtUserRestoreWindowDpiChanges,
    &NtUserSBGetParms,
    &NtUserScrollDC,
    &NtUserScrollWindowEx,
    &NtUserSelectPalette,
    &NtUserSendEventMessage,
    &NtUserSendInput,
    &NtUserSendInteractiveControlHapticsReport,
    &NtUserSendTouchInput,
    &NtUserSetActivationFilter,
    &NtUserSetActiveProcess,
    &NtUserSetActiveProcessForMonitor,
    &NtUserSetActiveWindow,
    &NtUserSetAppImeLevel,
    &NtUserSetAutoRotation,
    &NtUserSetBridgeWindowChild,
    &NtUserSetBrokeredForeground,
    &NtUserSetCalibrationData,
    &NtUserSetCapture,
    &NtUserSetChildWindowNoActivate,
    &NtUserSetClassLong,
    &NtUserSetClassLongPtr,
    &NtUserSetClassWord,
    &NtUserSetClipboardData,
    &NtUserSetClipboardViewer,
    &NtUserSetConsoleReserveKeys,
    &NtUserSetCoreWindow,
    &NtUserSetCoreWindowPartner,
    &NtUserSetCursor,
    &NtUserSetCursorContents,
    &NtUserSetCursorIconData,
    &NtUserSetCursorPos,
    &NtUserSetDesktopColorTransform,
    &NtUserSetDialogControlDpiChangeBehavior,
    &NtUserSetDimUndimTransitionTime,
    &NtUserSetDisplayAutoRotationPreferences,
    &NtUserSetDisplayConfig,
    &NtUserSetDisplayMapping,
    &NtUserSetFallbackForeground,
    &NtUserSetFeatureReportResponse,
    &NtUserSetFocus,
    &NtUserSetForegroundWindowForApplication,
    &NtUserSetGestureConfig,
    &NtUserSetImeHotKey,
    &NtUserSetImeInfoEx,
    &NtUserSetImeOwnerWindow,
    &NtUserSetImmersiveBackgroundWindow,
    &NtUserSetInformationProcess,
    &NtUserSetInformationThread,
    &NtUserSetInteractiveControlFocus,
    &NtUserSetInteractiveCtrlRotationAngle,
    &NtUserSetInternalWindowPos,
    &NtUserSetKeyboardState,
    &NtUserSetLayeredWindowAttributes,
    &NtUserSetLogonNotifyWindow,
    &NtUserSetMagnificationDesktopMagnifierOffsetsDWMUpdated,
    &NtUserSetManipulationInputTarget,
    &NtUserSetMenu,
    &NtUserSetMenuContextHelpId,
    &NtUserSetMenuDefaultItem,
    &NtUserSetMenuFlagRtoL,
    &NtUserSetMirrorRendering,
    &NtUserSetMonitorBrightness,
    &NtUserSetObjectInformation,
    &NtUserSetParent,
    &NtUserSetPrecisionTouchPadConfiguration,
    &NtUserSetProcessDPIAware,
    &NtUserSetProcessDpiAwareness,
    &NtUserSetProcessDpiAwarenessContext,
    &NtUserSetProcessInteractionFlags,
    &NtUserSetProcessMousewheelRoutingMode,
    &NtUserSetProcessRestrictionExemption,
    &NtUserSetProcessUIAccessZorder,
    &NtUserSetProcessWindowStation,
    &NtUserSetProp,
    &NtUserSetScrollInfo,
    &NtUserSetSensorPresence,
    &NtUserSetShellWindowEx,
    &NtUserSetSysColors,
    &NtUserSetSystemCursor,
    &NtUserSetSystemMenu,
    &NtUserSetSystemTimer,
    &NtUserSetTargetForResourceBrokering,
    &NtUserSetThreadDesktop,
    &NtUserSetThreadInputBlocked,
    &NtUserSetThreadLayoutHandles,
    &NtUserSetThreadState,
    &NtUserSetTimer,
    &NtUserSetWinEventHook,
    &NtUserSetWindowArrangement,
    &NtUserSetWindowBand,
    &NtUserSetWindowCompositionAttribute,
    &NtUserSetWindowCompositionTransition,
    &NtUserSetWindowDisplayAffinity,
    &NtUserSetWindowFNID,
    &NtUserSetWindowFeedbackSetting,
    &NtUserSetWindowGroup,
    &NtUserSetWindowLong,
    &NtUserSetWindowLongPtr,
    &NtUserSetWindowPlacement,
    &NtUserSetWindowPos,
    &NtUserSetWindowRgn,
    &NtUserSetWindowRgnEx,
    &NtUserSetWindowShowState,
    &NtUserSetWindowStationUser,
    &NtUserSetWindowWord,
    &NtUserSetWindowsHookAW,
    &NtUserSetWindowsHookEx,
    &NtUserSfmDestroyLogicalSurfaceBinding,
    &NtUserSfmDxBindSwapChain,
    &NtUserSfmDxGetSwapChainStats,
    &NtUserSfmDxOpenSwapChain,
    &NtUserSfmDxQuerySwapChainBindingStatus,
    &NtUserSfmDxReleaseSwapChain,
    &NtUserSfmDxReportPendingBindingsToDwm,
    &NtUserSfmDxSetSwapChainBindingStatus,
    &NtUserSfmDxSetSwapChainStats,
    &NtUserSfmGetLogicalSurfaceBinding,
    &NtUserShowCaret,
    &NtUserShowCursor,
    &NtUserShowScrollBar,
    &NtUserShowSystemCursor,
    &NtUserShowWindow,
    &NtUserShowWindowAsync,
    &NtUserShutdownBlockReasonCreate,
    &NtUserShutdownBlockReasonQuery,
    &NtUserShutdownReasonDestroy,
    &NtUserSignalRedirectionStartComplete,
    &NtUserSlicerControl,
    &NtUserSoundSentry,
    &NtUserStopAndEndInertia,
    &NtUserSwitchDesktop,
    &NtUserSystemParametersInfo,
    &NtUserSystemParametersInfoForDpi,
    &NtUserTestForInteractiveUser,
    &NtUserThunkedMenuInfo,
    &NtUserThunkedMenuItemInfo,
    &NtUserToUnicodeEx,
    &NtUserTrackMouseEvent,
    &NtUserTrackPopupMenuEx,
    &NtUserTransformPoint,
    &NtUserTransformRect,
    &NtUserTranslateAccelerator,
    &NtUserTranslateMessage,
    &NtUserUndelegateInput,
    &NtUserUnhookWinEvent,
    &NtUserUnhookWindowsHookEx,
    &NtUserUnloadKeyboardLayout,
    &NtUserUnlockWindowStation,
    &NtUserUnregisterClass,
    &NtUserUnregisterHotKey,
    &NtUserUnregisterSessionPort,
    &NtUserUnregisterUserApiHook,
    &NtUserUpdateDefaultDesktopThumbnail,
    &NtUserUpdateInputContext,
    &NtUserUpdateInstance,
    &NtUserUpdateLayeredWindow,
    &NtUserUpdatePerUserSystemParameters,
    &NtUserUpdateWindowInputSinkHints,
    &NtUserUpdateWindowTrackingInfo,
    &NtUserUpdateWindowTransform,
    &NtUserUserHandleGrantAccess,
    &NtUserValidateHandleSecure,
    &NtUserValidateRect,
    &NtUserValidateTimerCallback,
    &NtUserVkKeyScanEx,
    &NtUserWOWCleanup,
    &NtUserWaitAvailableMessageEx,
    &NtUserWaitForInputIdle,
    &NtUserWaitForMsgAndEvent,
    &NtUserWaitForRedirectionStartComplete,
    &NtUserWaitMessage,
    &NtUserWin32PoolAllocationStats,
    &NtUserWindowFromDC,
    &NtUserWindowFromPhysicalPoint,
    &NtUserWindowFromPoint,
    &NtUserYieldTask,
    &NtValidateCompositionSurfaceHandle,
    &NtVisualCaptureBits,
};

#define NUM_SYSCALLS_NT sizeof(nt)/sizeof(syscall_t*)
#define NUM_SYSCALLS_WIN32K sizeof(win32k)/sizeof(syscall_t*)

}

#endif
