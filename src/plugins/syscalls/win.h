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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"

SYSCALL(NtAcceptConnectPort, NTSTATUS, 6,
		"PortHandle", "", DIR_OUT, PHANDLE,
		"PortContext", "opt", DIR_IN, PVOID,
		"ConnectionRequest", "", DIR_IN, PPORT_MESSAGE,
		"AcceptConnection", "", DIR_IN, BOOLEAN,
		"ServerView", "opt", DIR_INOUT, PPORT_VIEW,
		"ClientView", "opt", DIR_OUT, PREMOTE_PORT_VIEW,
);
SYSCALL(NtAccessCheckAndAuditAlarm, NTSTATUS, 11,
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
SYSCALL(NtAccessCheckByTypeAndAuditAlarm, NTSTATUS, 16,
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
SYSCALL(NtAccessCheckByType, NTSTATUS, 11,
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
SYSCALL(NtAccessCheckByTypeResultListAndAuditAlarmByHandle, NTSTATUS, 17,
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
SYSCALL(NtAccessCheckByTypeResultListAndAuditAlarm, NTSTATUS, 16,
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
SYSCALL(NtAccessCheckByTypeResultList, NTSTATUS, 11,
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
SYSCALL(NtAccessCheck, NTSTATUS, 8,
		"SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR,
		"ClientToken", "", DIR_IN, HANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"GenericMapping", "", DIR_IN, PGENERIC_MAPPING,
		"PrivilegeSet", "bcount(*PrivilegeSetLength)", DIR_OUT, PPRIVILEGE_SET,
		"PrivilegeSetLength", "", DIR_INOUT, PULONG,
		"GrantedAccess", "", DIR_OUT, PACCESS_MASK,
		"AccessStatus", "", DIR_OUT, PNTSTATUS,
);
SYSCALL(NtAddAtom, NTSTATUS, 3,
		"AtomName", "bcount_opt(Length)", DIR_IN, PWSTR,
		"Length", "", DIR_IN, ULONG,
		"Atom", "opt", DIR_OUT, PRTL_ATOM,
);
SYSCALL(NtAddBootEntry, NTSTATUS, 2,
		"BootEntry", "", DIR_IN, PBOOT_ENTRY,
		"Id", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAddDriverEntry, NTSTATUS, 2,
		"DriverEntry", "", DIR_IN, PEFI_DRIVER_ENTRY,
		"Id", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAdjustGroupsToken, NTSTATUS, 6,
		"TokenHandle", "", DIR_IN, HANDLE,
		"ResetToDefault", "", DIR_IN, BOOLEAN,
		"NewState", "", DIR_IN, PTOKEN_GROUPS,
		"BufferLength", "", DIR_IN, ULONG,
		"PreviousState", "bcount_part_opt(BufferLength,*ReturnLength)", DIR_OUT, PTOKEN_GROUPS,
		"ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtAdjustPrivilegesToken, NTSTATUS, 6,
		"TokenHandle", "", DIR_IN, HANDLE,
		"DisableAllPrivileges", "", DIR_IN, BOOLEAN,
		"NewState", "opt", DIR_IN, PTOKEN_PRIVILEGES,
		"BufferLength", "", DIR_IN, ULONG,
		"PreviousState", "bcount_part_opt(BufferLength,*ReturnLength)", DIR_OUT, PTOKEN_PRIVILEGES,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAlertResumeThread, NTSTATUS, 2,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"PreviousSuspendCount", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAlertThread, NTSTATUS, 1,
		"ThreadHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtAllocateLocallyUniqueId, NTSTATUS, 1,
		"Luid", "", DIR_OUT, PLUID,
);
SYSCALL(NtAllocateReserveObject, NTSTATUS, 3,
		"MemoryReserveHandle", "", DIR_OUT, PHANDLE,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"Type", "", DIR_IN, MEMORY_RESERVE_TYPE,
);
SYSCALL(NtAllocateUserPhysicalPages, NTSTATUS, 3,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"NumberOfPages", "", DIR_INOUT, PULONG_PTR,
		"UserPfnArra;", "ecount(*NumberOfPages)", DIR_OUT, PULONG_PTR,
);
SYSCALL(NtAllocateUuids, NTSTATUS, 4,
		"Time", "", DIR_OUT, PULARGE_INTEGER,
		"Range", "", DIR_OUT, PULONG,
		"Sequence", "", DIR_OUT, PULONG,
		"Seed", "", DIR_OUT, PCHAR,
);
SYSCALL(NtAllocateVirtualMemory, NTSTATUS, 6,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"*BaseAddress", "", DIR_INOUT, PVOID,
		"ZeroBits", "", DIR_IN, ULONG_PTR,
		"RegionSize", "", DIR_INOUT, PSIZE_T,
		"AllocationType", "", DIR_IN, ULONG,
		"Protect", "", DIR_IN, ULONG,
);
SYSCALL(NtAlpcAcceptConnectPort, NTSTATUS, 9,
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
SYSCALL(NtAlpcCancelMessage, NTSTATUS, 3,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_IN, ULONG,
		"MessageContext", "", DIR_IN, PALPC_CONTEXT_ATTR,
);
SYSCALL(NtAlpcConnectPort, NTSTATUS, 11,
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
SYSCALL(NtAlpcCreatePort, NTSTATUS, 3,
		"PortHandle", "", DIR_OUT, PHANDLE,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"PortAttributes", "opt", DIR_IN, PALPC_PORT_ATTRIBUTES,
);
SYSCALL(NtAlpcCreatePortSection, NTSTATUS, 6,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_IN, ULONG,
		"SectionHandle", "opt", DIR_IN, HANDLE,
		"SectionSize", "", DIR_IN, SIZE_T,
		"AlpcSectionHandle", "", DIR_OUT, PALPC_HANDLE,
		"ActualSectionSize", "", DIR_OUT, PSIZE_T,
);
SYSCALL(NtAlpcCreateResourceReserve, NTSTATUS, 4,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_RESERVED, ULONG,
		"MessageSize", "", DIR_IN, SIZE_T,
		"ResourceId", "", DIR_OUT, PALPC_HANDLE,
);
SYSCALL(NtAlpcCreateSectionView, NTSTATUS, 3,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_RESERVED, ULONG,
		"ViewAttributes", "", DIR_INOUT, PALPC_DATA_VIEW_ATTR,
);
SYSCALL(NtAlpcCreateSecurityContext, NTSTATUS, 3,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_RESERVED, ULONG,
		"SecurityAttribute", "", DIR_INOUT, PALPC_SECURITY_ATTR,
);
SYSCALL(NtAlpcDeletePortSection, NTSTATUS, 3,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_RESERVED, ULONG,
		"SectionHandle", "", DIR_IN, ALPC_HANDLE,
);
SYSCALL(NtAlpcDeleteResourceReserve, NTSTATUS, 3,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_RESERVED, ULONG,
		"ResourceId", "", DIR_IN, ALPC_HANDLE,
);
SYSCALL(NtAlpcDeleteSectionView, NTSTATUS, 3,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_RESERVED, ULONG,
		"ViewBase", "", DIR_IN, PVOID,
);
SYSCALL(NtAlpcDeleteSecurityContext, NTSTATUS, 3,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_RESERVED, ULONG,
		"ContextHandle", "", DIR_IN, ALPC_HANDLE,
);
SYSCALL(NtAlpcDisconnectPort, NTSTATUS, 2,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtAlpcImpersonateClientOfPort, NTSTATUS, 3,
		"PortHandle", "", DIR_IN, HANDLE,
		"PortMessage", "", DIR_IN, PPORT_MESSAGE,
		"Reserved", "", DIR_RESERVED, PVOID,
);
SYSCALL(NtAlpcOpenSenderProcess, NTSTATUS, 6,
		"ProcessHandle", "", DIR_OUT, PHANDLE,
		"PortHandle", "", DIR_IN, HANDLE,
		"PortMessage", "", DIR_IN, PPORT_MESSAGE,
		"Flags", "", DIR_RESERVED, ULONG,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtAlpcOpenSenderThread, NTSTATUS, 6,
		"ThreadHandle", "", DIR_OUT, PHANDLE,
		"PortHandle", "", DIR_IN, HANDLE,
		"PortMessage", "", DIR_IN, PPORT_MESSAGE,
		"Flags", "", DIR_RESERVED, ULONG,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtAlpcQueryInformation, NTSTATUS, 5,
		"PortHandle", "", DIR_IN, HANDLE,
		"PortInformationClass", "", DIR_IN, ALPC_PORT_INFORMATION_CLASS,
		"PortInformation", "bcount(Length)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAlpcQueryInformationMessage, NTSTATUS, 6,
		"PortHandle", "", DIR_IN, HANDLE,
		"PortMessage", "", DIR_IN, PPORT_MESSAGE,
		"MessageInformationClass", "", DIR_IN, ALPC_MESSAGE_INFORMATION_CLASS,
		"MessageInformation", "bcount(Length)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtAlpcRevokeSecurityContext, NTSTATUS, 3,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_RESERVED, ULONG,
		"ContextHandle", "", DIR_IN, ALPC_HANDLE,
);
SYSCALL(NtAlpcSendWaitReceivePort, NTSTATUS, 8,
		"PortHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_IN, ULONG,
		"SendMessage", "opt", DIR_IN, PPORT_MESSAGE,
		"SendMessageAttributes", "opt", DIR_IN, PALPC_MESSAGE_ATTRIBUTES,
		"ReceiveMessage", "opt", DIR_INOUT, PPORT_MESSAGE,
		"BufferLength", "opt", DIR_INOUT, PULONG,
		"ReceiveMessageAttributes", "opt", DIR_INOUT, PALPC_MESSAGE_ATTRIBUTES,
		"Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtAlpcSetInformation, NTSTATUS, 4,
		"PortHandle", "", DIR_IN, HANDLE,
		"PortInformationClass", "", DIR_IN, ALPC_PORT_INFORMATION_CLASS,
		"PortInformation", "bcount(Length)", DIR_IN, PVOID,
		"Length", "", DIR_IN, ULONG,
);
SYSCALL(NtApphelpCacheControl, NTSTATUS, 2,
		"type", "", DIR_IN, APPHELPCOMMAND,
		"buf", "", DIR_IN, PVOID,
);
SYSCALL(NtAreMappedFilesTheSame, NTSTATUS, 2,
		"File1MappedAsAnImage", "", DIR_IN, PVOID,
		"File2MappedAsFile", "", DIR_IN, PVOID,
);
SYSCALL(NtAssignProcessToJobObject, NTSTATUS, 2,
		"JobHandle", "", DIR_IN, HANDLE,
		"ProcessHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtCallbackReturn, NTSTATUS, 3,
		"OutputBuffer", "opt", DIR_IN, PVOID,
		"OutputLength", "", DIR_IN, ULONG,
		"Status", "", DIR_IN, NTSTATUS,
);
SYSCALL(NtCancelIoFileEx, NTSTATUS, 3,
		"FileHandle", "", DIR_IN, HANDLE,
		"IoRequestToCancel", "opt", DIR_IN, PIO_STATUS_BLOCK,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
);
SYSCALL(NtCancelIoFile, NTSTATUS, 2,
		"FileHandle", "", DIR_IN, HANDLE,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
);
SYSCALL(NtCancelSynchronousIoFile, NTSTATUS, 3,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"IoRequestToCancel", "opt", DIR_IN, PIO_STATUS_BLOCK,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
);
SYSCALL(NtCancelTimer, NTSTATUS, 2,
		"TimerHandle", "", DIR_IN, HANDLE,
		"CurrentState", "opt", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtClearEvent, NTSTATUS, 1,
		"EventHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtClose, NTSTATUS, 1,
		"Handle", "", DIR_IN, HANDLE,
);
SYSCALL(NtCloseObjectAuditAlarm, NTSTATUS, 3,
		"SubsystemName", "", DIR_IN, PUNICODE_STRING,
		"HandleId", "opt", DIR_IN, PVOID,
		"GenerateOnClose", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCommitComplete, NTSTATUS, 2,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtCommitEnlistment, NTSTATUS, 2,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtCommitTransaction, NTSTATUS, 2,
		"TransactionHandle", "", DIR_IN, HANDLE,
		"Wait", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCompactKeys, NTSTATUS, 2,
		"Count", "", DIR_IN, ULONG,
		"KeyArray[;", "ecount(Count)", DIR_IN, HANDLE,
);
SYSCALL(NtCompareTokens, NTSTATUS, 3,
		"FirstTokenHandle", "", DIR_IN, HANDLE,
		"SecondTokenHandle", "", DIR_IN, HANDLE,
		"Equal", "", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtCompleteConnectPort, NTSTATUS, 1,
		"PortHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtCompressKey, NTSTATUS, 1,
		"Key", "", DIR_IN, HANDLE,
);
SYSCALL(NtConnectPort, NTSTATUS, 8,
		"PortHandle", "", DIR_OUT, PHANDLE,
		"PortName", "", DIR_IN, PUNICODE_STRING,
		"SecurityQos", "", DIR_IN, PSECURITY_QUALITY_OF_SERVICE,
		"ClientView", "opt", DIR_INOUT, PPORT_VIEW,
		"ServerView", "opt", DIR_INOUT, PREMOTE_PORT_VIEW,
		"MaxMessageLength", "opt", DIR_OUT, PULONG,
		"ConnectionInformation", "opt", DIR_INOUT, PVOID,
		"ConnectionInformationLength", "opt", DIR_INOUT, PULONG,
);
SYSCALL(NtContinue, NTSTATUS, 2,
		"ContextRecord", "", DIR_IN, PCONTEXT,
		"TestAlert", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCreateDebugObject, NTSTATUS, 4,
		"DebugObjectHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_OUT, ACCESS_MASK,
		"ObjectAttributes", "", DIR_OUT, POBJECT_ATTRIBUTES,
		"Flags", "", DIR_OUT, ULONG,
);
SYSCALL(NtCreateDirectoryObject, NTSTATUS, 3,
		"DirectoryHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtCreateEnlistment, NTSTATUS, 8,
		"EnlistmentHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ResourceManagerHandle", "", DIR_IN, HANDLE,
		"TransactionHandle", "", DIR_IN, HANDLE,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"CreateOptions", "opt", DIR_IN, ULONG,
		"NotificationMask", "", DIR_IN, NOTIFICATION_MASK,
		"EnlistmentKey", "opt", DIR_IN, PVOID,
);
SYSCALL(NtCreateEvent, NTSTATUS, 5,
		"EventHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"EventType", "", DIR_IN, EVENT_TYPE,
		"InitialState", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCreateEventPair, NTSTATUS, 3,
		"EventPairHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtCreateFile, NTSTATUS, 11,
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
SYSCALL(NtCreateIoCompletion, NTSTATUS, 4,
		"IoCompletionHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"Count", "", DIR_IN, ULONG,
);
SYSCALL(NtCreateJobObject, NTSTATUS, 3,
		"JobHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtCreateJobSet, NTSTATUS, 3,
		"NumJob", "", DIR_IN, ULONG,
		"UserJobSet", "ecount(NumJob)", DIR_IN, PJOB_SET_ARRAY,
		"Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtCreateKeyedEvent, NTSTATUS, 4,
		"KeyedEventHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtCreateKey, NTSTATUS, 7,
		"KeyHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"TitleIndex", "", DIR_RESERVED, ULONG,
		"Class", "opt", DIR_IN, PUNICODE_STRING,
		"CreateOptions", "", DIR_IN, ULONG,
		"Disposition", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtCreateKeyTransacted, NTSTATUS, 8,
		"KeyHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"TitleIndex", "", DIR_RESERVED, ULONG,
		"Class", "opt", DIR_IN, PUNICODE_STRING,
		"CreateOptions", "", DIR_IN, ULONG,
		"TransactionHandle", "", DIR_IN, HANDLE,
		"Disposition", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtCreateMailslotFile, NTSTATUS, 8,
		"FileHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ULONG,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
		"CreateOptions", "", DIR_IN, ULONG,
		"MailslotQuota", "", DIR_IN, ULONG,
		"MaximumMessageSize", "", DIR_IN, ULONG,
		"ReadTimeout", "", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtCreateMutant, NTSTATUS, 4,
		"MutantHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"InitialOwner", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCreateNamedPipeFile, NTSTATUS, 14,
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
SYSCALL(NtCreatePagingFile, NTSTATUS, 4,
		"PageFileName", "", DIR_IN, PUNICODE_STRING,
		"MinimumSize", "", DIR_IN, PLARGE_INTEGER,
		"MaximumSize", "", DIR_IN, PLARGE_INTEGER,
		"Priority", "", DIR_IN, ULONG,
);
SYSCALL(NtCreatePort, NTSTATUS, 5,
		"PortHandle", "", DIR_OUT, PHANDLE,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"MaxConnectionInfoLength", "", DIR_IN, ULONG,
		"MaxMessageLength", "", DIR_IN, ULONG,
		"MaxPoolUsage", "opt", DIR_IN, ULONG,
);
SYSCALL(NtCreatePrivateNamespace, NTSTATUS, 4,
		"NamespaceHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"BoundaryDescriptor", "", DIR_IN, PVOID,
);
SYSCALL(NtCreateProcessEx, NTSTATUS, 9,
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
SYSCALL(NtCreateProcess, NTSTATUS, 8,
		"ProcessHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"ParentProcess", "", DIR_IN, HANDLE,
		"InheritObjectTable", "", DIR_IN, BOOLEAN,
		"SectionHandle", "opt", DIR_IN, HANDLE,
		"DebugPort", "opt", DIR_IN, HANDLE,
		"ExceptionPort", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtCreateProfileEx, NTSTATUS, 10,
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
SYSCALL(NtCreateProfile, NTSTATUS, 9,
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
SYSCALL(NtCreateResourceManager, NTSTATUS, 7,
		"ResourceManagerHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"TmHandle", "", DIR_IN, HANDLE,
		"RmGuid", "", DIR_IN, LPGUID,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"CreateOptions", "opt", DIR_IN, ULONG,
		"Description", "opt", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtCreateSection, NTSTATUS, 7,
		"SectionHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"MaximumSize", "opt", DIR_IN, PLARGE_INTEGER,
		"SectionPageProtection", "", DIR_IN, ULONG,
		"AllocationAttributes", "", DIR_IN, ULONG,
		"FileHandle", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtCreateSemaphore, NTSTATUS, 5,
		"SemaphoreHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"InitialCount", "", DIR_IN, LONG,
		"MaximumCount", "", DIR_IN, LONG,
);
SYSCALL(NtCreateSymbolicLinkObject, NTSTATUS, 4,
		"LinkHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"LinkTarget", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtCreateThreadEx, NTSTATUS, 11,
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
SYSCALL(NtCreateThread, NTSTATUS, 8,
		"ThreadHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"ClientId", "", DIR_OUT, PCLIENT_ID,
		"ThreadContext", "", DIR_IN, PCONTEXT,
		"InitialTeb", "", DIR_IN, PINITIAL_TEB,
		"CreateSuspended", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtCreateTimer, NTSTATUS, 4,
		"TimerHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"TimerType", "", DIR_IN, TIMER_TYPE,
);
SYSCALL(NtCreateToken, NTSTATUS, 13,
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
SYSCALL(NtCreateTransactionManager, NTSTATUS, 6,
		"TmHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"LogFileName", "opt", DIR_IN, PUNICODE_STRING,
		"CreateOptions", "opt", DIR_IN, ULONG,
		"CommitStrength", "opt", DIR_IN, ULONG,
);
SYSCALL(NtCreateTransaction, NTSTATUS, 10,
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
SYSCALL(NtCreateUserProcess, NTSTATUS, 11,
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
SYSCALL(NtCreateWaitablePort, NTSTATUS, 5,
		"PortHandle", "", DIR_OUT, PHANDLE,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"MaxConnectionInfoLength", "", DIR_IN, ULONG,
		"MaxMessageLength", "", DIR_IN, ULONG,
		"MaxPoolUsage", "opt", DIR_IN, ULONG,
);
SYSCALL(NtCreateWorkerFactory, NTSTATUS, 10,
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
SYSCALL(NtDebugActiveProcess, NTSTATUS, 2,
		"ProcessHandle", "", DIR_OUT, HANDLE,
		"DebugObjectHandle", "", DIR_OUT, HANDLE,
);
SYSCALL(NtDebugContinue, NTSTATUS, 3,
		"DebugObjectHandle", "", DIR_OUT, HANDLE,
		"ClientId", "", DIR_OUT, PCLIENT_ID,
		"ContinueStatus", "", DIR_OUT, NTSTATUS,
);
SYSCALL(NtDelayExecution, NTSTATUS, 2,
		"Alertable", "", DIR_IN, BOOLEAN,
		"DelayInterval", "", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtDeleteAtom, NTSTATUS, 1,
		"Atom", "", DIR_IN, RTL_ATOM,
);
SYSCALL(NtDeleteBootEntry, NTSTATUS, 1,
		"Id", "", DIR_IN, ULONG,
);
SYSCALL(NtDeleteDriverEntry, NTSTATUS, 1,
		"Id", "", DIR_IN, ULONG,
);
SYSCALL(NtDeleteFile, NTSTATUS, 1,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtDeleteKey, NTSTATUS, 1,
		"KeyHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtDeleteObjectAuditAlarm, NTSTATUS, 3,
		"SubsystemName", "", DIR_IN, PUNICODE_STRING,
		"HandleId", "opt", DIR_IN, PVOID,
		"GenerateOnClose", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtDeletePrivateNamespace, NTSTATUS, 1,
		"NamespaceHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtDeleteValueKey, NTSTATUS, 2,
		"KeyHandle", "", DIR_IN, HANDLE,
		"ValueName", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtDeviceIoControlFile, NTSTATUS, 10,
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
SYSCALL(NtDisplayString, NTSTATUS, 1,
		"String", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtDrawText, NTSTATUS, 1,
		"Text", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtDuplicateObject, NTSTATUS, 7,
		"SourceProcessHandle", "", DIR_IN, HANDLE,
		"SourceHandle", "", DIR_IN, HANDLE,
		"TargetProcessHandle", "opt", DIR_IN, HANDLE,
		"TargetHandle", "opt", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"HandleAttributes", "", DIR_IN, ULONG,
		"Options", "", DIR_IN, ULONG,
);
SYSCALL(NtDuplicateToken, NTSTATUS, 6,
		"ExistingTokenHandle", "", DIR_IN, HANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"EffectiveOnly", "", DIR_IN, BOOLEAN,
		"TokenType", "", DIR_IN, TOKEN_TYPE,
		"NewTokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtEnumerateBootEntries, NTSTATUS, 2,
		"Buffer", "bcount_opt(*BufferLength)", DIR_OUT, PVOID,
		"BufferLength", "", DIR_INOUT, PULONG,
);
SYSCALL(NtEnumerateDriverEntries, NTSTATUS, 2,
		"Buffer", "bcount(*BufferLength)", DIR_OUT, PVOID,
		"BufferLength", "", DIR_INOUT, PULONG,
);
SYSCALL(NtEnumerateKey, NTSTATUS, 6,
		"KeyHandle", "", DIR_IN, HANDLE,
		"Index", "", DIR_IN, ULONG,
		"KeyInformationClass", "", DIR_IN, KEY_INFORMATION_CLASS,
		"KeyInformation", "bcount_opt(Length)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"ResultLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtEnumerateSystemEnvironmentValuesEx, NTSTATUS, 3,
		"InformationClass", "", DIR_IN, ULONG,
		"Buffer", "", DIR_OUT, PVOID,
		"BufferLength", "", DIR_INOUT, PULONG,
);
SYSCALL(NtEnumerateTransactionObject, NTSTATUS, 5,
		"RootObjectHandle", "opt", DIR_IN, HANDLE,
		"QueryType", "", DIR_IN, KTMOBJECT_TYPE,
		"ObjectCursor", "bcount(ObjectCursorLength)", DIR_INOUT, PKTMOBJECT_CURSOR,
		"ObjectCursorLength", "", DIR_IN, ULONG,
		"ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtEnumerateValueKey, NTSTATUS, 6,
		"KeyHandle", "", DIR_IN, HANDLE,
		"Index", "", DIR_IN, ULONG,
		"KeyValueInformationClass", "", DIR_IN, KEY_VALUE_INFORMATION_CLASS,
		"KeyValueInformation", "bcount_opt(Length)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"ResultLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtExtendSection, NTSTATUS, 2,
		"SectionHandle", "", DIR_IN, HANDLE,
		"NewSectionSize", "", DIR_INOUT, PLARGE_INTEGER,
);
SYSCALL(NtFilterToken, NTSTATUS, 6,
		"ExistingTokenHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_IN, ULONG,
		"SidsToDisable", "opt", DIR_IN, PTOKEN_GROUPS,
		"PrivilegesToDelete", "opt", DIR_IN, PTOKEN_PRIVILEGES,
		"RestrictedSids", "opt", DIR_IN, PTOKEN_GROUPS,
		"NewTokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtFindAtom, NTSTATUS, 3,
		"AtomName", "bcount_opt(Length)", DIR_IN, PWSTR,
		"Length", "", DIR_IN, ULONG,
		"Atom", "opt", DIR_OUT, PRTL_ATOM,
);
SYSCALL(NtFlushBuffersFile, NTSTATUS, 2,
		"FileHandle", "", DIR_IN, HANDLE,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
);
SYSCALL(NtFlushInstallUILanguage, NTSTATUS, 2,
		"InstallUILanguage", "", DIR_IN, LANGID,
		"SetComittedFlag", "", DIR_IN, ULONG,
);
SYSCALL(NtFlushInstructionCache, NTSTATUS, 3,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"BaseAddress", "opt", DIR_IN, PVOID,
		"Length", "", DIR_IN, SIZE_T,
);
SYSCALL(NtFlushKey, NTSTATUS, 1,
		"KeyHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtFlushVirtualMemory, NTSTATUS, 4,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"*BaseAddress", "", DIR_INOUT, PVOID,
		"RegionSize", "", DIR_INOUT, PSIZE_T,
		"IoStatus", "", DIR_OUT, PIO_STATUS_BLOCK,
);
SYSCALL(NtFreeUserPhysicalPages, NTSTATUS, 3,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"NumberOfPages", "", DIR_INOUT, PULONG_PTR,
		"UserPfnArra;", "ecount(*NumberOfPages)", DIR_IN, PULONG_PTR,
);
SYSCALL(NtFreeVirtualMemory, NTSTATUS, 4,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"*BaseAddress", "", DIR_INOUT, PVOID,
		"RegionSize", "", DIR_INOUT, PSIZE_T,
		"FreeType", "", DIR_IN, ULONG,
);
SYSCALL(NtFreezeRegistry, NTSTATUS, 1,
		"TimeOutInSeconds", "", DIR_IN, ULONG,
);
SYSCALL(NtFreezeTransactions, NTSTATUS, 2,
		"FreezeTimeout", "", DIR_IN, PLARGE_INTEGER,
		"ThawTimeout", "", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtFsControlFile, NTSTATUS, 10,
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
SYSCALL(NtGetContextThread, NTSTATUS, 2,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"ThreadContext", "", DIR_INOUT, PCONTEXT,
);
SYSCALL(NtGetDevicePowerState, NTSTATUS, 2,
		"Device", "", DIR_IN, HANDLE,
		"*State", "", DIR_OUT, DEVICE_POWER_STATE,
);
SYSCALL(NtGetMUIRegistryInfo, NTSTATUS, 3,
		"Flags", "", DIR_IN, ULONG,
		"DataSize", "", DIR_INOUT, PULONG,
		"Data", "", DIR_OUT, PVOID,
);
SYSCALL(NtGetNextProcess, NTSTATUS, 5,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"HandleAttributes", "", DIR_IN, ULONG,
		"Flags", "", DIR_IN, ULONG,
		"NewProcessHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtGetNextThread, NTSTATUS, 6,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"HandleAttributes", "", DIR_IN, ULONG,
		"Flags", "", DIR_IN, ULONG,
		"NewThreadHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtGetNlsSectionPtr, NTSTATUS, 5,
		"SectionType", "", DIR_IN, ULONG,
		"SectionData", "", DIR_IN, ULONG,
		"ContextData", "", DIR_IN, PVOID,
		"*SectionPointer", "", DIR_OUT, PVOID,
		"SectionSize", "", DIR_OUT, PULONG,
);
SYSCALL(NtGetNotificationResourceManager, NTSTATUS, 7,
		"ResourceManagerHandle", "", DIR_IN, HANDLE,
		"TransactionNotification", "", DIR_OUT, PTRANSACTION_NOTIFICATION,
		"NotificationLength", "", DIR_IN, ULONG,
		"Timeout", "opt", DIR_IN, PLARGE_INTEGER,
		"ReturnLength", "opt", DIR_OUT, PULONG,
		"Asynchronous", "", DIR_IN, ULONG,
		"AsynchronousContext", "opt", DIR_IN, ULONG_PTR,
);
SYSCALL(NtGetPlugPlayEvent, NTSTATUS, 4,
		"EventHandle", "", DIR_IN, HANDLE,
		"Context", "opt", DIR_IN, PVOID,
		"EventBlock", "bcount(EventBufferSize)", DIR_OUT, PPLUGPLAY_EVENT_BLOCK,
		"EventBufferSize", "", DIR_IN, ULONG,
);
SYSCALL(NtGetWriteWatch, NTSTATUS, 7,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_IN, ULONG,
		"BaseAddress", "", DIR_IN, PVOID,
		"RegionSize", "", DIR_IN, SIZE_T,
		"*UserAddressArray", "ecount(*EntriesInUserAddressArray)", DIR_OUT, PVOID,
		"EntriesInUserAddressArray", "", DIR_INOUT, PULONG_PTR,
		"Granularity", "", DIR_OUT, PULONG,
);
SYSCALL(NtImpersonateAnonymousToken, NTSTATUS, 1,
		"ThreadHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtImpersonateClientOfPort, NTSTATUS, 2,
		"PortHandle", "", DIR_IN, HANDLE,
		"Message", "", DIR_IN, PPORT_MESSAGE,
);
SYSCALL(NtImpersonateThread, NTSTATUS, 3,
		"ServerThreadHandle", "", DIR_IN, HANDLE,
		"ClientThreadHandle", "", DIR_IN, HANDLE,
		"SecurityQos", "", DIR_IN, PSECURITY_QUALITY_OF_SERVICE,
);
SYSCALL(NtInitializeNlsFiles, NTSTATUS, 3,
		"*BaseAddress", "", DIR_OUT, PVOID,
		"DefaultLocaleId", "", DIR_OUT, PLCID,
		"DefaultCasingTableSize", "", DIR_OUT, PLARGE_INTEGER,
);
SYSCALL(NtInitializeRegistry, NTSTATUS, 1,
		"BootCondition", "", DIR_IN, USHORT,
);
SYSCALL(NtInitiatePowerAction, NTSTATUS, 4,
		"SystemAction", "", DIR_IN, POWER_ACTION,
		"MinSystemState", "", DIR_IN, SYSTEM_POWER_STATE,
		"Flags", "", DIR_IN, ULONG,
		"Asynchronous", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtIsProcessInJob, NTSTATUS, 2,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"JobHandle", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtListenPort, NTSTATUS, 2,
		"PortHandle", "", DIR_IN, HANDLE,
		"ConnectionRequest", "", DIR_OUT, PPORT_MESSAGE,
);
SYSCALL(NtLoadDriver, NTSTATUS, 1,
		"DriverServiceName", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtLoadKey2, NTSTATUS, 3,
		"TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
		"SourceFile", "", DIR_IN, POBJECT_ATTRIBUTES,
		"Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtLoadKeyEx, NTSTATUS, 4,
		"TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
		"SourceFile", "", DIR_IN, POBJECT_ATTRIBUTES,
		"Flags", "", DIR_IN, ULONG,
		"TrustClassKey", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtLoadKey, NTSTATUS, 2,
		"TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
		"SourceFile", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtLockFile, NTSTATUS, 10,
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
SYSCALL(NtLockProductActivationKeys, NTSTATUS, 2,
		"*pPrivateVer", "opt", DIR_INOUT, ULONG,
		"*pSafeMode", "opt", DIR_OUT, ULONG,
);
SYSCALL(NtLockRegistryKey, NTSTATUS, 1,
		"KeyHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtLockVirtualMemory, NTSTATUS, 4,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"*BaseAddress", "", DIR_INOUT, PVOID,
		"RegionSize", "", DIR_INOUT, PSIZE_T,
		"MapType", "", DIR_IN, ULONG,
);
SYSCALL(NtMakePermanentObject, NTSTATUS, 1,
		"Handle", "", DIR_IN, HANDLE,
);
SYSCALL(NtMakeTemporaryObject, NTSTATUS, 1,
		"Handle", "", DIR_IN, HANDLE,
);
SYSCALL(NtMapCMFModule, NTSTATUS, 6,
		"What", "", DIR_IN, ULONG,
		"Index", "", DIR_IN, ULONG,
		"CacheIndexOut", "opt", DIR_OUT, PULONG,
		"CacheFlagsOut", "opt", DIR_OUT, PULONG,
		"ViewSizeOut", "opt", DIR_OUT, PULONG,
		"*BaseAddress", "opt", DIR_OUT, PVOID,
);
SYSCALL(NtMapUserPhysicalPages, NTSTATUS, 3,
		"VirtualAddress", "", DIR_IN, PVOID,
		"NumberOfPages", "", DIR_IN, ULONG_PTR,
		"UserPfnArra;", "ecount_opt(NumberOfPages)", DIR_IN, PULONG_PTR,
);
SYSCALL(NtMapUserPhysicalPagesScatter, NTSTATUS, 3,
		"*VirtualAddresses", "ecount(NumberOfPages)", DIR_IN, PVOID,
		"NumberOfPages", "", DIR_IN, ULONG_PTR,
		"UserPfnArray", "ecount_opt(NumberOfPages)", DIR_IN, PULONG_PTR,
);
SYSCALL(NtMapViewOfSection, NTSTATUS, 10,
		"SectionHandle", "", DIR_IN, HANDLE,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"*BaseAddress", "", DIR_INOUT, PVOID,
		"ZeroBits", "", DIR_IN, ULONG_PTR,
		"CommitSize", "", DIR_IN, SIZE_T,
		"SectionOffset", "opt", DIR_INOUT, PLARGE_INTEGER,
		"ViewSize", "", DIR_INOUT, PSIZE_T,
		"InheritDisposition", "", DIR_IN, SECTION_INHERIT,
		"AllocationType", "", DIR_IN, ULONG,
		"Win32Protect", "", DIR_IN, WIN32_PROTECTION_MASK,
);
SYSCALL(NtModifyBootEntry, NTSTATUS, 1,
		"BootEntry", "", DIR_IN, PBOOT_ENTRY,
);
SYSCALL(NtModifyDriverEntry, NTSTATUS, 1,
		"DriverEntry", "", DIR_IN, PEFI_DRIVER_ENTRY,
);
SYSCALL(NtNotifyChangeDirectoryFile, NTSTATUS, 9,
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
SYSCALL(NtNotifyChangeKey, NTSTATUS, 10,
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
SYSCALL(NtNotifyChangeMultipleKeys, NTSTATUS, 12,
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
SYSCALL(NtNotifyChangeSession, NTSTATUS, 8,
		"Session", "", DIR_IN, HANDLE,
		"IoStateSequence", "", DIR_IN, ULONG,
		"Reserved", "", DIR_IN, PVOID,
		"Action", "", DIR_IN, ULONG,
		"IoState", "", DIR_IN,  IO_SESSION_STATE,
		"IoState2", "", DIR_IN,  IO_SESSION_STATE,
		"Buffer", "", DIR_IN, PVOID,
		"BufferSize", "", DIR_IN, ULONG,
);
SYSCALL(NtOpenDirectoryObject, NTSTATUS, 3,
		"DirectoryHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenEnlistment, NTSTATUS, 5,
		"EnlistmentHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ResourceManagerHandle", "", DIR_IN, HANDLE,
		"EnlistmentGuid", "", DIR_IN, LPGUID,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenEvent, NTSTATUS, 3,
		"EventHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenEventPair, NTSTATUS, 3,
		"EventPairHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenFile, NTSTATUS, 6,
		"FileHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
		"ShareAccess", "", DIR_IN, ULONG,
		"OpenOptions", "", DIR_IN, ULONG,
);
SYSCALL(NtOpenIoCompletion, NTSTATUS, 3,
		"IoCompletionHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenJobObject, NTSTATUS, 3,
		"JobHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenKeyedEvent, NTSTATUS, 3,
		"KeyedEventHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenKeyEx, NTSTATUS, 4,
		"KeyHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"OpenOptions", "", DIR_IN, ULONG,
);
SYSCALL(NtOpenKey, NTSTATUS, 3,
		"KeyHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenKeyTransactedEx, NTSTATUS, 5,
		"KeyHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"OpenOptions", "", DIR_IN, ULONG,
		"TransactionHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtOpenKeyTransacted, NTSTATUS, 4,
		"KeyHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"TransactionHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtOpenMutant, NTSTATUS, 3,
		"MutantHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenObjectAuditAlarm, NTSTATUS, 12,
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
SYSCALL(NtOpenPrivateNamespace, NTSTATUS, 4,
		"NamespaceHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"BoundaryDescriptor", "", DIR_IN, PVOID,
);
SYSCALL(NtOpenProcess, NTSTATUS, 4,
		"ProcessHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"ClientId", "opt", DIR_IN, PCLIENT_ID,
);
SYSCALL(NtOpenProcessTokenEx, NTSTATUS, 4,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"HandleAttributes", "", DIR_IN, ULONG,
		"TokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtOpenProcessToken, NTSTATUS, 3,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"TokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtOpenResourceManager, NTSTATUS, 5,
		"ResourceManagerHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"TmHandle", "", DIR_IN, HANDLE,
		"ResourceManagerGuid", "opt", DIR_IN, LPGUID,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenSection, NTSTATUS, 3,
		"SectionHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenSemaphore, NTSTATUS, 3,
		"SemaphoreHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenSession, NTSTATUS, 3,
		"SessionHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenSymbolicLinkObject, NTSTATUS, 3,
		"LinkHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenThread, NTSTATUS, 4,
		"ThreadHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"ClientId", "opt", DIR_IN, PCLIENT_ID,
);
SYSCALL(NtOpenThreadTokenEx, NTSTATUS, 5,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"OpenAsSelf", "", DIR_IN, BOOLEAN,
		"HandleAttributes", "", DIR_IN, ULONG,
		"TokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtOpenThreadToken, NTSTATUS, 4,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"OpenAsSelf", "", DIR_IN, BOOLEAN,
		"TokenHandle", "", DIR_OUT, PHANDLE,
);
SYSCALL(NtOpenTimer, NTSTATUS, 3,
		"TimerHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtOpenTransactionManager, NTSTATUS, 6,
		"TmHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES,
		"LogFileName", "opt", DIR_IN, PUNICODE_STRING,
		"TmIdentity", "opt", DIR_IN, LPGUID,
		"OpenOptions", "opt", DIR_IN, ULONG,
);
SYSCALL(NtOpenTransaction, NTSTATUS, 5,
		"TransactionHandle", "", DIR_OUT, PHANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"Uow", "", DIR_IN, LPGUID,
		"TmHandle", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtPlugPlayControl, NTSTATUS, 3,
		"PnPControlClass", "", DIR_IN, PLUGPLAY_CONTROL_CLASS,
		"PnPControlData", "bcount(PnPControlDataLength)", DIR_INOUT, PVOID,
		"PnPControlDataLength", "", DIR_IN, ULONG,
);
SYSCALL(NtPowerInformation, NTSTATUS, 5,
		"InformationLevel", "", DIR_IN, POWER_INFORMATION_LEVEL,
		"InputBuffer", "bcount_opt(InputBufferLength)", DIR_IN, PVOID,
		"InputBufferLength", "", DIR_IN, ULONG,
		"OutputBuffer", "bcount_opt(OutputBufferLength)", DIR_OUT, PVOID,
		"OutputBufferLength", "", DIR_IN, ULONG,
);
SYSCALL(NtPrepareComplete, NTSTATUS, 2,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtPrepareEnlistment, NTSTATUS, 2,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtPrePrepareComplete, NTSTATUS, 2,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtPrePrepareEnlistment, NTSTATUS, 2,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtPrivilegeCheck, NTSTATUS, 3,
		"ClientToken", "", DIR_IN, HANDLE,
		"RequiredPrivileges", "", DIR_INOUT, PPRIVILEGE_SET,
		"Result", "", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtPrivilegedServiceAuditAlarm, NTSTATUS, 5,
		"SubsystemName", "", DIR_IN, PUNICODE_STRING,
		"ServiceName", "", DIR_IN, PUNICODE_STRING,
		"ClientToken", "", DIR_IN, HANDLE,
		"Privileges", "", DIR_IN, PPRIVILEGE_SET,
		"AccessGranted", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtPrivilegeObjectAuditAlarm, NTSTATUS, 6,
		"SubsystemName", "", DIR_IN, PUNICODE_STRING,
		"HandleId", "opt", DIR_IN, PVOID,
		"ClientToken", "", DIR_IN, HANDLE,
		"DesiredAccess", "", DIR_IN, ACCESS_MASK,
		"Privileges", "", DIR_IN, PPRIVILEGE_SET,
		"AccessGranted", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtPropagationComplete, NTSTATUS, 4,
		"ResourceManagerHandle", "", DIR_IN, HANDLE,
		"RequestCookie", "", DIR_IN, ULONG,
		"BufferLength", "", DIR_IN, ULONG,
		"Buffer", "", DIR_IN, PVOID,
);
SYSCALL(NtPropagationFailed, NTSTATUS, 3,
		"ResourceManagerHandle", "", DIR_IN, HANDLE,
		"RequestCookie", "", DIR_IN, ULONG,
		"PropStatus", "", DIR_IN, NTSTATUS,
);
SYSCALL(NtProtectVirtualMemory, NTSTATUS, 5,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"*BaseAddress", "", DIR_INOUT, PVOID,
		"RegionSize", "", DIR_INOUT, PSIZE_T,
		"NewProtectWin32", "", DIR_IN, WIN32_PROTECTION_MASK,
		"OldProtect", "", DIR_OUT, PULONG,
);
SYSCALL(NtPulseEvent, NTSTATUS, 2,
		"EventHandle", "", DIR_IN, HANDLE,
		"PreviousState", "opt", DIR_OUT, PLONG,
);
SYSCALL(NtQueryAttributesFile, NTSTATUS, 2,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"FileInformation", "", DIR_OUT, PFILE_BASIC_INFORMATION,
);
SYSCALL(NtQueryBootEntryOrder, NTSTATUS, 2,
		"Ids", "ecount_opt(*Count)", DIR_OUT, PULONG,
		"Count", "", DIR_INOUT, PULONG,
);
SYSCALL(NtQueryBootOptions, NTSTATUS, 2,
		"BootOptions", "bcount_opt(*BootOptionsLength)", DIR_OUT, PBOOT_OPTIONS,
		"BootOptionsLength", "", DIR_INOUT, PULONG,
);
SYSCALL(NtQueryDebugFilterState, NTSTATUS, 2,
		"ComponentId", "", DIR_IN, ULONG,
		"Level", "", DIR_IN, ULONG,
);
SYSCALL(NtQueryDefaultLocale, NTSTATUS, 2,
		"UserProfile", "", DIR_IN, BOOLEAN,
		"DefaultLocaleId", "", DIR_OUT, PLCID,
);
SYSCALL(NtQueryDefaultUILanguage, NTSTATUS, 1,
		"*DefaultUILanguageId", "", DIR_OUT, LANGID,
);
SYSCALL(NtQueryDirectoryFile, NTSTATUS, 11,
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
SYSCALL(NtQueryDirectoryObject, NTSTATUS, 7,
		"DirectoryHandle", "", DIR_IN, HANDLE,
		"Buffer", "bcount_opt(Length)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"ReturnSingleEntry", "", DIR_IN, BOOLEAN,
		"RestartScan", "", DIR_IN, BOOLEAN,
		"Context", "", DIR_INOUT, PULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryDriverEntryOrder, NTSTATUS, 2,
		"Ids", "ecount(*Count)", DIR_OUT, PULONG,
		"Count", "", DIR_INOUT, PULONG,
);
SYSCALL(NtQueryEaFile, NTSTATUS, 9,
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
SYSCALL(NtQueryEvent, NTSTATUS, 5,
		"EventHandle", "", DIR_IN, HANDLE,
		"EventInformationClass", "", DIR_IN, EVENT_INFORMATION_CLASS,
		"EventInformation", "bcount(EventInformationLength)", DIR_OUT, PVOID,
		"EventInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryFullAttributesFile, NTSTATUS, 2,
		"ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES,
		"FileInformation", "", DIR_OUT, PFILE_NETWORK_OPEN_INFORMATION,
);
SYSCALL(NtQueryInformationAtom, NTSTATUS, 5,
		"Atom", "", DIR_IN, RTL_ATOM,
		"InformationClass", "", DIR_IN, ATOM_INFORMATION_CLASS,
		"AtomInformation", "bcount(AtomInformationLength)", DIR_OUT, PVOID,
		"AtomInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationEnlistment, NTSTATUS, 5,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"EnlistmentInformationClass", "", DIR_IN, ENLISTMENT_INFORMATION_CLASS,
		"EnlistmentInformation", "bcount(EnlistmentInformationLength)", DIR_OUT, PVOID,
		"EnlistmentInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationFile, NTSTATUS, 5,
		"FileHandle", "", DIR_IN, HANDLE,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
		"FileInformation", "bcount(Length)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"FileInformationClass", "", DIR_IN, FILE_INFORMATION_CLASS,
);
SYSCALL(NtQueryInformationJobObject, NTSTATUS, 5,
		"JobHandle", "opt", DIR_IN, HANDLE,
		"JobObjectInformationClass", "", DIR_IN, JOBOBJECTINFOCLASS,
		"JobObjectInformation", "bcount(JobObjectInformationLength)", DIR_OUT, PVOID,
		"JobObjectInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationPort, NTSTATUS, 5,
		"PortHandle", "", DIR_IN, HANDLE,
		"PortInformationClass", "", DIR_IN, PORT_INFORMATION_CLASS,
		"PortInformation", "bcount(Length)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationProcess, NTSTATUS, 5,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"ProcessInformationClass", "", DIR_IN, PROCESSINFOCLASS,
		"ProcessInformation", "bcount(ProcessInformationLength)", DIR_OUT, PVOID,
		"ProcessInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationResourceManager, NTSTATUS, 5,
		"ResourceManagerHandle", "", DIR_IN, HANDLE,
		"ResourceManagerInformationClass", "", DIR_IN, RESOURCEMANAGER_INFORMATION_CLASS,
		"ResourceManagerInformation", "bcount(ResourceManagerInformationLength)", DIR_OUT, PVOID,
		"ResourceManagerInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationThread, NTSTATUS, 5,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"ThreadInformationClass", "", DIR_IN, THREADINFOCLASS,
		"ThreadInformation", "bcount(ThreadInformationLength)", DIR_OUT, PVOID,
		"ThreadInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationToken, NTSTATUS, 5,
		"TokenHandle", "", DIR_IN, HANDLE,
		"TokenInformationClass", "", DIR_IN, TOKEN_INFORMATION_CLASS,
		"TokenInformation", "bcount_part_opt(TokenInformationLength,*ReturnLength)", DIR_OUT, PVOID,
		"TokenInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationTransaction, NTSTATUS, 5,
		"TransactionHandle", "", DIR_IN, HANDLE,
		"TransactionInformationClass", "", DIR_IN, TRANSACTION_INFORMATION_CLASS,
		"TransactionInformation", "bcount(TransactionInformationLength)", DIR_OUT, PVOID,
		"TransactionInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationTransactionManager, NTSTATUS, 5,
		"TransactionManagerHandle", "", DIR_IN, HANDLE,
		"TransactionManagerInformationClass", "", DIR_IN, TRANSACTIONMANAGER_INFORMATION_CLASS,
		"TransactionManagerInformation", "bcount(TransactionManagerInformationLength)", DIR_OUT, PVOID,
		"TransactionManagerInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInformationWorkerFactory, NTSTATUS, 5,
		"WorkerFactoryHandle", "", DIR_IN, HANDLE,
		"WorkerFactoryInformationClass", "", DIR_IN, WORKERFACTORYINFOCLASS,
		"WorkerFactoryInformation", "bcount(WorkerFactoryInformationLength)", DIR_OUT, PVOID,
		"WorkerFactoryInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryInstallUILanguage, NTSTATUS, 1,
		"*InstallUILanguageId", "", DIR_OUT, LANGID,
);
SYSCALL(NtQueryIntervalProfile, NTSTATUS, 2,
		"ProfileSource", "", DIR_IN, KPROFILE_SOURCE,
		"Interval", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryIoCompletion, NTSTATUS, 5,
		"IoCompletionHandle", "", DIR_IN, HANDLE,
		"IoCompletionInformationClass", "", DIR_IN, IO_COMPLETION_INFORMATION_CLASS,
		"IoCompletionInformation", "bcount(IoCompletionInformationLength)", DIR_OUT, PVOID,
		"IoCompletionInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryKey, NTSTATUS, 5,
		"KeyHandle", "", DIR_IN, HANDLE,
		"KeyInformationClass", "", DIR_IN, KEY_INFORMATION_CLASS,
		"KeyInformation", "bcount_opt(Length)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"ResultLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryLicenseValue, NTSTATUS, 5,
		"Name", "", DIR_IN, PUNICODE_STRING,
		"Type", "opt", DIR_OUT, PULONG,
		"Buffer", "bcount(ReturnedLength)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"ReturnedLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryMultipleValueKey, NTSTATUS, 6,
		"KeyHandle", "", DIR_IN, HANDLE,
		"ValueEntries", "ecount(EntryCount)", DIR_INOUT, PKEY_VALUE_ENTRY,
		"EntryCount", "", DIR_IN, ULONG,
		"ValueBuffer", "bcount(*BufferLength)", DIR_OUT, PVOID,
		"BufferLength", "", DIR_INOUT, PULONG,
		"RequiredBufferLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryMutant, NTSTATUS, 5,
		"MutantHandle", "", DIR_IN, HANDLE,
		"MutantInformationClass", "", DIR_IN, MUTANT_INFORMATION_CLASS,
		"MutantInformation", "bcount(MutantInformationLength)", DIR_OUT, PVOID,
		"MutantInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryObject, NTSTATUS, 5,
		"Handle", "", DIR_IN, HANDLE,
		"ObjectInformationClass", "", DIR_IN, OBJECT_INFORMATION_CLASS,
		"ObjectInformation", "bcount_opt(ObjectInformationLength)", DIR_OUT, PVOID,
		"ObjectInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryOpenSubKeysEx, NTSTATUS, 4,
		"TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
		"BufferLength", "", DIR_IN, ULONG,
		"Buffer", "bcount(BufferLength)", DIR_OUT, PVOID,
		"RequiredSize", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryOpenSubKeys, NTSTATUS, 2,
		"TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
		"HandleCount", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryPerformanceCounter, NTSTATUS, 2,
		"PerformanceCounter", "", DIR_OUT, PLARGE_INTEGER,
		"PerformanceFrequency", "opt", DIR_OUT, PLARGE_INTEGER,
);
SYSCALL(NtQueryQuotaInformationFile, NTSTATUS, 9,
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
SYSCALL(NtQuerySection, NTSTATUS, 5,
		"SectionHandle", "", DIR_IN, HANDLE,
		"SectionInformationClass", "", DIR_IN, SECTION_INFORMATION_CLASS,
		"SectionInformation", "bcount(SectionInformationLength)", DIR_OUT, PVOID,
		"SectionInformationLength", "", DIR_IN, SIZE_T,
		"ReturnLength", "opt", DIR_OUT, PSIZE_T,
);
SYSCALL(NtQuerySecurityAttributesToken, NTSTATUS, 6,
		"TokenHandle", "", DIR_IN, HANDLE,
		"Attributes", "ecount_opt(NumberOfAttributes)", DIR_IN, PUNICODE_STRING,
		"NumberOfAttributes", "", DIR_IN, ULONG,
		"Buffer", "bcount(Length)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySecurityObject, NTSTATUS, 5,
		"Handle", "", DIR_IN, HANDLE,
		"SecurityInformation", "", DIR_IN, SECURITY_INFORMATION,
		"SecurityDescriptor", "bcount_opt(Length)", DIR_OUT, PSECURITY_DESCRIPTOR,
		"Length", "", DIR_IN, ULONG,
		"LengthNeeded", "", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySemaphore, NTSTATUS, 5,
		"SemaphoreHandle", "", DIR_IN, HANDLE,
		"SemaphoreInformationClass", "", DIR_IN, SEMAPHORE_INFORMATION_CLASS,
		"SemaphoreInformation", "bcount(SemaphoreInformationLength)", DIR_OUT, PVOID,
		"SemaphoreInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySymbolicLinkObject, NTSTATUS, 3,
		"LinkHandle", "", DIR_IN, HANDLE,
		"LinkTarget", "", DIR_INOUT, PUNICODE_STRING,
		"ReturnedLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySystemEnvironmentValueEx, NTSTATUS, 5,
		"VariableName", "", DIR_IN, PUNICODE_STRING,
		"VendorGuid", "", DIR_IN, LPGUID,
		"Value", "bcount_opt(*ValueLength)", DIR_OUT, PVOID,
		"ValueLength", "", DIR_INOUT, PULONG,
		"Attributes", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySystemEnvironmentValue, NTSTATUS, 4,
		"VariableName", "", DIR_IN, PUNICODE_STRING,
		"VariableValue", "bcount(ValueLength)", DIR_OUT, PWSTR,
		"ValueLength", "", DIR_IN, USHORT,
		"ReturnLength", "opt", DIR_OUT, PUSHORT,
);
SYSCALL(NtQuerySystemInformationEx, NTSTATUS, 6,
		"SystemInformationClass", "", DIR_IN, SYSTEM_INFORMATION_CLASS,
		"QueryInformation", "bcount(QueryInformationLength)", DIR_IN, PVOID,
		"QueryInformationLength", "", DIR_IN, ULONG,
		"SystemInformation", "bcount_opt(SystemInformationLength)", DIR_OUT, PVOID,
		"SystemInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySystemInformation, NTSTATUS, 4,
		"SystemInformationClass", "", DIR_IN, SYSTEM_INFORMATION_CLASS,
		"SystemInformation", "bcount_opt(SystemInformationLength)", DIR_OUT, PVOID,
		"SystemInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQuerySystemTime, NTSTATUS, 1,
		"SystemTime", "", DIR_OUT, PLARGE_INTEGER,
);
SYSCALL(NtQueryTimer, NTSTATUS, 5,
		"TimerHandle", "", DIR_IN, HANDLE,
		"TimerInformationClass", "", DIR_IN, TIMER_INFORMATION_CLASS,
		"TimerInformation", "bcount(TimerInformationLength)", DIR_OUT, PVOID,
		"TimerInformationLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtQueryTimerResolution, NTSTATUS, 3,
		"MaximumTime", "", DIR_OUT, PULONG,
		"MinimumTime", "", DIR_OUT, PULONG,
		"CurrentTime", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryValueKey, NTSTATUS, 6,
		"KeyHandle", "", DIR_IN, HANDLE,
		"ValueName", "", DIR_IN, PUNICODE_STRING,
		"KeyValueInformationClass", "", DIR_IN, KEY_VALUE_INFORMATION_CLASS,
		"KeyValueInformation", "bcount_opt(Length)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"ResultLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtQueryVirtualMemory, NTSTATUS, 6,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"BaseAddress", "", DIR_IN, PVOID,
		"MemoryInformationClass", "", DIR_IN, MEMORY_INFORMATION_CLASS,
		"MemoryInformation", "bcount(MemoryInformationLength)", DIR_OUT, PVOID,
		"MemoryInformationLength", "", DIR_IN, SIZE_T,
		"ReturnLength", "opt", DIR_OUT, PSIZE_T,
);
SYSCALL(NtQueryVolumeInformationFile, NTSTATUS, 5,
		"FileHandle", "", DIR_IN, HANDLE,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
		"FsInformation", "bcount(Length)", DIR_OUT, PVOID,
		"Length", "", DIR_IN, ULONG,
		"FsInformationClass", "", DIR_IN, FS_INFORMATION_CLASS,
);
SYSCALL(NtQueueApcThreadEx, NTSTATUS, 6,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"UserApcReserveHandle", "opt", DIR_IN, HANDLE,
		"ApcRoutine", "", DIR_IN, PPS_APC_ROUTINE,
		"ApcArgument1", "opt", DIR_IN, PVOID,
		"ApcArgument2", "opt", DIR_IN, PVOID,
		"ApcArgument3", "opt", DIR_IN, PVOID,
);
SYSCALL(NtQueueApcThread, NTSTATUS, 5,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"ApcRoutine", "", DIR_IN, PPS_APC_ROUTINE,
		"ApcArgument1", "opt", DIR_IN, PVOID,
		"ApcArgument2", "opt", DIR_IN, PVOID,
		"ApcArgument3", "opt", DIR_IN, PVOID,
);
SYSCALL(NtRaiseException, NTSTATUS, 3,
		"ExceptionRecord", "", DIR_OUT, PEXCEPTION_RECORD,
		"ContextRecord", "", DIR_OUT, PCONTEXT,
		"FirstChance", "", DIR_OUT, BOOLEAN,
);
SYSCALL(NtRaiseHardError, NTSTATUS, 6,
		"ErrorStatus", "", DIR_IN, NTSTATUS,
		"NumberOfParameters", "", DIR_IN, ULONG,
		"UnicodeStringParameterMask", "", DIR_IN, ULONG,
		"Parameters", "ecount(NumberOfParameters)", DIR_IN, PULONG_PTR,
		"ValidResponseOptions", "", DIR_IN, ULONG,
		"Response", "", DIR_OUT, PULONG,
);
SYSCALL(NtReadFile, NTSTATUS, 9,
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
SYSCALL(NtReadFileScatter, NTSTATUS, 9,
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
SYSCALL(NtReadOnlyEnlistment, NTSTATUS, 2,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtReadRequestData, NTSTATUS, 6,
		"PortHandle", "", DIR_IN, HANDLE,
		"Message", "", DIR_IN, PPORT_MESSAGE,
		"DataEntryIndex", "", DIR_IN, ULONG,
		"Buffer", "bcount(BufferSize)", DIR_OUT, PVOID,
		"BufferSize", "", DIR_IN, SIZE_T,
		"NumberOfBytesRead", "opt", DIR_OUT, PSIZE_T,
);
SYSCALL(NtReadVirtualMemory, NTSTATUS, 5,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"BaseAddress", "opt", DIR_IN, PVOID,
		"Buffer", "bcount(BufferSize)", DIR_OUT, PVOID,
		"BufferSize", "", DIR_IN, SIZE_T,
		"NumberOfBytesRead", "opt", DIR_OUT, PSIZE_T,
);
SYSCALL(NtRecoverEnlistment, NTSTATUS, 2,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"EnlistmentKey", "opt", DIR_IN, PVOID,
);
SYSCALL(NtRecoverResourceManager, NTSTATUS, 1,
		"ResourceManagerHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtRecoverTransactionManager, NTSTATUS, 1,
		"TransactionManagerHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtRegisterProtocolAddressInformation, NTSTATUS, 5,
		"ResourceManager", "", DIR_IN, HANDLE,
		"ProtocolId", "", DIR_IN, PCRM_PROTOCOL_ID,
		"ProtocolInformationSize", "", DIR_IN, ULONG,
		"ProtocolInformation", "", DIR_IN, PVOID,
		"CreateOptions", "opt", DIR_IN, ULONG,
);
SYSCALL(NtRegisterThreadTerminatePort, NTSTATUS, 1,
		"PortHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtReleaseKeyedEvent, NTSTATUS, 4,
		"KeyedEventHandle", "", DIR_IN, HANDLE,
		"KeyValue", "", DIR_IN, PVOID,
		"Alertable", "", DIR_IN, BOOLEAN,
		"Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtReleaseMutant, NTSTATUS, 2,
		"MutantHandle", "", DIR_IN, HANDLE,
		"PreviousCount", "opt", DIR_OUT, PLONG,
);
SYSCALL(NtReleaseSemaphore, NTSTATUS, 3,
		"SemaphoreHandle", "", DIR_IN, HANDLE,
		"ReleaseCount", "", DIR_IN, LONG,
		"PreviousCount", "opt", DIR_OUT, PLONG,
);
SYSCALL(NtReleaseWorkerFactoryWorker, NTSTATUS, 1,
		"WorkerFactoryHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtRemoveIoCompletionEx, NTSTATUS, 6,
		"IoCompletionHandle", "", DIR_IN, HANDLE,
		"IoCompletionInformation", "ecount(Count)", DIR_OUT, PFILE_IO_COMPLETION_INFORMATION,
		"Count", "", DIR_IN, ULONG,
		"NumEntriesRemoved", "", DIR_OUT, PULONG,
		"Timeout", "opt", DIR_IN, PLARGE_INTEGER,
		"Alertable", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtRemoveIoCompletion, NTSTATUS, 5,
		"IoCompletionHandle", "", DIR_IN, HANDLE,
		"*KeyContext", "", DIR_OUT, PVOID,
		"*ApcContext", "", DIR_OUT, PVOID,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
		"Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtRemoveProcessDebug, NTSTATUS, 2,
		"ProcessHandle", "", DIR_OUT, HANDLE,
		"DebugObjectHandle", "", DIR_OUT, HANDLE,
);
SYSCALL(NtRenameKey, NTSTATUS, 2,
		"KeyHandle", "", DIR_IN, HANDLE,
		"NewName", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtRenameTransactionManager, NTSTATUS, 2,
		"LogFileName", "", DIR_IN, PUNICODE_STRING,
		"ExistingTransactionManagerGuid", "", DIR_IN, LPGUID,
);
SYSCALL(NtReplaceKey, NTSTATUS, 3,
		"NewFile", "", DIR_IN, POBJECT_ATTRIBUTES,
		"TargetHandle", "", DIR_IN, HANDLE,
		"OldFile", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtReplacePartitionUnit, NTSTATUS, 3,
		"TargetInstancePath", "", DIR_IN, PUNICODE_STRING,
		"SpareInstancePath", "", DIR_IN, PUNICODE_STRING,
		"Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtReplyPort, NTSTATUS, 2,
		"PortHandle", "", DIR_IN, HANDLE,
		"ReplyMessage", "", DIR_IN, PPORT_MESSAGE,
);
SYSCALL(NtReplyWaitReceivePortEx, NTSTATUS, 5,
		"PortHandle", "", DIR_IN, HANDLE,
		"*PortContext", "opt", DIR_OUT, PVOID,
		"ReplyMessage", "opt", DIR_IN, PPORT_MESSAGE,
		"ReceiveMessage", "", DIR_OUT, PPORT_MESSAGE,
		"Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtReplyWaitReceivePort, NTSTATUS, 4,
		"PortHandle", "", DIR_IN, HANDLE,
		"*PortContext", "opt", DIR_OUT, PVOID,
		"ReplyMessage", "opt", DIR_IN, PPORT_MESSAGE,
		"ReceiveMessage", "", DIR_OUT, PPORT_MESSAGE,
);
SYSCALL(NtReplyWaitReplyPort, NTSTATUS, 2,
		"PortHandle", "", DIR_IN, HANDLE,
		"ReplyMessage", "", DIR_INOUT, PPORT_MESSAGE,
);
SYSCALL(NtRequestPort, NTSTATUS, 2,
		"PortHandle", "", DIR_IN, HANDLE,
		"RequestMessage", "", DIR_IN, PPORT_MESSAGE,
);
SYSCALL(NtRequestWaitReplyPort, NTSTATUS, 3,
		"PortHandle", "", DIR_IN, HANDLE,
		"RequestMessage", "", DIR_IN, PPORT_MESSAGE,
		"ReplyMessage", "", DIR_OUT, PPORT_MESSAGE,
);
SYSCALL(NtResetEvent, NTSTATUS, 2,
		"EventHandle", "", DIR_IN, HANDLE,
		"PreviousState", "opt", DIR_OUT, PLONG,
);
SYSCALL(NtResetWriteWatch, NTSTATUS, 3,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"BaseAddress", "", DIR_IN, PVOID,
		"RegionSize", "", DIR_IN, SIZE_T,
);
SYSCALL(NtRestoreKey, NTSTATUS, 3,
		"KeyHandle", "", DIR_IN, HANDLE,
		"FileHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtResumeProcess, NTSTATUS, 1,
		"ProcessHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtResumeThread, NTSTATUS, 2,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"PreviousSuspendCount", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtRollbackComplete, NTSTATUS, 2,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtRollbackEnlistment, NTSTATUS, 2,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtRollbackTransaction, NTSTATUS, 2,
		"TransactionHandle", "", DIR_IN, HANDLE,
		"Wait", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtRollforwardTransactionManager, NTSTATUS, 2,
		"TransactionManagerHandle", "", DIR_IN, HANDLE,
		"TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtSaveKeyEx, NTSTATUS, 3,
		"KeyHandle", "", DIR_IN, HANDLE,
		"FileHandle", "", DIR_IN, HANDLE,
		"Format", "", DIR_IN, ULONG,
);
SYSCALL(NtSaveKey, NTSTATUS, 2,
		"KeyHandle", "", DIR_IN, HANDLE,
		"FileHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSaveMergedKeys, NTSTATUS, 3,
		"HighPrecedenceKeyHandle", "", DIR_IN, HANDLE,
		"LowPrecedenceKeyHandle", "", DIR_IN, HANDLE,
		"FileHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSecureConnectPort, NTSTATUS, 9,
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
SYSCALL(NtSetBootEntryOrder, NTSTATUS, 2,
		"Ids", "ecount(Count)", DIR_IN, PULONG,
		"Count", "", DIR_IN, ULONG,
);
SYSCALL(NtSetBootOptions, NTSTATUS, 2,
		"BootOptions", "", DIR_IN, PBOOT_OPTIONS,
		"FieldsToChange", "", DIR_IN, ULONG,
);
SYSCALL(NtSetContextThread, NTSTATUS, 2,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"ThreadContext", "", DIR_IN, PCONTEXT,
);
SYSCALL(NtSetDebugFilterState, NTSTATUS, 3,
		"ComponentId", "", DIR_IN, ULONG,
		"Level", "", DIR_IN, ULONG,
		"State", "", DIR_IN, BOOLEAN,
);
SYSCALL(NtSetDefaultHardErrorPort, NTSTATUS, 1,
		"DefaultHardErrorPort", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetDefaultLocale, NTSTATUS, 2,
		"UserProfile", "", DIR_IN, BOOLEAN,
		"DefaultLocaleId", "", DIR_IN, LCID,
);
SYSCALL(NtSetDefaultUILanguage, NTSTATUS, 1,
		"DefaultUILanguageId", "", DIR_IN, LANGID,
);
SYSCALL(NtSetDriverEntryOrder, NTSTATUS, 2,
		"Ids", "ecount(Count)", DIR_IN, PULONG,
		"Count", "", DIR_IN, ULONG,
);
SYSCALL(NtSetEaFile, NTSTATUS, 4,
		"FileHandle", "", DIR_IN, HANDLE,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
		"Buffer", "bcount(Length)", DIR_IN, PVOID,
		"Length", "", DIR_IN, ULONG,
);
SYSCALL(NtSetEventBoostPriority, NTSTATUS, 1,
		"EventHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetEvent, NTSTATUS, 2,
		"EventHandle", "", DIR_IN, HANDLE,
		"PreviousState", "opt", DIR_OUT, PLONG,
);
SYSCALL(NtSetHighEventPair, NTSTATUS, 1,
		"EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetHighWaitLowEventPair, NTSTATUS, 1,
		"EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetInformationDebugObject, NTSTATUS, 5,
		"DebugObjectHandle", "", DIR_OUT, HANDLE,
		"DebugObjectInformationClass", "", DIR_OUT, DEBUGOBJECTINFOCLASS,
		"DebugInformation", "", DIR_OUT, PVOID,
		"DebugInformationLength", "", DIR_OUT, ULONG,
		"ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtSetInformationEnlistment, NTSTATUS, 4,
		"EnlistmentHandle", "opt", DIR_IN, HANDLE,
		"EnlistmentInformationClass", "", DIR_IN, ENLISTMENT_INFORMATION_CLASS,
		"EnlistmentInformation", "bcount(EnlistmentInformationLength)", DIR_IN, PVOID,
		"EnlistmentInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationFile, NTSTATUS, 5,
		"FileHandle", "", DIR_IN, HANDLE,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
		"FileInformation", "bcount(Length)", DIR_IN, PVOID,
		"Length", "", DIR_IN, ULONG,
		"FileInformationClass", "", DIR_IN, FILE_INFORMATION_CLASS,
);
SYSCALL(NtSetInformationJobObject, NTSTATUS, 4,
		"JobHandle", "", DIR_IN, HANDLE,
		"JobObjectInformationClass", "", DIR_IN, JOBOBJECTINFOCLASS,
		"JobObjectInformation", "bcount(JobObjectInformationLength)", DIR_IN, PVOID,
		"JobObjectInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationKey, NTSTATUS, 4,
		"KeyHandle", "", DIR_IN, HANDLE,
		"KeySetInformationClass", "", DIR_IN, KEY_SET_INFORMATION_CLASS,
		"KeySetInformation", "bcount(KeySetInformationLength)", DIR_IN, PVOID,
		"KeySetInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationObject, NTSTATUS, 4,
		"Handle", "", DIR_IN, HANDLE,
		"ObjectInformationClass", "", DIR_IN, OBJECT_INFORMATION_CLASS,
		"ObjectInformation", "bcount(ObjectInformationLength)", DIR_IN, PVOID,
		"ObjectInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationProcess, NTSTATUS, 4,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"ProcessInformationClass", "", DIR_IN, PROCESSINFOCLASS,
		"ProcessInformation", "bcount(ProcessInformationLength)", DIR_IN, PVOID,
		"ProcessInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationResourceManager, NTSTATUS, 4,
		"ResourceManagerHandle", "", DIR_IN, HANDLE,
		"ResourceManagerInformationClass", "", DIR_IN, RESOURCEMANAGER_INFORMATION_CLASS,
		"ResourceManagerInformation", "bcount(ResourceManagerInformationLength)", DIR_IN, PVOID,
		"ResourceManagerInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationThread, NTSTATUS, 4,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"ThreadInformationClass", "", DIR_IN, THREADINFOCLASS,
		"ThreadInformation", "bcount(ThreadInformationLength)", DIR_IN, PVOID,
		"ThreadInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationToken, NTSTATUS, 4,
		"TokenHandle", "", DIR_IN, HANDLE,
		"TokenInformationClass", "", DIR_IN, TOKEN_INFORMATION_CLASS,
		"TokenInformation", "bcount(TokenInformationLength)", DIR_IN, PVOID,
		"TokenInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationTransaction, NTSTATUS, 4,
		"TransactionHandle", "", DIR_IN, HANDLE,
		"TransactionInformationClass", "", DIR_IN, TRANSACTION_INFORMATION_CLASS,
		"TransactionInformation", "bcount(TransactionInformationLength)", DIR_IN, PVOID,
		"TransactionInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationTransactionManager, NTSTATUS, 4,
		"TmHandle", "opt", DIR_IN, HANDLE,
		"TransactionManagerInformationClass", "", DIR_IN, TRANSACTIONMANAGER_INFORMATION_CLASS,
		"TransactionManagerInformation", "bcount(TransactionManagerInformationLength)", DIR_IN, PVOID,
		"TransactionManagerInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetInformationWorkerFactory, NTSTATUS, 4,
		"WorkerFactoryHandle", "", DIR_IN, HANDLE,
		"WorkerFactoryInformationClass", "", DIR_IN, WORKERFACTORYINFOCLASS,
		"WorkerFactoryInformation", "bcount(WorkerFactoryInformationLength)", DIR_IN, PVOID,
		"WorkerFactoryInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetIntervalProfile, NTSTATUS, 2,
		"Interval", "", DIR_IN, ULONG,
		"Source", "", DIR_IN, KPROFILE_SOURCE,
);
SYSCALL(NtSetIoCompletionEx, NTSTATUS, 6,
		"IoCompletionHandle", "", DIR_IN, HANDLE,
		"IoCompletionReserveHandle", "", DIR_IN, HANDLE,
		"KeyContext", "", DIR_IN, PVOID,
		"ApcContext", "opt", DIR_IN, PVOID,
		"IoStatus", "", DIR_IN, NTSTATUS,
		"IoStatusInformation", "", DIR_IN, ULONG_PTR,
);
SYSCALL(NtSetIoCompletion, NTSTATUS, 5,
		"IoCompletionHandle", "", DIR_IN, HANDLE,
		"KeyContext", "", DIR_IN, PVOID,
		"ApcContext", "opt", DIR_IN, PVOID,
		"IoStatus", "", DIR_IN, NTSTATUS,
		"IoStatusInformation", "", DIR_IN, ULONG_PTR,
);
SYSCALL(NtSetLdtEntries, NTSTATUS, 6,
		"Selector0", "", DIR_IN, ULONG,
		"Entry0Low", "", DIR_IN, ULONG,
		"Entry0Hi", "", DIR_IN, ULONG,
		"Selector1", "", DIR_IN, ULONG,
		"Entry1Low", "", DIR_IN, ULONG,
		"Entry1Hi", "", DIR_IN, ULONG,
);
SYSCALL(NtSetLowEventPair, NTSTATUS, 1,
		"EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetLowWaitHighEventPair, NTSTATUS, 1,
		"EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSetQuotaInformationFile, NTSTATUS, 4,
		"FileHandle", "", DIR_IN, HANDLE,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
		"Buffer", "bcount(Length)", DIR_IN, PVOID,
		"Length", "", DIR_IN, ULONG,
);
SYSCALL(NtSetSecurityObject, NTSTATUS, 3,
		"Handle", "", DIR_IN, HANDLE,
		"SecurityInformation", "", DIR_IN, SECURITY_INFORMATION,
		"SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR,
);
SYSCALL(NtSetSystemEnvironmentValueEx, NTSTATUS, 5,
		"VariableName", "", DIR_IN, PUNICODE_STRING,
		"VendorGuid", "", DIR_IN, LPGUID,
		"Value", "bcount_opt(ValueLength)", DIR_IN, PVOID,
		"ValueLength", "", DIR_IN, ULONG,
		"Attributes", "", DIR_IN, ULONG,
);
SYSCALL(NtSetSystemEnvironmentValue, NTSTATUS, 2,
		"VariableName", "", DIR_IN, PUNICODE_STRING,
		"VariableValue", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtSetSystemInformation, NTSTATUS, 3,
		"SystemInformationClass", "", DIR_IN, SYSTEM_INFORMATION_CLASS,
		"SystemInformation", "bcount_opt(SystemInformationLength)", DIR_IN, PVOID,
		"SystemInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetSystemPowerState, NTSTATUS, 3,
		"SystemAction", "", DIR_IN, POWER_ACTION,
		"MinSystemState", "", DIR_IN, SYSTEM_POWER_STATE,
		"Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtSetSystemTime, NTSTATUS, 2,
		"SystemTime", "opt", DIR_IN, PLARGE_INTEGER,
		"PreviousTime", "opt", DIR_OUT, PLARGE_INTEGER,
);
SYSCALL(NtSetThreadExecutionState, NTSTATUS, 2,
		"esFlags", "", DIR_IN, EXECUTION_STATE,
		"*PreviousFlags", "", DIR_OUT, EXECUTION_STATE,
);
SYSCALL(NtSetTimerEx, NTSTATUS, 4,
		"TimerHandle", "", DIR_IN, HANDLE,
		"TimerSetInformationClass", "", DIR_IN, TIMER_SET_INFORMATION_CLASS,
		"TimerSetInformation", "bcount(TimerSetInformationLength)", DIR_INOUT, PVOID,
		"TimerSetInformationLength", "", DIR_IN, ULONG,
);
SYSCALL(NtSetTimer, NTSTATUS, 7,
		"TimerHandle", "", DIR_IN, HANDLE,
		"DueTime", "", DIR_IN, PLARGE_INTEGER,
		"TimerApcRoutine", "opt", DIR_IN, PTIMER_APC_ROUTINE,
		"TimerContext", "opt", DIR_IN, PVOID,
		"WakeTimer", "", DIR_IN, BOOLEAN,
		"Period", "opt", DIR_IN, LONG,
		"PreviousState", "opt", DIR_OUT, PBOOLEAN,
);
SYSCALL(NtSetTimerResolution, NTSTATUS, 3,
		"DesiredTime", "", DIR_IN, ULONG,
		"SetResolution", "", DIR_IN, BOOLEAN,
		"ActualTime", "", DIR_OUT, PULONG,
);
SYSCALL(NtSetUuidSeed, NTSTATUS, 1,
		"Seed", "", DIR_IN, PCHAR,
);
SYSCALL(NtSetValueKey, NTSTATUS, 6,
		"KeyHandle", "", DIR_IN, HANDLE,
		"ValueName", "", DIR_IN, PUNICODE_STRING,
		"TitleIndex", "opt", DIR_IN, ULONG,
		"Type", "", DIR_IN, ULONG,
		"Data", "bcount_opt(DataSize)", DIR_IN, PVOID,
		"DataSize", "", DIR_IN, ULONG,
);
SYSCALL(NtSetVolumeInformationFile, NTSTATUS, 5,
		"FileHandle", "", DIR_IN, HANDLE,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
		"FsInformation", "bcount(Length)", DIR_IN, PVOID,
		"Length", "", DIR_IN, ULONG,
		"FsInformationClass", "", DIR_IN, FS_INFORMATION_CLASS,
);
SYSCALL(NtShutdownSystem, NTSTATUS, 1,
		"Action", "", DIR_IN, SHUTDOWN_ACTION,
);
SYSCALL(NtShutdownWorkerFactory, NTSTATUS, 2,
		"WorkerFactoryHandle", "", DIR_IN, HANDLE,
		"*PendingWorkerCount", "", DIR_INOUT, LONG,
);
SYSCALL(NtSignalAndWaitForSingleObject, NTSTATUS, 4,
		"SignalHandle", "", DIR_IN, HANDLE,
		"WaitHandle", "", DIR_IN, HANDLE,
		"Alertable", "", DIR_IN, BOOLEAN,
		"Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtSinglePhaseReject, NTSTATUS, 2,
		"EnlistmentHandle", "", DIR_IN, HANDLE,
		"TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtStartProfile, NTSTATUS, 1,
		"ProfileHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtStopProfile, NTSTATUS, 1,
		"ProfileHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSuspendProcess, NTSTATUS, 1,
		"ProcessHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtSuspendThread, NTSTATUS, 2,
		"ThreadHandle", "", DIR_IN, HANDLE,
		"PreviousSuspendCount", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtSystemDebugControl, NTSTATUS, 6,
		"Command", "", DIR_IN, SYSDBG_COMMAND,
		"InputBuffer", "bcount_opt(InputBufferLength)", DIR_INOUT, PVOID,
		"InputBufferLength", "", DIR_IN, ULONG,
		"OutputBuffer", "bcount_opt(OutputBufferLength)", DIR_OUT, PVOID,
		"OutputBufferLength", "", DIR_IN, ULONG,
		"ReturnLength", "opt", DIR_OUT, PULONG,
);
SYSCALL(NtTerminateJobObject, NTSTATUS, 2,
		"JobHandle", "", DIR_IN, HANDLE,
		"ExitStatus", "", DIR_IN, NTSTATUS,
);
SYSCALL(NtTerminateProcess, NTSTATUS, 2,
		"ProcessHandle", "opt", DIR_IN, HANDLE,
		"ExitStatus", "", DIR_IN, NTSTATUS,
);
SYSCALL(NtTerminateThread, NTSTATUS, 2,
		"ThreadHandle", "opt", DIR_IN, HANDLE,
		"ExitStatus", "", DIR_IN, NTSTATUS,
);
SYSCALL(NtTraceControl, NTSTATUS, 6,
		"FunctionCode", "", DIR_IN, ULONG,
		"InBuffer", "bcount_opt(InBufferLen)", DIR_IN, PVOID,
		"InBufferLen", "", DIR_IN, ULONG,
		"OutBuffer", "bcount_opt(OutBufferLen)", DIR_OUT, PVOID,
		"OutBufferLen", "", DIR_IN, ULONG,
		"ReturnLength", "", DIR_OUT, PULONG,
);
SYSCALL(NtTraceEvent, NTSTATUS, 4,
		"TraceHandle", "", DIR_IN, HANDLE,
		"Flags", "", DIR_IN, ULONG,
		"FieldSize", "", DIR_IN, ULONG,
		"Fields", "", DIR_IN, PVOID,
);
SYSCALL(NtTranslateFilePath, NTSTATUS, 4,
		"InputFilePath", "", DIR_IN, PFILE_PATH,
		"OutputType", "", DIR_IN, ULONG,
		"OutputFilePath", "bcount_opt(*OutputFilePathLength)", DIR_OUT, PFILE_PATH,
		"OutputFilePathLength", "opt", DIR_INOUT, PULONG,
);
SYSCALL(NtUnloadDriver, NTSTATUS, 1,
		"DriverServiceName", "", DIR_IN, PUNICODE_STRING,
);
SYSCALL(NtUnloadKey2, NTSTATUS, 2,
		"TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
		"Flags", "", DIR_IN, ULONG,
);
SYSCALL(NtUnloadKeyEx, NTSTATUS, 2,
		"TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
		"Event", "opt", DIR_IN, HANDLE,
);
SYSCALL(NtUnloadKey, NTSTATUS, 1,
		"TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES,
);
SYSCALL(NtUnlockFile, NTSTATUS, 5,
		"FileHandle", "", DIR_IN, HANDLE,
		"IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK,
		"ByteOffset", "", DIR_IN, PLARGE_INTEGER,
		"Length", "", DIR_IN, PLARGE_INTEGER,
		"Key", "", DIR_IN, ULONG,
);
SYSCALL(NtUnlockVirtualMemory, NTSTATUS, 4,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"*BaseAddress", "", DIR_INOUT, PVOID,
		"RegionSize", "", DIR_INOUT, PSIZE_T,
		"MapType", "", DIR_IN, ULONG,
);
SYSCALL(NtUnmapViewOfSection, NTSTATUS, 2,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"BaseAddress", "", DIR_IN, PVOID,
);
SYSCALL(NtVdmControl, NTSTATUS, 2,
		"Service", "", DIR_IN, VDMSERVICECLASS,
		"ServiceData", "", DIR_INOUT, PVOID,
);
SYSCALL(NtWaitForDebugEvent, NTSTATUS, 4,
		"DebugObjectHandle", "", DIR_OUT, HANDLE,
		"Alertable", "", DIR_OUT, BOOLEAN,
		"Timeout", "", DIR_OUT, PLARGE_INTEGER,
		"WaitStateChange", "", DIR_OUT, PDBGUI_WAIT_STATE_CHANGE,
);
SYSCALL(NtWaitForKeyedEvent, NTSTATUS, 4,
		"KeyedEventHandle", "", DIR_IN, HANDLE,
		"KeyValue", "", DIR_IN, PVOID,
		"Alertable", "", DIR_IN, BOOLEAN,
		"Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtWaitForMultipleObjects32, NTSTATUS, 5,
		"Count", "", DIR_IN, ULONG,
		"Handles[]", "ecount(Count)", DIR_IN, LONG,
		"WaitType", "", DIR_IN, WAIT_TYPE,
		"Alertable", "", DIR_IN, BOOLEAN,
		"Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtWaitForMultipleObjects, NTSTATUS, 5,
		"Count", "", DIR_IN, ULONG,
		"Handles[]", "ecount(Count)", DIR_IN, HANDLE,
		"WaitType", "", DIR_IN, WAIT_TYPE,
		"Alertable", "", DIR_IN, BOOLEAN,
		"Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtWaitForSingleObject, NTSTATUS, 3,
		"Handle", "", DIR_IN, HANDLE,
		"Alertable", "", DIR_IN, BOOLEAN,
		"Timeout", "opt", DIR_IN, PLARGE_INTEGER,
);
SYSCALL(NtWaitForWorkViaWorkerFactory, NTSTATUS, 2,
		"WorkerFactoryHandle", "", DIR_IN, HANDLE,
		"MiniPacket", "", DIR_OUT, PFILE_IO_COMPLETION_INFORMATION,
);
SYSCALL(NtWaitHighEventPair, NTSTATUS, 1,
		"EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtWaitLowEventPair, NTSTATUS, 1,
		"EventPairHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtWorkerFactoryWorkerReady, NTSTATUS, 1,
		"WorkerFactoryHandle", "", DIR_IN, HANDLE,
);
SYSCALL(NtWriteFileGather, NTSTATUS, 9,
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
SYSCALL(NtWriteFile, NTSTATUS, 9,
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
SYSCALL(NtWriteRequestData, NTSTATUS, 6,
		"PortHandle", "", DIR_IN, HANDLE,
		"Message", "", DIR_IN, PPORT_MESSAGE,
		"DataEntryIndex", "", DIR_IN, ULONG,
		"Buffer", "bcount(BufferSize)", DIR_IN, PVOID,
		"BufferSize", "", DIR_IN, SIZE_T,
		"NumberOfBytesWritten", "opt", DIR_OUT, PSIZE_T,
);
SYSCALL(NtWriteVirtualMemory, NTSTATUS, 5,
		"ProcessHandle", "", DIR_IN, HANDLE,
		"BaseAddress", "opt", DIR_IN, PVOID,
		"Buffer", "bcount(BufferSize)", DIR_IN, PVOID,
		"BufferSize", "", DIR_IN, SIZE_T,
		"NumberOfBytesWritten", "opt", DIR_OUT, PSIZE_T,
);

// TODO: fill in argument information
SYSCALL(NtUmsThreadYield, NTSTATUS, 0);
SYSCALL(NtThawTransactions, NTSTATUS, 0);
SYSCALL(NtThawRegistry, NTSTATUS, 0);
SYSCALL(NtTestAlert, NTSTATUS, 0);
SYSCALL(NtSerializeBoot, NTSTATUS, 0);
SYSCALL(NtQueryPortInformationProcess, NTSTATUS, 0);
SYSCALL(NtFlushWriteBuffer, NTSTATUS, 0);
SYSCALL(NtEnableLastKnownGood, NTSTATUS, 0);
SYSCALL(NtDisableLastKnownGood, NTSTATUS, 0);
SYSCALL(NtFlushProcessWriteBuffers, VOID, 0);
SYSCALL(NtGetCurrentProcessorNumber, ULONG, 0);
SYSCALL(NtGetEnvironmentVariableEx, MISSING, 0);
SYSCALL(NtIsSystemResumeAutomatic, BOOLEAN, 0);
SYSCALL(NtIsUILanguageComitted, NTSTATUS, 0);
SYSCALL(NtQueryEnvironmentVariableInfoEx, MISSING, 0);
SYSCALL(NtYieldExecution, NTSTATUS, 0);
SYSCALL(NtAcquireProcessActivityReference, NTSTATUS, 0);
SYSCALL(NtAddAtomEx, NTSTATUS, 0);
SYSCALL(NtAlertThreadByThreadId, NTSTATUS, 0);
SYSCALL(NtAllocateVirtualMemoryEx, NTSTATUS, 0);
SYSCALL(NtAlpcConnectPortEx, NTSTATUS, 0);
SYSCALL(NtAlpcImpersonateClientContainerOfPort, NTSTATUS, 0);
SYSCALL(NtAssociateWaitCompletionPacket, NTSTATUS, 0);
SYSCALL(NtCallEnclave, NTSTATUS, 0);
SYSCALL(NtCancelTimer2, NTSTATUS, 0);
SYSCALL(NtCancelWaitCompletionPacket, NTSTATUS, 0);
SYSCALL(NtCommitRegistryTransaction, NTSTATUS, 0);
SYSCALL(NtCompareObjects, NTSTATUS, 0);
SYSCALL(NtCompareSigningLevels, NTSTATUS, 0);
SYSCALL(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter, NTSTATUS, 0);
SYSCALL(NtCreateDirectoryObjectEx, NTSTATUS, 0);
SYSCALL(NtCreateEnclave, NTSTATUS, 0);
SYSCALL(NtCreateIRTimer, NTSTATUS, 0);
SYSCALL(NtCreateLowBoxToken, NTSTATUS, 0);
SYSCALL(NtCreatePartition, NTSTATUS, 0);
SYSCALL(NtCreateRegistryTransaction, NTSTATUS, 0);
SYSCALL(NtCreateTimer2, NTSTATUS, 0);
SYSCALL(NtCreateTokenEx, NTSTATUS, 0);
SYSCALL(NtCreateWaitCompletionPacket, NTSTATUS, 0);
SYSCALL(NtCreateWnfStateName, NTSTATUS, 0);
SYSCALL(NtDeleteWnfStateData, NTSTATUS, 0);
SYSCALL(NtDeleteWnfStateName, NTSTATUS, 0);
SYSCALL(NtFilterBootOption, NTSTATUS, 0);
SYSCALL(NtFlushBuffersFileEx, NTSTATUS, 0);
SYSCALL(NtGetCachedSigningLevel, NTSTATUS, 0);
SYSCALL(NtGetCompleteWnfStateSubscription, NTSTATUS, 0);
SYSCALL(NtGetCurrentProcessorNumberEx, NTSTATUS, 0);
SYSCALL(NtInitializeEnclave, NTSTATUS, 0);
SYSCALL(NtLoadEnclaveData, NTSTATUS, 0);
SYSCALL(NtLoadHotPatch, NTSTATUS, 0);
SYSCALL(NtManagePartition, NTSTATUS, 0);
SYSCALL(NtMapViewOfSectionEx, NTSTATUS, 0);
SYSCALL(NtNotifyChangeDirectoryFileEx, NTSTATUS, 0);
SYSCALL(NtOpenPartition, NTSTATUS, 0);
SYSCALL(NtOpenRegistryTransaction, NTSTATUS, 0);
SYSCALL(NtQueryAuxiliaryCounterFrequency, NTSTATUS, 0);
SYSCALL(NtQueryDirectoryFileEx, NTSTATUS, 0);
SYSCALL(NtQueryInformationByName, NTSTATUS, 0);
SYSCALL(NtQuerySecurityPolicy, NTSTATUS, 0);
SYSCALL(NtQueryWnfStateData, NTSTATUS, 0);
SYSCALL(NtQueryWnfStateNameInformation, NTSTATUS, 0);
SYSCALL(NtRevertContainerImpersonation, NTSTATUS, 0);
SYSCALL(NtRollbackRegistryTransaction, NTSTATUS, 0);
SYSCALL(NtSetCachedSigningLevel, NTSTATUS, 0);
SYSCALL(NtSetCachedSigningLevel2, NTSTATUS, 0);
SYSCALL(NtSetIRTimer, NTSTATUS, 0);
SYSCALL(NtSetInformationSymbolicLink, NTSTATUS, 0);
SYSCALL(NtSetInformationVirtualMemory, NTSTATUS, 0);
SYSCALL(NtSetTimer2, NTSTATUS, 0);
SYSCALL(NtSetWnfProcessNotificationEvent, NTSTATUS, 0);
SYSCALL(NtSubscribeWnfStateChange, NTSTATUS, 0);
SYSCALL(NtTerminateEnclave, NTSTATUS, 0);
SYSCALL(NtUnmapViewOfSectionEx, NTSTATUS, 0);
SYSCALL(NtUnsubscribeWnfStateChange, NTSTATUS, 0);
SYSCALL(NtUpdateWnfStateData, NTSTATUS, 0);
SYSCALL(NtWaitForAlertByThreadId, NTSTATUS, 0);
SYSCALL(NtCreateSectionEx, NTSTATUS, 0);
SYSCALL(NtManageHotPatch, NTSTATUS, 0);
SYSCALL(BvgaSetVirtualFrameBuffer, NTSTATUS, 0);
SYSCALL(CmpCleanUpHigherLayerKcbCachesPreCallback, NTSTATUS, 0);
SYSCALL(GetPnpProperty, NTSTATUS, 0);
SYSCALL(ArbPreprocessEntry, NTSTATUS, 0);
SYSCALL(ArbAddReserved, NTSTATUS, 0);

// WIN32K

SYSCALL(NtBindCompositionSurface, NTSTATUS, 0);
SYSCALL(NtCloseCompositionInputSink, NTSTATUS, 0);
SYSCALL(NtCompositionInputThread, NTSTATUS, 0);
SYSCALL(NtCompositionSetDropTarget, NTSTATUS, 0);
SYSCALL(NtConfigureInputSpace, NTSTATUS, 0);
SYSCALL(NtCreateCompositionInputSink, NTSTATUS, 0);
SYSCALL(NtCreateCompositionSurfaceHandle, NTSTATUS, 0);
SYSCALL(NtCreateImplicitCompositionInputSink, NTSTATUS, 0);
SYSCALL(NtDCompositionAddCrossDeviceVisualChild, NTSTATUS, 0);
SYSCALL(NtDCompositionAddVisualChild, NTSTATUS, 0);
SYSCALL(NtDCompositionAttachMouseWheelToHwnd, NTSTATUS, 0);
SYSCALL(NtDCompositionBeginFrame, NTSTATUS, 0);
SYSCALL(NtDCompositionCapturePointer, NTSTATUS, 0);
SYSCALL(NtDCompositionCommitChannel, NTSTATUS, 0);
SYSCALL(NtDCompositionCommitSynchronizationObject, NTSTATUS, 0);
SYSCALL(NtDCompositionConfirmFrame, NTSTATUS, 0);
SYSCALL(NtDCompositionConnectPipe, NTSTATUS, 0);
SYSCALL(NtDCompositionCreateAndBindSharedSection, NTSTATUS, 0);
SYSCALL(NtDCompositionCreateChannel, NTSTATUS, 0);
SYSCALL(NtDCompositionCreateConnection, NTSTATUS, 0);
SYSCALL(NtDCompositionCreateConnectionContext, NTSTATUS, 0);
SYSCALL(NtDCompositionCreateDwmChannel, NTSTATUS, 0);
SYSCALL(NtDCompositionCreateResource, NTSTATUS, 0);
SYSCALL(NtDCompositionCreateSharedResourceHandle, NTSTATUS, 0);
SYSCALL(NtDCompositionCreateSharedVisualHandle, NTSTATUS, 0);
SYSCALL(NtDCompositionCreateSynchronizationObject, NTSTATUS, 0);
SYSCALL(NtDCompositionCurrentBatchId, NTSTATUS, 0);
SYSCALL(NtDCompositionDestroyChannel, NTSTATUS, 0);
SYSCALL(NtDCompositionDestroyConnection, NTSTATUS, 0);
SYSCALL(NtDCompositionDestroyConnectionContext, NTSTATUS, 0);
SYSCALL(NtDCompositionDiscardFrame, NTSTATUS, 0);
SYSCALL(NtDCompositionDuplicateHandleToProcess, NTSTATUS, 0);
SYSCALL(NtDCompositionDuplicateSwapchainHandleToDwm, NTSTATUS, 0);
SYSCALL(NtDCompositionDwmSyncFlush, NTSTATUS, 0);
SYSCALL(NtDCompositionEnableDDASupport, NTSTATUS, 0);
SYSCALL(NtDCompositionEnableMMCSS, NTSTATUS, 0);
SYSCALL(NtDCompositionGetAnimationTime, NTSTATUS, 0);
SYSCALL(NtDCompositionGetBatchId, NTSTATUS, 0);
SYSCALL(NtDCompositionGetChannels, NTSTATUS, 0);
SYSCALL(NtDCompositionGetConnectionBatch, NTSTATUS, 0);
SYSCALL(NtDCompositionGetConnectionContextBatch, NTSTATUS, 0);
SYSCALL(NtDCompositionGetDeletedResources, NTSTATUS, 0);
SYSCALL(NtDCompositionGetFrameLegacyTokens, NTSTATUS, 0);
SYSCALL(NtDCompositionGetFrameStatistics, NTSTATUS, 0);
SYSCALL(NtDCompositionGetFrameSurfaceUpdates, NTSTATUS, 0);
SYSCALL(NtDCompositionGetMaterialProperty, NTSTATUS, 0);
SYSCALL(NtDCompositionOpenSharedResource, NTSTATUS, 0);
SYSCALL(NtDCompositionOpenSharedResourceHandle, NTSTATUS, 0);
SYSCALL(NtDCompositionProcessChannelBatchBuffer, NTSTATUS, 0);
SYSCALL(NtDCompositionReferenceSharedResourceOnDwmChannel, NTSTATUS, 0);
SYSCALL(NtDCompositionRegisterThumbnailVisual, NTSTATUS, 0);
SYSCALL(NtDCompositionRegisterVirtualDesktopVisual, NTSTATUS, 0);
SYSCALL(NtDCompositionReleaseAllResources, NTSTATUS, 0);
SYSCALL(NtDCompositionReleaseResource, NTSTATUS, 0);
SYSCALL(NtDCompositionRemoveCrossDeviceVisualChild, NTSTATUS, 0);
SYSCALL(NtDCompositionRemoveVisualChild, NTSTATUS, 0);
SYSCALL(NtDCompositionReplaceVisualChildren, NTSTATUS, 0);
SYSCALL(NtDCompositionRetireFrame, NTSTATUS, 0);
SYSCALL(NtDCompositionSetChannelCallbackId, NTSTATUS, 0);
SYSCALL(NtDCompositionSetChannelCommitCompletionEvent, NTSTATUS, 0);
SYSCALL(NtDCompositionSetChannelConnectionId, NTSTATUS, 0);
SYSCALL(NtDCompositionSetChildRootVisual, NTSTATUS, 0);
SYSCALL(NtDCompositionSetDebugCounter, NTSTATUS, 0);
SYSCALL(NtDCompositionSetMaterialProperty, NTSTATUS, 0);
SYSCALL(NtDCompositionSetResourceAnimationProperty, NTSTATUS, 0);
SYSCALL(NtDCompositionSetResourceBufferProperty, NTSTATUS, 0);
SYSCALL(NtDCompositionSetResourceCallbackId, NTSTATUS, 0);
SYSCALL(NtDCompositionSetResourceDeletedNotificationTag, NTSTATUS, 0);
SYSCALL(NtDCompositionSetResourceFloatProperty, NTSTATUS, 0);
SYSCALL(NtDCompositionSetResourceHandleProperty, NTSTATUS, 0);
SYSCALL(NtDCompositionSetResourceIntegerProperty, NTSTATUS, 0);
SYSCALL(NtDCompositionSetResourceReferenceArrayProperty, NTSTATUS, 0);
SYSCALL(NtDCompositionSetResourceReferenceProperty, NTSTATUS, 0);
SYSCALL(NtDCompositionSetVisualInputSink, NTSTATUS, 0);
SYSCALL(NtDCompositionSignalGpuFence, NTSTATUS, 0);
SYSCALL(NtDCompositionSubmitDWMBatch, NTSTATUS, 0);
SYSCALL(NtDCompositionSuspendAnimations, NTSTATUS, 0);
SYSCALL(NtDCompositionSynchronize, NTSTATUS, 0);
SYSCALL(NtDCompositionTelemetryAnimationScenarioBegin, NTSTATUS, 0);
SYSCALL(NtDCompositionTelemetryAnimationScenarioReference, NTSTATUS, 0);
SYSCALL(NtDCompositionTelemetryAnimationScenarioUnreference, NTSTATUS, 0);
SYSCALL(NtDCompositionTelemetrySetApplicationId, NTSTATUS, 0);
SYSCALL(NtDCompositionTelemetryTouchInteractionBegin, NTSTATUS, 0);
SYSCALL(NtDCompositionTelemetryTouchInteractionEnd, NTSTATUS, 0);
SYSCALL(NtDCompositionTelemetryTouchInteractionUpdate, NTSTATUS, 0);
SYSCALL(NtDCompositionUpdatePointerCapture, NTSTATUS, 0);
SYSCALL(NtDCompositionValidateAndReferenceSystemVisualForHwndTarget, NTSTATUS, 0);
SYSCALL(NtDCompositionWaitForChannel, NTSTATUS, 0);
SYSCALL(NtDWMBindCursorToOutputConfig, NTSTATUS, 0);
SYSCALL(NtDWMCommitInputSystemOutputConfig, NTSTATUS, 0);
SYSCALL(NtDWMSetCursorOrientation, NTSTATUS, 0);
SYSCALL(NtDWMSetInputSystemOutputConfig, NTSTATUS, 0);
SYSCALL(NtDesktopCaptureBits, NTSTATUS, 0);
SYSCALL(NtDuplicateCompositionInputSink, NTSTATUS, 0);
SYSCALL(NtDxgkCreateTrackedWorkload, NTSTATUS, 0);
SYSCALL(NtDxgkDestroyTrackedWorkload, NTSTATUS, 0);
SYSCALL(NtDxgkDispMgrOperation, NTSTATUS, 0);
SYSCALL(NtDxgkEndTrackedWorkload, NTSTATUS, 0);
SYSCALL(NtDxgkGetAvailableTrackedWorkloadIndex, NTSTATUS, 0);
SYSCALL(NtDxgkGetProcessList, NTSTATUS, 0);
SYSCALL(NtDxgkGetTrackedWorkloadStatistics, NTSTATUS, 0);
SYSCALL(NtDxgkOutputDuplPresentToHwQueue, NTSTATUS, 0);
SYSCALL(NtDxgkRegisterVailProcess, NTSTATUS, 0);
SYSCALL(NtDxgkResetTrackedWorkload, NTSTATUS, 0);
SYSCALL(NtDxgkSubmitPresentBltToHwQueue, NTSTATUS, 0);
SYSCALL(NtDxgkSubmitPresentToHwQueue, NTSTATUS, 0);
SYSCALL(NtDxgkUpdateTrackedWorkload, NTSTATUS, 0);
SYSCALL(NtDxgkVailConnect, NTSTATUS, 0);
SYSCALL(NtDxgkVailDisconnect, NTSTATUS, 0);
SYSCALL(NtDxgkVailPromoteCompositionSurface, NTSTATUS, 0);
SYSCALL(NtEnableOneCoreTransformMode, NTSTATUS, 0);
SYSCALL(NtFlipObjectAddContent, NTSTATUS, 0);
SYSCALL(NtFlipObjectAddPoolBuffer, NTSTATUS, 0);
SYSCALL(NtFlipObjectConsumerAcquirePresent, NTSTATUS, 0);
SYSCALL(NtFlipObjectConsumerAdjustUsageReference, NTSTATUS, 0);
SYSCALL(NtFlipObjectConsumerBeginProcessPresent, NTSTATUS, 0);
SYSCALL(NtFlipObjectConsumerEndProcessPresent, NTSTATUS, 0);
SYSCALL(NtFlipObjectConsumerPostMessage, NTSTATUS, 0);
SYSCALL(NtFlipObjectConsumerQueryBufferInfo, NTSTATUS, 0);
SYSCALL(NtFlipObjectCreate, NTSTATUS, 0);
SYSCALL(NtFlipObjectDisconnectEndpoint, NTSTATUS, 0);
SYSCALL(NtFlipObjectOpen, NTSTATUS, 0);
SYSCALL(NtFlipObjectPresentCancel, NTSTATUS, 0);
SYSCALL(NtFlipObjectQueryBufferAvailableEvent, NTSTATUS, 0);
SYSCALL(NtFlipObjectQueryEndpointConnected, NTSTATUS, 0);
SYSCALL(NtFlipObjectQueryNextMessageToProducer, NTSTATUS, 0);
SYSCALL(NtFlipObjectReadNextMessageToProducer, NTSTATUS, 0);
SYSCALL(NtFlipObjectRemoveContent, NTSTATUS, 0);
SYSCALL(NtFlipObjectRemovePoolBuffer, NTSTATUS, 0);
SYSCALL(NtFlipObjectSetContent, NTSTATUS, 0);
SYSCALL(NtGdiAbortDoc, NTSTATUS, 0);
SYSCALL(NtGdiAbortPath, NTSTATUS, 0);
SYSCALL(NtGdiAddEmbFontToDC, NTSTATUS, 0);
SYSCALL(NtGdiAddFontMemResourceEx, NTSTATUS, 0);
SYSCALL(NtGdiAddFontResourceW, NTSTATUS, 0);
SYSCALL(NtGdiAddInitialFonts, NTSTATUS, 0);
SYSCALL(NtGdiAddRemoteFontToDC, NTSTATUS, 0);
SYSCALL(NtGdiAddRemoteMMInstanceToDC, NTSTATUS, 0);
SYSCALL(NtGdiAlphaBlend, NTSTATUS, 0);
SYSCALL(NtGdiAngleArc, NTSTATUS, 0);
SYSCALL(NtGdiAnyLinkedFonts, NTSTATUS, 0);
SYSCALL(NtGdiArcInternal, NTSTATUS, 0);
SYSCALL(NtGdiBRUSHOBJ_DeleteRbrush, NTSTATUS, 0);
SYSCALL(NtGdiBRUSHOBJ_hGetColorTransform, NTSTATUS, 0);
SYSCALL(NtGdiBRUSHOBJ_pvAllocRbrush, NTSTATUS, 0);
SYSCALL(NtGdiBRUSHOBJ_pvGetRbrush, NTSTATUS, 0);
SYSCALL(NtGdiBRUSHOBJ_ulGetBrushColor, NTSTATUS, 0);
SYSCALL(NtGdiBeginGdiRendering, NTSTATUS, 0);
SYSCALL(NtGdiBeginPath, NTSTATUS, 0);
SYSCALL(NtGdiBitBlt, NTSTATUS, 0);
SYSCALL(NtGdiCLIPOBJ_bEnum, NTSTATUS, 0);
SYSCALL(NtGdiCLIPOBJ_cEnumStart, NTSTATUS, 0);
SYSCALL(NtGdiCLIPOBJ_ppoGetPath, NTSTATUS, 0);
SYSCALL(NtGdiCancelDC, NTSTATUS, 0);
SYSCALL(NtGdiChangeGhostFont, NTSTATUS, 0);
SYSCALL(NtGdiCheckBitmapBits, NTSTATUS, 0);
SYSCALL(NtGdiClearBitmapAttributes, NTSTATUS, 0);
SYSCALL(NtGdiClearBrushAttributes, NTSTATUS, 0);
SYSCALL(NtGdiCloseFigure, NTSTATUS, 0);
SYSCALL(NtGdiColorCorrectPalette, NTSTATUS, 0);
SYSCALL(NtGdiCombineRgn, NTSTATUS, 0);
SYSCALL(NtGdiCombineTransform, NTSTATUS, 0);
SYSCALL(NtGdiComputeXformCoefficients, NTSTATUS, 0);
SYSCALL(NtGdiConfigureOPMProtectedOutput, NTSTATUS, 0);
SYSCALL(NtGdiConsoleTextOut, NTSTATUS, 0);
SYSCALL(NtGdiConvertMetafileRect, NTSTATUS, 0);
SYSCALL(NtGdiCreateBitmap, NTSTATUS, 0);
SYSCALL(NtGdiCreateBitmapFromDxSurface, NTSTATUS, 0);
SYSCALL(NtGdiCreateBitmapFromDxSurface2, NTSTATUS, 0);
SYSCALL(NtGdiCreateClientObj, NTSTATUS, 0);
SYSCALL(NtGdiCreateColorSpace, NTSTATUS, 0);
SYSCALL(NtGdiCreateColorTransform, NTSTATUS, 0);
SYSCALL(NtGdiCreateCompatibleBitmap, NTSTATUS, 0);
SYSCALL(NtGdiCreateCompatibleDC, NTSTATUS, 0);
SYSCALL(NtGdiCreateDIBBrush, NTSTATUS, 0);
SYSCALL(NtGdiCreateDIBSection, NTSTATUS, 0);
SYSCALL(NtGdiCreateDIBitmapInternal, NTSTATUS, 0);
SYSCALL(NtGdiCreateEllipticRgn, NTSTATUS, 0);
SYSCALL(NtGdiCreateHalftonePalette, NTSTATUS, 0);
SYSCALL(NtGdiCreateHatchBrushInternal, NTSTATUS, 0);
SYSCALL(NtGdiCreateMetafileDC, NTSTATUS, 0);
SYSCALL(NtGdiCreateOPMProtectedOutput, NTSTATUS, 0);
SYSCALL(NtGdiCreateOPMProtectedOutputs, NTSTATUS, 0);
SYSCALL(NtGdiCreatePaletteInternal, NTSTATUS, 0);
SYSCALL(NtGdiCreatePatternBrushInternal, NTSTATUS, 0);
SYSCALL(NtGdiCreatePen, NTSTATUS, 0);
SYSCALL(NtGdiCreateRectRgn, NTSTATUS, 0);
SYSCALL(NtGdiCreateRoundRectRgn, NTSTATUS, 0);
SYSCALL(NtGdiCreateServerMetaFile, NTSTATUS, 0);
SYSCALL(NtGdiCreateSessionMappedDIBSection, NTSTATUS, 0);
SYSCALL(NtGdiCreateSolidBrush, NTSTATUS, 0);
SYSCALL(NtGdiD3dContextCreate, NTSTATUS, 0);
SYSCALL(NtGdiD3dContextDestroy, NTSTATUS, 0);
SYSCALL(NtGdiD3dContextDestroyAll, NTSTATUS, 0);
SYSCALL(NtGdiD3dDrawPrimitives2, NTSTATUS, 0);
SYSCALL(NtGdiD3dValidateTextureStageState, NTSTATUS, 0);
SYSCALL(NtGdiDDCCIGetCapabilitiesString, NTSTATUS, 0);
SYSCALL(NtGdiDDCCIGetCapabilitiesStringLength, NTSTATUS, 0);
SYSCALL(NtGdiDDCCIGetTimingReport, NTSTATUS, 0);
SYSCALL(NtGdiDDCCIGetVCPFeature, NTSTATUS, 0);
SYSCALL(NtGdiDDCCISaveCurrentSettings, NTSTATUS, 0);
SYSCALL(NtGdiDDCCISetVCPFeature, NTSTATUS, 0);
SYSCALL(NtGdiDdAddAttachedSurface, NTSTATUS, 0);
SYSCALL(NtGdiDdAlphaBlt, NTSTATUS, 0);
SYSCALL(NtGdiDdAttachSurface, NTSTATUS, 0);
SYSCALL(NtGdiDdBeginMoCompFrame, NTSTATUS, 0);
SYSCALL(NtGdiDdBlt, NTSTATUS, 0);
SYSCALL(NtGdiDdCanCreateD3DBuffer, NTSTATUS, 0);
SYSCALL(NtGdiDdCanCreateSurface, NTSTATUS, 0);
SYSCALL(NtGdiDdColorControl, NTSTATUS, 0);
SYSCALL(NtGdiDdCreateD3DBuffer, NTSTATUS, 0);
SYSCALL(NtGdiDdCreateDirectDrawObject, NTSTATUS, 0);
SYSCALL(NtGdiDdCreateFullscreenSprite, NTSTATUS, 0);
SYSCALL(NtGdiDdCreateMoComp, NTSTATUS, 0);
SYSCALL(NtGdiDdCreateSurface, NTSTATUS, 0);
SYSCALL(NtGdiDdCreateSurfaceEx, NTSTATUS, 0);
SYSCALL(NtGdiDdCreateSurfaceObject, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIAbandonSwapChain, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIAcquireKeyedMutex, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIAcquireKeyedMutex2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIAcquireSwapChain, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIAddSurfaceToSwapChain, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIAdjustFullscreenGamma, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICacheHybridQueryValue, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIChangeVideoMemoryReservation, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICheckExclusiveOwnership, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICheckMonitorPowerState, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICheckMultiPlaneOverlaySupport, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICheckMultiPlaneOverlaySupport2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICheckMultiPlaneOverlaySupport3, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICheckOcclusion, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICheckSharedResourceAccess, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICheckVidPnExclusiveOwnership, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICloseAdapter, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIConfigureSharedResource, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateAllocation, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateBundleObject, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateContext, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateContextVirtual, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateDCFromMemory, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateDevice, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateHwContext, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateHwQueue, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateKeyedMutex, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateKeyedMutex2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateOutputDupl, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateOverlay, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreatePagingQueue, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateProtectedSession, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateSwapChain, NTSTATUS, 0);
SYSCALL(NtGdiDdDDICreateSynchronizationObject, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDDisplayEnum, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyAllocation, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyAllocation2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyContext, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyDCFromMemory, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyDevice, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyHwContext, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyHwQueue, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyKeyedMutex, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyOutputDupl, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyOverlay, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyPagingQueue, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroyProtectedSession, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDestroySynchronizationObject, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDispMgrCreate, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDispMgrSourceOperation, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIDispMgrTargetOperation, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIEnumAdapters, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIEnumAdapters2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIEscape, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIEvict, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIExtractBundleObject, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIFlipOverlay, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIFlushHeapTransitions, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIFreeGpuVirtualAddress, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetAllocationPriority, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetCachedHybridQueryValue, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetContextInProcessSchedulingPriority, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetContextSchedulingPriority, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetDWMVerticalBlankEvent, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetDeviceState, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetDisplayModeList, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetMemoryBudgetTarget, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetMultiPlaneOverlayCaps, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetMultisampleMethodList, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetOverlayState, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetPostCompositionCaps, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetPresentHistory, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetPresentQueueEvent, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetProcessDeviceLostSupport, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetProcessDeviceRemovalSupport, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetProcessSchedulingPriorityBand, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetProcessSchedulingPriorityClass, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetResourcePresentPrivateDriverData, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetRuntimeData, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetScanLine, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetSetSwapChainMetadata, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetSharedPrimaryHandle, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetSharedResourceAdapterLuid, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetSharedResourceAdapterLuidFlipManager, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIGetYieldPercentage, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIInvalidateActiveVidPn, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIInvalidateCache, NTSTATUS, 0);
SYSCALL(NtGdiDdDDILock, NTSTATUS, 0);
SYSCALL(NtGdiDdDDILock2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIMakeResident, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIMapGpuVirtualAddress, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIMarkDeviceAsError, NTSTATUS, 0);
SYSCALL(NtGdiDdDDINetDispGetNextChunkInfo, NTSTATUS, 0);
SYSCALL(NtGdiDdDDINetDispQueryMiracastDisplayDeviceStatus, NTSTATUS, 0);
SYSCALL(NtGdiDdDDINetDispQueryMiracastDisplayDeviceSupport, NTSTATUS, 0);
SYSCALL(NtGdiDdDDINetDispStartMiracastDisplayDevice, NTSTATUS, 0);
SYSCALL(NtGdiDdDDINetDispStartMiracastDisplayDeviceEx, NTSTATUS, 0);
SYSCALL(NtGdiDdDDINetDispStopMiracastDisplayDevice, NTSTATUS, 0);
SYSCALL(NtGdiDdDDINetDispStopSessions, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOfferAllocations, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenAdapterFromDeviceName, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenAdapterFromHdc, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenAdapterFromLuid, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenBundleObjectNtHandleFromName, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenKeyedMutex, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenKeyedMutex2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenKeyedMutexFromNtHandle, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenNtHandleFromName, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenProtectedSessionFromNtHandle, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenResource, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenResourceFromNtHandle, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenSwapChain, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenSyncObjectFromNtHandle, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenSyncObjectFromNtHandle2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenSyncObjectNtHandleFromName, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOpenSynchronizationObject, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOutputDuplGetFrameInfo, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOutputDuplGetMetaData, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOutputDuplGetPointerShapeData, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOutputDuplPresent, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIOutputDuplReleaseFrame, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIPinDirectFlipResources, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIPollDisplayChildren, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIPresent, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIPresentMultiPlaneOverlay, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIPresentMultiPlaneOverlay2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIPresentMultiPlaneOverlay3, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIPresentRedirected, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryAdapterInfo, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryAllocationResidency, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryClockCalibration, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryFSEBlock, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryProcessOfferInfo, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryProtectedSessionInfoFromNtHandle, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryProtectedSessionStatus, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryRemoteVidPnSourceFromGdiDisplayName, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryResourceInfo, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryResourceInfoFromNtHandle, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryStatistics, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryVidPnExclusiveOwnership, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIQueryVideoMemoryInfo, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIReclaimAllocations, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIReclaimAllocations2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIReleaseKeyedMutex, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIReleaseKeyedMutex2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIReleaseProcessVidPnSourceOwners, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIReleaseSwapChain, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIRemoveSurfaceFromSwapChain, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIRender, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIReserveGpuVirtualAddress, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetAllocationPriority, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetContextInProcessSchedulingPriority, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetContextSchedulingPriority, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetDeviceLostSupport, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetDisplayMode, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetDisplayPrivateDriverFormat, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetDodIndirectSwapchain, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetFSEBlock, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetGammaRamp, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetHwProtectionTeardownRecovery, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetMemoryBudgetTarget, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetMonitorColorSpaceTransform, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetProcessDeviceRemovalSupport, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetProcessSchedulingPriorityBand, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetProcessSchedulingPriorityClass, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetQueuedLimit, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetStablePowerState, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetStereoEnabled, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetSyncRefreshCountWaitTarget, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetVidPnSourceHwProtection, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetVidPnSourceOwner, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetVidPnSourceOwner1, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISetYieldPercentage, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIShareObjects, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISharedPrimaryLockNotification, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISharedPrimaryUnLockNotification, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISignalSynchronizationObject, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISignalSynchronizationObjectFromCpu, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISignalSynchronizationObjectFromGpu, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISignalSynchronizationObjectFromGpu2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISubmitCommand, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISubmitCommandToHwQueue, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISubmitSignalSyncObjectsToHwQueue, NTSTATUS, 0);
SYSCALL(NtGdiDdDDISubmitWaitForSyncObjectsToHwQueue, NTSTATUS, 0);
SYSCALL(NtGdiDdDDITrimProcessCommitment, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIUnOrderedPresentSwapChain, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIUnlock, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIUnlock2, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIUnpinDirectFlipResources, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIUpdateAllocationProperty, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIUpdateGpuVirtualAddress, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIUpdateOverlay, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIWaitForIdle, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIWaitForSynchronizationObject, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIWaitForSynchronizationObjectFromCpu, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIWaitForSynchronizationObjectFromGpu, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIWaitForVerticalBlankEvent, NTSTATUS, 0);
SYSCALL(NtGdiDdDDIWaitForVerticalBlankEvent2, NTSTATUS, 0);
SYSCALL(NtGdiDdDeleteDirectDrawObject, NTSTATUS, 0);
SYSCALL(NtGdiDdDeleteSurfaceObject, NTSTATUS, 0);
SYSCALL(NtGdiDdDestroyD3DBuffer, NTSTATUS, 0);
SYSCALL(NtGdiDdDestroyFullscreenSprite, NTSTATUS, 0);
SYSCALL(NtGdiDdDestroyMoComp, NTSTATUS, 0);
SYSCALL(NtGdiDdDestroySurface, NTSTATUS, 0);
SYSCALL(NtGdiDdEndMoCompFrame, NTSTATUS, 0);
SYSCALL(NtGdiDdFlip, NTSTATUS, 0);
SYSCALL(NtGdiDdFlipToGDISurface, NTSTATUS, 0);
SYSCALL(NtGdiDdGetAvailDriverMemory, NTSTATUS, 0);
SYSCALL(NtGdiDdGetBltStatus, NTSTATUS, 0);
SYSCALL(NtGdiDdGetDC, NTSTATUS, 0);
SYSCALL(NtGdiDdGetDriverInfo, NTSTATUS, 0);
SYSCALL(NtGdiDdGetDriverState, NTSTATUS, 0);
SYSCALL(NtGdiDdGetDxHandle, NTSTATUS, 0);
SYSCALL(NtGdiDdGetFlipStatus, NTSTATUS, 0);
SYSCALL(NtGdiDdGetInternalMoCompInfo, NTSTATUS, 0);
SYSCALL(NtGdiDdGetMoCompBuffInfo, NTSTATUS, 0);
SYSCALL(NtGdiDdGetMoCompFormats, NTSTATUS, 0);
SYSCALL(NtGdiDdGetMoCompGuids, NTSTATUS, 0);
SYSCALL(NtGdiDdGetScanLine, NTSTATUS, 0);
SYSCALL(NtGdiDdLock, NTSTATUS, 0);
SYSCALL(NtGdiDdLockD3D, NTSTATUS, 0);
SYSCALL(NtGdiDdNotifyFullscreenSpriteUpdate, NTSTATUS, 0);
SYSCALL(NtGdiDdQueryDirectDrawObject, NTSTATUS, 0);
SYSCALL(NtGdiDdQueryMoCompStatus, NTSTATUS, 0);
SYSCALL(NtGdiDdQueryVisRgnUniqueness, NTSTATUS, 0);
SYSCALL(NtGdiDdReenableDirectDrawObject, NTSTATUS, 0);
SYSCALL(NtGdiDdReleaseDC, NTSTATUS, 0);
SYSCALL(NtGdiDdRenderMoComp, NTSTATUS, 0);
SYSCALL(NtGdiDdResetVisrgn, NTSTATUS, 0);
SYSCALL(NtGdiDdSetColorKey, NTSTATUS, 0);
SYSCALL(NtGdiDdSetExclusiveMode, NTSTATUS, 0);
SYSCALL(NtGdiDdSetGammaRamp, NTSTATUS, 0);
SYSCALL(NtGdiDdSetOverlayPosition, NTSTATUS, 0);
SYSCALL(NtGdiDdUnattachSurface, NTSTATUS, 0);
SYSCALL(NtGdiDdUnlock, NTSTATUS, 0);
SYSCALL(NtGdiDdUnlockD3D, NTSTATUS, 0);
SYSCALL(NtGdiDdUpdateOverlay, NTSTATUS, 0);
SYSCALL(NtGdiDdWaitForVerticalBlank, NTSTATUS, 0);
SYSCALL(NtGdiDeleteClientObj, NTSTATUS, 0);
SYSCALL(NtGdiDeleteColorSpace, NTSTATUS, 0);
SYSCALL(NtGdiDeleteColorTransform, NTSTATUS, 0);
SYSCALL(NtGdiDeleteObjectApp, NTSTATUS, 0);
SYSCALL(NtGdiDescribePixelFormat, NTSTATUS, 0);
SYSCALL(NtGdiDestroyOPMProtectedOutput, NTSTATUS, 0);
SYSCALL(NtGdiDestroyPhysicalMonitor, NTSTATUS, 0);
SYSCALL(NtGdiDoBanding, NTSTATUS, 0);
SYSCALL(NtGdiDoPalette, NTSTATUS, 0);
SYSCALL(NtGdiDrawEscape, NTSTATUS, 0);
SYSCALL(NtGdiDrawStream, NTSTATUS, 0);
SYSCALL(NtGdiDvpAcquireNotification, NTSTATUS, 0);
SYSCALL(NtGdiDvpCanCreateVideoPort, NTSTATUS, 0);
SYSCALL(NtGdiDvpColorControl, NTSTATUS, 0);
SYSCALL(NtGdiDvpCreateVideoPort, NTSTATUS, 0);
SYSCALL(NtGdiDvpDestroyVideoPort, NTSTATUS, 0);
SYSCALL(NtGdiDvpFlipVideoPort, NTSTATUS, 0);
SYSCALL(NtGdiDvpGetVideoPortBandwidth, NTSTATUS, 0);
SYSCALL(NtGdiDvpGetVideoPortConnectInfo, NTSTATUS, 0);
SYSCALL(NtGdiDvpGetVideoPortField, NTSTATUS, 0);
SYSCALL(NtGdiDvpGetVideoPortFlipStatus, NTSTATUS, 0);
SYSCALL(NtGdiDvpGetVideoPortInputFormats, NTSTATUS, 0);
SYSCALL(NtGdiDvpGetVideoPortLine, NTSTATUS, 0);
SYSCALL(NtGdiDvpGetVideoPortOutputFormats, NTSTATUS, 0);
SYSCALL(NtGdiDvpGetVideoSignalStatus, NTSTATUS, 0);
SYSCALL(NtGdiDvpReleaseNotification, NTSTATUS, 0);
SYSCALL(NtGdiDvpUpdateVideoPort, NTSTATUS, 0);
SYSCALL(NtGdiDvpWaitForVideoPortSync, NTSTATUS, 0);
SYSCALL(NtGdiDwmCreatedBitmapRemotingOutput, NTSTATUS, 0);
SYSCALL(NtGdiDwmGetDirtyRgn, NTSTATUS, 0);
SYSCALL(NtGdiDwmGetSurfaceData, NTSTATUS, 0);
SYSCALL(NtGdiDxgGenericThunk, NTSTATUS, 0);
SYSCALL(NtGdiEllipse, NTSTATUS, 0);
SYSCALL(NtGdiEnableEudc, NTSTATUS, 0);
SYSCALL(NtGdiEndDoc, NTSTATUS, 0);
SYSCALL(NtGdiEndGdiRendering, NTSTATUS, 0);
SYSCALL(NtGdiEndPage, NTSTATUS, 0);
SYSCALL(NtGdiEndPath, NTSTATUS, 0);
SYSCALL(NtGdiEngAlphaBlend, NTSTATUS, 0);
SYSCALL(NtGdiEngAssociateSurface, NTSTATUS, 0);
SYSCALL(NtGdiEngBitBlt, NTSTATUS, 0);
SYSCALL(NtGdiEngCheckAbort, NTSTATUS, 0);
SYSCALL(NtGdiEngComputeGlyphSet, NTSTATUS, 0);
SYSCALL(NtGdiEngCopyBits, NTSTATUS, 0);
SYSCALL(NtGdiEngCreateBitmap, NTSTATUS, 0);
SYSCALL(NtGdiEngCreateClip, NTSTATUS, 0);
SYSCALL(NtGdiEngCreateDeviceBitmap, NTSTATUS, 0);
SYSCALL(NtGdiEngCreateDeviceSurface, NTSTATUS, 0);
SYSCALL(NtGdiEngCreatePalette, NTSTATUS, 0);
SYSCALL(NtGdiEngDeleteClip, NTSTATUS, 0);
SYSCALL(NtGdiEngDeletePalette, NTSTATUS, 0);
SYSCALL(NtGdiEngDeletePath, NTSTATUS, 0);
SYSCALL(NtGdiEngDeleteSurface, NTSTATUS, 0);
SYSCALL(NtGdiEngEraseSurface, NTSTATUS, 0);
SYSCALL(NtGdiEngFillPath, NTSTATUS, 0);
SYSCALL(NtGdiEngGradientFill, NTSTATUS, 0);
SYSCALL(NtGdiEngLineTo, NTSTATUS, 0);
SYSCALL(NtGdiEngLockSurface, NTSTATUS, 0);
SYSCALL(NtGdiEngMarkBandingSurface, NTSTATUS, 0);
SYSCALL(NtGdiEngPaint, NTSTATUS, 0);
SYSCALL(NtGdiEngPlgBlt, NTSTATUS, 0);
SYSCALL(NtGdiEngStretchBlt, NTSTATUS, 0);
SYSCALL(NtGdiEngStretchBltROP, NTSTATUS, 0);
SYSCALL(NtGdiEngStrokeAndFillPath, NTSTATUS, 0);
SYSCALL(NtGdiEngStrokePath, NTSTATUS, 0);
SYSCALL(NtGdiEngTextOut, NTSTATUS, 0);
SYSCALL(NtGdiEngTransparentBlt, NTSTATUS, 0);
SYSCALL(NtGdiEngUnlockSurface, NTSTATUS, 0);
SYSCALL(NtGdiEnsureDpiDepDefaultGuiFontForPlateau, NTSTATUS, 0);
SYSCALL(NtGdiEnumFontChunk, NTSTATUS, 0);
SYSCALL(NtGdiEnumFontClose, NTSTATUS, 0);
SYSCALL(NtGdiEnumFontOpen, NTSTATUS, 0);
SYSCALL(NtGdiEnumFonts, NTSTATUS, 0);
SYSCALL(NtGdiEnumObjects, NTSTATUS, 0);
SYSCALL(NtGdiEqualRgn, NTSTATUS, 0);
SYSCALL(NtGdiEudcLoadUnloadLink, NTSTATUS, 0);
SYSCALL(NtGdiExcludeClipRect, NTSTATUS, 0);
SYSCALL(NtGdiExtCreatePen, NTSTATUS, 0);
SYSCALL(NtGdiExtCreateRegion, NTSTATUS, 0);
SYSCALL(NtGdiExtEscape, NTSTATUS, 0);
SYSCALL(NtGdiExtFloodFill, NTSTATUS, 0);
SYSCALL(NtGdiExtGetObjectW, NTSTATUS, 0);
SYSCALL(NtGdiExtSelectClipRgn, NTSTATUS, 0);
SYSCALL(NtGdiExtTextOutW, NTSTATUS, 0);
SYSCALL(NtGdiFONTOBJ_cGetAllGlyphHandles, NTSTATUS, 0);
SYSCALL(NtGdiFONTOBJ_cGetGlyphs, NTSTATUS, 0);
SYSCALL(NtGdiFONTOBJ_pQueryGlyphAttrs, NTSTATUS, 0);
SYSCALL(NtGdiFONTOBJ_pfdg, NTSTATUS, 0);
SYSCALL(NtGdiFONTOBJ_pifi, NTSTATUS, 0);
SYSCALL(NtGdiFONTOBJ_pvTrueTypeFontFile, NTSTATUS, 0);
SYSCALL(NtGdiFONTOBJ_pxoGetXform, NTSTATUS, 0);
SYSCALL(NtGdiFONTOBJ_vGetInfo, NTSTATUS, 0);
SYSCALL(NtGdiFillPath, NTSTATUS, 0);
SYSCALL(NtGdiFillRgn, NTSTATUS, 0);
SYSCALL(NtGdiFlattenPath, NTSTATUS, 0);
SYSCALL(NtGdiFlush, NTSTATUS, 0);
SYSCALL(NtGdiFontIsLinked, NTSTATUS, 0);
SYSCALL(NtGdiForceUFIMapping, NTSTATUS, 0);
SYSCALL(NtGdiFrameRgn, NTSTATUS, 0);
SYSCALL(NtGdiFullscreenControl, NTSTATUS, 0);
SYSCALL(NtGdiGetAndSetDCDword, NTSTATUS, 0);
SYSCALL(NtGdiGetAppClipBox, NTSTATUS, 0);
SYSCALL(NtGdiGetAppliedDeviceGammaRamp, NTSTATUS, 0);
SYSCALL(NtGdiGetBitmapBits, NTSTATUS, 0);
SYSCALL(NtGdiGetBitmapDimension, NTSTATUS, 0);
SYSCALL(NtGdiGetBitmapDpiScaleValue, NTSTATUS, 0);
SYSCALL(NtGdiGetBoundsRect, NTSTATUS, 0);
SYSCALL(NtGdiGetCOPPCompatibleOPMInformation, NTSTATUS, 0);
SYSCALL(NtGdiGetCertificate, NTSTATUS, 0);
SYSCALL(NtGdiGetCertificateByHandle, NTSTATUS, 0);
SYSCALL(NtGdiGetCertificateSize, NTSTATUS, 0);
SYSCALL(NtGdiGetCertificateSizeByHandle, NTSTATUS, 0);
SYSCALL(NtGdiGetCharABCWidthsW, NTSTATUS, 0);
SYSCALL(NtGdiGetCharSet, NTSTATUS, 0);
SYSCALL(NtGdiGetCharWidthInfo, NTSTATUS, 0);
SYSCALL(NtGdiGetCharWidthW, NTSTATUS, 0);
SYSCALL(NtGdiGetCharacterPlacementW, NTSTATUS, 0);
SYSCALL(NtGdiGetColorAdjustment, NTSTATUS, 0);
SYSCALL(NtGdiGetColorSpaceforBitmap, NTSTATUS, 0);
SYSCALL(NtGdiGetCurrentDpiInfo, NTSTATUS, 0);
SYSCALL(NtGdiGetDCDpiScaleValue, NTSTATUS, 0);
SYSCALL(NtGdiGetDCDword, NTSTATUS, 0);
SYSCALL(NtGdiGetDCObject, NTSTATUS, 0);
SYSCALL(NtGdiGetDCPoint, NTSTATUS, 0);
SYSCALL(NtGdiGetDCforBitmap, NTSTATUS, 0);
SYSCALL(NtGdiGetDIBitsInternal, NTSTATUS, 0);
SYSCALL(NtGdiGetDeviceCaps, NTSTATUS, 0);
SYSCALL(NtGdiGetDeviceCapsAll, NTSTATUS, 0);
SYSCALL(NtGdiGetDeviceGammaRamp, NTSTATUS, 0);
SYSCALL(NtGdiGetDeviceWidth, NTSTATUS, 0);
SYSCALL(NtGdiGetDhpdev, NTSTATUS, 0);
SYSCALL(NtGdiGetETM, NTSTATUS, 0);
SYSCALL(NtGdiGetEmbUFI, NTSTATUS, 0);
SYSCALL(NtGdiGetEmbedFonts, NTSTATUS, 0);
SYSCALL(NtGdiGetEntry, NTSTATUS, 0);
SYSCALL(NtGdiGetEudcTimeStampEx, NTSTATUS, 0);
SYSCALL(NtGdiGetFontData, NTSTATUS, 0);
SYSCALL(NtGdiGetFontFileData, NTSTATUS, 0);
SYSCALL(NtGdiGetFontFileInfo, NTSTATUS, 0);
SYSCALL(NtGdiGetFontResourceInfoInternalW, NTSTATUS, 0);
SYSCALL(NtGdiGetFontUnicodeRanges, NTSTATUS, 0);
SYSCALL(NtGdiGetGammaRampCapability, NTSTATUS, 0);
SYSCALL(NtGdiGetGlyphIndicesW, NTSTATUS, 0);
SYSCALL(NtGdiGetGlyphIndicesWInternal, NTSTATUS, 0);
SYSCALL(NtGdiGetGlyphOutline, NTSTATUS, 0);
SYSCALL(NtGdiGetKerningPairs, NTSTATUS, 0);
SYSCALL(NtGdiGetLinkedUFIs, NTSTATUS, 0);
SYSCALL(NtGdiGetMiterLimit, NTSTATUS, 0);
SYSCALL(NtGdiGetMonitorID, NTSTATUS, 0);
SYSCALL(NtGdiGetNearestColor, NTSTATUS, 0);
SYSCALL(NtGdiGetNearestPaletteIndex, NTSTATUS, 0);
SYSCALL(NtGdiGetNumberOfPhysicalMonitors, NTSTATUS, 0);
SYSCALL(NtGdiGetOPMInformation, NTSTATUS, 0);
SYSCALL(NtGdiGetOPMRandomNumber, NTSTATUS, 0);
SYSCALL(NtGdiGetObjectBitmapHandle, NTSTATUS, 0);
SYSCALL(NtGdiGetOutlineTextMetricsInternalW, NTSTATUS, 0);
SYSCALL(NtGdiGetPath, NTSTATUS, 0);
SYSCALL(NtGdiGetPerBandInfo, NTSTATUS, 0);
SYSCALL(NtGdiGetPhysicalMonitorDescription, NTSTATUS, 0);
SYSCALL(NtGdiGetPhysicalMonitors, NTSTATUS, 0);
SYSCALL(NtGdiGetPixel, NTSTATUS, 0);
SYSCALL(NtGdiGetProcessSessionFonts, NTSTATUS, 0);
SYSCALL(NtGdiGetPublicFontTableChangeCookie, NTSTATUS, 0);
SYSCALL(NtGdiGetRandomRgn, NTSTATUS, 0);
SYSCALL(NtGdiGetRasterizerCaps, NTSTATUS, 0);
SYSCALL(NtGdiGetRealizationInfo, NTSTATUS, 0);
SYSCALL(NtGdiGetRegionData, NTSTATUS, 0);
SYSCALL(NtGdiGetRgnBox, NTSTATUS, 0);
SYSCALL(NtGdiGetServerMetaFileBits, NTSTATUS, 0);
SYSCALL(NtGdiGetSpoolMessage, NTSTATUS, 0);
SYSCALL(NtGdiGetStats, NTSTATUS, 0);
SYSCALL(NtGdiGetStockObject, NTSTATUS, 0);
SYSCALL(NtGdiGetStringBitmapW, NTSTATUS, 0);
SYSCALL(NtGdiGetSuggestedOPMProtectedOutputArraySize, NTSTATUS, 0);
SYSCALL(NtGdiGetSystemPaletteUse, NTSTATUS, 0);
SYSCALL(NtGdiGetTextCharsetInfo, NTSTATUS, 0);
SYSCALL(NtGdiGetTextExtent, NTSTATUS, 0);
SYSCALL(NtGdiGetTextExtentExW, NTSTATUS, 0);
SYSCALL(NtGdiGetTextFaceW, NTSTATUS, 0);
SYSCALL(NtGdiGetTextMetricsW, NTSTATUS, 0);
SYSCALL(NtGdiGetTransform, NTSTATUS, 0);
SYSCALL(NtGdiGetUFI, NTSTATUS, 0);
SYSCALL(NtGdiGetUFIPathname, NTSTATUS, 0);
SYSCALL(NtGdiGetWidthTable, NTSTATUS, 0);
SYSCALL(NtGdiGradientFill, NTSTATUS, 0);
SYSCALL(NtGdiHLSurfGetInformation, NTSTATUS, 0);
SYSCALL(NtGdiHLSurfSetInformation, NTSTATUS, 0);
SYSCALL(NtGdiHT_Get8BPPFormatPalette, NTSTATUS, 0);
SYSCALL(NtGdiHT_Get8BPPMaskPalette, NTSTATUS, 0);
SYSCALL(NtGdiHfontCreate, NTSTATUS, 0);
SYSCALL(NtGdiIcmBrushInfo, NTSTATUS, 0);
SYSCALL(NtGdiInit, NTSTATUS, 0);
SYSCALL(NtGdiInitSpool, NTSTATUS, 0);
SYSCALL(NtGdiIntersectClipRect, NTSTATUS, 0);
SYSCALL(NtGdiInvertRgn, NTSTATUS, 0);
SYSCALL(NtGdiLineTo, NTSTATUS, 0);
SYSCALL(NtGdiMakeFontDir, NTSTATUS, 0);
SYSCALL(NtGdiMakeInfoDC, NTSTATUS, 0);
SYSCALL(NtGdiMakeObjectUnXferable, NTSTATUS, 0);
SYSCALL(NtGdiMakeObjectXferable, NTSTATUS, 0);
SYSCALL(NtGdiMaskBlt, NTSTATUS, 0);
SYSCALL(NtGdiMirrorWindowOrg, NTSTATUS, 0);
SYSCALL(NtGdiModifyWorldTransform, NTSTATUS, 0);
SYSCALL(NtGdiMonoBitmap, NTSTATUS, 0);
SYSCALL(NtGdiMoveTo, NTSTATUS, 0);
SYSCALL(NtGdiOffsetClipRgn, NTSTATUS, 0);
SYSCALL(NtGdiOffsetRgn, NTSTATUS, 0);
SYSCALL(NtGdiOpenDCW, NTSTATUS, 0);
SYSCALL(NtGdiPATHOBJ_bEnum, NTSTATUS, 0);
SYSCALL(NtGdiPATHOBJ_bEnumClipLines, NTSTATUS, 0);
SYSCALL(NtGdiPATHOBJ_vEnumStart, NTSTATUS, 0);
SYSCALL(NtGdiPATHOBJ_vEnumStartClipLines, NTSTATUS, 0);
SYSCALL(NtGdiPATHOBJ_vGetBounds, NTSTATUS, 0);
SYSCALL(NtGdiPatBlt, NTSTATUS, 0);
SYSCALL(NtGdiPathToRegion, NTSTATUS, 0);
SYSCALL(NtGdiPlgBlt, NTSTATUS, 0);
SYSCALL(NtGdiPolyDraw, NTSTATUS, 0);
SYSCALL(NtGdiPolyPatBlt, NTSTATUS, 0);
SYSCALL(NtGdiPolyPolyDraw, NTSTATUS, 0);
SYSCALL(NtGdiPolyTextOutW, NTSTATUS, 0);
SYSCALL(NtGdiPtInRegion, NTSTATUS, 0);
SYSCALL(NtGdiPtVisible, NTSTATUS, 0);
SYSCALL(NtGdiQueryFontAssocInfo, NTSTATUS, 0);
SYSCALL(NtGdiQueryFonts, NTSTATUS, 0);
SYSCALL(NtGdiRectInRegion, NTSTATUS, 0);
SYSCALL(NtGdiRectVisible, NTSTATUS, 0);
SYSCALL(NtGdiRectangle, NTSTATUS, 0);
SYSCALL(NtGdiRemoveFontMemResourceEx, NTSTATUS, 0);
SYSCALL(NtGdiRemoveFontResourceW, NTSTATUS, 0);
SYSCALL(NtGdiRemoveMergeFont, NTSTATUS, 0);
SYSCALL(NtGdiResetDC, NTSTATUS, 0);
SYSCALL(NtGdiResizePalette, NTSTATUS, 0);
SYSCALL(NtGdiRestoreDC, NTSTATUS, 0);
SYSCALL(NtGdiRoundRect, NTSTATUS, 0);
SYSCALL(NtGdiSTROBJ_bEnum, NTSTATUS, 0);
SYSCALL(NtGdiSTROBJ_bEnumPositionsOnly, NTSTATUS, 0);
SYSCALL(NtGdiSTROBJ_bGetAdvanceWidths, NTSTATUS, 0);
SYSCALL(NtGdiSTROBJ_dwGetCodePage, NTSTATUS, 0);
SYSCALL(NtGdiSTROBJ_vEnumStart, NTSTATUS, 0);
SYSCALL(NtGdiSaveDC, NTSTATUS, 0);
SYSCALL(NtGdiScaleRgn, NTSTATUS, 0);
SYSCALL(NtGdiScaleValues, NTSTATUS, 0);
SYSCALL(NtGdiScaleViewportExtEx, NTSTATUS, 0);
SYSCALL(NtGdiScaleWindowExtEx, NTSTATUS, 0);
SYSCALL(NtGdiSelectBitmap, NTSTATUS, 0);
SYSCALL(NtGdiSelectBrush, NTSTATUS, 0);
SYSCALL(NtGdiSelectClipPath, NTSTATUS, 0);
SYSCALL(NtGdiSelectFont, NTSTATUS, 0);
SYSCALL(NtGdiSelectPen, NTSTATUS, 0);
SYSCALL(NtGdiSetBitmapAttributes, NTSTATUS, 0);
SYSCALL(NtGdiSetBitmapBits, NTSTATUS, 0);
SYSCALL(NtGdiSetBitmapDimension, NTSTATUS, 0);
SYSCALL(NtGdiSetBoundsRect, NTSTATUS, 0);
SYSCALL(NtGdiSetBrushAttributes, NTSTATUS, 0);
SYSCALL(NtGdiSetBrushOrg, NTSTATUS, 0);
SYSCALL(NtGdiSetColorAdjustment, NTSTATUS, 0);
SYSCALL(NtGdiSetColorSpace, NTSTATUS, 0);
SYSCALL(NtGdiSetDIBitsToDeviceInternal, NTSTATUS, 0);
SYSCALL(NtGdiSetDeviceGammaRamp, NTSTATUS, 0);
SYSCALL(NtGdiSetFontEnumeration, NTSTATUS, 0);
SYSCALL(NtGdiSetFontXform, NTSTATUS, 0);
SYSCALL(NtGdiSetIcmMode, NTSTATUS, 0);
SYSCALL(NtGdiSetLayout, NTSTATUS, 0);
SYSCALL(NtGdiSetLinkedUFIs, NTSTATUS, 0);
SYSCALL(NtGdiSetMagicColors, NTSTATUS, 0);
SYSCALL(NtGdiSetMetaRgn, NTSTATUS, 0);
SYSCALL(NtGdiSetMiterLimit, NTSTATUS, 0);
SYSCALL(NtGdiSetOPMSigningKeyAndSequenceNumbers, NTSTATUS, 0);
SYSCALL(NtGdiSetPUMPDOBJ, NTSTATUS, 0);
SYSCALL(NtGdiSetPixel, NTSTATUS, 0);
SYSCALL(NtGdiSetPixelFormat, NTSTATUS, 0);
SYSCALL(NtGdiSetPrivateDeviceGammaRamp, NTSTATUS, 0);
SYSCALL(NtGdiSetRectRgn, NTSTATUS, 0);
SYSCALL(NtGdiSetSizeDevice, NTSTATUS, 0);
SYSCALL(NtGdiSetSystemPaletteUse, NTSTATUS, 0);
SYSCALL(NtGdiSetTextJustification, NTSTATUS, 0);
SYSCALL(NtGdiSetUMPDSandboxState, NTSTATUS, 0);
SYSCALL(NtGdiSetVirtualResolution, NTSTATUS, 0);
SYSCALL(NtGdiSetupPublicCFONT, NTSTATUS, 0);
SYSCALL(NtGdiSfmGetNotificationTokens, NTSTATUS, 0);
SYSCALL(NtGdiStartDoc, NTSTATUS, 0);
SYSCALL(NtGdiStartPage, NTSTATUS, 0);
SYSCALL(NtGdiStretchBlt, NTSTATUS, 0);
SYSCALL(NtGdiStretchDIBitsInternal, NTSTATUS, 0);
SYSCALL(NtGdiStrokeAndFillPath, NTSTATUS, 0);
SYSCALL(NtGdiStrokePath, NTSTATUS, 0);
SYSCALL(NtGdiSwapBuffers, NTSTATUS, 0);
SYSCALL(NtGdiTransformPoints, NTSTATUS, 0);
SYSCALL(NtGdiTransparentBlt, NTSTATUS, 0);
SYSCALL(NtGdiUMPDEngFreeUserMem, NTSTATUS, 0);
SYSCALL(NtGdiUnloadPrinterDriver, NTSTATUS, 0);
SYSCALL(NtGdiUnmapMemFont, NTSTATUS, 0);
SYSCALL(NtGdiUnrealizeObject, NTSTATUS, 0);
SYSCALL(NtGdiUpdateColors, NTSTATUS, 0);
SYSCALL(NtGdiUpdateTransform, NTSTATUS, 0);
SYSCALL(NtGdiWidenPath, NTSTATUS, 0);
SYSCALL(NtGdiXFORMOBJ_bApplyXform, NTSTATUS, 0);
SYSCALL(NtGdiXFORMOBJ_iGetXform, NTSTATUS, 0);
SYSCALL(NtGdiXLATEOBJ_cGetPalette, NTSTATUS, 0);
SYSCALL(NtGdiXLATEOBJ_hGetColorTransform, NTSTATUS, 0);
SYSCALL(NtGdiXLATEOBJ_iXlate, NTSTATUS, 0);
SYSCALL(NtHWCursorUpdatePointer, NTSTATUS, 0);
SYSCALL(NtIsOneCoreTransformMode, NTSTATUS, 0);
SYSCALL(NtMITActivateInputProcessing, NTSTATUS, 0);
SYSCALL(NtMITBindInputTypeToMonitors, NTSTATUS, 0);
SYSCALL(NtMITCoreMsgKGetConnectionHandle, NTSTATUS, 0);
SYSCALL(NtMITCoreMsgKOpenConnectionTo, NTSTATUS, 0);
SYSCALL(NtMITCoreMsgKSend, NTSTATUS, 0);
SYSCALL(NtMITDeactivateInputProcessing, NTSTATUS, 0);
SYSCALL(NtMITDisableMouseIntercept, NTSTATUS, 0);
SYSCALL(NtMITDispatchCompletion, NTSTATUS, 0);
SYSCALL(NtMITEnableMouseIntercept, NTSTATUS, 0);
SYSCALL(NtMITGetCursorUpdateHandle, NTSTATUS, 0);
SYSCALL(NtMITSetInputCallbacks, NTSTATUS, 0);
SYSCALL(NtMITSetInputDelegationMode, NTSTATUS, 0);
SYSCALL(NtMITSetInputSuppressionState, NTSTATUS, 0);
SYSCALL(NtMITSetKeyboardInputRoutingPolicy, NTSTATUS, 0);
SYSCALL(NtMITSetKeyboardOverriderState, NTSTATUS, 0);
SYSCALL(NtMITSetLastInputRecipient, NTSTATUS, 0);
SYSCALL(NtMITSynthesizeKeyboardInput, NTSTATUS, 0);
SYSCALL(NtMITSynthesizeMouseInput, NTSTATUS, 0);
SYSCALL(NtMITSynthesizeMouseWheel, NTSTATUS, 0);
SYSCALL(NtMITSynthesizeTouchInput, NTSTATUS, 0);
SYSCALL(NtMITUpdateInputGlobals, NTSTATUS, 0);
SYSCALL(NtMITWaitForMultipleObjectsEx, NTSTATUS, 0);
SYSCALL(NtMapVisualRelativePoints, NTSTATUS, 0);
SYSCALL(NtNotifyPresentToCompositionSurface, NTSTATUS, 0);
SYSCALL(NtOpenCompositionSurfaceDirtyRegion, NTSTATUS, 0);
SYSCALL(NtOpenCompositionSurfaceSectionInfo, NTSTATUS, 0);
SYSCALL(NtOpenCompositionSurfaceSwapChainHandleInfo, NTSTATUS, 0);
SYSCALL(NtQueryCompositionInputIsImplicit, NTSTATUS, 0);
SYSCALL(NtQueryCompositionInputQueueAndTransform, NTSTATUS, 0);
SYSCALL(NtQueryCompositionInputSink, NTSTATUS, 0);
SYSCALL(NtQueryCompositionInputSinkLuid, NTSTATUS, 0);
SYSCALL(NtQueryCompositionInputSinkViewId, NTSTATUS, 0);
SYSCALL(NtQueryCompositionSurfaceBinding, NTSTATUS, 0);
SYSCALL(NtQueryCompositionSurfaceHDRMetaData, NTSTATUS, 0);
SYSCALL(NtQueryCompositionSurfaceRenderingRealization, NTSTATUS, 0);
SYSCALL(NtQueryCompositionSurfaceStatistics, NTSTATUS, 0);
SYSCALL(NtRIMAddInputObserver, NTSTATUS, 0);
SYSCALL(NtRIMAreSiblingDevices, NTSTATUS, 0);
SYSCALL(NtRIMDeviceIoControl, NTSTATUS, 0);
SYSCALL(NtRIMEnableMonitorMappingForDevice, NTSTATUS, 0);
SYSCALL(NtRIMFreeInputBuffer, NTSTATUS, 0);
SYSCALL(NtRIMGetDevicePreparsedData, NTSTATUS, 0);
SYSCALL(NtRIMGetDevicePreparsedDataLockfree, NTSTATUS, 0);
SYSCALL(NtRIMGetDeviceProperties, NTSTATUS, 0);
SYSCALL(NtRIMGetDevicePropertiesLockfree, NTSTATUS, 0);
SYSCALL(NtRIMGetPhysicalDeviceRect, NTSTATUS, 0);
SYSCALL(NtRIMGetSourceProcessId, NTSTATUS, 0);
SYSCALL(NtRIMObserveNextInput, NTSTATUS, 0);
SYSCALL(NtRIMOnPnpNotification, NTSTATUS, 0);
SYSCALL(NtRIMOnTimerNotification, NTSTATUS, 0);
SYSCALL(NtRIMReadInput, NTSTATUS, 0);
SYSCALL(NtRIMRegisterForInput, NTSTATUS, 0);
SYSCALL(NtRIMRemoveInputObserver, NTSTATUS, 0);
SYSCALL(NtRIMSetExtendedDeviceProperty, NTSTATUS, 0);
SYSCALL(NtRIMSetTestModeStatus, NTSTATUS, 0);
SYSCALL(NtRIMUnregisterForInput, NTSTATUS, 0);
SYSCALL(NtRIMUpdateInputObserverRegistration, NTSTATUS, 0);
SYSCALL(NtSetCompositionSurfaceAnalogExclusive, NTSTATUS, 0);
SYSCALL(NtSetCompositionSurfaceBufferCompositionMode, NTSTATUS, 0);
SYSCALL(NtSetCompositionSurfaceBufferCompositionModeAndOrientation, NTSTATUS, 0);
SYSCALL(NtSetCompositionSurfaceBufferUsage, NTSTATUS, 0);
SYSCALL(NtSetCompositionSurfaceDirectFlipState, NTSTATUS, 0);
SYSCALL(NtSetCompositionSurfaceHDRMetaData, NTSTATUS, 0);
SYSCALL(NtSetCompositionSurfaceIndependentFlipInfo, NTSTATUS, 0);
SYSCALL(NtSetCompositionSurfaceOutOfFrameDirectFlipNotification, NTSTATUS, 0);
SYSCALL(NtSetCompositionSurfaceStatistics, NTSTATUS, 0);
SYSCALL(NtSetCursorInputSpace, NTSTATUS, 0);
SYSCALL(NtSetPointerDeviceInputSpace, NTSTATUS, 0);
SYSCALL(NtSetShellCursorState, NTSTATUS, 0);
SYSCALL(NtTokenManagerConfirmOutstandingAnalogToken, NTSTATUS, 0);
SYSCALL(NtTokenManagerCreateCompositionTokenHandle, NTSTATUS, 0);
SYSCALL(NtTokenManagerCreateFlipObjectReturnTokenHandle, NTSTATUS, 0);
SYSCALL(NtTokenManagerCreateFlipObjectTokenHandle, NTSTATUS, 0);
SYSCALL(NtTokenManagerDeleteOutstandingDirectFlipTokens, NTSTATUS, 0);
SYSCALL(NtTokenManagerGetAnalogExclusiveSurfaceUpdates, NTSTATUS, 0);
SYSCALL(NtTokenManagerGetAnalogExclusiveTokenEvent, NTSTATUS, 0);
SYSCALL(NtTokenManagerGetOutOfFrameDirectFlipSurfaceUpdates, NTSTATUS, 0);
SYSCALL(NtTokenManagerOpenEvent, NTSTATUS, 0);
SYSCALL(NtTokenManagerOpenSection, NTSTATUS, 0);
SYSCALL(NtTokenManagerOpenSectionAndEvents, NTSTATUS, 0);
SYSCALL(NtTokenManagerThread, NTSTATUS, 0);
SYSCALL(NtUnBindCompositionSurface, NTSTATUS, 0);
SYSCALL(NtUpdateInputSinkTransforms, NTSTATUS, 0);
SYSCALL(NtUserAcquireIAMKey, NTSTATUS, 0);
SYSCALL(NtUserAcquireInteractiveControlBackgroundAccess, NTSTATUS, 0);
SYSCALL(NtUserActivateKeyboardLayout, NTSTATUS, 0);
SYSCALL(NtUserAddClipboardFormatListener, NTSTATUS, 0);
SYSCALL(NtUserAddVisualIdentifier, NTSTATUS, 0);
SYSCALL(NtUserAlterWindowStyle, NTSTATUS, 0);
SYSCALL(NtUserAssociateInputContext, NTSTATUS, 0);
SYSCALL(NtUserAttachThreadInput, NTSTATUS, 0);
SYSCALL(NtUserAutoPromoteMouseInPointer, NTSTATUS, 0);
SYSCALL(NtUserAutoRotateScreen, NTSTATUS, 0);
SYSCALL(NtUserBeginLayoutUpdate, NTSTATUS, 0);
SYSCALL(NtUserBeginPaint, NTSTATUS, 0);
SYSCALL(NtUserBitBltSysBmp, NTSTATUS, 0);
SYSCALL(NtUserBlockInput, NTSTATUS, 0);
SYSCALL(NtUserBroadcastThemeChangeEvent, NTSTATUS, 0);
SYSCALL(NtUserBuildHimcList, NTSTATUS, 0);
SYSCALL(NtUserBuildHwndList, NTSTATUS, 0);
SYSCALL(NtUserBuildNameList, NTSTATUS, 0);
SYSCALL(NtUserBuildPropList, NTSTATUS, 0);
SYSCALL(NtUserCalcMenuBar, NTSTATUS, 0);
SYSCALL(NtUserCalculatePopupWindowPosition, NTSTATUS, 0);
SYSCALL(NtUserCallHwnd, NTSTATUS, 0);
SYSCALL(NtUserCallHwndLock, NTSTATUS, 0);
SYSCALL(NtUserCallHwndLockSafe, NTSTATUS, 0);
SYSCALL(NtUserCallHwndOpt, NTSTATUS, 0);
SYSCALL(NtUserCallHwndParam, NTSTATUS, 0);
SYSCALL(NtUserCallHwndParamLock, NTSTATUS, 0);
SYSCALL(NtUserCallHwndParamLockSafe, NTSTATUS, 0);
SYSCALL(NtUserCallHwndSafe, NTSTATUS, 0);
SYSCALL(NtUserCallMsgFilter, NTSTATUS, 0);
SYSCALL(NtUserCallNextHookEx, NTSTATUS, 0);
SYSCALL(NtUserCallNoParam, NTSTATUS, 0);
SYSCALL(NtUserCallOneParam, NTSTATUS, 0);
SYSCALL(NtUserCallTwoParam, NTSTATUS, 0);
SYSCALL(NtUserCanBrokerForceForeground, NTSTATUS, 0);
SYSCALL(NtUserChangeClipboardChain, NTSTATUS, 0);
SYSCALL(NtUserChangeDisplaySettings, NTSTATUS, 0);
SYSCALL(NtUserChangeWindowMessageFilterEx, NTSTATUS, 0);
SYSCALL(NtUserCheckAccessForIntegrityLevel, NTSTATUS, 0);
SYSCALL(NtUserCheckDesktopByThreadId, NTSTATUS, 0);
SYSCALL(NtUserCheckImeHotKey, NTSTATUS, 0);
SYSCALL(NtUserCheckMenuItem, NTSTATUS, 0);
SYSCALL(NtUserCheckProcessForClipboardAccess, NTSTATUS, 0);
SYSCALL(NtUserCheckProcessSession, NTSTATUS, 0);
SYSCALL(NtUserCheckWindowThreadDesktop, NTSTATUS, 0);
SYSCALL(NtUserChildWindowFromPointEx, NTSTATUS, 0);
SYSCALL(NtUserClearForeground, NTSTATUS, 0);
SYSCALL(NtUserClipCursor, NTSTATUS, 0);
SYSCALL(NtUserCloseClipboard, NTSTATUS, 0);
SYSCALL(NtUserCloseDesktop, NTSTATUS, 0);
SYSCALL(NtUserCloseWindowStation, NTSTATUS, 0);
SYSCALL(NtUserCompositionInputSinkLuidFromPoint, NTSTATUS, 0);
SYSCALL(NtUserCompositionInputSinkViewInstanceIdFromPoint, NTSTATUS, 0);
SYSCALL(NtUserConfigureActivationObject, NTSTATUS, 0);
SYSCALL(NtUserConfirmResizeCommit, NTSTATUS, 0);
SYSCALL(NtUserConsoleControl, NTSTATUS, 0);
SYSCALL(NtUserConvertMemHandle, NTSTATUS, 0);
SYSCALL(NtUserCopyAcceleratorTable, NTSTATUS, 0);
SYSCALL(NtUserCountClipboardFormats, NTSTATUS, 0);
SYSCALL(NtUserCreateAcceleratorTable, NTSTATUS, 0);
SYSCALL(NtUserCreateActivationObject, NTSTATUS, 0);
SYSCALL(NtUserCreateCaret, NTSTATUS, 0);
SYSCALL(NtUserCreateDCompositionHwndTarget, NTSTATUS, 0);
SYSCALL(NtUserCreateDesktop, NTSTATUS, 0);
SYSCALL(NtUserCreateDesktopEx, NTSTATUS, 0);
SYSCALL(NtUserCreateEmptyCursorObject, NTSTATUS, 0);
SYSCALL(NtUserCreateInputContext, NTSTATUS, 0);
SYSCALL(NtUserCreateLocalMemHandle, NTSTATUS, 0);
SYSCALL(NtUserCreatePalmRejectionDelayZone, NTSTATUS, 0);
SYSCALL(NtUserCreateWindowEx, NTSTATUS, 0);
SYSCALL(NtUserCreateWindowGroup, NTSTATUS, 0);
SYSCALL(NtUserCreateWindowStation, NTSTATUS, 0);
SYSCALL(NtUserCtxDisplayIOCtl, NTSTATUS, 0);
SYSCALL(NtUserDdeGetQualityOfService, NTSTATUS, 0);
SYSCALL(NtUserDdeInitialize, NTSTATUS, 0);
SYSCALL(NtUserDdeSetQualityOfService, NTSTATUS, 0);
SYSCALL(NtUserDefSetText, NTSTATUS, 0);
SYSCALL(NtUserDeferWindowDpiChanges, NTSTATUS, 0);
SYSCALL(NtUserDeferWindowPos, NTSTATUS, 0);
SYSCALL(NtUserDeferWindowPosAndBand, NTSTATUS, 0);
SYSCALL(NtUserDelegateCapturePointers, NTSTATUS, 0);
SYSCALL(NtUserDelegateInput, NTSTATUS, 0);
SYSCALL(NtUserDeleteMenu, NTSTATUS, 0);
SYSCALL(NtUserDeleteWindowGroup, NTSTATUS, 0);
SYSCALL(NtUserDestroyAcceleratorTable, NTSTATUS, 0);
SYSCALL(NtUserDestroyActivationObject, NTSTATUS, 0);
SYSCALL(NtUserDestroyCursor, NTSTATUS, 0);
SYSCALL(NtUserDestroyDCompositionHwndTarget, NTSTATUS, 0);
SYSCALL(NtUserDestroyInputContext, NTSTATUS, 0);
SYSCALL(NtUserDestroyMenu, NTSTATUS, 0);
SYSCALL(NtUserDestroyPalmRejectionDelayZone, NTSTATUS, 0);
SYSCALL(NtUserDestroyWindow, NTSTATUS, 0);
SYSCALL(NtUserDisableImmersiveOwner, NTSTATUS, 0);
SYSCALL(NtUserDisableProcessWindowFiltering, NTSTATUS, 0);
SYSCALL(NtUserDisableThreadIme, NTSTATUS, 0);
SYSCALL(NtUserDiscardPointerFrameMessages, NTSTATUS, 0);
SYSCALL(NtUserDispatchMessage, NTSTATUS, 0);
SYSCALL(NtUserDisplayConfigGetDeviceInfo, NTSTATUS, 0);
SYSCALL(NtUserDisplayConfigSetDeviceInfo, NTSTATUS, 0);
SYSCALL(NtUserDoSoundConnect, NTSTATUS, 0);
SYSCALL(NtUserDoSoundDisconnect, NTSTATUS, 0);
SYSCALL(NtUserDownlevelTouchpad, NTSTATUS, 0);
SYSCALL(NtUserDragDetect, NTSTATUS, 0);
SYSCALL(NtUserDragObject, NTSTATUS, 0);
SYSCALL(NtUserDrawAnimatedRects, NTSTATUS, 0);
SYSCALL(NtUserDrawCaption, NTSTATUS, 0);
SYSCALL(NtUserDrawCaptionTemp, NTSTATUS, 0);
SYSCALL(NtUserDrawIconEx, NTSTATUS, 0);
SYSCALL(NtUserDrawMenuBarTemp, NTSTATUS, 0);
SYSCALL(NtUserDwmGetDxRgn, NTSTATUS, 0);
SYSCALL(NtUserDwmGetRemoteSessionOcclusionEvent, NTSTATUS, 0);
SYSCALL(NtUserDwmGetRemoteSessionOcclusionState, NTSTATUS, 0);
SYSCALL(NtUserDwmHintDxUpdate, NTSTATUS, 0);
SYSCALL(NtUserDwmKernelShutdown, NTSTATUS, 0);
SYSCALL(NtUserDwmKernelStartup, NTSTATUS, 0);
SYSCALL(NtUserDwmStartRedirection, NTSTATUS, 0);
SYSCALL(NtUserDwmStopRedirection, NTSTATUS, 0);
SYSCALL(NtUserDwmValidateWindow, NTSTATUS, 0);
SYSCALL(NtUserEmptyClipboard, NTSTATUS, 0);
SYSCALL(NtUserEnableChildWindowDpiMessage, NTSTATUS, 0);
SYSCALL(NtUserEnableIAMAccess, NTSTATUS, 0);
SYSCALL(NtUserEnableMenuItem, NTSTATUS, 0);
SYSCALL(NtUserEnableMouseInPointer, NTSTATUS, 0);
SYSCALL(NtUserEnableMouseInputForCursorSuppression, NTSTATUS, 0);
SYSCALL(NtUserEnableNonClientDpiScaling, NTSTATUS, 0);
SYSCALL(NtUserEnableResizeLayoutSynchronization, NTSTATUS, 0);
SYSCALL(NtUserEnableScrollBar, NTSTATUS, 0);
SYSCALL(NtUserEnableSoftwareCursorForScreenCapture, NTSTATUS, 0);
SYSCALL(NtUserEnableTouchPad, NTSTATUS, 0);
SYSCALL(NtUserEnableWindowGDIScaledDpiMessage, NTSTATUS, 0);
SYSCALL(NtUserEnableWindowGroupPolicy, NTSTATUS, 0);
SYSCALL(NtUserEnableWindowResizeOptimization, NTSTATUS, 0);
SYSCALL(NtUserEndDeferWindowPosEx, NTSTATUS, 0);
SYSCALL(NtUserEndMenu, NTSTATUS, 0);
SYSCALL(NtUserEndPaint, NTSTATUS, 0);
SYSCALL(NtUserEndTouchOperation, NTSTATUS, 0);
SYSCALL(NtUserEnumDisplayDevices, NTSTATUS, 0);
SYSCALL(NtUserEnumDisplayMonitors, NTSTATUS, 0);
SYSCALL(NtUserEnumDisplaySettings, NTSTATUS, 0);
SYSCALL(NtUserEvent, NTSTATUS, 0);
SYSCALL(NtUserExcludeUpdateRgn, NTSTATUS, 0);
SYSCALL(NtUserFillWindow, NTSTATUS, 0);
SYSCALL(NtUserFindExistingCursorIcon, NTSTATUS, 0);
SYSCALL(NtUserFindWindowEx, NTSTATUS, 0);
SYSCALL(NtUserFlashWindowEx, NTSTATUS, 0);
SYSCALL(NtUserForceWindowToDpiForTest, NTSTATUS, 0);
SYSCALL(NtUserFrostCrashedWindow, NTSTATUS, 0);
SYSCALL(NtUserFunctionalizeDisplayConfig, NTSTATUS, 0);
SYSCALL(NtUserGetActiveProcessesDpis, NTSTATUS, 0);
SYSCALL(NtUserGetAltTabInfo, NTSTATUS, 0);
SYSCALL(NtUserGetAncestor, NTSTATUS, 0);
SYSCALL(NtUserGetAppImeLevel, NTSTATUS, 0);
SYSCALL(NtUserGetAsyncKeyState, NTSTATUS, 0);
SYSCALL(NtUserGetAtomName, NTSTATUS, 0);
SYSCALL(NtUserGetAutoRotationState, NTSTATUS, 0);
SYSCALL(NtUserGetCIMSSM, NTSTATUS, 0);
SYSCALL(NtUserGetCPD, NTSTATUS, 0);
SYSCALL(NtUserGetCaretBlinkTime, NTSTATUS, 0);
SYSCALL(NtUserGetCaretPos, NTSTATUS, 0);
SYSCALL(NtUserGetClassInfoEx, NTSTATUS, 0);
SYSCALL(NtUserGetClassName, NTSTATUS, 0);
SYSCALL(NtUserGetClipCursor, NTSTATUS, 0);
SYSCALL(NtUserGetClipboardAccessToken, NTSTATUS, 0);
SYSCALL(NtUserGetClipboardData, NTSTATUS, 0);
SYSCALL(NtUserGetClipboardFormatName, NTSTATUS, 0);
SYSCALL(NtUserGetClipboardOwner, NTSTATUS, 0);
SYSCALL(NtUserGetClipboardSequenceNumber, NTSTATUS, 0);
SYSCALL(NtUserGetClipboardViewer, NTSTATUS, 0);
SYSCALL(NtUserGetComboBoxInfo, NTSTATUS, 0);
SYSCALL(NtUserGetControlBrush, NTSTATUS, 0);
SYSCALL(NtUserGetControlColor, NTSTATUS, 0);
SYSCALL(NtUserGetCurrentDpiInfoForWindow, NTSTATUS, 0);
SYSCALL(NtUserGetCurrentInputMessageSource, NTSTATUS, 0);
SYSCALL(NtUserGetCursor, NTSTATUS, 0);
SYSCALL(NtUserGetCursorDims, NTSTATUS, 0);
SYSCALL(NtUserGetCursorFrameInfo, NTSTATUS, 0);
SYSCALL(NtUserGetCursorInfo, NTSTATUS, 0);
SYSCALL(NtUserGetDC, NTSTATUS, 0);
SYSCALL(NtUserGetDCEx, NTSTATUS, 0);
SYSCALL(NtUserGetDManipHookInitFunction, NTSTATUS, 0);
SYSCALL(NtUserGetDesktopID, NTSTATUS, 0);
SYSCALL(NtUserGetDisplayAutoRotationPreferences, NTSTATUS, 0);
SYSCALL(NtUserGetDisplayAutoRotationPreferencesByProcessId, NTSTATUS, 0);
SYSCALL(NtUserGetDisplayConfigBufferSizes, NTSTATUS, 0);
SYSCALL(NtUserGetDoubleClickTime, NTSTATUS, 0);
SYSCALL(NtUserGetDpiForCurrentProcess, NTSTATUS, 0);
SYSCALL(NtUserGetDpiForMonitor, NTSTATUS, 0);
SYSCALL(NtUserGetDpiSystemMetrics, NTSTATUS, 0);
SYSCALL(NtUserGetExtendedPointerDeviceProperty, NTSTATUS, 0);
SYSCALL(NtUserGetForegroundWindow, NTSTATUS, 0);
SYSCALL(NtUserGetGUIThreadInfo, NTSTATUS, 0);
SYSCALL(NtUserGetGestureConfig, NTSTATUS, 0);
SYSCALL(NtUserGetGestureExtArgs, NTSTATUS, 0);
SYSCALL(NtUserGetGestureInfo, NTSTATUS, 0);
SYSCALL(NtUserGetGlobalIMEStatus, NTSTATUS, 0);
SYSCALL(NtUserGetGuiResources, NTSTATUS, 0);
SYSCALL(NtUserGetHDevName, NTSTATUS, 0);
SYSCALL(NtUserGetHimetricScaleFactorFromPixelLocation, NTSTATUS, 0);
SYSCALL(NtUserGetIconInfo, NTSTATUS, 0);
SYSCALL(NtUserGetIconSize, NTSTATUS, 0);
SYSCALL(NtUserGetImeHotKey, NTSTATUS, 0);
SYSCALL(NtUserGetImeInfoEx, NTSTATUS, 0);
SYSCALL(NtUserGetInputContainerId, NTSTATUS, 0);
SYSCALL(NtUserGetInputLocaleInfo, NTSTATUS, 0);
SYSCALL(NtUserGetInteractiveControlDeviceInfo, NTSTATUS, 0);
SYSCALL(NtUserGetInteractiveControlInfo, NTSTATUS, 0);
SYSCALL(NtUserGetInteractiveCtrlSupportedWaveforms, NTSTATUS, 0);
SYSCALL(NtUserGetInternalWindowPos, NTSTATUS, 0);
SYSCALL(NtUserGetKeyNameText, NTSTATUS, 0);
SYSCALL(NtUserGetKeyState, NTSTATUS, 0);
SYSCALL(NtUserGetKeyboardLayout, NTSTATUS, 0);
SYSCALL(NtUserGetKeyboardLayoutList, NTSTATUS, 0);
SYSCALL(NtUserGetKeyboardLayoutName, NTSTATUS, 0);
SYSCALL(NtUserGetKeyboardState, NTSTATUS, 0);
SYSCALL(NtUserGetLayeredWindowAttributes, NTSTATUS, 0);
SYSCALL(NtUserGetListBoxInfo, NTSTATUS, 0);
SYSCALL(NtUserGetMenuBarInfo, NTSTATUS, 0);
SYSCALL(NtUserGetMenuIndex, NTSTATUS, 0);
SYSCALL(NtUserGetMenuItemRect, NTSTATUS, 0);
SYSCALL(NtUserGetMessage, NTSTATUS, 0);
SYSCALL(NtUserGetMonitorBrightness, NTSTATUS, 0);
SYSCALL(NtUserGetMouseMovePointsEx, NTSTATUS, 0);
SYSCALL(NtUserGetObjectInformation, NTSTATUS, 0);
SYSCALL(NtUserGetOemBitmapSize, NTSTATUS, 0);
SYSCALL(NtUserGetOpenClipboardWindow, NTSTATUS, 0);
SYSCALL(NtUserGetOwnerTransformedMonitorRect, NTSTATUS, 0);
SYSCALL(NtUserGetPhysicalDeviceRect, NTSTATUS, 0);
SYSCALL(NtUserGetPointerCursorId, NTSTATUS, 0);
SYSCALL(NtUserGetPointerDevice, NTSTATUS, 0);
SYSCALL(NtUserGetPointerDeviceCursors, NTSTATUS, 0);
SYSCALL(NtUserGetPointerDeviceOrientation, NTSTATUS, 0);
SYSCALL(NtUserGetPointerDeviceProperties, NTSTATUS, 0);
SYSCALL(NtUserGetPointerDeviceRects, NTSTATUS, 0);
SYSCALL(NtUserGetPointerDevices, NTSTATUS, 0);
SYSCALL(NtUserGetPointerFrameArrivalTimes, NTSTATUS, 0);
SYSCALL(NtUserGetPointerFrameTimes, NTSTATUS, 0);
SYSCALL(NtUserGetPointerInfoList, NTSTATUS, 0);
SYSCALL(NtUserGetPointerInputTransform, NTSTATUS, 0);
SYSCALL(NtUserGetPointerProprietaryId, NTSTATUS, 0);
SYSCALL(NtUserGetPointerType, NTSTATUS, 0);
SYSCALL(NtUserGetPrecisionTouchPadConfiguration, NTSTATUS, 0);
SYSCALL(NtUserGetPriorityClipboardFormat, NTSTATUS, 0);
SYSCALL(NtUserGetProcessDpiAwareness, NTSTATUS, 0);
SYSCALL(NtUserGetProcessDpiAwarenessContext, NTSTATUS, 0);
SYSCALL(NtUserGetProcessUIContextInformation, NTSTATUS, 0);
SYSCALL(NtUserGetProcessWindowStation, NTSTATUS, 0);
SYSCALL(NtUserGetProp, NTSTATUS, 0);
SYSCALL(NtUserGetQueueEventStatus, NTSTATUS, 0);
SYSCALL(NtUserGetQueueStatusReadonly, NTSTATUS, 0);
SYSCALL(NtUserGetRawInputBuffer, NTSTATUS, 0);
SYSCALL(NtUserGetRawInputData, NTSTATUS, 0);
SYSCALL(NtUserGetRawInputDeviceInfo, NTSTATUS, 0);
SYSCALL(NtUserGetRawInputDeviceList, NTSTATUS, 0);
SYSCALL(NtUserGetRawPointerDeviceData, NTSTATUS, 0);
SYSCALL(NtUserGetRegisteredRawInputDevices, NTSTATUS, 0);
SYSCALL(NtUserGetRequiredCursorSizes, NTSTATUS, 0);
SYSCALL(NtUserGetResizeDCompositionSynchronizationObject, NTSTATUS, 0);
SYSCALL(NtUserGetScrollBarInfo, NTSTATUS, 0);
SYSCALL(NtUserGetSystemDpiForProcess, NTSTATUS, 0);
SYSCALL(NtUserGetSystemMenu, NTSTATUS, 0);
SYSCALL(NtUserGetThreadDesktop, NTSTATUS, 0);
SYSCALL(NtUserGetThreadState, NTSTATUS, 0);
SYSCALL(NtUserGetTitleBarInfo, NTSTATUS, 0);
SYSCALL(NtUserGetTopLevelWindow, NTSTATUS, 0);
SYSCALL(NtUserGetTouchInputInfo, NTSTATUS, 0);
SYSCALL(NtUserGetTouchValidationStatus, NTSTATUS, 0);
SYSCALL(NtUserGetUniformSpaceMapping, NTSTATUS, 0);
SYSCALL(NtUserGetUpdateRect, NTSTATUS, 0);
SYSCALL(NtUserGetUpdateRgn, NTSTATUS, 0);
SYSCALL(NtUserGetUpdatedClipboardFormats, NTSTATUS, 0);
SYSCALL(NtUserGetWOWClass, NTSTATUS, 0);
SYSCALL(NtUserGetWindowBand, NTSTATUS, 0);
SYSCALL(NtUserGetWindowCompositionAttribute, NTSTATUS, 0);
SYSCALL(NtUserGetWindowCompositionInfo, NTSTATUS, 0);
SYSCALL(NtUserGetWindowDC, NTSTATUS, 0);
SYSCALL(NtUserGetWindowDisplayAffinity, NTSTATUS, 0);
SYSCALL(NtUserGetWindowFeedbackSetting, NTSTATUS, 0);
SYSCALL(NtUserGetWindowGroupId, NTSTATUS, 0);
SYSCALL(NtUserGetWindowMinimizeRect, NTSTATUS, 0);
SYSCALL(NtUserGetWindowPlacement, NTSTATUS, 0);
SYSCALL(NtUserGetWindowProcessHandle, NTSTATUS, 0);
SYSCALL(NtUserGetWindowRgnEx, NTSTATUS, 0);
SYSCALL(NtUserGhostWindowFromHungWindow, NTSTATUS, 0);
SYSCALL(NtUserHandleDelegatedInput, NTSTATUS, 0);
SYSCALL(NtUserHardErrorControl, NTSTATUS, 0);
SYSCALL(NtUserHideCaret, NTSTATUS, 0);
SYSCALL(NtUserHidePointerContactVisualization, NTSTATUS, 0);
SYSCALL(NtUserHiliteMenuItem, NTSTATUS, 0);
SYSCALL(NtUserHungWindowFromGhostWindow, NTSTATUS, 0);
SYSCALL(NtUserHwndQueryRedirectionInfo, NTSTATUS, 0);
SYSCALL(NtUserHwndSetRedirectionInfo, NTSTATUS, 0);
SYSCALL(NtUserImpersonateDdeClientWindow, NTSTATUS, 0);
SYSCALL(NtUserInheritWindowMonitor, NTSTATUS, 0);
SYSCALL(NtUserInitTask, NTSTATUS, 0);
SYSCALL(NtUserInitialize, NTSTATUS, 0);
SYSCALL(NtUserInitializeClientPfnArrays, NTSTATUS, 0);
SYSCALL(NtUserInitializeGenericHidInjection, NTSTATUS, 0);
SYSCALL(NtUserInitializeInputDeviceInjection, NTSTATUS, 0);
SYSCALL(NtUserInitializePointerDeviceInjection, NTSTATUS, 0);
SYSCALL(NtUserInitializePointerDeviceInjectionEx, NTSTATUS, 0);
SYSCALL(NtUserInitializeTouchInjection, NTSTATUS, 0);
SYSCALL(NtUserInjectDeviceInput, NTSTATUS, 0);
SYSCALL(NtUserInjectGenericHidInput, NTSTATUS, 0);
SYSCALL(NtUserInjectGesture, NTSTATUS, 0);
SYSCALL(NtUserInjectKeyboardInput, NTSTATUS, 0);
SYSCALL(NtUserInjectMouseInput, NTSTATUS, 0);
SYSCALL(NtUserInjectPointerInput, NTSTATUS, 0);
SYSCALL(NtUserInjectTouchInput, NTSTATUS, 0);
SYSCALL(NtUserInteractiveControlQueryUsage, NTSTATUS, 0);
SYSCALL(NtUserInternalClipCursor, NTSTATUS, 0);
SYSCALL(NtUserInternalGetWindowIcon, NTSTATUS, 0);
SYSCALL(NtUserInternalGetWindowText, NTSTATUS, 0);
SYSCALL(NtUserInvalidateRect, NTSTATUS, 0);
SYSCALL(NtUserInvalidateRgn, NTSTATUS, 0);
SYSCALL(NtUserIsChildWindowDpiMessageEnabled, NTSTATUS, 0);
SYSCALL(NtUserIsClipboardFormatAvailable, NTSTATUS, 0);
SYSCALL(NtUserIsMouseInPointerEnabled, NTSTATUS, 0);
SYSCALL(NtUserIsMouseInputEnabled, NTSTATUS, 0);
SYSCALL(NtUserIsNonClientDpiScalingEnabled, NTSTATUS, 0);
SYSCALL(NtUserIsResizeLayoutSynchronizationEnabled, NTSTATUS, 0);
SYSCALL(NtUserIsTopLevelWindow, NTSTATUS, 0);
SYSCALL(NtUserIsTouchWindow, NTSTATUS, 0);
SYSCALL(NtUserIsWindowBroadcastingDpiToChildren, NTSTATUS, 0);
SYSCALL(NtUserIsWindowGDIScaledDpiMessageEnabled, NTSTATUS, 0);
SYSCALL(NtUserKillTimer, NTSTATUS, 0);
SYSCALL(NtUserLayoutCompleted, NTSTATUS, 0);
SYSCALL(NtUserLinkDpiCursor, NTSTATUS, 0);
SYSCALL(NtUserLoadKeyboardLayoutEx, NTSTATUS, 0);
SYSCALL(NtUserLockCursor, NTSTATUS, 0);
SYSCALL(NtUserLockWindowStation, NTSTATUS, 0);
SYSCALL(NtUserLockWindowUpdate, NTSTATUS, 0);
SYSCALL(NtUserLockWorkStation, NTSTATUS, 0);
SYSCALL(NtUserLogicalToPerMonitorDPIPhysicalPoint, NTSTATUS, 0);
SYSCALL(NtUserLogicalToPhysicalDpiPointForWindow, NTSTATUS, 0);
SYSCALL(NtUserLogicalToPhysicalPoint, NTSTATUS, 0);
SYSCALL(NtUserMNDragLeave, NTSTATUS, 0);
SYSCALL(NtUserMNDragOver, NTSTATUS, 0);
SYSCALL(NtUserMagControl, NTSTATUS, 0);
SYSCALL(NtUserMagGetContextInformation, NTSTATUS, 0);
SYSCALL(NtUserMagSetContextInformation, NTSTATUS, 0);
SYSCALL(NtUserManageGestureHandlerWindow, NTSTATUS, 0);
SYSCALL(NtUserMapPointsByVisualIdentifier, NTSTATUS, 0);
SYSCALL(NtUserMapVirtualKeyEx, NTSTATUS, 0);
SYSCALL(NtUserMenuItemFromPoint, NTSTATUS, 0);
SYSCALL(NtUserMessageCall, NTSTATUS, 0);
SYSCALL(NtUserMinMaximize, NTSTATUS, 0);
SYSCALL(NtUserModifyUserStartupInfoFlags, NTSTATUS, 0);
SYSCALL(NtUserModifyWindowTouchCapability, NTSTATUS, 0);
SYSCALL(NtUserMoveWindow, NTSTATUS, 0);
SYSCALL(NtUserMsgWaitForMultipleObjectsEx, NTSTATUS, 0);
SYSCALL(NtUserNavigateFocus, NTSTATUS, 0);
SYSCALL(NtUserNotifyIMEStatus, NTSTATUS, 0);
SYSCALL(NtUserNotifyProcessCreate, NTSTATUS, 0);
SYSCALL(NtUserNotifyWinEvent, NTSTATUS, 0);
SYSCALL(NtUserOpenClipboard, NTSTATUS, 0);
SYSCALL(NtUserOpenDesktop, NTSTATUS, 0);
SYSCALL(NtUserOpenInputDesktop, NTSTATUS, 0);
SYSCALL(NtUserOpenThreadDesktop, NTSTATUS, 0);
SYSCALL(NtUserOpenWindowStation, NTSTATUS, 0);
SYSCALL(NtUserPaintDesktop, NTSTATUS, 0);
SYSCALL(NtUserPaintMenuBar, NTSTATUS, 0);
SYSCALL(NtUserPaintMonitor, NTSTATUS, 0);
SYSCALL(NtUserPeekMessage, NTSTATUS, 0);
SYSCALL(NtUserPerMonitorDPIPhysicalToLogicalPoint, NTSTATUS, 0);
SYSCALL(NtUserPhysicalToLogicalDpiPointForWindow, NTSTATUS, 0);
SYSCALL(NtUserPhysicalToLogicalPoint, NTSTATUS, 0);
SYSCALL(NtUserPostMessage, NTSTATUS, 0);
SYSCALL(NtUserPostThreadMessage, NTSTATUS, 0);
SYSCALL(NtUserPrintWindow, NTSTATUS, 0);
SYSCALL(NtUserProcessConnect, NTSTATUS, 0);
SYSCALL(NtUserProcessInkFeedbackCommand, NTSTATUS, 0);
SYSCALL(NtUserPromoteMouseInPointer, NTSTATUS, 0);
SYSCALL(NtUserPromotePointer, NTSTATUS, 0);
SYSCALL(NtUserQueryActivationObject, NTSTATUS, 0);
SYSCALL(NtUserQueryBSDRWindow, NTSTATUS, 0);
SYSCALL(NtUserQueryDisplayConfig, NTSTATUS, 0);
SYSCALL(NtUserQueryInformationThread, NTSTATUS, 0);
SYSCALL(NtUserQueryInputContext, NTSTATUS, 0);
SYSCALL(NtUserQuerySendMessage, NTSTATUS, 0);
SYSCALL(NtUserQueryWindow, NTSTATUS, 0);
SYSCALL(NtUserRealChildWindowFromPoint, NTSTATUS, 0);
SYSCALL(NtUserRealInternalGetMessage, NTSTATUS, 0);
SYSCALL(NtUserRealWaitMessageEx, NTSTATUS, 0);
SYSCALL(NtUserRedrawWindow, NTSTATUS, 0);
SYSCALL(NtUserRegisterBSDRWindow, NTSTATUS, 0);
SYSCALL(NtUserRegisterClassExWOW, NTSTATUS, 0);
SYSCALL(NtUserRegisterDManipHook, NTSTATUS, 0);
SYSCALL(NtUserRegisterEdgy, NTSTATUS, 0);
SYSCALL(NtUserRegisterErrorReportingDialog, NTSTATUS, 0);
SYSCALL(NtUserRegisterHotKey, NTSTATUS, 0);
SYSCALL(NtUserRegisterManipulationThread, NTSTATUS, 0);
SYSCALL(NtUserRegisterPointerDeviceNotifications, NTSTATUS, 0);
SYSCALL(NtUserRegisterPointerInputTarget, NTSTATUS, 0);
SYSCALL(NtUserRegisterRawInputDevices, NTSTATUS, 0);
SYSCALL(NtUserRegisterServicesProcess, NTSTATUS, 0);
SYSCALL(NtUserRegisterSessionPort, NTSTATUS, 0);
SYSCALL(NtUserRegisterShellPTPListener, NTSTATUS, 0);
SYSCALL(NtUserRegisterTasklist, NTSTATUS, 0);
SYSCALL(NtUserRegisterTouchHitTestingWindow, NTSTATUS, 0);
SYSCALL(NtUserRegisterTouchPadCapable, NTSTATUS, 0);
SYSCALL(NtUserRegisterUserApiHook, NTSTATUS, 0);
SYSCALL(NtUserRegisterWindowMessage, NTSTATUS, 0);
SYSCALL(NtUserReleaseDC, NTSTATUS, 0);
SYSCALL(NtUserReleaseDwmHitTestWaiters, NTSTATUS, 0);
SYSCALL(NtUserRemoteConnect, NTSTATUS, 0);
SYSCALL(NtUserRemoteRedrawRectangle, NTSTATUS, 0);
SYSCALL(NtUserRemoteRedrawScreen, NTSTATUS, 0);
SYSCALL(NtUserRemoteStopScreenUpdates, NTSTATUS, 0);
SYSCALL(NtUserRemoveClipboardFormatListener, NTSTATUS, 0);
SYSCALL(NtUserRemoveInjectionDevice, NTSTATUS, 0);
SYSCALL(NtUserRemoveMenu, NTSTATUS, 0);
SYSCALL(NtUserRemoveProp, NTSTATUS, 0);
SYSCALL(NtUserRemoveVisualIdentifier, NTSTATUS, 0);
SYSCALL(NtUserReportInertia, NTSTATUS, 0);
SYSCALL(NtUserRequestMoveSizeOperation, NTSTATUS, 0);
SYSCALL(NtUserResolveDesktop, NTSTATUS, 0);
SYSCALL(NtUserResolveDesktopForWOW, NTSTATUS, 0);
SYSCALL(NtUserRestoreWindowDpiChanges, NTSTATUS, 0);
SYSCALL(NtUserSBGetParms, NTSTATUS, 0);
SYSCALL(NtUserScrollDC, NTSTATUS, 0);
SYSCALL(NtUserScrollWindowEx, NTSTATUS, 0);
SYSCALL(NtUserSelectPalette, NTSTATUS, 0);
SYSCALL(NtUserSendEventMessage, NTSTATUS, 0);
SYSCALL(NtUserSendInput, NTSTATUS, 0);
SYSCALL(NtUserSendInteractiveControlHapticsReport, NTSTATUS, 0);
SYSCALL(NtUserSendTouchInput, NTSTATUS, 0);
SYSCALL(NtUserSetActivationFilter, NTSTATUS, 0);
SYSCALL(NtUserSetActiveProcess, NTSTATUS, 0);
SYSCALL(NtUserSetActiveProcessForMonitor, NTSTATUS, 0);
SYSCALL(NtUserSetActiveWindow, NTSTATUS, 0);
SYSCALL(NtUserSetAppImeLevel, NTSTATUS, 0);
SYSCALL(NtUserSetAutoRotation, NTSTATUS, 0);
SYSCALL(NtUserSetBridgeWindowChild, NTSTATUS, 0);
SYSCALL(NtUserSetBrokeredForeground, NTSTATUS, 0);
SYSCALL(NtUserSetCalibrationData, NTSTATUS, 0);
SYSCALL(NtUserSetCapture, NTSTATUS, 0);
SYSCALL(NtUserSetChildWindowNoActivate, NTSTATUS, 0);
SYSCALL(NtUserSetClassLong, NTSTATUS, 0);
SYSCALL(NtUserSetClassLongPtr, NTSTATUS, 0);
SYSCALL(NtUserSetClassWord, NTSTATUS, 0);
SYSCALL(NtUserSetClipboardData, NTSTATUS, 0);
SYSCALL(NtUserSetClipboardViewer, NTSTATUS, 0);
SYSCALL(NtUserSetConsoleReserveKeys, NTSTATUS, 0);
SYSCALL(NtUserSetCoreWindow, NTSTATUS, 0);
SYSCALL(NtUserSetCoreWindowPartner, NTSTATUS, 0);
SYSCALL(NtUserSetCursor, NTSTATUS, 0);
SYSCALL(NtUserSetCursorContents, NTSTATUS, 0);
SYSCALL(NtUserSetCursorIconData, NTSTATUS, 0);
SYSCALL(NtUserSetCursorPos, NTSTATUS, 0);
SYSCALL(NtUserSetDesktopColorTransform, NTSTATUS, 0);
SYSCALL(NtUserSetDialogControlDpiChangeBehavior, NTSTATUS, 0);
SYSCALL(NtUserSetDimUndimTransitionTime, NTSTATUS, 0);
SYSCALL(NtUserSetDisplayAutoRotationPreferences, NTSTATUS, 0);
SYSCALL(NtUserSetDisplayConfig, NTSTATUS, 0);
SYSCALL(NtUserSetDisplayMapping, NTSTATUS, 0);
SYSCALL(NtUserSetFallbackForeground, NTSTATUS, 0);
SYSCALL(NtUserSetFeatureReportResponse, NTSTATUS, 0);
SYSCALL(NtUserSetFocus, NTSTATUS, 0);
SYSCALL(NtUserSetForegroundWindowForApplication, NTSTATUS, 0);
SYSCALL(NtUserSetGestureConfig, NTSTATUS, 0);
SYSCALL(NtUserSetImeHotKey, NTSTATUS, 0);
SYSCALL(NtUserSetImeInfoEx, NTSTATUS, 0);
SYSCALL(NtUserSetImeOwnerWindow, NTSTATUS, 0);
SYSCALL(NtUserSetImmersiveBackgroundWindow, NTSTATUS, 0);
SYSCALL(NtUserSetInformationProcess, NTSTATUS, 0);
SYSCALL(NtUserSetInformationThread, NTSTATUS, 0);
SYSCALL(NtUserSetInteractiveControlFocus, NTSTATUS, 0);
SYSCALL(NtUserSetInteractiveCtrlRotationAngle, NTSTATUS, 0);
SYSCALL(NtUserSetInternalWindowPos, NTSTATUS, 0);
SYSCALL(NtUserSetKeyboardState, NTSTATUS, 0);
SYSCALL(NtUserSetLayeredWindowAttributes, NTSTATUS, 0);
SYSCALL(NtUserSetLogonNotifyWindow, NTSTATUS, 0);
SYSCALL(NtUserSetMagnificationDesktopMagnifierOffsetsDWMUpdated, NTSTATUS, 0);
SYSCALL(NtUserSetManipulationInputTarget, NTSTATUS, 0);
SYSCALL(NtUserSetMenu, NTSTATUS, 0);
SYSCALL(NtUserSetMenuContextHelpId, NTSTATUS, 0);
SYSCALL(NtUserSetMenuDefaultItem, NTSTATUS, 0);
SYSCALL(NtUserSetMenuFlagRtoL, NTSTATUS, 0);
SYSCALL(NtUserSetMirrorRendering, NTSTATUS, 0);
SYSCALL(NtUserSetMonitorBrightness, NTSTATUS, 0);
SYSCALL(NtUserSetObjectInformation, NTSTATUS, 0);
SYSCALL(NtUserSetParent, NTSTATUS, 0);
SYSCALL(NtUserSetPrecisionTouchPadConfiguration, NTSTATUS, 0);
SYSCALL(NtUserSetProcessDPIAware, NTSTATUS, 0);
SYSCALL(NtUserSetProcessDpiAwareness, NTSTATUS, 0);
SYSCALL(NtUserSetProcessDpiAwarenessContext, NTSTATUS, 0);
SYSCALL(NtUserSetProcessInteractionFlags, NTSTATUS, 0);
SYSCALL(NtUserSetProcessMousewheelRoutingMode, NTSTATUS, 0);
SYSCALL(NtUserSetProcessRestrictionExemption, NTSTATUS, 0);
SYSCALL(NtUserSetProcessUIAccessZorder, NTSTATUS, 0);
SYSCALL(NtUserSetProcessWindowStation, NTSTATUS, 0);
SYSCALL(NtUserSetProp, NTSTATUS, 0);
SYSCALL(NtUserSetScrollInfo, NTSTATUS, 0);
SYSCALL(NtUserSetSensorPresence, NTSTATUS, 0);
SYSCALL(NtUserSetShellWindowEx, NTSTATUS, 0);
SYSCALL(NtUserSetSysColors, NTSTATUS, 0);
SYSCALL(NtUserSetSystemCursor, NTSTATUS, 0);
SYSCALL(NtUserSetSystemMenu, NTSTATUS, 0);
SYSCALL(NtUserSetSystemTimer, NTSTATUS, 0);
SYSCALL(NtUserSetTargetForResourceBrokering, NTSTATUS, 0);
SYSCALL(NtUserSetThreadDesktop, NTSTATUS, 0);
SYSCALL(NtUserSetThreadInputBlocked, NTSTATUS, 0);
SYSCALL(NtUserSetThreadLayoutHandles, NTSTATUS, 0);
SYSCALL(NtUserSetThreadState, NTSTATUS, 0);
SYSCALL(NtUserSetTimer, NTSTATUS, 0);
SYSCALL(NtUserSetWinEventHook, NTSTATUS, 0);
SYSCALL(NtUserSetWindowArrangement, NTSTATUS, 0);
SYSCALL(NtUserSetWindowBand, NTSTATUS, 0);
SYSCALL(NtUserSetWindowCompositionAttribute, NTSTATUS, 0);
SYSCALL(NtUserSetWindowCompositionTransition, NTSTATUS, 0);
SYSCALL(NtUserSetWindowDisplayAffinity, NTSTATUS, 0);
SYSCALL(NtUserSetWindowFNID, NTSTATUS, 0);
SYSCALL(NtUserSetWindowFeedbackSetting, NTSTATUS, 0);
SYSCALL(NtUserSetWindowGroup, NTSTATUS, 0);
SYSCALL(NtUserSetWindowLong, NTSTATUS, 0);
SYSCALL(NtUserSetWindowLongPtr, NTSTATUS, 0);
SYSCALL(NtUserSetWindowPlacement, NTSTATUS, 0);
SYSCALL(NtUserSetWindowPos, NTSTATUS, 0);
SYSCALL(NtUserSetWindowRgn, NTSTATUS, 0);
SYSCALL(NtUserSetWindowRgnEx, NTSTATUS, 0);
SYSCALL(NtUserSetWindowShowState, NTSTATUS, 0);
SYSCALL(NtUserSetWindowStationUser, NTSTATUS, 0);
SYSCALL(NtUserSetWindowWord, NTSTATUS, 0);
SYSCALL(NtUserSetWindowsHookAW, NTSTATUS, 0);
SYSCALL(NtUserSetWindowsHookEx, NTSTATUS, 0);
SYSCALL(NtUserSfmDestroyLogicalSurfaceBinding, NTSTATUS, 0);
SYSCALL(NtUserSfmDxBindSwapChain, NTSTATUS, 0);
SYSCALL(NtUserSfmDxGetSwapChainStats, NTSTATUS, 0);
SYSCALL(NtUserSfmDxOpenSwapChain, NTSTATUS, 0);
SYSCALL(NtUserSfmDxQuerySwapChainBindingStatus, NTSTATUS, 0);
SYSCALL(NtUserSfmDxReleaseSwapChain, NTSTATUS, 0);
SYSCALL(NtUserSfmDxReportPendingBindingsToDwm, NTSTATUS, 0);
SYSCALL(NtUserSfmDxSetSwapChainBindingStatus, NTSTATUS, 0);
SYSCALL(NtUserSfmDxSetSwapChainStats, NTSTATUS, 0);
SYSCALL(NtUserSfmGetLogicalSurfaceBinding, NTSTATUS, 0);
SYSCALL(NtUserShowCaret, NTSTATUS, 0);
SYSCALL(NtUserShowCursor, NTSTATUS, 0);
SYSCALL(NtUserShowScrollBar, NTSTATUS, 0);
SYSCALL(NtUserShowSystemCursor, NTSTATUS, 0);
SYSCALL(NtUserShowWindow, NTSTATUS, 0);
SYSCALL(NtUserShowWindowAsync, NTSTATUS, 0);
SYSCALL(NtUserShutdownBlockReasonCreate, NTSTATUS, 0);
SYSCALL(NtUserShutdownBlockReasonQuery, NTSTATUS, 0);
SYSCALL(NtUserShutdownReasonDestroy, NTSTATUS, 0);
SYSCALL(NtUserSignalRedirectionStartComplete, NTSTATUS, 0);
SYSCALL(NtUserSlicerControl, NTSTATUS, 0);
SYSCALL(NtUserSoundSentry, NTSTATUS, 0);
SYSCALL(NtUserStopAndEndInertia, NTSTATUS, 0);
SYSCALL(NtUserSwitchDesktop, NTSTATUS, 0);
SYSCALL(NtUserSystemParametersInfo, NTSTATUS, 0);
SYSCALL(NtUserSystemParametersInfoForDpi, NTSTATUS, 0);
SYSCALL(NtUserTestForInteractiveUser, NTSTATUS, 0);
SYSCALL(NtUserThunkedMenuInfo, NTSTATUS, 0);
SYSCALL(NtUserThunkedMenuItemInfo, NTSTATUS, 0);
SYSCALL(NtUserToUnicodeEx, NTSTATUS, 0);
SYSCALL(NtUserTrackMouseEvent, NTSTATUS, 0);
SYSCALL(NtUserTrackPopupMenuEx, NTSTATUS, 0);
SYSCALL(NtUserTransformPoint, NTSTATUS, 0);
SYSCALL(NtUserTransformRect, NTSTATUS, 0);
SYSCALL(NtUserTranslateAccelerator, NTSTATUS, 0);
SYSCALL(NtUserTranslateMessage, NTSTATUS, 0);
SYSCALL(NtUserUndelegateInput, NTSTATUS, 0);
SYSCALL(NtUserUnhookWinEvent, NTSTATUS, 0);
SYSCALL(NtUserUnhookWindowsHookEx, NTSTATUS, 0);
SYSCALL(NtUserUnloadKeyboardLayout, NTSTATUS, 0);
SYSCALL(NtUserUnlockWindowStation, NTSTATUS, 0);
SYSCALL(NtUserUnregisterClass, NTSTATUS, 0);
SYSCALL(NtUserUnregisterHotKey, NTSTATUS, 0);
SYSCALL(NtUserUnregisterSessionPort, NTSTATUS, 0);
SYSCALL(NtUserUnregisterUserApiHook, NTSTATUS, 0);
SYSCALL(NtUserUpdateDefaultDesktopThumbnail, NTSTATUS, 0);
SYSCALL(NtUserUpdateInputContext, NTSTATUS, 0);
SYSCALL(NtUserUpdateInstance, NTSTATUS, 0);
SYSCALL(NtUserUpdateLayeredWindow, NTSTATUS, 0);
SYSCALL(NtUserUpdatePerUserSystemParameters, NTSTATUS, 0);
SYSCALL(NtUserUpdateWindowInputSinkHints, NTSTATUS, 0);
SYSCALL(NtUserUpdateWindowTrackingInfo, NTSTATUS, 0);
SYSCALL(NtUserUpdateWindowTransform, NTSTATUS, 0);
SYSCALL(NtUserUserHandleGrantAccess, NTSTATUS, 0);
SYSCALL(NtUserValidateHandleSecure, NTSTATUS, 0);
SYSCALL(NtUserValidateRect, NTSTATUS, 0);
SYSCALL(NtUserValidateTimerCallback, NTSTATUS, 0);
SYSCALL(NtUserVkKeyScanEx, NTSTATUS, 0);
SYSCALL(NtUserWOWCleanup, NTSTATUS, 0);
SYSCALL(NtUserWaitAvailableMessageEx, NTSTATUS, 0);
SYSCALL(NtUserWaitForInputIdle, NTSTATUS, 0);
SYSCALL(NtUserWaitForMsgAndEvent, NTSTATUS, 0);
SYSCALL(NtUserWaitForRedirectionStartComplete, NTSTATUS, 0);
SYSCALL(NtUserWaitMessage, NTSTATUS, 0);
SYSCALL(NtUserWin32PoolAllocationStats, NTSTATUS, 0);
SYSCALL(NtUserWindowFromDC, NTSTATUS, 0);
SYSCALL(NtUserWindowFromPhysicalPoint, NTSTATUS, 0);
SYSCALL(NtUserWindowFromPoint, NTSTATUS, 0);
SYSCALL(NtUserYieldTask, NTSTATUS, 0);
SYSCALL(NtValidateCompositionSurfaceHandle, NTSTATUS, 0);
SYSCALL(NtVisualCaptureBits, NTSTATUS, 0);

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

#endif
