/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2016 Tamas K Lengyel.                                  *
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

/*
 * From http://laredo-13.mit.edu/~brendan/scproto.txt
 *
 * TODO Integrate argument extraction into syscall monitoring
 */

#ifndef SYSCALLS_PROTOTYPES_H
#define SYSCALLS_PROTOTYPES_H

/*
NTSTATUS NtAcceptConnectPort (__out PHANDLE PortHandle, __in_opt PVOID PortContext, __in PPORT_MESSAGE ConnectionRequest, __in BOOLEAN AcceptConnection, __inout_opt PPORT_VIEW ServerView, __out_opt PREMOTE_PORT_VIEW ClientView)
NTSTATUS NtAccessCheckAndAuditAlarm (__in PUNICODE_STRING SubsystemName, __in_opt PVOID HandleId, __in PUNICODE_STRING ObjectTypeName, __in PUNICODE_STRING ObjectName, __in PSECURITY_DESCRIPTOR SecurityDescriptor, __in ACCESS_MASK DesiredAccess, __in PGENERIC_MAPPING GenericMapping, __in BOOLEAN ObjectCreation, __out PACCESS_MASK GrantedAccess, __out PNTSTATUS AccessStatus, __out PBOOLEAN GenerateOnClose)
NTSTATUS NtAccessCheckByTypeAndAuditAlarm (__in PUNICODE_STRING SubsystemName, __in_opt PVOID HandleId, __in PUNICODE_STRING ObjectTypeName, __in PUNICODE_STRING ObjectName, __in PSECURITY_DESCRIPTOR SecurityDescriptor, __in_opt PSID PrincipalSelfSid, __in ACCESS_MASK DesiredAccess, __in AUDIT_EVENT_TYPE AuditType, __in ULONG Flags, __in_ecount_opt(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList, __in ULONG ObjectTypeListLength, __in PGENERIC_MAPPING GenericMapping, __in BOOLEAN ObjectCreation, __out PACCESS_MASK GrantedAccess, __out PNTSTATUS AccessStatus, __out PBOOLEAN GenerateOnClose)
NTSTATUS NtAccessCheckByType (__in PSECURITY_DESCRIPTOR SecurityDescriptor, __in_opt PSID PrincipalSelfSid, __in HANDLE ClientToken, __in ACCESS_MASK DesiredAccess, __in_ecount(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList, __in ULONG ObjectTypeListLength, __in PGENERIC_MAPPING GenericMapping, __out_bcount(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet, __inout PULONG PrivilegeSetLength, __out PACCESS_MASK GrantedAccess, __out PNTSTATUS AccessStatus)
NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarmByHandle (__in PUNICODE_STRING SubsystemName, __in_opt PVOID HandleId, __in HANDLE ClientToken, __in PUNICODE_STRING ObjectTypeName, __in PUNICODE_STRING ObjectName, __in PSECURITY_DESCRIPTOR SecurityDescriptor, __in_opt PSID PrincipalSelfSid, __in ACCESS_MASK DesiredAccess, __in AUDIT_EVENT_TYPE AuditType, __in ULONG Flags, __in_ecount_opt(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList, __in ULONG ObjectTypeListLength, __in PGENERIC_MAPPING GenericMapping, __in BOOLEAN ObjectCreation, __out_ecount(ObjectTypeListLength) PACCESS_MASK GrantedAccess, __out_ecount(ObjectTypeListLength) PNTSTATUS AccessStatus, __out PBOOLEAN GenerateOnClose)
NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarm (__in PUNICODE_STRING SubsystemName, __in_opt PVOID HandleId, __in PUNICODE_STRING ObjectTypeName, __in PUNICODE_STRING ObjectName, __in PSECURITY_DESCRIPTOR SecurityDescriptor, __in_opt PSID PrincipalSelfSid, __in ACCESS_MASK DesiredAccess, __in AUDIT_EVENT_TYPE AuditType, __in ULONG Flags, __in_ecount_opt(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList, __in ULONG ObjectTypeListLength, __in PGENERIC_MAPPING GenericMapping, __in BOOLEAN ObjectCreation, __out_ecount(ObjectTypeListLength) PACCESS_MASK GrantedAccess, __out_ecount(ObjectTypeListLength) PNTSTATUS AccessStatus, __out PBOOLEAN GenerateOnClose)
NTSTATUS NtAccessCheckByTypeResultList (__in PSECURITY_DESCRIPTOR SecurityDescriptor, __in_opt PSID PrincipalSelfSid, __in HANDLE ClientToken, __in ACCESS_MASK DesiredAccess, __in_ecount(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList, __in ULONG ObjectTypeListLength, __in PGENERIC_MAPPING GenericMapping, __out_bcount(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet, __inout PULONG PrivilegeSetLength, __out_ecount(ObjectTypeListLength) PACCESS_MASK GrantedAccess, __out_ecount(ObjectTypeListLength) PNTSTATUS AccessStatus)
NTSTATUS NtAccessCheck (__in PSECURITY_DESCRIPTOR SecurityDescriptor, __in HANDLE ClientToken, __in ACCESS_MASK DesiredAccess, __in PGENERIC_MAPPING GenericMapping, __out_bcount(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet, __inout PULONG PrivilegeSetLength, __out PACCESS_MASK GrantedAccess, __out PNTSTATUS AccessStatus)
NTSTATUS NtAddAtom (__in_bcount_opt(Length) PWSTR AtomName, __in ULONG Length, __out_opt PRTL_ATOM Atom)
NTSTATUS NtAddBootEntry (__in PBOOT_ENTRY BootEntry, __out_opt PULONG Id)
NTSTATUS NtAddDriverEntry (__in PEFI_DRIVER_ENTRY DriverEntry, __out_opt PULONG Id)
NTSTATUS NtAdjustGroupsToken (__in HANDLE TokenHandle, __in BOOLEAN ResetToDefault, __in PTOKEN_GROUPS NewState, __in ULONG BufferLength, __out_bcount_part_opt(BufferLength,*ReturnLength) PTOKEN_GROUPS PreviousState, __out PULONG ReturnLength)
NTSTATUS NtAdjustPrivilegesToken (__in HANDLE TokenHandle, __in BOOLEAN DisableAllPrivileges, __in_opt PTOKEN_PRIVILEGES NewState, __in ULONG BufferLength, __out_bcount_part_opt(BufferLength,*ReturnLength) PTOKEN_PRIVILEGES PreviousState, __out_opt PULONG ReturnLength)
NTSTATUS NtAlertResumeThread (__in HANDLE ThreadHandle, __out_opt PULONG PreviousSuspendCount)
NTSTATUS NtAlertThread (__in HANDLE ThreadHandle)
NTSTATUS NtAllocateLocallyUniqueId (__out PLUID Luid)
NTSTATUS NtAllocateReserveObject (__out PHANDLE MemoryReserveHandle, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in MEMORY_RESERVE_TYPE Type)
NTSTATUS NtAllocateUserPhysicalPages (__in HANDLE ProcessHandle, __inout PULONG_PTR NumberOfPages, __out_ecount(*NumberOfPages) PULONG_PTR UserPfnArray)
NTSTATUS NtAllocateUuids (__out PULARGE_INTEGER Time, __out PULONG Range, __out PULONG Sequence, __out PCHAR Seed)
NTSTATUS NtAllocateVirtualMemory (__in HANDLE ProcessHandle, __inout PVOID *BaseAddress, __in ULONG_PTR ZeroBits, __inout PSIZE_T RegionSize, __in ULONG AllocationType, __in ULONG Protect)
NTSTATUS NtAlpcAcceptConnectPort (__out PHANDLE PortHandle, __in HANDLE ConnectionPortHandle, __in ULONG Flags, __in POBJECT_ATTRIBUTES ObjectAttributes, __in PALPC_PORT_ATTRIBUTES PortAttributes, __in_opt PVOID PortContext, __in PPORT_MESSAGE ConnectionRequest, __inout_opt PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes, __in BOOLEAN AcceptConnection)
NTSTATUS NtAlpcCancelMessage (__in HANDLE PortHandle, __in ULONG Flags, __in PALPC_CONTEXT_ATTR MessageContext)
NTSTATUS NtAlpcConnectPort (__out PHANDLE PortHandle, __in PUNICODE_STRING PortName, __in POBJECT_ATTRIBUTES ObjectAttributes, __in_opt PALPC_PORT_ATTRIBUTES PortAttributes, __in ULONG Flags, __in_opt PSID RequiredServerSid, __inout PPORT_MESSAGE ConnectionMessage, __inout_opt PULONG BufferLength, __inout_opt PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes, __inout_opt PALPC_MESSAGE_ATTRIBUTES InMessageAttributes, __in_opt PLARGE_INTEGER Timeout)
NTSTATUS NtAlpcCreatePort (__out PHANDLE PortHandle, __in POBJECT_ATTRIBUTES ObjectAttributes, __in_opt PALPC_PORT_ATTRIBUTES PortAttributes)
NTSTATUS NtAlpcCreatePortSection (__in HANDLE PortHandle, __in ULONG Flags, __in_opt HANDLE SectionHandle, __in SIZE_T SectionSize, __out PALPC_HANDLE AlpcSectionHandle, __out PSIZE_T ActualSectionSize)
NTSTATUS NtAlpcCreateResourceReserve (__in HANDLE PortHandle, __reserved ULONG Flags, __in SIZE_T MessageSize, __out PALPC_HANDLE ResourceId)
NTSTATUS NtAlpcCreateSectionView (__in HANDLE PortHandle, __reserved ULONG Flags, __inout PALPC_DATA_VIEW_ATTR ViewAttributes)
NTSTATUS NtAlpcCreateSecurityContext (__in HANDLE PortHandle, __reserved ULONG Flags, __inout PALPC_SECURITY_ATTR SecurityAttribute)
NTSTATUS NtAlpcDeletePortSection (__in HANDLE PortHandle, __reserved ULONG Flags, __in ALPC_HANDLE SectionHandle)
NTSTATUS NtAlpcDeleteResourceReserve (__in HANDLE PortHandle, __reserved ULONG Flags, __in ALPC_HANDLE ResourceId)
NTSTATUS NtAlpcDeleteSectionView (__in HANDLE PortHandle, __reserved ULONG Flags, __in PVOID ViewBase)
NTSTATUS NtAlpcDeleteSecurityContext (__in HANDLE PortHandle, __reserved ULONG Flags, __in ALPC_HANDLE ContextHandle)
NTSTATUS NtAlpcDisconnectPort (__in HANDLE PortHandle, __in ULONG Flags)
NTSTATUS NtAlpcImpersonateClientOfPort (__in HANDLE PortHandle, __in PPORT_MESSAGE PortMessage, __reserved PVOID Reserved)
NTSTATUS NtAlpcOpenSenderProcess (__out PHANDLE ProcessHandle, __in HANDLE PortHandle, __in PPORT_MESSAGE PortMessage, __reserved ULONG Flags, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtAlpcOpenSenderThread (__out PHANDLE ThreadHandle, __in HANDLE PortHandle, __in PPORT_MESSAGE PortMessage, __reserved ULONG Flags, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtAlpcQueryInformation (__in HANDLE PortHandle, __in ALPC_PORT_INFORMATION_CLASS PortInformationClass, __out_bcount(Length) PVOID PortInformation, __in ULONG Length, __out_opt PULONG ReturnLength)
NTSTATUS NtAlpcQueryInformationMessage (__in HANDLE PortHandle, __in PPORT_MESSAGE PortMessage, __in ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass, __out_bcount(Length) PVOID MessageInformation, __in ULONG Length, __out_opt PULONG ReturnLength)
NTSTATUS NtAlpcRevokeSecurityContext (__in HANDLE PortHandle, __reserved ULONG Flags, __in ALPC_HANDLE ContextHandle)
NTSTATUS NtAlpcSendWaitReceivePort (__in HANDLE PortHandle, __in ULONG Flags, __in_opt PPORT_MESSAGE SendMessage, __in_opt PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes, __inout_opt PPORT_MESSAGE ReceiveMessage, __inout_opt PULONG BufferLength, __inout_opt PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes, __in_opt PLARGE_INTEGER Timeout)
NTSTATUS NtAlpcSetInformation (__in HANDLE PortHandle, __in ALPC_PORT_INFORMATION_CLASS PortInformationClass, __in_bcount(Length) PVOID PortInformation, __in ULONG Length)
NTSTATUS NtApphelpCacheControl (__in APPHELPCOMMAND type, __in PVOID buf)
NTSTATUS NtAreMappedFilesTheSame (__in PVOID File1MappedAsAnImage, __in PVOID File2MappedAsFile)
NTSTATUS NtAssignProcessToJobObject (__in HANDLE JobHandle, __in HANDLE ProcessHandle)
NTSTATUS NtCallbackReturn (__in_opt PVOID OutputBuffer, __in ULONG OutputLength, __in NTSTATUS Status)
NTSTATUS NtCancelIoFileEx (__in HANDLE FileHandle, __in_opt PIO_STATUS_BLOCK IoRequestToCancel, __out PIO_STATUS_BLOCK IoStatusBlock)
NTSTATUS NtCancelIoFile (__in HANDLE FileHandle, __out PIO_STATUS_BLOCK IoStatusBlock)
NTSTATUS NtCancelSynchronousIoFile (__in HANDLE ThreadHandle, __in_opt PIO_STATUS_BLOCK IoRequestToCancel, __out PIO_STATUS_BLOCK IoStatusBlock)
NTSTATUS NtCancelTimer (__in HANDLE TimerHandle, __out_opt PBOOLEAN CurrentState)
NTSTATUS NtClearEvent (__in HANDLE EventHandle)
NTSTATUS NtClose (__in HANDLE Handle)
NTSTATUS NtCloseObjectAuditAlarm (__in PUNICODE_STRING SubsystemName, __in_opt PVOID HandleId, __in BOOLEAN GenerateOnClose)
NTSTATUS NtCommitComplete (__in HANDLE EnlistmentHandle, __in_opt PLARGE_INTEGER TmVirtualClock)
NTSTATUS NtCommitEnlistment (__in HANDLE EnlistmentHandle, __in_opt PLARGE_INTEGER TmVirtualClock)
NTSTATUS NtCommitTransaction (__in HANDLE TransactionHandle, __in BOOLEAN Wait)
NTSTATUS NtCompactKeys (__in ULONG Count, __in_ecount(Count) HANDLE KeyArray[])
NTSTATUS NtCompareTokens (__in HANDLE FirstTokenHandle, __in HANDLE SecondTokenHandle, __out PBOOLEAN Equal)
NTSTATUS NtCompleteConnectPort (__in HANDLE PortHandle)
NTSTATUS NtCompressKey (__in HANDLE Key)
NTSTATUS NtConnectPort (__out PHANDLE PortHandle, __in PUNICODE_STRING PortName, __in PSECURITY_QUALITY_OF_SERVICE SecurityQos, __inout_opt PPORT_VIEW ClientView, __inout_opt PREMOTE_PORT_VIEW ServerView, __out_opt PULONG MaxMessageLength, __inout_opt PVOID ConnectionInformation, __inout_opt PULONG ConnectionInformationLength)
NTSTATUS NtContinue (__out PCONTEXT ContextRecord, __out BOOLEAN TestAlert)
NTSTATUS NtCreateDebugObject (__out PHANDLE DebugObjectHandle, __out ACCESS_MASK DesiredAccess, __out POBJECT_ATTRIBUTES ObjectAttributes, __out ULONG Flags)
NTSTATUS NtCreateDirectoryObject (__out PHANDLE DirectoryHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtCreateEnlistment (__out PHANDLE EnlistmentHandle, __in ACCESS_MASK DesiredAccess, __in HANDLE ResourceManagerHandle, __in HANDLE TransactionHandle, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in_opt ULONG CreateOptions, __in NOTIFICATION_MASK NotificationMask, __in_opt PVOID EnlistmentKey)
NTSTATUS NtCreateEvent (__out PHANDLE EventHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in EVENT_TYPE EventType, __in BOOLEAN InitialState)
NTSTATUS NtCreateEventPair (__out PHANDLE EventPairHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtCreateFile (__out PHANDLE FileHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __out PIO_STATUS_BLOCK IoStatusBlock, __in_opt PLARGE_INTEGER AllocationSize, __in ULONG FileAttributes, __in ULONG ShareAccess, __in ULONG CreateDisposition, __in ULONG CreateOptions, __in_bcount_opt(EaLength) PVOID EaBuffer, __in ULONG EaLength)
NTSTATUS NtCreateIoCompletion (__out PHANDLE IoCompletionHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in ULONG Count OPTIONAL)
NTSTATUS NtCreateJobObject (__out PHANDLE JobHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtCreateJobSet (__in ULONG NumJob, __in_ecount(NumJob) PJOB_SET_ARRAY UserJobSet, __in ULONG Flags)
NTSTATUS NtCreateKeyedEvent (__out PHANDLE KeyedEventHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in ULONG Flags)
NTSTATUS NtCreateKey (__out PHANDLE KeyHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __reserved ULONG TitleIndex, __in_opt PUNICODE_STRING Class, __in ULONG CreateOptions, __out_opt PULONG Disposition)
NTSTATUS NtCreateKeyTransacted (__out PHANDLE KeyHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __reserved ULONG TitleIndex, __in_opt PUNICODE_STRING Class, __in ULONG CreateOptions, __in HANDLE TransactionHandle, __out_opt PULONG Disposition)
NTSTATUS NtCreateMailslotFile (__out PHANDLE FileHandle, __in ULONG DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __out PIO_STATUS_BLOCK IoStatusBlock, __in ULONG CreateOptions, __in ULONG MailslotQuota, __in ULONG MaximumMessageSize, __in PLARGE_INTEGER ReadTimeout)
NTSTATUS NtCreateMutant (__out PHANDLE MutantHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in BOOLEAN InitialOwner)
NTSTATUS NtCreateNamedPipeFile (__out PHANDLE FileHandle, __in ULONG DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __out PIO_STATUS_BLOCK IoStatusBlock, __in ULONG ShareAccess, __in ULONG CreateDisposition, __in ULONG CreateOptions, __in ULONG NamedPipeType, __in ULONG ReadMode, __in ULONG CompletionMode, __in ULONG MaximumInstances, __in ULONG InboundQuota, __in ULONG OutboundQuota, __in_opt PLARGE_INTEGER DefaultTimeout)
NTSTATUS NtCreatePagingFile (__in PUNICODE_STRING PageFileName, __in PLARGE_INTEGER MinimumSize, __in PLARGE_INTEGER MaximumSize, __in ULONG Priority)
NTSTATUS NtCreatePort (__out PHANDLE PortHandle, __in POBJECT_ATTRIBUTES ObjectAttributes, __in ULONG MaxConnectionInfoLength, __in ULONG MaxMessageLength, __in_opt ULONG MaxPoolUsage)
NTSTATUS NtCreatePrivateNamespace (__out PHANDLE NamespaceHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in PVOID BoundaryDescriptor)
NTSTATUS NtCreateProcessEx (__out PHANDLE ProcessHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in HANDLE ParentProcess, __in ULONG Flags, __in_opt HANDLE SectionHandle, __in_opt HANDLE DebugPort, __in_opt HANDLE ExceptionPort, __in ULONG JobMemberLevel)
NTSTATUS NtCreateProcess (__out PHANDLE ProcessHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in HANDLE ParentProcess, __in BOOLEAN InheritObjectTable, __in_opt HANDLE SectionHandle, __in_opt HANDLE DebugPort, __in_opt HANDLE ExceptionPort)
NTSTATUS NtCreateProfileEx (__out PHANDLE ProfileHandle, __in_opt HANDLE Process, __in PVOID ProfileBase, __in SIZE_T ProfileSize, __in ULONG BucketSize, __in PULONG Buffer, __in ULONG BufferSize, __in KPROFILE_SOURCE ProfileSource, __in ULONG GroupAffinityCount, __in_opt PGROUP_AFFINITY GroupAffinity)
NTSTATUS NtCreateProfile (__out PHANDLE ProfileHandle, __in HANDLE Process OPTIONAL, __in PVOID RangeBase, __in SIZE_T RangeSize, __in ULONG BucketSize, __in PULONG Buffer, __in ULONG BufferSize, __in KPROFILE_SOURCE ProfileSource, __in KAFFINITY Affinity)
NTSTATUS NtCreateResourceManager (__out PHANDLE ResourceManagerHandle, __in ACCESS_MASK DesiredAccess, __in HANDLE TmHandle, __in LPGUID RmGuid, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in_opt ULONG CreateOptions, __in_opt PUNICODE_STRING Description)
NTSTATUS NtCreateSection (__out PHANDLE SectionHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in_opt PLARGE_INTEGER MaximumSize, __in ULONG SectionPageProtection, __in ULONG AllocationAttributes, __in_opt HANDLE FileHandle)
NTSTATUS NtCreateSemaphore (__out PHANDLE SemaphoreHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in LONG InitialCount, __in LONG MaximumCount)
NTSTATUS NtCreateSymbolicLinkObject (__out PHANDLE LinkHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __in PUNICODE_STRING LinkTarget)
NTSTATUS NtCreateThreadEx (__out PHANDLE ThreadHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in HANDLE ProcessHandle, __in PVOID StartRoutine, __in_opt PVOID Argument, __in ULONG CreateFlags, __in_opt ULONG_PTR ZeroBits, __in_opt SIZE_T StackSize, __in_opt SIZE_T MaximumStackSize, __in_opt PPS_ATTRIBUTE_LIST AttributeList)
NTSTATUS NtCreateThread (__out PHANDLE ThreadHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in HANDLE ProcessHandle, __out PCLIENT_ID ClientId, __in PCONTEXT ThreadContext, __in PINITIAL_TEB InitialTeb, __in BOOLEAN CreateSuspended)
NTSTATUS NtCreateTimer (__out PHANDLE TimerHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in TIMER_TYPE TimerType)
NTSTATUS NtCreateToken (__out PHANDLE TokenHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in TOKEN_TYPE TokenType, __in PLUID AuthenticationId, __in PLARGE_INTEGER ExpirationTime, __in PTOKEN_USER User, __in PTOKEN_GROUPS Groups, __in PTOKEN_PRIVILEGES Privileges, __in_opt PTOKEN_OWNER Owner, __in PTOKEN_PRIMARY_GROUP PrimaryGroup, __in_opt PTOKEN_DEFAULT_DACL DefaultDacl, __in PTOKEN_SOURCE TokenSource)
NTSTATUS NtCreateTransactionManager (__out PHANDLE TmHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in_opt PUNICODE_STRING LogFileName, __in_opt ULONG CreateOptions, __in_opt ULONG CommitStrength)
NTSTATUS NtCreateTransaction (__out PHANDLE TransactionHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in_opt LPGUID Uow, __in_opt HANDLE TmHandle, __in_opt ULONG CreateOptions, __in_opt ULONG IsolationLevel, __in_opt ULONG IsolationFlags, __in_opt PLARGE_INTEGER Timeout, __in_opt PUNICODE_STRING Description)
NTSTATUS NtCreateUserProcess (__out PHANDLE ProcessHandle, __out PHANDLE ThreadHandle, __in ACCESS_MASK ProcessDesiredAccess, __in ACCESS_MASK ThreadDesiredAccess, __in_opt POBJECT_ATTRIBUTES ProcessObjectAttributes, __in_opt POBJECT_ATTRIBUTES ThreadObjectAttributes, __in ULONG ProcessFlags, __in ULONG ThreadFlags, __in_opt PRTL_USER_PROCESS_PARAMETERS ProcessParameters, __in_opt PPROCESS_CREATE_INFO CreateInfo, __in_opt PPROCESS_ATTRIBUTE_LIST AttributeList)
NTSTATUS NtCreateWaitablePort (__out PHANDLE PortHandle, __in POBJECT_ATTRIBUTES ObjectAttributes, __in ULONG MaxConnectionInfoLength, __in ULONG MaxMessageLength, __in_opt ULONG MaxPoolUsage)
NTSTATUS NtCreateWorkerFactory (__out PHANDLE WorkerFactoryHandleReturn, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in HANDLE CompletionPortHandle, __in HANDLE WorkerProcessHandle, __in PVOID StartRoutine, __in_opt PVOID StartParameter, __in_opt ULONG MaxThreadCount, __in_opt SIZE_T StackReserve, __in_opt SIZE_T StackCommit)
NTSTATUS NtDebugActiveProcess (__out HANDLE ProcessHandle, __out HANDLE DebugObjectHandle)
NTSTATUS NtDebugContinue (__out HANDLE DebugObjectHandle, __out PCLIENT_ID ClientId, __out NTSTATUS ContinueStatus)
NTSTATUS NtDelayExecution (__in BOOLEAN Alertable, __in PLARGE_INTEGER DelayInterval)
NTSTATUS NtDeleteAtom (__in RTL_ATOM Atom)
NTSTATUS NtDeleteBootEntry (__in ULONG Id)
NTSTATUS NtDeleteDriverEntry (__in ULONG Id)
NTSTATUS NtDeleteFile (__in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtDeleteKey (__in HANDLE KeyHandle)
NTSTATUS NtDeleteObjectAuditAlarm (__in PUNICODE_STRING SubsystemName, __in_opt PVOID HandleId, __in BOOLEAN GenerateOnClose)
NTSTATUS NtDeletePrivateNamespace (__in HANDLE NamespaceHandle)
NTSTATUS NtDeleteValueKey (__in HANDLE KeyHandle, __in PUNICODE_STRING ValueName)
NTSTATUS NtDeviceIoControlFile (__in HANDLE FileHandle, __in_opt HANDLE Event, __in_opt PIO_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __in ULONG IoControlCode, __in_bcount_opt(InputBufferLength) PVOID InputBuffer, __in ULONG InputBufferLength, __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer, __in ULONG OutputBufferLength)
NTSTATUS NtDisableLastKnownGood (VOID)
NTSTATUS NtDisplayString (__in PUNICODE_STRING String)
NTSTATUS NtDrawText (__in PUNICODE_STRING Text)
NTSTATUS NtDuplicateObject (__in HANDLE SourceProcessHandle, __in HANDLE SourceHandle, __in_opt HANDLE TargetProcessHandle, __out_opt PHANDLE TargetHandle, __in ACCESS_MASK DesiredAccess, __in ULONG HandleAttributes, __in ULONG Options)
NTSTATUS NtDuplicateToken (__in HANDLE ExistingTokenHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __in BOOLEAN EffectiveOnly, __in TOKEN_TYPE TokenType, __out PHANDLE NewTokenHandle)
NTSTATUS NtEnableLastKnownGood (VOID)
NTSTATUS NtEnumerateBootEntries (__out_bcount_opt(*BufferLength) PVOID Buffer, __inout PULONG BufferLength)
NTSTATUS NtEnumerateDriverEntries (__out_bcount(*BufferLength) PVOID Buffer, __inout PULONG BufferLength)
NTSTATUS NtEnumerateKey (__in HANDLE KeyHandle, __in ULONG Index, __in KEY_INFORMATION_CLASS KeyInformationClass, __out_bcount_opt(Length) PVOID KeyInformation, __in ULONG Length, __out PULONG ResultLength)
NTSTATUS NtEnumerateSystemEnvironmentValuesEx (__in ULONG InformationClass, __out PVOID Buffer, __inout PULONG BufferLength)
NTSTATUS NtEnumerateTransactionObject (__in_opt HANDLE RootObjectHandle, __in KTMOBJECT_TYPE QueryType, __inout_bcount(ObjectCursorLength) PKTMOBJECT_CURSOR ObjectCursor, __in ULONG ObjectCursorLength, __out PULONG ReturnLength)
NTSTATUS NtEnumerateValueKey (__in HANDLE KeyHandle, __in ULONG Index, __in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, __out_bcount_opt(Length) PVOID KeyValueInformation, __in ULONG Length, __out PULONG ResultLength)
NTSTATUS NtExtendSection (__in HANDLE SectionHandle, __inout PLARGE_INTEGER NewSectionSize)
NTSTATUS NtFilterToken (__in HANDLE ExistingTokenHandle, __in ULONG Flags, __in_opt PTOKEN_GROUPS SidsToDisable, __in_opt PTOKEN_PRIVILEGES PrivilegesToDelete, __in_opt PTOKEN_GROUPS RestrictedSids, __out PHANDLE NewTokenHandle)
NTSTATUS NtFindAtom (__in_bcount_opt(Length) PWSTR AtomName, __in ULONG Length, __out_opt PRTL_ATOM Atom)
NTSTATUS NtFlushBuffersFile (__in HANDLE FileHandle, __out PIO_STATUS_BLOCK IoStatusBlock)
NTSTATUS NtFlushInstallUILanguage (__in LANGID InstallUILanguage, __in ULONG SetComittedFlag)
NTSTATUS NtFlushInstructionCache (__in HANDLE ProcessHandle, __in_opt PVOID BaseAddress, __in SIZE_T Length)
NTSTATUS NtFlushKey (__in HANDLE KeyHandle)
VOID NtFlushProcessWriteBuffers (VOID)
NTSTATUS NtFlushVirtualMemory (__in HANDLE ProcessHandle, __inout PVOID *BaseAddress, __inout PSIZE_T RegionSize, __out PIO_STATUS_BLOCK IoStatus)
NTSTATUS NtFlushWriteBuffer (VOID)
NTSTATUS NtFreeUserPhysicalPages (__in HANDLE ProcessHandle, __inout PULONG_PTR NumberOfPages, __in_ecount(*NumberOfPages) PULONG_PTR UserPfnArray)
NTSTATUS NtFreeVirtualMemory (__in HANDLE ProcessHandle, __inout PVOID *BaseAddress, __inout PSIZE_T RegionSize, __in ULONG FreeType)
NTSTATUS NtFreezeRegistry (__in ULONG TimeOutInSeconds)
NTSTATUS NtFreezeTransactions (__in PLARGE_INTEGER FreezeTimeout, __in PLARGE_INTEGER ThawTimeout)
NTSTATUS NtFsControlFile (__in HANDLE FileHandle, __in_opt HANDLE Event, __in_opt PIO_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __in ULONG IoControlCode, __in_bcount_opt(InputBufferLength) PVOID InputBuffer, __in ULONG InputBufferLength, __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer, __in ULONG OutputBufferLength)
NTSTATUS NtGetContextThread (__in HANDLE ThreadHandle, __inout PCONTEXT ThreadContext)
ULONG NtGetCurrentProcessorNumber (VOID)
NTSTATUS NtGetDevicePowerState (__in HANDLE Device, __out DEVICE_POWER_STATE *State)
NTSTATUS NtGetMUIRegistryInfo (__in ULONG Flags, __inout PULONG DataSize, __out PVOID Data)
NTSTATUS NtGetNextProcess (__in HANDLE ProcessHandle, __in ACCESS_MASK DesiredAccess, __in ULONG HandleAttributes, __in ULONG Flags, __out PHANDLE NewProcessHandle)
NTSTATUS NtGetNextThread (__in HANDLE ProcessHandle, __in HANDLE ThreadHandle, __in ACCESS_MASK DesiredAccess, __in ULONG HandleAttributes, __in ULONG Flags, __out PHANDLE NewThreadHandle)
NTSTATUS NtGetNlsSectionPtr (__in ULONG SectionType, __in ULONG SectionData, __in PVOID ContextData, __out PVOID *SectionPointer, __out PULONG SectionSize)
NTSTATUS NtGetNotificationResourceManager (__in HANDLE ResourceManagerHandle, __out PTRANSACTION_NOTIFICATION TransactionNotification, __in ULONG NotificationLength, __in_opt PLARGE_INTEGER Timeout, __out_opt PULONG ReturnLength, __in ULONG Asynchronous, __in_opt ULONG_PTR AsynchronousContext)
NTSTATUS NtGetPlugPlayEvent (__in HANDLE EventHandle, __in_opt PVOID Context, __out_bcount(EventBufferSize) PPLUGPLAY_EVENT_BLOCK EventBlock, __in ULONG EventBufferSize)
NTSTATUS NtGetWriteWatch (__in HANDLE ProcessHandle, __in ULONG Flags, __in PVOID BaseAddress, __in SIZE_T RegionSize, __out_ecount(*EntriesInUserAddressArray) PVOID *UserAddressArray, __inout PULONG_PTR EntriesInUserAddressArray, __out PULONG Granularity)
NTSTATUS NtImpersonateAnonymousToken (__in HANDLE ThreadHandle)
NTSTATUS NtImpersonateClientOfPort (__in HANDLE PortHandle, __in PPORT_MESSAGE Message)
NTSTATUS NtImpersonateThread (__in HANDLE ServerThreadHandle, __in HANDLE ClientThreadHandle, __in PSECURITY_QUALITY_OF_SERVICE SecurityQos)
NTSTATUS NtInitializeNlsFiles (__out PVOID *BaseAddress, __out PLCID DefaultLocaleId, __out PLARGE_INTEGER DefaultCasingTableSize)
NTSTATUS NtInitializeRegistry (__in USHORT BootCondition)
NTSTATUS NtInitiatePowerAction (__in POWER_ACTION SystemAction, __in SYSTEM_POWER_STATE MinSystemState, __in ULONG Flags, __in BOOLEAN Asynchronous)
NTSTATUS NtIsProcessInJob (__in HANDLE ProcessHandle, __in_opt HANDLE JobHandle)
BOOLEAN NtIsSystemResumeAutomatic (VOID)
NTSTATUS NtIsUILanguageComitted (VOID)
NTSTATUS NtListenPort (__in HANDLE PortHandle, __out PPORT_MESSAGE ConnectionRequest)
NTSTATUS NtLoadDriver (__in PUNICODE_STRING DriverServiceName)
NTSTATUS NtLoadKey2 (__in POBJECT_ATTRIBUTES TargetKey, __in POBJECT_ATTRIBUTES SourceFile, __in ULONG Flags)
NTSTATUS NtLoadKeyEx (__in POBJECT_ATTRIBUTES TargetKey, __in POBJECT_ATTRIBUTES SourceFile, __in ULONG Flags, __in_opt HANDLE TrustClassKey )
NTSTATUS NtLoadKey (__in POBJECT_ATTRIBUTES TargetKey, __in POBJECT_ATTRIBUTES SourceFile)
NTSTATUS NtLockFile (__in HANDLE FileHandle, __in_opt HANDLE Event, __in_opt PIO_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __in PLARGE_INTEGER ByteOffset, __in PLARGE_INTEGER Length, __in ULONG Key, __in BOOLEAN FailImmediately, __in BOOLEAN ExclusiveLock)
NTSTATUS NtLockProductActivationKeys (__inout_opt ULONG *pPrivateVer, __out_opt ULONG *pSafeMode)
NTSTATUS NtLockRegistryKey (__in HANDLE KeyHandle)
NTSTATUS NtLockVirtualMemory (__in HANDLE ProcessHandle, __inout PVOID *BaseAddress, __inout PSIZE_T RegionSize, __in ULONG MapType)
NTSTATUS NtMakePermanentObject (__in HANDLE Handle)
NTSTATUS NtMakeTemporaryObject (__in HANDLE Handle)
NTSTATUS NtMapCMFModule (__in ULONG What, __in ULONG Index, __out_opt PULONG CacheIndexOut, __out_opt PULONG CacheFlagsOut, __out_opt PULONG ViewSizeOut, __out_opt PVOID *BaseAddress)
NTSTATUS NtMapUserPhysicalPages (__in PVOID VirtualAddress, __in ULONG_PTR NumberOfPages, __in_ecount_opt(NumberOfPages) PULONG_PTR UserPfnArray)
NTSTATUS NtMapUserPhysicalPagesScatter (__in_ecount(NumberOfPages) PVOID *VirtualAddresses, __in ULONG_PTR NumberOfPages, __in_ecount_opt(NumberOfPages) PULONG_PTR UserPfnArray)
NTSTATUS NtMapViewOfSection (__in HANDLE SectionHandle, __in HANDLE ProcessHandle, __inout PVOID *BaseAddress, __in ULONG_PTR ZeroBits, __in SIZE_T CommitSize, __inout_opt PLARGE_INTEGER SectionOffset, __inout PSIZE_T ViewSize, __in SECTION_INHERIT InheritDisposition, __in ULONG AllocationType, __in WIN32_PROTECTION_MASK Win32Protect)
NTSTATUS NtModifyBootEntry (__in PBOOT_ENTRY BootEntry)
NTSTATUS NtModifyDriverEntry (__in PEFI_DRIVER_ENTRY DriverEntry)
NTSTATUS NtNotifyChangeDirectoryFile (__in HANDLE FileHandle, __in_opt HANDLE Event, __in_opt PIO_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __out_bcount(Length) PVOID Buffer, __in ULONG Length, __in ULONG CompletionFilter, __in BOOLEAN WatchTree)
NTSTATUS NtNotifyChangeKey (__in HANDLE KeyHandle, __in_opt HANDLE Event, __in_opt PIO_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __in ULONG CompletionFilter, __in BOOLEAN WatchTree, __out_bcount_opt(BufferSize) PVOID Buffer, __in ULONG BufferSize, __in BOOLEAN Asynchronous)
NTSTATUS NtNotifyChangeMultipleKeys (__in HANDLE MasterKeyHandle, __in_opt ULONG Count, __in_ecount_opt(Count) OBJECT_ATTRIBUTES SlaveObjects[], __in_opt HANDLE Event, __in_opt PIO_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __in ULONG CompletionFilter, __in BOOLEAN WatchTree, __out_bcount_opt(BufferSize) PVOID Buffer, __in ULONG BufferSize, __in BOOLEAN Asynchronous)
NTSTATUS NtNotifyChangeSession (__in HANDLE Session, __in ULONG IoStateSequence, __in PVOID Reserved, __in ULONG Action, __in IO_SESSION_STATE IoState, __in IO_SESSION_STATE IoState2, __in PVOID Buffer, __in ULONG BufferSize)
NTSTATUS NtOpenDirectoryObject (__out PHANDLE DirectoryHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenEnlistment (__out PHANDLE EnlistmentHandle, __in ACCESS_MASK DesiredAccess, __in HANDLE ResourceManagerHandle, __in LPGUID EnlistmentGuid, __in_opt POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenEvent (__out PHANDLE EventHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenEventPair (__out PHANDLE EventPairHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenFile (__out PHANDLE FileHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __out PIO_STATUS_BLOCK IoStatusBlock, __in ULONG ShareAccess, __in ULONG OpenOptions)
NTSTATUS NtOpenIoCompletion (__out PHANDLE IoCompletionHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenJobObject (__out PHANDLE JobHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenKeyedEvent (__out PHANDLE KeyedEventHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenKeyEx (__out PHANDLE KeyHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __in ULONG OpenOptions)
NTSTATUS NtOpenKey (__out PHANDLE KeyHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenKeyTransactedEx (__out PHANDLE KeyHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __in ULONG OpenOptions, __in HANDLE TransactionHandle)
NTSTATUS NtOpenKeyTransacted (__out PHANDLE KeyHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __in HANDLE TransactionHandle)
NTSTATUS NtOpenMutant (__out PHANDLE MutantHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenObjectAuditAlarm (__in PUNICODE_STRING SubsystemName, __in_opt PVOID HandleId, __in PUNICODE_STRING ObjectTypeName, __in PUNICODE_STRING ObjectName, __in_opt PSECURITY_DESCRIPTOR SecurityDescriptor, __in HANDLE ClientToken, __in ACCESS_MASK DesiredAccess, __in ACCESS_MASK GrantedAccess, __in_opt PPRIVILEGE_SET Privileges, __in BOOLEAN ObjectCreation, __in BOOLEAN AccessGranted, __out PBOOLEAN GenerateOnClose)
NTSTATUS NtOpenPrivateNamespace (__out PHANDLE NamespaceHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in PVOID BoundaryDescriptor)
NTSTATUS NtOpenProcess (__out PHANDLE ProcessHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __in_opt PCLIENT_ID ClientId)
NTSTATUS NtOpenProcessTokenEx (__in HANDLE ProcessHandle, __in ACCESS_MASK DesiredAccess, __in ULONG HandleAttributes, __out PHANDLE TokenHandle)
NTSTATUS NtOpenProcessToken (__in HANDLE ProcessHandle, __in ACCESS_MASK DesiredAccess, __out PHANDLE TokenHandle)
NTSTATUS NtOpenResourceManager (__out PHANDLE ResourceManagerHandle, __in ACCESS_MASK DesiredAccess, __in HANDLE TmHandle, __in_opt LPGUID ResourceManagerGuid, __in_opt POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenSection (__out PHANDLE SectionHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenSemaphore (__out PHANDLE SemaphoreHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenSession (__out PHANDLE SessionHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenSymbolicLinkObject (__out PHANDLE LinkHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenThread (__out PHANDLE ThreadHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __in_opt PCLIENT_ID ClientId)
NTSTATUS NtOpenThreadTokenEx (__in HANDLE ThreadHandle, __in ACCESS_MASK DesiredAccess, __in BOOLEAN OpenAsSelf, __in ULONG HandleAttributes, __out PHANDLE TokenHandle)
NTSTATUS NtOpenThreadToken (__in HANDLE ThreadHandle, __in ACCESS_MASK DesiredAccess, __in BOOLEAN OpenAsSelf, __out PHANDLE TokenHandle)
NTSTATUS NtOpenTimer (__out PHANDLE TimerHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes)
NTSTATUS NtOpenTransactionManager (__out PHANDLE TmHandle, __in ACCESS_MASK DesiredAccess, __in_opt POBJECT_ATTRIBUTES ObjectAttributes, __in_opt PUNICODE_STRING LogFileName, __in_opt LPGUID TmIdentity, __in_opt ULONG OpenOptions)
NTSTATUS NtOpenTransaction (__out PHANDLE TransactionHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes, __in LPGUID Uow, __in_opt HANDLE TmHandle)
NTSTATUS NtPlugPlayControl (__in PLUGPLAY_CONTROL_CLASS PnPControlClass, __inout_bcount(PnPControlDataLength) PVOID PnPControlData, __in ULONG PnPControlDataLength)
NTSTATUS NtPowerInformation (__in POWER_INFORMATION_LEVEL InformationLevel, __in_bcount_opt(InputBufferLength) PVOID InputBuffer, __in ULONG InputBufferLength, __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer, __in ULONG OutputBufferLength)
NTSTATUS NtPrepareComplete (__in HANDLE EnlistmentHandle, __in_opt PLARGE_INTEGER TmVirtualClock)
NTSTATUS NtPrepareEnlistment (__in HANDLE EnlistmentHandle, __in_opt PLARGE_INTEGER TmVirtualClock)
NTSTATUS NtPrePrepareComplete (__in HANDLE EnlistmentHandle, __in_opt PLARGE_INTEGER TmVirtualClock)
NTSTATUS NtPrePrepareEnlistment (__in HANDLE EnlistmentHandle, __in_opt PLARGE_INTEGER TmVirtualClock)
NTSTATUS NtPrivilegeCheck (__in HANDLE ClientToken, __inout PPRIVILEGE_SET RequiredPrivileges, __out PBOOLEAN Result)
NTSTATUS NtPrivilegedServiceAuditAlarm (__in PUNICODE_STRING SubsystemName, __in PUNICODE_STRING ServiceName, __in HANDLE ClientToken, __in PPRIVILEGE_SET Privileges, __in BOOLEAN AccessGranted)
NTSTATUS NtPrivilegeObjectAuditAlarm (__in PUNICODE_STRING SubsystemName, __in_opt PVOID HandleId, __in HANDLE ClientToken, __in ACCESS_MASK DesiredAccess, __in PPRIVILEGE_SET Privileges, __in BOOLEAN AccessGranted)
NTSTATUS NtPropagationComplete (__in HANDLE ResourceManagerHandle, __in ULONG RequestCookie, __in ULONG BufferLength, __in PVOID Buffer)
NTSTATUS NtPropagationFailed (__in HANDLE ResourceManagerHandle, __in ULONG RequestCookie, __in NTSTATUS PropStatus)
NTSTATUS NtProtectVirtualMemory (__in HANDLE ProcessHandle, __inout PVOID *BaseAddress, __inout PSIZE_T RegionSize, __in WIN32_PROTECTION_MASK NewProtectWin32, __out PULONG OldProtect)
NTSTATUS NtPulseEvent (__in HANDLE EventHandle, __out_opt PLONG PreviousState)
NTSTATUS NtQueryAttributesFile (__in POBJECT_ATTRIBUTES ObjectAttributes, __out PFILE_BASIC_INFORMATION FileInformation)
NTSTATUS NtQueryBootEntryOrder (__out_ecount_opt(*Count) PULONG Ids, __inout PULONG Count)
NTSTATUS NtQueryBootOptions (__out_bcount_opt(*BootOptionsLength) PBOOT_OPTIONS BootOptions, __inout PULONG BootOptionsLength)
NTSTATUS NtQueryDebugFilterState (__in ULONG ComponentId, __in ULONG Level)
NTSTATUS NtQueryDefaultLocale (__in BOOLEAN UserProfile, __out PLCID DefaultLocaleId)
NTSTATUS NtQueryDefaultUILanguage (__out LANGID *DefaultUILanguageId)
NTSTATUS NtQueryDirectoryFile (__in HANDLE FileHandle, __in_opt HANDLE Event, __in_opt PIO_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __out_bcount(Length) PVOID FileInformation, __in ULONG Length, __in FILE_INFORMATION_CLASS FileInformationClass, __in BOOLEAN ReturnSingleEntry, __in PUNICODE_STRING FileName OPTIONAL, __in BOOLEAN RestartScan)
NTSTATUS NtQueryDirectoryObject (__in HANDLE DirectoryHandle, __out_bcount_opt(Length) PVOID Buffer, __in ULONG Length, __in BOOLEAN ReturnSingleEntry, __in BOOLEAN RestartScan, __inout PULONG Context, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryDriverEntryOrder (__out_ecount(*Count) PULONG Ids, __inout PULONG Count)
NTSTATUS NtQueryEaFile (__in HANDLE FileHandle, __out PIO_STATUS_BLOCK IoStatusBlock, __out_bcount(Length) PVOID Buffer, __in ULONG Length, __in BOOLEAN ReturnSingleEntry, __in_bcount_opt(EaListLength) PVOID EaList, __in ULONG EaListLength, __in_opt PULONG EaIndex, __in BOOLEAN RestartScan)
NTSTATUS NtQueryEvent (__in HANDLE EventHandle, __in EVENT_INFORMATION_CLASS EventInformationClass, __out_bcount(EventInformationLength) PVOID EventInformation, __in ULONG EventInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryFullAttributesFile (__in POBJECT_ATTRIBUTES ObjectAttributes, __out PFILE_NETWORK_OPEN_INFORMATION FileInformation)
NTSTATUS NtQueryInformationAtom (__in RTL_ATOM Atom, __in ATOM_INFORMATION_CLASS InformationClass, __out_bcount(AtomInformationLength) PVOID AtomInformation, __in ULONG AtomInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryInformationEnlistment (__in HANDLE EnlistmentHandle, __in ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass, __out_bcount(EnlistmentInformationLength) PVOID EnlistmentInformation, __in ULONG EnlistmentInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryInformationFile (__in HANDLE FileHandle, __out PIO_STATUS_BLOCK IoStatusBlock, __out_bcount(Length) PVOID FileInformation, __in ULONG Length, __in FILE_INFORMATION_CLASS FileInformationClass)
NTSTATUS NtQueryInformationJobObject (__in_opt HANDLE JobHandle, __in JOBOBJECTINFOCLASS JobObjectInformationClass, __out_bcount(JobObjectInformationLength) PVOID JobObjectInformation, __in ULONG JobObjectInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryInformationPort (__in HANDLE PortHandle, __in PORT_INFORMATION_CLASS PortInformationClass, __out_bcount(Length) PVOID PortInformation, __in ULONG Length, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryInformationProcess (__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass, __out_bcount(ProcessInformationLength) PVOID ProcessInformation, __in ULONG ProcessInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryInformationResourceManager (__in HANDLE ResourceManagerHandle, __in RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass, __out_bcount(ResourceManagerInformationLength) PVOID ResourceManagerInformation, __in ULONG ResourceManagerInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryInformationThread (__in HANDLE ThreadHandle, __in THREADINFOCLASS ThreadInformationClass, __out_bcount(ThreadInformationLength) PVOID ThreadInformation, __in ULONG ThreadInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryInformationToken (__in HANDLE TokenHandle, __in TOKEN_INFORMATION_CLASS TokenInformationClass, __out_bcount_part_opt(TokenInformationLength,*ReturnLength) PVOID TokenInformation, __in ULONG TokenInformationLength, __out PULONG ReturnLength)
NTSTATUS NtQueryInformationTransaction (__in HANDLE TransactionHandle, __in TRANSACTION_INFORMATION_CLASS TransactionInformationClass, __out_bcount(TransactionInformationLength) PVOID TransactionInformation, __in ULONG TransactionInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryInformationTransactionManager (__in HANDLE TransactionManagerHandle, __in TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass, __out_bcount(TransactionManagerInformationLength) PVOID TransactionManagerInformation, __in ULONG TransactionManagerInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryInformationWorkerFactory (__in HANDLE WorkerFactoryHandle, __in WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, __out_bcount(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation, __in ULONG WorkerFactoryInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryInstallUILanguage (__out LANGID *InstallUILanguageId)
NTSTATUS NtQueryIntervalProfile (__in KPROFILE_SOURCE ProfileSource, __out PULONG Interval)
NTSTATUS NtQueryIoCompletion (__in HANDLE IoCompletionHandle, __in IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass, __out_bcount(IoCompletionInformationLength) PVOID IoCompletionInformation, __in ULONG IoCompletionInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryKey (__in HANDLE KeyHandle, __in KEY_INFORMATION_CLASS KeyInformationClass, __out_bcount_opt(Length) PVOID KeyInformation, __in ULONG Length, __out PULONG ResultLength)
NTSTATUS NtQueryLicenseValue (__in PUNICODE_STRING Name, __out_opt PULONG Type, __out_bcount(ReturnedLength) PVOID Buffer, __in ULONG Length, __out PULONG ReturnedLength)
NTSTATUS NtQueryMultipleValueKey (__in HANDLE KeyHandle, __inout_ecount(EntryCount) PKEY_VALUE_ENTRY ValueEntries, __in ULONG EntryCount, __out_bcount(*BufferLength) PVOID ValueBuffer, __inout PULONG BufferLength, __out_opt PULONG RequiredBufferLength)
NTSTATUS NtQueryMutant (__in HANDLE MutantHandle, __in MUTANT_INFORMATION_CLASS MutantInformationClass, __out_bcount(MutantInformationLength) PVOID MutantInformation, __in ULONG MutantInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryObject (__in HANDLE Handle, __in OBJECT_INFORMATION_CLASS ObjectInformationClass, __out_bcount_opt(ObjectInformationLength) PVOID ObjectInformation, __in ULONG ObjectInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryOpenSubKeysEx (__in POBJECT_ATTRIBUTES TargetKey, __in ULONG BufferLength, __out_bcount(BufferLength) PVOID Buffer, __out PULONG RequiredSize)
NTSTATUS NtQueryOpenSubKeys (__in POBJECT_ATTRIBUTES TargetKey, __out PULONG HandleCount)
NTSTATUS NtQueryPerformanceCounter (__out PLARGE_INTEGER PerformanceCounter, __out_opt PLARGE_INTEGER PerformanceFrequency)
NTSTATUS NtQueryPortInformationProcess (VOID)
NTSTATUS NtQueryQuotaInformationFile (__in HANDLE FileHandle, __out PIO_STATUS_BLOCK IoStatusBlock, __out_bcount(Length) PVOID Buffer, __in ULONG Length, __in BOOLEAN ReturnSingleEntry, __in_bcount_opt(SidListLength) PVOID SidList, __in ULONG SidListLength, __in_opt PULONG StartSid, __in BOOLEAN RestartScan)
NTSTATUS NtQuerySection (__in HANDLE SectionHandle, __in SECTION_INFORMATION_CLASS SectionInformationClass, __out_bcount(SectionInformationLength) PVOID SectionInformation, __in SIZE_T SectionInformationLength, __out_opt PSIZE_T ReturnLength)
NTSTATUS NtQuerySecurityAttributesToken (__in HANDLE TokenHandle, __in_ecount_opt(NumberOfAttributes) PUNICODE_STRING Attributes, __in ULONG NumberOfAttributes, __out_bcount(Length) PVOID Buffer, __in ULONG Length, __out PULONG ReturnLength)
NTSTATUS NtQuerySecurityObject (__in HANDLE Handle, __in SECURITY_INFORMATION SecurityInformation, __out_bcount_opt(Length) PSECURITY_DESCRIPTOR SecurityDescriptor, __in ULONG Length, __out PULONG LengthNeeded)
NTSTATUS NtQuerySemaphore (__in HANDLE SemaphoreHandle, __in SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass, __out_bcount(SemaphoreInformationLength) PVOID SemaphoreInformation, __in ULONG SemaphoreInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQuerySymbolicLinkObject (__in HANDLE LinkHandle, __inout PUNICODE_STRING LinkTarget, __out_opt PULONG ReturnedLength)
NTSTATUS NtQuerySystemEnvironmentValueEx (__in PUNICODE_STRING VariableName, __in LPGUID VendorGuid, __out_bcount_opt(*ValueLength) PVOID Value, __inout PULONG ValueLength, __out_opt PULONG Attributes)
NTSTATUS NtQuerySystemEnvironmentValue (__in PUNICODE_STRING VariableName, __out_bcount(ValueLength) PWSTR VariableValue, __in USHORT ValueLength, __out_opt PUSHORT ReturnLength)
NTSTATUS NtQuerySystemInformationEx (__in SYSTEM_INFORMATION_CLASS SystemInformationClass, __in_bcount(QueryInformationLength) PVOID QueryInformation, __in ULONG QueryInformationLength, __out_bcount_opt(SystemInformationLength) PVOID SystemInformation, __in ULONG SystemInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQuerySystemInformation (__in SYSTEM_INFORMATION_CLASS SystemInformationClass, __out_bcount_opt(SystemInformationLength) PVOID SystemInformation, __in ULONG SystemInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQuerySystemTime (__out PLARGE_INTEGER SystemTime)
NTSTATUS NtQueryTimer (__in HANDLE TimerHandle, __in TIMER_INFORMATION_CLASS TimerInformationClass, __out_bcount(TimerInformationLength) PVOID TimerInformation, __in ULONG TimerInformationLength, __out_opt PULONG ReturnLength)
NTSTATUS NtQueryTimerResolution (__out PULONG MaximumTime, __out PULONG MinimumTime, __out PULONG CurrentTime)
NTSTATUS NtQueryValueKey (__in HANDLE KeyHandle, __in PUNICODE_STRING ValueName, __in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, __out_bcount_opt(Length) PVOID KeyValueInformation, __in ULONG Length, __out PULONG ResultLength)
NTSTATUS NtQueryVirtualMemory (__in HANDLE ProcessHandle, __in PVOID BaseAddress, __in MEMORY_INFORMATION_CLASS MemoryInformationClass, __out_bcount(MemoryInformationLength) PVOID MemoryInformation, __in SIZE_T MemoryInformationLength, __out_opt PSIZE_T ReturnLength)
NTSTATUS NtQueryVolumeInformationFile (__in HANDLE FileHandle, __out PIO_STATUS_BLOCK IoStatusBlock, __out_bcount(Length) PVOID FsInformation, __in ULONG Length, __in FS_INFORMATION_CLASS FsInformationClass)
NTSTATUS NtQueueApcThreadEx (__in HANDLE ThreadHandle, __in_opt HANDLE UserApcReserveHandle, __in PPS_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcArgument1, __in_opt PVOID ApcArgument2, __in_opt PVOID ApcArgument3)
NTSTATUS NtQueueApcThread (__in HANDLE ThreadHandle, __in PPS_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcArgument1, __in_opt PVOID ApcArgument2, __in_opt PVOID ApcArgument3)
NTSTATUS NtRaiseException (__out PEXCEPTION_RECORD ExceptionRecord, __out PCONTEXT ContextRecord, __out BOOLEAN FirstChance)
NTSTATUS NtRaiseHardError (__in NTSTATUS ErrorStatus, __in ULONG NumberOfParameters, __in ULONG UnicodeStringParameterMask, __in_ecount(NumberOfParameters) PULONG_PTR Parameters, __in ULONG ValidResponseOptions, __out PULONG Response)
NTSTATUS NtReadFile (__in HANDLE FileHandle, __in_opt HANDLE Event, __in_opt PIO_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __out_bcount(Length) PVOID Buffer, __in ULONG Length, __in_opt PLARGE_INTEGER ByteOffset, __in_opt PULONG Key)
NTSTATUS NtReadFileScatter (__in HANDLE FileHandle, __in_opt HANDLE Event, __in_opt PIO_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __in PFILE_SEGMENT_ELEMENT SegmentArray, __in ULONG Length, __in_opt PLARGE_INTEGER ByteOffset, __in_opt PULONG Key)
NTSTATUS NtReadOnlyEnlistment (__in HANDLE EnlistmentHandle, __in_opt PLARGE_INTEGER TmVirtualClock)
NTSTATUS NtReadRequestData (__in HANDLE PortHandle, __in PPORT_MESSAGE Message, __in ULONG DataEntryIndex, __out_bcount(BufferSize) PVOID Buffer, __in SIZE_T BufferSize, __out_opt PSIZE_T NumberOfBytesRead)
NTSTATUS NtReadVirtualMemory (__in HANDLE ProcessHandle, __in_opt PVOID BaseAddress, __out_bcount(BufferSize) PVOID Buffer, __in SIZE_T BufferSize, __out_opt PSIZE_T NumberOfBytesRead)
NTSTATUS NtRecoverEnlistment (__in HANDLE EnlistmentHandle, __in_opt PVOID EnlistmentKey)
NTSTATUS NtRecoverResourceManager (__in HANDLE ResourceManagerHandle)
NTSTATUS NtRecoverTransactionManager (__in HANDLE TransactionManagerHandle)
NTSTATUS NtRegisterProtocolAddressInformation (__in HANDLE ResourceManager, __in PCRM_PROTOCOL_ID ProtocolId, __in ULONG ProtocolInformationSize, __in PVOID ProtocolInformation, __in_opt ULONG CreateOptions)
NTSTATUS NtRegisterThreadTerminatePort (__in HANDLE PortHandle)
NTSTATUS NtReleaseKeyedEvent (__in HANDLE KeyedEventHandle, __in PVOID KeyValue, __in BOOLEAN Alertable, __in_opt PLARGE_INTEGER Timeout)
NTSTATUS NtReleaseMutant (__in HANDLE MutantHandle, __out_opt PLONG PreviousCount)
NTSTATUS NtReleaseSemaphore (__in HANDLE SemaphoreHandle, __in LONG ReleaseCount, __out_opt PLONG PreviousCount)
NTSTATUS NtReleaseWorkerFactoryWorker (__in HANDLE WorkerFactoryHandle)
NTSTATUS NtRemoveIoCompletionEx (__in HANDLE IoCompletionHandle, __out_ecount(Count) PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation, __in ULONG Count, __out PULONG NumEntriesRemoved, __in_opt PLARGE_INTEGER Timeout, __in BOOLEAN Alertable)
NTSTATUS NtRemoveIoCompletion (__in HANDLE IoCompletionHandle, __out PVOID *KeyContext, __out PVOID *ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __in_opt PLARGE_INTEGER Timeout)
NTSTATUS NtRemoveProcessDebug (__out HANDLE ProcessHandle, __out HANDLE DebugObjectHandle)
NTSTATUS NtRenameKey (__in HANDLE KeyHandle, __in PUNICODE_STRING NewName)
NTSTATUS NtRenameTransactionManager (__in PUNICODE_STRING LogFileName, __in LPGUID ExistingTransactionManagerGuid)
NTSTATUS NtReplaceKey (__in POBJECT_ATTRIBUTES NewFile, __in HANDLE TargetHandle, __in POBJECT_ATTRIBUTES OldFile)
NTSTATUS NtReplacePartitionUnit (__in PUNICODE_STRING TargetInstancePath, __in PUNICODE_STRING SpareInstancePath, __in ULONG Flags)
NTSTATUS NtReplyPort (__in HANDLE PortHandle, __in PPORT_MESSAGE ReplyMessage)
NTSTATUS NtReplyWaitReceivePortEx (__in HANDLE PortHandle, __out_opt PVOID *PortContext, __in_opt PPORT_MESSAGE ReplyMessage, __out PPORT_MESSAGE ReceiveMessage, __in_opt PLARGE_INTEGER Timeout)
NTSTATUS NtReplyWaitReceivePort (__in HANDLE PortHandle, __out_opt PVOID *PortContext , __in_opt PPORT_MESSAGE ReplyMessage, __out PPORT_MESSAGE ReceiveMessage)
NTSTATUS NtReplyWaitReplyPort (__in HANDLE PortHandle, __inout PPORT_MESSAGE ReplyMessage)
NTSTATUS NtRequestPort (__in HANDLE PortHandle, __in PPORT_MESSAGE RequestMessage)
NTSTATUS NtRequestWaitReplyPort (__in HANDLE PortHandle, __in PPORT_MESSAGE RequestMessage, __out PPORT_MESSAGE ReplyMessage)
NTSTATUS NtResetEvent (__in HANDLE EventHandle, __out_opt PLONG PreviousState)
NTSTATUS NtResetWriteWatch (__in HANDLE ProcessHandle, __in PVOID BaseAddress, __in SIZE_T RegionSize)
NTSTATUS NtRestoreKey (__in HANDLE KeyHandle, __in HANDLE FileHandle, __in ULONG Flags)
NTSTATUS NtResumeProcess (__in HANDLE ProcessHandle)
NTSTATUS NtResumeThread (__in HANDLE ThreadHandle, __out_opt PULONG PreviousSuspendCount)
NTSTATUS NtRollbackComplete (__in HANDLE EnlistmentHandle, __in_opt PLARGE_INTEGER TmVirtualClock)
NTSTATUS NtRollbackEnlistment (__in HANDLE EnlistmentHandle, __in_opt PLARGE_INTEGER TmVirtualClock)
NTSTATUS NtRollbackTransaction (__in HANDLE TransactionHandle, __in BOOLEAN Wait)
NTSTATUS NtRollforwardTransactionManager (__in HANDLE TransactionManagerHandle, __in_opt PLARGE_INTEGER TmVirtualClock)
NTSTATUS NtSaveKeyEx (__in HANDLE KeyHandle, __in HANDLE FileHandle, __in ULONG Format)
NTSTATUS NtSaveKey (__in HANDLE KeyHandle, __in HANDLE FileHandle)
NTSTATUS NtSaveMergedKeys (__in HANDLE HighPrecedenceKeyHandle, __in HANDLE LowPrecedenceKeyHandle, __in HANDLE FileHandle)
NTSTATUS NtSecureConnectPort (__out PHANDLE PortHandle, __in PUNICODE_STRING PortName, __in PSECURITY_QUALITY_OF_SERVICE SecurityQos, __inout_opt PPORT_VIEW ClientView, __in_opt PSID RequiredServerSid, __inout_opt PREMOTE_PORT_VIEW ServerView, __out_opt PULONG MaxMessageLength, __inout_opt PVOID ConnectionInformation, __inout_opt PULONG ConnectionInformationLength)
NTSTATUS NtSerializeBoot (VOID)
NTSTATUS NtSetBootEntryOrder (__in_ecount(Count) PULONG Ids, __in ULONG Count)
NTSTATUS NtSetBootOptions (__in PBOOT_OPTIONS BootOptions, __in ULONG FieldsToChange)
NTSTATUS NtSetContextThread (__in HANDLE ThreadHandle, __in PCONTEXT ThreadContext)
NTSTATUS NtSetDebugFilterState (__in ULONG ComponentId, __in ULONG Level, __in BOOLEAN State)
NTSTATUS NtSetDefaultHardErrorPort (__in HANDLE DefaultHardErrorPort)
NTSTATUS NtSetDefaultLocale (__in BOOLEAN UserProfile, __in LCID DefaultLocaleId)
NTSTATUS NtSetDefaultUILanguage (__in LANGID DefaultUILanguageId)
NTSTATUS NtSetDriverEntryOrder (__in_ecount(Count) PULONG Ids, __in ULONG Count)
NTSTATUS NtSetEaFile (__in HANDLE FileHandle, __out PIO_STATUS_BLOCK IoStatusBlock, __in_bcount(Length) PVOID Buffer, __in ULONG Length)
NTSTATUS NtSetEventBoostPriority (__in HANDLE EventHandle)
NTSTATUS NtSetEvent (__in HANDLE EventHandle, __out_opt PLONG PreviousState)
NTSTATUS NtSetHighEventPair (__in HANDLE EventPairHandle)
NTSTATUS NtSetHighWaitLowEventPair (__in HANDLE EventPairHandle)
NTSTATUS NtSetInformationDebugObject (__out HANDLE DebugObjectHandle, __out DEBUGOBJECTINFOCLASS DebugObjectInformationClass, __out PVOID DebugInformation, __out ULONG DebugInformationLength, __out PULONG ReturnLength OPTIONAL)
NTSTATUS NtSetInformationEnlistment (__in_opt HANDLE EnlistmentHandle, __in ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass, __in_bcount(EnlistmentInformationLength) PVOID EnlistmentInformation, __in ULONG EnlistmentInformationLength)
NTSTATUS NtSetInformationFile (__in HANDLE FileHandle, __out PIO_STATUS_BLOCK IoStatusBlock, __in_bcount(Length) PVOID FileInformation, __in ULONG Length, __in FILE_INFORMATION_CLASS FileInformationClass)
NTSTATUS NtSetInformationJobObject (__in HANDLE JobHandle, __in JOBOBJECTINFOCLASS JobObjectInformationClass, __in_bcount(JobObjectInformationLength) PVOID JobObjectInformation, __in ULONG JobObjectInformationLength)
NTSTATUS NtSetInformationKey (__in HANDLE KeyHandle, __in KEY_SET_INFORMATION_CLASS KeySetInformationClass, __in_bcount(KeySetInformationLength) PVOID KeySetInformation, __in ULONG KeySetInformationLength)
NTSTATUS NtSetInformationObject (__in HANDLE Handle, __in OBJECT_INFORMATION_CLASS ObjectInformationClass, __in_bcount(ObjectInformationLength) PVOID ObjectInformation, __in ULONG ObjectInformationLength)
NTSTATUS NtSetInformationProcess (__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass, __in_bcount(ProcessInformationLength) PVOID ProcessInformation, __in ULONG ProcessInformationLength)
NTSTATUS NtSetInformationResourceManager (__in HANDLE ResourceManagerHandle, __in RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass, __in_bcount(ResourceManagerInformationLength) PVOID ResourceManagerInformation, __in ULONG ResourceManagerInformationLength)
NTSTATUS NtSetInformationThread (__in HANDLE ThreadHandle, __in THREADINFOCLASS ThreadInformationClass, __in_bcount(ThreadInformationLength) PVOID ThreadInformation, __in ULONG ThreadInformationLength)
NTSTATUS NtSetInformationToken (__in HANDLE TokenHandle, __in TOKEN_INFORMATION_CLASS TokenInformationClass, __in_bcount(TokenInformationLength) PVOID TokenInformation, __in ULONG TokenInformationLength)
NTSTATUS NtSetInformationTransaction (__in HANDLE TransactionHandle, __in TRANSACTION_INFORMATION_CLASS TransactionInformationClass, __in_bcount(TransactionInformationLength) PVOID TransactionInformation, __in ULONG TransactionInformationLength)
NTSTATUS NtSetInformationTransactionManager (__in_opt HANDLE TmHandle, __in TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass, __in_bcount(TransactionManagerInformationLength) PVOID TransactionManagerInformation, __in ULONG TransactionManagerInformationLength)
NTSTATUS NtSetInformationWorkerFactory (__in HANDLE WorkerFactoryHandle, __in WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, __in_bcount(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation, __in ULONG WorkerFactoryInformationLength)
NTSTATUS NtSetIntervalProfile (__in ULONG Interval, __in KPROFILE_SOURCE Source)
NTSTATUS NtSetIoCompletionEx (__in HANDLE IoCompletionHandle, __in HANDLE IoCompletionReserveHandle, __in PVOID KeyContext, __in_opt PVOID ApcContext, __in NTSTATUS IoStatus, __in ULONG_PTR IoStatusInformation)
NTSTATUS NtSetIoCompletion (__in HANDLE IoCompletionHandle, __in PVOID KeyContext, __in_opt PVOID ApcContext, __in NTSTATUS IoStatus, __in ULONG_PTR IoStatusInformation)
NTSTATUS NtSetLdtEntries (__in ULONG Selector0, __in ULONG Entry0Low, __in ULONG Entry0Hi, __in ULONG Selector1, __in ULONG Entry1Low, __in ULONG Entry1Hi)
NTSTATUS NtSetLowEventPair (__in HANDLE EventPairHandle)
NTSTATUS NtSetLowWaitHighEventPair (__in HANDLE EventPairHandle)
NTSTATUS NtSetQuotaInformationFile (__in HANDLE FileHandle, __out PIO_STATUS_BLOCK IoStatusBlock, __in_bcount(Length) PVOID Buffer, __in ULONG Length)
NTSTATUS NtSetSecurityObject (__in HANDLE Handle, __in SECURITY_INFORMATION SecurityInformation, __in PSECURITY_DESCRIPTOR SecurityDescriptor)
NTSTATUS NtSetSystemEnvironmentValueEx (__in PUNICODE_STRING VariableName, __in LPGUID VendorGuid, __in_bcount_opt(ValueLength) PVOID Value, __in ULONG ValueLength, __in ULONG Attributes)
NTSTATUS NtSetSystemEnvironmentValue (__in PUNICODE_STRING VariableName, __in PUNICODE_STRING VariableValue)
NTSTATUS NtSetSystemInformation (__in SYSTEM_INFORMATION_CLASS SystemInformationClass, __in_bcount_opt(SystemInformationLength) PVOID SystemInformation, __in ULONG SystemInformationLength)
NTSTATUS NtSetSystemPowerState (__in POWER_ACTION SystemAction, __in SYSTEM_POWER_STATE MinSystemState, __in ULONG Flags)
NTSTATUS NtSetSystemTime (__in_opt PLARGE_INTEGER SystemTime, __out_opt PLARGE_INTEGER PreviousTime)
NTSTATUS NtSetThreadExecutionState (__in EXECUTION_STATE esFlags, __out EXECUTION_STATE *PreviousFlags)
NTSTATUS NtSetTimerEx (__in HANDLE TimerHandle, __in TIMER_SET_INFORMATION_CLASS TimerSetInformationClass, __inout_bcount(TimerSetInformationLength) PVOID TimerSetInformation, __in ULONG TimerSetInformationLength)
NTSTATUS NtSetTimer (__in HANDLE TimerHandle, __in PLARGE_INTEGER DueTime, __in_opt PTIMER_APC_ROUTINE TimerApcRoutine, __in_opt PVOID TimerContext, __in BOOLEAN WakeTimer, __in_opt LONG Period, __out_opt PBOOLEAN PreviousState)
NTSTATUS NtSetTimerResolution (__in ULONG DesiredTime, __in BOOLEAN SetResolution, __out PULONG ActualTime)
NTSTATUS NtSetUuidSeed (__in PCHAR Seed)
NTSTATUS NtSetValueKey (__in HANDLE KeyHandle, __in PUNICODE_STRING ValueName, __in_opt ULONG TitleIndex, __in ULONG Type, __in_bcount_opt(DataSize) PVOID Data, __in ULONG DataSize)
NTSTATUS NtSetVolumeInformationFile (__in HANDLE FileHandle, __out PIO_STATUS_BLOCK IoStatusBlock, __in_bcount(Length) PVOID FsInformation, __in ULONG Length, __in FS_INFORMATION_CLASS FsInformationClass)
NTSTATUS NtShutdownSystem (__in SHUTDOWN_ACTION Action)
NTSTATUS NtShutdownWorkerFactory (__in HANDLE WorkerFactoryHandle, __inout LONG *PendingWorkerCount)
NTSTATUS NtSignalAndWaitForSingleObject (__in HANDLE SignalHandle, __in HANDLE WaitHandle, __in BOOLEAN Alertable, __in_opt PLARGE_INTEGER Timeout)
NTSTATUS NtSinglePhaseReject (__in HANDLE EnlistmentHandle, __in_opt PLARGE_INTEGER TmVirtualClock)
NTSTATUS NtStartProfile (__in HANDLE ProfileHandle)
NTSTATUS NtStopProfile (__in HANDLE ProfileHandle)
NTSTATUS NtSuspendProcess (__in HANDLE ProcessHandle)
NTSTATUS NtSuspendThread (__in HANDLE ThreadHandle, __out_opt PULONG PreviousSuspendCount)
NTSTATUS NtSystemDebugControl (__in SYSDBG_COMMAND Command, __inout_bcount_opt(InputBufferLength) PVOID InputBuffer, __in ULONG InputBufferLength, __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer, __in ULONG OutputBufferLength, __out_opt PULONG ReturnLength)
NTSTATUS NtTerminateJobObject (__in HANDLE JobHandle, __in NTSTATUS ExitStatus)
NTSTATUS NtTerminateProcess (__in_opt HANDLE ProcessHandle, __in NTSTATUS ExitStatus)
NTSTATUS NtTerminateThread (__in_opt HANDLE ThreadHandle, __in NTSTATUS ExitStatus)
NTSTATUS NtTestAlert (VOID)
NTSTATUS NtThawRegistry (VOID)
NTSTATUS NtThawTransactions (VOID)
NTSTATUS NtTraceControl (__in ULONG FunctionCode, __in_bcount_opt(InBufferLen) PVOID InBuffer, __in ULONG InBufferLen, __out_bcount_opt(OutBufferLen) PVOID OutBuffer, __in ULONG OutBufferLen, __out PULONG ReturnLength)
NTSTATUS NtTraceEvent (__in HANDLE TraceHandle, __in ULONG Flags, __in ULONG FieldSize, __in PVOID Fields)
NTSTATUS NtTranslateFilePath (__in PFILE_PATH InputFilePath, __in ULONG OutputType, __out_bcount_opt(*OutputFilePathLength) PFILE_PATH OutputFilePath, __inout_opt PULONG OutputFilePathLength)
NTSTATUS NtUmsThreadYield (__in PVOID SchedulerParam)
NTSTATUS NtUnloadDriver (__in PUNICODE_STRING DriverServiceName)
NTSTATUS NtUnloadKey2 (__in POBJECT_ATTRIBUTES TargetKey, __in ULONG Flags)
NTSTATUS NtUnloadKeyEx (__in POBJECT_ATTRIBUTES TargetKey, __in_opt HANDLE Event)
NTSTATUS NtUnloadKey (__in POBJECT_ATTRIBUTES TargetKey)
NTSTATUS NtUnlockFile (__in HANDLE FileHandle, __out PIO_STATUS_BLOCK IoStatusBlock, __in PLARGE_INTEGER ByteOffset, __in PLARGE_INTEGER Length, __in ULONG Key)
NTSTATUS NtUnlockVirtualMemory (__in HANDLE ProcessHandle, __inout PVOID *BaseAddress, __inout PSIZE_T RegionSize, __in ULONG MapType)
NTSTATUS NtUnmapViewOfSection (__in HANDLE ProcessHandle, __in PVOID BaseAddress)
NTSTATUS NtVdmControl (__in VDMSERVICECLASS Service, __inout PVOID ServiceData)
NTSTATUS NtWaitForDebugEvent (__out HANDLE DebugObjectHandle, __out BOOLEAN Alertable, __out PLARGE_INTEGER Timeout OPTIONAL, __out PDBGUI_WAIT_STATE_CHANGE WaitStateChange)
NTSTATUS NtWaitForKeyedEvent (__in HANDLE KeyedEventHandle, __in PVOID KeyValue, __in BOOLEAN Alertable, __in_opt PLARGE_INTEGER Timeout)
NTSTATUS NtWaitForMultipleObjects32 (__in ULONG Count, __in_ecount(Count) LONG Handles[], __in WAIT_TYPE WaitType, __in BOOLEAN Alertable, __in_opt PLARGE_INTEGER Timeout)
NTSTATUS NtWaitForMultipleObjects (__in ULONG Count, __in_ecount(Count) HANDLE Handles[], __in WAIT_TYPE WaitType, __in BOOLEAN Alertable, __in_opt PLARGE_INTEGER Timeout)
NTSTATUS NtWaitForSingleObject (__in HANDLE Handle, __in BOOLEAN Alertable, __in_opt PLARGE_INTEGER Timeout)
NTSTATUS NtWaitForWorkViaWorkerFactory (__in HANDLE WorkerFactoryHandle, __out PFILE_IO_COMPLETION_INFORMATION MiniPacket)
NTSTATUS NtWaitHighEventPair (__in HANDLE EventPairHandle)
NTSTATUS NtWaitLowEventPair (__in HANDLE EventPairHandle)
NTSTATUS NtWorkerFactoryWorkerReady (__in HANDLE WorkerFactoryHandle)
NTSTATUS NtWriteFileGather (__in HANDLE FileHandle, __in_opt HANDLE Event, __in_opt PIO_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __in PFILE_SEGMENT_ELEMENT SegmentArray, __in ULONG Length, __in_opt PLARGE_INTEGER ByteOffset, __in_opt PULONG Key)
NTSTATUS NtWriteFile (__in HANDLE FileHandle, __in_opt HANDLE Event, __in_opt PIO_APC_ROUTINE ApcRoutine, __in_opt PVOID ApcContext, __out PIO_STATUS_BLOCK IoStatusBlock, __in_bcount(Length) PVOID Buffer, __in ULONG Length, __in_opt PLARGE_INTEGER ByteOffset, __in_opt PULONG Key)
NTSTATUS NtWriteRequestData (__in HANDLE PortHandle, __in PPORT_MESSAGE Message, __in ULONG DataEntryIndex, __in_bcount(BufferSize) PVOID Buffer, __in SIZE_T BufferSize, __out_opt PSIZE_T NumberOfBytesWritten)
NTSTATUS NtWriteVirtualMemory (__in HANDLE ProcessHandle, __in_opt PVOID BaseAddress, __in_bcount(BufferSize) PVOID Buffer, __in SIZE_T BufferSize, __out_opt PSIZE_T NumberOfBytesWritten)
NTSTATUS NtYieldExecution (VOID)
*/

#endif
