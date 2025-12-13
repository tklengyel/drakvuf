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

#ifndef SYSCALLS_WIN_H
#define SYSCALLS_WIN_H

#include "private.h"
#include "private_2.h"

class win_syscalls : public syscalls_base
{
public:
    GSList* strings_to_free = nullptr;

    std::array<std::array<addr_t, 2>, 2> sst;

    std::unordered_map<vmi_pid_t, std::vector<syscalls_ns::syscalls_module>> procs;

    addr_t image_path_name;
    std::string win32k_profile;
    bool win32k_initialized;

    std::unique_ptr<libhook::SyscallHook> load_driver_hook;
    std::unique_ptr<libhook::SyscallHook> create_process_hook;
    std::unique_ptr<libhook::SyscallHook> delete_process_hook;
    std::unique_ptr<libhook::ReturnHook> wait_process_creation_hook;

    bool setup_win32k_syscalls(drakvuf_t drakvuf);

    event_response_t load_driver_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t create_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t create_process_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    event_response_t delete_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    bool trap_syscall_table_entries(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t cr3, bool ntos, addr_t base, std::array<addr_t, 2> _sst, json_object* json);

    void print_syscall(
        drakvuf_t drakvuf, drakvuf_trap_info_t* info,
        int nr, const char* module, const syscalls_ns::syscall_t* sc,
        const std::vector<uint64_t>& args, privilege_mode_t mode,
        const std::optional<std::string>& from_dll, const std::optional<std::string>& from_parent_dll,
        bool is_ret, std::optional<uint32_t> status
    );

    win_syscalls(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output);
    ~win_syscalls();

    void register_parsers();

protected:
    void parse_handle_for_pid_tid(
        fmt_args_t& fmt_args, const syscalls_ns::arg_t& arg, drakvuf_trap_info_t* info,
        uint64_t value, bool resolve_pid, bool resolve_tid
    );
};

namespace syscalls_ns
{

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
    ARG("PortHandle", "", DIR_OUT, PHANDLE),
    ARG("PortContext", "opt", DIR_IN, PVOID),
    ARG("ConnectionRequest", "", DIR_IN, PPORT_MESSAGE),
    ARG("AcceptConnection", "", DIR_IN, BOOLEAN),
    ARG("ServerView", "opt", DIR_INOUT, PPORT_VIEW),
    ARG("ClientView", "opt", DIR_OUT, PREMOTE_PORT_VIEW),
);
SYSCALL(NtAccessCheckAndAuditAlarm, NTSTATUS,
    ARG("SubsystemName", "", DIR_IN, PUNICODE_STRING),
    ARG("HandleId", "opt", DIR_IN, PVOID),
    ARG("ObjectTypeName", "", DIR_IN, PUNICODE_STRING),
    ARG("ObjectName", "", DIR_IN, PUNICODE_STRING),
    ARG("SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("GenericMapping", "", DIR_IN, PGENERIC_MAPPING),
    ARG("ObjectCreation", "", DIR_IN, BOOLEAN),
    ARG("GrantedAccess", "", DIR_OUT, PACCESS_MASK),
    ARG("AccessStatus", "", DIR_OUT, PNTSTATUS),
    ARG("GenerateOnClose", "", DIR_OUT, PBOOLEAN),
);
SYSCALL(NtAccessCheckByTypeAndAuditAlarm, NTSTATUS,
    ARG("SubsystemName", "", DIR_IN, PUNICODE_STRING),
    ARG("HandleId", "opt", DIR_IN, PVOID),
    ARG("ObjectTypeName", "", DIR_IN, PUNICODE_STRING),
    ARG("ObjectName", "", DIR_IN, PUNICODE_STRING),
    ARG("SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR),
    ARG("PrincipalSelfSid", "opt", DIR_IN, PSID),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("AuditType", "", DIR_IN, AUDIT_EVENT_TYPE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("ObjectTypeList", "ecount_opt(ObjectTypeListLength)", DIR_IN, POBJECT_TYPE_LIST),
    ARG("ObjectTypeListLength", "", DIR_IN, ULONG),
    ARG("GenericMapping", "", DIR_IN, PGENERIC_MAPPING),
    ARG("ObjectCreation", "", DIR_IN, BOOLEAN),
    ARG("GrantedAccess", "", DIR_OUT, PACCESS_MASK),
    ARG("AccessStatus", "", DIR_OUT, PNTSTATUS),
    ARG("GenerateOnClose", "", DIR_OUT, PBOOLEAN),
);
SYSCALL(NtAccessCheckByType, NTSTATUS,
    ARG("SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR),
    ARG("PrincipalSelfSid", "opt", DIR_IN, PSID),
    ARG("ClientToken", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectTypeList", "ecount(ObjectTypeListLength)", DIR_IN, POBJECT_TYPE_LIST),
    ARG("ObjectTypeListLength", "", DIR_IN, ULONG),
    ARG("GenericMapping", "", DIR_IN, PGENERIC_MAPPING),
    ARG("PrivilegeSet", "bcount(*PrivilegeSetLength)", DIR_OUT, PPRIVILEGE_SET),
    ARG("PrivilegeSetLength", "", DIR_INOUT, PULONG),
    ARG("GrantedAccess", "", DIR_OUT, PACCESS_MASK),
    ARG("AccessStatus", "", DIR_OUT, PNTSTATUS),
);
SYSCALL(NtAccessCheckByTypeResultListAndAuditAlarmByHandle, NTSTATUS,
    ARG("SubsystemName", "", DIR_IN, PUNICODE_STRING),
    ARG("HandleId", "opt", DIR_IN, PVOID),
    ARG("ClientToken", "", DIR_IN, HANDLE),
    ARG("ObjectTypeName", "", DIR_IN, PUNICODE_STRING),
    ARG("ObjectName", "", DIR_IN, PUNICODE_STRING),
    ARG("SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR),
    ARG("PrincipalSelfSid", "opt", DIR_IN, PSID),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("AuditType", "", DIR_IN, AUDIT_EVENT_TYPE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("ObjectTypeList", "ecount_opt(ObjectTypeListLength)", DIR_IN, POBJECT_TYPE_LIST),
    ARG("ObjectTypeListLength", "", DIR_IN, ULONG),
    ARG("GenericMapping", "", DIR_IN, PGENERIC_MAPPING),
    ARG("ObjectCreation", "", DIR_IN, BOOLEAN),
    ARG("GrantedAccess", "ecount(ObjectTypeListLength)", DIR_OUT, PACCESS_MASK),
    ARG("AccessStatus", "ecount(ObjectTypeListLength)", DIR_OUT, PNTSTATUS),
    ARG("GenerateOnClose", "", DIR_OUT, PBOOLEAN),
);
SYSCALL(NtAccessCheckByTypeResultListAndAuditAlarm, NTSTATUS,
    ARG("SubsystemName", "", DIR_IN, PUNICODE_STRING),
    ARG("HandleId", "opt", DIR_IN, PVOID),
    ARG("ObjectTypeName", "", DIR_IN, PUNICODE_STRING),
    ARG("ObjectName", "", DIR_IN, PUNICODE_STRING),
    ARG("SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR),
    ARG("PrincipalSelfSid", "opt", DIR_IN, PSID),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("AuditType", "", DIR_IN, AUDIT_EVENT_TYPE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("ObjectTypeList", "ecount_opt(ObjectTypeListLength)", DIR_IN, POBJECT_TYPE_LIST),
    ARG("ObjectTypeListLength", "", DIR_IN, ULONG),
    ARG("GenericMapping", "", DIR_IN, PGENERIC_MAPPING),
    ARG("ObjectCreation", "", DIR_IN, BOOLEAN),
    ARG("GrantedAccess", "ecount(ObjectTypeListLength)", DIR_OUT, PACCESS_MASK),
    ARG("AccessStatus", "ecount(ObjectTypeListLength)", DIR_OUT, PNTSTATUS),
    ARG("GenerateOnClose", "", DIR_OUT, PBOOLEAN),
);
SYSCALL(NtAccessCheckByTypeResultList, NTSTATUS,
    ARG("SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR),
    ARG("PrincipalSelfSid", "opt", DIR_IN, PSID),
    ARG("ClientToken", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectTypeList", "ecount(ObjectTypeListLength)", DIR_IN, POBJECT_TYPE_LIST),
    ARG("ObjectTypeListLength", "", DIR_IN, ULONG),
    ARG("GenericMapping", "", DIR_IN, PGENERIC_MAPPING),
    ARG("PrivilegeSet", "bcount(*PrivilegeSetLength)", DIR_OUT, PPRIVILEGE_SET),
    ARG("PrivilegeSetLength", "", DIR_INOUT, PULONG),
    ARG("GrantedAccess", "ecount(ObjectTypeListLength)", DIR_OUT, PACCESS_MASK),
    ARG("AccessStatus", "ecount(ObjectTypeListLength)", DIR_OUT, PNTSTATUS),
);
SYSCALL(NtAccessCheck, NTSTATUS,
    ARG("SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR),
    ARG("ClientToken", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("GenericMapping", "", DIR_IN, PGENERIC_MAPPING),
    ARG("PrivilegeSet", "bcount(*PrivilegeSetLength)", DIR_OUT, PPRIVILEGE_SET),
    ARG("PrivilegeSetLength", "", DIR_INOUT, PULONG),
    ARG("GrantedAccess", "", DIR_OUT, PACCESS_MASK),
    ARG("AccessStatus", "", DIR_OUT, PNTSTATUS),
);
SYSCALL(NtAddAtom, NTSTATUS,
    ARG("AtomName", "bcount_opt(Length)", DIR_IN, PWSTR),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("Atom", "opt", DIR_OUT, PRTL_ATOM),
);
SYSCALL(NtAddBootEntry, NTSTATUS,
    ARG("BootEntry", "", DIR_IN, PBOOT_ENTRY),
    ARG("Id", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtAddDriverEntry, NTSTATUS,
    ARG("DriverEntry", "", DIR_IN, PEFI_DRIVER_ENTRY),
    ARG("Id", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtAdjustGroupsToken, NTSTATUS,
    ARG("TokenHandle", "", DIR_IN, HANDLE),
    ARG("ResetToDefault", "", DIR_IN, BOOLEAN),
    ARG("NewState", "", DIR_IN, PTOKEN_GROUPS),
    ARG("BufferLength", "", DIR_IN, ULONG),
    ARG("PreviousState", "bcount_part_opt(BufferLength,*ReturnLength)", DIR_OUT, PTOKEN_GROUPS),
    ARG("ReturnLength", "", DIR_OUT, PULONG),
);
SYSCALL(NtAdjustPrivilegesToken, NTSTATUS,
    ARG("TokenHandle", "", DIR_IN, HANDLE),
    ARG("DisableAllPrivileges", "", DIR_IN, BOOLEAN),
    ARG("NewState", "opt", DIR_IN, PTOKEN_PRIVILEGES),
    ARG("BufferLength", "", DIR_IN, ULONG),
    ARG("PreviousState", "bcount_part_opt(BufferLength,*ReturnLength)", DIR_OUT, PTOKEN_PRIVILEGES),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtAlertResumeThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("PreviousSuspendCount", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtAlertThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtAllocateLocallyUniqueId, NTSTATUS,
    ARG("Luid", "", DIR_OUT, PLUID),
);
SYSCALL(NtAllocateReserveObject, NTSTATUS,
    ARG("MemoryReserveHandle", "", DIR_OUT, PHANDLE),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("Type", "", DIR_IN, MEMORY_RESERVE_TYPE),
);
SYSCALL(NtAllocateUserPhysicalPages, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("NumberOfPages", "", DIR_INOUT, PULONG_PTR),
    ARG("UserPfnArra;", "ecount(*NumberOfPages)", DIR_OUT, PULONG_PTR),
);
SYSCALL(NtAllocateUuids, NTSTATUS,
    ARG("Time", "", DIR_OUT, PULARGE_INTEGER),
    ARG("Range", "", DIR_OUT, PULONG),
    ARG("Sequence", "", DIR_OUT, PULONG),
    ARG("Seed", "", DIR_OUT, PCHAR),
);
SYSCALL(NtAllocateVirtualMemory, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_INOUT, PPVOID),
    ARG("ZeroBits", "", DIR_IN, ULONG_PTR),
    ARG("RegionSize", "", DIR_INOUT, PSIZE_T),
    ARG("AllocationType", "", DIR_IN, DWORD),
    ARG("Protect", "", DIR_IN, DWORD),
);
SYSCALL(NtAllocateVirtualMemoryEx, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_INOUT, PPVOID),
    ARG("RegionSize", "", DIR_INOUT, PSIZE_T),
    ARG("AllocationType", "", DIR_IN, DWORD),
    ARG("Protect", "", DIR_IN, DWORD),
    ARG("ExtendedParameter", "opt", DIR_INOUT, PMEM_EXTENDED_PARAMETER),
    ARG("ExtendedParameterCount", "", DIR_IN, ULONG),
);
SYSCALL(NtAlpcAcceptConnectPort, NTSTATUS,
    ARG("PortHandle", "", DIR_OUT, PHANDLE),
    ARG("ConnectionPortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("PortAttributes", "", DIR_IN, PALPC_PORT_ATTRIBUTES),
    ARG("PortContext", "opt", DIR_IN, PVOID),
    ARG("ConnectionRequest", "", DIR_IN, PPORT_MESSAGE),
    ARG("ConnectionMessageAttributes", "opt", DIR_INOUT, PALPC_MESSAGE_ATTRIBUTES),
    ARG("AcceptConnection", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtAlpcConnectPortEx, NTSTATUS,
    ARG("PortHandle", "", DIR_OUT, PHANDLE),
    ARG("ConnectionPortObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("ClientPortObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("PortAttributes", "opt", DIR_IN, PALPC_PORT_ATTRIBUTES),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("ServerSecurityRequirements", "opt", DIR_IN, PSECURITY_DESCRIPTOR),
    ARG("ConnectionMessage", "opt", DIR_INOUT, PPORT_MESSAGE),
    ARG("BufferLength", "opt", DIR_INOUT, PSIZE_T),
    ARG("OutMessageAttributes", "opt", DIR_INOUT, PALPC_MESSAGE_ATTRIBUTES),
    ARG("InMessageAttributes", "opt", DIR_INOUT, PALPC_MESSAGE_ATTRIBUTES),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtAlpcCancelMessage, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("MessageContext", "", DIR_IN, PALPC_CONTEXT_ATTR),
);
SYSCALL(NtAlpcConnectPort, NTSTATUS,
    ARG("PortHandle", "", DIR_OUT, PHANDLE),
    ARG("PortName", "", DIR_IN, PUNICODE_STRING),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("PortAttributes", "opt", DIR_IN, PALPC_PORT_ATTRIBUTES),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("RequiredServerSid", "opt", DIR_IN, PSID),
    ARG("ConnectionMessage", "", DIR_INOUT, PPORT_MESSAGE),
    ARG("BufferLength", "opt", DIR_INOUT, PULONG),
    ARG("OutMessageAttributes", "opt", DIR_INOUT, PALPC_MESSAGE_ATTRIBUTES),
    ARG("InMessageAttributes", "opt", DIR_INOUT, PALPC_MESSAGE_ATTRIBUTES),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtAlpcCreatePort, NTSTATUS,
    ARG("PortHandle", "", DIR_OUT, PHANDLE),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("PortAttributes", "opt", DIR_IN, PALPC_PORT_ATTRIBUTES),
);
SYSCALL(NtAlpcCreatePortSection, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("SectionHandle", "opt", DIR_IN, HANDLE),
    ARG("SectionSize", "", DIR_IN, SIZE_T),
    ARG("AlpcSectionHandle", "", DIR_OUT, PALPC_HANDLE),
    ARG("ActualSectionSize", "", DIR_OUT, PSIZE_T),
);
SYSCALL(NtAlpcCreateResourceReserve, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_RESERVED, ULONG),
    ARG("MessageSize", "", DIR_IN, SIZE_T),
    ARG("ResourceId", "", DIR_OUT, PALPC_HANDLE),
);
SYSCALL(NtAlpcCreateSectionView, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_RESERVED, ULONG),
    ARG("ViewAttributes", "", DIR_INOUT, PALPC_DATA_VIEW_ATTR),
);
SYSCALL(NtAlpcCreateSecurityContext, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_RESERVED, ULONG),
    ARG("SecurityAttribute", "", DIR_INOUT, PALPC_SECURITY_ATTR),
);
SYSCALL(NtAlpcDeletePortSection, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_RESERVED, ULONG),
    ARG("SectionHandle", "", DIR_IN, ALPC_HANDLE),
);
SYSCALL(NtAlpcDeleteResourceReserve, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_RESERVED, ULONG),
    ARG("ResourceId", "", DIR_IN, ALPC_HANDLE),
);
SYSCALL(NtAlpcDeleteSectionView, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_RESERVED, ULONG),
    ARG("ViewBase", "", DIR_IN, PVOID),
);
SYSCALL(NtAlpcDeleteSecurityContext, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_RESERVED, ULONG),
    ARG("ContextHandle", "", DIR_IN, ALPC_HANDLE),
);
SYSCALL(NtAlpcDisconnectPort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_IN, ULONG),
);
SYSCALL(NtAlpcImpersonateClientOfPort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("PortMessage", "", DIR_IN, PPORT_MESSAGE),
    ARG("Reserved", "", DIR_RESERVED, PVOID),
);
SYSCALL(NtAlpcOpenSenderProcess, NTSTATUS,
    ARG("ProcessHandle", "", DIR_OUT, PHANDLE),
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("PortMessage", "", DIR_IN, PPORT_MESSAGE),
    ARG("Flags", "", DIR_RESERVED, ULONG),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtAlpcOpenSenderThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_OUT, PHANDLE),
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("PortMessage", "", DIR_IN, PPORT_MESSAGE),
    ARG("Flags", "", DIR_RESERVED, ULONG),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtAlpcQueryInformation, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("PortInformationClass", "", DIR_IN, ALPC_PORT_INFORMATION_CLASS),
    ARG("PortInformation", "bcount(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtAlpcQueryInformationMessage, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("PortMessage", "", DIR_IN, PPORT_MESSAGE),
    ARG("MessageInformationClass", "", DIR_IN, ALPC_MESSAGE_INFORMATION_CLASS),
    ARG("MessageInformation", "bcount(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtAlpcRevokeSecurityContext, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_RESERVED, ULONG),
    ARG("ContextHandle", "", DIR_IN, ALPC_HANDLE),
);
SYSCALL(NtAlpcSendWaitReceivePort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("SendMessage", "opt", DIR_IN, PPORT_MESSAGE),
    ARG("SendMessageAttributes", "opt", DIR_IN, PALPC_MESSAGE_ATTRIBUTES),
    ARG("ReceiveMessage", "opt", DIR_INOUT, PPORT_MESSAGE),
    ARG("BufferLength", "opt", DIR_INOUT, PULONG),
    ARG("ReceiveMessageAttributes", "opt", DIR_INOUT, PALPC_MESSAGE_ATTRIBUTES),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtAlpcSetInformation, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("PortInformationClass", "", DIR_IN, ALPC_PORT_INFORMATION_CLASS),
    ARG("PortInformation", "bcount(Length)", DIR_IN, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
);
SYSCALL(NtApphelpCacheControl, NTSTATUS,
    ARG("type", "", DIR_IN, APPHELPCOMMAND),
    ARG("buf", "", DIR_IN, PVOID),
);
SYSCALL(NtAreMappedFilesTheSame, NTSTATUS,
    ARG("File1MappedAsAnImage", "", DIR_IN, PVOID),
    ARG("File2MappedAsFile", "", DIR_IN, PVOID),
);
SYSCALL(NtAssignProcessToJobObject, NTSTATUS,
    ARG("JobHandle", "", DIR_IN, HANDLE),
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtCallbackReturn, NTSTATUS,
    ARG("OutputBuffer", "opt", DIR_IN, PVOID),
    ARG("OutputLength", "", DIR_IN, ULONG),
    ARG("Status", "", DIR_IN, NTSTATUS),
);
SYSCALL(NtCancelIoFileEx, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoRequestToCancel", "opt", DIR_IN, PIO_STATUS_BLOCK),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
);
SYSCALL(NtCancelIoFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
);
SYSCALL(NtCancelSynchronousIoFile, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("IoRequestToCancel", "opt", DIR_IN, PIO_STATUS_BLOCK),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
);
SYSCALL(NtCancelTimer, NTSTATUS,
    ARG("TimerHandle", "", DIR_IN, HANDLE),
    ARG("CurrentState", "opt", DIR_OUT, PBOOLEAN),
);
SYSCALL(NtClearEvent, NTSTATUS,
    ARG("EventHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtClose, NTSTATUS,
    ARG("Handle", "", DIR_IN, HANDLE),
);
SYSCALL(NtCloseObjectAuditAlarm, NTSTATUS,
    ARG("SubsystemName", "", DIR_IN, PUNICODE_STRING),
    ARG("HandleId", "opt", DIR_IN, PVOID),
    ARG("GenerateOnClose", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtCommitComplete, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtCommitEnlistment, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtCommitTransaction, NTSTATUS,
    ARG("TransactionHandle", "", DIR_IN, HANDLE),
    ARG("Wait", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtCompactKeys, NTSTATUS,
    ARG("Count", "", DIR_IN, ULONG),
    ARG("KeyArray[;", "ecount(Count)", DIR_IN, HANDLE),
);
SYSCALL(NtCompareTokens, NTSTATUS,
    ARG("FirstTokenHandle", "", DIR_IN, HANDLE),
    ARG("SecondTokenHandle", "", DIR_IN, HANDLE),
    ARG("Equal", "", DIR_OUT, PBOOLEAN),
);
SYSCALL(NtCompleteConnectPort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtCompressKey, NTSTATUS,
    ARG("Key", "", DIR_IN, HANDLE),
);
SYSCALL(NtConnectPort, NTSTATUS,
    ARG("PortHandle", "", DIR_OUT, PHANDLE),
    ARG("PortName", "", DIR_IN, PUNICODE_STRING),
    ARG("SecurityQos", "", DIR_IN, PSECURITY_QUALITY_OF_SERVICE),
    ARG("ClientView", "opt", DIR_INOUT, PPORT_VIEW),
    ARG("ServerView", "opt", DIR_INOUT, PREMOTE_PORT_VIEW),
    ARG("MaxMessageLength", "opt", DIR_OUT, PULONG),
    ARG("ConnectionInformation", "opt", DIR_INOUT, PVOID),
    ARG("ConnectionInformationLength", "opt", DIR_INOUT, PULONG),
);
SYSCALL(NtContinue, NTSTATUS,
    ARG("ContextRecord", "", DIR_IN, PCONTEXT),
    ARG("TestAlert", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtCopyFileChunk, NTSTATUS,
    ARG("SourceHandle", "", DIR_IN, HANDLE),
    ARG("DestinationHandle", "", DIR_IN, HANDLE),
    ARG("EventHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("SourceOffset", "", DIR_IN, PLARGE_INTEGER),
    ARG("DestOffset", "", DIR_IN, PLARGE_INTEGER),
    ARG("SourceKey", "", DIR_IN, PULONG),
    ARG("DestKey", "", DIR_IN, PULONG),
    ARG("Flags", "", DIR_IN, ULONG)
);
SYSCALL(NtCreateDebugObject, NTSTATUS,
    ARG("DebugObjectHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("Flags", "", DIR_IN, ULONG),
);
SYSCALL(NtCreateDirectoryObject, NTSTATUS,
    ARG("DirectoryHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtCreateEnlistment, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ResourceManagerHandle", "", DIR_IN, HANDLE),
    ARG("TransactionHandle", "", DIR_IN, HANDLE),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("CreateOptions", "opt", DIR_IN, ULONG),
    ARG("NotificationMask", "", DIR_IN, NOTIFICATION_MASK),
    ARG("EnlistmentKey", "opt", DIR_IN, PVOID),
);
SYSCALL(NtCreateEvent, NTSTATUS,
    ARG("EventHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("EventType", "", DIR_IN, EVENT_TYPE),
    ARG("InitialState", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtCreateEventPair, NTSTATUS,
    ARG("EventPairHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtCreateFile, NTSTATUS,
    ARG("FileHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("AllocationSize", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("FileAttributes", "", DIR_IN, ULONG),
    ARG("ShareAccess", "", DIR_IN, ULONG),
    ARG("CreateDisposition", "", DIR_IN, ULONG),
    ARG("CreateOptions", "", DIR_IN, ULONG),
    ARG("EaBuffer", "bcount_opt(EaLength)", DIR_IN, PVOID),
    ARG("EaLength", "", DIR_IN, ULONG),
);
SYSCALL(NtCreateIoCompletion, NTSTATUS,
    ARG("IoCompletionHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("Count", "", DIR_IN, ULONG),
);
SYSCALL(NtCreateJobObject, NTSTATUS,
    ARG("JobHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtCreateJobSet, NTSTATUS,
    ARG("NumJob", "", DIR_IN, ULONG),
    ARG("UserJobSet", "ecount(NumJob)", DIR_IN, PJOB_SET_ARRAY),
    ARG("Flags", "", DIR_IN, ULONG),
);
SYSCALL(NtCreateKeyedEvent, NTSTATUS,
    ARG("KeyedEventHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("Flags", "", DIR_IN, ULONG),
);
SYSCALL(NtCreateKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("TitleIndex", "", DIR_RESERVED, ULONG),
    ARG("Class", "opt", DIR_IN, PUNICODE_STRING),
    ARG("CreateOptions", "", DIR_IN, ULONG),
    ARG("Disposition", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtCreateKeyTransacted, NTSTATUS,
    ARG("KeyHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("TitleIndex", "", DIR_RESERVED, ULONG),
    ARG("Class", "opt", DIR_IN, PUNICODE_STRING),
    ARG("CreateOptions", "", DIR_IN, ULONG),
    ARG("TransactionHandle", "", DIR_IN, HANDLE),
    ARG("Disposition", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtCreateMailslotFile, NTSTATUS,
    ARG("FileHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ULONG),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("CreateOptions", "", DIR_IN, ULONG),
    ARG("MailslotQuota", "", DIR_IN, ULONG),
    ARG("MaximumMessageSize", "", DIR_IN, ULONG),
    ARG("ReadTimeout", "", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtCreateMutant, NTSTATUS,
    ARG("MutantHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("InitialOwner", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtCreateNamedPipeFile, NTSTATUS,
    ARG("FileHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ULONG),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("ShareAccess", "", DIR_IN, ULONG),
    ARG("CreateDisposition", "", DIR_IN, ULONG),
    ARG("CreateOptions", "", DIR_IN, ULONG),
    ARG("NamedPipeType", "", DIR_IN, ULONG),
    ARG("ReadMode", "", DIR_IN, ULONG),
    ARG("CompletionMode", "", DIR_IN, ULONG),
    ARG("MaximumInstances", "", DIR_IN, ULONG),
    ARG("InboundQuota", "", DIR_IN, ULONG),
    ARG("OutboundQuota", "", DIR_IN, ULONG),
    ARG("DefaultTimeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtCreatePagingFile, NTSTATUS,
    ARG("PageFileName", "", DIR_IN, PUNICODE_STRING),
    ARG("MinimumSize", "", DIR_IN, PLARGE_INTEGER),
    ARG("MaximumSize", "", DIR_IN, PLARGE_INTEGER),
    ARG("Priority", "", DIR_IN, ULONG),
);
SYSCALL(NtCreatePort, NTSTATUS,
    ARG("PortHandle", "", DIR_OUT, PHANDLE),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("MaxConnectionInfoLength", "", DIR_IN, ULONG),
    ARG("MaxMessageLength", "", DIR_IN, ULONG),
    ARG("MaxPoolUsage", "opt", DIR_IN, ULONG),
);
SYSCALL(NtCreatePrivateNamespace, NTSTATUS,
    ARG("NamespaceHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("BoundaryDescriptor", "", DIR_IN, PVOID),
);
SYSCALL(NtCreateProcessEx, NTSTATUS,
    ARG("ProcessHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("ParentProcess", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("SectionHandle", "opt", DIR_IN, HANDLE),
    ARG("DebugPort", "opt", DIR_IN, HANDLE),
    ARG("ExceptionPort", "opt", DIR_IN, HANDLE),
    ARG("JobMemberLevel", "", DIR_IN, ULONG),
);
SYSCALL(NtCreateProcess, NTSTATUS,
    ARG("ProcessHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("ParentProcess", "", DIR_IN, HANDLE),
    ARG("InheritObjectTable", "", DIR_IN, BOOLEAN),
    ARG("SectionHandle", "opt", DIR_IN, HANDLE),
    ARG("DebugPort", "opt", DIR_IN, HANDLE),
    ARG("ExceptionPort", "opt", DIR_IN, HANDLE),
);
SYSCALL(NtCreateProfileEx, NTSTATUS,
    ARG("ProfileHandle", "", DIR_OUT, PHANDLE),
    ARG("Process", "opt", DIR_IN, HANDLE),
    ARG("ProfileBase", "", DIR_IN, PVOID),
    ARG("ProfileSize", "", DIR_IN, SIZE_T),
    ARG("BucketSize", "", DIR_IN, ULONG),
    ARG("Buffer", "", DIR_IN, PULONG),
    ARG("BufferSize", "", DIR_IN, ULONG),
    ARG("ProfileSource", "", DIR_IN, KPROFILE_SOURCE),
    ARG("GroupAffinityCount", "", DIR_IN, ULONG),
    ARG("GroupAffinity", "opt", DIR_IN, PGROUP_AFFINITY),
);
SYSCALL(NtCreateProfile, NTSTATUS,
    ARG("ProfileHandle", "", DIR_OUT, PHANDLE),
    ARG("Process", "", DIR_IN, HANDLE),
    ARG("RangeBase", "", DIR_IN, PVOID),
    ARG("RangeSize", "", DIR_IN, SIZE_T),
    ARG("BucketSize", "", DIR_IN, ULONG),
    ARG("Buffer", "", DIR_IN, PULONG),
    ARG("BufferSize", "", DIR_IN, ULONG),
    ARG("ProfileSource", "", DIR_IN, KPROFILE_SOURCE),
    ARG("Affinity", "", DIR_IN, KAFFINITY),
);
SYSCALL(NtCreateResourceManager, NTSTATUS,
    ARG("ResourceManagerHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("TmHandle", "", DIR_IN, HANDLE),
    ARG("RmGuid", "", DIR_IN, LPGUID),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("CreateOptions", "opt", DIR_IN, ULONG),
    ARG("Description", "opt", DIR_IN, PUNICODE_STRING),
);
SYSCALL(NtCreateSection, NTSTATUS,
    ARG("SectionHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("MaximumSize", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("SectionPageProtection", "", DIR_IN, ULONG),
    ARG("AllocationAttributes", "", DIR_IN, ULONG),
    ARG("FileHandle", "opt", DIR_IN, HANDLE),
);
SYSCALL(NtCreateSectionEx, NTSTATUS,
    ARG("SectionHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("MaximumSize", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("SectionPageProtection", "", DIR_IN, ULONG),
    ARG("AllocationAttributes", "", DIR_IN, ULONG),
    ARG("FileHandle", "opt", DIR_IN, HANDLE),
    ARG("ExtendedParameter", "opt", DIR_INOUT, PMEM_EXTENDED_PARAMETER),
    ARG("ExtendedParameterCount", "", DIR_IN, ULONG),
);
SYSCALL(NtCreateSemaphore, NTSTATUS,
    ARG("SemaphoreHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("InitialCount", "", DIR_IN, LONG),
    ARG("MaximumCount", "", DIR_IN, LONG),
);
SYSCALL(NtCreateSymbolicLinkObject, NTSTATUS,
    ARG("LinkHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("LinkTarget", "", DIR_IN, PUNICODE_STRING),
);
SYSCALL(NtCreateThreadEx, NTSTATUS,
    ARG("ThreadHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("StartRoutine", "", DIR_IN, PVOID),
    ARG("Argument", "opt", DIR_IN, PVOID),
    ARG("CreateFlags", "", DIR_IN, ULONG),
    ARG("ZeroBits", "opt", DIR_IN, ULONG_PTR),
    ARG("StackSize", "opt", DIR_IN, SIZE_T),
    ARG("MaximumStackSize", "opt", DIR_IN, SIZE_T),
    ARG("AttributeList", "opt", DIR_IN, PPS_ATTRIBUTE_LIST),
);
SYSCALL(NtCreateThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("ClientId", "", DIR_OUT, PCLIENT_ID),
    ARG("ThreadContext", "", DIR_IN, PCONTEXT),
    ARG("InitialTeb", "", DIR_IN, PINITIAL_TEB),
    ARG("CreateSuspended", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtCreateTimer, NTSTATUS,
    ARG("TimerHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("TimerType", "", DIR_IN, TIMER_TYPE),
);
SYSCALL(NtCreateToken, NTSTATUS,
    ARG("TokenHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("TokenType", "", DIR_IN, TOKEN_TYPE),
    ARG("AuthenticationId", "", DIR_IN, PLUID),
    ARG("ExpirationTime", "", DIR_IN, PLARGE_INTEGER),
    ARG("User", "", DIR_IN, PTOKEN_USER),
    ARG("Groups", "", DIR_IN, PTOKEN_GROUPS),
    ARG("Privileges", "", DIR_IN, PTOKEN_PRIVILEGES),
    ARG("Owner", "opt", DIR_IN, PTOKEN_OWNER),
    ARG("PrimaryGroup", "", DIR_IN, PTOKEN_PRIMARY_GROUP),
    ARG("DefaultDacl", "opt", DIR_IN, PTOKEN_DEFAULT_DACL),
    ARG("TokenSource", "", DIR_IN, PTOKEN_SOURCE),
);
SYSCALL(NtCreateTransactionManager, NTSTATUS,
    ARG("TmHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("LogFileName", "opt", DIR_IN, PUNICODE_STRING),
    ARG("CreateOptions", "opt", DIR_IN, ULONG),
    ARG("CommitStrength", "opt", DIR_IN, ULONG),
);
SYSCALL(NtCreateTransaction, NTSTATUS,
    ARG("TransactionHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("Uow", "opt", DIR_IN, LPGUID),
    ARG("TmHandle", "opt", DIR_IN, HANDLE),
    ARG("CreateOptions", "opt", DIR_IN, ULONG),
    ARG("IsolationLevel", "opt", DIR_IN, ULONG),
    ARG("IsolationFlags", "opt", DIR_IN, ULONG),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("Description", "opt", DIR_IN, PUNICODE_STRING),
);
SYSCALL(NtCreateUserProcess, NTSTATUS,
    ARG("ProcessHandle", "", DIR_OUT, PHANDLE),
    ARG("ThreadHandle", "", DIR_OUT, PHANDLE),
    ARG("ProcessDesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ThreadDesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ProcessObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("ThreadObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("ProcessFlags", "", DIR_IN, ULONG),
    ARG("ThreadFlags", "", DIR_IN, ULONG),
    ARG("ProcessParameters", "opt", DIR_IN, PRTL_USER_PROCESS_PARAMETERS),
    ARG("CreateInfo", "opt", DIR_IN, PPROCESS_CREATE_INFO),
    ARG("AttributeList", "opt", DIR_IN, PPROCESS_ATTRIBUTE_LIST),
);
SYSCALL(NtCreateWaitablePort, NTSTATUS,
    ARG("PortHandle", "", DIR_OUT, PHANDLE),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("MaxConnectionInfoLength", "", DIR_IN, ULONG),
    ARG("MaxMessageLength", "", DIR_IN, ULONG),
    ARG("MaxPoolUsage", "opt", DIR_IN, ULONG),
);
SYSCALL(NtCreateWorkerFactory, NTSTATUS,
    ARG("WorkerFactoryHandleReturn", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("CompletionPortHandle", "", DIR_IN, HANDLE),
    ARG("WorkerProcessHandle", "", DIR_IN, HANDLE),
    ARG("StartRoutine", "", DIR_IN, PVOID),
    ARG("StartParameter", "opt", DIR_IN, PVOID),
    ARG("MaxThreadCount", "opt", DIR_IN, ULONG),
    ARG("StackReserve", "opt", DIR_IN, SIZE_T),
    ARG("StackCommit", "opt", DIR_IN, SIZE_T),
);
SYSCALL(NtDebugActiveProcess, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("DebugObjectHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtDebugContinue, NTSTATUS,
    ARG("DebugObjectHandle", "", DIR_IN, HANDLE),
    ARG("ClientId", "", DIR_IN, PCLIENT_ID),
    ARG("ContinueStatus", "", DIR_IN, NTSTATUS),
);
SYSCALL(NtDelayExecution, NTSTATUS,
    ARG("Alertable", "", DIR_IN, BOOLEAN),
    ARG("DelayInterval", "", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtDeleteAtom, NTSTATUS,
    ARG("Atom", "", DIR_IN, RTL_ATOM),
);
SYSCALL(NtDeleteBootEntry, NTSTATUS,
    ARG("Id", "", DIR_IN, ULONG),
);
SYSCALL(NtDeleteDriverEntry, NTSTATUS,
    ARG("Id", "", DIR_IN, ULONG),
);
SYSCALL(NtDeleteFile, NTSTATUS,
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtDeleteKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtDeleteObjectAuditAlarm, NTSTATUS,
    ARG("SubsystemName", "", DIR_IN, PUNICODE_STRING),
    ARG("HandleId", "opt", DIR_IN, PVOID),
    ARG("GenerateOnClose", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtDeletePrivateNamespace, NTSTATUS,
    ARG("NamespaceHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtDeleteValueKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("ValueName", "", DIR_IN, PUNICODE_STRING),
);
SYSCALL(NtDeviceIoControlFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("Event", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("IoControlCode", "", DIR_IN, ULONG),
    ARG("InputBuffer", "bcount_opt(InputBufferLength)", DIR_IN, PVOID),
    ARG("InputBufferLength", "", DIR_IN, ULONG),
    ARG("OutputBuffer", "bcount_opt(OutputBufferLength)", DIR_OUT, PVOID),
    ARG("OutputBufferLength", "", DIR_IN, ULONG),
);
SYSCALL(NtDisplayString, NTSTATUS,
    ARG("String", "", DIR_IN, PUNICODE_STRING),
);
SYSCALL(NtDrawText, NTSTATUS,
    ARG("Text", "", DIR_IN, PUNICODE_STRING),
);
SYSCALL(NtDuplicateObject, NTSTATUS,
    ARG("SourceProcessHandle", "", DIR_IN, HANDLE),
    ARG("SourceHandle", "", DIR_IN, HANDLE),
    ARG("TargetProcessHandle", "opt", DIR_IN, HANDLE),
    ARG("TargetHandle", "opt", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("HandleAttributes", "", DIR_IN, ULONG),
    ARG("Options", "", DIR_IN, ULONG),
);
SYSCALL(NtDuplicateToken, NTSTATUS,
    ARG("ExistingTokenHandle", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("EffectiveOnly", "", DIR_IN, BOOLEAN),
    ARG("TokenType", "", DIR_IN, TOKEN_TYPE),
    ARG("NewTokenHandle", "", DIR_OUT, PHANDLE),
);
SYSCALL(NtEnumerateBootEntries, NTSTATUS,
    ARG("Buffer", "bcount_opt(*BufferLength)", DIR_OUT, PVOID),
    ARG("BufferLength", "", DIR_INOUT, PULONG),
);
SYSCALL(NtEnumerateDriverEntries, NTSTATUS,
    ARG("Buffer", "bcount(*BufferLength)", DIR_OUT, PVOID),
    ARG("BufferLength", "", DIR_INOUT, PULONG),
);
SYSCALL(NtEnumerateKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("Index", "", DIR_IN, ULONG),
    ARG("KeyInformationClass", "", DIR_IN, KEY_INFORMATION_CLASS),
    ARG("KeyInformation", "bcount_opt(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ResultLength", "", DIR_OUT, PULONG),
);
SYSCALL(NtEnumerateSystemEnvironmentValuesEx, NTSTATUS,
    ARG("InformationClass", "", DIR_IN, ULONG),
    ARG("Buffer", "", DIR_OUT, PVOID),
    ARG("BufferLength", "", DIR_INOUT, PULONG),
);
SYSCALL(NtEnumerateTransactionObject, NTSTATUS,
    ARG("RootObjectHandle", "opt", DIR_IN, HANDLE),
    ARG("QueryType", "", DIR_IN, KTMOBJECT_TYPE),
    ARG("ObjectCursor", "bcount(ObjectCursorLength)", DIR_INOUT, PKTMOBJECT_CURSOR),
    ARG("ObjectCursorLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "", DIR_OUT, PULONG),
);
SYSCALL(NtEnumerateValueKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("Index", "", DIR_IN, ULONG),
    ARG("KeyValueInformationClass", "", DIR_IN, KEY_VALUE_INFORMATION_CLASS),
    ARG("KeyValueInformation", "bcount_opt(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ResultLength", "", DIR_OUT, PULONG),
);
SYSCALL(NtExtendSection, NTSTATUS,
    ARG("SectionHandle", "", DIR_IN, HANDLE),
    ARG("NewSectionSize", "", DIR_INOUT, PLARGE_INTEGER),
);
SYSCALL(NtFilterToken, NTSTATUS,
    ARG("ExistingTokenHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("SidsToDisable", "opt", DIR_IN, PTOKEN_GROUPS),
    ARG("PrivilegesToDelete", "opt", DIR_IN, PTOKEN_PRIVILEGES),
    ARG("RestrictedSids", "opt", DIR_IN, PTOKEN_GROUPS),
    ARG("NewTokenHandle", "", DIR_OUT, PHANDLE),
);
SYSCALL(NtFindAtom, NTSTATUS,
    ARG("AtomName", "bcount_opt(Length)", DIR_IN, PWSTR),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("Atom", "opt", DIR_OUT, PRTL_ATOM),
);
SYSCALL(NtFlushBuffersFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
);
SYSCALL(NtFlushInstallUILanguage, NTSTATUS,
    ARG("InstallUILanguage", "", DIR_IN, LANGID),
    ARG("SetComittedFlag", "", DIR_IN, ULONG),
);
SYSCALL(NtFlushInstructionCache, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "opt", DIR_IN, PVOID),
    ARG("Length", "", DIR_IN, SIZE_T),
);
SYSCALL(NtFlushKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtFlushVirtualMemory, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_INOUT, PPVOID),
    ARG("RegionSize", "", DIR_INOUT, PSIZE_T),
    ARG("IoStatus", "", DIR_OUT, PIO_STATUS_BLOCK),
);
SYSCALL(NtFreeUserPhysicalPages, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("NumberOfPages", "", DIR_INOUT, PULONG_PTR),
    ARG("UserPfnArra;", "ecount(*NumberOfPages)", DIR_IN, PULONG_PTR),
);
SYSCALL(NtFreeVirtualMemory, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_INOUT, PPVOID),
    ARG("RegionSize", "", DIR_INOUT, PSIZE_T),
    ARG("FreeType", "", DIR_IN, ULONG),
);
SYSCALL(NtFreezeRegistry, NTSTATUS,
    ARG("TimeOutInSeconds", "", DIR_IN, ULONG),
);
SYSCALL(NtFreezeTransactions, NTSTATUS,
    ARG("FreezeTimeout", "", DIR_IN, PLARGE_INTEGER),
    ARG("ThawTimeout", "", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtFsControlFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("Event", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("IoControlCode", "", DIR_IN, ULONG),
    ARG("InputBuffer", "bcount_opt(InputBufferLength)", DIR_IN, PVOID),
    ARG("InputBufferLength", "", DIR_IN, ULONG),
    ARG("OutputBuffer", "bcount_opt(OutputBufferLength)", DIR_OUT, PVOID),
    ARG("OutputBufferLength", "", DIR_IN, ULONG),
);
SYSCALL(NtGdiBitBlt, INT,
    ARG("hdcDst", "", DIR_IN, HANDLE),
    ARG("x", "", DIR_IN, INT),
    ARG("y", "", DIR_IN, INT),
    ARG("cx", "", DIR_IN, INT),
    ARG("cy", "", DIR_IN, INT),
    ARG("hdcSrc", "", DIR_IN, HANDLE),
    ARG("xSrc", "", DIR_IN, INT),
    ARG("ySrc", "", DIR_IN, INT),
    ARG("rop4", "", DIR_IN, DWORD),
    ARG("crBackColor", "", DIR_IN, DWORD),
    ARG("fl", "", DIR_IN, ULONG)
);
SYSCALL(NtGetContextThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("ThreadContext", "", DIR_INOUT, PCONTEXT),
);
SYSCALL(NtGetDevicePowerState, NTSTATUS,
    ARG("Device", "", DIR_IN, HANDLE),
    ARG("State", "", DIR_OUT, PDEVICE_POWER_STATE),
);
SYSCALL(NtGetMUIRegistryInfo, NTSTATUS,
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("DataSize", "", DIR_INOUT, PULONG),
    ARG("Data", "", DIR_OUT, PVOID),
);
SYSCALL(NtGetNextProcess, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("HandleAttributes", "", DIR_IN, ULONG),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("NewProcessHandle", "", DIR_OUT, PHANDLE),
);
SYSCALL(NtGetNextThread, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("HandleAttributes", "", DIR_IN, ULONG),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("NewThreadHandle", "", DIR_OUT, PHANDLE),
);
SYSCALL(NtGetNlsSectionPtr, NTSTATUS,
    ARG("SectionType", "", DIR_IN, ULONG),
    ARG("SectionData", "", DIR_IN, ULONG),
    ARG("ContextData", "", DIR_IN, PVOID),
    ARG("SectionPointer", "", DIR_OUT, PPVOID),
    ARG("SectionSize", "", DIR_OUT, PULONG),
);
SYSCALL(NtGetNotificationResourceManager, NTSTATUS,
    ARG("ResourceManagerHandle", "", DIR_IN, HANDLE),
    ARG("TransactionNotification", "", DIR_OUT, PTRANSACTION_NOTIFICATION),
    ARG("NotificationLength", "", DIR_IN, ULONG),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
    ARG("Asynchronous", "", DIR_IN, ULONG),
    ARG("AsynchronousContext", "opt", DIR_IN, ULONG_PTR),
);
SYSCALL(NtGetPlugPlayEvent, NTSTATUS,
    ARG("EventHandle", "", DIR_IN, HANDLE),
    ARG("Context", "opt", DIR_IN, PVOID),
    ARG("EventBlock", "bcount(EventBufferSize)", DIR_OUT, PPLUGPLAY_EVENT_BLOCK),
    ARG("EventBufferSize", "", DIR_IN, ULONG),
);
SYSCALL(NtGetWriteWatch, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("BaseAddress", "", DIR_IN, PVOID),
    ARG("RegionSize", "", DIR_IN, SIZE_T),
    ARG("UserAddressArray", "ecount(*EntriesInUserAddressArray)", DIR_OUT, PVOID),
    ARG("EntriesInUserAddressArray", "", DIR_INOUT, PULONG_PTR),
    ARG("Granularity", "", DIR_OUT, PULONG),
);
SYSCALL(NtImpersonateAnonymousToken, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtImpersonateClientOfPort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Message", "", DIR_IN, PPORT_MESSAGE),
);
SYSCALL(NtImpersonateThread, NTSTATUS,
    ARG("ServerThreadHandle", "", DIR_IN, HANDLE),
    ARG("ClientThreadHandle", "", DIR_IN, HANDLE),
    ARG("SecurityQos", "", DIR_IN, PSECURITY_QUALITY_OF_SERVICE),
);
SYSCALL(NtInitializeNlsFiles, NTSTATUS,
    ARG("BaseAddress", "", DIR_OUT, PPVOID),
    ARG("DefaultLocaleId", "", DIR_OUT, PLCID),
    ARG("DefaultCasingTableSize", "", DIR_OUT, PLARGE_INTEGER),
);
SYSCALL(NtInitializeRegistry, NTSTATUS,
    ARG("BootCondition", "", DIR_IN, USHORT),
);
SYSCALL(NtInitiatePowerAction, NTSTATUS,
    ARG("SystemAction", "", DIR_IN, POWER_ACTION),
    ARG("MinSystemState", "", DIR_IN, SYSTEM_POWER_STATE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("Asynchronous", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtIsProcessInJob, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("JobHandle", "opt", DIR_IN, HANDLE),
);
SYSCALL(NtListenPort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("ConnectionRequest", "", DIR_OUT, PPORT_MESSAGE),
);
SYSCALL(NtLoadDriver, NTSTATUS,
    ARG("DriverServiceName", "", DIR_IN, PUNICODE_STRING),
);
SYSCALL(NtLoadKey2, NTSTATUS,
    ARG("TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("SourceFile", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("Flags", "", DIR_IN, ULONG),
);
SYSCALL(NtLoadKeyEx, NTSTATUS,
    ARG("TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("SourceFile", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("TrustClassKey", "opt", DIR_IN, HANDLE),
);
SYSCALL(NtLoadKey, NTSTATUS,
    ARG("TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("SourceFile", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtLockFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("Event", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("ByteOffset", "", DIR_IN, PLARGE_INTEGER),
    ARG("Length", "", DIR_IN, PLARGE_INTEGER),
    ARG("Key", "", DIR_IN, ULONG),
    ARG("FailImmediately", "", DIR_IN, BOOLEAN),
    ARG("ExclusiveLock", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtLockProductActivationKeys, NTSTATUS,
    ARG("pPrivateVer", "opt", DIR_INOUT, PULONG),
    ARG("pSafeMode", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtLockRegistryKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtLockVirtualMemory, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_INOUT, PPVOID),
    ARG("RegionSize", "", DIR_INOUT, PSIZE_T),
    ARG("MapType", "", DIR_IN, ULONG),
);
SYSCALL(NtMakePermanentObject, NTSTATUS,
    ARG("Handle", "", DIR_IN, HANDLE),
);
SYSCALL(NtMakeTemporaryObject, NTSTATUS,
    ARG("Handle", "", DIR_IN, HANDLE),
);
SYSCALL(NtMapCMFModule, NTSTATUS,
    ARG("What", "", DIR_IN, ULONG),
    ARG("Index", "", DIR_IN, ULONG),
    ARG("CacheIndexOut", "opt", DIR_OUT, PULONG),
    ARG("CacheFlagsOut", "opt", DIR_OUT, PULONG),
    ARG("ViewSizeOut", "opt", DIR_OUT, PULONG),
    ARG("BaseAddress", "opt", DIR_OUT, PPVOID),
);
SYSCALL(NtMapUserPhysicalPages, NTSTATUS,
    ARG("VirtualAddress", "", DIR_IN, PVOID),
    ARG("NumberOfPages", "", DIR_IN, ULONG_PTR),
    ARG("UserPfnArra;", "ecount_opt(NumberOfPages)", DIR_IN, PULONG_PTR),
);
SYSCALL(NtMapUserPhysicalPagesScatter, NTSTATUS,
    ARG("VirtualAddresses", "ecount(NumberOfPages)", DIR_IN, PVOID),
    ARG("NumberOfPages", "", DIR_IN, ULONG_PTR),
    ARG("UserPfnArray", "ecount_opt(NumberOfPages)", DIR_IN, PULONG_PTR),
);
SYSCALL(NtMapViewOfSection, NTSTATUS,
    ARG("SectionHandle", "", DIR_IN, HANDLE),
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_INOUT, PPVOID),
    ARG("ZeroBits", "", DIR_IN, ULONG_PTR),
    ARG("CommitSize", "", DIR_IN, SIZE_T),
    ARG("SectionOffset", "opt", DIR_INOUT, PLARGE_INTEGER),
    ARG("ViewSize", "", DIR_INOUT, PSIZE_T),
    ARG("InheritDisposition", "", DIR_IN, SECTION_INHERIT),
    ARG("AllocationType", "", DIR_IN, ULONG),
    ARG("Win32Protect", "", DIR_IN, WIN32_PROTECTION_MASK),
);
SYSCALL(NtMapViewOfSectionEx, NTSTATUS,
    ARG("SectionHandle", "", DIR_IN, HANDLE),
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_INOUT, PPVOID),
    ARG("SectionOffset", "opt", DIR_INOUT, PLARGE_INTEGER),
    ARG("ViewSize", "", DIR_INOUT, PSIZE_T),
    ARG("AllocationType", "", DIR_IN, ULONG),
    ARG("Win32Protect", "", DIR_IN, WIN32_PROTECTION_MASK),
    ARG("ExtendedParameter", "opt", DIR_INOUT, PMEM_EXTENDED_PARAMETER),
    ARG("ExtendedParameterCount", "", DIR_IN, ULONG),
);
SYSCALL(NtModifyBootEntry, NTSTATUS,
    ARG("BootEntry", "", DIR_IN, PBOOT_ENTRY),
);
SYSCALL(NtModifyDriverEntry, NTSTATUS,
    ARG("DriverEntry", "", DIR_IN, PEFI_DRIVER_ENTRY),
);
SYSCALL(NtNotifyChangeDirectoryFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("Event", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("Buffer", "bcount(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("CompletionFilter", "", DIR_IN, ULONG),
    ARG("WatchTree", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtNotifyChangeKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("Event", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("CompletionFilter", "", DIR_IN, ULONG),
    ARG("WatchTree", "", DIR_IN, BOOLEAN),
    ARG("Buffer", "bcount_opt(BufferSize)", DIR_OUT, PVOID),
    ARG("BufferSize", "", DIR_IN, ULONG),
    ARG("Asynchronous", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtNotifyChangeMultipleKeys, NTSTATUS,
    ARG("MasterKeyHandle", "", DIR_IN, HANDLE),
    ARG("Count", "opt", DIR_IN, ULONG),
    ARG("SlaveObjects", "ecount_opt(Count)", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("Event", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("CompletionFilter", "", DIR_IN, ULONG),
    ARG("WatchTree", "", DIR_IN, BOOLEAN),
    ARG("Buffer", "bcount_opt(BufferSize)", DIR_OUT, PVOID),
    ARG("BufferSize", "", DIR_IN, ULONG),
    ARG("Asynchronous", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtNotifyChangeSession, NTSTATUS,
    ARG("Session", "", DIR_IN, HANDLE),
    ARG("IoStateSequence", "", DIR_IN, ULONG),
    ARG("Reserved", "", DIR_IN, PVOID),
    ARG("Action", "", DIR_IN, ULONG),
    ARG("IoState", "", DIR_IN, IO_SESSION_STATE),
    ARG("IoState2", "", DIR_IN, IO_SESSION_STATE),
    ARG("Buffer", "", DIR_IN, PVOID),
    ARG("BufferSize", "", DIR_IN, ULONG),
);
SYSCALL(NtOpenDirectoryObject, NTSTATUS,
    ARG("DirectoryHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenEnlistment, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ResourceManagerHandle", "", DIR_IN, HANDLE),
    ARG("EnlistmentGuid", "", DIR_IN, LPGUID),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenEvent, NTSTATUS,
    ARG("EventHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenEventPair, NTSTATUS,
    ARG("EventPairHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenFile, NTSTATUS,
    ARG("FileHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("ShareAccess", "", DIR_IN, ULONG),
    ARG("OpenOptions", "", DIR_IN, ULONG),
);
SYSCALL(NtOpenIoCompletion, NTSTATUS,
    ARG("IoCompletionHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenJobObject, NTSTATUS,
    ARG("JobHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenKeyedEvent, NTSTATUS,
    ARG("KeyedEventHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenKeyEx, NTSTATUS,
    ARG("KeyHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("OpenOptions", "", DIR_IN, ULONG),
);
SYSCALL(NtOpenKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenKeyTransactedEx, NTSTATUS,
    ARG("KeyHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("OpenOptions", "", DIR_IN, ULONG),
    ARG("TransactionHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtOpenKeyTransacted, NTSTATUS,
    ARG("KeyHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("TransactionHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtOpenMutant, NTSTATUS,
    ARG("MutantHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenObjectAuditAlarm, NTSTATUS,
    ARG("SubsystemName", "", DIR_IN, PUNICODE_STRING),
    ARG("HandleId", "opt", DIR_IN, PVOID),
    ARG("ObjectTypeName", "", DIR_IN, PUNICODE_STRING),
    ARG("ObjectName", "", DIR_IN, PUNICODE_STRING),
    ARG("SecurityDescriptor", "opt", DIR_IN, PSECURITY_DESCRIPTOR),
    ARG("ClientToken", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("GrantedAccess", "", DIR_IN, ACCESS_MASK),
    ARG("Privileges", "opt", DIR_IN, PPRIVILEGE_SET),
    ARG("ObjectCreation", "", DIR_IN, BOOLEAN),
    ARG("AccessGranted", "", DIR_IN, BOOLEAN),
    ARG("GenerateOnClose", "", DIR_OUT, PBOOLEAN),
);
SYSCALL(NtOpenPrivateNamespace, NTSTATUS,
    ARG("NamespaceHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("BoundaryDescriptor", "", DIR_IN, PVOID),
);
SYSCALL(NtOpenProcess, NTSTATUS,
    ARG("ProcessHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("ClientId", "opt", DIR_IN, PCLIENT_ID),
);
SYSCALL(NtOpenProcessTokenEx, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("HandleAttributes", "", DIR_IN, ULONG),
    ARG("TokenHandle", "", DIR_OUT, PHANDLE),
);
SYSCALL(NtOpenProcessToken, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("TokenHandle", "", DIR_OUT, PHANDLE),
);
SYSCALL(NtOpenResourceManager, NTSTATUS,
    ARG("ResourceManagerHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("TmHandle", "", DIR_IN, HANDLE),
    ARG("ResourceManagerGuid", "opt", DIR_IN, LPGUID),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenSection, NTSTATUS,
    ARG("SectionHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenSemaphore, NTSTATUS,
    ARG("SemaphoreHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenSession, NTSTATUS,
    ARG("SessionHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenSymbolicLinkObject, NTSTATUS,
    ARG("LinkHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("ClientId", "opt", DIR_IN, PCLIENT_ID),
);
SYSCALL(NtOpenThreadTokenEx, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("OpenAsSelf", "", DIR_IN, BOOLEAN),
    ARG("HandleAttributes", "", DIR_IN, ULONG),
    ARG("TokenHandle", "", DIR_OUT, PHANDLE),
);
SYSCALL(NtOpenThreadToken, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("OpenAsSelf", "", DIR_IN, BOOLEAN),
    ARG("TokenHandle", "", DIR_OUT, PHANDLE),
);
SYSCALL(NtOpenTimer, NTSTATUS,
    ARG("TimerHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtOpenTransactionManager, NTSTATUS,
    ARG("TmHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "opt", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("LogFileName", "opt", DIR_IN, PUNICODE_STRING),
    ARG("TmIdentity", "opt", DIR_IN, LPGUID),
    ARG("OpenOptions", "opt", DIR_IN, ULONG),
);
SYSCALL(NtOpenTransaction, NTSTATUS,
    ARG("TransactionHandle", "", DIR_OUT, PHANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("Uow", "", DIR_IN, LPGUID),
    ARG("TmHandle", "opt", DIR_IN, HANDLE),
);
SYSCALL(NtPlugPlayControl, NTSTATUS,
    ARG("PnPControlClass", "", DIR_IN, PLUGPLAY_CONTROL_CLASS),
    ARG("PnPControlData", "bcount(PnPControlDataLength)", DIR_INOUT, PVOID),
    ARG("PnPControlDataLength", "", DIR_IN, ULONG),
);
SYSCALL(NtPowerInformation, NTSTATUS,
    ARG("InformationLevel", "", DIR_IN, POWER_INFORMATION_LEVEL),
    ARG("InputBuffer", "bcount_opt(InputBufferLength)", DIR_IN, PVOID),
    ARG("InputBufferLength", "", DIR_IN, ULONG),
    ARG("OutputBuffer", "bcount_opt(OutputBufferLength)", DIR_OUT, PVOID),
    ARG("OutputBufferLength", "", DIR_IN, ULONG),
);
SYSCALL(NtPrepareComplete, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtPrepareEnlistment, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtPrePrepareComplete, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtPrePrepareEnlistment, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtPrivilegeCheck, NTSTATUS,
    ARG("ClientToken", "", DIR_IN, HANDLE),
    ARG("RequiredPrivileges", "", DIR_INOUT, PPRIVILEGE_SET),
    ARG("Result", "", DIR_OUT, PBOOLEAN),
);
SYSCALL(NtPrivilegedServiceAuditAlarm, NTSTATUS,
    ARG("SubsystemName", "", DIR_IN, PUNICODE_STRING),
    ARG("ServiceName", "", DIR_IN, PUNICODE_STRING),
    ARG("ClientToken", "", DIR_IN, HANDLE),
    ARG("Privileges", "", DIR_IN, PPRIVILEGE_SET),
    ARG("AccessGranted", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtPrivilegeObjectAuditAlarm, NTSTATUS,
    ARG("SubsystemName", "", DIR_IN, PUNICODE_STRING),
    ARG("HandleId", "opt", DIR_IN, PVOID),
    ARG("ClientToken", "", DIR_IN, HANDLE),
    ARG("DesiredAccess", "", DIR_IN, ACCESS_MASK),
    ARG("Privileges", "", DIR_IN, PPRIVILEGE_SET),
    ARG("AccessGranted", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtPropagationComplete, NTSTATUS,
    ARG("ResourceManagerHandle", "", DIR_IN, HANDLE),
    ARG("RequestCookie", "", DIR_IN, ULONG),
    ARG("BufferLength", "", DIR_IN, ULONG),
    ARG("Buffer", "", DIR_IN, PVOID),
);
SYSCALL(NtPropagationFailed, NTSTATUS,
    ARG("ResourceManagerHandle", "", DIR_IN, HANDLE),
    ARG("RequestCookie", "", DIR_IN, ULONG),
    ARG("PropStatus", "", DIR_IN, NTSTATUS),
);
SYSCALL(NtProtectVirtualMemory, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_INOUT, PPVOID),
    ARG("RegionSize", "", DIR_INOUT, PSIZE_T),
    ARG("NewProtectWin32", "", DIR_IN, WIN32_PROTECTION_MASK),
    ARG("OldProtect", "", DIR_OUT, PULONG),
);
SYSCALL(NtPulseEvent, NTSTATUS,
    ARG("EventHandle", "", DIR_IN, HANDLE),
    ARG("PreviousState", "opt", DIR_OUT, PLONG),
);
SYSCALL(NtQueryAttributesFile, NTSTATUS,
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("FileInformation", "", DIR_OUT, PFILE_BASIC_INFORMATION),
);
SYSCALL(NtQueryBootEntryOrder, NTSTATUS,
    ARG("Ids", "ecount_opt(*Count)", DIR_OUT, PULONG),
    ARG("Count", "", DIR_INOUT, PULONG),
);
SYSCALL(NtQueryBootOptions, NTSTATUS,
    ARG("BootOptions", "bcount_opt(*BootOptionsLength)", DIR_OUT, PBOOT_OPTIONS),
    ARG("BootOptionsLength", "", DIR_INOUT, PULONG),
);
SYSCALL(NtQueryDebugFilterState, NTSTATUS,
    ARG("ComponentId", "", DIR_IN, ULONG),
    ARG("Level", "", DIR_IN, ULONG),
);
SYSCALL(NtQueryDefaultLocale, NTSTATUS,
    ARG("UserProfile", "", DIR_IN, BOOLEAN),
    ARG("DefaultLocaleId", "", DIR_OUT, PLCID),
);
SYSCALL(NtQueryDefaultUILanguage, NTSTATUS,
    ARG("DefaultUILanguageId", "", DIR_OUT, PLANGID),
);
SYSCALL(NtQueryDirectoryFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("Event", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("FileInformation", "bcount(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("FileInformationClass", "", DIR_IN, FILE_INFORMATION_CLASS),
    ARG("ReturnSingleEntry", "", DIR_IN, BOOLEAN),
    ARG("FileName", "", DIR_IN, PUNICODE_STRING),
    ARG("RestartScan", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtQueryDirectoryObject, NTSTATUS,
    ARG("DirectoryHandle", "", DIR_IN, HANDLE),
    ARG("Buffer", "bcount_opt(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ReturnSingleEntry", "", DIR_IN, BOOLEAN),
    ARG("RestartScan", "", DIR_IN, BOOLEAN),
    ARG("Context", "", DIR_INOUT, PULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryDriverEntryOrder, NTSTATUS,
    ARG("Ids", "ecount(*Count)", DIR_OUT, PULONG),
    ARG("Count", "", DIR_INOUT, PULONG),
);
SYSCALL(NtQueryEaFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("Buffer", "bcount(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ReturnSingleEntry", "", DIR_IN, BOOLEAN),
    ARG("EaList", "bcount_opt(EaListLength)", DIR_IN, PVOID),
    ARG("EaListLength", "", DIR_IN, ULONG),
    ARG("EaIndex", "opt", DIR_IN, PULONG),
    ARG("RestartScan", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtQueryEvent, NTSTATUS,
    ARG("EventHandle", "", DIR_IN, HANDLE),
    ARG("EventInformationClass", "", DIR_IN, EVENT_INFORMATION_CLASS),
    ARG("EventInformation", "bcount(EventInformationLength)", DIR_OUT, PVOID),
    ARG("EventInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryFullAttributesFile, NTSTATUS,
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("FileInformation", "", DIR_OUT, PFILE_NETWORK_OPEN_INFORMATION),
);
SYSCALL(NtQueryInformationAtom, NTSTATUS,
    ARG("Atom", "", DIR_IN, RTL_ATOM),
    ARG("InformationClass", "", DIR_IN, ATOM_INFORMATION_CLASS),
    ARG("AtomInformation", "bcount(AtomInformationLength)", DIR_OUT, PVOID),
    ARG("AtomInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryInformationEnlistment, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("EnlistmentInformationClass", "", DIR_IN, ENLISTMENT_INFORMATION_CLASS),
    ARG("EnlistmentInformation", "bcount(EnlistmentInformationLength)", DIR_OUT, PVOID),
    ARG("EnlistmentInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryInformationFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("FileInformation", "bcount(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("FileInformationClass", "", DIR_IN, FILE_INFORMATION_CLASS),
);
SYSCALL(NtQueryInformationJobObject, NTSTATUS,
    ARG("JobHandle", "opt", DIR_IN, HANDLE),
    ARG("JobObjectInformationClass", "", DIR_IN, JOBOBJECTINFOCLASS),
    ARG("JobObjectInformation", "bcount(JobObjectInformationLength)", DIR_OUT, PVOID),
    ARG("JobObjectInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryInformationPort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("PortInformationClass", "", DIR_IN, PORT_INFORMATION_CLASS),
    ARG("PortInformation", "bcount(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryInformationProcess, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("ProcessInformationClass", "", DIR_IN, PROCESSINFOCLASS),
    ARG("ProcessInformation", "bcount(ProcessInformationLength)", DIR_OUT, PVOID),
    ARG("ProcessInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryInformationResourceManager, NTSTATUS,
    ARG("ResourceManagerHandle", "", DIR_IN, HANDLE),
    ARG("ResourceManagerInformationClass", "", DIR_IN, RESOURCEMANAGER_INFORMATION_CLASS),
    ARG("ResourceManagerInformation", "bcount(ResourceManagerInformationLength)", DIR_OUT, PVOID),
    ARG("ResourceManagerInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryInformationThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("ThreadInformationClass", "", DIR_IN, THREADINFOCLASS),
    ARG("ThreadInformation", "bcount(ThreadInformationLength)", DIR_OUT, PVOID),
    ARG("ThreadInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryInformationToken, NTSTATUS,
    ARG("TokenHandle", "", DIR_IN, HANDLE),
    ARG("TokenInformationClass", "", DIR_IN, TOKEN_INFORMATION_CLASS),
    ARG("TokenInformation", "bcount_part_opt(TokenInformationLength,*ReturnLength)", DIR_OUT, PVOID),
    ARG("TokenInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "", DIR_OUT, PULONG),
);
SYSCALL(NtQueryInformationTransaction, NTSTATUS,
    ARG("TransactionHandle", "", DIR_IN, HANDLE),
    ARG("TransactionInformationClass", "", DIR_IN, TRANSACTION_INFORMATION_CLASS),
    ARG("TransactionInformation", "bcount(TransactionInformationLength)", DIR_OUT, PVOID),
    ARG("TransactionInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryInformationTransactionManager, NTSTATUS,
    ARG("TransactionManagerHandle", "", DIR_IN, HANDLE),
    ARG("TransactionManagerInformationClass", "", DIR_IN, TRANSACTIONMANAGER_INFORMATION_CLASS),
    ARG("TransactionManagerInformation", "bcount(TransactionManagerInformationLength)", DIR_OUT, PVOID),
    ARG("TransactionManagerInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryInformationWorkerFactory, NTSTATUS,
    ARG("WorkerFactoryHandle", "", DIR_IN, HANDLE),
    ARG("WorkerFactoryInformationClass", "", DIR_IN, WORKERFACTORYINFOCLASS),
    ARG("WorkerFactoryInformation", "bcount(WorkerFactoryInformationLength)", DIR_OUT, PVOID),
    ARG("WorkerFactoryInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryInstallUILanguage, NTSTATUS,
    ARG("InstallUILanguageId", "", DIR_OUT, PLANGID),
);
SYSCALL(NtQueryIntervalProfile, NTSTATUS,
    ARG("ProfileSource", "", DIR_IN, KPROFILE_SOURCE),
    ARG("Interval", "", DIR_OUT, PULONG),
);
SYSCALL(NtQueryIoCompletion, NTSTATUS,
    ARG("IoCompletionHandle", "", DIR_IN, HANDLE),
    ARG("IoCompletionInformationClass", "", DIR_IN, IO_COMPLETION_INFORMATION_CLASS),
    ARG("IoCompletionInformation", "bcount(IoCompletionInformationLength)", DIR_OUT, PVOID),
    ARG("IoCompletionInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("KeyInformationClass", "", DIR_IN, KEY_INFORMATION_CLASS),
    ARG("KeyInformation", "bcount_opt(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ResultLength", "", DIR_OUT, PULONG),
);
SYSCALL(NtQueryLicenseValue, NTSTATUS,
    ARG("Name", "", DIR_IN, PUNICODE_STRING),
    ARG("Type", "opt", DIR_OUT, PULONG),
    ARG("Buffer", "bcount(ReturnedLength)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ReturnedLength", "", DIR_OUT, PULONG),
);
SYSCALL(NtQueryMultipleValueKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("ValueEntries", "ecount(EntryCount)", DIR_INOUT, PKEY_VALUE_ENTRY),
    ARG("EntryCount", "", DIR_IN, ULONG),
    ARG("ValueBuffer", "bcount(*BufferLength)", DIR_OUT, PVOID),
    ARG("BufferLength", "", DIR_INOUT, PULONG),
    ARG("RequiredBufferLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryMutant, NTSTATUS,
    ARG("MutantHandle", "", DIR_IN, HANDLE),
    ARG("MutantInformationClass", "", DIR_IN, MUTANT_INFORMATION_CLASS),
    ARG("MutantInformation", "bcount(MutantInformationLength)", DIR_OUT, PVOID),
    ARG("MutantInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryObject, NTSTATUS,
    ARG("Handle", "", DIR_IN, HANDLE),
    ARG("ObjectInformationClass", "", DIR_IN, OBJECT_INFORMATION_CLASS),
    ARG("ObjectInformation", "bcount_opt(ObjectInformationLength)", DIR_OUT, PVOID),
    ARG("ObjectInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryOpenSubKeysEx, NTSTATUS,
    ARG("TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("BufferLength", "", DIR_IN, ULONG),
    ARG("Buffer", "bcount(BufferLength)", DIR_OUT, PVOID),
    ARG("RequiredSize", "", DIR_OUT, PULONG),
);
SYSCALL(NtQueryOpenSubKeys, NTSTATUS,
    ARG("TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("HandleCount", "", DIR_OUT, PULONG),
);
SYSCALL(NtQueryPerformanceCounter, NTSTATUS,
    ARG("PerformanceCounter", "", DIR_OUT, PLARGE_INTEGER),
    ARG("PerformanceFrequency", "opt", DIR_OUT, PLARGE_INTEGER),
);
SYSCALL(NtQueryQuotaInformationFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("Buffer", "bcount(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ReturnSingleEntry", "", DIR_IN, BOOLEAN),
    ARG("SidList", "bcount_opt(SidListLength)", DIR_IN, PVOID),
    ARG("SidListLength", "", DIR_IN, ULONG),
    ARG("StartSid", "opt", DIR_IN, PULONG),
    ARG("RestartScan", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtQuerySection, NTSTATUS,
    ARG("SectionHandle", "", DIR_IN, HANDLE),
    ARG("SectionInformationClass", "", DIR_IN, SECTION_INFORMATION_CLASS),
    ARG("SectionInformation", "bcount(SectionInformationLength)", DIR_OUT, PVOID),
    ARG("SectionInformationLength", "", DIR_IN, SIZE_T),
    ARG("ReturnLength", "opt", DIR_OUT, PSIZE_T),
);
SYSCALL(NtQuerySecurityAttributesToken, NTSTATUS,
    ARG("TokenHandle", "", DIR_IN, HANDLE),
    ARG("Attributes", "ecount_opt(NumberOfAttributes)", DIR_IN, PUNICODE_STRING),
    ARG("NumberOfAttributes", "", DIR_IN, ULONG),
    ARG("Buffer", "bcount(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ReturnLength", "", DIR_OUT, PULONG),
);
SYSCALL(NtQuerySecurityObject, NTSTATUS,
    ARG("Handle", "", DIR_IN, HANDLE),
    ARG("SecurityInformation", "", DIR_IN, SECURITY_INFORMATION),
    ARG("SecurityDescriptor", "bcount_opt(Length)", DIR_OUT, PSECURITY_DESCRIPTOR),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("LengthNeeded", "", DIR_OUT, PULONG),
);
SYSCALL(NtQuerySemaphore, NTSTATUS,
    ARG("SemaphoreHandle", "", DIR_IN, HANDLE),
    ARG("SemaphoreInformationClass", "", DIR_IN, SEMAPHORE_INFORMATION_CLASS),
    ARG("SemaphoreInformation", "bcount(SemaphoreInformationLength)", DIR_OUT, PVOID),
    ARG("SemaphoreInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQuerySymbolicLinkObject, NTSTATUS,
    ARG("LinkHandle", "", DIR_IN, HANDLE),
    ARG("LinkTarget", "", DIR_INOUT, PUNICODE_STRING),
    ARG("ReturnedLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQuerySystemEnvironmentValueEx, NTSTATUS,
    ARG("VariableName", "", DIR_IN, PUNICODE_STRING),
    ARG("VendorGuid", "", DIR_IN, LPGUID),
    ARG("Value", "bcount_opt(*ValueLength)", DIR_OUT, PVOID),
    ARG("ValueLength", "", DIR_INOUT, PULONG),
    ARG("Attributes", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQuerySystemEnvironmentValue, NTSTATUS,
    ARG("VariableName", "", DIR_IN, PUNICODE_STRING),
    ARG("VariableValue", "bcount(ValueLength)", DIR_OUT, PWSTR),
    ARG("ValueLength", "", DIR_IN, USHORT),
    ARG("ReturnLength", "opt", DIR_OUT, PUSHORT),
);
SYSCALL(NtQuerySystemInformationEx, NTSTATUS,
    ARG("SystemInformationClass", "", DIR_IN, SYSTEM_INFORMATION_CLASS),
    ARG("QueryInformation", "bcount(QueryInformationLength)", DIR_IN, PVOID),
    ARG("QueryInformationLength", "", DIR_IN, ULONG),
    ARG("SystemInformation", "bcount_opt(SystemInformationLength)", DIR_OUT, PVOID),
    ARG("SystemInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQuerySystemInformation, NTSTATUS,
    ARG("SystemInformationClass", "", DIR_IN, SYSTEM_INFORMATION_CLASS),
    ARG("SystemInformation", "bcount_opt(SystemInformationLength)", DIR_OUT, PVOID),
    ARG("SystemInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQuerySystemTime, NTSTATUS,
    ARG("SystemTime", "", DIR_OUT, PLARGE_INTEGER),
);
SYSCALL(NtQueryTimer, NTSTATUS,
    ARG("TimerHandle", "", DIR_IN, HANDLE),
    ARG("TimerInformationClass", "", DIR_IN, TIMER_INFORMATION_CLASS),
    ARG("TimerInformation", "bcount(TimerInformationLength)", DIR_OUT, PVOID),
    ARG("TimerInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtQueryTimerResolution, NTSTATUS,
    ARG("MaximumTime", "", DIR_OUT, PULONG),
    ARG("MinimumTime", "", DIR_OUT, PULONG),
    ARG("CurrentTime", "", DIR_OUT, PULONG),
);
SYSCALL(NtQueryValueKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("ValueName", "", DIR_IN, PUNICODE_STRING),
    ARG("KeyValueInformationClass", "", DIR_IN, KEY_VALUE_INFORMATION_CLASS),
    ARG("KeyValueInformation", "bcount_opt(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ResultLength", "", DIR_OUT, PULONG),
);
SYSCALL(NtQueryVirtualMemory, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_IN, PVOID),
    ARG("MemoryInformationClass", "", DIR_IN, MEMORY_INFORMATION_CLASS),
    ARG("MemoryInformation", "bcount(MemoryInformationLength)", DIR_OUT, PVOID),
    ARG("MemoryInformationLength", "", DIR_IN, SIZE_T),
    ARG("ReturnLength", "opt", DIR_OUT, PSIZE_T),
);
SYSCALL(NtQueryVolumeInformationFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("FsInformation", "bcount(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("FsInformationClass", "", DIR_IN, FS_INFORMATION_CLASS),
);
SYSCALL(NtQueueApcThreadEx, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("UserApcReserveHandle", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "", DIR_IN, PPS_APC_ROUTINE),
    ARG("ApcArgument1", "opt", DIR_IN, PVOID),
    ARG("ApcArgument2", "opt", DIR_IN, PVOID),
    ARG("ApcArgument3", "opt", DIR_IN, PVOID),
);
SYSCALL(NtQueueApcThreadEx2, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("ReserveHandle", "", DIR_IN, HANDLE),
    ARG("ApcFlags", "", DIR_IN, ULONG),
    ARG("ApcRoutine", "", DIR_IN, PPS_APC_ROUTINE),
    ARG("ApcArgument1", "", DIR_IN, PVOID),
    ARG("ApcArgument2", "", DIR_IN, PVOID),
    ARG("ApcArgument3", "", DIR_IN, PVOID)
);
SYSCALL(NtQueueApcThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("ApcRoutine", "", DIR_IN, PPS_APC_ROUTINE),
    ARG("ApcArgument1", "opt", DIR_IN, PVOID),
    ARG("ApcArgument2", "opt", DIR_IN, PVOID),
    ARG("ApcArgument3", "opt", DIR_IN, PVOID),
);
SYSCALL(NtRaiseException, NTSTATUS,
    ARG("ExceptionRecord", "", DIR_IN, PEXCEPTION_RECORD),
    ARG("ContextRecord", "", DIR_IN, PCONTEXT),
    ARG("FirstChance", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtRaiseHardError, NTSTATUS,
    ARG("ErrorStatus", "", DIR_IN, NTSTATUS),
    ARG("NumberOfParameters", "", DIR_IN, ULONG),
    ARG("UnicodeStringParameterMask", "", DIR_IN, ULONG),
    ARG("Parameters", "ecount(NumberOfParameters)", DIR_IN, PULONG_PTR),
    ARG("ValidResponseOptions", "", DIR_IN, ULONG),
    ARG("Response", "", DIR_OUT, PULONG),
);
SYSCALL(NtReadFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("Event", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("Buffer", "bcount(Length)", DIR_OUT, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ByteOffset", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("Key", "opt", DIR_IN, PULONG),
);
SYSCALL(NtReadFileScatter, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("Event", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("SegmentArray", "", DIR_IN, PFILE_SEGMENT_ELEMENT),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ByteOffset", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("Key", "opt", DIR_IN, PULONG),
);
SYSCALL(NtReadOnlyEnlistment, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtReadRequestData, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Message", "", DIR_IN, PPORT_MESSAGE),
    ARG("DataEntryIndex", "", DIR_IN, ULONG),
    ARG("Buffer", "bcount(BufferSize)", DIR_OUT, PVOID),
    ARG("BufferSize", "", DIR_IN, SIZE_T),
    ARG("NumberOfBytesRead", "opt", DIR_OUT, PSIZE_T),
);
SYSCALL(NtReadVirtualMemory, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "opt", DIR_IN, PVOID),
    ARG("Buffer", "bcount(BufferSize)", DIR_OUT, PVOID),
    ARG("BufferSize", "", DIR_IN, SIZE_T),
    ARG("NumberOfBytesRead", "opt", DIR_OUT, PSIZE_T),
);
SYSCALL(NtReadVirtualMemoryEx, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "opt", DIR_IN, PVOID),
    ARG("Buffer", "bcount(BufferSize)", DIR_OUT, PVOID),
    ARG("BufferSize", "", DIR_IN, SIZE_T),
    ARG("NumberOfBytesRead", "opt", DIR_OUT, PSIZE_T),
    ARG("Flags", "", DIR_IN, ULONG),
);
SYSCALL(NtRecoverEnlistment, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("EnlistmentKey", "opt", DIR_IN, PVOID),
);
SYSCALL(NtRecoverResourceManager, NTSTATUS,
    ARG("ResourceManagerHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtRecoverTransactionManager, NTSTATUS,
    ARG("TransactionManagerHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtRegisterProtocolAddressInformation, NTSTATUS,
    ARG("ResourceManager", "", DIR_IN, HANDLE),
    ARG("ProtocolId", "", DIR_IN, PCRM_PROTOCOL_ID),
    ARG("ProtocolInformationSize", "", DIR_IN, ULONG),
    ARG("ProtocolInformation", "", DIR_IN, PVOID),
    ARG("CreateOptions", "opt", DIR_IN, ULONG),
);
SYSCALL(NtRegisterThreadTerminatePort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtReleaseKeyedEvent, NTSTATUS,
    ARG("KeyedEventHandle", "", DIR_IN, HANDLE),
    ARG("KeyValue", "", DIR_IN, PVOID),
    ARG("Alertable", "", DIR_IN, BOOLEAN),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtReleaseMutant, NTSTATUS,
    ARG("MutantHandle", "", DIR_IN, HANDLE),
    ARG("PreviousCount", "opt", DIR_OUT, PLONG),
);
SYSCALL(NtReleaseSemaphore, NTSTATUS,
    ARG("SemaphoreHandle", "", DIR_IN, HANDLE),
    ARG("ReleaseCount", "", DIR_IN, LONG),
    ARG("PreviousCount", "opt", DIR_OUT, PLONG),
);
SYSCALL(NtReleaseWorkerFactoryWorker, NTSTATUS,
    ARG("WorkerFactoryHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtRemoveIoCompletionEx, NTSTATUS,
    ARG("IoCompletionHandle", "", DIR_IN, HANDLE),
    ARG("IoCompletionInformation", "ecount(Count)", DIR_OUT, PFILE_IO_COMPLETION_INFORMATION),
    ARG("Count", "", DIR_IN, ULONG),
    ARG("NumEntriesRemoved", "", DIR_OUT, PULONG),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("Alertable", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtRemoveIoCompletion, NTSTATUS,
    ARG("IoCompletionHandle", "", DIR_IN, HANDLE),
    ARG("KeyContext", "", DIR_OUT, PPVOID),
    ARG("ApcContext", "", DIR_OUT, PPVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtRemoveProcessDebug, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("DebugObjectHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtRenameKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("NewName", "", DIR_IN, PUNICODE_STRING),
);
SYSCALL(NtRenameTransactionManager, NTSTATUS,
    ARG("LogFileName", "", DIR_IN, PUNICODE_STRING),
    ARG("ExistingTransactionManagerGuid", "", DIR_IN, LPGUID),
);
SYSCALL(NtReplaceKey, NTSTATUS,
    ARG("NewFile", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("TargetHandle", "", DIR_IN, HANDLE),
    ARG("OldFile", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtReplacePartitionUnit, NTSTATUS,
    ARG("TargetInstancePath", "", DIR_IN, PUNICODE_STRING),
    ARG("SpareInstancePath", "", DIR_IN, PUNICODE_STRING),
    ARG("Flags", "", DIR_IN, ULONG),
);
SYSCALL(NtReplyPort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("ReplyMessage", "", DIR_IN, PPORT_MESSAGE),
);
SYSCALL(NtReplyWaitReceivePortEx, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("PortContext", "opt", DIR_OUT, PPVOID),
    ARG("ReplyMessage", "opt", DIR_IN, PPORT_MESSAGE),
    ARG("ReceiveMessage", "", DIR_OUT, PPORT_MESSAGE),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtReplyWaitReceivePort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("PortContext", "opt", DIR_OUT, PPVOID),
    ARG("ReplyMessage", "opt", DIR_IN, PPORT_MESSAGE),
    ARG("ReceiveMessage", "", DIR_OUT, PPORT_MESSAGE),
);
SYSCALL(NtReplyWaitReplyPort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("ReplyMessage", "", DIR_INOUT, PPORT_MESSAGE),
);
SYSCALL(NtRequestPort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("RequestMessage", "", DIR_IN, PPORT_MESSAGE),
);
SYSCALL(NtRequestWaitReplyPort, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("RequestMessage", "", DIR_IN, PPORT_MESSAGE),
    ARG("ReplyMessage", "", DIR_OUT, PPORT_MESSAGE),
);
SYSCALL(NtResetEvent, NTSTATUS,
    ARG("EventHandle", "", DIR_IN, HANDLE),
    ARG("PreviousState", "opt", DIR_OUT, PLONG),
);
SYSCALL(NtResetWriteWatch, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_IN, PVOID),
    ARG("RegionSize", "", DIR_IN, SIZE_T),
);
SYSCALL(NtRestoreKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_IN, ULONG),
);
SYSCALL(NtResumeProcess, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtResumeThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("PreviousSuspendCount", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtRollbackComplete, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtRollbackEnlistment, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtRollbackTransaction, NTSTATUS,
    ARG("TransactionHandle", "", DIR_IN, HANDLE),
    ARG("Wait", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtRollforwardTransactionManager, NTSTATUS,
    ARG("TransactionManagerHandle", "", DIR_IN, HANDLE),
    ARG("TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtSaveKeyEx, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("Format", "", DIR_IN, ULONG),
);
SYSCALL(NtSaveKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("FileHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtSaveMergedKeys, NTSTATUS,
    ARG("HighPrecedenceKeyHandle", "", DIR_IN, HANDLE),
    ARG("LowPrecedenceKeyHandle", "", DIR_IN, HANDLE),
    ARG("FileHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtSecureConnectPort, NTSTATUS,
    ARG("PortHandle", "", DIR_OUT, PHANDLE),
    ARG("PortName", "", DIR_IN, PUNICODE_STRING),
    ARG("SecurityQos", "", DIR_IN, PSECURITY_QUALITY_OF_SERVICE),
    ARG("ClientView", "opt", DIR_INOUT, PPORT_VIEW),
    ARG("RequiredServerSid", "opt", DIR_IN, PSID),
    ARG("ServerView", "opt", DIR_INOUT, PREMOTE_PORT_VIEW),
    ARG("MaxMessageLength", "opt", DIR_OUT, PULONG),
    ARG("ConnectionInformation", "opt", DIR_INOUT, PVOID),
    ARG("ConnectionInformationLength", "opt", DIR_INOUT, PULONG),
);
SYSCALL(NtSetBootEntryOrder, NTSTATUS,
    ARG("Ids", "ecount(Count)", DIR_IN, PULONG),
    ARG("Count", "", DIR_IN, ULONG),
);
SYSCALL(NtSetBootOptions, NTSTATUS,
    ARG("BootOptions", "", DIR_IN, PBOOT_OPTIONS),
    ARG("FieldsToChange", "", DIR_IN, ULONG),
);
SYSCALL(NtSetContextThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("ThreadContext", "", DIR_IN, PCONTEXT),
);
SYSCALL(NtSetDebugFilterState, NTSTATUS,
    ARG("ComponentId", "", DIR_IN, ULONG),
    ARG("Level", "", DIR_IN, ULONG),
    ARG("State", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtSetDefaultHardErrorPort, NTSTATUS,
    ARG("DefaultHardErrorPort", "", DIR_IN, HANDLE),
);
SYSCALL(NtSetDefaultLocale, NTSTATUS,
    ARG("UserProfile", "", DIR_IN, BOOLEAN),
    ARG("DefaultLocaleId", "", DIR_IN, LCID),
);
SYSCALL(NtSetDefaultUILanguage, NTSTATUS,
    ARG("DefaultUILanguageId", "", DIR_IN, LANGID),
);
SYSCALL(NtSetDriverEntryOrder, NTSTATUS,
    ARG("Ids", "ecount(Count)", DIR_IN, PULONG),
    ARG("Count", "", DIR_IN, ULONG),
);
SYSCALL(NtSetEaFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("Buffer", "bcount(Length)", DIR_IN, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
);
SYSCALL(NtSetEventBoostPriority, NTSTATUS,
    ARG("EventHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtSetEvent, NTSTATUS,
    ARG("EventHandle", "", DIR_IN, HANDLE),
    ARG("PreviousState", "opt", DIR_OUT, PLONG),
);
SYSCALL(NtSetHighEventPair, NTSTATUS,
    ARG("EventPairHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtSetHighWaitLowEventPair, NTSTATUS,
    ARG("EventPairHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtSetInformationDebugObject, NTSTATUS,
    ARG("DebugObjectHandle", "", DIR_IN, HANDLE),
    ARG("DebugObjectInformationClass", "", DIR_IN, DEBUGOBJECTINFOCLASS),
    ARG("DebugInformation", "", DIR_IN, PVOID),
    ARG("DebugInformationLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtSetInformationEnlistment, NTSTATUS,
    ARG("EnlistmentHandle", "opt", DIR_IN, HANDLE),
    ARG("EnlistmentInformationClass", "", DIR_IN, ENLISTMENT_INFORMATION_CLASS),
    ARG("EnlistmentInformation", "bcount(EnlistmentInformationLength)", DIR_IN, PVOID),
    ARG("EnlistmentInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetInformationFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("FileInformation", "bcount(Length)", DIR_IN, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("FileInformationClass", "", DIR_IN, FILE_INFORMATION_CLASS),
);
SYSCALL(NtSetInformationJobObject, NTSTATUS,
    ARG("JobHandle", "", DIR_IN, HANDLE),
    ARG("JobObjectInformationClass", "", DIR_IN, JOBOBJECTINFOCLASS),
    ARG("JobObjectInformation", "bcount(JobObjectInformationLength)", DIR_IN, PVOID),
    ARG("JobObjectInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetInformationKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("KeySetInformationClass", "", DIR_IN, KEY_SET_INFORMATION_CLASS),
    ARG("KeySetInformation", "bcount(KeySetInformationLength)", DIR_IN, PVOID),
    ARG("KeySetInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetInformationObject, NTSTATUS,
    ARG("Handle", "", DIR_IN, HANDLE),
    ARG("ObjectInformationClass", "", DIR_IN, OBJECT_INFORMATION_CLASS),
    ARG("ObjectInformation", "bcount(ObjectInformationLength)", DIR_IN, PVOID),
    ARG("ObjectInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetInformationProcess, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("ProcessInformationClass", "", DIR_IN, PROCESSINFOCLASS),
    ARG("ProcessInformation", "bcount(ProcessInformationLength)", DIR_IN, PVOID),
    ARG("ProcessInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetInformationResourceManager, NTSTATUS,
    ARG("ResourceManagerHandle", "", DIR_IN, HANDLE),
    ARG("ResourceManagerInformationClass", "", DIR_IN, RESOURCEMANAGER_INFORMATION_CLASS),
    ARG("ResourceManagerInformation", "bcount(ResourceManagerInformationLength)", DIR_IN, PVOID),
    ARG("ResourceManagerInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetInformationThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("ThreadInformationClass", "", DIR_IN, THREADINFOCLASS),
    ARG("ThreadInformation", "bcount(ThreadInformationLength)", DIR_IN, PVOID),
    ARG("ThreadInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetInformationToken, NTSTATUS,
    ARG("TokenHandle", "", DIR_IN, HANDLE),
    ARG("TokenInformationClass", "", DIR_IN, TOKEN_INFORMATION_CLASS),
    ARG("TokenInformation", "bcount(TokenInformationLength)", DIR_IN, PVOID),
    ARG("TokenInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetInformationTransaction, NTSTATUS,
    ARG("TransactionHandle", "", DIR_IN, HANDLE),
    ARG("TransactionInformationClass", "", DIR_IN, TRANSACTION_INFORMATION_CLASS),
    ARG("TransactionInformation", "bcount(TransactionInformationLength)", DIR_IN, PVOID),
    ARG("TransactionInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetInformationTransactionManager, NTSTATUS,
    ARG("TmHandle", "opt", DIR_IN, HANDLE),
    ARG("TransactionManagerInformationClass", "", DIR_IN, TRANSACTIONMANAGER_INFORMATION_CLASS),
    ARG("TransactionManagerInformation", "bcount(TransactionManagerInformationLength)", DIR_IN, PVOID),
    ARG("TransactionManagerInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetInformationWorkerFactory, NTSTATUS,
    ARG("WorkerFactoryHandle", "", DIR_IN, HANDLE),
    ARG("WorkerFactoryInformationClass", "", DIR_IN, WORKERFACTORYINFOCLASS),
    ARG("WorkerFactoryInformation", "bcount(WorkerFactoryInformationLength)", DIR_IN, PVOID),
    ARG("WorkerFactoryInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetIntervalProfile, NTSTATUS,
    ARG("Interval", "", DIR_IN, ULONG),
    ARG("Source", "", DIR_IN, KPROFILE_SOURCE),
);
SYSCALL(NtSetIoCompletionEx, NTSTATUS,
    ARG("IoCompletionHandle", "", DIR_IN, HANDLE),
    ARG("IoCompletionReserveHandle", "", DIR_IN, HANDLE),
    ARG("KeyContext", "", DIR_IN, PVOID),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatus", "", DIR_IN, NTSTATUS),
    ARG("IoStatusInformation", "", DIR_IN, ULONG_PTR),
);
SYSCALL(NtSetIoCompletion, NTSTATUS,
    ARG("IoCompletionHandle", "", DIR_IN, HANDLE),
    ARG("KeyContext", "", DIR_IN, PVOID),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatus", "", DIR_IN, NTSTATUS),
    ARG("IoStatusInformation", "", DIR_IN, ULONG_PTR),
);
SYSCALL(NtSetLdtEntries, NTSTATUS,
    ARG("Selector0", "", DIR_IN, ULONG),
    ARG("Entry0Low", "", DIR_IN, ULONG),
    ARG("Entry0Hi", "", DIR_IN, ULONG),
    ARG("Selector1", "", DIR_IN, ULONG),
    ARG("Entry1Low", "", DIR_IN, ULONG),
    ARG("Entry1Hi", "", DIR_IN, ULONG),
);
SYSCALL(NtSetLowEventPair, NTSTATUS,
    ARG("EventPairHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtSetLowWaitHighEventPair, NTSTATUS,
    ARG("EventPairHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtSetQuotaInformationFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("Buffer", "bcount(Length)", DIR_IN, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
);
SYSCALL(NtSetSecurityObject, NTSTATUS,
    ARG("Handle", "", DIR_IN, HANDLE),
    ARG("SecurityInformation", "", DIR_IN, SECURITY_INFORMATION),
    ARG("SecurityDescriptor", "", DIR_IN, PSECURITY_DESCRIPTOR),
);
SYSCALL(NtSetSystemEnvironmentValueEx, NTSTATUS,
    ARG("VariableName", "", DIR_IN, PUNICODE_STRING),
    ARG("VendorGuid", "", DIR_IN, LPGUID),
    ARG("Value", "bcount_opt(ValueLength)", DIR_IN, PVOID),
    ARG("ValueLength", "", DIR_IN, ULONG),
    ARG("Attributes", "", DIR_IN, ULONG),
);
SYSCALL(NtSetSystemEnvironmentValue, NTSTATUS,
    ARG("VariableName", "", DIR_IN, PUNICODE_STRING),
    ARG("VariableValue", "", DIR_IN, PUNICODE_STRING),
);
SYSCALL(NtSetSystemInformation, NTSTATUS,
    ARG("SystemInformationClass", "", DIR_IN, SYSTEM_INFORMATION_CLASS),
    ARG("SystemInformation", "bcount_opt(SystemInformationLength)", DIR_IN, PVOID),
    ARG("SystemInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetSystemPowerState, NTSTATUS,
    ARG("SystemAction", "", DIR_IN, POWER_ACTION),
    ARG("MinSystemState", "", DIR_IN, SYSTEM_POWER_STATE),
    ARG("Flags", "", DIR_IN, ULONG),
);
SYSCALL(NtSetSystemTime, NTSTATUS,
    ARG("SystemTime", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("PreviousTime", "opt", DIR_OUT, PLARGE_INTEGER),
);
SYSCALL(NtSetThreadExecutionState, NTSTATUS,
    ARG("esFlags", "", DIR_IN, EXECUTION_STATE),
    ARG("PreviousFlags", "", DIR_OUT, PEXECUTION_STATE),
);
SYSCALL(NtSetTimerEx, NTSTATUS,
    ARG("TimerHandle", "", DIR_IN, HANDLE),
    ARG("TimerSetInformationClass", "", DIR_IN, TIMER_SET_INFORMATION_CLASS),
    ARG("TimerSetInformation", "bcount(TimerSetInformationLength)", DIR_INOUT, PVOID),
    ARG("TimerSetInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetTimer, NTSTATUS,
    ARG("TimerHandle", "", DIR_IN, HANDLE),
    ARG("DueTime", "", DIR_IN, PLARGE_INTEGER),
    ARG("TimerApcRoutine", "opt", DIR_IN, PTIMER_APC_ROUTINE),
    ARG("TimerContext", "opt", DIR_IN, PVOID),
    ARG("WakeTimer", "", DIR_IN, BOOLEAN),
    ARG("Period", "opt", DIR_IN, LONG),
    ARG("PreviousState", "opt", DIR_OUT, PBOOLEAN),
);
SYSCALL(NtSetTimerResolution, NTSTATUS,
    ARG("DesiredTime", "", DIR_IN, ULONG),
    ARG("SetResolution", "", DIR_IN, BOOLEAN),
    ARG("ActualTime", "", DIR_OUT, PULONG),
);
SYSCALL(NtSetUuidSeed, NTSTATUS,
    ARG("Seed", "", DIR_IN, PCHAR),
);
SYSCALL(NtSetValueKey, NTSTATUS,
    ARG("KeyHandle", "", DIR_IN, HANDLE),
    ARG("ValueName", "", DIR_IN, PUNICODE_STRING),
    ARG("TitleIndex", "opt", DIR_IN, ULONG),
    ARG("Type", "", DIR_IN, ULONG),
    ARG("Data", "bcount_opt(DataSize)", DIR_IN, PVOID),
    ARG("DataSize", "", DIR_IN, ULONG),
);
SYSCALL(NtSetVolumeInformationFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("FsInformation", "bcount(Length)", DIR_IN, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("FsInformationClass", "", DIR_IN, FS_INFORMATION_CLASS),
);
SYSCALL(NtShutdownSystem, NTSTATUS,
    ARG("Action", "", DIR_IN, SHUTDOWN_ACTION),
);
SYSCALL(NtShutdownWorkerFactory, NTSTATUS,
    ARG("WorkerFactoryHandle", "", DIR_IN, HANDLE),
    ARG("PendingWorkerCount", "", DIR_INOUT, PLONG),
);
SYSCALL(NtSignalAndWaitForSingleObject, NTSTATUS,
    ARG("SignalHandle", "", DIR_IN, HANDLE),
    ARG("WaitHandle", "", DIR_IN, HANDLE),
    ARG("Alertable", "", DIR_IN, BOOLEAN),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtSinglePhaseReject, NTSTATUS,
    ARG("EnlistmentHandle", "", DIR_IN, HANDLE),
    ARG("TmVirtualClock", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtStartProfile, NTSTATUS,
    ARG("ProfileHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtStopProfile, NTSTATUS,
    ARG("ProfileHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtSuspendProcess, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtSuspendThread, NTSTATUS,
    ARG("ThreadHandle", "", DIR_IN, HANDLE),
    ARG("PreviousSuspendCount", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtSystemDebugControl, NTSTATUS,
    ARG("Command", "", DIR_IN, SYSDBG_COMMAND),
    ARG("InputBuffer", "bcount_opt(InputBufferLength)", DIR_INOUT, PVOID),
    ARG("InputBufferLength", "", DIR_IN, ULONG),
    ARG("OutputBuffer", "bcount_opt(OutputBufferLength)", DIR_OUT, PVOID),
    ARG("OutputBufferLength", "", DIR_IN, ULONG),
    ARG("ReturnLength", "opt", DIR_OUT, PULONG),
);
SYSCALL(NtTerminateJobObject, NTSTATUS,
    ARG("JobHandle", "", DIR_IN, HANDLE),
    ARG("ExitStatus", "", DIR_IN, NTSTATUS),
);
SYSCALL(NtTerminateProcess, NTSTATUS,
    ARG("ProcessHandle", "opt", DIR_IN, HANDLE),
    ARG("ExitStatus", "", DIR_IN, NTSTATUS),
);
SYSCALL(NtTerminateThread, NTSTATUS,
    ARG("ThreadHandle", "opt", DIR_IN, HANDLE),
    ARG("ExitStatus", "", DIR_IN, NTSTATUS),
);
SYSCALL(NtTraceControl, NTSTATUS,
    ARG("FunctionCode", "", DIR_IN, ULONG),
    ARG("InBuffer", "bcount_opt(InBufferLen)", DIR_IN, PVOID),
    ARG("InBufferLen", "", DIR_IN, ULONG),
    ARG("OutBuffer", "bcount_opt(OutBufferLen)", DIR_OUT, PVOID),
    ARG("OutBufferLen", "", DIR_IN, ULONG),
    ARG("ReturnLength", "", DIR_OUT, PULONG),
);
SYSCALL(NtTraceEvent, NTSTATUS,
    ARG("TraceHandle", "", DIR_IN, HANDLE),
    ARG("Flags", "", DIR_IN, ULONG),
    ARG("FieldSize", "", DIR_IN, ULONG),
    ARG("Fields", "", DIR_IN, PVOID),
);
SYSCALL(NtTranslateFilePath, NTSTATUS,
    ARG("InputFilePath", "", DIR_IN, PFILE_PATH),
    ARG("OutputType", "", DIR_IN, ULONG),
    ARG("OutputFilePath", "bcount_opt(*OutputFilePathLength)", DIR_OUT, PFILE_PATH),
    ARG("OutputFilePathLength", "opt", DIR_INOUT, PULONG),
);
SYSCALL(NtUnloadDriver, NTSTATUS,
    ARG("DriverServiceName", "", DIR_IN, PUNICODE_STRING),
);
SYSCALL(NtUnloadKey2, NTSTATUS,
    ARG("TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("Flags", "", DIR_IN, ULONG),
);
SYSCALL(NtUnloadKeyEx, NTSTATUS,
    ARG("TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("Event", "opt", DIR_IN, HANDLE),
);
SYSCALL(NtUnloadKey, NTSTATUS,
    ARG("TargetKey", "", DIR_IN, POBJECT_ATTRIBUTES),
);
SYSCALL(NtUnlockFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("ByteOffset", "", DIR_IN, PLARGE_INTEGER),
    ARG("Length", "", DIR_IN, PLARGE_INTEGER),
    ARG("Key", "", DIR_IN, ULONG),
);
SYSCALL(NtUnlockVirtualMemory, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_INOUT, PPVOID),
    ARG("RegionSize", "", DIR_INOUT, PSIZE_T),
    ARG("MapType", "", DIR_IN, ULONG),
);
SYSCALL(NtUnmapViewOfSection, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_IN, PVOID),
);
SYSCALL(NtUnmapViewOfSectionEx, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "", DIR_IN, PVOID),
    ARG("Flags", "", DIR_IN, ULONG),
);
SYSCALL(NtUserBlockInput, NTSTATUS,
    ARG("BlockIt", "", DIR_IN, BOOLEAN)
);
SYSCALL(NtUserCallNextHookEx, NTSTATUS,
    ARG("Code", "", DIR_IN, INT),
    ARG("wParam", "", DIR_IN, WPARAM),
    ARG("lParam", "", DIR_IN, LPARAM),
    ARG("Ansi", "", DIR_IN, BOOLEAN));
SYSCALL(NtUserCallTwoParam, NTSTATUS,
    ARG("Param1", "", DIR_IN, DWORD),
    ARG("Param2", "", DIR_IN, DWORD),
    ARG("Routine", "", DIR_IN, DWORD));
SYSCALL(NtUserCreateDesktop, NTSTATUS,
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("lpszDevice", "", DIR_IN, PUNICODE_STRING),
    ARG("devmode", "", DIR_IN, PVOID),
    ARG("dwflags", "", DIR_IN, DWORD),
    ARG("access", "", DIR_IN, ACCESS_MASK),
    ARG("heapsize", "", DIR_IN, DWORD));
SYSCALL(NtUserCreateDesktopEx, NTSTATUS,
    ARG("ObjectAttributes", "", DIR_IN, POBJECT_ATTRIBUTES),
    ARG("lpszDevice", "", DIR_IN, PUNICODE_STRING),
    ARG("devmode", "", DIR_IN, PVOID),
    ARG("dwflags", "", DIR_IN, DWORD),
    ARG("access", "", DIR_IN, ACCESS_MASK),
    ARG("heapsize", "", DIR_IN, DWORD));
SYSCALL(NtUserFindWindowEx, HWND,
    ARG("hwndParent", "", DIR_MISSING, HWND),
    ARG("hwndChildAfter", "", DIR_MISSING, HWND),
    ARG("ucClassName", "", DIR_IN, PVOID),
    ARG("ucWindowName", "", DIR_IN, PVOID),
    ARG("dwUnknown", "", DIR_MISSING, DWORD));
SYSCALL(NtUserGetAsyncKeyState, SHORT,
    ARG("Key", "", DIR_IN, INT)
);
SYSCALL(NtUserGetDC, HANDLE,
    ARG("hWnd", "", DIR_IN, HWND));
SYSCALL(NtUserGetKeyState, SHORT,
    ARG("VirtKey", "", DIR_IN, INT)
);
SYSCALL(NtUserLoadKeyboardLayoutEx, NTSTATUS,
    ARG("Handle", "", DIR_IN, HANDLE),
    ARG("offTable", "", DIR_IN, DWORD),
    ARG("puszKeyboardName", "", DIR_IN, PUNICODE_STRING),
    ARG("hKL", "", DIR_IN, HANDLE),
    ARG("puszKLID", "", DIR_IN, PUNICODE_STRING),
    ARG("dwKLID", "", DIR_IN, DWORD),
    ARG("Flags", "", DIR_IN, UINT)
);
SYSCALL(NtUserMessageCall, NTSTATUS,
    ARG("hWnd", "", DIR_IN, HWND),
    ARG("Msg", "", DIR_IN, UINT),
    ARG("wParam", "", DIR_IN, WPARAM),
    ARG("lParam", "", DIR_IN, LPARAM),
    ARG("ResultInfo", "", DIR_IN, ULONG_PTR),
    ARG("dwType", "", DIR_IN, DWORD),
    ARG("Ansi", "", DIR_IN, BOOLEAN));
SYSCALL(NtUserSetWindowLong, NTSTATUS,
    ARG("hWnd", "", DIR_IN, HWND),
    ARG("nIndex", "", DIR_IN, INT),
    ARG("dwNewLong", "", DIR_IN, LONG),
    ARG("Ansi", "", DIR_IN, BOOLEAN));
SYSCALL(NtUserSetWindowsHookEx, HHOOK,
    ARG("Mod", "", DIR_IN, HINSTANCE),
    ARG("UnsafeModuleName", "", DIR_IN, PUNICODE_STRING),
    ARG("ThreadId", "", DIR_IN, DWORD),
    ARG("HookId", "", DIR_IN, INT),
    ARG("HookProc", "", DIR_IN, HOOKPROC),
    ARG("Ansi", "", DIR_IN, BOOLEAN),
);
SYSCALL(NtUserShowWindow, NTSTATUS,
    ARG("hWnd", "", DIR_IN, HWND),
    ARG("nCmdShow", "", DIR_IN, LONG)
);
SYSCALL(NtVdmControl, NTSTATUS,
    ARG("Service", "", DIR_IN, VDMSERVICECLASS),
    ARG("ServiceData", "", DIR_INOUT, PVOID),
);
SYSCALL(NtWaitForDebugEvent, NTSTATUS,
    ARG("DebugObjectHandle", "", DIR_IN, HANDLE),
    ARG("Alertable", "", DIR_IN, BOOLEAN),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("WaitStateChange", "", DIR_OUT, PDBGUI_WAIT_STATE_CHANGE),
);
SYSCALL(NtWaitForKeyedEvent, NTSTATUS,
    ARG("KeyedEventHandle", "", DIR_IN, HANDLE),
    ARG("KeyValue", "", DIR_IN, PVOID),
    ARG("Alertable", "", DIR_IN, BOOLEAN),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtWaitForMultipleObjects32, NTSTATUS,
    ARG("Count", "", DIR_IN, ULONG),
    ARG("Handles[]", "ecount(Count)", DIR_IN, LONG),
    ARG("WaitType", "", DIR_IN, WAIT_TYPE),
    ARG("Alertable", "", DIR_IN, BOOLEAN),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtWaitForMultipleObjects, NTSTATUS,
    ARG("Count", "", DIR_IN, ULONG),
    ARG("Handles[]", "ecount(Count)", DIR_IN, HANDLE),
    ARG("WaitType", "", DIR_IN, WAIT_TYPE),
    ARG("Alertable", "", DIR_IN, BOOLEAN),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtWaitForSingleObject, NTSTATUS,
    ARG("Handle", "", DIR_IN, HANDLE),
    ARG("Alertable", "", DIR_IN, BOOLEAN),
    ARG("Timeout", "opt", DIR_IN, PLARGE_INTEGER),
);
SYSCALL(NtWaitForWorkViaWorkerFactory, NTSTATUS,
    ARG("WorkerFactoryHandle", "", DIR_IN, HANDLE),
    ARG("MiniPacket", "", DIR_OUT, PFILE_IO_COMPLETION_INFORMATION),
);
SYSCALL(NtWaitHighEventPair, NTSTATUS,
    ARG("EventPairHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtWaitLowEventPair, NTSTATUS,
    ARG("EventPairHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtWorkerFactoryWorkerReady, NTSTATUS,
    ARG("WorkerFactoryHandle", "", DIR_IN, HANDLE),
);
SYSCALL(NtWriteFileGather, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("Event", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("SegmentArray", "", DIR_IN, PFILE_SEGMENT_ELEMENT),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ByteOffset", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("Key", "opt", DIR_IN, PULONG),
);
SYSCALL(NtWriteFile, NTSTATUS,
    ARG("FileHandle", "", DIR_IN, HANDLE),
    ARG("Event", "opt", DIR_IN, HANDLE),
    ARG("ApcRoutine", "opt", DIR_IN, PIO_APC_ROUTINE),
    ARG("ApcContext", "opt", DIR_IN, PVOID),
    ARG("IoStatusBlock", "", DIR_OUT, PIO_STATUS_BLOCK),
    ARG("Buffer", "bcount(Length)", DIR_IN, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ByteOffset", "opt", DIR_IN, PLARGE_INTEGER),
    ARG("Key", "opt", DIR_IN, PULONG),
);
SYSCALL(NtWriteRequestData, NTSTATUS,
    ARG("PortHandle", "", DIR_IN, HANDLE),
    ARG("Message", "", DIR_IN, PPORT_MESSAGE),
    ARG("DataEntryIndex", "", DIR_IN, ULONG),
    ARG("Buffer", "bcount(BufferSize)", DIR_IN, PVOID),
    ARG("BufferSize", "", DIR_IN, SIZE_T),
    ARG("NumberOfBytesWritten", "opt", DIR_OUT, PSIZE_T),
);
SYSCALL(NtWriteVirtualMemory, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("BaseAddress", "opt", DIR_IN, PVOID),
    ARG("Buffer", "bcount(BufferSize)", DIR_IN, PVOID),
    ARG("BufferSize", "", DIR_IN, SIZE_T),
    ARG("NumberOfBytesWritten", "opt", DIR_OUT, PSIZE_T),
);
SYSCALL(NtSetInformationVirtualMemory, NTSTATUS,
    ARG("ProcessHandle", "", DIR_IN, HANDLE),
    ARG("VmInformationClass", "", DIR_IN, VIRTUAL_MEMORY_INFORMATION_CLASS),
    ARG("NumberOfEntries", "", DIR_IN, ULONG_PTR),
    ARG("VirtualAddresses", "ecount(NumberOfEntries)", DIR_IN, PMEMORY_RANGE_ENTRY),
    ARG("VmInformation", "bcount(VmInformationLength)", DIR_IN, PVOID),
    ARG("VmInformationLength", "opt", DIR_IN, ULONG),
);
SYSCALL(NtManagePartition, NTSTATUS,
    ARG("TargetHandle", "", DIR_IN, HANDLE),
    ARG("SourceHandle", "opt", DIR_IN, HANDLE),
    ARG("PartitionInformationClass", "", DIR_IN, PARTITION_INFORMATION_CLASS),
    ARG("PartitionInformation", "", DIR_INOUT, PVOID),
    ARG("PartitionInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtSetInformationSymbolicLink, NTSTATUS,
    ARG("LinkHandle", "", DIR_IN, HANDLE),
    ARG("SymbolicLinkInformationClass", "", DIR_IN, SYMBOLIC_LINK_INFO_CLASS),
    ARG("SymbolicLinkInformation", "bcount(SymbolicLinkInformationLength)", DIR_IN, PVOID),
    ARG("SymbolicLinkInformationLength", "", DIR_IN, ULONG),
);
SYSCALL(NtManageHotPatch, NTSTATUS,
    ARG("HotPatchInformation", "", DIR_IN, HOT_PATCH_INFORMATION_CLASS),
    ARG("HotPatchData", "bcount(Length)", DIR_IN, PVOID),
    ARG("Length", "", DIR_IN, ULONG),
    ARG("ReturnLength", "", DIR_OUT, PULONG),
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
SYSCALL(NtGetEnvironmentVariableEx, NTSTATUS);
SYSCALL(NtIsSystemResumeAutomatic, BOOLEAN);
SYSCALL(NtIsUILanguageComitted, NTSTATUS);
SYSCALL(NtQueryEnvironmentVariableInfoEx, NTSTATUS);
SYSCALL(NtYieldExecution, NTSTATUS);
SYSCALL(NtAcquireProcessActivityReference, NTSTATUS);
SYSCALL(NtAddAtomEx, NTSTATUS);
SYSCALL(NtAlertThreadByThreadId, NTSTATUS);
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
SYSCALL(NtSetTimer2, NTSTATUS);
SYSCALL(NtSetWnfProcessNotificationEvent, NTSTATUS);
SYSCALL(NtSubscribeWnfStateChange, NTSTATUS);
SYSCALL(NtTerminateEnclave, NTSTATUS);
SYSCALL(NtUnsubscribeWnfStateChange, NTSTATUS);
SYSCALL(NtUpdateWnfStateData, NTSTATUS);
SYSCALL(NtWaitForAlertByThreadId, NTSTATUS);
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
    &NtAllocateVirtualMemoryEx,
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
    &NtCopyFileChunk,
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
    &NtCreateSectionEx,
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
    &NtMapViewOfSectionEx,
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
    &NtQueueApcThreadEx2,
    &NtQueueApcThread,
    &NtRaiseException,
    &NtRaiseHardError,
    &NtReadFile,
    &NtReadFileScatter,
    &NtReadOnlyEnlistment,
    &NtReadRequestData,
    &NtReadVirtualMemory,
    &NtReadVirtualMemoryEx,
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
    &NtUnmapViewOfSectionEx,
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
    &NtUnsubscribeWnfStateChange,
    &NtUpdateWnfStateData,
    &NtWaitForAlertByThreadId,
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
