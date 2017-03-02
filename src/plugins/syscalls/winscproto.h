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
 */

typedef struct
{
  const char* name;
  const char* dir;
  const char* dir_opt;
  const char* type;
} ARG;

struct syscall
{
  const char* name;
  int num_args;
  ARG args[20];
};

struct syscall_wrapper {
 syscalls *sc;
 unsigned int syscall_index;
};

typedef struct syscall_wrapper syscall_wrapper_t;

#define NUM_SYSCALLS 401

static const struct syscall syscall_struct[] = {
  { .name = "NtAcceptConnectPort", .num_args = 6, .args = 
    {
      {.name = "PortHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "PortContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ConnectionRequest", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"},
      {.name = "AcceptConnection", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "ServerView", .dir = "inout", .dir_opt = "opt", .type = "PPORT_VIEW"},
      {.name = "ClientView", .dir = "out", .dir_opt = "opt", .type = "PREMOTE_PORT_VIEW"}
    }
  },
  { .name = "NtAccessCheckAndAuditAlarm", .num_args = 11, .args = 
    {
      {.name = "SubsystemName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "HandleId", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ObjectTypeName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "ObjectName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "SecurityDescriptor", .dir = "in", .dir_opt = "", .type = "PSECURITY_DESCRIPTOR"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "GenericMapping", .dir = "in", .dir_opt = "", .type = "PGENERIC_MAPPING"},
      {.name = "ObjectCreation", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "GrantedAccess", .dir = "out", .dir_opt = "", .type = "PACCESS_MASK"},
      {.name = "AccessStatus", .dir = "out", .dir_opt = "", .type = "PNTSTATUS"},
      {.name = "GenerateOnClose", .dir = "out", .dir_opt = "", .type = "PBOOLEAN"}
    }
  },
  { .name = "NtAccessCheckByTypeAndAuditAlarm", .num_args = 16, .args = 
    {
      {.name = "SubsystemName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "HandleId", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ObjectTypeName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "ObjectName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "SecurityDescriptor", .dir = "in", .dir_opt = "", .type = "PSECURITY_DESCRIPTOR"},
      {.name = "PrincipalSelfSid", .dir = "in", .dir_opt = "opt", .type = "PSID"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "AuditType", .dir = "in", .dir_opt = "", .type = "AUDIT_EVENT_TYPE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ObjectTypeList", .dir = "in", .dir_opt = "ecount_opt(ObjectTypeListLength)", .type = "POBJECT_TYPE_LIST"},
      {.name = "ObjectTypeListLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "GenericMapping", .dir = "in", .dir_opt = "", .type = "PGENERIC_MAPPING"},
      {.name = "ObjectCreation", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "GrantedAccess", .dir = "out", .dir_opt = "", .type = "PACCESS_MASK"},
      {.name = "AccessStatus", .dir = "out", .dir_opt = "", .type = "PNTSTATUS"},
      {.name = "GenerateOnClose", .dir = "out", .dir_opt = "", .type = "PBOOLEAN"}
    }
  },
  { .name = "NtAccessCheckByType", .num_args = 11, .args = 
    {
      {.name = "SecurityDescriptor", .dir = "in", .dir_opt = "", .type = "PSECURITY_DESCRIPTOR"},
      {.name = "PrincipalSelfSid", .dir = "in", .dir_opt = "opt", .type = "PSID"},
      {.name = "ClientToken", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectTypeList", .dir = "in", .dir_opt = "ecount(ObjectTypeListLength)", .type = "POBJECT_TYPE_LIST"},
      {.name = "ObjectTypeListLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "GenericMapping", .dir = "in", .dir_opt = "", .type = "PGENERIC_MAPPING"},
      {.name = "PrivilegeSet", .dir = "out", .dir_opt = "bcount(*PrivilegeSetLength)", .type = "PPRIVILEGE_SET"},
      {.name = "PrivilegeSetLength", .dir = "inout", .dir_opt = "", .type = "PULONG"},
      {.name = "GrantedAccess", .dir = "out", .dir_opt = "", .type = "PACCESS_MASK"},
      {.name = "AccessStatus", .dir = "out", .dir_opt = "", .type = "PNTSTATUS"}
    }
  },
  { .name = "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", .num_args = 17, .args = 
    {
      {.name = "SubsystemName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "HandleId", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ClientToken", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ObjectTypeName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "ObjectName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "SecurityDescriptor", .dir = "in", .dir_opt = "", .type = "PSECURITY_DESCRIPTOR"},
      {.name = "PrincipalSelfSid", .dir = "in", .dir_opt = "opt", .type = "PSID"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "AuditType", .dir = "in", .dir_opt = "", .type = "AUDIT_EVENT_TYPE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ObjectTypeList", .dir = "in", .dir_opt = "ecount_opt(ObjectTypeListLength)", .type = "POBJECT_TYPE_LIST"},
      {.name = "ObjectTypeListLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "GenericMapping", .dir = "in", .dir_opt = "", .type = "PGENERIC_MAPPING"},
      {.name = "ObjectCreation", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "GrantedAccess", .dir = "out", .dir_opt = "ecount(ObjectTypeListLength)", .type = "PACCESS_MASK"},
      {.name = "AccessStatus", .dir = "out", .dir_opt = "ecount(ObjectTypeListLength)", .type = "PNTSTATUS"},
      {.name = "GenerateOnClose", .dir = "out", .dir_opt = "", .type = "PBOOLEAN"}
    }
  },
  { .name = "NtAccessCheckByTypeResultListAndAuditAlarm", .num_args = 16, .args = 
    {
      {.name = "SubsystemName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "HandleId", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ObjectTypeName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "ObjectName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "SecurityDescriptor", .dir = "in", .dir_opt = "", .type = "PSECURITY_DESCRIPTOR"},
      {.name = "PrincipalSelfSid", .dir = "in", .dir_opt = "opt", .type = "PSID"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "AuditType", .dir = "in", .dir_opt = "", .type = "AUDIT_EVENT_TYPE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ObjectTypeList", .dir = "in", .dir_opt = "ecount_opt(ObjectTypeListLength)", .type = "POBJECT_TYPE_LIST"},
      {.name = "ObjectTypeListLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "GenericMapping", .dir = "in", .dir_opt = "", .type = "PGENERIC_MAPPING"},
      {.name = "ObjectCreation", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "GrantedAccess", .dir = "out", .dir_opt = "ecount(ObjectTypeListLength)", .type = "PACCESS_MASK"},
      {.name = "AccessStatus", .dir = "out", .dir_opt = "ecount(ObjectTypeListLength)", .type = "PNTSTATUS"},
      {.name = "GenerateOnClose", .dir = "out", .dir_opt = "", .type = "PBOOLEAN"}
    }
  },
  { .name = "NtAccessCheckByTypeResultList", .num_args = 11, .args = 
    {
      {.name = "SecurityDescriptor", .dir = "in", .dir_opt = "", .type = "PSECURITY_DESCRIPTOR"},
      {.name = "PrincipalSelfSid", .dir = "in", .dir_opt = "opt", .type = "PSID"},
      {.name = "ClientToken", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectTypeList", .dir = "in", .dir_opt = "ecount(ObjectTypeListLength)", .type = "POBJECT_TYPE_LIST"},
      {.name = "ObjectTypeListLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "GenericMapping", .dir = "in", .dir_opt = "", .type = "PGENERIC_MAPPING"},
      {.name = "PrivilegeSet", .dir = "out", .dir_opt = "bcount(*PrivilegeSetLength)", .type = "PPRIVILEGE_SET"},
      {.name = "PrivilegeSetLength", .dir = "inout", .dir_opt = "", .type = "PULONG"},
      {.name = "GrantedAccess", .dir = "out", .dir_opt = "ecount(ObjectTypeListLength)", .type = "PACCESS_MASK"},
      {.name = "AccessStatus", .dir = "out", .dir_opt = "ecount(ObjectTypeListLength)", .type = "PNTSTATUS"}
    }
  },
  { .name = "NtAccessCheck", .num_args = 8, .args = 
    {
      {.name = "SecurityDescriptor", .dir = "in", .dir_opt = "", .type = "PSECURITY_DESCRIPTOR"},
      {.name = "ClientToken", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "GenericMapping", .dir = "in", .dir_opt = "", .type = "PGENERIC_MAPPING"},
      {.name = "PrivilegeSet", .dir = "out", .dir_opt = "bcount(*PrivilegeSetLength)", .type = "PPRIVILEGE_SET"},
      {.name = "PrivilegeSetLength", .dir = "inout", .dir_opt = "", .type = "PULONG"},
      {.name = "GrantedAccess", .dir = "out", .dir_opt = "", .type = "PACCESS_MASK"},
      {.name = "AccessStatus", .dir = "out", .dir_opt = "", .type = "PNTSTATUS"}
    }
  },
  { .name = "NtAddAtom", .num_args = 3, .args = 
    {
      {.name = "AtomName", .dir = "in", .dir_opt = "bcount_opt(Length)", .type = "PWSTR"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Atom", .dir = "out", .dir_opt = "opt", .type = "PRTL_ATOM"}
    }
  },
  { .name = "NtAddBootEntry", .num_args = 2, .args = 
    {
      {.name = "BootEntry", .dir = "in", .dir_opt = "", .type = "PBOOT_ENTRY"},
      {.name = "Id", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtAddDriverEntry", .num_args = 2, .args = 
    {
      {.name = "DriverEntry", .dir = "in", .dir_opt = "", .type = "PEFI_DRIVER_ENTRY"},
      {.name = "Id", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtAdjustGroupsToken", .num_args = 6, .args = 
    {
      {.name = "TokenHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ResetToDefault", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "NewState", .dir = "in", .dir_opt = "", .type = "PTOKEN_GROUPS"},
      {.name = "BufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "PreviousState", .dir = "out", .dir_opt = "bcount_part_opt(BufferLength,*ReturnLength)", .type = "PTOKEN_GROUPS"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtAdjustPrivilegesToken", .num_args = 6, .args = 
    {
      {.name = "TokenHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DisableAllPrivileges", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "NewState", .dir = "in", .dir_opt = "opt", .type = "PTOKEN_PRIVILEGES"},
      {.name = "BufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "PreviousState", .dir = "out", .dir_opt = "bcount_part_opt(BufferLength,*ReturnLength)", .type = "PTOKEN_PRIVILEGES"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtAlertResumeThread", .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PreviousSuspendCount", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtAlertThread", .num_args = 0  },
  { .name = "NtAllocateLocallyUniqueId", .num_args = 0  },
  { .name = "NtAllocateReserveObject", .num_args = 3, .args = 
    {
      {.name = "MemoryReserveHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "Type", .dir = "in", .dir_opt = "", .type = "MEMORY_RESERVE_TYPE"}
    }
  },
  { .name = "NtAllocateUserPhysicalPages", .num_args = 3, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "NumberOfPages", .dir = "inout", .dir_opt = "", .type = "PULONG_PTR"},
      {.name = "UserPfnArra;", .dir = "out", .dir_opt = "ecount(*NumberOfPages)", .type = "PULONG_PTR"}
    }
  },
  { .name = "NtAllocateUuids", .num_args = 4, .args = 
    {
      {.name = "Time", .dir = "out", .dir_opt = "", .type = "PULARGE_INTEGER"},
      {.name = "Range", .dir = "out", .dir_opt = "", .type = "PULONG"},
      {.name = "Sequence", .dir = "out", .dir_opt = "", .type = "PULONG"},
      {.name = "Seed", .dir = "out", .dir_opt = "", .type = "PCHAR"}
    }
  },
  { .name = "NtAllocateVirtualMemory", .num_args = 6, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*BaseAddress", .dir = "inout", .dir_opt = "", .type = "PVOID"},
      {.name = "ZeroBits", .dir = "in", .dir_opt = "", .type = "ULONG_PTR"},
      {.name = "RegionSize", .dir = "inout", .dir_opt = "", .type = "PSIZE_T"},
      {.name = "AllocationType", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Protect", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtAlpcAcceptConnectPort", .num_args = 9, .args = 
    {
      {.name = "PortHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "ConnectionPortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "PortAttributes", .dir = "in", .dir_opt = "", .type = "PALPC_PORT_ATTRIBUTES"},
      {.name = "PortContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ConnectionRequest", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"},
      {.name = "ConnectionMessageAttributes", .dir = "inout", .dir_opt = "opt", .type = "PALPC_MESSAGE_ATTRIBUTES"},
      {.name = "AcceptConnection", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtAlpcCancelMessage", .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "MessageContext", .dir = "in", .dir_opt = "", .type = "PALPC_CONTEXT_ATTR"}
    }
  },
  { .name = "NtAlpcConnectPort", .num_args = 11, .args = 
    {
      {.name = "PortHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "PortName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "PortAttributes", .dir = "in", .dir_opt = "opt", .type = "PALPC_PORT_ATTRIBUTES"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "RequiredServerSid", .dir = "in", .dir_opt = "opt", .type = "PSID"},
      {.name = "ConnectionMessage", .dir = "inout", .dir_opt = "", .type = "PPORT_MESSAGE"},
      {.name = "BufferLength", .dir = "inout", .dir_opt = "opt", .type = "PULONG"},
      {.name = "OutMessageAttributes", .dir = "inout", .dir_opt = "opt", .type = "PALPC_MESSAGE_ATTRIBUTES"},
      {.name = "InMessageAttributes", .dir = "inout", .dir_opt = "opt", .type = "PALPC_MESSAGE_ATTRIBUTES"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtAlpcCreatePort", .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "PortAttributes", .dir = "in", .dir_opt = "opt", .type = "PALPC_PORT_ATTRIBUTES"}
    }
  },
  { .name = "NtAlpcCreatePortSection", .num_args = 6, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "SectionHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "SectionSize", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "AlpcSectionHandle", .dir = "out", .dir_opt = "", .type = "PALPC_HANDLE"},
      {.name = "ActualSectionSize", .dir = "out", .dir_opt = "", .type = "PSIZE_T"}
    }
  },
  { .name = "NtAlpcCreateResourceReserve", .num_args = 4, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "MessageSize", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "ResourceId", .dir = "out", .dir_opt = "", .type = "PALPC_HANDLE"}
    }
  },
  { .name = "NtAlpcCreateSectionView", .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "ViewAttributes", .dir = "inout", .dir_opt = "", .type = "PALPC_DATA_VIEW_ATTR"}
    }
  },
  { .name = "NtAlpcCreateSecurityContext", .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "SecurityAttribute", .dir = "inout", .dir_opt = "", .type = "PALPC_SECURITY_ATTR"}
    }
  },
  { .name = "NtAlpcDeletePortSection", .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "SectionHandle", .dir = "in", .dir_opt = "", .type = "ALPC_HANDLE"}
    }
  },
  { .name = "NtAlpcDeleteResourceReserve", .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "ResourceId", .dir = "in", .dir_opt = "", .type = "ALPC_HANDLE"}
    }
  },
  { .name = "NtAlpcDeleteSectionView", .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "ViewBase", .dir = "in", .dir_opt = "", .type = "PVOID"}
    }
  },
  { .name = "NtAlpcDeleteSecurityContext", .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "ContextHandle", .dir = "in", .dir_opt = "", .type = "ALPC_HANDLE"}
    }
  },
  { .name = "NtAlpcDisconnectPort", .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtAlpcImpersonateClientOfPort", .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PortMessage", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"},
      {.name = "Reserved", .dir = "reserved", .dir_opt = "", .type = "PVOID"}
    }
  },
  { .name = "NtAlpcOpenSenderProcess", .num_args = 6, .args = 
    {
      {.name = "ProcessHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PortMessage", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"},
      {.name = "Flags", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtAlpcOpenSenderThread", .num_args = 6, .args = 
    {
      {.name = "ThreadHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PortMessage", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"},
      {.name = "Flags", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtAlpcQueryInformation", .num_args = 5, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PortInformationClass", .dir = "in", .dir_opt = "", .type = "ALPC_PORT_INFORMATION_CLASS"},
      {.name = "PortInformation", .dir = "out", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtAlpcQueryInformationMessage", .num_args = 6, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PortMessage", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"},
      {.name = "MessageInformationClass", .dir = "in", .dir_opt = "", .type = "ALPC_MESSAGE_INFORMATION_CLASS"},
      {.name = "MessageInformation", .dir = "out", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtAlpcRevokeSecurityContext", .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "ContextHandle", .dir = "in", .dir_opt = "", .type = "ALPC_HANDLE"}
    }
  },
  { .name = "NtAlpcSendWaitReceivePort", .num_args = 8, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "SendMessage", .dir = "in", .dir_opt = "opt", .type = "PPORT_MESSAGE"},
      {.name = "SendMessageAttributes", .dir = "in", .dir_opt = "opt", .type = "PALPC_MESSAGE_ATTRIBUTES"},
      {.name = "ReceiveMessage", .dir = "inout", .dir_opt = "opt", .type = "PPORT_MESSAGE"},
      {.name = "BufferLength", .dir = "inout", .dir_opt = "opt", .type = "PULONG"},
      {.name = "ReceiveMessageAttributes", .dir = "inout", .dir_opt = "opt", .type = "PALPC_MESSAGE_ATTRIBUTES"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtAlpcSetInformation", .num_args = 4, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PortInformationClass", .dir = "in", .dir_opt = "", .type = "ALPC_PORT_INFORMATION_CLASS"},
      {.name = "PortInformation", .dir = "in", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtApphelpCacheControl", .num_args = 2, .args = 
    {
      {.name = "type", .dir = "in", .dir_opt = "", .type = "APPHELPCOMMAND"},
      {.name = "buf", .dir = "in", .dir_opt = "", .type = "PVOID"}
    }
  },
  { .name = "NtAreMappedFilesTheSame", .num_args = 2, .args = 
    {
      {.name = "File1MappedAsAnImage", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "File2MappedAsFile", .dir = "in", .dir_opt = "", .type = "PVOID"}
    }
  },
  { .name = "NtAssignProcessToJobObject", .num_args = 2, .args = 
    {
      {.name = "JobHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"}
    }
  },
  { .name = "NtCallbackReturn", .num_args = 3, .args = 
    {
      {.name = "OutputBuffer", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "OutputLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Status", .dir = "in", .dir_opt = "", .type = "NTSTATUS"}
    }
  },
  { .name = "NtCancelIoFileEx", .num_args = 3, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoRequestToCancel", .dir = "in", .dir_opt = "opt", .type = "PIO_STATUS_BLOCK"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"}
    }
  },
  { .name = "NtCancelIoFile", .num_args = 2, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"}
    }
  },
  { .name = "NtCancelSynchronousIoFile", .num_args = 3, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoRequestToCancel", .dir = "in", .dir_opt = "opt", .type = "PIO_STATUS_BLOCK"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"}
    }
  },
  { .name = "NtCancelTimer", .num_args = 2, .args = 
    {
      {.name = "TimerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "CurrentState", .dir = "out", .dir_opt = "opt", .type = "PBOOLEAN"}
    }
  },
  { .name = "NtClearEvent", .num_args = 0  },
  { .name = "NtClose", .num_args = 0  },
  { .name = "NtCloseObjectAuditAlarm", .num_args = 3, .args = 
    {
      {.name = "SubsystemName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "HandleId", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "GenerateOnClose", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtCommitComplete", .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TmVirtualClock", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtCommitEnlistment", .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TmVirtualClock", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtCommitTransaction", .num_args = 2, .args = 
    {
      {.name = "TransactionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Wait", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtCompactKeys", .num_args = 2, .args = 
    {
      {.name = "Count", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "KeyArray[;", .dir = "in", .dir_opt = "ecount(Count)", .type = "HANDLE"}
    }
  },
  { .name = "NtCompareTokens", .num_args = 3, .args = 
    {
      {.name = "FirstTokenHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "SecondTokenHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Equal", .dir = "out", .dir_opt = "", .type = "PBOOLEAN"}
    }
  },
  { .name = "NtCompleteConnectPort", .num_args = 0  },
  { .name = "NtCompressKey", .num_args = 0  },
  { .name = "NtConnectPort", .num_args = 8, .args = 
    {
      {.name = "PortHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "PortName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "SecurityQos", .dir = "in", .dir_opt = "", .type = "PSECURITY_QUALITY_OF_SERVICE"},
      {.name = "ClientView", .dir = "inout", .dir_opt = "opt", .type = "PPORT_VIEW"},
      {.name = "ServerView", .dir = "inout", .dir_opt = "opt", .type = "PREMOTE_PORT_VIEW"},
      {.name = "MaxMessageLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"},
      {.name = "ConnectionInformation", .dir = "inout", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ConnectionInformationLength", .dir = "inout", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtContinue", .num_args = 2, .args = 
    {
      {.name = "ContextRecord", .dir = "out", .dir_opt = "", .type = "PCONTEXT"},
      {.name = "TestAlert", .dir = "out", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtCreateDebugObject", .num_args = 4, .args = 
    {
      {.name = "DebugObjectHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "out", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "out", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "Flags", .dir = "out", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtCreateDirectoryObject", .num_args = 3, .args = 
    {
      {.name = "DirectoryHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtCreateEnlistment", .num_args = 8, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ResourceManagerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TransactionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "CreateOptions", .dir = "in", .dir_opt = "opt", .type = "ULONG"},
      {.name = "NotificationMask", .dir = "in", .dir_opt = "", .type = "NOTIFICATION_MASK"},
      {.name = "EnlistmentKey", .dir = "in", .dir_opt = "opt", .type = "PVOID"}
    }
  },
  { .name = "NtCreateEvent", .num_args = 5, .args = 
    {
      {.name = "EventHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "EventType", .dir = "in", .dir_opt = "", .type = "EVENT_TYPE"},
      {.name = "InitialState", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtCreateEventPair", .num_args = 3, .args = 
    {
      {.name = "EventPairHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtCreateFile", .num_args = 11, .args = 
    {
      {.name = "FileHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "AllocationSize", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"},
      {.name = "FileAttributes", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ShareAccess", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "CreateDisposition", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "CreateOptions", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "EaBuffer", .dir = "in", .dir_opt = "bcount_opt(EaLength)", .type = "PVOID"},
      {.name = "EaLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtCreateIoCompletion", .num_args = 4, .args = 
    {
      {.name = "IoCompletionHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "Count", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtCreateJobObject", .num_args = 3, .args = 
    {
      {.name = "JobHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtCreateJobSet", .num_args = 3, .args = 
    {
      {.name = "NumJob", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "UserJobSet", .dir = "in", .dir_opt = "ecount(NumJob)", .type = "PJOB_SET_ARRAY"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtCreateKeyedEvent", .num_args = 4, .args = 
    {
      {.name = "KeyedEventHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtCreateKey", .num_args = 7, .args = 
    {
      {.name = "KeyHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "TitleIndex", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "Class", .dir = "in", .dir_opt = "opt", .type = "PUNICODE_STRING"},
      {.name = "CreateOptions", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Disposition", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtCreateKeyTransacted", .num_args = 8, .args = 
    {
      {.name = "KeyHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "TitleIndex", .dir = "reserved", .dir_opt = "", .type = "ULONG"},
      {.name = "Class", .dir = "in", .dir_opt = "opt", .type = "PUNICODE_STRING"},
      {.name = "CreateOptions", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "TransactionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Disposition", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtCreateMailslotFile", .num_args = 8, .args = 
    {
      {.name = "FileHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "CreateOptions", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "MailslotQuota", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "MaximumMessageSize", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReadTimeout", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtCreateMutant", .num_args = 4, .args = 
    {
      {.name = "MutantHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "InitialOwner", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtCreateNamedPipeFile", .num_args = 14, .args = 
    {
      {.name = "FileHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "ShareAccess", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "CreateDisposition", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "CreateOptions", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "NamedPipeType", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReadMode", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "CompletionMode", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "MaximumInstances", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "InboundQuota", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "OutboundQuota", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "DefaultTimeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtCreatePagingFile", .num_args = 4, .args = 
    {
      {.name = "PageFileName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "MinimumSize", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"},
      {.name = "MaximumSize", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"},
      {.name = "Priority", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtCreatePort", .num_args = 5, .args = 
    {
      {.name = "PortHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "MaxConnectionInfoLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "MaxMessageLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "MaxPoolUsage", .dir = "in", .dir_opt = "opt", .type = "ULONG"}
    }
  },
  { .name = "NtCreatePrivateNamespace", .num_args = 4, .args = 
    {
      {.name = "NamespaceHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "BoundaryDescriptor", .dir = "in", .dir_opt = "", .type = "PVOID"}
    }
  },
  { .name = "NtCreateProcessEx", .num_args = 9, .args = 
    {
      {.name = "ProcessHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "ParentProcess", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "SectionHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "DebugPort", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ExceptionPort", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "JobMemberLevel", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtCreateProcess", .num_args = 8, .args = 
    {
      {.name = "ProcessHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "ParentProcess", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "InheritObjectTable", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "SectionHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "DebugPort", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ExceptionPort", .dir = "in", .dir_opt = "opt", .type = "HANDLE"}
    }
  },
  { .name = "NtCreateProfileEx", .num_args = 10, .args = 
    {
      {.name = "ProfileHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "Process", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ProfileBase", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "ProfileSize", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "BucketSize", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Buffer", .dir = "in", .dir_opt = "", .type = "PULONG"},
      {.name = "BufferSize", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ProfileSource", .dir = "in", .dir_opt = "", .type = "KPROFILE_SOURCE"},
      {.name = "GroupAffinityCount", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "GroupAffinity", .dir = "in", .dir_opt = "opt", .type = "PGROUP_AFFINITY"}
    }
  },
  { .name = "NtCreateProfile", .num_args = 9, .args = 
    {
      {.name = "ProfileHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "Process", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "RangeBase", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "RangeSize", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "BucketSize", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Buffer", .dir = "in", .dir_opt = "", .type = "PULONG"},
      {.name = "BufferSize", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ProfileSource", .dir = "in", .dir_opt = "", .type = "KPROFILE_SOURCE"},
      {.name = "Affinity", .dir = "in", .dir_opt = "", .type = "KAFFINITY"}
    }
  },
  { .name = "NtCreateResourceManager", .num_args = 7, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "TmHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "RmGuid", .dir = "in", .dir_opt = "", .type = "LPGUID"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "CreateOptions", .dir = "in", .dir_opt = "opt", .type = "ULONG"},
      {.name = "Description", .dir = "in", .dir_opt = "opt", .type = "PUNICODE_STRING"}
    }
  },
  { .name = "NtCreateSection", .num_args = 7, .args = 
    {
      {.name = "SectionHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "MaximumSize", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"},
      {.name = "SectionPageProtection", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "AllocationAttributes", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "FileHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"}
    }
  },
  { .name = "NtCreateSemaphore", .num_args = 5, .args = 
    {
      {.name = "SemaphoreHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "InitialCount", .dir = "in", .dir_opt = "", .type = "LONG"},
      {.name = "MaximumCount", .dir = "in", .dir_opt = "", .type = "LONG"}
    }
  },
  { .name = "NtCreateSymbolicLinkObject", .num_args = 4, .args = 
    {
      {.name = "LinkHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "LinkTarget", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"}
    }
  },
  { .name = "NtCreateThreadEx", .num_args = 11, .args = 
    {
      {.name = "ThreadHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "StartRoutine", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "Argument", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "CreateFlags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ZeroBits", .dir = "in", .dir_opt = "opt", .type = "ULONG_PTR"},
      {.name = "StackSize", .dir = "in", .dir_opt = "opt", .type = "SIZE_T"},
      {.name = "MaximumStackSize", .dir = "in", .dir_opt = "opt", .type = "SIZE_T"},
      {.name = "AttributeList", .dir = "in", .dir_opt = "opt", .type = "PPS_ATTRIBUTE_LIST"}
    }
  },
  { .name = "NtCreateThread", .num_args = 8, .args = 
    {
      {.name = "ThreadHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ClientId", .dir = "out", .dir_opt = "", .type = "PCLIENT_ID"},
      {.name = "ThreadContext", .dir = "in", .dir_opt = "", .type = "PCONTEXT"},
      {.name = "InitialTeb", .dir = "in", .dir_opt = "", .type = "PINITIAL_TEB"},
      {.name = "CreateSuspended", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtCreateTimer", .num_args = 4, .args = 
    {
      {.name = "TimerHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "TimerType", .dir = "in", .dir_opt = "", .type = "TIMER_TYPE"}
    }
  },
  { .name = "NtCreateToken", .num_args = 13, .args = 
    {
      {.name = "TokenHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "TokenType", .dir = "in", .dir_opt = "", .type = "TOKEN_TYPE"},
      {.name = "AuthenticationId", .dir = "in", .dir_opt = "", .type = "PLUID"},
      {.name = "ExpirationTime", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"},
      {.name = "User", .dir = "in", .dir_opt = "", .type = "PTOKEN_USER"},
      {.name = "Groups", .dir = "in", .dir_opt = "", .type = "PTOKEN_GROUPS"},
      {.name = "Privileges", .dir = "in", .dir_opt = "", .type = "PTOKEN_PRIVILEGES"},
      {.name = "Owner", .dir = "in", .dir_opt = "opt", .type = "PTOKEN_OWNER"},
      {.name = "PrimaryGroup", .dir = "in", .dir_opt = "", .type = "PTOKEN_PRIMARY_GROUP"},
      {.name = "DefaultDacl", .dir = "in", .dir_opt = "opt", .type = "PTOKEN_DEFAULT_DACL"},
      {.name = "TokenSource", .dir = "in", .dir_opt = "", .type = "PTOKEN_SOURCE"}
    }
  },
  { .name = "NtCreateTransactionManager", .num_args = 6, .args = 
    {
      {.name = "TmHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "LogFileName", .dir = "in", .dir_opt = "opt", .type = "PUNICODE_STRING"},
      {.name = "CreateOptions", .dir = "in", .dir_opt = "opt", .type = "ULONG"},
      {.name = "CommitStrength", .dir = "in", .dir_opt = "opt", .type = "ULONG"}
    }
  },
  { .name = "NtCreateTransaction", .num_args = 10, .args = 
    {
      {.name = "TransactionHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "Uow", .dir = "in", .dir_opt = "opt", .type = "LPGUID"},
      {.name = "TmHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "CreateOptions", .dir = "in", .dir_opt = "opt", .type = "ULONG"},
      {.name = "IsolationLevel", .dir = "in", .dir_opt = "opt", .type = "ULONG"},
      {.name = "IsolationFlags", .dir = "in", .dir_opt = "opt", .type = "ULONG"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"},
      {.name = "Description", .dir = "in", .dir_opt = "opt", .type = "PUNICODE_STRING"}
    }
  },
  { .name = "NtCreateUserProcess", .num_args = 11, .args = 
    {
      {.name = "ProcessHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "ThreadHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "ProcessDesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ThreadDesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ProcessObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "ThreadObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "ProcessFlags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ThreadFlags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ProcessParameters", .dir = "in", .dir_opt = "opt", .type = "PRTL_USER_PROCESS_PARAMETERS"},
      {.name = "CreateInfo", .dir = "in", .dir_opt = "opt", .type = "PPROCESS_CREATE_INFO"},
      {.name = "AttributeList", .dir = "in", .dir_opt = "opt", .type = "PPROCESS_ATTRIBUTE_LIST"}
    }
  },
  { .name = "NtCreateWaitablePort", .num_args = 5, .args = 
    {
      {.name = "PortHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "MaxConnectionInfoLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "MaxMessageLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "MaxPoolUsage", .dir = "in", .dir_opt = "opt", .type = "ULONG"}
    }
  },
  { .name = "NtCreateWorkerFactory", .num_args = 10, .args = 
    {
      {.name = "WorkerFactoryHandleReturn", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "CompletionPortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "WorkerProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "StartRoutine", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "StartParameter", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "MaxThreadCount", .dir = "in", .dir_opt = "opt", .type = "ULONG"},
      {.name = "StackReserve", .dir = "in", .dir_opt = "opt", .type = "SIZE_T"},
      {.name = "StackCommit", .dir = "in", .dir_opt = "opt", .type = "SIZE_T"}
    }
  },
  { .name = "NtDebugActiveProcess", .num_args = 2, .args = 
    {
      {.name = "ProcessHandle", .dir = "out", .dir_opt = "", .type = "HANDLE"},
      {.name = "DebugObjectHandle", .dir = "out", .dir_opt = "", .type = "HANDLE"}
    }
  },
  { .name = "NtDebugContinue", .num_args = 3, .args = 
    {
      {.name = "DebugObjectHandle", .dir = "out", .dir_opt = "", .type = "HANDLE"},
      {.name = "ClientId", .dir = "out", .dir_opt = "", .type = "PCLIENT_ID"},
      {.name = "ContinueStatus", .dir = "out", .dir_opt = "", .type = "NTSTATUS"}
    }
  },
  { .name = "NtDelayExecution", .num_args = 2, .args = 
    {
      {.name = "Alertable", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "DelayInterval", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtDeleteAtom", .num_args = 0  },
  { .name = "NtDeleteBootEntry", .num_args = 0  },
  { .name = "NtDeleteDriverEntry", .num_args = 0  },
  { .name = "NtDeleteFile", .num_args = 0  },
  { .name = "NtDeleteKey", .num_args = 0  },
  { .name = "NtDeleteObjectAuditAlarm", .num_args = 3, .args = 
    {
      {.name = "SubsystemName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "HandleId", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "GenerateOnClose", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtDeletePrivateNamespace", .num_args = 0  },
  { .name = "NtDeleteValueKey", .num_args = 2, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ValueName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"}
    }
  },
  { .name = "NtDeviceIoControlFile", .num_args = 10, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PIO_APC_ROUTINE"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "IoControlCode", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "InputBuffer", .dir = "in", .dir_opt = "bcount_opt(InputBufferLength)", .type = "PVOID"},
      {.name = "InputBufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "OutputBuffer", .dir = "out", .dir_opt = "bcount_opt(OutputBufferLength)", .type = "PVOID"},
      {.name = "OutputBufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtDisableLastKnownGood", .num_args = 0  },
  { .name = "NtDisplayString", .num_args = 0  },
  { .name = "NtDrawText", .num_args = 0  },
  { .name = "NtDuplicateObject", .num_args = 7, .args = 
    {
      {.name = "SourceProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "SourceHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TargetProcessHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "TargetHandle", .dir = "out", .dir_opt = "opt", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "HandleAttributes", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Options", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtDuplicateToken", .num_args = 6, .args = 
    {
      {.name = "ExistingTokenHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "EffectiveOnly", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "TokenType", .dir = "in", .dir_opt = "", .type = "TOKEN_TYPE"},
      {.name = "NewTokenHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"}
    }
  },
  { .name = "NtEnableLastKnownGood", .num_args = 0  },
  { .name = "NtEnumerateBootEntries", .num_args = 2, .args = 
    {
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount_opt(*BufferLength)", .type = "PVOID"},
      {.name = "BufferLength", .dir = "inout", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtEnumerateDriverEntries", .num_args = 2, .args = 
    {
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount(*BufferLength)", .type = "PVOID"},
      {.name = "BufferLength", .dir = "inout", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtEnumerateKey", .num_args = 6, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Index", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "KeyInformationClass", .dir = "in", .dir_opt = "", .type = "KEY_INFORMATION_CLASS"},
      {.name = "KeyInformation", .dir = "out", .dir_opt = "bcount_opt(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ResultLength", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtEnumerateSystemEnvironmentValuesEx", .num_args = 3, .args = 
    {
      {.name = "InformationClass", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Buffer", .dir = "out", .dir_opt = "", .type = "PVOID"},
      {.name = "BufferLength", .dir = "inout", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtEnumerateTransactionObject", .num_args = 5, .args = 
    {
      {.name = "RootObjectHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "QueryType", .dir = "in", .dir_opt = "", .type = "KTMOBJECT_TYPE"},
      {.name = "ObjectCursor", .dir = "inout", .dir_opt = "bcount(ObjectCursorLength)", .type = "PKTMOBJECT_CURSOR"},
      {.name = "ObjectCursorLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtEnumerateValueKey", .num_args = 6, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Index", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "KeyValueInformationClass", .dir = "in", .dir_opt = "", .type = "KEY_VALUE_INFORMATION_CLASS"},
      {.name = "KeyValueInformation", .dir = "out", .dir_opt = "bcount_opt(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ResultLength", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtExtendSection", .num_args = 2, .args = 
    {
      {.name = "SectionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "NewSectionSize", .dir = "inout", .dir_opt = "", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtFilterToken", .num_args = 6, .args = 
    {
      {.name = "ExistingTokenHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "SidsToDisable", .dir = "in", .dir_opt = "opt", .type = "PTOKEN_GROUPS"},
      {.name = "PrivilegesToDelete", .dir = "in", .dir_opt = "opt", .type = "PTOKEN_PRIVILEGES"},
      {.name = "RestrictedSids", .dir = "in", .dir_opt = "opt", .type = "PTOKEN_GROUPS"},
      {.name = "NewTokenHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"}
    }
  },
  { .name = "NtFindAtom", .num_args = 3, .args = 
    {
      {.name = "AtomName", .dir = "in", .dir_opt = "bcount_opt(Length)", .type = "PWSTR"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Atom", .dir = "out", .dir_opt = "opt", .type = "PRTL_ATOM"}
    }
  },
  { .name = "NtFlushBuffersFile", .num_args = 2, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"}
    }
  },
  { .name = "NtFlushInstallUILanguage", .num_args = 2, .args = 
    {
      {.name = "InstallUILanguage", .dir = "in", .dir_opt = "", .type = "LANGID"},
      {.name = "SetComittedFlag", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtFlushInstructionCache", .num_args = 3, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "BaseAddress", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "SIZE_T"}
    }
  },
  { .name = "NtFlushKey", .num_args = 0  },
  { .name = "", .num_args = 0  },
  { .name = "NtFlushVirtualMemory", .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*BaseAddress", .dir = "inout", .dir_opt = "", .type = "PVOID"},
      {.name = "RegionSize", .dir = "inout", .dir_opt = "", .type = "PSIZE_T"},
      {.name = "IoStatus", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"}
    }
  },
  { .name = "NtFlushWriteBuffer", .num_args = 0  },
  { .name = "NtFreeUserPhysicalPages", .num_args = 3, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "NumberOfPages", .dir = "inout", .dir_opt = "", .type = "PULONG_PTR"},
      {.name = "UserPfnArra;", .dir = "in", .dir_opt = "ecount(*NumberOfPages)", .type = "PULONG_PTR"}
    }
  },
  { .name = "NtFreeVirtualMemory", .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*BaseAddress", .dir = "inout", .dir_opt = "", .type = "PVOID"},
      {.name = "RegionSize", .dir = "inout", .dir_opt = "", .type = "PSIZE_T"},
      {.name = "FreeType", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtFreezeRegistry", .num_args = 0  },
  { .name = "NtFreezeTransactions", .num_args = 2, .args = 
    {
      {.name = "FreezeTimeout", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"},
      {.name = "ThawTimeout", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtFsControlFile", .num_args = 10, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PIO_APC_ROUTINE"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "IoControlCode", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "InputBuffer", .dir = "in", .dir_opt = "bcount_opt(InputBufferLength)", .type = "PVOID"},
      {.name = "InputBufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "OutputBuffer", .dir = "out", .dir_opt = "bcount_opt(OutputBufferLength)", .type = "PVOID"},
      {.name = "OutputBufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtGetContextThread", .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ThreadContext", .dir = "inout", .dir_opt = "", .type = "PCONTEXT"}
    }
  },
  { .name = "", .num_args = 0  },
  { .name = "NtGetDevicePowerState", .num_args = 2, .args = 
    {
      {.name = "Device", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*State", .dir = "out", .dir_opt = "", .type = "DEVICE_POWER_STATE"}
    }
  },
  { .name = "NtGetMUIRegistryInfo", .num_args = 3, .args = 
    {
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "DataSize", .dir = "inout", .dir_opt = "", .type = "PULONG"},
      {.name = "Data", .dir = "out", .dir_opt = "", .type = "PVOID"}
    }
  },
  { .name = "NtGetNextProcess", .num_args = 5, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "HandleAttributes", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "NewProcessHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"}
    }
  },
  { .name = "NtGetNextThread", .num_args = 6, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "HandleAttributes", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "NewThreadHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"}
    }
  },
  { .name = "NtGetNlsSectionPtr", .num_args = 5, .args = 
    {
      {.name = "SectionType", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "SectionData", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ContextData", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "*SectionPointer", .dir = "out", .dir_opt = "", .type = "PVOID"},
      {.name = "SectionSize", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtGetNotificationResourceManager", .num_args = 7, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TransactionNotification", .dir = "out", .dir_opt = "", .type = "PTRANSACTION_NOTIFICATION"},
      {.name = "NotificationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"},
      {.name = "Asynchronous", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "AsynchronousContext", .dir = "in", .dir_opt = "opt", .type = "ULONG_PTR"}
    }
  },
  { .name = "NtGetPlugPlayEvent", .num_args = 4, .args = 
    {
      {.name = "EventHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Context", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "EventBlock", .dir = "out", .dir_opt = "bcount(EventBufferSize)", .type = "PPLUGPLAY_EVENT_BLOCK"},
      {.name = "EventBufferSize", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtGetWriteWatch", .num_args = 7, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "BaseAddress", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "RegionSize", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "*UserAddressArray", .dir = "out", .dir_opt = "ecount(*EntriesInUserAddressArray)", .type = "PVOID"},
      {.name = "EntriesInUserAddressArray", .dir = "inout", .dir_opt = "", .type = "PULONG_PTR"},
      {.name = "Granularity", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtImpersonateAnonymousToken", .num_args = 0  },
  { .name = "NtImpersonateClientOfPort", .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Message", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"}
    }
  },
  { .name = "NtImpersonateThread", .num_args = 3, .args = 
    {
      {.name = "ServerThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ClientThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "SecurityQos", .dir = "in", .dir_opt = "", .type = "PSECURITY_QUALITY_OF_SERVICE"}
    }
  },
  { .name = "NtInitializeNlsFiles", .num_args = 3, .args = 
    {
      {.name = "*BaseAddress", .dir = "out", .dir_opt = "", .type = "PVOID"},
      {.name = "DefaultLocaleId", .dir = "out", .dir_opt = "", .type = "PLCID"},
      {.name = "DefaultCasingTableSize", .dir = "out", .dir_opt = "", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtInitializeRegistry", .num_args = 0  },
  { .name = "NtInitiatePowerAction", .num_args = 4, .args = 
    {
      {.name = "SystemAction", .dir = "in", .dir_opt = "", .type = "POWER_ACTION"},
      {.name = "MinSystemState", .dir = "in", .dir_opt = "", .type = "SYSTEM_POWER_STATE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Asynchronous", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtIsProcessInJob", .num_args = 2, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "JobHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"}
    }
  },
  { .name = "", .num_args = 0  },
  { .name = "NtIsUILanguageComitted", .num_args = 0  },
  { .name = "NtListenPort", .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ConnectionRequest", .dir = "out", .dir_opt = "", .type = "PPORT_MESSAGE"}
    }
  },
  { .name = "NtLoadDriver", .num_args = 0  },
  { .name = "NtLoadKey2", .num_args = 3, .args = 
    {
      {.name = "TargetKey", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "SourceFile", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtLoadKeyEx", .num_args = 4, .args = 
    {
      {.name = "TargetKey", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "SourceFile", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "TrustClassKey", .dir = "in", .dir_opt = "opt", .type = "HANDLE"}
    }
  },
  { .name = "NtLoadKey", .num_args = 2, .args = 
    {
      {.name = "TargetKey", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "SourceFile", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtLockFile", .num_args = 10, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PIO_APC_ROUTINE"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "ByteOffset", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"},
      {.name = "Key", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "FailImmediately", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "ExclusiveLock", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtLockProductActivationKeys", .num_args = 2, .args = 
    {
      {.name = "*pPrivateVer", .dir = "inout", .dir_opt = "opt", .type = "ULONG"},
      {.name = "*pSafeMode", .dir = "out", .dir_opt = "opt", .type = "ULONG"}
    }
  },
  { .name = "NtLockRegistryKey", .num_args = 0  },
  { .name = "NtLockVirtualMemory", .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*BaseAddress", .dir = "inout", .dir_opt = "", .type = "PVOID"},
      {.name = "RegionSize", .dir = "inout", .dir_opt = "", .type = "PSIZE_T"},
      {.name = "MapType", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtMakePermanentObject", .num_args = 0  },
  { .name = "NtMakeTemporaryObject", .num_args = 0  },
  { .name = "NtMapCMFModule", .num_args = 6, .args = 
    {
      {.name = "What", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Index", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "CacheIndexOut", .dir = "out", .dir_opt = "opt", .type = "PULONG"},
      {.name = "CacheFlagsOut", .dir = "out", .dir_opt = "opt", .type = "PULONG"},
      {.name = "ViewSizeOut", .dir = "out", .dir_opt = "opt", .type = "PULONG"},
      {.name = "*BaseAddress", .dir = "out", .dir_opt = "opt", .type = "PVOID"}
    }
  },
  { .name = "NtMapUserPhysicalPages", .num_args = 3, .args = 
    {
      {.name = "VirtualAddress", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "NumberOfPages", .dir = "in", .dir_opt = "", .type = "ULONG_PTR"},
      {.name = "UserPfnArra;", .dir = "in", .dir_opt = "ecount_opt(NumberOfPages)", .type = "PULONG_PTR"}
    }
  },
  { .name = "NtMapUserPhysicalPagesScatter", .num_args = 3, .args = 
    {
      {.name = "*VirtualAddresses", .dir = "in", .dir_opt = "ecount(NumberOfPages)", .type = "PVOID"},
      {.name = "NumberOfPages", .dir = "in", .dir_opt = "", .type = "ULONG_PTR"},
      {.name = "UserPfnArray", .dir = "in", .dir_opt = "ecount_opt(NumberOfPages)", .type = "PULONG_PTR"}
    }
  },
  { .name = "NtMapViewOfSection", .num_args = 10, .args = 
    {
      {.name = "SectionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*BaseAddress", .dir = "inout", .dir_opt = "", .type = "PVOID"},
      {.name = "ZeroBits", .dir = "in", .dir_opt = "", .type = "ULONG_PTR"},
      {.name = "CommitSize", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "SectionOffset", .dir = "inout", .dir_opt = "opt", .type = "PLARGE_INTEGER"},
      {.name = "ViewSize", .dir = "inout", .dir_opt = "", .type = "PSIZE_T"},
      {.name = "InheritDisposition", .dir = "in", .dir_opt = "", .type = "SECTION_INHERIT"},
      {.name = "AllocationType", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Win32Protect", .dir = "in", .dir_opt = "", .type = "WIN32_PROTECTION_MASK"}
    }
  },
  { .name = "NtModifyBootEntry", .num_args = 0  },
  { .name = "NtModifyDriverEntry", .num_args = 0  },
  { .name = "NtNotifyChangeDirectoryFile", .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PIO_APC_ROUTINE"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "CompletionFilter", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "WatchTree", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtNotifyChangeKey", .num_args = 10, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PIO_APC_ROUTINE"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "CompletionFilter", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "WatchTree", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount_opt(BufferSize)", .type = "PVOID"},
      {.name = "BufferSize", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Asynchronous", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtNotifyChangeMultipleKeys", .num_args = 12, .args = 
    {
      {.name = "MasterKeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Count", .dir = "in", .dir_opt = "opt", .type = "ULONG"},
      {.name = "SlaveObjects[]", .dir = "in", .dir_opt = "ecount_opt(Count)", .type = "OBJECT_ATTRIBUTES"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PIO_APC_ROUTINE"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "CompletionFilter", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "WatchTree", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount_opt(BufferSize)", .type = "PVOID"},
      {.name = "BufferSize", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Asynchronous", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtNotifyChangeSession", .num_args = 8, .args = 
    {
      {.name = "Session", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStateSequence", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Reserved", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "Action", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "IoState", .dir = "in", .dir_opt = "", .type = "IO_SESSION_STATE"},
      {.name = "IoState2", .dir = "in", .dir_opt = "", .type = "IO_SESSION_STATE"},
      {.name = "Buffer", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "BufferSize", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtOpenDirectoryObject", .num_args = 3, .args = 
    {
      {.name = "DirectoryHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenEnlistment", .num_args = 5, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ResourceManagerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "EnlistmentGuid", .dir = "in", .dir_opt = "", .type = "LPGUID"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenEvent", .num_args = 3, .args = 
    {
      {.name = "EventHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenEventPair", .num_args = 3, .args = 
    {
      {.name = "EventPairHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenFile", .num_args = 6, .args = 
    {
      {.name = "FileHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "ShareAccess", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "OpenOptions", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtOpenIoCompletion", .num_args = 3, .args = 
    {
      {.name = "IoCompletionHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenJobObject", .num_args = 3, .args = 
    {
      {.name = "JobHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenKeyedEvent", .num_args = 3, .args = 
    {
      {.name = "KeyedEventHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenKeyEx", .num_args = 4, .args = 
    {
      {.name = "KeyHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "OpenOptions", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtOpenKey", .num_args = 3, .args = 
    {
      {.name = "KeyHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenKeyTransactedEx", .num_args = 5, .args = 
    {
      {.name = "KeyHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "OpenOptions", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "TransactionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"}
    }
  },
  { .name = "NtOpenKeyTransacted", .num_args = 4, .args = 
    {
      {.name = "KeyHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "TransactionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"}
    }
  },
  { .name = "NtOpenMutant", .num_args = 3, .args = 
    {
      {.name = "MutantHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenObjectAuditAlarm", .num_args = 12, .args = 
    {
      {.name = "SubsystemName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "HandleId", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ObjectTypeName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "ObjectName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "SecurityDescriptor", .dir = "in", .dir_opt = "opt", .type = "PSECURITY_DESCRIPTOR"},
      {.name = "ClientToken", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "GrantedAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "Privileges", .dir = "in", .dir_opt = "opt", .type = "PPRIVILEGE_SET"},
      {.name = "ObjectCreation", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "AccessGranted", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "GenerateOnClose", .dir = "out", .dir_opt = "", .type = "PBOOLEAN"}
    }
  },
  { .name = "NtOpenPrivateNamespace", .num_args = 4, .args = 
    {
      {.name = "NamespaceHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "BoundaryDescriptor", .dir = "in", .dir_opt = "", .type = "PVOID"}
    }
  },
  { .name = "NtOpenProcess", .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "ClientId", .dir = "in", .dir_opt = "opt", .type = "PCLIENT_ID"}
    }
  },
  { .name = "NtOpenProcessTokenEx", .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "HandleAttributes", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "TokenHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"}
    }
  },
  { .name = "NtOpenProcessToken", .num_args = 3, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "TokenHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"}
    }
  },
  { .name = "NtOpenResourceManager", .num_args = 5, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "TmHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ResourceManagerGuid", .dir = "in", .dir_opt = "opt", .type = "LPGUID"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenSection", .num_args = 3, .args = 
    {
      {.name = "SectionHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenSemaphore", .num_args = 3, .args = 
    {
      {.name = "SemaphoreHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenSession", .num_args = 3, .args = 
    {
      {.name = "SessionHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenSymbolicLinkObject", .num_args = 3, .args = 
    {
      {.name = "LinkHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenThread", .num_args = 4, .args = 
    {
      {.name = "ThreadHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "ClientId", .dir = "in", .dir_opt = "opt", .type = "PCLIENT_ID"}
    }
  },
  { .name = "NtOpenThreadTokenEx", .num_args = 5, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "OpenAsSelf", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "HandleAttributes", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "TokenHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"}
    }
  },
  { .name = "NtOpenThreadToken", .num_args = 4, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "OpenAsSelf", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "TokenHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"}
    }
  },
  { .name = "NtOpenTimer", .num_args = 3, .args = 
    {
      {.name = "TimerHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtOpenTransactionManager", .num_args = 6, .args = 
    {
      {.name = "TmHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "opt", .type = "POBJECT_ATTRIBUTES"},
      {.name = "LogFileName", .dir = "in", .dir_opt = "opt", .type = "PUNICODE_STRING"},
      {.name = "TmIdentity", .dir = "in", .dir_opt = "opt", .type = "LPGUID"},
      {.name = "OpenOptions", .dir = "in", .dir_opt = "opt", .type = "ULONG"}
    }
  },
  { .name = "NtOpenTransaction", .num_args = 5, .args = 
    {
      {.name = "TransactionHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "Uow", .dir = "in", .dir_opt = "", .type = "LPGUID"},
      {.name = "TmHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"}
    }
  },
  { .name = "NtPlugPlayControl", .num_args = 3, .args = 
    {
      {.name = "PnPControlClass", .dir = "in", .dir_opt = "", .type = "PLUGPLAY_CONTROL_CLASS"},
      {.name = "PnPControlData", .dir = "inout", .dir_opt = "bcount(PnPControlDataLength)", .type = "PVOID"},
      {.name = "PnPControlDataLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtPowerInformation", .num_args = 5, .args = 
    {
      {.name = "InformationLevel", .dir = "in", .dir_opt = "", .type = "POWER_INFORMATION_LEVEL"},
      {.name = "InputBuffer", .dir = "in", .dir_opt = "bcount_opt(InputBufferLength)", .type = "PVOID"},
      {.name = "InputBufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "OutputBuffer", .dir = "out", .dir_opt = "bcount_opt(OutputBufferLength)", .type = "PVOID"},
      {.name = "OutputBufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtPrepareComplete", .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TmVirtualClock", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtPrepareEnlistment", .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TmVirtualClock", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtPrePrepareComplete", .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TmVirtualClock", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtPrePrepareEnlistment", .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TmVirtualClock", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtPrivilegeCheck", .num_args = 3, .args = 
    {
      {.name = "ClientToken", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "RequiredPrivileges", .dir = "inout", .dir_opt = "", .type = "PPRIVILEGE_SET"},
      {.name = "Result", .dir = "out", .dir_opt = "", .type = "PBOOLEAN"}
    }
  },
  { .name = "NtPrivilegedServiceAuditAlarm", .num_args = 5, .args = 
    {
      {.name = "SubsystemName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "ServiceName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "ClientToken", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Privileges", .dir = "in", .dir_opt = "", .type = "PPRIVILEGE_SET"},
      {.name = "AccessGranted", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtPrivilegeObjectAuditAlarm", .num_args = 6, .args = 
    {
      {.name = "SubsystemName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "HandleId", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ClientToken", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DesiredAccess", .dir = "in", .dir_opt = "", .type = "ACCESS_MASK"},
      {.name = "Privileges", .dir = "in", .dir_opt = "", .type = "PPRIVILEGE_SET"},
      {.name = "AccessGranted", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtPropagationComplete", .num_args = 4, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "RequestCookie", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "BufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Buffer", .dir = "in", .dir_opt = "", .type = "PVOID"}
    }
  },
  { .name = "NtPropagationFailed", .num_args = 3, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "RequestCookie", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "PropStatus", .dir = "in", .dir_opt = "", .type = "NTSTATUS"}
    }
  },
  { .name = "NtProtectVirtualMemory", .num_args = 5, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*BaseAddress", .dir = "inout", .dir_opt = "", .type = "PVOID"},
      {.name = "RegionSize", .dir = "inout", .dir_opt = "", .type = "PSIZE_T"},
      {.name = "NewProtectWin32", .dir = "in", .dir_opt = "", .type = "WIN32_PROTECTION_MASK"},
      {.name = "OldProtect", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtPulseEvent", .num_args = 2, .args = 
    {
      {.name = "EventHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PreviousState", .dir = "out", .dir_opt = "opt", .type = "PLONG"}
    }
  },
  { .name = "NtQueryAttributesFile", .num_args = 2, .args = 
    {
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "FileInformation", .dir = "out", .dir_opt = "", .type = "PFILE_BASIC_INFORMATION"}
    }
  },
  { .name = "NtQueryBootEntryOrder", .num_args = 2, .args = 
    {
      {.name = "Ids", .dir = "out", .dir_opt = "ecount_opt(*Count)", .type = "PULONG"},
      {.name = "Count", .dir = "inout", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQueryBootOptions", .num_args = 2, .args = 
    {
      {.name = "BootOptions", .dir = "out", .dir_opt = "bcount_opt(*BootOptionsLength)", .type = "PBOOT_OPTIONS"},
      {.name = "BootOptionsLength", .dir = "inout", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQueryDebugFilterState", .num_args = 2, .args = 
    {
      {.name = "ComponentId", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Level", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtQueryDefaultLocale", .num_args = 2, .args = 
    {
      {.name = "UserProfile", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "DefaultLocaleId", .dir = "out", .dir_opt = "", .type = "PLCID"}
    }
  },
  { .name = "NtQueryDefaultUILanguage", .num_args = 0  },
  { .name = "NtQueryDirectoryFile", .num_args = 11, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PIO_APC_ROUTINE"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "FileInformation", .dir = "out", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "FileInformationClass", .dir = "in", .dir_opt = "", .type = "FILE_INFORMATION_CLASS"},
      {.name = "ReturnSingleEntry", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "FileName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "RestartScan", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtQueryDirectoryObject", .num_args = 7, .args = 
    {
      {.name = "DirectoryHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount_opt(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnSingleEntry", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "RestartScan", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "Context", .dir = "inout", .dir_opt = "", .type = "PULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryDriverEntryOrder", .num_args = 2, .args = 
    {
      {.name = "Ids", .dir = "out", .dir_opt = "ecount(*Count)", .type = "PULONG"},
      {.name = "Count", .dir = "inout", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQueryEaFile", .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnSingleEntry", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "EaList", .dir = "in", .dir_opt = "bcount_opt(EaListLength)", .type = "PVOID"},
      {.name = "EaListLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "EaIndex", .dir = "in", .dir_opt = "opt", .type = "PULONG"},
      {.name = "RestartScan", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtQueryEvent", .num_args = 5, .args = 
    {
      {.name = "EventHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "EventInformationClass", .dir = "in", .dir_opt = "", .type = "EVENT_INFORMATION_CLASS"},
      {.name = "EventInformation", .dir = "out", .dir_opt = "bcount(EventInformationLength)", .type = "PVOID"},
      {.name = "EventInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryFullAttributesFile", .num_args = 2, .args = 
    {
      {.name = "ObjectAttributes", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "FileInformation", .dir = "out", .dir_opt = "", .type = "PFILE_NETWORK_OPEN_INFORMATION"}
    }
  },
  { .name = "NtQueryInformationAtom", .num_args = 5, .args = 
    {
      {.name = "Atom", .dir = "in", .dir_opt = "", .type = "RTL_ATOM"},
      {.name = "InformationClass", .dir = "in", .dir_opt = "", .type = "ATOM_INFORMATION_CLASS"},
      {.name = "AtomInformation", .dir = "out", .dir_opt = "bcount(AtomInformationLength)", .type = "PVOID"},
      {.name = "AtomInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryInformationEnlistment", .num_args = 5, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "EnlistmentInformationClass", .dir = "in", .dir_opt = "", .type = "ENLISTMENT_INFORMATION_CLASS"},
      {.name = "EnlistmentInformation", .dir = "out", .dir_opt = "bcount(EnlistmentInformationLength)", .type = "PVOID"},
      {.name = "EnlistmentInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryInformationFile", .num_args = 5, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "FileInformation", .dir = "out", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "FileInformationClass", .dir = "in", .dir_opt = "", .type = "FILE_INFORMATION_CLASS"}
    }
  },
  { .name = "NtQueryInformationJobObject", .num_args = 5, .args = 
    {
      {.name = "JobHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "JobObjectInformationClass", .dir = "in", .dir_opt = "", .type = "JOBOBJECTINFOCLASS"},
      {.name = "JobObjectInformation", .dir = "out", .dir_opt = "bcount(JobObjectInformationLength)", .type = "PVOID"},
      {.name = "JobObjectInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryInformationPort", .num_args = 5, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PortInformationClass", .dir = "in", .dir_opt = "", .type = "PORT_INFORMATION_CLASS"},
      {.name = "PortInformation", .dir = "out", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryInformationProcess", .num_args = 5, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ProcessInformationClass", .dir = "in", .dir_opt = "", .type = "PROCESSINFOCLASS"},
      {.name = "ProcessInformation", .dir = "out", .dir_opt = "bcount(ProcessInformationLength)", .type = "PVOID"},
      {.name = "ProcessInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryInformationResourceManager", .num_args = 5, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ResourceManagerInformationClass", .dir = "in", .dir_opt = "", .type = "RESOURCEMANAGER_INFORMATION_CLASS"},
      {.name = "ResourceManagerInformation", .dir = "out", .dir_opt = "bcount(ResourceManagerInformationLength)", .type = "PVOID"},
      {.name = "ResourceManagerInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryInformationThread", .num_args = 5, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ThreadInformationClass", .dir = "in", .dir_opt = "", .type = "THREADINFOCLASS"},
      {.name = "ThreadInformation", .dir = "out", .dir_opt = "bcount(ThreadInformationLength)", .type = "PVOID"},
      {.name = "ThreadInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryInformationToken", .num_args = 5, .args = 
    {
      {.name = "TokenHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TokenInformationClass", .dir = "in", .dir_opt = "", .type = "TOKEN_INFORMATION_CLASS"},
      {.name = "TokenInformation", .dir = "out", .dir_opt = "bcount_part_opt(TokenInformationLength,*ReturnLength)", .type = "PVOID"},
      {.name = "TokenInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQueryInformationTransaction", .num_args = 5, .args = 
    {
      {.name = "TransactionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TransactionInformationClass", .dir = "in", .dir_opt = "", .type = "TRANSACTION_INFORMATION_CLASS"},
      {.name = "TransactionInformation", .dir = "out", .dir_opt = "bcount(TransactionInformationLength)", .type = "PVOID"},
      {.name = "TransactionInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryInformationTransactionManager", .num_args = 5, .args = 
    {
      {.name = "TransactionManagerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TransactionManagerInformationClass", .dir = "in", .dir_opt = "", .type = "TRANSACTIONMANAGER_INFORMATION_CLASS"},
      {.name = "TransactionManagerInformation", .dir = "out", .dir_opt = "bcount(TransactionManagerInformationLength)", .type = "PVOID"},
      {.name = "TransactionManagerInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryInformationWorkerFactory", .num_args = 5, .args = 
    {
      {.name = "WorkerFactoryHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "WorkerFactoryInformationClass", .dir = "in", .dir_opt = "", .type = "WORKERFACTORYINFOCLASS"},
      {.name = "WorkerFactoryInformation", .dir = "out", .dir_opt = "bcount(WorkerFactoryInformationLength)", .type = "PVOID"},
      {.name = "WorkerFactoryInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryInstallUILanguage", .num_args = 0  },
  { .name = "NtQueryIntervalProfile", .num_args = 2, .args = 
    {
      {.name = "ProfileSource", .dir = "in", .dir_opt = "", .type = "KPROFILE_SOURCE"},
      {.name = "Interval", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQueryIoCompletion", .num_args = 5, .args = 
    {
      {.name = "IoCompletionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoCompletionInformationClass", .dir = "in", .dir_opt = "", .type = "IO_COMPLETION_INFORMATION_CLASS"},
      {.name = "IoCompletionInformation", .dir = "out", .dir_opt = "bcount(IoCompletionInformationLength)", .type = "PVOID"},
      {.name = "IoCompletionInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryKey", .num_args = 5, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "KeyInformationClass", .dir = "in", .dir_opt = "", .type = "KEY_INFORMATION_CLASS"},
      {.name = "KeyInformation", .dir = "out", .dir_opt = "bcount_opt(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ResultLength", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQueryLicenseValue", .num_args = 5, .args = 
    {
      {.name = "Name", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "Type", .dir = "out", .dir_opt = "opt", .type = "PULONG"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount(ReturnedLength)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnedLength", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQueryMultipleValueKey", .num_args = 6, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ValueEntries", .dir = "inout", .dir_opt = "ecount(EntryCount)", .type = "PKEY_VALUE_ENTRY"},
      {.name = "EntryCount", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ValueBuffer", .dir = "out", .dir_opt = "bcount(*BufferLength)", .type = "PVOID"},
      {.name = "BufferLength", .dir = "inout", .dir_opt = "", .type = "PULONG"},
      {.name = "RequiredBufferLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryMutant", .num_args = 5, .args = 
    {
      {.name = "MutantHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "MutantInformationClass", .dir = "in", .dir_opt = "", .type = "MUTANT_INFORMATION_CLASS"},
      {.name = "MutantInformation", .dir = "out", .dir_opt = "bcount(MutantInformationLength)", .type = "PVOID"},
      {.name = "MutantInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryObject", .num_args = 5, .args = 
    {
      {.name = "Handle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ObjectInformationClass", .dir = "in", .dir_opt = "", .type = "OBJECT_INFORMATION_CLASS"},
      {.name = "ObjectInformation", .dir = "out", .dir_opt = "bcount_opt(ObjectInformationLength)", .type = "PVOID"},
      {.name = "ObjectInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryOpenSubKeysEx", .num_args = 4, .args = 
    {
      {.name = "TargetKey", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "BufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount(BufferLength)", .type = "PVOID"},
      {.name = "RequiredSize", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQueryOpenSubKeys", .num_args = 2, .args = 
    {
      {.name = "TargetKey", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "HandleCount", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQueryPerformanceCounter", .num_args = 2, .args = 
    {
      {.name = "PerformanceCounter", .dir = "out", .dir_opt = "", .type = "PLARGE_INTEGER"},
      {.name = "PerformanceFrequency", .dir = "out", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtQueryPortInformationProcess", .num_args = 0  },
  { .name = "NtQueryQuotaInformationFile", .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnSingleEntry", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "SidList", .dir = "in", .dir_opt = "bcount_opt(SidListLength)", .type = "PVOID"},
      {.name = "SidListLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "StartSid", .dir = "in", .dir_opt = "opt", .type = "PULONG"},
      {.name = "RestartScan", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtQuerySection", .num_args = 5, .args = 
    {
      {.name = "SectionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "SectionInformationClass", .dir = "in", .dir_opt = "", .type = "SECTION_INFORMATION_CLASS"},
      {.name = "SectionInformation", .dir = "out", .dir_opt = "bcount(SectionInformationLength)", .type = "PVOID"},
      {.name = "SectionInformationLength", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PSIZE_T"}
    }
  },
  { .name = "NtQuerySecurityAttributesToken", .num_args = 6, .args = 
    {
      {.name = "TokenHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Attributes", .dir = "in", .dir_opt = "ecount_opt(NumberOfAttributes)", .type = "PUNICODE_STRING"},
      {.name = "NumberOfAttributes", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQuerySecurityObject", .num_args = 5, .args = 
    {
      {.name = "Handle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "SecurityInformation", .dir = "in", .dir_opt = "", .type = "SECURITY_INFORMATION"},
      {.name = "SecurityDescriptor", .dir = "out", .dir_opt = "bcount_opt(Length)", .type = "PSECURITY_DESCRIPTOR"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "LengthNeeded", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQuerySemaphore", .num_args = 5, .args = 
    {
      {.name = "SemaphoreHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "SemaphoreInformationClass", .dir = "in", .dir_opt = "", .type = "SEMAPHORE_INFORMATION_CLASS"},
      {.name = "SemaphoreInformation", .dir = "out", .dir_opt = "bcount(SemaphoreInformationLength)", .type = "PVOID"},
      {.name = "SemaphoreInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQuerySymbolicLinkObject", .num_args = 3, .args = 
    {
      {.name = "LinkHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "LinkTarget", .dir = "inout", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "ReturnedLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQuerySystemEnvironmentValueEx", .num_args = 5, .args = 
    {
      {.name = "VariableName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "VendorGuid", .dir = "in", .dir_opt = "", .type = "LPGUID"},
      {.name = "Value", .dir = "out", .dir_opt = "bcount_opt(*ValueLength)", .type = "PVOID"},
      {.name = "ValueLength", .dir = "inout", .dir_opt = "", .type = "PULONG"},
      {.name = "Attributes", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQuerySystemEnvironmentValue", .num_args = 4, .args = 
    {
      {.name = "VariableName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "VariableValue", .dir = "out", .dir_opt = "bcount(ValueLength)", .type = "PWSTR"},
      {.name = "ValueLength", .dir = "in", .dir_opt = "", .type = "USHORT"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PUSHORT"}
    }
  },
  { .name = "NtQuerySystemInformationEx", .num_args = 6, .args = 
    {
      {.name = "SystemInformationClass", .dir = "in", .dir_opt = "", .type = "SYSTEM_INFORMATION_CLASS"},
      {.name = "QueryInformation", .dir = "in", .dir_opt = "bcount(QueryInformationLength)", .type = "PVOID"},
      {.name = "QueryInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "SystemInformation", .dir = "out", .dir_opt = "bcount_opt(SystemInformationLength)", .type = "PVOID"},
      {.name = "SystemInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQuerySystemInformation", .num_args = 4, .args = 
    {
      {.name = "SystemInformationClass", .dir = "in", .dir_opt = "", .type = "SYSTEM_INFORMATION_CLASS"},
      {.name = "SystemInformation", .dir = "out", .dir_opt = "bcount_opt(SystemInformationLength)", .type = "PVOID"},
      {.name = "SystemInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQuerySystemTime", .num_args = 0  },
  { .name = "NtQueryTimer", .num_args = 5, .args = 
    {
      {.name = "TimerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TimerInformationClass", .dir = "in", .dir_opt = "", .type = "TIMER_INFORMATION_CLASS"},
      {.name = "TimerInformation", .dir = "out", .dir_opt = "bcount(TimerInformationLength)", .type = "PVOID"},
      {.name = "TimerInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtQueryTimerResolution", .num_args = 3, .args = 
    {
      {.name = "MaximumTime", .dir = "out", .dir_opt = "", .type = "PULONG"},
      {.name = "MinimumTime", .dir = "out", .dir_opt = "", .type = "PULONG"},
      {.name = "CurrentTime", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQueryValueKey", .num_args = 6, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ValueName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "KeyValueInformationClass", .dir = "in", .dir_opt = "", .type = "KEY_VALUE_INFORMATION_CLASS"},
      {.name = "KeyValueInformation", .dir = "out", .dir_opt = "bcount_opt(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ResultLength", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtQueryVirtualMemory", .num_args = 6, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "BaseAddress", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "MemoryInformationClass", .dir = "in", .dir_opt = "", .type = "MEMORY_INFORMATION_CLASS"},
      {.name = "MemoryInformation", .dir = "out", .dir_opt = "bcount(MemoryInformationLength)", .type = "PVOID"},
      {.name = "MemoryInformationLength", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PSIZE_T"}
    }
  },
  { .name = "NtQueryVolumeInformationFile", .num_args = 5, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "FsInformation", .dir = "out", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "FsInformationClass", .dir = "in", .dir_opt = "", .type = "FS_INFORMATION_CLASS"}
    }
  },
  { .name = "NtQueueApcThreadEx", .num_args = 6, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "UserApcReserveHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "", .type = "PPS_APC_ROUTINE"},
      {.name = "ApcArgument1", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ApcArgument2", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ApcArgument3", .dir = "in", .dir_opt = "opt", .type = "PVOID"}
    }
  },
  { .name = "NtQueueApcThread", .num_args = 5, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "", .type = "PPS_APC_ROUTINE"},
      {.name = "ApcArgument1", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ApcArgument2", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ApcArgument3", .dir = "in", .dir_opt = "opt", .type = "PVOID"}
    }
  },
  { .name = "NtRaiseException", .num_args = 3, .args = 
    {
      {.name = "ExceptionRecord", .dir = "out", .dir_opt = "", .type = "PEXCEPTION_RECORD"},
      {.name = "ContextRecord", .dir = "out", .dir_opt = "", .type = "PCONTEXT"},
      {.name = "FirstChance", .dir = "out", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtRaiseHardError", .num_args = 6, .args = 
    {
      {.name = "ErrorStatus", .dir = "in", .dir_opt = "", .type = "NTSTATUS"},
      {.name = "NumberOfParameters", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "UnicodeStringParameterMask", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Parameters", .dir = "in", .dir_opt = "ecount(NumberOfParameters)", .type = "PULONG_PTR"},
      {.name = "ValidResponseOptions", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Response", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtReadFile", .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PIO_APC_ROUTINE"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ByteOffset", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"},
      {.name = "Key", .dir = "in", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtReadFileScatter", .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PIO_APC_ROUTINE"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "SegmentArray", .dir = "in", .dir_opt = "", .type = "PFILE_SEGMENT_ELEMENT"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ByteOffset", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"},
      {.name = "Key", .dir = "in", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtReadOnlyEnlistment", .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TmVirtualClock", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtReadRequestData", .num_args = 6, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Message", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"},
      {.name = "DataEntryIndex", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount(BufferSize)", .type = "PVOID"},
      {.name = "BufferSize", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "NumberOfBytesRead", .dir = "out", .dir_opt = "opt", .type = "PSIZE_T"}
    }
  },
  { .name = "NtReadVirtualMemory", .num_args = 5, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "BaseAddress", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "Buffer", .dir = "out", .dir_opt = "bcount(BufferSize)", .type = "PVOID"},
      {.name = "BufferSize", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "NumberOfBytesRead", .dir = "out", .dir_opt = "opt", .type = "PSIZE_T"}
    }
  },
  { .name = "NtRecoverEnlistment", .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "EnlistmentKey", .dir = "in", .dir_opt = "opt", .type = "PVOID"}
    }
  },
  { .name = "NtRecoverResourceManager", .num_args = 0  },
  { .name = "NtRecoverTransactionManager", .num_args = 0  },
  { .name = "NtRegisterProtocolAddressInformation", .num_args = 5, .args = 
    {
      {.name = "ResourceManager", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ProtocolId", .dir = "in", .dir_opt = "", .type = "PCRM_PROTOCOL_ID"},
      {.name = "ProtocolInformationSize", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ProtocolInformation", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "CreateOptions", .dir = "in", .dir_opt = "opt", .type = "ULONG"}
    }
  },
  { .name = "NtRegisterThreadTerminatePort", .num_args = 0  },
  { .name = "NtReleaseKeyedEvent", .num_args = 4, .args = 
    {
      {.name = "KeyedEventHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "KeyValue", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "Alertable", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtReleaseMutant", .num_args = 2, .args = 
    {
      {.name = "MutantHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PreviousCount", .dir = "out", .dir_opt = "opt", .type = "PLONG"}
    }
  },
  { .name = "NtReleaseSemaphore", .num_args = 3, .args = 
    {
      {.name = "SemaphoreHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ReleaseCount", .dir = "in", .dir_opt = "", .type = "LONG"},
      {.name = "PreviousCount", .dir = "out", .dir_opt = "opt", .type = "PLONG"}
    }
  },
  { .name = "NtReleaseWorkerFactoryWorker", .num_args = 0  },
  { .name = "NtRemoveIoCompletionEx", .num_args = 6, .args = 
    {
      {.name = "IoCompletionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoCompletionInformation", .dir = "out", .dir_opt = "ecount(Count)", .type = "PFILE_IO_COMPLETION_INFORMATION"},
      {.name = "Count", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "NumEntriesRemoved", .dir = "out", .dir_opt = "", .type = "PULONG"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"},
      {.name = "Alertable", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtRemoveIoCompletion", .num_args = 5, .args = 
    {
      {.name = "IoCompletionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*KeyContext", .dir = "out", .dir_opt = "", .type = "PVOID"},
      {.name = "*ApcContext", .dir = "out", .dir_opt = "", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtRemoveProcessDebug", .num_args = 2, .args = 
    {
      {.name = "ProcessHandle", .dir = "out", .dir_opt = "", .type = "HANDLE"},
      {.name = "DebugObjectHandle", .dir = "out", .dir_opt = "", .type = "HANDLE"}
    }
  },
  { .name = "NtRenameKey", .num_args = 2, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "NewName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"}
    }
  },
  { .name = "NtRenameTransactionManager", .num_args = 2, .args = 
    {
      {.name = "LogFileName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "ExistingTransactionManagerGuid", .dir = "in", .dir_opt = "", .type = "LPGUID"}
    }
  },
  { .name = "NtReplaceKey", .num_args = 3, .args = 
    {
      {.name = "NewFile", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "TargetHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "OldFile", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"}
    }
  },
  { .name = "NtReplacePartitionUnit", .num_args = 3, .args = 
    {
      {.name = "TargetInstancePath", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "SpareInstancePath", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtReplyPort", .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ReplyMessage", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"}
    }
  },
  { .name = "NtReplyWaitReceivePortEx", .num_args = 5, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*PortContext", .dir = "out", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ReplyMessage", .dir = "in", .dir_opt = "opt", .type = "PPORT_MESSAGE"},
      {.name = "ReceiveMessage", .dir = "out", .dir_opt = "", .type = "PPORT_MESSAGE"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtReplyWaitReceivePort", .num_args = 4, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*PortContext", .dir = "out", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ReplyMessage", .dir = "in", .dir_opt = "opt", .type = "PPORT_MESSAGE"},
      {.name = "ReceiveMessage", .dir = "out", .dir_opt = "", .type = "PPORT_MESSAGE"}
    }
  },
  { .name = "NtReplyWaitReplyPort", .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ReplyMessage", .dir = "inout", .dir_opt = "", .type = "PPORT_MESSAGE"}
    }
  },
  { .name = "NtRequestPort", .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "RequestMessage", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"}
    }
  },
  { .name = "NtRequestWaitReplyPort", .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "RequestMessage", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"},
      {.name = "ReplyMessage", .dir = "out", .dir_opt = "", .type = "PPORT_MESSAGE"}
    }
  },
  { .name = "NtResetEvent", .num_args = 2, .args = 
    {
      {.name = "EventHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PreviousState", .dir = "out", .dir_opt = "opt", .type = "PLONG"}
    }
  },
  { .name = "NtResetWriteWatch", .num_args = 3, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "BaseAddress", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "RegionSize", .dir = "in", .dir_opt = "", .type = "SIZE_T"}
    }
  },
  { .name = "NtRestoreKey", .num_args = 3, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtResumeProcess", .num_args = 0  },
  { .name = "NtResumeThread", .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PreviousSuspendCount", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtRollbackComplete", .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TmVirtualClock", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtRollbackEnlistment", .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TmVirtualClock", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtRollbackTransaction", .num_args = 2, .args = 
    {
      {.name = "TransactionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Wait", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtRollforwardTransactionManager", .num_args = 2, .args = 
    {
      {.name = "TransactionManagerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TmVirtualClock", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtSaveKeyEx", .num_args = 3, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Format", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSaveKey", .num_args = 2, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"}
    }
  },
  { .name = "NtSaveMergedKeys", .num_args = 3, .args = 
    {
      {.name = "HighPrecedenceKeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "LowPrecedenceKeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"}
    }
  },
  { .name = "NtSecureConnectPort", .num_args = 9, .args = 
    {
      {.name = "PortHandle", .dir = "out", .dir_opt = "", .type = "PHANDLE"},
      {.name = "PortName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "SecurityQos", .dir = "in", .dir_opt = "", .type = "PSECURITY_QUALITY_OF_SERVICE"},
      {.name = "ClientView", .dir = "inout", .dir_opt = "opt", .type = "PPORT_VIEW"},
      {.name = "RequiredServerSid", .dir = "in", .dir_opt = "opt", .type = "PSID"},
      {.name = "ServerView", .dir = "inout", .dir_opt = "opt", .type = "PREMOTE_PORT_VIEW"},
      {.name = "MaxMessageLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"},
      {.name = "ConnectionInformation", .dir = "inout", .dir_opt = "opt", .type = "PVOID"},
      {.name = "ConnectionInformationLength", .dir = "inout", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtSerializeBoot", .num_args = 0  },
  { .name = "NtSetBootEntryOrder", .num_args = 2, .args = 
    {
      {.name = "Ids", .dir = "in", .dir_opt = "ecount(Count)", .type = "PULONG"},
      {.name = "Count", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetBootOptions", .num_args = 2, .args = 
    {
      {.name = "BootOptions", .dir = "in", .dir_opt = "", .type = "PBOOT_OPTIONS"},
      {.name = "FieldsToChange", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetContextThread", .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ThreadContext", .dir = "in", .dir_opt = "", .type = "PCONTEXT"}
    }
  },
  { .name = "NtSetDebugFilterState", .num_args = 3, .args = 
    {
      {.name = "ComponentId", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Level", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "State", .dir = "in", .dir_opt = "", .type = "BOOLEAN"}
    }
  },
  { .name = "NtSetDefaultHardErrorPort", .num_args = 0  },
  { .name = "NtSetDefaultLocale", .num_args = 2, .args = 
    {
      {.name = "UserProfile", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "DefaultLocaleId", .dir = "in", .dir_opt = "", .type = "LCID"}
    }
  },
  { .name = "NtSetDefaultUILanguage", .num_args = 0  },
  { .name = "NtSetDriverEntryOrder", .num_args = 2, .args = 
    {
      {.name = "Ids", .dir = "in", .dir_opt = "ecount(Count)", .type = "PULONG"},
      {.name = "Count", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetEaFile", .num_args = 4, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "Buffer", .dir = "in", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetEventBoostPriority", .num_args = 0  },
  { .name = "NtSetEvent", .num_args = 2, .args = 
    {
      {.name = "EventHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PreviousState", .dir = "out", .dir_opt = "opt", .type = "PLONG"}
    }
  },
  { .name = "NtSetHighEventPair", .num_args = 0  },
  { .name = "NtSetHighWaitLowEventPair", .num_args = 0  },
  { .name = "NtSetInformationDebugObject", .num_args = 5, .args = 
    {
      {.name = "DebugObjectHandle", .dir = "out", .dir_opt = "", .type = "HANDLE"},
      {.name = "DebugObjectInformationClass", .dir = "out", .dir_opt = "", .type = "DEBUGOBJECTINFOCLASS"},
      {.name = "DebugInformation", .dir = "out", .dir_opt = "", .type = "PVOID"},
      {.name = "DebugInformationLength", .dir = "out", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtSetInformationEnlistment", .num_args = 4, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "EnlistmentInformationClass", .dir = "in", .dir_opt = "", .type = "ENLISTMENT_INFORMATION_CLASS"},
      {.name = "EnlistmentInformation", .dir = "in", .dir_opt = "bcount(EnlistmentInformationLength)", .type = "PVOID"},
      {.name = "EnlistmentInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetInformationFile", .num_args = 5, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "FileInformation", .dir = "in", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "FileInformationClass", .dir = "in", .dir_opt = "", .type = "FILE_INFORMATION_CLASS"}
    }
  },
  { .name = "NtSetInformationJobObject", .num_args = 4, .args = 
    {
      {.name = "JobHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "JobObjectInformationClass", .dir = "in", .dir_opt = "", .type = "JOBOBJECTINFOCLASS"},
      {.name = "JobObjectInformation", .dir = "in", .dir_opt = "bcount(JobObjectInformationLength)", .type = "PVOID"},
      {.name = "JobObjectInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetInformationKey", .num_args = 4, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "KeySetInformationClass", .dir = "in", .dir_opt = "", .type = "KEY_SET_INFORMATION_CLASS"},
      {.name = "KeySetInformation", .dir = "in", .dir_opt = "bcount(KeySetInformationLength)", .type = "PVOID"},
      {.name = "KeySetInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetInformationObject", .num_args = 4, .args = 
    {
      {.name = "Handle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ObjectInformationClass", .dir = "in", .dir_opt = "", .type = "OBJECT_INFORMATION_CLASS"},
      {.name = "ObjectInformation", .dir = "in", .dir_opt = "bcount(ObjectInformationLength)", .type = "PVOID"},
      {.name = "ObjectInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetInformationProcess", .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ProcessInformationClass", .dir = "in", .dir_opt = "", .type = "PROCESSINFOCLASS"},
      {.name = "ProcessInformation", .dir = "in", .dir_opt = "bcount(ProcessInformationLength)", .type = "PVOID"},
      {.name = "ProcessInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetInformationResourceManager", .num_args = 4, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ResourceManagerInformationClass", .dir = "in", .dir_opt = "", .type = "RESOURCEMANAGER_INFORMATION_CLASS"},
      {.name = "ResourceManagerInformation", .dir = "in", .dir_opt = "bcount(ResourceManagerInformationLength)", .type = "PVOID"},
      {.name = "ResourceManagerInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetInformationThread", .num_args = 4, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ThreadInformationClass", .dir = "in", .dir_opt = "", .type = "THREADINFOCLASS"},
      {.name = "ThreadInformation", .dir = "in", .dir_opt = "bcount(ThreadInformationLength)", .type = "PVOID"},
      {.name = "ThreadInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetInformationToken", .num_args = 4, .args = 
    {
      {.name = "TokenHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TokenInformationClass", .dir = "in", .dir_opt = "", .type = "TOKEN_INFORMATION_CLASS"},
      {.name = "TokenInformation", .dir = "in", .dir_opt = "bcount(TokenInformationLength)", .type = "PVOID"},
      {.name = "TokenInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetInformationTransaction", .num_args = 4, .args = 
    {
      {.name = "TransactionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TransactionInformationClass", .dir = "in", .dir_opt = "", .type = "TRANSACTION_INFORMATION_CLASS"},
      {.name = "TransactionInformation", .dir = "in", .dir_opt = "bcount(TransactionInformationLength)", .type = "PVOID"},
      {.name = "TransactionInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetInformationTransactionManager", .num_args = 4, .args = 
    {
      {.name = "TmHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "TransactionManagerInformationClass", .dir = "in", .dir_opt = "", .type = "TRANSACTIONMANAGER_INFORMATION_CLASS"},
      {.name = "TransactionManagerInformation", .dir = "in", .dir_opt = "bcount(TransactionManagerInformationLength)", .type = "PVOID"},
      {.name = "TransactionManagerInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetInformationWorkerFactory", .num_args = 4, .args = 
    {
      {.name = "WorkerFactoryHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "WorkerFactoryInformationClass", .dir = "in", .dir_opt = "", .type = "WORKERFACTORYINFOCLASS"},
      {.name = "WorkerFactoryInformation", .dir = "in", .dir_opt = "bcount(WorkerFactoryInformationLength)", .type = "PVOID"},
      {.name = "WorkerFactoryInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetIntervalProfile", .num_args = 2, .args = 
    {
      {.name = "Interval", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Source", .dir = "in", .dir_opt = "", .type = "KPROFILE_SOURCE"}
    }
  },
  { .name = "NtSetIoCompletionEx", .num_args = 6, .args = 
    {
      {.name = "IoCompletionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoCompletionReserveHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "KeyContext", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatus", .dir = "in", .dir_opt = "", .type = "NTSTATUS"},
      {.name = "IoStatusInformation", .dir = "in", .dir_opt = "", .type = "ULONG_PTR"}
    }
  },
  { .name = "NtSetIoCompletion", .num_args = 5, .args = 
    {
      {.name = "IoCompletionHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "KeyContext", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatus", .dir = "in", .dir_opt = "", .type = "NTSTATUS"},
      {.name = "IoStatusInformation", .dir = "in", .dir_opt = "", .type = "ULONG_PTR"}
    }
  },
  { .name = "NtSetLdtEntries", .num_args = 6, .args = 
    {
      {.name = "Selector0", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Entry0Low", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Entry0Hi", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Selector1", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Entry1Low", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Entry1Hi", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetLowEventPair", .num_args = 0  },
  { .name = "NtSetLowWaitHighEventPair", .num_args = 0  },
  { .name = "NtSetQuotaInformationFile", .num_args = 4, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "Buffer", .dir = "in", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetSecurityObject", .num_args = 3, .args = 
    {
      {.name = "Handle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "SecurityInformation", .dir = "in", .dir_opt = "", .type = "SECURITY_INFORMATION"},
      {.name = "SecurityDescriptor", .dir = "in", .dir_opt = "", .type = "PSECURITY_DESCRIPTOR"}
    }
  },
  { .name = "NtSetSystemEnvironmentValueEx", .num_args = 5, .args = 
    {
      {.name = "VariableName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "VendorGuid", .dir = "in", .dir_opt = "", .type = "LPGUID"},
      {.name = "Value", .dir = "in", .dir_opt = "bcount_opt(ValueLength)", .type = "PVOID"},
      {.name = "ValueLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Attributes", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetSystemEnvironmentValue", .num_args = 2, .args = 
    {
      {.name = "VariableName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "VariableValue", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"}
    }
  },
  { .name = "NtSetSystemInformation", .num_args = 3, .args = 
    {
      {.name = "SystemInformationClass", .dir = "in", .dir_opt = "", .type = "SYSTEM_INFORMATION_CLASS"},
      {.name = "SystemInformation", .dir = "in", .dir_opt = "bcount_opt(SystemInformationLength)", .type = "PVOID"},
      {.name = "SystemInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetSystemPowerState", .num_args = 3, .args = 
    {
      {.name = "SystemAction", .dir = "in", .dir_opt = "", .type = "POWER_ACTION"},
      {.name = "MinSystemState", .dir = "in", .dir_opt = "", .type = "SYSTEM_POWER_STATE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetSystemTime", .num_args = 2, .args = 
    {
      {.name = "SystemTime", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"},
      {.name = "PreviousTime", .dir = "out", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtSetThreadExecutionState", .num_args = 2, .args = 
    {
      {.name = "esFlags", .dir = "in", .dir_opt = "", .type = "EXECUTION_STATE"},
      {.name = "*PreviousFlags", .dir = "out", .dir_opt = "", .type = "EXECUTION_STATE"}
    }
  },
  { .name = "NtSetTimerEx", .num_args = 4, .args = 
    {
      {.name = "TimerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TimerSetInformationClass", .dir = "in", .dir_opt = "", .type = "TIMER_SET_INFORMATION_CLASS"},
      {.name = "TimerSetInformation", .dir = "inout", .dir_opt = "bcount(TimerSetInformationLength)", .type = "PVOID"},
      {.name = "TimerSetInformationLength", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetTimer", .num_args = 7, .args = 
    {
      {.name = "TimerHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "DueTime", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"},
      {.name = "TimerApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PTIMER_APC_ROUTINE"},
      {.name = "TimerContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "WakeTimer", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "Period", .dir = "in", .dir_opt = "opt", .type = "LONG"},
      {.name = "PreviousState", .dir = "out", .dir_opt = "opt", .type = "PBOOLEAN"}
    }
  },
  { .name = "NtSetTimerResolution", .num_args = 3, .args = 
    {
      {.name = "DesiredTime", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "SetResolution", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "ActualTime", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtSetUuidSeed", .num_args = 0  },
  { .name = "NtSetValueKey", .num_args = 6, .args = 
    {
      {.name = "KeyHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ValueName", .dir = "in", .dir_opt = "", .type = "PUNICODE_STRING"},
      {.name = "TitleIndex", .dir = "in", .dir_opt = "opt", .type = "ULONG"},
      {.name = "Type", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Data", .dir = "in", .dir_opt = "bcount_opt(DataSize)", .type = "PVOID"},
      {.name = "DataSize", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtSetVolumeInformationFile", .num_args = 5, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "FsInformation", .dir = "in", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "FsInformationClass", .dir = "in", .dir_opt = "", .type = "FS_INFORMATION_CLASS"}
    }
  },
  { .name = "NtShutdownSystem", .num_args = 0  },
  { .name = "NtShutdownWorkerFactory", .num_args = 2, .args = 
    {
      {.name = "WorkerFactoryHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*PendingWorkerCount", .dir = "inout", .dir_opt = "", .type = "LONG"}
    }
  },
  { .name = "NtSignalAndWaitForSingleObject", .num_args = 4, .args = 
    {
      {.name = "SignalHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "WaitHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Alertable", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtSinglePhaseReject", .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "TmVirtualClock", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtStartProfile", .num_args = 0  },
  { .name = "NtStopProfile", .num_args = 0  },
  { .name = "NtSuspendProcess", .num_args = 0  },
  { .name = "NtSuspendThread", .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "PreviousSuspendCount", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtSystemDebugControl", .num_args = 6, .args = 
    {
      {.name = "Command", .dir = "in", .dir_opt = "", .type = "SYSDBG_COMMAND"},
      {.name = "InputBuffer", .dir = "inout", .dir_opt = "bcount_opt(InputBufferLength)", .type = "PVOID"},
      {.name = "InputBufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "OutputBuffer", .dir = "out", .dir_opt = "bcount_opt(OutputBufferLength)", .type = "PVOID"},
      {.name = "OutputBufferLength", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtTerminateJobObject", .num_args = 2, .args = 
    {
      {.name = "JobHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "ExitStatus", .dir = "in", .dir_opt = "", .type = "NTSTATUS"}
    }
  },
  { .name = "NtTerminateProcess", .num_args = 2, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ExitStatus", .dir = "in", .dir_opt = "", .type = "NTSTATUS"}
    }
  },
  { .name = "NtTerminateThread", .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ExitStatus", .dir = "in", .dir_opt = "", .type = "NTSTATUS"}
    }
  },
  { .name = "NtTestAlert", .num_args = 0  },
  { .name = "NtThawRegistry", .num_args = 0  },
  { .name = "NtThawTransactions", .num_args = 0  },
  { .name = "NtTraceControl", .num_args = 6, .args = 
    {
      {.name = "FunctionCode", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "InBuffer", .dir = "in", .dir_opt = "bcount_opt(InBufferLen)", .type = "PVOID"},
      {.name = "InBufferLen", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "OutBuffer", .dir = "out", .dir_opt = "bcount_opt(OutBufferLen)", .type = "PVOID"},
      {.name = "OutBufferLen", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ReturnLength", .dir = "out", .dir_opt = "", .type = "PULONG"}
    }
  },
  { .name = "NtTraceEvent", .num_args = 4, .args = 
    {
      {.name = "TraceHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "FieldSize", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Fields", .dir = "in", .dir_opt = "", .type = "PVOID"}
    }
  },
  { .name = "NtTranslateFilePath", .num_args = 4, .args = 
    {
      {.name = "InputFilePath", .dir = "in", .dir_opt = "", .type = "PFILE_PATH"},
      {.name = "OutputType", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "OutputFilePath", .dir = "out", .dir_opt = "bcount_opt(*OutputFilePathLength)", .type = "PFILE_PATH"},
      {.name = "OutputFilePathLength", .dir = "inout", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtUmsThreadYield", .num_args = 0  },
  { .name = "NtUnloadDriver", .num_args = 0  },
  { .name = "NtUnloadKey2", .num_args = 2, .args = 
    {
      {.name = "TargetKey", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "Flags", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtUnloadKeyEx", .num_args = 2, .args = 
    {
      {.name = "TargetKey", .dir = "in", .dir_opt = "", .type = "POBJECT_ATTRIBUTES"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"}
    }
  },
  { .name = "NtUnloadKey", .num_args = 0  },
  { .name = "NtUnlockFile", .num_args = 5, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "ByteOffset", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "PLARGE_INTEGER"},
      {.name = "Key", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtUnlockVirtualMemory", .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "*BaseAddress", .dir = "inout", .dir_opt = "", .type = "PVOID"},
      {.name = "RegionSize", .dir = "inout", .dir_opt = "", .type = "PSIZE_T"},
      {.name = "MapType", .dir = "in", .dir_opt = "", .type = "ULONG"}
    }
  },
  { .name = "NtUnmapViewOfSection", .num_args = 2, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "BaseAddress", .dir = "in", .dir_opt = "", .type = "PVOID"}
    }
  },
  { .name = "NtVdmControl", .num_args = 2, .args = 
    {
      {.name = "Service", .dir = "in", .dir_opt = "", .type = "VDMSERVICECLASS"},
      {.name = "ServiceData", .dir = "inout", .dir_opt = "", .type = "PVOID"}
    }
  },
  { .name = "NtWaitForDebugEvent", .num_args = 4, .args = 
    {
      {.name = "DebugObjectHandle", .dir = "out", .dir_opt = "", .type = "HANDLE"},
      {.name = "Alertable", .dir = "out", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "Timeout", .dir = "out", .dir_opt = "", .type = "PLARGE_INTEGER"},
      {.name = "WaitStateChange", .dir = "out", .dir_opt = "", .type = "PDBGUI_WAIT_STATE_CHANGE"}
    }
  },
  { .name = "NtWaitForKeyedEvent", .num_args = 4, .args = 
    {
      {.name = "KeyedEventHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "KeyValue", .dir = "in", .dir_opt = "", .type = "PVOID"},
      {.name = "Alertable", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtWaitForMultipleObjects32", .num_args = 5, .args = 
    {
      {.name = "Count", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Handles[]", .dir = "in", .dir_opt = "ecount(Count)", .type = "LONG"},
      {.name = "WaitType", .dir = "in", .dir_opt = "", .type = "WAIT_TYPE"},
      {.name = "Alertable", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtWaitForMultipleObjects", .num_args = 5, .args = 
    {
      {.name = "Count", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Handles[]", .dir = "in", .dir_opt = "ecount(Count)", .type = "HANDLE"},
      {.name = "WaitType", .dir = "in", .dir_opt = "", .type = "WAIT_TYPE"},
      {.name = "Alertable", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtWaitForSingleObject", .num_args = 3, .args = 
    {
      {.name = "Handle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Alertable", .dir = "in", .dir_opt = "", .type = "BOOLEAN"},
      {.name = "Timeout", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"}
    }
  },
  { .name = "NtWaitForWorkViaWorkerFactory", .num_args = 2, .args = 
    {
      {.name = "WorkerFactoryHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "MiniPacket", .dir = "out", .dir_opt = "", .type = "PFILE_IO_COMPLETION_INFORMATION"}
    }
  },
  { .name = "NtWaitHighEventPair", .num_args = 0  },
  { .name = "NtWaitLowEventPair", .num_args = 0  },
  { .name = "NtWorkerFactoryWorkerReady", .num_args = 0  },
  { .name = "NtWriteFileGather", .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PIO_APC_ROUTINE"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "SegmentArray", .dir = "in", .dir_opt = "", .type = "PFILE_SEGMENT_ELEMENT"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ByteOffset", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"},
      {.name = "Key", .dir = "in", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtWriteFile", .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Event", .dir = "in", .dir_opt = "opt", .type = "HANDLE"},
      {.name = "ApcRoutine", .dir = "in", .dir_opt = "opt", .type = "PIO_APC_ROUTINE"},
      {.name = "ApcContext", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "IoStatusBlock", .dir = "out", .dir_opt = "", .type = "PIO_STATUS_BLOCK"},
      {.name = "Buffer", .dir = "in", .dir_opt = "bcount(Length)", .type = "PVOID"},
      {.name = "Length", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "ByteOffset", .dir = "in", .dir_opt = "opt", .type = "PLARGE_INTEGER"},
      {.name = "Key", .dir = "in", .dir_opt = "opt", .type = "PULONG"}
    }
  },
  { .name = "NtWriteRequestData", .num_args = 6, .args = 
    {
      {.name = "PortHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "Message", .dir = "in", .dir_opt = "", .type = "PPORT_MESSAGE"},
      {.name = "DataEntryIndex", .dir = "in", .dir_opt = "", .type = "ULONG"},
      {.name = "Buffer", .dir = "in", .dir_opt = "bcount(BufferSize)", .type = "PVOID"},
      {.name = "BufferSize", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "NumberOfBytesWritten", .dir = "out", .dir_opt = "opt", .type = "PSIZE_T"}
    }
  },
  { .name = "NtWriteVirtualMemory", .num_args = 5, .args = 
    {
      {.name = "ProcessHandle", .dir = "in", .dir_opt = "", .type = "HANDLE"},
      {.name = "BaseAddress", .dir = "in", .dir_opt = "opt", .type = "PVOID"},
      {.name = "Buffer", .dir = "in", .dir_opt = "bcount(BufferSize)", .type = "PVOID"},
      {.name = "BufferSize", .dir = "in", .dir_opt = "", .type = "SIZE_T"},
      {.name = "NumberOfBytesWritten", .dir = "out", .dir_opt = "opt", .type = "PSIZE_T"}
    }
  },
  { .name = "NtYieldExecution", .num_args = 0 }
};


