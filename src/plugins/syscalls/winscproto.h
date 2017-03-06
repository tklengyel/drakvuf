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
 
#define NUM_SYSCALLS 406

typedef struct{
  const char* name;
  int dir;
  const char* dir_opt;
  int type;
} win_arg_t;

struct win_syscall{
  const char* name;
  int return_value;
  unsigned int num_args;
  win_arg_t args[20];
};

struct syscall_wrapper{
  syscalls *sc;
  int syscall_index;
};

typedef struct syscall_wrapper syscall_wrapper_t;

enum { in, out, inout, reserved, missing } direction;

enum {
  ACCESS_MASK,
  ALPC_HANDLE,
  ALPC_MESSAGE_INFORMATION_CLASS,
  ALPC_PORT_INFORMATION_CLASS,
  APPHELPCOMMAND,
  ATOM_INFORMATION_CLASS,
  AUDIT_EVENT_TYPE,
  BOOLEAN,
  DEBUGOBJECTINFOCLASS,
  DEVICE_POWER_STATE,
  ENLISTMENT_INFORMATION_CLASS,
  EVENT_INFORMATION_CLASS,
  EVENT_TYPE,
  EXECUTION_STATE,
  FILE_INFORMATION_CLASS,
  FS_INFORMATION_CLASS,
  HANDLE,
  IO_COMPLETION_INFORMATION_CLASS,
  IO_SESSION_STATE,
  JOBOBJECTINFOCLASS,
  KAFFINITY,
  KEY_INFORMATION_CLASS,
  KEY_SET_INFORMATION_CLASS,
  KEY_VALUE_INFORMATION_CLASS,
  KPROFILE_SOURCE,
  KTMOBJECT_TYPE,
  LANGID,
  LCID,
  LONG,
  LPGUID,
  MEMORY_INFORMATION_CLASS,
  MEMORY_RESERVE_TYPE,
  MISSING,
  MUTANT_INFORMATION_CLASS,
  NOTIFICATION_MASK,
  NTAPI,
  NTSTATUS,
  OBJECT_ATTRIBUTES,
  OBJECT_INFORMATION_CLASS,
  PACCESS_MASK,
  PALPC_CONTEXT_ATTR,
  PALPC_DATA_VIEW_ATTR,
  PALPC_HANDLE,
  PALPC_MESSAGE_ATTRIBUTES,
  PALPC_PORT_ATTRIBUTES,
  PALPC_SECURITY_ATTR,
  PBOOLEAN,
  PBOOT_ENTRY,
  PBOOT_OPTIONS,
  PCHAR,
  PCLIENT_ID,
  PCONTEXT,
  PCRM_PROTOCOL_ID,
  PDBGUI_WAIT_STATE_CHANGE,
  PEFI_DRIVER_ENTRY,
  PEXCEPTION_RECORD,
  PFILE_BASIC_INFORMATION,
  PFILE_IO_COMPLETION_INFORMATION,
  PFILE_NETWORK_OPEN_INFORMATION,
  PFILE_PATH,
  PFILE_SEGMENT_ELEMENT,
  PGENERIC_MAPPING,
  PGROUP_AFFINITY,
  PHANDLE,
  PINITIAL_TEB,
  PIO_APC_ROUTINE,
  PIO_STATUS_BLOCK,
  PJOB_SET_ARRAY,
  PKEY_VALUE_ENTRY,
  PKTMOBJECT_CURSOR,
  PLARGE_INTEGER,
  PLCID,
  PLONG,
  PLUGPLAY_CONTROL_CLASS,
  PLUID,
  PNTSTATUS,
  POBJECT_ATTRIBUTES,
  POBJECT_TYPE_LIST,
  PORT_INFORMATION_CLASS,
  POWER_ACTION,
  POWER_INFORMATION_LEVEL,
  PPLUGPLAY_EVENT_BLOCK,
  PPORT_MESSAGE,
  PPORT_VIEW,
  PPRIVILEGE_SET,
  PPROCESS_ATTRIBUTE_LIST,
  PPROCESS_CREATE_INFO,
  PPS_APC_ROUTINE,
  PPS_ATTRIBUTE_LIST,
  PREMOTE_PORT_VIEW,
  PROCESSINFOCLASS,
  PRTL_ATOM,
  PRTL_USER_PROCESS_PARAMETERS,
  PSECURITY_DESCRIPTOR,
  PSECURITY_QUALITY_OF_SERVICE,
  PSID,
  PSIZE_T,
  PTIMER_APC_ROUTINE,
  PTOKEN_DEFAULT_DACL,
  PTOKEN_GROUPS,
  PTOKEN_OWNER,
  PTOKEN_PRIMARY_GROUP,
  PTOKEN_PRIVILEGES,
  PTOKEN_SOURCE,
  PTOKEN_USER,
  PTRANSACTION_NOTIFICATION,
  PULARGE_INTEGER,
  PULONG,
  PULONG_PTR,
  PUNICODE_STRING,
  PUSHORT,
  PVOID,
  PWSTR,
  RESOURCEMANAGER_INFORMATION_CLASS,
  RTL_ATOM,
  SECTION_INFORMATION_CLASS,
  SECTION_INHERIT,
  SECURITY_INFORMATION,
  SEMAPHORE_INFORMATION_CLASS,
  SHUTDOWN_ACTION,
  SIZE_T,
  SYSDBG_COMMAND,
  SYSTEM_INFORMATION_CLASS,
  SYSTEM_POWER_STATE,
  THREADINFOCLASS,
  TIMER_INFORMATION_CLASS,
  TIMER_SET_INFORMATION_CLASS,
  TIMER_TYPE,
  TOKEN_INFORMATION_CLASS,
  TOKEN_TYPE,
  TRANSACTIONMANAGER_INFORMATION_CLASS,
  TRANSACTION_INFORMATION_CLASS,
  ULONG,
  ULONG_PTR,
  USHORT,
  VDMSERVICECLASS,
  VOID,
  WAIT_TYPE,
  WIN32_PROTECTION_MASK,
  WINAPI,
  WORKERFACTORYINFOCLASS } types; 

static const struct win_syscall win_syscall_struct[] = {
  { .name = "NtFlushProcessWriteBuffers", .return_value = NTAPI, .num_args = 0  },
  { .name = "NtGetCurrentProcessorNumber", .return_value = WINAPI, .num_args = 0  },
  { .name = "NtGetEnvironmentVariableEx", .return_value = MISSING, .num_args = 1, .args = 
    {
      {.name = "Missing", .dir = missing, .dir_opt = "", .type = MISSING}
    }
  },
  { .name = "NtIsSystemResumeAutomatic", .return_value = MISSING, .num_args = 1, .args = 
    {
      {.name = "Missing", .dir = missing, .dir_opt = "", .type = MISSING}
    }
  },
  { .name = "NtQueryEnvironmentVariableInfoEx", .return_value = MISSING, .num_args = 1, .args = 
    {
      {.name = "Missing", .dir = missing, .dir_opt = "", .type = MISSING}
    }
  },
  { .name = "NtAcceptConnectPort", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "PortHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "PortContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ConnectionRequest", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE},
      {.name = "AcceptConnection", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "ServerView", .dir = inout, .dir_opt = "opt", .type = PPORT_VIEW},
      {.name = "ClientView", .dir = out, .dir_opt = "opt", .type = PREMOTE_PORT_VIEW}
    }
  },
  { .name = "NtAccessCheckAndAuditAlarm", .return_value = NTSTATUS, .num_args = 11, .args = 
    {
      {.name = "SubsystemName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "HandleId", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ObjectTypeName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "ObjectName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "SecurityDescriptor", .dir = in, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "GenericMapping", .dir = in, .dir_opt = "", .type = PGENERIC_MAPPING},
      {.name = "ObjectCreation", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "GrantedAccess", .dir = out, .dir_opt = "", .type = PACCESS_MASK},
      {.name = "AccessStatus", .dir = out, .dir_opt = "", .type = PNTSTATUS},
      {.name = "GenerateOnClose", .dir = out, .dir_opt = "", .type = PBOOLEAN}
    }
  },
  { .name = "NtAccessCheckByTypeAndAuditAlarm", .return_value = NTSTATUS, .num_args = 16, .args = 
    {
      {.name = "SubsystemName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "HandleId", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ObjectTypeName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "ObjectName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "SecurityDescriptor", .dir = in, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
      {.name = "PrincipalSelfSid", .dir = in, .dir_opt = "opt", .type = PSID},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "AuditType", .dir = in, .dir_opt = "", .type = AUDIT_EVENT_TYPE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ObjectTypeList", .dir = in, .dir_opt = "ecount_opt(ObjectTypeListLength)", .type = POBJECT_TYPE_LIST},
      {.name = "ObjectTypeListLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "GenericMapping", .dir = in, .dir_opt = "", .type = PGENERIC_MAPPING},
      {.name = "ObjectCreation", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "GrantedAccess", .dir = out, .dir_opt = "", .type = PACCESS_MASK},
      {.name = "AccessStatus", .dir = out, .dir_opt = "", .type = PNTSTATUS},
      {.name = "GenerateOnClose", .dir = out, .dir_opt = "", .type = PBOOLEAN}
    }
  },
  { .name = "NtAccessCheckByType", .return_value = NTSTATUS, .num_args = 11, .args = 
    {
      {.name = "SecurityDescriptor", .dir = in, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
      {.name = "PrincipalSelfSid", .dir = in, .dir_opt = "opt", .type = PSID},
      {.name = "ClientToken", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectTypeList", .dir = in, .dir_opt = "ecount(ObjectTypeListLength)", .type = POBJECT_TYPE_LIST},
      {.name = "ObjectTypeListLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "GenericMapping", .dir = in, .dir_opt = "", .type = PGENERIC_MAPPING},
      {.name = "PrivilegeSet", .dir = out, .dir_opt = "bcount(*PrivilegeSetLength)", .type = PPRIVILEGE_SET},
      {.name = "PrivilegeSetLength", .dir = inout, .dir_opt = "", .type = PULONG},
      {.name = "GrantedAccess", .dir = out, .dir_opt = "", .type = PACCESS_MASK},
      {.name = "AccessStatus", .dir = out, .dir_opt = "", .type = PNTSTATUS}
    }
  },
  { .name = "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", .return_value = NTSTATUS, .num_args = 17, .args = 
    {
      {.name = "SubsystemName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "HandleId", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ClientToken", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ObjectTypeName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "ObjectName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "SecurityDescriptor", .dir = in, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
      {.name = "PrincipalSelfSid", .dir = in, .dir_opt = "opt", .type = PSID},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "AuditType", .dir = in, .dir_opt = "", .type = AUDIT_EVENT_TYPE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ObjectTypeList", .dir = in, .dir_opt = "ecount_opt(ObjectTypeListLength)", .type = POBJECT_TYPE_LIST},
      {.name = "ObjectTypeListLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "GenericMapping", .dir = in, .dir_opt = "", .type = PGENERIC_MAPPING},
      {.name = "ObjectCreation", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "GrantedAccess", .dir = out, .dir_opt = "ecount(ObjectTypeListLength)", .type = PACCESS_MASK},
      {.name = "AccessStatus", .dir = out, .dir_opt = "ecount(ObjectTypeListLength)", .type = PNTSTATUS},
      {.name = "GenerateOnClose", .dir = out, .dir_opt = "", .type = PBOOLEAN}
    }
  },
  { .name = "NtAccessCheckByTypeResultListAndAuditAlarm", .return_value = NTSTATUS, .num_args = 16, .args = 
    {
      {.name = "SubsystemName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "HandleId", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ObjectTypeName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "ObjectName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "SecurityDescriptor", .dir = in, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
      {.name = "PrincipalSelfSid", .dir = in, .dir_opt = "opt", .type = PSID},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "AuditType", .dir = in, .dir_opt = "", .type = AUDIT_EVENT_TYPE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ObjectTypeList", .dir = in, .dir_opt = "ecount_opt(ObjectTypeListLength)", .type = POBJECT_TYPE_LIST},
      {.name = "ObjectTypeListLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "GenericMapping", .dir = in, .dir_opt = "", .type = PGENERIC_MAPPING},
      {.name = "ObjectCreation", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "GrantedAccess", .dir = out, .dir_opt = "ecount(ObjectTypeListLength)", .type = PACCESS_MASK},
      {.name = "AccessStatus", .dir = out, .dir_opt = "ecount(ObjectTypeListLength)", .type = PNTSTATUS},
      {.name = "GenerateOnClose", .dir = out, .dir_opt = "", .type = PBOOLEAN}
    }
  },
  { .name = "NtAccessCheckByTypeResultList", .return_value = NTSTATUS, .num_args = 11, .args = 
    {
      {.name = "SecurityDescriptor", .dir = in, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
      {.name = "PrincipalSelfSid", .dir = in, .dir_opt = "opt", .type = PSID},
      {.name = "ClientToken", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectTypeList", .dir = in, .dir_opt = "ecount(ObjectTypeListLength)", .type = POBJECT_TYPE_LIST},
      {.name = "ObjectTypeListLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "GenericMapping", .dir = in, .dir_opt = "", .type = PGENERIC_MAPPING},
      {.name = "PrivilegeSet", .dir = out, .dir_opt = "bcount(*PrivilegeSetLength)", .type = PPRIVILEGE_SET},
      {.name = "PrivilegeSetLength", .dir = inout, .dir_opt = "", .type = PULONG},
      {.name = "GrantedAccess", .dir = out, .dir_opt = "ecount(ObjectTypeListLength)", .type = PACCESS_MASK},
      {.name = "AccessStatus", .dir = out, .dir_opt = "ecount(ObjectTypeListLength)", .type = PNTSTATUS}
    }
  },
  { .name = "NtAccessCheck", .return_value = NTSTATUS, .num_args = 8, .args = 
    {
      {.name = "SecurityDescriptor", .dir = in, .dir_opt = "", .type = PSECURITY_DESCRIPTOR},
      {.name = "ClientToken", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "GenericMapping", .dir = in, .dir_opt = "", .type = PGENERIC_MAPPING},
      {.name = "PrivilegeSet", .dir = out, .dir_opt = "bcount(*PrivilegeSetLength)", .type = PPRIVILEGE_SET},
      {.name = "PrivilegeSetLength", .dir = inout, .dir_opt = "", .type = PULONG},
      {.name = "GrantedAccess", .dir = out, .dir_opt = "", .type = PACCESS_MASK},
      {.name = "AccessStatus", .dir = out, .dir_opt = "", .type = PNTSTATUS}
    }
  },
  { .name = "NtAddAtom", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "AtomName", .dir = in, .dir_opt = "bcount_opt(Length)", .type = PWSTR},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Atom", .dir = out, .dir_opt = "opt", .type = PRTL_ATOM}
    }
  },
  { .name = "NtAddBootEntry", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "BootEntry", .dir = in, .dir_opt = "", .type = PBOOT_ENTRY},
      {.name = "Id", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtAddDriverEntry", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "DriverEntry", .dir = in, .dir_opt = "", .type = PEFI_DRIVER_ENTRY},
      {.name = "Id", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtAdjustGroupsToken", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "TokenHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ResetToDefault", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "NewState", .dir = in, .dir_opt = "", .type = PTOKEN_GROUPS},
      {.name = "BufferLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "PreviousState", .dir = out, .dir_opt = "bcount_part_opt(BufferLength,*ReturnLength)", .type = PTOKEN_GROUPS},
      {.name = "ReturnLength", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtAdjustPrivilegesToken", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "TokenHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DisableAllPrivileges", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "NewState", .dir = in, .dir_opt = "opt", .type = PTOKEN_PRIVILEGES},
      {.name = "BufferLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "PreviousState", .dir = out, .dir_opt = "bcount_part_opt(BufferLength,*ReturnLength)", .type = PTOKEN_PRIVILEGES},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtAlertResumeThread", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PreviousSuspendCount", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtAlertThread", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtAllocateLocallyUniqueId", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "Luid", .dir = out, .dir_opt = "", .type = PLUID}
    }
  },
  { .name = "NtAllocateReserveObject", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "MemoryReserveHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "Type", .dir = in, .dir_opt = "", .type = MEMORY_RESERVE_TYPE}
    }
  },
  { .name = "NtAllocateUserPhysicalPages", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "NumberOfPages", .dir = inout, .dir_opt = "", .type = PULONG_PTR},
      {.name = "UserPfnArra;", .dir = out, .dir_opt = "ecount(*NumberOfPages)", .type = PULONG_PTR}
    }
  },
  { .name = "NtAllocateUuids", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "Time", .dir = out, .dir_opt = "", .type = PULARGE_INTEGER},
      {.name = "Range", .dir = out, .dir_opt = "", .type = PULONG},
      {.name = "Sequence", .dir = out, .dir_opt = "", .type = PULONG},
      {.name = "Seed", .dir = out, .dir_opt = "", .type = PCHAR}
    }
  },
  { .name = "NtAllocateVirtualMemory", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*BaseAddress", .dir = inout, .dir_opt = "", .type = PVOID},
      {.name = "ZeroBits", .dir = in, .dir_opt = "", .type = ULONG_PTR},
      {.name = "RegionSize", .dir = inout, .dir_opt = "", .type = PSIZE_T},
      {.name = "AllocationType", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Protect", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtAlpcAcceptConnectPort", .return_value = NTSTATUS, .num_args = 9, .args = 
    {
      {.name = "PortHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "ConnectionPortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "PortAttributes", .dir = in, .dir_opt = "", .type = PALPC_PORT_ATTRIBUTES},
      {.name = "PortContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ConnectionRequest", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE},
      {.name = "ConnectionMessageAttributes", .dir = inout, .dir_opt = "opt", .type = PALPC_MESSAGE_ATTRIBUTES},
      {.name = "AcceptConnection", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtAlpcCancelMessage", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "MessageContext", .dir = in, .dir_opt = "", .type = PALPC_CONTEXT_ATTR}
    }
  },
  { .name = "NtAlpcConnectPort", .return_value = NTSTATUS, .num_args = 11, .args = 
    {
      {.name = "PortHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "PortName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "PortAttributes", .dir = in, .dir_opt = "opt", .type = PALPC_PORT_ATTRIBUTES},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "RequiredServerSid", .dir = in, .dir_opt = "opt", .type = PSID},
      {.name = "ConnectionMessage", .dir = inout, .dir_opt = "", .type = PPORT_MESSAGE},
      {.name = "BufferLength", .dir = inout, .dir_opt = "opt", .type = PULONG},
      {.name = "OutMessageAttributes", .dir = inout, .dir_opt = "opt", .type = PALPC_MESSAGE_ATTRIBUTES},
      {.name = "InMessageAttributes", .dir = inout, .dir_opt = "opt", .type = PALPC_MESSAGE_ATTRIBUTES},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtAlpcCreatePort", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "PortAttributes", .dir = in, .dir_opt = "opt", .type = PALPC_PORT_ATTRIBUTES}
    }
  },
  { .name = "NtAlpcCreatePortSection", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "SectionHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "SectionSize", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "AlpcSectionHandle", .dir = out, .dir_opt = "", .type = PALPC_HANDLE},
      {.name = "ActualSectionSize", .dir = out, .dir_opt = "", .type = PSIZE_T}
    }
  },
  { .name = "NtAlpcCreateResourceReserve", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "MessageSize", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "ResourceId", .dir = out, .dir_opt = "", .type = PALPC_HANDLE}
    }
  },
  { .name = "NtAlpcCreateSectionView", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "ViewAttributes", .dir = inout, .dir_opt = "", .type = PALPC_DATA_VIEW_ATTR}
    }
  },
  { .name = "NtAlpcCreateSecurityContext", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "SecurityAttribute", .dir = inout, .dir_opt = "", .type = PALPC_SECURITY_ATTR}
    }
  },
  { .name = "NtAlpcDeletePortSection", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "SectionHandle", .dir = in, .dir_opt = "", .type = ALPC_HANDLE}
    }
  },
  { .name = "NtAlpcDeleteResourceReserve", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "ResourceId", .dir = in, .dir_opt = "", .type = ALPC_HANDLE}
    }
  },
  { .name = "NtAlpcDeleteSectionView", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "ViewBase", .dir = in, .dir_opt = "", .type = PVOID}
    }
  },
  { .name = "NtAlpcDeleteSecurityContext", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "ContextHandle", .dir = in, .dir_opt = "", .type = ALPC_HANDLE}
    }
  },
  { .name = "NtAlpcDisconnectPort", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtAlpcImpersonateClientOfPort", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PortMessage", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE},
      {.name = "Reserved", .dir = reserved, .dir_opt = "", .type = PVOID}
    }
  },
  { .name = "NtAlpcOpenSenderProcess", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "ProcessHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PortMessage", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE},
      {.name = "Flags", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtAlpcOpenSenderThread", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "ThreadHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PortMessage", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE},
      {.name = "Flags", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtAlpcQueryInformation", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PortInformationClass", .dir = in, .dir_opt = "", .type = ALPC_PORT_INFORMATION_CLASS},
      {.name = "PortInformation", .dir = out, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtAlpcQueryInformationMessage", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PortMessage", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE},
      {.name = "MessageInformationClass", .dir = in, .dir_opt = "", .type = ALPC_MESSAGE_INFORMATION_CLASS},
      {.name = "MessageInformation", .dir = out, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtAlpcRevokeSecurityContext", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "ContextHandle", .dir = in, .dir_opt = "", .type = ALPC_HANDLE}
    }
  },
  { .name = "NtAlpcSendWaitReceivePort", .return_value = NTSTATUS, .num_args = 8, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "SendMessage", .dir = in, .dir_opt = "opt", .type = PPORT_MESSAGE},
      {.name = "SendMessageAttributes", .dir = in, .dir_opt = "opt", .type = PALPC_MESSAGE_ATTRIBUTES},
      {.name = "ReceiveMessage", .dir = inout, .dir_opt = "opt", .type = PPORT_MESSAGE},
      {.name = "BufferLength", .dir = inout, .dir_opt = "opt", .type = PULONG},
      {.name = "ReceiveMessageAttributes", .dir = inout, .dir_opt = "opt", .type = PALPC_MESSAGE_ATTRIBUTES},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtAlpcSetInformation", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PortInformationClass", .dir = in, .dir_opt = "", .type = ALPC_PORT_INFORMATION_CLASS},
      {.name = "PortInformation", .dir = in, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtApphelpCacheControl", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "type", .dir = in, .dir_opt = "", .type = APPHELPCOMMAND},
      {.name = "buf", .dir = in, .dir_opt = "", .type = PVOID}
    }
  },
  { .name = "NtAreMappedFilesTheSame", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "File1MappedAsAnImage", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "File2MappedAsFile", .dir = in, .dir_opt = "", .type = PVOID}
    }
  },
  { .name = "NtAssignProcessToJobObject", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "JobHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtCallbackReturn", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "OutputBuffer", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "OutputLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Status", .dir = in, .dir_opt = "", .type = NTSTATUS}
    }
  },
  { .name = "NtCancelIoFileEx", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoRequestToCancel", .dir = in, .dir_opt = "opt", .type = PIO_STATUS_BLOCK},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK}
    }
  },
  { .name = "NtCancelIoFile", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK}
    }
  },
  { .name = "NtCancelSynchronousIoFile", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoRequestToCancel", .dir = in, .dir_opt = "opt", .type = PIO_STATUS_BLOCK},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK}
    }
  },
  { .name = "NtCancelTimer", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "TimerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "CurrentState", .dir = out, .dir_opt = "opt", .type = PBOOLEAN}
    }
  },
  { .name = "NtClearEvent", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "EventHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtClose", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "Handle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtCloseObjectAuditAlarm", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "SubsystemName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "HandleId", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "GenerateOnClose", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtCommitComplete", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TmVirtualClock", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtCommitEnlistment", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TmVirtualClock", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtCommitTransaction", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "TransactionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Wait", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtCompactKeys", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "Count", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "KeyArray[;", .dir = in, .dir_opt = "ecount(Count)", .type = HANDLE}
    }
  },
  { .name = "NtCompareTokens", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "FirstTokenHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "SecondTokenHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Equal", .dir = out, .dir_opt = "", .type = PBOOLEAN}
    }
  },
  { .name = "NtCompleteConnectPort", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtCompressKey", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "Key", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtConnectPort", .return_value = NTSTATUS, .num_args = 8, .args = 
    {
      {.name = "PortHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "PortName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "SecurityQos", .dir = in, .dir_opt = "", .type = PSECURITY_QUALITY_OF_SERVICE},
      {.name = "ClientView", .dir = inout, .dir_opt = "opt", .type = PPORT_VIEW},
      {.name = "ServerView", .dir = inout, .dir_opt = "opt", .type = PREMOTE_PORT_VIEW},
      {.name = "MaxMessageLength", .dir = out, .dir_opt = "opt", .type = PULONG},
      {.name = "ConnectionInformation", .dir = inout, .dir_opt = "opt", .type = PVOID},
      {.name = "ConnectionInformationLength", .dir = inout, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtContinue", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ContextRecord", .dir = out, .dir_opt = "", .type = PCONTEXT},
      {.name = "TestAlert", .dir = out, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtCreateDebugObject", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "DebugObjectHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = out, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = out, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "Flags", .dir = out, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtCreateDirectoryObject", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "DirectoryHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtCreateEnlistment", .return_value = NTSTATUS, .num_args = 8, .args = 
    {
      {.name = "EnlistmentHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ResourceManagerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TransactionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "CreateOptions", .dir = in, .dir_opt = "opt", .type = ULONG},
      {.name = "NotificationMask", .dir = in, .dir_opt = "", .type = NOTIFICATION_MASK},
      {.name = "EnlistmentKey", .dir = in, .dir_opt = "opt", .type = PVOID}
    }
  },
  { .name = "NtCreateEvent", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "EventHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "EventType", .dir = in, .dir_opt = "", .type = EVENT_TYPE},
      {.name = "InitialState", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtCreateEventPair", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "EventPairHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtCreateFile", .return_value = NTSTATUS, .num_args = 11, .args = 
    {
      {.name = "FileHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "AllocationSize", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER},
      {.name = "FileAttributes", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ShareAccess", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "CreateDisposition", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "CreateOptions", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "EaBuffer", .dir = in, .dir_opt = "bcount_opt(EaLength)", .type = PVOID},
      {.name = "EaLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtCreateIoCompletion", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "IoCompletionHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "Count", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtCreateJobObject", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "JobHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtCreateJobSet", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "NumJob", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "UserJobSet", .dir = in, .dir_opt = "ecount(NumJob)", .type = PJOB_SET_ARRAY},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtCreateKeyedEvent", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "KeyedEventHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtCreateKey", .return_value = NTSTATUS, .num_args = 7, .args = 
    {
      {.name = "KeyHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "TitleIndex", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "Class", .dir = in, .dir_opt = "opt", .type = PUNICODE_STRING},
      {.name = "CreateOptions", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Disposition", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtCreateKeyTransacted", .return_value = NTSTATUS, .num_args = 8, .args = 
    {
      {.name = "KeyHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "TitleIndex", .dir = reserved, .dir_opt = "", .type = ULONG},
      {.name = "Class", .dir = in, .dir_opt = "opt", .type = PUNICODE_STRING},
      {.name = "CreateOptions", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "TransactionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Disposition", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtCreateMailslotFile", .return_value = NTSTATUS, .num_args = 8, .args = 
    {
      {.name = "FileHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "CreateOptions", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "MailslotQuota", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "MaximumMessageSize", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReadTimeout", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtCreateMutant", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "MutantHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "InitialOwner", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtCreateNamedPipeFile", .return_value = NTSTATUS, .num_args = 14, .args = 
    {
      {.name = "FileHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "ShareAccess", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "CreateDisposition", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "CreateOptions", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "NamedPipeType", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReadMode", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "CompletionMode", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "MaximumInstances", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "InboundQuota", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "OutboundQuota", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "DefaultTimeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtCreatePagingFile", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "PageFileName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "MinimumSize", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER},
      {.name = "MaximumSize", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER},
      {.name = "Priority", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtCreatePort", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "PortHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "MaxConnectionInfoLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "MaxMessageLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "MaxPoolUsage", .dir = in, .dir_opt = "opt", .type = ULONG}
    }
  },
  { .name = "NtCreatePrivateNamespace", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "NamespaceHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "BoundaryDescriptor", .dir = in, .dir_opt = "", .type = PVOID}
    }
  },
  { .name = "NtCreateProcessEx", .return_value = NTSTATUS, .num_args = 9, .args = 
    {
      {.name = "ProcessHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "ParentProcess", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "SectionHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "DebugPort", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ExceptionPort", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "JobMemberLevel", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtCreateProcess", .return_value = NTSTATUS, .num_args = 8, .args = 
    {
      {.name = "ProcessHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "ParentProcess", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "InheritObjectTable", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "SectionHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "DebugPort", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ExceptionPort", .dir = in, .dir_opt = "opt", .type = HANDLE}
    }
  },
  { .name = "NtCreateProfileEx", .return_value = NTSTATUS, .num_args = 10, .args = 
    {
      {.name = "ProfileHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "Process", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ProfileBase", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "ProfileSize", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "BucketSize", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Buffer", .dir = in, .dir_opt = "", .type = PULONG},
      {.name = "BufferSize", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ProfileSource", .dir = in, .dir_opt = "", .type = KPROFILE_SOURCE},
      {.name = "GroupAffinityCount", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "GroupAffinity", .dir = in, .dir_opt = "opt", .type = PGROUP_AFFINITY}
    }
  },
  { .name = "NtCreateProfile", .return_value = NTSTATUS, .num_args = 9, .args = 
    {
      {.name = "ProfileHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "Process", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "RangeBase", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "RangeSize", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "BucketSize", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Buffer", .dir = in, .dir_opt = "", .type = PULONG},
      {.name = "BufferSize", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ProfileSource", .dir = in, .dir_opt = "", .type = KPROFILE_SOURCE},
      {.name = "Affinity", .dir = in, .dir_opt = "", .type = KAFFINITY}
    }
  },
  { .name = "NtCreateResourceManager", .return_value = NTSTATUS, .num_args = 7, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "TmHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "RmGuid", .dir = in, .dir_opt = "", .type = LPGUID},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "CreateOptions", .dir = in, .dir_opt = "opt", .type = ULONG},
      {.name = "Description", .dir = in, .dir_opt = "opt", .type = PUNICODE_STRING}
    }
  },
  { .name = "NtCreateSection", .return_value = NTSTATUS, .num_args = 7, .args = 
    {
      {.name = "SectionHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "MaximumSize", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER},
      {.name = "SectionPageProtection", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "AllocationAttributes", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "FileHandle", .dir = in, .dir_opt = "opt", .type = HANDLE}
    }
  },
  { .name = "NtCreateSemaphore", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "SemaphoreHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "InitialCount", .dir = in, .dir_opt = "", .type = LONG},
      {.name = "MaximumCount", .dir = in, .dir_opt = "", .type = LONG}
    }
  },
  { .name = "NtCreateSymbolicLinkObject", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "LinkHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "LinkTarget", .dir = in, .dir_opt = "", .type = PUNICODE_STRING}
    }
  },
  { .name = "NtCreateThreadEx", .return_value = NTSTATUS, .num_args = 11, .args = 
    {
      {.name = "ThreadHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "StartRoutine", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "Argument", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "CreateFlags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ZeroBits", .dir = in, .dir_opt = "opt", .type = ULONG_PTR},
      {.name = "StackSize", .dir = in, .dir_opt = "opt", .type = SIZE_T},
      {.name = "MaximumStackSize", .dir = in, .dir_opt = "opt", .type = SIZE_T},
      {.name = "AttributeList", .dir = in, .dir_opt = "opt", .type = PPS_ATTRIBUTE_LIST}
    }
  },
  { .name = "NtCreateThread", .return_value = NTSTATUS, .num_args = 8, .args = 
    {
      {.name = "ThreadHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ClientId", .dir = out, .dir_opt = "", .type = PCLIENT_ID},
      {.name = "ThreadContext", .dir = in, .dir_opt = "", .type = PCONTEXT},
      {.name = "InitialTeb", .dir = in, .dir_opt = "", .type = PINITIAL_TEB},
      {.name = "CreateSuspended", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtCreateTimer", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "TimerHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "TimerType", .dir = in, .dir_opt = "", .type = TIMER_TYPE}
    }
  },
  { .name = "NtCreateToken", .return_value = NTSTATUS, .num_args = 13, .args = 
    {
      {.name = "TokenHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "TokenType", .dir = in, .dir_opt = "", .type = TOKEN_TYPE},
      {.name = "AuthenticationId", .dir = in, .dir_opt = "", .type = PLUID},
      {.name = "ExpirationTime", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER},
      {.name = "User", .dir = in, .dir_opt = "", .type = PTOKEN_USER},
      {.name = "Groups", .dir = in, .dir_opt = "", .type = PTOKEN_GROUPS},
      {.name = "Privileges", .dir = in, .dir_opt = "", .type = PTOKEN_PRIVILEGES},
      {.name = "Owner", .dir = in, .dir_opt = "opt", .type = PTOKEN_OWNER},
      {.name = "PrimaryGroup", .dir = in, .dir_opt = "", .type = PTOKEN_PRIMARY_GROUP},
      {.name = "DefaultDacl", .dir = in, .dir_opt = "opt", .type = PTOKEN_DEFAULT_DACL},
      {.name = "TokenSource", .dir = in, .dir_opt = "", .type = PTOKEN_SOURCE}
    }
  },
  { .name = "NtCreateTransactionManager", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "TmHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "LogFileName", .dir = in, .dir_opt = "opt", .type = PUNICODE_STRING},
      {.name = "CreateOptions", .dir = in, .dir_opt = "opt", .type = ULONG},
      {.name = "CommitStrength", .dir = in, .dir_opt = "opt", .type = ULONG}
    }
  },
  { .name = "NtCreateTransaction", .return_value = NTSTATUS, .num_args = 10, .args = 
    {
      {.name = "TransactionHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "Uow", .dir = in, .dir_opt = "opt", .type = LPGUID},
      {.name = "TmHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "CreateOptions", .dir = in, .dir_opt = "opt", .type = ULONG},
      {.name = "IsolationLevel", .dir = in, .dir_opt = "opt", .type = ULONG},
      {.name = "IsolationFlags", .dir = in, .dir_opt = "opt", .type = ULONG},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER},
      {.name = "Description", .dir = in, .dir_opt = "opt", .type = PUNICODE_STRING}
    }
  },
  { .name = "NtCreateUserProcess", .return_value = NTSTATUS, .num_args = 11, .args = 
    {
      {.name = "ProcessHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "ThreadHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "ProcessDesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ThreadDesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ProcessObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "ThreadObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "ProcessFlags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ThreadFlags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ProcessParameters", .dir = in, .dir_opt = "opt", .type = PRTL_USER_PROCESS_PARAMETERS},
      {.name = "CreateInfo", .dir = in, .dir_opt = "opt", .type = PPROCESS_CREATE_INFO},
      {.name = "AttributeList", .dir = in, .dir_opt = "opt", .type = PPROCESS_ATTRIBUTE_LIST}
    }
  },
  { .name = "NtCreateWaitablePort", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "PortHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "MaxConnectionInfoLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "MaxMessageLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "MaxPoolUsage", .dir = in, .dir_opt = "opt", .type = ULONG}
    }
  },
  { .name = "NtCreateWorkerFactory", .return_value = NTSTATUS, .num_args = 10, .args = 
    {
      {.name = "WorkerFactoryHandleReturn", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "CompletionPortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "WorkerProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "StartRoutine", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "StartParameter", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "MaxThreadCount", .dir = in, .dir_opt = "opt", .type = ULONG},
      {.name = "StackReserve", .dir = in, .dir_opt = "opt", .type = SIZE_T},
      {.name = "StackCommit", .dir = in, .dir_opt = "opt", .type = SIZE_T}
    }
  },
  { .name = "NtDebugActiveProcess", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ProcessHandle", .dir = out, .dir_opt = "", .type = HANDLE},
      {.name = "DebugObjectHandle", .dir = out, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtDebugContinue", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "DebugObjectHandle", .dir = out, .dir_opt = "", .type = HANDLE},
      {.name = "ClientId", .dir = out, .dir_opt = "", .type = PCLIENT_ID},
      {.name = "ContinueStatus", .dir = out, .dir_opt = "", .type = NTSTATUS}
    }
  },
  { .name = "NtDelayExecution", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "Alertable", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "DelayInterval", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtDeleteAtom", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "Atom", .dir = in, .dir_opt = "", .type = RTL_ATOM}
    }
  },
  { .name = "NtDeleteBootEntry", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "Id", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtDeleteDriverEntry", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "Id", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtDeleteFile", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtDeleteKey", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtDeleteObjectAuditAlarm", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "SubsystemName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "HandleId", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "GenerateOnClose", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtDeletePrivateNamespace", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "NamespaceHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtDeleteValueKey", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ValueName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING}
    }
  },
  { .name = "NtDeviceIoControlFile", .return_value = NTSTATUS, .num_args = 10, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "IoControlCode", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "InputBuffer", .dir = in, .dir_opt = "bcount_opt(InputBufferLength)", .type = PVOID},
      {.name = "InputBufferLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "OutputBuffer", .dir = out, .dir_opt = "bcount_opt(OutputBufferLength)", .type = PVOID},
      {.name = "OutputBufferLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtDisableLastKnownGood", .return_value = NTSTATUS, .num_args = 0  },
  { .name = "NtDisplayString", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "String", .dir = in, .dir_opt = "", .type = PUNICODE_STRING}
    }
  },
  { .name = "NtDrawText", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "Text", .dir = in, .dir_opt = "", .type = PUNICODE_STRING}
    }
  },
  { .name = "NtDuplicateObject", .return_value = NTSTATUS, .num_args = 7, .args = 
    {
      {.name = "SourceProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "SourceHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TargetProcessHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "TargetHandle", .dir = out, .dir_opt = "opt", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "HandleAttributes", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Options", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtDuplicateToken", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "ExistingTokenHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "EffectiveOnly", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "TokenType", .dir = in, .dir_opt = "", .type = TOKEN_TYPE},
      {.name = "NewTokenHandle", .dir = out, .dir_opt = "", .type = PHANDLE}
    }
  },
  { .name = "NtEnableLastKnownGood", .return_value = NTSTATUS, .num_args = 0  },
  { .name = "NtEnumerateBootEntries", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "Buffer", .dir = out, .dir_opt = "bcount_opt(*BufferLength)", .type = PVOID},
      {.name = "BufferLength", .dir = inout, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtEnumerateDriverEntries", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "Buffer", .dir = out, .dir_opt = "bcount(*BufferLength)", .type = PVOID},
      {.name = "BufferLength", .dir = inout, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtEnumerateKey", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Index", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "KeyInformationClass", .dir = in, .dir_opt = "", .type = KEY_INFORMATION_CLASS},
      {.name = "KeyInformation", .dir = out, .dir_opt = "bcount_opt(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ResultLength", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtEnumerateSystemEnvironmentValuesEx", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "InformationClass", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Buffer", .dir = out, .dir_opt = "", .type = PVOID},
      {.name = "BufferLength", .dir = inout, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtEnumerateTransactionObject", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "RootObjectHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "QueryType", .dir = in, .dir_opt = "", .type = KTMOBJECT_TYPE},
      {.name = "ObjectCursor", .dir = inout, .dir_opt = "bcount(ObjectCursorLength)", .type = PKTMOBJECT_CURSOR},
      {.name = "ObjectCursorLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtEnumerateValueKey", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Index", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "KeyValueInformationClass", .dir = in, .dir_opt = "", .type = KEY_VALUE_INFORMATION_CLASS},
      {.name = "KeyValueInformation", .dir = out, .dir_opt = "bcount_opt(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ResultLength", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtExtendSection", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "SectionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "NewSectionSize", .dir = inout, .dir_opt = "", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtFilterToken", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "ExistingTokenHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "SidsToDisable", .dir = in, .dir_opt = "opt", .type = PTOKEN_GROUPS},
      {.name = "PrivilegesToDelete", .dir = in, .dir_opt = "opt", .type = PTOKEN_PRIVILEGES},
      {.name = "RestrictedSids", .dir = in, .dir_opt = "opt", .type = PTOKEN_GROUPS},
      {.name = "NewTokenHandle", .dir = out, .dir_opt = "", .type = PHANDLE}
    }
  },
  { .name = "NtFindAtom", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "AtomName", .dir = in, .dir_opt = "bcount_opt(Length)", .type = PWSTR},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Atom", .dir = out, .dir_opt = "opt", .type = PRTL_ATOM}
    }
  },
  { .name = "NtFlushBuffersFile", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK}
    }
  },
  { .name = "NtFlushInstallUILanguage", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "InstallUILanguage", .dir = in, .dir_opt = "", .type = LANGID},
      {.name = "SetComittedFlag", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtFlushInstructionCache", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "BaseAddress", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = SIZE_T}
    }
  },
  { .name = "NtFlushKey", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtFlushProcessWriteBuffers", .return_value = VOID, .num_args = 0  },
  { .name = "NtFlushVirtualMemory", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*BaseAddress", .dir = inout, .dir_opt = "", .type = PVOID},
      {.name = "RegionSize", .dir = inout, .dir_opt = "", .type = PSIZE_T},
      {.name = "IoStatus", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK}
    }
  },
  { .name = "NtFlushWriteBuffer", .return_value = NTSTATUS, .num_args = 0  },
  { .name = "NtFreeUserPhysicalPages", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "NumberOfPages", .dir = inout, .dir_opt = "", .type = PULONG_PTR},
      {.name = "UserPfnArra;", .dir = in, .dir_opt = "ecount(*NumberOfPages)", .type = PULONG_PTR}
    }
  },
  { .name = "NtFreeVirtualMemory", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*BaseAddress", .dir = inout, .dir_opt = "", .type = PVOID},
      {.name = "RegionSize", .dir = inout, .dir_opt = "", .type = PSIZE_T},
      {.name = "FreeType", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtFreezeRegistry", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "TimeOutInSeconds", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtFreezeTransactions", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "FreezeTimeout", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER},
      {.name = "ThawTimeout", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtFsControlFile", .return_value = NTSTATUS, .num_args = 10, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "IoControlCode", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "InputBuffer", .dir = in, .dir_opt = "bcount_opt(InputBufferLength)", .type = PVOID},
      {.name = "InputBufferLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "OutputBuffer", .dir = out, .dir_opt = "bcount_opt(OutputBufferLength)", .type = PVOID},
      {.name = "OutputBufferLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtGetContextThread", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ThreadContext", .dir = inout, .dir_opt = "", .type = PCONTEXT}
    }
  },
  { .name = "NtGetCurrentProcessorNumber", .return_value = ULONG, .num_args = 0  },
  { .name = "NtGetDevicePowerState", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "Device", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*State", .dir = out, .dir_opt = "", .type = DEVICE_POWER_STATE}
    }
  },
  { .name = "NtGetMUIRegistryInfo", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "DataSize", .dir = inout, .dir_opt = "", .type = PULONG},
      {.name = "Data", .dir = out, .dir_opt = "", .type = PVOID}
    }
  },
  { .name = "NtGetNextProcess", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "HandleAttributes", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "NewProcessHandle", .dir = out, .dir_opt = "", .type = PHANDLE}
    }
  },
  { .name = "NtGetNextThread", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "HandleAttributes", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "NewThreadHandle", .dir = out, .dir_opt = "", .type = PHANDLE}
    }
  },
  { .name = "NtGetNlsSectionPtr", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "SectionType", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "SectionData", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ContextData", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "*SectionPointer", .dir = out, .dir_opt = "", .type = PVOID},
      {.name = "SectionSize", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtGetNotificationResourceManager", .return_value = NTSTATUS, .num_args = 7, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TransactionNotification", .dir = out, .dir_opt = "", .type = PTRANSACTION_NOTIFICATION},
      {.name = "NotificationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG},
      {.name = "Asynchronous", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "AsynchronousContext", .dir = in, .dir_opt = "opt", .type = ULONG_PTR}
    }
  },
  { .name = "NtGetPlugPlayEvent", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "EventHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Context", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "EventBlock", .dir = out, .dir_opt = "bcount(EventBufferSize)", .type = PPLUGPLAY_EVENT_BLOCK},
      {.name = "EventBufferSize", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtGetWriteWatch", .return_value = NTSTATUS, .num_args = 7, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "BaseAddress", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "RegionSize", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "*UserAddressArray", .dir = out, .dir_opt = "ecount(*EntriesInUserAddressArray)", .type = PVOID},
      {.name = "EntriesInUserAddressArray", .dir = inout, .dir_opt = "", .type = PULONG_PTR},
      {.name = "Granularity", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtImpersonateAnonymousToken", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtImpersonateClientOfPort", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Message", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE}
    }
  },
  { .name = "NtImpersonateThread", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "ServerThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ClientThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "SecurityQos", .dir = in, .dir_opt = "", .type = PSECURITY_QUALITY_OF_SERVICE}
    }
  },
  { .name = "NtInitializeNlsFiles", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "*BaseAddress", .dir = out, .dir_opt = "", .type = PVOID},
      {.name = "DefaultLocaleId", .dir = out, .dir_opt = "", .type = PLCID},
      {.name = "DefaultCasingTableSize", .dir = out, .dir_opt = "", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtInitializeRegistry", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "BootCondition", .dir = in, .dir_opt = "", .type = USHORT}
    }
  },
  { .name = "NtInitiatePowerAction", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "SystemAction", .dir = in, .dir_opt = "", .type = POWER_ACTION},
      {.name = "MinSystemState", .dir = in, .dir_opt = "", .type = SYSTEM_POWER_STATE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Asynchronous", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtIsProcessInJob", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "JobHandle", .dir = in, .dir_opt = "opt", .type = HANDLE}
    }
  },
  { .name = "NtIsSystemResumeAutomatic", .return_value = BOOLEAN, .num_args = 0  },
  { .name = "NtIsUILanguageComitted", .return_value = NTSTATUS, .num_args = 0  },
  { .name = "NtListenPort", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ConnectionRequest", .dir = out, .dir_opt = "", .type = PPORT_MESSAGE}
    }
  },
  { .name = "NtLoadDriver", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "DriverServiceName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING}
    }
  },
  { .name = "NtLoadKey2", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "TargetKey", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "SourceFile", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtLoadKeyEx", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "TargetKey", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "SourceFile", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "TrustClassKey", .dir = in, .dir_opt = "opt", .type = HANDLE}
    }
  },
  { .name = "NtLoadKey", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "TargetKey", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "SourceFile", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtLockFile", .return_value = NTSTATUS, .num_args = 10, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "ByteOffset", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER},
      {.name = "Length", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER},
      {.name = "Key", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "FailImmediately", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "ExclusiveLock", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtLockProductActivationKeys", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "*pPrivateVer", .dir = inout, .dir_opt = "opt", .type = ULONG},
      {.name = "*pSafeMode", .dir = out, .dir_opt = "opt", .type = ULONG}
    }
  },
  { .name = "NtLockRegistryKey", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtLockVirtualMemory", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*BaseAddress", .dir = inout, .dir_opt = "", .type = PVOID},
      {.name = "RegionSize", .dir = inout, .dir_opt = "", .type = PSIZE_T},
      {.name = "MapType", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtMakePermanentObject", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "Handle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtMakeTemporaryObject", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "Handle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtMapCMFModule", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "What", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Index", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "CacheIndexOut", .dir = out, .dir_opt = "opt", .type = PULONG},
      {.name = "CacheFlagsOut", .dir = out, .dir_opt = "opt", .type = PULONG},
      {.name = "ViewSizeOut", .dir = out, .dir_opt = "opt", .type = PULONG},
      {.name = "*BaseAddress", .dir = out, .dir_opt = "opt", .type = PVOID}
    }
  },
  { .name = "NtMapUserPhysicalPages", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "VirtualAddress", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "NumberOfPages", .dir = in, .dir_opt = "", .type = ULONG_PTR},
      {.name = "UserPfnArra;", .dir = in, .dir_opt = "ecount_opt(NumberOfPages)", .type = PULONG_PTR}
    }
  },
  { .name = "NtMapUserPhysicalPagesScatter", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "*VirtualAddresses", .dir = in, .dir_opt = "ecount(NumberOfPages)", .type = PVOID},
      {.name = "NumberOfPages", .dir = in, .dir_opt = "", .type = ULONG_PTR},
      {.name = "UserPfnArray", .dir = in, .dir_opt = "ecount_opt(NumberOfPages)", .type = PULONG_PTR}
    }
  },
  { .name = "NtMapViewOfSection", .return_value = NTSTATUS, .num_args = 10, .args = 
    {
      {.name = "SectionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*BaseAddress", .dir = inout, .dir_opt = "", .type = PVOID},
      {.name = "ZeroBits", .dir = in, .dir_opt = "", .type = ULONG_PTR},
      {.name = "CommitSize", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "SectionOffset", .dir = inout, .dir_opt = "opt", .type = PLARGE_INTEGER},
      {.name = "ViewSize", .dir = inout, .dir_opt = "", .type = PSIZE_T},
      {.name = "InheritDisposition", .dir = in, .dir_opt = "", .type = SECTION_INHERIT},
      {.name = "AllocationType", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Win32Protect", .dir = in, .dir_opt = "", .type = WIN32_PROTECTION_MASK}
    }
  },
  { .name = "NtModifyBootEntry", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "BootEntry", .dir = in, .dir_opt = "", .type = PBOOT_ENTRY}
    }
  },
  { .name = "NtModifyDriverEntry", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "DriverEntry", .dir = in, .dir_opt = "", .type = PEFI_DRIVER_ENTRY}
    }
  },
  { .name = "NtNotifyChangeDirectoryFile", .return_value = NTSTATUS, .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "CompletionFilter", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "WatchTree", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtNotifyChangeKey", .return_value = NTSTATUS, .num_args = 10, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "CompletionFilter", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "WatchTree", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount_opt(BufferSize)", .type = PVOID},
      {.name = "BufferSize", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Asynchronous", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtNotifyChangeMultipleKeys", .return_value = NTSTATUS, .num_args = 12, .args = 
    {
      {.name = "MasterKeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Count", .dir = in, .dir_opt = "opt", .type = ULONG},
      {.name = "SlaveObjects[]", .dir = in, .dir_opt = "ecount_opt(Count)", .type = OBJECT_ATTRIBUTES},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "CompletionFilter", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "WatchTree", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount_opt(BufferSize)", .type = PVOID},
      {.name = "BufferSize", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Asynchronous", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtNotifyChangeSession", .return_value = NTSTATUS, .num_args = 8, .args = 
    {
      {.name = "Session", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStateSequence", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Reserved", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "Action", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "IoState", .dir = in, .dir_opt = "", .type = IO_SESSION_STATE},
      {.name = "IoState2", .dir = in, .dir_opt = "", .type = IO_SESSION_STATE},
      {.name = "Buffer", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "BufferSize", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtOpenDirectoryObject", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "DirectoryHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenEnlistment", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "EnlistmentHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ResourceManagerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "EnlistmentGuid", .dir = in, .dir_opt = "", .type = LPGUID},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenEvent", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "EventHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenEventPair", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "EventPairHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenFile", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "FileHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "ShareAccess", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "OpenOptions", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtOpenIoCompletion", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "IoCompletionHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenJobObject", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "JobHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenKeyedEvent", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "KeyedEventHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenKeyEx", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "KeyHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "OpenOptions", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtOpenKey", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "KeyHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenKeyTransactedEx", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "KeyHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "OpenOptions", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "TransactionHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtOpenKeyTransacted", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "KeyHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "TransactionHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtOpenMutant", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "MutantHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenObjectAuditAlarm", .return_value = NTSTATUS, .num_args = 12, .args = 
    {
      {.name = "SubsystemName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "HandleId", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ObjectTypeName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "ObjectName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "SecurityDescriptor", .dir = in, .dir_opt = "opt", .type = PSECURITY_DESCRIPTOR},
      {.name = "ClientToken", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "GrantedAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "Privileges", .dir = in, .dir_opt = "opt", .type = PPRIVILEGE_SET},
      {.name = "ObjectCreation", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "AccessGranted", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "GenerateOnClose", .dir = out, .dir_opt = "", .type = PBOOLEAN}
    }
  },
  { .name = "NtOpenPrivateNamespace", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "NamespaceHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "BoundaryDescriptor", .dir = in, .dir_opt = "", .type = PVOID}
    }
  },
  { .name = "NtOpenProcess", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "ClientId", .dir = in, .dir_opt = "opt", .type = PCLIENT_ID}
    }
  },
  { .name = "NtOpenProcessTokenEx", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "HandleAttributes", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "TokenHandle", .dir = out, .dir_opt = "", .type = PHANDLE}
    }
  },
  { .name = "NtOpenProcessToken", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "TokenHandle", .dir = out, .dir_opt = "", .type = PHANDLE}
    }
  },
  { .name = "NtOpenResourceManager", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "TmHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ResourceManagerGuid", .dir = in, .dir_opt = "opt", .type = LPGUID},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenSection", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "SectionHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenSemaphore", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "SemaphoreHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenSession", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "SessionHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenSymbolicLinkObject", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "LinkHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenThread", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ThreadHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "ClientId", .dir = in, .dir_opt = "opt", .type = PCLIENT_ID}
    }
  },
  { .name = "NtOpenThreadTokenEx", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "OpenAsSelf", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "HandleAttributes", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "TokenHandle", .dir = out, .dir_opt = "", .type = PHANDLE}
    }
  },
  { .name = "NtOpenThreadToken", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "OpenAsSelf", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "TokenHandle", .dir = out, .dir_opt = "", .type = PHANDLE}
    }
  },
  { .name = "NtOpenTimer", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "TimerHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtOpenTransactionManager", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "TmHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "opt", .type = POBJECT_ATTRIBUTES},
      {.name = "LogFileName", .dir = in, .dir_opt = "opt", .type = PUNICODE_STRING},
      {.name = "TmIdentity", .dir = in, .dir_opt = "opt", .type = LPGUID},
      {.name = "OpenOptions", .dir = in, .dir_opt = "opt", .type = ULONG}
    }
  },
  { .name = "NtOpenTransaction", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "TransactionHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "Uow", .dir = in, .dir_opt = "", .type = LPGUID},
      {.name = "TmHandle", .dir = in, .dir_opt = "opt", .type = HANDLE}
    }
  },
  { .name = "NtPlugPlayControl", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PnPControlClass", .dir = in, .dir_opt = "", .type = PLUGPLAY_CONTROL_CLASS},
      {.name = "PnPControlData", .dir = inout, .dir_opt = "bcount(PnPControlDataLength)", .type = PVOID},
      {.name = "PnPControlDataLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtPowerInformation", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "InformationLevel", .dir = in, .dir_opt = "", .type = POWER_INFORMATION_LEVEL},
      {.name = "InputBuffer", .dir = in, .dir_opt = "bcount_opt(InputBufferLength)", .type = PVOID},
      {.name = "InputBufferLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "OutputBuffer", .dir = out, .dir_opt = "bcount_opt(OutputBufferLength)", .type = PVOID},
      {.name = "OutputBufferLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtPrepareComplete", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TmVirtualClock", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtPrepareEnlistment", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TmVirtualClock", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtPrePrepareComplete", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TmVirtualClock", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtPrePrepareEnlistment", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TmVirtualClock", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtPrivilegeCheck", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "ClientToken", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "RequiredPrivileges", .dir = inout, .dir_opt = "", .type = PPRIVILEGE_SET},
      {.name = "Result", .dir = out, .dir_opt = "", .type = PBOOLEAN}
    }
  },
  { .name = "NtPrivilegedServiceAuditAlarm", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "SubsystemName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "ServiceName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "ClientToken", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Privileges", .dir = in, .dir_opt = "", .type = PPRIVILEGE_SET},
      {.name = "AccessGranted", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtPrivilegeObjectAuditAlarm", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "SubsystemName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "HandleId", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ClientToken", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DesiredAccess", .dir = in, .dir_opt = "", .type = ACCESS_MASK},
      {.name = "Privileges", .dir = in, .dir_opt = "", .type = PPRIVILEGE_SET},
      {.name = "AccessGranted", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtPropagationComplete", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "RequestCookie", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "BufferLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Buffer", .dir = in, .dir_opt = "", .type = PVOID}
    }
  },
  { .name = "NtPropagationFailed", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "RequestCookie", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "PropStatus", .dir = in, .dir_opt = "", .type = NTSTATUS}
    }
  },
  { .name = "NtProtectVirtualMemory", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*BaseAddress", .dir = inout, .dir_opt = "", .type = PVOID},
      {.name = "RegionSize", .dir = inout, .dir_opt = "", .type = PSIZE_T},
      {.name = "NewProtectWin32", .dir = in, .dir_opt = "", .type = WIN32_PROTECTION_MASK},
      {.name = "OldProtect", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtPulseEvent", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EventHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PreviousState", .dir = out, .dir_opt = "opt", .type = PLONG}
    }
  },
  { .name = "NtQueryAttributesFile", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "FileInformation", .dir = out, .dir_opt = "", .type = PFILE_BASIC_INFORMATION}
    }
  },
  { .name = "NtQueryBootEntryOrder", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "Ids", .dir = out, .dir_opt = "ecount_opt(*Count)", .type = PULONG},
      {.name = "Count", .dir = inout, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQueryBootOptions", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "BootOptions", .dir = out, .dir_opt = "bcount_opt(*BootOptionsLength)", .type = PBOOT_OPTIONS},
      {.name = "BootOptionsLength", .dir = inout, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQueryDebugFilterState", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ComponentId", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Level", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtQueryDefaultLocale", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "UserProfile", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "DefaultLocaleId", .dir = out, .dir_opt = "", .type = PLCID}
    }
  },
  { .name = "NtQueryDefaultUILanguage", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "*DefaultUILanguageId", .dir = out, .dir_opt = "", .type = LANGID}
    }
  },
  { .name = "NtQueryDirectoryFile", .return_value = NTSTATUS, .num_args = 11, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "FileInformation", .dir = out, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "FileInformationClass", .dir = in, .dir_opt = "", .type = FILE_INFORMATION_CLASS},
      {.name = "ReturnSingleEntry", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "FileName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "RestartScan", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtQueryDirectoryObject", .return_value = NTSTATUS, .num_args = 7, .args = 
    {
      {.name = "DirectoryHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount_opt(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnSingleEntry", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "RestartScan", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "Context", .dir = inout, .dir_opt = "", .type = PULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryDriverEntryOrder", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "Ids", .dir = out, .dir_opt = "ecount(*Count)", .type = PULONG},
      {.name = "Count", .dir = inout, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQueryEaFile", .return_value = NTSTATUS, .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnSingleEntry", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "EaList", .dir = in, .dir_opt = "bcount_opt(EaListLength)", .type = PVOID},
      {.name = "EaListLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "EaIndex", .dir = in, .dir_opt = "opt", .type = PULONG},
      {.name = "RestartScan", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtQueryEvent", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "EventHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "EventInformationClass", .dir = in, .dir_opt = "", .type = EVENT_INFORMATION_CLASS},
      {.name = "EventInformation", .dir = out, .dir_opt = "bcount(EventInformationLength)", .type = PVOID},
      {.name = "EventInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryFullAttributesFile", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ObjectAttributes", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "FileInformation", .dir = out, .dir_opt = "", .type = PFILE_NETWORK_OPEN_INFORMATION}
    }
  },
  { .name = "NtQueryInformationAtom", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "Atom", .dir = in, .dir_opt = "", .type = RTL_ATOM},
      {.name = "InformationClass", .dir = in, .dir_opt = "", .type = ATOM_INFORMATION_CLASS},
      {.name = "AtomInformation", .dir = out, .dir_opt = "bcount(AtomInformationLength)", .type = PVOID},
      {.name = "AtomInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryInformationEnlistment", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "EnlistmentInformationClass", .dir = in, .dir_opt = "", .type = ENLISTMENT_INFORMATION_CLASS},
      {.name = "EnlistmentInformation", .dir = out, .dir_opt = "bcount(EnlistmentInformationLength)", .type = PVOID},
      {.name = "EnlistmentInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryInformationFile", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "FileInformation", .dir = out, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "FileInformationClass", .dir = in, .dir_opt = "", .type = FILE_INFORMATION_CLASS}
    }
  },
  { .name = "NtQueryInformationJobObject", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "JobHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "JobObjectInformationClass", .dir = in, .dir_opt = "", .type = JOBOBJECTINFOCLASS},
      {.name = "JobObjectInformation", .dir = out, .dir_opt = "bcount(JobObjectInformationLength)", .type = PVOID},
      {.name = "JobObjectInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryInformationPort", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PortInformationClass", .dir = in, .dir_opt = "", .type = PORT_INFORMATION_CLASS},
      {.name = "PortInformation", .dir = out, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryInformationProcess", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ProcessInformationClass", .dir = in, .dir_opt = "", .type = PROCESSINFOCLASS},
      {.name = "ProcessInformation", .dir = out, .dir_opt = "bcount(ProcessInformationLength)", .type = PVOID},
      {.name = "ProcessInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryInformationResourceManager", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ResourceManagerInformationClass", .dir = in, .dir_opt = "", .type = RESOURCEMANAGER_INFORMATION_CLASS},
      {.name = "ResourceManagerInformation", .dir = out, .dir_opt = "bcount(ResourceManagerInformationLength)", .type = PVOID},
      {.name = "ResourceManagerInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryInformationThread", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ThreadInformationClass", .dir = in, .dir_opt = "", .type = THREADINFOCLASS},
      {.name = "ThreadInformation", .dir = out, .dir_opt = "bcount(ThreadInformationLength)", .type = PVOID},
      {.name = "ThreadInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryInformationToken", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "TokenHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TokenInformationClass", .dir = in, .dir_opt = "", .type = TOKEN_INFORMATION_CLASS},
      {.name = "TokenInformation", .dir = out, .dir_opt = "bcount_part_opt(TokenInformationLength,*ReturnLength)", .type = PVOID},
      {.name = "TokenInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQueryInformationTransaction", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "TransactionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TransactionInformationClass", .dir = in, .dir_opt = "", .type = TRANSACTION_INFORMATION_CLASS},
      {.name = "TransactionInformation", .dir = out, .dir_opt = "bcount(TransactionInformationLength)", .type = PVOID},
      {.name = "TransactionInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryInformationTransactionManager", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "TransactionManagerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TransactionManagerInformationClass", .dir = in, .dir_opt = "", .type = TRANSACTIONMANAGER_INFORMATION_CLASS},
      {.name = "TransactionManagerInformation", .dir = out, .dir_opt = "bcount(TransactionManagerInformationLength)", .type = PVOID},
      {.name = "TransactionManagerInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryInformationWorkerFactory", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "WorkerFactoryHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "WorkerFactoryInformationClass", .dir = in, .dir_opt = "", .type = WORKERFACTORYINFOCLASS},
      {.name = "WorkerFactoryInformation", .dir = out, .dir_opt = "bcount(WorkerFactoryInformationLength)", .type = PVOID},
      {.name = "WorkerFactoryInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryInstallUILanguage", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "*InstallUILanguageId", .dir = out, .dir_opt = "", .type = LANGID}
    }
  },
  { .name = "NtQueryIntervalProfile", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ProfileSource", .dir = in, .dir_opt = "", .type = KPROFILE_SOURCE},
      {.name = "Interval", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQueryIoCompletion", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "IoCompletionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoCompletionInformationClass", .dir = in, .dir_opt = "", .type = IO_COMPLETION_INFORMATION_CLASS},
      {.name = "IoCompletionInformation", .dir = out, .dir_opt = "bcount(IoCompletionInformationLength)", .type = PVOID},
      {.name = "IoCompletionInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryKey", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "KeyInformationClass", .dir = in, .dir_opt = "", .type = KEY_INFORMATION_CLASS},
      {.name = "KeyInformation", .dir = out, .dir_opt = "bcount_opt(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ResultLength", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQueryLicenseValue", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "Name", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "Type", .dir = out, .dir_opt = "opt", .type = PULONG},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount(ReturnedLength)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnedLength", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQueryMultipleValueKey", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ValueEntries", .dir = inout, .dir_opt = "ecount(EntryCount)", .type = PKEY_VALUE_ENTRY},
      {.name = "EntryCount", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ValueBuffer", .dir = out, .dir_opt = "bcount(*BufferLength)", .type = PVOID},
      {.name = "BufferLength", .dir = inout, .dir_opt = "", .type = PULONG},
      {.name = "RequiredBufferLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryMutant", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "MutantHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "MutantInformationClass", .dir = in, .dir_opt = "", .type = MUTANT_INFORMATION_CLASS},
      {.name = "MutantInformation", .dir = out, .dir_opt = "bcount(MutantInformationLength)", .type = PVOID},
      {.name = "MutantInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryObject", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "Handle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ObjectInformationClass", .dir = in, .dir_opt = "", .type = OBJECT_INFORMATION_CLASS},
      {.name = "ObjectInformation", .dir = out, .dir_opt = "bcount_opt(ObjectInformationLength)", .type = PVOID},
      {.name = "ObjectInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryOpenSubKeysEx", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "TargetKey", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "BufferLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount(BufferLength)", .type = PVOID},
      {.name = "RequiredSize", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQueryOpenSubKeys", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "TargetKey", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "HandleCount", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQueryPerformanceCounter", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "PerformanceCounter", .dir = out, .dir_opt = "", .type = PLARGE_INTEGER},
      {.name = "PerformanceFrequency", .dir = out, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtQueryPortInformationProcess", .return_value = NTSTATUS, .num_args = 0  },
  { .name = "NtQueryQuotaInformationFile", .return_value = NTSTATUS, .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnSingleEntry", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "SidList", .dir = in, .dir_opt = "bcount_opt(SidListLength)", .type = PVOID},
      {.name = "SidListLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "StartSid", .dir = in, .dir_opt = "opt", .type = PULONG},
      {.name = "RestartScan", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtQuerySection", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "SectionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "SectionInformationClass", .dir = in, .dir_opt = "", .type = SECTION_INFORMATION_CLASS},
      {.name = "SectionInformation", .dir = out, .dir_opt = "bcount(SectionInformationLength)", .type = PVOID},
      {.name = "SectionInformationLength", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PSIZE_T}
    }
  },
  { .name = "NtQuerySecurityAttributesToken", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "TokenHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Attributes", .dir = in, .dir_opt = "ecount_opt(NumberOfAttributes)", .type = PUNICODE_STRING},
      {.name = "NumberOfAttributes", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQuerySecurityObject", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "Handle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "SecurityInformation", .dir = in, .dir_opt = "", .type = SECURITY_INFORMATION},
      {.name = "SecurityDescriptor", .dir = out, .dir_opt = "bcount_opt(Length)", .type = PSECURITY_DESCRIPTOR},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "LengthNeeded", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQuerySemaphore", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "SemaphoreHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "SemaphoreInformationClass", .dir = in, .dir_opt = "", .type = SEMAPHORE_INFORMATION_CLASS},
      {.name = "SemaphoreInformation", .dir = out, .dir_opt = "bcount(SemaphoreInformationLength)", .type = PVOID},
      {.name = "SemaphoreInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQuerySymbolicLinkObject", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "LinkHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "LinkTarget", .dir = inout, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "ReturnedLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQuerySystemEnvironmentValueEx", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "VariableName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "VendorGuid", .dir = in, .dir_opt = "", .type = LPGUID},
      {.name = "Value", .dir = out, .dir_opt = "bcount_opt(*ValueLength)", .type = PVOID},
      {.name = "ValueLength", .dir = inout, .dir_opt = "", .type = PULONG},
      {.name = "Attributes", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQuerySystemEnvironmentValue", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "VariableName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "VariableValue", .dir = out, .dir_opt = "bcount(ValueLength)", .type = PWSTR},
      {.name = "ValueLength", .dir = in, .dir_opt = "", .type = USHORT},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PUSHORT}
    }
  },
  { .name = "NtQuerySystemInformationEx", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "SystemInformationClass", .dir = in, .dir_opt = "", .type = SYSTEM_INFORMATION_CLASS},
      {.name = "QueryInformation", .dir = in, .dir_opt = "bcount(QueryInformationLength)", .type = PVOID},
      {.name = "QueryInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "SystemInformation", .dir = out, .dir_opt = "bcount_opt(SystemInformationLength)", .type = PVOID},
      {.name = "SystemInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQuerySystemInformation", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "SystemInformationClass", .dir = in, .dir_opt = "", .type = SYSTEM_INFORMATION_CLASS},
      {.name = "SystemInformation", .dir = out, .dir_opt = "bcount_opt(SystemInformationLength)", .type = PVOID},
      {.name = "SystemInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQuerySystemTime", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "SystemTime", .dir = out, .dir_opt = "", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtQueryTimer", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "TimerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TimerInformationClass", .dir = in, .dir_opt = "", .type = TIMER_INFORMATION_CLASS},
      {.name = "TimerInformation", .dir = out, .dir_opt = "bcount(TimerInformationLength)", .type = PVOID},
      {.name = "TimerInformationLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtQueryTimerResolution", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "MaximumTime", .dir = out, .dir_opt = "", .type = PULONG},
      {.name = "MinimumTime", .dir = out, .dir_opt = "", .type = PULONG},
      {.name = "CurrentTime", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQueryValueKey", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ValueName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "KeyValueInformationClass", .dir = in, .dir_opt = "", .type = KEY_VALUE_INFORMATION_CLASS},
      {.name = "KeyValueInformation", .dir = out, .dir_opt = "bcount_opt(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ResultLength", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtQueryVirtualMemory", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "BaseAddress", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "MemoryInformationClass", .dir = in, .dir_opt = "", .type = MEMORY_INFORMATION_CLASS},
      {.name = "MemoryInformation", .dir = out, .dir_opt = "bcount(MemoryInformationLength)", .type = PVOID},
      {.name = "MemoryInformationLength", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PSIZE_T}
    }
  },
  { .name = "NtQueryVolumeInformationFile", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "FsInformation", .dir = out, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "FsInformationClass", .dir = in, .dir_opt = "", .type = FS_INFORMATION_CLASS}
    }
  },
  { .name = "NtQueueApcThreadEx", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "UserApcReserveHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "", .type = PPS_APC_ROUTINE},
      {.name = "ApcArgument1", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ApcArgument2", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ApcArgument3", .dir = in, .dir_opt = "opt", .type = PVOID}
    }
  },
  { .name = "NtQueueApcThread", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "", .type = PPS_APC_ROUTINE},
      {.name = "ApcArgument1", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ApcArgument2", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "ApcArgument3", .dir = in, .dir_opt = "opt", .type = PVOID}
    }
  },
  { .name = "NtRaiseException", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "ExceptionRecord", .dir = out, .dir_opt = "", .type = PEXCEPTION_RECORD},
      {.name = "ContextRecord", .dir = out, .dir_opt = "", .type = PCONTEXT},
      {.name = "FirstChance", .dir = out, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtRaiseHardError", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "ErrorStatus", .dir = in, .dir_opt = "", .type = NTSTATUS},
      {.name = "NumberOfParameters", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "UnicodeStringParameterMask", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Parameters", .dir = in, .dir_opt = "ecount(NumberOfParameters)", .type = PULONG_PTR},
      {.name = "ValidResponseOptions", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Response", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtReadFile", .return_value = NTSTATUS, .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ByteOffset", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER},
      {.name = "Key", .dir = in, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtReadFileScatter", .return_value = NTSTATUS, .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "SegmentArray", .dir = in, .dir_opt = "", .type = PFILE_SEGMENT_ELEMENT},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ByteOffset", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER},
      {.name = "Key", .dir = in, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtReadOnlyEnlistment", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TmVirtualClock", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtReadRequestData", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Message", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE},
      {.name = "DataEntryIndex", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount(BufferSize)", .type = PVOID},
      {.name = "BufferSize", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "NumberOfBytesRead", .dir = out, .dir_opt = "opt", .type = PSIZE_T}
    }
  },
  { .name = "NtReadVirtualMemory", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "BaseAddress", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "Buffer", .dir = out, .dir_opt = "bcount(BufferSize)", .type = PVOID},
      {.name = "BufferSize", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "NumberOfBytesRead", .dir = out, .dir_opt = "opt", .type = PSIZE_T}
    }
  },
  { .name = "NtRecoverEnlistment", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "EnlistmentKey", .dir = in, .dir_opt = "opt", .type = PVOID}
    }
  },
  { .name = "NtRecoverResourceManager", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtRecoverTransactionManager", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "TransactionManagerHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtRegisterProtocolAddressInformation", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "ResourceManager", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ProtocolId", .dir = in, .dir_opt = "", .type = PCRM_PROTOCOL_ID},
      {.name = "ProtocolInformationSize", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ProtocolInformation", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "CreateOptions", .dir = in, .dir_opt = "opt", .type = ULONG}
    }
  },
  { .name = "NtRegisterThreadTerminatePort", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtReleaseKeyedEvent", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "KeyedEventHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "KeyValue", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "Alertable", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtReleaseMutant", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "MutantHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PreviousCount", .dir = out, .dir_opt = "opt", .type = PLONG}
    }
  },
  { .name = "NtReleaseSemaphore", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "SemaphoreHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ReleaseCount", .dir = in, .dir_opt = "", .type = LONG},
      {.name = "PreviousCount", .dir = out, .dir_opt = "opt", .type = PLONG}
    }
  },
  { .name = "NtReleaseWorkerFactoryWorker", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "WorkerFactoryHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtRemoveIoCompletionEx", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "IoCompletionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoCompletionInformation", .dir = out, .dir_opt = "ecount(Count)", .type = PFILE_IO_COMPLETION_INFORMATION},
      {.name = "Count", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "NumEntriesRemoved", .dir = out, .dir_opt = "", .type = PULONG},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER},
      {.name = "Alertable", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtRemoveIoCompletion", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "IoCompletionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*KeyContext", .dir = out, .dir_opt = "", .type = PVOID},
      {.name = "*ApcContext", .dir = out, .dir_opt = "", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtRemoveProcessDebug", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ProcessHandle", .dir = out, .dir_opt = "", .type = HANDLE},
      {.name = "DebugObjectHandle", .dir = out, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtRenameKey", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "NewName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING}
    }
  },
  { .name = "NtRenameTransactionManager", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "LogFileName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "ExistingTransactionManagerGuid", .dir = in, .dir_opt = "", .type = LPGUID}
    }
  },
  { .name = "NtReplaceKey", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "NewFile", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "TargetHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "OldFile", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtReplacePartitionUnit", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "TargetInstancePath", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "SpareInstancePath", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtReplyPort", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ReplyMessage", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE}
    }
  },
  { .name = "NtReplyWaitReceivePortEx", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*PortContext", .dir = out, .dir_opt = "opt", .type = PVOID},
      {.name = "ReplyMessage", .dir = in, .dir_opt = "opt", .type = PPORT_MESSAGE},
      {.name = "ReceiveMessage", .dir = out, .dir_opt = "", .type = PPORT_MESSAGE},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtReplyWaitReceivePort", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*PortContext", .dir = out, .dir_opt = "opt", .type = PVOID},
      {.name = "ReplyMessage", .dir = in, .dir_opt = "opt", .type = PPORT_MESSAGE},
      {.name = "ReceiveMessage", .dir = out, .dir_opt = "", .type = PPORT_MESSAGE}
    }
  },
  { .name = "NtReplyWaitReplyPort", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ReplyMessage", .dir = inout, .dir_opt = "", .type = PPORT_MESSAGE}
    }
  },
  { .name = "NtRequestPort", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "RequestMessage", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE}
    }
  },
  { .name = "NtRequestWaitReplyPort", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "RequestMessage", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE},
      {.name = "ReplyMessage", .dir = out, .dir_opt = "", .type = PPORT_MESSAGE}
    }
  },
  { .name = "NtResetEvent", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EventHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PreviousState", .dir = out, .dir_opt = "opt", .type = PLONG}
    }
  },
  { .name = "NtResetWriteWatch", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "BaseAddress", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "RegionSize", .dir = in, .dir_opt = "", .type = SIZE_T}
    }
  },
  { .name = "NtRestoreKey", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtResumeProcess", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtResumeThread", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PreviousSuspendCount", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtRollbackComplete", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TmVirtualClock", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtRollbackEnlistment", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TmVirtualClock", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtRollbackTransaction", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "TransactionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Wait", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtRollforwardTransactionManager", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "TransactionManagerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TmVirtualClock", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtSaveKeyEx", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Format", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSaveKey", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtSaveMergedKeys", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "HighPrecedenceKeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "LowPrecedenceKeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtSecureConnectPort", .return_value = NTSTATUS, .num_args = 9, .args = 
    {
      {.name = "PortHandle", .dir = out, .dir_opt = "", .type = PHANDLE},
      {.name = "PortName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "SecurityQos", .dir = in, .dir_opt = "", .type = PSECURITY_QUALITY_OF_SERVICE},
      {.name = "ClientView", .dir = inout, .dir_opt = "opt", .type = PPORT_VIEW},
      {.name = "RequiredServerSid", .dir = in, .dir_opt = "opt", .type = PSID},
      {.name = "ServerView", .dir = inout, .dir_opt = "opt", .type = PREMOTE_PORT_VIEW},
      {.name = "MaxMessageLength", .dir = out, .dir_opt = "opt", .type = PULONG},
      {.name = "ConnectionInformation", .dir = inout, .dir_opt = "opt", .type = PVOID},
      {.name = "ConnectionInformationLength", .dir = inout, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtSerializeBoot", .return_value = NTSTATUS, .num_args = 0  },
  { .name = "NtSetBootEntryOrder", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "Ids", .dir = in, .dir_opt = "ecount(Count)", .type = PULONG},
      {.name = "Count", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetBootOptions", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "BootOptions", .dir = in, .dir_opt = "", .type = PBOOT_OPTIONS},
      {.name = "FieldsToChange", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetContextThread", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ThreadContext", .dir = in, .dir_opt = "", .type = PCONTEXT}
    }
  },
  { .name = "NtSetDebugFilterState", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "ComponentId", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Level", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "State", .dir = in, .dir_opt = "", .type = BOOLEAN}
    }
  },
  { .name = "NtSetDefaultHardErrorPort", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "DefaultHardErrorPort", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtSetDefaultLocale", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "UserProfile", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "DefaultLocaleId", .dir = in, .dir_opt = "", .type = LCID}
    }
  },
  { .name = "NtSetDefaultUILanguage", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "DefaultUILanguageId", .dir = in, .dir_opt = "", .type = LANGID}
    }
  },
  { .name = "NtSetDriverEntryOrder", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "Ids", .dir = in, .dir_opt = "ecount(Count)", .type = PULONG},
      {.name = "Count", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetEaFile", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "Buffer", .dir = in, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetEventBoostPriority", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "EventHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtSetEvent", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EventHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PreviousState", .dir = out, .dir_opt = "opt", .type = PLONG}
    }
  },
  { .name = "NtSetHighEventPair", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "EventPairHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtSetHighWaitLowEventPair", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "EventPairHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtSetInformationDebugObject", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "DebugObjectHandle", .dir = out, .dir_opt = "", .type = HANDLE},
      {.name = "DebugObjectInformationClass", .dir = out, .dir_opt = "", .type = DEBUGOBJECTINFOCLASS},
      {.name = "DebugInformation", .dir = out, .dir_opt = "", .type = PVOID},
      {.name = "DebugInformationLength", .dir = out, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtSetInformationEnlistment", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "EnlistmentInformationClass", .dir = in, .dir_opt = "", .type = ENLISTMENT_INFORMATION_CLASS},
      {.name = "EnlistmentInformation", .dir = in, .dir_opt = "bcount(EnlistmentInformationLength)", .type = PVOID},
      {.name = "EnlistmentInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetInformationFile", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "FileInformation", .dir = in, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "FileInformationClass", .dir = in, .dir_opt = "", .type = FILE_INFORMATION_CLASS}
    }
  },
  { .name = "NtSetInformationJobObject", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "JobHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "JobObjectInformationClass", .dir = in, .dir_opt = "", .type = JOBOBJECTINFOCLASS},
      {.name = "JobObjectInformation", .dir = in, .dir_opt = "bcount(JobObjectInformationLength)", .type = PVOID},
      {.name = "JobObjectInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetInformationKey", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "KeySetInformationClass", .dir = in, .dir_opt = "", .type = KEY_SET_INFORMATION_CLASS},
      {.name = "KeySetInformation", .dir = in, .dir_opt = "bcount(KeySetInformationLength)", .type = PVOID},
      {.name = "KeySetInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetInformationObject", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "Handle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ObjectInformationClass", .dir = in, .dir_opt = "", .type = OBJECT_INFORMATION_CLASS},
      {.name = "ObjectInformation", .dir = in, .dir_opt = "bcount(ObjectInformationLength)", .type = PVOID},
      {.name = "ObjectInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetInformationProcess", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ProcessInformationClass", .dir = in, .dir_opt = "", .type = PROCESSINFOCLASS},
      {.name = "ProcessInformation", .dir = in, .dir_opt = "bcount(ProcessInformationLength)", .type = PVOID},
      {.name = "ProcessInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetInformationResourceManager", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ResourceManagerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ResourceManagerInformationClass", .dir = in, .dir_opt = "", .type = RESOURCEMANAGER_INFORMATION_CLASS},
      {.name = "ResourceManagerInformation", .dir = in, .dir_opt = "bcount(ResourceManagerInformationLength)", .type = PVOID},
      {.name = "ResourceManagerInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetInformationThread", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ThreadInformationClass", .dir = in, .dir_opt = "", .type = THREADINFOCLASS},
      {.name = "ThreadInformation", .dir = in, .dir_opt = "bcount(ThreadInformationLength)", .type = PVOID},
      {.name = "ThreadInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetInformationToken", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "TokenHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TokenInformationClass", .dir = in, .dir_opt = "", .type = TOKEN_INFORMATION_CLASS},
      {.name = "TokenInformation", .dir = in, .dir_opt = "bcount(TokenInformationLength)", .type = PVOID},
      {.name = "TokenInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetInformationTransaction", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "TransactionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TransactionInformationClass", .dir = in, .dir_opt = "", .type = TRANSACTION_INFORMATION_CLASS},
      {.name = "TransactionInformation", .dir = in, .dir_opt = "bcount(TransactionInformationLength)", .type = PVOID},
      {.name = "TransactionInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetInformationTransactionManager", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "TmHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "TransactionManagerInformationClass", .dir = in, .dir_opt = "", .type = TRANSACTIONMANAGER_INFORMATION_CLASS},
      {.name = "TransactionManagerInformation", .dir = in, .dir_opt = "bcount(TransactionManagerInformationLength)", .type = PVOID},
      {.name = "TransactionManagerInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetInformationWorkerFactory", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "WorkerFactoryHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "WorkerFactoryInformationClass", .dir = in, .dir_opt = "", .type = WORKERFACTORYINFOCLASS},
      {.name = "WorkerFactoryInformation", .dir = in, .dir_opt = "bcount(WorkerFactoryInformationLength)", .type = PVOID},
      {.name = "WorkerFactoryInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetIntervalProfile", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "Interval", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Source", .dir = in, .dir_opt = "", .type = KPROFILE_SOURCE}
    }
  },
  { .name = "NtSetIoCompletionEx", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "IoCompletionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoCompletionReserveHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "KeyContext", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatus", .dir = in, .dir_opt = "", .type = NTSTATUS},
      {.name = "IoStatusInformation", .dir = in, .dir_opt = "", .type = ULONG_PTR}
    }
  },
  { .name = "NtSetIoCompletion", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "IoCompletionHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "KeyContext", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatus", .dir = in, .dir_opt = "", .type = NTSTATUS},
      {.name = "IoStatusInformation", .dir = in, .dir_opt = "", .type = ULONG_PTR}
    }
  },
  { .name = "NtSetLdtEntries", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "Selector0", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Entry0Low", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Entry0Hi", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Selector1", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Entry1Low", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Entry1Hi", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetLowEventPair", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "EventPairHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtSetLowWaitHighEventPair", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "EventPairHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtSetQuotaInformationFile", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "Buffer", .dir = in, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetSecurityObject", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "Handle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "SecurityInformation", .dir = in, .dir_opt = "", .type = SECURITY_INFORMATION},
      {.name = "SecurityDescriptor", .dir = in, .dir_opt = "", .type = PSECURITY_DESCRIPTOR}
    }
  },
  { .name = "NtSetSystemEnvironmentValueEx", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "VariableName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "VendorGuid", .dir = in, .dir_opt = "", .type = LPGUID},
      {.name = "Value", .dir = in, .dir_opt = "bcount_opt(ValueLength)", .type = PVOID},
      {.name = "ValueLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Attributes", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetSystemEnvironmentValue", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "VariableName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "VariableValue", .dir = in, .dir_opt = "", .type = PUNICODE_STRING}
    }
  },
  { .name = "NtSetSystemInformation", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "SystemInformationClass", .dir = in, .dir_opt = "", .type = SYSTEM_INFORMATION_CLASS},
      {.name = "SystemInformation", .dir = in, .dir_opt = "bcount_opt(SystemInformationLength)", .type = PVOID},
      {.name = "SystemInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetSystemPowerState", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "SystemAction", .dir = in, .dir_opt = "", .type = POWER_ACTION},
      {.name = "MinSystemState", .dir = in, .dir_opt = "", .type = SYSTEM_POWER_STATE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetSystemTime", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "SystemTime", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER},
      {.name = "PreviousTime", .dir = out, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtSetThreadExecutionState", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "esFlags", .dir = in, .dir_opt = "", .type = EXECUTION_STATE},
      {.name = "*PreviousFlags", .dir = out, .dir_opt = "", .type = EXECUTION_STATE}
    }
  },
  { .name = "NtSetTimerEx", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "TimerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TimerSetInformationClass", .dir = in, .dir_opt = "", .type = TIMER_SET_INFORMATION_CLASS},
      {.name = "TimerSetInformation", .dir = inout, .dir_opt = "bcount(TimerSetInformationLength)", .type = PVOID},
      {.name = "TimerSetInformationLength", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetTimer", .return_value = NTSTATUS, .num_args = 7, .args = 
    {
      {.name = "TimerHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "DueTime", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER},
      {.name = "TimerApcRoutine", .dir = in, .dir_opt = "opt", .type = PTIMER_APC_ROUTINE},
      {.name = "TimerContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "WakeTimer", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "Period", .dir = in, .dir_opt = "opt", .type = LONG},
      {.name = "PreviousState", .dir = out, .dir_opt = "opt", .type = PBOOLEAN}
    }
  },
  { .name = "NtSetTimerResolution", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "DesiredTime", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "SetResolution", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "ActualTime", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtSetUuidSeed", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "Seed", .dir = in, .dir_opt = "", .type = PCHAR}
    }
  },
  { .name = "NtSetValueKey", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "KeyHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ValueName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING},
      {.name = "TitleIndex", .dir = in, .dir_opt = "opt", .type = ULONG},
      {.name = "Type", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Data", .dir = in, .dir_opt = "bcount_opt(DataSize)", .type = PVOID},
      {.name = "DataSize", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtSetVolumeInformationFile", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "FsInformation", .dir = in, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "FsInformationClass", .dir = in, .dir_opt = "", .type = FS_INFORMATION_CLASS}
    }
  },
  { .name = "NtShutdownSystem", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "Action", .dir = in, .dir_opt = "", .type = SHUTDOWN_ACTION}
    }
  },
  { .name = "NtShutdownWorkerFactory", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "WorkerFactoryHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*PendingWorkerCount", .dir = inout, .dir_opt = "", .type = LONG}
    }
  },
  { .name = "NtSignalAndWaitForSingleObject", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "SignalHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "WaitHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Alertable", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtSinglePhaseReject", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "EnlistmentHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "TmVirtualClock", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtStartProfile", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "ProfileHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtStopProfile", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "ProfileHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtSuspendProcess", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtSuspendThread", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "PreviousSuspendCount", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtSystemDebugControl", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "Command", .dir = in, .dir_opt = "", .type = SYSDBG_COMMAND},
      {.name = "InputBuffer", .dir = inout, .dir_opt = "bcount_opt(InputBufferLength)", .type = PVOID},
      {.name = "InputBufferLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "OutputBuffer", .dir = out, .dir_opt = "bcount_opt(OutputBufferLength)", .type = PVOID},
      {.name = "OutputBufferLength", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtTerminateJobObject", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "JobHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "ExitStatus", .dir = in, .dir_opt = "", .type = NTSTATUS}
    }
  },
  { .name = "NtTerminateProcess", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ExitStatus", .dir = in, .dir_opt = "", .type = NTSTATUS}
    }
  },
  { .name = "NtTerminateThread", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ThreadHandle", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ExitStatus", .dir = in, .dir_opt = "", .type = NTSTATUS}
    }
  },
  { .name = "NtTestAlert", .return_value = NTSTATUS, .num_args = 0  },
  { .name = "NtThawRegistry", .return_value = NTSTATUS, .num_args = 0  },
  { .name = "NtThawTransactions", .return_value = NTSTATUS, .num_args = 0  },
  { .name = "NtTraceControl", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "FunctionCode", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "InBuffer", .dir = in, .dir_opt = "bcount_opt(InBufferLen)", .type = PVOID},
      {.name = "InBufferLen", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "OutBuffer", .dir = out, .dir_opt = "bcount_opt(OutBufferLen)", .type = PVOID},
      {.name = "OutBufferLen", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ReturnLength", .dir = out, .dir_opt = "", .type = PULONG}
    }
  },
  { .name = "NtTraceEvent", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "TraceHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "FieldSize", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Fields", .dir = in, .dir_opt = "", .type = PVOID}
    }
  },
  { .name = "NtTranslateFilePath", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "InputFilePath", .dir = in, .dir_opt = "", .type = PFILE_PATH},
      {.name = "OutputType", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "OutputFilePath", .dir = out, .dir_opt = "bcount_opt(*OutputFilePathLength)", .type = PFILE_PATH},
      {.name = "OutputFilePathLength", .dir = inout, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtUmsThreadYield", .return_value = NTSTATUS, .num_args = 0  },
  { .name = "NtUnloadDriver", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "DriverServiceName", .dir = in, .dir_opt = "", .type = PUNICODE_STRING}
    }
  },
  { .name = "NtUnloadKey2", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "TargetKey", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "Flags", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtUnloadKeyEx", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "TargetKey", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE}
    }
  },
  { .name = "NtUnloadKey", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "TargetKey", .dir = in, .dir_opt = "", .type = POBJECT_ATTRIBUTES}
    }
  },
  { .name = "NtUnlockFile", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "ByteOffset", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER},
      {.name = "Length", .dir = in, .dir_opt = "", .type = PLARGE_INTEGER},
      {.name = "Key", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtUnlockVirtualMemory", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "*BaseAddress", .dir = inout, .dir_opt = "", .type = PVOID},
      {.name = "RegionSize", .dir = inout, .dir_opt = "", .type = PSIZE_T},
      {.name = "MapType", .dir = in, .dir_opt = "", .type = ULONG}
    }
  },
  { .name = "NtUnmapViewOfSection", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "BaseAddress", .dir = in, .dir_opt = "", .type = PVOID}
    }
  },
  { .name = "NtVdmControl", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "Service", .dir = in, .dir_opt = "", .type = VDMSERVICECLASS},
      {.name = "ServiceData", .dir = inout, .dir_opt = "", .type = PVOID}
    }
  },
  { .name = "NtWaitForDebugEvent", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "DebugObjectHandle", .dir = out, .dir_opt = "", .type = HANDLE},
      {.name = "Alertable", .dir = out, .dir_opt = "", .type = BOOLEAN},
      {.name = "Timeout", .dir = out, .dir_opt = "", .type = PLARGE_INTEGER},
      {.name = "WaitStateChange", .dir = out, .dir_opt = "", .type = PDBGUI_WAIT_STATE_CHANGE}
    }
  },
  { .name = "NtWaitForKeyedEvent", .return_value = NTSTATUS, .num_args = 4, .args = 
    {
      {.name = "KeyedEventHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "KeyValue", .dir = in, .dir_opt = "", .type = PVOID},
      {.name = "Alertable", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtWaitForMultipleObjects32", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "Count", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Handles[]", .dir = in, .dir_opt = "ecount(Count)", .type = LONG},
      {.name = "WaitType", .dir = in, .dir_opt = "", .type = WAIT_TYPE},
      {.name = "Alertable", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtWaitForMultipleObjects", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "Count", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Handles[]", .dir = in, .dir_opt = "ecount(Count)", .type = HANDLE},
      {.name = "WaitType", .dir = in, .dir_opt = "", .type = WAIT_TYPE},
      {.name = "Alertable", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtWaitForSingleObject", .return_value = NTSTATUS, .num_args = 3, .args = 
    {
      {.name = "Handle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Alertable", .dir = in, .dir_opt = "", .type = BOOLEAN},
      {.name = "Timeout", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER}
    }
  },
  { .name = "NtWaitForWorkViaWorkerFactory", .return_value = NTSTATUS, .num_args = 2, .args = 
    {
      {.name = "WorkerFactoryHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "MiniPacket", .dir = out, .dir_opt = "", .type = PFILE_IO_COMPLETION_INFORMATION}
    }
  },
  { .name = "NtWaitHighEventPair", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "EventPairHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtWaitLowEventPair", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "EventPairHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtWorkerFactoryWorkerReady", .return_value = NTSTATUS, .num_args = 1, .args = 
    {
      {.name = "WorkerFactoryHandle", .dir = in, .dir_opt = "", .type = HANDLE}
    }
  },
  { .name = "NtWriteFileGather", .return_value = NTSTATUS, .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "SegmentArray", .dir = in, .dir_opt = "", .type = PFILE_SEGMENT_ELEMENT},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ByteOffset", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER},
      {.name = "Key", .dir = in, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtWriteFile", .return_value = NTSTATUS, .num_args = 9, .args = 
    {
      {.name = "FileHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Event", .dir = in, .dir_opt = "opt", .type = HANDLE},
      {.name = "ApcRoutine", .dir = in, .dir_opt = "opt", .type = PIO_APC_ROUTINE},
      {.name = "ApcContext", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "IoStatusBlock", .dir = out, .dir_opt = "", .type = PIO_STATUS_BLOCK},
      {.name = "Buffer", .dir = in, .dir_opt = "bcount(Length)", .type = PVOID},
      {.name = "Length", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "ByteOffset", .dir = in, .dir_opt = "opt", .type = PLARGE_INTEGER},
      {.name = "Key", .dir = in, .dir_opt = "opt", .type = PULONG}
    }
  },
  { .name = "NtWriteRequestData", .return_value = NTSTATUS, .num_args = 6, .args = 
    {
      {.name = "PortHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "Message", .dir = in, .dir_opt = "", .type = PPORT_MESSAGE},
      {.name = "DataEntryIndex", .dir = in, .dir_opt = "", .type = ULONG},
      {.name = "Buffer", .dir = in, .dir_opt = "bcount(BufferSize)", .type = PVOID},
      {.name = "BufferSize", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "NumberOfBytesWritten", .dir = out, .dir_opt = "opt", .type = PSIZE_T}
    }
  },
  { .name = "NtWriteVirtualMemory", .return_value = NTSTATUS, .num_args = 5, .args = 
    {
      {.name = "ProcessHandle", .dir = in, .dir_opt = "", .type = HANDLE},
      {.name = "BaseAddress", .dir = in, .dir_opt = "opt", .type = PVOID},
      {.name = "Buffer", .dir = in, .dir_opt = "bcount(BufferSize)", .type = PVOID},
      {.name = "BufferSize", .dir = in, .dir_opt = "", .type = SIZE_T},
      {.name = "NumberOfBytesWritten", .dir = out, .dir_opt = "opt", .type = PSIZE_T}
    }
  },
  { .name = "NtYieldExecution", .return_value = NTSTATUS, .num_args = 0 }
};

