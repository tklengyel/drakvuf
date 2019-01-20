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

/*
 * From http://laredo-13.mit.edu/~brendan/scproto.txt
 *
 */

#define NUM_SYSCALLS 406

typedef enum
{
    DIR_IN,
    DIR_OUT,
    DIR_INOUT,
    DIR_RESERVED,
    DIR_MISSING
} win_arg_direction_t;

const char* win_arg_direction_names[]
{
    [DIR_IN] = "IN",
    [DIR_OUT] = "OUT",
    [DIR_INOUT] = "INOUT",
    [DIR_RESERVED] = "RESERVED",
    [DIR_MISSING] = "MISSING"
};

typedef enum
{
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
    WORKERFACTORYINFOCLASS
} win_type_t;

static const char* win_type_names[]
{
    [ACCESS_MASK] = "ACCESS_MASK",
    [ALPC_HANDLE] = "ALPC_HANDLE",
    [ALPC_MESSAGE_INFORMATION_CLASS] = "ALPC_MESSAGE_INFORMATION_CLASS",
    [ALPC_PORT_INFORMATION_CLASS] = "ALPC_PORT_INFORMATION_CLASS",
    [APPHELPCOMMAND] = "APPHELPCOMMAND",
    [ATOM_INFORMATION_CLASS] = "ATOM_INFORMATION_CLASS",
    [AUDIT_EVENT_TYPE] = "AUDIT_EVENT_TYPE",
    [BOOLEAN] = "BOOLEAN",
    [DEBUGOBJECTINFOCLASS] = "DEBUGOBJECTINFOCLASS",
    [DEVICE_POWER_STATE] = "DEVICE_POWER_STATE",
    [ENLISTMENT_INFORMATION_CLASS] = "ENLISTMENT_INFORMATION_CLASS",
    [EVENT_INFORMATION_CLASS] = "EVENT_INFORMATION_CLASS",
    [EVENT_TYPE] = "EVENT_TYPE",
    [EXECUTION_STATE] = "EXECUTION_STATE",
    [FILE_INFORMATION_CLASS] = "FILE_INFORMATION_CLASS",
    [FS_INFORMATION_CLASS] = "FS_INFORMATION_CLASS",
    [HANDLE] = "HANDLE",
    [IO_COMPLETION_INFORMATION_CLASS] = "IO_COMPLETION_INFORMATION_CLASS",
    [IO_SESSION_STATE] = " IO_SESSION_STATE",
    [JOBOBJECTINFOCLASS] = "JOBOBJECTINFOCLASS",
    [KAFFINITY] = "KAFFINITY",
    [KEY_INFORMATION_CLASS] = "KEY_INFORMATION_CLASS",
    [KEY_SET_INFORMATION_CLASS] = "KEY_SET_INFORMATION_CLASS",
    [KEY_VALUE_INFORMATION_CLASS] = "KEY_VALUE_INFORMATION_CLASS",
    [KPROFILE_SOURCE] = "KPROFILE_SOURCE",
    [KTMOBJECT_TYPE] = "KTMOBJECT_TYPE",
    [LANGID] = "LANGID",
    [LCID] = "LCID",
    [LONG] = "LONG",
    [LPGUID] = "LPGUID",
    [MEMORY_INFORMATION_CLASS] = "MEMORY_INFORMATION_CLASS",
    [MEMORY_RESERVE_TYPE] = "MEMORY_RESERVE_TYPE",
    [MISSING] = "MISSING",
    [MUTANT_INFORMATION_CLASS] = "MUTANT_INFORMATION_CLASS",
    [NOTIFICATION_MASK] = "NOTIFICATION_MASK",
    [NTAPI] = "NTAPI",
    [NTSTATUS] = "NTSTATUS",
    [OBJECT_ATTRIBUTES] = "OBJECT_ATTRIBUTES",
    [OBJECT_INFORMATION_CLASS] = "OBJECT_INFORMATION_CLASS",
    [PACCESS_MASK] = "PACCESS_MASK",
    [PALPC_CONTEXT_ATTR] = "PALPC_CONTEXT_ATTR",
    [PALPC_DATA_VIEW_ATTR] = "PALPC_DATA_VIEW_ATTR",
    [PALPC_HANDLE] = "PALPC_HANDLE",
    [PALPC_MESSAGE_ATTRIBUTES] = "PALPC_MESSAGE_ATTRIBUTES",
    [PALPC_PORT_ATTRIBUTES] = "PALPC_PORT_ATTRIBUTES",
    [PALPC_SECURITY_ATTR] = "PALPC_SECURITY_ATTR",
    [PBOOLEAN] = "PBOOLEAN",
    [PBOOT_ENTRY] = "PBOOT_ENTRY",
    [PBOOT_OPTIONS] = "PBOOT_OPTIONS",
    [PCHAR] = "PCHAR",
    [PCLIENT_ID] = "PCLIENT_ID",
    [PCONTEXT] = "PCONTEXT",
    [PCRM_PROTOCOL_ID] = "PCRM_PROTOCOL_ID",
    [PDBGUI_WAIT_STATE_CHANGE] = "PDBGUI_WAIT_STATE_CHANGE",
    [PEFI_DRIVER_ENTRY] = "PEFI_DRIVER_ENTRY",
    [PEXCEPTION_RECORD] = "PEXCEPTION_RECORD",
    [PFILE_BASIC_INFORMATION] = "PFILE_BASIC_INFORMATION",
    [PFILE_IO_COMPLETION_INFORMATION] = "PFILE_IO_COMPLETION_INFORMATION",
    [PFILE_NETWORK_OPEN_INFORMATION] = "PFILE_NETWORK_OPEN_INFORMATION",
    [PFILE_PATH] = "PFILE_PATH",
    [PFILE_SEGMENT_ELEMENT] = "PFILE_SEGMENT_ELEMENT",
    [PGENERIC_MAPPING] = "PGENERIC_MAPPING",
    [PGROUP_AFFINITY] = "PGROUP_AFFINITY",
    [PHANDLE] = "PHANDLE",
    [PINITIAL_TEB] = "PINITIAL_TEB",
    [PIO_APC_ROUTINE] = "PIO_APC_ROUTINE",
    [PIO_STATUS_BLOCK] = "PIO_STATUS_BLOCK",
    [PJOB_SET_ARRAY] = "PJOB_SET_ARRAY",
    [PKEY_VALUE_ENTRY] = "PKEY_VALUE_ENTRY",
    [PKTMOBJECT_CURSOR] = "PKTMOBJECT_CURSOR",
    [PLARGE_INTEGER] = "PLARGE_INTEGER",
    [PLCID] = "PLCID",
    [PLONG] = "PLONG",
    [PLUGPLAY_CONTROL_CLASS] = "PLUGPLAY_CONTROL_CLASS",
    [PLUID] = "PLUID",
    [PNTSTATUS] = "PNTSTATUS",
    [POBJECT_ATTRIBUTES] = "POBJECT_ATTRIBUTES",
    [POBJECT_TYPE_LIST] = "POBJECT_TYPE_LIST",
    [PORT_INFORMATION_CLASS] = "PORT_INFORMATION_CLASS",
    [POWER_ACTION] = "POWER_ACTION",
    [POWER_INFORMATION_LEVEL] = "POWER_INFORMATION_LEVEL",
    [PPLUGPLAY_EVENT_BLOCK] = "PPLUGPLAY_EVENT_BLOCK",
    [PPORT_MESSAGE] = "PPORT_MESSAGE",
    [PPORT_VIEW] = "PPORT_VIEW",
    [PPRIVILEGE_SET] = "PPRIVILEGE_SET",
    [PPROCESS_ATTRIBUTE_LIST] = "PPROCESS_ATTRIBUTE_LIST",
    [PPROCESS_CREATE_INFO] = "PPROCESS_CREATE_INFO",
    [PPS_APC_ROUTINE] = "PPS_APC_ROUTINE",
    [PPS_ATTRIBUTE_LIST] = "PPS_ATTRIBUTE_LIST",
    [PREMOTE_PORT_VIEW] = "PREMOTE_PORT_VIEW",
    [PROCESSINFOCLASS] = "PROCESSINFOCLASS",
    [PRTL_ATOM] = "PRTL_ATOM",
    [PRTL_USER_PROCESS_PARAMETERS] = "PRTL_USER_PROCESS_PARAMETERS",
    [PSECURITY_DESCRIPTOR] = "PSECURITY_DESCRIPTOR",
    [PSECURITY_QUALITY_OF_SERVICE] = "PSECURITY_QUALITY_OF_SERVICE",
    [PSID] = "PSID",
    [PSIZE_T] = "PSIZE_T",
    [PTIMER_APC_ROUTINE] = "PTIMER_APC_ROUTINE",
    [PTOKEN_DEFAULT_DACL] = "PTOKEN_DEFAULT_DACL",
    [PTOKEN_GROUPS] = "PTOKEN_GROUPS",
    [PTOKEN_OWNER] = "PTOKEN_OWNER",
    [PTOKEN_PRIMARY_GROUP] = "PTOKEN_PRIMARY_GROUP",
    [PTOKEN_PRIVILEGES] = "PTOKEN_PRIVILEGES",
    [PTOKEN_SOURCE] = "PTOKEN_SOURCE",
    [PTOKEN_USER] = "PTOKEN_USER",
    [PTRANSACTION_NOTIFICATION] = "PTRANSACTION_NOTIFICATION",
    [PULARGE_INTEGER] = "PULARGE_INTEGER",
    [PULONG] = "PULONG",
    [PULONG_PTR] = "PULONG_PTR",
    [PUNICODE_STRING] = "PUNICODE_STRING",
    [PUSHORT] = "PUSHORT",
    [PVOID] = "PVOID",
    [PWSTR] = "PWSTR",
    [RESOURCEMANAGER_INFORMATION_CLASS] = "RESOURCEMANAGER_INFORMATION_CLASS",
    [RTL_ATOM] = "RTL_ATOM",
    [SECTION_INFORMATION_CLASS] = "SECTION_INFORMATION_CLASS",
    [SECTION_INHERIT] = "SECTION_INHERIT",
    [SECURITY_INFORMATION] = "SECURITY_INFORMATION",
    [SEMAPHORE_INFORMATION_CLASS] = "SEMAPHORE_INFORMATION_CLASS",
    [SHUTDOWN_ACTION] = "SHUTDOWN_ACTION",
    [SIZE_T] = "SIZE_T",
    [SYSDBG_COMMAND] = "SYSDBG_COMMAND",
    [SYSTEM_INFORMATION_CLASS] = "SYSTEM_INFORMATION_CLASS",
    [SYSTEM_POWER_STATE] = "SYSTEM_POWER_STATE",
    [THREADINFOCLASS] = "THREADINFOCLASS",
    [TIMER_INFORMATION_CLASS] = "TIMER_INFORMATION_CLASS",
    [TIMER_SET_INFORMATION_CLASS] = "TIMER_SET_INFORMATION_CLASS",
    [TIMER_TYPE] = "TIMER_TYPE",
    [TOKEN_INFORMATION_CLASS] = "TOKEN_INFORMATION_CLASS",
    [TOKEN_TYPE] = "TOKEN_TYPE",
    [TRANSACTIONMANAGER_INFORMATION_CLASS] = "TRANSACTIONMANAGER_INFORMATION_CLASS",
    [TRANSACTION_INFORMATION_CLASS] = "TRANSACTION_INFORMATION_CLASS",
    [ULONG] = "ULONG",
    [ULONG_PTR] = "ULONG_PTR",
    [USHORT] = "USHORT",
    [VDMSERVICECLASS] = "VDMSERVICECLASS",
    [VOID] = "VOID",
    [WAIT_TYPE] = "WAIT_TYPE",
    [WIN32_PROTECTION_MASK] = "WIN32_PROTECTION_MASK",
    [WINAPI] = "WINAPI",
    [WORKERFACTORYINFOCLASS] = "WORKERFACTORYINFOCLASS"
};

typedef struct
{
    const char* name;
    win_arg_direction_t dir;
    win_type_t type;
    const char* dir_opt;
} win_arg_t;

typedef struct
{
    const char* name;
    win_type_t ret;
    unsigned int num_args;
    win_arg_t args[17];
} win_syscall_t;

typedef struct
{
    syscalls* sc;
    int syscall_index;
} syscall_wrapper_t;

static const win_syscall_t win_syscalls[] =
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
    { .name = "NtYieldExecution", .ret = NTSTATUS, .num_args = 0 }
};

