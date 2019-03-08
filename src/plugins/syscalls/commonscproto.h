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
#ifndef commoncsproto_h
#define commoncsproto_h

typedef enum
{
    DIR_IN,
    DIR_OUT,
    DIR_INOUT,
    DIR_RESERVED,
    DIR_MISSING
} arg_direction_t;

const char* arg_direction_names[]
{
    [DIR_IN] = "IN",
    [DIR_OUT] = "OUT",
    [DIR_INOUT] = "INOUT",
    [DIR_RESERVED] = "RESERVED",
    [DIR_MISSING] = "MISSING"
};


// All types for Windows and Linux
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
} type_t;

static const char* type_names[]
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


/* For now, put all syscall flags here */
#define SYSCALL_FLAG_LINUX_PT_REGS (1 << 0) /* Args passed via struct pt_regs rather than direct registers */


typedef struct
{
    const char*     name;
    arg_direction_t dir;
    type_t          type;
    const char*     dir_opt;
} arg_t;

typedef struct
{
    const char*  name;
    addr_t       addr;
    type_t       ret;
    unsigned int num_args;
    arg_t        args[17];
} syscall_t;

typedef struct
{
    syscalls* sc;
    int       syscall_index;
    uint32_t  flags;
} syscall_wrapper_t;


#endif // commoncsproto_h
