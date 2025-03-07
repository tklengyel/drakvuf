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

#ifndef SYSCALLS_PRIVATE_H
#define SYSCALLS_PRIVATE_H

#include "plugins/plugins_ex.h"
#include "plugins/plugin_utils.h"

namespace syscalls_ns
{

struct syscalls_module
{
    std::string name;
    addr_t base;
    size_t size;
};

typedef enum
{
    DIR_IN,
    DIR_OUT,
    DIR_INOUT,
    DIR_RESERVED,
    DIR_MISSING
} arg_direction_t;

static const char* arg_direction_names[]
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
    // All
    Void,
    VoidPtr,
    // Windows
    ACCESS_MASK,
    ALPC_HANDLE,
    ALPC_MESSAGE_INFORMATION_CLASS,
    ALPC_PORT_INFORMATION_CLASS,
    APPHELPCOMMAND,
    ATOM_INFORMATION_CLASS,
    AUDIT_EVENT_TYPE,
    BOOLEAN,
    BYTE,
    DEBUGOBJECTINFOCLASS,
    DEVICE_POWER_STATE,
    DWORD,
    ENLISTMENT_INFORMATION_CLASS,
    EVENT_INFORMATION_CLASS,
    EVENT_TYPE,
    EXECUTION_STATE,
    FILE_INFORMATION_CLASS,
    FS_INFORMATION_CLASS,
    HANDLE,
    HHOOK,
    HINSTANCE,
    HOOKPROC,
    HOT_PATCH_INFORMATION_CLASS,
    HWND,
    INT,
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
    LPARAM,
    LPGUID,
    MEMORY_INFORMATION_CLASS,
    MEMORY_RESERVE_TYPE,
    MUTANT_INFORMATION_CLASS,
    NOTIFICATION_MASK,
    NTSTATUS,
    OBJECT_INFORMATION_CLASS,
    PACCESS_MASK,
    PALPC_CONTEXT_ATTR,
    PALPC_DATA_VIEW_ATTR,
    PALPC_HANDLE,
    PALPC_MESSAGE_ATTRIBUTES,
    PALPC_PORT_ATTRIBUTES,
    PALPC_SECURITY_ATTR,
    PARTITION_INFORMATION_CLASS,
    PBOOLEAN,
    PBOOT_ENTRY,
    PBOOT_OPTIONS,
    PCHAR,
    PCLIENT_ID,
    PCONTEXT,
    PCRM_PROTOCOL_ID,
    PDBGUI_WAIT_STATE_CHANGE,
    PDEVICE_POWER_STATE,
    PEFI_DRIVER_ENTRY,
    PEXCEPTION_RECORD,
    PEXECUTION_STATE,
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
    PLANGID,
    PLARGE_INTEGER,
    PLCID,
    PLONG,
    PLUGPLAY_CONTROL_CLASS,
    PLUID,
    PMEM_EXTENDED_PARAMETER,
    PMEMORY_RANGE_ENTRY,
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
    PPVOID,
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
    PWSTR,
    RESOURCEMANAGER_INFORMATION_CLASS,
    RTL_ATOM,
    SECTION_INFORMATION_CLASS,
    SECTION_INHERIT,
    SECURITY_INFORMATION,
    SEMAPHORE_INFORMATION_CLASS,
    SHORT,
    SHUTDOWN_ACTION,
    SIZE_T,
    SYMBOLIC_LINK_INFO_CLASS,
    SYSDBG_COMMAND,
    SYSTEM_INFORMATION_CLASS,
    SYSTEM_POWER_STATE,
    THREADINFOCLASS,
    TIMER_INFORMATION_CLASS,
    TIMER_SET_INFORMATION_CLASS,
    TIMER_TYPE,
    TOKEN_INFORMATION_CLASS,
    TOKEN_TYPE,
    TRANSACTION_INFORMATION_CLASS,
    TRANSACTIONMANAGER_INFORMATION_CLASS,
    UINT,
    ULONG,
    ULONG_PTR,
    USHORT,
    VDMSERVICECLASS,
    VIRTUAL_MEMORY_INFORMATION_CLASS,
    WAIT_TYPE,
    WIN32_PROTECTION_MASK,
    WORD,
    WORKERFACTORYINFOCLASS,
    WPARAM,
    // Linux, with original (lower)case
    linux_bpf_attr_ptr,
    linux_caddr_t,
    linux_char_ptr,
    linux_clock_t,
    linux_dev_t,
    linux_dirent_ptr,
    linux_fd_set_ptr,
    linux_file_handle_ptr,
    linux_gid_t,
    linux_int,
    linux_int_ptr,
    linux_intmask_map_,
    linux_intmask_prot_,
    linux_intopt_arch_,
    linux_intopt_pr_,
    linux_iovec_ptr,
    linux_itimerspec_ptr,
    linux_key_serial_t,
    linux_key_t,
    linux_linux_dirent64_ptr,
    linux_loff_t,
    linux_long,
    linux_mmsghdr_ptr,
    linux_mode_t,
    linux_module_ptr,
    linux_msghdr_ptr,
    linux_nfds_t,
    linux_nfsctl_arg_ptr,
    linux_nfsctl_res_ptr,
    linux_off64_t,
    linux_off64_t_ptr,
    linux_off_t,
    linux_off_t_ptr,
    linux_pid_t,
    linux_pollfd_ptr,
    linux_ptrace_request,
    linux_rlimit_ptr,
    linux_rusage_ptr,
    linux_sched_attr_ptr,
    linux_sched_param_ptr,
    linux_sembuf_ptr,
    linux_shmid_ds_ptr,
    linux_sigaction_ptr,
    linux_sigset_t_ptr,
    linux_size_t,
    linux_size_t_ptr,
    linux_sockaddr_ptr,
    linux_socklen_t,
    linux_socklen_t_ptr,
    linux_ssize_t,
    linux_stat_ptr,
    linux_statfs_ptr,
    linux_statx_ptr,
    linux_sysctl_args_ptr,
    linux_timespec_ptr,
    linux_timeval_ptr,
    linux_timex_ptr,
    linux_uchar_ptr,
    linux_uid_t,
    linux_uint32_t,
    linux_uint64_t,
    linux_unsigned,
    linux_unsigned_int,
    linux_unsigned_long,
    linux_unsigned_long_ptr,
    linux_utimbuf_ptr,

    __ARG_TYPE_MAX,
} arg_type_t;

typedef enum
{
    ARG_SIZE_VOID,
    ARG_SIZE_8,
    ARG_SIZE_16,
    ARG_SIZE_32,
    ARG_SIZE_64,
    ARG_SIZE_NATIVE,
} arg_size_t;

typedef struct
{
    const char* name;
    arg_size_t size;
    bool is_ptr;
    arg_type_t ptr_for_type; // VOID if not pointer or pointer to incomplete type
} arg_type_info_t;

#define ARG_TYPE_VOID(TYPE) {TYPE, {.name = #TYPE, .size = ARG_SIZE_VOID, .is_ptr = false, .ptr_for_type = Void}}
#define ARG_TYPE_8(TYPE) {TYPE, {.name = #TYPE, .size = ARG_SIZE_8, .is_ptr = false, .ptr_for_type = Void}}
#define ARG_TYPE_16(TYPE) {TYPE, {.name = #TYPE, .size = ARG_SIZE_16, .is_ptr = false, .ptr_for_type = Void}}
#define ARG_TYPE_32(TYPE) {TYPE, {.name = #TYPE, .size = ARG_SIZE_32, .is_ptr = false, .ptr_for_type = Void}}
#define ARG_TYPE_64(TYPE) {TYPE, {.name = #TYPE, .size = ARG_SIZE_64, .is_ptr = false, .ptr_for_type = Void}}
#define ARG_TYPE_NATIVE(TYPE) {TYPE, {.name = #TYPE, .size = ARG_SIZE_NATIVE, .is_ptr = false, .ptr_for_type = Void}}

#define ARG_TYPE_PTR_TO_TYPE(PTR_TYPE, TO_TYPE) {PTR_TYPE, {.name = #PTR_TYPE, .size = ARG_SIZE_NATIVE, .is_ptr = true, .ptr_for_type = TO_TYPE}}
#define ARG_TYPE_PTR(PTR_TYPE) {PTR_TYPE, {.name = #PTR_TYPE, .size = ARG_SIZE_NATIVE, .is_ptr = true, .ptr_for_type = Void}}

#define VOID Void
#define PVOID VoidPtr

#define linux_void Void
#define linux_void_ptr VoidPtr

static const std::unordered_map<arg_type_t, arg_type_info_t> arg_types
{
    // All //
    // void-related types
    ARG_TYPE_VOID(Void),
    ARG_TYPE_PTR_TO_TYPE(VoidPtr, Void),

    // Windows //
    // void-related types
    ARG_TYPE_PTR_TO_TYPE(PPVOID, PVOID),
    // base types
    ARG_TYPE_NATIVE(ULONG_PTR),
    ARG_TYPE_PTR_TO_TYPE(PULONG_PTR, ULONG_PTR),
    ARG_TYPE_NATIVE(SIZE_T),
    ARG_TYPE_PTR_TO_TYPE(PSIZE_T, SIZE_T),
    ARG_TYPE_8(BYTE),
    ARG_TYPE_8(BOOLEAN),
    ARG_TYPE_PTR_TO_TYPE(PBOOLEAN, BOOLEAN),
    ARG_TYPE_16(WORD),
    ARG_TYPE_16(SHORT),
    ARG_TYPE_16(USHORT),
    ARG_TYPE_PTR_TO_TYPE(PUSHORT, USHORT),
    ARG_TYPE_32(DWORD),
    ARG_TYPE_32(INT),
    ARG_TYPE_32(UINT),
    ARG_TYPE_32(LONG),
    ARG_TYPE_PTR_TO_TYPE(PLONG, LONG),
    ARG_TYPE_32(ULONG),
    ARG_TYPE_PTR_TO_TYPE(PULONG, ULONG),
    ARG_TYPE_PTR(PCHAR),
    ARG_TYPE_PTR(PLARGE_INTEGER),
    ARG_TYPE_PTR(PULARGE_INTEGER),
    ARG_TYPE_PTR(PUNICODE_STRING),
    ARG_TYPE_PTR(PWSTR),
    // statuses
    ARG_TYPE_32(NTSTATUS),
    ARG_TYPE_PTR_TO_TYPE(PNTSTATUS, NTSTATUS),
    // handles
    ARG_TYPE_NATIVE(HANDLE),
    ARG_TYPE_PTR_TO_TYPE(PHANDLE, HANDLE),
    ARG_TYPE_NATIVE(ALPC_HANDLE),
    ARG_TYPE_PTR_TO_TYPE(PALPC_HANDLE, ALPC_HANDLE),
    ARG_TYPE_NATIVE(HINSTANCE),
    ARG_TYPE_NATIVE(HWND),
    ARG_TYPE_NATIVE(HHOOK),
    // pointers to functions
    ARG_TYPE_PTR(HOOKPROC),
    // classes
    ARG_TYPE_32(ALPC_MESSAGE_INFORMATION_CLASS),
    ARG_TYPE_32(ALPC_PORT_INFORMATION_CLASS),
    ARG_TYPE_32(ATOM_INFORMATION_CLASS),
    ARG_TYPE_32(ENLISTMENT_INFORMATION_CLASS),
    ARG_TYPE_32(EVENT_INFORMATION_CLASS),
    ARG_TYPE_32(FILE_INFORMATION_CLASS),
    ARG_TYPE_32(FS_INFORMATION_CLASS),
    ARG_TYPE_32(HOT_PATCH_INFORMATION_CLASS),
    ARG_TYPE_32(IO_COMPLETION_INFORMATION_CLASS),
    ARG_TYPE_32(JOBOBJECTINFOCLASS),
    ARG_TYPE_32(KEY_INFORMATION_CLASS),
    ARG_TYPE_32(KEY_SET_INFORMATION_CLASS),
    ARG_TYPE_32(KEY_VALUE_INFORMATION_CLASS),
    ARG_TYPE_32(MEMORY_INFORMATION_CLASS),
    ARG_TYPE_32(MUTANT_INFORMATION_CLASS),
    ARG_TYPE_32(OBJECT_INFORMATION_CLASS),
    ARG_TYPE_32(PARTITION_INFORMATION_CLASS),
    ARG_TYPE_32(PLUGPLAY_CONTROL_CLASS),
    ARG_TYPE_32(PROCESSINFOCLASS),
    ARG_TYPE_32(PORT_INFORMATION_CLASS),
    ARG_TYPE_32(RESOURCEMANAGER_INFORMATION_CLASS),
    ARG_TYPE_32(SECTION_INFORMATION_CLASS),
    ARG_TYPE_32(SEMAPHORE_INFORMATION_CLASS),
    ARG_TYPE_32(SYMBOLIC_LINK_INFO_CLASS),
    ARG_TYPE_32(SYSTEM_INFORMATION_CLASS),
    ARG_TYPE_32(THREADINFOCLASS),
    ARG_TYPE_32(TIMER_INFORMATION_CLASS),
    ARG_TYPE_32(TIMER_SET_INFORMATION_CLASS),
    ARG_TYPE_32(TOKEN_INFORMATION_CLASS),
    ARG_TYPE_32(TRANSACTIONMANAGER_INFORMATION_CLASS),
    ARG_TYPE_32(TRANSACTION_INFORMATION_CLASS),
    ARG_TYPE_32(VDMSERVICECLASS),
    ARG_TYPE_32(VIRTUAL_MEMORY_INFORMATION_CLASS),
    ARG_TYPE_32(DEBUGOBJECTINFOCLASS),
    ARG_TYPE_32(WORKERFACTORYINFOCLASS),
    // other types
    ARG_TYPE_16(LANGID),
    ARG_TYPE_PTR_TO_TYPE(PLANGID, LANGID),
    ARG_TYPE_16(RTL_ATOM),
    ARG_TYPE_PTR_TO_TYPE(PRTL_ATOM, RTL_ATOM),
    ARG_TYPE_32(LCID),
    ARG_TYPE_PTR_TO_TYPE(PLCID, LCID),
    ARG_TYPE_32(POWER_ACTION),
    ARG_TYPE_32(POWER_INFORMATION_LEVEL),
    ARG_TYPE_32(ACCESS_MASK),
    ARG_TYPE_PTR_TO_TYPE(PACCESS_MASK, ACCESS_MASK),
    ARG_TYPE_32(APPHELPCOMMAND),
    ARG_TYPE_32(AUDIT_EVENT_TYPE),
    ARG_TYPE_32(DEVICE_POWER_STATE),
    ARG_TYPE_PTR_TO_TYPE(PDEVICE_POWER_STATE, DEVICE_POWER_STATE),
    ARG_TYPE_32(EVENT_TYPE),
    ARG_TYPE_32(EXECUTION_STATE),
    ARG_TYPE_PTR_TO_TYPE(PEXECUTION_STATE, EXECUTION_STATE),
    ARG_TYPE_32(IO_SESSION_STATE),
    ARG_TYPE_32(KPROFILE_SOURCE),
    ARG_TYPE_32(KTMOBJECT_TYPE),
    ARG_TYPE_32(SECTION_INHERIT),
    ARG_TYPE_32(SECURITY_INFORMATION),
    ARG_TYPE_32(SHUTDOWN_ACTION),
    ARG_TYPE_32(SYSDBG_COMMAND),
    ARG_TYPE_32(SYSTEM_POWER_STATE),
    ARG_TYPE_32(MEMORY_RESERVE_TYPE),
    ARG_TYPE_32(NOTIFICATION_MASK),
    ARG_TYPE_32(TIMER_TYPE),
    ARG_TYPE_32(TOKEN_TYPE),
    ARG_TYPE_32(WAIT_TYPE),
    ARG_TYPE_32(WIN32_PROTECTION_MASK),
    ARG_TYPE_NATIVE(KAFFINITY),
    ARG_TYPE_NATIVE(LPARAM),
    ARG_TYPE_NATIVE(WPARAM),
    // incomplete types, only pointers
    ARG_TYPE_PTR(LPGUID),
    ARG_TYPE_PTR(PLUID),
    ARG_TYPE_PTR(PALPC_CONTEXT_ATTR),
    ARG_TYPE_PTR(PALPC_DATA_VIEW_ATTR),
    ARG_TYPE_PTR(PALPC_MESSAGE_ATTRIBUTES),
    ARG_TYPE_PTR(PALPC_PORT_ATTRIBUTES),
    ARG_TYPE_PTR(PALPC_SECURITY_ATTR),
    ARG_TYPE_PTR(PBOOT_ENTRY),
    ARG_TYPE_PTR(PBOOT_OPTIONS),
    ARG_TYPE_PTR(PCLIENT_ID),
    ARG_TYPE_PTR(PCONTEXT),
    ARG_TYPE_PTR(PCRM_PROTOCOL_ID),
    ARG_TYPE_PTR(PDBGUI_WAIT_STATE_CHANGE),
    ARG_TYPE_PTR(PEFI_DRIVER_ENTRY),
    ARG_TYPE_PTR(PEXCEPTION_RECORD),
    ARG_TYPE_PTR(PFILE_BASIC_INFORMATION),
    ARG_TYPE_PTR(PFILE_IO_COMPLETION_INFORMATION),
    ARG_TYPE_PTR(PFILE_NETWORK_OPEN_INFORMATION),
    ARG_TYPE_PTR(PFILE_PATH),
    ARG_TYPE_PTR(PFILE_SEGMENT_ELEMENT),
    ARG_TYPE_PTR(PGENERIC_MAPPING),
    ARG_TYPE_PTR(PGROUP_AFFINITY),
    ARG_TYPE_PTR(PMEM_EXTENDED_PARAMETER),
    ARG_TYPE_PTR(PMEMORY_RANGE_ENTRY),
    ARG_TYPE_PTR(PINITIAL_TEB),
    ARG_TYPE_PTR(PIO_APC_ROUTINE),
    ARG_TYPE_PTR(PIO_STATUS_BLOCK),
    ARG_TYPE_PTR(PJOB_SET_ARRAY),
    ARG_TYPE_PTR(PKEY_VALUE_ENTRY),
    ARG_TYPE_PTR(PKTMOBJECT_CURSOR),
    ARG_TYPE_PTR(POBJECT_ATTRIBUTES),
    ARG_TYPE_PTR(POBJECT_TYPE_LIST),
    ARG_TYPE_PTR(PPLUGPLAY_EVENT_BLOCK),
    ARG_TYPE_PTR(PPORT_MESSAGE),
    ARG_TYPE_PTR(PPORT_VIEW),
    ARG_TYPE_PTR(PPRIVILEGE_SET),
    ARG_TYPE_PTR(PPROCESS_ATTRIBUTE_LIST),
    ARG_TYPE_PTR(PPROCESS_CREATE_INFO),
    ARG_TYPE_PTR(PPS_APC_ROUTINE),
    ARG_TYPE_PTR(PPS_ATTRIBUTE_LIST),
    ARG_TYPE_PTR(PREMOTE_PORT_VIEW),
    ARG_TYPE_PTR(PRTL_USER_PROCESS_PARAMETERS),
    ARG_TYPE_PTR(PSECURITY_DESCRIPTOR),
    ARG_TYPE_PTR(PSECURITY_QUALITY_OF_SERVICE),
    ARG_TYPE_PTR(PSID),
    ARG_TYPE_PTR(PTIMER_APC_ROUTINE),
    ARG_TYPE_PTR(PTOKEN_DEFAULT_DACL),
    ARG_TYPE_PTR(PTOKEN_GROUPS),
    ARG_TYPE_PTR(PTOKEN_OWNER),
    ARG_TYPE_PTR(PTOKEN_PRIMARY_GROUP),
    ARG_TYPE_PTR(PTOKEN_PRIVILEGES),
    ARG_TYPE_PTR(PTOKEN_SOURCE),
    ARG_TYPE_PTR(PTOKEN_USER),
    ARG_TYPE_PTR(PTRANSACTION_NOTIFICATION),

    // Linux //
    // base types
    ARG_TYPE_NATIVE(linux_size_t),
    ARG_TYPE_PTR_TO_TYPE(linux_size_t_ptr, linux_size_t),
    ARG_TYPE_NATIVE(linux_ssize_t),
    ARG_TYPE_NATIVE(linux_long),
    ARG_TYPE_NATIVE(linux_unsigned_long),
    ARG_TYPE_PTR_TO_TYPE(linux_unsigned_long_ptr, linux_unsigned_long),
    ARG_TYPE_32(linux_unsigned),
    ARG_TYPE_32(linux_int),
    ARG_TYPE_PTR_TO_TYPE(linux_int_ptr, linux_int),
    ARG_TYPE_32(linux_unsigned_int),
    ARG_TYPE_PTR(linux_uchar_ptr),
    ARG_TYPE_32(linux_uint32_t),
    ARG_TYPE_64(linux_uint64_t),
    ARG_TYPE_PTR(linux_char_ptr),
    // special masks and options
    ARG_TYPE_32(linux_intmask_prot_), // int prot, PROT_* flags
    ARG_TYPE_32(linux_intmask_map_), // int flags, MAP_* flags
    ARG_TYPE_32(linux_intopt_pr_), // int option, PR_* values
    ARG_TYPE_32(linux_intopt_arch_), // int code, ARCH_* values
    // other types
    ARG_TYPE_32(linux_ptrace_request),
    ARG_TYPE_32(linux_pid_t),
    ARG_TYPE_32(linux_uid_t),
    ARG_TYPE_32(linux_gid_t),
    ARG_TYPE_32(linux_mode_t),
    ARG_TYPE_32(linux_key_t),
    ARG_TYPE_32(linux_key_serial_t),
    ARG_TYPE_32(linux_socklen_t),
    ARG_TYPE_PTR_TO_TYPE(linux_socklen_t_ptr, linux_socklen_t),
    ARG_TYPE_64(linux_dev_t),
    ARG_TYPE_NATIVE(linux_clock_t),
    ARG_TYPE_NATIVE(linux_caddr_t),
    ARG_TYPE_NATIVE(linux_nfds_t),
    ARG_TYPE_NATIVE(linux_off_t),
    ARG_TYPE_PTR_TO_TYPE(linux_off_t_ptr, linux_off_t),
    ARG_TYPE_64(linux_off64_t),
    ARG_TYPE_PTR_TO_TYPE(linux_off64_t_ptr, linux_off64_t),
    ARG_TYPE_64(linux_loff_t),
    // incomplete types, only pointers
    ARG_TYPE_PTR(linux_nfsctl_arg_ptr), // struct nfsctl_arg *
    ARG_TYPE_PTR(linux_nfsctl_res_ptr), // union nfsctl_res *
    ARG_TYPE_PTR(linux_file_handle_ptr), // struct file_handle *
    ARG_TYPE_PTR(linux_fd_set_ptr), // fd_set *
    ARG_TYPE_PTR(linux_stat_ptr), // struct stat *
    ARG_TYPE_PTR(linux_statfs_ptr),  // struct statfs *
    ARG_TYPE_PTR(linux_pollfd_ptr), // struct pollfd *
    ARG_TYPE_PTR(linux_sigaction_ptr), // struct sigaction *
    ARG_TYPE_PTR(linux_sigset_t_ptr), // sigset_t *
    ARG_TYPE_PTR(linux_sched_param_ptr), // struct sched_param *
    ARG_TYPE_PTR(linux_iovec_ptr), // struct iovec *
    ARG_TYPE_PTR(linux_timeval_ptr), // struct timeval *
    ARG_TYPE_PTR(linux_shmid_ds_ptr), // struct shmid_ds *
    ARG_TYPE_PTR(linux_rusage_ptr), // struct rusage *
    ARG_TYPE_PTR(linux_sembuf_ptr), // struct sembuf *
    ARG_TYPE_PTR(linux_dirent_ptr), // struct dirent *
    ARG_TYPE_PTR(linux_timespec_ptr), // struct timespec *
    ARG_TYPE_PTR(linux_itimerspec_ptr), // struct itimerspec *
    ARG_TYPE_PTR(linux_utimbuf_ptr), // struct utimbuf *
    ARG_TYPE_PTR(linux_sysctl_args_ptr), // struct __sysctl_args *
    ARG_TYPE_PTR(linux_timex_ptr), // struct timex *
    ARG_TYPE_PTR(linux_rlimit_ptr), // struct rlimit *
    ARG_TYPE_PTR(linux_module_ptr), // struct module *
    ARG_TYPE_PTR(linux_sched_attr_ptr), // struct sched_attr *
    ARG_TYPE_PTR(linux_bpf_attr_ptr), // union bpf_attr *
    ARG_TYPE_PTR(linux_statx_ptr), // struct statx *
    ARG_TYPE_PTR(linux_linux_dirent64_ptr), // struct linux_dirent64 *
    ARG_TYPE_PTR(linux_sockaddr_ptr), // struct sockaddr *
    ARG_TYPE_PTR(linux_msghdr_ptr), // struct msghdr *
    ARG_TYPE_PTR(linux_mmsghdr_ptr), // struct mmsghdr *
};

typedef struct
{
    const char* name;
    const char* dir_opt;
    arg_direction_t dir;
    arg_type_t type;
} arg_t;

typedef struct
{
    const char* name;
    const char* display_name;
    arg_type_t ret;
    unsigned int num_args;
    const arg_t* args;
} syscall_t;

typedef struct
{
    void* plugin;
    addr_t size_rva;
    addr_t name_rva;
} pass_ctx_t;

typedef struct
{
    const char* name;
    addr_t base;
    addr_t size;
} resolve_ctx_t;

struct windows_syscall_trap_data_t : public call_result_t
{
    windows_syscall_trap_data_t() : call_result_t()
    {}

    const syscall_t* sc;
    const char* type;
    uint16_t num;

    std::vector<uint64_t> args;
    bool is_ret;
    privilege_mode_t mode;
    std::optional<std::string> module;
    std::optional<std::string> parent_module;
};

#define SYSCALL_EX(_name, _alias, _ret, ...)                     \
   static const arg_t _name ## _arg[] = { __VA_ARGS__ };         \
   static const syscall_t _name = {                              \
     .name = #_name,                                             \
     .display_name = #_alias,                                    \
     .ret = _ret,                                                \
     .num_args = sizeof(_name ## _arg)/sizeof(arg_t),            \
     .args = (const arg_t*)&_name ## _arg                        \
   }

#define SYSCALL(_name, _ret, ...) SYSCALL_EX(_name, _name, _ret, __VA_ARGS__)

struct linux_syscall_data : PluginResult
{
    linux_syscall_data()
        : PluginResult()
        , type()
        , sc()
        , num()
    {
    }

    const syscall_t* sc;
    std::string type;
    uint16_t num;

    std::vector<uint64_t> args;
    bool is_ret;
};

#define ENUM(name, number) { number, #name }

static inline std::unordered_map<uint64_t, std::string> prctl_option =
{
    ENUM(PR_SET_PDEATHSIG, 1),
    ENUM(PR_GET_PDEATHSIG, 2),
    ENUM(PR_GET_DUMPABLE, 3),
    ENUM(PR_SET_DUMPABLE, 4),
    ENUM(PR_GET_UNALIGN, 5),
    ENUM(PR_SET_UNALIGN, 6),
    ENUM(PR_GET_FPEMU, 9),
    ENUM(PR_SET_FPEMU, 10),
    ENUM(PR_GET_FPEXC, 11),
    ENUM(PR_SET_FPEXC, 12),
    ENUM(PR_GET_TIMING, 13),
    ENUM(PR_SET_TIMING, 14),
    ENUM(PR_SET_NAME, 15),
    ENUM(PR_GET_NAME, 16),
    ENUM(PR_GET_ENDIAN, 19),
    ENUM(PR_SET_ENDIAN, 20),
    ENUM(PR_GET_SECCOMP, 21),
    ENUM(PR_SET_SECCOMP, 22),
    ENUM(PR_GET_TSC, 25),
    ENUM(PR_SET_TSC, 26),
    ENUM(PR_GET_SECUREBITS, 27),
    ENUM(PR_SET_SECUREBITS, 28),
    ENUM(PR_SET_TIMERSLACK, 29),
    ENUM(PR_GET_TIMERSLACK, 30),
    ENUM(PR_TASK_PERF_EVENTS_DISABLE, 31),
    ENUM(PR_TASK_PERF_EVENTS_ENABLE, 32),
    ENUM(PR_MCE_KILL, 33),
    ENUM(PR_MCE_KILL_GET, 34),
    ENUM(PR_SET_MM, 35),
    ENUM(PR_SET_CHILD_SUBREAPER, 36),
    ENUM(PR_GET_CHILD_SUBREAPER, 37),
    ENUM(PR_SET_NO_NEW_PRIVS, 38),
    ENUM(PR_GET_NO_NEW_PRIVS, 39),
    ENUM(PR_GET_TID_ADDRESS, 40),
    ENUM(PR_SET_THP_DISABLE, 41),
    ENUM(PR_GET_THP_DISABLE, 42),
    ENUM(PR_MPX_ENABLE_MANAGEMENT, 43),
    ENUM(PR_MPX_DISABLE_MANAGEMENT, 44),
    ENUM(PR_SET_FP_MODE, 45),
    ENUM(PR_GET_FP_MODE, 46),
    ENUM(PR_CAP_AMBIENT, 47),
    ENUM(PR_SVE_SET_VL, 50),
    ENUM(PR_SVE_GET_VL, 51),
    ENUM(PR_GET_SPECULATION_CTRL, 52),
    ENUM(PR_SET_SPECULATION_CTRL, 53),
    ENUM(PR_PAC_RESET_KEYS, 54),
    ENUM(PR_SET_TAGGED_ADDR_CTRL, 55),
    ENUM(PR_GET_TAGGED_ADDR_CTRL, 56),
    ENUM(PR_SET_IO_FLUSHER, 57),
    ENUM(PR_GET_IO_FLUSHER, 58),
    ENUM(PR_SET_SYSCALL_USER_DISPATCH, 59),
    ENUM(PR_PAC_SET_ENABLED_KEYS, 60),
    ENUM(PR_PAC_GET_ENABLED_KEYS, 61),
    ENUM(PR_SCHED_CORE, 62),
    ENUM(PR_SME_SET_VL, 63),
    ENUM(PR_SME_GET_VL, 64),
};

static inline std::unordered_map<uint64_t, std::string> arch_prctl_code =
{
    ENUM(ARCH_SET_GS, 0x1001),
    ENUM(ARCH_SET_FS, 0x1002),
    ENUM(ARCH_GET_FS, 0x1003),
    ENUM(ARCH_GET_GS, 0x1004),
    ENUM(ARCH_GET_CPUID, 0x1011),
    ENUM(ARCH_SET_CPUID, 0x1012),
    ENUM(ARCH_GET_XCOMP_SUPP, 0x1021),
    ENUM(ARCH_GET_XCOMP_PERM, 0x1022),
    ENUM(ARCH_REQ_XCOMP_PERM, 0x1023),
    ENUM(ARCH_GET_XCOMP_GUEST_PERM, 0x1024),
    ENUM(ARCH_REQ_XCOMP_GUEST_PERM, 0x1025),
    ENUM(ARCH_MAP_VDSO_X32, 0x2001),
    ENUM(ARCH_MAP_VDSO_32, 0x2002),
    ENUM(ARCH_MAP_VDSO_64, 0x2003),
};

static const flags_str_t mmap_prot =
{
    REGISTER_FLAG(PROT_READ),
    REGISTER_FLAG(PROT_WRITE),
    REGISTER_FLAG(PROT_EXEC),
    REGISTER_FLAG(PROT_GROWSUP),
    REGISTER_FLAG(PROT_GROWSDOWN),
};

/**
 * Older Linux kernels pass the arguments to the syscall functions via
 * registers, per the ABI. Newer kernels pass the arguments via a
 * struct pt_regs. This change was made Apr 2018 in/near commit
 * fa697140f9a20119a9ec8fd7460cc4314fbdaff3.
 *
 * See kernel: arch/x86/include/asm/syscall_wrapper.h
 *             arch/x86/entry/entry_64.S
 *             arch/x86/include/uapi/asm/ptrace.h
 */

enum linux_pt_regs
{
    PT_REGS_R15,
    PT_REGS_R14,
    PT_REGS_R13,
    PT_REGS_R12,
    PT_REGS_RBP,
    PT_REGS_RBX,

    PT_REGS_R11,
    PT_REGS_R10,
    PT_REGS_R9,
    PT_REGS_R8,
    PT_REGS_RAX,
    PT_REGS_RCX,
    PT_REGS_RDX,
    PT_REGS_RSI,
    PT_REGS_RDI,

    PT_REGS_ORIG_RAX,

    PT_REGS_RIP,
    PT_REGS_CS,
    PT_REGS_EFLAGS,
    PT_REGS_RSP,
    PT_REGS_SS,

    __PT_REGS_MAX
};

// TODO: make global for all plugins, copy from plugin to plugin is bullshit
static const char* linux_pt_regs_offsets_name[__PT_REGS_MAX][2] =
{
    [PT_REGS_R15]      = {"pt_regs", "r15"},
    [PT_REGS_R14]      = {"pt_regs", "r14"},
    [PT_REGS_R13]      = {"pt_regs", "r13"},
    [PT_REGS_R12]      = {"pt_regs", "r12"},
    [PT_REGS_RBP]      = {"pt_regs", "bp"},
    [PT_REGS_RBX]      = {"pt_regs", "bx"},

    [PT_REGS_R11]      = {"pt_regs", "r11"},
    [PT_REGS_R10]      = {"pt_regs", "r10"},
    [PT_REGS_R9]       = {"pt_regs", "r9"},
    [PT_REGS_R8]       = {"pt_regs", "r8"},
    [PT_REGS_RAX]      = {"pt_regs", "ax"},
    [PT_REGS_RCX]      = {"pt_regs", "cx"},
    [PT_REGS_RDX]      = {"pt_regs", "dx"},
    [PT_REGS_RSI]      = {"pt_regs", "si"},
    [PT_REGS_RDI]      = {"pt_regs", "di"},

    [PT_REGS_ORIG_RAX] = {"pt_regs", "orig_ax"},

    [PT_REGS_RIP]      = {"pt_regs", "ip"},
    [PT_REGS_CS]       = {"pt_regs", "cs"},
    [PT_REGS_EFLAGS]   = {"pt_regs", "flags"},
    [PT_REGS_RSP]      = {"pt_regs", "sp"},
    [PT_REGS_SS]       = {"pt_regs", "ss"},
};

}

#endif // commoncsproto_h
