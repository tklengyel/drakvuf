/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
*                                                                         *
* DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
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

#include <libdrakvuf/libdrakvuf.h>

#include "bsodmon.h"
#include "private.h"

/*
 * Bugcheck code list:
 *     https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
 */

void init_bugcheck_win7( bsodmon* monitor )
{
    monitor->bugcheck_map[ 0x00000001 ] = "APC_INDEX_MISMATCH";
    monitor->bugcheck_map[ 0x00000002 ] = "DEVICE_QUEUE_NOT_BUSY";
    monitor->bugcheck_map[ 0x00000003 ] = "INVALID_AFFINITY_SET";
    monitor->bugcheck_map[ 0x00000004 ] = "INVALID_DATA_ACCESS_TRAP";
    monitor->bugcheck_map[ 0x00000005 ] = "INVALID_PROCESS_ATTACH_ATTEMPT";
    monitor->bugcheck_map[ 0x00000006 ] = "INVALID_PROCESS_DETACH_ATTEMPT";
    monitor->bugcheck_map[ 0x00000007 ] = "INVALID_SOFTWARE_INTERRUPT";
    monitor->bugcheck_map[ 0x00000008 ] = "IRQL_NOT_DISPATCH_LEVEL";
    monitor->bugcheck_map[ 0x00000009 ] = "IRQL_NOT_GREATER_OR_EQUAL";
    monitor->bugcheck_map[ 0x0000000A ] = "IRQL_NOT_LESS_OR_EQUAL";
    monitor->bugcheck_map[ 0x0000000B ] = "NO_EXCEPTION_HANDLING_SUPPORT";
    monitor->bugcheck_map[ 0x0000000C ] = "MAXIMUM_WAIT_OBJECTS_EXCEEDED";
    monitor->bugcheck_map[ 0x0000000D ] = "MUTEX_LEVEL_NUMBER_VIOLATION";
    monitor->bugcheck_map[ 0x0000000E ] = "NO_USER_MODE_CONTEXT";
    monitor->bugcheck_map[ 0x0000000F ] = "SPIN_LOCK_ALREADY_OWNED";
    monitor->bugcheck_map[ 0x00000010 ] = "SPIN_LOCK_NOT_OWNED";
    monitor->bugcheck_map[ 0x00000011 ] = "THREAD_NOT_MUTEX_OWNER";
    monitor->bugcheck_map[ 0x00000012 ] = "TRAP_CAUSE_UNKNOWN";
    monitor->bugcheck_map[ 0x00000013 ] = "EMPTY_THREAD_REAPER_LIST";
    monitor->bugcheck_map[ 0x00000014 ] = "CREATE_DELETE_LOCK_NOT_LOCKED";
    monitor->bugcheck_map[ 0x00000015 ] = "LAST_CHANCE_CALLED_FROM_KMODE";
    monitor->bugcheck_map[ 0x00000016 ] = "CID_HANDLE_CREATION";
    monitor->bugcheck_map[ 0x00000017 ] = "CID_HANDLE_DELETION";
    monitor->bugcheck_map[ 0x00000018 ] = "REFERENCE_BY_POINTER";
    monitor->bugcheck_map[ 0x00000019 ] = "BAD_POOL_HEADER";
    monitor->bugcheck_map[ 0x0000001A ] = "MEMORY_MANAGEMENT";
    monitor->bugcheck_map[ 0x0000001B ] = "PFN_SHARE_COUNT";
    monitor->bugcheck_map[ 0x0000001C ] = "PFN_REFERENCE_COUNT";
    monitor->bugcheck_map[ 0x0000001D ] = "NO_SPIN_LOCK_AVAILABLE";
    monitor->bugcheck_map[ 0x0000001E ] = "KMODE_EXCEPTION_NOT_HANDLED";
    monitor->bugcheck_map[ 0x0000001F ] = "SHARED_RESOURCE_CONV_ERROR";
    monitor->bugcheck_map[ 0x00000020 ] = "KERNEL_APC_PENDING_DURING_EXIT";
    monitor->bugcheck_map[ 0x00000021 ] = "QUOTA_UNDERFLOW";
    monitor->bugcheck_map[ 0x00000022 ] = "FILE_SYSTEM";
    monitor->bugcheck_map[ 0x00000023 ] = "FAT_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x00000024 ] = "NTFS_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x00000025 ] = "NPFS_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x00000026 ] = "CDFS_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x00000027 ] = "RDR_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x00000028 ] = "CORRUPT_ACCESS_TOKEN";
    monitor->bugcheck_map[ 0x00000029 ] = "SECURITY_SYSTEM";
    monitor->bugcheck_map[ 0x0000002A ] = "INCONSISTENT_IRP";
    monitor->bugcheck_map[ 0x0000002B ] = "PANIC_STACK_SWITCH";
    monitor->bugcheck_map[ 0x0000002C ] = "PORT_DRIVER_INTERNAL";
    monitor->bugcheck_map[ 0x0000002D ] = "SCSI_DISK_DRIVER_INTERNAL";
    monitor->bugcheck_map[ 0x0000002E ] = "DATA_BUS_ERROR";
    monitor->bugcheck_map[ 0x0000002F ] = "INSTRUCTION_BUS_ERROR";
    monitor->bugcheck_map[ 0x00000030 ] = "SET_OF_INVALID_CONTEXT";
    monitor->bugcheck_map[ 0x00000031 ] = "PHASE0_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000032 ] = "PHASE1_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000033 ] = "UNEXPECTED_INITIALIZATION_CALL";
    monitor->bugcheck_map[ 0x00000034 ] = "CACHE_MANAGER";
    monitor->bugcheck_map[ 0x00000035 ] = "NO_MORE_IRP_STACK_LOCATIONS";
    monitor->bugcheck_map[ 0x00000036 ] = "DEVICE_REFERENCE_COUNT_NOT_ZERO";
    monitor->bugcheck_map[ 0x00000037 ] = "FLOPPY_INTERNAL_ERROR";
    monitor->bugcheck_map[ 0x00000038 ] = "SERIAL_DRIVER_INTERNAL";
    monitor->bugcheck_map[ 0x00000039 ] = "SYSTEM_EXIT_OWNED_MUTEX";
    monitor->bugcheck_map[ 0x0000003A ] = "SYSTEM_UNWIND_PREVIOUS_USER";
    monitor->bugcheck_map[ 0x0000003B ] = "SYSTEM_SERVICE_EXCEPTION";
    monitor->bugcheck_map[ 0x0000003C ] = "INTERRUPT_UNWIND_ATTEMPTED";
    monitor->bugcheck_map[ 0x0000003D ] = "INTERRUPT_EXCEPTION_NOT_HANDLED";
    monitor->bugcheck_map[ 0x0000003E ] = "MULTIPROCESSOR_CONFIGURATION_NOT_SUPPORTED";
    monitor->bugcheck_map[ 0x0000003F ] = "NO_MORE_SYSTEM_PTES";
    monitor->bugcheck_map[ 0x00000040 ] = "TARGET_MDL_TOO_SMALL";
    monitor->bugcheck_map[ 0x00000041 ] = "MUST_SUCCEED_POOL_EMPTY";
    monitor->bugcheck_map[ 0x00000042 ] = "ATDISK_DRIVER_INTERNAL";
    monitor->bugcheck_map[ 0x00000043 ] = "NO_SUCH_PARTITION";
    monitor->bugcheck_map[ 0x00000044 ] = "MULTIPLE_IRP_COMPLETE_REQUESTS";
    monitor->bugcheck_map[ 0x00000045 ] = "INSUFFICIENT_SYSTEM_MAP_REGS";
    monitor->bugcheck_map[ 0x00000046 ] = "DEREF_UNKNOWN_LOGON_SESSION";
    monitor->bugcheck_map[ 0x00000047 ] = "REF_UNKNOWN_LOGON_SESSION";
    monitor->bugcheck_map[ 0x00000048 ] = "CANCEL_STATE_IN_COMPLETED_IRP";
    monitor->bugcheck_map[ 0x00000049 ] = "PAGE_FAULT_WITH_INTERRUPTS_OFF";
    monitor->bugcheck_map[ 0x0000004A ] = "IRQL_GT_ZERO_AT_SYSTEM_SERVICE";
    monitor->bugcheck_map[ 0x0000004B ] = "STREAMS_INTERNAL_ERROR";
    monitor->bugcheck_map[ 0x0000004C ] = "FATAL_UNHANDLED_HARD_ERROR";
    monitor->bugcheck_map[ 0x0000004D ] = "NO_PAGES_AVAILABLE";
    monitor->bugcheck_map[ 0x0000004E ] = "PFN_LIST_CORRUPT";
    monitor->bugcheck_map[ 0x0000004F ] = "NDIS_INTERNAL_ERROR";
    monitor->bugcheck_map[ 0x00000050 ] = "PAGE_FAULT_IN_NONPAGED_AREA";
    monitor->bugcheck_map[ 0x00000051 ] = "REGISTRY_ERROR";
    monitor->bugcheck_map[ 0x00000052 ] = "MAILSLOT_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x00000053 ] = "NO_BOOT_DEVICE";
    monitor->bugcheck_map[ 0x00000054 ] = "LM_SERVER_INTERNAL_ERROR";
    monitor->bugcheck_map[ 0x00000055 ] = "DATA_COHERENCY_EXCEPTION";
    monitor->bugcheck_map[ 0x00000056 ] = "INSTRUCTION_COHERENCY_EXCEPTION";
    monitor->bugcheck_map[ 0x00000057 ] = "XNS_INTERNAL_ERROR";
    monitor->bugcheck_map[ 0x00000058 ] = "FTDISK_INTERNAL_ERROR";
    monitor->bugcheck_map[ 0x00000059 ] = "PINBALL_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x0000005A ] = "CRITICAL_SERVICE_FAILED";
    monitor->bugcheck_map[ 0x0000005B ] = "SET_ENV_VAR_FAILED";
    monitor->bugcheck_map[ 0x0000005C ] = "HAL_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x0000005D ] = "UNSUPPORTED_PROCESSOR";
    monitor->bugcheck_map[ 0x0000005E ] = "OBJECT_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x0000005F ] = "SECURITY_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000060 ] = "PROCESS_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000061 ] = "HAL1_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000062 ] = "OBJECT1_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000063 ] = "SECURITY1_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000064 ] = "SYMBOLIC_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000065 ] = "MEMORY1_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000066 ] = "CACHE_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000067 ] = "CONFIG_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000068 ] = "FILE_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000069 ] = "IO1_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x0000006A ] = "LPC_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x0000006B ] = "PROCESS1_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x0000006C ] = "REFMON_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x0000006D ] = "SESSION1_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x0000006E ] = "SESSION2_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x0000006F ] = "SESSION3_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000070 ] = "SESSION4_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000071 ] = "SESSION5_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000072 ] = "ASSIGN_DRIVE_LETTERS_FAILED";
    monitor->bugcheck_map[ 0x00000073 ] = "CONFIG_LIST_FAILED";
    monitor->bugcheck_map[ 0x00000074 ] = "BAD_SYSTEM_CONFIG_INFO";
    monitor->bugcheck_map[ 0x00000075 ] = "CANNOT_WRITE_CONFIGURATION";
    monitor->bugcheck_map[ 0x00000076 ] = "PROCESS_HAS_LOCKED_PAGES";
    monitor->bugcheck_map[ 0x00000077 ] = "KERNEL_STACK_INPAGE_ERROR";
    monitor->bugcheck_map[ 0x00000078 ] = "PHASE0_EXCEPTION";
    monitor->bugcheck_map[ 0x00000079 ] = "MISMATCHED_HAL";
    monitor->bugcheck_map[ 0x0000007A ] = "KERNEL_DATA_INPAGE_ERROR";
    monitor->bugcheck_map[ 0x0000007B ] = "INACCESSIBLE_BOOT_DEVICE";
    monitor->bugcheck_map[ 0x0000007C ] = "BUGCODE_NDIS_DRIVER";
    monitor->bugcheck_map[ 0x0000007D ] = "INSTALL_MORE_MEMORY";
    monitor->bugcheck_map[ 0x0000007E ] = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED";
    monitor->bugcheck_map[ 0x0000007F ] = "UNEXPECTED_KERNEL_MODE_TRAP";
    monitor->bugcheck_map[ 0x00000080 ] = "NMI_HARDWARE_FAILURE";
    monitor->bugcheck_map[ 0x00000081 ] = "SPIN_LOCK_INIT_FAILURE";
    monitor->bugcheck_map[ 0x00000082 ] = "DFS_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x00000085 ] = "SETUP_FAILURE";
    monitor->bugcheck_map[ 0x0000008B ] = "MBR_CHECKSUM_MISMATCH";
    monitor->bugcheck_map[ 0x0000008E ] = "KERNEL_MODE_EXCEPTION_NOT_HANDLED";
    monitor->bugcheck_map[ 0x0000008F ] = "PP0_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000090 ] = "PP1_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000092 ] = "UP_DRIVER_ON_MP_SYSTEM";
    monitor->bugcheck_map[ 0x00000093 ] = "INVALID_KERNEL_HANDLE";
    monitor->bugcheck_map[ 0x00000094 ] = "KERNEL_STACK_LOCKED_AT_EXIT";
    monitor->bugcheck_map[ 0x00000096 ] = "INVALID_WORK_QUEUE_ITEM";
    monitor->bugcheck_map[ 0x00000097 ] = "BOUND_IMAGE_UNSUPPORTED";
    monitor->bugcheck_map[ 0x00000098 ] = "END_OF_NT_EVALUATION_PERIOD";
    monitor->bugcheck_map[ 0x00000099 ] = "INVALID_REGION_OR_SEGMENT";
    monitor->bugcheck_map[ 0x0000009A ] = "SYSTEM_LICENSE_VIOLATION";
    monitor->bugcheck_map[ 0x0000009B ] = "UDFS_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x0000009C ] = "MACHINE_CHECK_EXCEPTION";
    monitor->bugcheck_map[ 0x0000009E ] = "USER_MODE_HEALTH_MONITOR";
    monitor->bugcheck_map[ 0x0000009F ] = "DRIVER_POWER_STATE_FAILURE";
    monitor->bugcheck_map[ 0x000000A0 ] = "INTERNAL_POWER_ERROR";
    monitor->bugcheck_map[ 0x000000A1 ] = "PCI_BUS_DRIVER_INTERNAL";
    monitor->bugcheck_map[ 0x000000A2 ] = "MEMORY_IMAGE_CORRUPT";
    monitor->bugcheck_map[ 0x000000A3 ] = "ACPI_DRIVER_INTERNAL";
    monitor->bugcheck_map[ 0x000000A4 ] = "CNSS_FILE_SYSTEM_FILTER";
    monitor->bugcheck_map[ 0x000000A5 ] = "ACPI_BIOS_ERROR";
    monitor->bugcheck_map[ 0x000000A7 ] = "BAD_EXHANDLE";
    monitor->bugcheck_map[ 0x000000AB ] = "SESSION_HAS_VALID_POOL_ON_EXIT";
    monitor->bugcheck_map[ 0x000000AC ] = "HAL_MEMORY_ALLOCATION";
    monitor->bugcheck_map[ 0x000000AD ] = "VIDEO_DRIVER_DEBUG_REPORT_REQUEST";
    monitor->bugcheck_map[ 0x000000B1 ] = "BGI_DETECTED_VIOLATION";
    monitor->bugcheck_map[ 0x000000B4 ] = "VIDEO_DRIVER_INIT_FAILURE";
    monitor->bugcheck_map[ 0x000000B8 ] = "ATTEMPTED_SWITCH_FROM_DPC";
    monitor->bugcheck_map[ 0x000000B9 ] = "CHIPSET_DETECTED_ERROR";
    monitor->bugcheck_map[ 0x000000BA ] = "SESSION_HAS_VALID_VIEWS_ON_EXIT";
    monitor->bugcheck_map[ 0x000000BB ] = "NETWORK_BOOT_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x000000BC ] = "NETWORK_BOOT_DUPLICATE_ADDRESS";
    monitor->bugcheck_map[ 0x000000BD ] = "INVALID_HIBERNATED_STATE";
    monitor->bugcheck_map[ 0x000000BE ] = "ATTEMPTED_WRITE_TO_READONLY_MEMORY";
    monitor->bugcheck_map[ 0x000000BF ] = "MUTEX_ALREADY_OWNED";
    monitor->bugcheck_map[ 0x000000C1 ] = "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION";
    monitor->bugcheck_map[ 0x000000C2 ] = "BAD_POOL_CALLER";
    monitor->bugcheck_map[ 0x000000C4 ] = "DRIVER_VERIFIER_DETECTED_VIOLATION";
    monitor->bugcheck_map[ 0x000000C5 ] = "DRIVER_CORRUPTED_EXPOOL";
    monitor->bugcheck_map[ 0x000000C6 ] = "DRIVER_CAUGHT_MODIFYING_FREED_POOL";
    monitor->bugcheck_map[ 0x000000C7 ] = "TIMER_OR_DPC_INVALID";
    monitor->bugcheck_map[ 0x000000C8 ] = "IRQL_UNEXPECTED_VALUE";
    monitor->bugcheck_map[ 0x000000C9 ] = "DRIVER_VERIFIER_IOMANAGER_VIOLATION";
    monitor->bugcheck_map[ 0x000000CA ] = "PNP_DETECTED_FATAL_ERROR";
    monitor->bugcheck_map[ 0x000000CB ] = "DRIVER_LEFT_LOCKED_PAGES_IN_PROCESS";
    monitor->bugcheck_map[ 0x000000CC ] = "PAGE_FAULT_IN_FREED_SPECIAL_POOL";
    monitor->bugcheck_map[ 0x000000CD ] = "PAGE_FAULT_BEYOND_END_OF_ALLOCATION";
    monitor->bugcheck_map[ 0x000000CE ] = "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS";
    monitor->bugcheck_map[ 0x000000CF ] = "TERMINAL_SERVER_DRIVER_MADE_INCORRECT_MEMORY_REFERENCE";
    monitor->bugcheck_map[ 0x000000D0 ] = "DRIVER_CORRUPTED_MMPOOL";
    monitor->bugcheck_map[ 0x000000D1 ] = "DRIVER_IRQL_NOT_LESS_OR_EQUAL";
    monitor->bugcheck_map[ 0x000000D2 ] = "BUGCODE_ID_DRIVER";
    monitor->bugcheck_map[ 0x000000D3 ] = "DRIVER_PORTION_MUST_BE_NONPAGED";
    monitor->bugcheck_map[ 0x000000D4 ] = "SYSTEM_SCAN_AT_RAISED_IRQL_CAUGHT_IMPROPER_DRIVER_UNLOAD";
    monitor->bugcheck_map[ 0x000000D5 ] = "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL";
    monitor->bugcheck_map[ 0x000000D6 ] = "DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION";
    monitor->bugcheck_map[ 0x000000D7 ] = "DRIVER_UNMAPPING_INVALID_VIEW";
    monitor->bugcheck_map[ 0x000000D8 ] = "DRIVER_USED_EXCESSIVE_PTES";
    monitor->bugcheck_map[ 0x000000D9 ] = "LOCKED_PAGES_TRACKER_CORRUPTION";
    monitor->bugcheck_map[ 0x000000DA ] = "SYSTEM_PTE_MISUSE";
    monitor->bugcheck_map[ 0x000000DB ] = "DRIVER_CORRUPTED_SYSPTES";
    monitor->bugcheck_map[ 0x000000DC ] = "DRIVER_INVALID_STACK_ACCESS";
    monitor->bugcheck_map[ 0x000000DE ] = "POOL_CORRUPTION_IN_FILE_AREA";
    monitor->bugcheck_map[ 0x000000DF ] = "IMPERSONATING_WORKER_THREAD";
    monitor->bugcheck_map[ 0x000000E0 ] = "ACPI_BIOS_FATAL_ERROR";
    monitor->bugcheck_map[ 0x000000E1 ] = "WORKER_THREAD_RETURNED_AT_BAD_IRQL";
    monitor->bugcheck_map[ 0x000000E2 ] = "MANUALLY_INITIATED_CRASH";
    monitor->bugcheck_map[ 0x000000E3 ] = "RESOURCE_NOT_OWNED";
    monitor->bugcheck_map[ 0x000000E4 ] = "WORKER_INVALID";
    monitor->bugcheck_map[ 0x000000E6 ] = "DRIVER_VERIFIER_DMA_VIOLATION";
    monitor->bugcheck_map[ 0x000000E7 ] = "INVALID_FLOATING_POINT_STATE";
    monitor->bugcheck_map[ 0x000000E8 ] = "INVALID_CANCEL_OF_FILE_OPEN";
    monitor->bugcheck_map[ 0x000000E9 ] = "ACTIVE_EX_WORKER_THREAD_TERMINATION";
    monitor->bugcheck_map[ 0x000000EA ] = "THREAD_STUCK_IN_DEVICE_DRIVER";
    monitor->bugcheck_map[ 0x000000EB ] = "DIRTY_MAPPED_PAGES_CONGESTION";
    monitor->bugcheck_map[ 0x000000EC ] = "SESSION_HAS_VALID_SPECIAL_POOL_ON_EXIT";
    monitor->bugcheck_map[ 0x000000ED ] = "UNMOUNTABLE_BOOT_VOLUME";
    monitor->bugcheck_map[ 0x000000EF ] = "CRITICAL_PROCESS_DIED";
    monitor->bugcheck_map[ 0x000000F1 ] = "SCSI_VERIFIER_DETECTED_VIOLATION";
    monitor->bugcheck_map[ 0x000000F2 ] = "HARDWARE_INTERRUPT_STORM";
    monitor->bugcheck_map[ 0x000000F3 ] = "DISORDERLY_SHUTDOWN";
    monitor->bugcheck_map[ 0x000000F4 ] = "CRITICAL_OBJECT_TERMINATION";
    monitor->bugcheck_map[ 0x000000F5 ] = "FLTMGR_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x000000F6 ] = "PCI_VERIFIER_DETECTED_VIOLATION";
    monitor->bugcheck_map[ 0x000000F7 ] = "DRIVER_OVERRAN_STACK_BUFFER";
    monitor->bugcheck_map[ 0x000000F8 ] = "RAMDISK_BOOT_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x000000F9 ] = "DRIVER_RETURNED_STATUS_REPARSE_FOR_VOLUME_OPEN";
    monitor->bugcheck_map[ 0x000000FA ] = "HTTP_DRIVER_CORRUPTED";
    monitor->bugcheck_map[ 0x000000FC ] = "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY";
    monitor->bugcheck_map[ 0x000000FD ] = "DIRTY_NOWRITE_PAGES_CONGESTION";
    monitor->bugcheck_map[ 0x000000FE ] = "BUGCODE_USB_DRIVER";
    monitor->bugcheck_map[ 0x000000FF ] = "RESERVE_QUEUE_OVERFLOW";
    monitor->bugcheck_map[ 0x00000100 ] = "LOADER_BLOCK_MISMATCH";
    monitor->bugcheck_map[ 0x00000101 ] = "CLOCK_WATCHDOG_TIMEOUT";
    monitor->bugcheck_map[ 0x00000102 ] = "DPC_WATCHDOG_TIMEOUT";
    monitor->bugcheck_map[ 0x00000103 ] = "MUP_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x00000104 ] = "AGP_INVALID_ACCESS";
    monitor->bugcheck_map[ 0x00000105 ] = "AGP_GART_CORRUPTION";
    monitor->bugcheck_map[ 0x00000106 ] = "AGP_ILLEGALLY_REPROGRAMMED";
    monitor->bugcheck_map[ 0x00000108 ] = "THIRD_PARTY_FILE_SYSTEM_FAILURE";
    monitor->bugcheck_map[ 0x00000109 ] = "CRITICAL_STRUCTURE_CORRUPTION";
    monitor->bugcheck_map[ 0x0000010A ] = "APP_TAGGING_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x0000010C ] = "FSRTL_EXTRA_CREATE_PARAMETER_VIOLATION";
    monitor->bugcheck_map[ 0x0000010D ] = "WDF_VIOLATION";
    monitor->bugcheck_map[ 0x0000010E ] = "VIDEO_MEMORY_MANAGEMENT_INTERNAL";
    monitor->bugcheck_map[ 0x0000010F ] = "RESOURCE_MANAGER_EXCEPTION_NOT_HANDLED";
    monitor->bugcheck_map[ 0x00000111 ] = "RECURSIVE_NMI";
    monitor->bugcheck_map[ 0x00000112 ] = "MSRPC_STATE_VIOLATION";
    monitor->bugcheck_map[ 0x00000113 ] = "VIDEO_DXGKRNL_FATAL_ERROR";
    monitor->bugcheck_map[ 0x00000114 ] = "VIDEO_SHADOW_DRIVER_FATAL_ERROR";
    monitor->bugcheck_map[ 0x00000115 ] = "AGP_INTERNAL";
    monitor->bugcheck_map[ 0x00000116 ] = "VIDEO_TDR_ERROR";
    monitor->bugcheck_map[ 0x00000117 ] = "VIDEO_TDR_TIMEOUT_DETECTED";
    monitor->bugcheck_map[ 0x00000119 ] = "VIDEO_SCHEDULER_INTERNAL_ERROR";
    monitor->bugcheck_map[ 0x0000011A ] = "EM_INITIALIZATION_FAILURE";
    monitor->bugcheck_map[ 0x0000011B ] = "DRIVER_RETURNED_HOLDING_CANCEL_LOCK";
    monitor->bugcheck_map[ 0x0000011C ] = "ATTEMPTED_WRITE_TO_CM_PROTECTED_STORAGE";
    monitor->bugcheck_map[ 0x0000011D ] = "EVENT_TRACING_FATAL_ERROR";
    monitor->bugcheck_map[ 0x0000011E ] = "TOO_MANY_RECURSIVE_FAULTS";
    monitor->bugcheck_map[ 0x0000011F ] = "INVALID_DRIVER_HANDLE";
    monitor->bugcheck_map[ 0x00000120 ] = "BITLOCKER_FATAL_ERROR";
    monitor->bugcheck_map[ 0x00000121 ] = "DRIVER_VIOLATION";
    monitor->bugcheck_map[ 0x00000122 ] = "WHEA_INTERNAL_ERROR";
    monitor->bugcheck_map[ 0x00000123 ] = "CRYPTO_SELF_TEST_FAILURE";
    monitor->bugcheck_map[ 0x00000124 ] = "WHEA_UNCORRECTABLE_ERROR";
    monitor->bugcheck_map[ 0x00000125 ] = "NMR_INVALID_STATE";
    monitor->bugcheck_map[ 0x00000126 ] = "NETIO_INVALID_POOL_CALLER";
    monitor->bugcheck_map[ 0x00000127 ] = "PAGE_NOT_ZERO";
    monitor->bugcheck_map[ 0x00000128 ] = "WORKER_THREAD_RETURNED_WITH_BAD_IO_PRIORITY";
    monitor->bugcheck_map[ 0x00000129 ] = "WORKER_THREAD_RETURNED_WITH_BAD_PAGING_IO_PRIORITY";
    monitor->bugcheck_map[ 0x0000012A ] = "MUI_NO_VALID_SYSTEM_LANGUAGE";
    monitor->bugcheck_map[ 0x0000012B ] = "FAULTY_HARDWARE_CORRUPTED_PAGE";
    monitor->bugcheck_map[ 0x0000012C ] = "EXFAT_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x0000012D ] = "VOLSNAP_OVERLAPPED_TABLE_ACCESS";
    monitor->bugcheck_map[ 0x0000012E ] = "INVALID_MDL_RANGE";
    monitor->bugcheck_map[ 0x0000012F ] = "VHD_BOOT_INITIALIZATION_FAILED";
    monitor->bugcheck_map[ 0x00000130 ] = "DYNAMIC_ADD_PROCESSOR_MISMATCH";
    monitor->bugcheck_map[ 0x00000131 ] = "INVALID_EXTENDED_PROCESSOR_STATE";
    monitor->bugcheck_map[ 0x00000132 ] = "RESOURCE_OWNER_POINTER_INVALID";
    monitor->bugcheck_map[ 0x00000133 ] = "DPC_WATCHDOG_VIOLATION";
    monitor->bugcheck_map[ 0x00000134 ] = "DRIVE_EXTENDER";
    monitor->bugcheck_map[ 0x00000135 ] = "REGISTRY_FILTER_DRIVER_EXCEPTION";
    monitor->bugcheck_map[ 0x00000136 ] = "VHD_BOOT_HOST_VOLUME_NOT_ENOUGH_SPACE";
    monitor->bugcheck_map[ 0x00000137 ] = "WIN32K_HANDLE_MANAGER";
    monitor->bugcheck_map[ 0x00000138 ] = "GPIO_CONTROLLER_DRIVER_ERROR";
    monitor->bugcheck_map[ 0x00000139 ] = "KERNEL_SECURITY_CHECK_FAILURE";
    monitor->bugcheck_map[ 0x0000013A ] = "KERNEL_MODE_HEAP_CORRUPTION";
    monitor->bugcheck_map[ 0x0000013B ] = "PASSIVE_INTERRUPT_ERROR";
    monitor->bugcheck_map[ 0x0000013C ] = "INVALID_IO_BOOST_STATE";
    monitor->bugcheck_map[ 0x0000013D ] = "CRITICAL_INITIALIZATION_FAILURE";
    monitor->bugcheck_map[ 0x00000140 ] = "STORAGE_DEVICE_ABNORMALITY_DETECTED";
    monitor->bugcheck_map[ 0x00000141 ] = "VIDEO_ENGINE_TIMEOUT_DETECTED";
    monitor->bugcheck_map[ 0x00000142 ] = "VIDEO_TDR_APPLICATION_BLOCKED";
    monitor->bugcheck_map[ 0x00000143 ] = "PROCESSOR_DRIVER_INTERNAL";
    monitor->bugcheck_map[ 0x00000144 ] = "BUGCODE_USB3_DRIVER";
    monitor->bugcheck_map[ 0x00000145 ] = "SECURE_BOOT_VIOLATION";
    monitor->bugcheck_map[ 0x00000147 ] = "ABNORMAL_RESET_DETECTED";
    monitor->bugcheck_map[ 0x00000149 ] = "REFS_FILE_SYSTEM";
    monitor->bugcheck_map[ 0x0000014A ] = "KERNEL_WMI_INTERNAL";
    monitor->bugcheck_map[ 0x0000014B ] = "SOC_SUBSYSTEM_FAILURE";
    monitor->bugcheck_map[ 0x0000014C ] = "FATAL_ABNORMAL_RESET_ERROR";
    monitor->bugcheck_map[ 0x0000014D ] = "EXCEPTION_SCOPE_INVALID";
    monitor->bugcheck_map[ 0x0000014E ] = "SOC_CRITICAL_DEVICE_REMOVED";
    monitor->bugcheck_map[ 0x0000014F ] = "PDC_WATCHDOG_TIMEOUT";
    monitor->bugcheck_map[ 0x00000150 ] = "TCPIP_AOAC_NIC_ACTIVE_REFERENCE_LEAK";
    monitor->bugcheck_map[ 0x00000151 ] = "UNSUPPORTED_INSTRUCTION_MODE";
    monitor->bugcheck_map[ 0x00000152 ] = "INVALID_PUSH_LOCK_FLAGS";
    monitor->bugcheck_map[ 0x00000153 ] = "KERNEL_LOCK_ENTRY_LEAKED_ON_THREAD_TERMINATION";
    monitor->bugcheck_map[ 0x00000154 ] = "UNEXPECTED_STORE_EXCEPTION";
    monitor->bugcheck_map[ 0x00000155 ] = "OS_DATA_TAMPERING";
    monitor->bugcheck_map[ 0x00000156 ] = "WINSOCK_DETECTED_HUNG_CLOSESOCKET_LIVEDUMP";
    monitor->bugcheck_map[ 0x00000157 ] = "KERNEL_THREAD_PRIORITY_FLOOR_VIOLATION";
    monitor->bugcheck_map[ 0x00000158 ] = "ILLEGAL_IOMMU_PAGE_FAULT";
    monitor->bugcheck_map[ 0x00000159 ] = "HAL_ILLEGAL_IOMMU_PAGE_FAULT";
    monitor->bugcheck_map[ 0x0000015A ] = "SDBUS_INTERNAL_ERROR";
    monitor->bugcheck_map[ 0x0000015B ] = "WORKER_THREAD_RETURNED_WITH_SYSTEM_PAGE_PRIORITY_ACTIVE";
    monitor->bugcheck_map[ 0x0000015C ] = "PDC_WATCHDOG_TIMEOUT_LIVEDUMP";
    monitor->bugcheck_map[ 0x0000015F ] = "CONNECTED_STANDBY_WATCHDOG_TIMEOUT_LIVEDUMP";
    monitor->bugcheck_map[ 0x00000160 ] = "WIN32K_ATOMIC_CHECK_FAILURE";
    monitor->bugcheck_map[ 0x00000161 ] = "LIVE_SYSTEM_DUMP";
    monitor->bugcheck_map[ 0x00000162 ] = "KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE";
    monitor->bugcheck_map[ 0x00000163 ] = "WORKER_THREAD_TEST_CONDITION";
    monitor->bugcheck_map[ 0x00000164 ] = "WIN32K_CRITICAL_FAILURE";
    monitor->bugcheck_map[ 0x0000016C ] = "INVALID_RUNDOWN_PROTECTION_FLAGS";
    monitor->bugcheck_map[ 0x0000016D ] = "INVALID_SLOT_ALLOCATOR_FLAGS";
    monitor->bugcheck_map[ 0x0000016E ] = "ERESOURCE_INVALID_RELEASE";
    monitor->bugcheck_map[ 0x00000175 ] = "PREVIOUS_FATAL_ABNORMAL_RESET_ERROR";
    monitor->bugcheck_map[ 0x00000178 ] = "ELAM_DRIVER_DETECTED_FATAL_ERROR";
    monitor->bugcheck_map[ 0x0000017B ] = "PROFILER_CONFIGURATION_ILLEGAL";
    monitor->bugcheck_map[ 0x00000187 ] = "VIDEO_DWMINIT_TIMEOUT_FALLBACK_BDD";
    monitor->bugcheck_map[ 0x00000188 ] = "CLUSTER_CSVFS_LIVEDUMP";
    monitor->bugcheck_map[ 0x00000189 ] = "BAD_OBJECT_HEADER";
    monitor->bugcheck_map[ 0x0000018B ] = "SECURE_KERNEL_ERROR";
    monitor->bugcheck_map[ 0x0000018E ] = "KERNEL_PARTITION_REFERENCE_VIOLATION";
    monitor->bugcheck_map[ 0x00000190 ] = "WIN32K_CRITICAL_FAILURE_LIVEDUMP";
    monitor->bugcheck_map[ 0x00000191 ] = "PF_DETECTED_CORRUPTION";
    monitor->bugcheck_map[ 0x00000192 ] = "KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL";
    monitor->bugcheck_map[ 0x00000193 ] = "VIDEO_DXGKRNL_LIVEDUMP";
    monitor->bugcheck_map[ 0x00000195 ] = "SMB_SERVER_LIVEDUMP";
    monitor->bugcheck_map[ 0x00000196 ] = "LOADER_ROLLBACK_DETECTED";
    monitor->bugcheck_map[ 0x00000197 ] = "WIN32K_SECURITY_FAILURE";
    monitor->bugcheck_map[ 0x00000198 ] = "UFX_LIVEDUMP";
    monitor->bugcheck_map[ 0x00000199 ] = "KERNEL_STORAGE_SLOT_IN_USE";
    monitor->bugcheck_map[ 0x0000019A ] = "WORKER_THREAD_RETURNED_WHILE_ATTACHED_TO_SILO";
    monitor->bugcheck_map[ 0x0000019B ] = "TTM_FATAL_ERROR";
    monitor->bugcheck_map[ 0x0000019C ] = "WIN32K_POWER_WATCHDOG_TIMEOUT";
    monitor->bugcheck_map[ 0x0000019D ] = "CLUSTER_SVHDX_LIVEDUMP";
    monitor->bugcheck_map[ 0x000001A3 ] = "CALL_HAS_NOT_RETURNED_WATCHDOG_TIMEOUT_LIVEDUMP";
    monitor->bugcheck_map[ 0x000001A4 ] = "DRIPS_SW_HW_DIVERGENCE_LIVEDUMP";
    monitor->bugcheck_map[ 0x000001C4 ] = "DRIVER_VERIFIER_DETECTED_VIOLATION_LIVEDUMP";
    monitor->bugcheck_map[ 0x000001C5 ] = "IO_THREADPOOL_DEADLOCK_LIVEDUMP";
    monitor->bugcheck_map[ 0x000001CC ] = "EXRESOURCE_TIMEOUT_LIVEDUMP";
    monitor->bugcheck_map[ 0x000001CD ] = "INVALID_CALLBACK_STACK_ADDRESS";
    monitor->bugcheck_map[ 0x000001CE ] = "INVALID_KERNEL_STACK_ADDRESS";
    monitor->bugcheck_map[ 0x000001CF ] = "HARDWARE_WATCHDOG_TIMEOUT";
    monitor->bugcheck_map[ 0x000001D0 ] = "CPI_FIRMWARE_WATCHDOG_TIMEOUT";
    monitor->bugcheck_map[ 0x000001D1 ] = "TELEMETRY_ASSERTS_LIVEDUMP";
    monitor->bugcheck_map[ 0x000001D2 ] = "WORKER_THREAD_INVALID_STATE";
    monitor->bugcheck_map[ 0x000001D3 ] = "WFP_INVALID_OPERATION";
    monitor->bugcheck_map[ 0x000001D4 ] = "UCMUCSI_LIVEDUMP";
    monitor->bugcheck_map[ 0x00000356 ] = "XBOX_ERACTRL_CS_TIMEOUT";
    monitor->bugcheck_map[ 0x00000BFE ] = "BC_BLUETOOTH_VERIFIER_FAULT";
    monitor->bugcheck_map[ 0x00000BFF ] = "BC_BTHMINI_VERIFIER_FAULT";
    monitor->bugcheck_map[ 0x00020001 ] = "HYPERVISOR_ERROR";
    monitor->bugcheck_map[ 0x1000007E ] = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M";
    monitor->bugcheck_map[ 0x1000007F ] = "UNEXPECTED_KERNEL_MODE_TRAP_M";
    monitor->bugcheck_map[ 0x1000008E ] = "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M";
    monitor->bugcheck_map[ 0x100000EA ] = "THREAD_STUCK_IN_DEVICE_DRIVER_M";
    monitor->bugcheck_map[ 0x4000008A ] = "THREAD_TERMINATE_HELD_MUTEX";
    monitor->bugcheck_map[ 0xC0000218 ] = "STATUS_CANNOT_LOAD_REGISTRY_FILE";
    monitor->bugcheck_map[ 0xC000021A ] = "STATUS_SYSTEM_PROCESS_TERMINATED";
    monitor->bugcheck_map[ 0xC0000221 ] = "STATUS_IMAGE_CHECKSUM_MISMATCH";
    monitor->bugcheck_map[ 0xDEADDEAD ] = "MANUALLY_INITIATED_CRASH1";
}



void init_bugcheck_map( bsodmon* monitor, drakvuf_t drakvuf )
{
    init_bugcheck_win7( monitor );
}
