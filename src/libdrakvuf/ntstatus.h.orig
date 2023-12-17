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

#ifndef NTSTATUS_H
#define NTSTATUS_H

#include <stdio.h>

typedef enum ntstatus
{
    STATUS_SUCCESS                                                     = 0x00000000L,
    STATUS_WAIT_1                                                      = 0x00000001L,
    STATUS_WAIT_2                                                      = 0x00000002L,
    STATUS_WAIT_3                                                      = 0x00000003L,
    STATUS_WAIT_63                                                     = 0x0000003FL,
    STATUS_ABANDONED                                                   = 0x00000080L,
    STATUS_ABANDONED_WAIT_63                                           = 0x000000BFL,
    STATUS_USER_APC                                                    = 0x000000C0L,
    STATUS_ALREADY_COMPLETE                                            = 0x000000FFL,
    STATUS_KERNEL_APC                                                  = 0x00000100L,
    STATUS_ALERTED                                                     = 0x00000101L,
    STATUS_TIMEOUT                                                     = 0x00000102L,
    STATUS_PENDING                                                     = 0x00000103L,
    STATUS_REPARSE                                                     = 0x00000104L,
    STATUS_MORE_ENTRIES                                                = 0x00000105L,
    STATUS_NOT_ALL_ASSIGNED                                            = 0x00000106L,
    STATUS_SOME_NOT_MAPPED                                             = 0x00000107L,
    STATUS_OPLOCK_BREAK_IN_PROGRESS                                    = 0x00000108L,
    STATUS_VOLUME_MOUNTED                                              = 0x00000109L,
    STATUS_RXACT_COMMITTED                                             = 0x0000010AL,
    STATUS_NOTIFY_CLEANUP                                              = 0x0000010BL,
    STATUS_NOTIFY_ENUM_DIR                                             = 0x0000010CL,
    STATUS_NO_QUOTAS_FOR_ACCOUNT                                       = 0x0000010DL,
    STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED                            = 0x0000010EL,
    STATUS_PAGE_FAULT_TRANSITION                                       = 0x00000110L,
    STATUS_PAGE_FAULT_DEMAND_ZERO                                      = 0x00000111L,
    STATUS_PAGE_FAULT_COPY_ON_WRITE                                    = 0x00000112L,
    STATUS_PAGE_FAULT_GUARD_PAGE                                       = 0x00000113L,
    STATUS_PAGE_FAULT_PAGING_FILE                                      = 0x00000114L,
    STATUS_CACHE_PAGE_LOCKED                                           = 0x00000115L,
    STATUS_CRASH_DUMP                                                  = 0x00000116L,
    STATUS_BUFFER_ALL_ZEROS                                            = 0x00000117L,
    STATUS_REPARSE_OBJECT                                              = 0x00000118L,
    STATUS_RESOURCE_REQUIREMENTS_CHANGED                               = 0x00000119L,
    STATUS_TRANSLATION_COMPLETE                                        = 0x00000120L,
    STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY                             = 0x00000121L,
    STATUS_NOTHING_TO_TERMINATE                                        = 0x00000122L,
    STATUS_PROCESS_NOT_IN_JOB                                          = 0x00000123L,
    STATUS_PROCESS_IN_JOB                                              = 0x00000124L,
    STATUS_VOLSNAP_HIBERNATE_READY                                     = 0x00000125L,
    STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY                          = 0x00000126L,
    STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED                          = 0x00000127L,
    STATUS_INTERRUPT_STILL_CONNECTED                                   = 0x00000128L,
    STATUS_PROCESS_CLONED                                              = 0x00000129L,
    STATUS_FILE_LOCKED_WITH_ONLY_READERS                               = 0x0000012AL,
    STATUS_FILE_LOCKED_WITH_WRITERS                                    = 0x0000012BL,
    STATUS_VALID_IMAGE_HASH                                            = 0x0000012CL,
    STATUS_VALID_CATALOG_HASH                                          = 0x0000012DL,
    STATUS_VALID_STRONG_CODE_HASH                                      = 0x0000012EL,
    STATUS_GHOSTED                                                     = 0x0000012FL,
    STATUS_DATA_OVERWRITTEN                                            = 0x00000130L,
    STATUS_RESOURCEMANAGER_READ_ONLY                                   = 0x00000202L,
    STATUS_RING_PREVIOUSLY_EMPTY                                       = 0x00000210L,
    STATUS_RING_PREVIOUSLY_FULL                                        = 0x00000211L,
    STATUS_RING_PREVIOUSLY_ABOVE_QUOTA                                 = 0x00000212L,
    STATUS_RING_NEWLY_EMPTY                                            = 0x00000213L,
    STATUS_RING_SIGNAL_OPPOSITE_ENDPOINT                               = 0x00000214L,
    STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE                               = 0x00000215L,
    STATUS_OPLOCK_HANDLE_CLOSED                                        = 0x00000216L,
    STATUS_WAIT_FOR_OPLOCK                                             = 0x00000367L,
    STATUS_REPARSE_GLOBAL                                              = 0x00000368L,
    DBG_EXCEPTION_HANDLED                                              = 0x00010001L,
    DBG_CONTINUE                                                       = 0x00010002L,
    STATUS_FLT_IO_COMPLETE                                             = 0x001C0001L,
    STATUS_OBJECT_NAME_EXISTS                                          = 0x40000000L,
    STATUS_THREAD_WAS_SUSPENDED                                        = 0x40000001L,
    STATUS_WORKING_SET_LIMIT_RANGE                                     = 0x40000002L,
    STATUS_IMAGE_NOT_AT_BASE                                           = 0x40000003L,
    STATUS_RXACT_STATE_CREATED                                         = 0x40000004L,
    STATUS_SEGMENT_NOTIFICATION                                        = 0x40000005L,
    STATUS_LOCAL_USER_SESSION_KEY                                      = 0x40000006L,
    STATUS_BAD_CURRENT_DIRECTORY                                       = 0x40000007L,
    STATUS_SERIAL_MORE_WRITES                                          = 0x40000008L,
    STATUS_REGISTRY_RECOVERED                                          = 0x40000009L,
    STATUS_FT_READ_RECOVERY_FROM_BACKUP                                = 0x4000000AL,
    STATUS_FT_WRITE_RECOVERY                                           = 0x4000000BL,
    STATUS_SERIAL_COUNTER_TIMEOUT                                      = 0x4000000CL,
    STATUS_NULL_LM_PASSWORD                                            = 0x4000000DL,
    STATUS_IMAGE_MACHINE_TYPE_MISMATCH                                 = 0x4000000EL,
    STATUS_RECEIVE_PARTIAL                                             = 0x4000000FL,
    STATUS_RECEIVE_EXPEDITED                                           = 0x40000010L,
    STATUS_RECEIVE_PARTIAL_EXPEDITED                                   = 0x40000011L,
    STATUS_EVENT_DONE                                                  = 0x40000012L,
    STATUS_EVENT_PENDING                                               = 0x40000013L,
    STATUS_CHECKING_FILE_SYSTEM                                        = 0x40000014L,
    STATUS_FATAL_APP_EXIT                                              = 0x40000015L,
    STATUS_PREDEFINED_HANDLE                                           = 0x40000016L,
    STATUS_WAS_UNLOCKED                                                = 0x40000017L,
    STATUS_SERVICE_NOTIFICATION                                        = 0x40000018L,
    STATUS_WAS_LOCKED                                                  = 0x40000019L,
    STATUS_LOG_HARD_ERROR                                              = 0x4000001AL,
    STATUS_ALREADY_WIN32                                               = 0x4000001BL,
    STATUS_WX86_UNSIMULATE                                             = 0x4000001CL,
    STATUS_WX86_CONTINUE                                               = 0x4000001DL,
    STATUS_WX86_SINGLE_STEP                                            = 0x4000001EL,
    STATUS_WX86_BREAKPOINT                                             = 0x4000001FL,
    STATUS_WX86_EXCEPTION_CONTINUE                                     = 0x40000020L,
    STATUS_WX86_EXCEPTION_LASTCHANCE                                   = 0x40000021L,
    STATUS_WX86_EXCEPTION_CHAIN                                        = 0x40000022L,
    STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE                             = 0x40000023L,
    STATUS_NO_YIELD_PERFORMED                                          = 0x40000024L,
    STATUS_TIMER_RESUME_IGNORED                                        = 0x40000025L,
    STATUS_ARBITRATION_UNHANDLED                                       = 0x40000026L,
    STATUS_CARDBUS_NOT_SUPPORTED                                       = 0x40000027L,
    STATUS_WX86_CREATEWX86TIB                                          = 0x40000028L,
    STATUS_MP_PROCESSOR_MISMATCH                                       = 0x40000029L,
    STATUS_HIBERNATED                                                  = 0x4000002AL,
    STATUS_RESUME_HIBERNATION                                          = 0x4000002BL,
    STATUS_FIRMWARE_UPDATED                                            = 0x4000002CL,
    STATUS_DRIVERS_LEAKING_LOCKED_PAGES                                = 0x4000002DL,
    STATUS_MESSAGE_RETRIEVED                                           = 0x4000002EL,
    STATUS_SYSTEM_POWERSTATE_TRANSITION                                = 0x4000002FL,
    STATUS_ALPC_CHECK_COMPLETION_LIST                                  = 0x40000030L,
    STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION                        = 0x40000031L,
    STATUS_ACCESS_AUDIT_BY_POLICY                                      = 0x40000032L,
    STATUS_ABANDON_HIBERFILE                                           = 0x40000033L,
    STATUS_BIZRULES_NOT_ENABLED                                        = 0x40000034L,
    STATUS_FT_READ_FROM_COPY                                           = 0x40000035L,
    STATUS_IMAGE_AT_DIFFERENT_BASE                                     = 0x40000036L,
    STATUS_PATCH_DEFERRED                                              = 0x40000037L,
    DBG_REPLY_LATER                                                    = 0x40010001L,
    DBG_UNABLE_TO_PROVIDE_HANDLE                                       = 0x40010002L,
    DBG_TERMINATE_THREAD                                               = 0x40010003L,
    DBG_TERMINATE_PROCESS                                              = 0x40010004L,
    DBG_CONTROL_C                                                      = 0x40010005L,
    DBG_PRINTEXCEPTION_C                                               = 0x40010006L,
    DBG_RIPEXCEPTION                                                   = 0x40010007L,
    DBG_CONTROL_BREAK                                                  = 0x40010008L,
    DBG_COMMAND_EXCEPTION                                              = 0x40010009L,
    DBG_PRINTEXCEPTION_WIDE_C                                          = 0x4001000AL,
    STATUS_HEURISTIC_DAMAGE_POSSIBLE                                   = 0x40190001L,
    STATUS_GUARD_PAGE_VIOLATION                                        = 0x80000001L,
    STATUS_DATATYPE_MISALIGNMENT                                       = 0x80000002L,
    STATUS_BREAKPOINT                                                  = 0x80000003L,
    STATUS_SINGLE_STEP                                                 = 0x80000004L,
    STATUS_BUFFER_OVERFLOW                                             = 0x80000005L,
    STATUS_NO_MORE_FILES                                               = 0x80000006L,
    STATUS_WAKE_SYSTEM_DEBUGGER                                        = 0x80000007L,
    STATUS_HANDLES_CLOSED                                              = 0x8000000AL,
    STATUS_NO_INHERITANCE                                              = 0x8000000BL,
    STATUS_GUID_SUBSTITUTION_MADE                                      = 0x8000000CL,
    STATUS_PARTIAL_COPY                                                = 0x8000000DL,
    STATUS_DEVICE_PAPER_EMPTY                                          = 0x8000000EL,
    STATUS_DEVICE_POWERED_OFF                                          = 0x8000000FL,
    STATUS_DEVICE_OFF_LINE                                             = 0x80000010L,
    STATUS_DEVICE_BUSY                                                 = 0x80000011L,
    STATUS_NO_MORE_EAS                                                 = 0x80000012L,
    STATUS_INVALID_EA_NAME                                             = 0x80000013L,
    STATUS_EA_LIST_INCONSISTENT                                        = 0x80000014L,
    STATUS_INVALID_EA_FLAG                                             = 0x80000015L,
    STATUS_VERIFY_REQUIRED                                             = 0x80000016L,
    STATUS_EXTRANEOUS_INFORMATION                                      = 0x80000017L,
    STATUS_RXACT_COMMIT_NECESSARY                                      = 0x80000018L,
    STATUS_NO_MORE_ENTRIES                                             = 0x8000001AL,
    STATUS_FILEMARK_DETECTED                                           = 0x8000001BL,
    STATUS_MEDIA_CHANGED                                               = 0x8000001CL,
    STATUS_BUS_RESET                                                   = 0x8000001DL,
    STATUS_END_OF_MEDIA                                                = 0x8000001EL,
    STATUS_BEGINNING_OF_MEDIA                                          = 0x8000001FL,
    STATUS_MEDIA_CHECK                                                 = 0x80000020L,
    STATUS_SETMARK_DETECTED                                            = 0x80000021L,
    STATUS_NO_DATA_DETECTED                                            = 0x80000022L,
    STATUS_REDIRECTOR_HAS_OPEN_HANDLES                                 = 0x80000023L,
    STATUS_SERVER_HAS_OPEN_HANDLES                                     = 0x80000024L,
    STATUS_ALREADY_DISCONNECTED                                        = 0x80000025L,
    STATUS_LONGJUMP                                                    = 0x80000026L,
    STATUS_CLEANER_CARTRIDGE_INSTALLED                                 = 0x80000027L,
    STATUS_PLUGPLAY_QUERY_VETOED                                       = 0x80000028L,
    STATUS_UNWIND_CONSOLIDATE                                          = 0x80000029L,
    STATUS_REGISTRY_HIVE_RECOVERED                                     = 0x8000002AL,
    STATUS_DLL_MIGHT_BE_INSECURE                                       = 0x8000002BL,
    STATUS_DLL_MIGHT_BE_INCOMPATIBLE                                   = 0x8000002CL,
    STATUS_STOPPED_ON_SYMLINK                                          = 0x8000002DL,
    STATUS_CANNOT_GRANT_REQUESTED_OPLOCK                               = 0x8000002EL,
    STATUS_NO_ACE_CONDITION                                            = 0x8000002FL,
    STATUS_DEVICE_SUPPORT_IN_PROGRESS                                  = 0x80000030L,
    STATUS_DEVICE_POWER_CYCLE_REQUIRED                                 = 0x80000031L,
    STATUS_NO_WORK_DONE                                                = 0x80000032L,
    DBG_EXCEPTION_NOT_HANDLED                                          = 0x80010001L,
    STATUS_CLUSTER_NODE_ALREADY_UP                                     = 0x80130001L,
    STATUS_CLUSTER_NODE_ALREADY_DOWN                                   = 0x80130002L,
    STATUS_CLUSTER_NETWORK_ALREADY_ONLINE                              = 0x80130003L,
    STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE                             = 0x80130004L,
    STATUS_CLUSTER_NODE_ALREADY_MEMBER                                 = 0x80130005L,
    STATUS_FLT_BUFFER_TOO_SMALL                                        = 0x801C0001L,
    STATUS_FVE_PARTIAL_METADATA                                        = 0x80210001L,
    STATUS_FVE_TRANSIENT_STATE                                         = 0x80210002L,
    STATUS_CLOUD_FILE_PROPERTY_BLOB_CHECKSUM_MISMATCH                  = 0x8000CF00L,
    STATUS_UNSUCCESSFUL                                                = 0xC0000001L,
    STATUS_NOT_IMPLEMENTED                                             = 0xC0000002L,
    STATUS_INVALID_INFO_CLASS                                          = 0xC0000003L,
    STATUS_INFO_LENGTH_MISMATCH                                        = 0xC0000004L,
    STATUS_ACCESS_VIOLATION                                            = 0xC0000005L,
    STATUS_IN_PAGE_ERROR                                               = 0xC0000006L,
    STATUS_PAGEFILE_QUOTA                                              = 0xC0000007L,
    STATUS_INVALID_HANDLE                                              = 0xC0000008L,
    STATUS_BAD_INITIAL_STACK                                           = 0xC0000009L,
    STATUS_BAD_INITIAL_PC                                              = 0xC000000AL,
    STATUS_INVALID_CID                                                 = 0xC000000BL,
    STATUS_TIMER_NOT_CANCELED                                          = 0xC000000CL,
    STATUS_INVALID_PARAMETER                                           = 0xC000000DL,
    STATUS_NO_SUCH_DEVICE                                              = 0xC000000EL,
    STATUS_NO_SUCH_FILE                                                = 0xC000000FL,
    STATUS_INVALID_DEVICE_REQUEST                                      = 0xC0000010L,
    STATUS_END_OF_FILE                                                 = 0xC0000011L,
    STATUS_WRONG_VOLUME                                                = 0xC0000012L,
    STATUS_NO_MEDIA_IN_DEVICE                                          = 0xC0000013L,
    STATUS_UNRECOGNIZED_MEDIA                                          = 0xC0000014L,
    STATUS_NONEXISTENT_SECTOR                                          = 0xC0000015L,
    STATUS_MORE_PROCESSING_REQUIRED                                    = 0xC0000016L,
    STATUS_NO_MEMORY                                                   = 0xC0000017L,
    STATUS_CONFLICTING_ADDRESSES                                       = 0xC0000018L,
    STATUS_NOT_MAPPED_VIEW                                             = 0xC0000019L,
    STATUS_UNABLE_TO_FREE_VM                                           = 0xC000001AL,
    STATUS_UNABLE_TO_DELETE_SECTION                                    = 0xC000001BL,
    STATUS_INVALID_SYSTEM_SERVICE                                      = 0xC000001CL,
    STATUS_ILLEGAL_INSTRUCTION                                         = 0xC000001DL,
    STATUS_INVALID_LOCK_SEQUENCE                                       = 0xC000001EL,
    STATUS_INVALID_VIEW_SIZE                                           = 0xC000001FL,
    STATUS_INVALID_FILE_FOR_SECTION                                    = 0xC0000020L,
    STATUS_ALREADY_COMMITTED                                           = 0xC0000021L,
    STATUS_ACCESS_DENIED                                               = 0xC0000022L,
    STATUS_BUFFER_TOO_SMALL                                            = 0xC0000023L,
    STATUS_OBJECT_TYPE_MISMATCH                                        = 0xC0000024L,
    STATUS_NONCONTINUABLE_EXCEPTION                                    = 0xC0000025L,
    STATUS_INVALID_DISPOSITION                                         = 0xC0000026L,
    STATUS_UNWIND                                                      = 0xC0000027L,
    STATUS_BAD_STACK                                                   = 0xC0000028L,
    STATUS_INVALID_UNWIND_TARGET                                       = 0xC0000029L,
    STATUS_NOT_LOCKED                                                  = 0xC000002AL,
    STATUS_PARITY_ERROR                                                = 0xC000002BL,
    STATUS_UNABLE_TO_DECOMMIT_VM                                       = 0xC000002CL,
    STATUS_NOT_COMMITTED                                               = 0xC000002DL,
    STATUS_INVALID_PORT_ATTRIBUTES                                     = 0xC000002EL,
    STATUS_PORT_MESSAGE_TOO_LONG                                       = 0xC000002FL,
    STATUS_INVALID_PARAMETER_MIX                                       = 0xC0000030L,
    STATUS_INVALID_QUOTA_LOWER                                         = 0xC0000031L,
    STATUS_DISK_CORRUPT_ERROR                                          = 0xC0000032L,
    STATUS_OBJECT_NAME_INVALID                                         = 0xC0000033L,
    STATUS_OBJECT_NAME_NOT_FOUND                                       = 0xC0000034L,
    STATUS_OBJECT_NAME_COLLISION                                       = 0xC0000035L,
    STATUS_PORT_DO_NOT_DISTURB                                         = 0xC0000036L,
    STATUS_PORT_DISCONNECTED                                           = 0xC0000037L,
    STATUS_DEVICE_ALREADY_ATTACHED                                     = 0xC0000038L,
    STATUS_OBJECT_PATH_INVALID                                         = 0xC0000039L,
    STATUS_OBJECT_PATH_NOT_FOUND                                       = 0xC000003AL,
    STATUS_OBJECT_PATH_SYNTAX_BAD                                      = 0xC000003BL,
    STATUS_DATA_OVERRUN                                                = 0xC000003CL,
    STATUS_DATA_LATE_ERROR                                             = 0xC000003DL,
    STATUS_DATA_ERROR                                                  = 0xC000003EL,
    STATUS_CRC_ERROR                                                   = 0xC000003FL,
    STATUS_SECTION_TOO_BIG                                             = 0xC0000040L,
    STATUS_PORT_CONNECTION_REFUSED                                     = 0xC0000041L,
    STATUS_INVALID_PORT_HANDLE                                         = 0xC0000042L,
    STATUS_SHARING_VIOLATION                                           = 0xC0000043L,
    STATUS_QUOTA_EXCEEDED                                              = 0xC0000044L,
    STATUS_INVALID_PAGE_PROTECTION                                     = 0xC0000045L,
    STATUS_MUTANT_NOT_OWNED                                            = 0xC0000046L,
    STATUS_SEMAPHORE_LIMIT_EXCEEDED                                    = 0xC0000047L,
    STATUS_PORT_ALREADY_SET                                            = 0xC0000048L,
    STATUS_SECTION_NOT_IMAGE                                           = 0xC0000049L,
    STATUS_SUSPEND_COUNT_EXCEEDED                                      = 0xC000004AL,
    STATUS_THREAD_IS_TERMINATING                                       = 0xC000004BL,
    STATUS_BAD_WORKING_SET_LIMIT                                       = 0xC000004CL,
    STATUS_INCOMPATIBLE_FILE_MAP                                       = 0xC000004DL,
    STATUS_SECTION_PROTECTION                                          = 0xC000004EL,
    STATUS_EAS_NOT_SUPPORTED                                           = 0xC000004FL,
    STATUS_EA_TOO_LARGE                                                = 0xC0000050L,
    STATUS_NONEXISTENT_EA_ENTRY                                        = 0xC0000051L,
    STATUS_NO_EAS_ON_FILE                                              = 0xC0000052L,
    STATUS_EA_CORRUPT_ERROR                                            = 0xC0000053L,
    STATUS_FILE_LOCK_CONFLICT                                          = 0xC0000054L,
    STATUS_LOCK_NOT_GRANTED                                            = 0xC0000055L,
    STATUS_DELETE_PENDING                                              = 0xC0000056L,
    STATUS_CTL_FILE_NOT_SUPPORTED                                      = 0xC0000057L,
    STATUS_UNKNOWN_REVISION                                            = 0xC0000058L,
    STATUS_REVISION_MISMATCH                                           = 0xC0000059L,
    STATUS_INVALID_OWNER                                               = 0xC000005AL,
    STATUS_INVALID_PRIMARY_GROUP                                       = 0xC000005BL,
    STATUS_NO_IMPERSONATION_TOKEN                                      = 0xC000005CL,
    STATUS_CANT_DISABLE_MANDATORY                                      = 0xC000005DL,
    STATUS_NO_LOGON_SERVERS                                            = 0xC000005EL,
    STATUS_NO_SUCH_LOGON_SESSION                                       = 0xC000005FL,
    STATUS_NO_SUCH_PRIVILEGE                                           = 0xC0000060L,
    STATUS_PRIVILEGE_NOT_HELD                                          = 0xC0000061L,
    STATUS_INVALID_ACCOUNT_NAME                                        = 0xC0000062L,
    STATUS_USER_EXISTS                                                 = 0xC0000063L,
    STATUS_NO_SUCH_USER                                                = 0xC0000064L,
    STATUS_GROUP_EXISTS                                                = 0xC0000065L,
    STATUS_NO_SUCH_GROUP                                               = 0xC0000066L,
    STATUS_MEMBER_IN_GROUP                                             = 0xC0000067L,
    STATUS_MEMBER_NOT_IN_GROUP                                         = 0xC0000068L,
    STATUS_LAST_ADMIN                                                  = 0xC0000069L,
    STATUS_WRONG_PASSWORD                                              = 0xC000006AL,
    STATUS_ILL_FORMED_PASSWORD                                         = 0xC000006BL,
    STATUS_PASSWORD_RESTRICTION                                        = 0xC000006CL,
    STATUS_LOGON_FAILURE                                               = 0xC000006DL,
    STATUS_ACCOUNT_RESTRICTION                                         = 0xC000006EL,
    STATUS_INVALID_LOGON_HOURS                                         = 0xC000006FL,
    STATUS_INVALID_WORKSTATION                                         = 0xC0000070L,
    STATUS_PASSWORD_EXPIRED                                            = 0xC0000071L,
    STATUS_ACCOUNT_DISABLED                                            = 0xC0000072L,
    STATUS_NONE_MAPPED                                                 = 0xC0000073L,
    STATUS_TOO_MANY_LUIDS_REQUESTED                                    = 0xC0000074L,
    STATUS_LUIDS_EXHAUSTED                                             = 0xC0000075L,
    STATUS_INVALID_SUB_AUTHORITY                                       = 0xC0000076L,
    STATUS_INVALID_ACL                                                 = 0xC0000077L,
    STATUS_INVALID_SID                                                 = 0xC0000078L,
    STATUS_INVALID_SECURITY_DESCR                                      = 0xC0000079L,
    STATUS_PROCEDURE_NOT_FOUND                                         = 0xC000007AL,
    STATUS_INVALID_IMAGE_FORMAT                                        = 0xC000007BL,
    STATUS_NO_TOKEN                                                    = 0xC000007CL,
    STATUS_BAD_INHERITANCE_ACL                                         = 0xC000007DL,
    STATUS_RANGE_NOT_LOCKED                                            = 0xC000007EL,
    STATUS_DISK_FULL                                                   = 0xC000007FL,
    STATUS_SERVER_DISABLED                                             = 0xC0000080L,
    STATUS_SERVER_NOT_DISABLED                                         = 0xC0000081L,
    STATUS_TOO_MANY_GUIDS_REQUESTED                                    = 0xC0000082L,
    STATUS_GUIDS_EXHAUSTED                                             = 0xC0000083L,
    STATUS_INVALID_ID_AUTHORITY                                        = 0xC0000084L,
    STATUS_AGENTS_EXHAUSTED                                            = 0xC0000085L,
    STATUS_INVALID_VOLUME_LABEL                                        = 0xC0000086L,
    STATUS_SECTION_NOT_EXTENDED                                        = 0xC0000087L,
    STATUS_NOT_MAPPED_DATA                                             = 0xC0000088L,
    STATUS_RESOURCE_DATA_NOT_FOUND                                     = 0xC0000089L,
    STATUS_RESOURCE_TYPE_NOT_FOUND                                     = 0xC000008AL,
    STATUS_RESOURCE_NAME_NOT_FOUND                                     = 0xC000008BL,
    STATUS_ARRAY_BOUNDS_EXCEEDED                                       = 0xC000008CL,
    STATUS_FLOAT_DENORMAL_OPERAND                                      = 0xC000008DL,
    STATUS_FLOAT_DIVIDE_BY_ZERO                                        = 0xC000008EL,
    STATUS_FLOAT_INEXACT_RESULT                                        = 0xC000008FL,
    STATUS_FLOAT_INVALID_OPERATION                                     = 0xC0000090L,
    STATUS_FLOAT_OVERFLOW                                              = 0xC0000091L,
    STATUS_FLOAT_STACK_CHECK                                           = 0xC0000092L,
    STATUS_FLOAT_UNDERFLOW                                             = 0xC0000093L,
    STATUS_INTEGER_DIVIDE_BY_ZERO                                      = 0xC0000094L,
    STATUS_INTEGER_OVERFLOW                                            = 0xC0000095L,
    STATUS_PRIVILEGED_INSTRUCTION                                      = 0xC0000096L,
    STATUS_TOO_MANY_PAGING_FILES                                       = 0xC0000097L,
    STATUS_FILE_INVALID                                                = 0xC0000098L,
    STATUS_ALLOTTED_SPACE_EXCEEDED                                     = 0xC0000099L,
    STATUS_INSUFFICIENT_RESOURCES                                      = 0xC000009AL,
    STATUS_DFS_EXIT_PATH_FOUND                                         = 0xC000009BL,
    STATUS_DEVICE_DATA_ERROR                                           = 0xC000009CL,
    STATUS_DEVICE_NOT_CONNECTED                                        = 0xC000009DL,
    STATUS_DEVICE_POWER_FAILURE                                        = 0xC000009EL,
    STATUS_FREE_VM_NOT_AT_BASE                                         = 0xC000009FL,
    STATUS_MEMORY_NOT_ALLOCATED                                        = 0xC00000A0L,
    STATUS_WORKING_SET_QUOTA                                           = 0xC00000A1L,
    STATUS_MEDIA_WRITE_PROTECTED                                       = 0xC00000A2L,
    STATUS_DEVICE_NOT_READY                                            = 0xC00000A3L,
    STATUS_INVALID_GROUP_ATTRIBUTES                                    = 0xC00000A4L,
    STATUS_BAD_IMPERSONATION_LEVEL                                     = 0xC00000A5L,
    STATUS_CANT_OPEN_ANONYMOUS                                         = 0xC00000A6L,
    STATUS_BAD_VALIDATION_CLASS                                        = 0xC00000A7L,
    STATUS_BAD_TOKEN_TYPE                                              = 0xC00000A8L,
    STATUS_BAD_MASTER_BOOT_RECORD                                      = 0xC00000A9L,
    STATUS_INSTRUCTION_MISALIGNMENT                                    = 0xC00000AAL,
    STATUS_INSTANCE_NOT_AVAILABLE                                      = 0xC00000ABL,
    STATUS_PIPE_NOT_AVAILABLE                                          = 0xC00000ACL,
    STATUS_INVALID_PIPE_STATE                                          = 0xC00000ADL,
    STATUS_PIPE_BUSY                                                   = 0xC00000AEL,
    STATUS_ILLEGAL_FUNCTION                                            = 0xC00000AFL,
    STATUS_PIPE_DISCONNECTED                                           = 0xC00000B0L,
    STATUS_PIPE_CLOSING                                                = 0xC00000B1L,
    STATUS_PIPE_CONNECTED                                              = 0xC00000B2L,
    STATUS_PIPE_LISTENING                                              = 0xC00000B3L,
    STATUS_INVALID_READ_MODE                                           = 0xC00000B4L,
    STATUS_IO_TIMEOUT                                                  = 0xC00000B5L,
    STATUS_FILE_FORCED_CLOSED                                          = 0xC00000B6L,
    STATUS_PROFILING_NOT_STARTED                                       = 0xC00000B7L,
    STATUS_PROFILING_NOT_STOPPED                                       = 0xC00000B8L,
    STATUS_COULD_NOT_INTERPRET                                         = 0xC00000B9L,
    STATUS_FILE_IS_A_DIRECTORY                                         = 0xC00000BAL,
    STATUS_NOT_SUPPORTED                                               = 0xC00000BBL,
    STATUS_REMOTE_NOT_LISTENING                                        = 0xC00000BCL,
    STATUS_DUPLICATE_NAME                                              = 0xC00000BDL,
    STATUS_BAD_NETWORK_PATH                                            = 0xC00000BEL,
    STATUS_NETWORK_BUSY                                                = 0xC00000BFL,
    STATUS_DEVICE_DOES_NOT_EXIST                                       = 0xC00000C0L,
    STATUS_TOO_MANY_COMMANDS                                           = 0xC00000C1L,
    STATUS_ADAPTER_HARDWARE_ERROR                                      = 0xC00000C2L,
    STATUS_INVALID_NETWORK_RESPONSE                                    = 0xC00000C3L,
    STATUS_UNEXPECTED_NETWORK_ERROR                                    = 0xC00000C4L,
    STATUS_BAD_REMOTE_ADAPTER                                          = 0xC00000C5L,
    STATUS_PRINT_QUEUE_FULL                                            = 0xC00000C6L,
    STATUS_NO_SPOOL_SPACE                                              = 0xC00000C7L,
    STATUS_PRINT_CANCELLED                                             = 0xC00000C8L,
    STATUS_NETWORK_NAME_DELETED                                        = 0xC00000C9L,
    STATUS_NETWORK_ACCESS_DENIED                                       = 0xC00000CAL,
    STATUS_BAD_DEVICE_TYPE                                             = 0xC00000CBL,
    STATUS_BAD_NETWORK_NAME                                            = 0xC00000CCL,
    STATUS_TOO_MANY_NAMES                                              = 0xC00000CDL,
    STATUS_TOO_MANY_SESSIONS                                           = 0xC00000CEL,
    STATUS_SHARING_PAUSED                                              = 0xC00000CFL,
    STATUS_REQUEST_NOT_ACCEPTED                                        = 0xC00000D0L,
    STATUS_REDIRECTOR_PAUSED                                           = 0xC00000D1L,
    STATUS_NET_WRITE_FAULT                                             = 0xC00000D2L,
    STATUS_PROFILING_AT_LIMIT                                          = 0xC00000D3L,
    STATUS_NOT_SAME_DEVICE                                             = 0xC00000D4L,
    STATUS_FILE_RENAMED                                                = 0xC00000D5L,
    STATUS_VIRTUAL_CIRCUIT_CLOSED                                      = 0xC00000D6L,
    STATUS_NO_SECURITY_ON_OBJECT                                       = 0xC00000D7L,
    STATUS_CANT_WAIT                                                   = 0xC00000D8L,
    STATUS_PIPE_EMPTY                                                  = 0xC00000D9L,
    STATUS_CANT_ACCESS_DOMAIN_INFO                                     = 0xC00000DAL,
    STATUS_CANT_TERMINATE_SELF                                         = 0xC00000DBL,
    STATUS_INVALID_SERVER_STATE                                        = 0xC00000DCL,
    STATUS_INVALID_DOMAIN_STATE                                        = 0xC00000DDL,
    STATUS_INVALID_DOMAIN_ROLE                                         = 0xC00000DEL,
    STATUS_NO_SUCH_DOMAIN                                              = 0xC00000DFL,
    STATUS_DOMAIN_EXISTS                                               = 0xC00000E0L,
    STATUS_DOMAIN_LIMIT_EXCEEDED                                       = 0xC00000E1L,
    STATUS_OPLOCK_NOT_GRANTED                                          = 0xC00000E2L,
    STATUS_INVALID_OPLOCK_PROTOCOL                                     = 0xC00000E3L,
    STATUS_INTERNAL_DB_CORRUPTION                                      = 0xC00000E4L,
    STATUS_INTERNAL_ERROR                                              = 0xC00000E5L,
    STATUS_GENERIC_NOT_MAPPED                                          = 0xC00000E6L,
    STATUS_BAD_DESCRIPTOR_FORMAT                                       = 0xC00000E7L,
    STATUS_INVALID_USER_BUFFER                                         = 0xC00000E8L,
    STATUS_UNEXPECTED_IO_ERROR                                         = 0xC00000E9L,
    STATUS_UNEXPECTED_MM_CREATE_ERR                                    = 0xC00000EAL,
    STATUS_UNEXPECTED_MM_MAP_ERROR                                     = 0xC00000EBL,
    STATUS_UNEXPECTED_MM_EXTEND_ERR                                    = 0xC00000ECL,
    STATUS_NOT_LOGON_PROCESS                                           = 0xC00000EDL,
    STATUS_LOGON_SESSION_EXISTS                                        = 0xC00000EEL,
    STATUS_INVALID_PARAMETER_1                                         = 0xC00000EFL,
    STATUS_INVALID_PARAMETER_2                                         = 0xC00000F0L,
    STATUS_INVALID_PARAMETER_3                                         = 0xC00000F1L,
    STATUS_INVALID_PARAMETER_4                                         = 0xC00000F2L,
    STATUS_INVALID_PARAMETER_5                                         = 0xC00000F3L,
    STATUS_INVALID_PARAMETER_6                                         = 0xC00000F4L,
    STATUS_INVALID_PARAMETER_7                                         = 0xC00000F5L,
    STATUS_INVALID_PARAMETER_8                                         = 0xC00000F6L,
    STATUS_INVALID_PARAMETER_9                                         = 0xC00000F7L,
    STATUS_INVALID_PARAMETER_10                                        = 0xC00000F8L,
    STATUS_INVALID_PARAMETER_11                                        = 0xC00000F9L,
    STATUS_INVALID_PARAMETER_12                                        = 0xC00000FAL,
    STATUS_REDIRECTOR_NOT_STARTED                                      = 0xC00000FBL,
    STATUS_REDIRECTOR_STARTED                                          = 0xC00000FCL,
    STATUS_STACK_OVERFLOW                                              = 0xC00000FDL,
    STATUS_NO_SUCH_PACKAGE                                             = 0xC00000FEL,
    STATUS_BAD_FUNCTION_TABLE                                          = 0xC00000FFL,
    STATUS_VARIABLE_NOT_FOUND                                          = 0xC0000100L,
    STATUS_DIRECTORY_NOT_EMPTY                                         = 0xC0000101L,
    STATUS_FILE_CORRUPT_ERROR                                          = 0xC0000102L,
    STATUS_NOT_A_DIRECTORY                                             = 0xC0000103L,
    STATUS_BAD_LOGON_SESSION_STATE                                     = 0xC0000104L,
    STATUS_LOGON_SESSION_COLLISION                                     = 0xC0000105L,
    STATUS_NAME_TOO_LONG                                               = 0xC0000106L,
    STATUS_FILES_OPEN                                                  = 0xC0000107L,
    STATUS_CONNECTION_IN_USE                                           = 0xC0000108L,
    STATUS_MESSAGE_NOT_FOUND                                           = 0xC0000109L,
    STATUS_PROCESS_IS_TERMINATING                                      = 0xC000010AL,
    STATUS_INVALID_LOGON_TYPE                                          = 0xC000010BL,
    STATUS_NO_GUID_TRANSLATION                                         = 0xC000010CL,
    STATUS_CANNOT_IMPERSONATE                                          = 0xC000010DL,
    STATUS_IMAGE_ALREADY_LOADED                                        = 0xC000010EL,
    STATUS_ABIOS_NOT_PRESENT                                           = 0xC000010FL,
    STATUS_ABIOS_LID_NOT_EXIST                                         = 0xC0000110L,
    STATUS_ABIOS_LID_ALREADY_OWNED                                     = 0xC0000111L,
    STATUS_ABIOS_NOT_LID_OWNER                                         = 0xC0000112L,
    STATUS_ABIOS_INVALID_COMMAND                                       = 0xC0000113L,
    STATUS_ABIOS_INVALID_LID                                           = 0xC0000114L,
    STATUS_ABIOS_SELECTOR_NOT_AVAILABLE                                = 0xC0000115L,
    STATUS_ABIOS_INVALID_SELECTOR                                      = 0xC0000116L,
    STATUS_NO_LDT                                                      = 0xC0000117L,
    STATUS_INVALID_LDT_SIZE                                            = 0xC0000118L,
    STATUS_INVALID_LDT_OFFSET                                          = 0xC0000119L,
    STATUS_INVALID_LDT_DESCRIPTOR                                      = 0xC000011AL,
    STATUS_INVALID_IMAGE_NE_FORMAT                                     = 0xC000011BL,
    STATUS_RXACT_INVALID_STATE                                         = 0xC000011CL,
    STATUS_RXACT_COMMIT_FAILURE                                        = 0xC000011DL,
    STATUS_MAPPED_FILE_SIZE_ZERO                                       = 0xC000011EL,
    STATUS_TOO_MANY_OPENED_FILES                                       = 0xC000011FL,
    STATUS_CANCELLED                                                   = 0xC0000120L,
    STATUS_CANNOT_DELETE                                               = 0xC0000121L,
    STATUS_INVALID_COMPUTER_NAME                                       = 0xC0000122L,
    STATUS_FILE_DELETED                                                = 0xC0000123L,
    STATUS_SPECIAL_ACCOUNT                                             = 0xC0000124L,
    STATUS_SPECIAL_GROUP                                               = 0xC0000125L,
    STATUS_SPECIAL_USER                                                = 0xC0000126L,
    STATUS_MEMBERS_PRIMARY_GROUP                                       = 0xC0000127L,
    STATUS_FILE_CLOSED                                                 = 0xC0000128L,
    STATUS_TOO_MANY_THREADS                                            = 0xC0000129L,
    STATUS_THREAD_NOT_IN_PROCESS                                       = 0xC000012AL,
    STATUS_TOKEN_ALREADY_IN_USE                                        = 0xC000012BL,
    STATUS_PAGEFILE_QUOTA_EXCEEDED                                     = 0xC000012CL,
    STATUS_COMMITMENT_LIMIT                                            = 0xC000012DL,
    STATUS_INVALID_IMAGE_LE_FORMAT                                     = 0xC000012EL,
    STATUS_INVALID_IMAGE_NOT_MZ                                        = 0xC000012FL,
    STATUS_INVALID_IMAGE_PROTECT                                       = 0xC0000130L,
    STATUS_INVALID_IMAGE_WIN_16                                        = 0xC0000131L,
    STATUS_LOGON_SERVER_CONFLICT                                       = 0xC0000132L,
    STATUS_TIME_DIFFERENCE_AT_DC                                       = 0xC0000133L,
    STATUS_SYNCHRONIZATION_REQUIRED                                    = 0xC0000134L,
    STATUS_DLL_NOT_FOUND                                               = 0xC0000135L,
    STATUS_OPEN_FAILED                                                 = 0xC0000136L,
    STATUS_IO_PRIVILEGE_FAILED                                         = 0xC0000137L,
    STATUS_ORDINAL_NOT_FOUND                                           = 0xC0000138L,
    STATUS_ENTRYPOINT_NOT_FOUND                                        = 0xC0000139L,
    STATUS_CONTROL_C_EXIT                                              = 0xC000013AL,
    STATUS_LOCAL_DISCONNECT                                            = 0xC000013BL,
    STATUS_REMOTE_DISCONNECT                                           = 0xC000013CL,
    STATUS_REMOTE_RESOURCES                                            = 0xC000013DL,
    STATUS_LINK_FAILED                                                 = 0xC000013EL,
    STATUS_LINK_TIMEOUT                                                = 0xC000013FL,
    STATUS_INVALID_CONNECTION                                          = 0xC0000140L,
    STATUS_INVALID_ADDRESS                                             = 0xC0000141L,
    STATUS_DLL_INIT_FAILED                                             = 0xC0000142L,
    STATUS_MISSING_SYSTEMFILE                                          = 0xC0000143L,
    STATUS_UNHANDLED_EXCEPTION                                         = 0xC0000144L,
    STATUS_APP_INIT_FAILURE                                            = 0xC0000145L,
    STATUS_PAGEFILE_CREATE_FAILED                                      = 0xC0000146L,
    STATUS_NO_PAGEFILE                                                 = 0xC0000147L,
    STATUS_INVALID_LEVEL                                               = 0xC0000148L,
    STATUS_WRONG_PASSWORD_CORE                                         = 0xC0000149L,
    STATUS_ILLEGAL_FLOAT_CONTEXT                                       = 0xC000014AL,
    STATUS_PIPE_BROKEN                                                 = 0xC000014BL,
    STATUS_REGISTRY_CORRUPT                                            = 0xC000014CL,
    STATUS_REGISTRY_IO_FAILED                                          = 0xC000014DL,
    STATUS_NO_EVENT_PAIR                                               = 0xC000014EL,
    STATUS_UNRECOGNIZED_VOLUME                                         = 0xC000014FL,
    STATUS_SERIAL_NO_DEVICE_INITED                                     = 0xC0000150L,
    STATUS_NO_SUCH_ALIAS                                               = 0xC0000151L,
    STATUS_MEMBER_NOT_IN_ALIAS                                         = 0xC0000152L,
    STATUS_MEMBER_IN_ALIAS                                             = 0xC0000153L,
    STATUS_ALIAS_EXISTS                                                = 0xC0000154L,
    STATUS_LOGON_NOT_GRANTED                                           = 0xC0000155L,
    STATUS_TOO_MANY_SECRETS                                            = 0xC0000156L,
    STATUS_SECRET_TOO_LONG                                             = 0xC0000157L,
    STATUS_INTERNAL_DB_ERROR                                           = 0xC0000158L,
    STATUS_FULLSCREEN_MODE                                             = 0xC0000159L,
    STATUS_TOO_MANY_CONTEXT_IDS                                        = 0xC000015AL,
    STATUS_LOGON_TYPE_NOT_GRANTED                                      = 0xC000015BL,
    STATUS_NOT_REGISTRY_FILE                                           = 0xC000015CL,
    STATUS_NT_CROSS_ENCRYPTION_REQUIRED                                = 0xC000015DL,
    STATUS_DOMAIN_CTRLR_CONFIG_ERROR                                   = 0xC000015EL,
    STATUS_FT_MISSING_MEMBER                                           = 0xC000015FL,
    STATUS_ILL_FORMED_SERVICE_ENTRY                                    = 0xC0000160L,
    STATUS_ILLEGAL_CHARACTER                                           = 0xC0000161L,
    STATUS_UNMAPPABLE_CHARACTER                                        = 0xC0000162L,
    STATUS_UNDEFINED_CHARACTER                                         = 0xC0000163L,
    STATUS_FLOPPY_VOLUME                                               = 0xC0000164L,
    STATUS_FLOPPY_ID_MARK_NOT_FOUND                                    = 0xC0000165L,
    STATUS_FLOPPY_WRONG_CYLINDER                                       = 0xC0000166L,
    STATUS_FLOPPY_UNKNOWN_ERROR                                        = 0xC0000167L,
    STATUS_FLOPPY_BAD_REGISTERS                                        = 0xC0000168L,
    STATUS_DISK_RECALIBRATE_FAILED                                     = 0xC0000169L,
    STATUS_DISK_OPERATION_FAILED                                       = 0xC000016AL,
    STATUS_DISK_RESET_FAILED                                           = 0xC000016BL,
    STATUS_SHARED_IRQ_BUSY                                             = 0xC000016CL,
    STATUS_FT_ORPHANING                                                = 0xC000016DL,
    STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT                            = 0xC000016EL,
    STATUS_PARTITION_FAILURE                                           = 0xC0000172L,
    STATUS_INVALID_BLOCK_LENGTH                                        = 0xC0000173L,
    STATUS_DEVICE_NOT_PARTITIONED                                      = 0xC0000174L,
    STATUS_UNABLE_TO_LOCK_MEDIA                                        = 0xC0000175L,
    STATUS_UNABLE_TO_UNLOAD_MEDIA                                      = 0xC0000176L,
    STATUS_EOM_OVERFLOW                                                = 0xC0000177L,
    STATUS_NO_MEDIA                                                    = 0xC0000178L,
    STATUS_NO_SUCH_MEMBER                                              = 0xC000017AL,
    STATUS_INVALID_MEMBER                                              = 0xC000017BL,
    STATUS_KEY_DELETED                                                 = 0xC000017CL,
    STATUS_NO_LOG_SPACE                                                = 0xC000017DL,
    STATUS_TOO_MANY_SIDS                                               = 0xC000017EL,
    STATUS_LM_CROSS_ENCRYPTION_REQUIRED                                = 0xC000017FL,
    STATUS_KEY_HAS_CHILDREN                                            = 0xC0000180L,
    STATUS_CHILD_MUST_BE_VOLATILE                                      = 0xC0000181L,
    STATUS_DEVICE_CONFIGURATION_ERROR                                  = 0xC0000182L,
    STATUS_DRIVER_INTERNAL_ERROR                                       = 0xC0000183L,
    STATUS_INVALID_DEVICE_STATE                                        = 0xC0000184L,
    STATUS_IO_DEVICE_ERROR                                             = 0xC0000185L,
    STATUS_DEVICE_PROTOCOL_ERROR                                       = 0xC0000186L,
    STATUS_BACKUP_CONTROLLER                                           = 0xC0000187L,
    STATUS_LOG_FILE_FULL                                               = 0xC0000188L,
    STATUS_TOO_LATE                                                    = 0xC0000189L,
    STATUS_NO_TRUST_LSA_SECRET                                         = 0xC000018AL,
    STATUS_NO_TRUST_SAM_ACCOUNT                                        = 0xC000018BL,
    STATUS_TRUSTED_DOMAIN_FAILURE                                      = 0xC000018CL,
    STATUS_TRUSTED_RELATIONSHIP_FAILURE                                = 0xC000018DL,
    STATUS_EVENTLOG_FILE_CORRUPT                                       = 0xC000018EL,
    STATUS_EVENTLOG_CANT_START                                         = 0xC000018FL,
    STATUS_TRUST_FAILURE                                               = 0xC0000190L,
    STATUS_MUTANT_LIMIT_EXCEEDED                                       = 0xC0000191L,
    STATUS_NETLOGON_NOT_STARTED                                        = 0xC0000192L,
    STATUS_ACCOUNT_EXPIRED                                             = 0xC0000193L,
    STATUS_POSSIBLE_DEADLOCK                                           = 0xC0000194L,
    STATUS_NETWORK_CREDENTIAL_CONFLICT                                 = 0xC0000195L,
    STATUS_REMOTE_SESSION_LIMIT                                        = 0xC0000196L,
    STATUS_EVENTLOG_FILE_CHANGED                                       = 0xC0000197L,
    STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT                           = 0xC0000198L,
    STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT                           = 0xC0000199L,
    STATUS_NOLOGON_SERVER_TRUST_ACCOUNT                                = 0xC000019AL,
    STATUS_DOMAIN_TRUST_INCONSISTENT                                   = 0xC000019BL,
    STATUS_FS_DRIVER_REQUIRED                                          = 0xC000019CL,
    STATUS_IMAGE_ALREADY_LOADED_AS_DLL                                 = 0xC000019DL,
    STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING        = 0xC000019EL,
    STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME                           = 0xC000019FL,
    STATUS_SECURITY_STREAM_IS_INCONSISTENT                             = 0xC00001A0L,
    STATUS_INVALID_LOCK_RANGE                                          = 0xC00001A1L,
    STATUS_INVALID_ACE_CONDITION                                       = 0xC00001A2L,
    STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT                                 = 0xC00001A3L,
    STATUS_NOTIFICATION_GUID_ALREADY_DEFINED                           = 0xC00001A4L,
    STATUS_INVALID_EXCEPTION_HANDLER                                   = 0xC00001A5L,
    STATUS_DUPLICATE_PRIVILEGES                                        = 0xC00001A6L,
    STATUS_NOT_ALLOWED_ON_SYSTEM_FILE                                  = 0xC00001A7L,
    STATUS_REPAIR_NEEDED                                               = 0xC00001A8L,
    STATUS_QUOTA_NOT_ENABLED                                           = 0xC00001A9L,
    STATUS_NO_APPLICATION_PACKAGE                                      = 0xC00001AAL,
    STATUS_FILE_METADATA_OPTIMIZATION_IN_PROGRESS                      = 0xC00001ABL,
    STATUS_NOT_SAME_OBJECT                                             = 0xC00001ACL,
    STATUS_FATAL_MEMORY_EXHAUSTION                                     = 0xC00001ADL,
    STATUS_ERROR_PROCESS_NOT_IN_JOB                                    = 0xC00001AEL,
    STATUS_CPU_SET_INVALID                                             = 0xC00001AFL,
    STATUS_IO_DEVICE_INVALID_DATA                                      = 0xC00001B0L,
    STATUS_NETWORK_OPEN_RESTRICTION                                    = 0xC0000201L,
    STATUS_NO_USER_SESSION_KEY                                         = 0xC0000202L,
    STATUS_USER_SESSION_DELETED                                        = 0xC0000203L,
    STATUS_RESOURCE_LANG_NOT_FOUND                                     = 0xC0000204L,
    STATUS_INSUFF_SERVER_RESOURCES                                     = 0xC0000205L,
    STATUS_INVALID_BUFFER_SIZE                                         = 0xC0000206L,
    STATUS_INVALID_ADDRESS_COMPONENT                                   = 0xC0000207L,
    STATUS_INVALID_ADDRESS_WILDCARD                                    = 0xC0000208L,
    STATUS_TOO_MANY_ADDRESSES                                          = 0xC0000209L,
    STATUS_ADDRESS_ALREADY_EXISTS                                      = 0xC000020AL,
    STATUS_ADDRESS_CLOSED                                              = 0xC000020BL,
    STATUS_CONNECTION_DISCONNECTED                                     = 0xC000020CL,
    STATUS_CONNECTION_RESET                                            = 0xC000020DL,
    STATUS_TOO_MANY_NODES                                              = 0xC000020EL,
    STATUS_TRANSACTION_ABORTED                                         = 0xC000020FL,
    STATUS_TRANSACTION_TIMED_OUT                                       = 0xC0000210L,
    STATUS_TRANSACTION_NO_RELEASE                                      = 0xC0000211L,
    STATUS_TRANSACTION_NO_MATCH                                        = 0xC0000212L,
    STATUS_TRANSACTION_RESPONDED                                       = 0xC0000213L,
    STATUS_TRANSACTION_INVALID_ID                                      = 0xC0000214L,
    STATUS_TRANSACTION_INVALID_TYPE                                    = 0xC0000215L,
    STATUS_NOT_SERVER_SESSION                                          = 0xC0000216L,
    STATUS_NOT_CLIENT_SESSION                                          = 0xC0000217L,
    STATUS_CANNOT_LOAD_REGISTRY_FILE                                   = 0xC0000218L,
    STATUS_DEBUG_ATTACH_FAILED                                         = 0xC0000219L,
    STATUS_SYSTEM_PROCESS_TERMINATED                                   = 0xC000021AL,
    STATUS_DATA_NOT_ACCEPTED                                           = 0xC000021BL,
    STATUS_NO_BROWSER_SERVERS_FOUND                                    = 0xC000021CL,
    STATUS_VDM_HARD_ERROR                                              = 0xC000021DL,
    STATUS_DRIVER_CANCEL_TIMEOUT                                       = 0xC000021EL,
    STATUS_REPLY_MESSAGE_MISMATCH                                      = 0xC000021FL,
    STATUS_MAPPED_ALIGNMENT                                            = 0xC0000220L,
    STATUS_IMAGE_CHECKSUM_MISMATCH                                     = 0xC0000221L,
    STATUS_LOST_WRITEBEHIND_DATA                                       = 0xC0000222L,
    STATUS_CLIENT_SERVER_PARAMETERS_INVALID                            = 0xC0000223L,
    STATUS_PASSWORD_MUST_CHANGE                                        = 0xC0000224L,
    STATUS_NOT_FOUND                                                   = 0xC0000225L,
    STATUS_NOT_TINY_STREAM                                             = 0xC0000226L,
    STATUS_RECOVERY_FAILURE                                            = 0xC0000227L,
    STATUS_STACK_OVERFLOW_READ                                         = 0xC0000228L,
    STATUS_FAIL_CHECK                                                  = 0xC0000229L,
    STATUS_DUPLICATE_OBJECTID                                          = 0xC000022AL,
    STATUS_OBJECTID_EXISTS                                             = 0xC000022BL,
    STATUS_CONVERT_TO_LARGE                                            = 0xC000022CL,
    STATUS_RETRY                                                       = 0xC000022DL,
    STATUS_FOUND_OUT_OF_SCOPE                                          = 0xC000022EL,
    STATUS_ALLOCATE_BUCKET                                             = 0xC000022FL,
    STATUS_PROPSET_NOT_FOUND                                           = 0xC0000230L,
    STATUS_MARSHALL_OVERFLOW                                           = 0xC0000231L,
    STATUS_INVALID_VARIANT                                             = 0xC0000232L,
    STATUS_DOMAIN_CONTROLLER_NOT_FOUND                                 = 0xC0000233L,
    STATUS_ACCOUNT_LOCKED_OUT                                          = 0xC0000234L,
    STATUS_HANDLE_NOT_CLOSABLE                                         = 0xC0000235L,
    STATUS_CONNECTION_REFUSED                                          = 0xC0000236L,
    STATUS_GRACEFUL_DISCONNECT                                         = 0xC0000237L,
    STATUS_ADDRESS_ALREADY_ASSOCIATED                                  = 0xC0000238L,
    STATUS_ADDRESS_NOT_ASSOCIATED                                      = 0xC0000239L,
    STATUS_CONNECTION_INVALID                                          = 0xC000023AL,
    STATUS_CONNECTION_ACTIVE                                           = 0xC000023BL,
    STATUS_NETWORK_UNREACHABLE                                         = 0xC000023CL,
    STATUS_HOST_UNREACHABLE                                            = 0xC000023DL,
    STATUS_PROTOCOL_UNREACHABLE                                        = 0xC000023EL,
    STATUS_PORT_UNREACHABLE                                            = 0xC000023FL,
    STATUS_REQUEST_ABORTED                                             = 0xC0000240L,
    STATUS_CONNECTION_ABORTED                                          = 0xC0000241L,
    STATUS_BAD_COMPRESSION_BUFFER                                      = 0xC0000242L,
    STATUS_USER_MAPPED_FILE                                            = 0xC0000243L,
    STATUS_AUDIT_FAILED                                                = 0xC0000244L,
    STATUS_TIMER_RESOLUTION_NOT_SET                                    = 0xC0000245L,
    STATUS_CONNECTION_COUNT_LIMIT                                      = 0xC0000246L,
    STATUS_LOGIN_TIME_RESTRICTION                                      = 0xC0000247L,
    STATUS_LOGIN_WKSTA_RESTRICTION                                     = 0xC0000248L,
    STATUS_IMAGE_MP_UP_MISMATCH                                        = 0xC0000249L,
    STATUS_INSUFFICIENT_LOGON_INFO                                     = 0xC0000250L,
    STATUS_BAD_DLL_ENTRYPOINT                                          = 0xC0000251L,
    STATUS_BAD_SERVICE_ENTRYPOINT                                      = 0xC0000252L,
    STATUS_LPC_REPLY_LOST                                              = 0xC0000253L,
    STATUS_IP_ADDRESS_CONFLICT1                                        = 0xC0000254L,
    STATUS_IP_ADDRESS_CONFLICT2                                        = 0xC0000255L,
    STATUS_REGISTRY_QUOTA_LIMIT                                        = 0xC0000256L,
    STATUS_PATH_NOT_COVERED                                            = 0xC0000257L,
    STATUS_NO_CALLBACK_ACTIVE                                          = 0xC0000258L,
    STATUS_LICENSE_QUOTA_EXCEEDED                                      = 0xC0000259L,
    STATUS_PWD_TOO_SHORT                                               = 0xC000025AL,
    STATUS_PWD_TOO_RECENT                                              = 0xC000025BL,
    STATUS_PWD_HISTORY_CONFLICT                                        = 0xC000025CL,
    STATUS_PLUGPLAY_NO_DEVICE                                          = 0xC000025EL,
    STATUS_UNSUPPORTED_COMPRESSION                                     = 0xC000025FL,
    STATUS_INVALID_HW_PROFILE                                          = 0xC0000260L,
    STATUS_INVALID_PLUGPLAY_DEVICE_PATH                                = 0xC0000261L,
    STATUS_DRIVER_ORDINAL_NOT_FOUND                                    = 0xC0000262L,
    STATUS_DRIVER_ENTRYPOINT_NOT_FOUND                                 = 0xC0000263L,
    STATUS_RESOURCE_NOT_OWNED                                          = 0xC0000264L,
    STATUS_TOO_MANY_LINKS                                              = 0xC0000265L,
    STATUS_QUOTA_LIST_INCONSISTENT                                     = 0xC0000266L,
    STATUS_FILE_IS_OFFLINE                                             = 0xC0000267L,
    STATUS_EVALUATION_EXPIRATION                                       = 0xC0000268L,
    STATUS_ILLEGAL_DLL_RELOCATION                                      = 0xC0000269L,
    STATUS_LICENSE_VIOLATION                                           = 0xC000026AL,
    STATUS_DLL_INIT_FAILED_LOGOFF                                      = 0xC000026BL,
    STATUS_DRIVER_UNABLE_TO_LOAD                                       = 0xC000026CL,
    STATUS_DFS_UNAVAILABLE                                             = 0xC000026DL,
    STATUS_VOLUME_DISMOUNTED                                           = 0xC000026EL,
    STATUS_WX86_INTERNAL_ERROR                                         = 0xC000026FL,
    STATUS_WX86_FLOAT_STACK_CHECK                                      = 0xC0000270L,
    STATUS_VALIDATE_CONTINUE                                           = 0xC0000271L,
    STATUS_NO_MATCH                                                    = 0xC0000272L,
    STATUS_NO_MORE_MATCHES                                             = 0xC0000273L,
    STATUS_NOT_A_REPARSE_POINT                                         = 0xC0000275L,
    STATUS_IO_REPARSE_TAG_INVALID                                      = 0xC0000276L,
    STATUS_IO_REPARSE_TAG_MISMATCH                                     = 0xC0000277L,
    STATUS_IO_REPARSE_DATA_INVALID                                     = 0xC0000278L,
    STATUS_IO_REPARSE_TAG_NOT_HANDLED                                  = 0xC0000279L,
    STATUS_PWD_TOO_LONG                                                = 0xC000027AL,
    STATUS_STOWED_EXCEPTION                                            = 0xC000027BL,
    STATUS_CONTEXT_STOWED_EXCEPTION                                    = 0xC000027CL,
    STATUS_REPARSE_POINT_NOT_RESOLVED                                  = 0xC0000280L,
    STATUS_DIRECTORY_IS_A_REPARSE_POINT                                = 0xC0000281L,
    STATUS_RANGE_LIST_CONFLICT                                         = 0xC0000282L,
    STATUS_SOURCE_ELEMENT_EMPTY                                        = 0xC0000283L,
    STATUS_DESTINATION_ELEMENT_FULL                                    = 0xC0000284L,
    STATUS_ILLEGAL_ELEMENT_ADDRESS                                     = 0xC0000285L,
    STATUS_MAGAZINE_NOT_PRESENT                                        = 0xC0000286L,
    STATUS_REINITIALIZATION_NEEDED                                     = 0xC0000287L,
    STATUS_DEVICE_REQUIRES_CLEANING                                    = 0x80000288L,
    STATUS_DEVICE_DOOR_OPEN                                            = 0x80000289L,
    STATUS_ENCRYPTION_FAILED                                           = 0xC000028AL,
    STATUS_DECRYPTION_FAILED                                           = 0xC000028BL,
    STATUS_RANGE_NOT_FOUND                                             = 0xC000028CL,
    STATUS_NO_RECOVERY_POLICY                                          = 0xC000028DL,
    STATUS_NO_EFS                                                      = 0xC000028EL,
    STATUS_WRONG_EFS                                                   = 0xC000028FL,
    STATUS_NO_USER_KEYS                                                = 0xC0000290L,
    STATUS_FILE_NOT_ENCRYPTED                                          = 0xC0000291L,
    STATUS_NOT_EXPORT_FORMAT                                           = 0xC0000292L,
    STATUS_FILE_ENCRYPTED                                              = 0xC0000293L,
    STATUS_WAKE_SYSTEM                                                 = 0x40000294L,
    STATUS_WMI_GUID_NOT_FOUND                                          = 0xC0000295L,
    STATUS_WMI_INSTANCE_NOT_FOUND                                      = 0xC0000296L,
    STATUS_WMI_ITEMID_NOT_FOUND                                        = 0xC0000297L,
    STATUS_WMI_TRY_AGAIN                                               = 0xC0000298L,
    STATUS_SHARED_POLICY                                               = 0xC0000299L,
    STATUS_POLICY_OBJECT_NOT_FOUND                                     = 0xC000029AL,
    STATUS_POLICY_ONLY_IN_DS                                           = 0xC000029BL,
    STATUS_VOLUME_NOT_UPGRADED                                         = 0xC000029CL,
    STATUS_REMOTE_STORAGE_NOT_ACTIVE                                   = 0xC000029DL,
    STATUS_REMOTE_STORAGE_MEDIA_ERROR                                  = 0xC000029EL,
    STATUS_NO_TRACKING_SERVICE                                         = 0xC000029FL,
    STATUS_SERVER_SID_MISMATCH                                         = 0xC00002A0L,
    STATUS_DS_NO_ATTRIBUTE_OR_VALUE                                    = 0xC00002A1L,
    STATUS_DS_INVALID_ATTRIBUTE_SYNTAX                                 = 0xC00002A2L,
    STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED                                 = 0xC00002A3L,
    STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS                                = 0xC00002A4L,
    STATUS_DS_BUSY                                                     = 0xC00002A5L,
    STATUS_DS_UNAVAILABLE                                              = 0xC00002A6L,
    STATUS_DS_NO_RIDS_ALLOCATED                                        = 0xC00002A7L,
    STATUS_DS_NO_MORE_RIDS                                             = 0xC00002A8L,
    STATUS_DS_INCORRECT_ROLE_OWNER                                     = 0xC00002A9L,
    STATUS_DS_RIDMGR_INIT_ERROR                                        = 0xC00002AAL,
    STATUS_DS_OBJ_CLASS_VIOLATION                                      = 0xC00002ABL,
    STATUS_DS_CANT_ON_NON_LEAF                                         = 0xC00002ACL,
    STATUS_DS_CANT_ON_RDN                                              = 0xC00002ADL,
    STATUS_DS_CANT_MOD_OBJ_CLASS                                       = 0xC00002AEL,
    STATUS_DS_CROSS_DOM_MOVE_FAILED                                    = 0xC00002AFL,
    STATUS_DS_GC_NOT_AVAILABLE                                         = 0xC00002B0L,
    STATUS_DIRECTORY_SERVICE_REQUIRED                                  = 0xC00002B1L,
    STATUS_REPARSE_ATTRIBUTE_CONFLICT                                  = 0xC00002B2L,
    STATUS_CANT_ENABLE_DENY_ONLY                                       = 0xC00002B3L,
    STATUS_FLOAT_MULTIPLE_FAULTS                                       = 0xC00002B4L,
    STATUS_FLOAT_MULTIPLE_TRAPS                                        = 0xC00002B5L,
    STATUS_DEVICE_REMOVED                                              = 0xC00002B6L,
    STATUS_JOURNAL_DELETE_IN_PROGRESS                                  = 0xC00002B7L,
    STATUS_JOURNAL_NOT_ACTIVE                                          = 0xC00002B8L,
    STATUS_NOINTERFACE                                                 = 0xC00002B9L,
    STATUS_DS_RIDMGR_DISABLED                                          = 0xC00002BAL,
    STATUS_DS_ADMIN_LIMIT_EXCEEDED                                     = 0xC00002C1L,
    STATUS_DRIVER_FAILED_SLEEP                                         = 0xC00002C2L,
    STATUS_MUTUAL_AUTHENTICATION_FAILED                                = 0xC00002C3L,
    STATUS_CORRUPT_SYSTEM_FILE                                         = 0xC00002C4L,
    STATUS_DATATYPE_MISALIGNMENT_ERROR                                 = 0xC00002C5L,
    STATUS_WMI_READ_ONLY                                               = 0xC00002C6L,
    STATUS_WMI_SET_FAILURE                                             = 0xC00002C7L,
    STATUS_COMMITMENT_MINIMUM                                          = 0xC00002C8L,
    STATUS_REG_NAT_CONSUMPTION                                         = 0xC00002C9L,
    STATUS_TRANSPORT_FULL                                              = 0xC00002CAL,
    STATUS_DS_SAM_INIT_FAILURE                                         = 0xC00002CBL,
    STATUS_ONLY_IF_CONNECTED                                           = 0xC00002CCL,
    STATUS_DS_SENSITIVE_GROUP_VIOLATION                                = 0xC00002CDL,
    STATUS_PNP_RESTART_ENUMERATION                                     = 0xC00002CEL,
    STATUS_JOURNAL_ENTRY_DELETED                                       = 0xC00002CFL,
    STATUS_DS_CANT_MOD_PRIMARYGROUPID                                  = 0xC00002D0L,
    STATUS_SYSTEM_IMAGE_BAD_SIGNATURE                                  = 0xC00002D1L,
    STATUS_PNP_REBOOT_REQUIRED                                         = 0xC00002D2L,
    STATUS_POWER_STATE_INVALID                                         = 0xC00002D3L,
    STATUS_DS_INVALID_GROUP_TYPE                                       = 0xC00002D4L,
    STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN                       = 0xC00002D5L,
    STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN                        = 0xC00002D6L,
    STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER                            = 0xC00002D7L,
    STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER                        = 0xC00002D8L,
    STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER                         = 0xC00002D9L,
    STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER                      = 0xC00002DAL,
    STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER                 = 0xC00002DBL,
    STATUS_DS_HAVE_PRIMARY_MEMBERS                                     = 0xC00002DCL,
    STATUS_WMI_NOT_SUPPORTED                                           = 0xC00002DDL,
    STATUS_INSUFFICIENT_POWER                                          = 0xC00002DEL,
    STATUS_SAM_NEED_BOOTKEY_PASSWORD                                   = 0xC00002DFL,
    STATUS_SAM_NEED_BOOTKEY_FLOPPY                                     = 0xC00002E0L,
    STATUS_DS_CANT_START                                               = 0xC00002E1L,
    STATUS_DS_INIT_FAILURE                                             = 0xC00002E2L,
    STATUS_SAM_INIT_FAILURE                                            = 0xC00002E3L,
    STATUS_DS_GC_REQUIRED                                              = 0xC00002E4L,
    STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY                               = 0xC00002E5L,
    STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS                               = 0xC00002E6L,
    STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED                           = 0xC00002E7L,
    STATUS_MULTIPLE_FAULT_VIOLATION                                    = 0xC00002E8L,
    STATUS_CURRENT_DOMAIN_NOT_ALLOWED                                  = 0xC00002E9L,
    STATUS_CANNOT_MAKE                                                 = 0xC00002EAL,
    STATUS_SYSTEM_SHUTDOWN                                             = 0xC00002EBL,
    STATUS_DS_INIT_FAILURE_CONSOLE                                     = 0xC00002ECL,
    STATUS_DS_SAM_INIT_FAILURE_CONSOLE                                 = 0xC00002EDL,
    STATUS_UNFINISHED_CONTEXT_DELETED                                  = 0xC00002EEL,
    STATUS_NO_TGT_REPLY                                                = 0xC00002EFL,
    STATUS_OBJECTID_NOT_FOUND                                          = 0xC00002F0L,
    STATUS_NO_IP_ADDRESSES                                             = 0xC00002F1L,
    STATUS_WRONG_CREDENTIAL_HANDLE                                     = 0xC00002F2L,
    STATUS_CRYPTO_SYSTEM_INVALID                                       = 0xC00002F3L,
    STATUS_MAX_REFERRALS_EXCEEDED                                      = 0xC00002F4L,
    STATUS_MUST_BE_KDC                                                 = 0xC00002F5L,
    STATUS_STRONG_CRYPTO_NOT_SUPPORTED                                 = 0xC00002F6L,
    STATUS_TOO_MANY_PRINCIPALS                                         = 0xC00002F7L,
    STATUS_NO_PA_DATA                                                  = 0xC00002F8L,
    STATUS_PKINIT_NAME_MISMATCH                                        = 0xC00002F9L,
    STATUS_SMARTCARD_LOGON_REQUIRED                                    = 0xC00002FAL,
    STATUS_KDC_INVALID_REQUEST                                         = 0xC00002FBL,
    STATUS_KDC_UNABLE_TO_REFER                                         = 0xC00002FCL,
    STATUS_KDC_UNKNOWN_ETYPE                                           = 0xC00002FDL,
    STATUS_SHUTDOWN_IN_PROGRESS                                        = 0xC00002FEL,
    STATUS_SERVER_SHUTDOWN_IN_PROGRESS                                 = 0xC00002FFL,
    STATUS_NOT_SUPPORTED_ON_SBS                                        = 0xC0000300L,
    STATUS_WMI_GUID_DISCONNECTED                                       = 0xC0000301L,
    STATUS_WMI_ALREADY_DISABLED                                        = 0xC0000302L,
    STATUS_WMI_ALREADY_ENABLED                                         = 0xC0000303L,
    STATUS_MFT_TOO_FRAGMENTED                                          = 0xC0000304L,
    STATUS_COPY_PROTECTION_FAILURE                                     = 0xC0000305L,
    STATUS_CSS_AUTHENTICATION_FAILURE                                  = 0xC0000306L,
    STATUS_CSS_KEY_NOT_PRESENT                                         = 0xC0000307L,
    STATUS_CSS_KEY_NOT_ESTABLISHED                                     = 0xC0000308L,
    STATUS_CSS_SCRAMBLED_SECTOR                                        = 0xC0000309L,
    STATUS_CSS_REGION_MISMATCH                                         = 0xC000030AL,
    STATUS_CSS_RESETS_EXHAUSTED                                        = 0xC000030BL,
    STATUS_PASSWORD_CHANGE_REQUIRED                                    = 0xC000030CL,
    STATUS_LOST_MODE_LOGON_RESTRICTION                                 = 0xC000030DL,
    STATUS_PKINIT_FAILURE                                              = 0xC0000320L,
    STATUS_SMARTCARD_SUBSYSTEM_FAILURE                                 = 0xC0000321L,
    STATUS_NO_KERB_KEY                                                 = 0xC0000322L,
    STATUS_HOST_DOWN                                                   = 0xC0000350L,
    STATUS_UNSUPPORTED_PREAUTH                                         = 0xC0000351L,
    STATUS_EFS_ALG_BLOB_TOO_BIG                                        = 0xC0000352L,
    STATUS_PORT_NOT_SET                                                = 0xC0000353L,
    STATUS_DEBUGGER_INACTIVE                                           = 0xC0000354L,
    STATUS_DS_VERSION_CHECK_FAILURE                                    = 0xC0000355L,
    STATUS_AUDITING_DISABLED                                           = 0xC0000356L,
    STATUS_PRENT4_MACHINE_ACCOUNT                                      = 0xC0000357L,
    STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER                            = 0xC0000358L,
    STATUS_INVALID_IMAGE_WIN_32                                        = 0xC0000359L,
    STATUS_INVALID_IMAGE_WIN_64                                        = 0xC000035AL,
    STATUS_BAD_BINDINGS                                                = 0xC000035BL,
    STATUS_NETWORK_SESSION_EXPIRED                                     = 0xC000035CL,
    STATUS_APPHELP_BLOCK                                               = 0xC000035DL,
    STATUS_ALL_SIDS_FILTERED                                           = 0xC000035EL,
    STATUS_NOT_SAFE_MODE_DRIVER                                        = 0xC000035FL,
    STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT                           = 0xC0000361L,
    STATUS_ACCESS_DISABLED_BY_POLICY_PATH                              = 0xC0000362L,
    STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER                         = 0xC0000363L,
    STATUS_ACCESS_DISABLED_BY_POLICY_OTHER                             = 0xC0000364L,
    STATUS_FAILED_DRIVER_ENTRY                                         = 0xC0000365L,
    STATUS_DEVICE_ENUMERATION_ERROR                                    = 0xC0000366L,
    STATUS_MOUNT_POINT_NOT_RESOLVED                                    = 0xC0000368L,
    STATUS_INVALID_DEVICE_OBJECT_PARAMETER                             = 0xC0000369L,
    STATUS_MCA_OCCURED                                                 = 0xC000036AL,
    STATUS_DRIVER_BLOCKED_CRITICAL                                     = 0xC000036BL,
    STATUS_DRIVER_BLOCKED                                              = 0xC000036CL,
    STATUS_DRIVER_DATABASE_ERROR                                       = 0xC000036DL,
    STATUS_SYSTEM_HIVE_TOO_LARGE                                       = 0xC000036EL,
    STATUS_INVALID_IMPORT_OF_NON_DLL                                   = 0xC000036FL,
    STATUS_DS_SHUTTING_DOWN                                            = 0x40000370L,
    STATUS_NO_SECRETS                                                  = 0xC0000371L,
    STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY                       = 0xC0000372L,
    STATUS_FAILED_STACK_SWITCH                                         = 0xC0000373L,
    STATUS_HEAP_CORRUPTION                                             = 0xC0000374L,
    STATUS_SMARTCARD_WRONG_PIN                                         = 0xC0000380L,
    STATUS_SMARTCARD_CARD_BLOCKED                                      = 0xC0000381L,
    STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED                            = 0xC0000382L,
    STATUS_SMARTCARD_NO_CARD                                           = 0xC0000383L,
    STATUS_SMARTCARD_NO_KEY_CONTAINER                                  = 0xC0000384L,
    STATUS_SMARTCARD_NO_CERTIFICATE                                    = 0xC0000385L,
    STATUS_SMARTCARD_NO_KEYSET                                         = 0xC0000386L,
    STATUS_SMARTCARD_IO_ERROR                                          = 0xC0000387L,
    STATUS_DOWNGRADE_DETECTED                                          = 0xC0000388L,
    STATUS_SMARTCARD_CERT_REVOKED                                      = 0xC0000389L,
    STATUS_ISSUING_CA_UNTRUSTED                                        = 0xC000038AL,
    STATUS_REVOCATION_OFFLINE_C                                        = 0xC000038BL,
    STATUS_PKINIT_CLIENT_FAILURE                                       = 0xC000038CL,
    STATUS_SMARTCARD_CERT_EXPIRED                                      = 0xC000038DL,
    STATUS_DRIVER_FAILED_PRIOR_UNLOAD                                  = 0xC000038EL,
    STATUS_SMARTCARD_SILENT_CONTEXT                                    = 0xC000038FL,
    STATUS_PER_USER_TRUST_QUOTA_EXCEEDED                               = 0xC0000401L,
    STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED                               = 0xC0000402L,
    STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED                            = 0xC0000403L,
    STATUS_DS_NAME_NOT_UNIQUE                                          = 0xC0000404L,
    STATUS_DS_DUPLICATE_ID_FOUND                                       = 0xC0000405L,
    STATUS_DS_GROUP_CONVERSION_ERROR                                   = 0xC0000406L,
    STATUS_VOLSNAP_PREPARE_HIBERNATE                                   = 0xC0000407L,
    STATUS_USER2USER_REQUIRED                                          = 0xC0000408L,
    STATUS_STACK_BUFFER_OVERRUN                                        = 0xC0000409L,
    STATUS_NO_S4U_PROT_SUPPORT                                         = 0xC000040AL,
    STATUS_CROSSREALM_DELEGATION_FAILURE                               = 0xC000040BL,
    STATUS_REVOCATION_OFFLINE_KDC                                      = 0xC000040CL,
    STATUS_ISSUING_CA_UNTRUSTED_KDC                                    = 0xC000040DL,
    STATUS_KDC_CERT_EXPIRED                                            = 0xC000040EL,
    STATUS_KDC_CERT_REVOKED                                            = 0xC000040FL,
    STATUS_PARAMETER_QUOTA_EXCEEDED                                    = 0xC0000410L,
    STATUS_HIBERNATION_FAILURE                                         = 0xC0000411L,
    STATUS_DELAY_LOAD_FAILED                                           = 0xC0000412L,
    STATUS_AUTHENTICATION_FIREWALL_FAILED                              = 0xC0000413L,
    STATUS_VDM_DISALLOWED                                              = 0xC0000414L,
    STATUS_HUNG_DISPLAY_DRIVER_THREAD                                  = 0xC0000415L,
    STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE     = 0xC0000416L,
    STATUS_INVALID_CRUNTIME_PARAMETER                                  = 0xC0000417L,
    STATUS_NTLM_BLOCKED                                                = 0xC0000418L,
    STATUS_DS_SRC_SID_EXISTS_IN_FOREST                                 = 0xC0000419L,
    STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST                             = 0xC000041AL,
    STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST                               = 0xC000041BL,
    STATUS_INVALID_USER_PRINCIPAL_NAME                                 = 0xC000041CL,
    STATUS_FATAL_USER_CALLBACK_EXCEPTION                               = 0xC000041DL,
    STATUS_ASSERTION_FAILURE                                           = 0xC0000420L,
    STATUS_VERIFIER_STOP                                               = 0xC0000421L,
    STATUS_CALLBACK_POP_STACK                                          = 0xC0000423L,
    STATUS_INCOMPATIBLE_DRIVER_BLOCKED                                 = 0xC0000424L,
    STATUS_HIVE_UNLOADED                                               = 0xC0000425L,
    STATUS_COMPRESSION_DISABLED                                        = 0xC0000426L,
    STATUS_FILE_SYSTEM_LIMITATION                                      = 0xC0000427L,
    STATUS_INVALID_IMAGE_HASH                                          = 0xC0000428L,
    STATUS_NOT_CAPABLE                                                 = 0xC0000429L,
    STATUS_REQUEST_OUT_OF_SEQUENCE                                     = 0xC000042AL,
    STATUS_IMPLEMENTATION_LIMIT                                        = 0xC000042BL,
    STATUS_ELEVATION_REQUIRED                                          = 0xC000042CL,
    STATUS_NO_SECURITY_CONTEXT                                         = 0xC000042DL,
    STATUS_PKU2U_CERT_FAILURE                                          = 0xC000042FL,
    STATUS_BEYOND_VDL                                                  = 0xC0000432L,
    STATUS_ENCOUNTERED_WRITE_IN_PROGRESS                               = 0xC0000433L,
    STATUS_PTE_CHANGED                                                 = 0xC0000434L,
    STATUS_PURGE_FAILED                                                = 0xC0000435L,
    STATUS_CRED_REQUIRES_CONFIRMATION                                  = 0xC0000440L,
    STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE                       = 0xC0000441L,
    STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER                            = 0xC0000442L,
    STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE                       = 0xC0000443L,
    STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE                            = 0xC0000444L,
    STATUS_CS_ENCRYPTION_FILE_NOT_CSE                                  = 0xC0000445L,
    STATUS_INVALID_LABEL                                               = 0xC0000446L,
    STATUS_DRIVER_PROCESS_TERMINATED                                   = 0xC0000450L,
    STATUS_AMBIGUOUS_SYSTEM_DEVICE                                     = 0xC0000451L,
    STATUS_SYSTEM_DEVICE_NOT_FOUND                                     = 0xC0000452L,
    STATUS_RESTART_BOOT_APPLICATION                                    = 0xC0000453L,
    STATUS_INSUFFICIENT_NVRAM_RESOURCES                                = 0xC0000454L,
    STATUS_INVALID_SESSION                                             = 0xC0000455L,
    STATUS_THREAD_ALREADY_IN_SESSION                                   = 0xC0000456L,
    STATUS_THREAD_NOT_IN_SESSION                                       = 0xC0000457L,
    STATUS_INVALID_WEIGHT                                              = 0xC0000458L,
    STATUS_REQUEST_PAUSED                                              = 0xC0000459L,
    STATUS_NO_RANGES_PROCESSED                                         = 0xC0000460L,
    STATUS_DISK_RESOURCES_EXHAUSTED                                    = 0xC0000461L,
    STATUS_NEEDS_REMEDIATION                                           = 0xC0000462L,
    STATUS_DEVICE_FEATURE_NOT_SUPPORTED                                = 0xC0000463L,
    STATUS_DEVICE_UNREACHABLE                                          = 0xC0000464L,
    STATUS_INVALID_TOKEN                                               = 0xC0000465L,
    STATUS_SERVER_UNAVAILABLE                                          = 0xC0000466L,
    STATUS_FILE_NOT_AVAILABLE                                          = 0xC0000467L,
    STATUS_DEVICE_INSUFFICIENT_RESOURCES                               = 0xC0000468L,
    STATUS_PACKAGE_UPDATING                                            = 0xC0000469L,
    STATUS_NOT_READ_FROM_COPY                                          = 0xC000046AL,
    STATUS_FT_WRITE_FAILURE                                            = 0xC000046BL,
    STATUS_FT_DI_SCAN_REQUIRED                                         = 0xC000046CL,
    STATUS_OBJECT_NOT_EXTERNALLY_BACKED                                = 0xC000046DL,
    STATUS_EXTERNAL_BACKING_PROVIDER_UNKNOWN                           = 0xC000046EL,
    STATUS_COMPRESSION_NOT_BENEFICIAL                                  = 0xC000046FL,
    STATUS_DATA_CHECKSUM_ERROR                                         = 0xC0000470L,
    STATUS_INTERMIXED_KERNEL_EA_OPERATION                              = 0xC0000471L,
    STATUS_TRIM_READ_ZERO_NOT_SUPPORTED                                = 0xC0000472L,
    STATUS_TOO_MANY_SEGMENT_DESCRIPTORS                                = 0xC0000473L,
    STATUS_INVALID_OFFSET_ALIGNMENT                                    = 0xC0000474L,
    STATUS_INVALID_FIELD_IN_PARAMETER_LIST                             = 0xC0000475L,
    STATUS_OPERATION_IN_PROGRESS                                       = 0xC0000476L,
    STATUS_INVALID_INITIATOR_TARGET_PATH                               = 0xC0000477L,
    STATUS_SCRUB_DATA_DISABLED                                         = 0xC0000478L,
    STATUS_NOT_REDUNDANT_STORAGE                                       = 0xC0000479L,
    STATUS_RESIDENT_FILE_NOT_SUPPORTED                                 = 0xC000047AL,
    STATUS_COMPRESSED_FILE_NOT_SUPPORTED                               = 0xC000047BL,
    STATUS_DIRECTORY_NOT_SUPPORTED                                     = 0xC000047CL,
    STATUS_IO_OPERATION_TIMEOUT                                        = 0xC000047DL,
    STATUS_SYSTEM_NEEDS_REMEDIATION                                    = 0xC000047EL,
    STATUS_APPX_INTEGRITY_FAILURE_CLR_NGEN                             = 0xC000047FL,
    STATUS_SHARE_UNAVAILABLE                                           = 0xC0000480L,
    STATUS_APISET_NOT_HOSTED                                           = 0xC0000481L,
    STATUS_APISET_NOT_PRESENT                                          = 0xC0000482L,
    STATUS_DEVICE_HARDWARE_ERROR                                       = 0xC0000483L,
    STATUS_FIRMWARE_SLOT_INVALID                                       = 0xC0000484L,
    STATUS_FIRMWARE_IMAGE_INVALID                                      = 0xC0000485L,
    STATUS_STORAGE_TOPOLOGY_ID_MISMATCH                                = 0xC0000486L,
    STATUS_WIM_NOT_BOOTABLE                                            = 0xC0000487L,
    STATUS_BLOCKED_BY_PARENTAL_CONTROLS                                = 0xC0000488L,
    STATUS_NEEDS_REGISTRATION                                          = 0xC0000489L,
    STATUS_QUOTA_ACTIVITY                                              = 0xC000048AL,
    STATUS_CALLBACK_INVOKE_INLINE                                      = 0xC000048BL,
    STATUS_BLOCK_TOO_MANY_REFERENCES                                   = 0xC000048CL,
    STATUS_MARKED_TO_DISALLOW_WRITES                                   = 0xC000048DL,
    STATUS_NETWORK_ACCESS_DENIED_EDP                                   = 0xC000048EL,
    STATUS_ENCLAVE_FAILURE                                             = 0xC000048FL,
    STATUS_PNP_NO_COMPAT_DRIVERS                                       = 0xC0000490L,
    STATUS_PNP_DRIVER_PACKAGE_NOT_FOUND                                = 0xC0000491L,
    STATUS_PNP_DRIVER_CONFIGURATION_NOT_FOUND                          = 0xC0000492L,
    STATUS_PNP_DRIVER_CONFIGURATION_INCOMPLETE                         = 0xC0000493L,
    STATUS_PNP_FUNCTION_DRIVER_REQUIRED                                = 0xC0000494L,
    STATUS_PNP_DEVICE_CONFIGURATION_PENDING                            = 0xC0000495L,
    STATUS_DEVICE_HINT_NAME_BUFFER_TOO_SMALL                           = 0xC0000496L,
    STATUS_PACKAGE_NOT_AVAILABLE                                       = 0xC0000497L,
    STATUS_DEVICE_IN_MAINTENANCE                                       = 0xC0000499L,
    STATUS_NOT_SUPPORTED_ON_DAX                                        = 0xC000049AL,
    STATUS_FREE_SPACE_TOO_FRAGMENTED                                   = 0xC000049BL,
    STATUS_DAX_MAPPING_EXISTS                                          = 0xC000049CL,
    STATUS_CHILD_PROCESS_BLOCKED                                       = 0xC000049DL,
    STATUS_STORAGE_LOST_DATA_PERSISTENCE                               = 0xC000049EL,
    STATUS_VRF_CFG_ENABLED                                             = 0xC000049FL,
    STATUS_PARTITION_TERMINATING                                       = 0xC00004A0L,
    STATUS_EXTERNAL_SYSKEY_NOT_SUPPORTED                               = 0xC00004A1L,
    STATUS_ENCLAVE_VIOLATION                                           = 0xC00004A2L,
    STATUS_FILE_PROTECTED_UNDER_DPL                                    = 0xC00004A3L,
    STATUS_VOLUME_NOT_CLUSTER_ALIGNED                                  = 0xC00004A4L,
    STATUS_NO_PHYSICALLY_ALIGNED_FREE_SPACE_FOUND                      = 0xC00004A5L,
    STATUS_APPX_FILE_NOT_ENCRYPTED                                     = 0xC00004A6L,
    STATUS_RWRAW_ENCRYPTED_FILE_NOT_ENCRYPTED                          = 0xC00004A7L,
    STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILEOFFSET                = 0xC00004A8L,
    STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILERANGE                 = 0xC00004A9L,
    STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_PARAMETER                 = 0xC00004AAL,
    STATUS_FT_READ_FAILURE                                             = 0xC00004ABL,
    STATUS_PATCH_CONFLICT                                              = 0xC00004ACL,
    STATUS_STORAGE_RESERVE_ID_INVALID                                  = 0xC00004ADL,
    STATUS_STORAGE_RESERVE_DOES_NOT_EXIST                              = 0xC00004AEL,
    STATUS_STORAGE_RESERVE_ALREADY_EXISTS                              = 0xC00004AFL,
    STATUS_STORAGE_RESERVE_NOT_EMPTY                                   = 0xC00004B0L,
    STATUS_NOT_A_DAX_VOLUME                                            = 0xC00004B1L,
    STATUS_NOT_DAX_MAPPABLE                                            = 0xC00004B2L,
    STATUS_CASE_DIFFERING_NAMES_IN_DIR                                 = 0xC00004B3L,
    STATUS_INVALID_TASK_NAME                                           = 0xC0000500L,
    STATUS_INVALID_TASK_INDEX                                          = 0xC0000501L,
    STATUS_THREAD_ALREADY_IN_TASK                                      = 0xC0000502L,
    STATUS_CALLBACK_BYPASS                                             = 0xC0000503L,
    STATUS_UNDEFINED_SCOPE                                             = 0xC0000504L,
    STATUS_INVALID_CAP                                                 = 0xC0000505L,
    STATUS_NOT_GUI_PROCESS                                             = 0xC0000506L,
    STATUS_DEVICE_HUNG                                                 = 0xC0000507L,
    STATUS_CONTAINER_ASSIGNED                                          = 0xC0000508L,
    STATUS_JOB_NO_CONTAINER                                            = 0xC0000509L,
    STATUS_DEVICE_UNRESPONSIVE                                         = 0xC000050AL,
    STATUS_REPARSE_POINT_ENCOUNTERED                                   = 0xC000050BL,
    STATUS_ATTRIBUTE_NOT_PRESENT                                       = 0xC000050CL,
    STATUS_NOT_A_TIERED_VOLUME                                         = 0xC000050DL,
    STATUS_ALREADY_HAS_STREAM_ID                                       = 0xC000050EL,
    STATUS_JOB_NOT_EMPTY                                               = 0xC000050FL,
    STATUS_ALREADY_INITIALIZED                                         = 0xC0000510L,
    STATUS_ENCLAVE_NOT_TERMINATED                                      = 0xC0000511L,
    STATUS_ENCLAVE_IS_TERMINATING                                      = 0xC0000512L,
    STATUS_SMB1_NOT_AVAILABLE                                          = 0xC0000513L,
    STATUS_SMR_GARBAGE_COLLECTION_REQUIRED                             = 0xC0000514L,
    STATUS_FAIL_FAST_EXCEPTION                                         = 0xC0000602L,
    STATUS_IMAGE_CERT_REVOKED                                          = 0xC0000603L,
    STATUS_DYNAMIC_CODE_BLOCKED                                        = 0xC0000604L,
    STATUS_IMAGE_CERT_EXPIRED                                          = 0xC0000605L,
    STATUS_STRICT_CFG_VIOLATION                                        = 0xC0000606L,
    STATUS_SET_CONTEXT_DENIED                                          = 0xC000060AL,
    STATUS_CROSS_PARTITION_VIOLATION                                   = 0xC000060BL,
    STATUS_PORT_CLOSED                                                 = 0xC0000700L,
    STATUS_MESSAGE_LOST                                                = 0xC0000701L,
    STATUS_INVALID_MESSAGE                                             = 0xC0000702L,
    STATUS_REQUEST_CANCELED                                            = 0xC0000703L,
    STATUS_RECURSIVE_DISPATCH                                          = 0xC0000704L,
    STATUS_LPC_RECEIVE_BUFFER_EXPECTED                                 = 0xC0000705L,
    STATUS_LPC_INVALID_CONNECTION_USAGE                                = 0xC0000706L,
    STATUS_LPC_REQUESTS_NOT_ALLOWED                                    = 0xC0000707L,
    STATUS_RESOURCE_IN_USE                                             = 0xC0000708L,
    STATUS_HARDWARE_MEMORY_ERROR                                       = 0xC0000709L,
    STATUS_THREADPOOL_HANDLE_EXCEPTION                                 = 0xC000070AL,
    STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED                   = 0xC000070BL,
    STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED           = 0xC000070CL,
    STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED               = 0xC000070DL,
    STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED                = 0xC000070EL,
    STATUS_THREADPOOL_RELEASED_DURING_OPERATION                        = 0xC000070FL,
    STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING                       = 0xC0000710L,
    STATUS_APC_RETURNED_WHILE_IMPERSONATING                            = 0xC0000711L,
    STATUS_PROCESS_IS_PROTECTED                                        = 0xC0000712L,
    STATUS_MCA_EXCEPTION                                               = 0xC0000713L,
    STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE                              = 0xC0000714L,
    STATUS_SYMLINK_CLASS_DISABLED                                      = 0xC0000715L,
    STATUS_INVALID_IDN_NORMALIZATION                                   = 0xC0000716L,
    STATUS_NO_UNICODE_TRANSLATION                                      = 0xC0000717L,
    STATUS_ALREADY_REGISTERED                                          = 0xC0000718L,
    STATUS_CONTEXT_MISMATCH                                            = 0xC0000719L,
    STATUS_PORT_ALREADY_HAS_COMPLETION_LIST                            = 0xC000071AL,
    STATUS_CALLBACK_RETURNED_THREAD_PRIORITY                           = 0xC000071BL,
    STATUS_INVALID_THREAD                                              = 0xC000071CL,
    STATUS_CALLBACK_RETURNED_TRANSACTION                               = 0xC000071DL,
    STATUS_CALLBACK_RETURNED_LDR_LOCK                                  = 0xC000071EL,
    STATUS_CALLBACK_RETURNED_LANG                                      = 0xC000071FL,
    STATUS_CALLBACK_RETURNED_PRI_BACK                                  = 0xC0000720L,
    STATUS_CALLBACK_RETURNED_THREAD_AFFINITY                           = 0xC0000721L,
    STATUS_LPC_HANDLE_COUNT_EXCEEDED                                   = 0xC0000722L,
    STATUS_EXECUTABLE_MEMORY_WRITE                                     = 0xC0000723L,
    STATUS_KERNEL_EXECUTABLE_MEMORY_WRITE                              = 0xC0000724L,
    STATUS_ATTACHED_EXECUTABLE_MEMORY_WRITE                            = 0xC0000725L,
    STATUS_TRIGGERED_EXECUTABLE_MEMORY_WRITE                           = 0xC0000726L,
    STATUS_DISK_REPAIR_DISABLED                                        = 0xC0000800L,
    STATUS_DS_DOMAIN_RENAME_IN_PROGRESS                                = 0xC0000801L,
    STATUS_DISK_QUOTA_EXCEEDED                                         = 0xC0000802L,
    STATUS_DATA_LOST_REPAIR                                            = 0x80000803L,
    STATUS_CONTENT_BLOCKED                                             = 0xC0000804L,
    STATUS_BAD_CLUSTERS                                                = 0xC0000805L,
    STATUS_VOLUME_DIRTY                                                = 0xC0000806L,
    STATUS_DISK_REPAIR_REDIRECTED                                      = 0x40000807L,
    STATUS_DISK_REPAIR_UNSUCCESSFUL                                    = 0xC0000808L,
    STATUS_CORRUPT_LOG_OVERFULL                                        = 0xC0000809L,
    STATUS_CORRUPT_LOG_CORRUPTED                                       = 0xC000080AL,
    STATUS_CORRUPT_LOG_UNAVAILABLE                                     = 0xC000080BL,
    STATUS_CORRUPT_LOG_DELETED_FULL                                    = 0xC000080CL,
    STATUS_CORRUPT_LOG_CLEARED                                         = 0xC000080DL,
    STATUS_ORPHAN_NAME_EXHAUSTED                                       = 0xC000080EL,
    STATUS_PROACTIVE_SCAN_IN_PROGRESS                                  = 0xC000080FL,
    STATUS_ENCRYPTED_IO_NOT_POSSIBLE                                   = 0xC0000810L,
    STATUS_CORRUPT_LOG_UPLEVEL_RECORDS                                 = 0xC0000811L,
    STATUS_FILE_CHECKED_OUT                                            = 0xC0000901L,
    STATUS_CHECKOUT_REQUIRED                                           = 0xC0000902L,
    STATUS_BAD_FILE_TYPE                                               = 0xC0000903L,
    STATUS_FILE_TOO_LARGE                                              = 0xC0000904L,
    STATUS_FORMS_AUTH_REQUIRED                                         = 0xC0000905L,
    STATUS_VIRUS_INFECTED                                              = 0xC0000906L,
    STATUS_VIRUS_DELETED                                               = 0xC0000907L,
    STATUS_BAD_MCFG_TABLE                                              = 0xC0000908L,
    STATUS_CANNOT_BREAK_OPLOCK                                         = 0xC0000909L,
    STATUS_BAD_KEY                                                     = 0xC000090AL,
    STATUS_BAD_DATA                                                    = 0xC000090BL,
    STATUS_NO_KEY                                                      = 0xC000090CL,
    STATUS_FILE_HANDLE_REVOKED                                         = 0xC0000910L,
    STATUS_WOW_ASSERTION                                               = 0xC0009898L,
    STATUS_INVALID_SIGNATURE                                           = 0xC000A000L,
    STATUS_HMAC_NOT_SUPPORTED                                          = 0xC000A001L,
    STATUS_AUTH_TAG_MISMATCH                                           = 0xC000A002L,
    STATUS_INVALID_STATE_TRANSITION                                    = 0xC000A003L,
    STATUS_INVALID_KERNEL_INFO_VERSION                                 = 0xC000A004L,
    STATUS_INVALID_PEP_INFO_VERSION                                    = 0xC000A005L,
    STATUS_HANDLE_REVOKED                                              = 0xC000A006L,
    STATUS_EOF_ON_GHOSTED_RANGE                                        = 0xC000A007L,
    STATUS_IPSEC_QUEUE_OVERFLOW                                        = 0xC000A010L,
    STATUS_ND_QUEUE_OVERFLOW                                           = 0xC000A011L,
    STATUS_HOPLIMIT_EXCEEDED                                           = 0xC000A012L,
    STATUS_PROTOCOL_NOT_SUPPORTED                                      = 0xC000A013L,
    STATUS_FASTPATH_REJECTED                                           = 0xC000A014L,
    STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED                  = 0xC000A080L,
    STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR                  = 0xC000A081L,
    STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR                      = 0xC000A082L,
    STATUS_XML_PARSE_ERROR                                             = 0xC000A083L,
    STATUS_XMLDSIG_ERROR                                               = 0xC000A084L,
    STATUS_WRONG_COMPARTMENT                                           = 0xC000A085L,
    STATUS_AUTHIP_FAILURE                                              = 0xC000A086L,
    STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS                       = 0xC000A087L,
    STATUS_DS_OID_NOT_FOUND                                            = 0xC000A088L,
    STATUS_INCORRECT_ACCOUNT_TYPE                                      = 0xC000A089L,
    STATUS_HASH_NOT_SUPPORTED                                          = 0xC000A100L,
    STATUS_HASH_NOT_PRESENT                                            = 0xC000A101L,
    STATUS_SECONDARY_IC_PROVIDER_NOT_REGISTERED                        = 0xC000A121L,
    STATUS_GPIO_CLIENT_INFORMATION_INVALID                             = 0xC000A122L,
    STATUS_GPIO_VERSION_NOT_SUPPORTED                                  = 0xC000A123L,
    STATUS_GPIO_INVALID_REGISTRATION_PACKET                            = 0xC000A124L,
    STATUS_GPIO_OPERATION_DENIED                                       = 0xC000A125L,
    STATUS_GPIO_INCOMPATIBLE_CONNECT_MODE                              = 0xC000A126L,
    STATUS_GPIO_INTERRUPT_ALREADY_UNMASKED                             = 0x8000A127L,
    STATUS_CANNOT_SWITCH_RUNLEVEL                                      = 0xC000A141L,
    STATUS_INVALID_RUNLEVEL_SETTING                                    = 0xC000A142L,
    STATUS_RUNLEVEL_SWITCH_TIMEOUT                                     = 0xC000A143L,
    STATUS_SERVICES_FAILED_AUTOSTART                                   = 0x4000A144L,
    STATUS_RUNLEVEL_SWITCH_AGENT_TIMEOUT                               = 0xC000A145L,
    STATUS_RUNLEVEL_SWITCH_IN_PROGRESS                                 = 0xC000A146L,
    STATUS_NOT_APPCONTAINER                                            = 0xC000A200L,
    STATUS_NOT_SUPPORTED_IN_APPCONTAINER                               = 0xC000A201L,
    STATUS_INVALID_PACKAGE_SID_LENGTH                                  = 0xC000A202L,
    STATUS_LPAC_ACCESS_DENIED                                          = 0xC000A203L,
    STATUS_ADMINLESS_ACCESS_DENIED                                     = 0xC000A204L,
    STATUS_APP_DATA_NOT_FOUND                                          = 0xC000A281L,
    STATUS_APP_DATA_EXPIRED                                            = 0xC000A282L,
    STATUS_APP_DATA_CORRUPT                                            = 0xC000A283L,
    STATUS_APP_DATA_LIMIT_EXCEEDED                                     = 0xC000A284L,
    STATUS_APP_DATA_REBOOT_REQUIRED                                    = 0xC000A285L,
    STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED                              = 0xC000A2A1L,
    STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED                             = 0xC000A2A2L,
    STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED                             = 0xC000A2A3L,
    STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED                            = 0xC000A2A4L,
    STATUS_WOF_WIM_HEADER_CORRUPT                                      = 0xC000A2A5L,
    STATUS_WOF_WIM_RESOURCE_TABLE_CORRUPT                              = 0xC000A2A6L,
    STATUS_WOF_FILE_RESOURCE_TABLE_CORRUPT                             = 0xC000A2A7L,
    STATUS_FILE_SYSTEM_VIRTUALIZATION_UNAVAILABLE                      = 0xC000CE01L,
    STATUS_FILE_SYSTEM_VIRTUALIZATION_METADATA_CORRUPT                 = 0xC000CE02L,
    STATUS_FILE_SYSTEM_VIRTUALIZATION_BUSY                             = 0xC000CE03L,
    STATUS_FILE_SYSTEM_VIRTUALIZATION_PROVIDER_UNKNOWN                 = 0xC000CE04L,
    STATUS_FILE_SYSTEM_VIRTUALIZATION_INVALID_OPERATION                = 0xC000CE05L,
    STATUS_CLOUD_FILE_SYNC_ROOT_METADATA_CORRUPT                       = 0xC000CF00L,
    STATUS_CLOUD_FILE_PROVIDER_NOT_RUNNING                             = 0xC000CF01L,
    STATUS_CLOUD_FILE_METADATA_CORRUPT                                 = 0xC000CF02L,
    STATUS_CLOUD_FILE_METADATA_TOO_LARGE                               = 0xC000CF03L,
    STATUS_CLOUD_FILE_PROPERTY_BLOB_TOO_LARGE                          = 0x8000CF04L,
    STATUS_CLOUD_FILE_TOO_MANY_PROPERTY_BLOBS                          = 0x8000CF05L,
    STATUS_CLOUD_FILE_PROPERTY_VERSION_NOT_SUPPORTED                   = 0xC000CF06L,
    STATUS_NOT_A_CLOUD_FILE                                            = 0xC000CF07L,
    STATUS_CLOUD_FILE_NOT_IN_SYNC                                      = 0xC000CF08L,
    STATUS_CLOUD_FILE_ALREADY_CONNECTED                                = 0xC000CF09L,
    STATUS_CLOUD_FILE_NOT_SUPPORTED                                    = 0xC000CF0AL,
    STATUS_CLOUD_FILE_INVALID_REQUEST                                  = 0xC000CF0BL,
    STATUS_CLOUD_FILE_READ_ONLY_VOLUME                                 = 0xC000CF0CL,
    STATUS_CLOUD_FILE_CONNECTED_PROVIDER_ONLY                          = 0xC000CF0DL,
    STATUS_CLOUD_FILE_VALIDATION_FAILED                                = 0xC000CF0EL,
    STATUS_CLOUD_FILE_AUTHENTICATION_FAILED                            = 0xC000CF0FL,
    STATUS_CLOUD_FILE_INSUFFICIENT_RESOURCES                           = 0xC000CF10L,
    STATUS_CLOUD_FILE_NETWORK_UNAVAILABLE                              = 0xC000CF11L,
    STATUS_CLOUD_FILE_UNSUCCESSFUL                                     = 0xC000CF12L,
    STATUS_CLOUD_FILE_NOT_UNDER_SYNC_ROOT                              = 0xC000CF13L,
    STATUS_CLOUD_FILE_IN_USE                                           = 0xC000CF14L,
    STATUS_CLOUD_FILE_PINNED                                           = 0xC000CF15L,
    STATUS_CLOUD_FILE_REQUEST_ABORTED                                  = 0xC000CF16L,
    STATUS_CLOUD_FILE_PROPERTY_CORRUPT                                 = 0xC000CF17L,
    STATUS_CLOUD_FILE_ACCESS_DENIED                                    = 0xC000CF18L,
    STATUS_CLOUD_FILE_INCOMPATIBLE_HARDLINKS                           = 0xC000CF19L,
    STATUS_CLOUD_FILE_PROPERTY_LOCK_CONFLICT                           = 0xC000CF1AL,
    STATUS_CLOUD_FILE_REQUEST_CANCELED                                 = 0xC000CF1BL,
    STATUS_CLOUD_FILE_PROVIDER_TERMINATED                              = 0xC000CF1DL,
    STATUS_NOT_A_CLOUD_SYNC_ROOT                                       = 0xC000CF1EL,
    DBG_NO_STATE_CHANGE                                                = 0xC0010001L,
    DBG_APP_NOT_IDLE                                                   = 0xC0010002L,
    RPC_NT_INVALID_STRING_BINDING                                      = 0xC0020001L,
    RPC_NT_WRONG_KIND_OF_BINDING                                       = 0xC0020002L,
    RPC_NT_INVALID_BINDING                                             = 0xC0020003L,
    RPC_NT_PROTSEQ_NOT_SUPPORTED                                       = 0xC0020004L,
    RPC_NT_INVALID_RPC_PROTSEQ                                         = 0xC0020005L,
    RPC_NT_INVALID_STRING_UUID                                         = 0xC0020006L,
    RPC_NT_INVALID_ENDPOINT_FORMAT                                     = 0xC0020007L,
    RPC_NT_INVALID_NET_ADDR                                            = 0xC0020008L,
    RPC_NT_NO_ENDPOINT_FOUND                                           = 0xC0020009L,
    RPC_NT_INVALID_TIMEOUT                                             = 0xC002000AL,
    RPC_NT_OBJECT_NOT_FOUND                                            = 0xC002000BL,
    RPC_NT_ALREADY_REGISTERED                                          = 0xC002000CL,
    RPC_NT_TYPE_ALREADY_REGISTERED                                     = 0xC002000DL,
    RPC_NT_ALREADY_LISTENING                                           = 0xC002000EL,
    RPC_NT_NO_PROTSEQS_REGISTERED                                      = 0xC002000FL,
    RPC_NT_NOT_LISTENING                                               = 0xC0020010L,
    RPC_NT_UNKNOWN_MGR_TYPE                                            = 0xC0020011L,
    RPC_NT_UNKNOWN_IF                                                  = 0xC0020012L,
    RPC_NT_NO_BINDINGS                                                 = 0xC0020013L,
    RPC_NT_NO_PROTSEQS                                                 = 0xC0020014L,
    RPC_NT_CANT_CREATE_ENDPOINT                                        = 0xC0020015L,
    RPC_NT_OUT_OF_RESOURCES                                            = 0xC0020016L,
    RPC_NT_SERVER_UNAVAILABLE                                          = 0xC0020017L,
    RPC_NT_SERVER_TOO_BUSY                                             = 0xC0020018L,
    RPC_NT_INVALID_NETWORK_OPTIONS                                     = 0xC0020019L,
    RPC_NT_NO_CALL_ACTIVE                                              = 0xC002001AL,
    RPC_NT_CALL_FAILED                                                 = 0xC002001BL,
    RPC_NT_CALL_FAILED_DNE                                             = 0xC002001CL,
    RPC_NT_PROTOCOL_ERROR                                              = 0xC002001DL,
    RPC_NT_UNSUPPORTED_TRANS_SYN                                       = 0xC002001FL,
    RPC_NT_UNSUPPORTED_TYPE                                            = 0xC0020021L,
    RPC_NT_INVALID_TAG                                                 = 0xC0020022L,
    RPC_NT_INVALID_BOUND                                               = 0xC0020023L,
    RPC_NT_NO_ENTRY_NAME                                               = 0xC0020024L,
    RPC_NT_INVALID_NAME_SYNTAX                                         = 0xC0020025L,
    RPC_NT_UNSUPPORTED_NAME_SYNTAX                                     = 0xC0020026L,
    RPC_NT_UUID_NO_ADDRESS                                             = 0xC0020028L,
    RPC_NT_DUPLICATE_ENDPOINT                                          = 0xC0020029L,
    RPC_NT_UNKNOWN_AUTHN_TYPE                                          = 0xC002002AL,
    RPC_NT_MAX_CALLS_TOO_SMALL                                         = 0xC002002BL,
    RPC_NT_STRING_TOO_LONG                                             = 0xC002002CL,
    RPC_NT_PROTSEQ_NOT_FOUND                                           = 0xC002002DL,
    RPC_NT_PROCNUM_OUT_OF_RANGE                                        = 0xC002002EL,
    RPC_NT_BINDING_HAS_NO_AUTH                                         = 0xC002002FL,
    RPC_NT_UNKNOWN_AUTHN_SERVICE                                       = 0xC0020030L,
    RPC_NT_UNKNOWN_AUTHN_LEVEL                                         = 0xC0020031L,
    RPC_NT_INVALID_AUTH_IDENTITY                                       = 0xC0020032L,
    RPC_NT_UNKNOWN_AUTHZ_SERVICE                                       = 0xC0020033L,
    EPT_NT_INVALID_ENTRY                                               = 0xC0020034L,
    EPT_NT_CANT_PERFORM_OP                                             = 0xC0020035L,
    EPT_NT_NOT_REGISTERED                                              = 0xC0020036L,
    RPC_NT_NOTHING_TO_EXPORT                                           = 0xC0020037L,
    RPC_NT_INCOMPLETE_NAME                                             = 0xC0020038L,
    RPC_NT_INVALID_VERS_OPTION                                         = 0xC0020039L,
    RPC_NT_NO_MORE_MEMBERS                                             = 0xC002003AL,
    RPC_NT_NOT_ALL_OBJS_UNEXPORTED                                     = 0xC002003BL,
    RPC_NT_INTERFACE_NOT_FOUND                                         = 0xC002003CL,
    RPC_NT_ENTRY_ALREADY_EXISTS                                        = 0xC002003DL,
    RPC_NT_ENTRY_NOT_FOUND                                             = 0xC002003EL,
    RPC_NT_NAME_SERVICE_UNAVAILABLE                                    = 0xC002003FL,
    RPC_NT_INVALID_NAF_ID                                              = 0xC0020040L,
    RPC_NT_CANNOT_SUPPORT                                              = 0xC0020041L,
    RPC_NT_NO_CONTEXT_AVAILABLE                                        = 0xC0020042L,
    RPC_NT_INTERNAL_ERROR                                              = 0xC0020043L,
    RPC_NT_ZERO_DIVIDE                                                 = 0xC0020044L,
    RPC_NT_ADDRESS_ERROR                                               = 0xC0020045L,
    RPC_NT_FP_DIV_ZERO                                                 = 0xC0020046L,
    RPC_NT_FP_UNDERFLOW                                                = 0xC0020047L,
    RPC_NT_FP_OVERFLOW                                                 = 0xC0020048L,
    RPC_NT_NO_MORE_ENTRIES                                             = 0xC0030001L,
    RPC_NT_SS_CHAR_TRANS_OPEN_FAIL                                     = 0xC0030002L,
    RPC_NT_SS_CHAR_TRANS_SHORT_FILE                                    = 0xC0030003L,
    RPC_NT_SS_IN_NULL_CONTEXT                                          = 0xC0030004L,
    RPC_NT_SS_CONTEXT_MISMATCH                                         = 0xC0030005L,
    RPC_NT_SS_CONTEXT_DAMAGED                                          = 0xC0030006L,
    RPC_NT_SS_HANDLES_MISMATCH                                         = 0xC0030007L,
    RPC_NT_SS_CANNOT_GET_CALL_HANDLE                                   = 0xC0030008L,
    RPC_NT_NULL_REF_POINTER                                            = 0xC0030009L,
    RPC_NT_ENUM_VALUE_OUT_OF_RANGE                                     = 0xC003000AL,
    RPC_NT_BYTE_COUNT_TOO_SMALL                                        = 0xC003000BL,
    RPC_NT_BAD_STUB_DATA                                               = 0xC003000CL,
    RPC_NT_CALL_IN_PROGRESS                                            = 0xC0020049L,
    RPC_NT_NO_MORE_BINDINGS                                            = 0xC002004AL,
    RPC_NT_GROUP_MEMBER_NOT_FOUND                                      = 0xC002004BL,
    EPT_NT_CANT_CREATE                                                 = 0xC002004CL,
    RPC_NT_INVALID_OBJECT                                              = 0xC002004DL,
    RPC_NT_NO_INTERFACES                                               = 0xC002004FL,
    RPC_NT_CALL_CANCELLED                                              = 0xC0020050L,
    RPC_NT_BINDING_INCOMPLETE                                          = 0xC0020051L,
    RPC_NT_COMM_FAILURE                                                = 0xC0020052L,
    RPC_NT_UNSUPPORTED_AUTHN_LEVEL                                     = 0xC0020053L,
    RPC_NT_NO_PRINC_NAME                                               = 0xC0020054L,
    RPC_NT_NOT_RPC_ERROR                                               = 0xC0020055L,
    RPC_NT_UUID_LOCAL_ONLY                                             = 0x40020056L,
    RPC_NT_SEC_PKG_ERROR                                               = 0xC0020057L,
    RPC_NT_NOT_CANCELLED                                               = 0xC0020058L,
    RPC_NT_INVALID_ES_ACTION                                           = 0xC0030059L,
    RPC_NT_WRONG_ES_VERSION                                            = 0xC003005AL,
    RPC_NT_WRONG_STUB_VERSION                                          = 0xC003005BL,
    RPC_NT_INVALID_PIPE_OBJECT                                         = 0xC003005CL,
    RPC_NT_INVALID_PIPE_OPERATION                                      = 0xC003005DL,
    RPC_NT_WRONG_PIPE_VERSION                                          = 0xC003005EL,
    RPC_NT_PIPE_CLOSED                                                 = 0xC003005FL,
    RPC_NT_PIPE_DISCIPLINE_ERROR                                       = 0xC0030060L,
    RPC_NT_PIPE_EMPTY                                                  = 0xC0030061L,
    RPC_NT_INVALID_ASYNC_HANDLE                                        = 0xC0020062L,
    RPC_NT_INVALID_ASYNC_CALL                                          = 0xC0020063L,
    RPC_NT_PROXY_ACCESS_DENIED                                         = 0xC0020064L,
    RPC_NT_COOKIE_AUTH_FAILED                                          = 0xC0020065L,
    RPC_NT_SEND_INCOMPLETE                                             = 0x400200AFL,
    STATUS_ACPI_INVALID_OPCODE                                         = 0xC0140001L,
    STATUS_ACPI_STACK_OVERFLOW                                         = 0xC0140002L,
    STATUS_ACPI_ASSERT_FAILED                                          = 0xC0140003L,
    STATUS_ACPI_INVALID_INDEX                                          = 0xC0140004L,
    STATUS_ACPI_INVALID_ARGUMENT                                       = 0xC0140005L,
    STATUS_ACPI_FATAL                                                  = 0xC0140006L,
    STATUS_ACPI_INVALID_SUPERNAME                                      = 0xC0140007L,
    STATUS_ACPI_INVALID_ARGTYPE                                        = 0xC0140008L,
    STATUS_ACPI_INVALID_OBJTYPE                                        = 0xC0140009L,
    STATUS_ACPI_INVALID_TARGETTYPE                                     = 0xC014000AL,
    STATUS_ACPI_INCORRECT_ARGUMENT_COUNT                               = 0xC014000BL,
    STATUS_ACPI_ADDRESS_NOT_MAPPED                                     = 0xC014000CL,
    STATUS_ACPI_INVALID_EVENTTYPE                                      = 0xC014000DL,
    STATUS_ACPI_HANDLER_COLLISION                                      = 0xC014000EL,
    STATUS_ACPI_INVALID_DATA                                           = 0xC014000FL,
    STATUS_ACPI_INVALID_REGION                                         = 0xC0140010L,
    STATUS_ACPI_INVALID_ACCESS_SIZE                                    = 0xC0140011L,
    STATUS_ACPI_ACQUIRE_GLOBAL_LOCK                                    = 0xC0140012L,
    STATUS_ACPI_ALREADY_INITIALIZED                                    = 0xC0140013L,
    STATUS_ACPI_NOT_INITIALIZED                                        = 0xC0140014L,
    STATUS_ACPI_INVALID_MUTEX_LEVEL                                    = 0xC0140015L,
    STATUS_ACPI_MUTEX_NOT_OWNED                                        = 0xC0140016L,
    STATUS_ACPI_MUTEX_NOT_OWNER                                        = 0xC0140017L,
    STATUS_ACPI_RS_ACCESS                                              = 0xC0140018L,
    STATUS_ACPI_INVALID_TABLE                                          = 0xC0140019L,
    STATUS_ACPI_REG_HANDLER_FAILED                                     = 0xC0140020L,
    STATUS_ACPI_POWER_REQUEST_FAILED                                   = 0xC0140021L,
    STATUS_CTX_WINSTATION_NAME_INVALID                                 = 0xC00A0001L,
    STATUS_CTX_INVALID_PD                                              = 0xC00A0002L,
    STATUS_CTX_PD_NOT_FOUND                                            = 0xC00A0003L,
    STATUS_CTX_CDM_CONNECT                                             = 0x400A0004L,
    STATUS_CTX_CDM_DISCONNECT                                          = 0x400A0005L,
    STATUS_CTX_CLOSE_PENDING                                           = 0xC00A0006L,
    STATUS_CTX_NO_OUTBUF                                               = 0xC00A0007L,
    STATUS_CTX_MODEM_INF_NOT_FOUND                                     = 0xC00A0008L,
    STATUS_CTX_INVALID_MODEMNAME                                       = 0xC00A0009L,
    STATUS_CTX_RESPONSE_ERROR                                          = 0xC00A000AL,
    STATUS_CTX_MODEM_RESPONSE_TIMEOUT                                  = 0xC00A000BL,
    STATUS_CTX_MODEM_RESPONSE_NO_CARRIER                               = 0xC00A000CL,
    STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE                              = 0xC00A000DL,
    STATUS_CTX_MODEM_RESPONSE_BUSY                                     = 0xC00A000EL,
    STATUS_CTX_MODEM_RESPONSE_VOICE                                    = 0xC00A000FL,
    STATUS_CTX_TD_ERROR                                                = 0xC00A0010L,
    STATUS_CTX_LICENSE_CLIENT_INVALID                                  = 0xC00A0012L,
    STATUS_CTX_LICENSE_NOT_AVAILABLE                                   = 0xC00A0013L,
    STATUS_CTX_LICENSE_EXPIRED                                         = 0xC00A0014L,
    STATUS_CTX_WINSTATION_NOT_FOUND                                    = 0xC00A0015L,
    STATUS_CTX_WINSTATION_NAME_COLLISION                               = 0xC00A0016L,
    STATUS_CTX_WINSTATION_BUSY                                         = 0xC00A0017L,
    STATUS_CTX_BAD_VIDEO_MODE                                          = 0xC00A0018L,
    STATUS_CTX_GRAPHICS_INVALID                                        = 0xC00A0022L,
    STATUS_CTX_NOT_CONSOLE                                             = 0xC00A0024L,
    STATUS_CTX_CLIENT_QUERY_TIMEOUT                                    = 0xC00A0026L,
    STATUS_CTX_CONSOLE_DISCONNECT                                      = 0xC00A0027L,
    STATUS_CTX_CONSOLE_CONNECT                                         = 0xC00A0028L,
    STATUS_CTX_SHADOW_DENIED                                           = 0xC00A002AL,
    STATUS_CTX_WINSTATION_ACCESS_DENIED                                = 0xC00A002BL,
    STATUS_CTX_INVALID_WD                                              = 0xC00A002EL,
    STATUS_CTX_WD_NOT_FOUND                                            = 0xC00A002FL,
    STATUS_CTX_SHADOW_INVALID                                          = 0xC00A0030L,
    STATUS_CTX_SHADOW_DISABLED                                         = 0xC00A0031L,
    STATUS_RDP_PROTOCOL_ERROR                                          = 0xC00A0032L,
    STATUS_CTX_CLIENT_LICENSE_NOT_SET                                  = 0xC00A0033L,
    STATUS_CTX_CLIENT_LICENSE_IN_USE                                   = 0xC00A0034L,
    STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE                             = 0xC00A0035L,
    STATUS_CTX_SHADOW_NOT_RUNNING                                      = 0xC00A0036L,
    STATUS_CTX_LOGON_DISABLED                                          = 0xC00A0037L,
    STATUS_CTX_SECURITY_LAYER_ERROR                                    = 0xC00A0038L,
    STATUS_TS_INCOMPATIBLE_SESSIONS                                    = 0xC00A0039L,
    STATUS_TS_VIDEO_SUBSYSTEM_ERROR                                    = 0xC00A003AL,
    STATUS_PNP_BAD_MPS_TABLE                                           = 0xC0040035L,
    STATUS_PNP_TRANSLATION_FAILED                                      = 0xC0040036L,
    STATUS_PNP_IRQ_TRANSLATION_FAILED                                  = 0xC0040037L,
    STATUS_PNP_INVALID_ID                                              = 0xC0040038L,
    STATUS_IO_REISSUE_AS_CACHED                                        = 0xC0040039L,
    STATUS_MUI_FILE_NOT_FOUND                                          = 0xC00B0001L,
    STATUS_MUI_INVALID_FILE                                            = 0xC00B0002L,
    STATUS_MUI_INVALID_RC_CONFIG                                       = 0xC00B0003L,
    STATUS_MUI_INVALID_LOCALE_NAME                                     = 0xC00B0004L,
    STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME                           = 0xC00B0005L,
    STATUS_MUI_FILE_NOT_LOADED                                         = 0xC00B0006L,
    STATUS_RESOURCE_ENUM_USER_STOP                                     = 0xC00B0007L,
    STATUS_FLT_NO_HANDLER_DEFINED                                      = 0xC01C0001L,
    STATUS_FLT_CONTEXT_ALREADY_DEFINED                                 = 0xC01C0002L,
    STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST                            = 0xC01C0003L,
    STATUS_FLT_DISALLOW_FAST_IO                                        = 0xC01C0004L,
    STATUS_FLT_INVALID_NAME_REQUEST                                    = 0xC01C0005L,
    STATUS_FLT_NOT_SAFE_TO_POST_OPERATION                              = 0xC01C0006L,
    STATUS_FLT_NOT_INITIALIZED                                         = 0xC01C0007L,
    STATUS_FLT_FILTER_NOT_READY                                        = 0xC01C0008L,
    STATUS_FLT_POST_OPERATION_CLEANUP                                  = 0xC01C0009L,
    STATUS_FLT_INTERNAL_ERROR                                          = 0xC01C000AL,
    STATUS_FLT_DELETING_OBJECT                                         = 0xC01C000BL,
    STATUS_FLT_MUST_BE_NONPAGED_POOL                                   = 0xC01C000CL,
    STATUS_FLT_DUPLICATE_ENTRY                                         = 0xC01C000DL,
    STATUS_FLT_CBDQ_DISABLED                                           = 0xC01C000EL,
    STATUS_FLT_DO_NOT_ATTACH                                           = 0xC01C000FL,
    STATUS_FLT_DO_NOT_DETACH                                           = 0xC01C0010L,
    STATUS_FLT_INSTANCE_ALTITUDE_COLLISION                             = 0xC01C0011L,
    STATUS_FLT_INSTANCE_NAME_COLLISION                                 = 0xC01C0012L,
    STATUS_FLT_FILTER_NOT_FOUND                                        = 0xC01C0013L,
    STATUS_FLT_VOLUME_NOT_FOUND                                        = 0xC01C0014L,
    STATUS_FLT_INSTANCE_NOT_FOUND                                      = 0xC01C0015L,
    STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND                            = 0xC01C0016L,
    STATUS_FLT_INVALID_CONTEXT_REGISTRATION                            = 0xC01C0017L,
    STATUS_FLT_NAME_CACHE_MISS                                         = 0xC01C0018L,
    STATUS_FLT_NO_DEVICE_OBJECT                                        = 0xC01C0019L,
    STATUS_FLT_VOLUME_ALREADY_MOUNTED                                  = 0xC01C001AL,
    STATUS_FLT_ALREADY_ENLISTED                                        = 0xC01C001BL,
    STATUS_FLT_CONTEXT_ALREADY_LINKED                                  = 0xC01C001CL,
    STATUS_FLT_NO_WAITER_FOR_REPLY                                     = 0xC01C0020L,
    STATUS_FLT_REGISTRATION_BUSY                                       = 0xC01C0023L,
    STATUS_SXS_SECTION_NOT_FOUND                                       = 0xC0150001L,
    STATUS_SXS_CANT_GEN_ACTCTX                                         = 0xC0150002L,
    STATUS_SXS_INVALID_ACTCTXDATA_FORMAT                               = 0xC0150003L,
    STATUS_SXS_ASSEMBLY_NOT_FOUND                                      = 0xC0150004L,
    STATUS_SXS_MANIFEST_FORMAT_ERROR                                   = 0xC0150005L,
    STATUS_SXS_MANIFEST_PARSE_ERROR                                    = 0xC0150006L,
    STATUS_SXS_ACTIVATION_CONTEXT_DISABLED                             = 0xC0150007L,
    STATUS_SXS_KEY_NOT_FOUND                                           = 0xC0150008L,
    STATUS_SXS_VERSION_CONFLICT                                        = 0xC0150009L,
    STATUS_SXS_WRONG_SECTION_TYPE                                      = 0xC015000AL,
    STATUS_SXS_THREAD_QUERIES_DISABLED                                 = 0xC015000BL,
    STATUS_SXS_ASSEMBLY_MISSING                                        = 0xC015000CL,
    STATUS_SXS_RELEASE_ACTIVATION_CONTEXT                              = 0x4015000DL,
    STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET                             = 0xC015000EL,
    STATUS_SXS_EARLY_DEACTIVATION                                      = 0xC015000FL,
    STATUS_SXS_INVALID_DEACTIVATION                                    = 0xC0150010L,
    STATUS_SXS_MULTIPLE_DEACTIVATION                                   = 0xC0150011L,
    STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY                 = 0xC0150012L,
    STATUS_SXS_PROCESS_TERMINATION_REQUESTED                           = 0xC0150013L,
    STATUS_SXS_CORRUPT_ACTIVATION_STACK                                = 0xC0150014L,
    STATUS_SXS_CORRUPTION                                              = 0xC0150015L,
    STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE                        = 0xC0150016L,
    STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME                         = 0xC0150017L,
    STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE                            = 0xC0150018L,
    STATUS_SXS_IDENTITY_PARSE_ERROR                                    = 0xC0150019L,
    STATUS_SXS_COMPONENT_STORE_CORRUPT                                 = 0xC015001AL,
    STATUS_SXS_FILE_HASH_MISMATCH                                      = 0xC015001BL,
    STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT           = 0xC015001CL,
    STATUS_SXS_IDENTITIES_DIFFERENT                                    = 0xC015001DL,
    STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT                            = 0xC015001EL,
    STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY                               = 0xC015001FL,
    STATUS_ADVANCED_INSTALLER_FAILED                                   = 0xC0150020L,
    STATUS_XML_ENCODING_MISMATCH                                       = 0xC0150021L,
    STATUS_SXS_MANIFEST_TOO_BIG                                        = 0xC0150022L,
    STATUS_SXS_SETTING_NOT_REGISTERED                                  = 0xC0150023L,
    STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE                          = 0xC0150024L,
    STATUS_SMI_PRIMITIVE_INSTALLER_FAILED                              = 0xC0150025L,
    STATUS_GENERIC_COMMAND_FAILED                                      = 0xC0150026L,
    STATUS_SXS_FILE_HASH_MISSING                                       = 0xC0150027L,
    STATUS_CLUSTER_INVALID_NODE                                        = 0xC0130001L,
    STATUS_CLUSTER_NODE_EXISTS                                         = 0xC0130002L,
    STATUS_CLUSTER_JOIN_IN_PROGRESS                                    = 0xC0130003L,
    STATUS_CLUSTER_NODE_NOT_FOUND                                      = 0xC0130004L,
    STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND                                = 0xC0130005L,
    STATUS_CLUSTER_NETWORK_EXISTS                                      = 0xC0130006L,
    STATUS_CLUSTER_NETWORK_NOT_FOUND                                   = 0xC0130007L,
    STATUS_CLUSTER_NETINTERFACE_EXISTS                                 = 0xC0130008L,
    STATUS_CLUSTER_NETINTERFACE_NOT_FOUND                              = 0xC0130009L,
    STATUS_CLUSTER_INVALID_REQUEST                                     = 0xC013000AL,
    STATUS_CLUSTER_INVALID_NETWORK_PROVIDER                            = 0xC013000BL,
    STATUS_CLUSTER_NODE_DOWN                                           = 0xC013000CL,
    STATUS_CLUSTER_NODE_UNREACHABLE                                    = 0xC013000DL,
    STATUS_CLUSTER_NODE_NOT_MEMBER                                     = 0xC013000EL,
    STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS                                = 0xC013000FL,
    STATUS_CLUSTER_INVALID_NETWORK                                     = 0xC0130010L,
    STATUS_CLUSTER_NO_NET_ADAPTERS                                     = 0xC0130011L,
    STATUS_CLUSTER_NODE_UP                                             = 0xC0130012L,
    STATUS_CLUSTER_NODE_PAUSED                                         = 0xC0130013L,
    STATUS_CLUSTER_NODE_NOT_PAUSED                                     = 0xC0130014L,
    STATUS_CLUSTER_NO_SECURITY_CONTEXT                                 = 0xC0130015L,
    STATUS_CLUSTER_NETWORK_NOT_INTERNAL                                = 0xC0130016L,
    STATUS_CLUSTER_POISONED                                            = 0xC0130017L,
    STATUS_CLUSTER_NON_CSV_PATH                                        = 0xC0130018L,
    STATUS_CLUSTER_CSV_VOLUME_NOT_LOCAL                                = 0xC0130019L,
    STATUS_CLUSTER_CSV_READ_OPLOCK_BREAK_IN_PROGRESS                   = 0xC0130020L,
    STATUS_CLUSTER_CSV_AUTO_PAUSE_ERROR                                = 0xC0130021L,
    STATUS_CLUSTER_CSV_REDIRECTED                                      = 0xC0130022L,
    STATUS_CLUSTER_CSV_NOT_REDIRECTED                                  = 0xC0130023L,
    STATUS_CLUSTER_CSV_VOLUME_DRAINING                                 = 0xC0130024L,
    STATUS_CLUSTER_CSV_SNAPSHOT_CREATION_IN_PROGRESS                   = 0xC0130025L,
    STATUS_CLUSTER_CSV_VOLUME_DRAINING_SUCCEEDED_DOWNLEVEL             = 0xC0130026L,
    STATUS_CLUSTER_CSV_NO_SNAPSHOTS                                    = 0xC0130027L,
    STATUS_CSV_IO_PAUSE_TIMEOUT                                        = 0xC0130028L,
    STATUS_CLUSTER_CSV_INVALID_HANDLE                                  = 0xC0130029L,
    STATUS_CLUSTER_CSV_SUPPORTED_ONLY_ON_COORDINATOR                   = 0xC0130030L,
    STATUS_CLUSTER_CAM_TICKET_REPLAY_DETECTED                          = 0xC0130031L,
    STATUS_TRANSACTIONAL_CONFLICT                                      = 0xC0190001L,
    STATUS_INVALID_TRANSACTION                                         = 0xC0190002L,
    STATUS_TRANSACTION_NOT_ACTIVE                                      = 0xC0190003L,
    STATUS_TM_INITIALIZATION_FAILED                                    = 0xC0190004L,
    STATUS_RM_NOT_ACTIVE                                               = 0xC0190005L,
    STATUS_RM_METADATA_CORRUPT                                         = 0xC0190006L,
    STATUS_TRANSACTION_NOT_JOINED                                      = 0xC0190007L,
    STATUS_DIRECTORY_NOT_RM                                            = 0xC0190008L,
    STATUS_COULD_NOT_RESIZE_LOG                                        = 0x80190009L,
    STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE                             = 0xC019000AL,
    STATUS_LOG_RESIZE_INVALID_SIZE                                     = 0xC019000BL,
    STATUS_REMOTE_FILE_VERSION_MISMATCH                                = 0xC019000CL,
    STATUS_CRM_PROTOCOL_ALREADY_EXISTS                                 = 0xC019000FL,
    STATUS_TRANSACTION_PROPAGATION_FAILED                              = 0xC0190010L,
    STATUS_CRM_PROTOCOL_NOT_FOUND                                      = 0xC0190011L,
    STATUS_TRANSACTION_SUPERIOR_EXISTS                                 = 0xC0190012L,
    STATUS_TRANSACTION_REQUEST_NOT_VALID                               = 0xC0190013L,
    STATUS_TRANSACTION_NOT_REQUESTED                                   = 0xC0190014L,
    STATUS_TRANSACTION_ALREADY_ABORTED                                 = 0xC0190015L,
    STATUS_TRANSACTION_ALREADY_COMMITTED                               = 0xC0190016L,
    STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER                         = 0xC0190017L,
    STATUS_CURRENT_TRANSACTION_NOT_VALID                               = 0xC0190018L,
    STATUS_LOG_GROWTH_FAILED                                           = 0xC0190019L,
    STATUS_OBJECT_NO_LONGER_EXISTS                                     = 0xC0190021L,
    STATUS_STREAM_MINIVERSION_NOT_FOUND                                = 0xC0190022L,
    STATUS_STREAM_MINIVERSION_NOT_VALID                                = 0xC0190023L,
    STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION         = 0xC0190024L,
    STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT                    = 0xC0190025L,
    STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS                        = 0xC0190026L,
    STATUS_HANDLE_NO_LONGER_VALID                                      = 0xC0190028L,
    STATUS_NO_TXF_METADATA                                             = 0x80190029L,
    STATUS_LOG_CORRUPTION_DETECTED                                     = 0xC0190030L,
    STATUS_CANT_RECOVER_WITH_HANDLE_OPEN                               = 0x80190031L,
    STATUS_RM_DISCONNECTED                                             = 0xC0190032L,
    STATUS_ENLISTMENT_NOT_SUPERIOR                                     = 0xC0190033L,
    STATUS_RECOVERY_NOT_NEEDED                                         = 0x40190034L,
    STATUS_RM_ALREADY_STARTED                                          = 0x40190035L,
    STATUS_FILE_IDENTITY_NOT_PERSISTENT                                = 0xC0190036L,
    STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY                         = 0xC0190037L,
    STATUS_CANT_CROSS_RM_BOUNDARY                                      = 0xC0190038L,
    STATUS_TXF_DIR_NOT_EMPTY                                           = 0xC0190039L,
    STATUS_INDOUBT_TRANSACTIONS_EXIST                                  = 0xC019003AL,
    STATUS_TM_VOLATILE                                                 = 0xC019003BL,
    STATUS_ROLLBACK_TIMER_EXPIRED                                      = 0xC019003CL,
    STATUS_TXF_ATTRIBUTE_CORRUPT                                       = 0xC019003DL,
    STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION                              = 0xC019003EL,
    STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED                              = 0xC019003FL,
    STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE                       = 0xC0190040L,
    STATUS_TXF_METADATA_ALREADY_PRESENT                                = 0x80190041L,
    STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET                         = 0x80190042L,
    STATUS_TRANSACTION_REQUIRED_PROMOTION                              = 0xC0190043L,
    STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION                          = 0xC0190044L,
    STATUS_TRANSACTIONS_NOT_FROZEN                                     = 0xC0190045L,
    STATUS_TRANSACTION_FREEZE_IN_PROGRESS                              = 0xC0190046L,
    STATUS_NOT_SNAPSHOT_VOLUME                                         = 0xC0190047L,
    STATUS_NO_SAVEPOINT_WITH_OPEN_FILES                                = 0xC0190048L,
    STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION                           = 0xC0190049L,
    STATUS_TM_IDENTITY_MISMATCH                                        = 0xC019004AL,
    STATUS_FLOATED_SECTION                                             = 0xC019004BL,
    STATUS_CANNOT_ACCEPT_TRANSACTED_WORK                               = 0xC019004CL,
    STATUS_CANNOT_ABORT_TRANSACTIONS                                   = 0xC019004DL,
    STATUS_TRANSACTION_NOT_FOUND                                       = 0xC019004EL,
    STATUS_RESOURCEMANAGER_NOT_FOUND                                   = 0xC019004FL,
    STATUS_ENLISTMENT_NOT_FOUND                                        = 0xC0190050L,
    STATUS_TRANSACTIONMANAGER_NOT_FOUND                                = 0xC0190051L,
    STATUS_TRANSACTIONMANAGER_NOT_ONLINE                               = 0xC0190052L,
    STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION                  = 0xC0190053L,
    STATUS_TRANSACTION_NOT_ROOT                                        = 0xC0190054L,
    STATUS_TRANSACTION_OBJECT_EXPIRED                                  = 0xC0190055L,
    STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION                      = 0xC0190056L,
    STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED                           = 0xC0190057L,
    STATUS_TRANSACTION_RECORD_TOO_LONG                                 = 0xC0190058L,
    STATUS_NO_LINK_TRACKING_IN_TRANSACTION                             = 0xC0190059L,
    STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION                      = 0xC019005AL,
    STATUS_TRANSACTION_INTEGRITY_VIOLATED                              = 0xC019005BL,
    STATUS_TRANSACTIONMANAGER_IDENTITY_MISMATCH                        = 0xC019005CL,
    STATUS_RM_CANNOT_BE_FROZEN_FOR_SNAPSHOT                            = 0xC019005DL,
    STATUS_TRANSACTION_MUST_WRITETHROUGH                               = 0xC019005EL,
    STATUS_TRANSACTION_NO_SUPERIOR                                     = 0xC019005FL,
    STATUS_EXPIRED_HANDLE                                              = 0xC0190060L,
    STATUS_TRANSACTION_NOT_ENLISTED                                    = 0xC0190061L,
    STATUS_LOG_SECTOR_INVALID                                          = 0xC01A0001L,
    STATUS_LOG_SECTOR_PARITY_INVALID                                   = 0xC01A0002L,
    STATUS_LOG_SECTOR_REMAPPED                                         = 0xC01A0003L,
    STATUS_LOG_BLOCK_INCOMPLETE                                        = 0xC01A0004L,
    STATUS_LOG_INVALID_RANGE                                           = 0xC01A0005L,
    STATUS_LOG_BLOCKS_EXHAUSTED                                        = 0xC01A0006L,
    STATUS_LOG_READ_CONTEXT_INVALID                                    = 0xC01A0007L,
    STATUS_LOG_RESTART_INVALID                                         = 0xC01A0008L,
    STATUS_LOG_BLOCK_VERSION                                           = 0xC01A0009L,
    STATUS_LOG_BLOCK_INVALID                                           = 0xC01A000AL,
    STATUS_LOG_READ_MODE_INVALID                                       = 0xC01A000BL,
    STATUS_LOG_NO_RESTART                                              = 0x401A000CL,
    STATUS_LOG_METADATA_CORRUPT                                        = 0xC01A000DL,
    STATUS_LOG_METADATA_INVALID                                        = 0xC01A000EL,
    STATUS_LOG_METADATA_INCONSISTENT                                   = 0xC01A000FL,
    STATUS_LOG_RESERVATION_INVALID                                     = 0xC01A0010L,
    STATUS_LOG_CANT_DELETE                                             = 0xC01A0011L,
    STATUS_LOG_CONTAINER_LIMIT_EXCEEDED                                = 0xC01A0012L,
    STATUS_LOG_START_OF_LOG                                            = 0xC01A0013L,
    STATUS_LOG_POLICY_ALREADY_INSTALLED                                = 0xC01A0014L,
    STATUS_LOG_POLICY_NOT_INSTALLED                                    = 0xC01A0015L,
    STATUS_LOG_POLICY_INVALID                                          = 0xC01A0016L,
    STATUS_LOG_POLICY_CONFLICT                                         = 0xC01A0017L,
    STATUS_LOG_PINNED_ARCHIVE_TAIL                                     = 0xC01A0018L,
    STATUS_LOG_RECORD_NONEXISTENT                                      = 0xC01A0019L,
    STATUS_LOG_RECORDS_RESERVED_INVALID                                = 0xC01A001AL,
    STATUS_LOG_SPACE_RESERVED_INVALID                                  = 0xC01A001BL,
    STATUS_LOG_TAIL_INVALID                                            = 0xC01A001CL,
    STATUS_LOG_FULL                                                    = 0xC01A001DL,
    STATUS_LOG_MULTIPLEXED                                             = 0xC01A001EL,
    STATUS_LOG_DEDICATED                                               = 0xC01A001FL,
    STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS                                 = 0xC01A0020L,
    STATUS_LOG_ARCHIVE_IN_PROGRESS                                     = 0xC01A0021L,
    STATUS_LOG_EPHEMERAL                                               = 0xC01A0022L,
    STATUS_LOG_NOT_ENOUGH_CONTAINERS                                   = 0xC01A0023L,
    STATUS_LOG_CLIENT_ALREADY_REGISTERED                               = 0xC01A0024L,
    STATUS_LOG_CLIENT_NOT_REGISTERED                                   = 0xC01A0025L,
    STATUS_LOG_FULL_HANDLER_IN_PROGRESS                                = 0xC01A0026L,
    STATUS_LOG_CONTAINER_READ_FAILED                                   = 0xC01A0027L,
    STATUS_LOG_CONTAINER_WRITE_FAILED                                  = 0xC01A0028L,
    STATUS_LOG_CONTAINER_OPEN_FAILED                                   = 0xC01A0029L,
    STATUS_LOG_CONTAINER_STATE_INVALID                                 = 0xC01A002AL,
    STATUS_LOG_STATE_INVALID                                           = 0xC01A002BL,
    STATUS_LOG_PINNED                                                  = 0xC01A002CL,
    STATUS_LOG_METADATA_FLUSH_FAILED                                   = 0xC01A002DL,
    STATUS_LOG_INCONSISTENT_SECURITY                                   = 0xC01A002EL,
    STATUS_LOG_APPENDED_FLUSH_FAILED                                   = 0xC01A002FL,
    STATUS_LOG_PINNED_RESERVATION                                      = 0xC01A0030L,
    STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD                            = 0xC01B00EAL,
    STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED                  = 0x801B00EBL,
    STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST                           = 0x401B00ECL,
    STATUS_MONITOR_NO_DESCRIPTOR                                       = 0xC01D0001L,
    STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT                           = 0xC01D0002L,
    STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM                         = 0xC01D0003L,
    STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK                       = 0xC01D0004L,
    STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED                   = 0xC01D0005L,
    STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK                  = 0xC01D0006L,
    STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK                  = 0xC01D0007L,
    STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA                             = 0xC01D0008L,
    STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK                       = 0xC01D0009L,
    STATUS_MONITOR_INVALID_MANUFACTURE_DATE                            = 0xC01D000AL,
    STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER                           = 0xC01E0000L,
    STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER                            = 0xC01E0001L,
    STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER                            = 0xC01E0002L,
    STATUS_GRAPHICS_ADAPTER_WAS_RESET                                  = 0xC01E0003L,
    STATUS_GRAPHICS_INVALID_DRIVER_MODEL                               = 0xC01E0004L,
    STATUS_GRAPHICS_PRESENT_MODE_CHANGED                               = 0xC01E0005L,
    STATUS_GRAPHICS_PRESENT_OCCLUDED                                   = 0xC01E0006L,
    STATUS_GRAPHICS_PRESENT_DENIED                                     = 0xC01E0007L,
    STATUS_GRAPHICS_CANNOTCOLORCONVERT                                 = 0xC01E0008L,
    STATUS_GRAPHICS_DRIVER_MISMATCH                                    = 0xC01E0009L,
    STATUS_GRAPHICS_PARTIAL_DATA_POPULATED                             = 0x401E000AL,
    STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED                       = 0xC01E000BL,
    STATUS_GRAPHICS_PRESENT_UNOCCLUDED                                 = 0xC01E000CL,
    STATUS_GRAPHICS_WINDOWDC_NOT_AVAILABLE                             = 0xC01E000DL,
    STATUS_GRAPHICS_WINDOWLESS_PRESENT_DISABLED                        = 0xC01E000EL,
    STATUS_GRAPHICS_PRESENT_INVALID_WINDOW                             = 0xC01E000FL,
    STATUS_GRAPHICS_PRESENT_BUFFER_NOT_BOUND                           = 0xC01E0010L,
    STATUS_GRAPHICS_VAIL_STATE_CHANGED                                 = 0xC01E0011L,
    STATUS_GRAPHICS_NO_VIDEO_MEMORY                                    = 0xC01E0100L,
    STATUS_GRAPHICS_CANT_LOCK_MEMORY                                   = 0xC01E0101L,
    STATUS_GRAPHICS_ALLOCATION_BUSY                                    = 0xC01E0102L,
    STATUS_GRAPHICS_TOO_MANY_REFERENCES                                = 0xC01E0103L,
    STATUS_GRAPHICS_TRY_AGAIN_LATER                                    = 0xC01E0104L,
    STATUS_GRAPHICS_TRY_AGAIN_NOW                                      = 0xC01E0105L,
    STATUS_GRAPHICS_ALLOCATION_INVALID                                 = 0xC01E0106L,
    STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE                   = 0xC01E0107L,
    STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED                   = 0xC01E0108L,
    STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION                       = 0xC01E0109L,
    STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE                           = 0xC01E0110L,
    STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION                      = 0xC01E0111L,
    STATUS_GRAPHICS_ALLOCATION_CLOSED                                  = 0xC01E0112L,
    STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE                        = 0xC01E0113L,
    STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE                          = 0xC01E0114L,
    STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE                            = 0xC01E0115L,
    STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST                            = 0xC01E0116L,
    STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE                            = 0xC01E0200L,
    STATUS_GRAPHICS_SKIP_ALLOCATION_PREPARATION                        = 0x401E0201L,
    STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY                             = 0xC01E0300L,
    STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED                       = 0xC01E0301L,
    STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED             = 0xC01E0302L,
    STATUS_GRAPHICS_INVALID_VIDPN                                      = 0xC01E0303L,
    STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE                       = 0xC01E0304L,
    STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET                       = 0xC01E0305L,
    STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED                       = 0xC01E0306L,
    STATUS_GRAPHICS_MODE_NOT_PINNED                                    = 0x401E0307L,
    STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET                        = 0xC01E0308L,
    STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET                        = 0xC01E0309L,
    STATUS_GRAPHICS_INVALID_FREQUENCY                                  = 0xC01E030AL,
    STATUS_GRAPHICS_INVALID_ACTIVE_REGION                              = 0xC01E030BL,
    STATUS_GRAPHICS_INVALID_TOTAL_REGION                               = 0xC01E030CL,
    STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE                  = 0xC01E0310L,
    STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE                  = 0xC01E0311L,
    STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET                     = 0xC01E0312L,
    STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY                           = 0xC01E0313L,
    STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET                            = 0xC01E0314L,
    STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET                      = 0xC01E0315L,
    STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET                      = 0xC01E0316L,
    STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET                              = 0xC01E0317L,
    STATUS_GRAPHICS_TARGET_ALREADY_IN_SET                              = 0xC01E0318L,
    STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH                         = 0xC01E0319L,
    STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY                      = 0xC01E031AL,
    STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET                  = 0xC01E031BL,
    STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE                     = 0xC01E031CL,
    STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET                          = 0xC01E031DL,
    STATUS_GRAPHICS_NO_PREFERRED_MODE                                  = 0x401E031EL,
    STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET                      = 0xC01E031FL,
    STATUS_GRAPHICS_STALE_MODESET                                      = 0xC01E0320L,
    STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET                      = 0xC01E0321L,
    STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE                        = 0xC01E0322L,
    STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN                    = 0xC01E0323L,
    STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE                             = 0xC01E0324L,
    STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION    = 0xC01E0325L,
    STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES            = 0xC01E0326L,
    STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY                               = 0xC01E0327L,
    STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE              = 0xC01E0328L,
    STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET              = 0xC01E0329L,
    STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET                       = 0xC01E032AL,
    STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR                          = 0xC01E032BL,
    STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET                       = 0xC01E032CL,
    STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET                   = 0xC01E032DL,
    STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE                = 0xC01E032EL,
    STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE                   = 0xC01E032FL,
    STATUS_GRAPHICS_RESOURCES_NOT_RELATED                              = 0xC01E0330L,
    STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE                           = 0xC01E0331L,
    STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE                           = 0xC01E0332L,
    STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET                          = 0xC01E0333L,
    STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER       = 0xC01E0334L,
    STATUS_GRAPHICS_NO_VIDPNMGR                                        = 0xC01E0335L,
    STATUS_GRAPHICS_NO_ACTIVE_VIDPN                                    = 0xC01E0336L,
    STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY                               = 0xC01E0337L,
    STATUS_GRAPHICS_MONITOR_NOT_CONNECTED                              = 0xC01E0338L,
    STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY                             = 0xC01E0339L,
    STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE                        = 0xC01E033AL,
    STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE                         = 0xC01E033BL,
    STATUS_GRAPHICS_INVALID_STRIDE                                     = 0xC01E033CL,
    STATUS_GRAPHICS_INVALID_PIXELFORMAT                                = 0xC01E033DL,
    STATUS_GRAPHICS_INVALID_COLORBASIS                                 = 0xC01E033EL,
    STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE                       = 0xC01E033FL,
    STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY                             = 0xC01E0340L,
    STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT                 = 0xC01E0341L,
    STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE                                = 0xC01E0342L,
    STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN                           = 0xC01E0343L,
    STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL                    = 0xC01E0344L,
    STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION       = 0xC01E0345L,
    STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED = 0xC01E0346L,
    STATUS_GRAPHICS_INVALID_GAMMA_RAMP                                 = 0xC01E0347L,
    STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED                           = 0xC01E0348L,
    STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED                        = 0xC01E0349L,
    STATUS_GRAPHICS_MODE_NOT_IN_MODESET                                = 0xC01E034AL,
    STATUS_GRAPHICS_DATASET_IS_EMPTY                                   = 0x401E034BL,
    STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET                        = 0x401E034CL,
    STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON       = 0xC01E034DL,
    STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE                          = 0xC01E034EL,
    STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE                        = 0xC01E034FL,
    STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS                  = 0xC01E0350L,
    STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED    = 0x401E0351L,
    STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING                          = 0xC01E0352L,
    STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED                       = 0xC01E0353L,
    STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS                   = 0xC01E0354L,
    STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT                        = 0xC01E0355L,
    STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM                     = 0xC01E0356L,
    STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN                  = 0xC01E0357L,
    STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT          = 0xC01E0358L,
    STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED                              = 0xC01E0359L,
    STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION                 = 0xC01E035AL,
    STATUS_GRAPHICS_INVALID_CLIENT_TYPE                                = 0xC01E035BL,
    STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET                                = 0xC01E035CL,
    STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED                  = 0xC01E0400L,
    STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED                     = 0xC01E0401L,
    STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS                               = 0x401E042FL,
    STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER                               = 0xC01E0430L,
    STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED                            = 0xC01E0431L,
    STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED                          = 0xC01E0432L,
    STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY                            = 0xC01E0433L,
    STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED                             = 0xC01E0434L,
    STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON                          = 0xC01E0435L,
    STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE                     = 0xC01E0436L,
    STATUS_GRAPHICS_LEADLINK_START_DEFERRED                            = 0x401E0437L,
    STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER                             = 0xC01E0438L,
    STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY                             = 0x401E0439L,
    STATUS_GRAPHICS_START_DEFERRED                                     = 0x401E043AL,
    STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED                        = 0xC01E043BL,
    STATUS_GRAPHICS_DEPENDABLE_CHILD_STATUS                            = 0x401E043CL,
    STATUS_GRAPHICS_OPM_NOT_SUPPORTED                                  = 0xC01E0500L,
    STATUS_GRAPHICS_COPP_NOT_SUPPORTED                                 = 0xC01E0501L,
    STATUS_GRAPHICS_UAB_NOT_SUPPORTED                                  = 0xC01E0502L,
    STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS                   = 0xC01E0503L,
    STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST                     = 0xC01E0505L,
    STATUS_GRAPHICS_OPM_INTERNAL_ERROR                                 = 0xC01E050BL,
    STATUS_GRAPHICS_OPM_INVALID_HANDLE                                 = 0xC01E050CL,
    STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH                     = 0xC01E050EL,
    STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED                          = 0xC01E050FL,
    STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED                           = 0xC01E0510L,
    STATUS_GRAPHICS_PVP_HFS_FAILED                                     = 0xC01E0511L,
    STATUS_GRAPHICS_OPM_INVALID_SRM                                    = 0xC01E0512L,
    STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP                   = 0xC01E0513L,
    STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP                    = 0xC01E0514L,
    STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA                  = 0xC01E0515L,
    STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET                             = 0xC01E0516L,
    STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH                            = 0xC01E0517L,
    STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE               = 0xC01E0518L,
    STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS              = 0xC01E051AL,
    STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS  = 0xC01E051CL,
    STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST                    = 0xC01E051DL,
    STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR                          = 0xC01E051EL,
    STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS   = 0xC01E051FL,
    STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED                        = 0xC01E0520L,
    STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST                  = 0xC01E0521L,
    STATUS_GRAPHICS_I2C_NOT_SUPPORTED                                  = 0xC01E0580L,
    STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST                          = 0xC01E0581L,
    STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA                        = 0xC01E0582L,
    STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA                           = 0xC01E0583L,
    STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED                            = 0xC01E0584L,
    STATUS_GRAPHICS_DDCCI_INVALID_DATA                                 = 0xC01E0585L,
    STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE  = 0xC01E0586L,
    STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING                  = 0xC01E0587L,
    STATUS_GRAPHICS_MCA_INTERNAL_ERROR                                 = 0xC01E0588L,
    STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND                      = 0xC01E0589L,
    STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH                       = 0xC01E058AL,
    STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM                     = 0xC01E058BL,
    STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE                    = 0xC01E058CL,
    STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS                           = 0xC01E058DL,
    STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED                     = 0xC01E05E0L,
    STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME              = 0xC01E05E1L,
    STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP             = 0xC01E05E2L,
    STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED                    = 0xC01E05E3L,
    STATUS_GRAPHICS_INVALID_POINTER                                    = 0xC01E05E4L,
    STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE           = 0xC01E05E5L,
    STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL                          = 0xC01E05E6L,
    STATUS_GRAPHICS_INTERNAL_ERROR                                     = 0xC01E05E7L,
    STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS                    = 0xC01E05E8L,
    STATUS_FVE_LOCKED_VOLUME                                           = 0xC0210000L,
    STATUS_FVE_NOT_ENCRYPTED                                           = 0xC0210001L,
    STATUS_FVE_BAD_INFORMATION                                         = 0xC0210002L,
    STATUS_FVE_TOO_SMALL                                               = 0xC0210003L,
    STATUS_FVE_FAILED_WRONG_FS                                         = 0xC0210004L,
    STATUS_FVE_BAD_PARTITION_SIZE                                      = 0xC0210005L,
    STATUS_FVE_FS_NOT_EXTENDED                                         = 0xC0210006L,
    STATUS_FVE_FS_MOUNTED                                              = 0xC0210007L,
    STATUS_FVE_NO_LICENSE                                              = 0xC0210008L,
    STATUS_FVE_ACTION_NOT_ALLOWED                                      = 0xC0210009L,
    STATUS_FVE_BAD_DATA                                                = 0xC021000AL,
    STATUS_FVE_VOLUME_NOT_BOUND                                        = 0xC021000BL,
    STATUS_FVE_NOT_DATA_VOLUME                                         = 0xC021000CL,
    STATUS_FVE_CONV_READ_ERROR                                         = 0xC021000DL,
    STATUS_FVE_CONV_WRITE_ERROR                                        = 0xC021000EL,
    STATUS_FVE_OVERLAPPED_UPDATE                                       = 0xC021000FL,
    STATUS_FVE_FAILED_SECTOR_SIZE                                      = 0xC0210010L,
    STATUS_FVE_FAILED_AUTHENTICATION                                   = 0xC0210011L,
    STATUS_FVE_NOT_OS_VOLUME                                           = 0xC0210012L,
    STATUS_FVE_KEYFILE_NOT_FOUND                                       = 0xC0210013L,
    STATUS_FVE_KEYFILE_INVALID                                         = 0xC0210014L,
    STATUS_FVE_KEYFILE_NO_VMK                                          = 0xC0210015L,
    STATUS_FVE_TPM_DISABLED                                            = 0xC0210016L,
    STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO                                   = 0xC0210017L,
    STATUS_FVE_TPM_INVALID_PCR                                         = 0xC0210018L,
    STATUS_FVE_TPM_NO_VMK                                              = 0xC0210019L,
    STATUS_FVE_PIN_INVALID                                             = 0xC021001AL,
    STATUS_FVE_AUTH_INVALID_APPLICATION                                = 0xC021001BL,
    STATUS_FVE_AUTH_INVALID_CONFIG                                     = 0xC021001CL,
    STATUS_FVE_DEBUGGER_ENABLED                                        = 0xC021001DL,
    STATUS_FVE_DRY_RUN_FAILED                                          = 0xC021001EL,
    STATUS_FVE_BAD_METADATA_POINTER                                    = 0xC021001FL,
    STATUS_FVE_OLD_METADATA_COPY                                       = 0xC0210020L,
    STATUS_FVE_REBOOT_REQUIRED                                         = 0xC0210021L,
    STATUS_FVE_RAW_ACCESS                                              = 0xC0210022L,
    STATUS_FVE_RAW_BLOCKED                                             = 0xC0210023L,
    STATUS_FVE_NO_AUTOUNLOCK_MASTER_KEY                                = 0xC0210024L,
    STATUS_FVE_MOR_FAILED                                              = 0xC0210025L,
    STATUS_FVE_NO_FEATURE_LICENSE                                      = 0xC0210026L,
    STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED                     = 0xC0210027L,
    STATUS_FVE_CONV_RECOVERY_FAILED                                    = 0xC0210028L,
    STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG                               = 0xC0210029L,
    STATUS_FVE_INVALID_DATUM_TYPE                                      = 0xC021002AL,
    STATUS_FVE_VOLUME_TOO_SMALL                                        = 0xC0210030L,
    STATUS_FVE_ENH_PIN_INVALID                                         = 0xC0210031L,
    STATUS_FVE_FULL_ENCRYPTION_NOT_ALLOWED_ON_TP_STORAGE               = 0xC0210032L,
    STATUS_FVE_WIPE_NOT_ALLOWED_ON_TP_STORAGE                          = 0xC0210033L,
    STATUS_FVE_NOT_ALLOWED_ON_CSV_STACK                                = 0xC0210034L,
    STATUS_FVE_NOT_ALLOWED_ON_CLUSTER                                  = 0xC0210035L,
    STATUS_FVE_NOT_ALLOWED_TO_UPGRADE_WHILE_CONVERTING                 = 0xC0210036L,
    STATUS_FVE_WIPE_CANCEL_NOT_APPLICABLE                              = 0xC0210037L,
    STATUS_FVE_EDRIVE_DRY_RUN_FAILED                                   = 0xC0210038L,
    STATUS_FVE_SECUREBOOT_DISABLED                                     = 0xC0210039L,
    STATUS_FVE_SECUREBOOT_CONFIG_CHANGE                                = 0xC021003AL,
    STATUS_FVE_DEVICE_LOCKEDOUT                                        = 0xC021003BL,
    STATUS_FVE_VOLUME_EXTEND_PREVENTS_EOW_DECRYPT                      = 0xC021003CL,
    STATUS_FVE_NOT_DE_VOLUME                                           = 0xC021003DL,
    STATUS_FVE_PROTECTION_DISABLED                                     = 0xC021003EL,
    STATUS_FVE_PROTECTION_CANNOT_BE_DISABLED                           = 0xC021003FL,
    STATUS_FVE_OSV_KSR_NOT_ALLOWED                                     = 0xC0210040L,
    STATUS_FWP_CALLOUT_NOT_FOUND                                       = 0xC0220001L,
    STATUS_FWP_CONDITION_NOT_FOUND                                     = 0xC0220002L,
    STATUS_FWP_FILTER_NOT_FOUND                                        = 0xC0220003L,
    STATUS_FWP_LAYER_NOT_FOUND                                         = 0xC0220004L,
    STATUS_FWP_PROVIDER_NOT_FOUND                                      = 0xC0220005L,
    STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND                              = 0xC0220006L,
    STATUS_FWP_SUBLAYER_NOT_FOUND                                      = 0xC0220007L,
    STATUS_FWP_NOT_FOUND                                               = 0xC0220008L,
    STATUS_FWP_ALREADY_EXISTS                                          = 0xC0220009L,
    STATUS_FWP_IN_USE                                                  = 0xC022000AL,
    STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS                             = 0xC022000BL,
    STATUS_FWP_WRONG_SESSION                                           = 0xC022000CL,
    STATUS_FWP_NO_TXN_IN_PROGRESS                                      = 0xC022000DL,
    STATUS_FWP_TXN_IN_PROGRESS                                         = 0xC022000EL,
    STATUS_FWP_TXN_ABORTED                                             = 0xC022000FL,
    STATUS_FWP_SESSION_ABORTED                                         = 0xC0220010L,
    STATUS_FWP_INCOMPATIBLE_TXN                                        = 0xC0220011L,
    STATUS_FWP_TIMEOUT                                                 = 0xC0220012L,
    STATUS_FWP_NET_EVENTS_DISABLED                                     = 0xC0220013L,
    STATUS_FWP_INCOMPATIBLE_LAYER                                      = 0xC0220014L,
    STATUS_FWP_KM_CLIENTS_ONLY                                         = 0xC0220015L,
    STATUS_FWP_LIFETIME_MISMATCH                                       = 0xC0220016L,
    STATUS_FWP_BUILTIN_OBJECT                                          = 0xC0220017L,
    STATUS_FWP_TOO_MANY_CALLOUTS                                       = 0xC0220018L,
    STATUS_FWP_NOTIFICATION_DROPPED                                    = 0xC0220019L,
    STATUS_FWP_TRAFFIC_MISMATCH                                        = 0xC022001AL,
    STATUS_FWP_INCOMPATIBLE_SA_STATE                                   = 0xC022001BL,
    STATUS_FWP_NULL_POINTER                                            = 0xC022001CL,
    STATUS_FWP_INVALID_ENUMERATOR                                      = 0xC022001DL,
    STATUS_FWP_INVALID_FLAGS                                           = 0xC022001EL,
    STATUS_FWP_INVALID_NET_MASK                                        = 0xC022001FL,
    STATUS_FWP_INVALID_RANGE                                           = 0xC0220020L,
    STATUS_FWP_INVALID_INTERVAL                                        = 0xC0220021L,
    STATUS_FWP_ZERO_LENGTH_ARRAY                                       = 0xC0220022L,
    STATUS_FWP_NULL_DISPLAY_NAME                                       = 0xC0220023L,
    STATUS_FWP_INVALID_ACTION_TYPE                                     = 0xC0220024L,
    STATUS_FWP_INVALID_WEIGHT                                          = 0xC0220025L,
    STATUS_FWP_MATCH_TYPE_MISMATCH                                     = 0xC0220026L,
    STATUS_FWP_TYPE_MISMATCH                                           = 0xC0220027L,
    STATUS_FWP_OUT_OF_BOUNDS                                           = 0xC0220028L,
    STATUS_FWP_RESERVED                                                = 0xC0220029L,
    STATUS_FWP_DUPLICATE_CONDITION                                     = 0xC022002AL,
    STATUS_FWP_DUPLICATE_KEYMOD                                        = 0xC022002BL,
    STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER                          = 0xC022002CL,
    STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER                       = 0xC022002DL,
    STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER                         = 0xC022002EL,
    STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT                       = 0xC022002FL,
    STATUS_FWP_INCOMPATIBLE_AUTH_METHOD                                = 0xC0220030L,
    STATUS_FWP_INCOMPATIBLE_DH_GROUP                                   = 0xC0220031L,
    STATUS_FWP_EM_NOT_SUPPORTED                                        = 0xC0220032L,
    STATUS_FWP_NEVER_MATCH                                             = 0xC0220033L,
    STATUS_FWP_PROVIDER_CONTEXT_MISMATCH                               = 0xC0220034L,
    STATUS_FWP_INVALID_PARAMETER                                       = 0xC0220035L,
    STATUS_FWP_TOO_MANY_SUBLAYERS                                      = 0xC0220036L,
    STATUS_FWP_CALLOUT_NOTIFICATION_FAILED                             = 0xC0220037L,
    STATUS_FWP_INVALID_AUTH_TRANSFORM                                  = 0xC0220038L,
    STATUS_FWP_INVALID_CIPHER_TRANSFORM                                = 0xC0220039L,
    STATUS_FWP_INCOMPATIBLE_CIPHER_TRANSFORM                           = 0xC022003AL,
    STATUS_FWP_INVALID_TRANSFORM_COMBINATION                           = 0xC022003BL,
    STATUS_FWP_DUPLICATE_AUTH_METHOD                                   = 0xC022003CL,
    STATUS_FWP_INVALID_TUNNEL_ENDPOINT                                 = 0xC022003DL,
    STATUS_FWP_L2_DRIVER_NOT_READY                                     = 0xC022003EL,
    STATUS_FWP_KEY_DICTATOR_ALREADY_REGISTERED                         = 0xC022003FL,
    STATUS_FWP_KEY_DICTATION_INVALID_KEYING_MATERIAL                   = 0xC0220040L,
    STATUS_FWP_CONNECTIONS_DISABLED                                    = 0xC0220041L,
    STATUS_FWP_INVALID_DNS_NAME                                        = 0xC0220042L,
    STATUS_FWP_STILL_ON                                                = 0xC0220043L,
    STATUS_FWP_IKEEXT_NOT_RUNNING                                      = 0xC0220044L,
    STATUS_FWP_TCPIP_NOT_READY                                         = 0xC0220100L,
    STATUS_FWP_INJECT_HANDLE_CLOSING                                   = 0xC0220101L,
    STATUS_FWP_INJECT_HANDLE_STALE                                     = 0xC0220102L,
    STATUS_FWP_CANNOT_PEND                                             = 0xC0220103L,
    STATUS_FWP_DROP_NOICMP                                             = 0xC0220104L,
    STATUS_NDIS_CLOSING                                                = 0xC0230002L,
    STATUS_NDIS_BAD_VERSION                                            = 0xC0230004L,
    STATUS_NDIS_BAD_CHARACTERISTICS                                    = 0xC0230005L,
    STATUS_NDIS_ADAPTER_NOT_FOUND                                      = 0xC0230006L,
    STATUS_NDIS_OPEN_FAILED                                            = 0xC0230007L,
    STATUS_NDIS_DEVICE_FAILED                                          = 0xC0230008L,
    STATUS_NDIS_MULTICAST_FULL                                         = 0xC0230009L,
    STATUS_NDIS_MULTICAST_EXISTS                                       = 0xC023000AL,
    STATUS_NDIS_MULTICAST_NOT_FOUND                                    = 0xC023000BL,
    STATUS_NDIS_REQUEST_ABORTED                                        = 0xC023000CL,
    STATUS_NDIS_RESET_IN_PROGRESS                                      = 0xC023000DL,
    STATUS_NDIS_NOT_SUPPORTED                                          = 0xC02300BBL,
    STATUS_NDIS_INVALID_PACKET                                         = 0xC023000FL,
    STATUS_NDIS_ADAPTER_NOT_READY                                      = 0xC0230011L,
    STATUS_NDIS_INVALID_LENGTH                                         = 0xC0230014L,
    STATUS_NDIS_INVALID_DATA                                           = 0xC0230015L,
    STATUS_NDIS_BUFFER_TOO_SHORT                                       = 0xC0230016L,
    STATUS_NDIS_INVALID_OID                                            = 0xC0230017L,
    STATUS_NDIS_ADAPTER_REMOVED                                        = 0xC0230018L,
    STATUS_NDIS_UNSUPPORTED_MEDIA                                      = 0xC0230019L,
    STATUS_NDIS_GROUP_ADDRESS_IN_USE                                   = 0xC023001AL,
    STATUS_NDIS_FILE_NOT_FOUND                                         = 0xC023001BL,
    STATUS_NDIS_ERROR_READING_FILE                                     = 0xC023001CL,
    STATUS_NDIS_ALREADY_MAPPED                                         = 0xC023001DL,
    STATUS_NDIS_RESOURCE_CONFLICT                                      = 0xC023001EL,
    STATUS_NDIS_MEDIA_DISCONNECTED                                     = 0xC023001FL,
    STATUS_NDIS_INVALID_ADDRESS                                        = 0xC0230022L,
    STATUS_NDIS_INVALID_DEVICE_REQUEST                                 = 0xC0230010L,
    STATUS_NDIS_PAUSED                                                 = 0xC023002AL,
    STATUS_NDIS_INTERFACE_NOT_FOUND                                    = 0xC023002BL,
    STATUS_NDIS_UNSUPPORTED_REVISION                                   = 0xC023002CL,
    STATUS_NDIS_INVALID_PORT                                           = 0xC023002DL,
    STATUS_NDIS_INVALID_PORT_STATE                                     = 0xC023002EL,
    STATUS_NDIS_LOW_POWER_STATE                                        = 0xC023002FL,
    STATUS_NDIS_REINIT_REQUIRED                                        = 0xC0230030L,
    STATUS_NDIS_NO_QUEUES                                              = 0xC0230031L,
    STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED                              = 0xC0232000L,
    STATUS_NDIS_DOT11_MEDIA_IN_USE                                     = 0xC0232001L,
    STATUS_NDIS_DOT11_POWER_STATE_INVALID                              = 0xC0232002L,
    STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL                               = 0xC0232003L,
    STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL                          = 0xC0232004L,
    STATUS_NDIS_DOT11_AP_CHANNEL_CURRENTLY_NOT_AVAILABLE               = 0xC0232005L,
    STATUS_NDIS_DOT11_AP_BAND_CURRENTLY_NOT_AVAILABLE                  = 0xC0232006L,
    STATUS_NDIS_DOT11_AP_CHANNEL_NOT_ALLOWED                           = 0xC0232007L,
    STATUS_NDIS_DOT11_AP_BAND_NOT_ALLOWED                              = 0xC0232008L,
    STATUS_NDIS_INDICATION_REQUIRED                                    = 0x40230001L,
    STATUS_NDIS_OFFLOAD_POLICY                                         = 0xC023100FL,
    STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED                            = 0xC0231012L,
    STATUS_NDIS_OFFLOAD_PATH_REJECTED                                  = 0xC0231013L,
    STATUS_TPM_ERROR_MASK                                              = 0xC0290000L,
    STATUS_TPM_AUTHFAIL                                                = 0xC0290001L,
    STATUS_TPM_BADINDEX                                                = 0xC0290002L,
    STATUS_TPM_BAD_PARAMETER                                           = 0xC0290003L,
    STATUS_TPM_AUDITFAILURE                                            = 0xC0290004L,
    STATUS_TPM_CLEAR_DISABLED                                          = 0xC0290005L,
    STATUS_TPM_DEACTIVATED                                             = 0xC0290006L,
    STATUS_TPM_DISABLED                                                = 0xC0290007L,
    STATUS_TPM_DISABLED_CMD                                            = 0xC0290008L,
    STATUS_TPM_FAIL                                                    = 0xC0290009L,
    STATUS_TPM_BAD_ORDINAL                                             = 0xC029000AL,
    STATUS_TPM_INSTALL_DISABLED                                        = 0xC029000BL,
    STATUS_TPM_INVALID_KEYHANDLE                                       = 0xC029000CL,
    STATUS_TPM_KEYNOTFOUND                                             = 0xC029000DL,
    STATUS_TPM_INAPPROPRIATE_ENC                                       = 0xC029000EL,
    STATUS_TPM_MIGRATEFAIL                                             = 0xC029000FL,
    STATUS_TPM_INVALID_PCR_INFO                                        = 0xC0290010L,
    STATUS_TPM_NOSPACE                                                 = 0xC0290011L,
    STATUS_TPM_NOSRK                                                   = 0xC0290012L,
    STATUS_TPM_NOTSEALED_BLOB                                          = 0xC0290013L,
    STATUS_TPM_OWNER_SET                                               = 0xC0290014L,
    STATUS_TPM_RESOURCES                                               = 0xC0290015L,
    STATUS_TPM_SHORTRANDOM                                             = 0xC0290016L,
    STATUS_TPM_SIZE                                                    = 0xC0290017L,
    STATUS_TPM_WRONGPCRVAL                                             = 0xC0290018L,
    STATUS_TPM_BAD_PARAM_SIZE                                          = 0xC0290019L,
    STATUS_TPM_SHA_THREAD                                              = 0xC029001AL,
    STATUS_TPM_SHA_ERROR                                               = 0xC029001BL,
    STATUS_TPM_FAILEDSELFTEST                                          = 0xC029001CL,
    STATUS_TPM_AUTH2FAIL                                               = 0xC029001DL,
    STATUS_TPM_BADTAG                                                  = 0xC029001EL,
    STATUS_TPM_IOERROR                                                 = 0xC029001FL,
    STATUS_TPM_ENCRYPT_ERROR                                           = 0xC0290020L,
    STATUS_TPM_DECRYPT_ERROR                                           = 0xC0290021L,
    STATUS_TPM_INVALID_AUTHHANDLE                                      = 0xC0290022L,
    STATUS_TPM_NO_ENDORSEMENT                                          = 0xC0290023L,
    STATUS_TPM_INVALID_KEYUSAGE                                        = 0xC0290024L,
    STATUS_TPM_WRONG_ENTITYTYPE                                        = 0xC0290025L,
    STATUS_TPM_INVALID_POSTINIT                                        = 0xC0290026L,
    STATUS_TPM_INAPPROPRIATE_SIG                                       = 0xC0290027L,
    STATUS_TPM_BAD_KEY_PROPERTY                                        = 0xC0290028L,
    STATUS_TPM_BAD_MIGRATION                                           = 0xC0290029L,
    STATUS_TPM_BAD_SCHEME                                              = 0xC029002AL,
    STATUS_TPM_BAD_DATASIZE                                            = 0xC029002BL,
    STATUS_TPM_BAD_MODE                                                = 0xC029002CL,
    STATUS_TPM_BAD_PRESENCE                                            = 0xC029002DL,
    STATUS_TPM_BAD_VERSION                                             = 0xC029002EL,
    STATUS_TPM_NO_WRAP_TRANSPORT                                       = 0xC029002FL,
    STATUS_TPM_AUDITFAIL_UNSUCCESSFUL                                  = 0xC0290030L,
    STATUS_TPM_AUDITFAIL_SUCCESSFUL                                    = 0xC0290031L,
    STATUS_TPM_NOTRESETABLE                                            = 0xC0290032L,
    STATUS_TPM_NOTLOCAL                                                = 0xC0290033L,
    STATUS_TPM_BAD_TYPE                                                = 0xC0290034L,
    STATUS_TPM_INVALID_RESOURCE                                        = 0xC0290035L,
    STATUS_TPM_NOTFIPS                                                 = 0xC0290036L,
    STATUS_TPM_INVALID_FAMILY                                          = 0xC0290037L,
    STATUS_TPM_NO_NV_PERMISSION                                        = 0xC0290038L,
    STATUS_TPM_REQUIRES_SIGN                                           = 0xC0290039L,
    STATUS_TPM_KEY_NOTSUPPORTED                                        = 0xC029003AL,
    STATUS_TPM_AUTH_CONFLICT                                           = 0xC029003BL,
    STATUS_TPM_AREA_LOCKED                                             = 0xC029003CL,
    STATUS_TPM_BAD_LOCALITY                                            = 0xC029003DL,
    STATUS_TPM_READ_ONLY                                               = 0xC029003EL,
    STATUS_TPM_PER_NOWRITE                                             = 0xC029003FL,
    STATUS_TPM_FAMILYCOUNT                                             = 0xC0290040L,
    STATUS_TPM_WRITE_LOCKED                                            = 0xC0290041L,
    STATUS_TPM_BAD_ATTRIBUTES                                          = 0xC0290042L,
    STATUS_TPM_INVALID_STRUCTURE                                       = 0xC0290043L,
    STATUS_TPM_KEY_OWNER_CONTROL                                       = 0xC0290044L,
    STATUS_TPM_BAD_COUNTER                                             = 0xC0290045L,
    STATUS_TPM_NOT_FULLWRITE                                           = 0xC0290046L,
    STATUS_TPM_CONTEXT_GAP                                             = 0xC0290047L,
    STATUS_TPM_MAXNVWRITES                                             = 0xC0290048L,
    STATUS_TPM_NOOPERATOR                                              = 0xC0290049L,
    STATUS_TPM_RESOURCEMISSING                                         = 0xC029004AL,
    STATUS_TPM_DELEGATE_LOCK                                           = 0xC029004BL,
    STATUS_TPM_DELEGATE_FAMILY                                         = 0xC029004CL,
    STATUS_TPM_DELEGATE_ADMIN                                          = 0xC029004DL,
    STATUS_TPM_TRANSPORT_NOTEXCLUSIVE                                  = 0xC029004EL,
    STATUS_TPM_OWNER_CONTROL                                           = 0xC029004FL,
    STATUS_TPM_DAA_RESOURCES                                           = 0xC0290050L,
    STATUS_TPM_DAA_INPUT_DATA0                                         = 0xC0290051L,
    STATUS_TPM_DAA_INPUT_DATA1                                         = 0xC0290052L,
    STATUS_TPM_DAA_ISSUER_SETTINGS                                     = 0xC0290053L,
    STATUS_TPM_DAA_TPM_SETTINGS                                        = 0xC0290054L,
    STATUS_TPM_DAA_STAGE                                               = 0xC0290055L,
    STATUS_TPM_DAA_ISSUER_VALIDITY                                     = 0xC0290056L,
    STATUS_TPM_DAA_WRONG_W                                             = 0xC0290057L,
    STATUS_TPM_BAD_HANDLE                                              = 0xC0290058L,
    STATUS_TPM_BAD_DELEGATE                                            = 0xC0290059L,
    STATUS_TPM_BADCONTEXT                                              = 0xC029005AL,
    STATUS_TPM_TOOMANYCONTEXTS                                         = 0xC029005BL,
    STATUS_TPM_MA_TICKET_SIGNATURE                                     = 0xC029005CL,
    STATUS_TPM_MA_DESTINATION                                          = 0xC029005DL,
    STATUS_TPM_MA_SOURCE                                               = 0xC029005EL,
    STATUS_TPM_MA_AUTHORITY                                            = 0xC029005FL,
    STATUS_TPM_PERMANENTEK                                             = 0xC0290061L,
    STATUS_TPM_BAD_SIGNATURE                                           = 0xC0290062L,
    STATUS_TPM_NOCONTEXTSPACE                                          = 0xC0290063L,
    STATUS_TPM_20_E_ASYMMETRIC                                         = 0xC0290081L,
    STATUS_TPM_20_E_ATTRIBUTES                                         = 0xC0290082L,
    STATUS_TPM_20_E_HASH                                               = 0xC0290083L,
    STATUS_TPM_20_E_VALUE                                              = 0xC0290084L,
    STATUS_TPM_20_E_HIERARCHY                                          = 0xC0290085L,
    STATUS_TPM_20_E_KEY_SIZE                                           = 0xC0290087L,
    STATUS_TPM_20_E_MGF                                                = 0xC0290088L,
    STATUS_TPM_20_E_MODE                                               = 0xC0290089L,
    STATUS_TPM_20_E_TYPE                                               = 0xC029008AL,
    STATUS_TPM_20_E_HANDLE                                             = 0xC029008BL,
    STATUS_TPM_20_E_KDF                                                = 0xC029008CL,
    STATUS_TPM_20_E_RANGE                                              = 0xC029008DL,
    STATUS_TPM_20_E_AUTH_FAIL                                          = 0xC029008EL,
    STATUS_TPM_20_E_NONCE                                              = 0xC029008FL,
    STATUS_TPM_20_E_PP                                                 = 0xC0290090L,
    STATUS_TPM_20_E_SCHEME                                             = 0xC0290092L,
    STATUS_TPM_20_E_SIZE                                               = 0xC0290095L,
    STATUS_TPM_20_E_SYMMETRIC                                          = 0xC0290096L,
    STATUS_TPM_20_E_TAG                                                = 0xC0290097L,
    STATUS_TPM_20_E_SELECTOR                                           = 0xC0290098L,
    STATUS_TPM_20_E_INSUFFICIENT                                       = 0xC029009AL,
    STATUS_TPM_20_E_SIGNATURE                                          = 0xC029009BL,
    STATUS_TPM_20_E_KEY                                                = 0xC029009CL,
    STATUS_TPM_20_E_POLICY_FAIL                                        = 0xC029009DL,
    STATUS_TPM_20_E_INTEGRITY                                          = 0xC029009FL,
    STATUS_TPM_20_E_TICKET                                             = 0xC02900A0L,
    STATUS_TPM_20_E_RESERVED_BITS                                      = 0xC02900A1L,
    STATUS_TPM_20_E_BAD_AUTH                                           = 0xC02900A2L,
    STATUS_TPM_20_E_EXPIRED                                            = 0xC02900A3L,
    STATUS_TPM_20_E_POLICY_CC                                          = 0xC02900A4L,
    STATUS_TPM_20_E_BINDING                                            = 0xC02900A5L,
    STATUS_TPM_20_E_CURVE                                              = 0xC02900A6L,
    STATUS_TPM_20_E_ECC_POINT                                          = 0xC02900A7L,
    STATUS_TPM_20_E_INITIALIZE                                         = 0xC0290100L,
    STATUS_TPM_20_E_FAILURE                                            = 0xC0290101L,
    STATUS_TPM_20_E_SEQUENCE                                           = 0xC0290103L,
    STATUS_TPM_20_E_PRIVATE                                            = 0xC029010BL,
    STATUS_TPM_20_E_HMAC                                               = 0xC0290119L,
    STATUS_TPM_20_E_DISABLED                                           = 0xC0290120L,
    STATUS_TPM_20_E_EXCLUSIVE                                          = 0xC0290121L,
    STATUS_TPM_20_E_ECC_CURVE                                          = 0xC0290123L,
    STATUS_TPM_20_E_AUTH_TYPE                                          = 0xC0290124L,
    STATUS_TPM_20_E_AUTH_MISSING                                       = 0xC0290125L,
    STATUS_TPM_20_E_POLICY                                             = 0xC0290126L,
    STATUS_TPM_20_E_PCR                                                = 0xC0290127L,
    STATUS_TPM_20_E_PCR_CHANGED                                        = 0xC0290128L,
    STATUS_TPM_20_E_UPGRADE                                            = 0xC029012DL,
    STATUS_TPM_20_E_TOO_MANY_CONTEXTS                                  = 0xC029012EL,
    STATUS_TPM_20_E_AUTH_UNAVAILABLE                                   = 0xC029012FL,
    STATUS_TPM_20_E_REBOOT                                             = 0xC0290130L,
    STATUS_TPM_20_E_UNBALANCED                                         = 0xC0290131L,
    STATUS_TPM_20_E_COMMAND_SIZE                                       = 0xC0290142L,
    STATUS_TPM_20_E_COMMAND_CODE                                       = 0xC0290143L,
    STATUS_TPM_20_E_AUTHSIZE                                           = 0xC0290144L,
    STATUS_TPM_20_E_AUTH_CONTEXT                                       = 0xC0290145L,
    STATUS_TPM_20_E_NV_RANGE                                           = 0xC0290146L,
    STATUS_TPM_20_E_NV_SIZE                                            = 0xC0290147L,
    STATUS_TPM_20_E_NV_LOCKED                                          = 0xC0290148L,
    STATUS_TPM_20_E_NV_AUTHORIZATION                                   = 0xC0290149L,
    STATUS_TPM_20_E_NV_UNINITIALIZED                                   = 0xC029014AL,
    STATUS_TPM_20_E_NV_SPACE                                           = 0xC029014BL,
    STATUS_TPM_20_E_NV_DEFINED                                         = 0xC029014CL,
    STATUS_TPM_20_E_BAD_CONTEXT                                        = 0xC0290150L,
    STATUS_TPM_20_E_CPHASH                                             = 0xC0290151L,
    STATUS_TPM_20_E_PARENT                                             = 0xC0290152L,
    STATUS_TPM_20_E_NEEDS_TEST                                         = 0xC0290153L,
    STATUS_TPM_20_E_NO_RESULT                                          = 0xC0290154L,
    STATUS_TPM_20_E_SENSITIVE                                          = 0xC0290155L,
    STATUS_TPM_COMMAND_BLOCKED                                         = 0xC0290400L,
    STATUS_TPM_INVALID_HANDLE                                          = 0xC0290401L,
    STATUS_TPM_DUPLICATE_VHANDLE                                       = 0xC0290402L,
    STATUS_TPM_EMBEDDED_COMMAND_BLOCKED                                = 0xC0290403L,
    STATUS_TPM_EMBEDDED_COMMAND_UNSUPPORTED                            = 0xC0290404L,
    STATUS_TPM_RETRY                                                   = 0xC0290800L,
    STATUS_TPM_NEEDS_SELFTEST                                          = 0xC0290801L,
    STATUS_TPM_DOING_SELFTEST                                          = 0xC0290802L,
    STATUS_TPM_DEFEND_LOCK_RUNNING                                     = 0xC0290803L,
    STATUS_TPM_COMMAND_CANCELED                                        = 0xC0291001L,
    STATUS_TPM_TOO_MANY_CONTEXTS                                       = 0xC0291002L,
    STATUS_TPM_NOT_FOUND                                               = 0xC0291003L,
    STATUS_TPM_ACCESS_DENIED                                           = 0xC0291004L,
    STATUS_TPM_INSUFFICIENT_BUFFER                                     = 0xC0291005L,
    STATUS_TPM_PPI_FUNCTION_UNSUPPORTED                                = 0xC0291006L,
    STATUS_PCP_ERROR_MASK                                              = 0xC0292000L,
    STATUS_PCP_DEVICE_NOT_READY                                        = 0xC0292001L,
    STATUS_PCP_INVALID_HANDLE                                          = 0xC0292002L,
    STATUS_PCP_INVALID_PARAMETER                                       = 0xC0292003L,
    STATUS_PCP_FLAG_NOT_SUPPORTED                                      = 0xC0292004L,
    STATUS_PCP_NOT_SUPPORTED                                           = 0xC0292005L,
    STATUS_PCP_BUFFER_TOO_SMALL                                        = 0xC0292006L,
    STATUS_PCP_INTERNAL_ERROR                                          = 0xC0292007L,
    STATUS_PCP_AUTHENTICATION_FAILED                                   = 0xC0292008L,
    STATUS_PCP_AUTHENTICATION_IGNORED                                  = 0xC0292009L,
    STATUS_PCP_POLICY_NOT_FOUND                                        = 0xC029200AL,
    STATUS_PCP_PROFILE_NOT_FOUND                                       = 0xC029200BL,
    STATUS_PCP_VALIDATION_FAILED                                       = 0xC029200CL,
    STATUS_PCP_DEVICE_NOT_FOUND                                        = 0xC029200DL,
    STATUS_PCP_WRONG_PARENT                                            = 0xC029200EL,
    STATUS_PCP_KEY_NOT_LOADED                                          = 0xC029200FL,
    STATUS_PCP_NO_KEY_CERTIFICATION                                    = 0xC0292010L,
    STATUS_PCP_KEY_NOT_FINALIZED                                       = 0xC0292011L,
    STATUS_PCP_ATTESTATION_CHALLENGE_NOT_SET                           = 0xC0292012L,
    STATUS_PCP_NOT_PCR_BOUND                                           = 0xC0292013L,
    STATUS_PCP_KEY_ALREADY_FINALIZED                                   = 0xC0292014L,
    STATUS_PCP_KEY_USAGE_POLICY_NOT_SUPPORTED                          = 0xC0292015L,
    STATUS_PCP_KEY_USAGE_POLICY_INVALID                                = 0xC0292016L,
    STATUS_PCP_SOFT_KEY_ERROR                                          = 0xC0292017L,
    STATUS_PCP_KEY_NOT_AUTHENTICATED                                   = 0xC0292018L,
    STATUS_PCP_KEY_NOT_AIK                                             = 0xC0292019L,
    STATUS_PCP_KEY_NOT_SIGNING_KEY                                     = 0xC029201AL,
    STATUS_PCP_LOCKED_OUT                                              = 0xC029201BL,
    STATUS_PCP_CLAIM_TYPE_NOT_SUPPORTED                                = 0xC029201CL,
    STATUS_PCP_TPM_VERSION_NOT_SUPPORTED                               = 0xC029201DL,
    STATUS_PCP_BUFFER_LENGTH_MISMATCH                                  = 0xC029201EL,
    STATUS_PCP_IFX_RSA_KEY_CREATION_BLOCKED                            = 0xC029201FL,
    STATUS_PCP_TICKET_MISSING                                          = 0xC0292020L,
    STATUS_PCP_RAW_POLICY_NOT_SUPPORTED                                = 0xC0292021L,
    STATUS_PCP_KEY_HANDLE_INVALIDATED                                  = 0xC0292022L,
    STATUS_PCP_UNSUPPORTED_PSS_SALT                                    = 0x40292023L,
    STATUS_RTPM_CONTEXT_CONTINUE                                       = 0x00293000L,
    STATUS_RTPM_CONTEXT_COMPLETE                                       = 0x00293001L,
    STATUS_RTPM_NO_RESULT                                              = 0xC0293002L,
    STATUS_RTPM_PCR_READ_INCOMPLETE                                    = 0xC0293003L,
    STATUS_RTPM_INVALID_CONTEXT                                        = 0xC0293004L,
    STATUS_RTPM_UNSUPPORTED_CMD                                        = 0xC0293005L,
    STATUS_TPM_ZERO_EXHAUST_ENABLED                                    = 0xC0294000L,
    STATUS_HV_INVALID_HYPERCALL_CODE                                   = 0xC0350002L,
    STATUS_HV_INVALID_HYPERCALL_INPUT                                  = 0xC0350003L,
    STATUS_HV_INVALID_ALIGNMENT                                        = 0xC0350004L,
    STATUS_HV_INVALID_PARAMETER                                        = 0xC0350005L,
    STATUS_HV_ACCESS_DENIED                                            = 0xC0350006L,
    STATUS_HV_INVALID_PARTITION_STATE                                  = 0xC0350007L,
    STATUS_HV_OPERATION_DENIED                                         = 0xC0350008L,
    STATUS_HV_UNKNOWN_PROPERTY                                         = 0xC0350009L,
    STATUS_HV_PROPERTY_VALUE_OUT_OF_RANGE                              = 0xC035000AL,
    STATUS_HV_INSUFFICIENT_MEMORY                                      = 0xC035000BL,
    STATUS_HV_PARTITION_TOO_DEEP                                       = 0xC035000CL,
    STATUS_HV_INVALID_PARTITION_ID                                     = 0xC035000DL,
    STATUS_HV_INVALID_VP_INDEX                                         = 0xC035000EL,
    STATUS_HV_INVALID_PORT_ID                                          = 0xC0350011L,
    STATUS_HV_INVALID_CONNECTION_ID                                    = 0xC0350012L,
    STATUS_HV_INSUFFICIENT_BUFFERS                                     = 0xC0350013L,
    STATUS_HV_NOT_ACKNOWLEDGED                                         = 0xC0350014L,
    STATUS_HV_INVALID_VP_STATE                                         = 0xC0350015L,
    STATUS_HV_ACKNOWLEDGED                                             = 0xC0350016L,
    STATUS_HV_INVALID_SAVE_RESTORE_STATE                               = 0xC0350017L,
    STATUS_HV_INVALID_SYNIC_STATE                                      = 0xC0350018L,
    STATUS_HV_OBJECT_IN_USE                                            = 0xC0350019L,
    STATUS_HV_INVALID_PROXIMITY_DOMAIN_INFO                            = 0xC035001AL,
    STATUS_HV_NO_DATA                                                  = 0xC035001BL,
    STATUS_HV_INACTIVE                                                 = 0xC035001CL,
    STATUS_HV_NO_RESOURCES                                             = 0xC035001DL,
    STATUS_HV_FEATURE_UNAVAILABLE                                      = 0xC035001EL,
    STATUS_HV_INSUFFICIENT_BUFFER                                      = 0xC0350033L,
    STATUS_HV_INSUFFICIENT_DEVICE_DOMAINS                              = 0xC0350038L,
    STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR                           = 0xC035003CL,
    STATUS_HV_CPUID_XSAVE_FEATURE_VALIDATION_ERROR                     = 0xC035003DL,
    STATUS_HV_PROCESSOR_STARTUP_TIMEOUT                                = 0xC035003EL,
    STATUS_HV_SMX_ENABLED                                              = 0xC035003FL,
    STATUS_HV_INVALID_LP_INDEX                                         = 0xC0350041L,
    STATUS_HV_INVALID_REGISTER_VALUE                                   = 0xC0350050L,
    STATUS_HV_INVALID_VTL_STATE                                        = 0xC0350051L,
    STATUS_HV_NX_NOT_DETECTED                                          = 0xC0350055L,
    STATUS_HV_INVALID_DEVICE_ID                                        = 0xC0350057L,
    STATUS_HV_INVALID_DEVICE_STATE                                     = 0xC0350058L,
    STATUS_HV_PENDING_PAGE_REQUESTS                                    = 0x00350059L,
    STATUS_HV_PAGE_REQUEST_INVALID                                     = 0xC0350060L,
    STATUS_HV_INVALID_CPU_GROUP_ID                                     = 0xC035006FL,
    STATUS_HV_INVALID_CPU_GROUP_STATE                                  = 0xC0350070L,
    STATUS_HV_OPERATION_FAILED                                         = 0xC0350071L,
    STATUS_HV_NOT_ALLOWED_WITH_NESTED_VIRT_ACTIVE                      = 0xC0350072L,
    STATUS_HV_INSUFFICIENT_ROOT_MEMORY                                 = 0xC0350073L,
    STATUS_HV_NOT_PRESENT                                              = 0xC0351000L,
    STATUS_VID_DUPLICATE_HANDLER                                       = 0xC0370001L,
    STATUS_VID_TOO_MANY_HANDLERS                                       = 0xC0370002L,
    STATUS_VID_QUEUE_FULL                                              = 0xC0370003L,
    STATUS_VID_HANDLER_NOT_PRESENT                                     = 0xC0370004L,
    STATUS_VID_INVALID_OBJECT_NAME                                     = 0xC0370005L,
    STATUS_VID_PARTITION_NAME_TOO_LONG                                 = 0xC0370006L,
    STATUS_VID_MESSAGE_QUEUE_NAME_TOO_LONG                             = 0xC0370007L,
    STATUS_VID_PARTITION_ALREADY_EXISTS                                = 0xC0370008L,
    STATUS_VID_PARTITION_DOES_NOT_EXIST                                = 0xC0370009L,
    STATUS_VID_PARTITION_NAME_NOT_FOUND                                = 0xC037000AL,
    STATUS_VID_MESSAGE_QUEUE_ALREADY_EXISTS                            = 0xC037000BL,
    STATUS_VID_EXCEEDED_MBP_ENTRY_MAP_LIMIT                            = 0xC037000CL,
    STATUS_VID_MB_STILL_REFERENCED                                     = 0xC037000DL,
    STATUS_VID_CHILD_GPA_PAGE_SET_CORRUPTED                            = 0xC037000EL,
    STATUS_VID_INVALID_NUMA_SETTINGS                                   = 0xC037000FL,
    STATUS_VID_INVALID_NUMA_NODE_INDEX                                 = 0xC0370010L,
    STATUS_VID_NOTIFICATION_QUEUE_ALREADY_ASSOCIATED                   = 0xC0370011L,
    STATUS_VID_INVALID_MEMORY_BLOCK_HANDLE                             = 0xC0370012L,
    STATUS_VID_PAGE_RANGE_OVERFLOW                                     = 0xC0370013L,
    STATUS_VID_INVALID_MESSAGE_QUEUE_HANDLE                            = 0xC0370014L,
    STATUS_VID_INVALID_GPA_RANGE_HANDLE                                = 0xC0370015L,
    STATUS_VID_NO_MEMORY_BLOCK_NOTIFICATION_QUEUE                      = 0xC0370016L,
    STATUS_VID_MEMORY_BLOCK_LOCK_COUNT_EXCEEDED                        = 0xC0370017L,
    STATUS_VID_INVALID_PPM_HANDLE                                      = 0xC0370018L,
    STATUS_VID_MBPS_ARE_LOCKED                                         = 0xC0370019L,
    STATUS_VID_MESSAGE_QUEUE_CLOSED                                    = 0xC037001AL,
    STATUS_VID_VIRTUAL_PROCESSOR_LIMIT_EXCEEDED                        = 0xC037001BL,
    STATUS_VID_STOP_PENDING                                            = 0xC037001CL,
    STATUS_VID_INVALID_PROCESSOR_STATE                                 = 0xC037001DL,
    STATUS_VID_EXCEEDED_KM_CONTEXT_COUNT_LIMIT                         = 0xC037001EL,
    STATUS_VID_KM_INTERFACE_ALREADY_INITIALIZED                        = 0xC037001FL,
    STATUS_VID_MB_PROPERTY_ALREADY_SET_RESET                           = 0xC0370020L,
    STATUS_VID_MMIO_RANGE_DESTROYED                                    = 0xC0370021L,
    STATUS_VID_INVALID_CHILD_GPA_PAGE_SET                              = 0xC0370022L,
    STATUS_VID_RESERVE_PAGE_SET_IS_BEING_USED                          = 0xC0370023L,
    STATUS_VID_RESERVE_PAGE_SET_TOO_SMALL                              = 0xC0370024L,
    STATUS_VID_MBP_ALREADY_LOCKED_USING_RESERVED_PAGE                  = 0xC0370025L,
    STATUS_VID_MBP_COUNT_EXCEEDED_LIMIT                                = 0xC0370026L,
    STATUS_VID_SAVED_STATE_CORRUPT                                     = 0xC0370027L,
    STATUS_VID_SAVED_STATE_UNRECOGNIZED_ITEM                           = 0xC0370028L,
    STATUS_VID_SAVED_STATE_INCOMPATIBLE                                = 0xC0370029L,
    STATUS_VID_VTL_ACCESS_DENIED                                       = 0xC037002AL,
    STATUS_VID_REMOTE_NODE_PARENT_GPA_PAGES_USED                       = 0x80370001L,
    STATUS_IPSEC_BAD_SPI                                               = 0xC0360001L,
    STATUS_IPSEC_SA_LIFETIME_EXPIRED                                   = 0xC0360002L,
    STATUS_IPSEC_WRONG_SA                                              = 0xC0360003L,
    STATUS_IPSEC_REPLAY_CHECK_FAILED                                   = 0xC0360004L,
    STATUS_IPSEC_INVALID_PACKET                                        = 0xC0360005L,
    STATUS_IPSEC_INTEGRITY_CHECK_FAILED                                = 0xC0360006L,
    STATUS_IPSEC_CLEAR_TEXT_DROP                                       = 0xC0360007L,
    STATUS_IPSEC_AUTH_FIREWALL_DROP                                    = 0xC0360008L,
    STATUS_IPSEC_THROTTLE_DROP                                         = 0xC0360009L,
    STATUS_IPSEC_DOSP_BLOCK                                            = 0xC0368000L,
    STATUS_IPSEC_DOSP_RECEIVED_MULTICAST                               = 0xC0368001L,
    STATUS_IPSEC_DOSP_INVALID_PACKET                                   = 0xC0368002L,
    STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED                              = 0xC0368003L,
    STATUS_IPSEC_DOSP_MAX_ENTRIES                                      = 0xC0368004L,
    STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED                               = 0xC0368005L,
    STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES                      = 0xC0368006L,
    STATUS_VOLMGR_INCOMPLETE_REGENERATION                              = 0x80380001L,
    STATUS_VOLMGR_INCOMPLETE_DISK_MIGRATION                            = 0x80380002L,
    STATUS_VOLMGR_DATABASE_FULL                                        = 0xC0380001L,
    STATUS_VOLMGR_DISK_CONFIGURATION_CORRUPTED                         = 0xC0380002L,
    STATUS_VOLMGR_DISK_CONFIGURATION_NOT_IN_SYNC                       = 0xC0380003L,
    STATUS_VOLMGR_PACK_CONFIG_UPDATE_FAILED                            = 0xC0380004L,
    STATUS_VOLMGR_DISK_CONTAINS_NON_SIMPLE_VOLUME                      = 0xC0380005L,
    STATUS_VOLMGR_DISK_DUPLICATE                                       = 0xC0380006L,
    STATUS_VOLMGR_DISK_DYNAMIC                                         = 0xC0380007L,
    STATUS_VOLMGR_DISK_ID_INVALID                                      = 0xC0380008L,
    STATUS_VOLMGR_DISK_INVALID                                         = 0xC0380009L,
    STATUS_VOLMGR_DISK_LAST_VOTER                                      = 0xC038000AL,
    STATUS_VOLMGR_DISK_LAYOUT_INVALID                                  = 0xC038000BL,
    STATUS_VOLMGR_DISK_LAYOUT_NON_BASIC_BETWEEN_BASIC_PARTITIONS       = 0xC038000CL,
    STATUS_VOLMGR_DISK_LAYOUT_NOT_CYLINDER_ALIGNED                     = 0xC038000DL,
    STATUS_VOLMGR_DISK_LAYOUT_PARTITIONS_TOO_SMALL                     = 0xC038000EL,
    STATUS_VOLMGR_DISK_LAYOUT_PRIMARY_BETWEEN_LOGICAL_PARTITIONS       = 0xC038000FL,
    STATUS_VOLMGR_DISK_LAYOUT_TOO_MANY_PARTITIONS                      = 0xC0380010L,
    STATUS_VOLMGR_DISK_MISSING                                         = 0xC0380011L,
    STATUS_VOLMGR_DISK_NOT_EMPTY                                       = 0xC0380012L,
    STATUS_VOLMGR_DISK_NOT_ENOUGH_SPACE                                = 0xC0380013L,
    STATUS_VOLMGR_DISK_REVECTORING_FAILED                              = 0xC0380014L,
    STATUS_VOLMGR_DISK_SECTOR_SIZE_INVALID                             = 0xC0380015L,
    STATUS_VOLMGR_DISK_SET_NOT_CONTAINED                               = 0xC0380016L,
    STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_MEMBERS                        = 0xC0380017L,
    STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_PLEXES                         = 0xC0380018L,
    STATUS_VOLMGR_DYNAMIC_DISK_NOT_SUPPORTED                           = 0xC0380019L,
    STATUS_VOLMGR_EXTENT_ALREADY_USED                                  = 0xC038001AL,
    STATUS_VOLMGR_EXTENT_NOT_CONTIGUOUS                                = 0xC038001BL,
    STATUS_VOLMGR_EXTENT_NOT_IN_PUBLIC_REGION                          = 0xC038001CL,
    STATUS_VOLMGR_EXTENT_NOT_SECTOR_ALIGNED                            = 0xC038001DL,
    STATUS_VOLMGR_EXTENT_OVERLAPS_EBR_PARTITION                        = 0xC038001EL,
    STATUS_VOLMGR_EXTENT_VOLUME_LENGTHS_DO_NOT_MATCH                   = 0xC038001FL,
    STATUS_VOLMGR_FAULT_TOLERANT_NOT_SUPPORTED                         = 0xC0380020L,
    STATUS_VOLMGR_INTERLEAVE_LENGTH_INVALID                            = 0xC0380021L,
    STATUS_VOLMGR_MAXIMUM_REGISTERED_USERS                             = 0xC0380022L,
    STATUS_VOLMGR_MEMBER_IN_SYNC                                       = 0xC0380023L,
    STATUS_VOLMGR_MEMBER_INDEX_DUPLICATE                               = 0xC0380024L,
    STATUS_VOLMGR_MEMBER_INDEX_INVALID                                 = 0xC0380025L,
    STATUS_VOLMGR_MEMBER_MISSING                                       = 0xC0380026L,
    STATUS_VOLMGR_MEMBER_NOT_DETACHED                                  = 0xC0380027L,
    STATUS_VOLMGR_MEMBER_REGENERATING                                  = 0xC0380028L,
    STATUS_VOLMGR_ALL_DISKS_FAILED                                     = 0xC0380029L,
    STATUS_VOLMGR_NO_REGISTERED_USERS                                  = 0xC038002AL,
    STATUS_VOLMGR_NO_SUCH_USER                                         = 0xC038002BL,
    STATUS_VOLMGR_NOTIFICATION_RESET                                   = 0xC038002CL,
    STATUS_VOLMGR_NUMBER_OF_MEMBERS_INVALID                            = 0xC038002DL,
    STATUS_VOLMGR_NUMBER_OF_PLEXES_INVALID                             = 0xC038002EL,
    STATUS_VOLMGR_PACK_DUPLICATE                                       = 0xC038002FL,
    STATUS_VOLMGR_PACK_ID_INVALID                                      = 0xC0380030L,
    STATUS_VOLMGR_PACK_INVALID                                         = 0xC0380031L,
    STATUS_VOLMGR_PACK_NAME_INVALID                                    = 0xC0380032L,
    STATUS_VOLMGR_PACK_OFFLINE                                         = 0xC0380033L,
    STATUS_VOLMGR_PACK_HAS_QUORUM                                      = 0xC0380034L,
    STATUS_VOLMGR_PACK_WITHOUT_QUORUM                                  = 0xC0380035L,
    STATUS_VOLMGR_PARTITION_STYLE_INVALID                              = 0xC0380036L,
    STATUS_VOLMGR_PARTITION_UPDATE_FAILED                              = 0xC0380037L,
    STATUS_VOLMGR_PLEX_IN_SYNC                                         = 0xC0380038L,
    STATUS_VOLMGR_PLEX_INDEX_DUPLICATE                                 = 0xC0380039L,
    STATUS_VOLMGR_PLEX_INDEX_INVALID                                   = 0xC038003AL,
    STATUS_VOLMGR_PLEX_LAST_ACTIVE                                     = 0xC038003BL,
    STATUS_VOLMGR_PLEX_MISSING                                         = 0xC038003CL,
    STATUS_VOLMGR_PLEX_REGENERATING                                    = 0xC038003DL,
    STATUS_VOLMGR_PLEX_TYPE_INVALID                                    = 0xC038003EL,
    STATUS_VOLMGR_PLEX_NOT_RAID5                                       = 0xC038003FL,
    STATUS_VOLMGR_PLEX_NOT_SIMPLE                                      = 0xC0380040L,
    STATUS_VOLMGR_STRUCTURE_SIZE_INVALID                               = 0xC0380041L,
    STATUS_VOLMGR_TOO_MANY_NOTIFICATION_REQUESTS                       = 0xC0380042L,
    STATUS_VOLMGR_TRANSACTION_IN_PROGRESS                              = 0xC0380043L,
    STATUS_VOLMGR_UNEXPECTED_DISK_LAYOUT_CHANGE                        = 0xC0380044L,
    STATUS_VOLMGR_VOLUME_CONTAINS_MISSING_DISK                         = 0xC0380045L,
    STATUS_VOLMGR_VOLUME_ID_INVALID                                    = 0xC0380046L,
    STATUS_VOLMGR_VOLUME_LENGTH_INVALID                                = 0xC0380047L,
    STATUS_VOLMGR_VOLUME_LENGTH_NOT_SECTOR_SIZE_MULTIPLE               = 0xC0380048L,
    STATUS_VOLMGR_VOLUME_NOT_MIRRORED                                  = 0xC0380049L,
    STATUS_VOLMGR_VOLUME_NOT_RETAINED                                  = 0xC038004AL,
    STATUS_VOLMGR_VOLUME_OFFLINE                                       = 0xC038004BL,
    STATUS_VOLMGR_VOLUME_RETAINED                                      = 0xC038004CL,
    STATUS_VOLMGR_NUMBER_OF_EXTENTS_INVALID                            = 0xC038004DL,
    STATUS_VOLMGR_DIFFERENT_SECTOR_SIZE                                = 0xC038004EL,
    STATUS_VOLMGR_BAD_BOOT_DISK                                        = 0xC038004FL,
    STATUS_VOLMGR_PACK_CONFIG_OFFLINE                                  = 0xC0380050L,
    STATUS_VOLMGR_PACK_CONFIG_ONLINE                                   = 0xC0380051L,
    STATUS_VOLMGR_NOT_PRIMARY_PACK                                     = 0xC0380052L,
    STATUS_VOLMGR_PACK_LOG_UPDATE_FAILED                               = 0xC0380053L,
    STATUS_VOLMGR_NUMBER_OF_DISKS_IN_PLEX_INVALID                      = 0xC0380054L,
    STATUS_VOLMGR_NUMBER_OF_DISKS_IN_MEMBER_INVALID                    = 0xC0380055L,
    STATUS_VOLMGR_VOLUME_MIRRORED                                      = 0xC0380056L,
    STATUS_VOLMGR_PLEX_NOT_SIMPLE_SPANNED                              = 0xC0380057L,
    STATUS_VOLMGR_NO_VALID_LOG_COPIES                                  = 0xC0380058L,
    STATUS_VOLMGR_PRIMARY_PACK_PRESENT                                 = 0xC0380059L,
    STATUS_VOLMGR_NUMBER_OF_DISKS_INVALID                              = 0xC038005AL,
    STATUS_VOLMGR_MIRROR_NOT_SUPPORTED                                 = 0xC038005BL,
    STATUS_VOLMGR_RAID5_NOT_SUPPORTED                                  = 0xC038005CL,
    STATUS_BCD_NOT_ALL_ENTRIES_IMPORTED                                = 0x80390001L,
    STATUS_BCD_TOO_MANY_ELEMENTS                                       = 0xC0390002L,
    STATUS_BCD_NOT_ALL_ENTRIES_SYNCHRONIZED                            = 0x80390003L,
    STATUS_VHD_DRIVE_FOOTER_MISSING                                    = 0xC03A0001L,
    STATUS_VHD_DRIVE_FOOTER_CHECKSUM_MISMATCH                          = 0xC03A0002L,
    STATUS_VHD_DRIVE_FOOTER_CORRUPT                                    = 0xC03A0003L,
    STATUS_VHD_FORMAT_UNKNOWN                                          = 0xC03A0004L,
    STATUS_VHD_FORMAT_UNSUPPORTED_VERSION                              = 0xC03A0005L,
    STATUS_VHD_SPARSE_HEADER_CHECKSUM_MISMATCH                         = 0xC03A0006L,
    STATUS_VHD_SPARSE_HEADER_UNSUPPORTED_VERSION                       = 0xC03A0007L,
    STATUS_VHD_SPARSE_HEADER_CORRUPT                                   = 0xC03A0008L,
    STATUS_VHD_BLOCK_ALLOCATION_FAILURE                                = 0xC03A0009L,
    STATUS_VHD_BLOCK_ALLOCATION_TABLE_CORRUPT                          = 0xC03A000AL,
    STATUS_VHD_INVALID_BLOCK_SIZE                                      = 0xC03A000BL,
    STATUS_VHD_BITMAP_MISMATCH                                         = 0xC03A000CL,
    STATUS_VHD_PARENT_VHD_NOT_FOUND                                    = 0xC03A000DL,
    STATUS_VHD_CHILD_PARENT_ID_MISMATCH                                = 0xC03A000EL,
    STATUS_VHD_CHILD_PARENT_TIMESTAMP_MISMATCH                         = 0xC03A000FL,
    STATUS_VHD_METADATA_READ_FAILURE                                   = 0xC03A0010L,
    STATUS_VHD_METADATA_WRITE_FAILURE                                  = 0xC03A0011L,
    STATUS_VHD_INVALID_SIZE                                            = 0xC03A0012L,
    STATUS_VHD_INVALID_FILE_SIZE                                       = 0xC03A0013L,
    STATUS_VIRTDISK_PROVIDER_NOT_FOUND                                 = 0xC03A0014L,
    STATUS_VIRTDISK_NOT_VIRTUAL_DISK                                   = 0xC03A0015L,
    STATUS_VHD_PARENT_VHD_ACCESS_DENIED                                = 0xC03A0016L,
    STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH                              = 0xC03A0017L,
    STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED                       = 0xC03A0018L,
    STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT                      = 0xC03A0019L,
    STATUS_VIRTUAL_DISK_LIMITATION                                     = 0xC03A001AL,
    STATUS_VHD_INVALID_TYPE                                            = 0xC03A001BL,
    STATUS_VHD_INVALID_STATE                                           = 0xC03A001CL,
    STATUS_VIRTDISK_UNSUPPORTED_DISK_SECTOR_SIZE                       = 0xC03A001DL,
    STATUS_VIRTDISK_DISK_ALREADY_OWNED                                 = 0xC03A001EL,
    STATUS_VIRTDISK_DISK_ONLINE_AND_WRITABLE                           = 0xC03A001FL,
    STATUS_CTLOG_TRACKING_NOT_INITIALIZED                              = 0xC03A0020L,
    STATUS_CTLOG_LOGFILE_SIZE_EXCEEDED_MAXSIZE                         = 0xC03A0021L,
    STATUS_CTLOG_VHD_CHANGED_OFFLINE                                   = 0xC03A0022L,
    STATUS_CTLOG_INVALID_TRACKING_STATE                                = 0xC03A0023L,
    STATUS_CTLOG_INCONSISTENT_TRACKING_FILE                            = 0xC03A0024L,
    STATUS_VHD_METADATA_FULL                                           = 0xC03A0028L,
    STATUS_VHD_INVALID_CHANGE_TRACKING_ID                              = 0xC03A0029L,
    STATUS_VHD_CHANGE_TRACKING_DISABLED                                = 0xC03A002AL,
    STATUS_VHD_MISSING_CHANGE_TRACKING_INFORMATION                     = 0xC03A0030L,
    STATUS_VHD_RESIZE_WOULD_TRUNCATE_DATA                              = 0xC03A0031L,
    STATUS_VHD_COULD_NOT_COMPUTE_MINIMUM_VIRTUAL_SIZE                  = 0xC03A0032L,
    STATUS_VHD_ALREADY_AT_OR_BELOW_MINIMUM_VIRTUAL_SIZE                = 0xC03A0033L,
    STATUS_QUERY_STORAGE_ERROR                                         = 0x803A0001L,
    STATUS_GDI_HANDLE_LEAK                                             = 0x803F0001L,
    STATUS_RKF_KEY_NOT_FOUND                                           = 0xC0400001L,
    STATUS_RKF_DUPLICATE_KEY                                           = 0xC0400002L,
    STATUS_RKF_BLOB_FULL                                               = 0xC0400003L,
    STATUS_RKF_STORE_FULL                                              = 0xC0400004L,
    STATUS_RKF_FILE_BLOCKED                                            = 0xC0400005L,
    STATUS_RKF_ACTIVE_KEY                                              = 0xC0400006L,
    STATUS_RDBSS_RESTART_OPERATION                                     = 0xC0410001L,
    STATUS_RDBSS_CONTINUE_OPERATION                                    = 0xC0410002L,
    STATUS_RDBSS_POST_OPERATION                                        = 0xC0410003L,
    STATUS_RDBSS_RETRY_LOOKUP                                          = 0xC0410004L,
    STATUS_BTH_ATT_INVALID_HANDLE                                      = 0xC0420001L,
    STATUS_BTH_ATT_READ_NOT_PERMITTED                                  = 0xC0420002L,
    STATUS_BTH_ATT_WRITE_NOT_PERMITTED                                 = 0xC0420003L,
    STATUS_BTH_ATT_INVALID_PDU                                         = 0xC0420004L,
    STATUS_BTH_ATT_INSUFFICIENT_AUTHENTICATION                         = 0xC0420005L,
    STATUS_BTH_ATT_REQUEST_NOT_SUPPORTED                               = 0xC0420006L,
    STATUS_BTH_ATT_INVALID_OFFSET                                      = 0xC0420007L,
    STATUS_BTH_ATT_INSUFFICIENT_AUTHORIZATION                          = 0xC0420008L,
    STATUS_BTH_ATT_PREPARE_QUEUE_FULL                                  = 0xC0420009L,
    STATUS_BTH_ATT_ATTRIBUTE_NOT_FOUND                                 = 0xC042000AL,
    STATUS_BTH_ATT_ATTRIBUTE_NOT_LONG                                  = 0xC042000BL,
    STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE                    = 0xC042000CL,
    STATUS_BTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH                      = 0xC042000DL,
    STATUS_BTH_ATT_UNLIKELY                                            = 0xC042000EL,
    STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION                             = 0xC042000FL,
    STATUS_BTH_ATT_UNSUPPORTED_GROUP_TYPE                              = 0xC0420010L,
    STATUS_BTH_ATT_INSUFFICIENT_RESOURCES                              = 0xC0420011L,
    STATUS_BTH_ATT_UNKNOWN_ERROR                                       = 0xC0421000L,
    STATUS_SECUREBOOT_ROLLBACK_DETECTED                                = 0xC0430001L,
    STATUS_SECUREBOOT_POLICY_VIOLATION                                 = 0xC0430002L,
    STATUS_SECUREBOOT_INVALID_POLICY                                   = 0xC0430003L,
    STATUS_SECUREBOOT_POLICY_PUBLISHER_NOT_FOUND                       = 0xC0430004L,
    STATUS_SECUREBOOT_POLICY_NOT_SIGNED                                = 0xC0430005L,
    STATUS_SECUREBOOT_NOT_ENABLED                                      = 0x80430006L,
    STATUS_SECUREBOOT_FILE_REPLACED                                    = 0xC0430007L,
    STATUS_SECUREBOOT_POLICY_NOT_AUTHORIZED                            = 0xC0430008L,
    STATUS_SECUREBOOT_POLICY_UNKNOWN                                   = 0xC0430009L,
    STATUS_SECUREBOOT_POLICY_MISSING_ANTIROLLBACKVERSION               = 0xC043000AL,
    STATUS_SECUREBOOT_PLATFORM_ID_MISMATCH                             = 0xC043000BL,
    STATUS_SECUREBOOT_POLICY_ROLLBACK_DETECTED                         = 0xC043000CL,
    STATUS_SECUREBOOT_POLICY_UPGRADE_MISMATCH                          = 0xC043000DL,
    STATUS_SECUREBOOT_REQUIRED_POLICY_FILE_MISSING                     = 0xC043000EL,
    STATUS_SECUREBOOT_NOT_BASE_POLICY                                  = 0xC043000FL,
    STATUS_SECUREBOOT_NOT_SUPPLEMENTAL_POLICY                          = 0xC0430010L,
    STATUS_PLATFORM_MANIFEST_NOT_AUTHORIZED                            = 0xC0EB0001L,
    STATUS_PLATFORM_MANIFEST_INVALID                                   = 0xC0EB0002L,
    STATUS_PLATFORM_MANIFEST_FILE_NOT_AUTHORIZED                       = 0xC0EB0003L,
    STATUS_PLATFORM_MANIFEST_CATALOG_NOT_AUTHORIZED                    = 0xC0EB0004L,
    STATUS_PLATFORM_MANIFEST_BINARY_ID_NOT_FOUND                       = 0xC0EB0005L,
    STATUS_PLATFORM_MANIFEST_NOT_ACTIVE                                = 0xC0EB0006L,
    STATUS_PLATFORM_MANIFEST_NOT_SIGNED                                = 0xC0EB0007L,
    STATUS_SYSTEM_INTEGRITY_ROLLBACK_DETECTED                          = 0xC0E90001L,
    STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION                           = 0xC0E90002L,
    STATUS_SYSTEM_INTEGRITY_INVALID_POLICY                             = 0xC0E90003L,
    STATUS_SYSTEM_INTEGRITY_POLICY_NOT_SIGNED                          = 0xC0E90004L,
    STATUS_NO_APPLICABLE_APP_LICENSES_FOUND                            = 0xC0EA0001L,
    STATUS_CLIP_LICENSE_NOT_FOUND                                      = 0xC0EA0002L,
    STATUS_CLIP_DEVICE_LICENSE_MISSING                                 = 0xC0EA0003L,
    STATUS_CLIP_LICENSE_INVALID_SIGNATURE                              = 0xC0EA0004L,
    STATUS_CLIP_KEYHOLDER_LICENSE_MISSING_OR_INVALID                   = 0xC0EA0005L,
    STATUS_CLIP_LICENSE_EXPIRED                                        = 0xC0EA0006L,
    STATUS_CLIP_LICENSE_SIGNED_BY_UNKNOWN_SOURCE                       = 0xC0EA0007L,
    STATUS_CLIP_LICENSE_NOT_SIGNED                                     = 0xC0EA0008L,
    STATUS_CLIP_LICENSE_HARDWARE_ID_OUT_OF_TOLERANCE                   = 0xC0EA0009L,
    STATUS_CLIP_LICENSE_DEVICE_ID_MISMATCH                             = 0xC0EA000AL,
    STATUS_AUDIO_ENGINE_NODE_NOT_FOUND                                 = 0xC0440001L,
    STATUS_HDAUDIO_EMPTY_CONNECTION_LIST                               = 0xC0440002L,
    STATUS_HDAUDIO_CONNECTION_LIST_NOT_SUPPORTED                       = 0xC0440003L,
    STATUS_HDAUDIO_NO_LOGICAL_DEVICES_CREATED                          = 0xC0440004L,
    STATUS_HDAUDIO_NULL_LINKED_LIST_ENTRY                              = 0xC0440005L,
    STATUS_SPACES_REPAIRED                                             = 0x00E70000L,
    STATUS_SPACES_PAUSE                                                = 0x00E70001L,
    STATUS_SPACES_COMPLETE                                             = 0x00E70002L,
    STATUS_SPACES_REDIRECT                                             = 0x00E70003L,
    STATUS_SPACES_FAULT_DOMAIN_TYPE_INVALID                            = 0xC0E70001L,
    STATUS_SPACES_RESILIENCY_TYPE_INVALID                              = 0xC0E70003L,
    STATUS_SPACES_DRIVE_SECTOR_SIZE_INVALID                            = 0xC0E70004L,
    STATUS_SPACES_DRIVE_REDUNDANCY_INVALID                             = 0xC0E70006L,
    STATUS_SPACES_NUMBER_OF_DATA_COPIES_INVALID                        = 0xC0E70007L,
    STATUS_SPACES_INTERLEAVE_LENGTH_INVALID                            = 0xC0E70009L,
    STATUS_SPACES_NUMBER_OF_COLUMNS_INVALID                            = 0xC0E7000AL,
    STATUS_SPACES_NOT_ENOUGH_DRIVES                                    = 0xC0E7000BL,
    STATUS_SPACES_EXTENDED_ERROR                                       = 0xC0E7000CL,
    STATUS_SPACES_PROVISIONING_TYPE_INVALID                            = 0xC0E7000DL,
    STATUS_SPACES_ALLOCATION_SIZE_INVALID                              = 0xC0E7000EL,
    STATUS_SPACES_ENCLOSURE_AWARE_INVALID                              = 0xC0E7000FL,
    STATUS_SPACES_WRITE_CACHE_SIZE_INVALID                             = 0xC0E70010L,
    STATUS_SPACES_NUMBER_OF_GROUPS_INVALID                             = 0xC0E70011L,
    STATUS_SPACES_DRIVE_OPERATIONAL_STATE_INVALID                      = 0xC0E70012L,
    STATUS_SPACES_UPDATE_COLUMN_STATE                                  = 0xC0E70013L,
    STATUS_SPACES_MAP_REQUIRED                                         = 0xC0E70014L,
    STATUS_SPACES_UNSUPPORTED_VERSION                                  = 0xC0E70015L,
    STATUS_SPACES_CORRUPT_METADATA                                     = 0xC0E70016L,
    STATUS_SPACES_DRT_FULL                                             = 0xC0E70017L,
    STATUS_SPACES_INCONSISTENCY                                        = 0xC0E70018L,
    STATUS_SPACES_LOG_NOT_READY                                        = 0xC0E70019L,
    STATUS_SPACES_NO_REDUNDANCY                                        = 0xC0E7001AL,
    STATUS_SPACES_DRIVE_NOT_READY                                      = 0xC0E7001BL,
    STATUS_SPACES_DRIVE_SPLIT                                          = 0xC0E7001CL,
    STATUS_SPACES_DRIVE_LOST_DATA                                      = 0xC0E7001DL,
    STATUS_SPACES_ENTRY_INCOMPLETE                                     = 0xC0E7001EL,
    STATUS_SPACES_ENTRY_INVALID                                        = 0xC0E7001FL,
    STATUS_VOLSNAP_BOOTFILE_NOT_VALID                                  = 0xC0500003L,
    STATUS_VOLSNAP_ACTIVATION_TIMEOUT                                  = 0xC0500004L,
    STATUS_IO_PREEMPTED                                                = 0xC0510001L,
    STATUS_SVHDX_ERROR_STORED                                          = 0xC05C0000L,
    STATUS_SVHDX_ERROR_NOT_AVAILABLE                                   = 0xC05CFF00L,
    STATUS_SVHDX_UNIT_ATTENTION_AVAILABLE                              = 0xC05CFF01L,
    STATUS_SVHDX_UNIT_ATTENTION_CAPACITY_DATA_CHANGED                  = 0xC05CFF02L,
    STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_PREEMPTED                 = 0xC05CFF03L,
    STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_RELEASED                  = 0xC05CFF04L,
    STATUS_SVHDX_UNIT_ATTENTION_REGISTRATIONS_PREEMPTED                = 0xC05CFF05L,
    STATUS_SVHDX_UNIT_ATTENTION_OPERATING_DEFINITION_CHANGED           = 0xC05CFF06L,
    STATUS_SVHDX_RESERVATION_CONFLICT                                  = 0xC05CFF07L,
    STATUS_SVHDX_WRONG_FILE_TYPE                                       = 0xC05CFF08L,
    STATUS_SVHDX_VERSION_MISMATCH                                      = 0xC05CFF09L,
    STATUS_VHD_SHARED                                                  = 0xC05CFF0AL,
    STATUS_SVHDX_NO_INITIATOR                                          = 0xC05CFF0BL,
    STATUS_VHDSET_BACKING_STORAGE_NOT_FOUND                            = 0xC05CFF0CL,
    STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP                       = 0xC05D0000L,
    STATUS_SMB_BAD_CLUSTER_DIALECT                                     = 0xC05D0001L,
    STATUS_SMB_GUEST_LOGON_BLOCKED                                     = 0xC05D0002L,
    STATUS_SECCORE_INVALID_COMMAND                                     = 0xC0E80000L,
    STATUS_VSM_NOT_INITIALIZED                                         = 0xC0450000L,
    STATUS_VSM_DMA_PROTECTION_NOT_IN_USE                               = 0xC0450001L,
    STATUS_APPEXEC_CONDITION_NOT_SATISFIED                             = 0xC0EC0000L,
    STATUS_APPEXEC_HANDLE_INVALIDATED                                  = 0xC0EC0001L,
    STATUS_APPEXEC_INVALID_HOST_GENERATION                             = 0xC0EC0002L,
    STATUS_APPEXEC_UNEXPECTED_PROCESS_REGISTRATION                     = 0xC0EC0003L,
    STATUS_APPEXEC_INVALID_HOST_STATE                                  = 0xC0EC0004L,
    STATUS_APPEXEC_NO_DONOR                                            = 0xC0EC0005L,
    STATUS_APPEXEC_HOST_ID_MISMATCH                                    = 0xC0EC0006L,
    STATUS_APPEXEC_UNKNOWN_USER                                        = 0xC0EC0007L
} ntstatus_t;

typedef enum ntstatus_facility
{
    FACILITY_DEBUGGER            = 0x1,
    FACILITY_RPC_RUNTIME         = 0x2,
    FACILITY_RPC_STUBS           = 0x3,
    FACILITY_IO_ERROR_CODE       = 0x4,
    FACILITY_CODCLASS_ERROR_CODE = 0x6,
    FACILITY_NTWIN32             = 0x7,
    FACILITY_NTCERT              = 0x8,
    FACILITY_NTSSPI              = 0x9,
    FACILITY_TERMINAL_SERVER     = 0xA,
    FACILITY_USB_ERROR_CODE      = 0x10,
    FACILITY_HID_ERROR_CODE      = 0x11,
    FACILITY_FIREWIRE_ERROR_CODE = 0x12,
    FACILITY_CLUSTER_ERROR_CODE  = 0x13,
    FACILITY_ACPI_ERROR_CODE     = 0x14,
    FACILITY_SXS_ERROR_CODE      = 0x15,
    FACILITY_TRANSACTION         = 0x19,
    FACILITY_COMMONLOG           = 0x1A,
    FACILITY_VIDEO               = 0x1B,
    FACILITY_FILTER_MANAGER      = 0x1C,
    FACILITY_MONITOR             = 0x1D,
    FACILITY_GRAPHICS_KERNEL     = 0x1E,
    FACILITY_DRIVER_FRAMEWORK    = 0x20,
    FACILITY_FVE_ERROR_CODE      = 0x21,
    FACILITY_FWP_ERROR_CODE      = 0x22,
    FACILITY_NDIS_ERROR_CODE     = 0x23,
    FACILITY_TPM                 = 0x29,
    FACILITY_RTPM                = 0x2A,
    FACILITY_HYPERVISOR          = 0x35,
    FACILITY_IPSEC               = 0x36,
    FACILITY_VIRTUALIZATION      = 0x37,
    FACILITY_VOLMGR              = 0x38,
    FACILITY_BCD_ERROR_CODE      = 0x39,
    FACILITY_WIN32K_NTUSER       = 0x3E,
    FACILITY_WIN32K_NTGDI        = 0x3F,
    FACILITY_RESUME_KEY_FILTER   = 0x40,
    FACILITY_RDBSS               = 0x41,
    FACILITY_BTH_ATT             = 0x42,
    FACILITY_SECUREBOOT          = 0x43,
    FACILITY_AUDIO_KERNEL        = 0x44,
    FACILITY_VSM                 = 0x45,
    FACILITY_VOLSNAP             = 0x50,
    FACILITY_SDBUS               = 0x51,
    FACILITY_SHARED_VHDX         = 0x5C,
    FACILITY_SMB                 = 0x5D,
    FACILITY_INTERIX             = 0x99,
    FACILITY_SPACES              = 0xE7,
    FACILITY_SECURITY_CORE       = 0xE8,
    FACILITY_SYSTEM_INTEGRITY    = 0xE9,
    FACILITY_LICENSING           = 0xEA,
    FACILITY_PLATFORM_MANIFEST   = 0xEB,
    FACILITY_APP_EXEC            = 0xEC,
    FACILITY_MAXIMUM_VALUE       = 0xED
} ntstatus_facility_t;

typedef enum ntstatus_severity
{
    STATUS_SEVERITY_SUCCESS       = 0x0,
    STATUS_SEVERITY_INFORMATIONAL = 0x1,
    STATUS_SEVERITY_WARNING       = 0x2,
    STATUS_SEVERITY_ERROR         = 0x3
} ntstatus_severity_t;

#define NTSTATUS_MAX_FORMAT_STR_SIZE 128

static inline
const char* ntstatus_format_string(ntstatus_t status, char* buffer, unsigned buf_size)
{
    static const char* severities[] =
    {
        [STATUS_SEVERITY_SUCCESS]       = "SUCCESS",
        [STATUS_SEVERITY_INFORMATIONAL] = "INFO",
        [STATUS_SEVERITY_WARNING]       = "WARNING",
        [STATUS_SEVERITY_ERROR]         = "ERROR"
    };

    static const char* facilities[] =
    {
        [0]                            = "NONE",
        [FACILITY_DEBUGGER]            = "DEBUGGER",
        [FACILITY_RPC_RUNTIME]         = "RPC_RUNTIME",
        [FACILITY_RPC_STUBS]           = "RPC_STUBS",
        [FACILITY_IO_ERROR_CODE]       = "IO_ERROR_CODE",
        [FACILITY_CODCLASS_ERROR_CODE] = "CODCLASS_ERROR_CODE",
        [FACILITY_NTWIN32]             = "NTWIN32",
        [FACILITY_NTCERT]              = "NTCERT",
        [FACILITY_NTSSPI]              = "NTSSPI",
        [FACILITY_TERMINAL_SERVER]     = "TERMINAL_SERVER",
        [FACILITY_USB_ERROR_CODE]      = "USB_ERROR_CODE",
        [FACILITY_HID_ERROR_CODE]      = "HID_ERROR_CODE",
        [FACILITY_FIREWIRE_ERROR_CODE] = "FIREWIRE_ERROR_CODE",
        [FACILITY_CLUSTER_ERROR_CODE]  = "CLUSTER_ERROR_CODE",
        [FACILITY_ACPI_ERROR_CODE]     = "ACPI_ERROR_CODE",
        [FACILITY_SXS_ERROR_CODE]      = "SXS_ERROR_CODE",
        [FACILITY_TRANSACTION]         = "TRANSACTION",
        [FACILITY_COMMONLOG]           = "COMMONLOG",
        [FACILITY_VIDEO]               = "VIDEO",
        [FACILITY_FILTER_MANAGER]      = "FILTER_MANAGER",
        [FACILITY_MONITOR]             = "MONITOR",
        [FACILITY_GRAPHICS_KERNEL]     = "GRAPHICS_KERNEL",
        [FACILITY_DRIVER_FRAMEWORK]    = "DRIVER_FRAMEWORK",
        [FACILITY_FVE_ERROR_CODE]      = "FVE_ERROR_CODE",
        [FACILITY_FWP_ERROR_CODE]      = "FWP_ERROR_CODE",
        [FACILITY_NDIS_ERROR_CODE]     = "NDIS_ERROR_CODE",
        [FACILITY_TPM]                 = "TPM",
        [FACILITY_RTPM]                = "RTPM",
        [FACILITY_HYPERVISOR]          = "HYPERVISOR",
        [FACILITY_IPSEC]               = "IPSEC",
        [FACILITY_VIRTUALIZATION]      = "VIRTUALIZATION",
        [FACILITY_VOLMGR]              = "VOLMGR",
        [FACILITY_BCD_ERROR_CODE]      = "BCD_ERROR_CODE",
        [FACILITY_WIN32K_NTUSER]       = "WIN32K_NTUSER",
        [FACILITY_WIN32K_NTGDI]        = "WIN32K_NTGDI",
        [FACILITY_RESUME_KEY_FILTER]   = "RESUME_KEY_FILTER",
        [FACILITY_RDBSS]               = "RDBSS",
        [FACILITY_BTH_ATT]             = "BTH_ATT",
        [FACILITY_SECUREBOOT]          = "SECUREBOOT",
        [FACILITY_AUDIO_KERNEL]        = "AUDIO_KERNEL",
        [FACILITY_VSM]                 = "VSM",
        [FACILITY_VOLSNAP]             = "VOLSNAP",
        [FACILITY_SDBUS]               = "SDBUS",
        [FACILITY_SHARED_VHDX]         = "SHARED_VHDX",
        [FACILITY_SMB]                 = "SMB",
        [FACILITY_INTERIX]             = "INTERIX",
        [FACILITY_SPACES]              = "SPACES",
        [FACILITY_SECURITY_CORE]       = "SECURITY_CORE",
        [FACILITY_SYSTEM_INTEGRITY]    = "SYSTEM_INTEGRITY",
        [FACILITY_LICENSING]           = "LICENSING",
        [FACILITY_PLATFORM_MANIFEST]   = "PLATFORM_MANIFEST",
        [FACILITY_APP_EXEC]            = "APP_EXEC"
    };
    unsigned severity = (status >> 30) & 3;
    unsigned customer = (status >> 29) & 1;
    unsigned facility = (status >> 16) & 0x00000FFFL;
    unsigned code     = (status & 0x0000FFFFL);

    snprintf(buffer, buf_size, "%s:%d:%s:0x%x",
        severities[severity],
        customer,
        facility < FACILITY_MAXIMUM_VALUE ? facilities[facility] : "UNKNOWN",
        code);

    return buffer;
}

static inline
const char* ntstatus_to_string(ntstatus_t status)
{
    switch (status)
    {
        case STATUS_SUCCESS:
            return "STATUS_SUCCESS";
        case STATUS_WAIT_1:
            return "STATUS_WAIT_1";
        case STATUS_WAIT_2:
            return "STATUS_WAIT_2";
        case STATUS_WAIT_3:
            return "STATUS_WAIT_3";
        case STATUS_WAIT_63:
            return "STATUS_WAIT_63";
        case STATUS_ABANDONED:
            return "STATUS_ABANDONED";
        case STATUS_ABANDONED_WAIT_63:
            return "STATUS_ABANDONED_WAIT_63";
        case STATUS_USER_APC:
            return "STATUS_USER_APC";
        case STATUS_ALREADY_COMPLETE:
            return "STATUS_ALREADY_COMPLETE";
        case STATUS_KERNEL_APC:
            return "STATUS_KERNEL_APC";
        case STATUS_ALERTED:
            return "STATUS_ALERTED";
        case STATUS_TIMEOUT:
            return "STATUS_TIMEOUT";
        case STATUS_PENDING:
            return "STATUS_PENDING";
        case STATUS_REPARSE:
            return "STATUS_REPARSE";
        case STATUS_MORE_ENTRIES:
            return "STATUS_MORE_ENTRIES";
        case STATUS_NOT_ALL_ASSIGNED:
            return "STATUS_NOT_ALL_ASSIGNED";
        case STATUS_SOME_NOT_MAPPED:
            return "STATUS_SOME_NOT_MAPPED";
        case STATUS_OPLOCK_BREAK_IN_PROGRESS:
            return "STATUS_OPLOCK_BREAK_IN_PROGRESS";
        case STATUS_VOLUME_MOUNTED:
            return "STATUS_VOLUME_MOUNTED";
        case STATUS_RXACT_COMMITTED:
            return "STATUS_RXACT_COMMITTED";
        case STATUS_NOTIFY_CLEANUP:
            return "STATUS_NOTIFY_CLEANUP";
        case STATUS_NOTIFY_ENUM_DIR:
            return "STATUS_NOTIFY_ENUM_DIR";
        case STATUS_NO_QUOTAS_FOR_ACCOUNT:
            return "STATUS_NO_QUOTAS_FOR_ACCOUNT";
        case STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED:
            return "STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED";
        case STATUS_PAGE_FAULT_TRANSITION:
            return "STATUS_PAGE_FAULT_TRANSITION";
        case STATUS_PAGE_FAULT_DEMAND_ZERO:
            return "STATUS_PAGE_FAULT_DEMAND_ZERO";
        case STATUS_PAGE_FAULT_COPY_ON_WRITE:
            return "STATUS_PAGE_FAULT_COPY_ON_WRITE";
        case STATUS_PAGE_FAULT_GUARD_PAGE:
            return "STATUS_PAGE_FAULT_GUARD_PAGE";
        case STATUS_PAGE_FAULT_PAGING_FILE:
            return "STATUS_PAGE_FAULT_PAGING_FILE";
        case STATUS_CACHE_PAGE_LOCKED:
            return "STATUS_CACHE_PAGE_LOCKED";
        case STATUS_CRASH_DUMP:
            return "STATUS_CRASH_DUMP";
        case STATUS_BUFFER_ALL_ZEROS:
            return "STATUS_BUFFER_ALL_ZEROS";
        case STATUS_REPARSE_OBJECT:
            return "STATUS_REPARSE_OBJECT";
        case STATUS_RESOURCE_REQUIREMENTS_CHANGED:
            return "STATUS_RESOURCE_REQUIREMENTS_CHANGED";
        case STATUS_TRANSLATION_COMPLETE:
            return "STATUS_TRANSLATION_COMPLETE";
        case STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY:
            return "STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY";
        case STATUS_NOTHING_TO_TERMINATE:
            return "STATUS_NOTHING_TO_TERMINATE";
        case STATUS_PROCESS_NOT_IN_JOB:
            return "STATUS_PROCESS_NOT_IN_JOB";
        case STATUS_PROCESS_IN_JOB:
            return "STATUS_PROCESS_IN_JOB";
        case STATUS_VOLSNAP_HIBERNATE_READY:
            return "STATUS_VOLSNAP_HIBERNATE_READY";
        case STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY:
            return "STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY";
        case STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED:
            return "STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED";
        case STATUS_INTERRUPT_STILL_CONNECTED:
            return "STATUS_INTERRUPT_STILL_CONNECTED";
        case STATUS_PROCESS_CLONED:
            return "STATUS_PROCESS_CLONED";
        case STATUS_FILE_LOCKED_WITH_ONLY_READERS:
            return "STATUS_FILE_LOCKED_WITH_ONLY_READERS";
        case STATUS_FILE_LOCKED_WITH_WRITERS:
            return "STATUS_FILE_LOCKED_WITH_WRITERS";
        case STATUS_VALID_IMAGE_HASH:
            return "STATUS_VALID_IMAGE_HASH";
        case STATUS_VALID_CATALOG_HASH:
            return "STATUS_VALID_CATALOG_HASH";
        case STATUS_VALID_STRONG_CODE_HASH:
            return "STATUS_VALID_STRONG_CODE_HASH";
        case STATUS_GHOSTED:
            return "STATUS_GHOSTED";
        case STATUS_DATA_OVERWRITTEN:
            return "STATUS_DATA_OVERWRITTEN";
        case STATUS_RESOURCEMANAGER_READ_ONLY:
            return "STATUS_RESOURCEMANAGER_READ_ONLY";
        case STATUS_RING_PREVIOUSLY_EMPTY:
            return "STATUS_RING_PREVIOUSLY_EMPTY";
        case STATUS_RING_PREVIOUSLY_FULL:
            return "STATUS_RING_PREVIOUSLY_FULL";
        case STATUS_RING_PREVIOUSLY_ABOVE_QUOTA:
            return "STATUS_RING_PREVIOUSLY_ABOVE_QUOTA";
        case STATUS_RING_NEWLY_EMPTY:
            return "STATUS_RING_NEWLY_EMPTY";
        case STATUS_RING_SIGNAL_OPPOSITE_ENDPOINT:
            return "STATUS_RING_SIGNAL_OPPOSITE_ENDPOINT";
        case STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE:
            return "STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE";
        case STATUS_OPLOCK_HANDLE_CLOSED:
            return "STATUS_OPLOCK_HANDLE_CLOSED";
        case STATUS_WAIT_FOR_OPLOCK:
            return "STATUS_WAIT_FOR_OPLOCK";
        case STATUS_REPARSE_GLOBAL:
            return "STATUS_REPARSE_GLOBAL";
        case DBG_EXCEPTION_HANDLED:
            return "DBG_EXCEPTION_HANDLED";
        case DBG_CONTINUE:
            return "DBG_CONTINUE";
        case STATUS_FLT_IO_COMPLETE:
            return "STATUS_FLT_IO_COMPLETE";
        case STATUS_OBJECT_NAME_EXISTS:
            return "STATUS_OBJECT_NAME_EXISTS";
        case STATUS_THREAD_WAS_SUSPENDED:
            return "STATUS_THREAD_WAS_SUSPENDED";
        case STATUS_WORKING_SET_LIMIT_RANGE:
            return "STATUS_WORKING_SET_LIMIT_RANGE";
        case STATUS_IMAGE_NOT_AT_BASE:
            return "STATUS_IMAGE_NOT_AT_BASE";
        case STATUS_RXACT_STATE_CREATED:
            return "STATUS_RXACT_STATE_CREATED";
        case STATUS_SEGMENT_NOTIFICATION:
            return "STATUS_SEGMENT_NOTIFICATION";
        case STATUS_LOCAL_USER_SESSION_KEY:
            return "STATUS_LOCAL_USER_SESSION_KEY";
        case STATUS_BAD_CURRENT_DIRECTORY:
            return "STATUS_BAD_CURRENT_DIRECTORY";
        case STATUS_SERIAL_MORE_WRITES:
            return "STATUS_SERIAL_MORE_WRITES";
        case STATUS_REGISTRY_RECOVERED:
            return "STATUS_REGISTRY_RECOVERED";
        case STATUS_FT_READ_RECOVERY_FROM_BACKUP:
            return "STATUS_FT_READ_RECOVERY_FROM_BACKUP";
        case STATUS_FT_WRITE_RECOVERY:
            return "STATUS_FT_WRITE_RECOVERY";
        case STATUS_SERIAL_COUNTER_TIMEOUT:
            return "STATUS_SERIAL_COUNTER_TIMEOUT";
        case STATUS_NULL_LM_PASSWORD:
            return "STATUS_NULL_LM_PASSWORD";
        case STATUS_IMAGE_MACHINE_TYPE_MISMATCH:
            return "STATUS_IMAGE_MACHINE_TYPE_MISMATCH";
        case STATUS_RECEIVE_PARTIAL:
            return "STATUS_RECEIVE_PARTIAL";
        case STATUS_RECEIVE_EXPEDITED:
            return "STATUS_RECEIVE_EXPEDITED";
        case STATUS_RECEIVE_PARTIAL_EXPEDITED:
            return "STATUS_RECEIVE_PARTIAL_EXPEDITED";
        case STATUS_EVENT_DONE:
            return "STATUS_EVENT_DONE";
        case STATUS_EVENT_PENDING:
            return "STATUS_EVENT_PENDING";
        case STATUS_CHECKING_FILE_SYSTEM:
            return "STATUS_CHECKING_FILE_SYSTEM";
        case STATUS_FATAL_APP_EXIT:
            return "STATUS_FATAL_APP_EXIT";
        case STATUS_PREDEFINED_HANDLE:
            return "STATUS_PREDEFINED_HANDLE";
        case STATUS_WAS_UNLOCKED:
            return "STATUS_WAS_UNLOCKED";
        case STATUS_SERVICE_NOTIFICATION:
            return "STATUS_SERVICE_NOTIFICATION";
        case STATUS_WAS_LOCKED:
            return "STATUS_WAS_LOCKED";
        case STATUS_LOG_HARD_ERROR:
            return "STATUS_LOG_HARD_ERROR";
        case STATUS_ALREADY_WIN32:
            return "STATUS_ALREADY_WIN32";
        case STATUS_WX86_UNSIMULATE:
            return "STATUS_WX86_UNSIMULATE";
        case STATUS_WX86_CONTINUE:
            return "STATUS_WX86_CONTINUE";
        case STATUS_WX86_SINGLE_STEP:
            return "STATUS_WX86_SINGLE_STEP";
        case STATUS_WX86_BREAKPOINT:
            return "STATUS_WX86_BREAKPOINT";
        case STATUS_WX86_EXCEPTION_CONTINUE:
            return "STATUS_WX86_EXCEPTION_CONTINUE";
        case STATUS_WX86_EXCEPTION_LASTCHANCE:
            return "STATUS_WX86_EXCEPTION_LASTCHANCE";
        case STATUS_WX86_EXCEPTION_CHAIN:
            return "STATUS_WX86_EXCEPTION_CHAIN";
        case STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE:
            return "STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE";
        case STATUS_NO_YIELD_PERFORMED:
            return "STATUS_NO_YIELD_PERFORMED";
        case STATUS_TIMER_RESUME_IGNORED:
            return "STATUS_TIMER_RESUME_IGNORED";
        case STATUS_ARBITRATION_UNHANDLED:
            return "STATUS_ARBITRATION_UNHANDLED";
        case STATUS_CARDBUS_NOT_SUPPORTED:
            return "STATUS_CARDBUS_NOT_SUPPORTED";
        case STATUS_WX86_CREATEWX86TIB:
            return "STATUS_WX86_CREATEWX86TIB";
        case STATUS_MP_PROCESSOR_MISMATCH:
            return "STATUS_MP_PROCESSOR_MISMATCH";
        case STATUS_HIBERNATED:
            return "STATUS_HIBERNATED";
        case STATUS_RESUME_HIBERNATION:
            return "STATUS_RESUME_HIBERNATION";
        case STATUS_FIRMWARE_UPDATED:
            return "STATUS_FIRMWARE_UPDATED";
        case STATUS_DRIVERS_LEAKING_LOCKED_PAGES:
            return "STATUS_DRIVERS_LEAKING_LOCKED_PAGES";
        case STATUS_MESSAGE_RETRIEVED:
            return "STATUS_MESSAGE_RETRIEVED";
        case STATUS_SYSTEM_POWERSTATE_TRANSITION:
            return "STATUS_SYSTEM_POWERSTATE_TRANSITION";
        case STATUS_ALPC_CHECK_COMPLETION_LIST:
            return "STATUS_ALPC_CHECK_COMPLETION_LIST";
        case STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION:
            return "STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION";
        case STATUS_ACCESS_AUDIT_BY_POLICY:
            return "STATUS_ACCESS_AUDIT_BY_POLICY";
        case STATUS_ABANDON_HIBERFILE:
            return "STATUS_ABANDON_HIBERFILE";
        case STATUS_BIZRULES_NOT_ENABLED:
            return "STATUS_BIZRULES_NOT_ENABLED";
        case STATUS_FT_READ_FROM_COPY:
            return "STATUS_FT_READ_FROM_COPY";
        case STATUS_IMAGE_AT_DIFFERENT_BASE:
            return "STATUS_IMAGE_AT_DIFFERENT_BASE";
        case STATUS_PATCH_DEFERRED:
            return "STATUS_PATCH_DEFERRED";
        case DBG_REPLY_LATER:
            return "DBG_REPLY_LATER";
        case DBG_UNABLE_TO_PROVIDE_HANDLE:
            return "DBG_UNABLE_TO_PROVIDE_HANDLE";
        case DBG_TERMINATE_THREAD:
            return "DBG_TERMINATE_THREAD";
        case DBG_TERMINATE_PROCESS:
            return "DBG_TERMINATE_PROCESS";
        case DBG_CONTROL_C:
            return "DBG_CONTROL_C";
        case DBG_PRINTEXCEPTION_C:
            return "DBG_PRINTEXCEPTION_C";
        case DBG_RIPEXCEPTION:
            return "DBG_RIPEXCEPTION";
        case DBG_CONTROL_BREAK:
            return "DBG_CONTROL_BREAK";
        case DBG_COMMAND_EXCEPTION:
            return "DBG_COMMAND_EXCEPTION";
        case DBG_PRINTEXCEPTION_WIDE_C:
            return "DBG_PRINTEXCEPTION_WIDE_C";
        case STATUS_HEURISTIC_DAMAGE_POSSIBLE:
            return "STATUS_HEURISTIC_DAMAGE_POSSIBLE";
        case STATUS_GUARD_PAGE_VIOLATION:
            return "STATUS_GUARD_PAGE_VIOLATION";
        case STATUS_DATATYPE_MISALIGNMENT:
            return "STATUS_DATATYPE_MISALIGNMENT";
        case STATUS_BREAKPOINT:
            return "STATUS_BREAKPOINT";
        case STATUS_SINGLE_STEP:
            return "STATUS_SINGLE_STEP";
        case STATUS_BUFFER_OVERFLOW:
            return "STATUS_BUFFER_OVERFLOW";
        case STATUS_NO_MORE_FILES:
            return "STATUS_NO_MORE_FILES";
        case STATUS_WAKE_SYSTEM_DEBUGGER:
            return "STATUS_WAKE_SYSTEM_DEBUGGER";
        case STATUS_HANDLES_CLOSED:
            return "STATUS_HANDLES_CLOSED";
        case STATUS_NO_INHERITANCE:
            return "STATUS_NO_INHERITANCE";
        case STATUS_GUID_SUBSTITUTION_MADE:
            return "STATUS_GUID_SUBSTITUTION_MADE";
        case STATUS_PARTIAL_COPY:
            return "STATUS_PARTIAL_COPY";
        case STATUS_DEVICE_PAPER_EMPTY:
            return "STATUS_DEVICE_PAPER_EMPTY";
        case STATUS_DEVICE_POWERED_OFF:
            return "STATUS_DEVICE_POWERED_OFF";
        case STATUS_DEVICE_OFF_LINE:
            return "STATUS_DEVICE_OFF_LINE";
        case STATUS_DEVICE_BUSY:
            return "STATUS_DEVICE_BUSY";
        case STATUS_NO_MORE_EAS:
            return "STATUS_NO_MORE_EAS";
        case STATUS_INVALID_EA_NAME:
            return "STATUS_INVALID_EA_NAME";
        case STATUS_EA_LIST_INCONSISTENT:
            return "STATUS_EA_LIST_INCONSISTENT";
        case STATUS_INVALID_EA_FLAG:
            return "STATUS_INVALID_EA_FLAG";
        case STATUS_VERIFY_REQUIRED:
            return "STATUS_VERIFY_REQUIRED";
        case STATUS_EXTRANEOUS_INFORMATION:
            return "STATUS_EXTRANEOUS_INFORMATION";
        case STATUS_RXACT_COMMIT_NECESSARY:
            return "STATUS_RXACT_COMMIT_NECESSARY";
        case STATUS_NO_MORE_ENTRIES:
            return "STATUS_NO_MORE_ENTRIES";
        case STATUS_FILEMARK_DETECTED:
            return "STATUS_FILEMARK_DETECTED";
        case STATUS_MEDIA_CHANGED:
            return "STATUS_MEDIA_CHANGED";
        case STATUS_BUS_RESET:
            return "STATUS_BUS_RESET";
        case STATUS_END_OF_MEDIA:
            return "STATUS_END_OF_MEDIA";
        case STATUS_BEGINNING_OF_MEDIA:
            return "STATUS_BEGINNING_OF_MEDIA";
        case STATUS_MEDIA_CHECK:
            return "STATUS_MEDIA_CHECK";
        case STATUS_SETMARK_DETECTED:
            return "STATUS_SETMARK_DETECTED";
        case STATUS_NO_DATA_DETECTED:
            return "STATUS_NO_DATA_DETECTED";
        case STATUS_REDIRECTOR_HAS_OPEN_HANDLES:
            return "STATUS_REDIRECTOR_HAS_OPEN_HANDLES";
        case STATUS_SERVER_HAS_OPEN_HANDLES:
            return "STATUS_SERVER_HAS_OPEN_HANDLES";
        case STATUS_ALREADY_DISCONNECTED:
            return "STATUS_ALREADY_DISCONNECTED";
        case STATUS_LONGJUMP:
            return "STATUS_LONGJUMP";
        case STATUS_CLEANER_CARTRIDGE_INSTALLED:
            return "STATUS_CLEANER_CARTRIDGE_INSTALLED";
        case STATUS_PLUGPLAY_QUERY_VETOED:
            return "STATUS_PLUGPLAY_QUERY_VETOED";
        case STATUS_UNWIND_CONSOLIDATE:
            return "STATUS_UNWIND_CONSOLIDATE";
        case STATUS_REGISTRY_HIVE_RECOVERED:
            return "STATUS_REGISTRY_HIVE_RECOVERED";
        case STATUS_DLL_MIGHT_BE_INSECURE:
            return "STATUS_DLL_MIGHT_BE_INSECURE";
        case STATUS_DLL_MIGHT_BE_INCOMPATIBLE:
            return "STATUS_DLL_MIGHT_BE_INCOMPATIBLE";
        case STATUS_STOPPED_ON_SYMLINK:
            return "STATUS_STOPPED_ON_SYMLINK";
        case STATUS_CANNOT_GRANT_REQUESTED_OPLOCK:
            return "STATUS_CANNOT_GRANT_REQUESTED_OPLOCK";
        case STATUS_NO_ACE_CONDITION:
            return "STATUS_NO_ACE_CONDITION";
        case STATUS_DEVICE_SUPPORT_IN_PROGRESS:
            return "STATUS_DEVICE_SUPPORT_IN_PROGRESS";
        case STATUS_DEVICE_POWER_CYCLE_REQUIRED:
            return "STATUS_DEVICE_POWER_CYCLE_REQUIRED";
        case STATUS_NO_WORK_DONE:
            return "STATUS_NO_WORK_DONE";
        case DBG_EXCEPTION_NOT_HANDLED:
            return "DBG_EXCEPTION_NOT_HANDLED";
        case STATUS_CLUSTER_NODE_ALREADY_UP:
            return "STATUS_CLUSTER_NODE_ALREADY_UP";
        case STATUS_CLUSTER_NODE_ALREADY_DOWN:
            return "STATUS_CLUSTER_NODE_ALREADY_DOWN";
        case STATUS_CLUSTER_NETWORK_ALREADY_ONLINE:
            return "STATUS_CLUSTER_NETWORK_ALREADY_ONLINE";
        case STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE:
            return "STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE";
        case STATUS_CLUSTER_NODE_ALREADY_MEMBER:
            return "STATUS_CLUSTER_NODE_ALREADY_MEMBER";
        case STATUS_FLT_BUFFER_TOO_SMALL:
            return "STATUS_FLT_BUFFER_TOO_SMALL";
        case STATUS_FVE_PARTIAL_METADATA:
            return "STATUS_FVE_PARTIAL_METADATA";
        case STATUS_FVE_TRANSIENT_STATE:
            return "STATUS_FVE_TRANSIENT_STATE";
        case STATUS_CLOUD_FILE_PROPERTY_BLOB_CHECKSUM_MISMATCH:
            return "STATUS_CLOUD_FILE_PROPERTY_BLOB_CHECKSUM_MISMATCH";
        case STATUS_UNSUCCESSFUL:
            return "STATUS_UNSUCCESSFUL";
        case STATUS_NOT_IMPLEMENTED:
            return "STATUS_NOT_IMPLEMENTED";
        case STATUS_INVALID_INFO_CLASS:
            return "STATUS_INVALID_INFO_CLASS";
        case STATUS_INFO_LENGTH_MISMATCH:
            return "STATUS_INFO_LENGTH_MISMATCH";
        case STATUS_ACCESS_VIOLATION:
            return "STATUS_ACCESS_VIOLATION";
        case STATUS_IN_PAGE_ERROR:
            return "STATUS_IN_PAGE_ERROR";
        case STATUS_PAGEFILE_QUOTA:
            return "STATUS_PAGEFILE_QUOTA";
        case STATUS_INVALID_HANDLE:
            return "STATUS_INVALID_HANDLE";
        case STATUS_BAD_INITIAL_STACK:
            return "STATUS_BAD_INITIAL_STACK";
        case STATUS_BAD_INITIAL_PC:
            return "STATUS_BAD_INITIAL_PC";
        case STATUS_INVALID_CID:
            return "STATUS_INVALID_CID";
        case STATUS_TIMER_NOT_CANCELED:
            return "STATUS_TIMER_NOT_CANCELED";
        case STATUS_INVALID_PARAMETER:
            return "STATUS_INVALID_PARAMETER";
        case STATUS_NO_SUCH_DEVICE:
            return "STATUS_NO_SUCH_DEVICE";
        case STATUS_NO_SUCH_FILE:
            return "STATUS_NO_SUCH_FILE";
        case STATUS_INVALID_DEVICE_REQUEST:
            return "STATUS_INVALID_DEVICE_REQUEST";
        case STATUS_END_OF_FILE:
            return "STATUS_END_OF_FILE";
        case STATUS_WRONG_VOLUME:
            return "STATUS_WRONG_VOLUME";
        case STATUS_NO_MEDIA_IN_DEVICE:
            return "STATUS_NO_MEDIA_IN_DEVICE";
        case STATUS_UNRECOGNIZED_MEDIA:
            return "STATUS_UNRECOGNIZED_MEDIA";
        case STATUS_NONEXISTENT_SECTOR:
            return "STATUS_NONEXISTENT_SECTOR";
        case STATUS_MORE_PROCESSING_REQUIRED:
            return "STATUS_MORE_PROCESSING_REQUIRED";
        case STATUS_NO_MEMORY:
            return "STATUS_NO_MEMORY";
        case STATUS_CONFLICTING_ADDRESSES:
            return "STATUS_CONFLICTING_ADDRESSES";
        case STATUS_NOT_MAPPED_VIEW:
            return "STATUS_NOT_MAPPED_VIEW";
        case STATUS_UNABLE_TO_FREE_VM:
            return "STATUS_UNABLE_TO_FREE_VM";
        case STATUS_UNABLE_TO_DELETE_SECTION:
            return "STATUS_UNABLE_TO_DELETE_SECTION";
        case STATUS_INVALID_SYSTEM_SERVICE:
            return "STATUS_INVALID_SYSTEM_SERVICE";
        case STATUS_ILLEGAL_INSTRUCTION:
            return "STATUS_ILLEGAL_INSTRUCTION";
        case STATUS_INVALID_LOCK_SEQUENCE:
            return "STATUS_INVALID_LOCK_SEQUENCE";
        case STATUS_INVALID_VIEW_SIZE:
            return "STATUS_INVALID_VIEW_SIZE";
        case STATUS_INVALID_FILE_FOR_SECTION:
            return "STATUS_INVALID_FILE_FOR_SECTION";
        case STATUS_ALREADY_COMMITTED:
            return "STATUS_ALREADY_COMMITTED";
        case STATUS_ACCESS_DENIED:
            return "STATUS_ACCESS_DENIED";
        case STATUS_BUFFER_TOO_SMALL:
            return "STATUS_BUFFER_TOO_SMALL";
        case STATUS_OBJECT_TYPE_MISMATCH:
            return "STATUS_OBJECT_TYPE_MISMATCH";
        case STATUS_NONCONTINUABLE_EXCEPTION:
            return "STATUS_NONCONTINUABLE_EXCEPTION";
        case STATUS_INVALID_DISPOSITION:
            return "STATUS_INVALID_DISPOSITION";
        case STATUS_UNWIND:
            return "STATUS_UNWIND";
        case STATUS_BAD_STACK:
            return "STATUS_BAD_STACK";
        case STATUS_INVALID_UNWIND_TARGET:
            return "STATUS_INVALID_UNWIND_TARGET";
        case STATUS_NOT_LOCKED:
            return "STATUS_NOT_LOCKED";
        case STATUS_PARITY_ERROR:
            return "STATUS_PARITY_ERROR";
        case STATUS_UNABLE_TO_DECOMMIT_VM:
            return "STATUS_UNABLE_TO_DECOMMIT_VM";
        case STATUS_NOT_COMMITTED:
            return "STATUS_NOT_COMMITTED";
        case STATUS_INVALID_PORT_ATTRIBUTES:
            return "STATUS_INVALID_PORT_ATTRIBUTES";
        case STATUS_PORT_MESSAGE_TOO_LONG:
            return "STATUS_PORT_MESSAGE_TOO_LONG";
        case STATUS_INVALID_PARAMETER_MIX:
            return "STATUS_INVALID_PARAMETER_MIX";
        case STATUS_INVALID_QUOTA_LOWER:
            return "STATUS_INVALID_QUOTA_LOWER";
        case STATUS_DISK_CORRUPT_ERROR:
            return "STATUS_DISK_CORRUPT_ERROR";
        case STATUS_OBJECT_NAME_INVALID:
            return "STATUS_OBJECT_NAME_INVALID";
        case STATUS_OBJECT_NAME_NOT_FOUND:
            return "STATUS_OBJECT_NAME_NOT_FOUND";
        case STATUS_OBJECT_NAME_COLLISION:
            return "STATUS_OBJECT_NAME_COLLISION";
        case STATUS_PORT_DO_NOT_DISTURB:
            return "STATUS_PORT_DO_NOT_DISTURB";
        case STATUS_PORT_DISCONNECTED:
            return "STATUS_PORT_DISCONNECTED";
        case STATUS_DEVICE_ALREADY_ATTACHED:
            return "STATUS_DEVICE_ALREADY_ATTACHED";
        case STATUS_OBJECT_PATH_INVALID:
            return "STATUS_OBJECT_PATH_INVALID";
        case STATUS_OBJECT_PATH_NOT_FOUND:
            return "STATUS_OBJECT_PATH_NOT_FOUND";
        case STATUS_OBJECT_PATH_SYNTAX_BAD:
            return "STATUS_OBJECT_PATH_SYNTAX_BAD";
        case STATUS_DATA_OVERRUN:
            return "STATUS_DATA_OVERRUN";
        case STATUS_DATA_LATE_ERROR:
            return "STATUS_DATA_LATE_ERROR";
        case STATUS_DATA_ERROR:
            return "STATUS_DATA_ERROR";
        case STATUS_CRC_ERROR:
            return "STATUS_CRC_ERROR";
        case STATUS_SECTION_TOO_BIG:
            return "STATUS_SECTION_TOO_BIG";
        case STATUS_PORT_CONNECTION_REFUSED:
            return "STATUS_PORT_CONNECTION_REFUSED";
        case STATUS_INVALID_PORT_HANDLE:
            return "STATUS_INVALID_PORT_HANDLE";
        case STATUS_SHARING_VIOLATION:
            return "STATUS_SHARING_VIOLATION";
        case STATUS_QUOTA_EXCEEDED:
            return "STATUS_QUOTA_EXCEEDED";
        case STATUS_INVALID_PAGE_PROTECTION:
            return "STATUS_INVALID_PAGE_PROTECTION";
        case STATUS_MUTANT_NOT_OWNED:
            return "STATUS_MUTANT_NOT_OWNED";
        case STATUS_SEMAPHORE_LIMIT_EXCEEDED:
            return "STATUS_SEMAPHORE_LIMIT_EXCEEDED";
        case STATUS_PORT_ALREADY_SET:
            return "STATUS_PORT_ALREADY_SET";
        case STATUS_SECTION_NOT_IMAGE:
            return "STATUS_SECTION_NOT_IMAGE";
        case STATUS_SUSPEND_COUNT_EXCEEDED:
            return "STATUS_SUSPEND_COUNT_EXCEEDED";
        case STATUS_THREAD_IS_TERMINATING:
            return "STATUS_THREAD_IS_TERMINATING";
        case STATUS_BAD_WORKING_SET_LIMIT:
            return "STATUS_BAD_WORKING_SET_LIMIT";
        case STATUS_INCOMPATIBLE_FILE_MAP:
            return "STATUS_INCOMPATIBLE_FILE_MAP";
        case STATUS_SECTION_PROTECTION:
            return "STATUS_SECTION_PROTECTION";
        case STATUS_EAS_NOT_SUPPORTED:
            return "STATUS_EAS_NOT_SUPPORTED";
        case STATUS_EA_TOO_LARGE:
            return "STATUS_EA_TOO_LARGE";
        case STATUS_NONEXISTENT_EA_ENTRY:
            return "STATUS_NONEXISTENT_EA_ENTRY";
        case STATUS_NO_EAS_ON_FILE:
            return "STATUS_NO_EAS_ON_FILE";
        case STATUS_EA_CORRUPT_ERROR:
            return "STATUS_EA_CORRUPT_ERROR";
        case STATUS_FILE_LOCK_CONFLICT:
            return "STATUS_FILE_LOCK_CONFLICT";
        case STATUS_LOCK_NOT_GRANTED:
            return "STATUS_LOCK_NOT_GRANTED";
        case STATUS_DELETE_PENDING:
            return "STATUS_DELETE_PENDING";
        case STATUS_CTL_FILE_NOT_SUPPORTED:
            return "STATUS_CTL_FILE_NOT_SUPPORTED";
        case STATUS_UNKNOWN_REVISION:
            return "STATUS_UNKNOWN_REVISION";
        case STATUS_REVISION_MISMATCH:
            return "STATUS_REVISION_MISMATCH";
        case STATUS_INVALID_OWNER:
            return "STATUS_INVALID_OWNER";
        case STATUS_INVALID_PRIMARY_GROUP:
            return "STATUS_INVALID_PRIMARY_GROUP";
        case STATUS_NO_IMPERSONATION_TOKEN:
            return "STATUS_NO_IMPERSONATION_TOKEN";
        case STATUS_CANT_DISABLE_MANDATORY:
            return "STATUS_CANT_DISABLE_MANDATORY";
        case STATUS_NO_LOGON_SERVERS:
            return "STATUS_NO_LOGON_SERVERS";
        case STATUS_NO_SUCH_LOGON_SESSION:
            return "STATUS_NO_SUCH_LOGON_SESSION";
        case STATUS_NO_SUCH_PRIVILEGE:
            return "STATUS_NO_SUCH_PRIVILEGE";
        case STATUS_PRIVILEGE_NOT_HELD:
            return "STATUS_PRIVILEGE_NOT_HELD";
        case STATUS_INVALID_ACCOUNT_NAME:
            return "STATUS_INVALID_ACCOUNT_NAME";
        case STATUS_USER_EXISTS:
            return "STATUS_USER_EXISTS";
        case STATUS_NO_SUCH_USER:
            return "STATUS_NO_SUCH_USER";
        case STATUS_GROUP_EXISTS:
            return "STATUS_GROUP_EXISTS";
        case STATUS_NO_SUCH_GROUP:
            return "STATUS_NO_SUCH_GROUP";
        case STATUS_MEMBER_IN_GROUP:
            return "STATUS_MEMBER_IN_GROUP";
        case STATUS_MEMBER_NOT_IN_GROUP:
            return "STATUS_MEMBER_NOT_IN_GROUP";
        case STATUS_LAST_ADMIN:
            return "STATUS_LAST_ADMIN";
        case STATUS_WRONG_PASSWORD:
            return "STATUS_WRONG_PASSWORD";
        case STATUS_ILL_FORMED_PASSWORD:
            return "STATUS_ILL_FORMED_PASSWORD";
        case STATUS_PASSWORD_RESTRICTION:
            return "STATUS_PASSWORD_RESTRICTION";
        case STATUS_LOGON_FAILURE:
            return "STATUS_LOGON_FAILURE";
        case STATUS_ACCOUNT_RESTRICTION:
            return "STATUS_ACCOUNT_RESTRICTION";
        case STATUS_INVALID_LOGON_HOURS:
            return "STATUS_INVALID_LOGON_HOURS";
        case STATUS_INVALID_WORKSTATION:
            return "STATUS_INVALID_WORKSTATION";
        case STATUS_PASSWORD_EXPIRED:
            return "STATUS_PASSWORD_EXPIRED";
        case STATUS_ACCOUNT_DISABLED:
            return "STATUS_ACCOUNT_DISABLED";
        case STATUS_NONE_MAPPED:
            return "STATUS_NONE_MAPPED";
        case STATUS_TOO_MANY_LUIDS_REQUESTED:
            return "STATUS_TOO_MANY_LUIDS_REQUESTED";
        case STATUS_LUIDS_EXHAUSTED:
            return "STATUS_LUIDS_EXHAUSTED";
        case STATUS_INVALID_SUB_AUTHORITY:
            return "STATUS_INVALID_SUB_AUTHORITY";
        case STATUS_INVALID_ACL:
            return "STATUS_INVALID_ACL";
        case STATUS_INVALID_SID:
            return "STATUS_INVALID_SID";
        case STATUS_INVALID_SECURITY_DESCR:
            return "STATUS_INVALID_SECURITY_DESCR";
        case STATUS_PROCEDURE_NOT_FOUND:
            return "STATUS_PROCEDURE_NOT_FOUND";
        case STATUS_INVALID_IMAGE_FORMAT:
            return "STATUS_INVALID_IMAGE_FORMAT";
        case STATUS_NO_TOKEN:
            return "STATUS_NO_TOKEN";
        case STATUS_BAD_INHERITANCE_ACL:
            return "STATUS_BAD_INHERITANCE_ACL";
        case STATUS_RANGE_NOT_LOCKED:
            return "STATUS_RANGE_NOT_LOCKED";
        case STATUS_DISK_FULL:
            return "STATUS_DISK_FULL";
        case STATUS_SERVER_DISABLED:
            return "STATUS_SERVER_DISABLED";
        case STATUS_SERVER_NOT_DISABLED:
            return "STATUS_SERVER_NOT_DISABLED";
        case STATUS_TOO_MANY_GUIDS_REQUESTED:
            return "STATUS_TOO_MANY_GUIDS_REQUESTED";
        case STATUS_GUIDS_EXHAUSTED:
            return "STATUS_GUIDS_EXHAUSTED";
        case STATUS_INVALID_ID_AUTHORITY:
            return "STATUS_INVALID_ID_AUTHORITY";
        case STATUS_AGENTS_EXHAUSTED:
            return "STATUS_AGENTS_EXHAUSTED";
        case STATUS_INVALID_VOLUME_LABEL:
            return "STATUS_INVALID_VOLUME_LABEL";
        case STATUS_SECTION_NOT_EXTENDED:
            return "STATUS_SECTION_NOT_EXTENDED";
        case STATUS_NOT_MAPPED_DATA:
            return "STATUS_NOT_MAPPED_DATA";
        case STATUS_RESOURCE_DATA_NOT_FOUND:
            return "STATUS_RESOURCE_DATA_NOT_FOUND";
        case STATUS_RESOURCE_TYPE_NOT_FOUND:
            return "STATUS_RESOURCE_TYPE_NOT_FOUND";
        case STATUS_RESOURCE_NAME_NOT_FOUND:
            return "STATUS_RESOURCE_NAME_NOT_FOUND";
        case STATUS_ARRAY_BOUNDS_EXCEEDED:
            return "STATUS_ARRAY_BOUNDS_EXCEEDED";
        case STATUS_FLOAT_DENORMAL_OPERAND:
            return "STATUS_FLOAT_DENORMAL_OPERAND";
        case STATUS_FLOAT_DIVIDE_BY_ZERO:
            return "STATUS_FLOAT_DIVIDE_BY_ZERO";
        case STATUS_FLOAT_INEXACT_RESULT:
            return "STATUS_FLOAT_INEXACT_RESULT";
        case STATUS_FLOAT_INVALID_OPERATION:
            return "STATUS_FLOAT_INVALID_OPERATION";
        case STATUS_FLOAT_OVERFLOW:
            return "STATUS_FLOAT_OVERFLOW";
        case STATUS_FLOAT_STACK_CHECK:
            return "STATUS_FLOAT_STACK_CHECK";
        case STATUS_FLOAT_UNDERFLOW:
            return "STATUS_FLOAT_UNDERFLOW";
        case STATUS_INTEGER_DIVIDE_BY_ZERO:
            return "STATUS_INTEGER_DIVIDE_BY_ZERO";
        case STATUS_INTEGER_OVERFLOW:
            return "STATUS_INTEGER_OVERFLOW";
        case STATUS_PRIVILEGED_INSTRUCTION:
            return "STATUS_PRIVILEGED_INSTRUCTION";
        case STATUS_TOO_MANY_PAGING_FILES:
            return "STATUS_TOO_MANY_PAGING_FILES";
        case STATUS_FILE_INVALID:
            return "STATUS_FILE_INVALID";
        case STATUS_ALLOTTED_SPACE_EXCEEDED:
            return "STATUS_ALLOTTED_SPACE_EXCEEDED";
        case STATUS_INSUFFICIENT_RESOURCES:
            return "STATUS_INSUFFICIENT_RESOURCES";
        case STATUS_DFS_EXIT_PATH_FOUND:
            return "STATUS_DFS_EXIT_PATH_FOUND";
        case STATUS_DEVICE_DATA_ERROR:
            return "STATUS_DEVICE_DATA_ERROR";
        case STATUS_DEVICE_NOT_CONNECTED:
            return "STATUS_DEVICE_NOT_CONNECTED";
        case STATUS_DEVICE_POWER_FAILURE:
            return "STATUS_DEVICE_POWER_FAILURE";
        case STATUS_FREE_VM_NOT_AT_BASE:
            return "STATUS_FREE_VM_NOT_AT_BASE";
        case STATUS_MEMORY_NOT_ALLOCATED:
            return "STATUS_MEMORY_NOT_ALLOCATED";
        case STATUS_WORKING_SET_QUOTA:
            return "STATUS_WORKING_SET_QUOTA";
        case STATUS_MEDIA_WRITE_PROTECTED:
            return "STATUS_MEDIA_WRITE_PROTECTED";
        case STATUS_DEVICE_NOT_READY:
            return "STATUS_DEVICE_NOT_READY";
        case STATUS_INVALID_GROUP_ATTRIBUTES:
            return "STATUS_INVALID_GROUP_ATTRIBUTES";
        case STATUS_BAD_IMPERSONATION_LEVEL:
            return "STATUS_BAD_IMPERSONATION_LEVEL";
        case STATUS_CANT_OPEN_ANONYMOUS:
            return "STATUS_CANT_OPEN_ANONYMOUS";
        case STATUS_BAD_VALIDATION_CLASS:
            return "STATUS_BAD_VALIDATION_CLASS";
        case STATUS_BAD_TOKEN_TYPE:
            return "STATUS_BAD_TOKEN_TYPE";
        case STATUS_BAD_MASTER_BOOT_RECORD:
            return "STATUS_BAD_MASTER_BOOT_RECORD";
        case STATUS_INSTRUCTION_MISALIGNMENT:
            return "STATUS_INSTRUCTION_MISALIGNMENT";
        case STATUS_INSTANCE_NOT_AVAILABLE:
            return "STATUS_INSTANCE_NOT_AVAILABLE";
        case STATUS_PIPE_NOT_AVAILABLE:
            return "STATUS_PIPE_NOT_AVAILABLE";
        case STATUS_INVALID_PIPE_STATE:
            return "STATUS_INVALID_PIPE_STATE";
        case STATUS_PIPE_BUSY:
            return "STATUS_PIPE_BUSY";
        case STATUS_ILLEGAL_FUNCTION:
            return "STATUS_ILLEGAL_FUNCTION";
        case STATUS_PIPE_DISCONNECTED:
            return "STATUS_PIPE_DISCONNECTED";
        case STATUS_PIPE_CLOSING:
            return "STATUS_PIPE_CLOSING";
        case STATUS_PIPE_CONNECTED:
            return "STATUS_PIPE_CONNECTED";
        case STATUS_PIPE_LISTENING:
            return "STATUS_PIPE_LISTENING";
        case STATUS_INVALID_READ_MODE:
            return "STATUS_INVALID_READ_MODE";
        case STATUS_IO_TIMEOUT:
            return "STATUS_IO_TIMEOUT";
        case STATUS_FILE_FORCED_CLOSED:
            return "STATUS_FILE_FORCED_CLOSED";
        case STATUS_PROFILING_NOT_STARTED:
            return "STATUS_PROFILING_NOT_STARTED";
        case STATUS_PROFILING_NOT_STOPPED:
            return "STATUS_PROFILING_NOT_STOPPED";
        case STATUS_COULD_NOT_INTERPRET:
            return "STATUS_COULD_NOT_INTERPRET";
        case STATUS_FILE_IS_A_DIRECTORY:
            return "STATUS_FILE_IS_A_DIRECTORY";
        case STATUS_NOT_SUPPORTED:
            return "STATUS_NOT_SUPPORTED";
        case STATUS_REMOTE_NOT_LISTENING:
            return "STATUS_REMOTE_NOT_LISTENING";
        case STATUS_DUPLICATE_NAME:
            return "STATUS_DUPLICATE_NAME";
        case STATUS_BAD_NETWORK_PATH:
            return "STATUS_BAD_NETWORK_PATH";
        case STATUS_NETWORK_BUSY:
            return "STATUS_NETWORK_BUSY";
        case STATUS_DEVICE_DOES_NOT_EXIST:
            return "STATUS_DEVICE_DOES_NOT_EXIST";
        case STATUS_TOO_MANY_COMMANDS:
            return "STATUS_TOO_MANY_COMMANDS";
        case STATUS_ADAPTER_HARDWARE_ERROR:
            return "STATUS_ADAPTER_HARDWARE_ERROR";
        case STATUS_INVALID_NETWORK_RESPONSE:
            return "STATUS_INVALID_NETWORK_RESPONSE";
        case STATUS_UNEXPECTED_NETWORK_ERROR:
            return "STATUS_UNEXPECTED_NETWORK_ERROR";
        case STATUS_BAD_REMOTE_ADAPTER:
            return "STATUS_BAD_REMOTE_ADAPTER";
        case STATUS_PRINT_QUEUE_FULL:
            return "STATUS_PRINT_QUEUE_FULL";
        case STATUS_NO_SPOOL_SPACE:
            return "STATUS_NO_SPOOL_SPACE";
        case STATUS_PRINT_CANCELLED:
            return "STATUS_PRINT_CANCELLED";
        case STATUS_NETWORK_NAME_DELETED:
            return "STATUS_NETWORK_NAME_DELETED";
        case STATUS_NETWORK_ACCESS_DENIED:
            return "STATUS_NETWORK_ACCESS_DENIED";
        case STATUS_BAD_DEVICE_TYPE:
            return "STATUS_BAD_DEVICE_TYPE";
        case STATUS_BAD_NETWORK_NAME:
            return "STATUS_BAD_NETWORK_NAME";
        case STATUS_TOO_MANY_NAMES:
            return "STATUS_TOO_MANY_NAMES";
        case STATUS_TOO_MANY_SESSIONS:
            return "STATUS_TOO_MANY_SESSIONS";
        case STATUS_SHARING_PAUSED:
            return "STATUS_SHARING_PAUSED";
        case STATUS_REQUEST_NOT_ACCEPTED:
            return "STATUS_REQUEST_NOT_ACCEPTED";
        case STATUS_REDIRECTOR_PAUSED:
            return "STATUS_REDIRECTOR_PAUSED";
        case STATUS_NET_WRITE_FAULT:
            return "STATUS_NET_WRITE_FAULT";
        case STATUS_PROFILING_AT_LIMIT:
            return "STATUS_PROFILING_AT_LIMIT";
        case STATUS_NOT_SAME_DEVICE:
            return "STATUS_NOT_SAME_DEVICE";
        case STATUS_FILE_RENAMED:
            return "STATUS_FILE_RENAMED";
        case STATUS_VIRTUAL_CIRCUIT_CLOSED:
            return "STATUS_VIRTUAL_CIRCUIT_CLOSED";
        case STATUS_NO_SECURITY_ON_OBJECT:
            return "STATUS_NO_SECURITY_ON_OBJECT";
        case STATUS_CANT_WAIT:
            return "STATUS_CANT_WAIT";
        case STATUS_PIPE_EMPTY:
            return "STATUS_PIPE_EMPTY";
        case STATUS_CANT_ACCESS_DOMAIN_INFO:
            return "STATUS_CANT_ACCESS_DOMAIN_INFO";
        case STATUS_CANT_TERMINATE_SELF:
            return "STATUS_CANT_TERMINATE_SELF";
        case STATUS_INVALID_SERVER_STATE:
            return "STATUS_INVALID_SERVER_STATE";
        case STATUS_INVALID_DOMAIN_STATE:
            return "STATUS_INVALID_DOMAIN_STATE";
        case STATUS_INVALID_DOMAIN_ROLE:
            return "STATUS_INVALID_DOMAIN_ROLE";
        case STATUS_NO_SUCH_DOMAIN:
            return "STATUS_NO_SUCH_DOMAIN";
        case STATUS_DOMAIN_EXISTS:
            return "STATUS_DOMAIN_EXISTS";
        case STATUS_DOMAIN_LIMIT_EXCEEDED:
            return "STATUS_DOMAIN_LIMIT_EXCEEDED";
        case STATUS_OPLOCK_NOT_GRANTED:
            return "STATUS_OPLOCK_NOT_GRANTED";
        case STATUS_INVALID_OPLOCK_PROTOCOL:
            return "STATUS_INVALID_OPLOCK_PROTOCOL";
        case STATUS_INTERNAL_DB_CORRUPTION:
            return "STATUS_INTERNAL_DB_CORRUPTION";
        case STATUS_INTERNAL_ERROR:
            return "STATUS_INTERNAL_ERROR";
        case STATUS_GENERIC_NOT_MAPPED:
            return "STATUS_GENERIC_NOT_MAPPED";
        case STATUS_BAD_DESCRIPTOR_FORMAT:
            return "STATUS_BAD_DESCRIPTOR_FORMAT";
        case STATUS_INVALID_USER_BUFFER:
            return "STATUS_INVALID_USER_BUFFER";
        case STATUS_UNEXPECTED_IO_ERROR:
            return "STATUS_UNEXPECTED_IO_ERROR";
        case STATUS_UNEXPECTED_MM_CREATE_ERR:
            return "STATUS_UNEXPECTED_MM_CREATE_ERR";
        case STATUS_UNEXPECTED_MM_MAP_ERROR:
            return "STATUS_UNEXPECTED_MM_MAP_ERROR";
        case STATUS_UNEXPECTED_MM_EXTEND_ERR:
            return "STATUS_UNEXPECTED_MM_EXTEND_ERR";
        case STATUS_NOT_LOGON_PROCESS:
            return "STATUS_NOT_LOGON_PROCESS";
        case STATUS_LOGON_SESSION_EXISTS:
            return "STATUS_LOGON_SESSION_EXISTS";
        case STATUS_INVALID_PARAMETER_1:
            return "STATUS_INVALID_PARAMETER_1";
        case STATUS_INVALID_PARAMETER_2:
            return "STATUS_INVALID_PARAMETER_2";
        case STATUS_INVALID_PARAMETER_3:
            return "STATUS_INVALID_PARAMETER_3";
        case STATUS_INVALID_PARAMETER_4:
            return "STATUS_INVALID_PARAMETER_4";
        case STATUS_INVALID_PARAMETER_5:
            return "STATUS_INVALID_PARAMETER_5";
        case STATUS_INVALID_PARAMETER_6:
            return "STATUS_INVALID_PARAMETER_6";
        case STATUS_INVALID_PARAMETER_7:
            return "STATUS_INVALID_PARAMETER_7";
        case STATUS_INVALID_PARAMETER_8:
            return "STATUS_INVALID_PARAMETER_8";
        case STATUS_INVALID_PARAMETER_9:
            return "STATUS_INVALID_PARAMETER_9";
        case STATUS_INVALID_PARAMETER_10:
            return "STATUS_INVALID_PARAMETER_10";
        case STATUS_INVALID_PARAMETER_11:
            return "STATUS_INVALID_PARAMETER_11";
        case STATUS_INVALID_PARAMETER_12:
            return "STATUS_INVALID_PARAMETER_12";
        case STATUS_REDIRECTOR_NOT_STARTED:
            return "STATUS_REDIRECTOR_NOT_STARTED";
        case STATUS_REDIRECTOR_STARTED:
            return "STATUS_REDIRECTOR_STARTED";
        case STATUS_STACK_OVERFLOW:
            return "STATUS_STACK_OVERFLOW";
        case STATUS_NO_SUCH_PACKAGE:
            return "STATUS_NO_SUCH_PACKAGE";
        case STATUS_BAD_FUNCTION_TABLE:
            return "STATUS_BAD_FUNCTION_TABLE";
        case STATUS_VARIABLE_NOT_FOUND:
            return "STATUS_VARIABLE_NOT_FOUND";
        case STATUS_DIRECTORY_NOT_EMPTY:
            return "STATUS_DIRECTORY_NOT_EMPTY";
        case STATUS_FILE_CORRUPT_ERROR:
            return "STATUS_FILE_CORRUPT_ERROR";
        case STATUS_NOT_A_DIRECTORY:
            return "STATUS_NOT_A_DIRECTORY";
        case STATUS_BAD_LOGON_SESSION_STATE:
            return "STATUS_BAD_LOGON_SESSION_STATE";
        case STATUS_LOGON_SESSION_COLLISION:
            return "STATUS_LOGON_SESSION_COLLISION";
        case STATUS_NAME_TOO_LONG:
            return "STATUS_NAME_TOO_LONG";
        case STATUS_FILES_OPEN:
            return "STATUS_FILES_OPEN";
        case STATUS_CONNECTION_IN_USE:
            return "STATUS_CONNECTION_IN_USE";
        case STATUS_MESSAGE_NOT_FOUND:
            return "STATUS_MESSAGE_NOT_FOUND";
        case STATUS_PROCESS_IS_TERMINATING:
            return "STATUS_PROCESS_IS_TERMINATING";
        case STATUS_INVALID_LOGON_TYPE:
            return "STATUS_INVALID_LOGON_TYPE";
        case STATUS_NO_GUID_TRANSLATION:
            return "STATUS_NO_GUID_TRANSLATION";
        case STATUS_CANNOT_IMPERSONATE:
            return "STATUS_CANNOT_IMPERSONATE";
        case STATUS_IMAGE_ALREADY_LOADED:
            return "STATUS_IMAGE_ALREADY_LOADED";
        case STATUS_ABIOS_NOT_PRESENT:
            return "STATUS_ABIOS_NOT_PRESENT";
        case STATUS_ABIOS_LID_NOT_EXIST:
            return "STATUS_ABIOS_LID_NOT_EXIST";
        case STATUS_ABIOS_LID_ALREADY_OWNED:
            return "STATUS_ABIOS_LID_ALREADY_OWNED";
        case STATUS_ABIOS_NOT_LID_OWNER:
            return "STATUS_ABIOS_NOT_LID_OWNER";
        case STATUS_ABIOS_INVALID_COMMAND:
            return "STATUS_ABIOS_INVALID_COMMAND";
        case STATUS_ABIOS_INVALID_LID:
            return "STATUS_ABIOS_INVALID_LID";
        case STATUS_ABIOS_SELECTOR_NOT_AVAILABLE:
            return "STATUS_ABIOS_SELECTOR_NOT_AVAILABLE";
        case STATUS_ABIOS_INVALID_SELECTOR:
            return "STATUS_ABIOS_INVALID_SELECTOR";
        case STATUS_NO_LDT:
            return "STATUS_NO_LDT";
        case STATUS_INVALID_LDT_SIZE:
            return "STATUS_INVALID_LDT_SIZE";
        case STATUS_INVALID_LDT_OFFSET:
            return "STATUS_INVALID_LDT_OFFSET";
        case STATUS_INVALID_LDT_DESCRIPTOR:
            return "STATUS_INVALID_LDT_DESCRIPTOR";
        case STATUS_INVALID_IMAGE_NE_FORMAT:
            return "STATUS_INVALID_IMAGE_NE_FORMAT";
        case STATUS_RXACT_INVALID_STATE:
            return "STATUS_RXACT_INVALID_STATE";
        case STATUS_RXACT_COMMIT_FAILURE:
            return "STATUS_RXACT_COMMIT_FAILURE";
        case STATUS_MAPPED_FILE_SIZE_ZERO:
            return "STATUS_MAPPED_FILE_SIZE_ZERO";
        case STATUS_TOO_MANY_OPENED_FILES:
            return "STATUS_TOO_MANY_OPENED_FILES";
        case STATUS_CANCELLED:
            return "STATUS_CANCELLED";
        case STATUS_CANNOT_DELETE:
            return "STATUS_CANNOT_DELETE";
        case STATUS_INVALID_COMPUTER_NAME:
            return "STATUS_INVALID_COMPUTER_NAME";
        case STATUS_FILE_DELETED:
            return "STATUS_FILE_DELETED";
        case STATUS_SPECIAL_ACCOUNT:
            return "STATUS_SPECIAL_ACCOUNT";
        case STATUS_SPECIAL_GROUP:
            return "STATUS_SPECIAL_GROUP";
        case STATUS_SPECIAL_USER:
            return "STATUS_SPECIAL_USER";
        case STATUS_MEMBERS_PRIMARY_GROUP:
            return "STATUS_MEMBERS_PRIMARY_GROUP";
        case STATUS_FILE_CLOSED:
            return "STATUS_FILE_CLOSED";
        case STATUS_TOO_MANY_THREADS:
            return "STATUS_TOO_MANY_THREADS";
        case STATUS_THREAD_NOT_IN_PROCESS:
            return "STATUS_THREAD_NOT_IN_PROCESS";
        case STATUS_TOKEN_ALREADY_IN_USE:
            return "STATUS_TOKEN_ALREADY_IN_USE";
        case STATUS_PAGEFILE_QUOTA_EXCEEDED:
            return "STATUS_PAGEFILE_QUOTA_EXCEEDED";
        case STATUS_COMMITMENT_LIMIT:
            return "STATUS_COMMITMENT_LIMIT";
        case STATUS_INVALID_IMAGE_LE_FORMAT:
            return "STATUS_INVALID_IMAGE_LE_FORMAT";
        case STATUS_INVALID_IMAGE_NOT_MZ:
            return "STATUS_INVALID_IMAGE_NOT_MZ";
        case STATUS_INVALID_IMAGE_PROTECT:
            return "STATUS_INVALID_IMAGE_PROTECT";
        case STATUS_INVALID_IMAGE_WIN_16:
            return "STATUS_INVALID_IMAGE_WIN_16";
        case STATUS_LOGON_SERVER_CONFLICT:
            return "STATUS_LOGON_SERVER_CONFLICT";
        case STATUS_TIME_DIFFERENCE_AT_DC:
            return "STATUS_TIME_DIFFERENCE_AT_DC";
        case STATUS_SYNCHRONIZATION_REQUIRED:
            return "STATUS_SYNCHRONIZATION_REQUIRED";
        case STATUS_DLL_NOT_FOUND:
            return "STATUS_DLL_NOT_FOUND";
        case STATUS_OPEN_FAILED:
            return "STATUS_OPEN_FAILED";
        case STATUS_IO_PRIVILEGE_FAILED:
            return "STATUS_IO_PRIVILEGE_FAILED";
        case STATUS_ORDINAL_NOT_FOUND:
            return "STATUS_ORDINAL_NOT_FOUND";
        case STATUS_ENTRYPOINT_NOT_FOUND:
            return "STATUS_ENTRYPOINT_NOT_FOUND";
        case STATUS_CONTROL_C_EXIT:
            return "STATUS_CONTROL_C_EXIT";
        case STATUS_LOCAL_DISCONNECT:
            return "STATUS_LOCAL_DISCONNECT";
        case STATUS_REMOTE_DISCONNECT:
            return "STATUS_REMOTE_DISCONNECT";
        case STATUS_REMOTE_RESOURCES:
            return "STATUS_REMOTE_RESOURCES";
        case STATUS_LINK_FAILED:
            return "STATUS_LINK_FAILED";
        case STATUS_LINK_TIMEOUT:
            return "STATUS_LINK_TIMEOUT";
        case STATUS_INVALID_CONNECTION:
            return "STATUS_INVALID_CONNECTION";
        case STATUS_INVALID_ADDRESS:
            return "STATUS_INVALID_ADDRESS";
        case STATUS_DLL_INIT_FAILED:
            return "STATUS_DLL_INIT_FAILED";
        case STATUS_MISSING_SYSTEMFILE:
            return "STATUS_MISSING_SYSTEMFILE";
        case STATUS_UNHANDLED_EXCEPTION:
            return "STATUS_UNHANDLED_EXCEPTION";
        case STATUS_APP_INIT_FAILURE:
            return "STATUS_APP_INIT_FAILURE";
        case STATUS_PAGEFILE_CREATE_FAILED:
            return "STATUS_PAGEFILE_CREATE_FAILED";
        case STATUS_NO_PAGEFILE:
            return "STATUS_NO_PAGEFILE";
        case STATUS_INVALID_LEVEL:
            return "STATUS_INVALID_LEVEL";
        case STATUS_WRONG_PASSWORD_CORE:
            return "STATUS_WRONG_PASSWORD_CORE";
        case STATUS_ILLEGAL_FLOAT_CONTEXT:
            return "STATUS_ILLEGAL_FLOAT_CONTEXT";
        case STATUS_PIPE_BROKEN:
            return "STATUS_PIPE_BROKEN";
        case STATUS_REGISTRY_CORRUPT:
            return "STATUS_REGISTRY_CORRUPT";
        case STATUS_REGISTRY_IO_FAILED:
            return "STATUS_REGISTRY_IO_FAILED";
        case STATUS_NO_EVENT_PAIR:
            return "STATUS_NO_EVENT_PAIR";
        case STATUS_UNRECOGNIZED_VOLUME:
            return "STATUS_UNRECOGNIZED_VOLUME";
        case STATUS_SERIAL_NO_DEVICE_INITED:
            return "STATUS_SERIAL_NO_DEVICE_INITED";
        case STATUS_NO_SUCH_ALIAS:
            return "STATUS_NO_SUCH_ALIAS";
        case STATUS_MEMBER_NOT_IN_ALIAS:
            return "STATUS_MEMBER_NOT_IN_ALIAS";
        case STATUS_MEMBER_IN_ALIAS:
            return "STATUS_MEMBER_IN_ALIAS";
        case STATUS_ALIAS_EXISTS:
            return "STATUS_ALIAS_EXISTS";
        case STATUS_LOGON_NOT_GRANTED:
            return "STATUS_LOGON_NOT_GRANTED";
        case STATUS_TOO_MANY_SECRETS:
            return "STATUS_TOO_MANY_SECRETS";
        case STATUS_SECRET_TOO_LONG:
            return "STATUS_SECRET_TOO_LONG";
        case STATUS_INTERNAL_DB_ERROR:
            return "STATUS_INTERNAL_DB_ERROR";
        case STATUS_FULLSCREEN_MODE:
            return "STATUS_FULLSCREEN_MODE";
        case STATUS_TOO_MANY_CONTEXT_IDS:
            return "STATUS_TOO_MANY_CONTEXT_IDS";
        case STATUS_LOGON_TYPE_NOT_GRANTED:
            return "STATUS_LOGON_TYPE_NOT_GRANTED";
        case STATUS_NOT_REGISTRY_FILE:
            return "STATUS_NOT_REGISTRY_FILE";
        case STATUS_NT_CROSS_ENCRYPTION_REQUIRED:
            return "STATUS_NT_CROSS_ENCRYPTION_REQUIRED";
        case STATUS_DOMAIN_CTRLR_CONFIG_ERROR:
            return "STATUS_DOMAIN_CTRLR_CONFIG_ERROR";
        case STATUS_FT_MISSING_MEMBER:
            return "STATUS_FT_MISSING_MEMBER";
        case STATUS_ILL_FORMED_SERVICE_ENTRY:
            return "STATUS_ILL_FORMED_SERVICE_ENTRY";
        case STATUS_ILLEGAL_CHARACTER:
            return "STATUS_ILLEGAL_CHARACTER";
        case STATUS_UNMAPPABLE_CHARACTER:
            return "STATUS_UNMAPPABLE_CHARACTER";
        case STATUS_UNDEFINED_CHARACTER:
            return "STATUS_UNDEFINED_CHARACTER";
        case STATUS_FLOPPY_VOLUME:
            return "STATUS_FLOPPY_VOLUME";
        case STATUS_FLOPPY_ID_MARK_NOT_FOUND:
            return "STATUS_FLOPPY_ID_MARK_NOT_FOUND";
        case STATUS_FLOPPY_WRONG_CYLINDER:
            return "STATUS_FLOPPY_WRONG_CYLINDER";
        case STATUS_FLOPPY_UNKNOWN_ERROR:
            return "STATUS_FLOPPY_UNKNOWN_ERROR";
        case STATUS_FLOPPY_BAD_REGISTERS:
            return "STATUS_FLOPPY_BAD_REGISTERS";
        case STATUS_DISK_RECALIBRATE_FAILED:
            return "STATUS_DISK_RECALIBRATE_FAILED";
        case STATUS_DISK_OPERATION_FAILED:
            return "STATUS_DISK_OPERATION_FAILED";
        case STATUS_DISK_RESET_FAILED:
            return "STATUS_DISK_RESET_FAILED";
        case STATUS_SHARED_IRQ_BUSY:
            return "STATUS_SHARED_IRQ_BUSY";
        case STATUS_FT_ORPHANING:
            return "STATUS_FT_ORPHANING";
        case STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT:
            return "STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT";
        case STATUS_PARTITION_FAILURE:
            return "STATUS_PARTITION_FAILURE";
        case STATUS_INVALID_BLOCK_LENGTH:
            return "STATUS_INVALID_BLOCK_LENGTH";
        case STATUS_DEVICE_NOT_PARTITIONED:
            return "STATUS_DEVICE_NOT_PARTITIONED";
        case STATUS_UNABLE_TO_LOCK_MEDIA:
            return "STATUS_UNABLE_TO_LOCK_MEDIA";
        case STATUS_UNABLE_TO_UNLOAD_MEDIA:
            return "STATUS_UNABLE_TO_UNLOAD_MEDIA";
        case STATUS_EOM_OVERFLOW:
            return "STATUS_EOM_OVERFLOW";
        case STATUS_NO_MEDIA:
            return "STATUS_NO_MEDIA";
        case STATUS_NO_SUCH_MEMBER:
            return "STATUS_NO_SUCH_MEMBER";
        case STATUS_INVALID_MEMBER:
            return "STATUS_INVALID_MEMBER";
        case STATUS_KEY_DELETED:
            return "STATUS_KEY_DELETED";
        case STATUS_NO_LOG_SPACE:
            return "STATUS_NO_LOG_SPACE";
        case STATUS_TOO_MANY_SIDS:
            return "STATUS_TOO_MANY_SIDS";
        case STATUS_LM_CROSS_ENCRYPTION_REQUIRED:
            return "STATUS_LM_CROSS_ENCRYPTION_REQUIRED";
        case STATUS_KEY_HAS_CHILDREN:
            return "STATUS_KEY_HAS_CHILDREN";
        case STATUS_CHILD_MUST_BE_VOLATILE:
            return "STATUS_CHILD_MUST_BE_VOLATILE";
        case STATUS_DEVICE_CONFIGURATION_ERROR:
            return "STATUS_DEVICE_CONFIGURATION_ERROR";
        case STATUS_DRIVER_INTERNAL_ERROR:
            return "STATUS_DRIVER_INTERNAL_ERROR";
        case STATUS_INVALID_DEVICE_STATE:
            return "STATUS_INVALID_DEVICE_STATE";
        case STATUS_IO_DEVICE_ERROR:
            return "STATUS_IO_DEVICE_ERROR";
        case STATUS_DEVICE_PROTOCOL_ERROR:
            return "STATUS_DEVICE_PROTOCOL_ERROR";
        case STATUS_BACKUP_CONTROLLER:
            return "STATUS_BACKUP_CONTROLLER";
        case STATUS_LOG_FILE_FULL:
            return "STATUS_LOG_FILE_FULL";
        case STATUS_TOO_LATE:
            return "STATUS_TOO_LATE";
        case STATUS_NO_TRUST_LSA_SECRET:
            return "STATUS_NO_TRUST_LSA_SECRET";
        case STATUS_NO_TRUST_SAM_ACCOUNT:
            return "STATUS_NO_TRUST_SAM_ACCOUNT";
        case STATUS_TRUSTED_DOMAIN_FAILURE:
            return "STATUS_TRUSTED_DOMAIN_FAILURE";
        case STATUS_TRUSTED_RELATIONSHIP_FAILURE:
            return "STATUS_TRUSTED_RELATIONSHIP_FAILURE";
        case STATUS_EVENTLOG_FILE_CORRUPT:
            return "STATUS_EVENTLOG_FILE_CORRUPT";
        case STATUS_EVENTLOG_CANT_START:
            return "STATUS_EVENTLOG_CANT_START";
        case STATUS_TRUST_FAILURE:
            return "STATUS_TRUST_FAILURE";
        case STATUS_MUTANT_LIMIT_EXCEEDED:
            return "STATUS_MUTANT_LIMIT_EXCEEDED";
        case STATUS_NETLOGON_NOT_STARTED:
            return "STATUS_NETLOGON_NOT_STARTED";
        case STATUS_ACCOUNT_EXPIRED:
            return "STATUS_ACCOUNT_EXPIRED";
        case STATUS_POSSIBLE_DEADLOCK:
            return "STATUS_POSSIBLE_DEADLOCK";
        case STATUS_NETWORK_CREDENTIAL_CONFLICT:
            return "STATUS_NETWORK_CREDENTIAL_CONFLICT";
        case STATUS_REMOTE_SESSION_LIMIT:
            return "STATUS_REMOTE_SESSION_LIMIT";
        case STATUS_EVENTLOG_FILE_CHANGED:
            return "STATUS_EVENTLOG_FILE_CHANGED";
        case STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT:
            return "STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT";
        case STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT:
            return "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT";
        case STATUS_NOLOGON_SERVER_TRUST_ACCOUNT:
            return "STATUS_NOLOGON_SERVER_TRUST_ACCOUNT";
        case STATUS_DOMAIN_TRUST_INCONSISTENT:
            return "STATUS_DOMAIN_TRUST_INCONSISTENT";
        case STATUS_FS_DRIVER_REQUIRED:
            return "STATUS_FS_DRIVER_REQUIRED";
        case STATUS_IMAGE_ALREADY_LOADED_AS_DLL:
            return "STATUS_IMAGE_ALREADY_LOADED_AS_DLL";
        case STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING:
            return "STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING";
        case STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME:
            return "STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME";
        case STATUS_SECURITY_STREAM_IS_INCONSISTENT:
            return "STATUS_SECURITY_STREAM_IS_INCONSISTENT";
        case STATUS_INVALID_LOCK_RANGE:
            return "STATUS_INVALID_LOCK_RANGE";
        case STATUS_INVALID_ACE_CONDITION:
            return "STATUS_INVALID_ACE_CONDITION";
        case STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT:
            return "STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT";
        case STATUS_NOTIFICATION_GUID_ALREADY_DEFINED:
            return "STATUS_NOTIFICATION_GUID_ALREADY_DEFINED";
        case STATUS_INVALID_EXCEPTION_HANDLER:
            return "STATUS_INVALID_EXCEPTION_HANDLER";
        case STATUS_DUPLICATE_PRIVILEGES:
            return "STATUS_DUPLICATE_PRIVILEGES";
        case STATUS_NOT_ALLOWED_ON_SYSTEM_FILE:
            return "STATUS_NOT_ALLOWED_ON_SYSTEM_FILE";
        case STATUS_REPAIR_NEEDED:
            return "STATUS_REPAIR_NEEDED";
        case STATUS_QUOTA_NOT_ENABLED:
            return "STATUS_QUOTA_NOT_ENABLED";
        case STATUS_NO_APPLICATION_PACKAGE:
            return "STATUS_NO_APPLICATION_PACKAGE";
        case STATUS_FILE_METADATA_OPTIMIZATION_IN_PROGRESS:
            return "STATUS_FILE_METADATA_OPTIMIZATION_IN_PROGRESS";
        case STATUS_NOT_SAME_OBJECT:
            return "STATUS_NOT_SAME_OBJECT";
        case STATUS_FATAL_MEMORY_EXHAUSTION:
            return "STATUS_FATAL_MEMORY_EXHAUSTION";
        case STATUS_ERROR_PROCESS_NOT_IN_JOB:
            return "STATUS_ERROR_PROCESS_NOT_IN_JOB";
        case STATUS_CPU_SET_INVALID:
            return "STATUS_CPU_SET_INVALID";
        case STATUS_IO_DEVICE_INVALID_DATA:
            return "STATUS_IO_DEVICE_INVALID_DATA";
        case STATUS_NETWORK_OPEN_RESTRICTION:
            return "STATUS_NETWORK_OPEN_RESTRICTION";
        case STATUS_NO_USER_SESSION_KEY:
            return "STATUS_NO_USER_SESSION_KEY";
        case STATUS_USER_SESSION_DELETED:
            return "STATUS_USER_SESSION_DELETED";
        case STATUS_RESOURCE_LANG_NOT_FOUND:
            return "STATUS_RESOURCE_LANG_NOT_FOUND";
        case STATUS_INSUFF_SERVER_RESOURCES:
            return "STATUS_INSUFF_SERVER_RESOURCES";
        case STATUS_INVALID_BUFFER_SIZE:
            return "STATUS_INVALID_BUFFER_SIZE";
        case STATUS_INVALID_ADDRESS_COMPONENT:
            return "STATUS_INVALID_ADDRESS_COMPONENT";
        case STATUS_INVALID_ADDRESS_WILDCARD:
            return "STATUS_INVALID_ADDRESS_WILDCARD";
        case STATUS_TOO_MANY_ADDRESSES:
            return "STATUS_TOO_MANY_ADDRESSES";
        case STATUS_ADDRESS_ALREADY_EXISTS:
            return "STATUS_ADDRESS_ALREADY_EXISTS";
        case STATUS_ADDRESS_CLOSED:
            return "STATUS_ADDRESS_CLOSED";
        case STATUS_CONNECTION_DISCONNECTED:
            return "STATUS_CONNECTION_DISCONNECTED";
        case STATUS_CONNECTION_RESET:
            return "STATUS_CONNECTION_RESET";
        case STATUS_TOO_MANY_NODES:
            return "STATUS_TOO_MANY_NODES";
        case STATUS_TRANSACTION_ABORTED:
            return "STATUS_TRANSACTION_ABORTED";
        case STATUS_TRANSACTION_TIMED_OUT:
            return "STATUS_TRANSACTION_TIMED_OUT";
        case STATUS_TRANSACTION_NO_RELEASE:
            return "STATUS_TRANSACTION_NO_RELEASE";
        case STATUS_TRANSACTION_NO_MATCH:
            return "STATUS_TRANSACTION_NO_MATCH";
        case STATUS_TRANSACTION_RESPONDED:
            return "STATUS_TRANSACTION_RESPONDED";
        case STATUS_TRANSACTION_INVALID_ID:
            return "STATUS_TRANSACTION_INVALID_ID";
        case STATUS_TRANSACTION_INVALID_TYPE:
            return "STATUS_TRANSACTION_INVALID_TYPE";
        case STATUS_NOT_SERVER_SESSION:
            return "STATUS_NOT_SERVER_SESSION";
        case STATUS_NOT_CLIENT_SESSION:
            return "STATUS_NOT_CLIENT_SESSION";
        case STATUS_CANNOT_LOAD_REGISTRY_FILE:
            return "STATUS_CANNOT_LOAD_REGISTRY_FILE";
        case STATUS_DEBUG_ATTACH_FAILED:
            return "STATUS_DEBUG_ATTACH_FAILED";
        case STATUS_SYSTEM_PROCESS_TERMINATED:
            return "STATUS_SYSTEM_PROCESS_TERMINATED";
        case STATUS_DATA_NOT_ACCEPTED:
            return "STATUS_DATA_NOT_ACCEPTED";
        case STATUS_NO_BROWSER_SERVERS_FOUND:
            return "STATUS_NO_BROWSER_SERVERS_FOUND";
        case STATUS_VDM_HARD_ERROR:
            return "STATUS_VDM_HARD_ERROR";
        case STATUS_DRIVER_CANCEL_TIMEOUT:
            return "STATUS_DRIVER_CANCEL_TIMEOUT";
        case STATUS_REPLY_MESSAGE_MISMATCH:
            return "STATUS_REPLY_MESSAGE_MISMATCH";
        case STATUS_MAPPED_ALIGNMENT:
            return "STATUS_MAPPED_ALIGNMENT";
        case STATUS_IMAGE_CHECKSUM_MISMATCH:
            return "STATUS_IMAGE_CHECKSUM_MISMATCH";
        case STATUS_LOST_WRITEBEHIND_DATA:
            return "STATUS_LOST_WRITEBEHIND_DATA";
        case STATUS_CLIENT_SERVER_PARAMETERS_INVALID:
            return "STATUS_CLIENT_SERVER_PARAMETERS_INVALID";
        case STATUS_PASSWORD_MUST_CHANGE:
            return "STATUS_PASSWORD_MUST_CHANGE";
        case STATUS_NOT_FOUND:
            return "STATUS_NOT_FOUND";
        case STATUS_NOT_TINY_STREAM:
            return "STATUS_NOT_TINY_STREAM";
        case STATUS_RECOVERY_FAILURE:
            return "STATUS_RECOVERY_FAILURE";
        case STATUS_STACK_OVERFLOW_READ:
            return "STATUS_STACK_OVERFLOW_READ";
        case STATUS_FAIL_CHECK:
            return "STATUS_FAIL_CHECK";
        case STATUS_DUPLICATE_OBJECTID:
            return "STATUS_DUPLICATE_OBJECTID";
        case STATUS_OBJECTID_EXISTS:
            return "STATUS_OBJECTID_EXISTS";
        case STATUS_CONVERT_TO_LARGE:
            return "STATUS_CONVERT_TO_LARGE";
        case STATUS_RETRY:
            return "STATUS_RETRY";
        case STATUS_FOUND_OUT_OF_SCOPE:
            return "STATUS_FOUND_OUT_OF_SCOPE";
        case STATUS_ALLOCATE_BUCKET:
            return "STATUS_ALLOCATE_BUCKET";
        case STATUS_PROPSET_NOT_FOUND:
            return "STATUS_PROPSET_NOT_FOUND";
        case STATUS_MARSHALL_OVERFLOW:
            return "STATUS_MARSHALL_OVERFLOW";
        case STATUS_INVALID_VARIANT:
            return "STATUS_INVALID_VARIANT";
        case STATUS_DOMAIN_CONTROLLER_NOT_FOUND:
            return "STATUS_DOMAIN_CONTROLLER_NOT_FOUND";
        case STATUS_ACCOUNT_LOCKED_OUT:
            return "STATUS_ACCOUNT_LOCKED_OUT";
        case STATUS_HANDLE_NOT_CLOSABLE:
            return "STATUS_HANDLE_NOT_CLOSABLE";
        case STATUS_CONNECTION_REFUSED:
            return "STATUS_CONNECTION_REFUSED";
        case STATUS_GRACEFUL_DISCONNECT:
            return "STATUS_GRACEFUL_DISCONNECT";
        case STATUS_ADDRESS_ALREADY_ASSOCIATED:
            return "STATUS_ADDRESS_ALREADY_ASSOCIATED";
        case STATUS_ADDRESS_NOT_ASSOCIATED:
            return "STATUS_ADDRESS_NOT_ASSOCIATED";
        case STATUS_CONNECTION_INVALID:
            return "STATUS_CONNECTION_INVALID";
        case STATUS_CONNECTION_ACTIVE:
            return "STATUS_CONNECTION_ACTIVE";
        case STATUS_NETWORK_UNREACHABLE:
            return "STATUS_NETWORK_UNREACHABLE";
        case STATUS_HOST_UNREACHABLE:
            return "STATUS_HOST_UNREACHABLE";
        case STATUS_PROTOCOL_UNREACHABLE:
            return "STATUS_PROTOCOL_UNREACHABLE";
        case STATUS_PORT_UNREACHABLE:
            return "STATUS_PORT_UNREACHABLE";
        case STATUS_REQUEST_ABORTED:
            return "STATUS_REQUEST_ABORTED";
        case STATUS_CONNECTION_ABORTED:
            return "STATUS_CONNECTION_ABORTED";
        case STATUS_BAD_COMPRESSION_BUFFER:
            return "STATUS_BAD_COMPRESSION_BUFFER";
        case STATUS_USER_MAPPED_FILE:
            return "STATUS_USER_MAPPED_FILE";
        case STATUS_AUDIT_FAILED:
            return "STATUS_AUDIT_FAILED";
        case STATUS_TIMER_RESOLUTION_NOT_SET:
            return "STATUS_TIMER_RESOLUTION_NOT_SET";
        case STATUS_CONNECTION_COUNT_LIMIT:
            return "STATUS_CONNECTION_COUNT_LIMIT";
        case STATUS_LOGIN_TIME_RESTRICTION:
            return "STATUS_LOGIN_TIME_RESTRICTION";
        case STATUS_LOGIN_WKSTA_RESTRICTION:
            return "STATUS_LOGIN_WKSTA_RESTRICTION";
        case STATUS_IMAGE_MP_UP_MISMATCH:
            return "STATUS_IMAGE_MP_UP_MISMATCH";
        case STATUS_INSUFFICIENT_LOGON_INFO:
            return "STATUS_INSUFFICIENT_LOGON_INFO";
        case STATUS_BAD_DLL_ENTRYPOINT:
            return "STATUS_BAD_DLL_ENTRYPOINT";
        case STATUS_BAD_SERVICE_ENTRYPOINT:
            return "STATUS_BAD_SERVICE_ENTRYPOINT";
        case STATUS_LPC_REPLY_LOST:
            return "STATUS_LPC_REPLY_LOST";
        case STATUS_IP_ADDRESS_CONFLICT1:
            return "STATUS_IP_ADDRESS_CONFLICT1";
        case STATUS_IP_ADDRESS_CONFLICT2:
            return "STATUS_IP_ADDRESS_CONFLICT2";
        case STATUS_REGISTRY_QUOTA_LIMIT:
            return "STATUS_REGISTRY_QUOTA_LIMIT";
        case STATUS_PATH_NOT_COVERED:
            return "STATUS_PATH_NOT_COVERED";
        case STATUS_NO_CALLBACK_ACTIVE:
            return "STATUS_NO_CALLBACK_ACTIVE";
        case STATUS_LICENSE_QUOTA_EXCEEDED:
            return "STATUS_LICENSE_QUOTA_EXCEEDED";
        case STATUS_PWD_TOO_SHORT:
            return "STATUS_PWD_TOO_SHORT";
        case STATUS_PWD_TOO_RECENT:
            return "STATUS_PWD_TOO_RECENT";
        case STATUS_PWD_HISTORY_CONFLICT:
            return "STATUS_PWD_HISTORY_CONFLICT";
        case STATUS_PLUGPLAY_NO_DEVICE:
            return "STATUS_PLUGPLAY_NO_DEVICE";
        case STATUS_UNSUPPORTED_COMPRESSION:
            return "STATUS_UNSUPPORTED_COMPRESSION";
        case STATUS_INVALID_HW_PROFILE:
            return "STATUS_INVALID_HW_PROFILE";
        case STATUS_INVALID_PLUGPLAY_DEVICE_PATH:
            return "STATUS_INVALID_PLUGPLAY_DEVICE_PATH";
        case STATUS_DRIVER_ORDINAL_NOT_FOUND:
            return "STATUS_DRIVER_ORDINAL_NOT_FOUND";
        case STATUS_DRIVER_ENTRYPOINT_NOT_FOUND:
            return "STATUS_DRIVER_ENTRYPOINT_NOT_FOUND";
        case STATUS_RESOURCE_NOT_OWNED:
            return "STATUS_RESOURCE_NOT_OWNED";
        case STATUS_TOO_MANY_LINKS:
            return "STATUS_TOO_MANY_LINKS";
        case STATUS_QUOTA_LIST_INCONSISTENT:
            return "STATUS_QUOTA_LIST_INCONSISTENT";
        case STATUS_FILE_IS_OFFLINE:
            return "STATUS_FILE_IS_OFFLINE";
        case STATUS_EVALUATION_EXPIRATION:
            return "STATUS_EVALUATION_EXPIRATION";
        case STATUS_ILLEGAL_DLL_RELOCATION:
            return "STATUS_ILLEGAL_DLL_RELOCATION";
        case STATUS_LICENSE_VIOLATION:
            return "STATUS_LICENSE_VIOLATION";
        case STATUS_DLL_INIT_FAILED_LOGOFF:
            return "STATUS_DLL_INIT_FAILED_LOGOFF";
        case STATUS_DRIVER_UNABLE_TO_LOAD:
            return "STATUS_DRIVER_UNABLE_TO_LOAD";
        case STATUS_DFS_UNAVAILABLE:
            return "STATUS_DFS_UNAVAILABLE";
        case STATUS_VOLUME_DISMOUNTED:
            return "STATUS_VOLUME_DISMOUNTED";
        case STATUS_WX86_INTERNAL_ERROR:
            return "STATUS_WX86_INTERNAL_ERROR";
        case STATUS_WX86_FLOAT_STACK_CHECK:
            return "STATUS_WX86_FLOAT_STACK_CHECK";
        case STATUS_VALIDATE_CONTINUE:
            return "STATUS_VALIDATE_CONTINUE";
        case STATUS_NO_MATCH:
            return "STATUS_NO_MATCH";
        case STATUS_NO_MORE_MATCHES:
            return "STATUS_NO_MORE_MATCHES";
        case STATUS_NOT_A_REPARSE_POINT:
            return "STATUS_NOT_A_REPARSE_POINT";
        case STATUS_IO_REPARSE_TAG_INVALID:
            return "STATUS_IO_REPARSE_TAG_INVALID";
        case STATUS_IO_REPARSE_TAG_MISMATCH:
            return "STATUS_IO_REPARSE_TAG_MISMATCH";
        case STATUS_IO_REPARSE_DATA_INVALID:
            return "STATUS_IO_REPARSE_DATA_INVALID";
        case STATUS_IO_REPARSE_TAG_NOT_HANDLED:
            return "STATUS_IO_REPARSE_TAG_NOT_HANDLED";
        case STATUS_PWD_TOO_LONG:
            return "STATUS_PWD_TOO_LONG";
        case STATUS_STOWED_EXCEPTION:
            return "STATUS_STOWED_EXCEPTION";
        case STATUS_CONTEXT_STOWED_EXCEPTION:
            return "STATUS_CONTEXT_STOWED_EXCEPTION";
        case STATUS_REPARSE_POINT_NOT_RESOLVED:
            return "STATUS_REPARSE_POINT_NOT_RESOLVED";
        case STATUS_DIRECTORY_IS_A_REPARSE_POINT:
            return "STATUS_DIRECTORY_IS_A_REPARSE_POINT";
        case STATUS_RANGE_LIST_CONFLICT:
            return "STATUS_RANGE_LIST_CONFLICT";
        case STATUS_SOURCE_ELEMENT_EMPTY:
            return "STATUS_SOURCE_ELEMENT_EMPTY";
        case STATUS_DESTINATION_ELEMENT_FULL:
            return "STATUS_DESTINATION_ELEMENT_FULL";
        case STATUS_ILLEGAL_ELEMENT_ADDRESS:
            return "STATUS_ILLEGAL_ELEMENT_ADDRESS";
        case STATUS_MAGAZINE_NOT_PRESENT:
            return "STATUS_MAGAZINE_NOT_PRESENT";
        case STATUS_REINITIALIZATION_NEEDED:
            return "STATUS_REINITIALIZATION_NEEDED";
        case STATUS_DEVICE_REQUIRES_CLEANING:
            return "STATUS_DEVICE_REQUIRES_CLEANING";
        case STATUS_DEVICE_DOOR_OPEN:
            return "STATUS_DEVICE_DOOR_OPEN";
        case STATUS_ENCRYPTION_FAILED:
            return "STATUS_ENCRYPTION_FAILED";
        case STATUS_DECRYPTION_FAILED:
            return "STATUS_DECRYPTION_FAILED";
        case STATUS_RANGE_NOT_FOUND:
            return "STATUS_RANGE_NOT_FOUND";
        case STATUS_NO_RECOVERY_POLICY:
            return "STATUS_NO_RECOVERY_POLICY";
        case STATUS_NO_EFS:
            return "STATUS_NO_EFS";
        case STATUS_WRONG_EFS:
            return "STATUS_WRONG_EFS";
        case STATUS_NO_USER_KEYS:
            return "STATUS_NO_USER_KEYS";
        case STATUS_FILE_NOT_ENCRYPTED:
            return "STATUS_FILE_NOT_ENCRYPTED";
        case STATUS_NOT_EXPORT_FORMAT:
            return "STATUS_NOT_EXPORT_FORMAT";
        case STATUS_FILE_ENCRYPTED:
            return "STATUS_FILE_ENCRYPTED";
        case STATUS_WAKE_SYSTEM:
            return "STATUS_WAKE_SYSTEM";
        case STATUS_WMI_GUID_NOT_FOUND:
            return "STATUS_WMI_GUID_NOT_FOUND";
        case STATUS_WMI_INSTANCE_NOT_FOUND:
            return "STATUS_WMI_INSTANCE_NOT_FOUND";
        case STATUS_WMI_ITEMID_NOT_FOUND:
            return "STATUS_WMI_ITEMID_NOT_FOUND";
        case STATUS_WMI_TRY_AGAIN:
            return "STATUS_WMI_TRY_AGAIN";
        case STATUS_SHARED_POLICY:
            return "STATUS_SHARED_POLICY";
        case STATUS_POLICY_OBJECT_NOT_FOUND:
            return "STATUS_POLICY_OBJECT_NOT_FOUND";
        case STATUS_POLICY_ONLY_IN_DS:
            return "STATUS_POLICY_ONLY_IN_DS";
        case STATUS_VOLUME_NOT_UPGRADED:
            return "STATUS_VOLUME_NOT_UPGRADED";
        case STATUS_REMOTE_STORAGE_NOT_ACTIVE:
            return "STATUS_REMOTE_STORAGE_NOT_ACTIVE";
        case STATUS_REMOTE_STORAGE_MEDIA_ERROR:
            return "STATUS_REMOTE_STORAGE_MEDIA_ERROR";
        case STATUS_NO_TRACKING_SERVICE:
            return "STATUS_NO_TRACKING_SERVICE";
        case STATUS_SERVER_SID_MISMATCH:
            return "STATUS_SERVER_SID_MISMATCH";
        case STATUS_DS_NO_ATTRIBUTE_OR_VALUE:
            return "STATUS_DS_NO_ATTRIBUTE_OR_VALUE";
        case STATUS_DS_INVALID_ATTRIBUTE_SYNTAX:
            return "STATUS_DS_INVALID_ATTRIBUTE_SYNTAX";
        case STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED:
            return "STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED";
        case STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS:
            return "STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS";
        case STATUS_DS_BUSY:
            return "STATUS_DS_BUSY";
        case STATUS_DS_UNAVAILABLE:
            return "STATUS_DS_UNAVAILABLE";
        case STATUS_DS_NO_RIDS_ALLOCATED:
            return "STATUS_DS_NO_RIDS_ALLOCATED";
        case STATUS_DS_NO_MORE_RIDS:
            return "STATUS_DS_NO_MORE_RIDS";
        case STATUS_DS_INCORRECT_ROLE_OWNER:
            return "STATUS_DS_INCORRECT_ROLE_OWNER";
        case STATUS_DS_RIDMGR_INIT_ERROR:
            return "STATUS_DS_RIDMGR_INIT_ERROR";
        case STATUS_DS_OBJ_CLASS_VIOLATION:
            return "STATUS_DS_OBJ_CLASS_VIOLATION";
        case STATUS_DS_CANT_ON_NON_LEAF:
            return "STATUS_DS_CANT_ON_NON_LEAF";
        case STATUS_DS_CANT_ON_RDN:
            return "STATUS_DS_CANT_ON_RDN";
        case STATUS_DS_CANT_MOD_OBJ_CLASS:
            return "STATUS_DS_CANT_MOD_OBJ_CLASS";
        case STATUS_DS_CROSS_DOM_MOVE_FAILED:
            return "STATUS_DS_CROSS_DOM_MOVE_FAILED";
        case STATUS_DS_GC_NOT_AVAILABLE:
            return "STATUS_DS_GC_NOT_AVAILABLE";
        case STATUS_DIRECTORY_SERVICE_REQUIRED:
            return "STATUS_DIRECTORY_SERVICE_REQUIRED";
        case STATUS_REPARSE_ATTRIBUTE_CONFLICT:
            return "STATUS_REPARSE_ATTRIBUTE_CONFLICT";
        case STATUS_CANT_ENABLE_DENY_ONLY:
            return "STATUS_CANT_ENABLE_DENY_ONLY";
        case STATUS_FLOAT_MULTIPLE_FAULTS:
            return "STATUS_FLOAT_MULTIPLE_FAULTS";
        case STATUS_FLOAT_MULTIPLE_TRAPS:
            return "STATUS_FLOAT_MULTIPLE_TRAPS";
        case STATUS_DEVICE_REMOVED:
            return "STATUS_DEVICE_REMOVED";
        case STATUS_JOURNAL_DELETE_IN_PROGRESS:
            return "STATUS_JOURNAL_DELETE_IN_PROGRESS";
        case STATUS_JOURNAL_NOT_ACTIVE:
            return "STATUS_JOURNAL_NOT_ACTIVE";
        case STATUS_NOINTERFACE:
            return "STATUS_NOINTERFACE";
        case STATUS_DS_RIDMGR_DISABLED:
            return "STATUS_DS_RIDMGR_DISABLED";
        case STATUS_DS_ADMIN_LIMIT_EXCEEDED:
            return "STATUS_DS_ADMIN_LIMIT_EXCEEDED";
        case STATUS_DRIVER_FAILED_SLEEP:
            return "STATUS_DRIVER_FAILED_SLEEP";
        case STATUS_MUTUAL_AUTHENTICATION_FAILED:
            return "STATUS_MUTUAL_AUTHENTICATION_FAILED";
        case STATUS_CORRUPT_SYSTEM_FILE:
            return "STATUS_CORRUPT_SYSTEM_FILE";
        case STATUS_DATATYPE_MISALIGNMENT_ERROR:
            return "STATUS_DATATYPE_MISALIGNMENT_ERROR";
        case STATUS_WMI_READ_ONLY:
            return "STATUS_WMI_READ_ONLY";
        case STATUS_WMI_SET_FAILURE:
            return "STATUS_WMI_SET_FAILURE";
        case STATUS_COMMITMENT_MINIMUM:
            return "STATUS_COMMITMENT_MINIMUM";
        case STATUS_REG_NAT_CONSUMPTION:
            return "STATUS_REG_NAT_CONSUMPTION";
        case STATUS_TRANSPORT_FULL:
            return "STATUS_TRANSPORT_FULL";
        case STATUS_DS_SAM_INIT_FAILURE:
            return "STATUS_DS_SAM_INIT_FAILURE";
        case STATUS_ONLY_IF_CONNECTED:
            return "STATUS_ONLY_IF_CONNECTED";
        case STATUS_DS_SENSITIVE_GROUP_VIOLATION:
            return "STATUS_DS_SENSITIVE_GROUP_VIOLATION";
        case STATUS_PNP_RESTART_ENUMERATION:
            return "STATUS_PNP_RESTART_ENUMERATION";
        case STATUS_JOURNAL_ENTRY_DELETED:
            return "STATUS_JOURNAL_ENTRY_DELETED";
        case STATUS_DS_CANT_MOD_PRIMARYGROUPID:
            return "STATUS_DS_CANT_MOD_PRIMARYGROUPID";
        case STATUS_SYSTEM_IMAGE_BAD_SIGNATURE:
            return "STATUS_SYSTEM_IMAGE_BAD_SIGNATURE";
        case STATUS_PNP_REBOOT_REQUIRED:
            return "STATUS_PNP_REBOOT_REQUIRED";
        case STATUS_POWER_STATE_INVALID:
            return "STATUS_POWER_STATE_INVALID";
        case STATUS_DS_INVALID_GROUP_TYPE:
            return "STATUS_DS_INVALID_GROUP_TYPE";
        case STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN:
            return "STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN";
        case STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN:
            return "STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN";
        case STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER:
            return "STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER";
        case STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER:
            return "STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER";
        case STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER:
            return "STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER";
        case STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER:
            return "STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER";
        case STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER:
            return "STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER";
        case STATUS_DS_HAVE_PRIMARY_MEMBERS:
            return "STATUS_DS_HAVE_PRIMARY_MEMBERS";
        case STATUS_WMI_NOT_SUPPORTED:
            return "STATUS_WMI_NOT_SUPPORTED";
        case STATUS_INSUFFICIENT_POWER:
            return "STATUS_INSUFFICIENT_POWER";
        case STATUS_SAM_NEED_BOOTKEY_PASSWORD:
            return "STATUS_SAM_NEED_BOOTKEY_PASSWORD";
        case STATUS_SAM_NEED_BOOTKEY_FLOPPY:
            return "STATUS_SAM_NEED_BOOTKEY_FLOPPY";
        case STATUS_DS_CANT_START:
            return "STATUS_DS_CANT_START";
        case STATUS_DS_INIT_FAILURE:
            return "STATUS_DS_INIT_FAILURE";
        case STATUS_SAM_INIT_FAILURE:
            return "STATUS_SAM_INIT_FAILURE";
        case STATUS_DS_GC_REQUIRED:
            return "STATUS_DS_GC_REQUIRED";
        case STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY:
            return "STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY";
        case STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS:
            return "STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS";
        case STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED:
            return "STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED";
        case STATUS_MULTIPLE_FAULT_VIOLATION:
            return "STATUS_MULTIPLE_FAULT_VIOLATION";
        case STATUS_CURRENT_DOMAIN_NOT_ALLOWED:
            return "STATUS_CURRENT_DOMAIN_NOT_ALLOWED";
        case STATUS_CANNOT_MAKE:
            return "STATUS_CANNOT_MAKE";
        case STATUS_SYSTEM_SHUTDOWN:
            return "STATUS_SYSTEM_SHUTDOWN";
        case STATUS_DS_INIT_FAILURE_CONSOLE:
            return "STATUS_DS_INIT_FAILURE_CONSOLE";
        case STATUS_DS_SAM_INIT_FAILURE_CONSOLE:
            return "STATUS_DS_SAM_INIT_FAILURE_CONSOLE";
        case STATUS_UNFINISHED_CONTEXT_DELETED:
            return "STATUS_UNFINISHED_CONTEXT_DELETED";
        case STATUS_NO_TGT_REPLY:
            return "STATUS_NO_TGT_REPLY";
        case STATUS_OBJECTID_NOT_FOUND:
            return "STATUS_OBJECTID_NOT_FOUND";
        case STATUS_NO_IP_ADDRESSES:
            return "STATUS_NO_IP_ADDRESSES";
        case STATUS_WRONG_CREDENTIAL_HANDLE:
            return "STATUS_WRONG_CREDENTIAL_HANDLE";
        case STATUS_CRYPTO_SYSTEM_INVALID:
            return "STATUS_CRYPTO_SYSTEM_INVALID";
        case STATUS_MAX_REFERRALS_EXCEEDED:
            return "STATUS_MAX_REFERRALS_EXCEEDED";
        case STATUS_MUST_BE_KDC:
            return "STATUS_MUST_BE_KDC";
        case STATUS_STRONG_CRYPTO_NOT_SUPPORTED:
            return "STATUS_STRONG_CRYPTO_NOT_SUPPORTED";
        case STATUS_TOO_MANY_PRINCIPALS:
            return "STATUS_TOO_MANY_PRINCIPALS";
        case STATUS_NO_PA_DATA:
            return "STATUS_NO_PA_DATA";
        case STATUS_PKINIT_NAME_MISMATCH:
            return "STATUS_PKINIT_NAME_MISMATCH";
        case STATUS_SMARTCARD_LOGON_REQUIRED:
            return "STATUS_SMARTCARD_LOGON_REQUIRED";
        case STATUS_KDC_INVALID_REQUEST:
            return "STATUS_KDC_INVALID_REQUEST";
        case STATUS_KDC_UNABLE_TO_REFER:
            return "STATUS_KDC_UNABLE_TO_REFER";
        case STATUS_KDC_UNKNOWN_ETYPE:
            return "STATUS_KDC_UNKNOWN_ETYPE";
        case STATUS_SHUTDOWN_IN_PROGRESS:
            return "STATUS_SHUTDOWN_IN_PROGRESS";
        case STATUS_SERVER_SHUTDOWN_IN_PROGRESS:
            return "STATUS_SERVER_SHUTDOWN_IN_PROGRESS";
        case STATUS_NOT_SUPPORTED_ON_SBS:
            return "STATUS_NOT_SUPPORTED_ON_SBS";
        case STATUS_WMI_GUID_DISCONNECTED:
            return "STATUS_WMI_GUID_DISCONNECTED";
        case STATUS_WMI_ALREADY_DISABLED:
            return "STATUS_WMI_ALREADY_DISABLED";
        case STATUS_WMI_ALREADY_ENABLED:
            return "STATUS_WMI_ALREADY_ENABLED";
        case STATUS_MFT_TOO_FRAGMENTED:
            return "STATUS_MFT_TOO_FRAGMENTED";
        case STATUS_COPY_PROTECTION_FAILURE:
            return "STATUS_COPY_PROTECTION_FAILURE";
        case STATUS_CSS_AUTHENTICATION_FAILURE:
            return "STATUS_CSS_AUTHENTICATION_FAILURE";
        case STATUS_CSS_KEY_NOT_PRESENT:
            return "STATUS_CSS_KEY_NOT_PRESENT";
        case STATUS_CSS_KEY_NOT_ESTABLISHED:
            return "STATUS_CSS_KEY_NOT_ESTABLISHED";
        case STATUS_CSS_SCRAMBLED_SECTOR:
            return "STATUS_CSS_SCRAMBLED_SECTOR";
        case STATUS_CSS_REGION_MISMATCH:
            return "STATUS_CSS_REGION_MISMATCH";
        case STATUS_CSS_RESETS_EXHAUSTED:
            return "STATUS_CSS_RESETS_EXHAUSTED";
        case STATUS_PASSWORD_CHANGE_REQUIRED:
            return "STATUS_PASSWORD_CHANGE_REQUIRED";
        case STATUS_LOST_MODE_LOGON_RESTRICTION:
            return "STATUS_LOST_MODE_LOGON_RESTRICTION";
        case STATUS_PKINIT_FAILURE:
            return "STATUS_PKINIT_FAILURE";
        case STATUS_SMARTCARD_SUBSYSTEM_FAILURE:
            return "STATUS_SMARTCARD_SUBSYSTEM_FAILURE";
        case STATUS_NO_KERB_KEY:
            return "STATUS_NO_KERB_KEY";
        case STATUS_HOST_DOWN:
            return "STATUS_HOST_DOWN";
        case STATUS_UNSUPPORTED_PREAUTH:
            return "STATUS_UNSUPPORTED_PREAUTH";
        case STATUS_EFS_ALG_BLOB_TOO_BIG:
            return "STATUS_EFS_ALG_BLOB_TOO_BIG";
        case STATUS_PORT_NOT_SET:
            return "STATUS_PORT_NOT_SET";
        case STATUS_DEBUGGER_INACTIVE:
            return "STATUS_DEBUGGER_INACTIVE";
        case STATUS_DS_VERSION_CHECK_FAILURE:
            return "STATUS_DS_VERSION_CHECK_FAILURE";
        case STATUS_AUDITING_DISABLED:
            return "STATUS_AUDITING_DISABLED";
        case STATUS_PRENT4_MACHINE_ACCOUNT:
            return "STATUS_PRENT4_MACHINE_ACCOUNT";
        case STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER:
            return "STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER";
        case STATUS_INVALID_IMAGE_WIN_32:
            return "STATUS_INVALID_IMAGE_WIN_32";
        case STATUS_INVALID_IMAGE_WIN_64:
            return "STATUS_INVALID_IMAGE_WIN_64";
        case STATUS_BAD_BINDINGS:
            return "STATUS_BAD_BINDINGS";
        case STATUS_NETWORK_SESSION_EXPIRED:
            return "STATUS_NETWORK_SESSION_EXPIRED";
        case STATUS_APPHELP_BLOCK:
            return "STATUS_APPHELP_BLOCK";
        case STATUS_ALL_SIDS_FILTERED:
            return "STATUS_ALL_SIDS_FILTERED";
        case STATUS_NOT_SAFE_MODE_DRIVER:
            return "STATUS_NOT_SAFE_MODE_DRIVER";
        case STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT:
            return "STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT";
        case STATUS_ACCESS_DISABLED_BY_POLICY_PATH:
            return "STATUS_ACCESS_DISABLED_BY_POLICY_PATH";
        case STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER:
            return "STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER";
        case STATUS_ACCESS_DISABLED_BY_POLICY_OTHER:
            return "STATUS_ACCESS_DISABLED_BY_POLICY_OTHER";
        case STATUS_FAILED_DRIVER_ENTRY:
            return "STATUS_FAILED_DRIVER_ENTRY";
        case STATUS_DEVICE_ENUMERATION_ERROR:
            return "STATUS_DEVICE_ENUMERATION_ERROR";
        case STATUS_MOUNT_POINT_NOT_RESOLVED:
            return "STATUS_MOUNT_POINT_NOT_RESOLVED";
        case STATUS_INVALID_DEVICE_OBJECT_PARAMETER:
            return "STATUS_INVALID_DEVICE_OBJECT_PARAMETER";
        case STATUS_MCA_OCCURED:
            return "STATUS_MCA_OCCURED";
        case STATUS_DRIVER_BLOCKED_CRITICAL:
            return "STATUS_DRIVER_BLOCKED_CRITICAL";
        case STATUS_DRIVER_BLOCKED:
            return "STATUS_DRIVER_BLOCKED";
        case STATUS_DRIVER_DATABASE_ERROR:
            return "STATUS_DRIVER_DATABASE_ERROR";
        case STATUS_SYSTEM_HIVE_TOO_LARGE:
            return "STATUS_SYSTEM_HIVE_TOO_LARGE";
        case STATUS_INVALID_IMPORT_OF_NON_DLL:
            return "STATUS_INVALID_IMPORT_OF_NON_DLL";
        case STATUS_DS_SHUTTING_DOWN:
            return "STATUS_DS_SHUTTING_DOWN";
        case STATUS_NO_SECRETS:
            return "STATUS_NO_SECRETS";
        case STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY:
            return "STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY";
        case STATUS_FAILED_STACK_SWITCH:
            return "STATUS_FAILED_STACK_SWITCH";
        case STATUS_HEAP_CORRUPTION:
            return "STATUS_HEAP_CORRUPTION";
        case STATUS_SMARTCARD_WRONG_PIN:
            return "STATUS_SMARTCARD_WRONG_PIN";
        case STATUS_SMARTCARD_CARD_BLOCKED:
            return "STATUS_SMARTCARD_CARD_BLOCKED";
        case STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED:
            return "STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED";
        case STATUS_SMARTCARD_NO_CARD:
            return "STATUS_SMARTCARD_NO_CARD";
        case STATUS_SMARTCARD_NO_KEY_CONTAINER:
            return "STATUS_SMARTCARD_NO_KEY_CONTAINER";
        case STATUS_SMARTCARD_NO_CERTIFICATE:
            return "STATUS_SMARTCARD_NO_CERTIFICATE";
        case STATUS_SMARTCARD_NO_KEYSET:
            return "STATUS_SMARTCARD_NO_KEYSET";
        case STATUS_SMARTCARD_IO_ERROR:
            return "STATUS_SMARTCARD_IO_ERROR";
        case STATUS_DOWNGRADE_DETECTED:
            return "STATUS_DOWNGRADE_DETECTED";
        case STATUS_SMARTCARD_CERT_REVOKED:
            return "STATUS_SMARTCARD_CERT_REVOKED";
        case STATUS_ISSUING_CA_UNTRUSTED:
            return "STATUS_ISSUING_CA_UNTRUSTED";
        case STATUS_REVOCATION_OFFLINE_C:
            return "STATUS_REVOCATION_OFFLINE_C";
        case STATUS_PKINIT_CLIENT_FAILURE:
            return "STATUS_PKINIT_CLIENT_FAILURE";
        case STATUS_SMARTCARD_CERT_EXPIRED:
            return "STATUS_SMARTCARD_CERT_EXPIRED";
        case STATUS_DRIVER_FAILED_PRIOR_UNLOAD:
            return "STATUS_DRIVER_FAILED_PRIOR_UNLOAD";
        case STATUS_SMARTCARD_SILENT_CONTEXT:
            return "STATUS_SMARTCARD_SILENT_CONTEXT";
        case STATUS_PER_USER_TRUST_QUOTA_EXCEEDED:
            return "STATUS_PER_USER_TRUST_QUOTA_EXCEEDED";
        case STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED:
            return "STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED";
        case STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED:
            return "STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED";
        case STATUS_DS_NAME_NOT_UNIQUE:
            return "STATUS_DS_NAME_NOT_UNIQUE";
        case STATUS_DS_DUPLICATE_ID_FOUND:
            return "STATUS_DS_DUPLICATE_ID_FOUND";
        case STATUS_DS_GROUP_CONVERSION_ERROR:
            return "STATUS_DS_GROUP_CONVERSION_ERROR";
        case STATUS_VOLSNAP_PREPARE_HIBERNATE:
            return "STATUS_VOLSNAP_PREPARE_HIBERNATE";
        case STATUS_USER2USER_REQUIRED:
            return "STATUS_USER2USER_REQUIRED";
        case STATUS_STACK_BUFFER_OVERRUN:
            return "STATUS_STACK_BUFFER_OVERRUN";
        case STATUS_NO_S4U_PROT_SUPPORT:
            return "STATUS_NO_S4U_PROT_SUPPORT";
        case STATUS_CROSSREALM_DELEGATION_FAILURE:
            return "STATUS_CROSSREALM_DELEGATION_FAILURE";
        case STATUS_REVOCATION_OFFLINE_KDC:
            return "STATUS_REVOCATION_OFFLINE_KDC";
        case STATUS_ISSUING_CA_UNTRUSTED_KDC:
            return "STATUS_ISSUING_CA_UNTRUSTED_KDC";
        case STATUS_KDC_CERT_EXPIRED:
            return "STATUS_KDC_CERT_EXPIRED";
        case STATUS_KDC_CERT_REVOKED:
            return "STATUS_KDC_CERT_REVOKED";
        case STATUS_PARAMETER_QUOTA_EXCEEDED:
            return "STATUS_PARAMETER_QUOTA_EXCEEDED";
        case STATUS_HIBERNATION_FAILURE:
            return "STATUS_HIBERNATION_FAILURE";
        case STATUS_DELAY_LOAD_FAILED:
            return "STATUS_DELAY_LOAD_FAILED";
        case STATUS_AUTHENTICATION_FIREWALL_FAILED:
            return "STATUS_AUTHENTICATION_FIREWALL_FAILED";
        case STATUS_VDM_DISALLOWED:
            return "STATUS_VDM_DISALLOWED";
        case STATUS_HUNG_DISPLAY_DRIVER_THREAD:
            return "STATUS_HUNG_DISPLAY_DRIVER_THREAD";
        case STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE:
            return "STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE";
        case STATUS_INVALID_CRUNTIME_PARAMETER:
            return "STATUS_INVALID_CRUNTIME_PARAMETER";
        case STATUS_NTLM_BLOCKED:
            return "STATUS_NTLM_BLOCKED";
        case STATUS_DS_SRC_SID_EXISTS_IN_FOREST:
            return "STATUS_DS_SRC_SID_EXISTS_IN_FOREST";
        case STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST:
            return "STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST";
        case STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST:
            return "STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST";
        case STATUS_INVALID_USER_PRINCIPAL_NAME:
            return "STATUS_INVALID_USER_PRINCIPAL_NAME";
        case STATUS_FATAL_USER_CALLBACK_EXCEPTION:
            return "STATUS_FATAL_USER_CALLBACK_EXCEPTION";
        case STATUS_ASSERTION_FAILURE:
            return "STATUS_ASSERTION_FAILURE";
        case STATUS_VERIFIER_STOP:
            return "STATUS_VERIFIER_STOP";
        case STATUS_CALLBACK_POP_STACK:
            return "STATUS_CALLBACK_POP_STACK";
        case STATUS_INCOMPATIBLE_DRIVER_BLOCKED:
            return "STATUS_INCOMPATIBLE_DRIVER_BLOCKED";
        case STATUS_HIVE_UNLOADED:
            return "STATUS_HIVE_UNLOADED";
        case STATUS_COMPRESSION_DISABLED:
            return "STATUS_COMPRESSION_DISABLED";
        case STATUS_FILE_SYSTEM_LIMITATION:
            return "STATUS_FILE_SYSTEM_LIMITATION";
        case STATUS_INVALID_IMAGE_HASH:
            return "STATUS_INVALID_IMAGE_HASH";
        case STATUS_NOT_CAPABLE:
            return "STATUS_NOT_CAPABLE";
        case STATUS_REQUEST_OUT_OF_SEQUENCE:
            return "STATUS_REQUEST_OUT_OF_SEQUENCE";
        case STATUS_IMPLEMENTATION_LIMIT:
            return "STATUS_IMPLEMENTATION_LIMIT";
        case STATUS_ELEVATION_REQUIRED:
            return "STATUS_ELEVATION_REQUIRED";
        case STATUS_NO_SECURITY_CONTEXT:
            return "STATUS_NO_SECURITY_CONTEXT";
        case STATUS_PKU2U_CERT_FAILURE:
            return "STATUS_PKU2U_CERT_FAILURE";
        case STATUS_BEYOND_VDL:
            return "STATUS_BEYOND_VDL";
        case STATUS_ENCOUNTERED_WRITE_IN_PROGRESS:
            return "STATUS_ENCOUNTERED_WRITE_IN_PROGRESS";
        case STATUS_PTE_CHANGED:
            return "STATUS_PTE_CHANGED";
        case STATUS_PURGE_FAILED:
            return "STATUS_PURGE_FAILED";
        case STATUS_CRED_REQUIRES_CONFIRMATION:
            return "STATUS_CRED_REQUIRES_CONFIRMATION";
        case STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE:
            return "STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE";
        case STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER:
            return "STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER";
        case STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE:
            return "STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE";
        case STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE:
            return "STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE";
        case STATUS_CS_ENCRYPTION_FILE_NOT_CSE:
            return "STATUS_CS_ENCRYPTION_FILE_NOT_CSE";
        case STATUS_INVALID_LABEL:
            return "STATUS_INVALID_LABEL";
        case STATUS_DRIVER_PROCESS_TERMINATED:
            return "STATUS_DRIVER_PROCESS_TERMINATED";
        case STATUS_AMBIGUOUS_SYSTEM_DEVICE:
            return "STATUS_AMBIGUOUS_SYSTEM_DEVICE";
        case STATUS_SYSTEM_DEVICE_NOT_FOUND:
            return "STATUS_SYSTEM_DEVICE_NOT_FOUND";
        case STATUS_RESTART_BOOT_APPLICATION:
            return "STATUS_RESTART_BOOT_APPLICATION";
        case STATUS_INSUFFICIENT_NVRAM_RESOURCES:
            return "STATUS_INSUFFICIENT_NVRAM_RESOURCES";
        case STATUS_INVALID_SESSION:
            return "STATUS_INVALID_SESSION";
        case STATUS_THREAD_ALREADY_IN_SESSION:
            return "STATUS_THREAD_ALREADY_IN_SESSION";
        case STATUS_THREAD_NOT_IN_SESSION:
            return "STATUS_THREAD_NOT_IN_SESSION";
        case STATUS_INVALID_WEIGHT:
            return "STATUS_INVALID_WEIGHT";
        case STATUS_REQUEST_PAUSED:
            return "STATUS_REQUEST_PAUSED";
        case STATUS_NO_RANGES_PROCESSED:
            return "STATUS_NO_RANGES_PROCESSED";
        case STATUS_DISK_RESOURCES_EXHAUSTED:
            return "STATUS_DISK_RESOURCES_EXHAUSTED";
        case STATUS_NEEDS_REMEDIATION:
            return "STATUS_NEEDS_REMEDIATION";
        case STATUS_DEVICE_FEATURE_NOT_SUPPORTED:
            return "STATUS_DEVICE_FEATURE_NOT_SUPPORTED";
        case STATUS_DEVICE_UNREACHABLE:
            return "STATUS_DEVICE_UNREACHABLE";
        case STATUS_INVALID_TOKEN:
            return "STATUS_INVALID_TOKEN";
        case STATUS_SERVER_UNAVAILABLE:
            return "STATUS_SERVER_UNAVAILABLE";
        case STATUS_FILE_NOT_AVAILABLE:
            return "STATUS_FILE_NOT_AVAILABLE";
        case STATUS_DEVICE_INSUFFICIENT_RESOURCES:
            return "STATUS_DEVICE_INSUFFICIENT_RESOURCES";
        case STATUS_PACKAGE_UPDATING:
            return "STATUS_PACKAGE_UPDATING";
        case STATUS_NOT_READ_FROM_COPY:
            return "STATUS_NOT_READ_FROM_COPY";
        case STATUS_FT_WRITE_FAILURE:
            return "STATUS_FT_WRITE_FAILURE";
        case STATUS_FT_DI_SCAN_REQUIRED:
            return "STATUS_FT_DI_SCAN_REQUIRED";
        case STATUS_OBJECT_NOT_EXTERNALLY_BACKED:
            return "STATUS_OBJECT_NOT_EXTERNALLY_BACKED";
        case STATUS_EXTERNAL_BACKING_PROVIDER_UNKNOWN:
            return "STATUS_EXTERNAL_BACKING_PROVIDER_UNKNOWN";
        case STATUS_COMPRESSION_NOT_BENEFICIAL:
            return "STATUS_COMPRESSION_NOT_BENEFICIAL";
        case STATUS_DATA_CHECKSUM_ERROR:
            return "STATUS_DATA_CHECKSUM_ERROR";
        case STATUS_INTERMIXED_KERNEL_EA_OPERATION:
            return "STATUS_INTERMIXED_KERNEL_EA_OPERATION";
        case STATUS_TRIM_READ_ZERO_NOT_SUPPORTED:
            return "STATUS_TRIM_READ_ZERO_NOT_SUPPORTED";
        case STATUS_TOO_MANY_SEGMENT_DESCRIPTORS:
            return "STATUS_TOO_MANY_SEGMENT_DESCRIPTORS";
        case STATUS_INVALID_OFFSET_ALIGNMENT:
            return "STATUS_INVALID_OFFSET_ALIGNMENT";
        case STATUS_INVALID_FIELD_IN_PARAMETER_LIST:
            return "STATUS_INVALID_FIELD_IN_PARAMETER_LIST";
        case STATUS_OPERATION_IN_PROGRESS:
            return "STATUS_OPERATION_IN_PROGRESS";
        case STATUS_INVALID_INITIATOR_TARGET_PATH:
            return "STATUS_INVALID_INITIATOR_TARGET_PATH";
        case STATUS_SCRUB_DATA_DISABLED:
            return "STATUS_SCRUB_DATA_DISABLED";
        case STATUS_NOT_REDUNDANT_STORAGE:
            return "STATUS_NOT_REDUNDANT_STORAGE";
        case STATUS_RESIDENT_FILE_NOT_SUPPORTED:
            return "STATUS_RESIDENT_FILE_NOT_SUPPORTED";
        case STATUS_COMPRESSED_FILE_NOT_SUPPORTED:
            return "STATUS_COMPRESSED_FILE_NOT_SUPPORTED";
        case STATUS_DIRECTORY_NOT_SUPPORTED:
            return "STATUS_DIRECTORY_NOT_SUPPORTED";
        case STATUS_IO_OPERATION_TIMEOUT:
            return "STATUS_IO_OPERATION_TIMEOUT";
        case STATUS_SYSTEM_NEEDS_REMEDIATION:
            return "STATUS_SYSTEM_NEEDS_REMEDIATION";
        case STATUS_APPX_INTEGRITY_FAILURE_CLR_NGEN:
            return "STATUS_APPX_INTEGRITY_FAILURE_CLR_NGEN";
        case STATUS_SHARE_UNAVAILABLE:
            return "STATUS_SHARE_UNAVAILABLE";
        case STATUS_APISET_NOT_HOSTED:
            return "STATUS_APISET_NOT_HOSTED";
        case STATUS_APISET_NOT_PRESENT:
            return "STATUS_APISET_NOT_PRESENT";
        case STATUS_DEVICE_HARDWARE_ERROR:
            return "STATUS_DEVICE_HARDWARE_ERROR";
        case STATUS_FIRMWARE_SLOT_INVALID:
            return "STATUS_FIRMWARE_SLOT_INVALID";
        case STATUS_FIRMWARE_IMAGE_INVALID:
            return "STATUS_FIRMWARE_IMAGE_INVALID";
        case STATUS_STORAGE_TOPOLOGY_ID_MISMATCH:
            return "STATUS_STORAGE_TOPOLOGY_ID_MISMATCH";
        case STATUS_WIM_NOT_BOOTABLE:
            return "STATUS_WIM_NOT_BOOTABLE";
        case STATUS_BLOCKED_BY_PARENTAL_CONTROLS:
            return "STATUS_BLOCKED_BY_PARENTAL_CONTROLS";
        case STATUS_NEEDS_REGISTRATION:
            return "STATUS_NEEDS_REGISTRATION";
        case STATUS_QUOTA_ACTIVITY:
            return "STATUS_QUOTA_ACTIVITY";
        case STATUS_CALLBACK_INVOKE_INLINE:
            return "STATUS_CALLBACK_INVOKE_INLINE";
        case STATUS_BLOCK_TOO_MANY_REFERENCES:
            return "STATUS_BLOCK_TOO_MANY_REFERENCES";
        case STATUS_MARKED_TO_DISALLOW_WRITES:
            return "STATUS_MARKED_TO_DISALLOW_WRITES";
        case STATUS_NETWORK_ACCESS_DENIED_EDP:
            return "STATUS_NETWORK_ACCESS_DENIED_EDP";
        case STATUS_ENCLAVE_FAILURE:
            return "STATUS_ENCLAVE_FAILURE";
        case STATUS_PNP_NO_COMPAT_DRIVERS:
            return "STATUS_PNP_NO_COMPAT_DRIVERS";
        case STATUS_PNP_DRIVER_PACKAGE_NOT_FOUND:
            return "STATUS_PNP_DRIVER_PACKAGE_NOT_FOUND";
        case STATUS_PNP_DRIVER_CONFIGURATION_NOT_FOUND:
            return "STATUS_PNP_DRIVER_CONFIGURATION_NOT_FOUND";
        case STATUS_PNP_DRIVER_CONFIGURATION_INCOMPLETE:
            return "STATUS_PNP_DRIVER_CONFIGURATION_INCOMPLETE";
        case STATUS_PNP_FUNCTION_DRIVER_REQUIRED:
            return "STATUS_PNP_FUNCTION_DRIVER_REQUIRED";
        case STATUS_PNP_DEVICE_CONFIGURATION_PENDING:
            return "STATUS_PNP_DEVICE_CONFIGURATION_PENDING";
        case STATUS_DEVICE_HINT_NAME_BUFFER_TOO_SMALL:
            return "STATUS_DEVICE_HINT_NAME_BUFFER_TOO_SMALL";
        case STATUS_PACKAGE_NOT_AVAILABLE:
            return "STATUS_PACKAGE_NOT_AVAILABLE";
        case STATUS_DEVICE_IN_MAINTENANCE:
            return "STATUS_DEVICE_IN_MAINTENANCE";
        case STATUS_NOT_SUPPORTED_ON_DAX:
            return "STATUS_NOT_SUPPORTED_ON_DAX";
        case STATUS_FREE_SPACE_TOO_FRAGMENTED:
            return "STATUS_FREE_SPACE_TOO_FRAGMENTED";
        case STATUS_DAX_MAPPING_EXISTS:
            return "STATUS_DAX_MAPPING_EXISTS";
        case STATUS_CHILD_PROCESS_BLOCKED:
            return "STATUS_CHILD_PROCESS_BLOCKED";
        case STATUS_STORAGE_LOST_DATA_PERSISTENCE:
            return "STATUS_STORAGE_LOST_DATA_PERSISTENCE";
        case STATUS_VRF_CFG_ENABLED:
            return "STATUS_VRF_CFG_ENABLED";
        case STATUS_PARTITION_TERMINATING:
            return "STATUS_PARTITION_TERMINATING";
        case STATUS_EXTERNAL_SYSKEY_NOT_SUPPORTED:
            return "STATUS_EXTERNAL_SYSKEY_NOT_SUPPORTED";
        case STATUS_ENCLAVE_VIOLATION:
            return "STATUS_ENCLAVE_VIOLATION";
        case STATUS_FILE_PROTECTED_UNDER_DPL:
            return "STATUS_FILE_PROTECTED_UNDER_DPL";
        case STATUS_VOLUME_NOT_CLUSTER_ALIGNED:
            return "STATUS_VOLUME_NOT_CLUSTER_ALIGNED";
        case STATUS_NO_PHYSICALLY_ALIGNED_FREE_SPACE_FOUND:
            return "STATUS_NO_PHYSICALLY_ALIGNED_FREE_SPACE_FOUND";
        case STATUS_APPX_FILE_NOT_ENCRYPTED:
            return "STATUS_APPX_FILE_NOT_ENCRYPTED";
        case STATUS_RWRAW_ENCRYPTED_FILE_NOT_ENCRYPTED:
            return "STATUS_RWRAW_ENCRYPTED_FILE_NOT_ENCRYPTED";
        case STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILEOFFSET:
            return "STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILEOFFSET";
        case STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILERANGE:
            return "STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILERANGE";
        case STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_PARAMETER:
            return "STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_PARAMETER";
        case STATUS_FT_READ_FAILURE:
            return "STATUS_FT_READ_FAILURE";
        case STATUS_PATCH_CONFLICT:
            return "STATUS_PATCH_CONFLICT";
        case STATUS_STORAGE_RESERVE_ID_INVALID:
            return "STATUS_STORAGE_RESERVE_ID_INVALID";
        case STATUS_STORAGE_RESERVE_DOES_NOT_EXIST:
            return "STATUS_STORAGE_RESERVE_DOES_NOT_EXIST";
        case STATUS_STORAGE_RESERVE_ALREADY_EXISTS:
            return "STATUS_STORAGE_RESERVE_ALREADY_EXISTS";
        case STATUS_STORAGE_RESERVE_NOT_EMPTY:
            return "STATUS_STORAGE_RESERVE_NOT_EMPTY";
        case STATUS_NOT_A_DAX_VOLUME:
            return "STATUS_NOT_A_DAX_VOLUME";
        case STATUS_NOT_DAX_MAPPABLE:
            return "STATUS_NOT_DAX_MAPPABLE";
        case STATUS_CASE_DIFFERING_NAMES_IN_DIR:
            return "STATUS_CASE_DIFFERING_NAMES_IN_DIR";
        case STATUS_INVALID_TASK_NAME:
            return "STATUS_INVALID_TASK_NAME";
        case STATUS_INVALID_TASK_INDEX:
            return "STATUS_INVALID_TASK_INDEX";
        case STATUS_THREAD_ALREADY_IN_TASK:
            return "STATUS_THREAD_ALREADY_IN_TASK";
        case STATUS_CALLBACK_BYPASS:
            return "STATUS_CALLBACK_BYPASS";
        case STATUS_UNDEFINED_SCOPE:
            return "STATUS_UNDEFINED_SCOPE";
        case STATUS_INVALID_CAP:
            return "STATUS_INVALID_CAP";
        case STATUS_NOT_GUI_PROCESS:
            return "STATUS_NOT_GUI_PROCESS";
        case STATUS_DEVICE_HUNG:
            return "STATUS_DEVICE_HUNG";
        case STATUS_CONTAINER_ASSIGNED:
            return "STATUS_CONTAINER_ASSIGNED";
        case STATUS_JOB_NO_CONTAINER:
            return "STATUS_JOB_NO_CONTAINER";
        case STATUS_DEVICE_UNRESPONSIVE:
            return "STATUS_DEVICE_UNRESPONSIVE";
        case STATUS_REPARSE_POINT_ENCOUNTERED:
            return "STATUS_REPARSE_POINT_ENCOUNTERED";
        case STATUS_ATTRIBUTE_NOT_PRESENT:
            return "STATUS_ATTRIBUTE_NOT_PRESENT";
        case STATUS_NOT_A_TIERED_VOLUME:
            return "STATUS_NOT_A_TIERED_VOLUME";
        case STATUS_ALREADY_HAS_STREAM_ID:
            return "STATUS_ALREADY_HAS_STREAM_ID";
        case STATUS_JOB_NOT_EMPTY:
            return "STATUS_JOB_NOT_EMPTY";
        case STATUS_ALREADY_INITIALIZED:
            return "STATUS_ALREADY_INITIALIZED";
        case STATUS_ENCLAVE_NOT_TERMINATED:
            return "STATUS_ENCLAVE_NOT_TERMINATED";
        case STATUS_ENCLAVE_IS_TERMINATING:
            return "STATUS_ENCLAVE_IS_TERMINATING";
        case STATUS_SMB1_NOT_AVAILABLE:
            return "STATUS_SMB1_NOT_AVAILABLE";
        case STATUS_SMR_GARBAGE_COLLECTION_REQUIRED:
            return "STATUS_SMR_GARBAGE_COLLECTION_REQUIRED";
        case STATUS_FAIL_FAST_EXCEPTION:
            return "STATUS_FAIL_FAST_EXCEPTION";
        case STATUS_IMAGE_CERT_REVOKED:
            return "STATUS_IMAGE_CERT_REVOKED";
        case STATUS_DYNAMIC_CODE_BLOCKED:
            return "STATUS_DYNAMIC_CODE_BLOCKED";
        case STATUS_IMAGE_CERT_EXPIRED:
            return "STATUS_IMAGE_CERT_EXPIRED";
        case STATUS_STRICT_CFG_VIOLATION:
            return "STATUS_STRICT_CFG_VIOLATION";
        case STATUS_SET_CONTEXT_DENIED:
            return "STATUS_SET_CONTEXT_DENIED";
        case STATUS_CROSS_PARTITION_VIOLATION:
            return "STATUS_CROSS_PARTITION_VIOLATION";
        case STATUS_PORT_CLOSED:
            return "STATUS_PORT_CLOSED";
        case STATUS_MESSAGE_LOST:
            return "STATUS_MESSAGE_LOST";
        case STATUS_INVALID_MESSAGE:
            return "STATUS_INVALID_MESSAGE";
        case STATUS_REQUEST_CANCELED:
            return "STATUS_REQUEST_CANCELED";
        case STATUS_RECURSIVE_DISPATCH:
            return "STATUS_RECURSIVE_DISPATCH";
        case STATUS_LPC_RECEIVE_BUFFER_EXPECTED:
            return "STATUS_LPC_RECEIVE_BUFFER_EXPECTED";
        case STATUS_LPC_INVALID_CONNECTION_USAGE:
            return "STATUS_LPC_INVALID_CONNECTION_USAGE";
        case STATUS_LPC_REQUESTS_NOT_ALLOWED:
            return "STATUS_LPC_REQUESTS_NOT_ALLOWED";
        case STATUS_RESOURCE_IN_USE:
            return "STATUS_RESOURCE_IN_USE";
        case STATUS_HARDWARE_MEMORY_ERROR:
            return "STATUS_HARDWARE_MEMORY_ERROR";
        case STATUS_THREADPOOL_HANDLE_EXCEPTION:
            return "STATUS_THREADPOOL_HANDLE_EXCEPTION";
        case STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED:
            return "STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED";
        case STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED:
            return "STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED";
        case STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED:
            return "STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED";
        case STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED:
            return "STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED";
        case STATUS_THREADPOOL_RELEASED_DURING_OPERATION:
            return "STATUS_THREADPOOL_RELEASED_DURING_OPERATION";
        case STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING:
            return "STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING";
        case STATUS_APC_RETURNED_WHILE_IMPERSONATING:
            return "STATUS_APC_RETURNED_WHILE_IMPERSONATING";
        case STATUS_PROCESS_IS_PROTECTED:
            return "STATUS_PROCESS_IS_PROTECTED";
        case STATUS_MCA_EXCEPTION:
            return "STATUS_MCA_EXCEPTION";
        case STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE:
            return "STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE";
        case STATUS_SYMLINK_CLASS_DISABLED:
            return "STATUS_SYMLINK_CLASS_DISABLED";
        case STATUS_INVALID_IDN_NORMALIZATION:
            return "STATUS_INVALID_IDN_NORMALIZATION";
        case STATUS_NO_UNICODE_TRANSLATION:
            return "STATUS_NO_UNICODE_TRANSLATION";
        case STATUS_ALREADY_REGISTERED:
            return "STATUS_ALREADY_REGISTERED";
        case STATUS_CONTEXT_MISMATCH:
            return "STATUS_CONTEXT_MISMATCH";
        case STATUS_PORT_ALREADY_HAS_COMPLETION_LIST:
            return "STATUS_PORT_ALREADY_HAS_COMPLETION_LIST";
        case STATUS_CALLBACK_RETURNED_THREAD_PRIORITY:
            return "STATUS_CALLBACK_RETURNED_THREAD_PRIORITY";
        case STATUS_INVALID_THREAD:
            return "STATUS_INVALID_THREAD";
        case STATUS_CALLBACK_RETURNED_TRANSACTION:
            return "STATUS_CALLBACK_RETURNED_TRANSACTION";
        case STATUS_CALLBACK_RETURNED_LDR_LOCK:
            return "STATUS_CALLBACK_RETURNED_LDR_LOCK";
        case STATUS_CALLBACK_RETURNED_LANG:
            return "STATUS_CALLBACK_RETURNED_LANG";
        case STATUS_CALLBACK_RETURNED_PRI_BACK:
            return "STATUS_CALLBACK_RETURNED_PRI_BACK";
        case STATUS_CALLBACK_RETURNED_THREAD_AFFINITY:
            return "STATUS_CALLBACK_RETURNED_THREAD_AFFINITY";
        case STATUS_LPC_HANDLE_COUNT_EXCEEDED:
            return "STATUS_LPC_HANDLE_COUNT_EXCEEDED";
        case STATUS_EXECUTABLE_MEMORY_WRITE:
            return "STATUS_EXECUTABLE_MEMORY_WRITE";
        case STATUS_KERNEL_EXECUTABLE_MEMORY_WRITE:
            return "STATUS_KERNEL_EXECUTABLE_MEMORY_WRITE";
        case STATUS_ATTACHED_EXECUTABLE_MEMORY_WRITE:
            return "STATUS_ATTACHED_EXECUTABLE_MEMORY_WRITE";
        case STATUS_TRIGGERED_EXECUTABLE_MEMORY_WRITE:
            return "STATUS_TRIGGERED_EXECUTABLE_MEMORY_WRITE";
        case STATUS_DISK_REPAIR_DISABLED:
            return "STATUS_DISK_REPAIR_DISABLED";
        case STATUS_DS_DOMAIN_RENAME_IN_PROGRESS:
            return "STATUS_DS_DOMAIN_RENAME_IN_PROGRESS";
        case STATUS_DISK_QUOTA_EXCEEDED:
            return "STATUS_DISK_QUOTA_EXCEEDED";
        case STATUS_DATA_LOST_REPAIR:
            return "STATUS_DATA_LOST_REPAIR";
        case STATUS_CONTENT_BLOCKED:
            return "STATUS_CONTENT_BLOCKED";
        case STATUS_BAD_CLUSTERS:
            return "STATUS_BAD_CLUSTERS";
        case STATUS_VOLUME_DIRTY:
            return "STATUS_VOLUME_DIRTY";
        case STATUS_DISK_REPAIR_REDIRECTED:
            return "STATUS_DISK_REPAIR_REDIRECTED";
        case STATUS_DISK_REPAIR_UNSUCCESSFUL:
            return "STATUS_DISK_REPAIR_UNSUCCESSFUL";
        case STATUS_CORRUPT_LOG_OVERFULL:
            return "STATUS_CORRUPT_LOG_OVERFULL";
        case STATUS_CORRUPT_LOG_CORRUPTED:
            return "STATUS_CORRUPT_LOG_CORRUPTED";
        case STATUS_CORRUPT_LOG_UNAVAILABLE:
            return "STATUS_CORRUPT_LOG_UNAVAILABLE";
        case STATUS_CORRUPT_LOG_DELETED_FULL:
            return "STATUS_CORRUPT_LOG_DELETED_FULL";
        case STATUS_CORRUPT_LOG_CLEARED:
            return "STATUS_CORRUPT_LOG_CLEARED";
        case STATUS_ORPHAN_NAME_EXHAUSTED:
            return "STATUS_ORPHAN_NAME_EXHAUSTED";
        case STATUS_PROACTIVE_SCAN_IN_PROGRESS:
            return "STATUS_PROACTIVE_SCAN_IN_PROGRESS";
        case STATUS_ENCRYPTED_IO_NOT_POSSIBLE:
            return "STATUS_ENCRYPTED_IO_NOT_POSSIBLE";
        case STATUS_CORRUPT_LOG_UPLEVEL_RECORDS:
            return "STATUS_CORRUPT_LOG_UPLEVEL_RECORDS";
        case STATUS_FILE_CHECKED_OUT:
            return "STATUS_FILE_CHECKED_OUT";
        case STATUS_CHECKOUT_REQUIRED:
            return "STATUS_CHECKOUT_REQUIRED";
        case STATUS_BAD_FILE_TYPE:
            return "STATUS_BAD_FILE_TYPE";
        case STATUS_FILE_TOO_LARGE:
            return "STATUS_FILE_TOO_LARGE";
        case STATUS_FORMS_AUTH_REQUIRED:
            return "STATUS_FORMS_AUTH_REQUIRED";
        case STATUS_VIRUS_INFECTED:
            return "STATUS_VIRUS_INFECTED";
        case STATUS_VIRUS_DELETED:
            return "STATUS_VIRUS_DELETED";
        case STATUS_BAD_MCFG_TABLE:
            return "STATUS_BAD_MCFG_TABLE";
        case STATUS_CANNOT_BREAK_OPLOCK:
            return "STATUS_CANNOT_BREAK_OPLOCK";
        case STATUS_BAD_KEY:
            return "STATUS_BAD_KEY";
        case STATUS_BAD_DATA:
            return "STATUS_BAD_DATA";
        case STATUS_NO_KEY:
            return "STATUS_NO_KEY";
        case STATUS_FILE_HANDLE_REVOKED:
            return "STATUS_FILE_HANDLE_REVOKED";
        case STATUS_WOW_ASSERTION:
            return "STATUS_WOW_ASSERTION";
        case STATUS_INVALID_SIGNATURE:
            return "STATUS_INVALID_SIGNATURE";
        case STATUS_HMAC_NOT_SUPPORTED:
            return "STATUS_HMAC_NOT_SUPPORTED";
        case STATUS_AUTH_TAG_MISMATCH:
            return "STATUS_AUTH_TAG_MISMATCH";
        case STATUS_INVALID_STATE_TRANSITION:
            return "STATUS_INVALID_STATE_TRANSITION";
        case STATUS_INVALID_KERNEL_INFO_VERSION:
            return "STATUS_INVALID_KERNEL_INFO_VERSION";
        case STATUS_INVALID_PEP_INFO_VERSION:
            return "STATUS_INVALID_PEP_INFO_VERSION";
        case STATUS_HANDLE_REVOKED:
            return "STATUS_HANDLE_REVOKED";
        case STATUS_EOF_ON_GHOSTED_RANGE:
            return "STATUS_EOF_ON_GHOSTED_RANGE";
        case STATUS_IPSEC_QUEUE_OVERFLOW:
            return "STATUS_IPSEC_QUEUE_OVERFLOW";
        case STATUS_ND_QUEUE_OVERFLOW:
            return "STATUS_ND_QUEUE_OVERFLOW";
        case STATUS_HOPLIMIT_EXCEEDED:
            return "STATUS_HOPLIMIT_EXCEEDED";
        case STATUS_PROTOCOL_NOT_SUPPORTED:
            return "STATUS_PROTOCOL_NOT_SUPPORTED";
        case STATUS_FASTPATH_REJECTED:
            return "STATUS_FASTPATH_REJECTED";
        case STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED:
            return "STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED";
        case STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR:
            return "STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR";
        case STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR:
            return "STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR";
        case STATUS_XML_PARSE_ERROR:
            return "STATUS_XML_PARSE_ERROR";
        case STATUS_XMLDSIG_ERROR:
            return "STATUS_XMLDSIG_ERROR";
        case STATUS_WRONG_COMPARTMENT:
            return "STATUS_WRONG_COMPARTMENT";
        case STATUS_AUTHIP_FAILURE:
            return "STATUS_AUTHIP_FAILURE";
        case STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS:
            return "STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS";
        case STATUS_DS_OID_NOT_FOUND:
            return "STATUS_DS_OID_NOT_FOUND";
        case STATUS_INCORRECT_ACCOUNT_TYPE:
            return "STATUS_INCORRECT_ACCOUNT_TYPE";
        case STATUS_HASH_NOT_SUPPORTED:
            return "STATUS_HASH_NOT_SUPPORTED";
        case STATUS_HASH_NOT_PRESENT:
            return "STATUS_HASH_NOT_PRESENT";
        case STATUS_SECONDARY_IC_PROVIDER_NOT_REGISTERED:
            return "STATUS_SECONDARY_IC_PROVIDER_NOT_REGISTERED";
        case STATUS_GPIO_CLIENT_INFORMATION_INVALID:
            return "STATUS_GPIO_CLIENT_INFORMATION_INVALID";
        case STATUS_GPIO_VERSION_NOT_SUPPORTED:
            return "STATUS_GPIO_VERSION_NOT_SUPPORTED";
        case STATUS_GPIO_INVALID_REGISTRATION_PACKET:
            return "STATUS_GPIO_INVALID_REGISTRATION_PACKET";
        case STATUS_GPIO_OPERATION_DENIED:
            return "STATUS_GPIO_OPERATION_DENIED";
        case STATUS_GPIO_INCOMPATIBLE_CONNECT_MODE:
            return "STATUS_GPIO_INCOMPATIBLE_CONNECT_MODE";
        case STATUS_GPIO_INTERRUPT_ALREADY_UNMASKED:
            return "STATUS_GPIO_INTERRUPT_ALREADY_UNMASKED";
        case STATUS_CANNOT_SWITCH_RUNLEVEL:
            return "STATUS_CANNOT_SWITCH_RUNLEVEL";
        case STATUS_INVALID_RUNLEVEL_SETTING:
            return "STATUS_INVALID_RUNLEVEL_SETTING";
        case STATUS_RUNLEVEL_SWITCH_TIMEOUT:
            return "STATUS_RUNLEVEL_SWITCH_TIMEOUT";
        case STATUS_SERVICES_FAILED_AUTOSTART:
            return "STATUS_SERVICES_FAILED_AUTOSTART";
        case STATUS_RUNLEVEL_SWITCH_AGENT_TIMEOUT:
            return "STATUS_RUNLEVEL_SWITCH_AGENT_TIMEOUT";
        case STATUS_RUNLEVEL_SWITCH_IN_PROGRESS:
            return "STATUS_RUNLEVEL_SWITCH_IN_PROGRESS";
        case STATUS_NOT_APPCONTAINER:
            return "STATUS_NOT_APPCONTAINER";
        case STATUS_NOT_SUPPORTED_IN_APPCONTAINER:
            return "STATUS_NOT_SUPPORTED_IN_APPCONTAINER";
        case STATUS_INVALID_PACKAGE_SID_LENGTH:
            return "STATUS_INVALID_PACKAGE_SID_LENGTH";
        case STATUS_LPAC_ACCESS_DENIED:
            return "STATUS_LPAC_ACCESS_DENIED";
        case STATUS_ADMINLESS_ACCESS_DENIED:
            return "STATUS_ADMINLESS_ACCESS_DENIED";
        case STATUS_APP_DATA_NOT_FOUND:
            return "STATUS_APP_DATA_NOT_FOUND";
        case STATUS_APP_DATA_EXPIRED:
            return "STATUS_APP_DATA_EXPIRED";
        case STATUS_APP_DATA_CORRUPT:
            return "STATUS_APP_DATA_CORRUPT";
        case STATUS_APP_DATA_LIMIT_EXCEEDED:
            return "STATUS_APP_DATA_LIMIT_EXCEEDED";
        case STATUS_APP_DATA_REBOOT_REQUIRED:
            return "STATUS_APP_DATA_REBOOT_REQUIRED";
        case STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED:
            return "STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED";
        case STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED:
            return "STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED";
        case STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED:
            return "STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED";
        case STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED:
            return "STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED";
        case STATUS_WOF_WIM_HEADER_CORRUPT:
            return "STATUS_WOF_WIM_HEADER_CORRUPT";
        case STATUS_WOF_WIM_RESOURCE_TABLE_CORRUPT:
            return "STATUS_WOF_WIM_RESOURCE_TABLE_CORRUPT";
        case STATUS_WOF_FILE_RESOURCE_TABLE_CORRUPT:
            return "STATUS_WOF_FILE_RESOURCE_TABLE_CORRUPT";
        case STATUS_FILE_SYSTEM_VIRTUALIZATION_UNAVAILABLE:
            return "STATUS_FILE_SYSTEM_VIRTUALIZATION_UNAVAILABLE";
        case STATUS_FILE_SYSTEM_VIRTUALIZATION_METADATA_CORRUPT:
            return "STATUS_FILE_SYSTEM_VIRTUALIZATION_METADATA_CORRUPT";
        case STATUS_FILE_SYSTEM_VIRTUALIZATION_BUSY:
            return "STATUS_FILE_SYSTEM_VIRTUALIZATION_BUSY";
        case STATUS_FILE_SYSTEM_VIRTUALIZATION_PROVIDER_UNKNOWN:
            return "STATUS_FILE_SYSTEM_VIRTUALIZATION_PROVIDER_UNKNOWN";
        case STATUS_FILE_SYSTEM_VIRTUALIZATION_INVALID_OPERATION:
            return "STATUS_FILE_SYSTEM_VIRTUALIZATION_INVALID_OPERATION";
        case STATUS_CLOUD_FILE_SYNC_ROOT_METADATA_CORRUPT:
            return "STATUS_CLOUD_FILE_SYNC_ROOT_METADATA_CORRUPT";
        case STATUS_CLOUD_FILE_PROVIDER_NOT_RUNNING:
            return "STATUS_CLOUD_FILE_PROVIDER_NOT_RUNNING";
        case STATUS_CLOUD_FILE_METADATA_CORRUPT:
            return "STATUS_CLOUD_FILE_METADATA_CORRUPT";
        case STATUS_CLOUD_FILE_METADATA_TOO_LARGE:
            return "STATUS_CLOUD_FILE_METADATA_TOO_LARGE";
        case STATUS_CLOUD_FILE_PROPERTY_BLOB_TOO_LARGE:
            return "STATUS_CLOUD_FILE_PROPERTY_BLOB_TOO_LARGE";
        case STATUS_CLOUD_FILE_TOO_MANY_PROPERTY_BLOBS:
            return "STATUS_CLOUD_FILE_TOO_MANY_PROPERTY_BLOBS";
        case STATUS_CLOUD_FILE_PROPERTY_VERSION_NOT_SUPPORTED:
            return "STATUS_CLOUD_FILE_PROPERTY_VERSION_NOT_SUPPORTED";
        case STATUS_NOT_A_CLOUD_FILE:
            return "STATUS_NOT_A_CLOUD_FILE";
        case STATUS_CLOUD_FILE_NOT_IN_SYNC:
            return "STATUS_CLOUD_FILE_NOT_IN_SYNC";
        case STATUS_CLOUD_FILE_ALREADY_CONNECTED:
            return "STATUS_CLOUD_FILE_ALREADY_CONNECTED";
        case STATUS_CLOUD_FILE_NOT_SUPPORTED:
            return "STATUS_CLOUD_FILE_NOT_SUPPORTED";
        case STATUS_CLOUD_FILE_INVALID_REQUEST:
            return "STATUS_CLOUD_FILE_INVALID_REQUEST";
        case STATUS_CLOUD_FILE_READ_ONLY_VOLUME:
            return "STATUS_CLOUD_FILE_READ_ONLY_VOLUME";
        case STATUS_CLOUD_FILE_CONNECTED_PROVIDER_ONLY:
            return "STATUS_CLOUD_FILE_CONNECTED_PROVIDER_ONLY";
        case STATUS_CLOUD_FILE_VALIDATION_FAILED:
            return "STATUS_CLOUD_FILE_VALIDATION_FAILED";
        case STATUS_CLOUD_FILE_AUTHENTICATION_FAILED:
            return "STATUS_CLOUD_FILE_AUTHENTICATION_FAILED";
        case STATUS_CLOUD_FILE_INSUFFICIENT_RESOURCES:
            return "STATUS_CLOUD_FILE_INSUFFICIENT_RESOURCES";
        case STATUS_CLOUD_FILE_NETWORK_UNAVAILABLE:
            return "STATUS_CLOUD_FILE_NETWORK_UNAVAILABLE";
        case STATUS_CLOUD_FILE_UNSUCCESSFUL:
            return "STATUS_CLOUD_FILE_UNSUCCESSFUL";
        case STATUS_CLOUD_FILE_NOT_UNDER_SYNC_ROOT:
            return "STATUS_CLOUD_FILE_NOT_UNDER_SYNC_ROOT";
        case STATUS_CLOUD_FILE_IN_USE:
            return "STATUS_CLOUD_FILE_IN_USE";
        case STATUS_CLOUD_FILE_PINNED:
            return "STATUS_CLOUD_FILE_PINNED";
        case STATUS_CLOUD_FILE_REQUEST_ABORTED:
            return "STATUS_CLOUD_FILE_REQUEST_ABORTED";
        case STATUS_CLOUD_FILE_PROPERTY_CORRUPT:
            return "STATUS_CLOUD_FILE_PROPERTY_CORRUPT";
        case STATUS_CLOUD_FILE_ACCESS_DENIED:
            return "STATUS_CLOUD_FILE_ACCESS_DENIED";
        case STATUS_CLOUD_FILE_INCOMPATIBLE_HARDLINKS:
            return "STATUS_CLOUD_FILE_INCOMPATIBLE_HARDLINKS";
        case STATUS_CLOUD_FILE_PROPERTY_LOCK_CONFLICT:
            return "STATUS_CLOUD_FILE_PROPERTY_LOCK_CONFLICT";
        case STATUS_CLOUD_FILE_REQUEST_CANCELED:
            return "STATUS_CLOUD_FILE_REQUEST_CANCELED";
        case STATUS_CLOUD_FILE_PROVIDER_TERMINATED:
            return "STATUS_CLOUD_FILE_PROVIDER_TERMINATED";
        case STATUS_NOT_A_CLOUD_SYNC_ROOT:
            return "STATUS_NOT_A_CLOUD_SYNC_ROOT";
        case DBG_NO_STATE_CHANGE:
            return "DBG_NO_STATE_CHANGE";
        case DBG_APP_NOT_IDLE:
            return "DBG_APP_NOT_IDLE";
        case RPC_NT_INVALID_STRING_BINDING:
            return "RPC_NT_INVALID_STRING_BINDING";
        case RPC_NT_WRONG_KIND_OF_BINDING:
            return "RPC_NT_WRONG_KIND_OF_BINDING";
        case RPC_NT_INVALID_BINDING:
            return "RPC_NT_INVALID_BINDING";
        case RPC_NT_PROTSEQ_NOT_SUPPORTED:
            return "RPC_NT_PROTSEQ_NOT_SUPPORTED";
        case RPC_NT_INVALID_RPC_PROTSEQ:
            return "RPC_NT_INVALID_RPC_PROTSEQ";
        case RPC_NT_INVALID_STRING_UUID:
            return "RPC_NT_INVALID_STRING_UUID";
        case RPC_NT_INVALID_ENDPOINT_FORMAT:
            return "RPC_NT_INVALID_ENDPOINT_FORMAT";
        case RPC_NT_INVALID_NET_ADDR:
            return "RPC_NT_INVALID_NET_ADDR";
        case RPC_NT_NO_ENDPOINT_FOUND:
            return "RPC_NT_NO_ENDPOINT_FOUND";
        case RPC_NT_INVALID_TIMEOUT:
            return "RPC_NT_INVALID_TIMEOUT";
        case RPC_NT_OBJECT_NOT_FOUND:
            return "RPC_NT_OBJECT_NOT_FOUND";
        case RPC_NT_ALREADY_REGISTERED:
            return "RPC_NT_ALREADY_REGISTERED";
        case RPC_NT_TYPE_ALREADY_REGISTERED:
            return "RPC_NT_TYPE_ALREADY_REGISTERED";
        case RPC_NT_ALREADY_LISTENING:
            return "RPC_NT_ALREADY_LISTENING";
        case RPC_NT_NO_PROTSEQS_REGISTERED:
            return "RPC_NT_NO_PROTSEQS_REGISTERED";
        case RPC_NT_NOT_LISTENING:
            return "RPC_NT_NOT_LISTENING";
        case RPC_NT_UNKNOWN_MGR_TYPE:
            return "RPC_NT_UNKNOWN_MGR_TYPE";
        case RPC_NT_UNKNOWN_IF:
            return "RPC_NT_UNKNOWN_IF";
        case RPC_NT_NO_BINDINGS:
            return "RPC_NT_NO_BINDINGS";
        case RPC_NT_NO_PROTSEQS:
            return "RPC_NT_NO_PROTSEQS";
        case RPC_NT_CANT_CREATE_ENDPOINT:
            return "RPC_NT_CANT_CREATE_ENDPOINT";
        case RPC_NT_OUT_OF_RESOURCES:
            return "RPC_NT_OUT_OF_RESOURCES";
        case RPC_NT_SERVER_UNAVAILABLE:
            return "RPC_NT_SERVER_UNAVAILABLE";
        case RPC_NT_SERVER_TOO_BUSY:
            return "RPC_NT_SERVER_TOO_BUSY";
        case RPC_NT_INVALID_NETWORK_OPTIONS:
            return "RPC_NT_INVALID_NETWORK_OPTIONS";
        case RPC_NT_NO_CALL_ACTIVE:
            return "RPC_NT_NO_CALL_ACTIVE";
        case RPC_NT_CALL_FAILED:
            return "RPC_NT_CALL_FAILED";
        case RPC_NT_CALL_FAILED_DNE:
            return "RPC_NT_CALL_FAILED_DNE";
        case RPC_NT_PROTOCOL_ERROR:
            return "RPC_NT_PROTOCOL_ERROR";
        case RPC_NT_UNSUPPORTED_TRANS_SYN:
            return "RPC_NT_UNSUPPORTED_TRANS_SYN";
        case RPC_NT_UNSUPPORTED_TYPE:
            return "RPC_NT_UNSUPPORTED_TYPE";
        case RPC_NT_INVALID_TAG:
            return "RPC_NT_INVALID_TAG";
        case RPC_NT_INVALID_BOUND:
            return "RPC_NT_INVALID_BOUND";
        case RPC_NT_NO_ENTRY_NAME:
            return "RPC_NT_NO_ENTRY_NAME";
        case RPC_NT_INVALID_NAME_SYNTAX:
            return "RPC_NT_INVALID_NAME_SYNTAX";
        case RPC_NT_UNSUPPORTED_NAME_SYNTAX:
            return "RPC_NT_UNSUPPORTED_NAME_SYNTAX";
        case RPC_NT_UUID_NO_ADDRESS:
            return "RPC_NT_UUID_NO_ADDRESS";
        case RPC_NT_DUPLICATE_ENDPOINT:
            return "RPC_NT_DUPLICATE_ENDPOINT";
        case RPC_NT_UNKNOWN_AUTHN_TYPE:
            return "RPC_NT_UNKNOWN_AUTHN_TYPE";
        case RPC_NT_MAX_CALLS_TOO_SMALL:
            return "RPC_NT_MAX_CALLS_TOO_SMALL";
        case RPC_NT_STRING_TOO_LONG:
            return "RPC_NT_STRING_TOO_LONG";
        case RPC_NT_PROTSEQ_NOT_FOUND:
            return "RPC_NT_PROTSEQ_NOT_FOUND";
        case RPC_NT_PROCNUM_OUT_OF_RANGE:
            return "RPC_NT_PROCNUM_OUT_OF_RANGE";
        case RPC_NT_BINDING_HAS_NO_AUTH:
            return "RPC_NT_BINDING_HAS_NO_AUTH";
        case RPC_NT_UNKNOWN_AUTHN_SERVICE:
            return "RPC_NT_UNKNOWN_AUTHN_SERVICE";
        case RPC_NT_UNKNOWN_AUTHN_LEVEL:
            return "RPC_NT_UNKNOWN_AUTHN_LEVEL";
        case RPC_NT_INVALID_AUTH_IDENTITY:
            return "RPC_NT_INVALID_AUTH_IDENTITY";
        case RPC_NT_UNKNOWN_AUTHZ_SERVICE:
            return "RPC_NT_UNKNOWN_AUTHZ_SERVICE";
        case EPT_NT_INVALID_ENTRY:
            return "EPT_NT_INVALID_ENTRY";
        case EPT_NT_CANT_PERFORM_OP:
            return "EPT_NT_CANT_PERFORM_OP";
        case EPT_NT_NOT_REGISTERED:
            return "EPT_NT_NOT_REGISTERED";
        case RPC_NT_NOTHING_TO_EXPORT:
            return "RPC_NT_NOTHING_TO_EXPORT";
        case RPC_NT_INCOMPLETE_NAME:
            return "RPC_NT_INCOMPLETE_NAME";
        case RPC_NT_INVALID_VERS_OPTION:
            return "RPC_NT_INVALID_VERS_OPTION";
        case RPC_NT_NO_MORE_MEMBERS:
            return "RPC_NT_NO_MORE_MEMBERS";
        case RPC_NT_NOT_ALL_OBJS_UNEXPORTED:
            return "RPC_NT_NOT_ALL_OBJS_UNEXPORTED";
        case RPC_NT_INTERFACE_NOT_FOUND:
            return "RPC_NT_INTERFACE_NOT_FOUND";
        case RPC_NT_ENTRY_ALREADY_EXISTS:
            return "RPC_NT_ENTRY_ALREADY_EXISTS";
        case RPC_NT_ENTRY_NOT_FOUND:
            return "RPC_NT_ENTRY_NOT_FOUND";
        case RPC_NT_NAME_SERVICE_UNAVAILABLE:
            return "RPC_NT_NAME_SERVICE_UNAVAILABLE";
        case RPC_NT_INVALID_NAF_ID:
            return "RPC_NT_INVALID_NAF_ID";
        case RPC_NT_CANNOT_SUPPORT:
            return "RPC_NT_CANNOT_SUPPORT";
        case RPC_NT_NO_CONTEXT_AVAILABLE:
            return "RPC_NT_NO_CONTEXT_AVAILABLE";
        case RPC_NT_INTERNAL_ERROR:
            return "RPC_NT_INTERNAL_ERROR";
        case RPC_NT_ZERO_DIVIDE:
            return "RPC_NT_ZERO_DIVIDE";
        case RPC_NT_ADDRESS_ERROR:
            return "RPC_NT_ADDRESS_ERROR";
        case RPC_NT_FP_DIV_ZERO:
            return "RPC_NT_FP_DIV_ZERO";
        case RPC_NT_FP_UNDERFLOW:
            return "RPC_NT_FP_UNDERFLOW";
        case RPC_NT_FP_OVERFLOW:
            return "RPC_NT_FP_OVERFLOW";
        case RPC_NT_NO_MORE_ENTRIES:
            return "RPC_NT_NO_MORE_ENTRIES";
        case RPC_NT_SS_CHAR_TRANS_OPEN_FAIL:
            return "RPC_NT_SS_CHAR_TRANS_OPEN_FAIL";
        case RPC_NT_SS_CHAR_TRANS_SHORT_FILE:
            return "RPC_NT_SS_CHAR_TRANS_SHORT_FILE";
        case RPC_NT_SS_IN_NULL_CONTEXT:
            return "RPC_NT_SS_IN_NULL_CONTEXT";
        case RPC_NT_SS_CONTEXT_MISMATCH:
            return "RPC_NT_SS_CONTEXT_MISMATCH";
        case RPC_NT_SS_CONTEXT_DAMAGED:
            return "RPC_NT_SS_CONTEXT_DAMAGED";
        case RPC_NT_SS_HANDLES_MISMATCH:
            return "RPC_NT_SS_HANDLES_MISMATCH";
        case RPC_NT_SS_CANNOT_GET_CALL_HANDLE:
            return "RPC_NT_SS_CANNOT_GET_CALL_HANDLE";
        case RPC_NT_NULL_REF_POINTER:
            return "RPC_NT_NULL_REF_POINTER";
        case RPC_NT_ENUM_VALUE_OUT_OF_RANGE:
            return "RPC_NT_ENUM_VALUE_OUT_OF_RANGE";
        case RPC_NT_BYTE_COUNT_TOO_SMALL:
            return "RPC_NT_BYTE_COUNT_TOO_SMALL";
        case RPC_NT_BAD_STUB_DATA:
            return "RPC_NT_BAD_STUB_DATA";
        case RPC_NT_CALL_IN_PROGRESS:
            return "RPC_NT_CALL_IN_PROGRESS";
        case RPC_NT_NO_MORE_BINDINGS:
            return "RPC_NT_NO_MORE_BINDINGS";
        case RPC_NT_GROUP_MEMBER_NOT_FOUND:
            return "RPC_NT_GROUP_MEMBER_NOT_FOUND";
        case EPT_NT_CANT_CREATE:
            return "EPT_NT_CANT_CREATE";
        case RPC_NT_INVALID_OBJECT:
            return "RPC_NT_INVALID_OBJECT";
        case RPC_NT_NO_INTERFACES:
            return "RPC_NT_NO_INTERFACES";
        case RPC_NT_CALL_CANCELLED:
            return "RPC_NT_CALL_CANCELLED";
        case RPC_NT_BINDING_INCOMPLETE:
            return "RPC_NT_BINDING_INCOMPLETE";
        case RPC_NT_COMM_FAILURE:
            return "RPC_NT_COMM_FAILURE";
        case RPC_NT_UNSUPPORTED_AUTHN_LEVEL:
            return "RPC_NT_UNSUPPORTED_AUTHN_LEVEL";
        case RPC_NT_NO_PRINC_NAME:
            return "RPC_NT_NO_PRINC_NAME";
        case RPC_NT_NOT_RPC_ERROR:
            return "RPC_NT_NOT_RPC_ERROR";
        case RPC_NT_UUID_LOCAL_ONLY:
            return "RPC_NT_UUID_LOCAL_ONLY";
        case RPC_NT_SEC_PKG_ERROR:
            return "RPC_NT_SEC_PKG_ERROR";
        case RPC_NT_NOT_CANCELLED:
            return "RPC_NT_NOT_CANCELLED";
        case RPC_NT_INVALID_ES_ACTION:
            return "RPC_NT_INVALID_ES_ACTION";
        case RPC_NT_WRONG_ES_VERSION:
            return "RPC_NT_WRONG_ES_VERSION";
        case RPC_NT_WRONG_STUB_VERSION:
            return "RPC_NT_WRONG_STUB_VERSION";
        case RPC_NT_INVALID_PIPE_OBJECT:
            return "RPC_NT_INVALID_PIPE_OBJECT";
        case RPC_NT_INVALID_PIPE_OPERATION:
            return "RPC_NT_INVALID_PIPE_OPERATION";
        case RPC_NT_WRONG_PIPE_VERSION:
            return "RPC_NT_WRONG_PIPE_VERSION";
        case RPC_NT_PIPE_CLOSED:
            return "RPC_NT_PIPE_CLOSED";
        case RPC_NT_PIPE_DISCIPLINE_ERROR:
            return "RPC_NT_PIPE_DISCIPLINE_ERROR";
        case RPC_NT_PIPE_EMPTY:
            return "RPC_NT_PIPE_EMPTY";
        case RPC_NT_INVALID_ASYNC_HANDLE:
            return "RPC_NT_INVALID_ASYNC_HANDLE";
        case RPC_NT_INVALID_ASYNC_CALL:
            return "RPC_NT_INVALID_ASYNC_CALL";
        case RPC_NT_PROXY_ACCESS_DENIED:
            return "RPC_NT_PROXY_ACCESS_DENIED";
        case RPC_NT_COOKIE_AUTH_FAILED:
            return "RPC_NT_COOKIE_AUTH_FAILED";
        case RPC_NT_SEND_INCOMPLETE:
            return "RPC_NT_SEND_INCOMPLETE";
        case STATUS_ACPI_INVALID_OPCODE:
            return "STATUS_ACPI_INVALID_OPCODE";
        case STATUS_ACPI_STACK_OVERFLOW:
            return "STATUS_ACPI_STACK_OVERFLOW";
        case STATUS_ACPI_ASSERT_FAILED:
            return "STATUS_ACPI_ASSERT_FAILED";
        case STATUS_ACPI_INVALID_INDEX:
            return "STATUS_ACPI_INVALID_INDEX";
        case STATUS_ACPI_INVALID_ARGUMENT:
            return "STATUS_ACPI_INVALID_ARGUMENT";
        case STATUS_ACPI_FATAL:
            return "STATUS_ACPI_FATAL";
        case STATUS_ACPI_INVALID_SUPERNAME:
            return "STATUS_ACPI_INVALID_SUPERNAME";
        case STATUS_ACPI_INVALID_ARGTYPE:
            return "STATUS_ACPI_INVALID_ARGTYPE";
        case STATUS_ACPI_INVALID_OBJTYPE:
            return "STATUS_ACPI_INVALID_OBJTYPE";
        case STATUS_ACPI_INVALID_TARGETTYPE:
            return "STATUS_ACPI_INVALID_TARGETTYPE";
        case STATUS_ACPI_INCORRECT_ARGUMENT_COUNT:
            return "STATUS_ACPI_INCORRECT_ARGUMENT_COUNT";
        case STATUS_ACPI_ADDRESS_NOT_MAPPED:
            return "STATUS_ACPI_ADDRESS_NOT_MAPPED";
        case STATUS_ACPI_INVALID_EVENTTYPE:
            return "STATUS_ACPI_INVALID_EVENTTYPE";
        case STATUS_ACPI_HANDLER_COLLISION:
            return "STATUS_ACPI_HANDLER_COLLISION";
        case STATUS_ACPI_INVALID_DATA:
            return "STATUS_ACPI_INVALID_DATA";
        case STATUS_ACPI_INVALID_REGION:
            return "STATUS_ACPI_INVALID_REGION";
        case STATUS_ACPI_INVALID_ACCESS_SIZE:
            return "STATUS_ACPI_INVALID_ACCESS_SIZE";
        case STATUS_ACPI_ACQUIRE_GLOBAL_LOCK:
            return "STATUS_ACPI_ACQUIRE_GLOBAL_LOCK";
        case STATUS_ACPI_ALREADY_INITIALIZED:
            return "STATUS_ACPI_ALREADY_INITIALIZED";
        case STATUS_ACPI_NOT_INITIALIZED:
            return "STATUS_ACPI_NOT_INITIALIZED";
        case STATUS_ACPI_INVALID_MUTEX_LEVEL:
            return "STATUS_ACPI_INVALID_MUTEX_LEVEL";
        case STATUS_ACPI_MUTEX_NOT_OWNED:
            return "STATUS_ACPI_MUTEX_NOT_OWNED";
        case STATUS_ACPI_MUTEX_NOT_OWNER:
            return "STATUS_ACPI_MUTEX_NOT_OWNER";
        case STATUS_ACPI_RS_ACCESS:
            return "STATUS_ACPI_RS_ACCESS";
        case STATUS_ACPI_INVALID_TABLE:
            return "STATUS_ACPI_INVALID_TABLE";
        case STATUS_ACPI_REG_HANDLER_FAILED:
            return "STATUS_ACPI_REG_HANDLER_FAILED";
        case STATUS_ACPI_POWER_REQUEST_FAILED:
            return "STATUS_ACPI_POWER_REQUEST_FAILED";
        case STATUS_CTX_WINSTATION_NAME_INVALID:
            return "STATUS_CTX_WINSTATION_NAME_INVALID";
        case STATUS_CTX_INVALID_PD:
            return "STATUS_CTX_INVALID_PD";
        case STATUS_CTX_PD_NOT_FOUND:
            return "STATUS_CTX_PD_NOT_FOUND";
        case STATUS_CTX_CDM_CONNECT:
            return "STATUS_CTX_CDM_CONNECT";
        case STATUS_CTX_CDM_DISCONNECT:
            return "STATUS_CTX_CDM_DISCONNECT";
        case STATUS_CTX_CLOSE_PENDING:
            return "STATUS_CTX_CLOSE_PENDING";
        case STATUS_CTX_NO_OUTBUF:
            return "STATUS_CTX_NO_OUTBUF";
        case STATUS_CTX_MODEM_INF_NOT_FOUND:
            return "STATUS_CTX_MODEM_INF_NOT_FOUND";
        case STATUS_CTX_INVALID_MODEMNAME:
            return "STATUS_CTX_INVALID_MODEMNAME";
        case STATUS_CTX_RESPONSE_ERROR:
            return "STATUS_CTX_RESPONSE_ERROR";
        case STATUS_CTX_MODEM_RESPONSE_TIMEOUT:
            return "STATUS_CTX_MODEM_RESPONSE_TIMEOUT";
        case STATUS_CTX_MODEM_RESPONSE_NO_CARRIER:
            return "STATUS_CTX_MODEM_RESPONSE_NO_CARRIER";
        case STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE:
            return "STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE";
        case STATUS_CTX_MODEM_RESPONSE_BUSY:
            return "STATUS_CTX_MODEM_RESPONSE_BUSY";
        case STATUS_CTX_MODEM_RESPONSE_VOICE:
            return "STATUS_CTX_MODEM_RESPONSE_VOICE";
        case STATUS_CTX_TD_ERROR:
            return "STATUS_CTX_TD_ERROR";
        case STATUS_CTX_LICENSE_CLIENT_INVALID:
            return "STATUS_CTX_LICENSE_CLIENT_INVALID";
        case STATUS_CTX_LICENSE_NOT_AVAILABLE:
            return "STATUS_CTX_LICENSE_NOT_AVAILABLE";
        case STATUS_CTX_LICENSE_EXPIRED:
            return "STATUS_CTX_LICENSE_EXPIRED";
        case STATUS_CTX_WINSTATION_NOT_FOUND:
            return "STATUS_CTX_WINSTATION_NOT_FOUND";
        case STATUS_CTX_WINSTATION_NAME_COLLISION:
            return "STATUS_CTX_WINSTATION_NAME_COLLISION";
        case STATUS_CTX_WINSTATION_BUSY:
            return "STATUS_CTX_WINSTATION_BUSY";
        case STATUS_CTX_BAD_VIDEO_MODE:
            return "STATUS_CTX_BAD_VIDEO_MODE";
        case STATUS_CTX_GRAPHICS_INVALID:
            return "STATUS_CTX_GRAPHICS_INVALID";
        case STATUS_CTX_NOT_CONSOLE:
            return "STATUS_CTX_NOT_CONSOLE";
        case STATUS_CTX_CLIENT_QUERY_TIMEOUT:
            return "STATUS_CTX_CLIENT_QUERY_TIMEOUT";
        case STATUS_CTX_CONSOLE_DISCONNECT:
            return "STATUS_CTX_CONSOLE_DISCONNECT";
        case STATUS_CTX_CONSOLE_CONNECT:
            return "STATUS_CTX_CONSOLE_CONNECT";
        case STATUS_CTX_SHADOW_DENIED:
            return "STATUS_CTX_SHADOW_DENIED";
        case STATUS_CTX_WINSTATION_ACCESS_DENIED:
            return "STATUS_CTX_WINSTATION_ACCESS_DENIED";
        case STATUS_CTX_INVALID_WD:
            return "STATUS_CTX_INVALID_WD";
        case STATUS_CTX_WD_NOT_FOUND:
            return "STATUS_CTX_WD_NOT_FOUND";
        case STATUS_CTX_SHADOW_INVALID:
            return "STATUS_CTX_SHADOW_INVALID";
        case STATUS_CTX_SHADOW_DISABLED:
            return "STATUS_CTX_SHADOW_DISABLED";
        case STATUS_RDP_PROTOCOL_ERROR:
            return "STATUS_RDP_PROTOCOL_ERROR";
        case STATUS_CTX_CLIENT_LICENSE_NOT_SET:
            return "STATUS_CTX_CLIENT_LICENSE_NOT_SET";
        case STATUS_CTX_CLIENT_LICENSE_IN_USE:
            return "STATUS_CTX_CLIENT_LICENSE_IN_USE";
        case STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE:
            return "STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE";
        case STATUS_CTX_SHADOW_NOT_RUNNING:
            return "STATUS_CTX_SHADOW_NOT_RUNNING";
        case STATUS_CTX_LOGON_DISABLED:
            return "STATUS_CTX_LOGON_DISABLED";
        case STATUS_CTX_SECURITY_LAYER_ERROR:
            return "STATUS_CTX_SECURITY_LAYER_ERROR";
        case STATUS_TS_INCOMPATIBLE_SESSIONS:
            return "STATUS_TS_INCOMPATIBLE_SESSIONS";
        case STATUS_TS_VIDEO_SUBSYSTEM_ERROR:
            return "STATUS_TS_VIDEO_SUBSYSTEM_ERROR";
        case STATUS_PNP_BAD_MPS_TABLE:
            return "STATUS_PNP_BAD_MPS_TABLE";
        case STATUS_PNP_TRANSLATION_FAILED:
            return "STATUS_PNP_TRANSLATION_FAILED";
        case STATUS_PNP_IRQ_TRANSLATION_FAILED:
            return "STATUS_PNP_IRQ_TRANSLATION_FAILED";
        case STATUS_PNP_INVALID_ID:
            return "STATUS_PNP_INVALID_ID";
        case STATUS_IO_REISSUE_AS_CACHED:
            return "STATUS_IO_REISSUE_AS_CACHED";
        case STATUS_MUI_FILE_NOT_FOUND:
            return "STATUS_MUI_FILE_NOT_FOUND";
        case STATUS_MUI_INVALID_FILE:
            return "STATUS_MUI_INVALID_FILE";
        case STATUS_MUI_INVALID_RC_CONFIG:
            return "STATUS_MUI_INVALID_RC_CONFIG";
        case STATUS_MUI_INVALID_LOCALE_NAME:
            return "STATUS_MUI_INVALID_LOCALE_NAME";
        case STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME:
            return "STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME";
        case STATUS_MUI_FILE_NOT_LOADED:
            return "STATUS_MUI_FILE_NOT_LOADED";
        case STATUS_RESOURCE_ENUM_USER_STOP:
            return "STATUS_RESOURCE_ENUM_USER_STOP";
        case STATUS_FLT_NO_HANDLER_DEFINED:
            return "STATUS_FLT_NO_HANDLER_DEFINED";
        case STATUS_FLT_CONTEXT_ALREADY_DEFINED:
            return "STATUS_FLT_CONTEXT_ALREADY_DEFINED";
        case STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST:
            return "STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST";
        case STATUS_FLT_DISALLOW_FAST_IO:
            return "STATUS_FLT_DISALLOW_FAST_IO";
        case STATUS_FLT_INVALID_NAME_REQUEST:
            return "STATUS_FLT_INVALID_NAME_REQUEST";
        case STATUS_FLT_NOT_SAFE_TO_POST_OPERATION:
            return "STATUS_FLT_NOT_SAFE_TO_POST_OPERATION";
        case STATUS_FLT_NOT_INITIALIZED:
            return "STATUS_FLT_NOT_INITIALIZED";
        case STATUS_FLT_FILTER_NOT_READY:
            return "STATUS_FLT_FILTER_NOT_READY";
        case STATUS_FLT_POST_OPERATION_CLEANUP:
            return "STATUS_FLT_POST_OPERATION_CLEANUP";
        case STATUS_FLT_INTERNAL_ERROR:
            return "STATUS_FLT_INTERNAL_ERROR";
        case STATUS_FLT_DELETING_OBJECT:
            return "STATUS_FLT_DELETING_OBJECT";
        case STATUS_FLT_MUST_BE_NONPAGED_POOL:
            return "STATUS_FLT_MUST_BE_NONPAGED_POOL";
        case STATUS_FLT_DUPLICATE_ENTRY:
            return "STATUS_FLT_DUPLICATE_ENTRY";
        case STATUS_FLT_CBDQ_DISABLED:
            return "STATUS_FLT_CBDQ_DISABLED";
        case STATUS_FLT_DO_NOT_ATTACH:
            return "STATUS_FLT_DO_NOT_ATTACH";
        case STATUS_FLT_DO_NOT_DETACH:
            return "STATUS_FLT_DO_NOT_DETACH";
        case STATUS_FLT_INSTANCE_ALTITUDE_COLLISION:
            return "STATUS_FLT_INSTANCE_ALTITUDE_COLLISION";
        case STATUS_FLT_INSTANCE_NAME_COLLISION:
            return "STATUS_FLT_INSTANCE_NAME_COLLISION";
        case STATUS_FLT_FILTER_NOT_FOUND:
            return "STATUS_FLT_FILTER_NOT_FOUND";
        case STATUS_FLT_VOLUME_NOT_FOUND:
            return "STATUS_FLT_VOLUME_NOT_FOUND";
        case STATUS_FLT_INSTANCE_NOT_FOUND:
            return "STATUS_FLT_INSTANCE_NOT_FOUND";
        case STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND:
            return "STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND";
        case STATUS_FLT_INVALID_CONTEXT_REGISTRATION:
            return "STATUS_FLT_INVALID_CONTEXT_REGISTRATION";
        case STATUS_FLT_NAME_CACHE_MISS:
            return "STATUS_FLT_NAME_CACHE_MISS";
        case STATUS_FLT_NO_DEVICE_OBJECT:
            return "STATUS_FLT_NO_DEVICE_OBJECT";
        case STATUS_FLT_VOLUME_ALREADY_MOUNTED:
            return "STATUS_FLT_VOLUME_ALREADY_MOUNTED";
        case STATUS_FLT_ALREADY_ENLISTED:
            return "STATUS_FLT_ALREADY_ENLISTED";
        case STATUS_FLT_CONTEXT_ALREADY_LINKED:
            return "STATUS_FLT_CONTEXT_ALREADY_LINKED";
        case STATUS_FLT_NO_WAITER_FOR_REPLY:
            return "STATUS_FLT_NO_WAITER_FOR_REPLY";
        case STATUS_FLT_REGISTRATION_BUSY:
            return "STATUS_FLT_REGISTRATION_BUSY";
        case STATUS_SXS_SECTION_NOT_FOUND:
            return "STATUS_SXS_SECTION_NOT_FOUND";
        case STATUS_SXS_CANT_GEN_ACTCTX:
            return "STATUS_SXS_CANT_GEN_ACTCTX";
        case STATUS_SXS_INVALID_ACTCTXDATA_FORMAT:
            return "STATUS_SXS_INVALID_ACTCTXDATA_FORMAT";
        case STATUS_SXS_ASSEMBLY_NOT_FOUND:
            return "STATUS_SXS_ASSEMBLY_NOT_FOUND";
        case STATUS_SXS_MANIFEST_FORMAT_ERROR:
            return "STATUS_SXS_MANIFEST_FORMAT_ERROR";
        case STATUS_SXS_MANIFEST_PARSE_ERROR:
            return "STATUS_SXS_MANIFEST_PARSE_ERROR";
        case STATUS_SXS_ACTIVATION_CONTEXT_DISABLED:
            return "STATUS_SXS_ACTIVATION_CONTEXT_DISABLED";
        case STATUS_SXS_KEY_NOT_FOUND:
            return "STATUS_SXS_KEY_NOT_FOUND";
        case STATUS_SXS_VERSION_CONFLICT:
            return "STATUS_SXS_VERSION_CONFLICT";
        case STATUS_SXS_WRONG_SECTION_TYPE:
            return "STATUS_SXS_WRONG_SECTION_TYPE";
        case STATUS_SXS_THREAD_QUERIES_DISABLED:
            return "STATUS_SXS_THREAD_QUERIES_DISABLED";
        case STATUS_SXS_ASSEMBLY_MISSING:
            return "STATUS_SXS_ASSEMBLY_MISSING";
        case STATUS_SXS_RELEASE_ACTIVATION_CONTEXT:
            return "STATUS_SXS_RELEASE_ACTIVATION_CONTEXT";
        case STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET:
            return "STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET";
        case STATUS_SXS_EARLY_DEACTIVATION:
            return "STATUS_SXS_EARLY_DEACTIVATION";
        case STATUS_SXS_INVALID_DEACTIVATION:
            return "STATUS_SXS_INVALID_DEACTIVATION";
        case STATUS_SXS_MULTIPLE_DEACTIVATION:
            return "STATUS_SXS_MULTIPLE_DEACTIVATION";
        case STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY:
            return "STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY";
        case STATUS_SXS_PROCESS_TERMINATION_REQUESTED:
            return "STATUS_SXS_PROCESS_TERMINATION_REQUESTED";
        case STATUS_SXS_CORRUPT_ACTIVATION_STACK:
            return "STATUS_SXS_CORRUPT_ACTIVATION_STACK";
        case STATUS_SXS_CORRUPTION:
            return "STATUS_SXS_CORRUPTION";
        case STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE:
            return "STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE";
        case STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME:
            return "STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME";
        case STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE:
            return "STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE";
        case STATUS_SXS_IDENTITY_PARSE_ERROR:
            return "STATUS_SXS_IDENTITY_PARSE_ERROR";
        case STATUS_SXS_COMPONENT_STORE_CORRUPT:
            return "STATUS_SXS_COMPONENT_STORE_CORRUPT";
        case STATUS_SXS_FILE_HASH_MISMATCH:
            return "STATUS_SXS_FILE_HASH_MISMATCH";
        case STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT:
            return "STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT";
        case STATUS_SXS_IDENTITIES_DIFFERENT:
            return "STATUS_SXS_IDENTITIES_DIFFERENT";
        case STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT:
            return "STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT";
        case STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY:
            return "STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY";
        case STATUS_ADVANCED_INSTALLER_FAILED:
            return "STATUS_ADVANCED_INSTALLER_FAILED";
        case STATUS_XML_ENCODING_MISMATCH:
            return "STATUS_XML_ENCODING_MISMATCH";
        case STATUS_SXS_MANIFEST_TOO_BIG:
            return "STATUS_SXS_MANIFEST_TOO_BIG";
        case STATUS_SXS_SETTING_NOT_REGISTERED:
            return "STATUS_SXS_SETTING_NOT_REGISTERED";
        case STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE:
            return "STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE";
        case STATUS_SMI_PRIMITIVE_INSTALLER_FAILED:
            return "STATUS_SMI_PRIMITIVE_INSTALLER_FAILED";
        case STATUS_GENERIC_COMMAND_FAILED:
            return "STATUS_GENERIC_COMMAND_FAILED";
        case STATUS_SXS_FILE_HASH_MISSING:
            return "STATUS_SXS_FILE_HASH_MISSING";
        case STATUS_CLUSTER_INVALID_NODE:
            return "STATUS_CLUSTER_INVALID_NODE";
        case STATUS_CLUSTER_NODE_EXISTS:
            return "STATUS_CLUSTER_NODE_EXISTS";
        case STATUS_CLUSTER_JOIN_IN_PROGRESS:
            return "STATUS_CLUSTER_JOIN_IN_PROGRESS";
        case STATUS_CLUSTER_NODE_NOT_FOUND:
            return "STATUS_CLUSTER_NODE_NOT_FOUND";
        case STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND:
            return "STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND";
        case STATUS_CLUSTER_NETWORK_EXISTS:
            return "STATUS_CLUSTER_NETWORK_EXISTS";
        case STATUS_CLUSTER_NETWORK_NOT_FOUND:
            return "STATUS_CLUSTER_NETWORK_NOT_FOUND";
        case STATUS_CLUSTER_NETINTERFACE_EXISTS:
            return "STATUS_CLUSTER_NETINTERFACE_EXISTS";
        case STATUS_CLUSTER_NETINTERFACE_NOT_FOUND:
            return "STATUS_CLUSTER_NETINTERFACE_NOT_FOUND";
        case STATUS_CLUSTER_INVALID_REQUEST:
            return "STATUS_CLUSTER_INVALID_REQUEST";
        case STATUS_CLUSTER_INVALID_NETWORK_PROVIDER:
            return "STATUS_CLUSTER_INVALID_NETWORK_PROVIDER";
        case STATUS_CLUSTER_NODE_DOWN:
            return "STATUS_CLUSTER_NODE_DOWN";
        case STATUS_CLUSTER_NODE_UNREACHABLE:
            return "STATUS_CLUSTER_NODE_UNREACHABLE";
        case STATUS_CLUSTER_NODE_NOT_MEMBER:
            return "STATUS_CLUSTER_NODE_NOT_MEMBER";
        case STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS:
            return "STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS";
        case STATUS_CLUSTER_INVALID_NETWORK:
            return "STATUS_CLUSTER_INVALID_NETWORK";
        case STATUS_CLUSTER_NO_NET_ADAPTERS:
            return "STATUS_CLUSTER_NO_NET_ADAPTERS";
        case STATUS_CLUSTER_NODE_UP:
            return "STATUS_CLUSTER_NODE_UP";
        case STATUS_CLUSTER_NODE_PAUSED:
            return "STATUS_CLUSTER_NODE_PAUSED";
        case STATUS_CLUSTER_NODE_NOT_PAUSED:
            return "STATUS_CLUSTER_NODE_NOT_PAUSED";
        case STATUS_CLUSTER_NO_SECURITY_CONTEXT:
            return "STATUS_CLUSTER_NO_SECURITY_CONTEXT";
        case STATUS_CLUSTER_NETWORK_NOT_INTERNAL:
            return "STATUS_CLUSTER_NETWORK_NOT_INTERNAL";
        case STATUS_CLUSTER_POISONED:
            return "STATUS_CLUSTER_POISONED";
        case STATUS_CLUSTER_NON_CSV_PATH:
            return "STATUS_CLUSTER_NON_CSV_PATH";
        case STATUS_CLUSTER_CSV_VOLUME_NOT_LOCAL:
            return "STATUS_CLUSTER_CSV_VOLUME_NOT_LOCAL";
        case STATUS_CLUSTER_CSV_READ_OPLOCK_BREAK_IN_PROGRESS:
            return "STATUS_CLUSTER_CSV_READ_OPLOCK_BREAK_IN_PROGRESS";
        case STATUS_CLUSTER_CSV_AUTO_PAUSE_ERROR:
            return "STATUS_CLUSTER_CSV_AUTO_PAUSE_ERROR";
        case STATUS_CLUSTER_CSV_REDIRECTED:
            return "STATUS_CLUSTER_CSV_REDIRECTED";
        case STATUS_CLUSTER_CSV_NOT_REDIRECTED:
            return "STATUS_CLUSTER_CSV_NOT_REDIRECTED";
        case STATUS_CLUSTER_CSV_VOLUME_DRAINING:
            return "STATUS_CLUSTER_CSV_VOLUME_DRAINING";
        case STATUS_CLUSTER_CSV_SNAPSHOT_CREATION_IN_PROGRESS:
            return "STATUS_CLUSTER_CSV_SNAPSHOT_CREATION_IN_PROGRESS";
        case STATUS_CLUSTER_CSV_VOLUME_DRAINING_SUCCEEDED_DOWNLEVEL:
            return "STATUS_CLUSTER_CSV_VOLUME_DRAINING_SUCCEEDED_DOWNLEVEL";
        case STATUS_CLUSTER_CSV_NO_SNAPSHOTS:
            return "STATUS_CLUSTER_CSV_NO_SNAPSHOTS";
        case STATUS_CSV_IO_PAUSE_TIMEOUT:
            return "STATUS_CSV_IO_PAUSE_TIMEOUT";
        case STATUS_CLUSTER_CSV_INVALID_HANDLE:
            return "STATUS_CLUSTER_CSV_INVALID_HANDLE";
        case STATUS_CLUSTER_CSV_SUPPORTED_ONLY_ON_COORDINATOR:
            return "STATUS_CLUSTER_CSV_SUPPORTED_ONLY_ON_COORDINATOR";
        case STATUS_CLUSTER_CAM_TICKET_REPLAY_DETECTED:
            return "STATUS_CLUSTER_CAM_TICKET_REPLAY_DETECTED";
        case STATUS_TRANSACTIONAL_CONFLICT:
            return "STATUS_TRANSACTIONAL_CONFLICT";
        case STATUS_INVALID_TRANSACTION:
            return "STATUS_INVALID_TRANSACTION";
        case STATUS_TRANSACTION_NOT_ACTIVE:
            return "STATUS_TRANSACTION_NOT_ACTIVE";
        case STATUS_TM_INITIALIZATION_FAILED:
            return "STATUS_TM_INITIALIZATION_FAILED";
        case STATUS_RM_NOT_ACTIVE:
            return "STATUS_RM_NOT_ACTIVE";
        case STATUS_RM_METADATA_CORRUPT:
            return "STATUS_RM_METADATA_CORRUPT";
        case STATUS_TRANSACTION_NOT_JOINED:
            return "STATUS_TRANSACTION_NOT_JOINED";
        case STATUS_DIRECTORY_NOT_RM:
            return "STATUS_DIRECTORY_NOT_RM";
        case STATUS_COULD_NOT_RESIZE_LOG:
            return "STATUS_COULD_NOT_RESIZE_LOG";
        case STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE:
            return "STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE";
        case STATUS_LOG_RESIZE_INVALID_SIZE:
            return "STATUS_LOG_RESIZE_INVALID_SIZE";
        case STATUS_REMOTE_FILE_VERSION_MISMATCH:
            return "STATUS_REMOTE_FILE_VERSION_MISMATCH";
        case STATUS_CRM_PROTOCOL_ALREADY_EXISTS:
            return "STATUS_CRM_PROTOCOL_ALREADY_EXISTS";
        case STATUS_TRANSACTION_PROPAGATION_FAILED:
            return "STATUS_TRANSACTION_PROPAGATION_FAILED";
        case STATUS_CRM_PROTOCOL_NOT_FOUND:
            return "STATUS_CRM_PROTOCOL_NOT_FOUND";
        case STATUS_TRANSACTION_SUPERIOR_EXISTS:
            return "STATUS_TRANSACTION_SUPERIOR_EXISTS";
        case STATUS_TRANSACTION_REQUEST_NOT_VALID:
            return "STATUS_TRANSACTION_REQUEST_NOT_VALID";
        case STATUS_TRANSACTION_NOT_REQUESTED:
            return "STATUS_TRANSACTION_NOT_REQUESTED";
        case STATUS_TRANSACTION_ALREADY_ABORTED:
            return "STATUS_TRANSACTION_ALREADY_ABORTED";
        case STATUS_TRANSACTION_ALREADY_COMMITTED:
            return "STATUS_TRANSACTION_ALREADY_COMMITTED";
        case STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER:
            return "STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER";
        case STATUS_CURRENT_TRANSACTION_NOT_VALID:
            return "STATUS_CURRENT_TRANSACTION_NOT_VALID";
        case STATUS_LOG_GROWTH_FAILED:
            return "STATUS_LOG_GROWTH_FAILED";
        case STATUS_OBJECT_NO_LONGER_EXISTS:
            return "STATUS_OBJECT_NO_LONGER_EXISTS";
        case STATUS_STREAM_MINIVERSION_NOT_FOUND:
            return "STATUS_STREAM_MINIVERSION_NOT_FOUND";
        case STATUS_STREAM_MINIVERSION_NOT_VALID:
            return "STATUS_STREAM_MINIVERSION_NOT_VALID";
        case STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION:
            return "STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION";
        case STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT:
            return "STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT";
        case STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS:
            return "STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS";
        case STATUS_HANDLE_NO_LONGER_VALID:
            return "STATUS_HANDLE_NO_LONGER_VALID";
        case STATUS_NO_TXF_METADATA:
            return "STATUS_NO_TXF_METADATA";
        case STATUS_LOG_CORRUPTION_DETECTED:
            return "STATUS_LOG_CORRUPTION_DETECTED";
        case STATUS_CANT_RECOVER_WITH_HANDLE_OPEN:
            return "STATUS_CANT_RECOVER_WITH_HANDLE_OPEN";
        case STATUS_RM_DISCONNECTED:
            return "STATUS_RM_DISCONNECTED";
        case STATUS_ENLISTMENT_NOT_SUPERIOR:
            return "STATUS_ENLISTMENT_NOT_SUPERIOR";
        case STATUS_RECOVERY_NOT_NEEDED:
            return "STATUS_RECOVERY_NOT_NEEDED";
        case STATUS_RM_ALREADY_STARTED:
            return "STATUS_RM_ALREADY_STARTED";
        case STATUS_FILE_IDENTITY_NOT_PERSISTENT:
            return "STATUS_FILE_IDENTITY_NOT_PERSISTENT";
        case STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY:
            return "STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY";
        case STATUS_CANT_CROSS_RM_BOUNDARY:
            return "STATUS_CANT_CROSS_RM_BOUNDARY";
        case STATUS_TXF_DIR_NOT_EMPTY:
            return "STATUS_TXF_DIR_NOT_EMPTY";
        case STATUS_INDOUBT_TRANSACTIONS_EXIST:
            return "STATUS_INDOUBT_TRANSACTIONS_EXIST";
        case STATUS_TM_VOLATILE:
            return "STATUS_TM_VOLATILE";
        case STATUS_ROLLBACK_TIMER_EXPIRED:
            return "STATUS_ROLLBACK_TIMER_EXPIRED";
        case STATUS_TXF_ATTRIBUTE_CORRUPT:
            return "STATUS_TXF_ATTRIBUTE_CORRUPT";
        case STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION:
            return "STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION";
        case STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED:
            return "STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED";
        case STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE:
            return "STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE";
        case STATUS_TXF_METADATA_ALREADY_PRESENT:
            return "STATUS_TXF_METADATA_ALREADY_PRESENT";
        case STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET:
            return "STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET";
        case STATUS_TRANSACTION_REQUIRED_PROMOTION:
            return "STATUS_TRANSACTION_REQUIRED_PROMOTION";
        case STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION:
            return "STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION";
        case STATUS_TRANSACTIONS_NOT_FROZEN:
            return "STATUS_TRANSACTIONS_NOT_FROZEN";
        case STATUS_TRANSACTION_FREEZE_IN_PROGRESS:
            return "STATUS_TRANSACTION_FREEZE_IN_PROGRESS";
        case STATUS_NOT_SNAPSHOT_VOLUME:
            return "STATUS_NOT_SNAPSHOT_VOLUME";
        case STATUS_NO_SAVEPOINT_WITH_OPEN_FILES:
            return "STATUS_NO_SAVEPOINT_WITH_OPEN_FILES";
        case STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION:
            return "STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION";
        case STATUS_TM_IDENTITY_MISMATCH:
            return "STATUS_TM_IDENTITY_MISMATCH";
        case STATUS_FLOATED_SECTION:
            return "STATUS_FLOATED_SECTION";
        case STATUS_CANNOT_ACCEPT_TRANSACTED_WORK:
            return "STATUS_CANNOT_ACCEPT_TRANSACTED_WORK";
        case STATUS_CANNOT_ABORT_TRANSACTIONS:
            return "STATUS_CANNOT_ABORT_TRANSACTIONS";
        case STATUS_TRANSACTION_NOT_FOUND:
            return "STATUS_TRANSACTION_NOT_FOUND";
        case STATUS_RESOURCEMANAGER_NOT_FOUND:
            return "STATUS_RESOURCEMANAGER_NOT_FOUND";
        case STATUS_ENLISTMENT_NOT_FOUND:
            return "STATUS_ENLISTMENT_NOT_FOUND";
        case STATUS_TRANSACTIONMANAGER_NOT_FOUND:
            return "STATUS_TRANSACTIONMANAGER_NOT_FOUND";
        case STATUS_TRANSACTIONMANAGER_NOT_ONLINE:
            return "STATUS_TRANSACTIONMANAGER_NOT_ONLINE";
        case STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION:
            return "STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION";
        case STATUS_TRANSACTION_NOT_ROOT:
            return "STATUS_TRANSACTION_NOT_ROOT";
        case STATUS_TRANSACTION_OBJECT_EXPIRED:
            return "STATUS_TRANSACTION_OBJECT_EXPIRED";
        case STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION:
            return "STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION";
        case STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED:
            return "STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED";
        case STATUS_TRANSACTION_RECORD_TOO_LONG:
            return "STATUS_TRANSACTION_RECORD_TOO_LONG";
        case STATUS_NO_LINK_TRACKING_IN_TRANSACTION:
            return "STATUS_NO_LINK_TRACKING_IN_TRANSACTION";
        case STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION:
            return "STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION";
        case STATUS_TRANSACTION_INTEGRITY_VIOLATED:
            return "STATUS_TRANSACTION_INTEGRITY_VIOLATED";
        case STATUS_TRANSACTIONMANAGER_IDENTITY_MISMATCH:
            return "STATUS_TRANSACTIONMANAGER_IDENTITY_MISMATCH";
        case STATUS_RM_CANNOT_BE_FROZEN_FOR_SNAPSHOT:
            return "STATUS_RM_CANNOT_BE_FROZEN_FOR_SNAPSHOT";
        case STATUS_TRANSACTION_MUST_WRITETHROUGH:
            return "STATUS_TRANSACTION_MUST_WRITETHROUGH";
        case STATUS_TRANSACTION_NO_SUPERIOR:
            return "STATUS_TRANSACTION_NO_SUPERIOR";
        case STATUS_EXPIRED_HANDLE:
            return "STATUS_EXPIRED_HANDLE";
        case STATUS_TRANSACTION_NOT_ENLISTED:
            return "STATUS_TRANSACTION_NOT_ENLISTED";
        case STATUS_LOG_SECTOR_INVALID:
            return "STATUS_LOG_SECTOR_INVALID";
        case STATUS_LOG_SECTOR_PARITY_INVALID:
            return "STATUS_LOG_SECTOR_PARITY_INVALID";
        case STATUS_LOG_SECTOR_REMAPPED:
            return "STATUS_LOG_SECTOR_REMAPPED";
        case STATUS_LOG_BLOCK_INCOMPLETE:
            return "STATUS_LOG_BLOCK_INCOMPLETE";
        case STATUS_LOG_INVALID_RANGE:
            return "STATUS_LOG_INVALID_RANGE";
        case STATUS_LOG_BLOCKS_EXHAUSTED:
            return "STATUS_LOG_BLOCKS_EXHAUSTED";
        case STATUS_LOG_READ_CONTEXT_INVALID:
            return "STATUS_LOG_READ_CONTEXT_INVALID";
        case STATUS_LOG_RESTART_INVALID:
            return "STATUS_LOG_RESTART_INVALID";
        case STATUS_LOG_BLOCK_VERSION:
            return "STATUS_LOG_BLOCK_VERSION";
        case STATUS_LOG_BLOCK_INVALID:
            return "STATUS_LOG_BLOCK_INVALID";
        case STATUS_LOG_READ_MODE_INVALID:
            return "STATUS_LOG_READ_MODE_INVALID";
        case STATUS_LOG_NO_RESTART:
            return "STATUS_LOG_NO_RESTART";
        case STATUS_LOG_METADATA_CORRUPT:
            return "STATUS_LOG_METADATA_CORRUPT";
        case STATUS_LOG_METADATA_INVALID:
            return "STATUS_LOG_METADATA_INVALID";
        case STATUS_LOG_METADATA_INCONSISTENT:
            return "STATUS_LOG_METADATA_INCONSISTENT";
        case STATUS_LOG_RESERVATION_INVALID:
            return "STATUS_LOG_RESERVATION_INVALID";
        case STATUS_LOG_CANT_DELETE:
            return "STATUS_LOG_CANT_DELETE";
        case STATUS_LOG_CONTAINER_LIMIT_EXCEEDED:
            return "STATUS_LOG_CONTAINER_LIMIT_EXCEEDED";
        case STATUS_LOG_START_OF_LOG:
            return "STATUS_LOG_START_OF_LOG";
        case STATUS_LOG_POLICY_ALREADY_INSTALLED:
            return "STATUS_LOG_POLICY_ALREADY_INSTALLED";
        case STATUS_LOG_POLICY_NOT_INSTALLED:
            return "STATUS_LOG_POLICY_NOT_INSTALLED";
        case STATUS_LOG_POLICY_INVALID:
            return "STATUS_LOG_POLICY_INVALID";
        case STATUS_LOG_POLICY_CONFLICT:
            return "STATUS_LOG_POLICY_CONFLICT";
        case STATUS_LOG_PINNED_ARCHIVE_TAIL:
            return "STATUS_LOG_PINNED_ARCHIVE_TAIL";
        case STATUS_LOG_RECORD_NONEXISTENT:
            return "STATUS_LOG_RECORD_NONEXISTENT";
        case STATUS_LOG_RECORDS_RESERVED_INVALID:
            return "STATUS_LOG_RECORDS_RESERVED_INVALID";
        case STATUS_LOG_SPACE_RESERVED_INVALID:
            return "STATUS_LOG_SPACE_RESERVED_INVALID";
        case STATUS_LOG_TAIL_INVALID:
            return "STATUS_LOG_TAIL_INVALID";
        case STATUS_LOG_FULL:
            return "STATUS_LOG_FULL";
        case STATUS_LOG_MULTIPLEXED:
            return "STATUS_LOG_MULTIPLEXED";
        case STATUS_LOG_DEDICATED:
            return "STATUS_LOG_DEDICATED";
        case STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS:
            return "STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS";
        case STATUS_LOG_ARCHIVE_IN_PROGRESS:
            return "STATUS_LOG_ARCHIVE_IN_PROGRESS";
        case STATUS_LOG_EPHEMERAL:
            return "STATUS_LOG_EPHEMERAL";
        case STATUS_LOG_NOT_ENOUGH_CONTAINERS:
            return "STATUS_LOG_NOT_ENOUGH_CONTAINERS";
        case STATUS_LOG_CLIENT_ALREADY_REGISTERED:
            return "STATUS_LOG_CLIENT_ALREADY_REGISTERED";
        case STATUS_LOG_CLIENT_NOT_REGISTERED:
            return "STATUS_LOG_CLIENT_NOT_REGISTERED";
        case STATUS_LOG_FULL_HANDLER_IN_PROGRESS:
            return "STATUS_LOG_FULL_HANDLER_IN_PROGRESS";
        case STATUS_LOG_CONTAINER_READ_FAILED:
            return "STATUS_LOG_CONTAINER_READ_FAILED";
        case STATUS_LOG_CONTAINER_WRITE_FAILED:
            return "STATUS_LOG_CONTAINER_WRITE_FAILED";
        case STATUS_LOG_CONTAINER_OPEN_FAILED:
            return "STATUS_LOG_CONTAINER_OPEN_FAILED";
        case STATUS_LOG_CONTAINER_STATE_INVALID:
            return "STATUS_LOG_CONTAINER_STATE_INVALID";
        case STATUS_LOG_STATE_INVALID:
            return "STATUS_LOG_STATE_INVALID";
        case STATUS_LOG_PINNED:
            return "STATUS_LOG_PINNED";
        case STATUS_LOG_METADATA_FLUSH_FAILED:
            return "STATUS_LOG_METADATA_FLUSH_FAILED";
        case STATUS_LOG_INCONSISTENT_SECURITY:
            return "STATUS_LOG_INCONSISTENT_SECURITY";
        case STATUS_LOG_APPENDED_FLUSH_FAILED:
            return "STATUS_LOG_APPENDED_FLUSH_FAILED";
        case STATUS_LOG_PINNED_RESERVATION:
            return "STATUS_LOG_PINNED_RESERVATION";
        case STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD:
            return "STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD";
        case STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED:
            return "STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED";
        case STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST:
            return "STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST";
        case STATUS_MONITOR_NO_DESCRIPTOR:
            return "STATUS_MONITOR_NO_DESCRIPTOR";
        case STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT:
            return "STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT";
        case STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM:
            return "STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM";
        case STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK:
            return "STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK";
        case STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED:
            return "STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED";
        case STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK:
            return "STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK";
        case STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK:
            return "STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK";
        case STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA:
            return "STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA";
        case STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK:
            return "STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK";
        case STATUS_MONITOR_INVALID_MANUFACTURE_DATE:
            return "STATUS_MONITOR_INVALID_MANUFACTURE_DATE";
        case STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER:
            return "STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER";
        case STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER:
            return "STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER";
        case STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER:
            return "STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER";
        case STATUS_GRAPHICS_ADAPTER_WAS_RESET:
            return "STATUS_GRAPHICS_ADAPTER_WAS_RESET";
        case STATUS_GRAPHICS_INVALID_DRIVER_MODEL:
            return "STATUS_GRAPHICS_INVALID_DRIVER_MODEL";
        case STATUS_GRAPHICS_PRESENT_MODE_CHANGED:
            return "STATUS_GRAPHICS_PRESENT_MODE_CHANGED";
        case STATUS_GRAPHICS_PRESENT_OCCLUDED:
            return "STATUS_GRAPHICS_PRESENT_OCCLUDED";
        case STATUS_GRAPHICS_PRESENT_DENIED:
            return "STATUS_GRAPHICS_PRESENT_DENIED";
        case STATUS_GRAPHICS_CANNOTCOLORCONVERT:
            return "STATUS_GRAPHICS_CANNOTCOLORCONVERT";
        case STATUS_GRAPHICS_DRIVER_MISMATCH:
            return "STATUS_GRAPHICS_DRIVER_MISMATCH";
        case STATUS_GRAPHICS_PARTIAL_DATA_POPULATED:
            return "STATUS_GRAPHICS_PARTIAL_DATA_POPULATED";
        case STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED:
            return "STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED";
        case STATUS_GRAPHICS_PRESENT_UNOCCLUDED:
            return "STATUS_GRAPHICS_PRESENT_UNOCCLUDED";
        case STATUS_GRAPHICS_WINDOWDC_NOT_AVAILABLE:
            return "STATUS_GRAPHICS_WINDOWDC_NOT_AVAILABLE";
        case STATUS_GRAPHICS_WINDOWLESS_PRESENT_DISABLED:
            return "STATUS_GRAPHICS_WINDOWLESS_PRESENT_DISABLED";
        case STATUS_GRAPHICS_PRESENT_INVALID_WINDOW:
            return "STATUS_GRAPHICS_PRESENT_INVALID_WINDOW";
        case STATUS_GRAPHICS_PRESENT_BUFFER_NOT_BOUND:
            return "STATUS_GRAPHICS_PRESENT_BUFFER_NOT_BOUND";
        case STATUS_GRAPHICS_VAIL_STATE_CHANGED:
            return "STATUS_GRAPHICS_VAIL_STATE_CHANGED";
        case STATUS_GRAPHICS_NO_VIDEO_MEMORY:
            return "STATUS_GRAPHICS_NO_VIDEO_MEMORY";
        case STATUS_GRAPHICS_CANT_LOCK_MEMORY:
            return "STATUS_GRAPHICS_CANT_LOCK_MEMORY";
        case STATUS_GRAPHICS_ALLOCATION_BUSY:
            return "STATUS_GRAPHICS_ALLOCATION_BUSY";
        case STATUS_GRAPHICS_TOO_MANY_REFERENCES:
            return "STATUS_GRAPHICS_TOO_MANY_REFERENCES";
        case STATUS_GRAPHICS_TRY_AGAIN_LATER:
            return "STATUS_GRAPHICS_TRY_AGAIN_LATER";
        case STATUS_GRAPHICS_TRY_AGAIN_NOW:
            return "STATUS_GRAPHICS_TRY_AGAIN_NOW";
        case STATUS_GRAPHICS_ALLOCATION_INVALID:
            return "STATUS_GRAPHICS_ALLOCATION_INVALID";
        case STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE:
            return "STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE";
        case STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED:
            return "STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED";
        case STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION:
            return "STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION";
        case STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE:
            return "STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE";
        case STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION:
            return "STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION";
        case STATUS_GRAPHICS_ALLOCATION_CLOSED:
            return "STATUS_GRAPHICS_ALLOCATION_CLOSED";
        case STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE:
            return "STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE";
        case STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE:
            return "STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE";
        case STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE:
            return "STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE";
        case STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST:
            return "STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST";
        case STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE:
            return "STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE";
        case STATUS_GRAPHICS_SKIP_ALLOCATION_PREPARATION:
            return "STATUS_GRAPHICS_SKIP_ALLOCATION_PREPARATION";
        case STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY:
            return "STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY";
        case STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED";
        case STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED";
        case STATUS_GRAPHICS_INVALID_VIDPN:
            return "STATUS_GRAPHICS_INVALID_VIDPN";
        case STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE:
            return "STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE";
        case STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET:
            return "STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET";
        case STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED";
        case STATUS_GRAPHICS_MODE_NOT_PINNED:
            return "STATUS_GRAPHICS_MODE_NOT_PINNED";
        case STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET:
            return "STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET";
        case STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET:
            return "STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET";
        case STATUS_GRAPHICS_INVALID_FREQUENCY:
            return "STATUS_GRAPHICS_INVALID_FREQUENCY";
        case STATUS_GRAPHICS_INVALID_ACTIVE_REGION:
            return "STATUS_GRAPHICS_INVALID_ACTIVE_REGION";
        case STATUS_GRAPHICS_INVALID_TOTAL_REGION:
            return "STATUS_GRAPHICS_INVALID_TOTAL_REGION";
        case STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE:
            return "STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE";
        case STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE:
            return "STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE";
        case STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET:
            return "STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET";
        case STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY:
            return "STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY";
        case STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET:
            return "STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET";
        case STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET:
            return "STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET";
        case STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET:
            return "STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET";
        case STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET:
            return "STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET";
        case STATUS_GRAPHICS_TARGET_ALREADY_IN_SET:
            return "STATUS_GRAPHICS_TARGET_ALREADY_IN_SET";
        case STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH:
            return "STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH";
        case STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY:
            return "STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY";
        case STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET:
            return "STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET";
        case STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE:
            return "STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE";
        case STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET:
            return "STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET";
        case STATUS_GRAPHICS_NO_PREFERRED_MODE:
            return "STATUS_GRAPHICS_NO_PREFERRED_MODE";
        case STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET:
            return "STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET";
        case STATUS_GRAPHICS_STALE_MODESET:
            return "STATUS_GRAPHICS_STALE_MODESET";
        case STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET:
            return "STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET";
        case STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE:
            return "STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE";
        case STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN:
            return "STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN";
        case STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE:
            return "STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE";
        case STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION:
            return "STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION";
        case STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES:
            return "STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES";
        case STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY:
            return "STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY";
        case STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE:
            return "STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE";
        case STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET:
            return "STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET";
        case STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET:
            return "STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET";
        case STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR:
            return "STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR";
        case STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET:
            return "STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET";
        case STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET:
            return "STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET";
        case STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE:
            return "STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE";
        case STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE:
            return "STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE";
        case STATUS_GRAPHICS_RESOURCES_NOT_RELATED:
            return "STATUS_GRAPHICS_RESOURCES_NOT_RELATED";
        case STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE:
            return "STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE";
        case STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE:
            return "STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE";
        case STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET:
            return "STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET";
        case STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER:
            return "STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER";
        case STATUS_GRAPHICS_NO_VIDPNMGR:
            return "STATUS_GRAPHICS_NO_VIDPNMGR";
        case STATUS_GRAPHICS_NO_ACTIVE_VIDPN:
            return "STATUS_GRAPHICS_NO_ACTIVE_VIDPN";
        case STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY:
            return "STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY";
        case STATUS_GRAPHICS_MONITOR_NOT_CONNECTED:
            return "STATUS_GRAPHICS_MONITOR_NOT_CONNECTED";
        case STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY:
            return "STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY";
        case STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE:
            return "STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE";
        case STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE:
            return "STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE";
        case STATUS_GRAPHICS_INVALID_STRIDE:
            return "STATUS_GRAPHICS_INVALID_STRIDE";
        case STATUS_GRAPHICS_INVALID_PIXELFORMAT:
            return "STATUS_GRAPHICS_INVALID_PIXELFORMAT";
        case STATUS_GRAPHICS_INVALID_COLORBASIS:
            return "STATUS_GRAPHICS_INVALID_COLORBASIS";
        case STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE:
            return "STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE";
        case STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY:
            return "STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY";
        case STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT:
            return "STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT";
        case STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE:
            return "STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE";
        case STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN:
            return "STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN";
        case STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL:
            return "STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL";
        case STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION:
            return "STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION";
        case STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED";
        case STATUS_GRAPHICS_INVALID_GAMMA_RAMP:
            return "STATUS_GRAPHICS_INVALID_GAMMA_RAMP";
        case STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED";
        case STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED";
        case STATUS_GRAPHICS_MODE_NOT_IN_MODESET:
            return "STATUS_GRAPHICS_MODE_NOT_IN_MODESET";
        case STATUS_GRAPHICS_DATASET_IS_EMPTY:
            return "STATUS_GRAPHICS_DATASET_IS_EMPTY";
        case STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET:
            return "STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET";
        case STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON:
            return "STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON";
        case STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE:
            return "STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE";
        case STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE:
            return "STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE";
        case STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS:
            return "STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS";
        case STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED:
            return "STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED";
        case STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING:
            return "STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING";
        case STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED:
            return "STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED";
        case STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS:
            return "STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS";
        case STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT:
            return "STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT";
        case STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM:
            return "STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM";
        case STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN:
            return "STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN";
        case STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT:
            return "STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT";
        case STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED:
            return "STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED";
        case STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION:
            return "STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION";
        case STATUS_GRAPHICS_INVALID_CLIENT_TYPE:
            return "STATUS_GRAPHICS_INVALID_CLIENT_TYPE";
        case STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET:
            return "STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET";
        case STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED:
            return "STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED";
        case STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED";
        case STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS:
            return "STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS";
        case STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER:
            return "STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER";
        case STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED:
            return "STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED";
        case STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED:
            return "STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED";
        case STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY:
            return "STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY";
        case STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED:
            return "STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED";
        case STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON:
            return "STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON";
        case STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE:
            return "STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE";
        case STATUS_GRAPHICS_LEADLINK_START_DEFERRED:
            return "STATUS_GRAPHICS_LEADLINK_START_DEFERRED";
        case STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER:
            return "STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER";
        case STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY:
            return "STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY";
        case STATUS_GRAPHICS_START_DEFERRED:
            return "STATUS_GRAPHICS_START_DEFERRED";
        case STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED:
            return "STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED";
        case STATUS_GRAPHICS_DEPENDABLE_CHILD_STATUS:
            return "STATUS_GRAPHICS_DEPENDABLE_CHILD_STATUS";
        case STATUS_GRAPHICS_OPM_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_OPM_NOT_SUPPORTED";
        case STATUS_GRAPHICS_COPP_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_COPP_NOT_SUPPORTED";
        case STATUS_GRAPHICS_UAB_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_UAB_NOT_SUPPORTED";
        case STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS:
            return "STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS";
        case STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST:
            return "STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST";
        case STATUS_GRAPHICS_OPM_INTERNAL_ERROR:
            return "STATUS_GRAPHICS_OPM_INTERNAL_ERROR";
        case STATUS_GRAPHICS_OPM_INVALID_HANDLE:
            return "STATUS_GRAPHICS_OPM_INVALID_HANDLE";
        case STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH:
            return "STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH";
        case STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED:
            return "STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED";
        case STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED:
            return "STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED";
        case STATUS_GRAPHICS_PVP_HFS_FAILED:
            return "STATUS_GRAPHICS_PVP_HFS_FAILED";
        case STATUS_GRAPHICS_OPM_INVALID_SRM:
            return "STATUS_GRAPHICS_OPM_INVALID_SRM";
        case STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP:
            return "STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP";
        case STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP:
            return "STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP";
        case STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA:
            return "STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA";
        case STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET:
            return "STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET";
        case STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH:
            return "STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH";
        case STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE:
            return "STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE";
        case STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS:
            return "STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS";
        case STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS:
            return "STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS";
        case STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST:
            return "STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST";
        case STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR:
            return "STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR";
        case STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS:
            return "STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS";
        case STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED";
        case STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST:
            return "STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST";
        case STATUS_GRAPHICS_I2C_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_I2C_NOT_SUPPORTED";
        case STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST:
            return "STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST";
        case STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA:
            return "STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA";
        case STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA:
            return "STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA";
        case STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED";
        case STATUS_GRAPHICS_DDCCI_INVALID_DATA:
            return "STATUS_GRAPHICS_DDCCI_INVALID_DATA";
        case STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE:
            return "STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE";
        case STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING:
            return "STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING";
        case STATUS_GRAPHICS_MCA_INTERNAL_ERROR:
            return "STATUS_GRAPHICS_MCA_INTERNAL_ERROR";
        case STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND:
            return "STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND";
        case STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH:
            return "STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH";
        case STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM:
            return "STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM";
        case STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE:
            return "STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE";
        case STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS:
            return "STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS";
        case STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED:
            return "STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED";
        case STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME:
            return "STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME";
        case STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP:
            return "STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP";
        case STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED:
            return "STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED";
        case STATUS_GRAPHICS_INVALID_POINTER:
            return "STATUS_GRAPHICS_INVALID_POINTER";
        case STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE:
            return "STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE";
        case STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL:
            return "STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL";
        case STATUS_GRAPHICS_INTERNAL_ERROR:
            return "STATUS_GRAPHICS_INTERNAL_ERROR";
        case STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS:
            return "STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS";
        case STATUS_FVE_LOCKED_VOLUME:
            return "STATUS_FVE_LOCKED_VOLUME";
        case STATUS_FVE_NOT_ENCRYPTED:
            return "STATUS_FVE_NOT_ENCRYPTED";
        case STATUS_FVE_BAD_INFORMATION:
            return "STATUS_FVE_BAD_INFORMATION";
        case STATUS_FVE_TOO_SMALL:
            return "STATUS_FVE_TOO_SMALL";
        case STATUS_FVE_FAILED_WRONG_FS:
            return "STATUS_FVE_FAILED_WRONG_FS";
        case STATUS_FVE_BAD_PARTITION_SIZE:
            return "STATUS_FVE_BAD_PARTITION_SIZE";
        case STATUS_FVE_FS_NOT_EXTENDED:
            return "STATUS_FVE_FS_NOT_EXTENDED";
        case STATUS_FVE_FS_MOUNTED:
            return "STATUS_FVE_FS_MOUNTED";
        case STATUS_FVE_NO_LICENSE:
            return "STATUS_FVE_NO_LICENSE";
        case STATUS_FVE_ACTION_NOT_ALLOWED:
            return "STATUS_FVE_ACTION_NOT_ALLOWED";
        case STATUS_FVE_BAD_DATA:
            return "STATUS_FVE_BAD_DATA";
        case STATUS_FVE_VOLUME_NOT_BOUND:
            return "STATUS_FVE_VOLUME_NOT_BOUND";
        case STATUS_FVE_NOT_DATA_VOLUME:
            return "STATUS_FVE_NOT_DATA_VOLUME";
        case STATUS_FVE_CONV_READ_ERROR:
            return "STATUS_FVE_CONV_READ_ERROR";
        case STATUS_FVE_CONV_WRITE_ERROR:
            return "STATUS_FVE_CONV_WRITE_ERROR";
        case STATUS_FVE_OVERLAPPED_UPDATE:
            return "STATUS_FVE_OVERLAPPED_UPDATE";
        case STATUS_FVE_FAILED_SECTOR_SIZE:
            return "STATUS_FVE_FAILED_SECTOR_SIZE";
        case STATUS_FVE_FAILED_AUTHENTICATION:
            return "STATUS_FVE_FAILED_AUTHENTICATION";
        case STATUS_FVE_NOT_OS_VOLUME:
            return "STATUS_FVE_NOT_OS_VOLUME";
        case STATUS_FVE_KEYFILE_NOT_FOUND:
            return "STATUS_FVE_KEYFILE_NOT_FOUND";
        case STATUS_FVE_KEYFILE_INVALID:
            return "STATUS_FVE_KEYFILE_INVALID";
        case STATUS_FVE_KEYFILE_NO_VMK:
            return "STATUS_FVE_KEYFILE_NO_VMK";
        case STATUS_FVE_TPM_DISABLED:
            return "STATUS_FVE_TPM_DISABLED";
        case STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO:
            return "STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO";
        case STATUS_FVE_TPM_INVALID_PCR:
            return "STATUS_FVE_TPM_INVALID_PCR";
        case STATUS_FVE_TPM_NO_VMK:
            return "STATUS_FVE_TPM_NO_VMK";
        case STATUS_FVE_PIN_INVALID:
            return "STATUS_FVE_PIN_INVALID";
        case STATUS_FVE_AUTH_INVALID_APPLICATION:
            return "STATUS_FVE_AUTH_INVALID_APPLICATION";
        case STATUS_FVE_AUTH_INVALID_CONFIG:
            return "STATUS_FVE_AUTH_INVALID_CONFIG";
        case STATUS_FVE_DEBUGGER_ENABLED:
            return "STATUS_FVE_DEBUGGER_ENABLED";
        case STATUS_FVE_DRY_RUN_FAILED:
            return "STATUS_FVE_DRY_RUN_FAILED";
        case STATUS_FVE_BAD_METADATA_POINTER:
            return "STATUS_FVE_BAD_METADATA_POINTER";
        case STATUS_FVE_OLD_METADATA_COPY:
            return "STATUS_FVE_OLD_METADATA_COPY";
        case STATUS_FVE_REBOOT_REQUIRED:
            return "STATUS_FVE_REBOOT_REQUIRED";
        case STATUS_FVE_RAW_ACCESS:
            return "STATUS_FVE_RAW_ACCESS";
        case STATUS_FVE_RAW_BLOCKED:
            return "STATUS_FVE_RAW_BLOCKED";
        case STATUS_FVE_NO_AUTOUNLOCK_MASTER_KEY:
            return "STATUS_FVE_NO_AUTOUNLOCK_MASTER_KEY";
        case STATUS_FVE_MOR_FAILED:
            return "STATUS_FVE_MOR_FAILED";
        case STATUS_FVE_NO_FEATURE_LICENSE:
            return "STATUS_FVE_NO_FEATURE_LICENSE";
        case STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED:
            return "STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED";
        case STATUS_FVE_CONV_RECOVERY_FAILED:
            return "STATUS_FVE_CONV_RECOVERY_FAILED";
        case STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG:
            return "STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG";
        case STATUS_FVE_INVALID_DATUM_TYPE:
            return "STATUS_FVE_INVALID_DATUM_TYPE";
        case STATUS_FVE_VOLUME_TOO_SMALL:
            return "STATUS_FVE_VOLUME_TOO_SMALL";
        case STATUS_FVE_ENH_PIN_INVALID:
            return "STATUS_FVE_ENH_PIN_INVALID";
        case STATUS_FVE_FULL_ENCRYPTION_NOT_ALLOWED_ON_TP_STORAGE:
            return "STATUS_FVE_FULL_ENCRYPTION_NOT_ALLOWED_ON_TP_STORAGE";
        case STATUS_FVE_WIPE_NOT_ALLOWED_ON_TP_STORAGE:
            return "STATUS_FVE_WIPE_NOT_ALLOWED_ON_TP_STORAGE";
        case STATUS_FVE_NOT_ALLOWED_ON_CSV_STACK:
            return "STATUS_FVE_NOT_ALLOWED_ON_CSV_STACK";
        case STATUS_FVE_NOT_ALLOWED_ON_CLUSTER:
            return "STATUS_FVE_NOT_ALLOWED_ON_CLUSTER";
        case STATUS_FVE_NOT_ALLOWED_TO_UPGRADE_WHILE_CONVERTING:
            return "STATUS_FVE_NOT_ALLOWED_TO_UPGRADE_WHILE_CONVERTING";
        case STATUS_FVE_WIPE_CANCEL_NOT_APPLICABLE:
            return "STATUS_FVE_WIPE_CANCEL_NOT_APPLICABLE";
        case STATUS_FVE_EDRIVE_DRY_RUN_FAILED:
            return "STATUS_FVE_EDRIVE_DRY_RUN_FAILED";
        case STATUS_FVE_SECUREBOOT_DISABLED:
            return "STATUS_FVE_SECUREBOOT_DISABLED";
        case STATUS_FVE_SECUREBOOT_CONFIG_CHANGE:
            return "STATUS_FVE_SECUREBOOT_CONFIG_CHANGE";
        case STATUS_FVE_DEVICE_LOCKEDOUT:
            return "STATUS_FVE_DEVICE_LOCKEDOUT";
        case STATUS_FVE_VOLUME_EXTEND_PREVENTS_EOW_DECRYPT:
            return "STATUS_FVE_VOLUME_EXTEND_PREVENTS_EOW_DECRYPT";
        case STATUS_FVE_NOT_DE_VOLUME:
            return "STATUS_FVE_NOT_DE_VOLUME";
        case STATUS_FVE_PROTECTION_DISABLED:
            return "STATUS_FVE_PROTECTION_DISABLED";
        case STATUS_FVE_PROTECTION_CANNOT_BE_DISABLED:
            return "STATUS_FVE_PROTECTION_CANNOT_BE_DISABLED";
        case STATUS_FVE_OSV_KSR_NOT_ALLOWED:
            return "STATUS_FVE_OSV_KSR_NOT_ALLOWED";
        case STATUS_FWP_CALLOUT_NOT_FOUND:
            return "STATUS_FWP_CALLOUT_NOT_FOUND";
        case STATUS_FWP_CONDITION_NOT_FOUND:
            return "STATUS_FWP_CONDITION_NOT_FOUND";
        case STATUS_FWP_FILTER_NOT_FOUND:
            return "STATUS_FWP_FILTER_NOT_FOUND";
        case STATUS_FWP_LAYER_NOT_FOUND:
            return "STATUS_FWP_LAYER_NOT_FOUND";
        case STATUS_FWP_PROVIDER_NOT_FOUND:
            return "STATUS_FWP_PROVIDER_NOT_FOUND";
        case STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND:
            return "STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND";
        case STATUS_FWP_SUBLAYER_NOT_FOUND:
            return "STATUS_FWP_SUBLAYER_NOT_FOUND";
        case STATUS_FWP_NOT_FOUND:
            return "STATUS_FWP_NOT_FOUND";
        case STATUS_FWP_ALREADY_EXISTS:
            return "STATUS_FWP_ALREADY_EXISTS";
        case STATUS_FWP_IN_USE:
            return "STATUS_FWP_IN_USE";
        case STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS:
            return "STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS";
        case STATUS_FWP_WRONG_SESSION:
            return "STATUS_FWP_WRONG_SESSION";
        case STATUS_FWP_NO_TXN_IN_PROGRESS:
            return "STATUS_FWP_NO_TXN_IN_PROGRESS";
        case STATUS_FWP_TXN_IN_PROGRESS:
            return "STATUS_FWP_TXN_IN_PROGRESS";
        case STATUS_FWP_TXN_ABORTED:
            return "STATUS_FWP_TXN_ABORTED";
        case STATUS_FWP_SESSION_ABORTED:
            return "STATUS_FWP_SESSION_ABORTED";
        case STATUS_FWP_INCOMPATIBLE_TXN:
            return "STATUS_FWP_INCOMPATIBLE_TXN";
        case STATUS_FWP_TIMEOUT:
            return "STATUS_FWP_TIMEOUT";
        case STATUS_FWP_NET_EVENTS_DISABLED:
            return "STATUS_FWP_NET_EVENTS_DISABLED";
        case STATUS_FWP_INCOMPATIBLE_LAYER:
            return "STATUS_FWP_INCOMPATIBLE_LAYER";
        case STATUS_FWP_KM_CLIENTS_ONLY:
            return "STATUS_FWP_KM_CLIENTS_ONLY";
        case STATUS_FWP_LIFETIME_MISMATCH:
            return "STATUS_FWP_LIFETIME_MISMATCH";
        case STATUS_FWP_BUILTIN_OBJECT:
            return "STATUS_FWP_BUILTIN_OBJECT";
        case STATUS_FWP_TOO_MANY_CALLOUTS:
            return "STATUS_FWP_TOO_MANY_CALLOUTS";
        case STATUS_FWP_NOTIFICATION_DROPPED:
            return "STATUS_FWP_NOTIFICATION_DROPPED";
        case STATUS_FWP_TRAFFIC_MISMATCH:
            return "STATUS_FWP_TRAFFIC_MISMATCH";
        case STATUS_FWP_INCOMPATIBLE_SA_STATE:
            return "STATUS_FWP_INCOMPATIBLE_SA_STATE";
        case STATUS_FWP_NULL_POINTER:
            return "STATUS_FWP_NULL_POINTER";
        case STATUS_FWP_INVALID_ENUMERATOR:
            return "STATUS_FWP_INVALID_ENUMERATOR";
        case STATUS_FWP_INVALID_FLAGS:
            return "STATUS_FWP_INVALID_FLAGS";
        case STATUS_FWP_INVALID_NET_MASK:
            return "STATUS_FWP_INVALID_NET_MASK";
        case STATUS_FWP_INVALID_RANGE:
            return "STATUS_FWP_INVALID_RANGE";
        case STATUS_FWP_INVALID_INTERVAL:
            return "STATUS_FWP_INVALID_INTERVAL";
        case STATUS_FWP_ZERO_LENGTH_ARRAY:
            return "STATUS_FWP_ZERO_LENGTH_ARRAY";
        case STATUS_FWP_NULL_DISPLAY_NAME:
            return "STATUS_FWP_NULL_DISPLAY_NAME";
        case STATUS_FWP_INVALID_ACTION_TYPE:
            return "STATUS_FWP_INVALID_ACTION_TYPE";
        case STATUS_FWP_INVALID_WEIGHT:
            return "STATUS_FWP_INVALID_WEIGHT";
        case STATUS_FWP_MATCH_TYPE_MISMATCH:
            return "STATUS_FWP_MATCH_TYPE_MISMATCH";
        case STATUS_FWP_TYPE_MISMATCH:
            return "STATUS_FWP_TYPE_MISMATCH";
        case STATUS_FWP_OUT_OF_BOUNDS:
            return "STATUS_FWP_OUT_OF_BOUNDS";
        case STATUS_FWP_RESERVED:
            return "STATUS_FWP_RESERVED";
        case STATUS_FWP_DUPLICATE_CONDITION:
            return "STATUS_FWP_DUPLICATE_CONDITION";
        case STATUS_FWP_DUPLICATE_KEYMOD:
            return "STATUS_FWP_DUPLICATE_KEYMOD";
        case STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER:
            return "STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER";
        case STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER:
            return "STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER";
        case STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER:
            return "STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER";
        case STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT:
            return "STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT";
        case STATUS_FWP_INCOMPATIBLE_AUTH_METHOD:
            return "STATUS_FWP_INCOMPATIBLE_AUTH_METHOD";
        case STATUS_FWP_INCOMPATIBLE_DH_GROUP:
            return "STATUS_FWP_INCOMPATIBLE_DH_GROUP";
        case STATUS_FWP_EM_NOT_SUPPORTED:
            return "STATUS_FWP_EM_NOT_SUPPORTED";
        case STATUS_FWP_NEVER_MATCH:
            return "STATUS_FWP_NEVER_MATCH";
        case STATUS_FWP_PROVIDER_CONTEXT_MISMATCH:
            return "STATUS_FWP_PROVIDER_CONTEXT_MISMATCH";
        case STATUS_FWP_INVALID_PARAMETER:
            return "STATUS_FWP_INVALID_PARAMETER";
        case STATUS_FWP_TOO_MANY_SUBLAYERS:
            return "STATUS_FWP_TOO_MANY_SUBLAYERS";
        case STATUS_FWP_CALLOUT_NOTIFICATION_FAILED:
            return "STATUS_FWP_CALLOUT_NOTIFICATION_FAILED";
        case STATUS_FWP_INVALID_AUTH_TRANSFORM:
            return "STATUS_FWP_INVALID_AUTH_TRANSFORM";
        case STATUS_FWP_INVALID_CIPHER_TRANSFORM:
            return "STATUS_FWP_INVALID_CIPHER_TRANSFORM";
        case STATUS_FWP_INCOMPATIBLE_CIPHER_TRANSFORM:
            return "STATUS_FWP_INCOMPATIBLE_CIPHER_TRANSFORM";
        case STATUS_FWP_INVALID_TRANSFORM_COMBINATION:
            return "STATUS_FWP_INVALID_TRANSFORM_COMBINATION";
        case STATUS_FWP_DUPLICATE_AUTH_METHOD:
            return "STATUS_FWP_DUPLICATE_AUTH_METHOD";
        case STATUS_FWP_INVALID_TUNNEL_ENDPOINT:
            return "STATUS_FWP_INVALID_TUNNEL_ENDPOINT";
        case STATUS_FWP_L2_DRIVER_NOT_READY:
            return "STATUS_FWP_L2_DRIVER_NOT_READY";
        case STATUS_FWP_KEY_DICTATOR_ALREADY_REGISTERED:
            return "STATUS_FWP_KEY_DICTATOR_ALREADY_REGISTERED";
        case STATUS_FWP_KEY_DICTATION_INVALID_KEYING_MATERIAL:
            return "STATUS_FWP_KEY_DICTATION_INVALID_KEYING_MATERIAL";
        case STATUS_FWP_CONNECTIONS_DISABLED:
            return "STATUS_FWP_CONNECTIONS_DISABLED";
        case STATUS_FWP_INVALID_DNS_NAME:
            return "STATUS_FWP_INVALID_DNS_NAME";
        case STATUS_FWP_STILL_ON:
            return "STATUS_FWP_STILL_ON";
        case STATUS_FWP_IKEEXT_NOT_RUNNING:
            return "STATUS_FWP_IKEEXT_NOT_RUNNING";
        case STATUS_FWP_TCPIP_NOT_READY:
            return "STATUS_FWP_TCPIP_NOT_READY";
        case STATUS_FWP_INJECT_HANDLE_CLOSING:
            return "STATUS_FWP_INJECT_HANDLE_CLOSING";
        case STATUS_FWP_INJECT_HANDLE_STALE:
            return "STATUS_FWP_INJECT_HANDLE_STALE";
        case STATUS_FWP_CANNOT_PEND:
            return "STATUS_FWP_CANNOT_PEND";
        case STATUS_FWP_DROP_NOICMP:
            return "STATUS_FWP_DROP_NOICMP";
        case STATUS_NDIS_CLOSING:
            return "STATUS_NDIS_CLOSING";
        case STATUS_NDIS_BAD_VERSION:
            return "STATUS_NDIS_BAD_VERSION";
        case STATUS_NDIS_BAD_CHARACTERISTICS:
            return "STATUS_NDIS_BAD_CHARACTERISTICS";
        case STATUS_NDIS_ADAPTER_NOT_FOUND:
            return "STATUS_NDIS_ADAPTER_NOT_FOUND";
        case STATUS_NDIS_OPEN_FAILED:
            return "STATUS_NDIS_OPEN_FAILED";
        case STATUS_NDIS_DEVICE_FAILED:
            return "STATUS_NDIS_DEVICE_FAILED";
        case STATUS_NDIS_MULTICAST_FULL:
            return "STATUS_NDIS_MULTICAST_FULL";
        case STATUS_NDIS_MULTICAST_EXISTS:
            return "STATUS_NDIS_MULTICAST_EXISTS";
        case STATUS_NDIS_MULTICAST_NOT_FOUND:
            return "STATUS_NDIS_MULTICAST_NOT_FOUND";
        case STATUS_NDIS_REQUEST_ABORTED:
            return "STATUS_NDIS_REQUEST_ABORTED";
        case STATUS_NDIS_RESET_IN_PROGRESS:
            return "STATUS_NDIS_RESET_IN_PROGRESS";
        case STATUS_NDIS_NOT_SUPPORTED:
            return "STATUS_NDIS_NOT_SUPPORTED";
        case STATUS_NDIS_INVALID_PACKET:
            return "STATUS_NDIS_INVALID_PACKET";
        case STATUS_NDIS_ADAPTER_NOT_READY:
            return "STATUS_NDIS_ADAPTER_NOT_READY";
        case STATUS_NDIS_INVALID_LENGTH:
            return "STATUS_NDIS_INVALID_LENGTH";
        case STATUS_NDIS_INVALID_DATA:
            return "STATUS_NDIS_INVALID_DATA";
        case STATUS_NDIS_BUFFER_TOO_SHORT:
            return "STATUS_NDIS_BUFFER_TOO_SHORT";
        case STATUS_NDIS_INVALID_OID:
            return "STATUS_NDIS_INVALID_OID";
        case STATUS_NDIS_ADAPTER_REMOVED:
            return "STATUS_NDIS_ADAPTER_REMOVED";
        case STATUS_NDIS_UNSUPPORTED_MEDIA:
            return "STATUS_NDIS_UNSUPPORTED_MEDIA";
        case STATUS_NDIS_GROUP_ADDRESS_IN_USE:
            return "STATUS_NDIS_GROUP_ADDRESS_IN_USE";
        case STATUS_NDIS_FILE_NOT_FOUND:
            return "STATUS_NDIS_FILE_NOT_FOUND";
        case STATUS_NDIS_ERROR_READING_FILE:
            return "STATUS_NDIS_ERROR_READING_FILE";
        case STATUS_NDIS_ALREADY_MAPPED:
            return "STATUS_NDIS_ALREADY_MAPPED";
        case STATUS_NDIS_RESOURCE_CONFLICT:
            return "STATUS_NDIS_RESOURCE_CONFLICT";
        case STATUS_NDIS_MEDIA_DISCONNECTED:
            return "STATUS_NDIS_MEDIA_DISCONNECTED";
        case STATUS_NDIS_INVALID_ADDRESS:
            return "STATUS_NDIS_INVALID_ADDRESS";
        case STATUS_NDIS_INVALID_DEVICE_REQUEST:
            return "STATUS_NDIS_INVALID_DEVICE_REQUEST";
        case STATUS_NDIS_PAUSED:
            return "STATUS_NDIS_PAUSED";
        case STATUS_NDIS_INTERFACE_NOT_FOUND:
            return "STATUS_NDIS_INTERFACE_NOT_FOUND";
        case STATUS_NDIS_UNSUPPORTED_REVISION:
            return "STATUS_NDIS_UNSUPPORTED_REVISION";
        case STATUS_NDIS_INVALID_PORT:
            return "STATUS_NDIS_INVALID_PORT";
        case STATUS_NDIS_INVALID_PORT_STATE:
            return "STATUS_NDIS_INVALID_PORT_STATE";
        case STATUS_NDIS_LOW_POWER_STATE:
            return "STATUS_NDIS_LOW_POWER_STATE";
        case STATUS_NDIS_REINIT_REQUIRED:
            return "STATUS_NDIS_REINIT_REQUIRED";
        case STATUS_NDIS_NO_QUEUES:
            return "STATUS_NDIS_NO_QUEUES";
        case STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED:
            return "STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED";
        case STATUS_NDIS_DOT11_MEDIA_IN_USE:
            return "STATUS_NDIS_DOT11_MEDIA_IN_USE";
        case STATUS_NDIS_DOT11_POWER_STATE_INVALID:
            return "STATUS_NDIS_DOT11_POWER_STATE_INVALID";
        case STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL:
            return "STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL";
        case STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL:
            return "STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL";
        case STATUS_NDIS_DOT11_AP_CHANNEL_CURRENTLY_NOT_AVAILABLE:
            return "STATUS_NDIS_DOT11_AP_CHANNEL_CURRENTLY_NOT_AVAILABLE";
        case STATUS_NDIS_DOT11_AP_BAND_CURRENTLY_NOT_AVAILABLE:
            return "STATUS_NDIS_DOT11_AP_BAND_CURRENTLY_NOT_AVAILABLE";
        case STATUS_NDIS_DOT11_AP_CHANNEL_NOT_ALLOWED:
            return "STATUS_NDIS_DOT11_AP_CHANNEL_NOT_ALLOWED";
        case STATUS_NDIS_DOT11_AP_BAND_NOT_ALLOWED:
            return "STATUS_NDIS_DOT11_AP_BAND_NOT_ALLOWED";
        case STATUS_NDIS_INDICATION_REQUIRED:
            return "STATUS_NDIS_INDICATION_REQUIRED";
        case STATUS_NDIS_OFFLOAD_POLICY:
            return "STATUS_NDIS_OFFLOAD_POLICY";
        case STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED:
            return "STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED";
        case STATUS_NDIS_OFFLOAD_PATH_REJECTED:
            return "STATUS_NDIS_OFFLOAD_PATH_REJECTED";
        case STATUS_TPM_ERROR_MASK:
            return "STATUS_TPM_ERROR_MASK";
        case STATUS_TPM_AUTHFAIL:
            return "STATUS_TPM_AUTHFAIL";
        case STATUS_TPM_BADINDEX:
            return "STATUS_TPM_BADINDEX";
        case STATUS_TPM_BAD_PARAMETER:
            return "STATUS_TPM_BAD_PARAMETER";
        case STATUS_TPM_AUDITFAILURE:
            return "STATUS_TPM_AUDITFAILURE";
        case STATUS_TPM_CLEAR_DISABLED:
            return "STATUS_TPM_CLEAR_DISABLED";
        case STATUS_TPM_DEACTIVATED:
            return "STATUS_TPM_DEACTIVATED";
        case STATUS_TPM_DISABLED:
            return "STATUS_TPM_DISABLED";
        case STATUS_TPM_DISABLED_CMD:
            return "STATUS_TPM_DISABLED_CMD";
        case STATUS_TPM_FAIL:
            return "STATUS_TPM_FAIL";
        case STATUS_TPM_BAD_ORDINAL:
            return "STATUS_TPM_BAD_ORDINAL";
        case STATUS_TPM_INSTALL_DISABLED:
            return "STATUS_TPM_INSTALL_DISABLED";
        case STATUS_TPM_INVALID_KEYHANDLE:
            return "STATUS_TPM_INVALID_KEYHANDLE";
        case STATUS_TPM_KEYNOTFOUND:
            return "STATUS_TPM_KEYNOTFOUND";
        case STATUS_TPM_INAPPROPRIATE_ENC:
            return "STATUS_TPM_INAPPROPRIATE_ENC";
        case STATUS_TPM_MIGRATEFAIL:
            return "STATUS_TPM_MIGRATEFAIL";
        case STATUS_TPM_INVALID_PCR_INFO:
            return "STATUS_TPM_INVALID_PCR_INFO";
        case STATUS_TPM_NOSPACE:
            return "STATUS_TPM_NOSPACE";
        case STATUS_TPM_NOSRK:
            return "STATUS_TPM_NOSRK";
        case STATUS_TPM_NOTSEALED_BLOB:
            return "STATUS_TPM_NOTSEALED_BLOB";
        case STATUS_TPM_OWNER_SET:
            return "STATUS_TPM_OWNER_SET";
        case STATUS_TPM_RESOURCES:
            return "STATUS_TPM_RESOURCES";
        case STATUS_TPM_SHORTRANDOM:
            return "STATUS_TPM_SHORTRANDOM";
        case STATUS_TPM_SIZE:
            return "STATUS_TPM_SIZE";
        case STATUS_TPM_WRONGPCRVAL:
            return "STATUS_TPM_WRONGPCRVAL";
        case STATUS_TPM_BAD_PARAM_SIZE:
            return "STATUS_TPM_BAD_PARAM_SIZE";
        case STATUS_TPM_SHA_THREAD:
            return "STATUS_TPM_SHA_THREAD";
        case STATUS_TPM_SHA_ERROR:
            return "STATUS_TPM_SHA_ERROR";
        case STATUS_TPM_FAILEDSELFTEST:
            return "STATUS_TPM_FAILEDSELFTEST";
        case STATUS_TPM_AUTH2FAIL:
            return "STATUS_TPM_AUTH2FAIL";
        case STATUS_TPM_BADTAG:
            return "STATUS_TPM_BADTAG";
        case STATUS_TPM_IOERROR:
            return "STATUS_TPM_IOERROR";
        case STATUS_TPM_ENCRYPT_ERROR:
            return "STATUS_TPM_ENCRYPT_ERROR";
        case STATUS_TPM_DECRYPT_ERROR:
            return "STATUS_TPM_DECRYPT_ERROR";
        case STATUS_TPM_INVALID_AUTHHANDLE:
            return "STATUS_TPM_INVALID_AUTHHANDLE";
        case STATUS_TPM_NO_ENDORSEMENT:
            return "STATUS_TPM_NO_ENDORSEMENT";
        case STATUS_TPM_INVALID_KEYUSAGE:
            return "STATUS_TPM_INVALID_KEYUSAGE";
        case STATUS_TPM_WRONG_ENTITYTYPE:
            return "STATUS_TPM_WRONG_ENTITYTYPE";
        case STATUS_TPM_INVALID_POSTINIT:
            return "STATUS_TPM_INVALID_POSTINIT";
        case STATUS_TPM_INAPPROPRIATE_SIG:
            return "STATUS_TPM_INAPPROPRIATE_SIG";
        case STATUS_TPM_BAD_KEY_PROPERTY:
            return "STATUS_TPM_BAD_KEY_PROPERTY";
        case STATUS_TPM_BAD_MIGRATION:
            return "STATUS_TPM_BAD_MIGRATION";
        case STATUS_TPM_BAD_SCHEME:
            return "STATUS_TPM_BAD_SCHEME";
        case STATUS_TPM_BAD_DATASIZE:
            return "STATUS_TPM_BAD_DATASIZE";
        case STATUS_TPM_BAD_MODE:
            return "STATUS_TPM_BAD_MODE";
        case STATUS_TPM_BAD_PRESENCE:
            return "STATUS_TPM_BAD_PRESENCE";
        case STATUS_TPM_BAD_VERSION:
            return "STATUS_TPM_BAD_VERSION";
        case STATUS_TPM_NO_WRAP_TRANSPORT:
            return "STATUS_TPM_NO_WRAP_TRANSPORT";
        case STATUS_TPM_AUDITFAIL_UNSUCCESSFUL:
            return "STATUS_TPM_AUDITFAIL_UNSUCCESSFUL";
        case STATUS_TPM_AUDITFAIL_SUCCESSFUL:
            return "STATUS_TPM_AUDITFAIL_SUCCESSFUL";
        case STATUS_TPM_NOTRESETABLE:
            return "STATUS_TPM_NOTRESETABLE";
        case STATUS_TPM_NOTLOCAL:
            return "STATUS_TPM_NOTLOCAL";
        case STATUS_TPM_BAD_TYPE:
            return "STATUS_TPM_BAD_TYPE";
        case STATUS_TPM_INVALID_RESOURCE:
            return "STATUS_TPM_INVALID_RESOURCE";
        case STATUS_TPM_NOTFIPS:
            return "STATUS_TPM_NOTFIPS";
        case STATUS_TPM_INVALID_FAMILY:
            return "STATUS_TPM_INVALID_FAMILY";
        case STATUS_TPM_NO_NV_PERMISSION:
            return "STATUS_TPM_NO_NV_PERMISSION";
        case STATUS_TPM_REQUIRES_SIGN:
            return "STATUS_TPM_REQUIRES_SIGN";
        case STATUS_TPM_KEY_NOTSUPPORTED:
            return "STATUS_TPM_KEY_NOTSUPPORTED";
        case STATUS_TPM_AUTH_CONFLICT:
            return "STATUS_TPM_AUTH_CONFLICT";
        case STATUS_TPM_AREA_LOCKED:
            return "STATUS_TPM_AREA_LOCKED";
        case STATUS_TPM_BAD_LOCALITY:
            return "STATUS_TPM_BAD_LOCALITY";
        case STATUS_TPM_READ_ONLY:
            return "STATUS_TPM_READ_ONLY";
        case STATUS_TPM_PER_NOWRITE:
            return "STATUS_TPM_PER_NOWRITE";
        case STATUS_TPM_FAMILYCOUNT:
            return "STATUS_TPM_FAMILYCOUNT";
        case STATUS_TPM_WRITE_LOCKED:
            return "STATUS_TPM_WRITE_LOCKED";
        case STATUS_TPM_BAD_ATTRIBUTES:
            return "STATUS_TPM_BAD_ATTRIBUTES";
        case STATUS_TPM_INVALID_STRUCTURE:
            return "STATUS_TPM_INVALID_STRUCTURE";
        case STATUS_TPM_KEY_OWNER_CONTROL:
            return "STATUS_TPM_KEY_OWNER_CONTROL";
        case STATUS_TPM_BAD_COUNTER:
            return "STATUS_TPM_BAD_COUNTER";
        case STATUS_TPM_NOT_FULLWRITE:
            return "STATUS_TPM_NOT_FULLWRITE";
        case STATUS_TPM_CONTEXT_GAP:
            return "STATUS_TPM_CONTEXT_GAP";
        case STATUS_TPM_MAXNVWRITES:
            return "STATUS_TPM_MAXNVWRITES";
        case STATUS_TPM_NOOPERATOR:
            return "STATUS_TPM_NOOPERATOR";
        case STATUS_TPM_RESOURCEMISSING:
            return "STATUS_TPM_RESOURCEMISSING";
        case STATUS_TPM_DELEGATE_LOCK:
            return "STATUS_TPM_DELEGATE_LOCK";
        case STATUS_TPM_DELEGATE_FAMILY:
            return "STATUS_TPM_DELEGATE_FAMILY";
        case STATUS_TPM_DELEGATE_ADMIN:
            return "STATUS_TPM_DELEGATE_ADMIN";
        case STATUS_TPM_TRANSPORT_NOTEXCLUSIVE:
            return "STATUS_TPM_TRANSPORT_NOTEXCLUSIVE";
        case STATUS_TPM_OWNER_CONTROL:
            return "STATUS_TPM_OWNER_CONTROL";
        case STATUS_TPM_DAA_RESOURCES:
            return "STATUS_TPM_DAA_RESOURCES";
        case STATUS_TPM_DAA_INPUT_DATA0:
            return "STATUS_TPM_DAA_INPUT_DATA0";
        case STATUS_TPM_DAA_INPUT_DATA1:
            return "STATUS_TPM_DAA_INPUT_DATA1";
        case STATUS_TPM_DAA_ISSUER_SETTINGS:
            return "STATUS_TPM_DAA_ISSUER_SETTINGS";
        case STATUS_TPM_DAA_TPM_SETTINGS:
            return "STATUS_TPM_DAA_TPM_SETTINGS";
        case STATUS_TPM_DAA_STAGE:
            return "STATUS_TPM_DAA_STAGE";
        case STATUS_TPM_DAA_ISSUER_VALIDITY:
            return "STATUS_TPM_DAA_ISSUER_VALIDITY";
        case STATUS_TPM_DAA_WRONG_W:
            return "STATUS_TPM_DAA_WRONG_W";
        case STATUS_TPM_BAD_HANDLE:
            return "STATUS_TPM_BAD_HANDLE";
        case STATUS_TPM_BAD_DELEGATE:
            return "STATUS_TPM_BAD_DELEGATE";
        case STATUS_TPM_BADCONTEXT:
            return "STATUS_TPM_BADCONTEXT";
        case STATUS_TPM_TOOMANYCONTEXTS:
            return "STATUS_TPM_TOOMANYCONTEXTS";
        case STATUS_TPM_MA_TICKET_SIGNATURE:
            return "STATUS_TPM_MA_TICKET_SIGNATURE";
        case STATUS_TPM_MA_DESTINATION:
            return "STATUS_TPM_MA_DESTINATION";
        case STATUS_TPM_MA_SOURCE:
            return "STATUS_TPM_MA_SOURCE";
        case STATUS_TPM_MA_AUTHORITY:
            return "STATUS_TPM_MA_AUTHORITY";
        case STATUS_TPM_PERMANENTEK:
            return "STATUS_TPM_PERMANENTEK";
        case STATUS_TPM_BAD_SIGNATURE:
            return "STATUS_TPM_BAD_SIGNATURE";
        case STATUS_TPM_NOCONTEXTSPACE:
            return "STATUS_TPM_NOCONTEXTSPACE";
        case STATUS_TPM_20_E_ASYMMETRIC:
            return "STATUS_TPM_20_E_ASYMMETRIC";
        case STATUS_TPM_20_E_ATTRIBUTES:
            return "STATUS_TPM_20_E_ATTRIBUTES";
        case STATUS_TPM_20_E_HASH:
            return "STATUS_TPM_20_E_HASH";
        case STATUS_TPM_20_E_VALUE:
            return "STATUS_TPM_20_E_VALUE";
        case STATUS_TPM_20_E_HIERARCHY:
            return "STATUS_TPM_20_E_HIERARCHY";
        case STATUS_TPM_20_E_KEY_SIZE:
            return "STATUS_TPM_20_E_KEY_SIZE";
        case STATUS_TPM_20_E_MGF:
            return "STATUS_TPM_20_E_MGF";
        case STATUS_TPM_20_E_MODE:
            return "STATUS_TPM_20_E_MODE";
        case STATUS_TPM_20_E_TYPE:
            return "STATUS_TPM_20_E_TYPE";
        case STATUS_TPM_20_E_HANDLE:
            return "STATUS_TPM_20_E_HANDLE";
        case STATUS_TPM_20_E_KDF:
            return "STATUS_TPM_20_E_KDF";
        case STATUS_TPM_20_E_RANGE:
            return "STATUS_TPM_20_E_RANGE";
        case STATUS_TPM_20_E_AUTH_FAIL:
            return "STATUS_TPM_20_E_AUTH_FAIL";
        case STATUS_TPM_20_E_NONCE:
            return "STATUS_TPM_20_E_NONCE";
        case STATUS_TPM_20_E_PP:
            return "STATUS_TPM_20_E_PP";
        case STATUS_TPM_20_E_SCHEME:
            return "STATUS_TPM_20_E_SCHEME";
        case STATUS_TPM_20_E_SIZE:
            return "STATUS_TPM_20_E_SIZE";
        case STATUS_TPM_20_E_SYMMETRIC:
            return "STATUS_TPM_20_E_SYMMETRIC";
        case STATUS_TPM_20_E_TAG:
            return "STATUS_TPM_20_E_TAG";
        case STATUS_TPM_20_E_SELECTOR:
            return "STATUS_TPM_20_E_SELECTOR";
        case STATUS_TPM_20_E_INSUFFICIENT:
            return "STATUS_TPM_20_E_INSUFFICIENT";
        case STATUS_TPM_20_E_SIGNATURE:
            return "STATUS_TPM_20_E_SIGNATURE";
        case STATUS_TPM_20_E_KEY:
            return "STATUS_TPM_20_E_KEY";
        case STATUS_TPM_20_E_POLICY_FAIL:
            return "STATUS_TPM_20_E_POLICY_FAIL";
        case STATUS_TPM_20_E_INTEGRITY:
            return "STATUS_TPM_20_E_INTEGRITY";
        case STATUS_TPM_20_E_TICKET:
            return "STATUS_TPM_20_E_TICKET";
        case STATUS_TPM_20_E_RESERVED_BITS:
            return "STATUS_TPM_20_E_RESERVED_BITS";
        case STATUS_TPM_20_E_BAD_AUTH:
            return "STATUS_TPM_20_E_BAD_AUTH";
        case STATUS_TPM_20_E_EXPIRED:
            return "STATUS_TPM_20_E_EXPIRED";
        case STATUS_TPM_20_E_POLICY_CC:
            return "STATUS_TPM_20_E_POLICY_CC";
        case STATUS_TPM_20_E_BINDING:
            return "STATUS_TPM_20_E_BINDING";
        case STATUS_TPM_20_E_CURVE:
            return "STATUS_TPM_20_E_CURVE";
        case STATUS_TPM_20_E_ECC_POINT:
            return "STATUS_TPM_20_E_ECC_POINT";
        case STATUS_TPM_20_E_INITIALIZE:
            return "STATUS_TPM_20_E_INITIALIZE";
        case STATUS_TPM_20_E_FAILURE:
            return "STATUS_TPM_20_E_FAILURE";
        case STATUS_TPM_20_E_SEQUENCE:
            return "STATUS_TPM_20_E_SEQUENCE";
        case STATUS_TPM_20_E_PRIVATE:
            return "STATUS_TPM_20_E_PRIVATE";
        case STATUS_TPM_20_E_HMAC:
            return "STATUS_TPM_20_E_HMAC";
        case STATUS_TPM_20_E_DISABLED:
            return "STATUS_TPM_20_E_DISABLED";
        case STATUS_TPM_20_E_EXCLUSIVE:
            return "STATUS_TPM_20_E_EXCLUSIVE";
        case STATUS_TPM_20_E_ECC_CURVE:
            return "STATUS_TPM_20_E_ECC_CURVE";
        case STATUS_TPM_20_E_AUTH_TYPE:
            return "STATUS_TPM_20_E_AUTH_TYPE";
        case STATUS_TPM_20_E_AUTH_MISSING:
            return "STATUS_TPM_20_E_AUTH_MISSING";
        case STATUS_TPM_20_E_POLICY:
            return "STATUS_TPM_20_E_POLICY";
        case STATUS_TPM_20_E_PCR:
            return "STATUS_TPM_20_E_PCR";
        case STATUS_TPM_20_E_PCR_CHANGED:
            return "STATUS_TPM_20_E_PCR_CHANGED";
        case STATUS_TPM_20_E_UPGRADE:
            return "STATUS_TPM_20_E_UPGRADE";
        case STATUS_TPM_20_E_TOO_MANY_CONTEXTS:
            return "STATUS_TPM_20_E_TOO_MANY_CONTEXTS";
        case STATUS_TPM_20_E_AUTH_UNAVAILABLE:
            return "STATUS_TPM_20_E_AUTH_UNAVAILABLE";
        case STATUS_TPM_20_E_REBOOT:
            return "STATUS_TPM_20_E_REBOOT";
        case STATUS_TPM_20_E_UNBALANCED:
            return "STATUS_TPM_20_E_UNBALANCED";
        case STATUS_TPM_20_E_COMMAND_SIZE:
            return "STATUS_TPM_20_E_COMMAND_SIZE";
        case STATUS_TPM_20_E_COMMAND_CODE:
            return "STATUS_TPM_20_E_COMMAND_CODE";
        case STATUS_TPM_20_E_AUTHSIZE:
            return "STATUS_TPM_20_E_AUTHSIZE";
        case STATUS_TPM_20_E_AUTH_CONTEXT:
            return "STATUS_TPM_20_E_AUTH_CONTEXT";
        case STATUS_TPM_20_E_NV_RANGE:
            return "STATUS_TPM_20_E_NV_RANGE";
        case STATUS_TPM_20_E_NV_SIZE:
            return "STATUS_TPM_20_E_NV_SIZE";
        case STATUS_TPM_20_E_NV_LOCKED:
            return "STATUS_TPM_20_E_NV_LOCKED";
        case STATUS_TPM_20_E_NV_AUTHORIZATION:
            return "STATUS_TPM_20_E_NV_AUTHORIZATION";
        case STATUS_TPM_20_E_NV_UNINITIALIZED:
            return "STATUS_TPM_20_E_NV_UNINITIALIZED";
        case STATUS_TPM_20_E_NV_SPACE:
            return "STATUS_TPM_20_E_NV_SPACE";
        case STATUS_TPM_20_E_NV_DEFINED:
            return "STATUS_TPM_20_E_NV_DEFINED";
        case STATUS_TPM_20_E_BAD_CONTEXT:
            return "STATUS_TPM_20_E_BAD_CONTEXT";
        case STATUS_TPM_20_E_CPHASH:
            return "STATUS_TPM_20_E_CPHASH";
        case STATUS_TPM_20_E_PARENT:
            return "STATUS_TPM_20_E_PARENT";
        case STATUS_TPM_20_E_NEEDS_TEST:
            return "STATUS_TPM_20_E_NEEDS_TEST";
        case STATUS_TPM_20_E_NO_RESULT:
            return "STATUS_TPM_20_E_NO_RESULT";
        case STATUS_TPM_20_E_SENSITIVE:
            return "STATUS_TPM_20_E_SENSITIVE";
        case STATUS_TPM_COMMAND_BLOCKED:
            return "STATUS_TPM_COMMAND_BLOCKED";
        case STATUS_TPM_INVALID_HANDLE:
            return "STATUS_TPM_INVALID_HANDLE";
        case STATUS_TPM_DUPLICATE_VHANDLE:
            return "STATUS_TPM_DUPLICATE_VHANDLE";
        case STATUS_TPM_EMBEDDED_COMMAND_BLOCKED:
            return "STATUS_TPM_EMBEDDED_COMMAND_BLOCKED";
        case STATUS_TPM_EMBEDDED_COMMAND_UNSUPPORTED:
            return "STATUS_TPM_EMBEDDED_COMMAND_UNSUPPORTED";
        case STATUS_TPM_RETRY:
            return "STATUS_TPM_RETRY";
        case STATUS_TPM_NEEDS_SELFTEST:
            return "STATUS_TPM_NEEDS_SELFTEST";
        case STATUS_TPM_DOING_SELFTEST:
            return "STATUS_TPM_DOING_SELFTEST";
        case STATUS_TPM_DEFEND_LOCK_RUNNING:
            return "STATUS_TPM_DEFEND_LOCK_RUNNING";
        case STATUS_TPM_COMMAND_CANCELED:
            return "STATUS_TPM_COMMAND_CANCELED";
        case STATUS_TPM_TOO_MANY_CONTEXTS:
            return "STATUS_TPM_TOO_MANY_CONTEXTS";
        case STATUS_TPM_NOT_FOUND:
            return "STATUS_TPM_NOT_FOUND";
        case STATUS_TPM_ACCESS_DENIED:
            return "STATUS_TPM_ACCESS_DENIED";
        case STATUS_TPM_INSUFFICIENT_BUFFER:
            return "STATUS_TPM_INSUFFICIENT_BUFFER";
        case STATUS_TPM_PPI_FUNCTION_UNSUPPORTED:
            return "STATUS_TPM_PPI_FUNCTION_UNSUPPORTED";
        case STATUS_PCP_ERROR_MASK:
            return "STATUS_PCP_ERROR_MASK";
        case STATUS_PCP_DEVICE_NOT_READY:
            return "STATUS_PCP_DEVICE_NOT_READY";
        case STATUS_PCP_INVALID_HANDLE:
            return "STATUS_PCP_INVALID_HANDLE";
        case STATUS_PCP_INVALID_PARAMETER:
            return "STATUS_PCP_INVALID_PARAMETER";
        case STATUS_PCP_FLAG_NOT_SUPPORTED:
            return "STATUS_PCP_FLAG_NOT_SUPPORTED";
        case STATUS_PCP_NOT_SUPPORTED:
            return "STATUS_PCP_NOT_SUPPORTED";
        case STATUS_PCP_BUFFER_TOO_SMALL:
            return "STATUS_PCP_BUFFER_TOO_SMALL";
        case STATUS_PCP_INTERNAL_ERROR:
            return "STATUS_PCP_INTERNAL_ERROR";
        case STATUS_PCP_AUTHENTICATION_FAILED:
            return "STATUS_PCP_AUTHENTICATION_FAILED";
        case STATUS_PCP_AUTHENTICATION_IGNORED:
            return "STATUS_PCP_AUTHENTICATION_IGNORED";
        case STATUS_PCP_POLICY_NOT_FOUND:
            return "STATUS_PCP_POLICY_NOT_FOUND";
        case STATUS_PCP_PROFILE_NOT_FOUND:
            return "STATUS_PCP_PROFILE_NOT_FOUND";
        case STATUS_PCP_VALIDATION_FAILED:
            return "STATUS_PCP_VALIDATION_FAILED";
        case STATUS_PCP_DEVICE_NOT_FOUND:
            return "STATUS_PCP_DEVICE_NOT_FOUND";
        case STATUS_PCP_WRONG_PARENT:
            return "STATUS_PCP_WRONG_PARENT";
        case STATUS_PCP_KEY_NOT_LOADED:
            return "STATUS_PCP_KEY_NOT_LOADED";
        case STATUS_PCP_NO_KEY_CERTIFICATION:
            return "STATUS_PCP_NO_KEY_CERTIFICATION";
        case STATUS_PCP_KEY_NOT_FINALIZED:
            return "STATUS_PCP_KEY_NOT_FINALIZED";
        case STATUS_PCP_ATTESTATION_CHALLENGE_NOT_SET:
            return "STATUS_PCP_ATTESTATION_CHALLENGE_NOT_SET";
        case STATUS_PCP_NOT_PCR_BOUND:
            return "STATUS_PCP_NOT_PCR_BOUND";
        case STATUS_PCP_KEY_ALREADY_FINALIZED:
            return "STATUS_PCP_KEY_ALREADY_FINALIZED";
        case STATUS_PCP_KEY_USAGE_POLICY_NOT_SUPPORTED:
            return "STATUS_PCP_KEY_USAGE_POLICY_NOT_SUPPORTED";
        case STATUS_PCP_KEY_USAGE_POLICY_INVALID:
            return "STATUS_PCP_KEY_USAGE_POLICY_INVALID";
        case STATUS_PCP_SOFT_KEY_ERROR:
            return "STATUS_PCP_SOFT_KEY_ERROR";
        case STATUS_PCP_KEY_NOT_AUTHENTICATED:
            return "STATUS_PCP_KEY_NOT_AUTHENTICATED";
        case STATUS_PCP_KEY_NOT_AIK:
            return "STATUS_PCP_KEY_NOT_AIK";
        case STATUS_PCP_KEY_NOT_SIGNING_KEY:
            return "STATUS_PCP_KEY_NOT_SIGNING_KEY";
        case STATUS_PCP_LOCKED_OUT:
            return "STATUS_PCP_LOCKED_OUT";
        case STATUS_PCP_CLAIM_TYPE_NOT_SUPPORTED:
            return "STATUS_PCP_CLAIM_TYPE_NOT_SUPPORTED";
        case STATUS_PCP_TPM_VERSION_NOT_SUPPORTED:
            return "STATUS_PCP_TPM_VERSION_NOT_SUPPORTED";
        case STATUS_PCP_BUFFER_LENGTH_MISMATCH:
            return "STATUS_PCP_BUFFER_LENGTH_MISMATCH";
        case STATUS_PCP_IFX_RSA_KEY_CREATION_BLOCKED:
            return "STATUS_PCP_IFX_RSA_KEY_CREATION_BLOCKED";
        case STATUS_PCP_TICKET_MISSING:
            return "STATUS_PCP_TICKET_MISSING";
        case STATUS_PCP_RAW_POLICY_NOT_SUPPORTED:
            return "STATUS_PCP_RAW_POLICY_NOT_SUPPORTED";
        case STATUS_PCP_KEY_HANDLE_INVALIDATED:
            return "STATUS_PCP_KEY_HANDLE_INVALIDATED";
        case STATUS_PCP_UNSUPPORTED_PSS_SALT:
            return "STATUS_PCP_UNSUPPORTED_PSS_SALT";
        case STATUS_RTPM_CONTEXT_CONTINUE:
            return "STATUS_RTPM_CONTEXT_CONTINUE";
        case STATUS_RTPM_CONTEXT_COMPLETE:
            return "STATUS_RTPM_CONTEXT_COMPLETE";
        case STATUS_RTPM_NO_RESULT:
            return "STATUS_RTPM_NO_RESULT";
        case STATUS_RTPM_PCR_READ_INCOMPLETE:
            return "STATUS_RTPM_PCR_READ_INCOMPLETE";
        case STATUS_RTPM_INVALID_CONTEXT:
            return "STATUS_RTPM_INVALID_CONTEXT";
        case STATUS_RTPM_UNSUPPORTED_CMD:
            return "STATUS_RTPM_UNSUPPORTED_CMD";
        case STATUS_TPM_ZERO_EXHAUST_ENABLED:
            return "STATUS_TPM_ZERO_EXHAUST_ENABLED";
        case STATUS_HV_INVALID_HYPERCALL_CODE:
            return "STATUS_HV_INVALID_HYPERCALL_CODE";
        case STATUS_HV_INVALID_HYPERCALL_INPUT:
            return "STATUS_HV_INVALID_HYPERCALL_INPUT";
        case STATUS_HV_INVALID_ALIGNMENT:
            return "STATUS_HV_INVALID_ALIGNMENT";
        case STATUS_HV_INVALID_PARAMETER:
            return "STATUS_HV_INVALID_PARAMETER";
        case STATUS_HV_ACCESS_DENIED:
            return "STATUS_HV_ACCESS_DENIED";
        case STATUS_HV_INVALID_PARTITION_STATE:
            return "STATUS_HV_INVALID_PARTITION_STATE";
        case STATUS_HV_OPERATION_DENIED:
            return "STATUS_HV_OPERATION_DENIED";
        case STATUS_HV_UNKNOWN_PROPERTY:
            return "STATUS_HV_UNKNOWN_PROPERTY";
        case STATUS_HV_PROPERTY_VALUE_OUT_OF_RANGE:
            return "STATUS_HV_PROPERTY_VALUE_OUT_OF_RANGE";
        case STATUS_HV_INSUFFICIENT_MEMORY:
            return "STATUS_HV_INSUFFICIENT_MEMORY";
        case STATUS_HV_PARTITION_TOO_DEEP:
            return "STATUS_HV_PARTITION_TOO_DEEP";
        case STATUS_HV_INVALID_PARTITION_ID:
            return "STATUS_HV_INVALID_PARTITION_ID";
        case STATUS_HV_INVALID_VP_INDEX:
            return "STATUS_HV_INVALID_VP_INDEX";
        case STATUS_HV_INVALID_PORT_ID:
            return "STATUS_HV_INVALID_PORT_ID";
        case STATUS_HV_INVALID_CONNECTION_ID:
            return "STATUS_HV_INVALID_CONNECTION_ID";
        case STATUS_HV_INSUFFICIENT_BUFFERS:
            return "STATUS_HV_INSUFFICIENT_BUFFERS";
        case STATUS_HV_NOT_ACKNOWLEDGED:
            return "STATUS_HV_NOT_ACKNOWLEDGED";
        case STATUS_HV_INVALID_VP_STATE:
            return "STATUS_HV_INVALID_VP_STATE";
        case STATUS_HV_ACKNOWLEDGED:
            return "STATUS_HV_ACKNOWLEDGED";
        case STATUS_HV_INVALID_SAVE_RESTORE_STATE:
            return "STATUS_HV_INVALID_SAVE_RESTORE_STATE";
        case STATUS_HV_INVALID_SYNIC_STATE:
            return "STATUS_HV_INVALID_SYNIC_STATE";
        case STATUS_HV_OBJECT_IN_USE:
            return "STATUS_HV_OBJECT_IN_USE";
        case STATUS_HV_INVALID_PROXIMITY_DOMAIN_INFO:
            return "STATUS_HV_INVALID_PROXIMITY_DOMAIN_INFO";
        case STATUS_HV_NO_DATA:
            return "STATUS_HV_NO_DATA";
        case STATUS_HV_INACTIVE:
            return "STATUS_HV_INACTIVE";
        case STATUS_HV_NO_RESOURCES:
            return "STATUS_HV_NO_RESOURCES";
        case STATUS_HV_FEATURE_UNAVAILABLE:
            return "STATUS_HV_FEATURE_UNAVAILABLE";
        case STATUS_HV_INSUFFICIENT_BUFFER:
            return "STATUS_HV_INSUFFICIENT_BUFFER";
        case STATUS_HV_INSUFFICIENT_DEVICE_DOMAINS:
            return "STATUS_HV_INSUFFICIENT_DEVICE_DOMAINS";
        case STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR:
            return "STATUS_HV_CPUID_FEATURE_VALIDATION_ERROR";
        case STATUS_HV_CPUID_XSAVE_FEATURE_VALIDATION_ERROR:
            return "STATUS_HV_CPUID_XSAVE_FEATURE_VALIDATION_ERROR";
        case STATUS_HV_PROCESSOR_STARTUP_TIMEOUT:
            return "STATUS_HV_PROCESSOR_STARTUP_TIMEOUT";
        case STATUS_HV_SMX_ENABLED:
            return "STATUS_HV_SMX_ENABLED";
        case STATUS_HV_INVALID_LP_INDEX:
            return "STATUS_HV_INVALID_LP_INDEX";
        case STATUS_HV_INVALID_REGISTER_VALUE:
            return "STATUS_HV_INVALID_REGISTER_VALUE";
        case STATUS_HV_INVALID_VTL_STATE:
            return "STATUS_HV_INVALID_VTL_STATE";
        case STATUS_HV_NX_NOT_DETECTED:
            return "STATUS_HV_NX_NOT_DETECTED";
        case STATUS_HV_INVALID_DEVICE_ID:
            return "STATUS_HV_INVALID_DEVICE_ID";
        case STATUS_HV_INVALID_DEVICE_STATE:
            return "STATUS_HV_INVALID_DEVICE_STATE";
        case STATUS_HV_PENDING_PAGE_REQUESTS:
            return "STATUS_HV_PENDING_PAGE_REQUESTS";
        case STATUS_HV_PAGE_REQUEST_INVALID:
            return "STATUS_HV_PAGE_REQUEST_INVALID";
        case STATUS_HV_INVALID_CPU_GROUP_ID:
            return "STATUS_HV_INVALID_CPU_GROUP_ID";
        case STATUS_HV_INVALID_CPU_GROUP_STATE:
            return "STATUS_HV_INVALID_CPU_GROUP_STATE";
        case STATUS_HV_OPERATION_FAILED:
            return "STATUS_HV_OPERATION_FAILED";
        case STATUS_HV_NOT_ALLOWED_WITH_NESTED_VIRT_ACTIVE:
            return "STATUS_HV_NOT_ALLOWED_WITH_NESTED_VIRT_ACTIVE";
        case STATUS_HV_INSUFFICIENT_ROOT_MEMORY:
            return "STATUS_HV_INSUFFICIENT_ROOT_MEMORY";
        case STATUS_HV_NOT_PRESENT:
            return "STATUS_HV_NOT_PRESENT";
        case STATUS_VID_DUPLICATE_HANDLER:
            return "STATUS_VID_DUPLICATE_HANDLER";
        case STATUS_VID_TOO_MANY_HANDLERS:
            return "STATUS_VID_TOO_MANY_HANDLERS";
        case STATUS_VID_QUEUE_FULL:
            return "STATUS_VID_QUEUE_FULL";
        case STATUS_VID_HANDLER_NOT_PRESENT:
            return "STATUS_VID_HANDLER_NOT_PRESENT";
        case STATUS_VID_INVALID_OBJECT_NAME:
            return "STATUS_VID_INVALID_OBJECT_NAME";
        case STATUS_VID_PARTITION_NAME_TOO_LONG:
            return "STATUS_VID_PARTITION_NAME_TOO_LONG";
        case STATUS_VID_MESSAGE_QUEUE_NAME_TOO_LONG:
            return "STATUS_VID_MESSAGE_QUEUE_NAME_TOO_LONG";
        case STATUS_VID_PARTITION_ALREADY_EXISTS:
            return "STATUS_VID_PARTITION_ALREADY_EXISTS";
        case STATUS_VID_PARTITION_DOES_NOT_EXIST:
            return "STATUS_VID_PARTITION_DOES_NOT_EXIST";
        case STATUS_VID_PARTITION_NAME_NOT_FOUND:
            return "STATUS_VID_PARTITION_NAME_NOT_FOUND";
        case STATUS_VID_MESSAGE_QUEUE_ALREADY_EXISTS:
            return "STATUS_VID_MESSAGE_QUEUE_ALREADY_EXISTS";
        case STATUS_VID_EXCEEDED_MBP_ENTRY_MAP_LIMIT:
            return "STATUS_VID_EXCEEDED_MBP_ENTRY_MAP_LIMIT";
        case STATUS_VID_MB_STILL_REFERENCED:
            return "STATUS_VID_MB_STILL_REFERENCED";
        case STATUS_VID_CHILD_GPA_PAGE_SET_CORRUPTED:
            return "STATUS_VID_CHILD_GPA_PAGE_SET_CORRUPTED";
        case STATUS_VID_INVALID_NUMA_SETTINGS:
            return "STATUS_VID_INVALID_NUMA_SETTINGS";
        case STATUS_VID_INVALID_NUMA_NODE_INDEX:
            return "STATUS_VID_INVALID_NUMA_NODE_INDEX";
        case STATUS_VID_NOTIFICATION_QUEUE_ALREADY_ASSOCIATED:
            return "STATUS_VID_NOTIFICATION_QUEUE_ALREADY_ASSOCIATED";
        case STATUS_VID_INVALID_MEMORY_BLOCK_HANDLE:
            return "STATUS_VID_INVALID_MEMORY_BLOCK_HANDLE";
        case STATUS_VID_PAGE_RANGE_OVERFLOW:
            return "STATUS_VID_PAGE_RANGE_OVERFLOW";
        case STATUS_VID_INVALID_MESSAGE_QUEUE_HANDLE:
            return "STATUS_VID_INVALID_MESSAGE_QUEUE_HANDLE";
        case STATUS_VID_INVALID_GPA_RANGE_HANDLE:
            return "STATUS_VID_INVALID_GPA_RANGE_HANDLE";
        case STATUS_VID_NO_MEMORY_BLOCK_NOTIFICATION_QUEUE:
            return "STATUS_VID_NO_MEMORY_BLOCK_NOTIFICATION_QUEUE";
        case STATUS_VID_MEMORY_BLOCK_LOCK_COUNT_EXCEEDED:
            return "STATUS_VID_MEMORY_BLOCK_LOCK_COUNT_EXCEEDED";
        case STATUS_VID_INVALID_PPM_HANDLE:
            return "STATUS_VID_INVALID_PPM_HANDLE";
        case STATUS_VID_MBPS_ARE_LOCKED:
            return "STATUS_VID_MBPS_ARE_LOCKED";
        case STATUS_VID_MESSAGE_QUEUE_CLOSED:
            return "STATUS_VID_MESSAGE_QUEUE_CLOSED";
        case STATUS_VID_VIRTUAL_PROCESSOR_LIMIT_EXCEEDED:
            return "STATUS_VID_VIRTUAL_PROCESSOR_LIMIT_EXCEEDED";
        case STATUS_VID_STOP_PENDING:
            return "STATUS_VID_STOP_PENDING";
        case STATUS_VID_INVALID_PROCESSOR_STATE:
            return "STATUS_VID_INVALID_PROCESSOR_STATE";
        case STATUS_VID_EXCEEDED_KM_CONTEXT_COUNT_LIMIT:
            return "STATUS_VID_EXCEEDED_KM_CONTEXT_COUNT_LIMIT";
        case STATUS_VID_KM_INTERFACE_ALREADY_INITIALIZED:
            return "STATUS_VID_KM_INTERFACE_ALREADY_INITIALIZED";
        case STATUS_VID_MB_PROPERTY_ALREADY_SET_RESET:
            return "STATUS_VID_MB_PROPERTY_ALREADY_SET_RESET";
        case STATUS_VID_MMIO_RANGE_DESTROYED:
            return "STATUS_VID_MMIO_RANGE_DESTROYED";
        case STATUS_VID_INVALID_CHILD_GPA_PAGE_SET:
            return "STATUS_VID_INVALID_CHILD_GPA_PAGE_SET";
        case STATUS_VID_RESERVE_PAGE_SET_IS_BEING_USED:
            return "STATUS_VID_RESERVE_PAGE_SET_IS_BEING_USED";
        case STATUS_VID_RESERVE_PAGE_SET_TOO_SMALL:
            return "STATUS_VID_RESERVE_PAGE_SET_TOO_SMALL";
        case STATUS_VID_MBP_ALREADY_LOCKED_USING_RESERVED_PAGE:
            return "STATUS_VID_MBP_ALREADY_LOCKED_USING_RESERVED_PAGE";
        case STATUS_VID_MBP_COUNT_EXCEEDED_LIMIT:
            return "STATUS_VID_MBP_COUNT_EXCEEDED_LIMIT";
        case STATUS_VID_SAVED_STATE_CORRUPT:
            return "STATUS_VID_SAVED_STATE_CORRUPT";
        case STATUS_VID_SAVED_STATE_UNRECOGNIZED_ITEM:
            return "STATUS_VID_SAVED_STATE_UNRECOGNIZED_ITEM";
        case STATUS_VID_SAVED_STATE_INCOMPATIBLE:
            return "STATUS_VID_SAVED_STATE_INCOMPATIBLE";
        case STATUS_VID_VTL_ACCESS_DENIED:
            return "STATUS_VID_VTL_ACCESS_DENIED";
        case STATUS_VID_REMOTE_NODE_PARENT_GPA_PAGES_USED:
            return "STATUS_VID_REMOTE_NODE_PARENT_GPA_PAGES_USED";
        case STATUS_IPSEC_BAD_SPI:
            return "STATUS_IPSEC_BAD_SPI";
        case STATUS_IPSEC_SA_LIFETIME_EXPIRED:
            return "STATUS_IPSEC_SA_LIFETIME_EXPIRED";
        case STATUS_IPSEC_WRONG_SA:
            return "STATUS_IPSEC_WRONG_SA";
        case STATUS_IPSEC_REPLAY_CHECK_FAILED:
            return "STATUS_IPSEC_REPLAY_CHECK_FAILED";
        case STATUS_IPSEC_INVALID_PACKET:
            return "STATUS_IPSEC_INVALID_PACKET";
        case STATUS_IPSEC_INTEGRITY_CHECK_FAILED:
            return "STATUS_IPSEC_INTEGRITY_CHECK_FAILED";
        case STATUS_IPSEC_CLEAR_TEXT_DROP:
            return "STATUS_IPSEC_CLEAR_TEXT_DROP";
        case STATUS_IPSEC_AUTH_FIREWALL_DROP:
            return "STATUS_IPSEC_AUTH_FIREWALL_DROP";
        case STATUS_IPSEC_THROTTLE_DROP:
            return "STATUS_IPSEC_THROTTLE_DROP";
        case STATUS_IPSEC_DOSP_BLOCK:
            return "STATUS_IPSEC_DOSP_BLOCK";
        case STATUS_IPSEC_DOSP_RECEIVED_MULTICAST:
            return "STATUS_IPSEC_DOSP_RECEIVED_MULTICAST";
        case STATUS_IPSEC_DOSP_INVALID_PACKET:
            return "STATUS_IPSEC_DOSP_INVALID_PACKET";
        case STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED:
            return "STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED";
        case STATUS_IPSEC_DOSP_MAX_ENTRIES:
            return "STATUS_IPSEC_DOSP_MAX_ENTRIES";
        case STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED:
            return "STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED";
        case STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES:
            return "STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES";
        case STATUS_VOLMGR_INCOMPLETE_REGENERATION:
            return "STATUS_VOLMGR_INCOMPLETE_REGENERATION";
        case STATUS_VOLMGR_INCOMPLETE_DISK_MIGRATION:
            return "STATUS_VOLMGR_INCOMPLETE_DISK_MIGRATION";
        case STATUS_VOLMGR_DATABASE_FULL:
            return "STATUS_VOLMGR_DATABASE_FULL";
        case STATUS_VOLMGR_DISK_CONFIGURATION_CORRUPTED:
            return "STATUS_VOLMGR_DISK_CONFIGURATION_CORRUPTED";
        case STATUS_VOLMGR_DISK_CONFIGURATION_NOT_IN_SYNC:
            return "STATUS_VOLMGR_DISK_CONFIGURATION_NOT_IN_SYNC";
        case STATUS_VOLMGR_PACK_CONFIG_UPDATE_FAILED:
            return "STATUS_VOLMGR_PACK_CONFIG_UPDATE_FAILED";
        case STATUS_VOLMGR_DISK_CONTAINS_NON_SIMPLE_VOLUME:
            return "STATUS_VOLMGR_DISK_CONTAINS_NON_SIMPLE_VOLUME";
        case STATUS_VOLMGR_DISK_DUPLICATE:
            return "STATUS_VOLMGR_DISK_DUPLICATE";
        case STATUS_VOLMGR_DISK_DYNAMIC:
            return "STATUS_VOLMGR_DISK_DYNAMIC";
        case STATUS_VOLMGR_DISK_ID_INVALID:
            return "STATUS_VOLMGR_DISK_ID_INVALID";
        case STATUS_VOLMGR_DISK_INVALID:
            return "STATUS_VOLMGR_DISK_INVALID";
        case STATUS_VOLMGR_DISK_LAST_VOTER:
            return "STATUS_VOLMGR_DISK_LAST_VOTER";
        case STATUS_VOLMGR_DISK_LAYOUT_INVALID:
            return "STATUS_VOLMGR_DISK_LAYOUT_INVALID";
        case STATUS_VOLMGR_DISK_LAYOUT_NON_BASIC_BETWEEN_BASIC_PARTITIONS:
            return "STATUS_VOLMGR_DISK_LAYOUT_NON_BASIC_BETWEEN_BASIC_PARTITIONS";
        case STATUS_VOLMGR_DISK_LAYOUT_NOT_CYLINDER_ALIGNED:
            return "STATUS_VOLMGR_DISK_LAYOUT_NOT_CYLINDER_ALIGNED";
        case STATUS_VOLMGR_DISK_LAYOUT_PARTITIONS_TOO_SMALL:
            return "STATUS_VOLMGR_DISK_LAYOUT_PARTITIONS_TOO_SMALL";
        case STATUS_VOLMGR_DISK_LAYOUT_PRIMARY_BETWEEN_LOGICAL_PARTITIONS:
            return "STATUS_VOLMGR_DISK_LAYOUT_PRIMARY_BETWEEN_LOGICAL_PARTITIONS";
        case STATUS_VOLMGR_DISK_LAYOUT_TOO_MANY_PARTITIONS:
            return "STATUS_VOLMGR_DISK_LAYOUT_TOO_MANY_PARTITIONS";
        case STATUS_VOLMGR_DISK_MISSING:
            return "STATUS_VOLMGR_DISK_MISSING";
        case STATUS_VOLMGR_DISK_NOT_EMPTY:
            return "STATUS_VOLMGR_DISK_NOT_EMPTY";
        case STATUS_VOLMGR_DISK_NOT_ENOUGH_SPACE:
            return "STATUS_VOLMGR_DISK_NOT_ENOUGH_SPACE";
        case STATUS_VOLMGR_DISK_REVECTORING_FAILED:
            return "STATUS_VOLMGR_DISK_REVECTORING_FAILED";
        case STATUS_VOLMGR_DISK_SECTOR_SIZE_INVALID:
            return "STATUS_VOLMGR_DISK_SECTOR_SIZE_INVALID";
        case STATUS_VOLMGR_DISK_SET_NOT_CONTAINED:
            return "STATUS_VOLMGR_DISK_SET_NOT_CONTAINED";
        case STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_MEMBERS:
            return "STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_MEMBERS";
        case STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_PLEXES:
            return "STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_PLEXES";
        case STATUS_VOLMGR_DYNAMIC_DISK_NOT_SUPPORTED:
            return "STATUS_VOLMGR_DYNAMIC_DISK_NOT_SUPPORTED";
        case STATUS_VOLMGR_EXTENT_ALREADY_USED:
            return "STATUS_VOLMGR_EXTENT_ALREADY_USED";
        case STATUS_VOLMGR_EXTENT_NOT_CONTIGUOUS:
            return "STATUS_VOLMGR_EXTENT_NOT_CONTIGUOUS";
        case STATUS_VOLMGR_EXTENT_NOT_IN_PUBLIC_REGION:
            return "STATUS_VOLMGR_EXTENT_NOT_IN_PUBLIC_REGION";
        case STATUS_VOLMGR_EXTENT_NOT_SECTOR_ALIGNED:
            return "STATUS_VOLMGR_EXTENT_NOT_SECTOR_ALIGNED";
        case STATUS_VOLMGR_EXTENT_OVERLAPS_EBR_PARTITION:
            return "STATUS_VOLMGR_EXTENT_OVERLAPS_EBR_PARTITION";
        case STATUS_VOLMGR_EXTENT_VOLUME_LENGTHS_DO_NOT_MATCH:
            return "STATUS_VOLMGR_EXTENT_VOLUME_LENGTHS_DO_NOT_MATCH";
        case STATUS_VOLMGR_FAULT_TOLERANT_NOT_SUPPORTED:
            return "STATUS_VOLMGR_FAULT_TOLERANT_NOT_SUPPORTED";
        case STATUS_VOLMGR_INTERLEAVE_LENGTH_INVALID:
            return "STATUS_VOLMGR_INTERLEAVE_LENGTH_INVALID";
        case STATUS_VOLMGR_MAXIMUM_REGISTERED_USERS:
            return "STATUS_VOLMGR_MAXIMUM_REGISTERED_USERS";
        case STATUS_VOLMGR_MEMBER_IN_SYNC:
            return "STATUS_VOLMGR_MEMBER_IN_SYNC";
        case STATUS_VOLMGR_MEMBER_INDEX_DUPLICATE:
            return "STATUS_VOLMGR_MEMBER_INDEX_DUPLICATE";
        case STATUS_VOLMGR_MEMBER_INDEX_INVALID:
            return "STATUS_VOLMGR_MEMBER_INDEX_INVALID";
        case STATUS_VOLMGR_MEMBER_MISSING:
            return "STATUS_VOLMGR_MEMBER_MISSING";
        case STATUS_VOLMGR_MEMBER_NOT_DETACHED:
            return "STATUS_VOLMGR_MEMBER_NOT_DETACHED";
        case STATUS_VOLMGR_MEMBER_REGENERATING:
            return "STATUS_VOLMGR_MEMBER_REGENERATING";
        case STATUS_VOLMGR_ALL_DISKS_FAILED:
            return "STATUS_VOLMGR_ALL_DISKS_FAILED";
        case STATUS_VOLMGR_NO_REGISTERED_USERS:
            return "STATUS_VOLMGR_NO_REGISTERED_USERS";
        case STATUS_VOLMGR_NO_SUCH_USER:
            return "STATUS_VOLMGR_NO_SUCH_USER";
        case STATUS_VOLMGR_NOTIFICATION_RESET:
            return "STATUS_VOLMGR_NOTIFICATION_RESET";
        case STATUS_VOLMGR_NUMBER_OF_MEMBERS_INVALID:
            return "STATUS_VOLMGR_NUMBER_OF_MEMBERS_INVALID";
        case STATUS_VOLMGR_NUMBER_OF_PLEXES_INVALID:
            return "STATUS_VOLMGR_NUMBER_OF_PLEXES_INVALID";
        case STATUS_VOLMGR_PACK_DUPLICATE:
            return "STATUS_VOLMGR_PACK_DUPLICATE";
        case STATUS_VOLMGR_PACK_ID_INVALID:
            return "STATUS_VOLMGR_PACK_ID_INVALID";
        case STATUS_VOLMGR_PACK_INVALID:
            return "STATUS_VOLMGR_PACK_INVALID";
        case STATUS_VOLMGR_PACK_NAME_INVALID:
            return "STATUS_VOLMGR_PACK_NAME_INVALID";
        case STATUS_VOLMGR_PACK_OFFLINE:
            return "STATUS_VOLMGR_PACK_OFFLINE";
        case STATUS_VOLMGR_PACK_HAS_QUORUM:
            return "STATUS_VOLMGR_PACK_HAS_QUORUM";
        case STATUS_VOLMGR_PACK_WITHOUT_QUORUM:
            return "STATUS_VOLMGR_PACK_WITHOUT_QUORUM";
        case STATUS_VOLMGR_PARTITION_STYLE_INVALID:
            return "STATUS_VOLMGR_PARTITION_STYLE_INVALID";
        case STATUS_VOLMGR_PARTITION_UPDATE_FAILED:
            return "STATUS_VOLMGR_PARTITION_UPDATE_FAILED";
        case STATUS_VOLMGR_PLEX_IN_SYNC:
            return "STATUS_VOLMGR_PLEX_IN_SYNC";
        case STATUS_VOLMGR_PLEX_INDEX_DUPLICATE:
            return "STATUS_VOLMGR_PLEX_INDEX_DUPLICATE";
        case STATUS_VOLMGR_PLEX_INDEX_INVALID:
            return "STATUS_VOLMGR_PLEX_INDEX_INVALID";
        case STATUS_VOLMGR_PLEX_LAST_ACTIVE:
            return "STATUS_VOLMGR_PLEX_LAST_ACTIVE";
        case STATUS_VOLMGR_PLEX_MISSING:
            return "STATUS_VOLMGR_PLEX_MISSING";
        case STATUS_VOLMGR_PLEX_REGENERATING:
            return "STATUS_VOLMGR_PLEX_REGENERATING";
        case STATUS_VOLMGR_PLEX_TYPE_INVALID:
            return "STATUS_VOLMGR_PLEX_TYPE_INVALID";
        case STATUS_VOLMGR_PLEX_NOT_RAID5:
            return "STATUS_VOLMGR_PLEX_NOT_RAID5";
        case STATUS_VOLMGR_PLEX_NOT_SIMPLE:
            return "STATUS_VOLMGR_PLEX_NOT_SIMPLE";
        case STATUS_VOLMGR_STRUCTURE_SIZE_INVALID:
            return "STATUS_VOLMGR_STRUCTURE_SIZE_INVALID";
        case STATUS_VOLMGR_TOO_MANY_NOTIFICATION_REQUESTS:
            return "STATUS_VOLMGR_TOO_MANY_NOTIFICATION_REQUESTS";
        case STATUS_VOLMGR_TRANSACTION_IN_PROGRESS:
            return "STATUS_VOLMGR_TRANSACTION_IN_PROGRESS";
        case STATUS_VOLMGR_UNEXPECTED_DISK_LAYOUT_CHANGE:
            return "STATUS_VOLMGR_UNEXPECTED_DISK_LAYOUT_CHANGE";
        case STATUS_VOLMGR_VOLUME_CONTAINS_MISSING_DISK:
            return "STATUS_VOLMGR_VOLUME_CONTAINS_MISSING_DISK";
        case STATUS_VOLMGR_VOLUME_ID_INVALID:
            return "STATUS_VOLMGR_VOLUME_ID_INVALID";
        case STATUS_VOLMGR_VOLUME_LENGTH_INVALID:
            return "STATUS_VOLMGR_VOLUME_LENGTH_INVALID";
        case STATUS_VOLMGR_VOLUME_LENGTH_NOT_SECTOR_SIZE_MULTIPLE:
            return "STATUS_VOLMGR_VOLUME_LENGTH_NOT_SECTOR_SIZE_MULTIPLE";
        case STATUS_VOLMGR_VOLUME_NOT_MIRRORED:
            return "STATUS_VOLMGR_VOLUME_NOT_MIRRORED";
        case STATUS_VOLMGR_VOLUME_NOT_RETAINED:
            return "STATUS_VOLMGR_VOLUME_NOT_RETAINED";
        case STATUS_VOLMGR_VOLUME_OFFLINE:
            return "STATUS_VOLMGR_VOLUME_OFFLINE";
        case STATUS_VOLMGR_VOLUME_RETAINED:
            return "STATUS_VOLMGR_VOLUME_RETAINED";
        case STATUS_VOLMGR_NUMBER_OF_EXTENTS_INVALID:
            return "STATUS_VOLMGR_NUMBER_OF_EXTENTS_INVALID";
        case STATUS_VOLMGR_DIFFERENT_SECTOR_SIZE:
            return "STATUS_VOLMGR_DIFFERENT_SECTOR_SIZE";
        case STATUS_VOLMGR_BAD_BOOT_DISK:
            return "STATUS_VOLMGR_BAD_BOOT_DISK";
        case STATUS_VOLMGR_PACK_CONFIG_OFFLINE:
            return "STATUS_VOLMGR_PACK_CONFIG_OFFLINE";
        case STATUS_VOLMGR_PACK_CONFIG_ONLINE:
            return "STATUS_VOLMGR_PACK_CONFIG_ONLINE";
        case STATUS_VOLMGR_NOT_PRIMARY_PACK:
            return "STATUS_VOLMGR_NOT_PRIMARY_PACK";
        case STATUS_VOLMGR_PACK_LOG_UPDATE_FAILED:
            return "STATUS_VOLMGR_PACK_LOG_UPDATE_FAILED";
        case STATUS_VOLMGR_NUMBER_OF_DISKS_IN_PLEX_INVALID:
            return "STATUS_VOLMGR_NUMBER_OF_DISKS_IN_PLEX_INVALID";
        case STATUS_VOLMGR_NUMBER_OF_DISKS_IN_MEMBER_INVALID:
            return "STATUS_VOLMGR_NUMBER_OF_DISKS_IN_MEMBER_INVALID";
        case STATUS_VOLMGR_VOLUME_MIRRORED:
            return "STATUS_VOLMGR_VOLUME_MIRRORED";
        case STATUS_VOLMGR_PLEX_NOT_SIMPLE_SPANNED:
            return "STATUS_VOLMGR_PLEX_NOT_SIMPLE_SPANNED";
        case STATUS_VOLMGR_NO_VALID_LOG_COPIES:
            return "STATUS_VOLMGR_NO_VALID_LOG_COPIES";
        case STATUS_VOLMGR_PRIMARY_PACK_PRESENT:
            return "STATUS_VOLMGR_PRIMARY_PACK_PRESENT";
        case STATUS_VOLMGR_NUMBER_OF_DISKS_INVALID:
            return "STATUS_VOLMGR_NUMBER_OF_DISKS_INVALID";
        case STATUS_VOLMGR_MIRROR_NOT_SUPPORTED:
            return "STATUS_VOLMGR_MIRROR_NOT_SUPPORTED";
        case STATUS_VOLMGR_RAID5_NOT_SUPPORTED:
            return "STATUS_VOLMGR_RAID5_NOT_SUPPORTED";
        case STATUS_BCD_NOT_ALL_ENTRIES_IMPORTED:
            return "STATUS_BCD_NOT_ALL_ENTRIES_IMPORTED";
        case STATUS_BCD_TOO_MANY_ELEMENTS:
            return "STATUS_BCD_TOO_MANY_ELEMENTS";
        case STATUS_BCD_NOT_ALL_ENTRIES_SYNCHRONIZED:
            return "STATUS_BCD_NOT_ALL_ENTRIES_SYNCHRONIZED";
        case STATUS_VHD_DRIVE_FOOTER_MISSING:
            return "STATUS_VHD_DRIVE_FOOTER_MISSING";
        case STATUS_VHD_DRIVE_FOOTER_CHECKSUM_MISMATCH:
            return "STATUS_VHD_DRIVE_FOOTER_CHECKSUM_MISMATCH";
        case STATUS_VHD_DRIVE_FOOTER_CORRUPT:
            return "STATUS_VHD_DRIVE_FOOTER_CORRUPT";
        case STATUS_VHD_FORMAT_UNKNOWN:
            return "STATUS_VHD_FORMAT_UNKNOWN";
        case STATUS_VHD_FORMAT_UNSUPPORTED_VERSION:
            return "STATUS_VHD_FORMAT_UNSUPPORTED_VERSION";
        case STATUS_VHD_SPARSE_HEADER_CHECKSUM_MISMATCH:
            return "STATUS_VHD_SPARSE_HEADER_CHECKSUM_MISMATCH";
        case STATUS_VHD_SPARSE_HEADER_UNSUPPORTED_VERSION:
            return "STATUS_VHD_SPARSE_HEADER_UNSUPPORTED_VERSION";
        case STATUS_VHD_SPARSE_HEADER_CORRUPT:
            return "STATUS_VHD_SPARSE_HEADER_CORRUPT";
        case STATUS_VHD_BLOCK_ALLOCATION_FAILURE:
            return "STATUS_VHD_BLOCK_ALLOCATION_FAILURE";
        case STATUS_VHD_BLOCK_ALLOCATION_TABLE_CORRUPT:
            return "STATUS_VHD_BLOCK_ALLOCATION_TABLE_CORRUPT";
        case STATUS_VHD_INVALID_BLOCK_SIZE:
            return "STATUS_VHD_INVALID_BLOCK_SIZE";
        case STATUS_VHD_BITMAP_MISMATCH:
            return "STATUS_VHD_BITMAP_MISMATCH";
        case STATUS_VHD_PARENT_VHD_NOT_FOUND:
            return "STATUS_VHD_PARENT_VHD_NOT_FOUND";
        case STATUS_VHD_CHILD_PARENT_ID_MISMATCH:
            return "STATUS_VHD_CHILD_PARENT_ID_MISMATCH";
        case STATUS_VHD_CHILD_PARENT_TIMESTAMP_MISMATCH:
            return "STATUS_VHD_CHILD_PARENT_TIMESTAMP_MISMATCH";
        case STATUS_VHD_METADATA_READ_FAILURE:
            return "STATUS_VHD_METADATA_READ_FAILURE";
        case STATUS_VHD_METADATA_WRITE_FAILURE:
            return "STATUS_VHD_METADATA_WRITE_FAILURE";
        case STATUS_VHD_INVALID_SIZE:
            return "STATUS_VHD_INVALID_SIZE";
        case STATUS_VHD_INVALID_FILE_SIZE:
            return "STATUS_VHD_INVALID_FILE_SIZE";
        case STATUS_VIRTDISK_PROVIDER_NOT_FOUND:
            return "STATUS_VIRTDISK_PROVIDER_NOT_FOUND";
        case STATUS_VIRTDISK_NOT_VIRTUAL_DISK:
            return "STATUS_VIRTDISK_NOT_VIRTUAL_DISK";
        case STATUS_VHD_PARENT_VHD_ACCESS_DENIED:
            return "STATUS_VHD_PARENT_VHD_ACCESS_DENIED";
        case STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH:
            return "STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH";
        case STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED:
            return "STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED";
        case STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT:
            return "STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT";
        case STATUS_VIRTUAL_DISK_LIMITATION:
            return "STATUS_VIRTUAL_DISK_LIMITATION";
        case STATUS_VHD_INVALID_TYPE:
            return "STATUS_VHD_INVALID_TYPE";
        case STATUS_VHD_INVALID_STATE:
            return "STATUS_VHD_INVALID_STATE";
        case STATUS_VIRTDISK_UNSUPPORTED_DISK_SECTOR_SIZE:
            return "STATUS_VIRTDISK_UNSUPPORTED_DISK_SECTOR_SIZE";
        case STATUS_VIRTDISK_DISK_ALREADY_OWNED:
            return "STATUS_VIRTDISK_DISK_ALREADY_OWNED";
        case STATUS_VIRTDISK_DISK_ONLINE_AND_WRITABLE:
            return "STATUS_VIRTDISK_DISK_ONLINE_AND_WRITABLE";
        case STATUS_CTLOG_TRACKING_NOT_INITIALIZED:
            return "STATUS_CTLOG_TRACKING_NOT_INITIALIZED";
        case STATUS_CTLOG_LOGFILE_SIZE_EXCEEDED_MAXSIZE:
            return "STATUS_CTLOG_LOGFILE_SIZE_EXCEEDED_MAXSIZE";
        case STATUS_CTLOG_VHD_CHANGED_OFFLINE:
            return "STATUS_CTLOG_VHD_CHANGED_OFFLINE";
        case STATUS_CTLOG_INVALID_TRACKING_STATE:
            return "STATUS_CTLOG_INVALID_TRACKING_STATE";
        case STATUS_CTLOG_INCONSISTENT_TRACKING_FILE:
            return "STATUS_CTLOG_INCONSISTENT_TRACKING_FILE";
        case STATUS_VHD_METADATA_FULL:
            return "STATUS_VHD_METADATA_FULL";
        case STATUS_VHD_INVALID_CHANGE_TRACKING_ID:
            return "STATUS_VHD_INVALID_CHANGE_TRACKING_ID";
        case STATUS_VHD_CHANGE_TRACKING_DISABLED:
            return "STATUS_VHD_CHANGE_TRACKING_DISABLED";
        case STATUS_VHD_MISSING_CHANGE_TRACKING_INFORMATION:
            return "STATUS_VHD_MISSING_CHANGE_TRACKING_INFORMATION";
        case STATUS_VHD_RESIZE_WOULD_TRUNCATE_DATA:
            return "STATUS_VHD_RESIZE_WOULD_TRUNCATE_DATA";
        case STATUS_VHD_COULD_NOT_COMPUTE_MINIMUM_VIRTUAL_SIZE:
            return "STATUS_VHD_COULD_NOT_COMPUTE_MINIMUM_VIRTUAL_SIZE";
        case STATUS_VHD_ALREADY_AT_OR_BELOW_MINIMUM_VIRTUAL_SIZE:
            return "STATUS_VHD_ALREADY_AT_OR_BELOW_MINIMUM_VIRTUAL_SIZE";
        case STATUS_QUERY_STORAGE_ERROR:
            return "STATUS_QUERY_STORAGE_ERROR";
        case STATUS_GDI_HANDLE_LEAK:
            return "STATUS_GDI_HANDLE_LEAK";
        case STATUS_RKF_KEY_NOT_FOUND:
            return "STATUS_RKF_KEY_NOT_FOUND";
        case STATUS_RKF_DUPLICATE_KEY:
            return "STATUS_RKF_DUPLICATE_KEY";
        case STATUS_RKF_BLOB_FULL:
            return "STATUS_RKF_BLOB_FULL";
        case STATUS_RKF_STORE_FULL:
            return "STATUS_RKF_STORE_FULL";
        case STATUS_RKF_FILE_BLOCKED:
            return "STATUS_RKF_FILE_BLOCKED";
        case STATUS_RKF_ACTIVE_KEY:
            return "STATUS_RKF_ACTIVE_KEY";
        case STATUS_RDBSS_RESTART_OPERATION:
            return "STATUS_RDBSS_RESTART_OPERATION";
        case STATUS_RDBSS_CONTINUE_OPERATION:
            return "STATUS_RDBSS_CONTINUE_OPERATION";
        case STATUS_RDBSS_POST_OPERATION:
            return "STATUS_RDBSS_POST_OPERATION";
        case STATUS_RDBSS_RETRY_LOOKUP:
            return "STATUS_RDBSS_RETRY_LOOKUP";
        case STATUS_BTH_ATT_INVALID_HANDLE:
            return "STATUS_BTH_ATT_INVALID_HANDLE";
        case STATUS_BTH_ATT_READ_NOT_PERMITTED:
            return "STATUS_BTH_ATT_READ_NOT_PERMITTED";
        case STATUS_BTH_ATT_WRITE_NOT_PERMITTED:
            return "STATUS_BTH_ATT_WRITE_NOT_PERMITTED";
        case STATUS_BTH_ATT_INVALID_PDU:
            return "STATUS_BTH_ATT_INVALID_PDU";
        case STATUS_BTH_ATT_INSUFFICIENT_AUTHENTICATION:
            return "STATUS_BTH_ATT_INSUFFICIENT_AUTHENTICATION";
        case STATUS_BTH_ATT_REQUEST_NOT_SUPPORTED:
            return "STATUS_BTH_ATT_REQUEST_NOT_SUPPORTED";
        case STATUS_BTH_ATT_INVALID_OFFSET:
            return "STATUS_BTH_ATT_INVALID_OFFSET";
        case STATUS_BTH_ATT_INSUFFICIENT_AUTHORIZATION:
            return "STATUS_BTH_ATT_INSUFFICIENT_AUTHORIZATION";
        case STATUS_BTH_ATT_PREPARE_QUEUE_FULL:
            return "STATUS_BTH_ATT_PREPARE_QUEUE_FULL";
        case STATUS_BTH_ATT_ATTRIBUTE_NOT_FOUND:
            return "STATUS_BTH_ATT_ATTRIBUTE_NOT_FOUND";
        case STATUS_BTH_ATT_ATTRIBUTE_NOT_LONG:
            return "STATUS_BTH_ATT_ATTRIBUTE_NOT_LONG";
        case STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE:
            return "STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE";
        case STATUS_BTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH:
            return "STATUS_BTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH";
        case STATUS_BTH_ATT_UNLIKELY:
            return "STATUS_BTH_ATT_UNLIKELY";
        case STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION:
            return "STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION";
        case STATUS_BTH_ATT_UNSUPPORTED_GROUP_TYPE:
            return "STATUS_BTH_ATT_UNSUPPORTED_GROUP_TYPE";
        case STATUS_BTH_ATT_INSUFFICIENT_RESOURCES:
            return "STATUS_BTH_ATT_INSUFFICIENT_RESOURCES";
        case STATUS_BTH_ATT_UNKNOWN_ERROR:
            return "STATUS_BTH_ATT_UNKNOWN_ERROR";
        case STATUS_SECUREBOOT_ROLLBACK_DETECTED:
            return "STATUS_SECUREBOOT_ROLLBACK_DETECTED";
        case STATUS_SECUREBOOT_POLICY_VIOLATION:
            return "STATUS_SECUREBOOT_POLICY_VIOLATION";
        case STATUS_SECUREBOOT_INVALID_POLICY:
            return "STATUS_SECUREBOOT_INVALID_POLICY";
        case STATUS_SECUREBOOT_POLICY_PUBLISHER_NOT_FOUND:
            return "STATUS_SECUREBOOT_POLICY_PUBLISHER_NOT_FOUND";
        case STATUS_SECUREBOOT_POLICY_NOT_SIGNED:
            return "STATUS_SECUREBOOT_POLICY_NOT_SIGNED";
        case STATUS_SECUREBOOT_NOT_ENABLED:
            return "STATUS_SECUREBOOT_NOT_ENABLED";
        case STATUS_SECUREBOOT_FILE_REPLACED:
            return "STATUS_SECUREBOOT_FILE_REPLACED";
        case STATUS_SECUREBOOT_POLICY_NOT_AUTHORIZED:
            return "STATUS_SECUREBOOT_POLICY_NOT_AUTHORIZED";
        case STATUS_SECUREBOOT_POLICY_UNKNOWN:
            return "STATUS_SECUREBOOT_POLICY_UNKNOWN";
        case STATUS_SECUREBOOT_POLICY_MISSING_ANTIROLLBACKVERSION:
            return "STATUS_SECUREBOOT_POLICY_MISSING_ANTIROLLBACKVERSION";
        case STATUS_SECUREBOOT_PLATFORM_ID_MISMATCH:
            return "STATUS_SECUREBOOT_PLATFORM_ID_MISMATCH";
        case STATUS_SECUREBOOT_POLICY_ROLLBACK_DETECTED:
            return "STATUS_SECUREBOOT_POLICY_ROLLBACK_DETECTED";
        case STATUS_SECUREBOOT_POLICY_UPGRADE_MISMATCH:
            return "STATUS_SECUREBOOT_POLICY_UPGRADE_MISMATCH";
        case STATUS_SECUREBOOT_REQUIRED_POLICY_FILE_MISSING:
            return "STATUS_SECUREBOOT_REQUIRED_POLICY_FILE_MISSING";
        case STATUS_SECUREBOOT_NOT_BASE_POLICY:
            return "STATUS_SECUREBOOT_NOT_BASE_POLICY";
        case STATUS_SECUREBOOT_NOT_SUPPLEMENTAL_POLICY:
            return "STATUS_SECUREBOOT_NOT_SUPPLEMENTAL_POLICY";
        case STATUS_PLATFORM_MANIFEST_NOT_AUTHORIZED:
            return "STATUS_PLATFORM_MANIFEST_NOT_AUTHORIZED";
        case STATUS_PLATFORM_MANIFEST_INVALID:
            return "STATUS_PLATFORM_MANIFEST_INVALID";
        case STATUS_PLATFORM_MANIFEST_FILE_NOT_AUTHORIZED:
            return "STATUS_PLATFORM_MANIFEST_FILE_NOT_AUTHORIZED";
        case STATUS_PLATFORM_MANIFEST_CATALOG_NOT_AUTHORIZED:
            return "STATUS_PLATFORM_MANIFEST_CATALOG_NOT_AUTHORIZED";
        case STATUS_PLATFORM_MANIFEST_BINARY_ID_NOT_FOUND:
            return "STATUS_PLATFORM_MANIFEST_BINARY_ID_NOT_FOUND";
        case STATUS_PLATFORM_MANIFEST_NOT_ACTIVE:
            return "STATUS_PLATFORM_MANIFEST_NOT_ACTIVE";
        case STATUS_PLATFORM_MANIFEST_NOT_SIGNED:
            return "STATUS_PLATFORM_MANIFEST_NOT_SIGNED";
        case STATUS_SYSTEM_INTEGRITY_ROLLBACK_DETECTED:
            return "STATUS_SYSTEM_INTEGRITY_ROLLBACK_DETECTED";
        case STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION:
            return "STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION";
        case STATUS_SYSTEM_INTEGRITY_INVALID_POLICY:
            return "STATUS_SYSTEM_INTEGRITY_INVALID_POLICY";
        case STATUS_SYSTEM_INTEGRITY_POLICY_NOT_SIGNED:
            return "STATUS_SYSTEM_INTEGRITY_POLICY_NOT_SIGNED";
        case STATUS_NO_APPLICABLE_APP_LICENSES_FOUND:
            return "STATUS_NO_APPLICABLE_APP_LICENSES_FOUND";
        case STATUS_CLIP_LICENSE_NOT_FOUND:
            return "STATUS_CLIP_LICENSE_NOT_FOUND";
        case STATUS_CLIP_DEVICE_LICENSE_MISSING:
            return "STATUS_CLIP_DEVICE_LICENSE_MISSING";
        case STATUS_CLIP_LICENSE_INVALID_SIGNATURE:
            return "STATUS_CLIP_LICENSE_INVALID_SIGNATURE";
        case STATUS_CLIP_KEYHOLDER_LICENSE_MISSING_OR_INVALID:
            return "STATUS_CLIP_KEYHOLDER_LICENSE_MISSING_OR_INVALID";
        case STATUS_CLIP_LICENSE_EXPIRED:
            return "STATUS_CLIP_LICENSE_EXPIRED";
        case STATUS_CLIP_LICENSE_SIGNED_BY_UNKNOWN_SOURCE:
            return "STATUS_CLIP_LICENSE_SIGNED_BY_UNKNOWN_SOURCE";
        case STATUS_CLIP_LICENSE_NOT_SIGNED:
            return "STATUS_CLIP_LICENSE_NOT_SIGNED";
        case STATUS_CLIP_LICENSE_HARDWARE_ID_OUT_OF_TOLERANCE:
            return "STATUS_CLIP_LICENSE_HARDWARE_ID_OUT_OF_TOLERANCE";
        case STATUS_CLIP_LICENSE_DEVICE_ID_MISMATCH:
            return "STATUS_CLIP_LICENSE_DEVICE_ID_MISMATCH";
        case STATUS_AUDIO_ENGINE_NODE_NOT_FOUND:
            return "STATUS_AUDIO_ENGINE_NODE_NOT_FOUND";
        case STATUS_HDAUDIO_EMPTY_CONNECTION_LIST:
            return "STATUS_HDAUDIO_EMPTY_CONNECTION_LIST";
        case STATUS_HDAUDIO_CONNECTION_LIST_NOT_SUPPORTED:
            return "STATUS_HDAUDIO_CONNECTION_LIST_NOT_SUPPORTED";
        case STATUS_HDAUDIO_NO_LOGICAL_DEVICES_CREATED:
            return "STATUS_HDAUDIO_NO_LOGICAL_DEVICES_CREATED";
        case STATUS_HDAUDIO_NULL_LINKED_LIST_ENTRY:
            return "STATUS_HDAUDIO_NULL_LINKED_LIST_ENTRY";
        case STATUS_SPACES_REPAIRED:
            return "STATUS_SPACES_REPAIRED";
        case STATUS_SPACES_PAUSE:
            return "STATUS_SPACES_PAUSE";
        case STATUS_SPACES_COMPLETE:
            return "STATUS_SPACES_COMPLETE";
        case STATUS_SPACES_REDIRECT:
            return "STATUS_SPACES_REDIRECT";
        case STATUS_SPACES_FAULT_DOMAIN_TYPE_INVALID:
            return "STATUS_SPACES_FAULT_DOMAIN_TYPE_INVALID";
        case STATUS_SPACES_RESILIENCY_TYPE_INVALID:
            return "STATUS_SPACES_RESILIENCY_TYPE_INVALID";
        case STATUS_SPACES_DRIVE_SECTOR_SIZE_INVALID:
            return "STATUS_SPACES_DRIVE_SECTOR_SIZE_INVALID";
        case STATUS_SPACES_DRIVE_REDUNDANCY_INVALID:
            return "STATUS_SPACES_DRIVE_REDUNDANCY_INVALID";
        case STATUS_SPACES_NUMBER_OF_DATA_COPIES_INVALID:
            return "STATUS_SPACES_NUMBER_OF_DATA_COPIES_INVALID";
        case STATUS_SPACES_INTERLEAVE_LENGTH_INVALID:
            return "STATUS_SPACES_INTERLEAVE_LENGTH_INVALID";
        case STATUS_SPACES_NUMBER_OF_COLUMNS_INVALID:
            return "STATUS_SPACES_NUMBER_OF_COLUMNS_INVALID";
        case STATUS_SPACES_NOT_ENOUGH_DRIVES:
            return "STATUS_SPACES_NOT_ENOUGH_DRIVES";
        case STATUS_SPACES_EXTENDED_ERROR:
            return "STATUS_SPACES_EXTENDED_ERROR";
        case STATUS_SPACES_PROVISIONING_TYPE_INVALID:
            return "STATUS_SPACES_PROVISIONING_TYPE_INVALID";
        case STATUS_SPACES_ALLOCATION_SIZE_INVALID:
            return "STATUS_SPACES_ALLOCATION_SIZE_INVALID";
        case STATUS_SPACES_ENCLOSURE_AWARE_INVALID:
            return "STATUS_SPACES_ENCLOSURE_AWARE_INVALID";
        case STATUS_SPACES_WRITE_CACHE_SIZE_INVALID:
            return "STATUS_SPACES_WRITE_CACHE_SIZE_INVALID";
        case STATUS_SPACES_NUMBER_OF_GROUPS_INVALID:
            return "STATUS_SPACES_NUMBER_OF_GROUPS_INVALID";
        case STATUS_SPACES_DRIVE_OPERATIONAL_STATE_INVALID:
            return "STATUS_SPACES_DRIVE_OPERATIONAL_STATE_INVALID";
        case STATUS_SPACES_UPDATE_COLUMN_STATE:
            return "STATUS_SPACES_UPDATE_COLUMN_STATE";
        case STATUS_SPACES_MAP_REQUIRED:
            return "STATUS_SPACES_MAP_REQUIRED";
        case STATUS_SPACES_UNSUPPORTED_VERSION:
            return "STATUS_SPACES_UNSUPPORTED_VERSION";
        case STATUS_SPACES_CORRUPT_METADATA:
            return "STATUS_SPACES_CORRUPT_METADATA";
        case STATUS_SPACES_DRT_FULL:
            return "STATUS_SPACES_DRT_FULL";
        case STATUS_SPACES_INCONSISTENCY:
            return "STATUS_SPACES_INCONSISTENCY";
        case STATUS_SPACES_LOG_NOT_READY:
            return "STATUS_SPACES_LOG_NOT_READY";
        case STATUS_SPACES_NO_REDUNDANCY:
            return "STATUS_SPACES_NO_REDUNDANCY";
        case STATUS_SPACES_DRIVE_NOT_READY:
            return "STATUS_SPACES_DRIVE_NOT_READY";
        case STATUS_SPACES_DRIVE_SPLIT:
            return "STATUS_SPACES_DRIVE_SPLIT";
        case STATUS_SPACES_DRIVE_LOST_DATA:
            return "STATUS_SPACES_DRIVE_LOST_DATA";
        case STATUS_SPACES_ENTRY_INCOMPLETE:
            return "STATUS_SPACES_ENTRY_INCOMPLETE";
        case STATUS_SPACES_ENTRY_INVALID:
            return "STATUS_SPACES_ENTRY_INVALID";
        case STATUS_VOLSNAP_BOOTFILE_NOT_VALID:
            return "STATUS_VOLSNAP_BOOTFILE_NOT_VALID";
        case STATUS_VOLSNAP_ACTIVATION_TIMEOUT:
            return "STATUS_VOLSNAP_ACTIVATION_TIMEOUT";
        case STATUS_IO_PREEMPTED:
            return "STATUS_IO_PREEMPTED";
        case STATUS_SVHDX_ERROR_STORED:
            return "STATUS_SVHDX_ERROR_STORED";
        case STATUS_SVHDX_ERROR_NOT_AVAILABLE:
            return "STATUS_SVHDX_ERROR_NOT_AVAILABLE";
        case STATUS_SVHDX_UNIT_ATTENTION_AVAILABLE:
            return "STATUS_SVHDX_UNIT_ATTENTION_AVAILABLE";
        case STATUS_SVHDX_UNIT_ATTENTION_CAPACITY_DATA_CHANGED:
            return "STATUS_SVHDX_UNIT_ATTENTION_CAPACITY_DATA_CHANGED";
        case STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_PREEMPTED:
            return "STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_PREEMPTED";
        case STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_RELEASED:
            return "STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_RELEASED";
        case STATUS_SVHDX_UNIT_ATTENTION_REGISTRATIONS_PREEMPTED:
            return "STATUS_SVHDX_UNIT_ATTENTION_REGISTRATIONS_PREEMPTED";
        case STATUS_SVHDX_UNIT_ATTENTION_OPERATING_DEFINITION_CHANGED:
            return "STATUS_SVHDX_UNIT_ATTENTION_OPERATING_DEFINITION_CHANGED";
        case STATUS_SVHDX_RESERVATION_CONFLICT:
            return "STATUS_SVHDX_RESERVATION_CONFLICT";
        case STATUS_SVHDX_WRONG_FILE_TYPE:
            return "STATUS_SVHDX_WRONG_FILE_TYPE";
        case STATUS_SVHDX_VERSION_MISMATCH:
            return "STATUS_SVHDX_VERSION_MISMATCH";
        case STATUS_VHD_SHARED:
            return "STATUS_VHD_SHARED";
        case STATUS_SVHDX_NO_INITIATOR:
            return "STATUS_SVHDX_NO_INITIATOR";
        case STATUS_VHDSET_BACKING_STORAGE_NOT_FOUND:
            return "STATUS_VHDSET_BACKING_STORAGE_NOT_FOUND";
        case STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP:
            return "STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP";
        case STATUS_SMB_BAD_CLUSTER_DIALECT:
            return "STATUS_SMB_BAD_CLUSTER_DIALECT";
        case STATUS_SMB_GUEST_LOGON_BLOCKED:
            return "STATUS_SMB_GUEST_LOGON_BLOCKED";
        case STATUS_SECCORE_INVALID_COMMAND:
            return "STATUS_SECCORE_INVALID_COMMAND";
        case STATUS_VSM_NOT_INITIALIZED:
            return "STATUS_VSM_NOT_INITIALIZED";
        case STATUS_VSM_DMA_PROTECTION_NOT_IN_USE:
            return "STATUS_VSM_DMA_PROTECTION_NOT_IN_USE";
        case STATUS_APPEXEC_CONDITION_NOT_SATISFIED:
            return "STATUS_APPEXEC_CONDITION_NOT_SATISFIED";
        case STATUS_APPEXEC_HANDLE_INVALIDATED:
            return "STATUS_APPEXEC_HANDLE_INVALIDATED";
        case STATUS_APPEXEC_INVALID_HOST_GENERATION:
            return "STATUS_APPEXEC_INVALID_HOST_GENERATION";
        case STATUS_APPEXEC_UNEXPECTED_PROCESS_REGISTRATION:
            return "STATUS_APPEXEC_UNEXPECTED_PROCESS_REGISTRATION";
        case STATUS_APPEXEC_INVALID_HOST_STATE:
            return "STATUS_APPEXEC_INVALID_HOST_STATE";
        case STATUS_APPEXEC_NO_DONOR:
            return "STATUS_APPEXEC_NO_DONOR";
        case STATUS_APPEXEC_HOST_ID_MISMATCH:
            return "STATUS_APPEXEC_HOST_ID_MISMATCH";
        case STATUS_APPEXEC_UNKNOWN_USER:
            return "STATUS_APPEXEC_UNKNOWN_USER";
    }
    return NULL;
}

#endif
