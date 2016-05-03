/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014-2016 Tamas K Lengyel.  *
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

#ifndef VMI_H
#define VMI_H

#include "private.h"

#define BIT32 0
#define BIT64 1
#define PM2BIT(pm) ((pm == VMI_PM_IA32E) ? BIT64 : BIT32)

#define TRAP 0xCC

#define ghashtable_foreach(table, i, key, val) \
      g_hash_table_iter_init(&i, table); \
      while(g_hash_table_iter_next(&i,(void**)&key,(void**)&val))

#define NOW(ts) \
      do { \
          GTimeVal __now; \
          g_get_current_time(&__now); \
          *ts = g_time_val_to_iso8601(&__now); \
      } while(0)

enum offset {

    KIINITIALPCR,
    KDDEBUGGERDATABLOCK,
    PSINITIALSYSTEMPROCESS,

    EPROCESS_PID,
    EPROCESS_PDBASE,
    EPROCESS_PNAME,
    EPROCESS_TASKS,
    EPROCESS_PEB,
    EPROCESS_OBJECTTABLE,
    EPROCESS_PCB,

    KPROCESS_HEADER,

    PEB_IMAGEBASADDRESS,
    PEB_LDR,

    PEB_LDR_DATA_INLOADORDERMODULELIST,

    LDR_DATA_TABLE_ENTRY_DLLBASE,
    LDR_DATA_TABLE_ENTRY_SIZEOFIMAGE,
    LDR_DATA_TABLE_ENTRY_BASEDLLNAME,

    FILE_OBJECT_DEVICEOBJECT,
    FILE_OBJECT_READACCESS,
    FILE_OBJECT_WRITEACCESS,
    FILE_OBJECT_DELETEACCESS,
    FILE_OBJECT_FILENAME,

    HANDLE_TABLE_HANDLECOUNT,

    KPCR_PRCB,
    KPCR_PRCBDATA,
    KPRCB_CURRENTTHREAD,

    KTHREAD_PROCESS,
    KTHREAD_INITIALSTACK,
    KTHREAD_STACKLIMIT,
    KTHREAD_APCSTATE,
    KTHREAD_TRAPFRAME,
    KTHREAD_APCQUEUEABLE,
    KTHREAD_PREVIOUSMODE,
    KTHREAD_HEADER,

    KTRAP_FRAME_RIP,

    KAPC_APCLISTENTRY,

    NT_TIB_STACKBASE,
    NT_TIB_STACKLIMIT,

    ETHREAD_CID,
    ETHREAD_TCB,
    CLIENT_ID_UNIQUETHREAD,

    OBJECT_HEADER_TYPEINDEX,
    OBJECT_HEADER_BODY,

    UNICODE_STRING_LENGTH,
    UNICODE_STRING_BUFFER,

    POOL_HEADER_BLOCKSIZE,
    POOL_HEADER_POOLTYPE,
    POOL_HEADER_POOLTAG,

    DISPATCHER_TYPE,

    OFFSET_MAX
};

static const char *offset_names[OFFSET_MAX][2] = {
    [KIINITIALPCR] = { "KiInitialPCR", NULL },
    [KDDEBUGGERDATABLOCK] = { "KdDebuggerDataBlock", NULL },
    [PSINITIALSYSTEMPROCESS] = { "PsInitialSystemProcess", NULL },
    [EPROCESS_PID] = { "_EPROCESS", "UniqueProcessId" },
    [EPROCESS_PDBASE] = { "_KPROCESS", "DirectoryTableBase" },
    [EPROCESS_PNAME] = { "_EPROCESS", "ImageFileName" },
    [EPROCESS_TASKS] = { "_EPROCESS", "ActiveProcessLinks" },
    [EPROCESS_PEB] = { "_EPROCESS", "Peb" },
    [EPROCESS_OBJECTTABLE] = {"_EPROCESS", "ObjectTable" },
    [EPROCESS_PCB] = { "_EPROCESS", "Pcb" },
    [KPROCESS_HEADER] = { "_KPROCESS", "Header" },
    [PEB_IMAGEBASADDRESS] = { "_PEB", "ImageBaseAddress" },
    [PEB_LDR] = { "_PEB", "Ldr" },
    [PEB_LDR_DATA_INLOADORDERMODULELIST] = {"_PEB_LDR_DATA", "InLoadOrderModuleList" },
    [LDR_DATA_TABLE_ENTRY_DLLBASE] = { "_LDR_DATA_TABLE_ENTRY", "DllBase" },
    [LDR_DATA_TABLE_ENTRY_SIZEOFIMAGE] = { "_LDR_DATA_TABLE_ENTRY", "SizeOfImage" },
    [LDR_DATA_TABLE_ENTRY_BASEDLLNAME] = { "_LDR_DATA_TABLE_ENTRY", "BaseDllName" },
    [FILE_OBJECT_DEVICEOBJECT] = {"_FILE_OBJECT", "DeviceObject" },
    [FILE_OBJECT_READACCESS] = {"_FILE_OBJECT", "ReadAccess" },
    [FILE_OBJECT_WRITEACCESS] = {"_FILE_OBJECT", "WriteAccess" },
    [FILE_OBJECT_DELETEACCESS] = {"_FILE_OBJECT", "DeleteAccess" },
    [FILE_OBJECT_FILENAME] = {"_FILE_OBJECT", "FileName"},
    [HANDLE_TABLE_HANDLECOUNT] = {"_HANDLE_TABLE", "HandleCount" },
    [KPCR_PRCB] = {"_KPCR", "Prcb" },
    [KPCR_PRCBDATA] = {"_KPCR", "PrcbData" },
    [KPRCB_CURRENTTHREAD] = { "_KPRCB", "CurrentThread" },
    [KTHREAD_PROCESS] = {"_KTHREAD", "Process" },
    [KTHREAD_INITIALSTACK] = {"_KTHREAD", "InitialStack"},
    [KTHREAD_STACKLIMIT] = {"_KTHREAD", "StackLimit"},
    [KTHREAD_TRAPFRAME] = {"_KTHREAD", "TrapFrame" },
    [KTHREAD_APCSTATE] = {"_KTHREAD", "ApcState" },
    [KTHREAD_APCQUEUEABLE] = {"_KTHREAD", "ApcQueueable"},
    [KTHREAD_PREVIOUSMODE] = { "_KTHREAD", "PreviousMode" },
    [KTHREAD_HEADER] = { "_KTHREAD", "Header" },
    [KAPC_APCLISTENTRY] = {"_KAPC", "ApcListEntry" },
    [KTRAP_FRAME_RIP] = {"_KTRAP_FRAME", "Rip" },
    [NT_TIB_STACKBASE] = { "_NT_TIB", "StackBase" },
    [NT_TIB_STACKLIMIT] = { "_NT_TIB", "StackLimit" },
    [ETHREAD_CID] = {"_ETHREAD", "Cid" },
    [ETHREAD_TCB] = { "_ETHREAD", "Tcb" },
    [CLIENT_ID_UNIQUETHREAD] = {"_CLIENT_ID", "UniqueThread" },
    [OBJECT_HEADER_TYPEINDEX] = { "_OBJECT_HEADER", "TypeIndex" },
    [OBJECT_HEADER_BODY] = { "_OBJECT_HEADER", "Body" },
    [UNICODE_STRING_LENGTH] = {"_UNICODE_STRING", "Length" },
    [UNICODE_STRING_BUFFER] = {"_UNICODE_STRING", "Buffer" },
    [POOL_HEADER_BLOCKSIZE] = {"_POOL_HEADER", "BlockSize" },
    [POOL_HEADER_POOLTYPE] = {"_POOL_HEADER", "PoolType" },
    [POOL_HEADER_POOLTAG] = {"_POOL_HEADER", "PoolTag" },
    [DISPATCHER_TYPE] = { "_DISPATCHER_HEADER",  "Type" },
};

size_t offsets[OFFSET_MAX];

enum size {
    FILE_OBJECT,
    //OBJECT_ATTRIBUTES,
    //OBJECT_HEADER,
    POOL_HEADER,

    SIZE_LIST_MAX
};

static const char *size_names[SIZE_LIST_MAX] = {
        [FILE_OBJECT] = "_FILE_OBJECT",
        //[OBJECT_ATTRIBUTES] = "_OBJECT_ATTRIBUTES", // May be useful TODO
        //[OBJECT_HEADER] = "_OBJECT_HEADER",
        [POOL_HEADER] = "_POOL_HEADER",
};

// Aligned object sizes
size_t struct_sizes[SIZE_LIST_MAX];

bool init_vmi(drakvuf_t drakvuf);
void close_vmi(drakvuf_t drakvuf);

event_response_t trap_guard(vmi_instance_t vmi, vmi_event_t *event);
event_response_t vmi_reset_trap(vmi_instance_t vmi, vmi_event_t *event);
event_response_t vmi_save_and_reset_trap(vmi_instance_t vmi, vmi_event_t *event);

bool inject_trap_mem(drakvuf_t drakvuf,
                     drakvuf_trap_t *trap);
bool inject_trap_pa(drakvuf_t drakvuf,
                    drakvuf_trap_t *trap,
                    addr_t pa);
bool inject_traps_modules(drakvuf_t drakvuf,
                          drakvuf_trap_t *trap,
                          addr_t list_head,
                          vmi_pid_t pid);
void remove_trap(drakvuf_t drakvuf,
                 const drakvuf_trap_t *trap);

#endif
