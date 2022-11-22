/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2022 Tamas K Lengyel.                                  *
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

#ifndef WIN_OFFSETS_MAP_H
#define WIN_OFFSETS_MAP_H

/*
 * Map offset enums to actual structure+member or global variable/function names.
 */
static const char* win_offset_names[__WIN_OFFSETS_MAX][2] =
{
    [KIINITIALPCR] = { "KiInitialPCR", NULL },
    [EPROCESS_PID] = { "_EPROCESS", "UniqueProcessId" },
    [EPROCESS_PDBASE] = { "_KPROCESS", "DirectoryTableBase" },
    [EPROCESS_PNAME] = { "_EPROCESS", "ImageFileName" },
    [EPROCESS_PROCCREATIONINFO] = { "_EPROCESS", "SeAuditProcessCreationInfo" },
    [EPROCESS_TASKS] = { "_EPROCESS", "ActiveProcessLinks" },
    [EPROCESS_THREADLISTHEAD] = { "_EPROCESS", "ThreadListHead" },
    [EPROCESS_PEB] = { "_EPROCESS", "Peb" },
    [EPROCESS_OBJECTTABLE] = {"_EPROCESS", "ObjectTable" },
    [EPROCESS_PCB] = { "_EPROCESS", "Pcb" },
    [EPROCESS_INHERITEDPID] = { "_EPROCESS", "InheritedFromUniqueProcessId" },
    [EPROCESS_WOW64PROCESS] = { "_EPROCESS", "Wow64Process" },
    [EPROCESS_WOW64PROCESS_WIN10] = { "_EPROCESS", "WoW64Process" },
    [EPROCESS_VADROOT] = { "_EPROCESS", "VadRoot" },
    [EPROCESS_LISTTHREADHEAD] = { "_EPROCESS", "ThreadListHead" },
    [EPROCESS_SECTIONOBJECT] = { "_EPROCESS", "SectionObject" },

    [SECTIONOBJECT_SEGMENT] = { "_SECTION_OBJECT", "Segment" },
    [SECTION_CONTROLAREA] = { "_SECTION", "ControlArea" },
    [SEGMENT_CONTROLAREA] = { "_SEGMENT", "ControlArea" },

    // Windows >=8 specific
    [RTL_AVL_TREE_ROOT] = { "_RTL_AVL_TREE", "Root"},
    [RTL_BALANCED_NODE_LEFT] = {"_RTL_BALANCED_NODE", "Left"},
    [RTL_BALANCED_NODE_RIGHT] = {"_RTL_BALANCED_NODE", "Right"},
    [RTL_BALANCED_NODE_PARENTVALUE] = {"_RTL_BALANCED_NODE", "ParentValue"},
    [MMVAD_CORE] = {"_MMVAD", "Core"},
    [MMVAD_SHORT_STARTING_VPN] = {"_MMVAD_SHORT", "StartingVpn"},
    [MMVAD_SHORT_STARTING_VPN_HIGH] = {"_MMVAD_SHORT", "StartingVpnHigh"},
    [MMVAD_SHORT_ENDING_VPN] = {"_MMVAD_SHORT", "EndingVpn"},
    [MMVAD_SHORT_ENDING_VPN_HIGH] = {"_MMVAD_SHORT", "EndingVpnHigh"},
    [MMVAD_SHORT_FLAGS] = { "_MMVAD_SHORT", "u" },
    [MMVAD_SHORT_FLAGS1] = { "_MMVAD_SHORT", "u1" },

    [VADROOT_BALANCED_ROOT] = { "VadRoot", "BalancedRoot" },
    [MMVAD_LEFT_CHILD] = { "_MMVAD", "LeftChild" },
    [MMVAD_RIGHT_CHILD] = { "_MMVAD", "RightChild" },
    [MMVAD_STARTING_VPN] = { "_MMVAD", "StartingVpn" },
    [MMVAD_ENDING_VPN] = { "_MMVAD", "EndingVpn" },
    [MMVAD_FLAGS] = { "_MMVAD", "u" },
    [MMVAD_SUBSECTION] = { "_MMVAD", "Subsection" },
    [SUBSECTION_CONTROL_AREA] = { "_SUBSECTION", "ControlArea" },
    [CONTROL_AREA_FILEPOINTER] = { "_CONTROL_AREA", "FilePointer" },
    [CONTROL_AREA_SEGMENT] = { "_CONTROL_AREA", "Segment" },
    [SEGMENT_TOTALNUMBEROFPTES] = { "_SEGMENT", "TotalNumberOfPtes"},
    [SEGMENT_PROTOTYPEPTE] = { "_SEGMENT", "PrototypePte"},

    [KPROCESS_HEADER] = { "_KPROCESS", "Header" },
    [PEB_IMAGEBASADDRESS] = { "_PEB", "ImageBaseAddress" },
    [PEB_LDR] = { "_PEB", "Ldr" },
    [PEB_PROCESSPARAMETERS] = { "_PEB", "ProcessParameters" },
    [PEB_SESSIONID] = { "_PEB", "SessionId" },
    [PEB_CSDVERSION] = { "_PEB", "CSDVersion"},
    [PEB_LDR_DATA_INLOADORDERMODULELIST] = {"_PEB_LDR_DATA", "InLoadOrderModuleList" },
    [LDR_DATA_TABLE_ENTRY_DLLBASE] = { "_LDR_DATA_TABLE_ENTRY", "DllBase" },
    [LDR_DATA_TABLE_ENTRY_SIZEOFIMAGE] = { "_LDR_DATA_TABLE_ENTRY", "SizeOfImage" },
    [LDR_DATA_TABLE_ENTRY_BASEDLLNAME] = { "_LDR_DATA_TABLE_ENTRY", "BaseDllName" },
    [LDR_DATA_TABLE_ENTRY_FULLDLLNAME] = { "_LDR_DATA_TABLE_ENTRY", "FullDllName" },
    [HANDLE_TABLE_TABLECODE] = {"_HANDLE_TABLE", "TableCode" },
    [KPCR_PRCB] = {"_KPCR", "Prcb" },
    [KPCR_PRCBDATA] = {"_KPCR", "PrcbData" },
    [KPCR_IRQL] = { "_KPCR", "Irql" },
    [KPRCB_CURRENTTHREAD] = { "_KPRCB", "CurrentThread" },
    [KTHREAD_APCSTATE] = {"_KTHREAD", "ApcState" },
    [KTHREAD_APCSTATEINDEX] = {"_KTHREAD", "ApcStateIndex" },
    [KTHREAD_PROCESS] = {"_KTHREAD", "Process" },
    [KTHREAD_PREVIOUSMODE] = { "_KTHREAD", "PreviousMode" },
    [KTHREAD_HEADER] = { "_KTHREAD", "Header" },
    [KTHREAD_TEB] = { "_KTHREAD", "Teb" },
    [KTHREAD_STACKBASE] = { "_KTHREAD", "StackBase" },
    [KTHREAD_TRAPFRAME] = { "_KTHREAD", "TrapFrame" },
    [KTHREAD_STATE] = { "_KTHREAD", "State" },
    [KAPC_STATE_PROCESS] = { "_KAPC_STATE", "Process" },
    [KTRAP_FRAME_RBP] = { "_KTRAP_FRAME", "Rbp" },
    [KTRAP_FRAME_RSP] = { "_KTRAP_FRAME", "Rsp" },
    [TEB_TLS_SLOTS] = { "_TEB", "TlsSlots" },
    [TEB_LASTERRORVALUE] = { "_TEB", "LastErrorValue" },
    [ETHREAD_CID] = {"_ETHREAD", "Cid" },
    [ETHREAD_TCB] = { "_ETHREAD", "Tcb" },
    [ETHREAD_WIN32STARTADDRESS] = { "_ETHREAD", "Win32StartAddress" },
    [ETHREAD_THREADLISTENTRY] = { "_ETHREAD", "ThreadListEntry" },
    [CLIENT_ID_UNIQUETHREAD] = {"_CLIENT_ID", "UniqueThread" },
    [OBJECT_HEADER_TYPEINDEX] = { "_OBJECT_HEADER", "TypeIndex" },
    [OBJECT_HEADER_BODY] = { "_OBJECT_HEADER", "Body" },
    [POOL_HEADER_BLOCKSIZE] = {"_POOL_HEADER", "BlockSize" },
    [POOL_HEADER_POOLTYPE] = {"_POOL_HEADER", "PoolType" },
    [POOL_HEADER_POOLTAG] = {"_POOL_HEADER", "PoolTag" },
    [DISPATCHER_TYPE] = { "_DISPATCHER_HEADER",  "Type" },

    [CM_KEY_CONTROL_BLOCK] = { "_CM_KEY_BODY",           "KeyControlBlock" },
    [CM_KEY_NAMEBLOCK]     = { "_CM_KEY_CONTROL_BLOCK",  "NameBlock"       },
    [CM_KEY_NAMEBUFFER]    = { "_CM_NAME_CONTROL_BLOCK", "Name"            },
    [CM_KEY_NAMELENGTH]    = { "_CM_NAME_CONTROL_BLOCK", "NameLength"      },
    [CM_KEY_PARENTKCB]     = { "_CM_KEY_CONTROL_BLOCK",  "ParentKcb"       },
    [CM_KEY_PROCESSID]     = { "_CM_KEY_BODY",           "ProcessID"       },

    [PROCCREATIONINFO_IMAGEFILENAME] = { "_SE_AUDIT_PROCESS_CREATION_INFO", "ImageFileName" },
    [OBJECTNAMEINFORMATION_NAME] = { "_OBJECT_NAME_INFORMATION", "Name" },

    [FILEOBJECT_NAME] = { "_FILE_OBJECT", "FileName" },
    [RTL_USER_PROCESS_PARAMETERS_COMMANDLINE] = { "_RTL_USER_PROCESS_PARAMETERS", "CommandLine" },

    [EWOW64PROCESS_PEB] = { "_EWOW64PROCESS", "Peb" },

    [LIST_ENTRY_FLINK] = { "_LIST_ENTRY", "Flink" },

    [OBJECT_ATTRIBUTES_OBJECTNAME] = {"_OBJECT_ATTRIBUTES", "ObjectName"},
    [OBJECT_ATTRIBUTES_ROOTDIRECTORY] = {"_OBJECT_ATTRIBUTES", "RootDirectory"},
};

static const char* win_bitfields_names[__WIN_OFFSETS_MAX][2] =
{
    [MMVAD_FLAGS_PROTECTION] = { "_MMVAD_FLAGS", "Protection" },
    [MMVAD_FLAGS_MEMCOMMIT] = { "_MMVAD_FLAGS", "MemCommit" },
    [MMVAD_FLAGS1_MEMCOMMIT] = { "_MMVAD_FLAGS1", "MemCommit" },
    [MMVAD_FLAGS_VADTYPE] = { "_MMVAD_FLAGS", "VadType" },
    [MMVAD_FLAGS_COMMITCHARGE] = { "_MMVAD_FLAGS", "CommitCharge" },
    [MMVAD_FLAGS1_COMMITCHARGE] = { "_MMVAD_FLAGS1", "CommitCharge" },
    [MMVAD_FLAGS_PRIVATEMEMORY] = { "_MMVAD_FLAGS",  "PrivateMemory" },
};

#endif
