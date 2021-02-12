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

#ifndef WIN_OFFSETS_H
#define WIN_OFFSETS_H

/*
 * Easy-to-use structure offsets to be loaded from the Rekall profile.
 * Define actual mapping in win-offsets-map.h
 */
enum win_offsets
{
    KIINITIALPCR,

    EPROCESS_PID,
    EPROCESS_PDBASE,
    EPROCESS_PNAME,
    EPROCESS_PROCCREATIONINFO,
    EPROCESS_TASKS,
    EPROCESS_PEB,
    EPROCESS_OBJECTTABLE,
    EPROCESS_PCB,
    EPROCESS_INHERITEDPID,
    EPROCESS_WOW64PROCESS,
    EPROCESS_WOW64PROCESS_WIN10,

    EPROCESS_VADROOT,
    EPROCESS_LISTTHREADHEAD,

    RTL_AVL_TREE_ROOT,
    RTL_BALANCED_NODE_LEFT,
    RTL_BALANCED_NODE_RIGHT,
    RTL_BALANCED_NODE_PARENTVALUE,
    MMVAD_CORE,
    MMVAD_SHORT_STARTING_VPN,
    MMVAD_SHORT_STARTING_VPN_HIGH,
    MMVAD_SHORT_ENDING_VPN,
    MMVAD_SHORT_ENDING_VPN_HIGH,
    MMVAD_SHORT_FLAGS,
    MMVAD_SHORT_FLAGS1,


    VADROOT_BALANCED_ROOT,

    MMVAD_LEFT_CHILD,
    MMVAD_RIGHT_CHILD,
    MMVAD_STARTING_VPN,
    MMVAD_ENDING_VPN,
    MMVAD_FLAGS,
    MMVAD_SUBSECTION,
    SUBSECTION_CONTROL_AREA,
    CONTROL_AREA_FILEPOINTER,
    CONTROL_AREA_SEGMENT,
    SEGMENT_TOTALNUMBEROFPTES,
    SEGMENT_PROTOTYPEPTE,

    KPROCESS_HEADER,

    PEB_IMAGEBASADDRESS,
    PEB_LDR,
    PEB_PROCESSPARAMETERS,
    PEB_SESSIONID,
    PEB_CSDVERSION,

    PEB_LDR_DATA_INLOADORDERMODULELIST,

    LDR_DATA_TABLE_ENTRY_DLLBASE,
    LDR_DATA_TABLE_ENTRY_SIZEOFIMAGE,
    LDR_DATA_TABLE_ENTRY_BASEDLLNAME,
    LDR_DATA_TABLE_ENTRY_FULLDLLNAME,

    HANDLE_TABLE_TABLECODE,

    KPCR_PRCB,
    KPCR_PRCBDATA,
    KPRCB_CURRENTTHREAD,

    KTHREAD_APCSTATE,
    KTHREAD_APCSTATEINDEX,
    KTHREAD_PROCESS,
    KTHREAD_PREVIOUSMODE,
    KTHREAD_HEADER,
    KTHREAD_TEB,
    KTHREAD_STACKBASE,
    KTHREAD_TRAPFRAME,
    KAPC_STATE_PROCESS,
    KTRAP_FRAME_RBP,
    KTRAP_FRAME_RSP,

    TEB_TLS_SLOTS,
    TEB_LASTERRORVALUE,

    ETHREAD_CID,
    ETHREAD_TCB,
    ETHREAD_WIN32STARTADDRESS,
    ETHREAD_THREADLISTENTRY,
    CLIENT_ID_UNIQUETHREAD,

    OBJECT_HEADER_TYPEINDEX,
    OBJECT_HEADER_BODY,

    POOL_HEADER_BLOCKSIZE,
    POOL_HEADER_POOLTYPE,
    POOL_HEADER_POOLTAG,

    DISPATCHER_TYPE,

    CM_KEY_CONTROL_BLOCK,
    CM_KEY_NAMEBLOCK,
    CM_KEY_NAMEBUFFER,
    CM_KEY_NAMELENGTH,
    CM_KEY_PARENTKCB,
    CM_KEY_PROCESSID,

    PROCCREATIONINFO_IMAGEFILENAME,

    OBJECTNAMEINFORMATION_NAME,

    FILEOBJECT_NAME,

    RTL_USER_PROCESS_PARAMETERS_COMMANDLINE,

    EWOW64PROCESS_PEB,

    LIST_ENTRY_FLINK,

    __WIN_OFFSETS_MAX
};

enum win_bitfields
{
    MMVAD_FLAGS_PROTECTION,
    MMVAD_FLAGS_MEMCOMMIT,
    MMVAD_FLAGS1_MEMCOMMIT,
    MMVAD_FLAGS_VADTYPE,
    MMVAD_FLAGS1_VADTYPE,
    MMVAD_FLAGS_COMMITCHARGE,
    MMVAD_FLAGS1_COMMITCHARGE,
    __WIN_BITFIELDS_MAX
};

enum win_sizes
{
    HANDLE_TABLE_ENTRY,

    __WIN_SIZES_MAX
};

#endif
