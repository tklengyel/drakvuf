/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014-2015 Tamas K Lengyel.  *
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

#ifndef EXMON_PRIVATE_H
#define EXMON_PRIVATE_H

#define CSV_FORMAT32 "exmon,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x\n" 
#define CSV_FORMAT64 "exmon,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x\n"

#define DEFAULT_FORMAT32 "[EXMON] RSP: %x EXCEPTION_RECORD: %x EXCEPTION_CODE: %x EIP: %x EAX: %x EBX: %x ECX: %x EDX: %x EDI: %x ESI: %x EBP: %x ESP: %x \n"
#define DEFAULT_FORMAT64 "[EXMON] EXCEPTION_RECORD: %x EXCEPTION_CODE: %x RIP: %x RAX: %x RBX: %x RSP: %x RBP: %x RDX: %x R8: %x R9: %x R10: %x R11:%x \n"

typedef struct _KTRAP_FRAME
{
     uint32_t DbgEbp;
     uint32_t DbgEip;
     uint32_t DbgArgMark;
     uint32_t DbgArgPointer;
     uint16_t TempSegCs;
     unsigned char Logging;
     unsigned char Reserved;
     uint32_t TempEsp;
     uint32_t Dr0;
     uint32_t Dr1;
     uint32_t Dr2;
     uint32_t Dr3;
     uint32_t Dr6;
     uint32_t Dr7;
     uint32_t SegGs;
     uint32_t SegEs;
     uint32_t SegDs;
     uint32_t Edx;
     uint32_t Ecx;
     uint32_t Eax;
     uint32_t PreviousPreviousMode;
     uint32_t ExceptionList;
     uint32_t SegFs;
     uint32_t Edi;
     uint32_t Esi;
     uint32_t Ebx;
     uint32_t Ebp;
     uint32_t ErrCode;
     uint32_t Eip;
     uint32_t SegCs;
     uint32_t EFlags;
     uint32_t HardwareEsp;
     uint32_t HardwareSegSs;
     uint32_t V86Es;
     uint32_t V86Ds;
     uint32_t V86Fs;
     uint32_t V86Gs;
} KTRAP_FRAME, *PKTRAP_FRAME;

// Based on http://msdn.moonsols.com/win7rtm_x64/KTRAP_FRAME.html
typedef struct _M128A  // 2 elements, 0x10 bytes (sizeof)
{
     uint64_t       Low;
     int64_t        High;
}M128A, *PM128A;

typedef struct _KTRAP_FRAME64                    // 64 elements, 0x190 bytes (sizeof)
{
     uint64_t       P1Home;
     uint64_t       P2Home;
     uint64_t       P3Home;
     uint64_t       P4Home;
     uint64_t       P5;
     char         PreviousMode;
     uint8_t        PreviousIrql;
     uint8_t        FaultIndicator;
     uint8_t        ExceptionActive;
     uint32_t      MxCsr;
     uint64_t       Rax;
     uint64_t       Rcx;
     uint64_t       Rdx;
     uint64_t       R8;
     uint64_t       R9;
     uint64_t       R10;
     uint64_t       R11;
     union                                      // 2 elements, 0x8 bytes (sizeof)
     {
         uint64_t       GsBase;
         uint64_t       GsSwap;
     };
     struct _M128A Xmm0;                        // 2 elements, 0x10 bytes (sizeof)
     struct _M128A Xmm1;                        // 2 elements, 0x10 bytes (sizeof)
     struct _M128A Xmm2;                        // 2 elements, 0x10 bytes (sizeof)
     struct _M128A Xmm3;                        // 2 elements, 0x10 bytes (sizeof)
     struct _M128A Xmm4;                        // 2 elements, 0x10 bytes (sizeof)
     struct _M128A Xmm5;                        // 2 elements, 0x10 bytes (sizeof)
     union                                      // 3 elements, 0x8 bytes (sizeof)
     {
         uint64_t       FaultAddress;
         uint64_t       ContextRecord;
         uint64_t       TimeStampCKCL;
     };
     uint64_t       Dr0;
     uint64_t       Dr1;
     uint64_t       Dr2;
     uint64_t       Dr3;
     uint64_t       Dr6;
     uint64_t       Dr7;
     union                                      // 2 elements, 0x28 bytes (sizeof)
     {
         struct                                 // 5 elements, 0x28 bytes (sizeof)
         {
             uint64_t       DebugControl;
             uint64_t       LastBranchToRip;
             uint64_t       LastBranchFromRip;
             uint64_t       LastExceptionToRip;
             uint64_t       LastExceptionFromRip;
         };
         struct                                 // 2 elements, 0x28 bytes (sizeof)
         {
             uint64_t       LastBranchControl;
             uint32_t      LastBranchMSR;
             uint8_t        _PADDING0_[0x1C];
         };
     };
     uint16_t       SegDs;
     uint16_t       SegEs;
     uint16_t       SegFs;
     uint16_t       SegGs;
     uint64_t       TrapFrame;
     uint64_t       Rbx;
     uint64_t       Rdi;
     uint64_t       Rsi;
     uint64_t       Rbp;
     union                                      // 3 elements, 0x8 bytes (sizeof)
     {
         uint64_t       ErrorCode;
         uint64_t       ExceptionFrame;
         uint64_t       TimeStampKlog;
     };
     uint64_t       Rip;
     uint16_t       SegCs;
     uint8_t        Fill0;
     uint8_t        Logging;
     uint16_t       Fill1[2];
     uint32_t      EFlags;
     uint32_t      Fill2;
     uint64_t       Rsp;
     uint16_t       SegSs;
     uint16_t       Fill3;
     int32_t       CodePatchCycle;
}KTRAP_FRAME64, *PKTRAP_FRAME64;

#endif
