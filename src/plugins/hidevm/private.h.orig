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

#ifndef HIDEVM_PRIVATE_H
#define HIDEVM_PRIVATE_H

/*
* advapi32!WmiOpenBlock results in calling nt!NtDeviceIoControlFile with IoControlCode 0x0022413C and InputBuffer and OutputBuffer
* defined as pointers to the same struct WMI_KM_REQUEST_OPEN_BLOCK
*
* struct WMI_KM_REQUEST_OPEN_BLOCK
* {
*     OBJECT_ATTRIBUTES *GuidObjectAttributes;
*     __int64 Access;
*     HANDLE Handle;
* };
*
* GuidObjectAttributes.ObjectName equals to "WmiGuid\{A1BC18C0-A7C8-11d1-BF3C-00A0C9062910}" for MSAcpi_ThermalZoneTemperature object
* GuidObjectAttributes.Handle on return contains handle to WmiGuid entry
*
*/
#define IOCTL_WMI_OPEN_GUID_BLOCK 0x0022413C
#define WmiKmRequestOpenBlock_ObjectAttributes    0
#define WmiKmRequestOpenBlock_Handle           0x10


/*
* After obtaining WmiGuid Handle via advapi!WmiOpenBlock advapi32!WmiQueryGuidInformation is called, which results in calling
* NtDeviceIoControlFile with IoControl code equals to 0x224138 and InputBuffer and OutputBuffer set *WMI_KM_REQUEST_GUID_INFO
*
* struct WMI_KM_REQUEST_GUID_INFO
* {
*     HANDLE Handle;
*     __int64 Status;
* };
*
* NtDeviceIoControlFile should return STATUS_SUCCESS in RAX and IO_STATUS_BLOCK.Information should contain 0x10 and
* WMI_KM_REQUEST_GUID_INFO.Status set to 0
*/
#define IOCTL_WMI_QUERY_GUID_INFORMATION 0x00224138
#define WmiKmRequestQueryGuidInfo_Status 0x00000008
#define WmiKmRequestQueryGuidInfo_Handle 0x00000000

/*
* advapi32!WmiQueryAllDataW called twice, 1st call
* return:
* WMI_KM_QUERY_DATA.Length -> 0x38
* WMI_KM_QUERY_DATA.Guid -> ThermalZoneGuid
* WMI_KM_QUERY_DATA.Flags -> 0x20
* WMI_KM_QUERY_DATA.DataLen -> 0xD8
* WMI_KM_QUERY_DATA.field_34 -> 1
* IoStatusBlock.Information -> 0x38
* NTSTATUS_SUCCESS
*
* struct WMI_KM_QUERY_DATA
* {
*     int Length;
*     int field_4;
*     int field_8;
*     int field_C;
*     HANDLE Handle;
*     GUID Guid;
*     int field_28;
*     int Flags;
*     int DataLen;
*     int field_34;
* };
*
* 2nd call returns
* IoStatusBlock.Information -> 0xD8
* OutputBuffer contains data
*/

const uint8_t binThermalZoneGuid[] = {0xC0, 0x18, 0xBC, 0xA1, 0xC8, 0xA7, 0xD1, 0x11, 0xBF, 0x3C, 0x00, 0xA0, 0xC9, 0x06, 0x29, 0x10};
const uint8_t WMI_data[] = {0xD4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x45, 0xCA, 0x73, 0x47, 0xBB, 0xC9, 0xD7, 0x01, 0xC0, 0x18, 0xBC, 0xA1, 0xC8, 0xA7, 0xD1, 0x11,
        0xBF, 0x3C, 0x00, 0xA0, 0xC9, 0x06, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x01, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
        0x4C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x0C, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x94, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x30, 0x00, 0x41, 0x00, 0x43, 0x00, 0x50, 0x00,
        0x49, 0x00, 0x5C, 0x00, 0x54, 0x00, 0x68, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6D, 0x00, 0x61, 0x00,
        0x6C, 0x00, 0x5A, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x65, 0x00, 0x5C, 0x00, 0x54, 0x00, 0x48, 0x00,
        0x52, 0x00, 0x4D, 0x00, 0x5F, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

#define IOCTL_WMI_QUERY_ALL_DATA  0x00224000
#define WmiKmQueryData_Length     0x00000000
#define WmiKmQueryData_Handle     0x00000010
#define WmiKmQueryData_Guid       0x00000018
#define WmiKmQueryData_Flags      0x0000002C
#define WmiKmQueryData_DataLen    0x00000030

#define STATUS_SUCCESS            0x00000000
#define STATUS_WMI_GUID_NOT_FOUND 0xC0000295

// Stages
#define STAGE_WMI_OPEN_BLOCK             1
#define STAGE_WMI_QUERY_GUID_INFORMATION 2
#define STAGE_WMI_QUERY_ALL_DATA         3

#endif