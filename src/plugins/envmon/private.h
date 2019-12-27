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

#ifndef ENVMON_PRIVATE_H
#define ENVMON_PRIVATE_H

// from Windows secext.h
enum extended_name_format
{
    NameUnknown          = 0,
    NameFullyQualifiedDN = 1,
    NameSamCompatible    = 2,
    NameDisplay          = 3,
    NameUniqueId         = 6,
    NameCanonical        = 7,
    NameUserPrincipal    = 8,
    NameCanonicalEx      = 9,
    NameServicePrincipal = 10,
    NameDnsDomain        = 12,
    NameGivenName        = 13,
    NameSurname          = 14
};

// from Windows sysinfoapi.h
enum computer_name_format
{
    ComputerNameNetBIOS,
    ComputerNameDnsHostname,
    ComputerNameDnsDomain,
    ComputerNameDnsFullyQualified,
    ComputerNamePhysicalNetBIOS,
    ComputerNamePhysicalDnsHostname,
    ComputerNamePhysicalDnsDomain,
    ComputerNamePhysicalDnsFullyQualified,
    ComputerNameMax
};

enum family_types_format
{
    AF_UNSPEC   = 0,
    AF_INET     = 2,
    AF_INET6    = 23
};

enum flags_types_format
{
    GAA_FLAG_SKIP_UNICAST                   = 0x0001,
    GAA_FLAG_SKIP_ANYCAST                   = 0x0002,
    GAA_FLAG_SKIP_MULTICAST                 = 0x0004,
    GAA_FLAG_SKIP_DNS_SERVER                = 0x0008,
    GAA_FLAG_INCLUDE_PREFIX                 = 0x0010,
    GAA_FLAG_SKIP_FRIENDLY_NAME             = 0x0020,
    GAA_FLAG_INCLUDE_WINS_INFO              = 0x0040,
    GAA_FLAG_INCLUDE_GATEWAYS               = 0x0080,
    GAA_FLAG_INCLUDE_ALL_INTERFACES         = 0x0100,
    GAA_FLAG_INCLUDE_ALL_COMPARTMENTS       = 0x0200,
    GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER    = 0x0400
};

// emum network_types_name
// {
//     WNNC_NET_MSNET       = 0x00010000,
//     WNNC_NET_SMB         = 0x00020000,
//     WNNC_NET_NETWARE     = 0x00030000,
//     WNNC_NET_VINES       = 0x00040000,
//     WNNC_NET_10NET       = 0x00050000,
//     WNNC_NET_LOCUS       = 0x00060000,
//     WNNC_NET_SUN_PC_NFS  = 0x00070000,
//     WNNC_NET_LANSTEP     = 0x00080000,
//     WNNC_NET_9TILES      = 0x00090000,
//     WNNC_NET_LANTASTIC   = 0x000A0000,
//     WNNC_NET_AS400       = 0x000B0000,
//     WNNC_NET_FTP_NFS     = 0x000C0000,
//     WNNC_NET_PATHWORKS   = 0x000D0000,
//     WNNC_NET_LIFENET     = 0x000E0000,
//     WNNC_NET_POWERLAN    = 0x000F0000,
//     WNNC_NET_BWNFS       = 0x00100000,
//     WNNC_NET_COGENT      = 0x00110000,
//     WNNC_NET_FARALLON    = 0x00120000,
//     WNNC_NET_APPLETALK   = 0x00130000,
//     WNNC_NET_INTERGRAPH  = 0x00140000,
//     WNNC_NET_SYMFONET    = 0x00150000,
//     WNNC_NET_CLEARCASE   = 0x00160000,
//     WNNC_NET_FRONTIER    = 0x00170000,
//     WNNC_NET_BMC         = 0x00180000,
//     WNNC_NET_DCE         = 0x00190000,
//     WNNC_NET_AVID        = 0x001A0000,
//     WNNC_NET_DOCUSPACE   = 0x001B0000,
//     WNNC_NET_MANGOSOFT   = 0x001C0000,
//     WNNC_NET_SERNET      = 0x001D0000,
//     WNNC_NET_RIVERFRONT1 = 0X001E0000,
//     WNNC_NET_RIVERFRONT2 = 0x001F0000,
//     WNNC_NET_DECORB      = 0x00200000,
//     WNNC_NET_PROTSTOR    = 0x00210000,
//     WNNC_NET_FJ_REDIR    = 0x00220000,
//     WNNC_NET_DISTINCT    = 0x00230000,
//     WNNC_NET_TWINS       = 0x00240000,
//     WNNC_NET_RDR2SAMPLE  = 0x00250000,
//     WNNC_NET_CSC         = 0x00260000,
//     WNNC_NET_3IN1        = 0x00270000,
//     WNNC_NET_EXTENDNET   = 0x00290000,
//     WNNC_NET_STAC        = 0x002A0000,
//     WNNC_NET_FOXBAT      = 0x002B0000,
//     WNNC_NET_YAHOO       = 0x002C0000,
//     WNNC_NET_EXIFS       = 0x002D0000,
//     WNNC_NET_DAV         = 0x002E0000,
//     WNNC_NET_KNOWARE     = 0x002F0000,
//     WNNC_NET_OBJECT_DIRE = 0x00300000,
//     WNNC_NET_MASFAX      = 0x00310000,
//     WNNC_NET_HOB_NFS     = 0x00320000,
//     WNNC_NET_SHIVA       = 0x00330000,
//     WNNC_NET_IBMAL       = 0x00340000,
//     WNNC_NET_LOCK        = 0x00350000,
//     WNNC_NET_TERMSRV     = 0x00360000,
//     WNNC_NET_SRT         = 0x00370000,
//     WNNC_NET_QUINCY      = 0x00380000,
//     WNNC_NET_OPENAFS     = 0x00390000,
//     WNNC_NET_AVID1       = 0X003A0000,
//     WNNC_NET_DFS         = 0x003B0000,
//     WNNC_NET_KWNP        = 0x003C0000,
//     WNNC_NET_ZENWORKS    = 0x003D0000,
//     WNNC_NET_DRIVEONWEB  = 0x003E0000,
//     WNNC_NET_VMWARE      = 0x003F0000,
//     WNNC_NET_RSFX        = 0x00400000,
//     WNNC_NET_MFILES      = 0x00410000,
//     WNNC_NET_MS_NFS      = 0x00420000,
//     WNNC_NET_GOOGLE      = 0x00430000,

//     WNNC_CRED_MANAGER    = 0xFFFF0000,
// };

enum define_dos_device_flag
{
    DDD_RAW_TARGET_PATH       = 0x1,
    DDD_REMOVE_DEFINITION     = 0x2,
    DDD_EXACT_MATCH_ON_REMOVE = 0x3,
    DDD_NO_BROADCAST_SYSTEM   = 0x4
};

#endif
