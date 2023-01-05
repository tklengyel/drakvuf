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

#ifndef UNIXSOCKETMON_PRIVATE_H
#define UNIXSOCKETMON_PRIVATE_H

typedef enum socket_family
{
    AF_LOCAL                = 1,	/* POSIX name for AF_UNIX	*/
    AF_INET                 = 2,	/* Internet IP Protocol 	*/
    AF_AX25                 = 3,	/* Amateur Radio AX.25 		*/
    AF_IPX                  = 4,	/* Novell IPX 			*/
    AF_APPLETALK            = 5,	/* AppleTalk DDP 		*/
    AF_NETROM               = 6,	/* Amateur Radio NET/ROM 	*/
    AF_BRIDGE               = 7,	/* Multiprotocol bridge 	*/
    AF_ATMPVC               = 8,	/* ATM PVCs			*/
    AF_X25                  = 9,    /* Reserved for X.25 project 	*/
    AF_INET6                = 10,	/* IP version 6			*/
    AF_ROSE                 = 11,	/* Amateur Radio X.25 PLP	*/
    AF_DECnet               = 12,	/* Reserved for DECnet project	*/
    AF_NETBEUI              = 13,	/* Reserved for 802.2LLC project*/
    AF_SECURITY             = 14,	/* Security callback pseudo AF */
    AF_KEY                  = 15,   /* PF_KEY key management API */
    AF_NETLINK              = 16,
    AF_PACKET               = 17,	/* Packet family		*/
    AF_ASH                  = 18,	/* Ash				*/
    AF_ECONET               = 19,	/* Acorn Econet			*/
    AF_ATMSVC               = 20,	/* ATM SVCs			*/
    AF_RDS                  = 21,	/* RDS sockets 			*/
    AF_SNA                  = 22,	/* Linux SNA Project (nutters!) */
    AF_IRDA                 = 23,	/* IRDA sockets			*/
    AF_PPPOX                = 24,	/* PPPoX sockets		*/
    AF_WANPIPE              = 25,	/* Wanpipe API Sockets */
    AF_LLC                  = 26,	/* Linux LLC			*/
    AF_IB                   = 27,	/* Native InfiniBand address	*/
    AF_MPLS                 = 28,	/* MPLS */
    AF_CAN                  = 29,	/* Controller Area Network      */
    AF_TIPC                 = 30,	/* TIPC sockets			*/
    AF_BLUETOOTH            = 31,	/* Bluetooth sockets 		*/
    AF_IUCV                 = 32,	/* IUCV sockets			*/
    AF_RXRPC                = 33,	/* RxRPC sockets 		*/
    AF_ISDN                 = 34,	/* mISDN sockets 		*/
    AF_PHONET               = 35,	/* Phonet sockets		*/
    AF_IEEE802154           = 36,	/* IEEE802154 sockets		*/
    AF_CAIF                 = 37,	/* CAIF sockets			*/
    AF_ALG                  = 38,	/* Algorithm sockets		*/
    AF_NFC                  = 39,	/* NFC sockets			*/
    AF_VSOCK                = 40,	/* vSockets			*/
    AF_KCM                  = 41,	/* Kernel Connection Multiplexor*/
    AF_QIPCRTR              = 42,	/* Qualcomm IPC Router */
    AF_SMC                  = 43,	/* smc sockets: reserve number for PF_SMC protocol family that reuses AF_INET address family */
    AF_XDP                  = 44,	/* XDP sockets */
    AF_MCTP                 = 45,	/* Management component transport protocol */
} socket_family_t;

static inline const char* socket_family_to_str(socket_family_t family)
{
    switch (family)
    {
        case AF_LOCAL:
            return "AF_LOCAL";
        case AF_INET:
            return "AF_INET";
        case AF_AX25:
            return "AF_AX25";
        case AF_IPX:
            return "AF_IPX";
        case AF_APPLETALK:
            return "AF_APPLETALK";
        case AF_NETROM:
            return "AF_NETROM";
        case AF_BRIDGE:
            return "AF_BRIDGE";
        case AF_ATMPVC:
            return "AF_ATMPVC";
        case AF_X25:
            return "AF_X25";
        case AF_INET6:
            return "AF_INET6";
        case AF_ROSE:
            return "AF_ROSE";
        case AF_DECnet:
            return "AF_DECnet";
        case AF_NETBEUI:
            return "AF_NETBEUI";
        case AF_SECURITY:
            return "AF_SECURITY";
        case AF_KEY:
            return "AF_KEY";
        case AF_NETLINK:
            return "AF_NETLINK";
        case AF_PACKET:
            return "AF_PACKET";
        case AF_ASH:
            return "AF_ASH";
        case AF_ECONET:
            return "AF_ECONET";
        case AF_ATMSVC:
            return "AF_ATMSVC";
        case AF_RDS:
            return "AF_RDS";
        case AF_SNA:
            return "AF_SNA";
        case AF_IRDA:
            return "AF_IRDA";
        case AF_PPPOX:
            return "AF_PPPOX";
        case AF_WANPIPE:
            return "AF_WANPIPE";
        case AF_LLC:
            return "AF_LLC";
        case AF_IB:
            return "AF_IB";
        case AF_MPLS:
            return "AF_MPLS";
        case AF_CAN:
            return "AF_CAN";
        case AF_TIPC:
            return "AF_TIPC";
        case AF_BLUETOOTH:
            return "AF_BLUETOOTH";
        case AF_IUCV:
            return "AF_IUCV";
        case AF_RXRPC:
            return "AF_RXRPC";
        case AF_ISDN:
            return "AF_ISDN";
        case AF_PHONET:
            return "AF_PHONET";
        case AF_IEEE802154:
            return "AF_IEEE802154";
        case AF_CAIF:
            return "AF_CAIF";
        case AF_ALG:
            return "AF_ALG";
        case AF_NFC:
            return "AF_NFC";
        case AF_VSOCK:
            return "AF_VSOCK";
        case AF_KCM:
            return "AF_KCM";
        case AF_QIPCRTR:
            return "AF_QIPCRTR";
        case AF_SMC:
            return "AF_SMC";
        case AF_XDP:
            return "AF_XDP";
        case AF_MCTP:
            return "AF_MCTP";
    }
    return NULL;
}

#endif