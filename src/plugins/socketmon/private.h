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

#ifndef SOCKETMON_PRIVATE_H
#define SOCKETMON_PRIVATE_H

/*
 * Socketmon installs some traps on CR3 switches to ensure
 * that traps get registered properly. This sets an upper bound.
 * before bailing.
 */
#define CR3_COUNT_BEFORE_BAIL 1000

/* TcpE */
enum tcp_state
{
    CLOSED = 0,
    LISTENING = 1,
    SYN_SENT = 2,
    SYN_RCVD = 3,
    ESTABLISHED = 4,
    FIN_WAIT1 = 5,
    FIN_WAIT2 = 6,
    CLOSE_WAIT = 7,
    CLOSING = 8,
    LIST_ACK = 9,
    TIME_WAIT = 12,
    DELETE_TCB = 13,
    __TCP_STATE_MAX
};

static const char* tcp_state_str[] =
{
    [CLOSED] = "closed",
    [LISTENING] = "listening",
    [SYN_SENT] = "syn_sent",
    [SYN_RCVD] = "syn_rcvd",
    [ESTABLISHED] = "established",
    [FIN_WAIT1] = "fin_wait1",
    [FIN_WAIT2] = "fin_wait2",
    [CLOSE_WAIT] = "close_wait",
    [CLOSING] = "closing",
    [LIST_ACK] = "list_ack",
    [TIME_WAIT] = "time_wait",
    [DELETE_TCB] = "delete_tcb",
    [10 ... 11] = "__undefined__"
};

struct tcp_endpoint_x86
{
    uint64_t createtime;
    uint32_t _pad1;
    uint32_t inetaf;
    uint32_t addrinfo;
    uint32_t listentry;
    uint8_t _pad2[0x1c];
    uint32_t state;
    uint16_t localport;
    uint16_t remoteport;
    uint8_t _pad3[0x138];
    uint32_t owner;
} __attribute__ ((packed));

struct tcp_endpoint_x64
{
    uint8_t _pad1[0x18];
    uint64_t inetaf;
    uint64_t addrinfo;
    uint64_t listentry;
    uint8_t _pad2[0x38];
    uint32_t state;
    uint16_t localport;
    uint16_t remoteport;
    uint8_t _pad3[0x1c8];
    uint64_t owner;
} __attribute__ ((packed));

// Tested for Windows 8.1
struct tcp_endpoint_win81_x64
{
    addr_t _pad1[2];      // +0x0
    addr_t inetaf;        // +0x10 -> inetaf_win10_x64
    addr_t addrinfo;      // +0x18
    uint8_t _pad2[0x4c];  // +0x20
    uint32_t state;       // +0x6c
    uint16_t localport;   // +0x70
    uint16_t remoteport;  // +0x72
    uint8_t _pad3[0x1e4]; // +0x74
    addr_t owner;         // +0x258
} __attribute__((packed));

// That worked with Windows 10 before 1803
struct tcp_endpoint_win10_x64
{
    addr_t _pad1[2];
    addr_t inetaf; // inetaf_win10_x64
    addr_t addrinfo;
    uint8_t _pad2[0x4c];
    uint32_t state;
    uint16_t localport;
    uint16_t remoteport;
    uint8_t _pad3[0x1E4];
    addr_t owner;
    addr_t _pad4;
    addr_t createtime;
} __attribute__((packed));

// Tested for Windows 10 build 1803
struct tcp_endpoint_win10_x64_1803
{
    addr_t _pad1[2];      // +0x0
    addr_t inetaf;        // +0x10 -> inetaf_win10_x64
    addr_t addrinfo;      // +0x18
    uint8_t _pad2[0x4c];  // +0x20
    uint32_t state;       // +0x6c
    uint16_t localport;   // +0x70
    uint16_t remoteport;  // +0x72
    uint8_t _pad3[0x204]; // +0x74
    addr_t owner;         // +0x278
} __attribute__((packed));

struct addr_info_x86
{
    uint32_t local; // local_address
    uint32_t _pad;
    uint32_t remote; // ipv4/ipv6
} __attribute__ ((packed));

struct addr_info_x64
{
    uint64_t local;
    uint64_t _pad;
    uint64_t remote;
} __attribute__ ((packed));

struct local_address_x86
{
    uint8_t _pad[0xc];
    uint32_t pdata;
} __attribute__ ((packed));

struct local_address_x64
{
    uint8_t _pad[0x10];
    uint64_t pdata;
} __attribute__ ((packed));

struct local_address_win10_udp_x64
{
    addr_t pdata;
} __attribute__((packed));

#define AF_INET     0x2
#define AF_INET6    0x17

struct inetaf_x86
{
    uint8_t _pad[0xc];
    uint8_t addressfamily;
} __attribute__ ((packed));

struct inetaf_x64
{
    uint8_t _pad[0x14];
    uint8_t addressfamily;
} __attribute__ ((packed));

struct inetaf_win81_x64
{
    uint8_t _pad[0x18];
    uint8_t addressfamily;
} __attribute__ ((packed));

using inetaf_win10_x64 = inetaf_win81_x64;

/* UdpA */
struct udp_endpoint_x86
{
    uint8_t _pad1[0x14];
    uint32_t inetaf;
    uint32_t owner;
    uint8_t _pad2[0x14];
    uint64_t createtime;
    uint32_t localaddr;
    uint8_t _pad3[0xc];
    uint16_t port;
} __attribute__ ((packed));

struct udp_endpoint_x64
{
    uint8_t _pad1[0x20];
    uint64_t inetaf;
    uint64_t owner;
    uint8_t _pad2[0x28];
    uint64_t createtime;
    uint64_t localaddr;
    uint8_t _pad3[0x18];
    uint16_t port;
} __attribute__ ((packed));

struct udp_endpoint_win10_x64
{
    addr_t _pad1[4];
    addr_t inetaf; // inetaf_win10_x64
    addr_t owner;
    addr_t _pad2[5];
    addr_t createtime;
    uint8_t _pad3[0x18];
    uint16_t port;
    addr_t localaddr; // local_address_win10_udp_x64
} __attribute__ ((packed));

struct sockaddr_in
{
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
} __attribute__ ((packed));

struct sockaddr_in6
{
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t  sin6_addr[16];
    uint32_t sin6_scope_id;
} __attribute__ ((packed));

// This is yet another type of Windows string representation
// specific for undocumented DnsQueryExW(...) function.
struct dns_query_ex_w_string_x64_t
{
    uint32_t length = 0;
    uint32_t unknown = 0; // maybe type of bytes in string, was equal to 1 in my case of wchars?
    uint64_t pBuffer = 0; // pointer to a null-terminated string of wchars
    //uint64_t unknown2 = 0; // maybe type of bytes in string, was equal to 1 in my case of wchars, commented out, since not needed yet
} __attribute__ ((packed));

struct dns_query_ex_w_string_x86_t
{
    uint32_t length = 0;
    uint32_t unknown = 0;
    uint32_t pBuffer = 0;
} __attribute__ ((packed));

#endif
