/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
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

/*
 * 1) ExAllocatePoolWithTag: is it TcpL or UdpA?
 *   - YES: breakpoint RSP
 * 2) RSP: RAX -> _TCP_LISTENER or _UDP_ENDPOINT
 *    - MEMTRAP W location
 * 3) MEMTRAP: Read info
 *    - YES: read string and remove trap
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dirent.h>
#include <err.h>

#include <byteswap.h>

#include <string>
#include <iostream>
#include <cassert>

#include "plugins/plugins.h"
#include "plugins/output_format.h"

#include "private.h"
#include "socketmon.h"

#define IPV4_ADDR_OFFSET 4
#define IPV6_ADDR_OFFSET 8

static constexpr uint16_t win_7_sp1_ver   = 7601;
static constexpr uint16_t win_10_1803_ver = 17134;

static char* ipv4_to_str(uint8_t ipv4[4])
{
    return g_strdup_printf("%u.%u.%u.%u", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
}

static char* ipv6_to_str(uint8_t ipv6[16])
{
    return g_strdup_printf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
            ipv6[0], ipv6[1], ipv6[2], ipv6[3],
            ipv6[4], ipv6[5], ipv6[6], ipv6[7],
            ipv6[8], ipv6[9], ipv6[10], ipv6[11],
            ipv6[12], ipv6[13], ipv6[14], ipv6[15]);
}

static char* read_ipv4_string(vmi_instance_t vmi, access_context_t& ctx, addr_t addr)
{
    uint8_t ip[4]  = {0};

    if ( addr )
    {
        ctx.addr = addr;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(ip), ip, NULL) )
            return nullptr;
    }

    return ipv4_to_str(ip);
}

static char* read_ipv6_string(vmi_instance_t vmi, access_context_t& ctx, addr_t addr)
{
    uint8_t ip[16]  = {0};

    if ( addr )
    {
        ctx.addr = addr;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(ip), ip, NULL) )
            return nullptr;
    }

    return ipv6_to_str(ip);
}

static char* read_ip_string(vmi_instance_t vmi, access_context_t& ctx, addr_t addr, int addressfamily)
{
    if (addressfamily == AF_INET)
        return read_ipv4_string(vmi, ctx, addr);

    if (addressfamily == AF_INET6)
        return read_ipv6_string(vmi, ctx, addr);

    return nullptr;
}

static char const* udp_addressfamily_string(int family)
{
    return (family == AF_INET) ? "UDPv4" : "UDPv6";
}

static char const* tcp_addressfamily_string(int family)
{
    return (family == AF_INET) ? "TCPv4" : "TCPv6";
}

static void print_udp_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, socketmon* s, proc_data_t const& owner_proc_data, int addressfamily, char const* lip, int port)
{
    fmt::print(s->format, "socketmon", drakvuf, info,
        keyval("Owner", fmt::Qstr(owner_proc_data.name)),
        keyval("OwnerId", fmt::Nval(owner_proc_data.userid)),
        keyval("OwnerPID", fmt::Nval(owner_proc_data.pid)),
        keyval("OwnerPPID", fmt::Nval(owner_proc_data.ppid)),
        keyval("Protocol", fmt::Rstr(udp_addressfamily_string(addressfamily))),
        keyval("LocalIp", fmt::Rstr(lip ?: "")),
        keyval("LocalPort", fmt::Nval(port))
    );
}

static void print_tcpe(drakvuf_t drakvuf, drakvuf_trap_info_t* info, socketmon* s, proc_data_t const& owner_proc_data,
    int addressfamily, char const* lip, int localport, char const* rip, int remoteport)
{
    fmt::print(s->format, "socketmon", drakvuf, info,
        keyval("Owner", fmt::Qstr(owner_proc_data.name)),
        keyval("OwnerId", fmt::Nval(owner_proc_data.userid)),
        keyval("OwnerPID", fmt::Nval(owner_proc_data.pid)),
        keyval("OwnerPPID", fmt::Nval(owner_proc_data.ppid)),
        keyval("Protocol", fmt::Rstr(tcp_addressfamily_string(addressfamily))),
        keyval("LocalIp", fmt::Rstr(lip ?: "")),
        keyval("LocalPort", fmt::Nval(localport)),
        keyval("RemoteIp", fmt::Rstr(rip ?: "")),
        keyval("RemotePort", fmt::Nval(remoteport))
    );
}

template<typename tcp_endpoint_struct, typename inetaf_struct, typename addr_info_struct>
static event_response_t tcpe_old_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* s = (socketmon*)info->trap->data;

    char* rip = nullptr;

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb                 = info->regs->cr3;

    proc_data_t owner_proc_data = {};
    tcp_endpoint_struct tcpe    = {};
    inetaf_struct inetaf        = {};
    addr_info_struct addrinfo   = {};

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ctx.addr = info->regs->rcx;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(tcpe), &tcpe, NULL) )
        goto done;

    if ( tcpe.state >= __TCP_STATE_MAX )
    {
        PRINT_DEBUG("[SOCKETMON] tcpe.state >= __TCP_STATE_MAX\n");
        goto done;
    }

    // Convert ports to little endian
    tcpe.localport  = __bswap_16(tcpe.localport);
    tcpe.remoteport = __bswap_16(tcpe.remoteport);

    ctx.addr = tcpe.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(inetaf), &inetaf, NULL) )
        goto done;

    ctx.addr = tcpe.addrinfo;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(addrinfo), &addrinfo, NULL) )
        goto done;

    rip = read_ip_string(vmi, ctx, addrinfo.remote, inetaf.addressfamily);
    if (!rip) goto done;

    if (!drakvuf_get_process_data(drakvuf, tcpe.owner, &owner_proc_data))
        goto done;

    if (inetaf.addressfamily == AF_INET)
        print_tcpe(drakvuf, info, s, owner_proc_data, inetaf.addressfamily, "127.0.0.1", tcpe.localport, rip, tcpe.remoteport);
    else
        print_tcpe(drakvuf, info, s, owner_proc_data, inetaf.addressfamily, "::1", tcpe.localport, rip, tcpe.remoteport);

done:
    g_free(const_cast<char*>(owner_proc_data.name));
    g_free(rip);
    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t tcpe_x86_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return tcpe_old_cb<tcp_endpoint_x86, inetaf_x86, addr_info_x86>(drakvuf, info);
}

static event_response_t tcpe_win81_x64_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return tcpe_old_cb<tcp_endpoint_win81_x64, inetaf_win81_x64, addr_info_x64>(drakvuf, info);
}

static event_response_t tcpe_win10_x64_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return tcpe_old_cb<tcp_endpoint_win10_x64, inetaf_win10_x64, addr_info_x64>(drakvuf, info);
}

static uint16_t tcp_get_family(vmi_instance_t vmi, addr_t rcx, addr_t build)
{
    addr_t ptr = 0;
    uint16_t family = 0;
    const uint16_t* offsets = nullptr;

    switch (build)
    {
        case win_7_sp1_ver:
            offsets = win7_sp1_tcp_offsets;
            break;
        case win_10_1803_ver:
            offsets = win10_1803_tcp_offsets;
            break;
        default:
            return 0;
    };

    if (VMI_SUCCESS != vmi_read_addr_va(vmi, rcx + offsets[IP_FAMILY_OFF0], 0, &ptr))
        return 0;

    if (VMI_SUCCESS != vmi_read_16_va(vmi, ptr + offsets[IP_FAMILY_OFF1], 0, &family))
        return 0;
    return family;
}

static std::pair<uint16_t, uint16_t> tcp_get_port(vmi_instance_t vmi, addr_t rcx, addr_t build)
{
    uint16_t rport = 0, lport = 0;
    const uint16_t* offsets = nullptr;

    switch (build)
    {
        case win_7_sp1_ver:
            offsets = win7_sp1_tcp_offsets;
            break;
        case win_10_1803_ver:
            offsets = win10_1803_tcp_offsets;
            break;
        default:
            return std::make_pair(0, 0);
    };

    vmi_read_16_va(vmi, rcx + offsets[LOCAL_PORT],  0, &lport);
    vmi_read_16_va(vmi, rcx + offsets[REMOTE_PORT], 0, &rport);
    lport = __bswap_16(lport);
    rport = __bswap_16(rport);
    return std::make_pair(lport, rport);
}

static char* tcp_get_addr(vmi_instance_t vmi, addr_t rcx, addr_t build, uint16_t family)
{
    addr_t ptr = 0;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid                 = 4
    );

    const uint16_t* offsets = nullptr;

    switch (build)
    {
        case win_7_sp1_ver:
            offsets = win7_sp1_tcp_offsets;
            break;
        case win_10_1803_ver:
            offsets = win10_1803_tcp_offsets;
            break;
        default:
            return nullptr;
    };


    if (VMI_SUCCESS != vmi_read_addr_va(vmi, rcx + offsets[REMOTE_ADDR_OFF0], 0, &ptr))
        return nullptr;
    return read_ip_string(vmi, ctx, ptr + offsets[REMOTE_ADDR_OFF1], family);
}

static event_response_t tcp_tcb_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* s = (socketmon*)info->trap->data;
    vmi_lock_guard vmi(drakvuf);

    auto arg            = drakvuf_get_function_argument(drakvuf, info, 1);
    auto family         = tcp_get_family(vmi, arg, s->build.buildnumber);
    auto [lport, rport] = tcp_get_port  (vmi, arg, s->build.buildnumber);
    auto remote         = tcp_get_addr  (vmi, arg, s->build.buildnumber, family);
    auto local          = family == AF_INET ? "127.0.0.1" : "::1";

    print_tcpe(drakvuf, info, s, info->attached_proc_data, family, local, lport, remote, rport);

    g_free(remote);
    return VMI_EVENT_RESPONSE_NONE;
}

static proc_data_t* udp_get_process_data(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t udp_info)
{
    proc_data_t* data = new proc_data_t();
    addr_t process_ptr;
    // 0x28 offset - EPROCESS* of a calling process
    // Tested on Win 10 x64 21H1 and Win 7 SP1 x64
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, udp_info + 0x28, 4, &process_ptr))
    {
        PRINT_DEBUG("[SOCKETMON] Failed to read process ptr\n");
        delete data;
        return nullptr;
    }

    if (!drakvuf_get_process_data(drakvuf, process_ptr, data))
    {
        PRINT_DEBUG("[SOCKETMON] Failed to get process data\n");
        delete data;
        return nullptr;
    }
    return data;
}

static event_response_t udp_send_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* s = (socketmon*)info->trap->data;
    // Undocumented
    addr_t udp_info = drakvuf_get_function_argument(drakvuf, info, 1);
    // Undocumented
    addr_t message = drakvuf_get_function_argument(drakvuf, info, 2);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = message + 0x20 // struct sockaddr_in*, tested on Win7 sp1 x64 and Win10 21H1 x64
    );

    sockaddr_in6 sockaddr = {};
    vmi_lock_guard vmi(drakvuf);
    addr_t sockaddr_ptr;
    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &sockaddr_ptr))
    {
        PRINT_DEBUG("[SOCKETMON] UdpSendMessages failed to read sockaddr ptr\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!sockaddr_ptr)
        return VMI_EVENT_RESPONSE_NONE;

    ctx.addr = sockaddr_ptr;
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(sockaddr_in6), &sockaddr, NULL))
    {
        PRINT_DEBUG("[SOCKETMON] UdpSendMessages failed to read sockaddr\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    sockaddr.sin6_port = __bswap_16(sockaddr.sin6_port);

    char* rip = nullptr;
    if (sockaddr.sin6_family == AF_INET)
    {
        // 0: kd> dt SOCKADDR_IN
        // ndis!sockaddr_in
        //    +0x000 sin_family       : Uint2B
        //    +0x002 sin_port         : Uint2B
        //    +0x004 sin_addr         : in_addr
        //    +0x008 sin_zero         : [8] Char
        rip = read_ip_string(vmi, ctx, sockaddr_ptr + IPV4_ADDR_OFFSET, sockaddr.sin6_family);
        if (!rip)
        {
            PRINT_DEBUG("[SOCKETMON] Failed to read remote ip string\n");
            return VMI_EVENT_RESPONSE_NONE;
        }
    }
    else if (sockaddr.sin6_family == AF_INET6)
    {
        // 0: kd> dt SOCKADDR_IN6
        // ndis!sockaddr_in6
        //    +0x000 sin6_family      : Uint2B
        //    +0x002 sin6_port        : Uint2B
        //    +0x004 sin6_flowinfo    : Uint4B
        //    +0x008 sin6_addr        : in6_addr
        //    +0x018 sin6_scope_id    : Uint4B
        //    +0x018 sin6_scope_struct : SCOPE_ID
        rip = read_ip_string(vmi, ctx, sockaddr_ptr + IPV6_ADDR_OFFSET, sockaddr.sin6_family);
        if (!rip)
        {
            PRINT_DEBUG("[SOCKETMON] Failed to read remote ip string\n");
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    proc_data_t* data = udp_get_process_data(drakvuf, vmi, udp_info);
    if (data)
    {
        print_udp_info(drakvuf, info, s, *data, sockaddr.sin6_family, rip, sockaddr.sin6_port);
        g_free(const_cast<char*>(data->name));
        delete data;
    }
    g_free(rip);
    return VMI_EVENT_RESPONSE_NONE;
}

/* ----------------------------------------------------- */

static void print_dns_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, socketmon* sm, const char* dns_name)
{
    fmt::print(sm->format, "socketmon", drakvuf, info,
        keyval("DnsName", fmt::Qstr(dns_name ?: ""))
    );
}

static event_response_t trap_DnsQuery_A_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* sm = (socketmon*)info->trap->data;

    addr_t domain_name_addr = drakvuf_get_function_argument(drakvuf, info, 1);

    char* dns_name = drakvuf_read_ascii_str(drakvuf, info, domain_name_addr);

    print_dns_info(drakvuf, info, sm, dns_name);
    g_free(dns_name);

    return 0;
}


static event_response_t trap_DnsQuery_W_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* sm = (socketmon*)info->trap->data;

    addr_t domain_name_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    unicode_string_t* domain_name_us = nullptr;

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = domain_name_addr;

    {
        vmi_lock_guard vmi_lg(drakvuf);
        domain_name_us = drakvuf_read_wchar_string(drakvuf, &ctx);
    }

    if (domain_name_us)
    {
        print_dns_info(drakvuf, info, sm, (char*)domain_name_us->contents);
    }
    else
    {
        PRINT_DEBUG("[SOCKETMON] Error, getting unicode domain name string in %s()", __FUNCTION__);
    }
    vmi_free_unicode_str(domain_name_us);

    return 0;
}

// Works on Windows 7
template <typename dns_query_ex_w_string_t>
static event_response_t trap_DnsQueryExW_impl(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    unicode_string_t* domain_name_us = nullptr;
    socketmon* sm = (socketmon*)info->trap->data;

    addr_t domain_name_addr = drakvuf_get_function_argument(drakvuf, info, 1);

    {
        dns_query_ex_w_string_t function_specific_string;
        uint32_t struct_size = sizeof(function_specific_string);

        ACCESS_CONTEXT(ctx);
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = domain_name_addr;

        auto vmi = vmi_lock_guard(drakvuf);

        // Read strange function-specific string
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, struct_size, &function_specific_string, NULL) )
        {
            PRINT_DEBUG("[SOCKETMON] Error, getting unicode domain name string from 'strange string' in %s()", __FUNCTION__);
            return 0;
        }

        ctx.addr = function_specific_string.pBuffer;
        domain_name_us = drakvuf_read_wchar_string(drakvuf, &ctx);
    }

    if (domain_name_us)
    {
        print_dns_info(drakvuf, info, sm, (char*)domain_name_us->contents);
    }
    else
    {
        PRINT_DEBUG("[SOCKETMON] Error, getting unicode domain name string in %s()", __FUNCTION__);
    }

    vmi_free_unicode_str(domain_name_us);

    return 0;
}

static event_response_t trap_DnsQueryExW_x64_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return trap_DnsQueryExW_impl<dns_query_ex_w_string_x64_t>(drakvuf, info);
}

static event_response_t trap_DnsQueryExW_x86_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return trap_DnsQueryExW_impl<dns_query_ex_w_string_x86_t>(drakvuf, info);
}

// Works on Windows 7
static event_response_t trap_DnsQueryExA_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* sm = (socketmon*)info->trap->data;

    addr_t domain_name_addr = drakvuf_get_function_argument(drakvuf, info, 1);

    char* dns_name = drakvuf_read_ascii_str(drakvuf, info, domain_name_addr);

    print_dns_info(drakvuf, info, sm, dns_name);
    g_free(dns_name);

    return 0;
}

// Works on Windows 8+
static event_response_t trap_DnsQueryEx_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* sm = (socketmon*)info->trap->data;

    unicode_string_t* domain_name_us = nullptr;
    addr_t query_request_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    int query_name_offset = drakvuf_get_process_address_width(drakvuf, info);

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = query_request_addr + query_name_offset;

    addr_t query_name_addr = 0;
    if (VMI_FAILURE == drakvuf_read_addr(drakvuf, info, &ctx, &query_name_addr))
    {
        PRINT_DEBUG("[SOCKETMON] Couldn't read query_name_addr in %s(...) trap. Unsupported.\n", info->trap->name);
        return 0;
    }

    ctx.addr = query_name_addr;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        domain_name_us = drakvuf_read_wchar_string(drakvuf, &ctx);
    }

    if (domain_name_us)
    {
        print_dns_info(drakvuf, info, sm, (const char*)domain_name_us->contents);
    }
    else
    {
        PRINT_DEBUG("[SOCKETMON] Error, getting unicode domain name string in %s()", __FUNCTION__);
    }

    vmi_free_unicode_str(domain_name_us);

    return 0;
}

static void register_tcpip_trap( drakvuf_t drakvuf, json_object* tcpip_profile_json, const char* function_name,
    drakvuf_trap_t* trap,
    event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !json_get_symbol_rva(drakvuf, tcpip_profile_json, function_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = function_name;
    trap->cb   = hook_cb;
    trap->ttl  = drakvuf_get_limited_traps_ttl(drakvuf);

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}

namespace
{

struct module_trap_context_t
{
    bool is_wow;
    const char* module_name;
    const char* function_name;
    drakvuf_trap_t* trap;
    event_response_t(*hook_cb)(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
};

}

static bool module_trap_visitor(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx )
{
    module_trap_context_t const* data = reinterpret_cast<module_trap_context_t*>(visitor_ctx);
    status_t ret ;
    vmi_instance_t vmi;
    addr_t exec_func ;
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb                 = module_info->dtb,
        .addr                = module_info->base_addr
    );

    PRINT_DEBUG("[SOCKETMON] trap_visitor: CR3[0x%lX] pid[0x%X %d] is_wow_process[%d]  is_wow_module[%d] base_name[%s] load_address[0x%lX] full_name[%s]\n",
        module_info->dtb, module_info->pid, module_info->pid, module_info->is_wow_process, module_info->is_wow, module_info->base_name->contents, module_info->base_addr, module_info->full_name->contents );

    if (data->is_wow && !module_info->is_wow)
        return false;

    vmi = drakvuf_lock_and_get_vmi( drakvuf );

    ret = vmi_translate_sym2v( vmi, &ctx, data->function_name, &exec_func );

    drakvuf_release_vmi( drakvuf );

    if ( ret == VMI_FAILURE )
    {
        PRINT_DEBUG("[SOCKETMON] Failed to get address of %s!%s\n", data->module_name, data->function_name);
        return false;
    }

    PRINT_DEBUG("[SOCKETMON] Address of %s!%s is 0x%lx\n", data->module_name, data->function_name, exec_func);

    data->trap->breakpoint.module = data->module_name;
    data->trap->breakpoint.pid    = module_info->pid;
    data->trap->breakpoint.addr   = exec_func;

    data->trap->name = data->function_name;
    data->trap->cb   = data->hook_cb;

    return drakvuf_add_trap(drakvuf, data->trap);
}

static void register_module_trap( drakvuf_t drakvuf, drakvuf_trap_t* trap,
    const char* module_name, const char* function_name,
    event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ),
    event_response_t(*wow_hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) = nullptr )
{
    struct module_trap_context_t visitor_ctx = {};
    visitor_ctx.is_wow = false;
    visitor_ctx.module_name = module_name;
    visitor_ctx.function_name = function_name;
    visitor_ctx.trap = trap;
    visitor_ctx.hook_cb = hook_cb;

    if (!drakvuf_enumerate_processes_with_module(drakvuf, module_name, module_trap_visitor, &visitor_ctx))
    {
        PRINT_DEBUG("[SOCKETMON] Failed to trap function %s!%s\n", module_name, function_name);
        throw -1;
    }

    if (drakvuf_get_page_mode(drakvuf) == VMI_PM_IA32E)
    {
        visitor_ctx.is_wow = true;
        if (wow_hook_cb)
            visitor_ctx.hook_cb = wow_hook_cb;
        if (!drakvuf_enumerate_processes_with_module(drakvuf, module_name, module_trap_visitor, &visitor_ctx))
        {
            PRINT_DEBUG("[SOCKETMON] Failed to trap function SysWOW64 %s!%s\n", module_name, function_name);
            throw -1;
        }
    }
}

static void register_dnsapi_trap( drakvuf_t drakvuf, drakvuf_trap_t* trap,
    const char* function_name,
    event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ),
    event_response_t(*wow_hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) = nullptr )
{
    trap->ttl = drakvuf_get_limited_traps_ttl(drakvuf);
    register_module_trap(drakvuf, trap, "dnsapi.dll", function_name, hook_cb, wow_hook_cb);
}

socketmon::socketmon(drakvuf_t drakvuf, const socketmon_config* c, output_format_t output)
    : format{output}
{
    this->pm = drakvuf_get_page_mode(drakvuf);
    {
        vmi_lock_guard vmi(drakvuf);
        if (!vmi_get_windows_build_info(vmi, &this->build))
            throw -1;
    }

    if ( !c->tcpip_profile )
    {
        PRINT_DEBUG("Socketmon plugin requires the JSON debug info for tcpip.sys!\n");
        return;
    }

    if ( this->build.version == VMI_OS_WINDOWS_10 && this->pm != VMI_PM_IA32E )
    {
        PRINT_DEBUG("Socketmon plugin not supported on 32-bit Windows 10\n");
        throw -1;
    }

    assert(sizeof(dnsapi_traps) / sizeof(dnsapi_traps[0]) > 5);
    register_dnsapi_trap(drakvuf, &this->dnsapi_traps[0], "DnsQuery_W", trap_DnsQuery_W_cb);
    register_dnsapi_trap(drakvuf, &this->dnsapi_traps[1], "DnsQuery_A", trap_DnsQuery_A_cb);
    register_dnsapi_trap(drakvuf, &this->dnsapi_traps[2], "DnsQuery_UTF8", trap_DnsQuery_A_cb); // intentionally trap_DnsQuery_A_cb

    if (this->build.version == VMI_OS_WINDOWS_7)
    {
        if (pm == VMI_PM_IA32E)
            register_dnsapi_trap(drakvuf, &this->dnsapi_traps[3], "DnsQueryExW", trap_DnsQueryExW_x64_cb, trap_DnsQueryExW_x86_cb);
        else
            register_dnsapi_trap(drakvuf, &this->dnsapi_traps[3], "DnsQueryExW", trap_DnsQueryExW_x86_cb);
        register_dnsapi_trap(drakvuf, &this->dnsapi_traps[4], "DnsQueryExA", trap_DnsQueryExA_cb);
    }

    if (this->build.version >= VMI_OS_WINDOWS_8)
    {
        register_dnsapi_trap(drakvuf, &this->dnsapi_traps[5], "DnsQueryEx", trap_DnsQueryEx_cb);
    }

    json_object* tcpip_profile_json = json_object_from_file(c->tcpip_profile);
    if (!tcpip_profile_json)
    {
        PRINT_DEBUG("Socketmon plugin fails to load JSON debug info for tcpip.sys\n");
        throw -1;
    }

    event_response_t(*tcpe_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) = tcp_tcb_cb;

    if (pm == VMI_PM_IA32E)
    {
        switch (this->build.version)
        {
            case VMI_OS_WINDOWS_8:
                // Tested on Windows 8.1 update 1 x64
                tcpe_cb = tcpe_win81_x64_cb;
                break;
            case VMI_OS_WINDOWS_10:
                if (this->build.buildnumber < 17134)
                    // Tested on Windows 10 x64 before 1803
                    tcpe_cb = tcpe_win10_x64_cb;
                break;
            case VMI_OS_WINDOWS_7:
                break;
            default:
                PRINT_DEBUG("Socketmon plugin is not supported on %d %d", this->build.version, this->build.buildnumber);
                throw -1;
                break;
        }
    }
    else
    {
        // Tested on Windows 7 SP1 x86
        tcpe_cb = tcpe_x86_cb;
    }

    auto tcp_hook = tcpe_cb == tcp_tcb_cb ? "TcpCreateAndConnectTcbRateLimitComplete" : "TcpCreateAndConnectTcbComplete";

    register_tcpip_trap(drakvuf, tcpip_profile_json, tcp_hook, &this->tcpip_trap[0], tcpe_cb);
    if (this->pm == VMI_PM_IA32E)
        register_tcpip_trap(drakvuf, tcpip_profile_json, "UdpSendMessages", &this->tcpip_trap[1], udp_send_cb);

    json_object_put(tcpip_profile_json);
}

socketmon::~socketmon()
{
}

bool socketmon::stop_impl()
{
    return true;
}
