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

/*
 * 1) ExAllocatePoolWithTag: is it TcpL or UdpA?
 *   - YES: breakpoint RSP
 * 2) RSP: RAX -> _TCP_LISTENER or _UDP_ENDPOINT
 *    - MEMTRAP W location
 * 3) MEMTRAP: Read info
 *    - YES: read string and remove trap
 */

#include <config.h>
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
#include <glib.h>
#include <err.h>

#include <byteswap.h>

#include <string>
#include <iostream>
#include <cassert>

#include <libvmi/libvmi.h>
#include "plugins/plugins.h"
#include "private.h"
#include "socketmon.h"
#include "plugins/output_format.h"

struct wrapper
{
    socketmon* s;
    addr_t obj;
};

static void free_wrapper (drakvuf_trap_t* trap)
{
    g_free(trap->data);
    g_free(trap);
}

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

static char const* tcp_state_string(int tcp_state)
{
    if (tcp_state < 0 || tcp_state >= __TCP_STATE_MAX)
        return "invalid";
    return tcp_state_str[tcp_state];
}

static void print_udpa_ret(drakvuf_t drakvuf, drakvuf_trap_info_t* info, socketmon* s, proc_data_t const& owner_proc_data, int addressfamily, char const* lip, int port)
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
                       int addressfamily, int tcp_state, char const* lip, int localport, char const* rip, int remoteport)
{
    fmt::print(s->format, "socketmon", drakvuf, info,
               keyval("Owner", fmt::Qstr(owner_proc_data.name)),
               keyval("OwnerId", fmt::Nval(owner_proc_data.userid)),
               keyval("OwnerPID", fmt::Nval(owner_proc_data.pid)),
               keyval("OwnerPPID", fmt::Nval(owner_proc_data.ppid)),
               keyval("Protocol", fmt::Rstr(tcp_addressfamily_string(addressfamily))),
               keyval("TcpState", fmt::Rstr(tcp_state_string(tcp_state))),
               keyval("LocalIp", fmt::Rstr(lip ?: "")),
               keyval("LocalPort", fmt::Nval(localport)),
               keyval("RemoteIp", fmt::Rstr(rip ?: "")),
               keyval("RemotePort", fmt::Nval(remoteport))
              );
}

template<typename udp_endpoint_struct, typename inetaf_struct, typename local_address_struct>
static event_response_t udpa_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct wrapper* w = (struct wrapper*)info->trap->data;
    socketmon* s = w->s;

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    addr_t p1 = 0;
    char* lip = NULL;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    proc_data_t owner_proc_data = {};
    udp_endpoint_struct udpa = {};
    inetaf_struct inetaf = {};
    local_address_struct local = {};

    ctx.addr = w->obj;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(udpa), &udpa, NULL) )
        goto done;

    // Convert port to little endian
    udpa.port = __bswap_16(udpa.port);

    if ( !udpa.port )
        goto done;

    ctx.addr = udpa.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(inetaf), &inetaf, NULL) )
        goto done;

    if ( udpa.localaddr )
    {
        ctx.addr = udpa.localaddr;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(local), &local, NULL) )
            goto done;

        ctx.addr = local.pdata;
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
            goto done;
    }

    lip = read_ip_string(vmi, ctx, p1, inetaf.addressfamily);
    if (!lip) goto done;

    if (!drakvuf_get_process_data(drakvuf, udpa.owner, &owner_proc_data))
        goto done;

    print_udpa_ret(drakvuf, info, s, owner_proc_data, inetaf.addressfamily, lip, udpa.port);

done:
    g_free(const_cast<char*>(owner_proc_data.name));
    g_free(lip);
    drakvuf_release_vmi(drakvuf);
    drakvuf_remove_trap(drakvuf, info->trap, free_wrapper);
    return 0;
}

static event_response_t udpa_x86_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return udpa_ret_cb<udp_endpoint_x86, inetaf_x86, local_address_x86>(drakvuf, info);
}

static event_response_t udpa_x64_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return udpa_ret_cb<udp_endpoint_x64, inetaf_x64, local_address_x64>(drakvuf, info);
}

static event_response_t udpa_win10_x64_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return udpa_ret_cb<udp_endpoint_win10_x64, inetaf_win10_x64, local_address_x64>(drakvuf, info);
}

template<typename tcp_endpoint_struct, typename inetaf_struct, typename addr_info_struct, typename local_address_struct>
static event_response_t tcpe_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* s = (socketmon*)info->trap->data;

    addr_t p1 = 0;
    char* lip = NULL;
    char* rip = NULL;
    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    proc_data_t owner_proc_data = {};
    tcp_endpoint_struct tcpe = {};
    inetaf_struct inetaf = {};
    addr_info_struct addrinfo = {};
    local_address_struct local = {};

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ctx.addr = info->regs->rcx;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(tcpe), &tcpe, NULL) )
        goto done;

    if ( tcpe.state >= __TCP_STATE_MAX )
        goto done;

    // Convert ports to little endian
    tcpe.localport = __bswap_16(tcpe.localport);
    tcpe.remoteport = __bswap_16(tcpe.remoteport);

    ctx.addr = tcpe.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(inetaf), &inetaf, NULL) )
        goto done;

    ctx.addr = tcpe.addrinfo;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(addrinfo), &addrinfo, NULL) )
        goto done;

    ctx.addr = addrinfo.local;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(local), &local, NULL) )
        goto done;

    ctx.addr = local.pdata;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
        goto done;

    lip = read_ip_string(vmi, ctx, p1, inetaf.addressfamily);
    if (!lip) goto done;

    rip = read_ip_string(vmi, ctx, addrinfo.remote, inetaf.addressfamily);
    if (!rip) goto done;

    if (!drakvuf_get_process_data(drakvuf, tcpe.owner, &owner_proc_data))
        goto done;

    print_tcpe(drakvuf, info, s, owner_proc_data, inetaf.addressfamily, tcpe.state, lip, tcpe.localport, rip, tcpe.remoteport);

done:
    g_free(const_cast<char*>(owner_proc_data.name));
    g_free(lip);
    g_free(rip);
    drakvuf_release_vmi(drakvuf);

    return 0;
}

static event_response_t tcpe_x86_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return tcpe_cb<tcp_endpoint_x86, inetaf_x86, addr_info_x86, local_address_x86>(drakvuf, info);
}

static event_response_t tcpe_x64_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return tcpe_cb<tcp_endpoint_x64, inetaf_x64, addr_info_x64, local_address_x64>(drakvuf, info);
}

static event_response_t tcpe_win81_x64_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return tcpe_cb<tcp_endpoint_win81_x64, inetaf_win81_x64, addr_info_x64, local_address_x64>(drakvuf, info);
}

static event_response_t tcpe_win10_x64_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return tcpe_cb<tcp_endpoint_win10_x64, inetaf_win10_x64, addr_info_x64, local_address_x64>(drakvuf, info);
}

static event_response_t tcpe_win10_x64_1803_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return tcpe_cb<tcp_endpoint_win10_x64_1803, inetaf_win10_x64, addr_info_x64, local_address_x64>(drakvuf, info);
}

// TODO Return static qualifier after fixing UDP monitor
event_response_t udpb_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct wrapper* w = (struct wrapper*)g_try_malloc0(sizeof(struct wrapper));
    w->s = (socketmon*)info->trap->data;

    addr_t ret_addr = drakvuf_get_function_return_address(drakvuf, info);

    w->obj = drakvuf_get_function_argument(drakvuf, info, 1);

    if ( !w->obj )
    {
        g_free(w);
        return 0;
    }

    drakvuf_trap_t* trap = (drakvuf_trap_t*)g_try_malloc0(sizeof(drakvuf_trap_t));
    trap->breakpoint.lookup_type = LOOKUP_PID;
    trap->breakpoint.pid = 4;
    trap->breakpoint.addr_type = ADDR_VA;
    trap->breakpoint.addr = ret_addr;
    trap->type = BREAKPOINT;
    trap->data = w;
    trap->ttl = LIMITED_TTL;

    if ( w->s->winver == VMI_OS_WINDOWS_7 || w->s->winver == VMI_OS_WINDOWS_8 )
        trap->cb = ( w->s->pm == VMI_PM_IA32E ) ? udpa_x64_ret_cb : udpa_x86_ret_cb;
    else
        trap->cb = ( w->s->pm == VMI_PM_IA32E ) ? udpa_win10_x64_ret_cb : NULL;

    if ( !drakvuf_add_trap(drakvuf, trap) )
    {
        printf("Failed to trap return at 0x%lx\n", ret_addr);
        g_free(w);
    }

    return 0;
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

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = domain_name_addr;

    char* dns_name = [&]
    {
        vmi_lock_guard vmi_lg(drakvuf);
        return vmi_read_str(vmi_lg.vmi, &ctx);
    }();
    print_dns_info(drakvuf, info, sm, dns_name);
    g_free(dns_name);

    return 0;
}


static event_response_t trap_DnsQuery_W_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* sm = (socketmon*)info->trap->data;

    addr_t domain_name_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    unicode_string_t* domain_name_us = nullptr;

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = domain_name_addr;

    {
        vmi_lock_guard vmi_lg(drakvuf);
        domain_name_us = drakvuf_read_wchar_string(vmi_lg.vmi, &ctx);
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
static event_response_t trap_DnsQueryExW_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    unicode_string_t* domain_name_us = nullptr;
    socketmon* sm = (socketmon*)info->trap->data;

    addr_t domain_name_addr = drakvuf_get_function_argument(drakvuf, info, 1);

    {
        dns_query_ex_w_string_t function_specific_string;
        uint32_t struct_size = sizeof(function_specific_string);

        access_context_t ctx;
        memset(&ctx, 0, sizeof(access_context_t));
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = domain_name_addr;

        vmi_lock_guard vmi_lg(drakvuf);

        // Read strange function-specific string
        if ( VMI_FAILURE == vmi_read(vmi_lg.vmi, &ctx, struct_size, &function_specific_string, NULL) )
        {
            PRINT_DEBUG("[SOCKETMON] Error, getting unicode domain name string from 'strange string' in %s()", __FUNCTION__);
            return 0;
        }

        ctx.addr = function_specific_string.pBuffer;
        domain_name_us = drakvuf_read_wchar_string(vmi_lg.vmi, &ctx);
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
static event_response_t trap_DnsQueryExA_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* sm = (socketmon*)info->trap->data;

    addr_t domain_name_addr = drakvuf_get_function_argument(drakvuf, info, 1);

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = domain_name_addr;

    char* dns_name = [&]
    {
        vmi_lock_guard vmi_lg(drakvuf);
        return vmi_read_str(vmi_lg.vmi, &ctx);
    }();

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
    addr_t query_name_addr = 0;

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = query_request_addr + drakvuf_get_address_width(drakvuf);

    {
        vmi_lock_guard vmi_lg(drakvuf);

        if ( VMI_FAILURE == vmi_read_addr(vmi_lg.vmi, &ctx, &query_name_addr) )
        {
            PRINT_DEBUG("[SOCKETMON] Couldn't read query_name_addr in %s(...) trap. Unsupported.\n", info->trap->name);
            return 0;
        }

        ctx.addr = query_name_addr;
        domain_name_us = drakvuf_read_wchar_string(vmi_lg.vmi, &ctx);
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

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}

namespace
{

struct module_trap_context_t
{
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
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb                 = module_info->dtb,
        .addr                = module_info->base_addr,
    };

    PRINT_DEBUG("[SOCKETMON] trap_visitor: CR3[0x%lX] pid[0x%X %d] is_wow_process[%d]  is_wow_module[%d] base_name[%s] load_address[0x%lX] full_name[%s]\n",
                module_info->dtb, module_info->pid, module_info->pid, module_info->is_wow_process, module_info->is_wow, module_info->base_name->contents, module_info->base_addr, module_info->full_name->contents );

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
                                  event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    struct module_trap_context_t visitor_ctx = {};
    visitor_ctx.module_name = module_name;
    visitor_ctx.function_name = function_name;
    visitor_ctx.trap = trap;
    visitor_ctx.hook_cb = hook_cb;

    if (!drakvuf_enumerate_processes_with_module(drakvuf, module_name, module_trap_visitor, &visitor_ctx))
    {
        PRINT_DEBUG("[SOCKETMON] Failed to trap function %s!%s\n", module_name, function_name);
        throw -1;
    }
}

static void register_dnsapi_trap( drakvuf_t drakvuf, drakvuf_trap_t* trap,
                                  const char* function_name,
                                  event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    register_module_trap(drakvuf, trap, "dnsapi.dll", function_name, hook_cb);
}

socketmon::socketmon(drakvuf_t drakvuf, const socketmon_config* c, output_format_t output)
    : format{output}
{
    this->pm = drakvuf_get_page_mode(drakvuf);

    uint16_t build = 0;
    {
        vmi_lock_guard vmi(drakvuf);
        win_build_info_t build_info;
        if (!vmi_get_windows_build_info(vmi.vmi, &build_info))
            throw -1;

        this->winver = build_info.version;
        build = build_info.buildnumber;
    }

    if ( !c->tcpip_profile )
    {
        PRINT_DEBUG("Socketmon plugin requires the JSON debug info for tcpip.sys!\n");
        return;
    }

    if ( this->winver == VMI_OS_WINDOWS_10 && this->pm != VMI_PM_IA32E )
    {
        PRINT_DEBUG("Socketmon plugin not supported on 32-bit Windows 10\n");
        throw -1;
    }

    assert(sizeof(dnsapi_traps) / sizeof(dnsapi_traps[0]) > 5);
    register_dnsapi_trap(drakvuf, &this->dnsapi_traps[0], "DnsQuery_W", trap_DnsQuery_W_cb);
    register_dnsapi_trap(drakvuf, &this->dnsapi_traps[1], "DnsQuery_A", trap_DnsQuery_A_cb);
    register_dnsapi_trap(drakvuf, &this->dnsapi_traps[2], "DnsQuery_UTF8", trap_DnsQuery_A_cb); // intentionally trap_DnsQuery_A_cb

    if (this->winver == VMI_OS_WINDOWS_7)
    {
        register_dnsapi_trap(drakvuf, &this->dnsapi_traps[3], "DnsQueryExW", trap_DnsQueryExW_cb);
        register_dnsapi_trap(drakvuf, &this->dnsapi_traps[4], "DnsQueryExA", trap_DnsQueryExA_cb);
    }

    if (this->winver >= VMI_OS_WINDOWS_8)
    {
        register_dnsapi_trap(drakvuf, &this->dnsapi_traps[5], "DnsQueryEx", trap_DnsQueryEx_cb);
    }

    json_object* tcpip_profile_json = json_object_from_file(c->tcpip_profile);
    if (!tcpip_profile_json)
    {
        PRINT_DEBUG("Socketmon plugin fails to load JSON debug info for tcpip.sys\n");
        throw -1;
    }

    event_response_t(*tcpe_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) = nullptr;
    if (pm == VMI_PM_IA32E)
    {
        switch (winver)
        {
            case VMI_OS_WINDOWS_8:
                // Tested on Windows 8.1 update 1 x64
                tcpe_cb = tcpe_win81_x64_cb;
                break;
            case VMI_OS_WINDOWS_10:
                if (build < 1734)
                    // Tested on Windows 10 x64 before 1803
                    tcpe_cb = tcpe_win10_x64_cb;
                else
                    // Tested on Windows 10 1803 x64
                    tcpe_cb = tcpe_win10_x64_1803_cb;
                break;
            default:
                // Tested on Windows 7 SP1 x64
                tcpe_cb = tcpe_x64_cb;
                break;
        }
    }
    else
    {
        // Tested on Windows 7 SP1 x86
        tcpe_cb = tcpe_x86_cb;
    }

    // TODO Test and fix UDP monitor
    // register_tcpip_trap(drakvuf, tcpip_profile_json, "UdpSetSockOptEndpoint", &this->tcpip_traps[5], udpb_cb);
    register_tcpip_trap(drakvuf, tcpip_profile_json, "TcpCreateAndConnectTcbComplete", &this->tcpip_trap, tcpe_cb);

    json_object_put(tcpip_profile_json);

    PRINT_DEBUG("[SOCKETMON] Socketmon constructor end.\n");
}

socketmon::~socketmon()
{
}
