/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2017 Tamas K Lengyel.                                  *
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

#include <libvmi/libvmi.h>
#include "plugins/plugins.h"
#include "private.h"
#include "socketmon.h"

struct wrapper
{
    socketmon* s;
    addr_t obj;
};

void free_wrapper (drakvuf_trap_t* trap)
{
    g_free(trap->data);
    g_free(trap);
}

static inline void ipv4_to_str(char** str, uint8_t ipv4[4])
{
    *str = (char*)g_malloc0(snprintf(NULL, 0, "%u.%u.%u.%u",
                                     ipv4[0], ipv4[1], ipv4[2], ipv4[3]) + 1);
    if ( !(*str) )
        return;

    sprintf(*str, "%u.%u.%u.%u", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
}

static inline void ipv6_to_str(char** str, uint8_t ipv6[16])
{
    *str = (char*)g_malloc0(snprintf(NULL, 0,
                                     "%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
                                     ipv6[0], ipv6[1], ipv6[2], ipv6[3],
                                     ipv6[4], ipv6[5], ipv6[6], ipv6[7],
                                     ipv6[8], ipv6[9], ipv6[10], ipv6[11],
                                     ipv6[12], ipv6[13], ipv6[14], ipv6[15]) + 1);

    if ( !(*str) )
        return;

    sprintf(*str,
            "%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
            ipv6[0], ipv6[1], ipv6[2], ipv6[3],
            ipv6[4], ipv6[5], ipv6[6], ipv6[7],
            ipv6[8], ipv6[9], ipv6[10], ipv6[11],
            ipv6[12], ipv6[13], ipv6[14], ipv6[15]);
}

static event_response_t udpa_x86_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    int64_t ownerid = 0;
    addr_t p1 = 0;
    char* lip = NULL, *owner = NULL;
    struct wrapper* w = (struct wrapper*)info->trap->data;
    socketmon* s = w->s;

    struct udp_endpoint_x86 udpa;;
    struct inetaf_x86 inetaf;
    struct local_address_x86 local;
    memset(&udpa, 0, sizeof(struct udp_endpoint_x86));
    memset(&inetaf, 0, sizeof(struct inetaf_x86));
    memset(&local, 0, sizeof(local_address_x86));

    ctx.addr = w->obj;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct udp_endpoint_x86), &udpa, NULL) )
        goto done;

    // Convert port to little endian
    udpa.port = __bswap_16(udpa.port);

    if ( !udpa.port )
        goto done;

    ctx.addr = udpa.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct inetaf_x86), &inetaf, NULL) )
        goto done;

    if ( udpa.localaddr )
    {
        ctx.addr = udpa.localaddr;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct local_address_x86), &local, NULL) )
            goto done;


        ctx.addr = local.pdata;
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
            goto done;
    }

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
                goto done;
        }

        ipv4_to_str(&lip, localip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &localip[0], NULL) )
                goto done;
        }

        ipv6_to_str(&lip, localip);
    }

    owner = drakvuf_get_process_name(drakvuf, udpa.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, udpa.owner);

    switch (s->format)
    {
        case OUTPUT_CSV:
            printf("socketmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%" PRIi64 ",%s,%s,%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
                   lip, udpa.port);
            break;

        case OUTPUT_KV:
            printf("socketmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",UserId=%" PRIi64",Owner=%s,OwnerId=%" PRIi64 ",Protocol=%s,LocalIp=%s,LocalPort=%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
                   lip, udpa.port);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[SOCKETMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s %s:%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   owner, USERIDSTR(drakvuf), ownerid,
                   (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
                   lip, udpa.port);
            break;
    };

done:
    g_free(owner);
    g_free(lip);
    drakvuf_release_vmi(drakvuf);
    drakvuf_remove_trap(drakvuf, info->trap, free_wrapper);
    return 0;
}

static event_response_t udpa_x64_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    int64_t ownerid = 0;
    addr_t p1 = 0;
    char* lip = NULL, *owner = NULL;
    struct wrapper* w = (struct wrapper*)info->trap->data;
    socketmon* s = w->s;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    struct udp_endpoint_x64 udpa;
    struct inetaf_x64 inetaf;
    struct local_address_x64 local;
    memset(&udpa, 0, sizeof(struct udp_endpoint_x64));
    memset(&inetaf, 0, sizeof(struct inetaf_x64));
    memset(&local, 0, sizeof(local_address_x64));

    ctx.addr = w->obj;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct udp_endpoint_x64), &udpa, NULL) )
        goto done;

    // Convert port to little endian
    udpa.port = __bswap_16(udpa.port);

    if ( !udpa.port )
        goto done;

    ctx.addr = udpa.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct inetaf_x64), &inetaf, NULL) )
        goto done;

    if ( udpa.localaddr )
    {
        ctx.addr = udpa.localaddr;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct local_address_x64), &local, NULL) )
            goto done;

        ctx.addr = local.pdata;
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
            goto done;
    }

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
                goto done;
        }

        ipv4_to_str(&lip, localip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &localip[0], NULL) )
                goto done;
        }

        ipv6_to_str(&lip, localip);
    }

    owner = drakvuf_get_process_name(drakvuf, udpa.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, udpa.owner);

    switch (s->format)
    {
        case OUTPUT_CSV:
            printf("socketmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%" PRIi64",%s,%s,%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
                   lip, udpa.port);
            break;

        case OUTPUT_KV:
            printf("socketmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",UserId=%" PRIi64",Owner=%s,OwnerId=%" PRIi64",Protocol=%s,LocalIp=%s,LocalPort=%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
                   lip, udpa.port);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[SOCKETMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s %s:%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   owner, USERIDSTR(drakvuf), ownerid,
                   (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
                   lip, udpa.port);
            break;
    };

done:
    g_free(owner);
    g_free(lip);
    drakvuf_release_vmi(drakvuf);
    drakvuf_remove_trap(drakvuf, info->trap, free_wrapper);
    return 0;
}

static event_response_t udpa_win10_x64_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    int64_t ownerid = 0;
    addr_t p1 = 0;
    char* lip = NULL, *owner = NULL;
    struct wrapper* w = (struct wrapper*)info->trap->data;
    socketmon* s = w->s;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    struct udp_endpoint_win10_x64 udpa;
    struct inetaf_win10_x64 inetaf;
    struct local_address_x64 local;
    memset(&udpa, 0, sizeof(struct udp_endpoint_win10_x64));
    memset(&inetaf, 0, sizeof(struct inetaf_win10_x64));
    memset(&local, 0, sizeof(local_address_x64));

    ctx.addr = w->obj;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct udp_endpoint_win10_x64), &udpa, NULL) )
        goto done;

    // Convert port to little endian
    udpa.port = __bswap_16(udpa.port);

    if ( !udpa.port )
        goto done;

    ctx.addr = udpa.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct inetaf_win10_x64), &inetaf, NULL) )
        goto done;

    if ( udpa.localaddr )
    {
        ctx.addr = udpa.localaddr;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct local_address_x64), &local, NULL) )
            goto done;

        ctx.addr = local.pdata;
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
            goto done;
    }

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
                goto done;
        }

        ipv4_to_str(&lip, localip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {

        uint8_t localip[16]  = {[0 ... 15] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &localip[0], NULL) )
                goto done;
        }

        ipv6_to_str(&lip, localip);
    }

    owner = drakvuf_get_process_name(drakvuf, udpa.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, udpa.owner);

    switch (s->format)
    {
        case OUTPUT_CSV:
            printf("socketmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%" PRIi64",%s,%s,%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
                   lip, udpa.port);
            break;

        case OUTPUT_KV:
            printf("socketmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",UserId=%" PRIi64",Owner=%s,"
                   "OwnerId=%" PRIi64",Protocol=%s,LocalIp=%s,LocalPort=%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
                   lip, udpa.port);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[SOCKETMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s %s:%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   owner, USERIDSTR(drakvuf), ownerid,
                   (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
                   lip, udpa.port);
            break;
    };

done:
    g_free(owner);
    g_free(lip);
    drakvuf_release_vmi(drakvuf);
    drakvuf_remove_trap(drakvuf, info->trap, free_wrapper);
    return 0;
}

static event_response_t tcpe_x86_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    socketmon* s = (socketmon*)info->trap->data;

    int64_t ownerid = -1;
    addr_t p1 = 0;
    char* lip = NULL, *rip = NULL, *owner=NULL;
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    struct tcp_endpoint_x86 tcpe;
    struct inetaf_x86 inetaf;
    struct addr_info_x86 addrinfo;
    struct local_address_x86 local;
    memset(&tcpe, 0, sizeof(struct tcp_endpoint_x86));
    memset(&inetaf, 0, sizeof(struct inetaf_x86));
    memset(&addrinfo, 0, sizeof(struct addr_info_x86));
    memset(&local, 0, sizeof(local_address_x86));

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ctx.addr = info->regs->rsp + sizeof(uint32_t);
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ctx.addr) )
        goto done;

    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct tcp_endpoint_x86), &tcpe, NULL) )
        goto done;

    if ( tcpe.state >= __TCP_STATE_MAX )
        goto done;

    // Convert ports to little endian
    tcpe.localport = __bswap_16(tcpe.localport);
    tcpe.remoteport = __bswap_16(tcpe.remoteport);

    ctx.addr = tcpe.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct inetaf_x86), &inetaf, NULL) )
        goto done;

    if ( tcpe.addrinfo )
    {
        ctx.addr = tcpe.addrinfo;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct addr_info_x86), &addrinfo, NULL) )
            goto done;
    }

    if ( addrinfo.local )
    {
        ctx.addr = addrinfo.local;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct local_address_x86), &local, NULL) )
            goto done;
    }

    if ( local.pdata )
    {
        ctx.addr = local.pdata;
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
            goto done;
    }

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};
        uint8_t remoteip[4] = {[0 ... 3] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
                goto done;
        }

        if ( addrinfo.remote )
        {
            ctx.addr = addrinfo.remote;
            if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&remoteip[0]) )
                goto done;
        }

        ipv4_to_str(&lip, localip);
        ipv4_to_str(&rip, remoteip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};
        uint8_t remoteip[16] = {[0 ... 15] = 0};

        ctx.addr = p1;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &localip[0], NULL) )
            goto done;

        ctx.addr = addrinfo.remote;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &remoteip[0], NULL) )
            goto done;

        ipv6_to_str(&lip, localip);
        ipv6_to_str(&rip, remoteip);
    }

    owner = drakvuf_get_process_name(drakvuf, tcpe.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, tcpe.owner);

    switch (s->format)
    {
        case OUTPUT_CSV:
            printf("socketmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,%" PRIi64 ",%s,%s,%s,%" PRIu16 ",%s,%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->proc_data.userid,
                   owner,ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   tcp_state_str[tcpe.state],
                   lip, tcpe.localport, rip, tcpe.remoteport);
            break;

        case OUTPUT_KV:
            printf("socketmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",UserId=%" PRIi64 ",Owner=%s,OwnerId=%" PRIi64 ",Protocol=%s,TcpState=%s,"
                   "LocalIp=%s,LocalPort=%" PRIu16 ",RemoteIp=%s,RemotePort=%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->proc_data.userid,
                   owner,ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   tcp_state_str[tcpe.state],
                   lip, tcpe.localport, rip, tcpe.remoteport);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[SOCKETMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s State:%s Local:%s:%" PRIu16 " Remote:%s:%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, USERIDSTR(drakvuf), info->proc_data.userid,
                   owner, USERIDSTR(drakvuf), ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   tcp_state_str[tcpe.state],
                   lip, tcpe.localport, rip, tcpe.remoteport);
            break;
    };

done:
    g_free(lip);
    g_free(rip);
    drakvuf_release_vmi(drakvuf);

    return 0;
}

static event_response_t tcpe_x64_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* s = (socketmon*)info->trap->data;

    int64_t ownerid;
    addr_t p1 = 0;
    char* lip = NULL, *rip = NULL, *owner = NULL;
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    struct tcp_endpoint_x64 tcpe;
    struct inetaf_x64 inetaf;
    struct addr_info_x64 addrinfo;
    struct local_address_x64 local;
    memset(&tcpe, 0, sizeof(struct tcp_endpoint_x64));
    memset(&inetaf, 0, sizeof(struct inetaf_x64));
    memset(&addrinfo, 0, sizeof(struct addr_info_x64));
    memset(&local, 0, sizeof(local_address_x64));

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ctx.addr = info->regs->rcx;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct tcp_endpoint_x64), &tcpe, NULL) )
        goto done;

    if ( tcpe.state >= __TCP_STATE_MAX )
        goto done;

    // Convert ports to little endian
    tcpe.localport = __bswap_16(tcpe.localport);
    tcpe.remoteport = __bswap_16(tcpe.remoteport);

    ctx.addr = tcpe.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct inetaf_x64),  &inetaf, NULL) )
        goto done;

    ctx.addr = tcpe.addrinfo;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct addr_info_x64), &addrinfo, NULL) )
        goto done;

    ctx.addr = addrinfo.local;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct local_address_x64), &local, NULL) )
        goto done;

    ctx.addr = local.pdata;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
        goto done;

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};
        uint8_t remoteip[4] = {[0 ... 3] = 0};

        ctx.addr = p1;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
            goto done;

        ctx.addr = addrinfo.remote;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&remoteip[0]) )
            goto done;

        ipv4_to_str(&lip, localip);
        ipv4_to_str(&rip, remoteip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};
        uint8_t remoteip[16] = {[0 ... 15] = 0};

        ctx.addr = p1;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &localip[0], NULL) )
            goto done;

        ctx.addr = addrinfo.remote;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &remoteip[0], NULL) )
            goto done;

        ipv6_to_str(&lip, localip);
        ipv6_to_str(&rip, remoteip);
    }

    owner = drakvuf_get_process_name(drakvuf, tcpe.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, tcpe.owner);

    switch (s->format)
    {
        case OUTPUT_CSV:
            printf("socketmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,%" PRIi64 ",%s,%s,%s,%" PRIu16 ",%s,%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->proc_data.userid,
                   owner,ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   tcp_state_str[tcpe.state],
                   lip, tcpe.localport, rip, tcpe.remoteport);
            break;

        case OUTPUT_KV:
            printf("socketmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",UserId=%" PRIi64 ",Owner=%s,OwnerId=%" PRIi64 ",Protocol=%s,TcpState=%s,"
                   "LocalIp=%s,LocalPort=%" PRIu16 ",RemoteIp=%s,RemotePort=%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->proc_data.userid,
                   owner,ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   tcp_state_str[tcpe.state],
                   lip, tcpe.localport, rip, tcpe.remoteport);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[SOCKETMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s State:%s Local:%s:%" PRIu16 " Remote:%s:%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, USERIDSTR(drakvuf), info->proc_data.userid,
                   owner, USERIDSTR(drakvuf), ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   tcp_state_str[tcpe.state],
                   lip, tcpe.localport, rip, tcpe.remoteport);
            break;
    };

done:
    g_free(owner);
    g_free(lip);
    g_free(rip);
    drakvuf_release_vmi(drakvuf);

    return 0;
}

static event_response_t tcpe_win10_x64_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* s = (socketmon*)info->trap->data;

    int64_t ownerid;
    addr_t p1 = 0;
    char* lip = NULL, *rip = NULL, *owner = NULL;
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    struct tcp_endpoint_win10_x64 tcpe;
    struct inetaf_win10_x64 inetaf;
    struct addr_info_x64 addrinfo;
    struct local_address_x64 local;
    memset(&tcpe, 0, sizeof(struct tcp_endpoint_win10_x64));
    memset(&inetaf, 0, sizeof(struct inetaf_win10_x64));
    memset(&addrinfo, 0, sizeof(struct addr_info_x64));
    memset(&local, 0, sizeof(local_address_x64));

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ctx.addr = info->regs->rcx;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct tcp_endpoint_win10_x64), &tcpe, NULL) )
        goto done;

    if ( tcpe.state >= __TCP_STATE_MAX )
        goto done;

    // Convert ports to little endian
    tcpe.localport = __bswap_16(tcpe.localport);
    tcpe.remoteport = __bswap_16(tcpe.remoteport);

    ctx.addr = tcpe.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct inetaf_win10_x64), &inetaf, NULL) )
        goto done;

    ctx.addr = tcpe.addrinfo;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct addr_info_x64), &addrinfo, NULL) )
        goto done;

    ctx.addr = addrinfo.local;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct local_address_x64), &local, NULL) )
        goto done;

    ctx.addr = local.pdata;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
        goto done;

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};
        uint8_t remoteip[4] = {[0 ... 3] = 0};

        ctx.addr = p1;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
            goto done;

        ctx.addr = addrinfo.remote;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&remoteip[0]) )
            goto done;

        ipv4_to_str(&lip, localip);
        ipv4_to_str(&rip, remoteip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};
        uint8_t remoteip[16] = {[0 ... 15] = 0};

        ctx.addr = p1;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &localip[0], NULL) )
            goto done;

        ctx.addr = addrinfo.remote;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &remoteip[0], NULL) )
            goto done;

        ipv6_to_str(&lip, localip);
        ipv6_to_str(&rip, remoteip);
    }

    owner = drakvuf_get_process_name(drakvuf, tcpe.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, tcpe.owner);

    switch (s->format)
    {
        case OUTPUT_CSV:
            printf("socketmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,%" PRIi64 ",%s,%s,%s,%" PRIu16 ",%s,%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->proc_data.userid,
                   owner,ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   tcp_state_str[tcpe.state],
                   lip, tcpe.localport, rip, tcpe.remoteport);
            break;

        case OUTPUT_KV:
            printf("socketmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",UserId=%" PRIi64 ",Owner=%s,OwnerId=%" PRIi64 ",Protocol=%s,TcpState=%s,"
                   "LocalIp=%s,LocalPort=%" PRIu16 ",RemoteIp=%s,RemotePort=%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->proc_data.userid,
                   owner,ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   tcp_state_str[tcpe.state],
                   lip, tcpe.localport, rip, tcpe.remoteport);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[SOCKETMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s State:%s Local:%s:%" PRIu16 " Remote:%s:%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, USERIDSTR(drakvuf), info->proc_data.userid,
                   owner, USERIDSTR(drakvuf), ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   tcp_state_str[tcpe.state],
                   lip, tcpe.localport, rip, tcpe.remoteport);
            break;
    };

done:
    g_free(owner);
    g_free(lip);
    g_free(rip);
    drakvuf_release_vmi(drakvuf);

    return 0;
}

static event_response_t tcpl_x86_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct wrapper* w = (struct wrapper*)info->trap->data;
    socketmon* s = w->s;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    int64_t ownerid = 0;
    addr_t p1 = 0;
    char* lip = NULL, *owner = NULL;
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    struct tcp_listener_x86 tcpl;
    struct inetaf_x86 inetaf;
    struct local_address_x86 local;
    memset(&tcpl, 0, sizeof(struct tcp_listener_x86));
    memset(&inetaf, 0, sizeof(struct inetaf_x86));
    memset(&local, 0, sizeof(local_address_x86));

    uint32_t ownerp = 0;

    ctx.addr = w->obj - sizeof(struct tcp_listener_x86);
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct tcp_listener_x86), &tcpl, NULL) )
    {
        printf("Failed to tcp listener @ 0x%lx\n", ctx.addr);
        goto done;
    }

    // Convert port to little endian
    tcpl.port = __bswap_16(tcpl.port);

    ctx.addr = w->obj - sizeof(struct tcp_listener_x86);
    if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &ownerp) )
        goto done;

    ctx.addr = tcpl.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct inetaf_x86), &inetaf, NULL) )
        goto done;

    if ( tcpl.localaddr )
    {
        ctx.addr = tcpl.localaddr;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct local_address_x86), &local, NULL) )
            goto done;
    }

    if ( local.pdata )
    {
        ctx.addr = local.pdata;
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
            goto done;
    }

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
                goto done;
        }

        ipv4_to_str(&lip, localip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &localip[0], NULL) )
                goto done;
        }

        ipv6_to_str(&lip, localip);
    }

    owner = drakvuf_get_process_name(drakvuf, tcpl.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, tcpl.owner);

    switch (s->format)
    {
        case OUTPUT_CSV:
            printf("socketmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64",%s,%" PRIi64 ",%s,listener,%s,%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   lip, tcpl.port);
            break;

        case OUTPUT_KV:
            printf("socketmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",UserId=%" PRIi64 ",Owner=%s,OwnerId=%" PRIi64 ",Protocol=%s,listener,LocalIp=%s,LocalPort=%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   lip, tcpl.port);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[SOCKETMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s listener %s:%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   owner, USERIDSTR(drakvuf), ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   lip, tcpl.port);
            break;
    };

done:
    g_free(owner);
    g_free(lip);
    drakvuf_release_vmi(drakvuf);
    drakvuf_remove_trap(drakvuf, info->trap, free_wrapper);

    return 0;
}

static event_response_t tcpl_x64_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct wrapper* w = (struct wrapper*)info->trap->data;
    socketmon* s = w->s;

    int64_t ownerid = 0;
    addr_t p1 = 0;
    char* lip = NULL, *owner = NULL;
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    struct tcp_listener_x64 tcpl;
    struct inetaf_x64 inetaf;
    struct local_address_x64 local;
    memset(&tcpl, 0, sizeof(struct tcp_listener_x64));
    memset(&inetaf, 0, sizeof(struct inetaf_x64));
    memset(&local, 0, sizeof(local_address_x64));

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ctx.addr = w->obj - sizeof(struct tcp_listener_x64);
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct tcp_listener_x64), &tcpl, NULL) )
        goto done;

    // Convert port to little endian
    tcpl.port = __bswap_16(tcpl.port);

    ctx.addr = tcpl.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct inetaf_x64), &inetaf, NULL) )
        goto done;

    if ( tcpl.localaddr )
    {
        ctx.addr = tcpl.localaddr;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct local_address_x64), &local, NULL) )
            goto done;
    }

    if ( local.pdata )
    {
        ctx.addr = local.pdata;
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
            goto done;
    }

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
                goto done;
        }

        ipv4_to_str(&lip, localip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &localip[0], NULL) )
                goto done;
        }

        ipv6_to_str(&lip, localip);
    }

    owner = drakvuf_get_process_name(drakvuf, tcpl.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, tcpl.owner);

    switch (s->format)
    {
        case OUTPUT_CSV:
            printf("socketmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,%" PRIi64 ",%s,listener,%s,%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   lip, tcpl.port);
            break;

        case OUTPUT_KV:
            printf("socketmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",UserId=%" PRIi64 ",Owner=%s,OwnerId=%" PRIi64 ",Protocol=%s,listener,LocalIp=%s,LocalPort=%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   lip, tcpl.port);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[SOCKETMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s listener %s:%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   owner, USERIDSTR(drakvuf), ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   lip, tcpl.port);
            break;
    };

done:
    g_free(owner);
    g_free(lip);
    drakvuf_release_vmi(drakvuf);
    drakvuf_remove_trap(drakvuf, info->trap, free_wrapper);

    return 0;
}

static event_response_t tcpl_win10_x64_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct wrapper* w = (struct wrapper*)info->trap->data;
    socketmon* s = w->s;

    int64_t ownerid = 0;
    addr_t p1 = 0;
    char* lip = NULL, *owner = NULL;
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    struct tcp_listener_win10_x64 tcpl;
    struct inetaf_win10_x64 inetaf;
    struct local_address_x64 local;
    memset(&tcpl, 0, sizeof(struct tcp_listener_win10_x64));
    memset(&inetaf, 0, sizeof(struct inetaf_win10_x64));
    memset(&local, 0, sizeof(local_address_x64));

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ctx.addr = w->obj - sizeof(struct tcp_listener_win10_x64);
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct tcp_listener_win10_x64), &tcpl, NULL) )
        goto done;

    // Convert port to little endian
    tcpl.port = __bswap_16(tcpl.port);

    ctx.addr = tcpl.inetaf;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct inetaf_win10_x64), &inetaf, NULL) )
        goto done;

    if ( tcpl.localaddr )
    {
        ctx.addr = tcpl.localaddr;
        if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct local_address_x64), &local, NULL) )
            goto done;
    }

    if ( local.pdata )
    {
        ctx.addr = local.pdata;
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
            goto done;
    }

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
                goto done;
        }

        ipv4_to_str(&lip, localip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};

        if ( p1 )
        {
            ctx.addr = p1;
            if ( VMI_FAILURE == vmi_read(vmi, &ctx, 16, &localip[0], NULL) )
                goto done;
        }

        ipv6_to_str(&lip, localip);
    }

    owner = drakvuf_get_process_name(drakvuf, tcpl.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, tcpl.owner);

    switch (s->format)
    {
        case OUTPUT_CSV:
            printf("socketmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%s,%" PRIi64 ",%s,listener,%s,%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   lip, tcpl.port);
            break;

        case OUTPUT_KV:
            printf("socketmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",UserId=%" PRIi64 ",Owner=%s,OwnerId=%" PRIi64 ",Protocol=%s,listener,LocalIp=%s,LocalPort=%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, info->proc_data.userid,
                   owner, ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   lip, tcpl.port);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[SOCKETMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s listener %s:%" PRIu16 "\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   owner, USERIDSTR(drakvuf), ownerid,
                   (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
                   lip, tcpl.port);
            break;
    };

done:
    g_free(owner);
    g_free(lip);
    drakvuf_release_vmi(drakvuf);
    drakvuf_remove_trap(drakvuf, info->trap, free_wrapper);

    return 0;
}

static event_response_t tcpl_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t rsp = 0;
    struct wrapper* w = (struct wrapper*)g_malloc0(sizeof(struct wrapper));
    w->s = (socketmon*)info->trap->data;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    vmi_read_addr_va(vmi, info->regs->rsp, 0, &rsp);

    if ( w->s->pm == VMI_PM_IA32E )
        w->obj = info->regs->rcx;
    else
        vmi_read_addr_va(vmi, info->regs->rsp + sizeof(uint32_t), 0, &w->obj);

    drakvuf_release_vmi(drakvuf);

    if ( !w->obj )
        return 0;

    drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    trap->breakpoint.lookup_type = LOOKUP_PID;
    trap->breakpoint.pid = 4;
    trap->breakpoint.addr_type = ADDR_VA;
    trap->breakpoint.addr = rsp;
    trap->type = BREAKPOINT;
    trap->data = w;

    switch (w->s->winver)
    {
        case VMI_OS_WINDOWS_7:
        case VMI_OS_WINDOWS_8:
            trap->cb = ( w->s->pm == VMI_PM_IA32E ) ? tcpl_x64_ret_cb : tcpl_x86_ret_cb;
            break;
        default:
        case VMI_OS_WINDOWS_10:
            trap->cb = ( w->s->pm == VMI_PM_IA32E ) ? tcpl_win10_x64_ret_cb : NULL;
            break;
    };

    if ( !drakvuf_add_trap(drakvuf, trap) )
        printf("Failed to trap return at 0x%lx\n", rsp);

    return 0;
}

static event_response_t udpb_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t rsp = 0;
    struct wrapper* w = (struct wrapper*)g_malloc0(sizeof(struct wrapper));
    w->s = (socketmon*)info->trap->data;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    vmi_read_addr_va(vmi, info->regs->rsp, 0, &rsp);

    if ( w->s->pm == VMI_PM_IA32E )
        w->obj = info->regs->rcx;
    else
        vmi_read_addr_va(vmi, info->regs->rsp + sizeof(uint32_t), 0, &w->obj);

    drakvuf_release_vmi(drakvuf);

    if ( !w->obj )
        return 0;

    drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    trap->breakpoint.lookup_type = LOOKUP_PID;
    trap->breakpoint.pid = 4;
    trap->breakpoint.addr_type = ADDR_VA;
    trap->breakpoint.addr = rsp;
    trap->type = BREAKPOINT;
    trap->data = w;

    switch (w->s->winver)
    {
        case VMI_OS_WINDOWS_7:
        case VMI_OS_WINDOWS_8:
            trap->cb = ( w->s->pm == VMI_PM_IA32E ) ? udpa_x64_ret_cb : udpa_x86_ret_cb;
            break;
        default:
        case VMI_OS_WINDOWS_10:
            trap->cb = ( w->s->pm == VMI_PM_IA32E ) ? udpa_win10_x64_ret_cb : NULL;
            break;
    };

    if ( !drakvuf_add_trap(drakvuf, trap) )
        printf("Failed to trap return at 0x%lx\n", rsp);

    return 0;
}

/* ----------------------------------------------------- */

static void print_dns_info(drakvuf_t drakvuf, drakvuf_trap_info_t* info, socketmon* sm, const char* function_name, const char* dns_name)
{
    switch (sm->format)
    {
        case OUTPUT_CSV:
            printf("socketmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",\"%s\",\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3,
                   info->proc_data.name, dns_name, function_name);
            break;

        case OUTPUT_KV:
            printf("socketmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",DnsName=\"%s\",Method=\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid,
                   info->proc_data.name, dns_name, function_name);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[SOCKETMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" DNS_NAME:\"%s\" METHOD:\"%s\"\n",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   dns_name, function_name);
            break;
    };
}

static event_response_t trap_DnsQuery_A_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* sm = (socketmon*)info->trap->data;

    addr_t domain_name_addr = 0;

    if (sm->pm == VMI_PM_IA32E) // only 64 bit for now
    {
        domain_name_addr = info->regs->rcx;

        access_context_t ctx;
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = domain_name_addr;

        char* dns_name = [&]
        {
            vmi_lock_guard vmi_lg(drakvuf);
            return vmi_read_str(vmi_lg.vmi, &ctx);
        }();
        print_dns_info(drakvuf, info, sm, info->trap->name, dns_name);
        g_free(dns_name);
    }
    else
    {
        PRINT_DEBUG("[SOCKETMON] Suddenly, we are in 32 bit mode in %s(...) trap. Unsupported.\n", info->trap->name);
    }

    return 0;
}


static event_response_t trap_DnsQuery_W_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* sm = (socketmon*)info->trap->data;

    addr_t domain_name_addr = 0;
    unicode_string_t* domain_name_us = nullptr;

    if (sm->pm == VMI_PM_IA32E) // only 64 bit for now
    {
        domain_name_addr = info->regs->rcx;

        access_context_t ctx;
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = domain_name_addr;

        {
            vmi_lock_guard vmi_lg(drakvuf);
            domain_name_us = drakvuf_read_wchar_string(vmi_lg.vmi, &ctx);
        }

        if (domain_name_us)
        {
            print_dns_info(drakvuf, info, sm, info->trap->name, (char*)domain_name_us->contents);
        }
        else
        {
            PRINT_DEBUG("[SOCKETMON] Error, getting unicode domain name string in %s()", __FUNCTION__);
        }
        vmi_free_unicode_str(domain_name_us);
    }
    else
    {
        PRINT_DEBUG("[SOCKETMON] Suddenly, we are in 32 bit mode in %s(...) trap. Unsupported.\n", info->trap->name);
    }


    return 0;
}

// Works on Windows 7
static event_response_t trap_DnsQueryExW_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* sm = (socketmon*)info->trap->data;

    if (sm->pm != VMI_PM_IA32E) // only 64 bit for now
    {
        PRINT_DEBUG("[SOCKETMON] Suddenly, we are in 32 bit mode in %s(...) trap. Unsupported.\n", info->trap->name);
        return 0;
    }

    unicode_string_t* domain_name_us = drakvuf_read_unicode(drakvuf, info, info->regs->rcx);

    if (domain_name_us)
    {
        print_dns_info(drakvuf, info, sm, info->trap->name, (char*)domain_name_us->contents);
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

    addr_t domain_name_addr = 0;

    if (sm->pm == VMI_PM_IA32E) // only 64 bit for now
    {
        domain_name_addr = info->regs->rcx;

        access_context_t ctx;
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = domain_name_addr;

        char* dns_name = [&]
        {
            vmi_lock_guard vmi_lg(drakvuf);
            return vmi_read_str(vmi_lg.vmi, &ctx);
        }();

        print_dns_info(drakvuf, info, sm, info->trap->name, dns_name);
        g_free(dns_name);
    }
    else
    {
        PRINT_DEBUG("[SOCKETMON] Suddenly, we are in 32 bit mode in %s(...) trap. Unsupported.\n", info->trap->name);
    }

    return 0;
}

// Works on Windows 8+
static event_response_t trap_DnsQueryEx_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* sm = (socketmon*)info->trap->data;

    unicode_string_t* domain_name_us = nullptr;

    if (sm->pm == VMI_PM_IA32E) // only 64 bit for now
    {
        addr_t query_request_addr = info->regs->rcx;
        addr_t query_name_addr = 0;

        access_context_t ctx;
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = query_request_addr + 8;

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
            print_dns_info(drakvuf, info, sm, info->trap->name, (const char*)domain_name_us->contents);
        }
        else
        {
            PRINT_DEBUG("[SOCKETMON] Error, getting unicode domain name string in %s()", __FUNCTION__);
        }
    }
    else
    {
        PRINT_DEBUG("[SOCKETMON] Suddenly, we are in 32 bit mode in %s(...) trap. Unsupported.\n", info->trap->name);
    }

    vmi_free_unicode_str(domain_name_us);

    return 0;
}

static int set_trap_universal(socketmon_trapinfo& ti, socketmon* f, drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    if (ti.already_set)
        return 0;

    drakvuf_trap_t& current_trap = ti.trap;
    auto response = 0;
    addr_t exec_func = 0;

    auto eprocess_base = drakvuf_get_current_process(drakvuf, info->vcpu);
    if ( 0 == eprocess_base )
    {
        PRINT_DEBUG("[SOCKETMON] Failed to get process base on vCPU 0x%d\n",
                    info->vcpu);
        goto err;
    }

    exec_func = drakvuf_exportsym_to_va(drakvuf, eprocess_base, ti.lib, ti.fun);
    if (!exec_func)
    {
        PRINT_DEBUG("[SOCKETMON] Failed to get address of %s!%s\n", ti.lib, ti.fun);
        goto err;
    }

    current_trap.type = BREAKPOINT;
    current_trap.name = ti.fun;
    current_trap.cb = ti.trap_callback;
    current_trap.data = info->trap->data;
    current_trap.breakpoint.lookup_type = LOOKUP_DTB;
    current_trap.breakpoint.dtb = info->regs->cr3;
    current_trap.breakpoint.addr_type = ADDR_VA;
    current_trap.breakpoint.addr = exec_func;

    if ( !drakvuf_add_trap(drakvuf, &current_trap) )
    {
        PRINT_DEBUG("[SOCKETMON] Failed to trap function call @ 0x%lx!\n",
                    current_trap.breakpoint.addr);
        return 0;
    }

    PRINT_DEBUG("[SOCKETMON] Set trap for %s:%s successfully\n", ti.lib, ti.fun);
    ti.already_set = true;

    return 1;

err:
    return response;
}

static event_response_t cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    socketmon* sm = (socketmon*)info->trap->data;

    const unsigned expected_number_of_traps = sm->traps.size();
    for (auto& ti : sm->traps)
    {
        sm->traps_set += set_trap_universal(ti, sm, drakvuf, info);
    }

    PRINT_DEBUG("[SOCKETMON] cr3_cb(...) traps_set=%d.\n", (int)sm->traps_set);

    // Unsubscribe from the CR3 trap
    if (sm->traps_set == expected_number_of_traps)
    {
        PRINT_DEBUG("[SOCKETMON] Set all traps, removing CR3 trap.\n");
        PRINT_DEBUG("[SOCKETMON] TIME:" FORMAT_TIMEVAL "\n", UNPACK_TIMEVAL(info->timestamp) );

        drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);
    }

    return 0;
}


socketmon::socketmon(drakvuf_t drakvuf, const void* config, output_format_t output)
{
    const struct socketmon_config* c = (const struct socketmon_config*)config;
    const char* tcpip_profile = c->tcpip_profile;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->pm = vmi_get_page_mode(vmi, 0);
    this->winver = vmi_get_winver(vmi);
    drakvuf_release_vmi(drakvuf);
    this->format = output;

    if (pm == VMI_PM_IA32E)
    {
        traps.emplace_back("dnsapi.dll", "DnsQuery_W", trap_DnsQuery_W_cb);
        traps.emplace_back("dnsapi.dll", "DnsQuery_A", trap_DnsQuery_A_cb);
        traps.emplace_back("dnsapi.dll", "DnsQuery_UTF8", trap_DnsQuery_A_cb); // intentionally trap_DnsQuery_A_cb

        if (this->winver == VMI_OS_WINDOWS_7)
        {
            traps.emplace_back( "dnsapi.dll", "DnsQueryExW", trap_DnsQueryExW_cb );
            traps.emplace_back( "dnsapi.dll", "DnsQueryExA", trap_DnsQueryExA_cb );
        }

        if (this->winver >= VMI_OS_WINDOWS_8)
        {
            traps.emplace_back( "dnsapi.dll", "DnsQueryEx", trap_DnsQueryEx_cb );
        }
    }

    // Will be freed while "drakvuf_remove_trap()"
    drakvuf_trap_t* bp = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    if (!bp)
        throw -1;

    bp->type = REGISTER;
    bp->reg = CR3;
    bp->cb = cr3_cb;
    bp->data = this;
    if ( !drakvuf_add_trap(drakvuf, bp) )
        throw -1;

    if ( !tcpip_profile )
    {
        PRINT_DEBUG("Socketmon plugin requires the Rekall profile for tcpip.sys!\n");
        return;
    }

    if ( this->winver == VMI_OS_WINDOWS_10 && this->pm != VMI_PM_IA32E )
    {
        PRINT_DEBUG("Socketmon plugin not supported on 32-bit Windows 10\n");
        throw -1;
    }

    if ( this->pm == VMI_PM_IA32E )
    {
        switch (this->winver)
        {
            case VMI_OS_WINDOWS_10:
                this->trap[0].cb = tcpe_win10_x64_cb;
                this->trap[1].cb = tcpe_win10_x64_cb;
                this->trap[2].cb = tcpe_win10_x64_cb;
                this->trap[3].cb = tcpe_win10_x64_cb;
                this->trap[4].cb = tcpe_win10_x64_cb;
                break;
            default:
            case VMI_OS_WINDOWS_7:
                this->trap[0].cb = tcpe_x64_cb;
                this->trap[1].cb = tcpe_x64_cb;
                this->trap[2].cb = tcpe_x64_cb;
                this->trap[3].cb = tcpe_x64_cb;
                this->trap[4].cb = tcpe_x64_cb;
                break;
        };
    }
    else
    {
        this->trap[0].cb = tcpe_x86_cb;
        this->trap[1].cb = tcpe_x86_cb;
        this->trap[2].cb = tcpe_x86_cb;
        this->trap[3].cb = tcpe_x86_cb;
        this->trap[4].cb = tcpe_x86_cb;
    }

    this->trap[5].cb = udpb_cb;
    this->trap[6].cb = tcpl_cb;

    if ( !drakvuf_get_function_rva(tcpip_profile, "TcpTcbDelay", &this->trap[0].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(tcpip_profile, "TcpFinAcknowledged", &this->trap[1].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(tcpip_profile, "TcpDisconnectTcb", &this->trap[2].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(tcpip_profile, "TcpShutdownTcb", &this->trap[3].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(tcpip_profile, "TcpSetSockOptTcb", &this->trap[4].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(tcpip_profile, "UdpSetSockOptEndpoint", &this->trap[5].breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_function_rva(tcpip_profile, "TcpCreateListenerWorkQueueRoutine", &this->trap[6].breakpoint.rva) )
        throw -1;

    if ( !drakvuf_add_trap(drakvuf, &this->trap[0]) )
        throw -1;
    if ( !drakvuf_add_trap(drakvuf, &this->trap[1]) )
        throw -1;
    if ( !drakvuf_add_trap(drakvuf, &this->trap[2]) )
        throw -1;
    if ( !drakvuf_add_trap(drakvuf, &this->trap[3]) )
        throw -1;
    if ( !drakvuf_add_trap(drakvuf, &this->trap[4]) )
        throw -1;
    if ( !drakvuf_add_trap(drakvuf, &this->trap[5]) )
        throw -1;
    if ( !drakvuf_add_trap(drakvuf, &this->trap[6]) )
        throw -1;

    PRINT_DEBUG("[SOCKETMON] Socketmon constructor end.\n");

}

socketmon::~socketmon()
{
}
