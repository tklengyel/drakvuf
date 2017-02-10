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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <byteswap.h>

#include <libvmi/libvmi.h>
#include "plugins/plugins.h"
#include "private.h"
#include "socketmon.h"

#define POOLTAG_TCPE "TcpE"
#define POOLTAG_TCPL "TcpL"
#define POOLTAG_UDPA "UdpA"

#define ALIGN_SIZE(alignment, size) \
    ( (size % alignment) ? (alignment - (size % alignment)) : 0 )

struct rettrap_struct {
    socketmon *s;
    drakvuf_trap_t *trap;
    unsigned long counter;
};

struct watch {
    socketmon *s;
    addr_t obj_base;
    addr_t obj_base_pa;
};

static void free_writetrap(drakvuf_trap_t *trap) {
    //printf("Freeing writetrap @ %p\n", trap);
    struct watch *watch = (struct watch *)trap->data;
    socketmon *s = watch->s;
    s->writetraps = g_slist_remove(s->writetraps, trap);
    g_free(trap);
    g_free(watch);
}

static inline void ipv4_to_str(char **str, uint8_t ipv4[4])
{
    *str = (char *)g_malloc0(snprintf(NULL, 0, "%u.%u.%u.%u",
                             ipv4[0], ipv4[1], ipv4[2], ipv4[3]) + 1);
    if ( !str )
        return;

    sprintf(*str, "%u.%u.%u.%u", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
}

static inline void ipv6_to_str(char **str, uint8_t ipv6[16])
{
    *str = (char*)g_malloc0(snprintf(NULL, 0,
                    "%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
                     ipv6[0], ipv6[1], ipv6[2], ipv6[3],
                     ipv6[4], ipv6[5], ipv6[6], ipv6[7],
                     ipv6[8], ipv6[9], ipv6[10], ipv6[11],
                     ipv6[12], ipv6[13], ipv6[14], ipv6[15]) + 1);

    if ( !str )
        return;

   sprintf(*str,
           "%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
           ipv6[0], ipv6[1], ipv6[2], ipv6[3],
           ipv6[4], ipv6[5], ipv6[6], ipv6[7],
           ipv6[8], ipv6[9], ipv6[10], ipv6[11],
           ipv6[12], ipv6[13], ipv6[14], ipv6[15]);
}

static event_response_t udpa_x86_write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    int64_t ownerid = 0;
    addr_t p1 = 0;
    char *lip = NULL, *owner = NULL;
    struct watch *watch = (struct watch *)info->trap->data;
    socketmon *s = watch->s;

    if (info->trap_pa != watch->obj_base + offsetof(struct udp_endpoint_x86, port))
        return 0;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    struct udp_endpoint_x86 udpa;
    struct inetaf_x86 inetaf;
    struct local_address_x86 local;
    memset(&udpa, 0, sizeof(struct udp_endpoint_x86));
    memset(&inetaf, 0, sizeof(struct inetaf_x86));
    memset(&local, 0, sizeof(local_address_x86));

    if ( sizeof(struct udp_endpoint_x86) != vmi_read_pa(vmi, watch->obj_base, &udpa, sizeof(struct udp_endpoint_x86)) )
        goto done;

    /* Convert port to little endian */
    udpa.port = __bswap_16(udpa.port);

    if ( !udpa.port )
        goto done;

    ctx.addr = udpa.inetaf;
    if ( sizeof(struct inetaf_x86) != vmi_read(vmi, &ctx, &inetaf, sizeof(struct inetaf_x86)) )
        goto done;

    ctx.addr = udpa.localaddr;
    if ( sizeof(struct local_address_x86) != vmi_read(vmi, &ctx, &local, sizeof(struct local_address_x86)) )
        goto done;

    ctx.addr = local.pdata;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
        goto done;

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};

        ctx.addr = p1;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
            goto done;

        ipv4_to_str(&lip, localip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};

        ctx.addr = p1;
        if ( 16 != vmi_read(vmi, &ctx, &localip[0], 16) )
            goto done;

        ipv6_to_str(&lip, localip);
    }
    else
    {
        drakvuf_remove_trap(drakvuf, info->trap, free_writetrap);
        goto done;
    }

    owner = drakvuf_get_process_name(drakvuf, udpa.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, udpa.owner);

    switch(s->format) {
    case OUTPUT_CSV:
        printf("socketmon,%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64",%s,%" PRIi64 ",%s,%s,%u\n",
               info->vcpu, info->regs->cr3,
               info->procname, info->userid,
               owner, ownerid,
               (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
               lip, udpa.port);
        break;
    default:
    case OUTPUT_DEFAULT:
        printf("[SOCKETMON] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s %s:%u\n",
               info->vcpu, info->regs->cr3, info->procname,
               USERIDSTR(drakvuf), info->userid,
               owner, USERIDSTR(drakvuf), ownerid,
               (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
               lip, udpa.port);
        break;
    };

done:
    g_free(owner);
    g_free(lip);
    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t udpa_x64_write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    int64_t ownerid = 0;
    addr_t p1 = 0;
    char *lip = NULL, *owner = NULL;
    struct watch *watch = (struct watch *)info->trap->data;
    socketmon *s = watch->s;

    if (info->trap_pa != watch->obj_base + offsetof(struct udp_endpoint_x64, port))
        return 0;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    struct udp_endpoint_x64 udpa;
    struct inetaf_x64 inetaf;
    struct local_address_x64 local;
    memset(&udpa, 0, sizeof(struct udp_endpoint_x64));
    memset(&inetaf, 0, sizeof(struct inetaf_x64));
    memset(&local, 0, sizeof(local_address_x64));

    if ( sizeof(struct udp_endpoint_x64) != vmi_read_pa(vmi, watch->obj_base, &udpa, sizeof(struct udp_endpoint_x64)) )
        goto done;

    /* Convert port to little endian */
    udpa.port = __bswap_16(udpa.port);

    if ( !udpa.port )
        goto done;

    ctx.addr = udpa.inetaf;
    if ( sizeof(struct inetaf_x64) != vmi_read(vmi, &ctx, &inetaf, sizeof(struct inetaf_x64)) )
        goto done;

    ctx.addr = udpa.localaddr;
    if ( sizeof(struct local_address_x64) != vmi_read(vmi, &ctx, &local, sizeof(struct local_address_x64)) )
        goto done;

    ctx.addr = local.pdata;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
        goto done;

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};

        ctx.addr = p1;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
            goto done;

        ipv4_to_str(&lip, localip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};

        ctx.addr = p1;
        if ( 16 != vmi_read(vmi, &ctx, &localip[0], 16) )
            goto done;

        ipv6_to_str(&lip, localip);
    }
    else
    {
        drakvuf_remove_trap(drakvuf, info->trap, free_writetrap);
        goto done;
    }

    owner = drakvuf_get_process_name(drakvuf, udpa.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, udpa.owner);

    switch(s->format) {
    case OUTPUT_CSV:
        printf("socketmon,%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64",%s,%" PRIi64",%s,%s,%u\n",
               info->vcpu, info->regs->cr3,
               info->procname, info->userid,
               owner, ownerid,
               (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
               lip, udpa.port);
        break;
    default:
    case OUTPUT_DEFAULT:
        printf("[SOCKETMON] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s %s:%u\n",
               info->vcpu, info->regs->cr3, info->procname,
               USERIDSTR(drakvuf), info->userid,
               owner, USERIDSTR(drakvuf), ownerid,
               (inetaf.addressfamily == AF_INET) ? "UDPv4" : "UDPv6",
               lip, udpa.port);
        break;
    };

done:
    g_free(owner);
    g_free(lip);
    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t tcpe_x86_write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    struct watch *watch = (struct watch *)info->trap->data;
    socketmon *s = watch->s;

    if (info->trap_pa != watch->obj_base + offsetof(struct tcp_endpoint_x86, state) )
        return 0;

    int64_t ownerid = -1;
    addr_t p1 = 0;
    char *lip = NULL, *rip = NULL, *owner=NULL;
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
    if ( sizeof(struct tcp_endpoint_x86) != vmi_read_pa(vmi, watch->obj_base, &tcpe, sizeof(struct tcp_endpoint_x86)) )
        goto done;

    if ( tcpe.state >= __TCP_STATE_MAX )
        goto done;

    /* Convert ports to little endian */
    tcpe.localport = __bswap_16(tcpe.localport);
    tcpe.remoteport = __bswap_16(tcpe.remoteport);

    ctx.addr = tcpe.inetaf;
    if ( sizeof(struct inetaf_x86) != vmi_read(vmi, &ctx, &inetaf, sizeof(struct inetaf_x86)) )
        goto done;

    ctx.addr = tcpe.addrinfo;
    if ( sizeof(struct addr_info_x86) != vmi_read(vmi, &ctx, &addrinfo, sizeof(struct addr_info_x86)) )
        goto done;

    ctx.addr = addrinfo.local;
    if ( sizeof(struct local_address_x86) != vmi_read(vmi, &ctx, &local, sizeof(struct local_address_x86)) )
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
        if ( 16 != vmi_read(vmi, &ctx, &localip[0], 16) )
            goto done;

        ctx.addr = addrinfo.remote;
        if ( 16 != vmi_read(vmi, &ctx, &remoteip[0], 16) )
            goto done;

        ipv6_to_str(&lip, localip);
        ipv6_to_str(&rip, remoteip);
    }

    owner = drakvuf_get_process_name(drakvuf, tcpe.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, tcpe.owner);

    switch(s->format) {
    case OUTPUT_CSV:
        printf("socketmon,%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64 ",%s,%" PRIi64 ",%s,%s,%s,%u,%s,%u\n",
               info->vcpu, info->regs->cr3,
               info->procname, info->userid,
               owner,ownerid,
               (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
               tcp_state_str[tcpe.state],
               lip, tcpe.localport, rip, tcpe.remoteport);
        break;
    default:
    case OUTPUT_DEFAULT:
        printf("[SOCKETMON] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s State:%s Local:%s:%u Remote:%s:%u\n",
               info->vcpu, info->regs->cr3,
               info->procname, USERIDSTR(drakvuf), info->userid,
               owner, USERIDSTR(drakvuf), ownerid,
               (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
               tcp_state_str[tcpe.state],
               lip, tcpe.localport, rip, tcpe.remoteport);
        break;
    };

    if ( !tcpe.state )
        drakvuf_remove_trap(drakvuf, info->trap, free_writetrap);

done:
    g_free(lip);
    g_free(rip);
    drakvuf_release_vmi(drakvuf);

    return 0;
}

static event_response_t tcpe_x64_write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    struct watch *watch = (struct watch *)info->trap->data;
    socketmon *s = watch->s;

    if (info->trap_pa != watch->obj_base + offsetof(struct tcp_endpoint_x64, state) )
        return 0;

    int64_t ownerid;
    addr_t p1 = 0;
    char *lip = NULL, *rip = NULL, *owner = NULL;
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
    if ( sizeof(struct tcp_endpoint_x64) != vmi_read_pa(vmi, watch->obj_base, &tcpe, sizeof(struct tcp_endpoint_x64)) )
        goto done;

    if ( tcpe.state >= __TCP_STATE_MAX )
        goto done;

    /* Convert ports to little endian */
    tcpe.localport = __bswap_16(tcpe.localport);
    tcpe.remoteport = __bswap_16(tcpe.remoteport);

    ctx.addr = tcpe.inetaf;
    if ( sizeof(struct inetaf_x64) != vmi_read(vmi, &ctx, &inetaf, sizeof(struct inetaf_x64)) )
        goto done;

    ctx.addr = tcpe.addrinfo;
    if ( sizeof(struct addr_info_x64) != vmi_read(vmi, &ctx, &addrinfo, sizeof(struct addr_info_x64)) )
        goto done;

    ctx.addr = addrinfo.local;
    if ( sizeof(struct local_address_x64) != vmi_read(vmi, &ctx, &local, sizeof(struct local_address_x64)) )
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
        if ( 16 != vmi_read(vmi, &ctx, &localip[0], 16) )
            goto done;

        ctx.addr = addrinfo.remote;
        if ( 16 != vmi_read(vmi, &ctx, &remoteip[0], 16) )
            goto done;

        ipv6_to_str(&lip, localip);
        ipv6_to_str(&rip, remoteip);
    }

    owner = drakvuf_get_process_name(drakvuf, tcpe.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, tcpe.owner);

    switch(s->format) {
    case OUTPUT_CSV:
        printf("socketmon,%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64 ",%s,%" PRIi64 ",%s,%s,%s,%u,%s,%u\n",
               info->vcpu, info->regs->cr3,
               info->procname, info->userid,
               owner,ownerid,
               (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
               tcp_state_str[tcpe.state],
               lip, tcpe.localport, rip, tcpe.remoteport);
        break;
    default:
    case OUTPUT_DEFAULT:
        printf("[SOCKETMON] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s State:%s Local:%s:%u Remote:%s:%u\n",
               info->vcpu, info->regs->cr3,
               info->procname, USERIDSTR(drakvuf), info->userid,
               owner, USERIDSTR(drakvuf), ownerid,
               (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
               tcp_state_str[tcpe.state],
               lip, tcpe.localport, rip, tcpe.remoteport);
        break;
    };

    if ( !tcpe.state )
        drakvuf_remove_trap(drakvuf, info->trap, free_writetrap);

done:
    g_free(owner);
    g_free(lip);
    g_free(rip);
    drakvuf_release_vmi(drakvuf);

    return 0;
}

static event_response_t tcpl_x86_write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    struct watch *watch = (struct watch *)info->trap->data;
    socketmon *s = watch->s;

    if (info->trap_pa != watch->obj_base + offsetof(struct tcp_listener_x86, port) )
        return 0;

    int64_t ownerid = 0;
    addr_t p1 = 0;
    char *lip = NULL, *owner = NULL;
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    struct tcp_listener_x86 tcpl;
    struct inetaf_x86 inetaf;
    struct local_address_x86 local;
    memset(&tcpl, 0, sizeof(struct tcp_listener_x86));
    memset(&inetaf, 0, sizeof(struct inetaf_x86));
    memset(&local, 0, sizeof(local_address_x86));

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    if ( sizeof(struct tcp_listener_x86) != vmi_read_pa(vmi, watch->obj_base, &tcpl, sizeof(struct tcp_listener_x86)) )
        goto done;

    /* Convert port to little endian */
    tcpl.port = __bswap_16(tcpl.port);

    ctx.addr = tcpl.inetaf;
    if ( sizeof(struct inetaf_x86) != vmi_read(vmi, &ctx, &inetaf, sizeof(struct inetaf_x86)) )
        goto done;

    ctx.addr = tcpl.localaddr;
    if ( sizeof(struct local_address_x86) != vmi_read(vmi, &ctx, &local, sizeof(struct local_address_x86)) )
        goto done;

    ctx.addr = local.pdata;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
        goto done;

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};

        ctx.addr = p1;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
            goto done;

        ipv4_to_str(&lip, localip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};

        ctx.addr = p1;
        if ( 16 != vmi_read(vmi, &ctx, &localip[0], 16) )
            goto done;

        ipv6_to_str(&lip, localip);
    }

    owner = drakvuf_get_process_name(drakvuf, tcpl.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, tcpl.owner);

    switch(s->format) {
    case OUTPUT_CSV:
        printf("socketmon,%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64",%s,%" PRIi64 ",%s,listener,%s,%u\n",
               info->vcpu, info->regs->cr3,
               info->procname, info->userid,
               owner, ownerid,
               (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
               lip, tcpl.port);
        break;
    default:
    case OUTPUT_DEFAULT:
        printf("[SOCKETMON] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s listener %s:%u\n",
               info->vcpu, info->regs->cr3, info->procname,
               USERIDSTR(drakvuf), info->userid,
               owner, USERIDSTR(drakvuf), ownerid,
               (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
               lip, tcpl.port);
        break;
    };

done:
    g_free(owner);
    g_free(lip);
    drakvuf_release_vmi(drakvuf);

    return 0;
}

static event_response_t tcpl_x64_write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    struct watch *watch = (struct watch *)info->trap->data;
    socketmon *s = watch->s;

    if (info->trap_pa != watch->obj_base + offsetof(struct tcp_listener_x64, port) )
        return 0;

    int64_t ownerid = 0;
    addr_t p1 = 0;
    char *lip = NULL, *owner = NULL;
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
    if ( sizeof(struct tcp_listener_x64) != vmi_read_pa(vmi, watch->obj_base, &tcpl, sizeof(struct tcp_listener_x64)) )
        goto done;

    /* Convert port to little endian */
    tcpl.port = __bswap_16(tcpl.port);

    ctx.addr = tcpl.inetaf;
    if ( sizeof(struct inetaf_x64) != vmi_read(vmi, &ctx, &inetaf, sizeof(struct inetaf_x64)) )
        goto done;

    ctx.addr = tcpl.localaddr;
    if ( sizeof(struct local_address_x64) != vmi_read(vmi, &ctx, &local, sizeof(struct local_address_x64)) )
        goto done;

    ctx.addr = local.pdata;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &p1) )
        goto done;

    if ( inetaf.addressfamily == AF_INET )
    {
        uint8_t localip[4]  = {[0 ... 3] = 0};

        ctx.addr = p1;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&localip[0]) )
            goto done;

        ipv4_to_str(&lip, localip);
    }
    else if (inetaf.addressfamily == AF_INET6 )
    {
        uint8_t localip[16]  = {[0 ... 15] = 0};

        ctx.addr = p1;
        if ( 16 != vmi_read(vmi, &ctx, &localip[0], 16) )
            goto done;

        ipv6_to_str(&lip, localip);
    }

    owner = drakvuf_get_process_name(drakvuf, tcpl.owner);
    ownerid = drakvuf_get_process_userid(drakvuf, tcpl.owner);

    switch(s->format) {
    case OUTPUT_CSV:
        printf("socketmon,%" PRIu32 ",0x%" PRIx64 ",%s,%" PRIi64 ",%s,%" PRIi64 ",%s,listener,%s,%u\n",
               info->vcpu, info->regs->cr3,
               info->procname, info->userid,
               owner, ownerid,
               (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
               lip, tcpl.port);
        break;
    default:
    case OUTPUT_DEFAULT:
        printf("[SOCKETMON] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s:%" PRIi64 " Owner:%s %s:%" PRIi64 " %s listener %s:%u\n",
               info->vcpu, info->regs->cr3, info->procname,
               USERIDSTR(drakvuf), info->userid,
               owner, USERIDSTR(drakvuf), ownerid,
               (inetaf.addressfamily == AF_INET) ? "TCPv4" : "TCPv6",
               lip, tcpl.port);
        break;
    };

done:
    g_free(owner);
    g_free(lip);
    drakvuf_release_vmi(drakvuf);

    return 0;
}

static inline void tag_test(void *tag, bool *tcpe_alloc, bool *tcpl_alloc, bool *udpa_alloc)
{
    if(!memcmp(tag, &POOLTAG_TCPE, 4))
    {
        *tcpe_alloc = 1;
        return;
    }

    if(!memcmp(tag, &POOLTAG_TCPL, 4))
    {
        *tcpl_alloc = 1;
        return;
    }

    if(!memcmp(tag, &POOLTAG_UDPA, 4))
    {
        *udpa_alloc = 1;
        return;
    }
}

/* This will be hit for all sorts of heap alloc returns */
static event_response_t pool_alloc_return(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    struct rettrap_struct *r = (struct rettrap_struct *)info->trap->data;
    socketmon *s = r->s;
    addr_t obj_pa = vmi_pagetable_lookup(vmi, info->regs->cr3, info->regs->rax);
    bool tcpe_alloc = 0;
    bool tcpl_alloc = 0;
    bool udpa_alloc = 0;

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    if ( s->pm == VMI_PM_IA32E ) {
        addr_t ph_base = obj_pa - sizeof(struct pool_header_x64);
        struct pool_header_x64 ph;
        memset(&ph, 0, sizeof(struct pool_header_x64));

        if ( sizeof(struct pool_header_x64) != vmi_read_pa(vmi, ph_base, &ph, sizeof(struct pool_header_x64)) )
            goto done;

        tag_test(&ph.pool_tag, &tcpe_alloc, &tcpl_alloc, &udpa_alloc);
    } else {
        addr_t ph_base = obj_pa - sizeof(struct pool_header_x86);
        struct pool_header_x86 ph;
        memset(&ph, 0, sizeof(struct pool_header_x86));

        if ( sizeof(struct pool_header_x86) != vmi_read_pa(vmi, ph_base, &ph, sizeof(struct pool_header_x86)) )
            goto done;

        tag_test(&ph.pool_tag, &tcpe_alloc, &tcpl_alloc, &udpa_alloc);
    }

    if (!tcpe_alloc && !tcpl_alloc && !udpa_alloc)
        goto done;

    /*
     * Normal pool allocations would have to be aligned based on the top of the
     * block size, but since our struct definitions aren't based on the info
     * in the Rekall profile, we can just use the base allocation address.
     */

    if ( tcpe_alloc )
    {
        struct watch *watch = (struct watch *)g_malloc0(sizeof(struct watch));
        if ( !watch )
            goto done;

        watch->s = s;
        watch->obj_base = obj_pa;

        drakvuf_trap_t *writetrap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
        writetrap->memaccess.access = VMI_MEMACCESS_W;
        writetrap->memaccess.type = POST;
        writetrap->memaccess.gfn = obj_pa >> 12;
        writetrap->cb = (s->pm == VMI_PM_IA32E) ? tcpe_x64_write_cb : tcpe_x86_write_cb;
        writetrap->data = watch;
        writetrap->type = MEMACCESS;

        if (!drakvuf_add_trap(drakvuf, writetrap))
        {
            fprintf(stderr, "[SOCKETMON] Error: failed to add write memaccess trap!\n");
            g_free(writetrap);
            g_free(watch);
            goto done;
        }

        s->writetraps = g_slist_prepend(s->writetraps, writetrap);
        goto done;
    }

    if ( tcpl_alloc )
    {
        struct watch *watch = (struct watch *)g_malloc0(sizeof(struct watch));
        if ( !watch )
            goto done;

        watch->s = s;
        watch->obj_base = obj_pa;

        drakvuf_trap_t *writetrap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
        writetrap->memaccess.access = VMI_MEMACCESS_W;
        writetrap->memaccess.type = POST;
        writetrap->memaccess.gfn = obj_pa >> 12;
        writetrap->cb = (s->pm == VMI_PM_IA32E) ? tcpl_x64_write_cb : tcpl_x86_write_cb;
        writetrap->data = watch;
        writetrap->type = MEMACCESS;

        if (!drakvuf_add_trap(drakvuf, writetrap))
        {
            fprintf(stderr, "[SOCKETMON] Error: failed to add write memaccess trap!\n");
            g_free(writetrap);
            g_free(watch);
            goto done;
        }

        s->writetraps = g_slist_prepend(s->writetraps, writetrap);
        goto done;
    }

    if ( udpa_alloc )
    {
        struct watch *watch = (struct watch *)g_malloc0(sizeof(struct watch));
        if ( !watch )
            goto done;

        watch->s = s;
        watch->obj_base = obj_pa;

        drakvuf_trap_t *writetrap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
        if ( !writetrap )
        {
            g_free(watch);
            goto done;
        }

        writetrap->memaccess.access = VMI_MEMACCESS_W;
        writetrap->memaccess.type = POST;
        writetrap->memaccess.gfn = obj_pa >> 12;
        writetrap->cb = (s->pm == VMI_PM_IA32E) ? udpa_x64_write_cb: udpa_x86_write_cb;
        writetrap->data = watch;
        writetrap->type = MEMACCESS;

        if (!drakvuf_add_trap(drakvuf, writetrap))
        {
            fprintf(stderr, "[SOCKETMON] Error: failed to add write memaccess trap!\n");
            g_free(writetrap);
            g_free(watch);
            goto done;
        }

        s->writetraps = g_slist_prepend(s->writetraps, writetrap);
        goto done;
    }

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {

    socketmon *s = (socketmon*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    reg_t tag = 0, size = 0;
    bool tcpe_alloc = 0;
    bool tcpl_alloc = 0;
    bool udpa_alloc = 0;

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    if (s->pm == VMI_PM_IA32E) {
        size = info->regs->rdx;
        tag = info->regs->r8;
    } else {
        ctx.addr = info->regs->rsp+8;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&size) )
            goto done;

        ctx.addr = info->regs->rsp+12;
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&tag) )
            goto done;
    }

    tag_test(&tag, &tcpe_alloc, &tcpl_alloc, &udpa_alloc);

    if(tcpe_alloc || tcpl_alloc || udpa_alloc) {

        addr_t ret = 0, ret_pa = 0;
        ctx.addr = info->regs->rsp;
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ret) )
            goto done;

        ret_pa = vmi_pagetable_lookup(vmi, info->regs->cr3, ret);

        struct rettrap_struct *r = (struct rettrap_struct*)g_hash_table_lookup(s->rettraps, &ret_pa);
        if (r) {
            r->counter++;
        } else {
            drakvuf_trap_t *rettrap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
            r = (struct rettrap_struct*)g_malloc0(sizeof(struct rettrap_struct));
            if ( !r )
                goto  done;

            r->trap = rettrap;
            r->counter = 1;
            r->s = s;

            rettrap->breakpoint.lookup_type = LOOKUP_NONE;
            rettrap->breakpoint.addr_type = ADDR_PA;
            rettrap->breakpoint.addr = ret_pa;
            rettrap->type = BREAKPOINT;
            rettrap->name = "HeapRetTrap";
            rettrap->cb = pool_alloc_return;
            rettrap->data = r;

            if (!drakvuf_add_trap(drakvuf, rettrap))
                goto done;

            g_hash_table_insert(s->rettraps, &rettrap->breakpoint.addr, r);
        }
    }

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

/* ----------------------------------------------------- */

socketmon::socketmon(drakvuf_t drakvuf, const void* config, output_format_t output) {
    const char *rekall_profile = (const char *)config;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->pm = vmi_get_page_mode(vmi);
    drakvuf_release_vmi(drakvuf);
    this->rettraps = g_hash_table_new(g_int64_hash, g_int64_equal);
    this->format = output;
    this->writetraps = NULL;

    this->poolalloc.breakpoint.lookup_type = LOOKUP_PID;
    this->poolalloc.breakpoint.pid = 4;
    this->poolalloc.breakpoint.addr_type = ADDR_RVA;
    this->poolalloc.breakpoint.module = "ntoskrnl.exe";
    this->poolalloc.name = "ExAllocatePoolWithTag";
    this->poolalloc.type = BREAKPOINT;
    this->poolalloc.cb = cb;
    this->poolalloc.data = (void*)this;

    if (VMI_FAILURE == drakvuf_get_function_rva(rekall_profile, "ExAllocatePoolWithTag", &this->poolalloc.breakpoint.rva))
        throw -1;

    if ( !drakvuf_add_trap(drakvuf, &this->poolalloc) )
        throw -1;
}

socketmon::~socketmon() {

    GSList *loop = this->writetraps;
    while(loop) {
        g_free(loop->data);
        loop=loop->next;
    }
    g_slist_free(this->writetraps);

    if ( this->rettraps )
        g_hash_table_destroy(this->rettraps);
}
