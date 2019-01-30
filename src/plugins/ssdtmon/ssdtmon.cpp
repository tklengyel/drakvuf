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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
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

#include <libvmi/libvmi.h>
#include "../plugins.h"
#include "private.h"
#include "ssdtmon.h"

event_response_t write_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    char * escaped_pname = NULL;
    ssdtmon* s = (ssdtmon*)info->trap->data;

    if ( info->trap_pa > s->kiservicetable - 8 && info->trap_pa <= s->kiservicetable + s->ulongs * s->kiservicelimit + s->ulongs - 1 )
    {
        int64_t table_index = (info->trap_pa - s->kiservicetable) / s->ulongs;
        switch (s->format)
        {
            case OUTPUT_CSV:
                printf("ssdtmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ", %" PRIi64 "\n",
                       UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, table_index);
                break;

            case OUTPUT_KV:
                printf("ssdtmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",TableIndex=%" PRIi64 "\n",
                       UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name, table_index);
                break;

            case OUTPUT_JSON:
                escaped_pname = drakvuf_escape_str(info->proc_data.name);
                printf( "{"
                        "\"Plugin\" : \"ssdtmon\","
                        "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                        "\"ProcessName\": \"%s\","
                        "\"UserName\": \"%s\","
                        "\"UserId\": %" PRIu64 ","
                        "\"PID\" : %d,"
                        "\"PPID\": %d,"
                        "\"TableIndex\": %" PRIi64 ","
                        "}\n",
                        UNPACK_TIMEVAL(info->timestamp),
                        escaped_pname,
                        USERIDSTR(drakvuf), info->proc_data.userid,
                        info->proc_data.pid, info->proc_data.ppid,
                        table_index);
                g_free(escaped_pname);
                break;

            default:
            case OUTPUT_DEFAULT:
                printf("[SSDTMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64" Table index:%" PRIi64 "\n",
                       UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                       USERIDSTR(drakvuf), info->proc_data.userid, table_index);
                break;
        }
    }
    return 0;
}

/* ----------------------------------------------------- */

ssdtmon::ssdtmon(drakvuf_t drakvuf, const void* config, output_format_t output)
{
    addr_t kiservicetable_rva = 0, kiservicelimit_rva = 0;
    addr_t kernbase = 0;

    this->format = output;

    if ( !drakvuf_get_constant_rva(drakvuf, "KiServiceTable", &kiservicetable_rva) )
    {
        PRINT_DEBUG("SSDT plugin can't find KiServiceTable RVA\n");
        throw -1;
    }
    if ( !drakvuf_get_constant_rva(drakvuf, "KiServiceLimit", &kiservicelimit_rva) )
    {
        PRINT_DEBUG("SSDT plugin can't find KiServiceLimit RVA\n");
        throw -1;
    }

    kernbase = drakvuf_get_kernel_base(drakvuf);
    if ( !kernbase )
    {
        PRINT_DEBUG("SSDT plugin can't find kernel base address\n");
        throw -1;
    }

    page_mode_t pm = drakvuf_get_page_mode(drakvuf);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    if ( VMI_FAILURE == vmi_translate_kv2p(vmi, kernbase + kiservicetable_rva, &this->kiservicetable) )
        throw -1;

    vmi_read_32_va(vmi, kernbase + kiservicelimit_rva, 0, &this->kiservicelimit);
    drakvuf_release_vmi(drakvuf);

    if ( !this->kiservicetable )
    {
        PRINT_DEBUG("SSDT plugin can't find the physical address of KiServiceTable\n");
        throw -1;
    }
    if ( !this->kiservicelimit )
    {
        PRINT_DEBUG("SSDT plugin can't read the value of KiServiceLimit\n");
        throw -1;
    }

    this->ulongs = (pm == VMI_PM_IA32E) ? 8 : 4;

    PRINT_DEBUG("SSDT is at 0x%lx. Number of syscalls: %u. Size: %lu\n",
                this->kiservicetable,
                this->kiservicelimit,
                this->ulongs*this->kiservicelimit);

    this->ssdtwrite.cb = write_cb;
    this->ssdtwrite.data = (void*)this;
    this->ssdtwrite.type = MEMACCESS;
    this->ssdtwrite.memaccess.gfn = this->kiservicetable >> 12;
    this->ssdtwrite.memaccess.type = PRE;
    this->ssdtwrite.memaccess.access = VMI_MEMACCESS_W;

    addr_t ssdtwrite_end = (this->kiservicetable + this->ulongs * this->kiservicelimit) >> 12;

    if ( !drakvuf_add_trap(drakvuf, &this->ssdtwrite) )
    {
        PRINT_DEBUG("SSDT plugin failed to trap on \n");
        throw -1;
    }

    if ( ssdtwrite_end != this->ssdtwrite.memaccess.gfn )
    {
        this->ssdtwrite2 = this->ssdtwrite;
        this->ssdtwrite2.memaccess.gfn = ssdtwrite_end;

        if ( !drakvuf_add_trap(drakvuf, &this->ssdtwrite2) )
            throw -1;
    }
}

ssdtmon::~ssdtmon() {}
