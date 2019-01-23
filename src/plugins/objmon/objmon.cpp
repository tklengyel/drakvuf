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
#include "objmon.h"

/*
 NTKERNELAPI
 NTSTATUS
 ObCreateObject (
 IN KPROCESSOR_MODE ObjectAttributesAccessMode OPTIONAL,
 IN POBJECT_TYPE ObjectType,
 IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
 IN KPROCESSOR_MODE AccessMode,
 IN PVOID Reserved,
 IN ULONG ObjectSizeToAllocate,
 IN ULONG PagedPoolCharge OPTIONAL,
 IN ULONG NonPagedPoolCharge OPTIONAL,
 OUT PVOID *Object
 );
 */

struct ckey
{
    union
    {
        uint32_t key;
        char _key[4];
    };
};

static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    objmon* o = (objmon*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    struct ckey ckey = {};

    char * escaped_pname = NULL;
    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    if ( o->pm == VMI_PM_IA32E )
    {
        ctx.addr = info->regs->rdx;
    }
    else
    {
        ctx.addr = info->regs->rsp + sizeof(uint32_t)*2;
        vmi_read_32(vmi, &ctx, (uint32_t*)&ctx.addr);
    }

    ctx.addr += o->key_offset;

    vmi_read_32(vmi, &ctx, &ckey.key);

    switch (o->format)
    {
        case OUTPUT_CSV:
            printf("objmon," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",%c%c%c%c",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid,
                   ckey._key[0], ckey._key[1], ckey._key[2], ckey._key[3]);
            break;

        case OUTPUT_KV:
            printf("objmon Time=" FORMAT_TIMEVAL ",PID=%d,PPID=%d,ProcessName=\"%s\",Key=\"%c%c%c%c\"",
                   UNPACK_TIMEVAL(info->timestamp), info->proc_data.pid, info->proc_data.ppid, info->proc_data.name,
                   ckey._key[0], ckey._key[1], ckey._key[2], ckey._key[3]);
            break;

        case OUTPUT_JSON:
	    escaped_pname = drakvuf_escape_str(info->proc_data.name);
	    printf( "{"
		    "\"Plugin\" : \"objmon\","
		    "\"TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
		    "\"ProcessName\": \"%s\","
		    "\"UserId\": %" PRIu64 ","
		    "\"PID\" : %d,"
		    "\"PPID\": %d,"
		    "\"Key\" : \"%c%c%c%c\""
		    "}", // EOL below
		    UNPACK_TIMEVAL(info->timestamp),
		    escaped_pname,
		    info->proc_data.userid,
		    info->proc_data.pid, info->proc_data.ppid,
		    ckey._key[0], ckey._key[1], ckey._key[2], ckey._key[3]);
	    g_free(escaped_pname);
	    break;

        default:
        case OUTPUT_DEFAULT:
            printf("[OBJMON] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64" '%c%c%c%c'",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   ckey._key[0], ckey._key[1], ckey._key[2], ckey._key[3]);
            break;
    }

    printf("\n");

    drakvuf_release_vmi(drakvuf);
    return 0;
}

/* ----------------------------------------------------- */

objmon::objmon(drakvuf_t drakvuf, const void* config, output_format_t output)
{
    if ( !drakvuf_get_function_rva(drakvuf, "ObCreateObject", &this->trap.breakpoint.rva) )
        throw -1;
    if ( !drakvuf_get_struct_member_rva(drakvuf, "_OBJECT_TYPE", "Key", &this->key_offset) )
        throw -1;

    this->trap.cb = cb;
    this->pm = drakvuf_get_page_mode(drakvuf);

    this->format = output;
    if ( !drakvuf_add_trap(drakvuf, &this->trap) )
        throw -1;
}

objmon::~objmon() {}
