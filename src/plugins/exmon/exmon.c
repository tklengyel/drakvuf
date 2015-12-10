/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014-2015 Tamas K Lengyel.  *
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

#include <glib.h>
#include <libvmi/libvmi.h>
#include "private.h"
#include "../plugins.h"


// In case we'll need more APIs hooked, we keep a list handy
static GSList *traps;
static output_format_t format;

static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    char *str_format;
    page_mode_t pm = vmi_get_page_mode(vmi);
    uint8_t index = ~0;

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    if(pm != VMI_PM_IA32E){
        KTRAP_FRAME trap_frame;
        reg_t exception_record, ptrap_frame, exception_code;

        ctx.addr = info->regs->rsp+4;
        vmi_read_32(vmi, &ctx, (uint32_t*)&exception_record);
        ctx.addr = info->regs->rsp+12;
        vmi_read_32(vmi, &ctx, (uint32_t*)&ptrap_frame);
        ctx.addr = ptrap_frame;
        vmi_read(vmi,&ctx, &trap_frame,sizeof(KTRAP_FRAME));
        ctx.addr = exception_record;
        vmi_read_32(vmi, &ctx, (uint32_t*)&exception_code);
        switch(format) {
        case OUTPUT_CSV:
            str_format=CSV_FORMAT32;
            break;
        default:
        case OUTPUT_DEFAULT:
            str_format=DEFAULT_FORMAT32;
            break;
        }
        printf(str_format, \
        (uint32_t)info->regs->rsp, (uint32_t)exception_record, (uint32_t)exception_code,\
        (uint32_t)(trap_frame.Eip), (uint32_t)(trap_frame.Eax), (uint32_t)(trap_frame.Ebx),\
        (uint32_t)(trap_frame.Ecx), (uint32_t)(trap_frame.Edx), (uint32_t)(trap_frame.Edi),\
        (uint32_t)(trap_frame.Esi), (uint32_t)(trap_frame.Ebp), (uint32_t)(trap_frame.HardwareEsp));
    }else{
        KTRAP_FRAME64 trap_frame64;
        reg_t exception_code;

        ctx.addr = info->regs->r8;
        vmi_read(vmi,&ctx, &trap_frame64,sizeof(KTRAP_FRAME64));
        ctx.addr = info->regs->rcx;
        vmi_read_32(vmi, &ctx, (uint32_t*)&exception_code);
        switch(format) {
        case OUTPUT_CSV:
            str_format=CSV_FORMAT64;
            break;
        default:
        case OUTPUT_DEFAULT:
            str_format=DEFAULT_FORMAT64;
            break;
        }
        printf(str_format, \
        info->regs->rcx, exception_code, trap_frame64.Rip, trap_frame64.Rax, trap_frame64.Rbx,\
        trap_frame64.Rsp,  trap_frame64.Rbp, trap_frame64.Rdx,trap_frame64.R8, trap_frame64.R9,\
        trap_frame64.R10, trap_frame64.R11);
    }

    drakvuf_release_vmi(drakvuf);
    return 0;
}

int plugin_exmon_init(drakvuf_t drakvuf, const char *rekall_profile) {

    drakvuf_trap_t *trap = g_malloc0(sizeof(drakvuf_trap_t));
    trap->lookup_type = LOOKUP_PID;
    trap->u.pid = 4;
    trap->addr_type = ADDR_RVA;
    trap->u2.rva = drakvuf_get_function_rva(rekall_profile, "KiDispatchException");
    trap->name = "KiDispatchException";
    trap->module = "ntoskrnl.exe";
    trap->type = BREAKPOINT;
    trap->cb = cb;

    if (!trap->u2.rva) {
        return 0;
    }

    traps = g_slist_prepend(traps, trap);
    format = drakvuf_get_output_format(drakvuf);

    return 1;
}



int plugin_exmon_start(drakvuf_t drakvuf) {
    drakvuf_add_traps(drakvuf, traps);
    return 1;
}

int plugin_exmon_close(drakvuf_t drakvuf) {
    GSList *loop = traps;
    while(loop) {
        free(loop->data);
        loop = loop->next;
    }

    g_slist_free(traps);
    traps = NULL;

    return 1;
}

