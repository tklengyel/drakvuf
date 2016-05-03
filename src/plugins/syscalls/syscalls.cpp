/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014-2016 Tamas K Lengyel.  *
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
#include <inttypes.h>
#include "syscalls.h"

static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {

    syscalls *s = (syscalls*)info->trap->data;
    char *procname = drakvuf_get_current_process_name(drakvuf, info->vcpu, info->regs);

    switch(s->format) {
    case OUTPUT_CSV:
        printf("syscall,%" PRIu32" 0x%" PRIx64 ",%s,%s,%s\n",
               info->vcpu, info->regs->cr3, procname, info->trap->module, info->trap->name);
        break;
    default:
    case OUTPUT_DEFAULT:
        printf("[SYSCALL] vCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s!%s\n",
               info->vcpu, info->regs->cr3, procname, info->trap->module, info->trap->name);
        break;
    }

    free(procname);
    return 0;
}

static GSList* create_trap_config(drakvuf_t drakvuf, syscalls *s, symbols_t *symbols) {

    GSList *ret = NULL;
    unsigned long i;
    addr_t module_list, ntoskrnl;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if(VMI_FAILURE == vmi_read_addr_ksym(vmi, (char *)"PsLoadedModuleList", &module_list))
        goto done;

    if( !drakvuf_get_module_base_addr(drakvuf, module_list, "ntoskrnl.exe", &ntoskrnl) )
        goto done;

    for (i=0; i < symbols->count; i++) {

        const struct symbol *symbol = &symbols->symbols[i];

        if (strncmp(symbol->name, "Nt", 2))
            continue;
        //if (strcmp(symbol->name, "NtCallbackReturn"))
        //    continue;

        drakvuf_trap_t *trap = (drakvuf_trap_t *)g_malloc0(sizeof(drakvuf_trap_t));
        trap->lookup_type = LOOKUP_PID;
        trap->u.pid = 4;
        trap->addr_type = ADDR_VA;
        trap->u2.addr = ntoskrnl + symbol->rva;
        trap->name = g_strdup(symbol->name);
        trap->module = "ntoskrnl.exe";
        trap->type = BREAKPOINT;
        trap->cb = cb;
        trap->data = s;

        ret = g_slist_prepend(ret, trap);
    }

done:
    drakvuf_release_vmi(drakvuf);
    return ret;
}

syscalls::syscalls(drakvuf_t drakvuf, const void *config, output_format_t output) {
    const char *rekall_profile = (const char *)config;
    symbols_t *symbols = drakvuf_get_symbols_from_rekall(rekall_profile);
    if (!symbols)
    {
        fprintf(stderr, "Failed to parse Rekall profile at %s\n", rekall_profile);
        return;
    }

    this->traps = create_trap_config(drakvuf, this, symbols);
    this->format = output;

    drakvuf_free_symbols(symbols);

    GSList *loop = this->traps;
    while(loop) {
        drakvuf_trap_t *trap = (drakvuf_trap_t *)loop->data;

        if ( !drakvuf_add_trap(drakvuf, trap) )
            throw -1;

        loop = loop->next;
    }
}

syscalls::~syscalls() {
    GSList *loop = this->traps;
    while(loop) {
        drakvuf_trap_t *trap = (drakvuf_trap_t *)loop->data;
        free((char*)trap->name);
        free(loop->data);
        loop = loop->next;
    }

    g_slist_free(this->traps);
}
