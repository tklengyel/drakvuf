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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <inttypes.h>
#include <glib.h>
#include <err.h>

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>

#include "../xen_helper/xen_helper.h"

#include "drakvuf.h"
#include "win-symbols.h"
#include "vmi.h"
#include "rdtsc.h"

static uint8_t bp = 0xCC;

// This is the callback when an int3 or a read event happens
event_response_t vmi_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {

    /*reg_t tsc, deltatsc;
     deltatsc = rdtsc();
     vmi_get_vcpureg(vmi, &tsc, TSC, event->vcpu_id);*/

    addr_t pa;

    if (event->type == VMI_EVENT_INTERRUPT) {
        pa = (event->interrupt_event.gfn << 12) + event->interrupt_event.offset;
        //PRINT_DEBUG("Resetting trap @ 0x%lx.\n", pa);
        vmi_write_8_pa(vmi, pa, &bp);
    } else {

        vmi_register_event(vmi, event);
        reg_t cr3;
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        pa = (event->mem_event.gfn << 12) + event->mem_event.offset;

        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct breakpoint *s = NULL;
        ghashtable_foreach(containers, i, key, s)
        {
            if (pa > s->pa - 7 && pa <= s->pa + 7) {
                //PRINT_DEBUG("Violation @ 0x%lx. Resetting trap @ 0x%lx.\n", pa, s->pa);
                vmi_write_8_pa(vmi, s->pa, &bp);
            }
        }
    }

    //vmi_set_vcpureg(vmi, tsc+(rdtsc()-deltatsc), TSC, event->vcpu_id);
    return 0;
}

// This is the callback when a write event happens
event_response_t vmi_save_and_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {

    vmi_register_event(vmi, event);
    uint8_t trap = TRAP;
    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
    GHashTable *containers = event->data;
    GHashTableIter i;
    addr_t *key = NULL;
    struct breakpoint *s = NULL;
    ghashtable_foreach(containers, i, key, s)
    {
        if (pa > s->pa - 7 && pa <= s->pa + 7) {
            //save the write
            vmi_read_8_pa(vmi, s->pa, &s->backup);
            //add trap back
            vmi_write_8_pa(vmi, s->pa, &trap);
        }
    }
    return 0;
}

event_response_t trap_guard(vmi_instance_t vmi, vmi_event_t *event) {

    /*reg_t tsc, deltatsc;
     deltatsc = rdtsc();
     vmi_get_vcpureg(vmi, &tsc, TSC, event->vcpu_id);*/

    reg_t cr3;
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
    vmi_clear_event(vmi, event);

    if (event->mem_event.out_access & VMI_MEMACCESS_R) {
        //PRINT_DEBUG("Read memaccess @ 0x%lx. Page %lu.\n", pa, event->mem_event.gfn);
        //read_count++;
        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct breakpoint *s = NULL;
        ghashtable_foreach(containers, i, key, s) {
                if (pa > s->pa - 7 && pa <= s->pa + 7) {
                    PRINT_DEBUG("** Mem event removing trap 0x%lx\n", s->pa);
                    vmi_write_8_pa(vmi, s->pa, &s->backup);
                }
        }

        vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
    }

    if (event->mem_event.out_access & VMI_MEMACCESS_W) {
        //write_count++;
        PRINT_DEBUG("Write memaccess @ 0x%lx. Page %lu.\n", pa,
                event->mem_event.gfn);

        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct breakpoint *s = NULL;
        ghashtable_foreach(containers, i, key, s) {
            /*PRINT_DEBUG("Write memaccess @ 0x%lx. Page %lu. Symbol: %s!%s\n", pa,
                    event->mem_event.gfn, s->symbol.config->name,
                    s->symbol.symbol->name);*/
                if (pa > s->pa - 7 && pa <= s->pa) {
                    PRINT_DEBUG("** Mem event removing trap 0x%lx\n", s->pa);
                    vmi_write_8_pa(vmi, s->pa, &s->backup);
                }
        }

        vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_save_and_reset_trap);
    }

    //vmi_set_vcpureg(vmi, tsc+(rdtsc()-deltatsc), TSC, event->vcpu_id);
    return 0;
}

event_response_t post_mem_cb(vmi_instance_t vmi, vmi_event_t *event) {

    struct memaccess *s = event->data;
    drakvuf_t drakvuf = s->drakvuf;
    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
    event_response_t response = 0;
    vmi_clear_event(vmi, event);

    drakvuf->in_callback = 1;
    GSList *loop = s->traps;
    while(loop) {
        drakvuf_trap_t *trap = loop->data;

        if(trap->memaccess_type == POST) {
            drakvuf_trap_info_t trap_info = {
                .trap = trap,
                .trap_pa = pa,
                .regs = event->regs.x86,
                .vcpu = event->vcpu_id,
            };

            response |= trap->cb(drakvuf, &trap_info);
        }

        loop = loop->next;
     }
     drakvuf->in_callback = 0;

     // If there were any trap removal requests in the callbacks
     // we process those now
     loop = drakvuf->remove_traps;
     while(loop) {
            remove_trap(drakvuf, loop->data);
            loop = loop->next;
     }
     g_slist_free(drakvuf->remove_traps);
     drakvuf->remove_traps = NULL;
     s = NULL; // it may already have got freed

     // Check if we have traps still active on this page
     if ( g_hash_table_lookup(drakvuf->memaccess_lookup_gfn, &event->mem_event.gfn) )
        vmi_register_event(vmi, event);

    return 0;
}

event_response_t pre_mem_cb(vmi_instance_t vmi, vmi_event_t *event) {

    struct memaccess *s = event->data;
    drakvuf_t drakvuf = s->drakvuf;
    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
    event_response_t response = 0;
    vmi_clear_event(vmi, event);

    drakvuf->in_callback = 1;
    GSList *loop = s->traps;
    while(loop) {
        drakvuf_trap_t *trap = loop->data;

        if(trap->memaccess_type == PRE) {
            drakvuf_trap_info_t trap_info = {
                .trap = trap,
                .trap_pa = pa,
                .regs = event->regs.x86,
                .vcpu = event->vcpu_id,
            };

            response |= trap->cb(drakvuf, &trap_info);
        }

        loop = loop->next;
     }
     drakvuf->in_callback = 0;

     // If there were any trap removal requests in the callbacks
     // we process those now
     loop = drakvuf->remove_traps;
     while(loop) {
            remove_trap(drakvuf, loop->data);
            loop = loop->next;
     }
     g_slist_free(drakvuf->remove_traps);
     drakvuf->remove_traps = NULL;
     s = NULL; // it may already have got freed

     // Check if we have traps still active on this page
     if ( g_hash_table_lookup(drakvuf->memaccess_lookup_gfn, &event->mem_event.gfn) )
        vmi_step_event(vmi, event, event->vcpu_id, 1, post_mem_cb);

    return 0;
}

event_response_t int3_cb(vmi_instance_t vmi, vmi_event_t *event) {

    reg_t cr3 = event->regs.x86->cr3;
    event_response_t response = 0;

    drakvuf_t drakvuf = event->data;
    addr_t pa = (event->interrupt_event.gfn << 12)
            + event->interrupt_event.offset;
    struct breakpoint *s = g_hash_table_lookup(drakvuf->breakpoint_lookup_pa, &pa);

    if (!s) {
        fprintf(stderr,
                "Unknown Int3 event: CR3: 0x%"PRIx64" PA=0x%"PRIx64" RIP=0x%"PRIx64"\n",
                cr3, pa, event->interrupt_event.gla);
        event->interrupt_event.reinject = 1;
    } else {
        event->interrupt_event.reinject = 0;
        // remove trap
        vmi_write_8_pa(vmi, pa, &s->backup);

        drakvuf->in_callback = 1;
        GSList *loop = s->traps;
        while(loop) {
            drakvuf_trap_t *trap = loop->data;
            drakvuf_trap_info_t trap_info = {
                .trap = trap,
                .trap_pa = pa,
                .regs = event->regs.x86,
                .vcpu = event->vcpu_id,
            };

            loop = loop->next;
            response |= trap->cb(drakvuf, &trap_info);
        }
        drakvuf->in_callback = 0;

        // If there were any trap removal requests in the callbacks
        // we process those now
        loop = drakvuf->remove_traps;
        while(loop) {
            remove_trap(drakvuf, loop->data);
            loop = loop->next;
        }
        g_slist_free(drakvuf->remove_traps);
        drakvuf->remove_traps = NULL;
        s = NULL; // it may already have got freed

        // Check if we have traps still active on this breakpoint
        if ( g_hash_table_lookup(drakvuf->breakpoint_lookup_pa, &pa) )
            vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
    }

    return 0;
}

void remove_trap(drakvuf_t drakvuf,
                 const drakvuf_trap_t *trap)
{
    vmi_instance_t vmi = drakvuf->vmi;

    if (trap->type == BREAKPOINT) {
        struct breakpoint *container =
            g_hash_table_lookup(drakvuf->breakpoint_lookup_trap, &trap);
        if ( !container )
            return;

        g_hash_table_remove(drakvuf->breakpoint_lookup_trap, &trap);
        container->traps = g_slist_remove(container->traps, trap);

        if(!container->traps)
        {
            vmi_event_t *guard =
                vmi_get_mem_event(vmi, container->pa, VMI_MEMEVENT_PAGE);

            if (guard)
            {
                g_hash_table_remove(guard->data, &container->pa);
                if ( !g_hash_table_size(guard->data) ) {
                    g_hash_table_destroy(guard->data);
                    vmi_clear_event(vmi, guard);
                    free(guard);
                }
            }

            vmi_write_8_pa(vmi, container->pa, &container->backup);
            g_hash_table_remove(drakvuf->breakpoint_lookup_pa, &container->pa);
        }
    } else {
        struct memaccess *container =
            g_hash_table_lookup(drakvuf->memaccess_lookup_trap, &trap);

        if ( !container ) {
            return;
        }

        container->traps = g_slist_remove(container->traps, trap);
        if (!container->traps) {
            vmi_clear_event(vmi, container->memtrap);
            free(container->memtrap);
            g_hash_table_remove(drakvuf->memaccess_lookup_trap, &trap);
            g_hash_table_remove(drakvuf->memaccess_lookup_gfn, &container->gfn);
        }
    }
}

void inject_trap_mem(drakvuf_t drakvuf, drakvuf_trap_t *trap) {
    addr_t gfn = trap->u2.addr >> 12;
    struct memaccess *s =
        g_hash_table_lookup(drakvuf->memaccess_lookup_gfn, &gfn);

    // We already have a trap registered on this page
    // check if type matches, if so, add trap to the list
    if (s) {
        drakvuf_trap_t *havetrap = s->traps->data;
        if(havetrap->type != trap->type)
            return;

        s->traps = g_slist_prepend(s->traps, trap);
        g_hash_table_insert(drakvuf->memaccess_lookup_trap, g_memdup(&trap, sizeof(void*)),
                            s);
        return;
    } else {
        // No trap registered, check if guard is used on this page
        vmi_event_t *guard = vmi_get_mem_event(drakvuf->vmi, trap->u2.addr, VMI_MEMEVENT_PAGE);
        if ( guard )
            return;

        s = g_malloc0(sizeof(struct memaccess));
        s->gfn = gfn;
        s->drakvuf = drakvuf;
        s->memtrap = g_malloc0(sizeof(vmi_event_t));
        s->memtrap->data = s;
        SETUP_MEM_EVENT(s->memtrap, trap->u2.addr, VMI_MEMEVENT_PAGE,
                        mem_conversion[trap->type], pre_mem_cb);

        if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, s->memtrap)) {
            PRINT_DEBUG("*** FAILED TO REGISTER MEMORY TRAP @ PAGE %lu ***\n",
                        trap->u2.addr >> 12);
            free(s->memtrap);
            free(s);
            return;
        }

        s->traps = g_slist_prepend(s->traps, trap);
        g_hash_table_insert(drakvuf->memaccess_lookup_gfn, g_memdup(&s->gfn, sizeof(addr_t)),
                            s);
        g_hash_table_insert(drakvuf->memaccess_lookup_trap, g_memdup(&trap, sizeof(void*)),
                            s);
    }

    return;
}

void inject_trap_pa(drakvuf_t drakvuf,
                    drakvuf_trap_t *trap,
                    addr_t pa)
{
    // check if already marked
    struct breakpoint *container = g_hash_table_lookup(drakvuf->breakpoint_lookup_pa, &pa);
    if (container) {
        g_hash_table_insert(drakvuf->breakpoint_lookup_trap,
                            g_memdup(&trap, sizeof(void*)),
                            container);
        container->traps = g_slist_prepend(container->traps, trap);
        return;
    }

    container = g_malloc0(sizeof(struct breakpoint));

    // backup current byte
    uint8_t byte = 0;
    vmi_instance_t vmi = drakvuf->vmi;
    vmi_read_8_pa(vmi, pa, &byte);
    if (byte == TRAP) {
        PRINT_DEBUG("\n\n** SKIPPING, PA IS ALREADY TRAPPED @ 0x%lx %s!%s**\n\n",
                    pa, trap->module, trap->name);
        return;
    }

    container->drakvuf = drakvuf;
    container->backup = byte;
    container->pa = pa;
    container->vmi = vmi;
    container->guard = vmi_get_mem_event(vmi, pa, VMI_MEMEVENT_PAGE);
    container->traps = g_slist_prepend(container->traps, trap);

    // write trap
    // THIS AUTOMATICALLY UNSHARES THE PAGE
    // This has to happen before the MEMEVENT is registered because
    // the MFN is yet to be allocated on which we want the MEMEVENT set on
    if (VMI_FAILURE == vmi_write_8_pa(vmi, container->pa, &bp)) {
        PRINT_DEBUG("FAILED TO INJECT TRAP @ 0x%lx !\n", container->pa);
        return;
    }

    // Now we can set the EPT permissions
    if (!container->guard) {
        container->guard = g_malloc0(sizeof(vmi_event_t));
        SETUP_MEM_EVENT(container->guard, container->pa, VMI_MEMEVENT_PAGE,
                        VMI_MEMACCESS_RW, trap_guard);
        if (VMI_FAILURE == vmi_register_event(vmi, container->guard)) {
            PRINT_DEBUG("*** FAILED TO REGISTER MEMORY GUARD @ PAGE %lu ***\n",
                        pa >> 12);
            free(container->guard);
            free(container);

            // TODO remove trap

            return;
        }

        container->guard->data =
            g_hash_table_new(g_int64_hash, g_int64_equal);

        //PRINT_DEBUG("\t\tNew memory event guard set on page %lu\n", pa >> 12);
    } else
        PRINT_DEBUG("\t\tMemory event guard already set on page %lu\n", pa >> 12);

    struct breakpoint *test =
        g_hash_table_lookup(container->guard->data, &container->pa);

    if (!test)
        g_hash_table_insert(container->guard->data, &container->pa,
                            container);
    else
        PRINT_DEBUG("Address is already guarded\n");

    // save trap location into lookup tree
    g_hash_table_insert(drakvuf->breakpoint_lookup_pa, g_memdup(&container->pa, sizeof(addr_t)),
                        container);
    g_hash_table_insert(drakvuf->breakpoint_lookup_trap, g_memdup(&trap, sizeof(void*)),
                        container);

    PRINT_DEBUG("\t\tTrap added @ PA 0x%lx Page %lu for %s. Backup: 0x%x.\n",
                container->pa, pa >> 12, trap->name,
                container->backup);
}

void inject_trap(drakvuf_t drakvuf,
                 drakvuf_trap_t *trap,
                 addr_t vaddr,
                 vmi_pid_t pid)
{

    vmi_instance_t vmi = drakvuf->vmi;
    addr_t dtb = vmi_pid_to_dtb(vmi, pid);

    // get pa
    addr_t pa = 0;

    if (trap->addr_type == ADDR_VA)
        pa = vmi_pagetable_lookup(vmi, dtb, trap->u2.addr);
    else
        pa = vmi_pagetable_lookup(vmi, dtb, vaddr + trap->u2.rva);

    if (!pa)
        return;

    inject_trap_pa(drakvuf, trap, pa);
}

void inject_traps_modules(drakvuf_t drakvuf,
                          GSList *traps,
                          drakvuf_trap_t *trap,
                          addr_t list_head,
                          vmi_pid_t pid,
                          const char *name)

{
    PRINT_DEBUG("Inject traps in module list of [%u]: %s\n", pid, name);

    if (traps == NULL && trap == NULL)
        return;

    vmi_instance_t vmi = drakvuf->vmi;

    addr_t next_module = list_head;
    while (1) {

        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, pid, &tmp_next);

        if (list_head == tmp_next)
            break;

        addr_t dllbase = 0;
        vmi_read_addr_va(vmi,
                    next_module + offsets[LDR_DATA_TABLE_ENTRY_DLLBASE], pid,
                    &dllbase);

        if (!dllbase)
            break;

        unicode_string_t *us =
            vmi_read_unicode_str_va(vmi, next_module + offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME], pid);
        unicode_string_t out = { .contents = NULL };

        if (us && VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8")) {
            PRINT_DEBUG("\t%s @ 0x%lx\n", out.contents, dllbase);
        } // if
        if (us)
            vmi_free_unicode_str(us);

        if(out.contents) {

            if (traps) {
                GSList *loop = traps;
                while(loop) {

                    drakvuf_trap_t *curtrap = loop->data;

                    if (curtrap->module &&
                        (
                        (curtrap->lookup_type == LOOKUP_PID && pid == curtrap->u.pid)
                        ||
                        (curtrap->lookup_type == LOOKUP_NAME && !strcmp(name,curtrap->u.proc))
                        ) &&
                        !strcmp((char*)out.contents,curtrap->module))
                    {
                        inject_trap(drakvuf, curtrap, dllbase, pid);
                    }

                    loop = loop->next;
                }
            } else if(!strcmp((char*)out.contents,trap->module)) {
                inject_trap(drakvuf, trap, dllbase, pid);
                free(out.contents);
                break;
            }

            free(out.contents);
        }

        next_module = tmp_next;
    }
}

void drakvuf_loop(drakvuf_t drakvuf) {

    PRINT_DEBUG("Started DRAKVUF loop\n");

    drakvuf->interrupted = 0;

    vmi_event_t interrupt_event;
    memset(&interrupt_event, 0, sizeof(vmi_event_t));
    interrupt_event.type = VMI_EVENT_INTERRUPT;
    interrupt_event.interrupt_event.intr = INT3;
    interrupt_event.callback = int3_cb;
    interrupt_event.data = drakvuf;

    vmi_register_event(drakvuf->vmi, &interrupt_event);

    vmi_resume_vm(drakvuf->vmi);

    while (!drakvuf->interrupted) {
        //PRINT_DEBUG("Waiting for events in DRAKVUF...\n");
        status_t status = vmi_events_listen(drakvuf->vmi, 100);

        if ( VMI_SUCCESS != status )
        {
            PRINT_DEBUG("Error waiting for events or timeout, quitting...\n");
            drakvuf->interrupted = -1;
        }
    }

    vmi_pause_vm(drakvuf->vmi);
    //print_sharing_info(drakvuf->xen, drakvuf->domID);

    PRINT_DEBUG("DRAKVUF loop finished\n");
}

void init_vmi(drakvuf_t drakvuf) {

    PRINT_DEBUG("Init VMI on domID %u -> %s\n", drakvuf->domID, drakvuf->dom_name);

    GHashTable *config = g_hash_table_new(g_str_hash, g_str_equal);
    g_hash_table_insert(config, "os_type", "Windows");
    g_hash_table_insert(config, "domid", &drakvuf->domID);
    g_hash_table_insert(config, "sysmap", drakvuf->rekall_profile);

    // Initialize the libvmi library.
    if (vmi_init_custom(&drakvuf->vmi,
            VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS
                    | VMI_CONFIG_GHASHTABLE, (vmi_config_t) config)
            == VMI_FAILURE) {
        PRINT_DEBUG("Failed to init LibVMI library.\n");
        if (drakvuf->vmi != NULL) {
            vmi_destroy(drakvuf->vmi);
        }
        drakvuf->vmi = NULL;
        return;
    }
    g_hash_table_destroy(config);

    drakvuf->pm = vmi_get_page_mode(drakvuf->vmi);

    // Crete tables to lookup breakpoints
    drakvuf->breakpoint_lookup_pa =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, free, free);
    drakvuf->breakpoint_lookup_trap =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);
    drakvuf->memaccess_lookup_gfn =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, free, free);
    drakvuf->memaccess_lookup_trap =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);

    // Get the offsets from the Rekall profile
    int i;
    for (i = 0; i < OFFSET_MAX; i++) {
        if (VMI_FAILURE
                == windows_system_map_lookup(
                        drakvuf->rekall_profile, offset_names[i][0],
                        offset_names[i][1], &offsets[i], NULL)) {
            PRINT_DEBUG("Failed to find offset for %s:%s\n", offset_names[i][0],
                    offset_names[i][1]);
        }
    }

    for (i = 0; i < SIZE_LIST_MAX; i++) {
        if (VMI_FAILURE
                == windows_system_map_lookup(
                        drakvuf->rekall_profile, size_names[i],
                        (char *) &i, NULL, &struct_sizes[i])) {
            PRINT_DEBUG("Failed to find offset for %s:%s\n", offset_names[i][0],
                    offset_names[i][1]);
            continue;
        }
    }
}

// -------------------------- closing

void close_vmi(drakvuf_t drakvuf) {

    vmi_instance_t vmi = drakvuf->vmi;
    GHashTableIter i;
    addr_t *key = NULL;
    struct breakpoint *s = NULL;
    ghashtable_foreach(drakvuf->breakpoint_lookup_pa, i, key, s)
    {
        vmi_event_t *guard =
            vmi_get_mem_event(vmi, s->pa, VMI_MEMEVENT_PAGE);

        if (guard) {
            vmi_clear_event(vmi, guard);
            g_hash_table_destroy(guard->data);
            free(guard);
        }

        vmi_write_8_pa(vmi, s->pa, &s->backup);
        g_slist_free(s->traps);
    }

    g_hash_table_destroy(drakvuf->breakpoint_lookup_pa);
    g_hash_table_destroy(drakvuf->breakpoint_lookup_trap);

    GHashTableIter i2;
    addr_t *key2 = NULL;
    struct memaccess *s2 = NULL;
    ghashtable_foreach(drakvuf->memaccess_lookup_gfn, i2, key2, s2)
    {
        vmi_clear_event(vmi, s2->memtrap);
        free(s2->memtrap);
        g_slist_free(s2->traps);
    }

    g_hash_table_destroy(drakvuf->memaccess_lookup_gfn);

    if (drakvuf->vmi) {
        vmi_destroy(drakvuf->vmi);
        drakvuf->vmi = NULL;
    }
    PRINT_DEBUG("close_vmi_drakvuf finished\n");
}
