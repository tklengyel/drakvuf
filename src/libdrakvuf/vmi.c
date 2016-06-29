/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2016 Tamas K Lengyel.                                  *
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

#include "private.h"
#include "libdrakvuf.h"
#include "win-symbols.h"
#include "vmi.h"

static uint8_t bp = 0xCC;

/*
 * This function gets called from the singlestep event
 * after an int3 or a read event happens.
 */
event_response_t vmi_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {
    drakvuf_t drakvuf = event->data;
    PRINT_DEBUG("reset trap, switching %u->%u\n", event->vmm_pagetable_id, drakvuf->altp2m_idx);
    event->vmm_pagetable_id = drakvuf->altp2m_idx;
    return (1u << VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP) | // Turn off singlestep
           (1u << VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
}

/*
 * Loop through the table, call the free_routine (if any)
 * any free the wrapper.
 */
static inline
void process_free_requests(drakvuf_t drakvuf) {
    GHashTableIter i;
    addr_t *key = NULL;
    struct free_trap_wrapper *free_wrapper = NULL;

    ghashtable_foreach(drakvuf->remove_traps, i, key, free_wrapper)
    {
        remove_trap(drakvuf, free_wrapper->trap);
        if(free_wrapper->free_routine)
            free_wrapper->free_routine(free_wrapper->trap);
        free(free_wrapper);
    }

    g_hash_table_destroy(drakvuf->remove_traps);
    drakvuf->remove_traps =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);
}

/* Here we are in singlestep mode already and this is a singlstep cb */
event_response_t post_mem_cb(vmi_instance_t vmi, vmi_event_t *event) {

    struct memcb_pass *pass = event->data;
    drakvuf_t drakvuf = pass->drakvuf;
    struct wrapper *s =
        g_hash_table_lookup(drakvuf->memaccess_lookup_gfn, &pass->gfn);

    /*
     * The trap may have been removed since in another callback,
     * in which case we have nothing to do.
     */
    if (!s) {
        PRINT_DEBUG("Post mem cb @ 0x%lx has been cleared\n", pass->gfn);
        goto done;
    }

    PRINT_DEBUG("Post mem cb @ 0x%lx vCPU %u\n", pass->gfn, event->vcpu_id);

    drakvuf->in_callback = 1;
    GSList *loop = s->traps;
    while(loop) {
        drakvuf_trap_t *trap = loop->data;

        if(trap->cb && trap->memaccess.type == POST) {
            drakvuf_trap_info_t trap_info = {
                .trap = trap,
                .trap_pa = s->memaccess.pa,
                .regs = event->regs.x86,
                .vcpu = event->vcpu_id,
            };

            trap->cb(drakvuf, &trap_info);
        }

        loop = loop->next;
    }
    drakvuf->in_callback = 0;

    /*
     * We don't need to pause the VM here because mem events
     * are safely cleared by LibVMI.
     */
    process_free_requests(drakvuf);

    /*
     * We need to copy the newly written page to the remapped gfn
     * and reapply all traps
     */
    if ( pass->traps ) {

        PRINT_DEBUG("Re-copying remapped gfn\n");

        uint8_t backup[VMI_PS_4KB] = {0};

        vmi_read_pa(drakvuf->vmi, pass->remapped_gfn->o<<12, &backup, VMI_PS_4KB);
        vmi_write_pa(drakvuf->vmi, pass->remapped_gfn->r<<12, &backup, VMI_PS_4KB);

        GSList *loop = pass->traps;
        while(loop) {

            addr_t *pa = loop->data;
            uint8_t test = 0;
            struct wrapper *s = g_hash_table_lookup(drakvuf->breakpoint_lookup_pa, pa);

            vmi_read_8_pa(drakvuf->vmi, *pa, &test);

            if ( test == bp )
            {
                PRINT_DEBUG("Double-trap at 0x%lx\n", *pa);
                s->breakpoint.doubletrap = 1;
            }
            else
            {
                s->breakpoint.doubletrap = 0;
                vmi_write_8_pa(drakvuf->vmi,
                               (pass->remapped_gfn->r << 12) + (*pa & VMI_BIT_MASK(0,11)),
                               &bp);
            }

            loop = loop->next;
        };

    }

done:
    free(pass);
    /* We switch back to the altp2m view no matter what */
    event->vmm_pagetable_id = drakvuf->altp2m_idx;
    drakvuf->step_event[event->vcpu_id]->callback = vmi_reset_trap;
    drakvuf->step_event[event->vcpu_id]->data = drakvuf;
    return (1u << VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP) | // Turn off singlestep
           (1u << VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
}

/* This hits on the first access on a page, so not in singlestep yet */
event_response_t pre_mem_cb(vmi_instance_t vmi, vmi_event_t *event) {

    drakvuf_t drakvuf = event->data;
    struct wrapper *s =
        g_hash_table_lookup(drakvuf->memaccess_lookup_gfn, &event->mem_event.gfn);

    if (!s) {
        PRINT_DEBUG("Event has been cleared for GFN 0x%lx but we are still in view %u\n",
                    event->mem_event.gfn, event->vmm_pagetable_id);
        goto done;
    }

    PRINT_DEBUG("Pre mem cb with vCPU %u @ 0x%lx 0x%lx in view %u: %c%c%c\n",
                event->vcpu_id, event->mem_event.gfn, event->mem_event.offset, event->vmm_pagetable_id,
                (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
                (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
                (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-'
                );

    s->memaccess.pa = (event->mem_event.gfn << 12) + event->mem_event.offset;

    GSList *loop = s->traps;
    drakvuf->in_callback = 1;
    while(loop) {
        drakvuf_trap_t *trap = loop->data;

        if(trap->cb && trap->memaccess.type == PRE) {
            drakvuf_trap_info_t trap_info = {
                .trap = trap,
                .trap_pa = s->memaccess.pa,
                .regs = event->regs.x86,
                .vcpu = event->vcpu_id,
            };

            trap->cb(drakvuf, &trap_info);
        }

        loop = loop->next;
    }
    drakvuf->in_callback = 0;

    /*
     * We don't need to pause the VM here because mem events
     * are safely cleared by LibVMI.
     */
    process_free_requests(drakvuf);

     // Check if we have traps still active on this page
    s = g_hash_table_lookup(drakvuf->memaccess_lookup_gfn, &event->mem_event.gfn);
    if (s) {
        /*
         * There seems to be another trap still active
         * but it may already have another event queued that will clear it.
         */
        struct memcb_pass *pass = g_malloc0(sizeof(struct memcb_pass));
        pass->drakvuf = drakvuf;
        pass->gfn = event->mem_event.gfn;
        if(!s->memaccess.guard2) {
            event->vmm_pagetable_id = 0;

            /*
             * If this is a remapped gfn and the page is getting written, the remapped copy needs to be updated
             */
            if ( event->mem_event.out_access & VMI_MEMACCESS_W ) {
                pass->traps = g_hash_table_lookup(drakvuf->breakpoint_lookup_gfn, &pass->gfn);
                if ( pass->traps )
                    pass->remapped_gfn = g_hash_table_lookup(drakvuf->remapped_gfns, &pass->gfn);
            }
        } else
            event->vmm_pagetable_id = drakvuf->altp2m_idr;
        drakvuf->step_event[event->vcpu_id]->callback = post_mem_cb;
        drakvuf->step_event[event->vcpu_id]->data = pass;
        return (1u << VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP) | // Turn on singlestep
               (1u << VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
    }

done:
    return 0;
}

event_response_t int3_cb(vmi_instance_t vmi, vmi_event_t *event) {

    reg_t cr3 = event->regs.x86->cr3;

    drakvuf_t drakvuf = event->data;
    addr_t pa = (event->interrupt_event.gfn << 12)
            + event->interrupt_event.offset;
    struct wrapper *s = g_hash_table_lookup(drakvuf->breakpoint_lookup_pa, &pa);

    PRINT_DEBUG("INT3 event vCPU %u altp2m:%u CR3: 0x%"PRIx64" PA=0x%"PRIx64" RIP=0x%"PRIx64"\n",
                event->vcpu_id, event->vmm_pagetable_id, cr3, pa, event->interrupt_event.gla);

    if (!s) {
        /*
         * No trap is currently registered for this location
         * but this event may have been triggered by one we just
         * removed.
         */
        uint8_t test = 0;
        vmi_read_8_pa(vmi, pa, &test);

        if (test == bp) {
            // There is a breakpoint instruction in memory here
            // so we need to reinject this to the guest.
            PRINT_DEBUG("Reinjecting breakpoint into the guest\n");
            event->interrupt_event.reinject = 1;
        } else {
            // This was an event for an old breakpoint no longer set
            PRINT_DEBUG("Ignoring old breakpoint event found in the queue\n");
            event->interrupt_event.reinject = 0;
        }
    } else {
        if ( s->breakpoint.doubletrap )
            event->interrupt_event.reinject = 1;
        else
            event->interrupt_event.reinject = 0;

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
            trap->cb(drakvuf, &trap_info);
        }
        drakvuf->in_callback = 0;

        process_free_requests(drakvuf);

        // Check if we have traps still active on this breakpoint
        if ( g_hash_table_lookup(drakvuf->breakpoint_lookup_pa, &pa) ) {
            PRINT_DEBUG("Switching altp2m and to singlestep on vcpu %u\n", event->vcpu_id);
            event->vmm_pagetable_id = 0;
            drakvuf->step_event[event->vcpu_id]->callback = vmi_reset_trap;
            drakvuf->step_event[event->vcpu_id]->data = drakvuf;
            return (1u << VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP) | // Enable singlestep
                   (1u << VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
        }
    }

    return 0;
}

event_response_t cr3_cb(vmi_instance_t vmi, vmi_event_t *event) {
    drakvuf_t drakvuf = (drakvuf_t)event->data;

#ifdef DRAKVUF_DEBUG
    /* This is very verbose and always on so we only print debug information
     * when there is a subscriber trap */
    if(drakvuf->cr3)
        PRINT_DEBUG("CR3 cb on vCPU %u: 0x%" PRIx64 "\n", event->vcpu_id, event->reg_event.value);
#endif

    event->regs.x86->cr3 = event->reg_event.value;

    /* Flush the LibVMI caches */
    vmi_v2pcache_flush(drakvuf->vmi);
    vmi_pidcache_flush(drakvuf->vmi);
    vmi_rvacache_flush(drakvuf->vmi);
    vmi_symcache_flush(drakvuf->vmi);

    drakvuf->in_callback = 1;
    GSList *loop = drakvuf->cr3;
    while(loop) {
        drakvuf_trap_t *trap = loop->data;
        drakvuf_trap_info_t trap_info = {
            .trap = trap,
            .regs = event->regs.x86,
            .vcpu = event->vcpu_id,
        };

        loop = loop->next;
        trap->cb(drakvuf, &trap_info);
    }
    drakvuf->in_callback = 0;

    process_free_requests(drakvuf);

    return 0;
}

void clear_memtrap(vmi_event_t *event, status_t rc) {
    drakvuf_t drakvuf = event->data;
    xc_altp2m_change_gfn(drakvuf->xen->xc, drakvuf->domID,
                         drakvuf->altp2m_idx, event->mem_event.gfn, ~0);
    free(event);
}

void remove_trap(drakvuf_t drakvuf,
                 const drakvuf_trap_t *trap)
{
    vmi_instance_t vmi = drakvuf->vmi;

    switch(trap->type) {
    case BREAKPOINT:
    {
        struct wrapper *container =
            g_hash_table_lookup(drakvuf->breakpoint_lookup_trap, &trap);
        xen_pfn_t current_gfn = container->breakpoint.pa >> 12;
        uint64_t _current_gfn = current_gfn;

        if ( !container )
            return;

        PRINT_DEBUG("Removing breakpoint trap from 0x%lx.\n",
                    container->breakpoint.pa);

        g_hash_table_remove(drakvuf->breakpoint_lookup_trap, &trap);
        container->traps = g_slist_remove(container->traps, trap);

        /* Update list of traps on this gfn */
        GSList *traps_on_gfn =
            g_hash_table_lookup(drakvuf->breakpoint_lookup_gfn, &_current_gfn);
        traps_on_gfn = g_slist_remove(traps_on_gfn, &container->breakpoint.pa);
        g_hash_table_remove(drakvuf->breakpoint_lookup_gfn, &_current_gfn);

        if ( traps_on_gfn ) {
            // the list head may change so we force a reinsert
            g_hash_table_insert(drakvuf->breakpoint_lookup_gfn, g_memdup(&_current_gfn, sizeof(uint64_t)), traps_on_gfn);
        }

        if(!container->traps) {

            struct remapped_gfn *remapped_gfn = g_hash_table_lookup(drakvuf->remapped_gfns, &current_gfn);
            uint8_t backup;

            vmi_read_8_pa(drakvuf->vmi, container->breakpoint.pa, &backup);
            vmi_write_8_pa(drakvuf->vmi,
                           (remapped_gfn->r << 12) + (container->breakpoint.pa & VMI_BIT_MASK(0,11)),
                           &backup);

            remove_trap(drakvuf, &container->breakpoint.guard);
            remove_trap(drakvuf, &container->breakpoint.guard2);

            g_hash_table_remove(drakvuf->breakpoint_lookup_pa, &container->breakpoint.pa);
        }

        break;
    }
    case MEMACCESS:
    {
        struct wrapper *container =
            g_hash_table_lookup(drakvuf->memaccess_lookup_trap, &trap);

        if ( !container ) {
            return;
        }

        container->traps = g_slist_remove(container->traps, trap);
        vmi_event_t *event = container->memaccess.memtrap;
        event->vmm_pagetable_id = drakvuf->altp2m_idx;

        if (!container->traps) {
            PRINT_DEBUG("Removing memtrap for GFN 0x%lx, event @ %p\n",
                        container->memaccess.gfn, container->memaccess.memtrap);

            /*
             * This vmi_clear_event will be queued and removed when all events
             * are pulled from the ring.
             */
            event->data = drakvuf;
            vmi_clear_event(vmi, event, clear_memtrap);
            g_hash_table_remove(drakvuf->memaccess_lookup_trap, &trap);
            g_hash_table_remove(drakvuf->memaccess_lookup_gfn, &container->memaccess.gfn);
            return;
        }

        /*
         * If more subscriber are present make sure we only set the required access settings.
         */
        GSList *loop = container->traps;
        event->vmm_pagetable_id = drakvuf->altp2m_idx;
        vmi_event_t *update_event = g_memdup(event, sizeof(vmi_event_t));
        update_event->mem_event.in_access = 0;

        while(loop) {
            drakvuf_trap_t *trap = loop->data;
            update_event->mem_event.in_access |= trap->memaccess.access;
            loop=loop->next;
        }

        if(VMI_SUCCESS == vmi_swap_events(vmi, event, update_event, (vmi_event_free_t)free)) {
            PRINT_DEBUG("Successfully requested to swap events to permission %c%c%c!\n",
                        (update_event->mem_event.in_access & VMI_MEMACCESS_R) ? 'r' : '-',
                        (update_event->mem_event.in_access & VMI_MEMACCESS_W) ? 'w' : '-',
                        (update_event->mem_event.in_access & VMI_MEMACCESS_X) ? 'x' : '-'
                        );
            container->memaccess.memtrap = update_event;
        } else {
            PRINT_DEBUG("Failed to update memaccess trap settings!\n");
            free(update_event);
        }

        break;
    }
    case REGISTER:
    {
        if(CR3 == trap->reg) {
            /* We don't disable the event itself even if the list is empty
               as we may use it to flush the LibVMI cache */
            drakvuf->cr3 = g_slist_remove(drakvuf->cr3, trap);
        }
        break;
    }
    default:
        break;
    };
}

bool inject_trap_mem(drakvuf_t drakvuf, drakvuf_trap_t *trap, bool guard2) {
    struct wrapper *s =
        g_hash_table_lookup(drakvuf->memaccess_lookup_gfn, &trap->memaccess.gfn);

    // We already have a trap registered on this page
    // check if type matches, if so, add trap to the list
    if (s) {
        drakvuf_trap_t *havetrap = s->traps->data;
        if(havetrap->type != trap->type) {
            PRINT_DEBUG("Failed to add memaccess trap as gfn is already trapped!\n");
            return 0;
        }

        /*
         * Guard2 types are protecting remapped gfns, thus when hit
         * these need to be swapped to the altp2m_idr view.
         */
        s->memaccess.guard2 = guard2;

        if ( s->memaccess.memtrap->mem_event.in_access != trap->memaccess.access ) {

            s->memaccess.memtrap->vmm_pagetable_id = drakvuf->altp2m_idx;
            vmi_event_t *update_event = g_memdup(s->memaccess.memtrap, sizeof(vmi_event_t));
            update_event->mem_event.in_access |= trap->memaccess.access;

            if (VMI_FAILURE == vmi_swap_events(drakvuf->vmi, s->memaccess.memtrap, update_event, (vmi_event_free_t)free)) {
                PRINT_DEBUG("*** FAILED TO SWAP MEMORY TRAP @ PAGE %lu ***\n",
                            trap->memaccess.gfn);
                free(update_event);
                return 0;
            } else {
                PRINT_DEBUG("Successfully requested to swap events to permission %c%c%c!\n",
                            (update_event->mem_event.in_access & VMI_MEMACCESS_R) ? 'r' : '-',
                            (update_event->mem_event.in_access & VMI_MEMACCESS_W) ? 'w' : '-',
                            (update_event->mem_event.in_access & VMI_MEMACCESS_X) ? 'x' : '-'
                            );
                s->memaccess.memtrap = update_event;
            }
        }

        s->traps = g_slist_prepend(s->traps, trap);
        g_hash_table_insert(drakvuf->memaccess_lookup_trap, g_memdup(&trap, sizeof(void*)), s);
        return 1;
    } else {

        xen_unshare_gfn(drakvuf->xen, drakvuf->domID, trap->memaccess.gfn);

        s = g_malloc0(sizeof(struct wrapper));
        s->drakvuf = drakvuf;
        s->traps = g_slist_prepend(s->traps, trap);
        s->memaccess.gfn = trap->memaccess.gfn;

        /*
         * Guard2 types are protecting remapped gfns, thus when hit
         * these need to be swapped to the altp2m_idr view.
         */
        s->memaccess.guard2 = guard2;
        s->memaccess.memtrap = g_malloc0(sizeof(vmi_event_t));
        s->memaccess.memtrap->data = drakvuf;
        SETUP_MEM_EVENT(s->memaccess.memtrap, trap->memaccess.gfn<<12,
                        trap->memaccess.access, pre_mem_cb);
        s->memaccess.memtrap->vmm_pagetable_id = drakvuf->altp2m_idx;

        if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, s->memaccess.memtrap)) {
            PRINT_DEBUG("*** FAILED TO REGISTER MEMORY TRAP @ PAGE %lu ***\n",
                        trap->memaccess.gfn);
            free(s->memaccess.memtrap);
            g_slist_free(s->traps);
            free(s);
            return 0;
        }

        g_hash_table_insert(drakvuf->memaccess_lookup_gfn, g_memdup(&s->memaccess.gfn, sizeof(addr_t)), s);
        g_hash_table_insert(drakvuf->memaccess_lookup_trap, g_memdup(&trap, sizeof(void*)), s);
    }

    return 1;
}

bool inject_trap_pa(drakvuf_t drakvuf,
                    drakvuf_trap_t *trap,
                    addr_t pa)
{
    // check if already marked
    vmi_instance_t vmi = drakvuf->vmi;
    xen_pfn_t current_gfn = pa >> 12;
    struct wrapper *container = g_hash_table_lookup(drakvuf->breakpoint_lookup_pa, &pa);

    if (container) {
        g_hash_table_insert(drakvuf->breakpoint_lookup_trap,
                            g_memdup(&trap, sizeof(void*)),
                            container);
        container->traps = g_slist_prepend(container->traps, trap);

        GSList *traps = g_hash_table_lookup(drakvuf->breakpoint_lookup_gfn, &current_gfn);
        traps = g_slist_append(traps, &container->breakpoint.pa);

        return 1;
    }

    container = g_malloc0(sizeof(struct wrapper));

    container->drakvuf = drakvuf;
    container->traps = g_slist_prepend(container->traps, trap);
    container->breakpoint.pa = pa;
    container->breakpoint.guard.type = MEMACCESS;
    container->breakpoint.guard.memaccess.access = VMI_MEMACCESS_RW;
    container->breakpoint.guard.memaccess.type = PRE;
    container->breakpoint.guard.memaccess.gfn = current_gfn;

    if ( !inject_trap_mem(drakvuf, &container->breakpoint.guard, 0) ) {
        PRINT_DEBUG("Failed to create guard trap for the breakpoint!\n");
        return 0;
    }

    /* Let's see if we have already created the shadow copy of this page */
    struct remapped_gfn *remapped_gfn = g_hash_table_lookup(drakvuf->remapped_gfns, &current_gfn);

    if ( !remapped_gfn ) {
        remapped_gfn = g_malloc0(sizeof(struct remapped_gfn));
        remapped_gfn->o = current_gfn;

        int rc = xc_domain_setmaxmem(drakvuf->xen->xc, drakvuf->domID, drakvuf->memsize+VMI_PS_4KB);
        drakvuf->memsize+=VMI_PS_4KB;

        rc = xc_domain_increase_reservation_exact(drakvuf->xen->xc, drakvuf->domID, 1, 0, 0, &remapped_gfn->r);
        if (!rc)
            PRINT_DEBUG("Reservation increased? %u with new gfn: 0x%lx\n", rc, remapped_gfn->r);
        else
            return 0;

        rc = xc_domain_populate_physmap_exact(drakvuf->xen->xc, drakvuf->domID, 1, 0, 0, &remapped_gfn->r);
        if (rc)
            return 0;

        g_hash_table_insert(drakvuf->remapped_gfns,
                            &remapped_gfn->o,
                            remapped_gfn);
    }

    /*
     * The page may have been remapped previously but if it has no active traps
     * then the contents may be stale, so we copy it in that case just to make sure
     */
    if (!g_hash_table_lookup(drakvuf->breakpoint_lookup_gfn, &remapped_gfn->o) )
    {
        uint8_t backup[VMI_PS_4KB] = {0};
        if(VMI_PS_4KB != vmi_read_pa(drakvuf->vmi, current_gfn<<12, &backup, VMI_PS_4KB))
        {
            fprintf(stderr, "Copying trapped page to new location FAILED\n");
            return 0;
        }

        if ( VMI_PS_4KB == vmi_write_pa(drakvuf->vmi, remapped_gfn->r << 12, &backup, VMI_PS_4KB) )
            PRINT_DEBUG("Copied trapped page to new location\n");
        else {
            // TODO cleanup
            fprintf(stderr, "Copying trapped page to new location FAILED\n");
            return 0;
        }
    }

    container->breakpoint.guard2.type = MEMACCESS;
    container->breakpoint.guard2.memaccess.access = VMI_MEMACCESS_RW;
    container->breakpoint.guard2.memaccess.type = PRE;
    container->breakpoint.guard2.memaccess.gfn = remapped_gfn->r;

    if ( !inject_trap_mem(drakvuf, &container->breakpoint.guard2, 1) ) {
        PRINT_DEBUG("Failed to create guard2 trap for the breakpoint!\n");
        return 0;
    }

    if ( !remapped_gfn->active ) {
        PRINT_DEBUG("Activating remapped gfns in the altp2m views!\n");
        remapped_gfn->active = 1;

        xc_altp2m_change_gfn(drakvuf->xen->xc, drakvuf->domID,
                         drakvuf->altp2m_idx, current_gfn, remapped_gfn->r);
        xc_altp2m_change_gfn(drakvuf->xen->xc, drakvuf->domID,
                         drakvuf->altp2m_idr, remapped_gfn->r, drakvuf->zero_page_gfn);
    }

    addr_t rpa = (remapped_gfn->r<<12) + (container->breakpoint.pa & VMI_BIT_MASK(0,11));
    uint8_t test;

    if (VMI_FAILURE == vmi_read_8_pa(vmi, pa, &test))
    {
        PRINT_DEBUG("FAILED TO READ @ 0x%lx !\n", container->breakpoint.pa);
        return 0;
    }

    if (test == bp)
    {
        PRINT_DEBUG("Double-trap location @ 0x%lx !\n", container->breakpoint.pa);
        container->breakpoint.doubletrap = 1;
    }
    else
    {
        container->breakpoint.doubletrap = 0;

        if (VMI_FAILURE == vmi_write_8_pa(vmi, rpa, &bp))
        {
            PRINT_DEBUG("FAILED TO INJECT TRAP @ 0x%lx !\n", container->breakpoint.pa);
            return 0;
        }
    }

    // list of traps on this page
    GSList *traps = NULL;
    traps = g_slist_append(traps, &container->breakpoint.pa);

    // save trap location into lookup tree
    uint64_t _current_gfn = current_gfn;
    g_hash_table_insert(drakvuf->breakpoint_lookup_gfn, g_memdup(&_current_gfn, sizeof(uint64_t)),
                        traps);
    g_hash_table_insert(drakvuf->breakpoint_lookup_pa, g_memdup(&container->breakpoint.pa, sizeof(addr_t)),
                        container);
    g_hash_table_insert(drakvuf->breakpoint_lookup_trap, g_memdup(&trap, sizeof(void*)),
                        container);

    PRINT_DEBUG("\t\tTrap added @ PA 0x%" PRIx64 " RPA 0x%" PRIx64 " Page %" PRIu64 " for %s. \n",
                container->breakpoint.pa, rpa, pa >> 12, trap->name);
    return 1;
}

bool inject_trap(drakvuf_t drakvuf,
                 drakvuf_trap_t *trap,
                 addr_t vaddr,
                 vmi_pid_t pid)
{

    vmi_instance_t vmi = drakvuf->vmi;
    addr_t dtb = vmi_pid_to_dtb(vmi, pid);

    // get pa
    addr_t pa = 0;

    if (trap->breakpoint.addr_type == ADDR_VA)
        pa = vmi_pagetable_lookup(vmi, dtb, trap->breakpoint.addr);
    else
        pa = vmi_pagetable_lookup(vmi, dtb, vaddr + trap->breakpoint.rva);

    if (!pa)
        return 0;

    return inject_trap_pa(drakvuf, trap, pa);
}

bool inject_traps_modules(drakvuf_t drakvuf,
                          drakvuf_trap_t *trap,
                          addr_t list_head,
                          vmi_pid_t pid)
{
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t next_module = list_head;

    if (!trap)
        return 0;

    PRINT_DEBUG("Inject traps in module list of PID %u\n", pid);

    while (1) {

        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, pid, &tmp_next);

        if (list_head == tmp_next)
            break;

        addr_t dllbase = 0;
        vmi_read_addr_va(vmi, next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_DLLBASE], pid, &dllbase);

        if (!dllbase)
            break;

        unicode_string_t *us = vmi_read_unicode_str_va(vmi, next_module + drakvuf->offsets[LDR_DATA_TABLE_ENTRY_BASEDLLNAME], pid);
        unicode_string_t out = { .contents = NULL };

        if (us) {
            status_t status = vmi_convert_str_encoding(us, &out, "UTF-8");
            if(VMI_SUCCESS == status)
                PRINT_DEBUG("\t%s @ 0x%" PRIx64 "\n", out.contents, dllbase);

            vmi_free_unicode_str(us);
        }

        if(out.contents && !strcmp((char*)out.contents,trap->breakpoint.module)) {
            free(out.contents);
            return inject_trap(drakvuf, trap, dllbase, pid);
        }

        next_module = tmp_next;
    }

    return 0;
}

void drakvuf_loop(drakvuf_t drakvuf) {

    PRINT_DEBUG("Started DRAKVUF loop\n");

    drakvuf->interrupted = 0;
    drakvuf_force_resume(drakvuf);

    while (!drakvuf->interrupted) {
        //PRINT_DEBUG("Waiting for events in DRAKVUF...\n");
        status_t status = vmi_events_listen(drakvuf->vmi, 1000);

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

bool init_vmi(drakvuf_t drakvuf) {

    int rc;
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
        return 0;
    }
    g_hash_table_destroy(config);

    drakvuf->pm = vmi_get_page_mode(drakvuf->vmi);
    drakvuf->vcpus = vmi_get_num_vcpus(drakvuf->vmi);
    drakvuf->memsize = drakvuf->init_memsize = vmi_get_memsize(drakvuf->vmi);

    // Crete tables to lookup breakpoints
    drakvuf->breakpoint_lookup_pa =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, free, free);
    drakvuf->breakpoint_lookup_gfn =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);
    drakvuf->breakpoint_lookup_trap =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);
    drakvuf->memaccess_lookup_gfn =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, free, free);
    drakvuf->memaccess_lookup_trap =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);
    drakvuf->remapped_gfns =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, free);
    drakvuf->remove_traps =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);

    // Get the offsets from the Rekall profile
    unsigned int i;
    for (i = 0; i < OFFSET_MAX; i++) {
        if (VMI_FAILURE
                == drakvuf_get_struct_member_rva(
                        drakvuf->rekall_profile, offset_names[i][0],
                        offset_names[i][1], &drakvuf->offsets[i])) {
            PRINT_DEBUG("Failed to find offset for %s:%s\n", offset_names[i][0],
                    offset_names[i][1]);
        }
    }

    /*
     * Setup singlestep event handlers but don't turn on MTF.
     * Max 16 CPUs!
     */
    for (i = 0; i < drakvuf->vcpus && i < 16; i++) {
        drakvuf->step_event[i] = g_malloc0(sizeof(vmi_event_t));
        SETUP_SINGLESTEP_EVENT(drakvuf->step_event[i], 1u << i, vmi_reset_trap, 0);
        drakvuf->step_event[i]->data = drakvuf;
        if (VMI_FAILURE == vmi_register_event(drakvuf->vmi, drakvuf->step_event[i])) {
            fprintf(stderr, "Failed to register singlestep for vCPU %u\n", i);
            return 0;
        }
    }

    rc = xc_domain_setmaxmem(drakvuf->xen->xc, drakvuf->domID, drakvuf->memsize+VMI_PS_4KB);
    if ( rc ) {
        fprintf(stderr, "Failed to increase max memory\n");
        return 0;
    }

    drakvuf->memsize+=VMI_PS_4KB;

    rc = xc_domain_increase_reservation_exact(drakvuf->xen->xc, drakvuf->domID, 1, 0, 0, &drakvuf->zero_page_gfn);
    if (!rc)
        PRINT_DEBUG("Reservation increased? %u with new gfn: 0x%lx\n", rc, drakvuf->zero_page_gfn);
    else
        return 0;

    rc = xc_domain_populate_physmap_exact(drakvuf->xen->xc, drakvuf->domID, 1, 0, 0, &drakvuf->zero_page_gfn);
    if (rc)
        return 0;

    /*
     * Create altp2m view
     */
    rc = xc_altp2m_set_domain_state(drakvuf->xen->xc, drakvuf->domID, 1);
    if ( rc < 0 )
    {
        fprintf(stderr, "Failed to enable altp2m on domain!\n");
        return 0;
    }

    /*
     * The idx view is used primarily during DRAKVUF execution. In this view all breakpointed
     * pages will have their shadow copies activated.
     */
    rc = xc_altp2m_create_view( drakvuf->xen->xc, drakvuf->domID, 0, &drakvuf->altp2m_idx );
    if ( rc < 0 )
    {
        fprintf(stderr, "Failed to create altp2m view\n");
        return 0;
    }

    /*
     * TODO: We will use the idr view to map all shadow pages to the zero (empty) page in case
     * something is trying to check the contents of these pages. However, since all shadow pages
     * will point to the zero page, if someone writes to one, the change will appear through the
     * other shadow pages as well, thus potentially revealing the presence of DRAKVUF. This can
     * be avoided if we cache all pages separately that have been written to and use emulate with
     * custom read data to only return the change in the page on the gfn it was written to.
     */
    rc = xc_altp2m_create_view( drakvuf->xen->xc, drakvuf->domID, 0, &drakvuf->altp2m_idr );
    if ( rc < 0 )
    {
        fprintf(stderr, "Failed to create altp2m view\n");
        return 0;
    }
    PRINT_DEBUG("Xen altp2m view created with idx: %u idr: %u\n", drakvuf->altp2m_idx, drakvuf->altp2m_idr);

    SETUP_INTERRUPT_EVENT(&drakvuf->interrupt_event, 0, int3_cb);
    drakvuf->interrupt_event.data = drakvuf;

    if(VMI_FAILURE == vmi_register_event(drakvuf->vmi, &drakvuf->interrupt_event)) {
        fprintf(stderr, "Failed to register interrupt event\n");
        return 0;
    }

    SETUP_REG_EVENT(&drakvuf->cr3_event, CR3, VMI_REGACCESS_W, 0, cr3_cb);
    drakvuf->cr3_event.data = drakvuf;

    if(VMI_FAILURE == vmi_register_event(drakvuf->vmi, &drakvuf->cr3_event)) {
        fprintf(stderr, "Failed to register CR3 event\n");
        return 0;
    }

    rc = xc_altp2m_switch_to_view(drakvuf->xen->xc, drakvuf->domID, drakvuf->altp2m_idx);
    if ( rc < 0 ) {
        fprintf(stderr, "Failed to switch to altp2m view %u\n", drakvuf->altp2m_idx);
        return 0;
    }

    return 1;
}

// -------------------------- closing

void close_vmi(drakvuf_t drakvuf) {

    xen_pause(drakvuf->xen, drakvuf->domID);

    /*
     * Make sure all memaccess events are on altp2m_idx
     * so that vmi_destroy can properly reset the permissions.
     */
    if(drakvuf->memaccess_lookup_gfn) {
        GHashTableIter i;
        addr_t *key = NULL;
        struct wrapper *s = NULL;
        ghashtable_foreach(drakvuf->memaccess_lookup_gfn, i, key, s)
            s->memaccess.memtrap->vmm_pagetable_id = drakvuf->altp2m_idx;
    }

    if (drakvuf->vmi) {
        vmi_destroy(drakvuf->vmi);
        drakvuf->vmi = NULL;
    }

    if(drakvuf->breakpoint_lookup_gfn) {
        GHashTableIter i;
        uint64_t *key = NULL;
        GSList *list = NULL;
        ghashtable_foreach(drakvuf->breakpoint_lookup_gfn, i, key, list)
            g_slist_free(list);
        g_hash_table_destroy(drakvuf->breakpoint_lookup_gfn);
    }

    if(drakvuf->breakpoint_lookup_pa) {
        GHashTableIter i;
        addr_t *key = NULL;
        struct wrapper *s = NULL;
        ghashtable_foreach(drakvuf->breakpoint_lookup_pa, i, key, s)
            g_slist_free(s->traps);
        g_hash_table_destroy(drakvuf->breakpoint_lookup_pa);
    }

    if(drakvuf->memaccess_lookup_gfn) {
        GHashTableIter i;
        addr_t *key = NULL;
        struct wrapper *s = NULL;
        ghashtable_foreach(drakvuf->memaccess_lookup_gfn, i, key, s)
        {
            xc_altp2m_change_gfn(drakvuf->xen->xc, drakvuf->domID, drakvuf->altp2m_idx, s->memaccess.gfn, ~0);
            free(s->memaccess.memtrap);
            g_slist_free(s->traps);
        }
        g_hash_table_destroy(drakvuf->memaccess_lookup_gfn);
    }

    if(drakvuf->remapped_gfns) {
        GHashTableIter i;
        xen_pfn_t *key;
        struct remapped_gfn *remapped_gfn = NULL;
        ghashtable_foreach(drakvuf->remapped_gfns, i, key, remapped_gfn) {
            xc_altp2m_change_gfn(drakvuf->xen->xc, drakvuf->domID, drakvuf->altp2m_idx, remapped_gfn->o, ~0);
            xc_altp2m_change_gfn(drakvuf->xen->xc, drakvuf->domID, drakvuf->altp2m_idr, remapped_gfn->r, ~0);
            xc_domain_decrease_reservation_exact(drakvuf->xen->xc, drakvuf->domID, 1, 0, &remapped_gfn->r);
        }
        g_hash_table_destroy(drakvuf->remapped_gfns);
    };

    if(drakvuf->breakpoint_lookup_trap)
        g_hash_table_destroy(drakvuf->breakpoint_lookup_trap);
    if(drakvuf->remove_traps)
        g_hash_table_destroy(drakvuf->remove_traps);

    unsigned int i3;
    for (i3 = 0; i3 < drakvuf->vcpus; i3++) {
        free(drakvuf->step_event[i3]);
    }

    xc_altp2m_switch_to_view(drakvuf->xen->xc, drakvuf->domID, 0);
    if(drakvuf->altp2m_idx)
        xc_altp2m_destroy_view(drakvuf->xen->xc, drakvuf->domID, drakvuf->altp2m_idx);
    if(drakvuf->altp2m_idr)
        xc_altp2m_destroy_view(drakvuf->xen->xc, drakvuf->domID, drakvuf->altp2m_idr);
    xc_altp2m_set_domain_state(drakvuf->xen->xc, drakvuf->domID, 0);

    if(drakvuf->zero_page_gfn)
        xc_domain_decrease_reservation_exact(drakvuf->xen->xc, drakvuf->domID, 1, 0, &drakvuf->zero_page_gfn);
    xc_domain_setmaxmem(drakvuf->xen->xc, drakvuf->domID, drakvuf->init_memsize);

    xen_resume(drakvuf->xen, drakvuf->domID);

    PRINT_DEBUG("close_vmi_drakvuf finished\n");
}
