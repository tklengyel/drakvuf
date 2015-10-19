/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014 Tamas K Lengyel.       *
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

#include "drakvuf.h"
#include "win-symbols.h"
#include "vmi.h"
#include "vmi-poolmon.h"
#include "file_extractor.h"
#include "xen_helper.h"
#include "rdtsc.h"
#include "output.h"

static uint64_t read_count, write_count, x_count;

// This is the callback when an int3 or a read event happens
event_response_t vmi_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {

    /*reg_t tsc, deltatsc;
     deltatsc = rdtsc();
     vmi_get_vcpureg(vmi, &tsc, TSC, event->vcpu_id);*/

    uint8_t trap = TRAP;
    addr_t pa;

    if (event->type == VMI_EVENT_INTERRUPT) {
        pa = (event->interrupt_event.gfn << 12) + event->interrupt_event.offset;
        //PRINT_DEBUG("Resetting trap @ 0x%lx.\n", pa);
        vmi_write_8_pa(vmi, pa, &trap);
    } else {

        vmi_register_event(vmi, event);
        reg_t cr3;
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        pa = (event->mem_event.gfn << 12) + event->mem_event.offset;

        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
        ghashtable_foreach(containers, i, key, s)
        {
            if (pa > s->pa - 7 && pa <= s->pa + 7) {
                //PRINT_DEBUG("Violation @ 0x%lx. Resetting trap @ 0x%lx.\n", pa, s->pa);
                vmi_write_8_pa(vmi, s->pa, &trap);
            }
        }
    }

    //vmi_set_vcpureg(vmi, tsc+(rdtsc()-deltatsc), TSC, event->vcpu_id);
    return 0;
}

// This is the callback when an write event happens
event_response_t vmi_save_and_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {

    vmi_register_event(vmi, event);
    uint8_t trap = TRAP;
    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
    GHashTable *containers = event->data;
    GHashTableIter i;
    addr_t *key = NULL;
    struct memevent *s = NULL;
    ghashtable_foreach(containers, i, key, s)
    {
        if (s && s->sID == SYMBOLWRAP) {
            if (pa > s->pa - 7 && pa <= s->pa + 7) {
                //save the write
                vmi_read_8_pa(vmi, s->pa, &s->symbol.backup);
                //add trap back
                vmi_write_8_pa(vmi, s->pa, &trap);
            }
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
        struct memevent *s = NULL;
        ghashtable_foreach(containers, i, key, s) {
            if (s && s->sID == SYMBOLWRAP) {
                if (pa > s->pa - 7 && pa <= s->pa + 7) {
                    PRINT_DEBUG("** Mem event removing trap 0x%lx -> %s!%s\n", s->pa,
                            s->symbol.config->name, s->symbol.symbol->name);
                    vmi_write_8_pa(vmi, s->pa, &s->symbol.backup);
                }
            }
            if (s && s->sID == POOL_LOOKUP) {
                if (pa > s->pa - 7 && pa <= s->pa + 7) {
                    PRINT_DEBUG("** Mem event removing trap pool return 0x%lx\n",
                            s->pa);
                    vmi_write_8_pa(vmi, s->pa, &s->pool.backup);
                }
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
        struct memevent *s = NULL;
        ghashtable_foreach(containers, i, key, s) {
            /*PRINT_DEBUG("Write memaccess @ 0x%lx. Page %lu. Symbol: %s!%s\n", pa,
                    event->mem_event.gfn, s->symbol.config->name,
                    s->symbol.symbol->name);*/
            if (s && s->sID == SYMBOLWRAP) {
                if (pa > s->pa - 7 && pa <= s->pa) {
                    PRINT_DEBUG("** Mem event removing trap 0x%lx -> %s!%s\n", s->pa,
                            s->symbol.config->name, s->symbol.symbol->name);
                    vmi_write_8_pa(vmi, s->pa, &s->symbol.backup);
                }
            }
            if (s && s->sID == POOL_LOOKUP) {
                if (pa > s->pa - 7 && pa <= s->pa) {
                    PRINT_DEBUG("** Mem event removing trap 0x%lx\n", s->pa);
                    vmi_write_8_pa(vmi, s->pa, &s->pool.backup);
                }
            }
        }

        vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_save_and_reset_trap);
    }

    //vmi_set_vcpureg(vmi, tsc+(rdtsc()-deltatsc), TSC, event->vcpu_id);
    return 0;
}

event_response_t int3_cb(vmi_instance_t vmi, vmi_event_t *event) {

    /*reg_t tsc, deltatsc;
     deltatsc = rdtsc();
     vmi_get_vcpureg(vmi, &tsc, TSC, event->vcpu_id);*/

    reg_t cr3 = event->regs.x86->cr3;

    char *ts;
    NOW(&ts);

    drakvuf_t *drakvuf = event->data;
    addr_t pa = (event->interrupt_event.gfn << 12)
            + event->interrupt_event.offset;
    struct symbolwrap *s = g_hash_table_lookup(drakvuf->pa_lookup, &pa);

    if (s) {
        PRINT(drakvuf, INT3_CB_STRING,
              cr3, event->interrupt_event.gla,
              s->config->name, s->symbol->name);

        //if (!strcmp(s->config->name, "ntkrnlmp")
        //        || !strcmp(s->config->name, "ntkrpamp")) {

        if (!strncmp(s->symbol->name, "ObCreateObject", 14)) {
            objcreate(vmi, event, cr3);
        }

        if (!strncmp(s->symbol->name, "ExAllocatePoolWithTag", 21)
                || !strcmp(s->symbol->name, "ExAllocatePoolWithQuotaTag")

                ) {
            pool_tracker(vmi, event, cr3, ts);
        }

        if (!strcmp(s->symbol->name, "ExFreePoolWithTag")) {
            pool_tracker_free(vmi, event);
        }

        // Uncomment this to extract all files when their handle is closed
        /*if (!strcmp(s->symbol->name, "NtClose")) {
         // TODO x86
         reg_t handle;
         vmi_get_vcpureg(vmi, &handle, RCX, event->vcpu_id);
         grab_file_by_handle(drakvuf, event, cr3, handle);
         }*/

        if (!strcmp(s->symbol->name, "NtDeleteFile")
                || !strcmp(s->symbol->name, "ZwDeleteFile")
                || !strcmp(s->symbol->name, "NtSetInformationFile")
                || !strcmp(s->symbol->name, "ZwSetInformationFile")) {
            grab_file_before_delete(vmi, event, cr3, s);
        }
        //}

        // remove trap
        vmi_write_8_pa(vmi, pa, &s->backup);
        event->interrupt_event.reinject = 0;
        vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
    } else {
        GHashTable *pool_rets = g_hash_table_lookup(drakvuf->pool_lookup, &pa);
        if (pool_rets) {
            pool_alloc_return(vmi, event, pa, cr3, ts, pool_rets);
            event->interrupt_event.reinject = 0;
        } else {
            fprintf(stderr,
                    "%s Unknown Int3 event: CR3: 0x%"PRIx64" PA=0x%"PRIx64" RIP=0x%"PRIx64"\n",
                    ts, cr3, pa, event->interrupt_event.gla);
            event->interrupt_event.reinject = 1;
        }
    }

    g_free(ts);
    //vmi_set_vcpureg(vmi, tsc+(rdtsc()-deltatsc), TSC, event->vcpu_id);
    return 0;
}

void inject_traps_pe(drakvuf_t *drakvuf, addr_t vaddr, uint32_t pid) {

    vmi_instance_t vmi = drakvuf->vmi;

    // So that LibVMI can find the _EPROCESS appropriately in pid2dtb
    if(pid == 0) {
        pid = 4;
    }
    addr_t dtb = vmi_pid_to_dtb(vmi, pid);
    uint8_t trap = TRAP;

    uint32_t i = 0;
    uint64_t trapped = 0;

    for (; i < drakvuf->sym_config->sym_count; i++) {

        const struct symbol *symbol = &drakvuf->sym_config->syms[i];

        //Kernel
        if (
                strncmp(symbol->name, "ExAllocatePoolWithTag", 21)
                && strcmp(symbol->name, "ExAllocatePoolWithQuotaTag")
                //&& strncmp(symbol->name, "ObCreateObject", 14)
                //&& strcmp(symbol->name, "ExFreePoolWithTag")
                && strcmp(symbol->name, "NtSetInformationFile")
                && strcmp(symbol->name, "ZwSetInformationFile")
                &&
                strncmp(symbol->name, "Nt", 2)
                //&& strncmp(symbol->name, "Zw", 2)
            ) continue;

        // get pa
        addr_t pa = vmi_pagetable_lookup(vmi, dtb,
                vaddr + drakvuf->sym_config->syms[i].rva);

        if (!pa)
            continue;

        // check if already marked
        if (g_hash_table_lookup(drakvuf->pa_lookup, &pa))
            continue;

        // backup current byte
        uint8_t byte = 0;
        vmi_read_8_pa(vmi, pa, &byte);
        if (byte == TRAP) {
            PRINT_DEBUG("\n\n** SKIPPING, PA IS ALREADY TRAPPED @ 0x%lx %s!%s**\n\n",
                    pa, drakvuf->sym_config->name,
                    drakvuf->sym_config->syms[i].name);
            continue;
        }

        struct memevent *container = g_malloc0(sizeof(struct memevent));
        container->sID = SYMBOLWRAP;
        container->symbol.drakvuf = drakvuf;
        container->symbol.config = drakvuf->sym_config;
        container->symbol.symbol = symbol;
        container->symbol.backup = byte;
        container->pa = pa;
        container->vmi = vmi;
        container->guard = vmi_get_mem_event(vmi, pa, VMI_MEMEVENT_PAGE);

        // write trap
        // THIS AUTOMATICALLY UNSHARES THE PAGE
        // This has to happen before the MEMEVENT is registered because
        // the MFN is yet to be allocated on which we want the MEMEVENT set on
        if (VMI_FAILURE == vmi_write_8_pa(vmi, container->pa, &trap)) {
            PRINT_DEBUG("FAILED TO INJECT TRAP @ 0x%lx !\n", container->pa);
            continue;
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
                continue;
            }
            container->guard->data = g_hash_table_new(g_int64_hash,
                    g_int64_equal);
            PRINT_DEBUG("\t\tNew memory event trap set on page %lu\n", pa >> 12);
        } else {
            PRINT_DEBUG("\t\tMemory event trap already set on page %lu\n", pa >> 12);
        }

        struct memevent *test = g_hash_table_lookup(container->guard->data,
                &container->pa);
        if (!test) {
            g_hash_table_insert(container->guard->data, &container->pa,
                    container);
        } else if (test->sID == SYMBOLWRAP) {
            PRINT_DEBUG("Address is already guarded\n");
        } else {
            PRINT_DEBUG("Address is trapped by another feature! ERROR/TODO!\n");
        }

        // save trap location into lookup tree
        g_hash_table_insert(drakvuf->pa_lookup, g_memdup(&container->pa, 8),
                &container->symbol);

        trapped++;
        PRINT_DEBUG(
                "\t\tTrap added @ VA 0x%lx PA 0x%lx Page %lu for %s!%s. Backup: 0x%x.\n",
                vaddr + drakvuf->sym_config->syms[i].rva, container->pa,
                pa >> 12, drakvuf->sym_config->name,
                drakvuf->sym_config->syms[i].name,
                container->symbol.backup);
    }

    PRINT_DEBUG("\tInjected %lu traps into PID %i\n", trapped, pid);

}

void inject_traps_modules(drakvuf_t *drakvuf, addr_t list_head,
        vmi_pid_t pid) {

    PRINT_DEBUG("Inject traps in module list of PID %u\n", pid);

    vmi_instance_t vmi = drakvuf->vmi;

    addr_t next_module = list_head;

    while (1) {

        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, pid, &tmp_next);

        if (list_head == tmp_next) {
            break;
        }

        addr_t dllbase = 0;
        vmi_read_addr_va(vmi,
                next_module + offsets[LDR_DATA_TABLE_ENTRY_DLLBASE], pid,
                &dllbase);

        if (!dllbase) {
            return;
        }

        unicode_string_t *us = NULL;
        if (VMI_PM_IA32E == vmi_get_page_mode(vmi)) {
            us = vmi_read_unicode_str_va(vmi, next_module + 0x58, pid);
        } else {
            us = vmi_read_unicode_str_va(vmi, next_module + 0x2c, pid);
        }

        unicode_string_t out = { .contents = NULL };
        if (us && VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8")) {
            PRINT_DEBUG("\t%s @ 0x%lx\n", out.contents, dllbase);
        } // if
        if (us)
            vmi_free_unicode_str(us);

        if(out.contents) {
            //TODO: We only care about the kernel at this point
            if(!strcmp((char*)out.contents,"ntoskrnl.exe")) {
                inject_traps_pe(drakvuf, dllbase, pid);
            }
            free(out.contents);
        }

        next_module = tmp_next;
    };
}

void inject_traps(drakvuf_t *drakvuf) {

    vmi_instance_t vmi = drakvuf->vmi;
    vmi_pause_vm(vmi);

    // Loop kernel modules
    addr_t kernel_list_head;
    vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &kernel_list_head);
    inject_traps_modules(drakvuf, kernel_list_head, 0);

    addr_t current_process = 0, next_list_entry = 0;
    vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);

    addr_t list_head = current_process + offsets[EPROCESS_TASKS];
    addr_t current_list_entry = list_head;

    status_t status = vmi_read_addr_va(vmi, current_list_entry, 0,
            &next_list_entry);
    if (status == VMI_FAILURE) {
        PRINT_DEBUG(
                "Failed to read next pointer at 0x%"PRIx64" before entering loop\n",
                current_list_entry);
        return;
    }

    do {

        vmi_pid_t pid;
        uint32_t dtb;
        vmi_read_32_va(vmi, current_process + offsets[EPROCESS_PID], 0, (uint32_t*)&pid);
        vmi_read_32_va(vmi, current_process + offsets[EPROCESS_PDBASE], 0, &dtb);

        char *procname = vmi_read_str_va(vmi, current_process + offsets[EPROCESS_PNAME], 0);

        if (!procname) {
            goto exit;
        }

        PRINT(drakvuf, FOUND_PROCESS_STRING, pid, dtb, procname);

        free(procname);

        addr_t imagebase = 0, peb = 0, ldr = 0, modlist = 0;
        vmi_read_addr_va(vmi, current_process + offsets[EPROCESS_PEB], 0, &peb);
        vmi_read_addr_va(vmi, peb + offsets[PEB_IMAGEBASADDRESS], pid,
                &imagebase);
        vmi_read_addr_va(vmi, peb + offsets[PEB_LDR], pid, &ldr);
        vmi_read_addr_va(vmi, ldr + offsets[PEB_LDR_DATA_INLOADORDERMODULELIST],
                pid, &modlist);

        /* TODO We only trap the kernel for now. */
        /*if (pid != 4) {
            inject_traps_pe(drakvuf, imagebase, pid, NULL);
            inject_traps_modules(drakvuf, modlist, pid);
        }*/

        current_list_entry = next_list_entry;
        current_process = current_list_entry - offsets[EPROCESS_TASKS];

        /* follow the next pointer */

        status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            PRINT_DEBUG("Failed to read next pointer in loop at %"PRIx64"\n",
                    current_list_entry);
            return;
        }

    } while (next_list_entry != list_head);

exit:
    return;
}

void drakvuf_loop(drakvuf_t *drakvuf) {

    PRINT_DEBUG("Started DRAKVUF loop\n");

    drakvuf->interrupted = 0;

    vmi_event_t interrupt_event;
    memset(&interrupt_event, 0, sizeof(vmi_event_t));
    interrupt_event.type = VMI_EVENT_INTERRUPT;
    interrupt_event.interrupt_event.intr = INT3;
    interrupt_event.callback = int3_cb;
    interrupt_event.data = drakvuf;

    vmi_register_event(drakvuf->vmi, &interrupt_event);

    read_count = write_count = x_count = 0;

    vmi_resume_vm(drakvuf->vmi);
    drakvuf->timer = g_timer_new();

    gdouble elapsed;

    while (!drakvuf->interrupted) {
        //PRINT_DEBUG("Waiting for events in DRAKVUF...\n");
        status_t status = vmi_events_listen(drakvuf->vmi, 100);

        elapsed = g_timer_elapsed(drakvuf->timer, NULL);

        if ( VMI_SUCCESS != status ||
             (drakvuf->timeout > 0 && elapsed >= drakvuf->timeout)
           )
        {
            PRINT_DEBUG("Error waiting for events or timeout, quitting...\n");
            drakvuf->interrupted = -1;
        }
    }

    vmi_pause_vm(drakvuf->vmi);
    print_sharing_info(drakvuf->xen, drakvuf->domID);

    PRINT_DEBUG("DRAKVUF loop finished\n");
}

void init_vmi(drakvuf_t *drakvuf) {

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

    // Crete tables to lokup symbols from
    drakvuf->pa_lookup = g_hash_table_new_full(g_int64_hash, g_int64_equal, free,
            NULL);

    // Pool/file watcher tables
    drakvuf->pool_lookup = g_hash_table_new_full(g_int64_hash, g_int64_equal,
            free, NULL);
    drakvuf->file_watch = g_hash_table_new_full(g_int64_hash, g_int64_equal, free,
            NULL);

    // Get the offsets from the Rekall profile
    int i;
    for (i = 0; i < OFFSET_MAX; i++) {
        if (VMI_FAILURE
                == windows_system_map_symbol_to_address(
                        drakvuf->rekall_profile, offset_names[i][0],
                        offset_names[i][1], &offsets[i], NULL)) {
            PRINT_DEBUG("Failed to find offset for %s:%s\n", offset_names[i][0],
                    offset_names[i][1]);
        }
    }

    for (i = 0; i < SIZE_LIST_MAX; i++) {
        if (VMI_FAILURE
                == windows_system_map_symbol_to_address(
                        drakvuf->rekall_profile, size_names[i],
                        (char *) &i, NULL, &struct_sizes[i])) {
            PRINT_DEBUG("Failed to find offset for %s:%s\n", offset_names[i][0],
                    offset_names[i][1]);
            continue;
        }
    }
}

// -------------------------- closing

void close_vmi(drakvuf_t *drakvuf) {

    vmi_instance_t vmi = drakvuf->vmi;
    do {
        GHashTableIter i;
        addr_t *key = NULL;
        struct symbolwrap *s = NULL;
        ghashtable_foreach(drakvuf->pa_lookup, i, key, s)
        {
            vmi_event_t *guard = vmi_get_mem_event(vmi, *key,
                    VMI_MEMEVENT_PAGE);
            if (guard) {
                GHashTableIter i2;
                addr_t *key2 = NULL;
                struct memevent *container = NULL;
                ghashtable_foreach(guard->data, i2, key2, container) {
                    if (container->sID == SYMBOLWRAP) {
                        vmi_write_8_pa(drakvuf->vmi, container->pa,
                                &container->symbol.backup);
                        free(container);
                    }
                }
                vmi_clear_event(vmi, guard);
                g_hash_table_destroy(guard->data);
                free(guard);
            }
        }
    } while (0);
    g_hash_table_destroy(drakvuf->pa_lookup);

    do {
        GHashTableIter i;
        addr_t *key = NULL;
        GHashTable *s = NULL;
        ghashtable_foreach(drakvuf->pool_lookup, i, key, s)
        {
            vmi_event_t *guard = vmi_get_mem_event(vmi, *key,
                    VMI_MEMEVENT_PAGE);
            if (guard) {
                GHashTableIter i2;
                addr_t *key2 = NULL;
                struct memevent *container = NULL;
                ghashtable_foreach(guard->data, i2, key2, container) {
                    if (container->sID == POOL_LOOKUP) {
                        vmi_write_8_pa(drakvuf->vmi, container->pa,
                                &container->pool.backup);
                    }
                }
                g_hash_table_destroy(guard->data);
                vmi_clear_event(vmi, guard);
                free(guard);
            }

            GHashTableIter i2;
            addr_t *key2 = NULL;
            struct memevent *container = NULL;
            ghashtable_foreach(s, i2, key2, container) {
                free(container);
            }
            g_hash_table_destroy(s);
        }
    } while (0);

    g_hash_table_destroy(drakvuf->pool_lookup);
    g_hash_table_destroy(drakvuf->file_watch);

    if (drakvuf->timer) {
        g_timer_destroy(drakvuf->timer);
        drakvuf->timer = NULL;
    }

    if (drakvuf->vmi) {
        vmi_destroy(drakvuf->vmi);
        drakvuf->vmi = NULL;
    }
    PRINT_DEBUG("close_vmi_drakvuf finished\n");
}
