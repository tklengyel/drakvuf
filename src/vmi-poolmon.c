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
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dirent.h>
#include <glib.h>
#include <err.h>

#include <libvmi/libvmi.h>

#include "vmi.h"
#include "vmi-poolmon.h"
#include "file_extractor.h"

#define POOLTAG_FILE "Fil\xe5"

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
void objcreate(vmi_instance_t vmi, vmi_event_t *event, reg_t cr3) {

    uint8_t index = ~0;
    reg_t obj_header_addr;
    vmi_get_vcpureg(vmi, &obj_header_addr, RDX, event->vcpu_id);

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3,
        .addr = obj_header_addr + offsets[OBJECT_HEADER_TYPEINDEX]
    };

    vmi_read_8(vmi, &ctx, &index);

    if (index < WIN7_TYPEINDEX_LAST) {
        printf("\tObject: %s\n", win7_typeindex[index]);
    } else {
        printf("\tUnknown object type index: %u\n", index);
    }
}

void pool_tracker(vmi_instance_t vmi, vmi_event_t *event, reg_t cr3,
        const char *ts) {

    honeymon_clone_t *clone = event->data;
    uint8_t trap = TRAP;
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3
    };

    // get the inputs of the function
    reg_t pool_type, size, tag, rsp;
    vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);

    // get the inputs of the function
    if (PM2BIT(clone->pm) == BIT32) {
        ctx.addr = rsp+12;
        vmi_read_32(vmi, &ctx, (uint32_t*)&tag);
        ctx.addr = rsp+8;
        vmi_read_32(vmi, &ctx, (uint32_t*)&size);
        ctx.addr = rsp+4;
        vmi_read_32(vmi, &ctx, (uint32_t*)&pool_type);
    } else {
        vmi_get_vcpureg(vmi, &pool_type, RCX, event->vcpu_id);
        vmi_get_vcpureg(vmi, &size, RDX, event->vcpu_id);
        vmi_get_vcpureg(vmi, &tag, R8, event->vcpu_id);
    }

    char ctag[5];
    memcpy(ctag, &tag, 4);
    ctag[4] = '\0';

    // Get the return address of the function
    // It is pushed on the stack
    // and RSP is pointing at it right now as a VA
    addr_t ret_va = 0;
    ctx.addr = rsp;
    vmi_read_addr(vmi, &ctx, &ret_va);
    addr_t ret_pa = vmi_pagetable_lookup(vmi, cr3, ret_va);

    struct pooltag *s = g_tree_lookup(clone->pooltags, ctag);

    if (s) {
        printf(
                "Heap allocation with known pool tag: '%s' (%u), %s, %s.\n",
                ctag, (uint32_t)tag, s->source, s->description);
    } else {
        printf(
                "Heap allocation with unknown pool tag: '%s' \\x%x\\x%x\\x%x\\x%x\n",
                ctag, ctag[0], ctag[1], ctag[2], ctag[3]);
    }

    // Only trap the return of File allocations for now
    if (strncmp(ctag, POOLTAG_FILE, 4))
        return;

    uint8_t backup = 0;

    GHashTable *pool_rets = g_hash_table_lookup(clone->pool_lookup, &ret_pa);
    //Return is already trapped
    //This can happen if the allocation is context-switched before returning
    if (pool_rets) {
        struct memevent *test = g_hash_table_lookup(pool_rets, &cr3);
        if (test) {
            test->pool.count++;
            printf(
                    "Pool allocation double called by the same process with CR3 0x%lx. Count %u\n",
                    cr3, test->pool.count);
            return;
        } else {
            GHashTableIter i;
            addr_t *key = NULL;
            struct memevent *container = NULL;
            ghashtable_foreach(pool_rets, i, key, container)
            {
                printf("Return was already trapped by 0x%lx\n",
                        container->pool.cr3);
                backup = container->pool.backup;
                break;
            }
        }
    } else {
        vmi_read_8_pa(vmi, ret_pa, &backup);
    }

    if (backup == trap) {
        printf("Backup byte is TRAP, TODO\n");
        return;
    }

    struct memevent *container = malloc(sizeof(struct memevent));
    container->pool.count = 1;
    container->pool.tag = tag;
    container->pool.size = size;
    container->pool.cr3 = cr3;
    container->vmi = vmi;
    container->pa = ret_pa;
    container->pool.backup = backup;

    // trap the return
    //printf("Trapping pool allocation return @ 0x%lx\n", container->pa);
    vmi_write_8_pa(vmi, container->pa, &trap);

    // Setup memory guard
    container->guard = vmi_get_mem_event(vmi, container->pa, VMI_MEMEVENT_PAGE);
    if (!container->guard) {
        container->guard = g_malloc0(sizeof(vmi_event_t));
        SETUP_MEM_EVENT(container->guard, container->pa, VMI_MEMEVENT_PAGE,
                VMI_MEMACCESS_RW, trap_guard);
        if (VMI_FAILURE == vmi_register_event(vmi, container->guard)) {
            free(container->guard);
            free(container);
            return;
        }
        container->guard->data = g_hash_table_new(g_int64_hash, g_int64_equal);
    }

    // Save the return
    if (!pool_rets) {
        pool_rets = g_hash_table_new(g_int64_hash, g_int64_equal);
        g_hash_table_insert(clone->pool_lookup, g_memdup(&container->pa, 8),
                pool_rets);
    }

    g_hash_table_insert(pool_rets, &container->pool.cr3, container);

    GHashTable *test = g_hash_table_lookup(container->guard->data,
            &container->pa);
    if (!test) {
        g_hash_table_insert(container->guard->data, &container->pa, container);
    }

}

void pool_tracker_free(vmi_instance_t vmi, vmi_event_t *event) {
    // TODO: 32-bit inputs are on the stack
    reg_t rcx, rdx;
    vmi_get_vcpureg(vmi, &rcx, RCX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rdx, RDX, event->vcpu_id);

    char ctag[5] = { [0 ... 4] = '\0' };
    memcpy(ctag, &rdx, 4);
    printf("\t Freeing pool allocation @ 0x%lx. Tag '%s'\n", rcx, ctag);
}

static inline
uint32_t get_bits_9to0 (uint32_t value)
{
    return value & 0x000003FFUL;
}

static inline
uint32_t get_bits_23to16 (uint32_t value)
{
    return value & 0x00FF0000UL;
}

/*
 * The memory allocated by ExAllocatePoolWithTag is unitialized.
 * The only header that has been created is the _POOL_HEADER
 * located right before the address that has been returned in RAX.
 * For regular allocations the _POOL_HEADER will be followed by
 * optional object headers. The actual object will be at the
 * bottom of the allocation (base of _POOL_HEADER + pool block size - sizeof(object));
 * We need to grab the block size from the _POOL_HEADER and work our
 * way back from there.
 *
 * See: http://www.codemachine.com/article_objectheader.html
 *
 * With Windows 8 this approach will need to be reexamined.
 */
void pool_alloc_return(vmi_instance_t vmi, vmi_event_t *event, addr_t pa,
        reg_t cr3, const char *ts, GHashTable *s) {

    honeymon_clone_t *clone = event->data;

    reg_t rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);

    struct memevent *container = g_hash_table_lookup(s, &cr3);
    struct pool_lookup *pool = container ? &container->pool : NULL;

    if (pool) {
        // Lets take a look at the allocated _POOL_HEADER
        addr_t obj_pa = vmi_pagetable_lookup(vmi, cr3, rax);
        if (!rax || !obj_pa) {
            goto done;
        }

        //printf("Object allocated on heap @ VA 0x%lx -> PA 0x%lx. Size: %u\n",
        //        rax, obj_pa, pool->size);

        // For small pool allocations we check if the header is attached
        if (pool->size < VMI_PS_4KB) {
            uint32_t block_size = 0;
            uint32_t tag = 0;

            //printf("Allocation in normal pool\n");

            addr_t ph_base = obj_pa - struct_sizes[POOL_HEADER];
            vmi_read_32_pa(vmi, ph_base + offsets[POOL_HEADER_POOLTAG], &tag);

            if (PM2BIT(clone->pm) == BIT32) {
                struct pool_header_x86 ph = { .flags = 0 };
                vmi_read_pa(vmi, ph_base, &ph, sizeof(struct pool_header_x86));
                block_size = ph.block_size * 0x8; // align it
            } else {
                struct pool_header_x64 ph = { .flags = 0 };
                vmi_read_pa(vmi, ph_base, &ph, sizeof(struct pool_header_x64));
                block_size = ph.block_size * 0x10; // align it
            }

            if ((uint32_t)tag != pool->tag) {
                printf(
                        "%s --!! Pool tag mangling detected: got '%c%c%c%c', expected '%c%c%c%c' !!--\n",
                        ts, ((char *)&tag)[0], ((char *)&tag)[1], ((char *)&tag)[2], ((char *)&tag)[3],
                        pool->ctag[0], pool->ctag[1], pool->ctag[2], pool->ctag[3]);
            } else {
                printf("\t'%c%c%c%c' heap allocation verified @ PA 0x%lx. Size: %u\n",
                        pool->ctag[0], pool->ctag[1], pool->ctag[2], pool->ctag[3], obj_pa, block_size);

                if (!strncmp(pool->ctag, POOLTAG_FILE, 4)) {
                    setup_file_watch(clone, vmi, rax, ph_base, block_size);
                }
            }
        } else {
            // TODO: Allocation happened in the big pool
            printf("Allocation in big pool: %u >= %u\n", pool->size, VMI_PS_4KB);
        }

        done:

        //printf("Pool allocation return placing backup 0x%x\n", pool->backup);
        vmi_write_8_pa(vmi, pa, &pool->backup);

        pool->count--;
        if (pool->count) {
            vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
            return;
        }

        g_hash_table_remove(s, &cr3);
        if (!g_hash_table_size(s)) {
            vmi_event_t *guard = vmi_get_mem_event(vmi, pa, VMI_MEMEVENT_PAGE);
            if (guard) {
                g_hash_table_remove(guard->data, &pa);
                if (!g_hash_table_size(guard->data)) {
                    g_hash_table_destroy(guard->data);
                    vmi_clear_event(vmi, guard);
                    free(guard);
                }
            }

            g_hash_table_remove(clone->pool_lookup, &pa);
            g_hash_table_destroy(s);
        }

        free(container);
    } else {

        //printf("Unknown pool return with CR3 0x%lx @ 0x%lx\n", cr3, pa);
        GHashTableIter i;
        addr_t *key = NULL;
        ghashtable_foreach(s, i, key, container)
        {
            //printf("\t Have CR3 0x%lx\n", *key);
            vmi_write_8_pa(vmi, pa, &container->pool.backup);
        }
    }
}
