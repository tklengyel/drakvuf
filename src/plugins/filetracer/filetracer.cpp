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

/*
 * 1) ExAllocatePoolWithTag: is it a FILE?
 *   - YES: breakpoint RSP
 * 2) RSP: RAX -> _FILE_OBJECT
 *    - MEMTRAP W location
 * 3) MEMTRAP: is it at FileName string buffer?
 *    - YES: read string and remove trap
 */

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
#include "plugins/plugins.h"
#include "private.h"
#include "filetracer.h"

#define POOLTAG_FILE "Fil\xe5"
#define ALIGN_SIZE(alignment, size) \
    ( (size % alignment) ? (alignment - (size % alignment)) : 0 )

struct rettrap_struct {
    filetracer *f;
    drakvuf_trap_t *trap;
    unsigned long counter;
};

struct file_watch {
    filetracer *f;
    addr_t file_name_buffer;
    addr_t file_name_length;
};

void free_writetrap(drakvuf_trap_t *trap) {
    //printf("Freeing writetrap @ %p\n", trap);
    filetracer *f = (filetracer *)trap->data;
    f->writetraps = g_slist_remove(f->writetraps, trap);
    free(trap);
}

static event_response_t file_name_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    struct file_watch *watch = (struct file_watch*)info->trap->data;
    filetracer *f = watch->f;

    if (info->trap_pa == watch->file_name_buffer)
    {
        addr_t file_name = 0;
        uint16_t length = 0;
        vmi_read_addr_pa(vmi, watch->file_name_buffer, &file_name);
        vmi_read_16_pa(vmi, watch->file_name_length, &length);

        //printf("File name @ 0x%lx. Length: %u\n", file_name, length);

        if (file_name && length > 0 && length < VMI_PS_4KB) {
            char *procname = drakvuf_get_current_process_name(drakvuf, info->vcpu, info->regs);
            unicode_string_t str = { .contents = NULL };
            str.length = length;
            str.encoding = "UTF-16";
            str.contents = (unsigned char *)g_malloc0(length);
            vmi_read_va(vmi, file_name, 0, str.contents, length);
            unicode_string_t str2 = { .contents = NULL };
            status_t rc = vmi_convert_str_encoding(&str, &str2, "UTF-8");

            if (VMI_SUCCESS == rc) {

                switch(f->format) {
                case OUTPUT_CSV:
                    printf("filetracer,%" PRIu32 ",0x%" PRIx64 ",%s,%s\n",
                           info->vcpu, info->regs->cr3, procname, str2.contents);
                    break;
                default:
                case OUTPUT_DEFAULT:
                    printf("[FILETRACER] VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",%s %s\n",
                           info->vcpu, info->regs->cr3, procname, str2.contents);
                    break;
                };

                g_free(str2.contents);
            }

            free(str.contents);
            free(procname);
            //printf("Requesting to free writetrap @ %p\n", info->trap);
            info->trap->data=f;
            drakvuf_remove_trap(drakvuf, info->trap, free_writetrap);
        }
    }

    drakvuf_release_vmi(drakvuf);
    return 0;
}

/* This will be hit for all sorts of heap alloc returns */
static event_response_t pool_alloc_return(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    struct rettrap_struct *s = (struct rettrap_struct *)info->trap->data;
    filetracer *f = s->f;
    addr_t obj_pa = vmi_pagetable_lookup(vmi, info->regs->cr3, info->regs->rax);
    bool file_alloc = 0;
    addr_t ph_base = 0, thread = 0;
    uint32_t block_size = 0;
    uint32_t tag;
    uint32_t aligned_file_size = f->file_object_size;

    if ( f->pm == VMI_PM_IA32E ) {
        struct pool_header_x64 ph;
        memset(&ph, 0, sizeof(struct pool_header_x64));
        ph_base = obj_pa - sizeof(struct pool_header_x64);
        vmi_read_pa(vmi, ph_base, &ph, sizeof(struct pool_header_x64));
        block_size = ph.block_size * 0x10; // align it
        if(!memcmp(&ph.pool_tag, &POOLTAG_FILE, 4))
            file_alloc = 1;
    } else {
        struct pool_header_x86 ph;
        memset(&ph, 0, sizeof(struct pool_header_x86));
        ph_base = obj_pa - sizeof(struct pool_header_x86);
        vmi_read_pa(vmi, ph_base, &ph, sizeof(struct pool_header_x86));
        block_size = ph.block_size * 0x8; // align it
        if(!memcmp(&ph.pool_tag, &POOLTAG_FILE, 4))
            file_alloc = 1;
    }

    if (!file_alloc) {
        drakvuf_release_vmi(drakvuf);
        return 0;
    }

    // We will need to catch when the file string buffer pointer is updated
    addr_t file_base = ph_base + block_size - f->file_object_size; // addr of "_FILE_OBJECT"
    addr_t file_name = file_base + f->file_name_offset; // addr of "_UNICODE_STRING"

    struct file_watch *watch = (struct file_watch *)g_malloc0(sizeof(struct file_watch));
    watch->f = f;
    watch->file_name_buffer = file_name + f->string_buffer_offset;
    watch->file_name_length = file_name + f->string_length_offset;

    //printf("PH 0x%lx. Block size: %u\n", ph_base, block_size);
    //printf("File size: 0x%lx File base: 0x%lx. Unicode string @ 0x%lx. Last write @ 0x%lx\n",
    //       f->file_object_size, file_base, file_name-file_base, watch->file_name_buffer-file_base);

    drakvuf_trap_t *writetrap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    writetrap->memaccess.access = VMI_MEMACCESS_W;
    writetrap->memaccess.type = POST;
    writetrap->memaccess.gfn = watch->file_name_buffer >> 12;
    writetrap->cb = file_name_cb;
    writetrap->data = watch;
    writetrap->type = MEMACCESS;

    f->writetraps = g_slist_prepend(f->writetraps, writetrap);

    if (!drakvuf_add_trap(drakvuf, writetrap))
        fprintf(stderr, "[FILETRACER] Error: failed to add write memaccess trap!\n");

    s->counter--;

    /*
    if(s->counter == 0) {
        drakvuf_remove_trap(drakvuf, info->trap, free);
        g_hash_table_remove(rettraps, &s->trap->u2.addr);
        free(s);
    }*/

    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {

    filetracer *f = (filetracer*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    reg_t tag = 0, size = 0;

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    if (f->pm == VMI_PM_IA32E) {
        size = info->regs->rdx;
        tag = info->regs->r8;
    } else {
        ctx.addr = info->regs->rsp+8;
        vmi_read_32(vmi, &ctx, (uint32_t*)&size);
        ctx.addr = info->regs->rsp+12;
        vmi_read_32(vmi, &ctx, (uint32_t*)&tag);
    }

    /*printf("Got a heap alloc request for tag %c%c%c%c!\n",
           ((uint8_t*)&tag)[0],
           ((uint8_t*)&tag)[1],
           ((uint8_t*)&tag)[2],
           ((uint8_t*)&tag)[3]
    );*/

    if(!memcmp(&tag, &POOLTAG_FILE, 4)) {

        addr_t ret, ret_pa;
        ctx.addr = info->regs->rsp;
        vmi_read_addr(vmi, &ctx, &ret);
        ret_pa = vmi_pagetable_lookup(vmi, info->regs->cr3, ret);

        struct rettrap_struct *s = (struct rettrap_struct*)g_hash_table_lookup(f->rettraps, &ret_pa);
        if (s) {
            s->counter++;
        } else {
            drakvuf_trap_t *rettrap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
            s = (struct rettrap_struct*)g_malloc0(sizeof(struct rettrap_struct));
            s->trap = rettrap;
            s->counter = 1;
            s->f = f;

            rettrap->breakpoint.lookup_type = LOOKUP_NONE;
            rettrap->breakpoint.addr_type = ADDR_PA;
            rettrap->breakpoint.addr = ret_pa;
            rettrap->type = BREAKPOINT;
            rettrap->name = "HeapRetTrap";
            rettrap->cb = pool_alloc_return;
            rettrap->data = s;

            drakvuf_add_trap(drakvuf, rettrap);
            g_hash_table_insert(f->rettraps, &rettrap->breakpoint.addr, s);
        }

        //printf("File alloc request on vCPU %u. Ret: 0x%lx. Counter: %lu\n",
        //         info->vcpu, ret_pa, s->counter);
    }

    drakvuf_release_vmi(drakvuf);
    return 0;
}

/* ----------------------------------------------------- */

filetracer::filetracer(drakvuf_t drakvuf, const void* config, output_format_t output) {
    const char *rekall_profile = (const char *)config;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->pm = vmi_get_page_mode(vmi);
    drakvuf_release_vmi(drakvuf);
    this->rettraps = g_hash_table_new(g_int64_hash, g_int64_equal);
    this->format = output;

    this->poolalloc.breakpoint.lookup_type = LOOKUP_PID;
    this->poolalloc.breakpoint.pid = 4;
    this->poolalloc.breakpoint.addr_type = ADDR_RVA;
    this->poolalloc.breakpoint.module = "ntoskrnl.exe";
    this->poolalloc.name = "ExAllocatePoolWithTag";
    this->poolalloc.type = BREAKPOINT;
    this->poolalloc.cb = cb;
    this->poolalloc.data = (void*)this;

    if (VMI_FAILURE == drakvuf_get_function_rva(rekall_profile, "ExAllocatePoolWithTag", &this->poolalloc.breakpoint.rva))
        return;
    if (VMI_FAILURE == drakvuf_get_struct_member_rva(rekall_profile, "_FILE_OBJECT", "FileName", &this->file_name_offset))
        return;
    if (VMI_FAILURE == drakvuf_get_struct_member_rva(rekall_profile, "_UNICODE_STRING", "Buffer", &this->string_buffer_offset))
        return;
    if (VMI_FAILURE == drakvuf_get_struct_member_rva(rekall_profile, "_UNICODE_STRING", "Length", &this->string_length_offset))
        return;
    if (VMI_FAILURE == drakvuf_get_struct_size(rekall_profile, "_FILE_OBJECT", &this->file_object_size))
        return;

    if (this->pm == VMI_PM_IA32E)
        this->file_object_size += ALIGN_SIZE(16, this->file_object_size);
    else
        this->file_object_size += ALIGN_SIZE(8, this->file_object_size);

    if ( !drakvuf_add_trap(drakvuf, &this->poolalloc) )
        throw -1;
}

filetracer::~filetracer() {

    GSList *loop = this->writetraps;
    while(loop) {
        free(loop->data);
        loop=loop->next;
    }
    g_slist_free(this->writetraps);

    if ( this->rettraps )
        g_hash_table_destroy(this->rettraps);
}
