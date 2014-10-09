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
#include <error.h>
#include <stdio.h>
#include <glib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "structures.h"
#include "vmi.h"
#include "win-handles.h"

#define VOL_DUMPFILES "%s %s -l vmi://domid/%u --profile=%s -Q %lu -D /tmp -n dumpfiles 2>&1"
#define PROFILE32 "Win7SP1x86"
#define PROFILE64 "Win7SP1x64"

// From FILE_INFORMATION_CLASS
#define FILE_DISPOSITION_INFORMATION 13

void volatility_extract_file(honeymon_clone_t *clone, addr_t file_object) {

    char* profile = NULL;
    if (PM2BIT(clone->pm) == BIT32) {
        profile = PROFILE32;
    } else {
        profile = PROFILE64;
    }

    char *command = g_malloc0(
            snprintf(NULL, 0, VOL_DUMPFILES, PYTHON, VOLATILITY, clone->domID,
                    profile, file_object) + 1);
    sprintf(command, VOL_DUMPFILES, PYTHON, VOLATILITY, clone->domID, profile,
            file_object);
    printf("** RUNNING COMMAND: %s\n", command);
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
    free(command);
}

void carve_file_from_memory(honeymon_clone_t *clone, addr_t ph_base,
        addr_t block_size) {

    addr_t aligned_file_size = struct_sizes[FILE_OBJECT];
    if(PM2BIT(clone->pm) == BIT32) {
        // 8-byte alignment on 32-bit mode
        if(struct_sizes[FILE_OBJECT] % 8) {
            aligned_file_size += 8 - (struct_sizes[FILE_OBJECT] % 8);
        }
    } else {
        // 16-byte alignment on 64-bit mode
        if(struct_sizes[FILE_OBJECT] % 16) {
            aligned_file_size += 16 - (struct_sizes[FILE_OBJECT] % 16);
        }
    }

    addr_t file_base = ph_base + block_size - aligned_file_size;
    addr_t file_name = file_base + offsets[FILE_OBJECT_FILENAME];

    addr_t file_name_str = 0;
    uint16_t length = 0;

    vmi_read_addr_pa(clone->vmi, file_name + offsets[UNICODE_STRING_BUFFER], &file_name_str);
    vmi_read_16_pa(clone->vmi, file_name + offsets[UNICODE_STRING_LENGTH], &length);

    if (file_name_str && length) {
        unicode_string_t str = { .contents = NULL };
        str.length = length;
        str.encoding = "UTF-16";
        str.contents = malloc(length);
        vmi_read_va(clone->vmi, file_name, 0, str.contents, length);
        unicode_string_t str2 = { .contents = NULL };
        status_t rc = vmi_convert_str_encoding(&str, &str2, "UTF-8");

        if (VMI_SUCCESS == rc) {
            printf("\tFile closing: %s.\n", str2.contents);
            volatility_extract_file(clone, file_base);
            g_free(str2.contents);
        }

        free(str.contents);
    }

}

void grab_file_by_handle(honeymon_clone_t *clone, vmi_event_t *event, reg_t cr3,
        addr_t handle) {

    vmi_instance_t vmi = clone->vmi;
    uint8_t type_index = 0;

    addr_t obj = get_obj_by_handle(clone, vmi, event->vcpu_id, handle);

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .addr = obj + offsets[OBJECT_HEADER_TYPEINDEX],
        .dtb = cr3
    };
    vmi_read_8(vmi, &ctx, &type_index);

    //printf("Handle: 0x%lx. Obj @ 0x%lx. Type: %s\n", handle, obj, win7_typeindex[obj_hdr.type_index]);

    if (type_index != 28)
        return;

    addr_t file = obj + struct_sizes[OBJECT_HEADER];
    addr_t filename = file + offsets[FILE_OBJECT_FILENAME];
    printf("Object header is @ 0x%lx. File Object is @ 0x%lx.\n", obj, file);

    uint16_t length = 0;
    addr_t buffer = 0;

    ctx.addr = filename + offsets[UNICODE_STRING_BUFFER];
    vmi_read_addr(vmi, &ctx, &buffer);

    ctx.addr = filename + offsets[UNICODE_STRING_LENGTH];
    vmi_read_16(vmi, &ctx, &length);

    if (length && buffer) {

        unicode_string_t str = { .contents = NULL };
        str.length = length;
        str.encoding = "UTF-16";
        str.contents = malloc(length + 1);

        ctx.addr = buffer;
        vmi_read(vmi, &ctx, str.contents, length);

        unicode_string_t str2 = { .contents = NULL };
        vmi_convert_str_encoding(&str, &str2, "UTF-8");
        if (str2.contents) {
            printf("\tExtracting file: %s\n", str2.contents);

            volatility_extract_file(clone, file);

            free(str2.contents);
        }

        free(str.contents);
    }
}

void grab_file_before_delete(vmi_instance_t vmi, vmi_event_t *event, reg_t cr3,
        struct symbolwrap *s) {

    honeymon_clone_t *clone = event->data;
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3
    };

    if (!strcmp(s->symbol->name, "NtSetInformationFile")
            || !strcmp(s->symbol->name, "ZwSetInformationFile")) {

        uint32_t fileinfoclass;
        reg_t handle, info, length, rsp;
        vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id); // stack pointer

        if (PM2BIT(clone->pm) == BIT32) {
            ctx.addr = rsp + sizeof(uint32_t);
            vmi_read_32(vmi, &ctx, (uint32_t*) &handle);
            ctx.addr += 2 * sizeof(uint32_t);
            vmi_read_32(vmi, &ctx, (uint32_t*) &info);
            ctx.addr += sizeof(uint32_t);
            vmi_read_32(vmi, &ctx, (uint32_t*) &length);
            ctx.addr += sizeof(uint32_t);
            vmi_read_32(vmi, &ctx, &fileinfoclass);
        } else {
            vmi_get_vcpureg(vmi, &handle, RCX, event->vcpu_id); // HANDLE FileHandle
            vmi_get_vcpureg(vmi, &info, R8, event->vcpu_id); // PVOID FileInformation
            vmi_get_vcpureg(vmi, &length, R9, event->vcpu_id); // ULONG Length

            ctx.addr = rsp + 5 * sizeof(addr_t); // addr of fileinfoclass
            vmi_read_32(vmi, &ctx, &fileinfoclass);
        }

        if (fileinfoclass == FILE_DISPOSITION_INFORMATION && length == 1) {
            uint8_t del = 0;
            ctx.addr = info;
            vmi_read_8(vmi, &ctx, &del);
            if (del) {
                printf("DELETE FILE _FILE_OBJECT Handle: 0x%lx.\n", handle);
                grab_file_by_handle(clone, event, cr3, handle);
            }
        }
    }
}

// post-write
void file_name_post_cb(vmi_instance_t vmi, vmi_event_t *event) {

    struct memevent *container = event->data;
    struct file_watch *watch = &container->file;

    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
    addr_t file_name = 0;
    uint16_t length = 0;

    status_t rc = VMI_FAILURE;

    vmi_read_addr_pa(vmi, watch->file_name + offsets[UNICODE_STRING_BUFFER], &file_name);
    vmi_read_16_pa(vmi, watch->file_name + offsets[UNICODE_STRING_LENGTH], &length);

    //printf("\n\nFile name @ 0x%lx. Length: %u\n\n", file_name, length);

    if (file_name && length) {
        unicode_string_t str = { .contents = NULL };
        str.length = length;
        str.encoding = "UTF-16";
        str.contents = malloc(length);
        vmi_read_va(vmi, file_name, 0, str.contents, length);
        unicode_string_t str2 = { .contents = NULL };
        rc = vmi_convert_str_encoding(&str, &str2, "UTF-8");

        if (VMI_SUCCESS == rc) {

            reg_t cr3;
            vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

            printf("CR3 0x%lx File accessed: %s.\n File object @ 0x%lx. File base @ 0x%lx.\n",
                    cr3, str2.contents, watch->obj, watch->file_base);

            if (VMI_SUCCESS == rc) {
                g_hash_table_remove(watch->clone->file_watch, &pa);
                free(event);
                free(container);
            }

            g_free(str2.contents);
        }
        free(str.contents);
    }

    if (VMI_FAILURE == rc)
        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
}

// pre-write
void file_name_pre_cb(vmi_instance_t vmi, vmi_event_t *event) {
    vmi_clear_event(vmi, event);
    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;

    if (pa == event->mem_event.physical_address) {
        vmi_step_event(vmi, event, event->vcpu_id, 1, file_name_post_cb);
    } else {
        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
    }
}

// Create mem event to catch when the memory space of the struct gets written to
// so we can extract the path of the file
void setup_file_watch(honeymon_clone_t *clone, vmi_instance_t vmi, addr_t obj,
        addr_t ph_base, uint32_t block_size) {

    addr_t aligned_file_size = struct_sizes[FILE_OBJECT];
    if(PM2BIT(clone->pm) == BIT32) {
        // 8-byte alignment on 32-bit mode
        if(struct_sizes[FILE_OBJECT] % 8) {
            aligned_file_size += 8 - (struct_sizes[FILE_OBJECT] % 8);
        }
    } else {
        // 16-byte alignment on 64-bit mode
        if(struct_sizes[FILE_OBJECT] % 16) {
            aligned_file_size += 16 - (struct_sizes[FILE_OBJECT] % 16);
        }
    }

    // Write events happen in two chunks
    addr_t file_base = ph_base + block_size - aligned_file_size; // addr of "_FILE_OBJECT"
    addr_t file_name = file_base + offsets[FILE_OBJECT_FILENAME]; // addr of "_UNICODE_STRING"
    addr_t last_write = file_name + offsets[UNICODE_STRING_BUFFER]; // actual file name buffer

    //printf("PH 0x%lx. Block size: %u\n", ph_base, block_size);
    //printf("File size: 0x%lx File base: 0x%lx. Unicode string @ 0x%lx. Last write @ 0x%lx\n",
    //        aligned_file_size, file_base, file_name, last_write);

    if (g_hash_table_lookup(clone->file_watch, &last_write))
        return;

    struct memevent *container = g_malloc0(sizeof(struct memevent));
    container->clone = clone;
    container->vmi = vmi;
    container->pa = last_write;
    container->file.file_name = file_name;
    container->file.file_base = file_base;
    container->file.obj = obj;
    container->file.clone = clone;

    container->guard = g_malloc0(sizeof(vmi_event_t));
    SETUP_MEM_EVENT(container->guard, last_write, VMI_MEMEVENT_PAGE,
            VMI_MEMACCESS_W, file_name_pre_cb);
    container->guard->data = container;
    if (VMI_FAILURE == vmi_register_event(vmi, container->guard)) {
        printf("Page is already trapped, can't setup file watch (TODO)\n");
        free(container->guard);
        free(container);
        return;
    }
    g_hash_table_insert(clone->file_watch, g_memdup(&container->pa, 8),
            container);
}
