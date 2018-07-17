/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
*                                                                         *
* DRAKVUF (C) 2014-2017 Tamas K Lengyel.                                  *
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
#include <config.h>
#include <inttypes.h>
#include <libvmi/x86.h>
#include <algorithm>
#include <cassert>
#include <set>

#include "../plugins.h"
#include "filedelete.h"
#include "private.h"

#include <libinjector/libinjector.h>

struct injector
{
    filedelete* f;
    bool is32bit;

    handle_t handle;

    reg_t target_cr3;
    uint32_t target_thread_id;
    addr_t eprocess_base;

    x86_registers_t saved_regs;

    union
    {
        struct
        {
            addr_t out;
            size_t size;
        } ntqueryobject_info;

        struct
        {
            size_t bytes_read;
            addr_t out;
            addr_t io_status_block;
        } ntreadfile_info;
    };

    drakvuf_trap_t* bp;
};

static const uint64_t BYTES_TO_READ = 0x4000;

struct IO_STATUS_BLOCK
{
    uint64_t dummy;
    uint64_t info;
} __attribute__((packed));

struct _LARGE_INTEGER
{
    uint64_t QuadPart;
} __attribute__((packed));

struct FILE_FS_DEVICE_INFORMATION
{
    uint32_t device_type;
    uint32_t characteristics;
} __attribute__((packed));

static event_response_t readfile_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct injector* injector = (struct injector*)info->trap->data;

    auto response = 0;
    uint32_t thread_id = 0;
    std::pair<addr_t, uint32_t> thread;
    filedelete* f = injector->f;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    struct IO_STATUS_BLOCK io_status_block = { 0 };

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if (info->regs->cr3 != injector->target_cr3)
        goto done;

    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &thread_id) ||
            !injector->target_thread_id || thread_id != injector->target_thread_id )
        goto done;

    if ( !info->regs->rax )
    {
        ctx.addr = injector->ntreadfile_info.io_status_block;
        if ((VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct IO_STATUS_BLOCK), &io_status_block, NULL)))
            goto err;
    }

    if ( !info->regs->rax)
    {
        static uint64_t idx = 0;
        char* file = NULL;

        if (injector->ntreadfile_info.bytes_read == 0)
            ++idx;

        if ( asprintf(&file, "%s/file.%06lu.metadata", f->dump_folder, idx) < 0 )
            goto err;

        FILE* fp = fopen(file, "w");
        if (!fp)
        {
            free(file);
            goto err;
        }

        fprintf(fp, "FileName: \"%s\"\n", injector->f->files[info->proc_data.pid][injector->handle].c_str());
        fprintf(fp, "PID: %" PRIu64 "\n", static_cast<uint64_t>(info->proc_data.pid));
        fprintf(fp, "PPID: %" PRIu64 "\n", static_cast<uint64_t>(info->proc_data.ppid));
        fprintf(fp, "ProcessName: \"%s\"\n", info->proc_data.name);

        fclose(fp);
        free(file);

        ctx.addr = injector->ntreadfile_info.out;
        void* buffer = g_malloc0(io_status_block.info);
        auto status = vmi_read(vmi, &ctx, io_status_block.info, buffer, NULL);
        if ((VMI_FAILURE == status))
            goto err;

        if ( asprintf(&file, "%s/file.%06lu", f->dump_folder, idx) < 0 )
            goto err;

        fp = fopen(file, "a");
        if (!fp)
        {
            free(file);
            goto err;
        }

        fwrite(buffer, 1, io_status_block.info, fp);
        fclose(fp);
        free(file);
        g_free(buffer);

        injector->ntreadfile_info.bytes_read += io_status_block.info;

        if (BYTES_TO_READ == io_status_block.info)
        {
            // Remove stack arguments and home space from previous injection
            info->regs->rsp = injector->saved_regs.rsp;

            ctx.addr = info->regs->rsp;

            if (injector->is32bit)
            {
                PRINT_DEBUG("[FILEDELETE2] 32bit VMs not supported yet\n");
                goto err;
            }

            struct argument args[9] = { {0} };
            struct _LARGE_INTEGER byte_offset = { .QuadPart = injector->ntreadfile_info.bytes_read };
            const struct IO_STATUS_BLOCK io_status_block = { 0 };
            const uint8_t buffer[BYTES_TO_READ] = { 0 };
            uint64_t null64 = 0;

            init_argument(0, &args[0], ARGUMENT_INT, sizeof(uint64_t), (void*)injector->handle);
            init_argument(0, &args[1], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[2], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[3], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[4], ARGUMENT_STRUCT, sizeof(struct IO_STATUS_BLOCK), (void*)&io_status_block);
            init_argument(0, &args[5], ARGUMENT_STRUCT, BYTES_TO_READ, (void*)buffer);
            init_argument(0, &args[6], ARGUMENT_INT, sizeof(uint64_t), (void*)BYTES_TO_READ);
            init_argument(0, &args[7], ARGUMENT_STRUCT, sizeof(byte_offset), (void*)&byte_offset);
            init_argument(0, &args[8], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);

            if ( !setup_stack_64(vmi, info, &ctx, args, 9) )
                goto err;

            injector->ntreadfile_info.io_status_block = args[4].data_on_stack;
            injector->ntreadfile_info.out = args[5].data_on_stack;

            info->regs->rip = f->readfile_va;

            response = VMI_EVENT_RESPONSE_SET_REGISTERS;

            goto done;
        }
    }
    else
        PRINT_DEBUG("[FILEDELETE2] [ReadFile] Failed to read %s with status 0x%lx.\n", injector->f->files[info->proc_data.pid][injector->handle].c_str(), info->regs->rax);

    thread = std::make_pair(info->regs->cr3, thread_id);
    injector->f->closing_handles[thread] = true;
    injector->f->files[info->proc_data.pid].erase(injector->handle);
    if (injector->f->files[info->proc_data.pid].size() == 0)
        injector->f->files.erase(info->proc_data.pid);

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    response = VMI_EVENT_RESPONSE_SET_REGISTERS;

    drakvuf_remove_trap(drakvuf, injector->bp, (drakvuf_trap_free_t)free);

    delete injector;

    goto done;

err:
    PRINT_DEBUG("[FILEDELETE2] [ReadFile] Error. Stop processing (CR3 0x%lx, TID %d).\n",
                info->regs->cr3, thread_id);

    thread = std::make_pair(info->regs->cr3, thread_id);
    injector->f->closing_handles[thread] = true;

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    response = VMI_EVENT_RESPONSE_SET_REGISTERS;

    drakvuf_remove_trap(drakvuf, injector->bp, (drakvuf_trap_free_t)free);

    delete injector;

done:
    drakvuf_release_vmi(drakvuf);

    return response;
}

static event_response_t queryobject_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct injector* injector = (struct injector*)info->trap->data;
    filedelete* f = injector->f;

    auto response = 0;
    uint32_t thread_id = 0;
    std::pair<addr_t, uint32_t> thread;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if (info->regs->cr3 != injector->target_cr3)
        goto done;

    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &thread_id) ||
            !injector->target_thread_id || thread_id != injector->target_thread_id )
        goto done;

    if (info->regs->rax)
        goto handled;
    else
    {
        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = injector->ntqueryobject_info.out,
        };

        struct FILE_FS_DEVICE_INFORMATION dev_info = { 0 };
        if ((VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct FILE_FS_DEVICE_INFORMATION), &dev_info, NULL)))
        {
            PRINT_DEBUG("[FILEDELETE2] [QueryObject] Failed to read FsDeviceInformation\n");
            goto err;
        }

        if (7 != dev_info.device_type) // FILE_DEVICE_DISK
            goto handled;

        injector->ntreadfile_info.bytes_read = 0UL;

        {
            // Remove stack arguments and home space from previous injection
            info->regs->rsp = injector->saved_regs.rsp;

            ctx.addr = info->regs->rsp;

            if (injector->is32bit)
            {
                PRINT_DEBUG("[FILEDELETE2] 32bit VMs not supported yet\n");
                goto err;
            }

            struct argument args[9] = { {0} };
            struct _LARGE_INTEGER byte_offset = { .QuadPart = 0 };
            const struct IO_STATUS_BLOCK io_status_block = { 0 };
            const uint8_t buffer[BYTES_TO_READ] = { 0 };
            uint64_t null64 = 0;

            init_argument(0, &args[0], ARGUMENT_INT, sizeof(uint64_t), (void*)injector->handle);
            init_argument(0, &args[1], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[2], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[3], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[4], ARGUMENT_STRUCT, sizeof(struct IO_STATUS_BLOCK), (void*)&io_status_block);
            init_argument(0, &args[5], ARGUMENT_STRUCT, BYTES_TO_READ, (void*)buffer);
            init_argument(0, &args[6], ARGUMENT_INT, sizeof(uint64_t), (void*)BYTES_TO_READ);
            init_argument(0, &args[7], ARGUMENT_STRUCT, sizeof(byte_offset), (void*)&byte_offset);
            init_argument(0, &args[8], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);

            if ( !setup_stack_64(vmi, info, &ctx, args, 9) )
                goto err;

            injector->ntreadfile_info.io_status_block = args[4].data_on_stack;
            injector->ntreadfile_info.out = args[5].data_on_stack;
        }

        info->regs->rip = f->readfile_va;

        injector->bp->name = "ReadFile ret";
        injector->bp->cb = readfile_cb;

        response = VMI_EVENT_RESPONSE_SET_REGISTERS;

        goto done;
    }


err:
    PRINT_DEBUG("[FILEDELETE2] [QueryObject] Error. Stop processing (CR3 0x%lx, TID %d).\n",
                info->regs->cr3, thread_id);

handled:
    thread = std::make_pair(info->regs->cr3, thread_id);
    injector->f->closing_handles[thread] = true;

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    response = VMI_EVENT_RESPONSE_SET_REGISTERS;

    drakvuf_remove_trap(drakvuf, injector->bp, (drakvuf_trap_free_t)free);

    delete injector;

done:
    drakvuf_release_vmi(drakvuf);

    return response;
}

/*
 * Drakvuf must be locked/unlocked in the caller
 */
static event_response_t start_readfile(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, handle_t handle)
{
    auto response = 0;
    auto restore_regs = false;
    struct injector* injector = nullptr;
    filedelete* f = (filedelete*)info->trap->data;

    injector = new struct injector;
    injector->f = f;
    injector->handle = handle;
    injector->is32bit = f->pm == VMI_PM_IA32E ? false : true;
    injector->target_cr3 = info->regs->cr3;

    injector->eprocess_base = drakvuf_get_current_process(drakvuf, info->vcpu);
    if ( 0 == injector->eprocess_base )
    {
        PRINT_DEBUG("[FILEDELETE2] Failed to get process base on vCPU 0x%d\n",
                    info->vcpu);
        goto err;
    }

    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &injector->target_thread_id) ||
            !injector->target_thread_id )
    {
        PRINT_DEBUG("[FILEDELETE2] Failed to get Thread ID\n");
        goto err;
    }

    /*
     * Check if process/thread is being processed. If so skip it. Add it into
     * regestry otherwise.
     */
    {
        auto thread = std::make_pair(info->regs->cr3, injector->target_thread_id);
        auto thread_it = f->closing_handles.find(thread);
        auto map_end = f->closing_handles.end();
        if (map_end != thread_it)
        {
            bool handled = thread_it->second;
            if (handled)
                f->closing_handles.erase(thread);

            goto err;
        }
        else
            f->closing_handles[thread] = false;
    }

    /*
     * Real function body.
     *
     * Now we are sure this is new call to NtClose (not result of function injection) and
     * the Handle have been modified in NtWriteFile. So we should save it on the host.
     */
    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));
    restore_regs = true;

    {
        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = info->regs->rsp,
        };

        if (injector->is32bit)
        {
            PRINT_DEBUG("[FILEDELETE2] 32bit VMs not supported yet\n");
            goto err;
        }

        struct argument args[5] = { {0} };
        const struct IO_STATUS_BLOCK io_status_block = { 0 };
        struct FILE_FS_DEVICE_INFORMATION dev_info = { 0 };

        init_argument(0, &args[0], ARGUMENT_INT, sizeof(uint64_t), (void*)handle);
        init_argument(0, &args[1], ARGUMENT_STRUCT, sizeof(struct IO_STATUS_BLOCK), (void*)&io_status_block);
        init_argument(0, &args[2], ARGUMENT_STRUCT, sizeof(struct FILE_FS_DEVICE_INFORMATION), (void*)&dev_info);
        init_argument(0, &args[3], ARGUMENT_INT, sizeof(uint64_t), (void*)sizeof(struct FILE_FS_DEVICE_INFORMATION));
        init_argument(0, &args[4], ARGUMENT_INT, sizeof(uint64_t), (void*)4); // FileFsDeviceInformation

        if ( !setup_stack_64(vmi, info, &ctx, args, 5) )
            goto err;

        injector->ntqueryobject_info.out = args[2].data_on_stack;
    }

    injector->bp = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    if (!injector->bp)
        goto err;

    injector->bp->type = BREAKPOINT;
    injector->bp->name = "QueryObject ret";
    injector->bp->cb = queryobject_cb;
    injector->bp->data = injector;
    injector->bp->breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp->breakpoint.dtb = info->regs->cr3;
    injector->bp->breakpoint.addr_type = ADDR_VA;
    injector->bp->breakpoint.addr = info->regs->rip;

    if ( !drakvuf_add_trap(drakvuf, injector->bp) )
    {
        fprintf(stderr, "Failed to trap return location of injected function call @ 0x%lx!\n",
                injector->bp->breakpoint.addr);
        goto err;
    }

    info->regs->rip = f->queryobject_va;

    response = VMI_EVENT_RESPONSE_SET_REGISTERS;

    return response;

err:
    if (restore_regs)
        memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

    delete injector;

    return response;
}

/*
 * Intercept all handles close and filter file handles.
 *
 * The main difficulty is that this handler intercepts not only CloseHandle()
 * calls but returns from injected functions. To distinguish such situations
 * we use the regestry of processes/threads being processed.
 */
static event_response_t closehandle_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto response = 0;
    filedelete* f = (filedelete*)info->trap->data;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    reg_t handle = 0;

    if (f->pm == VMI_PM_IA32E)
    {
        handle = info->regs->rcx;
    }
    else
    {
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = info->regs->rsp + sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &handle) )
            goto err;
    }

    /*
     * Check if closing handle have been changed with NtWriteFile
     */
    if (f->files[info->proc_data.pid][handle].empty())
        goto err;

    response = start_readfile(drakvuf, info, vmi, handle);

err:
    drakvuf_release_vmi(drakvuf);
    return response;
}

/*
 * NTSTATUS ZwSetInformationFile(
 *  HANDLE                 FileHandle,
 *  PIO_STATUS_BLOCK       IoStatusBlock,
 *  PVOID                  FileInformation,
 *  ULONG                  Length,
 *  FILE_INFORMATION_CLASS FileInformationClass
 * );
 *
 * When FileInformationClass is FileDispositionInformation then FileInformation points to
 * struct _FILE_DISPOSITION_INFORMATION {
 *  BOOLEAN DeleteFile;
 * }
 */
static event_response_t setinformation_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    event_response_t response = 0;
    filedelete* f = (filedelete*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    uint32_t fileinfoclass = 0;
    reg_t handle = 0, fileinfo = 0;

    if (f->pm == VMI_PM_IA32E)
    {
        handle = info->regs->rcx;
        fileinfo = info->regs->r8;

        ctx.addr = info->regs->rsp + 5 * sizeof(addr_t); // addr of fileinfoclass
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &fileinfoclass) )
            goto done;
    }
    else
    {
        ctx.addr = info->regs->rsp + sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &handle) )
            goto done;
        ctx.addr += 2 * sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &fileinfo) )
            goto done;
        ctx.addr += 2 * sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &fileinfoclass) )
            goto done;
    }

    if (fileinfoclass == FILE_DISPOSITION_INFORMATION)
    {
        uint8_t del = 0;
        ctx.addr = fileinfo;
        if ( VMI_FAILURE == vmi_read_8(vmi, &ctx, &del) )
            goto done;

        if (del)
        {
            auto filename_us = get_file_name(f, drakvuf, vmi, info, handle, nullptr, nullptr);
            std::string filename = "<UNKNOWN>";
            if (filename_us)
                filename = std::string((const char*)filename_us->contents);

            f->files[info->proc_data.pid][handle] = filename;

            response = start_readfile(drakvuf, info, vmi, handle);
        }
    }

done:
    drakvuf_release_vmi(drakvuf);
    return response;
}

static event_response_t writefile_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    filedelete* f = (filedelete*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    unicode_string_t* filename_us = nullptr;
    std::string filename = "<UNKNOWN>";
    handle_t handle = 0;
    access_context_t ctx;

    if (f->pm == VMI_PM_IA32E)
    {
        handle = info->regs->rcx;
    }
    else
    {
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = info->regs->rsp + sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &handle) )
            goto done;
    }

    filename_us = get_file_name(f, drakvuf, vmi, info, handle, nullptr, nullptr);
    if (filename_us)
        filename = std::string((const char*)filename_us->contents);

    f->files[info->proc_data.pid][handle] = filename;

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t createsection_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    filedelete* f = (filedelete*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    unicode_string_t* filename_us = nullptr;
    std::string filename = "<UNKNOWN>";
    handle_t handle = 0;
    uint32_t access_mask = 0;
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    if (f->pm == VMI_PM_IA32E)
    {
        access_mask = (uint32_t) info->regs->rdx;
        ctx.addr = info->regs->rsp + 7 * sizeof(uint64_t);
        if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, (uint64_t*) &handle) )
            goto done;
        // Filter out system handles: those having high bits rised
        // WARNING Without this target VM could freeze or crash!
        if (handle & ~(0x7fffffffULL))
            goto done;
    }
    else
    {
        ctx.addr = info->regs->rsp + 2 * sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &access_mask) )
            goto done;

        ctx.addr = info->regs->rsp + 7 * sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &handle) )
            goto done;
    }

    if ( !(0x2 & access_mask) ) // SECTION_MAP_WRITE
        goto done;

    filename_us = get_file_name(f, drakvuf, vmi, info, handle, nullptr, nullptr);
    if (filename_us)
        filename = std::string((const char*)filename_us->contents);

    f->files[info->proc_data.pid][handle] = filename;

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

void filedelete::filedelete2(drakvuf_t drakvuf, const char* rekall_profile)
{
    const char* lib = "ntoskrnl.exe";
    const char* queryobject_name = "ZwQueryVolumeInformationFile";
    addr_t rva = 0;

    if ( !drakvuf_get_function_rva( rekall_profile, queryobject_name, &rva) )
    {
        PRINT_DEBUG("[FILEDELETE2] [Init] Failed to get RVA of %s\n", queryobject_name);
        throw -1;
    }

    queryobject_va = drakvuf_exportksym_to_va(drakvuf, 4, nullptr, lib, rva);
    if (!queryobject_va)
    {
        PRINT_DEBUG("[FILEDELETE2] [Init] Failed to get VA of %s\n", queryobject_name);
        throw -1;
    }

    const char* readfile_name = "ZwReadFile";

    if ( !drakvuf_get_function_rva( rekall_profile, readfile_name, &rva) )
    {
        PRINT_DEBUG("[FILEDELETE2] [Init] Failed to get RVA of %s\n", readfile_name);
        throw -1;
    }

    readfile_va = drakvuf_exportksym_to_va(drakvuf, 4, nullptr, lib, rva);
    if (!readfile_va)
    {
        PRINT_DEBUG("[FILEDELETE2] [Init] Failed to get VA of %s\n", readfile_name);
        throw -1;
    }

    assert(sizeof(traps)/sizeof(traps[0]) > 3);
    register_trap(drakvuf, rekall_profile, "NtSetInformationFile", &traps[0], setinformation_cb);
    register_trap(drakvuf, rekall_profile, "NtWriteFile", &traps[1], writefile_cb);
    register_trap(drakvuf, rekall_profile, "NtClose", &traps[2], closehandle_cb);
    register_trap(drakvuf, rekall_profile, "ZwCreateSection", &traps[3], createsection_cb);
}
