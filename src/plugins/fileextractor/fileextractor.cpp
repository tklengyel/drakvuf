/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
*                                                                         *
* DRAKVUF (C) 2014-2022 Tamas K Lengyel.                                  *
* Tamas K Lengyel is hereinafter referred to as the author.               *
* This program is free software; you may redistribute and/or modify it    *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
* CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
* right to use, modify, and redistribute this software under certain      *
* conditions.  If you wish to embed DRAKVUF technology into proprietary   *
* software, alternative licenses can be acquired from the author.         *
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
#include <sys/stat.h>
#include <cassert>
#include <sstream>
#include <string>

#include <libinjector/libinjector.h>

#include "plugins/plugins.h"
#include "plugins/output_format.h"

#include "fileextractor.h"
#include "private.h"

using std::ostringstream;
using std::string;

/*****************************************************************************
 *                               Hook handlers                               *
 *****************************************************************************/

//
// The group of hooks that detects new tasks - files to dump.
//
event_response_t fileextractor::openfile_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    if (this->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t create_options = drakvuf_get_function_argument(drakvuf, info, 6);

    if (create_options & FILE_DELETE_ON_CLOSE)
        createfile_cb_impl(drakvuf, info, handle);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t fileextractor::createfile_cb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info)
{
    if (this->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t create_options = drakvuf_get_function_argument(drakvuf, info, 9);

    if (create_options & FILE_DELETE_ON_CLOSE)
        createfile_cb_impl(drakvuf, info, handle);

    return VMI_EVENT_RESPONSE_NONE;
}

void fileextractor::createfile_cb_impl(drakvuf_t,
    drakvuf_trap_info_t* info,
    addr_t handle)
{
    auto hook_id = make_hook_id(info);
    auto hook = createReturnHook<createfile_result_t>(info,
            &fileextractor::createfile_ret_cb);
    auto params = libhook::GetTrapParams<createfile_result_t>(hook->trap_);
    params->handle = handle;

    createfile_ret_hooks[hook_id] = std::move(hook);
}

event_response_t fileextractor::createfile_ret_cb(drakvuf_t,
    drakvuf_trap_info_t* info)
{
    auto params = libhook::GetTrapParams<createfile_result_t>(info);
    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    // Return if NtCreateFile/NtOpenFile failed
    if (info->regs->rax)
        return VMI_EVENT_RESPONSE_NONE;

    uint32_t handle = 0;
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = params->handle
    );

    vmi_lock_guard vmi(drakvuf);
    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, &handle))
        PRINT_DEBUG("[FILEDELETE] "
            "Failed to read pHandle at 0x%lx (PID %d, TID %d)\n",
            params->handle,
            params->target_pid,
            params->target_tid);

    if (handle && is_handle_valid(handle))
    {
        auto id = make_task_id(info->attached_proc_data.pid, handle);
        if (tasks.find(id) == tasks.end())
        {
            addr_t file = 0;
            auto filename = get_file_name(vmi, info, handle, &file, nullptr);
            if (filename.empty()) filename = "<UNKNOWN>";

            tasks[id] = std::make_unique<task_t>(handle,
                    filename,
                    task_t::task_reason::del,
                    file);
        }
    }

    auto hook_id = make_hook_id(info);
    createfile_ret_hooks.erase(hook_id);

    return VMI_EVENT_RESPONSE_NONE;
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
 * When FileInformationClass is FileDispositionInformation then
 * FileInformation points to:
 * struct _FILE_DISPOSITION_INFORMATION {
 *  BOOLEAN DeleteFile;
 * }
 */
event_response_t fileextractor::setinformation_cb(drakvuf_t,
    drakvuf_trap_info_t* info)
{
    if (this->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    vmi_lock_guard vmi(drakvuf);

    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t fileinfo = drakvuf_get_function_argument(drakvuf, info, 3);
    uint32_t fileinfoclass = drakvuf_get_function_argument(drakvuf, info, 5);

    if (fileinfoclass == FILE_DISPOSITION_INFORMATION && is_handle_valid(handle))
    {
        uint8_t del = 0;
        ACCESS_CONTEXT(ctx);
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = fileinfo;

        if ( VMI_SUCCESS == vmi_read_8(vmi, &ctx, &del) && del)
        {
            auto id = make_task_id(info->attached_proc_data.pid, handle);
            if (tasks.find(id) == tasks.end())
            {
                addr_t file = 0;
                auto filename = get_file_name(vmi, info, handle, &file, nullptr);
                if (filename.empty()) filename = "<UNKNOWN>";

                tasks[id] = std::make_unique<task_t>(handle,
                        filename,
                        task_t::task_reason::del,
                        file);
            }
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t fileextractor::writefile_cb(drakvuf_t,
    drakvuf_trap_info_t* info)
{
    if (this->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    vmi_lock_guard vmi(drakvuf);

    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);

    if (is_handle_valid(handle))
    {
        auto id = make_task_id(info->attached_proc_data.pid, handle);
        if (tasks.find(id) == tasks.end())
        {
            addr_t file = 0;
            auto filename = get_file_name(vmi, info, handle, &file, nullptr);
            if (filename.empty()) filename = "<UNKNOWN>";

            tasks[id] = std::make_unique<task_t>(handle,
                    filename,
                    task_t::task_reason::write,
                    file);
        }
    }
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t fileextractor::createsection_cb(drakvuf_t,
    drakvuf_trap_info_t* info)
{
    if (this->is_stopping())
        return VMI_EVENT_RESPONSE_NONE;

    vmi_lock_guard vmi(drakvuf);

    handle_t handle = drakvuf_get_function_argument(drakvuf, info, 7);
    uint32_t access_mask = drakvuf_get_function_argument(drakvuf, info, 2);

    if ( is_handle_valid(handle) &&
        (0x2 & access_mask) ) // SECTION_MAP_WRITE
    {
        auto id = make_task_id(info->attached_proc_data.pid, handle);
        if (tasks.find(id) == tasks.end())
        {
            addr_t file = 0;
            auto filename = get_file_name(vmi, info, handle, &file, nullptr);
            if (filename.empty()) filename = "<UNKNOWN>";

            tasks[id] = std::make_unique<task_t>(handle,
                    filename,
                    task_t::task_reason::write,
                    file);
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

//
// Dumps file on last handle close.
//
event_response_t fileextractor::close_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    vmi_lock_guard vmi(drakvuf);

    fileextractor::error status{fileextractor::error::error};
    task_t* task = nullptr;
    for (auto& i: tasks)
        if (drakvuf_check_return_context(drakvuf,
                info,
                i.second->target.ret_pid,
                i.second->target.ret_tid,
                i.second->target.ret_rsp))
        {
            task = i.second.get();
            break;
        }

    if (!task)
    {
        auto handle = drakvuf_get_function_argument(drakvuf, info, 1);
        /* If there are more then one open handle to the file. So do nothing. */
        uint64_t handle_count = 1;
        if (get_file_object_handle_count(info, handle, &handle_count) &&
            handle_count > 1)
            return VMI_EVENT_RESPONSE_NONE;

        auto id = make_task_id(info->attached_proc_data.pid, handle);
        auto task_it = tasks.find(id);

        /* The system closes handle to untracked resource. So do nothing. */
        if ( tasks.end() == task_it )
            return VMI_EVENT_RESPONSE_NONE;

        task = task_it->second.get();
    }

    switch (task->stage)
    {
        case task_t::stage_t::pending:
            status = dispatch_pending(vmi, info, *task);
            break;
        case task_t::stage_t::queryvolumeinfo:
            status = dispatch_queryvolumeinfo(vmi, info, *task);
            break;
        case task_t::stage_t::queryinfo:
            status = dispatch_queryinfo(vmi, info, *task);
            break;
        case task_t::stage_t::createsection:
            status = dispatch_createsection(vmi, info, *task);
            break;
        case task_t::stage_t::mapview:
            status = dispatch_mapview(vmi, info, *task);
            break;
        case task_t::stage_t::allocate_pool:
            status = dispatch_allocate_pool(vmi, info, *task);
            break;
        case task_t::stage_t::memcpy:
            status = dispatch_memcpy(vmi, info, *task);
            break;
        case task_t::stage_t::unmapview:
            status = dispatch_unmapview(vmi, info, *task);
            break;
        case task_t::stage_t::close_handle:
            status = dispatch_close_handle(vmi, info, *task);
            break;
        case task_t::stage_t::finished:
            break;
    }

    if (error::error == status)
    {
        grab_file_by_handle(vmi, info, *task);
        task->stage = task_t::stage_t::finished;
        status = error::success;
    }

    if (task_t::stage_t::finished == task->stage)
    {
        free_resources(info, *task);
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    if (error::success == status)
        return VMI_EVENT_RESPONSE_SET_REGISTERS;

    return VMI_EVENT_RESPONSE_NONE;
}

/*****************************************************************************
 *                                Dispatchers                                *
 *****************************************************************************/
fileextractor::error fileextractor::dispatch_pending(
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    task_t& task)
{
    // do not start dumping new file
    if (this->is_stopping())
        return error::none;

    memcpy(&task.target.regs, info->regs, sizeof(x86_registers_t));

    if (!get_file_object_flags(info, vmi, task.handle, &task.fo_flags))
        return error::error;

    task.target_process_base = info->attached_proc_data.base_addr;
    task.target.ret_pid = info->attached_proc_data.pid;
    task.target.ret_tid = info->attached_proc_data.tid;

    if (!inject_queryvolumeinfo(info, vmi, task))
        return error::error;

    return error::success;
}

fileextractor::error fileextractor::dispatch_queryvolumeinfo(
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    task_t& task)
{
    if (info->regs->rax)
    {
        ostringstream msg;
        msg << "ZwQueryVolumeInformationFile failed with status 0x"
            << std::hex << info->regs->rax;

        print_extraction_failure(info, task.filename, msg.str());
        return error::error;
    }
    else
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = task.queryvolumeinfo.out
        );

        struct FILE_FS_DEVICE_INFORMATION dev_info = {};
        if ((VMI_FAILURE == vmi_read(vmi,
                    &ctx,
                    sizeof(struct FILE_FS_DEVICE_INFORMATION),
                    &dev_info,
                    NULL)))
        {
            PRINT_DEBUG("[FILEDELETE] [ZwQueryVolumeInformationFile] "
                "Failed to read FsDeviceInformation\n");
            return error::error;
        }

        if (7 != dev_info.device_type) // FILE_DEVICE_DISK
        {
            ostringstream msg;
            msg << "ZwQueryVolumeInformationFile stop processing device type "
                << dev_info.device_type;

            print_extraction_failure(info, task.filename, msg.str());
            task.stage = task_t::stage_t::finished;
            return error::none;
        }

        if (!inject_queryinfo(info, vmi, task))
            return error::error;
    }

    return error::success;
}

fileextractor::error fileextractor::dispatch_queryinfo(
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    task_t& task)
{
    if (info->regs->rax)
    {
        ostringstream msg;
        msg << "ZwQueryInformationFile failed with status 0x"
            << std::hex << info->regs->rax;

        print_extraction_failure(info, task.filename, msg.str());
        return error::error;
    }
    else
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = task.queryvolumeinfo.out
        );

        struct FILE_STANDARD_INFORMATION dev_info = {};
        if ((VMI_FAILURE == vmi_read(vmi,
                    &ctx,
                    sizeof(dev_info),
                    &dev_info,
                    NULL)))
        {
            PRINT_DEBUG("[FILEDELETE] [ZwQueryInformationFile] "
                "Failed to read FsDeviceInformation\n");
            return error::error;
        }

        if (0 == dev_info.end_of_file)
        {
            print_extraction_failure(info, task.filename, "Zero size file");
            return error::error;
        }

        task.file_size = dev_info.end_of_file;

        if (!inject_createsection(info, vmi, task))
            return error::error;
    }

    return error::success;
}

fileextractor::error fileextractor::dispatch_createsection(
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    task_t& task)
{
    if (info->regs->rax)
    {
        ostringstream msg;
        msg << "ZwCreateSection failed with status 0x"
            << std::hex << info->regs->rax;
        print_extraction_failure(info, task.filename, msg.str());
        return error::error;
    }
    else
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = task.createsection.handle
        );

        if ((VMI_FAILURE == vmi_read(vmi,
                    &ctx,
                    sizeof(task.section_handle),
                    &task.section_handle,
                    NULL)))
        {
            PRINT_DEBUG("[FILEDELETE] [ZwCreateSection] "
                "Failed to read section handle\n");
            return error::error;
        }

        if (!inject_mapview(info, vmi, task))
            return error::error;
    }

    return error::success;
}

fileextractor::error fileextractor::dispatch_mapview(
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    task_t& task)
{
    if (info->regs->rax)
    {
        ostringstream msg;
        msg << "ZwMapViewOfSection failed with status 0x"
            << std::hex << info->regs->rax;
        print_extraction_failure(info, task.filename, msg.str());
    }
    else
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = task.mapview.base
        );

        if ((VMI_FAILURE == vmi_read(vmi,
                    &ctx,
                    sizeof(task.view_base),
                    &task.view_base,
                    NULL)))
        {
            PRINT_DEBUG("[FILEDELETE] [ZwMapViewOfSection] "
                "Failed to read view base\n");
            return error::error;
        }

        // TODO Why to read this field? Add check for size?
        ctx.addr = task.mapview.size;
        uint64_t view_size = 0;
        if ((VMI_FAILURE == vmi_read(vmi,
                    &ctx,
                    sizeof(view_size),
                    &view_size,
                    NULL)))
        {
            PRINT_DEBUG("[FILEDELETE] [ZwMapViewOfSection] "
                "Failed to read view size\n");
            return error::error;
        }

        // TODO Why to allocate pool at this stage? May be earlier?
        addr_t pool = find_pool();
        if (!pool)
        {
            if (!inject_allocate_pool(info, vmi, task))
                return error::error;
        }
        else
        {
            task.pool = pool;
            if (!inject_memcpy(info, vmi, task))
                return error::error;
        }
    }

    return error::success;
}

fileextractor::error fileextractor::dispatch_allocate_pool(
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    task_t& task)
{
    if (info->regs->rax)
    {
        this->pools[info->regs->rax] = true;

        task.pool = info->regs->rax;
        // TODO Check why I have done in old version?
        // if (!inject_unmapview(info, vmi, task))
        //     return error::error;
        if (!inject_memcpy(info, vmi, task))
            return error::error;
    }
    else
    {
        print_extraction_failure(info,
            task.filename,
            "ExAllocatePoolWithTag failed to allocate pool");
        return error::error;
    }

    return error::success;
}

fileextractor::error fileextractor::dispatch_memcpy(
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    task_t& task)
{
    if (!task.idx)
        task.idx = ++this->sequence_number;
    read_vm(vmi, info, task);
    task.file_offset += task.bytes_to_read;
    if (task.file_offset >= task.file_size)
        save_file_metadata(info, 0, task);

    if (!inject_unmapview(info, vmi, task))
        return error::error;

    return error::success;
}

fileextractor::error fileextractor::dispatch_unmapview(
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    task_t& task)
{
    if (task.file_offset < task.file_size)
    {
        if (!inject_mapview(info, vmi, task))
            return error::error;
    }
    else if (!inject_close_handle(info, vmi, task))
        return error::error;

    return error::success;
}

fileextractor::error fileextractor::dispatch_close_handle(
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    task_t& task)
{
    task.stage = task_t::stage_t::finished;

    return error::success;
}

/*****************************************************************************
 *                             Injection helpers                             *
 *****************************************************************************/

bool fileextractor::inject_queryvolumeinfo(drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    task_t& task)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = task.target.regs.rsp;

    struct argument args[5] = {};
    struct IO_STATUS_BLOCK_32 io_status_block_32 = {};
    struct IO_STATUS_BLOCK_64 io_status_block_64 = {};
    struct FILE_FS_DEVICE_INFORMATION dev_info = {};

    init_int_argument(&args[0], task.handle);
    if (is32bit)
        init_struct_argument(&args[1], io_status_block_32);
    else
        init_struct_argument(&args[1], io_status_block_64);
    init_struct_argument(&args[2], dev_info);
    init_int_argument(&args[3], sizeof(dev_info));
    init_int_argument(&args[4], FileFsDeviceInformation);

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 5))
        return false;

    task.target.ret_rsp = info->regs->rsp;
    task.queryvolumeinfo.out = args[2].data_on_stack;
    info->regs->rip = this->queryvolumeinfo_va;

    task.stage = task_t::stage_t::queryvolumeinfo;
    return true;
}

bool fileextractor::inject_queryinfo(drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    task_t& task)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = task.target.regs.rsp;

    struct argument args[5] = {};
    struct IO_STATUS_BLOCK_32 io_status_block_32 = {};
    struct IO_STATUS_BLOCK_64 io_status_block_64 = {};
    struct FILE_STANDARD_INFORMATION dev_info = {};

    init_int_argument(&args[0], task.handle);
    if (is32bit)
        init_struct_argument(&args[1], io_status_block_32);
    else
        init_struct_argument(&args[1], io_status_block_64);
    init_struct_argument(&args[2], dev_info);
    init_int_argument(&args[3], sizeof(dev_info));
    init_int_argument(&args[4], FileStandardInformation);

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 5))
        return false;

    task.target.ret_rsp = info->regs->rsp;
    task.queryinfo.out = args[2].data_on_stack;
    info->regs->rip = queryinfo_va;

    task.stage = task_t::stage_t::queryinfo;
    return true;
}

bool fileextractor::inject_createsection(drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    task_t& task)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = task.target.regs.rsp;

    struct argument args[7] = {};
    handle_t section_handle = 0;
    struct _LARGE_INTEGER max_size = { 0 };
    max_size.QuadPart = task.file_size;

    init_struct_argument(&args[0], section_handle); // SectionHandle
    init_int_argument(&args[1], 0xf0005); // DesiredAccess = SECTION_MAP_READ | SECTION_QUERY
    init_int_argument(&args[2], 0); // ObjectAttributes = 0
    init_struct_argument(&args[3], max_size); // MaximumSize = 0
    init_int_argument(&args[4], 2); // SectionPageProtection = PAGE_READONLY
    init_int_argument(&args[5], 0x8000000); // AllocationAttributes = SEC_COMMIT
    init_int_argument(&args[6], task.handle); // FileHandle

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 7))
        return false;

    task.target.ret_rsp = info->regs->rsp;
    task.createsection.handle = args[0].data_on_stack;
    info->regs->rip = this->createsection_va;

    task.stage = task_t::stage_t::createsection;
    return true;
}

bool fileextractor::inject_mapview(drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    task_t& task)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = task.target.regs.rsp;

    struct argument args[10] = {};
    uint64_t base = 0;
    struct _LARGE_INTEGER offset = { 0 };
    offset.QuadPart = task.file_offset;
    uint64_t view_size = std::min(task.file_size - task.file_offset, BYTES_TO_READ);

    init_int_argument   (&args[0], task.section_handle); // SectionHandle
    init_int_argument   (&args[1], 0xffffffffffffffff); // ProcessHandle = current process pseudo handle
    init_struct_argument(&args[2], base); // BaseAddress
    init_int_argument   (&args[3], 0); // ZeroBits
    init_int_argument   (&args[4], 0); // CommitSize
    init_struct_argument(&args[5], offset); // SectionOffset
    init_struct_argument(&args[6], view_size); // ViewSize
    init_int_argument   (&args[7], 1); // InheritDisposition
    init_int_argument   (&args[8], 0); // AllocationType
    init_int_argument   (&args[9], 2); // Win32Protect

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 10))
        return false;

    task.target.ret_rsp = info->regs->rsp;
    task.mapview.base = args[2].data_on_stack;
    task.mapview.size = args[6].data_on_stack;
    info->regs->rip = this->mapview_va;

    task.stage = task_t::stage_t::mapview;
    return true;
}

bool fileextractor::inject_allocate_pool(drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    task_t& task)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = task.target.regs.rsp;

    struct argument args[3] = {};
    init_int_argument(&args[0], 0); // NonPagedPool
    init_int_argument(&args[1], BYTES_TO_READ);
    init_int_argument(&args[2], 0);

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 3))
        return false;

    task.target.ret_rsp = info->regs->rsp;
    info->regs->rip = this->exallocatepool_va;

    task.stage = task_t::stage_t::allocate_pool;
    return true;
}

bool fileextractor::inject_memcpy(drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    task_t& task)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = task.target.regs.rsp;

    task.bytes_to_read = std::min(task.file_size - task.file_offset, BYTES_TO_READ);

    struct argument args[3] = {};
    init_int_argument(&args[0], task.pool);
    init_int_argument(&args[1], task.view_base);
    init_int_argument(&args[2], task.bytes_to_read);

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 3))
        return false;

    task.target.ret_rsp = info->regs->rsp;
    info->regs->rip = this->memcpy_va;

    task.stage = task_t::stage_t::memcpy;
    return true;
}

bool fileextractor::inject_unmapview(drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    task_t& task)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = task.target.regs.rsp;

    struct argument args[2] = {};

    init_int_argument(&args[0], 0xffffffffffffffff); // current process pseudo handle
    init_int_argument(&args[1], task.view_base);

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 2))
        return false;

    task.target.ret_rsp = info->regs->rsp;
    info->regs->rip = this->unmapview_va;

    task.stage = task_t::stage_t::unmapview;
    return true;
}

bool fileextractor::inject_close_handle(drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    task_t& task)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = task.target.regs.rsp;

    struct argument args[1] = {};

    init_int_argument(&args[0], task.section_handle);

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 1))
        return false;

    task.target.ret_rsp = info->regs->rsp;
    info->regs->rip = this->close_handle_va;

    task.stage = task_t::stage_t::close_handle;
    return true;
}

/*****************************************************************************
 *                                 Routines                                  *
 *****************************************************************************/

bool fileextractor::get_file_object_handle_count(drakvuf_trap_info_t* info,
    handle_t handle,
    uint64_t* handle_count)
{
    if (!handle_count)
        return false;

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf,
            info->attached_proc_data.base_addr,
            handle);
    if (!obj)
        return false; // Break operatioin to not crash VM

    addr_t handles = obj + this->offsets[OBJECT_HEADER_HANDLE_COUNT];

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.addr = handles;
    ctx.dtb = info->regs->cr3;

    uint64_t handles_value = 0;
    bool success = (VMI_SUCCESS == drakvuf_read_addr(drakvuf,
                info,
                &ctx,
                &handles_value));
    if (success)
        *handle_count = handles_value;

    return success;
}

bool fileextractor::get_file_object_flags(drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    handle_t handle,
    uint64_t* flags)
{
    addr_t obj = drakvuf_get_obj_by_handle(drakvuf,
            info->attached_proc_data.base_addr,
            handle);
    if (!obj)
        return false; // Break operatioin to not crash VM

    addr_t file = obj + this->offsets[OBJECT_HEADER_BODY];
    addr_t fileflags = file + this->offsets[FILE_OBJECT_FLAGS];

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.addr = fileflags;
    ctx.dtb = info->regs->cr3;

    uint32_t flags_value;
    bool success = (VMI_SUCCESS == vmi_read_32(vmi, &ctx, &flags_value));
    if (success && flags) *flags = flags_value;
    return success;
}

std::string fileextractor::get_file_name(vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    addr_t handle,
    addr_t* out_file,
    addr_t* out_filetype)
{
    addr_t obj = drakvuf_get_obj_by_handle(drakvuf,
            info->attached_proc_data.base_addr,
            handle);

    if (!obj)
        return {};

    addr_t file = obj + this->offsets[OBJECT_HEADER_BODY];
    addr_t filename = file + this->offsets[FILE_OBJECT_FILENAME];
    addr_t filetype = file + this->offsets[FILE_OBJECT_TYPE];

    if (out_file)
        *out_file = file;

    if (out_filetype)
        *out_filetype = filetype;

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.addr = filetype;
    ctx.dtb = info->regs->cr3;

    uint8_t type = 0;
    if (VMI_FAILURE == vmi_read_8(vmi, &ctx, &type))
        return {};

    if (type != 5)
        return {};

    unicode_string_t* filename_us = drakvuf_read_unicode(drakvuf,
            info,
            filename);
    if (!filename_us) return {};
    std::string ret = {(const char*)filename_us->contents};
    vmi_free_unicode_str(filename_us);
    return ret;
}

void fileextractor::print_file_information(drakvuf_trap_info_t* info,
    task_t& task)
{
    std::string flags = parse_flags(task.fo_flags, fo_flags_map, this->format);
    std::string r;
    switch (task.reason)
    {
        case task_t::task_reason::write:
            r = "WriteFile";
            break;
        case task_t::task_reason::del:
            r = "DeleteFile";
            break;
        default:
            r = "Unknown";
            break;
    }

    if (this->format == OUTPUT_KV)
    {
        kvfmt::print("fileextractor", drakvuf, info,
            keyval("FileName", fmt::Qstr(task.filename)),
            keyval("Size", fmt::Nval(task.file_size)),
            keyval("Flags", fmt::Xval(task.fo_flags)),
            fmt::Rstr(flags),
            keyval("SeqNum", fmt::Nval(task.idx)),
            keyval("Reason", fmt::Qstr(r))
        );
    }
    else
    {
        fmt::print(this->format, "fileextractor", drakvuf, info,
            keyval("FileName", fmt::Qstr(task.filename)),
            keyval("Size", fmt::Nval(task.file_size)),
            keyval("Flags", fmt::Xval(task.fo_flags)),
            keyval("FlagsExpanded", fmt::Qstr(flags)),
            keyval("SeqNum", fmt::Nval(task.idx)),
            keyval("Reason", fmt::Qstr(r))
        );
    }
}

void fileextractor::print_extraction_failure(drakvuf_trap_info_t* info,
    const string& filename,
    const string& message)
{
    fmt::print(this->format, "fileextractor_fail", drakvuf, info,
        keyval("FileName", fmt::Qstr(filename)),
        keyval("Message", fmt::Qstr(message))
    );
}

void fileextractor::save_file_metadata(drakvuf_trap_info_t* info,
    addr_t control_area,
    task_t& task)
{
    char* file = NULL;
    if ( asprintf(&file,
            "%s/file.%06d.metadata",
            this->dump_folder,
            task.idx) < 0 )
        return;

    umask(S_IWGRP|S_IWOTH);
    FILE* fp = fopen(file, "w");
    free(file);
    if (!fp)
        return;

    json_object* jobj = json_object_new_object();
    if (!jobj)
    {
        fclose(fp);
        return;
    }

    json_object_object_add(jobj,
        "FileName",
        json_object_new_string(task.filename.data()));

    json_object_object_add(jobj,
        "FileSize",
        json_object_new_int64(task.file_size));

    json_object_object_add(jobj,
        "FileFlags",
        json_object_new_string_fmt("0x%lx (%s)",
            task.fo_flags,
            parse_flags(task.fo_flags, fo_flags_map, OUTPUT_DEFAULT, "0").c_str()));

    json_object_object_add(jobj,
        "SequenceNumber",
        json_object_new_int(task.idx));

    json_object_object_add(jobj,
        "ControlArea",
        json_object_new_string_fmt("0x%lx", control_area));

    json_object_object_add(jobj,
        "PID",
        json_object_new_int64(static_cast<uint64_t>(info->attached_proc_data.pid)));

    json_object_object_add(jobj,
        "PPID",
        json_object_new_int64(static_cast<uint64_t>(info->attached_proc_data.ppid)));

    json_object_object_add(jobj,
        "ProcessName",
        json_object_new_string(info->attached_proc_data.name));

    fprintf(fp, "%s\n", json_object_get_string(jobj));
    fclose(fp);

    json_object_put(jobj);
    print_file_information(info, task);
}

void fileextractor::extract_ca_file(drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    addr_t control_area,
    task_t& task)
{
    addr_t subsection = control_area + this->control_area_size;
    addr_t segment = 0;
    addr_t test = 0;
    uint32_t test2 = 0;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    /* Check whether subsection points back to the control area */
    ctx.addr = control_area + this->offsets[CONTROL_AREA_SEGMENT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &segment) )
        return;

    ctx.addr = segment + this->offsets[SEGMENT_CONTROLAREA];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &test) || test != control_area )
        return;

    ctx.addr = segment + this->offsets[SEGMENT_SIZEOFSEGMENT];
    if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &test) )
        return;

    ctx.addr = segment + this->offsets[SEGMENT_TOTALNUMBEROFPTES];
    if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &test2) )
        return;

    if ( test != (static_cast<addr_t>(test2) * 4096) )
        return;

    char* file = NULL;
    if ( asprintf(&file,
            "%s/file.%06d.mm",
            this->dump_folder,
            task.idx) < 0 )
        return;

    umask(S_IWGRP|S_IWOTH);
    FILE* fp = fopen(file, "w");
    free(file);
    if (!fp)
        return;

    while (subsection)
    {
        /* Check whether subsection points back to the control area */
        ctx.addr = subsection + this->offsets[SUBSECTION_CONTROLAREA];
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &test) ||
            test != control_area )
            break;

        addr_t base = 0;
        uint32_t start = 0;
        uint32_t ptes = 0;

        ctx.addr = subsection + this->offsets[SUBSECTION_SUBSECTIONBASE];
        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &base) )
            break;

        ctx.addr = subsection + this->offsets[SUBSECTION_PTESINSUBSECTION];
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &ptes) )
            break;

        ctx.addr = subsection + this->offsets[SUBSECTION_STARTINGSECTOR];
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &start) )
            break;

        /*
         * The offset into the file is stored implicitely
         * based on the PTE's location within the Subsection.
         */
        addr_t subsection_offset = static_cast<addr_t>(start) * 0x200;
        addr_t ptecount;
        for (ptecount=0; ptecount < ptes; ptecount++)
        {
            addr_t pteoffset = base + this->mmpte_size * ptecount;
            addr_t fileoffset = subsection_offset + ptecount * 0x1000;

            addr_t pte = 0;
            ctx.addr = pteoffset;
            if ( VMI_FAILURE == vmi_read(vmi,
                    &ctx,
                    this->mmpte_size,
                    &pte, NULL) )
                break;

            if ( ENTRY_PRESENT(1, pte) )
            {
                uint8_t page[4096];

                if ( VMI_FAILURE == vmi_read_pa(vmi,
                        VMI_BIT_MASK(12, 48) & pte,
                        4096,
                        &page,
                        NULL) )
                    continue;

                if ( !fseek ( fp, fileoffset, SEEK_SET ) )
                {
                    if ( fwrite(page, 4096, 1, fp) )
                        task.file_size = MAX(task.file_size, fileoffset + 4096);
                }
            }
        }

        ctx.addr = subsection + this->offsets[SUBSECTION_NEXTSUBSECTION];
        if ( !vmi_read_addr(vmi, &ctx, &subsection) )
            break;
    }

    fclose(fp);

    save_file_metadata(info, control_area, task);
}

void fileextractor::extract_file(drakvuf_trap_info_t* info,
    vmi_instance_t vmi,
    task_t& task)
{
    addr_t sop = 0;
    addr_t datasection = 0;
    addr_t sharedcachemap = 0;
    addr_t imagesection = 0;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    ctx.addr = task.file_obj + this->offsets[FILE_OBJECT_SECTIONOBJECTPOINTER];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &sop) )
        return;

    ctx.addr = sop + this->offsets[SECTIONOBJECTPOINTER_DATASECTIONOBJECT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &datasection) )
        return;

    if ( datasection )
        extract_ca_file(info, vmi, datasection, task);

    ctx.addr = sop + this->offsets[SECTIONOBJECTPOINTER_SHAREDCACHEMAP];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &sharedcachemap) )
        return;

    // TODO: extraction from sharedcachemap

    ctx.addr = sop + this->offsets[SECTIONOBJECTPOINTER_IMAGESECTIONOBJECT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &imagesection) )
        return;

    if ( imagesection != datasection )
        extract_ca_file(info, vmi, imagesection, task);
}

/*
 * The approach where the system process list es enumerated looking for
 * the matching cr3 value in each _EPROCESS struct is not going to work
 * if a DKOM attack unhooks the _EPROCESS struct.
 *
 * We can access the _EPROCESS structure by reading the FS_BASE register on x86
 * or the GS_BASE register on x64, which contains the _KPCR.
 *
 * FS/GS -> _KPCR._KPRCB.CurrentThread -> _ETHREAD._KTHREAD.Process = _EPROCESS
 *
 * See: http://www.csee.umbc.edu/~stephens/SECURITY/491M/HiddenProcesses.ppt
 */
void fileextractor::grab_file_by_handle(vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    task_t& task)
{
    get_file_object_flags(info, vmi, task.handle, &task.fo_flags);

    if (this->dump_folder)
        extract_file(info, vmi, task);
    else
        print_file_information(info, task);
}

bool fileextractor::save_file_chunk(int file_sequence_number,
    void* buffer,
    size_t size)
{
    char* file = nullptr;
    if ( asprintf(&file,
            "%s/file.%06d.mm",
            this->dump_folder,
            file_sequence_number) < 0 )
        return false;

    umask(S_IWGRP|S_IWOTH);
    FILE* fp = fopen(file, "a");
    free(file);
    if (!fp) return false;

    bool success = (fwrite(buffer, size, 1, fp) == 1);
    fclose(fp);

    return success;
}

uint64_t fileextractor::make_hook_id(drakvuf_trap_info_t* info)
{
    uint64_t u64_pid = info->attached_proc_data.pid;
    uint64_t u64_tid = info->attached_proc_data.tid;
    return (u64_pid << 32) | u64_tid;
}

uint64_t fileextractor::make_task_id(vmi_pid_t pid, handle_t handle)
{
    uint64_t u64_pid = pid;
    uint64_t u64_handle = handle;
    return (u64_pid << 32) | u64_handle;
}

uint64_t fileextractor::make_task_id(task_t& task)
{
    return make_task_id(task.target.ret_pid, task.handle);
}

void fileextractor::free_pool(addr_t va)
{
    for (auto pool: pools)
        if (va == pool.first)
        {
            pool.second = true;
            return;
        }
}

addr_t fileextractor::find_pool()
{
    for (auto pool: pools)
        if (pool.second)
        {
            pool.second = false;
            return pool.first;
        }

    return 0;
}

void fileextractor::free_resources(drakvuf_trap_info_t* info, task_t& task)
{
    // One could not restore all registers at once like this:
    //     memcpy(info->regs, &saved_regs, sizeof(x86_registers_t)),
    // because thus kernel structures could be affected.
    // For example on Windows 7 x64 GS BASE stores pointer to KPCR. If save
    // GS BASE on vCPU0 and start injections Windows scheduler could switch
    // thread to other vCPU1. After restoring all registers vCPU1's GS BASE
    // would point to KPCR of vCPU0.
    info->regs->rax = task.target.regs.rax;
    info->regs->rcx = task.target.regs.rcx;
    info->regs->rdx = task.target.regs.rdx;
    info->regs->rbx = task.target.regs.rbx;
    info->regs->rbp = task.target.regs.rbp;
    info->regs->rsp = task.target.regs.rsp;
    info->regs->rdi = task.target.regs.rdi;
    info->regs->rsi = task.target.regs.rsi;
    info->regs->r8  = task.target.regs.r8;
    info->regs->r9  = task.target.regs.r9;
    info->regs->r10 = task.target.regs.r10;
    info->regs->r11 = task.target.regs.r11;
    info->regs->r12 = task.target.regs.r12;
    info->regs->r13 = task.target.regs.r13;
    info->regs->r14 = task.target.regs.r14;
    info->regs->r15 = task.target.regs.r15;
    info->regs->rip = task.target.regs.rip;
    info->regs->rsp = task.target.regs.rsp;

    free_pool(task.pool);
    tasks.erase(make_task_id(task));
}

void fileextractor::read_vm(vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    task_t& task)
{
    auto size = task.bytes_to_read;
    if (!size)
        return;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = task.pool
    );

    auto num_pages = size / VMI_PS_4KB;
    if (num_pages * VMI_PS_4KB < size)
        ++num_pages;
    auto access_ptrs = new void* [num_pages] { 0 };

    uint64_t bytes_read = 0;
    if (VMI_SUCCESS == vmi_mmap_guest(vmi, &ctx, num_pages, access_ptrs))
        for (size_t i = 0; i < num_pages; ++i)
            if (access_ptrs[i])
            {
                uint64_t bytes_to_read = std::min((uint64_t)VMI_PS_4KB, size - bytes_read);
                bytes_read += bytes_to_read;
                save_file_chunk(task.idx, static_cast<uint8_t*>(access_ptrs[i]), bytes_to_read);
                munmap(access_ptrs[i], VMI_PS_4KB);
            }

    delete[] access_ptrs;
}

bool fileextractor::is_handle_valid(handle_t handle)
{
    return handle && !VMI_GET_BIT(handle, 31);
}

/*****************************************************************************
 *                             Public interface                              *
 *****************************************************************************/
fileextractor::fileextractor(drakvuf_t drakvuf,
    const fileextractor_config* c,
    output_format_t output)
    : pluginex(drakvuf, output)
    , is32bit(drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E)
    , offsets(new size_t[__OFFSET_MAX])
    , dump_folder(c->dump_folder)
    , format(output)
    , sequence_number()
{
    if ( !drakvuf_get_kernel_struct_members_array_rva(drakvuf,
            offset_names, __OFFSET_MAX, this->offsets) )
        throw -1;

    if ( !drakvuf_get_kernel_struct_size(drakvuf,
            "_CONTROL_AREA", &this->control_area_size) )
        throw -1;

    if ( this->is32bit )
        this->mmpte_size = 4;
    else
        this->mmpte_size = 8;

    this->queryvolumeinfo_va = drakvuf_kernel_symbol_to_va(drakvuf,
            "ZwQueryVolumeInformationFile");
    this->queryinfo_va = drakvuf_kernel_symbol_to_va(drakvuf,
            "ZwQueryInformationFile");
    this->createsection_va = drakvuf_kernel_symbol_to_va(drakvuf,
            "ZwCreateSection");
    this->close_handle_va = drakvuf_kernel_symbol_to_va(drakvuf,
            "ZwClose");
    this->mapview_va = drakvuf_kernel_symbol_to_va(drakvuf,
            "ZwMapViewOfSection");
    this->unmapview_va = drakvuf_kernel_symbol_to_va(drakvuf,
            "ZwUnmapViewOfSection");
    this->readfile_va = drakvuf_kernel_symbol_to_va(drakvuf,
            "ZwReadFile");
    this->waitobject_va = drakvuf_kernel_symbol_to_va(drakvuf,
            "ZwWaitForSingleObject");
    this->exallocatepool_va = drakvuf_kernel_symbol_to_va(drakvuf,
            "ExAllocatePoolWithTag");
    this->exfreepool_va = drakvuf_kernel_symbol_to_va(drakvuf,
            "ExFreePoolWithTag");
    this->memcpy_va = drakvuf_kernel_symbol_to_va(drakvuf,
            "RtlCopyMemoryNonTemporal");

    if (!this->queryvolumeinfo_va ||
        !this->queryinfo_va ||
        !this->createsection_va ||
        !this->close_handle_va ||
        !this->mapview_va ||
        !this->unmapview_va ||
        !this->readfile_va ||
        !this->waitobject_va ||
        !this->exallocatepool_va ||
        !this->exfreepool_va ||
        !this->memcpy_va)
    {
        PRINT_DEBUG("[FILEEXTRACTOR] Failed to get function address\n");
        throw -1;
    }

    this->setinformation_hook = createSyscallHook("NtSetInformationFile",
            &fileextractor::setinformation_cb);
    this->writefile_hook = createSyscallHook("NtWriteFile",
            &fileextractor::writefile_cb);
    this->close_hook = createSyscallHook("NtClose",
            &fileextractor::close_cb);
    this->createsection_hook = createSyscallHook("ZwCreateSection",
            &fileextractor::createsection_cb);
    this->createfile_hook = createSyscallHook("NtCreateFile",
            &fileextractor::createfile_cb);
    this->openfile_hook = createSyscallHook("NtOpenFile",
            &fileextractor::openfile_cb);
}

/* NOTE One should run drakvuf loop to restore VM state.
 *
 * The plug-in injects syscalls thus changes the state. So to avoid BSOD
 * one should restore state here. This requires to allow VM to live for a
 * while.
 *
 * Hint: there is no need to wait all files read finish. Just waite every
 * hook and restore state.
 */
fileextractor::~fileextractor()
{
    delete[] offsets;
}

bool fileextractor::stop_impl()
{
    for (auto& i: tasks)
        if (i.second->stage != task_t::stage_t::pending)
            return false;
    return true;
}
