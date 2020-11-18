/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
*                                                                         *
* DRAKVUF (C) 2014-2020 Tamas K Lengyel.                                  *
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

#include "../plugins.h"
#include "filedelete.h"
#include "private.h"

#include <libinjector/libinjector.h>

void free_pool(std::map<addr_t, bool>& pools, addr_t va)
{
    for (auto pool: pools)
        if (va == pool.first)
        {
            pool.second = true;
            return;
        }
}

addr_t find_pool(std::map<addr_t, bool>& pools)
{
    for (auto pool: pools)
        if (pool.second)
        {
            pool.second = false;
            return pool.first;
        }

    return 0;
}

void free_resources(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;
    filedelete* f = injector->f;

    f->closing_handles[std::make_pair(injector->target_pid, injector->target_tid)] = true;
    free_pool(f->pools, injector->pool);

    // One could not restore all registers at once like this:
    //     memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t)),
    // because thus kernel structures could be affected.
    // For example on Windows 7 x64 GS BASE stores pointer to KPCR. If save
    // GS BASE on vCPU0 and start injections Windows scheduler could switch
    // thread to other vCPU1. After restoring all registers vCPU1's GS BASE
    // would point to KPCR of vCPU0.
    info->regs->rax = injector->saved_regs.rax;
    info->regs->rcx = injector->saved_regs.rcx;
    info->regs->rdx = injector->saved_regs.rdx;
    info->regs->rbx = injector->saved_regs.rbx;
    info->regs->rbp = injector->saved_regs.rbp;
    info->regs->rsp = injector->saved_regs.rsp;
    info->regs->rdi = injector->saved_regs.rdi;
    info->regs->rsi = injector->saved_regs.rsi;
    info->regs->r8 = injector->saved_regs.r8;
    info->regs->r9 = injector->saved_regs.r9;
    info->regs->r10 = injector->saved_regs.r10;
    info->regs->r11 = injector->saved_regs.r11;
    info->regs->r12 = injector->saved_regs.r12;
    info->regs->r13 = injector->saved_regs.r13;
    info->regs->r14 = injector->saved_regs.r14;
    info->regs->r15 = injector->saved_regs.r15;

    info->regs->rip = injector->saved_regs.rip;
    info->regs->rsp = injector->saved_regs.rsp;

    drakvuf_remove_trap(drakvuf, injector->bp, (drakvuf_trap_free_t)free);
    g_free(injector->buffer);
    g_free(injector);
}

bool inject_allocate_pool(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = injector->saved_regs.rsp;

    struct argument args[3] = {};
    init_int_argument(&args[0], 0); // NonPagedPool
    init_int_argument(&args[1], BYTES_TO_READ);
    init_int_argument(&args[2], 0);

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 3))
        return false;

    info->regs->rip = injector->f->exallocatepool_va;

    injector->bp->cb = exallocatepool_cb;

    return true;
}

bool inject_memcpy(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = injector->saved_regs.rsp;

    injector->bytes_to_read = std::min(injector->file_size - injector->file_offset, BYTES_TO_READ);

    struct argument args[3] = {};
    init_int_argument(&args[0], injector->pool);
    init_int_argument(&args[1], injector->view_base);
    init_int_argument(&args[2], injector->bytes_to_read);

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 3))
        return false;

    info->regs->rip = injector->f->memcpy_va;
    injector->bp->cb = memcpy_cb;

    return true;
}

bool inject_unmapview(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = injector->saved_regs.rsp;

    struct argument args[2] = {};

    init_int_argument(&args[0], 0xffffffffffffffff); // current process pseudo handle
    init_int_argument(&args[1], injector->view_base);

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 2))
        return false;

    info->regs->rip = injector->f->unmapview_va;
    injector->bp->cb = unmapview_cb;

    return true;
}

bool inject_mapview(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = injector->saved_regs.rsp;

    struct argument args[10] = {};
    uint64_t base = 0;
    struct _LARGE_INTEGER offset = { 0 };
    offset.QuadPart = injector->file_offset;
    uint64_t view_size = std::min(injector->file_size - injector->file_offset, BYTES_TO_READ);

    init_int_argument   (&args[0], injector->section_handle); // SectionHandle
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

    injector->mapview.base = args[2].data_on_stack;
    injector->mapview.size = args[6].data_on_stack;

    info->regs->rip = injector->f->mapview_va;
    injector->bp->cb = mapview_cb;

    return true;
}

bool inject_createsection(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = injector->saved_regs.rsp;

    struct argument args[7] = {};
    handle_t section_handle = 0;
    struct _LARGE_INTEGER max_size = { 0 };
    max_size.QuadPart = injector->file_size;

    init_struct_argument(&args[0], section_handle); // SectionHandle
    init_int_argument(&args[1], 0xf0005); // DesiredAccess = SECTION_MAP_READ | SECTION_QUERY
    init_int_argument(&args[2], 0); // ObjectAttributes = 0
    init_struct_argument(&args[3], max_size); // MaximumSize = 0
    init_int_argument(&args[4], 2); // SectionPageProtection = PAGE_READONLY
    init_int_argument(&args[5], 0x8000000); // AllocationAttributes = SEC_COMMIT
    init_int_argument(&args[6], injector->handle); // FileHandle

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 7))
        return false;

    injector->createsection.handle = args[0].data_on_stack;

    info->regs->rip = injector->f->createsection_va;
    injector->bp->cb = injected_createsection_cb;

    return true;
}

bool inject_queryinfo(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = injector->saved_regs.rsp;

    struct argument args[5] = {};
    struct IO_STATUS_BLOCK_32 io_status_block_32 = {};
    struct IO_STATUS_BLOCK_64 io_status_block_64 = {};
    struct FILE_STANDARD_INFORMATION dev_info = {};

    init_int_argument(&args[0], injector->handle);
    if (injector->is32bit)
        init_struct_argument(&args[1], io_status_block_32);
    else
        init_struct_argument(&args[1], io_status_block_64);
    init_struct_argument(&args[2], dev_info);
    init_int_argument(&args[3], sizeof(dev_info));
    init_int_argument(&args[4], FileStandardInformation);

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 5))
        return false;

    injector->queryinfo.out = args[2].data_on_stack;

    info->regs->rip = injector->f->queryinfo_va;
    injector->bp->cb = queryinfo_cb;

    return true;
}

bool inject_queryvolumeinfo(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = injector->saved_regs.rsp;

    struct argument args[5] = {};
    struct IO_STATUS_BLOCK_32 io_status_block_32 = {};
    struct IO_STATUS_BLOCK_64 io_status_block_64 = {};
    struct FILE_FS_DEVICE_INFORMATION dev_info = {};

    init_int_argument(&args[0], injector->handle);
    if (injector->is32bit)
        init_struct_argument(&args[1], io_status_block_32);
    else
        init_struct_argument(&args[1], io_status_block_64);
    init_struct_argument(&args[2], dev_info);
    init_int_argument(&args[3], sizeof(dev_info));
    init_int_argument(&args[4], FileFsDeviceInformation);

    if (!setup_stack_locked(drakvuf, vmi, info->regs, args, 5))
        return false;

    injector->queryvolumeinfo.out = args[2].data_on_stack;

    injector->bp->type = BREAKPOINT;
    injector->bp->cb = queryvolumeinfo_cb;
    injector->bp->data = injector;
    injector->bp->breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp->breakpoint.dtb = info->regs->cr3;
    injector->bp->breakpoint.addr_type = ADDR_VA;
    injector->bp->breakpoint.addr = info->regs->rip;

    if ( !drakvuf_add_trap(drakvuf, injector->bp) )
    {
        PRINT_DEBUG("Failed to trap return location of injected function call @ 0x%lx!\n",
                    injector->bp->breakpoint.addr);
        return false;
    }

    info->regs->rip = injector->f->queryvolumeinfo_va;

    return true;
}
