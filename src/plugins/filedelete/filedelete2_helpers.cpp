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

#include "../plugins.h"
#include "filedelete.h"
#include "private.h"

#include <libinjector/libinjector.h>

void free_resources(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    wrapper_t* injector = (wrapper_t*)info->trap->data;
    filedelete* f = injector->f;

    f->closing_handles[std::make_pair(info->regs->cr3, injector->target_thread_id)] = true;

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

    drakvuf_remove_trap(drakvuf, injector->bp, (drakvuf_trap_free_t)free);

    g_free(injector);
}

bool inject_free_pool(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = injector->saved_regs.rsp;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };
    struct argument args[2] = { {0} };
    const size_t int_size = injector->is32bit ? sizeof (uint32_t) : sizeof (uint64_t);

    init_argument(&args[0], ARGUMENT_INT, int_size, (void*)injector->pool);
    init_argument(&args[1], ARGUMENT_INT, int_size, (void*)'SMTP'); // TODO Debug-only

    bool stack_ok = injector->is32bit ? setup_stack_32(vmi, info, &ctx, args, 1) : setup_stack_64(vmi, info, &ctx, args, 1);
    if (!stack_ok)
        return false;

    info->regs->rip = injector->f->exfreepool_va;

    injector->bp->name = "ExFreePool ret";
    injector->bp->cb = exfreepool_cb;

    return true;
}

bool inject_allocate_pool(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    // Remove stack arguments and home space from previous injection
    info->regs->rsp = injector->saved_regs.rsp;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = info->regs->rsp,
    };
    struct argument args[3] = { {0} };
    uint64_t null = 0;
    const size_t int_size = injector->is32bit ? sizeof (uint32_t) : sizeof (uint64_t);

    init_argument(&args[0], ARGUMENT_INT, int_size, (void*)null); // NonPagedPool
    init_argument(&args[1], ARGUMENT_INT, int_size, (void*)BYTES_TO_READ);
    init_argument(&args[2], ARGUMENT_INT, int_size, (void*)'SMTP'); // Tag value TODO Debug-only

    bool stack_ok = injector->is32bit ? setup_stack_32(vmi, info, &ctx, args, 3) : setup_stack_64(vmi, info, &ctx, args, 3);
    if ( !stack_ok )
    {
        g_free(injector);
    }

    injector->bp = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    if (!injector->bp)
    {
        g_free(injector);
    }

    injector->bp->type = BREAKPOINT;
    injector->bp->name = "QueryObject ret";
    injector->bp->cb = exallocatepool_cb;
    injector->bp->data = injector;
    injector->bp->breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp->breakpoint.dtb = info->regs->cr3;
    injector->bp->breakpoint.addr_type = ADDR_VA;
    injector->bp->breakpoint.addr = info->regs->rip;

    if ( !drakvuf_add_trap(drakvuf, injector->bp) )
    {
        PRINT_DEBUG("Failed to trap return location of injected function call @ 0x%lx!\n",
                    injector->bp->breakpoint.addr);
        g_free(injector->bp);
        g_free(injector);
        return false;
    }

    info->regs->rip = injector->f->exallocatepool_va;

    return true;
}

bool inject_waitobject(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    // Preserve stack to read buffer contents after wait

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = info->regs->rsp,
    };

    struct argument args[3] = { {0} };
    uint64_t null = 0;
    const size_t int_size = injector->is32bit ? sizeof (uint32_t) : sizeof (uint64_t);

    init_argument(&args[0], ARGUMENT_INT, int_size, (void*)injector->handle);
    init_argument(&args[1], ARGUMENT_INT, int_size, (void*)null);
    init_argument(&args[2], ARGUMENT_INT, int_size, (void*)null);

    bool stack_ok = injector->is32bit ? setup_stack_32(vmi, info, &ctx, args, 3) : setup_stack_64(vmi, info, &ctx, args, 3);
    if ( !stack_ok )
        return true;

    info->regs->rip = injector->f->waitobject_va;

    injector->bp->name = "WaitForSingleObject ret";
    injector->bp->cb = waitobject_cb;

    return true;
}

bool inject_readfile(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    if (!injector->pool)
        return false;

    // Remove stack arguments and home space from previous injection
    info->regs->rsp = injector->saved_regs.rsp;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = info->regs->rsp,
    };
    struct argument args[9] = { {0} };
    struct _LARGE_INTEGER byte_offset = { .QuadPart = injector->ntreadfile_info.bytes_read };
    const union IO_STATUS_BLOCK io_status_block = { { 0 } };
    uint64_t null = 0;

    const size_t int_size = injector->is32bit ? sizeof (uint32_t) : sizeof (uint64_t);

    init_argument(&args[0], ARGUMENT_INT, int_size, (void*)injector->handle);
    init_argument(&args[1], ARGUMENT_INT, int_size, (void*)null);
    init_argument(&args[2], ARGUMENT_INT, int_size, (void*)null);
    init_argument(&args[3], ARGUMENT_INT, int_size, (void*)null);
    init_argument(&args[4], ARGUMENT_STRUCT, sizeof(union IO_STATUS_BLOCK), (void*)&io_status_block);
    init_argument(&args[5], ARGUMENT_INT, int_size, (void*)injector->pool);
    init_argument(&args[6], ARGUMENT_INT, int_size, (void*)BYTES_TO_READ);
    init_argument(&args[7], ARGUMENT_STRUCT, sizeof(byte_offset), (void*)&byte_offset);
    init_argument(&args[8], ARGUMENT_INT, int_size, (void*)null);

    bool stack_ok = injector->is32bit ? setup_stack_32(vmi, info, &ctx, args, 9) : setup_stack_64(vmi, info, &ctx, args, 9);
    if ( !stack_ok )
        return false;

    injector->ntreadfile_info.io_status_block = args[4].data_on_stack;
    injector->ntreadfile_info.out = args[5].data_on_stack;

    info->regs->rip = injector->f->readfile_va;

    injector->bp->name = "ReadFile ret";
    injector->bp->cb = readfile_cb;

    return true;
}

bool inject_queryobject(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_instance_t vmi, wrapper_t* injector)
{
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = info->regs->rsp,
    };

    struct argument args[5] = { {0} };
    const union IO_STATUS_BLOCK io_status_block = { { 0 } };
    struct FILE_FS_DEVICE_INFORMATION dev_info = { 0 };
    const size_t int_size = injector->is32bit ? sizeof (uint32_t) : sizeof (uint64_t);

    init_argument(&args[0], ARGUMENT_INT, int_size, (void*)injector->handle);
    init_argument(&args[1], ARGUMENT_STRUCT, sizeof(union IO_STATUS_BLOCK), (void*)&io_status_block);
    init_argument(&args[2], ARGUMENT_STRUCT, sizeof(struct FILE_FS_DEVICE_INFORMATION), (void*)&dev_info);
    init_argument(&args[3], ARGUMENT_INT, int_size, (void*)sizeof(struct FILE_FS_DEVICE_INFORMATION));
    init_argument(&args[4], ARGUMENT_INT, int_size, (void*)4); // FileFsDeviceInformation

    bool stack_ok = injector->is32bit ? setup_stack_32(vmi, info, &ctx, args, 5) : setup_stack_64(vmi, info, &ctx, args, 5);
    if ( !stack_ok )
        return false;

    injector->ntqueryobject_info.out = args[2].data_on_stack;

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
        PRINT_DEBUG("Failed to trap return location of injected function call @ 0x%lx!\n",
                    injector->bp->breakpoint.addr);
        return false;
    }

    info->regs->rip = injector->f->queryobject_va;

    return true;
}
