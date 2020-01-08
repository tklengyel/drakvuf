/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
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

#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/x86.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <glib.h>

#include "libdrakvuf/libdrakvuf.h"
#include <libinjector/libinjector.h>

void init_argument(struct argument* arg, argument_type_t type, size_t size, void* data)
{
    arg->type = type;
    arg->size = size;
    arg->data = data;
    arg->data_on_stack = 0;
}

void init_int_argument(struct argument* arg, uint64_t value)
{
    arg->type = ARGUMENT_INT;
    arg->size = 0; // unused
    arg->data = (void*)value;
    arg->data_on_stack = 0;
}

void init_unicode_argument(struct argument* arg, unicode_string_t* us)
{
    if (us && us->length)
        init_argument(arg, ARGUMENT_STRING, us->length, us->contents);
    else
        init_int_argument(arg, 0);
}

static addr_t place_string_on_stack_32(vmi_instance_t vmi, drakvuf_trap_info_t* info, addr_t addr, void const* str, size_t str_len)
{
    if (!str) return 0;

    const uint32_t string_align = 64;
    const size_t len = str_len + 2;// null terminated string

    // the stack has to be aligned _not_ to 0x4 but to 64
    // for special instructions operating on strings to work correctly
    // this string has to be aligned as well!
    addr -= len + string_align - (len % string_align);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr,
    };

    if (VMI_FAILURE == vmi_write(vmi, &ctx, len, (void*) str, NULL))
        return 0;

    return addr;
}

static addr_t place_string_on_stack_64(vmi_instance_t vmi, drakvuf_trap_info_t* info, addr_t addr, void const* str, size_t str_len)
{
    if (!str) return addr;
    // String length with null terminator
    size_t len = str_len + 2;
    addr_t orig_addr = addr;

    addr -= len;
    // Align string address on 32B boundary (for SSE2 instructions).
    addr &= ~0x1f;

    size_t buf_len = orig_addr - addr;
    void* buf = g_try_malloc0(buf_len);
    if (!buf) return 0;
    memcpy(buf, str, str_len);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr,
    };

    status_t status = vmi_write(vmi, &ctx, buf_len, buf, NULL);
    g_free(buf);

    return status == VMI_FAILURE ? 0 : addr;
}

static addr_t place_struct_on_stack_32(vmi_instance_t vmi, drakvuf_trap_info_t* info, addr_t addr, void* data, size_t size)
{
    const uint32_t stack_align = 64;

    addr -= size;
    addr -= addr % stack_align;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr,
    };

    status_t status = vmi_write(vmi, &ctx, size, data, NULL);

    return status == VMI_FAILURE ? 0 : addr;
}

static addr_t place_struct_on_stack_64(vmi_instance_t vmi, drakvuf_trap_info_t* info, addr_t addr, void* data, size_t size)
{
    /* According to Microsoft Doc "Building C/C++ Programs":
     * > The alignment of the beginning of a structure or a union is the maximum
     * > alignment of any individual member.
     */
    addr -= size;
    addr &= ~0xf; // Align stack

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr,
    };

    status_t status = vmi_write(vmi, &ctx, size, data, NULL);

    return status == VMI_FAILURE ? 0 : addr;
}

static bool setup_stack_32(vmi_instance_t vmi, drakvuf_trap_info_t* info, struct argument args[], int nb_args)
{
    addr_t addr = info->regs->rsp;

    // make room for strings and structs into guest's stack
    for (int i = 0; i < nb_args; i++)
    {
        switch (args[i].type)
        {
            case ARGUMENT_STRING:
                addr = place_string_on_stack_32(vmi, info, addr, args[i].data, args[i].size);
                if ( !addr ) goto err;
                args[i].data_on_stack = addr;
                break;
            case ARGUMENT_STRUCT:
                addr = place_struct_on_stack_32(vmi, info, addr, args[i].data, args[i].size);
                if ( !addr ) goto err;
                args[i].data_on_stack = addr;
                break;
            case ARGUMENT_INT:
                args[i].data_on_stack = (uint64_t)args[i].data;
                break;
            default:
                goto err;
        }
    }

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    // write parameters into guest's stack
    for (int i = nb_args-1; i >= 0; i--)
    {
        addr -= 0x4;
        ctx.addr = addr;
        if (VMI_FAILURE == vmi_write_32(vmi, &ctx, (uint32_t*)&args[i].data_on_stack))
            goto err;
    }

    // save the return address
    addr -= 0x4;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_32(vmi, &ctx, (uint32_t*) &info->regs->rip))
        goto err;

    // grow the stack
    info->regs->rsp = addr;

    return 1;

err:
    return 0;
}

static bool setup_stack_64(vmi_instance_t vmi, drakvuf_trap_info_t* info, struct argument args[], int nb_args)
{
    uint64_t nul64 = 0;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    addr_t addr = info->regs->rsp;

    if ( args )
    {
        // make room for strings and structs into guest's stack
        for (int i = 0; i < nb_args; i++)
        {
            switch (args[i].type)
            {
                case ARGUMENT_STRING:
                    addr = place_string_on_stack_64(vmi, info, addr, args[i].data, args[i].size);
                    if ( !addr ) goto err;
                    args[i].data_on_stack = addr;
                    break;
                case ARGUMENT_STRUCT:
                    addr = place_struct_on_stack_64(vmi, info, addr, args[i].data, args[i].size);
                    if ( !addr ) goto err;
                    args[i].data_on_stack = addr;
                    break;
                case ARGUMENT_INT:
                    args[i].data_on_stack = (uint64_t)args[i].data;
                    break;
                default:
                    goto err;
            }
        }

        /* According to Microsoft Doc "Building C/C++ Programs":
         * > The stack will always be maintained 16-byte aligned, except within the prolog
         * > (for example, after the return address is pushed), and except where indicated
         * > in Function Types for a certain class of frame functions.
         *
         * So place one extra argument to achieve alignment just before CALL instruction.
         */
        if (nb_args % 2)
        {
            addr -= 0x8;
            ctx.addr = addr;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
                goto err;
        }

        // http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
        //
        // First 4 parameters to functions are always passed in registers
        // P1=rcx, P2=rdx, P3=r8, P4=r9
        // 5th parameter onwards (if any) passed via the stack

        // write parameters (5th onwards) into guest's stack
        for (int i = nb_args-1; i > 3; i--)
        {
            addr -= 0x8;
            ctx.addr = addr;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &(args[i].data_on_stack)) )
                goto err;
        }

        switch (nb_args)
        {
            default:
                // p4
                info->regs->r9 = args[3].data_on_stack;
            // fall through
            case 3:
                // p3
                info->regs->r8 = args[2].data_on_stack;
            // fall through
            case 2:
                // p2
                info->regs->rdx = args[1].data_on_stack;
            // fall through
            case 1:
                // p1
                info->regs->rcx = args[0].data_on_stack;
            // fall through
            case 0:
                break;
        }
    }

    // allocate 0x20 "homing space"
    for (int i = 0; i < 4; i++)
    {
        addr -= 0x8;
        ctx.addr = addr;
        if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
            goto err;
    }

    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    // grow the stack
    info->regs->rsp = addr;

    return 1;

err:
    return 0;
}

static addr_t place_string_on_linux_stack(vmi_instance_t vmi, drakvuf_trap_info_t* info, addr_t addr, void const* str, size_t str_len)
{
    if (!str) return addr;
    // String length with null terminator
    size_t len = str_len + 2;
    addr_t orig_addr = addr;

    addr -= len;
    // Align string address on 32B boundary (for SSE2 instructions).
    addr &= ~0x1f;

    size_t buf_len = orig_addr - addr;
    void* buf = g_try_malloc0(buf_len);

    if (!buf) return 0;
    memcpy(buf, str, str_len);

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr,
    };

    status_t status = vmi_write(vmi, &ctx, buf_len, buf, NULL);
    g_free(buf);

    return status == VMI_FAILURE ? 0 : addr;
}

bool setup_linux_stack(vmi_instance_t vmi, drakvuf_trap_info_t* info, struct argument args[], int nb_args)
{
    uint64_t nul64 = 0;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    addr_t addr = info->regs->rsp;

    // unsigned int cpl = info->regs->cs_sel & 3;
    // PRINT_DEBUG("CPL value is : %d\n", cpl);

    addr = info->regs->rsp;

    if ( args )
    {
        // make room for strings and structs into guest's stack
        for (int i = 0; i < nb_args; i++)
        {
            switch (args[i].type)
            {
                case ARGUMENT_STRING:
                    addr = place_string_on_linux_stack(vmi, info, addr, args[i].data, args[i].size);
                    if ( !addr ) goto err;
                    args[i].data_on_stack = addr;
                    break;
                case ARGUMENT_STRUCT:
                    addr = place_struct_on_stack_64(vmi, info, addr, args[i].data, args[i].size);
                    if ( !addr ) goto err;
                    args[i].data_on_stack = addr;
                    break;
                case ARGUMENT_INT:
                    args[i].data_on_stack = (uint64_t)args[i].data;
                    break;
                default:
                    goto err;
            }
        }

        //  x86-64: Maintain 16-byte stack alignment
        //  the stack pointer misaligned by 8 bytes on function entry
        if (addr % 0x10 == 0)
        {
            addr -= 0x8;
            ctx.addr = addr;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
                goto err;
        }
        // Stack aligned before settting up registers

        // first 6 arguments are sent by registers
        // 1: rdi
        // 2: rsi
        // 3: rdx
        // 4: rcx
        // 5: r8
        // 6: r9

        // if number of arguments number > 6
        // put them on stack
        for (int i = nb_args-1; i > 5; i--)
        {
            addr -= 0x8;
            ctx.addr = addr;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &(args[i].data_on_stack)) )
                goto err;
        }

        switch (nb_args)
        {
            default:
                info->regs->r9 = args[5].data_on_stack;
            // fall through
            case 5:
                info->regs->r8 = args[4].data_on_stack;
            // fall through
            case 4:
                info->regs->rcx = args[3].data_on_stack;
            // fall through
            case 3:
                info->regs->rdx = args[2].data_on_stack;
            // fall through
            case 2:
                info->regs->rsi = args[1].data_on_stack;
            // fall through
            case 1:
                info->regs->rdi = args[0].data_on_stack;
            // fall through
            case 0:
                break;
        }
    }

    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    // grow the stack
    info->regs->rsp = addr;
    info->regs->rbp = addr;

    return true;

err:
    return false;
}

bool setup_stack_locked(
    drakvuf_t drakvuf,
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    struct argument args[],
    int nb_args)
{
    if (drakvuf_get_os_type(drakvuf) == VMI_OS_WINDOWS)
    {
        bool is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
        return is32bit ? setup_stack_32(vmi, info, args, nb_args) : setup_stack_64(vmi, info, args, nb_args);
    }
    else if (drakvuf_get_os_type(drakvuf) == VMI_OS_LINUX)
    {
        return setup_linux_stack(vmi, info, args, nb_args);
    }
    else
        return false;
}

bool setup_stack(
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    struct argument args[],
    int nb_args)
{

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool success = setup_stack_locked(drakvuf, vmi, info, args, nb_args);
    drakvuf_release_vmi(drakvuf);
    return success;
}