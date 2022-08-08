/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
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

#include <libvmi/libvmi.h>
#include <libvmi/x86.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <glib.h>

#include "libdrakvuf/libdrakvuf.h"
#include <libinjector/libinjector.h>
#include "private.h"

void init_argument(struct argument* arg, argument_type_t type, size_t size, const void* data)
{
    arg->type = type;
    arg->size = size;
    arg->data = data;
    arg->data_on_stack = 0;
}

void init_int_argument(struct argument* arg, uint64_t value)
{
    init_argument(arg, ARGUMENT_INT, 0 /* unused */, (void*)value);
}

void init_string_argument(struct argument* arg, const char* string)
{
    init_argument(arg, ARGUMENT_STRING, strlen(string), string);
}

void init_array_argument(struct argument* arg, struct argument array[], int size)
{
    init_argument(arg, ARGUMENT_ARRAY, size, array);
}

void init_unicode_argument(struct argument* arg, unicode_string_t* us)
{
    if (us && us->length)
        init_argument(arg, ARGUMENT_STRING, us->length, us->contents);
    else
        init_int_argument(arg, 0);
}

static addr_t place_string_on_stack_32(vmi_instance_t vmi, x86_registers_t* regs, addr_t addr, void const* str, size_t str_len)
{
    if (!str) return 0;

    const uint32_t string_align = 64;
    const size_t len = str_len + 2;// null terminated string

    // the stack has to be aligned _not_ to 0x4 but to 64
    // for special instructions operating on strings to work correctly
    // this string has to be aligned as well!
    addr -= len + string_align - (len % string_align);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = regs->cr3,
        .addr = addr
    );

    if (VMI_FAILURE == vmi_write(vmi, &ctx, len, (void*) str, NULL))
    {
        PRINT_DEBUG("Could not place string(%s) on stack\n", (char*)str);
        return 0;
    }

    return addr;
}

static addr_t place_string_on_stack_64(vmi_instance_t vmi, x86_registers_t* regs, addr_t addr, void const* str, size_t str_len)
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
    if (!buf)
    {
        PRINT_DEBUG("Could not allocate buffer\n");
        return 0;
    }
    memcpy(buf, str, str_len);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = regs->cr3,
        .addr = addr
    );

    if (VMI_FAILURE == vmi_write(vmi, &ctx, buf_len, buf, NULL))
    {
        PRINT_DEBUG("Could not place string(%s) on stack\n", (char*)str);
        g_free(buf);
        return 0;
    }
    g_free(buf);

    return addr;
}

static addr_t place_struct_on_stack_32(vmi_instance_t vmi, x86_registers_t* regs, addr_t addr, const void* data, size_t size)
{
    const uint32_t stack_align = 64;

    addr -= size;
    addr -= addr % stack_align;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = regs->cr3,
        .addr = addr
    );

    if (VMI_FAILURE == vmi_write(vmi, &ctx, size, (void*)data, NULL))
    {
        PRINT_DEBUG("Could not place struct on stack\n");
        return 0;
    }

    return addr;
}

static addr_t place_struct_on_stack_64(vmi_instance_t vmi, x86_registers_t* regs, addr_t addr, const void* data, size_t size)
{
    /* According to Microsoft Doc "Building C/C++ Programs":
     * > The alignment of the beginning of a structure or a union is the maximum
     * > alignment of any individual member.
     */
    addr -= size;
    addr &= ~0xf; // Align stack

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = regs->cr3,
        .addr = addr
    );

    if (VMI_FAILURE == vmi_write(vmi, &ctx, size, (void*)data, NULL))
    {
        PRINT_DEBUG("Could not place struct on stack\n");
        return 0;
    }

    return addr;
}

static addr_t place_argument_on_addr_32(vmi_instance_t vmi, x86_registers_t* regs, struct argument* arg, addr_t addr)
{
    switch (arg->type)
    {
        case ARGUMENT_STRING:
        {
            addr = place_string_on_stack_32(vmi, regs, addr, arg->data, arg->size);
            if ( !addr ) goto err;
            arg->data_on_stack = addr;
            break;
        }
        case ARGUMENT_STRUCT:
        {
            addr = place_struct_on_stack_32(vmi, regs, addr, arg->data, arg->size);
            if ( !addr ) goto err;
            arg->data_on_stack = addr;
            break;
        }
        case ARGUMENT_INT:
        {
            arg->data_on_stack = (uint64_t)arg->data;
            addr -= 0x4;

            ACCESS_CONTEXT(ctx,
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = regs->cr3,
                .addr = addr
            );

            if (VMI_FAILURE == vmi_write_32(vmi, &ctx, (uint32_t*)&arg->data_on_stack))
            {
                PRINT_DEBUG("Could not write int(%d) at address(%lx)\n", (uint32_t)arg->data_on_stack, addr);
                goto err;
            }

            break;
        }
        default:
            goto err;
    }
    return addr;
err:
    PRINT_DEBUG("Could not place argument on address specified\n");
    return 0;
}

static addr_t place_argument_on_addr_64(vmi_instance_t vmi, x86_registers_t* regs, struct argument* arg, addr_t addr)
{
    switch (arg->type)
    {
        case ARGUMENT_STRING:
        {
            addr = place_string_on_stack_64(vmi, regs, addr, arg->data, arg->size);
            if ( !addr ) goto err;
            arg->data_on_stack = addr;
            break;
        }
        case ARGUMENT_STRUCT:
        {
            addr = place_struct_on_stack_64(vmi, regs, addr, arg->data, arg->size);
            if ( !addr ) goto err;
            arg->data_on_stack = addr;
            break;
        }
        case ARGUMENT_INT:
        {
            arg->data_on_stack = (uint64_t)arg->data;
            addr -= 0x8;

            ACCESS_CONTEXT(ctx,
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = regs->cr3,
                .addr = addr
            );

            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &(arg->data_on_stack)) )
            {
                PRINT_DEBUG("Could not write int(%ld) at address(%lx)\n", arg->data_on_stack, addr);
                goto err;
            }

            break;
        }
        default:
            goto err;
    }
    return addr;
err:
    PRINT_DEBUG("Could not place argument on address specified\n");
    return 0;
}

static addr_t place_array_data_on_addr_64(vmi_instance_t vmi, x86_registers_t* regs, struct argument* args, size_t nb_args, addr_t addr)
{
    for (size_t i = 0; i < nb_args; i++)
    {
        switch (args[i].type)
        {
            case ARGUMENT_STRING:
                addr = place_string_on_stack_64(vmi, regs, addr, args[i].data, args[i].size);
                if (!addr) return 0;
                args[i].data_on_stack = addr;
                break;
            case ARGUMENT_STRUCT:
                addr = place_struct_on_stack_64(vmi, regs, addr, args[i].data, args[i].size);
                if (!addr) return 0;
                args[i].data_on_stack = addr;
                break;
            case ARGUMENT_INT:
                args[i].data_on_stack = (uint64_t)args[i].data;
                break;
            case ARGUMENT_ARRAY:
                // should be placed manually using place_array_on_addr_64
                // which will set data_on_stack
                break;
            default:
                PRINT_DEBUG("Undefined argument type\n");
                return 0;
        }
    }
    return addr;
}

addr_t place_array_on_addr_64(vmi_instance_t vmi, x86_registers_t* regs, struct argument* arg, bool null_terminate, addr_t* data_addr, addr_t* array_addr)
{
    struct argument* array = (struct argument*)arg->data;

    // place array elements data onto data_addr

    *data_addr = place_array_data_on_addr_64(vmi, regs, array, arg->size, *data_addr);
    if (*data_addr == 0)
        goto err;

    // fill bottom up as stack grows towards top

    if (null_terminate)
    {
        struct argument data;
        init_int_argument(&data, 0);
        *array_addr = place_argument_on_addr_64(vmi, regs, &data, *array_addr);
        if (*array_addr == 0)
            goto err;
    }

    for (int i=arg->size - 1; i>=0; i--)
    {
        const struct argument* element = &array[i];
        // put the pointer to data on array_addr
        struct argument data;
        init_int_argument(&data, element->data_on_stack);
        *array_addr = place_argument_on_addr_64(vmi, regs, &data, *array_addr);
        if (*array_addr == 0)
            goto err;
    }

    arg->data_on_stack = *array_addr;
    return *array_addr;
err:
    PRINT_DEBUG("Array could not be placed on address specified\n");
    PRINT_DEBUG("Data addr: %lx\n", *data_addr);
    PRINT_DEBUG("Array addr: %lx\n", *array_addr);
    return 0;
}

addr_t place_array_on_addr_32(vmi_instance_t vmi, x86_registers_t* regs, struct argument* arg, addr_t* data_addr, addr_t* array_addr)
{
    // fill bottom up as stack grows towards top
    int i;
    for (i=arg->size - 1; i>=0; i--)
    {
        // put the argument on data_addr
        struct argument data;
        *data_addr = place_argument_on_addr_32(vmi, regs, &((struct argument*)arg->data)[i], *data_addr);
        if (*data_addr == 0)
            goto err;

        // put the pointer to data on array_addr
        init_int_argument(&data, *data_addr);
        *array_addr = place_argument_on_addr_32(vmi, regs, &data, *array_addr);
        if (*array_addr == 0)
            goto err;
    }
    arg->data_on_stack = *array_addr;
    return *array_addr;
err:
    PRINT_DEBUG("Array could not be placed on address specified\n");
    PRINT_DEBUG("Failure index: %d\n", i);
    PRINT_DEBUG("Data addr: %lx\n", *data_addr);
    PRINT_DEBUG("Array addr: %lx\n", *array_addr);
    return 0;
}

static bool setup_stack_32(vmi_instance_t vmi, x86_registers_t* regs, struct argument args[], int nb_args)
{
    addr_t addr = regs->rsp;

    // make room for strings and structs into guest's stack
    int i;
    for (i = 0; i < nb_args; i++)
    {
        switch (args[i].type)
        {
            case ARGUMENT_STRING:
                addr = place_string_on_stack_32(vmi, regs, addr, args[i].data, args[i].size);
                if ( !addr ) goto err;
                args[i].data_on_stack = addr;
                break;
            case ARGUMENT_STRUCT:
                addr = place_struct_on_stack_32(vmi, regs, addr, args[i].data, args[i].size);
                if ( !addr ) goto err;
                args[i].data_on_stack = addr;
                break;
            case ARGUMENT_INT:
                args[i].data_on_stack = (uint64_t)args[i].data;
                break;
            case ARGUMENT_ARRAY:
                // should be placed manually using place_array_on_addr_32
                // which will set data_on_stack
                break;
            default:
                PRINT_DEBUG("Undefined argument type\n");
                goto err;
        }
    }

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = regs->cr3
    );

    // write parameters into guest's stack
    for (i = nb_args-1; i >= 0; i--)
    {
        addr -= 0x4;
        ctx.addr = addr;
        if (VMI_FAILURE == vmi_write_32(vmi, &ctx, (uint32_t*)&args[i].data_on_stack))
            goto err;
    }

    // save the return address
    addr -= 0x4;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_32(vmi, &ctx, (uint32_t*) &regs->rip))
    {
        PRINT_DEBUG("Could not write return address on stack\n");
        goto err;
    }

    // grow the stack
    regs->rsp = addr;

    return 1;

err:
    PRINT_DEBUG("Could not setup stack for 32 bit\n");
    PRINT_DEBUG("Failure index: %d\n", i);
    return 0;
}

static bool setup_stack_64(vmi_instance_t vmi, x86_registers_t* regs, struct argument args[], int nb_args)
{
    uint64_t nul64 = 0;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = regs->cr3
    );

    addr_t addr = regs->rsp;

    if ( args )
    {
        // make room for strings and structs into guest's stack
        addr = place_array_data_on_addr_64(vmi, regs, args, nb_args, addr);
        if (!addr) goto err;

        /* According to Microsoft Doc "Building C/C++ Programs":
         * > The stack will always be maintained 16-byte aligned, except within the prolog
         * > (for example, after the return address is pushed), and except where indicated
         * > in Function Types for a certain class of frame functions.
         *
         * Add padding to be aligned to "16+8" boundary.
         *
         * https://www.gamasutra.com/view/news/178446/Indepth_Windows_x64_ABI_Stack_frames.php
         *
         * This padding on the stack only exists if the maximum number of parameters passed
         * to functions is greater than 4 and is an odd number.
         */
        int effective_nb_args = nb_args > 4 ? nb_args : 4;
        if (((addr - effective_nb_args * 0x8 - 0x8) & 0xf) != 8)
            addr -= 0x8;

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
            {
                PRINT_DEBUG("Could not place parameter on stack\n");
                goto err;
            }
        }

        switch (nb_args)
        {
            default:
                // p4
                regs->r9 = args[3].data_on_stack;
            // fall through
            case 3:
                // p3
                regs->r8 = args[2].data_on_stack;
            // fall through
            case 2:
                // p2
                regs->rdx = args[1].data_on_stack;
            // fall through
            case 1:
                // p1
                regs->rcx = args[0].data_on_stack;
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
        {
            PRINT_DEBUG("Could not allocate homing space\n");
            goto err;
        }
    }

    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &regs->rip))
    {
        PRINT_DEBUG("Could not write return address on stack\n");
        goto err;
    }

    // grow the stack
    regs->rsp = addr;

    return 1;

err:
    PRINT_DEBUG("Could not setup stack for 64 bit\n");
    return 0;
}

static bool setup_linux_syscall(vmi_instance_t vmi, x86_registers_t* regs, struct argument args[], int nb_args)
{
    addr_t addr = regs->rsp;

    if ( args )
    {
        // make room for strings and structs into guest's stack
        addr = place_array_data_on_addr_64(vmi, regs, args, nb_args, addr);
        if (!addr) goto err;

        // First 6 arguments are sent by registers
        // It follows system-call ABI instead of function-call ABI
        // 1: rdi
        // 2: rsi
        // 3: rdx
        // 4: r10
        // 5: r8
        // 6: r9

        switch (nb_args)
        {
            default:
                regs->r9 = args[5].data_on_stack;
            // fall through
            case 5:
                regs->r8 = args[4].data_on_stack;
            // fall through
            case 4:
                regs->r10 = args[3].data_on_stack;
            // fall through
            case 3:
                regs->rdx = args[2].data_on_stack;
            // fall through
            case 2:
                regs->rsi = args[1].data_on_stack;
            // fall through
            case 1:
                regs->rdi = args[0].data_on_stack;
            // fall through
            case 0:
                break;
        }
    }

    return true;

err:
    return false;
}

bool setup_stack_locked(
    drakvuf_t drakvuf,
    vmi_instance_t vmi,
    x86_registers_t* regs,
    struct argument args[],
    int nb_args)
{
    if (drakvuf_get_os_type(drakvuf) == VMI_OS_WINDOWS)
    {
        bool is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
        return is32bit ? setup_stack_32(vmi, regs, args, nb_args) : setup_stack_64(vmi, regs, args, nb_args);
    }
    else if (drakvuf_get_os_type(drakvuf) == VMI_OS_LINUX)
    {
        // linux uses syscall interface for injecting
        return setup_linux_syscall(vmi, regs, args, nb_args);
    }
    else
    {
        PRINT_DEBUG("setup_stack: unknown OS type\n");
        return false;
    }
}

bool setup_stack(
    drakvuf_t drakvuf,
    x86_registers_t* regs,
    struct argument args[],
    int nb_args)
{

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool success = setup_stack_locked(drakvuf, vmi, regs, args, nb_args);
    drakvuf_release_vmi(drakvuf);
    return success;
}

bool inject_function_call(
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    event_response_t (*cb)(drakvuf_t, drakvuf_trap_info_t*),
    x86_registers_t* regs,
    struct argument args[],
    int nb_args,
    addr_t function_addr,
    addr_t* stack_pointer)
{
    drakvuf_lock_and_get_vmi(drakvuf);

    if (drakvuf_lookup_injection(drakvuf, info))
    {
        drakvuf_release_vmi(drakvuf);
        return false;
    }

    if (!setup_stack(drakvuf, regs, args, nb_args))
    {
        drakvuf_release_vmi(drakvuf);
        return false;
    }

    regs->rip = function_addr;
    if (!drakvuf_vmi_response_set_registers(drakvuf, info, regs, false))
    {
        drakvuf_release_vmi(drakvuf);
        return false;
    }
    *stack_pointer = regs->rsp;

    drakvuf_insert_injection(drakvuf, info, cb);
    drakvuf_release_vmi(drakvuf);
    return true;
}
