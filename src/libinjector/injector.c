/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
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

#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/x86.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <inttypes.h>
#include <glib.h>

#include "libdrakvuf/libdrakvuf.h"
#include <libinjector/libinjector.h>
#include "private.h"

struct injector
{
    // Inputs:
    const char* target_file;
    reg_t target_cr3;
    vmi_pid_t target_pid;
    uint32_t target_tid;
    const char* cwd;

    // Internal:
    drakvuf_t drakvuf;
    vmi_instance_t vmi;
    const char* rekall_profile;
    bool is32bit, hijacked;
    injection_method_t method;
    addr_t exec_func;

    // For shellcode execution
    addr_t payload, payload_addr, write_proc_mem;
    size_t payload_size;
    uint32_t status;

    addr_t process_info;
    x86_registers_t saved_regs;

    drakvuf_trap_t bp, cr3_event;
    GSList* memtraps;

    size_t offsets[OFFSET_MAX];

    // Results:
    reg_t cr3;
    int rc;
    uint32_t pid, tid;
    uint32_t hProc, hThr;
};

#define SW_SHOWDEFAULT  10
#define MEM_COMMIT      0x00001000
#define MEM_RESERVE     0x00002000
#define MEM_PHYSICAL    0x00400000
#define PAGE_EXECUTE_READWRITE  0x40

struct startup_info_32
{
    uint32_t cb;
    uint32_t lpReserved;
    uint32_t lpDesktop;
    uint32_t lpTitle;
    uint32_t dwX;
    uint32_t dwY;
    uint32_t dwXSize;
    uint32_t dwYSize;
    uint32_t dwXCountChars;
    uint32_t dwYCountChars;
    uint32_t dwFillAttribute;
    uint32_t dwFlags;
    uint16_t wShowWindow;
    uint16_t cbReserved2;
    uint32_t lpReserved2;
    uint32_t hStdInput;
    uint32_t hStdOutput;
    uint32_t hStdError;
};

struct startup_info_64
{
    uint32_t cb;
    addr_t lpReserved;
    addr_t lpDesktop;
    addr_t lpTitle;
    uint32_t dwX;
    uint32_t dwY;
    uint32_t dwXSize;
    uint32_t dwYSize;
    uint32_t dwXCountChars;
    uint32_t dwYCountChars;
    uint32_t dwFillAttribute;
    uint32_t dwFlags;
    uint16_t wShowWindow;
    uint16_t cbReserved2;
    addr_t lpReserved2;
    addr_t hStdInput;
    addr_t hStdOutput;
    addr_t hStdError;
};

struct process_information_32
{
    uint32_t hProcess;
    uint32_t hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
} __attribute__ ((packed));

struct process_information_64
{
    addr_t hProcess;
    addr_t hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
} __attribute__ ((packed));

struct list_entry_32
{
    uint32_t flink;
    uint32_t blink;
} __attribute__ ((packed));

struct list_entry_64
{
    uint64_t flink;
    uint64_t blink;
} __attribute__ ((packed));

struct kapc_state_32
{
    // apc_list_head[0] = kernel apc list
    // apc_list_head[1] = user apc list
    struct list_entry_32 apc_list_head[2];
    uint32_t process;
    uint8_t kernel_apc_in_progress;
    uint8_t kernel_apc_pending;
    uint8_t user_apc_pending;
} __attribute__ ((packed));

struct kapc_state_64
{
    // apc_list_head[0] = kernel apc list
    // apc_list_head[1] = user apc list
    struct list_entry_64 apc_list_head[2];
    uint64_t process;
    uint8_t kernel_apc_in_progress;
    uint8_t kernel_apc_pending;
    uint8_t user_apc_pending;
};

struct kapc_32
{
    uint8_t type;
    uint8_t spare_byte0;
    uint8_t size;
    uint8_t spare_byte1;
    uint32_t spare_long0;
    uint32_t thread;
    struct list_entry_32 apc_list_entry;
    uint32_t kernel_routine;
    uint32_t rundown_routine;
    uint32_t normal_routine;
    uint32_t normal_context;
    uint32_t system_argument_1;
    uint32_t system_argument_2;
    uint8_t apc_state_index;
    uint8_t apc_mode;
    uint8_t inserted;
} __attribute__ ((packed));

struct kapc_64
{
    uint8_t type;
    uint8_t spare_byte0;
    uint8_t size;
    uint8_t spare_byte1;
    uint32_t spare_long0;
    uint64_t thread;
    struct list_entry_64 apc_list_entry;
    uint64_t kernel_routine;
    uint64_t rundown_routine;
    uint64_t normal_routine;
    uint64_t normal_context;
    uint64_t system_argument_1;
    uint64_t system_argument_2;
    uint8_t apc_state_index;
    uint8_t apc_mode;
    uint8_t inserted;
};

static addr_t place_string_on_stack_32(vmi_instance_t vmi, access_context_t* ctx, addr_t addr, char const* str)
{
    if (!str)
        return 0;

    const uint32_t string_align = 64;
    const size_t len = strlen(str) + 1;// null terminated string

    // the stack has to be aligned _not_ to 0x4 but to 64
    // for special instructions operating on strings to work correctly
    // this string has to be aligned as well!
    addr -= len + string_align - (len % string_align);
    ctx->addr = addr;
    if (VMI_FAILURE == vmi_write(vmi, ctx, len, (void*) str, NULL))
        goto err;

    return addr;

err:
    return 0;
}

bool setup_stack_32(
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    access_context_t* ctx,
    struct argument args[],
    int nb_args)
{
    const uint32_t stack_align = 64;

    addr_t addr = info->regs->rsp;

    // make room for strings and structs into guest's stack
    for (int i = 0; i < nb_args; i++)
    {
        switch (args[i].type)
        {
            case ARGUMENT_STRING:
            {
                addr = place_string_on_stack_32(vmi, ctx, addr, (const char*)args[i].data_32);
                if ( !addr ) goto err;
                args[i].data_on_stack = addr;
                break;
            }
            case ARGUMENT_STRUCT:
            {
                size_t len = args[i].size;
                addr -= len;
                addr -= addr % stack_align;
                ctx->addr = addr;
                args[i].data_on_stack = addr;

                if (VMI_FAILURE == vmi_write(vmi, ctx, len, args[i].data_32, NULL))
                    goto err;
                break;
            }
            case ARGUMENT_INT:
            {
                args[i].data_on_stack = (uint64_t)args[i].data_32;
                break;
            }
            default:
                goto err;
        }
    }

    // write parameters into guest's stack
    for (int i = nb_args-1; i >= 0; i--)
    {
        addr -= 0x4;
        ctx->addr = addr;
        if (VMI_FAILURE == vmi_write_32(vmi, ctx, (uint32_t*)&(args[i].data_on_stack)) )
            goto err;
    }

    // save the return address
    addr -= 0x4;
    ctx->addr = addr;
    if (VMI_FAILURE == vmi_write_32(vmi, ctx, (uint32_t*) &info->regs->rip))
        goto err;

    // grow the stack
    info->regs->rsp = addr;

    return 1;

err:
    return 0;
}

static addr_t place_string_on_stack_64(vmi_instance_t vmi, access_context_t* ctx, addr_t addr, char const* str)
{
    if (!str) return addr;
    // String length with null terminator
    size_t len = strlen(str) + 1;
    addr_t orig_addr = addr;

    addr -= len;
    // Align string address on 32B boundary (for SSE2 instructions).
    addr &= ~0x1f;

    size_t buf_len = orig_addr - addr;
    void* buf = g_malloc0(buf_len);
    g_stpcpy(buf, str);

    ctx->addr = addr;
    status_t status = vmi_write(vmi, ctx, buf_len, buf, NULL);
    g_free(buf);

    return status == VMI_FAILURE ? 0 : addr;
}

bool setup_stack_64(
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    access_context_t* ctx,
    struct argument args[],
    int nb_args)
{
    uint64_t nul64 = 0;

    addr_t addr = info->regs->rsp;

    if ( args )
    {
        // make room for strings and structs into guest's stack
        for (int i = 0; i < nb_args; i++)
        {
            switch (args[i].type)
            {
                case ARGUMENT_STRING:
                {
                    addr = place_string_on_stack_64(vmi, ctx, addr, (const char*)args[i].data_64);
                    if ( !addr ) goto err;
                    args[i].data_on_stack = addr;
                    break;
                }
                case ARGUMENT_STRUCT:
                {
                    /* According to Microsoft Doc "Building C/C++ Programs":
                     * > The alignment of the beginning of a structure or a union is the maximum
                     * > alignment of any individual member.
                     */
                    size_t len = args[i].size;
                    addr -= len;
                    addr &= ~0xf; // Align stack
                    ctx->addr = addr;
                    args[i].data_on_stack = addr;

                    if (VMI_FAILURE == vmi_write(vmi, ctx, len, args[i].data_64, NULL))
                        goto err;
                    break;
                }
                case ARGUMENT_INT:
                {
                    args[i].data_on_stack = (uint64_t)args[i].data_64;
                    break;
                }
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
            ctx->addr = addr;
            if (VMI_FAILURE == vmi_write_64(vmi, ctx, &nul64))
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
            ctx->addr = addr;
            if (VMI_FAILURE == vmi_write_64(vmi, ctx, &(args[i].data_on_stack)) )
                goto err;
        }

        // p1
        info->regs->rcx = args[0].data_on_stack;
        // p2
        info->regs->rdx = args[1].data_on_stack;
        // p3
        info->regs->r8 = args[2].data_on_stack;
        // p4
        info->regs->r9 = args[3].data_on_stack;
    }

    // allocate 0x20 "homing space"
    for (int i = 0; i < 4; i++)
    {
        addr -= 0x8;
        ctx->addr = addr;
        if (VMI_FAILURE == vmi_write_64(vmi, ctx, &nul64))
            goto err;
    }

    // save the return address
    addr -= 0x8;
    ctx->addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, ctx, &info->regs->rip))
        goto err;

    // grow the stack
    info->regs->rsp = addr;

    return 1;

err:
    return 0;
}

void init_argument(
    bool is32bit,
    struct argument* arg,
    argument_type_t type,
    size_t size,
    void* data)
{
    arg->type = type;
    arg->size = size;

    if (is32bit)
        arg->data_32 = data;
    else
        arg->data_64 = data;

    arg->data_on_stack = 0;
}

bool pass_inputs(struct injector* injector, drakvuf_trap_info_t* info)
{

    vmi_instance_t vmi = injector->vmi;
    reg_t fsgs;
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    addr_t stack_base, stack_limit;

    if (injector->is32bit)
        fsgs = info->regs->fs_base;
    else
        fsgs = info->regs->gs_base;

    ctx.addr = fsgs + injector->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    ctx.addr = fsgs + injector->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    //Push input arguments on the stack

    if (injector->is32bit)
    {
        if (INJECT_METHOD_SHELLEXEC == injector->method)
        {
            // TODO Implement
            goto err;
        }
        else
        {
            struct argument args[10] = { {0} };
            struct startup_info_32 si;
            struct process_information_32 pi;
            uint64_t null32 = 0;

            memset(&si, 0, sizeof(struct startup_info_32));
            memset(&pi, 0, sizeof(struct process_information_32));

            // CreateProcess(NULL, TARGETPROC, NULL, NULL, 0, 0, NULL, NULL, &si, pi))
            init_argument(1, &args[0], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(1, &args[1], ARGUMENT_STRING, strlen(injector->target_file),
                          (void*)injector->target_file);
            init_argument(1, &args[2], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(1, &args[3], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(1, &args[4], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(1, &args[5], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(1, &args[6], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(1, &args[7], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(1, &args[8], ARGUMENT_STRUCT, sizeof(struct startup_info_32),
                          (void*)&si);
            init_argument(1, &args[9], ARGUMENT_STRUCT, sizeof(struct process_information_32),
                          (void*)&pi);

            if ( !setup_stack_32(injector->vmi, info, &ctx, args, 10) )
                goto err;

            injector->process_info = args[9].data_on_stack;
        }

    }
    else
    {

        if (INJECT_METHOD_SHELLEXEC == injector->method)
        {
            struct argument args[6] = { {0} };
            uint64_t null64 = 0;
            uint64_t show_cmd = 1;

            // ShellExecute(NULL, NULL, &FilePath, NULL, NULL, SW_SHOWNORMAL)
            init_argument(0, &args[0], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[1], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[2], ARGUMENT_STRING, strlen(injector->target_file),
                          (void*)injector->target_file);
            init_argument(0, &args[3], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[4], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &(args[5]), ARGUMENT_INT, sizeof(uint64_t), (void*)show_cmd);

            if ( !setup_stack_64(injector->vmi, info, &ctx, args, 6) )
                goto err;
        }
        else if (INJECT_METHOD_CREATEPROC == injector->method)
        {
            struct argument args[10] = { {0} };
            struct startup_info_64 si;
            struct process_information_64 pi;
            uint64_t null64 = 0;

            memset(&si, 0, sizeof(struct startup_info_64));
            memset(&pi, 0, sizeof(struct process_information_64));

            // CreateProcess(NULL, TARGETPROC, NULL, NULL, 0, 0, NULL, NULL, &si, pi))
            init_argument(0, &args[0], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[1], ARGUMENT_STRING, strlen(injector->target_file),
                          (void*)injector->target_file);
            init_argument(0, &args[2], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[3], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[4], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[5], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[6], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[7], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[8], ARGUMENT_STRUCT, sizeof(struct startup_info_64),
                          (void*)&si);
            init_argument(0, &args[9], ARGUMENT_STRUCT, sizeof(struct process_information_64),
                          (void*)&pi);

            if ( !setup_stack_64(injector->vmi, info, &ctx, args, 10) )
                goto err;

            injector->process_info = args[9].data_on_stack;
        }
        else if (INJECT_METHOD_SHELLCODE == injector->method && STATUS_NULL == injector->status)
        {
            struct argument args[4] = { {0} };
            uint64_t null64 = 0;
            uint64_t allocation_type = MEM_COMMIT | MEM_RESERVE;
            uint64_t protect = PAGE_EXECUTE_READWRITE;

            init_argument(0, &args[0], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(0, &args[1], ARGUMENT_INT, sizeof(uint64_t), (void*)injector->payload_size);
            init_argument(0, &args[2], ARGUMENT_INT, sizeof(uint64_t), (void*)allocation_type);
            init_argument(0, &args[3], ARGUMENT_INT, sizeof(uint64_t), (void*)protect);

            if ( !setup_stack_64(injector->vmi, info, &ctx, args, 4) )
                goto err;

        }
        else if (INJECT_METHOD_SHELLCODE == injector->method && STATUS_ALLOC_OK == injector->status)
        {
            struct argument args[5] = { {0} };
            uint64_t handle = -1;
            size_t bytes_written = 0;

            init_argument(0, &args[0], ARGUMENT_INT, sizeof(uint64_t), (void*)handle);
            init_argument(0, &args[1], ARGUMENT_INT, sizeof(uint64_t), (void*)injector->payload_addr);
            init_argument(0, &args[2], ARGUMENT_STRUCT, injector->payload_size, (void*)injector->payload);
            init_argument(0, &args[3], ARGUMENT_INT, sizeof(uint64_t), (void*)injector->payload_size);
            init_argument(0, &args[4], ARGUMENT_INT, sizeof(uint64_t), (void*)bytes_written);

            if ( !setup_stack_64(injector->vmi, info, &ctx, args, 5) )
                return 0;
            g_free((void*)injector->payload);
        }
        else if (INJECT_METHOD_SHELLCODE == injector->method && STATUS_WRITE_OK == injector->status)
        {
            if ( !setup_stack_64(injector->vmi, info, &ctx, NULL, 4) )
                return 0;
        }
    }

    return 1;

err:
    PRINT_DEBUG("Failed to pass inputs to hijacked function!\n");
    return 0;
}

event_response_t mem_callback(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct injector* injector = info->trap->data;

    if ( info->regs->cr3 != injector->target_cr3 )
    {
        PRINT_DEBUG("MemX received but CR3 (0x%lx) doesn't match target process (0x%lx)\n",
                    info->regs->cr3, injector->target_cr3);
        return 0;
    }

    PRINT_DEBUG("MemX at 0x%lx\n", info->regs->rip);

    /* We might have already hijacked a thread on another vCPU */
    if (injector->hijacked)
        return 0;

    GSList* loop = injector->memtraps;
    while (loop)
    {
        drakvuf_remove_trap(drakvuf, loop->data, (drakvuf_trap_free_t)free);
        loop=loop->next;
    }
    g_slist_free(injector->memtraps);
    injector->memtraps = NULL;

    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

    if (!pass_inputs(injector, info))
    {
        PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
        return 0;
    }

    injector->bp.type = BREAKPOINT;
    injector->bp.name = "ret";
    injector->bp.cb = injector_int3_cb;
    injector->bp.data = injector;
    injector->bp.breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp.breakpoint.dtb = info->regs->cr3;
    injector->bp.breakpoint.addr_type = ADDR_VA;
    injector->bp.breakpoint.addr = info->regs->rip;

    if ( !drakvuf_add_trap(drakvuf, &injector->bp) )
    {
        fprintf(stderr, "Failed to trap return location of injected function call @ 0x%lx!\n",
                injector->bp.breakpoint.addr);
        return 0;
    }

    if ( !injector->target_tid )
    {
        uint32_t threadid = 0;
        if ( !drakvuf_get_current_thread_id(injector->drakvuf, info->vcpu, &threadid) || !threadid )
            return 0;

        injector->target_tid = threadid;
    }

    PRINT_DEBUG("Stack setup finished and return trap added @ 0x%" PRIx64 "\n",
                injector->bp.breakpoint.addr);

    info->regs->rip = injector->exec_func;
    injector->hijacked = 1;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

event_response_t cr3_callback(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    struct injector* injector = info->trap->data;
    addr_t thread = 0;
    reg_t cr3 = info->regs->cr3;
    status_t status;

    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 "\n", info->regs->cr3);

    if (cr3 != injector->target_cr3)
        return 0;

    thread = drakvuf_get_current_thread(drakvuf, info->vcpu);
    if (!thread)
    {
        PRINT_DEBUG("cr3_cb: Failed to find current thread\n");
        return 0;
    }

    uint32_t threadid = 0;
    if ( !drakvuf_get_current_thread_id(injector->drakvuf, info->vcpu, &threadid) || !threadid )
        return 0;

    PRINT_DEBUG("Thread @ 0x%lx. ThreadID: %u\n", thread, threadid);

    if ( injector->target_tid && injector->target_tid != threadid)
        return 0;

    /*
     * At this point the process is still in kernel mode, so
     * we need to trap when it enters into user mode.
     * For this we use different mechanisms on 32-bit and 64-bit.
     * The reason for this is that the same methods are not equally
     * reliably.
     *
     * For 64-bit Windows we use the trapframe approach, where we read
     * the saved RIP from the stack trap frame and trap it.
     * When this address is hit, we hijack the flow and afterwards return
     * the registers to the original values, thus the process continues to run.
     * This method is workable on 32-bit Windows as well but finding the trapframe
     * sometimes fail for yet unknown reasons.
     */
    if (!injector->is32bit)
    {

        addr_t trapframe = 0;
        status = vmi_read_addr_va(injector->vmi,
                                  thread + injector->offsets[KTHREAD_TRAPFRAME],
                                  0, &trapframe);

        if (status == VMI_FAILURE || !trapframe)
        {
            PRINT_DEBUG("cr3_cb: failed to read trapframe (0x%lx)\n", trapframe);
            return 0;
        }

        status = vmi_read_addr_va(injector->vmi,
                                  trapframe + injector->offsets[KTRAP_FRAME_RIP],
                                  0, &injector->bp.breakpoint.addr);

        if (status == VMI_FAILURE || !injector->bp.breakpoint.addr)
        {
            PRINT_DEBUG("Failed to read RIP from trapframe or RIP is NULL!\n");
            return 0;
        }

        injector->bp.type = BREAKPOINT;
        injector->bp.name = "entry";
        injector->bp.cb = injector_int3_cb;
        injector->bp.data = injector;
        injector->bp.breakpoint.lookup_type = LOOKUP_DTB;
        injector->bp.breakpoint.dtb = cr3;
        injector->bp.breakpoint.addr_type = ADDR_VA;

        if ( drakvuf_add_trap(drakvuf, &injector->bp) )
        {
            PRINT_DEBUG("Got return address 0x%lx from trapframe and it's now trapped!\n",
                        injector->bp.breakpoint.addr);

            // Unsubscribe from the CR3 trap
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
        }
        else
            fprintf(stderr, "Failed to trap trapframe return address\n");
    }
    else
    {
        GSList* va_pages = vmi_get_va_pages(injector->vmi, info->regs->cr3);
        GSList* loop = va_pages;
        drakvuf_pause(drakvuf);
        while (loop)
        {
            page_info_t* page = loop->data;
            if (page->vaddr < 0x80000000 && USER_SUPERVISOR(page->x86_pae.pte_value))
            {
                drakvuf_trap_t* new_trap = g_malloc0(sizeof(drakvuf_trap_t));
                new_trap->type = MEMACCESS;
                new_trap->cb = mem_callback;
                new_trap->data = injector;
                new_trap->memaccess.access = VMI_MEMACCESS_X;
                new_trap->memaccess.type = POST;
                new_trap->memaccess.gfn = page->paddr >> 12;
                injector->memtraps = g_slist_prepend(injector->memtraps, new_trap);
                if ( drakvuf_add_trap(injector->drakvuf, new_trap) )
                    injector->memtraps = g_slist_prepend(injector->memtraps, new_trap);
                else
                    g_free(new_trap);
            }
            g_free(page);
            loop = loop->next;
        }
        g_slist_free(va_pages);
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
        drakvuf_resume(drakvuf);
    }

    return 0;
}

event_response_t injector_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct injector* injector = info->trap->data;
    reg_t cr3 = info->regs->cr3;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3,
    };

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx.\n",
                info->regs->rip, cr3);

    if ( cr3 != injector->target_cr3 )
    {
        PRINT_DEBUG("INT3 received but CR3 (0x%lx) doesn't match target process (0x%lx)\n",
                    cr3, injector->target_cr3);
        return 0;
    }

    uint32_t threadid = 0;
    if ( !drakvuf_get_current_thread_id(injector->drakvuf, info->vcpu, &threadid) || !threadid )
        return 0;

    if ( !injector->is32bit && !injector->hijacked && info->regs->rip == injector->bp.breakpoint.addr && injector->status == STATUS_NULL )
    {
        /* We just hit the RIP from the trapframe */

        memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

        if ( !pass_inputs(injector, info) )
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        info->regs->rip = injector->exec_func;

        if (INJECT_METHOD_SHELLCODE == injector->method)
        {
            injector->status = STATUS_ALLOC_OK;
        }
        else
        {
            injector->hijacked = 1;

            if ( !injector->target_tid )
                injector->target_tid = threadid;
        }

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    // Chain the injection with a second function
    if ( !injector->is32bit && info->regs->rip == injector->bp.breakpoint.addr && STATUS_ALLOC_OK == injector->status)
    {
        PRINT_DEBUG("Writing payload in memory..\n");
        PRINT_DEBUG("Payload is at: 0x%lx\n", info->regs->rax);

        injector->payload_addr = info->regs->rax;
        if ( !pass_inputs(injector, info) )
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        info->regs->rip = injector->write_proc_mem;

        injector->status = STATUS_WRITE_OK;

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    // Execute the payload
    if ( !injector->is32bit && info->regs->rip == injector->bp.breakpoint.addr && STATUS_WRITE_OK == injector->status)
    {
        PRINT_DEBUG("Executing the payload..\n");
        if ( !pass_inputs(injector, info) )
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        info->regs->rip = injector->payload_addr;

        injector->hijacked = 1;

        if ( !injector->target_tid )
            injector->target_tid = threadid;

        injector->status = STATUS_EXEC_OK;

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    if ( !injector->hijacked || info->regs->rip != injector->bp.breakpoint.addr || threadid != injector->target_tid )
        return 0;

    // We are now in the return path from CreateProcessA

    drakvuf_interrupt(drakvuf, -1);
    drakvuf_remove_trap(drakvuf, &injector->bp, NULL);

    PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);

    if (INJECT_METHOD_CREATEPROC == injector->method && info->regs->rax)
    {
        ctx.addr = injector->process_info;

        if (injector->is32bit)
        {
            struct process_information_32 pip = { 0 };
            if ( VMI_SUCCESS == vmi_read(injector->vmi, &ctx, sizeof(struct process_information_32), &pip, NULL) )
            {
                injector->pid = pip.dwProcessId;
                injector->tid = pip.dwThreadId;
                injector->hProc = pip.hProcess;
                injector->hThr = pip.hThread;
            }
        }
        else
        {
            struct process_information_64 pip = { 0 };
            if ( VMI_SUCCESS == vmi_read(injector->vmi, &ctx, sizeof(struct process_information_64), &pip, NULL) )
            {
                injector->pid = pip.dwProcessId;
                injector->tid = pip.dwThreadId;
                injector->hProc = pip.hProcess;
                injector->hThr = pip.hThread;
            }
        }

        if (injector->pid && injector->tid)
        {
            PRINT_DEBUG("Injected PID: %i. TID: %i\n", injector->pid, injector->tid);
            injector->rc = info->regs->rax;
        }
        else
        {
            PRINT_DEBUG("Failed to inject\n");
            injector->rc = 0;
        }
    }
    // For some reason ShellExecute could return ERROR_FILE_NOT_FOUND while
    // successfully opening file. So check only for out of resources (0) error.
    else if (INJECT_METHOD_SHELLEXEC == injector->method && info->regs->rax)
    {
        // TODO Retrieve PID and TID
        PRINT_DEBUG("Injected\n");
        injector->rc = 1;
    }
    else if (INJECT_METHOD_SHELLCODE == injector->method && STATUS_EXEC_OK == injector->status)
    {
        PRINT_DEBUG("Shellcode executed\n");

        injector->rc = 1;
    }

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

status_t read_payload(struct injector* injector, const char* file)
{
    size_t bytes_read = 0;
    size_t mem_size = 4096, payload_size = 0;
    unsigned char* shellcode = NULL, *tmp = NULL;
    char buffer[4096] = { '\0' };
    FILE* fp = NULL;

    if ( !(fp = fopen(file, "rb")) )
        return VMI_FAILURE;

    shellcode = g_malloc0(sizeof(char) * mem_size);

    tmp = shellcode;
    while ( (bytes_read = fread(buffer, 1, 4096, fp)) )
    {
        if (bytes_read + payload_size > mem_size)
        {
            mem_size *= 2;
            shellcode = g_realloc(shellcode, mem_size);
            tmp = shellcode;
            tmp += payload_size;
        }

        memcpy(shellcode, buffer, bytes_read);
        payload_size += bytes_read;
        tmp += bytes_read;
    }

    injector->payload = (addr_t)shellcode;
    injector->payload_size = payload_size;

    PRINT_DEBUG("Size of shellcode : %lu\n", injector->payload_size);

    fclose(fp);

    return VMI_SUCCESS;
}

static void print_injection_info(output_format_t format, vmi_pid_t pid, uint64_t dtb, const char* file, vmi_pid_t injected_pid, uint32_t injected_tid)
{
    GTimeVal t;
    g_get_current_time(&t);

    char* process_name = NULL;
    char* arguments = NULL;

    char* splitter = " ";
    const char* begin_proc_name = &file[0];

    if (file[0] == '"')
    {
        splitter = "\"";
        begin_proc_name = &file[1];
    }

    char** split_results = g_strsplit_set(begin_proc_name, splitter, 2);
    char** split_results_iterator = split_results;

    if (*split_results_iterator)
    {
        process_name = *(split_results_iterator++);
    }

    if (*split_results_iterator)
    {
        arguments = *(split_results_iterator++);
        if (arguments[0] == ' ')
            arguments++;
    }
    else
    {
        arguments = "";
    }

    char* escaped_arguments = g_strescape(arguments, NULL);

    switch (format)
    {
        case OUTPUT_CSV:
            printf("inject," FORMAT_TIMEVAL ",%u,0x%lx,\"%s\",\"%s\",%u,%u\n",
                   UNPACK_TIMEVAL(t), pid, dtb, process_name, escaped_arguments, injected_pid, injected_tid);
            break;

        case OUTPUT_KV:
            printf("inject Time=" FORMAT_TIMEVAL ",PID=%u,DTB=0x%lx,ProcessName=\"%s\",Arguments=\"%s\",InjectedPid=%u,InjectedTid=%u\n",
                   UNPACK_TIMEVAL(t), pid, dtb, process_name, escaped_arguments, injected_pid, injected_tid);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[INJECT] TIME:" FORMAT_TIMEVAL " PID:%u DTB:0x%lx FILE:\"%s\" ARGUMENTS:\"%s\" INJECTED_PID:%u INJECTED_TID:%u\n",
                   UNPACK_TIMEVAL(t), pid, dtb, process_name, escaped_arguments, injected_pid, injected_tid);
            break;
    }

    g_free(escaped_arguments);
    g_strfreev(split_results);
}

int injector_start_app(drakvuf_t drakvuf, vmi_pid_t pid, uint32_t tid, const char* file, const char* cwd, injection_method_t method, output_format_t format)
{

    struct injector injector = { 0 };
    injector.drakvuf = drakvuf;
    injector.vmi = drakvuf_lock_and_get_vmi(drakvuf);
    injector.rekall_profile = drakvuf_get_rekall_profile(drakvuf);
    injector.target_pid = pid;
    injector.target_tid = tid;
    injector.target_file = file;
    injector.cwd = cwd;

    injector.method = method;

    injector.is32bit = (vmi_get_page_mode(injector.vmi, 0) == VMI_PM_IA32E) ? 0 : 1;
    if ( VMI_FAILURE == vmi_pid_to_dtb(injector.vmi, pid, &injector.target_cr3) )
    {
        PRINT_DEBUG("Unable to find target PID's DTB\n");
        goto done;
    }

    // Get the offsets from the Rekall profile
    unsigned int i;
    for (i = 0; i < OFFSET_MAX; i++)
    {
        if ( !drakvuf_get_struct_member_rva(injector.rekall_profile, offset_names[i][0], offset_names[i][1], &injector.offsets[i]))
        {
            PRINT_DEBUG("Failed to find offset for %s:%s\n", offset_names[i][0],
                        offset_names[i][1]);
        }
    }

    PRINT_DEBUG("Target PID %u with DTB 0x%lx to start '%s'\n", pid,
                injector.target_cr3, file);

    addr_t eprocess_base = 0;
    if ( !drakvuf_find_process(injector.drakvuf, pid, NULL, &eprocess_base) )
        goto done;

    char* lib = "kernel32.dll";
    char* fun = "CreateProcessA";
    if (INJECT_METHOD_SHELLEXEC == method)
    {
        lib = "shell32.dll";
        fun = "ShellExecuteA";
    }
    else if (INJECT_METHOD_SHELLCODE == method)
    {
        // Read payload to inject from a file
        if ( VMI_SUCCESS != read_payload(&injector, file) )
            goto done;

        lib = "kernel32.dll";
        fun = "WriteProcessMemory";
        injector.write_proc_mem = drakvuf_exportsym_to_va(injector.drakvuf, eprocess_base, lib, fun);
        if (!injector.write_proc_mem)
        {
            PRINT_DEBUG("Failed to get address of %s!%s\n", lib, fun);
            goto done;
        }

        lib = "kernel32.dll";
        fun = "VirtualAlloc";
    }

    injector.status = STATUS_NULL;
    injector.exec_func = drakvuf_exportsym_to_va(injector.drakvuf, eprocess_base, lib, fun);
    if (!injector.exec_func)
    {
        PRINT_DEBUG("Failed to get address of %s!%s\n", lib, fun);
        goto done;
    }

    injector.cr3_event.type = REGISTER;
    injector.cr3_event.reg = CR3;
    injector.cr3_event.cb = cr3_callback;
    injector.cr3_event.data = &injector;
    if ( !drakvuf_add_trap(drakvuf, &injector.cr3_event) )
        goto done;

    PRINT_DEBUG("Starting injection loop\n");
    drakvuf_loop(drakvuf);

    if (injector.is32bit)
    {
        GSList* loop = injector.memtraps;
        while (loop)
        {
            drakvuf_remove_trap(drakvuf, loop->data, (drakvuf_trap_free_t)free);
            loop=loop->next;
        }
        g_slist_free(loop);
    }

    drakvuf_pause(drakvuf);
    drakvuf_remove_trap(drakvuf, &injector.cr3_event, NULL);

    print_injection_info(format, pid, injector.target_cr3, file, injector.pid, injector.tid);

done:
    PRINT_DEBUG("Finished with injection. Ret: %i\n", injector.rc);
    drakvuf_release_vmi(drakvuf);
    return injector.rc;
}
