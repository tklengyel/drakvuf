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
#include <json-c/json.h>

#include "libdrakvuf/libdrakvuf.h"
#include <libinjector/libinjector.h>
#include "private.h"

struct injector
{
    // Inputs:
    const char* target_file;
    const char* target_pname;
    reg_t target_cr3;
    vmi_pid_t target_pid;
    uint32_t target_tid;
    const char* cwd;

    // Internal:
    drakvuf_t drakvuf;
    bool is32bit, hijacked, wait_for_process, target_running, restored;
    injection_method_t method;
    addr_t exec_func;

    // For shellcode execution
    addr_t payload, payload_addr, memset;
    size_t binary_size, payload_size;
    uint32_t status;

    // For process doppelganging shellcode
    addr_t binary, binary_addr, saved_bp;
    addr_t process_notify;

    const char* binary_path;
    const char* target_process;

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
                addr = place_string_on_stack_32(vmi, ctx, addr, (const char*)args[i].data);
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

                if (VMI_FAILURE == vmi_write(vmi, ctx, len, args[i].data, NULL))
                    goto err;
                break;
            }
            case ARGUMENT_INT:
            {
                args[i].data_on_stack = (uint64_t)args[i].data;
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
                    addr = place_string_on_stack_64(vmi, ctx, addr, (const char*)args[i].data);
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

                    if (VMI_FAILURE == vmi_write(vmi, ctx, len, args[i].data, NULL))
                        goto err;
                    break;
                }
                case ARGUMENT_INT:
                {
                    args[i].data_on_stack = (uint64_t)args[i].data;
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

#ifdef ENABLE_DOPPELGANGING
static int patch_payload(struct injector* injector, unsigned char* addr)
{
    // First byte at which each variable instanciation start in the shellcode.
    addr_t offset_target_process = 0xa;
    addr_t offset_binary_buffer = 0xd0b;
    addr_t offset_binary_size = 0xd22;
    addr_t tmp_baddr = injector->binary_addr;
    addr_t tmp_bsize = injector->binary_size;
    unsigned char* tmp = NULL;
    unsigned char* patch = NULL;
    unsigned int size = sizeof(addr_t);
    unsigned int size_dword = sizeof(uint32_t);

    // Patch targetProcess string (cf. doppelganging.c) by the one provided at the
    // command line. This variable contains the path of the program that will be
    // used as a cover. The string is set one byte at a time, every 13 bytes
    // (instructions' opcodes are between).
    tmp = (unsigned char*)(addr + offset_target_process);
    patch = (unsigned char*)injector->target_process;

    while (*patch != '\0')
    {
        *tmp = *patch;

        tmp += 13;
        patch++;
    }
    *tmp = '\0';

    // Patch lpBinaryBuffer address (cf. doppelganging.c). It's an address pointing
    // to the content of the binary file to inject.
    tmp = (unsigned char*)(addr + offset_binary_buffer);

    for (; size > 0; size--)
    {
        *tmp = (unsigned char)tmp_baddr;

        tmp_baddr = tmp_baddr >> 8;
        tmp++;
    }

    // Patch binarySize (cf. doppelganging.c). It's an address pointing
    // to the content of the binary file to inject.
    tmp = (unsigned char*)(addr + offset_binary_size);

    for (; size_dword > 0; size_dword--)
    {
        *tmp = (unsigned char)tmp_bsize;

        tmp_bsize = tmp_bsize >> 8;
        tmp++;
    }

    return 0;
}
#endif

static bool pass_inputs(struct injector* injector, drakvuf_trap_info_t* info)
{
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

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(injector->drakvuf);

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
            init_argument(&args[0], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(&args[1], ARGUMENT_STRING, strlen(injector->target_file),
                          (void*)injector->target_file);
            init_argument(&args[2], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(&args[3], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(&args[4], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(&args[5], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(&args[6], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(&args[7], ARGUMENT_INT, sizeof(uint32_t), (void*)null32);
            init_argument(&args[8], ARGUMENT_STRUCT, sizeof(struct startup_info_32),
                          (void*)&si);
            init_argument(&args[9], ARGUMENT_STRUCT, sizeof(struct process_information_32),
                          (void*)&pi);

            if ( !setup_stack_32(vmi, info, &ctx, args, 10) )
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
            init_argument(&args[0], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&args[1], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&args[2], ARGUMENT_STRING, strlen(injector->target_file),
                          (void*)injector->target_file);
            init_argument(&args[3], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&args[4], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&(args[5]), ARGUMENT_INT, sizeof(uint64_t), (void*)show_cmd);

            if ( !setup_stack_64(vmi, info, &ctx, args, 6) )
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
            init_argument(&args[0], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&args[1], ARGUMENT_STRING, strlen(injector->target_file),
                          (void*)injector->target_file);
            init_argument(&args[2], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&args[3], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&args[4], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&args[5], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&args[6], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&args[7], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&args[8], ARGUMENT_STRUCT, sizeof(struct startup_info_64),
                          (void*)&si);
            init_argument(&args[9], ARGUMENT_STRUCT, sizeof(struct process_information_64),
                          (void*)&pi);

            if ( !setup_stack_64(vmi, info, &ctx, args, 10) )
                goto err;

            injector->process_info = args[9].data_on_stack;
        }
        else if ( (INJECT_METHOD_SHELLCODE == injector->method || INJECT_METHOD_DOPP == injector->method) && STATUS_NULL == injector->status)
        {
            struct argument args[4] = { {0} };
            uint64_t null64 = 0;
            uint64_t allocation_type = MEM_COMMIT | MEM_RESERVE;
            uint64_t protect = PAGE_EXECUTE_READWRITE;
            size_t size = injector->payload_size;

            // Allocate enough space for the shellcode and the binary at once
            if (INJECT_METHOD_DOPP == injector->method)
                size += injector->binary_size;

            // VirtualAlloc(NULL, size, allocation_type, protect);
            init_argument(&args[0], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);
            init_argument(&args[1], ARGUMENT_INT, sizeof(uint64_t), (void*)size);
            init_argument(&args[2], ARGUMENT_INT, sizeof(uint64_t), (void*)allocation_type);
            init_argument(&args[3], ARGUMENT_INT, sizeof(uint64_t), (void*)protect);

            if ( !setup_stack_64(vmi, info, &ctx, args, 4) )
                goto err;

        }
        else if ( (INJECT_METHOD_SHELLCODE == injector->method || INJECT_METHOD_DOPP == injector->method) && STATUS_ALLOC_OK == injector->status)
        {
            struct argument args[4] = { {0} };
            uint64_t c = 0;
            uint64_t null64 = 0;
            size_t size = injector->payload_size;

            if (INJECT_METHOD_DOPP == injector->method)
                size += injector->binary_size;

            // memset(payload_addr, c, payload_size);
            init_argument(&args[0], ARGUMENT_INT, sizeof(uint64_t), (void*)injector->payload_addr);
            init_argument(&args[1], ARGUMENT_INT, sizeof(uint64_t), (void*)c);
            init_argument(&args[2], ARGUMENT_INT, sizeof(uint64_t), (void*)size);
            init_argument(&args[3], ARGUMENT_INT, sizeof(uint64_t), (void*)null64);

            if ( !setup_stack_64(vmi, info, &ctx, args, 4) )
                goto err;
        }
        else if ( (INJECT_METHOD_SHELLCODE == injector->method || INJECT_METHOD_DOPP == injector->method) && STATUS_PHYS_ALLOC_OK == injector->status)
        {
            if ( !setup_stack_64(vmi, info, &ctx, NULL, 4) )
                goto err;
        }
    }

    drakvuf_release_vmi(injector->drakvuf);
    return 1;

err:
    drakvuf_release_vmi(injector->drakvuf);
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

event_response_t cr3_catch_create_proc(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct injector* injector = info->trap->data;
    (void)drakvuf;

    PRINT_DEBUG("CR3 in catcher changed to 0x%" PRIx64 ". PID: %u PPID: %u\n",
                info->regs->cr3, info->proc_data.pid, info->proc_data.ppid);

    if ( info->proc_data.ppid == injector->target_pid )
    {
        char* pname = drakvuf_get_process_name(drakvuf, info->proc_data.base_addr, 0);
        gchar* pname_utf8 = g_utf8_casefold(pname, -1);

        if ( !strncmp(pname_utf8, injector->target_pname, 8) )
        {
            drakvuf_interrupt(drakvuf, -1);
            drakvuf_pause(drakvuf);
            injector->pid = info->proc_data.pid;
            drakvuf_get_current_thread_id(drakvuf, info->vcpu, &injector->tid);
            injector->rc = 1;
            injector->target_running = 1;
        }

        g_free(pname);
        g_free(pname_utf8);
    }

    return 0;
}

event_response_t cr3_callback(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct injector* injector = info->trap->data;
    addr_t thread = 0;
    reg_t cr3 = info->regs->cr3;
    status_t status;

    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 ". PID: %u PPID: %u\n",
                info->regs->cr3, info->proc_data.pid, info->proc_data.ppid);

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

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    /*
     * At this point the process is still in kernel mode, so
     * we need to trap when it enters into user mode.
     * For this we use different mechanisms on 32-bit and 64-bit.
     * The reason for this is that the same methods are not equally
     * reliable.
     *
     * For 64-bit Windows we use the trapframe approach, where we read
     * the saved RIP from the stack trap frame and breakpoint it.
     * When this address is hit, we hijack the flow and afterwards return
     * the registers to the original values, thus the process continues to run.
     * This method is workable on 32-bit Windows as well but finding the trapframe
     * sometimes fail for yet unknown reasons.
     */
    if (!injector->is32bit)
    {
        addr_t trapframe = 0;
        status = vmi_read_addr_va(vmi,
                                  thread + injector->offsets[KTHREAD_TRAPFRAME],
                                  0, &trapframe);

        if (status == VMI_FAILURE || !trapframe)
        {
            PRINT_DEBUG("cr3_cb: failed to read trapframe (0x%lx)\n", trapframe);
            goto done;
        }

        status = vmi_read_addr_va(vmi,
                                  trapframe + injector->offsets[KTRAP_FRAME_RIP],
                                  0, &injector->bp.breakpoint.addr);

        if (status == VMI_FAILURE || !injector->bp.breakpoint.addr)
        {
            PRINT_DEBUG("Failed to read RIP from trapframe or RIP is NULL!\n");
            goto done;
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

            info->trap->cb = cr3_catch_create_proc;
        }
        else
            fprintf(stderr, "Failed to trap trapframe return address\n");
    }
    else
    {
        GSList* va_pages = vmi_get_va_pages(vmi, info->regs->cr3);
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

        info->trap->cb = cr3_catch_create_proc;
        drakvuf_resume(drakvuf);
    }

done:
    drakvuf_release_vmi(drakvuf);
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
        PRINT_DEBUG("INT3 received from PID: %d [%s]\n",
                    info->proc_data.pid, info->proc_data.name);
        return 0;
    }

    uint32_t threadid = 0;
    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &threadid) || !threadid )
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

        if (INJECT_METHOD_SHELLCODE == injector->method || INJECT_METHOD_DOPP == injector->method)
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
        PRINT_DEBUG("Writing to allocated virtual memory to allocate physical memory..\n");

        injector->payload_addr = info->regs->rax;
        if ( !pass_inputs(injector, info) )
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        info->regs->rip = injector->memset;

        injector->status = STATUS_PHYS_ALLOC_OK;

        PRINT_DEBUG("Payload is at: 0x%lx\n", injector->payload_addr);

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    // Execute the payload
    if ( !injector->is32bit && info->regs->rip == injector->bp.breakpoint.addr && STATUS_PHYS_ALLOC_OK == injector->status)
    {
#ifdef ENABLE_DOPPELGANGING
        // If we are doing process doppelganging we need to write the binary to
        // inject in memory too (in addition to the shellcode), since it is not
        // present in the guest's filesystem.
        if (INJECT_METHOD_DOPP == injector->method)
        {
            addr_t kernbase = 0, process_notify_rva = 0;

            injector->binary_addr = injector->payload_addr + injector->payload_size;

            ctx.addr = injector->binary_addr;
            vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
            bool success = ( VMI_SUCCESS == vmi_write(vmi, &ctx, injector->binary_size, (void*)injector->binary, NULL) );
            drakvuf_release_vmi(drakvuf);

            if (!success)
            {
                PRINT_DEBUG("Failed to write the binary into memory!\n");
                return 0;
            }
            g_free((void*)injector->binary);


            // Get address of PspCallProcessNotifyRoutines() from the rekall profile
            if ( !drakvuf_get_function_rva(drakvuf, "PspCallProcessNotifyRoutines", &process_notify_rva) )
            {
                PRINT_DEBUG("[-] Error getting PspCallProcessNotifyRoutines RVA\n");
                return 0;
            }

            kernbase = drakvuf_get_kernel_base(drakvuf);
            injector->process_notify = kernbase + process_notify_rva;

            // Patch payload
            PRINT_DEBUG("Patching the shellcode with user inputs..\n");
            patch_payload(injector, (unsigned char*)injector->payload);
        }
#endif

        // Write payload into guest's memory
        ctx.addr = injector->payload_addr;
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        bool success = ( VMI_SUCCESS == vmi_write(vmi, &ctx, injector->payload_size, (void*)injector->payload, NULL) );
        drakvuf_release_vmi(drakvuf);

        if ( !success )
        {
            PRINT_DEBUG("Failed to write the payload into memory!\n");
            return 0;
        }
        g_free((void*)injector->payload);

        if ( !pass_inputs(injector, info) )
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        info->regs->rip = injector->payload_addr;

        // At some point the shellcode will call NtCreateThreadEx() wich in turn
        // will cause a call to PspCallProcessNotifyRoutines(). In our case,
        // this function will make NtCreateThreadEx() to fail and the binary we
        // want to inject will never run. We want to place a breakpoint on it to
        // bypass this call.
#ifdef ENABLE_DOPPELGANGING
        if (INJECT_METHOD_DOPP == injector->method)
        {
            // Save breakpoint address to restore it latter
            injector->saved_bp = injector->bp.breakpoint.addr;
            injector->bp.breakpoint.addr = injector->process_notify;

            if ( drakvuf_add_trap(drakvuf, &injector->bp) )
            {
                PRINT_DEBUG("BP placed on PspCallProcessNotifyRoutines() at: 0x%lx\n", injector->bp.breakpoint.addr);
            }

            injector->status = STATUS_BP_HIT;
        }
        else
#endif
        {
            injector->hijacked = 1;

            if ( !injector->target_tid )
                injector->target_tid = threadid;

            injector->status = STATUS_EXEC_OK;
        }

        PRINT_DEBUG("Executing the payload..\n");

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    // Handle breakpoint on PspCallProcessNotifyRoutines()
    if ( !injector->is32bit && info->regs->rip == injector->bp.breakpoint.addr && STATUS_BP_HIT == injector->status)
    {
        addr_t saved_rip = 0;

        // Get saved RIP from the stack
        ctx.addr = info->regs->rsp;
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        bool success = (VMI_SUCCESS == vmi_read(vmi, &ctx, sizeof(addr_t), &saved_rip, NULL));
        drakvuf_release_vmi(drakvuf);

        if ( !success )
        {
            PRINT_DEBUG("[-] Error while reading the saved RIP\n");
            return 0;
        }

        // Bypass call to the function
        info->regs->rip = saved_rip;
        info->regs->rsp += 0x8;

        injector->hijacked = 1;

        if ( !injector->target_tid )
            injector->target_tid = threadid;

        // Restore original value of the breakpoint
        injector->bp.breakpoint.addr = injector->saved_bp;

        injector->status = STATUS_EXEC_OK;

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    if ( !injector->hijacked || info->regs->rip != injector->bp.breakpoint.addr || threadid != injector->target_tid )
        return 0;

    // We are now in the return path from CreateProcessA

    drakvuf_remove_trap(drakvuf, &injector->bp, NULL);
    injector->restored = 1;

    drakvuf_interrupt(drakvuf, -1);

    PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);

    if (INJECT_METHOD_CREATEPROC == injector->method && info->regs->rax)
    {
        ctx.addr = injector->process_info;

        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

        if (injector->is32bit)
        {
            struct process_information_32 pip = { 0 };
            if ( VMI_SUCCESS == vmi_read(vmi, &ctx, sizeof(struct process_information_32), &pip, NULL) )
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
            if ( VMI_SUCCESS == vmi_read(vmi, &ctx, sizeof(struct process_information_64), &pip, NULL) )
            {
                injector->pid = pip.dwProcessId;
                injector->tid = pip.dwThreadId;
                injector->hProc = pip.hProcess;
                injector->hThr = pip.hThread;
            }
        }

        drakvuf_release_vmi(drakvuf);

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
    else if ( (INJECT_METHOD_SHELLCODE == injector->method || INJECT_METHOD_DOPP == injector->method) && STATUS_EXEC_OK == injector->status)
    {
        PRINT_DEBUG("Shellcode executed\n");

        injector->rc = 1;
    }

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static status_t file_to_memory(addr_t* output, size_t* size, const char* file)
{
    size_t bytes_read = 0;
    size_t mem_size = 4096, payload_size = 0;
    unsigned char* shellcode = NULL, *tmp = NULL;
    unsigned char buffer[4096] = { '\0' };
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

        memcpy(tmp, buffer, bytes_read);
        payload_size += bytes_read;
        tmp += bytes_read;
    }

    *output = (addr_t)shellcode;
    *size = payload_size;

    PRINT_DEBUG("Size of file read: %lu\n", *size);

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

static bool get_dtb_for_pid(drakvuf_t drakvuf, vmi_pid_t pid, reg_t* p_target_cr3)
{
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool success = ( VMI_FAILURE != vmi_pid_to_dtb(vmi, pid, p_target_cr3) );
    drakvuf_release_vmi(drakvuf);
    return success;
}

injector_t injector_start_app(drakvuf_t drakvuf, vmi_pid_t pid, uint32_t tid, const char* file, const char* cwd, injection_method_t method, output_format_t format, const char* binary_path, const char* target_process, bool wait_for_process, int* ret)
{

    injector_t injector = (injector_t)g_malloc0(sizeof(struct injector));
    if ( !injector )
        return NULL;

    injector->drakvuf = drakvuf;
    injector->target_pid = pid;
    injector->target_tid = tid;
    injector->target_file = file;
    injector->cwd = cwd;

    gchar* target_pname = g_strrstr(file, "\\");
    injector->target_pname = target_pname ? ++target_pname : file;

    injector->method = method;
    injector->binary_path = binary_path;
    injector->target_process = target_process;
    injector->wait_for_process = wait_for_process;

    injector->is32bit = (drakvuf_get_page_mode(drakvuf) == VMI_PM_IA32E) ? 0 : 1;

    if ( !get_dtb_for_pid(drakvuf, pid, &injector->target_cr3) )
    {
        PRINT_DEBUG("Unable to find target PID's DTB\n");
        goto done;
    }

    // Get the offsets from the Rekall profile
    if ( !drakvuf_get_struct_members_array_rva(injector->drakvuf, offset_names, OFFSET_MAX, injector->offsets) )
        PRINT_DEBUG("Failed to find one of offsets.\n");

    printf("Target PID %u with DTB 0x%lx to start '%s' ['%s']\n", pid,
           injector->target_cr3, file, injector->target_pname);

    addr_t eprocess_base = 0;
    if ( !drakvuf_find_process(injector->drakvuf, pid, NULL, &eprocess_base) )
        goto done;

    char* lib = "kernel32.dll";
    char* fun = "CreateProcessA";
    if (INJECT_METHOD_SHELLEXEC == method)
    {
        lib = "shell32.dll";
        fun = "ShellExecuteA";
    }
    else if (INJECT_METHOD_SHELLCODE == method || INJECT_METHOD_DOPP == method)
    {
        // Read shellcode from a file
        if ( VMI_SUCCESS != file_to_memory(&(injector->payload), &(injector->payload_size), file) )
            goto done;

        if (INJECT_METHOD_DOPP == method)
        {
            // Check for Windows 10 version 1803 or higher
            int build_1803 = 20180410;
            if ( drakvuf_get_os_build_date(injector->drakvuf) < build_1803 )
            {
                PRINT_DEBUG("This injection method requires Windows 10 version 1803 or higher!\n");
                goto done;
            }

            // Read binary to inject from a file
            if ( VMI_SUCCESS != file_to_memory(&(injector->binary), &(injector->binary_size), binary_path) )
                goto done;
        }

        lib = "ntdll.dll";
        fun = "memset";
        injector->memset= drakvuf_exportsym_to_va(injector->drakvuf, eprocess_base, lib, fun);
        if (!injector->memset)
        {
            PRINT_DEBUG("Failed to get address of %s!%s\n", lib, fun);
            goto done;
        }

        lib = "kernel32.dll";
        fun = "VirtualAlloc";
    }

    injector->status = STATUS_NULL;
    injector->exec_func = drakvuf_exportsym_to_va(injector->drakvuf, eprocess_base, lib, fun);
    if (!injector->exec_func)
    {
        PRINT_DEBUG("Failed to get address of %s!%s\n", lib, fun);
        goto done;
    }

    injector->cr3_event.type = REGISTER;
    injector->cr3_event.reg = CR3;
    injector->cr3_event.cb = cr3_callback;
    injector->cr3_event.data = injector;
    if ( !drakvuf_add_trap(drakvuf, &injector->cr3_event) )
        goto done;

    PRINT_DEBUG("Starting injection loop\n");
    drakvuf_loop(drakvuf);

    if (injector->is32bit)
    {
        GSList* loop = injector->memtraps;
        while (loop)
        {
            drakvuf_remove_trap(drakvuf, loop->data, (drakvuf_trap_free_t)free);
            loop=loop->next;
        }
        g_slist_free(loop);
    }

    if ( !injector->rc || !injector->wait_for_process || injector->target_running )
        drakvuf_remove_trap(drakvuf, &injector->cr3_event, NULL);

    print_injection_info(format, pid, injector->target_cr3, file, injector->pid, injector->tid);

done:
    PRINT_DEBUG("Finished with injection. Ret: %i\n", injector->rc);
    *ret = injector->rc;
    return injector;
}

void injector_cleanup(injector_t injector)
{
    while ( !injector->restored )
        drakvuf_loop(injector->drakvuf);

    while ( injector->rc && injector->wait_for_process && !injector->target_running )
        drakvuf_loop(injector->drakvuf);

    drakvuf_remove_trap(injector->drakvuf, &injector->cr3_event, NULL);

    g_free((void*)injector->binary);
    g_free((void*)injector->payload);
    g_free(injector);
}
