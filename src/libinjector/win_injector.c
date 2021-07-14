/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
 *                                                                         *
 * DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
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

#define LIBVMI_EXTRA_GLIB
#define LIBVMI_EXTRA_JSON

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
#include "win_private.h"

typedef enum
{
    INJECT_RESULT_SUCCESS,
    INJECT_RESULT_TIMEOUT,
    INJECT_RESULT_CRASH,
    INJECT_RESULT_PREMATURE,
    INJECT_RESULT_ERROR_CODE,
    INJECT_RESULT_INIT_FAIL
} inject_result_t;

struct injector
{
    // Inputs:
    unicode_string_t* target_file_us;
    vmi_pid_t target_pid;
    uint32_t target_tid;
    unicode_string_t* cwd_us;
    bool break_loop_on_detection;

    // Internal:
    drakvuf_t drakvuf;
    bool is32bit, hijacked, resumed, detected;
    injection_method_t method;
    bool global_search;
    bool wait_for_exit;
    addr_t exec_func;
    reg_t target_rsp;

    // For create process
    addr_t resume_thread;

    // For terminate process
    vmi_pid_t terminate_pid;
    addr_t open_process;
    addr_t exit_process;

    // For shellcode execution
    addr_t payload, payload_addr, memset;
    // For readfile/writefile
    addr_t create_file, read_file, write_file, close_handle, expand_env;
    size_t binary_size, payload_size;
    uint32_t status;
    uint32_t file_handle;
    FILE* host_file;
    unicode_string_t* expanded_target;

    // For process doppelganging shellcode
    addr_t binary, binary_addr, saved_bp;
    addr_t process_notify;

    const char* binary_path;
    const char* target_process;

    addr_t process_info;
    registers_t saved_regs;

    drakvuf_trap_t bp;
    GSList* memtraps;

    // Used only on x64
    size_t offsets[OFFSET_MAX];

    // Results:
    injector_status_t rc;
    inject_result_t result;
    struct
    {
        bool valid;
        uint32_t code;
        const char* string;
    } error_code;

    uint32_t pid, tid;
    uint64_t hProc, hThr;
};

static void free_memtraps(injector_t injector)
{
    GSList* loop = injector->memtraps;
    injector->memtraps = NULL;

    while (loop)
    {
        drakvuf_remove_trap(injector->drakvuf, loop->data, (drakvuf_trap_free_t)free);
        loop = loop->next;
    }
    g_slist_free(loop);
}

static void free_injector(injector_t injector)
{
    if (!injector) return;

    PRINT_DEBUG("Injector freed\n");

    free_memtraps(injector);

    vmi_free_unicode_str(injector->target_file_us);
    vmi_free_unicode_str(injector->cwd_us);
    vmi_free_unicode_str(injector->expanded_target);

    g_free((void*)injector->binary);
    g_free((void*)injector->payload);
    g_free((void*)injector);
}

#define SW_SHOWNORMAL   1
#define MEM_COMMIT      0x00001000
#define MEM_RESERVE     0x00002000
#define MEM_PHYSICAL    0x00400000
#define PAGE_EXECUTE_READWRITE  0x40
#define CREATE_SUSPENDED 0x00000004

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

#ifdef ENABLE_DOPPELGANGING
static int patch_payload(injector_t injector, unsigned char* addr)
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

static unicode_string_t* convert_utf8_to_utf16(char const* str)
{
    if (!str) return NULL;

    unicode_string_t us =
    {
        .contents = (uint8_t*)g_strdup(str),
        .length = strlen(str),
        .encoding = "UTF-8",
    };

    if (!us.contents) return NULL;

    unicode_string_t* out = (unicode_string_t*)g_try_malloc0(sizeof(unicode_string_t));
    if (!out)
    {
        g_free(us.contents);
        return NULL;
    }

    status_t rc = vmi_convert_str_encoding(&us, out, "UTF-16LE");
    g_free(us.contents);

    if (VMI_SUCCESS == rc)
        return out;

    g_free(out);
    return NULL;
}

static bool setup_create_process_stack(injector_t injector, x86_registers_t* regs)
{
    struct argument args[10] = { {0} };
    struct startup_info_32 si_32 = { 0 };
    struct process_information_32 pi_32 = { 0 };
    struct startup_info_64 si_64 = { 0 };
    struct process_information_64 pi_64 = { 0 };

    // CreateProcess(NULL, TARGETPROC, NULL, NULL, 0, 0, NULL, NULL, &si, pi))
    init_int_argument(&args[0], 0);
    init_unicode_argument(&args[1], injector->target_file_us);
    init_int_argument(&args[2], 0);
    init_int_argument(&args[3], 0);
    init_int_argument(&args[4], 0);
    init_int_argument(&args[5], CREATE_SUSPENDED);
    init_int_argument(&args[6], 0);
    init_unicode_argument(&args[7], injector->cwd_us);
    if (injector->is32bit)
    {
        init_struct_argument(&args[8], si_32);
        init_struct_argument(&args[9], pi_32);
    }
    else
    {
        init_struct_argument(&args[8], si_64);
        init_struct_argument(&args[9], pi_64);
    }

    bool success = setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
    injector->process_info = args[9].data_on_stack;
    return success;
}

static bool setup_resume_thread_stack(injector_t injector, x86_registers_t* regs)
{
    struct argument args[1] = { {0} };
    init_int_argument(&args[0], injector->hThr);

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

static bool setup_shell_execute_stack(injector_t injector, x86_registers_t* regs)
{
    struct argument args[6] = { {0} };

    // ShellExecute(NULL, NULL, &FilePath, NULL, NULL, SW_SHOWNORMAL)
    init_int_argument(&args[0], 0);
    init_unicode_argument(&args[1], NULL);
    init_unicode_argument(&args[2], injector->target_file_us);
    init_unicode_argument(&args[3], NULL);
    init_unicode_argument(&args[4], injector->cwd_us);
    init_int_argument(&args[5], SW_SHOWNORMAL);

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

static bool setup_virtual_alloc_stack(injector_t injector, x86_registers_t* regs)
{
    struct argument args[4] = { {0} };

    // VirtualAlloc(NULL, size, allocation_type, protect);
    init_int_argument(&args[0], 0);
    // Allocate enough space for the shellcode and the binary at once
    init_int_argument(&args[1], injector->payload_size + injector->binary_size);
    init_int_argument(&args[2], MEM_COMMIT | MEM_RESERVE);
    init_int_argument(&args[3], PAGE_EXECUTE_READWRITE);

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

static bool setup_memset_stack(injector_t injector, x86_registers_t* regs)
{
    struct argument args[4] = { {0} };

    // memset(payload_addr, c, payload_size);
    init_int_argument(&args[0], injector->payload_addr);
    init_int_argument(&args[1], 0);
    init_int_argument(&args[2], injector->payload_size + injector->binary_size);
    init_int_argument(&args[3], 0);

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

static bool setup_expand_env_stack(injector_t injector, x86_registers_t* regs)
{
    struct argument args[3] = { {0} };

    init_unicode_argument(&args[0], injector->target_file_us);
    init_int_argument(&args[1], injector->payload_addr);
    init_int_argument(&args[2], 256);

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

static bool setup_create_file_stack(injector_t injector, x86_registers_t* regs)
{
    struct argument args[7] = { {0} };

    init_int_argument(&args[0], injector->payload_addr);

    if (injector->method == INJECT_METHOD_READ_FILE)
        init_int_argument(&args[1], GENERIC_READ);
    else
        init_int_argument(&args[1], GENERIC_WRITE);

    init_int_argument(&args[2], FILE_SHARE_READ);
    init_int_argument(&args[3], 0);

    if (injector->method == INJECT_METHOD_READ_FILE)
        init_int_argument(&args[4], OPEN_EXISTING);
    else
        init_int_argument(&args[4], CREATE_NEW);

    init_int_argument(&args[5], FILE_ATTRIBUTE_NORMAL);
    init_int_argument(&args[6], 0);

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

static bool setup_read_file_stack(injector_t injector, x86_registers_t* regs)
{
    struct argument args[5] = { {0} };

    // ReadFile(HANDLE, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, NULL)

    // first page is reserved for lpNumberOfBytesRead value
    init_int_argument(&args[0], injector->file_handle);
    init_int_argument(&args[1], injector->payload_addr + FILE_BUF_RESERVED);
    init_int_argument(&args[2], injector->payload_size - FILE_BUF_RESERVED);
    init_int_argument(&args[3], injector->payload_addr);
    init_int_argument(&args[4], 0);

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

static bool setup_write_file_stack(injector_t injector, x86_registers_t* regs, size_t amount)
{
    struct argument args[5] = { {0} };

    // WriteFile(HANDLE, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, NULL)

    // first page is reserved for lpNumberOfBytesWritten value
    init_int_argument(&args[0], injector->file_handle);
    init_int_argument(&args[1], injector->payload_addr + FILE_BUF_RESERVED);
    init_int_argument(&args[2], amount);
    init_int_argument(&args[3], injector->payload_addr);
    init_int_argument(&args[4], 0);

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

static bool setup_close_handle_stack(injector_t injector, x86_registers_t* regs)
{
    struct argument args[1] = { {0} };

    // CloseHandle(HANDLE)

    init_int_argument(&args[0], injector->file_handle);

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

static bool injector_set_hijacked(injector_t injector, drakvuf_trap_info_t* info)
{
    if (!injector->target_tid)
    {
        uint32_t threadid = 0;
        if (!drakvuf_get_current_thread_id(injector->drakvuf, info, &threadid) || !threadid)
            return false;

        injector->target_tid = threadid;
    }

    injector->hijacked = true;

    return true;
}

static void fill_created_process_info(injector_t injector, drakvuf_trap_info_t* info)
{
    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = injector->process_info;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(injector->drakvuf);

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

    drakvuf_release_vmi(injector->drakvuf);
}

static event_response_t injector_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
static event_response_t injector_int3_terminate_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

static bool setup_int3_trap(injector_t injector, drakvuf_trap_info_t* info, addr_t bp_addr)
{
    injector->bp.type = BREAKPOINT;
    injector->bp.name = "entry";
    if (INJECT_METHOD_TERMINATEPROC == injector->method)
        injector->bp.cb = injector_int3_terminate_cb;
    else
        injector->bp.cb = injector_int3_cb;
    injector->bp.data = injector;
    injector->bp.breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp.breakpoint.dtb = info->regs->cr3;
    injector->bp.breakpoint.addr_type = ADDR_VA;
    injector->bp.breakpoint.addr = bp_addr;
    injector->bp.ttl = UNLIMITED_TTL;
    injector->bp.ah_cb = NULL;

    return drakvuf_add_trap(injector->drakvuf, &injector->bp);
}

static event_response_t mem_callback(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    (void)drakvuf;
    injector_t injector = info->trap->data;

    if ( info->proc_data.pid != injector->target_pid || ( injector->target_tid && (uint32_t)info->proc_data.tid != injector->target_tid ))
    {
        PRINT_DEBUG("MemX received but PID:TID (%u:%u) doesn't match target process (%u:%u)\n",
            info->proc_data.pid, info->proc_data.tid, injector->target_pid, injector->target_tid);
        return 0;
    }

    PRINT_DEBUG("MemX at 0x%lx\n", info->regs->rip);

    /* We might have already hijacked a thread on another vCPU */
    if (injector->hijacked)
        return 0;

    free_memtraps(injector);

    registers_t regs;
    memcpy(&regs.x86, info->regs, sizeof(x86_registers_t));
    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

    bool success = false;
    if (injector->method == INJECT_METHOD_CREATEPROC)
    {
        success = setup_create_process_stack(injector, &regs.x86);
        injector->target_rsp = regs.x86.rsp;
    }
    else if (injector->method == INJECT_METHOD_SHELLEXEC)
        success = setup_shell_execute_stack(injector, &regs.x86);

    if (!success)
    {
        PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
        return 0;
    }

    if (!setup_int3_trap(injector, info, regs.x86.rip))
    {
        fprintf(stderr, "Failed to trap return location of injected function call @ 0x%lx!\n",
            regs.x86.rip);
        return 0;
    }

    if (!injector_set_hijacked(injector, info))
        return 0;

    PRINT_DEBUG("Stack setup finished and return trap added @ 0x%" PRIx64 "\n",
        regs.x86.rip);

    regs.x86.rip = injector->exec_func;
    injector->status = STATUS_CREATE_OK;

    drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

    return 0;
}

static event_response_t wait_for_crash_of_target_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    vmi_pid_t crashed_pid = 0;
    if (drakvuf_is_crashreporter(drakvuf, info, &crashed_pid) && crashed_pid == injector->target_pid)
    {
        injector->rc = INJECTOR_FAILED;
        injector->detected = false;

        drakvuf_interrupt(drakvuf, SIGDRAKVUFCRASH);
    }

    return 0;
}

static event_response_t wait_for_target_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 ". PID: %u PPID: %u TID: %u\n",
        info->regs->cr3, info->proc_data.pid, info->proc_data.ppid, info->proc_data.tid);

    if (info->proc_data.pid != injector->target_pid)
        return 0;

    addr_t thread = drakvuf_get_current_thread(drakvuf, info);
    if (!thread)
    {
        PRINT_DEBUG("Failed to find current thread\n");
        return 0;
    }

    if (injector->target_tid && injector->target_tid != (uint32_t)info->proc_data.tid)
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
        status_t status;
        status = vmi_read_addr_va(vmi,
                thread + injector->offsets[KTHREAD_TRAPFRAME],
                0, &trapframe);

        if (status == VMI_FAILURE || !trapframe)
        {
            PRINT_DEBUG("cr3_cb: failed to read trapframe (0x%lx)\n", trapframe);
            goto done;
        }

        addr_t bp_addr;
        status = vmi_read_addr_va(vmi,
                trapframe + injector->offsets[KTRAP_FRAME_RIP],
                0, &bp_addr);

        if (status == VMI_FAILURE || !bp_addr)
        {
            PRINT_DEBUG("Failed to read RIP from trapframe or RIP is NULL!\n");
            goto done;
        }

        if (setup_int3_trap(injector, info, bp_addr))
        {
            PRINT_DEBUG("Got return address 0x%lx from trapframe and it's now trapped!\n",
                bp_addr);

            // Unsubscribe from the CR3 trap
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
        }
        else
            fprintf(stderr, "Failed to trap trapframe return address\n");
    }
    else
    {
        drakvuf_pause(drakvuf);

        GSList* va_pages = vmi_get_va_pages(vmi, info->regs->cr3);
        GSList* loop = va_pages;
        while (loop)
        {
            page_info_t* page = loop->data;
            if (page->vaddr < 0x80000000 && USER_SUPERVISOR(page->x86_pae.pte_value))
            {
                drakvuf_trap_t* new_trap = g_try_malloc0(sizeof(drakvuf_trap_t));
                new_trap->type = MEMACCESS;
                new_trap->cb = mem_callback;
                new_trap->data = injector;
                new_trap->ttl = UNLIMITED_TTL;
                new_trap->ah_cb = NULL;
                new_trap->memaccess.access = VMI_MEMACCESS_X;
                new_trap->memaccess.type = POST;
                new_trap->memaccess.gfn = page->paddr >> 12;
                if ( drakvuf_add_trap(injector->drakvuf, new_trap) )
                    injector->memtraps = g_slist_prepend(injector->memtraps, new_trap);
                else
                    g_free(new_trap);
            }
            g_free(page);
            loop = loop->next;
        }
        g_slist_free(va_pages);

        // Unsubscribe from the CR3 trap
        drakvuf_remove_trap(drakvuf, info->trap, NULL);

        drakvuf_resume(drakvuf);
    }

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t wait_for_termination_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;
    addr_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    uint64_t exit_code = drakvuf_get_function_argument(drakvuf, info, 2);
    exit_code &= 0xFFFFFFFF;

    vmi_pid_t exit_pid;
    if (!drakvuf_get_pid_from_handle(drakvuf, info, process_handle, &exit_pid))
        exit_pid = info->proc_data.pid;

    if ((int)injector->pid != exit_pid)
        return 0;

    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);

    if (!exit_code)
    {
        injector->rc = INJECTOR_SUCCEEDED;
    }
    else
    {
        injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
        injector->error_code.valid = true;
        injector->error_code.code = exit_code;
        injector->error_code.string = "PROGRAM_FAILED";
    }

    injector->detected = true;

    if ( injector->break_loop_on_detection )
        drakvuf_interrupt(drakvuf, SIGINT);
    else if ( injector->resumed )
        drakvuf_interrupt(drakvuf, SIGINT);

    return 0;
}

static event_response_t wait_for_injected_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    if (injector->pid != (uint32_t)info->proc_data.pid || injector->tid != (uint32_t)info->proc_data.tid)
        return 0;

    PRINT_DEBUG("Process start detected %i -> 0x%lx\n", injector->pid, info->regs->cr3);
    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);

    if (injector->wait_for_exit)
    {
        addr_t rva;

        if (!drakvuf_get_kernel_symbol_rva(drakvuf, "NtTerminateProcess", &rva))
        {
            PRINT_DEBUG("Failed to find NtTerminateProcess RVA!\n");
            return 0;
        }

        drakvuf_trap_t* trap = g_try_malloc0(sizeof(drakvuf_trap_t));
        trap->type = BREAKPOINT;
        trap->name = "terminate_proc";
        trap->cb = wait_for_termination_cb;
        trap->data = injector;
        trap->breakpoint.lookup_type = LOOKUP_PID;
        trap->breakpoint.pid = 4;
        trap->breakpoint.addr_type = ADDR_RVA;
        trap->breakpoint.module = "ntoskrnl.exe";
        trap->breakpoint.rva = rva;
        trap->ttl = UNLIMITED_TTL;

        if (!drakvuf_add_trap(injector->drakvuf, trap))
        {
            PRINT_DEBUG("Failed to setup wait_for_termination_cb trap!\n");
            return 0;
        }
    }
    else
    {
        injector->rc = INJECTOR_SUCCEEDED;
        injector->detected = true;

        if ( injector->break_loop_on_detection )
            drakvuf_interrupt(drakvuf, SIGINT);
        else if ( injector->resumed )
            drakvuf_interrupt(drakvuf, SIGINT);
    }

    return 0;
}

// Setup callback for waiting for first occurence of resumed thread
static bool setup_wait_for_injected_process_trap(injector_t injector)
{
    drakvuf_trap_t* trap = g_try_malloc0(sizeof(drakvuf_trap_t));
    trap->type = REGISTER;
    trap->reg = CR3;
    trap->cb = wait_for_injected_process_cb;
    trap->data = injector;
    if (!drakvuf_add_trap(injector->drakvuf, trap))
    {
        PRINT_DEBUG("Failed to setup wait_for_injected_process trap!\n");
        return false;
    }
    PRINT_DEBUG("Waiting for injected process\n");
    return true;
}

static event_response_t inject_payload(drakvuf_t drakvuf, drakvuf_trap_info_t* info, registers_t* regs)
{
    injector_t injector = info->trap->data;

#ifdef ENABLE_DOPPELGANGING
    // If we are doing process doppelganging we need to write the binary to
    // inject in memory too (in addition to the shellcode), since it is not
    // present in the guest's filesystem.
    if (INJECT_METHOD_DOPP == injector->method)
    {
        addr_t kernbase = 0, process_notify_rva = 0;

        injector->binary_addr = injector->payload_addr + injector->payload_size;

        ACCESS_CONTEXT(ctx);
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = regs->x86.cr3;
        ctx.addr = injector->binary_addr;

        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        bool success = ( VMI_SUCCESS == vmi_write(vmi, &ctx, injector->binary_size, (void*)injector->binary, NULL) );
        drakvuf_release_vmi(drakvuf);

        if (!success)
        {
            PRINT_DEBUG("Failed to write the binary into memory!\n");
            return 0;
        }

        // Get address of PspCallProcessNotifyRoutines() from the JSON debug info
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
    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = regs->x86.cr3;
    ctx.addr = injector->payload_addr;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool success = ( VMI_SUCCESS == vmi_write(vmi, &ctx, injector->payload_size, (void*)injector->payload, NULL) );
    drakvuf_release_vmi(drakvuf);

    if ( !success )
    {
        PRINT_DEBUG("Failed to write the payload into memory!\n");
        return 0;
    }

    if (!setup_stack(injector->drakvuf, &regs->x86, NULL, 4))
    {
        PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
        return 0;
    }

    regs->x86.rip = injector->payload_addr;

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
        injector->bp.ttl = UNLIMITED_TTL;
        injector->bp.ah_cb = NULL;

        if ( drakvuf_add_trap(drakvuf, &injector->bp) )
        {
            PRINT_DEBUG("BP placed on PspCallProcessNotifyRoutines() at: 0x%lx\n", injector->bp.breakpoint.addr);
        }

        injector->status = STATUS_BP_HIT;
    }
    else
#endif
    {
        if (!injector_set_hijacked(injector, info))
            return 0;
        injector->status = STATUS_EXEC_OK;
    }

    PRINT_DEBUG("Executing the payload..\n");

    drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, regs);

    return 0;
}

static event_response_t injector_int3_terminate_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx. vcpu %i. TID %u\n",
        info->regs->rip, info->regs->cr3, info->vcpu, info->proc_data.tid);

    if ( info->proc_data.pid != injector->target_pid )
    {
        PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
            info->proc_data.name, info->proc_data.pid, injector->target_pid);
        return 0;
    }

    if (info->regs->rip != info->trap->breakpoint.addr)
        return 0;

    if (injector->target_tid && (uint32_t)info->proc_data.tid != injector->target_tid)
    {
        PRINT_DEBUG("INT3 received but '%s' TID (%u) doesn't match target process (%u)\n",
            info->proc_data.name, info->proc_data.tid, injector->target_tid);
        return 0;
    }
    else if (!injector->target_tid)
    {
        PRINT_DEBUG("Target TID not provided by the user, pinning TID to %u\n",
            info->proc_data.tid);
        injector->target_tid = info->proc_data.tid;
    }

    if (injector->target_rsp && info->regs->rsp <= injector->target_rsp)
    {
        PRINT_DEBUG("INT3 received but RSP (0x%lx) doesn't match target rsp (0x%lx)\n",
            info->regs->rsp, injector->target_rsp);
        return 0;
    }

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    registers_t regs;
    vmi_get_vcpuregs(vmi, &regs, info->vcpu);
    drakvuf_release_vmi(drakvuf);

    if (injector->status == STATUS_NULL)
    {
        /* We just hit the RIP from the trapframe */
        PRINT_DEBUG("Open process %d to terminate it.\n", injector->terminate_pid);

        memcpy(&injector->saved_regs, &regs, sizeof(x86_registers_t));

        struct argument args[3] = { {0} };

        enum
        {
            PROCESS_TERMINATE = 0x1,
            PROCESS_CREATE_THREAD = 0x2,
            PROCESS_VM_OPERATION = 0x8,
            PROCESS_VM_WRITE = 0x10,
            PROCESS_VM_READ = 0x20,
            PROCESS_QUERY_INFORMATION = 0x400,
        };

        // OpenProcess(PROCESS_TERMINATE, false, PID)
        init_int_argument(&args[0], PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
        init_int_argument(&args[1], 0);
        init_int_argument(&args[2], injector->terminate_pid);

        if (!setup_stack(injector->drakvuf, &regs.x86, args, ARRAY_SIZE(args)))
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        regs.x86.rip = injector->open_process;

        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

        injector->status = STATUS_OPEN;

        return 0;
    }
    else if (injector->status == STATUS_OPEN)
    {
        PRINT_DEBUG("Process %d opened with handle %#lx. Terminate it!\n", injector->terminate_pid, regs.x86.rax);
        struct argument args[7] = { {0} };

        // CreateRemoteThread(handle, NULL, NULL, ExitProcess, 0, NULL, NULL)
        init_int_argument(&args[0], regs.x86.rax);
        init_int_argument(&args[1], 0);
        init_int_argument(&args[2], 0);
        init_int_argument(&args[3], injector->exit_process);
        init_int_argument(&args[4], 0);
        init_int_argument(&args[5], 0);
        init_int_argument(&args[6], 0);

        if (!setup_stack(injector->drakvuf, &regs.x86, args, ARRAY_SIZE(args)))
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        regs.x86.rip = injector->exec_func;

        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

        injector->status = STATUS_TERMINATE;

        return 0;
    }
    else if (injector->status == STATUS_TERMINATE)
    {
        if (info->regs->rax)
            injector->rc = INJECTOR_SUCCEEDED;
        else
            injector->rc = INJECTOR_FAILED;

        PRINT_DEBUG("Process %d terminated %ssuccessfully!\n", injector->terminate_pid, regs.x86.rax ? " " : "un");

        drakvuf_remove_trap(drakvuf, info->trap, NULL);
        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);

        if (injector->rc == INJECTOR_SUCCEEDED)
        {
            PRINT_DEBUG("Terminated\n");
        }
        else
        {
            PRINT_DEBUG("Failed to terminate\n");
            injector->rc = INJECTOR_FAILED;

            drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
        }

        drakvuf_interrupt(drakvuf, SIGINT);

        return 0;
    }

    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);

    drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);

    return 0;
}

static event_response_t injector_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx. vcpu %i. TID %u\n",
        info->regs->rip, info->regs->cr3, info->vcpu, info->proc_data.tid);

    if ( info->proc_data.pid != injector->target_pid )
    {
        PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
            info->proc_data.name, info->proc_data.pid, injector->target_pid);
        return 0;
    }

    if (info->regs->rip != info->trap->breakpoint.addr)
        return 0;

    if (injector->target_tid && (uint32_t)info->proc_data.tid != injector->target_tid)
    {
        PRINT_DEBUG("INT3 received but '%s' TID (%u) doesn't match target process (%u)\n",
            info->proc_data.name, info->proc_data.tid, injector->target_tid);
        return 0;
    }
    else if (!injector->target_tid)
    {
        PRINT_DEBUG("Target TID not provided by the user, pinning TID to %u\n",
            info->proc_data.tid);
        injector->target_tid = info->proc_data.tid;
    }

    if (injector->target_rsp && info->regs->rsp <= injector->target_rsp)
    {
        PRINT_DEBUG("INT3 received but RSP (0x%lx) doesn't match target rsp (0x%lx)\n",
            info->regs->rsp, injector->target_rsp);
        return 0;
    }

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    registers_t regs;
    vmi_get_vcpuregs(vmi, &regs, info->vcpu);
    drakvuf_release_vmi(drakvuf);

    if (injector->is32bit && injector->status == STATUS_CREATE_OK)
    {
        PRINT_DEBUG("32-bit RAX: 0x%lx\n", info->regs->rax);

        if (INJECT_METHOD_SHELLEXEC == injector->method)
        {
            // We are now in the return path from ShellExecuteW called from mem_callback

            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);

            // For some reason ShellExecute could return ERROR_FILE_NOT_FOUND while
            // successfully opening file. So check only for out of resources (0) error.
            if (info->regs->rax)
            {
                // TODO Retrieve PID and TID
                PRINT_DEBUG("Injected\n");
                injector->rc = INJECTOR_SUCCEEDED;
            }

            drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);

            return 0;
        }

        if (INJECT_METHOD_CREATEPROC == injector->method)
        {
            // We are now in the return path from CreateProcessW called from mem_callback

            if (regs.x86.rax)
            {
                injector->rc = INJECTOR_SUCCEEDED;
                fill_created_process_info(injector, info);
            }
            else
            {
                injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
                injector->error_code.valid = true;
                drakvuf_get_last_error(injector->drakvuf, info, &injector->error_code.code, &injector->error_code.string);
            }

            copy_gprs(&regs, &injector->saved_regs);

            if (injector->pid && injector->tid)
            {
                PRINT_DEBUG("Injected PID: %i. TID: %i\n", injector->pid, injector->tid);

                if (!setup_resume_thread_stack(injector, &regs.x86))
                {
                    PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
                    return 0;
                }

                injector->target_rsp = regs.x86.rsp;

                if (!setup_wait_for_injected_process_trap(injector))
                    return 0;

                regs.x86.rip = injector->resume_thread;
                injector->status = STATUS_RESUME_OK;
            }
            else
            {
                PRINT_DEBUG("Failed to inject\n");

                drakvuf_remove_trap(drakvuf, info->trap, NULL);
                drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
            }

            drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);
        }

        return 0;
    }

    if (injector->status == STATUS_RESUME_OK)
    {
        PRINT_DEBUG("Resume RAX: 0x%lx\n", info->regs->rax);

        // We are now in the return path from ResumeThread

        drakvuf_remove_trap(drakvuf, info->trap, NULL);

        if (info->regs->rax == 1)
            injector->rc = INJECTOR_SUCCEEDED;
        else
            injector->rc = INJECTOR_FAILED;

        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);

        if (injector->rc == INJECTOR_SUCCEEDED)
        {
            PRINT_DEBUG("Resumed\n");
        }
        else
        {
            PRINT_DEBUG("Failed to resume\n");
            injector->rc = INJECTOR_FAILED;

            drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
        }

        // If the injected process was already detected to be running but
        // the loop is not broken on detection, that means that resumethread
        // was the last remaining trap we were waiting for and it's time
        // to break the loop now
        //
        // If the injected processwas already detected to be running and
        // the loop is broken on detected, then we are now in a loop
        // outside the normal injection loop (ie. main drakvuf)
        // so we don't break the loop
        if ( injector->detected && !injector->break_loop_on_detection )
            drakvuf_interrupt(drakvuf, SIGINT);

        injector->resumed = true;

        return 0;
    }

    if (!injector->is32bit && !injector->hijacked && injector->status == STATUS_NULL)
    {
        /* We just hit the RIP from the trapframe */

        memcpy(&injector->saved_regs, &regs, sizeof(x86_registers_t));

        bool success = false;
        switch (injector->method)
        {
            case INJECT_METHOD_CREATEPROC:
                success = setup_create_process_stack(injector, &regs.x86);
                injector->target_rsp = regs.x86.rsp;
                break;
            case INJECT_METHOD_SHELLEXEC:
                success = setup_shell_execute_stack(injector, &regs.x86);
                break;
            case INJECT_METHOD_SHELLCODE:
            case INJECT_METHOD_DOPP:
            case INJECT_METHOD_READ_FILE:
            case INJECT_METHOD_WRITE_FILE:
                success = setup_virtual_alloc_stack(injector, &regs.x86);
                break;
            default:
                // TODO Implement
                success = false;
                break;
        }

        if (!success)
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        if (INJECT_METHOD_SHELLCODE == injector->method ||
            INJECT_METHOD_DOPP == injector->method ||
            INJECT_METHOD_WRITE_FILE == injector->method ||
            INJECT_METHOD_READ_FILE == injector->method)
        {
            injector->status = STATUS_ALLOC_OK;
        }
        else
        {
            if (!injector_set_hijacked(injector, info))
                return 0;
            injector->status = STATUS_CREATE_OK;
        }

        regs.x86.rip = injector->exec_func;

        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

        return 0;
    }

    // Chain the injection with a second function
    if ( !injector->is32bit && STATUS_ALLOC_OK == injector->status)
    {
        PRINT_DEBUG("Writing to allocated virtual memory to allocate physical memory..\n");

        injector->payload_addr = regs.x86.rax;

        if (!setup_memset_stack(injector, &regs.x86))
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        regs.x86.rip = injector->memset;

        injector->status = STATUS_PHYS_ALLOC_OK;

        PRINT_DEBUG("Payload is at: 0x%lx\n", injector->payload_addr);

        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

        return 0;
    }

    // Execute the payload
    if ( !injector->is32bit && STATUS_PHYS_ALLOC_OK == injector->status)
    {
        if (INJECT_METHOD_READ_FILE != injector->method &&
            INJECT_METHOD_WRITE_FILE != injector->method)
        {
            return inject_payload(drakvuf, info, &regs);
        }
        else
        {
            PRINT_DEBUG("Expanding shell...\n");

            if (!setup_expand_env_stack(injector, &regs.x86))
            {
                PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
                return 0;
            }

            regs.x86.rip = injector->expand_env;

            injector->status = STATUS_EXPAND_ENV_OK;

            drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

            return 0;
        }
    }

    if ( !injector->is32bit && STATUS_EXPAND_ENV_OK == injector->status )
    {
        PRINT_DEBUG("Env expand status: %lx\n", regs.x86.rax);

        if (!regs.x86.rax)
        {
            PRINT_DEBUG("Failed to expand environemnt variables!\n");
            return 0;
        }

        uint8_t buf[FILE_BUF_SIZE] = {0};;
        unicode_string_t in;

        ACCESS_CONTEXT(ctx);
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = regs.x86.cr3;
        ctx.addr = injector->payload_addr;

        if (regs.x86.rax * 2 > FILE_BUF_SIZE)
        {
            PRINT_DEBUG("Env expand reported more than the buffer can carry.\n");
            return 0;
        }

        vmi = drakvuf_lock_and_get_vmi(drakvuf);
        if (VMI_SUCCESS != vmi_read(vmi, &ctx, regs.x86.rax * 2, buf, NULL))
        {
            drakvuf_release_vmi(drakvuf);
            PRINT_DEBUG("Failed to read buffer at %lx\n", regs.x86.rax * 2);
            return 0;
        }

        drakvuf_release_vmi(drakvuf);
        in.contents = buf;
        in.length = regs.x86.rax * 2;
        in.encoding = "UTF-16";

        injector->expanded_target = (unicode_string_t*)g_try_malloc0(sizeof(unicode_string_t));
        if (VMI_SUCCESS != vmi_convert_str_encoding(&in, injector->expanded_target, "UTF-8"))
        {
            PRINT_DEBUG("Failed to convert buffer\n");
            return 0;
        }

        PRINT_DEBUG("Expanded: %s\n", injector->expanded_target->contents);
        PRINT_DEBUG("Opening file...\n");

        if (!setup_create_file_stack(injector, &regs.x86))
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        regs.x86.rip = injector->create_file;

        injector->status = STATUS_CREATE_FILE_OK;

        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

        return 0;
    }

    if (!injector->is32bit &&
        ( STATUS_CREATE_FILE_OK == injector->status || STATUS_WRITE_FILE_OK == injector->status ) &&
        INJECT_METHOD_WRITE_FILE == injector->method)
    {
        uint8_t buf[FILE_BUF_SIZE];
        size_t amount;

        if (STATUS_CREATE_FILE_OK == injector->status)
        {
            PRINT_DEBUG("File create result %lx\n", regs.x86.rax);
            if (regs.x86.rax == (~0ULL) || !regs.x86.rax)
            {
                PRINT_DEBUG("Failed to open guest file\n");
                injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
                injector->error_code.valid = true;
                drakvuf_get_last_error(injector->drakvuf, info, &injector->error_code.code, &injector->error_code.string);

                drakvuf_remove_trap(drakvuf, info->trap, NULL);
                drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
                drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);
                return 0;
            }

            injector->file_handle = regs.x86.rax;
            injector->host_file = fopen(injector->binary_path, "rb");

            if (!injector->host_file)
            {
                PRINT_DEBUG("Failed to open host file\n");
                injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
                injector->error_code.code = errno;
                injector->error_code.string = "HOST_FAILED_FOPEN";
                injector->error_code.valid = true;

                drakvuf_remove_trap(drakvuf, info->trap, NULL);
                drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
                drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);
                return 0;
            }
        }
        else
        {
            if (!regs.x86.rax)
            {
                PRINT_DEBUG("Failed to write to the guest file\n");
                injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
                injector->error_code.valid = true;
                drakvuf_get_last_error(injector->drakvuf, info, &injector->error_code.code, &injector->error_code.string);

                drakvuf_remove_trap(drakvuf, info->trap, NULL);
                drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
                drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);
                return 0;
            }
        }

        PRINT_DEBUG("Writing file...\n");
        amount = fread(buf + FILE_BUF_RESERVED, 1, FILE_BUF_SIZE - FILE_BUF_RESERVED, injector->host_file);
        PRINT_DEBUG("Amount: %lx\n", amount);

        if (!amount)
        {
            PRINT_DEBUG("Finishing\n");

            if (!setup_close_handle_stack(injector, &regs.x86))
            {
                PRINT_DEBUG("Failed to setup stack for closing handle\n");
                return 0;
            }

            regs.x86.rip = injector->close_handle;

            injector->status = STATUS_CLOSE_FILE_OK;
            drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

            return 0;
        }

        PRINT_DEBUG("Writing...\n");

        if (!setup_write_file_stack(injector, &regs.x86, amount))
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = regs.x86.cr3,
            .addr = injector->payload_addr + FILE_BUF_RESERVED
        );

        vmi = drakvuf_lock_and_get_vmi(drakvuf);
        bool success = (VMI_SUCCESS == vmi_write(vmi, &ctx, amount, buf + FILE_BUF_RESERVED, NULL));
        drakvuf_release_vmi(drakvuf);

        if (!success)
        {
            PRINT_DEBUG("Failed to write payload chunk!\n");
            return 0;
        }

        regs.x86.rip = injector->write_file;

        injector->status = STATUS_WRITE_FILE_OK;
        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

        return 0;
    }

    if (!injector->is32bit &&
        STATUS_CREATE_FILE_OK == injector->status &&
        INJECT_METHOD_READ_FILE == injector->method)
    {
        PRINT_DEBUG("File create result %lx\n", regs.x86.rax);

        if (regs.x86.rax == (~0ULL) || !regs.x86.rax)
        {
            PRINT_DEBUG("Failed to open guest file\n");
            injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
            injector->error_code.valid = true;
            drakvuf_get_last_error(injector->drakvuf, info, &injector->error_code.code, &injector->error_code.string);

            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
            drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);
            return 0;
        }

        injector->file_handle = regs.x86.rax;
        injector->host_file = fopen(injector->binary_path, "wb");

        if (!injector->host_file)
        {
            PRINT_DEBUG("Failed to open host file\n");
            injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
            injector->error_code.code = errno;
            injector->error_code.string = "HOST_FAILED_FOPEN";
            injector->error_code.valid = true;

            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
            drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);
            return 0;
        }

        PRINT_DEBUG("Reading file...\n");

        if (!setup_read_file_stack(injector, &regs.x86))
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        regs.x86.rip = injector->read_file;

        injector->status = STATUS_READ_FILE_OK;
        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

        return 0;
    }

    if (!injector->is32bit && STATUS_READ_FILE_OK == injector->status)
    {
        uint8_t buf[FILE_BUF_SIZE];

        PRINT_DEBUG("File read result: %lx\n", regs.x86.rax);

        if (!regs.x86.rax)
        {
            PRINT_DEBUG("Failed to read the guest file\n");
            injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
            injector->error_code.valid = true;
            drakvuf_get_last_error(injector->drakvuf, info, &injector->error_code.code, &injector->error_code.string);

            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
            drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);
            return 0;
        }

        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = regs.x86.cr3,
            .addr = injector->payload_addr
        );

        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        bool success = (VMI_SUCCESS == vmi_read(vmi, &ctx, FILE_BUF_SIZE, buf, NULL));
        drakvuf_release_vmi(drakvuf);

        if (!success)
        {
            PRINT_DEBUG("Failed to read payload chunk!\n");
            return 0;
        }

        uint32_t num_bytes = *(uint32_t*)buf;

        if (num_bytes > FILE_BUF_SIZE)
        {
            num_bytes = FILE_BUF_SIZE;
            PRINT_DEBUG("Number of bytes read by ReadFile is greater than the buffer size, truncating.\n");
        }

        fwrite(buf + FILE_BUF_RESERVED, num_bytes, 1, injector->host_file);

        if (num_bytes != 0)
        {
            if (!setup_read_file_stack(injector, &regs.x86))
            {
                PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
                return 0;
            }

            regs.x86.rip = injector->read_file;

            injector->status = STATUS_READ_FILE_OK;
        }
        else
        {
            PRINT_DEBUG("Finishing\n");

            if (!setup_close_handle_stack(injector, &regs.x86))
            {
                PRINT_DEBUG("Failed to setup stack for closing handle\n");
                return 0;
            }

            injector->status = STATUS_CLOSE_FILE_OK;
        }

        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

        return 0;
    }

    if ( !injector->is32bit && STATUS_CLOSE_FILE_OK == injector->status )
    {
        PRINT_DEBUG("Close handle RAX: 0x%lx\n", regs.x86.rax);
        fclose(injector->host_file);

        if (regs.x86.rax == ~0ULL || !regs.x86.rax)
        {
            injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
            injector->error_code.valid = true;
            drakvuf_get_last_error(injector->drakvuf, info, &injector->error_code.code, &injector->error_code.string);

            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
            drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);

            return 0;
        }

        injector->status = STATUS_EXEC_OK;

        drakvuf_remove_trap(drakvuf, info->trap, NULL);
        drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);

        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);

        PRINT_DEBUG("File operation executed OK\n");
        injector->rc = INJECTOR_SUCCEEDED;

        return 0;
    }

    // Handle breakpoint on PspCallProcessNotifyRoutines()
    if ( !injector->is32bit && STATUS_BP_HIT == injector->status)
    {
        addr_t saved_rip = 0;

        // Get saved RIP from the stack
        ACCESS_CONTEXT(ctx);
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
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
        regs.x86.rip = saved_rip;
        regs.x86.rsp += 0x8;

        if (!injector_set_hijacked(injector, info))
            return 0;

        // Restore original value of the breakpoint
        injector->bp.breakpoint.addr = injector->saved_bp;

        injector->status = STATUS_EXEC_OK;

        drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

        return 0;
    }

    if (!injector->hijacked)
        return 0;

    PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);

    if (INJECT_METHOD_CREATEPROC == injector->method && injector->status == STATUS_CREATE_OK)
    {
        // We are now in the return path from CreateProcessW

        if (info->regs->rax)
        {
            injector->rc = INJECTOR_SUCCEEDED;
            fill_created_process_info(injector, info);
        }
        else
        {
            injector->error_code.valid = true;
            injector->rc = INJECTOR_FAILED_WITH_ERROR_CODE;
            drakvuf_get_last_error(injector->drakvuf, info, &injector->error_code.code, &injector->error_code.string);
        }

        if (injector->pid && injector->tid)
        {
            PRINT_DEBUG("Injected PID: %i. TID: %i\n", injector->pid, injector->tid);

            if (!setup_resume_thread_stack(injector, &regs.x86))
            {
                PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
                return 0;
            }

            injector->target_rsp = regs.x86.rsp;

            if (!setup_wait_for_injected_process_trap(injector))
                return 0;

            regs.x86.rip = injector->resume_thread;
            injector->status = STATUS_RESUME_OK;

            drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

            return 0;
        }
        else
        {
            PRINT_DEBUG("Failed to inject\n");
        }
    }
    // For some reason ShellExecute could return ERROR_FILE_NOT_FOUND while
    // successfully opening file. So check only for out of resources (0) error.
    else if (INJECT_METHOD_SHELLEXEC == injector->method && info->regs->rax)
    {
        // TODO Retrieve PID and TID
        PRINT_DEBUG("Injected\n");
        injector->rc = INJECTOR_SUCCEEDED;
    }
    else if ( (INJECT_METHOD_SHELLCODE == injector->method ||
            INJECT_METHOD_DOPP == injector->method) &&
        STATUS_EXEC_OK == injector->status)
    {
        PRINT_DEBUG("Shellcode executed\n");
        injector->rc = INJECTOR_SUCCEEDED;
    }

    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);

    drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);

    return 0;
}

static bool is_interrupted(drakvuf_t drakvuf, void* data __attribute__((unused)))
{
    return drakvuf_is_interrupted(drakvuf);
}

static bool inject(drakvuf_t drakvuf, injector_t injector)
{
    injector->hijacked = 0;
    injector->status = STATUS_NULL;

    drakvuf_trap_t trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = wait_for_target_process_cb,
        .data = injector,
    };
    if (!drakvuf_add_trap(drakvuf, &trap))
        return false;

    drakvuf_trap_t trap_crashreporter =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = wait_for_crash_of_target_process,
        .data = injector,
    };
    if (!drakvuf_add_trap(drakvuf, &trap_crashreporter))
        return false;

    if (!drakvuf_is_interrupted(drakvuf))
    {
        const char* method = injector->method == INJECT_METHOD_TERMINATEPROC ? "termination" : "injection";
        PRINT_DEBUG("Starting %s loop\n", method);
        drakvuf_loop(drakvuf, is_interrupted, NULL);
        PRINT_DEBUG("Finished %s loop\n", method);
    }

    if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        injector->rc = INJECTOR_TIMEOUTED;

    free_memtraps(injector);

    drakvuf_remove_trap(drakvuf, &trap, NULL);
    drakvuf_remove_trap(drakvuf, &trap_crashreporter, NULL);

    return true;
}

static bool load_file_to_memory(addr_t* output, size_t* size, const char* file)
{
    if (!output || !size || !file)
        return false;

    long payload_size = 0;
    unsigned char* data = NULL;
    FILE* fp = fopen(file, "rb");

    if (!fp)
        return false;

    // obtain file size:
    fseek (fp, 0, SEEK_END);
    if ( (payload_size = ftell (fp)) < 0 )
    {
        fclose(fp);
        return false;
    }
    rewind (fp);

    data = g_try_malloc0(payload_size);
    if ( !data )
    {
        fclose(fp);
        return false;
    }

    if ( (size_t)payload_size != fread(data, payload_size, 1, fp) )
    {
        g_free(data);
        fclose(fp);
        return false;
    }

    *output = (addr_t)data;
    *size = payload_size;

    PRINT_DEBUG("Size of file read: %lu\n", payload_size);

    fclose(fp);

    return true;
}

static void print_injection_info(output_format_t format, const char* file, injector_t injector)
{
    gint64 t = g_get_real_time();

    const char* process_name = "";
    const char* arguments = "";

    const char* splitter = " ";
    const char* begin_proc_name = file;

    if (file[0] == '"')
    {
        splitter = "\"";
        begin_proc_name = &file[1];
    }

    char** split_results = g_strsplit_set(begin_proc_name, splitter, 2);
    char** split_results_iterator = split_results;

    if (*split_results_iterator)
    {
        // Advance iterator to step over image/process name
        split_results_iterator++;
    }

    if (*split_results_iterator)
    {
        arguments = *(split_results_iterator++);
        while (*arguments == ' ')
            arguments++;
    }

    if (injector->expanded_target && injector->expanded_target->contents)
        process_name = (const char*)injector->expanded_target->contents;

    char* escaped_pname = g_strescape(process_name, NULL);
    char* escaped_arguments = g_strescape(arguments, NULL);

    switch (injector->result)
    {
        case INJECT_RESULT_SUCCESS:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Success,%u,\"%s\",\"%s\",%u,%u\n",
                        UNPACK_TIMEVAL(t), injector->target_pid, process_name, escaped_arguments, injector->pid, injector->tid);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Success,PID=%u,ProcessName=\"%s\",Arguments=\"%s\",InjectedPid=%u,InjectedTid=%u\n",
                        UNPACK_TIMEVAL(t), injector->target_pid, process_name, escaped_arguments, injector->pid, injector->tid);
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Status\": \"Success\", "
                        "\"ProcessName\": \"%s\", "
                        "\"Arguments\": \"%s\", "
                        "\"InjectedPid\": %d, "
                        "\"InjectedTid\": %d"
                        "}\n",
                        UNPACK_TIMEVAL(t), escaped_pname, escaped_arguments, injector->pid, injector->tid);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:SUCCESS PID:%u FILE:\"%s\" ARGUMENTS:\"%s\" INJECTED_PID:%u INJECTED_TID:%u\n",
                        UNPACK_TIMEVAL(t), injector->target_pid, process_name, escaped_arguments, injector->pid, injector->tid);
                    break;
            }
            break;
        case INJECT_RESULT_TIMEOUT:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Timeout\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Timeout\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Status\": \"Timeout\""
                        "}\n", UNPACK_TIMEVAL(t));
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:Timeout\n", UNPACK_TIMEVAL(t));
                    break;
            }
            break;
        case INJECT_RESULT_CRASH:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Crash\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Crash\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Status\": \"Crash\""
                        "}\n", UNPACK_TIMEVAL(t));
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:Crash\n", UNPACK_TIMEVAL(t));
                    break;
            }
            break;
        case INJECT_RESULT_PREMATURE:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",PrematureBreak\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=PrematureBreak\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Status\": \"PrematureBreak\""
                        "}\n", UNPACK_TIMEVAL(t));
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:PrematureBreak\n", UNPACK_TIMEVAL(t));
                    break;
            }
            break;
        case INJECT_RESULT_INIT_FAIL:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",InitFail\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=InitFail\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Status\": \"InitFail\""
                        "}\n", UNPACK_TIMEVAL(t));
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:InitFail\n", UNPACK_TIMEVAL(t));
                    break;
            }
            break;
        case INJECT_RESULT_ERROR_CODE:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Error,%d,\"%s\"\n",
                        UNPACK_TIMEVAL(t), injector->error_code.code, injector->error_code.string);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Error,ErrorCode=%d,Error=\"%s\"\n",
                        UNPACK_TIMEVAL(t), injector->error_code.code, injector->error_code.string);
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Plugin\": \"inject\", "
                        "\"TimeStamp\": \"" FORMAT_TIMEVAL "\", "
                        "\"Status\": \"Error\", "
                        "\"ErrorCode\": %d, "
                        "\"Error\": \"%s\""
                        "}\n",
                        UNPACK_TIMEVAL(t), injector->error_code.code, injector->error_code.string);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:Error ERROR_CODE:%d ERROR:\"%s\"\n",
                        UNPACK_TIMEVAL(t), injector->error_code.code, injector->error_code.string);
                    break;
            }
            break;
    }

    g_free(escaped_pname);
    g_free(escaped_arguments);
    g_strfreev(split_results);
}

struct module_context
{
    const char* lib;
    const char* fun;
    addr_t module_addr;
    addr_t addr;
};

static bool module_visitor(drakvuf_t drakvuf, const module_info_t* module_info, void* ctx )
{
    struct module_context* data = (struct module_context*)ctx;

    if (module_info->base_addr != data->module_addr)
        return false;

    data->addr = drakvuf_exportsym_to_va(drakvuf, module_info->eprocess_addr, data->lib, data->fun);
    if (data->addr)
        return true;

    return false;
}

static addr_t get_function_va(drakvuf_t drakvuf, addr_t eprocess_base, char const* lib, char const* fun, bool global_search)
{
    // First check current process for function
    addr_t addr = drakvuf_exportsym_to_va(drakvuf, eprocess_base, lib, fun);
    if (addr)
        return addr;

    // If function is not mapped into the processes address space search it in other processes
    struct module_context module_ctx =
    {
        .lib = lib,
        .fun = fun,
        .addr = 0
    };

    if (global_search)
    {
        // First get modules load address to search for other process with same address
        ACCESS_CONTEXT(ctx);
        ctx.translate_mechanism = VMI_TM_PROCESS_PID;

        addr_t module_list_head;
        if (drakvuf_get_process_pid(drakvuf, eprocess_base, &ctx.pid) &&
            drakvuf_get_module_list(drakvuf, eprocess_base, &module_list_head) &&
            drakvuf_get_module_base_addr_ctx(drakvuf, module_list_head, &ctx, lib, &module_ctx.module_addr))
        {
            drakvuf_enumerate_processes_with_module(drakvuf, lib, module_visitor, &module_ctx);
        }
    }

    if (!module_ctx.addr)
        PRINT_DEBUG("Failed to get address of %s!%s\n", lib, fun);

    return module_ctx.addr;
}

static bool initialize_injector_functions(drakvuf_t drakvuf, injector_t injector, const char* file, const char* binary_path)
{
    addr_t eprocess_base = 0;
    if ( !drakvuf_find_process(drakvuf, injector->target_pid, NULL, &eprocess_base) )
        return false;

    if (!injector->is32bit)
    {
        // Get the offsets from the Rekall profile
        if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_KTHREAD", "TrapFrame", &injector->offsets[KTHREAD_TRAPFRAME]))
            PRINT_DEBUG("Failed to find _KTHREAD:TrapFrame.\n");

        if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_KTRAP_FRAME", "Rip", &injector->offsets[KTRAP_FRAME_RIP]))
            PRINT_DEBUG("Failed to find _KTRAP_FRAME:Rip.\n");
    }

    if (INJECT_METHOD_CREATEPROC == injector->method)
    {
        injector->resume_thread = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "ResumeThread", injector->global_search);
        if (!injector->resume_thread) return false;
        injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "CreateProcessW", injector->global_search);
    }
    else if (INJECT_METHOD_TERMINATEPROC == injector->method)
    {
        injector->open_process = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "OpenProcess", injector->global_search);
        if (!injector->open_process) return false;
        injector->exit_process = get_function_va(drakvuf, eprocess_base, "ntdll.dll", "RtlExitUserProcess", injector->global_search);
        if (!injector->exit_process) return false;
        injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "CreateRemoteThread", injector->global_search);
    }
    else if (INJECT_METHOD_SHELLEXEC == injector->method)
    {
        injector->exec_func = get_function_va(drakvuf, eprocess_base, "shell32.dll", "ShellExecuteW", injector->global_search);
    }
    else if (INJECT_METHOD_SHELLCODE == injector->method || INJECT_METHOD_DOPP == injector->method)
    {
        // Read shellcode from a file
        if ( !load_file_to_memory(&injector->payload, &injector->payload_size, file) )
            return false;

        if (INJECT_METHOD_DOPP == injector->method)
        {
            // Read binary to inject from a file
            if ( !load_file_to_memory(&injector->binary, &injector->binary_size, binary_path) )
                return false;
        }

        injector->memset = get_function_va(drakvuf, eprocess_base, "ntdll.dll", "memset", injector->global_search);
        if (!injector->memset) return false;
        injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "VirtualAlloc", injector->global_search);
    }
    else if (INJECT_METHOD_WRITE_FILE == injector->method || INJECT_METHOD_READ_FILE == injector->method)
    {
        injector->payload_size = FILE_BUF_SIZE;

        injector->memset = get_function_va(drakvuf, eprocess_base, "ntdll.dll", "memset", injector->global_search);
        if (!injector->memset) return false;
        injector->create_file = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "CreateFileW", injector->global_search);
        if (!injector->create_file) return false;
        injector->expand_env = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "ExpandEnvironmentStringsW", injector->global_search);
        if (!injector->expand_env) return false;

        if (INJECT_METHOD_WRITE_FILE == injector->method)
        {
            injector->write_file = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "WriteFile", injector->global_search);
            if (!injector->write_file) return false;
        }
        else if (INJECT_METHOD_READ_FILE == injector->method)
        {
            injector->read_file = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "ReadFile", injector->global_search);
            if (!injector->read_file) return false;
        }

        injector->close_handle = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "CloseHandle", injector->global_search);
        if (!injector->close_handle) return false;
        injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "VirtualAlloc", injector->global_search);
    }

    return injector->exec_func != 0;
}

injector_status_t injector_start_app_on_win(
    drakvuf_t drakvuf,
    vmi_pid_t pid,
    uint32_t tid,
    const char* file,
    const char* cwd,
    injection_method_t method,
    output_format_t format,
    const char* binary_path,
    const char* target_process,
    bool break_loop_on_detection,
    injector_t* to_be_freed_later,
    bool global_search,
    bool wait_for_exit,
    vmi_pid_t* injected_pid)
{
    injector_status_t rc = 0;
    PRINT_DEBUG("Target PID %u to start '%s'\n", pid, file);

    unicode_string_t* target_file_us = convert_utf8_to_utf16(file);
    if (!target_file_us)
    {
        PRINT_DEBUG("Unable to convert file path from utf8 to utf16\n");
        return 0;
    }

    unicode_string_t* cwd_us = NULL;
    if (cwd)
    {
        cwd_us = convert_utf8_to_utf16(cwd);
        if (!cwd_us)
        {
            PRINT_DEBUG("Unable to convert cwd from utf8 to utf16\n");
            vmi_free_unicode_str(target_file_us);
            return 0;
        }
    }

    injector_t injector = (injector_t)g_try_malloc0(sizeof(struct injector));
    if (!injector)
    {
        vmi_free_unicode_str(target_file_us);
        vmi_free_unicode_str(cwd_us);
        return 0;
    }

    injector->drakvuf = drakvuf;
    injector->target_pid = pid;
    injector->target_tid = tid;
    injector->target_file_us = target_file_us;
    injector->cwd_us = cwd_us;
    injector->method = method;
    injector->global_search = global_search;
    injector->wait_for_exit = wait_for_exit;
    injector->binary_path = binary_path;
    injector->target_process = target_process;
    injector->status = STATUS_NULL;
    injector->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    injector->break_loop_on_detection = break_loop_on_detection;
    injector->error_code.valid = false;
    injector->error_code.code = -1;
    injector->error_code.string = "<UNKNOWN>";

    if (!initialize_injector_functions(drakvuf, injector, file, binary_path))
    {
        PRINT_DEBUG("Unable to initialize injector functions\n");
        injector->result = INJECT_RESULT_INIT_FAIL;
        print_injection_info(format, file, injector);
        free_injector(injector);
        return 0;
    }

    if (inject(drakvuf, injector) && injector->rc == INJECTOR_SUCCEEDED)
    {
        injector->result = INJECT_RESULT_SUCCESS;
        print_injection_info(format, file, injector);
    }
    else
    {
        if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        {
            PRINT_DEBUG("Injection timeout\n");
            injector->result = INJECT_RESULT_TIMEOUT;
            print_injection_info(format, file, injector);
        }
        else if (SIGDRAKVUFCRASH == drakvuf_is_interrupted(drakvuf))
        {
            PRINT_DEBUG("Target process crash detected\n");
            injector->result = INJECT_RESULT_CRASH;
            print_injection_info(format, file, injector);
        }
        else if (injector->error_code.valid)
        {
            PRINT_DEBUG("Injection failed with error '%s' (%d)\n",
                injector->error_code.string,
                injector->error_code.code);
            injector->result = INJECT_RESULT_ERROR_CODE;
            print_injection_info(format, file, injector);
        }
        else
        {
            PRINT_DEBUG("Injection premature break\n");
            injector->result = INJECT_RESULT_PREMATURE;
            print_injection_info(format, file, injector);
        }
    }

    rc = injector->rc;
    if (injected_pid)
        *injected_pid = injector->pid;
    PRINT_DEBUG("Finished with injection. Ret: %i.\n", rc);

    switch (method)
    {
        case INJECT_METHOD_CREATEPROC:
            if ( break_loop_on_detection )
                if ( injector->resumed && injector->detected )
                {
                    free_injector(injector);
                }
                else
                {
                    *to_be_freed_later = injector;
                }
            else
                free_injector(injector);
            break;
        default:
            free_injector(injector);
            break;
    }

    return rc;
}

void injector_terminate_on_win(drakvuf_t drakvuf,
    vmi_pid_t injection_pid,
    uint32_t injection_tid,
    vmi_pid_t pid)
{
    PRINT_DEBUG("Target PID %u to terminate %u\n", injection_pid, pid);
    drakvuf_interrupt(drakvuf, 0); // clean

    injector_t injector = (injector_t)g_try_malloc0(sizeof(struct injector));

    injector->method = INJECT_METHOD_TERMINATEPROC;
    injector->drakvuf = drakvuf;
    injector->target_pid = injection_pid;
    injector->target_tid = injection_tid;
    injector->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    injector->terminate_pid = pid;
    injector->status = STATUS_NULL;

    if (!initialize_injector_functions(drakvuf, injector, NULL, NULL))
    {
        PRINT_DEBUG("Unable to initialize injector functions\n");
        free_injector(injector);
        return;
    }

    inject(drakvuf, injector);
    PRINT_DEBUG("Finished with termination. Ret: %i.\n", injector->rc);
}
