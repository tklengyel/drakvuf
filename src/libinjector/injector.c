/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
 *                                                                         *
 * DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  *
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

typedef enum
{
    INJECT_RESULT_SUCCESS,
    INJECT_RESULT_TIMEOUT,
    INJECT_RESULT_CRASH,
    INJECT_RESULT_PREMATURE,
    INJECT_RESULT_ERROR_CODE,
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
    addr_t exec_func;
    reg_t target_rsp;

    // For create process
    addr_t resume_thread;

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

    drakvuf_trap_t bp;
    GSList* memtraps;

    size_t offsets[OFFSET_MAX];

    // Results:
    int rc;
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

    unicode_string_t* out = (unicode_string_t*)g_malloc0(sizeof(unicode_string_t));
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

static bool setup_message_box_stack(injector_t injector, drakvuf_trap_info_t *info){
    /**
     * int MessageBox(
        HWND    hWnd,           ==>NULL
        LPCTSTR lpText,         ==>String
        LPCTSTR lpCaption,      ==>NULL
        UINT    uType           ==>0x00000000L
    );
    */
   struct argument args[4] = { {0} };
   init_int_argument(&args[0], 0);
   char *str = "Hijacked";
   unicode_string_t message =
    {
        .contents = (uint8_t*)g_strdup(str),
        .length = strlen(str),
        .encoding = "UTF-8",
    };
   init_unicode_argument(&args[1], &message);
   init_int_argument(&args[2], 0);
   init_int_argument(&args[3], 0);
   //assuming 64 bit
   //TODO add checks for 32 bit
   bool success = setup_stack(injector->drakvuf, info, args, ARRAY_SIZE(args));
   return success;

}

static bool setup_create_process_stack(injector_t injector, drakvuf_trap_info_t* info)
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

    bool success = setup_stack(injector->drakvuf, info, args, ARRAY_SIZE(args));
    injector->process_info = args[9].data_on_stack;
    return success;
}

static bool setup_resume_thread_stack(injector_t injector, drakvuf_trap_info_t* info)
{
    struct argument args[1] = { {0} };
    init_int_argument(&args[0], injector->hThr);

    return setup_stack(injector->drakvuf, info, args, ARRAY_SIZE(args));
}

static bool setup_shell_execute_stack(injector_t injector, drakvuf_trap_info_t* info)
{
    struct argument args[6] = { {0} };

    // ShellExecute(NULL, NULL, &FilePath, NULL, NULL, SW_SHOWNORMAL)
    init_int_argument(&args[0], 0);
    init_unicode_argument(&args[1], NULL);
    init_unicode_argument(&args[2], injector->target_file_us);
    init_unicode_argument(&args[3], NULL);
    init_unicode_argument(&args[4], injector->cwd_us);
    init_int_argument(&args[5], SW_SHOWNORMAL);

    return setup_stack(injector->drakvuf, info, args, ARRAY_SIZE(args));
}

static bool setup_virtual_alloc_stack(injector_t injector, drakvuf_trap_info_t* info)
{
    struct argument args[4] = { {0} };

    // VirtualAlloc(NULL, size, allocation_type, protect);
    init_int_argument(&args[0], 0);
    // Allocate enough space for the shellcode and the binary at once
    init_int_argument(&args[1], injector->payload_size + injector->binary_size);
    init_int_argument(&args[2], MEM_COMMIT | MEM_RESERVE);
    init_int_argument(&args[3], PAGE_EXECUTE_READWRITE);

    return setup_stack(injector->drakvuf, info, args, ARRAY_SIZE(args));
}

static bool setup_memset_stack(injector_t injector, drakvuf_trap_info_t* info)
{
    struct argument args[4] = { {0} };

    // memset(payload_addr, c, payload_size);
    init_int_argument(&args[0], injector->payload_addr);
    init_int_argument(&args[1], 0);
    init_int_argument(&args[2], injector->payload_size + injector->binary_size);
    init_int_argument(&args[3], 0);

    return setup_stack(injector->drakvuf, info, args, ARRAY_SIZE(args));
}

static bool injector_set_hijacked(injector_t injector, drakvuf_trap_info_t* info)
{
    if (!injector->target_tid)
    {
        uint32_t threadid = 0;
        if (!drakvuf_get_current_thread_id(injector->drakvuf, info->vcpu, &threadid) || !threadid)
            return false;

        injector->target_tid = threadid;
    }

    injector->hijacked = true;

    return true;
}

static void fill_created_process_info(injector_t injector, drakvuf_trap_info_t* info)
{
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = injector->process_info,
    };

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

static bool setup_int3_trap(injector_t injector, drakvuf_trap_info_t* info, addr_t bp_addr)
{
    injector->bp.type = BREAKPOINT;
    injector->bp.name = "entry";
    injector->bp.cb = injector_int3_cb;
    injector->bp.data = injector;
    injector->bp.breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp.breakpoint.dtb = info->regs->cr3;
    injector->bp.breakpoint.addr_type = ADDR_VA;
    injector->bp.breakpoint.addr = bp_addr;

    return drakvuf_add_trap(injector->drakvuf, &injector->bp);
}

static event_response_t mem_callback(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    (void)drakvuf;
    injector_t injector = info->trap->data;

    if ( info->proc_data.pid != injector->target_pid )
    {
        PRINT_DEBUG("MemX received but PID (%u) doesn't match target process (%u)\n",
                    info->proc_data.pid, injector->target_pid);
        return 0;
    }

    PRINT_DEBUG("MemX at 0x%lx\n", info->regs->rip);

    /* We might have already hijacked a thread on another vCPU */
    if (injector->hijacked)
        return 0;

    free_memtraps(injector);

    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

    bool success = false;
    if (injector->method == INJECT_METHOD_CREATEPROC)
    {
        success = setup_create_process_stack(injector, info);
        injector->target_rsp = info->regs->rsp;
    }
    else if (injector->method == INJECT_METHOD_SHELLEXEC)
        success = setup_shell_execute_stack(injector, info);

    if (!success)
    {
        PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
        return 0;
    }

    if (!setup_int3_trap(injector, info, info->regs->rip))
    {
        fprintf(stderr, "Failed to trap return location of injected function call @ 0x%lx!\n",
                info->regs->rip);
        return 0;
    }

    if (!injector_set_hijacked(injector, info))
        return 0;

    PRINT_DEBUG("Stack setup finished and return trap added @ 0x%" PRIx64 "\n",
                info->regs->rip);

    info->regs->rip = injector->exec_func;
    injector->status = STATUS_CREATE_OK;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t wait_for_crash_of_target_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    vmi_pid_t crashed_pid = 0;
    if (drakvuf_is_crashreporter(drakvuf, info, &crashed_pid) && crashed_pid == injector->target_pid)
    {
        injector->rc = 0;
        injector->detected = false;
        PRINT_DEBUG("Target process crash detected\n");

        drakvuf_interrupt(drakvuf, SIGDRAKVUFCRASH);
    }

    return 0;
}

static event_response_t wait_for_target_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 ". PID: %u PPID: %u\n",
                info->regs->cr3, info->proc_data.pid, info->proc_data.ppid);

    if (info->proc_data.pid != injector->target_pid)
        return 0;

    addr_t thread = drakvuf_get_current_thread(drakvuf, info->vcpu);
    if (!thread)
    {
        PRINT_DEBUG("Failed to find current thread\n");
        return 0;
    }

    uint32_t threadid = 0;
    if ( !drakvuf_get_current_thread_id(injector->drakvuf, info->vcpu, &threadid) || !threadid )
        return 0;

    PRINT_DEBUG("Thread @ 0x%lx. ThreadID: %u\n", thread, threadid);

    if (injector->target_tid && injector->target_tid != threadid)
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
                drakvuf_trap_t* new_trap = g_malloc0(sizeof(drakvuf_trap_t));
                new_trap->type = MEMACCESS;
                new_trap->cb = mem_callback;
                new_trap->data = injector;
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

static event_response_t wait_for_injected_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    if (injector->pid != (uint32_t)info->proc_data.pid)
        return 0;

    PRINT_DEBUG("Process start detected %i -> 0x%lx\n", injector->pid, info->regs->cr3);
    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);

    injector->rc = 1;
    injector->detected = true;

    if ( injector->break_loop_on_detection )
        drakvuf_interrupt(drakvuf, SIGINT);
    else if ( injector->resumed )
        drakvuf_interrupt(drakvuf, SIGINT);

    return 0;
}

// Setup callback for waiting for first occurence of resumed thread
static bool setup_wait_for_injected_process_trap(injector_t injector)
{
    drakvuf_trap_t* trap = g_malloc0(sizeof(drakvuf_trap_t));
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

static event_response_t inject_payload(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
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

        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = injector->binary_addr,
        };

        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        bool success = ( VMI_SUCCESS == vmi_write(vmi, &ctx, injector->binary_size, (void*)injector->binary, NULL) );
        drakvuf_release_vmi(drakvuf);

        if (!success)
        {
            PRINT_DEBUG("Failed to write the binary into memory!\n");
            return 0;
        }

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
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = injector->payload_addr,
    };
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool success = ( VMI_SUCCESS == vmi_write(vmi, &ctx, injector->payload_size, (void*)injector->payload, NULL) );
    drakvuf_release_vmi(drakvuf);

    if ( !success )
    {
        PRINT_DEBUG("Failed to write the payload into memory!\n");
        return 0;
    }

    if (!setup_stack(injector->drakvuf, info, NULL, 4))
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
        if (!injector_set_hijacked(injector, info))
            return 0;
        injector->status = STATUS_EXEC_OK;
    }

    PRINT_DEBUG("Executing the payload..\n");

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}




static event_response_t injector_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx.\n", info->regs->rip, info->regs->cr3);

    if ( info->proc_data.pid != injector->target_pid )
    {
        PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
                    info->proc_data.name, info->proc_data.pid, injector->target_pid);
        return 0;
    }

    if (info->regs->rip != info->trap->breakpoint.addr)
        return 0;

    if (injector->target_tid)
    {
        uint32_t threadid = 0;
        if (!drakvuf_get_current_thread_id(drakvuf, info->vcpu, &threadid) || threadid != injector->target_tid)
            return 0;
    }

    if (injector->target_rsp && info->regs->rsp <= injector->target_rsp)
    {
        PRINT_DEBUG("INT3 received but RSP (0x%lx) doesn't match target rsp (0x%lx)\n",
                    info->regs->rsp, injector->target_rsp);
        return 0;
    }

    if (injector->is32bit && injector->status == STATUS_CREATE_OK)
    {
        PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);

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
                injector->rc = 1;
            }

            memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }

        if (INJECT_METHOD_CREATEPROC == injector->method)
        {
            // We are now in the return path from CreateProcessW called from mem_callback

            if (info->regs->rax)
                fill_created_process_info(injector, info);
            else
            {
                injector->error_code.valid = true;
                drakvuf_get_last_error(injector->drakvuf, info->vcpu, &injector->error_code.code, &injector->error_code.string);
            }

            injector->rc = info->regs->rax;
            memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

            if (injector->pid && injector->tid)
            {
                PRINT_DEBUG("Injected PID: %i. TID: %i\n", injector->pid, injector->tid);

                if (!setup_resume_thread_stack(injector, info))
                {
                    PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
                    return 0;
                }

                injector->target_rsp = info->regs->rsp;

                if (!setup_wait_for_injected_process_trap(injector))
                    return 0;

                info->regs->rip = injector->resume_thread;
                injector->status = STATUS_RESUME_OK;

                return VMI_EVENT_RESPONSE_SET_REGISTERS;
            }
            else
            {
                PRINT_DEBUG("Failed to inject\n");
                injector->rc = 0;

                drakvuf_remove_trap(drakvuf, info->trap, NULL);
                drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);

                return VMI_EVENT_RESPONSE_SET_REGISTERS;
            }
        }

        return 0;
    }

    if (injector->status == STATUS_RESUME_OK)
    {
        PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);

        // We are now in the return path from ResumeThread

        drakvuf_remove_trap(drakvuf, info->trap, NULL);

        injector->rc = info->regs->rax;
        memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

        if (injector->rc == 1)
        {
            PRINT_DEBUG("Resumed\n");
        }
        else
        {
            PRINT_DEBUG("Failed to resume\n");
            injector->rc = 0;

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

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    if (!injector->is32bit && !injector->hijacked && injector->status == STATUS_NULL)
    {
        /* We just hit the RIP from the trapframe */

        memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

        bool success = false;
        switch (injector->method)
        {
            case INJECT_METHOD_CREATEPROC:
                success = setup_create_process_stack(injector, info);
                injector->target_rsp = info->regs->rsp;
                break;
            case INJECT_METHOD_SHELLEXEC:
                success = setup_shell_execute_stack(injector, info);
                break;
            case INJECT_METHOD_SHELLCODE:
            case INJECT_METHOD_DOPP:
                success = setup_virtual_alloc_stack(injector, info);
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

        if (INJECT_METHOD_SHELLCODE == injector->method || INJECT_METHOD_DOPP == injector->method)
        {
            injector->status = STATUS_ALLOC_OK;
        }
        else
        {
            if (!injector_set_hijacked(injector, info))
                return 0;
            injector->status = STATUS_CREATE_OK;
        }

        info->regs->rip = injector->exec_func;

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    // Chain the injection with a second function
    if ( !injector->is32bit && STATUS_ALLOC_OK == injector->status)
    {
        PRINT_DEBUG("Writing to allocated virtual memory to allocate physical memory..\n");

        injector->payload_addr = info->regs->rax;

        if (!setup_memset_stack(injector, info))
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
    if ( !injector->is32bit && STATUS_PHYS_ALLOC_OK == injector->status)
    {
        return inject_payload(drakvuf, info);
    }

    // Handle breakpoint on PspCallProcessNotifyRoutines()
    if ( !injector->is32bit && STATUS_BP_HIT == injector->status)
    {
        addr_t saved_rip = 0;

        // Get saved RIP from the stack
        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = info->regs->rsp,
        };
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

        if (!injector_set_hijacked(injector, info))
            return 0;

        // Restore original value of the breakpoint
        injector->bp.breakpoint.addr = injector->saved_bp;

        injector->status = STATUS_EXEC_OK;

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    if (!injector->hijacked)
        return 0;

    PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);

    if (INJECT_METHOD_CREATEPROC == injector->method && injector->status == STATUS_CREATE_OK)
    {
        // We are now in the return path from CreateProcessW

        if (info->regs->rax)
            fill_created_process_info(injector, info);
        else
        {
            injector->error_code.valid = true;
            drakvuf_get_last_error(injector->drakvuf, info->vcpu, &injector->error_code.code, &injector->error_code.string);
        }

        injector->rc = info->regs->rax;
        memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

        if (injector->pid && injector->tid)
        {
            PRINT_DEBUG("Injected PID: %i. TID: %i\n", injector->pid, injector->tid);

            if (!setup_resume_thread_stack(injector, info))
            {
                PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
                return 0;
            }

            injector->target_rsp = info->regs->rsp;

            if (!setup_wait_for_injected_process_trap(injector))
                return 0;

            info->regs->rip = injector->resume_thread;
            injector->status = STATUS_RESUME_OK;

            return VMI_EVENT_RESPONSE_SET_REGISTERS;
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

    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
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
        PRINT_DEBUG("Starting injection loop\n");
        drakvuf_loop(drakvuf);
    }

    free_memtraps(injector);

    drakvuf_remove_trap(drakvuf, &trap, NULL);
    drakvuf_remove_trap(drakvuf, &trap_crashreporter, NULL);

    return true;
}

static bool load_file_to_memory(addr_t* output, size_t* size, const char* file)
{
    size_t payload_size = 0;
    unsigned char* data = NULL;
    FILE* fp = fopen(file, "rb");

    if (!fp)
        return false;

    // obtain file size:
    fseek (fp, 0, SEEK_END);
    payload_size = ftell (fp);
    rewind (fp);

    data = g_malloc0(payload_size);
    if ( !data )
    {
        fclose(fp);
        return false;
    }

    if ( payload_size != fread(data, payload_size, 1, fp) )
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

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:PrematureBreak\n", UNPACK_TIMEVAL(t));
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

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:Error ERROR_CODE:%d ERROR:\"%s\"\n",
                           UNPACK_TIMEVAL(t), injector->error_code.code, injector->error_code.string);
                    break;
            }
            break;
    }

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
        access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_PID, };
        addr_t module_list_head;
        if (VMI_SUCCESS == drakvuf_get_process_pid(drakvuf, eprocess_base, &ctx.pid) &&
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

    // Get the offsets from the Rekall profile
    if ( !drakvuf_get_struct_members_array_rva(drakvuf, offset_names, OFFSET_MAX, injector->offsets) )
        PRINT_DEBUG("Failed to find one of offsets.\n");

    if (INJECT_METHOD_CREATEPROC == injector->method)
    {
        injector->resume_thread = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "ResumeThread", injector->global_search);
        if (!injector->resume_thread) return false;
        injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "CreateProcessW", injector->global_search);
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
            // Check for Windows 10 version 1803 or higher
            int build_1803 = 20180410;
            if ( drakvuf_get_os_build_date(drakvuf) < build_1803 )
            {
                PRINT_DEBUG("This injection method requires Windows 10 version 1803 or higher!\n");
                return false;
            }

            // Read binary to inject from a file
            if ( !load_file_to_memory(&injector->binary, &injector->binary_size, binary_path) )
                return false;
        }

        injector->memset = get_function_va(drakvuf, eprocess_base, "ntdll.dll", "memset", injector->global_search);
        if (!injector->memset) return false;
        injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "VirtualAlloc", injector->global_search);
    }

    return injector->exec_func != 0;
}

static event_response_t hijack_wait_for_kernel_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info)
{
    
    addr_t msg_box_addr;
    addr_t eprocess_base;
    injector_t injector = info->trap->data;

    if ( info->proc_data.pid != injector->target_pid )
    {
        PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
                    info->proc_data.name, info->proc_data.pid, injector->target_pid);
        return 0;
    }

    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);

    if ( !drakvuf_find_process(drakvuf, injector->target_pid, NULL, &eprocess_base) ){
        PRINT_DEBUG("[+] Find process failed");
        return false;
    }

    msg_box_addr = get_function_va(drakvuf, eprocess_base, "user32.dll", "MessageBox", true);
    if (!msg_box_addr){
        PRINT_DEBUG("msg_box_addr not found");
        return false;
    }

    PRINT_DEBUG(" [+] In kernel by hijack cb... \
        \n[+] Setting up stack\n");
    if (!setup_message_box_stack(injector, info))
        PRINT_DEBUG("[+] Hijacking: Stack setup failed\n");

    info->regs->rip = msg_box_addr;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
    

    
}

bool injector_hijack(
    drakvuf_t drakvuf,
    vmi_pid_t target_pid,
    char *function_name
)
{
    PRINT_DEBUG("[+] Target PID %u to jump to function %s", target_pid, function_name );

    injector_t injector = (injector_t)g_malloc0(sizeof(struct injector));
    if (!injector)
    {
        PRINT_DEBUG("[+] Injector g_malloc failed");
        return false;
    }

    injector->drakvuf = drakvuf;
    injector->target_pid = target_pid;
    // injector->target_tid = tid;
    // injector->target_file_us = target_file_us;
    // injector->cwd_us = cwd_us;
    injector->method = INJECT_METHOD_CREATEPROC;
    injector->global_search = true;
    // injector->binary_path = binary_path;
    // injector->target_process = target_process;
    injector->status = STATUS_NULL;
    injector->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    // injector->break_loop_on_detection = break_loop_on_detection;
    injector->error_code.valid = false;
    injector->error_code.code = -1;
    injector->error_code.string = "<UNKNOWN>";

    if (!initialize_injector_functions(drakvuf, injector, NULL, NULL))
    {
        PRINT_DEBUG("Unable to initialize injector functions\n");
        free_injector(injector);
        return 0;
    }
    drakvuf_trap_t trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = hijack_wait_for_kernel_cb,
        .data = injector,
    };

     if (!drakvuf_add_trap(drakvuf, &trap))
        return false;

    return true;

}

int injector_start_app(
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
    bool global_search)
{
    int rc = 0;
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

    injector_t injector = (injector_t)g_malloc0(sizeof(struct injector));
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
        free_injector(injector);
        return 0;
    }

    if (inject(drakvuf, injector) && injector->rc)
    {
        injector->result = INJECT_RESULT_SUCCESS;
        print_injection_info(format, file, injector);
    }
    else
    {
        if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        {
            injector->result = INJECT_RESULT_TIMEOUT;
            print_injection_info(format, file, injector);
        }
        else if (SIGDRAKVUFCRASH == drakvuf_is_interrupted(drakvuf))
        {
            injector->result = INJECT_RESULT_CRASH;
            print_injection_info(format, file, injector);
        }
        else if (injector->error_code.valid)
        {
            injector->result = INJECT_RESULT_ERROR_CODE;
            print_injection_info(format, file, injector);
        }
        else
        {
            injector->result = INJECT_RESULT_PREMATURE;
            print_injection_info(format, file, injector);
        }
    }

    rc = injector->rc;
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
