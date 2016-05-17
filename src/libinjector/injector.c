 /*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014-2016 Tamas K Lengyel.  *
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <inttypes.h>
#include <glib.h>

#include "libdrakvuf/libdrakvuf.h"
#include "private.h"

static uint8_t trap = 0xCC;

struct injector {
    // Inputs:
    const char *target_proc;
    reg_t target_cr3;
    vmi_pid_t target_pid;

    // Internal:
    drakvuf_t drakvuf;
    vmi_instance_t vmi;
    const char *rekall_profile;
    bool is32bit, hijacked;
    addr_t createprocessa, psexit_rva;

    addr_t process_info;
    addr_t saved_rsp;
    addr_t saved_rax;
    addr_t saved_rcx;
    addr_t saved_rdx;
    addr_t saved_r8;
    addr_t saved_r9;

    drakvuf_trap_t entry, ret, cr3_event;
    GSList *memtraps;
    GTimer *timer;

    size_t offsets[OFFSET_MAX];

    // Results:
    reg_t cr3;
    int rc;
    uint32_t pid, tid;
    uint32_t hProc, hThr;
};

#define SW_SHOWDEFAULT 10

struct startup_info_32 {
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

struct startup_info_64 {
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

struct process_information_32 {
    uint32_t hProcess;
    uint32_t hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
} __attribute__ ((packed));

struct process_information_64 {
    addr_t hProcess;
    addr_t hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
} __attribute__ ((packed));

struct list_entry_32 {
    uint32_t flink;
    uint32_t blink;
} __attribute__ ((packed));

struct list_entry_64 {
    uint64_t flink;
    uint64_t blink;
} __attribute__ ((packed));

struct kapc_state_32 {
    // apc_list_head[0] = kernel apc list
    // apc_list_head[1] = user apc list
    struct list_entry_32 apc_list_head[2];
    uint32_t process;
    uint8_t kernel_apc_in_progress;
    uint8_t kernel_apc_pending;
    uint8_t user_apc_pending;
} __attribute__ ((packed));

struct kapc_state_64 {
    // apc_list_head[0] = kernel apc list
    // apc_list_head[1] = user apc list
    struct list_entry_64 apc_list_head[2];
    uint64_t process;
    uint8_t kernel_apc_in_progress;
    uint8_t kernel_apc_pending;
    uint8_t user_apc_pending;
};

struct kapc_32 {
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

struct kapc_64 {
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

void pass_inputs(struct injector *injector, drakvuf_trap_info_t *info) {

    vmi_instance_t vmi = injector->vmi;
    status_t status;
    reg_t fsgs, rsp = info->regs->rsp;
    addr_t stack_base, stack_limit;

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    if (injector->is32bit)
        fsgs = info->regs->fs_base;
    else
        fsgs = info->regs->gs_base;

    ctx.addr = fsgs + injector->offsets[NT_TIB_STACKBASE];
    vmi_read_addr(vmi, &ctx, &stack_base);
    ctx.addr = fsgs + injector->offsets[NT_TIB_STACKLIMIT];
    vmi_read_addr(vmi, &ctx, &stack_limit);

    //Push input arguments on the stack
    //CreateProcess(NULL, TARGETPROC, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si, pi))

    uint64_t nul64 = 0;
    uint32_t nul32 = 0;
    uint8_t nul8 = 0;
    size_t len = strlen(injector->target_proc);
    addr_t addr = rsp;

    addr_t str_addr, sip_addr;

    if (injector->is32bit) {

        addr -= 0x4; // the stack has to be alligned to 0x4
                     // and we need a bit of extra buffer before the string for \0
        // we just going to null out that extra space fully
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, &nul32);

        // this string has to be aligned as well!
        addr -= len + 0x4 - (len % 0x4);
        str_addr = addr;
        ctx.addr = addr;
        vmi_write(vmi, &ctx, (void*) injector->target_proc, len);
        // add null termination
        ctx.addr = addr + len;
        vmi_write_8(vmi, &ctx, &nul8);

        //struct startup_info_32 si = {.wShowWindow = SW_SHOWDEFAULT };
        struct startup_info_32 si;
        memset(&si, 0, sizeof(struct startup_info_32));
        struct process_information_32 pi;
        memset(&pi, 0, sizeof(struct process_information_32));

        addr -= sizeof(struct process_information_32);
        injector->process_info = addr;

        ctx.addr = addr;
        vmi_write(vmi, &ctx, &pi,
                sizeof(struct process_information_32));

        addr -= sizeof(struct startup_info_32);
        sip_addr = addr;
        ctx.addr = addr;
        vmi_write(vmi, &ctx, &si, sizeof(struct startup_info_32));

        //p10
        addr -= 0x4;
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, (uint32_t *) &injector->process_info);
        //p9
        addr -= 0x4;
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, (uint32_t *) &sip_addr);
        //p8
        addr -= 0x4;
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, &nul32);
        //p7
        addr -= 0x4;
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, &nul32);
        //p6
        addr -= 0x4;
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, &nul32);
        //p5
        addr -= 0x4;
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, &nul32);
        //p4
        addr -= 0x4;
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, &nul32);
        //p3
        addr -= 0x4;
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, &nul32);
        //p2
        addr -= 0x4;
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, (uint32_t *) &str_addr);
        //p1
        addr -= 0x4;
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, &nul32);

        // save the return address
        addr -= 0x4;
        ctx.addr = addr;
        vmi_write_32(vmi, &ctx, (uint32_t *) &info->regs->rip);

    } else {

        addr -= 0x8; // the stack has to be alligned to 0x8
                     // and we need a bit of extra buffer before the string for \0

        // we just going to null out that extra space fully
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &nul64);

        // this string has to be aligned as well!
        addr -= len + 0x8 - (len % 0x8);
        str_addr = addr;
        ctx.addr = addr;
        vmi_write(vmi, &ctx, (void*) injector->target_proc, len);
        // add null termination
        ctx.addr = addr+len;
        vmi_write_8(vmi, &ctx, &nul8);

        struct startup_info_64 si;
        memset(&si, 0, sizeof(struct startup_info_64));
        struct process_information_64 pi;
        memset(&pi, 0, sizeof(struct process_information_64));

        addr -= sizeof(struct process_information_64);
        injector->process_info = addr;
        ctx.addr = addr;
        vmi_write(vmi, &ctx, &pi,
                sizeof(struct process_information_64));

        addr -= sizeof(struct startup_info_64);
        sip_addr = addr;
        ctx.addr = addr;
        vmi_write(vmi, &ctx, &si, sizeof(struct startup_info_64));

        //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
        //
        //First 4 parameters to functions are always passed in registers
        //P1=rcx, P2=rdx, P3=r8, P4=r9
        //5th parameter onwards (if any) passed via the stack

        //p10
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &injector->process_info);
        //p9
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &sip_addr);
        //p8
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &nul64);
        //p7
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &nul64);
        //p6
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &nul64);
        //p5
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &nul64);

        // allocate 0x20 "homing space"
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &nul64);
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &nul64);
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &nul64);
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &nul64);

        //p1
        vmi_set_vcpureg(vmi, 0, RCX, info->vcpu);
        //p2
        vmi_set_vcpureg(vmi, str_addr, RDX, info->vcpu);
        //p3
        vmi_set_vcpureg(vmi, 0, R8, info->vcpu);
        //p4
        vmi_set_vcpureg(vmi, 0, R9, info->vcpu);

        // save the return address
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &info->regs->rip);
    }

    // Grow the stack
    vmi_set_vcpureg(vmi, addr, RSP, info->vcpu);

    injector->ret.type = BREAKPOINT;
    injector->ret.name = "ret";
    injector->ret.cb = injector_int3_cb;
    injector->ret.data = injector;
    injector->ret.breakpoint.lookup_type = LOOKUP_DTB;
    injector->ret.breakpoint.dtb = info->regs->cr3;
    injector->ret.breakpoint.addr_type = ADDR_VA;
    injector->ret.breakpoint.addr = info->regs->rip;

    if ( !drakvuf_add_trap(injector->drakvuf, &injector->ret) )
        fprintf(stderr, "Failed to trap return location of injected function call @ 0x%lx!\n",
                injector->ret.breakpoint.addr);
}

event_response_t mem_callback(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    struct injector *injector = info->trap->data;

    if ( info->regs->cr3 != injector->target_cr3 ) {
        PRINT_DEBUG("MemX received but CR3 (0x%lx) doesn't match target process (0x%lx)\n",
                    info->regs->cr3, injector->target_cr3);
        return 0;
    }

    PRINT_DEBUG("MemX at 0x%lx\n", info->regs->rip);

    /* We might have already hijacked a thread on another vCPU */
    if(injector->hijacked)
        return 0;

    GSList* loop = injector->memtraps;
    while(loop) {
        drakvuf_remove_trap(injector->drakvuf, loop->data, free);
        loop=loop->next;
    }
    g_slist_free(injector->memtraps);
    injector->memtraps = NULL;

    injector->saved_rsp = info->regs->rsp;
    injector->saved_rax = info->regs->rax;
    injector->saved_rcx = info->regs->rcx;
    injector->saved_rdx = info->regs->rdx;
    injector->saved_r8 = info->regs->r8;
    injector->saved_r9 = info->regs->r9;

    vmi_set_vcpureg(injector->vmi, injector->createprocessa, RIP, info->vcpu);
    pass_inputs(injector, info);

    PRINT_DEBUG("Stack setup finished and return trap added @ 0x%" PRIx64 "\n", injector->ret.breakpoint.addr);

    injector->hijacked = 1;

    return 0;
}

event_response_t cr3_callback(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {

    struct injector *injector = info->trap->data;
    addr_t thread = 0, kpcrb_offset = 0, tid = 0, stack_base = 0, stack_limit = 0;
    uint8_t apcqueueable;
    reg_t fsgs = 0, cr3 = info->regs->cr3;
    status_t status;

    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 "\n", info->regs->cr3);

    if (cr3 != injector->target_cr3)
        return 0;

    thread = drakvuf_get_current_thread(drakvuf, info->vcpu, info->regs);
    if (!thread) {
        PRINT_DEBUG("cr3_cb: Failed to find current thread\n");
        return 0;
    }

    uint32_t threadid = 0;
    if ( !drakvuf_get_current_thread_id(injector->drakvuf, info->vcpu, info->regs, &threadid) || !threadid )
        return 0;

    PRINT_DEBUG("Thread @ 0x%lx. ThreadID: %u\n", thread, threadid);

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
     if (!injector->is32bit) {

        access_context_t ctx = {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = cr3,
        };

        addr_t trapframe = 0;
        status = vmi_read_addr_va(injector->vmi,
                        thread + injector->offsets[KTHREAD_TRAPFRAME],
                        0, &trapframe);

        if (status == VMI_FAILURE || !trapframe) {
            PRINT_DEBUG("cr3_cb: failed to read trapframe (0x%lx)\n", trapframe);
            return 0;
        }

        status = vmi_read_addr_va(injector->vmi,
                        trapframe + injector->offsets[KTRAP_FRAME_RIP],
                        0, &injector->entry.breakpoint.addr);

        if (status == VMI_FAILURE || !injector->entry.breakpoint.addr) {
            PRINT_DEBUG("Failed to read RIP from trapframe or RIP is NULL!\n");
            return 0;
        }

        injector->entry.type = BREAKPOINT;
        injector->entry.name = "entry";
        injector->entry.cb = injector_int3_cb;
        injector->entry.data = injector;
        injector->entry.breakpoint.lookup_type = LOOKUP_DTB;
        injector->entry.breakpoint.dtb = cr3;
        injector->entry.breakpoint.addr_type = ADDR_VA;

        if ( drakvuf_add_trap(drakvuf, &injector->entry) ) {
            PRINT_DEBUG("Got return address 0x%lx from trapframe and it's now trapped!\n",
                        injector->entry.breakpoint.addr);

            // Unsubscribe from the CR3 trap
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
        } else
            fprintf(stderr, "Failed to trap trapframe return address\n");
    } else {
        GSList *va_pages = vmi_get_va_pages(injector->vmi, info->regs->cr3);
        GSList *loop = va_pages;
        while(loop) {
            page_info_t *page = loop->data;
            if(page->vaddr < 0x80000000) {
                vmi_event_t *new_event = vmi_get_mem_event(injector->vmi, page->paddr);
                if(!new_event) {
                    drakvuf_trap_t *new_trap = g_malloc0(sizeof(drakvuf_trap_t));
                    new_trap->type = MEMACCESS;
                    new_trap->cb = mem_callback;
                    new_trap->data = injector;
                    new_trap->memaccess.access = VMI_MEMACCESS_X;
                    new_trap->memaccess.type = POST;
                    new_trap->memaccess.gfn = page->paddr >> 12;
                    injector->memtraps = g_slist_prepend(injector->memtraps, new_trap);
                    drakvuf_add_trap(injector->drakvuf, new_trap);
                }
            }
            free(page);
            loop = loop->next;
        }
        g_slist_free(va_pages);
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
    }

    return 0;
}

event_response_t injector_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info) {
    struct injector *injector = info->trap->data;
    addr_t pa = info->trap_pa;
    reg_t cr3 = info->regs->cr3;

    vmi_pid_t pid = vmi_dtb_to_pid(injector->vmi, cr3);

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3,
    };

    PRINT_DEBUG("INT3 Callback @ 0x%lx. PID %u. CR3 0x%lx.\n",
                info->regs->rip, pid, cr3);

    if ( cr3 != injector->target_cr3 ) {
        PRINT_DEBUG("INT3 received but CR3 (0x%lx) doesn't match target process (0x%lx)\n",
                    cr3, injector->target_cr3);
        return 0;
    }

    if ( !injector->is32bit && info->regs->rip == injector->entry.breakpoint.addr ) {
        /* We just hit the RIP from the trapframe */

        injector->saved_rsp = info->regs->rsp;
        injector->saved_rax = info->regs->rax;
        injector->saved_rcx = info->regs->rcx;
        injector->saved_rdx = info->regs->rdx;
        injector->saved_r8 = info->regs->r8;
        injector->saved_r9 = info->regs->r9;

        drakvuf_remove_trap(drakvuf, &injector->entry, NULL);
        injector->entry.breakpoint.addr = 0;

        vmi_set_vcpureg(injector->vmi, injector->createprocessa, RIP, info->vcpu);
        pass_inputs(injector, info);

        PRINT_DEBUG("Stack setup finished and return trap added @ 0x%" PRIx64 "\n", injector->ret.breakpoint.addr);

        return 0;
    }

    if ( info->regs->rip != injector->ret.breakpoint.addr )
        return 0;

    // We are now in the return path from CreateProcessA

    drakvuf_interrupt(drakvuf, -1);
    drakvuf_remove_trap(drakvuf, &injector->ret, NULL);

    reg_t rax = info->regs->rax;

    vmi_set_vcpureg(injector->vmi, injector->saved_rsp, RSP, info->vcpu);
    vmi_set_vcpureg(injector->vmi, injector->saved_rax, RAX, info->vcpu);
    vmi_set_vcpureg(injector->vmi, injector->saved_rcx, RCX, info->vcpu);
    vmi_set_vcpureg(injector->vmi, injector->saved_rdx, RDX, info->vcpu);
    vmi_set_vcpureg(injector->vmi, injector->saved_r8, R8, info->vcpu);
    vmi_set_vcpureg(injector->vmi, injector->saved_r9, R9, info->vcpu);

    PRINT_DEBUG("RAX: 0x%lx\n", rax);

    if (rax) {
        ctx.addr = injector->process_info;

        if (injector->is32bit) {
            struct process_information_32 pip = { 0 };
            vmi_read(injector->vmi, &ctx, &pip,
                     sizeof(struct process_information_32));

            injector->pid = pip.dwProcessId;
            injector->tid = pip.dwThreadId;
            injector->hProc = pip.hProcess;
            injector->hThr = pip.hThread;

        } else {
            struct process_information_64 pip = { 0 };
            vmi_read(injector->vmi, &ctx, &pip,
                     sizeof(struct process_information_64));

            injector->pid = pip.dwProcessId;
            injector->tid = pip.dwThreadId;
            injector->hProc = pip.hProcess;
            injector->hThr = pip.hThread;
        }

        PRINT_DEBUG("Injected PID: %i. TID: %i\n", injector->pid, injector->tid);

        /*
         * Sometimes injection seem to return 1 in RAX but
         * the host process actually crashed. While investigating
         * the root cause just return 0 for PID >= 5000.
         */
        if (injector->pid < 5000 && injector->tid) {
            injector->rc = rax;
            /*injector->cr3 = vmi_pid_to_dtb(vmi, injector->pid);
            injector->cr3_event.callback = waitfor_cr3_callback;
            injector->cr3_event.reg_event.equal = injector->cr3;
            injector->cr3_event.data = injector;
            vmi_register_event(vmi, &injector->cr3_event);*/
        } else {
            injector->rc = 0;
        }
    }

    return 0;
}

int injector_start_app(drakvuf_t drakvuf, vmi_pid_t pid, const char *app) {

    struct injector injector = {
        .drakvuf = drakvuf,
        .vmi = drakvuf_lock_and_get_vmi(drakvuf),
        .rekall_profile = drakvuf_get_rekall_profile(drakvuf),
        .target_pid = pid,
        .target_proc = app,
        .rc = 0
    };

    injector.is32bit = (vmi_get_page_mode(injector.vmi) == VMI_PM_IA32E) ? 0 : 1,
    injector.target_cr3 = vmi_pid_to_dtb(injector.vmi, pid);
    if (!injector.target_cr3)
    {
        PRINT_DEBUG("Unable to find target PID's DTB\n");
        goto done;
    }

    // Get the offsets from the Rekall profile
    unsigned int i;
    for (i = 0; i < OFFSET_MAX; i++) {
        if (VMI_FAILURE
                == drakvuf_get_struct_member_rva(
                        injector.rekall_profile, offset_names[i][0],
                        offset_names[i][1], &injector.offsets[i])) {
            PRINT_DEBUG("Failed to find offset for %s:%s\n", offset_names[i][0],
                    offset_names[i][1]);
        }
    }

    if (VMI_FAILURE == drakvuf_get_function_rva(injector.rekall_profile,
                                                "PsGetCurrentProcess",
                                                //"PsExitSpecialApc",
                                                &injector.psexit_rva))
    {
        PRINT_DEBUG("Failed to get address of ntoskrnl.exe!PsExitSpecialApc\n");
        goto done;
    }

    PRINT_DEBUG("Target PID %u with DTB 0x%lx to start '%s'\n", pid,
                injector.target_cr3, app);

    addr_t eprocess_base = 0;
    if ( !drakvuf_find_eprocess(injector.drakvuf, pid, NULL, &eprocess_base) )
        goto done;

    injector.createprocessa = drakvuf_exportsym_to_va(injector.drakvuf, eprocess_base, "kernel32.dll", "CreateProcessA");
    if (!injector.createprocessa) {
        PRINT_DEBUG("Failed to get address of kernel32.dll!CreateProcessA\n");
        return 0;
    }


        injector.cr3_event.type = REGISTER;
        injector.cr3_event.reg = CR3;
        injector.cr3_event.cb = cr3_callback;
        injector.cr3_event.data = &injector;
        drakvuf_add_trap(drakvuf, &injector.cr3_event);


    PRINT_DEBUG("Starting injection loop\n");
    drakvuf_resume(drakvuf);
    drakvuf_loop(drakvuf);

    if(injector.is32bit) {
        GSList *loop = injector.memtraps;
        while(loop) {
            drakvuf_remove_trap(drakvuf, loop->data, free);
            loop=loop->next;
        }
        g_slist_free(loop);
    }

    drakvuf_remove_trap(drakvuf, &injector.cr3_event, NULL);

done:
    PRINT_DEBUG("Finished with injection. Ret: %i\n", injector.rc);
    drakvuf_release_vmi(drakvuf);
    return injector.rc;
}
