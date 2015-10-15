 /*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014 Tamas K Lengyel.       *
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <inttypes.h>
#include <glib.h>

#include "injector.h"
#include "vmi.h"
#include "win-exports.h"
#include "win-handles.h"

#define KERNEL32 0x80000000UL
#define KERNEL64 0xFFFFF80000000000ULL
#define CREATE_SUSPENDED 0x4ULL

struct injector {
    const char *target_proc;
    reg_t target_cr3;
    vmi_pid_t target_pid;

    drakvuf_t *drakvuf;
    win_ver_t winver;
    page_mode_t pm;

    uint8_t ret;
    reg_t cr3;
    uint32_t pid, tid;
    uint32_t hProc, hThr;
    addr_t userspace_return;
    uint8_t userspace_return_backup;

    void *stack_backup;
    size_t stack_backup_size;
    addr_t stack_limit;

    vmi_event_t cr3_event;
    vmi_event_t mm_event;
    vmi_event_t ss_event;
    int mm_enabled;
    int ss_enabled;
    addr_t target_rip;
    addr_t process_info;
    addr_t saved_rsp;
    addr_t saved_rip;
    addr_t saved_rax;
    addr_t saved_rcx;
    addr_t saved_rdx;
    addr_t saved_r8;
    addr_t saved_r9;
    int mm_count;

    uint8_t backup;
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
// __attribute__ ((packed));

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
// __attribute__ ((packed));

struct process_information_32 {
    uint32_t hProcess;
    uint32_t hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
}__attribute__ ((packed));

struct process_information_64 {
    addr_t hProcess;
    addr_t hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
}__attribute__ ((packed));

void hijack_thread(struct injector *injector, vmi_instance_t vmi,
        unsigned int vcpu, vmi_pid_t pid) {

    printf("Ready to hijack thread of PID %u on vCPU %u!\n", pid, vcpu);

    addr_t cpa = sym2va(vmi, pid, "kernel32.dll", "CreateProcessA");

    printf("CPA @ 0x%lx\n", cpa);

    reg_t fsgs, rbp, rsp, rip, rcx, rdx, rax, r8, r9;
    addr_t stack_base, stack_limit;

    vmi_get_vcpureg(vmi, &rsp, RSP, vcpu);
    vmi_get_vcpureg(vmi, &rip, RIP, vcpu);
    vmi_get_vcpureg(vmi, &rax, RAX, vcpu);
    vmi_get_vcpureg(vmi, &rcx, RCX, vcpu);
    vmi_get_vcpureg(vmi, &rdx, RDX, vcpu);
    vmi_get_vcpureg(vmi, &r8, R8, vcpu);
    vmi_get_vcpureg(vmi, &r9, R9, vcpu);

    if (injector->pm == VMI_PM_LEGACY || injector->pm == VMI_PM_PAE) {
        vmi_get_vcpureg(vmi, &fsgs, FS_BASE, vcpu);
        vmi_get_vcpureg(vmi, &rbp, RBP, vcpu);
        printf("FS: 0x%lx RBP: 0x%lx ", fsgs, rbp);
        vmi_read_addr_va(vmi, fsgs + 0x4, pid, &stack_base);
        vmi_read_addr_va(vmi, fsgs + 0x8, pid, &stack_limit);
    } else {
        vmi_get_vcpureg(vmi, &fsgs, GS_BASE, vcpu);
        printf("GS: 0x%lx ", fsgs);
        vmi_read_addr_va(vmi, fsgs + 0x8, pid, &stack_base);
        vmi_read_addr_va(vmi, fsgs + 0x10, pid, &stack_limit);
    }

    printf("RSP: 0x%lx. RIP: 0x%lx. RCX: 0x%lx\n", rsp, rip, rcx);
    printf("Stack base: 0x%lx. Limit: 0x%lx\n", stack_base, stack_limit);

    // Backup stack contents
    injector->stack_backup_size = rsp - stack_limit;
    injector->stack_backup = g_malloc0(injector->stack_backup_size);
    injector->stack_limit = stack_limit;
    vmi_read_va(vmi, stack_limit, pid, injector->stack_backup, injector->stack_backup_size);

    //Push input arguments on the stack
    //CreateProcess(NULL, TARGETPROC, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si, pi))

    uint64_t nul64 = 0;
    uint32_t nul32 = 0;
    uint8_t nul8 = 0;
    size_t len = strlen(injector->target_proc);
    addr_t addr = rsp;
    injector->saved_rsp = rsp;
    injector->saved_rip = rip;
    injector->saved_rax = rax;
    injector->saved_rdx = rdx;
    injector->saved_rcx = rcx;
    injector->saved_r8 = r8;
    injector->saved_r9 = r9;

    if (injector->pm == VMI_PM_LEGACY || injector->pm == VMI_PM_PAE) {

        addr -= 0x4; // the stack has to be alligned to 0x4
                     // and we need a bit of extra buffer before the string for \0
        // we just going to null out that extra space fully
        vmi_write_32_va(vmi, addr, pid, &nul32);

        // this string has to be aligned as well!
        addr -= len + 0x4 - (len % 0x4);
        addr_t str_addr = addr;
        vmi_write_va(vmi, addr, pid, (void*) injector->target_proc, len);
        // add null termination
        vmi_write_8_va(vmi, addr + len, pid, &nul8);
        printf("%s @ 0x%lx.\n", injector->target_proc, str_addr);

        //struct startup_info_32 si = {.wShowWindow = SW_SHOWDEFAULT };
        struct startup_info_32 si;
        memset(&si, 0, sizeof(struct startup_info_32));
        struct process_information_32 pi;
        memset(&pi, 0, sizeof(struct process_information_32));

        addr -= sizeof(struct process_information_32);
        injector->process_info = addr;
        vmi_write_va(vmi, addr, pid, &pi,
                sizeof(struct process_information_32));
        printf("pip @ 0x%lx\n", addr);

        addr -= sizeof(struct startup_info_32);
        addr_t sip = addr;
        vmi_write_va(vmi, addr, pid, &si, sizeof(struct startup_info_32));
        printf("sip @ 0x%lx\n", addr);

        //p10
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, (uint32_t *) &injector->process_info);
        //p9
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, (uint32_t *) &sip);
        //p8
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p7
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p6
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p5
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p4
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p3
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);
        //p2
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, (uint32_t *) &str_addr);
        //p1
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, &nul32);

        // save the return address (RIP)
        addr -= 0x4;
        vmi_write_32_va(vmi, addr, pid, (uint32_t *) &rip);

    } else {

        addr -= 0x8; // the stack has to be alligned to 0x8
                     // and we need a bit of extra buffer before the string for \0

        // we just going to null out that extra space fully
        vmi_write_64_va(vmi, addr, pid, &nul64);

        // this string has to be aligned as well!
        addr -= len + 0x8 - (len % 0x8);
        addr_t str_addr = addr;
        vmi_write_va(vmi, addr, pid, (void*) injector->target_proc, len);
        // add null termination
        vmi_write_8_va(vmi, addr + len, pid, &nul8);
        printf("%s @ 0x%lx.\n", injector->target_proc, str_addr);

        struct startup_info_64 si;
        memset(&si, 0, sizeof(struct startup_info_64));
        struct process_information_64 pi;
        memset(&pi, 0, sizeof(struct process_information_64));

        addr -= sizeof(struct process_information_64);
        injector->process_info = addr;
        vmi_write_va(vmi, addr, pid, &pi,
                sizeof(struct process_information_64));
        printf("pip @ 0x%lx\n", addr);

        addr -= sizeof(struct startup_info_64);
        addr_t sip = addr;
        vmi_write_va(vmi, addr, pid, &si, sizeof(struct startup_info_64));
        printf("sip @ 0x%lx\n", addr);

        //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
        //
        //First 4 parameters to functions are always passed in registers
        //P1=rcx, P2=rdx, P3=r8, P4=r9
        //5th parameter onwards (if any) passed via the stack

        //p10
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &injector->process_info);
        //p9
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &sip);
        //p8
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        //p7
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        //p6
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        //p5
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);

        // allocate 0x20 "homing space"
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &nul64);

        //p1
        vmi_set_vcpureg(vmi, 0, RCX, vcpu);
        //p2
        vmi_set_vcpureg(vmi, str_addr, RDX, vcpu);
        //p3
        vmi_set_vcpureg(vmi, 0, R8, vcpu);
        //p4
        vmi_set_vcpureg(vmi, 0, R9, vcpu);

        // save the return address (RIP)
        addr -= 0x8;
        vmi_write_64_va(vmi, addr, pid, &rip);
    }

    printf("Return address @ 0x%lx -> 0x%lx. Setting RSP: 0x%lx.\n", addr, rip,
            addr);

    // Grow the stack and switch execution
    vmi_set_vcpureg(vmi, addr, RSP, vcpu);
    vmi_set_vcpureg(vmi, cpa, RIP, vcpu);

    printf("Done with hijack routine\n");
}

/*
 * These functions may be useful for debugging
 */
/*void ss_callback(vmi_instance_t vmi, vmi_event_t *event) {
    reg_t rip, cr3, cs;
    vmi_get_vcpureg(vmi, &rip, RIP, event->vcpu_id);
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    vmi_get_vcpureg(vmi, &cs, CS_SEL, event->vcpu_id);
    page_mode_t pm = vmi_get_page_mode(vmi);
    vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);
    printf("----- Singlestep: CR3 0x%lx PID %u executing RIP 0x%lx CPL %u\n", cr3, pid, rip, VMI_BIT_MASK(0,2) & cs);

    if ((PM2BIT(pm) == BIT32 && rip < KERNEL32)
            || (PM2BIT(pm) == BIT64 && rip < KERNEL64)) {
        printf("Good RIP: 0x%lx\n", rip);
        struct injector *injector = event->data;
        injector->ss_enabled = 0;

        injector->target_pid = pid;
        injector->target_rip = vmi_pagetable_lookup(vmi, cr3, rip);

        hijack_thread(injector, vmi, event->vcpu_id, pid);

        vmi_clear_event(vmi, event);
        vmi_clear_event(vmi, &injector->cr3_event);
        injector->mm_count++;

        uint8_t trap = 0xCC;
        vmi_read_8_pa(vmi, injector->target_rip, &injector->backup);
        vmi_write_8_pa(vmi, injector->target_rip, &trap);
    }
}

void mm_callback(vmi_instance_t vmi, vmi_event_t *event) {
    struct injector *injector = event->data;
    reg_t rip, cr3, rsp;
    vmi_get_vcpureg(vmi, &rip, RIP, event->vcpu_id);
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);
    vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);

    printf("----- Memevent: PID %u executing RIP 0x%lx. Target PID: %u. Target RIP: 0x%lx. My event count: %u\n",
        pid, ((event->mem_event.gfn<<12) + event->mem_event.offset), injector->target_pid, injector->target_rip, injector->mm_count);

    if ((PM2BIT(injector->pm) == BIT32 && rip < KERNEL32)
            || (PM2BIT(injector->pm) == BIT64 && rip < KERNEL64)) {
        injector->target_pid = pid;
        injector->target_rip = (event->mem_event.gfn << 12)
                + event->mem_event.offset;

        hijack_thread(injector, vmi, event->vcpu_id, pid);

        vmi_clear_event(vmi, event);
        vmi_clear_event(vmi, &injector->cr3_event);
        injector->mm_count++;

        uint8_t trap = 0xCC;
        vmi_read_8_pa(vmi, injector->target_rip, &injector->backup);
        vmi_write_8_pa(vmi, injector->target_rip, &trap);

        return;
    }

    vmi_clear_event(vmi, event);
    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
}*/

event_response_t cr3_callback(vmi_instance_t vmi, vmi_event_t *event) {

    //printf("CR3 changed to 0x%lx - PID %i\n", event->reg_event.value, vmi_dtb_to_pid(vmi, event->reg_event.value));
    struct injector *injector = event->data;

    addr_t thread = 0, kpcrb_offset = 0, trapframe = 0;
    addr_t userspace_return_va = 0, userspace_return_pa = 0;
    reg_t fsgs = 0;

    if (event->reg_event.value == injector->target_cr3) {
        if (!injector->target_rip) {

            /* We determine the point where we want to hijack the thread by
               looking at the trap frame "_KTRAP_FRAME".
               While on x86-64 we can trap the RIP saved directly in the
               trap frame, on x86 that point is not yet safe. Thus, on x86 we
               read the stack base pointer (EBP/RBP) and get the return address
               from that stack frame. Remember, EBP points to another saved EBP,
               the return address is saved directly above it. */

            if (PM2BIT(injector->pm) == BIT32) {
                vmi_get_vcpureg(vmi, &fsgs, FS_BASE, event->vcpu_id);
                kpcrb_offset = offsets[KPCR_PRCBDATA];
            } else {
                vmi_get_vcpureg(vmi, &fsgs, GS_BASE, event->vcpu_id);
                kpcrb_offset = offsets[KPCR_PRCB];
            }

            vmi_read_addr_va(vmi,
                fsgs + kpcrb_offset + offsets[KPRCB_CURRENTTHREAD],
                0, &thread);

            if (!thread) {
                printf("cr3_cb: Failed to find current thread\n");
                return 0;
            }

            //printf("Current thread @ 0x%lx\n", thread);

            vmi_read_addr_va(vmi,
                thread + offsets[KTHREAD_TRAPFRAME],
                0, &trapframe);

            if (!trapframe) {
                printf("cr3_cb: Failed to find trapframe\n");
                return 0;
            }

            //printf("Trap frame @ 0x%lx\n", trapframe);

            addr_t tid;
            vmi_read_addr_va(vmi,
                thread + offsets[ETHREAD_CID] + offsets[CLIENT_ID_UNIQUETHREAD],
                0, &tid);

            addr_t rbp;
            vmi_pid_t pid = vmi_dtb_to_pid(vmi, injector->target_cr3);
            if (PM2BIT(injector->pm) == BIT32) {
                vmi_read_addr_va(vmi,
                    trapframe + offsets[KTRAP_FRAME_EBP],
                    0, &rbp);
                vmi_read_addr_va(vmi, rbp + 0x4, pid, &userspace_return_va);

            } else {
                vmi_read_addr_va(vmi,
                    trapframe + offsets[KTRAP_FRAME_RIP],
                    0, &userspace_return_va);
            }

            injector->userspace_return = vmi_pagetable_lookup(vmi, event->reg_event.value, userspace_return_va);
            printf("Trapping userspace return of Thread: %u @ VA 0x%lx -> PA 0x%lx\n",
                   tid, userspace_return_va, injector->userspace_return);

            uint8_t trap = 0xCC;
            vmi_read_8_pa(vmi, injector->userspace_return, &injector->userspace_return_backup);
            vmi_write_8_pa(vmi, injector->userspace_return, &trap);

        }
    } else {
        //printf("CR3 0x%lx is executing, not my process!\n",
        //        event->reg_event.value);

        if (injector->mm_enabled) {
            injector->mm_enabled = 0;
            vmi_clear_event(vmi, &injector->mm_event);
        }
        if (injector->ss_enabled) {
            injector->ss_enabled = 0;
            vmi_clear_event(vmi, &injector->ss_event);
        }

        if (injector->userspace_return) {
            vmi_write_8_pa(vmi, injector->userspace_return, &injector->userspace_return_backup);
            injector->userspace_return_backup = 0;
            injector->userspace_return = 0;
        }
    }

    return 0;
}

event_response_t waitfor_cr3_callback(vmi_instance_t vmi, vmi_event_t *event) {
    struct injector *injector = event->data;
    injector->drakvuf->interrupted = 1;
    printf("Injected process is scheduled to execute\n");
    vmi_pause_vm(vmi);
    vmi_clear_event(vmi, event);
    return 0;
}

event_response_t reset_return_trap(vmi_instance_t vmi, vmi_event_t *event) {
    addr_t pa = (event->interrupt_event.gfn << 12)
            + event->interrupt_event.offset;
    uint8_t trap = 0xCC;
    vmi_write_8_pa(vmi, pa, &trap);
    return 0;
}

event_response_t injector_int3_cb(vmi_instance_t vmi, vmi_event_t *event) {

    struct injector *injector = event->data;
    addr_t pa = (event->interrupt_event.gfn << 12)
            + event->interrupt_event.offset;

    reg_t cr3, cs, fsgs, rbp;
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rbp, RBP, event->vcpu_id);
    vmi_get_vcpureg(vmi, &cs, CS_SEL, event->vcpu_id);
    vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);

    /*addr_t ret = 0;

    if (PM2BIT(injector->pm) == BIT32) {
        vmi_read_addr_va(vmi, rbp + 0x4, pid, &ret);
    } else {
        vmi_read_addr_va(vmi, rbp + 0x8, pid, &ret);
    }

    printf("INT3 @ 0x%lx. PID %u. CPL: %u. Stack ret: 0x%lx\n", pa, pid, VMI_BIT_MASK(0,2) & cs, ret);*/

    if (pa == injector->userspace_return) {

        event->interrupt_event.reinject = 0;

        if (pid != injector->target_pid) {
            printf("Userspace return trap hit by another PID, not the target (%u)\n",
                    injector->target_pid);
            vmi_write_8_pa(vmi, pa, &injector->userspace_return_backup);
            vmi_step_event(vmi, event, event->vcpu_id, 1, reset_return_trap);
            return 0;
        }

            injector->target_pid = pid;
            injector->target_rip = pa;
            injector->backup = injector->userspace_return_backup;
            injector->userspace_return = 0;

            hijack_thread(injector, vmi, event->vcpu_id, pid);

                /*injector->ss_enabled = 1;
                memset(&injector->ss_event, 0, sizeof(vmi_event_t));
                injector->ss_event.type = VMI_EVENT_SINGLESTEP;
                injector->ss_event.callback = ss_callback;
                injector->ss_event.data = injector;
                SET_VCPU_SINGLESTEP(injector->ss_event.ss_event,
                        event->vcpu_id);
                vmi_register_event(vmi, &injector->ss_event);*/

            vmi_clear_event(vmi, &injector->cr3_event);
            injector->mm_count++;
            return 0;
    }

    if (pa == injector->target_rip) {

        event->interrupt_event.reinject = 0;

        if (pid != injector->target_pid) {
            printf("Return trap hit by another PID, not the target (%u)\n",
                    injector->target_pid);
            vmi_write_8_pa(vmi, pa, &injector->backup);
            vmi_step_event(vmi, event, event->vcpu_id, 1, reset_return_trap);
            return 0;

        }

        reg_t rax;
        vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);
        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);

        printf("RAX: 0x%lx\n", rax);

        printf("Restoring RSP to 0x%lx\n", injector->saved_rsp);
        printf("Restoring RAX to 0x%lx\n", injector->saved_rax);
        printf("Restoring RCX to 0x%lx\n", injector->saved_rcx);
        printf("Restoring RDX to 0x%lx\n", injector->saved_rdx);
        printf("Restoring R8 to 0x%lx\n", injector->saved_r8);
        printf("Restoring R9 to 0x%lx\n", injector->saved_r9);

        vmi_set_vcpureg(vmi, injector->saved_rsp, RSP, event->vcpu_id);
        vmi_set_vcpureg(vmi, injector->saved_rax, RAX, event->vcpu_id);
        vmi_set_vcpureg(vmi, injector->saved_rcx, RCX, event->vcpu_id);
        vmi_set_vcpureg(vmi, injector->saved_rdx, RDX, event->vcpu_id);
        vmi_set_vcpureg(vmi, injector->saved_r8, R8, event->vcpu_id);
        vmi_set_vcpureg(vmi, injector->saved_r9, R9, event->vcpu_id);

        if (rax) {
            printf("-- CreateProcessA SUCCESS --\n");

            if (PM2BIT(injector->pm) == BIT32) {
                struct process_information_32 pip;
                vmi_read_va(vmi, injector->process_info, pid, &pip,
                        sizeof(struct process_information_32));
                printf("\tProcess handle: 0x%x. Thread handle: 0x%x\n",
                        pip.hProcess, pip.hThread);
                printf("\tPID: %u. TID: %u\n", pip.dwProcessId, pip.dwThreadId);

                injector->pid = pip.dwProcessId;
                injector->tid = pip.dwThreadId;
                injector->hProc = pip.hProcess;
                injector->hThr = pip.hThread;

            } else {
                struct process_information_64 pip;
                vmi_read_va(vmi, injector->process_info, pid, &pip,
                        sizeof(struct process_information_64));
                printf("\tProcess handle: 0x%lx. Thread handle: 0x%lx\n",
                        pip.hProcess, pip.hThread);
                printf("\tPID: %u. TID: %u\n", pip.dwProcessId, pip.dwThreadId);

                injector->pid = pip.dwProcessId;
                injector->tid = pip.dwThreadId;
                injector->hProc = pip.hProcess;
                injector->hThr = pip.hThread;

            }

            if (injector->pid && injector->tid) {
                injector->ret = rax;

                injector->cr3_event.callback = waitfor_cr3_callback;
                injector->cr3_event.reg_event.equal = vmi_pid_to_dtb(vmi,
                        injector->pid);
                injector->cr3_event.data = injector;
                vmi_register_event(vmi, &injector->cr3_event);
                printf("\tInjected process CR3: 0x%lx\n",
                        injector->cr3_event.reg_event.equal);
            }
        } else {
            injector->drakvuf->interrupted = 1;
        }

        // Restore stack
        if(injector->stack_backup) {
            vmi_write_va(vmi, injector->stack_limit, pid, injector->stack_backup, injector->stack_backup_size);
            free(injector->stack_backup);
        }

        vmi_write_8_pa(vmi, pa, &injector->backup);
        vmi_clear_event(vmi, event);

    } else {
        event->interrupt_event.reinject = 1;
    }

    return 0;
}

int start_app(drakvuf_t *drakvuf, vmi_pid_t pid, const char *app) {

    vmi_pause_vm(drakvuf->vmi);

    struct injector injector = {
        .drakvuf = drakvuf,
        .target_cr3 = vmi_pid_to_dtb(drakvuf->vmi, pid),
        .target_pid = pid,
        .target_proc = app,
        .winver = drakvuf->winver,
        .pm = vmi_get_page_mode(drakvuf->vmi),
        .ret = 0
    };

    if (!injector.target_cr3)
    {
        printf("Unable to find target PID's DTB\n");
        return 0;
    }

    printf("Target PID %u with DTB 0x%lx to start '%s'\n", pid,
            injector.target_cr3, app);

    injector.cr3_event.type = VMI_EVENT_REGISTER;
    injector.cr3_event.reg_event.reg = CR3;
    injector.cr3_event.reg_event.in_access = VMI_REGACCESS_W;
    injector.cr3_event.callback = cr3_callback;
    injector.cr3_event.data = &injector;
    vmi_register_event(drakvuf->vmi, &injector.cr3_event);

    vmi_event_t interrupt_event;
    memset(&interrupt_event, 0, sizeof(vmi_event_t));
    interrupt_event.type = VMI_EVENT_INTERRUPT;
    interrupt_event.interrupt_event.intr = INT3;
    interrupt_event.callback = injector_int3_cb;
    interrupt_event.data = &injector;
    vmi_register_event(drakvuf->vmi, &interrupt_event);

    printf("Starting injection loop\n");
    vmi_resume_vm(drakvuf->vmi);

    status_t status = VMI_FAILURE;
    while (!drakvuf->interrupted) {
        //printf("Waiting for events...\n");
        status = vmi_events_listen(drakvuf->vmi, 500);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            drakvuf->interrupted = -1;
        }
    }

    vmi_clear_event(drakvuf->vmi, &injector.cr3_event);
    vmi_clear_event(drakvuf->vmi, &injector.mm_event);
    vmi_clear_event(drakvuf->vmi, &injector.ss_event);
    vmi_clear_event(drakvuf->vmi, &interrupt_event);

    printf("Finished with injection.\n");
    return injector.ret;
}
