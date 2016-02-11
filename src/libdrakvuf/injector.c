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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <inttypes.h>
#include <glib.h>

#include "libdrakvuf.h"
#include "injector.h"
#include "vmi.h"
#include "win-symbols.h"
#include "win-exports.h"
#include "win-handles.h"

static uint8_t trap = 0xCC;

struct injector {
    // Inputs:
    const char *target_proc;
    reg_t target_cr3;
    vmi_pid_t target_pid;

    // Internal:
    drakvuf_t drakvuf;
    page_mode_t pm;

    addr_t process_info;
    addr_t saved_rsp;
    addr_t saved_rip;
    addr_t saved_rax;
    addr_t saved_rcx;
    addr_t saved_rdx;
    addr_t saved_r8;
    addr_t saved_r9;

    addr_t entry, ret;
    uint8_t entry_backup, ret_backup;
    GTimer *timer;

    // Results:
    reg_t cr3;
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

void pass_inputs(struct injector *injector, vmi_instance_t vmi,
        unsigned int vcpu, reg_t cr3) {

    status_t status;
    reg_t fsgs, rsp;
    addr_t stack_base, stack_limit;

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3,
    };

    status = vmi_get_vcpureg(vmi, &rsp, RSP, vcpu);

    if (injector->pm == VMI_PM_LEGACY || injector->pm == VMI_PM_PAE)
        status = vmi_get_vcpureg(vmi, &fsgs, FS_BASE, vcpu);
    if (injector->pm == VMI_PM_IA32E)
        status = vmi_get_vcpureg(vmi, &fsgs, GS_BASE, vcpu);

    ctx.addr = fsgs + offsets[NT_TIB_STACKBASE];
    vmi_read_addr(vmi, &ctx, &stack_base);
    ctx.addr = fsgs + offsets[NT_TIB_STACKLIMIT];
    vmi_read_addr(vmi, &ctx, &stack_limit);

    //PRINT(injector->drakvuf, INJECTION_STACK_INFO_STRING,
    //      fsgs, rsp, stack_base, stack_limit);

    ctx.addr = rsp;
    vmi_read_addr(vmi, &ctx, &injector->ret);
    ctx.addr = injector->ret;
    vmi_read_8(vmi, &ctx, &injector->ret_backup);

    //Push input arguments on the stack
    //CreateProcess(NULL, TARGETPROC, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si, pi))

    uint64_t nul64 = 0;
    uint32_t nul32 = 0;
    uint8_t nul8 = 0;
    size_t len = strlen(injector->target_proc);
    addr_t addr = rsp;

    addr_t str_addr, sip_addr;

    if (injector->pm == VMI_PM_LEGACY || injector->pm == VMI_PM_PAE) {

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
        vmi_write_32(vmi, &ctx, (uint32_t *) &injector->ret);

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
        vmi_set_vcpureg(vmi, 0, RCX, vcpu);
        //p2
        vmi_set_vcpureg(vmi, str_addr, RDX, vcpu);
        //p3
        vmi_set_vcpureg(vmi, 0, R8, vcpu);
        //p4
        vmi_set_vcpureg(vmi, 0, R9, vcpu);

        // save the return address
        addr -= 0x8;
        ctx.addr = addr;
        vmi_write_64(vmi, &ctx, &injector->ret);
    }

    //PRINT(injector->drakvuf, INJECTION_STACK_PUSHED_STRING,
    //      injector->target_proc, str_addr,
    //      injector->process_info, sip_addr);

    // Grow the stack
    vmi_set_vcpureg(vmi, addr, RSP, vcpu);
}

/*
 * Once an apc queueable thread is found, we inject an apc structure
 * to call CreateProcessA. Since the call arguments cannot be passed
 * in the APC message, we trap CreateProcessA with an int3 and will
 * setup the stack for the function just before it is executed
*/
void inject_apc(struct injector *injector,
                vmi_instance_t vmi,
                unsigned int vcpu,
                reg_t cr3,
                addr_t kernbase,
                addr_t thread)
{
    addr_t apc_state_addr, psexit;
    status_t status;
    reg_t rsp;

    addr_t kstack_base = 0, kstack_limit = 0;

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3,
    };

    status = vmi_read_addr_va(vmi, thread+offsets[KTHREAD_INITIALSTACK], 0, &kstack_base);
    if(status == VMI_FAILURE) {
        PRINT_DEBUG("Failed to read kernel thread initial stack\n");
        return;
    }

    status = vmi_read_addr_va(vmi, thread+offsets[KTHREAD_STACKLIMIT], 0, &kstack_limit);
    if(status == VMI_FAILURE) {
        PRINT_DEBUG("Failed to read kernel thread stack limit\n");
        return;
    }

    PRINT_DEBUG("Kernel stack base: 0x%lx. Limit: 0x%lx\n", kstack_base, kstack_limit);

    vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);
    if(!pid) {
        PRINT_DEBUG("Failed to get PID of current process\n");
        return;
    }

    injector->entry = sym2va(vmi, pid, "kernel32.dll", "CreateProcessA");
    if (!injector->entry) {
        PRINT_DEBUG("Failed to get address of kernel32.dll!CreateProcessA\n");
        return;
    }

    /*
     * Passing PsExitSpecialApc as the kernel_routine does the trick
     * of scheduling this APC right away. Any other function
     * crashes the process.
     */
    if (VMI_FAILURE == drakvuf_get_function_rva(injector->drakvuf->rekall_profile,
                                                "PsExitSpecialApc",
                                                &psexit))
    {
        PRINT_DEBUG("Failed to get address of ntoskrnl.exe!PsExitSpecialApc\n");
        return;
    }

    psexit += kernbase;

    status = vmi_read_addr_va(vmi, thread + offsets[KTHREAD_APCSTATE], 0, &apc_state_addr);
    if(status == VMI_FAILURE) {
        PRINT_DEBUG("inject_apc: Failed to read apc state address\n");
        return;
    }

    if (injector->pm == VMI_PM_LEGACY || injector->pm == VMI_PM_PAE) {

        struct kapc_state_32 kapc_state = { 0 };
        struct kapc_32 kapc = { 0 };

        kapc.type = 0;
        kapc.apc_mode = 1;
        kapc.inserted = 1;
        kapc.thread = thread;
        kapc.normal_routine = injector->entry;
        kapc.kernel_routine = psexit;

        PRINT_DEBUG("APC Normal routine @ 0x%x. Kernel routine @ 0x%x\n",
                    kapc.normal_routine,
                    kapc.kernel_routine);

        ctx.addr = apc_state_addr;
        status = vmi_read(vmi, &ctx, &kapc_state, sizeof(struct kapc_state_32));
        if(status == VMI_FAILURE) {
            PRINT_DEBUG("Failed to read kapc state\n");
            return;
        }

        // Make this apc hook into the linked-list
        kapc.apc_list_entry.flink = kapc_state.apc_list_head[1].flink;
        kapc.apc_list_entry.blink = kapc_state.apc_list_head[1].blink;

        // Write this kapc on the kernel stack at the very end
        // It will be used before anything has a chance to overwrite it
        addr_t apc_addr = kstack_limit;
        status = vmi_write_va(vmi, apc_addr, 0, &kapc, sizeof(struct kapc_32));
        if(status == VMI_FAILURE) {
            PRINT_DEBUG("Failed to write kapc on the stack at 0x%lx\n", apc_addr);
            return;
        }

        PRINT_DEBUG("APC injected at 0x%lx\n", apc_addr);

        // Update _KAPC_STATE
        // link pointers must point into the list entries in _KAPC
        kapc_state.user_apc_pending = 1;
        kapc_state.apc_list_head[1].flink = apc_addr + offsets[KAPC_APCLISTENTRY];

        // Save _KAPC_STATE
        ctx.addr = apc_state_addr;
        status = vmi_write(vmi, &ctx, &kapc_state, sizeof(struct kapc_state_32));
        if(status == VMI_FAILURE) {
            PRINT_DEBUG("Failed to save updated _KAPC_STATE\n");
            return;
        }

    } else {

        /*
         * This works 100% for process termination
         * where the normal_routine passed is ntdll.dll!RtlExitUserProcess.
         * Unfortunately passing non-ntdll functions crashes the host process.
         * Once in the ntdll function you can divert the flow to any loaded library
         * but unfortunately the process will crash once returning.
         * Root cause yet unknown so just disabling this for now.
         */

        /*
        struct kapc_state_64 kapc_state = { 0 };
        struct kapc_64 kapc = { 0 };

        kapc.type = 0;
        kapc.apc_mode = 1;
        kapc.inserted = 1;
        kapc.thread = thread;
        kapc.normal_routine = injector->entry;
        kapc.kernel_routine = psexit;

        PRINT_DEBUG("APC Normal routine @ 0x%lx. Kernel routine @ 0x%lx\n",
                    kapc.normal_routine,
                    kapc.kernel_routine);

        ctx.addr = apc_state_addr;
        status = vmi_read(vmi, &ctx, &kapc_state, sizeof(struct kapc_state_64));
        if(status == VMI_FAILURE) {
            PRINT_DEBUG("Failed to read kapc state\n");
            return;
        }

        // Make this apc hook into the linked-list
        kapc.apc_list_entry.flink = kapc_state.apc_list_head[1].flink;
        kapc.apc_list_entry.blink = kapc_state.apc_list_head[1].blink;

        // Write this kapc on the kernel stack at the very end
        // It will be used before anything has a chance to overwrite it
        addr_t apc_addr = kstack_limit;
        status = vmi_write_va(vmi, apc_addr, 0, &kapc, sizeof(struct kapc_64));
        if(status == VMI_FAILURE) {
            PRINT_DEBUG("Failed to write kapc on the stack at 0x%lx\n", apc_addr);
            return;
        }

        PRINT_DEBUG("APC injected at 0x%lx\n", apc_addr);

        // Update _KAPC_STATE
        // link pointers must point into the list entries in _KAPC
        kapc_state.user_apc_pending = 1;
        kapc_state.apc_list_head[1].flink = apc_addr + offsets[KAPC_APCLISTENTRY];

        // Save _KAPC_STATE
        ctx.addr = apc_state_addr;
        status = vmi_write(vmi, &ctx, &kapc_state, sizeof(struct kapc_state_64));
        if(status == VMI_FAILURE) {
            PRINT_DEBUG("Failed to save updated _KAPC_STATE\n");
            return;
        }
        */
    }

    ctx.addr = injector->entry;
    vmi_read_8(vmi, &ctx, &injector->entry_backup);
    vmi_write_8(vmi, &ctx, &trap);

    PRINT_DEBUG("Wrote trap to 0x%lx. Backup: %u\n",
                ctx.addr, injector->entry_backup);
}

event_response_t cr3_callback(vmi_instance_t vmi, vmi_event_t *event) {

    struct injector *injector = event->data;
    addr_t thread = 0, kpcrb_offset = 0, tid = 0, stack_base = 0, stack_limit = 0;
    addr_t kernbase;
    uint8_t apcqueueable;
    reg_t fsgs = 0, cr3 = event->reg_event.value;
    status_t status;

    /*PRINT_DEBUG("CR3 changed to 0x%lx - PID %i\n",
                event->reg_event.value,
                vmi_dtb_to_pid(vmi, event->reg_event.value));*/

    if (event->reg_event.value == injector->target_cr3) {

        if (PM2BIT(injector->pm) == BIT32) {
            status = vmi_get_vcpureg(vmi, &fsgs, FS_BASE, event->vcpu_id);
            kpcrb_offset = offsets[KPCR_PRCBDATA];
        } else {
            status = vmi_get_vcpureg(vmi, &fsgs, GS_BASE, event->vcpu_id);
            kpcrb_offset = offsets[KPCR_PRCB];
        }

        kernbase = fsgs - offsets[KIINITIALPCR];

        if(status == VMI_FAILURE) {
            PRINT_DEBUG("Failed to get GS_BASE\n");
            goto done;
        }

        status = vmi_read_addr_va(vmi,
                         fsgs + kpcrb_offset + offsets[KPRCB_CURRENTTHREAD],
                         0, &thread);

        if (status == VMI_FAILURE || !thread) {
            PRINT_DEBUG("cr3_cb: Failed to find current thread\n");
            goto done;
        }

        /*
         * At this point the process is still in kernel mode, so
         * we need to trap when it enters into user mode.
         * For this we use different mechanisms on 32-bit and 64-bit.
         * The reason for this is that the same methods are not equally
         * reliably.
         *
         * For 32-bit Windows we inject a fake APC structure with a function
         * that will be trapped and diverted.
         * This method on Windows 7 64-bit _only_ works if the function is one
         * defined by ntdll.dll. The host process unfortunatelly crashes
         * after the APC is delivered.
         *
         * For 64-bit Windows we use the trapframe approach, where we read
         * the saved RIP from the stack trap frame and trap it.
         * When this address is hit, we hijack the flow and afterwards return
         * the registers to the original values, thus the process continues to run.
         * This method is workable on 32-bit Windows as well but finding the trapframe
         * sometimes fail for yet unknown reasons.
         */
        if (PM2BIT(injector->pm) == BIT64) {

            access_context_t ctx = {
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = cr3,
            };

            addr_t trapframe = 0;
            status = vmi_read_addr_va(vmi,
                        thread + offsets[KTHREAD_TRAPFRAME],
                        0, &trapframe);

            if (status == VMI_FAILURE || !trapframe) {
                PRINT_DEBUG("cr3_cb: failed to read trapframe or trapframe is NULL\n");
                goto done;
            }

            status = vmi_read_addr_va(vmi,
                        trapframe + offsets[KTRAP_FRAME_RIP],
                        0, &injector->entry);

            if (status == VMI_FAILURE || !injector->entry) {
                PRINT_DEBUG("Failed to read RIP from trapframe or RIP is NULL!\n");
                goto done;
            }

            ctx.addr = injector->entry;
            vmi_read_8(vmi, &ctx, &injector->entry_backup);
            vmi_write_8(vmi, &ctx, &trap);

            PRINT_DEBUG("Trapframe @ 0x%lx. Return address: 0x%lx Backup: %u\n",
                        trapframe, injector->entry,
                        injector->entry_backup);
        } else {

            status = vmi_read_8_va(vmi,
                       thread + offsets[KTHREAD_APCQUEUEABLE],
                       0, &apcqueueable);

            if (status == VMI_FAILURE) {
                PRINT_DEBUG("cr3_cb: Failed to read apc queueable\n");
                goto done;
            }

            status = vmi_read_addr_va(vmi,
                       thread + offsets[ETHREAD_CID] + offsets[CLIENT_ID_UNIQUETHREAD],
                       0, &tid);

            if (status == VMI_FAILURE) {
                PRINT_DEBUG("cr3_cb: Failed to read current Thread ID\n");
                goto done;
            }

            apcqueueable = !!(apcqueueable & (1<<5));

            PRINT_DEBUG("Current thread: %lu. Base: 0x%lx. ApcQueueable: %u.\n",
                        tid, thread, apcqueueable);

            if (!apcqueueable)
                goto done;

            inject_apc(injector, vmi, event->vcpu_id, cr3, kernbase, thread);

        }

        vmi_clear_event(vmi, event, NULL);
    }

done:
    return 0;
}


event_response_t singlestep_cb(vmi_instance_t vmi, vmi_event_t *event) {
    addr_t *pa = event->data;
    vmi_write_8_pa(vmi, *pa, &trap);
    free(pa);
    return 1u<<VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

event_response_t injector_int3_cb(vmi_instance_t vmi, vmi_event_t *event) {
    vmi_pause_vm(vmi);

    struct injector *injector = event->data;
    addr_t pa = (event->interrupt_event.gfn << 12)
                 + event->interrupt_event.offset;
    reg_t cr3 = event->regs.x86->cr3;
    vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3,
    };

    PRINT_DEBUG("INT3 Callback @ 0x%lx. PID %u. CR3 0x%lx\n",
                event->interrupt_event.gla, pid, cr3);

    if ( cr3 != injector->target_cr3 ) {
        PRINT_DEBUG("Stepping INT3 as CR3 doesn't match target process\n");

        if ( event->interrupt_event.gla == injector->entry )
            vmi_write_8_pa(vmi, pa, &injector->entry_backup);
        else if ( event->interrupt_event.gla == injector->ret )
            vmi_write_8_pa(vmi, pa, &injector->ret_backup);
        else
            goto notmine;

        injector->drakvuf->step_event[event->vcpu_id]->callback = singlestep_cb;
        injector->drakvuf->step_event[event->vcpu_id]->data = g_memdup(&pa, sizeof(addr_t));
        event->interrupt_event.reinject = 0;
        vmi_resume_vm(vmi);

        return 1u<<VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    if ( event->interrupt_event.gla == injector->entry ) {

        if (PM2BIT(injector->pm) == BIT64) {
            addr_t cpa = sym2va(vmi, pid, "kernel32.dll", "CreateProcessA");

            injector->saved_rip = event->regs.x86->rip;
            injector->saved_rsp = event->regs.x86->rsp;
            injector->saved_rax = event->regs.x86->rax;
            injector->saved_rcx = event->regs.x86->rcx;
            injector->saved_r8 = event->regs.x86->r8;
            injector->saved_r9 = event->regs.x86->r9;

            vmi_set_vcpureg(vmi, cpa, RIP, event->vcpu_id);

            PRINT_DEBUG("Diverting flow to 0x%lx\n", cpa);
        }

        // On 32-bit Windows we are already at CreateProcessA

        vmi_write_8_pa(vmi, pa, &injector->entry_backup);
        pass_inputs(injector, vmi, event->vcpu_id, cr3);

        ctx.addr = injector->ret;
        vmi_write_8(vmi, &ctx, &trap);

        PRINT_DEBUG("Stack setup finished and return trap added @ 0x%" PRIx64 "\n", injector->ret);

        event->interrupt_event.reinject = 0;
        vmi_resume_vm(vmi);
        return 0;
    }

    if ( event->interrupt_event.gla != injector->ret )
        goto notmine;

    // We are now in the return path from CreateProcessA

    vmi_clear_event(vmi, event, NULL);
    vmi_write_8_pa(vmi, pa, &injector->ret_backup);
    injector->drakvuf->interrupted=1;
    event->interrupt_event.reinject = 0;

    reg_t rax = event->regs.x86->rax;

    if (PM2BIT(injector->pm) == BIT64) {
        PRINT_DEBUG("Returning flow to 0x%lx\n", injector->saved_rip);
        vmi_set_vcpureg(vmi, injector->saved_rip, RIP, event->vcpu_id);
        vmi_set_vcpureg(vmi, injector->saved_rsp, RSP, event->vcpu_id);
        vmi_set_vcpureg(vmi, injector->saved_rax, RAX, event->vcpu_id);
        vmi_set_vcpureg(vmi, injector->saved_rcx, RCX, event->vcpu_id);
        vmi_set_vcpureg(vmi, injector->saved_r8, R8, event->vcpu_id);
        vmi_set_vcpureg(vmi, injector->saved_r9, R9, event->vcpu_id);
    }

    PRINT_DEBUG("RAX: 0x%lx\n", rax);

    if (rax) {
        ctx.addr = injector->process_info;

        if (PM2BIT(injector->pm) == BIT32) {
            struct process_information_32 pip = { 0 };
            vmi_read(vmi, &ctx, &pip,
                     sizeof(struct process_information_32));

            injector->pid = pip.dwProcessId;
            injector->tid = pip.dwThreadId;
            injector->hProc = pip.hProcess;
            injector->hThr = pip.hThread;

        } else {
            struct process_information_64 pip = { 0 };
            vmi_read(vmi, &ctx, &pip,
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
            injector->ret = rax;
            /*injector->cr3 = vmi_pid_to_dtb(vmi, injector->pid);
            injector->cr3_event.callback = waitfor_cr3_callback;
            injector->cr3_event.reg_event.equal = injector->cr3;
            injector->cr3_event.data = injector;
            vmi_register_event(vmi, &injector->cr3_event);*/
        } else {
            injector->ret = 0;
        }
    }

    return 0;

notmine:
    event->interrupt_event.reinject = 1;
    vmi_resume_vm(vmi);
    return 0;
}

int drakvuf_inject_cmd(drakvuf_t drakvuf, vmi_pid_t pid, const char *app) {

    struct injector injector = {
        .drakvuf = drakvuf,
        .target_cr3 = vmi_pid_to_dtb(drakvuf->vmi, pid),
        .target_pid = pid,
        .target_proc = app,
        .pm = vmi_get_page_mode(drakvuf->vmi),
        .ret = 0
    };

    if (!injector.target_cr3)
    {
        PRINT_DEBUG("Unable to find target PID's DTB\n");
        return 0;
    }

    PRINT_DEBUG("Target PID %u with DTB 0x%lx to start '%s'\n", pid,
                injector.target_cr3, app);

    vmi_event_t cr3_event;
    memset(&cr3_event, 0, sizeof(vmi_event_t));
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;
    cr3_event.callback = cr3_callback;
    cr3_event.data = &injector;
    vmi_register_event(drakvuf->vmi, &cr3_event);

    vmi_event_t interrupt_event;
    memset(&interrupt_event, 0, sizeof(vmi_event_t));
    interrupt_event.type = VMI_EVENT_INTERRUPT;
    interrupt_event.interrupt_event.intr = INT3;
    interrupt_event.callback = injector_int3_cb;
    interrupt_event.data = &injector;
    vmi_register_event(drakvuf->vmi, &interrupt_event);

    PRINT_DEBUG("Starting injection loop\n");
    drakvuf_resume(drakvuf);

    status_t status = VMI_FAILURE;
    while (!drakvuf->interrupted) {

        status = vmi_events_listen(drakvuf->vmi, 500);

        if (status != VMI_SUCCESS)
        {
            PRINT_DEBUG("Error waiting for events or timeout...\n");
            drakvuf->interrupted = -1;
        }
    }

    vmi_clear_event(drakvuf->vmi, &cr3_event, NULL);
    vmi_clear_event(drakvuf->vmi, &interrupt_event, NULL);

    PRINT_DEBUG("Finished with injection. Ret: %i\n", injector.ret);
    return injector.ret;
}
