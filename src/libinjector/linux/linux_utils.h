/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
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
 * This file was created by Manorit Chawdhry.                              *
 * It is distributed as part of DRAKVUF under the same license             *
 ***************************************************************************/


#ifndef LINUX_UTILS_H
#define LINUX_UTILS_H

#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <libinjector/libinjector.h>
#include <libvmi/libvmi.h>
#include <libvmi/x86.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>
#include <libdrakvuf/libdrakvuf.h>
#include <libinjector/private.h>
#include "injector_utils.h"

// syscall limit for error codes
#define MAX_ERRNO 4096UL
#define FILE_BUF_SIZE 65536UL

typedef enum
{
    sys_read = 0,
    sys_write = 1,
    sys_open = 2,
    sys_close = 3,
    sys_stat = 4,
    sys_mmap = 9,
    sys_mprotect = 10,
    sys_munmap = 11,
    sys_vfork = 58,
    sys_execve = 59,
    sys_exit = 60,
    sys_kill = 62,
} syscall_t;

struct injector
{
    // common in win and linux
    // KEEP THESE IN TOP and in sync with the order in injector_utils.c
    injector_step_t step;
    bool step_override; // set this as true for jumping to some arbitrary step
    bool dummy; // set_gprs_only

    // Inputs:
    vmi_pid_t target_pid;
    uint32_t target_tid;
    addr_t target_process;
    const char* target_file;
    const char* host_file;
    int args_count;
    // A NULL-terminated array of arguments
    const char** args;

    // Internal:
    drakvuf_t drakvuf;
    injection_method_t method;
    addr_t syscall_addr;
    bool injection_failed;

    // Buffer
    struct
    {
        void* data;
        size_t len;
        size_t total_len;
        size_t total_processed;
    } buffer;

    // read_file and write_file
    long int fd;
    FILE* fp;

    // mmap
    addr_t virtual_memory_addr;

    // for restoring stack
    x86_registers_t saved_regs;

    // int3 trap
    drakvuf_trap_t* bp;

    // execve
    bool fork;
    proc_data_t child_data;

    // Traps
    drakvuf_trap_t* cr3_trap;

    // Results:
    injector_status_t rc;
    inject_result_t result;
    injection_error_t error_code;

    uint32_t pid, tid;
};

void free_bp_trap(drakvuf_t drakvuf, injector_t injector, drakvuf_trap_t* trap);
void injector_free_linux(injector_t injector);
bool save_rip_for_ret(drakvuf_t drakvuf, x86_registers_t* regs);
addr_t find_vdso(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
addr_t find_syscall(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t vdso);
bool setup_post_syscall_trap(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t syscall_addr);
event_response_t override_step(injector_t injector, const injector_step_t step, event_response_t event);
bool is_syscall_error(addr_t rax, const char* err);
void print_linux_injection_info(output_format_t format, injector_t injector);

#endif
