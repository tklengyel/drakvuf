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
 ***************************************************************************/

#ifndef LIBINJECTOR_H
#define LIBINJECTOR_H

#ifdef __cplusplus
extern "C" {
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#pragma GCC visibility push(default)

#include <libdrakvuf/libdrakvuf.h>

typedef struct injector* injector_t;

typedef enum
{
    STEP1,
    STEP2,
    STEP3,
    STEP4,
    STEP5,
    STEP6,
    STEP7,
    STEP8,
} injector_step_t;

typedef enum
{
    INJECTOR_FAILED,
    INJECTOR_FAILED_WITH_ERROR_CODE,
    INJECTOR_SUCCEEDED,
    INJECTOR_TIMEOUTED,
} injector_status_t;

typedef enum
{
    // win
    INJECT_METHOD_CREATEPROC,
    INJECT_METHOD_TERMINATEPROC,
    INJECT_METHOD_EXITTHREAD,
    INJECT_METHOD_SHELLEXEC,
    INJECT_METHOD_SHELLCODE,
    INJECT_METHOD_READ_FILE,
    INJECT_METHOD_WRITE_FILE,
    // linux
    INJECT_METHOD_EXECPROC,

    __INJECT_METHOD_MAX
}
injection_method_t;

typedef enum
{
    ARGUMENT_STRING,
    ARGUMENT_STRUCT,
    ARGUMENT_INT,
    ARGUMENT_ARRAY,
    __ARGUMENT_MAX
} argument_type_t;

typedef enum
{
    STATUS_NULL,
    STATUS_ALLOC_OK,
    STATUS_PHYS_ALLOC_OK,
    STATUS_EXPAND_ENV_OK,
    STATUS_WRITE_OK,
    STATUS_EXEC_OK,
    STATUS_BP_HIT,
    STATUS_OPEN,
    STATUS_TERMINATE,
    STATUS_CREATE_OK,
    STATUS_RESUME_OK,
    STATUS_CREATE_FILE_OK,
    STATUS_READ_FILE_OK,
    STATUS_WRITE_FILE_OK,
    STATUS_CLOSE_FILE_OK,
    STATUS_GET_LAST_ERROR,
    __STATUS_MAX
} status_type_t;

struct argument
{
    uint32_t type;
    uint32_t size;
    uint64_t data_on_stack;
    const void* data;
};

void init_argument(struct argument* arg,
    argument_type_t type,
    size_t size,
    const void* data) NOEXCEPT;

void init_int_argument(struct argument* arg,
    uint64_t value) NOEXCEPT;

void init_unicode_argument(struct argument* arg,
    unicode_string_t* us) NOEXCEPT;

void init_string_argument(struct argument* arg,
    const char* string) NOEXCEPT;

void init_array_argument(struct argument* arg,
    struct argument array[],
    int size) NOEXCEPT;

#define init_struct_argument(arg, sv) \
    init_argument((arg), ARGUMENT_STRUCT, sizeof((sv)), (void*)&(sv))

addr_t place_array_on_addr_64(vmi_instance_t vmi,
    x86_registers_t* regs,
    struct argument* arg,
    bool null_terminate,
    addr_t* data_addr,
    addr_t* array_addr) NOEXCEPT;

addr_t place_array_on_addr_32(vmi_instance_t vmi,
    x86_registers_t* regs,
    struct argument* arg,
    addr_t* data_addr,
    addr_t* array_addr) NOEXCEPT;

bool setup_stack(drakvuf_t drakvuf,
    x86_registers_t* regs,
    struct argument args[],
    int nb_args) NOEXCEPT;

bool setup_stack_locked(drakvuf_t drakvuf,
    vmi_instance_t vmi,
    x86_registers_t* regs,
    struct argument args[],
    int nb_args) NOEXCEPT;

bool inject_function_call(
    drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    event_response_t (*cb)(drakvuf_t, drakvuf_trap_info_t*),
    x86_registers_t* regs,
    struct argument args[],
    int nb_args,
    addr_t function_addr);

injector_status_t injector_start_app(drakvuf_t drakvuf,
    vmi_pid_t pid,
    uint32_t tid, // optional, if tid=0 the first thread that gets scheduled is used
    const char* app,
    const char* cwd,
    injection_method_t method,
    output_format_t format,
    const char* binary_path,     // if -m = doppelganging
    const char* target_process,  // if -m = doppelganging
    bool break_loop_on_detection,
    injector_t* injector_to_be_freed,
    bool global_search, // out: iff break_loop_on_detection is set
    bool wait_for_exit,
    int args_count,
    const char* args[],
    vmi_pid_t* injected_pid) NOEXCEPT;

void injector_terminate(drakvuf_t drakvuf,
    vmi_pid_t injection_pid,
    uint32_t injection_tid,
    vmi_pid_t pid);

void injector_exitthread(drakvuf_t drakvuf,
    vmi_pid_t injection_pid,
    uint32_t injection_tid);


void injector_free(drakvuf_t drakvuf, injector_t injector);

const char* injection_method_name(injection_method_t method);

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif // LIBINJECTOR_H
