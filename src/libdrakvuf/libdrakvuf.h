/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014-2015 Tamas K Lengyel.  *
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

#ifndef LIBDRAKVUF_H
#define LIBDRAKVUF_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

/*---------------------------------------------------------
 * Reading in Rekall profile informations
 */

typedef struct symbol {
    const char *name;
    addr_t rva;
    uint8_t type;
    int inputs;
} __attribute__ ((packed)) symbol_t;

typedef struct symbols {
    const char *name;
    symbol_t *symbols; // array of size count
    uint64_t count;
} symbols_t;

symbols_t* drakvuf_get_symbols_from_rekall(const char *profile);
void drakvuf_free_symbols(symbols_t *symbols);

status_t drakvuf_get_function_rva(const char *rekall_profile,
                                  const char *function,
                                  addr_t *rva);
status_t drakvuf_get_struct_size(const char *rekall_profile,
                                 const char *struct_name,
                                 size_t *size);
status_t drakvuf_get_struct_member_rva(const char *rekall_profile,
                                       const char *struct_name,
                                       const char *symbol,
                                       addr_t *rva);

/*---------------------------------------------------------
 * DRAKVUF functions
 */

typedef enum lookup_type {
    LOOKUP_NONE,
    LOOKUP_DTB,
    LOOKUP_PID,
    LOOKUP_NAME,
} lookup_type_t;

typedef enum addr_type {
    ADDR_RVA,
    ADDR_VA,
    ADDR_PA
} addr_type_t;

typedef enum trap_type {
    BREAKPOINT      = 1 << 0,
    MEMACCESS_R     = 1 << 1,
    MEMACCESS_W     = 1 << 2,
    MEMACCESS_X     = 1 << 3,
    MEMACCESS_RW    = (MEMACCESS_R | MEMACCESS_W),
    MEMACCESS_RX    = (MEMACCESS_R | MEMACCESS_X),
    MEMACCESS_RWX   = (MEMACCESS_R | MEMACCESS_W | MEMACCESS_W)
} trap_type_t;

typedef enum memaccess_type {
    PRE,
    POST
} memaccess_type_t;

typedef struct drakvuf* drakvuf_t;
struct drakvuf_trap;
typedef struct drakvuf_trap drakvuf_trap_t;

typedef struct drakvuf_trap_info {
    unsigned int vcpu;
    uint16_t altp2m_idx;
    addr_t trap_pa;
    x86_registers_t *regs;
    drakvuf_trap_t *trap;
} drakvuf_trap_info_t;

struct drakvuf_trap {
    event_response_t (*cb)(drakvuf_t, drakvuf_trap_info_t*);

    lookup_type_t lookup_type;
    union {
        vmi_pid_t pid;
        const char *proc;
    } u;

    /* If specified and RVA is used
       RVA will be calculated from the base
       of this module */
    const char *module;
    const char *name;

    addr_type_t addr_type;
    union {
        addr_t rva;
        addr_t addr;
    } u2;

    trap_type_t type;
    memaccess_type_t memaccess_type; // iff type == MEMACCESS_*

    void *data;
};


////////////////////////////////////////////////////////////////////////////

// IMHO these definitions must be placed within another file, named
// libdrakvuf-windows.h or something similar

// For get_previous_mode...
typedef enum privilege_mode {
    KERNEL_MODE,
    USER_MODE,
    MAXIMUM_MODE
} privilege_mode_t ;

// Confirmed only on Win7 SP1...
typedef enum object_manager_object {
    OBJ_MANAGER_PROCESS_OBJECT = 7,
    OBJ_MANAGER_THREAD_OBJECT  = 8
} object_manager_object_t ;

////////////////////////////////////////////////////////////////////////////


bool drakvuf_init (drakvuf_t *drakvuf,
                   const char *domain,
                   const char *rekall_profile);
void drakvuf_close (drakvuf_t drakvuf);
bool drakvuf_add_trap(drakvuf_t drakvuf,
                      drakvuf_trap_t *trap);
void drakvuf_remove_trap (drakvuf_t drakvuf,
                          drakvuf_trap_t *trap,
                          void(*free_routine)(drakvuf_trap_t *trap));
void drakvuf_loop (drakvuf_t drakvuf);
void drakvuf_interrupt (drakvuf_t drakvuf,
                        int sig);
int drakvuf_inject_cmd (drakvuf_t drakvuf,
                        vmi_pid_t pid,
                        const char *cmd);
void drakvuf_pause (drakvuf_t drakvuf);
void drakvuf_resume (drakvuf_t drakvuf);

vmi_instance_t drakvuf_lock_and_get_vmi(drakvuf_t drakvuf);
void drakvuf_release_vmi(drakvuf_t drakvuf);

addr_t drakvuf_get_obj_by_handle(drakvuf_t drakvuf,
                                 addr_t process,
                                 uint64_t handle);

/*
 * Specify either vcpu_id and/or regs. If regs don't have the required info
 * (for example Xen 4.6 doesn't actually send fs_base/gs_base), it falls back
 * on the vcpu id so it's best to specify both.
 */
addr_t drakvuf_get_current_process(drakvuf_t drakvuf,
                                   uint64_t vcpu_id,
                                   x86_registers_t *regs);
addr_t drakvuf_get_current_thread(drakvuf_t drakvuf,
                                   uint64_t vcpu_id,
                                   x86_registers_t *regs);

/* Caller must free the returned string */
char *drakvuf_get_process_name(drakvuf_t drakvuf,
                               addr_t eprocess_base);
char *drakvuf_get_current_process_name(drakvuf_t drakvuf,
                                       uint64_t vcpu_id,
                                       x86_registers_t *regs);


bool drakvuf_get_current_thread_id( drakvuf_t drakvuf, 
                                    uint64_t vcpu_id, 
                                    x86_registers_t *regs,
                                    uint32_t *thread_id );

// Microsoft PreviousMode KTHREAD explanation:
// https://msdn.microsoft.com/en-us/library/windows/hardware/ff559860(v=vs.85).aspx
bool drakvuf_get_current_thread_previous_mode( drakvuf_t drakvuf, 
                                               drakvuf_trap_info_t *info, 
                                               privilege_mode_t *previous_mode );

bool drakvuf_get_thread_previous_mode( drakvuf_t drakvuf, 
                                       addr_t kthread, 
                                       privilege_mode_t *previous_mode );

bool drakvuf_is_ethread( drakvuf_t drakvuf, 
                         drakvuf_trap_info_t *info, 
                         addr_t ethread_addr );

bool drakvuf_is_eprocess( drakvuf_t drakvuf, 
                          drakvuf_trap_info_t *info, 
                          addr_t eprocess_addr );

// ObReferenceObjectByHandle
bool drakvuf_obj_ref_by_handle( drakvuf_t drakvuf, 
                                drakvuf_trap_info_t *info, 
                                addr_t current_eprocess,
                                addr_t handle, 
                                object_manager_object_t obj_type_arg, 
                                addr_t *obj_body_addr );

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif
