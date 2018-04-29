/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
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

#ifndef LIBDRAKVUF_H
#define LIBDRAKVUF_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

#include <glib.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

/*---------------------------------------------------------
 * Reading in Rekall profile informations
 */

typedef struct symbol
{
    const char* name;
    addr_t rva;
    uint8_t type;
    int inputs;
} __attribute__ ((packed)) symbol_t;

typedef struct symbols
{
    const char* name;
    symbol_t* symbols; // array of size count
    uint64_t count;
} symbols_t;

symbols_t* drakvuf_get_symbols_from_rekall(const char* profile);
void drakvuf_free_symbols(symbols_t* symbols);

bool drakvuf_get_function_rva(const char* rekall_profile,
                              const char* function,
                              addr_t* rva);
bool drakvuf_get_constant_rva(const char* rekall_profile,
                              const char* constant,
                              addr_t* rva);
bool drakvuf_get_struct_size(const char* rekall_profile,
                             const char* struct_name,
                             size_t* size);
bool drakvuf_get_struct_member_rva(const char* rekall_profile,
                                   const char* struct_name,
                                   const char* symbol,
                                   addr_t* rva);

/*---------------------------------------------------------
 * DRAKVUF functions
 */

typedef enum lookup_type
{
    __INVALID_LOOKUP_TYPE,
    LOOKUP_NONE,
    LOOKUP_DTB,
    LOOKUP_PID,
    LOOKUP_NAME,
} lookup_type_t;

typedef enum addr_type
{
    __INVALID_ADDR_TYPE,
    ADDR_RVA,
    ADDR_VA,
    ADDR_PA
} addr_type_t;

typedef enum trap_type
{
    __INVALID_TRAP_TYPE,
    BREAKPOINT,
    MEMACCESS,
    REGISTER,
    DEBUG,
    CPUID
} trap_type_t;

typedef enum memaccess_type
{
    __INVALID_MEMACCESS_TYPE,
    PRE,
    POST
} memaccess_type_t;

typedef struct process_data
{
    const char* name;   /* Process name */
    vmi_pid_t pid ;     /* Process pid */
    vmi_pid_t ppid ;    /* Process parent pid */
    addr_t base_addr ;  /* Process base address */
    int64_t userid ;    /* Process SessionID/UID */
} proc_data_t ;

typedef struct drakvuf* drakvuf_t;
struct drakvuf_trap;
typedef struct drakvuf_trap drakvuf_trap_t;

typedef struct drakvuf_trap_info
{
    GTimeVal timestamp;
    unsigned int vcpu;
    uint16_t altp2m_idx;
    proc_data_t proc_data ; /* Current executing process data */
    addr_t trap_pa;
    x86_registers_t* regs;
    drakvuf_trap_t* trap;
    union
    {
        const cpuid_event_t* cpuid; /* For CPUID traps */
        const debug_event_t* debug; /* For DEBUG traps */
    };
} drakvuf_trap_info_t;

struct drakvuf_trap
{
    trap_type_t type;
    event_response_t (*cb)(drakvuf_t, drakvuf_trap_info_t*);
    void* data;
    const char* name; // Only used for informational/debugging purposes

    union
    {
        struct
        {
            lookup_type_t lookup_type;
            union
            {
                vmi_pid_t pid;
                const char* proc;
                addr_t dtb;
            };

            /* If specified and RVA is used
               RVA will be calculated from the base
               of this module */
            const char* module;

            addr_type_t addr_type;
            union
            {
                addr_t rva;
                addr_t addr;
            };
        } breakpoint;

        struct
        {
            addr_t gfn;
            vmi_mem_access_t access;
            memaccess_type_t type;
        } memaccess;

        register_t reg;
    };
};


////////////////////////////////////////////////////////////////////////////

// IMHO these definitions must be placed within another file, named
// libdrakvuf-windows.h or something similar

// For get_previous_mode...
typedef enum privilege_mode
{
    KERNEL_MODE,
    USER_MODE,
    MAXIMUM_MODE
} privilege_mode_t ;

// Confirmed only on Win7 SP1...
typedef enum object_manager_object
{
    OBJ_MANAGER_PROCESS_OBJECT = 7,
    OBJ_MANAGER_THREAD_OBJECT  = 8
} object_manager_object_t ;

////////////////////////////////////////////////////////////////////////////

typedef void (*drakvuf_trap_free_t)(drakvuf_trap_t* trap);

bool drakvuf_init (drakvuf_t* drakvuf,
                   const char* domain,
                   const char* rekall_profile,
                   const bool verbose);
void drakvuf_close (drakvuf_t drakvuf, const bool pause);
bool drakvuf_add_trap(drakvuf_t drakvuf,
                      drakvuf_trap_t* trap);
void drakvuf_remove_trap (drakvuf_t drakvuf,
                          drakvuf_trap_t* trap,
                          drakvuf_trap_free_t free_routine);
void drakvuf_loop (drakvuf_t drakvuf);
void drakvuf_interrupt (drakvuf_t drakvuf,
                        int sig);
void drakvuf_pause (drakvuf_t drakvuf);
void drakvuf_resume (drakvuf_t drakvuf);

vmi_instance_t drakvuf_lock_and_get_vmi(drakvuf_t drakvuf);
void drakvuf_release_vmi(drakvuf_t drakvuf);

addr_t drakvuf_get_obj_by_handle(drakvuf_t drakvuf,
                                 addr_t process,
                                 uint64_t handle);

os_t drakvuf_get_os_type(drakvuf_t drakvuf);
const char* drakvuf_get_rekall_profile(drakvuf_t drakvuf);

addr_t drakvuf_get_kernel_base(drakvuf_t drakvuf);

/*
 * Specify either vcpu_id and/or regs. If regs don't have the required info
 * (for example Xen 4.6 doesn't actually send fs_base/gs_base), it falls back
 * on the vcpu id so it's best to specify both.
 */
addr_t drakvuf_get_current_process(drakvuf_t drakvuf,
                                   uint64_t vcpu_id);
addr_t drakvuf_get_current_thread(drakvuf_t drakvuf,
                                  uint64_t vcpu_id);

/* Caller must free the returned string */
char* drakvuf_get_process_name(drakvuf_t drakvuf,
                               addr_t process_base);

status_t drakvuf_get_process_pid( drakvuf_t drakvuf,
                                  addr_t process_base,
                                  vmi_pid_t* pid);

/* Process userid or -1 on error */
int64_t drakvuf_get_process_userid(drakvuf_t drakvuf,
                                   addr_t process_base);

bool drakvuf_get_current_thread_id(drakvuf_t drakvuf,
                                   uint64_t vcpu_id,
                                   uint32_t* thread_id);

addr_t drakvuf_exportsym_to_va(drakvuf_t drakvuf, addr_t process_addr,
                               const char* module, const char* sym);

// Microsoft PreviousMode KTHREAD explanation:
// https://msdn.microsoft.com/en-us/library/windows/hardware/ff559860(v=vs.85).aspx
bool drakvuf_get_current_thread_previous_mode(drakvuf_t drakvuf,
        uint64_t vcpu_id,
        privilege_mode_t* previous_mode);

bool drakvuf_get_thread_previous_mode(drakvuf_t drakvuf,
                                      addr_t kthread,
                                      privilege_mode_t* previous_mode);

bool drakvuf_is_thread(drakvuf_t drakvuf,
                       addr_t dtb,
                       addr_t thread_addr);

bool drakvuf_is_process(drakvuf_t drakvuf,
                        addr_t dtb,
                        addr_t process_addr);

bool drakvuf_find_process(drakvuf_t drakvuf,
                          vmi_pid_t find_pid,
                          const char* find_procname,
                          addr_t* process_addr);

bool drakvuf_get_module_list(drakvuf_t drakvuf,
                             addr_t process_base,
                             addr_t* module_list);

// ObReferenceObjectByHandle
bool drakvuf_obj_ref_by_handle(drakvuf_t drakvuf,
                               drakvuf_trap_info_t* info,
                               addr_t current_process,
                               addr_t handle,
                               object_manager_object_t obj_type_arg,
                               addr_t* obj_body_addr);

unicode_string_t* drakvuf_read_unicode(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr);

unicode_string_t* drakvuf_read_unicode_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid);

bool drakvuf_get_module_base_addr( drakvuf_t drakvuf,
                                   addr_t module_list_head,
                                   const char* module_name,
                                   addr_t* base_addr );

char* drakvuf_reg_keybody_path( drakvuf_t drakvuf,
                                drakvuf_trap_info_t* info,
                                addr_t p_key_body );

char* drakvuf_reg_keycontrolblock_path( drakvuf_t drakvuf,
                                        drakvuf_trap_info_t* info,
                                        addr_t p_key_control_block );

char* drakvuf_reg_keyhandle_path( drakvuf_t drakvuf,
                                  drakvuf_trap_info_t* info,
                                  addr_t key_handle,
                                  addr_t process_arg );

status_t drakvuf_get_process_ppid( drakvuf_t drakvuf,
                                   addr_t process_base,
                                   vmi_pid_t* ppid );

bool drakvuf_get_current_process_data( drakvuf_t drakvuf,
                                       uint64_t vcpu_id,
                                       proc_data_t* proc_data );

bool drakvuf_normalize_file_path_us( unicode_string_t* file_path );
bool drakvuf_normalize_file_path( char** file_path );

/*---------------------------------------------------------
 * Output helpers
 */

typedef enum
{
    OUTPUT_DEFAULT,
    OUTPUT_CSV,
    OUTPUT_KV,
    __OUTPUT_MAX
} output_format_t;

// Printf helpers for timestamp.
#define FORMAT_TIMEVAL "%" PRId64 ".%06" PRId64
#define UNPACK_TIMEVAL(t) (t).tv_sec, (t).tv_usec

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif
