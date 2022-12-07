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

#ifndef LIBDRAKVUF_H
#define LIBDRAKVUF_H

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#pragma GCC visibility push(default)

#define LIBVMI_EXTRA_GLIB
#define LIBVMI_EXTRA_JSON

#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/events.h>
#include <libvmi/x86.h>
#include <json-c/json.h>

// Printf helpers for timestamp.
#define FORMAT_TIMEVAL "%" PRId64 ".%06" PRId64
#define UNPACK_TIMEVAL(t) (t/G_USEC_PER_SEC), (t - (t/G_USEC_PER_SEC)*G_USEC_PER_SEC)

#define eprint_current_time(...) \
    do { \
        gint64 current_time = g_get_real_time(); \
        fprintf(stderr, FORMAT_TIMEVAL " ", UNPACK_TIMEVAL(current_time)); \
    } while (0)

#ifdef DRAKVUF_DEBUG
extern bool verbose;
#define PRINT_DEBUG(...) \
    do { \
        if(verbose) { eprint_current_time(); fprintf (stderr, __VA_ARGS__); } \
    } while (0)
#else
#define PRINT_DEBUG(...) do {} while(0)
#endif

#define UNUSED(x)       (void)(x)
#define NUMBER_OF(x)    (sizeof(x) / sizeof(x[0]))
#define ARRAY_SIZE(arr) NUMBER_OF(arr)

/*---------------------------------------------------------
 * DRAKVUF functions
 */

// Additional signal number constants for Drakvuf
#define SIGDRAKVUFERROR   -1
#define SIGDRAKVUFTIMEOUT -2
#define SIGDRAKVUFCRASH   -3
#define SIGDRAKVUFKERNELPANIC -4 // drakvuf loop interrupted by BSOD or KERNEL PANIC

typedef enum lookup_type
{
    __INVALID_LOOKUP_TYPE,
    LOOKUP_NONE,
    LOOKUP_DTB,
    LOOKUP_PID,
    LOOKUP_NAME,
    LOOKUP_KERNEL,
} lookup_type_t;

typedef enum addr_type
{
    __INVALID_ADDR_TYPE,
    ADDR_RVA,
    ADDR_VA,
    ADDR_PA,
    ADDR_SYMBOL,
} addr_type_t;

typedef enum trap_type
{
    __INVALID_TRAP_TYPE,
    BREAKPOINT,
    MEMACCESS,
    REGISTER,
    DEBUG,
    CPUID,
    CATCHALL_BREAKPOINT
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
    uint32_t tid ;    /* Thread Id for Linux & Windows*/
} proc_data_t ;

typedef struct drakvuf* drakvuf_t;
struct drakvuf_trap;
typedef struct drakvuf_trap drakvuf_trap_t;

typedef struct drakvuf_trap_info
{
    gint64 timestamp;
    unsigned int vcpu;
    uint16_t altp2m_idx;
    proc_data_t proc_data ; /* Current owning process data */
    proc_data_t attached_proc_data ; /* Current attached process data */
    addr_t trap_pa;
    x86_registers_t* regs;
    drakvuf_trap_t* trap;
    uint64_t event_uid; /* Unique sequential event identifier */
    union
    {
        const cpuid_event_t* cpuid; /* For CPUID traps */
        const debug_event_t* debug; /* For DEBUG traps */
        const reg_event_t*   reg;   /* For MSR traps */
    };
} drakvuf_trap_info_t;

#define UNLIMITED_TTL 0
#define TRAP_TTL_RESET_INTERVAL_SEC 10

struct drakvuf_trap
{
    trap_type_t type;
    event_response_t (*cb)(drakvuf_t, drakvuf_trap_info_t*);
    void* data;

    union
    {
        const char* name; // Only used for informational/debugging purposes
        void* _name;
    };

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
                const char* symbol;
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

    // How many times trap can be hit in TRAP_TTL_RESET_INTERVAL_SEC interval,
    // before it gets discarded. Protects against api-hammering.
    // 0 for infinity.
    uint64_t ttl;
    time_t last_ttl_rst;
    // Callback invoked when the trap hits api-hammering limit. If not set (NULL),
    // the trap will be simply unhooked (not deleted).
    void(*ah_cb)(drakvuf_t, drakvuf_trap_t*);
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

vmi_instance_t drakvuf_lock_and_get_vmi(drakvuf_t drakvuf) NOEXCEPT;
void drakvuf_release_vmi(drakvuf_t drakvuf) NOEXCEPT;

////////////////////////////////////////////////////////////////////////////

/*---------------------------------------------------------
 * Reading in Rekall profile informations
 */

typedef struct symbol
{
    char* name;
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

uint64_t drakvuf_get_limited_traps_ttl(drakvuf_t drakvuf) NOEXCEPT;

const char* drakvuf_get_json_wow_path(drakvuf_t drakvuf) NOEXCEPT;
json_object* drakvuf_get_json_wow(drakvuf_t drakvuf) NOEXCEPT;

symbols_t* json_get_symbols(json_object* json_profile) NOEXCEPT;
void drakvuf_free_symbols(symbols_t* symbols) NOEXCEPT;

bool drakvuf_get_kernel_symbol_rva(drakvuf_t drakvuf,
    const char* function,
    addr_t* rva) NOEXCEPT;
bool drakvuf_get_kernel_symbol_va(drakvuf_t drakvuf,
    const char* function,
    addr_t* va) NOEXCEPT;
bool drakvuf_get_kernel_struct_size(drakvuf_t drakvuf,
    const char* struct_name,
    size_t* size) NOEXCEPT;
bool drakvuf_get_kernel_struct_member_rva(drakvuf_t drakvuf,
    const char* struct_name,
    const char* symbol,
    addr_t* rva) NOEXCEPT;
bool drakvuf_get_bitfield_offset_and_size(drakvuf_t drakvuf,
    const char* struct_name,
    const char* struct_member,
    addr_t* offset,
    size_t* start_bit,
    size_t* end_bit) NOEXCEPT;
bool json_get_symbol_rva(drakvuf_t drakvuf,
    json_object* json,
    const char* function,
    addr_t* rva) NOEXCEPT;
bool json_get_struct_size(drakvuf_t drakvuf,
    json_object* json,
    const char* struct_name,
    size_t* size) NOEXCEPT;
bool json_get_struct_member_rva(drakvuf_t drakvuf,
    json_object* json,
    const char* struct_name,
    const char* symbol,
    addr_t* rva) NOEXCEPT;

bool json_get_struct_members_array_rva(
    drakvuf_t drakvuf,
    json_object* json_profile,
    const char* struct_name_subsymbol_array[][2],
    size_t array_size,
    addr_t* rva) NOEXCEPT;
static inline
bool drakvuf_get_kernel_struct_members_array_rva(
    drakvuf_t drakvuf,
    const char* struct_name_subsymbol_array[][2],
    size_t array_size,
    addr_t* rva)
{
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool ret = json_get_struct_members_array_rva(drakvuf, vmi_get_kernel_json(vmi), struct_name_subsymbol_array, array_size, rva);
    drakvuf_release_vmi(drakvuf);
    return ret;
}

//---- end of paired drakvuf_* and json_* functions ----

typedef void (*drakvuf_trap_free_t)(drakvuf_trap_t* trap);

typedef void (*event_cb_t) (int fd, void* data);

bool drakvuf_init (drakvuf_t* drakvuf,
    const char* domain,
    const char* json_profile,
    const char* json_wow_profile,
    const bool libvmi_conf,
    const addr_t kpgd,
    const bool fast_singlestep,
    uint64_t limited_traps_ttl,
    GSList* ignored_processes,
    bool get_userid,
    bool enable_active_callback_check) NOEXCEPT;
bool drakvuf_init_os (drakvuf_t drakvuf) NOEXCEPT;
void drakvuf_close (drakvuf_t drakvuf, const bool pause) NOEXCEPT;
int drakvuf_send_qemu_monitor_command(drakvuf_t drakvuf, const char* in, char** out);
bool drakvuf_add_trap(drakvuf_t drakvuf,
    drakvuf_trap_t* trap) NOEXCEPT;
void drakvuf_remove_trap (drakvuf_t drakvuf,
    drakvuf_trap_t* trap,
    drakvuf_trap_free_t free_routine) NOEXCEPT;
void drakvuf_unhook_trap(drakvuf_t drakvuf, drakvuf_trap_t* trap) NOEXCEPT;
void drakvuf_loop (drakvuf_t drakvuf, bool (*is_interrupted)(drakvuf_t, void*), void* data) NOEXCEPT;
void drakvuf_interrupt (drakvuf_t drakvuf,
    int sig) NOEXCEPT;
int drakvuf_is_interrupted(drakvuf_t drakvuf) NOEXCEPT;
void drakvuf_pause (drakvuf_t drakvuf) NOEXCEPT;
void drakvuf_resume (drakvuf_t drakvuf) NOEXCEPT;

addr_t drakvuf_get_obj_by_handle(drakvuf_t drakvuf,
    addr_t process,
    uint64_t handle) NOEXCEPT;

os_t drakvuf_get_os_type(drakvuf_t drakvuf) NOEXCEPT;
page_mode_t drakvuf_get_page_mode(drakvuf_t drakvuf) NOEXCEPT;
size_t drakvuf_get_address_width(drakvuf_t drakvuf) NOEXCEPT;
uint64_t drakvuf_get_init_memsize(drakvuf_t drakvuf) NOEXCEPT;
size_t drakvuf_get_process_address_width(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info) NOEXCEPT;
int drakvuf_read_addr(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    const access_context_t* ctx, addr_t* addr) NOEXCEPT;

uint16_t drakvuf_get_dom_id(drakvuf_t drakvuf) NOEXCEPT;

addr_t drakvuf_get_kernel_base(drakvuf_t drakvuf) NOEXCEPT;

addr_t drakvuf_get_current_process(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info) NOEXCEPT;

addr_t drakvuf_get_current_attached_process(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info) NOEXCEPT;

bool drakvuf_get_current_irql(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info, uint8_t* irql) NOEXCEPT;

addr_t drakvuf_get_current_thread(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info) NOEXCEPT;

addr_t drakvuf_get_current_thread_teb(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info) NOEXCEPT;

addr_t drakvuf_get_current_thread_stackbase(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info) NOEXCEPT;

bool drakvuf_get_last_error(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    uint32_t* err,
    const char** err_str) NOEXCEPT;

/* Caller must free the returned string */
char* drakvuf_get_process_name(drakvuf_t drakvuf,
    addr_t process_base,
    bool fullpath) NOEXCEPT;

/* Caller must free the returned string */
char* drakvuf_get_process_commandline(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    addr_t process_base) NOEXCEPT;

bool drakvuf_get_process_pid(drakvuf_t drakvuf,
    addr_t process_base,
    vmi_pid_t* pid) NOEXCEPT;

bool drakvuf_process_is32bit(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info) NOEXCEPT;

bool drakvuf_get_process_by_handle(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    uint64_t handle,
    addr_t* process,
    addr_t* dtb);

bool drakvuf_get_process_by_pid(drakvuf_t drakvuf,
    vmi_pid_t pid,
    addr_t* process,
    addr_t* dtb);

bool drakvuf_get_process_thread_id( drakvuf_t drakvuf,
    addr_t process_base,
    uint32_t* pid) NOEXCEPT;

bool drakvuf_get_process_dtb(drakvuf_t drakvuf,
    addr_t process_base,
    addr_t* dtb) NOEXCEPT;

bool drakvuf_get_current_process_environ(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    GHashTable** environ) NOEXCEPT;

bool drakvuf_get_process_arguments(drakvuf_t drakvuf,
    addr_t process_base,
    addr_t* argv) NOEXCEPT;

/* Process userid or -1 on error */
int64_t drakvuf_get_process_userid(drakvuf_t drakvuf,
    addr_t process_base) NOEXCEPT;

unicode_string_t* drakvuf_get_process_csdversion(drakvuf_t drakvuf,
    addr_t process_base) NOEXCEPT;

bool drakvuf_get_process_data(drakvuf_t drakvuf,
    addr_t process_base,
    proc_data_t* proc_data) NOEXCEPT;

addr_t drakvuf_get_rspbase(drakvuf_t dravkuf, drakvuf_trap_info_t* info);

typedef struct _mmvad_info
{
    uint64_t starting_vpn;
    uint64_t ending_vpn;
    uint64_t flags;
    uint64_t flags1;

    /* Pointer to the file name, if this MMVAD is backed by some file on disk.
     * If not null, read with: drakvuf_read_unicode_va(drakvuf, mmvad->file_name_ptr, 0) */
    addr_t file_name_ptr;
    uint32_t total_number_of_ptes;
    addr_t prototype_pte;
    addr_t node_addr;
} mmvad_info_t;

typedef bool (*mmvad_callback)(drakvuf_t drakvuf, mmvad_info_t* mmvad, void* callback_data);

bool drakvuf_find_mmvad(drakvuf_t drakvuf, addr_t eprocess, addr_t vaddr, mmvad_info_t* out_mmvad) NOEXCEPT;
bool drakvuf_traverse_mmvad(drakvuf_t drakvuf, addr_t eprocess, mmvad_callback callback, void* callback_data) NOEXCEPT;
bool drakvuf_is_mmvad_commited(drakvuf_t drakvuf, mmvad_info_t* mmvad) NOEXCEPT;
uint32_t drakvuf_mmvad_type(drakvuf_t drakvuf, mmvad_info_t* mmvad);
uint64_t drakvuf_mmvad_commit_charge(drakvuf_t drakvuf, mmvad_info_t* mmvad, uint64_t* width) NOEXCEPT;
bool drakvuf_mmvad_private_memory(drakvuf_t drakvuf, mmvad_info_t* mmvad) NOEXCEPT;
uint64_t drakvuf_mmvad_protection(drakvuf_t drakvuf, mmvad_info_t* mmvad) NOEXCEPT;

addr_t drakvuf_get_wow_peb(drakvuf_t drakvuf, access_context_t* ctx, addr_t eprocess) NOEXCEPT;
bool drakvuf_get_wow_context(drakvuf_t drakvuf, addr_t ethread, addr_t* wow_ctx) NOEXCEPT;
bool drakvuf_get_user_stack32(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* stack_ptr, addr_t* frame_ptr);
bool drakvuf_get_user_stack64(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* stack_ptr) NOEXCEPT;

bool drakvuf_get_current_thread_id(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    uint32_t* thread_id) NOEXCEPT;

/*
 * To catch the moment of exiting the currently executing function,
 * we put a breakpoint on the instruction located at the function's
 * return address.
 *
 * Such a breakpoint can also be triggered on exit from another function
 * call (called in another thread or even a process), or on exit from a
 * recursive call.
 *
 * This function checks that the callback was triggered on exit from the
 * function call we need.
 */
bool drakvuf_check_return_context(drakvuf_t drakvuf, drakvuf_trap_info_t* info,
    vmi_pid_t target_pid, uint32_t target_tid,
    addr_t target_rsp) NOEXCEPT;

addr_t drakvuf_exportksym_to_va(drakvuf_t drakvuf,
    const vmi_pid_t pid, const char* proc_name,
    const char* mod_name, addr_t rva) NOEXCEPT;

addr_t drakvuf_kernel_symbol_to_va(drakvuf_t drakvuf, const char* func) NOEXCEPT;

addr_t drakvuf_exportsym_to_va(drakvuf_t drakvuf, addr_t process_addr,
    const char* module, const char* sym) NOEXCEPT;

addr_t drakvuf_export_lib_address(drakvuf_t drakvuf, addr_t process_addr, const char* lib) NOEXCEPT;

// Microsoft PreviousMode KTHREAD explanation:
// https://msdn.microsoft.com/en-us/library/windows/hardware/ff559860(v=vs.85).aspx
bool drakvuf_get_current_thread_previous_mode(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    privilege_mode_t* previous_mode) NOEXCEPT;

bool drakvuf_get_thread_previous_mode(drakvuf_t drakvuf,
    addr_t kthread,
    privilege_mode_t* previous_mode) NOEXCEPT;

bool drakvuf_is_thread(drakvuf_t drakvuf,
    addr_t dtb,
    addr_t thread_addr) NOEXCEPT;

bool drakvuf_is_process(drakvuf_t drakvuf,
    addr_t dtb,
    addr_t process_addr) NOEXCEPT;

bool drakvuf_is_process_suspended(drakvuf_t drakvuf,
    addr_t process,
    bool* status) NOEXCEPT;

GHashTable* drakvuf_enum_threads(drakvuf_t drakvuf, addr_t process) NOEXCEPT;
addr_t drakvuf_get_thread(drakvuf_t drakvuf,
    addr_t process,
    uint32_t tid) NOEXCEPT;

bool drakvuf_find_process(drakvuf_t drakvuf,
    vmi_pid_t find_pid,
    const char* find_procname,
    addr_t* process_addr) NOEXCEPT;

typedef struct _module_info
{
    addr_t eprocess_addr ;        /* EPROCESS to which the module is currently loaded           */
    addr_t dtb ;                  /* DTB for the process where the module is currently loaded   */
    vmi_pid_t pid ;               /* PID of the process where the module is currently is loaded */
    addr_t base_addr ;            /* Module base address                                        */
    addr_t size ;                 /* Size of Image                                              */
    unicode_string_t* full_name ; /* Module full name                                           */
    unicode_string_t* base_name ; /* Module base name                                           */
    bool is_wow ;                 /* Is WoW64 module?                                           */
    bool is_wow_process ;         /* Is WoW64 process?                                          */
} module_info_t ;

bool drakvuf_enumerate_processes(drakvuf_t drakvuf,
    void (*visitor_func)(drakvuf_t drakvuf, addr_t process, void* visitor_ctx),
    void* visitor_ctx) NOEXCEPT;

bool drakvuf_enumerate_processes_with_module(drakvuf_t drakvuf,
    const char* module_name,
    bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx),
    void* visitor_ctx) NOEXCEPT;

bool drakvuf_enumerate_drivers(drakvuf_t drakvuf,
    void (*visitor_func)(drakvuf_t drakvuf, addr_t process, void* visitor_ctx),
    void* visitor_ctx) NOEXCEPT;

bool drakvuf_enumerate_process_modules(drakvuf_t drakvuf,
    addr_t eprocess,
    bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, bool* need_free, bool* need_stop, void* visitor_ctx),
    void* visitor_ctx) NOEXCEPT;

bool drakvuf_is_crashreporter(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    vmi_pid_t* pid) NOEXCEPT;

bool drakvuf_get_module_list(drakvuf_t drakvuf,
    addr_t process_base,
    addr_t* module_list) NOEXCEPT;

bool drakvuf_get_module_list_wow(drakvuf_t drakvuf,
    access_context_t* ctx,
    addr_t wow_peb,
    addr_t* module_list) NOEXCEPT;

// ObReferenceObjectByHandle
bool drakvuf_obj_ref_by_handle(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    addr_t current_process,
    addr_t handle,
    object_manager_object_t obj_type_arg,
    addr_t* obj_body_addr) NOEXCEPT;


char* drakvuf_read_ascii_str(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr) NOEXCEPT;

unicode_string_t* drakvuf_read_unicode_common(drakvuf_t drakvuf, const access_context_t* ctx) NOEXCEPT;

unicode_string_t* drakvuf_read_unicode(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr) NOEXCEPT;

unicode_string_t* drakvuf_read_unicode_va(drakvuf_t drakvuf, addr_t vaddr, vmi_pid_t pid) NOEXCEPT;

unicode_string_t* drakvuf_read_unicode32_common(drakvuf_t drakvuf, const access_context_t* ctx) NOEXCEPT;

unicode_string_t* drakvuf_read_unicode32(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr) NOEXCEPT;

unicode_string_t* drakvuf_read_unicode32_va(drakvuf_t drakvuf, addr_t vaddr, vmi_pid_t pid) NOEXCEPT;

bool drakvuf_get_module_base_addr( drakvuf_t drakvuf,
    addr_t module_list_head,
    const char* module_name,
    addr_t* base_addr ) NOEXCEPT;

bool drakvuf_get_module_base_addr_ctx( drakvuf_t drakvuf,
    addr_t module_list_head,
    access_context_t* ctx,
    const char* module_name,
    addr_t* base_addr_out ) NOEXCEPT;

bool drakvuf_get_process_ppid(drakvuf_t drakvuf,
    addr_t process_base,
    vmi_pid_t* ppid ) NOEXCEPT;

gchar* drakvuf_reg_keyhandle_path(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    uint64_t key_handle) NOEXCEPT;

char* drakvuf_get_filename_from_handle( drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    addr_t handle ) NOEXCEPT;

char* drakvuf_get_filename_from_object_attributes( drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    addr_t attrs ) NOEXCEPT;

char* drakvuf_get_filepath_from_dentry(drakvuf_t drakvuf,
    addr_t dentry_addr) NOEXCEPT;

// Reads 'length' characters from array of UTF_16 charachters into unicode_string_t object with UTF_8 encoding
unicode_string_t* drakvuf_read_wchar_array(drakvuf_t drakvuf, const access_context_t* ctx, size_t length) NOEXCEPT;


// Determines length of null-terminated array of UTF_16 charachters
size_t drakvuf_wchar_string_length(drakvuf_t drakvuf, const access_context_t* ctx) NOEXCEPT;

// Reads null-terminated string of UTF_16 charachters, automatically determining length, into unicode_string_t object with UTF_8 encoding
unicode_string_t* drakvuf_read_wchar_string(drakvuf_t drakvuf, const access_context_t* ctx) NOEXCEPT;

// Returns JSON-compliant copy of input string. User must free the result.
gchar* drakvuf_escape_str(const char* input) NOEXCEPT;

bool drakvuf_is_wow64(drakvuf_t drakvuf, drakvuf_trap_info_t* info) NOEXCEPT;

addr_t drakvuf_get_function_argument(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    int argument_number) NOEXCEPT;
addr_t drakvuf_get_function_return_address(drakvuf_t drakvuf, drakvuf_trap_info_t* info) NOEXCEPT;

bool drakvuf_get_pid_from_handle(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle, vmi_pid_t* pid) NOEXCEPT;
bool drakvuf_get_tid_from_handle(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle, uint32_t* tid) NOEXCEPT;

bool drakvuf_set_vcpu_gprs(drakvuf_t drakvuf, unsigned int vcpu, registers_t* regs) NOEXCEPT;
void drakvuf_copy_gpr_registers(x86_registers_t* dst, x86_registers_t* src);
/* This function is used to delay registers modification on injections.
 * This fixes two issues:
 * 1. Two plug-ins injects function call or modify registers.
 * 2. One plug-in injects function call and other one reads modified registers.
 */
bool drakvuf_vmi_response_set_gpr_registers(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    x86_registers_t* regs,
    bool immediate);
/* The plug-in is called "active" if it injects function call. */
bool drakvuf_is_active_callback(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
void* drakvuf_lookup_injection(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
void drakvuf_insert_injection(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    event_response_t (*cb)(drakvuf_t, drakvuf_trap_info_t*));
void drakvuf_remove_injection(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

#define DRAKVUF_IPT_BRANCH_EN (1 << 0)
#define DRAKVUF_IPT_TRACE_OS  (1 << 1)
#define DRAKVUF_IPT_TRACE_USR (1 << 2)
#define DRAKVUF_IPT_DIS_RETC  (1 << 3)

bool drakvuf_enable_ipt(drakvuf_t drakvuf, unsigned int vcpu, uint8_t** buf, uint64_t* size, uint64_t flags);
bool drakvuf_get_ipt_offset(drakvuf_t drakvuf, unsigned int vcpu, uint64_t* offset, uint64_t* last_offset);
bool drakvuf_disable_ipt(drakvuf_t drakvuf, unsigned int vcpu);

/* Context based views functions and enum */
typedef enum
{
    MATCH_NAME,
    MATCH_PID,
    MATCH_PID_NAME,
} context_match_t;

void drakvuf_toggle_context_based_interception(drakvuf_t drakvuf);
void drakvuf_intercept_process_add(drakvuf_t drakvuf, char* process_name, vmi_pid_t pid, context_match_t strict);

typedef struct
{
    int major;
    int minor;
    int patch;
} kernel_version_t;

const kernel_version_t* drakvuf_get_kernel_version(drakvuf_t drakvuf, drakvuf_trap_info_t* info) NOEXCEPT;

/*---------------------------------------------------------
 * Event FD functions
 */

int drakvuf_event_fd_add(drakvuf_t drakvuf,
    int fd,
    event_cb_t event_cb,
    void* data) NOEXCEPT;

int drakvuf_event_fd_remove(drakvuf_t drakvuf,
    int fd) NOEXCEPT;

/*---------------------------------------------------------
 * Output helpers
 */

typedef enum
{
    OUTPUT_DEFAULT,
    OUTPUT_CSV,
    OUTPUT_KV,
    OUTPUT_JSON,
} output_format_t;

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif
