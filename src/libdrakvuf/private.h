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

#ifndef STRUCTURES_H
#define STRUCTURES_H

/******************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <glib.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include "libdrakvuf.h"
#include "vmi.h"
#include "os.h"
#include "json-profile.h"
#include "../xen_helper/xen_helper.h"

#include <sys/poll.h>

#define UNUSED(x) (void)(x)

#if GLIB_CHECK_VERSION(2,67,3)
#define g_memdup_compat(x,y) g_memdup2(x,y)
#else
#define g_memdup_compat(x,y) g_memdup(x,y)
#endif

/*
 * How often should the VMI caches be flushed?
 *
 * TODO: develop intelligent cache-flush system that
 *       catches the events that actually make flushes
 *       necessary.
 */
#define VMI_FLUSH_RATE 100

/*
 * How many vCPUs are supported per single DomU
 * this value could be increased if needed
 */
#define MAX_DRAKVUF_VCPU 16

struct fd_info
{
    int fd;
    event_cb_t event_cb;
    void* data;
};
typedef struct fd_info* fd_info_t;


struct bitfield
{
    size_t offset;
    size_t start_bit;
    size_t end_bit;
};
typedef struct bitfield* bitfield_t;

struct drakvuf
{
    char* dom_name;
    domid_t domID;
    os_t os;

    char* json_kernel_path;
    char* json_wow_path;
    json_object* json_wow;
    bool libvmi_conf;
    bool get_userid;

    xen_interface_t* xen;
    os_interface_t osi;
    uint16_t altp2m_idx, altp2m_idr, altp2m_idrx;
    bool vcpu_monitor[MAX_DRAKVUF_VCPU];

    xen_pfn_t sink_page_gfn;

    event_response_t int3_response_flags;

    // VMI
    unsigned long flush_counter;
    GRecMutex vmi_lock;
    vmi_instance_t vmi;

    vmi_event_t cr3_event;
    vmi_event_t interrupt_event;
    vmi_event_t mem_event;
    vmi_event_t debug_event;
    vmi_event_t cpuid_event;
    vmi_event_t msr_event;
    vmi_event_t* step_event[MAX_DRAKVUF_VCPU];

    size_t* offsets;
    size_t* sizes;
    bitfield_t bitfields;

    size_t* wow_offsets;

    // Processing trap removals in trap callbacks
    // is problematic so we save all such requests
    // in a list to be processed after all callbacks
    // are finished.
    bool in_callback;
    GHashTable* remove_traps;

    int interrupted;
    page_mode_t pm;
    unsigned int vcpus;
    uint64_t init_memsize;
    xen_pfn_t max_gpfn;
    addr_t kernbase;
    addr_t kpgd;

    size_t address_width;

    GHashTable* remapped_gfns; // Key: gfn
    // val: remapped gfn

    GHashTable* breakpoint_lookup_pa;   // key: PA of trap
    // val: struct breakpoint
    GHashTable* breakpoint_lookup_gfn;  // key: gfn (size uint64_t)
    // val: GSList of addr_t* for trap locations
    GHashTable* breakpoint_lookup_trap; // key: trap pointer
    // val: struct breakpoint

    GHashTable* memaccess_lookup_gfn;  // key: gfn of trap
    // val: struct memaccess
    GHashTable* memaccess_lookup_trap; // key: trap pointer
    // val: struct memaccess

    GSList* cr0, *cr3, *cr4, *debug, *cpuid, *catchall_breakpoint, *msr;

    // list of processes to be intercepted
    bool enable_cr3_based_interception;
    GSList* context_switch_intercept_processes;

    GSList* event_fd_info;     // the list of registered event FDs
    struct pollfd* event_fds;  // auto-generated pollfd for poll()
    int event_fd_cnt;          // auto-generated for poll()
    fd_info_t fd_info_lookup;  // auto-generated for fast drakvuf_loop lookups
    int poll_rc;

    uint64_t event_counter;    // incremental unique trap event ID

    ipt_state_t ipt_state[MAX_DRAKVUF_VCPU];

    int64_t limited_traps_ttl;
};

struct breakpoint
{
    addr_t pa;
    drakvuf_trap_t guard, guard2, guard3, guard4;
    bool doubletrap;
};
struct memaccess
{
    addr_t gfn;
    bool guard2;
    vmi_mem_access_t access;
};

struct wrapper
{
    trap_type_t type;
    drakvuf_t drakvuf;
    GSList* traps; /* List of DRAKVUF traps registered for this event */
    union
    {
        struct memaccess memaccess;
        struct breakpoint breakpoint;
    };
};

void free_wrapper(gpointer p);

struct free_trap_wrapper
{
    unsigned int counter;
    drakvuf_trap_t* trap;
    drakvuf_trap_free_t free_routine;
};

struct remapped_gfn
{
    xen_pfn_t o;
    xen_pfn_t r;
    bool active;
};

void free_remapped_gfn(gpointer p);

typedef struct process_data_priv
{
    char* name;         /* Process name */
    vmi_pid_t pid ;     /* Process pid | tgid in linux*/
    vmi_pid_t ppid ;    /* Process parent pid */
    addr_t base_addr ;  /* Process base address */
    int64_t userid ;    /* Process SessionID/UID */
    uint32_t tid;      /* Thread id for Linux*/
} proc_data_priv_t ;

struct memcb_pass
{
    drakvuf_t drakvuf;
    uint64_t gfn;
    addr_t pa;
    proc_data_priv_t proc_data ;
    proc_data_priv_t attached_proc_data ;
    struct remapped_gfn* remapped_gfn;
    vmi_mem_access_t access;
    GSList* traps;
};

typedef struct intercept_process
{
    char* name;
    vmi_pid_t pid;
    context_match_t strict; /* 0: Match Name, 1: Match PID , 2: Match PID and Name */
} intercept_process_t;

void drakvuf_force_resume (drakvuf_t drakvuf);

bool drakvuf_get_current_process_data(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    proc_data_priv_t* proc_data);

bool drakvuf_get_process_data_priv(drakvuf_t drakvuf,
    addr_t process_base,
    proc_data_priv_t* proc_data);

char* drakvuf_get_current_process_name(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info,
    bool fullpath);

int64_t drakvuf_get_current_process_userid(drakvuf_t drakvuf,
    drakvuf_trap_info_t* info);

#endif
